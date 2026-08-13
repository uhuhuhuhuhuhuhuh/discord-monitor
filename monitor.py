import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path

import discord

from app.account_inventory import write_account_inventory
from app.behavior import BehaviorTracker
from app.config import load_settings
from app.db import Database
from app.detection import evaluate_content
from app.models import Reason, severity_for

ALERT_MARKER = "[MONITOR_ALERT]"
settings = load_settings(require_discord=True)

settings.log_file.parent.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("discord_monitor")
logger.setLevel(logging.INFO)
logger.propagate = False
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
file_handler = logging.handlers.TimedRotatingFileHandler(settings.log_file, when="midnight", backupCount=14, encoding="utf-8")
file_handler.setFormatter(formatter)
logger.handlers.clear()
logger.addHandler(stdout_handler)
logger.addHandler(file_handler)

db = Database(settings.db_path)
behavior = BehaviorTracker(settings.raw)
client = discord.Client()


async def send_alert(payload: dict) -> None:
    channel = client.get_channel(settings.target_channel_id)
    if channel is None:
        try:
            channel = await client.fetch_channel(settings.target_channel_id)
        except Exception:
            logger.exception("Unable to resolve alert channel %s", settings.target_channel_id)
            return
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if len(text) > 1800:
        payload = dict(payload)
        payload["content"] = str(payload.get("content", ""))[:250]
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    try:
        await channel.send(f"{ALERT_MARKER}\n```json\n{text}\n```")
    except Exception:
        logger.exception("Failed to send alert")


@client.event
async def on_ready():
    logger.info("Authenticated as %s (%s)", client.user, getattr(client.user, "id", None))
    logger.info("Alert channel: %s", settings.target_channel_id)
    for guild in client.guilds:
        db.upsert_guild(str(guild.id), guild.name, str(getattr(guild, "owner_id", "")) or None, getattr(guild, "member_count", None), True)
    try:
        inventory = write_account_inventory(client, Path("/app/backups"))
        logger.info("Wrote account inventory snapshot: %s", inventory)
    except Exception:
        logger.exception("Unable to write account inventory snapshot")


@client.event
async def on_message(message):
    content = getattr(message, "content", "") or ""
    author_id = str(getattr(getattr(message, "author", None), "id", ""))
    channel_id = str(getattr(getattr(message, "channel", None), "id", ""))
    guild = getattr(message, "guild", None)
    guild_id = str(getattr(guild, "id", "")) if guild else None
    outgoing = bool(client.user and getattr(message.author, "id", None) == client.user.id)
    direction = "SENT" if outgoing else "RECEIVED"

    logger.info("MESSAGE | %s | author=%s | content=%r", direction, author_id, content[:500])

    if channel_id == str(settings.target_channel_id) and content.startswith(ALERT_MARKER):
        return

    new_contact = db.touch_contact(author_id, str(getattr(message, "author", ""))) if author_id else False
    attachment_names = [str(getattr(a, "filename", "")) for a in getattr(message, "attachments", []) or []]
    result = evaluate_content(content, settings.raw, outgoing=outgoing, attachment_names=attachment_names)
    extra = behavior.message_reasons(content, outgoing=outgoing)

    if guild is None and result.score > 0:
        extra.append(Reason("dm_context", "Suspicious content was received/sent in a DM", int(settings.scoring.get("dm_context", 10))))

    created_at = getattr(getattr(message, "author", None), "created_at", None)
    if created_at is not None and result.score > 0:
        try:
            age_days = (datetime.now(timezone.utc) - created_at).days
            if age_days < 14:
                extra.append(Reason("new_account", f"Author account is approximately {age_days} days old", int(settings.scoring.get("new_account", 15))))
        except Exception:
            pass

    if new_contact and not outgoing and result.score > 0:
        extra.append(Reason("new_contact", "First observed message from this contact", int(settings.scoring.get("new_contact", 10))))

    result.reasons.extend(extra)
    result.score += sum(r.score for r in extra)
    result.severity = severity_for(result.score)
    result.suspicious = result.score >= int(settings.monitor.get("alert_threshold", 35))

    if not result.reasons:
        return

    reason_strings = [f"{r.code}: {r.detail}" for r in result.reasons]
    db.add_event(
        event_type="message",
        severity=result.severity,
        score=result.score,
        author_id=author_id,
        guild_id=guild_id,
        channel_id=channel_id,
        message_id=str(getattr(message, "id", "")),
        direction=direction,
        summary=reason_strings[0],
        reasons=reason_strings,
        domains=result.domains,
        content_redacted=result.redacted_text[: int(settings.monitor.get("log_content_max_chars", 500))],
    )

    if not result.suspicious:
        return

    await send_alert({
        "event": "suspicious_message",
        "severity": result.severity,
        "risk_score": result.score,
        "direction": direction,
        "message_id": str(getattr(message, "id", "")),
        "author_id": author_id,
        "guild_id": guild_id,
        "guild_name": getattr(guild, "name", None),
        "channel_id": channel_id,
        "domains": result.domains,
        "reasons": reason_strings,
        "content": result.redacted_text[:700],
    })


@client.event
async def on_guild_join(guild):
    db.upsert_guild(str(guild.id), guild.name, str(getattr(guild, "owner_id", "")) or None, getattr(guild, "member_count", None), True)
    reasons = behavior.guild_join_reasons()
    score = sum(r.score for r in reasons)
    severity = severity_for(score)
    db.add_event(event_type="guild_join", severity=severity, score=score, guild_id=str(guild.id), summary=f"Joined guild {guild.name}", reasons=[r.detail for r in reasons])
    logger.info("GUILD JOIN | %s (%s)", guild.name, guild.id)
    if score >= int(settings.monitor.get("alert_threshold", 35)):
        await send_alert({"event": "guild_join_anomaly", "severity": severity, "risk_score": score, "guild_id": str(guild.id), "guild_name": guild.name, "reasons": [r.detail for r in reasons]})


@client.event
async def on_guild_remove(guild):
    db.upsert_guild(str(guild.id), guild.name, str(getattr(guild, "owner_id", "")) or None, getattr(guild, "member_count", None), False)
    db.add_event(event_type="guild_remove", severity="INFO", score=0, guild_id=str(guild.id), summary=f"Left/removed from guild {guild.name}")
    logger.info("GUILD REMOVE | %s (%s)", guild.name, guild.id)


def main():
    logger.info("Starting Discord monitor...")
    try:
        client.run(settings.token)
    finally:
        db.close()


if __name__ == "__main__":
    main()
