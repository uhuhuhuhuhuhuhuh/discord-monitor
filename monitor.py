import json
import logging
import os
import re
import sys
from urllib.parse import urlparse

import discord

TOKEN = os.getenv("DISCORD_TOKEN")
TARGET_CHANNEL_ID_RAW = os.getenv("DISCORD_TARGET_CHANNEL_ID")

if not TOKEN:
    raise RuntimeError("Missing required environment variable: DISCORD_TOKEN")

if not TARGET_CHANNEL_ID_RAW:
    raise RuntimeError("Missing required environment variable: DISCORD_TARGET_CHANNEL_ID")

try:
    TARGET_CHANNEL_ID = int(TARGET_CHANNEL_ID_RAW)
except ValueError as exc:
    raise RuntimeError("DISCORD_TARGET_CHANNEL_ID must be numeric") from exc

logger = logging.getLogger("discord_monitor")
logger.setLevel(logging.INFO)
logger.propagate = False

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

os.makedirs("/app/logs", exist_ok=True)
file_handler = logging.FileHandler(
    "/app/logs/discord_monitor.log",
    encoding="utf-8",
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
SUSPICIOUS_TLDS = (".tk", ".ml", ".ga")
SUSPICIOUS_DOMAIN_KEYWORDS = ("gift", "free", "nitro", "steam")
SOCIAL_ENGINEERING_KEYWORDS = (
    "claim now",
    "verify your account",
    "account suspended",
    "your account is suspended",
    "suspended",
)
ALERT_MARKER = "[MONITOR_ALERT]"


def normalize_url(url: str) -> str:
    return url.rstrip(".,!?;:)]}\"'")


def get_hostname(url: str) -> str:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate

    try:
        hostname = urlparse(candidate).hostname
    except ValueError:
        return ""

    return hostname.lower().rstrip(".") if hostname else ""


def evaluate_content(text: str) -> tuple[bool, list[str]]:
    if not text:
        return False, []

    reasons: list[str] = []
    urls = [normalize_url(match.group(0)) for match in URL_PATTERN.finditer(text)]

    for url in urls:
        hostname = get_hostname(url)
        if not hostname:
            continue

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                reasons.append(f"Suspicious domain TLD '{tld}': {hostname}")
                break

        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in hostname:
                reasons.append(f"Suspicious domain keyword '{keyword}': {hostname}")

    normalized_text = text.casefold()
    for keyword in SOCIAL_ENGINEERING_KEYWORDS:
        if keyword.casefold() in normalized_text:
            reasons.append(f"Social-engineering phrase detected: '{keyword}'")

    reasons = list(dict.fromkeys(reasons))
    return bool(reasons), reasons


client = discord.Client()


@client.event
async def on_ready():
    logger.info(
        "Successfully authenticated as %s (%s)",
        client.user,
        client.user.id,
    )
    logger.info("Configured alert channel: %s", TARGET_CHANNEL_ID)


@client.event
async def on_message(message):
    content = message.content or ""
    author_id = getattr(message.author, "id", None)

    logger.info(
        "MESSAGE | author_id=%s | content=%r",
        author_id,
        content,
    )

    if (
        getattr(message.channel, "id", None) == TARGET_CHANNEL_ID
        and content.startswith(ALERT_MARKER)
    ):
        return

    is_suspicious, reasons = evaluate_content(content)
    if not is_suspicious:
        return

    alert_payload = {
        "event": "suspicious_message",
        "message_id": str(message.id),
        "author_id": str(author_id),
        "channel_id": str(message.channel.id),
        "guild_id": str(message.guild.id) if message.guild else None,
        "guild_name": message.guild.name if message.guild else None,
        "content": content[:1000],
        "reasons": reasons,
    }

    alert_channel = client.get_channel(TARGET_CHANNEL_ID)
    if alert_channel is None:
        try:
            alert_channel = await client.fetch_channel(TARGET_CHANNEL_ID)
        except Exception:
            logger.exception("Unable to resolve target alert channel %s", TARGET_CHANNEL_ID)
            return

    alert_json = json.dumps(alert_payload, indent=2, ensure_ascii=False)
    if len(alert_json) > 1800:
        alert_payload["content"] = content[:300]
        alert_json = json.dumps(alert_payload, indent=2, ensure_ascii=False)

    try:
        await alert_channel.send(
            f"{ALERT_MARKER}\n```json\n{alert_json}\n```"
        )
        logger.info("Alert sent for message %s", message.id)
    except Exception:
        logger.exception("Failed to send alert for message %s", message.id)


@client.event
async def on_guild_join(guild):
    logger.info("GUILD JOIN | name=%r | id=%s", guild.name, guild.id)


def main():
    logger.info("Starting Discord monitor...")
    client.run(TOKEN)


if __name__ == "__main__":
    main()
