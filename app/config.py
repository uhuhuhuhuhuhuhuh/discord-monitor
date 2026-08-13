from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Settings:
    token: str
    target_channel_id: int
    config_path: Path
    db_path: Path
    log_file: Path
    backup_key: str | None
    web_host: str
    web_port: int
    virustotal_api_key: str | None
    ntfy_url: str | None
    raw: dict[str, Any]

    @property
    def monitor(self) -> dict[str, Any]:
        return self.raw.get("monitor", {})

    @property
    def rules(self) -> dict[str, Any]:
        return self.raw.get("rules", {})

    @property
    def scoring(self) -> dict[str, Any]:
        return self.raw.get("scoring", {})

    @property
    def features(self) -> dict[str, Any]:
        return self.raw.get("features", {})

    @property
    def backup(self) -> dict[str, Any]:
        return self.raw.get("backup", {})

    @property
    def restore(self) -> dict[str, Any]:
        return self.raw.get("restore", {})


def load_settings(require_discord: bool = True) -> Settings:
    config_path = Path(os.getenv("MONITOR_CONFIG", "/app/config.yaml"))
    if not config_path.exists():
        local = Path(__file__).resolve().parent.parent / "config.yaml"
        config_path = local if local.exists() else config_path
    raw: dict[str, Any] = {}
    if config_path.exists():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    token = os.getenv("DISCORD_TOKEN", "")
    channel_raw = os.getenv("DISCORD_TARGET_CHANNEL_ID", "0")
    if require_discord and not token:
        raise RuntimeError("DISCORD_TOKEN is required")
    try:
        channel_id = int(channel_raw)
    except ValueError as exc:
        raise RuntimeError("DISCORD_TARGET_CHANNEL_ID must be numeric") from exc
    if require_discord and channel_id <= 0:
        raise RuntimeError("DISCORD_TARGET_CHANNEL_ID is required")

    web = raw.get("webui", {})
    return Settings(
        token=token,
        target_channel_id=channel_id,
        config_path=config_path,
        db_path=Path(os.getenv("MONITOR_DB", "/app/data/monitor.db")),
        log_file=Path(os.getenv("LOG_FILE", "/app/logs/discord_monitor.log")),
        backup_key=os.getenv("BACKUP_KEY") or None,
        web_host=os.getenv("WEB_HOST", str(web.get("host", "0.0.0.0"))),
        web_port=int(os.getenv("WEB_PORT", str(web.get("port", 8080)))),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        ntfy_url=os.getenv("NTFY_URL") or None,
        raw=raw,
    )
