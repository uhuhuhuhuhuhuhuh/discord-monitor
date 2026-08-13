from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def collect_account_inventory(client: Any) -> dict[str, Any]:
    user = getattr(client, "user", None)
    relationships = []
    for relationship in getattr(client, "relationships", []) or []:
        related = getattr(relationship, "user", None)
        relationships.append({
            "relationship_type": str(getattr(relationship, "type", "unknown")),
            "user_id": str(getattr(related, "id", "")),
            "username": str(related) if related else None,
            "nickname": getattr(relationship, "nickname", None),
        })

    guilds = []
    for guild in getattr(client, "guilds", []) or []:
        guilds.append({
            "guild_id": str(getattr(guild, "id", "")),
            "name": getattr(guild, "name", None),
            "owner_id": str(getattr(guild, "owner_id", "")) or None,
            "member_count": getattr(guild, "member_count", None),
            "icon": str(getattr(guild, "icon", "") or "") or None,
        })

    return {
        "format": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "account": {
            "user_id": str(getattr(user, "id", "")),
            "username": str(user) if user else None,
            "display_name": getattr(user, "display_name", None),
        },
        "relationships": relationships,
        "guilds": guilds,
    }


def write_account_inventory(client: Any, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = collect_account_inventory(client)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"account-inventory-{stamp}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
