from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_manual_migration_plan(inventory: dict[str, Any], target_minutes: int = 30) -> dict[str, Any]:
    target_minutes = max(20, min(int(target_minutes), 40))
    actions: list[dict[str, Any]] = []

    for relationship in inventory.get("relationships", []):
        actions.append({
            "action": "review_relationship",
            "status": "MANUAL_REQUIRED",
            "target": relationship.get("user_id"),
            "details": relationship,
        })

    for guild in inventory.get("guilds", []):
        actions.append({
            "action": "review_guild_membership",
            "status": "MANUAL_REQUIRED",
            "target": guild.get("guild_id"),
            "details": guild,
        })

    delay = round(target_minutes * 60 / max(1, len(actions)), 2)
    return {
        "target_minutes": target_minutes,
        "suggested_seconds_between_manual_actions": delay,
        "action_count": len(actions),
        "note": "This plan preserves order and pacing for manual recovery. It does not submit friend requests or guild joins automatically.",
        "actions": actions,
    }


def plan_from_file(inventory_path: Path, output_path: Path, target_minutes: int = 30) -> Path:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    plan = build_manual_migration_plan(inventory, target_minutes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path
