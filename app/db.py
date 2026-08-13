from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    author_id TEXT,
    guild_id TEXT,
    channel_id TEXT,
    message_id TEXT,
    direction TEXT,
    summary TEXT,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    domains_json TEXT NOT NULL DEFAULT '[]',
    content_redacted TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE TABLE IF NOT EXISTS contacts (
    user_id TEXT PRIMARY KEY,
    username TEXT,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    message_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS guilds (
    guild_id TEXT PRIMARY KEY,
    name TEXT,
    owner_id TEXT,
    member_count INTEGER,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add_event(self, **event: Any) -> int:
        fields = {
            "event_type": event.get("event_type", "unknown"),
            "severity": event.get("severity", "INFO"),
            "score": int(event.get("score", 0)),
            "author_id": event.get("author_id"),
            "guild_id": event.get("guild_id"),
            "channel_id": event.get("channel_id"),
            "message_id": event.get("message_id"),
            "direction": event.get("direction"),
            "summary": event.get("summary"),
            "reasons_json": json.dumps(event.get("reasons", []), ensure_ascii=False),
            "domains_json": json.dumps(event.get("domains", []), ensure_ascii=False),
            "content_redacted": event.get("content_redacted"),
        }
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO events(event_type,severity,score,author_id,guild_id,channel_id,message_id,direction,summary,reasons_json,domains_json,content_redacted)
                VALUES(:event_type,:severity,:score,:author_id,:guild_id,:channel_id,:message_id,:direction,:summary,:reasons_json,:domains_json,:content_redacted)""",
                fields,
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            critical = self._conn.execute("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'").fetchone()[0]
            high = self._conn.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
            guilds = self._conn.execute("SELECT COUNT(*) FROM guilds WHERE active=1").fetchone()[0]
            contacts = self._conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        return {"events": total, "critical": critical, "high": high, "guilds": guilds, "contacts": contacts}

    def touch_contact(self, user_id: str, username: str | None) -> bool:
        with self._lock:
            existed = self._conn.execute("SELECT 1 FROM contacts WHERE user_id=?", (user_id,)).fetchone() is not None
            self._conn.execute(
                """INSERT INTO contacts(user_id,username,message_count) VALUES(?,?,1)
                ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,last_seen=CURRENT_TIMESTAMP,message_count=contacts.message_count+1""",
                (user_id, username),
            )
            self._conn.commit()
        return not existed

    def upsert_guild(self, guild_id: str, name: str, owner_id: str | None, member_count: int | None, active: bool = True) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO guilds(guild_id,name,owner_id,member_count,active) VALUES(?,?,?,?,?)
                ON CONFLICT(guild_id) DO UPDATE SET name=excluded.name,owner_id=excluded.owner_id,member_count=excluded.member_count,last_seen=CURRENT_TIMESTAMP,active=excluded.active""",
                (guild_id, name, owner_id, member_count, 1 if active else 0),
            )
            self._conn.commit()

    def export_inventory(self) -> dict[str, Any]:
        with self._lock:
            contacts = [dict(r) for r in self._conn.execute("SELECT * FROM contacts ORDER BY username").fetchall()]
            guilds = [dict(r) for r in self._conn.execute("SELECT * FROM guilds ORDER BY name").fetchall()]
            events = [dict(r) for r in self._conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500").fetchall()]
        return {"contacts": contacts, "guilds": guilds, "recent_security_events": events}
