from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from typing import Any


class AlertGate:
    """In-memory alert deduplication and cooldown control."""

    def __init__(self, cfg: dict[str, Any]):
        monitor = cfg.get("monitor", {})
        self.dedupe_window = int(monitor.get("dedupe_window_seconds", 1800))
        self.cooldown = int(monitor.get("alert_cooldown_seconds", 120))
        self._fingerprints: dict[str, float] = {}
        self._subject_times: dict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def fingerprint(payload: dict[str, Any]) -> str:
        stable = {
            "event": payload.get("event"),
            "author_id": payload.get("author_id"),
            "guild_id": payload.get("guild_id"),
            "domains": sorted(payload.get("domains") or []),
            "reasons": sorted(payload.get("reason_codes") or payload.get("reasons") or []),
        }
        raw = json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def allow(self, payload: dict[str, Any]) -> tuple[bool, str | None]:
        now = time.time()
        fp = self.fingerprint(payload)
        previous = self._fingerprints.get(fp)
        if previous is not None and now - previous < self.dedupe_window:
            return False, "duplicate"

        subject = str(payload.get("author_id") or payload.get("guild_id") or "global")
        q = self._subject_times[subject]
        while q and now - q[0] > self.cooldown:
            q.popleft()

        severity = str(payload.get("severity", "INFO")).upper()
        if q and severity not in {"HIGH", "CRITICAL"}:
            return False, "cooldown"

        self._fingerprints[fp] = now
        q.append(now)

        cutoff = now - self.dedupe_window
        if len(self._fingerprints) > 5000:
            self._fingerprints = {key: ts for key, ts in self._fingerprints.items() if ts >= cutoff}
        return True, None
