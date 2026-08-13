from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque

from .models import Reason


class BehaviorTracker:
    def __init__(self, cfg: dict):
        monitor = cfg.get("monitor", {})
        self.velocity_window = int(monitor.get("outgoing_velocity_window_seconds", 300))
        self.velocity_threshold = int(monitor.get("outgoing_velocity_threshold", 12))
        self.repeat_threshold = int(monitor.get("repeated_message_threshold", 4))
        self.outgoing_times: deque[float] = deque()
        self.hash_times: dict[str, deque[float]] = defaultdict(deque)
        self.guild_join_times: deque[float] = deque()
        self.scoring = cfg.get("scoring", {})

    def _trim(self, q: deque[float], now: float, window: int) -> None:
        while q and now - q[0] > window:
            q.popleft()

    def message_reasons(self, text: str, *, outgoing: bool) -> list[Reason]:
        if not outgoing:
            return []
        now = time.time()
        reasons: list[Reason] = []
        self.outgoing_times.append(now)
        self._trim(self.outgoing_times, now, self.velocity_window)
        if len(self.outgoing_times) >= self.velocity_threshold:
            reasons.append(Reason("high_velocity", f"{len(self.outgoing_times)} outgoing messages in {self.velocity_window}s", int(self.scoring.get("high_velocity", 35))))
        digest = hashlib.sha256((text or "").strip().casefold().encode()).hexdigest()
        q = self.hash_times[digest]
        q.append(now)
        self._trim(q, now, self.velocity_window)
        if text.strip() and len(q) >= self.repeat_threshold:
            reasons.append(Reason("repeated_message", f"Repeated outgoing message {len(q)} times", int(self.scoring.get("repeated_message", 25))))
        return reasons

    def guild_join_reasons(self) -> list[Reason]:
        now = time.time()
        self.guild_join_times.append(now)
        self._trim(self.guild_join_times, now, 600)
        if len(self.guild_join_times) >= 4:
            return [Reason("rapid_guild_joins", f"Joined {len(self.guild_join_times)} guilds within 10 minutes", int(self.scoring.get("rapid_guild_joins", 40)))]
        return []
