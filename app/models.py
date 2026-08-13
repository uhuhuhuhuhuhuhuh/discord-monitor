from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(slots=True)
class Reason:
    code: str
    detail: str
    score: int


@dataclass(slots=True)
class DetectionResult:
    suspicious: bool
    score: int
    severity: str
    reasons: list[Reason] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    redacted_text: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = [asdict(r) for r in self.reasons]
        return data


def severity_for(score: int) -> str:
    if score >= 100:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"
