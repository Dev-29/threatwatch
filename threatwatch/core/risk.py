"""Shared severity helpers. All modules score on 0-100 and bucket with the same thresholds."""

from __future__ import annotations

import math

from ..config import SEVERITIES

THRESHOLDS = [(85, "critical"), (65, "high"), (40, "medium"), (15, "low"), (0, "info")]


def severity_for(score: float) -> str:
    for threshold, sev in THRESHOLDS:
        if score >= threshold:
            return sev
    return "info"


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def clamp(score: float, lo: int = 0, hi: int = 100) -> int:
    return int(round(max(lo, min(hi, score))))


class Factors:
    """Accumulates an explainable score: each contribution is recorded with a reason."""

    def __init__(self, base: float = 0.0, reason: str = "base"):
        self.score = float(base)
        self.items: list[dict] = [{"factor": reason, "delta": round(base, 1)}] if base else []

    def add(self, delta: float, reason: str) -> None:
        if delta:
            self.score += delta
            self.items.append({"factor": reason, "delta": round(delta, 1)})

    def mul(self, m: float, reason: str) -> None:
        if m != 1:
            before = self.score
            self.score *= m
            self.items.append({"factor": f"{reason} (x{m:g})", "delta": round(self.score - before, 1)})

    def soft_cap(self, knee: float = 90.0, room: float = 10.0, scale: float = 30.0) -> None:
        """Compress scores above ``knee`` asymptotically toward 100 so the top tier keeps its ordering."""
        if self.score > knee:
            before = self.score
            self.score = knee + room * (1 - math.exp(-(self.score - knee) / scale))
            self.items.append({"factor": "soft cap above 90", "delta": round(self.score - before, 1)})

    def result(self) -> tuple[int, str, list[dict]]:
        s = clamp(self.score)
        return s, severity_for(s), self.items
