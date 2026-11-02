"""IOC scoring model (documented in docs/SCORING.md).

    confidence = min(100, max(source confidence) + corroboration bonus)
    score      = confidence x threat-type weight x recency decay
"""

from __future__ import annotations

from datetime import datetime

from ...core.risk import Factors, clamp, severity_for
from ...models import utcnow

THREAT_WEIGHT = {
    "botnet_c2": 1.0, "c2": 1.0, "ransomware": 1.0, "exploited_vulnerability": 0.95,
    "malware_download": 0.95, "payload_delivery": 0.95, "malware": 0.9, "phishing": 0.9,
    "credential_theft": 0.9, "hijacked_netblock": 0.85, "compromised": 0.8, "malicious_activity": 0.7,
    "brute_force": 0.65, "scanner": 0.6, "cryptomining": 0.6, "spam": 0.5,
}
DEFAULT_WEIGHT = 0.6

# Days after which an indicator's relevance halves. None = no decay (vulnerabilities).
HALF_LIFE = {
    "ipv4": 30, "ipv6": 30, "cidr": 180, "domain": 90, "url": 30, "email": 180,
    "md5": 365, "sha1": 365, "sha256": 365, "x509-sha1": 180, "cve": None,
}
DECAY_FLOOR = 0.35
CORROBORATION_PER_SOURCE = 8
CORROBORATION_CAP = 25


def confidence_of(source_conf: dict[str, int]) -> int:
    if not source_conf:
        return 0
    base = max(source_conf.values())
    bonus = min(CORROBORATION_CAP, CORROBORATION_PER_SOURCE * (len(source_conf) - 1))
    return clamp(base + bonus)


def score_indicator(
    ioc_type: str,
    source_conf: dict[str, int],
    threat_types: list[str],
    tags: list[str],
    last_seen: datetime,
    now: datetime | None = None,
    explain: bool = False,
):
    now = now or utcnow()
    f = Factors(max(source_conf.values()) if source_conf else 0, "highest source reliability")
    n = len(source_conf)
    if n > 1:
        f.add(min(CORROBORATION_CAP, CORROBORATION_PER_SOURCE * (n - 1)), f"corroborated by {n} sources")
    confidence = clamp(f.score)
    weight = max([THREAT_WEIGHT.get(t, DEFAULT_WEIGHT) for t in threat_types] or [DEFAULT_WEIGHT])
    if "ransomware" in tags:
        weight = max(weight, 1.0)
    f.mul(weight, "threat-type weight")
    hl = HALF_LIFE.get(ioc_type)
    if hl:
        age = max(0, (now - last_seen).days)
        decay = max(DECAY_FLOOR, 0.5 ** (age / hl))
        if decay < 0.999:
            f.mul(round(decay, 2), f"recency decay ({age}d old, half-life {hl}d)")
    score = clamp(f.score)
    if explain:
        return score, confidence, severity_for(score), f.items
    return score, confidence, severity_for(score)
