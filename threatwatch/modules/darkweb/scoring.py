"""Exposure risk model (documented in docs/SCORING.md).

score = (source-type base + data sensitivity + recency + asset-type bonus)
        x asset criticality x source credibility, soft-capped above 90
"""

from __future__ import annotations

from datetime import datetime

from ...core.risk import Factors
from ...models import utcnow

SOURCE_BASE = {
    "ransomware_leak": 50, "stealer_log": 45, "combolist": 30, "code_repo": 30,
    "forum": 25, "paste": 25, "breach": 20,
}

SENSITIVE = [
    # (keywords, plaintext bonus, otherwise bonus, label)
    (("password", "credential", "auth token", "session", "cookie", "private key", "api key", "security question",
      "password hint"), 20, 12, "credentials exposed"),
    (("credit card", "bank account", "payment", "financial", "crypto wallet", "partial credit"), 10, 10,
     "financial data"),
    (("social security", "ssn", "passport", "government issued", "national id", "tax", "driver"), 10, 10,
     "government ID"),
    (("phone", "physical address", "date of birth", "dates of birth", "geographic", "address"), 4, 4, "personal data"),
    (("corporate data", "source code", "corporate urls"), 8, 8, "corporate data"),
]

CRITICALITY = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low": 0.85}


def score_exposure(
    *,
    source_type: str,
    data_classes: list[str],
    has_password: bool,
    password_plaintext: bool,
    leaked_at: datetime | None,
    credibility: float,
    asset_type: str,
    asset_criticality: str,
    now: datetime | None = None,
) -> tuple[int, str, list[dict]]:
    now = now or utcnow()
    f = Factors(SOURCE_BASE.get(source_type, 30), f"source type: {source_type.replace('_', ' ')}")

    text = " ".join(data_classes).lower()
    for keywords, plain_bonus, bonus, label in SENSITIVE:
        hit = any(k in text for k in keywords) or (label == "credentials exposed" and has_password)
        if hit:
            if label == "credentials exposed" and password_plaintext:
                f.add(plain_bonus, "plaintext / easily cracked credentials")
            else:
                f.add(bonus, label)

    if leaked_at:
        age = (now - leaked_at).days
        if age <= 30:
            f.add(15, "leaked in the last 30 days")
        elif age <= 180:
            f.add(10, "leaked in the last 6 months")
        elif age <= 365:
            f.add(5, "leaked in the last year")
        elif age > 365 * 5:
            f.add(-10, "older than 5 years")

    if asset_type == "executive":
        f.add(8, "executive (BEC / whaling target)")
    elif asset_type == "domain" and source_type in ("stealer_log", "ransomware_leak"):
        f.add(5, "organisation-wide exposure")

    f.mul(CRITICALITY.get(asset_criticality, 1.0), f"asset criticality {asset_criticality}")
    f.mul(round(0.6 + 0.4 * max(0.0, min(1.0, credibility)), 2), "source credibility")
    f.soft_cap()
    return f.result()
