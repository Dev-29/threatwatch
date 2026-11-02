"""Dark web monitoring orchestration: watchlist -> connectors -> score -> persist -> alert."""

from __future__ import annotations

import asyncio
import hashlib
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import get_settings
from ...core import http
from ...core.alerts import raise_alert
from ...db import session_scope
from ...models import Asset, Exposure, utcnow
from . import connectors as cx
from .scoring import score_exposure

log = logging.getLogger(__name__)

MONITORED_TYPES = ("domain", "email", "executive", "keyword", "brand")


def query_plan(asset: Asset) -> list[tuple[str, str]]:
    """Which (term kind, term) pairs to search for an asset."""
    v = asset.value.strip()
    if asset.type == "email":
        return [("email", v.lower())]
    if asset.type == "domain":
        return [("domain", v.lower())]
    if asset.type in ("keyword", "brand"):
        return [("keyword", v)]
    if asset.type == "executive":
        meta = asset.meta or {}
        plan = [("email", e.lower()) for e in meta.get("emails", []) if e]
        plan += [("keyword", u) for u in meta.get("usernames", []) if u]
        plan.append(("name", v))
        return plan
    return []


def fingerprint(asset_id: int, f: cx.LeakFinding) -> str:
    key = f"{asset_id}|{f.source}|{(f.identifier or '').lower()}|{f.title.lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


def upsert_exposure(db: Session, asset: Asset, f: cx.LeakFinding) -> tuple[Exposure, bool]:
    fp = fingerprint(asset.id, f)
    score, severity, factors = score_exposure(
        source_type=f.source_type, data_classes=f.data_classes, has_password=f.has_password,
        password_plaintext=f.password_plaintext, leaked_at=f.leaked_at, credibility=f.credibility,
        asset_type=asset.type, asset_criticality=asset.criticality,
    )
    exp = db.scalar(select(Exposure).where(Exposure.fingerprint == fp))
    created = exp is None
    if created:
        exp = Exposure(asset_id=asset.id, fingerprint=fp, first_seen=utcnow(), status="new")
        db.add(exp)
    exp.source, exp.source_type, exp.title = f.source, f.source_type, f.title[:500]
    exp.identifier, exp.description, exp.url = f.identifier, f.description, f.url
    exp.data_classes, exp.has_password, exp.password_plaintext = f.data_classes, f.has_password, f.password_plaintext
    exp.record_count, exp.leaked_at = f.record_count, f.leaked_at
    exp.risk_score, exp.severity, exp.score_factors = score, severity, factors
    exp.raw = {**f.raw, "credibility": f.credibility, "verified": f.verified}
    exp.last_seen = utcnow()
    db.flush()
    return exp, created


def alert_for(db: Session, asset: Asset, exp: Exposure) -> bool:
    if exp.status in ("remediated", "false_positive"):
        return False
    who = asset.label or asset.value
    a = raise_alert(
        db, module="darkweb", severity=exp.severity,
        title=f"{exp.source_type.replace('_', ' ').title()} exposure for {who}: {exp.title}",
        description=(f"Identifier: {exp.identifier}. Source: {exp.source}. Data: {', '.join(exp.data_classes[:8])}. "
                     f"Risk score {exp.risk_score}/100."),
        ref_type="exposure", ref_id=exp.id, dedup_key=f"exposure:{exp.fingerprint}",
    )
    return a is not None


async def scan_asset_findings(asset_snapshot: dict, connectors: list[cx.Connector]) -> tuple[list[cx.LeakFinding], dict]:
    plan = asset_snapshot["plan"]
    findings: list[cx.LeakFinding] = []
    errors: dict[str, str] = {}
    async with http.client(timeout=30) as c:
        async def run(con: cx.Connector, kind: str, term: str):
            try:
                return await con.search(c, kind, term)
            except Exception as exc:  # noqa: BLE001 - a failing source must not stop the scan
                log.warning("connector %s failed for %s: %s", con.name, term, exc)
                errors[con.name] = f"{type(exc).__name__}: {exc}"[:200]
                return []

        tasks = [run(con, kind, term) for kind, term in plan for con in connectors if kind in con.kinds]
        for res in await asyncio.gather(*tasks):
            findings.extend(res)
    return findings, errors


async def scan(job_id: int | None = None, asset_ids: list[int] | None = None, only: list[str] | None = None) -> dict:
    settings = get_settings()
    connectors = [c for c in cx.build(settings, only) if c.available()]
    with session_scope() as db:
        q = select(Asset).where(Asset.enabled.is_(True), Asset.type.in_(MONITORED_TYPES))
        if asset_ids:
            q = q.where(Asset.id.in_(asset_ids))
        snapshots = [{"id": a.id, "plan": query_plan(a), "value": a.value} for a in db.scalars(q)]

    stats = {"assets": len(snapshots), "findings": 0, "new_exposures": 0, "alerts": 0,
             "connectors": [c.name for c in connectors], "errors": {}}
    for snap in snapshots:
        findings, errors = await scan_asset_findings(snap, connectors)
        stats["errors"].update(errors)
        with session_scope() as db:
            asset = db.get(Asset, snap["id"])
            if asset is None:
                continue
            for f in findings:
                exp, created = upsert_exposure(db, asset, f)
                stats["findings"] += 1
                if created:
                    stats["new_exposures"] += 1
                    stats["alerts"] += alert_for(db, asset, exp)
            asset.last_scanned_at = utcnow()
    stats["message"] = (f"{stats['assets']} assets scanned with {len(connectors)} sources: "
                        f"{stats['new_exposures']} new exposures, {stats['alerts']} alerts")
    return stats
