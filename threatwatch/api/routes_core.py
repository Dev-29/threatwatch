"""Dashboard, watchlist (assets), alerts, jobs and settings endpoints."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import __version__
from ..config import get_settings
from ..core import jobs
from ..core.domains import is_valid_hostname, registrable
from ..db import get_db
from ..models import Alert, AsmScan, Asset, Exposure, FeedState, Indicator, JobRun, LookalikeDomain, utcnow
from ..modules.intel import attack
from .common import Page, alert_json, asset_json, job_json, paginate

router = APIRouter()

AssetType = Literal["domain", "email", "executive", "keyword", "brand"]
Criticality = Literal["low", "medium", "high", "critical"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ------------------------------------------------------------------ dashboard
@router.get("/dashboard", tags=["dashboard"])
def dashboard(db: Session = Depends(get_db)):
    now = utcnow()

    def grouped(col, *where):
        return {k: v for k, v in db.execute(select(col, func.count()).where(*where).group_by(col)).all()}

    alerts_open = grouped(Alert.severity, Alert.status == "open")
    since = now - timedelta(days=13)
    trend_rows = db.execute(
        select(func.date(Alert.created_at), Alert.severity, func.count())
        .where(Alert.created_at >= since.replace(hour=0, minute=0, second=0, microsecond=0))
        .group_by(func.date(Alert.created_at), Alert.severity)).all()
    days = [(since + timedelta(days=i)).date().isoformat() for i in range(14)]
    trend = {d: {} for d in days}
    for day, sev, n in trend_rows:
        trend.setdefault(str(day), {})[sev] = n

    technique_counts = {}
    for (techs,) in db.execute(select(Indicator.attack_techniques).where(Indicator.active.is_(True))
                               .order_by(Indicator.score.desc()).limit(20000)):
        for t in techs or []:
            technique_counts[t] = technique_counts.get(t, 0) + 1
    top_tech = sorted(technique_counts.items(), key=lambda x: -x[1])[:8]

    fam_counts: dict[str, int] = {}
    for (fams,) in db.execute(select(Indicator.malware_families).where(
            Indicator.active.is_(True), func.json_array_length(Indicator.malware_families) > 0).limit(20000)):
        for f in fams or []:
            fam_counts[f] = fam_counts.get(f, 0) + 1

    latest_scans = []
    for root, in db.execute(select(AsmScan.root_domain).where(AsmScan.status == "done").distinct()):
        s = db.scalar(select(AsmScan).where(AsmScan.root_domain == root, AsmScan.status == "done")
                      .order_by(AsmScan.id.desc()).limit(1))
        latest_scans.append({"id": s.id, "root_domain": s.root_domain, "grade": s.grade, "risk_score": s.risk_score,
                             "finished_at": s.finished_at.isoformat() + "Z" if s.finished_at else None,
                             "by_severity": (s.summary or {}).get("by_severity", {}),
                             "hosts": (s.summary or {}).get("hosts_resolved", 0)})

    feeds = db.scalars(select(FeedState)).all()
    return {
        "alerts": {"open_by_severity": alerts_open, "open_total": sum(alerts_open.values()), "trend": trend,
                   "recent": [alert_json(a) for a in db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8))]},
        "darkweb": {
            "total": db.scalar(select(func.count(Exposure.id))) or 0,
            "open_by_severity": grouped(Exposure.severity, Exposure.status.in_(["new", "investigating"])),
            "by_source_type": grouped(Exposure.source_type),
            "new_7d": db.scalar(select(func.count(Exposure.id)).where(Exposure.first_seen >= now - timedelta(days=7))) or 0,
            "credentials": db.scalar(select(func.count(Exposure.id)).where(Exposure.has_password.is_(True))) or 0,
        },
        "intel": {
            "active": db.scalar(select(func.count(Indicator.id)).where(Indicator.active.is_(True))) or 0,
            "by_type": grouped(Indicator.type, Indicator.active.is_(True)),
            "by_severity": grouped(Indicator.severity, Indicator.active.is_(True)),
            "new_24h": db.scalar(select(func.count(Indicator.id)).where(Indicator.created_at >= now - timedelta(days=1))) or 0,
            "feeds_ok": sum(1 for f in feeds if f.last_status == "ok"),
            "feeds_error": sum(1 for f in feeds if f.last_status == "error"),
            "top_techniques": [{**attack.technique(t), "count": n} for t, n in top_tech],
            "top_malware": sorted(fam_counts.items(), key=lambda x: -x[1])[:8],
        },
        "phishing": {
            "registered": db.scalar(select(func.count(LookalikeDomain.id))) or 0,
            "high_risk": db.scalar(select(func.count(LookalikeDomain.id)).where(LookalikeDomain.risk_score >= 65)) or 0,
            "with_mx": db.scalar(select(func.count(LookalikeDomain.id)).where(func.json_array_length(LookalikeDomain.dns_mx) > 0)) or 0,
            "by_severity": grouped(LookalikeDomain.severity),
        },
        "asm": {"latest": latest_scans},
        "watchlist": grouped(Asset.type, Asset.enabled.is_(True)),
        "jobs": {"running": [{"kind": k, "target": t} for k, t in jobs.running_jobs()],
                 "recent": [job_json(j) for j in db.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(6))]},
    }


# ------------------------------------------------------------------ watchlist
class AssetIn(BaseModel):
    type: AssetType
    value: str = Field(min_length=2, max_length=255)
    label: str | None = None
    criticality: Criticality = "medium"
    meta: dict = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("value")
    @classmethod
    def strip(cls, v: str) -> str:
        return v.strip()


class AssetPatch(BaseModel):
    label: str | None = None
    criticality: Criticality | None = None
    meta: dict | None = None
    enabled: bool | None = None


def _validate_asset(a: AssetIn) -> AssetIn:
    if a.type == "domain":
        a.value = a.value.lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not is_valid_hostname(a.value):
            raise HTTPException(422, "invalid domain")
    elif a.type == "email":
        a.value = a.value.lower()
        if not EMAIL_RE.match(a.value):
            raise HTTPException(422, "invalid email address")
    elif a.type == "executive":
        emails = [e.strip().lower() for e in a.meta.get("emails", []) if e and e.strip()]
        bad = [e for e in emails if not EMAIL_RE.match(e)]
        if bad:
            raise HTTPException(422, f"invalid executive email(s): {', '.join(bad)}")
        a.meta["emails"] = emails
        if a.criticality == "medium":
            a.criticality = "high"
    return a


@router.get("/assets", tags=["watchlist"])
def list_assets(type: AssetType | None = None, db: Session = Depends(get_db)):
    q = select(Asset).order_by(Asset.type, Asset.value)
    if type:
        q = q.where(Asset.type == type)
    rows = db.scalars(q).all()
    counts = dict(db.execute(select(Exposure.asset_id, func.count()).group_by(Exposure.asset_id)).all())
    return [{**asset_json(a), "exposures": counts.get(a.id, 0)} for a in rows]


@router.post("/assets", tags=["watchlist"], status_code=201)
def create_asset(body: AssetIn, db: Session = Depends(get_db)):
    body = _validate_asset(body)
    a = Asset(**body.model_dump())
    db.add(a)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"{body.type} '{body.value}' is already on the watchlist")
    return asset_json(a)


@router.patch("/assets/{asset_id}", tags=["watchlist"])
def update_asset(asset_id: int, body: AssetPatch, db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "asset not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(a, k, v)
    return asset_json(a)


@router.delete("/assets/{asset_id}", tags=["watchlist"], status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "asset not found")
    db.delete(a)


# ------------------------------------------------------------------ alerts
class AlertPatch(BaseModel):
    status: Literal["open", "acknowledged", "closed"]


class AlertBulk(BaseModel):
    ids: list[int]
    status: Literal["open", "acknowledged", "closed"]


@router.get("/alerts", tags=["alerts"])
def list_alerts(status: str | None = None, severity: str | None = None, module: str | None = None,
                q: str | None = None, page: Page = Depends(), db: Session = Depends(get_db)):
    query = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
    if status:
        query = query.where(Alert.status.in_(status.split(",")))
    if severity:
        query = query.where(Alert.severity.in_(severity.split(",")))
    if module:
        query = query.where(Alert.module == module)
    if q:
        query = query.where(Alert.title.ilike(f"%{q}%"))
    return paginate(db, query, page, alert_json)


@router.patch("/alerts/{alert_id}", tags=["alerts"])
def update_alert(alert_id: int, body: AlertPatch, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    a.status, a.updated_at = body.status, utcnow()
    return alert_json(a)


@router.post("/alerts/bulk", tags=["alerts"])
def bulk_alerts(body: AlertBulk, db: Session = Depends(get_db)):
    n = 0
    for a in db.scalars(select(Alert).where(Alert.id.in_(body.ids))):
        a.status, a.updated_at = body.status, utcnow()
        n += 1
    return {"updated": n}


# ------------------------------------------------------------------ jobs & settings
@router.get("/jobs", tags=["jobs"])
def list_jobs(kind: str | None = None, page: Page = Depends(), db: Session = Depends(get_db)):
    q = select(JobRun).order_by(JobRun.id.desc())
    if kind:
        q = q.where(JobRun.kind == kind)
    res = paginate(db, q, page, job_json)
    res["running"] = [{"kind": k, "target": t} for k, t in jobs.running_jobs()]
    return res


@router.get("/settings", tags=["settings"])
def settings_view():
    s = get_settings()
    return {
        "version": __version__,
        "integrations": s.integration_status(),
        "auth_enabled": bool(s.api_key),
        "database": s.database_url.split("://")[0],
        "scheduler": {"enabled": s.scheduler_enabled, "feeds_interval_minutes": s.feeds_interval_minutes,
                      "darkweb_interval_hours": s.darkweb_interval_hours,
                      "phishing_interval_hours": s.phishing_interval_hours, "asm_interval_hours": s.asm_interval_hours},
        "alerting": {"min_severity": s.alert_min_severity, "webhook": bool(s.alert_webhook_url)},
        "limits": {"feed_max_items": s.feed_max_items, "ioc_retention_days": s.ioc_retention_days,
                   "phishing_max_permutations": s.phishing_max_permutations, "asm_max_hosts": s.asm_max_hosts},
        "onion_sources": len(s.onion_source_list),
        "asm_active_default": s.asm_active_default,
        "attack_catalog_size": len(attack.catalog()),
    }


def registrable_or_400(domain: str) -> str:
    d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not is_valid_hostname(d):
        raise HTTPException(422, f"invalid domain: {domain}")
    return registrable(d) or d
