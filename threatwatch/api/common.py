"""Shared API plumbing: authentication (API key + browser sessions), pagination and ORM -> JSON serialisers."""

from __future__ import annotations

import hmac
from datetime import datetime

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..core import auth
from ..db import get_db
from ..models import Alert, Asset, Exposure, JobRun, LookalikeDomain, User


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "ThreatWatch"


def _supplied_api_key(request: Request) -> str:
    supplied = request.headers.get("x-api-key") or request.query_params.get("api_key") or ""
    auth = request.headers.get("authorization", "")
    if not supplied and auth.lower().startswith("bearer "):
        supplied = auth[7:]
    return supplied


def api_key_valid(request: Request) -> bool:
    expected = get_settings().api_key
    supplied = _supplied_api_key(request)
    return bool(expected and supplied) and hmac.compare_digest(supplied.encode(), expected.encode())


def has_csrf_header(request: Request) -> bool:
    """Cookie-authenticated writes must carry a custom header. Browsers refuse to add custom headers to
    cross-site requests without a CORS preflight (which this app never grants), so this blocks CSRF."""
    return request.headers.get(CSRF_HEADER) == CSRF_VALUE


def identify(request: Request, db: Session) -> tuple[str | None, User | None]:
    """Who is calling: ("api_key", None) | ("session", user) | ("open", None) | (None, None)."""
    if api_key_valid(request):
        return "api_key", None
    user = auth.resolve_session(db, request.cookies.get(auth.COOKIE_NAME))
    if user is not None:
        return "session", user
    if not get_settings().api_key and auth.user_count(db) == 0:
        return "open", None  # nothing configured yet: behave like before accounts existed
    return None, None


def require_auth(request: Request, db: Session = Depends(get_db)) -> None:
    """Gate for /api/v1 and /taxii2.

    Accepts the TW_API_KEY (X-API-Key, Bearer or ?api_key=) or a browser session cookie. Viewers are
    read-only. With no users and no API key configured the instance is open, as in earlier versions.
    """
    mode, user = identify(request, db)
    if mode is None:
        raise HTTPException(status_code=401, detail="authentication required")
    request.state.auth_mode, request.state.user = mode, user
    if mode == "session" and request.method not in SAFE_METHODS:
        if not has_csrf_header(request):
            raise HTTPException(status_code=403, detail=f"missing {CSRF_HEADER} header")
        if user.role == "viewer":
            raise HTTPException(status_code=403, detail="viewer accounts are read-only")


def require_admin(request: Request) -> None:
    """Use after require_auth. The API key counts as admin (it is the instance's root secret)."""
    mode, user = getattr(request.state, "auth_mode", None), getattr(request.state, "user", None)
    if mode == "api_key" or (mode == "session" and user.role == "admin"):
        return
    raise HTTPException(status_code=403, detail="admin role required")


class Page:
    def __init__(self, limit: int = Query(50, ge=1, le=5000), offset: int = Query(0, ge=0)):
        self.limit, self.offset = limit, offset


def paginate(db: Session, q, page: Page, serialize) -> dict:
    total = db.scalar(select(func.count()).select_from(q.order_by(None).subquery()))
    items = db.scalars(q.limit(page.limit).offset(page.offset)).all()
    return {"total": total, "limit": page.limit, "offset": page.offset, "items": [serialize(i) for i in items]}


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def asset_json(a: Asset) -> dict:
    return {"id": a.id, "type": a.type, "value": a.value, "label": a.label, "criticality": a.criticality,
            "meta": a.meta or {}, "enabled": a.enabled, "created_at": iso(a.created_at),
            "last_scanned_at": iso(a.last_scanned_at)}


def exposure_json(e: Exposure, full: bool = False) -> dict:
    d = {"id": e.id, "asset_id": e.asset_id, "asset": e.asset.value if e.asset else None,
         "asset_type": e.asset.type if e.asset else None, "asset_label": e.asset.label if e.asset else None,
         "source": e.source, "source_type": e.source_type, "title": e.title, "identifier": e.identifier,
         "data_classes": e.data_classes, "has_password": e.has_password, "password_plaintext": e.password_plaintext,
         "record_count": e.record_count, "leaked_at": iso(e.leaked_at), "first_seen": iso(e.first_seen),
         "last_seen": iso(e.last_seen), "risk_score": e.risk_score, "severity": e.severity, "status": e.status,
         "url": e.url}
    if full:
        d.update({"description": e.description, "score_factors": e.score_factors, "raw": e.raw})
    return d


def lookalike_json(l: LookalikeDomain) -> dict:
    return {"id": l.id, "brand_domain": l.brand_domain, "domain": l.domain, "domain_unicode": l.domain_unicode,
            "technique": l.technique, "registered": l.registered, "dns_a": l.dns_a, "dns_mx": l.dns_mx,
            "dns_ns": l.dns_ns, "created_date": iso(l.created_date), "registrar": l.registrar,
            "http_status": l.http_status, "final_url": l.final_url, "title": l.title, "similarity": l.similarity,
            "has_login_form": l.has_login_form, "parked": l.parked, "in_threat_feed": l.in_threat_feed,
            "risk_score": l.risk_score, "severity": l.severity, "score_factors": l.score_factors,
            "status": l.status, "first_seen": iso(l.first_seen), "last_checked": iso(l.last_checked)}


def alert_json(a: Alert) -> dict:
    return {"id": a.id, "module": a.module, "severity": a.severity, "title": a.title, "description": a.description,
            "ref_type": a.ref_type, "ref_id": a.ref_id, "status": a.status, "created_at": iso(a.created_at),
            "updated_at": iso(a.updated_at), "notified": a.notified}


def job_json(j: JobRun) -> dict:
    return {"id": j.id, "kind": j.kind, "target": j.target, "trigger": j.trigger, "status": j.status,
            "started_at": iso(j.started_at), "finished_at": iso(j.finished_at), "message": j.message,
            "stats": j.stats}


def user_json(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "disabled": u.disabled,
            "created_at": iso(u.created_at), "last_login_at": iso(u.last_login_at),
            "password_changed_at": iso(u.password_changed_at)}
