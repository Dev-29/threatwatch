"""Shared API plumbing: authentication (JWT bearer tokens + API key), pagination and ORM -> JSON serialisers."""

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


def bearer_token(request: Request) -> str | None:
    """The token from ``Authorization: Bearer <token>``, or the ``access_token`` query parameter (used by
    plain-link downloads, which cannot set an Authorization header). None if neither is present."""
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return request.query_params.get("access_token") or None


def api_key_valid(request: Request) -> bool:
    """True if the configured TW_API_KEY was supplied via X-API-Key, ?api_key= or a Bearer header."""
    expected = get_settings().api_key
    supplied = request.headers.get("x-api-key") or request.query_params.get("api_key") or bearer_token(request) or ""
    return bool(expected and supplied) and hmac.compare_digest(supplied.encode(), expected.encode())


def identify(request: Request, db: Session) -> tuple[str | None, dict | None]:
    """Who is calling: ("jwt", claims) | ("api_key", None) | ("open", None) | (None, None).

    A bearer token is tried as a JWT first; if it is instead the instance API key it matches here.
    """
    claims = auth.decode_access_token(bearer_token(request))
    if claims is not None:
        return "jwt", claims
    if api_key_valid(request):
        return "api_key", None
    if not get_settings().api_key and auth.user_count(db) == 0:
        return "open", None  # nothing configured yet: behave like before accounts existed
    return None, None


def require_auth(request: Request, db: Session = Depends(get_db)) -> None:
    """Gate for /api/v1 and /taxii2.

    Accepts a JWT (``Authorization: Bearer <token>``) or the TW_API_KEY (X-API-Key, Bearer or ?api_key=).
    Viewers are read-only. With no users and no API key configured the instance is open, as in earlier
    versions. No CSRF defence is needed: the Authorization header is never attached automatically by the
    browser the way a cookie is, so cross-site requests cannot authenticate.
    """
    mode, claims = identify(request, db)
    if mode is None:
        raise HTTPException(status_code=401, detail="authentication required")
    request.state.auth_mode = mode
    request.state.claims = claims
    request.state.user_id = int(claims["sub"]) if claims else None
    request.state.role = claims["role"] if claims else ("admin" if mode == "api_key" else None)
    request.state.username = claims.get("username") if claims else None
    if mode == "jwt" and request.method not in SAFE_METHODS and request.state.role == "viewer":
        raise HTTPException(status_code=403, detail="viewer accounts are read-only")


def require_admin(request: Request) -> None:
    """Use after require_auth. The API key counts as admin (it is the instance's root secret)."""
    mode = getattr(request.state, "auth_mode", None)
    role = getattr(request.state, "role", None)
    if mode == "api_key" or role == "admin":
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
