"""Anti-phishing endpoints: look-alike domains, URL analysis and permutation preview."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..core import jobs
from ..core.domains import to_unicode
from ..db import get_db
from ..models import LookalikeDomain
from ..modules.phishing import analyzer, permutations, service
from .common import Page, lookalike_json, paginate
from .routes_core import registrable_or_400

router = APIRouter(prefix="/phishing", tags=["anti-phishing"])


@router.get("/lookalikes")
def list_lookalikes(brand: str | None = None, severity: str | None = None, status: str | None = None,
                    technique: str | None = None, q: str | None = None, has_mx: bool | None = None,
                    live: bool | None = None, page: Page = Depends(), db: Session = Depends(get_db)):
    query = select(LookalikeDomain).order_by(LookalikeDomain.risk_score.desc(), LookalikeDomain.id.desc())
    if brand:
        query = query.where(LookalikeDomain.brand_domain == brand)
    if severity:
        query = query.where(LookalikeDomain.severity.in_(severity.split(",")))
    if status:
        query = query.where(LookalikeDomain.status.in_(status.split(",")))
    if technique:
        query = query.where(LookalikeDomain.technique == technique)
    if q:
        query = query.where(or_(LookalikeDomain.domain.ilike(f"%{q}%"), LookalikeDomain.domain_unicode.ilike(f"%{q}%")))
    if has_mx is not None:
        n = func.json_array_length(LookalikeDomain.dns_mx)
        query = query.where(n > 0 if has_mx else n == 0)
    if live is not None:
        query = query.where(LookalikeDomain.http_status.is_not(None) if live else LookalikeDomain.http_status.is_(None))
    return paginate(db, query, page, lookalike_json)


class LookalikePatch(BaseModel):
    status: Literal["new", "monitoring", "takedown_requested", "taken_down", "benign"]


@router.patch("/lookalikes/{lid}")
def update_lookalike(lid: int, body: LookalikePatch, db: Session = Depends(get_db)):
    row = db.get(LookalikeDomain, lid)
    if not row:
        raise HTTPException(404, "look-alike not found")
    row.status = body.status
    return lookalike_json(row)


class PhishScanIn(BaseModel):
    domains: list[str] | None = None


@router.post("/scan", status_code=202)
async def start_scan(body: PhishScanIn | None = None):
    domains = [registrable_or_400(d) for d in (body.domains if body and body.domains else [])] or None

    async def job(job_id):
        return await service.scan(job_id, domains=domains)

    target = ",".join(domains) if domains else "all"
    if not jobs.submit("phishing_scan", job, target=target):
        raise HTTPException(409, "a look-alike scan is already running for these domains")
    return {"status": "started", "kind": "phishing_scan", "target": target}


class AnalyzeIn(BaseModel):
    url: str = Field(min_length=3, max_length=4000)
    fetch: bool = True


@router.post("/analyze")
async def analyze_url(body: AnalyzeIn, db: Session = Depends(get_db)):
    try:
        return await analyzer.analyze(body.url, db, fetch=body.fetch)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/permutations")
def preview_permutations(domain: str, limit: int = Query(500, ge=1, le=10000)):
    """Generate candidate look-alikes without any network activity (preview / export to blocklists)."""
    d = registrable_or_400(domain)
    cands = permutations.generate(d, limit=limit)
    by_tech: dict[str, int] = {}
    for c in cands:
        by_tech[c.technique] = by_tech.get(c.technique, 0) + 1
    return {"domain": d, "count": len(cands), "by_technique": by_tech,
            "candidates": [{"domain": c.domain, "unicode": to_unicode(c.domain), "technique": c.technique}
                           for c in cands]}
