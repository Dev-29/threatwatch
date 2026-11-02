"""Threat-intelligence endpoints: indicators, feeds, ATT&CK, exports and a TAXII 2.1 server."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..config import get_settings
from ..core import jobs
from ..core.ioc import extract_iocs, host_of
from ..core.domains import registrable
from ..db import get_db
from ..models import Indicator, IndicatorSource
from ..modules.intel import attack, export, service
from ..modules.intel.feeds import FEEDS, available
from .common import Page, paginate
from ..models import utcnow

router = APIRouter(prefix="/intel", tags=["threat intel"])
taxii = APIRouter(prefix="/taxii2", tags=["TAXII 2.1"])

SORTS = {"score": Indicator.score.desc(), "recent": Indicator.last_seen.desc(), "new": Indicator.created_at.desc()}


def _json_text(col):
    """JSON list column as text - portable across SQLite and PostgreSQL."""
    return cast(col, String)


def _filters(query, *, type=None, severity=None, feed=None, technique=None, q=None, min_score=None,
             active=True, since=None, malware=None, threat_type=None):
    if type:
        query = query.where(Indicator.type.in_(type.split(",")))
    if severity:
        query = query.where(Indicator.severity.in_(severity.split(",")))
    if feed:
        query = query.where(Indicator.id.in_(select(IndicatorSource.indicator_id).where(
            IndicatorSource.feed.in_(feed.split(",")))))
    if technique:
        query = query.where(_json_text(Indicator.attack_techniques).like(f'%"{technique}"%'))
    if malware:
        query = query.where(_json_text(Indicator.malware_families).ilike(f"%{malware}%"))
    if threat_type:  # suffix match so "c2" also selects "botnet_c2"
        query = query.where(_json_text(Indicator.threat_types).like(f'%{threat_type}"%'))
    if q:
        query = query.where(Indicator.value.ilike(f"%{q.strip()}%"))
    if min_score is not None:
        query = query.where(Indicator.score >= min_score)
    if active is not None:
        query = query.where(Indicator.active.is_(active))
    if since:
        query = query.where(Indicator.updated_at >= since)
    return query


class IndicatorFilters:
    def __init__(self, type: str | None = None, severity: str | None = None, feed: str | None = None,
                 technique: str | None = None, q: str | None = None, min_score: int | None = Query(None, ge=0, le=100),
                 active: bool | None = True, since: datetime | None = None, malware: str | None = None,
                 threat_type: str | None = None, sort: str = Query("score", pattern="^(score|recent|new)$")):
        self.kw = dict(type=type, severity=severity, feed=feed, technique=technique, q=q, min_score=min_score,
                       active=active, since=since, malware=malware, threat_type=threat_type)
        self.sort = sort


def _ser(i: Indicator) -> dict:
    return {"id": i.id, "type": i.type, "value": i.value, "score": i.score, "confidence": i.confidence,
            "severity": i.severity, "threat_types": i.threat_types, "malware_families": i.malware_families,
            "tags": i.tags[:8], "attack_techniques": i.attack_techniques, "sources": i.sources,
            "source_count": i.source_count, "first_seen": export.ts(i.first_seen), "last_seen": export.ts(i.last_seen),
            "active": i.active}


@router.get("/indicators")
def list_indicators(f: IndicatorFilters = Depends(), page: Page = Depends(), db: Session = Depends(get_db)):
    q = _filters(select(Indicator), **f.kw).order_by(SORTS[f.sort], Indicator.id.desc())
    return paginate(db, q, page, _ser)


@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    i = db.get(Indicator, indicator_id)
    if not i:
        raise HTTPException(404, "indicator not found")
    d = export.indicator_to_json(i, explain=True)
    d["stix"] = export.indicator_to_stix(i)
    return d


class LookupIn(BaseModel):
    text: str = Field(max_length=500000)


@router.post("/lookup")
def lookup(body: LookupIn, db: Session = Depends(get_db)):
    """Extract indicators from free text and report which are known (also matches URL hosts and parent domains)."""
    iocs = extract_iocs(body.text)[:5000]
    results = []
    for n in iocs:
        conds = [(Indicator.type == n.type) & (Indicator.value == n.value)]
        host = host_of(n.type, n.value)
        if host:
            conds.append((Indicator.type == "domain") & Indicator.value.in_({host, registrable(host) or host}))
        hits = db.scalars(select(Indicator).where(or_(*conds))).all()
        results.append({"type": n.type, "value": n.value, "known": bool(hits),
                        "matches": [_ser(h) for h in hits]})
    return {"extracted": len(iocs), "known": sum(r["known"] for r in results),
            "results": sorted(results, key=lambda r: (not r["known"], r["type"]))}


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db)):
    s = get_settings()
    out = []
    counts = dict(db.execute(select(IndicatorSource.feed, func.count()).group_by(IndicatorSource.feed)).all())
    for name, f in FEEDS.items():
        st = service.get_feed_state(db, name)
        out.append({"name": name, "title": f.title, "description": f.description, "homepage": f.homepage,
                    "category": f.category, "confidence": f.confidence, "indicator_types": f.indicator_types,
                    "requires": f"TW_{f.requires.upper()}" if f.requires else None, "available": available(f, s),
                    "enabled": st.enabled, "last_run": export.ts(st.last_run) if st.last_run else None,
                    "last_status": st.last_status, "last_message": st.last_message, "last_count": st.last_count,
                    "last_new": st.last_new, "indicators": counts.get(name, 0),
                    "running": jobs.is_running("feed", name) or jobs.is_running("feeds", "all")})
    return out


class FeedPatch(BaseModel):
    enabled: bool


@router.patch("/feeds/{name}")
def update_feed(name: str, body: FeedPatch, db: Session = Depends(get_db)):
    if name not in FEEDS:
        raise HTTPException(404, "unknown feed")
    st = service.get_feed_state(db, name)
    st.enabled = body.enabled
    return {"name": name, "enabled": st.enabled}


class FeedRun(BaseModel):
    feeds: list[str] | None = None


@router.post("/feeds/run", status_code=202)
async def run_feeds(body: FeedRun | None = None):
    names = (body.feeds if body else None) or None
    if names:
        unknown = [n for n in names if n not in FEEDS]
        if unknown:
            raise HTTPException(404, f"unknown feed(s): {', '.join(unknown)}")
        s = get_settings()
        missing = [n for n in names if not available(FEEDS[n], s)]
        if missing:
            raise HTTPException(400, f"feed(s) need an API key: {', '.join(missing)}")

    async def job(job_id):
        return await service.run_all_feeds(job_id, only=names)

    target = ",".join(names) if names else "all"
    if not jobs.submit("feeds", job, target=target):
        raise HTTPException(409, "feed collection already running")
    return {"status": "started", "kind": "feeds", "target": target}


@router.get("/attack/matrix")
def attack_matrix(db: Session = Depends(get_db)):
    counts: dict[str, int] = {}
    for (techs,) in db.execute(select(Indicator.attack_techniques).where(Indicator.active.is_(True))):
        for t in techs or []:
            counts[t] = counts.get(t, 0) + 1
    return {"tactics": attack.matrix(counts), "total_techniques": len(counts)}


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    def g(col):
        return dict(db.execute(select(col, func.count()).where(Indicator.active.is_(True)).group_by(col)).all())
    return {"by_type": g(Indicator.type), "by_severity": g(Indicator.severity),
            "by_feed": dict(db.execute(select(IndicatorSource.feed, func.count()).group_by(IndicatorSource.feed)).all()),
            "total": db.scalar(select(func.count(Indicator.id))), "active": db.scalar(
                select(func.count(Indicator.id)).where(Indicator.active.is_(True)))}


@router.get("/export/{fmt}")
def export_indicators(fmt: str, f: IndicatorFilters = Depends(), limit: int = Query(10000, ge=1, le=200000),
                      db: Session = Depends(get_db)):
    """Export filtered indicators. Formats: stix (STIX 2.1 bundle), json (threatwatch.ioc.v1), csv, txt."""
    if fmt not in ("stix", "json", "csv", "txt"):
        raise HTTPException(404, "format must be one of stix, json, csv, txt")
    q = _filters(select(Indicator), **f.kw).order_by(SORTS[f.sort]).limit(limit)
    if fmt in ("stix", "json"):
        q = q.options(selectinload(Indicator.sightings))
    rows = db.scalars(q).all()
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    disp = {"Content-Disposition": f'attachment; filename="threatwatch-iocs-{stamp}.{ {"stix": "stix.json"}.get(fmt, fmt)}"'}
    if fmt == "stix":
        return JSONResponse(export.stix_bundle(rows), headers=disp, media_type="application/stix+json;version=2.1")
    if fmt == "json":
        return JSONResponse(export.json_document(rows), headers=disp)
    if fmt == "csv":
        return Response(export.csv_document(rows), media_type="text/csv", headers=disp)
    return PlainTextResponse(export.text_document(rows), headers=disp)


# ------------------------------------------------------------------ TAXII 2.1 (read-only)
TAXII_MT = "application/taxii+json;version=2.1"
COLLECTIONS = {
    "4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c01": ("All indicators", "Every active indicator", {}),
    "4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c02": ("High confidence", "Active indicators with score >= 65", {"min_score": 65}),
    "4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c03": ("Phishing", "Phishing URLs and domains", {"threat_type": "phishing"}),
    "4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c04": ("C2 infrastructure", "Botnet / malware command-and-control",
                                             {"threat_type": "c2"}),
}


def _taxii(data, status=200):
    return JSONResponse(data, status_code=status, media_type=TAXII_MT)


@taxii.get("/")
def taxii_discovery(request: Request):
    base = str(request.base_url).rstrip("/")
    return _taxii({"title": "ThreatWatch TAXII 2.1", "description": "Read-only TAXII server for ThreatWatch indicators",
                   "default": f"{base}/taxii2/api/", "api_roots": [f"{base}/taxii2/api/"]})


@taxii.get("/api/")
def taxii_api_root():
    return _taxii({"title": "ThreatWatch", "versions": ["application/taxii+json;version=2.1"],
                   "max_content_length": 104857600})


def _collection(cid):
    title, desc, _ = COLLECTIONS[cid]
    return {"id": cid, "title": title, "description": desc, "can_read": True, "can_write": False,
            "media_types": ["application/stix+json;version=2.1"]}


@taxii.get("/api/collections/")
def taxii_collections():
    return _taxii({"collections": [_collection(c) for c in COLLECTIONS]})


@taxii.get("/api/collections/{cid}/")
def taxii_collection(cid: str):
    if cid not in COLLECTIONS:
        return _taxii({"title": "Collection not found", "http_status": "404"}, 404)
    return _taxii(_collection(cid))


@taxii.get("/api/collections/{cid}/objects/")
def taxii_objects(cid: str, added_after: datetime | None = None, limit: int = Query(1000, ge=1, le=10000),
                  db: Session = Depends(get_db)):
    if cid not in COLLECTIONS:
        return _taxii({"title": "Collection not found", "http_status": "404"}, 404)
    kw = dict(COLLECTIONS[cid][2])
    q = _filters(select(Indicator), active=True, since=added_after.replace(tzinfo=None) if added_after else None, **kw)
    rows = db.scalars(q.order_by(Indicator.updated_at.asc(), Indicator.id.asc()).limit(limit + 1)
                      .options(selectinload(Indicator.sightings))).all()
    more = len(rows) > limit
    rows = rows[:limit]
    headers = {}
    if rows:
        headers["X-TAXII-Date-Added-First"] = export.ts(rows[0].updated_at)
        headers["X-TAXII-Date-Added-Last"] = export.ts(rows[-1].updated_at)
    body = {"more": more, "objects": export.stix_objects(rows)}
    if more and rows:
        body["next"] = export.ts(rows[-1].updated_at + timedelta(microseconds=1))
    return JSONResponse(body, media_type="application/stix+json;version=2.1", headers=headers)
