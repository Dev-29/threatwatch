"""Dark web monitoring endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from ..config import get_settings
from ..core import jobs
from ..db import get_db
from ..models import Exposure
from ..modules.darkweb import connectors, importer, service
from .common import Page, exposure_json, paginate

router = APIRouter(prefix="/darkweb", tags=["dark web"])

SORTS = {"risk": Exposure.risk_score.desc(), "recent": Exposure.first_seen.desc(), "leaked": Exposure.leaked_at.desc()}


@router.get("/exposures")
def list_exposures(severity: str | None = None, status: str | None = None, source_type: str | None = None,
                   source: str | None = None, asset_id: int | None = None, q: str | None = None,
                   sort: Literal["risk", "recent", "leaked"] = "risk", page: Page = Depends(),
                   db: Session = Depends(get_db)):
    query = select(Exposure).options(joinedload(Exposure.asset)).order_by(SORTS[sort], Exposure.id.desc())
    if severity:
        query = query.where(Exposure.severity.in_(severity.split(",")))
    if status:
        query = query.where(Exposure.status.in_(status.split(",")))
    if source_type:
        query = query.where(Exposure.source_type.in_(source_type.split(",")))
    if source:
        query = query.where(Exposure.source == source)
    if asset_id:
        query = query.where(Exposure.asset_id == asset_id)
    if q:
        like = f"%{q}%"
        query = query.where(or_(Exposure.title.ilike(like), Exposure.identifier.ilike(like)))
    return paginate(db, query, page, exposure_json)


@router.get("/exposures/{exposure_id}")
def get_exposure(exposure_id: int, db: Session = Depends(get_db)):
    e = db.get(Exposure, exposure_id)
    if not e:
        raise HTTPException(404, "exposure not found")
    return exposure_json(e, full=True)


class ExposurePatch(BaseModel):
    status: Literal["new", "investigating", "remediated", "false_positive"]


@router.patch("/exposures/{exposure_id}")
def update_exposure(exposure_id: int, body: ExposurePatch, db: Session = Depends(get_db)):
    e = db.get(Exposure, exposure_id)
    if not e:
        raise HTTPException(404, "exposure not found")
    e.status = body.status
    return exposure_json(e, full=True)


@router.get("/sources")
def list_sources():
    s = get_settings()
    return [{"name": c.name, "title": c.title, "description": c.description, "kinds": sorted(c.kinds),
             "available": c.available(), "requires": c.requires} for c in connectors.build(s)]


class ScanIn(BaseModel):
    asset_ids: list[int] | None = None
    sources: list[str] | None = None


@router.post("/scan", status_code=202)
async def start_scan(body: ScanIn | None = None):
    body = body or ScanIn()

    async def job(job_id):
        return await service.scan(job_id, asset_ids=body.asset_ids, only=body.sources)

    target = ",".join(map(str, body.asset_ids or [])) or "all"
    if not jobs.submit("darkweb_scan", job, target=target):
        raise HTTPException(409, "a dark web scan for these assets is already running")
    return {"status": "started", "kind": "darkweb_scan", "target": target}


@router.post("/import")
async def import_file(file: UploadFile = File(...),
                      source_type: Literal["combolist", "stealer_log", "breach", "paste", "forum"] = Form("combolist"),
                      leaked_at: str | None = Form(None)):
    data = await file.read()
    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(413, "file larger than 200 MB")
    text = data.decode("utf-8", errors="replace")
    when = None
    if leaked_at:
        try:
            when = datetime.fromisoformat(leaked_at)
        except ValueError:
            raise HTTPException(422, "leaked_at must be ISO date (YYYY-MM-DD)")
    return importer.import_text(text, file.filename or "upload.txt", source_type, when)
