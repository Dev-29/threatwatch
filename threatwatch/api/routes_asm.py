"""Attack surface management endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..core import jobs
from ..db import get_db
from ..models import AsmAsset, AsmFinding, AsmScan
from ..modules.asm import pentest, report, service
from .common import iso
from .routes_core import registrable_or_400

router = APIRouter(prefix="/asm", tags=["attack surface"])


def scan_json(s: AsmScan) -> dict:
    mode = "pentest" if (s.summary or {}).get("mode") == "pentest" else "scan"
    return {"id": s.id, "root_domain": s.root_domain, "active": s.active, "status": s.status, "mode": mode,
            "started_at": iso(s.started_at), "finished_at": iso(s.finished_at), "risk_score": s.risk_score,
            "grade": s.grade, "summary": s.summary, "message": s.message,
            "running": jobs.is_running("asm_scan", str(s.id)) or jobs.is_running("asm_pentest", str(s.id))}


@router.get("/scans")
def list_scans(root_domain: str | None = None, db: Session = Depends(get_db)):
    q = select(AsmScan).order_by(AsmScan.id.desc()).limit(200)
    if root_domain:
        q = q.where(AsmScan.root_domain == root_domain)
    return [scan_json(s) for s in db.scalars(q)]


class ScanIn(BaseModel):
    root_domain: str
    active: bool | None = None
    authorized: bool = False


@router.post("/scans", status_code=202)
async def start_scan(body: ScanIn):
    root = registrable_or_400(body.root_domain)
    active = get_settings().asm_active_default if body.active is None else body.active
    if active and not body.authorized:
        raise HTTPException(400, "active scanning requires 'authorized': true - only scan assets you own or are "
                                 "permitted to test")
    scan_id = service.create_scan(root, active)

    async def job(job_id):
        return await service.run_scan(scan_id, job_id)

    jobs.submit("asm_scan", job, target=str(scan_id))
    return {"status": "started", "scan_id": scan_id, "root_domain": root, "active": active}


class PentestIn(BaseModel):
    target: str
    authorized: bool = False
    by: str | None = None


@router.post("/pentests", status_code=202)
async def start_pentest(body: PentestIn):
    """Launch an autonomous OWASP Top 10 pentest of a single authorised target (Claude Code)."""
    if not get_settings().pentest_enabled:
        raise HTTPException(403, "autonomous pentest is disabled; set TW_PENTEST_ENABLED=true to enable it")
    if not body.authorized:
        raise HTTPException(400, "an autonomous pentest performs active, intrusive testing - set 'authorized': "
                                 "true to confirm you own or are permitted to test this exact target")
    try:
        target = pentest.parse_target(body.target)
        scan_id = pentest.create_pentest(body.target, authorized_by=f"api:{body.by}" if body.by else "api",
                                         scope_ack=body.authorized)
    except pentest.ScopeError as e:
        raise HTTPException(400, str(e))

    async def job(job_id):
        return await pentest.run_pentest(scan_id, job_id)

    jobs.submit("asm_pentest", job, target=str(scan_id))
    return {"status": "started", "scan_id": scan_id, "target": target.host, "scope_hosts": target.scope_hosts}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    s = db.get(AsmScan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    return scan_json(s)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    s = db.get(AsmScan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    if jobs.is_running("asm_scan", str(scan_id)) or jobs.is_running("asm_pentest", str(scan_id)):
        raise HTTPException(409, "scan is running")
    db.delete(s)


@router.get("/scans/{scan_id}/assets")
def scan_assets(scan_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(select(AsmAsset).where(AsmAsset.scan_id == scan_id)
                      .order_by(AsmAsset.risk_score.desc(), AsmAsset.hostname)).all()
    return [{"id": a.id, "hostname": a.hostname, "sources": a.sources, "resolved": a.resolved, "ips": a.ips,
             "cname": a.cname, "asn": a.asn, "hosting": a.hosting, "ports": a.ports, "http": a.http, "tls": a.tls,
             "technologies": a.technologies, "risk_score": a.risk_score} for a in rows]


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(select(AsmFinding).where(AsmFinding.scan_id == scan_id)).all()
    rows = sorted(rows, key=lambda f: (report.SEV_ORDER.get(f.severity, 9), f.hostname))
    return [{"id": f.id, "hostname": f.hostname, "category": f.category, "check_id": f.check_id,
             "severity": f.severity, "title": f.title, "description": f.description, "evidence": f.evidence,
             "remediation": f.remediation, "attack_techniques": f.attack_techniques} for f in rows]


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: int, format: Literal["html", "md", "json"] = "html", download: bool = False,
                db: Session = Depends(get_db)):
    s = db.get(AsmScan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    if s.status != "done":
        raise HTTPException(409, f"scan is {s.status}")
    name = f"asm-report-{s.root_domain}-{s.id}.{format}"
    headers = {"Content-Disposition": f'{"attachment" if download else "inline"}; filename="{name}"'}
    if format == "html":
        return HTMLResponse(report.render_html(s), headers=headers)
    if format == "md":
        return PlainTextResponse(report.render_markdown(s), media_type="text/markdown", headers=headers)
    return JSONResponse(report.scan_to_dict(s), headers=headers)
