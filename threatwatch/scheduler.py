"""Minimal in-process scheduler: periodically submits collection jobs on the app's event loop.

Intervals come from settings (TW_*_INTERVAL_*). Last-run times are derived from the job_runs
table, so restarts do not cause a burst of duplicate runs.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import select

from .config import get_settings
from .core import jobs
from .db import session_scope
from .models import Asset, AsmScan, JobRun, utcnow
from .modules.asm import service as asm
from .modules.darkweb import service as darkweb
from .modules.intel import service as intel
from .modules.phishing import service as phishing

log = logging.getLogger(__name__)
TICK_SECONDS = 60


def _last_run(kind: str):
    with session_scope() as db:
        return db.scalar(select(JobRun.started_at).where(JobRun.kind == kind, JobRun.status != "failed")
                         .order_by(JobRun.id.desc()).limit(1))


def _due(kind: str, interval: timedelta) -> bool:
    if interval.total_seconds() <= 0:
        return False
    last = _last_run(kind)
    return last is None or utcnow() - last >= interval


async def _asm_job(job_id):
    with session_scope() as db:
        roots = [a.value for a in db.scalars(select(Asset).where(Asset.enabled.is_(True), Asset.type == "domain"))]
    results = []
    for root in roots:
        sid = asm.create_scan(root, active=get_settings().asm_active_default)
        results.append(await asm.run_scan(sid, job_id))
    return {"scans": len(results), "message": f"{len(results)} scheduled ASM scans"}


async def tick() -> None:
    s = get_settings()
    plan = [
        ("feeds", timedelta(minutes=s.feeds_interval_minutes), lambda j: intel.run_all_feeds(j), "all"),
        ("darkweb_scan", timedelta(hours=s.darkweb_interval_hours), lambda j: darkweb.scan(j), "all"),
        ("phishing_scan", timedelta(hours=s.phishing_interval_hours), lambda j: phishing.scan(j), "all"),
        ("asm_scheduled", timedelta(hours=s.asm_interval_hours), _asm_job, "all"),
    ]
    for kind, interval, fn, target in plan:
        if _due(kind, interval) and not jobs.is_running(kind, target):
            log.info("scheduler: starting %s", kind)
            jobs.submit(kind, fn, target=target, trigger="schedule")


def recover_interrupted() -> None:
    """Mark jobs/scans left 'running' by a previous process as failed."""
    with session_scope() as db:
        for j in db.scalars(select(JobRun).where(JobRun.status == "running")):
            j.status, j.message, j.finished_at = "failed", "interrupted (process restarted)", utcnow()
        for sc in db.scalars(select(AsmScan).where(AsmScan.status.in_(["running", "queued"]))):
            sc.status, sc.message = "failed", "interrupted (process restarted)"


async def run_forever(stop: asyncio.Event) -> None:
    await asyncio.sleep(5)  # let the server finish starting
    while not stop.is_set():
        try:
            await tick()
        except Exception as exc:  # noqa: BLE001
            log.exception("scheduler tick failed: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=TICK_SECONDS)
        except asyncio.TimeoutError:
            pass
