"""Background job runner.

Jobs are plain ``async def fn(job_id) -> dict`` coroutines. :func:`run_job` records a
:class:`JobRun` row (status, timings, stats) around them, so the UI and CLI can report progress.
Only one job per (kind, target) runs at a time.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from typing import Awaitable, Callable

from ..db import session_scope
from ..models import JobRun, utcnow
from .alerts import notify_pending

log = logging.getLogger(__name__)

JobFn = Callable[[int], Awaitable[dict]]

_running: dict[tuple[str, str], asyncio.Task] = {}


def is_running(kind: str, target: str = "") -> bool:
    t = _running.get((kind, target))
    return bool(t and not t.done())


def running_jobs() -> list[tuple[str, str]]:
    return [k for k, t in _running.items() if not t.done()]


async def run_job(kind: str, fn: JobFn, *, target: str = "", trigger: str = "manual") -> dict:
    with session_scope() as db:
        job = JobRun(kind=kind, target=target or None, trigger=trigger, status="running")
        db.add(job)
        db.flush()
        job_id = job.id
    log.info("job %s #%s started (%s)", kind, job_id, target)
    status, message, stats = "success", "", {}
    try:
        stats = await fn(job_id) or {}
        message = stats.pop("message", "") if isinstance(stats, dict) else ""
    except Exception as exc:  # noqa: BLE001 - we record any failure on the job row
        status, message = "failed", f"{type(exc).__name__}: {exc}"
        log.error("job %s #%s failed: %s\n%s", kind, job_id, exc, traceback.format_exc())
    with session_scope() as db:
        job = db.get(JobRun, job_id)
        if job:
            job.status, job.message, job.stats, job.finished_at = status, message, stats, utcnow()
        try:
            await notify_pending(db)
        except Exception as exc:  # noqa: BLE001
            log.warning("alert notification failed: %s", exc)
    log.info("job %s #%s %s %s", kind, job_id, status, stats)
    return {"job_id": job_id, "status": status, "message": message, "stats": stats}


def submit(kind: str, fn: JobFn, *, target: str = "", trigger: str = "manual") -> bool:
    """Schedule a job on the running event loop. Returns False if an identical job is running."""
    key = (kind, target)
    if is_running(kind, target):
        return False
    _running[key] = asyncio.get_running_loop().create_task(run_job(kind, fn, target=target, trigger=trigger))
    return True
