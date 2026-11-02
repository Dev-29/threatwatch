"""Alert creation (de-duplicated) and outbound webhook notification."""

from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Alert, utcnow
from .risk import severity_rank

log = logging.getLogger(__name__)

SEV_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:",
             "low": ":large_blue_circle:", "info": ":white_circle:"}


def raise_alert(
    db: Session,
    *,
    module: str,
    severity: str,
    title: str,
    description: str = "",
    ref_type: str | None = None,
    ref_id: int | None = None,
    dedup_key: str | None = None,
) -> Alert | None:
    """Create an alert if it meets the configured minimum severity and is not a duplicate.

    When a duplicate exists with a *lower* severity, it is escalated and re-opened instead.
    """
    settings = get_settings()
    if severity_rank(severity) < severity_rank(settings.alert_min_severity):
        return None
    if dedup_key:
        existing = db.scalar(select(Alert).where(Alert.dedup_key == dedup_key))
        if existing:
            if severity_rank(severity) > severity_rank(existing.severity):
                existing.severity = severity
                existing.title = title
                existing.description = description
                existing.status = "open"
                existing.updated_at = utcnow()
                existing.notified = False
                return existing
            return None
    alert = Alert(
        module=module, severity=severity, title=title[:500], description=description,
        ref_type=ref_type, ref_id=ref_id, dedup_key=dedup_key,
    )
    db.add(alert)
    db.flush()
    return alert


async def notify_pending(db: Session) -> int:
    """Send not-yet-notified alerts to the configured webhook. Returns count sent."""
    url = get_settings().alert_webhook_url
    if not url:
        return 0
    pending = db.scalars(select(Alert).where(Alert.notified.is_(False)).order_by(Alert.id).limit(50)).all()
    if not pending:
        return 0
    sent = 0
    async with httpx.AsyncClient(timeout=10) as c:
        for a in pending:
            text = f"{SEV_EMOJI.get(a.severity, '')} *[{a.severity.upper()}] {a.module}* - {a.title}"
            if a.description:
                text += f"\n{a.description[:500]}"
            try:
                r = await c.post(url, json={"text": text, "severity": a.severity, "module": a.module,
                                            "alert_id": a.id})
                r.raise_for_status()
                a.notified = True
                sent += 1
            except httpx.HTTPError as exc:
                log.warning("webhook delivery failed: %s", exc)
                break
    return sent
