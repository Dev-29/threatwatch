"""Feed collection pipeline: fetch -> normalise -> de-duplicate -> merge -> score -> ATT&CK map -> alert."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ...config import get_settings
from ...core import http
from ...core.alerts import raise_alert
from ...core.domains import is_subdomain_of
from ...core.ioc import host_of, try_normalize
from ...db import session_scope
from ...models import Asset, FeedState, Indicator, IndicatorSource, utcnow
from . import attack
from .feeds import FEEDS, Feed, RawIOC, available
from .scoring import score_indicator

log = logging.getLogger(__name__)
CHUNK = 500


@dataclass
class _Agg:
    """In-run aggregate of all rows a single feed produced for one (type, value)."""

    type: str
    value: str
    confidence: int
    threat_types: set[str] = field(default_factory=set)
    malware: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    reference: str | None = None
    first_seen: datetime | None = None
    description: str | None = None
    context: dict = field(default_factory=dict)
    last_activity: datetime | None = None


def _merge_list(a: list, b) -> list:
    out = list(a or [])
    for x in b:
        if x and x not in out:
            out.append(x)
    return out


def get_feed_state(db: Session, name: str) -> FeedState:
    st = db.get(FeedState, name)
    if st is None:
        st = FeedState(name=name, enabled=FEEDS[name].default_enabled)
        db.add(st)
        db.flush()
    return st


async def _collect(feed: Feed) -> tuple[dict[tuple[str, str], _Agg], int, int]:
    settings = get_settings()
    rows: dict[tuple[str, str], _Agg] = {}
    seen = rejected = 0
    async with http.client(timeout=60) as c:
        async for raw in feed.fetch(c, settings):
            seen += 1
            n = try_normalize(raw.value, raw.type_hint)
            if n is None:
                rejected += 1
                continue
            key = (n.type, n.value)
            agg = rows.get(key)
            if agg is None:
                if len(rows) >= settings.feed_max_items:
                    continue
                conf = raw.confidence if raw.confidence is not None else feed.confidence
                agg = rows[key] = _Agg(n.type, n.value, int(conf))
            _absorb(agg, raw)
    return rows, seen, rejected


def _absorb(agg: _Agg, raw: RawIOC) -> None:
    if raw.threat_type:
        agg.threat_types.add(raw.threat_type)
    if raw.malware and raw.malware.lower() not in ("unknown", "none", "n/a"):
        agg.malware.add(raw.malware)
    agg.tags.update(t.lower() for t in raw.tags if t)
    agg.reference = agg.reference or raw.reference
    agg.description = agg.description or raw.description
    if raw.first_seen and (agg.first_seen is None or raw.first_seen < agg.first_seen):
        agg.first_seen = raw.first_seen
    act = raw.last_activity or raw.first_seen
    if act and (agg.last_activity is None or act > agg.last_activity):
        agg.last_activity = act
    for k, v in raw.context.items():
        if v not in (None, "", []):
            agg.context.setdefault(k, v)


def activity_date(ind: Indicator) -> datetime:
    """Latest activity reported by any source (falls back to when we last saw it in a feed)."""
    raw = (ind.context or {}).get("last_activity")
    if raw:
        try:
            return min(datetime.fromisoformat(raw), ind.last_seen)
        except ValueError:
            pass
    return ind.last_seen


def apply_scoring(ind: Indicator, now: datetime | None = None) -> None:
    ind.attack_techniques = attack.map_indicator(
        ind.type, ind.threat_types or [], ind.malware_families or [], ind.tags or [], ind.context or {}
    )
    ind.score, ind.confidence, ind.severity = score_indicator(
        ind.type, ind.source_confidence or {}, ind.threat_types or [], ind.tags or [], activity_date(ind), now
    )


def merge_into_db(db: Session, feed: Feed, rows: dict[tuple[str, str], _Agg]) -> tuple[int, list[Indicator]]:
    """Upsert aggregated rows. Returns (new_count, touched indicators)."""
    now = utcnow()
    new_count = 0
    touched: list[Indicator] = []
    by_type: dict[str, list[_Agg]] = {}
    for agg in rows.values():
        by_type.setdefault(agg.type, []).append(agg)

    for ioc_type, aggs in by_type.items():
        for i in range(0, len(aggs), CHUNK):
            chunk = aggs[i : i + CHUNK]
            values = [a.value for a in chunk]
            existing = {
                ind.value: ind
                for ind in db.scalars(select(Indicator).where(Indicator.type == ioc_type, Indicator.value.in_(values)))
            }
            ids = [e.id for e in existing.values()]
            sightings = {
                s.indicator_id: s
                for s in db.scalars(select(IndicatorSource).where(IndicatorSource.feed == feed.name,
                                                                   IndicatorSource.indicator_id.in_(ids)))
            } if ids else {}
            pending: list[tuple[Indicator, _Agg]] = []
            for a in chunk:
                ind = existing.get(a.value)
                if ind is None:
                    ind = Indicator(
                        type=a.type, value=a.value, tlp=feed.tlp, sources=[], source_confidence={},
                        threat_types=[], malware_families=[], tags=[], context={}, attack_techniques=[],
                        first_seen=a.first_seen or now, last_seen=now, created_at=now,
                    )
                    db.add(ind)
                    new_count += 1
                ind.sources = _merge_list(ind.sources, [feed.name])
                sc = dict(ind.source_confidence or {})
                sc[feed.name] = a.confidence
                ind.source_confidence = sc
                ind.source_count = len(sc)
                ind.threat_types = _merge_list(ind.threat_types, sorted(a.threat_types))
                ind.malware_families = _merge_list(ind.malware_families, sorted(a.malware))
                ind.tags = _merge_list(ind.tags, sorted(a.tags))[:25]
                ctx = dict(ind.context or {})
                for k, v in a.context.items():
                    ctx.setdefault(k, v)
                reported = (a.last_activity or now).isoformat(timespec="seconds")
                ctx["last_activity"] = max(ctx.get("last_activity") or "", reported)
                ind.context = ctx
                ind.description = ind.description or a.description
                if a.first_seen and a.first_seen < ind.first_seen:
                    ind.first_seen = a.first_seen
                ind.last_seen = now
                ind.updated_at = now
                ind.active = True
                apply_scoring(ind, now)
                touched.append(ind)
                sighting = sightings.get(ind.id) if ind.id else None
                if sighting is None:
                    pending.append((ind, a))
                else:
                    sighting.last_seen = now
                    sighting.confidence = a.confidence
            db.flush()  # assigns ids to new indicators
            for ind, a in pending:
                db.add(IndicatorSource(
                    indicator_id=ind.id, feed=feed.name, confidence=a.confidence,
                    threat_type=next(iter(sorted(a.threat_types)), None),
                    malware=next(iter(sorted(a.malware)), None), reference=a.reference,
                    first_seen=a.first_seen or now, last_seen=now,
                ))
            db.flush()
    return new_count, touched


def _watch_terms(db: Session) -> tuple[list[str], list[str]]:
    assets = db.scalars(select(Asset).where(Asset.enabled.is_(True), Asset.type.in_(["domain", "brand"]))).all()
    doms = [a.value.lower() for a in assets if a.type == "domain"]
    brands = [a.value.lower() for a in assets if a.type == "brand" and len(a.value) >= 4]
    return doms, brands


def match_watchlist(db: Session, touched: list[Indicator]) -> int:
    """Alert when feed indicators reference the organisation's own domains or brand names."""
    doms, brands = _watch_terms(db)
    if not doms and not brands:
        return 0
    alerts = 0
    for ind in touched:
        host = host_of(ind.type, ind.value)
        if not host:
            continue
        own = next((d for d in doms if is_subdomain_of(host, d)), None)
        if own:
            a = raise_alert(
                db, module="intel", severity="high",
                title=f"Organisation domain {host} listed in threat feed ({', '.join(ind.sources)})",
                description=f"{ind.type} {ind.value} is flagged as {', '.join(ind.threat_types) or 'malicious'}. "
                            "This may indicate a compromised website or abused infrastructure.",
                ref_type="indicator", ref_id=ind.id, dedup_key=f"intel-own:{ind.type}:{ind.value}",
            )
            alerts += bool(a)
            continue
        if "phishing" in (ind.threat_types or []):
            low = ind.value.lower()
            brand = next((b for b in brands + [d.split(".")[0] for d in doms if len(d.split(".")[0]) >= 5]
                          if b in low), None)
            if brand:
                a = raise_alert(
                    db, module="phishing", severity="high",
                    title=f"Phishing {ind.type} referencing brand '{brand}': {ind.value[:120]}",
                    description=f"Reported by {', '.join(ind.sources)}. Consider a takedown request and "
                                "blocking at the mail/web gateway.",
                    ref_type="indicator", ref_id=ind.id, dedup_key=f"intel-brand:{ind.type}:{ind.value}",
                )
                alerts += bool(a)
    return alerts


async def run_feed(name: str) -> dict:
    feed = FEEDS[name]
    settings = get_settings()
    if not available(feed, settings):
        raise RuntimeError(f"feed {name} requires TW_{feed.requires.upper()}")
    started = utcnow()
    try:
        rows, seen, rejected = await _collect(feed)
    except Exception as exc:
        with session_scope() as db:
            st = get_feed_state(db, name)
            st.last_run, st.last_status, st.last_message = started, "error", f"{type(exc).__name__}: {exc}"[:1000]
            st.total_runs += 1
        raise
    with session_scope() as db:
        new, touched = merge_into_db(db, feed, rows)
        alerts = match_watchlist(db, touched)
        st = get_feed_state(db, name)
        st.last_run, st.last_status = started, "ok"
        st.last_count, st.last_new = len(rows), new
        st.last_message = f"{seen} rows read, {rejected} rejected by validation, {len(rows)} unique"
        st.total_runs += 1
    log.info("feed %s: %d unique (%d new), %d rejected", name, len(rows), new, rejected)
    return {"feed": name, "rows": seen, "unique": len(rows), "new": new, "rejected": rejected, "alerts": alerts}


def expire_indicators(db: Session) -> int:
    cutoff = utcnow() - timedelta(days=get_settings().ioc_retention_days)
    res = db.execute(update(Indicator).where(Indicator.active.is_(True), Indicator.last_seen < cutoff)
                     .values(active=False))
    return res.rowcount or 0


def enabled_feeds() -> list[str]:
    settings = get_settings()
    with session_scope() as db:
        return [n for n, f in FEEDS.items() if available(f, settings) and get_feed_state(db, n).enabled]


async def run_all_feeds(job_id: int | None = None, only: list[str] | None = None) -> dict:
    results, errors = {}, {}
    for name in only or enabled_feeds():
        try:
            results[name] = await run_feed(name)
        except Exception as exc:  # noqa: BLE001 - one broken feed must not stop the rest
            log.warning("feed %s failed: %s", name, exc)
            errors[name] = f"{type(exc).__name__}: {exc}"[:300]
    with session_scope() as db:
        expired = expire_indicators(db)
    total_new = sum(r["new"] for r in results.values())
    return {
        "feeds_ok": len(results), "feeds_failed": len(errors), "new_indicators": total_new,
        "expired": expired, "errors": errors,
        "message": f"{len(results)} feeds ok, {len(errors)} failed, {total_new} new indicators",
    }
