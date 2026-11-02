"""Look-alike domain monitoring: generate -> resolve -> inspect -> score -> persist -> alert."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...config import get_settings
from ...core import dnsutil, http
from ...core.alerts import raise_alert
from ...core.domains import registrable, split, to_unicode
from ...core.risk import Factors
from ...db import session_scope
from ...models import Asset, Indicator, LookalikeDomain, utcnow
from . import page as pagemod
from .permutations import Candidate, generate
from .rdap import lookup as rdap_lookup

log = logging.getLogger(__name__)

TECHNIQUE_WEIGHT = {
    "idn-homograph": 15, "homoglyph": 12, "ct-log": 10, "transposition": 8, "omission": 8, "repetition": 8,
    "replacement": 8, "vowel-swap": 8, "combosquatting": 8, "tld-swap": 6, "tld-concat": 6, "hyphenation": 5,
    "insertion": 5, "addition": 5, "subdomain": 5, "bitsquatting": 4,
}


def score_lookalike(*, technique: str, has_a: bool, has_mx: bool, page_live: bool, parked: bool,
                    similarity: float, login_form: bool, brand_mentioned: bool, created: datetime | None,
                    in_feed: bool, now: datetime | None = None) -> tuple[int, str, list[dict]]:
    now = now or utcnow()
    f = Factors(20, "registered look-alike domain")
    f.add(TECHNIQUE_WEIGHT.get(technique, 5), f"technique: {technique}")
    if has_a:
        f.add(8, "resolves to an IP address")
    if has_mx:
        f.add(15, "MX records - can send/receive email (BEC / phishing mail)")
    if page_live and not parked:
        f.add(7, "live website")
    if parked:
        f.add(-15, "parked / for-sale page")
    if similarity >= 0.3:
        f.add(round(30 * similarity, 1), f"content similar to genuine site ({similarity:.0%})")
    if login_form:
        f.add(15, "credential-harvesting form (password field)")
    if brand_mentioned:
        f.add(10, "page mentions the brand")
    if created:
        age = (now - created).days
        if age < 30:
            f.add(20, f"registered {age} days ago")
        elif age < 180:
            f.add(10, f"registered {age} days ago")
    if in_feed:
        f.add(30, "listed in threat-intelligence feeds")
    f.soft_cap()
    return f.result()


async def ct_candidates(domain: str) -> list[Candidate]:
    """Certificates issued for names containing the brand label (crt.sh) that are not ours."""
    _, label, _ = split(domain)
    if len(label) < 5:
        return []
    own = registrable(domain)
    out: dict[str, Candidate] = {}
    try:
        async with http.client(timeout=45) as c:
            r = await c.get("https://crt.sh/", params={"q": f"%{label}%", "output": "json", "exclude": "expired"})
            if r.status_code != 200:
                return []
            for row in r.json()[:5000]:
                for name in str(row.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    reg = registrable(name)
                    if reg and reg != own and label in reg and reg not in out:
                        out[reg] = Candidate(reg, "ct-log")
    except Exception as exc:  # noqa: BLE001 - crt.sh is frequently overloaded
        log.info("crt.sh keyword search failed for %s: %s", label, exc)
    return list(out.values())[:300]


async def _resolve(cands: list[Candidate], concurrency: int = 64) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)

    async def one(cand: Candidate):
        async with sem:
            if await dnsutil.exists(cand.domain) == "nxdomain":
                return None
            a, mx, ns = await asyncio.gather(dnsutil.query(cand.domain, "A"), dnsutil.query(cand.domain, "MX"),
                                             dnsutil.query(cand.domain, "NS"))
            if not (a or mx or ns):
                return None
            return {"domain": cand.domain, "technique": cand.technique, "a": a, "mx": [m for m in mx if m], "ns": ns}

    results = await asyncio.gather(*(one(c) for c in cands))
    return [r for r in results if r]


def _in_feed(db: Session, domain: str) -> bool:
    return db.scalar(select(Indicator.id).where(or_(
        (Indicator.type == "domain") & (Indicator.value == domain),
        (Indicator.type == "url") & (Indicator.value.like(f"%://{domain}/%")),
    )).limit(1)) is not None


async def scan_domain(brand_domain: str) -> dict:
    settings = get_settings()
    brand_domain = registrable(brand_domain) or brand_domain
    _, brand_label, _ = split(brand_domain)
    cands = generate(brand_domain, limit=settings.phishing_max_permutations)
    cands += await ct_candidates(brand_domain)
    log.info("phishing scan %s: %d candidates", brand_domain, len(cands))
    registered = await _resolve(cands)

    sem = asyncio.Semaphore(10)
    async with http.client(timeout=12, verify=False) as c:
        original = await pagemod.fetch_site(c, brand_domain)

        async def inspect(rec: dict):
            async with sem:
                p = await pagemod.fetch_site(c, rec["domain"]) if rec["a"] else pagemod.Page(url=rec["domain"])
                reg = registrable(rec["domain"]) or rec["domain"]
                whois = await rdap_lookup(reg)
                rec["page"], rec["whois"] = p, whois or {}
                return rec

        inspected = await asyncio.gather(*(inspect(r) for r in registered))

    new = alerts = 0
    with session_scope() as db:
        for rec in inspected:
            p: pagemod.Page = rec["page"]
            sim = pagemod.similarity(p, original, brand_domain)
            brand_mentioned = p.live and pagemod.mentions_brand(p, brand_label)
            in_feed = _in_feed(db, rec["domain"])
            created = rec["whois"].get("created")
            score, sev, factors = score_lookalike(
                technique=rec["technique"], has_a=bool(rec["a"]), has_mx=bool(rec["mx"]), page_live=p.live,
                parked=p.parked, similarity=sim, login_form=p.has_password, brand_mentioned=brand_mentioned,
                created=created, in_feed=in_feed,
            )
            row = db.scalar(select(LookalikeDomain).where(LookalikeDomain.brand_domain == brand_domain,
                                                          LookalikeDomain.domain == rec["domain"]))
            created_row = row is None
            if created_row:
                row = LookalikeDomain(brand_domain=brand_domain, domain=rec["domain"], first_seen=utcnow())
                db.add(row)
                new += 1
            prev_score = row.risk_score or 0
            row.domain_unicode = to_unicode(rec["domain"])
            row.technique, row.registered = rec["technique"], True
            row.dns_a, row.dns_mx, row.dns_ns = rec["a"], rec["mx"], rec["ns"]
            row.created_date, row.registrar = created, rec["whois"].get("registrar")
            row.http_status, row.final_url, row.title = p.status, p.final_url, (p.title or None)
            row.similarity, row.has_login_form, row.parked = sim, p.has_password, p.parked
            row.in_threat_feed = in_feed
            row.risk_score, row.severity, row.score_factors = score, sev, factors
            row.last_checked = utcnow()
            db.flush()
            if row.status in ("benign", "taken_down"):
                continue
            if created_row or score >= prev_score + 15:
                a = raise_alert(
                    db, module="phishing", severity=sev,
                    title=f"Look-alike domain {row.domain_unicode} ({rec['technique']}) targeting {brand_domain}",
                    description=(f"Risk {score}/100. A: {', '.join(rec['a'][:3]) or '-'}; MX: {', '.join(rec['mx'][:2]) or '-'}; "
                                 f"web: {p.status or 'down'} {p.title[:80] if p.title else ''}"),
                    ref_type="lookalike", ref_id=row.id, dedup_key=f"lookalike:{brand_domain}:{rec['domain']}:{sev}",
                )
                alerts += bool(a)
    return {"brand": brand_domain, "candidates": len(cands), "registered": len(registered), "new": new,
            "alerts": alerts}


async def scan(job_id: int | None = None, domains: list[str] | None = None) -> dict:
    if not domains:
        with session_scope() as db:
            domains = [a.value for a in db.scalars(select(Asset).where(Asset.enabled.is_(True), Asset.type == "domain"))
                       if (a.meta or {}).get("monitor_lookalikes", True)]
    results = []
    for d in domains:
        results.append(await scan_domain(d))
    reg = sum(r["registered"] for r in results)
    new = sum(r["new"] for r in results)
    return {"domains": len(results), "registered_lookalikes": reg, "new": new, "results": results,
            "message": f"{len(results)} brand domains checked: {reg} registered look-alikes ({new} new)"}
