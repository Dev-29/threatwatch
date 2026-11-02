"""Heuristic phishing URL analyser (static URL features + optional live page inspection).

Returns an explainable verdict: every signal that contributed to the score is listed.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from datetime import datetime
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...core import http
from ...core.domains import registrable, split, to_unicode
from ...core.ioc import try_normalize
from ...core.risk import clamp, severity_for
from ...models import Asset, Indicator, LookalikeDomain
from . import page as pagemod
from .permutations import damerau_levenshtein, skeleton
from .rdap import lookup as rdap_lookup
from ...models import utcnow

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "link", "live", "shop", "rest", "support", "icu", "cfd",
                   "sbs", "buzz", "gq", "tk", "ml", "cf", "ga", "work", "fit", "monster", "quest", "cyou", "bond",
                   "online", "site", "store", "website", "space", "lat", "beauty", "hair", "ru.com"}
FREE_HOSTING = ("blogspot.", "weebly", "wixsite", "000webhostapp", "firebaseapp.com", "web.app", "pages.dev",
                "workers.dev", "netlify.app", "vercel.app", "github.io", "glitch.me", "ngrok", "duckdns",
                "r2.dev", "ipfs", "repl.co", "herokuapp.com", "azurewebsites.net", "appspot.com", "square.site",
                "godaddysites.com", "webflow.io", "framer.app", "my.canva.site", "sites.google.com", "forms.gle")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at", "tiny.cc",
              "s.id", "t.ly", "rebrand.ly", "buff.ly"}
KEYWORDS = ("login", "signin", "sign-in", "verify", "verification", "account", "secure", "update", "wallet",
            "banking", "password", "webscr", "auth", "session", "confirm", "unlock", "suspend", "billing",
            "invoice", "office365", "o365", "microsoft", "outlook", "docusign", "sharepoint", "onedrive")


# Interstitials served by CDNs / hosts once they have flagged a site (Cloudflare, Google Safe Browsing...)
HOSTER_FLAG = re.compile(r"suspected phishing|deceptive site ahead|phishing site|site has been suspended for abuse", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def brands_from_db(db: Session) -> list[str]:
    """Registrable domains + brand keywords the organisation protects."""
    out = []
    for a in db.scalars(select(Asset).where(Asset.enabled.is_(True), Asset.type.in_(["domain", "brand"]))):
        out.append(a.value.lower())
    return out


async def analyze(url: str, db: Session, *, fetch: bool = True) -> dict:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL has no host")
    signals: list[dict] = []

    def sig(weight: int, name: str, detail: str = "") -> None:
        signals.append({"signal": name, "weight": weight, "detail": detail})

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        sig(25, "IP address used instead of a domain name", host)
    except ValueError:
        pass

    reg = registrable(host) if not is_ip else None
    sub, label, suffix = split(host) if not is_ip else ("", host, "")
    if parts.scheme != "https":
        sig(5, "No TLS (http://)")
    if "xn--" in host:
        sig(20, "Internationalised (punycode) domain - possible homograph", to_unicode(host))
    if "@" in parts.netloc:
        sig(20, "'@' in URL authority hides the real destination", parts.netloc)
    if host.count(".") >= 4:
        sig(10, "Deep sub-domain nesting", host)
    if len(raw) > 100:
        sig(5, "Very long URL", f"{len(raw)} characters")
    if host.count("-") >= 3:
        sig(8, "Many hyphens in hostname", host)
    if suffix and suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        sig(8, "TLD frequently abused for phishing", "." + suffix)
    if any(h in host for h in FREE_HOSTING):
        sig(10, "Free hosting / tunnelling service", host)
    if host in SHORTENERS:
        sig(10, "URL shortener hides the destination", host)
    if label and _entropy(label) > 3.8 and len(label) > 12:
        sig(8, "Random-looking (high-entropy) domain label", label)
    lowered = raw.lower()
    kws = [k for k in KEYWORDS if k in lowered]
    if kws:
        sig(min(15, 4 * len(kws)), "Credential-phishing keywords", ", ".join(kws[:6]))

    # Brand impersonation vs. the organisation's watchlist
    brands = brands_from_db(db)
    protected = {registrable(b) for b in brands if registrable(b)}
    if reg and reg in protected:
        sig(-40, "Hostname belongs to a protected (legitimate) domain", reg)
        brands = []
    for b in brands:
        b_reg = registrable(b) or ""
        b_label = split(b)[1] if b_reg else b.lower()
        if len(b_label) >= 4 and b_label in (sub + "." + label + parts.path.lower()):
            sig(30, f"Brand '{b_label}' used outside its genuine domain", host)
        elif label and len(b_label) >= 5 and (
            skeleton(label) == skeleton(b_label) or damerau_levenshtein(label, b_label) <= 2
        ):
            sig(35, f"Domain is a look-alike of protected brand '{b_label}'",
                f"edit distance {damerau_levenshtein(label, b_label)}")

    # Threat-intel cross-reference
    matches = []
    n = try_normalize(raw, "url")
    conds = [((Indicator.type == "domain") & (Indicator.value == host))]
    if reg:
        conds.append((Indicator.type == "domain") & (Indicator.value == reg))
    if n:
        conds.append((Indicator.type == "url") & (Indicator.value == n.value))
    if is_ip:
        conds.append((Indicator.type == "ipv4") & (Indicator.value == host))
    for ind in db.scalars(select(Indicator).where(or_(*conds)).limit(10)):
        matches.append({"type": ind.type, "value": ind.value, "sources": ind.sources, "score": ind.score,
                        "threat_types": ind.threat_types})
    if matches:
        sig(70, "Listed in threat-intelligence feeds", "; ".join(f"{m['value']} ({', '.join(m['sources'])})" for m in matches))
    known = db.scalar(select(LookalikeDomain).where(LookalikeDomain.domain.in_([host, reg or host])))
    if known:
        sig(30, f"Known look-alike of {known.brand_domain}", f"technique {known.technique}, risk {known.risk_score}")

    page_info = None
    whois = None
    if fetch:
        async with http.client(timeout=15, verify=False) as c:
            p = await pagemod.fetch(c, raw)
        page_info = {"status": p.status, "final_url": p.final_url, "title": p.title, "has_password_form": p.has_password,
                     "form_action_hosts": p.form_action_hosts, "parked": p.parked, "error": p.error}
        if p.title and HOSTER_FLAG.search(p.title):
            sig(40, "Hosting provider / CDN has flagged this page as phishing", p.title)
        if p.live:
            if p.has_password:
                sig(15, "Page contains a password field")
            ext = [h for h in p.form_action_hosts if registrable(h) != reg]
            if ext:
                sig(15, "Form submits to a different domain", ", ".join(sorted(set(ext))[:3]))
            for b in brands:
                b_label = split(b)[1] if registrable(b) else b.lower()
                if registrable(b) != reg and pagemod.mentions_brand(p, b_label):
                    sig(15, f"Page content mentions brand '{b_label}'", p.title[:120])
                    break
            if p.parked:
                sig(-10, "Parked / for-sale page")
            if p.final_url and registrable(urlsplit(p.final_url).hostname or "") not in (reg, None):
                sig(5, "Redirects to another domain", p.final_url[:200])
        if reg:
            whois = await rdap_lookup(reg)
            created = whois.get("created") if whois else None
            if created:
                age = (utcnow() - created).days
                if age < 30:
                    sig(20, "Domain registered in the last 30 days", created.date().isoformat())
                elif age < 180:
                    sig(10, "Domain registered in the last 6 months", created.date().isoformat())

    score = clamp(sum(s["weight"] for s in signals))
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "low-risk"
    return {
        "url": raw, "host": host, "host_unicode": to_unicode(host), "registrable_domain": reg,
        "score": score, "severity": severity_for(score), "verdict": verdict,
        "signals": sorted(signals, key=lambda s: -s["weight"]), "intel_matches": matches, "page": page_info,
        "registration": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in (whois or {}).items()},
    }
