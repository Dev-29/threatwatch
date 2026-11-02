"""Web page fetching and comparison used by look-alike scoring and the URL analyser."""

from __future__ import annotations

import asyncio
import difflib
import html as htmlmod
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlsplit

import httpx

from ...core.domains import registrable
from ...models import utcnow

PARKED_PATTERNS = re.compile(
    r"domain (?:name )?(?:is|may be) for sale|buy this domain|this domain is parked|parked (?:free|domain)|"
    r"sedoparking|parkingcrew|bodis\.com|afternic|hugedomains|dan\.com|domain parking|"
    r"related searches|this web page is parked|godaddy\.com/domainsearch|domainmarket|undeveloped\.com",
    re.I,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
ACTION_RE = re.compile(r"action\s*=\s*[\"']([^\"']*)[\"']", re.I)
PASSWORD_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
RESOURCE_RE = re.compile(r"(?:src|href)\s*=\s*[\"'](https?://[^\"'>\s]+)", re.I)
SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript)[^>]*>.*?</\1>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
WORD_RE = re.compile(r"[a-z][a-z0-9]{2,}")


@dataclass
class Page:
    url: str
    final_url: str | None = None
    status: int | None = None
    title: str = ""
    text: str = ""
    has_password: bool = False
    form_action_hosts: list[str] = field(default_factory=list)
    resource_hosts: set[str] = field(default_factory=set)
    parked: bool = False
    error: str | None = None
    headers: dict = field(default_factory=dict)
    fetched_at: datetime | None = None

    @property
    def live(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    def tokens(self) -> set[str]:
        return set(WORD_RE.findall(self.text.lower())[:3000])


def parse(url: str, final_url: str, status: int, body: str, headers: dict | None = None) -> Page:
    p = Page(url=url, final_url=final_url, status=status, headers=dict(headers or {}), fetched_at=utcnow())
    m = TITLE_RE.search(body)
    p.title = htmlmod.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:300] if m else ""
    clean = SCRIPT_STYLE_RE.sub(" ", body)
    p.text = re.sub(r"\s+", " ", htmlmod.unescape(TAG_RE.sub(" ", clean))).strip()[:20000]
    p.has_password = bool(PASSWORD_RE.search(body))
    for form in FORM_RE.findall(body):
        am = ACTION_RE.search(form)
        if am and am.group(1).strip():
            host = urlsplit(urljoin(final_url, am.group(1).strip())).hostname
            if host:
                p.form_action_hosts.append(host.lower())
    p.resource_hosts = {urlsplit(u).hostname.lower() for u in RESOURCE_RE.findall(body)[:500] if urlsplit(u).hostname}
    p.parked = bool(PARKED_PATTERNS.search(body[:200000]))
    return p


async def is_public_host(host: str) -> bool:
    """True only if every address the host resolves to is globally routable (SSRF guard)."""
    try:
        return ipaddress.ip_address(host.strip("[]")).is_global
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)


async def fetch(c: httpx.AsyncClient, url: str, max_redirects: int = 5) -> Page:
    """GET a possibly hostile URL. Redirects are followed manually so that every hop is checked:
    requests to private, loopback, link-local (cloud metadata) or reserved addresses are refused."""
    current = url
    try:
        for _ in range(max_redirects + 1):
            host = urlsplit(current).hostname
            if not host or not await is_public_host(host):
                return Page(url=url, final_url=current, error="blocked: destination is not a public address")
            r = await c.get(current, follow_redirects=False)
            if r.is_redirect and r.headers.get("location"):
                current = urljoin(str(r.url), r.headers["location"])
                continue
            ctype = r.headers.get("content-type", "")
            body = r.text[:500000] if ("html" in ctype or "text" in ctype or not ctype) else ""
            return parse(url, str(r.url), r.status_code, body, r.headers)
        return Page(url=url, final_url=current, error="too many redirects")
    except (httpx.HTTPError, UnicodeDecodeError, ValueError) as exc:
        return Page(url=url, error=f"{type(exc).__name__}: {exc}"[:200])


async def fetch_site(c: httpx.AsyncClient, domain: str) -> Page:
    """Try https:// then http:// for a bare domain."""
    p = await fetch(c, f"https://{domain}/")
    if not p.live:
        p2 = await fetch(c, f"http://{domain}/")
        if p2.live or p.status is None:
            return p2
    return p


def similarity(candidate: Page, original: Page, brand_domain: str) -> float:
    """0..1 visual/content similarity of a suspect page to the genuine site."""
    if not candidate.live or not original.live:
        return 0.0
    title = difflib.SequenceMatcher(None, candidate.title.lower(), original.title.lower()).ratio() \
        if candidate.title and original.title else 0.0
    a, b = candidate.tokens(), original.tokens()
    jaccard = len(a & b) / len(a | b) if a and b else 0.0
    score = 0.55 * title + 0.45 * min(1.0, jaccard * 1.6)
    brand_reg = registrable(brand_domain)
    # hot-linking the genuine site's assets (logos, CSS) is a strong cloning signal
    if brand_reg and any(registrable(h) == brand_reg for h in candidate.resource_hosts):
        score += 0.25
    return round(min(1.0, score), 3)


def mentions_brand(page: Page, brand_label: str) -> bool:
    if len(brand_label) < 4:
        return False
    hay = f"{page.title} {page.text[:5000]}".lower()
    return brand_label.lower() in hay
