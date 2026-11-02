"""Leak-source connectors for dark web / credential exposure monitoring.

Each connector answers one question: *"what does this source know about <term>?"* where a term is
an email address, a domain, a keyword (brand / project name) or a person's name. Connectors return
:class:`LeakFinding` objects; scoring, de-duplication and alerting happen in ``service.py``.

Connectors never return plaintext secrets: anything password-like is masked before it leaves here.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote, urlsplit

import httpx

from ...config import Settings
from ...core import http
from ...core.domains import registrable, split

log = logging.getLogger(__name__)

TermKind = str  # "email" | "domain" | "keyword" | "name"


@dataclass
class LeakFinding:
    source: str
    source_type: str  # breach | paste | stealer_log | ransomware_leak | forum | code_repo | combolist
    title: str
    identifier: str | None = None
    description: str = ""
    url: str | None = None
    data_classes: list[str] = field(default_factory=list)
    has_password: bool = False
    password_plaintext: bool = False
    record_count: int | None = None
    leaked_at: datetime | None = None
    credibility: float = 0.8  # 0..1, how much we trust the attribution
    verified: bool = False
    raw: dict = field(default_factory=dict)


def _strip_html(s: str | None) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


def _parse_date(s) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    for fmt, n in (("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10), ("%Y-%m", 7), ("%Y", 4)):
        try:
            return datetime.strptime(s[:n], fmt)
        except ValueError:
            continue
    return None


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


class Connector:
    name = "base"
    title = "Base"
    description = ""
    kinds: set[TermKind] = set()
    requires: str | None = None  # Settings attribute
    delay = 1.0  # polite delay between requests to the same source (seconds)

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = asyncio.Lock()

    def available(self) -> bool:
        if self.requires and not getattr(self.settings, self.requires, None):
            return False
        return True

    async def search(self, c: httpx.AsyncClient, kind: TermKind, term: str) -> list[LeakFinding]:
        if kind not in self.kinds:
            return []
        async with self._lock:  # serialise per source to respect rate limits
            try:
                return await self._search(c, kind, term)
            finally:
                await asyncio.sleep(self.delay)

    async def _search(self, c, kind, term) -> list[LeakFinding]:  # pragma: no cover - abstract
        raise NotImplementedError


# ---------------------------------------------------------------------------- free sources
class XposedOrNot(Connector):
    name = "xposedornot"
    title = "XposedOrNot"
    description = "Free breach database (email -> breaches with exposed data classes and password risk)."
    kinds = {"email"}
    delay = 1.2

    async def _search(self, c, kind, term):
        r = await c.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": term})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        d = r.json()
        out = []
        for b in ((d.get("ExposedBreaches") or {}).get("breaches_details") or []):
            classes = [x.strip() for x in (b.get("xposed_data") or "").split(";") if x.strip()]
            risk = (b.get("password_risk") or "unknown").lower()
            has_pw = any("password" in x.lower() for x in classes) or risk not in ("unknown", "")
            out.append(LeakFinding(
                source=self.name, source_type="combolist" if _is_combo(b.get("breach", "")) else "breach",
                title=f"{b.get('breach')} breach", identifier=term,
                description=b.get("details") or "", url=f"https://xposedornot.com/xposed/#{b.get('breach')}",
                data_classes=classes, has_password=has_pw,
                password_plaintext=risk in ("plaintext", "easytocrack"),
                record_count=b.get("xposed_records"), leaked_at=_parse_date(b.get("xposed_date")),
                credibility=0.9 if b.get("verified") == "Yes" else 0.6,
                verified=b.get("verified") == "Yes",
                raw={k: b.get(k) for k in ("breach", "domain", "industry", "password_risk", "xposed_date", "added")},
            ))
        for p in ((d.get("ExposedPastes") or {}).get("pastes_details") or []) if isinstance(d.get("ExposedPastes"), dict) else []:
            out.append(LeakFinding(
                source=self.name, source_type="paste", title=f"Paste {p.get('id', '')}", identifier=term,
                url=p.get("link"), data_classes=["Email addresses"], leaked_at=_parse_date(p.get("date")),
                credibility=0.7, raw=p,
            ))
        return out


def _is_combo(name: str) -> bool:
    return bool(re.search(r"combo|collection ?#|anti ?public|exploit\.?in|cit0day|naz\.api|alien ?txtbase|"
                          r"verifications|stealer", name or "", re.I))


class LeakCheckPublic(Connector):
    name = "leakcheck"
    title = "LeakCheck (public API)"
    description = "Free lookup of an email across leak databases; returns source names, dates and field types."
    kinds = {"email"}
    delay = 1.5

    async def _search(self, c, kind, term):
        r = await c.get("https://leakcheck.io/api/public", params={"check": term})
        if r.status_code in (400, 404):
            return []
        r.raise_for_status()
        d = r.json()
        if not d.get("success") or not d.get("found"):
            return []
        fields = [f.lower() for f in d.get("fields", [])]
        classes = sorted({_FIELD_LABELS.get(f, f.replace("_", " ").title()) for f in fields})
        has_pw = "password" in fields
        out = []
        for s in d.get("sources", [])[:100]:
            name = s.get("name") or "unknown"
            stype = "stealer_log" if "stealer" in name.lower() else ("combolist" if _is_combo(name) else "breach")
            out.append(LeakFinding(
                source=self.name, source_type=stype, title=f"{name} leak", identifier=term,
                description=f"LeakCheck reports these field types across all {d.get('found')} records for this "
                            f"address (not per source): {', '.join(fields)}",
                url="https://leakcheck.io/", data_classes=classes, has_password=has_pw,
                leaked_at=_parse_date(s.get("date")), credibility=0.6, raw=s,
            ))
        return out


_FIELD_LABELS = {"password": "Passwords", "username": "Usernames", "phone": "Phone numbers", "dob": "Dates of birth",
                 "address": "Physical addresses", "ip": "IP addresses", "ssn": "Social security numbers",
                 "name": "Names", "first_name": "Names", "last_name": "Names"}


class HudsonRock(Connector):
    name = "hudsonrock"
    title = "Hudson Rock Cavalier (infostealer intel)"
    description = "Free infostealer-infection lookups: compromised employees/users per domain, infections per email."
    kinds = {"email", "domain"}
    delay = 1.5
    BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

    async def _search(self, c, kind, term):
        if kind == "email":
            r = await c.get(f"{self.BASE}/search-by-email", params={"email": term})
            if r.status_code in (400, 404):
                return []
            r.raise_for_status()
            out = []
            for s in r.json().get("stealers", []) or []:
                out.append(LeakFinding(
                    source=self.name, source_type="stealer_log",
                    title=f"Infostealer infection on '{s.get('computer_name', 'unknown')}' exposing saved credentials",
                    identifier=term,
                    description=(f"Machine {s.get('computer_name')} ({s.get('operating_system')}) was infected; "
                                 f"malware path: {s.get('malware_path')}. {s.get('total_corporate_services', 0)} "
                                 f"corporate and {s.get('total_user_services', 0)} personal service credentials "
                                 f"captured. Masked top passwords: {', '.join(s.get('top_passwords') or [])}"),
                    url="https://www.hudsonrock.com/free-tools",
                    data_classes=["Passwords", "Usernames", "Browser cookies", "Autofill data", "Device information"],
                    has_password=True, password_plaintext=True, leaked_at=_parse_date(s.get("date_compromised")),
                    credibility=0.9, verified=True,
                    raw={k: s.get(k) for k in ("date_compromised", "computer_name", "operating_system", "malware_path",
                                               "total_corporate_services", "total_user_services", "antiviruses", "ip")},
                ))
            return out
        r = await c.get(f"{self.BASE}/search-by-domain", params={"domain": term})
        if r.status_code in (400, 404):
            return []
        r.raise_for_status()
        d = r.json()
        out = []
        emp, users = int(d.get("employees") or 0), int(d.get("users") or 0)
        families = ", ".join(list((d.get("stealerFamilies") or {}).keys())[:8])
        if emp:
            urls = [u.get("url") for u in (d.get("data") or {}).get("employees_urls", [])[:10]]
            out.append(LeakFinding(
                source=self.name, source_type="stealer_log",
                title=f"{emp} employee machine(s) infected by infostealers with {term} credentials",
                identifier=term, record_count=emp,
                description=(f"Corporate logins captured by infostealer malware ({families}). Most exposed "
                             f"employee URLs: {', '.join(u for u in urls if u)}. Force password resets, revoke "
                             "sessions and investigate the infected endpoints."),
                url=f"https://www.hudsonrock.com/search/domain/{term}",
                data_classes=["Passwords", "Usernames", "Browser cookies", "Corporate URLs"],
                has_password=True, password_plaintext=True,
                leaked_at=_parse_date(d.get("last_employee_compromised")), credibility=0.9, verified=True,
                raw={"employees": emp, "users": users, "third_parties": d.get("third_parties"),
                     "employees_urls": urls, "stealer_families": d.get("stealerFamilies")},
            ))
        if users:
            out.append(LeakFinding(
                source=self.name, source_type="stealer_log",
                title=f"{users} customer/user credential set(s) for {term} services in infostealer logs",
                identifier=term, record_count=users,
                description=("Credentials of external users of your services were captured by infostealers; "
                             "expect credential-stuffing / account-takeover attempts against your login pages."),
                url=f"https://www.hudsonrock.com/search/domain/{term}",
                data_classes=["Passwords", "Usernames"], has_password=True, password_plaintext=True,
                leaked_at=_parse_date(d.get("last_user_compromised")), credibility=0.8,
                raw={"users": users},
            ))
        return out


class HIBPDomain(Connector):
    name = "hibp_domain"
    title = "Have I Been Pwned (breach catalogue)"
    description = "Free: breaches where your domain itself was the breached service."
    kinds = {"domain"}
    delay = 1.6

    async def _search(self, c, kind, term):
        r = await c.get("https://haveibeenpwned.com/api/v3/breaches", params={"domain": term})
        r.raise_for_status()
        return [_hibp_breach(self.name, b, term, organisation=True) for b in r.json()]


def _hibp_breach(source: str, b: dict, term: str, organisation: bool = False) -> LeakFinding:
    classes = b.get("DataClasses") or []
    has_pw = any("password" in x.lower() for x in classes)
    title = f"{b.get('Title')} breach" + (" (your organisation was breached)" if organisation else "")
    return LeakFinding(
        source=source, source_type="combolist" if b.get("IsSpamList") or _is_combo(b.get("Name", "")) else "breach",
        title=title, identifier=term, description=_strip_html(b.get("Description")),
        url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}", data_classes=classes,
        has_password=has_pw, record_count=b.get("PwnCount"), leaked_at=_parse_date(b.get("BreachDate")),
        credibility=1.0 if b.get("IsVerified") else 0.7, verified=bool(b.get("IsVerified")),
        raw={k: b.get(k) for k in ("Name", "Domain", "BreachDate", "AddedDate", "PwnCount", "IsVerified", "IsSensitive")},
    )


class HIBPAccount(Connector):
    name = "hibp"
    title = "Have I Been Pwned (accounts & pastes)"
    description = "Breaches and pastes per email address. Requires TW_HIBP_API_KEY."
    kinds = {"email"}
    requires = "hibp_api_key"
    delay = 6.5  # lowest HIBP tier = 10 RPM

    async def _search(self, c, kind, term):
        h = {"hibp-api-key": self.settings.hibp_api_key or ""}
        out = []
        r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(term)}",
                        params={"truncateResponse": "false"}, headers=h)
        if r.status_code != 404:
            r.raise_for_status()
            out += [_hibp_breach(self.name, b, term) for b in r.json()]
        await asyncio.sleep(self.delay)
        r = await c.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(term)}", headers=h)
        if r.status_code != 404:
            r.raise_for_status()
            for p in r.json() or []:
                url = f"https://pastebin.com/{p['Id']}" if p.get("Source") == "Pastebin" else None
                out.append(LeakFinding(
                    source=self.name, source_type="paste", title=f"{p.get('Source')} paste {p.get('Title') or p.get('Id')}",
                    identifier=term, url=url, data_classes=["Email addresses"], record_count=p.get("EmailCount"),
                    leaked_at=_parse_date(p.get("Date")), credibility=0.85, raw=p,
                ))
        return out


class RansomwareLive(Connector):
    name = "ransomware_live"
    title = "ransomware.live (leak-site tracker)"
    description = "Free: victims posted on ransomware data-leak sites (onion), searchable by name/domain."
    kinds = {"domain", "keyword"}
    delay = 2.0

    async def _search(self, c, kind, term):
        query = split(term)[1] if kind == "domain" else term
        if len(query) < 3:
            return []
        r = await c.get(f"https://api.ransomware.live/v2/searchvictims/{quote(query)}")
        if r.status_code == 404:
            return []
        r.raise_for_status()
        out = []
        for v in r.json() or []:
            vdom = (v.get("domain") or "").lower()
            vname = (v.get("victim") or "").lower()
            if kind == "domain":
                if vdom and (registrable(vdom) or vdom) == (registrable(term) or term):
                    cred = 0.9
                elif len(query) >= 5 and re.search(rf"\b{re.escape(query.lower())}\b", vname):
                    cred = 0.5
                else:
                    continue
            else:
                if not re.search(rf"\b{re.escape(term.lower())}\b", f"{vname} {vdom}"):
                    continue
                cred = 0.6
            out.append(LeakFinding(
                source=self.name, source_type="ransomware_leak",
                title=f"'{v.get('victim')}' listed on {v.get('group')} ransomware leak site", identifier=term,
                description=(v.get("description") or "") + (f" Claimed data size: {v['data_size']}." if v.get("data_size") else ""),
                url=v.get("url") or v.get("claim_url"),
                data_classes=["Corporate data", "Possibly employee / customer PII"],
                leaked_at=_parse_date(v.get("attackdate") or v.get("discovered")), credibility=cred,
                raw={k: v.get(k) for k in ("victim", "domain", "group", "country", "activity", "attackdate",
                                           "discovered", "claim_url", "data_size", "url")},
            ))
        return out


# ---------------------------------------------------------------------------- keyed sources
class IntelX(Connector):
    name = "intelx"
    title = "Intelligence X"
    description = "Pastes, darknet (Tor/I2P), leaks and dumps search. Requires TW_INTELX_API_KEY (free tier available)."
    kinds = {"email", "domain", "keyword", "name"}
    requires = "intelx_api_key"
    delay = 2.0
    BUCKET_TYPES = {"pastes": "paste", "darknet": "forum", "leaks": "breach", "dumpster": "breach", "web": "forum"}

    async def _search(self, c, kind, term):
        base = self.settings.intelx_api_url.rstrip("/")
        h = {"x-key": self.settings.intelx_api_key or ""}
        r = await c.post(f"{base}/intelligent/search", headers=h,
                         json={"term": term, "maxresults": 50, "media": 0, "timeout": 5, "sort": 2})
        r.raise_for_status()
        sid = r.json().get("id")
        if not sid:
            return []
        await asyncio.sleep(3)
        r = await c.get(f"{base}/intelligent/search/result", params={"id": sid, "limit": 50}, headers=h)
        r.raise_for_status()
        out = []
        for rec in r.json().get("records", []) or []:
            bucket = (rec.get("bucket") or "").split(".")[0]
            if bucket in ("whois", "dns", "usenet"):
                continue
            stype = self.BUCKET_TYPES.get(bucket, "breach")
            out.append(LeakFinding(
                source=self.name, source_type=stype,
                title=f"{rec.get('bucketh') or rec.get('bucket')}: {(rec.get('name') or '')[:150]}",
                identifier=term, url=f"https://intelx.io/?did={rec.get('systemid')}",
                data_classes=["Mention"] + (["Possible credentials"] if bucket in ("leaks", "dumpster") else []),
                has_password=bucket in ("leaks", "dumpster"), leaked_at=_parse_date(rec.get("date")),
                credibility=0.6, raw={k: rec.get(k) for k in ("systemid", "bucket", "name", "date", "media")},
            ))
        return out


class GitHubLeaks(Connector):
    name = "github"
    title = "GitHub code search (secret leaks)"
    description = "Public code referencing your domain/brand next to secrets. Requires TW_GITHUB_TOKEN."
    kinds = {"domain", "keyword"}
    requires = "github_token"
    delay = 7.0  # code search: 10 req/min
    QUALIFIERS = ["password", "secret", "api_key"]

    async def _search(self, c, kind, term):
        h = {"Authorization": f"Bearer {self.settings.github_token}", "Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28"}
        seen, out = set(), []
        for q in self.QUALIFIERS:
            r = await c.get("https://api.github.com/search/code", params={"q": f'"{term}" {q}', "per_page": 20},
                            headers=h)
            if r.status_code in (403, 422):
                log.warning("github search %s: %s", r.status_code, r.text[:200])
                break
            r.raise_for_status()
            for it in r.json().get("items", []):
                key = it.get("html_url")
                if key in seen:
                    continue
                seen.add(key)
                repo = (it.get("repository") or {}).get("full_name")
                out.append(LeakFinding(
                    source=self.name, source_type="code_repo",
                    title=f"Possible {q} referencing {term} in {repo}/{it.get('path')}", identifier=term,
                    url=key, data_classes=["Source code", "Possible credentials"], has_password=q == "password",
                    credibility=0.5, raw={"repo": repo, "path": it.get("path"), "query": q},
                ))
            await asyncio.sleep(self.delay)
        return out


class OnionMonitor(Connector):
    """Keyword monitoring of operator-supplied .onion pages (forums, leak-site indexes) over Tor."""

    name = "onion"
    title = "Tor .onion page monitor"
    description = "Fetches configured .onion pages via Tor and searches them for watched terms. Requires " \
                  "TW_TOR_PROXY and TW_ONION_SOURCES."
    kinds = {"email", "domain", "keyword", "name"}
    requires = "tor_proxy"
    delay = 0.0
    CRED_WORDS = re.compile(r"passw|credential|combo|dump|database|leak|logs?\b|access|vpn|rdp|shell", re.I)

    def __init__(self, settings):
        super().__init__(settings)
        self._pages: dict[str, str] | None = None

    def available(self) -> bool:
        return super().available() and bool(self.settings.onion_source_list)

    async def _load(self) -> dict[str, str]:
        if self._pages is None:
            self._pages = {}
            async with http.client(tor=True, timeout=90, verify=False) as tc:
                for url in self.settings.onion_source_list:
                    try:
                        r = await tc.get(url)
                        self._pages[url] = _strip_html(r.text)
                    except httpx.HTTPError as exc:
                        log.warning("onion fetch %s failed: %s", url, exc)
        return self._pages

    async def _search(self, c, kind, term):
        out = []
        pat = re.compile(rf"(?<![\w.-]){re.escape(term)}(?![\w-])", re.I)
        for url, text in (await self._load()).items():
            for m in list(pat.finditer(text))[:5]:
                snippet = text[max(0, m.start() - 160): m.end() + 160].replace("\n", " ")
                creds = bool(self.CRED_WORDS.search(snippet))
                out.append(LeakFinding(
                    source=self.name, source_type="forum",
                    title=f"Mention of '{term}' on {urlsplit(url).hostname}", identifier=term, url=url,
                    description=f"...{snippet}...", data_classes=["Mention"] + (["Possible credentials"] if creds else []),
                    has_password=creds, credibility=0.6, raw={"offset": m.start()},
                ))
        return out


CONNECTORS = [XposedOrNot, LeakCheckPublic, HudsonRock, HIBPDomain, HIBPAccount, RansomwareLive, IntelX,
              GitHubLeaks, OnionMonitor]


def build(settings: Settings, only: list[str] | None = None) -> list[Connector]:
    out = []
    for cls in CONNECTORS:
        con = cls(settings)
        if only and con.name not in only:
            continue
        out.append(con)
    return out
