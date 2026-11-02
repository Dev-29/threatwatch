"""Threat-intelligence feed definitions and parsers.

A feed is a :class:`Feed` with an async ``fetch`` that yields :class:`RawIOC` records. Parsing
is intentionally lenient (bad rows are skipped); normalisation and validation happen centrally
in :mod:`threatwatch.core.ioc` when the records are ingested.

To add a feed: write a ``fetch`` coroutine, register a ``Feed`` in ``FEEDS``. See docs/SOURCES.md.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Callable

import httpx

from ...config import Settings


@dataclass
class RawIOC:
    value: str
    type_hint: str | None = None
    threat_type: str | None = None
    malware: str | None = None
    tags: list[str] = field(default_factory=list)
    confidence: int | None = None  # overrides the feed default when the source scores itself
    reference: str | None = None
    first_seen: datetime | None = None
    description: str | None = None
    context: dict = field(default_factory=dict)
    # Most recent activity the *source* reports (e.g. Feodo "last_online"). Drives recency decay;
    # defaults to first_seen, and to "now" for undated blocklists (presence = currently active).
    last_activity: datetime | None = None


FetchFn = Callable[[httpx.AsyncClient, Settings], AsyncIterator[RawIOC]]


@dataclass
class Feed:
    name: str
    title: str
    description: str
    homepage: str
    fetch: FetchFn
    confidence: int  # source reliability 0-100 (see docs/SCORING.md)
    tlp: str = "clear"
    requires: str | None = None  # Settings attribute that must be set
    default_enabled: bool = True
    category: str = "open-source"  # open-source | trial
    indicator_types: tuple[str, ...] = ()


def _dt(s: str | None, fmts=("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace(" UTC", "").replace("Z", "")
    s = s.split(".")[0].split("+")[0]
    for f in fmts:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def _lines(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", ";", "//")):
            yield line


async def _get(c: httpx.AsyncClient, url: str, **kw) -> httpx.Response:
    r = await c.get(url, **kw)
    r.raise_for_status()
    return r


# ------------------------------------------------------------------ open-source (no key)
async def fetch_feodo(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    for row in r.json():
        yield RawIOC(
            value=row["ip_address"], type_hint="ipv4", threat_type="botnet_c2", malware=row.get("malware"),
            tags=["c2", (row.get("malware") or "").lower()], first_seen=_dt(row.get("first_seen")),
            last_activity=_dt(row.get("last_online")),
            reference=f"https://feodotracker.abuse.ch/browse/host/{row['ip_address']}/",
            context={"port": row.get("port"), "asn": row.get("as_number"), "as_name": row.get("as_name"),
                     "country": row.get("country"), "status": row.get("status")},
        )


async def fetch_sslbl(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
    for row in csv.reader(_lines(r.text)):
        if len(row) < 3:
            continue
        listed, sha1, reason = row[0], row[1], row[2]
        malware = reason.replace("C&C", "").replace("Malware", "").strip() or None
        yield RawIOC(
            value=sha1, type_hint="x509-sha1", threat_type="c2", malware=malware, tags=["c2", "ssl-certificate"],
            first_seen=_dt(listed), description=f"SSL certificate used by {reason}",
            reference=f"https://sslbl.abuse.ch/ssl-certificates/sha1/{sha1}/",
        )


async def fetch_openphish(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://openphish.com/feed.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line, type_hint="url", threat_type="phishing", tags=["phishing"],
                     reference="https://openphish.com/")


async def fetch_phishing_army(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://phishing.army/download/phishing_army_blocklist.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line, type_hint="domain", threat_type="phishing", tags=["phishing"],
                     reference="https://phishing.army/")


async def fetch_cins(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://cinsscore.com/list/ci-badguys.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line, type_hint="ipv4", threat_type="malicious_activity", tags=["scanner"],
                     reference="https://cinsscore.com/")


async def fetch_et_compromised(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line, type_hint="ipv4", threat_type="compromised", tags=["compromised"],
                     reference="https://rules.emergingthreats.net/")


async def fetch_blocklist_de(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://lists.blocklist.de/lists/all.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line, threat_type="brute_force", tags=["brute-force"],
                     reference="https://www.blocklist.de/")


async def fetch_ipsum(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt")
    for line in _lines(r.text):
        yield RawIOC(value=line.split()[0], type_hint="ipv4", threat_type="malicious_activity",
                     tags=["multi-blocklist"], reference="https://github.com/stamparm/ipsum",
                     description="Listed on 3+ public blocklists (IPsum level 3)")


async def fetch_spamhaus_drop(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://www.spamhaus.org/drop/drop_v4.json")
    for line in _lines(r.text):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "cidr" not in row:
            continue
        yield RawIOC(value=row["cidr"], type_hint="cidr", threat_type="hijacked_netblock", tags=["drop"],
                     reference=f"https://check.spamhaus.org/sbl/query/{row.get('sblid', '')}",
                     context={"sblid": row.get("sblid"), "rir": row.get("rir")})


async def fetch_cisa_kev(c, s) -> AsyncIterator[RawIOC]:
    r = await _get(c, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    for v in r.json().get("vulnerabilities", []):
        tags = ["kev"]
        if (v.get("knownRansomwareCampaignUse") or "").lower() == "known":
            tags.append("ransomware")
        yield RawIOC(
            value=v["cveID"], type_hint="cve", threat_type="exploited_vulnerability", tags=tags,
            first_seen=_dt(v.get("dateAdded")),
            description=f"{v.get('vendorProject')} {v.get('product')}: {v.get('vulnerabilityName')}. "
                        f"{v.get('shortDescription', '')}",
            reference=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            context={"vendor": v.get("vendorProject"), "product": v.get("product"),
                     "vulnerability_name": v.get("vulnerabilityName"), "due_date": v.get("dueDate"),
                     "required_action": v.get("requiredAction"), "cwes": v.get("cwes", [])},
        )


# ------------------------------------------------------------------ trial / keyed feeds
async def fetch_threatfox(c, s) -> AsyncIterator[RawIOC]:
    r = await c.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 1},
                     headers={"Auth-Key": s.abusech_auth_key or ""})
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") not in ("ok", None):
        raise RuntimeError(f"ThreatFox: {data.get('query_status')}")
    type_map = {"ip:port": "ipv4", "domain": "domain", "url": "url", "md5_hash": "md5",
                "sha1_hash": "sha1", "sha256_hash": "sha256"}
    tt_map = {"botnet_cc": "botnet_c2", "payload_delivery": "payload_delivery", "payload": "malware"}
    for row in data.get("data") or []:
        ctx = {}
        val = row.get("ioc", "")
        if row.get("ioc_type") == "ip:port" and ":" in val:
            val, port = val.rsplit(":", 1)
            ctx["port"] = port
        yield RawIOC(
            value=val, type_hint=type_map.get(row.get("ioc_type")),
            threat_type=tt_map.get(row.get("threat_type"), row.get("threat_type")),
            malware=row.get("malware_printable"), tags=row.get("tags") or [],
            confidence=row.get("confidence_level"), first_seen=_dt(row.get("first_seen")),
            reference=f"https://threatfox.abuse.ch/ioc/{row.get('id')}/", context=ctx,
        )


async def fetch_urlhaus(c, s) -> AsyncIterator[RawIOC]:
    r = await c.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/",
                    headers={"Auth-Key": s.abusech_auth_key or ""})
    r.raise_for_status()
    data = r.json()
    for row in data.get("urls") or []:
        yield RawIOC(
            value=row["url"], type_hint="url", threat_type="malware_download", tags=row.get("tags") or [],
            first_seen=_dt(row.get("date_added")), reference=row.get("urlhaus_reference"),
            context={"url_status": row.get("url_status"), "threat": row.get("threat")},
        )


async def fetch_malwarebazaar(c, s) -> AsyncIterator[RawIOC]:
    r = await c.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "time"},
                     headers={"Auth-Key": s.abusech_auth_key or ""})
    r.raise_for_status()
    data = r.json()
    for row in data.get("data") or []:
        tags = (row.get("tags") or []) + ([row["file_type"]] if row.get("file_type") else [])
        yield RawIOC(
            value=row["sha256_hash"], type_hint="sha256", threat_type="malware", malware=row.get("signature"),
            tags=tags, first_seen=_dt(row.get("first_seen")),
            reference=f"https://bazaar.abuse.ch/sample/{row['sha256_hash']}/",
            context={"md5": row.get("md5_hash"), "sha1": row.get("sha1_hash"), "file_name": row.get("file_name"),
                     "file_type": row.get("file_type")},
        )


async def fetch_otx(c, s) -> AsyncIterator[RawIOC]:
    since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S")
    type_map = {"IPv4": "ipv4", "IPv6": "ipv6", "domain": "domain", "hostname": "domain", "URL": "url",
                "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256", "CVE": "cve",
                "email": "email", "CIDR": "cidr"}
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since={since}"
    pages = 0
    while url and pages < 10:
        r = await c.get(url, headers={"X-OTX-API-KEY": s.otx_api_key or ""})
        r.raise_for_status()
        data = r.json()
        for pulse in data.get("results", []):
            fams = [m.get("display_name") for m in pulse.get("malware_families", []) if isinstance(m, dict)]
            attack_ids = [a.get("id") if isinstance(a, dict) else a for a in pulse.get("attack_ids", [])]
            for ind in pulse.get("indicators", []):
                t = type_map.get(ind.get("type"))
                if not t:
                    continue
                yield RawIOC(
                    value=ind["indicator"], type_hint=t, threat_type="malicious_activity",
                    malware=fams[0] if fams else None, tags=[x.lower() for x in pulse.get("tags", [])][:10],
                    first_seen=_dt(ind.get("created")), description=pulse.get("name"),
                    reference=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                    context={"attack_ids": attack_ids, "pulse": pulse.get("name")},
                )
        url, pages = data.get("next"), pages + 1


async def fetch_abuseipdb(c, s) -> AsyncIterator[RawIOC]:
    r = await c.get("https://api.abuseipdb.com/api/v2/blacklist", params={"confidenceMinimum": 90, "limit": 10000},
                    headers={"Key": s.abuseipdb_api_key or "", "Accept": "application/json"})
    r.raise_for_status()
    for row in r.json().get("data", []):
        yield RawIOC(
            value=row["ipAddress"], threat_type="malicious_activity", tags=["abuse-report"],
            confidence=row.get("abuseConfidenceScore"), first_seen=_dt(row.get("lastReportedAt")),
            reference=f"https://www.abuseipdb.com/check/{row['ipAddress']}",
            context={"country": row.get("countryCode")},
        )


FEEDS: dict[str, Feed] = {f.name: f for f in [
    Feed("feodo", "abuse.ch Feodo Tracker", "Botnet C2 servers (Emotet, Dridex, QakBot, ...)",
         "https://feodotracker.abuse.ch/", fetch_feodo, 90, indicator_types=("ipv4",)),
    Feed("sslbl", "abuse.ch SSL Blacklist", "SHA1 fingerprints of SSL certificates used by malware C2",
         "https://sslbl.abuse.ch/", fetch_sslbl, 85, indicator_types=("x509-sha1",)),
    Feed("openphish", "OpenPhish Community", "Active phishing URLs", "https://openphish.com/",
         fetch_openphish, 80, indicator_types=("url",)),
    Feed("phishing_army", "Phishing Army", "Aggregated phishing domains (PhishTank, OpenPhish, CERT.PL ...)",
         "https://phishing.army/", fetch_phishing_army, 70, indicator_types=("domain",)),
    Feed("cins", "CINS Army", "IPs with poor reputation observed by Sentinel IPS", "https://cinsscore.com/",
         fetch_cins, 60, indicator_types=("ipv4",)),
    Feed("et_compromised", "Emerging Threats Compromised IPs", "Known compromised hosts",
         "https://rules.emergingthreats.net/", fetch_et_compromised, 70, indicator_types=("ipv4",)),
    Feed("blocklist_de", "blocklist.de", "IPs attacking SSH, mail, FTP, web logins (brute force)",
         "https://www.blocklist.de/", fetch_blocklist_de, 60, indicator_types=("ipv4", "ipv6")),
    Feed("ipsum", "IPsum (level 3)", "IPs present on 3 or more public blocklists",
         "https://github.com/stamparm/ipsum", fetch_ipsum, 65, indicator_types=("ipv4",)),
    Feed("spamhaus_drop", "Spamhaus DROP", "Hijacked / criminal netblocks - do not route or peer",
         "https://www.spamhaus.org/drop/", fetch_spamhaus_drop, 95, indicator_types=("cidr",)),
    Feed("cisa_kev", "CISA Known Exploited Vulnerabilities", "CVEs exploited in the wild",
         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", fetch_cisa_kev, 100,
         indicator_types=("cve",)),
    Feed("threatfox", "abuse.ch ThreatFox", "Malware IOCs (C2, payload delivery) - last 24h",
         "https://threatfox.abuse.ch/", fetch_threatfox, 80, requires="abusech_auth_key", category="trial",
         indicator_types=("ipv4", "domain", "url", "md5", "sha256")),
    Feed("urlhaus", "abuse.ch URLhaus", "Malware distribution URLs", "https://urlhaus.abuse.ch/",
         fetch_urlhaus, 85, requires="abusech_auth_key", category="trial", indicator_types=("url",)),
    Feed("malwarebazaar", "abuse.ch MalwareBazaar", "Recent malware sample hashes", "https://bazaar.abuse.ch/",
         fetch_malwarebazaar, 90, requires="abusech_auth_key", category="trial", indicator_types=("sha256",)),
    Feed("otx", "AlienVault OTX (subscribed pulses)", "Community pulses incl. ATT&CK technique IDs",
         "https://otx.alienvault.com/", fetch_otx, 60, requires="otx_api_key", category="trial",
         indicator_types=("ipv4", "domain", "url", "md5", "sha1", "sha256", "cve")),
    Feed("abuseipdb", "AbuseIPDB blacklist", "IPs with abuse confidence >= 90", "https://www.abuseipdb.com/",
         fetch_abuseipdb, 75, requires="abuseipdb_api_key", category="trial", indicator_types=("ipv4", "ipv6")),
]}


def available(feed: Feed, settings: Settings) -> bool:
    return not feed.requires or bool(getattr(settings, feed.requires, None))
