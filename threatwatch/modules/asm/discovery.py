"""Sub-domain discovery: passive sources (CT logs, passive DNS, archives) + DNS brute force."""

from __future__ import annotations

import asyncio
import logging
import random
import re
import string
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ...config import get_settings
from ...core import dnsutil, http
from ...core.domains import is_subdomain_of, is_valid_hostname

log = logging.getLogger(__name__)
WORDLIST = Path(__file__).resolve().parents[2] / "data" / "subdomains.txt"


def _clean(name: str, root: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    name = re.sub(r"^\*\.", "", name)
    if "@" in name or " " in name:
        return None
    if not is_subdomain_of(name, root) or not is_valid_hostname(name):
        return None
    return name


async def src_crtsh(c: httpx.AsyncClient, root: str) -> set[str]:
    r = await c.get("https://crt.sh/", params={"q": f"%.{root}", "output": "json"}, timeout=60)
    r.raise_for_status()
    out = set()
    for row in r.json():
        for n in str(row.get("name_value", "")).split("\n"):
            out.add(n)
        out.add(row.get("common_name", ""))
    return out


async def src_certspotter(c, root):
    r = await c.get("https://api.certspotter.com/v1/issuances",
                    params={"domain": root, "include_subdomains": "true", "expand": "dns_names"})
    r.raise_for_status()
    return {n for row in r.json() for n in row.get("dns_names", [])}


async def src_hackertarget(c, root):
    r = await c.get("https://api.hackertarget.com/hostsearch/", params={"q": root})
    r.raise_for_status()
    if "error" in r.text[:100].lower() or "API count exceeded" in r.text:
        raise RuntimeError(r.text[:100])
    return {line.split(",")[0] for line in r.text.splitlines() if "," in line}


async def src_wayback(c, root):
    r = await c.get("https://web.archive.org/cdx/search/cdx",
                    params={"url": f"*.{root}", "output": "json", "fl": "original", "collapse": "urlkey",
                            "limit": 5000}, timeout=60)
    r.raise_for_status()
    rows = r.json()[1:] if r.text.strip() else []
    return {urlsplit(row[0] if "://" in row[0] else "http://" + row[0]).hostname or "" for row in rows}


async def src_otx(c, root):
    key = get_settings().otx_api_key
    if not key:
        return set()
    r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{root}/passive_dns",
                    headers={"X-OTX-API-KEY": key})
    r.raise_for_status()
    return {row.get("hostname", "") for row in r.json().get("passive_dns", [])}


PASSIVE_SOURCES = {"crt.sh": src_crtsh, "certspotter": src_certspotter, "hackertarget": src_hackertarget,
                   "wayback": src_wayback, "otx": src_otx}


async def passive(root: str) -> tuple[dict[str, set[str]], dict[str, str]]:
    """-> ({hostname: {sources}}, {source: error})"""
    found: dict[str, set[str]] = {root: {"root"}}
    errors: dict[str, str] = {}
    async with http.client(timeout=40) as c:
        async def run(name, fn):
            try:
                return name, await fn(c, root)
            except Exception as exc:  # noqa: BLE001
                errors[name] = f"{type(exc).__name__}: {exc}"[:200]
                return name, set()

        for name, names in await asyncio.gather(*(run(n, f) for n, f in PASSIVE_SOURCES.items())):
            for n in names:
                cn = _clean(n or "", root)
                if cn:
                    found.setdefault(cn, set()).add(name)
    return found, errors


async def wildcard_ips(root: str) -> set[str]:
    """IPs returned for random labels -> wildcard DNS; used to discard brute-force false positives."""
    ips: set[str] = set()
    for _ in range(2):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        ips.update(await dnsutil.query(f"{label}.{root}", "A"))
    return ips


async def brute_force(root: str, concurrency: int = 100) -> set[str]:
    words = [w.strip() for w in WORDLIST.read_text().splitlines() if w.strip() and not w.startswith("#")]
    wild = await wildcard_ips(root)
    sem = asyncio.Semaphore(concurrency)
    found: set[str] = set()

    async def one(w: str):
        name = f"{w}.{root}"
        async with sem:
            a = await dnsutil.query(name, "A")
        if a and not set(a) <= wild:
            found.add(name)
        elif not a and not wild:
            async with sem:
                if await dnsutil.query(name, "CNAME"):
                    found.add(name)

    await asyncio.gather(*(one(w) for w in words))
    return found
