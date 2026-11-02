"""Domain registration data via RDAP (the structured successor to WHOIS). Uses the rdap.org bootstrap."""

from __future__ import annotations

from datetime import datetime

import httpx

from ...core import http


def _date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


async def lookup(domain: str, c: httpx.AsyncClient | None = None) -> dict | None:
    own = c is None
    c = c or http.client(timeout=15, headers={"Accept": "application/rdap+json"})
    try:
        r = await c.get(f"https://rdap.org/domain/{domain}")
        if r.status_code != 200:
            return None
        d = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    finally:
        if own:
            await c.aclose()
    out: dict = {"created": None, "expires": None, "registrar": None, "status": d.get("status", [])}
    for ev in d.get("events", []):
        if ev.get("eventAction") == "registration":
            out["created"] = _date(ev.get("eventDate"))
        elif ev.get("eventAction") == "expiration":
            out["expires"] = _date(ev.get("eventDate"))
    for ent in d.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    out["registrar"] = item[3]
    return out
