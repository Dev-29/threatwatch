"""Manual ingestion of leak files (combolists, stealer-log ULP dumps, CSV exports, paste text).

Analysts often obtain dumps from forums or incident partners. This importer matches each line
against the watchlist and records exposures **without storing plaintext secrets** (only a mask).

Supported line shapes (auto-detected):
    email:password            email;password          email|password
    url:login:password        url|login|password      (infostealer "ULP" format)
    CSV with any column containing an email address
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select

from ...core.domains import is_subdomain_of
from ...db import session_scope
from ...models import Asset
from .connectors import LeakFinding, mask_secret
from .service import alert_for, upsert_exposure

EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+", re.I)
URL_RE = re.compile(r"https?://([^/:\s|;]+)", re.I)
MAX_MATCHES = 5000


@dataclass
class _Hit:
    asset: Asset
    identifier: str
    secret_mask: str | None
    login_url_host: str | None


def _secret_after(line: str, email_end: int) -> str | None:
    rest = line[email_end:]
    if rest[:1] in (":", ";", "|", ",", "\t", " "):
        secret = re.split(r"[\s|;,]", rest[1:].strip(), maxsplit=1)[0] if rest[1:].strip() else ""
        return secret or None
    return None


def _parse_line(line: str) -> list[tuple[str, str | None, str | None]]:
    """-> [(email_or_login, secret, url_host)]"""
    m = URL_RE.match(line)
    if m:
        # ULP: <url>:<login>:<pass>  or  <url>|<login>|<pass>
        url_host = m.group(1).lower()
        rest = line.split("://", 1)[1]
        parts = re.split(r"[|;\t ]", rest) if re.search(r"[|;\t ]", rest) else rest.split(":")
        parts = [p for p in parts if p]
        if len(parts) >= 3:
            return [(parts[-2].lower(), parts[-1], url_host)]
    return [(em.group(0).lower(), _secret_after(line, em.end()), None) for em in EMAIL_RE.finditer(line)]


def import_text(content: str, filename: str, source_type: str = "combolist", leaked_at=None) -> dict:
    with session_scope() as db:
        assets = db.scalars(select(Asset).where(Asset.enabled.is_(True))).all()
        emails = {a.value.lower(): a for a in assets if a.type == "email"}
        for a in assets:
            if a.type == "executive":
                for e in (a.meta or {}).get("emails", []):
                    emails[e.lower()] = a
        domains = [a for a in assets if a.type == "domain"]

        hits: dict[tuple[int, str], _Hit] = {}
        lines = 0
        for raw in content.splitlines():
            lines += 1
            line = raw.strip()
            if not line:
                continue
            for login, secret, url_host in _parse_line(line):
                asset = emails.get(login)
                if asset is None and "@" in login:
                    dom = login.split("@", 1)[1]
                    asset = next((d for d in domains if is_subdomain_of(dom, d.value)), None)
                if asset is None and url_host:
                    # credential for one of *our* login portals, whatever the username
                    asset = next((d for d in domains if is_subdomain_of(url_host, d.value)), None)
                if asset is None:
                    continue
                key = (asset.id, login)
                if key not in hits:
                    hits[key] = _Hit(asset, login, mask_secret(secret) if secret else None, url_host)
                if len(hits) >= MAX_MATCHES:
                    break

        new = alerts = 0
        for hit in hits.values():
            has_pw = hit.secret_mask is not None
            title = f"Credential for {hit.identifier} in imported file {filename}"
            if hit.login_url_host:
                title = f"Login for {hit.login_url_host} ({hit.identifier}) in imported file {filename}"
            f = LeakFinding(
                source=f"import:{filename}"[:80], source_type=source_type, title=title, identifier=hit.identifier,
                description="Matched during manual leak-file import. Plaintext secrets are never stored; "
                            f"masked value: {hit.secret_mask or 'n/a'}",
                data_classes=["Email addresses"] + (["Passwords"] if has_pw else []),
                has_password=has_pw, password_plaintext=has_pw, leaked_at=leaked_at, credibility=0.8,
                raw={"masked_secret": hit.secret_mask, "login_url_host": hit.login_url_host, "file": filename},
            )
            exp, created = upsert_exposure(db, hit.asset, f)
            if created:
                new += 1
                alerts += alert_for(db, hit.asset, exp)
    return {"lines": lines, "matches": len(hits), "new_exposures": new, "alerts": alerts}
