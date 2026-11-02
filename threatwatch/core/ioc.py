"""IOC normalisation: refanging, type detection, canonicalisation and validation.

Every indicator that enters the database passes through :func:`normalize`, which guarantees a
single canonical representation per (type, value) so that de-duplication across feeds works.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from . import domains

IOC_TYPES = ("ipv4", "ipv6", "cidr", "domain", "url", "md5", "sha1", "sha256", "email", "cve", "x509-sha1")

_HEX = re.compile(r"^[a-f0-9]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_EMAIL = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9\-]+\.)+[a-z0-9\-]{2,}$", re.I)

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[at\]|\(at\)|\[@\]", re.I), "@"),
]

# Registrable domains that are never treated as malicious on their own (prevents feed noise
# such as "google.com" landing in a blocklist). Sub-domains / URLs on them are still accepted.
BENIGN_REGISTRABLE = {
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "github.com", "githubusercontent.com", "googleusercontent.com", "live.com",
    "office.com", "windows.net", "azure.com", "akamaihd.net", "wikipedia.org", "twitter.com",
    "x.com", "linkedin.com", "instagram.com", "dropbox.com", "yahoo.com", "bing.com", "gstatic.com",
    "googleapis.com", "blogspot.com", "sharepoint.com", "outlook.com", "icloud.com", "whatsapp.com",
}


class InvalidIOC(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedIOC:
    type: str
    value: str


def refang(value: str) -> str:
    v = value.strip().strip("\"'<>").strip()
    for pat, rep in _REFANG:
        v = pat.sub(rep, v)
    return v


def detect_type(value: str) -> str | None:
    """Best-effort type detection for a refanged value."""
    v = value.strip()
    if not v:
        return None
    if _CVE.match(v):
        return "cve"
    if "://" in v:
        return "url"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
    if _EMAIL.match(v):
        return "email"
    lv = v.lower()
    if _HEX.match(lv):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(lv))
    if domains.is_valid_hostname(lv):
        return "domain"
    return None


def _norm_ip(v: str) -> tuple[str, str]:
    ip = ipaddress.ip_address(v)
    if not ip.is_global:
        raise InvalidIOC(f"non-routable address {v}")
    return ("ipv4" if ip.version == 4 else "ipv6", ip.compressed)


def _norm_url(v: str) -> str:
    parts = urlsplit(v)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https", "ftp", "tcp", "udp"):
        raise InvalidIOC(f"unsupported url scheme {scheme!r}")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidIOC("url without host")
    try:
        host = domains.to_ascii(host)
    except UnicodeError as exc:
        raise InvalidIOC(str(exc)) from exc
    port = parts.port
    netloc = host if ":" not in host else f"[{host}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize(value: str, type_hint: str | None = None) -> NormalizedIOC:
    """Return the canonical (type, value) or raise :class:`InvalidIOC`."""
    if value is None:
        raise InvalidIOC("empty")
    v = refang(str(value))
    if not v:
        raise InvalidIOC("empty")

    # "1.2.3.4:443" -> ip ; feeds often append ports
    if type_hint in (None, "ipv4", "ip") and re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", v):
        v = v.split(":")[0]

    t = type_hint if type_hint in IOC_TYPES else None
    if t in (None, "domain") and v.startswith("*."):
        v = v[2:]
    detected = detect_type(v)
    if t is None:
        t = detected
    if t is None:
        raise InvalidIOC(f"unrecognised indicator {value!r}")

    if t in ("ipv4", "ipv6"):
        t, v = _norm_ip(v)
    elif t == "cidr":
        net = ipaddress.ip_network(v, strict=False)
        if not net.is_global:
            raise InvalidIOC(f"non-routable network {v}")
        v = net.compressed
    elif t == "domain":
        v = v.lower().rstrip(".")
        try:
            v = domains.to_ascii(v)
        except UnicodeError as exc:
            raise InvalidIOC(str(exc)) from exc
        if not domains.is_valid_hostname(v):
            raise InvalidIOC(f"invalid domain {v!r}")
        if v in BENIGN_REGISTRABLE:
            raise InvalidIOC(f"allow-listed domain {v}")
    elif t == "url":
        if "://" not in v:
            v = "http://" + v
        v = _norm_url(v)
    elif t in ("md5", "sha1", "sha256", "x509-sha1"):
        v = v.lower().replace(":", "")
        expected = {"md5": 32, "sha1": 40, "sha256": 64, "x509-sha1": 40}[t]
        if not _HEX.match(v) or len(v) != expected:
            raise InvalidIOC(f"invalid {t} hash")
    elif t == "email":
        v = v.lower()
        if not _EMAIL.match(v):
            raise InvalidIOC("invalid email")
    elif t == "cve":
        v = v.upper()
        if not _CVE.match(v):
            raise InvalidIOC("invalid CVE id")
    return NormalizedIOC(t, v)


def try_normalize(value: str, type_hint: str | None = None) -> NormalizedIOC | None:
    try:
        return normalize(value, type_hint)
    except (InvalidIOC, ValueError):
        return None


def host_of(ioc_type: str, value: str) -> str | None:
    """Hostname component of a domain/url indicator (used for cross-module matching)."""
    if ioc_type == "domain":
        return value
    if ioc_type == "url":
        return urlsplit(value).hostname
    return None


def extract_iocs(text: str) -> list[NormalizedIOC]:
    """Pull every recognisable indicator out of free text (used by the bulk lookup box)."""
    out: dict[tuple[str, str], NormalizedIOC] = {}
    for token in re.split(r"[\s,;|\"'<>()]+", refang(text)):
        token = token.strip().rstrip(".")
        if not token:
            continue
        n = try_normalize(token)
        if n:
            out[(n.type, n.value)] = n
    return list(out.values())
