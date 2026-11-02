"""Domain-name helpers built on the Public Suffix List (bundled snapshot, no network)."""

from __future__ import annotations

import re

import tldextract

# suffix_list_urls=() -> always use the snapshot shipped with tldextract (offline, deterministic)
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


# Reserved (RFC 2606 / 6761 / 8375) and common private TLDs are not in the PSL; treat them as
# one-label suffixes so demo data and internal domains (corp.internal) behave like public ones.
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "corp", "home", "intranet"}


def split(domain: str) -> tuple[str, str, str]:
    """Return (subdomain, registrable label, public suffix) for a hostname."""
    name = domain.lower().strip().rstrip(".")
    labels = name.split(".")
    if len(labels) >= 2 and labels[-1] in RESERVED_TLDS:
        return ".".join(labels[:-2]), labels[-2], labels[-1]
    r = _extract(name)
    return r.subdomain, r.domain, r.suffix


def registrable(domain: str) -> str | None:
    """``login.secure.example.co.uk`` -> ``example.co.uk``. None if not a valid public hostname."""
    sub, dom, suf = split(domain)
    if not dom or not suf:
        return None
    return f"{dom}.{suf}"


def is_valid_hostname(name: str) -> bool:
    name = name.lower().rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    try:
        ascii_name = name.encode("idna").decode() if not name.isascii() else name
    except UnicodeError:
        return False
    labels = ascii_name.split(".")
    if not all(_LABEL_RE.match(lbl) for lbl in labels):
        return False
    _, dom, suf = split(ascii_name)
    return bool(dom and suf)


def to_ascii(name: str) -> str:
    """IDNA-encode a hostname (``exämple.com`` -> ``xn--exmple-cua.com``)."""
    name = name.lower().strip().rstrip(".")
    if name.isascii():
        return name
    return name.encode("idna").decode()


def to_unicode(name: str) -> str:
    try:
        return name.encode().decode("idna")
    except UnicodeError:
        return name


def is_subdomain_of(name: str, root: str) -> bool:
    name, root = name.lower().rstrip("."), root.lower().rstrip(".")
    return name == root or name.endswith("." + root)
