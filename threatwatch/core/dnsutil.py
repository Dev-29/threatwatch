"""Async DNS helpers (dnspython)."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone

_resolver: dns.asyncresolver.Resolver | None = None


def resolver() -> dns.asyncresolver.Resolver:
    global _resolver
    if _resolver is None:
        try:
            r = dns.asyncresolver.Resolver()
        except dns.resolver.NoResolverConfiguration:  # pragma: no cover - containers w/o resolv.conf
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = ["1.1.1.1", "8.8.8.8"]
        r.timeout = 3.0
        r.lifetime = 6.0
        _resolver = r
    return _resolver


async def query(name: str, rdtype: str) -> list[str]:
    """Return record strings, or [] on NXDOMAIN / no answer / timeout."""
    try:
        ans = await resolver().resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.NoAnswer, dns.name.EmptyLabel, dns.name.LabelTooLong, ValueError):
        return []
    except dns.exception.DNSException:
        return []
    if ans.rrset is None:
        return []
    out = []
    for r in ans:
        if rdtype == "MX":
            out.append(str(r.exchange).rstrip("."))
        elif rdtype == "TXT":
            out.append(b"".join(r.strings).decode(errors="replace"))
        else:
            out.append(r.to_text().rstrip("."))
    return out


async def exists(name: str) -> str:
    """'nxdomain' | 'exists' | 'unknown' for a name (SOA/NS presence check)."""
    try:
        await resolver().resolve(name, "NS", raise_on_no_answer=False)
        return "exists"
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except dns.exception.DNSException:
        return "unknown"


async def resolve_host(name: str) -> dict:
    """A/AAAA/CNAME for a hostname."""
    a, aaaa, cname = await asyncio.gather(query(name, "A"), query(name, "AAAA"), query(name, "CNAME"))
    return {"a": a, "aaaa": aaaa, "cname": cname[0] if cname else None}


async def asn_lookup(ip: str) -> dict:
    """Team Cymru IP-to-ASN mapping over DNS (no API key required)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = addr.exploded.replace(":", "")
        q = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    txt = await query(q, "TXT")
    if not txt:
        return {}
    parts = [p.strip() for p in txt[0].split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    info = {
        "asn": asn,
        "prefix": parts[1] if len(parts) > 1 else "",
        "cc": parts[2] if len(parts) > 2 else "",
        "registry": parts[3] if len(parts) > 3 else "",
    }
    if asn:
        name = await query(f"AS{asn}.asn.cymru.com", "TXT")
        if name:
            info["org"] = name[0].split("|")[-1].strip()
    return info


def try_axfr(domain: str, nameserver_ip: str, timeout: float = 5.0) -> list[str] | None:
    """Attempt a zone transfer (blocking). Returns record names if the server allows it."""
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain, timeout=timeout, lifetime=timeout * 2))
    except Exception:
        return None
    return sorted(str(n) for n in z.nodes.keys())
