"""Attack surface management scan pipeline.

    discover (CT logs, passive DNS, archives, DNS brute force)
      -> resolve (A/AAAA/CNAME) -> enrich (ASN / hosting) -> threat-intel cross-check
      -> probe (HTTP fingerprint, TLS certificate)        [semi-passive: normal client traffic]
      -> active checks (ports, sensitive paths, AXFR)    [only when scan.active is True]
      -> findings (rules in checks.py) -> risk score + grade -> alerts
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
from collections import defaultdict

from sqlalchemy import or_, select

from ...config import get_settings
from ...core import dnsutil, http
from ...core.alerts import raise_alert
from ...core.risk import clamp
from ...db import session_scope
from ...models import AsmAsset, AsmFinding, AsmScan, Indicator, utcnow
from . import checks, discovery, probes

log = logging.getLogger(__name__)

SEV_POINTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (101, "F")]


# The worst severity present bounds the score: breadth of minor issues alone cannot fail a target,
# and a single critical exposure cannot hide behind an otherwise clean surface.
SEV_BANDS = {"critical": (65, 100), "high": (25, 64), "medium": (10, 44), "low": (0, 24), "info": (0, 9)}


def risk_from_findings(findings: list[dict]) -> int:
    if not findings:
        return 0
    points = sum(SEV_POINTS.get(f["severity"], 0) for f in findings)
    risk = 100 * (1 - math.exp(-points / 50))
    worst = min((f["severity"] for f in findings), key=lambda s: list(SEV_POINTS).index(s) if s in SEV_POINTS else 9)
    lo, hi = SEV_BANDS.get(worst, (0, 100))
    return clamp(min(hi, max(lo, risk)))


def grade_for(risk: int) -> str:
    return next(g for limit, g in GRADES if risk < limit)


def _prioritise(found: dict[str, set[str]], root: str, limit: int) -> list[str]:
    def key(h):
        return (h != root, h != f"www.{root}", -len(found[h]), h.count("."), h)
    return sorted(found, key=key)[:limit]


def _intel_hits(hosts: list[str], ips: list[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    with session_scope() as db:
        q = select(Indicator).where(Indicator.active.is_(True), or_(
            (Indicator.type == "domain") & Indicator.value.in_(hosts or [""]),
            (Indicator.type.in_(["ipv4", "ipv6"])) & Indicator.value.in_(ips or [""]),
        ))
        for ind in db.scalars(q):
            out[ind.value].append({"value": ind.value, "sources": ind.sources, "threat_types": ind.threat_types,
                                   "score": ind.score})
        # CIDR blocklists (Spamhaus DROP): match IPs against listed networks
        nets = [(ipaddress.ip_network(v), v) for (v,) in db.execute(
            select(Indicator.value).where(Indicator.type == "cidr", Indicator.active.is_(True)))]
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net, v in nets:
                if addr.version == net.version and addr in net:
                    out[ip].append({"value": f"{ip} (in {v})", "sources": ["spamhaus_drop"],
                                    "threat_types": ["hijacked_netblock"], "score": 80})
    return out


def _kev_products() -> list[dict]:
    with session_scope() as db:
        return [{"cve": i.value, "vendor": (i.context or {}).get("vendor"), "product": (i.context or {}).get("product")}
                for i in db.scalars(select(Indicator).where(Indicator.type == "cve"))]


async def run_scan(scan_id: int, job_id: int | None = None) -> dict:
    settings = get_settings()
    with session_scope() as db:
        scan = db.get(AsmScan, scan_id)
        root, active = scan.root_domain, scan.active
        scan.status, scan.started_at = "running", utcnow()
    try:
        stats = await _pipeline(scan_id, root, active, settings)
    except Exception as exc:
        with session_scope() as db:
            scan = db.get(AsmScan, scan_id)
            scan.status, scan.message, scan.finished_at = "failed", f"{type(exc).__name__}: {exc}", utcnow()
        raise
    return stats


async def _pipeline(scan_id: int, root: str, active: bool, settings) -> dict:
    # 1. discovery -------------------------------------------------------------------------
    found, source_errors = await discovery.passive(root)
    for h in await discovery.brute_force(root):
        found.setdefault(h, set()).add("bruteforce")
    hosts = _prioritise(found, root, settings.asm_max_hosts)
    log.info("asm %s: %d names discovered, probing %d", root, len(found), len(hosts))

    # 2. resolution ------------------------------------------------------------------------
    sem = asyncio.Semaphore(50)

    async def resolve(h):
        async with sem:
            r = await dnsutil.resolve_host(h)
            r["cname_resolves"] = None
            if r["cname"] and not r["a"] and not r["aaaa"]:
                r["cname_resolves"] = await dnsutil.exists(r["cname"]) != "nxdomain"
            return h, r

    dns_map = dict(await asyncio.gather(*(resolve(h) for h in hosts)))
    live_hosts = [h for h in hosts if dns_map[h]["a"] or dns_map[h]["aaaa"]]
    ip_hosts: dict[str, list[str]] = defaultdict(list)
    for h in live_hosts:
        for ip in dns_map[h]["a"] + dns_map[h]["aaaa"]:
            ip_hosts[ip].append(h)
    ips = list(ip_hosts)[:300]

    # 3. enrichment ------------------------------------------------------------------------
    asn_map = dict(zip(ips, await asyncio.gather(*(dnsutil.asn_lookup(ip) for ip in ips))))
    intel = _intel_hits(hosts, ips)
    kev = _kev_products()

    # 4. HTTP + TLS ------------------------------------------------------------------------
    hsem = asyncio.Semaphore(20)
    async with http.client(timeout=10, verify=False) as c:
        async def web(h):
            async with hsem:
                res = await probes.http_probe(c, h)
                tls = await probes.tls_info(h) if res.get("https") else {}
                sens = []
                if active and (res.get("https") or res.get("http")):
                    base = (res.get("https") or res.get("http"))["url"]
                    sens = await probes.sensitive_paths(c, base)
                body = ""
                if dns_map[h]["cname"]:
                    try:
                        body = (await c.get(f"http://{h}/")).text[:20000]
                    except Exception:  # noqa: BLE001
                        body = ""
                return h, res, tls, sens, body

        web_results = {r[0]: r[1:] for r in await asyncio.gather(*(web(h) for h in live_hosts))}
        cname_only = [h for h in hosts if dns_map[h]["cname"] and h not in web_results]

    # 5. active: port scan + AXFR ----------------------------------------------------------
    port_map: dict[str, list[dict]] = {}
    axfr: dict[str, list[str]] = {}
    if active:
        psem = asyncio.Semaphore(settings.asm_concurrency)
        scan_ips = [ip for ip in ips if ":" not in ip][:100]

        async def ports_for(ip):
            org = asn_map.get(ip, {}).get("org")
            cdn = probes.hosting_from_org(org) in ("Cloudflare", "Akamai", "Fastly", "Imperva")
            plist = [80, 443, 8080, 8443] if cdn else None  # CDNs answer on everything; don't misreport
            return ip, await probes.scan_ports(ip, plist, sem=psem)

        port_map = dict(await asyncio.gather(*(ports_for(ip) for ip in scan_ips)))
        for ns in (await dnsutil.query(root, "NS"))[:4]:
            ns_ips = await dnsutil.query(ns, "A")
            if ns_ips:
                names = await asyncio.to_thread(dnsutil.try_axfr, root, ns_ips[0])
                if names:
                    axfr[ns] = names

    # 6. root-level DNS / mail hygiene -----------------------------------------------------
    mx, txt, dmarc, caa, ds, wild = await asyncio.gather(
        dnsutil.query(root, "MX"), dnsutil.query(root, "TXT"), dnsutil.query(f"_dmarc.{root}", "TXT"),
        dnsutil.query(root, "CAA"), dnsutil.query(root, "DS"), discovery.wildcard_ips(root))

    # 7. findings --------------------------------------------------------------------------
    findings: list[dict] = []
    findings += checks.check_email(root, mx, txt, dmarc)
    findings += checks.check_dns(root, caa, ds, axfr, bool(wild))
    assets: list[dict] = []
    for h in hosts:
        d = dns_map[h]
        res, tls, sens, body = web_results.get(h, ({}, {}, [], ""))
        host_ips = d["a"] + d["aaaa"]
        host_findings = []
        host_findings += checks.check_tls(h, tls)
        host_findings += checks.check_http(h, res, kev)
        host_findings += checks.check_sensitive(h, sens)
        host_findings += checks.check_takeover(h, d["cname"], d["cname_resolves"], body)
        host_findings += checks.check_nonprod(h, root, bool(host_ips), res)
        hits = intel.get(h, []) + [x for ip in host_ips for x in intel.get(ip, [])]
        host_findings += checks.check_intel(h, host_ips, hits)
        host_ports = []
        for ip in host_ips:
            for p in port_map.get(ip, []):
                if p not in host_ports:
                    host_ports.append({**p, "ip": ip})
            # report port findings once per IP, on its first hostname
            if ip_hosts.get(ip, [None])[0] == h:
                for f in checks.check_ports(h, port_map.get(ip, [])):
                    f["evidence"] = f"{ip}: {f['evidence']}".strip(": ")
                    host_findings.append(f)
        findings += host_findings
        main = res.get("https") or res.get("http") or {}
        org = next((asn_map.get(ip, {}).get("org") for ip in host_ips if asn_map.get(ip)), None)
        assets.append({
            "hostname": h, "sources": sorted(found.get(h, [])), "resolved": bool(host_ips), "ips": host_ips,
            "cname": d["cname"], "asn": {ip: asn_map.get(ip, {}) for ip in host_ips if ip in asn_map},
            "hosting": probes.hosting_from_org(org), "ports": host_ports,
            "http": {k: v for k, v in res.items()}, "tls": tls, "technologies": main.get("technologies", []),
            "risk_score": risk_from_findings(host_findings),
        })

    risk = risk_from_findings(findings)
    grade = grade_for(risk)
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    summary = {
        "names_discovered": len(found), "hosts_analysed": len(hosts), "hosts_resolved": len(live_hosts),
        "unique_ips": len(ips), "web_services": sum(1 for r in web_results.values() if r[0].get("https") or r[0].get("http")),
        "open_ports": sum(len(v) for v in port_map.values()), "findings": len(findings),
        "by_severity": dict(by_sev), "source_errors": source_errors, "dangling_cnames": len(cname_only),
        "certificates": sum(1 for r in web_results.values() if r[1] and not r[1].get("error")),
        "hosting": dict(sorted(_count(a["hosting"] or "Other" for a in assets if a["resolved"]).items())),
        "email_security": {"mx": mx, "spf": next((t for t in txt if t.lower().startswith("v=spf1")), None),
                           "dmarc": next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)},
        "active": active,
    }

    with session_scope() as db:
        scan = db.get(AsmScan, scan_id)
        for a in assets:
            db.add(AsmAsset(scan_id=scan_id, **a))
        for f in findings:
            db.add(AsmFinding(scan_id=scan_id, **f))
        scan.status, scan.finished_at = "done", utcnow()
        scan.risk_score, scan.grade, scan.summary = risk, grade, summary
        scan.message = f"{len(hosts)} hosts, {len(findings)} findings, grade {grade}"
        alerts = 0
        for f in findings:
            if f["severity"] in ("critical", "high"):
                a = raise_alert(db, module="asm", severity=f["severity"], title=f"{f['hostname']}: {f['title']}",
                                description=f"{f['description']} Remediation: {f['remediation']}",
                                ref_type="asm_scan", ref_id=scan_id,
                                dedup_key=f"asm:{root}:{f['hostname']}:{f['check_id']}")
                alerts += bool(a)
    return {"scan_id": scan_id, "root": root, "risk": risk, "grade": grade, "alerts": alerts, **{
        k: summary[k] for k in ("names_discovered", "hosts_resolved", "findings")},
        "message": f"{root}: grade {grade} (risk {risk}), {len(findings)} findings"}


def _count(items) -> dict:
    out: dict = defaultdict(int)
    for i in items:
        out[i] += 1
    return out


def create_scan(root: str, active: bool) -> int:
    with session_scope() as db:
        scan = AsmScan(root_domain=root, active=active, status="queued")
        db.add(scan)
        db.flush()
        return scan.id
