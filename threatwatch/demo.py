"""Demo data for a fictional organisation ("Acme Corp", acme-corp.example).

Everything here is synthetic: domains use the reserved ``.example`` / ``.invalid`` TLDs, IPs come
from the RFC 5737 documentation ranges, and feeds are named ``demo_*`` so nothing is attributed
to a real source. The data is pushed through the *real* scoring, ATT&CK mapping and ASM rule
engines, so the UI shows exactly what production data looks like.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select

from .core.alerts import raise_alert
from .db import Base, session_scope
from .models import Alert, Asset, AsmAsset, AsmFinding, AsmScan, LookalikeDomain, utcnow
from .modules.asm import checks
from .modules.asm.probes import PORTS
from .modules.asm.service import grade_for, risk_from_findings
from .modules.darkweb.connectors import LeakFinding
from .modules.darkweb.service import alert_for, upsert_exposure
from .modules.intel.feeds import Feed
from .modules.intel.service import _Agg, merge_into_db
from .modules.phishing.service import score_lookalike

DOMAIN = "acme-corp.example"
R = random.Random(1337)


def _ago(days: float) -> datetime:
    return utcnow() - timedelta(days=days)


def _assets(db) -> dict[str, Asset]:
    rows = [
        Asset(type="domain", value=DOMAIN, label="Acme Corp primary domain", criticality="critical",
              meta={"monitor_lookalikes": True, "demo": True}),
        Asset(type="brand", value="AcmeCorp", label="Brand name", criticality="high", meta={"demo": True}),
        Asset(type="executive", value="Jane Doe", label="CEO", criticality="critical",
              meta={"emails": [f"jane.doe@{DOMAIN}"], "usernames": ["janedoe_acme"], "demo": True}),
        Asset(type="executive", value="John Roe", label="CFO", criticality="high",
              meta={"emails": [f"john.roe@{DOMAIN}"], "demo": True}),
        Asset(type="email", value=f"it-admin@{DOMAIN}", label="IT admin mailbox", criticality="high", meta={"demo": True}),
        Asset(type="email", value=f"m.smith@{DOMAIN}", label="Employee", criticality="medium", meta={"demo": True}),
        Asset(type="email", value=f"support@{DOMAIN}", label="Shared mailbox", criticality="low", meta={"demo": True}),
        Asset(type="keyword", value="Project Falcon", label="Confidential project codename", criticality="high",
              meta={"demo": True}),
    ]
    db.add_all(rows)
    db.flush()
    return {a.label: a for a in rows}


def _exposures(db, a: dict[str, Asset]) -> int:
    F = LeakFinding
    items = [
        (a["CEO"], F("demo_stealer_intel", "stealer_log", "Infostealer infection on 'JDOE-LAPTOP' exposing saved credentials",
                     f"jane.doe@{DOMAIN}", "[demo] Lumma Stealer infection; 14 corporate credentials incl. sso.acme-corp.example and VPN.",
                     None, ["Passwords", "Usernames", "Browser cookies", "Autofill data"], True, True, 14, _ago(9), 0.9, True)),
        (a["Acme Corp primary domain"], F("demo_ransomware_tracker", "ransomware_leak",
                                          "'Acme Corp Supplier Ltd' listed on demo-locker ransomware leak site", DOMAIN,
                                          "[demo] Supplier claimed by a ransomware group; 120 GB of shared project data allegedly exfiltrated.",
                                          None, ["Corporate data", "Possibly employee / customer PII"], False, False, None, _ago(4), 0.5)),
        (a["Acme Corp primary domain"], F("demo_stealer_intel", "stealer_log",
                                          f"37 employee machine(s) infected by infostealers with {DOMAIN} credentials", DOMAIN,
                                          "[demo] Corporate logins captured by RedLine, Vidar and Lumma. Top URLs: sso, vpn, mail.",
                                          None, ["Passwords", "Usernames", "Browser cookies", "Corporate URLs"], True, True, 37, _ago(21), 0.9, True)),
        (a["CFO"], F("demo_breach_db", "breach", "MegaRetail breach", f"john.roe@{DOMAIN}",
                     "[demo] Online retailer breach exposing customer accounts.", None,
                     ["Email addresses", "Names", "Passwords", "Phone numbers", "Physical addresses"], True, False, 8_400_000, _ago(400), 0.9, True)),
        (a["CFO"], F("demo_breach_db", "combolist", "Combo list 'corp-mail-2026' leak", f"john.roe@{DOMAIN}",
                     "[demo] Email:password combo list traded on a forum.", None, ["Email addresses", "Passwords"], True, True, None, _ago(45), 0.7)),
        (a["IT admin mailbox"], F("demo_paste_monitor", "paste", "Paste 'vpn configs dump'", f"it-admin@{DOMAIN}",
                                  "[demo] Paste containing VPN profile and the admin mailbox.", None,
                                  ["Email addresses", "Passwords"], True, True, None, _ago(2), 0.7)),
        (a["Employee"], F("demo_breach_db", "breach", "SocialNet breach", f"m.smith@{DOMAIN}",
                          "[demo] Social network breach (bcrypt hashes).", None, ["Email addresses", "Passwords", "Usernames"],
                          True, False, 2_100_000, _ago(2200), 1.0, True)),
        (a["Employee"], F("demo_breach_db", "breach", "FitnessApp breach", f"m.smith@{DOMAIN}",
                          "[demo] Fitness tracking app breach.", None, ["Email addresses", "Dates of birth", "Geographic locations"],
                          False, False, 700_000, _ago(150), 0.8)),
        (a["Shared mailbox"], F("demo_breach_db", "breach", "Forum software breach", f"support@{DOMAIN}",
                                "[demo] Old forum breach.", None, ["Email addresses", "Usernames"], False, False, 90_000, _ago(3000), 0.6)),
        (a["Confidential project codename"], F("demo_onion_monitor", "forum", "Mention of 'Project Falcon' on demo forum",
                                                "Project Falcon", "...selling access + internal docs for 'Project Falcon' (acme) - DM for samples...",
                                                None, ["Mention", "Possible credentials"], True, False, None, _ago(1), 0.6)),
        (a["Acme Corp primary domain"], F("demo_code_search", "code_repo", f"Possible secret referencing {DOMAIN} in dev-user/infra-scripts/deploy.env",
                                          DOMAIN, "[demo] SMTP password committed to a public repository.", None,
                                          ["Source code", "Possible credentials"], True, False, None, _ago(12), 0.5)),
        (a["CEO"], F("demo_onion_monitor", "forum", "Mention of 'Jane Doe' on demo forum", "Jane Doe",
                     "...looking for fullz on Jane Doe acme ceo, paying well...", None, ["Mention"], False, False, None, _ago(6), 0.6)),
    ]
    n = 0
    for asset, f in items:
        f.url = "https://threatwatch.invalid/demo"
        exp, created = upsert_exposure(db, asset, f)
        if created:
            n += 1
            alert_for(db, asset, exp)
            exp.first_seen = (f.leaked_at or utcnow()) if (f.leaked_at and (utcnow() - f.leaked_at).days < 14) else _ago(R.randint(1, 13))
    db.flush()
    return n


def _demo_ip(i: int) -> str:
    blocks = ["192.0.2", "198.51.100", "203.0.113"]
    return f"{blocks[i % 3]}.{(i * 7) % 254 + 1}"


def _indicators(db) -> int:
    families = ["Emotet", "QakBot", "Lumma Stealer", "RedLine Stealer", "AsyncRAT", "Cobalt Strike", "LockBit", "Mirai", "XMRig"]
    feeds = {
        "demo_c2": Feed("demo_c2", "Demo C2 feed", "", "", None, 90),
        "demo_phish": Feed("demo_phish", "Demo phishing feed", "", "", None, 80),
        "demo_scanners": Feed("demo_scanners", "Demo scanner feed", "", "", None, 60),
        "demo_malware": Feed("demo_malware", "Demo malware feed", "", "", None, 85),
        "demo_kev": Feed("demo_kev", "Demo exploited-vuln feed", "", "", None, 100),
    }
    rows: dict[str, dict] = {k: {} for k in feeds}

    def add(feed, t, v, threat, fam=None, tags=(), ctx=None, desc=None, seen=None):
        rows[feed][(t, v)] = _Agg(t, v, feeds[feed].confidence, {threat}, {fam} if fam else set(), set(tags),
                                  "https://threatwatch.invalid/demo", seen or _ago(R.uniform(0, 40)), desc, ctx or {})

    for i in range(60):
        fam = families[i % 6]
        add("demo_c2", "ipv4", _demo_ip(i), "botnet_c2", fam, ["c2"], {"port": R.choice([443, 8080, 4444, 447])})
    for i in range(40):
        add("demo_c2", "domain", f"c2-{i:03d}.malicious.invalid", "c2", families[i % 6])
    for i in range(70):
        target = R.choice(["acmecorp", "bank", "m365", "parcel", "wallet"])
        add("demo_phish", "url", f"https://login-{target}-{i}.phish.invalid/secure/verify", "phishing", tags=["phishing"])
    for i in range(30):
        add("demo_phish", "domain", f"{R.choice(['secure', 'verify', 'account'])}-update-{i}.phish.invalid", "phishing",
            tags=["phishing"])
    for i in range(80):
        add("demo_scanners", "ipv4", _demo_ip(i + 30), "brute_force" if i % 2 else "scanner",
            tags=["ssh" if i % 2 else "scanner"])
    for i in range(50):
        fam = families[(i % 3) + 6]
        h = hashlib.sha256(f"demo{i}".encode()).hexdigest()
        add("demo_malware", "sha256", h, "malware", fam, ["exe"] if i % 2 else ["elf"])
    for i, (vendor, product, name) in enumerate([
        ("DemoVendor", "Edge VPN", "DemoVendor Edge VPN Remote Code Execution"),
        ("DemoVendor", "Mail Server", "DemoVendor Mail Server Privilege Escalation"),
        ("DemoSoft", "Browser", "DemoSoft Browser Use-After-Free"),
    ]):
        add("demo_kev", "cve", f"CVE-2099-{1000 + i}", "exploited_vulnerability",
            tags=["kev"] + (["ransomware"] if i == 0 else []),
            ctx={"vendor": vendor, "product": product, "vulnerability_name": name},
            desc=f"[demo] {vendor} {product}: {name}")
    # corroboration: some C2 IPs also reported by the scanner feed
    for i in range(30, 60):
        rows["demo_scanners"][("ipv4", _demo_ip(i))] = _Agg("ipv4", _demo_ip(i), 60, {"malicious_activity"},
                                                            set(), {"multi-blocklist"}, None, _ago(3), None, {})
    total = 0
    for name, feed in feeds.items():
        new, touched = merge_into_db(db, feed, rows[name])
        total += new
        for ind in touched:  # spread timestamps so dashboards and decay look realistic
            age = R.uniform(0, 30)
            ind.last_seen = ind.updated_at = _ago(age)
            ind.created_at = _ago(age + R.uniform(0, 5))
    db.flush()
    from .models import Indicator
    from .modules.intel.service import apply_scoring
    for ind in db.scalars(select(Indicator)):
        apply_scoring(ind)
    return total


def _lookalikes(db) -> int:
    specs = [
        ("acme-c0rp.example", "homoglyph", ["192.0.2.66"], ["mx.acme-c0rp.example"], 200, "Acme Corp | Sign in", 0.82, True, False, 6, True),
        ("acmecorp-login.example", "combosquatting", ["198.51.100.23"], [], 200, "Microsoft 365 - Sign in", 0.21, True, False, 3, True),
        ("acme-corp-sso.example", "combosquatting", ["203.0.113.40"], ["mail.acme-corp-sso.example"], 200, "Acme SSO", 0.74, True, False, 15, False),
        ("acrne-corp.example", "homoglyph", ["198.51.100.91"], ["mx1.parking.invalid"], 200, "acrne-corp.example is for sale", 0.05, False, True, 400, False),
        ("acme-crop.example", "transposition", ["192.0.2.12"], [], None, "", 0.0, False, False, 90, False),
        ("acmecorp.example", "hyphenation", ["203.0.113.5"], ["mx.acmecorp.example"], 200, "Acme Corp Supplier Portal", 0.35, False, False, 1200, False),
        ("acme-corp-invoice.example", "combosquatting", [], ["mx.acme-corp-invoice.example"], None, "", 0.0, False, False, 2, False),
        ("acme-cop.example", "omission", ["198.51.100.7"], [], 404, "Not Found", 0.0, False, False, 2000, False),
        ("xn--acme-crp-xxx.example", "idn-homograph", ["192.0.2.201"], [], 200, "Acme Corp", 0.66, True, False, 20, False),
        ("acme-corp-hr.example", "combosquatting", ["203.0.113.88"], [], 200, "Benefits enrollment", 0.28, True, False, 40, False),
    ]
    n = 0
    for dom, tech, a, mx, status, title, sim, login, parked, age, feed in specs:
        created = _ago(age)
        score, sev, factors = score_lookalike(technique=tech, has_a=bool(a), has_mx=bool(mx), page_live=bool(status and status < 400),
                                              parked=parked, similarity=sim, login_form=login,
                                              brand_mentioned="acme" in title.lower(), created=created, in_feed=feed)
        row = LookalikeDomain(brand_domain=DOMAIN, domain=dom, domain_unicode=dom, technique=tech, registered=True,
                              dns_a=a, dns_mx=mx, dns_ns=["ns1.demo-dns.invalid"], created_date=created,
                              registrar="Demo Registrar Inc.", http_status=status, final_url=f"https://{dom}/" if status else None,
                              title=title or None, similarity=sim, has_login_form=login, parked=parked, in_threat_feed=feed,
                              risk_score=score, severity=sev, score_factors=factors, first_seen=_ago(min(age, R.randint(1, 13))))
        db.add(row)
        db.flush()
        raise_alert(db, module="phishing", severity=sev, title=f"Look-alike domain {dom} ({tech}) targeting {DOMAIN}",
                    description=f"[demo] Risk {score}/100.", ref_type="lookalike", ref_id=row.id,
                    dedup_key=f"lookalike:{DOMAIN}:{dom}:{sev}")
        n += 1
    return n


def _asm(db) -> int:
    hosts = {
        DOMAIN: dict(ips=["192.0.2.10"], hosting="Cloudflare", ports=[80, 443], tech=["Cloudflare", "Next.js", "React"],
                     tls=dict(days=62), headers=True),
        f"www.{DOMAIN}": dict(ips=["192.0.2.10"], hosting="Cloudflare", ports=[], tech=["Cloudflare", "Next.js"], tls=dict(days=62), headers=True),
        f"vpn.{DOMAIN}": dict(ips=["198.51.100.20"], hosting=None, ports=[443, 4443], tech=["Fortinet FortiGate"], tls=dict(days=200, legacy=["TLSv1.0", "TLSv1.1"])),
        f"mail.{DOMAIN}": dict(ips=["198.51.100.21"], hosting=None, ports=[25, 443, 587, 993], tech=["Outlook Web App", "Microsoft IIS"], tls=dict(days=9)),
        f"jenkins.{DOMAIN}": dict(ips=["203.0.113.30"], hosting="AWS", ports=[22, 8080], tech=["Jenkins"], http_only=True, server="Jetty(10.0.13)"),
        f"dev.{DOMAIN}": dict(ips=["203.0.113.31"], hosting="AWS", ports=[22, 80, 443, 3306], tech=["PHP", "nginx"], tls=dict(days=-12), git=True, server="nginx/1.18.0"),
        f"staging-api.{DOMAIN}": dict(ips=["203.0.113.32"], hosting="AWS", ports=[443, 6379], tech=["Express", "Swagger UI"], tls=dict(days=30, self_signed=True)),
        f"legacy.{DOMAIN}": dict(ips=["198.51.100.40"], hosting=None, ports=[21, 80, 3389], tech=["Microsoft IIS", "ASP.NET"], http_only=True, server="Microsoft-IIS/7.5", listing=True),
        f"blog.{DOMAIN}": dict(cname="acme-blog.ghost.invalid", ips=[], takeover=True),
        f"shop.{DOMAIN}": dict(ips=["192.0.2.50"], hosting="Shopify", ports=[443], tech=["Shopify"], tls=dict(days=70), headers=True),
        f"grafana.{DOMAIN}": dict(ips=["203.0.113.33"], hosting="AWS", ports=[443], tech=["Grafana"], tls=dict(days=45)),
        f"sso.{DOMAIN}": dict(ips=["192.0.2.11"], hosting="Azure", ports=[443], tech=["Microsoft IIS"], tls=dict(days=150), headers=True),
    }
    kev = [{"cve": "CVE-2099-1000", "vendor": "fortinet", "product": "FortiOS"}]
    scan = AsmScan(root_domain=DOMAIN, active=True, status="done", started_at=_ago(1.02), finished_at=_ago(1))
    db.add(scan)
    db.flush()
    findings: list[dict] = []
    findings += checks.check_email(DOMAIN, [f"mail.{DOMAIN}"], ["v=spf1 include:_spf.demo.invalid ~all"],
                                   ["v=DMARC1; p=none; rua=mailto:dmarc@acme-corp.example"])
    findings += checks.check_dns(DOMAIN, [], [], {}, False)
    for h, s in hosts.items():
        hf: list[dict] = []
        tls = {}
        if "tls" in s:
            t = s["tls"]
            tls = {"subject_cn": h, "issuer_cn": "Demo CA" if not t.get("self_signed") else h, "days_left": t["days"],
                   "not_after": (utcnow() + timedelta(days=t["days"])).isoformat(), "self_signed": t.get("self_signed", False),
                   "trusted": not t.get("self_signed", False), "hostname_match": True, "legacy_protocols": t.get("legacy", []),
                   "key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256", "protocol": "TLSv1.3", "sans": [h]}
        web_entry = {"url": f"{'http' if s.get('http_only') else 'https'}://{h}/", "status": 200, "title": h.split(".")[0].title(),
                     "server": s.get("server"), "technologies": s.get("tech", []), "directory_listing": s.get("listing", False),
                     "security_headers": {k: s.get("headers", False) for k in ("strict-transport-security", "content-security-policy",
                                                                                "x-frame-options", "x-content-type-options")}}
        http = {} if not s["ips"] else ({"http": web_entry} if s.get("http_only") else
                                        {"https": web_entry, "http_redirects_to_https": True, "http_status": 301})
        ports = [{"port": p, "service": PORTS.get(p, "unknown"), "banner": "", "ip": s["ips"][0]}
                 for p in s.get("ports", [])]
        hf += checks.check_tls(h, tls)
        hf += checks.check_http(h, http, kev)
        hf += checks.check_ports(h, ports)
        hf += checks.check_nonprod(h, DOMAIN, bool(s["ips"]), http)
        if s.get("git"):
            hf += checks.check_sensitive(h, [{"path": "/.git/HEAD", "key": "git", "severity": "critical", "evidence": "ref: refs/heads/main"}])
        if s.get("takeover"):
            hf += checks.check_takeover(h, s["cname"], False)
        findings += hf
        db.add(AsmAsset(scan_id=scan.id, hostname=h, sources=["crt.sh", "certspotter"] if h != DOMAIN else ["root"],
                        resolved=bool(s["ips"]), ips=s["ips"], cname=s.get("cname"), hosting=s.get("hosting"),
                        asn={ip: {"asn": "64500", "org": f"DEMO-AS ({s.get('hosting') or 'on-prem'})", "cc": "US"} for ip in s["ips"]},
                        ports=ports, http=http, tls=tls, technologies=s.get("tech", []), risk_score=risk_from_findings(hf)))
    for f in findings:
        db.add(AsmFinding(scan_id=scan.id, **f))
        if f["severity"] in ("critical", "high"):
            raise_alert(db, module="asm", severity=f["severity"], title=f"{f['hostname']}: {f['title']}",
                        description=f"[demo] {f['remediation']}", ref_type="asm_scan", ref_id=scan.id,
                        dedup_key=f"asm:{DOMAIN}:{f['hostname']}:{f['check_id']}")
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    scan.risk_score = risk_from_findings(findings)
    scan.grade = grade_for(scan.risk_score)
    scan.summary = {"names_discovered": 31, "hosts_analysed": len(hosts), "hosts_resolved": sum(1 for s in hosts.values() if s["ips"]),
                    "unique_ips": len({ip for s in hosts.values() for ip in s["ips"]}), "web_services": 11,
                    "open_ports": sum(len(s.get("ports", [])) for s in hosts.values()), "findings": len(findings),
                    "by_severity": by_sev, "certificates": sum(1 for s in hosts.values() if "tls" in s),
                    "hosting": {"AWS": 4, "Cloudflare": 2, "Azure": 1, "Shopify": 1, "Other": 3},
                    "email_security": {"mx": [f"mail.{DOMAIN}"], "spf": "v=spf1 include:_spf.demo.invalid ~all",
                                       "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@acme-corp.example"},
                    "source_errors": {}, "active": True}
    scan.message = f"[demo] {len(hosts)} hosts, {len(findings)} findings, grade {scan.grade}"
    return len(findings)


def seed(reset: bool = False) -> dict:
    with session_scope() as db:
        existing = db.scalar(select(func.count(Asset.id)))
        if existing and not reset:
            return {"skipped": True, "reason": "database already contains assets - use --reset to wipe and reseed"}
    if reset:
        with session_scope() as db:
            for table in reversed(Base.metadata.sorted_tables):
                db.execute(delete(table))
    with session_scope() as db:
        assets = _assets(db)
        exp = _exposures(db, assets)
        iocs = _indicators(db)
        looks = _lookalikes(db)
        fnd = _asm(db)
        # spread alert creation over the last two weeks for the trend chart
        for al in db.scalars(select(Alert)):
            al.created_at = al.updated_at = _ago(R.uniform(0, 13))
            if R.random() < 0.25:
                al.status = R.choice(["acknowledged", "closed"])
            al.notified = True
    return {"assets": len(assets), "exposures": exp, "indicators": iocs, "lookalikes": looks, "asm_findings": fnd}
