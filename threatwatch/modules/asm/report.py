"""ASM risk report rendering: self-contained HTML (print-to-PDF friendly), Markdown and JSON."""

from __future__ import annotations

from html import escape

from ...models import AsmScan
from ..intel import attack

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#b42318", "high": "#d4580b", "medium": "#b8860b", "low": "#2563eb", "info": "#6b7280"}
GRADE_COLOR = {"A": "#15803d", "B": "#4d7c0f", "C": "#b8860b", "D": "#d4580b", "F": "#b42318"}


def scan_to_dict(scan: AsmScan) -> dict:
    findings = sorted(scan.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.hostname))
    return {
        "report": "threatwatch.asm.v1",
        "scan": {"id": scan.id, "root_domain": scan.root_domain, "active": scan.active, "status": scan.status,
                 "started_at": scan.started_at.isoformat() if scan.started_at else None,
                 "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                 "risk_score": scan.risk_score, "grade": scan.grade, "summary": scan.summary},
        "findings": [{"hostname": f.hostname, "category": f.category, "check_id": f.check_id, "severity": f.severity,
                      "title": f.title, "description": f.description, "evidence": f.evidence,
                      "remediation": f.remediation,
                      "attack": [attack.technique(t) for t in f.attack_techniques]} for f in findings],
        "assets": [{"hostname": a.hostname, "resolved": a.resolved, "ips": a.ips, "cname": a.cname,
                    "hosting": a.hosting, "asn": a.asn, "ports": a.ports, "technologies": a.technologies,
                    "http": a.http, "tls": a.tls, "sources": a.sources, "risk_score": a.risk_score}
                   for a in sorted(scan.assets, key=lambda a: (-a.risk_score, a.hostname))],
    }


def _sev(s: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOR.get(s, "#666")}">{escape(s.upper())}</span>'


def render_html(scan: AsmScan) -> str:
    d = scan_to_dict(scan)
    s = d["scan"]
    summ = s["summary"] or {}
    by_sev = summ.get("by_severity", {})
    grade = s["grade"] or "?"
    top = [f for f in d["findings"] if f["severity"] in ("critical", "high")][:8]

    def rows_findings():
        out = []
        for f in d["findings"]:
            techs = ", ".join(f'<a href="{t["url"]}">{t["id"]}</a>' for t in f["attack"])
            out.append(f"<tr><td>{_sev(f['severity'])}</td><td><code>{escape(f['hostname'])}</code></td>"
                       f"<td><b>{escape(f['title'])}</b><div class='muted'>{escape(f['description'] or '')}</div>"
                       f"{'<div class=ev>' + escape(f['evidence']) + '</div>' if f['evidence'] else ''}</td>"
                       f"<td>{escape(f['remediation'] or '')}</td><td>{techs}</td></tr>")
        return "\n".join(out) or "<tr><td colspan=5>No findings.</td></tr>"

    def rows_assets():
        out = []
        for a in d["assets"]:
            main = a["http"].get("https") or a["http"].get("http") or {}
            ports = ", ".join(str(p["port"]) for p in a["ports"]) or "-"
            web = f"{main.get('status', '')} {escape(main.get('title', '')[:60])}" if main else "-"
            tls = a["tls"] or {}
            cert = f"{escape(str(tls.get('issuer_cn', '')))} ({tls.get('days_left')}d)" if tls.get("not_after") else "-"
            out.append(f"<tr><td><code>{escape(a['hostname'])}</code>"
                       f"{'<div class=muted>CNAME ' + escape(a['cname']) + '</div>' if a['cname'] else ''}</td>"
                       f"<td>{escape(', '.join(a['ips'][:3])) or '<span class=muted>unresolved</span>'}</td>"
                       f"<td>{escape(a['hosting'] or '-')}</td><td>{ports}</td><td>{web}</td><td>{cert}</td>"
                       f"<td>{escape(', '.join(a['technologies'][:5]))}</td><td>{a['risk_score']}</td></tr>")
        return "\n".join(out)

    email = summ.get("email_security", {})
    sev_cards = "".join(
        f'<div class="card"><div class="n" style="color:{SEV_COLOR[k]}">{by_sev.get(k, 0)}</div><div>{k.title()}</div></div>'
        for k in ("critical", "high", "medium", "low", "info"))
    stat_cards = "".join(f'<div class="card"><div class="n">{v}</div><div>{k}</div></div>' for k, v in [
        ("Names discovered", summ.get("names_discovered", 0)), ("Hosts resolved", summ.get("hosts_resolved", 0)),
        ("Unique IPs", summ.get("unique_ips", 0)), ("Web services", summ.get("web_services", 0)),
        ("TLS certificates", summ.get("certificates", 0)), ("Open ports", summ.get("open_ports", 0))])
    top_html = "".join(f"<li>{_sev(f['severity'])} <code>{escape(f['hostname'])}</code> - {escape(f['title'])}</li>"
                       for f in top) or "<li>No critical or high severity findings.</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASM Risk Report - {escape(s['root_domain'])}</title>
<style>
:root{{--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#fff;--soft:#f9fafb}}
body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:32px;max-width:1200px;margin:auto}}
h1{{margin:0 0 4px;font-size:26px}} h2{{margin-top:36px;border-bottom:2px solid var(--line);padding-bottom:6px;font-size:18px}}
.muted{{color:var(--muted);font-size:12px}} code{{font-size:12px;background:var(--soft);padding:1px 4px;border-radius:4px}}
.head{{display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap}}
.grade{{font-size:56px;font-weight:800;color:#fff;background:{GRADE_COLOR.get(grade, '#666')};border-radius:16px;width:96px;height:96px;display:flex;align-items:center;justify-content:center}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:12px 0}}
.card{{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--soft)}} .card .n{{font-size:24px;font-weight:700}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{background:var(--soft);font-weight:600}} .sev{{color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:700}}
.ev{{font-family:ui-monospace,monospace;font-size:11px;color:#374151;margin-top:3px;word-break:break-all}}
ul{{padding-left:18px}} li{{margin:4px 0}} a{{color:#2563eb}}
@media print{{body{{padding:0}} h2{{break-after:avoid}} tr{{break-inside:avoid}}}}
</style></head><body>
<div class="head"><div><div class="muted">ThreatWatch - Attack Surface Management</div>
<h1>External Risk Report: {escape(s['root_domain'])}</h1>
<div class="muted">Scan #{s['id']} - {escape(str(s['finished_at'] or s['started_at']))} UTC - mode: {'active (ports, paths, AXFR)' if s['active'] else 'passive / non-intrusive'}</div></div>
<div style="text-align:center"><div class="grade">{grade}</div><div class="muted">risk score {s['risk_score']}/100</div></div></div>

<h2>Executive summary</h2>
<div class="cards">{sev_cards}</div><div class="cards">{stat_cards}</div>
<p><b>Top risks</b></p><ul>{top_html}</ul>

<h2>Findings ({len(d['findings'])})</h2>
<table><thead><tr><th>Severity</th><th>Host</th><th>Finding</th><th>Remediation</th><th>ATT&amp;CK</th></tr></thead>
<tbody>{rows_findings()}</tbody></table>

<h2>Email &amp; DNS posture</h2>
<table><tbody>
<tr><th>MX</th><td>{escape(', '.join(email.get('mx') or []) or 'none')}</td></tr>
<tr><th>SPF</th><td><code>{escape(email.get('spf') or 'missing')}</code></td></tr>
<tr><th>DMARC</th><td><code>{escape(email.get('dmarc') or 'missing')}</code></td></tr>
<tr><th>Hosting</th><td>{escape(', '.join(f'{k}: {v}' for k, v in (summ.get('hosting') or {}).items()))}</td></tr>
</tbody></table>

<h2>Asset inventory ({len(d['assets'])})</h2>
<table><thead><tr><th>Hostname</th><th>IPs</th><th>Hosting</th><th>Open ports</th><th>Web</th><th>Certificate</th><th>Technologies</th><th>Risk</th></tr></thead>
<tbody>{rows_assets()}</tbody></table>

<h2>Methodology</h2>
<p class="muted">Assets were discovered from Certificate Transparency logs (crt.sh, CertSpotter), passive DNS (HackerTarget{', OTX' if 'otx' not in (summ.get('source_errors') or {}) else ''}),
web archives (Wayback Machine) and DNS brute force, then resolved and enriched with ASN data (Team Cymru). Each web service was
fingerprinted and its TLS certificate analysed. {'Active checks (TCP connect scan of common service ports, confirmation of sensitive file exposure, DNS zone transfer attempts) were performed.' if s['active'] else 'No active scanning was performed.'}
Risk score = 100 x (1 - e^(-points/50)) where critical=25, high=10, medium=4, low=1 points, bounded by the worst severity present (critical 65-100, high 25-64, medium 10-44, low 0-24); grades A&lt;10, B&lt;25, C&lt;45, D&lt;65, F&gt;=65.
Findings are mapped to MITRE ATT&amp;CK techniques an adversary could use against the exposure.</p>
</body></html>"""


def render_markdown(scan: AsmScan) -> str:
    d = scan_to_dict(scan)
    s, summ = d["scan"], d["scan"]["summary"] or {}
    lines = [f"# External Risk Report: {s['root_domain']}", "",
             f"*Scan #{s['id']} - {s['finished_at'] or s['started_at']} UTC - {'active' if s['active'] else 'passive'} mode*", "",
             f"**Grade {s['grade']}** - risk score **{s['risk_score']}/100**", "",
             "| Metric | Value |", "|---|---|"]
    for k in ("names_discovered", "hosts_resolved", "unique_ips", "web_services", "certificates", "open_ports", "findings"):
        lines.append(f"| {k.replace('_', ' ').title()} | {summ.get(k, 0)} |")
    lines += ["", "## Findings", "", "| Severity | Host | Finding | Remediation |", "|---|---|---|---|"]
    for f in d["findings"]:
        lines.append(f"| {f['severity'].upper()} | `{f['hostname']}` | {f['title']} | {f['remediation'] or ''} |")
    lines += ["", "## Assets", "", "| Host | IPs | Hosting | Ports | Technologies |", "|---|---|---|---|---|"]
    for a in d["assets"]:
        lines.append(f"| `{a['hostname']}` | {', '.join(a['ips'][:3])} | {a['hosting'] or ''} | "
                     f"{', '.join(str(p['port']) for p in a['ports'])} | {', '.join(a['technologies'][:5])} |")
    return "\n".join(lines) + "\n"
