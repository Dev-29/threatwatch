import { api } from "../api.js";
import { barList, legend, sevStrip, stackedColumns, stat } from "../charts.js";
import { SEVERITIES, ago, fmtNum, html, mount, sectionHead, sevBadge, truncate } from "../ui.js";

const MODULE_LINK = { darkweb: "#/darkweb", intel: "#/intel", phishing: "#/phishing", asm: "#/asm" };
const SOURCE_LABEL = { stealer_log: "Infostealer logs", ransomware_leak: "Ransomware leak sites", breach: "Breaches",
  combolist: "Combo lists", paste: "Paste sites", forum: "Forums / dark web", code_repo: "Code repositories" };

export async function render(main) {
  const d = await api("/dashboard");
  const days = Object.entries(d.alerts.trend).map(([day, values]) => {
    const dt = new Date(day + "T00:00:00");
    return { label: dt.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }),
             short: dt.toLocaleDateString(undefined, { month: "numeric", day: "numeric" }), values };
  });
  const crit = (d.alerts.open_by_severity.critical || 0) + (d.alerts.open_by_severity.high || 0);
  const latest = d.asm.latest[0];
  const empty = !Object.keys(d.watchlist).length;

  mount(main, html`
    ${sectionHead("Overview", "External threat exposure across dark web, threat intel, phishing and attack surface")}
    ${empty ? html`<div class="banner">Your watchlist is empty. <a href="#/watchlist">Add your domains, executives and brand keywords</a>
      to start monitoring - or run <code>threatwatch seed-demo</code> to explore with sample data.</div>` : ""}
    <div class="stats">
      ${stat("Open alerts", fmtNum(d.alerts.open_total), { sub: `${crit} critical / high`, tone: crit ? "critical" : "", link: "#/alerts" })}
      ${stat("Dark web exposures", fmtNum(d.darkweb.total), { sub: `${d.darkweb.new_7d} new this week · ${d.darkweb.credentials} with credentials`, link: "#/darkweb" })}
      ${stat("Active IOCs", fmtNum(d.intel.active), { sub: `${fmtNum(d.intel.new_24h)} new in 24h · ${d.intel.feeds_ok} feeds healthy`, link: "#/intel" })}
      ${stat("Look-alike domains", fmtNum(d.phishing.registered), { sub: `${d.phishing.high_risk} high risk · ${d.phishing.with_mx} can send mail`, link: "#/phishing" })}
      ${latest ? html`<a class="stat" href="#/asm/${latest.id}"><div class="stat-label">Attack surface · ${latest.root_domain}</div>
        <div style="display:flex;align-items:center;gap:12px;margin-top:6px"><span class="grade grade-${latest.grade}">${latest.grade}</span>
        <div><div class="stat-sub" style="margin:0">risk ${latest.risk_score}/100 · ${latest.hosts} hosts</div></div></div></a>`
        : stat("Attack surface", "-", { sub: "No scans yet", link: "#/asm" })}
    </div>

    <div class="grid g-21 align-start">
      <div class="card">
        <div class="card-head"><h2>Alerts per day (last 14 days)</h2><a class="small" href="#/alerts">All alerts →</a></div>
        ${stackedColumns(days, SEVERITIES)}
        ${legend(SEVERITIES)}
      </div>
      <div class="card">
        <div class="card-head"><h2>Latest alerts</h2></div>
        ${d.alerts.recent.length ? d.alerts.recent.slice(0, 6).map((a) => html`
          <div class="alert-row">${sevBadge(a.severity)}<div style="min-width:0">
            <div class="t"><a href="${MODULE_LINK[a.module] || "#/alerts"}">${truncate(a.title, 90)}</a></div>
            <div class="meta">${a.module} · ${ago(a.created_at)}</div></div></div>`) : html`<div class="empty small">No alerts yet</div>`}
      </div>
    </div>

    <div class="grid g-3" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Exposures by source</h2><a class="small" href="#/darkweb">Dark web →</a></div>
        ${barList(Object.entries(d.darkweb.by_source_type).sort((a, b) => b[1] - a[1])
          .map(([k, v]) => ({ label: SOURCE_LABEL[k] || k, value: v, link: `#/darkweb?source_type=${k}` })), { empty: "No exposures" })}
        <h3 style="margin-top:16px">Open by severity</h3>${sevStrip(d.darkweb.open_by_severity)}
      </div>
      <div class="card">
        <div class="card-head"><h2>Active IOCs by type</h2><a class="small" href="#/intel">Threat intel →</a></div>
        ${barList(Object.entries(d.intel.by_type).sort((a, b) => b[1] - a[1])
          .map(([k, v]) => ({ label: k, value: v, link: `#/intel?type=${k}` })), { empty: "Run feed collection to populate" })}
        <h3 style="margin-top:16px">By severity</h3>${sevStrip(d.intel.by_severity)}
      </div>
      <div class="card">
        <div class="card-head"><h2>Top ATT&CK techniques</h2><a class="small" href="#/attack">Matrix →</a></div>
        ${barList(d.intel.top_techniques.map((t) => ({ label: `${t.id} ${t.name}`, value: t.count,
          link: `#/intel?technique=${t.id}`, tip: `${t.id} ${t.name}\n${t.tactics.join(", ")}\n${t.count} indicators` })),
          { empty: "No mapped indicators yet" })}
      </div>
    </div>

    <div class="grid g-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Most active malware families</h2></div>
        ${barList(d.intel.top_malware.map(([k, v]) => ({ label: k, value: v, link: `#/intel?malware=${encodeURIComponent(k)}` })),
          { empty: "No malware attribution yet" })}
      </div>
      <div class="card">
        <div class="card-head"><h2>Attack surface</h2><a class="small" href="#/asm">ASM →</a></div>
        ${d.asm.latest.length ? d.asm.latest.map((s) => html`
          <div class="alert-row"><span class="grade grade-${s.grade}">${s.grade}</span><div style="flex:1;min-width:0">
            <div class="t"><a href="#/asm/${s.id}">${s.root_domain}</a> <span class="muted small">risk ${s.risk_score}/100 · ${s.hosts} hosts · ${ago(s.finished_at)}</span></div>
            ${sevStrip(s.by_severity)}</div></div>`) : html`<div class="empty small">No completed scans. <a href="#/asm">Start one →</a></div>`}
      </div>
    </div>`);
}
