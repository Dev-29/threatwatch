import { api, href } from "../api.js";
import { jobStarted } from "../app.js";
import { barList, sevStrip, stat } from "../charts.js";
import { $, ago, attackLink, chip, closeModal, fmtDate, html, kv, mount, openDrawer, openModal, sectionHead, sevBadge,
  table, toast, truncate } from "../ui.js";

export async function render(main, { args, signal }) {
  if (args[0]) return renderScan(main, Number(args[0]), signal);
  return renderList(main, signal);
}

async function renderList(main, signal) {
  mount(main, html`${sectionHead("Attack Surface Management", "Discover sub-domains, exposed services and certificates; produce a risk report",
    html`<button class="btn btn-primary" id="new">New scan</button>`)}<div id="list"></div>`);
  async function load() {
    const scans = await api("/asm/scans");
    mount($("#list", main), table([
      { label: "Grade", render: (s) => s.grade ? html`<span class="grade grade-${s.grade}">${s.grade}</span>` : html`<span class="spin"></span>` },
      { label: "Root domain", render: (s) => html`<div class="cell-title"><a href="#/asm/${s.id}">${s.root_domain}</a></div><div class="cell-sub">${s.message || ""}</div>` },
      { label: "Mode", render: (s) => chip(s.active ? "active" : "passive") },
      { label: "Status", render: (s) => html`<span class="status-dot ${s.status === "done" ? "ok" : s.status === "failed" ? "error" : "running"}"></span>${s.status}` },
      { label: "Findings", render: (s) => s.summary?.by_severity ? html`<div style="min-width:160px">${sevStrip(s.summary.by_severity)}</div>` : "-" },
      { label: "Hosts", render: (s) => s.summary?.hosts_resolved ?? "-", cls: "num" },
      { label: "Started", render: (s) => ago(s.started_at), cls: "nowrap" },
    ], scans, { empty: "No scans yet. Start with your primary domain." }));
    if (scans.some((s) => s.status === "running" || s.status === "queued")) setTimeout(() => { if (main.isConnected) load(); }, 5000);
  }
  $("#new", main).addEventListener("click", () => newScanModal());
  window.addEventListener("tw:job-done", load, { signal });
  await load();
}

async function newScanModal() {
  const assets = await api("/assets", { params: { type: "domain" } }).catch(() => []);
  const body = openModal("New attack surface scan", html`<form id="scan-form">
    <label class="field"><span>Root domain</span><input name="root_domain" required placeholder="example.com" list="dom-list" value="${assets[0]?.value || ""}">
      <datalist id="dom-list">${assets.map((a) => html`<option value="${a.value}">`)}</datalist></label>
    <p class="small"><b>Passive mode</b> (default): CT logs, passive DNS, archives, DNS resolution, TLS certificate and homepage
      fingerprinting - indistinguishable from normal visitors.</p>
    <label class="checkline"><input type="checkbox" name="active"> <span><b>Active mode</b>: TCP port scan of ~60 service ports,
      confirmation of exposed sensitive files (/.git, /.env…), DNS zone-transfer attempts.</span></label>
    <label class="checkline" id="auth-line" hidden><input type="checkbox" name="authorized"> <span>I confirm I own these assets or have
      written authorisation to test them.</span></label>
    <div class="modal-foot"><button type="button" class="btn" id="cancel">Cancel</button><button class="btn btn-primary">Start scan</button></div></form>`);
  const f = $("#scan-form", body);
  f.active.addEventListener("change", () => { $("#auth-line").hidden = !f.active.checked; });
  $("#cancel").addEventListener("click", closeModal);
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (f.active.checked && !f.authorized.checked) { toast("Confirm authorisation to run an active scan", "error"); return; }
    try {
      const r = await api("/asm/scans", { method: "POST", body: { root_domain: f.root_domain.value, active: f.active.checked, authorized: f.authorized.checked } });
      closeModal();
      jobStarted("asm_scan", String(r.scan_id));
      toast(`Scan of ${r.root_domain} started`, "ok");
      location.hash = `#/asm/${r.scan_id}`;
    } catch (err) { toast(err.message, "error"); }
  });
}

async function renderScan(main, id, signal) {
  const s = await api(`/asm/scans/${id}`);
  if (s.status !== "done") {
    mount(main, html`${sectionHead(s.root_domain, `Scan #${s.id} · ${s.active ? "active" : "passive"} mode`)}
      <div class="card">${s.status === "failed" ? html`<div class="empty">Scan failed: ${s.message}</div>`
        : html`<div class="loading"><span class="spin"></span>Scan ${s.status}… discovery, resolution and probing can take several minutes.
          This page refreshes automatically.</div>`}</div>`);
    if (s.status !== "failed") {
      const t = setInterval(async () => {
        if (!main.isConnected) return clearInterval(t);
        const cur = await api(`/asm/scans/${id}`);
        if (cur.status !== s.status && main.isConnected) { clearInterval(t); renderScan(main, id, signal); }
      }, 4000);
    }
    return;
  }
  const [findings, assets] = await Promise.all([api(`/asm/scans/${id}/findings`), api(`/asm/scans/${id}/assets`)]);
  const sum = s.summary || {};
  const certs = assets.filter((a) => a.tls && a.tls.not_after);
  mount(main, html`
    <div class="page-head"><div style="display:flex;gap:16px;align-items:center">
      <span class="grade big grade-${s.grade}">${s.grade}</span>
      <div><div class="muted small"><a href="#/asm">Attack surface</a> / scan #${s.id}</div><h1>${s.root_domain}</h1>
      <p class="muted">Risk ${s.risk_score}/100 · ${s.active ? "active" : "passive"} scan · ${fmtDate(s.finished_at, true)}</p></div></div>
      <div class="actions">
        <a class="btn btn-primary" href="${href(`/asm/scans/${id}/report`, { format: "html" })}" target="_blank" rel="noopener">Open risk report</a>
        <a class="btn" href="${href(`/asm/scans/${id}/report`, { format: "md", download: true })}">Markdown</a>
        <a class="btn" href="${href(`/asm/scans/${id}/report`, { format: "json", download: true })}">JSON</a>
        <button class="btn" id="rescan">Re-scan</button></div></div>
    <div class="stats">
      ${stat("Names discovered", sum.names_discovered ?? 0, { sub: `${sum.hosts_analysed ?? 0} analysed` })}
      ${stat("Live hosts", sum.hosts_resolved ?? 0, { sub: `${sum.unique_ips ?? 0} unique IPs` })}
      ${stat("Web services", sum.web_services ?? 0, { sub: `${sum.certificates ?? 0} TLS certificates` })}
      ${stat("Open ports", sum.open_ports ?? 0, { sub: s.active ? "TCP connect scan" : "passive scan - not probed" })}
      ${stat("Findings", findings.length, { sub: `${(sum.by_severity?.critical || 0) + (sum.by_severity?.high || 0)} critical / high`,
        tone: (sum.by_severity?.critical || 0) ? "critical" : "" })}
    </div>
    <div class="grid g-21" style="margin-bottom:16px">
      <div class="card"><div class="card-head"><h2>Findings by severity</h2></div>${sevStrip(sum.by_severity || {})}
        <h3 style="margin-top:16px">By category</h3>
        ${barList(Object.entries(findings.reduce((acc, f) => ((acc[f.category] = (acc[f.category] || 0) + 1), acc), {}))
          .sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })))}</div>
      <div class="card"><div class="card-head"><h2>Hosting</h2></div>
        ${barList(Object.entries(sum.hosting || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })))}
        <h3 style="margin-top:16px">Email security</h3>${kv([
          ["SPF", sum.email_security?.spf ? html`<code class="small">${truncate(sum.email_security.spf, 60)}</code>` : html`<b class="tone-critical">missing</b>`],
          ["DMARC", sum.email_security?.dmarc ? html`<code class="small">${truncate(sum.email_security.dmarc, 60)}</code>` : html`<b class="tone-critical">missing</b>`],
          ["MX", (sum.email_security?.mx || []).join(", ") || "none"]])}
        ${Object.keys(sum.source_errors || {}).length ? html`<p class="muted small">Unavailable sources: ${Object.keys(sum.source_errors).join(", ")}</p>` : ""}</div>
    </div>
    <div class="tabs" role="tablist">${[["findings", `Findings (${findings.length})`], ["assets", `Assets (${assets.length})`], ["certs", `Certificates (${certs.length})`]]
      .map(([k, l], i) => html`<button role="tab" data-tab="${k}" class="${i === 0 ? "active" : ""}">${l}</button>`)}</div>
    <div id="tab"></div>`);

  const tabs = {
    findings: () => table([
      { label: "Severity", render: (f) => sevBadge(f.severity) },
      { label: "Finding", render: (f) => html`<div class="cell-title">${f.title}</div><div class="cell-sub">${f.description}</div>
          ${f.evidence ? html`<div class="cell-sub mono wrap-any">${truncate(f.evidence, 160)}</div>` : ""}` },
      { label: "Host", render: (f) => html`<span class="mono small">${f.hostname}</span>` },
      { label: "Category", render: (f) => chip(f.category) },
      { label: "Remediation", render: (f) => html`<span class="small">${f.remediation}</span>` },
      { label: "ATT&CK", render: (f) => html`<div class="chips">${f.attack_techniques.map(attackLink)}</div>` },
    ], findings, { empty: "No findings - nice." }),
    assets: () => table([
      { label: "Risk", render: (a) => html`<b>${a.risk_score}</b>`, cls: "num" },
      { label: "Hostname", render: (a) => html`<div class="mono small cell-title">${a.hostname}</div>
          <div class="cell-sub">${a.cname ? `CNAME ${a.cname} · ` : ""}${a.sources.join(", ")}</div>` },
      { label: "IPs", render: (a) => a.resolved ? html`<span class="mono small">${a.ips.slice(0, 2).join(", ")}${a.ips.length > 2 ? ` +${a.ips.length - 2}` : ""}</span>` : html`<span class="muted">unresolved</span>` },
      { label: "Hosting", render: (a) => a.hosting || html`<span class="muted small">${truncate(Object.values(a.asn)[0]?.org || "-", 24)}</span>` },
      { label: "Ports", render: (a) => html`<div class="chips">${a.ports.map((p) => chip(`${p.port}/${p.service}`))}</div>` },
      { label: "Web", render: (a) => { const w = a.http.https || a.http.http; return w ? html`<div class="small">${w.status} ${truncate(w.title, 40)}</div>` : "-"; } },
      { label: "Tech", render: (a) => html`<div class="chips">${a.technologies.slice(0, 4).map((t) => chip(t))}</div>` },
    ], assets, { rowAttr: () => 'class="clickable"' }),
    certs: () => table([
      { label: "Host", render: (a) => html`<span class="mono small">${a.hostname}</span>` },
      { label: "Subject", render: (a) => a.tls.subject_cn },
      { label: "Issuer", render: (a) => a.tls.issuer_cn },
      { label: "Expires", render: (a) => html`${fmtDate(a.tls.not_after)} <span class="${a.tls.days_left < 14 ? "tone-critical" : "muted"} small">(${a.tls.days_left}d)</span>`, cls: "nowrap" },
      { label: "Protocol", render: (a) => html`${a.tls.protocol || "-"}${a.tls.legacy_protocols?.length ? html` ${chip("legacy: " + a.tls.legacy_protocols.join(", "), "chip-bad")}` : ""}` },
      { label: "Key", render: (a) => `${a.tls.key_type} ${a.tls.key_bits || ""}` },
      { label: "Trust", render: (a) => a.tls.self_signed ? chip("self-signed", "chip-bad") : a.tls.trusted === false ? chip("untrusted", "chip-bad")
          : a.tls.hostname_match === false ? chip("name mismatch", "chip-bad") : chip("valid", "chip-ok") },
    ], certs.sort((a, b) => a.tls.days_left - b.tls.days_left), { empty: "No TLS certificates collected." }),
  };
  let current = "findings";
  const draw = () => mount($("#tab", main), tabs[current]());
  main.querySelector(".tabs").addEventListener("click", (e) => {
    const t = e.target.dataset.tab;
    if (!t) return;
    current = t;
    main.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
    draw();
  });
  $("#tab", main).addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-i]");
    if (tr && current === "assets") openAsset(assets[tr.dataset.i], findings);
  });
  $("#rescan", main).addEventListener("click", async () => {
    if (s.active && !confirm("Re-run an ACTIVE scan? Only proceed if you are authorised to test these assets.")) return;
    const r = await api("/asm/scans", { method: "POST", body: { root_domain: s.root_domain, active: s.active, authorized: s.active } });
    jobStarted("asm_scan", String(r.scan_id));
    location.hash = `#/asm/${r.scan_id}`;
  });
  draw();
}

function openAsset(a, findings) {
  const mine = findings.filter((f) => f.hostname === a.hostname);
  const w = a.http.https || a.http.http || {};
  openDrawer(html`<span class="mono">${a.hostname}</span>`, html`
    <section>${kv([
      ["Resolved", a.resolved ? "yes" : "no"], ["IPs", a.ips.join(", ")], ["CNAME", a.cname],
      ["ASN", Object.entries(a.asn).map(([ip, x]) => `${ip}: AS${x.asn} ${x.org || ""} (${x.cc || "?"})`).join("; ")],
      ["Hosting", a.hosting], ["Discovered via", a.sources.join(", ")],
      ["Open ports", a.ports.map((p) => `${p.port}/${p.service}${p.banner ? ` "${truncate(p.banner, 40)}"` : ""}`).join(", ")],
      ["Web", w.url ? html`<a href="${w.url}" target="_blank" rel="noopener noreferrer">${w.url}</a> → ${w.status} ${w.title}` : null],
      ["Server", [w.server, w.powered_by].filter(Boolean).join(" · ")],
      ["Technologies", a.technologies.join(", ")],
      ["Security headers", w.security_headers ? html`<div class="chips">${Object.entries(w.security_headers).map(([k, v]) => chip(k, v ? "chip-ok" : "chip-bad"))}</div>` : null],
      ["Certificate", a.tls.not_after ? `${a.tls.subject_cn} by ${a.tls.issuer_cn}, expires ${fmtDate(a.tls.not_after)} (${a.tls.days_left}d)` : a.tls.error],
      ["SANs", (a.tls.sans || []).slice(0, 12).join(", ")],
    ])}</section>
    <section><h3>Findings (${mine.length})</h3>${mine.length ? mine.map((f) => html`<div class="alert-row">${sevBadge(f.severity)}<div>
      <div class="t">${f.title}</div><div class="meta">${f.remediation}</div></div></div>`) : html`<div class="muted">None.</div>`}</section>`);
}
