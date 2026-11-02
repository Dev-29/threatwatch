import { api } from "../api.js";
import { jobStarted, setParams } from "../app.js";
import { $, ago, chip, debounce, factors, fmtDate, html, kv, mount, openDrawer, pager, scoreBar, sectionHead, select,
  sevBadge, table, toast, truncate } from "../ui.js";

const STATUSES = ["new", "monitoring", "takedown_requested", "taken_down", "benign"];

export async function render(main, { params, signal }) {
  const tab = params.tab || "lookalikes";
  mount(main, html`
    ${sectionHead("Anti-Phishing", "Look-alike domain detection, certificate-transparency monitoring and URL analysis",
      html`<button class="btn btn-primary" id="scan">Scan look-alikes now</button>`)}
    <div class="tabs" role="tablist">${[["lookalikes", "Look-alike domains"], ["analyze", "URL analyzer"], ["generate", "Permutation preview"]]
      .map(([k, l]) => html`<button role="tab" data-tab="${k}" class="${tab === k ? "active" : ""}">${l}</button>`)}</div>
    <div id="tab"></div>`);
  main.querySelector(".tabs").addEventListener("click", (e) => { if (e.target.dataset.tab) location.hash = `#/phishing?tab=${e.target.dataset.tab}`; });
  $("#scan").addEventListener("click", async () => {
    try {
      await api("/phishing/scan", { method: "POST", body: {} });
      jobStarted("phishing_scan", "all");
      toast("Look-alike scan started (DNS + web + RDAP checks take a few minutes)", "ok");
    } catch (err) { toast(err.message, "error"); }
  });
  const el = $("#tab");
  if (tab === "analyze") return renderAnalyzer(el, params);
  if (tab === "generate") return renderGenerate(el, params);
  return renderLookalikes(el, params, signal);
}

async function renderLookalikes(el, params, signal) {
  const state = { severity: params.severity || "", status: params.status || "", technique: params.technique || "",
    has_mx: params.has_mx || "", q: params.q || "", offset: Number(params.offset || 0), limit: 50 };
  mount(el, html`<div class="toolbar" id="filters">
      <input type="search" name="q" placeholder="Search domain…" value="${state.q}">
      ${select("severity", [["", "Any"], ["critical", "Critical"], ["high", "High"], ["critical,high", "Critical + high"], ["medium", "Medium"], ["low", "Low"]], state.severity, "Severity")}
      ${select("has_mx", [["", "Any"], ["true", "Has MX (can email)"], ["false", "No MX"]], state.has_mx, "Mail")}
      ${select("status", [["", "Any"], ...STATUSES.map((s) => [s, s.replace("_", " ")])], state.status, "Status")}
    </div><div id="rows"></div>`);
  let rows = [];
  async function load() {
    setParams({ ...state, limit: undefined, offset: state.offset || undefined });
    const res = await api("/phishing/lookalikes", { params: state });
    rows = res.items;
    mount($("#rows"), html`${table([
      { label: "Risk", render: (l) => scoreBar(l.risk_score, l.severity), cls: "nowrap" },
      { label: "Severity", render: (l) => sevBadge(l.severity) },
      { label: "Domain", render: (l) => html`<div class="cell-title mono">${l.domain_unicode || l.domain}</div>
          <div class="cell-sub">imitates ${l.brand_domain} · ${l.technique}${l.domain_unicode && l.domain_unicode !== l.domain ? ` · ${l.domain}` : ""}</div>` },
      { label: "Signals", render: (l) => html`<div class="chips">
          ${l.dns_mx.length ? chip("MX", "chip-bad") : ""}${l.http_status ? chip(`web ${l.http_status}`) : ""}
          ${l.has_login_form ? chip("login form", "chip-bad") : ""}${l.similarity >= 0.3 ? chip(`${Math.round(l.similarity * 100)}% similar`, "chip-bad") : ""}
          ${l.in_threat_feed ? chip("in TI feed", "chip-bad") : ""}${l.parked ? chip("parked") : ""}</div>` },
      { label: "Registered", render: (l) => l.created_date ? html`${fmtDate(l.created_date)}<div class="cell-sub">${ago(l.created_date)}</div>` : "-", cls: "nowrap" },
      { label: "Page title", render: (l) => html`<span class="small">${truncate(l.title, 50)}</span>` },
      { label: "Status", render: (l) => chip(l.status.replace("_", " ")) },
    ], rows, { empty: "No registered look-alikes found yet. Add a domain to the watchlist and run a scan.", rowAttr: () => 'class="clickable"' })}
    ${pager(res.total, state.limit, state.offset)}`);
  }
  el.addEventListener("change", (e) => {
    if (e.target.closest("#filters") && e.target.name) { state[e.target.name] = e.target.value; state.offset = 0; load(); }
  });
  $("input[name=q]", el).addEventListener("input", debounce((e) => { state.q = e.target.value; state.offset = 0; load(); }));
  el.addEventListener("click", (e) => {
    const p = e.target.closest("[data-page]");
    if (p) { state.offset = Number(p.dataset.page); return load(); }
    const tr = e.target.closest("tr[data-i]");
    if (tr && !e.target.closest("a")) openLookalike(rows[tr.dataset.i], load);
  });
  window.addEventListener("tw:job-done", load, { signal });
  await load();
}

function openLookalike(l, reload) {
  const body = openDrawer(html`<span class="mono">${l.domain_unicode || l.domain}</span>`, html`
    <section style="display:flex;gap:12px;align-items:center">${sevBadge(l.severity)} ${scoreBar(l.risk_score, l.severity)}
      <label class="field-inline" style="margin-left:auto"><span>Status</span><select id="lk-status">
      ${STATUSES.map((s) => html`<option value="${s}" ${s === l.status ? "selected" : ""}>${s.replace("_", " ")}</option>`)}</select></label></section>
    <section>${kv([
      ["Imitates", l.brand_domain], ["Technique", l.technique], ["Punycode", l.domain !== l.domain_unicode ? l.domain : null],
      ["A records", l.dns_a.join(", ") || "none"], ["MX records", l.dns_mx.join(", ") || "none"], ["Name servers", l.dns_ns.join(", ")],
      ["Registered", l.created_date ? `${fmtDate(l.created_date)} (${ago(l.created_date)})` : "unknown"], ["Registrar", l.registrar],
      ["Website", l.http_status ? html`${l.http_status} - ${l.title || "no title"}` : "not reachable"],
      ["Final URL", l.final_url ? html`<span class="mono small wrap-any">${l.final_url}</span>` : null],
      ["Content similarity", `${Math.round(l.similarity * 100)}%`], ["Login form", l.has_login_form ? "yes" : "no"],
      ["Parked", l.parked ? "yes" : "no"], ["In threat feed", l.in_threat_feed ? "yes" : "no"],
      ["First seen", fmtDate(l.first_seen, true)], ["Last checked", ago(l.last_checked)],
    ])}</section>
    <section><h3>Why this score</h3>${factors(l.score_factors)}</section>
    <section><h3>Recommended response</h3><ul class="small" style="padding-left:18px;margin:0">
      ${l.dns_mx.length ? html`<li>Block the domain at the mail gateway; it can send email impersonating you.</li>` : ""}
      ${l.has_login_form || l.similarity >= 0.5 ? html`<li>Request a takedown from the registrar / host (evidence: screenshots, headers).</li>` : ""}
      <li>Add to web proxy / DNS blocklists; monitor for changes (parked domains are often weaponised later).</li>
      <li>Consider defensive registration of high-risk permutations.</li></ul></section>
    <p class="muted small">Do not visit suspicious sites from a corporate workstation; use an isolated analysis environment.</p>`);
  $("#lk-status", body).addEventListener("change", async (e) => {
    await api(`/phishing/lookalikes/${l.id}`, { method: "PATCH", body: { status: e.target.value } });
    toast("Status updated", "ok");
    reload();
  });
}

function renderAnalyzer(el, params) {
  mount(el, html`<div class="card"><form id="az" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input name="url" required placeholder="https://suspicious.example/login" style="flex:1;min-width:260px" value="${params.url || ""}">
      <label class="checkline" style="margin:0"><input type="checkbox" name="fetch" checked> Fetch page (sandboxed server-side request)</label>
      <button class="btn btn-primary">Analyze</button></form></div>
    <div id="az-res" style="margin-top:16px"></div>`);
  $("#az").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    mount($("#az-res"), html`<div class="loading"><span class="spin"></span>Analyzing…</div>`);
    try {
      const r = await api("/phishing/analyze", { method: "POST", body: { url: fd.get("url"), fetch: fd.get("fetch") === "on" } });
      mount($("#az-res"), html`
        <div class="verdict v-${r.verdict}"><div class="big">${r.score}</div><div><div style="font-size:18px;font-weight:700;text-transform:capitalize">${r.verdict.replace("-", " ")}</div>
          <div class="muted small mono wrap-any">${r.host_unicode}${r.host_unicode !== r.host ? ` (${r.host})` : ""}</div></div>
          <div style="margin-left:auto">${sevBadge(r.severity)}</div></div>
        <div class="grid g-2"><div class="card"><h3>Signals</h3>${r.signals.length ? html`<ul class="factors">${r.signals.map((s) => html`
          <li><span>${s.signal}${s.detail ? html`<div class="cell-sub wrap-any">${s.detail}</div>` : ""}</span><b class="${s.weight >= 0 ? "pos" : "neg"}">${s.weight >= 0 ? "+" : ""}${s.weight}</b></li>`)}</ul>`
          : html`<div class="muted">No phishing indicators detected.</div>`}</div>
        <div class="card"><h3>Page & registration</h3>${r.page ? kv([
          ["HTTP status", r.page.status || r.page.error], ["Title", r.page.title], ["Final URL", r.page.final_url ? html`<span class="small wrap-any">${r.page.final_url}</span>` : null],
          ["Password form", r.page.has_password_form ? "yes" : "no"], ["Form posts to", r.page.form_action_hosts.join(", ")],
          ["Parked", r.page.parked ? "yes" : "no"], ["Registered", r.registration.created], ["Registrar", r.registration.registrar],
        ]) : html`<div class="muted">Page not fetched.</div>`}
        ${r.intel_matches.length ? html`<h3 style="margin-top:12px">Threat-intel matches</h3>${r.intel_matches.map((m) => html`<div class="small">${m.value} - ${m.sources.join(", ")} (score ${m.score})</div>`)}` : ""}
        </div></div>`);
    } catch (err) { mount($("#az-res"), html`<div class="empty">${err.message}</div>`); }
    btn.disabled = false;
  });
  if (params.url) $("#az").requestSubmit();
}

function renderGenerate(el, params) {
  mount(el, html`<div class="card"><form id="gen" style="display:flex;gap:10px;flex-wrap:wrap">
    <input name="domain" required placeholder="example.com" value="${params.domain || ""}" style="flex:1;min-width:220px">
    <button class="btn btn-primary">Generate</button></form>
    <p class="muted small">Offline preview of the permutations the scanner checks (no DNS queries). Useful for defensive registration or blocklists.</p></div>
    <div id="gen-res" style="margin-top:16px"></div>`);
  $("#gen").addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = new FormData(e.target).get("domain");
    try {
      const r = await api("/phishing/permutations", { params: { domain, limit: 5000 } });
      mount($("#gen-res"), html`<div class="card"><div class="card-head"><h2>${r.count} candidates for ${r.domain}</h2></div>
        <div class="chips" style="margin-bottom:12px">${Object.entries(r.by_technique).map(([k, v]) => chip(`${k}: ${v}`))}</div>
        <div class="pre" style="max-height:480px">${r.candidates.map((c) => `${c.unicode.padEnd(40)} ${c.technique}`).join("\n")}</div></div>`);
    } catch (err) { toast(err.message, "error"); }
  });
}
