import { api } from "../api.js";
import { jobStarted, setParams } from "../app.js";
import { $, ago, chip, debounce, factors, fmtDate, fmtNum, html, kv, mount, openDrawer, pager, scoreBar, sectionHead,
  select, sevBadge, table, toast, truncate } from "../ui.js";

const SOURCE_TYPES = [["", "All sources"], ["stealer_log", "Infostealer logs"], ["ransomware_leak", "Ransomware leak sites"],
  ["breach", "Breaches"], ["combolist", "Combo lists"], ["paste", "Paste sites"], ["forum", "Forums / dark web"],
  ["code_repo", "Code repositories"]];
const ST_LABEL = Object.fromEntries(SOURCE_TYPES);
const STATUSES = ["new", "investigating", "remediated", "false_positive"];

export async function render(main, { params, signal }) {
  const tab = params.tab || "exposures";
  mount(main, html`
    ${sectionHead("Dark Web Monitoring", "Leaked credentials, infostealer infections, ransomware listings and mentions of your assets",
      html`<button class="btn btn-primary" id="scan">Run scan now</button>`)}
    <div class="tabs" role="tablist">
      ${[["exposures", "Exposures"], ["sources", "Sources"], ["import", "Import leak file"]].map(([k, l]) =>
        html`<button role="tab" data-tab="${k}" class="${tab === k ? "active" : ""}">${l}</button>`)}
    </div>
    <div id="tab"></div>`);

  $("#scan").addEventListener("click", async () => {
    try {
      await api("/darkweb/scan", { method: "POST", body: {} });
      jobStarted("darkweb_scan", "all");
      toast("Dark web scan started - results appear as sources respond", "ok");
    } catch (err) { toast(err.message, "error"); }
  });
  main.querySelector(".tabs").addEventListener("click", (e) => {
    const t = e.target.dataset.tab;
    if (t) location.hash = `#/darkweb?tab=${t}`;
  });
  if (tab === "sources") return renderSources($("#tab"));
  if (tab === "import") return renderImport($("#tab"));
  return renderExposures($("#tab"), params, signal);
}

async function renderExposures(el, params, signal) {
  const state = { severity: params.severity || "", status: params.status || "", source_type: params.source_type || "",
    asset_id: params.asset_id || "", q: params.q || "", sort: params.sort || "risk", offset: Number(params.offset || 0), limit: 50 };
  mount(el, html`<div class="toolbar" id="filters">
      <input type="search" name="q" placeholder="Search title or identifier…" value="${state.q}">
      ${select("severity", [["", "Any"], ["critical", "Critical"], ["high", "High"], ["critical,high", "Critical + high"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]], state.severity, "Severity")}
      ${select("source_type", SOURCE_TYPES, state.source_type, "Source")}
      ${select("status", [["", "Any"], ...STATUSES.map((s) => [s, s.replace("_", " ")])], state.status, "Status")}
      ${select("sort", [["risk", "Highest risk"], ["recent", "Newest"], ["leaked", "Leak date"]], state.sort, "Sort")}
      ${state.asset_id ? html`<span class="chip">asset #${state.asset_id} <a href="#/darkweb">✕</a></span>` : ""}
    </div><div id="rows"></div>`);
  let rows = [];
  async function load() {
    setParams({ ...state, limit: undefined, offset: state.offset || undefined, sort: state.sort === "risk" ? undefined : state.sort });
    const res = await api("/darkweb/exposures", { params: state });
    rows = res.items;
    mount($("#rows"), html`${table([
      { label: "Risk", render: (e) => scoreBar(e.risk_score, e.severity), cls: "nowrap" },
      { label: "Severity", render: (e) => sevBadge(e.severity) },
      { label: "Exposure", render: (e) => html`<div class="cell-title">${truncate(e.title, 110)}</div>
          <div class="cell-sub">${ST_LABEL[e.source_type] || e.source_type} · ${e.source} ${e.has_password ? html`· <b class="tone-critical">${e.password_plaintext ? "plaintext credentials" : "credentials"}</b>` : ""}</div>` },
      { label: "Asset", render: (e) => html`<div>${e.identifier || e.asset}</div><div class="cell-sub">${e.asset_type}${e.asset_label ? " · " + e.asset_label : ""}</div>` },
      { label: "Leaked", render: (e) => fmtDate(e.leaked_at), cls: "nowrap" },
      { label: "Found", render: (e) => ago(e.first_seen), cls: "nowrap" },
      { label: "Status", render: (e) => chip(e.status.replace("_", " ")) },
    ], rows, { empty: "No exposures found. Add assets to the watchlist and run a scan.", rowAttr: () => 'class="clickable"' })}
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
    if (tr && !e.target.closest("a")) openExposure(rows[tr.dataset.i].id, load);
  });
  window.addEventListener("tw:job-done", load, { signal });
  await load();
  if (params.open) openExposure(params.open, load);
}

async function openExposure(id, reload) {
  const e = await api(`/darkweb/exposures/${id}`);
  const body = openDrawer(e.title, html`
    <section style="display:flex;gap:12px;align-items:center">${sevBadge(e.severity)} ${scoreBar(e.risk_score, e.severity)}
      <label class="field-inline" style="margin-left:auto"><span>Status</span><select id="exp-status">
        ${STATUSES.map((s) => html`<option value="${s}" ${s === e.status ? "selected" : ""}>${s.replace("_", " ")}</option>`)}</select></label></section>
    <section>${kv([
      ["Asset", html`${e.asset} <span class="muted">(${e.asset_type})</span>`],
      ["Matched identifier", e.identifier],
      ["Source", html`${e.source} · ${ST_LABEL[e.source_type] || e.source_type}`],
      ["Leak date", fmtDate(e.leaked_at)],
      ["First seen", fmtDate(e.first_seen, true)],
      ["Records in leak", e.record_count ? fmtNum(e.record_count) : null],
      ["Credentials", e.has_password ? (e.password_plaintext ? "Yes - plaintext / easily cracked" : "Yes - hashed or unknown") : "No"],
      ["Reference", e.url ? html`<a href="${e.url}" target="_blank" rel="noopener noreferrer">${truncate(e.url, 60)}</a>` : null],
    ])}</section>
    ${e.data_classes.length ? html`<section><h3>Exposed data</h3><div class="chips">${e.data_classes.map((d) => chip(d))}</div></section>` : ""}
    ${e.description ? html`<section><h3>Details</h3><p style="margin:0">${e.description}</p></section>` : ""}
    <section><h3>Why this score</h3>${factors(e.score_factors)}</section>
    <section><h3>Recommended response</h3><ul class="small" style="padding-left:18px;margin:0">
      ${e.has_password ? html`<li>Force a password reset for <b>${e.identifier}</b> and any account sharing the password.</li>
        <li>Revoke active sessions / refresh tokens; verify MFA is enrolled.</li>` : ""}
      ${e.source_type === "stealer_log" ? html`<li>Treat the device as compromised: isolate, reimage, rotate every credential stored in its browser.</li>` : ""}
      ${e.source_type === "ransomware_leak" ? html`<li>Engage incident response and legal; confirm whether the victim is you or a supplier; assess data in the claim.</li>` : ""}
      ${e.source_type === "code_repo" ? html`<li>Rotate the secret immediately and request removal from the repository / history.</li>` : ""}
      <li>Watch for phishing / credential-stuffing targeting this identity.</li></ul></section>
    <section><h3>Raw source data</h3><div class="pre">${JSON.stringify(e.raw, null, 2)}</div></section>`);
  $("#exp-status", body).addEventListener("change", async (ev) => {
    await api(`/darkweb/exposures/${id}`, { method: "PATCH", body: { status: ev.target.value } });
    toast("Status updated", "ok");
    reload();
  });
}

async function renderSources(el) {
  const src = await api("/darkweb/sources");
  mount(el, html`<p class="muted">Sources are queried for each watchlist asset. Keyed sources activate when their
    environment variable is set (see <a href="#/settings">Settings</a> and docs/SOURCES.md).</p>
    ${table([
      { label: "Source", render: (s) => html`<div class="cell-title">${s.title}</div><div class="cell-sub">${s.description}</div>` },
      { label: "Searches", render: (s) => html`<div class="chips">${s.kinds.map((k) => chip(k))}</div>` },
      { label: "Status", render: (s) => s.available ? html`<span class="chip chip-ok">● active</span>`
          : html`<span class="chip">needs ${s.requires ? "TW_" + s.requires.toUpperCase() : "config"}</span>` },
    ], src)}`);
}

function renderImport(el) {
  mount(el, html`<div class="grid g-21"><div class="card">
    <h2 style="margin-bottom:6px">Import a leak file</h2>
    <p class="muted small">Upload a combo list, infostealer log export (URL:login:password), CSV or paste dump obtained during
      an investigation. Lines are matched against watched emails, executive addresses and domains (including credentials for
      your own login portals). <b>Plaintext passwords are never stored</b> - only a masked hint.</p>
    <form id="imp">
      <label class="field"><span>File</span><input type="file" name="file" required></label>
      <div class="form-row">
        <label class="field"><span>Source type</span><select name="source_type">
          <option value="combolist">Combo list</option><option value="stealer_log">Infostealer log</option>
          <option value="breach">Breach dump</option><option value="paste">Paste</option><option value="forum">Forum post</option></select></label>
        <label class="field"><span>Leak date (optional)</span><input type="date" name="leaked_at"></label>
      </div>
      <button class="btn btn-primary">Import and match</button>
    </form><div id="imp-result" style="margin-top:14px"></div></div>
    <div class="card"><h3>Supported formats</h3><div class="pre">email:password
email;password
https://sso.example.com/login:user:password
https://vpn.example.com|user@example.com|password
any CSV / text containing email addresses</div></div></div>`);
  $("#imp").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    if (!fd.get("leaked_at")) fd.delete("leaked_at");
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    try {
      const r = await api("/darkweb/import", { method: "POST", form: fd });
      mount($("#imp-result"), html`<div class="banner">Processed ${fmtNum(r.lines)} lines: <b>${r.matches}</b> matched your watchlist,
        <b>${r.new_exposures}</b> new exposures, ${r.alerts} alerts. <a href="#/darkweb?sort=recent">View exposures →</a></div>`);
    } catch (err) { toast(err.message, "error"); }
    btn.disabled = false;
  });
}
