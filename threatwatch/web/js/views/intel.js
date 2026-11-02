import { api, href } from "../api.js";
import { jobStarted, setParams } from "../app.js";
import { $, ago, attackLink, chip, debounce, factors, fmtDate, fmtNum, html, kv, mount, openDrawer, pager, scoreBar,
  sectionHead, select, sevBadge, table, toast, truncate } from "../ui.js";

const TYPES = ["ipv4", "ipv6", "cidr", "domain", "url", "md5", "sha1", "sha256", "x509-sha1", "email", "cve"];

export async function render(main, { params, signal }) {
  const tab = params.tab || "indicators";
  mount(main, html`
    ${sectionHead("Threat Intelligence", "Normalised, de-duplicated and scored IOCs from open-source and trial feeds, mapped to MITRE ATT&CK",
      html`<button class="btn btn-primary" id="collect">Collect feeds now</button>`)}
    <div class="tabs" role="tablist">${[["indicators", "Indicators"], ["feeds", "Feeds"], ["lookup", "Lookup"], ["export", "Export & API"]]
      .map(([k, l]) => html`<button role="tab" data-tab="${k}" class="${tab === k ? "active" : ""}">${l}</button>`)}</div>
    <div id="tab"></div>`);
  main.querySelector(".tabs").addEventListener("click", (e) => { if (e.target.dataset.tab) location.hash = `#/intel?tab=${e.target.dataset.tab}`; });
  $("#collect").addEventListener("click", async () => {
    try {
      await api("/intel/feeds/run", { method: "POST", body: {} });
      jobStarted("feeds", "all");
      toast("Feed collection started", "ok");
    } catch (err) { toast(err.message, "error"); }
  });
  const el = $("#tab");
  if (tab === "feeds") return renderFeeds(el, signal);
  if (tab === "lookup") return renderLookup(el, params);
  if (tab === "export") return renderExport(el, params);
  return renderIndicators(el, params, signal);
}

async function renderIndicators(el, params, signal) {
  const state = { type: params.type || "", severity: params.severity || "", feed: params.feed || "", technique: params.technique || "",
    malware: params.malware || "", threat_type: params.threat_type || "", q: params.q || "", sort: params.sort || "score",
    min_score: params.min_score || "", offset: Number(params.offset || 0), limit: 50 };
  const feeds = await api("/intel/feeds");
  mount(el, html`<div class="toolbar" id="filters">
      <input type="search" name="q" placeholder="Search value…" value="${state.q}">
      ${select("type", [["", "All types"], ...TYPES.map((t) => [t, t])], state.type, "Type")}
      ${select("severity", [["", "Any"], ["critical", "Critical"], ["high", "High"], ["critical,high", "Critical + high"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]], state.severity, "Severity")}
      ${select("feed", [["", "All feeds"], ...feeds.filter((f) => f.indicators).map((f) => [f.name, f.title])], state.feed, "Feed")}
      ${select("sort", [["score", "Highest score"], ["recent", "Last seen"], ["new", "Newest"]], state.sort, "Sort")}
      ${["technique", "malware", "threat_type"].filter((k) => state[k]).map((k) => html`<span class="chip">${k}: ${state[k]} <a href="#" data-clear="${k}">✕</a></span>`)}
    </div><div id="rows"></div>`);
  let rows = [];
  async function load() {
    setParams({ ...state, limit: undefined, offset: state.offset || undefined, sort: state.sort === "score" ? undefined : state.sort });
    const res = await api("/intel/indicators", { params: state });
    rows = res.items;
    mount($("#rows"), html`${table([
      { label: "Score", render: (i) => scoreBar(i.score, i.severity), cls: "nowrap" },
      { label: "Type", render: (i) => chip(i.type), cls: "nowrap" },
      { label: "Indicator", render: (i) => html`<div class="mono wrap-any">${truncate(i.value, 90)}</div>
          <div class="cell-sub">${[...i.threat_types, ...i.malware_families].join(" · ")}</div>`, cls: "wrap-any" },
      { label: "ATT&CK", render: (i) => html`<div class="chips">${i.attack_techniques.slice(0, 4).map(attackLink)}${i.attack_techniques.length > 4 ? chip(`+${i.attack_techniques.length - 4}`) : ""}</div>` },
      { label: "Sources", render: (i) => html`<span title="${i.sources.join(", ")}">${i.source_count}</span>`, cls: "num" },
      { label: "Confidence", key: "confidence", cls: "num" },
      { label: "Last seen", render: (i) => ago(i.last_seen), cls: "nowrap" },
    ], rows, { empty: "No indicators. Click “Collect feeds now” to ingest open-source feeds.", rowAttr: () => 'class="clickable"' })}
    ${pager(res.total, state.limit, state.offset)}`);
  }
  el.addEventListener("change", (e) => {
    if (e.target.closest("#filters") && e.target.name) { state[e.target.name] = e.target.value; state.offset = 0; load(); }
  });
  $("input[name=q]", el).addEventListener("input", debounce((e) => { state.q = e.target.value; state.offset = 0; load(); }));
  el.addEventListener("click", (e) => {
    const c = e.target.closest("[data-clear]");
    if (c) { e.preventDefault(); state[c.dataset.clear] = ""; c.parentElement.remove(); state.offset = 0; return load(); }
    const p = e.target.closest("[data-page]");
    if (p) { state.offset = Number(p.dataset.page); return load(); }
    const tr = e.target.closest("tr[data-i]");
    if (tr && !e.target.closest("a")) openIndicator(rows[tr.dataset.i].id);
  });
  window.addEventListener("tw:job-done", load, { signal });
  await load();
  if (params.open) openIndicator(params.open);
}

export async function openIndicator(id) {
  const i = await api(`/intel/indicators/${id}`);
  openDrawer(html`<span class="mono">${truncate(i.value, 80)}</span>`, html`
    <section style="display:flex;gap:12px;align-items:center">${sevBadge(i.severity)} ${scoreBar(i.score, i.severity)}
      <span class="muted small">confidence ${i.confidence} · ${i.active ? "active" : "expired"}</span></section>
    <section>${kv([
      ["Type", i.type], ["Value", html`<span class="mono wrap-any">${i.value}</span>`],
      ["Threat types", i.threat_types.join(", ")], ["Malware", i.malware_families.join(", ")],
      ["First seen", fmtDate(i.first_seen, true)], ["Last seen", fmtDate(i.last_seen, true)], ["TLP", i.tlp.toUpperCase()],
      ["Tags", i.tags.length ? html`<div class="chips">${i.tags.map((t) => chip(t))}</div>` : null],
      ["Context", Object.keys(i.context || {}).length ? html`<span class="small">${Object.entries(i.context).filter(([, v]) => typeof v !== "object")
        .map(([k, v]) => `${k}: ${v}`).join(" · ")}</span>` : null],
      ["Description", i.description],
    ])}</section>
    <section><h3>MITRE ATT&CK</h3>${i.attack.length ? html`<div class="table-wrap"><table class="tbl"><tbody>${i.attack.map((t) => html`
      <tr><td class="nowrap">${attackLink(t)}</td><td>${t.name}</td><td class="muted small">${t.tactics.join(", ")}</td></tr>`)}</tbody></table></div>`
      : html`<div class="muted">No technique mapping.</div>`}</section>
    <section><h3>Sources (${i.sources.length})</h3>${table([
      { label: "Feed", key: "feed" }, { label: "Confidence", key: "confidence", cls: "num" },
      { label: "First seen", render: (s) => fmtDate(s.first_seen) }, { label: "Last seen", render: (s) => ago(s.last_seen) },
      { label: "", render: (s) => s.reference ? html`<a href="${s.reference}" target="_blank" rel="noopener noreferrer">ref ↗</a>` : "" },
    ], i.sources)}</section>
    <section><h3>Why this score</h3>${factors(i.score_factors)}</section>
    <section><h3>STIX 2.1</h3><div class="pre">${JSON.stringify(i.stix, null, 2)}</div></section>`);
}

async function renderFeeds(el, signal) {
  async function load() {
    const feeds = await api("/intel/feeds");
    mount(el, html`<p class="muted">Feeds are collected on a schedule (TW_FEEDS_INTERVAL_MINUTES). Trial feeds need a free API key.</p>
      ${table([
      { label: "Feed", render: (f) => html`<div class="cell-title"><a href="${f.homepage}" target="_blank" rel="noopener">${f.title}</a></div><div class="cell-sub">${f.description}</div>` },
      { label: "Category", render: (f) => chip(f.category) },
      { label: "Reliability", key: "confidence", cls: "num" },
      { label: "Indicators", render: (f) => f.indicators ? html`<a href="#/intel?feed=${f.name}">${fmtNum(f.indicators)}</a>` : "0", cls: "num" },
      { label: "Last run", render: (f) => f.last_run ? html`<span class="status-dot ${f.running ? "running" : f.last_status}"></span>${ago(f.last_run)}
          <div class="cell-sub" title="${f.last_message || ""}">${f.last_status === "ok" ? `+${fmtNum(f.last_new)} new / ${fmtNum(f.last_count)}` : truncate(f.last_message, 60)}</div>`
          : html`<span class="muted">never</span>`, cls: "nowrap" },
      { label: "Enabled", render: (f) => f.available ? html`<input type="checkbox" data-feed="${f.name}" ${f.enabled ? "checked" : ""} aria-label="Enable ${f.title}">`
          : html`<span class="chip" title="Set ${f.requires}">needs key</span>` },
      { label: "", render: (f) => f.available ? html`<button class="btn btn-sm" data-run="${f.name}" ${f.running ? "disabled" : ""}>Run</button>` : "" },
    ], feeds)}`);
  }
  el.addEventListener("change", async (e) => {
    if (e.target.dataset.feed) {
      await api(`/intel/feeds/${e.target.dataset.feed}`, { method: "PATCH", body: { enabled: e.target.checked } });
      toast(`Feed ${e.target.checked ? "enabled" : "disabled"}`, "ok");
    }
  });
  el.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-run]");
    if (!b) return;
    try {
      await api("/intel/feeds/run", { method: "POST", body: { feeds: [b.dataset.run] } });
      jobStarted("feeds", b.dataset.run);
      b.disabled = true;
      toast(`Collecting ${b.dataset.run}…`, "ok");
    } catch (err) { toast(err.message, "error"); }
  });
  window.addEventListener("tw:job-done", load, { signal });
  await load();
}

async function renderLookup(el, params) {
  mount(el, html`<div class="card"><p class="muted small" style="margin-top:0">Paste anything - logs, an email, a report. Indicators are
    extracted (refanging <code>hxxp</code> / <code>[.]</code>), normalised and checked against the database. URLs also match their host and parent domain.</p>
    <form id="lk"><textarea name="text" rows="7" placeholder="185.220.101.1, hxxps://evil[.]example/login, 44d88612fea8a8f36de82e1278abb02f">${params.text || ""}</textarea>
    <div style="margin-top:10px"><button class="btn btn-primary">Check indicators</button></div></form></div>
    <div id="lk-res" style="margin-top:16px"></div>`);
  async function run(text) {
    const r = await api("/intel/lookup", { method: "POST", body: { text } });
    mount($("#lk-res"), html`<div class="banner ${r.known ? "warn" : ""}">${r.extracted} indicators extracted - <b>${r.known} known malicious</b>.</div>
      ${table([
        { label: "Result", render: (x) => x.known ? sevBadge(x.matches[0].severity) : html`<span class="chip">not found</span>` },
        { label: "Type", render: (x) => chip(x.type) },
        { label: "Indicator", render: (x) => html`<span class="mono wrap-any">${x.value}</span>` },
        { label: "Matches", render: (x) => x.matches.map((m) => html`<div class="small"><a href="#/intel?open=${m.id}">${truncate(m.value, 50)}</a> ·
            score ${m.score} · ${m.sources.join(", ")} · ${[...m.threat_types, ...m.malware_families].join(", ")}</div>`) },
      ], r.results, { empty: "No indicators recognised in the text." })}`);
  }
  $("#lk").addEventListener("submit", (e) => { e.preventDefault(); run(new FormData(e.target).get("text")); });
  if (params.text) run(params.text);
}

function renderExport(el, params) {
  const origin = location.origin;
  const f = { min_score: params.min_score || "", type: params.type || "", severity: params.severity || "" };
  mount(el, html`<div class="grid g-2">
    <div class="card"><h2 style="margin-bottom:10px">Download</h2>
      <form id="ex" class="form-row">
        <label class="field"><span>Indicator types</span><select name="type"><option value="">All</option>${TYPES.map((t) => html`<option ${t === f.type ? "selected" : ""}>${t}</option>`)}</select></label>
        <label class="field"><span>Minimum score</span><input name="min_score" type="number" min="0" max="100" value="${f.min_score}" placeholder="0"></label>
        <label class="field"><span>Severity</span><select name="severity"><option value="">Any</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label>
      </form>
      <div class="actions" id="ex-btns">
        <a class="btn btn-primary" data-fmt="stix">STIX 2.1 bundle</a><a class="btn" data-fmt="json">ThreatWatch JSON</a>
        <a class="btn" data-fmt="csv">CSV</a><a class="btn" data-fmt="txt">Plain text blocklist</a></div>
      <p class="muted small">STIX bundles contain indicators, vulnerabilities, malware families and ATT&amp;CK attack-patterns linked with
        <code>indicates</code> relationships. Object IDs are deterministic, so re-imports upsert. Format reference: <code>docs/DATA_FORMAT.md</code>.</p>
    </div>
    <div class="card"><h2 style="margin-bottom:10px">TAXII 2.1 server</h2>
      <p class="small">Point a TIP / SIEM (OpenCTI, MISP, Sentinel, Splunk ES…) at the read-only TAXII endpoint:</p>
      ${kv([["Discovery", html`<code>${origin}/taxii2/</code>`], ["API root", html`<code>${origin}/taxii2/api/</code>`],
        ["Collections", "All indicators · High confidence (score ≥ 65) · Phishing · C2 infrastructure"],
        ["Auth", "X-API-Key header (when TW_API_KEY is set)"]])}
      <h3 style="margin-top:16px">REST examples</h3>
      <div class="pre">curl -H "X-API-Key: $KEY" "${origin}/api/v1/intel/indicators?type=ipv4&amp;min_score=70"
curl -H "X-API-Key: $KEY" "${origin}/api/v1/intel/export/stix?severity=critical,high" -o iocs.stix.json
curl -H "X-API-Key: $KEY" -H "Accept: application/taxii+json;version=2.1" \\
  "${origin}/taxii2/api/collections/4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c02/objects/?limit=100"</div>
      <p class="small"><a href="/api/docs" target="_blank" rel="noopener">Interactive OpenAPI documentation →</a></p>
    </div></div>`);
  function update() {
    const fd = Object.fromEntries(new FormData($("#ex")));
    for (const a of el.querySelectorAll("[data-fmt]")) a.href = href(`/intel/export/${a.dataset.fmt}`, fd);
  }
  $("#ex").addEventListener("input", update);
  update();
}
