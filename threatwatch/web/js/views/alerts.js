import { api } from "../api.js";
import { setParams } from "../app.js";
import { $, $$, ago, debounce, html, mount, pager, sectionHead, select, sevBadge, table, toast } from "../ui.js";

const LINK = { exposure: (id) => `#/darkweb?open=${id}`, indicator: (id) => `#/intel?open=${id}`,
  lookalike: () => "#/phishing", asm_scan: (id) => `#/asm/${id}` };

export async function render(main, { params }) {
  const state = { status: params.status ?? "open", severity: params.severity || "", module: params.module || "",
    q: params.q || "", offset: Number(params.offset || 0), limit: 50 };

  mount(main, html`
    ${sectionHead("Alerts", "Generated when an exposure, indicator, look-alike or ASM finding meets the alert threshold")}
    <div class="toolbar" id="filters">
      <input type="search" name="q" placeholder="Search alerts…" value="${state.q}">
      ${select("status", [["", "Any status"], ["open", "Open"], ["acknowledged", "Acknowledged"], ["closed", "Closed"]], state.status, "Status")}
      ${select("severity", [["", "Any"], ["critical", "Critical"], ["high", "High"], ["critical,high", "Critical + high"], ["medium", "Medium"], ["low", "Low"]], state.severity, "Severity")}
      ${select("module", [["", "All modules"], ["darkweb", "Dark web"], ["intel", "Threat intel"], ["phishing", "Anti-phishing"], ["asm", "Attack surface"]], state.module, "Module")}
      <span style="flex:1"></span>
      <button class="btn btn-sm" id="ack-all">Acknowledge shown</button>
      <button class="btn btn-sm" id="close-all">Close shown</button>
    </div>
    <div id="list"></div>`);

  let rows = [];
  async function load() {
    setParams({ ...state, limit: undefined, offset: state.offset || undefined });
    const res = await api("/alerts", { params: state });
    rows = res.items;
    mount($("#list"), html`${table([
      { label: "Severity", render: (a) => sevBadge(a.severity), cls: "nowrap" },
      { label: "Alert", render: (a) => html`<div class="cell-title">${LINK[a.ref_type] ? html`<a href="${LINK[a.ref_type](a.ref_id)}">${a.title}</a>` : a.title}</div>
          <div class="cell-sub">${a.description}</div>` },
      { label: "Module", key: "module", cls: "nowrap" },
      { label: "Raised", render: (a) => ago(a.created_at), cls: "nowrap" },
      { label: "Status", render: (a) => html`<select data-id="${a.id}" class="status-sel">
          ${["open", "acknowledged", "closed"].map((s) => html`<option ${s === a.status ? "selected" : ""}>${s}</option>`)}</select>`, cls: "nowrap" },
    ], rows, { empty: "No alerts match these filters." })}${pager(res.total, state.limit, state.offset)}`);
  }

  main.addEventListener("change", async (e) => {
    if (e.target.classList.contains("status-sel")) {
      await api(`/alerts/${e.target.dataset.id}`, { method: "PATCH", body: { status: e.target.value } });
      toast("Alert updated", "ok");
    } else if (e.target.closest("#filters") && e.target.name) {
      state[e.target.name] = e.target.value; state.offset = 0; load();
    }
  });
  $("input[name=q]", main).addEventListener("input", debounce((e) => { state.q = e.target.value; state.offset = 0; load(); }));
  main.addEventListener("click", (e) => {
    const p = e.target.closest("[data-page]");
    if (p) { state.offset = Number(p.dataset.page); load(); }
  });
  for (const [id, status] of [["#ack-all", "acknowledged"], ["#close-all", "closed"]]) {
    $(id, main).addEventListener("click", async () => {
      if (!rows.length) return;
      const r = await api("/alerts/bulk", { method: "POST", body: { ids: rows.map((a) => a.id), status } });
      toast(`${r.updated} alerts ${status}`, "ok");
      load();
    });
  }
  await load();
}
