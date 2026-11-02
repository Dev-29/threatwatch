import { api } from "../api.js";
import { $, ago, closeModal, html, mount, openModal, sectionHead, table, toast, chip } from "../ui.js";

const TYPES = {
  domain: ["Domain", "Organisation domains. Drive dark-web domain searches, look-alike detection and ASM.", "example.com"],
  email: ["Email", "Individual mailboxes (employees, shared, service accounts).", "jane@example.com"],
  executive: ["Executive", "VIPs: name + known email addresses / handles. Higher default criticality.", "Jane Doe"],
  brand: ["Brand", "Brand / product names to spot in phishing URLs, leaks and ransomware listings.", "ExampleCorp"],
  keyword: ["Keyword", "Sensitive project codenames or internal terms.", "Project Falcon"],
};

export async function render(main) {
  mount(main, html`
    ${sectionHead("Watchlist", "What ThreatWatch monitors on your behalf",
      html`<button class="btn btn-primary" id="add">+ Add asset</button>`)}
    <div id="list"></div>`);

  async function load() {
    const rows = await api("/assets");
    mount($("#list"), table([
      { label: "Type", render: (a) => chip(TYPES[a.type]?.[0] || a.type), cls: "nowrap" },
      { label: "Value", render: (a) => html`<div class="cell-title">${a.value}</div>
          ${a.type === "executive" && a.meta.emails?.length ? html`<div class="cell-sub">${a.meta.emails.join(", ")}</div>` : ""}` },
      { label: "Label", render: (a) => a.label || html`<span class="muted">-</span>` },
      { label: "Criticality", key: "criticality" },
      { label: "Exposures", render: (a) => a.exposures ? html`<a href="#/darkweb?asset_id=${a.id}">${a.exposures}</a>` : "0", cls: "num" },
      { label: "Last scanned", render: (a) => ago(a.last_scanned_at), cls: "nowrap" },
      { label: "Monitoring", render: (a) => html`<label class="checkline" style="margin:0"><input type="checkbox" data-toggle="${a.id}" ${a.enabled ? "checked" : ""}> ${a.enabled ? "on" : "off"}</label>` },
      { label: "", render: (a) => html`<button class="btn btn-ghost btn-sm btn-danger" data-del="${a.id}" aria-label="Delete ${a.value}">Delete</button>` },
    ], rows, { empty: "No assets yet. Add your primary domain first - it powers every module." }));
  }

  main.addEventListener("change", async (e) => {
    const id = e.target.dataset.toggle;
    if (id) { await api(`/assets/${id}`, { method: "PATCH", body: { enabled: e.target.checked } }); load(); }
  });
  main.addEventListener("click", async (e) => {
    const del = e.target.closest("[data-del]");
    if (del && confirm("Delete this asset and all of its exposures?")) {
      await api(`/assets/${del.dataset.del}`, { method: "DELETE" });
      toast("Asset deleted", "ok");
      load();
    }
  });
  $("#add").addEventListener("click", () => {
    const body = openModal("Add watchlist asset", html`<form id="asset-form">
      <label class="field"><span>Type</span><select name="type">${Object.entries(TYPES).map(([k, v]) => html`<option value="${k}">${v[0]}</option>`)}</select></label>
      <p class="muted small" id="type-help">${TYPES.domain[1]}</p>
      <label class="field"><span id="value-label">Value</span><input name="value" required placeholder="${TYPES.domain[2]}"></label>
      <label class="field" id="emails-field" hidden><span>Email addresses (comma-separated)</span><input name="emails" placeholder="jane.doe@example.com, jdoe@example.com"></label>
      <div class="form-row">
        <label class="field"><span>Label (optional)</span><input name="label" placeholder="e.g. CEO, primary domain"></label>
        <label class="field"><span>Criticality</span><select name="criticality"><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select></label>
      </div>
      <div class="modal-foot"><button type="button" class="btn" id="cancel">Cancel</button><button class="btn btn-primary">Add</button></div>
    </form>`);
    const f = $("#asset-form", body);
    f.type.addEventListener("change", () => {
      const t = TYPES[f.type.value];
      $("#type-help").textContent = t[1];
      f.value.placeholder = t[2];
      $("#emails-field").hidden = f.type.value !== "executive";
      $("#value-label").textContent = f.type.value === "executive" ? "Full name" : "Value";
    });
    $("#cancel").addEventListener("click", closeModal);
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(f);
      const payload = { type: fd.get("type"), value: fd.get("value"), label: fd.get("label") || null, criticality: fd.get("criticality"), meta: {} };
      if (payload.type === "executive") payload.meta.emails = (fd.get("emails") || "").split(",").map((s) => s.trim()).filter(Boolean);
      try {
        await api("/assets", { method: "POST", body: payload });
        closeModal();
        toast("Asset added", "ok");
        load();
      } catch (err) { toast(err.message, "error"); }
    });
  });
  await load();
}
