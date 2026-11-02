// Shared UI helpers. All dynamic content goes through `html` which escapes interpolations by
// default: feed data, page titles of phishing sites and dark-web snippets are untrusted input.

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
export const raw = (s) => new Raw(s);

function interp(v) {
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(interp).join("");
  if (v === null || v === undefined || v === false) return "";
  return esc(v);
}

/** Tagged template: html`<b>${userText}</b>` -> Raw with escaped interpolations. */
export function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => { out += interp(v) + strings[i + 1]; });
  return new Raw(out);
}

export function mount(el, content) { el.innerHTML = interp(content); return el; }
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function sevBadge(sev) {
  return html`<span class="sev sev-${sev}"><i></i>${sev}</span>`;
}

export function scoreBar(score, sev) {
  return html`<span class="score" title="Risk score ${score}/100"><span class="score-track"><span class="score-fill sev-bg-${sev}" style="width:${Math.max(3, score)}%"></span></span><b>${score}</b></span>`;
}

export function chip(text, cls = "") { return html`<span class="chip ${cls}">${text}</span>`; }

export function fmtNum(n) { return n == null ? "-" : Number(n).toLocaleString(); }

export function fmtDate(iso, withTime = false) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return "-";
  return withTime ? d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
                  : d.toLocaleDateString(undefined, { dateStyle: "medium" });
}

export function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  const units = [[86400 * 365, "y"], [86400 * 30, "mo"], [86400, "d"], [3600, "h"], [60, "m"]];
  for (const [n, u] of units) if (s >= n) return `${Math.floor(s / n)}${u} ago`;
  return "just now";
}

export function truncate(s, n = 80) { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

// ---------------------------------------------------------------- toasts
export function toast(msg, kind = "info") {
  let host = $("#toasts");
  const t = document.createElement("div");
  t.className = `toast toast-${kind}`;
  t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => t.classList.add("out"), 4200);
  setTimeout(() => t.remove(), 4700);
}

// ---------------------------------------------------------------- drawer (detail panel)
export function openDrawer(title, content) {
  const d = $("#drawer");
  mount($("#drawer-title"), title);
  mount($("#drawer-body"), content);
  d.classList.add("open");
  d.setAttribute("aria-hidden", "false");
  $("#drawer-close").focus();
  return $("#drawer-body");
}
export function closeDrawer() {
  const d = $("#drawer");
  d.classList.remove("open");
  d.setAttribute("aria-hidden", "true");
}

// ---------------------------------------------------------------- modal
export function openModal(title, content) {
  mount($("#modal-title"), title);
  mount($("#modal-body"), content);
  $("#modal").showModal();
  return $("#modal-body");
}
export function closeModal() { $("#modal").close(); }

// ---------------------------------------------------------------- tables
/**
 * cols: [{key, label, render?(row), cls?, sort?}]
 * Renders a table; rows clickable when onRow given (event delegation by data-i).
 */
export function table(cols, rows, { empty = "Nothing here yet.", rowAttr = () => "" } = {}) {
  if (!rows.length) return html`<div class="empty">${empty}</div>`;
  return html`<div class="table-wrap"><table class="tbl">
    <thead><tr>${cols.map((c) => html`<th class="${c.cls || ""}">${c.label}</th>`)}</tr></thead>
    <tbody>${rows.map((r, i) => html`<tr data-i="${i}" ${raw(rowAttr(r))}>${cols.map((c) =>
      html`<td class="${c.cls || ""}">${c.render ? c.render(r) : r[c.key]}</td>`)}</tr>`)}</tbody>
  </table></div>`;
}

export function pager(total, limit, offset) {
  if (total <= limit) return html`<div class="pager muted">${fmtNum(total)} result${total === 1 ? "" : "s"}</div>`;
  const from = offset + 1, to = Math.min(total, offset + limit);
  return html`<div class="pager"><span class="muted">${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(total)}</span>
    <button class="btn btn-ghost btn-sm" data-page="${Math.max(0, offset - limit)}" ${offset === 0 ? "disabled" : ""}>← Prev</button>
    <button class="btn btn-ghost btn-sm" data-page="${offset + limit}" ${to >= total ? "disabled" : ""}>Next →</button></div>`;
}

export function kv(pairs) {
  return html`<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>`;
}

export function factors(list) {
  if (!list || !list.length) return html`<div class="muted">No scoring factors recorded.</div>`;
  return html`<ul class="factors">${list.map((f) => html`<li><span>${f.factor}</span>
    <b class="${f.delta >= 0 ? "pos" : "neg"}">${f.delta >= 0 ? "+" : ""}${f.delta}</b></li>`)}</ul>`;
}

export function debounce(fn, ms = 300) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function select(name, options, value, label) {
  return html`<label class="field-inline"><span>${label}</span><select name="${name}">
    ${options.map(([v, l]) => html`<option value="${v}" ${String(v) === String(value ?? "") ? "selected" : ""}>${l}</option>`)}
  </select></label>`;
}

export function spinner(text = "Loading…") { return html`<div class="loading"><span class="spin"></span>${text}</div>`; }

export function sectionHead(title, sub, actions = "") {
  return html`<div class="page-head"><div><h1>${title}</h1>${sub ? html`<p class="muted">${sub}</p>` : ""}</div>
    <div class="actions">${actions}</div></div>`;
}

export function attackLink(t) {
  const id = typeof t === "string" ? t : t.id;
  const url = "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
  return html`<a class="chip chip-attack" href="${url}" target="_blank" rel="noopener" title="${typeof t === "string" ? id : t.name}">${id}</a>`;
}
