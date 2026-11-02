// App shell: hash router, theme, API-key prompt, global IOC lookup, background-job indicator.
import { api, setKey, getKey } from "./api.js";
import { $, $$, closeDrawer, closeModal, html, mount, openModal, spinner, toast } from "./ui.js";
import { installTooltips } from "./charts.js";

const ROUTES = {
  "": () => import("./views/dashboard.js"),
  alerts: () => import("./views/alerts.js"),
  watchlist: () => import("./views/watchlist.js"),
  darkweb: () => import("./views/darkweb.js"),
  intel: () => import("./views/intel.js"),
  attack: () => import("./views/attack.js"),
  phishing: () => import("./views/phishing.js"),
  asm: () => import("./views/asm.js"),
  settings: () => import("./views/settings.js"),
};

let renderToken = 0;
let viewAbort = new AbortController();

export function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = h.split("?");
  const parts = path.split("/").filter(Boolean);
  return { route: parts[0] || "", args: parts.slice(1), params: Object.fromEntries(new URLSearchParams(query)) };
}

/** Update query params of the current route without re-rendering (filters, tabs). */
export function setParams(params, { replace = true } = {}) {
  const { route, args } = parseHash();
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)).toString();
  const url = `#/${[route, ...args].filter(Boolean).join("/")}${q ? "?" + q : ""}`;
  if (replace) history.replaceState(null, "", url); else history.pushState(null, "", url);
}

async function render() {
  const token = ++renderToken;
  const { route, args, params } = parseHash();
  const loader = ROUTES[route];
  // fresh <main> per render drops listeners the previous view attached; window listeners use `signal`
  viewAbort.abort();
  viewAbort = new AbortController();
  const old = $("#main");
  const main = old.cloneNode(false);
  old.replaceWith(main);
  closeDrawer();
  $$(".sidebar nav a[data-route]").forEach((a) => a.classList.toggle("active", a.dataset.route === (route || "dashboard")));
  $("#sidebar").classList.remove("open");
  if (!loader) { mount(main, html`<div class="empty">Page not found.</div>`); return; }
  mount(main, spinner());
  try {
    const mod = await loader();
    if (token !== renderToken) return;
    await mod.render(main, { args, params, signal: viewAbort.signal, isCurrent: () => token === renderToken });
    main.focus({ preventScroll: true });
  } catch (err) {
    if (token !== renderToken) return;
    if (err.status === 401) return; // auth prompt shown
    console.error(err);
    mount(main, html`<div class="empty">Failed to load: ${err.message}</div>`);
  }
}

// ---------------------------------------------------------------- theme
function initTheme() {
  $("#theme-toggle").addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme
      || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("tw.theme", next); } catch { /* ignore */ }
  });
}

// ---------------------------------------------------------------- auth
let authPromptOpen = false;
function promptKey() {
  if (authPromptOpen) return;
  authPromptOpen = true;
  const body = openModal("API key required", html`
    <p class="muted">This ThreatWatch instance is protected by <code>TW_API_KEY</code>. Enter the key to continue.
    It is stored only in this browser.</p>
    <form id="key-form"><label class="field"><span>API key</span><input name="key" type="password" required autocomplete="off"></label>
    <div class="modal-foot"><button class="btn btn-primary">Save</button></div></form>`);
  $("input", body).focus();
  $("#key-form").addEventListener("submit", (e) => {
    e.preventDefault();
    setKey(new FormData(e.target).get("key").trim());
    authPromptOpen = false;
    closeModal();
    render();
  });
  $("#modal").addEventListener("close", () => { authPromptOpen = false; }, { once: true });
}

// ---------------------------------------------------------------- background jobs + alert badge
let lastRunning = new Set();
async function pollStatus() {
  try {
    const [jobs, alerts] = await Promise.all([
      api("/jobs", { params: { limit: 1 } }),
      api("/alerts", { params: { status: "open", severity: "critical,high", limit: 1 } }),
    ]);
    const running = new Set(jobs.running.map((j) => `${j.kind}:${j.target}`));
    const ind = $("#jobs-indicator");
    ind.hidden = running.size === 0;
    $("#jobs-text").textContent = running.size ? `${[...running].map((r) => r.split(":")[0].replace("_", " ")).join(", ")} running` : "";
    for (const r of lastRunning) {
      if (!running.has(r)) {
        toast(`${r.split(":")[0].replace("_", " ")} finished`, "ok");
        window.dispatchEvent(new CustomEvent("tw:job-done", { detail: r }));
      }
    }
    lastRunning = running;
    $("#nav-alerts").textContent = alerts.total ? (alerts.total > 99 ? "99+" : alerts.total) : "";
  } catch { /* offline or auth - ignore */ }
}
export function jobStarted(kind, target) {
  lastRunning.add(`${kind}:${target}`);
  $("#jobs-indicator").hidden = false;
  $("#jobs-text").textContent = `${kind.replace("_", " ")} running`;
  setTimeout(pollStatus, 1500);
}

// ---------------------------------------------------------------- boot
function boot() {
  initTheme();
  installTooltips();
  window.addEventListener("hashchange", render);
  window.addEventListener("tw:auth-required", promptKey);
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#modal-close").addEventListener("click", closeModal);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  $("#menu-toggle").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#global-search").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = new FormData(e.target).get("q").trim();
    if (q) location.hash = `#/intel?tab=lookup&text=${encodeURIComponent(q)}`;
  });
  render();
  pollStatus();
  setInterval(pollStatus, 5000);
}

boot();
export { getKey };
