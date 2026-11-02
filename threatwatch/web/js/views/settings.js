import { api, getKey, setKey } from "../api.js";
import { $, ago, chip, html, kv, mount, sectionHead, table, toast } from "../ui.js";

const INTEGRATIONS = {
  hibp: ["Have I Been Pwned", "TW_HIBP_API_KEY", "Per-email breaches & pastes"],
  intelx: ["Intelligence X", "TW_INTELX_API_KEY", "Pastes, darknet, leaks search"],
  github: ["GitHub", "TW_GITHUB_TOKEN", "Secret leaks in public code"],
  abusech: ["abuse.ch", "TW_ABUSECH_AUTH_KEY", "ThreatFox, URLhaus, MalwareBazaar feeds"],
  otx: ["AlienVault OTX", "TW_OTX_API_KEY", "Pulses (with ATT&CK IDs) + passive DNS for ASM"],
  abuseipdb: ["AbuseIPDB", "TW_ABUSEIPDB_API_KEY", "High-confidence abusive IP blacklist"],
  tor: ["Tor proxy", "TW_TOR_PROXY + TW_ONION_SOURCES", ".onion forum / leak-site keyword monitoring"],
  webhook: ["Alert webhook", "TW_ALERT_WEBHOOK_URL", "Slack / Teams / Mattermost notifications"],
};

export async function render(main) {
  const [s, jobs] = await Promise.all([api("/settings"), api("/jobs", { params: { limit: 25 } })]);
  mount(main, html`
    ${sectionHead("Settings", `ThreatWatch v${s.version} · configuration is read from environment variables / .env (see .env.example)`)}
    <div class="grid g-2">
      <div class="card"><div class="card-head"><h2>Integrations</h2></div>
        ${table([
          { label: "Integration", render: ([k, v]) => html`<div class="cell-title">${v[0]}</div><div class="cell-sub">${v[2]}</div>` },
          { label: "Variable", render: ([, v]) => html`<code class="small">${v[1]}</code>` },
          { label: "Status", render: ([k]) => s.integrations[k] ? chip("configured", "chip-ok") : chip("not set") },
        ], Object.entries(INTEGRATIONS))}</div>
      <div class="stack">
        <div class="card"><div class="card-head"><h2>Scheduler & limits</h2></div>${kv([
          ["Scheduler", s.scheduler.enabled ? "enabled" : "disabled"],
          ["Feed collection", `every ${s.scheduler.feeds_interval_minutes} min`],
          ["Dark web scan", s.scheduler.darkweb_interval_hours ? `every ${s.scheduler.darkweb_interval_hours} h` : "off"],
          ["Look-alike scan", s.scheduler.phishing_interval_hours ? `every ${s.scheduler.phishing_interval_hours} h` : "off"],
          ["ASM scan", s.scheduler.asm_interval_hours ? `every ${s.scheduler.asm_interval_hours} h` : "manual only"],
          ["Alert threshold", `${s.alerting.min_severity} and above`],
          ["IOC retention", `${s.limits.ioc_retention_days} days`], ["Max items per feed", s.limits.feed_max_items.toLocaleString()],
          ["Max permutations", s.limits.phishing_max_permutations.toLocaleString()], ["ASM max hosts", s.limits.asm_max_hosts],
          ["ATT&CK catalogue", `${s.attack_catalog_size} techniques`], ["Database", s.database],
        ])}</div>
        <div class="card"><div class="card-head"><h2>API access</h2></div>
          <p class="small">${s.auth_enabled ? "API key authentication is ON." : html`API key authentication is <b>OFF</b> - set <code>TW_API_KEY</code> before exposing this instance beyond localhost.`}</p>
          <form id="key" style="display:flex;gap:8px"><input type="password" name="key" placeholder="API key for this browser" value="${getKey()}" style="flex:1">
          <button class="btn">Save</button></form></div>
      </div>
    </div>
    <div class="card" style="margin-top:16px"><div class="card-head"><h2>Recent jobs</h2></div>
      ${table([
        { label: "Job", render: (j) => html`<b>${j.kind.replace("_", " ")}</b> <span class="muted small">${j.target || ""}</span>` },
        { label: "Trigger", key: "trigger" },
        { label: "Status", render: (j) => html`<span class="status-dot ${j.status === "success" ? "ok" : j.status === "failed" ? "error" : "running"}"></span>${j.status}` },
        { label: "Started", render: (j) => ago(j.started_at), cls: "nowrap" },
        { label: "Result", render: (j) => html`<span class="small">${j.message}</span>${Object.keys(j.stats?.errors || {}).length ? html`<div class="cell-sub">source errors: ${Object.keys(j.stats.errors).join(", ")}</div>` : ""}` },
      ], jobs.items, { empty: "No jobs have run yet." })}</div>`);
  $("#key").addEventListener("submit", (e) => {
    e.preventDefault();
    setKey(new FormData(e.target).get("key").trim());
    toast("API key saved in this browser", "ok");
  });
}
