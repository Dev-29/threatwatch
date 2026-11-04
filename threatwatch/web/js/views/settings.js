import { api, getKey, setKey, setToken } from "../api.js";
import { refreshMe } from "../auth.js";
import { $, $$, ago, chip, closeModal, html, kv, mount, openModal, sectionHead, table, toast } from "../ui.js";

const ROLE_HELP = {
  admin: "Everything, plus managing user accounts",
  analyst: "Read and change everything: watchlist, scans, triage",
  viewer: "Read-only access",
};

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
  const [s, jobs, me] = await Promise.all([api("/settings"), api("/jobs", { params: { limit: 25 } }), refreshMe()]);
  const canAdmin = me.mode === "api_key" || (me.mode === "jwt" && me.user.role === "admin");
  const users = canAdmin ? (await api("/users")).items : [];
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
        ${me.mode === "jwt" ? html`<div class="card"><div class="card-head"><h2>Your account</h2></div>
          ${kv([["Username", me.user.username], ["Role", html`${me.user.role} <span class="muted small">· ${ROLE_HELP[me.user.role]}</span>`],
                ["Password changed", ago(me.user.password_changed_at)]])}
          <form id="pw-form" style="margin-top:12px">
            <label class="field"><span>Current password</span><input name="current_password" type="password" required autocomplete="current-password"></label>
            <label class="field"><span>New password</span><input name="new_password" type="password" required minlength="10" autocomplete="new-password"></label>
            <label class="field"><span>Confirm new password</span><input name="confirm" type="password" required autocomplete="new-password"></label>
            <button class="btn">Change password</button>
            <p class="small muted">You'll get a new token. Tokens already issued stay valid until they expire.</p>
          </form></div>` : ""}
        <div class="card"><div class="card-head"><h2>API access</h2></div>
          <p class="small">${s.auth.users ? html`Browser sign-in is <b>ON</b> (${s.auth.users} user${s.auth.users === 1 ? "" : "s"}; JWT tokens expire ${s.auth.token_expiry_minutes} min after issue).`
            : html`No user accounts exist yet.`}
          ${s.auth.api_key ? " The API key for scripts and TAXII clients is ON." : html` API key is <b>off</b>: set <code>TW_API_KEY</code> to let scripts and TAXII clients authenticate.`}</p>
          ${s.auth.api_key ? html`<form id="key" style="display:flex;gap:8px"><input type="password" name="key" placeholder="Use the API key in this browser instead of signing in" value="${getKey()}" style="flex:1">
          <button class="btn">Save</button></form>` : ""}</div>
      </div>
    </div>
    <div class="card" style="margin-top:16px"><div class="card-head"><h2>Recent jobs</h2></div>
      ${table([
        { label: "Job", render: (j) => html`<b>${j.kind.replace("_", " ")}</b> <span class="muted small">${j.target || ""}</span>` },
        { label: "Trigger", key: "trigger" },
        { label: "Status", render: (j) => html`<span class="status-dot ${j.status === "success" ? "ok" : j.status === "failed" ? "error" : "running"}"></span>${j.status}` },
        { label: "Started", render: (j) => ago(j.started_at), cls: "nowrap" },
        { label: "Result", render: (j) => html`<span class="small">${j.message}</span>${Object.keys(j.stats?.errors || {}).length ? html`<div class="cell-sub">source errors: ${Object.keys(j.stats.errors).join(", ")}</div>` : ""}` },
      ], jobs.items, { empty: "No jobs have run yet." })}</div>
    ${canAdmin ? html`<div class="card" style="margin-top:16px" id="users-card"><div class="card-head"><h2>Users</h2>
        <button class="btn btn-primary btn-sm" id="user-add" type="button">Add user</button></div>
      ${table([
        { label: "User", render: (u) => html`<b>${u.username}</b>${me.user?.id === u.id ? html` <span class="muted small">(you)</span>` : ""}` },
        { label: "Role", render: (u) => html`<select data-role="${u.id}" aria-label="Role for ${u.username}">${["admin", "analyst", "viewer"].map((r) =>
            html`<option value="${r}" ${u.role === r ? "selected" : ""}>${r}</option>`)}</select>` },
        { label: "Status", render: (u) => u.disabled ? chip("disabled", "chip-bad") : chip("active", "chip-ok") },
        { label: "Last sign-in", render: (u) => ago(u.last_login_at), cls: "nowrap" },
        { label: "", cls: "nowrap", render: (u) => html`
            <button class="btn btn-sm" data-act="reset" data-id="${u.id}" type="button">Reset password</button>
            <button class="btn btn-sm" data-act="${u.disabled ? "enable" : "disable"}" data-id="${u.id}" type="button">${u.disabled ? "Enable" : "Disable"}</button>
            <button class="btn btn-sm btn-danger" data-act="delete" data-id="${u.id}" type="button">Delete</button>` },
      ], users, { empty: "No users yet." })}
      <p class="small muted">${Object.entries(ROLE_HELP).map(([r, d]) => html`<b>${r}</b>: ${d}. `)}</p></div>` : ""}`);
  const rerender = () => render(main);
  $("#key")?.addEventListener("submit", (e) => {
    e.preventDefault();
    setKey(new FormData(e.target).get("key").trim());
    toast("API key saved in this browser", "ok");
  });

  $("#pw-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    if (fd.get("new_password") !== fd.get("confirm")) return toast("The new passwords do not match", "error");
    try {
      const res = await api("/auth/password", { method: "POST", body: { current_password: fd.get("current_password"), new_password: fd.get("new_password") } });
      if (res.token) setToken(res.token);  // adopt the freshly issued token
      toast("Password changed", "ok");
      rerender();
    } catch (err) { toast(err.message, "error"); }
  });

  if (!canAdmin) return;
  const userById = Object.fromEntries(users.map((u) => [u.id, u]));
  const patch = async (id, body, msg) => {
    try { await api(`/users/${id}`, { method: "PATCH", body }); toast(msg, "ok"); } catch (err) { toast(err.message, "error"); }
    rerender();
  };

  $$("select[data-role]", main).forEach((sel) => sel.addEventListener("change", () =>
    patch(sel.dataset.role, { role: sel.value }, `${userById[sel.dataset.role].username} is now ${sel.value}`)));

  $("#users-card").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    const u = userById[b.dataset.id];
    if (b.dataset.act === "disable") return patch(u.id, { disabled: true }, `${u.username} disabled and signed out`);
    if (b.dataset.act === "enable") return patch(u.id, { disabled: false }, `${u.username} enabled`);
    if (b.dataset.act === "delete") {
      if (!confirm(`Delete user ${u.username}? This cannot be undone.`)) return;
      try { await api(`/users/${u.id}`, { method: "DELETE" }); toast(`${u.username} deleted`, "ok"); } catch (err) { toast(err.message, "error"); }
      return rerender();
    }
    if (b.dataset.act === "reset") {
      const body = openModal(`Reset password: ${u.username}`, html`<form id="reset-form">
        <label class="field"><span>New password</span><input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
        <p class="small muted">The user is signed out everywhere and must use the new password.</p>
        <div class="modal-foot"><button class="btn btn-primary">Set password</button></div></form>`);
      $("input", body).focus();
      $("#reset-form").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        try {
          await api(`/users/${u.id}`, { method: "PATCH", body: { password: new FormData(ev.target).get("password") } });
          closeModal();
          toast(`Password reset for ${u.username}`, "ok");
        } catch (err) { toast(err.message, "error"); }
      });
    }
  });

  $("#user-add").addEventListener("click", () => {
    const body = openModal("Add user", html`<form id="add-user-form">
      <label class="field"><span>Username</span><input name="username" required maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false"></label>
      <label class="field"><span>Initial password</span><input name="password" type="password" required minlength="10" autocomplete="new-password">
        <small class="muted">At least 10 characters. Share it securely; they can change it under Settings.</small></label>
      <label class="field"><span>Role</span><select name="role">${Object.entries(ROLE_HELP).map(([r, d]) =>
        html`<option value="${r}" ${r === "analyst" ? "selected" : ""}>${r}: ${d}</option>`)}</select></label>
      <div class="modal-foot"><button class="btn btn-primary">Create user</button></div></form>`);
    $("input", body).focus();
    $("#add-user-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      try {
        await api("/users", { method: "POST", body: Object.fromEntries(fd) });
        closeModal();
        toast(`User ${fd.get("username")} created`, "ok");
        rerender();
      } catch (err) { toast(err.message, "error"); }
    });
  });
}
