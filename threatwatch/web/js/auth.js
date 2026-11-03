// Sign-in and first-run setup screens, plus the signed-in user box in the sidebar.
import { api } from "./api.js";
import { $, html, mount } from "./ui.js";

/** Last /auth/me response: { authenticated, mode, user, setup_required, api_key_configured }. */
export let me = null;

export async function refreshMe() {
  me = await api("/auth/me");
  return me;
}

export const authScreenVisible = () => !$("#auth-screen").hidden;

const LOGO = html`<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)"/><circle cx="16" cy="15" r="5" fill="none" stroke="#fff" stroke-width="2.5"/></svg>`;

/**
 * Replace the app with a sign-in (or first-admin setup) card. Resolves once the user is signed in.
 * @param {{setup?: boolean, apiKeyConfigured?: boolean, message?: string}} opts
 */
export function showAuthScreen({ setup = false, apiKeyConfigured = false, message = "" } = {}) {
  return new Promise((resolve) => {
    const screen = $("#auth-screen");
    $(".shell").hidden = true;
    screen.hidden = false;
    mount(screen, html`
      <div class="auth-card card">
        <div class="auth-brand">${LOGO}<span>ThreatWatch</span></div>
        <h1>${setup ? "Create the admin account" : "Sign in"}</h1>
        <p class="muted small">${setup
          ? "No user accounts exist yet. The account you create here becomes the first administrator; add more people later under Settings."
          : "Sign in to continue."}</p>
        <form id="auth-form" novalidate>
          <label class="field"><span>Username</span>
            <input name="username" required autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64"></label>
          <label class="field"><span>Password</span>
            <input name="password" type="password" required autocomplete="${setup ? "new-password" : "current-password"}" maxlength="1024"
              ${setup ? html`minlength="10" aria-describedby="pw-hint"` : ""}>
            ${setup ? html`<small id="pw-hint" class="muted">At least 10 characters.</small>` : ""}</label>
          ${setup ? html`<label class="field"><span>Confirm password</span>
            <input name="confirm" type="password" required autocomplete="new-password" maxlength="1024"></label>` : ""}
          ${setup && apiKeyConfigured ? html`<label class="field"><span>API key (<code>TW_API_KEY</code>)</span>
            <input name="apikey" type="password" required autocomplete="off">
            <small class="muted">Required because this instance has an API key: it proves you administer the server.</small></label>` : ""}
          <p class="auth-error" id="auth-error" role="alert" ${message ? "" : "hidden"}>${message}</p>
          <button class="btn btn-primary auth-submit" type="submit">${setup ? "Create account and sign in" : "Sign in"}</button>
        </form>
        ${setup ? html`<p class="muted small auth-foot">Prefer the command line? <code>threatwatch user add &lt;name&gt; --role admin</code></p>` : ""}
      </div>`);
    const form = $("#auth-form");
    const err = $("#auth-error");
    const showErr = (m) => { err.textContent = m; err.hidden = false; };
    $("input", form).focus();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const username = String(fd.get("username") || "").trim();
      const password = String(fd.get("password") || "");
      if (!username || !password) return showErr("Enter a username and password.");
      if (setup && password.length < 10) return showErr("The password must be at least 10 characters.");
      if (setup && password !== fd.get("confirm")) return showErr("The passwords do not match.");
      const btn = $(".auth-submit", form);
      btn.disabled = true;
      try {
        const headers = setup && apiKeyConfigured ? { "X-API-Key": String(fd.get("apikey") || "") } : {};
        await api(setup ? "/auth/setup" : "/auth/login", { method: "POST", body: { username, password }, headers });
        await refreshMe();
        hideAuthScreen();
        resolve(me);
      } catch (ex) {
        showErr(ex.message || "Sign-in failed.");
        btn.disabled = false;
        if (!setup) { form.password.value = ""; form.password.focus(); }
      }
    });
  });
}

export function hideAuthScreen() {
  const screen = $("#auth-screen");
  screen.hidden = true;
  mount(screen, "");
  $(".shell").hidden = false;
  renderUserBox();
}

export function renderUserBox() {
  const box = $("#user-box");
  if (me?.mode === "session" && me.user) {
    box.hidden = false;
    mount($("#user-name"), html`<b>${me.user.username}</b> <span class="muted">· ${me.user.role}</span>`);
  } else {
    box.hidden = true;
  }
}

export async function signOut() {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* already signed out */ }
  location.reload();
}

/** Make sure someone is signed in; shows the right screen if not. Resolves when the app may load. */
export async function ensureSignedIn(message = "") {
  await refreshMe();
  if (me.mode === "session" || me.mode === "api_key") { renderUserBox(); return me; }
  // "open" = no users and no API key yet; null = credentials needed
  if (me.setup_required) return showAuthScreen({ setup: true, apiKeyConfigured: me.api_key_configured, message });
  return showAuthScreen({ message });
}
