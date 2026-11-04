// Thin fetch wrapper. The browser authenticates with a JWT obtained at sign-in and sent as
// `Authorization: Bearer <token>`; the token is kept in localStorage. An API key saved in this browser is
// still honoured for instances that use TW_API_KEY only.
//
// Note: unlike the old HttpOnly session cookie, a JWT in localStorage is readable by JavaScript, so a
// cross-site-scripting bug could exfiltrate it. That is the standard trade-off of bearer-token auth.

const KEY_STORAGE = "tw.apiKey";
const TOKEN_STORAGE = "tw.token";

export function getKey() {
  try { return localStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
}
export function setKey(k) {
  try { k ? localStorage.setItem(KEY_STORAGE, k) : localStorage.removeItem(KEY_STORAGE); } catch { /* private mode */ }
}
export function getToken() {
  try { return localStorage.getItem(TOKEN_STORAGE) || ""; } catch { return ""; }
}
export function setToken(t) {
  try { t ? localStorage.setItem(TOKEN_STORAGE, t) : localStorage.removeItem(TOKEN_STORAGE); } catch { /* private mode */ }
}

export class ApiError extends Error {
  constructor(status, detail) { super(detail || `HTTP ${status}`); this.status = status; }
}

function qs(params = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, v);
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export async function api(path, { method = "GET", body, params, form, headers: extra = {} } = {}) {
  const headers = { ...extra };
  const token = getToken();
  const key = getKey();
  // A JWT wins; fall back to a saved API key. Caller-supplied Authorization (e.g. setup) is left untouched.
  if (!("Authorization" in headers)) {
    if (token) headers["Authorization"] = `Bearer ${token}`;
    else if (key) headers["X-API-Key"] = key;
  }
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(`/api/v1${path}${qs(params)}`, { method, headers, body: payload });
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("tw:auth-required"));
    throw new ApiError(401, "Sign-in required");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* not JSON */ }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

/** URL for downloads/links opened by the browser directly. A plain link cannot carry an Authorization
 *  header, so the JWT (or a saved API key) is passed as a query parameter the server also accepts. */
export function href(path, params = {}) {
  const token = getToken();
  const key = getKey();
  const auth = token ? { access_token: token } : (key ? { api_key: key } : {});
  return `/api/v1${path}${qs({ ...params, ...auth })}`;
}
