// Thin fetch wrapper. The browser authenticates with the HttpOnly session cookie (sent automatically);
// an API key saved in this browser is still honoured for instances that use TW_API_KEY only.

const KEY_STORAGE = "tw.apiKey";

export function getKey() {
  try { return localStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
}
export function setKey(k) {
  try { k ? localStorage.setItem(KEY_STORAGE, k) : localStorage.removeItem(KEY_STORAGE); } catch { /* private mode */ }
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
  // Custom header = CSRF protection: cross-site pages cannot add it without a CORS preflight.
  const headers = { "X-Requested-With": "ThreatWatch", ...extra };
  const key = getKey();
  if (key) headers["X-API-Key"] = key;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(`/api/v1${path}${qs(params)}`, { method, headers, body: payload, credentials: "same-origin" });
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

/** URL for downloads/links opened by the browser directly. The session cookie covers these; a saved API key
 *  (which cannot be sent as a header on a plain link) is added as a query parameter. */
export function href(path, params = {}) {
  const key = getKey();
  return `/api/v1${path}${qs({ ...params, ...(key ? { api_key: key } : {}) })}`;
}
