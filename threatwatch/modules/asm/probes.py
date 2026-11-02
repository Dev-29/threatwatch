"""Active and semi-passive probes: TCP port scan with banner grab, TLS certificate analysis, HTTP fingerprinting."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ...core.domains import is_subdomain_of

# Port -> service name. Covers the services that matter most for external exposure.
PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 4443: "https-alt", 5000: "http-alt", 5432: "postgresql", 5601: "kibana", 5900: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes", 7001: "weblogic",
    8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
}
HTTP_PORTS = {80, 443, 3000, 4443, 5000, 5601, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 15672}

# Fingerprints: (technology, compiled regex, where) - where in {"header", "body", "title", "cookie"}
TECH_SIGNATURES = [
    ("WordPress", r"wp-content|wp-includes", "body"), ("Drupal", r"Drupal|drupal-settings-json", "body"),
    ("Joomla", r"/media/jui/|Joomla!", "body"), ("Magento", r"Mage\.Cookies|/static/frontend/", "body"),
    ("Shopify", r"cdn\.shopify\.com", "body"), ("Next.js", r"__NEXT_DATA__|/_next/static", "body"),
    ("React", r"data-reactroot|react-dom", "body"), ("Angular", r"ng-version=", "body"),
    ("Vue.js", r"data-v-[0-9a-f]{8}|__vue__", "body"), ("jQuery", r"jquery[.-]?\d", "body"),
    ("Jenkins", r"X-Jenkins|Jenkins", "header"), ("Grafana", r"Grafana", "title"), ("Kibana", r"Kibana", "title"),
    ("GitLab", r"GitLab", "title"), ("phpMyAdmin", r"phpMyAdmin", "title"), ("Apache Tomcat", r"Apache Tomcat", "title"),
    ("Confluence", r"Confluence", "title"), ("Jira", r"Jira|JIRA", "title"), ("SonarQube", r"SonarQube", "title"),
    ("Outlook Web App", r"Outlook Web App|owa/auth", "body"), ("Citrix Gateway", r"Citrix Gateway|NetScaler", "body"),
    ("Fortinet FortiGate", r"fortinet|FortiGate|/remote/login", "body"),
    ("Ivanti Connect Secure", r"Pulse Secure|Ivanti|dana-na", "body"),
    ("Palo Alto GlobalProtect", r"GlobalProtect", "body"), ("Cisco ASA", r"webvpn|CSCOE", "body"),
    ("SonicWall", r"SonicWall|sonicui", "body"), ("F5 BIG-IP", r"BIG-IP|F5 Networks", "body"),
    ("VMware", r"VMware|vSphere|Horizon", "title"), ("Microsoft IIS", r"Microsoft-IIS", "header"),
    ("nginx", r"nginx", "header"), ("Apache httpd", r"Apache(?!-Coyote)", "header"), ("Cloudflare", r"cloudflare", "header"),
    ("Amazon CloudFront", r"CloudFront", "header"), ("Akamai", r"AkamaiGHost|akamai", "header"),
    ("PHP", r"PHP/\d|PHPSESSID", "header"), ("ASP.NET", r"ASP\.NET|X-AspNet", "header"),
    ("Express", r"Express", "header"), ("Elasticsearch", r"\"cluster_name\"|You Know, for Search", "body"),
    ("Webmin", r"Webmin", "title"), ("RabbitMQ", r"RabbitMQ", "title"), ("Swagger UI", r"swagger-ui", "body"),
]
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy"]
# Checked in order: more specific names first ("AKAMAI-LINODE" is Linode compute, not the Akamai CDN).
CDN_ORGS = {"linode": "Linode/Akamai", "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "amazon": "AWS",
            "google": "Google Cloud", "microsoft": "Azure", "incapsula": "Imperva", "digitalocean": "DigitalOcean",
            "ovh": "OVH", "hetzner": "Hetzner", "github": "GitHub", "vercel": "Vercel",
            "netlify": "Netlify", "oracle": "Oracle Cloud"}


def hosting_from_org(org: str | None) -> str | None:
    o = (org or "").lower()
    return next((v for k, v in CDN_ORGS.items() if k in o), None)


# ------------------------------------------------------------------ port scan
async def _probe_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    banner = ""
    if port not in HTTP_PORTS and port not in (443, 465, 636, 993, 995, 8443, 4443, 5986, 2376):
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=2.0)
            banner = data.decode(errors="replace").strip().replace("\r", " ").replace("\n", " ")[:200]
        except (OSError, asyncio.TimeoutError):
            pass
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return {"port": port, "service": PORTS.get(port, "unknown"), "banner": banner}


async def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 1.5,
                     sem: asyncio.Semaphore | None = None) -> list[dict]:
    sem = sem or asyncio.Semaphore(200)

    async def one(p):
        async with sem:
            return await _probe_port(ip, p, timeout)

    res = await asyncio.gather(*(one(p) for p in (ports or list(PORTS))))
    return sorted([r for r in res if r], key=lambda r: r["port"])


# ------------------------------------------------------------------ TLS
def _get_cert(host: str, port: int, timeout: float) -> dict:
    out: dict = {"port": port}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
            out["protocol"] = ss.version()
            out["cipher"] = (ss.cipher() or [None])[0]
    # chain validation with the system trust store
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                out["trusted"], out["verify_error"] = True, None
    except ssl.SSLCertVerificationError as exc:
        out["trusted"], out["verify_error"] = False, exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        out["trusted"], out["verify_error"] = None, str(exc)[:200]
    out.update(parse_cert(der, host))
    return out


def parse_cert(der: bytes, host: str | None = None) -> dict:
    cert = x509.load_der_x509_certificate(der)

    def cn(name):
        try:
            return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            return name.rfc4514_string()

    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    pub = cert.public_key()
    key_type, key_bits = "unknown", None
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.curve.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pub.key_size
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"
    names = [n.lower() for n in sans] or [str(cn(cert.subject)).lower()]
    matches = None
    if host:
        matches = any(n == host or (n.startswith("*.") and is_subdomain_of(host, n[2:]) and host.count(".") == n.count("."))
                      for n in names)
    return {
        "subject_cn": str(cn(cert.subject)), "issuer_cn": str(cn(cert.issuer)),
        "issuer": cert.issuer.rfc4514_string(), "sans": sans[:100],
        "not_before": cert.not_valid_before_utc.isoformat(), "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "self_signed": cert.issuer == cert.subject, "key_type": key_type, "key_bits": key_bits,
        "signature_hash": sig_hash, "serial": format(cert.serial_number, "x"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(), "sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "hostname_match": matches,
    }


def _legacy_protocols(host: str, port: int, timeout: float) -> list[str]:
    supported = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    supported.append(name)
        except (ssl.SSLError, OSError):
            pass
    return supported


async def tls_info(host: str, port: int = 443, timeout: float = 6.0, legacy: bool = True) -> dict:
    try:
        info = await asyncio.to_thread(_get_cert, host, port, timeout)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"port": port, "error": f"{type(exc).__name__}: {exc}"[:200]}
    if legacy:
        info["legacy_protocols"] = await asyncio.to_thread(_legacy_protocols, host, port, timeout)
    return info


# ------------------------------------------------------------------ HTTP
def fingerprint(headers: dict, body: str, title: str, cookies: str = "") -> list[str]:
    hdr = "\n".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for tech, pattern, where in TECH_SIGNATURES:
        hay = {"header": hdr + cookies, "body": body[:200000], "title": title, "cookie": cookies}[where]
        if re.search(pattern, hay):
            found.append(tech)
    return found


async def http_probe(c: httpx.AsyncClient, host: str, port: int | None = None) -> dict:
    """Probe https then http. Returns status, title, headers of interest, redirect info and technologies."""
    schemes = [("https", port or 443), ("http", port or 80)] if port in (None, 443, 80) else \
        [("https" if port in (443, 4443, 8443) else "http", port)]
    result: dict = {}
    for scheme, p in schemes:
        default = (scheme == "https" and p == 443) or (scheme == "http" and p == 80)
        url = f"{scheme}://{host}{'' if default else f':{p}'}/"
        try:
            r = await c.get(url)
        except httpx.HTTPError as exc:
            result.setdefault("errors", {})[scheme] = f"{type(exc).__name__}"
            continue
        body = r.text[:300000] if "text" in r.headers.get("content-type", "") or "json" in r.headers.get("content-type", "") else ""
        m = TITLE_RE.search(body)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""
        h = {k.lower(): v for k, v in r.headers.items()}
        entry = {
            "url": url, "status": r.status_code, "final_url": str(r.url), "title": title,
            "server": h.get("server"), "powered_by": h.get("x-powered-by"),
            "security_headers": {k: (k in h) for k in SECURITY_HEADERS},
            "hsts": h.get("strict-transport-security"),
            "redirects_to_https": str(r.url).startswith("https://"),
            "technologies": fingerprint(h, body, title, h.get("set-cookie", "")),
            "directory_listing": bool(re.search(r"<title>Index of /", body, re.I)),
            "login_form": bool(re.search(r"type=[\"']?password", body, re.I)),
            "content_length": len(r.content),
        }
        result[scheme] = entry
        if scheme == "https":
            break  # https works; http only probed separately for redirect check below
    if "https" in result:
        try:
            r = await c.get(f"http://{host}/", follow_redirects=False)
            loc = r.headers.get("location", "")
            result["http_redirects_to_https"] = r.status_code in (301, 302, 307, 308) and loc.startswith("https://")
            result["http_status"] = r.status_code
        except httpx.HTTPError:
            result["http_redirects_to_https"] = None
    return result


SENSITIVE_PATHS = [
    ("/.git/HEAD", re.compile(r"^ref: refs/|^[0-9a-f]{40}\s*$", re.M), "git", "critical"),
    ("/.env", re.compile(r"^(APP_KEY|DB_PASSWORD|DATABASE_URL|AWS_SECRET|SECRET_KEY|API_KEY)\s*=", re.M), "env", "critical"),
    ("/server-status", re.compile(r"Apache Server Status", re.I), "server-status", "medium"),
    ("/phpinfo.php", re.compile(r"<title>phpinfo\(\)</title>|PHP Version", re.I), "phpinfo", "medium"),
    ("/actuator/env", re.compile(r"\"activeProfiles\"|\"propertySources\""), "actuator", "high"),
    ("/.DS_Store", re.compile(r"Bud1"), "ds_store", "low"),
    ("/swagger-ui.html", re.compile(r"swagger-ui", re.I), "swagger", "low"),
]


async def sensitive_paths(c: httpx.AsyncClient, base_url: str) -> list[dict]:
    """Request a few well-known sensitive paths; only report when the *content* confirms exposure."""
    out = []
    for path, pattern, key, sev in SENSITIVE_PATHS:
        try:
            r = await c.get(base_url.rstrip("/") + path, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and pattern.search(r.text[:20000]):
            out.append({"path": path, "key": key, "severity": sev, "evidence": r.text[:120].replace("\n", " ")})
    return out
