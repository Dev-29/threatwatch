"""ASM finding rules. Each rule turns observed facts about an asset into zero or more findings.

A finding is a dict: {hostname, category, check_id, severity, title, description, evidence,
remediation, attack_techniques}. Rules are pure functions so they are easy to unit test.
"""

from __future__ import annotations

import re

# port -> (severity, title, remediation, techniques)
RISKY_PORTS = {
    23: ("high", "Telnet exposed to the Internet", "Disable Telnet; use SSH with key authentication.", ["T1133", "T1110", "T1557"]),
    21: ("medium", "FTP exposed to the Internet", "Replace FTP with SFTP/FTPS or restrict by IP allow-list.", ["T1133", "T1557"]),
    445: ("critical", "SMB exposed to the Internet", "Block TCP/445 at the perimeter; SMB must never be Internet-facing.", ["T1210", "T1190"]),
    139: ("high", "NetBIOS exposed to the Internet", "Block NetBIOS at the perimeter.", ["T1210"]),
    135: ("high", "MS-RPC exposed to the Internet", "Block TCP/135 at the perimeter.", ["T1210"]),
    3389: ("high", "RDP exposed to the Internet", "Put RDP behind a VPN / RD Gateway with MFA; enable NLA.", ["T1133", "T1021.001", "T1110"]),
    5900: ("high", "VNC exposed to the Internet", "Restrict VNC to a VPN; enforce strong authentication.", ["T1133", "T1219"]),
    5985: ("high", "WinRM (HTTP) exposed to the Internet", "Restrict WinRM to management networks.", ["T1133"]),
    5986: ("medium", "WinRM (HTTPS) exposed to the Internet", "Restrict WinRM to management networks.", ["T1133"]),
    3306: ("high", "MySQL database exposed to the Internet", "Bind the database to private interfaces / firewall it.", ["T1190", "T1110"]),
    5432: ("high", "PostgreSQL database exposed to the Internet", "Bind the database to private interfaces / firewall it.", ["T1190", "T1110"]),
    1433: ("high", "MS SQL Server exposed to the Internet", "Firewall TCP/1433; never expose SQL Server publicly.", ["T1190", "T1110"]),
    1521: ("high", "Oracle DB listener exposed to the Internet", "Firewall the Oracle listener.", ["T1190"]),
    27017: ("critical", "MongoDB exposed to the Internet", "Enable auth and firewall TCP/27017.", ["T1190", "T1530"]),
    6379: ("critical", "Redis exposed to the Internet", "Bind Redis to localhost/private network and require AUTH.", ["T1190"]),
    9200: ("critical", "Elasticsearch exposed to the Internet", "Enable security features and firewall TCP/9200.", ["T1190", "T1530"]),
    9300: ("high", "Elasticsearch transport port exposed", "Firewall TCP/9300.", ["T1190"]),
    5984: ("high", "CouchDB exposed to the Internet", "Firewall CouchDB; require authentication.", ["T1190"]),
    11211: ("high", "Memcached exposed to the Internet", "Firewall memcached (also a DDoS amplification vector).", ["T1498"]),
    2375: ("critical", "Docker API (unauthenticated) exposed", "Never expose the Docker socket; use TLS mutual auth.", ["T1190", "T1496"]),
    2376: ("medium", "Docker API (TLS) exposed", "Restrict the Docker API to management networks.", ["T1190"]),
    6443: ("medium", "Kubernetes API server exposed", "Restrict API server access by IP; verify RBAC/anonymous auth.", ["T1190"]),
    10250: ("high", "Kubelet API exposed", "Firewall the kubelet; disable anonymous auth.", ["T1190"]),
    111: ("medium", "RPCbind exposed", "Firewall portmapper.", ["T1046"]),
    2049: ("high", "NFS exposed to the Internet", "Firewall NFS.", ["T1530"]),
    389: ("high", "LDAP exposed to the Internet", "Firewall LDAP; it leaks directory data and enables brute force.", ["T1190", "T1110"]),
    1723: ("medium", "PPTP VPN exposed (broken protocol)", "Migrate off PPTP to IPsec/WireGuard/SSL VPN.", ["T1133"]),
    10000: ("medium", "Webmin exposed", "Restrict admin interfaces to VPN.", ["T1190"]),
    7001: ("medium", "WebLogic admin port exposed", "Restrict WebLogic administration to internal networks.", ["T1190"]),
    15672: ("medium", "RabbitMQ management UI exposed", "Restrict to internal networks.", ["T1190"]),
    5601: ("medium", "Kibana exposed", "Place Kibana behind SSO/VPN.", ["T1190"]),
    22: ("info", "SSH exposed to the Internet", "Ensure key-only auth, disable root login, consider IP allow-listing.", ["T1133", "T1110"]),
}

ADMIN_TECH = {"Jenkins", "Grafana", "Kibana", "phpMyAdmin", "Apache Tomcat", "SonarQube", "Webmin", "RabbitMQ",
              "GitLab", "Swagger UI"}
EDGE_TECH = {"Citrix Gateway", "Fortinet FortiGate", "Ivanti Connect Secure", "Palo Alto GlobalProtect", "Cisco ASA",
             "SonicWall", "F5 BIG-IP", "Outlook Web App", "VMware", "Confluence", "Jira"}
# technology -> KEV vendorProject/product keywords
TECH_TO_KEV = {
    "Citrix Gateway": ("citrix", None), "Fortinet FortiGate": ("fortinet", "forti"), "Ivanti Connect Secure": ("ivanti", None),
    "Palo Alto GlobalProtect": ("palo alto", "pan-os"), "Cisco ASA": ("cisco", "adaptive security"),
    "SonicWall": ("sonicwall", None), "F5 BIG-IP": ("f5", "big-ip"), "Outlook Web App": ("microsoft", "exchange"),
    "Confluence": ("atlassian", "confluence"), "Jira": ("atlassian", "jira"), "VMware": ("vmware", None),
    "Apache Tomcat": ("apache", "tomcat"), "Jenkins": ("jenkins", None), "GitLab": ("gitlab", None),
    "Drupal": ("drupal", None), "WordPress": ("wordpress", None), "Magento": ("magento", None),
}
NONPROD = re.compile(r"(^|[.-])(dev|develop|development|staging|stage|stg|test|testing|uat|qa|preprod|sandbox|demo|"
                     r"old|legacy|backup|bak|tmp|temp|internal|lab)\d*([.-]|$)")

TAKEOVER_FINGERPRINTS = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"), ("herokudns.com", "No such app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"), ("s3-website", "NoSuchBucket", "AWS S3"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("wordpress.com", "Do you want to register", "WordPress.com"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("surge.sh", "project not found", "Surge"), ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"), ("readme.io", "Project doesnt exist", "ReadMe"),
    ("zendesk.com", "Help Center Closed", "Zendesk"), ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("helpscoutdocs.com", "No settings were found for this company", "HelpScout"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service"),
]
CLAIMABLE_SUFFIXES = ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
                      "blob.core.windows.net", "azureedge.net", "s3.amazonaws.com", "elasticbeanstalk.com",
                      "herokuapp.com", "github.io", "netlify.app", "vercel.app", "pages.dev")


def F(hostname, category, check_id, severity, title, description="", evidence="", remediation="", techniques=None):
    return {"hostname": hostname, "category": category, "check_id": check_id, "severity": severity, "title": title,
            "description": description, "evidence": str(evidence)[:1000], "remediation": remediation,
            "attack_techniques": techniques or []}


def check_ports(host: str, ports: list[dict]) -> list[dict]:
    out = []
    for p in ports:
        rule = RISKY_PORTS.get(p["port"])
        if rule:
            sev, title, rem, techs = rule
            out.append(F(host, "exposure", f"port-{p['port']}", sev, f"{title} (tcp/{p['port']})",
                         f"Service {p['service']} is reachable from the Internet.", p.get("banner") or "",
                         rem, techs))
    return out


def check_tls(host: str, tls: dict) -> list[dict]:
    if not tls or tls.get("error"):
        return []
    out = []
    days = tls.get("days_left")
    ev = f"CN={tls.get('subject_cn')} issuer={tls.get('issuer_cn')} expires={str(tls.get('not_after'))[:10]}"
    if days is not None and days < 0:
        out.append(F(host, "tls", "tls-expired", "high", "TLS certificate expired",
                     f"The certificate expired {-days} days ago; browsers show interstitial warnings.", ev,
                     "Renew the certificate and automate renewal (ACME).", ["T1557"]))
    elif days is not None and days < 14:
        out.append(F(host, "tls", "tls-expiring", "medium", f"TLS certificate expires in {days} days", "", ev,
                     "Renew the certificate; automate renewal."))
    elif days is not None and days < 30:
        out.append(F(host, "tls", "tls-expiring-soon", "low", f"TLS certificate expires in {days} days", "", ev,
                     "Plan renewal."))
    if tls.get("self_signed"):
        out.append(F(host, "tls", "tls-self-signed", "medium", "Self-signed TLS certificate", "", ev,
                     "Use a certificate from a publicly trusted CA.", ["T1557"]))
    elif tls.get("trusted") is False and "hostname" not in (tls.get("verify_error") or "").lower():
        out.append(F(host, "tls", "tls-untrusted", "medium", "TLS certificate chain not trusted",
                     tls.get("verify_error") or "", ev, "Serve the full chain from a trusted CA.", ["T1557"]))
    if tls.get("hostname_match") is False:
        out.append(F(host, "tls", "tls-hostname-mismatch", "medium", "TLS certificate does not match hostname",
                     f"Certificate names: {', '.join((tls.get('sans') or [])[:5])}", ev,
                     "Issue a certificate covering this hostname.", ["T1557"]))
    legacy = tls.get("legacy_protocols") or []
    if legacy:
        out.append(F(host, "tls", "tls-legacy-protocol", "medium" if "TLSv1.0" in legacy else "low",
                     f"Deprecated protocol(s) enabled: {', '.join(legacy)}", "TLS 1.0/1.1 are deprecated (RFC 8996).",
                     ", ".join(legacy), "Disable TLS 1.0 and 1.1; support TLS 1.2+ only.", ["T1557"]))
    if tls.get("key_type") == "RSA" and (tls.get("key_bits") or 4096) < 2048:
        out.append(F(host, "tls", "tls-weak-key", "medium", f"Weak RSA key ({tls.get('key_bits')} bits)", "", ev,
                     "Use RSA >= 2048 bits or ECDSA P-256."))
    if tls.get("signature_hash") in ("sha1", "md5"):
        out.append(F(host, "tls", "tls-weak-signature", "medium", f"Certificate signed with {tls['signature_hash'].upper()}",
                     "", ev, "Re-issue with SHA-256."))
    return out


def check_http(host: str, http: dict, kev_products: list[dict] | None = None) -> list[dict]:
    out = []
    https, plain = http.get("https"), http.get("http")
    main = https or plain
    if not main:
        return out
    if plain and not https:
        out.append(F(host, "web", "web-no-https", "medium", "Website served over plain HTTP only",
                     "Traffic, cookies and credentials can be intercepted.", plain.get("url"),
                     "Serve over HTTPS and redirect HTTP to HTTPS.", ["T1557"]))
    if https and http.get("http_redirects_to_https") is False and http.get("http_status"):
        out.append(F(host, "web", "web-no-redirect", "low", "HTTP does not redirect to HTTPS", "",
                     f"http:// returned {http.get('http_status')}", "Add a 301 redirect to HTTPS."))
    if https and not (https.get("security_headers") or {}).get("strict-transport-security"):
        out.append(F(host, "web", "web-no-hsts", "low", "HSTS header missing", "", https.get("url"),
                     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    sh = main.get("security_headers") or {}
    missing = [h for h in ("content-security-policy", "x-frame-options", "x-content-type-options") if not sh.get(h)]
    if missing and main.get("status", 0) < 400:
        out.append(F(host, "web", "web-headers", "info", "Missing security headers", ", ".join(missing), main.get("url"),
                     "Add CSP, X-Frame-Options (or frame-ancestors) and X-Content-Type-Options: nosniff."))
    server = " ".join(x for x in (main.get("server"), main.get("powered_by")) if x)
    if re.search(r"\d+\.\d+", server):
        out.append(F(host, "web", "web-version-disclosure", "low", "Server version disclosed in headers", "", server,
                     "Suppress version banners (ServerTokens Prod / server_tokens off / remove X-Powered-By)."))
    if main.get("directory_listing"):
        out.append(F(host, "web", "web-dir-listing", "medium", "Directory listing enabled", "", main.get("url"),
                     "Disable autoindex / directory browsing.", ["T1593"]))
    techs = set(main.get("technologies") or [])
    for t in sorted(techs & ADMIN_TECH):
        out.append(F(host, "exposure", f"admin-{t.lower().replace(' ', '-')}", "medium",
                     f"{t} interface exposed to the Internet", main.get("title") or "", main.get("url"),
                     "Restrict administrative interfaces to VPN / SSO and IP allow-lists.", ["T1190", "T1133"]))
    for t in sorted(techs & EDGE_TECH):
        out.append(F(host, "exposure", f"edge-{t.lower().replace(' ', '-')}", "info",
                     f"{t} (high-value edge appliance / app) identified", "Frequently targeted by initial-access brokers.",
                     main.get("url"), "Keep fully patched; monitor vendor advisories; enforce MFA.", ["T1190", "T1133"]))
    for t in sorted(techs):
        if t in TECH_TO_KEV and kev_products:
            vendor, product = TECH_TO_KEV[t]
            hits = [k for k in kev_products if vendor in (k.get("vendor") or "").lower()
                    and (product is None or product in (k.get("product") or "").lower())]
            if hits:
                cves = ", ".join(sorted({h['cve'] for h in hits})[-8:])
                out.append(F(host, "intel", f"kev-{t.lower().replace(' ', '-')}", "high" if t in EDGE_TECH else "medium",
                             f"{t} has {len(hits)} actively exploited CVEs (CISA KEV)",
                             "Verify this instance is patched against all known exploited vulnerabilities.",
                             cves, "Patch to the latest version; review CISA KEV required actions.", ["T1190"]))
    return out


def check_sensitive(host: str, hits: list[dict]) -> list[dict]:
    titles = {"git": "Git repository exposed (/.git/)", "env": "Environment file with secrets exposed (/.env)",
              "server-status": "Apache server-status page exposed", "phpinfo": "phpinfo() page exposed",
              "actuator": "Spring Boot actuator /env exposed", "ds_store": ".DS_Store file exposed",
              "swagger": "API documentation (Swagger UI) exposed"}
    return [F(host, "exposure", f"path-{h['key']}", h["severity"], titles.get(h["key"], h["path"]),
              "Confirmed by content match, not just HTTP status.", f"{h['path']}: {h['evidence']}",
              "Remove the file or block the path at the web server / WAF; rotate any exposed secrets.",
              ["T1552.001", "T1593"]) for h in hits]


def check_takeover(host: str, cname: str | None, cname_resolves: bool | None, body: str = "") -> list[dict]:
    if not cname:
        return []
    out = []
    for suffix, fp, service in TAKEOVER_FINGERPRINTS:
        if suffix in cname and fp.lower() in (body or "").lower():
            return [F(host, "takeover", "takeover-fingerprint", "high", f"Possible sub-domain takeover ({service})",
                      f"{host} is a CNAME to {cname}, which returns the '{service}' unclaimed-resource page.",
                      f"CNAME {cname}; body contains '{fp}'",
                      "Remove the DNS record or re-claim the resource on the provider.", ["T1584.001"])]
    if cname_resolves is False:
        claimable = any(cname.endswith(s) for s in CLAIMABLE_SUFFIXES)
        out.append(F(host, "takeover", "dangling-cname", "high" if claimable else "medium",
                     "Dangling CNAME (target does not resolve)",
                     f"{host} points to {cname}, which returns NXDOMAIN. "
                     + ("The target is on a provider where names can be registered by anyone." if claimable else ""),
                     f"CNAME {cname} -> NXDOMAIN", "Delete the stale DNS record.", ["T1584.001"]))
    return out


def check_nonprod(host: str, root: str, resolved: bool, http: dict) -> list[dict]:
    sub = host[: -len(root) - 1] if host.endswith("." + root) else ""
    if resolved and sub and NONPROD.search(sub) and (http.get("https") or http.get("http")):
        return [F(host, "exposure", "nonprod-exposed", "low", "Non-production environment reachable from the Internet",
                  "Dev/test systems often run outdated code, debug modes and weak credentials.", host,
                  "Restrict non-production environments to VPN / IP allow-lists.", ["T1190"])]
    return []


def check_email(root: str, mx: list[str], spf: list[str], dmarc: list[str]) -> list[dict]:
    out = []
    spf_rec = next((t for t in spf if t.lower().startswith("v=spf1")), None)
    if not spf_rec:
        out.append(F(root, "email", "spf-missing", "medium", "No SPF record",
                     "Anyone can send mail claiming to be from this domain.", "",
                     "Publish an SPF record ending in -all (or ~all while testing).", ["T1566"]))
    elif re.search(r"[+]all\b", spf_rec) or spf_rec.strip().endswith(" all"):
        out.append(F(root, "email", "spf-permissive", "high", "SPF record allows all senders (+all)", "", spf_rec,
                     "Change +all to -all.", ["T1566"]))
    elif "?all" in spf_rec:
        out.append(F(root, "email", "spf-neutral", "low", "SPF record is neutral (?all)", "", spf_rec, "Use -all or ~all."))
    dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    if not dmarc_rec:
        out.append(F(root, "email", "dmarc-missing", "medium", "No DMARC record",
                     "Receivers have no policy for spoofed mail from this domain; exact-domain phishing is easy.", "",
                     "Publish _dmarc TXT 'v=DMARC1; p=quarantine; rua=mailto:...' and progress to p=reject.", ["T1566"]))
    else:
        m = re.search(r"\bp=(\w+)", dmarc_rec, re.I)
        policy = (m.group(1).lower() if m else "none")
        if policy == "none":
            out.append(F(root, "email", "dmarc-none", "low", "DMARC policy is p=none (monitor only)", "", dmarc_rec,
                         "Move to p=quarantine then p=reject once reports are clean.", ["T1566"]))
    if not mx:
        out.append(F(root, "email", "mx-missing", "info", "No MX record", "Domain does not receive mail.", "",
                     "If the domain never sends mail, publish 'v=spf1 -all' and DMARC p=reject."))
    return out


def check_dns(root: str, caa: list[str], ds: list[str], axfr: dict[str, list[str]] | None, wildcard: bool) -> list[dict]:
    out = []
    if axfr:
        for ns, names in axfr.items():
            out.append(F(root, "dns", "dns-axfr", "high", f"DNS zone transfer allowed by {ns}",
                         f"{len(names)} records disclosed - full map of the infrastructure.", ", ".join(names[:15]),
                         "Restrict AXFR to secondary name servers (allow-transfer).", ["T1596"]))
    if not caa:
        out.append(F(root, "dns", "dns-no-caa", "info", "No CAA record", "Any CA may issue certificates for this domain.",
                     "", "Publish CAA records naming your certificate authorities."))
    if not ds:
        out.append(F(root, "dns", "dns-no-dnssec", "info", "DNSSEC not enabled", "", "",
                     "Consider enabling DNSSEC at the registrar and DNS host."))
    if wildcard:
        out.append(F(root, "dns", "dns-wildcard", "info", "Wildcard DNS record present",
                     "Every sub-domain resolves; increases phishing/takeover surface.", "", "Avoid wildcard records if possible."))
    return out


def check_intel(host: str, ips: list[str], hits: list[dict]) -> list[dict]:
    return [F(host, "intel", "intel-listed", "high", f"{h['value']} listed in threat intelligence feeds",
              f"Flagged as {', '.join(h['threat_types']) or 'malicious'} by {', '.join(h['sources'])}. "
              "The host may be compromised or IP reputation may block your mail/web traffic.",
              h["value"], "Investigate the host for compromise; request delisting once clean.", ["T1584"])
            for h in hits]
