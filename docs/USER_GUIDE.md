# User guide

- [Concepts](#concepts)
- [Watchlist](#watchlist)
- [Dashboard and alerts](#dashboard-and-alerts)
- [Dark Web Monitoring](#dark-web-monitoring)
- [Threat Intelligence](#threat-intelligence)
- [Anti-Phishing](#anti-phishing)
- [Attack Surface Management](#attack-surface-management)
- [Attack-surface findings](#attack-surface-findings)
- [Suggested operating rhythm](#suggested-operating-rhythm)

## Concepts

- **Watchlist**: the organisation profile. Everything ThreatWatch monitors is derived from it.
- **Score / severity**: every item is scored 0-100 with the factors visible under *Why this score* ([SCORING.md](SCORING.md)).
- **Alert**: created when a *new* item reaches the alert threshold. Alerts are de-duplicated, and re-opened if their subject escalates.
- **Job**: scans and collections run in the background. The sidebar shows running jobs, and you get a toast when one finishes.
- **Status**: every finding type has a triage status, so the team can work through it:

  | Item | Statuses |
  |---|---|
  | Exposures | new → investigating → remediated / false positive |
  | Look-alikes | new → monitoring → takedown requested → taken down / benign |
  | Alerts | open → acknowledged → closed |

## Watchlist

| Type | Enter | Used by |
|---|---|---|
| Domain | Every registered domain you own | Dark web (domain search), look-alike scans, ASM roots, TI "own domain in feed" alerts, URL-analyser brand protection |
| Executive | Full name plus all known emails (corporate *and* personal) and handles | Dark web; scores get an executive bonus (BEC / whaling targets) |
| Email | Admin, finance and shared mailboxes, service accounts | Dark web |
| Brand | Brand and product names (≥ 4 characters) | Phishing URLs in feeds, ransomware-leak matching, URL analyser |
| Keyword | Confidential project names, internal hostnames | Dark web (ransomware.live, IntelX, GitHub, onion) |

**Criticality** multiplies exposure scores: ×1.2 critical, ×1.1 high, ×1.0 medium, ×0.85 low. Untick *Monitoring* to pause an asset without deleting its history.

## Dashboard and alerts

The dashboard shows:

- **KPI tiles**: open alerts, exposures, active IOCs, look-alikes, and the latest ASM grade. Each tile links to its module.
- **Alerts per day**: last 14 days, stacked by severity. Hover for counts.
- Exposures by source, IOCs by type, top ATT&CK techniques and malware families. Rows are clickable filters.

**Alerts** lists every alert with filters by status, severity and module. *Acknowledge shown* / *Close shown* bulk-update the visible page. Set `TW_ALERT_WEBHOOK_URL` to push new alerts to chat.

## Dark Web Monitoring

**Run scan now** queries every available source for every enabled asset. A scan takes 10-60 s depending on the number of assets and keys.

The exposure table is sorted by risk. Each row shows the source type, whether credentials were exposed (and whether in plaintext), the matched identifier and the leak date. Click a row for:

- the full record and exposed data classes,
- the score factors,
- a recommended response tailored to the source type,
- the raw source data (masked).

**Triage guidance**

| Source type | Why it matters | Typical response |
|---|---|---|
| **Infostealer log** | Live session cookies and saved passwords from an infected device, the most common initial-access vector today | Treat the device as compromised: reimage it, reset *all* stored credentials, revoke sessions, check MFA enrolment |
| **Ransomware leak site** | You or a supplier is claimed as a victim | Incident response, legal, supplier management; verify the claim and assess the data |
| **Combo list** | Credentials circulating for credential stuffing | Reset the password, enforce MFA, check for password reuse |
| **Breach** | Third-party service breach containing the address | Old breaches with hashed passwords are low priority; recent ones with plaintext passwords are not |
| **Code repository** | Secrets in public code | Rotate immediately and purge from git history |
| **Forum / paste** | Mentions, sale offers, doxxing | Verify, escalate to threat intel / legal as needed |

Use the **Sources** tab to see which connectors are active. Use **Import leak file** for dumps obtained during investigations; plaintext passwords are never stored.

## Threat Intelligence

**Indicators tab**

- Searchable table of normalised IOCs, filterable by type, severity, feed and sort order. Filters from the dashboard and matrix (technique, malware, threat type) appear as removable chips.
- Click a row for sources (with reference links), context, ATT&CK techniques, score factors and the STIX representation.

**Feeds tab**

- Every feed with category, reliability, indicator count and last-run result.
- Enable or disable a feed, or run it on demand.
- Trial feeds show *needs key* until their variable is set.

**Lookup tab**

- Paste anything: an email, logs, an incident ticket. Indicators are extracted (defanged forms included), normalised and checked.
- The global search box in the top bar does the same for a single value.

**Export & API tab**

- One-click STIX 2.1, JSON, CSV or plain-text exports, honouring the filters you choose.
- TAXII 2.1 connection details for your TIP or SIEM, and curl examples.

**ATT&CK Matrix** is a heat map of techniques across active indicators (log scale). Click a technique to list its indicators. Run `threatwatch attack-sync` to load the complete ATT&CK catalogue.

## Anti-Phishing

### Look-alike domains

**Scan look-alikes now** checks every watchlist domain (unless `meta.monitor_lookalikes` is `false`):

1. Up to `TW_PHISHING_MAX_PERMUTATIONS` permutations are generated, plus brand-containing names from Certificate Transparency.
2. Unregistered names are discarded via NXDOMAIN.
3. Registered ones are inspected: DNS, MX, website, content similarity to your real site, login forms, parked-page detection, RDAP registration date, and TI feed listing.

Signals in the table:

| Signal | Meaning |
|---|---|
| **MX** | The domain can send and receive email. This is the main enabler of BEC and invoice fraud, even with no website. |
| **login form** | The page asks for a password |
| **NN% similar** | The page imitates your site |
| **in TI feed** | Already reported as malicious |
| **parked** | For sale or parked. Usually low risk now, but often weaponised later; keep monitoring. |

Workflow:

1. Review critical and high rows.
2. For confirmed abuse, set the status to *takedown requested* and file reports with the registrar and host. The drawer lists the registrar and IPs.
3. Add the domain to mail and web blocklists.
4. Mark your own defensive registrations and unrelated legitimate sites as *benign* to silence them.

### URL analyzer

Paste a reported URL. The verdict (malicious / suspicious / low-risk) lists every signal that fired. Fetching is done server-side, so the analyst's browser never touches the page; the result shows the HTTP status, title, password form, form-post targets, redirects and registration date.

### Permutation preview

Offline list of all candidates for a domain, grouped by technique. Useful for defensive registrations or proactive DNS blocklists.

## Attack Surface Management

**New scan** asks for a root domain and a mode:

- **Passive** (default): CT logs, passive DNS, archives, DNS brute force, ASN/hosting, one homepage request and one TLS handshake per host, plus email/DNS hygiene checks.
- **Active**: adds a TCP connect scan of about 60 service ports per IP (CDN edges are limited to web ports), confirmation of exposed sensitive files (`/.git/HEAD`, `/.env`, Spring actuator, `server-status`, `phpinfo`...) by *content* match, and DNS zone-transfer attempts. You must confirm authorisation.

The scan page shows:

- the **grade** (A-F) and risk score,
- discovery statistics,
- findings by severity and category,
- hosting distribution and email security posture,
- tabs for **Findings**, **Assets** (click for host detail) and **Certificates** (sorted by expiry).

**Reports**:

| Format | Notes |
|---|---|
| HTML | Executive summary, top risks, findings with remediation and ATT&CK, email/DNS posture, asset inventory, methodology. Print to PDF from the browser. |
| Markdown | For tickets and wikis |
| JSON | For automation |

## Attack-surface findings

| Category | Check | Severity |
|---|---|---|
| exposure | SMB / MongoDB / Redis / Elasticsearch / unauthenticated Docker API reachable | critical |
| exposure | RDP, Telnet, VNC, WinRM, MySQL, PostgreSQL, MSSQL, Oracle, CouchDB, Memcached, kubelet, LDAP, NFS, NetBIOS, MS-RPC | high |
| exposure | FTP, PPTP, Kubernetes API, Webmin, WebLogic admin, RabbitMQ UI, Kibana, RPCbind | medium |
| exposure | SSH exposed | info |
| exposure | `/.git/` or `/.env` confirmed | critical |
| exposure | Spring actuator `/env` confirmed | high |
| exposure | `server-status`, `phpinfo()` | medium |
| exposure | Admin UIs (Jenkins, Grafana, Kibana, phpMyAdmin, Tomcat, GitLab, SonarQube, Swagger UI...) | medium |
| exposure | Non-production host (dev/staging/test/uat...) publicly reachable | low |
| exposure | High-value edge appliance identified (VPN, ADC, OWA, Confluence...) | info |
| intel | Detected product has CISA-KEV vulnerabilities (edge appliance / other) | high / medium |
| intel | Host or IP listed in a threat-intel feed (incl. Spamhaus DROP netblock) | high |
| tls | Certificate expired | high |
| tls | Expires < 14 d; self-signed; untrusted chain; hostname mismatch; TLS 1.0 enabled; RSA < 2048; SHA-1 signature | medium |
| tls | Expires < 30 d; TLS 1.1 only legacy | low |
| web | Plain HTTP only; directory listing | medium |
| web | No HTTP→HTTPS redirect; HSTS missing; server version disclosure | low |
| web | Missing CSP / X-Frame-Options / X-Content-Type-Options | info |
| takeover | CNAME to a cloud service showing its "unclaimed" page (GitHub Pages, Heroku, S3, Azure, Shopify...) | high |
| takeover | Dangling CNAME (NXDOMAIN) to a claimable provider | high |
| takeover | Dangling CNAME, other target | medium |
| email | SPF `+all` | high |
| email | No SPF; no DMARC | medium |
| email | DMARC `p=none`; SPF `?all` | low |
| email | No MX | info |
| dns | Zone transfer allowed | high |
| dns | No CAA; no DNSSEC; wildcard DNS | info |

## Suggested operating rhythm

| Cadence | Activity |
|---|---|
| Continuous (scheduler) | Feeds hourly; dark web and look-alikes daily; alerts to chat |
| Daily (10 min) | Triage new critical/high alerts; move exposures to *investigating*; check new look-alikes with MX or a login form |
| Weekly | Passive ASM scan of each domain; review the grade trend; export a STIX/TXT blocklist to perimeter controls (or let them pull TAXII) |
| Monthly | Active ASM scan (authorised); share the HTML report with infrastructure owners; review false positives and tune `criticality` |
| Quarterly | Review the watchlist (joiners/leavers in the executive list, new domains and brands); review feed reliability; run `attack-sync` |
