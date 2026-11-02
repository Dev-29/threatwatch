# Security, legal and ethical use

ThreatWatch is a defensive tool for monitoring **your own organisation's** external exposure. Some of its capabilities can harm third parties or break the law if misused. Read this before deploying.

## Authorised use only

| Capability | Rule |
|---|---|
| **Active ASM** (port scanning, sensitive-path probing, DNS zone-transfer attempts) | Only against assets you own or have **written authorisation** to test. Unauthorised scanning may be illegal (e.g. under the US CFAA or the UK Computer Misuse Act) and breaches most hosting terms. The API and CLI refuse active scans without an explicit authorisation flag (`authorized: true` / `--i-am-authorized`). The default mode is passive. |
| **Passive ASM** | Collects public data (CT logs, passive DNS, archives) and makes one ordinary web request and TLS handshake per discovered host. Still scope it to your organisation. |
| **Dark-web monitoring** | Queries breach and leak *indexes* for your own identifiers. Do not add people outside your organisation's responsibility to the watchlist. Employee monitoring may need notice to employees and works-council or DPO approval, depending on jurisdiction (GDPR Art. 6(1)(f) legitimate interest assessment, for example). |
| **Tor / `.onion` sources** | Only configure sources your policy and local law allow you to access. ThreatWatch only *reads* pages; never use it to interact with criminal marketplaces. |
| **Leak-file import** | Handle dumps under your evidence-handling procedure. ThreatWatch stores only matches, with masked secrets; the original file is not kept. |
| **Look-alike inspection** | Fetches pages from suspected phishing sites server-side. Run the server in a network segment where such outbound traffic is acceptable. |

Respect the terms of service and rate limits of every data provider (see [SOURCES.md](SOURCES.md)).

## Data handling

- **No plaintext credentials are stored.** Connectors and the importer persist masked values only (`S************3`). Infostealer password samples come pre-masked from the provider.
- Personal data collected includes names, email addresses, breach metadata and infostealer machine names. Define a retention period and a lawful basis, and restrict UI access to the security team.
- Secrets (API keys, webhook URLs) live only in the environment / `.env`. They are never returned by the API (Settings shows configured/not configured) and never logged.
- TLP defaults to `TLP:CLEAR` for open-source feed data. Do not ingest restricted partner intelligence without setting an appropriate TLP on the feed (`Feed.tlp`).

## Hardening checklist

- [ ] `TW_API_KEY` set to a long random value (`openssl rand -hex 32`).
- [ ] Bind to localhost (default) and publish through a TLS reverse proxy, ideally with SSO.
- [ ] Run as an unprivileged user (the Docker image does) with a read-only code directory.
- [ ] Restrict egress to the hosts in [SOURCES.md](SOURCES.md) where possible. The server must not be able to reach internal admin networks it doesn't need: URL analysis and look-alike inspection fetch attacker-controlled URLs (SSRF consideration).
- [ ] Back up and encrypt the database and `.env`.
- [ ] Keep dependencies updated (`pip list --outdated`) and rebuild the image regularly.
- [ ] If PostgreSQL is used, change the default compose password and restrict network access to the database.

## Application security notes

- All UI rendering escapes dynamic content via a tagged-template helper. Feed values, phishing page titles and dark-web snippets are attacker-controlled. External links open with `rel="noopener noreferrer"`.
- API keys are compared in constant time (`hmac.compare_digest`).
- Server-side fetches of suspicious pages never execute JavaScript, parse at most ~500 kB, and use timeouts.
- **SSRF guard:** URL analysis and look-alike inspection fetch user-supplied and attacker-controlled URLs. Every hop, including each redirect (followed manually, max 5), is checked: destinations that resolve to private, loopback, link-local (e.g. cloud metadata `169.254.169.254`) or reserved addresses are refused. Egress filtering is still recommended as defence in depth (DNS rebinding).
- ASM probes connect to whatever your root domain's records point to. If public DNS publishes internal addresses, they will be probed from the ThreatWatch host, so scope scans accordingly.
- Uploaded leak files are size-limited (200 MB) and are not retained. The web framework may spool large uploads to a temporary file during the request; only matches, with masked secrets, are stored.

## Reporting vulnerabilities

Please report security issues privately to the maintainers rather than opening a public issue.
