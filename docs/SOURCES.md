# Sources and integrations

Everything below was verified working at the time of writing (November 2026). Public APIs change, so check **Settings → Recent jobs** and the feed status column for per-source errors. A failing source never stops the other sources in the same run.

Respect each provider's terms of use and rate limits. Some free feeds are licensed for non-commercial use only; review them before commercial deployment.

## 1. Threat-intelligence feeds

### Open-source (no key)

| Name (`--feed`) | Provider | Content | Format | Reliability |
|---|---|---|---|---|
| `feodo` | abuse.ch Feodo Tracker | Botnet C2 IPs (Emotet, QakBot, Dridex...) with port, ASN, malware family | JSON | 90 |
| `sslbl` | abuse.ch SSL Blacklist | SHA-1 fingerprints of TLS certificates used by malware C2, with family | CSV | 85 |
| `openphish` | OpenPhish community | Active phishing URLs | text | 80 |
| `phishing_army` | Phishing Army | Phishing domains aggregated from PhishTank, OpenPhish, CERT.PL... | text | 70 |
| `cins` | CINS Army (Sentinel IPS) | Poor-reputation IPs | text | 60 |
| `et_compromised` | Proofpoint Emerging Threats | Known compromised hosts | text | 70 |
| `blocklist_de` | blocklist.de | IPs attacking SSH, mail, FTP and web logins | text | 60 |
| `ipsum` | stamparm/ipsum (level 3) | IPs on 3 or more public blocklists | text | 65 |
| `spamhaus_drop` | Spamhaus DROP | Hijacked or criminal netblocks | NDJSON | 95 |
| `cisa_kev` | CISA | Known Exploited Vulnerabilities (CVE, vendor, product, ransomware use, due date) | JSON | 100 |

### Trial / free-key feeds

| Name | Key variable | Get a key | Content |
|---|---|---|---|
| `threatfox` | `TW_ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ (free) | Malware IOCs: C2 IP:port, domains, URLs, hashes, with family and confidence |
| `urlhaus` | `TW_ABUSECH_AUTH_KEY` | same key | Malware distribution URLs |
| `malwarebazaar` | `TW_ABUSECH_AUTH_KEY` | same key | Recent malware sample hashes with signature and file type |
| `otx` | `TW_OTX_API_KEY` | https://otx.alienvault.com/ (free account) | Indicators from subscribed pulses, **including ATT&CK technique IDs** |
| `abuseipdb` | `TW_ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/ (free tier) | IPs with abuse confidence ≥ 90 |

> abuse.ch retired its anonymous bulk exports (ThreatFox, URLhaus and MalwareBazaar now return HTTP 410). A free Auth-Key is required.

Commands:

```bash
threatwatch feeds --list
threatwatch feeds --feed threatfox --feed urlhaus
```

You can also enable or disable feeds in **Threat Intel → Feeds**.

### Adding a feed

```python
# modules/intel/feeds.py  (csv is already imported there; add "import io")
async def fetch_myfeed(c, s):
    r = await _get(c, "https://intel.example/feed.csv")
    for row in csv.DictReader(io.StringIO(r.text)):
        yield RawIOC(value=row["indicator"], type_hint=None,     # auto-detected
                     threat_type="c2", malware=row.get("family"),
                     tags=["myfeed"], reference=row.get("link"),
                     first_seen=_dt(row.get("date")))

FEEDS["myfeed"] = Feed("myfeed", "My Feed", "C2 servers from partner X", "https://intel.example",
                       fetch_myfeed, confidence=75, requires=None, category="trial")
```

Normalisation, de-duplication, scoring, ATT&CK mapping, the UI listing, exports and TAXII all apply automatically.

## 2. Dark-web and leak connectors

| Connector | Key | Searches | What it finds |
|---|---|---|---|
| `xposedornot` | none | email | Breaches with exposed data classes, password risk (plaintext / easy / strong), verification flag; pastes |
| `leakcheck` | none | email | Leak sources and dates for an address (public API reports field types across all sources) |
| `hudsonrock` | none | email, domain | **Infostealer infections**: per-email machine infections (date, OS, malware path, masked passwords); per-domain counts of compromised employees and users, with exposed corporate URLs |
| `hibp_domain` | none | domain | Breaches where *your* service was breached (HIBP catalogue) |
| `ransomware_live` | none | domain, keyword | Victims posted on ransomware data-leak sites (onion), with group, date and claim URL |
| `hibp` | `TW_HIBP_API_KEY` | email | Per-account breaches and pastes (https://haveibeenpwned.com/API/Key) |
| `intelx` | `TW_INTELX_API_KEY` | email, domain, keyword, name | Pastes, darknet (Tor/I2P), leaks, dumps (https://intelx.io/account?tab=developer; free tier) |
| `github` | `TW_GITHUB_TOKEN` | domain, keyword | Public code containing your domain or brand next to `password`, `secret` or `api_key` |
| `onion` | `TW_TOR_PROXY` + `TW_ONION_SOURCES` | all | Keyword hits on operator-supplied `.onion` pages (forum sections, leak-site indexes), with snippets |

How each asset type is searched:

| Asset | Searched as |
|---|---|
| `email` | email |
| `domain` | domain |
| `brand`, `keyword` | keyword |
| `executive` | each email in `meta.emails`, each `meta.usernames` value as a keyword, and the full name |

### Leak-file import (manual source)

**Dark Web → Import leak file** (or `POST /api/v1/darkweb/import`) matches a file obtained during an investigation against the watchlist. Supported line formats:

```
email:password    email;password    email|password
url:login:password    url|login|password        # infostealer "ULP" logs
any CSV or text containing email addresses
```

Matching rules:

- Exact watched emails, including executive addresses.
- Any address on a watched domain.
- Any credential for a login URL on a watched domain, whatever the username. This catches service accounts.

Passwords are reduced to a mask before storage.

### Adding a connector

```python
class MySource(Connector):
    name, title = "mysource", "My Source"
    kinds = {"email", "domain"}
    requires = "my_api_key"          # add the field to config.Settings
    delay = 1.0

    async def _search(self, c, kind, term):
        r = await c.get("https://api.example/search", params={"q": term})
        r.raise_for_status()
        return [LeakFinding(source=self.name, source_type="breach", title=f"{x['name']} breach",
                            identifier=term, data_classes=x["fields"], leaked_at=_parse_date(x["date"]),
                            has_password="password" in x["fields"], credibility=0.8)
                for x in r.json()["results"]]

CONNECTORS.append(MySource)
```

## 3. Anti-phishing sources

| Source | Purpose |
|---|---|
| System DNS resolver | Registration check (NXDOMAIN filter), A / MX / NS records |
| RDAP (`rdap.org` bootstrap) | Registration date, registrar |
| Direct HTTP(S) fetch | Title, content similarity, login forms, parked-page detection |
| crt.sh | Certificates issued for names containing the brand label |
| Local TI database | Whether a look-alike or URL is already in a feed |

## 4. ASM sources

| Source | Key | Purpose |
|---|---|---|
| crt.sh | none | Certificate Transparency names |
| CertSpotter (SSLMate) | none (rate-limited) | CT names |
| HackerTarget host search | none (about 50 queries per day) | Passive DNS |
| Wayback Machine CDX | none | Historical hostnames |
| AlienVault OTX passive DNS | `TW_OTX_API_KEY` | Passive DNS |
| DNS brute force | n/a | 300+ common labels, wildcard-aware (`data/subdomains.txt`, editable) |
| Team Cymru IP-to-ASN (DNS) | none | ASN, prefix, country, organisation, hosting provider |
| Target hosts | n/a | HTTP fingerprint, TLS handshake; with `active`, also TCP ports, sensitive paths and AXFR |
| Local TI database | n/a | Hosts or IPs listed in feeds (including Spamhaus DROP netblocks); CISA KEV cross-reference for detected products |

## Outbound hosts to allow-list

```
feodotracker.abuse.ch sslbl.abuse.ch threatfox-api.abuse.ch urlhaus-api.abuse.ch mb-api.abuse.ch
openphish.com phishing.army cinsscore.com rules.emergingthreats.net lists.blocklist.de
raw.githubusercontent.com www.spamhaus.org www.cisa.gov otx.alienvault.com api.abuseipdb.com
api.xposedornot.com leakcheck.io cavalier.hudsonrock.com haveibeenpwned.com api.ransomware.live
free.intelx.io api.github.com crt.sh api.certspotter.com api.hackertarget.com web.archive.org rdap.org (+ registry RDAP servers)
```

DNS (UDP/TCP 53) is also required. Look-alike inspection and ASM probes contact arbitrary hosts on 80 and 443 (and other ports in active mode).
