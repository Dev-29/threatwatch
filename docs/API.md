# API reference

The interactive OpenAPI documentation is served by every instance at **`/api/docs`** (Swagger UI) and **`/api/redoc`**. The schema is at `/api/openapi.json`. This page summarises the API and shows common workflows.

- Base path: `/api/v1`
- Content type: JSON
- Timestamps: ISO-8601 UTC

## Authentication

When `TW_API_KEY` is set, every `/api/v1/*` and `/taxii2/*` request needs the key in one of three forms:

```
X-API-Key: <key>
Authorization: Bearer <key>
?api_key=<key>              # for browser download links only; avoid in logs
```

`GET /api/health` is always open, for load-balancer health checks.

| Status | Meaning |
|---|---|
| 401 | Missing or wrong key |
| 404 | Unknown object |
| 409 | Conflict: duplicate asset, or job already running |
| 422 | Validation error |

## Pagination

List endpoints accept `limit` (default 50, max 5000) and `offset`, and return:

```json
{"total": 1234, "limit": 50, "offset": 0, "items": [ ... ]}
```

## Endpoints

### Meta and overview

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness: `{"status":"ok","version":"1.0.0"}` |
| GET | `/dashboard` | KPIs, 14-day alert trend, recent alerts, per-module aggregates, latest ASM grades, running jobs |
| GET | `/settings` | Effective configuration (integration flags only, never secrets) |
| GET | `/jobs?kind=` | Job history and currently running jobs |

### Watchlist

| Method | Path | Body / params |
|---|---|---|
| GET | `/assets?type=` | List, with exposure counts |
| POST | `/assets` | `{"type":"domain\|email\|executive\|keyword\|brand","value":"…","label":"…","criticality":"low\|medium\|high\|critical","meta":{"emails":[…],"usernames":[…],"monitor_lookalikes":true}}` |
| PATCH | `/assets/{id}` | Any of `label`, `criticality`, `meta`, `enabled` |
| DELETE | `/assets/{id}` | Also deletes the asset's exposures |

### Dark web

| Method | Path | Description |
|---|---|---|
| GET | `/darkweb/exposures` | Filters: `severity`, `status`, `source_type`, `source`, `asset_id`, `q`; `sort=risk\|recent\|leaked` |
| GET | `/darkweb/exposures/{id}` | Full record with `score_factors`, `description`, `raw` |
| PATCH | `/darkweb/exposures/{id}` | `{"status":"new\|investigating\|remediated\|false_positive"}` |
| GET | `/darkweb/sources` | Connectors, supported term kinds, availability |
| POST | `/darkweb/scan` | `{"asset_ids":[…]?, "sources":["hudsonrock",…]?}` → `202`, runs in the background |
| POST | `/darkweb/import` | multipart: `file`, `source_type` (`combolist\|stealer_log\|breach\|paste\|forum`), `leaked_at` (YYYY-MM-DD, optional) |

### Threat intelligence

| Method | Path | Description |
|---|---|---|
| GET | `/intel/indicators` | Filters: `type`, `severity`, `feed`, `technique`, `malware`, `threat_type`, `q`, `min_score`, `active`, `since`; `sort=score\|recent\|new` |
| GET | `/intel/indicators/{id}` | Full record with sources, ATT&CK details, `score_factors` and its STIX objects |
| POST | `/intel/lookup` | `{"text":"<any text>"}`: extracts, refangs and normalises indicators and reports which are known (URLs also match their host and parent domain) |
| GET | `/intel/feeds` | Feeds with category, reliability, key requirement, last run and indicator counts |
| PATCH | `/intel/feeds/{name}` | `{"enabled":true\|false}` |
| POST | `/intel/feeds/run` | `{"feeds":["openphish",…]?}` → `202` (all enabled feeds when omitted) |
| GET | `/intel/attack/matrix` | Tactic columns with technique counts across active indicators |
| GET | `/intel/stats` | Counts by type, severity and feed |
| GET | `/intel/export/{stix\|json\|csv\|txt}` | Same filters as the list, plus `limit` (default 10,000, max 200,000). See [DATA_FORMAT.md](DATA_FORMAT.md). |

### Anti-phishing

| Method | Path | Description |
|---|---|---|
| GET | `/phishing/lookalikes` | Filters: `brand`, `severity`, `status`, `technique`, `q`, `has_mx`, `live` |
| PATCH | `/phishing/lookalikes/{id}` | `{"status":"new\|monitoring\|takedown_requested\|taken_down\|benign"}`. `benign` and `taken_down` suppress further alerts. |
| POST | `/phishing/scan` | `{"domains":["example.com"]?}` → `202` (all watchlist domains when omitted) |
| POST | `/phishing/analyze` | `{"url":"…","fetch":true}` → verdict, score, signals, page info, TI matches, registration data |
| GET | `/phishing/permutations?domain=&limit=` | Offline candidate generation (no network) |

### Attack surface

| Method | Path | Description |
|---|---|---|
| GET | `/asm/scans?root_domain=` | Scan list |
| POST | `/asm/scans` | `{"root_domain":"example.com","active":false,"authorized":false}` → `202 {"scan_id":…}`. **`active: true` requires `authorized: true`.** |
| GET | `/asm/scans/{id}` | Status, grade, risk, summary |
| GET | `/asm/scans/{id}/assets` | Discovered hosts with DNS, ASN, ports, HTTP, TLS, technologies |
| GET | `/asm/scans/{id}/findings` | Findings, sorted by severity |
| GET | `/asm/scans/{id}/report?format=html\|md\|json&download=false` | Risk report |
| DELETE | `/asm/scans/{id}` | Delete a scan (not while running) |

### Alerts

| Method | Path | Description |
|---|---|---|
| GET | `/alerts` | Filters: `status` (comma list), `severity`, `module`, `q` |
| PATCH | `/alerts/{id}` | `{"status":"open\|acknowledged\|closed"}` |
| POST | `/alerts/bulk` | `{"ids":[…],"status":"…"}` |

### TAXII 2.1

TAXII lives at `/taxii2/` (discovery), `/taxii2/api/` and `/taxii2/api/collections/{id}/objects/`. See [DATA_FORMAT.md § TAXII](DATA_FORMAT.md#5-taxii-21).

## Examples

```bash
export TW=http://127.0.0.1:8000 KEY=change-me
H="X-API-Key: $KEY"

# add the organisation
curl -sH "$H" -H 'content-type: application/json' -X POST $TW/api/v1/assets \
  -d '{"type":"domain","value":"example.com","criticality":"critical"}'
curl -sH "$H" -H 'content-type: application/json' -X POST $TW/api/v1/assets \
  -d '{"type":"executive","value":"Jane Doe","meta":{"emails":["jane@example.com","jane.doe@gmail.com"]}}'

# start collection, then poll jobs
curl -sH "$H" -X POST $TW/api/v1/intel/feeds/run
curl -sH "$H" -X POST $TW/api/v1/darkweb/scan
curl -sH "$H" "$TW/api/v1/jobs?limit=5"

# triage
curl -sH "$H" "$TW/api/v1/darkweb/exposures?severity=critical,high&status=new"
curl -sH "$H" -X PATCH -H 'content-type: application/json' $TW/api/v1/darkweb/exposures/42 -d '{"status":"investigating"}'

# blocklist for a firewall: high-confidence C2 IPs
curl -sH "$H" "$TW/api/v1/intel/export/txt?type=ipv4&threat_type=c2&min_score=65" -o c2-ips.txt

# STIX bundle of everything critical/high updated in the last day
curl -sH "$H" "$TW/api/v1/intel/export/stix?severity=critical,high&since=$(date -u -d '1 day ago' +%FT%T)" -o daily.stix.json

# check indicators from an incident ticket
curl -sH "$H" -H 'content-type: application/json' -X POST $TW/api/v1/intel/lookup \
  -d '{"text":"beacon to 45.9.148.3 and hxxps://login-m365[.]example/verify"}'

# analyse a reported phishing URL
curl -sH "$H" -H 'content-type: application/json' -X POST $TW/api/v1/phishing/analyze \
  -d '{"url":"https://examp1e-login.com/auth","fetch":true}'

# ASM scan + report
SCAN=$(curl -sH "$H" -H 'content-type: application/json' -X POST $TW/api/v1/asm/scans \
  -d '{"root_domain":"example.com"}' | jq .scan_id)
curl -sH "$H" "$TW/api/v1/asm/scans/$SCAN" | jq '.status,.grade'
curl -sH "$H" "$TW/api/v1/asm/scans/$SCAN/report?format=html" -o report.html
```

### Python

```python
import httpx

tw = httpx.Client(base_url="http://127.0.0.1:8000/api/v1", headers={"X-API-Key": "change-me"})
crit = tw.get("/intel/indicators", params={"severity": "critical", "type": "domain", "limit": 500}).json()
for ind in crit["items"]:
    print(ind["value"], ind["score"], ind["sources"], ind["attack_techniques"])
```

### TAXII clients

```python
from taxii2client.v21 import Server   # pip install taxii2-client
srv = Server("http://127.0.0.1:8000/taxii2/", headers={"X-API-Key": "change-me"})
col = srv.default.collections[1]        # "High confidence"
print(col.title, len(col.get_objects()["objects"]))
```
