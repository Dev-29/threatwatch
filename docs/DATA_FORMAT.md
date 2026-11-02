# Data formats

ThreatWatch publishes indicators in four formats, plus a TAXII 2.1 feed. All of them are produced from the same normalised records.

| Format | Endpoint | CLI | Use for |
|---|---|---|---|
| **STIX 2.1 bundle** | `GET /api/v1/intel/export/stix` | `threatwatch export --format stix` | TIPs (OpenCTI, MISP), SIEM threat-intel modules |
| **ThreatWatch JSON** (`threatwatch.ioc.v1`) | `GET /api/v1/intel/export/json` | `--format json` | Scripts, SOAR, data lakes |
| **CSV** | `GET /api/v1/intel/export/csv` | `--format csv` | Spreadsheets, SIEM lookups |
| **Plain text** | `GET /api/v1/intel/export/txt` | `--format txt` | Firewall / DNS / proxy blocklists (one value per line) |
| **TAXII 2.1** | `/taxii2/` | n/a | Pull-based STIX consumption |

All export endpoints accept the same filters as the indicator list:

| Filter | Meaning |
|---|---|
| `type` | Comma-separated indicator types |
| `severity` | Comma-separated severities |
| `feed` | Only indicators reported by this feed |
| `technique` | ATT&CK technique ID |
| `malware` | Malware family name |
| `threat_type` | Threat type (suffix match, so `c2` includes `botnet_c2`) |
| `q` | Substring of the value |
| `min_score` | Minimum score |
| `active` | Default `true` |
| `since` | Updated at or after this ISO time |
| `limit` | Default 10,000 |

## 1. Canonical indicator model

Every indicator is normalised before storage (see `core/ioc.py`):

| `type` | Canonical form | Example |
|---|---|---|
| `ipv4` / `ipv6` | compressed address; private, reserved and loopback rejected | `185.220.101.1` |
| `cidr` | network address / prefix | `1.10.16.0/20` |
| `domain` | lower-case, IDNA (punycode), no trailing dot | `xn--exmple-cua.com` |
| `url` | lower-case scheme and host, default port removed, path kept (`/` if empty) | `https://evil.example/login` |
| `md5`, `sha1`, `sha256` | lower-case hex | `44d88612fea8a8f36de82e1278abb02f` |
| `x509-sha1` | lower-case SHA-1 certificate fingerprint | `66c6...67d6` |
| `email` | lower-case | `actor@example.net` |
| `cve` | upper-case | `CVE-2024-3400` |

Defanged input (`hxxp`, `[.]`, `(.)`, `[at]`) is refanged. Well-known benign registrable domains (`google.com`, `microsoft.com`...) are rejected as *exact* values, which prevents blocklist accidents; sub-domains and URLs on them are still accepted.

## 2. ThreatWatch JSON (`threatwatch.ioc.v1`)

The JSON Schema is in [`schemas/ioc.v1.schema.json`](schemas/ioc.v1.schema.json).

```json
{
  "schema": "threatwatch.ioc.v1",
  "generated_at": "2026-11-02T18:31:07.112Z",
  "count": 1,
  "indicators": [
    {
      "id": 4211,
      "type": "ipv4",
      "value": "50.16.16.211",
      "score": 91,
      "severity": "critical",
      "confidence": 98,
      "threat_types": ["botnet_c2", "malicious_activity"],
      "malware_families": ["QakBot"],
      "tags": ["c2", "qakbot", "multi-blocklist"],
      "attack": [
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
         "tactics": ["command-and-control"], "url": "https://attack.mitre.org/techniques/T1071/001/"}
      ],
      "sources": [
        {"feed": "feodo", "confidence": 90, "reference": "https://feodotracker.abuse.ch/browse/host/50.16.16.211/",
         "first_seen": "2025-01-01T00:00:00.000Z", "last_seen": "2026-11-02T18:00:00.000Z"},
        {"feed": "ipsum", "confidence": 65, "reference": "https://github.com/stamparm/ipsum",
         "first_seen": "2026-11-02T18:00:00.000Z", "last_seen": "2026-11-02T18:00:00.000Z"}
      ],
      "source_count": 2,
      "tlp": "clear",
      "description": null,
      "context": {"port": 443, "asn": 14618, "country": "US", "last_activity": "2026-11-01T00:00:00"},
      "first_seen": "2025-01-01T00:00:00.000Z",
      "last_seen": "2026-11-02T18:00:00.000Z",
      "last_activity": "2026-11-01T00:00:00",
      "active": true,
      "stix_id": "indicator--5ff2cb01-91a3-5171-8e4b-3fcdfdf0732a"
    }
  ]
}
```

Field semantics:

| Field | Meaning |
|---|---|
| `score` | Risk 0-100 (confidence × threat weight × recency decay), see [SCORING.md](SCORING.md) |
| `confidence` | Belief that the indicator is malicious, 0-100 (source reliability + corroboration) |
| `severity` | Bucket of `score` |
| `threat_types` | Normalised behaviour labels: `botnet_c2`, `c2`, `phishing`, `malware_download`, `payload_delivery`, `malware`, `brute_force`, `scanner`, `compromised`, `malicious_activity`, `hijacked_netblock`, `exploited_vulnerability` |
| `sources[]` | One entry per feed that reported the indicator, with that feed's reliability and reference link |
| `first_seen` / `last_seen` | First time any feed reported it / last time it was present in a feed |
| `last_activity` | Most recent activity reported by a source (drives decay) |
| `stix_id` | Deterministic ID of the corresponding STIX object |
| `context` | Feed-specific extras: `port`, `asn`, `country`, `sblid`, `vendor` / `product` / `due_date` (KEV), `file_name` / `file_type` (MalwareBazaar), `pulse` / `attack_ids` (OTX) |

The detail endpoint `GET /api/v1/intel/indicators/{id}` additionally returns `score_factors` and the indicator's STIX objects.

## 3. STIX 2.1 mapping

Bundles are valid STIX 2.1 and verified in the test suite with the OASIS `stix2` library, including the pattern grammar.

| ThreatWatch | STIX object | Notes |
|---|---|---|
| Producer | `identity` (`identity_class: system`, name "ThreatWatch") | Referenced by `created_by_ref` on every object |
| TLP | `marking-definition` (standard TLP 1.0 IDs) | `object_marking_refs` on indicators and vulnerabilities |
| Indicator (`ipv4`, `ipv6`, `cidr`, `domain`, `url`, `email`, hashes, `x509-sha1`) | `indicator` | `pattern_type: stix`; see the pattern table below |
| CVE (`cve`) | `vulnerability` | `external_references: [{source_name: "cve", external_id}]` |
| Malware family | `malware` (`is_family: true`) | `indicator --indicates--> malware` |
| ATT&CK technique | `attack-pattern` with `external_references[source_name=mitre-attack]` and `kill_chain_phases` | `indicator --indicates--> attack-pattern`; `attack-pattern --targets--> vulnerability` |
| Feed sightings | `external_references` on the indicator (`source_name` = feed, `url` = reference) | |

Indicator properties:

| STIX property | Source |
|---|---|
| `name` | `"<type>: <value>"` |
| `indicator_types` | from threat types (`malicious-activity`, `anomalous-activity`, `compromised`) |
| `valid_from` | `first_seen` |
| `valid_until` | set only when the indicator is inactive (expired) |
| `confidence` | ThreatWatch confidence (0-100) |
| `labels` | tags |
| `kill_chain_phases` | `mitre-attack` phases of the mapped techniques |
| `x_threatwatch_score`, `x_threatwatch_severity`, `x_threatwatch_sources`, `x_threatwatch_threat_types` | custom properties (STIX 2.1 `x_` convention) |

Patterns:

| Type | Pattern |
|---|---|
| ipv4 / cidr | `[ipv4-addr:value = '1.2.3.4']`, `[ipv4-addr:value = '1.10.16.0/20']` |
| ipv6 | `[ipv6-addr:value = '2001:db8::1']` |
| domain | `[domain-name:value = 'evil.example']` |
| url | `[url:value = 'https://evil.example/login']` (`'` and `\` escaped) |
| email | `[email-addr:value = 'a@evil.example']` |
| md5 / sha1 / sha256 | `[file:hashes.MD5 = '…']`, `[file:hashes.'SHA-1' = '…']`, `[file:hashes.'SHA-256' = '…']` |
| x509-sha1 | `[x509-certificate:hashes.'SHA-1' = '…']` |

**Deterministic identifiers**: `<type>--uuid5(NAMESPACE, "<type>:<natural key>")`. Re-exporting the same indicator always yields the same ID, so consumers upsert instead of duplicating. The bundle ID itself is random per export, as the spec requires.

## 4. CSV

Columns (multi-value fields are `|`-separated):

```
type,value,score,severity,confidence,threat_types,malware_families,attack_techniques,sources,tags,first_seen,last_seen,tlp
ipv4,50.16.16.211,91,critical,98,botnet_c2|malicious_activity,QakBot,T1071|T1071.001|T1573,feodo|ipsum,c2|qakbot,2025-01-01T00:00:00.000Z,2026-11-02T18:00:00.000Z,clear
```

## 5. TAXII 2.1

A read-only server implementing discovery, the API root, collections and objects:

| Endpoint | |
|---|---|
| `GET /taxii2/` | discovery |
| `GET /taxii2/api/` | API root |
| `GET /taxii2/api/collections/` | collection list |
| `GET /taxii2/api/collections/{id}/objects/?added_after=<ts>&limit=<n>` | STIX objects (paged via `more` / `next` and the `X-TAXII-Date-Added-First/Last` headers) |

| Collection ID | Title | Content |
|---|---|---|
| `4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c01` | All indicators | every active indicator |
| `4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c02` | High confidence | score ≥ 65 |
| `4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c03` | Phishing | phishing URLs and domains |
| `4b0b2d1a-1f6e-4d7a-9a51-0a6f6d3f1c04` | C2 infrastructure | C2 / botnet C2 |

Pagination is by `added_after`: request again with `added_after` set to the `next` value from the previous page.

## 6. ASM report (`threatwatch.asm.v1`)

`GET /api/v1/asm/scans/{id}/report?format=json` (also `html` for a print-ready report, `md` for Markdown):

```json
{
  "report": "threatwatch.asm.v1",
  "scan": {"id": 3, "root_domain": "example.com", "active": false, "status": "done",
           "started_at": "…", "finished_at": "…", "risk_score": 44, "grade": "C",
           "summary": {"names_discovered": 16, "hosts_resolved": 15, "unique_ips": 4, "web_services": 15,
                       "certificates": 13, "open_ports": 0, "findings": 48,
                       "by_severity": {"medium": 21, "low": 20, "info": 7},
                       "hosting": {"Cloudflare": 10, "AWS": 5},
                       "email_security": {"mx": ["…"], "spf": "v=spf1 …", "dmarc": null},
                       "source_errors": {}, "active": false}},
  "findings": [{"hostname": "…", "category": "tls", "check_id": "tls-hostname-mismatch", "severity": "medium",
                "title": "…", "description": "…", "evidence": "…", "remediation": "…",
                "attack": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactics": ["credential-access", "collection"], "url": "…"}]}],
  "assets": [{"hostname": "…", "resolved": true, "ips": ["…"], "cname": null, "hosting": "Cloudflare",
              "asn": {"203.0.113.10": {"asn": "13335", "org": "CLOUDFLARENET, US", "cc": "US", "prefix": "…"}},
              "ports": [{"port": 443, "service": "https", "banner": "", "ip": "…"}],
              "technologies": ["nginx", "WordPress"],
              "http": {"https": {"url": "…", "status": 200, "title": "…", "server": "…", "security_headers": {"…": true},
                                 "technologies": ["…"], "directory_listing": false, "login_form": false}},
              "tls": {"subject_cn": "…", "issuer_cn": "…", "not_after": "…", "days_left": 61, "self_signed": false,
                      "trusted": true, "hostname_match": true, "protocol": "TLSv1.3", "legacy_protocols": [],
                      "key_type": "EC", "key_bits": 256, "signature_hash": "sha256", "sans": ["…"], "sha256": "…"},
              "sources": ["crt.sh", "certspotter"], "risk_score": 12}]
}
```

## 7. Dark-web exposure record

Returned by `GET /api/v1/darkweb/exposures/{id}`:

```json
{
  "id": 1, "asset_id": 3, "asset": "Jane Doe", "asset_type": "executive", "asset_label": "CEO",
  "source": "hudsonrock", "source_type": "stealer_log",
  "title": "Infostealer infection on 'JDOE-LAPTOP' exposing saved credentials",
  "identifier": "jane.doe@example.com",
  "data_classes": ["Passwords", "Usernames", "Browser cookies"],
  "has_password": true, "password_plaintext": true, "record_count": null,
  "leaked_at": "2026-10-24T00:00:00Z", "first_seen": "…", "last_seen": "…",
  "risk_score": 93, "severity": "critical", "status": "new", "url": "…",
  "description": "…",
  "score_factors": [{"factor": "source type: stealer log", "delta": 45}, {"factor": "plaintext / easily cracked credentials", "delta": 20}],
  "raw": {"computer_name": "…", "credibility": 0.9, "verified": true}
}
```

`source_type` is one of:

| Value | Meaning |
|---|---|
| `breach` | breach of a third-party service |
| `combolist` | aggregated email:password lists |
| `stealer_log` | infostealer malware logs |
| `ransomware_leak` | data-leak site listing |
| `paste` | paste site |
| `forum` | dark-web or forum mention |
| `code_repo` | public source code |

Plaintext secrets are never stored. `raw.masked_secret` holds a mask such as `S************3`.
