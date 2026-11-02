# Scoring and ATT&CK mapping

Every score in ThreatWatch is on a 0-100 scale, is **explainable** (the factors are stored with the record and shown in the UI under *Why this score*), and maps to severity with the same thresholds:

| Score | Severity |
|---|---|
| ≥ 85 | critical |
| 65-84 | high |
| 40-64 | medium |
| 15-39 | low |
| < 15 | info |

Alerts are raised for new items at or above `TW_ALERT_MIN_SEVERITY` (default `medium`). They are de-duplicated by a stable key, and if an existing alert's subject escalates, the alert is re-opened at the higher severity.

The weights live in one place per module, so you can tune them:

| Model | File |
|---|---|
| IOC | `modules/intel/scoring.py` |
| Exposure | `modules/darkweb/scoring.py` |
| Look-alike | `modules/phishing/service.py` (`score_lookalike`) |
| URL analyser | `modules/phishing/analyzer.py` |
| ASM | `modules/asm/service.py` |

---

## 1. Threat-intelligence indicators

```
confidence = min(100, max(source reliability) + min(25, 8 x (number_of_sources - 1)))
score      = confidence x threat_weight x recency_decay
decay      = max(0.35, 0.5 ^ (age_days / half_life))
```

**Source reliability** is a per-feed prior. Feeds that score their own indicators (ThreatFox `confidence_level`, AbuseIPDB `abuseConfidenceScore`) override it per indicator.

| Feed | Reliability | | Feed | Reliability |
|---|---|---|---|---|
| CISA KEV | 100 | | URLhaus | 85 |
| Spamhaus DROP | 95 | | SSL Blacklist | 85 |
| Feodo Tracker | 90 | | OpenPhish | 80 |
| MalwareBazaar | 90 | | ThreatFox | 80 |
| AbuseIPDB (≥90) | 75 | | Phishing Army | 70 |
| ET compromised | 70 | | IPsum L3 | 65 |
| CINS Army | 60 | | blocklist.de | 60 |
| OTX pulses | 60 | | | |

**Corroboration**: each additional independent feed adds 8 points, capped at +25. An IP on CINS (60), blocklist.de (60) *and* IPsum (65) reaches 65 + 16 = 81 confidence.

**Threat-type weight** (the highest across the indicator's threat types; a `ransomware` tag forces 1.0):

| Threat type | Weight | | Threat type | Weight |
|---|---|---|---|---|
| botnet_c2, c2, ransomware | 1.00 | | hijacked_netblock | 0.85 |
| exploited_vulnerability, malware_download, payload_delivery | 0.95 | | compromised | 0.80 |
| malware, phishing, credential_theft | 0.90 | | malicious_activity | 0.70 |
| brute_force | 0.65 | | scanner, cryptomining | 0.60 |
| spam | 0.50 | | *(unknown)* | 0.60 |

**Recency decay** uses the most recent activity reported by any source: Feodo `last_online`, the SSLBL listing date, or the time the indicator last appeared in an undated blocklist (presence on the current list counts as current activity). Half-lives:

| Type | Half-life | | Type | Half-life |
|---|---|---|---|---|
| ipv4 / ipv6 | 30 d | | domain | 90 d |
| url | 30 d | | email | 180 d |
| cidr | 180 d | | x509-sha1 | 180 d |
| md5 / sha1 / sha256 | 365 d | | cve | no decay |

The decay never drops below 0.35. Old but still-listed indicators remain visible at low severity.

**Retention**: indicators not seen in any feed for `TW_IOC_RETENTION_DAYS` (90) are marked `active=false`. They are excluded from default views and TAXII, and exported with `valid_until`.

**Example.** A Feodo C2 IP last online 3 days ago, also on IPsum:

| Step | Value |
|---|---|
| Base (highest source reliability) | 90 |
| Corroboration (+8) | 98 |
| × botnet_c2 weight 1.0 | 98 |
| × decay 0.93 (3 d, 30 d half-life) | **91 → critical** |

## 2. Dark-web exposures

```
raw   = source_base + data_sensitivity + recency + asset_bonus
score = raw x asset_criticality x (0.6 + 0.4 x source_credibility), soft-capped above 90
```

| Source type | Base | | Data exposed | Bonus |
|---|---|---|---|---|
| ransomware_leak | 50 | | credentials, plaintext or easily cracked | +20 |
| stealer_log | 45 | | credentials, hashed or unknown | +12 |
| combolist | 30 | | financial (cards, bank, wallets) | +10 |
| code_repo | 30 | | government IDs (SSN, passport, tax) | +10 |
| forum | 25 | | corporate data, source code, corporate URLs | +8 |
| paste | 25 | | personal (phone, address, DOB, location) | +4 |
| breach | 20 | | | |

| Recency of leak | | | Asset | |
|---|---|---|---|---|
| ≤ 30 days | +15 | | executive | +8 (BEC / whaling target) |
| ≤ 180 days | +10 | | domain + stealer/ransomware | +5 (organisation-wide) |
| ≤ 1 year | +5 | | criticality critical / high / medium / low | ×1.2 / ×1.1 / ×1.0 / ×0.85 |
| > 5 years | −10 | | | |

**Source credibility** (0-1) is set by the connector:

| Credibility | Sources |
|---|---|
| 1.0 | HIBP verified breach |
| 0.9 | Hudson Rock; XposedOrNot verified; ransomware.live exact domain match |
| 0.6 | LeakCheck, IntelX, onion mentions |
| 0.5 | GitHub code search; ransomware.live name-only match |

**Soft cap**: above 90, `score = 90 + 10 x (1 - e^-(raw-90)/30)`. The worst exposures still rank against each other instead of all sitting at 100.

**Example.** An infostealer infection on the CEO's laptop 9 days ago:

| Step | Value |
|---|---|
| stealer_log base | 45 |
| + plaintext credentials | +20 |
| + leaked ≤ 30 days | +15 |
| + executive | +8 → 88 |
| × critical 1.2 | 105.6 |
| × credibility 0.96 | 101.4 |
| soft cap | **93 → critical** |

## 3. Look-alike domains

| Signal | Points |
|---|---|
| Registered look-alike (base) | 20 |
| Technique: idn-homograph | +15 |
| Technique: homoglyph | +12 |
| Technique: ct-log (certificate issued for a name containing the brand) | +10 |
| Technique: transposition, omission, repetition, replacement, vowel-swap, combosquatting | +8 |
| Technique: tld-swap, tld-concat | +6 |
| Technique: hyphenation, insertion, addition, subdomain | +5 |
| Technique: bitsquatting | +4 |
| Resolves to an IP | +8 |
| **Has MX records** (can send and receive mail, so BEC is possible) | +15 |
| Live website, not parked | +7 |
| Parked / for-sale page | −15 |
| Content similarity to the genuine site (when ≥ 0.3) | +30 × similarity |
| Password form | +15 |
| Page mentions the brand | +10 |
| Registered < 30 days ago | +20 |
| Registered < 180 days ago | +10 |
| Listed in a threat-intel feed | +30 |

The same soft cap above 90 applies.

**Content similarity** combines three signals:

```
0.55 x title_similarity + 0.45 x min(1, 1.6 x jaccard(page tokens)) + 0.25 (if the page hot-links the genuine site's assets)
```

The result is capped at 1.0.

A new alert is raised when a look-alike is first found, or when its score rises by 15 or more.

## 4. URL analyser

The verdict is the sum of the signals that fired: **≥ 70 malicious**, **≥ 40 suspicious**, otherwise low-risk.

| Signal | Points | | Signal | Points |
|---|---|---|---|---|
| Listed in threat-intel feeds | +70 | | Brand used outside its genuine domain | +30 |
| Hosting provider / CDN flagged the page as phishing | +40 | | Look-alike of a protected brand (skeleton match or edit distance ≤ 2) | +35 |
| Known look-alike in DB | +30 | | IP address as host | +25 |
| Punycode / IDN host | +20 | | `@` in authority | +20 |
| Registered < 30 d | +20 | | Registered < 180 d | +10 |
| Password field | +15 | | Form posts to another domain | +15 |
| Page mentions a protected brand | +15 | | Phishing keywords in URL | +4 each (max 15) |
| Free hosting / tunnelling | +10 | | URL shortener | +10 |
| Deep sub-domain nesting | +10 | | Suspicious TLD | +8 |
| Many hyphens | +8 | | High-entropy label | +8 |
| No TLS | +5 | | Long URL / cross-domain redirect | +5 |
| Parked page | −10 | | Host belongs to a protected domain | −40 |

## 5. Attack surface

```
points = 25 x critical + 10 x high + 4 x medium + 1 x low
risk   = 100 x (1 - e^(-points/50)), then clamped into the band of the worst severity present
```

| Worst finding | Risk band | Resulting grades |
|---|---|---|
| critical | 65-100 | F |
| high | 25-64 | C-D |
| medium | 10-44 | B-C |
| low | 0-24 | A-B |
| info / none | 0-9 | A |

Grades: **A** < 10, **B** < 25, **C** < 45, **D** < 65, **F** ≥ 65.

The bands guarantee two things. Breadth of minor issues alone can never fail a target. A single critical exposure (an open Redis, a leaked `.env`) can never hide behind an otherwise clean surface. Each asset also gets its own risk, computed the same way from its findings.

The finding rules and their severities are listed in [USER_GUIDE.md](USER_GUIDE.md#attack-surface-findings).

---

## MITRE ATT&CK mapping

Mapping is deterministic and auditable (`modules/intel/attack.py`). The union of four rule families is applied:

**1. Threat type**

| Threat type | Techniques |
|---|---|
| c2 / botnet_c2 | T1071, T1071.001, T1573 (+T1584.005 botnet) |
| phishing | T1566, T1566.002, T1598.003, T1204.001 |
| malware_download / payload_delivery | T1105, T1204.002 (+T1189) |
| brute_force | T1110, T1110.001, T1110.003 |
| scanner | T1595, T1595.001, T1595.002 |
| compromised | T1584, T1090 |
| hijacked_netblock | T1583, T1584 |
| exploited_vulnerability | T1190 |
| ransomware | T1486, T1490, T1567 |

**2. Malware family behaviour** (regex groups)

| Family group | Techniques |
|---|---|
| Info-stealers (Lumma, RedLine, Vidar, StealC, ...) | T1555.003, T1539, T1552.001, T1041 |
| Keyloggers (Agent Tesla, FormBook, ...) | T1056.001, T1555.003, T1041 |
| Loaders (Emotet, QakBot, IcedID, ...) | T1105, T1566.001, T1204.002, T1059 |
| RATs (AsyncRAT, Remcos, DCRat, ...) | T1219, T1056.001, T1113, T1071.001 |
| Post-exploitation (Cobalt Strike, Sliver, ...) | T1071.001, T1573.002, T1055, T1059.001 |
| Ransomware (LockBit, Akira, ...) | T1486, T1490, T1567.002 |
| IoT botnets (Mirai, ...) | T1498, T1110, T1190, T1584.005 |
| Miners | T1496 |

**3. Tags and indicator type**

| Tag / type | Techniques |
|---|---|
| `rdp` tag | T1133, T1021.001 |
| `doc` tag | T1566.001, T1204.002 |
| `x509-sha1` type | T1573.002 |
| `cidr` type | T1583 |

**4. Context**

| Context | Techniques |
|---|---|
| C2 on a non-standard port | T1571 |
| KEV "privilege escalation" | T1068 |
| KEV browser / Office / reader products | T1203 |
| Feed-supplied ATT&CK IDs (OTX) | passed through |

**ASM findings** carry the techniques an attacker would use against the exposure. For example:

| Finding | Techniques |
|---|---|
| RDP exposed | T1133, T1021.001, T1110 |
| Missing DMARC | T1566 |
| Dangling CNAME | T1584.001 |

The embedded catalogue contains the subset of techniques the rules use. `threatwatch attack-sync` loads the full Enterprise matrix from `mitre/cti`, including the newer *Stealth* / *Defense Impairment* tactics that replaced *Defense Evasion*. The matrix view adapts to whichever tactics the catalogue contains.
