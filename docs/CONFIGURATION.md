# Configuration reference

All settings are environment variables prefixed with `TW_`. They can also be put in a `.env` file in the working directory; `.env.example` is a fully commented template. Restart the process after changes. The **Settings** page shows the effective scheduler and limit values and which integrations are configured (never their secrets).

## Core

| Variable | Default | Description |
|---|---|---|
| `TW_DATABASE_URL` | `sqlite:///./data/threatwatch.db` | SQLAlchemy URL. PostgreSQL: `postgresql+psycopg://user:pass@host:5432/db` |
| `TW_HOST` | `127.0.0.1` | Bind address for `threatwatch serve` |
| `TW_PORT` | `8000` | Bind port |
| `TW_API_KEY` | *(unset)* | Key for scripts and TAXII clients: `X-API-Key: <key>`, `Authorization: Bearer <key>` or `?api_key=<key>`. Full access. `/api/health` stays open. |
| `TW_SESSION_IDLE_HOURS` | `12` | Browser sessions expire after this much inactivity |
| `TW_SESSION_MAX_DAYS` | `7` | Absolute session lifetime, regardless of activity |
| `TW_SESSION_COOKIE_SECURE` | `auto` | `Secure` flag on the session cookie. `auto` sets it for HTTPS requests, including `X-Forwarded-Proto: https` from a proxy on 127.0.0.1 (uvicorn's default trusted proxy). Set `true` when the proxy runs elsewhere, e.g. another container |
| `TW_LOGIN_MAX_FAILURES` | `5` | Failed sign-ins per client IP and username within 15 minutes before sign-in is blocked |
| `TW_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `TW_DATA_DIR` | `./data` | Runtime data (synced ATT&CK catalogue) |

## Outbound HTTP

| Variable | Default | Description |
|---|---|---|
| `TW_HTTP_TIMEOUT` | `20` | Default request timeout (seconds) |
| `TW_HTTP_PROXY` | *(unset)* | Proxy for all outbound requests, e.g. `http://proxy:3128` |
| `TW_TOR_PROXY` | *(unset)* | SOCKS proxy for `.onion` sources, e.g. `socks5://127.0.0.1:9050` (hostnames are resolved by the proxy) |
| `TW_ONION_SOURCES` | *(empty)* | Comma-separated `.onion` URLs to keyword-monitor |
| `TW_USER_AGENT` | `Mozilla/5.0 (compatible; ThreatWatch/1.0; ...)` | User-Agent for outbound requests |

## Dark-web and leak integrations

| Variable | Unlocks |
|---|---|
| `TW_HIBP_API_KEY` | Have I Been Pwned per-account breaches and pastes |
| `TW_INTELX_API_KEY` | Intelligence X search (pastes, darknet, leaks) |
| `TW_INTELX_API_URL` | `https://free.intelx.io` (free tier) or `https://2.intelx.io` (paid) |
| `TW_GITHUB_TOKEN` | GitHub code search for secrets next to your domain or brand (fine-grained token, public repo read) |

## Threat-intel feeds

| Variable | Default | Description |
|---|---|---|
| `TW_ABUSECH_AUTH_KEY` | *(unset)* | One free key for ThreatFox, URLhaus and MalwareBazaar |
| `TW_OTX_API_KEY` | *(unset)* | AlienVault OTX subscribed pulses, plus passive DNS in ASM |
| `TW_ABUSEIPDB_API_KEY` | *(unset)* | AbuseIPDB blacklist (confidence ≥ 90) |
| `TW_FEED_MAX_ITEMS` | `20000` | Maximum unique indicators ingested per feed per run |
| `TW_IOC_RETENTION_DAYS` | `90` | Indicators not seen for this long are marked inactive |

## Scheduler

| Variable | Default | Description |
|---|---|---|
| `TW_SCHEDULER_ENABLED` | `true` | Run the in-process scheduler. Disable on API-only replicas or when using cron. |
| `TW_FEEDS_INTERVAL_MINUTES` | `60` | Feed collection interval |
| `TW_DARKWEB_INTERVAL_HOURS` | `24` | Dark-web scan interval (`0` = off) |
| `TW_PHISHING_INTERVAL_HOURS` | `24` | Look-alike scan interval (`0` = off) |
| `TW_ASM_INTERVAL_HOURS` | `0` | Scheduled ASM scans of every watchlist domain (`0` = manual only) |

## Alerting

| Variable | Default | Description |
|---|---|---|
| `TW_ALERT_MIN_SEVERITY` | `medium` | Lowest severity that creates an alert: `info`, `low`, `medium`, `high`, `critical` |
| `TW_ALERT_WEBHOOK_URL` | *(unset)* | Incoming-webhook URL. Payload: `{"text", "severity", "module", "alert_id"}`. Compatible with Slack, Mattermost, Rocket.Chat, and Teams (via Workflows). |

## Anti-phishing

| Variable | Default | Description |
|---|---|---|
| `TW_PHISHING_MAX_PERMUTATIONS` | `1500` | Candidates checked per brand domain. Generated most-dangerous-first, so a lower cap drops bit-squats and additions before homoglyphs. |

## Attack surface management

| Variable | Default | Description |
|---|---|---|
| `TW_ASM_ACTIVE_DEFAULT` | `false` | Default mode for scheduled scans and API calls that omit `active` |
| `TW_ASM_MAX_HOSTS` | `150` | Maximum hostnames analysed per scan (prioritises root, `www`, and names seen by more sources) |
| `TW_ASM_CONCURRENCY` | `200` | Concurrent TCP connection attempts during port scans |
