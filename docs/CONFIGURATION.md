# Configuration reference

All settings are environment variables prefixed with `TW_`. They can also be put in a `.env` file in the working directory; `.env.example` is a fully commented template. Restart the process after changes. The **Settings** page shows the effective scheduler and limit values and which integrations are configured (never their secrets).

## Core

| Variable | Default | Description |
|---|---|---|
| `TW_DATABASE_URL` | `sqlite:///./data/threatwatch.db` | SQLAlchemy URL. PostgreSQL: `postgresql+psycopg://user:pass@host:5432/db` |
| `TW_HOST` | `127.0.0.1` | Bind address for `threatwatch serve` |
| `TW_PORT` | `8000` | Bind port |
| `TW_API_KEY` | *(unset)* | Key for scripts and TAXII clients: `X-API-Key: <key>`, `Authorization: Bearer <key>` or `?api_key=<key>`. Full access. `/api/health` stays open. |
| `TW_JWT_SECRET` | *(auto)* | HS256 signing key for session JWTs. If unset, a random key is generated once and stored at `<data_dir>/jwt_secret.key` so tokens survive restarts. Set this explicitly to share one key across multiple instances, or to rotate it (rotating invalidates all existing tokens) |
| `TW_JWT_EXPIRY_MINUTES` | `720` | How long an issued token stays valid. Tokens are stateless and cannot be revoked early, so shorter values bound the damage of a leaked token (at the cost of re-signing in more often) |
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

### Autonomous pentest (OWASP Top 10)

Active, intrusive testing driven by Claude Code. See [PENTEST.md](PENTEST.md). Only run against
targets you own or are authorised to assess.

| Variable | Default | Meaning |
|---|---|---|
| `TW_PENTEST_ENABLED` | `false` | Enable the pentest API endpoint (`POST /api/v1/asm/pentests`) and the web-UI "New pentest" button (the CLI `pentest` command works regardless, and always requires `--i-am-authorized`) |
| `TW_PENTEST_MODEL` | *(CLI default)* | Model id the agent runs as, e.g. `claude-opus-4-8` |
| `TW_PENTEST_MAX_TURNS` | `120` | Maximum agent turns before a run stops |
| `TW_PENTEST_ALLOWED_TOOLS` | *(module default)* | Override the agent's tool allowlist (JSON list) |
