# Operations

## Scheduler and jobs

The built-in scheduler (`TW_SCHEDULER_ENABLED=true`) wakes every 60 s and starts any job whose interval has elapsed since its last successful run:

| Job kind | Interval variable | Default |
|---|---|---|
| `feeds` | `TW_FEEDS_INTERVAL_MINUTES` | 60 min |
| `darkweb_scan` | `TW_DARKWEB_INTERVAL_HOURS` | 24 h |
| `phishing_scan` | `TW_PHISHING_INTERVAL_HOURS` | 24 h |
| `asm_scheduled` | `TW_ASM_INTERVAL_HOURS` | off |

- Last-run times come from the `job_runs` table, so restarts do not trigger a burst of duplicate runs. Failed runs are retried on the next tick.
- Jobs left `running` by a crashed process are marked `failed: interrupted` at start-up, and so are their ASM scans.
- Only one job per `(kind, target)` runs at a time. A second request returns HTTP 409.
- Job history and per-source errors are shown in **Settings → Recent jobs** and at `GET /api/v1/jobs`.

With several API replicas, enable the scheduler on **one** instance only.

## Logs

Logs go to stdout/stderr (`TW_LOG_LEVEL`). Each job logs its start and end with stats; per-source failures are logged at WARNING. Under systemd: `journalctl -u threatwatch -f`. Under Docker: `docker compose logs -f threatwatch`.

## Backups

**SQLite** (online, consistent):

```bash
sqlite3 data/threatwatch.db ".backup 'backup/threatwatch-$(date +%F).db'"
# Docker:
docker compose exec threatwatch python -c "import sqlite3; s=sqlite3.connect('/data/threatwatch.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
```

**PostgreSQL**: `pg_dump -Fc threatwatch > threatwatch-$(date +%F).dump`

What to back up: the database and `.env` (it contains secrets, so store it encrypted). The synced ATT&CK file can be re-downloaded.

## Data retention

| Data | Retention |
|---|---|
| Indicators | Marked inactive after `TW_IOC_RETENTION_DAYS` without a sighting; kept for history. To purge: `DELETE FROM indicators WHERE active = 0 AND last_seen < date('now','-365 day');` |
| Exposures, look-alikes, alerts | Kept until deleted. Deleting an asset deletes its exposures. |
| ASM scans | Each scan is a snapshot. Delete old scans in the UI or with `DELETE /api/v1/asm/scans/{id}`. |
| Job history | Grows slowly (one row per job). Prune with `DELETE FROM job_runs WHERE started_at < date('now','-180 day');` |

Run `VACUUM;` (SQLite) after large deletions.

## Upgrades

1. Back up the database.
2. Update the code (`git pull`, or a new image) and run `pip install -e .`, or `docker compose build`.
3. Restart. New tables are created automatically.

Version 1.0 has no destructive schema changes. Future column changes will ship with Alembic migrations (`alembic upgrade head`).

## Performance tuning

| Symptom | Tuning |
|---|---|
| Feed run slow or DB large | Lower `TW_FEED_MAX_ITEMS`; disable broad feeds (`phishing_army`, `blocklist_de`) you don't use; move to PostgreSQL |
| Look-alike scan slow | Lower `TW_PHISHING_MAX_PERMUTATIONS` (candidates are generated most-dangerous-first); most time goes to RDAP and HTTP for *registered* names |
| ASM scan slow | Lower `TW_ASM_MAX_HOSTS`. Active scans are bounded by `TW_ASM_CONCURRENCY` × 1.5 s per closed port. |
| Rate-limit errors from a source | Connectors are serialised per source with a delay. Increase `delay` on the connector class, or reduce scan frequency. |
| UI slow on big lists | Use filters. Lists are server-side paginated (50 rows). |

Reference numbers on a 2-vCPU VM:

| Job | Time |
|---|---|
| All 10 free feeds (~76k indicators) | ~20 s |
| Dark-web scan of 3 assets (5 sources) | ~15 s |
| Look-alike scan, 400 candidates | ~100 s |
| Passive ASM of a 16-host domain | ~60 s |

## Troubleshooting

| Problem | Fix |
|---|---|
| UI asks for an API key | `TW_API_KEY` is set. Enter it once; it is stored in that browser's localStorage. Clear it in Settings. |
| Feed shows `error` | Check the message in **Threat Intel → Feeds** (hover). HTTP 401/403 means a key is wrong or missing; 410 means the provider retired the endpoint; timeouts usually mean egress filtering or a proxy (`TW_HTTP_PROXY`). |
| `needs key` on a trial feed | Set the variable listed in the Feeds tab and restart |
| Dark-web scan finds nothing | Check **Dark Web → Sources**. Executive assets need email addresses in their profile. HackerTarget and LeakCheck have daily quotas. |
| ASM scan shows few hosts | Passive sources may be rate-limited (shown under *Unavailable sources*). Add `TW_OTX_API_KEY`; extend `threatwatch/data/subdomains.txt`. |
| Many "open ports" on a CDN IP | Shouldn't happen: CDN edges are limited to web ports. If a provider isn't recognised, add its ASN organisation keyword to `CDN_ORGS` in `modules/asm/probes.py`. |
| TLS 1.0/1.1 never detected | Some OpenSSL builds disable legacy protocols at the library level. The check then reports nothing (no false positives). |
| `.onion` sources not fetched | `TW_TOR_PROXY` must point to a running Tor SOCKS port; check `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org` |
| `database is locked` (SQLite) | Several processes are writing heavily at once. Run CLI jobs when the server is idle, or use PostgreSQL. |
| Webhook alerts not delivered | Check logs for `webhook delivery failed`. Undelivered alerts are retried after the next job. |

## Health and monitoring

- `GET /api/health` returns 200 when the app is up (used by the Docker HEALTHCHECK).
- For freshness, alert if `GET /api/v1/jobs?kind=feeds&limit=1` shows `status != success`, or `started_at` is older than 2 × the interval.
- `GET /api/v1/intel/feeds` exposes `last_status` per feed for external monitoring.
