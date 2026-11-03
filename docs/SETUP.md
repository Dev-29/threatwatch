# Setup guide

- [Requirements](#requirements)
- [Option A: local install](#option-a-local-install-python)
- [Option B: Docker](#option-b-docker)
- [PostgreSQL](#postgresql)
- [Tor for .onion monitoring](#tor-for-onion-monitoring)
- [Production deployment](#production-deployment-reverse-proxy-tls-systemd)
- [First-run checklist](#first-run-checklist)
- [Verifying the installation](#verifying-the-installation)

## Requirements

| | Minimum | Notes |
|---|---|---|
| OS | Linux, macOS, Windows (WSL2 recommended) | Developed and tested on Linux |
| Python | 3.11+ | Tested on 3.12 and 3.14 |
| RAM | 512 MB | ~1 GB with all feeds enabled |
| Disk | 500 MB | SQLite DB grows ~60 MB per 100k indicators |
| Network | Outbound HTTPS (443) and DNS (53) | Active ASM also needs outbound TCP to target ports |

No API keys are required to start. Keys only add sources (see [SOURCES.md](SOURCES.md)).

## Option A: local install (Python)

```bash
git clone <your-repo-url> threatwatch && cd threatwatch
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"          # or: pip install -r requirements.txt
cp .env.example .env                        # edit as needed
.venv/bin/threatwatch serve                 # -> http://127.0.0.1:8000
```

`make install && make run` does the same. Useful variants:

```bash
make dev                         # auto-reload, scheduler off
make demo                        # load the fictional "Acme Corp" dataset (wipes data!)
make test                        # 64 tests, ~1 s
threatwatch serve --host 0.0.0.0 --port 8080
```

The database is created automatically at `./data/threatwatch.db`.

## Option B: Docker

```bash
cp .env.example .env              # set TW_API_KEY, optional feed keys
docker compose up -d --build
docker compose logs -f threatwatch
```

- The UI and API listen on `127.0.0.1:8000`. The port is bound to localhost on purpose; publish it through a TLS reverse proxy.
- Data lives in the `threatwatch-data` volume (`/data` in the container): the SQLite database and the synced ATT&CK catalogue.
- The container runs as an unprivileged user and has a health check on `/api/health`.

Run CLI commands inside the container:

```bash
docker compose exec threatwatch threatwatch feeds
docker compose exec threatwatch threatwatch asm example.com --report /data/example-report.html
docker compose exec threatwatch threatwatch seed-demo
```

## PostgreSQL

```bash
# with the bundled container
docker compose --profile postgres up -d db
echo 'TW_DATABASE_URL=postgresql+psycopg://threatwatch:threatwatch@db/threatwatch' >> .env
docker compose up -d threatwatch

# or an existing server (local install)
.venv/bin/pip install -e ".[postgres]"
export TW_DATABASE_URL='postgresql+psycopg://tw_user:secret@db.internal:5432/threatwatch'
threatwatch init-db
```

Change the default password in `docker-compose.yml` before using the bundled database for anything real.

## Tor for .onion monitoring

The `onion` connector fetches the `.onion` pages you list (forum sections, leak-site indexes) through Tor and searches them for every watchlist term.

```bash
# Docker: bundled Tor proxy
docker compose --profile tor up -d tor
cat >> .env <<'EOF'
TW_TOR_PROXY=socks5://tor:9050
TW_ONION_SOURCES=http://<forum>.onion/leaks/,http://<leaksite>.onion/
EOF
docker compose up -d threatwatch

# Local: system Tor
sudo apt install tor && sudo systemctl enable --now tor
export TW_TOR_PROXY=socks5://127.0.0.1:9050
```

Only list sources you are permitted to access and that your organisation's policy allows. See [SECURITY.md](SECURITY.md).

## Production deployment (reverse proxy, TLS, systemd)

1. **Create the first admin**: `threatwatch user add <name> --role admin` (or use the setup screen the UI shows on first visit). Add teammates under **Settings → Users**. Set `TW_API_KEY=$(openssl rand -hex 32)` as well if scripts or TAXII clients need access.
2. **Terminate TLS** in a reverse proxy. Example nginx config:

   ```nginx
   server {
       listen 443 ssl http2;
       server_name threatwatch.corp.example;
       ssl_certificate     /etc/ssl/threatwatch.crt;
       ssl_certificate_key /etc/ssl/threatwatch.key;
       client_max_body_size 200m;                # leak-file imports
       add_header Strict-Transport-Security "max-age=31536000" always;
       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_read_timeout 300s;
       }
   }
   ```

   Consider SSO in front of it as well (oauth2-proxy, Cloudflare Access, Authentik...).

3. **Run as a service** (local install), in `/etc/systemd/system/threatwatch.service`:

   ```ini
   [Unit]
   Description=ThreatWatch
   After=network-online.target
   Wants=network-online.target

   [Service]
   User=threatwatch
   WorkingDirectory=/opt/threatwatch
   EnvironmentFile=/opt/threatwatch/.env
   ExecStart=/opt/threatwatch/.venv/bin/threatwatch serve
   Restart=on-failure
   NoNewPrivileges=true
   ProtectSystem=strict
   ReadWritePaths=/opt/threatwatch/data

   [Install]
   WantedBy=multi-user.target
   ```

   Then: `sudo systemctl daemon-reload && sudo systemctl enable --now threatwatch`.

4. **Outbound access**: allow HTTPS to the source hosts in [SOURCES.md](SOURCES.md), and DNS. For egress via a proxy, set `TW_HTTP_PROXY`.
5. **Backups**: see [OPERATIONS.md](OPERATIONS.md#backups).

### Running scans from cron instead of the built-in scheduler

```cron
# /etc/cron.d/threatwatch  (with TW_SCHEDULER_ENABLED=false on the server)
15 * * * *  threatwatch cd /opt/threatwatch && .venv/bin/threatwatch feeds     >> /var/log/threatwatch.log 2>&1
30 2 * * *  threatwatch cd /opt/threatwatch && .venv/bin/threatwatch darkweb   >> /var/log/threatwatch.log 2>&1
45 3 * * *  threatwatch cd /opt/threatwatch && .venv/bin/threatwatch phishing  >> /var/log/threatwatch.log 2>&1
0 4 * * 1   threatwatch cd /opt/threatwatch && .venv/bin/threatwatch asm example.com --report data/reports/weekly.html
```

## First-run checklist

1. Open the UI and go to **Settings**. Confirm which integrations are configured.
2. In **Watchlist**, add:
   - every **domain** you own (`criticality: critical` for the primary). Domains drive dark-web domain search, look-alike monitoring and ASM.
   - **executives**: full name plus all known corporate and personal email addresses, `critical`.
   - important **emails**: IT admins, finance, shared mailboxes.
   - **brand** names and product names (used in phishing-URL and ransomware matching).
   - sensitive **keywords** (project codenames).
3. **Threat Intel → Collect feeds now**. The first run takes about 20-60 s and loads around 75k indicators.
4. **Dark Web → Run scan now**.
5. **Anti-Phishing → Scan look-alikes now**. This takes a few minutes per domain.
6. **Attack Surface → New scan** on your primary domain (passive first).
7. Optionally run `threatwatch attack-sync` to load the full MITRE ATT&CK catalogue (about 700 techniques).
8. Set `TW_ALERT_WEBHOOK_URL` to get alerts in Slack or Teams.

## Verifying the installation

```bash
curl -s http://127.0.0.1:8000/api/health            # {"status":"ok",...}
threatwatch feeds --list                             # shows which feeds need keys
threatwatch analyze-url https://example.com --no-fetch
make test
```

Interactive API documentation is at `http://127.0.0.1:8000/api/docs`.
