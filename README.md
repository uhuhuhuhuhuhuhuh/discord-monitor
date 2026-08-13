# Discord Monitor

Python/Docker security monitor built around `discord.py-self`. It watches message and guild events, scores suspicious behavior, stores security history in SQLite, sends alerts to a configured channel, and keeps read-only account inventory snapshots for recovery planning.

> `discord.py-self` automates a Discord user account. Discord may prohibit this under its Terms of Service and may take action against accounts using self-bots. Use only with an account you control and understand the risk.

## Current features

### Monitoring and scoring

- Incoming vs outgoing message direction
- Suspicious URL/TLD/domain-keyword detection
- URL shortener, direct-IP, punycode, user-info, unusual-port, and brand-impersonation checks
- Social-engineering phrase detection
- Risky and double-extension attachment filename checks
- Secret/API-key/private-key detection with redaction before alert storage
- Configurable risk scoring and severity levels
- Higher weighting for suspicious outgoing content
- DM context, first-seen contact, and very-new-account context
- Outgoing message velocity and repeated-message detection
- Rapid guild-join anomaly detection
- Guild join/leave history

### Persistence and operations

- SQLite event, contact, and guild history under `./data`
- Timed rotating log files under `./logs`
- YAML rules/scoring configuration in `config.yaml`
- Non-root Docker user
- Read-only container filesystem with only runtime volumes writable
- `no-new-privileges` and dropped Linux capabilities
- Detection tests under `tests/`
- Ubuntu update helper at `scripts/update.sh`

### Dashboard

`app/webui.py` provides a read-only local dashboard with:

- Event totals and severity counts
- Recent event timeline
- Current configuration endpoint
- JSON and CSV event exports
- `/health` endpoint

The dashboard is intentionally not exposed by the default Compose service. See **Optional local WebUI** below.

### Backup and account recovery

On every successful connection the monitor writes a read-only account inventory snapshot into `./backups`. The snapshot records:

- Source account identity metadata
- Relationship/friend metadata exposed by the library
- Guild/server IDs and names
- Guild owner/member-count/icon metadata when available

The backup does **not** contain the Discord session token.

`app/migration_plan.py` and `scripts/make_migration_plan.py` can turn an inventory snapshot into an ordered recovery checklist paced across a target window of 20 to 40 minutes. Relationship and guild membership changes are marked `MANUAL_REQUIRED`; the project does not automatically mass-send friend requests or auto-join servers.

## Repository layout

```text
discord-monitor/
├── app/
│   ├── __init__.py
│   ├── account_inventory.py
│   ├── behavior.py
│   ├── config.py
│   ├── db.py
│   ├── detection.py
│   ├── migration_plan.py
│   ├── models.py
│   └── webui.py
├── backups/
├── data/
├── logs/
├── scripts/
│   ├── make_migration_plan.py
│   └── update.sh
├── tests/
│   └── test_detection.py
├── config.yaml
├── monitor.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## First Ubuntu installation

Clone the repository:

```bash
git clone https://github.com/uhuhuhuhuhuhuhuh/discord-monitor.git
cd discord-monitor
```

Create the local environment file:

```bash
cp .env.example .env
nano .env
```

At minimum set:

```env
DISCORD_TOKEN=your_real_token_here
DISCORD_TARGET_CHANNEL_ID=123456789012345678
```

Protect it:

```bash
chmod 600 .env
```

Prepare the persistent directories for the non-root container user:

```bash
mkdir -p logs data backups
sudo chown -R 10001:10001 logs data backups
```

Build and start:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
```

Watch logs:

```bash
docker compose logs -f discord-monitor
```

Persistent application log:

```bash
tail -f logs/discord_monitor.log
```

Security history is stored in:

```text
data/monitor.db
```

Account inventory snapshots appear in:

```text
backups/account-inventory-*.json
```

## Updating an existing installation

Before a major update, preserve your local state:

```bash
cp .env .env.before-update
cp config.yaml config.yaml.before-update
```

Then update and rebuild:

```bash
git pull --ff-only
sudo chown -R 10001:10001 logs data backups
docker compose build --pull
docker compose up -d --remove-orphans
docker compose ps
```

Or use the helper:

```bash
bash scripts/update.sh
```

If `config.yaml` has local edits, Git may stop the pull instead of overwriting them. Review the new repository configuration and merge your custom rules deliberately.

After updating, verify:

```bash
docker compose logs --tail=100 discord-monitor
```

You should see a successful authentication message and a newly written account inventory snapshot.

## Changing detection rules

Edit:

```bash
nano config.yaml
```

Then restart the service:

```bash
docker compose restart discord-monitor
```

The main values to tune are:

- `monitor.alert_threshold`
- `monitor.incident_threshold`
- `rules.suspicious_tlds`
- `rules.suspicious_domain_keywords`
- `rules.suspicious_phrases`
- `rules.allow_domains`
- `rules.deny_domains`
- `scoring.*`

## Running tests

On the host with Python 3.11:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q
```

Or inside a one-off Docker container:

```bash
docker compose run --rm --entrypoint sh discord-monitor -lc 'pip install pytest && pytest -q'
```

## Optional local WebUI

The WebUI is read-only and can be started separately from the monitoring process. Build the normal image first, then run a second container that receives only the database/config paths:

```bash
IMAGE="$(docker compose images -q discord-monitor)"

docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -e MONITOR_CONFIG=/app/config.yaml \
  -e MONITOR_DB=/app/data/monitor.db \
  -e WEB_HOST=0.0.0.0 \
  -e WEB_PORT=8080 \
  -v "$PWD/data:/app/data" \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  "$IMAGE" python -m app.webui
```

Then, from the Ubuntu server itself, open:

```text
http://127.0.0.1:8080
```

For remote administration, keep it bound to loopback and use an SSH tunnel rather than exposing the dashboard directly to the internet.

## Creating a migration/recovery plan

Find the latest inventory on the Ubuntu host:

```bash
LATEST="$(basename "$(ls -1t backups/account-inventory-*.json | head -n 1)")"
echo "$LATEST"
```

Create a 30-minute paced checklist:

```bash
docker compose exec discord-monitor \
  python scripts/make_migration_plan.py \
  "/app/backups/$LATEST" \
  /app/backups/migration-plan.json \
  --minutes 30
```

The planner accepts 20 to 40 minutes and calculates a suggested delay between manual recovery actions. It preserves the old account's relationship and guild references, but it does not impersonate the source account or bypass normal friend/server membership controls.

## Security notes

- Never commit `.env`.
- Never put the session token in `config.yaml`.
- Treat `backups/` and `data/` as sensitive because they contain account and security metadata.
- Keep the WebUI on loopback or behind a trusted private network/tunnel.
- If a real token is ever committed to Git history, rotate it rather than merely deleting the file in a later commit.
