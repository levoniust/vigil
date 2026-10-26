# Installing Vigil

This file tells an AI coding agent how to install Vigil, a homelab watchtower dashboard. Follow the steps in order. Check each step before moving on.

## Rules

- Ask the user before anything that changes their system.
- Read-only discovery is fine without asking.
- Do not invent flags, environment variables, or options beyond what is listed here.

## Step 1. Discover

Ask the user (or check with their permission):

1. **Target machine.** Which host will run Vigil?
2. **Runtime.** Docker, TrueNAS SCALE, or plain Python 3.12+?
3. **Port.** Free host port. Default is 8080.
4. **Services.** What does the user want monitored? Ask, or (with permission) read `docker ps` output.

Record the answers. Do not install yet.

## Step 2. Install

First run with demo data so the user sees a working page before real configuration.

Demo mode simulates a made-up lab: it makes no network requests and keeps its data in a throwaway temporary folder, so it never touches the real `config.yaml`.

**Option A - Docker (no compose):**

```bash
mkdir -p vigil-data && sudo chown 1000:1000 vigil-data   # the container runs as uid 1000
docker run -d --name vigil -p 8080:8080 -v "$PWD/vigil-data:/data" -v /etc/localtime:/etc/localtime:ro --restart unless-stopped -e VIGIL_DEMO=1 ghcr.io/levoniust/vigil:latest
```

Images exist for amd64 and arm64 (Raspberry Pi 4/5).

**Option B - Docker Compose:**

Download the repository's `docker-compose.yml`, create `./data` owned by uid 1000, and uncomment the `environment: [VIGIL_DEMO=1]` line. Then `docker compose up -d`.

**Option C - Python:**

```bash
git clone https://github.com/levoniust/vigil.git && cd vigil
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
VIGIL_DEMO=1 VIGIL_DATA=./data VIGIL_PORT=8080 .venv/bin/python -m vigil
```

Once the user confirms they see the demo, stop the demo flag and restart with their real data:

- Docker: recreate the container without `-e VIGIL_DEMO=1`.
- Compose: comment the `VIGIL_DEMO` line out again, then `docker compose up -d`.
- Python: remove `VIGIL_DEMO=1` from the command.

## Step 3. Configure

The file is `vigil-data/config.yaml` (Docker), `data/config.yaml` next to `docker-compose.yml` (Compose) or `./data/config.yaml` (Python). It is created from the example on first start and hot-reloads within one minute. If the file is broken, Vigil keeps the last good config and shows the error on the page.

Only these keys exist:

| Key | Meaning |
|---|---|
| `title` | Dashboard heading |
| `interval_seconds` | Check period, must be 15 or more |
| `timeout_seconds` | Per-check timeout |
| `fail_after` | Consecutive failures before a check is marked down |
| `keep_days` | How long to keep history |
| `groups` | List of group names |
| `checks` | List of check objects |
| `nut` | List of NUT/UPS objects |
| `scrutiny_url` | Scrutiny base URL |
| `games` | List of game server objects |
| `exposure` | Internet exposure block |
| `briefing` | AI daily briefing block |
| `notify` | Alert destinations |

**Check object fields:**

- `id`, `name`, `group`
- `type`: `http` or `tcp`
- `url` (http) or `host` + `port` (tcp)
- `icon`, `link`
- `optional: true` for non-critical services
- `expect: [200]` (http only): the status codes that count as up. Without it, any answer below 500 is up
- `insecure: false` (http only): require a valid certificate. By default self-signed LAN certificates are accepted

**NUT object fields:** `name`, `host`, `port` (3493), `watts` (map of UPS name to wattage).

**Game object fields:** `name`, `type` (`valheim` or `minecraft`), `host`, `port`, `query_port` (Valheim only; default is game port + 1), `address` (the name players connect to, display only).

Use the `games` list for game servers, not a `tcp` check: Valheim uses UDP, so a TCP check on it always fails.

**Exposure block fields:** `enabled`, `expected_ports`, `domain`, `public_hosts` (list of `{name, url, planned}`), `cert_warn_days`.

**Briefing block fields:** `enabled`, `url` (OpenAI-compatible `/v1/chat/completions`), `model`, `api_key`, `headers`, `extra_body`, `time` (e.g. `"07:00"`).

**Notify block fields:** `discord_webhook`, `ntfy_url`, `ha_webhook`.

### Example

If discovery found PostgreSQL on `10.0.0.5:5432`, Nextcloud at `https://nextcloud.local` and a Valheim server on `10.0.0.9` (game port 2456), the config would be:

```yaml
title: Homelab Tower
interval_seconds: 30
timeout_seconds: 10
fail_after: 3
keep_days: 30
groups:
  - Database
  - Apps
checks:
  - id: postgres
    name: PostgreSQL
    group: Database
    type: tcp
    host: 10.0.0.5
    port: 5432
  - id: nextcloud
    name: Nextcloud
    group: Apps
    type: http
    url: https://nextcloud.local
    expect: [200]
games:
  - name: Valheim
    type: valheim
    host: 10.0.0.9
    port: 2456          # query port 2457 is used automatically
    address: valheim.example.com
```

### Exposure

The exposure section asks Shodan InternetDB about the user's public IP and crt.sh about their domain. It sends the public IP and domain to those services. Ask the user before enabling it. To switch it off, set `exposure.enabled: false`.

## Step 4. Verify

1. Open `http://HOST:PORT/` in a browser. The dashboard should load.
2. Run `curl http://HOST:PORT/healthz`. It must return `ok`.
3. If `notify` is configured, run `curl -X POST http://HOST:PORT/api/test-alert`. The user should see the alert.
4. Run `curl http://HOST:PORT/api/state`. It returns JSON with the current check results.

## Step 5. Report to the User

Tell the user:

- The URL to open.
- Which services are now monitored.
- Where the config file lives (container volume or local path).
- How to update: `docker pull` and recreate the container, or `git pull` if installed from source.
- How to uninstall: `docker rm -f vigil` and delete the data folder (Docker), `docker compose down` (Compose), or delete the cloned folder (Python, the venv is inside it).

## Safety Rules

- Never place secrets in shared or world-readable locations.
- Webhook URLs (`discord_webhook`, `ntfy_url`, `ha_webhook`) are secrets.
- Vigil does not need passwords for NUT or Scrutiny.
- Do not expose the port to the internet. The page has no login, and anyone who can reach it can trigger refreshes, briefings and test alerts.
- An LLM `api_key` in `briefing` is a secret too; keep `config.yaml` readable only by the user and the container.
