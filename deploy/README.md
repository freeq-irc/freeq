# Deployment

**Map of this directory:** [`miren/`](miren/README.md) is the **recommended
self-hosting path** — a generalized, parameterized [Miren](https://miren.md/)
deploy (server + web client) any user can run from a fresh clone; start with
[deploy/miren/README.md](miren/README.md). `irc/` is the **maintainer's
bespoke production deploy** of irc.freeq.at on Miren (hardcoded app name,
route, and MOTD — reference only), and `staging/` is the same for
staging.freeq.at. `setup.sh` / `deploy.sh` are the **bare-VPS systemd path**
(Ubuntu + nginx + certbot), documented below.

## Initial Setup (Ubuntu VPS)

```sh
git clone https://github.com/freeq-irc/freeq.git
cd freeq
./deploy/setup.sh yourdomain.com [--nginx] [--iroh]
```

**Options:**
- `--nginx` — Set up nginx reverse proxy with TLS (runs certbot)
- `--iroh` — Enable iroh transport for S2S federation

The setup script:

1. Creates a dedicated `freeq` system user (no login, no home, no sudo)
2. Checks for missing apt packages and prompts to install
3. Checks for Rust/Node.js and prompts to install if missing
4. Builds the server and web app
5. Obtains a TLS cert via certbot (if `--nginx` and not already present)
6. Sets up ssl-cert group for non-root cert access
7. Generates and installs a systemd service from template
8. Creates `/etc/freeq/secrets` for environment variables
9. Creates `/var/lib/freeq/` for database storage
10. Optionally sets up nginx reverse proxy (if `--nginx`)
11. Opens firewall ports
12. Starts (or restarts) the service

The script is **idempotent** — safe to run multiple times.

## Subsequent Deploys

```sh
./deploy/deploy.sh
```

Pulls latest code, rebuilds server and web app, restarts the service.

## Secrets

Add environment variables to `/etc/freeq/secrets`. The systemd service loads this file automatically.

```sh
sudo vim /etc/freeq/secrets
```

The file is owned by `root:freeq` with mode 640 (readable by the freeq user).

## Manual Service Management

```sh
sudo systemctl status freeq-server   # Check status
sudo systemctl restart freeq-server  # Restart
sudo systemctl stop freeq-server     # Stop
sudo journalctl -u freeq-server -f   # Tail logs
```

## Files

| File | Purpose |
|------|---------|
| `setup.sh` | Initial setup (installs deps, builds, configures services) |
| `deploy.sh` | Subsequent deploys (pull, build, restart) |
| `freeq-server.service.template` | Systemd unit template (setup.sh substitutes variables) |
| `nginx.conf.template` | Nginx config template (setup.sh substitutes variables) |
| `freeq-server.service` | Chad's example systemd unit (reference only) |
| `nginx-irc-freeq-at.conf` | Chad's production nginx config (reference only) |
| `miren/` | **Recommended** generalized Miren deployment (see below) |
| `irc/` | Maintainer's Miren deploy of irc.freeq.at (reference only) |
| `staging/` | Maintainer's Miren deploy of staging.freeq.at (reference only) |

## Recommended: Miren Deployment

[Miren](https://miren.md/) is a container platform you run on your own
server. The repo ships a ready-to-use config at `.miren/app.toml`, so a
fresh clone deploys directly — no staging script:

```sh
miren deploy -e FREEQ_SERVER_NAME=irc.example.com
miren route set irc.example.com freeq
```

The committed config builds the root `Dockerfile` (server + web client),
runs `freeq-server` with `$PORT` injected, pins the app to **one fixed
instance** (in-process IRC state + SQLite must never autoscale), and
attaches a **managed disk at `/data`** so the database and server keys
survive redeploys. Secrets go in via `miren env set -s` — never into
`app.toml`.

**Requirements:** Miren CLI installed and logged in (`miren login`), TCP
80/443 + UDP 8443 open on the host, and DNS pointing your domain at the
cluster.

Full quickstart (DNS/TLS, secrets, backups, upgrades, federation, native
IRC): [deploy/miren/README.md](miren/README.md).

`irc/` and `staging/` are the maintainer's hardcoded production/staging
variants of the same approach — useful as reference, not meant to be run by
self-hosters.

## Paths

| Path | Purpose |
|------|---------|
| `/var/lib/freeq/freeq.db` | SQLite database |
| `/etc/freeq/secrets` | Environment variables (secrets) |
| `/etc/systemd/system/freeq-server.service` | Systemd unit |

## Manual Setup

If you prefer to set things up manually, the templates use these placeholders:

- `{{DOMAIN}}` — your domain (e.g. freeq.example.com)
- `{{USER}}` — system user running the service (default: `freeq`)
- `{{REPO_DIR}}` — path to the freeq repo

Example:
```sh
sed -e 's|{{DOMAIN}}|freeq.example.com|g' \
    -e 's|{{USER}}|freeq|g' \
    -e 's|{{REPO_DIR}}|/home/ubuntu/freeq|g' \
    deploy/freeq-server.service.template > /tmp/freeq-server.service

# Optional: add --iroh flag
sed -i 's|--server-name freeq.example.com \\|--server-name freeq.example.com \\\n    --iroh \\|' /tmp/freeq-server.service
```
