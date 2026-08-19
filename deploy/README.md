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
| `miren/` | **Recommended** generalized Miren deployment (see below) |
| `irc/` | Reference Miren deploy of a production instance |
| `staging/` | Reference Miren deploy of a staging instance |
| `av-deploy.sh` | Push/build/restart + AV TLS plumbing over SSH (set `FREEQ_SERVER`) |
| `new-host/` | Terraform + cloud-init for a self-contained single-box host |

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

`irc/` and `staging/` are opinionated production/staging variants of the same
approach with the app name, route, and MOTD baked in — useful as reference,
not meant to be run unmodified by self-hosters.

## Paths

| Path | Purpose |
|------|---------|
| `/var/lib/freeq/freeq.db` | SQLite database |
| `/etc/freeq/server.toml` | Server configuration (every CLI flag as a TOML key) |
| `/etc/freeq/secrets` | Environment variables (secrets) — env beats the config file |
| `/etc/systemd/system/freeq-server.service` | Systemd unit (just `--config /etc/freeq/server.toml`) |

## Manual Setup

The unit is a one-liner pointing at the config file; server options live in `/etc/freeq/server.toml`, not in the unit. The template uses two placeholders — `{{USER}}` (service user, default `freeq`) and `{{REPO_DIR}}` (path to the repo):

```sh
sed -e 's|{{USER}}|freeq|g' \
    -e 's|{{REPO_DIR}}|/home/ubuntu/freeq|g' \
    deploy/freeq-server.service.template | sudo tee /etc/systemd/system/freeq-server.service

sudo mkdir -p /etc/freeq
# Start from the annotated example (every key documented, commented out):
cp server.toml.example /etc/freeq/server.toml
$EDITOR /etc/freeq/server.toml   # uncomment and set listen/db/domain/etc.

# Validate before starting — a typo'd key is an error naming the key:
target/release/freeq-server --config /etc/freeq/server.toml --check-config
```

`setup.sh` writes `/etc/freeq/server.toml` on first run and never overwrites an existing one — the file belongs to the operator after that. `deploy.sh` validates it before every restart.

**Converting an existing flag-style install:** write the complete `/etc/freeq/server.toml` *first* — every flag from your current unit's `ExecStart` mapped to its key, because setup.sh's own generated file covers only the options it manages (a fresh one would silently drop e.g. S2S peer settings). With your file pre-written, re-running setup.sh is safe: it leaves the file alone, swaps the unit to `--config`, validates, and restarts.
