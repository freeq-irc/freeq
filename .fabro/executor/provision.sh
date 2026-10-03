#!/usr/bin/env bash
# Idempotent provisioning for the Fabro executor VM (boxd `fabro-freeq`).
# Run ON the VM from the repo checkout:  bash .fabro/executor/provision.sh
#
# Installs the host-side pieces Fabro runs depend on. Fabro itself, its
# secrets (ANTHROPIC_API_KEY, GitHub token), and the fabro-server systemd
# unit are set up once by hand — see .fabro/README.md "Executor setup".
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"

# ── sccache WebDAV store (warm builds across runs) ───────────────────────
command -v rclone >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq rclone; }
sudo install -d -o boxd -g boxd /var/cache/sccache
sudo install -m 0644 "$HERE/sccache-webdav.service" /etc/systemd/system/
# Evict cache entries untouched for 14 days (sccache writes, never deletes).
echo '17 3 * * * boxd find /var/cache/sccache -type f -atime +14 -delete' \
  | sudo tee /etc/cron.d/sccache-prune >/dev/null

# ── Disk hygiene ──────────────────────────────────────────────────────────
# Fabro's docker provider stops a run's container when the run ends but never
# removes it, and each one keeps its Rust target (~9 GB). Ten of them filled
# the 98 GB disk and killed a run mid-flight. Run work lives on its git
# branch, so stopped sandboxes older than 12h are disposable.
printf '%s\n' \
  '23 * * * * boxd docker container prune -f --filter until=12h >/dev/null 2>&1' \
  '47 3 * * * boxd docker builder prune -f --filter until=72h >/dev/null 2>&1' \
  | sudo tee /etc/cron.d/fabro-docker-prune >/dev/null

# ── Custom model catalog (Claude 5.5 isn't built into Fabro 0.254) ───────
if ! grep -q 'llm.models."claude-opus-5-5"' ~/.fabro/settings.toml; then
  { echo; cat "$HERE/models.toml"; } >> ~/.fabro/settings.toml
  RESTART_FABRO=1
fi

# ── Automations (cron) ────────────────────────────────────────────────────
# Fabro 0.254 loads automations from ~/.fabro/automations/, not the repo.
# Each fire clones freeq-irc/freeq@main, so the config a scheduled run sees
# is whatever is pushed to main — not this checkout.
install -d ~/.fabro/automations
if ! diff -rq "$ROOT/.fabro/automations" ~/.fabro/automations >/dev/null 2>&1; then
  cp "$ROOT"/.fabro/automations/*.toml ~/.fabro/automations/
  RESTART_FABRO=1
fi

# ── Run image ─────────────────────────────────────────────────────────────
docker build -f "$ROOT/.fabro/Dockerfile.tools" -t freeq-fabro:tools "$ROOT"

# ── freeq-fabro relay (run notifications → #freeq-dev) ───────────────────
( cd "$ROOT/freeq-bot-kit-js" && npm install --no-audit --no-fund --silent && npm run build --silent )
( cd "$ROOT/freeq-fabro" && npm install --no-audit --no-fund --silent && npm run build --silent )
ENV_FILE="$HOME/.config/freeq-fabro.env"
if [ ! -f "$ENV_FILE" ]; then
  install -d "$HOME/.config"
  cat > "$ENV_FILE" <<'ENV'
FREEQ_OWNER_DID=did:plc:4qsyxmnsblo4luuycm3572bq
FREEQ_CHANNEL=#freeq-dev
FREEQ_NICK=fabro
FABRO_REPO=freeq-irc/freeq
# Run links open through scripts/fabro-remote's tunnel.
FABRO_WEB_URL=http://127.0.0.1:32277
# #freeq-dev gates joins on accepting its rules; the owner opted in.
FREEQ_ACCEPT_POLICY=1
ENV
fi
sudo install -m 0644 "$HERE/freeq-fabro.service" /etc/systemd/system/
if ! cmp -s "$HERE/fabro-server.service" /etc/systemd/system/fabro-server.service; then
  sudo install -m 0644 "$HERE/fabro-server.service" /etc/systemd/system/
  RESTART_FABRO=1
fi
# Keep the server log from growing without bound.
printf '%s\n' '/home/boxd/.fabro/storage/logs/fabro-server.log /home/boxd/.config/freeq-fabro.log {' \
  '  weekly' '  rotate 4' '  compress' '  missingok' '  copytruncate' '}' \
  | sudo tee /etc/logrotate.d/fabro >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable --now sccache-webdav
sudo systemctl enable freeq-fabro && sudo systemctl restart freeq-fabro
[ "${RESTART_FABRO:-0}" = 1 ] && sudo systemctl restart fabro-server
echo "provisioned: sccache-webdav $(systemctl is-active sccache-webdav), freeq-fabro $(systemctl is-active freeq-fabro), image freeq-fabro:tools"
