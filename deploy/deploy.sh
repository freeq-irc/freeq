#!/usr/bin/env bash
# Deploy freeq updates (run after setup.sh)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "==> Pulling latest..."
git pull --ff-only

echo "==> Building server (release, with AV)..."
cargo build --release --bin freeq-server --features av-native

echo "==> Building web app (auto-builds @freeq/sdk via prebuild hook)..."
cd freeq-app
npm ci --silent
npm run build
cd "$REPO_DIR"

# Catch a bad config edit while the old server is still running, instead of
# discovering it as a crash loop after the restart. Run the check as the
# service user: the file is root:freeq 640, and this also proves the real
# service will be able to read it.
if [[ -f /etc/freeq/server.toml ]]; then
    echo "==> Validating /etc/freeq/server.toml..."
    SVC_USER=$(systemctl show -p User --value freeq-server 2>/dev/null || true)
    sudo -u "${SVC_USER:-freeq}" ./target/release/freeq-server --config /etc/freeq/server.toml --check-config
fi

echo "==> Restarting service..."
sudo systemctl restart freeq-server

echo "==> Status:"
sudo systemctl status freeq-server --no-pager
