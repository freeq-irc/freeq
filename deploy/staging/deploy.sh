#!/bin/bash
set -e

# Deploy freeq staging (IRC server + web client) to Miren
# Uses Dockerfile.miren for multi-stage Rust + Node build

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMPDIR=$(mktemp -d)

echo "Preparing staging deploy in $TMPDIR..."

# Copy workspace root files
cp "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" "$TMPDIR/"

# Copy workspace members that freeq-server ACTUALLY depends on
cp -r "$REPO_ROOT/freeq-sdk" "$TMPDIR/"
cp -r "$REPO_ROOT/freeq-server" "$TMPDIR/"
# freeq-av-client is needed if av-native feature is enabled
[ -d "$REPO_ROOT/freeq-av-client" ] && cp -r "$REPO_ROOT/freeq-av-client" "$TMPDIR/"

# Cargo needs every workspace member referenced by Cargo.toml to exist on
# disk, even if cargo-build only compiles freeq-server. Derive the member
# list from Cargo.toml itself so this can never go stale again (nested
# members like freeq-agent-kit/examples/* are covered by copying the top-
# level directory).
for dir in $(sed -n '/^members = \[/,/^\]/p' "$REPO_ROOT/Cargo.toml" | grep -o '"[^"]*"' | tr -d '"' | cut -d/ -f1 | sort -u); do
    if [ -d "$REPO_ROOT/$dir" ] && [ ! -d "$TMPDIR/$dir" ]; then
        cp -r "$REPO_ROOT/$dir" "$TMPDIR/"
    fi
done

# Copy web client source (without node_modules/dist/tauri)
cp -r "$REPO_ROOT/freeq-app" "$TMPDIR/web-client"
rm -rf "$TMPDIR/web-client/node_modules" "$TMPDIR/web-client/dist" "$TMPDIR/web-client/src-tauri"

# freeq-app depends on @freeq/sdk via `file:../freeq-sdk-js`; copy the source
# so the Dockerfile can build it before the web client.
cp -r "$REPO_ROOT/freeq-sdk-js" "$TMPDIR/freeq-sdk-js"
rm -rf "$TMPDIR/freeq-sdk-js/node_modules" "$TMPDIR/freeq-sdk-js/dist"

# Copy Dockerfile
cp "$SCRIPT_DIR/Dockerfile" "$TMPDIR/Dockerfile.miren"

# Miren app config
mkdir -p "$TMPDIR/.miren"
cat > "$TMPDIR/.miren/app.toml" << 'EOF'
name = 'freeq-staging'
post_import = ''
env = []
include = []
EOF

# Procfile — Miren needs explicit service definition; $PORT is set by Miren
cat > "$TMPDIR/Procfile" << 'EOF'
web: /app/freeq-server --listen-addr 127.0.0.1:16667 --web-addr 0.0.0.0:${PORT:-8080} --web-static-dir /app/web --server-name staging.freeq.at --db-path /app/data/freeq.db --data-dir /app/data --iroh --motd "freeq staging — AV with iroh"
EOF

# Remove any nested .miren dirs that came from source copies
find "$TMPDIR" -mindepth 2 -name ".miren" -type d -exec rm -rf {} + 2>/dev/null || true

# Optional cluster pin — `MIREN_CLUSTER=<name>` targets a specific cluster;
# unset uses whatever the CLI is currently logged into.
CLUSTER_ARGS=()
[ -n "${MIREN_CLUSTER:-}" ] && CLUSTER_ARGS=(-C "$MIREN_CLUSTER")

cd "$TMPDIR"
echo "Deploying from $TMPDIR..."
miren deploy -f "${CLUSTER_ARGS[@]}"

echo "Setting route..."
miren route set staging.freeq.at freeq-staging "${CLUSTER_ARGS[@]}" 2>/dev/null || true

# Cleanup
rm -rf "$TMPDIR"
echo "Done! App should be live at https://staging.freeq.at"
