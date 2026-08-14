#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# This script lives at freeq-app/deploy/staging, so the repo root is THREE up.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TMPDIR=$(mktemp -d)

echo "Preparing staging deploy in $TMPDIR..."

cp "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" "$TMPDIR/"

# Copy ALL workspace members — derived from Cargo.toml so it can never go
# stale. cargo-chef needs EVERY member on disk to extract the package graph;
# a hardcoded list (missing freeq-av, freeq-agent-kit, freeq-eliza, …) breaks
# the build with "Cannot extract package graph". Nested members (e.g.
# freeq-agent-kit/examples/*) are covered by copying the top-level dir.
for dir in $(sed -n '/^members = \[/,/^\]/p' "$REPO_ROOT/Cargo.toml" | grep -o '"[^"]*"' | tr -d '"' | cut -d/ -f1 | sort -u); do
    if [ -d "$REPO_ROOT/$dir" ] && [ ! -d "$TMPDIR/$dir" ]; then
        cp -r "$REPO_ROOT/$dir" "$TMPDIR/"
    fi
done

cp -r "$REPO_ROOT/freeq-app" "$TMPDIR/web-client"
rm -rf "$TMPDIR/web-client/node_modules" "$TMPDIR/web-client/dist" "$TMPDIR/web-client/src-tauri"

# freeq-app depends on @freeq/sdk via `file:../freeq-sdk-js`. Copy the source
# in (without node_modules/dist) so the Dockerfile can build it before web.
cp -r "$REPO_ROOT/freeq-sdk-js" "$TMPDIR/freeq-sdk-js"
rm -rf "$TMPDIR/freeq-sdk-js/node_modules" "$TMPDIR/freeq-sdk-js/dist"

cp "$SCRIPT_DIR/Dockerfile" "$TMPDIR/Dockerfile.miren"

mkdir -p "$TMPDIR/.miren"
cat > "$TMPDIR/.miren/app.toml" << 'EOF'
name = 'freeq-staging'
post_import = ''
env = []
include = []
EOF

cat > "$TMPDIR/Procfile" << 'EOF'
web: /app/freeq-server --listen-addr 127.0.0.1:16667 --web-addr 0.0.0.0:${PORT:-8080} --web-static-dir /app/web --server-name staging.freeq.at --db-path /app/data/freeq.db --data-dir /app/data --iroh --motd "freeq staging — AV with iroh-live"
EOF

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

rm -rf "$TMPDIR"
echo "Done! App should be live at https://staging.freeq.at"
