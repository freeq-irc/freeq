#!/bin/bash
# Deploy freeq-site to Miren
# Copies docs from repo root before deploying

set -e
cd "$(dirname "$0")"

# Copy docs from parent repo (these get uploaded with the deploy)
rm -rf docs
cp -r ../docs ./docs

# Write git commit hash for the /version endpoint
git -C .. rev-parse --short HEAD 2>/dev/null > .git_commit || echo "unknown" > .git_commit

echo "Deploying freeq-site (commit: $(cat .git_commit))..."
# Pin the target cluster explicitly. The site exists on more than one cluster,
# and deploying to the wrong one silently leaves the live site stale — so set
# MIREN_CLUSTER to the one your public DNS actually points at
# (`miren app list -C <cluster>` to confirm the route lives there).
CLUSTER="${MIREN_CLUSTER:-}"
if [ -z "$CLUSTER" ]; then
  echo "set MIREN_CLUSTER to the cluster serving your site's DNS" >&2
  exit 1
fi
miren deploy -f -C "$CLUSTER"

echo "Deployed! Docs will be at https://www.freeq.at/docs/"
