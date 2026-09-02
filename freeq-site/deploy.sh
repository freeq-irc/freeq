#!/bin/bash
# Deploy freeq-site to Miren
# Copies docs from repo root before deploying

set -e
cd "$(dirname "$0")"

# Copy docs from parent repo (these get uploaded with the deploy)
rm -rf docs
cp -r ../docs ./docs

# Same for the agent-facing documents both hosts serve byte-for-byte
# (agents.md, auth.md, welcome.md, tos.txt). The deploy uploads only this
# directory, so without this copy /agents.md and /auth.md 404 in production
# while passing every test locally.
rm -rf agent-docs
cp -r ../agent-docs ./agent-docs

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

# Verify we deployed the thing we think we did.
#
# A deploy that reports success while the public site serves the old build is
# the expensive failure: it happened for two weeks (#74) because the app went
# to a cluster the DNS does not point at, and every local test still passed.
# Same shape as the "av":true gate in deploy/deploy.sh.
SITE_URL="${SITE_URL:-https://freeq.at}"
WANT="$(cat .git_commit)"
echo "==> Verifying $SITE_URL serves $WANT ..."
for attempt in $(seq 1 20); do
    GOT=$(curl -fsS --max-time 10 "$SITE_URL/version" 2>/dev/null \
          | sed -n 's/.*"git_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ "$GOT" = "$WANT" ] && break
    sleep 3
done
if [ "$GOT" != "$WANT" ]; then
    echo "DEPLOY FAILED: $SITE_URL/version reports '${GOT:-nothing}', expected '$WANT'." >&2
    echo "The app deployed to cluster '$CLUSTER', but that is not what this" >&2
    echo "hostname serves. Check 'miren app list -C <cluster>' against DNS." >&2
    exit 1
fi
echo "    $SITE_URL is serving $WANT"

echo "Deployed! Docs will be at https://freeq.at/docs/"
