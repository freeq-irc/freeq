#!/usr/bin/env bash
#
# Manual test for embedded durable sessions (auth-broker
# unification). Exercises the mode gate live — the part that needs no browser —
# and documents the full OAuth loop for an end-to-end check.
#
#   Embedded mode  (no BROKER_SHARED_SECRET): /session is mounted in-process,
#                  backed by an ephemeral in-memory store.
#   Broker mode    (BROKER_SHARED_SECRET set): /session is NOT mounted; a
#                  separate freeq-auth-broker owns it.
#
# The automated equivalent is freeq-server/tests/embedded_session.rs.
set -euo pipefail

PORT="${PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/target/debug/freeq-server"

echo "==> Building freeq-server"
( cd "$ROOT" && cargo build -p freeq-server -q )

start() {  # $1 = extra env description; env vars already exported by caller
  "$BIN" --web-addr "127.0.0.1:${PORT}" --server-name test.local >/tmp/freeq-embed.log 2>&1 &
  SRV=$!
  # Wait for the HTTP listener.
  for _ in $(seq 1 50); do
    curl -sf "${BASE}/api/v1/health" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "server failed to start; log:"; cat /tmp/freeq-embed.log; exit 1
}
stop() { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; }

code() { curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/session" \
           -H 'content-type: application/json' -d '{"broker_token":"bogus"}'; }

echo
echo "==> Embedded mode (BROKER_SHARED_SECRET unset): /session should be mounted"
unset BROKER_SHARED_SECRET || true
start
got="$(code)"; stop
# A bogus token reaches the handler and is rejected 401 — proves it's mounted.
if [ "$got" = "401" ]; then echo "    PASS: /session mounted (bogus token -> 401)"; else
  echo "    FAIL: expected 401, got $got"; exit 1; fi

echo
echo "==> Broker mode (BROKER_SHARED_SECRET set): /session should NOT be mounted"
export BROKER_SHARED_SECRET="manual-test-secret"
start
got="$(code)"; stop
if [ "$got" = "404" ]; then echo "    PASS: /session not mounted (-> 404)"; else
  echo "    FAIL: expected 404, got $got"; exit 1; fi

cat <<'EOF'

==> Full end-to-end (needs a browser + a real AT Protocol account):
    1. Start the server embedded, pointed at a web client build:
         BROKER_SHARED_SECRET= ./target/debug/freeq-server \
           --web-addr 127.0.0.1:18080 --web-static-dir freeq-app/dist --server-name localhost
    2. Open http://127.0.0.1:18080, sign in with your handle (full OAuth).
    3. In devtools, confirm the OAuth result carries a `broker_token`.
    4. Re-run the session refresh (or reconnect after the web-token TTL):
         curl -X POST http://127.0.0.1:18080/session \
           -H 'content-type: application/json' -d "{\"broker_token\":\"<token>\"}"
       Expect 200 with a fresh { token, nick, did, handle } — no re-login.
    5. Restart the server → the same broker_token now 401s (in-memory store is
       ephemeral); the client falls back to a full sign-in. That is expected:
       embedded sessions are quick/easy, not durable-across-restart. Use a
       standalone broker for restart-durable sessions.

All mode-gate checks passed.
EOF
