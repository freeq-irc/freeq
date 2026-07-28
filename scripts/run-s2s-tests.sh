#!/usr/bin/env bash
#
# Run S2S acceptance tests with two local servers.
#
# Starts two freeq-server instances, peers them via iroh,
# and runs the acceptance test suite against them.
#
# Usage:
#   ./scripts/run-s2s-tests.sh [extra cargo test args...]
#
# Examples:
#   ./scripts/run-s2s-tests.sh                          # run all
#   ./scripts/run-s2s-tests.sh s2s_bidirectional        # run one test
#   ./scripts/run-s2s-tests.sh single_server            # single-server only

set -euo pipefail

PORT_A=16667
PORT_B=16668

# Test identities, resolvable offline so the suite can authenticate without the
# network. Channel authority in freeq is DID-anchored (see C-2 in
# docs/SECURITY-AUDIT-2026-03-29.md: a peer's `is_op` claim is never trusted, op
# status is derived from founder_did / did_ops), so any test about ops, modes,
# topics or invites crossing a hop has to log in as a DID, not as a guest.
#
# Each entry is `did=<publicKeyMultibase>` for an ed25519 key seeded with a fixed
# byte, so the values are reproducible. They are duplicated in
# freeq-server/tests/s2s_acceptance.rs (`TEST_IDS`, one identity per test), and
# `static_identities_match_the_harness` fails if the two ever drift.
STATIC_DIDS="did:key:z6MksPykuQeYh4zgthFRFBExrgo1dwFWWenY2TEJ9SvT9jn1=z6MksPykuQeYh4zgthFRFBExrgo1dwFWWenY2TEJ9SvT9jn1,did:key:z6MkgcTiPMbTofzVghWywkKDM7SeNYnG4jPbFxerG2rVnV8A=z6MkgcTiPMbTofzVghWywkKDM7SeNYnG4jPbFxerG2rVnV8A,did:key:z6Mkw9YUWaWMuG7ZMhwtpfEytLaMZjiaxYnXe9SxDQHN64sy=z6Mkw9YUWaWMuG7ZMhwtpfEytLaMZjiaxYnXe9SxDQHN64sy,did:key:z6MkqB3fVxzXFbVUK2q1GPrLQzaxgwDGGVuxkDzaf5tsLnpo=z6MkqB3fVxzXFbVUK2q1GPrLQzaxgwDGGVuxkDzaf5tsLnpo,did:key:z6Mksp9sfVKVpWAi43niHLXfGQ5NdCTEoiycLmrLPehquVqK=z6Mksp9sfVKVpWAi43niHLXfGQ5NdCTEoiycLmrLPehquVqK,did:key:z6MkofZ1WuSJkd6UMyevdzsBVrhCtmpcq53cWATRc3jRYAxJ=z6MkofZ1WuSJkd6UMyevdzsBVrhCtmpcq53cWATRc3jRYAxJ,did:key:z6MksvxZ2oR6ogBgsCwsDSiPi3F84SDNn1yCQdVDHf5zKtKp=z6MksvxZ2oR6ogBgsCwsDSiPi3F84SDNn1yCQdVDHf5zKtKp,did:key:z6MkuBDVJTuuJUJSC4XSVeHU6ZgTqcUZM6CkCYxSJ2jNRFSr=z6MkuBDVJTuuJUJSC4XSVeHU6ZgTqcUZM6CkCYxSJ2jNRFSr,did:key:z6MkqzWvFQiKjiXi57aaSdAkYE7WbxVw8ymXA4BMshHYghPh=z6MkqzWvFQiKjiXi57aaSdAkYE7WbxVw8ymXA4BMshHYghPh,did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD=z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD,did:key:z6MkmghdggH9iwAwmMypZmN9EsfPGwsbvmum2HkFWXVzrAeE=z6MkmghdggH9iwAwmMypZmN9EsfPGwsbvmum2HkFWXVzrAeE,did:key:z6MkvS2fUtMaVsmMNMMgGzvgSCu7j11e1cvvykBcEvyvz3xW=z6MkvS2fUtMaVsmMNMMgGzvgSCu7j11e1cvvykBcEvyvz3xW"
DIR_A=$(mktemp -d)
DIR_B=$(mktemp -d)
LOG_A="$DIR_A/server.log"
LOG_B="$DIR_B/server.log"

cleanup() {
    echo ""
    echo "═══ Cleaning up ═══"
    [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null && echo "Stopped server A (pid $PID_A)"
    [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null && echo "Stopped server B (pid $PID_B)"
    # Give them a moment to exit
    sleep 1
    [ -n "${PID_A:-}" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "${PID_B:-}" ] && kill -9 "$PID_B" 2>/dev/null || true
    echo "Server A logs: $LOG_A"
    echo "Server B logs: $LOG_B"
    echo "Temp dirs: $DIR_A  $DIR_B"
}
trap cleanup EXIT

# Build
echo "═══ Building freeq-server ═══"
cargo build --release --bin freeq-server 2>&1 | tail -3

BINARY="$(pwd)/target/release/freeq-server"

# Both servers run with a database. Editing or deleting a channel message is
# authorized against the stored row's author, so a server started without one
# refuses every edit and delete — a configuration no deployment runs, and one
# that made the history tests read as product bugs.
#
# ── Start Server A (iroh enabled, no peers yet — will accept incoming) ──
echo ""
echo "═══ Starting Server A on port $PORT_A ═══"
RUST_LOG=freeq_server=info "$BINARY" \
    --listen-addr "127.0.0.1:$PORT_A" \
    --server-name "server-a" \
    --data-dir "$DIR_A" \
    --db-path "$DIR_A/irc.db" \
    --did-resolver-static "$STATIC_DIDS" \
    --iroh \
    >> "$LOG_A" 2>&1 &
PID_A=$!

# Wait for server A to print its iroh endpoint ID
echo "Waiting for Server A iroh endpoint..."
IROH_ID_A=""
for i in $(seq 1 30); do
    if grep -q "Iroh ready" "$LOG_A" 2>/dev/null; then
        IROH_ID_A=$(grep "Iroh ready" "$LOG_A" | grep -oE '[0-9a-f]{64}' | head -1)
        break
    fi
    sleep 0.5
done

if [ -z "$IROH_ID_A" ]; then
    echo "ERROR: Server A failed to start iroh"
    cat "$LOG_A"
    exit 1
fi
echo "Server A iroh ID: ${IROH_ID_A:0:16}..."

# ── Start Server B (peers with A) ──
echo ""
echo "═══ Starting Server B on port $PORT_B (peered with A) ═══"
RUST_LOG=freeq_server=info "$BINARY" \
    --listen-addr "127.0.0.1:$PORT_B" \
    --server-name "server-b" \
    --data-dir "$DIR_B" \
    --db-path "$DIR_B/irc.db" \
    --did-resolver-static "$STATIC_DIDS" \
    --iroh \
    --s2s-peers "$IROH_ID_A" \
    --s2s-allowed-peers "$IROH_ID_A" \
    >> "$LOG_B" 2>&1 &
PID_B=$!

# Wait for S2S link to establish
echo "Waiting for S2S link..."
for i in $(seq 1 30); do
    if grep -q "S2S link established" "$LOG_B" 2>/dev/null; then
        break
    fi
    if grep -q "S2S Hello received" "$LOG_A" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# Verify both servers are accepting connections
echo "Verifying servers..."
for port in $PORT_A $PORT_B; do
    if ! nc -z 127.0.0.1 $port 2>/dev/null; then
        echo "ERROR: Server on port $port not accepting connections"
        exit 1
    fi
done

# Check S2S status
if grep -q "S2S link established\|S2S Hello received" "$LOG_A" "$LOG_B" 2>/dev/null; then
    echo "✓ S2S link established"
else
    echo "⚠ S2S link may not be ready yet (continuing anyway)"
fi

# Give S2S a moment to fully sync
sleep 2

# ── Run Tests ──
echo ""
echo "═══ Running acceptance tests ═══"
echo "  Server A: 127.0.0.1:$PORT_A"
echo "  Server B: 127.0.0.1:$PORT_B"
echo ""

LOCAL_SERVER="127.0.0.1:$PORT_A" \
REMOTE_SERVER="127.0.0.1:$PORT_B" \
    cargo test -p freeq-server --test s2s_acceptance \
    -- --nocapture --test-threads 1 "$@" 2>&1 | tee tests.log

echo ""
echo "═══ Done ═══"
echo "Results in: tests.log"
echo "Server A logs: $LOG_A"
echo "Server B logs: $LOG_B"
