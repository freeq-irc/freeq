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
