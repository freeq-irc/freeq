#!/bin/bash
# THE LAUNCH GATE FOR ANYTHING THAT TOUCHES AV.
#
# One command, one verdict. If this exits non-zero, the change is not ready —
# it does not matter how green the unit tests are, because none of them can
# tell you whether one person can hear another.
#
# What it runs, in order:
#
#   1. L1's `media_revocation_ordering` as a precondition — the class-A X-ray
#      (`?debug=1`) and the F6 revocation ordering. If the signaling layer is
#      broken there is no point measuring audio through it.
#   2. L2, the tone mesh: N agents join one call through the FULL lifecycle
#      (IRC connect → JOIN → av-start/av-join → wait for +freeq.at/av-token →
#      dial ?jwt&inst → publish/subscribe), each publishing a distinct sine,
#      and every agent must Goertzel-detect every other agent's tone. Then the
#      chaos steps — blip, media-kill, restart, collide, churn — each
#      re-asserting the matrix.
#
# The server is built with `--features av-native` here for the same reason
# deploy.sh hard-fails without it: a plain `cargo build` produces a binary
# whose AV endpoints all answer 503, and that shipped to production once.
#
# The L2 binary owns the server process rather than this script, because the
# `restart` chaos step has to kill and revive it mid-call — a wrapper that held
# the process could only fake that. This script builds it, provisions a temp
# data dir, and cleans up whatever is left.
#
# Usage:
#   ./scripts/avharness.sh                    # 4 agents, all chaos steps
#   ./scripts/avharness.sh --agents 6
#   ./scripts/avharness.sh --no-chaos         # baseline matrix only
#   ./scripts/avharness.sh --transport ws     # quic | ws | mixed (default)
#   ./scripts/avharness.sh --skip-l1          # L2 only (faster iteration)
#
# CI: not on the per-push path — this needs audio deps and an av-native build.
# It runs weekly and on workflow_dispatch as the `av-harness` job on macos-26.

set -euo pipefail

cd "$(dirname "$0")/.."

AGENTS=4
CHAOS=--chaos
TRANSPORT=mixed
SETTLE=8
GRACE=6
SKIP_L1=0
EXTRA=()

while [ $# -gt 0 ]; do
    case "$1" in
        --agents)    AGENTS="$2"; shift 2 ;;
        --transport) TRANSPORT="$2"; shift 2 ;;
        --settle)    SETTLE="$2"; shift 2 ;;
        --grace)     GRACE="$2"; shift 2 ;;
        --no-chaos)  CHAOS=""; shift ;;
        --skip-l1)   SKIP_L1=1; shift ;;
        -h|--help)   sed -n '2,37p' "$0"; exit 0 ;;
        *)           EXTRA+=("$1"); shift ;;
    esac
done

DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/avharness.XXXXXX")"
cleanup() {
    # The harness kills its own server on the way out; this catches the case
    # where it didn't get the chance (a panic, a Ctrl-C).
    pkill -f "server-name avharness" 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

say() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

say "building freeq-server --features av-native"
cargo build --release -p freeq-server --bin freeq-server --features av-native

say "building the L2 harness"
cargo build --release -p freeq-av-client --bin avharness

if [ "$SKIP_L1" = 0 ]; then
    say "L1 precondition: media_revocation_ordering (F6 + the class-A X-ray)"
    cargo test --release -p freeq-server --features av-native \
        --test av_lifecycle media_revocation_ordering -- --exact --nocapture
fi

say "L2: tone mesh through the full lifecycle"
./target/release/avharness \
    --server-bin ./target/release/freeq-server \
    --data-dir "$DATA_DIR" \
    --agents "$AGENTS" \
    --transport "$TRANSPORT" \
    --settle-secs "$SETTLE" \
    --grace-secs "$GRACE" \
    $CHAOS \
    ${EXTRA+"${EXTRA[@]}"}
