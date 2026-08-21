#!/bin/bash
# Screenshot every rendering state of the message list, deterministically.
#
# This is the visual half of the rendering harness. The numeric half lives in
# smoke.sh (the #rowdump geometry assertions, run in CI); this half produces
# named PNGs of every state that has to *look* right — grouping, wraps, hover
# in its three regimes, reaction chips, replies, threads, system pills, block
# markdown, jumbomoji — for a human or a vision-capable agent to review.
#
# It is not a golden-image diff on purpose: macOS font rendering, materials
# and window chrome shift between OS builds, so pixel gates flake. The loop
# that works: numbers gate CI; this sweep makes states reproducible; eyes
# judge them. When you build a feature with a visual surface, ADD ITS STATES
# HERE — the cost is a few `cmd` lines, and the payoff is that the state can
# be summoned forever.
#
# Everything runs offline: #mkchannel/#inject build the timeline locally, so
# no server, no accounts, no other people. Requires an unlocked GUI session.
#
#   ./scripts/render-states.sh            → /tmp/freeq-render-states/*.png
#   OUT=/somewhere ./scripts/render-states.sh
set -uo pipefail
cd "$(dirname "$0")/.."

OUT="${OUT:-/tmp/freeq-render-states}"
CMD="$HOME/Library/Containers/at.freeq.macos/Data/tmp/freeq-cmd"
APP="${1:-build/DerivedData/Build/Products/Debug/freeq.app}"
BIN="$APP/Contents/MacOS/freeq"
[ -x "$BIN" ] || { echo "FAIL: app binary not found at $BIN (build it first)"; exit 2; }
mkdir -p "$OUT" "$(dirname "$CMD")"
: > "$CMD"

# Window capture by CGWindowID — no focus stealing, so a human can keep
# working while the sweep runs. Compile the helper on first use.
WINID=/tmp/freeq-winid
[ -x "$WINID" ] || swiftc -O ../freeq-site/staging/winid.swift -o "$WINID" 2>/dev/null || true

shot() {
  sleep 0.5
  local id=""
  [ -x "$WINID" ] && id=$("$WINID" freeq 2>/dev/null | head -1 | cut -f1)
  if [ -n "$id" ]; then screencapture -x -o -l"$id" "$OUT/$1.png"
  else screencapture -x "$OUT/$1.png"; fi
  echo "  shot $1"
}
cmd() { echo "$1" >> "$CMD"; sleep "${2:-0.9}"; }

pkill -x freeq 2>/dev/null; sleep 1.5
FREEQ_TEST_NICK=renderer FREEQ_CMD_FILE="$CMD" "$BIN" >/tmp/freeq-render-states.log 2>&1 &
APP_PID=$!
trap 'pkill -x freeq 2>/dev/null' EXIT
sleep 7
osascript -e 'tell application "System Events" to tell process "freeq" to set position of window 1 to {100,60}' \
          -e 'tell application "System Events" to tell process "freeq" to set size of window 1 to {1360,900}' 2>/dev/null
sleep 1

cmd "#mkchannel #render"
cmd "#active #render"

# ── Mixed-author timeline: grouping, headers, wraps, chips ──
cmd "#inject m1 nap will push up a stacked pr in just a few"
cmd "#inject m2 nap https://github.com/freeq-irc/freeq/pull/62 @chadfowler.com"
cmd "#sysmsg 2 joined · 3 left"
cmd "#inject m3 nap pls merge em if you like em @chadfowler.com 🥹"
cmd "#inject m4 nap then i can rebase my wip act-federation work on top of it"
cmd "#inject m5 chadfowler.com looks good to me"
cmd "#reactlocal m5 👍 nap"
cmd "#inject m6 nap a longer report that has to wrap onto a second line at this window width so the row-height math is exercised by real wrapped text"
cmd "#inject m7 chadfowler.com nice.  let me know when i should build and redeploy freeq.at"
cmd "#reactlocal m7 🎉 renderer"
shot 01-baseline

# ── Hover: the three regimes ──
cmd "#hover m7";  shot 02-hover-after-wrapped-neighbor; cmd "#hover"
cmd "#hover m5";  shot 03-hover-header-row;             cmd "#hover"
cmd "#inject m8 nap first line of a group"
cmd "#inject m9 nap second line, grouped, one line tall"
cmd "#hover m9";  shot 04-hover-grouped-one-liner;      cmd "#hover"

# ── Reactions: chip wall, wrap, self-tint, crowding the next header ──
for r in "👍 a" "❤️ b" "😂 c" "🎉 d" "👀 e" "🔥 f" "🕺 g" "💃 h" "🎶 i" "🎷 j" "👍 renderer" "👍 k"; do
  cmd "#reactlocal m8 $r" 0.15
done
cmd "#inject m10 chadfowler.com message right below the chip wall"
shot 05-reaction-wall
cmd "#hover m8"; shot 06-hover-over-chips; cmd "#hover"

# ── Replies and threads ──
cmd "#injectreply m11 nap m5 agreed, shipping it"
shot 07-reply-pill
cmd "#thread m5"; shot 08-thread-panel; cmd "#unthread"

# ── Block markdown and jumbomoji ──
cmd "#inject m12 renderer fenced code:\\n\`\`\`rust\\nfn main() { println!(\"hi\"); }\\n\`\`\`\\n> a quote line\\n- a list item"
cmd "#inject m13 nap 🎉🎷🕺"
shot 09-blocks-and-jumbo
cmd "#hover m12"; shot 10-hover-block-message; cmd "#hover"

# ── In-place growth under load: the historical killer ──
cmd "#inject m14 nap streamer target"
cmd "#editstorm 60" 0.1
sleep 3.5
cmd "#reactlocal m6 🔥 late"
cmd "#reactlocal m6 👍 later"
shot 11-after-storm-and-late-reactions

# ── The numeric verdict on everything above ──
ROWDUMP="$(dirname "$CMD")/freeq-rowdump.json"
rm -f "$ROWDUMP"; cmd "#rowdump"
for _ in $(seq 1 20); do [ -f "$ROWDUMP" ] && break; sleep 0.2; done
python3 - "$ROWDUMP" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"  geometry: UNREADABLE ({e})"); raise SystemExit(1)
bad = [r for r in d["rows"] if "intrinsicH" in r and r["rectH"] + 0.5 < r["intrinsicH"]]
if bad:
    print("  geometry: FAIL — " + ", ".join(f"{r['id']} rect={r['rectH']} content={r['intrinsicH']}" for r in bad))
    raise SystemExit(1)
print(f"  geometry: all {len(d['rows'])} rows fit their content")
PY
GEO_RC=$?

echo
echo "states → $OUT"
exit $GEO_RC
