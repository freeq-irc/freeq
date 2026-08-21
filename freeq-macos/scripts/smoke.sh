#!/usr/bin/env bash
#
# End-to-end smoke test for the macOS app's core interactions. Launches the
# built app in test mode, drives a scripted sequence through the DebugBridge,
# and ASSERTS on state snapshots — catching the class of bug this session hit
# (delete not applying, reaction/format regressions, crashes on interaction),
# not just "the process didn't die".
#
# Server-independent: uses #mkchannel + #localmsg to build state locally, so it
# runs without a live connection or channel post permissions.
#
#   ./scripts/smoke.sh [path/to/freeq.app]
#
# Exit 0 = all assertions passed and no crash; non-zero = failure.
set -uo pipefail
cd "$(dirname "$0")/.."

APP="${1:-build/DerivedData/Build/Products/Debug/freeq.app}"
BIN="$APP/Contents/MacOS/freeq"
[ -x "$BIN" ] || { echo "FAIL: app binary not found at $BIN (build it first)"; exit 2; }

# The sandbox blocks /tmp — the bridge + snapshot live in the app container.
CONTAINER="$HOME/Library/Containers/at.freeq.macos/Data/tmp"
mkdir -p "$CONTAINER"
CMD="$CONTAINER/freeq-cmd"
SNAP="$CONTAINER/freeq-snapshot.json"
rm -f "$CMD" "$SNAP"; touch "$CMD"

ROWDUMP="$CONTAINER/freeq-rowdump.json"
PRECRASH="$(ls -t "$HOME"/Library/Logs/DiagnosticReports/freeq* 2>/dev/null | head -1)"
FAILURES=0

cleanup() { pkill -9 -f "$BIN" 2>/dev/null; }
trap cleanup EXIT

send() { printf '%s\n' "$1" >> "$CMD"; sleep 0.6; }

# Take a snapshot and print it; caller asserts with `assert`.
snap() { rm -f "$SNAP"; send "#snapshot"; for _ in $(seq 1 20); do [ -f "$SNAP" ] && break; sleep 0.2; done; cat "$SNAP" 2>/dev/null; }

# assert "<label>" <python-bool-expr over `s` (the parsed snapshot dict)>
assert() {
  local label="$1"; local expr="$2"
  local ok
  ok=$(python3 - "$SNAP" "$expr" <<'PY'
import json, sys
try:
    s = json.load(open(sys.argv[1]))
except Exception as e:
    print("ERR:%s" % e); sys.exit()
print("PASS" if eval(sys.argv[2]) else "FAIL")
PY
)
  if [ "$ok" = "PASS" ]; then
    echo "  ✅ $label"
  else
    echo "  ❌ $label  ($ok)"; FAILURES=$((FAILURES+1))
  fi
}

echo "== launching $APP in test mode =="
FREEQ_TEST_NICK=smoke FREEQ_CMD_FILE="$CMD" "$BIN" >/dev/null 2>&1 &
APP_PID=$!
for _ in $(seq 1 25); do
  kill -0 "$APP_PID" 2>/dev/null || { echo "FAIL: app exited during launch"; exit 1; }
  grep -q . "$CMD" 2>/dev/null; sleep 0.4
done
sleep 3

echo "== drive core interactions =="
send "#mkchannel #smoke"
send "#localmsg m1 hello world"
send "#localmsg m2 second message"
snap >/dev/null
assert "two messages present"        "len(s['messages'])==2"
assert "active channel is #smoke"    "s['activeChannel']=='#smoke'"
assert "m1 text preserved"           "any(m['id']=='m1' and m['text']=='hello world' for m in s['messages'])"

echo "== react to the last message =="
send "/react 🎉"
snap >/dev/null
assert "reaction applied optimistically" "any(m['id']=='m2' and m['reactions'].get('🎉',0)==1 for m in s['messages'])"

echo "== delete a message =="
send "/delete m1"
snap >/dev/null
assert "delete tombstones locally"   "any(m['id']=='m1' and m['deleted'] for m in s['messages'])"

echo "== channel switch =="
send "#mkchannel #other"
send "#active #smoke"
snap >/dev/null
assert "switched back to #smoke"     "s['activeChannel']=='#smoke'"
assert "both channels exist"         "'#smoke' in s['channels'] and '#other' in s['channels']"

echo "== row geometry: no row shorter than its content =="
# The buried-wrapped-line / halved-reaction-chip class: after reactions and
# edits have mutated rows in place, every row's height must still fit its
# hosted content. Caught numerically, not by eyeballing screenshots.
rm -f "$ROWDUMP"; send "#rowdump"
for _ in $(seq 1 20); do [ -f "$ROWDUMP" ] && break; sleep 0.2; done
GEO=$(python3 - "$ROWDUMP" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"ERR:{e}"); raise SystemExit
bad = [r for r in d["rows"]
       if "intrinsicH" in r and r["rectH"] + 0.5 < r["intrinsicH"]]
print("PASS" if not bad else "FAIL:" + ",".join(
    f"{r['id']}({r['rectH']}<{r['intrinsicH']})" for r in bad))
PYEOF
)
if [ "$GEO" = "PASS" ]; then echo "  ✅ all rows fit their content"
else echo "  ❌ under-measured rows: $GEO"; FAILURES=$((FAILURES+1)); fi

echo "== stress + no crash =="
send "#stress 2000"
send "#editstorm 60"
sleep 3
kill -0 "$APP_PID" 2>/dev/null && echo "  ✅ alive after stress + editstorm" || { echo "  ❌ crashed under stress"; FAILURES=$((FAILURES+1)); }

# And again after the storm: streaming edits are the other in-place mutation
# that historically froze row heights.
rm -f "$ROWDUMP"; send "#rowdump"
for _ in $(seq 1 20); do [ -f "$ROWDUMP" ] && break; sleep 0.2; done
GEO2=$(python3 - "$ROWDUMP" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"ERR:{e}"); raise SystemExit
bad = [r for r in d["rows"]
       if "intrinsicH" in r and r["rectH"] + 0.5 < r["intrinsicH"]]
print("PASS" if not bad else "FAIL:" + ",".join(
    f"{r['id']}({r['rectH']}<{r['intrinsicH']})" for r in bad))
PYEOF
)
if [ "$GEO2" = "PASS" ]; then echo "  ✅ rows still fit after the edit storm"
else echo "  ❌ under-measured rows after storm: $GEO2"; FAILURES=$((FAILURES+1)); fi

POSTCRASH="$(ls -t "$HOME"/Library/Logs/DiagnosticReports/freeq* 2>/dev/null | head -1)"
if [ "$POSTCRASH" != "$PRECRASH" ]; then
  echo "  ❌ new crash report: $(basename "$POSTCRASH")"; FAILURES=$((FAILURES+1))
else
  echo "  ✅ no new crash report"
fi

echo
if [ "$FAILURES" -eq 0 ]; then echo "SMOKE PASSED"; exit 0
else echo "SMOKE FAILED ($FAILURES)"; exit 1; fi
