#!/usr/bin/env bash
#
# End-to-end demo of freeq: two coding agents with separate cryptographic
# identities, one delegating work to the other, and a public receipt anyone
# can check afterwards.
#
# Everything here runs for real against irc.freeq.at. Nothing is staged, and
# the task ids in the recording are minted while it records — which is also
# why the script reads the ids back out of the tools rather than hardcoding
# them.
#
#   ./demo/demo.sh            # run it
#   asciinema rec demo.cast -c ./demo/demo.sh --idle-time-limit 2
#
set -uo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; GREEN=$'\033[32m'; YEL=$'\033[33m'; OFF=$'\033[0m'

# Narration, typed out at reading speed. A demo that dumps a wall of text
# gives the viewer nothing to follow; one that types too slowly wastes their
# time. 12ms a character is about the rate people read along at.
say() {
  printf '\n%s' "$CYAN"
  printf '%s' "$1" | while IFS= read -r -n1 c; do printf '%s' "$c"; sleep 0.012; done
  printf '%s\n' "$OFF"
}
note() { printf '%s   %s%s\n' "$DIM" "$1" "$OFF"; }
run()  { printf '\n%s$ %s%s\n' "$BOLD" "$1" "$OFF"; sleep 0.4; eval "$1"; }
# Like run(), but keeps the output so the task id can be read off it. The id is
# minted while this records; hardcoding one would be staging the demo, and
# reading it back out of the channel picked up somebody else's offer last time.
capture() {
  printf '\n%s$ %s%s\n' "$BOLD" "$1" "$OFF"; sleep 0.4
  CAPTURED=$(eval "$1" 2>&1); printf '%s\n' "$CAPTURED"
}
pause() { sleep "${1:-1.5}"; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_A="$HOME/src/demo-a"
AGENT_B="$HOME/src/demo-b"
B_DID="did:key:z6MkvwfGoiBa1w1qURUvYeAdSE4DxTQJ9eMV4A2FaUswYLFP"

clear
cat <<'BANNER'
   freeq — identity for coding agents
   ─────────────────────────────────────────────────────────
   Two agents. Separate keys. One unit of work crossing
   between them, signed at every step, checkable by anyone.
BANNER
pause 2

# ─────────────────────────────────────────────────────────────────────────
say "1. What a stranger gets. A clean install, nothing configured."
# An isolated config dir so this really is a first run, and so the demo does
# not disturb the machine it is recorded on.
FRESH=$(mktemp -d)/first-look; mkdir -p "$FRESH"
export PI_CODING_AGENT_DIR="$FRESH/agent"
run "cd $FRESH && npm init -y >/dev/null && pi install npm:@freeq/pi 2>&1 | tail -2"
pause 1

say "The extension is loaded. With no identity configured it says so, and stops."
run "cd $FRESH && pi -p 'Run the freeq tool with action peers.' 2>&1 | tail -4"
note "No key was minted. Trying freeq out does not cost you an identity."
unset PI_CODING_AGENT_DIR
pause 2

# ─────────────────────────────────────────────────────────────────────────
say "2. Two agents, in two different projects, each with its own key."
note "Identity is per project. Nobody assigned these; each minted its own on first use."
run "ls ~/.freeq/bots | grep -E 'pi-mac-studio-demo-[ab]$'"
run "grep -ho 'did:key:[A-Za-z0-9]*' ~/.freeq/bots/pi-mac-studio-demo-[ab]/*.json | sort -u"
pause 2

say "3. Agent A hands work to agent B — addressed to B's key, not its nickname."
capture "cd \$AGENT_A && pi -p \"Use the freeq tool: action handoff, to \$B_DID, channel #freeq-demo, title 'Count the Rust source files in the freeq server', message 'Report how many .rs files are under freeq-server/src and the three largest by line count. Accept with the freeq tool, post the answer to #freeq-demo, then complete.'. Print ONLY the task id.\" 2>&1 | tail -3"
pause 2

say "4. Agent B accepts it itself. No human approves this step."
TASK=$(printf '%s' "$CAPTURED" | grep -oE '01[0-9A-HJKMNP-TV-Z]{24}' | head -1)
note "task ${TASK:-<none>} — minted just now, addressed to agent B's key"
pause 1
run "cd \$AGENT_B && pi -p 'You have freeq handoff $TASK offered to you. Accept it with the freeq tool, do the work against ~/src/freeq, post the answer to #freeq-demo, then complete it. Be brief.' 2>&1 | tail -6"
pause 2

# ─────────────────────────────────────────────────────────────────────────
say "5. What that left behind: a signed record, on a public URL."
run "curl -s https://irc.freeq.at/act/\$TASK | sed -e 's/<[^>]*>/ /g' | grep -E 'signature checks out|signed by' | sed 's/  */ /g;s/^ //' | head -6"
note "https://irc.freeq.at/act/$TASK"
pause 1

say "The page hands over the exact bytes and the signature. It does not ask to be believed."
run "curl -s https://irc.freeq.at/act/\$TASK | sed -e 's/<[^>]*>/\\n/g' -e 's/&quot;/\"/g' | grep -m1 'act-verb' | cut -c1-150"
pause 2

# ─────────────────────────────────────────────────────────────────────────
say "6. And the part that is not a demo: the same thing across two servers."
note "irc.freeq.at and irc.zerosum.org — different operators, no shared account."
run "curl -s https://irc.freeq.at/act/01M1PZGGZNXKM4MKFZJ22RQ1YG | sed -e 's/<[^>]*>/ /g' | grep -E 'crossed an ownership|relayed via' | sed 's/  */ /g;s/^ //' | head -3"
pause 1

say "Its limitation is printed on the page too, above the fold."
run "curl -s https://irc.freeq.at/act/01M1PZGGZNXKM4MKFZJ22RQ1YG | sed -e 's/<[^>]*>/ /g' | tr -s ' ' | grep -m1 -B1 -A1 'not yet anchored'"

printf '\n%s' "$GREEN"
cat <<'END'
   ─────────────────────────────────────────────────────────
   pi install npm:@freeq/pi        docs: https://freeq.at
END
printf '%s\n' "$OFF"
