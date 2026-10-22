#!/usr/bin/env bash
# FOO Camp demo station helper. Run sheet + room setup: talks/foocamp2026/.
#
#   scripts/foo-demo.sh check   # before opening: is everything the demo needs up?
#   scripts/foo-demo.sh reset   # between visitors: reconnect irssi, re-check (~10s)
#   scripts/foo-demo.sh local   # irc.freeq.at unreachable: run a server on this laptop
#   scripts/foo-demo.sh stop    # stop the local fallback server and irssi session
#
# Settings live in talks/foocamp2026/demo.env (copy demo.env.example):
#   FOO_AGENT_DID   your pi agent's DID — checked to be online and in the room
#   FOO_CHANNEL     default #foo
#
# Nothing here writes to irc.freeq.at. `#foo` is never wiped: it is the camp
# guestbook. Reset puts the station back, not the room.
set -uo pipefail
cd "$(dirname "$0")/.."

ENV_FILE="talks/foocamp2026/demo.env"
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
CHANNEL="${FOO_CHANNEL:-#foo}"
AGENT_DID="${FOO_AGENT_DID:-}"
SERVER="irc.freeq.at"
API="https://$SERVER/api/v1"
CAST="demo/freeq-demo.cast"
TMUX_SESSION="foo-irssi"
LOCAL_DIR="${TMPDIR:-/tmp}/freeq-foo-local"
LOCAL_PID="$LOCAL_DIR/server.pid"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; problems=$((problems + 1)); }
note() { printf '  \033[33m!\033[0m %s\n' "$*"; }
problems=0

urlencode() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

check_tools() {
  local missing=()
  for t in irssi tmux asciinema jq; do command -v "$t" >/dev/null || missing+=("$t"); done
  if [ ${#missing[@]} -eq 0 ]; then ok "tools: irssi tmux asciinema jq"
  else bad "missing tools: ${missing[*]} — brew install ${missing[*]}"; fi
  [ -f "$CAST" ] && ok "recording: $CAST (offline fallback)" || bad "recording missing: $CAST"
}

check_network() {
  local h
  if h=$(curl -fsS -m 8 "$API/health" 2>/dev/null); then
    ok "$SERVER up ($(jq -r '"\(.connections) connections, av=\(.av)"' <<<"$h"))"
  else
    bad "$SERVER unreachable — laptop onto the hotspot, or: scripts/foo-demo.sh local"
  fi
  curl -fsS -m 8 -o /dev/null https://world.freeq.at && ok "world.freeq.at up" \
    || bad "world.freeq.at down — skip the pixel-world beat"
  curl -fsS -m 8 -o /dev/null https://bsky.social/xrpc/_health && ok "Bluesky reachable (sign-in will work)" \
    || bad "Bluesky unreachable — hand visitors the spare signed-in device"
}

check_agent() {
  if [ -z "$AGENT_DID" ]; then note "FOO_AGENT_DID not set in $ENV_FILE — agent not checked"; return; fi
  local a
  if ! a=$(curl -fsS -m 8 "$API/actors/$AGENT_DID" 2>/dev/null); then bad "agent $AGENT_DID unknown to $SERVER"; return; fi
  local nick online inroom
  nick=$(jq -r '.nick // .handle // "agent"' <<<"$a")
  online=$(jq -r '.online' <<<"$a")
  inroom=$(jq -r --arg c "$CHANNEL" '[.channels[]? | ascii_downcase] | index($c | ascii_downcase) != null' <<<"$a")
  if [ "$online" != "true" ]; then bad "agent $nick is offline — start pi in the demo project"
  elif [ "$inroom" != "true" ]; then bad "agent $nick is online but not in $CHANNEL — /freeq join $CHANNEL"
  else ok "agent $nick online and in $CHANNEL"; fi
}

check_room() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 "$API/channels/$(urlencode "$CHANNEL")")
  case "$code" in
    200) ok "$CHANNEL exists" ;;
    404) bad "$CHANNEL doesn't exist yet — see room setup in talks/foocamp2026/README.md" ;;
    *)   note "$CHANNEL: HTTP $code (may be fine if the room is restricted)" ;;
  esac
}

# irssi as a guest, in a detached tmux session the demo screen can attach to.
ensure_irssi() {
  local host="${1:-$SERVER}" port="${2:-6697}" tls="${3:-tls}"
  command -v irssi >/dev/null && command -v tmux >/dev/null || { bad "irssi/tmux not installed"; return; }
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    # Rejoining a channel you're already in is harmless; it also recovers a drop.
    tmux send-keys -t "$TMUX_SESSION" "/join $CHANNEL" Enter
    ok "irssi session '$TMUX_SESSION' alive, rejoined $CHANNEL (tmux attach -t $TMUX_SESSION)"
  else
    # irssi has no command-line TLS switch; connect from inside instead.
    local conn="/connect $host $port"
    [ "$tls" = tls ] && conn="/connect -tls $host $port"
    tmux new-session -d -s "$TMUX_SESSION" irssi --nick=foo-guest
    sleep 2
    tmux send-keys -t "$TMUX_SESSION" "$conn" Enter
    sleep 4
    tmux send-keys -t "$TMUX_SESSION" "/join $CHANNEL" Enter
    ok "started irssi as foo-guest in tmux '$TMUX_SESSION' (tmux attach -t $TMUX_SESSION)"
  fi
}

run_local() {
  mkdir -p "$LOCAL_DIR"
  if [ -f "$LOCAL_PID" ] && kill -0 "$(cat "$LOCAL_PID")" 2>/dev/null; then
    ok "local server already running (pid $(cat "$LOCAL_PID"))"
  else
    [ -d freeq-app/dist ] || { echo "building the web app…"; (cd freeq-app && npm ci --silent && npm run build --silent) || { bad "web app build failed"; return; }; }
    echo "building freeq-server (first time takes a few minutes)…"
    cargo build --release --bin freeq-server -q || { bad "freeq-server build failed"; return; }
    (cd "$LOCAL_DIR" && nohup "$OLDPWD/target/release/freeq-server" \
        --listen-addr 127.0.0.1:6667 --web-addr 127.0.0.1:8080 \
        --web-static-dir "$OLDPWD/freeq-app/dist" > server.log 2>&1 & echo $! > server.pid)
    sleep 3
    if kill -0 "$(cat "$LOCAL_PID")" 2>/dev/null; then ok "local server up: web app http://127.0.0.1:8080, IRC 127.0.0.1:6667"
    else bad "local server exited — see $LOCAL_DIR/server.log"; return; fi
  fi
  tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
  ensure_irssi 127.0.0.1 6667 plain
  note "local mode: guests only, no Bluesky sign-in, no phones. Say so; then show the recording."
}

stop_local() {
  if [ -f "$LOCAL_PID" ] && kill "$(cat "$LOCAL_PID")" 2>/dev/null; then ok "local server stopped"; rm -f "$LOCAL_PID"
  else note "no local server running"; fi
  tmux kill-session -t "$TMUX_SESSION" 2>/dev/null && ok "irssi session closed"
}

case "${1:-check}" in
  check) echo "freeq FOO demo — pre-flight"; check_tools; check_network; check_room; check_agent; ensure_irssi ;;
  reset) echo "freeq FOO demo — reset"; check_network; check_agent; ensure_irssi ;;
  local) echo "freeq FOO demo — local fallback"; run_local ;;
  stop)  stop_local ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac

if [ "$problems" -eq 0 ]; then printf '\nready.\n'; else printf '\n%d thing(s) need you.\n' "$problems"; exit 1; fi
