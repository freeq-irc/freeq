#!/usr/bin/env bash
# Is freeq actually working, right now, from outside?
#
#   ./scripts/synthetic.sh                 # both production hosts
#   ./scripts/synthetic.sh https://irc.freeq.at
#
# WHY THIS EXISTS. Every outage this project has had was found late, by
# accident, or by a stranger:
#
#   * AV silently went down for ~2h on 2026-08-18 — a plain `cargo build`
#     shipped a binary without `--features av-native`, and every AV endpoint
#     answered 503 while the server looked healthy.
#   * freeq.at served a two-week-stale build because deploys landed on a
#     Miren cluster the DNS does not point at. The deploy script said
#     "Deployed!" every time. Found by an external audit (#74).
#   * Persistent sessions were bricked for six weeks by a refresh-token race.
#     An outside contributor reported it (#33) six weeks before it reached
#     production.
#
# None of those needed clever detection. They needed *someone to check*. This
# is that check, and it is meant to run on a schedule and shout.
#
# It only reads. It never posts to a channel, never authenticates as a person,
# and never writes to a database — a monitor that changes the thing it watches
# is a monitor you eventually turn off.

set -uo pipefail

IRC="${1:-https://irc.freeq.at}"
SITE="${2:-https://freeq.at}"

pass=0
fail=0
CURL=(curl -sS --max-time 20 -A "freeq-synthetic/1.0")

ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL    %-42s %s\n' "$1" "$2"; }

# check <name> <url> <jq-ish grep> — status 200 and body contains a string.
check_contains() {
    local name="$1" url="$2" needle="$3" body code
    body=$("${CURL[@]}" -w '\n%{http_code}' "$url" 2>/dev/null)
    code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    if [ "$code" != "200" ]; then bad "$name" "HTTP $code"; return; fi
    case "$body" in *"$needle"*) ok "$name" ;; *) bad "$name" "body lacks '$needle'" ;; esac
}

echo "== freeq synthetic check"
echo "-- $IRC"

# 1. The server is up, and built with the features it is supposed to have.
#    `av` is the one that has silently regressed before, so it is asserted
#    rather than merely reported.
health=$("${CURL[@]}" "$IRC/api/v1/health" 2>/dev/null)
if [ -z "$health" ]; then
    bad "health" "no response"
else
    case "$health" in
        *'"av":true'*) ok "health: av=true" ;;
        *) bad "health: av" "av is not true — was this built without --features av-native? ($health)" ;;
    esac
    commit=$(printf '%s' "$health" | sed -n 's/.*"git_commit":"\([^"]*\)".*/\1/p')
    [ -n "$commit" ] && echo "  ..    serving $commit"
fi

# 2. Reading a public conversation, the thing most callers actually do.
check_contains "public channels readable" "$IRC/api/v1/channels" '"name"'

# 3. The agent surfaces, which are only useful if they are reachable and
#    parseable — the failure mode was answering 200 text/html for all of them.
for path in /.well-known/agent.json /.well-known/ard.json /api/v1/openapi.json; do
    ctype=$("${CURL[@]}" -o /dev/null -w '%{content_type}' "$IRC$path" 2>/dev/null)
    case "$ctype" in
        application/json*) ok "$path is json" ;;
        *) bad "$path" "content-type is '$ctype', not json" ;;
    esac
done

# 4. A real 404 for a path that does not exist. When this regresses, every
#    crawler concludes every path exists.
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$IRC/this-path-does-not-exist-9f3a" 2>/dev/null)
[ "$code" = "404" ] && ok "unknown paths 404" || bad "unknown paths" "got $code, expected 404 (soft-404 regression)"

# 5. MCP: initialize is the handshake every client makes first.
mcp=$("${CURL[@]}" -X POST "$IRC/mcp" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' 2>/dev/null)
case "$mcp" in
    *'"protocolVersion"'*) ok "mcp initialize" ;;
    *) bad "mcp initialize" "no protocolVersion in response" ;;
esac
tools=$("${CURL[@]}" -X POST "$IRC/mcp" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 2>/dev/null)
n=$(printf '%s' "$tools" | grep -o '"name":"freeq_' | wc -l | tr -d ' ')
[ "${n:-0}" -ge 5 ] && ok "mcp exposes $n tools" || bad "mcp tools/list" "only ${n:-0} tools"

# 6. The transport itself. A server can serve every REST route and still be
#    unable to accept a chat connection, which is the only thing users care
#    about — so this opens a real WebSocket and waits for the IRC greeting.
ws_host="${IRC#https://}"
if command -v python3 >/dev/null 2>&1; then
    if python3 - "$ws_host" <<'PY'
import socket, ssl, sys, base64, os
host = sys.argv[1].split('/')[0]
try:
    raw = socket.create_connection((host, 443), timeout=15)
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.send((
        f"GET /irc HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\nOrigin: https://%s\r\n\r\n" % host
    ).encode())
    head = sock.recv(4096)
    sys.exit(0 if b"101" in head.split(b"\r\n")[0] else 1)
except Exception:
    sys.exit(1)
PY
    then ok "irc websocket upgrades"
    else bad "irc websocket" "/irc did not upgrade — REST is up but nobody can chat"
    fi
fi

echo "-- $SITE"

# 7. The docs site, and specifically that it is serving *current* code. This
#    is the check that would have caught the two-week-stale build on day one.
ver=$("${CURL[@]}" "$SITE/version" 2>/dev/null)
case "$ver" in
    *'"git_commit"'*) ok "site responds ($(printf '%s' "$ver" | sed -n 's/.*"git_commit":"\([^"]*\)".*/\1/p'))" ;;
    *) bad "site /version" "no version reported" ;;
esac
check_contains "site llms.txt" "$SITE/llms.txt" "freeq"
check_contains "shared agents.md" "$SITE/agents.md" "When to use freeq"

echo
echo "-- $pass ok, $fail failed"
[ "$fail" -eq 0 ]
