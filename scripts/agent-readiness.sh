#!/usr/bin/env bash
# Verify the agent-discovery surfaces promised by docs/AGENT-READINESS-ORA.md.
#
#   ./scripts/agent-readiness.sh https://freeq.at
#   ./scripts/agent-readiness.sh http://127.0.0.1:8000 site
#   ./scripts/agent-readiness.sh https://irc.freeq.at server
#
# Second argument picks the expectation set (site|server); default is inferred
# from the host. Prints one line per failure and a single PASS/FAIL summary.
#
# WHY: ora (and every crawler like it) grades the *response*, not the intent.
# A path that answers 200 text/html where JSON was promised scores worse than
# one that 404s, because the auditor calls it malformed. So every assertion
# here checks status + content-type + parseability, never just reachability.

set -uo pipefail

BASE="${1:?usage: agent-readiness.sh <base-url> [site|server]}"
BASE="${BASE%/}"
KIND="${2:-}"
if [ -z "$KIND" ]; then
  case "$BASE" in
    *irc.freeq.at*|*:80[0-9][0-9]*) KIND=server ;;
    *) KIND=site ;;
  esac
fi

pass=0; fail=0
CURL=(curl -sS --max-time 20 -A "ora-agent/1.0 (+agent-readiness.sh)")

ok()   { pass=$((pass+1)); }
bad()  { fail=$((fail+1)); printf 'FAIL  %-46s %s\n' "$1" "$2"; }

# fetch <path> -> sets HTTP_CODE, CTYPE, BODY, HDRS
fetch() {
  local path="$1" hdrfile bodyfile extra
  shift || true
  hdrfile=$(mktemp); bodyfile=$(mktemp)
  "${CURL[@]}" "$@" -D "$hdrfile" -o "$bodyfile" -w '%{http_code}\t%{content_type}' \
    "$BASE$path" > /tmp/_ar_meta 2>/dev/null
  IFS=$'\t' read -r HTTP_CODE CTYPE < /tmp/_ar_meta
  BODY=$(cat "$bodyfile"); HDRS=$(cat "$hdrfile")
  rm -f "$hdrfile" "$bodyfile"
}

# expect_json <path> [required-key ...]
expect_json() {
  local path="$1"; shift
  fetch "$path"
  if [ "$HTTP_CODE" != "200" ]; then bad "$path" "want 200, got $HTTP_CODE"; return; fi
  case "$CTYPE" in *json*) ;; *) bad "$path" "want json content-type, got ${CTYPE:-none}"; return ;; esac
  if ! printf '%s' "$BODY" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    bad "$path" "body is not valid JSON"; return
  fi
  local k
  for k in "$@"; do
    if ! printf '%s' "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if '$k' in json.dumps(d) else 1)" 2>/dev/null; then
      bad "$path" "missing expected key/value '$k'"; return
    fi
  done
  ok
}

# expect_text <path> <content-type-substring> <must-contain>
expect_text() {
  local path="$1" want_ct="$2" needle="${3:-}"
  fetch "$path"
  if [ "$HTTP_CODE" != "200" ]; then bad "$path" "want 200, got $HTTP_CODE"; return; fi
  case "$CTYPE" in *"$want_ct"*) ;; *) bad "$path" "want $want_ct, got ${CTYPE:-none}"; return ;; esac
  if [ -n "$needle" ] && ! printf '%s' "$BODY" | grep -qi -- "$needle"; then
    bad "$path" "body missing '$needle'"; return
  fi
  ok
}

expect_404() {
  local path="$1"
  fetch "$path"
  if [ "$HTTP_CODE" != "404" ]; then bad "$path" "want 404 (soft-404 = agents believe every path exists), got $HTTP_CODE ${CTYPE:-}"; return; fi
  ok
}

expect_header() {
  local path="$1" needle="$2"
  fetch "$path"
  if printf '%s' "$HDRS" | grep -qi -- "$needle"; then ok; else bad "$path" "response header missing '$needle'"; fi
}

expect_jsonld() {
  local path="$1"; shift
  fetch "$path"
  local types
  types=$(printf '%s' "$BODY" | python3 - "$@" <<'PY'
import re,sys,json
body=sys.stdin.read()
found=set()
for m in re.finditer(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', body, re.S|re.I):
    try: d=json.loads(m.group(1))
    except Exception: print("INVALID"); sys.exit(0)
    for o in (d if isinstance(d,list) else [d]):
        g=o.get('@graph') if isinstance(o,dict) else None
        for n in (g if isinstance(g,list) else [o]):
            if isinstance(n,dict) and n.get('@type'): found.add(str(n['@type']))
print(' '.join(sorted(found)) or 'NONE')
PY
)
  if [ "$types" = "INVALID" ]; then bad "$path" "JSON-LD present but does not parse"; return; fi
  local t
  for t in "$@"; do
    case " $types " in *"$t"*) ;; *) bad "$path" "JSON-LD missing @type $t (found: $types)"; return ;; esac
  done
  ok
}

expect_md_negotiation() {
  local path="$1"
  fetch "$path" -H 'Accept: text/markdown'
  case "$CTYPE" in
    *markdown*) ;;
    *) bad "$path" "Accept: text/markdown returned ${CTYPE:-none}"; return ;;
  esac
  if ! printf '%s' "$HDRS" | grep -qi '^vary:.*accept'; then
    bad "$path" "markdown negotiated but Vary: Accept missing"; return
  fi
  ok
}

echo "== agent readiness: $BASE ($KIND)"

# ---- shared expectations -------------------------------------------------
expect_text  /robots.txt   text/plain  "Sitemap:"
fetch /robots.txt
for uaname in GPTBot ClaudeBot PerplexityBot Google-Extended ora-agent; do
  if printf '%s' "$BODY" | grep -qi "$uaname"; then ok; else bad /robots.txt "no directive for $uaname"; fi
done

expect_text  /sitemap.xml  xml         "<lastmod"
expect_text  /llms.txt     markdown    "freeq"
expect_text  /agents.md    markdown    "when to use"
expect_text  /auth.md      markdown    "ATPROTO-CHALLENGE"
expect_text  /index.md     markdown    "freeq"

expect_json  /.well-known/ard.json          freeq
expect_json  /.well-known/ai-catalog.json   freeq
expect_json  /.well-known/agent-card.json   freeq
expect_json  /.well-known/api-catalog       openapi.json
expect_json  /.well-known/mcp/server-card.json freeq

expect_jsonld / Organization SoftwareApplication WebSite
expect_text  / text/html '<link rel="canonical"'
expect_text  / text/html 'og:type'
expect_header / 'link:.*rel='
expect_md_negotiation /

expect_404 /this-path-does-not-exist-9f3a
expect_404 /.well-known/this-does-not-exist-9f3a
fetch /this-path-does-not-exist-9f3a
printf '%s' "$BODY" | grep -qi 'llms.txt\|sitemap\|docs' && ok || bad "404 body" "no markdown pointers (sitemap/llms.txt/docs) in 404 body"

# ---- host-specific -------------------------------------------------------
if [ "$KIND" = "server" ]; then
  expect_json /api/v1/health '"ok"'
  expect_json /api/v1/openapi.json openapi
  expect_json /openapi.json        openapi
  expect_json /.well-known/agent.json surfaces
  expect_json /.well-known/oauth-protected-resource resource
  expect_json /.well-known/http-message-signatures-directory keys
  # 401s must say where the auth metadata lives, per RFC 9728 §5.1.
  hdr=$("${CURL[@]}" -D - -o /dev/null "$BASE/api/v1/sessions" 2>/dev/null)
  if printf '%s' "$hdr" | grep -qi 'www-authenticate:.*resource_metadata='; then ok
  else bad "/api/v1 401" "no WWW-Authenticate: Bearer resource_metadata=…"; fi
  # The SPA shell must carry crawlable text for agents that do not run JS.
  fetch /
  words=$(printf '%s' "$BODY" | sed -e 's/<script[^>]*>.*<\/script>//g' -e 's/<[^>]*>/ /g' | tr -s ' \n' ' ' | wc -c | tr -d ' ')
  if [ "$words" -ge 400 ]; then ok; else bad "/" "only ${words} chars of text without JS (want >=400)"; fi
else
  expect_text /contact/ text/html 'freeq'
  expect_text /privacy/ text/html 'freeq'
  expect_text /about/   text/html 'freeq'
  expect_text /docs/llms.txt markdown 'freeq'
fi

echo "-- $pass passed, $fail failed"
[ "$fail" -eq 0 ]
