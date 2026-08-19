#!/usr/bin/env bash
# usage.sh — non-invasive usage snapshot for a freeq server.
#
# Reads the SQLite DB *read-only* (aggregate counts only, never message
# content) plus optional journald connection events. Safe to run against a
# live server.
#
# COUNTING NOTE (important): `messages.sender` is a full IRC hostmask,
# `nick!user@freeq/<class>/<prefix>`. Counting DISTINCT sender massively
# OVERCOUNTS people, because the same human appears once per device/session
# (web, macOS, iOS) and every guest reconnect mints a fresh nick. This script
# dedupes by the auth suffix (the DID prefix), and reports identity classes
# separately:
#   freeq/plc/<x>  = authenticated human (Bluesky did:plc)  <- the real count
#   freeq/key/<x>  = agent/bot (locally-minted did:key)
#   freeq/guest    = throwaway, inherently uncountable (no stable identity)
#
#   On the server:   ./scripts/usage.sh
#   From your box:   ssh "$FREEQ_SERVER" 'cd src/freeq && ./scripts/usage.sh'
#
# Env: DB=path/to/irc.db (default ./irc.db), DAYS=window for cohort (default 14)
set -euo pipefail
DB="${DB:-./irc.db}"
DAYS="${DAYS:-14}"
SECS=$(( DAYS * 86400 ))

if ! command -v sqlite3 >/dev/null; then echo "need sqlite3"; exit 1; fi
[ -f "$DB" ] || { echo "no DB at $DB (set DB=...)"; exit 1; }

sqlite3 "file:${DB}?mode=ro" <<SQL
.mode column
.headers on
.print '=== totals (all time) ==='
SELECT
  (SELECT count(*) FROM identities)                    AS dids_ever,
  (SELECT count(*) FROM messages)                      AS messages,
  (SELECT count(DISTINCT channel) FROM messages)       AS channels,
  (SELECT count(*) FROM av_sessions)                   AS av_sessions,
  (SELECT count(*) FROM av_participants)               AS av_joins;
.print ''
.print '=== activity windows ==='
SELECT 'msgs 24h'  k, count(*) v FROM messages WHERE timestamp > strftime('%s','now')-86400
UNION ALL SELECT 'msgs 7d',   count(*)          FROM messages WHERE timestamp > strftime('%s','now')-604800
UNION ALL SELECT 'talkers 24h', count(DISTINCT sender) FROM messages WHERE timestamp > strftime('%s','now')-86400
UNION ALL SELECT 'talkers 7d',  count(DISTINCT sender) FROM messages WHERE timestamp > strftime('%s','now')-604800
UNION ALL SELECT 'active chans 7d', count(DISTINCT channel) FROM messages WHERE timestamp > strftime('%s','now')-604800;
.print ''
.print '=== 7d by identity class (deduped by DID prefix) ==='
SELECT
  CASE
    WHEN sender LIKE '%@freeq/plc/%' THEN '1 authenticated human (did:plc)'
    WHEN sender LIKE '%@freeq/key/%' THEN '2 agent/bot (did:key)'
    WHEN sender LIKE '%@freeq/guest' THEN '3 guest (throwaway, uncountable)'
    ELSE '4 bare/legacy sender'
  END AS class,
  count(DISTINCT CASE WHEN sender LIKE '%@%'
                      THEN substr(sender, instr(sender,'@')+1)
                      ELSE sender END) AS identities,
  count(*) AS msgs
FROM messages WHERE timestamp > strftime('%s','now')-604800
GROUP BY class ORDER BY class;
.print ''
.print '=== the actual authenticated humans, 7d (one row per person) ==='
SELECT substr(sender, instr(sender,'@')+1) AS did_prefix,
       min(substr(sender,1,instr(sender,'!')-1)) AS nick,
       count(*) msgs, count(DISTINCT channel) chans,
       count(DISTINCT substr(sender,1,instr(sender,'!')-1)) AS nicks_used
FROM messages
WHERE timestamp > strftime('%s','now')-604800 AND sender LIKE '%@freeq/plc/%'
GROUP BY did_prefix ORDER BY msgs DESC;
.print ''
.print '=== per day (activity; people = deduped identities) ==='
SELECT date(timestamp,'unixepoch') day, count(*) msgs,
       count(DISTINCT CASE WHEN sender LIKE '%@%'
                           THEN substr(sender, instr(sender,'@')+1)
                           ELSE sender END) people
FROM messages WHERE timestamp > strftime('%s','now')-${SECS} GROUP BY day ORDER BY day;
.print ''
.print '=== NEW authenticated humans per day (first-ever message, by DID) ==='
SELECT date(first,'unixepoch') day, count(*) new_humans FROM
 (SELECT substr(sender, instr(sender,'@')+1) AS ident, min(timestamp) first
  FROM messages WHERE sender LIKE '%@freeq/plc/%' GROUP BY ident)
 WHERE first > strftime('%s','now')-${SECS} GROUP BY day ORDER BY day;
.print ''
.print '=== top channels 7d (dm:* are E2EE — counts only) ==='
SELECT substr(channel,1,48) channel, count(*) msgs, count(DISTINCT sender) people
FROM messages WHERE timestamp > strftime('%s','now')-604800
GROUP BY channel ORDER BY msgs DESC LIMIT 10;
SQL

# Optional: connection-level signal (includes lurkers who join but never talk).
if command -v journalctl >/dev/null && journalctl -u freeq-server -n1 >/dev/null 2>&1; then
  echo
  echo "=== connections (journald, last 24h) ==="
  since="24 hours ago"
  auths=$(journalctl -u freeq-server --since "$since" --no-pager 2>/dev/null | grep -c "authenticated as" || true)
  closes=$(journalctl -u freeq-server --since "$since" --no-pager 2>/dev/null | grep -c "Connection closed" || true)
  printf "authenticated_sessions=%s  connections_closed=%s\n" "${auths:-0}" "${closes:-0}"
  echo "distinct DIDs seen (24h):"
  journalctl -u freeq-server --since "$since" --no-pager 2>/dev/null \
    | grep -oE 'did=(did:[a-z0-9:._-]+)' | sort -u | wc -l
fi
