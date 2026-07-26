//! IRCv3 `draft/read-marker` support — the `MARKREAD` command.
//!
//! `MARKREAD` lets a client set and query a per-target "last read" timestamp
//! that syncs across all of a user's connections/devices. The marker is keyed
//! by the user's account (DID) and persisted in SQLite, so a marker set on a
//! phone shows up on a laptop and survives reconnects. Guests (no DID) get
//! session-local markers that live only as long as the connection — they can
//! still drive a client's own "New" line but never sync (there is no shared
//! identity to sync to).
//!
//! Wire format (spec: <https://ircv3.net/specs/extensions/read-marker>):
//!
//! - Client set:  `MARKREAD <target> timestamp=YYYY-MM-DDThh:mm:ss.sssZ`
//! - Client get:  `MARKREAD <target>`
//! - Server reply: `MARKREAD <target> timestamp=...`  (or `MARKREAD <target> *`
//!   when no marker exists).
//!
//! The marker is strictly monotonic: a set with a timestamp `<=` the stored
//! value is ignored and the server replies with the (newer) stored value. On a
//! successful advance the server replies to the requesting connection AND
//! broadcasts the new marker to the user's other `draft/read-marker`-capable
//! connections.

use std::sync::Arc;

use super::Connection;
use crate::irc::Message;
use crate::server::SharedState;

/// Standard-replies FAIL codes for `MARKREAD`, per the spec's "Errors" section.
pub mod fail_code {
    pub const NEED_MORE_PARAMS: &str = "NEED_MORE_PARAMS";
    pub const INVALID_PARAMS: &str = "INVALID_PARAMS";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
}

/// Extract the timestamp value from a `MARKREAD` set parameter.
///
/// The spec requires the parameter be spelled `timestamp=<iso>` (mirroring the
/// `server-time` tag). Returns the ISO string after the prefix, or `None` if
/// the parameter isn't in `timestamp=…` form.
pub fn extract_timestamp_value(param: &str) -> Option<&str> {
    param.strip_prefix("timestamp=")
}

/// Parse and validate an ISO-8601 marker timestamp. Returns the canonicalized
/// UTC value on success. We accept any RFC-3339 timestamp (the spec's
/// `YYYY-MM-DDThh:mm:ss.sssZ` is a strict subset) and normalize to the spec's
/// millisecond-precision `Z` form so stored markers compare and display
/// consistently regardless of the precision the client sent.
pub fn parse_marker_timestamp(ts: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    let utc = parsed.with_timezone(&chrono::Utc);
    Some(utc.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

/// Decide whether an incoming (already-validated, canonical) marker should
/// advance the stored one. The marker only ever moves forward: the incoming
/// value wins only when it is strictly greater than the current value. Ties and
/// regressions are rejected. A `None` current value (no marker yet) always
/// advances.
pub fn marker_advances(current: Option<&str>, incoming: &str) -> bool {
    match current {
        None => true,
        Some(cur) => {
            match (
                chrono::DateTime::parse_from_rfc3339(cur),
                chrono::DateTime::parse_from_rfc3339(incoming),
            ) {
                (Ok(c), Ok(i)) => i > c,
                // A stored value we can't parse shouldn't wedge the marker
                // forever — let a valid incoming value take over.
                (Err(_), Ok(_)) => true,
                _ => false,
            }
        }
    }
}

/// Handle a `MARKREAD` command (get or set).
pub(super) fn handle_markread(
    conn: &Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let target = match msg.params.first() {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::NEED_MORE_PARAMS,
                &[],
                "Missing parameters",
            );
            return;
        }
    };

    match msg.params.get(1) {
        // ── GET: `MARKREAD <target>` ──────────────────────────────────
        None => {
            let current = load_marker(conn, state, session_id, &target);
            send_marker(state, session_id, send, &target, current.as_deref());
        }
        // ── SET: `MARKREAD <target> timestamp=<iso>` ──────────────────
        Some(raw) => {
            let Some(raw_ts) = extract_timestamp_value(raw) else {
                send_fail(
                    state,
                    server_name,
                    session_id,
                    send,
                    fail_code::INVALID_PARAMS,
                    &[&target, raw],
                    "Invalid parameters",
                );
                return;
            };
            let Some(incoming) = parse_marker_timestamp(raw_ts) else {
                send_fail(
                    state,
                    server_name,
                    session_id,
                    send,
                    fail_code::INVALID_PARAMS,
                    &[&target, raw],
                    "Invalid timestamp",
                );
                return;
            };

            let current = load_marker(conn, state, session_id, &target);
            if !marker_advances(current.as_deref(), &incoming) {
                // Stale or equal — per spec, reply with the stored (newer)
                // value and ignore the client's timestamp. No broadcast.
                send_marker(state, session_id, send, &target, current.as_deref());
                return;
            }

            if !store_marker(conn, state, session_id, &target, &incoming) {
                send_fail(
                    state,
                    server_name,
                    session_id,
                    send,
                    fail_code::INTERNAL_ERROR,
                    &[&target],
                    "The read timestamp could not be set",
                );
                return;
            }

            // Confirm to the requesting connection, then fan out to the
            // user's OTHER read-marker-capable connections (multi-device).
            send_marker(state, session_id, send, &target, Some(&incoming));
            broadcast_marker(conn, state, session_id, &target, &incoming);
        }
    }
}

/// The durable storage key for a read marker. Channels key by their name;
/// a DM keys by the canonical `dm:<didA>,<didB>` so the marker is tied to
/// the conversation, not the alias used to address it (nick vs DID) — both
/// resolve to one key. Guests and unresolvable nicks fall back to the raw
/// target (session-local, ephemeral anyway).
fn marker_storage_key(conn: &Connection, target: &str, state: &Arc<SharedState>) -> String {
    if target.starts_with('#') || target.starts_with('&') {
        return target.to_string();
    }
    super::messaging::dm_canonical_key(conn, target, state).unwrap_or_else(|| target.to_string())
}

/// Read the current marker for `target`: from SQLite for DID users, from the
/// session-local map for guests.
fn load_marker(
    conn: &Connection,
    state: &Arc<SharedState>,
    session_id: &str,
    target: &str,
) -> Option<String> {
    if let Some(ref did) = conn.authenticated_did {
        let key = marker_storage_key(conn, target, state);
        state.with_db(|db| db.get_read_marker(did, &key)).flatten()
    } else {
        state
            .session_read_markers
            .lock()
            .get(session_id)
            .and_then(|m| m.get(target).cloned())
    }
}

/// Persist an advanced marker: SQLite for DID users, session-local map for
/// guests. Returns `false` when a DID user's write couldn't be durably stored
/// (no DB configured, or a DB error) so the caller can surface
/// `FAIL MARKREAD INTERNAL_ERROR` rather than silently claim success. Guest
/// writes are in-memory and always succeed.
fn store_marker(
    conn: &Connection,
    state: &Arc<SharedState>,
    session_id: &str,
    target: &str,
    timestamp: &str,
) -> bool {
    if let Some(ref did) = conn.authenticated_did {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = marker_storage_key(conn, target, state);
        state
            .with_db(|db| db.set_read_marker(did, &key, timestamp, now))
            .is_some()
    } else {
        state
            .session_read_markers
            .lock()
            .entry(session_id.to_string())
            .or_default()
            .insert(target.to_string(), timestamp.to_string());
        true
    }
}

/// Send a `MARKREAD <target> <value>` line to one session, where `<value>` is
/// `timestamp=<iso>` or `*` when there is no marker.
fn send_marker(
    state: &Arc<SharedState>,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
    target: &str,
    timestamp: Option<&str>,
) {
    send(
        state,
        session_id,
        format!("{}\r\n", marker_line(target, timestamp)),
    );
}

/// Build the bare `MARKREAD <target> <value>` line (no prefix, matching the
/// spec's examples).
fn marker_line(target: &str, timestamp: Option<&str>) -> String {
    match timestamp {
        Some(ts) => format!("MARKREAD {target} timestamp={ts}"),
        None => format!("MARKREAD {target} *"),
    }
}

/// Broadcast an advanced marker to the user's OTHER connections that
/// negotiated `draft/read-marker`. Only DID-authenticated users have other
/// connections to sync to; guests are session-local and this is a no-op.
fn broadcast_marker(
    conn: &Connection,
    state: &Arc<SharedState>,
    session_id: &str,
    target: &str,
    timestamp: &str,
) {
    let Some(ref did) = conn.authenticated_did else {
        return;
    };
    let others: Vec<String> = {
        let did_sessions = state.did_sessions.lock();
        let cap = state.cap_read_marker.lock();
        did_sessions
            .get(did)
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|sid| sid.as_str() != session_id && cap.contains(*sid))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    };
    if others.is_empty() {
        return;
    }
    let line = format!("{}\r\n", marker_line(target, Some(timestamp)));
    let conns = state.connections.lock();
    for sid in &others {
        if let Some(tx) = conns.get(sid) {
            let _ = tx.try_send(line.clone());
        }
    }
}

/// Emit a `FAIL MARKREAD <code> [<args>...] :<reason>` standard reply.
fn send_fail(
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
    code: &str,
    extra_args: &[&str],
    human_reason: &str,
) {
    let mut params: Vec<&str> = vec!["MARKREAD", code];
    params.extend_from_slice(extra_args);
    params.push(human_reason);
    let reply = Message::from_server(server_name, "FAIL", params);
    send(state, session_id, format!("{reply}\r\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_requires_timestamp_prefix() {
        assert_eq!(
            extract_timestamp_value("timestamp=2019-09-25T20:41:57.014Z"),
            Some("2019-09-25T20:41:57.014Z")
        );
        assert_eq!(extract_timestamp_value("2019-09-25T20:41:57.014Z"), None);
        assert_eq!(extract_timestamp_value("*"), None);
        assert_eq!(extract_timestamp_value("ts=2019"), None);
    }

    #[test]
    fn parse_accepts_spec_format_and_normalizes_to_millis() {
        assert_eq!(
            parse_marker_timestamp("2019-09-25T20:41:57.014Z").as_deref(),
            Some("2019-09-25T20:41:57.014Z")
        );
        // Second precision is normalized up to millis.
        assert_eq!(
            parse_marker_timestamp("2019-09-25T20:41:57Z").as_deref(),
            Some("2019-09-25T20:41:57.000Z")
        );
        // A non-Z offset is normalized to UTC.
        assert_eq!(
            parse_marker_timestamp("2019-09-25T21:41:57.000+01:00").as_deref(),
            Some("2019-09-25T20:41:57.000Z")
        );
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(parse_marker_timestamp("not-a-date"), None);
        assert_eq!(parse_marker_timestamp(""), None);
        assert_eq!(parse_marker_timestamp("2019-13-99T99:99:99Z"), None);
        assert_eq!(parse_marker_timestamp("*"), None);
    }

    #[test]
    fn marker_only_moves_forward() {
        // No current → any valid value advances.
        assert!(marker_advances(None, "2019-09-25T20:41:57.014Z"));
        // Strictly greater advances.
        assert!(marker_advances(
            Some("2019-09-25T20:41:57.014Z"),
            "2019-09-25T20:41:58.000Z"
        ));
        // Equal does NOT advance.
        assert!(!marker_advances(
            Some("2019-09-25T20:41:57.014Z"),
            "2019-09-25T20:41:57.014Z"
        ));
        // Older does NOT advance.
        assert!(!marker_advances(
            Some("2019-09-25T20:41:57.014Z"),
            "2019-09-25T20:41:50.000Z"
        ));
    }

    #[test]
    fn unparseable_stored_value_yields_to_valid_incoming() {
        assert!(marker_advances(Some("garbage"), "2019-09-25T20:41:57.014Z"));
    }

    #[test]
    fn marker_line_formats_present_and_absent() {
        assert_eq!(
            marker_line("#chan", Some("2019-09-25T20:41:57.014Z")),
            "MARKREAD #chan timestamp=2019-09-25T20:41:57.014Z"
        );
        assert_eq!(marker_line("#chan", None), "MARKREAD #chan *");
    }
}
