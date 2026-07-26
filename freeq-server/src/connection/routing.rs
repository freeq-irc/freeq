//! # Federation Routing Layer
//!
//! ## Architectural rule
//!
//! `remote_members` is a **display cache**, not a routing gate.
//!
//! It tells us what to show in NAMES, WHOIS, and WHO. It does NOT
//! determine whether a nick is reachable. The two concepts are different:
//!
//! - **Display**: "Is this nick in a channel we're tracking?" → check `remote_members`
//! - **Routing**: "Can we deliver a message to this nick?" → check local, then try S2S
//! - **Authorization**: "Is this nick an op?" → check `remote_members.is_op` / `did_ops`
//!
//! Any code that gates an **action** (PM, KICK, INVITE, MODE) on
//! `remote_members.contains_key()` is a latent asymmetric-federation bug.
//! Sync is eventually-consistent and may not have completed in both
//! directions. The receiving server doesn't need remote_members to
//! deliver a message — it just checks nick_to_session.
//!
//! ## When to use what
//!
//! | Need | Use | NOT |
//! |------|-----|-----|
//! | Send PM to nick | `relay_to_nick()` | `remote_members.contains_key()` |
//! | Show nick in NAMES | `remote_members` iteration | — |
//! | Check if nick is op | `resolve_channel_target()` | — |
//! | Kick remote user | `resolve_channel_target()` | ad-hoc remote_members scan |
//! | Invite any nick | `resolve_network_target()` | ad-hoc scan |
//! | WHOIS info | `remote_members.get()` (display) | — |
//!
//! ## Enforcement
//!
//! `scripts/lint-federation.sh` greps for patterns that indicate
//! local-only lookups or remote_members routing gates in action paths.
//! Run it in CI.

use crate::server::SharedState;
use std::sync::Arc;

/// The result of trying to route a message to a nick.
pub(crate) enum RouteResult {
    /// Nick is a local user — here's their session ID.
    Local(String),
    /// Nick is not local but we have S2S peers — message was relayed.
    Relayed,
    /// Nick is not local and we have no S2S peers — truly unreachable.
    Unreachable,
}

/// Route a PRIVMSG/NOTICE to a nick. Checks local first, then relays
/// to all S2S peers if federation is active. Never gates on
/// `remote_members` — that's a display cache, not a routing table.
///
/// When `multiline_lines` is `Some`, the message originated as a
/// `draft/multiline` BATCH and the breakdown is included in the S2S
/// relay event so the peer can re-emit BATCH frames to its own
/// multiline-capable channel members. For local-target delivery,
/// `multiline_lines` is unused — the caller (messaging.rs DM branch)
/// does its own per-receiver wire formatting via `build_dm_frames`.
pub(crate) fn relay_to_nick(
    state: &Arc<SharedState>,
    from: &str,
    account: Option<&str>,
    target: &str,
    text: &str,
    event_id: String,
    multiline_lines: Option<&[crate::connection::draft_multiline::BatchLine]>,
) -> RouteResult {
    // 1. Local delivery. A `did:` target resolves through `did_sessions`
    //    (any one bound session — the caller's fan-out reaches the rest via
    //    the DID); a nick resolves case-insensitively via `nick_to_session`.
    let local_session = if target.starts_with("did:") {
        state
            .did_sessions
            .lock()
            .get(target)
            .and_then(|s| s.iter().next().cloned())
    } else {
        let n2s = state.nick_to_session.lock();
        n2s.get_session(target).map(|s| s.to_string())
    };
    if let Some(sid) = local_session {
        return RouteResult::Local(sid);
    }

    // 2. S2S relay (if federation active)
    let has_s2s = state.s2s_manager.lock().is_some();
    if has_s2s {
        let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
        let manager = state.s2s_manager.lock().clone();
        if let Some(m) = manager {
            let (s2s_text, s2s_tags) =
                crate::s2s::encode_privmsg_text_for_s2s(text, std::collections::HashMap::new());
            m.broadcast(crate::s2s::S2sMessage::Privmsg {
                event_id,
                from: from.to_string(),
                target: target.to_string(),
                text: s2s_text,
                origin,
                msgid: None, // PM relay — no msgid (recipient server assigns)
                sig: None,   // PM relay — sig not available at routing layer
                account: account.map(|a| a.to_string()),
                recipient_did: recipient_did_for_target(state, target),
                tags: s2s_tags,
                multiline_lines: multiline_lines.map(|lines| {
                    lines
                        .iter()
                        .map(|l| crate::s2s::MultilineLine {
                            body: l.body.clone(),
                            concat: l.concat_to_previous,
                        })
                        .collect()
                }),
            });
        }
        return RouteResult::Relayed;
    }

    // 3. No federation — nick doesn't exist
    RouteResult::Unreachable
}

/// Resolve a DM target — a nick **or** a `did:` identifier — to every local
/// session that should receive it. Both forms resolve through the DID so all
/// of a user's multi-device sessions are returned:
///
/// - `did:` target → every session bound to that DID (empty if none local).
/// - nick target → the nick's session, then all sessions sharing its DID
///   (or just that one session for a guest with no DID).
/// - unknown nick → empty.
///
/// This is the single fan-out used by every DM delivery site so DID-addressed
/// and nick-addressed delivery stay identical.
pub(crate) fn local_sessions_for_target(state: &SharedState, target: &str) -> Vec<String> {
    if target.starts_with("did:") {
        return state
            .did_sessions
            .lock()
            .get(target)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
    }

    let session = match state.nick_to_session.lock().get_session(target) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    match state.session_dids.lock().get(&session).cloned() {
        Some(did) => state
            .did_sessions
            .lock()
            .get(&did)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_else(|| vec![session]),
        None => vec![session], // guest — no DID, single session
    }
}

/// Resolve a DM target — a nick or a `did:` — to the recipient's DID, if this
/// server can determine it authoritatively:
///
/// - `did:` target → itself (the address *is* the identity).
/// - nick target → the local nick→DID ownership map.
/// - a bare remote nick this server doesn't own → `None` (it can't guess; the
///   unsound alternative is resolving the nick to whoever *it* thinks it is).
///
/// Used to key DM persistence and to stamp the recipient DID onto S2S relays.
pub(crate) fn recipient_did_for_target(state: &SharedState, target: &str) -> Option<String> {
    if target.starts_with("did:") {
        // Only a plausibly-shaped DID is accepted as an authoritative recipient;
        // a junk `did:...` string must not get keyed into the durable store or
        // stamped onto a broadcast.
        return looks_like_did(target).then(|| target.to_string());
    }
    state
        .nick_owners
        .lock()
        .get(&target.to_lowercase())
        .cloned()
}

/// Cheap syntactic DID check (no network): a known method prefix and a
/// non-trivial length. Mirrors the S2S Join validation in `server.rs`.
fn looks_like_did(s: &str) -> bool {
    (s.starts_with("did:plc:") || s.starts_with("did:web:") || s.starts_with("did:key:"))
        && s.len() >= 12
        && s.len() <= 256
}

/// Reconcile a peer-stamped recipient DID against what this server resolves
/// locally, for keying a *durable* DM row. The stamp is origin-asserted and
/// unauthenticated, so:
///
/// - both present and equal → trust it (persist).
/// - both present and **different** → mismatch; fall back (return `None`, don't
///   persist a durable row under a possibly-wrong identity).
/// - only one present → use it (stamp honored when we can't resolve; local
///   resolution used when an older peer sent no stamp).
/// - neither → `None`.
pub(crate) fn reconcile_recipient_did(stamp: Option<&str>, local: Option<&str>) -> Option<String> {
    match (stamp, local) {
        (Some(s), Some(l)) if s == l => Some(s.to_string()),
        (Some(_), Some(_)) => None, // mismatch → don't persist on an unverified stamp
        (Some(s), None) => Some(s.to_string()),
        (None, Some(l)) => Some(l.to_string()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    /// Bind a DID to a set of sessions in both directions.
    fn bind_did(state: &SharedState, did: &str, sessions: &[&str]) {
        let mut ds = state.did_sessions.lock();
        let mut sd = state.session_dids.lock();
        let set = ds.entry(did.to_string()).or_default();
        for s in sessions {
            set.insert(s.to_string());
            sd.insert(s.to_string(), did.to_string());
        }
    }

    #[test]
    fn did_target_returns_all_sessions_bound_to_that_did() {
        let state = crate::server::test_state();
        bind_did(&state, "did:plc:bob", &["sess-b1", "sess-b2"]);
        state.nick_to_session.lock().insert("bob", "sess-b1");

        assert_eq!(
            sorted(local_sessions_for_target(&state, "did:plc:bob")),
            vec!["sess-b1".to_string(), "sess-b2".to_string()]
        );
    }

    #[test]
    fn nick_target_fans_out_through_its_did() {
        let state = crate::server::test_state();
        bind_did(&state, "did:plc:bob", &["sess-b1", "sess-b2"]);
        state.nick_to_session.lock().insert("bob", "sess-b1");

        // Addressing the nick reaches every device bound to the same DID.
        assert_eq!(
            sorted(local_sessions_for_target(&state, "bob")),
            vec!["sess-b1".to_string(), "sess-b2".to_string()]
        );
    }

    #[test]
    fn guest_nick_with_no_did_resolves_to_its_single_session() {
        let state = crate::server::test_state();
        state.nick_to_session.lock().insert("guest", "sess-g");

        assert_eq!(
            local_sessions_for_target(&state, "guest"),
            vec!["sess-g".to_string()]
        );
    }

    #[test]
    fn unknown_nick_or_did_resolves_to_nothing() {
        let state = crate::server::test_state();
        assert!(local_sessions_for_target(&state, "nobody").is_empty());
        assert!(local_sessions_for_target(&state, "did:plc:nobody").is_empty());
    }

    #[test]
    fn recipient_did_resolves_did_target_to_itself_and_nick_via_owners() {
        let state = crate::server::test_state();
        state
            .nick_owners
            .lock()
            .insert("bob".to_string(), "did:plc:bob".to_string());

        // A DID target is its own recipient identity.
        assert_eq!(
            recipient_did_for_target(&state, "did:plc:whoever").as_deref(),
            Some("did:plc:whoever")
        );
        // A known nick resolves through the ownership map (case-insensitive).
        assert_eq!(
            recipient_did_for_target(&state, "BOB").as_deref(),
            Some("did:plc:bob")
        );
        // A nick this server doesn't own is unresolvable — no guessing.
        assert_eq!(recipient_did_for_target(&state, "stranger"), None);
        // Junk `did:` strings are rejected — they must not reach the store.
        assert_eq!(recipient_did_for_target(&state, "did:"), None);
        assert_eq!(recipient_did_for_target(&state, "did:bogus:"), None);
        assert_eq!(recipient_did_for_target(&state, "did:plc:x"), None); // too short
    }

    #[test]
    fn reconcile_recipient_did_honors_stamp_but_refuses_mismatch() {
        // Agree → trust.
        assert_eq!(
            reconcile_recipient_did(Some("did:plc:x"), Some("did:plc:x")).as_deref(),
            Some("did:plc:x")
        );
        // Mismatch → fall back, do not persist under an unverified identity.
        assert_eq!(
            reconcile_recipient_did(Some("did:plc:x"), Some("did:plc:y")),
            None
        );
        // Only the stamp (receiver can't resolve locally) → honor it.
        assert_eq!(
            reconcile_recipient_did(Some("did:plc:x"), None).as_deref(),
            Some("did:plc:x")
        );
        // Only local (older peer sent no stamp) → today's behavior.
        assert_eq!(
            reconcile_recipient_did(None, Some("did:plc:x")).as_deref(),
            Some("did:plc:x")
        );
        assert_eq!(reconcile_recipient_did(None, None), None);
    }

    #[test]
    fn relay_to_nick_treats_a_local_did_target_as_local() {
        let state = crate::server::test_state();
        bind_did(&state, "did:plc:bob", &["sess-b1"]);
        // A DID with a local session must route Local, not fall through to relay.
        match relay_to_nick(
            &state,
            "alice",
            Some("did:plc:alice"),
            "did:plc:bob",
            "hi",
            "evt-1".to_string(),
            None,
        ) {
            RouteResult::Local(sid) => assert_eq!(sid, "sess-b1"),
            _ => panic!("expected Local for a DID with a local session"),
        }
    }
}
