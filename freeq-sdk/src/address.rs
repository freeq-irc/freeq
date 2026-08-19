//! DM addressing: one rule for referencing a direct-message peer.
//!
//! A DM peer can be named two ways — a nick (`"bob"`) or a DID
//! (`"did:plc:bob"`). To make a DID the load-bearing identity, the same rule
//! is applied everywhere a DM references a peer — the wire target we send to
//! AND the local buffer/thread key we file under:
//!
//! > DID when we know it, else the input unchanged.
//!
//! Because it is idempotent (DID in → same DID out) and maps a known nick to
//! the same DID, `"bob"` and `"did:plc:bob"` collapse to one conversation
//! instead of splitting into two. An unknown nick — a guest, or a remote user
//! this client hasn't learned a DID for — passes through untouched, so nick
//! addressing keeps working exactly as before.
//!
//! Channels are never routed through this (callers guard on `#`/`&` first).
//!
//! Twin of `freeq-sdk-js/src/address.ts`; the behaviours here mirror that
//! module and its tests exactly.

/// A syntactic DID: `did:<method>:<id>`. No network, no `id` validation.
/// Mirrors the JS regex `/^did:[a-z0-9]+:.+/i`: `did:`, then a non-empty
/// ASCII-alphanumeric method, then `:`, then a non-empty id.
pub fn is_did(s: &str) -> bool {
    let rest = match s.get(..4) {
        Some(p) if p.eq_ignore_ascii_case("did:") => &s[4..],
        _ => return false,
    };
    match rest.find(':') {
        // method is everything before the colon: non-empty, all alphanumeric
        Some(colon)
            if colon > 0
                && rest[..colon].bytes().all(|b| b.is_ascii_alphanumeric())
                // id is everything after: non-empty
                && colon + 1 < rest.len() =>
        {
            true
        }
        _ => false,
    }
}

/// Canonical key for a DM peer: its DID when known, else the input unchanged.
///
/// `resolve` maps a nick to its DID (`None` if unknown); a peer that is
/// already a DID is returned as-is without consulting it.
pub fn dm_peer_key<F>(peer: &str, resolve: F) -> String
where
    F: FnOnce(&str) -> Option<String>,
{
    if is_did(peer) {
        return peer.to_string();
    }
    resolve(peer).unwrap_or_else(|| peer.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_did_recognizes_dids_and_rejects_nicks_and_partials() {
        assert!(is_did("did:plc:k2n3e2vsihf3farequ44t5j7"));
        assert!(is_did("did:key:z6MkabcDEF"));
        assert!(is_did("did:web:example.com"));
        assert!(!is_did("alice"));
        assert!(!is_did("did:"));
        assert!(!is_did("did:plc:"));
        assert!(!is_did("#did:plc:x"));
    }

    /// The test resolver: nick → DID, case-insensitive, mirroring the JS test.
    fn resolver(nick: &str) -> Option<String> {
        match nick.to_lowercase().as_str() {
            "bob" => Some("did:plc:bob".to_string()),
            "alice" => Some("did:plc:alice".to_string()),
            _ => None,
        }
    }

    #[test]
    fn dm_peer_key_passes_a_did_through_unchanged() {
        assert_eq!(dm_peer_key("did:plc:bob", resolver), "did:plc:bob");
        // Idempotent even when the DID also has a nick mapped to it.
        let once = dm_peer_key("bob", resolver);
        assert_eq!(dm_peer_key(&once, resolver), "did:plc:bob");
    }

    #[test]
    fn dm_peer_key_resolves_a_known_nick_so_nick_and_did_collapse() {
        assert_eq!(dm_peer_key("bob", resolver), "did:plc:bob");
        assert_eq!(
            dm_peer_key("bob", resolver),
            dm_peer_key("did:plc:bob", resolver)
        );
    }

    #[test]
    fn dm_peer_key_leaves_an_unknown_nick_unchanged() {
        assert_eq!(dm_peer_key("carol", resolver), "carol");
    }

    #[test]
    fn dm_peer_key_does_not_lowercase_or_mangle_an_unresolvable_nick() {
        assert_eq!(dm_peer_key("Carol", resolver), "Carol");
    }
}
