//! Signing and verification for `freeq.at/act` action messages.
//!
//! Implements the act canonical from the act RFC (docs/HANDOFF-RFC.md, v0.4):
//! the signature covers **every `act-*` tag present** on the message — not a
//! fixed field list — JCS-canonicalized (RFC 8785) with sorted keys. Adding or
//! stripping an `act-*` tag in transit changes the rebuilt canonical, so
//! tampering is detected by construction.
//!
//! ## Only the sender writes `act-` tags
//!
//! The open coverage rule is what lets a new task kind add fields without
//! anyone updating a canonical — and it only works under one discipline: an
//! `act-` tag is written by the sender and by nobody else. A server that
//! stamped a tag of its own under that prefix would land it inside the
//! signature's coverage and break every act signature it relayed. Server
//! attestations go in their own namespaces (`account`, `time`, `msgid`,
//! `+freeq.at/origin`), exactly as they do for chat.
//!
//! Canonical mapping rules (frozen by the fixtures in
//! `spec/act-signing-vectors.json`, which the TS implementation must
//! reproduce byte-for-byte):
//!
//! - A tag is covered iff its name, after stripping the `+freeq.at/`
//!   client-tag prefix, is `act` or starts with `act-`. (`actor-class` does
//!   NOT match; `sig` does not match.) The unprefixed forms are accepted too.
//! - Canonical keys are the **stripped** names — the vendor prefix is wire
//!   framing, not semantics, so signatures survive a future de-vendoring of
//!   the tag names.
//! - Values are the (IRC-unescaped) tag values, verbatim, always JSON
//!   strings — `act-deadline` is not coerced to a number.
//! - Two more keys are **injected by the caller**, never read from a tag, and
//!   the same two chat's documents carry (see [`crate::chatsig`]):
//!   - **`target`** — the normalized venue ([`crate::chatsig::channel_venue`]
//!     / [`crate::chatsig::dm_venue`]), supplied by the signer and rebuilt by
//!     the verifier from delivery context. The channel is the queue: without
//!     it, an offer signed in one room replays into another with its
//!     signature intact.
//!   - **`msgid`** — the event id the signer minted, riding the wire in
//!     [`crate::chatsig::EVENT_ID_TAG`]. A task's id is its identity for the
//!     rest of its life, so it cannot be the one unsigned thing about it.
//!
//!   Neither name can collide with a covered tag: every covered key starts
//!   with `act`.
//! - An offer carries no `act-id` — its own event id *is* the task's id. The
//!   later events in a task's life name that id in `act-id` and mint their
//!   own id for themselves.
//! - The canonical bytes are the UTF-8 of `canonical::canonicalize` over
//!   that string→string map.
//!
//! The sig tag value is `ed25519:<kid>:<base64url sig>` — the format shared
//! by every freeq signing profile, which lives in [`crate::sigtag`] (kid
//! derivation, parsing, the raw sign/verify over canonical bytes) so the act
//! and chat profiles cannot disagree about it.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};

// The kid rule is shared, not act-specific: re-exported here so existing
// `freeq_sdk::act::derive_kid*` callers (the server's key store, the fixtures)
// keep working while there is exactly one implementation.
pub use crate::sigtag::{SIG_TAG, derive_kid, derive_kid_bytes};

const CLIENT_TAG_PREFIX: &str = "+freeq.at/";
const TAG_PREFIX: &str = "freeq.at/";

/// Why an act signature failed to verify.
///
/// `KidMismatch` is worth distinguishing: it means "this is not the key the
/// signature names" — a lookup-layer problem — where `SigInvalid` means the
/// named key was used and the bytes still don't verify (tampering/forgery).
#[derive(Debug, PartialEq, Eq)]
pub enum ActSigError {
    /// No `act`/`act-*` tags present — nothing to sign or verify.
    NoActTags,
    /// The sig tag is not `alg:kid:sig`.
    BadSigFormat,
    /// The sig tag names an algorithm other than `ed25519`.
    UnsupportedAlgorithm(String),
    /// The supplied public key does not hash to the kid the sig names.
    KidMismatch,
    /// Canonical rebuilt and key matched the kid, but the signature is wrong:
    /// a covered tag was added, stripped, or altered — or the sig is forged.
    SigInvalid,
}

impl std::fmt::Display for ActSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActSigError::NoActTags => write!(f, "no act-* tags present"),
            ActSigError::BadSigFormat => write!(f, "sig tag is not alg:kid:sig"),
            ActSigError::UnsupportedAlgorithm(a) => write!(f, "unsupported sig algorithm {a}"),
            ActSigError::KidMismatch => write!(f, "public key does not match the sig's kid"),
            ActSigError::SigInvalid => write!(f, "signature does not verify over the act tags"),
        }
    }
}

impl std::error::Error for ActSigError {}

impl From<crate::sigtag::SigError> for ActSigError {
    fn from(e: crate::sigtag::SigError) -> Self {
        match e {
            crate::sigtag::SigError::BadFormat => ActSigError::BadSigFormat,
            crate::sigtag::SigError::UnsupportedAlgorithm(a) => {
                ActSigError::UnsupportedAlgorithm(a)
            }
            crate::sigtag::SigError::KidMismatch => ActSigError::KidMismatch,
            crate::sigtag::SigError::Invalid => ActSigError::SigInvalid,
        }
    }
}

/// Strip the client-tag vendor prefix from a tag name, if present.
fn stripped_name(tag_name: &str) -> &str {
    tag_name
        .strip_prefix(CLIENT_TAG_PREFIX)
        .or_else(|| tag_name.strip_prefix(TAG_PREFIX))
        .unwrap_or(tag_name)
}

/// Whether a (possibly prefixed) tag name is covered by the act canonical.
fn is_act_tag(tag_name: &str) -> bool {
    let name = stripped_name(tag_name);
    name == "act" || name.starts_with("act-")
}

/// Build the canonical string over the act tags in `tags`, the venue, and the
/// event id.
///
/// `tags` is the message's tag map with wire names (prefixed or not) and
/// unescaped values. `target` is the normalized venue and `msgid` the id the
/// signer minted; both are supplied by the caller — a verifier rebuilds them
/// from delivery context rather than reading either off a tag. Returns `None`
/// if no act tags are present: delivery context alone is not a document.
pub fn act_canonical<'a, I>(tags: I, target: &'a str, msgid: &'a str) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut covered: BTreeMap<&str, &str> = tags
        .into_iter()
        .filter(|(name, _)| is_act_tag(name))
        .map(|(name, value)| (stripped_name(name), value))
        .collect();
    if covered.is_empty() {
        return None;
    }
    // Injected by the caller, never read from a tag — and they cannot collide
    // with a covered key, every one of which starts with `act`.
    covered.insert("target", target);
    covered.insert("msgid", msgid);
    // BTreeMap serializes with sorted keys; canonicalize re-sorts per JCS
    // (codepoint order) and applies JSON string escaping.
    Some(crate::canonical::canonicalize(&covered).expect("string map serializes"))
}

/// Sign the act tags in `tags`, posted to `target` under `msgid`, with `key`.
/// Returns the sig tag value (`ed25519:<kid>:<base64url sig>`), or `None` if
/// no act tags are present.
pub fn sign_act<'a, I>(tags: I, target: &'a str, msgid: &'a str, key: &SigningKey) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    Some(crate::sigtag::sign_canonical(
        &act_canonical(tags, target, msgid)?,
        key,
    ))
}

/// Parse a sig tag value into (kid, signature bytes).
pub fn parse_sig_tag(sig_tag: &str) -> Result<(&str, [u8; 64]), ActSigError> {
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)
}

/// Verify an act signature over the act tags in `tags` against `key`.
///
/// `target` and `msgid` come from the receiver's own view of the delivery —
/// the venue the message arrived in and the id it is being filed under — so a
/// message replayed elsewhere, or filed under another id, reads as tampering.
pub fn verify_act<'a, I>(
    tags: I,
    target: &'a str,
    msgid: &'a str,
    sig_tag: &str,
    key: &VerifyingKey,
) -> Result<(), ActSigError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    // Shape and kid first, so a missing canonical isn't reported as a format
    // problem and a wrong key isn't reported as tampering.
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)?;
    let canonical = act_canonical(tags, target, msgid).ok_or(ActSigError::NoActTags)?;
    crate::sigtag::verify_canonical(&canonical, sig_tag, key).map_err(ActSigError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// The venue and the signer-minted event id of the directed-offer vector.
    ///
    /// The offer's own event id *is* the task's id, which is why the accept
    /// vector's `act-id` carries this same value.
    const OFFER_VENUE: &str = "#ops";
    const OFFER_ID: &str = "01JABCDEF000000000000000EF";

    /// The RFC's directed-offer example, as a wire tag map (plus tags that
    /// must NOT be covered as tags: sig, eventid, msgid, actor-class).
    fn offer_tags() -> Vec<(&'static str, &'static str)> {
        vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/act-from", "did:plc:eliza"),
            ("+freeq.at/act-to", "did:plc:scholar"),
            ("+freeq.at/act-title", "Cite 3 sources on X"),
            ("+freeq.at/act-ctx-h", "sha256:9f00"),
            ("+freeq.at/act-caps", "freeq.at/web-search"),
            ("+freeq.at/act-deadline", "1788000000"),
            ("+freeq.at/sig", "ed25519:notcovered:notcovered"),
            ("+freeq.at/eventid", OFFER_ID),
            ("msgid", "01JSERVERMINTED0000000000"),
            ("+freeq.at/actor-class", "agent"),
        ]
    }

    #[test]
    fn canonical_covers_act_tags_the_venue_and_the_event_id() {
        let canonical = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        assert_eq!(
            canonical,
            r##"{"act":"handoff","act-caps":"freeq.at/web-search","act-ctx-h":"sha256:9f00","act-deadline":"1788000000","act-from":"did:plc:eliza","act-title":"Cite 3 sources on X","act-to":"did:plc:scholar","act-verb":"offer","msgid":"01JABCDEF000000000000000EF","target":"#ops"}"##
        );
    }

    #[test]
    fn actor_class_and_sig_and_msgid_are_not_covered() {
        // Same act tags with and without the extras → identical canonical.
        let with_extras = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        let only_act: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| is_act_tag(n))
            .collect();
        assert_eq!(
            with_extras,
            act_canonical(only_act, OFFER_VENUE, OFFER_ID).unwrap()
        );
    }

    /// The two injected fields come from the caller — the venue the delivery
    /// happened in, and the id the signer minted — never from a tag. A tag
    /// literally named `target` or `msgid` is not an act tag and cannot reach
    /// the document; changing the parameter always does.
    #[test]
    fn the_venue_and_the_event_id_come_from_the_caller_not_from_a_tag() {
        let plain = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();

        let mut spoofed = offer_tags();
        spoofed.push(("target", "#random"));
        spoofed.push(("msgid", "01JSPOOFED000000000000000X"));
        spoofed.push(("+freeq.at/eventid", "01JSPOOFED000000000000000X"));
        assert_eq!(
            act_canonical(spoofed, OFFER_VENUE, OFFER_ID).unwrap(),
            plain,
            "no tag may write the venue or the id into the document"
        );

        assert_ne!(
            act_canonical(offer_tags(), "#random", OFFER_ID).unwrap(),
            plain
        );
        assert_ne!(
            act_canonical(offer_tags(), OFFER_VENUE, "01JOTHEREVENTID00000000000").unwrap(),
            plain
        );
    }

    /// Settled with the id rule: an offer's own event id is the task's id, so
    /// the offer mints nothing of its own — `act-id` appears only on the
    /// follow-ups that name the task they are about.
    #[test]
    fn an_offer_signs_its_own_event_id_instead_of_an_act_id_tag() {
        let canonical = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        assert!(
            !canonical.contains("act-id"),
            "an offer carries no act-id: {canonical}"
        );
        assert!(canonical.contains(r#""msgid":"01JABCDEF000000000000000EF""#));
    }

    #[test]
    fn unprefixed_tag_names_are_accepted() {
        let prefixed = act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "accept"),
                ("+freeq.at/act-id", "01J"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        );
        let bare = act_canonical(
            vec![
                ("freeq.at/act", "handoff"),
                ("act-verb", "accept"),
                ("act-id", "01J"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        );
        assert_eq!(prefixed, bare);
    }

    #[test]
    fn no_act_tags_is_none() {
        // The venue and the id alone are not a document: with no act tags
        // there is nothing to sign, however much delivery context we hold.
        assert_eq!(
            act_canonical(
                vec![("msgid", "01J"), ("account", "did:plc:x")],
                OFFER_VENUE,
                OFFER_ID
            ),
            None
        );
        assert_eq!(
            act_canonical(
                vec![("+freeq.at/actor-class", "agent")],
                OFFER_VENUE,
                OFFER_ID
            ),
            None
        );
    }

    #[test]
    fn values_are_json_escaped() {
        let canonical = act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-title", "say \"hi\"\nplease"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        )
        .unwrap();
        assert_eq!(
            canonical,
            r##"{"act":"handoff","act-title":"say \"hi\"\nplease","msgid":"01JABCDEF000000000000000EF","target":"#ops"}"##
        );
    }

    #[test]
    fn kid_is_22_chars_base64url_and_key_specific() {
        let kid1 = derive_kid(&test_key(1).verifying_key());
        let kid2 = derive_kid(&test_key(2).verifying_key());
        assert_eq!(kid1.len(), 22); // 16 bytes → 22 base64url chars unpadded
        assert_ne!(kid1, kid2);
        assert!(
            kid1.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &key).unwrap();
        assert!(sig_tag.starts_with("ed25519:"));
        verify_act(
            offer_tags(),
            OFFER_VENUE,
            OFFER_ID,
            &sig_tag,
            &key.verifying_key(),
        )
        .unwrap();
    }

    #[test]
    fn verify_detects_altered_added_and_stripped_tags() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &key).unwrap();

        // Altered value
        let mut altered = offer_tags();
        altered.iter_mut().for_each(|(n, v)| {
            if *n == "+freeq.at/act-title" {
                *v = "Cite 4 sources on X";
            }
        });
        assert_eq!(
            verify_act(
                altered,
                OFFER_VENUE,
                OFFER_ID,
                &sig_tag,
                &key.verifying_key()
            ),
            Err(ActSigError::SigInvalid)
        );

        // Added act tag
        let mut added = offer_tags();
        added.push(("+freeq.at/act-priority", "urgent"));
        assert_eq!(
            verify_act(added, OFFER_VENUE, OFFER_ID, &sig_tag, &key.verifying_key()),
            Err(ActSigError::SigInvalid)
        );

        // Stripped act tag
        let stripped: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| *n != "+freeq.at/act-caps")
            .collect();
        assert_eq!(
            verify_act(
                stripped,
                OFFER_VENUE,
                OFFER_ID,
                &sig_tag,
                &key.verifying_key()
            ),
            Err(ActSigError::SigInvalid)
        );
    }

    /// A signed offer replayed into another room reads as tampering. Without
    /// the venue in the document, the copy verifies and the room a task was
    /// opened in becomes a thing anyone in the path can restate.
    #[test]
    fn re_venuing_breaks_the_signature() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), "#private-team", OFFER_ID, &key).unwrap();
        assert_eq!(
            verify_act(
                offer_tags(),
                "#public",
                OFFER_ID,
                &sig_tag,
                &key.verifying_key()
            ),
            Err(ActSigError::SigInvalid)
        );
    }

    /// A channel venue is folded the way the server folds it, so a client that
    /// types mixed case and one that types lower case sign the same document.
    #[test]
    fn a_folded_channel_venue_verifies_as_typed() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), "#ops", OFFER_ID, &key).unwrap();
        verify_act(
            offer_tags(),
            &crate::chatsig::channel_venue("#Ops"),
            OFFER_ID,
            &sig_tag,
            &key.verifying_key(),
        )
        .unwrap();
    }

    /// The id is the task's identity for the rest of its life. Filed under
    /// another id, the same signed tags would open a second task nobody
    /// offered — so the id the signer minted is inside the document.
    #[test]
    fn a_foreign_event_id_breaks_the_signature() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &key).unwrap();
        assert_eq!(
            verify_act(
                offer_tags(),
                OFFER_VENUE,
                "01JOTHEREVENTID00000000000",
                &sig_tag,
                &key.verifying_key()
            ),
            Err(ActSigError::SigInvalid)
        );
    }

    #[test]
    fn altering_a_non_covered_tag_does_not_break_the_sig() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &key).unwrap();
        let mut relayed = offer_tags();
        relayed.iter_mut().for_each(|(n, v)| {
            // The server's own msgid stamp, and the wire copy of the event id:
            // the signed id is the parameter, not either tag.
            if *n == "msgid" {
                *v = "01JREMINTEDBYPEER00000000";
            }
            if *n == "+freeq.at/eventid" {
                *v = "01JREWRITTENBYPEER0000000";
            }
        });
        verify_act(
            relayed,
            OFFER_VENUE,
            OFFER_ID,
            &sig_tag,
            &key.verifying_key(),
        )
        .unwrap();
    }

    #[test]
    fn wrong_key_is_kid_mismatch_not_sig_invalid() {
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &test_key(1)).unwrap();
        assert_eq!(
            verify_act(
                offer_tags(),
                OFFER_VENUE,
                OFFER_ID,
                &sig_tag,
                &test_key(2).verifying_key()
            ),
            Err(ActSigError::KidMismatch)
        );
    }

    #[test]
    fn bad_formats_are_rejected() {
        let key = test_key(1).verifying_key();
        assert_eq!(
            verify_act(
                offer_tags(),
                OFFER_VENUE,
                OFFER_ID,
                "ed25519:onlyonecolon",
                &key
            ),
            Err(ActSigError::BadSigFormat)
        );
        assert_eq!(
            verify_act(offer_tags(), OFFER_VENUE, OFFER_ID, "rsa:kid:c2ln", &key),
            Err(ActSigError::UnsupportedAlgorithm("rsa".into()))
        );
        // Correct kid, but the payload decodes to 3 bytes, not 64 → BadSigFormat
        // (parity with the TS verifier's length guard).
        let kid = derive_kid(&key);
        assert_eq!(
            verify_act(
                offer_tags(),
                OFFER_VENUE,
                OFFER_ID,
                &format!("ed25519:{kid}:AAAA"),
                &key
            ),
            Err(ActSigError::BadSigFormat)
        );
    }

    /// A shared vector: the wire tags plus the two fields the caller injects —
    /// the venue the message was delivered in and the id the signer minted.
    struct Case {
        name: &'static str,
        seed: u8,
        tags: Vec<(&'static str, &'static str)>,
        target: &'static str,
        msgid: &'static str,
    }

    /// The four shared vectors. Kept in one place so the generator and the
    /// checker can't drift.
    fn fixture_cases() -> Vec<Case> {
        vec![
            Case {
                name: "directed-offer",
                seed: 1,
                tags: offer_tags(),
                target: OFFER_VENUE,
                msgid: OFFER_ID,
            },
            Case {
                name: "open-offer-no-act-to",
                seed: 2,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "offer"),
                    ("+freeq.at/act-from", "did:plc:eliza"),
                    ("+freeq.at/act-title", "Summarize today's S2S logs"),
                    ("+freeq.at/act-ctx-h", "sha256:2c00"),
                    ("+freeq.at/act-caps", "freeq.at/log-analysis"),
                ],
                target: "#swarm",
                msgid: "01JXYZ0000000000000000000X",
            },
            Case {
                // A non-handoff kind carrying a field handoff never defined —
                // exercises sign-what's-present (no fixed field list) — and the
                // DM form of the venue, since a task in a DM is legal.
                name: "approval-with-kind-specific-field",
                seed: 3,
                tags: vec![
                    ("+freeq.at/act", "approval"),
                    // `request` opens its kind, so its own event id (msgid
                    // below) is the task's id — no act-id, same as an offer.
                    ("+freeq.at/act-verb", "request"),
                    ("+freeq.at/act-from", "did:plc:factory"),
                    ("+freeq.at/act-to", "did:plc:opslead"),
                    ("+freeq.at/act-title", "Deploy factory-bot v12"),
                    ("+freeq.at/act-scope", "deploy:factory-bot"),
                    ("+freeq.at/act-ctx-h", "sha256:1a00"),
                ],
                target: "dm:did:plc:factory,did:plc:opslead",
                msgid: "01KDEF0000000000000000000K",
            },
            Case {
                // A follow-up: it names the task it is about in `act-id` —
                // the offer's event id — and mints its own id for itself.
                name: "accept-minimal-with-escaping",
                seed: 4,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "accept"),
                    // act-id names the task, and that value IS the offer's own
                    // event id — which is how a follow-up finds its offer.
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-from", "did:plc:scholar"),
                    // Non-ASCII + JSON-escaping stress in a value.
                    ("+freeq.at/act-note", "ok — \"on it\" ✓\n(eta 5m)"),
                ],
                target: OFFER_VENUE,
                msgid: "01JACCEPTEVENTID0000000000",
            },
        ]
    }

    /// A negative vector: the same tags and the same signature, checked
    /// against delivery context the signer never wrote. Both attacks are on
    /// the injected fields, since every attack on the tags themselves is
    /// already covered by the sign-what's-present rule.
    struct Negative {
        name: &'static str,
        of: &'static str,
        target: &'static str,
        msgid: &'static str,
    }

    fn negatives() -> Vec<Negative> {
        vec![
            Negative {
                name: "re-venued-target",
                of: "directed-offer",
                target: "#random",
                msgid: OFFER_ID,
            },
            Negative {
                name: "swapped-event-id",
                of: "directed-offer",
                target: OFFER_VENUE,
                msgid: "01JOTHEREVENTID00000000000",
            },
        ]
    }

    fn fixtures_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/act-signing-vectors.json")
    }

    fn build_fixtures_json() -> serde_json::Value {
        use base64::Engine;
        let vectors: Vec<serde_json::Value> = fixture_cases()
            .into_iter()
            .map(|case| {
                let key = test_key(case.seed);
                let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(key.verifying_key().as_bytes());
                let tag_map: serde_json::Map<String, serde_json::Value> = case
                    .tags
                    .iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                    .collect();
                serde_json::json!({
                    "name": case.name,
                    "seed": hex_seed(case.seed),
                    "publicKey": pubkey_b64,
                    "kid": derive_kid(&key.verifying_key()),
                    "tags": tag_map,
                    "target": case.target,
                    "msgid": case.msgid,
                    "canonical": act_canonical(case.tags.clone(), case.target, case.msgid).unwrap(),
                    "sigTag": sign_act(case.tags, case.target, case.msgid, &key).unwrap(),
                })
            })
            .collect();
        let negatives: Vec<serde_json::Value> = negatives()
            .into_iter()
            .map(|n| {
                let case = fixture_cases()
                    .into_iter()
                    .find(|c| c.name == n.of)
                    .expect("a negative names a vector");
                serde_json::json!({
                    "name": n.name,
                    "vector": n.of,
                    "expected": "invalid",
                    "target": n.target,
                    "msgid": n.msgid,
                    "tamperedCanonical": act_canonical(case.tags, n.target, n.msgid).unwrap(),
                })
            })
            .collect();
        serde_json::json!({
            "description": "Worked signing examples for freeq.at/act (RFC v0.4). Every implementation must reproduce canonical, kid, and sigTag byte-for-byte from tags + target + msgid + seed, and must reject every negative: the named vector's own sigTag, checked against the negative's target and msgid, over the same tags. Non-act tags in `tags` are present deliberately: they must NOT be covered.",
            "documentRule": "JCS (RFC 8785) over a flat string map: every act/act-* tag present, keyed by its name with the +freeq.at/ prefix stripped, plus `target` and `msgid`. No fixed field list — a kind may add tags freely.",
            "injectedFieldRule": "target and msgid are supplied by the caller, never read from a tag: target is the normalized venue the message was delivered in, msgid is the id the signer minted (it rides the wire in +freeq.at/eventid). Neither name can collide with a covered tag, whose stripped name always starts with `act`.",
            "venueRule": "target is the normalized venue, never the wire target: a channel lowercased, or `dm:<did_a>,<did_b>` with the two DIDs sorted ascending.",
            "eventIdRule": "An offer carries no act-id: its own event id is the task's id. Every later event in a task's life names that id in act-id, and mints its own id for itself.",
            "senderOnlyTagRule": "Only the sender ever writes act-* tags. A server that stamped one of its own would land inside the signature's coverage and break every act signature it relayed.",
            "kidRule": "base64url-nopad(sha256(raw 32-byte ed25519 public key)[0..16])",
            "sigTagFormat": "ed25519:<kid>:<base64url-nopad signature over the UTF-8 canonical bytes>",
            "vectors": vectors,
            "negatives": negatives,
        })
    }

    fn hex_seed(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    /// Regenerate spec/act-signing-vectors.json. Run manually:
    /// `cargo test -p freeq-sdk generate_signing_vectors -- --ignored`
    #[test]
    #[ignore]
    fn generate_signing_vectors() {
        let json = serde_json::to_string_pretty(&build_fixtures_json()).unwrap();
        std::fs::create_dir_all(fixtures_path().parent().unwrap()).unwrap();
        std::fs::write(fixtures_path(), json + "\n").unwrap();
    }

    /// The committed fixture file must exactly match what this implementation
    /// produces — this is the cross-language byte-compatibility contract.
    #[test]
    fn committed_signing_vectors_are_reproducible() {
        let on_disk = std::fs::read_to_string(fixtures_path())
            .expect("spec/act-signing-vectors.json missing — run generate_signing_vectors");
        let on_disk: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(on_disk, build_fixtures_json());
    }

    /// Every vector verifies, and every negative is refused as tampering — so
    /// the fixture file can't drift from the semantics it publishes.
    #[test]
    fn every_vector_verifies_and_every_negative_is_invalid() {
        for case in fixture_cases() {
            let key = test_key(case.seed);
            let sig_tag = sign_act(case.tags.clone(), case.target, case.msgid, &key).unwrap();
            verify_act(
                case.tags,
                case.target,
                case.msgid,
                &sig_tag,
                &key.verifying_key(),
            )
            .unwrap_or_else(|e| panic!("vector {} failed to verify: {e}", case.name));
        }
        for n in negatives() {
            let case = fixture_cases()
                .into_iter()
                .find(|c| c.name == n.of)
                .unwrap_or_else(|| panic!("negative {} names unknown vector {}", n.name, n.of));
            let key = test_key(case.seed);
            let real_sig = sign_act(case.tags.clone(), case.target, case.msgid, &key).unwrap();
            assert_eq!(
                verify_act(
                    case.tags,
                    n.target,
                    n.msgid,
                    &real_sig,
                    &key.verifying_key()
                ),
                Err(ActSigError::SigInvalid),
                "negative {}",
                n.name
            );
        }
    }

    #[test]
    fn open_offer_omits_act_to() {
        // v0.4: open/claimable = no act-to at all.
        let open = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/act-from", "did:plc:eliza"),
            ("+freeq.at/act-title", "Summarize today's S2S logs"),
            ("+freeq.at/act-caps", "freeq.at/log-analysis"),
        ];
        let key = test_key(3);
        let id = "01JXYZ0000000000000000000X";
        let sig_tag = sign_act(open.clone(), "#swarm", id, &key).unwrap();
        verify_act(open, "#swarm", id, &sig_tag, &key.verifying_key()).unwrap();
    }
}
