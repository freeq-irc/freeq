//! Signing and verification for `freeq.at/act` action messages.
//!
//! Implements the act canonical from the act RFC — the gist body plus the
//! comment thread, which is part of the RFC. The signature covers **every
//! `act-*` tag present** on the message — not a fixed field list —
//! JCS-canonicalized (RFC 8785) with sorted keys. Adding or stripping an
//! `act-*` tag in transit changes the rebuilt canonical, so tampering is
//! detected by construction.
//!
//! ## Canonical keys are semantic names (thread agreement, 2026-08-02)
//!
//! The document's key for a field is the field's semantic name; the wire tag
//! name is framing. Three keys are **mandatory** in every act document:
//!
//! - **`from`** — the signer's DID, riding the wire in `+freeq.at/from`: an
//!   envelope tag like `eventid`, not an `act-*` tag, read explicitly rather
//!   than swept.
//! - **`id`** — the event id the signer minted, riding the wire in
//!   [`crate::chatsig::EVENT_ID_TAG`]. A task's id is its identity for the
//!   rest of its life, so it cannot be the one unsigned thing about it.
//! - **`target`** — the normalized venue ([`crate::chatsig::channel_venue`] /
//!   [`crate::chatsig::dm_venue`]), supplied by the signer and rebuilt by the
//!   verifier from delivery context. The channel is the queue: without it, an
//!   offer signed in one room replays into another with its signature intact.
//!
//! A document missing a mandatory field reads **unverifiable, never
//! invalid** — `from`/`id`/`target` are not `act-`prefixed, so sign-every-
//! `act-*` alone cannot strip-detect them, and an absence is not evidence
//! about the sender ([`ActSigError::MissingFrom`]; `id` and `target` are
//! caller-supplied here, so their absence is the caller's to report).
//!
//! (Until 2026-08 this module signed the pre-agreement keys `act-from` and
//! `msgid`. That never matched what the thread froze on 2026-08-02; the
//! realignment replaced the keys and regenerated the vector file. No history
//! survives under the old keys — pre-realignment act events were discarded.)
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
//! `spec/act-signing-vectors.json`, which the TS implementations must
//! reproduce byte-for-byte):
//!
//! - A tag is covered iff its name, after stripping the `+freeq.at/`
//!   client-tag prefix, is `act` or starts with `act-`. (`actor-class` does
//!   NOT match; `sig` does not match.) The unprefixed forms are accepted too.
//! - Canonical keys are the **stripped** tag names. The vendor
//!   prefix never reaches a document, so a future de-vendoring of the tag
//!   names changes no signature — with one honest caveat: the coverage
//!   predicate below recognizes the current wire spellings, so a renamed
//!   wire tag also needs its spelling added there (a code change, not a
//!   canonical change).
//! - Values are the (IRC-unescaped) tag values, verbatim, always JSON
//!   strings — `act-deadline` is not coerced to a number.
//! - `id` and `target` are injected by the caller, never read from a tag.
//!   No injected name can collide with a covered tag: every covered key
//!   starts with `act`.
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
/// `MissingFrom` is the unverifiable-mandatory-field case: the absence of a
/// mandatory key is not evidence about the sender, so it must never be
/// reported as invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum ActSigError {
    /// No `act`/`act-*` tags present — nothing to sign or verify.
    NoActTags,
    /// Act tags are present but no `from` tag names the signer. A mandatory
    /// canonical field (`from`/`id`/`target`) missing reads *unverifiable*,
    /// never invalid (thread agreement, 2026-08-02).
    MissingFrom,
    /// The caller supplied no event id. Same mandatory-field rule as
    /// `MissingFrom`; parameter-level because the id is injected, not a tag.
    MissingId,
    /// The caller supplied no venue. Same mandatory-field rule.
    MissingTarget,
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
            ActSigError::MissingFrom => {
                write!(f, "act tags present but no from tag names the signer")
            }
            ActSigError::MissingId => write!(f, "no event id supplied for the act document"),
            ActSigError::MissingTarget => write!(f, "no venue supplied for the act document"),
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
/// unescaped values. `target` is the normalized venue and `id` the event id
/// the signer minted; both are supplied by the caller — a verifier rebuilds
/// them from delivery context rather than reading either off a tag. The
/// signer's DID rides the `from` envelope tag and enters the document under
/// the same name.
///
/// Errors: [`ActSigError::NoActTags`] when nothing on the message is an act
/// tag (delivery context alone is not a document), and
/// [`ActSigError::MissingFrom`] when act tags are present but none names the
/// signer — the unverifiable-mandatory-field case, never invalid.
pub fn act_canonical<'a, I>(tags: I, target: &'a str, id: &'a str) -> Result<String, ActSigError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    // All three mandatory fields, or no document — the same rule whether the
    // field is a tag (from) or a parameter (id, target).
    if id.is_empty() {
        return Err(ActSigError::MissingId);
    }
    if target.is_empty() {
        return Err(ActSigError::MissingTarget);
    }
    let mut covered: BTreeMap<&str, &str> = BTreeMap::new();
    let mut from: Option<&str> = None;
    for (name, value) in tags {
        let stripped = stripped_name(name);
        if stripped == "from" {
            // The signer's envelope tag — not an act tag, read explicitly,
            // exactly as the event id rides `eventid`.
            from = Some(value);
            continue;
        }
        if !is_act_tag(name) {
            continue;
        }
        covered.insert(stripped, value);
    }
    if covered.is_empty() {
        return Err(ActSigError::NoActTags);
    }
    let Some(from) = from else {
        return Err(ActSigError::MissingFrom);
    };
    // Envelope fields — read from their own places, never from a covered
    // tag, and none can collide with one: every covered key starts with
    // `act`.
    covered.insert("from", from);
    covered.insert("id", id);
    covered.insert("target", target);
    // BTreeMap serializes with sorted keys; canonicalize re-sorts per JCS
    // (codepoint order) and applies JSON string escaping.
    Ok(crate::canonical::canonicalize(&covered).expect("string map serializes"))
}

/// Sign the act tags in `tags`, posted to `target` under `id`, with `key`.
/// Returns the sig tag value (`ed25519:<kid>:<base64url sig>`), or the same
/// errors as [`act_canonical`] when there is no document to sign.
pub fn sign_act<'a, I>(
    tags: I,
    target: &'a str,
    id: &'a str,
    key: &SigningKey,
) -> Result<String, ActSigError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    Ok(crate::sigtag::sign_canonical(
        &act_canonical(tags, target, id)?,
        key,
    ))
}

/// Parse a sig tag value into (kid, signature bytes).
pub fn parse_sig_tag(sig_tag: &str) -> Result<(&str, [u8; 64]), ActSigError> {
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)
}

/// Verify an act signature over the act tags in `tags` against `key`.
///
/// `target` and `id` come from the receiver's own view of the delivery — the
/// venue the message arrived in and the id it is being filed under — so a
/// message replayed elsewhere, or filed under another id, reads as tampering.
/// A missing mandatory field ([`ActSigError::MissingFrom`]) is unverifiable,
/// never invalid.
pub fn verify_act<'a, I>(
    tags: I,
    target: &'a str,
    id: &'a str,
    sig_tag: &str,
    key: &VerifyingKey,
) -> Result<(), ActSigError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    // Shape and kid first, so a missing canonical isn't reported as a format
    // problem and a wrong key isn't reported as tampering.
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)?;
    let canonical = act_canonical(tags, target, id)?;
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
            ("+freeq.at/from", "did:plc:eliza"),
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
    fn canonical_covers_act_tags_the_signer_the_venue_and_the_event_id() {
        let canonical = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        assert_eq!(
            canonical,
            r##"{"act":"handoff","act-caps":"freeq.at/web-search","act-ctx-h":"sha256:9f00","act-deadline":"1788000000","act-title":"Cite 3 sources on X","act-to":"did:plc:scholar","act-verb":"offer","from":"did:plc:eliza","id":"01JABCDEF000000000000000EF","target":"#ops"}"##
        );
    }

    /// The signer rides the `from` envelope tag and the document says the
    /// same word — wire name and document key agree, as they do for every
    /// field.
    #[test]
    fn the_from_tag_enters_the_document_under_its_own_name() {
        let canonical = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        assert!(canonical.contains(r#""from":"did:plc:eliza""#));
    }

    /// Act tags without an actor: unverifiable, never "no act tags" and never
    /// invalid — an absence is not evidence about the sender (2026-08-02).
    #[test]
    fn missing_act_from_is_unverifiable_not_invalid() {
        let without_from: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| *n != "+freeq.at/from")
            .collect();
        assert_eq!(
            act_canonical(without_from.clone(), OFFER_VENUE, OFFER_ID),
            Err(ActSigError::MissingFrom)
        );
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), OFFER_VENUE, OFFER_ID, &key).unwrap();
        assert_eq!(
            verify_act(
                without_from,
                OFFER_VENUE,
                OFFER_ID,
                &sig_tag,
                &key.verifying_key()
            ),
            Err(ActSigError::MissingFrom)
        );
    }

    #[test]
    fn actor_class_and_sig_and_msgid_are_not_covered() {
        // Same act tags (and the from envelope tag) with and without the
        // extras → identical canonical.
        let with_extras = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();
        let only_act: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| is_act_tag(n) || stripped_name(n) == "from")
            .collect();
        assert_eq!(
            with_extras,
            act_canonical(only_act, OFFER_VENUE, OFFER_ID).unwrap()
        );
    }

    /// The injected fields come from the caller — the venue the delivery
    /// happened in, and the id the signer minted — never from a tag. A tag
    /// literally named `from`, `target` or `id` is not an act tag and cannot
    /// reach the document; changing the parameter always does.
    #[test]
    fn the_mandatory_fields_come_from_the_caller_not_from_lookalike_tags() {
        let plain = act_canonical(offer_tags(), OFFER_VENUE, OFFER_ID).unwrap();

        let mut spoofed = offer_tags();
        spoofed.push(("target", "#random"));
        spoofed.push(("id", "01JSPOOFED000000000000000X"));
        spoofed.push(("msgid", "01JSPOOFED000000000000000X"));
        spoofed.push(("+freeq.at/eventid", "01JSPOOFED000000000000000X"));
        assert_eq!(
            act_canonical(spoofed, OFFER_VENUE, OFFER_ID).unwrap(),
            plain,
            "no lookalike tag may write a mandatory field into the document"
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
        assert!(canonical.contains(r#""id":"01JABCDEF000000000000000EF""#));
    }

    #[test]
    fn unprefixed_tag_names_are_accepted() {
        let prefixed = act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "accept"),
                ("+freeq.at/from", "did:plc:x"),
                ("+freeq.at/act-id", "01J"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        );
        let bare = act_canonical(
            vec![
                ("freeq.at/act", "handoff"),
                ("act-verb", "accept"),
                ("from", "did:plc:x"),
                ("act-id", "01J"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        );
        assert_eq!(prefixed, bare);
    }

    /// `id` and `target` are as mandatory as `from`; they are parameters
    /// rather than tags, so the guard is parameter-level. Unverifiable-class,
    /// like every missing mandatory field.
    #[test]
    fn an_empty_id_or_venue_is_a_missing_mandatory_field() {
        assert_eq!(
            act_canonical(offer_tags(), OFFER_VENUE, ""),
            Err(ActSigError::MissingId)
        );
        assert_eq!(
            act_canonical(offer_tags(), "", OFFER_ID),
            Err(ActSigError::MissingTarget)
        );
    }

    #[test]
    fn no_act_tags_is_an_error() {
        // The venue and the id alone are not a document: with no act tags
        // there is nothing to sign, however much delivery context we hold.
        assert_eq!(
            act_canonical(
                vec![("msgid", "01J"), ("account", "did:plc:x")],
                OFFER_VENUE,
                OFFER_ID
            ),
            Err(ActSigError::NoActTags)
        );
        assert_eq!(
            act_canonical(
                vec![("+freeq.at/actor-class", "agent")],
                OFFER_VENUE,
                OFFER_ID
            ),
            Err(ActSigError::NoActTags)
        );
        // A from tag alone is an envelope with no act content — still not a
        // document.
        assert_eq!(
            act_canonical(
                vec![("+freeq.at/from", "did:plc:x")],
                OFFER_VENUE,
                OFFER_ID
            ),
            Err(ActSigError::NoActTags)
        );
    }

    #[test]
    fn values_are_json_escaped() {
        let canonical = act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/from", "did:plc:eliza"),
                ("+freeq.at/act-title", "say \"hi\"\nplease"),
            ],
            OFFER_VENUE,
            OFFER_ID,
        )
        .unwrap();
        assert_eq!(
            canonical,
            r##"{"act":"handoff","act-title":"say \"hi\"\nplease","from":"did:plc:eliza","id":"01JABCDEF000000000000000EF","target":"#ops"}"##
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

        // An altered actor is tampering like any other signed value: the
        // from tag enters the document, so rewriting it breaks the sig.
        let mut reactored = offer_tags();
        reactored.iter_mut().for_each(|(n, v)| {
            if *n == "+freeq.at/from" {
                *v = "did:plc:mallory";
            }
        });
        assert_eq!(
            verify_act(
                reactored,
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
        id: &'static str,
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
                id: OFFER_ID,
            },
            Case {
                name: "open-offer-no-act-to",
                seed: 2,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "offer"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-title", "Summarize today's S2S logs"),
                    ("+freeq.at/act-ctx-h", "sha256:2c00"),
                    ("+freeq.at/act-caps", "freeq.at/log-analysis"),
                ],
                target: "#swarm",
                id: "01JXYZ0000000000000000000X",
            },
            Case {
                // A non-handoff kind carrying a field handoff never defined —
                // exercises sign-what's-present (no fixed field list) — and the
                // DM form of the venue, since a task in a DM is legal.
                name: "approval-with-kind-specific-field",
                seed: 3,
                tags: vec![
                    ("+freeq.at/act", "approval"),
                    // `request` opens its kind, so its own event id (id
                    // below) is the task's id — no act-id, same as an offer.
                    ("+freeq.at/act-verb", "request"),
                    ("+freeq.at/from", "did:plc:factory"),
                    ("+freeq.at/act-to", "did:plc:opslead"),
                    ("+freeq.at/act-title", "Deploy factory-bot v12"),
                    ("+freeq.at/act-scope", "deploy:factory-bot"),
                    ("+freeq.at/act-ctx-h", "sha256:1a00"),
                ],
                target: "dm:did:plc:factory,did:plc:opslead",
                id: "01KDEF0000000000000000000K",
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
                    ("+freeq.at/from", "did:plc:scholar"),
                    // Non-ASCII + JSON-escaping stress in a value.
                    ("+freeq.at/act-note", "ok — \"on it\" ✓\n(eta 5m)"),
                ],
                target: OFFER_VENUE,
                id: "01JACCEPTEVENTID0000000000",
            },
        ]
    }

    /// A negative vector. Two classes, and the split is the point:
    /// `invalid` — a signed fact was changed (tampering evidence);
    /// `unverifiable` — the check cannot run (a missing mandatory field, an
    /// unknown algorithm), which is not evidence about the sender.
    struct Negative {
        name: &'static str,
        of: &'static str,
        expected: &'static str,
        target: &'static str,
        id: &'static str,
        /// Strip this wire tag before verifying (missing-mandatory case).
        strip_tag: Option<&'static str>,
        /// Replace the sig tag's algorithm label (unknown-algorithm case).
        swap_alg: Option<&'static str>,
    }

    fn negatives() -> Vec<Negative> {
        vec![
            Negative {
                name: "re-venued-target",
                of: "directed-offer",
                expected: "invalid",
                target: "#random",
                id: OFFER_ID,
                strip_tag: None,
                swap_alg: None,
            },
            Negative {
                name: "swapped-event-id",
                of: "directed-offer",
                expected: "invalid",
                target: OFFER_VENUE,
                id: "01JOTHEREVENTID00000000000",
                strip_tag: None,
                swap_alg: None,
            },
            Negative {
                // act tags with the signer stripped: a mandatory field is
                // absent, and absence is not evidence — unverifiable, never
                // invalid (2026-08-02).
                name: "missing-from",
                of: "directed-offer",
                expected: "unverifiable",
                target: OFFER_VENUE,
                id: OFFER_ID,
                strip_tag: Some("+freeq.at/from"),
                swap_alg: None,
            },
            Negative {
                // A sig tag naming an algorithm this verifier has never heard
                // of: it cannot run the check, which is not a verdict about
                // the bytes — unverifiable, never invalid.
                name: "unknown-algorithm",
                of: "directed-offer",
                expected: "unverifiable",
                target: OFFER_VENUE,
                id: OFFER_ID,
                strip_tag: None,
                swap_alg: Some("rsa4096"),
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
                    "id": case.id,
                    "canonical": act_canonical(case.tags.clone(), case.target, case.id).unwrap(),
                    "sigTag": sign_act(case.tags, case.target, case.id, &key).unwrap(),
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
                let mut entry = serde_json::json!({
                    "name": n.name,
                    "vector": n.of,
                    "expected": n.expected,
                    "target": n.target,
                    "id": n.id,
                });
                if let Some(tag) = n.strip_tag {
                    entry["strippedTag"] = serde_json::Value::String(tag.to_string());
                } else if let Some(alg) = n.swap_alg {
                    entry["sigAlgorithm"] = serde_json::Value::String(alg.to_string());
                } else {
                    // Tamper-class negatives rebuild a real canonical under
                    // the wrong delivery context; the byte-level suites
                    // reproduce it. Unverifiable-class negatives have no
                    // canonical to rebuild — that is what unverifiable means.
                    entry["tamperedCanonical"] = serde_json::Value::String(
                        act_canonical(case.tags, n.target, n.id).unwrap(),
                    );
                }
                entry
            })
            .collect();
        serde_json::json!({
            "description": "Worked signing examples for freeq.at/act. Canonical keys follow the thread agreement frozen 2026-08-02: semantic names, with from/id/target mandatory and a missing one reading unverifiable. Every implementation must reproduce canonical, kid, and sigTag byte-for-byte from tags + target + id + seed, and must reach each negative's expected verdict. Non-act tags in `tags` are present deliberately: they must NOT be covered.",
            "documentRule": "JCS (RFC 8785) over a flat string map: every act/act-* tag present keyed by its name with the +freeq.at/ prefix stripped, plus the three envelope fields `from`, `id` and `target`. No fixed field list — a kind may add tags freely.",
            "mandatoryFieldRule": "`from`, `id` and `target` are mandatory. A document missing one reads unverifiable, never invalid: none is act-prefixed, so tag coverage cannot strip-detect it, and an absence is not evidence about the sender.",
            "envelopeRule": "The three envelope fields are not act tags: from rides the +freeq.at/from tag, id rides +freeq.at/eventid, and target is the normalized venue the message was delivered in — the last two supplied by the caller, never read from a tag. No envelope name can collide with a covered tag, whose stripped name always starts with `act`.",
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

    /// Every vector verifies, and every negative reaches its expected verdict
    /// class — so the fixture file can't drift from the semantics it
    /// publishes, including the invalid/unverifiable split.
    #[test]
    fn every_vector_verifies_and_every_negative_reaches_its_verdict() {
        for case in fixture_cases() {
            let key = test_key(case.seed);
            let sig_tag = sign_act(case.tags.clone(), case.target, case.id, &key).unwrap();
            verify_act(
                case.tags,
                case.target,
                case.id,
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
            let real_sig = sign_act(case.tags.clone(), case.target, case.id, &key).unwrap();
            let tags: Vec<_> = case
                .tags
                .into_iter()
                .filter(|(name, _)| n.strip_tag != Some(*name))
                .collect();
            let sig_tag = match n.swap_alg {
                Some(alg) => {
                    let rest = real_sig.split_once(':').expect("alg:kid:sig").1;
                    format!("{alg}:{rest}")
                }
                None => real_sig,
            };
            let verdict = verify_act(tags, n.target, n.id, &sig_tag, &key.verifying_key());
            match n.expected {
                "invalid" => assert_eq!(
                    verdict,
                    Err(ActSigError::SigInvalid),
                    "negative {}",
                    n.name
                ),
                "unverifiable" => match verdict {
                    Err(ActSigError::MissingFrom) | Err(ActSigError::UnsupportedAlgorithm(_)) => {}
                    other => panic!("negative {} expected unverifiable, got {other:?}", n.name),
                },
                other => panic!("negative {} names unknown verdict {other}", n.name),
            }
        }
    }

    #[test]
    fn open_offer_omits_act_to() {
        // v0.4: open/claimable = no act-to at all.
        let open = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", "did:plc:eliza"),
            ("+freeq.at/act-title", "Summarize today's S2S logs"),
            ("+freeq.at/act-caps", "freeq.at/log-analysis"),
        ];
        let key = test_key(3);
        let id = "01JXYZ0000000000000000000X";
        let sig_tag = sign_act(open.clone(), "#swarm", id, &key).unwrap();
        verify_act(open, "#swarm", id, &sig_tag, &key.verifying_key()).unwrap();
    }
}
