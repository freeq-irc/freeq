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

/// The wire tags of a task event.
///
/// `kind` and `verb` are what the event is and what it does; `task` names the
/// action it is about, and is `None` exactly for an opener, whose own event id
/// becomes the action's id for the rest of its life. `from` is the actor.
/// Every `(name, value)` in `fields` rides as `act-<name>`, so `("note", …)`
/// is `act-note` and `("ctx-h", …)` is `act-ctx-h`.
///
/// Nothing here knows a verb. Which verbs a kind allows, and from which state,
/// is the rules file's business ([`crate::act_transitions`]) — this builds the
/// document a sender wants to sign, whatever it says.
pub fn act_tags(
    kind: &str,
    verb: &str,
    task: Option<&str>,
    from: &str,
    fields: &[(&str, &str)],
) -> std::collections::HashMap<String, String> {
    let mut t = std::collections::HashMap::new();
    t.insert("+freeq.at/act".into(), kind.to_string());
    t.insert("+freeq.at/act-verb".into(), verb.to_string());
    t.insert("+freeq.at/from".into(), from.to_string());
    if let Some(task) = task {
        t.insert("+freeq.at/act-id".into(), task.to_string());
    }
    for (name, value) in fields {
        t.insert(format!("+freeq.at/act-{name}"), value.to_string());
    }
    t
}

/// `sha256:` + the lowercase hex digest of `content` — the one spelling
/// `act-ctx-h` is written in, matching the RFC's wire examples.
///
/// The hash covers the context bytes exactly as they are: no framing, no
/// normalization, nothing about the URL they came from. A reader who fetches
/// what `act-ctx` names hashes what it got and compares.
pub fn ctx_hash(content: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(content);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The line people read beside a task event, when the sender writes none.
///
/// The companion is prose for a room, so it is the one place a verb has to be
/// spelled out. Kept to a single function, with one arm per verb and the verb
/// itself as the answer for anything it has not been taught: a kind may add a
/// verb without touching this, and the room gets the verb's name until someone
/// writes it a sentence.
pub fn act_line(kind: &str, verb: &str, fields: &[(&str, &str)]) -> String {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .filter(|v| !v.is_empty())
    };
    // What a room calls the thing being acted on. A handoff is a task in
    // prose — it always has been in these lines — and every other kind is
    // called by its own name.
    let named = if kind == "handoff" { "task" } else { kind };
    match verb {
        "offer" => format!("offered: {}", field("title").unwrap_or_default()),
        "accept" => format!("accepted the {named}"),
        "decline" => format!("declined the {named}"),
        "claim" => format!("claimed the {named}"),
        "progress" => match field("note") {
            Some(note) => format!("progress: {note}"),
            None => "made progress".to_string(),
        },
        "complete" => format!("completed the {named}"),
        "fail" => format!("failed the {named}"),
        "cancel" => format!("cancelled the {named}"),
        "bid" => match field("note") {
            Some(note) => format!("bid: {note}"),
            None => "bid on the bounty".to_string(),
        },
        "award" => "awarded the bounty".to_string(),
        "submit" => "submitted the work".to_string(),
        "revise" => "asked for revisions".to_string(),
        "accept-work" => "accepted the work".to_string(),
        "forfeit" => "forfeited the bounty".to_string(),
        other => other.to_string(),
    }
}

/// A task event as it arrived: what the tags say, read once so a consumer does
/// not have to know the tag names.
///
/// The same fields the TypeScript SDK's `ActEventPayload` carries, under the
/// same rules — most of all that `task` is never empty. An opener names no
/// other action because its own id is the action's for the rest of its life,
/// so it names itself here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActEvent {
    /// The task kind — the `act` tag's value, e.g. `handoff`.
    pub kind: String,
    /// The move: `offer`, `claim`, `progress`, `confirm`, …
    pub verb: String,
    /// The acting identity: the `from` tag, else the server's `account`.
    pub did: Option<String>,
    /// The signer-minted id of this event.
    pub event_id: String,
    /// The action this event is about — `act-id`, or this event's own id when
    /// it opens one.
    pub task_id: String,
    /// Every act tag, keyed by its name with the vendor prefix stripped:
    /// `act-note` reads as `act-note`, `+freeq.at/act` as `act`. Exactly what
    /// the signature covers, so a reader drawing from these draws from what
    /// was signed.
    pub fields: BTreeMap<String, String>,
    /// The signature over the act document, if the line carried one.
    pub sig_tag: Option<String>,
    /// True when this arrived from history rather than live — a replayed line
    /// carries the server's `time` tag.
    pub replayed: bool,
}

/// Read a task event off a message's tags, or `None` when the message is not
/// one.
///
/// Not a task event: no act tag at all, or no id to file it under. Both are
/// silence rather than an error — an ordinary TAGMSG carries neither, and the
/// caller is asking "is this one?", not "is this valid?". Whether the
/// signature holds is [`verify_act`]'s question, asked separately and against
/// a venue only the receiver knows.
pub fn parse_event<'a, I>(tags: I) -> Option<ActEvent>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut fields = BTreeMap::new();
    let mut did = None;
    let mut account = None;
    let mut event_id = None;
    let mut sig_tag = None;
    let mut replayed = false;
    for (name, value) in tags {
        let stripped = stripped_name(name);
        match stripped {
            "from" => did = Some(value.to_string()),
            "account" => account = Some(value.to_string()),
            "eventid" => event_id = Some(value.to_string()),
            "sig" => sig_tag = Some(value.to_string()),
            "time" => replayed = true,
            // The id a signed event carries once an adopting server has taken
            // it: the server files the signed id under `msgid` and drops the
            // tag it arrived in.
            "msgid" if event_id.is_none() => event_id = Some(value.to_string()),
            _ if is_act_tag(name) => {
                fields.insert(stripped.to_string(), value.to_string());
            }
            _ => {}
        }
    }
    if fields.is_empty() {
        return None;
    }
    let event_id = event_id?;
    let task_id = fields
        .get("act-id")
        .cloned()
        .unwrap_or_else(|| event_id.clone());
    Some(ActEvent {
        kind: fields.get("act").cloned().unwrap_or_default(),
        verb: fields.get("act-verb").cloned().unwrap_or_default(),
        did: did.or(account),
        event_id,
        task_id,
        fields,
        sig_tag,
        replayed,
    })
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

    /// The bounty the bid and award vectors below are about — its opener's own
    /// event id, exactly as a handoff's is.
    const BOUNTY_ID: &str = "01JBOUNTYEVENTID00000000B";

    /// The bid on it, and so the value the award names in `act-accepts`: an
    /// award takes an event, not a DID.
    const BID_ID: &str = "01JBIDEVENTID00000000000B";

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
            act_canonical(vec![("+freeq.at/from", "did:plc:x")], OFFER_VENUE, OFFER_ID),
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

    /// The shared vectors, one per shape worth freezing. Kept in one place so
    /// the generator and the checker can't drift.
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
                // A bid on a bounty, with terms. Additive and unremarkable
                // to the canonical, which is the point: a second kind needed
                // a row in the transitions file and nothing at all here, and
                // its money tags are covered because they are present rather
                // than because anything knows what they mean.
                name: "bounty-bid",
                seed: 7,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "bid"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    // What the bidder asks and where they want it paid.
                    // Opaque to every server that handles them — the point of
                    // the vector is that two signers agree on bytes neither of
                    // them interprets.
                    ("+freeq.at/act-bid", "250 USD"),
                    ("+freeq.at/act-pay-to", "did:plc:scholar"),
                    ("+freeq.at/act-note", "two days, sources included"),
                ],
                target: "#swarm",
                id: BID_ID,
            },
            Case {
                // The award: the poster takes one bid by naming its event id,
                // and the view reads the assignee from that bid's author
                // rather than from the actor. The pointer is covered by the
                // signature, so it cannot be re-pointed in transit.
                name: "bounty-award",
                seed: 8,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "award"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    ("+freeq.at/act-accepts", BID_ID),
                ],
                target: "#swarm",
                id: "01JAWARDEVENTID000000000A",
            },
            Case {
                // A re-offer naming the finished handoff it revives. Another
                // tag the sweep covers by name and nothing else has to know
                // about: the relation is signed because it is present, which
                // is what stops a relay quietly re-pointing it.
                name: "re-offer-replacing-a-failed-handoff",
                seed: 6,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "offer"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-title", "Cite 3 sources on X"),
                    ("+freeq.at/act-replaces", OFFER_ID),
                ],
                target: OFFER_VENUE,
                id: "01JREOFFEREVENTID000000000",
            },
            Case {
                // The home's receipt for the accept below: same document as
                // any other event, signed under the server's own DID, naming
                // the confirmed event in `act-subject`. Nothing about the
                // canonical is special — the sweep covers the new tag by
                // name, which is the whole point of covering by prefix.
                name: "receipt-confirming-an-accept",
                seed: 5,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "confirm"),
                    ("+freeq.at/from", "did:web:irc.example"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-subject", "01JACCEPTEVENTID0000000000"),
                ],
                target: OFFER_VENUE,
                id: "01JCONFIRMEVENTID000000000",
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
            Case {
                // Taking an offer nobody was named for. The leanest follow-up
                // there is — kind, verb, actor, task — which is what makes it
                // worth freezing: if two implementations disagree about a
                // document this small, they disagree about all of them.
                name: "claim-on-an-open-handoff",
                seed: 9,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "claim"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", OFFER_ID),
                ],
                target: OFFER_VENUE,
                id: "01JCLAIMEVENTID00000000000",
            },
            Case {
                // A step carrying context: where the materials are and a hash
                // of what was there when this was signed. Both are ordinary
                // act tags, so the sweep covers them without knowing what
                // either means — which is how evidence rides a step at all.
                name: "progress-with-context",
                seed: 10,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "progress"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-note", "2 of 3 sources read"),
                    ("+freeq.at/act-ctx", "https://example.com/checks/abc"),
                    ("+freeq.at/act-ctx-h", "sha256:9f86d"),
                ],
                target: OFFER_VENUE,
                id: "01JPROGRESSEVENTID00000000",
            },
            Case {
                // A completion whose result rides `act-ctx` with no hash: the
                // sender had a link and not the bytes. Honest and allowed —
                // and the reason the hash is a separate tag rather than part
                // of the link.
                name: "complete-with-a-result-link",
                seed: 11,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "complete"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-note", "filed"),
                    ("+freeq.at/act-ctx", "https://example.com/article"),
                ],
                target: OFFER_VENUE,
                id: "01JCOMPLETEEVENTID00000000",
            },
            Case {
                // Giving up work you hold. Terminal, and the note is the only
                // account anyone gets of why.
                name: "fail-with-a-reason",
                seed: 12,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "fail"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-note", "the source is paywalled"),
                ],
                target: OFFER_VENUE,
                id: "01JFAILEVENTID000000000000",
            },
            Case {
                // The poster withdrawing their own task. Same document as any
                // participant step; who may send it is the rules file's
                // business, not the canonical's.
                name: "cancel-by-the-offerer",
                seed: 13,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "cancel"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-note", "no longer needed"),
                ],
                target: OFFER_VENUE,
                id: "01JCANCELEVENTID0000000000",
            },
            Case {
                // Turning down an offer that named you.
                name: "decline-by-the-offeree",
                seed: 14,
                tags: vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "decline"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", OFFER_ID),
                    ("+freeq.at/act-note", "no capacity today"),
                ],
                target: OFFER_VENUE,
                id: "01JDECLINEEVENTID000000000",
            },
            Case {
                // Handing work in on a bounty. Nothing about a submission
                // says the work is done — only that it is in — so the
                // document says no more than that.
                name: "bounty-submit",
                seed: 15,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "submit"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    ("+freeq.at/act-note", "branch pushed"),
                ],
                target: "#swarm",
                id: "01JSUBMITEVENTID0000000000",
            },
            Case {
                // The poster sending submitted work back for another pass.
                name: "bounty-revise",
                seed: 16,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "revise"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    ("+freeq.at/act-note", "tests missing"),
                ],
                target: "#swarm",
                id: "01JREVISEEVENTID0000000000",
            },
            Case {
                // The poster accepting the work, with a payment reference
                // along for the record. Opaque like the bid's terms: covered
                // because it is present, never because anything reads it.
                name: "bounty-accept-work-with-a-payment-reference",
                seed: 17,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "accept-work"),
                    ("+freeq.at/from", "did:plc:eliza"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    ("+freeq.at/act-tx", "lightning:abc123"),
                ],
                target: "#swarm",
                id: "01JACCEPTWORKEVENTID000000",
            },
            Case {
                // Walking away from a bounty you hold. Terminal: re-listing
                // it is a new bounty naming this one in the revival relation.
                name: "bounty-forfeit",
                seed: 18,
                tags: vec![
                    ("+freeq.at/act", "bounty"),
                    ("+freeq.at/act-verb", "forfeit"),
                    ("+freeq.at/from", "did:plc:scholar"),
                    ("+freeq.at/act-id", BOUNTY_ID),
                    ("+freeq.at/act-note", "out of time"),
                ],
                target: "#swarm",
                id: "01JFORFEITEVENTID000000000",
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
        /// Strip this wire tag before verifying.
        strip_tag: Option<&'static str>,
        /// Rewrite this wire tag's value before verifying (tamper case).
        swap_tag: Option<(&'static str, &'static str)>,
        /// Replace the sig tag's algorithm label (unknown-algorithm case).
        swap_alg: Option<&'static str>,
    }

    impl Negative {
        /// The vector's tags as this negative presents them to a verifier.
        fn tags_of(&self, case: &Case) -> Vec<(&'static str, &'static str)> {
            case.tags
                .iter()
                .filter(|(name, _)| self.strip_tag != Some(*name))
                .map(|(name, value)| match self.swap_tag {
                    Some((swapped, to)) if swapped == *name => (*name, to),
                    _ => (*name, *value),
                })
                .collect()
        }
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
                swap_tag: None,
                swap_alg: None,
            },
            Negative {
                name: "swapped-event-id",
                of: "directed-offer",
                expected: "invalid",
                target: OFFER_VENUE,
                id: "01JOTHEREVENTID00000000000",
                strip_tag: None,
                swap_tag: None,
                swap_alg: None,
            },
            Negative {
                // A receipt re-pointed at another event. The subject is the
                // whole content of a receipt — "the home confirms *this*" —
                // so rewriting it must read as tampering, not as a new fact.
                // The sweep covers act-subject by name, like every act tag.
                name: "receipt-with-a-swapped-subject",
                of: "receipt-confirming-an-accept",
                expected: "invalid",
                target: OFFER_VENUE,
                id: "01JCONFIRMEVENTID000000000",
                strip_tag: None,
                swap_tag: Some(("+freeq.at/act-subject", "01JOTHEREVENTID00000000000")),
                swap_alg: None,
            },
            Negative {
                // An award with the bid it takes stripped. Unlike a missing
                // envelope field this is strip-*detectable*: act-accepts is an
                // act tag, so the sweep covered it and the document rebuilds
                // without it into bytes the signature contradicts.
                name: "award-with-its-bid-stripped",
                of: "bounty-award",
                expected: "invalid",
                target: "#swarm",
                id: "01JAWARDEVENTID000000000A",
                strip_tag: Some("+freeq.at/act-accepts"),
                swap_tag: None,
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
                swap_tag: None,
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
                swap_tag: None,
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
                }
                if let Some((tag, to)) = n.swap_tag {
                    entry["swappedTag"] = serde_json::json!({ "name": tag, "value": to });
                }
                if let Some(alg) = n.swap_alg {
                    entry["sigAlgorithm"] = serde_json::Value::String(alg.to_string());
                }
                // Tamper-class negatives rebuild a real canonical — under the
                // wrong delivery context, or over a rewritten tag — and the
                // byte-level suites reproduce it. Unverifiable-class negatives
                // have no canonical to rebuild; that is what unverifiable
                // means.
                if n.expected == "invalid" {
                    entry["tamperedCanonical"] = serde_json::Value::String(
                        act_canonical(n.tags_of(&case), n.target, n.id).unwrap(),
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
            "negativeRule": "A negative names a vector and the conditions to check it under. `strippedTag` removes a wire tag and `swappedTag` rewrites one before verifying; `sigAlgorithm` relabels the signature's algorithm; `target` and `id` are the delivery context to rebuild from. Every `invalid` negative also carries the canonical those conditions rebuild to, so a byte-level suite with no verifier can still check it; an `unverifiable` one carries none, because having no canonical to rebuild is what unverifiable means.",
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

    /// Every vector's tags are what the builder makes of that vector's own
    /// inputs.
    ///
    /// The sending half of the contract: the signing half above proves the
    /// canonical and the signature reproduce, and this proves the tags a
    /// sender writes are the tags that were frozen. It walks the whole file
    /// rather than a list, so a vector cannot be added without being covered
    /// — including the two nothing here sends, the approval kind's opener and
    /// the home's receipt, because the builder knows no verb and does not
    /// care which of them it is spelling.
    #[test]
    fn every_vector_is_what_the_builder_makes_of_its_own_inputs() {
        for case in fixture_cases() {
            let by_name: BTreeMap<&str, &str> = case
                .tags
                .iter()
                .map(|(name, value)| (stripped_name(name), *value))
                .collect();
            // `verb` and `id` are the builder's own parameters; everything
            // else under the prefix is a field.
            let fields: Vec<(&str, &str)> = by_name
                .iter()
                .filter_map(|(name, value)| {
                    name.strip_prefix("act-")
                        .filter(|f| *f != "verb" && *f != "id")
                        .map(|f| (f, *value))
                })
                .collect();
            let built = act_tags(
                by_name.get("act").copied().unwrap_or_default(),
                by_name.get("act-verb").copied().unwrap_or_default(),
                by_name.get("act-id").copied(),
                by_name.get("from").copied().unwrap_or_default(),
                &fields,
            );
            // The vector carries tags no sender writes — the signature, the
            // event id, and two that are there to prove they are not covered.
            let expected: std::collections::HashMap<String, String> = case
                .tags
                .iter()
                .filter(|(name, _)| {
                    !matches!(
                        *name,
                        "+freeq.at/sig" | "+freeq.at/eventid" | "+freeq.at/actor-class" | "msgid"
                    )
                })
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            assert_eq!(built, expected, "vector {}", case.name);
        }
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
            let tags = n.tags_of(&case);
            let sig_tag = match n.swap_alg {
                Some(alg) => {
                    let rest = real_sig.split_once(':').expect("alg:kid:sig").1;
                    format!("{alg}:{rest}")
                }
                None => real_sig,
            };
            let verdict = verify_act(tags, n.target, n.id, &sig_tag, &key.verifying_key());
            match n.expected {
                "invalid" => {
                    assert_eq!(verdict, Err(ActSigError::SigInvalid), "negative {}", n.name)
                }
                "unverifiable" => match verdict {
                    Err(ActSigError::MissingFrom) | Err(ActSigError::UnsupportedAlgorithm(_)) => {}
                    other => panic!("negative {} expected unverifiable, got {other:?}", n.name),
                },
                other => panic!("negative {} names unknown verdict {other}", n.name),
            }
        }
    }

    /// An opener names no action, because its own event id becomes the
    /// action's — so `act-id` is the one tag it must not carry.
    #[test]
    fn act_tags_leaves_an_opener_naming_no_action() {
        let tags = act_tags(
            "handoff",
            "offer",
            None,
            "did:plc:eliza",
            &[
                ("title", "Cite 3 sources on X"),
                ("caps", "freeq.at/web-search"),
            ],
        );
        assert_eq!(
            tags,
            std::collections::HashMap::from([
                ("+freeq.at/act".to_string(), "handoff".to_string()),
                ("+freeq.at/act-verb".to_string(), "offer".to_string()),
                ("+freeq.at/from".to_string(), "did:plc:eliza".to_string()),
                (
                    "+freeq.at/act-title".to_string(),
                    "Cite 3 sources on X".to_string()
                ),
                (
                    "+freeq.at/act-caps".to_string(),
                    "freeq.at/web-search".to_string()
                ),
            ])
        );
    }

    /// A follow-up names the action it is about, and nothing else changes.
    #[test]
    fn act_tags_makes_a_follow_up_name_its_action() {
        let tags = act_tags("handoff", "claim", Some(OFFER_ID), "did:plc:scholar", &[]);
        assert_eq!(
            tags,
            std::collections::HashMap::from([
                ("+freeq.at/act".to_string(), "handoff".to_string()),
                ("+freeq.at/act-verb".to_string(), "claim".to_string()),
                ("+freeq.at/from".to_string(), "did:plc:scholar".to_string()),
                ("+freeq.at/act-id".to_string(), OFFER_ID.to_string()),
            ])
        );
    }

    /// A field name with a hyphen in it keeps the hyphen: the prefix goes on
    /// the front and nothing else is touched.
    #[test]
    fn act_tags_prefixes_a_hyphenated_field_whole() {
        let tags = act_tags(
            "handoff",
            "progress",
            Some(OFFER_ID),
            "did:plc:scholar",
            &[("ctx", "https://example.com/x"), ("ctx-h", "sha256:9f00")],
        );
        assert_eq!(
            tags.get("+freeq.at/act-ctx-h").map(String::as_str),
            Some("sha256:9f00")
        );
        assert_eq!(
            tags.get("+freeq.at/act-ctx").map(String::as_str),
            Some("https://example.com/x")
        );
    }

    /// The document a kind nobody has heard of produces: the builder writes
    /// what it is told, because which verbs a kind allows is not its question.
    #[test]
    fn act_tags_builds_a_kind_and_verb_it_has_never_heard_of() {
        let tags = act_tags(
            "lease",
            "renew",
            Some(OFFER_ID),
            "did:plc:eliza",
            &[("term", "30d")],
        );
        assert_eq!(tags.get("+freeq.at/act").map(String::as_str), Some("lease"));
        assert_eq!(
            tags.get("+freeq.at/act-verb").map(String::as_str),
            Some("renew")
        );
        assert_eq!(
            tags.get("+freeq.at/act-term").map(String::as_str),
            Some("30d")
        );
    }

    /// Every verb's default line, as the room reads it. A handoff is a task in
    /// prose; every other kind is called by its own name.
    #[test]
    fn act_line_says_what_each_verb_did() {
        let none: &[(&str, &str)] = &[];
        assert_eq!(
            act_line("handoff", "offer", &[("title", "Cite 3 sources on X")]),
            "offered: Cite 3 sources on X"
        );
        assert_eq!(act_line("handoff", "accept", none), "accepted the task");
        assert_eq!(act_line("handoff", "decline", none), "declined the task");
        assert_eq!(act_line("handoff", "claim", none), "claimed the task");
        assert_eq!(act_line("handoff", "complete", none), "completed the task");
        assert_eq!(act_line("handoff", "fail", none), "failed the task");
        assert_eq!(act_line("handoff", "cancel", none), "cancelled the task");
        assert_eq!(act_line("bounty", "cancel", none), "cancelled the bounty");
        assert_eq!(act_line("bounty", "award", none), "awarded the bounty");
        assert_eq!(act_line("bounty", "submit", none), "submitted the work");
        assert_eq!(act_line("bounty", "revise", none), "asked for revisions");
        assert_eq!(act_line("bounty", "accept-work", none), "accepted the work");
        assert_eq!(act_line("bounty", "forfeit", none), "forfeited the bounty");
    }

    /// Two verbs read their note when there is one and stand on their own when
    /// there is not.
    #[test]
    fn act_line_uses_a_note_only_when_one_was_written() {
        let none: &[(&str, &str)] = &[];
        assert_eq!(act_line("handoff", "progress", none), "made progress");
        assert_eq!(
            act_line("handoff", "progress", &[("note", "halfway")]),
            "progress: halfway"
        );
        assert_eq!(act_line("bounty", "bid", none), "bid on the bounty");
        assert_eq!(
            act_line("bounty", "bid", &[("note", "two days")]),
            "bid: two days"
        );
    }

    /// A verb this has not been taught is named rather than described: a kind
    /// may add one without editing prose, and the room still sees what it was.
    #[test]
    fn act_line_names_a_verb_it_has_no_sentence_for() {
        assert_eq!(act_line("lease", "renew", &[]), "renew");
    }

    /// A follow-up names the action it is about, and that value is the task's
    /// id for a reader.
    #[test]
    fn a_follow_up_reads_the_task_it_names() {
        let event = parse_event(vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/act-id", OFFER_ID),
            ("+freeq.at/from", "did:plc:scholar"),
            ("+freeq.at/eventid", "01JCLAIMEVENTID00000000000"),
            ("+freeq.at/sig", "ed25519:kid:sig"),
        ])
        .expect("a task event");
        assert_eq!(event.kind, "handoff");
        assert_eq!(event.verb, "claim");
        assert_eq!(event.did.as_deref(), Some("did:plc:scholar"));
        assert_eq!(event.event_id, "01JCLAIMEVENTID00000000000");
        assert_eq!(event.task_id, OFFER_ID);
        assert_eq!(event.sig_tag.as_deref(), Some("ed25519:kid:sig"));
        assert!(!event.replayed);
    }

    /// An opener names no action, so it is the action: its own id is what
    /// every later event will name.
    #[test]
    fn an_opener_reads_as_its_own_task() {
        let event = parse_event(offer_tags()).expect("a task event");
        assert_eq!(event.verb, "offer");
        assert_eq!(event.task_id, OFFER_ID);
        assert_eq!(event.event_id, OFFER_ID);
        // Only the covered tags are read back; the rest of the line is not
        // the document.
        assert_eq!(
            event.fields.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "act",
                "act-caps",
                "act-ctx-h",
                "act-deadline",
                "act-title",
                "act-to",
                "act-verb"
            ]
        );
    }

    /// Reading an opener's task from the absence of `act-id` is the rules
    /// file's own answer, checked against it rather than assumed: for every
    /// kind, the verb that opens it is the verb that carries no `act-id`.
    #[test]
    fn the_opening_verb_is_the_one_that_names_no_task() {
        for kind in ["handoff", "bounty"] {
            let opens = crate::act_transitions::opening_verb(kind).expect("a known kind");
            let event = parse_event(vec![
                ("+freeq.at/act", kind),
                ("+freeq.at/act-verb", opens),
                ("+freeq.at/act-title", "anything"),
                ("+freeq.at/from", "did:plc:eliza"),
                ("+freeq.at/eventid", OFFER_ID),
            ])
            .expect("a task event");
            assert_eq!(
                event.task_id, event.event_id,
                "{kind}'s opener names itself"
            );
        }
    }

    /// The server's `account` names the actor when the sender wrote no `from`
    /// tag — which a well-formed event always does, but a reader should not
    /// need the event to be well-formed to say who sent it.
    #[test]
    fn the_account_tag_names_the_actor_when_from_is_absent() {
        let event = parse_event(vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "progress"),
            ("+freeq.at/act-id", OFFER_ID),
            ("account", "did:plc:scholar"),
            ("msgid", "01JPROGRESSEVENTID00000000"),
        ])
        .expect("a task event");
        assert_eq!(event.did.as_deref(), Some("did:plc:scholar"));
        assert_eq!(event.event_id, "01JPROGRESSEVENTID00000000");
    }

    /// The signed id wins over the server's `msgid` whichever order the tags
    /// arrive in — a map hands them up unordered.
    #[test]
    fn the_signed_id_wins_over_the_servers_msgid() {
        for tags in [
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", "did:plc:eliza"),
                ("msgid", "01JSERVERMINTED0000000000"),
                ("+freeq.at/eventid", OFFER_ID),
            ],
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", "did:plc:eliza"),
                ("+freeq.at/eventid", OFFER_ID),
                ("msgid", "01JSERVERMINTED0000000000"),
            ],
        ] {
            assert_eq!(parse_event(tags).expect("a task event").event_id, OFFER_ID);
        }
    }

    /// A replayed line carries the server's time tag; a live one does not.
    #[test]
    fn a_replayed_line_says_so() {
        let mut tags = offer_tags();
        tags.push(("time", "2026-08-22T10:00:00.000Z"));
        assert!(parse_event(tags).expect("a task event").replayed);
    }

    /// Two silences, not errors: an ordinary TAGMSG is not a task event, and
    /// neither is one nothing can be filed under.
    #[test]
    fn a_line_that_is_not_a_task_event_reads_as_none() {
        // No act tag at all — a reaction.
        assert!(parse_event(vec![("+react", "👍"), ("+reply", "01ABC")]).is_none());
        // `actor-class` is not an act tag; the coverage rule says so.
        assert!(
            parse_event(vec![("+freeq.at/actor-class", "agent"), ("msgid", "01ABC")]).is_none()
        );
        // Act tags but no id: nothing to file it under, and nothing to dedupe.
        assert!(
            parse_event(vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", "did:plc:eliza"),
            ])
            .is_none()
        );
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
