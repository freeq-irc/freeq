//! Signing and verification for chat events — messages, deletes, reactions.
//!
//! The chat profile of freeq's one signing model (see [`crate::sigtag`] for the
//! tag format and [`crate::act`] for the action profile). It replaces the
//! original PRIVMSG canonical, `{did}\0{target}\0{text}\0{timestamp}`, which
//! could not work: the timestamp was minted by the *client* and verified
//! against the *server's* clock, so a signature only verified when both landed
//! in the same second, and it never crossed S2S at all (the signed timestamp
//! is not on the wire, so a receiving server cannot rebuild the bytes).
//!
//! ## The documents
//!
//! Each event kind signs an **enumerated document**, JCS-canonicalized
//! (RFC 8785). Enumerated rather than act's sign-every-`act-*`-tag rule
//! because chat's tag space is *mixed*: the server stamps `account`, `time`,
//! `msgid`, `+freeq.at/reactions`, `+freeq.at/origin` and the commit verdicts
//! into the same namespaces clients write, so "sign what's present" would
//! cover the server's own tags and break the moment it stamped one.
//!
//! ```text
//! message:  {"body":"sha256:<hex>", "coord":{…}?, "edit":"<root msgid>"?,
//!            "from":"<DID>", "msgid":"<ULID>", "reply":"<root msgid>"?,
//!            "target":"<venue>"}
//!
//! delete:   {"from":"<DID>", "kind":"delete", "msgid":"<event ULID>",
//!            "subject":"<root msgid>", "target":"<venue>"}
//!
//! react:    {"emoji":"<emoji>", "from":"<DID>", "kind":"react"|"unreact",
//!            "msgid":"<event ULID>", "subject":"<root msgid>",
//!            "target":"<venue>"}
//!
//! coordination:
//!           {"event":"<event type>", "evidence":"<evidence type>"?,
//!            "from":"<DID>", "kind":"coordination", "msgid":"<event ULID>",
//!            "payload":"sha256:<hex>", "ref":"<referenced event id>"?,
//!            "target":"<venue>"}
//! ```
//!
//! Optional fields appear only when present, so a plain message reduces to
//! four keys. A message carries no `kind`: every other kind has one, so its
//! **absence is the message kind** — and because the field sets are disjoint
//! (`body` vs `kind`), no document of one kind can be reread as another.
//!
//! The coordination kind covers the task-event family (`+freeq.at/event`),
//! whose TAGMSG is what a server stores and later serves as a task card or an
//! audit row. Its `payload` is hashed like a body, over the **wire** value of
//! `+freeq.at/payload` — verbatim, app-level percent-encoding included, so a
//! verifier checks bytes it holds rather than a decoding it has to agree
//! about. Its `ref` is the event it refers to, usually a task's id; both wire
//! spellings (`+freeq.at/ref`, `+freeq.at/task-id`) mean that one field. Its
//! `evidence` is the kind of evidence an `evidence_attach` carries — covered
//! because it is what a reader renders and a bot reads, and a value on screen
//! that no signature covers is one a relay can change.
//!
//! Field rules, each with a reason:
//!
//! - **`body`** is `sha256:<lowercase hex>` over the UTF-8 **wire** body — the
//!   ciphertext under E2EE, so encryption and verification stay orthogonal,
//!   and the *assembled* body for a `draft/multiline` batch (the bytes the
//!   server stores), because the S2S hop re-escapes `\n` and the far side
//!   re-splits the frames. Hashed rather than inlined so the canonical stays
//!   small and a signature can be checked against a body held elsewhere.
//! - **`target`** is the **normalized venue**, not the wire target. See
//!   [`channel_venue`] and [`dm_venue`]: the server lowercases channel targets
//!   before anything else sees them, and DM history is replayed under the
//!   *reader's* view of the conversation, so "the target exactly as
//!   transmitted" is not reproducible by a verifier. The venue is bound
//!   because the channel is the queue: without it a server can present a line
//!   written in one room as written in another with every signature intact.
//! - **`msgid`** is the id the **signer** minted — the thing signed over, in
//!   place of a wall clock (a ULID embeds its own creation time and travels as
//!   a tag, so a receiver rebuilds the exact signed bytes instead of guessing
//!   a timestamp it cannot match).
//! - **`edit`/`reply`/`subject`** always name **root** msgids (the identity a
//!   message keeps for life). A signed event naming a revision is refused
//!   rather than rewritten, so the signed value is always the filed value.
//! - **`coord`** covers the client-authored coordination tags
//!   ([`COVERED_COORD_TAGS`], a **closed** set — an open rule would swallow
//!   future server-written `+freeq.at/*` tags). They're what bots act on, so
//!   receive-side sanitizing should break a signature exactly when it altered
//!   something.
//!
//! Excluded, each for its own reason: `+freeq.at/sig` (cannot cover itself);
//! `account`, `time`, the server-stamped `msgid` (server attestations);
//! `+freeq.at/origin` (provenance); the commit verdicts (the client's claim
//! rides the signed `coord` tags — the verdict is the server's);
//! `+freeq.at/reactions` (a server-computed tally); `+typing` and
//! `+freeq.at/av-*` (ephemera — durable state under a user's name gets
//! signed, ephemera don't); `batch`/`label`/`+freeq.at/multiline` (framing,
//! and the last is added by the sending server).
//!
//! The fixtures in `spec/chat-signing-vectors.json` freeze all of the above:
//! every implementation (server, TS bot-kit, Swift, Kotlin) must reproduce
//! each `canonical` and `sigTag` byte-for-byte from the `input`.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};

pub use crate::sigtag::SigError;

/// The tag carrying the id the **signer** minted for this event.
///
/// A signed event signs its own id, so the id cannot be the server-stamped
/// `msgid` (minted after the fact, and unknown to the signer). A server that
/// accepts this id files the event under it, which is what makes the signed
/// value and the stored value the same value.
pub const EVENT_ID_TAG: &str = "+freeq.at/eventid";

/// [`EVENT_ID_TAG`] without the client-tag `+`, accepted for symmetry with the
/// rest of the tag handling.
pub const EVENT_ID_TAG_BARE: &str = "freeq.at/eventid";

/// The tag by which a coordination event's **companion message** names the
/// event it renders. Covered by the message document — see
/// [`COVERED_COORD_TAGS`].
pub const COORD_ID_TAG: &str = "+freeq.at/coordid";

/// The client-authored coordination tags covered by a message document, as
/// canonical keys (the wire names are these with a `+freeq.at/` prefix).
///
/// Closed on purpose: a rule like "every `+freeq.at/*` tag" would cover tags
/// the *server* writes, and every new server-side tag would then invalidate
/// signatures that were fine.
///
/// `coordid` is how the **companion message** of a coordination event names
/// the event it renders. The event's own id rides on its TAGMSG in
/// [`EVENT_ID_TAG`], which no message can reuse — on a message that tag means
/// *that message's* id — and `ref`/`task-id` already mean the task an event
/// belongs to. Without a name of its own the pair travels joined by nothing,
/// and a reader holding both halves cannot tell they are one event.
///
/// The attachment fields are here for the same reason: a reader renders them
/// — an image inline, a link's title and description on screen — so a value
/// none of them covers is one a relay can change with the signature still
/// checking out. [`stripped_name`] folds both spellings onto one key, so
/// covering a field covers it however it was written; a client still writing
/// the bare spelling signs a field its peers never receive, which is what the
/// writers moving off it prevents.
///
/// Adding a name here costs nothing already signed: a document that does not
/// carry the tag canonicalizes to exactly the bytes it did before.
pub const COVERED_COORD_TAGS: [&str; 19] = [
    "coordid",
    "event",
    "evidence-type",
    "link-desc",
    "link-image",
    "link-title",
    "link-url",
    "media-alt",
    "media-blurhash",
    "media-duration",
    "media-filename",
    "media-h",
    "media-mime",
    "media-size",
    "media-url",
    "media-w",
    "payload",
    "ref",
    "task-id",
];

const CLIENT_TAG_PREFIX: &str = "+freeq.at/";
const TAG_PREFIX: &str = "freeq.at/";

/// What a mutation event does to the message it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Retract a message. Authorship (or channel op) is checked separately;
    /// the signature only attests who *asked*.
    Delete,
    /// Add a reaction.
    React,
    /// Remove a previously added reaction.
    Unreact,
}

impl Mutation {
    /// The `kind` value in the canonical document.
    pub fn as_str(self) -> &'static str {
        match self {
            Mutation::Delete => "delete",
            Mutation::React => "react",
            Mutation::Unreact => "unreact",
        }
    }
}

/// What a document that names a `kind` is a claim about.
///
/// A message names none — its absence is the message kind — so this covers
/// everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocKind {
    Mutation(Mutation),
    Coordination,
}

impl DocKind {
    fn as_str(self) -> &'static str {
        match self {
            DocKind::Mutation(m) => m.as_str(),
            DocKind::Coordination => "coordination",
        }
    }
}

/// A chat event's signed document, before canonicalization.
///
/// Built through [`ChatDoc::message`] / [`ChatDoc::mutation`] so a document is
/// impossible to construct without the mandatory fields — a missing `from`,
/// `msgid` or `target` is a programming error, not a runtime verdict.
#[derive(Debug, Clone)]
pub struct ChatDoc<'a> {
    from: &'a str,
    msgid: &'a str,
    target: &'a str,
    kind: Option<DocKind>,
    /// Message only: the raw wire body. Hashed on canonicalization.
    body: Option<&'a str>,
    /// Message only.
    reply: Option<&'a str>,
    /// Message only.
    edit: Option<&'a str>,
    /// Message only.
    coord: BTreeMap<&'a str, &'a str>,
    /// Mutation only: the root msgid being acted on.
    subject: Option<&'a str>,
    /// Reactions only.
    emoji: Option<&'a str>,
    /// Coordination only: the event type (`task_request`, `task_complete`, …).
    event: Option<&'a str>,
    /// Coordination only: the raw wire payload. Hashed on canonicalization.
    payload: Option<&'a str>,
    /// Coordination only: the event this one refers to, usually a task's id.
    reference: Option<&'a str>,
    /// Coordination only: what kind of evidence an `evidence_attach` carries.
    evidence: Option<&'a str>,
}

impl<'a> ChatDoc<'a> {
    /// A PRIVMSG/NOTICE document. `body` is the wire body (ciphertext under
    /// E2EE, assembled body for a multiline batch) and is hashed, never
    /// inlined. `target` must already be a normalized venue — see
    /// [`channel_venue`] / [`dm_venue`].
    pub fn message(from: &'a str, msgid: &'a str, target: &'a str, body: &'a str) -> Self {
        ChatDoc {
            from,
            msgid,
            target,
            kind: None,
            body: Some(body),
            reply: None,
            edit: None,
            coord: BTreeMap::new(),
            subject: None,
            emoji: None,
            event: None,
            payload: None,
            reference: None,
            evidence: None,
        }
    }

    /// A mutation document (delete / react / unreact). `subject` is the
    /// **root** msgid of the message being acted on; `msgid` is this event's
    /// own signer-minted id.
    pub fn mutation(
        kind: Mutation,
        from: &'a str,
        msgid: &'a str,
        target: &'a str,
        subject: &'a str,
    ) -> Self {
        ChatDoc {
            from,
            msgid,
            target,
            kind: Some(DocKind::Mutation(kind)),
            body: None,
            reply: None,
            edit: None,
            coord: BTreeMap::new(),
            subject: Some(subject),
            emoji: None,
            event: None,
            payload: None,
            reference: None,
            evidence: None,
        }
    }

    /// A coordination-event document — the TAGMSG half of a task request, an
    /// update, a completion, attached evidence.
    ///
    /// The server *stores and serves* this event: task cards and the audit
    /// timeline are built from it. So it signs standalone, over its own
    /// signer-minted id, rather than leaning on the companion PRIVMSG that
    /// renders it — a stored row nobody can check is the thing this signing
    /// model exists to end.
    ///
    /// `event_type` is the verb (`task_request`, `task_complete`, …).
    /// `target` must already be a normalized venue.
    pub fn coordination(
        from: &'a str,
        msgid: &'a str,
        target: &'a str,
        event_type: &'a str,
    ) -> Self {
        ChatDoc {
            from,
            msgid,
            target,
            kind: Some(DocKind::Coordination),
            body: None,
            reply: None,
            edit: None,
            coord: BTreeMap::new(),
            subject: None,
            emoji: None,
            event: Some(event_type),
            payload: None,
            reference: None,
            evidence: None,
        }
    }

    /// The coordination payload, exactly as it rides in `+freeq.at/payload`:
    /// IRC-unescaped, and otherwise verbatim.
    ///
    /// Hashed, not inlined — a payload runs to kilobytes, and the log stores
    /// the canonical. Verbatim because any app-level encoding inside the value
    /// (the emitters percent-encode `;` and space) is opaque bytes to the
    /// signature: a verifier hashes what it received without needing to know
    /// how to decode it. Ignored on other kinds.
    pub fn with_payload(mut self, payload: &'a str) -> Self {
        self.payload = Some(payload);
        self
    }

    /// The event this coordination event refers to — a task's id, for every
    /// event in a task's life after the request that opened it.
    ///
    /// Covered because the reference *is* the linkage: an update re-pointed at
    /// a different task in flight would otherwise still read as signed.
    /// Ignored on other kinds. Both wire spellings (`+freeq.at/ref` and
    /// `+freeq.at/task-id`) mean this one field.
    pub fn with_ref(mut self, reference: &'a str) -> Self {
        self.reference = Some(reference);
        self
    }

    /// The kind of evidence an `evidence_attach` event carries, as it rides in
    /// `+freeq.at/evidence-type`.
    ///
    /// Covered because it is *rendered*: a reader shows it as the evidence's
    /// icon and label, and a bot reads it off the event. A value on screen
    /// that no signature covers is a value a relay can change. Ignored on
    /// other kinds.
    pub fn with_evidence(mut self, evidence_type: &'a str) -> Self {
        self.evidence = Some(evidence_type);
        self
    }

    /// Mark this message as a reply to `root_msgid`. Covered so that adding or
    /// stripping the reply in flight — which changes what the message *is* —
    /// cannot happen without breaking the signature.
    pub fn with_reply(mut self, root_msgid: &'a str) -> Self {
        self.reply = Some(root_msgid);
        self
    }

    /// Mark this message as an edit of `root_msgid`.
    pub fn with_edit(mut self, root_msgid: &'a str) -> Self {
        self.edit = Some(root_msgid);
        self
    }

    /// The emoji a react/unreact carries. Ignored for other kinds.
    pub fn with_emoji(mut self, emoji: &'a str) -> Self {
        self.emoji = Some(emoji);
        self
    }

    /// Cover the coordination tags in `tags` (see [`COVERED_COORD_TAGS`]).
    ///
    /// Accepts wire names with or without the `+freeq.at/` prefix; values must
    /// be IRC-**unescaped** already, and are covered verbatim (any app-level
    /// encoding inside a value is opaque bytes to the signature).
    pub fn with_coord<I>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        for (name, value) in tags {
            let key = stripped_name(name);
            if COVERED_COORD_TAGS.contains(&key) {
                self.coord.insert(key, value);
            }
        }
        self
    }

    /// The exact UTF-8 string that gets signed.
    pub fn canonical(&self) -> String {
        let mut doc = serde_json::Map::new();
        let mut put = |k: &str, v: &str| {
            doc.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        };
        put("from", self.from);
        put("msgid", self.msgid);
        put("target", self.target);
        if let Some(kind) = self.kind {
            put("kind", kind.as_str());
        }
        if let Some(body) = self.body {
            put("body", &body_hash(body));
        }
        if let Some(reply) = self.reply {
            put("reply", reply);
        }
        if let Some(edit) = self.edit {
            put("edit", edit);
        }
        if let Some(subject) = self.subject {
            put("subject", subject);
        }
        if let Some(emoji) = self.emoji
            && matches!(
                self.kind,
                Some(DocKind::Mutation(Mutation::React | Mutation::Unreact))
            )
        {
            put("emoji", emoji);
        }
        if matches!(self.kind, Some(DocKind::Coordination)) {
            if let Some(event) = self.event {
                put("event", event);
            }
            if let Some(payload) = self.payload {
                put("payload", &body_hash(payload));
            }
            if let Some(reference) = self.reference {
                put("ref", reference);
            }
            if let Some(evidence) = self.evidence {
                put("evidence", evidence);
            }

        }
        if !self.coord.is_empty() {
            let coord: serde_json::Map<String, serde_json::Value> = self
                .coord
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect();
            doc.insert("coord".to_string(), serde_json::Value::Object(coord));
        }
        crate::canonical::canonicalize(&doc).expect("string map serializes")
    }

    /// Sign this document, returning the `+freeq.at/sig` tag value.
    pub fn sign(&self, key: &SigningKey) -> String {
        crate::sigtag::sign_canonical(&self.canonical(), key)
    }

    /// Verify `sig_tag` over this document. Rebuild the document from what was
    /// received — never from what was sent — so an altered field shows up as
    /// [`SigError::Invalid`].
    pub fn verify(&self, sig_tag: &str, key: &VerifyingKey) -> Result<(), SigError> {
        crate::sigtag::verify_canonical(&self.canonical(), sig_tag, key)
    }
}

/// `sha256:<lowercase hex>` over the UTF-8 bytes of a wire body.
pub fn body_hash(body: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(body.as_bytes());
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The venue of a channel event: the channel name, lowercased.
///
/// Not cosmetic. freeq's server normalizes a channel target to lowercase
/// before persistence, relay, or signature checking, so a client that signed
/// `#Ops` while sending `PRIVMSG #Ops` would fail verification at its own
/// origin. Normalizing in the canonical makes the venue reproducible by every
/// verifier, including one replaying history years later.
pub fn channel_venue(channel: &str) -> String {
    channel.to_lowercase()
}

/// The venue of a direct message: `dm:<did_a>,<did_b>` with the DIDs sorted.
///
/// A DM's wire target is a nick (mutable, and unique only per server) or a
/// `did:`, and history is replayed under whichever of those the *reader*
/// asked for — so the wire target is not a venue a verifier can reproduce.
/// The sorted DID pair is: both participants and any peer derive the same
/// string, and it is already the key the conversation is persisted under.
pub fn dm_venue(did_a: &str, did_b: &str) -> String {
    if did_a <= did_b {
        format!("dm:{did_a},{did_b}")
    } else {
        format!("dm:{did_b},{did_a}")
    }
}

/// Mint an event id: a ULID, 26 characters of uppercase Crockford base32,
/// 48-bit millisecond timestamp then 80 random bits.
///
/// Signers mint their own ids ([`EVENT_ID_TAG`]) because the signature covers
/// the id. A server checks the shape and that the embedded time is near its
/// own before adopting one, so the timestamp must be real.
pub fn new_event_id() -> String {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let random: u128 = ((rand::random::<u64>() as u128) << 16 | rand::random::<u16>() as u128)
        & ((1u128 << 80) - 1);

    let mut out = [0u8; 26];
    let mut t = ms;
    for slot in out[..10].iter_mut().rev() {
        *slot = CROCKFORD[(t & 0x1F) as usize];
        t >>= 5;
    }
    let mut r = random;
    for slot in out[10..].iter_mut().rev() {
        *slot = CROCKFORD[(r & 0x1F) as usize];
        r >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("Crockford alphabet is ASCII")
}

/// The venue to sign for a wire target, from the sender's point of view.
///
/// `None` when the target is a bare nick: a nick is not a venue (it is unique
/// only per server, and mutable), and the DM venue needs the recipient's DID.
/// A client that cannot resolve the peer's DID should send unsigned rather
/// than sign a venue no verifier would rebuild.
pub fn venue_for_target(target: &str, sender_did: &str) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return Some(channel_venue(target));
    }
    if target.starts_with("did:") {
        return Some(dm_venue(sender_did, target));
    }
    None
}

/// Strip the client-tag vendor prefix from a tag name, if present.
fn stripped_name(tag_name: &str) -> &str {
    tag_name
        .strip_prefix(CLIENT_TAG_PREFIX)
        .or_else(|| tag_name.strip_prefix(TAG_PREFIX))
        .unwrap_or(tag_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    const ALICE: &str = "did:plc:k2n3e2vsihf3farequ44t5j7";
    const MSGID: &str = "01KYVT5Z8Q0000000000000000";
    const ROOT: &str = "01KYVT1W2P0000000000000000";

    #[test]
    fn a_plain_message_reduces_to_four_keys() {
        let doc = ChatDoc::message(ALICE, MSGID, "#freeq", "hello");
        assert_eq!(
            doc.canonical(),
            format!(
                r##"{{"body":"{}","from":"{ALICE}","msgid":"{MSGID}","target":"#freeq"}}"##,
                body_hash("hello")
            )
        );
    }

    /// The exact bytes published in the RFC thread for a delete.
    #[test]
    fn the_delete_canonical_is_the_published_string() {
        let doc = ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT);
        assert_eq!(
            doc.canonical(),
            r##"{"from":"did:plc:k2n3e2vsihf3farequ44t5j7","kind":"delete","msgid":"01KYVT5Z8Q0000000000000000","subject":"01KYVT1W2P0000000000000000","target":"#freeq"}"##
        );
    }

    #[test]
    fn optional_message_fields_appear_only_when_present() {
        let plain = ChatDoc::message(ALICE, MSGID, "#freeq", "hi").canonical();
        assert!(!plain.contains("reply"), "no reply key on a plain message");
        assert!(!plain.contains("edit"));
        assert!(!plain.contains("coord"));

        let full = ChatDoc::message(ALICE, MSGID, "#freeq", "hi")
            .with_reply(ROOT)
            .with_edit(ROOT)
            .with_coord([("+freeq.at/event", "task_request")])
            .canonical();
        assert!(full.contains(r#""reply":"#));
        assert!(full.contains(r#""edit":"#));
        assert!(full.contains(r#""coord":{"event":"task_request"}"#));
    }

    /// The companion message of a coordination event names that event, and the
    /// name is inside the signature. Without it the pair is joined by nothing:
    /// the TAGMSG carries the event's id in a covered field, the message
    /// carries its own, and a reader holding both cannot tell they are one
    /// event.
    #[test]
    fn a_companion_message_covers_the_event_it_renders() {
        let doc = ChatDoc::message(ALICE, MSGID, "#swarm", "📋 New task: ship it").with_coord([
            ("+freeq.at/event", "task_request"),
            ("+freeq.at/coordid", ROOT),
        ]);
        assert!(
            doc.canonical()
                .contains(r#""coord":{"coordid":"01KYVT1W2P0000000000000000","event":"task_request"}"#),
            "{}",
            doc.canonical()
        );

        // Re-pointing the companion at another event is tampering: it would
        // file a rendering under work it does not describe.
        let key = test_key(1);
        let sig = doc.sign(&key);
        let repointed = ChatDoc::message(ALICE, MSGID, "#swarm", "📋 New task: ship it")
            .with_coord([
                ("+freeq.at/event", "task_request"),
                ("+freeq.at/coordid", "01KYVT9ZZZ0000000000000000"),
            ]);
        assert_eq!(
            repointed.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );
    }

    /// Adding a name to the covered set must not move a byte for a message
    /// that does not carry it — every signature already made stays good.
    #[test]
    fn a_message_without_the_new_tag_signs_exactly_as_before() {
        let plain = ChatDoc::message(ALICE, MSGID, "#freeq", "hi").canonical();
        assert_eq!(
            plain,
            format!(
                r##"{{"body":"{}","from":"{ALICE}","msgid":"{MSGID}","target":"#freeq"}}"##,
                body_hash("hi")
            )
        );
        let with_others = ChatDoc::message(ALICE, MSGID, "#freeq", "hi")
            .with_coord([("+freeq.at/event", "task_request")])
            .canonical();
        assert!(!with_others.contains("coordid"), "{with_others}");
    }

    /// An attachment is rendered, so a signature has to cover what it says
    /// about itself — and cover it under either spelling, since the two fold
    /// onto one key.
    #[test]
    fn an_attachment_is_covered_however_it_was_spelled() {
        let prefixed = ChatDoc::message(ALICE, MSGID, "#freeq", "📎 cat.png").with_coord([
            ("+freeq.at/media-url", "https://cdn/cat.png"),
            ("+freeq.at/media-mime", "image/png"),
            ("+freeq.at/media-alt", "a cat"),
        ]);
        let bare = ChatDoc::message(ALICE, MSGID, "#freeq", "📎 cat.png").with_coord([
            ("media-url", "https://cdn/cat.png"),
            ("media-mime", "image/png"),
            ("media-alt", "a cat"),
        ]);
        assert_eq!(
            prefixed.canonical(),
            bare.canonical(),
            "a covered set a relay could dodge by rewriting the spelling covers nothing"
        );
        assert!(prefixed.canonical().contains(r#""media-url":"https://cdn/cat.png""#));

        let key = test_key(1);
        let sig = prefixed.sign(&key);
        let repointed = ChatDoc::message(ALICE, MSGID, "#freeq", "📎 cat.png").with_coord([
            ("+freeq.at/media-url", "https://cdn/dog.png"),
            ("+freeq.at/media-mime", "image/png"),
            ("+freeq.at/media-alt", "a cat"),
        ]);
        assert_eq!(
            repointed.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );

        let retitled = ChatDoc::message(ALICE, MSGID, "#freeq", "🔗 A post")
            .with_coord([("+freeq.at/link-url", "https://example.com/post")]);
        let sig = retitled.sign(&key);
        let other = ChatDoc::message(ALICE, MSGID, "#freeq", "🔗 A post").with_coord([
            ("+freeq.at/link-url", "https://example.com/post"),
            ("+freeq.at/link-title", "Something else entirely"),
        ]);
        assert_eq!(
            other.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid),
            "a title added in flight is a title the sender never wrote"
        );
    }

    /// A field the sender left out is absent from the document, full stop.
    /// A reader's default for a missing type is a rendering decision; putting
    /// it in the signed bytes would have every other implementation rebuild
    /// from the wire, find no such field, and call an honest message invalid.
    #[test]
    fn a_field_the_sender_omitted_is_not_in_the_document() {
        let doc = ChatDoc::message(ALICE, MSGID, "#freeq", "📎 thing.bin")
            .with_coord([("+freeq.at/media-url", "https://cdn/thing.bin")]);
        let canonical = doc.canonical();
        assert!(canonical.contains(r#""media-url""#), "{canonical}");
        assert!(
            !canonical.contains("media-mime"),
            "no default may reach the signed bytes: {canonical}"
        );
        assert!(
            !canonical.contains("octet-stream"),
            "least of all a type nobody declared: {canonical}"
        );
    }

    #[test]
    fn coord_covers_the_closed_set_and_nothing_else() {
        let doc = ChatDoc::message(ALICE, MSGID, "#freeq", "hi").with_coord([
            ("+freeq.at/event", "task_request"),
            ("+freeq.at/payload", "%7B%7D"),
            ("freeq.at/task-id", "01HZ"),
            ("ref", "01HY"),
            // Not client-authored: a server tally, a verdict, provenance,
            // ephemera. None may enter a signed document.
            ("+freeq.at/reactions", "👍:2"),
            ("+freeq.at/commit-verified", "true"),
            ("+freeq.at/origin", "peer.example"),
            ("+freeq.at/av-state", "live"),
            ("account", "did:plc:someone-else"),
        ]);
        assert_eq!(
            doc.canonical(),
            format!(
                r##"{{"body":"{}","coord":{{"event":"task_request","payload":"%7B%7D","ref":"01HY","task-id":"01HZ"}},"from":"{ALICE}","msgid":"{MSGID}","target":"#freeq"}}"##,
                body_hash("hi")
            )
        );
    }

    #[test]
    fn a_reaction_covers_its_emoji_and_a_delete_has_none() {
        let react = ChatDoc::mutation(Mutation::React, ALICE, MSGID, "#freeq", ROOT)
            .with_emoji("👍")
            .canonical();
        assert!(react.contains(r#""emoji":"👍""#));
        assert!(react.contains(r#""kind":"react""#));

        // An emoji on a delete is meaningless and must not silently change the
        // bytes — otherwise a client that sets it and one that doesn't sign
        // different documents for the same event.
        let delete = ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT);
        assert_eq!(
            delete.clone().with_emoji("👍").canonical(),
            delete.canonical()
        );
    }

    #[test]
    fn react_and_unreact_are_different_documents() {
        let react =
            ChatDoc::mutation(Mutation::React, ALICE, MSGID, "#freeq", ROOT).with_emoji("👍");
        let unreact =
            ChatDoc::mutation(Mutation::Unreact, ALICE, MSGID, "#freeq", ROOT).with_emoji("👍");
        assert_ne!(react.canonical(), unreact.canonical());

        // A verb swap in flight is tampering, and reads as such.
        let key = test_key(1);
        let sig = react.sign(&key);
        assert_eq!(
            unreact.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );
    }

    #[test]
    fn a_coordination_event_signs_its_type_payload_and_reference() {
        let doc = ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
            .with_payload("%7B%22ok%22%3Atrue%7D")
            .with_ref(ROOT);
        assert_eq!(
            doc.canonical(),
            format!(
                r##"{{"event":"task_complete","from":"{ALICE}","kind":"coordination","msgid":"{MSGID}","payload":"{}","ref":"{ROOT}","target":"#swarm"}}"##,
                body_hash("%7B%22ok%22%3Atrue%7D")
            )
        );
    }

    /// A task request references nothing, so the key is absent rather than
    /// empty — the same rule every optional field follows.
    #[test]
    fn a_coordination_event_without_a_reference_omits_the_key() {
        let doc = ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_request")
            .with_payload("%7B%7D");
        assert!(!doc.canonical().contains(r#""ref""#), "{}", doc.canonical());
    }

    /// The payload is what a bot acts on. Rewriting it in flight — a relay
    /// "sanitizing" the JSON, an intermediary changing an amount — is the
    /// attack the signature exists to make visible.
    #[test]
    fn altering_a_coordination_payload_or_reference_breaks_the_signature() {
        let key = test_key(1);
        let sent = ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
            .with_payload("%7B%22paid%22%3A1%7D")
            .with_ref(ROOT);
        let sig = sent.sign(&key);
        for tampered in [
            ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
                .with_payload("%7B%22paid%22%3A9%7D")
                .with_ref(ROOT),
            ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
                .with_payload("%7B%22paid%22%3A1%7D")
                .with_ref("01KYVT9ZZZ0000000000000000"),
            // The event type is the verb: a completion re-presented as a
            // failure is a different claim about the same work.
            ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_failed")
                .with_payload("%7B%22paid%22%3A1%7D")
                .with_ref(ROOT),
        ] {
            assert_eq!(
                tampered.verify(&sig, &key.verifying_key()),
                Err(SigError::Invalid)
            );
        }
        sent.verify(&sig, &key.verifying_key()).unwrap();
    }

    /// Coordination fields belong to the coordination kind alone. A builder
    /// call on another kind must not move a byte, or a client that makes the
    /// call and one that doesn't sign different documents for the same event.
    /// What kind of evidence an event carries is rendered — a reader shows it
    /// as the evidence's icon and label, and a bot reads it off the event. It
    /// rode on a signed event covered by nothing, so a relay could change it
    /// and no verifier would notice. Both halves cover it now: the event's own
    /// document, and the companion's coordination tags.
    #[test]
    fn the_kind_of_evidence_an_event_carries_is_covered() {
        let key = test_key(1);
        let sent = ChatDoc::coordination(ALICE, MSGID, "#swarm", "evidence_attach")
            .with_payload("%7B%22type%22%3A%22code_review%22%7D")
            .with_ref(ROOT)
            .with_evidence("code_review");
        assert!(
            sent.canonical().contains(r#""evidence":"code_review""#),
            "{}",
            sent.canonical()
        );
        let sig = sent.sign(&key);
        sent.verify(&sig, &key.verifying_key()).unwrap();

        // A relabelled evidence card is a different claim about the same work.
        let relabelled = ChatDoc::coordination(ALICE, MSGID, "#swarm", "evidence_attach")
            .with_payload("%7B%22type%22%3A%22code_review%22%7D")
            .with_ref(ROOT)
            .with_evidence("test_run");
        assert_eq!(
            relabelled.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );

        // And on the companion, through the covered coordination tags.
        let companion = ChatDoc::message(ALICE, MSGID, "#swarm", "📎 Evidence")
            .with_coord([("+freeq.at/evidence-type", "code_review")]);
        assert!(
            companion
                .canonical()
                .contains(r#""coord":{"evidence-type":"code_review"}"#),
            "{}",
            companion.canonical()
        );
    }

    /// An event that carries no evidence type signs exactly the bytes it did
    /// before the field existed.
    #[test]
    fn a_coordination_event_without_evidence_signs_as_before() {
        let doc = ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_request")
            .with_payload("%7B%7D");
        assert_eq!(
            doc.canonical(),
            format!(
                r##"{{"event":"task_request","from":"{ALICE}","kind":"coordination","msgid":"{MSGID}","payload":"{}","target":"#swarm"}}"##,
                body_hash("%7B%7D")
            )
        );
    }

    #[test]
    fn coordination_fields_are_ignored_on_other_kinds() {
        let message = ChatDoc::message(ALICE, MSGID, "#freeq", "hi");
        assert_eq!(
            message
                .clone()
                .with_payload("%7B%7D")
                .with_ref(ROOT)
                .canonical(),
            message.canonical()
        );
        let delete = ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT);
        assert_eq!(
            delete
                .clone()
                .with_payload("%7B%7D")
                .with_evidence("code_review")
                .canonical(),
            delete.canonical()
        );
    }

    #[test]
    fn message_and_mutation_documents_cannot_be_confused() {
        // Disjoint field sets: a message has `body` and no `kind`.
        let msg = ChatDoc::message(ALICE, MSGID, "#freeq", "hi").canonical();
        let del = ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT).canonical();
        assert!(msg.contains(r#""body""#) && !msg.contains(r#""kind""#));
        assert!(del.contains(r#""kind""#) && !del.contains(r#""body""#));
        // A coordination event names its own kind and carries neither a body
        // nor a subject, so no document of one kind reads as another.
        let coord = ChatDoc::coordination(ALICE, MSGID, "#freeq", "task_request")
            .with_payload("%7B%7D")
            .canonical();
        assert!(coord.contains(r#""kind":"coordination""#));
        assert!(!coord.contains(r#""body""#) && !coord.contains(r#""subject""#));
    }

    #[test]
    fn body_is_hashed_over_wire_bytes_including_multiline_and_unicode() {
        // Known-answer: sha256("") — proves the hex encoding and the prefix.
        assert_eq!(
            body_hash(""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // An assembled multiline body hashes as the bytes the server stores,
        // real newlines and all — not the `\n`-escaped S2S form.
        assert_ne!(body_hash("a\nb"), body_hash("a\\nb"));
        // Non-ASCII is hashed as UTF-8, not as anything IRC-escaped.
        assert_eq!(body_hash("ok — ✓").len(), "sha256:".len() + 64);
    }

    #[test]
    fn altering_the_body_breaks_the_signature() {
        let key = test_key(1);
        let sent = ChatDoc::message(ALICE, MSGID, "#freeq", "ship it");
        let sig = sent.sign(&key);
        let tampered = ChatDoc::message(ALICE, MSGID, "#freeq", "ship it tomorrow");
        assert_eq!(
            tampered.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );
        verify_roundtrip(&sent, &sig, &key);
    }

    #[test]
    fn stripping_an_edit_or_reply_breaks_the_signature() {
        let key = test_key(1);
        for sent in [
            ChatDoc::message(ALICE, MSGID, "#freeq", "hi").with_edit(ROOT),
            ChatDoc::message(ALICE, MSGID, "#freeq", "hi").with_reply(ROOT),
        ] {
            let sig = sent.sign(&key);
            let stripped = ChatDoc::message(ALICE, MSGID, "#freeq", "hi");
            assert_eq!(
                stripped.verify(&sig, &key.verifying_key()),
                Err(SigError::Invalid),
                "stripping a covered field is tampering"
            );
        }
    }

    #[test]
    fn re_venuing_breaks_the_signature() {
        let key = test_key(1);
        let sent = ChatDoc::message(ALICE, MSGID, "#private-team", "the number is 12");
        let sig = sent.sign(&key);
        let re_venued = ChatDoc::message(ALICE, MSGID, "#public", "the number is 12");
        assert_eq!(
            re_venued.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid),
            "a sealed letter needs a sealed envelope"
        );
    }

    #[test]
    fn swapping_the_subject_of_a_mutation_breaks_the_signature() {
        let key = test_key(1);
        let sent = ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT);
        let sig = sent.sign(&key);
        let other = ChatDoc::mutation(
            Mutation::Delete,
            ALICE,
            MSGID,
            "#freeq",
            "01KYVT9ZZZ0000000000000000",
        );
        assert_eq!(
            other.verify(&sig, &key.verifying_key()),
            Err(SigError::Invalid)
        );
    }

    #[test]
    fn a_channel_venue_is_case_folded_the_way_the_server_folds_it() {
        assert_eq!(channel_venue("#Ops"), "#ops");
        assert_eq!(channel_venue("#ops"), "#ops");
        // …so a client that types mixed case and one that types lower case
        // sign the same document for the same room.
        let key = test_key(1);
        let (as_typed, as_folded) = (channel_venue("#Ops"), channel_venue("#ops"));
        let typed = ChatDoc::message(ALICE, MSGID, &as_typed, "hi");
        let sig = typed.sign(&key);
        let seen = ChatDoc::message(ALICE, MSGID, &as_folded, "hi");
        seen.verify(&sig, &key.verifying_key()).unwrap();
    }

    #[test]
    fn a_minted_event_id_is_a_ulid_at_the_current_time() {
        let id = new_event_id();
        assert_eq!(id.len(), 26);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b))),
            "Crockford base32 only: {id}"
        );
        // Two ids differ, and the timestamp half really is the time (so a
        // server's skew check passes).
        assert_ne!(new_event_id(), new_event_id());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut decoded: u64 = 0;
        const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        for b in id.bytes().take(10) {
            decoded = (decoded << 5) | CROCKFORD.iter().position(|c| *c == b).unwrap() as u64;
        }
        assert!(decoded.abs_diff(now_ms) < 5_000, "{decoded} vs {now_ms}");
    }

    #[test]
    fn a_venue_comes_from_the_target_except_for_a_bare_nick() {
        assert_eq!(
            venue_for_target("#Ops", ALICE).as_deref(),
            Some("#ops"),
            "a channel is folded"
        );
        assert_eq!(
            venue_for_target("did:plc:aaa", ALICE).as_deref(),
            Some("dm:did:plc:aaa,did:plc:k2n3e2vsihf3farequ44t5j7"),
            "a DID target gives the sorted pair"
        );
        assert_eq!(
            venue_for_target("bob", ALICE),
            None,
            "a nick is not a venue — send unsigned rather than sign a guess"
        );
    }

    #[test]
    fn a_dm_venue_is_the_sorted_did_pair_from_either_end() {
        let (a, b) = ("did:plc:aaa", "did:plc:bbb");
        assert_eq!(dm_venue(a, b), "dm:did:plc:aaa,did:plc:bbb");
        assert_eq!(dm_venue(b, a), dm_venue(a, b), "sender and recipient agree");
    }

    #[test]
    fn a_wrong_key_or_unknown_algorithm_is_unverifiable_never_invalid() {
        let doc = ChatDoc::message(ALICE, MSGID, "#freeq", "hi");
        let sig = doc.sign(&test_key(1));
        let err = doc.verify(&sig, &test_key(2).verifying_key()).unwrap_err();
        assert_eq!(err, SigError::KidMismatch);
        assert!(err.is_unverifiable());

        let future = doc
            .verify("ml-dsa-44:kid:c2ln", &test_key(1).verifying_key())
            .unwrap_err();
        assert!(future.is_unverifiable(), "a newer signer is not a forger");
    }

    fn verify_roundtrip(doc: &ChatDoc<'_>, sig: &str, key: &SigningKey) {
        doc.verify(sig, &key.verifying_key()).unwrap();
    }

    // ---------------------------------------------------------------
    // Cross-language vectors. Same pattern as spec/act-signing-vectors.json:
    // generated here, checked here, reproduced byte-for-byte by every other
    // implementation.
    // ---------------------------------------------------------------

    struct Case {
        name: &'static str,
        seed: u8,
        doc: ChatDoc<'static>,
        /// The document input as the fixture publishes it, so another
        /// implementation builds the canonical from data rather than from
        /// this file's Rust.
        input: serde_json::Value,
    }

    fn cases() -> Vec<Case> {
        use serde_json::json;
        vec![
            Case {
                name: "message-plain",
                seed: 1,
                doc: ChatDoc::message(ALICE, MSGID, "#freeq", "ship it"),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    "target": "#freeq", "bodyText": "ship it",
                }),
            },
            Case {
                name: "message-channel-venue-is-folded",
                seed: 1,
                doc: ChatDoc::message(ALICE, MSGID, "#ops", "deploying"),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    // The raw target as typed; the venue rule folds it.
                    "rawTarget": "#Ops", "target": "#ops", "bodyText": "deploying",
                }),
            },
            Case {
                name: "message-dm-venue",
                seed: 1,
                doc: ChatDoc::message(
                    ALICE,
                    MSGID,
                    "dm:did:plc:aaa,did:plc:k2n3e2vsihf3farequ44t5j7",
                    "just between us",
                ),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    "dmParticipants": [ALICE, "did:plc:aaa"],
                    "target": "dm:did:plc:aaa,did:plc:k2n3e2vsihf3farequ44t5j7",
                    "bodyText": "just between us",
                }),
            },
            Case {
                name: "message-reply-edit-and-coord",
                seed: 2,
                doc: ChatDoc::message(ALICE, MSGID, "#swarm", "revised: use the cached index")
                    .with_reply(ROOT)
                    .with_edit(ROOT)
                    .with_coord([
                        ("+freeq.at/event", "task_result"),
                        ("+freeq.at/payload", "%7B%22ok%22%3Atrue%7D"),
                        ("+freeq.at/task-id", "01KYVT2AAA0000000000000000"),
                        ("+freeq.at/ref", "01KYVT2BBB0000000000000000"),
                        // Must not be covered — a server tally.
                        ("+freeq.at/reactions", "👍:3"),
                    ]),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    "target": "#swarm", "bodyText": "revised: use the cached index",
                    "reply": ROOT, "edit": ROOT,
                    "tags": {
                        "+freeq.at/event": "task_result",
                        "+freeq.at/payload": "%7B%22ok%22%3Atrue%7D",
                        "+freeq.at/task-id": "01KYVT2AAA0000000000000000",
                        "+freeq.at/ref": "01KYVT2BBB0000000000000000",
                        "+freeq.at/reactions": "👍:3",
                    },
                }),
            },
            Case {
                name: "message-multiline-and-escaping",
                seed: 3,
                doc: ChatDoc::message(
                    ALICE,
                    MSGID,
                    "#freeq",
                    "line one\nline two — \"quoted\" ✓\nline three",
                ),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID, "target": "#freeq",
                    // The assembled body, real newlines — not the S2S-escaped form.
                    "bodyText": "line one\nline two — \"quoted\" ✓\nline three",
                }),
            },
            Case {
                name: "delete",
                seed: 1,
                doc: ChatDoc::mutation(Mutation::Delete, ALICE, MSGID, "#freeq", ROOT),
                input: json!({
                    "kind": "delete", "from": ALICE, "msgid": MSGID,
                    "target": "#freeq", "subject": ROOT,
                }),
            },
            Case {
                name: "react",
                seed: 4,
                doc: ChatDoc::mutation(Mutation::React, ALICE, MSGID, "#freeq", ROOT)
                    .with_emoji("👍"),
                input: json!({
                    "kind": "react", "from": ALICE, "msgid": MSGID,
                    "target": "#freeq", "subject": ROOT, "emoji": "👍",
                }),
            },
            Case {
                name: "unreact",
                seed: 4,
                doc: ChatDoc::mutation(Mutation::Unreact, ALICE, MSGID, "#freeq", ROOT)
                    .with_emoji("👍"),
                input: json!({
                    "kind": "unreact", "from": ALICE, "msgid": MSGID,
                    "target": "#freeq", "subject": ROOT, "emoji": "👍",
                }),
            },
            Case {
                name: "message-companion-of-a-coordination-event",
                seed: 5,
                doc: ChatDoc::message(ALICE, MSGID, "#swarm", "📋 New task: ship it").with_coord([
                    ("+freeq.at/event", "task_request"),
                    ("+freeq.at/payload", "%7B%22description%22%3A%22ship%20it%22%7D"),
                    // The event this message renders. Covered, so the tie
                    // between the two halves of one event is signed.
                    ("+freeq.at/coordid", ROOT),
                ]),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    "target": "#swarm", "bodyText": "📋 New task: ship it",
                    "tags": {
                        "+freeq.at/event": "task_request",
                        "+freeq.at/payload": "%7B%22description%22%3A%22ship%20it%22%7D",
                        "+freeq.at/coordid": ROOT,
                    },
                }),
            },
            Case {
                name: "message-with-an-attachment",
                seed: 6,
                doc: ChatDoc::message(ALICE, MSGID, "#freeq", "📎 https://cdn.example/cat.png")
                    .with_coord([
                        ("+freeq.at/media-url", "https://cdn.example/cat.png"),
                        ("+freeq.at/media-mime", "image/png"),
                        ("+freeq.at/media-alt", "a cat"),
                        ("+freeq.at/media-w", "640"),
                    ]),
                input: json!({
                    "kind": "message", "from": ALICE, "msgid": MSGID,
                    "target": "#freeq", "bodyText": "📎 https://cdn.example/cat.png",
                    "tags": {
                        "+freeq.at/media-url": "https://cdn.example/cat.png",
                        "+freeq.at/media-mime": "image/png",
                        "+freeq.at/media-alt": "a cat",
                        "+freeq.at/media-w": "640",
                    },
                }),
            },
            Case {
                name: "coordination-evidence-attach",
                seed: 5,
                doc: ChatDoc::coordination(ALICE, MSGID, "#swarm", "evidence_attach")
                    .with_payload("%7B%22type%22%3A%22code_review%22%7D")
                    .with_ref(ROOT)
                    .with_evidence("code_review"),
                input: json!({
                    "kind": "coordination", "from": ALICE, "msgid": MSGID,
                    "target": "#swarm", "eventType": "evidence_attach",
                    "payload": "%7B%22type%22%3A%22code_review%22%7D",
                    "ref": ROOT,
                    // The wire value of +freeq.at/evidence-type: what a reader
                    // renders, so what a signature has to cover.
                    "evidence": "code_review",
                }),
            },
            Case {
                name: "coordination-task-request",
                seed: 5,
                doc: ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_request")
                    .with_payload("%7B%22description%22%3A%22ship%20it%22%7D"),
                input: json!({
                    "kind": "coordination", "from": ALICE, "msgid": MSGID,
                    "target": "#swarm", "eventType": "task_request",
                    // The wire value of +freeq.at/payload, verbatim: the
                    // emitters percent-encode `;` and space, and the signature
                    // covers those bytes without decoding them.
                    "payload": "%7B%22description%22%3A%22ship%20it%22%7D",
                }),
            },
            Case {
                name: "coordination-task-complete-with-ref",
                seed: 5,
                doc: ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
                    .with_payload("%7B%22summary%22%3A%22done%22%7D")
                    .with_ref(ROOT),
                input: json!({
                    "kind": "coordination", "from": ALICE, "msgid": MSGID,
                    "target": "#swarm", "eventType": "task_complete",
                    "payload": "%7B%22summary%22%3A%22done%22%7D",
                    "ref": ROOT,
                }),
            },
        ]
    }

    /// A negative vector attacks one of the two things a verifier holds: the
    /// document (a tampered canonical, checked against the vector's real
    /// signature) or the sig tag itself (a rewritten tag, checked against the
    /// vector's real canonical). Exactly one of `tampered`/`sig` is set.
    /// `invalid` is evidence about the bytes; `unverifiable` never is.
    struct Negative {
        name: &'static str,
        of: &'static str,
        tampered: Option<ChatDoc<'static>>,
        sig: Option<SigAttack>,
        expected: &'static str,
    }

    /// The tag-level attacks. Each needs the positive vector's signature
    /// bytes, so the concrete tag is built at fixture time.
    enum SigAttack {
        /// Valid signature bytes, but the kid names a key nobody holds.
        WrongKid,
        /// An algorithm label this implementation has never heard of.
        UnknownAlgorithm,
        /// The pre-cutover format: a bare base64 blob, no algorithm, no kid.
        LegacyBareBase64,
    }

    impl SigAttack {
        fn build(&self, real_sig_tag: &str) -> String {
            use base64::Engine;
            let sig_b64 = real_sig_tag.rsplit(':').next().unwrap();
            match self {
                SigAttack::WrongKid => {
                    let foreign_kid = crate::sigtag::derive_kid(&test_key(9).verifying_key());
                    format!("ed25519:{foreign_kid}:{sig_b64}")
                }
                SigAttack::UnknownAlgorithm => {
                    let kid = real_sig_tag.split(':').nth(1).unwrap();
                    format!("ml-dsa-87:{kid}:{sig_b64}")
                }
                SigAttack::LegacyBareBase64 => {
                    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(sig_b64)
                        .unwrap();
                    base64::engine::general_purpose::STANDARD.encode(raw)
                }
            }
        }
    }

    fn doc_negative(name: &'static str, of: &'static str, tampered: ChatDoc<'static>) -> Negative {
        Negative { name, of, tampered: Some(tampered), sig: None, expected: "invalid" }
    }

    fn sig_negative(name: &'static str, of: &'static str, sig: SigAttack) -> Negative {
        Negative { name, of, tampered: None, sig: Some(sig), expected: "unverifiable" }
    }

    fn negatives() -> Vec<Negative> {
        vec![
            doc_negative(
                "altered-body",
                "message-plain",
                ChatDoc::message(ALICE, MSGID, "#freeq", "ship it tomorrow"),
            ),
            doc_negative(
                "stripped-edit",
                "message-reply-edit-and-coord",
                ChatDoc::message(ALICE, MSGID, "#swarm", "revised: use the cached index")
                    .with_reply(ROOT)
                    .with_coord([
                        ("+freeq.at/event", "task_result"),
                        ("+freeq.at/payload", "%7B%22ok%22%3Atrue%7D"),
                        ("+freeq.at/task-id", "01KYVT2AAA0000000000000000"),
                        ("+freeq.at/ref", "01KYVT2BBB0000000000000000"),
                    ]),
            ),
            // The inverse: an edit reference attached to a message that was
            // signed without one — an intermediary rewriting history *into*
            // a signed event rather than out of it.
            doc_negative(
                "injected-edit",
                "message-plain",
                ChatDoc::message(ALICE, MSGID, "#freeq", "ship it").with_edit(ROOT),
            ),
            doc_negative(
                "sanitized-coord-tag",
                "message-reply-edit-and-coord",
                ChatDoc::message(ALICE, MSGID, "#swarm", "revised: use the cached index")
                    .with_reply(ROOT)
                    .with_edit(ROOT)
                    .with_coord([
                        ("+freeq.at/event", "task_result"),
                        ("+freeq.at/payload", "%7B%22ok%22%3Afalse%7D"),
                        ("+freeq.at/task-id", "01KYVT2AAA0000000000000000"),
                        ("+freeq.at/ref", "01KYVT2BBB0000000000000000"),
                    ]),
            ),
            doc_negative(
                "re-venued-target",
                "message-plain",
                ChatDoc::message(ALICE, MSGID, "#public", "ship it"),
            ),
            doc_negative(
                "swapped-subject",
                "delete",
                ChatDoc::mutation(
                    Mutation::Delete,
                    ALICE,
                    MSGID,
                    "#freeq",
                    "01KYVT9ZZZ0000000000000000",
                ),
            ),
            doc_negative(
                "verb-swap-react-to-unreact",
                "react",
                ChatDoc::mutation(Mutation::Unreact, ALICE, MSGID, "#freeq", ROOT).with_emoji("👍"),
            ),
            // Re-pointing a companion at another event would file a rendering
            // under work it does not describe.
            doc_negative(
                "repointed-companion-coordid",
                "message-companion-of-a-coordination-event",
                ChatDoc::message(ALICE, MSGID, "#swarm", "📋 New task: ship it").with_coord([
                    ("+freeq.at/event", "task_request"),
                    ("+freeq.at/payload", "%7B%22description%22%3A%22ship%20it%22%7D"),
                    ("+freeq.at/coordid", "01KYVT9ZZZ0000000000000000"),
                ]),
            ),
            // Relabelling evidence changes what a reader is shown about work
            // that was signed for.
            doc_negative(
                "relabelled-evidence-type",
                "coordination-evidence-attach",
                ChatDoc::coordination(ALICE, MSGID, "#swarm", "evidence_attach")
                    .with_payload("%7B%22type%22%3A%22code_review%22%7D")
                    .with_ref(ROOT)
                    .with_evidence("test_run"),
            ),
            // Repointing an attachment changes what a reader is shown while
            // every other byte of the message stays as written.
            doc_negative(
                "repointed-attachment-url",
                "message-with-an-attachment",
                ChatDoc::message(ALICE, MSGID, "#freeq", "📎 https://cdn.example/cat.png")
                    .with_coord([
                        ("+freeq.at/media-url", "https://cdn.example/dog.png"),
                        ("+freeq.at/media-mime", "image/png"),
                        ("+freeq.at/media-alt", "a cat"),
                        ("+freeq.at/media-w", "640"),
                    ]),
            ),
            doc_negative(
                "altered-coordination-payload",
                "coordination-task-complete-with-ref",
                ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
                    .with_payload("%7B%22summary%22%3A%22not%20done%22%7D")
                    .with_ref(ROOT),
            ),
            // Re-pointing an update at another task keeps every other field
            // intact, and would rewrite one task's history into another's.
            doc_negative(
                "repointed-coordination-ref",
                "coordination-task-complete-with-ref",
                ChatDoc::coordination(ALICE, MSGID, "#swarm", "task_complete")
                    .with_payload("%7B%22summary%22%3A%22done%22%7D")
                    .with_ref("01KYVT9ZZZ0000000000000000"),
            ),
            sig_negative("wrong-kid", "message-plain", SigAttack::WrongKid),
            sig_negative("unknown-algorithm", "message-plain", SigAttack::UnknownAlgorithm),
            sig_negative("legacy-bare-base64", "message-plain", SigAttack::LegacyBareBase64),
        ]
    }

    fn fixtures_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/chat-signing-vectors.json")
    }

    fn hex_seed(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    fn build_fixtures_json() -> serde_json::Value {
        use crate::sigtag::derive_kid;
        use base64::Engine;

        let vectors: Vec<serde_json::Value> = cases()
            .into_iter()
            .map(|case| {
                let key = test_key(case.seed);
                serde_json::json!({
                    "name": case.name,
                    "seed": hex_seed(case.seed),
                    "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(key.verifying_key().as_bytes()),
                    "kid": derive_kid(&key.verifying_key()),
                    "input": case.input,
                    "canonical": case.doc.canonical(),
                    "sigTag": case.doc.sign(&key),
                })
            })
            .collect();

        let negatives: Vec<serde_json::Value> = negatives()
            .into_iter()
            .map(|n| {
                let mut entry = serde_json::json!({
                    "name": n.name,
                    "vector": n.of,
                    "expected": n.expected,
                });
                if let Some(tampered) = &n.tampered {
                    entry["tamperedCanonical"] = tampered.canonical().into();
                }
                if let Some(attack) = &n.sig {
                    let case = cases().into_iter().find(|c| c.name == n.of).unwrap();
                    let real = case.doc.sign(&test_key(case.seed));
                    entry["sigTag"] = attack.build(&real).into();
                }
                entry
            })
            .collect();

        serde_json::json!({
            "description": "Worked signing examples for freeq chat events (messages, deletes, reactions). Every implementation must reproduce `canonical` and `sigTag` byte-for-byte from `input` + `seed`, and must reach `expected` for each negative: check the negative's `sigTag` when present (a tag-level attack, against the named vector's canonical), otherwise the vector's own sigTag against `tamperedCanonical` (a document-level attack).",
            "documentRule": "JCS (RFC 8785) over an enumerated per-kind document. Mandatory: from, msgid, target. A message carries no `kind` (its absence is the kind) and covers body/reply?/edit?/coord?; a mutation carries kind and subject, plus emoji for react|unreact; a coordination event carries kind \"coordination\", event, payload, ref? and evidence?. Optional fields are omitted entirely when absent.",
            "bodyRule": "body = \"sha256:\" + lowercase hex of SHA-256 over the UTF-8 wire body — ciphertext under E2EE, and the assembled body (real newlines) for a draft/multiline batch.",
            "payloadRule": "payload = \"sha256:\" + lowercase hex of SHA-256 over the UTF-8 wire value of +freeq.at/payload, IRC-unescaped and otherwise verbatim — any app-level encoding inside it is opaque bytes to the signature.",
            "venueRule": "target is the normalized venue, never the wire target: a channel lowercased, or `dm:<did_a>,<did_b>` with the two DIDs sorted ascending.",
            "coordRule": "coord covers exactly the client-authored coordination and attachment tags coordid, event, evidence-type, link-desc, link-image, link-title, link-url, media-alt, media-blurhash, media-duration, media-filename, media-h, media-mime, media-size, media-url, media-w, payload, ref, task-id (canonical keys; wire names carry a +freeq.at/ prefix), IRC-unescaped, verbatim. coordid is how the companion message of a coordination event names that event; the event's own TAGMSG carries its id in +freeq.at/eventid instead. Every other tag — server stamps, tallies, verdicts, provenance, ephemera, framing — is excluded.",
            "referenceRule": "edit, reply and subject always name root msgids. A signed event naming a revision is refused, never rewritten.",
            "kidRule": "base64url-nopad(sha256(raw 32-byte ed25519 public key)[0..16])",
            "sigTagFormat": "ed25519:<kid>:<base64url-nopad signature over the UTF-8 canonical bytes>",
            "verdictRule": "Only a signature that fails against the key its kid names is `invalid`. An unknown algorithm, a kid we cannot resolve, or a malformed tag is `unverifiable` — never reported as forgery.",
            "vectors": vectors,
            "negatives": negatives,
        })
    }

    /// Regenerate spec/chat-signing-vectors.json. Run manually:
    /// `cargo test -p freeq-sdk generate_chat_signing_vectors -- --ignored`
    #[test]
    #[ignore]
    fn generate_chat_signing_vectors() {
        let json = serde_json::to_string_pretty(&build_fixtures_json()).unwrap();
        std::fs::create_dir_all(fixtures_path().parent().unwrap()).unwrap();
        std::fs::write(fixtures_path(), json + "\n").unwrap();
    }

    /// The committed fixture file must be exactly what this implementation
    /// produces — the cross-language byte-compatibility contract.
    #[test]
    fn committed_chat_signing_vectors_are_reproducible() {
        let on_disk = std::fs::read_to_string(fixtures_path())
            .expect("spec/chat-signing-vectors.json missing — run generate_chat_signing_vectors");
        let on_disk: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(on_disk, build_fixtures_json());
    }

    /// Every positive vector verifies, and every negative reaches its stated
    /// verdict — so the fixture file can't drift from the semantics.
    #[test]
    fn every_vector_verifies_and_every_negative_reaches_its_verdict() {
        for case in cases() {
            let key = test_key(case.seed);
            let sig = case.doc.sign(&key);
            case.doc
                .verify(&sig, &key.verifying_key())
                .unwrap_or_else(|e| panic!("vector {} failed to verify: {e}", case.name));
        }
        for n in negatives() {
            let case = cases()
                .into_iter()
                .find(|c| c.name == n.of)
                .unwrap_or_else(|| panic!("negative {} names unknown vector {}", n.name, n.of));
            let key = test_key(case.seed);
            let real_sig = case.doc.sign(&key);
            // A doc attack checks the real signature against the tampered
            // document; a tag attack checks the rewritten tag against the
            // real document.
            let (doc, sig) = match (&n.tampered, &n.sig) {
                (Some(tampered), None) => (tampered, real_sig),
                (None, Some(attack)) => (&case.doc, attack.build(&real_sig)),
                _ => panic!("negative {} must set exactly one of tampered/sig", n.name),
            };
            let err = doc
                .verify(&sig, &key.verifying_key())
                .expect_err("a negative must not verify");
            let got = if err.is_unverifiable() {
                "unverifiable"
            } else {
                "invalid"
            };
            assert_eq!(got, n.expected, "negative {}", n.name);
        }
    }
}
