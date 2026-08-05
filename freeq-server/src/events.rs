//! The append-only event log — what happened, in the bytes it happened in.
//!
//! One table, `events`, holding every chat event this server accepted:
//! messages, edits, deletes, reactions, unreactions, pins, and coordination
//! events. `messages`, `reactions` and `pins` are derived from it — they are
//! the shape queries want, the log is the shape evidence wants.
//!
//! ## What a row stores, and why
//!
//! The row **is** the signed document: `canonical` holds the exact JCS bytes
//! the signature covers, verbatim, in a plain TEXT column that no encoder ever
//! rewrites. Re-verifying a five-year-old event then needs no rebuild logic at
//! all, and no future change to the canonical can invalidate stored history —
//! which is not hypothetical, the canonical has already been replaced once
//! (see [`freeq_sdk::chatsig`]).
//!
//! Everything queryable is *derived from those bytes*: [`EventFacts`] is what
//! [`derive_facts`] reads back out, and a row whose columns disagree with its
//! own canonical is a bug the audit in `Db::events_disagreeing_with_their_bytes`
//! is there to catch.
//!
//! Three things are **not** derivable and are the caller's to state, because no
//! chat document contains them: when the event arrived (a document carries no
//! wall clock, deliberately — that was the flaw in the retired canonical),
//! which peer relayed it, and what verdict this server reached about the
//! signature. Those travel in [`EventContext`].
//!
//! ## Hash-only
//!
//! No body ever enters this table. A message document carries `body` as
//! `sha256:<hex>` and never the text, so storing the canonical stores the hash
//! and nothing more; the text stays in `messages`, where deleting it deletes
//! it. An audit log that quietly accumulated a second copy of every private
//! message would be a liability, not a feature.
//!
//! ## Rows with no canonical
//!
//! A guest has no identity to bind, so there is no document to sign and none
//! to store: `canonical` is empty, `sig_state` is [`SigState::Unsigned`], and
//! the [`EventFacts`] the caller supplies are the only record. The same holds
//! for events outside the signing model (pins today). The table is honest
//! about this rather than synthesising bytes nobody signed.

use serde::{Deserialize, Serialize};

/// What this server concluded about an event's signature, at the moment it
/// accepted the event.
///
/// Recorded rather than recomputed because it cannot be recomputed later: keys
/// rotate, peers vanish, and the question "could we check this *then*" has one
/// true answer that only the past holds.
///
/// There is deliberately no `Invalid`. A signature that fails against the key
/// it names is refused at ingress and the event is never filed, so no row can
/// exist in that state — see the schema comment in migration 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SigState {
    /// A signature is on file and this server checked it against the key its
    /// kid names. Whose key that was — the sender's device or this server
    /// vouching — is in the signature itself, not here.
    Valid,
    /// A signature is on file that this server could not check: a key it does
    /// not hold, an algorithm it does not know, a retired format. Honest, and
    /// never evidence of forgery.
    ///
    /// The default, on purpose. A caller that says nothing gets the answer
    /// that claims least; only a caller that actually verified may say
    /// [`SigState::Valid`].
    #[default]
    Unverifiable,
    /// Nothing signed this event.
    Unsigned,
}

impl SigState {
    pub fn as_str(self) -> &'static str {
        match self {
            SigState::Valid => "valid",
            SigState::Unverifiable => "unverifiable",
            SigState::Unsigned => "unsigned",
        }
    }

    pub fn from_str(s: &str) -> SigState {
        match s {
            "valid" => SigState::Valid,
            "unsigned" => SigState::Unsigned,
            _ => SigState::Unverifiable,
        }
    }
}

/// The facts about an event that a signed document contains — the whole
/// queryable surface of a row.
///
/// Read back out of the canonical by [`derive_facts`] whenever there is one,
/// so the columns can never say something the bytes don't. Supplied directly
/// only for events nothing signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFacts {
    /// The event's own id — the signer's, where there was a signer.
    pub event_id: String,
    /// `message` | `edit` | `delete` | `react` | `unreact` | `pin` | `unpin`
    /// | `coord`.
    pub kind: String,
    /// The normalized venue: a folded channel name, or `dm:<a>,<b>`.
    pub venue: String,
    /// The acting identity. `None` for a guest.
    pub actor_did: Option<String>,
    /// The root msgid this event acts on — a mutation's subject, an edit's
    /// original. `None` for a message that acts on nothing.
    pub subject: Option<String>,
    /// `sha256:<hex>` over the wire body, for the kinds that have one.
    pub body_hash: Option<String>,
    /// A reaction's emoji. A column of its own because it is a closed part of
    /// the document schema — and because an unsigned reaction has no canonical
    /// to hold it, which would otherwise make `reactions` unrebuildable for
    /// anyone who reacted without an account.
    pub emoji: Option<String>,
}

/// Facts about *receipt*, which no document contains.
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    /// The verdict this server reached. Left at the default —
    /// [`SigState::Unverifiable`] — by any caller that did not itself check,
    /// so a row never over-claims by omission.
    pub sig_state: SigState,
    /// The peer that relayed this event; `None` for local ingress.
    pub origin: Option<String>,
}

impl EventContext {
    /// The context for an event this server verified itself.
    pub fn verified() -> Self {
        EventContext {
            sig_state: SigState::Valid,
            ..Default::default()
        }
    }
}

/// Read the facts back out of a canonical document.
///
/// `None` when the bytes are not a chat document at all — an empty canonical,
/// or anything that does not parse as a JSON object with the mandatory fields.
/// A caller holding such bytes has nothing to derive and must state the facts
/// itself.
///
/// The kind is read the way the document defines it: a mutation names its
/// `kind` outright, and a message carries none — so the *absence* is the
/// message kind, refined to `edit` when the document names the message it
/// revises.
pub fn derive_facts(canonical: &str) -> Option<EventFacts> {
    if canonical.is_empty() {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_str(canonical).ok()?;
    let get = |k: &str| doc.get(k).and_then(|v| v.as_str()).map(str::to_string);

    let event_id = get("msgid")?;
    let venue = get("target")?;
    let actor_did = get("from")?;
    let body_hash = get("body");
    let edit = get("edit");
    let kind = match get("kind") {
        Some(k) => k,
        None if edit.is_some() => "edit".to_string(),
        None => "message".to_string(),
    };
    // A mutation acts on its `subject`; an edit acts on the message it
    // revises. Both name a root msgid, which is the identity a message keeps
    // for life — so one column serves both.
    let subject = get("subject").or(edit);

    Some(EventFacts {
        event_id,
        kind,
        venue,
        actor_did: Some(actor_did),
        subject,
        body_hash,
        emoji: get("emoji"),
    })
}

/// The venue a stored row belongs to: a channel key folded, anything else
/// (a `dm:<a>,<b>` conversation key) already being a venue.
///
/// Folded here rather than trusted to be folded already — a local row is filed
/// under a normalized channel, but a row that arrived over S2S keeps the
/// spelling the origin's user typed, and a signer signed the folded form.
pub fn venue_of(channel: &str) -> String {
    if channel.starts_with('#') || channel.starts_with('&') {
        freeq_sdk::chatsig::channel_venue(channel)
    } else {
        channel.to_string()
    }
}

/// Rebuild the document a stored message's signature covers, from the columns
/// the row already holds.
///
/// The one place this rebuild lives. It ran in three before — the log, the
/// verify endpoint, and ingress — and three copies of a byte-exact
/// reconstruction is three chances for one of them to drift and start calling
/// honest messages forged.
///
/// `replaces_msgid` is the column; `+draft/edit` is the tag. A local edit
/// files the tag, one that arrived over S2S carries the linkage only in the
/// column (the relayed tag map is filtered to `+freeq.at/*`), so both are
/// consulted and either answer serves.
pub fn message_canonical(
    sender_did: &str,
    msgid: &str,
    channel: &str,
    body: &str,
    tags: &std::collections::HashMap<String, String>,
    replaces_msgid: Option<&str>,
) -> String {
    let venue = venue_of(channel);
    let mut doc = freeq_sdk::chatsig::ChatDoc::message(sender_did, msgid, &venue, body);
    if let Some(reply) = tags.get("+reply").or_else(|| tags.get("+draft/reply")) {
        doc = doc.with_reply(reply);
    }
    let edit = tags.get("+draft/edit").map(String::as_str).or(replaces_msgid);
    if let Some(edit) = edit {
        doc = doc.with_edit(edit);
    }
    doc.with_coord(tags.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .canonical()
}

/// Rebuild the document a mutation's signature covers.
pub fn mutation_canonical(
    kind: freeq_sdk::chatsig::Mutation,
    actor_did: &str,
    event_id: &str,
    channel: &str,
    subject: &str,
    emoji: Option<&str>,
) -> String {
    let venue = venue_of(channel);
    let mut doc =
        freeq_sdk::chatsig::ChatDoc::mutation(kind, actor_did, event_id, &venue, subject);
    if let Some(emoji) = emoji {
        doc = doc.with_emoji(emoji);
    }
    doc.canonical()
}

/// A fingerprint of bytes, for the `conflict` column: `sha256:<lowercase hex>`.
///
/// Recorded when a second, differing claim on an id is dropped, so the fact
/// that two signed claims existed survives the drop. Local only — a receipt
/// this server writes for itself, never something that crosses the wire.
pub fn fingerprint(bytes: &str) -> String {
    freeq_sdk::chatsig::body_hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeq_sdk::chatsig::{ChatDoc, Mutation};

    const ALICE: &str = "did:plc:eventalice";
    const MSGID: &str = "01KYVT5Z8Q0000000000000000";
    const ROOT: &str = "01KYVT1W2P0000000000000000";

    #[test]
    fn a_plain_message_derives_its_own_columns() {
        let canonical = ChatDoc::message(ALICE, MSGID, "#room", "hello").canonical();
        let facts = derive_facts(&canonical).expect("a message is a document");
        assert_eq!(facts.event_id, MSGID);
        assert_eq!(facts.kind, "message");
        assert_eq!(facts.venue, "#room");
        assert_eq!(facts.actor_did.as_deref(), Some(ALICE));
        assert_eq!(facts.subject, None, "a message acts on nothing");
        assert_eq!(
            facts.body_hash.as_deref(),
            Some(freeq_sdk::chatsig::body_hash("hello").as_str()),
            "the hash is the document's, not recomputed from a body we kept"
        );
    }

    /// A message carries no `kind` — its absence is the kind — and an edit is
    /// a message that names what it revises.
    #[test]
    fn an_edit_is_a_message_that_names_what_it_revises() {
        let canonical = ChatDoc::message(ALICE, MSGID, "#room", "revised")
            .with_edit(ROOT)
            .canonical();
        let facts = derive_facts(&canonical).unwrap();
        assert_eq!(facts.kind, "edit");
        assert_eq!(facts.subject.as_deref(), Some(ROOT));
    }

    /// A reply is not a subject: replying to a message does not act on it.
    #[test]
    fn a_reply_is_not_something_the_event_acts_on() {
        let canonical = ChatDoc::message(ALICE, MSGID, "#room", "answering")
            .with_reply(ROOT)
            .canonical();
        let facts = derive_facts(&canonical).unwrap();
        assert_eq!(facts.kind, "message");
        assert_eq!(facts.subject, None);
    }

    #[test]
    fn every_mutation_kind_derives_its_kind_and_subject() {
        for (mutation, expected) in [
            (Mutation::Delete, "delete"),
            (Mutation::React, "react"),
            (Mutation::Unreact, "unreact"),
        ] {
            let canonical = ChatDoc::mutation(mutation, ALICE, MSGID, "#room", ROOT)
                .with_emoji("👍")
                .canonical();
            let facts = derive_facts(&canonical).unwrap();
            assert_eq!(facts.kind, expected);
            assert_eq!(facts.subject.as_deref(), Some(ROOT));
            assert_eq!(facts.body_hash, None, "a mutation carries no body");
        }
    }

    #[test]
    fn a_dm_venue_survives_the_round_trip_intact() {
        let venue = freeq_sdk::chatsig::dm_venue(ALICE, "did:plc:bob");
        let canonical = ChatDoc::message(ALICE, MSGID, &venue, "between us").canonical();
        assert_eq!(derive_facts(&canonical).unwrap().venue, venue);
    }

    #[test]
    fn bytes_that_are_not_a_document_derive_nothing() {
        assert_eq!(derive_facts(""), None, "a guest's event has no document");
        assert_eq!(derive_facts("not json"), None);
        assert_eq!(
            derive_facts(r#"{"from":"did:plc:x"}"#),
            None,
            "a document missing a mandatory field is not one"
        );
    }

    #[test]
    fn the_default_verdict_claims_the_least() {
        assert_eq!(EventContext::default().sig_state, SigState::Unverifiable);
        assert_eq!(EventContext::verified().sig_state, SigState::Valid);
        // Round-trips through the column, and an unknown value reads as the
        // claim-least state rather than panicking on data from a newer build.
        for state in [SigState::Valid, SigState::Unverifiable, SigState::Unsigned] {
            assert_eq!(SigState::from_str(state.as_str()), state);
        }
        assert_eq!(SigState::from_str("invalid"), SigState::Unverifiable);
    }
}
