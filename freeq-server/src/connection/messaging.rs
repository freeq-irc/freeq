#![allow(clippy::too_many_arguments)]
//! Message handling: PRIVMSG, NOTICE, TAGMSG, CHATHISTORY.

use super::Connection;
use super::helpers::{normalize_channel, s2s_broadcast, s2s_next_event_id};
use crate::irc::{self, Message};
use crate::server::SharedState;
use std::collections::HashMap;
use std::sync::Arc;

/// Prune every N inserts per channel rather than on every message — see the
/// prune call site. Process-static (like `S2S_RATE_LIMITS`), keyed by channel.
static PRUNE_COUNTERS: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, u32>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
const PRUNE_INTERVAL: u32 = 256;

/// The event id a message is filed under: the one the **client** minted if it
/// sent one and it holds up, otherwise one this server mints.
///
/// A signed event signs its own id, and a client cannot sign an id the server
/// invents after the fact — which is why `+freeq.at/eventid` exists. Adopting
/// it is what makes the signed value and the filed value the same value, all
/// the way down to the reactions and edits that reference it.
///
/// Adoption is guarded, because an id is an identity:
///
/// - **Authenticated senders only.** A guest has no durable identity to sign
///   with, so a guest-minted id buys nothing and costs a spoofing surface.
/// - **Well-formed, and near our clock** ([`crate::msgid::check_client_minted`]).
/// - **Not already taken** — `messages.msgid` carries no UNIQUE constraint, so
///   without this check a client could mint the id of an existing message and
///   every lookup that resolves an id (an edit, a delete, a pin, a reaction)
///   could land on the wrong row.
///
/// On refusal the message is **not** filed under a substitute id: the sender
/// believes it sent a signed event, and filing that event under an id its
/// signature doesn't cover would produce history that looks tampered with. The
/// caller reports `FAIL` and drops the message instead.
fn resolve_event_msgid(
    conn: &Connection,
    tags: &HashMap<String, String>,
    state: &Arc<SharedState>,
) -> Result<String, (&'static str, String)> {
    let Some(claimed) = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
    else {
        return Ok(crate::msgid::generate());
    };

    if conn.authenticated_did.is_none() {
        return Err((
            "EVENTID_NOT_AUTHENTICATED",
            "Only an authenticated identity may mint its own event ids".to_string(),
        ));
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if let Err(rejection) = crate::msgid::check_client_minted(claimed, now_ms) {
        return Err((rejection.code(), rejection.description().to_string()));
    }

    // `with_db` returns None when no database is attached, which is not
    // evidence that the id is free — but with no durable store there is
    // nothing for a duplicate to corrupt either, so treat it as available.
    let taken = state.with_db(|db| db.msgid_taken(claimed)).unwrap_or(false);
    if taken {
        return Err((
            "EVENTID_IN_USE",
            "That event id is already on file".to_string(),
        ));
    }

    Ok(claimed.to_string())
}

/// Put the resolved signature on the outgoing tags — or make sure no
/// signature rides along at all.
///
/// The removal is the point. The client's own `+freeq.at/sig` is in the tag
/// map we're about to relay, so a signature that failed verification (or a
/// guest's invented one) would travel untouched and every client would draw a
/// lock beside it. A signature the server did not stand behind must not leave
/// the server.
fn set_signature(tags: &mut HashMap<String, String>, resolved: Option<String>) {
    tags.remove("+freeq.at/sig");
    tags.remove("freeq.at/sig");
    if let Some(sig) = resolved {
        tags.insert("+freeq.at/sig".to_string(), sig);
    }
}

/// The root msgid a message replies to, from either spelling of the reply tag.
fn reply_reference(tags: &HashMap<String, String>) -> Option<&str> {
    tags.get("+reply")
        .or_else(|| tags.get("+draft/reply"))
        .map(|s| s.as_str())
}

/// Drop `+freeq.at/eventid` from the tags that go out on the wire.
///
/// Once adopted, the id *is* the `msgid` tag, and a verifier rebuilds the
/// signed document from that. Relaying both would create two tags that must
/// agree forever and no rule for which one wins when they don't — exactly the
/// ambiguity signing is supposed to remove.
fn strip_event_id_tag(tags: &mut HashMap<String, String>) {
    tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
    tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG_BARE);
}

/// Tell the sender its event id was refused, naming the id so a client with
/// several in flight knows which one.
fn send_eventid_fail(
    conn: &Connection,
    command: &str,
    code: &str,
    description: &str,
    state: &Arc<SharedState>,
) {
    let reply = Message::from_server(&state.server_name, "FAIL", vec![command, code, description]);
    if let Some(tx) = state.connections.lock().get(&conn.id) {
        let _ = tx.try_send(format!("{reply}\r\n"));
    }
}

/// The fields of a message that its signature covers, beyond the sender and
/// the venue (which the resolver works out for itself).
pub(crate) struct SignedFields<'a> {
    /// The wire body — ciphertext on an encrypted channel, the assembled body
    /// for a multiline batch. Hashed, never inlined.
    pub body: &'a str,
    /// The event's own id, as adopted by `resolve_event_msgid`.
    pub msgid: &'a str,
    /// Root msgid this message replies to, if any.
    pub reply: Option<&'a str>,
    /// Root msgid this message revises, if any.
    pub edit: Option<&'a str>,
    /// True when a plugin rewrote the body after the client signed it. The
    /// signature then cannot match, and the cause is this server, not the
    /// sender — so it must read *unverifiable*, never invalid.
    pub body_rewritten: bool,
}

/// The venue a signed document binds, or `None` when this server cannot work
/// it out (an unresolvable DM recipient), which makes the message's signature
/// unverifiable rather than wrong.
///
/// Never the wire target: a channel is folded (the server folds it too, so a
/// client signing `#Ops` as typed would fail at its own origin), and a DM
/// binds the sorted DID pair, because a DM's wire target is a nick or a `did:`
/// and history is replayed under whichever the *reader* asked for.
pub(crate) fn signing_venue(
    state: &Arc<SharedState>,
    sender_did: &str,
    target: &str,
) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return Some(freeq_sdk::chatsig::channel_venue(target));
    }
    let recipient = super::routing::recipient_did_for_target(state, target)?;
    Some(freeq_sdk::chatsig::dm_venue(sender_did, &recipient))
}

/// Build the document a chat message's signature covers.
fn message_document<'a>(
    did: &'a str,
    venue: &'a str,
    fields: &SignedFields<'a>,
    tags: &'a HashMap<String, String>,
) -> freeq_sdk::chatsig::ChatDoc<'a> {
    let mut doc = freeq_sdk::chatsig::ChatDoc::message(did, fields.msgid, venue, fields.body);
    // References always name root msgids — the only ids a client is ever told,
    // since a message keeps its identity through every revision.
    if let Some(reply) = fields.reply {
        doc = doc.with_reply(reply);
    }
    if let Some(edit) = fields.edit {
        doc = doc.with_edit(edit);
    }
    doc.with_coord(tags.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

/// Verify the sender's own signature, or sign on its behalf.
///
/// Returns the value for the outgoing `+freeq.at/sig` tag:
///
/// - **The client's signature**, when it verifies against the key its `kid`
///   names — the only case that carries real non-repudiation, because the
///   server never held the private key.
/// - **A server signature** over the same document, when the client didn't
///   sign or when its signature was *unverifiable* (no key on file for that
///   kid, an algorithm we don't know, a legacy-format signature, or a body
///   this server's plugins rewrote). Attaching ours says only what it means:
///   this server vouches that this identity sent this.
/// - **Nothing**, for a guest — and for a signature that *failed* against the
///   key it named. That is the one case we refuse to paper over: quietly
///   replacing a failed signature with the server's own would turn a signature
///   that didn't check into a badge that says it did.
fn resolve_signature(
    conn: &Connection,
    target: &str,
    fields: &SignedFields<'_>,
    tags: &HashMap<String, String>,
    client_sig: Option<&str>,
    state: &Arc<SharedState>,
) -> Option<String> {
    let did = conn.authenticated_did.as_ref()?;
    let venue = signing_venue(state, did, target);

    if let (Some(sig_tag), Some(venue)) = (client_sig, venue.as_deref())
        && !fields.body_rewritten
    {
        let doc = message_document(did, venue, fields, tags);
        match verify_client_signature(&doc, sig_tag, did, Some(&conn.id), state) {
            ClientSigOutcome::Verified => return Some(sig_tag.to_string()),
            ClientSigOutcome::Failed => {
                tracing::warn!(
                    session = %conn.id, did = %did, msgid = %fields.msgid,
                    "Client signature did not verify against the key it names — \
                     relaying the message unsigned rather than substituting ours"
                );
                return None;
            }
            ClientSigOutcome::Unverifiable(why) => {
                tracing::debug!(
                    session = %conn.id, did = %did, msgid = %fields.msgid, why = %why,
                    "Client signature not verifiable here — server-signing instead"
                );
            }
        }
    } else if client_sig.is_some() {
        tracing::debug!(
            session = %conn.id, did = %did, msgid = %fields.msgid,
            rewritten = fields.body_rewritten,
            "Client signature not verifiable here (no venue, or body rewritten \
             after signing) — server-signing instead"
        );
    }

    // Server signature over the same document. Without a venue there is no
    // document to sign, and inventing one would produce a signature nobody
    // could rebuild — the exact failure this canonical exists to end.
    let venue = venue?;
    let doc = message_document(did, &venue, fields, tags);
    Some(doc.sign(&state.msg_signing_key))
}

/// What happened when we checked a client's signature — three outcomes, not
/// two, because "cannot check" and "does not check out" are different facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientSigOutcome {
    Verified,
    /// The named key was found and the signature is wrong: tampering, forgery,
    /// or a client whose canonical disagrees with ours.
    Failed,
    /// We cannot reach a verdict, and must not pretend to. Carries the reason
    /// for the log.
    Unverifiable(&'static str),
}

/// The one reason a signature is uncheckable that a key lookup can fix — the
/// signer is real and named a key, we just do not hold it. See
/// [`crate::peer_keys`].
pub(crate) const NO_KEY_ON_FILE: &str = "no key on file for that kid";

/// Verify `sig_tag` over `doc`, using the key its `kid` names.
///
/// `session` is the local session that registered the key, when there is one.
/// A relayed event has no session here — its signer authenticated to another
/// server — so it passes `None` and the key can only come from the durable
/// per-(DID, kid) store.
fn verify_client_signature(
    doc: &freeq_sdk::chatsig::ChatDoc<'_>,
    sig_tag: &str,
    did: &str,
    session: Option<&str>,
    state: &Arc<SharedState>,
) -> ClientSigOutcome {
    // A legacy signature is a bare base64 blob over the retired canonical,
    // which folded a client-minted wall clock this server cannot reproduce.
    // It was never checkable; it is not evidence of anything.
    let Ok((kid, _)) = freeq_sdk::sigtag::parse(sig_tag) else {
        return ClientSigOutcome::Unverifiable("unparseable or legacy signature format");
    };

    // The session's registered key first (the common case: sign, then send),
    // then the durable per-(DID, kid) history, which is what keeps a signature
    // checkable after the session that made it has ended.
    let session_key = session
        .and_then(|s| state.session_msg_keys.lock().get(s).copied())
        .filter(|vk| freeq_sdk::sigtag::derive_kid(vk) == kid);
    let key = match session_key {
        Some(vk) => vk,
        None => match state
            .with_db(|db| db.get_signing_key_by_kid(did, kid))
            .flatten()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        {
            Some(vk) => vk,
            None => return ClientSigOutcome::Unverifiable(NO_KEY_ON_FILE),
        },
    };

    match doc.verify(sig_tag, &key) {
        Ok(()) => ClientSigOutcome::Verified,
        Err(e) if e.is_unverifiable() => ClientSigOutcome::Unverifiable("unusable signature tag"),
        Err(_) => ClientSigOutcome::Failed,
    }
}

/// Check a message signature that arrived from a peer, against the message
/// exactly as it arrived.
///
/// The same document and the same key rules as local ingress — the only
/// differences are that there is no session to consult (the signer
/// authenticated to another server, so the key comes from the durable store
/// that [`crate::peer_keys`] fills on miss) and that the caller must hand over
/// untidied values: an adopted msgid, a body as transmitted, an edit reference
/// before it was re-rooted, coordination tags before they were filtered.
///
/// A signer signs its own event id, so a relayed message carrying no msgid has
/// no document to rebuild — unverifiable, never wrong.
pub(crate) fn verify_relayed_message(
    state: &Arc<SharedState>,
    sender_did: &str,
    target: &str,
    fields: &SignedFields<'_>,
    coord_tags: &HashMap<String, String>,
    sig_tag: &str,
) -> ClientSigOutcome {
    if fields.msgid.is_empty() {
        return ClientSigOutcome::Unverifiable("relayed message carries no event id");
    }
    let Some(venue) = signing_venue(state, sender_did, target) else {
        return ClientSigOutcome::Unverifiable("venue for the relayed target does not resolve");
    };
    let doc = message_document(sender_did, &venue, fields, coord_tags);
    verify_client_signature(&doc, sig_tag, sender_did, None, state)
}

/// Check a mutation signature (delete / react / unreact) that arrived from a
/// peer, against the event exactly as it arrived.
///
/// `event_msgid` is the mutation's own signer-minted id and `subject` the
/// message it acts on, both as transmitted — the subject before it was
/// resolved to a local root, since the signer signed the id it was given.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_relayed_mutation(
    state: &Arc<SharedState>,
    sender_did: &str,
    target: &str,
    kind: freeq_sdk::chatsig::Mutation,
    event_msgid: &str,
    subject: &str,
    emoji: Option<&str>,
    sig_tag: &str,
) -> ClientSigOutcome {
    verify_mutation(
        state,
        sender_did,
        target,
        kind,
        event_msgid,
        subject,
        emoji,
        sig_tag,
        None,
    )
}

/// Check the signature on a mutation a client is sending *here*.
///
/// The same document and the same rules as a relayed one, with one
/// difference: this signer authenticated to this server, so its session's
/// registered key is consulted first. The common order is register-then-send,
/// and the durable store is not the fast path for a key minted seconds ago.
///
/// The document binds the sender's DID, so a signature made under someone
/// else's identity rebuilds a different document and fails — which is the
/// point, and why the caller passes the connection's own DID rather than
/// anything the client asserted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_local_mutation(
    state: &Arc<SharedState>,
    conn: &Connection,
    target: &str,
    kind: freeq_sdk::chatsig::Mutation,
    event_msgid: &str,
    subject: &str,
    emoji: Option<&str>,
    sig_tag: &str,
) -> ClientSigOutcome {
    let Some(did) = conn.authenticated_did.as_deref() else {
        // A guest has no identity to bind, so there is no document — and
        // nothing for a signature to be evidence of.
        return ClientSigOutcome::Unverifiable("a guest cannot sign");
    };
    verify_mutation(
        state,
        did,
        target,
        kind,
        event_msgid,
        subject,
        emoji,
        sig_tag,
        Some(&conn.id),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_mutation(
    state: &Arc<SharedState>,
    sender_did: &str,
    target: &str,
    kind: freeq_sdk::chatsig::Mutation,
    event_msgid: &str,
    subject: &str,
    emoji: Option<&str>,
    sig_tag: &str,
    session: Option<&str>,
) -> ClientSigOutcome {
    if event_msgid.is_empty() {
        return ClientSigOutcome::Unverifiable("mutation carries no event id");
    }
    let Some(venue) = signing_venue(state, sender_did, target) else {
        return ClientSigOutcome::Unverifiable("venue for the target does not resolve");
    };
    let mut doc =
        freeq_sdk::chatsig::ChatDoc::mutation(kind, sender_did, event_msgid, &venue, subject);
    if let Some(emoji) = emoji {
        doc = doc.with_emoji(emoji);
    }
    verify_client_signature(&doc, sig_tag, sender_did, session, state)
}

/// Verify a commit-reveal binding declared on a PRIVMSG carrying
/// `+freeq.at/event=reveal`.
///
/// The convention (see `docs/agents.md` § Commit-Reveal):
///
/// ```text
/// Commit PRIVMSG: +freeq.at/event=commit
///                 +freeq.at/payload={"hash":"<b64url>","alg":"sha256"}
///                 (body: human-readable placeholder)
///
/// Reveal PRIVMSG: +freeq.at/event=reveal
///                 +freeq.at/payload={"reveal_of":"<commit_msgid>","salt":"<b64url>"}
///                 (body: the plaintext being revealed)
/// ```
///
/// Verification recomputes `sha256(salt || body_bytes)` and compares to
/// the commit's stored hash. Same actor, same channel, and same
/// `+freeq.at/ref` are also required. Returns `Ok(())` on a clean
/// match, or `Err(reason)` with one of:
/// `bad_payload | commit_not_found | actor_mismatch | channel_mismatch |
/// not_a_commit | ref_id_mismatch | bad_commit_payload | unsupported_alg |
/// bad_salt | bad_commit_hash | hash_mismatch`.
///
/// Mirrors the verify-and-stamp pattern used by `+freeq.at/sig` above:
/// callers turn `Ok`/`Err` into `+freeq.at/commit-verified=true|false`
/// and (on error) `+freeq.at/commit-mismatch=<reason>` tags on the
/// outgoing relay. Verify-and-annotate, never reject.
pub(crate) fn verify_commit_reveal(
    state: &Arc<SharedState>,
    reveal_actor_did: Option<&str>,
    reveal_channel: &str,
    reveal_ref_id: Option<&str>,
    reveal_payload_json: &str,
    reveal_body: &str,
) -> Result<(), &'static str> {
    // Parse reveal payload: { reveal_of, salt }
    let payload: serde_json::Value =
        serde_json::from_str(reveal_payload_json).map_err(|_| "bad_payload")?;
    let reveal_of = payload
        .get("reveal_of")
        .and_then(|v| v.as_str())
        .ok_or("bad_payload")?;
    let salt_b64 = payload
        .get("salt")
        .and_then(|v| v.as_str())
        .ok_or("bad_payload")?;

    // Look up the prior commit message by msgid.
    // `with_db` already unwraps the inner SqlResult, so we get
    // Option<Option<MessageRow>>: outer None = no DB attached or
    // query errored; inner None = no row with that msgid.
    let commit = state
        .with_db(|db| db.find_message_by_msgid(reveal_of))
        .flatten()
        .ok_or("commit_not_found")?;

    // Actor must match (the same DID that committed must reveal).
    if commit.sender_did.as_deref() != reveal_actor_did {
        return Err("actor_mismatch");
    }
    // Channel must match.
    if commit.channel != reveal_channel {
        return Err("channel_mismatch");
    }
    // Must actually be a commit event.
    if commit.tags.get("+freeq.at/event").map(String::as_str) != Some("commit") {
        return Err("not_a_commit");
    }
    // Ref-id must agree (either both absent, or both present and equal).
    let commit_ref = commit
        .tags
        .get("+freeq.at/ref")
        .or_else(|| commit.tags.get("+freeq.at/task-id"))
        .map(String::as_str);
    if commit_ref != reveal_ref_id {
        return Err("ref_id_mismatch");
    }
    // Parse commit payload: { hash, alg }
    let commit_payload_raw = commit
        .tags
        .get("+freeq.at/payload")
        .ok_or("bad_commit_payload")?;
    let commit_payload_decoded: String = urlencoding::decode(commit_payload_raw)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| commit_payload_raw.clone());
    let commit_payload: serde_json::Value =
        serde_json::from_str(&commit_payload_decoded).map_err(|_| "bad_commit_payload")?;
    let expected_hash_b64 = commit_payload
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or("bad_commit_payload")?;
    let alg = commit_payload
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("sha256");
    if alg != "sha256" {
        return Err("unsupported_alg");
    }

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let salt = b64.decode(salt_b64).map_err(|_| "bad_salt")?;
    let expected_hash = b64
        .decode(expected_hash_b64)
        .map_err(|_| "bad_commit_hash")?;

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&salt);
    hasher.update(reveal_body.as_bytes());
    let computed = hasher.finalize();

    if computed.as_slice() != expected_hash.as_slice() {
        return Err("hash_mismatch");
    }
    Ok(())
}

/// The TAGMSG wire forms a sender's event takes, one per combination of the
/// two caps that change the line: `server-time` and `account-tag`.
///
/// `account` belongs on a TAGMSG for the same reason it belongs on a PRIVMSG.
/// It was originally scoped to PRIVMSG/NOTICE, when nothing about a TAGMSG was
/// a trust decision; a client that now has to decide whether the sender of a
/// delete may delete the message reads it off the event, and a nick is not an
/// identity. The IRCv3 account-tag spec asks for the tag on "all commands sent
/// by a user", so the narrower scope was the deviation.
///
/// The account forms are `None` for a guest — no DID, nothing to name — and
/// such a sender's events fall back to the forms without it.
struct TagmsgLines {
    plain: String,
    with_time: String,
    account: Option<String>,
    time_account: Option<String>,
}

impl TagmsgLines {
    fn build(
        tags: &std::collections::HashMap<String, String>,
        hostmask: &str,
        target: &str,
        time_tag: &str,
        sender_did: Option<&str>,
    ) -> Self {
        let render = |with_time: bool, with_account: bool| -> String {
            let mut t = tags.clone();
            if with_time {
                t.insert("time".to_string(), time_tag.to_string());
            }
            if with_account && let Some(did) = sender_did {
                t.insert("account".to_string(), did.to_string());
            }
            let msg = irc::Message {
                tags: t,
                prefix: Some(hostmask.to_string()),
                command: "TAGMSG".to_string(),
                params: vec![target.to_string()],
            };
            format!("{msg}\r\n")
        };
        TagmsgLines {
            plain: render(false, false),
            with_time: render(true, false),
            account: sender_did.map(|_| render(false, true)),
            time_account: sender_did.map(|_| render(true, true)),
        }
    }

    /// The form this receiver negotiated.
    fn pick(&self, has_time: bool, wants_account: bool) -> &str {
        match (has_time, wants_account) {
            (true, true) => self.time_account.as_deref().unwrap_or(&self.with_time),
            (true, false) => &self.with_time,
            (false, true) => self.account.as_deref().unwrap_or(&self.plain),
            (false, false) => &self.plain,
        }
    }
}

/// A mutation's signature, checked against the event exactly as it arrived.
pub(super) struct CheckedMutation {
    kind: freeq_sdk::chatsig::Mutation,
    /// The subject as the signer named it, before any re-rooting.
    subject: String,
    outcome: ClientSigOutcome,
}

/// The mutation a TAGMSG's tags describe, if any: the kind, the msgid it acts
/// on, and — for reactions — the emoji.
///
/// Both spellings of every tag, because this reads the wire before the draft
/// names are canonicalized. Kept in step with the sender side
/// (`freeq_sdk::client`) and the receive side (`verify_relayed_mutation_tags`)
/// so what one signs is what the others rebuild.
fn mutation_in(
    tags: &HashMap<String, String>,
) -> Option<(freeq_sdk::chatsig::Mutation, String, Option<String>)> {
    use freeq_sdk::chatsig::Mutation;
    let get = |a: &str, b: &str| tags.get(a).or_else(|| tags.get(b)).cloned();
    let subject = || get("+reply", "+draft/reply");
    if let Some(subject) = get("+draft/delete", "+delete") {
        return Some((Mutation::Delete, subject, None));
    }
    if let Some(emoji) = get("+react", "+draft/react") {
        return Some((Mutation::React, subject()?, Some(emoji)));
    }
    if let Some(emoji) = tags.get("+freeq.at/unreact").cloned() {
        return Some((Mutation::Unreact, subject()?, Some(emoji)));
    }
    None
}

/// Check the signature on an incoming mutation, if it carries one.
///
/// `None` when the event is not a mutation (typing, AV signalling — ephemera
/// nobody signs) or carries no signature at all, which is today's traffic and
/// stays exactly as permissive as today.
fn mutation_signature(
    conn: &Connection,
    target: &str,
    tags: &HashMap<String, String>,
    state: &Arc<SharedState>,
) -> Option<CheckedMutation> {
    let sig_tag = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))?;
    let (kind, subject, emoji) = mutation_in(tags)?;
    let event_msgid = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .map(String::as_str)
        .unwrap_or_default();
    let outcome = verify_local_mutation(
        state,
        conn,
        target,
        kind,
        event_msgid,
        &subject,
        emoji.as_deref(),
        sig_tag,
    );
    Some(CheckedMutation {
        kind,
        subject,
        outcome,
    })
}

/// Whether a *mutation's* signature may ride onward — to local members and
/// over S2S — attached to this event.
///
/// Only a signature that verified, and only while the values it covers are
/// still the values on the wire. Re-rooting a subject is this server's doing,
/// so a peer that then read the event as forged would be reading our edit, not
/// the sender's intent.
fn keep_signature(checked: Option<&CheckedMutation>, tidied: &HashMap<String, String>) -> bool {
    let Some(checked) = checked else {
        // An unsigned mutation, or one from a guest with nothing to vouch for.
        return false;
    };
    if checked.outcome != ClientSigOutcome::Verified {
        return false;
    }
    match mutation_in(tidied) {
        Some((kind, subject, _)) => kind == checked.kind && subject == checked.subject,
        None => false,
    }
}

/// What this server will stand behind for an outgoing mutation: the id the
/// event is filed under, and the signature that goes with it.
pub(crate) struct VouchedMutation {
    pub event_id: String,
    /// The sender's own signature, or this server's over the same document.
    /// `None` only for a guest — no identity, nothing to vouch for.
    pub signature: Option<String>,
}

/// Settle a mutation's signature the way a message's is settled.
///
/// A note under a user's name means the same thing whether it is a sentence or
/// a delete: *this server saw this authenticated account do this*. So the
/// rules are the message rules, with no special case:
///
/// - the sender's signature, when it verifies and still covers what is on the
///   wire — the only outcome with real non-repudiation;
/// - **this server's signature** over the same document otherwise, which says
///   only what it means. A reader tells the two apart by the key each names,
///   which is what `verified_by` reports;
/// - nothing at all for a guest, who has no identity to bind.
///
/// A signature that *failed* never reaches here: the caller refuses the event.
fn vouch_mutation(
    conn: &Connection,
    target: &str,
    tidied: &HashMap<String, String>,
    checked: Option<&CheckedMutation>,
    state: &Arc<SharedState>,
) -> Option<VouchedMutation> {
    let (kind, subject, emoji) = mutation_in(tidied)?;
    let event_id = tidied
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tidied.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .cloned();

    // The sender's own, when it verified and nothing since has moved out from
    // under it.
    if keep_signature(checked, tidied)
        && let (Some(event_id), Some(sig)) = (
            event_id.clone(),
            tidied
                .get("+freeq.at/sig")
                .or_else(|| tidied.get("freeq.at/sig"))
                .cloned(),
        )
    {
        return Some(VouchedMutation {
            event_id,
            signature: Some(sig),
        });
    }

    let did = conn.authenticated_did.as_deref()?;
    // Without a venue there is no document, and inventing one would produce a
    // signature nobody could rebuild — the exact failure the canonical exists
    // to end. The act still happens; it just isn't vouched for.
    let venue = signing_venue(state, did, target)?;
    // The sender's id is kept when it holds up, so the event this server
    // vouches for and the one the sender named are the same event. Otherwise
    // the act still needs an identity, and this server mints it.
    let event_id = event_id
        .filter(|id| crate::msgid::check_client_minted(id, now_ms()).is_ok())
        .unwrap_or_else(crate::msgid::generate);

    let mut doc =
        freeq_sdk::chatsig::ChatDoc::mutation(kind, did, &event_id, &venue, &subject);
    if let Some(ref emoji) = emoji {
        doc = doc.with_emoji(emoji);
    }
    let signature = doc.sign(&state.msg_signing_key);
    Some(VouchedMutation {
        event_id,
        signature: Some(signature),
    })
}

/// The log entry a settled mutation makes, if there is anything to log.
///
/// `None` when the mutation was never vouched for — a guest, or a target whose
/// venue does not resolve. The derived-table change still happens; the log
/// records only acts it can name an id for.
fn mutation_event<'a>(
    vouched: Option<&'a VouchedMutation>,
    actor_did: Option<&'a str>,
    ctx: &crate::events::EventContext,
    timestamp: u64,
) -> Option<crate::db::MutationEvent<'a>> {
    let vouched = vouched?;
    Some(crate::db::MutationEvent {
        event_id: &vouched.event_id,
        actor_did,
        signature: vouched.signature.as_deref(),
        ctx: ctx.clone(),
        timestamp,
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn handle_tagmsg(
    conn: &Connection,
    target: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
) {
    if tags.is_empty() {
        return; // TAGMSG with no tags is meaningless
    }

    // Channel names are case-insensitive, and `process_privmsg` normalizes its
    // target before persisting — so messages, reactions and pins all live under
    // the lowercased key. Normalize here too, or every TAGMSG-driven feature
    // addresses a key that may not exist: a client that keeps the display case
    // it joined with ("#Case") could not delete or edit its own messages
    // (MESSAGE_NOT_FOUND), and its reactions persisted under the un-normalized
    // name, orphaned from the message they annotate.
    let normalized_target;
    let target: &str = if target.starts_with('#') || target.starts_with('&') {
        normalized_target = normalize_channel(target);
        &normalized_target
    } else {
        target
    };

    // ── Check the signature before rewriting anything it covers ──
    //
    // Everything below renames draft tags and re-roots the subject. Both
    // change bytes the document binds, so the check runs against the event as
    // it arrived; the tidied copy is what gets filed and relayed.
    //
    // Scoped to mutations on purpose. An act event or a coordination event
    // also carries `+freeq.at/sig`, over a different document and verified by
    // a different profile — judging those by the mutation canonical would
    // condemn every one of them.
    let is_mutation = mutation_in(tags).is_some();
    let arrived = mutation_signature(conn, target, tags, state);
    if let Some(ref checked) = arrived
        && checked.outcome == ClientSigOutcome::Failed
    {
        tracing::warn!(
            session = %conn.id, did = ?conn.authenticated_did, target = %target,
            kind = %checked.kind.as_str(), subject = %checked.subject,
            "Mutation signature did not verify against the key it names — refusing the event"
        );
        let reply = Message::from_server(
            &state.server_name,
            "FAIL",
            vec![
                "TAGMSG",
                "SIGNATURE_INVALID",
                "That signature does not verify against the key it names",
            ],
        );
        if let Some(tx) = state.connections.lock().get(&conn.id) {
            let _ = tx.try_send(format!("{reply}\r\n"));
        }
        return;
    }

    // Normalize IRCv3 draft tags to their canonical forms so all downstream
    // code (persistence, relay, fallback) only needs to check one name.
    let mut tags = tags.clone();
    for (draft, canonical) in [("+draft/react", "+react"), ("+draft/reply", "+reply")] {
        if let Some(v) = tags.remove(draft) {
            tags.entry(canonical.to_string()).or_insert(v);
        }
    }
    // Resolve the message being acted on to its root id before anything —
    // persistence, local fan-out and the S2S relay all read this map, so
    // rewriting here is what makes every receiver of any revision hear the one
    // identity the message keeps for life.
    {
        let acts_on_a_message =
            tags.contains_key("+react") || tags.contains_key("+freeq.at/unreact");
        if acts_on_a_message
            && let Some(target_msgid) = tags.get("+reply")
        {
            let root = super::helpers::root_msgid(state, target_msgid);
            tags.insert("+reply".to_string(), root);
        }
        if let Some(deleted) = tags.get("+draft/delete") {
            let root = super::helpers::root_msgid(state, deleted);
            tags.insert("+draft/delete".to_string(), root);
        }
    }
    // Settle what this server stands behind. The sender's signature when it
    // verified and still covers what is on the wire; this server's over the
    // same document otherwise; nothing at all for a guest. A signature the
    // server did not make and cannot vouch for never leaves the server — the
    // never-launder rule, which is also what stops a guest inventing a lock
    // badge for free.
    let vouched = if is_mutation {
        vouch_mutation(conn, target, &tags, arrived.as_ref(), state)
    } else {
        None
    };
    if is_mutation {
        tags.remove("+freeq.at/sig");
        tags.remove("freeq.at/sig");
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG_BARE);
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
        if let Some(ref v) = vouched {
            tags.insert(
                freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                v.event_id.clone(),
            );
            if let Some(ref sig) = v.signature {
                tags.insert("+freeq.at/sig".to_string(), sig.clone());
            }
        }
    }
    let tags = &tags;
    // What the log records: a signature this server checked or made either
    // way, so the verdict is `valid` whenever there is one at all.
    let event_ctx = crate::events::EventContext::verified();

    // ── Message deletion (+draft/delete=<msgid>) ──
    if let Some(original_msgid) = tags.get("+draft/delete") {
        handle_delete(
            conn,
            target,
            original_msgid,
            tags,
            vouched.as_ref(),
            &event_ctx,
            state,
        );
        return;
    }

    // ── Coordination event storage (+freeq.at/event) ──
    if let Some(event_type) = tags.get("+freeq.at/event")
        && let Some(ref did) = conn.authenticated_did
    {
        // SECURITY (CTF-20): rate-limit event storage per session.
        // Previously TAGMSG had no flood protection, so an
        // authenticated user could spam hundreds of event TAGMSGs
        // per second to fill the DB. Cap at 5 events / 2s, same
        // window as PRIVMSG flood protection.
        //
        // Reuses msg_timestamps under a session-derived synthetic
        // key so this counter is independent of the PRIVMSG one.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let key = format!("event:{}", conn.id);
            let mut ts_map = state.msg_timestamps.lock();
            let ts = ts_map.entry(key).or_default();
            ts.retain(|&t| now.saturating_sub(t) < 2000);
            if ts.len() >= 5 {
                let nick = conn.nick_or_star();
                let reply = Message::from_server(
                    &state.server_name,
                    "FAIL",
                    vec![
                        "TAGMSG",
                        "RATE_LIMITED",
                        "event-storage TAGMSG flood: 5 events / 2s per session",
                    ],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
                tracing::warn!(
                    actor = %did, nick = %nick,
                    "Rate-limited coordination-event TAGMSG flood",
                );
                return;
            }
            ts.push(now);
        }
        // SECURITY (CTF-20 cont.): also cap payload size before
        // decoding + storing. The 8 KB IRC line cap already bounds
        // each payload, but the explicit cap here is defense in
        // depth — and lets us return a clean FAIL instead of a
        // silent truncation.
        const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
        let raw_payload = tags
            .get("+freeq.at/payload")
            .map(String::as_str)
            .unwrap_or("");
        if raw_payload.len() > MAX_PAYLOAD_BYTES {
            let nick = conn.nick_or_star();
            let reply = Message::from_server(
                &state.server_name,
                "FAIL",
                vec![
                    "TAGMSG",
                    "PAYLOAD_TOO_LARGE",
                    &format!(
                        "+freeq.at/payload exceeds {MAX_PAYLOAD_BYTES} bytes; got {}",
                        raw_payload.len()
                    ),
                ],
            );
            if let Some(tx) = state.connections.lock().get(&conn.id) {
                let _ = tx.try_send(format!("{reply}\r\n"));
            }
            tracing::warn!(
                actor = %did, nick = %nick, size = raw_payload.len(),
                "Refused oversized coordination event payload",
            );
            return;
        }
        let event_id = tags
            .get("msgid")
            .cloned()
            .unwrap_or_else(crate::msgid::generate);
        let ref_id = tags
            .get("+freeq.at/ref")
            .or_else(|| tags.get("+freeq.at/task-id"))
            .cloned();
        let payload = if raw_payload.is_empty() {
            "{}".to_string()
        } else {
            urlencoding::decode(raw_payload)
                .unwrap_or_else(|_| raw_payload.into())
                .into_owned()
        };
        // Re-check after decoding: percent-decoding can expand by
        // up to ~3x if the input was all `%xx`, so even a
        // payload that fit before decoding may exceed the cap
        // after.
        if payload.len() > MAX_PAYLOAD_BYTES {
            tracing::warn!(actor = %did, "Decoded payload exceeded cap; dropping");
            return;
        }
        let signature = tags.get("+freeq.at/sig").cloned();
        let now = chrono::Utc::now().timestamp();
        let event = crate::db::CoordinationEventRow {
            event_id: event_id.clone(),
            event_type: event_type.clone(),
            actor_did: did.clone(),
            channel: target.to_string(),
            ref_id,
            payload_json: payload,
            signature,
            timestamp: now,
        };
        state.with_db(|db| db.store_coordination_event(&event));
        tracing::debug!(
            event_type = %event_type,
            event_id = %event_id,
            actor = %did,
            channel = %target,
            "Stored coordination event"
        );
    }

    // Log av-signal relay for debugging
    if tags.contains_key("+freeq.at/av-signal") {
        tracing::info!(
            from = %conn.nick_or_star(),
            target = %target,
            "Relaying WebRTC signal TAGMSG"
        );
    }

    // ── AV session control (+freeq.at/av-*) ──
    //
    // The dispatch key must be the *action* tag (av-start / av-join /
    // av-leave / av-end), never a parameter (av-id, av-instance,
    // av-title, …). Previously we grabbed `tags.keys().find(...)` on
    // anything starting with `+freeq.at/av-` and HashMap iteration
    // order picked whichever tag happened to hash first — so an
    // av-join TAGMSG that also carried av-id and av-instance would
    // sometimes dispatch under av-id, fall into the `_ => debug!` arm,
    // and silently do nothing. That was the "av-join succeeds for one
    // device but not the other" bug.
    //
    // av-signal / av-chunk are relay tags (WebRTC signalling / data
    // chunks) — must be forwarded, not consumed.
    const AV_ACTIONS: &[&str] = &[
        "+freeq.at/av-start",
        "+freeq.at/av-join",
        "+freeq.at/av-leave",
        "+freeq.at/av-end",
    ];
    if let Some(action) = AV_ACTIONS.iter().find(|tag| tags.contains_key(**tag)) {
        handle_av_tagmsg(conn, target, tags, action, state);
        return; // AV control tags are consumed server-side; don't relay
    }

    // ── Persist reactions (+react with +reply) ──
    if let (Some(emoji), Some(target_msgid)) = (tags.get("+react"), tags.get("+reply")) {
        let nick = conn.nick_or_star().to_string();
        let did = conn.authenticated_did.clone();
        let channel = target.to_string();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let emoji = emoji.clone();
        let target_msgid = target_msgid.clone();
        let ev = mutation_event(vouched.as_ref(), did.as_deref(), &event_ctx, ts);
        state.with_db(|db| {
            db.store_reaction_by(
                &target_msgid,
                &channel,
                &nick,
                did.as_deref(),
                &emoji,
                ts,
                ev.as_ref(),
            )
        });
    }

    // ── Remove reactions (+freeq.at/unreact with +reply) ──
    // Identity-keyed: authenticated users remove by DID (so a nick change
    // doesn't strand their reaction, and a nick squatter can't strip it);
    // guests remove only their own DID-less rows. The TAGMSG itself still
    // relays through the broadcast below so other clients drop the pill.
    if let (Some(emoji), Some(target_msgid)) = (tags.get("+freeq.at/unreact"), tags.get("+reply")) {
        let nick = conn.nick_or_star().to_string();
        let did = conn.authenticated_did.clone();
        let target_msgid = target_msgid.clone();
        let emoji = emoji.clone();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // The reaction row goes; the signed event that removed it stays.
        let ev = mutation_event(vouched.as_ref(), did.as_deref(), &event_ctx, ts);
        state.with_db(|db| {
            db.remove_reaction_by(&target_msgid, &nick, did.as_deref(), &emoji, ev.as_ref())
        });
    }

    let hostmask = conn.hostmask();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_tag = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string();

    // `server-time` and `account-tag` are negotiated independently, so there
    // are four wire forms and each receiver gets the one it asked for.
    let lines = TagmsgLines::build(
        tags,
        &hostmask,
        target,
        &time_tag,
        conn.authenticated_did.as_deref(),
    );

    // Generate a PRIVMSG fallback for plain clients (server-side downgrade).
    // Only for known tag types — unknown TAGMSGs are silently dropped for plain clients.
    let plain_fallback = tags.get("+react").map(|emoji| {
        format!(":{hostmask} PRIVMSG {target} :\x01ACTION reacted with {emoji}\x01\r\n")
    });

    // Rich clients get TAGMSG, plain clients get fallback PRIVMSG (if any)
    if target.starts_with('#') || target.starts_with('&') {
        // Channel TAGMSG — enforce +n (no external messages) and +m (moderated)
        // Resolve sender DID once, before taking the channels lock.
        let sender_did = state.session_dids.lock().get(&conn.id).cloned();
        {
            let channels = state.channels.lock();
            if let Some(ch) = channels.get(target) {
                // Founder + persistent DID-ops bypass +m. (+n is membership-based;
                // a non-member can't be founder anyway, so no bypass needed there.)
                let is_did_authority = sender_did.as_deref().is_some_and(|d| {
                    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                });
                // +n: must be a member to send
                if ch.no_ext_msg && !ch.members.contains(&conn.id) {
                    let nick = conn.nick_or_star();
                    let reply = Message::from_server(
                        &state.server_name,
                        irc::ERR_CANNOTSENDTOCHAN,
                        vec![nick, target, "Cannot send to channel (+n)"],
                    );
                    if let Some(tx) = state.connections.lock().get(&conn.id) {
                        let _ = tx.try_send(format!("{reply}\r\n"));
                    }
                    return;
                }
                // +m: must be voiced or op to send
                if ch.moderated
                    && !is_did_authority
                    && !ch.ops.contains(&conn.id)
                    && !ch.halfops.contains(&conn.id)
                    && !ch.voiced.contains(&conn.id)
                {
                    let nick = conn.nick_or_star();
                    let reply = Message::from_server(
                        &state.server_name,
                        irc::ERR_CANNOTSENDTOCHAN,
                        vec![nick, target, "Cannot send to channel (+m)"],
                    );
                    if let Some(tx) = state.connections.lock().get(&conn.id) {
                        let _ = tx.try_send(format!("{reply}\r\n"));
                    }
                    return;
                }
            }
        }

        let members: Vec<String> = state
            .channels
            .lock()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock();
        let time_caps = state.cap_server_time.lock();
        let acct_caps = state.cap_account_tag.lock();
        let echo_caps = state.cap_echo_message.lock();
        let conns = state.connections.lock();
        for member_session in &members {
            // Skip sender unless they have echo-message
            if member_session == &conn.id && !echo_caps.contains(member_session) {
                continue;
            }
            if let Some(tx) = conns.get(member_session) {
                if tag_caps.contains(member_session) {
                    let line = lines.pick(
                        time_caps.contains(member_session),
                        acct_caps.contains(member_session),
                    );
                    let _ = tx.try_send(line.to_string());
                } else if let Some(ref fallback) = plain_fallback {
                    let _ = tx.try_send(fallback.clone());
                }
            }
        }

        // Broadcast channel TAGMSG to S2S peers
        super::helpers::s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Tagmsg {
                event_id: super::helpers::s2s_next_event_id(state),
                from: conn.nick.as_deref().unwrap_or("*").to_string(),
                target: target.to_string(),
                tags: tags.clone(),
                origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                account: conn.authenticated_did.clone(),
            },
        );
    } else {
        // TAGMSG to a nick or DID. Deliver to every local session bound to the
        // target, and relay a *structured* Tagmsg to peers so a remote (or
        // multi-homed) recipient receives the tags.
        //
        // We deliberately do NOT route through `relay_to_nick` here: it is
        // PRIVMSG-shaped and, for a remote-only target, broadcasts an S2S
        // *Privmsg* (the reaction's ACTION fallback), silently dropping the
        // tags. Emitting an `S2sMessage::Tagmsg` unconditionally (peers dedup
        // by event_id; a peer with no local session for the target just no-ops)
        // is the same shape the PRIVMSG DM path already uses.
        let mut sessions = super::routing::local_sessions_for_target(state, target);
        // The sender's other devices get the event too — reactions/typing in
        // a DM otherwise leave the sender's own other clients stale.
        for sib in sender_sibling_sessions(state, conn) {
            if !sessions.contains(&sib) {
                sessions.push(sib);
            }
        }
        // Echo to the sender, same as the channel branch: a client holding
        // echo-message renders its own reaction from the echo, not
        // optimistically.
        if state.cap_echo_message.lock().contains(&conn.id) && !sessions.contains(&conn.id) {
            sessions.push(conn.id.clone());
        }
        {
            let tag_caps = state.cap_message_tags.lock();
            let time_caps = state.cap_server_time.lock();
            let acct_caps = state.cap_account_tag.lock();
            let conns = state.connections.lock();
            for session in &sessions {
                if let Some(tx) = conns.get(session) {
                    if tag_caps.contains(session) {
                        let line =
                            lines.pick(time_caps.contains(session), acct_caps.contains(session));
                        let _ = tx.try_send(line.to_string());
                    } else if let Some(ref fallback) = plain_fallback {
                        let _ = tx.try_send(fallback.clone());
                    }
                }
            }
        }
        // Relay to peers for cross-server + multi-homed delivery. The receiver
        // rebuilds the plain-client fallback from the tags.
        super::helpers::s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Tagmsg {
                event_id: super::helpers::s2s_next_event_id(state),
                from: conn.nick.as_deref().unwrap_or("*").to_string(),
                target: target.to_string(),
                tags: tags.clone(),
                origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                account: conn.authenticated_did.clone(),
            },
        );
    }
}

pub(super) fn handle_privmsg(
    conn: &Connection,
    command: &str,
    target: &str,
    text: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
) {
    // Non-multiline entry — preserves the existing call-shape for every
    // caller that didn't come from a draft/multiline batch.
    handle_privmsg_with_multiline(conn, command, target, text, tags, state, None);
}

/// Same as `handle_privmsg`, but when `multiline_lines` is Some, the
/// channel-broadcast path emits per-receiver wire frames (BATCH-
/// wrapped for `draft/multiline`-capable receivers, individual
/// PRIVMSGs for fallback receivers) instead of a single line.
///
/// `handle_privmsg` is the wrapper for the normal single-PRIVMSG case;
/// `dispatch_assembled_batch` in connection::draft_multiline calls
/// this directly with `Some(batch.lines)` so the channel broadcast
/// produces wire-valid output (a single PRIVMSG with `\n` in its body
/// would corrupt the IRC line on the receiving side).
pub(super) fn handle_privmsg_with_multiline(
    conn: &Connection,
    command: &str,
    target: &str,
    text: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
    multiline_lines: Option<&[super::draft_multiline::BatchLine]>,
) {
    crate::server::Metrics::bump(&state.metrics.messages_total);
    let hostmask = conn.hostmask();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_tag = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string();

    // ── Message editing (+draft/edit=<msgid>) ──
    if let Some(original_msgid) = tags.get("+draft/edit") {
        // Carry the sender's pre-chunked breakdown through to handle_edit
        // when the edit arrived as a BATCH (plaintext multi-line OR
        // ciphertext-chunked E2EE). handle_edit re-broadcasts using the
        // same chunking; preserves concat=true semantics for ciphertext
        // so receivers reassemble the exact AES-GCM blob.
        handle_edit(
            conn,
            target,
            text,
            original_msgid,
            tags,
            state,
            multiline_lines,
        );
        return;
    }

    let is_channel = target.starts_with('#') || target.starts_with('&');
    let is_notice = command == "NOTICE";

    // Per-session flood protection: max 5 messages per 2 seconds (channels + DMs).
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut ts_map = state.msg_timestamps.lock();
        let ts = ts_map.entry(conn.id.clone()).or_default();
        ts.retain(|&t| now.saturating_sub(t) < 2000);
        if ts.len() >= 5 {
            // NOTICE must never generate error replies (RFC 2812 3.3.2)
            if !is_notice {
                let nick = conn.nick_or_star();
                let reply = Message::from_server(
                    &state.server_name,
                    irc::ERR_CANNOTSENDTOCHAN,
                    vec![nick, target, "Flood protection: sending too fast"],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
            }
            return;
        }
        ts.push(now);
    }

    if is_channel {
        // Channel message — enforce +n (no external messages) and +m (moderated)
        // Resolve sender DID once, before taking the channels lock.
        let sender_did = state.session_dids.lock().get(&conn.id).cloned();
        {
            let channels = state.channels.lock();
            if let Some(ch) = channels.get(target) {
                // Founder + persistent DID-ops bypass +m.
                let is_did_authority = sender_did.as_deref().is_some_and(|d| {
                    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                });
                // +n: must be a member to send
                if ch.no_ext_msg && !ch.members.contains(&conn.id) {
                    // NOTICE must never generate error replies (RFC 2812 3.3.2)
                    if !is_notice {
                        let nick = conn.nick_or_star();
                        let reply = Message::from_server(
                            &state.server_name,
                            irc::ERR_CANNOTSENDTOCHAN,
                            vec![nick, target, "Cannot send to channel (+n)"],
                        );
                        if let Some(tx) = state.connections.lock().get(&conn.id) {
                            let _ = tx.try_send(format!("{reply}\r\n"));
                        }
                    }
                    return;
                }
                // +m: must be voiced or op to send
                if ch.moderated
                    && !is_did_authority
                    && !ch.ops.contains(&conn.id)
                    && !ch.halfops.contains(&conn.id)
                    && !ch.voiced.contains(&conn.id)
                {
                    if !is_notice {
                        let nick = conn.nick_or_star();
                        let reply = Message::from_server(
                            &state.server_name,
                            irc::ERR_CANNOTSENDTOCHAN,
                            vec![nick, target, "Cannot send to channel (+m)"],
                        );
                        if let Some(tx) = state.connections.lock().get(&conn.id) {
                            let _ = tx.try_send(format!("{reply}\r\n"));
                        }
                    }
                    return;
                }
                // +E: encrypted-only mode.
                //
                // SECURITY (CTF-21): require BOTH the `+encrypted` tag
                // AND an actual ENC1-prefixed ciphertext body. Previously
                // only the tag was checked, so a malicious client could
                // send `@+encrypted PRIVMSG #ch :leaked plaintext` and
                // any logger or non-aware viewer would see the body in
                // the clear.
                // Accept either passphrase channels (ENC1) or VC-bootstrapped
                // sender-keys group channels (EG1). Both bodies are opaque
                // AEAD ciphertext the server never reads; the tag+prefix pair
                // is what CTF-21 enforces so no plaintext can ride a +E channel.
                let has_tag = tags.contains_key("+encrypted");
                let has_ciphertext =
                    (text.starts_with("ENC1:") || text.starts_with("EG1:")) && text.len() > 5;
                if ch.encrypted_only && !(has_tag && has_ciphertext) {
                    if !is_notice {
                        let nick = conn.nick_or_star();
                        let reason = if !has_tag {
                            "Cannot send to channel (+E) — messages must carry the +encrypted tag"
                        } else {
                            "Cannot send to channel (+E) — body must be ENC1/EG1-prefixed ciphertext"
                        };
                        let reply = Message::from_server(
                            &state.server_name,
                            irc::ERR_CANNOTSENDTOCHAN,
                            vec![nick, target, reason],
                        );
                        if let Some(tx) = state.connections.lock().get(&conn.id) {
                            let _ = tx.try_send(format!("{reply}\r\n"));
                        }
                    }
                    return;
                }
            }
        }

        // Run plugin on_message hook
        let msg_event = crate::plugin::MessageEvent {
            nick: conn.nick.clone().unwrap_or_default(),
            command: command.to_string(),
            target: target.to_string(),
            text: text.to_string(),
            did: conn.authenticated_did.clone(),
            session_id: conn.id.clone(),
        };
        let msg_result = state.plugin_manager.on_message(&msg_event);
        if msg_result.suppress {
            return;
        }
        let text = msg_result.rewrite_text.as_deref().unwrap_or(text);

        // The id this message is filed under — the sender's own if it minted
        // one and it holds up (see `resolve_event_msgid`).
        let msgid = match resolve_event_msgid(conn, tags, state) {
            Ok(id) => id,
            Err((code, description)) => {
                send_eventid_fail(conn, command, code, &description, state);
                return;
            }
        };

        // Build tags with msgid injected (for tag-capable clients)
        let mut full_tags = tags.clone();
        strip_event_id_tag(&mut full_tags);
        full_tags.insert("msgid".to_string(), msgid.clone());

        // Verify client signature or server-sign as fallback
        let client_sig = tags.get("+freeq.at/sig").map(|s| s.as_str());
        let signed = SignedFields {
            body: text,
            msgid: &msgid,
            reply: reply_reference(tags),
            edit: None,
            body_rewritten: msg_result.rewrite_text.is_some(),
        };
        set_signature(
            &mut full_tags,
            resolve_signature(conn, target, &signed, tags, client_sig, state),
        );

        // If this PRIVMSG is a commit-reveal `reveal` event, verify the
        // binding against the prior commit and stamp the outcome onto
        // the outgoing relay tags. Mirrors the verify-and-stamp pattern
        // used by `+freeq.at/sig` above. Verify-and-annotate, never
        // reject — bad reveals still relay, carrying a `false` verdict.
        if command == "PRIVMSG"
            && full_tags.get("+freeq.at/event").map(String::as_str) == Some("reveal")
        {
            let reveal_ref = full_tags
                .get("+freeq.at/ref")
                .or_else(|| full_tags.get("+freeq.at/task-id"))
                .cloned();
            let reveal_payload_raw = full_tags
                .get("+freeq.at/payload")
                .cloned()
                .unwrap_or_default();
            let reveal_payload_decoded = urlencoding::decode(&reveal_payload_raw)
                .map(|c| c.into_owned())
                .unwrap_or(reveal_payload_raw);
            let outcome = verify_commit_reveal(
                state,
                conn.authenticated_did.as_deref(),
                target,
                reveal_ref.as_deref(),
                &reveal_payload_decoded,
                text,
            );
            full_tags.insert(
                "+freeq.at/commit-verified".to_string(),
                if outcome.is_ok() { "true" } else { "false" }.to_string(),
            );
            if let Err(reason) = outcome {
                full_tags.insert("+freeq.at/commit-mismatch".to_string(), reason.to_string());
            }
        }

        let mut full_tags_with_time = full_tags.clone();
        full_tags_with_time.insert("time".to_string(), time_tag.clone());

        // Plain line (no tags) for clients that don't support message-tags
        let plain_line = format!(":{hostmask} {command} {target} :{text}\r\n");
        // Tagged line for clients that negotiated message-tags (no server-time)
        let tagged_line = {
            let tag_msg = irc::Message {
                tags: full_tags.clone(),
                prefix: Some(hostmask.clone()),
                command: command.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            format!("{tag_msg}\r\n")
        };
        // Tagged line with server-time
        let tagged_line_with_time = {
            let tag_msg = irc::Message {
                tags: full_tags_with_time.clone(),
                prefix: Some(hostmask.clone()),
                command: command.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            format!("{tag_msg}\r\n")
        };

        // Store in channel history
        if command == "PRIVMSG" {
            use crate::server::{HistoryMessage, MAX_HISTORY};
            let mut history_tags = full_tags.clone();
            if let Some(did) = conn.authenticated_did.as_deref() {
                history_tags.insert("account".to_string(), did.to_string());
            }
            let mut channels = state.channels.lock();
            if let Some(ch) = channels.get_mut(target) {
                ch.history.push_back(HistoryMessage {
                    from: hostmask.clone(),
                    text: text.to_string(),
                    timestamp,
                    tags: history_tags,
                    msgid: Some(msgid.clone()),
                    edited: false,
                });
                while ch.history.len() > MAX_HISTORY {
                    ch.history.pop_front();
                }
            }
            drop(channels);
            let sender_did = conn.authenticated_did.as_deref();
            // `full_tags`, not the tags as the client sent them — the same set
            // the DM path has always filed. The raw set carries whatever
            // signature the client attached, so history replayed a failed
            // signature that live delivery had stripped, and carried no
            // signature at all for a message the server signed on the
            // sender's behalf. It also still held the minted event id
            // alongside the msgid it became: two tags that must agree forever,
            // which is the ambiguity signing exists to remove.
            // Whatever signature is on `full_tags` is one this server stands
            // behind: it either verified the sender's, or made its own. A
            // failing one was stripped before it got here.
            let event_ctx = crate::events::EventContext::verified();
            state.with_db(|db| {
                db.insert_message_with(
                    target,
                    &hostmask,
                    text,
                    timestamp,
                    &full_tags,
                    Some(&msgid),
                    sender_did,
                    &event_ctx,
                )
            });

            // Prune old messages if configured — but only periodically, not on
            // every message. Pruning is a DELETE behind the single global DB
            // mutex; running it per-message doubled the blocking DB round-trips
            // on the hot path for no benefit (the in-memory history is already
            // capped above). Pruning every PRUNE_INTERVAL inserts keeps the DB
            // at most `max + PRUNE_INTERVAL` rows transiently.
            let max = state.config.max_messages_per_channel;
            if max > 0 {
                let should_prune = {
                    let mut counters = PRUNE_COUNTERS.lock();
                    let c = counters.entry(target.to_string()).or_insert(0);
                    *c += 1;
                    if *c >= PRUNE_INTERVAL {
                        *c = 0;
                        true
                    } else {
                        false
                    }
                };
                if should_prune {
                    state.with_db(|db| db.prune_messages(target, max));
                }
            }
        }

        let members: Vec<String> = state
            .channels
            .lock()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock();
        let time_caps = state.cap_server_time.lock();
        let account_caps = state.cap_account_tag.lock();
        let echo_caps = state.cap_echo_message.lock();
        let multiline_caps = state.cap_draft_multiline.lock();
        let conns = state.connections.lock();
        let sender_did = conn.authenticated_did.as_deref();
        // When the logical message arrived as a draft/multiline batch
        // we already have its per-line breakdown; reuse the same
        // outbound batch id for every receiver. Receivers that
        // negotiated draft/multiline see BATCH frames; everyone else
        // sees the constituent PRIVMSGs (msgid on the first only).
        let outbound_batch_id = multiline_lines.map(|_| format!("ml{}", crate::msgid::generate()));
        for member_session in &members {
            // echo-message: include sender if they requested it
            if member_session == &conn.id && !echo_caps.contains(member_session) {
                continue;
            }
            if let Some(tx) = conns.get(member_session) {
                let has_tags = tag_caps.contains(member_session);
                let has_time = time_caps.contains(member_session);
                let wants_account = sender_did.is_some() && account_caps.contains(member_session);
                if let (Some(lines), Some(batch_id)) =
                    (multiline_lines, outbound_batch_id.as_deref())
                {
                    let caps = super::draft_multiline::ReceiverCaps {
                        has_tags,
                        has_time,
                        has_multiline: multiline_caps.contains(member_session),
                        wants_account,
                        sender_did,
                    };
                    let ctx = super::draft_multiline::RelayContext {
                        hostmask: &hostmask,
                        command,
                        target,
                        msgid: &msgid,
                        time_tag: &time_tag,
                        opener_tags: &full_tags,
                        batch_id,
                        lines,
                    };
                    for frame in
                        super::draft_multiline::build_outbound_multiline_frames(&ctx, &caps)
                    {
                        let _ = tx.try_send(frame);
                    }
                    continue;
                }
                let line: String = if !has_tags {
                    plain_line.clone()
                } else if !wants_account {
                    if has_time {
                        tagged_line_with_time.clone()
                    } else {
                        tagged_line.clone()
                    }
                } else {
                    // Per-recipient build with `account` tag injected.
                    // IRCv3 account-tag spec requires this only for opted-in clients.
                    let mut recip_tags = if has_time {
                        full_tags_with_time.clone()
                    } else {
                        full_tags.clone()
                    };
                    recip_tags.insert("account".to_string(), sender_did.unwrap().to_string());
                    let tag_msg = irc::Message {
                        tags: recip_tags,
                        prefix: Some(hostmask.clone()),
                        command: command.to_string(),
                        params: vec![target.to_string(), text.to_string()],
                    };
                    format!("{tag_msg}\r\n")
                };
                let _ = tx.try_send(line);
            }
        }

        // Broadcast channel PRIVMSG to S2S peers
        if command == "PRIVMSG" {
            let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
            let sig = full_tags.get("+freeq.at/sig").cloned();
            let (s2s_text, s2s_tags) = crate::s2s::encode_privmsg_text_for_s2s(
                text,
                crate::s2s::relay_coordination_tags(&full_tags),
            );
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::Privmsg {
                    event_id: s2s_next_event_id(state),
                    from: conn.nick.as_deref().unwrap_or("*").to_string(),
                    target: target.to_string(),
                    text: s2s_text,
                    origin,
                    msgid: Some(msgid.clone()),
                    sig,
                    account: conn.authenticated_did.clone(),
                    recipient_did: super::routing::recipient_did_for_target(state, target),
                    replaces_msgid: None,
                    tags: s2s_tags,
                    // When this message originated as a draft/multiline
                    // batch, ship the per-line breakdown so the peer
                    // can re-emit BATCH frames to its own multiline-
                    // capable clients. Otherwise None and the peer
                    // treats it as a normal PRIVMSG.
                    multiline_lines: multiline_lines.map(|lines| {
                        lines
                            .iter()
                            .map(|l| crate::s2s::MultilineLine {
                                body: l.body.clone(),
                                concat: l.concat_to_previous,
                            })
                            .collect()
                    }),
                },
            );
        }
    } else {
        // Private message — check RPL_AWAY and deliver
        let pm_msgid = match resolve_event_msgid(conn, tags, state) {
            Ok(id) => id,
            Err((code, description)) => {
                send_eventid_fail(conn, command, code, &description, state);
                return;
            }
        };
        let mut pm_tags = tags.clone();
        strip_event_id_tag(&mut pm_tags);
        pm_tags.insert("msgid".to_string(), pm_msgid.clone());

        // Verify client signature or server-sign DMs
        let client_sig = tags.get("+freeq.at/sig").map(|s| s.as_str());
        let signed = SignedFields {
            body: text,
            msgid: &pm_msgid,
            reply: reply_reference(tags),
            edit: None,
            body_rewritten: false,
        };
        set_signature(
            &mut pm_tags,
            resolve_signature(conn, target, &signed, tags, client_sig, state),
        );

        let mut pm_tags_with_time = pm_tags.clone();
        pm_tags_with_time.insert("time".to_string(), time_tag.clone());

        let plain_line = format!(":{hostmask} {command} {target} :{text}\r\n");
        let tagged_line = {
            let tag_msg = irc::Message {
                tags: pm_tags.clone(),
                prefix: Some(hostmask.clone()),
                command: command.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            format!("{tag_msg}\r\n")
        };
        let tagged_line_with_time = {
            let tag_msg = irc::Message {
                tags: pm_tags_with_time.clone(),
                prefix: Some(hostmask.clone()),
                command: command.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            format!("{tag_msg}\r\n")
        };

        // Build the wire frames for a recipient based on their
        // negotiated caps. Honors message-tags, server-time, and
        // account-tag (per IRCv3 spec). When the logical message
        // arrived as a draft/multiline batch, emits BATCH-wrapped
        // frames for receivers that negotiated draft/multiline and
        // N PRIVMSGs (msgid + tags on first only) for fallback
        // receivers. Without this branch a multiline DM would relay
        // as a single PRIVMSG with `\n` in its body, breaking the
        // IRC wire on the recipient side.
        let sender_did_for_dm = conn.authenticated_did.clone();
        let dm_outbound_batch_id =
            multiline_lines.map(|_| format!("ml{}", crate::msgid::generate()));
        let build_dm_frames = |recipient_session: &str| -> Vec<String> {
            let has_tags = state.cap_message_tags.lock().contains(recipient_session);
            let has_time = state.cap_server_time.lock().contains(recipient_session);
            let wants_account = sender_did_for_dm.is_some()
                && state.cap_account_tag.lock().contains(recipient_session);
            if let (Some(lines), Some(batch_id)) =
                (multiline_lines, dm_outbound_batch_id.as_deref())
            {
                let caps = super::draft_multiline::ReceiverCaps {
                    has_tags,
                    has_time,
                    has_multiline: state.cap_draft_multiline.lock().contains(recipient_session),
                    wants_account,
                    sender_did: sender_did_for_dm.as_deref(),
                };
                let ctx = super::draft_multiline::RelayContext {
                    hostmask: &hostmask,
                    command,
                    target,
                    msgid: &pm_msgid,
                    time_tag: &time_tag,
                    opener_tags: &pm_tags,
                    batch_id,
                    lines,
                };
                return super::draft_multiline::build_outbound_multiline_frames(&ctx, &caps);
            }
            if !has_tags {
                return vec![plain_line.clone()];
            }
            if !wants_account {
                return vec![if has_time {
                    tagged_line_with_time.clone()
                } else {
                    tagged_line.clone()
                }];
            }
            let mut recip_tags = if has_time {
                pm_tags_with_time.clone()
            } else {
                pm_tags.clone()
            };
            recip_tags.insert("account".to_string(), sender_did_for_dm.clone().unwrap());
            let tag_msg = irc::Message {
                tags: recip_tags,
                prefix: Some(hostmask.clone()),
                command: command.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            vec![format!("{tag_msg}\r\n")]
        };

        // Route through the federation routing layer.
        // See routing.rs for why we NEVER gate on remote_members here.
        use super::routing::{RelayIdentity, RouteResult, relay_to_nick};
        let from_nick = conn.nick.as_deref().unwrap_or("*").to_string();
        match relay_to_nick(
            state,
            &from_nick,
            target,
            text,
            s2s_next_event_id(state),
            multiline_lines,
            RelayIdentity {
                account: conn.authenticated_did.as_deref(),
                // The id this server assigned. A peer that mints its own leaves
                // the two servers unable to name the same message.
                msgid: Some(&pm_msgid),
                sig: pm_tags.get("+freeq.at/sig").map(|s| s.as_str()),
                replaces_msgid: None,
                tags: crate::s2s::relay_coordination_tags(&pm_tags),
            },
        ) {
            RouteResult::Local(ref session) => {
                // Target is local — deliver to ALL sessions for target's DID (multi-device).
                // Also relay via S2S so the DM is visible on other federated servers
                // (e.g. sender logged into multiple servers).
                let (s2s_text, s2s_tags) = crate::s2s::encode_privmsg_text_for_s2s(
                    text,
                    crate::s2s::relay_coordination_tags(&pm_tags),
                );
                super::helpers::s2s_broadcast(
                    state,
                    crate::s2s::S2sMessage::Privmsg {
                        event_id: s2s_next_event_id(state),
                        from: conn.nick.as_deref().unwrap_or("*").to_string(),
                        target: target.to_string(),
                        text: s2s_text,
                        origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                        msgid: Some(pm_msgid.clone()),
                        sig: pm_tags.get("+freeq.at/sig").cloned(),
                        account: conn.authenticated_did.clone(),
                        recipient_did: super::routing::recipient_did_for_target(state, target),
                        replaces_msgid: None,
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
                    },
                );
                // Send RPL_AWAY if target is away
                if let Some(away_msg) = state.session_away.lock().get(session) {
                    let nick = conn.nick_or_star();
                    let reply = Message::from_server(
                        &state.server_name,
                        irc::RPL_AWAY,
                        vec![nick, target, away_msg],
                    );
                    if let Some(tx) = state.connections.lock().get(&conn.id) {
                        let _ = tx.try_send(format!("{reply}\r\n"));
                    }
                }

                // Find all sessions for target's DID
                let target_sessions: Vec<String> = {
                    let target_did = state.session_dids.lock().get(session).cloned();
                    if let Some(ref did) = target_did {
                        state
                            .did_sessions
                            .lock()
                            .get(did)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_else(|| vec![session.clone()])
                    } else {
                        vec![session.clone()] // Guest — single session
                    }
                };

                let conns = state.connections.lock();
                // Deliver to all target sessions
                for target_session in &target_sessions {
                    let frames = build_dm_frames(target_session);
                    if let Some(tx) = conns.get(target_session) {
                        for frame in frames {
                            if let Err(_e) = tx.try_send(frame) {
                                let target_nick = state
                                    .nick_to_session
                                    .lock()
                                    .get_nick(target_session)
                                    .map(|s| s.to_string())
                                    .unwrap_or_default();
                                tracing::warn!(
                                    from = %conn.nick.as_deref().unwrap_or("?"),
                                    to = %target_nick,
                                    session = %target_session,
                                    "DM dropped: target send buffer full"
                                );
                                break;
                            }
                        }
                    }
                }

                // echo-message: echo DM back to ALL sender's sessions
                let sender_sessions: Vec<String> = {
                    if let Some(ref did) = conn.authenticated_did {
                        state
                            .did_sessions
                            .lock()
                            .get(did)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_else(|| vec![conn.id.clone()])
                    } else {
                        vec![conn.id.clone()]
                    }
                };
                for sender_session in &sender_sessions {
                    if sender_session == &conn.id {
                        // Original sender — use echo-message cap
                        let sender_has_echo = state.cap_echo_message.lock().contains(&conn.id);
                        if sender_has_echo {
                            let frames = build_dm_frames(&conn.id);
                            if let Some(tx) = conns.get(&conn.id) {
                                for frame in frames {
                                    let _ = tx.try_send(frame);
                                }
                            }
                        }
                    } else {
                        // Other sessions of sender — deliver as if they received it
                        let frames = build_dm_frames(sender_session);
                        if let Some(tx) = conns.get(sender_session) {
                            for frame in frames {
                                let _ = tx.try_send(frame);
                            }
                        }
                    }
                }
            }
            RouteResult::Relayed => {
                // Sent to S2S peers — receiving server will deliver.
                // No ERR_NOSUCHNICK: we can't know if it arrived (same as email).
                // echo-message: echo DM back to sender even for relayed messages
                let sender_has_echo = state.cap_echo_message.lock().contains(&conn.id);
                if sender_has_echo {
                    let frames = build_dm_frames(&conn.id);
                    if let Some(tx) = state.connections.lock().get(&conn.id) {
                        for frame in frames {
                            let _ = tx.try_send(frame);
                        }
                    }
                }
            }
            RouteResult::Unreachable => {
                // No federation, nick doesn't exist locally
                let nick = conn.nick_or_star();
                let reply = Message::from_server(
                    &state.server_name,
                    irc::ERR_NOSUCHNICK,
                    vec![nick, target, "No such nick/channel"],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
            }
        }

        // Persist the sender's own copy if both ends have DIDs. Resolve the
        // recipient via the shared resolver so a `did:` target (and any nick
        // this server owns) is keyed correctly — previously a bare `nick_owners`
        // lookup missed DID-addressed DMs entirely.
        let sender_did = conn.authenticated_did.as_deref();
        let recipient_did = super::routing::recipient_did_for_target(state, target);
        if let (Some(s_did), Some(r_did)) = (sender_did, recipient_did.as_deref()) {
            let dm_key = crate::db::canonical_dm_key(s_did, r_did);
            let did_for_db = Some(s_did);
            let event_ctx = crate::events::EventContext::verified();
            state.with_db(|db| {
                db.insert_message_with(
                    &dm_key,
                    &hostmask,
                    text,
                    timestamp,
                    &pm_tags,
                    Some(&pm_msgid),
                    did_for_db,
                    &event_ctx,
                )
            });
        }
    }
}

// ── LIST command ────────────────────────────────────────────────────

fn parse_chathistory_ts(s: &str) -> Option<u64> {
    let s = s.strip_prefix("timestamp=").unwrap_or(s);
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp() as u64)
}

/// Resolve a CHATHISTORY/SEARCH target and authorize access.
/// For channels: membership check. For DMs: auth check + canonical key.
/// Returns (db_key, display_target); None means a FAIL was already sent.
/// `cmd` names the failing command in FAIL replies.
fn resolve_history_target(
    conn: &Connection,
    raw_target: &str,
    cmd: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &dyn Fn(&Arc<SharedState>, &str, String),
) -> Option<(String, String)> {
    let is_channel = raw_target.starts_with('#') || raw_target.starts_with('&');

    if is_channel {
        let target = normalize_channel(raw_target);
        {
            let channels = state.channels.lock();
            if let Some(ch) = channels.get(&target) {
                if !ch.members.contains(session_id) {
                    let reply = Message::from_server(
                        server_name,
                        "FAIL",
                        vec![
                            cmd,
                            "INVALID_TARGET",
                            &target,
                            "You are not in that channel",
                        ],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return None;
                }
            } else {
                let reply = Message::from_server(
                    server_name,
                    "FAIL",
                    vec![cmd, "INVALID_TARGET", &target, "No such channel"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return None;
            }
        }
        Some((target.clone(), target))
    } else {
        // DM target — require DID authentication
        let requester_did = match conn.authenticated_did.as_deref() {
            Some(did) => did.to_string(),
            None => {
                let reply = Message::from_server(
                    server_name,
                    "FAIL",
                    vec![
                        cmd,
                        "ACCOUNT_REQUIRED",
                        raw_target,
                        "You must be authenticated to access DM history",
                    ],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return None;
            }
        };

        // Resolve target to DID — accept DID directly or resolve nick
        let target_did = if raw_target.starts_with("did:") {
            raw_target.to_string()
        } else {
            match state
                .nick_owners
                .lock()
                .get(&raw_target.to_lowercase())
                .cloned()
            {
                Some(did) => did,
                None => {
                    let reply = Message::from_server(
                        server_name,
                        "FAIL",
                        vec![cmd, "INVALID_TARGET", raw_target, "Unknown target"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return None;
                }
            }
        };

        let dm_key = crate::db::canonical_dm_key(&requester_did, &target_did);
        Some((dm_key, raw_target.to_string()))
    }
}

pub(super) fn handle_chathistory(
    conn: &Connection,
    msg: &irc::Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &dyn Fn(&Arc<SharedState>, &str, String),
) {
    let _nick = conn.nick_or_star();

    // CHATHISTORY <subcommand> <target> [<param1> [<param2>]] <limit>
    if msg.params.len() < 3 {
        let reply = Message::from_server(
            server_name,
            "FAIL",
            vec!["CHATHISTORY", "NEED_MORE_PARAMS", "Insufficient parameters"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let subcmd = msg.params[0].to_uppercase();

    // Handle TARGETS subcommand separately — different parameter format.
    // CHATHISTORY TARGETS <from_ts> <to_ts> <limit>
    if subcmd == "TARGETS" {
        handle_chathistory_targets(conn, msg, state, server_name, session_id, send);
        return;
    }

    let Some((db_key, target)) = resolve_history_target(
        conn,
        &msg.params[1],
        "CHATHISTORY",
        state,
        server_name,
        session_id,
        send,
    ) else {
        return;
    };

    let has_tags = state.cap_message_tags.lock().contains(session_id);
    let has_time = state.cap_server_time.lock().contains(session_id);
    let has_batch = state.cap_batch.lock().contains(session_id);
    let has_multiline = state.cap_draft_multiline.lock().contains(session_id);

    // Fetch messages from DB based on subcommand
    let messages: Vec<crate::db::MessageRow> = match subcmd.as_str() {
        "BEFORE" => {
            if msg.params.len() < 4 {
                vec![]
            } else {
                let ts = parse_chathistory_ts(&msg.params[2]).unwrap_or(u64::MAX);
                let limit = msg.params[3].parse::<usize>().unwrap_or(50).min(500);
                state
                    .with_db(|db| db.get_messages(&db_key, limit, Some(ts)))
                    .unwrap_or_default()
            }
        }
        "AFTER" => {
            if msg.params.len() < 4 {
                vec![]
            } else {
                let ts = parse_chathistory_ts(&msg.params[2]).unwrap_or(0);
                let limit = msg.params[3].parse::<usize>().unwrap_or(50).min(500);
                state
                    .with_db(|db| db.get_messages_after(&db_key, ts, limit))
                    .unwrap_or_default()
            }
        }
        "LATEST" => {
            if msg.params.len() < 4 {
                vec![]
            } else {
                let limit = msg.params[3].parse::<usize>().unwrap_or(50).min(500);
                if msg.params[2] == "*" {
                    state
                        .with_db(|db| db.get_messages(&db_key, limit, None))
                        .unwrap_or_default()
                } else {
                    let ts = parse_chathistory_ts(&msg.params[2]).unwrap_or(0);
                    state
                        .with_db(|db| db.get_messages_after(&db_key, ts, limit))
                        .unwrap_or_default()
                }
            }
        }
        "BETWEEN" => {
            if msg.params.len() < 5 {
                vec![]
            } else {
                let start = parse_chathistory_ts(&msg.params[2]).unwrap_or(0);
                let end = parse_chathistory_ts(&msg.params[3]).unwrap_or(u64::MAX);
                let limit = msg.params[4].parse::<usize>().unwrap_or(50).min(500);
                state
                    .with_db(|db| db.get_messages_between(&db_key, start, end, limit))
                    .unwrap_or_default()
            }
        }
        _ => vec![],
    };

    replay_rows_as_batch(
        messages,
        &target,
        "chathistory",
        state,
        server_name,
        session_id,
        send,
        has_tags,
        has_time,
        has_batch,
        has_multiline,
    );
}

/// SEARCH <target> :<query> — full-text search over stored history.
/// Authorization matches CHATHISTORY: channel search requires membership,
/// DM search requires DID authentication. Results are replayed newest-last
/// inside a `freeq.at/search` batch, capped at 25 messages.
pub(super) fn handle_search(
    conn: &Connection,
    msg: &irc::Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &dyn Fn(&Arc<SharedState>, &str, String),
) {
    if msg.params.len() < 2 || msg.params[1].trim().is_empty() {
        let reply = Message::from_server(
            server_name,
            "FAIL",
            vec![
                "SEARCH",
                "NEED_MORE_PARAMS",
                "Usage: SEARCH <target> :<query>",
            ],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let Some((db_key, target)) = resolve_history_target(
        conn,
        &msg.params[0],
        "SEARCH",
        state,
        server_name,
        session_id,
        send,
    ) else {
        return;
    };

    let query = msg.params[1..].join(" ");
    const SEARCH_LIMIT: usize = 25;
    let mut messages: Vec<crate::db::MessageRow> = state
        .with_db(|db| db.search_messages(&db_key, &query, SEARCH_LIMIT, None))
        .unwrap_or_default();
    // search_messages returns newest-first; replay oldest-first so the
    // batch reads like CHATHISTORY output.
    messages.reverse();
    // A search hit is a pointer, not a replay event: address it by the root —
    // the id clients hold the message under. This also keys the reactions
    // lookup in replay_rows_as_batch, which files reactions by root.
    for row in &mut messages {
        if row.root_msgid.is_some() {
            row.msgid = row.root_msgid.clone();
        }
    }

    let has_tags = state.cap_message_tags.lock().contains(session_id);
    let has_time = state.cap_server_time.lock().contains(session_id);
    let has_batch = state.cap_batch.lock().contains(session_id);
    let has_multiline = state.cap_draft_multiline.lock().contains(session_id);

    replay_rows_as_batch(
        messages,
        &target,
        "freeq.at/search",
        state,
        server_name,
        session_id,
        send,
        has_tags,
        has_time,
        has_batch,
        has_multiline,
    );
}

/// Replay stored message rows to one session as an (optionally batched)
/// sequence of PRIVMSGs, preserving msgid/account/reaction tags and
/// multiline emission shapes. Shared by CHATHISTORY and SEARCH.
#[allow(clippy::too_many_arguments)]
fn replay_rows_as_batch(
    messages: Vec<crate::db::MessageRow>,
    target: &str,
    batch_type: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &dyn Fn(&Arc<SharedState>, &str, String),
    has_tags: bool,
    has_time: bool,
    has_batch: bool,
    has_multiline: bool,
) {
    let target = target.to_string();

    // Send as a batch (unique ID per request)
    let batch_id = format!("ch{}", crate::msgid::generate());
    if has_batch {
        send(
            state,
            session_id,
            format!(":{server_name} BATCH +{batch_id} {batch_type} {target}\r\n"),
        );
    }

    // Fetch reactions for all messages in this batch
    let msgids: Vec<&str> = messages.iter().filter_map(|r| r.msgid.as_deref()).collect();
    let reactions: std::collections::HashMap<String, Vec<crate::db::ReactionRow>> = state
        .with_db(|db| db.get_reactions_for_messages(&msgids))
        .unwrap_or_default();

    for row in &messages {
        let mut tags = if has_tags {
            row.tags.clone()
        } else {
            std::collections::HashMap::new()
        };
        // Include msgid if available
        if has_tags {
            if let Some(ref mid) = row.msgid {
                tags.insert("msgid".to_string(), mid.clone());
                // Include reactions as +freeq.at/reactions tag
                // Format: emoji1:nick1,nick2;emoji2:nick3
                if let Some(reaction_rows) = reactions.get(mid) {
                    let mut by_emoji: std::collections::HashMap<&str, Vec<&str>> =
                        std::collections::HashMap::new();
                    for r in reaction_rows {
                        by_emoji.entry(&r.emoji).or_default().push(&r.reactor_nick);
                    }
                    let encoded: Vec<String> = by_emoji
                        .iter()
                        .map(|(emoji, nicks)| format!("{}:{}", emoji, nicks.join(",")))
                        .collect();
                    if !encoded.is_empty() {
                        tags.insert("+freeq.at/reactions".to_string(), encoded.join(";"));
                    }
                }
            }
            if let Some(ref replaces) = row.replaces_msgid {
                tags.entry("+draft/edit".to_string())
                    .or_insert_with(|| replaces.clone());
            }
            if let Some(ref did) = row.sender_did {
                tags.insert("account".to_string(), did.clone());
            }
        }
        if has_time {
            let ts = chrono::DateTime::from_timestamp(row.timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%dT%H:%M:%S.000Z")
                .to_string();
            tags.insert("time".to_string(), ts);
        }
        if has_batch {
            tags.insert("batch".to_string(), batch_id.clone());
        }

        // If the stored body has internal newlines, the message
        // originated as a multiline batch. Re-emitting it as one
        // PRIVMSG would put `\n` on the wire, which terminates an
        // IRC line — the receiver's parser would split mid-line and
        // produce malformed input. Two emission shapes here, matching
        // the live broadcast path:
        //
        // - Capable receivers (negotiated draft/multiline): emit a
        //   nested `draft/multiline` BATCH inside the chathistory
        //   BATCH. They see history rows grouped as logical messages,
        //   the same way live broadcast presents them.
        // - Fallback receivers (no draft/multiline cap): split at \n
        //   and emit N tagged PRIVMSGs, msgid + client-only tags on
        //   the first only (per spec § "Message ids" + § "Fallback").
        let bodies: Vec<&str> = row.text.split('\n').collect();
        let is_multiline = bodies.len() > 1;
        if is_multiline && has_multiline && has_batch {
            // Nested BATCH path: emit `BATCH +<ml_id> draft/multiline
            // <target>` carrying the assembled-message tags (msgid,
            // sig, account, reactions, etc.) + batch=<chathistory_id>
            // for nesting, then per-chunk PRIVMSGs carrying only
            // batch=<ml_id>, then `BATCH -<ml_id>` carrying
            // batch=<chathistory_id>.
            let ml_id = format!("ml{}", crate::msgid::generate());
            let opener_msg = irc::Message {
                tags: tags.clone(),
                prefix: Some(row.sender.clone()),
                command: "BATCH".to_string(),
                params: vec![
                    format!("+{ml_id}"),
                    "draft/multiline".to_string(),
                    target.clone(),
                ],
            };
            send(state, session_id, format!("{opener_msg}\r\n"));
            for body in &bodies {
                let mut chunk_tags = std::collections::HashMap::new();
                chunk_tags.insert("batch".to_string(), ml_id.clone());
                let chunk_msg = irc::Message {
                    tags: chunk_tags,
                    prefix: Some(row.sender.clone()),
                    command: "PRIVMSG".to_string(),
                    params: vec![target.clone(), body.to_string()],
                };
                send(state, session_id, format!("{chunk_msg}\r\n"));
            }
            let mut closer_tags = std::collections::HashMap::new();
            if let Some(b) = tags.get("batch") {
                closer_tags.insert("batch".to_string(), b.clone());
            }
            let closer_msg = irc::Message {
                tags: closer_tags,
                prefix: None,
                command: "BATCH".to_string(),
                params: vec![format!("-{ml_id}")],
            };
            send(state, session_id, format!("{closer_msg}\r\n"));
            continue;
        }
        if is_multiline {
            // Fallback path: split at \n and emit N PRIVMSGs. msgid
            // and every client-only tag ride on the first chunk;
            // subsequent chunks carry only the chathistory batch tag
            // so they stay grouped under the same history-replay
            // unit.
            for (i, body) in bodies.iter().enumerate() {
                let chunk_tags = if i == 0 {
                    tags.clone()
                } else {
                    let mut t = std::collections::HashMap::new();
                    if let Some(b) = tags.get("batch") {
                        t.insert("batch".to_string(), b.clone());
                    }
                    t
                };
                if !chunk_tags.is_empty() && has_tags {
                    let tag_msg = irc::Message {
                        tags: chunk_tags,
                        prefix: Some(row.sender.clone()),
                        command: "PRIVMSG".to_string(),
                        params: vec![target.clone(), body.to_string()],
                    };
                    send(state, session_id, format!("{tag_msg}\r\n"));
                } else {
                    send(
                        state,
                        session_id,
                        format!(":{} PRIVMSG {} :{}\r\n", row.sender, target, body),
                    );
                }
            }
            continue;
        }
        if !tags.is_empty() && has_tags {
            let tag_msg = irc::Message {
                tags,
                prefix: Some(row.sender.clone()),
                command: "PRIVMSG".to_string(),
                params: vec![target.clone(), row.text.clone()],
            };
            send(state, session_id, format!("{tag_msg}\r\n"));
        } else {
            send(
                state,
                session_id,
                format!(":{} PRIVMSG {} :{}\r\n", row.sender, target, row.text),
            );
        }
    }

    if has_batch {
        send(
            state,
            session_id,
            format!(":{server_name} BATCH -{batch_id}\r\n"),
        );
    }
}

/// Handle CHATHISTORY TARGETS — list DM conversations for the authenticated user.
/// CHATHISTORY TARGETS <from_ts> <to_ts> <limit>
fn handle_chathistory_targets(
    conn: &Connection,
    msg: &irc::Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &dyn Fn(&Arc<SharedState>, &str, String),
) {
    // Require DID authentication
    let requester_did = match conn.authenticated_did.as_deref() {
        Some(did) => did,
        None => {
            let reply = Message::from_server(
                server_name,
                "FAIL",
                vec![
                    "CHATHISTORY",
                    "ACCOUNT_REQUIRED",
                    "*",
                    "You must be authenticated to list DM targets",
                ],
            );
            send(state, session_id, format!("{reply}\r\n"));
            return;
        }
    };

    let from_ts = if msg.params.len() > 1 {
        parse_chathistory_ts(&msg.params[1]).unwrap_or(0)
    } else {
        0
    };
    let to_ts = if msg.params.len() > 2 {
        parse_chathistory_ts(&msg.params[2]).unwrap_or(u64::MAX)
    } else {
        u64::MAX
    };
    let limit = if msg.params.len() > 3 {
        msg.params[3].parse::<usize>().unwrap_or(50).min(500)
    } else {
        50
    };

    let has_batch = state.cap_batch.lock().contains(session_id);
    let has_time = state.cap_server_time.lock().contains(session_id);
    let has_tags = state.cap_message_tags.lock().contains(session_id);

    let dm_conversations = state
        .with_db(|db| db.dm_conversations(requester_did, limit))
        .unwrap_or_default();

    let batch_id = format!("cht{}", crate::msgid::generate());
    if has_batch {
        send(
            state,
            session_id,
            format!(":{server_name} BATCH +{batch_id} draft/chathistory-targets\r\n"),
        );
    }

    for (dm_key, last_ts) in &dm_conversations {
        // Filter by timestamp range
        if *last_ts < from_ts || *last_ts > to_ts {
            continue;
        }

        // Extract partner DID from canonical key (dm:<did_a>,<did_b>)
        let partner_did = dm_key.strip_prefix("dm:").and_then(|rest| {
            let parts: Vec<&str> = rest.splitn(2, ',').collect();
            if parts.len() == 2 {
                if parts[0] == requester_did {
                    Some(parts[1])
                } else {
                    Some(parts[0])
                }
            } else {
                None
            }
        });

        if let Some(partner) = partner_did {
            // Resolve DID → nick for display via the full chain
            // (did_nicks → live session → identities table → message
            // history → raw DID), so an offline agent with a persisted or
            // previously-seen binding still shows a name, not the raw did:key.
            let display_nick = state.display_nick_for_did(partner);

            let mut tags = std::collections::HashMap::new();
            if has_batch {
                tags.insert("batch".to_string(), batch_id.clone());
            }
            if has_time {
                let ts_str = chrono::DateTime::from_timestamp(*last_ts as i64, 0)
                    .unwrap_or_default()
                    .format("%Y-%m-%dT%H:%M:%S.000Z")
                    .to_string();
                tags.insert("time".to_string(), ts_str);
            }
            // The partner's stable identity, so clients can key the
            // conversation by DID instead of re-deriving it from the display
            // nick (ambiguous across renames/servers — the source of DM
            // thread splits). Old clients ignore the tag; clients that never
            // negotiated message-tags keep getting the untagged line.
            if has_tags {
                tags.insert("freeq.at/partner-did".to_string(), partner.to_string());
            }

            if !tags.is_empty() {
                let tag_msg = irc::Message {
                    tags,
                    prefix: Some(server_name.to_string()),
                    command: "CHATHISTORY".to_string(),
                    params: vec!["TARGETS".to_string(), display_nick],
                };
                send(state, session_id, format!("{tag_msg}\r\n"));
            } else {
                send(
                    state,
                    session_id,
                    format!(":{server_name} CHATHISTORY TARGETS {display_nick}\r\n"),
                );
            }
        }
    }

    if has_batch {
        send(
            state,
            session_id,
            format!(":{server_name} BATCH -{batch_id}\r\n"),
        );
    }
}

// ── Message editing ─────────────────────────────────────────────────

/// Canonical DB storage key for a DM wire target from the sender's
/// perspective. DM messages live under `dm:<didA>,<didB>` (see
/// [`crate::db::canonical_dm_key`]), never under the wire target, which
/// may be the peer's nick OR their DID. Returns None for guests (no
/// sender DID) or an unresolvable nick.
pub(super) fn dm_canonical_key(
    conn: &Connection,
    target: &str,
    state: &Arc<SharedState>,
) -> Option<String> {
    let sender_did = conn.authenticated_did.as_deref()?;
    let recipient_did = if target.starts_with("did:") {
        target.to_string()
    } else {
        state
            .nick_owners
            .lock()
            .get(&target.to_lowercase())
            .cloned()?
    };
    Some(crate::db::canonical_dm_key(sender_did, &recipient_did))
}

/// Whether a row found by the *global* msgid fallback may be acted on for an
/// edit/delete addressed to a DM.
///
/// The fallback exists only to resolve DM-key ambiguity: the wire target may be
/// a nick or a DID, and the nick→DID mapping can be unavailable (partner
/// offline), so the canonical `dm:` key can't always be derived. It must never
/// reach a **channel** row. `handle_edit` / `handle_delete` derive both their
/// in-memory `ch.history`/`ch.pins` cleanup and their broadcast target from
/// `is_channel`, which is computed from the *wire* target — so a channel row
/// resolved through a DM target got soft-deleted in the DB while the channel
/// kept serving it from memory, and the channel was never told. That message
/// then vanished from search immediately and from history after the next
/// restart, while every current member still saw it.
///
/// Authorship is re-checked by the caller, so this is not the only guard — but
/// authorship alone doesn't make a cross-target mutation *coherent*.
pub(super) fn dm_fallback_row_is_addressable(row_channel: &str, caller_did: Option<&str>) -> bool {
    // Only DM rows are reachable this way; `dm:` keys are `dm:{did_a},{did_b}`.
    let Some(participants) = row_channel.strip_prefix("dm:") else {
        return false;
    };
    // Without an authenticated identity we cannot prove participation, so we
    // don't guess. Guest DM threads aren't persisted anyway, so this costs
    // nothing: the fallback would find no row for them regardless.
    let Some(did) = caller_did else { return false };
    participants.split(',').any(|p| p == did)
}

/// Look up an original message by msgid for an edit/delete. Channels key
/// by the wire target; DMs key by the canonical dm_key, so a DM tries the
/// target, then the canonical key, then a constrained global msgid search.
/// Returns the row so the caller can write back under `row.channel` — the key
/// it actually lives under — rather than re-deriving it.
fn find_original_message(
    conn: &Connection,
    target: &str,
    msgid: &str,
    is_channel: bool,
    state: &Arc<SharedState>,
) -> Option<Option<crate::db::MessageRow>> {
    let by_target = state.with_db(|db| db.get_message_by_msgid(target, msgid));
    if matches!(&by_target, Some(Some(_))) || is_channel {
        return by_target;
    }
    if let Some(dm_key) = dm_canonical_key(conn, target, state) {
        let by_dm = state.with_db(|db| db.get_message_by_msgid(&dm_key, msgid));
        if matches!(&by_dm, Some(Some(_))) {
            return by_dm;
        }
    }
    let global = state.with_db(|db| db.find_message_by_msgid(msgid));
    match &global {
        // Row exists but isn't addressable from this DM target — report it as
        // "not found" so no cross-target mutation happens. `Some(None)` keeps
        // the "DB present, no row" contract the callers already handle.
        Some(Some(row))
            if !dm_fallback_row_is_addressable(&row.channel, conn.authenticated_did.as_deref()) =>
        {
            Some(None)
        }
        _ => global,
    }
}

/// Handle a PRIVMSG with +draft/edit=<msgid> tag.
/// Verifies authorship, stores the edit, and broadcasts to channel or DM recipient.
///
/// `inbound_multiline_lines`: when the edit arrived as a draft/multiline
/// BATCH, the sender's pre-chunked breakdown — used directly for outbound
/// re-broadcast so the per-chunk shape (and `concat` flags) survive the
/// hop. Critical for ciphertext-chunked E2EE edits: the receiver needs
/// the same chunk boundaries to reassemble the AES-GCM blob byte-exact.
/// When None, falls back to splitting `new_text` on `\n` (plaintext
/// multi-line edits sent as a single PRIVMSG).
fn handle_edit(
    conn: &Connection,
    target: &str,
    new_text: &str,
    original_msgid: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
    inbound_multiline_lines: Option<&[super::draft_multiline::BatchLine]>,
) {
    let hostmask = conn.hostmask();
    let nick = conn.nick_or_star();
    let is_channel = target.starts_with('#') || target.starts_with('&');

    // An edit changes content, never identity. Anchor to the root so the
    // stored row, the in-memory entry and the `+draft/edit` tag every receiver
    // sees all name the same message, whichever revision the editor's client
    // held.
    let root_msgid = super::helpers::root_msgid(state, original_msgid);
    let original_msgid: &str = &root_msgid;

    // Verify authorship: look up original message by msgid, resolving the
    // canonical dm_key for DMs (target may be a nick or a DID).
    let original = find_original_message(conn, target, original_msgid, is_channel, state);
    // The key the row actually lives under — the edit must be written back
    // here (a DM lives under `dm:<a>,<b>`, not the wire target).
    let store_channel = match &original {
        Some(Some(row)) => row.channel.clone(),
        _ => target.to_string(),
    };
    match original {
        Some(Some(ref row)) => {
            // Prefer DID-based authorship check to prevent nick-reuse attacks
            let is_author = if let (Some(msg_did), Some(conn_did)) =
                (&row.sender_did, &conn.authenticated_did)
            {
                msg_did == conn_did
            } else if row.sender_did.is_some() {
                // Original message was from an authenticated user but current user has no DID
                // (or has a different DID) — deny
                false
            } else {
                // Fallback to nick comparison for guest (non-DID) messages
                let original_nick = row.sender.split('!').next().unwrap_or("");
                original_nick.eq_ignore_ascii_case(nick)
            };
            if !is_author {
                let reply = Message::from_server(
                    &state.server_name,
                    "FAIL",
                    vec![
                        "EDIT",
                        "AUTHOR_MISMATCH",
                        "You can only edit your own messages",
                    ],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
                return;
            }
            if row.deleted_at.is_some() {
                return; // Can't edit a deleted message
            }
        }
        _ => {
            // No row. In a channel that means a genuinely unknown msgid —
            // reject. In a DM the thread itself may be unpersisted (guest
            // DMs never write rows): relay the edit live like any other
            // message instead of failing — the DB is a bystander for these
            // threads, exactly as it is for their PRIVMSGs and reactions.
            // (No row also means no server-side authorship check; receiving
            // clients enforce editor == original sender.)
            if is_channel {
                let reply = Message::from_server(
                    &state.server_name,
                    "FAIL",
                    vec!["EDIT", "MESSAGE_NOT_FOUND", "Original message not found"],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
                return;
            }
        }
    }
    let persisted = matches!(original, Some(Some(_)));

    // The edit is its own event and gets its own id — the sender's, if it
    // minted one (an edit is signed like any other message).
    let edit_msgid = match resolve_event_msgid(conn, tags, state) {
        Ok(id) => id,
        Err((code, description)) => {
            send_eventid_fail(conn, "EDIT", code, &description, state);
            return;
        }
    };

    // Build tags with edit reference + new msgid
    let mut full_tags = tags.clone();
    strip_event_id_tag(&mut full_tags);
    full_tags.insert("msgid".to_string(), edit_msgid.clone());
    // Keep the +draft/edit tag so clients know this is an edit — pointing at
    // the root, which is the id they hold the message under.
    full_tags.insert("+draft/edit".to_string(), original_msgid.to_string());

    // Verify/sign edited message. The document covers `edit`, so a revision
    // cannot be detached from the message it revises without breaking the
    // signature.
    let client_sig = tags.get("+freeq.at/sig").map(|s| s.as_str());
    let signed = SignedFields {
        body: new_text,
        msgid: &edit_msgid,
        reply: reply_reference(tags),
        edit: Some(original_msgid),
        body_rewritten: false,
    };
    set_signature(
        &mut full_tags,
        resolve_signature(conn, target, &signed, tags, client_sig, state),
    );

    // Multi-line breakdown for BATCH-wrapped outbound. Two sources, in
    // priority order:
    //   1. Sender's pre-chunked BATCH (passed in as inbound_multiline_lines)
    //      — covers ciphertext-chunked E2EE edits where the body has no
    //      `\n` to split on but the wire frame still exceeds one PRIVMSG.
    //      Preserves the sender's `concat` flags so receivers reassemble
    //      the exact AES-GCM blob.
    //   2. Plaintext fallback: `new_text` contains `\n` — split on it.
    //      Covers multi-line edits that arrived as a single (malformed)
    //      PRIVMSG with embedded `\n`, OR were assembled from a sender
    //      BATCH but the per-chunk breakdown wasn't carried through.
    let multiline_lines: Option<Vec<super::draft_multiline::BatchLine>> =
        if let Some(lines) = inbound_multiline_lines {
            Some(lines.to_vec())
        } else if new_text.contains('\n') {
            Some(
                new_text
                    .split('\n')
                    .map(|body| super::draft_multiline::BatchLine {
                        body: body.to_string(),
                        concat_to_previous: false,
                        command: "PRIVMSG".to_string(),
                    })
                    .collect(),
            )
        } else {
            None
        };
    let outbound_batch_id = multiline_lines
        .as_ref()
        .map(|_| format!("ml{}", crate::msgid::generate()));
    // Fallback body: receivers without draft/multiline see only line1
    // of a multi-line edit. Single-line edits use new_text verbatim.
    let fallback_text: &str = multiline_lines
        .as_ref()
        .and_then(|lines| lines.first().map(|l| l.body.as_str()))
        .unwrap_or(new_text);

    // Plain line for non-tag clients (they see it as a new message)
    let plain_line = format!(":{hostmask} PRIVMSG {target} :{fallback_text}\r\n");
    // Tagged line with edit reference
    let tagged_line = {
        let tag_msg = irc::Message {
            tags: full_tags.clone(),
            prefix: Some(hostmask.clone()),
            command: "PRIVMSG".to_string(),
            params: vec![target.to_string(), fallback_text.to_string()],
        };
        format!("{tag_msg}\r\n")
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_tag = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string();
    let mut full_tags_with_time = full_tags.clone();
    full_tags_with_time.insert("time".to_string(), time_tag.clone());
    let tagged_line_with_time = {
        let tag_msg = irc::Message {
            tags: full_tags_with_time,
            prefix: Some(hostmask.clone()),
            command: "PRIVMSG".to_string(),
            params: vec![target.to_string(), fallback_text.to_string()],
        };
        format!("{tag_msg}\r\n")
    };

    // Store in DB
    // From `full_tags`, so the row keeps the signature the server actually
    // stood behind rather than whatever the client attached — the same rule
    // the plain-message path follows.
    let mut store_tags: std::collections::HashMap<String, String> = full_tags
        .iter()
        .filter(|(k, _)| *k != "msgid")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    store_tags.insert("+draft/edit".to_string(), original_msgid.to_string());
    // For DMs, store under the canonical dm_key (not the nick) so
    // edits appear in CHATHISTORY alongside the original message.
    // store_channel was captured from the original row above.
    // Unpersisted threads (no original row) get no edit row either —
    // the edit is as ephemeral as the message it replaces.
    let editor_did = conn.authenticated_did.as_deref();
    if persisted {
        let event_ctx = crate::events::EventContext::verified();
        state.with_db(|db| {
            db.insert_edit_with(
                &store_channel,
                &hostmask,
                new_text,
                timestamp,
                &store_tags,
                &edit_msgid,
                original_msgid,
                editor_did,
                &event_ctx,
            )
        });
    }

    // Update in-memory history (channels only)
    // Note: we keep the original msgid stable so that subsequent edits
    // (e.g., streaming) can still find the message by original_msgid.
    if is_channel {
        let mut channels = state.channels.lock();
        if let Some(ch) = channels.get_mut(target) {
            for hist in ch.history.iter_mut() {
                if hist.msgid.as_deref() == Some(original_msgid) {
                    hist.text = new_text.to_string();
                    // Don't change hist.msgid — keep original stable for chained edits
                    // Join replay collapses revisions into this one entry, so
                    // without the flag a late joiner can't tell it was edited.
                    hist.edited = true;
                    break;
                }
            }
        }
    }

    // Deliver edit
    if is_channel {
        // Channel: deliver to all members
        let members: Vec<String> = state
            .channels
            .lock()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock();
        let time_caps = state.cap_server_time.lock();
        let echo_caps = state.cap_echo_message.lock();
        let multiline_caps = state.cap_draft_multiline.lock();
        let conns = state.connections.lock();
        for sid in &members {
            if sid == &conn.id && !echo_caps.contains(sid) {
                continue;
            }
            if let Some(tx) = conns.get(sid) {
                // Multi-line edit + receiver negotiated draft/multiline →
                // emit BATCH-wrapped edit (opener carries +draft/edit + msgid).
                if let (Some(lines), Some(batch_id)) =
                    (multiline_lines.as_deref(), outbound_batch_id.as_deref())
                    && multiline_caps.contains(sid)
                {
                    let caps = super::draft_multiline::ReceiverCaps {
                        has_tags: tag_caps.contains(sid),
                        has_time: time_caps.contains(sid),
                        has_multiline: true,
                        wants_account: false,
                        sender_did: None,
                    };
                    let ctx = super::draft_multiline::RelayContext {
                        hostmask: &hostmask,
                        command: "PRIVMSG",
                        target,
                        msgid: &edit_msgid,
                        time_tag: &time_tag,
                        opener_tags: &full_tags,
                        batch_id,
                        lines,
                    };
                    for frame in
                        super::draft_multiline::build_outbound_multiline_frames(&ctx, &caps)
                    {
                        let _ = tx.try_send(frame);
                    }
                    continue;
                }
                // Fallback: single PRIVMSG (line1 only for multi-line edits).
                let line = if tag_caps.contains(sid) {
                    if time_caps.contains(sid) {
                        &tagged_line_with_time
                    } else {
                        &tagged_line
                    }
                } else {
                    &plain_line
                };
                let _ = tx.try_send(line.clone());
            }
        }

        // Broadcast to S2S peers
        let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
        let sig = full_tags.get("+freeq.at/sig").cloned();
        let (s2s_text, s2s_tags) = crate::s2s::encode_privmsg_text_for_s2s(
            new_text,
            crate::s2s::relay_coordination_tags(&full_tags),
        );
        s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Privmsg {
                event_id: s2s_next_event_id(state),
                from: nick.to_string(),
                target: target.to_string(),
                text: s2s_text,
                origin,
                msgid: Some(edit_msgid),
                sig,
                account: conn.authenticated_did.clone(),
                recipient_did: super::routing::recipient_did_for_target(state, target),
                // Tells the peer this revises a message it already has, rather
                // than being one. `+draft/edit` can't carry it: the relayed tag
                // map is filtered to `+freeq.at/*`.
                replaces_msgid: Some(original_msgid.to_string()),
                tags: s2s_tags,
                // Multi-line edit: pass the per-line breakdown so peer
                // servers can re-emit BATCH frames to their own
                // multiline-capable clients.
                multiline_lines: multiline_lines.as_ref().map(|lines| {
                    lines
                        .iter()
                        .map(|l| crate::s2s::MultilineLine {
                            body: l.body.clone(),
                            concat: l.concat_to_previous,
                        })
                        .collect()
                }),
            },
        );
    } else {
        // DM: deliver to target nick and echo to sender
        use super::routing::{RouteResult, relay_to_nick};
        let from_nick = conn.nick.as_deref().unwrap_or("*").to_string();

        // Per-session deliver helper: BATCH frames for multiline-capable
        // receivers, fallback single-PRIVMSG (line1 only) otherwise.
        let deliver_to_session = |tx: &tokio::sync::mpsc::Sender<String>, sid: &str| {
            let has_tags = state.cap_message_tags.lock().contains(sid);
            let has_time = state.cap_server_time.lock().contains(sid);
            let has_multiline = state.cap_draft_multiline.lock().contains(sid);
            if let (Some(lines), Some(batch_id)) =
                (multiline_lines.as_deref(), outbound_batch_id.as_deref())
                && has_multiline
            {
                let caps = super::draft_multiline::ReceiverCaps {
                    has_tags,
                    has_time,
                    has_multiline: true,
                    wants_account: false,
                    sender_did: None,
                };
                let ctx = super::draft_multiline::RelayContext {
                    hostmask: &hostmask,
                    command: "PRIVMSG",
                    target,
                    msgid: &edit_msgid,
                    time_tag: &time_tag,
                    opener_tags: &full_tags,
                    batch_id,
                    lines,
                };
                for frame in super::draft_multiline::build_outbound_multiline_frames(&ctx, &caps) {
                    let _ = tx.try_send(frame);
                }
                return;
            }
            let line = if has_tags {
                if has_time {
                    &tagged_line_with_time
                } else {
                    &tagged_line
                }
            } else {
                &plain_line
            };
            let _ = tx.try_send(line.clone());
        };

        // Pass multiline_lines to the federated relay so peers see a
        // multi-line edit and re-emit BATCH frames downstream.
        match relay_to_nick(
            state,
            &from_nick,
            target,
            new_text,
            s2s_next_event_id(state),
            multiline_lines.as_deref(),
            super::routing::RelayIdentity {
                account: conn.authenticated_did.as_deref(),
                msgid: Some(&edit_msgid),
                sig: full_tags.get("+freeq.at/sig").map(|s| s.as_str()),
                // What makes this an edit on the far side rather than a second
                // message in the thread.
                replaces_msgid: Some(original_msgid),
                tags: crate::s2s::relay_coordination_tags(&full_tags),
            },
        ) {
            RouteResult::Local(ref session) => {
                // Find all sessions for target's DID (multi-device support)
                let target_sessions: Vec<String> = {
                    let target_did = state.session_dids.lock().get(session).cloned();
                    if let Some(ref did) = target_did {
                        state
                            .did_sessions
                            .lock()
                            .get(did)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_else(|| vec![session.clone()])
                    } else {
                        vec![session.clone()]
                    }
                };

                // The sender's other devices need the edit too, or they show
                // stale text until their next history refetch.
                let siblings = sender_sibling_sessions(state, conn);
                let conns = state.connections.lock();
                // Deliver to all target sessions
                for target_session in &target_sessions {
                    if let Some(tx) = conns.get(target_session) {
                        deliver_to_session(tx, target_session);
                    }
                }
                for sib in &siblings {
                    if !target_sessions.contains(sib)
                        && let Some(tx) = conns.get(sib)
                    {
                        deliver_to_session(tx, sib);
                    }
                }

                // Echo to sender if echo-message enabled
                if state.cap_echo_message.lock().contains(&conn.id)
                    && let Some(tx) = conns.get(&conn.id)
                {
                    deliver_to_session(tx, &conn.id);
                }
            }
            RouteResult::Relayed => {
                // Target is on a federated peer — edit was relayed.
                // Deliver to the sender's other local devices + echo.
                let siblings = sender_sibling_sessions(state, conn);
                let conns = state.connections.lock();
                for sib in &siblings {
                    if let Some(tx) = conns.get(sib) {
                        deliver_to_session(tx, sib);
                    }
                }
                if state.cap_echo_message.lock().contains(&conn.id)
                    && let Some(tx) = conns.get(&conn.id)
                {
                    deliver_to_session(tx, &conn.id);
                }
            }
            RouteResult::Unreachable => {
                // Target not found — send error
                let reply = Message::from_server(
                    &state.server_name,
                    irc::ERR_NOSUCHNICK,
                    vec![&nick, target, "No such nick"],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
            }
        }
    }
}

// ── Message deletion ────────────────────────────────────────────────

/// Handle a TAGMSG with +draft/delete=<msgid> tag.
/// Verifies authorship, soft-deletes the message, broadcasts to channel or DM recipient.
///
/// `event_tags` carries the signer's `+freeq.at/sig` and the event id it
/// covers when the signature checked out — already stripped by the caller
/// when it did not, so this path never has to decide again. They ride on
/// every copy of the delete, local and federated, because a delete nobody
/// downstream can attribute is exactly the forgery this closes.
#[allow(clippy::too_many_arguments)]
fn handle_delete(
    conn: &Connection,
    target: &str,
    original_msgid: &str,
    event_tags: &std::collections::HashMap<String, String>,
    vouched: Option<&VouchedMutation>,
    event_ctx: &crate::events::EventContext,
    state: &Arc<SharedState>,
) {
    let hostmask = conn.hostmask();
    let nick = conn.nick_or_star();
    let is_channel = target.starts_with('#') || target.starts_with('&');

    // Verify authorship, resolving the canonical dm_key for DMs (target
    // may be a nick or a DID).
    let original = find_original_message(conn, target, original_msgid, is_channel, state);
    // The key the row actually lives under — soft-delete must target this,
    // not the wire target.
    let storage_key = match &original {
        Some(Some(row)) => row.channel.clone(),
        _ => target.to_string(),
    };
    match original {
        Some(Some(ref row)) => {
            // Prefer DID-based authorship check to prevent nick-reuse attacks
            let is_author = if let (Some(msg_did), Some(conn_did)) =
                (&row.sender_did, &conn.authenticated_did)
            {
                msg_did == conn_did
            } else if row.sender_did.is_some() {
                // Original message was from an authenticated user but current user has no DID
                // (or has a different DID) — deny
                false
            } else {
                // Fallback to nick comparison for guest (non-DID) messages
                let original_nick = row.sender.split('!').next().unwrap_or("");
                original_nick.eq_ignore_ascii_case(nick)
            };
            if !is_author {
                // Also allow ops to delete messages (channels only)
                let is_op = is_channel
                    && state
                        .channels
                        .lock()
                        .get(target)
                        .map(|ch| ch.ops.contains(&conn.id))
                        .unwrap_or(false);
                if !is_op {
                    let reply = Message::from_server(
                        &state.server_name,
                        "FAIL",
                        vec![
                            "DELETE",
                            "AUTHOR_MISMATCH",
                            "You can only delete your own messages",
                        ],
                    );
                    if let Some(tx) = state.connections.lock().get(&conn.id) {
                        let _ = tx.try_send(format!("{reply}\r\n"));
                    }
                    return;
                }
            }
            if row.deleted_at.is_some() {
                return; // Already deleted
            }
        }
        _ => {
            // No row: unknown msgid in a channel → reject; unpersisted DM
            // (guest threads) → relay the delete live like any other DM
            // event. Receiving clients enforce deleter == original sender.
            if is_channel {
                let reply = Message::from_server(
                    &state.server_name,
                    "FAIL",
                    vec!["DELETE", "MESSAGE_NOT_FOUND", "Original message not found"],
                );
                if let Some(tx) = state.connections.lock().get(&conn.id) {
                    let _ = tx.try_send(format!("{reply}\r\n"));
                }
                return;
            }
        }
    }
    let persisted = matches!(original, Some(Some(_)));

    // Soft-delete in DB (no-op for unpersisted threads — nothing to mark).
    // The event is what records *who* asked: the row itself keeps no actor,
    // and before the log there was nothing anywhere that did.
    if persisted {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let did = conn.authenticated_did.clone();
        let ev = mutation_event(vouched, did.as_deref(), event_ctx, ts);
        state.with_db(|db| db.soft_delete_message_by(&storage_key, original_msgid, ev.as_ref()));
    }

    // Remove from in-memory history and pins (channels only)
    if is_channel {
        let mut channels = state.channels.lock();
        if let Some(ch) = channels.get_mut(target) {
            ch.history
                .retain(|h| h.msgid.as_deref() != Some(original_msgid));
            ch.pins.retain(|p| p.msgid != original_msgid);
        }
    }

    // Build TAGMSG with +draft/delete for tag-capable clients. A recipient
    // that negotiated account-tag also gets the deleter's DID: deciding
    // whether this delete may act on the message is exactly what a client
    // cannot do from a nick.
    let mut del_tags = std::collections::HashMap::new();
    del_tags.insert("+draft/delete".to_string(), original_msgid.to_string());
    for name in [
        "+freeq.at/sig",
        freeq_sdk::chatsig::EVENT_ID_TAG,
    ] {
        if let Some(v) = event_tags.get(name) {
            del_tags.insert(name.to_string(), v.clone());
        }
    }
    let build_delete_line = |with_account: bool| -> String {
        let mut t = del_tags.clone();
        if with_account && let Some(ref did) = conn.authenticated_did {
            t.insert("account".to_string(), did.clone());
        }
        let tag_msg = irc::Message {
            tags: t,
            prefix: Some(hostmask.clone()),
            command: "TAGMSG".to_string(),
            params: vec![target.to_string()],
        };
        format!("{tag_msg}\r\n")
    };
    let tagged_line = build_delete_line(false);
    // `None` for a guest — no DID to name, so those recipients get the
    // plain form.
    let tagged_line_account = conn
        .authenticated_did
        .as_ref()
        .map(|_| build_delete_line(true));

    // Deliver delete notification
    if is_channel {
        // Channel: deliver to tag-capable members only (plain clients can't see deletes)
        let members: Vec<String> = state
            .channels
            .lock()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock();
        let acct_caps = state.cap_account_tag.lock();
        let conns = state.connections.lock();
        for sid in &members {
            if sid == &conn.id {
                continue; // Don't echo delete back to sender
            }
            if tag_caps.contains(sid)
                && let Some(tx) = conns.get(sid)
            {
                let line = if acct_caps.contains(sid) {
                    tagged_line_account.as_ref().unwrap_or(&tagged_line)
                } else {
                    &tagged_line
                };
                let _ = tx.try_send(line.clone());
            }
        }
        drop(conns);
        drop(acct_caps);
        drop(tag_caps);

        // Relay to peers. This has to be an explicit broadcast: `handle_tagmsg`
        // dispatches here and returns, so the generic TAGMSG relay below it
        // never runs for a delete — which is why deletes used to stop at the
        // origin, leaving the message readable on every other server.
        s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Tagmsg {
                event_id: s2s_next_event_id(state),
                from: nick.to_string(),
                target: target.to_string(),
                // `del_tags`, not a fresh map: a peer verifies the delete
                // against the signature and the event id it covers, and a
                // relay that dropped them left every receiver unable to
                // attribute the delete to anyone.
                tags: del_tags.clone(),
                origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                // The peer authorizes the delete against the message's author;
                // a nick alone would let any peer assert its way to one.
                account: conn.authenticated_did.clone(),
            },
        );
    } else {
        // DM: deliver the delete to every local session bound to the target
        // (a nick or a `did:`), fanning out across the DID's devices — and
        // to the sender's own other devices, which otherwise keep showing
        // the deleted message until their next refetch.
        // TAGMSG-specific, so we don't reuse relay_to_nick (it sends PRIVMSG).
        let mut target_sessions = super::routing::local_sessions_for_target(state, target);
        for sib in sender_sibling_sessions(state, conn) {
            if !target_sessions.contains(&sib) {
                target_sessions.push(sib);
            }
        }
        let tag_caps = state.cap_message_tags.lock();
        let acct_caps = state.cap_account_tag.lock();
        let conns = state.connections.lock();
        for target_session in &target_sessions {
            if tag_caps.contains(target_session)
                && let Some(tx) = conns.get(target_session)
            {
                let line = if acct_caps.contains(target_session) {
                    tagged_line_account.as_ref().unwrap_or(&tagged_line)
                } else {
                    &tagged_line
                };
                let _ = tx.try_send(line.clone());
            }
        }
        drop(conns);
        drop(acct_caps);
        drop(tag_caps);

        // The recipient may be on another server, or be reading this thread
        // from one. Relay unconditionally, the same way the DM PRIVMSG path
        // does — peers dedup by event_id, and one with no local session for
        // the target simply no-ops.
        s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Tagmsg {
                event_id: s2s_next_event_id(state),
                from: nick.to_string(),
                target: target.to_string(),
                // `del_tags`, not a fresh map: a peer verifies the delete
                // against the signature and the event id it covers, and a
                // relay that dropped them left every receiver unable to
                // attribute the delete to anyone.
                tags: del_tags.clone(),
                origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                account: conn.authenticated_did.clone(),
            },
        );
    }
}

/// Sessions of the sender's own DID other than the sending one. A DM event
/// (edit/delete/reaction) must reach the sender's other devices too — the
/// peer's sessions and the sending session alone leave the sender's other
/// clients showing stale state until their next history refetch. Guests
/// have no DID, hence no linkable siblings.
fn sender_sibling_sessions(state: &Arc<SharedState>, conn: &Connection) -> Vec<String> {
    let did = state.session_dids.lock().get(&conn.id).cloned();
    let Some(did) = did else {
        return Vec::new();
    };
    state
        .did_sessions
        .lock()
        .get(&did)
        .map(|s| s.iter().filter(|id| **id != conn.id).cloned().collect())
        .unwrap_or_default()
}

// ── AV session control ─────────────────────────────────────────────

/// Send a line to a specific session.
fn send_to(state: &Arc<SharedState>, session_id: &str, line: String) {
    if let Some(tx) = state.connections.lock().get(session_id) {
        let _ = tx.try_send(line);
    }
}

/// Handle TAGMSG with +freeq.at/av-* tags (session lifecycle control).
fn handle_av_tagmsg(
    conn: &super::Connection,
    target: &str,
    tags: &std::collections::HashMap<String, String>,
    av_tag: &str,
    state: &Arc<SharedState>,
) {
    let nick = conn.nick_or_star().to_string();
    // Use DID if authenticated, otherwise use nick as fallback identity
    let did = conn
        .authenticated_did
        .clone()
        .unwrap_or_else(|| format!("guest:{nick}"));

    let session_id = tags.get("+freeq.at/av-id").cloned().unwrap_or_default();

    match av_tag {
        "+freeq.at/av-start" => {
            let title = tags.get("+freeq.at/av-title").map(|s| s.as_str());
            let instance_id = tags.get("+freeq.at/av-instance").map(String::as_str);
            let channel = if target.starts_with('#') || target.starts_with('&') {
                Some(target)
            } else {
                None
            };

            let mut mgr = state.av_sessions.lock();
            match mgr.create_session(channel, &did, &nick, title, instance_id) {
                Ok(session) => {
                    let session_id = session.id.clone();
                    let participant_count = mgr.active_participant_count(&session_id);

                    // Persist to DB
                    if let Some(s) = mgr.get(&session_id) {
                        state.with_db(|db| db.save_av_session(s));
                    }

                    drop(mgr);

                    // Record this instance against the IRC connection. Without
                    // this, av-start-only clients (the iOS path doesn't send
                    // a separate av-join after creating the session) leave
                    // av_instances_per_conn empty, and the disconnect handler
                    // falls into the legacy whole-DID cleanup which ends the
                    // session on every minor reconnect blip.
                    if let Some(inst) = instance_id {
                        state
                            .av_instances_per_conn
                            .lock()
                            .entry(conn.id.clone())
                            .or_default()
                            .insert(inst.to_string());
                    }

                    // Broadcast session start to channel
                    let title_display = title.unwrap_or("voice session");
                    broadcast_av_state(
                        state,
                        target,
                        &session_id,
                        "started",
                        &nick,
                        instance_id.unwrap_or(""),
                        participant_count,
                        title_display,
                    );

                    // Create iroh-live Room for native client P2P audio.
                    // Browser clients use MoQ SFU; native clients join the Room directly.
                    {
                        let backend = state.av_media.lock().clone();
                        let state2 = state.clone();
                        let sid = session_id.clone();
                        let conn_id = conn.id.clone();
                        let nick2 = nick.clone();
                        tokio::spawn(async move {
                            if let Some(backend) = backend.as_ref() {
                                match crate::av_media::MediaBackend::create_room(
                                    backend.as_ref(),
                                    &sid,
                                )
                                .await
                                {
                                    Ok(ticket) => {
                                        // Store ticket in session
                                        let mut mgr = state2.av_sessions.lock();
                                        if let Some(s) = mgr.sessions.get_mut(&sid) {
                                            s.iroh_ticket = Some(ticket.clone());
                                        }
                                        if let Some(s) = mgr.get(&sid) {
                                            state2.with_db(|db| db.save_av_session(s));
                                        }
                                        drop(mgr);
                                        // Send ticket to creator
                                        let notice = Message::from_server(
                                            &state2.server_name,
                                            "NOTICE",
                                            vec![&nick2, &format!("AV ticket: {ticket}")],
                                        );
                                        send_to(&state2, &conn_id, format!("{notice}\r\n"));

                                        // Start the MoQ↔Room bridge
                                        #[cfg(feature = "av-native")]
                                        {
                                            if let Some((room_handle, room_events)) =
                                                backend.take_room_for_bridge(&sid)
                                            {
                                                let sfu = state2.sfu_state.lock().clone();
                                                if let Some(sfu) = sfu {
                                                    let bridge = crate::av_bridge::start_bridge(
                                                        sid.clone(),
                                                        sfu.cluster.clone(),
                                                        sfu.auth.clone(),
                                                        sfu.mint_session_token(&sid),
                                                        room_handle,
                                                        room_events,
                                                    );
                                                    // Store bridge handle to keep it alive
                                                    state2
                                                        .av_bridges
                                                        .lock()
                                                        .insert(sid.clone(), bridge);
                                                    tracing::info!(session = %sid, "MoQ↔Room bridge started");
                                                } else {
                                                    tracing::warn!(session = %sid, "SFU not available — bridge not started");
                                                }
                                            }
                                        }

                                        tracing::info!(session = %sid, "iroh-live room created");
                                    }
                                    Err(e) => {
                                        tracing::warn!(session = %sid, error = %e, "Failed to create iroh-live room");
                                    }
                                }
                            }
                        });
                    }

                    // Send session ID back to creator
                    let notice = Message::from_server(
                        &state.server_name,
                        "NOTICE",
                        vec![&nick, &format!("AV session started: {session_id}")],
                    );
                    send_to(state, &conn.id, format!("{notice}\r\n"));

                    // MoQ access token for the creator (they dial the SFU next)
                    send_av_token(state, &conn.id, &nick, &session_id);

                    // Broadcast via S2S
                    broadcast_av_s2s(
                        state,
                        "created",
                        &session_id,
                        channel,
                        &did,
                        &nick,
                        title,
                        None,
                    );

                    tracing::info!(session_id = %session_id, channel = ?channel, did = %did, "AV session created");
                }
                Err(e) => {
                    let reply = Message::from_server(
                        &state.server_name,
                        "NOTICE",
                        vec![&nick, &format!("Cannot start session: {e}")],
                    );
                    send_to(state, &conn.id, format!("{reply}\r\n"));
                    // Concurrent-start loser: tell the client WHICH session won
                    // so it can converge onto it immediately instead of waiting
                    // on a timeout heuristic (or silently showing a dead call).
                    let existing = mgr
                        .active_session_for_channel(target)
                        .map(|s| s.id.clone())
                        .unwrap_or_default();
                    send_av_error(state, &conn.id, &nick, &existing, "start-collision", &e);
                }
            }
        }

        "+freeq.at/av-join" => {
            if session_id.is_empty() {
                // Try to join the channel's active session
                let mgr = state.av_sessions.lock();
                if let Some(s) = mgr.active_session_for_channel(target) {
                    let id = s.id.clone();
                    drop(mgr);
                    // Re-call with the session ID
                    let mut tags2 = tags.clone();
                    tags2.insert("+freeq.at/av-id".to_string(), id);
                    return handle_av_tagmsg(conn, target, &tags2, av_tag, state);
                }
                let reply = Message::from_server(
                    &state.server_name,
                    "NOTICE",
                    vec![&nick, "No active session in this channel"],
                );
                send_to(state, &conn.id, format!("{reply}\r\n"));
                return;
            }

            // Per-device suffix: clients send a short random `av-instance`
            // tag so two devices on the same DID get separate participant
            // slots and distinct MoQ broadcast paths. Older clients omit
            // it; the manager falls back to one-slot-per-DID for them.
            let instance_id = tags.get("+freeq.at/av-instance").map(String::as_str);

            tracing::info!(
                session_id = %session_id,
                did = %did,
                nick = %nick,
                conn_id = %conn.id,
                instance_id = ?instance_id,
                "av-join: handler entry"
            );

            // Record THIS connection's instance BEFORE building the live-set
            // and reaping. The recording used to happen after join_session,
            // which opened a race: a second client av-joining a few ms later
            // built its live-set before we'd registered, didn't see us, and
            // reaped our just-created slot (observed live: two agents joining
            // ~5ms apart — the first vanished from the roster). Recording
            // up-front closes that window.
            if let Some(inst) = instance_id {
                state
                    .av_instances_per_conn
                    .lock()
                    .entry(conn.id.clone())
                    .or_default()
                    .insert(inst.to_string());
            }

            // Before joining: reap any orphan slots in this session whose
            // owning IRC connection is gone. Live-set is built from the
            // instances that current connections registered on their own
            // av-join. Without this, a refreshed/crashed tab leaves a
            // `left_at: None` ghost in the participants list and peers waste
            // subscriptions on a broadcast nobody publishes.
            let live: std::collections::HashSet<(String, Option<String>)> = {
                let per_conn = state.av_instances_per_conn.lock();
                let dids = state.session_dids.lock();
                per_conn
                    .iter()
                    .flat_map(|(sid, instances)| {
                        let did_for_sid = dids.get(sid).cloned();
                        let did_for_sid = did_for_sid.unwrap_or_default();
                        instances
                            .iter()
                            .map(move |inst| (did_for_sid.clone(), Some(inst.clone())))
                    })
                    // Always treat the joiner as live, even before we've
                    // recorded their instance.
                    .chain(std::iter::once((
                        did.clone(),
                        instance_id.map(|s| s.to_string()),
                    )))
                    .collect()
            };

            let grace_pending = state.av_grace_pending.lock().clone();
            // SFU handle taken BEFORE the av_sessions lock (single lock-order:
            // never acquire sfu_state while holding av_sessions).
            #[cfg(feature = "av-native")]
            let sfu_for_revoke = state.sfu_state.lock().clone();
            let mut mgr = state.av_sessions.lock();
            let reaped = mgr.reap_orphan_slots(&session_id, &live, &grace_pending);
            // Reaped roster slots lose their media too (F6): a ghost whose
            // slot just vanished must not keep streaming to announcement-
            // driven clients.
            #[cfg(feature = "av-native")]
            if let Some(sfu) = &sfu_for_revoke {
                for inst in &reaped {
                    sfu.revoke_media(inst);
                }
            }
            #[cfg(not(feature = "av-native"))]
            let _ = reaped;
            match mgr.join_session(&session_id, &did, &nick, instance_id) {
                Ok(session) => {
                    let participant_count = mgr.active_participant_count(&session_id);
                    let channel = session.channel.clone();

                    if let Some(s) = mgr.get(&session_id) {
                        state.with_db(|db| db.save_av_session(s));
                    }
                    drop(mgr);

                    // (Instance was recorded against this connection before
                    // the reap above, to close the concurrent-join race.)

                    // Send iroh-live RoomTicket to joiner (for native clients)
                    if let Some(ticket) = &session.iroh_ticket {
                        let ticket_notice = Message::from_server(
                            &state.server_name,
                            "NOTICE",
                            vec![&nick, &format!("AV ticket: {ticket}")],
                        );
                        send_to(state, &conn.id, format!("{ticket_notice}\r\n"));
                    }

                    // MoQ access token for the joiner (they dial the SFU next)
                    send_av_token(state, &conn.id, &nick, &session_id);

                    // Ensure bridge is running for this session.
                    // The bridge may have been cleaned up if the session creator disconnected
                    // while other participants remained (session stayed active but bridge was orphaned).
                    #[cfg(feature = "av-native")]
                    {
                        let has_bridge = state.av_bridges.lock().contains_key(&session_id);
                        if !has_bridge {
                            let backend = state.av_media.lock().clone();
                            if let Some(backend) = backend.as_ref() {
                                if let Some((room_handle, room_events)) =
                                    backend.take_room_for_bridge(&session_id)
                                {
                                    let sfu = state.sfu_state.lock().clone();
                                    if let Some(sfu) = sfu {
                                        let bridge = crate::av_bridge::start_bridge(
                                            session_id.clone(),
                                            sfu.cluster.clone(),
                                            sfu.auth.clone(),
                                            sfu.mint_session_token(&session_id),
                                            room_handle,
                                            room_events,
                                        );
                                        state.av_bridges.lock().insert(session_id.clone(), bridge);
                                        tracing::info!(session = %session_id, "MoQ↔Room bridge (re)started on join");
                                    }
                                }
                            }
                        }
                    }

                    // Broadcast updated state
                    broadcast_av_state(
                        state,
                        target,
                        &session_id,
                        "joined",
                        &nick,
                        instance_id.unwrap_or(""),
                        participant_count,
                        "",
                    );

                    // S2S
                    broadcast_av_s2s(
                        state,
                        "joined",
                        &session_id,
                        channel.as_deref(),
                        &did,
                        &nick,
                        None,
                        None,
                    );

                    tracing::info!(session_id = %session_id, did = %did, "AV session joined");
                }
                Err(e) => {
                    tracing::warn!(
                        session_id = %session_id,
                        did = %did,
                        nick = %nick,
                        instance_id = ?instance_id,
                        error = %e,
                        "av-join rejected by AvSessionManager"
                    );
                    let reply = Message::from_server(
                        &state.server_name,
                        "NOTICE",
                        vec![&nick, &format!("Cannot join session: {e}")],
                    );
                    send_to(state, &conn.id, format!("{reply}\r\n"));
                    // Machine-readable failure so clients can tear down the
                    // ghost call state (a NOTICE alone is invisible to code:
                    // macOS/web set up media & UI BEFORE the join round-trips,
                    // so an unsignalled failure leaves them publishing into a
                    // session they were never admitted to).
                    send_av_error(state, &conn.id, &nick, &session_id, "join-failed", &e);
                }
            }
        }

        "+freeq.at/av-leave" => {
            let instance_id = tags.get("+freeq.at/av-instance").map(String::as_str);
            // Untrack this instance against the connection so the disconnect
            // handler doesn't try to leave it a second time.
            if let Some(inst) = instance_id
                && let Some(set) = state.av_instances_per_conn.lock().get_mut(&conn.id)
            {
                set.remove(inst);
            }
            #[cfg(feature = "av-native")]
            let sfu_for_revoke = state.sfu_state.lock().clone();
            let mut mgr = state.av_sessions.lock();
            // If this leave ends the session, every remaining media conn must
            // die with it (F6) — snapshot instances before the state change.
            #[cfg(feature = "av-native")]
            let all_instances = mgr.active_instances(&session_id);
            match mgr.leave_session(&session_id, &did, instance_id) {
                Ok((session, should_end)) => {
                    let participant_count = if should_end {
                        0
                    } else {
                        mgr.active_participant_count(&session_id)
                    };
                    let channel = session.channel.clone();

                    if let Some(s) = mgr.get(&session_id) {
                        state.with_db(|db| db.save_av_session(s));
                    }
                    drop(mgr);

                    if should_end {
                        broadcast_av_state(state, target, &session_id, "ended", &nick, "", 0, "");
                        broadcast_av_s2s(
                            state,
                            "ended",
                            &session_id,
                            channel.as_deref(),
                            &did,
                            &nick,
                            None,
                            Some(&did),
                        );
                        // Close iroh-live room and bridge
                        #[cfg(feature = "av-native")]
                        {
                            state.av_bridges.lock().remove(&session_id);
                            if let Some(sfu) = &sfu_for_revoke {
                                for inst in &all_instances {
                                    sfu.revoke_media(inst);
                                }
                            }
                        }
                        let backend = state.av_media.lock().clone();
                        let sid = session_id.clone();
                        tokio::spawn(async move {
                            if let Some(backend) = backend.as_ref() {
                                let _ = crate::av_media::MediaBackend::close_room(
                                    backend.as_ref(),
                                    &sid,
                                )
                                .await;
                            }
                        });
                    } else {
                        broadcast_av_state(
                            state,
                            target,
                            &session_id,
                            "left",
                            &nick,
                            instance_id.unwrap_or(""),
                            participant_count,
                            "",
                        );
                        broadcast_av_s2s(
                            state,
                            "left",
                            &session_id,
                            channel.as_deref(),
                            &did,
                            &nick,
                            None,
                            None,
                        );
                    }

                    tracing::info!(session_id = %session_id, did = %did, ended = should_end, "AV session left");
                }
                Err(e) => {
                    let reply = Message::from_server(
                        &state.server_name,
                        "NOTICE",
                        vec![&nick, &format!("Cannot leave session: {e}")],
                    );
                    send_to(state, &conn.id, format!("{reply}\r\n"));
                }
            }
        }

        "+freeq.at/av-end" => {
            let mgr = state.av_sessions.lock();
            let can_end = mgr.can_end_session(&session_id, &did)
                || state.server_opers.lock().contains(&conn.id);
            // Also check if user is channel op
            let is_chan_op = if target.starts_with('#') || target.starts_with('&') {
                let channels = state.channels.lock();
                channels
                    .get(target)
                    .map(|ch| ch.ops.contains(&conn.id) || ch.did_ops.contains(&did))
                    .unwrap_or(false)
            } else {
                false
            };
            drop(mgr);

            if !can_end && !is_chan_op {
                let reply = Message::from_server(
                    &state.server_name,
                    "NOTICE",
                    vec![
                        &nick,
                        "Only the session host or channel ops can end a session",
                    ],
                );
                send_to(state, &conn.id, format!("{reply}\r\n"));
                return;
            }

            #[cfg(feature = "av-native")]
            let sfu_for_revoke = state.sfu_state.lock().clone();
            let mut mgr = state.av_sessions.lock();
            // Snapshot BEFORE end_session marks everyone left: an explicit
            // /av end must also close every participant's media conn (F6).
            #[cfg(feature = "av-native")]
            let all_instances = mgr.active_instances(&session_id);
            match mgr.end_session(&session_id, Some(&did)) {
                Ok(session) => {
                    let channel = session.channel.clone();
                    state.with_db(|db| db.save_av_session(&session));
                    drop(mgr);

                    #[cfg(feature = "av-native")]
                    if let Some(sfu) = &sfu_for_revoke {
                        for inst in &all_instances {
                            sfu.revoke_media(inst);
                        }
                    }
                    broadcast_av_state(state, target, &session_id, "ended", &nick, "", 0, "");
                    broadcast_av_s2s(
                        state,
                        "ended",
                        &session_id,
                        channel.as_deref(),
                        &did,
                        &nick,
                        None,
                        Some(&did),
                    );

                    // Close iroh-live room and bridge
                    {
                        #[cfg(feature = "av-native")]
                        {
                            state.av_bridges.lock().remove(&session_id);
                        }
                        let backend = state.av_media.lock().clone();
                        let sid = session_id.clone();
                        tokio::spawn(async move {
                            if let Some(backend) = backend.as_ref()
                                && let Err(e) = crate::av_media::MediaBackend::close_room(
                                    backend.as_ref(),
                                    &sid,
                                )
                                .await
                            {
                                tracing::warn!(session = %sid, error = %e, "Failed to close iroh-live room");
                            }
                        });
                    }

                    tracing::info!(session_id = %session_id, did = %did, "AV session ended");
                }
                Err(e) => {
                    drop(mgr);
                    let reply = Message::from_server(
                        &state.server_name,
                        "NOTICE",
                        vec![&nick, &format!("Cannot end session: {e}")],
                    );
                    send_to(state, &conn.id, format!("{reply}\r\n"));
                }
            }
        }

        _ => {
            tracing::debug!(tag = %av_tag, "Unknown AV tag — ignored");
        }
    }
}

/// Broadcast a plain NOTICE to all channel members (used for AV session events from S2S).
pub fn broadcast_av_notice(state: &Arc<SharedState>, channel: &str, text: &str) {
    let notice = Message::from_server(&state.server_name, "NOTICE", vec![channel, text]);
    let line = format!("{notice}\r\n");
    let members: Vec<String> = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();
    let conns = state.connections.lock();
    for member in &members {
        if let Some(tx) = conns.get(member) {
            let _ = tx.try_send(line.clone());
        }
    }
}

/// Broadcast AV session state to all channel members via TAGMSG (public for disconnect cleanup).
#[allow(clippy::too_many_arguments)]
pub fn broadcast_av_state_pub(
    state: &Arc<SharedState>,
    target: &str,
    session_id: &str,
    action: &str,
    actor_nick: &str,
    actor_instance: &str,
    participant_count: usize,
    title: &str,
) {
    broadcast_av_state(
        state,
        target,
        session_id,
        action,
        actor_nick,
        actor_instance,
        participant_count,
        title,
    );
}

/// Send the joiner their MoQ access token for a session as a directed
/// TAGMSG (`+freeq.at/av-token` + `+freeq.at/av-id`). Clients append it to
/// the SFU dial URL as `?jwt=…`; the same token is available via
/// `GET /api/v1/av/sessions/{id}/token`. JWTs are base64url+dots so the
/// value needs no IRC tag-escaping.
#[cfg(feature = "av-native")]
fn send_av_token(state: &Arc<SharedState>, conn_id: &str, nick: &str, session_id: &str) {
    let sfu = state.sfu_state.lock().clone();
    let Some(token) = sfu.and_then(|sfu| sfu.mint_session_token(session_id)) else {
        return;
    };
    let mut tags = std::collections::HashMap::new();
    tags.insert("+freeq.at/av-token".to_string(), token);
    tags.insert("+freeq.at/av-id".to_string(), session_id.to_string());
    let tag_msg = super::super::irc::Message {
        tags,
        prefix: Some(state.server_name.clone()),
        command: "TAGMSG".to_string(),
        params: vec![nick.to_string()],
    };
    send_to(state, conn_id, format!("{tag_msg}\r\n"));
}

#[cfg(not(feature = "av-native"))]
fn send_av_token(_state: &Arc<SharedState>, _conn_id: &str, _nick: &str, _session_id: &str) {}

/// Machine-readable AV failure signal: `@+freeq.at/av-error=<code>;
/// +freeq.at/av-id=<sid>;+freeq.at/av-reason=<human> TAGMSG <nick>`.
/// Codes: `join-failed` (av-join rejected — tear down local call state and
/// re-discover), `start-collision` (av-start lost a race — av-id names the
/// winning session to join). The NOTICE next to it is for humans; this tag
/// is for code. Sent to the requesting connection only.
fn send_av_error(
    state: &Arc<SharedState>,
    conn_id: &str,
    nick: &str,
    session_id: &str,
    code: &str,
    reason: &str,
) {
    let mut tags = std::collections::HashMap::new();
    tags.insert("+freeq.at/av-error".to_string(), code.to_string());
    if !session_id.is_empty() {
        tags.insert("+freeq.at/av-id".to_string(), session_id.to_string());
    }
    tags.insert("+freeq.at/av-reason".to_string(), reason.to_string());
    let tag_msg = super::super::irc::Message {
        tags,
        prefix: Some(state.server_name.clone()),
        command: "TAGMSG".to_string(),
        params: vec![nick.to_string()],
    };
    send_to(state, conn_id, format!("{tag_msg}\r\n"));
}

/// Build the message tags for an AV state TAGMSG (everything but the
/// nondeterministic `time` tag). Pure + unit-testable.
///
/// `actor_instance` is the actor's per-device instance. It's the stable
/// identity clients key presence on: `av-actor` (nick) can differ between the
/// media path and this signal for multi-nick accounts, but the instance
/// matches the media broadcast path `{session}/{nick}~{instance}`, so a `left`
/// here reliably clears the right tile. Empty for legacy clients (tag omitted).
fn av_state_tag_map(
    action: &str,
    session_id: &str,
    actor_nick: &str,
    actor_instance: &str,
    participant_count: usize,
    title: &str,
) -> std::collections::HashMap<String, String> {
    let mut tags = std::collections::HashMap::new();
    tags.insert("+freeq.at/av-state".to_string(), action.to_string());
    tags.insert("+freeq.at/av-id".to_string(), session_id.to_string());
    tags.insert(
        "+freeq.at/av-participants".to_string(),
        participant_count.to_string(),
    );
    tags.insert("+freeq.at/av-actor".to_string(), actor_nick.to_string());
    if !actor_instance.is_empty() {
        tags.insert(
            "+freeq.at/av-instance".to_string(),
            actor_instance.to_string(),
        );
    }
    if !title.is_empty() {
        tags.insert("+freeq.at/av-title".to_string(), title.to_string());
    }
    tags
}

/// Broadcast AV session state to all channel members via TAGMSG.
#[allow(clippy::too_many_arguments)]
fn broadcast_av_state(
    state: &Arc<SharedState>,
    target: &str,
    session_id: &str,
    action: &str,
    actor_nick: &str,
    actor_instance: &str,
    participant_count: usize,
    title: &str,
) {
    let mut tags = av_state_tag_map(
        action,
        session_id,
        actor_nick,
        actor_instance,
        participant_count,
        title,
    );
    let time_tag = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string();
    tags.insert("time".to_string(), time_tag);

    let tag_msg = super::super::irc::Message {
        tags,
        prefix: Some(state.server_name.clone()),
        command: "TAGMSG".to_string(),
        params: vec![target.to_string()],
    };
    let line = format!("{tag_msg}\r\n");

    // Also send a human-readable NOTICE for clients that don't parse tags
    let notice_text = match action {
        "started" => format!(
            "{actor_nick} started a voice session{}",
            if title.is_empty() {
                String::new()
            } else {
                format!(": {title}")
            }
        ),
        "joined" => {
            format!("{actor_nick} joined the voice session ({participant_count} participants)")
        }
        "left" => format!("{actor_nick} left the voice session ({participant_count} participants)"),
        "ended" => format!("{actor_nick} ended the voice session"),
        _ => return,
    };
    let notice = Message::from_server(&state.server_name, "NOTICE", vec![target, &notice_text]);
    let notice_line = format!("{notice}\r\n");

    // Broadcast to channel members
    if target.starts_with('#') || target.starts_with('&') {
        let members: Vec<String> = state
            .channels
            .lock()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock();
        let conns = state.connections.lock();
        for member in &members {
            if let Some(tx) = conns.get(member) {
                if tag_caps.contains(member) {
                    let _ = tx.try_send(line.clone());
                } else {
                    let _ = tx.try_send(notice_line.clone());
                }
            }
        }
    }
}

/// Broadcast AV session event via S2S federation.
fn broadcast_av_s2s(
    state: &Arc<SharedState>,
    action: &str,
    session_id: &str,
    channel: Option<&str>,
    did: &str,
    nick: &str,
    title: Option<&str>,
    ended_by: Option<&str>,
) {
    let s2s = state.s2s_manager.lock();
    let Some(ref mgr) = *s2s else { return };

    let event_id = mgr.next_event_id();
    let origin = mgr.server_id.clone();

    let msg = match action {
        "created" => crate::s2s::S2sMessage::AvSessionCreated {
            event_id,
            session_id: session_id.to_string(),
            channel: channel.unwrap_or("").to_string(),
            created_by_did: did.to_string(),
            created_by_nick: nick.to_string(),
            title: title.map(|s| s.to_string()),
            iroh_ticket: None, // TODO: add when iroh-live is integrated
            origin,
        },
        "joined" => crate::s2s::S2sMessage::AvSessionJoined {
            event_id,
            session_id: session_id.to_string(),
            did: did.to_string(),
            nick: nick.to_string(),
            origin,
        },
        "left" => crate::s2s::S2sMessage::AvSessionLeft {
            event_id,
            session_id: session_id.to_string(),
            did: did.to_string(),
            origin,
        },
        "ended" => crate::s2s::S2sMessage::AvSessionEnded {
            event_id,
            session_id: session_id.to_string(),
            ended_by: ended_by.map(|s| s.to_string()),
            origin,
        },
        _ => return,
    };

    mgr.broadcast(msg);
}

#[cfg(test)]
mod av_dispatch_tests {
    //! State matrix cell #16: multiple av-* tags on one TAGMSG must
    //! dispatch on the *action* tag, not whichever parameter tag HashMap
    //! iteration happens to return first. Pre-fix (commit 8b13ccd) the
    //! code did `tags.keys().find(|k| k.starts_with("+freeq.at/av-"))`,
    //! which was non-deterministic. Now we have an explicit AV_ACTIONS
    //! list and dispatch on the first matching action tag. This test
    //! pins the order so a future "be helpful and reorder" refactor
    //! doesn't accidentally re-introduce the bug.
    use std::collections::HashMap;

    /// Mirrors the dispatch order in `process_tagmsg`. Keep in sync.
    const AV_ACTIONS: &[&str] = &[
        "+freeq.at/av-start",
        "+freeq.at/av-join",
        "+freeq.at/av-leave",
        "+freeq.at/av-end",
    ];

    fn dispatch(tags: &HashMap<String, String>) -> Option<&'static &'static str> {
        AV_ACTIONS.iter().find(|tag| tags.contains_key(**tag))
    }

    #[test]
    fn av_join_with_id_and_instance_dispatches_to_join() {
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/av-join".into(), String::new());
        tags.insert("+freeq.at/av-id".into(), "sess-1".into());
        tags.insert("+freeq.at/av-instance".into(), "abcd1234".into());
        assert_eq!(dispatch(&tags), Some(&"+freeq.at/av-join"));
    }

    #[test]
    fn av_start_with_title_and_instance_dispatches_to_start() {
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/av-start".into(), String::new());
        tags.insert("+freeq.at/av-title".into(), "standup".into());
        tags.insert("+freeq.at/av-instance".into(), "abcd1234".into());
        assert_eq!(dispatch(&tags), Some(&"+freeq.at/av-start"));
    }

    #[test]
    fn av_leave_with_id_dispatches_to_leave() {
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/av-leave".into(), String::new());
        tags.insert("+freeq.at/av-id".into(), "sess-1".into());
        assert_eq!(dispatch(&tags), Some(&"+freeq.at/av-leave"));
    }

    #[test]
    fn av_id_alone_with_no_action_does_not_dispatch() {
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/av-id".into(), "sess-1".into());
        tags.insert("+freeq.at/av-instance".into(), "abcd1234".into());
        assert_eq!(
            dispatch(&tags),
            None,
            "parameter-only TAGMSG must not be treated as an action"
        );
    }

    #[test]
    fn av_signal_is_not_an_action() {
        // av-signal is a relay tag (WebRTC payload) — must NOT be
        // consumed as an action.
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/av-signal".into(), "payload".into());
        assert_eq!(dispatch(&tags), None);
    }

    #[test]
    fn priority_order_start_then_join_then_leave_then_end() {
        // The order matters: if a (malformed) message had multiple action
        // tags, we must dispatch deterministically. Tests pin the order.
        let mut both = HashMap::new();
        both.insert("+freeq.at/av-start".into(), String::new());
        both.insert("+freeq.at/av-join".into(), String::new());
        assert_eq!(
            dispatch(&both),
            Some(&"+freeq.at/av-start"),
            "av-start wins over av-join when both are present"
        );

        let mut both = HashMap::new();
        both.insert("+freeq.at/av-join".into(), String::new());
        both.insert("+freeq.at/av-leave".into(), String::new());
        assert_eq!(dispatch(&both), Some(&"+freeq.at/av-join"));

        let mut both = HashMap::new();
        both.insert("+freeq.at/av-leave".into(), String::new());
        both.insert("+freeq.at/av-end".into(), String::new());
        assert_eq!(dispatch(&both), Some(&"+freeq.at/av-leave"));
    }
}

#[cfg(test)]
mod av_state_tag_tests {
    //! Presence signals must carry the actor's per-device `instance` so
    //! clients key teardown on the stable id (matches the media path
    //! `{session}/{nick}~{instance}`), not the nick — which can differ
    //! between the media path and this signal for multi-nick accounts and
    //! leave a ghost tile on disconnect.
    use super::av_state_tag_map;

    #[test]
    fn left_signal_carries_actor_instance() {
        let tags = av_state_tag_map("left", "sess-1", "chadfowler.com", "devABCD", 1, "");
        assert_eq!(
            tags.get("+freeq.at/av-instance").map(String::as_str),
            Some("devABCD"),
            "a `left` must name the exact device that dropped"
        );
        assert_eq!(
            tags.get("+freeq.at/av-actor").map(String::as_str),
            Some("chadfowler.com")
        );
        assert_eq!(
            tags.get("+freeq.at/av-state").map(String::as_str),
            Some("left")
        );
    }

    #[test]
    fn joined_and_started_carry_instance() {
        for action in ["joined", "started"] {
            let tags = av_state_tag_map(action, "s", "nick", "inst9", 2, "");
            assert_eq!(
                tags.get("+freeq.at/av-instance").map(String::as_str),
                Some("inst9"),
                "{action} must carry the instance"
            );
        }
    }

    #[test]
    fn legacy_empty_instance_omits_the_tag() {
        // Older clients don't send an instance; the tag must be absent (not
        // an empty string) so receivers cleanly fall back to nick matching.
        let tags = av_state_tag_map("left", "s", "nick", "", 0, "");
        assert!(
            !tags.contains_key("+freeq.at/av-instance"),
            "empty instance must omit the tag entirely"
        );
    }

    #[test]
    fn instance_does_not_leak_into_unrelated_tags() {
        let tags = av_state_tag_map("started", "s", "nick", "inst9", 1, "standup");
        assert_eq!(
            tags.get("+freeq.at/av-title").map(String::as_str),
            Some("standup")
        );
        assert_eq!(
            tags.get("+freeq.at/av-participants").map(String::as_str),
            Some("1")
        );
    }
}

#[cfg(test)]
mod dm_fallback_tests {
    //! The global msgid fallback in `find_original_message` is the only path
    //! that can resolve a row outside the addressed target. These pin the rule
    //! that keeps it from mutating something the caller never addressed.
    use super::dm_fallback_row_is_addressable;

    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";

    #[test]
    fn channel_rows_are_never_addressable_from_a_dm() {
        // The regression: a delete addressed to a DM soft-deleted a CHANNEL row
        // in the DB while the channel kept serving it from memory.
        assert!(!dm_fallback_row_is_addressable("#freeq", Some(ALICE)));
        assert!(!dm_fallback_row_is_addressable("&local", Some(ALICE)));
    }

    #[test]
    fn own_dm_thread_is_addressable() {
        // The legitimate use: the canonical key couldn't be derived (partner
        // offline, so nick→DID failed) but the row is genuinely ours.
        let key = format!("dm:{ALICE},{BOB}");
        assert!(dm_fallback_row_is_addressable(&key, Some(ALICE)));
        assert!(dm_fallback_row_is_addressable(&key, Some(BOB)));
    }

    #[test]
    fn other_peoples_dm_threads_are_not_addressable() {
        let key = format!("dm:{BOB},did:plc:carol");
        assert!(!dm_fallback_row_is_addressable(&key, Some(ALICE)));
    }

    #[test]
    fn unauthenticated_callers_get_nothing_from_the_fallback() {
        // Guests can't prove participation. Their DM threads aren't persisted,
        // so refusing here costs nothing.
        let key = format!("dm:{ALICE},{BOB}");
        assert!(!dm_fallback_row_is_addressable(&key, None));
        assert!(!dm_fallback_row_is_addressable("#freeq", None));
    }

    #[test]
    fn did_must_match_a_whole_participant_not_a_prefix() {
        // `dm:` keys are comma-joined, so a substring match would let
        // did:plc:alice reach did:plc:alice2's threads.
        let key = "dm:did:plc:alice2,did:plc:bob";
        assert!(!dm_fallback_row_is_addressable(key, Some(ALICE)));
    }
}
