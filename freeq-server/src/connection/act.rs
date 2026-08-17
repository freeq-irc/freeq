//! Task messages: recognizing them, and refusing the ones that are not right.
//!
//! A message carrying `act-` tags is a task event. It is accepted only from a
//! logged-in sender whose signature checks out over the document the signer
//! built — the act tags, the venue, and the id it minted — and only for a kind
//! and a verb `spec/act-transitions.json` lists. Every other outcome is a
//! refusal that names its cause.
//!
//! Nothing here stores anything. An accepted task message is delivered to the
//! connections that asked for `freeq.at/act` and relayed to peers with its tag
//! map intact; where it goes on disk is a later concern.
//!
//! Only the sender ever writes `act-` tags. The signature covers every one of
//! them, so a tag this server added under that prefix would land inside the
//! coverage and break the signature it was checking. Nothing in this module
//! writes one.

use std::collections::HashMap;
use std::sync::Arc;

use super::Connection;
use crate::irc::Message;
use crate::server::SharedState;

/// The tag naming the task kind, and the prefix every covered tag shares.
const KIND_TAG: &str = "+freeq.at/act";
const KIND_TAG_BARE: &str = "freeq.at/act";
const VERB_TAG: &str = "+freeq.at/act-verb";
const VERB_TAG_BARE: &str = "act-verb";

/// What the gate concluded about a message.
pub(super) enum Gate {
    /// No act tags: not a task message, and none of this applies.
    NotATaskMessage,
    /// A task message that passed every check.
    Accepted,
    /// Refused. The `FAIL` has already been sent.
    Refused,
}

/// Whether any tag on this message is one the act canonical covers.
///
/// The same rule the signer used, so what is recognized here is exactly what
/// gets signed: a name that is `act` or starts with `act-`, under either
/// spelling of the vendor prefix.
///
/// Reachable from the S2S receive path too: a task message relayed from a peer
/// is gated on the capability exactly as a local one is, though this server
/// neither verifies nor stores it until federation lands.
pub(crate) fn carries_act_tags(tags: &HashMap<String, String>) -> bool {
    tags.keys().any(|name| is_act_tag(name))
}

fn is_act_tag(name: &str) -> bool {
    let stripped = name
        .strip_prefix("+freeq.at/")
        .or_else(|| name.strip_prefix("freeq.at/"))
        .unwrap_or(name);
    stripped == "act" || stripped.starts_with("act-")
}

/// The tags of other families that must never share a message with act tags.
///
/// One signature tag cannot sign two documents: a delete, a reaction and a
/// coordination event each have their own canonical, and a message carrying
/// both kinds of field would have to be judged by two of them at once. The
/// AV tags are here for a second reason as well — they are consumed rather
/// than relayed, so a task message carrying one would be eaten on the way
/// through.
fn foreign_family_tag(tags: &HashMap<String, String>) -> Option<&str> {
    const MUTATION: [&str; 7] = [
        "+draft/delete",
        "+delete",
        "+react",
        "+draft/react",
        "+freeq.at/unreact",
        "+reply",
        "+draft/reply",
    ];
    // The stopgap coordination family, which carries its own signed document.
    const COORDINATION: [&str; 5] = [
        "+freeq.at/event",
        "+freeq.at/payload",
        "+freeq.at/task-id",
        "+freeq.at/ref",
        "+freeq.at/evidence-type",
    ];
    for name in MUTATION.iter().chain(COORDINATION.iter()) {
        if tags.contains_key(*name) {
            return Some(name);
        }
    }
    tags.keys()
        .find(|name| name.starts_with("+freeq.at/av-"))
        .map(String::as_str)
}

/// Tell the sender why, in the words the copy sheet settled on.
///
/// `command` is the word the client sent, so the scope of an unprefixed code
/// reads off the reply the way IRCv3 intends.
pub(super) fn refuse(
    conn: &Connection,
    command: &str,
    code: &str,
    sentence: &str,
    state: &Arc<SharedState>,
) {
    let reply = Message::from_server(&state.server_name, "FAIL", vec![command, code, sentence]);
    if let Some(tx) = state.connections.lock().get(&conn.id) {
        let _ = tx.try_send(format!("{reply}\r\n"));
    }
}

/// The one refusal a task message can earn on a command that carries a body.
///
/// A body is a chat document; act tags are a task document. The PRIVMSG path
/// calls this so the two never travel together.
pub(super) fn refuse_body_with_act_tags(
    conn: &Connection,
    command: &str,
    state: &Arc<SharedState>,
) {
    tracing::debug!(
        session = %conn.id, command = %command,
        "Refused a message carrying act tags alongside a body"
    );
    refuse(
        conn,
        command,
        "MIXED_TAGS",
        "A task message carries only task tags",
        state,
    );
}

/// Expire one abandoned task: sign the event, run it through the same check
/// and storage every other event goes through, and announce it.
///
/// The sweep has no client connection, which is why this is separate from the
/// gate above — but it is not a separate path. The event is built the way a
/// sender would build it, signed with this server's own key under its own
/// identity, and applied through `apply_act_event` like anything else, so it
/// lands in the log, the view and replay identically.
///
/// Returns whether the task was expired.
pub(crate) fn expire_task(state: &Arc<SharedState>, task: &crate::db::ActTask) -> bool {
    let did = crate::server::server_did(&state.server_name);
    let event_id = freeq_sdk::chatsig::new_event_id();
    let tags = vec![
        ("+freeq.at/act", task.kind.as_str()),
        ("+freeq.at/act-verb", "expire"),
        ("+freeq.at/act-from", did.as_str()),
        ("+freeq.at/act-id", task.act_id.as_str()),
    ];
    let Some(canonical) = freeq_sdk::act::act_canonical(tags, &task.venue, &event_id) else {
        return false;
    };
    let signature = freeq_sdk::sigtag::sign_canonical(&canonical, &state.msg_signing_key);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let written = state.with_db(|db| {
        db.apply_act_event(&crate::db::ActEvent {
            canonical: &canonical,
            signature: Some(&signature),
            event_id: &event_id,
            act_id: &task.act_id,
            opens: false,
            venue: &task.venue,
            actor: &did,
            // Only the server may expire, and this is the server.
            from_system: true,
            origin: None,
            timestamp: now,
        })
    });
    match written {
        Some(crate::db::ActWrite::Filed { .. }) => {}
        other => {
            tracing::warn!(
                act_id = %task.act_id, venue = %task.venue, outcome = ?other,
                "Expiry sweep could not file its own event"
            );
            return false;
        }
    }
    crate::server::Metrics::bump(&state.metrics.act_expired_total);

    // The event is the record; this is the human's notice that it happened.
    // A NOTICE and not a message, because the server does not author message
    // rows into history — so scrollback will not show the ending until
    // clients render task events themselves.
    let title = state
        .with_db(|db| db.act_task_title(&task.act_id))
        .flatten()
        .unwrap_or_else(|| task.act_id.clone());
    announce_expiry(state, task, &title);
    tracing::info!(
        act_id = %task.act_id, venue = %task.venue, state = %task.state,
        "Expired an abandoned task"
    );
    true
}

/// A title is text its sender chose, and this notice is built as a wire line
/// rather than through `Message`, which escapes tag values on the way out. So
/// the bytes that end a line — and every other control byte — come out here,
/// and the length is capped: otherwise a title could append lines of its own
/// choosing to everyone in the room, spoken by the server.
///
/// Removed, not replaced: the title is a label, and a hole in a label reads
/// better than a row of placeholders.
fn title_for_wire(title: &str) -> String {
    title
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TITLE_CHARS)
        .collect()
}

/// Long enough for any real task name, short enough that no notice is a wall.
const MAX_TITLE_CHARS: usize = 200;

/// Tell the room — or the two people in the conversation — that a task ended
/// without finishing.
fn announce_expiry(state: &Arc<SharedState>, task: &crate::db::ActTask, title: &str) {
    // A title of nothing but stripped bytes would announce a task by no name at
    // all, so it falls back the same way a missing title does.
    let cleaned = title_for_wire(title);
    let shown = match cleaned.trim().is_empty() {
        true => task.act_id.as_str(),
        false => cleaned.as_str(),
    };
    let text = format!("Task expired without completion: {shown}");
    let sessions: Vec<String> = match task.venue.strip_prefix("dm:") {
        // A DM task belongs to two people and nobody else hears about it.
        Some(pair) => {
            let dids: Vec<&str> = pair.split(',').collect();
            let by_did = state.did_sessions.lock();
            dids.iter()
                .filter_map(|d| by_did.get(*d))
                .flat_map(|s| s.iter().cloned())
                .collect()
        }
        None => state
            .channels
            .lock()
            .get(&task.venue)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default(),
    };
    let target = match task.venue.starts_with("dm:") {
        true => None,
        false => Some(task.venue.as_str()),
    };
    let conns = state.connections.lock();
    for sid in &sessions {
        if let Some(tx) = conns.get(sid) {
            // A DM notice is addressed to the reader; a channel notice to the
            // channel, so a client files it where the conversation is.
            let to = target.unwrap_or("*");
            let _ = tx.try_send(format!(":{} NOTICE {to} :{text}\r\n", state.server_name));
        }
    }
}

/// The wire lines for a venue's stored task events, each with its timestamp so
/// a caller can interleave them with message history in time order.
///
/// Empty for a connection that did not ask for `freeq.at/act` — replay is
/// gated exactly as live delivery is, so a client that cannot render a task
/// card is not sent one it never asked for.
///
/// Each line is rebuilt from the stored canonical: the document's keys are the
/// act tag names with the vendor prefix stripped, so re-prefixing them
/// reproduces the tags the sender put on the wire, and the signature that
/// travels alongside verifies against the very bytes the row holds.
pub(super) fn replay_lines(
    state: &Arc<SharedState>,
    session_id: &str,
    venue: &str,
    target: &str,
    from_ts: i64,
    to_ts: i64,
    limit: usize,
    with_time: bool,
    batch_id: Option<&str>,
) -> Vec<(i64, String)> {
    if !state.cap_act.lock().contains(session_id) {
        return Vec::new();
    }
    let events = state
        .with_db(|db| db.act_events_for_venue(venue, from_ts, to_ts, limit))
        .unwrap_or_default();

    events
        .into_iter()
        .filter_map(|ev| {
            let doc: serde_json::Value = serde_json::from_str(&ev.canonical).ok()?;
            let fields = doc.as_object()?;
            let mut tags: HashMap<String, String> = HashMap::new();
            for (key, value) in fields {
                // `target` and `msgid` are the two the caller injected; they
                // ride as the message's own target and id, not as act tags.
                if key == "target" || key == "msgid" {
                    continue;
                }
                tags.insert(format!("+freeq.at/{key}"), value.as_str()?.to_string());
            }
            tags.insert(
                freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                ev.event_id.clone(),
            );
            tags.insert("msgid".to_string(), ev.event_id.clone());
            if let Some(ref sig) = ev.signature {
                tags.insert("+freeq.at/sig".to_string(), sig.clone());
            }
            if let Some(ref did) = ev.actor_did {
                tags.insert("account".to_string(), did.clone());
            }
            if with_time {
                tags.insert(
                    "time".to_string(),
                    chrono::DateTime::from_timestamp(ev.timestamp, 0)
                        .unwrap_or_default()
                        .format("%Y-%m-%dT%H:%M:%S.000Z")
                        .to_string(),
                );
            }
            if let Some(batch) = batch_id {
                tags.insert("batch".to_string(), batch.to_string());
            }
            // The nick the actor holds now, when this server knows one — a
            // replayed event carries no hostmask of its own, and the identity
            // that matters rides the account tag either way.
            let prefix = ev.actor_did.as_ref().map(|did| {
                state
                    .did_nicks
                    .lock()
                    .get(did)
                    .cloned()
                    .unwrap_or_else(|| did.clone())
            });
            let line = Message {
                tags,
                prefix,
                command: "TAGMSG".to_string(),
                params: vec![target.to_string()],
            };
            Some((ev.timestamp, format!("{line}\r\n")))
        })
        .collect()
}

/// Refuse a mutation aimed at a task event, and say so.
///
/// Returns whether the caller should stop. Task events are immutable: the
/// lifecycle is the only way a task changes, and a later event supersedes an
/// earlier one — the log and the view never un-apply anything. The plain-text
/// companion line a bot posts alongside is an ordinary message and stays
/// deletable; it is a rendering of the event, not the event.
///
/// `command` is the word the client sent, so a delete hears DELETE and an edit
/// hears EDIT.
pub(super) fn refuse_if_task_event(
    conn: &Connection,
    command: &str,
    subject: &str,
    state: &Arc<SharedState>,
) -> bool {
    if state.with_db(|db| db.is_act_event(subject)) != Some(true) {
        return false;
    }
    tracing::debug!(
        session = %conn.id, command = %command, subject = %subject,
        "Refused a mutation aimed at a task event"
    );
    refuse(
        conn,
        command,
        "IMMUTABLE_EVENT",
        "Task history cannot be changed or deleted",
        state,
    );
    true
}

/// Check a task message, in the order the plan sets: what the message is,
/// then who sent it, then whether the signature holds, then whether the rules
/// file knows the move.
///
/// `target` is already normalized — the venue the signature covers is built
/// from it, so it has to be the same string persistence and relay use.
pub(super) fn gate(
    conn: &Connection,
    target: &str,
    tags: &HashMap<String, String>,
    state: &Arc<SharedState>,
) -> Gate {
    if !carries_act_tags(tags) {
        return Gate::NotATaskMessage;
    }

    // ── One message, one job ──
    if let Some(foreign) = foreign_family_tag(tags) {
        tracing::debug!(
            session = %conn.id, target = %target, tag = %foreign,
            "Refused a task message that also carries another family's tags"
        );
        refuse(
            conn,
            "TAGMSG",
            "MIXED_TAGS",
            "A task message carries only task tags",
            state,
        );
        return Gate::Refused;
    }

    // ── Who sent it ──
    //
    // A guest has no durable identity and no key registered under one, so
    // there is no signature it could send that would mean anything.
    let Some(did) = conn.authenticated_did.as_deref() else {
        refuse(
            conn,
            "TAGMSG",
            "ACCOUNT_REQUIRED",
            "Only a logged-in sender can send task messages",
            state,
        );
        return Gate::Refused;
    };

    // ── Flood ──
    //
    // The same counter the stopgap family uses, deliberately: two budgets
    // would let one connection send twice as much by alternating families.
    if super::messaging::event_flood_exceeded(conn, state) {
        tracing::warn!(
            actor = %did, nick = %conn.nick_or_star(),
            "Rate-limited task-message flood"
        );
        return Gate::Refused;
    }

    // ── The id the signature covers ──
    //
    // Demanded before the signature is checked, because the signature covers
    // the id: with none on the wire there is no document to rebuild, and
    // saying "your signature is wrong" about a document the sender never
    // built would send them after the wrong problem.
    if !tags.contains_key(freeq_sdk::chatsig::EVENT_ID_TAG)
        && !tags.contains_key(freeq_sdk::chatsig::EVENT_ID_TAG_BARE)
    {
        tracing::debug!(
            session = %conn.id, did = %did, target = %target,
            "Refused a task message that carries no event id"
        );
        refuse(
            conn,
            "TAGMSG",
            "EVENTID_REQUIRED",
            "A task message must carry its sender's event id",
            state,
        );
        return Gate::Refused;
    }
    // Adopted through the same checks every signed event's id passes: well
    // formed, near our clock, not already taken, and only from an
    // authenticated sender.
    let msgid = match super::messaging::resolve_event_msgid(conn, tags, state) {
        Ok(id) => id,
        Err((code, description)) => {
            refuse(conn, "TAGMSG", code, &description, state);
            return Gate::Refused;
        }
    };

    // ── The actor it names ──
    //
    // Two words that are never interchangeable: the *author* of a message is
    // whoever wrote it; the *actor* of an event is whoever performed it. One
    // event can hold both as different people — an op deleting someone's
    // message is the actor, the person who wrote it is the author — which is
    // why the edit and delete paths answer with AUTHOR_MISMATCH and a task
    // step answers with ACTOR_MISMATCH.
    //
    // The signature establishes who sent the message; `act-from` claims who
    // acted, and the two have to be the same person. Checked before the
    // signature because both answers are decidable without one, and either is
    // more useful than a signature complaint.
    let Some(actor) = tags
        .get("+freeq.at/act-from")
        .or_else(|| tags.get("act-from"))
    else {
        // Naming nobody is its own answer. The log refuses such bytes as
        // unreadable — the view's offerer comes from this field — so without
        // a sentence here the event would vanish with nothing said about it.
        tracing::debug!(
            session = %conn.id, did = %did, target = %target,
            "Refused a task message that names no actor"
        );
        refuse(
            conn,
            "TAGMSG",
            "ACTOR_REQUIRED",
            "A task message must name its actor",
            state,
        );
        return Gate::Refused;
    };
    if actor != did {
        tracing::warn!(
            session = %conn.id, did = %did, actor = %actor, target = %target,
            "Refused a task message naming another actor than its sender"
        );
        refuse(
            conn,
            "TAGMSG",
            "ACTOR_MISMATCH",
            "That message names someone else as its actor",
            state,
        );
        return Gate::Refused;
    }

    // ── The signature ──
    let Some(sig_tag) = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))
    else {
        refuse(
            conn,
            "TAGMSG",
            "SIGNATURE_REQUIRED",
            "A task message must carry its sender's signature",
            state,
        );
        return Gate::Refused;
    };

    // The venue, worked out the way the signer worked it out: a channel
    // folded, a DM as the sorted DID pair. A DM whose other end has no DID has
    // no venue any verifier could rebuild, so no task message can ever be
    // signed there — which is a fact about the conversation, not about this
    // signature.
    let Some(venue) = super::messaging::signing_venue(state, did, target) else {
        tracing::debug!(
            session = %conn.id, did = %did, target = %target,
            "No venue for a task message — the conversation cannot carry tasks"
        );
        refuse(
            conn,
            "TAGMSG",
            "INVALID_TARGET",
            "A task in a direct conversation needs both people to have accounts",
            state,
        );
        return Gate::Refused;
    };

    let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    match super::messaging::verify_act_signature(
        pairs, &venue, &msgid, sig_tag, did, &conn.id, state,
    ) {
        super::messaging::ClientSigOutcome::Verified => {}
        super::messaging::ClientSigOutcome::Failed => {
            tracing::warn!(
                session = %conn.id, did = %did, target = %target, msgid = %msgid,
                "Task-message signature did not verify against the key it names — \
                 refusing the event"
            );
            refuse(
                conn,
                "TAGMSG",
                "SIGNATURE_INVALID",
                "That signature does not verify against the key it names",
                state,
            );
            return Gate::Refused;
        }
        // Only one thing makes a signature *temporarily* uncheckable: we do
        // not hold the key it names, and a later fetch could change that. On
        // one server it should not happen at all — a local signer's key is in
        // the local store — but it is the real case once peers are in the
        // picture, so it answers distinctly rather than as a forgery.
        super::messaging::ClientSigOutcome::Unverifiable(why)
            if why == super::messaging::NO_KEY_ON_FILE =>
        {
            tracing::warn!(
                session = %conn.id, did = %did, target = %target,
                "Task-message signature names a key this server does not hold — \
                 refusing the event"
            );
            refuse(
                conn,
                "TAGMSG",
                "SIGNATURE_UNVERIFIABLE",
                "That signature names a key this server does not have",
                state,
            );
            return Gate::Refused;
        }
        // Anything else uncheckable is malformed rather than pending: a tag
        // that is not `alg:kid:sig` names no key, so no lookup will ever make
        // it verify. It does not check out against the key it names, and
        // saying so is true of it.
        super::messaging::ClientSigOutcome::Unverifiable(why) => {
            tracing::warn!(
                session = %conn.id, did = %did, target = %target, why = %why,
                "Task-message signature is malformed — refusing the event"
            );
            refuse(
                conn,
                "TAGMSG",
                "SIGNATURE_INVALID",
                "That signature does not verify against the key it names",
                state,
            );
            return Gate::Refused;
        }
    }

    // ── The rules file ──
    //
    // A kind or a verb nobody wrote down is refused rather than relayed
    // unrefereed: an event this server cannot referee has no business in the
    // same stream as the ones it can.
    let kind = tags
        .get(KIND_TAG)
        .or_else(|| tags.get(KIND_TAG_BARE))
        .map(String::as_str)
        .unwrap_or("");
    if !freeq_sdk::act_transitions::knows_kind(kind) {
        tracing::debug!(
            session = %conn.id, did = %did, kind = %kind,
            "Refused a task message naming a kind the rules file does not list"
        );
        refuse(
            conn,
            "TAGMSG",
            "UNKNOWN_KIND",
            "This server does not know that task kind",
            state,
        );
        return Gate::Refused;
    }
    let verb = tags
        .get(VERB_TAG)
        .or_else(|| tags.get(VERB_TAG_BARE))
        .map(String::as_str)
        .unwrap_or("");

    // Opening a task and moving one are different questions. The opener is
    // the only move that can be judged in full here: it needs no prior state,
    // because there is no prior task. For everything else this step can only
    // ask whether the kind has the verb at all — what a task's own state
    // allows is what storage makes answerable.
    if freeq_sdk::act_transitions::opening_verb(kind) == Some(verb) {
        let directed = tags.contains_key("+freeq.at/act-to") || tags.contains_key("act-to");
        let names_task = tags.contains_key("+freeq.at/act-id") || tags.contains_key("act-id");
        if let Err(refusal) =
            freeq_sdk::act_transitions::check_open(kind, verb, directed, names_task)
        {
            let (code, sentence) = match refusal {
                // An opener carrying an act-id names a task that already
                // exists, which is not something an opener can do.
                freeq_sdk::act_transitions::Refusal::IllegalStep => (
                    "ILLEGAL_STEP",
                    "That step cannot be taken from the task's current state",
                ),
                freeq_sdk::act_transitions::Refusal::UnknownKind => {
                    ("UNKNOWN_KIND", "This server does not know that task kind")
                }
                _ => ("UNKNOWN_VERB", "That task kind has no such step"),
            };
            tracing::debug!(
                session = %conn.id, did = %did, kind = %kind, verb = %verb,
                reason = %refusal,
                "Refused a task message that cannot open a task"
            );
            refuse(conn, "TAGMSG", code, sentence, state);
            return Gate::Refused;
        }
    } else if !freeq_sdk::act_transitions::knows_verb(kind, verb) {
        tracing::debug!(
            session = %conn.id, did = %did, kind = %kind, verb = %verb,
            "Refused a task message naming a verb that neither opens nor moves a task"
        );
        refuse(
            conn,
            "TAGMSG",
            "UNKNOWN_VERB",
            "That task kind has no such step",
            state,
        );
        return Gate::Refused;
    }

    // ── The task's own state ──
    //
    // Everything above could be decided from the message alone. What is left
    // needs the task: whether it exists, whether it lives here, whether this
    // step is legal from where it stands, and whether this sender may take it.
    // The read, the decision and the write happen in one `with_db` call, which
    // holds the database mutex throughout — two agents racing to claim the
    // same open post are serialized by it, and exactly one wins.
    let is_opener = freeq_sdk::act_transitions::opening_verb(kind) == Some(verb);
    let act_id = match is_opener {
        // An opener's own event id is the task's id.
        true => msgid.clone(),
        false => tags
            .get("+freeq.at/act-id")
            .or_else(|| tags.get("act-id"))
            .cloned()
            // A follow-up that names no task names one this server has not
            // filed, which is the same answer.
            .unwrap_or_default(),
    };
    let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let Some(canonical) = freeq_sdk::act::act_canonical(pairs, &venue, &msgid) else {
        return Gate::Refused;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let written = state.with_db(|db| {
        db.apply_act_event(&crate::db::ActEvent {
            canonical: &canonical,
            signature: Some(sig_tag),
            event_id: &msgid,
            act_id: &act_id,
            opens: is_opener,
            venue: &venue,
            actor: did,
            from_system: false,
            origin: None,
            timestamp: now,
        })
    });

    match written {
        // No database attached: nothing to referee against, and nothing to
        // store. The message is still checked and delivered.
        None => {}
        Some(crate::db::ActWrite::Filed { .. }) => {}
        Some(crate::db::ActWrite::UnknownTask) => {
            refused(state);
            tracing::debug!(
                session = %conn.id, did = %did, act_id = %act_id,
                "Refused a task event naming a task not on file"
            );
            refuse(
                conn,
                "TAGMSG",
                "UNKNOWN_TASK",
                "That task is not on file",
                state,
            );
            return Gate::Refused;
        }
        Some(crate::db::ActWrite::WrongVenue) => {
            refused(state);
            refuse(
                conn,
                "TAGMSG",
                "WRONG_VENUE",
                "That task lives in a different conversation",
                state,
            );
            return Gate::Refused;
        }
        Some(crate::db::ActWrite::Refused(reason)) => {
            refused(state);
            use freeq_sdk::act_transitions::Refusal;
            let (code, sentence) = match reason {
                Refusal::TerminalTask => (
                    "TERMINAL_TASK",
                    "That task is finished and takes no further steps",
                ),
                Refusal::IllegalStep => (
                    "ILLEGAL_STEP",
                    "That step cannot be taken from the task's current state",
                ),
                Refusal::WrongSender => ("WRONG_SENDER", "That step is not yours to take"),
                Refusal::DeadlinePassed => ("DEADLINE_PASSED", "That offer's deadline has passed"),
                Refusal::UnknownKind => {
                    ("UNKNOWN_KIND", "This server does not know that task kind")
                }
                Refusal::UnknownVerb => ("UNKNOWN_VERB", "That task kind has no such step"),
            };
            tracing::debug!(
                session = %conn.id, did = %did, act_id = %act_id, reason = %reason,
                "Refused a task event against the task's state"
            );
            refuse(conn, "TAGMSG", code, sentence, state);
            return Gate::Refused;
        }
        // The id is already in the log: a resend, or a client reusing an id.
        // Nothing moved, and nothing should be delivered a second time.
        Some(crate::db::ActWrite::Duplicate) => {
            tracing::debug!(
                session = %conn.id, did = %did, msgid = %msgid,
                "Task event id already in the log; not filed again"
            );
            return Gate::Refused;
        }
        // The verification above rebuilt this canonical, so the log cannot
        // fail to read it. Refuse rather than deliver something unfileable.
        Some(crate::db::ActWrite::NotATaskEvent) => {
            tracing::error!(
                session = %conn.id, did = %did,
                "A verified task message produced bytes the log cannot read"
            );
            return Gate::Refused;
        }
    }

    tracing::debug!(
        session = %conn.id, did = %did, target = %target,
        kind = %kind, verb = %verb, msgid = %msgid, act_id = %act_id,
        "Accepted a task message"
    );
    Gate::Accepted
}

/// Count one refused task event.
///
/// Minimal on purpose: how many events the referee turned away is the number
/// that says whether the rules are working or whether something is wedged.
fn refused(state: &Arc<SharedState>) {
    crate::server::Metrics::bump(&state.metrics.act_refused_total);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn act_tags_are_recognized_under_either_spelling() {
        assert!(carries_act_tags(&tags(&[("+freeq.at/act", "handoff")])));
        assert!(carries_act_tags(&tags(&[("freeq.at/act-verb", "offer")])));
        assert!(carries_act_tags(&tags(&[("act-id", "01J")])));
    }

    /// The names that merely look close. `actor-class` is the one that would
    /// hurt: it is on ordinary messages, and treating it as a task tag would
    /// route every agent's chat through this gate.
    #[test]
    fn tags_that_are_not_act_tags_are_not_recognized() {
        assert!(!carries_act_tags(&tags(&[(
            "+freeq.at/actor-class",
            "agent"
        )])));
        assert!(!carries_act_tags(&tags(&[(
            "+freeq.at/sig",
            "ed25519:a:b"
        )])));
        assert!(!carries_act_tags(&tags(&[("+freeq.at/eventid", "01J")])));
        assert!(!carries_act_tags(&tags(&[
            ("msgid", "01J"),
            ("account", "did:plc:x")
        ])));
        assert!(!carries_act_tags(&HashMap::new()));
    }

    #[test]
    fn every_other_family_is_a_mix() {
        for name in [
            "+draft/delete",
            "+react",
            "+draft/react",
            "+freeq.at/unreact",
            "+reply",
            "+freeq.at/event",
            "+freeq.at/payload",
            "+freeq.at/ref",
            "+freeq.at/av-start",
            "+freeq.at/av-signal",
        ] {
            let t = tags(&[("+freeq.at/act", "handoff"), (name, "x")]);
            assert_eq!(foreign_family_tag(&t), Some(name), "{name}");
        }
    }

    /// A task message's own furniture is not another family: the signature,
    /// the id it covers, and the act tags themselves all belong here.
    #[test]
    fn a_task_messages_own_tags_are_not_a_mix() {
        let t = tags(&[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/act-to", "did:plc:bob"),
            ("+freeq.at/act-deadline", "1760000000"),
            ("+freeq.at/eventid", "01JNEW"),
            ("+freeq.at/sig", "ed25519:kid:sig"),
        ]);
        assert_eq!(foreign_family_tag(&t), None);
    }
}
