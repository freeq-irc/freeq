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
    // The signature establishes who sent the message; `act-from` claims who
    // acted. A message where those differ is either a mistake or an attempt
    // to file an event under someone else's name, and neither is worth
    // relaying. Checked before the signature because it is decidable without
    // one, and the answer is more useful than a signature complaint.
    if let Some(actor) = tags
        .get("+freeq.at/act-from")
        .or_else(|| tags.get("act-from"))
        && actor != did
    {
        tracing::warn!(
            session = %conn.id, did = %did, actor = %actor, target = %target,
            "Refused a task message naming another actor than its sender"
        );
        refuse(
            conn,
            "TAGMSG",
            "AUTHOR_MISMATCH",
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
            ("+freeq.at/act-ref", "01JOLDTASK"),
            ("+freeq.at/eventid", "01JNEW"),
            ("+freeq.at/sig", "ed25519:kid:sig"),
        ]);
        assert_eq!(foreign_family_tag(&t), None);
    }
}
