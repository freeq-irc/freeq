//! The rebuild proof: the derived tables are derived.
//!
//! `messages`, `reactions` and `pins` are the shape queries want; the log is
//! the shape evidence wants. That claim is only worth making if it can be
//! demonstrated, so this drops the derived tables, replays the log, and
//! compares what comes back.
//!
//! **Except message bodies**, which the log never contains. A message document
//! carries its body as a hash, and storing the document therefore stores the
//! hash and nothing more — an audit log that quietly accumulated a second copy
//! of every private message would be a liability, not a feature. So a replay
//! restores ids, ordering, edit chains, deletion state, reactions and pins, and
//! serves bodies by joining back to the rows that still hold them. What the
//! rebuild proves is that the *structure* is recoverable from the log alone;
//! what it deliberately does not prove is that the log could resurrect content
//! someone asked to have deleted.

use std::collections::{HashMap, HashSet};

use freeq_server::db::Db;

const ALICE: &str = "did:plc:rebuildalice";
const BOB: &str = "did:plc:rebuildbob";

/// The state a rebuild has to reproduce, read out of the derived tables.
#[derive(Debug, PartialEq, Eq)]
struct DerivedState {
    /// (msgid, root_msgid, replaces_msgid, deleted, venue), ordered.
    messages: Vec<(String, String, Option<String>, bool, String)>,
    /// (target_msgid, emoji, reactor_did), as a set — order is not meaning.
    reactions: HashSet<(String, String, Option<String>)>,
    /// (channel, msgid).
    pins: HashSet<(String, String)>,
}

fn read_derived(conn: &rusqlite::Connection) -> DerivedState {
    let mut stmt = conn
        .prepare(
            "SELECT msgid, root_msgid, replaces_msgid, deleted_at IS NOT NULL, channel
             FROM messages WHERE msgid IS NOT NULL
             ORDER BY timestamp ASC, msgid ASC",
        )
        .unwrap();
    let messages = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, bool>(3)?,
                freeq_server::events::venue_of(&r.get::<_, String>(4)?),
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT target_msgid, emoji, reactor_did FROM reactions")
        .unwrap();
    let reactions = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    let mut stmt = conn.prepare("SELECT channel, msgid FROM pins").unwrap();
    let pins = stmt
        .query_map([], |r| {
            Ok((
                freeq_server::events::venue_of(&r.get::<_, String>(0)?),
                r.get::<_, String>(1)?,
            ))
        })
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    DerivedState {
        messages,
        reactions,
        pins,
    }
}

/// Replay the log into the state it describes.
///
/// Deliberately written against the *stored events* and nothing else — no
/// peeking at `messages`, because the whole question is whether the log is
/// enough. Bodies are the one thing it cannot answer, and the comparison
/// excludes them for that reason.
fn replay(events: &[freeq_server::db::StoredEvent]) -> DerivedState {
    // msgid → (root, replaces, venue, order)
    let mut messages: Vec<(String, String, Option<String>, bool, String)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut reactions: HashSet<(String, String, Option<String>)> = HashSet::new();
    let mut pins: HashSet<(String, String)> = HashSet::new();

    for ev in events {
        match ev.kind.as_str() {
            "message" => {
                index.insert(ev.event_id.clone(), messages.len());
                messages.push((
                    ev.event_id.clone(),
                    ev.event_id.clone(),
                    None,
                    false,
                    ev.venue.clone(),
                ));
            }
            "edit" => {
                // A revision is its own row carrying the root it revises — the
                // identity the message keeps for life.
                let root = ev.subject.clone().unwrap_or_else(|| ev.event_id.clone());
                index.insert(ev.event_id.clone(), messages.len());
                messages.push((
                    ev.event_id.clone(),
                    root.clone(),
                    ev.subject.clone(),
                    false,
                    ev.venue.clone(),
                ));
            }
            "delete" => {
                // A delete strikes every revision of the message it names, and
                // takes the reactions and pins on it with them.
                let Some(root) = ev.subject.as_deref() else {
                    continue;
                };
                for row in messages.iter_mut().filter(|m| m.1 == root) {
                    row.3 = true;
                }
                reactions.retain(|(target, ..)| target != root);
                pins.retain(|(_, msgid)| msgid != root);
            }
            "react" => {
                if let Some(subject) = ev.subject.clone() {
                    reactions.insert((subject, emoji_of(ev), ev.actor_did.clone()));
                }
            }
            "unreact" => {
                if let Some(subject) = ev.subject.clone() {
                    reactions.remove(&(subject, emoji_of(ev), ev.actor_did.clone()));
                }
            }
            "pin" => {
                if let Some(subject) = ev.subject.clone() {
                    pins.insert((ev.venue.clone(), subject));
                }
            }
            "unpin" => {
                if let Some(subject) = ev.subject.clone() {
                    pins.remove(&(ev.venue.clone(), subject));
                }
            }
            _ => {}
        }
    }
    let _ = index;
    DerivedState {
        messages,
        reactions,
        pins,
    }
}

/// A reaction's emoji lives in the document, which is where a replay reads it
/// from — the column set deliberately holds nothing a document doesn't.
fn emoji_of(ev: &freeq_server::db::StoredEvent) -> String {
    serde_json::from_str::<serde_json::Value>(&ev.canonical)
        .ok()
        .and_then(|d| d.get("emoji").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default()
}

fn mutation(event_id: &str, did: Option<&str>, ts: u64) -> freeq_server::db::MutationEvent<'static> {
    // Leaked so the borrow outlives the call — a test-only convenience.
    freeq_server::db::MutationEvent {
        event_id: Box::leak(event_id.to_string().into_boxed_str()),
        actor_did: did.map(|d| &*Box::leak(d.to_string().into_boxed_str())),
        signature: Some("ed25519:testkid:testsig"),
        ctx: freeq_server::events::EventContext::verified(),
        timestamp: ts,
    }
}

/// Build a channel's worth of history through the real write paths, then drop
/// the derived tables and rebuild them from the log alone.
#[test]
fn replaying_the_log_reproduces_the_derived_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rebuild.db");
    let db = Db::open(&path).unwrap();

    // A message, a reply, an edit of the first, a second author.
    db.insert_message("#Rebuild", "a!u@h", "first", 10, &HashMap::new(), Some("M1"), Some(ALICE))
        .unwrap();
    let reply_tags: HashMap<String, String> =
        HashMap::from([("+reply".to_string(), "M1".to_string())]);
    db.insert_message("#Rebuild", "b!u@h", "answering", 20, &reply_tags, Some("M2"), Some(BOB))
        .unwrap();
    db.insert_edit("#Rebuild", "a!u@h", "first, revised", 30, &HashMap::new(), "M3", "M1", Some(ALICE))
        .unwrap();
    db.insert_message("#Rebuild", "g!u@h", "a guest speaks", 40, &HashMap::new(), Some("M4"), None)
        .unwrap();
    // A message in another venue, so the rebuild has to keep them apart.
    db.insert_message("dm:did:plc:x,did:plc:y", "a!u@h", "elsewhere", 45, &HashMap::new(), Some("M5"), Some(ALICE))
        .unwrap();

    // Reactions: two that stay, one taken back.
    db.store_reaction_by("M1", "#Rebuild", "b", Some(BOB), "👍", 50, Some(&mutation("R1", Some(BOB), 50)))
        .unwrap();
    db.store_reaction_by("M2", "#Rebuild", "a", Some(ALICE), "🎉", 51, Some(&mutation("R2", Some(ALICE), 51)))
        .unwrap();
    db.store_reaction_by("M2", "#Rebuild", "b", Some(BOB), "🔥", 52, Some(&mutation("R3", Some(BOB), 52)))
        .unwrap();
    db.remove_reaction_by("M2", "b", Some(BOB), "🔥", Some(&mutation("R4", Some(BOB), 53)))
        .unwrap();

    // Pins: one that stays, one lifted.
    db.store_pin("#Rebuild", "M1", "a", 60).unwrap();
    db.store_pin("#Rebuild", "M2", "a", 61).unwrap();
    db.remove_pin("#Rebuild", "M2").unwrap();

    // A delete, which has to strike the whole revision family.
    db.soft_delete_message_by("#Rebuild", "M1", Some(&mutation("D1", Some(ALICE), 70)))
        .unwrap();

    let events = db.all_events().unwrap();
    let before = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        read_derived(&conn)
    };
    drop(db);

    // Drop what the log claims to derive, and rebuild it from the log.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DELETE FROM messages; DELETE FROM reactions; DELETE FROM pins;")
            .unwrap();
        let after_drop = read_derived(&conn);
        assert_eq!(after_drop.messages.len(), 0, "the derived tables really are gone");
    }

    let rebuilt = replay(&events);

    assert_eq!(
        rebuilt.reactions, before.reactions,
        "reactions rebuild exactly — including the one taken back, which is gone from both"
    );
    assert_eq!(rebuilt.pins, before.pins, "pins rebuild exactly");
    assert_eq!(
        rebuilt.messages, before.messages,
        "ids, ordering, edit chains, deletion state and venues all rebuild"
    );
}

/// The log holds no bodies, so a rebuild cannot produce one. Stated as a test
/// rather than left implicit: it is the deliberate limit of the criterion, and
/// a future change that started storing bodies should fail here loudly.
#[test]
fn a_rebuild_cannot_produce_a_body_and_that_is_the_point() {
    let db = Db::open_memory().unwrap();
    db.insert_message(
        "#Rebuild",
        "a!u@h",
        "the passphrase is hunter2",
        10,
        &HashMap::new(),
        Some("M1"),
        Some(ALICE),
    )
    .unwrap();

    for ev in db.all_events().unwrap() {
        assert!(
            !ev.canonical.contains("hunter2"),
            "the document carries a hash, never the text: {}",
            ev.canonical
        );
        assert!(ev.body_hash.is_some(), "what it carries is the hash");
    }
}

/// Parity, in the one direction that holds: every message has an event. The
/// reverse is deliberately not asserted — the log outlives what it points at.
#[test]
fn every_message_has_an_event_and_the_log_may_outlive_them() {
    let db = Db::open_memory().unwrap();
    for (i, id) in ["M1", "M2", "M3"].iter().enumerate() {
        db.insert_message("#Parity", "a!u@h", "x", i as u64, &HashMap::new(), Some(id), Some(ALICE))
            .unwrap();
    }
    assert!(db.messages_without_events().unwrap().is_empty());

    // Pruning the bodies leaves the events, and parity still holds.
    db.prune_messages("#Parity", 1).unwrap();
    assert!(
        db.messages_without_events().unwrap().is_empty(),
        "parity is message → event; the log keeping more is the design"
    );
    assert_eq!(db.all_events().unwrap().len(), 3, "the log kept all three");
}
