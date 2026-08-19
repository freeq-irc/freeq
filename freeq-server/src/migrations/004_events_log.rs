//! Migration 4: the append-only `events` log, born complete.
//!
//! Every chat event this server accepts gets a row here, and `messages`,
//! `reactions` and `pins` become views of it — the shape queries want, where
//! the log is the shape evidence wants. See `crate::events` for the model.
//!
//! **Born complete on purpose.** The alternative — a table that starts with
//! mutations only and backfills messages later — puts a late backfill into a
//! table other code already depends on, which is the migration shape that has
//! hurt before. So the up step files one row for every message already on
//! disk, and from this rung onward nothing writes a message without writing
//! its event in the same transaction.
//!
//! **Backfilled rows carry no canonical.** The log begins here; the bytes of
//! events that predate it were never held in a form this server could hand
//! back verbatim, and at-rest encryption means the up step cannot even read a
//! body to hash. Rather than synthesise bytes nobody signed, a backfilled row
//! records what it knows — the id, the venue, the actor, the kind, the
//! revision chain, the timestamp, and the signature that was on file — and
//! leaves `canonical` empty. Anyone wanting those bytes can rebuild them from
//! `messages`, which is exactly where they still are.
//!
//! Down: drop the table. Every row in it is either derived from `messages` or
//! a duplicate of state the derived tables still hold, so a pre-4 binary is
//! equally correct without it.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

const CREATE: &str = r#"
-- The append-only log. One row per accepted event.
--
-- `canonical` is the exact JCS bytes the signature covers, verbatim — plain
-- TEXT so no encoder ever rewrites them, empty when nothing signed the event
-- (a guest, a pin). Every other queryable column is DERIVED from those bytes
-- when they exist; `crate::events::derive_facts` is the reader and
-- `Db::events_disagreeing_with_their_bytes` is the audit that keeps the two
-- honest.
--
-- `sig_state` is 'valid' | 'unverifiable' | 'unsigned'. There is deliberately
-- no 'invalid': a signature that fails against the key it names is refused at
-- ingress and the event is never filed, so no row can exist in that state. Do
-- not add one — a stored "invalid" would be an accusation this table has no
-- way to re-examine.
--
-- `conflict` holds the fingerprint of a *dropped* second claim on this id
-- (same id, different content). Local receipt only: it never crosses the wire.
-- NULL is the normal case.
--
-- `timestamp` and `origin` are facts about receipt, not about the document —
-- a chat document deliberately carries no wall clock and no provenance.
CREATE TABLE IF NOT EXISTS events (
    event_id  TEXT PRIMARY KEY,
    canonical TEXT NOT NULL DEFAULT '',
    signature TEXT,
    sig_state TEXT NOT NULL DEFAULT 'unsigned',
    kind      TEXT NOT NULL,
    venue     TEXT NOT NULL,
    actor_did TEXT,
    subject   TEXT,
    body_hash TEXT,
    origin    TEXT,
    conflict  TEXT,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_venue_ts ON events(venue, timestamp, event_id);
CREATE INDEX IF NOT EXISTS idx_events_subject ON events(subject);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_did, timestamp);
"#;

pub(super) fn migration() -> M<'static> {
    M::up_with_hook(CREATE, |tx: &Transaction| -> HookResult {
        // One row per message already on disk. Rows with no msgid predate
        // message ids entirely and have no identity to file under; they stay
        // where they are and the count-parity check excludes them for the
        // same reason.
        //
        // `venue` is the stored channel key folded, matching what a signer
        // would have signed: a local row is already normalized, but a row that
        // arrived over S2S keeps the spelling the origin's user typed.
        // `kind`/`subject` come from the revision chain: a row that replaces
        // another is an edit of it.
        tx.execute(
            "INSERT OR IGNORE INTO events
                 (event_id, canonical, signature, sig_state, kind, venue,
                  actor_did, subject, body_hash, origin, conflict, timestamp)
             SELECT
                 msgid,
                 '',
                 json_extract(tags_json, '$.\"+freeq.at/sig\"'),
                 CASE WHEN json_extract(tags_json, '$.\"+freeq.at/sig\"') IS NULL
                      THEN 'unsigned' ELSE 'unverifiable' END,
                 CASE WHEN replaces_msgid IS NULL THEN 'message' ELSE 'edit' END,
                 CASE WHEN substr(channel, 1, 1) IN ('#', '&')
                      THEN lower(channel) ELSE channel END,
                 sender_did,
                 replaces_msgid,
                 NULL,
                 json_extract(tags_json, '$.\"+freeq.at/origin\"'),
                 NULL,
                 timestamp
             FROM messages
             WHERE msgid IS NOT NULL",
            [],
        )?;
        Ok(())
    })
    .down("DROP TABLE IF EXISTS events;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn at_v3_with_messages() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 3).unwrap();
        conn.execute_batch(
            r#"INSERT INTO messages
                 (channel, sender, text, timestamp, tags_json, msgid, root_msgid,
                  replaces_msgid, sender_did) VALUES
               ('#Room', 'a!u@h', 'first', 10,
                '{"+freeq.at/sig":"ed25519:kid:sig"}', 'M1', 'M1', NULL, 'did:plc:a'),
               ('#Room', 'a!u@h', 'revised', 20, '{}', 'M2', 'M1', 'M1', 'did:plc:a'),
               ('dm:did:plc:a,did:plc:b', 'b!u@h', 'hi', 30, '{}', 'M3', 'M3', NULL, 'did:plc:b'),
               ('#Room', 'guest!u@h', 'anon', 40, '{}', 'M4', 'M4', NULL, NULL),
               ('#Room', 'old!u@h', 'prehistoric', 5, '{}', NULL, NULL, NULL, NULL);"#,
        )
        .unwrap();
        conn
    }

    /// Born complete: every message already on disk has an event when the
    /// rung is climbed, not at some later backfill.
    #[test]
    fn the_log_is_born_holding_every_message_already_on_disk() {
        let mut conn = at_v3_with_messages();
        migration_ladder().to_version(&mut conn, 4).unwrap();

        let (n, ids): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), group_concat(event_id) FROM
                   (SELECT event_id FROM events ORDER BY event_id)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(n, 4, "one per message with an id: {ids}");
        assert_eq!(ids, "M1,M2,M3,M4");

        // The row that predates message ids has no identity to file under, so
        // it is not in the log and never will be.
        let orphan: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE msgid IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan, 1, "and it stays where it is");
    }

    /// The columns a backfilled row can honestly fill, filled — and the one
    /// it can't, empty.
    #[test]
    fn a_backfilled_row_states_what_it_knows_and_nothing_more() {
        let mut conn = at_v3_with_messages();
        migration_ladder().to_version(&mut conn, 4).unwrap();

        let row = |id: &str| -> (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        ) {
            conn.query_row(
                "SELECT canonical, kind, venue, actor_did, subject, sig_state, signature
                 FROM events WHERE event_id = ?1",
                rusqlite::params![id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap()
        };

        let (canonical, kind, venue, actor, subject, sig_state, signature) = row("M1");
        assert_eq!(
            canonical, "",
            "the log begins here; earlier bytes are not ours to invent"
        );
        assert_eq!(kind, "message");
        assert_eq!(
            venue, "#room",
            "folded, the way a signer would have signed it"
        );
        assert_eq!(actor.as_deref(), Some("did:plc:a"));
        assert_eq!(subject, None);
        assert_eq!(
            signature.as_deref(),
            Some("ed25519:kid:sig"),
            "the signature was on file and stays on file"
        );
        assert_eq!(
            sig_state, "unverifiable",
            "nothing re-checked it during the migration, so nothing may claim it valid"
        );

        let (_, kind, _, _, subject, sig_state, _) = row("M2");
        assert_eq!((kind.as_str(), subject.as_deref()), ("edit", Some("M1")));
        assert_eq!(
            sig_state, "unsigned",
            "no signature was on file for the revision"
        );

        let (_, _, venue, _, _, _, _) = row("M3");
        assert_eq!(
            venue, "dm:did:plc:a,did:plc:b",
            "a DM venue is already a venue"
        );

        let (_, _, _, actor, _, sig_state, _) = row("M4");
        assert_eq!(
            (actor, sig_state.as_str()),
            (None, "unsigned"),
            "a guest has no identity to bind"
        );
    }

    /// Climbing the rung twice is what a restart does.
    #[test]
    fn re_running_the_rung_files_nothing_twice() {
        let mut conn = at_v3_with_messages();
        migration_ladder().to_version(&mut conn, 4).unwrap();
        migration_ladder().to_version(&mut conn, 3).unwrap();
        migration_ladder().to_version(&mut conn, 4).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 4);
    }

    /// Down drops the log and leaves the derived tables untouched — a pre-4
    /// binary is equally correct without it.
    #[test]
    fn migrating_down_drops_the_log_and_keeps_the_messages() {
        let mut conn = at_v3_with_messages();
        migration_ladder().to_version(&mut conn, 4).unwrap();
        migration_ladder().to_version(&mut conn, 3).unwrap();

        let has_events: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='events')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_events);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 5);
    }
}
