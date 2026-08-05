//! Migration 5: the reaction's emoji becomes a column of its own.
//!
//! A reaction document carries `emoji`, and until now the log held it only
//! inside `canonical`. That was fine for a signed reaction and useless for an
//! unsigned one: a guest has no identity to bind, so there are no signed bytes
//! to store, so the emoji had nowhere to live — and `reactions` could not be
//! rebuilt from the log for anyone who reacted without an account.
//!
//! A column rather than a JSON tail on purpose. `emoji` is a *closed* part of
//! the document schema, exactly like `subject` and `body_hash`, not the first
//! entry in an open bag that accretes six kinds' worth of ad-hoc keys. It
//! stays derivable: for a row with a canonical, `events::derive_facts` reads
//! it back out of the bytes and the column audit checks the two agree.
//!
//! Up: add the column and fill it from the canonical wherever there is one, so
//! the audit passes over rows that predate it.
//!
//! A hook rather than plain SQL, for the same reason migration 1 uses one:
//! SQLite has no `ADD COLUMN IF NOT EXISTS`, and this rung has to survive
//! being re-run against a database whose schema is already converged but whose
//! stamp was lost (see `an_unstamped_database_is_migrated_on_open`). So the
//! ALTER runs and its "duplicate column" error is the success case.
//!
//! Down: drop the column. Reactions filed by guests lose their emoji, which is
//! what a pre-5 binary could store anyway.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute("ALTER TABLE events ADD COLUMN emoji TEXT", []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "UPDATE events SET emoji = json_extract(canonical, '$.emoji')
             WHERE canonical <> ''",
            [],
        )?;
        Ok(())
    })
    .down("ALTER TABLE events DROP COLUMN emoji;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    /// A reaction already on file gets its emoji lifted out of the bytes that
    /// always held it, so the column and the canonical agree from the start.
    #[test]
    fn the_emoji_is_lifted_out_of_the_canonical_it_was_already_in() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 4).unwrap();
        conn.execute_batch(
            r##"INSERT INTO events (event_id, canonical, sig_state, kind, venue, timestamp) VALUES
               ('R1', '{"emoji":"👍","from":"did:plc:a","kind":"react","msgid":"R1","subject":"M1","target":"#c"}',
                'valid', 'react', '#c', 10),
               ('M1', '', 'unsigned', 'message', '#c', 5);"##,
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 5).unwrap();

        let emoji: Option<String> = conn
            .query_row("SELECT emoji FROM events WHERE event_id = 'R1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(emoji.as_deref(), Some("👍"));

        let none: Option<String> = conn
            .query_row("SELECT emoji FROM events WHERE event_id = 'M1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(none, None, "a message has no emoji to lift");
    }

    /// The rung survives a re-run against a database that already has the
    /// column — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 5).unwrap();
        conn.execute_batch("PRAGMA user_version = 4").unwrap();
        migration_ladder()
            .to_version(&mut conn, 5)
            .expect("a converged schema with a lost stamp climbs anyway");
    }

    /// Down leaves a pre-5 shape behind, and the log's rows survive it.
    #[test]
    fn migrating_down_drops_the_column_and_keeps_the_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 5).unwrap();
        conn.execute(
            "INSERT INTO events (event_id, canonical, sig_state, kind, venue, emoji, timestamp)
             VALUES ('R1', '', 'unsigned', 'react', '#c', '🔥', 10)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 4).unwrap();

        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('events')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!cols.iter().any(|c| c == "emoji"), "{cols:?}");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "the event itself survives");
    }
}
