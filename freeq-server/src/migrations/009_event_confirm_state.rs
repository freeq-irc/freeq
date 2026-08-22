//! Migration 9: whether a task event has been confirmed by its task's home.
//!
//! A task's record and the authority that orders it are two different things.
//! Every signed task event is relayed and logged wherever it lands; only the
//! server that owns the task decides which of them actually move it. This
//! column is where that decision is remembered:
//!
//! - `confirmed` — the event was applied through the rules here, either
//!   because this server owns the task or because the task's home emitted it.
//! - `unconfirmed` — filed and deliberately not applied: a transition on a
//!   task another server owns, still waiting on that server's ruling.
//! - `superseded` — it was unconfirmed, a confirmed transition then landed on
//!   the same task, and the rules no longer admit this one. A losing claim.
//!   The row stays: the record is never lost, only the pending flag.
//!
//! NULL for every event that is not a task event, which is most of them.
//!
//! A receipt column, like `origin` and `conflict` beside it — a fact about
//! what this server did with the bytes, not a field derivable from them. It
//! deliberately does not cross the wire: a peer's opinion about whose ruling
//! is final would defeat the point of asking the home.
//!
//! Up: add the column and fill every task event already on file with
//! `confirmed`. Those rows predate routing, so nothing is on its way to being
//! ruled on; calling them confirmed keeps a rebuild reproducing exactly the
//! view they already produce. Rows that were stored-and-not-applied before
//! this rung read as confirmed and a rebuild will apply them, which is the
//! behaviour that rung already had.
//!
//! A hook rather than plain SQL for the reason migration 5 uses one: SQLite
//! has no `ADD COLUMN IF NOT EXISTS`, so the ALTER runs and its "duplicate
//! column" error is the success case, and the rung survives a database whose
//! schema is converged but whose stamp was lost.
//!
//! Down: drop the column. A pre-9 binary rules on task events exactly as it
//! did, which is to say it never asks the question this column answers.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute("ALTER TABLE events ADD COLUMN confirm_state TEXT", []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "UPDATE events SET confirm_state = 'confirmed'
             WHERE kind = 'act' AND confirm_state IS NULL",
            [],
        )?;
        Ok(())
    })
    .down("ALTER TABLE events DROP COLUMN confirm_state;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn confirm_state(conn: &Connection, event_id: &str) -> Option<String> {
        conn.query_row(
            "SELECT confirm_state FROM events WHERE event_id = ?1",
            [event_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Task events already on file are confirmed; everything else is left
    /// alone, because the question does not apply to it.
    #[test]
    fn task_events_already_on_file_are_marked_confirmed() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 8).unwrap();
        conn.execute_batch(
            "INSERT INTO events (event_id, canonical, sig_state, kind, venue, timestamp) VALUES
               ('A1', '', 'valid', 'act', '#c', 10),
               ('M1', '', 'valid', 'message', '#c', 11);",
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 9).unwrap();

        assert_eq!(confirm_state(&conn, "A1").as_deref(), Some("confirmed"));
        assert_eq!(
            confirm_state(&conn, "M1"),
            None,
            "a message is not a task event and has no ruling to remember"
        );
    }

    /// Down drops the column and keeps every row — the log is the record.
    #[test]
    fn migrating_down_drops_the_column_and_keeps_the_log() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 9).unwrap();
        conn.execute(
            "INSERT INTO events (event_id, canonical, sig_state, kind, venue, timestamp)
             VALUES ('A1', '', 'valid', 'act', '#c', 10)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 8).unwrap();

        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('events')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            !cols.iter().any(|c| c == "confirm_state"),
            "the column is gone: {cols:?}"
        );
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the log survives");
    }

    /// The rung survives a re-run against a database that already has the
    /// column — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 9).unwrap();
        conn.execute_batch("PRAGMA user_version = 8").unwrap();
        migration_ladder()
            .to_version(&mut conn, 9)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
