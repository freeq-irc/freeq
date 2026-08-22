//! Migration 8: how many events about a task were dropped unchecked.
//!
//! A relayed task event whose signer's key cannot be fetched waits in a
//! bounded queue. When the queue is full, the oldest waiting event is thrown
//! away — and until now the only trace was a server log line, which the
//! people whose task lost an event cannot read. This column is the visible
//! trace: a count on the task's own row, shown wherever the task is shown,
//! meaning "this server threw away N events about this task that it never
//! managed to check."
//!
//! A receipt fact, like `origin` beside it — a record of what this server
//! did, not something derivable from the log: the dropped event is precisely
//! what the log never received, so a view rebuild cannot reproduce the
//! count. Local and non-authoritative, the same species as the orphaned
//! annotation: never relayed, never entering the signed log, deciding
//! nothing about the task's state.
//!
//! Only a task on file here can carry the count. An event whose task this
//! server never stored — an opening that never verified, or the stopgap
//! coordination family, which has no task view — leaves only the log line.
//!
//! A hook rather than plain SQL for the reason migrations 5 and 7 use one:
//! SQLite has no `ADD COLUMN IF NOT EXISTS`, so the ALTER runs and its
//! "duplicate column" error is the success case.
//!
//! Down: drop the column. A pre-8 binary never shows the count, which is
//! exactly the behaviour it always had.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute(
            "ALTER TABLE act_actions ADD COLUMN dropped_unchecked INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    })
    .down("ALTER TABLE act_actions DROP COLUMN dropped_unchecked;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn columns(conn: &Connection) -> Vec<String> {
        let mut cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('act_actions')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        cols.sort();
        cols
    }

    /// Rows that predate the column read zero: nothing was dropped that
    /// anyone recorded, and claiming otherwise would invent history.
    #[test]
    fn existing_task_rows_read_zero_dropped() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 7).unwrap();
        conn.execute_batch(
            "INSERT INTO act_actions (act_id, kind, venue, origin, state, offerer, updated)
             VALUES ('T1', 'handoff', '#ops', '', 'open', 'did:plc:alice', 10);",
        )
        .unwrap();

        migration_ladder().to_latest(&mut conn).unwrap();

        let dropped: i64 = conn
            .query_row(
                "SELECT dropped_unchecked FROM act_actions WHERE act_id = 'T1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dropped, 0);
    }

    /// The rung survives a re-run against a database that already has the
    /// column — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 8).unwrap();
        conn.execute_batch("PRAGMA user_version = 7").unwrap();
        migration_ladder()
            .to_version(&mut conn, 8)
            .expect("a converged schema with a lost stamp climbs anyway");
    }

    /// Down leaves a pre-8 shape behind, and the rows stay — the count is a
    /// note this server kept about a task, not part of the task itself, so
    /// losing the note must not cost the task.
    #[test]
    fn migrating_down_drops_the_column_and_keeps_the_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 8).unwrap();
        conn.execute(
            "INSERT INTO act_actions
               (act_id, kind, venue, origin, state, offerer, updated, dropped_unchecked)
             VALUES ('A1', 'handoff', '#c', 'peer-a', 'open', 'did:plc:a', 10, 3)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 7).unwrap();

        assert!(!columns(&conn).iter().any(|c| c == "dropped_unchecked"));
        let state: String = conn
            .query_row(
                "SELECT state FROM act_actions WHERE act_id = 'A1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "open", "the task itself outlives the note");
    }
}
