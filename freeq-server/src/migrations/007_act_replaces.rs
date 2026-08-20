//! Migration 7: the revival relation becomes a column of the live-task view.
//!
//! `act-replaces` names the finished action a new one revives — a failed
//! handoff re-offered, a forfeited bounty re-listed. The link is the opener's,
//! signed like every other act tag, and the log has held it since the tag
//! existed. This lifts it into the view so a reader can ask what an action
//! revives without reopening the opener's bytes, exactly as `offeree` and
//! `caps` are already lifted.
//!
//! Nullable, because most actions revive nothing, and derived like every other
//! column here: the rebuild fills it from the same bytes ingress reads, and the
//! rebuild-matches test covers it.
//!
//! A hook rather than plain SQL, for the reason migration 5 states: SQLite has
//! no `ADD COLUMN IF NOT EXISTS`, and this rung has to survive being re-run
//! against a database whose schema is already converged but whose stamp was
//! lost. So the ALTER runs and its "duplicate column" error is the success
//! case.
//!
//! Down: drop the column. Nothing is lost that the log cannot rebuild — the
//! link is in the opener's signed bytes either way.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute("ALTER TABLE act_actions ADD COLUMN replaces TEXT", []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    })
    .down("ALTER TABLE act_actions DROP COLUMN replaces;")
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

    #[test]
    fn the_view_gains_the_link_and_keeps_every_column_it_had() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 6).unwrap();
        assert!(!columns(&conn).iter().any(|c| c == "replaces"));

        migration_ladder().to_version(&mut conn, 7).unwrap();
        assert_eq!(
            columns(&conn),
            vec![
                "act_id", "assignee", "caps", "deadline", "kind", "offeree", "offerer", "origin",
                "replaces", "state", "updated", "venue",
            ]
        );
    }

    /// An action already on file revives nothing, which is what the column
    /// says about it — no backfill, because the answer for a row that never
    /// carried the tag is the empty one.
    #[test]
    fn a_row_that_predates_the_column_revives_nothing() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 6).unwrap();
        conn.execute(
            "INSERT INTO act_actions (act_id, kind, venue, state, offerer, updated)
             VALUES ('A1', 'handoff', '#c', 'open', 'did:plc:a', 10)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 7).unwrap();

        let replaces: Option<String> = conn
            .query_row(
                "SELECT replaces FROM act_actions WHERE act_id = 'A1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(replaces, None);
    }

    /// The rung survives a re-run against a database that already has the
    /// column — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 7).unwrap();
        conn.execute_batch("PRAGMA user_version = 6").unwrap();
        migration_ladder()
            .to_version(&mut conn, 7)
            .expect("a converged schema with a lost stamp climbs anyway");
    }

    /// Down leaves a pre-7 shape behind, and the log — the record — keeps the
    /// link in the bytes it always had it in.
    #[test]
    fn migrating_down_drops_the_column_and_keeps_the_log() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 7).unwrap();
        conn.execute(
            "INSERT INTO events (event_id, canonical, sig_state, kind, venue, timestamp)
             VALUES ('A2', '{\"act-replaces\":\"A1\"}', 'unsigned', 'act', '#c', 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO act_actions (act_id, kind, venue, state, offerer, replaces, updated)
             VALUES ('A2', 'handoff', '#c', 'open', 'did:plc:a', 'A1', 10)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 6).unwrap();

        assert!(!columns(&conn).iter().any(|c| c == "replaces"));
        let canonical: String = conn
            .query_row(
                "SELECT canonical FROM events WHERE event_id = 'A2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(canonical.contains("act-replaces"), "{canonical}");
    }
}
