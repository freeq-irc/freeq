//! Migration 6: `act_actions`, the live-task view.
//!
//! One row per task that has not finished. Every column is derived from
//! accepted task events in the log, in the same transaction that files them —
//! the log is the record and this table is the shape queries want, exactly the
//! relationship `messages` and `reactions` already have with it. A test proves
//! rebuilding this table from the log reproduces it row for row.
//!
//! Only unfinished tasks live here: a terminal event deletes the row. The
//! history of a finished task is still complete in the log, which is where a
//! reader goes for it. Keeping the view small is what makes the expiry sweep
//! and the open-work listing cheap.
//!
//! Two columns exist for reasons that are not obvious from a single server:
//! `origin` (empty = created here) is what federation will route and expire
//! by, and `offeree` is read by the who-may-accept check — a directed offer
//! names its recipient, and without the column the check would have to reopen
//! the opener's bytes on every follow-up.
//!
//! `caps` is stored and filterable and never interpreted: capabilities are a
//! self-declared hint, ruled out of the claim check.
//!
//! Up: create the table and its indexes. Down: drop it. Nothing is lost that
//! the log cannot rebuild.

use rusqlite_migration::M;

const CREATE: &str = r#"
CREATE TABLE IF NOT EXISTS act_actions (
    act_id   TEXT PRIMARY KEY,
    kind     TEXT NOT NULL,
    venue    TEXT NOT NULL,
    origin   TEXT NOT NULL DEFAULT '',
    state    TEXT NOT NULL,
    offerer  TEXT NOT NULL,
    offeree  TEXT,
    assignee TEXT,
    caps     TEXT,
    deadline INTEGER,
    updated  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_act_actions_venue ON act_actions(venue, updated);
CREATE INDEX IF NOT EXISTS idx_act_actions_assignee ON act_actions(assignee);
CREATE INDEX IF NOT EXISTS idx_act_actions_state ON act_actions(state, updated);
"#;

pub(super) fn migration() -> M<'static> {
    M::up(CREATE).down("DROP TABLE IF EXISTS act_actions;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    #[test]
    fn the_view_carries_every_column_the_plan_names() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 6).unwrap();
        let mut cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('act_actions')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        cols.sort();
        assert_eq!(
            cols,
            vec![
                "act_id", "assignee", "caps", "deadline", "kind", "offeree", "offerer", "origin",
                "state", "updated", "venue",
            ]
        );
    }

    /// Down drops the view and leaves the log — the record — untouched.
    #[test]
    fn migrating_down_drops_the_view_and_keeps_the_log() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 6).unwrap();
        conn.execute(
            "INSERT INTO events (event_id, canonical, sig_state, kind, venue, timestamp)
             VALUES ('A1', '', 'unsigned', 'act', '#c', 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO act_actions (act_id, kind, venue, state, offerer, updated)
             VALUES ('A1', 'handoff', '#c', 'open', 'did:plc:a', 10)",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 5).unwrap();

        let gone: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='act_actions'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gone, 0);
        let events: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 1, "the log is the record and survives");
    }

    /// The rung survives a re-run against a database that already has the
    /// table — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 6).unwrap();
        conn.execute_batch("PRAGMA user_version = 5").unwrap();
        migration_ladder()
            .to_version(&mut conn, 6)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
