//! Migration 11: persist one-shot channel invites.
//!
//! `+i` is durable — a column on `channels` — but the invites that make it
//! usable were runtime-only. A restart therefore left every invite-only
//! channel sealed: the gate survived, the keys did not. Anyone invited but
//! not yet joined was locked out with no signal, and an operator had to
//! notice and re-invite by hand.
//!
//! `invite_exceptions` is a different feature (the `+I` mask list, the
//! invite-only analogue of ban exceptions), so this needs its own table.
//!
//! Only identity-shaped tokens belong here. `ChannelState::invites` also
//! holds raw session ids, which are meaningless across a restart; persisting
//! those would restore invites that can never match anything.
//!
//! Down: drop the table. Outstanding invites are lost, which is exactly the
//! behaviour this rung exists to end.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS channel_invites (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 channel    TEXT NOT NULL,
                 token      TEXT NOT NULL,
                 invited_by TEXT NOT NULL,
                 invited_at INTEGER NOT NULL,
                 UNIQUE(channel, token)
             );
             CREATE INDEX IF NOT EXISTS idx_channel_invites_channel
                 ON channel_invites(channel);",
        )?;
        Ok(())
    })
    .down("DROP TABLE IF EXISTS channel_invites;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
            .unwrap()
            .query_map([name], |_| Ok(()))
            .unwrap()
            .next()
            .is_some()
    }

    #[test]
    fn up_creates_the_table_and_down_removes_it() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 11).unwrap();
        assert!(has_table(&conn, "channel_invites"));

        migration_ladder().to_version(&mut conn, 10).unwrap();
        assert!(!has_table(&conn, "channel_invites"));
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 11).unwrap();
        conn.execute_batch("PRAGMA user_version = 10").unwrap();
        migration_ladder()
            .to_version(&mut conn, 11)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
