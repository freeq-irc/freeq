//! Migration 10: per-channel private-media space key.
//!
//! A channel that has shared private media owns an AT Protocol space named
//! `at://{authority}/space/at.freeq.media/{key}`. The key is a ULID minted by
//! this server on the channel's first private upload. NULL means the channel
//! has no space yet.
//!
//! Down: drop the column. Spaces already created on the PDS become
//! unreachable through this server until the column returns; their records
//! remain in members' repos.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute("ALTER TABLE channels ADD COLUMN media_space_key TEXT", []) {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
            Err(e) => Err(e.into()),
        }
    })
    .down("ALTER TABLE channels DROP COLUMN media_space_key;")
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn columns(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM pragma_table_info('channels')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn up_adds_the_column_and_down_removes_it() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 10).unwrap();
        assert!(columns(&conn).iter().any(|c| c == "media_space_key"));

        migration_ladder().to_version(&mut conn, 9).unwrap();
        assert!(!columns(&conn).iter().any(|c| c == "media_space_key"));
    }

    /// The rung survives a re-run against a database that already has the
    /// column — an older build's file whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 10).unwrap();
        conn.execute_batch("PRAGMA user_version = 9").unwrap();
        migration_ladder()
            .to_version(&mut conn, 10)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
