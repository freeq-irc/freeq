//! Migration 12: a registration window on every signing key.
//!
//! `signing_keys` recorded one timestamp, `registered_at`, and the write path
//! moved it forward every time a key was re-registered. That made "when did
//! this identity first use this key" unanswerable — the only two facts a key
//! window needs, first seen and last seen, were folded into one column and the
//! first one lost. `last_seen_at` takes over the moving stamp so
//! `registered_at` can stand still.
//!
//! `removed_at` is the owner's retirement of a key. NULL means live. It exists
//! so a signature made after a key was retired can be told apart from one made
//! while the key was still in use.
//!
//! Existing rows get `last_seen_at = registered_at`: the one stamp on file is
//! the best evidence for both edges of a key that was never retired.
//!
//! Down: none. Dropping either column would discard retirements that nothing
//! else records, so a migration below this rung fails loudly rather than
//! guessing.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        // SQLite has no `ADD COLUMN IF NOT EXISTS`, so convergence relies on
        // running each ALTER and letting "duplicate column name" stand for
        // success — the same per-statement suppression migration 1 uses.
        for sql in [
            "ALTER TABLE signing_keys ADD COLUMN last_seen_at INTEGER",
            "ALTER TABLE signing_keys ADD COLUMN removed_at INTEGER",
        ] {
            let _ = tx.execute(sql, []);
        }
        tx.execute(
            "UPDATE signing_keys SET last_seen_at = registered_at WHERE last_seen_at IS NULL",
            [],
        )?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn columns(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM pragma_table_info('signing_keys')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn up_adds_the_window_columns() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 11).unwrap();
        let before = columns(&conn);
        assert!(!before.iter().any(|c| c == "last_seen_at"));
        assert!(!before.iter().any(|c| c == "removed_at"));

        migration_ladder().to_version(&mut conn, 12).unwrap();
        let after = columns(&conn);
        for expected in ["last_seen_at", "removed_at"] {
            assert!(
                after.iter().any(|c| c == expected),
                "migration 12 must add `signing_keys.{expected}`; got {after:?}"
            );
        }
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_columns() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 12).unwrap();
        conn.execute_batch("PRAGMA user_version = 11").unwrap();
        migration_ladder()
            .to_version(&mut conn, 12)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
