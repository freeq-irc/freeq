//! Migration 13: where each signing key on file came from.
//!
//! Keys reach `signing_keys` from a client's own registration on this server,
//! from a peer's key server, from the signer's published identity records, or
//! from a did:web signer's own document. `source` names which, so a verdict
//! can say what vouched for the key it checked against.
//!
//! Existing rows keep `NULL`: nothing recorded where they came from, and
//! readers report that as `unknown` rather than guessing.
//!
//! Down: none. Dropping the column would discard provenance nothing else
//! records, so a migration below this rung fails loudly rather than guessing.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        // SQLite has no `ADD COLUMN IF NOT EXISTS`: a converged schema whose
        // stamp was lost already has the column, and that counts as done.
        match tx.execute("ALTER TABLE signing_keys ADD COLUMN source TEXT", []) {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
            Err(e) => Err(e.into()),
        }
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
    fn up_adds_the_source_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 12).unwrap();
        assert!(!columns(&conn).iter().any(|c| c == "source"));

        migration_ladder().to_version(&mut conn, 13).unwrap();
        let after = columns(&conn);
        assert!(
            after.iter().any(|c| c == "source"),
            "migration 13 must add `signing_keys.source`; got {after:?}"
        );
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 13).unwrap();
        conn.execute_batch("PRAGMA user_version = 12").unwrap();
        migration_ladder()
            .to_version(&mut conn, 13)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
