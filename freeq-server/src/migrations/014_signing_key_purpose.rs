//! Migration 14: what each signing key on file may be used for.
//!
//! A key registered with `MSGSIG` verifies chat and act documents. A key
//! registered for delegation verifies `FreeqBotDelegation/v1` certificates and
//! nothing else. `purpose` names which.
//!
//! Existing rows keep `NULL`: unscoped, verifying both.
//!
//! Down: none. Dropping the column would widen what every scoped key verifies,
//! so a migration below this rung fails loudly rather than guessing.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        // SQLite has no `ADD COLUMN IF NOT EXISTS`: a converged schema whose
        // stamp was lost already has the column, and that counts as done.
        match tx.execute("ALTER TABLE signing_keys ADD COLUMN purpose TEXT", []) {
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
    fn up_adds_the_purpose_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 13).unwrap();
        assert!(!columns(&conn).iter().any(|c| c == "purpose"));

        migration_ladder().to_version(&mut conn, 14).unwrap();
        let after = columns(&conn);
        assert!(
            after.iter().any(|c| c == "purpose"),
            "migration 14 must add `signing_keys.purpose`; got {after:?}"
        );
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 14).unwrap();
        conn.execute_batch("PRAGMA user_version = 13").unwrap();
        migration_ladder()
            .to_version(&mut conn, 14)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
