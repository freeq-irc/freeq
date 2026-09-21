//! Migration 14: device sign-outs that outlive a restart.
//!
//! Signing a device out ends the login token it came in on. Where the broker
//! is a separate service, that means two things this table records: this
//! server refuses to mint web tokens for the token from now on, and the
//! broker is asked to delete the session behind it.
//!
//! The token itself is never stored. `token_hash` is its lowercase hex
//! SHA-256, which is all either job needs: a pushed token is hashed before it
//! is looked up here, and the broker's delete route names the session by the
//! same hash. `delivered_at` is when the session was actually ended — the
//! broker's delete answered, or the embedded store deleted it — and is null
//! until then, which is what the retry works from.
//!
//! Down: none. Dropping the table would let every signed-out device mint web
//! tokens again, so a migration below this rung fails loudly rather than
//! quietly undoing sign-outs.

use rusqlite_migration::M;

pub(super) fn migration() -> M<'static> {
    // IF NOT EXISTS: a converged schema whose stamp was lost already has the
    // table, and that counts as done.
    M::up(
        "CREATE TABLE IF NOT EXISTS revoked_broker_tokens (
             token_hash   TEXT PRIMARY KEY,
             revoked_at   INTEGER NOT NULL,
             delivered_at INTEGER
         );",
    )
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn columns(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM pragma_table_info('revoked_broker_tokens')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn up_adds_the_revoked_broker_tokens_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 13).unwrap();
        assert!(columns(&conn).is_empty(), "the table arrives at rung 14");

        migration_ladder().to_version(&mut conn, 14).unwrap();
        let after = columns(&conn);
        for expected in ["token_hash", "revoked_at", "delivered_at"] {
            assert!(
                after.iter().any(|c| c == expected),
                "migration 14 must create `revoked_broker_tokens.{expected}`; got {after:?}"
            );
        }
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 14).unwrap();
        conn.execute_batch("PRAGMA user_version = 13").unwrap();
        migration_ladder()
            .to_version(&mut conn, 14)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
