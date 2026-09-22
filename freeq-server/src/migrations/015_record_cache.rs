//! Migration 15: identity records and repository proofs the server has read.
//!
//! The server already lists signers' device-key records and fetches their
//! repository proofs from each signer's PDS, for the retired-key check and
//! the peer key fetch. These two tables keep what those reads download, so a
//! restart does not download it all again and an unreachable PDS still has
//! its last good copy served.
//!
//! `record_listings` holds one account's listing of one collection as the PDS
//! gave it, with the `#atproto` key of the DID document it was listed under.
//! `record_proofs` holds each checked proof's CAR bytes by record CID, with
//! the repo key it checked under. Both hold only what the PDS serves to
//! anyone, and are stored in plaintext.
//!
//! Down: none. The tables are a cache; a migration below this rung fails
//! loudly rather than dropping them.

use rusqlite_migration::M;

pub(super) fn migration() -> M<'static> {
    // IF NOT EXISTS: a converged schema whose stamp was lost already has the
    // tables, and that counts as done.
    M::up(
        "CREATE TABLE IF NOT EXISTS record_listings (
             did           TEXT NOT NULL,
             collection    TEXT NOT NULL,
             entries_json  TEXT NOT NULL,
             repo_key      TEXT NOT NULL,
             fetched_at    INTEGER NOT NULL,
             last_asked_at INTEGER NOT NULL,
             PRIMARY KEY (did, collection)
         );
         CREATE TABLE IF NOT EXISTS record_proofs (
             cid        TEXT PRIMARY KEY,
             did        TEXT NOT NULL,
             collection TEXT NOT NULL,
             rkey       TEXT NOT NULL,
             car        BLOB NOT NULL,
             repo_key   TEXT NOT NULL,
             fetched_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_record_proofs_did ON record_proofs(did, collection);",
    )
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn up_adds_the_record_cache_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 14).unwrap();
        assert!(
            columns(&conn, "record_listings").is_empty(),
            "the tables arrive at rung 15"
        );

        migration_ladder().to_version(&mut conn, 15).unwrap();
        for (table, expected) in [
            (
                "record_listings",
                &[
                    "did",
                    "collection",
                    "entries_json",
                    "repo_key",
                    "fetched_at",
                    "last_asked_at",
                ][..],
            ),
            (
                "record_proofs",
                &[
                    "cid",
                    "did",
                    "collection",
                    "rkey",
                    "car",
                    "repo_key",
                    "fetched_at",
                ][..],
            ),
        ] {
            let after = columns(&conn, table);
            for column in expected {
                assert!(
                    after.iter().any(|c| c == column),
                    "migration 15 must create `{table}.{column}`; got {after:?}"
                );
            }
        }
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 15).unwrap();
        conn.execute_batch("PRAGMA user_version = 14").unwrap();
        migration_ladder()
            .to_version(&mut conn, 15)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
