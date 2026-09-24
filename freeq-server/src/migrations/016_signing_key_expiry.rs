//! Migration 16: when each signing key on file stops counting.
//!
//! Every key this server holds expires, by default 90 days after it was
//! first filed here, except the keys whose owner rotates them: this server's
//! own keys, another server's own key, and a bot's did:key. `expires_at` is
//! that date in unix seconds, NULL for a key that never expires.
//!
//! Existing rows get `registered_at` plus 90 days — the record rules' default,
//! since a rung cannot read the server's configured lifetime. A `did:key:`
//! row whose key is the did:key's own stays NULL; that is decided here, since
//! SQL cannot decode the DID. This server's own rows and `did-document` rows
//! are made NULL at every start (`Db::exempt_own_and_document_keys`), since a
//! rung does not know the server's name either.
//!
//! Down: none. Dropping the column would discard the expiry of keys copied
//! from a peer that sent one, so a migration below this rung fails loudly.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

/// The record rules' default lifetime, in seconds.
const DEFAULT_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        // SQLite has no `ADD COLUMN IF NOT EXISTS`: a converged schema whose
        // stamp was lost already has the column, and that counts as done.
        match tx.execute("ALTER TABLE signing_keys ADD COLUMN expires_at INTEGER", []) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "UPDATE signing_keys SET expires_at = registered_at + ?1 WHERE expires_at IS NULL",
            [DEFAULT_LIFETIME_SECS],
        )?;
        // By DID and key bytes, not kid: a database older than the kid column
        // climbs the ladder before `Db::init` converts its table.
        let own_keys: Vec<(String, Vec<u8>)> = {
            let mut stmt =
                tx.prepare("SELECT did, pubkey FROM signing_keys WHERE did LIKE 'did:key:%'")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(did, pubkey)| crate::db::is_did_key_own_key(did, pubkey))
                .collect()
        };
        for (did, pubkey) in own_keys {
            tx.execute(
                "UPDATE signing_keys SET expires_at = NULL WHERE did = ?1 AND pubkey = ?2",
                rusqlite::params![did, pubkey],
            )?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    const DAY: i64 = 24 * 60 * 60;

    fn insert(conn: &Connection, did: &str, pubkey: &[u8; 32], registered_at: i64) -> String {
        let kid = freeq_sdk::sigtag::derive_kid_bytes(pubkey);
        conn.execute(
            "INSERT INTO signing_keys (did, kid, pubkey, registered_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            rusqlite::params![did, kid, pubkey.as_slice(), registered_at],
        )
        .unwrap();
        kid
    }

    fn expiry(conn: &Connection, did: &str, kid: &str) -> Option<i64> {
        conn.query_row(
            "SELECT expires_at FROM signing_keys WHERE did = ?1 AND kid = ?2",
            [did, kid],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn up_adds_the_column_and_dates_every_key_but_a_did_keys_own() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 15).unwrap();

        let session = [3u8; 32];
        let user = insert(&conn, "did:plc:alice", &session, 1_000_000);
        let bot = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let bot_did = format!(
            "did:key:{}",
            freeq_sdk::crypto::PublicKey::Ed25519(bot.verifying_key()).to_multibase()
        );
        let own = insert(&conn, &bot_did, bot.verifying_key().as_bytes(), 2_000_000);
        // A per-connect session key under the bot's DID is not its own key.
        let bot_session = insert(&conn, &bot_did, &[4u8; 32], 3_000_000);

        migration_ladder().to_version(&mut conn, 16).unwrap();

        assert_eq!(
            expiry(&conn, "did:plc:alice", &user),
            Some(1_000_000 + 90 * DAY)
        );
        assert_eq!(expiry(&conn, &bot_did, &own), None);
        assert_eq!(
            expiry(&conn, &bot_did, &bot_session),
            Some(3_000_000 + 90 * DAY)
        );
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 16).unwrap();
        conn.execute_batch("PRAGMA user_version = 15").unwrap();
        migration_ladder()
            .to_version(&mut conn, 16)
            .expect("a converged schema with a lost stamp climbs anyway");
    }
}
