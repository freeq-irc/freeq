//! SQLite persistence layer.
//!
//! Stores message history, channel state, bans, and DID-nick identity bindings.
//! Uses WAL mode for concurrent reads during writes.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};

use crate::server::{BanEntry, ChannelState, TopicInfo};

/// Prefix for encrypted-at-rest message content.
const EAR_PREFIX: &str = "EAR1:";

/// Encrypt text with AES-256-GCM for storage at rest.
/// Panics on encryption failure — this indicates a broken key or AES implementation
/// and must not silently degrade to plaintext storage.
fn encrypt_at_rest(key: &[u8; 32], plaintext: &str) -> String {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("AES-256-GCM encryption failed — this should never happen with a valid key");
    use base64::Engine;
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    format!(
        "{EAR_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(&combined)
    )
}

/// Decrypt text from at-rest storage.
/// Legacy unencrypted data (without EAR1: prefix) is returned as-is with a warning.
/// Decryption failures on encrypted data return an error placeholder and log at ERROR.
fn decrypt_at_rest(key: &[u8; 32], stored: &str) -> String {
    if !stored.starts_with(EAR_PREFIX) {
        // Legacy plaintext data — return as-is but log so operators can identify
        // unencrypted records during migration.
        if !stored.is_empty() {
            tracing::debug!(
                "Returning unencrypted legacy message — consider re-encrypting historical data"
            );
        }
        return stored.to_string();
    }
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use base64::Engine;
    let b64 = &stored[EAR_PREFIX.len()..];
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(combined) if combined.len() > 12 => {
            let nonce = Nonce::from_slice(&combined[..12]);
            let ct = &combined[12..];
            let cipher = Aes256Gcm::new(key.into());
            match cipher.decrypt(nonce, ct) {
                Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
                Err(e) => {
                    tracing::error!(
                        "Decryption failed (wrong key or corrupt data): {e} — \
                         returning placeholder. Check db-encryption-key.secret."
                    );
                    "[decryption failed]".to_string()
                }
            }
        }
        _ => {
            tracing::error!("Malformed encrypted message (bad base64 or too short)");
            "[decryption failed]".to_string()
        }
    }
}

/// Convert a user-supplied search string into a safe FTS5 query.
/// Each whitespace-separated term becomes a quoted phrase (embedded quotes
/// doubled), joined by implicit AND. FTS5 operators (OR, NEAR, *, etc.) in
/// user input are matched literally rather than interpreted.
fn sanitize_fts_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compute a canonical DM channel key from two DIDs.
/// The key is `dm:<did_a>,<did_b>` where the DIDs are alphabetically sorted.
/// This ensures both participants produce the same key regardless of who sends.
///
/// The same string is a DM's **signing venue** (`freeq_sdk::chatsig::dm_venue`),
/// which is why this delegates rather than reimplementing: a persistence key
/// and a signed venue that disagreed by one byte would make every DM signature
/// unverifiable on one side of the conversation.
pub fn canonical_dm_key(did_a: &str, did_b: &str) -> String {
    freeq_sdk::chatsig::dm_venue(did_a, did_b)
}

/// Database handle wrapping a SQLite connection.
pub struct Db {
    conn: Connection,
    /// AES-256-GCM key for encrypting message content at rest.
    /// Derived from the server's signing key. If None, messages stored as plaintext.
    encryption_key: Option<[u8; 32]>,
}

/// A persisted reaction row.
#[derive(Debug, Clone)]
pub struct ReactionRow {
    pub target_msgid: String,
    pub channel: String,
    pub reactor_nick: String,
    pub reactor_did: Option<String>,
    pub emoji: String,
    pub timestamp: u64,
}

/// Who wrote a message, and where it is filed — the minimum needed to
/// authorize an operation on a message without reading its contents.
#[derive(Debug, Clone)]
pub struct MessageAuthorship {
    /// The channel key the row is filed under, spelled as it was stored.
    pub channel: String,
    /// Full hostmask of the author, as stored.
    pub sender: String,
    /// Author's DID, when they were authenticated at send time.
    pub sender_did: Option<String>,
    /// Whether the message is already soft-deleted.
    pub deleted: bool,
}

/// A persisted message row.
#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: i64,
    pub channel: String,
    pub sender: String,
    pub text: String,
    pub timestamp: u64,
    pub tags: HashMap<String, String>,
    /// ULID message ID (IRCv3 `msgid` tag).
    pub msgid: Option<String>,
    /// If this is an edit, the msgid of the original message it replaces.
    pub replaces_msgid: Option<String>,
    /// The identity of the logical message this row is a revision of — the
    /// original msgid, and equal to `msgid` for an original. NULL only on rows
    /// old enough to have no msgid at all.
    pub root_msgid: Option<String>,
    /// Unix timestamp when this message was deleted (soft delete).
    pub deleted_at: Option<u64>,
    /// DID of the sender (if authenticated at send time).
    pub sender_did: Option<String>,
}

/// A persisted private-media metadata row. The bytes themselves live
/// encrypted-at-rest on disk (see `media_store`); this is just the index.
#[derive(Debug, Clone)]
pub struct MediaRow {
    pub id: String,
    pub uploader_did: String,
    /// Channel name or `canonical_dm_key` the media was uploaded to.
    pub scope: String,
    pub mime: String,
    pub size: u64,
    pub alt: Option<String>,
    pub filename: String,
    pub created_at: u64,
    pub deleted_at: Option<u64>,
}

/// A persisted identity (DID-nick binding).
#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub did: String,
    pub nick: String,
}

/// What an event row is made of, at the moment of filing.
///
/// Two shapes, and no way to supply both: an event either has signed bytes —
/// in which case they are the record and every column comes out of them — or
/// it has none, in which case the facts the caller states are the record.
pub enum EventShape<'a> {
    /// The exact canonical bytes a signature covers. Queryable columns are
    /// read back out of these, never taken on the caller's word.
    Document(&'a str),
    /// Nothing signed this: a guest's event, or an event outside the signing
    /// model. There is no canonical to store and none to derive from.
    Bare(crate::events::EventFacts),
}

/// An event on its way into the log.
pub struct EventRecord<'a> {
    pub shape: EventShape<'a>,
    /// The signature, verbatim. `None` when nothing signed this.
    pub signature: Option<&'a str>,
    /// Facts about receipt: the verdict reached, and the peer that relayed it.
    pub ctx: crate::events::EventContext,
    /// When this server accepted the event. Not in any document — a chat
    /// document deliberately carries no wall clock.
    pub timestamp: u64,
}

/// A mutation on its way into the log, alongside the derived-table change it
/// makes.
///
/// A delete, a reaction, an unreaction and a pin all change a derived table
/// *and* are events in their own right. The pair is written together, so the
/// record of who did it survives even when what they did was to remove
/// something — which is the whole point: an unreaction used to delete the
/// reaction row and leave nothing at all.
pub struct MutationEvent<'a> {
    /// This event's own id: the signer's where there was one, otherwise one
    /// this server minted so the act still has an identity.
    pub event_id: &'a str,
    /// The proven actor. `None` for a guest, who has no identity to bind.
    pub actor_did: Option<&'a str>,
    /// The signature, verbatim — the sender's own, or this server vouching.
    pub signature: Option<&'a str>,
    /// The venue the signature covers, as ingress worked it out. A DM's is the
    /// sorted DID pair, which the wire target never spells: the target is a
    /// nick or a `did:` depending on who addressed whom. `None` when the caller
    /// has no venue to offer (a guest, an unresolvable recipient), and the
    /// channel the change lands in is then the best the row can say.
    pub venue: Option<&'a str>,
    pub ctx: crate::events::EventContext,
    pub timestamp: u64,
}

/// An event read back out of the log.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub event_id: String,
    /// Empty when nothing signed this event.
    pub canonical: String,
    pub signature: Option<String>,
    pub sig_state: crate::events::SigState,
    pub kind: String,
    pub venue: String,
    pub actor_did: Option<String>,
    pub subject: Option<String>,
    pub body_hash: Option<String>,
    /// A reaction's emoji.
    pub emoji: Option<String>,
    pub origin: Option<String>,
    /// Fingerprint of a dropped second claim on this id, if there was one.
    pub conflict: Option<String>,
    pub timestamp: u64,
}

fn map_stored_event(row: &rusqlite::Row<'_>) -> SqlResult<StoredEvent> {
    Ok(StoredEvent {
        event_id: row.get(0)?,
        canonical: row.get(1)?,
        signature: row.get(2)?,
        sig_state: crate::events::SigState::parse(&row.get::<_, String>(3)?),
        kind: row.get(4)?,
        venue: row.get(5)?,
        actor_did: row.get(6)?,
        subject: row.get(7)?,
        body_hash: row.get(8)?,
        emoji: row.get(9)?,
        origin: row.get(10)?,
        conflict: row.get(11)?,
        timestamp: row.get::<_, i64>(12)? as u64,
    })
}

impl Db {
    /// Open (or create) the database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let mut db = Self {
            conn,
            encryption_key: None,
        };
        db.init()?;
        Ok(db)
    }

    /// Open a database with encryption at rest for message content.
    pub fn open_encrypted<P: AsRef<Path>>(path: P, key: [u8; 32]) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let mut db = Self {
            conn,
            encryption_key: Some(key),
        };
        db.init()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let mut db = Self {
            conn,
            encryption_key: None,
        };
        db.init()?;
        Ok(db)
    }

    /// Open an in-memory database with encryption at rest (for testing).
    pub fn open_encrypted_memory(key: [u8; 32]) -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let mut db = Self {
            conn,
            encryption_key: Some(key),
        };
        db.init()?;
        Ok(db)
    }

    /// Test helper: an in-memory DB whose `signing_keys` starts in the OLD
    /// (pre-kid, PK=did) schema with one row, so `init()`'s migration runs and
    /// backfills the kid — mirrors a real pre-migration database on first open.
    #[cfg(test)]
    pub(crate) fn open_memory_with_legacy_signing_keys() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE signing_keys (
                 did           TEXT PRIMARY KEY,
                 pubkey        BLOB NOT NULL,
                 registered_at INTEGER NOT NULL
             );",
        )?;
        conn.execute(
            "INSERT INTO signing_keys (did, pubkey, registered_at) VALUES ('did:plc:legacy', ?1, 0)",
            params![&[7u8; 32][..]],
        )?;
        let mut db = Self {
            conn,
            encryption_key: None,
        };
        db.init()?;
        Ok(db)
    }

    /// One-time migration: the `signing_keys` table gained a `kid` column and a
    /// composite PK `(did, kid)` so a DID's keys form an append-only history
    /// (was PK `did`, overwrite-on-reregister). Old databases have no `kid`
    /// column; since `ALTER` can't change a PK, copy the rows into a fresh table
    /// and backfill `kid = derive_kid_bytes(pubkey)`. A no-op once migrated.
    fn migrate_signing_keys_to_kid_history(&self) -> SqlResult<()> {
        let has_kid: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('signing_keys') WHERE name = 'kid'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if has_kid {
            return Ok(());
        }

        let legacy: Vec<(String, Vec<u8>, i64)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT did, pubkey, registered_at FROM signing_keys")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            rows.collect::<SqlResult<Vec<_>>>()?
        };
        // Transactional: DROP + CREATE + backfill commit atomically, so a crash
        // mid-migration can't leave the table dropped with the keys unrestored —
        // the durable signing keys are the exact asset this store exists for.
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "DROP TABLE signing_keys;
             CREATE TABLE signing_keys (
                 did            TEXT NOT NULL,
                 kid            TEXT NOT NULL,
                 pubkey         BLOB NOT NULL,
                 registered_at  INTEGER NOT NULL,
                 PRIMARY KEY (did, kid)
             );",
        )?;
        for (did, pubkey, registered_at) in legacy {
            let kid = freeq_sdk::act::derive_kid_bytes(&pubkey);
            tx.execute(
                "INSERT OR IGNORE INTO signing_keys (did, kid, pubkey, registered_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![did, kid, pubkey, registered_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The root msgid of the logical message `msgid` belongs to — its identity
    /// for life, unchanged by edits. An id with no row (an unpersisted guest-DM
    /// message) is its own root.
    ///
    /// This is the single definition of "the same message"; reactions, pins and
    /// deletes all file and look up by what it returns.
    ///
    /// Deliberately not channel-scoped: a ULID is globally unique, so the id
    /// alone identifies the row. `migration_root_of` is channel-scoped only
    /// because the backfill iterates per channel.
    pub fn root_of(&self, msgid: &str) -> String {
        self.conn
            .query_row(
                "SELECT root_msgid, msgid FROM messages WHERE msgid = ?1 LIMIT 1",
                params![msgid],
                |r| {
                    let root: Option<String> = r.get(0)?;
                    let own: Option<String> = r.get(1)?;
                    Ok(root.or(own))
                },
            )
            .ok()
            .flatten()
            .unwrap_or_else(|| msgid.to_string())
    }

    fn init(&mut self) -> SqlResult<()> {
        self.conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        self.conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        // The migration ladder owns everything durable: the schema baseline
        // (migration 1) and one-time data migrations (2+). It runs right
        // after the per-connection pragmas; everything below may assume
        // fully-shaped tables.
        //
        // Announced in the log, because a data migration over a large table
        // can hold startup for a while and a silent boot invites an abort —
        // and because "did it migrate?" should be answerable from the
        // journal, not by opening the database.
        let schema_before: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if schema_before < crate::migrations::ladder_top() as i64 {
            tracing::info!(
                from = schema_before,
                to = crate::migrations::ladder_top(),
                "migrating schema — may take a while on a large database; interrupting is safe (each rung is one transaction and rolls back whole)"
            );
        }
        crate::migrations::migration_ladder()
            .to_latest(&mut self.conn)
            .map_err(|e| match e {
                rusqlite_migration::Error::RusqliteError { err, .. } => err,
                other => rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                    Some(other.to_string()),
                ),
            })?;
        let schema_after: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if schema_before != schema_after {
            tracing::info!(
                from = schema_before,
                to = schema_after,
                "schema migrated at startup (each rung is one transaction; an interrupt rolls back to the previous rung)"
            );
        }

        // Outside the ladder on purpose: it manages its own transaction,
        // which the ladder's per-migration transaction cannot nest.
        self.migrate_signing_keys_to_kid_history()?;

        // Outside the ladder on purpose: whether the FTS index exists
        // depends on the at-rest encryption key (opening encrypted drops a
        // stale plaintext index) — state, not schema.
        self.init_fts()?;

        Ok(())
    }

    // ── Full-text search (FTS5) ────────────────────────────────────────
    //
    // The FTS index holds message plaintext, so it only exists when at-rest
    // encryption is OFF. Opening an encrypted database drops any index left
    // behind by a previous plaintext run, ensuring no plaintext survives the
    // switch to encryption. Encrypted databases fall back to a bounded
    // decrypt-and-scan in `search_messages`.

    /// Maximum rows decrypt-and-scanned per search on encrypted databases.
    const SEARCH_SCAN_CAP: usize = 10_000;

    fn fts_enabled(&self) -> bool {
        self.encryption_key.is_none()
    }

    fn init_fts(&self) -> SqlResult<()> {
        if self.encryption_key.is_some() {
            self.conn
                .execute_batch("DROP TABLE IF EXISTS messages_fts;")?;
            return Ok(());
        }
        self.conn
            .execute_batch("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(text);")?;
        // Backfill: index any messages that predate the FTS table (upgrade
        // path, or a database previously run with encryption enabled).
        self.conn.execute(
            "INSERT INTO messages_fts (rowid, text)
             SELECT id, text FROM messages
             WHERE deleted_at IS NULL
               AND id NOT IN (SELECT rowid FROM messages_fts)",
            [],
        )?;
        Ok(())
    }

    /// Index one message row. No-op when encryption is on.
    fn fts_index(&self, rowid: i64, text: &str) -> SqlResult<()> {
        if self.fts_enabled() {
            self.conn.execute(
                "INSERT OR REPLACE INTO messages_fts (rowid, text) VALUES (?1, ?2)",
                params![rowid, text],
            )?;
        }
        Ok(())
    }

    /// Search messages in a channel (or DM key), newest-first.
    /// `before`: if Some, only messages with timestamp < value (pagination).
    /// Terms are ANDed; FTS5 query syntax in `query` is treated literally.
    pub fn search_messages(
        &self,
        channel: &str,
        query: &str,
        limit: usize,
        before: Option<u64>,
    ) -> SqlResult<Vec<MessageRow>> {
        if self.fts_enabled() {
            let fts_query = sanitize_fts_query(query);
            if fts_query.is_empty() {
                return Ok(vec![]);
            }
            let before_ts = before.map(|b| b as i64).unwrap_or(i64::MAX);
            let mut stmt = self.conn.prepare(
                // Rows come back as themselves (`msgid` = the row's own id,
                // like every other query); the SEARCH and REST handlers
                // re-address hits by `root_msgid` — the id clients hold the
                // message under — when they emit.
                //
                // Superseded revisions are excluded, matching the
                // decrypt-and-scan path below. An edit made since the upgrade
                // leaves the index on its own, but rows indexed before it are
                // still there, and returning them alongside the current one
                // yields two hits for one logical message.
                "SELECT m.id, m.channel, m.sender, m.text, m.timestamp, m.tags_json,
                        m.msgid, m.replaces_msgid, m.deleted_at, m.sender_did, m.root_msgid
                 FROM messages_fts
                 JOIN messages m ON m.id = messages_fts.rowid
                 WHERE messages_fts MATCH ?1
                   AND m.channel = ?2
                   AND m.deleted_at IS NULL
                   AND m.timestamp < ?3
                   AND NOT EXISTS (
                       SELECT 1 FROM messages newer
                       WHERE newer.channel = m.channel
                         AND newer.root_msgid = m.root_msgid
                         AND newer.id > m.id
                   )
                 ORDER BY m.timestamp DESC, m.id DESC
                 LIMIT ?4",
            )?;
            let rows = stmt.query_map(
                params![fts_query, channel, before_ts, limit as i64],
                map_message_row,
            )?;
            return rows.collect::<SqlResult<Vec<_>>>();
        }

        // Encrypted at rest: bounded decrypt-and-scan, newest-first.
        let key = self.encryption_key.as_ref().expect("encrypted branch");
        let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
        if terms.is_empty() {
            return Ok(vec![]);
        }
        let before_ts = before.map(|b| b as i64).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json,
                    msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages m
             WHERE channel = ?1 AND deleted_at IS NULL AND timestamp < ?2
               AND NOT EXISTS (
                   SELECT 1 FROM messages newer
                   WHERE newer.channel = m.channel
                     AND newer.root_msgid = m.root_msgid
                     AND newer.id > m.id
               )
             ORDER BY timestamp DESC, id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![channel, before_ts, Self::SEARCH_SCAN_CAP as i64],
            map_message_row,
        )?;
        let mut matches = Vec::new();
        for row in rows {
            let mut row = row?;
            row.text = decrypt_at_rest(key, &row.text);
            let haystack = row.text.to_lowercase();
            if terms.iter().all(|t| haystack.contains(t)) {
                matches.push(row);
                if matches.len() >= limit {
                    break;
                }
            }
        }
        Ok(matches)
    }

    // ── Channel state ──────────────────────────────────────────────────

    /// Save or update a channel's metadata (topic, modes, key).
    pub fn save_channel(&self, name: &str, ch: &ChannelState) -> SqlResult<()> {
        let did_ops_json = serde_json::to_string(&ch.did_ops.iter().collect::<Vec<_>>())
            .unwrap_or_else(|_| "[]".to_string());
        self.conn.execute(
            "INSERT INTO channels (name, topic_text, topic_set_by, topic_set_at, topic_locked, invite_only, no_ext_msg, moderated, key, founder_did, did_ops_json, encrypted_only)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(name) DO UPDATE SET
                topic_text=excluded.topic_text,
                topic_set_by=excluded.topic_set_by,
                topic_set_at=excluded.topic_set_at,
                topic_locked=excluded.topic_locked,
                invite_only=excluded.invite_only,
                no_ext_msg=excluded.no_ext_msg,
                moderated=excluded.moderated,
                key=excluded.key,
                founder_did=excluded.founder_did,
                did_ops_json=excluded.did_ops_json,
                encrypted_only=excluded.encrypted_only",
            params![
                name,
                ch.topic.as_ref().map(|t| &t.text),
                ch.topic.as_ref().map(|t| &t.set_by),
                ch.topic.as_ref().map(|t| t.set_at as i64),
                ch.topic_locked as i32,
                ch.invite_only as i32,
                ch.no_ext_msg as i32,
                ch.moderated as i32,
                ch.key.as_deref(),
                ch.founder_did.as_deref(),
                did_ops_json,
                ch.encrypted_only as i32,
            ],
        )?;
        Ok(())
    }

    /// Delete a channel from the database (when it becomes empty and should be cleaned up).
    pub fn delete_channel(&self, name: &str) -> SqlResult<()> {
        self.conn
            .execute("DELETE FROM channels WHERE name = ?1", params![name])?;
        self.conn
            .execute("DELETE FROM bans WHERE channel = ?1", params![name])?;
        self.conn.execute(
            "DELETE FROM invite_exceptions WHERE channel = ?1",
            params![name],
        )?;
        Ok(())
    }

    /// Load all persisted channels (metadata + bans). Does not load messages
    /// or runtime-only state (members, ops, voiced, invites).
    pub fn load_channels(&self) -> SqlResult<HashMap<String, ChannelState>> {
        let mut channels = HashMap::new();

        let mut stmt = self.conn.prepare(
            "SELECT name, topic_text, topic_set_by, topic_set_at, topic_locked, invite_only, key, no_ext_msg, moderated, founder_did, did_ops_json, encrypted_only
             FROM channels"
        )?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let topic_text: Option<String> = row.get(1)?;
            let topic_set_by: Option<String> = row.get(2)?;
            let topic_set_at: Option<i64> = row.get(3)?;
            let topic_locked: bool = row.get::<_, i32>(4)? != 0;
            let invite_only: bool = row.get::<_, i32>(5)? != 0;
            let key: Option<String> = row.get(6)?;
            let no_ext_msg: bool = row.get::<_, Option<i32>>(7)?.unwrap_or(0) != 0;
            let moderated: bool = row.get::<_, Option<i32>>(8)?.unwrap_or(0) != 0;
            let founder_did: Option<String> = row.get(9)?;
            let did_ops_json: String = row
                .get::<_, Option<String>>(10)?
                .unwrap_or_else(|| "[]".to_string());
            let encrypted_only: bool = row.get::<_, Option<i32>>(11)?.unwrap_or(0) != 0;

            let topic = match (topic_text, topic_set_by, topic_set_at) {
                (Some(text), Some(set_by), Some(set_at)) => Some(TopicInfo {
                    text,
                    set_by,
                    set_at: set_at as u64,
                }),
                _ => None,
            };

            let did_ops: std::collections::HashSet<String> =
                serde_json::from_str(&did_ops_json).unwrap_or_default();

            let ch = ChannelState {
                topic,
                topic_locked,
                invite_only,
                no_ext_msg,
                moderated,
                key,
                founder_did,
                did_ops,
                encrypted_only,
                ..Default::default()
            };
            Ok((name, ch))
        })?;

        for row in rows {
            let (name, ch) = row?;
            channels.insert(name, ch);
        }

        // Load bans
        let mut stmt = self
            .conn
            .prepare("SELECT channel, mask, set_by, set_at FROM bans")?;
        let ban_rows = stmt.query_map([], |row| {
            let channel: String = row.get(0)?;
            let mask: String = row.get(1)?;
            let set_by: String = row.get(2)?;
            let set_at: i64 = row.get(3)?;
            Ok((
                channel,
                BanEntry {
                    mask,
                    set_by,
                    set_at: set_at as u64,
                },
            ))
        })?;

        for row in ban_rows {
            let (channel, ban) = row?;
            if let Some(ch) = channels.get_mut(&channel) {
                ch.bans.push(ban);
            }
        }

        // Load invite exceptions (+I)
        let mut stmt = self
            .conn
            .prepare("SELECT channel, mask, set_by, set_at FROM invite_exceptions")?;
        let invex_rows = stmt.query_map([], |row| {
            let channel: String = row.get(0)?;
            let mask: String = row.get(1)?;
            let set_by: String = row.get(2)?;
            let set_at: i64 = row.get(3)?;
            Ok((
                channel,
                crate::server::InviteExceptionEntry {
                    mask,
                    set_by,
                    set_at: set_at as u64,
                },
            ))
        })?;

        for row in invex_rows {
            let (channel, entry) = row?;
            if let Some(ch) = channels.get_mut(&channel) {
                ch.invite_exceptions.push(entry);
            }
        }

        // Load pins
        let mut stmt = self.conn.prepare(
            "SELECT channel, msgid, pinned_by, pinned_at FROM pins ORDER BY pinned_at DESC",
        )?;
        let pin_rows = stmt.query_map([], |row| {
            let channel: String = row.get(0)?;
            let msgid: String = row.get(1)?;
            let pinned_by: String = row.get(2)?;
            let pinned_at: i64 = row.get(3)?;
            Ok((
                channel,
                crate::server::PinnedMessage {
                    msgid,
                    pinned_by,
                    pinned_at: pinned_at as u64,
                },
            ))
        })?;

        for row in pin_rows {
            let (channel, pin) = row?;
            if let Some(ch) = channels.get_mut(&channel) {
                ch.pins.push(pin);
            }
        }

        Ok(channels)
    }

    // ── Bans ───────────────────────────────────────────────────────────

    /// Add a ban to a channel.
    pub fn add_ban(&self, channel: &str, ban: &BanEntry) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO bans (channel, mask, set_by, set_at) VALUES (?1, ?2, ?3, ?4)",
            params![channel, ban.mask, ban.set_by, ban.set_at as i64],
        )?;
        Ok(())
    }

    /// Remove a ban from a channel.
    pub fn remove_ban(&self, channel: &str, mask: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM bans WHERE channel = ?1 AND mask = ?2",
            params![channel, mask],
        )?;
        Ok(())
    }

    // ── Invite exceptions (+I) ─────────────────────────────────────────

    /// Add an invite-exception entry to a channel.
    pub fn add_invite_exception(
        &self,
        channel: &str,
        entry: &crate::server::InviteExceptionEntry,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO invite_exceptions (channel, mask, set_by, set_at) VALUES (?1, ?2, ?3, ?4)",
            params![channel, entry.mask, entry.set_by, entry.set_at as i64],
        )?;
        Ok(())
    }

    /// Remove an invite-exception entry from a channel.
    pub fn remove_invite_exception(&self, channel: &str, mask: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM invite_exceptions WHERE channel = ?1 AND mask = ?2",
            params![channel, mask],
        )?;
        Ok(())
    }

    // ── Messages ───────────────────────────────────────────────────────

    /// Store a message.
    /// Returns whether a row was written — `false` when the msgid was
    /// already on file (first write wins; callers must not present a
    /// message the store refused).
    pub fn insert_message(
        &self,
        channel: &str,
        sender: &str,
        text: &str,
        timestamp: u64,
        tags: &HashMap<String, String>,
        msgid: Option<&str>,
        sender_did: Option<&str>,
    ) -> SqlResult<bool> {
        self.insert_message_with(
            channel,
            sender,
            text,
            timestamp,
            tags,
            msgid,
            sender_did,
            &crate::events::EventContext::default(),
        )
    }

    /// [`Db::insert_message`], plus what this server concluded about the
    /// message's signature and where it came from — the facts the event log
    /// cannot derive from the document. Ingress paths use this; anything with
    /// no verdict to state uses the shorter form and gets the state that
    /// claims least.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message_with(
        &self,
        channel: &str,
        sender: &str,
        text: &str,
        timestamp: u64,
        tags: &HashMap<String, String>,
        msgid: Option<&str>,
        sender_did: Option<&str>,
        ctx: &crate::events::EventContext,
    ) -> SqlResult<bool> {
        let tags_json = serde_json::to_string(tags).unwrap_or_else(|_| "{}".to_string());
        let stored_text = if let Some(ref key) = self.encryption_key {
            encrypt_at_rest(key, text)
        } else {
            text.to_string()
        };
        // The message row and its event are one write or neither: a message
        // present in history with no event would be a hole in the log that
        // nothing later could tell from a message that never happened.
        let tx = self.conn.unchecked_transaction()?;
        // An original message is its own root — its identity for life.
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (channel, sender, text, timestamp, tags_json, msgid, root_msgid, sender_did)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
            params![
                channel,
                sender,
                stored_text,
                timestamp as i64,
                tags_json,
                msgid,
                sender_did
            ],
        )?;
        if self.conn.changes() == 0 {
            // The msgid is already on file. First write wins either way, and
            // `last_insert_rowid()` still names an earlier row, so neither
            // the recorder nor the search index may run — but same-content
            // (a peer re-delivering) and different-content (a conflicting
            // claim on an identity) deserve very different log lines.
            let conflicting = msgid
                .and_then(|id| self.find_message_by_msgid(id).ok().flatten())
                .is_some_and(|row| row.text != text);
            if conflicting {
                tracing::warn!(
                    ?msgid,
                    channel,
                    "msgid already on file with DIFFERENT content; conflicting insert dropped"
                );
                // The receipt: what was dropped, so that two claims on one id
                // leaves a trace instead of vanishing.
                if let Some(id) = msgid {
                    self.record_event_conflict(
                        id,
                        &self.claim_fingerprint(channel, text, tags, sender_did, id, None),
                    )?;
                }
            } else {
                tracing::debug!(?msgid, channel, "duplicate delivery; insert ignored");
            }
            tx.commit()?;
            return Ok(false);
        }
        self.file_message_event(channel, text, tags, msgid, sender_did, None, timestamp, ctx)?;
        // Record into the agent-assist diagnostic ring buffer. We
        // capture only the fact that a message was accepted — never
        // the body or tags. The auto-increment row id is the canonical
        // server sequence used by `diagnose_message_ordering`.
        let mut ev = crate::agent_assist::recorder::DiagnosticEvent::now(
            crate::agent_assist::recorder::EventKind::MessageAccepted,
        );
        ev.channel = Some(channel.to_string());
        ev.msgid = msgid.map(|s| s.to_string());
        ev.did = sender_did.map(|s| s.to_string());
        ev.server_sequence = Some(self.conn.last_insert_rowid());
        crate::agent_assist::recorder::record(ev);
        self.fts_index(self.conn.last_insert_rowid(), text)?;
        tx.commit()?;
        Ok(true)
    }

    /// Fetch recent messages for a channel, ordered oldest-first.
    /// `limit`: max number of messages to return.
    /// `before`: if Some, only return messages with timestamp < this value (for pagination).
    pub fn get_messages(
        &self,
        channel: &str,
        limit: usize,
        before: Option<u64>,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut rows_vec = if let Some(before_ts) = before {
            let mut stmt = self.conn.prepare(
                "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
                 FROM messages
                 WHERE channel = ?1 AND deleted_at IS NULL AND timestamp < ?2
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ?3"
            )?;
            let rows = stmt.query_map(
                params![channel, before_ts as i64, limit as i64],
                map_message_row,
            )?;
            rows.collect::<SqlResult<Vec<_>>>()?
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
                 FROM messages
                 WHERE channel = ?1 AND deleted_at IS NULL
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ?2"
            )?;
            let rows = stmt.query_map(params![channel, limit as i64], map_message_row)?;
            rows.collect::<SqlResult<Vec<_>>>()?
        };
        // Reverse to oldest-first order
        rows_vec.reverse();
        // Decrypt at-rest encryption if enabled
        if let Some(ref key) = self.encryption_key {
            for row in &mut rows_vec {
                row.text = decrypt_at_rest(key, &row.text);
            }
        }
        Ok(rows_vec)
    }

    /// Get messages after a timestamp (oldest first).
    pub fn get_messages_after(
        &self,
        channel: &str,
        after: u64,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL AND timestamp > ?2
             ORDER BY timestamp ASC, id ASC
             LIMIT ?3"
        )?;
        let rows = stmt.query_map(
            params![channel, after as i64, limit as i64],
            map_message_row,
        )?;
        let mut result = rows.collect::<SqlResult<Vec<_>>>()?;
        if let Some(ref key) = self.encryption_key {
            for row in &mut result {
                row.text = decrypt_at_rest(key, &row.text);
            }
        }
        Ok(result)
    }

    /// Get messages between two timestamps (oldest first).
    pub fn get_messages_between(
        &self,
        channel: &str,
        after: u64,
        before: u64,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL AND timestamp > ?2 AND timestamp < ?3
             ORDER BY timestamp ASC, id ASC
             LIMIT ?4"
        )?;
        let rows = stmt.query_map(
            params![channel, after as i64, before as i64, limit as i64],
            map_message_row,
        )?;
        let mut result = rows.collect::<SqlResult<Vec<_>>>()?;
        if let Some(ref key) = self.encryption_key {
            for row in &mut result {
                row.text = decrypt_at_rest(key, &row.text);
            }
        }
        Ok(result)
    }

    /// Prune old messages for a channel, keeping only the most recent `max_keep`.
    pub fn prune_messages(&self, channel: &str, max_keep: usize) -> SqlResult<()> {
        if self.fts_enabled() {
            self.conn.execute(
                "DELETE FROM messages_fts WHERE rowid IN (
                    SELECT id FROM messages WHERE channel = ?1 AND id NOT IN (
                        SELECT id FROM messages WHERE channel = ?1 ORDER BY timestamp DESC, id DESC LIMIT ?2
                    )
                )",
                params![channel, max_keep as i64],
            )?;
        }
        self.conn.execute(
            "DELETE FROM messages WHERE channel = ?1 AND id NOT IN (
                SELECT id FROM messages WHERE channel = ?1 ORDER BY timestamp DESC, id DESC LIMIT ?2
            )",
            params![channel, max_keep as i64],
        )?;
        Ok(())
    }

    /// Retention: delete all messages older than `cutoff_ts` (unix seconds)
    /// across every channel. Returns the number of rows removed. Keeps the FTS
    /// index consistent. Used by the age-based retention task (opt-in).
    pub fn prune_messages_older_than(&self, cutoff_ts: u64) -> SqlResult<usize> {
        if self.fts_enabled() {
            self.conn.execute(
                "DELETE FROM messages_fts WHERE rowid IN (
                    SELECT id FROM messages WHERE timestamp < ?1
                )",
                params![cutoff_ts as i64],
            )?;
        }
        let n = self.conn.execute(
            "DELETE FROM messages WHERE timestamp < ?1",
            params![cutoff_ts as i64],
        )?;
        Ok(n)
    }

    /// Find a message by its msgid. Returns the sender (hostmask) for authorship check.
    pub fn get_message_by_msgid(
        &self,
        channel: &str,
        msgid: &str,
    ) -> SqlResult<Option<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND msgid = ?2
             LIMIT 1"
        )?;
        let mut rows = stmt.query_map(params![channel, msgid], map_message_row)?;
        match rows.next() {
            Some(row) => {
                let mut msg = row?;
                if let Some(ref key) = self.encryption_key {
                    msg.text = decrypt_at_rest(key, &msg.text);
                }
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Find a message by msgid across all channels.
    pub fn find_message_by_msgid(&self, msgid: &str) -> SqlResult<Option<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE msgid = ?1 AND deleted_at IS NULL
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![msgid], map_message_row)?;
        match rows.next() {
            Some(row) => {
                let mut msg = row?;
                if let Some(ref key) = self.encryption_key {
                    msg.text = decrypt_at_rest(key, &msg.text);
                }
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Who wrote the logical message `msgid` names, and where it is filed.
    ///
    /// Keyed on `msgid` alone, deliberately. A msgid is a globally unique ULID
    /// and `root_of` already resolves identity without a channel, whereas a
    /// channel name arrives from a peer spelled the way its user typed it and is
    /// stored that way, while the in-memory channel map is keyed lowercase.
    /// Scoping an *authorization* lookup by channel therefore made the answer
    /// depend on that casing — a miss reads as "no such message", which is the
    /// permissive answer. There is no casing of a ULID that finds someone
    /// else's message.
    ///
    /// Resolves to the root first, so naming any revision answers for the
    /// message. Soft-deleted rows are included: an operation on an
    /// already-deleted message still has an author, and callers that must
    /// refuse a deleted target need to be able to see that it is deleted.
    pub fn message_authorship(&self, msgid: &str) -> SqlResult<Option<MessageAuthorship>> {
        let root = self.root_of(msgid);
        let mut stmt = self.conn.prepare(
            "SELECT channel, sender, sender_did, deleted_at FROM messages
             WHERE msgid = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![root], |r| {
            Ok(MessageAuthorship {
                channel: r.get(0)?,
                sender: r.get(1)?,
                sender_did: r.get(2).unwrap_or(None),
                deleted: r.get::<_, Option<i64>>(3).unwrap_or(None).is_some(),
            })
        })?;
        rows.next().transpose()
    }

    /// Whether any row already claims `msgid` — soft-deleted rows and every
    /// revision included.
    ///
    /// The uniqueness half of accepting a **client-minted** id. Deleted rows
    /// count: an id that has been used is spent forever, or a client could
    /// resurrect a deleted message's identity and everything that references
    /// it (a reaction, a pin, a reply) would silently re-point at new text.
    pub fn msgid_taken(&self, msgid: &str) -> SqlResult<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM messages WHERE msgid = ?1 LIMIT 1",
                params![msgid],
                |_| Ok(true),
            )
            .optional()
            .map(|found| found.unwrap_or(false))
    }

    /// The current text of the logical message `msgid` names — the newest
    /// revision, whichever revision was asked for.
    ///
    /// Displays that quote a message (pins, most visibly) need the version the
    /// author last wrote, not the one whose id happens to be on file.
    pub fn current_revision(&self, msgid: &str) -> SqlResult<Option<MessageRow>> {
        let root = self.root_of(msgid);
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE root_msgid = ?1 AND deleted_at IS NULL
             ORDER BY timestamp DESC, id DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![root], map_message_row)?;
        match rows.next() {
            Some(row) => {
                let mut msg = row?;
                if let Some(ref key) = self.encryption_key {
                    msg.text = decrypt_at_rest(key, &msg.text);
                }
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Soft-delete a message *and every revision of it*.
    ///
    /// A message's identity is its original msgid for life (that's the point of
    /// `+draft/edit=<original>`), so a delete names the original while the
    /// current text may live in a later edit row. Marking only the exact msgid
    /// left the newest text — the version the author most wants gone — readable
    /// in CHATHISTORY and in FTS search. Either end of the family may be named:
    /// every row of one logical message carries the same `root_msgid`.
    pub fn soft_delete_message(&self, channel: &str, msgid: &str) -> SqlResult<usize> {
        self.soft_delete_message_by(channel, msgid, None)
    }

    /// [`Db::soft_delete_message`], recording *who* asked.
    ///
    /// A soft delete used to leave no actor at all: the message vanished and
    /// the record of who removed it went with it. The event is the record —
    /// its own id, the acting identity, and the signature that proves the
    /// request came from them.
    pub fn soft_delete_message_by(
        &self,
        channel: &str,
        msgid: &str,
        ev: Option<&MutationEvent<'_>>,
    ) -> SqlResult<usize> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some(ev) = ev {
            self.file_mutation_event(
                freeq_sdk::chatsig::Mutation::Delete,
                channel,
                msgid,
                None,
                ev,
            )?;
        }
        let changed = self.soft_delete_rows(channel, msgid)?;
        tx.commit()?;
        Ok(changed)
    }

    fn soft_delete_rows(&self, channel: &str, msgid: &str) -> SqlResult<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let root = self.root_of(msgid);

        // The msgids of every revision. Pins and reactions are filed under the
        // root, but a row written before that was true may still name a
        // revision, so the sweeps below clear the whole set.
        let family: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT msgid FROM messages
                 WHERE channel = ?1 AND root_msgid = ?2 AND msgid IS NOT NULL",
            )?;
            let mut rows: Vec<String> = stmt
                .query_map(params![channel, &root], |r| r.get(0))?
                .collect::<SqlResult<Vec<String>>>()?;
            if !rows.iter().any(|m| m == &root) {
                rows.push(root.clone());
            }
            rows
        };

        // Resolve to row ids first so the FTS delete and the UPDATE act on
        // exactly the same set, with uniformly-typed bind parameters.
        let ph = family.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM messages
                 WHERE channel = ?1 AND deleted_at IS NULL AND root_msgid = ?2",
            )?;
            stmt.query_map(params![channel, &root], |r| r.get(0))?
                .collect::<SqlResult<Vec<i64>>>()?
        };
        if ids.is_empty() {
            return Ok(0);
        }

        let id_ph = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        if self.fts_enabled() {
            self.conn.execute(
                &format!("DELETE FROM messages_fts WHERE rowid IN ({id_ph})"),
                rusqlite::params_from_iter(ids.iter()),
            )?;
        }
        let mut binds: Vec<i64> = Vec::with_capacity(ids.len() + 1);
        binds.push(now as i64);
        binds.extend(ids.iter().copied());
        let changed = self.conn.execute(
            &format!("UPDATE messages SET deleted_at = ? WHERE id IN ({id_ph})"),
            rusqlite::params_from_iter(binds.iter()),
        )?;

        // A deleted message must not stay pinned. `handle_delete` only purges
        // the in-memory `ch.pins`, and pins are reloaded from this table on
        // startup — so without this the channel advertises a pin whose message
        // no longer exists after the next restart. Covers the whole family,
        // since the pin may name a different revision than the delete did.
        {
            let mut pin_binds: Vec<String> = Vec::with_capacity(family.len() + 1);
            pin_binds.push(channel.to_string());
            pin_binds.extend(family.iter().cloned());
            self.conn.execute(
                &format!("DELETE FROM pins WHERE channel = ? AND msgid IN ({ph})"),
                rusqlite::params_from_iter(pin_binds.iter()),
            )?;
        }

        // Reactions annotate a message that no longer exists. Nothing surfaces
        // them today, but they are orphaned rows that any future "reactions in
        // this channel" read would resurrect — and they retain a record of who
        // reacted to content the author asked to have deleted.
        {
            let mut reaction_binds: Vec<String> = Vec::with_capacity(family.len() + 1);
            reaction_binds.push(channel.to_string());
            reaction_binds.extend(family.iter().cloned());
            self.conn.execute(
                &format!("DELETE FROM reactions WHERE channel = ? AND target_msgid IN ({ph})"),
                rusqlite::params_from_iter(reaction_binds.iter()),
            )?;
        }

        Ok(changed)
    }

    /// Record metadata for a privately-stored media object.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_media(
        &self,
        id: &str,
        uploader_did: &str,
        scope: &str,
        mime: &str,
        size: u64,
        alt: Option<&str>,
        filename: &str,
        created_at: u64,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO media (id, uploader_did, scope, mime, size, alt, filename, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                uploader_did,
                scope,
                mime,
                size as i64,
                alt,
                filename,
                created_at as i64
            ],
        )?;
        Ok(())
    }

    /// Fetch live (non-deleted) media metadata by id. Returns None if missing
    /// or soft-deleted.
    pub fn get_media(&self, id: &str) -> SqlResult<Option<MediaRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, uploader_did, scope, mime, size, alt, filename, created_at, deleted_at
             FROM media WHERE id = ?1 AND deleted_at IS NULL LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(MediaRow {
                id: row.get(0)?,
                uploader_did: row.get(1)?,
                scope: row.get(2)?,
                mime: row.get(3)?,
                size: row.get::<_, i64>(4)? as u64,
                alt: row.get(5)?,
                filename: row.get(6)?,
                created_at: row.get::<_, i64>(7)? as u64,
                deleted_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Soft-delete a media object by id. Returns the number of rows changed.
    pub fn soft_delete_media(&self, id: &str) -> SqlResult<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let changed = self.conn.execute(
            "UPDATE media SET deleted_at = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![now as i64, id],
        )?;
        Ok(changed)
    }

    /// Store an edit (a new message that replaces an old one).
    ///
    /// The new row carries the *root* of what it replaces, so every revision of
    /// one logical message shares an identity no matter which revision the
    /// editor named. Only the newest revision stays in the search index —
    /// otherwise a search for pre-edit text surfaces superseded revisions.
    /// Returns whether a row was written, as [`Self::insert_message`] does.
    pub fn insert_edit(
        &self,
        channel: &str,
        sender: &str,
        text: &str,
        timestamp: u64,
        tags: &HashMap<String, String>,
        msgid: &str,
        replaces_msgid: &str,
        sender_did: Option<&str>,
    ) -> SqlResult<bool> {
        self.insert_edit_with(
            channel,
            sender,
            text,
            timestamp,
            tags,
            msgid,
            replaces_msgid,
            sender_did,
            &crate::events::EventContext::default(),
        )
    }

    /// [`Db::insert_edit`], plus the verdict and provenance the event log
    /// cannot derive. See [`Db::insert_message_with`].
    #[allow(clippy::too_many_arguments)]
    pub fn insert_edit_with(
        &self,
        channel: &str,
        sender: &str,
        text: &str,
        timestamp: u64,
        tags: &HashMap<String, String>,
        msgid: &str,
        replaces_msgid: &str,
        sender_did: Option<&str>,
        ctx: &crate::events::EventContext,
    ) -> SqlResult<bool> {
        let tags_json = serde_json::to_string(tags).unwrap_or_else(|_| "{}".to_string());
        let stored_text = if let Some(ref key) = self.encryption_key {
            encrypt_at_rest(key, text)
        } else {
            text.to_string()
        };
        let root = self.root_of(replaces_msgid);
        // Row and event together or not at all — see `insert_message_with`.
        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, root_msgid, sender_did)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![channel, sender, stored_text, timestamp as i64, tags_json, msgid, replaces_msgid, root, sender_did],
        )?;
        if self.conn.changes() == 0 {
            // A revision may not take over an id already on file (see
            // `insert_message` — same first-write-wins rule, same
            // duplicate-vs-conflict distinction).
            let conflicting = self
                .find_message_by_msgid(msgid)
                .ok()
                .flatten()
                .is_some_and(|row| row.text != text);
            if conflicting {
                tracing::warn!(
                    msgid,
                    channel,
                    "msgid already on file with DIFFERENT content; conflicting edit dropped"
                );
                self.record_event_conflict(
                    msgid,
                    &self.claim_fingerprint(
                        channel,
                        text,
                        tags,
                        sender_did,
                        msgid,
                        Some(replaces_msgid),
                    ),
                )?;
            } else {
                tracing::debug!(msgid, channel, "duplicate edit delivery; insert ignored");
            }
            tx.commit()?;
            return Ok(false);
        }
        self.file_message_event(
            channel,
            text,
            tags,
            Some(msgid),
            sender_did,
            Some(replaces_msgid),
            timestamp,
            ctx,
        )?;
        let rowid = self.conn.last_insert_rowid();
        if self.fts_enabled() {
            self.conn.execute(
                "DELETE FROM messages_fts WHERE rowid IN (
                     SELECT id FROM messages WHERE channel = ?1 AND root_msgid = ?2 AND id <> ?3
                 )",
                params![channel, root, rowid],
            )?;
        }
        self.fts_index(rowid, text)?;
        tx.commit()?;
        Ok(true)
    }

    // ── The event log ──────────────────────────────────────────────────

    /// File the event that accompanies a message row, from the same values
    /// the row was written with.
    ///
    /// The document is rebuilt here rather than threaded down from ingress:
    /// every input it needs is already an argument to the write, and asking
    /// 145 call sites to carry bytes they don't otherwise touch would be a
    /// worse trade than one rebuild in the one place that files the row.
    ///
    /// A sender with no DID has no identity to bind, so there is no document —
    /// the row records what it knows and says so.
    #[allow(clippy::too_many_arguments)]
    fn file_message_event(
        &self,
        channel: &str,
        text: &str,
        tags: &HashMap<String, String>,
        msgid: Option<&str>,
        sender_did: Option<&str>,
        replaces_msgid: Option<&str>,
        timestamp: u64,
        ctx: &crate::events::EventContext,
    ) -> SqlResult<()> {
        // No id, no identity to file the event under. Rows this old predate
        // message ids entirely; the parity check excludes them for the same
        // reason.
        let Some(msgid) = msgid else {
            return Ok(());
        };
        let signature = tags
            .get(freeq_sdk::sigtag::SIG_TAG)
            .or_else(|| tags.get("freeq.at/sig"))
            .map(String::as_str);
        let canonical = sender_did.map(|did| {
            crate::events::message_canonical(did, msgid, channel, text, tags, replaces_msgid)
        });
        let record = match canonical.as_deref() {
            Some(canonical) => EventRecord {
                shape: EventShape::Document(canonical),
                signature,
                ctx: ctx.clone(),
                timestamp,
            },
            None => EventRecord {
                shape: EventShape::Bare(crate::events::EventFacts {
                    event_id: msgid.to_string(),
                    kind: if replaces_msgid.is_some() { "edit" } else { "message" }.to_string(),
                    venue: crate::events::venue_of(channel),
                    actor_did: None,
                    subject: replaces_msgid.map(str::to_string),
                    body_hash: None,
                    emoji: None,
                }),
                signature: None,
                ctx: ctx.clone(),
                timestamp,
            },
        };
        self.insert_event(&record)?;
        Ok(())
    }

    /// The fingerprint of a *rejected* claim on an id — the bytes it would
    /// have been filed under, had it arrived first.
    ///
    /// A document where the claimant has an identity, so the receipt names
    /// exactly what was refused; the body otherwise, which is the only thing
    /// there is to name.
    fn claim_fingerprint(
        &self,
        channel: &str,
        text: &str,
        tags: &HashMap<String, String>,
        sender_did: Option<&str>,
        msgid: &str,
        replaces_msgid: Option<&str>,
    ) -> String {
        match sender_did {
            Some(did) => crate::events::fingerprint(&crate::events::message_canonical(
                did,
                msgid,
                channel,
                text,
                tags,
                replaces_msgid,
            )),
            None => crate::events::fingerprint(text),
        }
    }

    /// File the event a mutation is.
    ///
    /// The venue is the one the signature covers, which the caller carries down
    /// from ingress; the channel the derived change lands in stands in when
    /// there is none. Those two agree for a channel and differ for a DM, whose
    /// venue is the sorted DID pair while the change lands under a wire target
    /// that may be a nick — and a canonical built from the target is not the
    /// bytes the stored signature covers, so the act reads as forged.
    ///
    /// The subject is resolved to the root — the identity the message keeps for
    /// life — so a mutation naming any revision files against the same one
    /// the message is known by everywhere else.
    fn file_mutation_event(
        &self,
        kind: freeq_sdk::chatsig::Mutation,
        channel: &str,
        subject: &str,
        emoji: Option<&str>,
        ev: &MutationEvent<'_>,
    ) -> SqlResult<()> {
        let subject = self.root_of(subject);
        let venue = match ev.venue {
            Some(venue) => venue.to_string(),
            None => crate::events::venue_of(channel),
        };
        // A document only where one exists. The canonical column holds bytes
        // a signature covers, so an act nothing signed gets none — and its
        // facts, which happened either way, are stated instead.
        let canonical = match (ev.actor_did, ev.signature) {
            (Some(did), Some(_)) => Some(crate::events::mutation_canonical(
                kind, did, ev.event_id, &venue, &subject, emoji,
            )),
            _ => None,
        };
        let record = match canonical.as_deref() {
            Some(canonical) => EventRecord {
                shape: EventShape::Document(canonical),
                signature: ev.signature,
                ctx: ev.ctx.clone(),
                timestamp: ev.timestamp,
            },
            // A guest acted — or an identity acted somewhere with no venue a
            // verifier could rebuild. Either way the act is a fact worth
            // keeping; it just isn't a signed one, and the row says so.
            None => EventRecord {
                shape: EventShape::Bare(crate::events::EventFacts {
                    event_id: ev.event_id.to_string(),
                    kind: kind.as_str().to_string(),
                    venue,
                    actor_did: ev.actor_did.map(str::to_string),
                    subject: Some(subject.clone()),
                    body_hash: None,
                    emoji: emoji.map(str::to_string),
                }),
                signature: None,
                ctx: ev.ctx.clone(),
                timestamp: ev.timestamp,
            },
        };
        self.insert_event(&record)?;
        Ok(())
    }

    /// The channel a message is filed under, by any of its msgids.
    ///
    /// A mutation that only names its subject — an unreaction does — still
    /// needs the venue, because the venue is inside the document it signs.
    pub fn channel_of_message(&self, msgid: &str) -> SqlResult<Option<String>> {
        let root = self.root_of(msgid);
        let mut stmt = self
            .conn
            .prepare("SELECT channel FROM messages WHERE root_msgid = ?1 OR msgid = ?1 LIMIT 1")?;
        let mut rows = stmt.query_map(params![root], |r| r.get(0))?;
        rows.next().transpose()
    }

    /// File an event. **The only path that writes `events`.**
    ///
    /// One path, so one rule holds everywhere: when there is a document, every
    /// queryable column is read back out of those exact bytes
    /// ([`crate::events::derive_facts`]) rather than taken on the caller's
    /// word, and the columns therefore cannot say something the canonical
    /// doesn't. [`Db::events_disagreeing_with_their_bytes`] is the audit that
    /// keeps this true over time.
    ///
    /// Append-only and first-write-wins: a second claim on an id is ignored
    /// here, and its *content* is judged by the caller, which records a
    /// [`Db::record_event_conflict`] receipt when the second claim differed.
    ///
    /// Returns whether a row was written.
    pub fn insert_event(&self, rec: &EventRecord<'_>) -> SqlResult<bool> {
        use crate::events::SigState;
        let (canonical, facts) = match &rec.shape {
            EventShape::Document(canonical) => match crate::events::derive_facts(canonical) {
                Some(facts) => (*canonical, facts),
                None => {
                    // The caller handed over bytes it called a document and
                    // they are not one. Filing the row anyway would put a
                    // canonical in the log that nothing can read back — the
                    // one thing this table must never contain.
                    tracing::error!(
                        canonical_len = canonical.len(),
                        "refusing to file an event whose canonical is not a document"
                    );
                    return Ok(false);
                }
            },
            EventShape::Bare(facts) => ("", facts.clone()),
        };
        // A signature is what a verdict is *about*. Without one there is
        // nothing to have concluded, whatever the caller said.
        let sig_state = if rec.signature.is_none() {
            SigState::Unsigned
        } else {
            rec.ctx.sig_state
        };
        self.conn.execute(
            "INSERT OR IGNORE INTO events
                 (event_id, canonical, signature, sig_state, kind, venue,
                  actor_did, subject, body_hash, emoji, origin, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                facts.event_id,
                canonical,
                rec.signature,
                sig_state.as_str(),
                facts.kind,
                facts.venue,
                facts.actor_did,
                facts.subject,
                facts.body_hash,
                facts.emoji,
                rec.ctx.origin,
                rec.timestamp as i64,
            ],
        )?;
        Ok(self.conn.changes() > 0)
    }

    /// Record that a second, differing claim on `event_id` was dropped.
    ///
    /// The receipt is the fingerprint of what was dropped, so the fact that
    /// two signed claims existed survives the drop — without it, equivocation
    /// is invisible to everyone including us. Local only: it is written here,
    /// read here, and never crosses the wire.
    ///
    /// The first receipt wins. A third claim adds nothing: the question the
    /// column answers is "was there ever a conflicting claim on this id", and
    /// one is enough to answer it.
    pub fn record_event_conflict(&self, event_id: &str, fingerprint: &str) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE events SET conflict = ?2 WHERE event_id = ?1 AND conflict IS NULL",
            params![event_id, fingerprint],
        )
    }

    /// Every row whose columns disagree with its own canonical.
    ///
    /// The invariant this table rests on, made checkable: a row that carries
    /// bytes must be describable by them. Returns one line per disagreement,
    /// `<event_id> <column>: <stored> != <derived>`; empty is the healthy
    /// answer. Rows with no canonical are skipped — there is nothing to
    /// derive from, and their columns are the whole record by design.
    pub fn events_disagreeing_with_their_bytes(&self) -> SqlResult<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, kind, venue, actor_did, subject, body_hash, emoji
             FROM events WHERE canonical <> ''",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        })?;

        let mut bad = Vec::new();
        for row in rows {
            let (id, canonical, kind, venue, actor_did, subject, body_hash, emoji) = row?;
            let Some(derived) = crate::events::derive_facts(&canonical) else {
                bad.push(format!("{id} canonical: not a document"));
                continue;
            };
            let mut note = |column: &str, stored: String, want: String| {
                if stored != want {
                    bad.push(format!("{id} {column}: {stored} != {want}"));
                }
            };
            note("event_id", id.clone(), derived.event_id.clone());
            note("kind", kind, derived.kind);
            note("venue", venue, derived.venue);
            note(
                "actor_did",
                format!("{actor_did:?}"),
                format!("{:?}", derived.actor_did),
            );
            note(
                "subject",
                format!("{subject:?}"),
                format!("{:?}", derived.subject),
            );
            note(
                "body_hash",
                format!("{body_hash:?}"),
                format!("{:?}", derived.body_hash),
            );
            note("emoji", format!("{emoji:?}"), format!("{:?}", derived.emoji));
        }
        Ok(bad)
    }

    /// The msgids of messages with no event row — the count-parity check, in
    /// the one direction that holds.
    ///
    /// Parity runs message → event and never the reverse: the log is
    /// append-only and outlives what it points at, so a pruned message leaves
    /// its event behind on purpose. Rows predating message ids are excluded;
    /// they have no identity to file an event under.
    pub fn messages_without_events(&self) -> SqlResult<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.msgid FROM messages m
             LEFT JOIN events e ON e.event_id = m.msgid
             WHERE m.msgid IS NOT NULL AND e.event_id IS NULL",
        )?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    /// Read one event back, whole.
    pub fn get_event(&self, event_id: &str) -> SqlResult<Option<StoredEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, sig_state, kind, venue,
                    actor_did, subject, body_hash, emoji, origin, conflict, timestamp
             FROM events WHERE event_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![event_id], map_stored_event)?;
        rows.next().transpose()
    }

    /// Every event in a venue, oldest first — the order a replay applies them
    /// in, and the order a rebuild reads them in.
    pub fn events_in_venue(&self, venue: &str) -> SqlResult<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, sig_state, kind, venue,
                    actor_did, subject, body_hash, emoji, origin, conflict, timestamp
             FROM events WHERE venue = ?1 ORDER BY timestamp ASC, event_id ASC",
        )?;
        let rows = stmt.query_map(params![venue], map_stored_event)?;
        rows.collect()
    }

    /// Every event this server holds, oldest first.
    pub fn all_events(&self) -> SqlResult<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, sig_state, kind, venue,
                    actor_did, subject, body_hash, emoji, origin, conflict, timestamp
             FROM events ORDER BY timestamp ASC, event_id ASC",
        )?;
        let rows = stmt.query_map([], map_stored_event)?;
        rows.collect()
    }

    /// Drop event rows older than `cutoff_ts`. Only ever called when an
    /// operator has set a retention window — the log keeps everything by
    /// default, because discarding evidence should be a decision someone made.
    pub fn prune_events_older_than(&self, cutoff_ts: u64) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM events WHERE timestamp < ?1",
            params![cutoff_ts as i64],
        )
    }

    // ── Reactions ──────────────────────────────────────────────────────

    /// Store a reaction. Upsert — duplicate (msgid, nick, emoji) is ignored.
    ///
    /// Filed against the root, so reacting to an edited message lands on the
    /// same row whichever revision the reactor's client named.
    pub fn store_reaction(
        &self,
        target_msgid: &str,
        channel: &str,
        reactor_nick: &str,
        reactor_did: Option<&str>,
        emoji: &str,
        timestamp: u64,
    ) -> SqlResult<()> {
        self.store_reaction_by(target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp, None)
    }

    /// [`Db::store_reaction`], logging the act as its own event.
    #[allow(clippy::too_many_arguments)]
    pub fn store_reaction_by(
        &self,
        target_msgid: &str,
        channel: &str,
        reactor_nick: &str,
        reactor_did: Option<&str>,
        emoji: &str,
        timestamp: u64,
        ev: Option<&MutationEvent<'_>>,
    ) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some(ev) = ev {
            self.file_mutation_event(
                freeq_sdk::chatsig::Mutation::React,
                channel,
                target_msgid,
                Some(emoji),
                ev,
            )?;
        }
        let target_msgid = &self.root_of(target_msgid);
        self.conn.execute(
            "INSERT OR IGNORE INTO reactions (target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Remove a reaction. Identity-keyed, not just nick-keyed:
    ///
    /// - An **authenticated** remover (did = Some) deletes rows stored under
    ///   their DID — regardless of what nick they reacted under (nick changes
    ///   must not make a reaction irremovable) — plus any DID-less row under
    ///   their current nick (their own pre-auth reaction; they own the nick).
    /// - A **guest** remover (did = None) deletes only DID-less rows under
    ///   their nick. A guest squatting a previously-authenticated user's nick
    ///   must not be able to strip that user's reactions.
    pub fn remove_reaction(
        &self,
        target_msgid: &str,
        reactor_nick: &str,
        reactor_did: Option<&str>,
        emoji: &str,
    ) -> SqlResult<usize> {
        self.remove_reaction_by(target_msgid, reactor_nick, reactor_did, emoji, "", None)
    }

    /// [`Db::remove_reaction`], keeping the record of the removal.
    ///
    /// This is the case the log exists for. Removing a reaction deletes its
    /// row — that table is the current tally, and a removed reaction is not
    /// part of it — so before the log there was no trace that anyone had ever
    /// reacted, let alone that they later took it back. The signed event that
    /// removed it is now on file, and the react it undoes still is too.
    pub fn remove_reaction_by(
        &self,
        target_msgid: &str,
        reactor_nick: &str,
        reactor_did: Option<&str>,
        emoji: &str,
        channel: &str,
        ev: Option<&MutationEvent<'_>>,
    ) -> SqlResult<usize> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some(ev) = ev {
            // The channel comes from the caller, exactly as it does for the
            // react being undone — deriving it from the subject instead
            // silently dropped the event whenever the subject message wasn't
            // on file, which every legacy-id row is.
            self.file_mutation_event(
                freeq_sdk::chatsig::Mutation::Unreact,
                channel,
                target_msgid,
                Some(emoji),
                ev,
            )?;
        }
        let target_msgid = &self.root_of(target_msgid);
        let changed = match reactor_did {
            Some(did) => self.conn.execute(
                "DELETE FROM reactions WHERE target_msgid = ?1 AND emoji = ?2
                   AND (reactor_did = ?3 OR (reactor_did IS NULL AND reactor_nick = ?4))",
                params![target_msgid, emoji, did, reactor_nick],
            )?,
            None => self.conn.execute(
                "DELETE FROM reactions WHERE target_msgid = ?1 AND emoji = ?2
                   AND reactor_nick = ?3 AND reactor_did IS NULL",
                params![target_msgid, emoji, reactor_nick],
            )?,
        };
        tx.commit()?;
        Ok(changed)
    }

    /// Get reactions for a list of message IDs, grouped by msgid -> emoji -> nicks.
    pub fn get_reactions_for_messages(
        &self,
        msgids: &[&str],
    ) -> SqlResult<HashMap<String, Vec<ReactionRow>>> {
        if msgids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders: Vec<String> = msgids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let sql = format!(
            "SELECT target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp
             FROM reactions WHERE target_msgid IN ({})
             ORDER BY timestamp ASC",
            placeholders.join(", ")
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            msgids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(ReactionRow {
                target_msgid: row.get(0)?,
                channel: row.get(1)?,
                reactor_nick: row.get(2)?,
                reactor_did: row.get(3)?,
                emoji: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        })?;
        let mut result: HashMap<String, Vec<ReactionRow>> = HashMap::new();
        for row in rows {
            let row = row?;
            result
                .entry(row.target_msgid.clone())
                .or_default()
                .push(row);
        }
        Ok(result)
    }

    // ── Pins ──────────────────────────────────────────────────────────

    /// Store a pin. Duplicate (channel, msgid) is ignored.
    ///
    /// Filed against the root, so a message can't end up pinned twice by being
    /// pinned once before an edit and once after.
    pub fn store_pin(
        &self,
        channel: &str,
        msgid: &str,
        pinned_by: &str,
        pinned_at: u64,
    ) -> SqlResult<()> {
        let root = self.root_of(msgid);
        let tx = self.conn.unchecked_transaction()?;
        // Pins are outside the signing model — they are moderation, which
        // this phase leaves unsigned on purpose — so the event records the
        // act without a document to back it. `pinned_by` is a nick, which is
        // exactly why the row cannot claim an actor identity.
        self.file_bare_event("pin", channel, &root, pinned_at, &pin_event_id(channel, &root, pinned_at, true))?;
        self.conn.execute(
            "INSERT OR IGNORE INTO pins (channel, msgid, pinned_by, pinned_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![channel, &root, pinned_by, pinned_at as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Remove a pin.
    pub fn remove_pin(&self, channel: &str, msgid: &str) -> SqlResult<usize> {
        let root = self.root_of(msgid);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tx = self.conn.unchecked_transaction()?;
        self.file_bare_event("unpin", channel, &root, now, &pin_event_id(channel, &root, now, false))?;
        let changed = self.conn.execute(
            "DELETE FROM pins WHERE channel = ?1 AND msgid = ?2",
            params![channel, &root],
        )?;
        tx.commit()?;
        Ok(changed)
    }

    /// File an event nothing signed: the act is a fact, but no document
    /// stands behind it.
    fn file_bare_event(
        &self,
        kind: &str,
        channel: &str,
        subject: &str,
        timestamp: u64,
        event_id: &str,
    ) -> SqlResult<()> {
        self.insert_event(&EventRecord {
            shape: EventShape::Bare(crate::events::EventFacts {
                event_id: event_id.to_string(),
                kind: kind.to_string(),
                venue: crate::events::venue_of(channel),
                actor_did: None,
                subject: Some(subject.to_string()),
                body_hash: None,
                emoji: None,
            }),
            signature: None,
            ctx: crate::events::EventContext::default(),
            timestamp,
        })?;
        Ok(())
    }

    /// Get all pins for a channel, most recent first.
    pub fn get_pins(&self, channel: &str) -> SqlResult<Vec<crate::server::PinnedMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT msgid, pinned_by, pinned_at FROM pins
             WHERE channel = ?1
             ORDER BY pinned_at DESC",
        )?;
        let rows = stmt.query_map(params![channel], |row| {
            Ok(crate::server::PinnedMessage {
                msgid: row.get(0)?,
                pinned_by: row.get(1)?,
                pinned_at: row.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Get raw (potentially encrypted) message text for testing.
    /// Returns the stored text without decryption.
    pub fn get_raw_message_text(&self, channel: &str, timestamp: u64) -> SqlResult<String> {
        self.conn.query_row(
            "SELECT text FROM messages WHERE channel = ?1 AND timestamp = ?2",
            params![channel, timestamp as i64],
            |row| row.get(0),
        )
    }

    /// List DM conversations for a given DID, ordered by most recent message.
    /// Returns (canonical_dm_key, last_message_timestamp) pairs.
    pub fn dm_conversations(&self, did: &str, limit: usize) -> SqlResult<Vec<(String, u64)>> {
        let pattern = format!("%{did}%");
        let mut stmt = self.conn.prepare(
            "SELECT channel, MAX(timestamp) AS last_ts
             FROM messages
             WHERE channel LIKE 'dm:%' AND channel LIKE ?1
               AND deleted_at IS NULL
             GROUP BY channel
             ORDER BY last_ts DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            let channel: String = row.get(0)?;
            let ts: i64 = row.get(1)?;
            Ok((channel, ts as u64))
        })?;
        rows.collect()
    }

    // ── Pre-key bundles (E2EE) ────────────────────────────────────────

    /// Store or update a pre-key bundle for a DID.
    pub fn save_prekey_bundle(&self, did: &str, bundle_json: &str) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.conn.execute(
            "INSERT INTO prekey_bundles (did, bundle_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(did) DO UPDATE SET bundle_json=excluded.bundle_json, updated_at=excluded.updated_at",
            params![did, bundle_json, now as i64],
        )?;
        Ok(())
    }

    /// Load a pre-key bundle for a DID.
    pub fn get_prekey_bundle(&self, did: &str) -> SqlResult<Option<serde_json::Value>> {
        let mut stmt = self
            .conn
            .prepare("SELECT bundle_json FROM prekey_bundles WHERE did = ?1")?;
        let mut rows = stmt.query_map(params![did], |row| {
            let json_str: String = row.get(0)?;
            Ok(serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null))
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Store a group key sealed to one member at one epoch (server-blind).
    pub fn save_group_key(
        &self,
        channel: &str,
        member_did: &str,
        epoch: i64,
        sealed_wire: &str,
    ) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.conn.execute(
            "INSERT INTO group_keys (channel, member_did, epoch, sealed_wire, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(channel, member_did, epoch)
             DO UPDATE SET sealed_wire=excluded.sealed_wire, updated_at=excluded.updated_at",
            params![
                channel.to_lowercase(),
                member_did,
                epoch,
                sealed_wire,
                now as i64
            ],
        )?;
        Ok(())
    }

    /// Fetch all sealed group keys for one member of a channel, newest epoch
    /// first. Returns `(epoch, sealed_wire)` pairs.
    pub fn get_group_keys_for_member(
        &self,
        channel: &str,
        member_did: &str,
    ) -> SqlResult<Vec<(i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch, sealed_wire FROM group_keys
             WHERE channel = ?1 AND member_did = ?2 ORDER BY epoch DESC",
        )?;
        let rows = stmt.query_map(params![channel.to_lowercase(), member_did], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect()
    }

    /// Load all pre-key bundles (for populating in-memory cache on startup).
    pub fn load_all_prekey_bundles(&self) -> SqlResult<Vec<(String, serde_json::Value)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT did, bundle_json FROM prekey_bundles")?;
        let rows = stmt.query_map([], |row| {
            let did: String = row.get(0)?;
            let json_str: String = row.get(1)?;
            let bundle = serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null);
            Ok((did, bundle))
        })?;
        rows.collect()
    }

    // ── Per-DID signing keys (MSGSIG) ────────────────────────────────
    //
    // When a session sends `MSGSIG <pubkey>`, the connection layer mirrors it
    // here so we can verify signatures from that DID across server restarts
    // and even when the DID has no active session. Used by:
    //   • PROVENANCE FreeqBotDelegation/v1 cert verification
    //   • (future) cross-session signature checks for offline signers

    /// Record a client message-signing key for a DID, keyed by its kid.
    /// Append-only: re-registering a *different* key adds a row (history);
    /// re-registering the *same* key is idempotent. `pubkey` must be 32 bytes.
    pub fn save_signing_key(&self, did: &str, pubkey: &[u8]) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let kid = freeq_sdk::act::derive_kid_bytes(pubkey);
        // Append-only: a new (did, kid) is inserted, never overwriting a
        // different key. Re-registering an *existing* kid bumps registered_at
        // so "latest" (`get_signing_key`) tracks the most recently used key,
        // not the first one ever seen — no key is lost either way.
        self.conn.execute(
            "INSERT INTO signing_keys (did, kid, pubkey, registered_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(did, kid) DO UPDATE SET registered_at = excluded.registered_at",
            params![did, kid, pubkey, now as i64],
        )?;
        Ok(())
    }

    /// The DID's most-recently-registered signing key (raw 32-byte ed25519
    /// public key), or None. Used by the existing verify path, which wants the
    /// current key; a specific historical key is fetched via
    /// [`Db::get_signing_key_by_kid`].
    pub fn get_signing_key(&self, did: &str) -> SqlResult<Option<[u8; 32]>> {
        // rowid DESC breaks ties: registered_at is second-granularity, so two
        // keys registered in the same second must fall back to insertion order.
        self.query_signing_key(
            "SELECT pubkey FROM signing_keys WHERE did = ?1
             ORDER BY registered_at DESC, rowid DESC LIMIT 1",
            params![did],
        )
    }

    /// The exact key a DID registered under `kid`, or None. This is the lookup
    /// a verifier uses when a signature names its kid — the key stays available
    /// after the signer reconnects (unlike the old overwrite-on-reregister).
    pub fn get_signing_key_by_kid(&self, did: &str, kid: &str) -> SqlResult<Option<[u8; 32]>> {
        self.query_signing_key(
            "SELECT pubkey FROM signing_keys WHERE did = ?1 AND kid = ?2",
            params![did, kid],
        )
    }

    /// Shared read: run a single-column pubkey query, returning the 32-byte key
    /// or None (also None if the stored blob is not 32 bytes — guards against a
    /// manual edit or legacy corruption).
    fn query_signing_key(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> SqlResult<Option<[u8; 32]>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query_map(params, |row| row.get::<_, Vec<u8>>(0))?;
        match rows.next() {
            Some(row) => {
                let bytes = row?;
                if bytes.len() != 32 {
                    return Ok(None);
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }

    // ── User channel persistence (auto-rejoin) ────────────────────────

    /// Record that a DID-authenticated user has joined a channel.
    pub fn add_user_channel(&self, did: &str, channel: &str) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO user_channels (did, channel) VALUES (?1, ?2)",
            params![did, channel],
        )?;
        Ok(())
    }

    /// Record that a DID-authenticated user has left a channel.
    pub fn remove_user_channel(&self, did: &str, channel: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM user_channels WHERE did = ?1 AND channel = ?2",
            params![did, channel],
        )?;
        Ok(())
    }

    /// Get all channels a DID-authenticated user was last in.
    pub fn get_user_channels(&self, did: &str) -> SqlResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT channel FROM user_channels WHERE did = ?1")?;
        let rows = stmt.query_map(params![did], |row| row.get(0))?;
        rows.collect()
    }

    // ── Read markers (IRCv3 draft/read-marker) ─────────────────────────

    /// Fetch the last-read timestamp a user's clients have converged on for a
    /// target, if any. `None` means no marker has ever been set (`MARKREAD`
    /// replies with `*`).
    pub fn get_read_marker(&self, did: &str, target: &str) -> SqlResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT timestamp FROM read_markers WHERE did = ?1 AND target = ?2")?;
        let mut rows = stmt.query_map(params![did, target], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Set (or advance) the read marker for `(did, target)`. Callers are
    /// responsible for the forward-only check; this write is unconditional so
    /// the handler stays the single authority on monotonicity.
    pub fn set_read_marker(
        &self,
        did: &str,
        target: &str,
        timestamp: &str,
        updated_at: u64,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO read_markers (did, target, timestamp, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(did, target) DO UPDATE SET
                 timestamp = excluded.timestamp,
                 updated_at = excluded.updated_at",
            params![did, target, timestamp, updated_at as i64],
        )?;
        Ok(())
    }

    // ── Roaming favorites (per-DID) ────────────────────────────────────

    /// The user's favorite channels in saved order.
    pub fn get_user_favorites(&self, did: &str) -> SqlResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT channel FROM user_favorites WHERE did = ?1 ORDER BY ord ASC")?;
        let rows = stmt.query_map(params![did], |row| row.get::<_, String>(0))?;
        rows.collect()
    }

    /// Replace the user's favorites with `channels` (order = slice order).
    /// Atomic replace-all so a device's PUT is the authority for its DID.
    pub fn set_user_favorites(
        &self,
        did: &str,
        channels: &[String],
        updated_at: u64,
    ) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM user_favorites WHERE did = ?1", params![did])?;
        for (i, ch) in channels.iter().enumerate() {
            tx.execute(
                "INSERT INTO user_favorites (did, channel, ord, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![did, ch, i as i64, updated_at as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ── Identities (DID-nick bindings) ─────────────────────────────────

    /// Bind a DID to a nick. Overwrites any previous binding for that DID.
    pub fn save_identity(&self, did: &str, nick: &str) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO identities (did, nick, last_auth_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(did) DO UPDATE SET nick=excluded.nick, last_auth_at=excluded.last_auth_at",
            params![did, nick, now],
        )?;
        Ok(())
    }

    /// Load all DID-nick bindings.
    pub fn load_identities(&self) -> SqlResult<Vec<IdentityRow>> {
        let mut stmt = self.conn.prepare("SELECT did, nick FROM identities")?;
        let rows = stmt.query_map([], |row| {
            Ok(IdentityRow {
                did: row.get(0)?,
                nick: row.get(1)?,
            })
        })?;
        rows.collect()
    }

    /// Look up a DID by nick.
    pub fn get_identity_by_nick(&self, nick: &str) -> SqlResult<Option<IdentityRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT did, nick FROM identities WHERE nick = ?1")?;
        let mut rows = stmt.query_map(params![nick], |row| {
            Ok(IdentityRow {
                did: row.get(0)?,
                nick: row.get(1)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Look up a nick by DID.
    pub fn get_identity_by_did(&self, did: &str) -> SqlResult<Option<IdentityRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT did, nick FROM identities WHERE did = ?1")?;
        let mut rows = stmt.query_map(params![did], |row| {
            Ok(IdentityRow {
                did: row.get(0)?,
                nick: row.get(1)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Recover the nick a DID last sent under, from stored message history.
    /// The `sender` column holds a `nick!user@host` mask, so the bare nick is
    /// the part before `!`. Covers DIDs that have no `identities` row — remote
    /// DIDs whose messages were persisted on receipt, and threads that predate
    /// durable identity binding. Only rows carrying a `sender_did` are visible:
    /// messages persisted before that column existed are NULL and invisible, so
    /// resolution needs at least one post-migration message from the DID.
    /// Returns the most recent. Note the recovered nick may since have been
    /// reassigned to a different DID — display-only, so a collision only mildly
    /// misleads and never grants identity.
    pub fn recent_nick_for_did(&self, did: &str) -> SqlResult<Option<String>> {
        let mask: Option<String> = self
            .conn
            .query_row(
                "SELECT sender FROM messages WHERE sender_did = ?1 ORDER BY id DESC LIMIT 1",
                params![did],
                |row| row.get(0),
            )
            .optional()?;
        Ok(mask.and_then(|m| {
            let nick = m.split('!').next().unwrap_or(&m).trim();
            if nick.is_empty() || nick == did {
                None
            } else {
                Some(nick.to_string())
            }
        }))
    }
}

fn map_message_row(row: &rusqlite::Row) -> SqlResult<MessageRow> {
    let tags_json: String = row.get(5)?;
    let tags: HashMap<String, String> = serde_json::from_str(&tags_json).unwrap_or_default();
    // New columns may not exist in old schemas — handle gracefully
    let msgid: Option<String> = row.get(6).unwrap_or(None);
    let replaces_msgid: Option<String> = row.get(7).unwrap_or(None);
    let deleted_at: Option<u64> = row
        .get::<_, Option<i64>>(8)
        .unwrap_or(None)
        .map(|v| v as u64);
    let sender_did: Option<String> = row.get(9).unwrap_or(None);
    let root_msgid: Option<String> = row.get(10).unwrap_or(None);
    Ok(MessageRow {
        id: row.get(0)?,
        channel: row.get(1)?,
        sender: row.get(2)?,
        text: row.get(3)?,
        timestamp: row.get::<_, i64>(4)? as u64,
        tags,
        msgid,
        replaces_msgid,
        root_msgid,
        deleted_at,
        sender_did,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::BanEntry;

    fn msg(db: &Db, channel: &str, text: &str, ts: u64, msgid: &str) {
        db.insert_message(
            channel,
            "alice!a@host",
            text,
            ts,
            &HashMap::new(),
            Some(msgid),
            Some("did:plc:alice"),
        )
        .unwrap();
    }

    // ── Effective capabilities ────────────────────────────────────────────
    //
    // PHASE-4 says a spawned child gets "the intersection of the parent's caps
    // and requested caps". To intersect, the parent's set has to be knowable, so
    // this is where "what does this agent actually hold" is answered: a spawned
    // agent holds what it was recorded with, and a top-level agent holds what its
    // manifest declares plus whatever has been granted to it in the channel.

    fn caps(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_agent_with_nothing_declared_holds_nothing() {
        let db = Db::open_memory().unwrap();
        assert!(db.effective_capabilities("#c", "did:key:nobody").is_empty());
    }

    #[test]
    fn manifest_default_capabilities_are_held() {
        let db = Db::open_memory().unwrap();
        db.save_manifest(
            "did:key:bot",
            r#"{"capabilities":{"default":["post_message","read_channel"]}}"#,
            None,
            "did:plc:op",
        )
        .unwrap();
        let mut held = db.effective_capabilities("#c", "did:key:bot");
        held.sort();
        assert_eq!(held, caps(&["post_message", "read_channel"]));
    }

    #[test]
    fn per_channel_manifest_capabilities_are_added_for_that_channel_only() {
        let db = Db::open_memory().unwrap();
        db.save_manifest(
            "did:key:bot",
            r##"{"capabilities":{"default":["post_message"],"channels":{"#ops":["deploy"]}}}"##,
            None,
            "did:plc:op",
        )
        .unwrap();
        let mut in_ops = db.effective_capabilities("#ops", "did:key:bot");
        in_ops.sort();
        assert_eq!(in_ops, caps(&["deploy", "post_message"]));
        assert_eq!(
            db.effective_capabilities("#other", "did:key:bot"),
            caps(&["post_message"])
        );
    }

    #[test]
    fn granted_capabilities_are_held_and_revocation_removes_them() {
        let db = Db::open_memory().unwrap();
        let id = db
            .grant_capability(
                "#c",
                "did:key:bot",
                "deploy",
                None,
                0,
                false,
                0,
                "did:plc:op",
            )
            .unwrap();
        assert_eq!(
            db.effective_capabilities("#c", "did:key:bot"),
            caps(&["deploy"])
        );
        db.revoke_capability(id).unwrap();
        assert!(db.effective_capabilities("#c", "did:key:bot").is_empty());
    }

    #[test]
    fn a_spawned_agent_holds_exactly_what_it_was_recorded_with() {
        // Not its parent's set, and not a manifest's: a child's authority is the
        // narrowed list it was created with.
        let db = Db::open_memory().unwrap();
        db.save_manifest(
            "did:key:child",
            r#"{"capabilities":{"default":["admin"]}}"#,
            None,
            "did:plc:op",
        )
        .unwrap();
        db.record_spawn(
            "did:key:child",
            "did:key:parent",
            "s",
            "kid",
            "#c",
            &["post_message".to_string()],
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            db.effective_capabilities("#c", "did:key:child"),
            caps(&["post_message"])
        );
    }

    #[test]
    fn narrowing_keeps_only_what_the_parent_holds() {
        let db = Db::open_memory().unwrap();
        db.save_manifest(
            "did:key:parent",
            r#"{"capabilities":{"default":["post_message","call_tool"]}}"#,
            None,
            "did:plc:op",
        )
        .unwrap();
        let granted = db.narrow_capabilities(
            "#c",
            "did:key:parent",
            &["post_message".into(), "deploy".into(), "admin".into()],
        );
        assert_eq!(granted, caps(&["post_message"]));
    }

    #[test]
    fn narrowing_from_nothing_grants_nothing() {
        // You cannot delegate authority you do not hold. This is the case that
        // let a parent with no capabilities spawn a child with "deploy, admin".
        let db = Db::open_memory().unwrap();
        assert!(
            db.narrow_capabilities("#c", "did:key:parent", &["deploy".into(), "admin".into()])
                .is_empty()
        );
    }

    // ── Spawned agents and budgets: the seam between PHASE-4 and PHASE-5 ──
    //
    // A spawned child gets a narrowed subset of its parent's capabilities and
    // dies with the parent (PHASE-4). Budgets are per (channel, agent_did)
    // (PHASE-5). Neither document mentions the other, so the join between them
    // was never specified: a child spends against its OWN did, which means a
    // parent under a hard limit can spawn a child and keep spending.
    //
    // These pin the intended semantics: attribute spend to whoever spent it (so
    // the breakdown stays honest), but roll descendants up when asking what a
    // parent has spent, and let a child inherit the parent's budget.

    fn spend(db: &Db, channel: &str, did: &str, amount: f64) {
        db.record_spend(channel, did, amount, "usd", Some("claude call"), None)
            .unwrap();
    }

    #[test]
    fn a_childs_spend_counts_against_its_parent() {
        let db = Db::open_memory().unwrap();
        db.record_spawn(
            "did:key:child",
            "did:plc:parent",
            "sess-1",
            "worker",
            "#factory",
            &["llm".to_string()],
            None,
            None,
        )
        .unwrap();
        spend(&db, "#factory", "did:plc:parent", 6.0);
        spend(&db, "#factory", "did:key:child", 6.0);

        // The child spent the parent's credits; the parent's total must reflect it.
        assert_eq!(
            db.sum_spend_with_descendants("#factory", "did:plc:parent", "usd", 0),
            12.0
        );
        // Direct attribution is unchanged: the breakdown still shows who spent.
        assert_eq!(
            db.sum_spend("#factory", Some("did:plc:parent"), "usd", 0),
            6.0
        );
        assert_eq!(
            db.sum_spend("#factory", Some("did:key:child"), "usd", 0),
            6.0
        );
    }

    #[test]
    fn descendants_roll_up_through_a_chain() {
        // parent -> child -> grandchild. A grandchild cannot escape the limit by
        // being one more hop away.
        let db = Db::open_memory().unwrap();
        db.record_spawn("did:key:c", "did:plc:p", "s", "c", "#f", &[], None, None)
            .unwrap();
        db.record_spawn("did:key:g", "did:key:c", "s", "g", "#f", &[], None, None)
            .unwrap();
        spend(&db, "#f", "did:plc:p", 1.0);
        spend(&db, "#f", "did:key:c", 2.0);
        spend(&db, "#f", "did:key:g", 4.0);
        assert_eq!(
            db.sum_spend_with_descendants("#f", "did:plc:p", "usd", 0),
            7.0
        );
        assert_eq!(
            db.sum_spend_with_descendants("#f", "did:key:c", "usd", 0),
            6.0
        );
    }

    #[test]
    fn unrelated_agents_do_not_roll_up() {
        let db = Db::open_memory().unwrap();
        db.record_spawn(
            "did:key:mine",
            "did:plc:me",
            "s",
            "m",
            "#f",
            &[],
            None,
            None,
        )
        .unwrap();
        spend(&db, "#f", "did:plc:me", 1.0);
        spend(&db, "#f", "did:key:mine", 1.0);
        spend(&db, "#f", "did:plc:someone-else", 50.0);
        assert_eq!(
            db.sum_spend_with_descendants("#f", "did:plc:me", "usd", 0),
            2.0
        );
    }

    #[test]
    fn a_despawned_childs_spend_still_counts_for_the_period() {
        // Killing the child must not erase what it already spent, or a hard limit
        // could be reset by despawning and respawning.
        let db = Db::open_memory().unwrap();
        db.record_spawn("did:key:c", "did:plc:p", "s", "c", "#f", &[], None, None)
            .unwrap();
        spend(&db, "#f", "did:key:c", 9.0);
        db.record_despawn("did:key:c").unwrap();
        assert_eq!(
            db.sum_spend_with_descendants("#f", "did:plc:p", "usd", 0),
            9.0
        );
    }

    #[test]
    fn a_cycle_in_the_spawn_graph_terminates() {
        // Defensive: a malformed parent chain must not spin forever.
        let db = Db::open_memory().unwrap();
        db.record_spawn("did:key:a", "did:key:b", "s", "a", "#f", &[], None, None)
            .unwrap();
        db.record_spawn("did:key:b", "did:key:a", "s", "b", "#f", &[], None, None)
            .unwrap();
        spend(&db, "#f", "did:key:a", 1.0);
        spend(&db, "#f", "did:key:b", 1.0);
        assert_eq!(
            db.sum_spend_with_descendants("#f", "did:key:a", "usd", 0),
            2.0
        );
    }

    #[test]
    fn a_child_inherits_its_parents_budget() {
        // The child has no budget of its own. Without inheritance it falls through
        // to the channel default (or nothing), and the parent's limit is bypassed.
        let db = Db::open_memory().unwrap();
        db.record_spawn(
            "did:key:child",
            "did:plc:parent",
            "s",
            "w",
            "#f",
            &[],
            None,
            None,
        )
        .unwrap();
        db.set_budget(
            "#f",
            Some("did:plc:parent"),
            r#"{"max_amount":10.0}"#,
            "did:plc:owner",
        )
        .unwrap();
        let inherited = db.get_budget_inherited("#f", "did:key:child");
        assert!(
            inherited.as_deref() == Some(r#"{"max_amount":10.0}"#),
            "child should inherit the parent's budget, got {inherited:?}"
        );
    }

    #[test]
    fn a_childs_own_budget_wins_over_the_inherited_one() {
        let db = Db::open_memory().unwrap();
        db.record_spawn(
            "did:key:child",
            "did:plc:parent",
            "s",
            "w",
            "#f",
            &[],
            None,
            None,
        )
        .unwrap();
        db.set_budget("#f", Some("did:plc:parent"), r#"{"max_amount":10.0}"#, "o")
            .unwrap();
        db.set_budget("#f", Some("did:key:child"), r#"{"max_amount":2.0}"#, "o")
            .unwrap();
        assert_eq!(
            db.get_budget_inherited("#f", "did:key:child").as_deref(),
            Some(r#"{"max_amount":2.0}"#)
        );
    }

    /// Store an edit of `replaces` as the client sends one: a new row with its
    /// own msgid, pointing back at the message it revises.
    fn edit(db: &Db, channel: &str, text: &str, ts: u64, msgid: &str, replaces: &str) {
        db.insert_edit(
            channel,
            "alice!a@host",
            text,
            ts,
            &HashMap::new(),
            msgid,
            replaces,
            Some("did:plc:alice"),
        )
        .unwrap();
    }

    /// Deleting a message must remove every revision of it.
    ///
    /// An edit is a separate row carrying `replaces_msgid`, and clients keep the
    /// ORIGINAL msgid as the message's identity — so a delete names the
    /// original. If only that exact row is marked, the edit row survives and the
    /// newest text (the version the author most wants gone) stays readable in
    /// history and search.
    #[test]
    fn soft_delete_sweeps_the_whole_revision_family() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "secret v1", 100, "id-original");
        db.insert_edit(
            "#c",
            "alice!a@host",
            "secret v2",
            110,
            &HashMap::new(),
            "id-edit1",
            "id-original",
            Some("did:plc:alice"),
        )
        .unwrap();

        db.soft_delete_message("#c", "id-original").unwrap();

        let live: Vec<String> = db
            .get_messages("#c", 50, None)
            .unwrap()
            .into_iter()
            .map(|r| r.text)
            .collect();
        assert!(
            live.is_empty(),
            "delete of the original left revisions readable: {live:?}"
        );
    }

    /// Deleting a message must not leave its reactions behind.
    ///
    /// `soft_delete_message` sweeps messages, FTS rows and pins; reaction rows
    /// keyed by the deleted msgids outlived them. Nothing surfaces them today
    /// (the message they annotate is gone), but they are orphaned state that any
    /// future "reactions in this channel" read would resurrect, and they keep a
    /// record of who reacted to content the author deleted.
    #[test]
    fn soft_delete_removes_reactions_for_the_revision_family() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        db.insert_edit(
            "#c",
            "alice!a@host",
            "v2",
            110,
            &HashMap::new(),
            "id-2",
            "id-1",
            Some("did:plc:alice"),
        )
        .unwrap();
        msg(&db, "#c", "unrelated", 120, "id-other");
        db.store_reaction("id-1", "#c", "bob", Some("did:plc:bob"), "🔥", 111)
            .unwrap();
        db.store_reaction("id-2", "#c", "bob", Some("did:plc:bob"), "👍", 112)
            .unwrap();
        db.store_reaction("id-other", "#c", "bob", Some("did:plc:bob"), "🎉", 121)
            .unwrap();

        db.soft_delete_message("#c", "id-1").unwrap();

        let left = db
            .get_reactions_for_messages(&["id-1", "id-2", "id-other"])
            .unwrap();
        assert!(
            !left.contains_key("id-1") && !left.contains_key("id-2"),
            "reactions survived deletion of the message they annotate: {:?}",
            left.keys().collect::<Vec<_>>()
        );
        assert!(
            left.contains_key("id-other"),
            "unrelated reactions must be untouched"
        );
    }

    /// Deleting a pinned message must drop the pin.
    ///
    /// `handle_delete` only purges the in-memory `ch.pins`; the `pins` row
    /// outlives the message. Pins are reloaded from the DB on startup, so after
    /// a restart the channel advertises a pin whose message no longer exists.
    #[test]
    fn soft_delete_drops_pins_for_the_deleted_message() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "pin me", 100, "id-pinned");
        msg(&db, "#c", "other", 101, "id-other");
        db.store_pin("#c", "id-pinned", "alice", 100).unwrap();
        db.store_pin("#c", "id-other", "alice", 101).unwrap();

        db.soft_delete_message("#c", "id-pinned").unwrap();

        let pinned: Vec<String> = db
            .get_pins("#c")
            .unwrap()
            .into_iter()
            .map(|p| p.msgid)
            .collect();
        assert_eq!(
            pinned,
            vec!["id-other".to_string()],
            "a deleted message must not stay pinned (dangling pin survives restart)"
        );
    }

    /// …including when the pin names a different revision than the delete.
    #[test]
    fn soft_delete_drops_pins_across_the_revision_family() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        db.insert_edit(
            "#c",
            "alice!a@host",
            "v2",
            110,
            &HashMap::new(),
            "id-2",
            "id-1",
            Some("did:plc:alice"),
        )
        .unwrap();
        // Pinned after editing, so the pin names the edit revision.
        db.store_pin("#c", "id-2", "alice", 110).unwrap();

        // The client deletes using the identity it holds: the original.
        db.soft_delete_message("#c", "id-1").unwrap();

        assert!(
            db.get_pins("#c").unwrap().is_empty(),
            "pin on an edit revision survived deletion of the message"
        );
    }

    /// Same family, addressed from the other end: deleting by the *edit's*
    /// msgid must also remove the original it replaced. Both ids denote one
    /// logical message, so either name must delete the whole thing.
    #[test]
    fn soft_delete_by_edit_msgid_also_removes_the_original() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "secret v1", 100, "id-original");
        db.insert_edit(
            "#c",
            "alice!a@host",
            "secret v2",
            110,
            &HashMap::new(),
            "id-edit1",
            "id-original",
            Some("did:plc:alice"),
        )
        .unwrap();

        db.soft_delete_message("#c", "id-edit1").unwrap();

        let live: Vec<String> = db
            .get_messages("#c", 50, None)
            .unwrap()
            .into_iter()
            .map(|r| r.text)
            .collect();
        assert!(live.is_empty(), "revisions survived: {live:?}");
    }

    /// A chain of edits (edit of an edit) must collapse entirely, and the sweep
    /// must not wander into unrelated messages.
    #[test]
    fn soft_delete_sweeps_chained_edits_only() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        db.insert_edit(
            "#c",
            "alice!a@host",
            "v2",
            110,
            &HashMap::new(),
            "id-2",
            "id-1",
            Some("did:plc:alice"),
        )
        .unwrap();
        db.insert_edit(
            "#c",
            "alice!a@host",
            "v3",
            120,
            &HashMap::new(),
            "id-3",
            "id-2",
            Some("did:plc:alice"),
        )
        .unwrap();
        msg(&db, "#c", "unrelated", 130, "id-other");

        db.soft_delete_message("#c", "id-1").unwrap();

        let live: Vec<String> = db
            .get_messages("#c", 50, None)
            .unwrap()
            .into_iter()
            .map(|r| r.text)
            .collect();
        assert_eq!(
            live,
            vec!["unrelated".to_string()],
            "chained edits must all go, unrelated messages must stay"
        );
    }

    // ── Message identity: one root id per logical message ──────────────

    /// Simulate a database written before `root_msgid` existed: clear the
    /// stamps so the next backfill has to derive them from the back-pointers.
    fn strip_root_ids(db: &Db) {
        db.conn
            .execute("UPDATE messages SET root_msgid = NULL", [])
            .unwrap();
    }

    fn reaction_rows(db: &Db, msgid: &str) -> Vec<(String, String, u64)> {
        let mut stmt = db
            .conn
            .prepare(
                "SELECT reactor_nick, emoji, timestamp FROM reactions
                 WHERE target_msgid = ?1 ORDER BY timestamp",
            )
            .unwrap();
        stmt.query_map(params![msgid], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u64))
        })
        .unwrap()
        .collect::<SqlResult<Vec<_>>>()
        .unwrap()
    }

    #[test]
    fn an_edit_inherits_the_original_identity() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");
        edit(&db, "#c", "v3", 120, "id-3", "id-2");

        // Every revision resolves to the id the client has held since v1 —
        // including one named by the id of an intermediate revision.
        assert_eq!(db.root_of("id-1"), "id-1");
        assert_eq!(db.root_of("id-2"), "id-1");
        assert_eq!(db.root_of("id-3"), "id-1");
        // An id with no row is its own root (unpersisted guest-DM messages).
        assert_eq!(db.root_of("id-nowhere"), "id-nowhere");
    }

    #[test]
    fn backfill_roots_a_three_deep_chain() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");
        edit(&db, "#c", "v3", 120, "id-3", "id-2");
        msg(&db, "#c", "unrelated", 130, "id-other");
        strip_root_ids(&db);

        crate::migrations::backfill_root_msgids(&db.conn).unwrap();

        assert_eq!(db.root_of("id-3"), "id-1");
        assert_eq!(db.root_of("id-2"), "id-1");
        assert_eq!(db.root_of("id-other"), "id-other");
        // Re-running must not disturb what the first pass settled.
        crate::migrations::backfill_root_msgids(&db.conn).unwrap();
        assert_eq!(db.root_of("id-3"), "id-1");
    }

    /// Two revisions of one message could each collect the same person's
    /// reaction. Re-filing both under the root collides on
    /// `UNIQUE(target_msgid, reactor_nick, emoji)`; the earliest survives,
    /// whichever revision it was filed against.
    #[test]
    fn backfill_dedups_reactions_across_revisions() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");
        msg(&db, "#c", "v1", 100, "id-a");
        edit(&db, "#c", "v2", 110, "id-b", "id-a");
        strip_root_ids(&db);

        // Reacted before the edit and again after it — the double-file the
        // root id exists to prevent.
        for (target, ts) in [("id-1", 105u64), ("id-2", 115)] {
            db.conn
                .execute(
                    "INSERT INTO reactions (target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp)
                     VALUES (?1, '#c', 'bob', NULL, '🔥', ?2)",
                    params![target, ts as i64],
                )
                .unwrap();
        }
        // Same, with the revision carrying the *earlier* of the two.
        for (target, ts) in [("id-a", 205u64), ("id-b", 105)] {
            db.conn
                .execute(
                    "INSERT INTO reactions (target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp)
                     VALUES (?1, '#c', 'bob', NULL, '👍', ?2)",
                    params![target, ts as i64],
                )
                .unwrap();
        }

        crate::migrations::backfill_root_msgids(&db.conn).unwrap();

        assert_eq!(
            reaction_rows(&db, "id-1"),
            vec![("bob".to_string(), "🔥".to_string(), 105)],
            "one person reacting once must not read as two"
        );
        assert!(reaction_rows(&db, "id-2").is_empty());
        assert_eq!(
            reaction_rows(&db, "id-a"),
            vec![("bob".to_string(), "👍".to_string(), 105)],
            "the earliest reaction survives even when it named the revision"
        );
    }

    #[test]
    fn backfill_dedups_pins_across_revisions() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");
        strip_root_ids(&db);
        // Pinned before the edit, and again after it under the revision's id.
        db.conn
            .execute(
                "INSERT INTO pins (channel, msgid, pinned_by, pinned_at) VALUES
                 ('#c', 'id-1', 'alice', 101), ('#c', 'id-2', 'alice', 111)",
                [],
            )
            .unwrap();

        crate::migrations::backfill_root_msgids(&db.conn).unwrap();

        let pins = db.get_pins("#c").unwrap();
        assert_eq!(pins.len(), 1, "one message, one pin");
        assert_eq!(pins[0].msgid, "id-1");
        assert_eq!(pins[0].pinned_at, 101, "keeps when it was first pinned");
    }

    /// At-rest encryption covers message text only — the ids the backfill walks
    /// are stored plaintext — so an encrypted database upgrades identically.
    #[test]
    fn backfill_runs_on_an_encrypted_database() {
        let db = Db::open_encrypted_memory([3u8; 32]).unwrap();
        msg(&db, "#c", "v1", 100, "enc-1");
        edit(&db, "#c", "v2", 110, "enc-2", "enc-1");
        db.conn
            .execute(
                "INSERT INTO reactions (target_msgid, channel, reactor_nick, reactor_did, emoji, timestamp)
                 VALUES ('enc-2', '#c', 'bob', NULL, '🔥', 115)",
                [],
            )
            .unwrap();
        strip_root_ids(&db);

        crate::migrations::backfill_root_msgids(&db.conn).unwrap();

        assert_eq!(db.root_of("enc-2"), "enc-1");
        assert_eq!(reaction_rows(&db, "enc-1").len(), 1);
        assert_eq!(db.current_revision("enc-1").unwrap().unwrap().text, "v2");
    }

    /// Reacting to an edited message must land on the message, whichever
    /// revision the reactor's client named — and un-reacting must find it
    /// again from the other end.
    #[test]
    fn reactions_file_and_clear_under_the_root() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");

        db.store_reaction("id-2", "#c", "bob", Some("did:plc:bob"), "🔥", 111)
            .unwrap();
        assert_eq!(reaction_rows(&db, "id-1").len(), 1, "filed under the root");

        // A second client of the same person naming the other id must not
        // double the tally.
        db.store_reaction("id-1", "#c", "bob", Some("did:plc:bob"), "🔥", 112)
            .unwrap();
        assert_eq!(reaction_rows(&db, "id-1").len(), 1, "one person, one row");

        assert_eq!(
            db.remove_reaction("id-1", "bob", Some("did:plc:bob"), "🔥")
                .unwrap(),
            1,
            "un-reacting by the original id clears a reaction made on the edit"
        );
        assert!(reaction_rows(&db, "id-1").is_empty());
    }

    #[test]
    fn pins_file_and_clear_under_the_root() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");

        db.store_pin("#c", "id-1", "alice", 101).unwrap();
        db.store_pin("#c", "id-2", "alice", 111).unwrap();
        let pins = db.get_pins("#c").unwrap();
        assert_eq!(pins.len(), 1, "pinning before and after an edit is one pin");
        assert_eq!(pins[0].msgid, "id-1");

        // Unpinned by the revision's id — the same message, so it must clear.
        assert_eq!(db.remove_pin("#c", "id-2").unwrap(), 1);
        assert!(db.get_pins("#c").unwrap().is_empty());
    }

    /// What a pin quotes is the message, so it must follow the edits.
    #[test]
    fn current_revision_returns_the_newest_text() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#c", "v1", 100, "id-1");
        edit(&db, "#c", "v2", 110, "id-2", "id-1");
        edit(&db, "#c", "v3", 120, "id-3", "id-2");

        for named in ["id-1", "id-2", "id-3"] {
            assert_eq!(
                db.current_revision(named).unwrap().unwrap().text,
                "v3",
                "asked by {named}"
            );
        }
        assert!(db.current_revision("id-nowhere").unwrap().is_none());
    }

    /// A DM lives under a canonical `dm:` key rather than a channel name;
    /// resolution is by message lookup, so it must work there identically.
    #[test]
    fn root_resolution_works_in_a_dm_thread() {
        let db = Db::open_memory().unwrap();
        let dm = "dm:did:plc:alice,did:plc:bob";
        msg(&db, dm, "v1", 100, "dm-1");
        edit(&db, dm, "v2", 110, "dm-2", "dm-1");

        db.store_reaction("dm-2", dm, "bob", Some("did:plc:bob"), "🔥", 111)
            .unwrap();
        assert_eq!(reaction_rows(&db, "dm-1").len(), 1);
        assert_eq!(
            db.remove_reaction("dm-1", "bob", Some("did:plc:bob"), "🔥")
                .unwrap(),
            1
        );
    }

    /// An id nobody has a row for — an unpersisted guest DM — is its own root
    /// and must pass through every path untouched.
    #[test]
    fn unknown_ids_pass_through_unchanged() {
        let db = Db::open_memory().unwrap();
        db.store_reaction("ghost", "#c", "bob", None, "🔥", 100)
            .unwrap();
        assert_eq!(reaction_rows(&db, "ghost").len(), 1);
        assert_eq!(db.remove_reaction("ghost", "bob", None, "🔥").unwrap(), 1);

        db.store_pin("#c", "ghost", "alice", 100).unwrap();
        assert_eq!(db.get_pins("#c").unwrap()[0].msgid, "ghost");
        assert_eq!(db.remove_pin("#c", "ghost").unwrap(), 1);

        assert_eq!(db.soft_delete_message("#c", "ghost").unwrap(), 0);
    }

    #[test]
    fn recent_nick_for_did_recovers_bare_nick_from_history() {
        let db = Db::open_memory().unwrap();
        // A DID with no `identities` row (old/remote), but message history.
        db.insert_message(
            "#dev",
            "bob!b@freeq/plc/xxxx",
            "hi",
            100,
            &HashMap::new(),
            Some("m1"),
            Some("did:plc:bob"),
        )
        .unwrap();
        db.insert_message(
            "#dev",
            "bobby!b@freeq/plc/xxxx",
            "renamed",
            200,
            &HashMap::new(),
            Some("m2"),
            Some("did:plc:bob"),
        )
        .unwrap();

        // Most recent mask wins; the `!user@host` suffix is stripped.
        assert_eq!(
            db.recent_nick_for_did("did:plc:bob").unwrap().as_deref(),
            Some("bobby")
        );
        // Unknown DID resolves to nothing.
        assert_eq!(db.recent_nick_for_did("did:plc:nobody").unwrap(), None);
    }

    #[test]
    fn duplicate_msgid_insert_is_ignored() {
        let db = Db::open_memory().unwrap();
        db.insert_message("#c", "a!a@h", "original", 100, &HashMap::new(), Some("DUPID"), None)
            .unwrap();
        // Same msgid arriving again (an S2S re-delivery, or a raced client
        // mint slipping past the pre-insert lookup): first write wins, the
        // second is a no-op, not an error and not a second row.
        db.insert_message("#c", "a!a@h", "impostor", 200, &HashMap::new(), Some("DUPID"), None)
            .unwrap();
        let msgs = db.get_messages("#c", 10, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "original");
    }

    #[test]
    fn duplicate_msgid_insert_does_not_corrupt_search_index() {
        // On an ignored INSERT, `last_insert_rowid()` still names some earlier
        // row — indexing the discarded text under it would bind that text to
        // the wrong message in search.
        let db = Db::open_memory().unwrap();
        db.insert_message("#c", "a!a@h", "kept words", 100, &HashMap::new(), Some("DUPFTS"), None)
            .unwrap();
        db.insert_message("#c", "a!a@h", "phantom words", 200, &HashMap::new(), Some("DUPFTS"), None)
            .unwrap();
        assert!(db.search_messages("#c", "phantom", 10, None).unwrap().is_empty());
        assert_eq!(db.search_messages("#c", "kept", 10, None).unwrap().len(), 1);
    }

    #[test]
    fn edit_claiming_spent_msgid_is_ignored() {
        let db = Db::open_memory().unwrap();
        db.insert_message("#c", "a!a@h", "one", 100, &HashMap::new(), Some("SPENT"), None)
            .unwrap();
        db.insert_message("#c", "a!a@h", "two", 150, &HashMap::new(), Some("ORIG"), None)
            .unwrap();
        // A revision row may not take over an id already on file.
        db.insert_edit("#c", "a!a@h", "two edited", 200, &HashMap::new(), "SPENT", "ORIG", None)
            .unwrap();
        let n: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM messages WHERE msgid = 'SPENT'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let text: String = db
            .conn
            .query_row("SELECT text FROM messages WHERE msgid = 'SPENT'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(text, "one");
    }

    #[test]
    fn recent_nick_for_did_skips_rows_without_sender_did() {
        let db = Db::open_memory().unwrap();
        // Pre-migration rows carry NULL sender_did (no backfill) and must be
        // invisible to the DID-keyed lookup.
        db.insert_message(
            "#dev",
            "dave!d@host",
            "legacy",
            100,
            &HashMap::new(),
            Some("l1"),
            None,
        )
        .unwrap();
        assert_eq!(db.recent_nick_for_did("did:plc:dave").unwrap(), None);
    }

    #[test]
    fn recent_nick_for_did_ignores_degenerate_masks() {
        let db = Db::open_memory().unwrap();
        // Sender mask that is literally the DID (defensive) resolves to None.
        db.insert_message(
            "#dev",
            "did:plc:ghost",
            "x",
            100,
            &HashMap::new(),
            Some("g1"),
            Some("did:plc:ghost"),
        )
        .unwrap();
        assert_eq!(db.recent_nick_for_did("did:plc:ghost").unwrap(), None);
    }

    #[test]
    fn search_finds_matching_messages_newest_first() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "deploy went fine", 100, "m1");
        msg(&db, "#dev", "lunch plans anyone", 200, "m2");
        msg(&db, "#dev", "the deploy failed again", 300, "m3");

        let hits = db.search_messages("#dev", "deploy", 50, None).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].msgid.as_deref(), Some("m3"));
        assert_eq!(hits[1].msgid.as_deref(), Some("m1"));
    }

    #[test]
    fn retention_prunes_by_age_across_channels_and_keeps_recent() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "ancient", 100, "a1");
        msg(&db, "#ops", "also old", 150, "a2");
        msg(&db, "#dev", "recent", 1_000, "r1");

        // Cut off everything before ts 500: the two old rows go, the recent stays.
        let removed = db.prune_messages_older_than(500).unwrap();
        assert_eq!(removed, 2);

        assert!(
            db.get_messages("#dev", 50, None)
                .unwrap()
                .iter()
                .all(|m| m.msgid.as_deref() == Some("r1"))
        );
        assert!(db.get_messages("#ops", 50, None).unwrap().is_empty());
        // Pruned rows also leave the FTS index (no stale search hits).
        assert!(
            db.search_messages("#dev", "ancient", 50, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn search_is_channel_scoped_and_ands_terms() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "deploy failed", 100, "m1");
        msg(&db, "#ops", "deploy failed", 110, "m2");
        msg(&db, "#dev", "deploy succeeded", 120, "m3");

        let hits = db
            .search_messages("#dev", "deploy failed", 50, None)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].msgid.as_deref(), Some("m1"));
    }

    #[test]
    fn search_excludes_deleted_and_pruned() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "secret apple", 100, "m1");
        msg(&db, "#dev", "banana", 200, "m2");
        msg(&db, "#dev", "cherry", 300, "m3");

        db.soft_delete_message("#dev", "m1").unwrap();
        assert!(
            db.search_messages("#dev", "apple", 50, None)
                .unwrap()
                .is_empty()
        );

        db.prune_messages("#dev", 1).unwrap();
        assert!(
            db.search_messages("#dev", "banana", 50, None)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.search_messages("#dev", "cherry", 50, None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn search_pagination_with_before() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "build one", 100, "m1");
        msg(&db, "#dev", "build two", 200, "m2");
        msg(&db, "#dev", "build three", 300, "m3");

        let page = db.search_messages("#dev", "build", 2, None).unwrap();
        assert_eq!(page[0].msgid.as_deref(), Some("m3"));
        assert_eq!(page[1].msgid.as_deref(), Some("m2"));

        let next = db
            .search_messages("#dev", "build", 2, Some(page[1].timestamp))
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].msgid.as_deref(), Some("m1"));
    }

    #[test]
    fn search_treats_fts_operators_literally() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "a OR b syntax question", 100, "m1");
        msg(&db, "#dev", "unrelated", 200, "m2");

        // None of these may error or be interpreted as FTS5 syntax.
        for q in ["OR", "\"quoted\"", "wild*", "(group)", "NEAR", "col:val"] {
            let _ = db.search_messages("#dev", q, 50, None).unwrap();
        }
        let hits = db.search_messages("#dev", "OR", 50, None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].msgid.as_deref(), Some("m1"));
        assert!(
            db.search_messages("#dev", "   ", 50, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn search_reflects_edits() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "original wording", 100, "m1");
        edit(&db, "#dev", "revised phrasing", 200, "m2", "m1");

        assert!(
            db.search_messages("#dev", "original", 50, None)
                .unwrap()
                .is_empty()
        );
        let hits = db.search_messages("#dev", "revised", 50, None).unwrap();
        assert_eq!(hits.len(), 1);
        // The row comes back as itself; the root rides alongside for the
        // handlers to address the hit by.
        assert_eq!(hits[0].msgid.as_deref(), Some("m2"));
        assert_eq!(hits[0].root_msgid.as_deref(), Some("m1"));
    }

    /// Encrypted databases search by decrypt-and-scan rather than FTS; a
    /// superseded revision must not surface there either.
    #[test]
    fn search_reflects_edits_on_encrypted_database() {
        let db = Db::open_encrypted_memory([9u8; 32]).unwrap();
        msg(&db, "#dev", "original wording", 100, "m1");
        edit(&db, "#dev", "revised phrasing", 200, "m2", "m1");

        assert!(
            db.search_messages("#dev", "original", 50, None)
                .unwrap()
                .is_empty()
        );
        let hits = db.search_messages("#dev", "revised", 50, None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].msgid.as_deref(), Some("m2"));
        assert_eq!(hits[0].root_msgid.as_deref(), Some("m1"));
    }

    /// A revision indexed before the upgrade is still in the FTS table —
    /// nothing rewrites existing index rows. Searching a word both revisions
    /// share must not return the message twice, since both hits would carry
    /// the same root id: one message, two results, which is the duplicate
    /// identity the root keying exists to prevent.
    #[test]
    fn search_returns_one_hit_when_an_old_revision_is_still_indexed() {
        let db = Db::open_memory().unwrap();
        msg(&db, "#dev", "shared word original", 100, "m1");
        edit(&db, "#dev", "shared word revised", 200, "m2", "m1");

        // Undo the edit-time index prune to stand in for a row indexed before
        // the upgrade, then confirm the stale revision really is searchable.
        let old_rowid: i64 = db
            .conn
            .query_row(
                "SELECT id FROM messages WHERE msgid = 'm1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT OR REPLACE INTO messages_fts (rowid, text) VALUES (?1, 'shared word original')",
                params![old_rowid],
            )
            .unwrap();
        let indexed: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages_fts WHERE rowid = ?1",
                params![old_rowid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 1, "precondition: the old revision is indexed");

        let hits = db.search_messages("#dev", "shared", 50, None).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "one message, one hit: {:?}",
            hits.iter().map(|h| (&h.text, &h.msgid)).collect::<Vec<_>>()
        );
        assert_eq!(hits[0].text, "shared word revised");
        assert_eq!(hits[0].msgid.as_deref(), Some("m2"));
        assert_eq!(hits[0].root_msgid.as_deref(), Some("m1"));
    }

    /// The data migration runs once and stamps the schema, instead of
    /// re-scanning `reactions` and `pins` on every start to conclude there is
    /// nothing to move.
    #[test]
    fn the_root_msgid_migration_runs_once_and_stamps_the_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeq.db");
        {
            let db = Db::open(&path).unwrap();
            msg(&db, "#c", "v1", 100, "id-1");
            edit(&db, "#c", "v2", 110, "id-2", "id-1");
            assert_eq!(
                db.conn
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                6,
                "first open stamps the schema"
            );
        }

        // Reopening finds the stamp and skips the backfill; the identities it
        // established are still the ones on file.
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            6
        );
        assert_eq!(db.root_of("id-2"), "id-1");
        assert_eq!(db.current_revision("id-1").unwrap().unwrap().text, "v2");
    }

    /// A database written before the stamp existed still gets migrated: the
    /// gate is a floor, not a marker that only new databases carry.
    #[test]
    fn an_unstamped_database_is_migrated_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeq.db");
        {
            let db = Db::open(&path).unwrap();
            msg(&db, "#c", "v1", 100, "id-1");
            edit(&db, "#c", "v2", 110, "id-2", "id-1");
            // Roll back to what an older build left behind: roots unstamped,
            // schema version never set.
            db.conn
                .execute("UPDATE messages SET root_msgid = NULL", [])
                .unwrap();
            db.conn.execute_batch("PRAGMA user_version = 0").unwrap();
        }

        let db = Db::open(&path).unwrap();
        assert_eq!(db.root_of("id-2"), "id-1", "the backfill ran on open");
        assert_eq!(
            db.conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            6
        );
    }

    /// A database from before some ALTER-era columns existed still converges:
    /// the baseline's CREATE IF NOT EXISTS no-ops over its tables and the
    /// ALTER loop adds what's missing — the old boot-time replay's semantics,
    /// now inside migration 1. Guards against ever folding the ALTER columns
    /// into the baseline CREATEs, which would leave such a database stamped
    /// but missing columns.
    #[test]
    fn an_ancient_database_gains_the_altered_columns_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeq.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel   TEXT NOT NULL,
                    sender    TEXT NOT NULL,
                    text      TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    tags_json TEXT NOT NULL DEFAULT '{}'
                );",
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();
        // The ALTER-era columns now exist and are writable.
        db.conn
            .execute(
                "INSERT INTO messages (channel, sender, text, timestamp, msgid, root_msgid)
                 VALUES ('#c', 'a', 't', 1, 'm1', 'm1')",
                [],
            )
            .unwrap();
        assert_eq!(db.root_of("m1"), "m1");
        assert_eq!(
            db.conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            6
        );
    }

    #[test]
    fn search_works_on_encrypted_database_via_scan() {
        let db = Db::open_encrypted_memory([7u8; 32]).unwrap();
        msg(&db, "#dev", "Deploy Failed Loudly", 100, "m1");
        msg(&db, "#dev", "all quiet", 200, "m2");
        db.soft_delete_message("#dev", "m2").unwrap();

        // Case-insensitive match on decrypted text; no FTS table involved.
        let hits = db
            .search_messages("#dev", "deploy failed", 50, None)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "Deploy Failed Loudly");
        assert!(
            db.search_messages("#dev", "quiet", 50, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn opening_encrypted_drops_plaintext_fts_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeq.db");
        {
            let db = Db::open(&path).unwrap();
            msg(&db, "#dev", "plaintext indexed", 100, "m1");
            assert_eq!(
                db.search_messages("#dev", "plaintext", 50, None)
                    .unwrap()
                    .len(),
                1
            );
        }
        let db = Db::open_encrypted(&path, [9u8; 32]).unwrap();
        let fts_exists: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'messages_fts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            fts_exists, 0,
            "plaintext FTS index must not survive encryption"
        );
    }

    #[test]
    fn reopening_plaintext_backfills_fts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeq.db");
        {
            let db = Db::open(&path).unwrap();
            msg(&db, "#dev", "needle in history", 100, "m1");
            // Simulate a pre-FTS database (or one previously run encrypted).
            db.conn.execute_batch("DROP TABLE messages_fts;").unwrap();
        }
        let db = Db::open(&path).unwrap();
        let hits = db.search_messages("#dev", "needle", 50, None).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn roundtrip_channel_state() {
        let db = Db::open_memory().unwrap();

        let mut ch = ChannelState::default();
        ch.topic = Some(TopicInfo {
            text: "Hello world".to_string(),
            set_by: "alice!a@host".to_string(),
            set_at: 1700000000,
        });
        ch.topic_locked = true;
        ch.invite_only = false;
        ch.key = Some("secret".to_string());

        db.save_channel("#test", &ch).unwrap();

        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert!(loaded_ch.topic.is_some());
        let t = loaded_ch.topic.as_ref().unwrap();
        assert_eq!(t.text, "Hello world");
        assert_eq!(t.set_by, "alice!a@host");
        assert_eq!(t.set_at, 1700000000);
        assert!(loaded_ch.topic_locked);
        assert!(!loaded_ch.invite_only);
        assert_eq!(loaded_ch.key.as_deref(), Some("secret"));
        // Runtime state should be empty
        assert!(loaded_ch.members.is_empty());
        assert!(loaded_ch.ops.is_empty());
    }

    #[test]
    fn roundtrip_bans() {
        let db = Db::open_memory().unwrap();

        // Must create the channel first
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();

        let ban = BanEntry {
            mask: "bad!*@*".to_string(),
            set_by: "op!o@host".to_string(),
            set_at: 1700000000,
        };
        db.add_ban("#test", &ban).unwrap();

        let ban2 = BanEntry {
            mask: "did:plc:abc".to_string(),
            set_by: "op!o@host".to_string(),
            set_at: 1700000001,
        };
        db.add_ban("#test", &ban2).unwrap();

        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert_eq!(loaded_ch.bans.len(), 2);
        assert_eq!(loaded_ch.bans[0].mask, "bad!*@*");
        assert_eq!(loaded_ch.bans[1].mask, "did:plc:abc");

        // Remove one
        db.remove_ban("#test", "bad!*@*").unwrap();
        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert_eq!(loaded_ch.bans.len(), 1);
        assert_eq!(loaded_ch.bans[0].mask, "did:plc:abc");
    }

    #[test]
    fn media_insert_get_softdelete() {
        let db = Db::open_memory().unwrap();

        db.insert_media(
            "abc123",
            "did:plc:alice",
            "#test",
            "image/jpeg",
            4096,
            Some("a cat"),
            "cat.jpg",
            1000,
        )
        .unwrap();

        let row = db.get_media("abc123").unwrap().expect("media should exist");
        assert_eq!(row.id, "abc123");
        assert_eq!(row.uploader_did, "did:plc:alice");
        assert_eq!(row.scope, "#test");
        assert_eq!(row.mime, "image/jpeg");
        assert_eq!(row.size, 4096);
        assert_eq!(row.alt.as_deref(), Some("a cat"));
        assert_eq!(row.filename, "cat.jpg");
        assert_eq!(row.created_at, 1000);
        assert!(row.deleted_at.is_none());

        // Unknown id → None.
        assert!(db.get_media("nope").unwrap().is_none());

        // Soft delete hides it from get_media.
        assert_eq!(db.soft_delete_media("abc123").unwrap(), 1);
        assert!(db.get_media("abc123").unwrap().is_none());
        // Deleting again is a no-op.
        assert_eq!(db.soft_delete_media("abc123").unwrap(), 0);
    }

    #[test]
    fn roundtrip_messages() {
        let db = Db::open_memory().unwrap();

        let mut tags = HashMap::new();
        tags.insert("content-type".to_string(), "image/jpeg".to_string());

        db.insert_message(
            "#test",
            "alice!a@host",
            "hello",
            1000,
            &HashMap::new(),
            Some("01TEST00000000000000000001"),
            None,
        )
        .unwrap();
        db.insert_message(
            "#test",
            "bob!b@host",
            "world",
            1001,
            &tags,
            Some("01TEST00000000000000000002"),
            None,
        )
        .unwrap();
        db.insert_message(
            "#test",
            "alice!a@host",
            "third",
            1002,
            &HashMap::new(),
            Some("01TEST00000000000000000003"),
            None,
        )
        .unwrap();

        // Get last 2
        let msgs = db.get_messages("#test", 2, None).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].text, "world");
        assert_eq!(msgs[0].tags.get("content-type").unwrap(), "image/jpeg");
        assert_eq!(msgs[1].text, "third");

        // Paginate: before timestamp 1002
        let msgs = db.get_messages("#test", 10, Some(1002)).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].text, "hello");
        assert_eq!(msgs[1].text, "world");
    }

    #[test]
    fn roundtrip_identities() {
        let db = Db::open_memory().unwrap();

        db.save_identity("did:plc:alice", "alice").unwrap();
        db.save_identity("did:plc:bob", "bob").unwrap();

        let all = db.load_identities().unwrap();
        assert_eq!(all.len(), 2);

        let by_nick = db.get_identity_by_nick("alice").unwrap().unwrap();
        assert_eq!(by_nick.did, "did:plc:alice");

        let by_did = db.get_identity_by_did("did:plc:bob").unwrap().unwrap();
        assert_eq!(by_did.nick, "bob");

        // Update nick
        db.save_identity("did:plc:alice", "alice2").unwrap();
        let updated = db.get_identity_by_did("did:plc:alice").unwrap().unwrap();
        assert_eq!(updated.nick, "alice2");

        // Old nick no longer resolves
        assert!(db.get_identity_by_nick("alice").unwrap().is_none());
    }

    #[test]
    fn save_identity_records_last_auth_at() {
        let db = Db::open_memory().unwrap();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        db.save_identity("did:plc:alice", "alice").unwrap();

        let ts: Option<i64> = db
            .conn
            .query_row(
                "SELECT last_auth_at FROM identities WHERE did=?1",
                rusqlite::params!["did:plc:alice"],
                |r| r.get(0),
            )
            .unwrap();
        let ts = ts.expect("last_auth_at should be set on save_identity");

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            ts >= before && ts <= after,
            "last_auth_at {ts} not in [{before},{after}]"
        );
    }

    #[test]
    fn channel_delete_cascades_bans() {
        let db = Db::open_memory().unwrap();
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();
        let ban = BanEntry {
            mask: "bad!*@*".to_string(),
            set_by: "op".to_string(),
            set_at: 0,
        };
        db.add_ban("#test", &ban).unwrap();

        db.delete_channel("#test").unwrap();

        let loaded = db.load_channels().unwrap();
        assert!(!loaded.contains_key("#test"));
    }

    #[test]
    fn roundtrip_invite_exceptions() {
        use crate::server::InviteExceptionEntry;
        let db = Db::open_memory().unwrap();

        // Channel must exist first.
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();

        let entry1 = InviteExceptionEntry {
            mask: "*!*@trusted.example".to_string(),
            set_by: "op!o@host".to_string(),
            set_at: 1700000000,
        };
        db.add_invite_exception("#test", &entry1).unwrap();

        let entry2 = InviteExceptionEntry {
            mask: "did:plc:bot1".to_string(),
            set_by: "op!o@host".to_string(),
            set_at: 1700000001,
        };
        db.add_invite_exception("#test", &entry2).unwrap();

        // Duplicate insert must be a no-op (UNIQUE constraint, INSERT OR IGNORE).
        db.add_invite_exception("#test", &entry2).unwrap();

        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert_eq!(loaded_ch.invite_exceptions.len(), 2);
        let masks: Vec<_> = loaded_ch
            .invite_exceptions
            .iter()
            .map(|e| e.mask.as_str())
            .collect();
        assert!(masks.contains(&"*!*@trusted.example"));
        assert!(masks.contains(&"did:plc:bot1"));

        // Remove one, the other persists.
        db.remove_invite_exception("#test", "*!*@trusted.example")
            .unwrap();
        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert_eq!(loaded_ch.invite_exceptions.len(), 1);
        assert_eq!(loaded_ch.invite_exceptions[0].mask, "did:plc:bot1");
    }

    #[test]
    fn channel_delete_cascades_invite_exceptions() {
        use crate::server::InviteExceptionEntry;
        let db = Db::open_memory().unwrap();
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();

        let entry = InviteExceptionEntry {
            mask: "*!*@host".to_string(),
            set_by: "op".to_string(),
            set_at: 0,
        };
        db.add_invite_exception("#test", &entry).unwrap();

        db.delete_channel("#test").unwrap();

        // Channel gone — and recreating it shouldn't carry orphan +I entries.
        let ch2 = ChannelState::default();
        db.save_channel("#test", &ch2).unwrap();
        let loaded = db.load_channels().unwrap();
        let loaded_ch = loaded.get("#test").unwrap();
        assert!(loaded_ch.invite_exceptions.is_empty());
    }

    #[test]
    fn messages_different_channels() {
        let db = Db::open_memory().unwrap();
        db.insert_message("#a", "u", "msg-a", 1000, &HashMap::new(), None, None)
            .unwrap();
        db.insert_message("#b", "u", "msg-b", 1001, &HashMap::new(), None, None)
            .unwrap();

        let a = db.get_messages("#a", 100, None).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].text, "msg-a");

        let b = db.get_messages("#b", 100, None).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].text, "msg-b");
    }

    #[test]
    fn duplicate_ban_ignored() {
        let db = Db::open_memory().unwrap();
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();
        let ban = BanEntry {
            mask: "bad!*@*".to_string(),
            set_by: "op".to_string(),
            set_at: 0,
        };
        db.add_ban("#test", &ban).unwrap();
        db.add_ban("#test", &ban).unwrap(); // should not error

        let loaded = db.load_channels().unwrap();
        assert_eq!(loaded.get("#test").unwrap().bans.len(), 1);
    }

    #[test]
    fn store_and_get_reactions() {
        let db = Db::open_memory().unwrap();
        db.store_reaction(
            "msg001",
            "#test",
            "alice",
            Some("did:plc:alice"),
            "👍",
            1000,
        )
        .unwrap();
        db.store_reaction("msg001", "#test", "bob", None, "👍", 1001)
            .unwrap();
        db.store_reaction(
            "msg001",
            "#test",
            "alice",
            Some("did:plc:alice"),
            "❤️",
            1002,
        )
        .unwrap();

        let reactions = db.get_reactions_for_messages(&["msg001"]).unwrap();
        let msg_reactions = reactions.get("msg001").unwrap();
        assert_eq!(msg_reactions.len(), 3);
        assert_eq!(msg_reactions[0].reactor_nick, "alice");
        assert_eq!(msg_reactions[0].emoji, "👍");
        assert_eq!(msg_reactions[1].reactor_nick, "bob");
        assert_eq!(msg_reactions[2].emoji, "❤️");
    }

    #[test]
    fn user_favorites_roundtrip_preserves_order() {
        let db = Db::open_memory().unwrap();
        assert!(db.get_user_favorites("did:plc:a").unwrap().is_empty());
        db.set_user_favorites("did:plc:a", &["#z".into(), "#a".into(), "#m".into()], 100)
            .unwrap();
        assert_eq!(
            db.get_user_favorites("did:plc:a").unwrap(),
            vec!["#z", "#a", "#m"]
        );
    }

    #[test]
    fn user_favorites_replace_is_atomic_and_scoped_per_did() {
        let db = Db::open_memory().unwrap();
        db.set_user_favorites("did:plc:a", &["#a".into(), "#b".into()], 100)
            .unwrap();
        db.set_user_favorites("did:plc:b", &["#x".into()], 100)
            .unwrap();
        // Replace a's list entirely; b is untouched.
        db.set_user_favorites("did:plc:a", &["#c".into()], 200)
            .unwrap();
        assert_eq!(db.get_user_favorites("did:plc:a").unwrap(), vec!["#c"]);
        assert_eq!(db.get_user_favorites("did:plc:b").unwrap(), vec!["#x"]);
    }

    #[test]
    fn user_favorites_empty_clears() {
        let db = Db::open_memory().unwrap();
        db.set_user_favorites("did:plc:a", &["#a".into()], 100)
            .unwrap();
        db.set_user_favorites("did:plc:a", &[], 200).unwrap();
        assert!(db.get_user_favorites("did:plc:a").unwrap().is_empty());
    }

    #[test]
    fn duplicate_reaction_ignored() {
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#test", "alice", None, "👍", 1000)
            .unwrap();
        db.store_reaction("msg001", "#test", "alice", None, "👍", 1001)
            .unwrap(); // duplicate

        let reactions = db.get_reactions_for_messages(&["msg001"]).unwrap();
        assert_eq!(reactions.get("msg001").unwrap().len(), 1);
    }

    #[test]
    fn remove_reaction() {
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#test", "alice", None, "👍", 1000)
            .unwrap();
        db.store_reaction("msg001", "#test", "alice", None, "❤️", 1001)
            .unwrap();

        let removed = db.remove_reaction("msg001", "alice", None, "👍").unwrap();
        assert_eq!(removed, 1);

        let reactions = db.get_reactions_for_messages(&["msg001"]).unwrap();
        let msg_reactions = reactions.get("msg001").unwrap();
        assert_eq!(msg_reactions.len(), 1);
        assert_eq!(msg_reactions[0].emoji, "❤️");
    }

    #[test]
    fn an_unreact_event_files_even_when_the_subject_message_is_not_on_file() {
        // A reaction can land on a message this server never stored — the
        // UUID-era history rows are exactly that, and reacting to them works.
        // The react files its event under the channel the caller names; the
        // unreact must leave the same record instead of losing it because the
        // subject can't answer for its channel.
        let db = Db::open_memory().unwrap();
        let subject = "2b92520e-7d46-463a-a1ae-05d8e93ea966";
        let react_ev = MutationEvent {
            event_id: "01EVREACT00000000000000001",
            actor_did: Some("did:plc:aaa"),
            signature: None,
            venue: Some("#t"),
            ctx: crate::events::EventContext::default(),
            timestamp: 1000,
        };
        db.store_reaction_by(subject, "#t", "alice", Some("did:plc:aaa"), "👍", 1000, Some(&react_ev))
            .unwrap();
        assert!(
            db.get_event("01EVREACT00000000000000001").unwrap().is_some(),
            "the react on an unknown subject files its event"
        );

        let unreact_ev = MutationEvent {
            event_id: "01EVUNREACT000000000000001",
            actor_did: Some("did:plc:aaa"),
            signature: None,
            venue: Some("#t"),
            ctx: crate::events::EventContext::default(),
            timestamp: 1001,
        };
        let removed = db
            .remove_reaction_by(subject, "alice", Some("did:plc:aaa"), "👍", "#t", Some(&unreact_ev))
            .unwrap();
        assert_eq!(removed, 1, "the reaction row itself must go");
        assert!(
            db.get_event("01EVUNREACT000000000000001").unwrap().is_some(),
            "the unreact must leave the same record the react did"
        );
    }

    #[test]
    fn a_delete_event_files_even_when_the_subject_message_is_not_on_file() {
        // Same property as the unreact twin above, pinned so the guarantee is
        // a test and not an argument: delete takes its channel from the
        // caller, so an unknown subject cannot cost it its event.
        let db = Db::open_memory().unwrap();
        let ev = MutationEvent {
            event_id: "01EVDELETE0000000000000001",
            actor_did: Some("did:plc:aaa"),
            signature: None,
            venue: Some("#t"),
            ctx: crate::events::EventContext::default(),
            timestamp: 1000,
        };
        db.soft_delete_message_by("#t", "2b92520e-7d46-463a-a1ae-05d8e93ea966", Some(&ev))
            .unwrap();
        assert!(
            db.get_event("01EVDELETE0000000000000001").unwrap().is_some(),
            "the delete leaves its record regardless of the subject's presence"
        );
    }

    #[test]
    fn remove_reaction_by_did_survives_nick_change() {
        // A DID user reacted under nick "alice", then changed nick to "alia".
        // Removal must key on the DID — otherwise their reaction is
        // accidentally immortal (the durability bug's evil twin).
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#t", "alice", Some("did:plc:aaa"), "👍", 1000)
            .unwrap();

        let removed = db
            .remove_reaction("msg001", "alia", Some("did:plc:aaa"), "👍")
            .unwrap();
        assert_eq!(removed, 1, "DID match must remove regardless of nick");
        assert!(
            db.get_reactions_for_messages(&["msg001"])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn guest_cannot_remove_did_users_reaction_by_squatting_nick() {
        // alice (authenticated) reacted; later an unauthenticated guest holds
        // the nick "alice". The guest's unreact must NOT delete the DID
        // user's persisted reaction.
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#t", "alice", Some("did:plc:aaa"), "👍", 1000)
            .unwrap();

        let removed = db.remove_reaction("msg001", "alice", None, "👍").unwrap();
        assert_eq!(removed, 0, "guest must not remove a DID-keyed reaction");
        assert_eq!(
            db.get_reactions_for_messages(&["msg001"]).unwrap()["msg001"].len(),
            1
        );
    }

    #[test]
    fn did_user_can_remove_own_guest_era_reaction_under_owned_nick() {
        // A reaction stored before the user authenticated (no DID) under the
        // nick they now own: the authenticated remover with that nick may
        // clear it — it's their row.
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#t", "alice", None, "👍", 1000)
            .unwrap();

        let removed = db
            .remove_reaction("msg001", "alice", Some("did:plc:aaa"), "👍")
            .unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn get_reactions_multiple_messages() {
        let db = Db::open_memory().unwrap();
        db.store_reaction("msg001", "#test", "alice", None, "👍", 1000)
            .unwrap();
        db.store_reaction("msg002", "#test", "bob", None, "🎉", 1001)
            .unwrap();
        db.store_reaction("msg003", "#test", "carol", None, "❤️", 1002)
            .unwrap();

        let reactions = db
            .get_reactions_for_messages(&["msg001", "msg002", "msg003"])
            .unwrap();
        assert!(reactions.contains_key("msg001"));
        assert!(reactions.contains_key("msg002"));
        assert!(reactions.contains_key("msg003"));
    }

    #[test]
    fn get_reactions_empty_input() {
        let db = Db::open_memory().unwrap();
        let reactions = db.get_reactions_for_messages(&[]).unwrap();
        assert!(reactions.is_empty());
    }

    #[test]
    fn get_reactions_no_matches() {
        let db = Db::open_memory().unwrap();
        let reactions = db.get_reactions_for_messages(&["nonexistent"]).unwrap();
        assert!(reactions.is_empty());
    }

    // ── Pin persistence tests ──

    #[test]
    fn store_and_get_pins() {
        let db = Db::open_memory().unwrap();
        db.store_pin("#test", "msg001", "alice", 1000).unwrap();
        db.store_pin("#test", "msg002", "bob", 1001).unwrap();

        let pins = db.get_pins("#test").unwrap();
        assert_eq!(pins.len(), 2);
        // Most recent first
        assert_eq!(pins[0].msgid, "msg002");
        assert_eq!(pins[0].pinned_by, "bob");
        assert_eq!(pins[1].msgid, "msg001");
    }

    #[test]
    fn duplicate_pin_ignored() {
        let db = Db::open_memory().unwrap();
        db.store_pin("#test", "msg001", "alice", 1000).unwrap();
        db.store_pin("#test", "msg001", "bob", 1001).unwrap(); // same msgid

        let pins = db.get_pins("#test").unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].pinned_by, "alice"); // first pinner wins
    }

    #[test]
    fn remove_pin() {
        let db = Db::open_memory().unwrap();
        db.store_pin("#test", "msg001", "alice", 1000).unwrap();
        db.store_pin("#test", "msg002", "bob", 1001).unwrap();

        let removed = db.remove_pin("#test", "msg001").unwrap();
        assert_eq!(removed, 1);

        let pins = db.get_pins("#test").unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].msgid, "msg002");
    }

    #[test]
    fn remove_nonexistent_pin() {
        let db = Db::open_memory().unwrap();
        let removed = db.remove_pin("#test", "nonexistent").unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn pins_separate_per_channel() {
        let db = Db::open_memory().unwrap();
        db.store_pin("#chan1", "msg001", "alice", 1000).unwrap();
        db.store_pin("#chan2", "msg002", "bob", 1001).unwrap();

        let pins1 = db.get_pins("#chan1").unwrap();
        let pins2 = db.get_pins("#chan2").unwrap();
        assert_eq!(pins1.len(), 1);
        assert_eq!(pins2.len(), 1);
        assert_eq!(pins1[0].msgid, "msg001");
        assert_eq!(pins2[0].msgid, "msg002");
    }

    #[test]
    fn load_pins_on_channel_startup() {
        let db = Db::open_memory().unwrap();
        let ch = ChannelState::default();
        db.save_channel("#test", &ch).unwrap();
        db.store_pin("#test", "msg001", "alice", 1000).unwrap();
        db.store_pin("#test", "msg002", "bob", 1001).unwrap();

        let channels = db.load_channels().unwrap();
        let loaded = channels.get("#test").unwrap();
        assert_eq!(loaded.pins.len(), 2);
        assert_eq!(loaded.pins[0].msgid, "msg002"); // most recent first
    }

    #[test]
    fn signing_key_roundtrip_and_get_latest() {
        let db = Db::open_memory().unwrap();
        let did = "did:plc:abc";
        assert!(db.get_signing_key(did).unwrap().is_none());

        let key1 = [1u8; 32];
        db.save_signing_key(did, &key1).unwrap();
        assert_eq!(db.get_signing_key(did).unwrap(), Some(key1));

        // A newer key becomes the "latest" get_signing_key returns (key1 is
        // retained as history — see signing_key_history_is_append_only).
        let key2 = [2u8; 32];
        db.save_signing_key(did, &key2).unwrap();
        assert_eq!(db.get_signing_key(did).unwrap(), Some(key2));

        // Different DID is independent
        db.save_signing_key("did:plc:xyz", &[9u8; 32]).unwrap();
        assert_eq!(db.get_signing_key(did).unwrap(), Some(key2));
        assert_eq!(db.get_signing_key("did:plc:xyz").unwrap(), Some([9u8; 32]));
    }

    #[test]
    fn signing_key_history_is_append_only() {
        use freeq_sdk::act::derive_kid_bytes;
        let db = Db::open_memory().unwrap();
        let did = "did:plc:abc";
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        let (kid1, kid2) = (derive_kid_bytes(&k1), derive_kid_bytes(&k2));

        db.save_signing_key(did, &k1).unwrap();
        db.save_signing_key(did, &k2).unwrap(); // does NOT overwrite k1

        // Both keys retained, each fetchable by its kid.
        assert_eq!(db.get_signing_key_by_kid(did, &kid1).unwrap(), Some(k1));
        assert_eq!(db.get_signing_key_by_kid(did, &kid2).unwrap(), Some(k2));

        // Re-registering the same key is idempotent (no error, still resolves).
        db.save_signing_key(did, &k1).unwrap();
        assert_eq!(db.get_signing_key_by_kid(did, &kid1).unwrap(), Some(k1));
    }

    #[test]
    fn signing_key_lookup_by_unknown_kid_or_did_is_none() {
        use freeq_sdk::act::derive_kid_bytes;
        let db = Db::open_memory().unwrap();
        db.save_signing_key("did:plc:abc", &[1u8; 32]).unwrap();
        let kid = derive_kid_bytes(&[1u8; 32]);
        assert_eq!(
            db.get_signing_key_by_kid("did:plc:abc", "nope").unwrap(),
            None
        );
        assert_eq!(
            db.get_signing_key_by_kid("did:plc:other", &kid).unwrap(),
            None
        );
    }

    #[test]
    fn signing_key_legacy_rows_migrate_to_kid_history() {
        // A DB created with the OLD schema (PK=did, no kid) must, after opening
        // with the new code, have its key backfilled and fetchable by kid — and
        // still returnable as the latest via get_signing_key.
        let db = Db::open_memory_with_legacy_signing_keys().unwrap();
        let did = "did:plc:legacy";
        let key = [7u8; 32];
        let kid = freeq_sdk::act::derive_kid_bytes(&key);
        assert_eq!(db.get_signing_key_by_kid(did, &kid).unwrap(), Some(key));
        assert_eq!(db.get_signing_key(did).unwrap(), Some(key));
    }

    #[test]
    fn signing_key_rejects_wrong_length_on_read() {
        // If somehow a non-32-byte blob ends up in the table, the read API
        // returns None rather than panicking. This guards against a manual DB
        // edit or legacy corruption.
        let db = Db::open_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO signing_keys (did, kid, pubkey, registered_at) VALUES (?1, ?2, ?3, ?4)",
                params!["did:plc:short", "somekid", &[1u8; 16][..], 0i64],
            )
            .unwrap();
        assert!(db.get_signing_key("did:plc:short").unwrap().is_none());
    }
}

// ── Agent governance DB methods ────────────────────────────────────

/// A capability grant row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGrantRow {
    pub id: i64,
    pub channel: String,
    pub agent_did: String,
    pub capability: String,
    pub scope: Option<String>,
    pub ttl_seconds: u64,
    pub requires_approval: bool,
    pub rate_limit: u32,
    pub granted_by: String,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// A governance log entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceLogEntry {
    pub id: i64,
    pub channel: Option<String>,
    pub target_did: String,
    pub action: String,
    pub issued_by: String,
    pub reason: Option<String>,
    pub timestamp: i64,
}

/// A pending approval row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingApprovalRow {
    pub id: String,
    pub channel: String,
    pub agent_did: String,
    pub capability: String,
    pub resource: Option<String>,
    pub requested_at: i64,
    pub granted_by: Option<String>,
    pub granted_at: Option<i64>,
    pub denied_by: Option<String>,
    pub denied_at: Option<i64>,
    pub deny_reason: Option<String>,
    pub expires_at: Option<i64>,
}

impl Db {
    // ── Capability grants ──────────────────────────────────────────

    pub fn grant_capability(
        &self,
        channel: &str,
        agent_did: &str,
        capability: &str,
        scope: Option<&str>,
        ttl_seconds: u64,
        requires_approval: bool,
        rate_limit: u32,
        granted_by: &str,
    ) -> SqlResult<i64> {
        let now = chrono::Utc::now().timestamp();
        let expires_at = if ttl_seconds > 0 {
            Some(now + ttl_seconds as i64)
        } else {
            None
        };
        self.conn.execute(
            "INSERT INTO agent_capability_grants
             (channel, agent_did, capability, scope, ttl_seconds, requires_approval, rate_limit, granted_by, granted_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(channel, agent_did, capability, scope) DO UPDATE SET
                ttl_seconds=excluded.ttl_seconds,
                requires_approval=excluded.requires_approval,
                rate_limit=excluded.rate_limit,
                granted_by=excluded.granted_by,
                granted_at=excluded.granted_at,
                expires_at=excluded.expires_at,
                revoked_at=NULL",
            params![channel, agent_did, capability, scope, ttl_seconds as i64, requires_approval as i32, rate_limit as i32, granted_by, now, expires_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_capabilities(&self, channel: &str, agent_did: &str) -> Vec<CapabilityGrantRow> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, channel, agent_did, capability, scope, ttl_seconds, requires_approval, rate_limit, granted_by, granted_at, expires_at, revoked_at
                 FROM agent_capability_grants
                 WHERE channel = ?1 AND agent_did = ?2 AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?3)"
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        stmt.query_map(params![channel, agent_did, now], |row| {
            Ok(CapabilityGrantRow {
                id: row.get(0)?,
                channel: row.get(1)?,
                agent_did: row.get(2)?,
                capability: row.get(3)?,
                scope: row.get(4)?,
                ttl_seconds: row.get::<_, i64>(5)? as u64,
                requires_approval: row.get::<_, i32>(6)? != 0,
                rate_limit: row.get::<_, i32>(7)? as u32,
                granted_by: row.get(8)?,
                granted_at: row.get(9)?,
                expires_at: row.get(10)?,
                revoked_at: row.get(11)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// What `agent_did` actually holds in `channel`.
    ///
    /// A spawned agent holds exactly the narrowed list it was created with. Its
    /// own manifest is deliberately ignored: a child's authority comes from its
    /// parent, not from what it claims about itself, or delegation would be a
    /// formality anyone could widen by publishing a manifest.
    ///
    /// A top-level agent holds its manifest's channel-specific capabilities, plus
    /// its manifest defaults, plus every live grant in `agent_capability_grants`.
    /// Declaring nothing means holding nothing.
    pub fn effective_capabilities(&self, channel: &str, agent_did: &str) -> Vec<String> {
        // Spawned agents: exactly what was recorded for them.
        if let Ok(caps_json) = self.conn.query_row(
            "SELECT capabilities_json FROM spawned_agents
             WHERE child_did = ?1 AND despawned_at IS NULL",
            params![agent_did],
            |row| row.get::<_, String>(0),
        ) {
            return serde_json::from_str::<Vec<String>>(&caps_json).unwrap_or_default();
        }

        let mut held: Vec<String> = Vec::new();
        let mut add = |c: String| {
            if !c.is_empty() && !held.contains(&c) {
                held.push(c);
            }
        };

        if let Some(manifest_json) = self.get_manifest(agent_did)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&manifest_json)
        {
            let caps = &v["capabilities"];
            if let Some(list) = caps["channels"][channel].as_array() {
                for c in list {
                    if let Some(sc) = c.as_str() {
                        add(sc.to_string());
                    }
                }
            }
            if let Some(list) = caps["default"].as_array() {
                for c in list {
                    if let Some(sc) = c.as_str() {
                        add(sc.to_string());
                    }
                }
            }
        }

        for g in self.get_capabilities(channel, agent_did) {
            add(g.capability);
        }
        held
    }

    /// The capabilities a parent may confer: `requested`, minus anything the
    /// parent does not hold. Order follows `requested` so the result reads back
    /// the way it was asked for.
    ///
    /// This is the intersection PHASE-4 specifies. Without it a parent holding
    /// nothing could record a child holding anything, which is what the server
    /// used to do.
    pub fn narrow_capabilities(
        &self,
        channel: &str,
        parent_did: &str,
        requested: &[String],
    ) -> Vec<String> {
        let held = self.effective_capabilities(channel, parent_did);
        requested
            .iter()
            .filter(|r| held.iter().any(|h| h == *r))
            .cloned()
            .collect()
    }

    pub fn revoke_capability(&self, grant_id: i64) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "UPDATE agent_capability_grants SET revoked_at = ?1 WHERE id = ?2",
            params![now, grant_id],
        )?;
        Ok(())
    }

    pub fn revoke_all_capabilities(&self, channel: &str, agent_did: &str) -> SqlResult<usize> {
        let now = chrono::Utc::now().timestamp();
        let count = self.conn.execute(
            "UPDATE agent_capability_grants SET revoked_at = ?1
             WHERE channel = ?2 AND agent_did = ?3 AND revoked_at IS NULL",
            params![now, channel, agent_did],
        )?;
        Ok(count)
    }

    pub fn expire_capabilities(&self) -> SqlResult<usize> {
        let now = chrono::Utc::now().timestamp();
        let count = self.conn.execute(
            "UPDATE agent_capability_grants SET revoked_at = ?1
             WHERE expires_at IS NOT NULL AND expires_at < ?1 AND revoked_at IS NULL",
            params![now],
        )?;
        Ok(count)
    }

    // ── Governance log ─────────────────────────────────────────────

    pub fn log_governance(
        &self,
        channel: Option<&str>,
        target_did: &str,
        action: &str,
        issued_by: &str,
        reason: Option<&str>,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO governance_log (channel, target_did, action, issued_by, reason, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![channel, target_did, action, issued_by, reason, now],
        )?;
        Ok(())
    }

    // ── Pending approvals ──────────────────────────────────────────

    pub fn create_approval(
        &self,
        id: &str,
        channel: &str,
        agent_did: &str,
        capability: &str,
        resource: Option<&str>,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + 3600; // 1 hour
        self.conn.execute(
            "INSERT INTO pending_approvals (id, channel, agent_did, capability, resource, requested_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, channel, agent_did, capability, resource, now, expires_at],
        )?;
        Ok(())
    }

    pub fn grant_approval(&self, id: &str, granted_by: &str) -> SqlResult<bool> {
        let now = chrono::Utc::now().timestamp();
        let count = self.conn.execute(
            "UPDATE pending_approvals SET granted_by = ?1, granted_at = ?2
             WHERE id = ?3 AND granted_by IS NULL AND denied_by IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)",
            params![granted_by, now, id],
        )?;
        Ok(count > 0)
    }

    pub fn deny_approval(
        &self,
        id: &str,
        denied_by: &str,
        reason: Option<&str>,
    ) -> SqlResult<bool> {
        let now = chrono::Utc::now().timestamp();
        let count = self.conn.execute(
            "UPDATE pending_approvals SET denied_by = ?1, denied_at = ?2, deny_reason = ?3
             WHERE id = ?4 AND granted_by IS NULL AND denied_by IS NULL",
            params![denied_by, now, reason, id],
        )?;
        Ok(count > 0)
    }

    pub fn get_pending_approvals(&self, channel: &str) -> Vec<PendingApprovalRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, channel, agent_did, capability, resource, requested_at,
                        granted_by, granted_at, denied_by, denied_at, deny_reason, expires_at
                 FROM pending_approvals
                 WHERE channel = ?1 AND granted_by IS NULL AND denied_by IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                 ORDER BY requested_at ASC",
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        stmt.query_map(params![channel, now], |row| {
            Ok(PendingApprovalRow {
                id: row.get(0)?,
                channel: row.get(1)?,
                agent_did: row.get(2)?,
                capability: row.get(3)?,
                resource: row.get(4)?,
                requested_at: row.get(5)?,
                granted_by: row.get(6)?,
                granted_at: row.get(7)?,
                denied_by: row.get(8)?,
                denied_at: row.get(9)?,
                deny_reason: row.get(10)?,
                expires_at: row.get(11)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn find_pending_approval_for_agent(
        &self,
        channel: &str,
        agent_did: &str,
        capability: &str,
    ) -> Option<PendingApprovalRow> {
        self.get_pending_approvals(channel)
            .into_iter()
            .find(|a| a.agent_did == agent_did && a.capability == capability)
    }
}

/// A spend record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpendRecord {
    pub id: i64,
    pub channel: String,
    pub agent_did: String,
    pub amount: f64,
    pub unit: String,
    pub description: Option<String>,
    pub task_ref: Option<String>,
    pub timestamp: i64,
}

/// A spawned agent record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpawnedAgentRow {
    pub child_did: String,
    pub parent_did: String,
    pub parent_session: String,
    pub nick: String,
    pub channel: String,
    pub capabilities_json: String,
    pub ttl_seconds: Option<u64>,
    pub task_ref: Option<String>,
    pub spawned_at: i64,
}

// ── Coordination events DB methods ─────────────────────────────────

/// A coordination event row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoordinationEventRow {
    pub event_id: String,
    pub event_type: String,
    pub actor_did: String,
    pub channel: String,
    pub ref_id: Option<String>,
    pub payload_json: String,
    pub signature: Option<String>,
    pub timestamp: i64,
}

/// The bytes behind a coordination event's signature, and what this server
/// concluded about them.
///
/// A signature it could not check is still recorded — the state says so. The
/// alternative was throwing it away, which filed the event under an id the
/// signature did not cover and made it permanently uncheckable.
pub struct SignedCoordination<'a> {
    /// The exact canonical the sender signed.
    pub canonical: &'a str,
    pub state: crate::events::SigState,
}

/// What happened to a coordination event offered for filing.
///
/// Three answers, because a second claim on one id is three different
/// situations and only one of them is a problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationWrite {
    /// Filed: the card written, the event logged.
    Filed,
    /// Already on file, identical, by the same actor — a re-emit. Nothing
    /// written, nothing wrong.
    Duplicate,
    /// Refused. Either a different actor named an id already on file, or the
    /// same actor named it with different content; a conflict receipt records
    /// the second claim in the latter case.
    Refused,
}

impl Db {
    /// Store a coordination event, and file it in the append-only log.
    ///
    /// `signed` carries the exact bytes the event's signature covers and the
    /// verdict this server reached about them — including `Unverifiable`, for
    /// a signature it could not check yet. The row then holds a document a
    /// reader can re-verify later, when the key it names is on file. Without
    /// a signature at all the event is filed as facts and nothing else: it
    /// happened, and nobody signed for it.
    ///
    /// The id is the *client's*, so two claims can name the same one. The
    /// first write wins — the rule the message path already follows
    /// ([`Db::insert_message`]) — because the card and the log resolve a
    /// collision differently on their own: replacing the card while the log
    /// ignores the second write leaves the two disagreeing, and the verify
    /// endpoint then attests bytes the card no longer shows.
    ///
    /// So: an identical re-emit by the same actor is accepted and written
    /// nowhere; a differing claim on an id already on file is refused, with a
    /// [`Db::record_event_conflict`] receipt so the fact that two claims
    /// existed survives; and an id another actor filed is refused outright.
    pub fn store_coordination_event(
        &self,
        event: &CoordinationEventRow,
        signed: Option<SignedCoordination<'_>>,
    ) -> SqlResult<CoordinationWrite> {
        if let Some(filed) = self.coordination_event(&event.event_id)? {
            if filed.actor_did != event.actor_did {
                return Ok(CoordinationWrite::Refused);
            }
            // Everything the event *is*. Not the timestamp: that is when this
            // server took delivery, and a re-emit of the same event is the
            // same event however long later it arrives.
            let same = filed.event_type == event.event_type
                && filed.channel == event.channel
                && filed.ref_id == event.ref_id
                && filed.payload_json == event.payload_json
                && filed.signature == event.signature;
            if same {
                return Ok(CoordinationWrite::Duplicate);
            }
            self.record_event_conflict(
                &event.event_id,
                &crate::events::fingerprint(&format!(
                    "{}\0{}\0{}\0{}",
                    event.event_type,
                    event.channel,
                    event.ref_id.as_deref().unwrap_or(""),
                    event.payload_json,
                )),
            )?;
            tracing::warn!(
                event_id = %event.event_id, actor = %event.actor_did,
                "Coordination event id already on file with DIFFERENT content; \
                 conflicting claim dropped"
            );
            return Ok(CoordinationWrite::Refused);
        }

        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute(
            "INSERT INTO coordination_events
             (event_id, event_type, actor_did, channel, ref_id, payload_json, signature, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.event_id,
                event.event_type,
                event.actor_did,
                event.channel,
                event.ref_id,
                event.payload_json,
                event.signature,
                event.timestamp,
            ],
        )?;
        let record = match signed {
            Some(SignedCoordination { canonical, state }) => EventRecord {
                shape: EventShape::Document(canonical),
                signature: event.signature.as_deref(),
                ctx: crate::events::EventContext {
                    sig_state: state,
                    ..Default::default()
                },
                timestamp: event.timestamp as u64,
            },
            None => EventRecord {
                shape: EventShape::Bare(crate::events::EventFacts {
                    event_id: event.event_id.clone(),
                    kind: "coordination".to_string(),
                    venue: crate::events::venue_of(&event.channel),
                    actor_did: Some(event.actor_did.clone()),
                    subject: event.ref_id.clone(),
                    body_hash: None,
                    emoji: None,
                }),
                signature: None,
                ctx: crate::events::EventContext::default(),
                timestamp: event.timestamp as u64,
            },
        };
        // The log is append-only and first-write-wins. If it declines the id,
        // something else already holds it and the card must not be written
        // either — one of them showing an event the other does not is the
        // disagreement this whole path exists to prevent. Dropping the
        // transaction unwritten is the refusal.
        if !self.insert_event(&record)? {
            tracing::warn!(
                event_id = %event.event_id, actor = %event.actor_did,
                "Event id already in the log; coordination event not filed"
            );
            return Ok(CoordinationWrite::Refused);
        }
        tx.commit()?;
        Ok(CoordinationWrite::Filed)
    }

    /// A coordination event by id, whatever kind it is.
    fn coordination_event(&self, event_id: &str) -> SqlResult<Option<CoordinationEventRow>> {
        self.conn
            .query_row(
                "SELECT event_id, event_type, actor_did, channel, ref_id, payload_json,
                        signature, timestamp
                 FROM coordination_events WHERE event_id = ?1",
                params![event_id],
                |row| {
                    Ok(CoordinationEventRow {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        actor_did: row.get(2)?,
                        channel: row.get(3)?,
                        ref_id: row.get(4)?,
                        payload_json: row.get(5)?,
                        signature: row.get(6)?,
                        timestamp: row.get(7)?,
                    })
                },
            )
            .optional()
    }

    /// Query coordination events with optional filters.
    pub fn query_coordination_events(
        &self,
        channel: &str,
        event_type: Option<&str>,
        ref_id: Option<&str>,
        actor_did: Option<&str>,
        since: Option<i64>,
        limit: usize,
    ) -> Vec<CoordinationEventRow> {
        let mut sql = String::from(
            "SELECT event_id, event_type, actor_did, channel, ref_id, payload_json, signature, timestamp
             FROM coordination_events WHERE channel = ?1"
        );
        let mut param_idx = 2;
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(channel.to_string())];

        if let Some(et) = event_type {
            sql.push_str(&format!(" AND event_type = ?{param_idx}"));
            params_vec.push(Box::new(et.to_string()));
            param_idx += 1;
        }
        if let Some(ri) = ref_id {
            sql.push_str(&format!(" AND ref_id = ?{param_idx}"));
            params_vec.push(Box::new(ri.to_string()));
            param_idx += 1;
        }
        if let Some(ad) = actor_did {
            sql.push_str(&format!(" AND actor_did = ?{param_idx}"));
            params_vec.push(Box::new(ad.to_string()));
            param_idx += 1;
        }
        if let Some(s) = since {
            sql.push_str(&format!(" AND timestamp >= ?{param_idx}"));
            params_vec.push(Box::new(s));
            param_idx += 1;
        }
        let _ = param_idx; // suppress unused warning
        sql.push_str(&format!(" ORDER BY timestamp ASC LIMIT {limit}"));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to prepare coordination query: {e}");
                return Vec::new();
            }
        };
        match stmt.query_map(params_refs.as_slice(), |row| {
            Ok(CoordinationEventRow {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                actor_did: row.get(2)?,
                channel: row.get(3)?,
                ref_id: row.get(4)?,
                payload_json: row.get(5)?,
                signature: row.get(6)?,
                timestamp: row.get(7)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Get a task and all its related events.
    pub fn get_task(&self, task_id: &str) -> Option<CoordinationEventRow> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, event_type, actor_did, channel, ref_id, payload_json, signature, timestamp
             FROM coordination_events WHERE event_id = ?1 AND event_type = 'task_request'"
        ).ok()?;
        stmt.query_row(params![task_id], |row| {
            Ok(CoordinationEventRow {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                actor_did: row.get(2)?,
                channel: row.get(3)?,
                ref_id: row.get(4)?,
                payload_json: row.get(5)?,
                signature: row.get(6)?,
                timestamp: row.get(7)?,
            })
        })
        .ok()
    }

    /// Get all events referencing a task ID.
    pub fn get_task_events(&self, task_id: &str) -> Vec<CoordinationEventRow> {
        self.query_coordination_events("", None, Some(task_id), None, None, 1000)
            .into_iter()
            .collect()
    }

    /// Get task events regardless of channel (by ref_id).
    pub fn get_task_events_all_channels(&self, task_id: &str) -> Vec<CoordinationEventRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT event_id, event_type, actor_did, channel, ref_id, payload_json, signature, timestamp
             FROM coordination_events WHERE ref_id = ?1 ORDER BY timestamp ASC"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(params![task_id], |row| {
            Ok(CoordinationEventRow {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                actor_did: row.get(2)?,
                channel: row.get(3)?,
                ref_id: row.get(4)?,
                payload_json: row.get(5)?,
                signature: row.get(6)?,
                timestamp: row.get(7)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── Agent manifests ──────────────────────────────────────────────

    pub fn save_manifest(
        &self,
        agent_did: &str,
        manifest_json: &str,
        manifest_url: Option<&str>,
        registered_by: &str,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_manifests
             (agent_did, manifest_json, manifest_url, registered_by, registered_at, active)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![agent_did, manifest_json, manifest_url, registered_by, now],
        )?;
        Ok(())
    }

    pub fn get_manifest(&self, agent_did: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT manifest_json FROM agent_manifests WHERE agent_did = ?1 AND active = 1",
                params![agent_did],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn deactivate_manifest(&self, agent_did: &str) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE agent_manifests SET active = 0 WHERE agent_did = ?1",
            params![agent_did],
        )?;
        Ok(())
    }

    pub fn list_manifests(&self) -> Vec<(String, String, i64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT agent_did, manifest_json, registered_at FROM agent_manifests WHERE active = 1 ORDER BY registered_at DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── Spawned agents ─────────────────────────────────────────────

    pub fn record_spawn(
        &self,
        child_did: &str,
        parent_did: &str,
        parent_session: &str,
        nick: &str,
        channel: &str,
        capabilities: &[String],
        ttl_seconds: Option<u64>,
        task_ref: Option<&str>,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        let caps_json = serde_json::to_string(capabilities).unwrap_or_else(|_| "[]".to_string());
        self.conn.execute(
            "INSERT OR REPLACE INTO spawned_agents
             (child_did, parent_did, parent_session, nick, channel, capabilities_json, ttl_seconds, task_ref, spawned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![child_did, parent_did, parent_session, nick, channel, caps_json, ttl_seconds.map(|t| t as i64), task_ref, now],
        )?;
        Ok(())
    }

    pub fn record_despawn(&self, child_did: &str) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "UPDATE spawned_agents SET despawned_at = ?1 WHERE child_did = ?2",
            params![now, child_did],
        )?;
        Ok(())
    }

    pub fn get_active_spawns(&self, parent_did: &str) -> Vec<SpawnedAgentRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT child_did, parent_did, parent_session, nick, channel, capabilities_json, ttl_seconds, task_ref, spawned_at
             FROM spawned_agents WHERE parent_did = ?1 AND despawned_at IS NULL",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(params![parent_did], |row| {
            Ok(SpawnedAgentRow {
                child_did: row.get(0)?,
                parent_did: row.get(1)?,
                parent_session: row.get(2)?,
                nick: row.get(3)?,
                channel: row.get(4)?,
                capabilities_json: row.get(5)?,
                ttl_seconds: row.get::<_, Option<i64>>(6)?.map(|t| t as u64),
                task_ref: row.get(7)?,
                spawned_at: row.get(8)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_spawn_by_nick(&self, channel: &str, nick: &str) -> Option<SpawnedAgentRow> {
        self.conn.query_row(
            "SELECT child_did, parent_did, parent_session, nick, channel, capabilities_json, ttl_seconds, task_ref, spawned_at
             FROM spawned_agents WHERE channel = ?1 AND nick = ?2 AND despawned_at IS NULL",
            params![channel, nick],
            |row| Ok(SpawnedAgentRow {
                child_did: row.get(0)?,
                parent_did: row.get(1)?,
                parent_session: row.get(2)?,
                nick: row.get(3)?,
                channel: row.get(4)?,
                capabilities_json: row.get(5)?,
                ttl_seconds: row.get::<_, Option<i64>>(6)?.map(|t| t as u64),
                task_ref: row.get(7)?,
                spawned_at: row.get(8)?,
            }),
        ).ok()
    }

    // ── Agent spend tracking ──────────────────────────────────────────

    pub fn record_spend(
        &self,
        channel: &str,
        agent_did: &str,
        amount: f64,
        unit: &str,
        description: Option<&str>,
        task_ref: Option<&str>,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO agent_spend (channel, agent_did, amount, unit, description, task_ref, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![channel, agent_did, amount, unit, description, task_ref, now],
        )?;
        Ok(())
    }

    /// Sum spend for a channel/agent/unit since a given timestamp.
    pub fn sum_spend(&self, channel: &str, agent_did: Option<&str>, unit: &str, since: i64) -> f64 {
        let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match agent_did {
            Some(did) => (
                "SELECT COALESCE(SUM(amount), 0.0) FROM agent_spend
                 WHERE channel = ?1 AND agent_did = ?2 AND unit = ?3 AND timestamp >= ?4"
                    .to_string(),
                vec![
                    Box::new(channel.to_string()),
                    Box::new(did.to_string()),
                    Box::new(unit.to_string()),
                    Box::new(since),
                ],
            ),
            None => (
                "SELECT COALESCE(SUM(amount), 0.0) FROM agent_spend
                 WHERE channel = ?1 AND unit = ?2 AND timestamp >= ?3"
                    .to_string(),
                vec![
                    Box::new(channel.to_string()),
                    Box::new(unit.to_string()),
                    Box::new(since),
                ],
            ),
        };
        let refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        self.conn
            .query_row(&sql, refs.as_slice(), |row| row.get(0))
            .unwrap_or(0.0)
    }

    /// Query spend records with optional filters.
    pub fn query_spend(
        &self,
        channel: &str,
        agent_did: Option<&str>,
        since: Option<i64>,
        limit: usize,
    ) -> Vec<SpendRecord> {
        let mut sql = String::from(
            "SELECT id, channel, agent_did, amount, unit, description, task_ref, timestamp
             FROM agent_spend WHERE channel = ?1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(channel.to_string())];
        let mut idx = 2;
        if let Some(did) = agent_did {
            sql.push_str(&format!(" AND agent_did = ?{idx}"));
            params_vec.push(Box::new(did.to_string()));
            idx += 1;
        }
        if let Some(s) = since {
            sql.push_str(&format!(" AND timestamp >= ?{idx}"));
            params_vec.push(Box::new(s));
            idx += 1;
        }
        let _ = idx;
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT {limit}"));
        let refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(refs.as_slice(), |row| {
            Ok(SpendRecord {
                id: row.get(0)?,
                channel: row.get(1)?,
                agent_did: row.get(2)?,
                amount: row.get(3)?,
                unit: row.get(4)?,
                description: row.get(5)?,
                task_ref: row.get(6)?,
                timestamp: row.get(7)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Spend by agent for a channel/unit/period.
    pub fn spend_by_agent(&self, channel: &str, unit: &str, since: i64) -> Vec<(String, f64, i64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT agent_did, SUM(amount), COUNT(*) FROM agent_spend
             WHERE channel = ?1 AND unit = ?2 AND timestamp >= ?3
             GROUP BY agent_did ORDER BY SUM(amount) DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(params![channel, unit, since], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── Channel budgets ──────────────────────────────────────────────

    pub fn set_budget(
        &self,
        channel: &str,
        agent_did: Option<&str>,
        budget_json: &str,
        set_by: &str,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().timestamp();
        let did_key = agent_did.unwrap_or("*");
        self.conn.execute(
            "INSERT OR REPLACE INTO channel_budgets (channel, agent_did, budget_json, set_by, set_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![channel, did_key, budget_json, set_by, now],
        )?;
        Ok(())
    }

    /// Every DID spawned (transitively) by `parent_did` in this channel.
    ///
    /// Bounded, and tolerant of a malformed spawn graph: a cycle terminates
    /// because a DID is only expanded once.
    pub fn descendant_dids(&self, channel: &str, parent_did: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let mut frontier = vec![parent_did.to_string()];
        while let Some(current) = frontier.pop() {
            let mut stmt = match self.conn.prepare(
                "SELECT child_did FROM spawned_agents WHERE channel = ?1 AND parent_did = ?2",
            ) {
                Ok(s) => s,
                Err(_) => break,
            };
            let kids: Vec<String> = match stmt.query_map(params![channel, &current], |r| r.get(0)) {
                Ok(rows) => rows.filter_map(Result::ok).collect(),
                Err(_) => Vec::new(),
            };
            for k in kids {
                if k != parent_did && !found.contains(&k) {
                    found.push(k.clone());
                    frontier.push(k);
                }
            }
            if found.len() > 256 {
                break; // safety valve; no legitimate agent spawns 256 descendants
            }
        }
        found
    }

    /// What `agent_did` has spent, including everything its spawned agents spent.
    ///
    /// Spend is attributed to whoever spent it, so the per-agent breakdown stays
    /// honest — but a budget question is about the whole delegated subtree. A
    /// parent under a hard limit must not be able to spawn a child and carry on
    /// spending, which is what happens if you only sum the parent's own rows.
    pub fn sum_spend_with_descendants(
        &self,
        channel: &str,
        agent_did: &str,
        unit: &str,
        since: i64,
    ) -> f64 {
        let mut total = self.sum_spend(channel, Some(agent_did), unit, since);
        for child in self.descendant_dids(channel, agent_did) {
            total += self.sum_spend(channel, Some(&child), unit, since);
        }
        total
    }

    /// Which DID's budget governs `agent_did` — itself, or the nearest ancestor
    /// that has one. Needed so the subtree total is summed from the right root:
    /// charging a child against the parent's limit means totalling the parent's
    /// subtree, not the child's.
    pub fn budget_owner_for(&self, channel: &str, agent_did: &str) -> Option<String> {
        if self
            .conn
            .query_row(
                "SELECT 1 FROM channel_budgets WHERE channel = ?1 AND agent_did = ?2",
                params![channel, agent_did],
                |row| row.get::<_, i64>(0),
            )
            .is_ok()
        {
            return Some(agent_did.to_string());
        }
        let mut current = agent_did.to_string();
        let mut seen = vec![current.clone()];
        for _ in 0..64 {
            let parent: Option<String> = self
                .conn
                .query_row(
                    "SELECT parent_did FROM spawned_agents WHERE channel = ?1 AND child_did = ?2",
                    params![channel, &current],
                    |row| row.get(0),
                )
                .ok();
            let Some(parent) = parent else { break };
            if seen.contains(&parent) {
                break;
            }
            if self
                .conn
                .query_row(
                    "SELECT 1 FROM channel_budgets WHERE channel = ?1 AND agent_did = ?2",
                    params![channel, &parent],
                    |row| row.get::<_, i64>(0),
                )
                .is_ok()
            {
                return Some(parent);
            }
            seen.push(parent.clone());
            current = parent;
        }
        None
    }

    /// The budget that applies to `agent_did`: its own, else the nearest
    /// ancestor's, else the channel default.
    ///
    /// A spawned agent holds a narrowed subset of its parent's authority, so it
    /// inherits the parent's spending limit too. Without this a child with no
    /// budget of its own falls through to the channel default and the parent's
    /// limit simply does not apply to it.
    pub fn get_budget_inherited(&self, channel: &str, agent_did: &str) -> Option<String> {
        if let Ok(own) = self.conn.query_row(
            "SELECT budget_json FROM channel_budgets WHERE channel = ?1 AND agent_did = ?2",
            params![channel, agent_did],
            |row| row.get::<_, String>(0),
        ) {
            return Some(own);
        }
        // Walk up the spawn chain, nearest ancestor first.
        let mut current = agent_did.to_string();
        let mut seen = vec![current.clone()];
        for _ in 0..64 {
            let parent: Option<String> = self
                .conn
                .query_row(
                    "SELECT parent_did FROM spawned_agents WHERE channel = ?1 AND child_did = ?2",
                    params![channel, &current],
                    |row| row.get(0),
                )
                .ok();
            let Some(parent) = parent else { break };
            if seen.contains(&parent) {
                break; // cycle
            }
            if let Ok(b) = self.conn.query_row(
                "SELECT budget_json FROM channel_budgets WHERE channel = ?1 AND agent_did = ?2",
                params![channel, &parent],
                |row| row.get::<_, String>(0),
            ) {
                return Some(b);
            }
            seen.push(parent.clone());
            current = parent;
        }
        // Channel default.
        self.conn
            .query_row(
                "SELECT budget_json FROM channel_budgets WHERE channel = ?1 AND agent_did = '*'",
                params![channel],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn get_budget(&self, channel: &str, agent_did: Option<&str>) -> Option<String> {
        let did_key = agent_did.unwrap_or("*");
        // Try agent-specific first, then channel default
        self.conn.query_row(
            "SELECT budget_json FROM channel_budgets WHERE channel = ?1 AND agent_did = ?2",
            params![channel, did_key],
            |row| row.get(0),
        ).ok().or_else(|| {
            if agent_did.is_some() {
                self.conn.query_row(
                    "SELECT budget_json FROM channel_budgets WHERE channel = ?1 AND agent_did = '*'",
                    params![channel],
                    |row| row.get(0),
                ).ok()
            } else {
                None
            }
        })
    }

    /// Query governance log entries for a channel.
    pub fn query_governance_log(
        &self,
        channel: Option<&str>,
        limit: usize,
    ) -> Vec<GovernanceLogEntry> {
        let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match channel {
            Some(ch) => (
                "SELECT id, channel, target_did, action, issued_by, reason, timestamp
                 FROM governance_log WHERE channel = ?1 ORDER BY timestamp ASC LIMIT ?2"
                    .to_string(),
                vec![Box::new(ch.to_string()), Box::new(limit as i64)],
            ),
            None => (
                "SELECT id, channel, target_did, action, issued_by, reason, timestamp
                 FROM governance_log ORDER BY timestamp ASC LIMIT ?1"
                    .to_string(),
                vec![Box::new(limit as i64)],
            ),
        };
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(params_refs.as_slice(), |row| {
            Ok(GovernanceLogEntry {
                id: row.get(0)?,
                channel: row.get(1)?,
                target_did: row.get(2)?,
                action: row.get(3)?,
                issued_by: row.get(4)?,
                reason: row.get(5)?,
                timestamp: row.get(6)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── AV sessions ────────────────────────────────────────────────────

    pub fn save_av_session(&self, session: &crate::av::AvSession) -> SqlResult<()> {
        use crate::av::AvSessionState;
        let (ended_at, ended_by) = match &session.state {
            AvSessionState::Active => (None, None),
            AvSessionState::Ended { ended_at, ended_by } => (Some(*ended_at), ended_by.clone()),
        };
        self.conn.execute(
            "INSERT INTO av_sessions (id, channel, created_by, created_at, ended_at, ended_by, title, iroh_ticket, backend, recording, max_participants)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                ended_at=excluded.ended_at,
                ended_by=excluded.ended_by",
            params![
                session.id,
                session.channel,
                session.created_by,
                session.created_at,
                ended_at,
                ended_by,
                session.title,
                session.iroh_ticket,
                serde_json::to_string(&session.media_backend).unwrap_or_default(),
                session.recording_enabled,
                session.max_participants,
            ],
        )?;
        for p in session.participants.values() {
            self.conn.execute(
                "INSERT INTO av_participants (session_id, did, nick, joined_at, left_at, role)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(session_id, did) DO UPDATE SET
                    left_at=excluded.left_at, role=excluded.role",
                params![
                    session.id,
                    p.did,
                    p.nick,
                    p.joined_at,
                    p.left_at,
                    serde_json::to_string(&p.role).unwrap_or_default(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn save_av_artifact(&self, artifact: &crate::av::AvArtifact) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO av_artifacts (id, session_id, kind, created_at, created_by, content_ref, content_type, visibility, title)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact.id, artifact.session_id,
                serde_json::to_string(&artifact.kind).unwrap_or_default(),
                artifact.created_at, artifact.created_by,
                artifact.content_ref, artifact.content_type,
                serde_json::to_string(&artifact.visibility).unwrap_or_default(),
                artifact.title,
            ],
        )?;
        Ok(())
    }

    pub fn list_av_artifacts(&self, session_id: &str) -> SqlResult<Vec<crate::av::AvArtifact>> {
        use crate::av::{ArtifactKind, ArtifactVisibility, AvArtifact};
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, kind, created_at, created_by, content_ref, content_type, visibility, title
             FROM av_artifacts WHERE session_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map([session_id], |row: &rusqlite::Row| {
            let kind_str: String = row.get(2)?;
            let vis_str: String = row.get(7)?;
            Ok(AvArtifact {
                id: row.get(0)?,
                session_id: row.get(1)?,
                kind: serde_json::from_str(&kind_str).unwrap_or(ArtifactKind::Summary),
                created_at: row.get(3)?,
                created_by: row.get(4)?,
                content_ref: row.get(5)?,
                content_type: row.get(6)?,
                visibility: serde_json::from_str(&vis_str)
                    .unwrap_or(ArtifactVisibility::Participants),
                title: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Load all active (non-ended) AV sessions with their participants. Used on server restart.
    pub fn load_active_av_sessions(&self) -> SqlResult<Vec<crate::av::AvSession>> {
        use crate::av::{
            AvParticipant, AvSession, AvSessionState, MediaBackendType, ParticipantRole,
        };
        use std::collections::HashMap;
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, created_by, created_at, title, iroh_ticket, backend, recording, max_participants
             FROM av_sessions WHERE ended_at IS NULL",
        )?;
        let mut sessions: Vec<AvSession> = stmt
            .query_map([], |row: &rusqlite::Row| {
                let backend_str: String = row.get(6)?;
                Ok(AvSession {
                    id: row.get(0)?,
                    channel: row.get(1)?,
                    created_by: row.get(2)?,
                    created_by_nick: String::new(),
                    created_at: row.get(3)?,
                    state: AvSessionState::Active,
                    participants: HashMap::new(),
                    title: row.get(4)?,
                    iroh_ticket: row.get(5)?,
                    media_backend: serde_json::from_str(&backend_str)
                        .unwrap_or(MediaBackendType::IrohLive),
                    recording_enabled: row.get(7)?,
                    max_participants: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Load participants for each session
        for session in &mut sessions {
            let mut pstmt = self.conn.prepare(
                "SELECT did, nick, joined_at, left_at, role FROM av_participants WHERE session_id = ?1",
            )?;
            let participants: Vec<AvParticipant> = pstmt
                .query_map([&session.id], |row: &rusqlite::Row| {
                    let role_str: String = row.get(4)?;
                    Ok(AvParticipant {
                        did: row.get(0)?,
                        nick: row.get(1)?,
                        joined_at: row.get(2)?,
                        left_at: row.get(3)?,
                        role: serde_json::from_str(&role_str).unwrap_or(ParticipantRole::Speaker),
                        tracks: vec![],
                        // Pre-instance-id sessions in the DB: hydrate as None.
                        // New sessions write/read via the DB schema separately.
                        instance_id: None,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            for p in participants {
                // Also recover created_by_nick from the host participant
                if p.did == session.created_by {
                    session.created_by_nick = p.nick.clone();
                }
                session.participants.insert(p.did.clone(), p);
            }
        }
        Ok(sessions)
    }

    pub fn list_channel_av_sessions(
        &self,
        channel: &str,
        limit: u32,
    ) -> SqlResult<Vec<crate::av::AvSession>> {
        use crate::av::{AvSession, AvSessionState, MediaBackendType};
        use std::collections::HashMap;
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, created_by, created_at, ended_at, ended_by, title, iroh_ticket, backend, recording, max_participants
             FROM av_sessions WHERE channel = ?1 ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![channel, limit], |row: &rusqlite::Row| {
            let ended_at: Option<i64> = row.get(4)?;
            let ended_by: Option<String> = row.get(5)?;
            let backend_str: String = row.get(8)?;
            let state = match ended_at {
                Some(ea) => AvSessionState::Ended {
                    ended_at: ea,
                    ended_by,
                },
                None => AvSessionState::Active,
            };
            Ok(AvSession {
                id: row.get(0)?,
                channel: row.get(1)?,
                created_by: row.get(2)?,
                created_by_nick: String::new(),
                created_at: row.get(3)?,
                state,
                participants: HashMap::new(),
                title: row.get(6)?,
                iroh_ticket: row.get(7)?,
                media_backend: serde_json::from_str(&backend_str)
                    .unwrap_or(MediaBackendType::IrohLive),
                recording_enabled: row.get(9)?,
                max_participants: row.get(10)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod event_log_tests {
    use super::*;
    use crate::events::{EventContext, EventFacts, SigState};
    use freeq_sdk::chatsig::{ChatDoc, Mutation};

    const ALICE: &str = "did:plc:logalice";

    fn file(db: &Db, canonical: &str, signature: Option<&str>, ctx: EventContext, ts: u64) -> bool {
        db.insert_event(&EventRecord {
            shape: EventShape::Document(canonical),
            signature,
            ctx,
            timestamp: ts,
        })
        .unwrap()
    }

    /// Every column of every filed row is re-derivable from the row's own
    /// bytes. This is the invariant the whole table rests on: a column that
    /// could drift from the canonical would make the log a second, quieter
    /// source of truth, which is the thing it exists to replace.
    #[test]
    fn every_column_of_every_row_is_re_derivable_from_its_own_bytes() {
        let db = Db::open_memory().unwrap();
        let root = "01KYVT1W2P0000000000000000";
        let dm = freeq_sdk::chatsig::dm_venue(ALICE, "did:plc:bob");

        let docs = vec![
            ChatDoc::message(ALICE, "01AAAA0000000000000000000A", "#room", "plain").canonical(),
            ChatDoc::message(ALICE, "01AAAA0000000000000000000B", "#room", "a reply")
                .with_reply(root)
                .canonical(),
            ChatDoc::message(ALICE, "01AAAA0000000000000000000C", "#room", "revised")
                .with_edit(root)
                .canonical(),
            ChatDoc::message(ALICE, "01AAAA0000000000000000000D", &dm, "quietly").canonical(),
            ChatDoc::message(ALICE, "01AAAA0000000000000000000E", "#room", "coordinated")
                .with_coord([("+freeq.at/event", "task_request")])
                .canonical(),
            ChatDoc::mutation(Mutation::Delete, ALICE, "01AAAA0000000000000000000F", "#room", root)
                .canonical(),
            ChatDoc::mutation(Mutation::React, ALICE, "01AAAA0000000000000000000G", "#room", root)
                .with_emoji("👍")
                .canonical(),
            ChatDoc::mutation(
                Mutation::Unreact,
                ALICE,
                "01AAAA0000000000000000000H",
                "#room",
                root,
            )
            .with_emoji("👍")
            .canonical(),
        ];
        for (i, canonical) in docs.iter().enumerate() {
            assert!(
                file(&db, canonical, Some("ed25519:kid:sig"), EventContext::verified(), i as u64),
                "each document files a row"
            );
        }
        // And one with nothing to derive from, which the audit must skip
        // rather than trip over.
        db.insert_event(&EventRecord {
            shape: EventShape::Bare(EventFacts {
                event_id: "01BARE0000000000000000000A".to_string(),
                kind: "pin".to_string(),
                venue: "#room".to_string(),
                actor_did: None,
                subject: Some(root.to_string()),
                body_hash: None,
                emoji: None,
            }),
            signature: None,
            ctx: EventContext::default(),
            timestamp: 99,
        })
        .unwrap();

        assert_eq!(
            db.events_disagreeing_with_their_bytes().unwrap(),
            Vec::<String>::new()
        );
    }

    /// …and the audit really would catch a drift, rather than passing because
    /// it checks nothing.
    #[test]
    fn the_audit_catches_a_column_that_drifted_from_its_bytes() {
        let db = Db::open_memory().unwrap();
        let canonical = ChatDoc::message(ALICE, "01DRIFT000000000000000000A", "#room", "hi").canonical();
        file(&db, &canonical, None, EventContext::default(), 1);

        db.conn
            .execute("UPDATE events SET venue = '#elsewhere'", [])
            .unwrap();
        let bad = db.events_disagreeing_with_their_bytes().unwrap();
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("venue: #elsewhere != #room"), "{bad:?}");
    }

    /// Bytes the caller calls a document, that are not one, are refused —
    /// filing them would put a canonical in the log nothing can read back.
    #[test]
    fn bytes_that_are_not_a_document_are_refused() {
        let db = Db::open_memory().unwrap();
        assert!(!file(&db, "{\"nope\":true}", None, EventContext::default(), 1));
        assert!(db.all_events().unwrap().is_empty());
    }

    /// A verdict is about a signature. With none on file, nothing has been
    /// concluded — whatever the caller passed.
    #[test]
    fn a_row_with_no_signature_is_unsigned_whatever_the_caller_claimed() {
        let db = Db::open_memory().unwrap();
        let canonical = ChatDoc::message(ALICE, "01NOSIG000000000000000000A", "#room", "hi").canonical();
        file(&db, &canonical, None, EventContext::verified(), 1);
        assert_eq!(
            db.get_event("01NOSIG000000000000000000A").unwrap().unwrap().sig_state,
            SigState::Unsigned
        );
    }

    /// A caller that did not check gets the state that claims least — never
    /// `valid` by omission.
    #[test]
    fn a_signature_nobody_checked_files_as_unverifiable() {
        let db = Db::open_memory().unwrap();
        let canonical = ChatDoc::message(ALICE, "01UNCHK000000000000000000A", "#room", "hi").canonical();
        file(&db, &canonical, Some("ed25519:kid:sig"), EventContext::default(), 1);
        assert_eq!(
            db.get_event("01UNCHK000000000000000000A").unwrap().unwrap().sig_state,
            SigState::Unverifiable
        );
    }

    /// Append-only: an id already in the log keeps the row it has, and the
    /// second claim leaves a receipt instead of a rewrite.
    #[test]
    fn a_second_claim_on_an_id_leaves_a_receipt_not_a_rewrite() {
        let db = Db::open_memory().unwrap();
        let id = "01CONFL00000000000000000AA";
        let first = ChatDoc::message(ALICE, id, "#room", "what I said").canonical();
        let second = ChatDoc::message(ALICE, id, "#room", "what they claim I said").canonical();
        assert!(file(&db, &first, None, EventContext::default(), 1));
        assert!(!file(&db, &second, None, EventContext::default(), 2), "first write wins");

        db.record_event_conflict(id, &crate::events::fingerprint(&second))
            .unwrap();
        let row = db.get_event(id).unwrap().unwrap();
        assert_eq!(row.canonical, first, "the row still holds what arrived first");
        assert_eq!(
            row.conflict.as_deref(),
            Some(crate::events::fingerprint(&second).as_str()),
            "and the dropped claim leaves a trace, so equivocation is not invisible"
        );

        // A third claim adds nothing: the question is whether there was ever
        // a conflict, and one receipt answers it.
        db.record_event_conflict(id, "sha256:another").unwrap();
        assert_eq!(
            db.get_event(id).unwrap().unwrap().conflict,
            row.conflict,
            "the first receipt stands"
        );
    }

    /// The log keeps everything unless an operator says otherwise.
    #[test]
    fn pruning_the_log_happens_only_when_asked() {
        let db = Db::open_memory().unwrap();
        for (i, id) in ["01OLD00000000000000000000A", "01NEW00000000000000000000A"]
            .iter()
            .enumerate()
        {
            let canonical = ChatDoc::message(ALICE, id, "#room", "x").canonical();
            file(&db, &canonical, None, EventContext::default(), i as u64 * 1000);
        }
        assert_eq!(db.all_events().unwrap().len(), 2);
        assert_eq!(db.prune_events_older_than(500).unwrap(), 1);
        assert_eq!(db.all_events().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod dual_write_tests {
    use super::*;
    use crate::events::{EventContext, SigState};

    const ALICE: &str = "did:plc:dualalice";

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Every message written from here on has an event. That is the whole
    /// point of the log being born complete: there is no window in which the
    /// two can disagree.
    #[test]
    fn every_message_written_lands_in_the_log_too() {
        let db = Db::open_memory().unwrap();
        db.insert_message("#Room", "a!u@h", "hello", 10, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap();
        db.insert_message("#Room", "g!u@h", "guest here", 11, &HashMap::new(), Some("M2"), None)
            .unwrap();
        db.insert_edit("#Room", "a!u@h", "revised", 12, &HashMap::new(), "M3", "M1", Some(ALICE))
            .unwrap();

        assert_eq!(
            db.messages_without_events().unwrap(),
            Vec::<String>::new(),
            "message → event parity, which is the direction that holds"
        );
        assert_eq!(
            db.events_disagreeing_with_their_bytes().unwrap(),
            Vec::<String>::new()
        );

        let msg = db.get_event("M1").unwrap().unwrap();
        assert_eq!(msg.kind, "message");
        assert_eq!(msg.venue, "#room", "the venue a signer would have signed");
        assert_eq!(msg.actor_did.as_deref(), Some(ALICE));
        assert_eq!(
            msg.body_hash.as_deref(),
            Some(freeq_sdk::chatsig::body_hash("hello").as_str())
        );

        let guest = db.get_event("M2").unwrap().unwrap();
        assert_eq!(guest.canonical, "", "a guest has no identity to bind");
        assert_eq!(guest.sig_state, SigState::Unsigned);
        assert_eq!(guest.actor_did, None);

        let edit = db.get_event("M3").unwrap().unwrap();
        assert_eq!((edit.kind.as_str(), edit.subject.as_deref()), ("edit", Some("M1")));
    }

    /// The log holds hashes, never bodies. A table that quietly accumulated a
    /// second copy of every private message would be a liability.
    #[test]
    fn no_body_ever_reaches_the_log() {
        let db = Db::open_memory().unwrap();
        let secret = "the passphrase is hunter2";
        db.insert_message("#Room", "a!u@h", secret, 10, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap();

        let hits: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE
                   canonical LIKE '%hunter2%' OR subject LIKE '%hunter2%'
                   OR venue LIKE '%hunter2%' OR COALESCE(signature,'') LIKE '%hunter2%'
                   OR COALESCE(body_hash,'') LIKE '%hunter2%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 0, "the body is in `messages`, and only there");
        assert!(
            db.get_event("M1").unwrap().unwrap().canonical.contains("sha256:"),
            "what the log holds is the hash the document carries"
        );
    }

    /// The signature the row was filed with is the signature the log records,
    /// and the caller's verdict rides with it.
    #[test]
    fn the_log_records_the_signature_and_the_verdict_it_was_filed_with() {
        let db = Db::open_memory().unwrap();
        db.insert_message_with(
            "#Room",
            "a!u@h",
            "signed",
            10,
            &tags(&[("+freeq.at/sig", "ed25519:kid:sig")]),
            Some("M1"),
            Some(ALICE),
            &EventContext::verified(),
        )
        .unwrap();
        db.insert_message_with(
            "#Room",
            "a!u@h",
            "relayed",
            11,
            &tags(&[("+freeq.at/sig", "ed25519:other:sig")]),
            Some("M2"),
            Some(ALICE),
            &EventContext {
                sig_state: SigState::Unverifiable,
                origin: Some("peer.example".to_string()),
            },
        )
        .unwrap();

        let ours = db.get_event("M1").unwrap().unwrap();
        assert_eq!(ours.signature.as_deref(), Some("ed25519:kid:sig"));
        assert_eq!(ours.sig_state, SigState::Valid);
        assert_eq!(ours.origin, None, "local ingress has no relaying peer");

        let theirs = db.get_event("M2").unwrap().unwrap();
        assert_eq!(theirs.sig_state, SigState::Unverifiable);
        assert_eq!(theirs.origin.as_deref(), Some("peer.example"));
    }

    /// A second claim on an id keeps the first row and leaves a receipt —
    /// through the real write path, not a hand-built one.
    #[test]
    fn a_conflicting_message_leaves_a_receipt_on_the_event_it_lost_to() {
        let db = Db::open_memory().unwrap();
        assert!(db
            .insert_message("#Room", "a!u@h", "what I said", 10, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap());
        assert!(!db
            .insert_message("#Room", "a!u@h", "what they claim", 11, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap());

        let row = db.get_event("M1").unwrap().unwrap();
        assert_eq!(
            row.body_hash.as_deref(),
            Some(freeq_sdk::chatsig::body_hash("what I said").as_str()),
            "the log still holds what arrived first"
        );
        assert!(
            row.conflict.is_some(),
            "and records that a differing claim on this id was refused"
        );

        // A re-delivery of the *same* content is not a conflict and leaves no
        // receipt — peers re-deliver all the time.
        let db2 = Db::open_memory().unwrap();
        db2.insert_message("#Room", "a!u@h", "same", 10, &HashMap::new(), Some("M9"), Some(ALICE))
            .unwrap();
        db2.insert_message("#Room", "a!u@h", "same", 10, &HashMap::new(), Some("M9"), Some(ALICE))
            .unwrap();
        assert_eq!(db2.get_event("M9").unwrap().unwrap().conflict, None);
    }

    /// The message row and its event are one write. A message that reached
    /// history with no event would be a hole nothing later could distinguish
    /// from a message that never happened.
    #[test]
    fn the_pair_is_written_together_or_not_at_all() {
        let db = Db::open_memory().unwrap();
        db.insert_message("#Room", "a!u@h", "hi", 10, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap();
        let (msgs, events): (i64, i64) = db
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages), (SELECT COUNT(*) FROM events)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((msgs, events), (1, 1));

        // A refused message writes neither.
        db.insert_message("#Room", "a!u@h", "different", 11, &HashMap::new(), Some("M1"), Some(ALICE))
            .unwrap();
        let (msgs, events): (i64, i64) = db
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages), (SELECT COUNT(*) FROM events)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((msgs, events), (1, 1), "still one of each");
    }

    /// Encryption at rest changes what `messages` holds and nothing about the
    /// log: the document hashes the wire body, which is the same either way.
    #[test]
    fn an_encrypted_database_logs_the_same_document() {
        let plain = Db::open_memory().unwrap();
        let sealed = Db::open_encrypted_memory([7u8; 32]).unwrap();
        for db in [&plain, &sealed] {
            db.insert_message("#Room", "a!u@h", "same body", 10, &HashMap::new(), Some("M1"), Some(ALICE))
                .unwrap();
        }
        assert_eq!(
            plain.get_event("M1").unwrap().unwrap().canonical,
            sealed.get_event("M1").unwrap().unwrap().canonical
        );
    }
}

/// A stable id for a pin or unpin event.
///
/// Pins carry no signer-minted id — nothing signs them — so the log needs one
/// of its own. Derived from what the act *is* (channel, message, direction,
/// second), so re-pinning after an unpin is a new event while a duplicate
/// delivery of the same act is not: the append-only insert then dedupes it for
/// free, which a random id could never do.
fn pin_event_id(channel: &str, msgid: &str, at: u64, pinning: bool) -> String {
    let verb = if pinning { "pin" } else { "unpin" };
    let digest = freeq_sdk::chatsig::body_hash(&format!("{verb}\u{0}{channel}\u{0}{msgid}\u{0}{at}"));
    // `sha256:` + 26 hex characters: the same width as a ULID, so nothing
    // downstream that assumed an id's shape has to widen for these.
    format!("pin-{}", &digest["sha256:".len().."sha256:".len() + 22])
}

impl Db {
    /// Events accepted at or after `since_ts`, oldest first — the whole log,
    /// for local readers and tests.
    pub fn events_since(&self, since_ts: u64, limit: usize) -> SqlResult<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, sig_state, kind, venue,
                    actor_did, subject, body_hash, emoji, origin, conflict, timestamp
             FROM events WHERE timestamp >= ?1
             ORDER BY timestamp ASC, event_id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since_ts as i64, limit as i64], map_stored_event)?;
        rows.collect()
    }

}

#[cfg(test)]
mod replay_window_tests {
    use super::*;

    /// A catch-up answer carries the same events the peer receives live, DMs
    /// included. Live relay is peer-blind broadcast to allowlisted peers, so
    /// withholding a DM from a replay would protect nothing — the peer already
    /// got it as it happened — while denying its own users the messages they
    /// missed. Scope is one rule for both paths; see
    /// `docs/FEDERATION-TOPOLOGY.md`.
    #[test]
    fn a_replay_window_includes_a_direct_message() {
        let db = Db::open_memory().unwrap();
        db.insert_message(
            "#public",
            "a!u@h",
            "in the open",
            10,
            &HashMap::new(),
            Some("M1"),
            Some("did:plc:a"),
        )
        .unwrap();
        db.insert_message(
            "dm:did:plc:a,did:plc:b",
            "a!u@h",
            "between us",
            20,
            &HashMap::new(),
            Some("M2"),
            Some("did:plc:a"),
        )
        .unwrap();

        let window = db.events_since(0, 10).unwrap();
        assert_eq!(window.len(), 2, "the window is the window");
        assert!(
            window.iter().any(|e| e.venue.starts_with("dm:")),
            "including the direct message, which the peer receives live anyway"
        );
    }
}
