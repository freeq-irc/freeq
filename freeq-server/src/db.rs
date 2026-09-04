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

/// A live task, as the view holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActTask {
    pub act_id: String,
    pub kind: String,
    pub venue: String,
    /// Empty = created on this server.
    pub origin: String,
    pub state: String,
    pub offerer: String,
    pub offeree: Option<String>,
    pub assignee: Option<String>,
    pub caps: Option<String>,
    pub deadline: Option<i64>,
    /// The finished action this one revives, when its opener named one. An
    /// annotation: the named action may be one this server never filed.
    pub replaces: Option<String>,
    pub updated: i64,
}

/// One stored task event, as a reader gets it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActLoggedEvent {
    pub event_id: String,
    pub canonical: String,
    pub signature: Option<String>,
    pub actor_did: Option<String>,
    pub venue: String,
    /// Whether the server that owns the task has ruled on this event. A reader
    /// sees an unconfirmed event and knows it decides nothing yet.
    ///
    /// `None` for a receipt, which carries no confirm state of its own: it is
    /// the answer, not something awaiting one.
    pub confirm: Option<crate::events::ConfirmState>,
    pub timestamp: i64,
}

/// An accepted task event on its way into the log and the view.
pub struct ActEvent<'a> {
    /// The exact bytes the signature covers.
    pub canonical: &'a str,
    pub signature: Option<&'a str>,
    /// This event's own id.
    pub event_id: &'a str,
    /// The task it belongs to: its own id when it opens one, `act-id`
    /// otherwise.
    pub act_id: &'a str,
    /// Whether this event opens the task.
    pub opens: bool,
    pub venue: &'a str,
    pub actor: &'a str,
    /// The server itself, for the expiry sweep's own events.
    pub from_system: bool,
    /// The peer this arrived from; `None` for local ingress.
    pub origin: Option<&'a str>,
    pub timestamp: i64,
}

/// What happened to a task event offered to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActWrite {
    /// Filed, and the task now sits in this state. `was` is the state it
    /// came from — `None` for the event that opened it, which came from
    /// nowhere. The two together are what tells a step that moved the task
    /// from one that only reported on it, which is the question a receipt
    /// answers.
    Filed { was: Option<String>, state: String },
    /// Filed as a record, with the view left where it stood: a receipt whose
    /// subject this server has already settled. Confirming something twice
    /// must not move anything twice.
    Recorded,
    /// A receipt was applied: the event it names was re-checked against the
    /// task, ruled legal, and the task now stands in `state`.
    Confirmed { state: String },
    /// A receipt from a peer that is not the task's home. Filed as evidence —
    /// a signed claim to authority somebody made is worth keeping — and
    /// applied to nothing, because authority comes from the link a receipt
    /// arrived on and never from what its payload says.
    ReceiptIgnored,
    /// A receipt naming an event this server does not hold. Nothing is filed:
    /// the receipt waits for its subject and is offered again when the subject
    /// lands, the way an event waits for the key that would settle it.
    ReceiptBeforeSubject,
    /// The home's receipt for an event the rules here refuse. Filed and
    /// applied to nothing: a home's receipt that disagrees with the shared
    /// rules is kept as the signed, comparable evidence it is.
    ReceiptRefused(freeq_sdk::act_transitions::Refusal),
    /// The rules refused the move.
    Refused(freeq_sdk::act_transitions::Refusal),
    /// The event names a task this server has never filed. A task another
    /// server opened counts as filed once its opener has crossed — what stays
    /// unknown is a follow-up to an opener this server never saw. The live
    /// link is ordered per peer, so on a healthy one the opener arrives first;
    /// closing a gap left by an unhealthy one is catch-up's job.
    UnknownTask,
    /// The event belongs to a task another server owns, and it is one that
    /// would move that task. Filed in the log — it happened — and deliberately
    /// not applied to the view: the owning server referees its own tasks.
    StoredNotApplied,
    /// The event was posted outside its task's conversation.
    WrongVenue,
    /// That id is already in the log.
    Duplicate,
    /// The bytes are not a task document at all.
    NotATaskEvent,
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

/// Whether a stored task event's bytes are a receipt — the home's word about
/// another event, rather than a move on a task.
///
/// Read from the document instead of a column, because the column a receipt
/// leaves empty is the same one every event filed before that column existed
/// leaves empty, and the two mean different things.
fn is_receipt_document(canonical: &str) -> bool {
    crate::events::derive_act_view(canonical)
        .is_some_and(|view| freeq_sdk::act_transitions::is_confirmation(&view.verb))
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
            "INSERT INTO channels (name, topic_text, topic_set_by, topic_set_at, topic_locked, invite_only, no_ext_msg, moderated, key, founder_did, did_ops_json, encrypted_only, media_space_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
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
                encrypted_only=excluded.encrypted_only,
                media_space_key=excluded.media_space_key",
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
                ch.media_space_key.as_deref(),
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
        self.conn.execute(
            "DELETE FROM channel_invites WHERE channel = ?1",
            params![name],
        )?;
        Ok(())
    }

    /// Load all persisted channels (metadata + bans). Does not load messages
    /// or runtime-only state (members, ops, voiced, invites).
    pub fn load_channels(&self) -> SqlResult<HashMap<String, ChannelState>> {
        let mut channels = HashMap::new();

        let mut stmt = self.conn.prepare(
            "SELECT name, topic_text, topic_set_by, topic_set_at, topic_locked, invite_only, key, no_ext_msg, moderated, founder_did, did_ops_json, encrypted_only, media_space_key
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
            let media_space_key: Option<String> = row.get(12)?;

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
                media_space_key,
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

    // ── One-shot invites ───────────────────────────────────────────────
    //
    // Distinct from `+I` invite *exceptions* above: those are standing masks,
    // these are single-use grants consumed on join. `+i` is durable, so these
    // must be too — a persistent gate whose keys evaporate on restart locks
    // out everyone who was invited but had not yet joined.

    /// Record an invite. `token` is a DID or a `nick:<name>` fallback; raw
    /// session ids are deliberately never stored, because they cannot match
    /// anything after a restart.
    pub fn add_invite(&self, channel: &str, token: &str, invited_by: &str) -> SqlResult<()> {
        if !Self::is_persistable_invite(token) {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.conn.execute(
            "INSERT OR IGNORE INTO channel_invites (channel, token, invited_by, invited_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![channel, token, invited_by, now as i64],
        )?;
        Ok(())
    }

    /// Consume an invite (on join) or revoke one.
    pub fn remove_invite(&self, channel: &str, token: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM channel_invites WHERE channel = ?1 AND token = ?2",
            params![channel, token],
        )?;
        Ok(())
    }

    /// Drop every invite for a channel (e.g. when `-i` is set).
    pub fn clear_invites(&self, channel: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM channel_invites WHERE channel = ?1",
            params![channel],
        )?;
        Ok(())
    }

    /// All persisted invites, as `channel -> tokens`.
    pub fn load_invites(&self) -> SqlResult<HashMap<String, Vec<String>>> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT channel, token FROM channel_invites")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (channel, token) = row?;
            out.entry(channel).or_default().push(token);
        }
        Ok(out)
    }

    /// Is this token worth persisting? Identities survive a restart; session
    /// ids do not.
    fn is_persistable_invite(token: &str) -> bool {
        token.starts_with("did:") || token.starts_with("nick:")
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
    ///
    /// Ordered by `(timestamp, msgid)`, the same order the msgid cursor cuts
    /// on and the same one a client sorts by. Cutting the opening page on the
    /// row id instead put its boundary in a different place inside a second:
    /// the rows left out sorted newer than anything the client then held, so
    /// paging backwards could never reach them.
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
                 ORDER BY timestamp DESC, COALESCE(msgid, '') DESC
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
                 ORDER BY timestamp DESC, COALESCE(msgid, '') DESC
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
             ORDER BY timestamp ASC, COALESCE(msgid, '') ASC
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

    /// Where `msgid` sits in the order a page is cut on: `(timestamp, msgid)`.
    ///
    /// The second component is what determinately orders two rows sharing a
    /// second, which is the whole point of anchoring a page by msgid rather
    /// than by time. It is the msgid and not the row id because a client sorts
    /// its held messages by `(timestamp, msgid)`: concurrent senders land in
    /// the table in an order that has nothing to do with their msgids, so a
    /// page cut on row id can hand back only rows the client files above its
    /// anchor — the anchor never moves and the reader is stuck there.
    ///
    /// A soft-deleted row still anchors: the reader asked for the page around
    /// an id they hold, and a message deleted after they fetched it is still a
    /// valid place in the order. An edit's root id resolves too, since that is
    /// the id a client holds an edited message under.
    pub fn history_cursor(&self, channel: &str, msgid: &str) -> SqlResult<Option<(u64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp FROM messages
             WHERE channel = ?1 AND (msgid = ?2 OR root_msgid = ?2)
             ORDER BY msgid = ?2 DESC, timestamp ASC, id ASC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![channel, msgid], |row| {
            Ok(row.get::<_, i64>(0)? as u64)
        })?;
        match rows.next() {
            // The second half of the cursor is the id that was ASKED for, not
            // the one on the row it found. They differ only when the ask names
            // an edit's root, and the root is the id the client holds that
            // message under — so it is the id the client sorts it by, which is
            // what the cursor has to agree with.
            Some(ts) => Ok(Some((ts?, msgid.to_string()))),
            None => Ok(None),
        }
    }

    /// Messages strictly before the `(timestamp, msgid)` cursor, oldest first.
    ///
    /// A row with no msgid at all — old enough to predate them — orders as the
    /// empty string, which is where a client puts it too.
    pub fn get_messages_before_cursor(
        &self,
        channel: &str,
        ts: u64,
        msgid: &str,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL
               AND (timestamp < ?2 OR (timestamp = ?2 AND COALESCE(msgid, '') < ?3))
             ORDER BY timestamp DESC, COALESCE(msgid, '') DESC
             LIMIT ?4"
        )?;
        let rows = stmt.query_map(
            params![channel, ts as i64, msgid, limit as i64],
            map_message_row,
        )?;
        let mut result = rows.collect::<SqlResult<Vec<_>>>()?;
        result.reverse();
        if let Some(ref key) = self.encryption_key {
            for row in &mut result {
                row.text = decrypt_at_rest(key, &row.text);
            }
        }
        Ok(result)
    }

    /// Messages strictly after the `(timestamp, msgid)` cursor, oldest first.
    pub fn get_messages_after_cursor(
        &self,
        channel: &str,
        ts: u64,
        msgid: &str,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL
               AND (timestamp > ?2 OR (timestamp = ?2 AND COALESCE(msgid, '') > ?3))
             ORDER BY timestamp ASC, COALESCE(msgid, '') ASC
             LIMIT ?4"
        )?;
        let rows = stmt.query_map(
            params![channel, ts as i64, msgid, limit as i64],
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

    /// Messages at or after the `(timestamp, msgid)` cursor, oldest first.
    ///
    /// The inclusive sibling of {@link get_messages_after_cursor}: the row the
    /// cursor names is served. Only `AROUND` wants that — a reader who asked
    /// for the page surrounding a message wants the message in it.
    fn get_messages_from_cursor(
        &self,
        channel: &str,
        ts: u64,
        msgid: &str,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL
               AND (timestamp > ?2 OR (timestamp = ?2 AND COALESCE(msgid, '') >= ?3))
             ORDER BY timestamp ASC, COALESCE(msgid, '') ASC
             LIMIT ?4"
        )?;
        let rows = stmt.query_map(
            params![channel, ts as i64, msgid, limit as i64],
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

    /// Messages at or after a timestamp (oldest first).
    fn get_messages_from(
        &self,
        channel: &str,
        from: u64,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender, text, timestamp, tags_json, msgid, replaces_msgid, deleted_at, sender_did, root_msgid
             FROM messages
             WHERE channel = ?1 AND deleted_at IS NULL AND timestamp >= ?2
             ORDER BY timestamp ASC, COALESCE(msgid, '') ASC
             LIMIT ?3"
        )?;
        let rows = stmt.query_map(params![channel, from as i64, limit as i64], map_message_row)?;
        let mut result = rows.collect::<SqlResult<Vec<_>>>()?;
        if let Some(ref key) = self.encryption_key {
            for row in &mut result {
                row.text = decrypt_at_rest(key, &row.text);
            }
        }
        Ok(result)
    }

    /// The page surrounding the `(timestamp, msgid)` cursor, oldest first.
    ///
    /// Half the limit from older than the cursor, the rest from the cursor
    /// forward — the anchored row included, since it is the row the reader
    /// asked to be shown. Both halves cut on `(timestamp, msgid)`, so the
    /// page's two edges are ordinary cursors to page out of. A short half is
    /// not padded from the other side: the answer says what is there.
    pub fn get_messages_around_cursor(
        &self,
        channel: &str,
        ts: u64,
        msgid: &str,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let older_limit = limit / 2;
        let mut rows = self.get_messages_before_cursor(channel, ts, msgid, older_limit)?;
        rows.extend(self.get_messages_from_cursor(channel, ts, msgid, limit - older_limit)?);
        Ok(rows)
    }

    /// The page surrounding a timestamp, oldest first.
    ///
    /// The timestamp-anchored sibling of {@link get_messages_around_cursor},
    /// cutting on plain timestamp the way the timestamp-anchored one-sided
    /// pages do. A row stamped exactly `at` belongs to the newer half, so no
    /// row falls between the halves.
    pub fn get_messages_around(
        &self,
        channel: &str,
        at: u64,
        limit: usize,
    ) -> SqlResult<Vec<MessageRow>> {
        let older_limit = limit / 2;
        let mut rows = self.get_messages(channel, older_limit, Some(at))?;
        rows.extend(self.get_messages_from(channel, at, limit - older_limit)?);
        Ok(rows)
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
             ORDER BY timestamp ASC, COALESCE(msgid, '') ASC
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
                    kind: if replaces_msgid.is_some() {
                        "edit"
                    } else {
                        "message"
                    }
                    .to_string(),
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
                kind,
                did,
                ev.event_id,
                &venue,
                &subject,
                emoji,
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
                  actor_did, subject, body_hash, emoji, origin, confirm_state,
                  timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                rec.ctx.confirm.map(crate::events::ConfirmState::as_str),
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
            note(
                "emoji",
                format!("{emoji:?}"),
                format!("{:?}", derived.emoji),
            );
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
        self.store_reaction_by(
            target_msgid,
            channel,
            reactor_nick,
            reactor_did,
            emoji,
            timestamp,
            None,
        )
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
        self.file_bare_event(
            "pin",
            channel,
            &root,
            pinned_at,
            &pin_event_id(channel, &root, pinned_at, true),
        )?;
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
        self.file_bare_event(
            "unpin",
            channel,
            &root,
            now,
            &pin_event_id(channel, &root, now, false),
        )?;
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
    /// public key), or None.
    ///
    /// **Not a verification lookup.** This answers "what key is this identity
    /// using now", which the public key endpoint publishes and the provenance
    /// check needs — not "what key made this signature", which is the only
    /// question chat verification asks. Every chat path resolves the key by
    /// the `kid` the signature names ([`Db::get_signing_key_by_kid`]), so a
    /// signature stays checkable after the session that made it ends and a
    /// key rotation does not turn a body of honest history invalid.
    ///
    /// The retired signature format — a bare base64 blob over
    /// `did\0target\0text\0timestamp`, naming no kid — is what a "latest key"
    /// lookup existed for. It folded a client-minted wall clock that never
    /// crossed the wire, so nothing could rebuild its bytes: it is
    /// uncheckable on every path, classified `unverifiable-legacy-format`,
    /// and never evidence of forgery.
    pub fn get_signing_key(&self, did: &str) -> SqlResult<Option<[u8; 32]>> {
        // rowid DESC breaks ties: registered_at is second-granularity, so two
        // keys registered in the same second must fall back to insertion order.
        self.query_signing_key(
            "SELECT pubkey FROM signing_keys WHERE did = ?1
             ORDER BY registered_at DESC, rowid DESC LIMIT 1",
            params![did],
        )
    }

    /// Every key a DID has ever registered, newest first.
    ///
    /// A delegation certificate is signed once and presented for months, but
    /// the web client registers a fresh MSGSIG key on every session. Checking
    /// only the newest key (`get_signing_key`) therefore rejected every
    /// certificate older than the owner's last browser tab, and the flagship
    /// installation's own delegation verified as false. A verifier that does
    /// not know the kid must try all of them.
    pub fn get_signing_keys(&self, did: &str) -> SqlResult<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare(
            "SELECT pubkey FROM signing_keys WHERE did = ?1
             ORDER BY registered_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map(params![did], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                out.push(arr);
            }
        }
        Ok(out)
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

    // ── One-shot invites ──────────────────────────────────────────────────

    /// The bug this table exists for: `+i` persisted, its invites did not, so
    /// a restart sealed the channel against everyone already invited.
    #[test]
    fn an_invite_outlives_a_restart() {
        let db = Db::open_memory().unwrap();
        db.add_invite("#room", "did:plc:guest", "did:plc:host")
            .unwrap();

        let loaded = db.load_invites().unwrap();
        assert_eq!(
            loaded.get("#room").map(Vec::as_slice),
            Some(["did:plc:guest".to_string()].as_slice())
        );
    }

    /// Session ids are meaningless after a restart. Storing one would restore
    /// an invite that can never match, so they are dropped at the door.
    #[test]
    fn session_ids_are_never_persisted() {
        let db = Db::open_memory().unwrap();
        db.add_invite("#room", "stream-42", "did:plc:host").unwrap();
        db.add_invite("#room", "nick:guest", "did:plc:host")
            .unwrap();

        let loaded = db.load_invites().unwrap();
        let tokens = loaded.get("#room").cloned().unwrap_or_default();
        assert_eq!(tokens, vec!["nick:guest".to_string()]);
    }

    /// A one-shot grant is spent on join; a restart must not resurrect it.
    #[test]
    fn a_consumed_invite_does_not_come_back() {
        let db = Db::open_memory().unwrap();
        db.add_invite("#room", "did:plc:guest", "did:plc:host")
            .unwrap();
        db.remove_invite("#room", "did:plc:guest").unwrap();
        assert!(db.load_invites().unwrap().get("#room").is_none());
    }

    /// Dropping `+i` opens the room, so the outstanding grants are moot and
    /// must not linger to be honoured if `+i` ever returns.
    #[test]
    fn clearing_the_mode_clears_the_invites() {
        let db = Db::open_memory().unwrap();
        db.add_invite("#room", "did:plc:a", "did:plc:host").unwrap();
        db.add_invite("#room", "did:plc:b", "did:plc:host").unwrap();
        db.add_invite("#other", "did:plc:c", "did:plc:host")
            .unwrap();

        db.clear_invites("#room").unwrap();
        let loaded = db.load_invites().unwrap();
        assert!(loaded.get("#room").is_none());
        assert_eq!(loaded.get("#other").map(Vec::len), Some(1));
    }

    #[test]
    fn inviting_the_same_identity_twice_is_idempotent() {
        let db = Db::open_memory().unwrap();
        db.add_invite("#room", "did:plc:guest", "did:plc:host")
            .unwrap();
        db.add_invite("#room", "did:plc:guest", "did:plc:other")
            .unwrap();
        assert_eq!(db.load_invites().unwrap()["#room"].len(), 1);
    }

    // ── Task events: the log, and the view derived from it ────────────────

    const ELIZA: &str = "did:plc:eliza";
    const SCHOLAR: &str = "did:plc:scholar";
    const MALLORY: &str = "did:plc:mallory";
    /// Action ids, in the shape the revival relation insists on: a real ULID.
    /// The short ids elsewhere in these tests are fine — nothing else reads an
    /// id's shape — but `act-replaces` refuses a value that names no action.
    const ONE: &str = "01M16E7TC00000000000000001";
    const TWO: &str = "01M16E7TC00000000000000002";
    const NEVER_SEEN: &str = "01M16E7TC0NEVERSEEN0000000";

    /// Build a task event's canonical the way a signer would.
    fn act_doc(tags: &[(&str, &str)], venue: &str, id: &str) -> String {
        freeq_sdk::act::act_canonical(tags.to_vec(), venue, id).expect("act tags present")
    }

    fn offer(db: &Db, id: &str, venue: &str, to: Option<&str>, ts: i64) -> ActWrite {
        let mut tags = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", ELIZA),
        ];
        if let Some(to) = to {
            tags.push(("+freeq.at/act-to", to));
        }
        let canonical = act_doc(&tags, venue, id);
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    fn follow_up(
        db: &Db,
        verb: &str,
        actor: &str,
        task: &str,
        id: &str,
        venue: &str,
        ts: i64,
    ) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", verb),
                ("+freeq.at/from", actor),
                ("+freeq.at/act-id", task),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task,
            opens: false,
            venue,
            actor,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// The same two moves, arriving from a peer instead of a local client.
    /// `origin` is what tells the view whose task this is.
    fn relayed_offer(db: &Db, id: &str, venue: &str, origin: &str, ts: i64) -> ActWrite {
        let tags = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", ELIZA),
        ];
        let canonical = act_doc(&tags, venue, id);
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: Some(origin),
            timestamp: ts,
        })
        .unwrap()
    }

    fn relayed_follow_up(
        db: &Db,
        verb: &str,
        actor: &str,
        task: &str,
        id: &str,
        venue: &str,
        origin: &str,
        ts: i64,
    ) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", verb),
                ("+freeq.at/from", actor),
                ("+freeq.at/act-id", task),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task,
            opens: false,
            venue,
            actor,
            from_system: false,
            origin: Some(origin),
            timestamp: ts,
        })
        .unwrap()
    }

    /// One relayed event of any kind: an opener when `task` is `None`, a
    /// follow-up on that task otherwise. The pair above covers handoffs, which
    /// is most of these tests; this one is for the cases that need a second
    /// kind.
    #[allow(clippy::too_many_arguments)]
    fn relayed(
        db: &Db,
        id: &str,
        task: Option<&str>,
        kind: &str,
        verb: &str,
        actor: &str,
        venue: &str,
        origin: &str,
        ts: i64,
    ) -> ActWrite {
        let mut tags = vec![
            ("+freeq.at/act", kind),
            ("+freeq.at/act-verb", verb),
            ("+freeq.at/from", actor),
        ];
        if let Some(task) = task {
            tags.push(("+freeq.at/act-id", task));
        }
        let canonical = act_doc(&tags, venue, id);
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task.unwrap_or(id),
            opens: task.is_none(),
            venue,
            actor,
            from_system: false,
            origin: Some(origin),
            timestamp: ts,
        })
        .unwrap()
    }

    // ── whose ruling an event carries ─────────────────────────────────────

    /// What the log says about whose ruling an event carries.
    fn confirm_of(db: &Db, event_id: &str) -> crate::events::ConfirmState {
        let raw: Option<String> = db
            .conn
            .query_row(
                "SELECT confirm_state FROM events WHERE event_id = ?1",
                params![event_id],
                |r| r.get(0),
            )
            .unwrap();
        crate::events::ConfirmState::from_column(raw.as_deref())
    }

    /// An event this server accepted for a task it owns needs nobody's word
    /// but its own: it is confirmed the moment it is filed.
    #[test]
    fn an_event_on_our_own_task_is_confirmed_at_ingress() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", None, 10);
        follow_up(&db, "claim", SCHOLAR, "T1", "T2", "#ops", 11);

        for id in ["T1", "T2"] {
            assert_eq!(
                confirm_of(&db, id),
                crate::events::ConfirmState::Confirmed,
                "{id}: we are the authority over our own tasks"
            );
        }
    }

    /// The rebuild is the proof that the view is derived. It has to agree with
    /// the live table for a foreign task with unruled events hanging off it,
    /// which means passing over exactly the events the live path passed over.
    #[test]
    fn a_rebuild_matches_the_live_view_with_unconfirmed_events_on_file() {
        let db = Db::open_memory().unwrap();
        // Ours, moved by us.
        offer(&db, "M1", "#ops", None, 10);
        follow_up(&db, "claim", SCHOLAR, "M1", "M2", "#ops", 11);
        // A peer's, with a claim from a third server nobody has ruled on.
        relayed_offer(&db, "M3", "#ops", "peer-b", 12);
        relayed_follow_up(&db, "claim", MALLORY, "M3", "M4", "#ops", "peer-c", 13);
        // And a peer's bounty carrying a bid, which is additive — it leaves
        // the action open, so it decides nothing exclusive and is applied and
        // confirmed wherever it lands.
        relayed(
            &db, "M5", None, "bounty", "offer", ELIZA, "#ops", "peer-b", 14,
        );
        relayed(
            &db,
            "M6",
            Some("M5"),
            "bounty",
            "bid",
            MALLORY,
            "#ops",
            "peer-c",
            15,
        );

        assert_eq!(
            confirm_of(&db, "M4"),
            crate::events::ConfirmState::Unconfirmed,
            "a transition on a peer's task waits on that peer"
        );
        assert_eq!(
            confirm_of(&db, "M6"),
            crate::events::ConfirmState::Confirmed,
            "an additive move decides nothing exclusive and waits on nobody"
        );

        let mut live = db
            .act_tasks(&["#ops".to_string()], None, None, None, 100)
            .unwrap();
        let mut rebuilt = db.rebuild_act_actions().unwrap();
        live.sort_by(|a, b| a.act_id.cmp(&b.act_id));
        rebuilt.sort_by(|a, b| a.act_id.cmp(&b.act_id));
        assert_eq!(
            rebuilt, live,
            "the log is the record, and the view is what it derives to"
        );
        assert_eq!(
            rebuilt.iter().find(|t| t.act_id == "M3").unwrap().state,
            "open",
            "an unruled claim moves nothing, in the rebuild as in the view"
        );
    }

    // ── whose task is it ──────────────────────────────────────────────────

    /// An offer relayed from a peer creates the task here, stamped with the
    /// server that owns it. Nothing else can tell later events whose task
    /// they are addressing.
    #[test]
    fn a_task_opened_by_a_peer_is_stamped_with_whose_it_is() {
        let db = Db::open_memory().unwrap();
        assert_eq!(
            relayed_offer(&db, "R1", "#ops", "peer-b", 10),
            ActWrite::Filed {
                was: None,
                state: "open".into()
            }
        );
        let task = db.act_task("R1").unwrap().expect("the task is live");
        assert_eq!(task.origin, "peer-b");
    }

    /// A move that changes where a peer's task stands is filed and stops
    /// there. Deciding it here would be this server ruling on work another
    /// server is refereeing.
    #[test]
    fn a_state_transition_on_a_peers_task_is_filed_but_not_applied() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "R2", "#ops", "peer-b", 10);
        assert_eq!(
            relayed_follow_up(&db, "claim", SCHOLAR, "R2", "E2", "#ops", "peer-b", 20),
            ActWrite::StoredNotApplied
        );
        assert_eq!(
            confirm_of(&db, "E2"),
            crate::events::ConfirmState::Unconfirmed,
            "and it is on file as what it is: waiting on peer-b's ruling"
        );

        let task = db.act_task("R2").unwrap().expect("still live");
        assert_eq!(task.state, "open", "the view did not move");
        assert_eq!(task.assignee, None, "and nobody was assigned here");
        assert_eq!(task.updated, 10, "the row was not touched at all");
        assert!(
            db.is_act_event("E2").unwrap(),
            "but the log gained the event — it happened, we just did not rule on it"
        );
    }

    /// A move that adds to a peer's task without moving it goes through the
    /// ordinary path: there is no state decision in it to usurp.
    #[test]
    fn an_additive_event_on_a_peers_task_reaches_the_view() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "R3", "#ops", "peer-b", 10);
        // The state a claim would have left behind. Reached directly because
        // this server does not apply the peer's claim — routing events home
        // is what will close that gap.
        db.conn
            .execute(
                "UPDATE act_actions SET state = 'assigned', assignee = ?2 WHERE act_id = ?1",
                params!["R3", SCHOLAR],
            )
            .unwrap();

        assert_eq!(
            relayed_follow_up(&db, "progress", SCHOLAR, "R3", "E3", "#ops", "peer-b", 30),
            ActWrite::Filed {
                was: Some("assigned".into()),
                state: "assigned".into()
            }
        );
        let task = db.act_task("R3").unwrap().expect("still live");
        assert_eq!(task.state, "assigned");
        assert_eq!(task.updated, 30, "the view saw the report");
    }

    /// Our own task is ours to decide, whichever link the event came in on.
    #[test]
    fn a_task_opened_here_is_decided_here_however_the_event_arrives() {
        let db = Db::open_memory().unwrap();
        offer(&db, "L1", "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            relayed_follow_up(&db, "accept", SCHOLAR, "L1", "E4", "#ops", "peer-b", 20),
            ActWrite::Filed {
                was: Some("offered".into()),
                state: "assigned".into()
            }
        );
        let task = db.act_task("L1").unwrap().expect("still live");
        assert_eq!(task.state, "assigned");
        assert_eq!(task.assignee.as_deref(), Some(SCHOLAR));
    }

    /// A verb the rules file does not list is refused on a peer's task too.
    /// The table is the shared contract; not refereeing a peer's decisions is
    /// not the same as carrying anything at all.
    #[test]
    fn an_unknown_verb_on_a_peers_task_is_still_refused() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "R4", "#ops", "peer-b", 10);
        assert_eq!(
            relayed_follow_up(&db, "award", MALLORY, "R4", "E5", "#ops", "peer-b", 20),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::UnknownVerb)
        );
        assert!(!db.is_act_event("E5").unwrap(), "and nothing was filed");
    }

    #[test]
    fn an_offer_creates_the_task_it_opens() {
        let db = Db::open_memory().unwrap();
        assert_eq!(
            offer(&db, "T1", "#ops", Some(SCHOLAR), 10),
            ActWrite::Filed {
                was: None,
                state: "offered".into()
            }
        );
        let task = db.act_task("T1").unwrap().expect("the task is live");
        assert_eq!(task.kind, "handoff");
        assert_eq!(task.venue, "#ops");
        assert_eq!(task.state, "offered");
        assert_eq!(task.offerer, ELIZA);
        assert_eq!(task.offeree.as_deref(), Some(SCHOLAR));
        assert_eq!(task.assignee, None);
        assert_eq!(task.origin, "", "created here");
    }

    #[test]
    fn an_open_offer_names_no_offeree_and_lands_open() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", None, 10);
        let task = db.act_task("T1").unwrap().unwrap();
        assert_eq!(task.state, "open");
        assert_eq!(task.offeree, None);
    }

    #[test]
    fn whoever_moves_a_task_to_assigned_becomes_its_assignee() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        assert_eq!(
            db.act_task("T1").unwrap().unwrap().assignee.as_deref(),
            Some(SCHOLAR)
        );

        // …and a progress report does not reassign the work it reports on.
        follow_up(&db, "progress", SCHOLAR, "T1", "E2", "#ops", 12);
        let task = db.act_task("T1").unwrap().unwrap();
        assert_eq!(task.assignee.as_deref(), Some(SCHOLAR));
        assert_eq!(task.state, "assigned");
    }

    #[test]
    fn a_terminal_event_removes_the_row_and_leaves_the_history() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        follow_up(&db, "complete", SCHOLAR, "T1", "E2", "#ops", 12);
        assert_eq!(db.act_task("T1").unwrap(), None, "the view holds live work");
        assert_eq!(
            db.act_task_events("T1").unwrap().len(),
            3,
            "the log holds the whole story"
        );
    }

    /// The state read, the check and the write happen in one call, so the
    /// second claim sees the first one's result. Two agents racing for the
    /// same open post reach this method through `with_db`, which holds the
    /// database mutex for the whole closure — that serialization is what makes
    /// exactly one of them the winner.
    #[test]
    fn two_claims_on_one_open_task_leave_exactly_one_winner() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", None, 10);

        let first = follow_up(&db, "claim", SCHOLAR, "T1", "E1", "#ops", 11);
        let second = follow_up(&db, "claim", MALLORY, "T1", "E2", "#ops", 11);

        assert_eq!(
            first,
            ActWrite::Filed {
                was: Some("open".into()),
                state: "assigned".into()
            }
        );
        assert_eq!(
            second,
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::IllegalStep),
            "the loser is told the step is illegal, not that it lost a race"
        );
        assert_eq!(
            db.act_task("T1").unwrap().unwrap().assignee.as_deref(),
            Some(SCHOLAR)
        );
    }

    #[test]
    fn a_follow_up_naming_no_filed_task_is_unknown() {
        let db = Db::open_memory().unwrap();
        assert_eq!(
            follow_up(&db, "accept", SCHOLAR, "NOSUCH", "E1", "#ops", 11),
            ActWrite::UnknownTask
        );
    }

    #[test]
    fn a_follow_up_from_another_conversation_is_refused() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#elsewhere", 11),
            ActWrite::WrongVenue
        );
        assert_eq!(db.act_task("T1").unwrap().unwrap().state, "offered");
    }

    #[test]
    fn the_rules_refuse_a_wrong_sender_and_the_view_does_not_move() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            follow_up(&db, "accept", MALLORY, "T1", "E1", "#ops", 11),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::WrongSender)
        );
        let task = db.act_task("T1").unwrap().unwrap();
        assert_eq!(task.state, "offered");
        assert_eq!(task.assignee, None);
        assert_eq!(
            db.act_task_events("T1").unwrap().len(),
            1,
            "a refused event is not filed"
        );
    }

    #[test]
    fn a_second_event_under_one_id_is_a_duplicate() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            offer(&db, "T1", "#ops", Some(SCHOLAR), 10),
            ActWrite::Duplicate
        );
    }

    // ── receipts ──────────────────────────────────────────────────────────

    const HOME: &str = "did:web:test";

    /// A receipt as a peer relays one: signed by `home_did`, carried on the
    /// link `origin` names.
    #[allow(clippy::too_many_arguments)]
    fn relayed_receipt(
        db: &Db,
        home_did: &str,
        task: &str,
        subject: &str,
        id: &str,
        venue: &str,
        origin: &str,
        ts: i64,
    ) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "confirm"),
                ("+freeq.at/from", home_did),
                ("+freeq.at/act-id", task),
                ("+freeq.at/act-subject", subject),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task,
            opens: false,
            venue,
            actor: home_did,
            from_system: true,
            origin: Some(origin),
            timestamp: ts,
        })
        .unwrap()
    }

    /// A receipt, filed the way the home files one: its own event id, the
    /// task in `act-id`, and the confirmed event in `act-subject`.
    fn receipt(
        db: &Db,
        task: &str,
        subject: &str,
        id: &str,
        venue: &str,
        from_system: bool,
        ts: i64,
    ) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "confirm"),
                ("+freeq.at/from", HOME),
                ("+freeq.at/act-id", task),
                ("+freeq.at/act-subject", subject),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task,
            opens: false,
            venue,
            actor: HOME,
            from_system,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// A receipt is an appended record and nothing else: the state it names
    /// was moved by the event it confirms, and confirming that twice must not
    /// move anything twice.
    #[test]
    fn a_receipt_is_filed_without_moving_the_view() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        let before = db.act_task("T1").unwrap().unwrap();

        assert_eq!(
            receipt(&db, "T1", "E1", "R1", "#ops", true, 11),
            ActWrite::Recorded
        );
        assert_eq!(db.act_task("T1").unwrap().unwrap(), before);
        assert_eq!(
            db.act_task_events("T1").unwrap().len(),
            3,
            "the offer, the accept, and the home's word about the accept"
        );
    }

    /// A receipt confirming the event that ended a task is still filed: the
    /// row is gone, the log is the record, and the receipt belongs to it.
    #[test]
    fn a_receipt_outlives_the_task_it_confirms() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        follow_up(&db, "complete", SCHOLAR, "T1", "E2", "#ops", 12);
        assert_eq!(db.act_task("T1").unwrap(), None);

        assert_eq!(
            receipt(&db, "T1", "E2", "R1", "#ops", true, 12),
            ActWrite::Recorded
        );
        assert_eq!(db.act_task("T1").unwrap(), None, "and nothing came back");
        assert_eq!(db.act_task_events("T1").unwrap().len(), 4);
    }

    /// The verb is the home's. Bytes arriving from anywhere else carrying it
    /// are refused here as well as at the gate — this path is reachable from a
    /// rebuild and, later, from a peer.
    #[test]
    fn only_the_home_writes_a_receipt() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            receipt(&db, "T1", "T1", "R1", "#ops", false, 11),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::ClientConfirm)
        );
        assert_eq!(
            db.act_task_events("T1").unwrap().len(),
            1,
            "a refused receipt is not filed"
        );
    }

    #[test]
    fn a_second_receipt_under_one_id_is_a_duplicate() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        receipt(&db, "T1", "E1", "R1", "#ops", true, 11);
        assert_eq!(
            receipt(&db, "T1", "E1", "R1", "#ops", true, 11),
            ActWrite::Duplicate
        );
    }

    /// The receipt row carries no confirm state of its own. The column says
    /// whether a task's home has answered for an event, and a receipt is that
    /// answer — a reader seeing "confirmed" on one would be reading the answer
    /// as the question.
    #[test]
    fn a_receipt_carries_no_confirm_state() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        receipt(&db, "T1", "E1", "R1", "#ops", true, 11);

        let states: Vec<(String, Option<crate::events::ConfirmState>)> = db
            .act_task_events("T1")
            .unwrap()
            .into_iter()
            .map(|e| (e.event_id, e.confirm))
            .collect();
        assert_eq!(
            states,
            vec![
                (
                    "T1".to_string(),
                    Some(crate::events::ConfirmState::Confirmed)
                ),
                (
                    "E1".to_string(),
                    Some(crate::events::ConfirmState::Confirmed)
                ),
                ("R1".to_string(), None),
            ]
        );
    }

    // ── a receipt that crossed a link ─────────────────────────────────────
    //
    // The receiving half. A transition on a task another server owns is filed
    // here and moves nothing; the home's receipt naming it is what turns it
    // into a decision. The receipt carries no state — the state comes from
    // running the event it names through these very rules — and it counts as
    // the home's word only because of the link it arrived on.

    const PEER_HOME: &str = "did:web:peer-b.example";

    /// The whole of it: the claim waits, the receipt arrives, the rules take
    /// the claim, and the view moves.
    #[test]
    fn a_receipt_from_the_home_applies_the_event_it_names() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "C1", "#ops", "peer-b", 10);
        assert_eq!(
            relayed_follow_up(&db, "claim", SCHOLAR, "C1", "C2", "#ops", "peer-c", 11),
            ActWrite::StoredNotApplied
        );
        assert_eq!(
            db.act_task("C1").unwrap().unwrap().state,
            "open",
            "nothing moves on a claim nobody has ruled on"
        );

        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-b", 12),
            ActWrite::Confirmed {
                state: "assigned".into()
            }
        );
        let task = db.act_task("C1").unwrap().expect("still live");
        assert_eq!(task.state, "assigned");
        assert_eq!(task.assignee.as_deref(), Some(SCHOLAR));
        assert_eq!(
            confirm_of(&db, "C2"),
            crate::events::ConfirmState::Confirmed
        );
    }

    /// And the move is recorded at the time the event itself was filed, not at
    /// the moment the receipt turned up: a receipt is not a second event.
    #[test]
    fn a_receipt_moves_the_view_at_the_time_the_event_was_filed() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "C1", "#ops", "peer-b", 10);
        relayed_follow_up(&db, "claim", SCHOLAR, "C1", "C2", "#ops", "peer-c", 11);
        relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-b", 99);

        assert_eq!(
            db.act_task("C1").unwrap().unwrap().updated,
            11,
            "the claim happened at 11; the receipt for it is not when it happened"
        );
    }

    /// Authority is the link. A receipt that arrives from anywhere but the
    /// server the task was opened on is one peer asserting an authority it
    /// does not have: kept, because a signed claim is evidence, and applied to
    /// nothing.
    #[test]
    fn a_receipt_from_a_peer_that_does_not_own_the_task_applies_nothing() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "C1", "#ops", "peer-b", 10);
        relayed_follow_up(&db, "claim", SCHOLAR, "C1", "C2", "#ops", "peer-c", 11);

        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-c", 12),
            ActWrite::ReceiptIgnored
        );
        assert_eq!(
            db.act_task("C1").unwrap().unwrap().state,
            "open",
            "a peer that does not own the task decides nothing about it"
        );
        assert_eq!(
            confirm_of(&db, "C2"),
            crate::events::ConfirmState::Unconfirmed,
            "and the claim is still waiting on the server that does"
        );
        assert!(
            db.is_act_event("R1").unwrap(),
            "the claim to authority is kept: it is evidence about the peer that made it"
        );
    }

    /// Nobody rules on a task of ours but us. A peer's receipt about one is
    /// the same overreach as a peer's receipt about a third server's task.
    #[test]
    fn a_receipt_from_a_peer_about_a_task_of_ours_applies_nothing() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);

        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "T1", "T1", "R1", "#ops", "peer-b", 11),
            ActWrite::ReceiptIgnored
        );
        assert_eq!(db.act_task("T1").unwrap().unwrap().state, "offered");
    }

    /// A receipt carries no state, so a home whose word the rules refuse gets
    /// the rules' answer. The receipt stays on file: two servers disagreeing
    /// about what a shared rules file says is exactly the thing worth keeping
    /// signed evidence of.
    #[test]
    fn a_receipt_the_rules_refuse_applies_nothing_and_is_kept() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "C1", "#ops", "peer-b", 10);
        // Completing work nobody has been assigned is not a legal step from
        // `open`, whoever says it won.
        relayed_follow_up(&db, "complete", MALLORY, "C1", "C2", "#ops", "peer-c", 11);

        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-b", 12),
            ActWrite::ReceiptRefused(freeq_sdk::act_transitions::Refusal::IllegalStep)
        );
        assert_eq!(
            db.act_task("C1").unwrap().unwrap().state,
            "open",
            "the rules decide what this view says, not the home"
        );
        assert!(
            db.is_act_event("R1").unwrap(),
            "and the disagreement is on file, signed"
        );
    }

    /// A receipt can outrun the event it names — on a mesh with uneven
    /// latency that is ordinary. Nothing is filed for it: it is held, and the
    /// caller offers it again when the subject lands.
    #[test]
    fn a_receipt_naming_an_event_we_do_not_hold_waits_for_it() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "C1", "#ops", "peer-b", 10);

        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-b", 12),
            ActWrite::ReceiptBeforeSubject
        );
        assert!(
            !db.is_act_event("R1").unwrap(),
            "a held receipt is not filed, so the one that arrives later is not a duplicate"
        );

        // The claim turns up, and now the receipt can be offered again.
        relayed_follow_up(&db, "claim", SCHOLAR, "C1", "C2", "#ops", "peer-c", 13);
        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C1", "C2", "R1", "#ops", "peer-b", 14),
            ActWrite::Confirmed {
                state: "assigned".into()
            }
        );
    }

    /// A receipt for a task whose opener we have never seen names a home we
    /// cannot check it against — and its subject cannot be on file either. It
    /// waits, rather than being judged against an origin nobody knows.
    #[test]
    fn a_receipt_about_a_task_we_have_never_seen_waits() {
        let db = Db::open_memory().unwrap();
        assert_eq!(
            relayed_receipt(&db, PEER_HOME, "C9", "C8", "R1", "#ops", "peer-b", 12),
            ActWrite::ReceiptBeforeSubject
        );
    }

    /// Two agents claim one open task on two different servers. The home rules
    /// for one; once that lands the rules no longer admit the other, so it
    /// leaves the pending set. The log row stays — the record is never lost.
    #[test]
    fn a_losing_claim_leaves_the_pending_set_when_the_winner_is_confirmed() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "W1", "#ops", "peer-b", 10);
        relayed_follow_up(&db, "claim", SCHOLAR, "W1", "W2", "#ops", "peer-c", 11);
        relayed_follow_up(&db, "claim", MALLORY, "W1", "W3", "#ops", "peer-d", 12);
        for id in ["W2", "W3"] {
            assert_eq!(
                confirm_of(&db, id),
                crate::events::ConfirmState::Unconfirmed
            );
        }

        relayed_receipt(&db, PEER_HOME, "W1", "W2", "R1", "#ops", "peer-b", 13);

        assert_eq!(
            confirm_of(&db, "W2"),
            crate::events::ConfirmState::Confirmed
        );
        assert_eq!(
            confirm_of(&db, "W3"),
            crate::events::ConfirmState::Superseded,
            "a claim on a task that is no longer open cannot still be pending"
        );
        assert_eq!(
            db.act_task_events("W1").unwrap().len(),
            4,
            "all three moves and the receipt are in the log — the loser's claim happened"
        );
        assert_eq!(
            db.act_task("W1").unwrap().unwrap().assignee.as_deref(),
            Some(SCHOLAR),
            "and exactly one of them won"
        );
    }

    /// An unconfirmed event that is still a legal move is not a loser. It has
    /// simply not been ruled on, and dropping it because something else landed
    /// first would discard a claim its home may still confirm.
    #[test]
    fn a_still_legal_unconfirmed_event_keeps_waiting() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "P1", "#ops", "peer-b", 10);
        // A claim and, behind it, the completion of the work it claims. Both
        // are filed unconfirmed, and the completion is illegal until the claim
        // is confirmed.
        relayed_follow_up(&db, "claim", SCHOLAR, "P1", "P2", "#ops", "peer-c", 11);
        relayed_follow_up(&db, "complete", SCHOLAR, "P1", "P3", "#ops", "peer-c", 12);

        relayed_receipt(&db, PEER_HOME, "P1", "P2", "R1", "#ops", "peer-b", 13);

        assert_eq!(
            confirm_of(&db, "P3"),
            crate::events::ConfirmState::Unconfirmed,
            "still a legal move from where the task now stands, so still pending"
        );
    }

    /// The home's own transition needs no receipt: it already carries the
    /// signature of the server whose word settles the task. That is how a
    /// peer's view is cleared when the home's sweep ends a task.
    #[test]
    fn the_homes_own_expiry_ends_the_task_here_too() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "H1", "#ops", "peer-b", 10);
        relayed_follow_up(&db, "claim", SCHOLAR, "H1", "H2", "#ops", "peer-c", 11);

        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "expire"),
                ("+freeq.at/from", PEER_HOME),
                ("+freeq.at/act-id", "H1"),
            ],
            "#ops",
            "H3",
        );
        let written = db
            .apply_act_event(&ActEvent {
                canonical: &canonical,
                signature: Some("ed25519:kid:sig"),
                event_id: "H3",
                act_id: "H1",
                opens: false,
                venue: "#ops",
                actor: PEER_HOME,
                from_system: true,
                origin: Some("peer-b"),
                timestamp: 12,
            })
            .unwrap();
        assert_eq!(
            written,
            ActWrite::Filed {
                was: Some("open".into()),
                state: "expired".into()
            }
        );
        assert!(
            db.act_task("H1").unwrap().is_none(),
            "an expired task leaves the view wherever it is held"
        );
        assert_eq!(
            confirm_of(&db, "H2"),
            crate::events::ConfirmState::Superseded,
            "and the claim that was waiting can never be confirmed now"
        );
    }

    /// A server is the system only where it may be speaking as one. A peer
    /// relaying an event signed under some `did:web:` name is not thereby the
    /// authority over a task of ours.
    #[test]
    fn a_peers_system_event_cannot_expire_a_task_of_ours() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T3", "#ops", None, 10);
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "expire"),
                ("+freeq.at/from", PEER_HOME),
                ("+freeq.at/act-id", "T3"),
            ],
            "#ops",
            "T4",
        );
        let written = db
            .apply_act_event(&ActEvent {
                canonical: &canonical,
                signature: Some("ed25519:kid:sig"),
                event_id: "T4",
                act_id: "T3",
                opens: false,
                venue: "#ops",
                actor: PEER_HOME,
                from_system: true,
                origin: Some("peer-b"),
                timestamp: 11,
            })
            .unwrap();
        assert_eq!(
            written,
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::WrongSender)
        );
        assert_eq!(
            db.act_task("T3").unwrap().expect("still live").state,
            "open"
        );
    }

    /// And it has to agree once a receipt has landed: a foreign task's
    /// transition applies in the rebuild exactly where the live path applied
    /// it, which is where a receipt from that task's home is on file for it.
    #[test]
    fn a_rebuild_matches_the_live_view_once_a_receipt_has_landed() {
        let db = Db::open_memory().unwrap();
        // Ours, moved by us.
        offer(&db, "M1", "#ops", None, 10);
        follow_up(&db, "claim", SCHOLAR, "M1", "M2", "#ops", 11);
        // A peer's, with a claim from a third server the home has confirmed.
        relayed_offer(&db, "M3", "#ops", "peer-b", 12);
        relayed_follow_up(&db, "claim", MALLORY, "M3", "M4", "#ops", "peer-c", 13);
        // A peer's, still carrying only unruled moves.
        relayed_offer(&db, "M5", "#ops", "peer-b", 14);
        relayed_follow_up(&db, "claim", MALLORY, "M5", "M6", "#ops", "peer-c", 15);

        relayed_receipt(&db, PEER_HOME, "M3", "M4", "R1", "#ops", "peer-b", 16);

        let mut live = db
            .act_tasks(&["#ops".to_string()], None, None, None, 100)
            .unwrap();
        let mut rebuilt = db.rebuild_act_actions().unwrap();
        live.sort_by(|a, b| a.act_id.cmp(&b.act_id));
        rebuilt.sort_by(|a, b| a.act_id.cmp(&b.act_id));
        assert_eq!(
            rebuilt, live,
            "the log is the record, and the view is what it derives to"
        );
        assert_eq!(
            rebuilt.iter().find(|t| t.act_id == "M5").unwrap().state,
            "open",
            "an unruled claim moves nothing, in the rebuild as in the view"
        );
    }

    /// What the defer queue threw away is a fact about what this server never
    /// received. Re-materializing a task — which a rebuild does for every one
    /// of them — must not quietly say the record is whole again.
    #[test]
    fn re_materializing_a_task_keeps_the_count_of_what_was_thrown_away() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        assert!(db.bump_act_dropped_unchecked("T1").unwrap());
        assert_eq!(db.act_dropped_unchecked("T1").unwrap(), 1);

        // The opener again, as a replay of the log hands it back.
        assert_eq!(
            offer(&db, "T1", "#ops", Some(SCHOLAR), 10),
            ActWrite::Duplicate
        );
        assert_eq!(db.act_dropped_unchecked("T1").unwrap(), 1);

        let venue = "#ops";
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-to", SCHOLAR),
            ],
            venue,
            "T1",
        );
        let view = crate::events::derive_act_view(&canonical).unwrap();
        db.materialize_act(
            &ActEvent {
                canonical: &canonical,
                signature: None,
                event_id: "T1",
                act_id: "T1",
                opens: true,
                venue,
                actor: ELIZA,
                from_system: false,
                origin: None,
                timestamp: 10,
            },
            &view,
            "handoff",
            None,
            "offered",
            None,
        )
        .unwrap();
        assert_eq!(
            db.act_dropped_unchecked("T1").unwrap(),
            1,
            "the count of what was lost survives the row being written again"
        );
    }

    // ── bounty: the second kind, and no code of its own ───────────────────

    fn bounty_offer(db: &Db, id: &str, venue: &str, ts: i64) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-title", "index the archive"),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// A bounty whose offer names how long it takes bids.
    fn bounty_offer_with_cutoff(db: &Db, id: &str, venue: &str, cutoff: i64, ts: i64) -> ActWrite {
        let cutoff = cutoff.to_string();
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-title", "index the archive"),
                ("+freeq.at/act-bid-deadline", &cutoff),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// A bounty step. `accepts` is the bid an award takes — the event the
    /// rules file points `assignee_from` at, whose author gets the work.
    fn bounty_step(
        db: &Db,
        verb: &str,
        actor: &str,
        task: &str,
        id: &str,
        accepts: Option<&str>,
        venue: &str,
        ts: i64,
    ) -> ActWrite {
        let mut tags = vec![
            ("+freeq.at/act", "bounty"),
            ("+freeq.at/act-verb", verb),
            ("+freeq.at/from", actor),
            ("+freeq.at/act-id", task),
        ];
        if let Some(accepts) = accepts {
            tags.push(("+freeq.at/act-accepts", accepts));
        }
        let canonical = act_doc(&tags, venue, id);
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: task,
            opens: false,
            venue,
            actor,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// The whole point of the second kind: bids pile up without moving
    /// anything, and the award assigns whoever wrote the bid it names rather
    /// than the one who sent it.
    #[test]
    fn a_bounty_award_assigns_the_author_of_the_bid_it_names() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        for (i, bidder) in [SCHOLAR, MALLORY].iter().enumerate() {
            assert_eq!(
                bounty_step(
                    &db,
                    "bid",
                    bidder,
                    "B1",
                    &format!("BID{i}"),
                    None,
                    "#ops",
                    11 + i as i64
                ),
                ActWrite::Filed {
                    was: Some("open".into()),
                    state: "open".into()
                },
                "a bid is additive: it leaves the bounty exactly where it was"
            );
        }
        assert_eq!(db.act_task_events("B1").unwrap().len(), 3, "all on file");

        // The second bid, so the answer cannot come from "the first one" or
        // from the sender.
        assert_eq!(
            bounty_step(&db, "award", ELIZA, "B1", "AW", Some("BID1"), "#ops", 20),
            ActWrite::Filed {
                was: Some("open".into()),
                state: "assigned".into()
            }
        );
        let task = db.act_task("B1").unwrap().unwrap();
        assert_eq!(
            task.assignee.as_deref(),
            Some(MALLORY),
            "whoever wrote the bid the poster took, not the poster who took it"
        );
        assert_eq!(task.offerer, ELIZA);
    }

    /// An award naming no bid takes nothing, so the transition is illegal
    /// without the field its row requires.
    #[test]
    fn an_award_that_names_no_bid_is_refused() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        assert_eq!(
            bounty_step(&db, "award", ELIZA, "B1", "AW", None, "#ops", 20),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::MissingRequirement(
                "act-accepts"
            ))
        );
        assert_eq!(db.act_task("B1").unwrap().unwrap().state, "open");
    }

    /// The loser bid and was not taken, so the work is not theirs to hand in.
    #[test]
    fn the_loser_of_a_bounty_cannot_finish_the_work() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_step(&db, "bid", SCHOLAR, "B1", "BID0", None, "#ops", 11);
        bounty_step(&db, "bid", MALLORY, "B1", "BID1", None, "#ops", 12);
        bounty_step(&db, "award", ELIZA, "B1", "AW", Some("BID0"), "#ops", 20);

        assert_eq!(
            bounty_step(&db, "submit", MALLORY, "B1", "C1", None, "#ops", 21),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::WrongSender)
        );
        assert_eq!(
            bounty_step(&db, "bid", MALLORY, "B1", "BID2", None, "#ops", 22),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::IllegalStep),
            "an awarded bounty takes no further bids"
        );
        assert!(matches!(
            bounty_step(&db, "submit", SCHOLAR, "B1", "C2", None, "#ops", 23),
            ActWrite::Filed { .. }
        ));
        assert!(matches!(
            bounty_step(&db, "accept-work", ELIZA, "B1", "C3", None, "#ops", 24),
            ActWrite::Filed { .. }
        ));
        assert_eq!(db.act_task("B1").unwrap(), None, "accepted and gone");
    }

    /// The difference between this kind and a handoff: the worker says the
    /// work is in, and the poster says whether it is done. A submission
    /// parks the bounty in review and moves nothing else.
    #[test]
    fn a_bounty_ends_on_the_posters_word_and_not_the_workers() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_step(&db, "bid", SCHOLAR, "B1", "BID0", None, "#ops", 11);
        bounty_step(&db, "award", ELIZA, "B1", "AW", Some("BID0"), "#ops", 12);

        assert_eq!(
            bounty_step(&db, "submit", SCHOLAR, "B1", "S1", None, "#ops", 13),
            ActWrite::Filed {
                was: Some("assigned".into()),
                state: "under_review".into()
            }
        );
        assert_eq!(
            bounty_step(&db, "accept-work", SCHOLAR, "B1", "A1", None, "#ops", 14),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::WrongSender),
            "the worker cannot sign off on their own work"
        );
        // Sent back, worked again, handed in again.
        assert_eq!(
            bounty_step(&db, "revise", ELIZA, "B1", "R1", None, "#ops", 15),
            ActWrite::Filed {
                was: Some("under_review".into()),
                state: "assigned".into()
            }
        );
        assert!(matches!(
            bounty_step(&db, "submit", SCHOLAR, "B1", "S2", None, "#ops", 16),
            ActWrite::Filed { .. }
        ));
        assert_eq!(
            bounty_step(&db, "accept-work", ELIZA, "B1", "A2", None, "#ops", 17),
            ActWrite::Filed {
                was: Some("under_review".into()),
                state: "accepted".into()
            }
        );
        assert_eq!(
            db.act_task("B1").unwrap(),
            None,
            "accepted is the end of it"
        );
    }

    /// Once work is in, the poster's only moves are taking it and sending it
    /// back. Cancelling delivered work is the cheap unfairness the table
    /// closes: the row simply does not reach under_review.
    #[test]
    fn delivered_work_is_not_something_the_poster_can_cancel() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_step(&db, "bid", SCHOLAR, "B1", "BID0", None, "#ops", 11);
        bounty_step(&db, "award", ELIZA, "B1", "AW", Some("BID0"), "#ops", 12);
        // Before it lands, cancelling is the poster's to do.
        assert!(matches!(
            bounty_step(&db, "cancel", ELIZA, "B1", "X0", None, "#ops", 13),
            ActWrite::Filed { .. }
        ));

        bounty_offer(&db, "B2", "#ops", 20);
        bounty_step(&db, "bid", SCHOLAR, "B2", "BID1", None, "#ops", 21);
        bounty_step(&db, "award", ELIZA, "B2", "AW2", Some("BID1"), "#ops", 22);
        bounty_step(&db, "submit", SCHOLAR, "B2", "S1", None, "#ops", 23);
        assert_eq!(
            bounty_step(&db, "cancel", ELIZA, "B2", "X1", None, "#ops", 24),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::IllegalStep)
        );
        assert_eq!(db.act_task("B2").unwrap().unwrap().state, "under_review");
    }

    /// The worker's exit, from either state they may hold the work in. It is
    /// terminal, so re-running the job is a new bounty naming this one.
    #[test]
    fn the_worker_forfeits_work_they_hold_before_or_after_handing_it_in() {
        let db = Db::open_memory().unwrap();
        for (task, submit_first) in [("B1", false), ("B2", true)] {
            bounty_offer(&db, task, "#ops", 10);
            bounty_step(
                &db,
                "bid",
                SCHOLAR,
                task,
                &format!("{task}BID"),
                None,
                "#ops",
                11,
            );
            bounty_step(
                &db,
                "award",
                ELIZA,
                task,
                &format!("{task}AW"),
                Some(&format!("{task}BID")),
                "#ops",
                12,
            );
            if submit_first {
                bounty_step(
                    &db,
                    "submit",
                    SCHOLAR,
                    task,
                    &format!("{task}S"),
                    None,
                    "#ops",
                    13,
                );
            }
            assert_eq!(
                bounty_step(
                    &db,
                    "forfeit",
                    ELIZA,
                    task,
                    &format!("{task}FE"),
                    None,
                    "#ops",
                    14
                ),
                ActWrite::Refused(freeq_sdk::act_transitions::Refusal::WrongSender),
                "{task}: the poster does not forfeit the worker's work"
            );
            assert_eq!(
                bounty_step(
                    &db,
                    "forfeit",
                    SCHOLAR,
                    task,
                    &format!("{task}F"),
                    None,
                    "#ops",
                    15
                ),
                ActWrite::Filed {
                    was: Some(match submit_first {
                        true => "under_review".to_string(),
                        false => "assigned".to_string(),
                    }),
                    state: "forfeited".into()
                },
                "{task}"
            );
            assert_eq!(db.act_task(task).unwrap(), None, "{task}: terminal");
        }
    }

    /// A bounty takes bids until its own cutoff, which is read back out of
    /// the opener's bytes like every other tag the view has no column for.
    #[test]
    fn a_bounty_stops_taking_bids_at_the_cutoff_its_offer_named() {
        let db = Db::open_memory().unwrap();
        // 1788000000 unix seconds, as the fixtures use it, and the two ids
        // that sit either side of the tolerance around it.
        const TOO_LATE: &str = "01M16HSC58ACCEPTTOOLATE000";
        const AT_EDGE: &str = "01M16HSB60ACCEPTATEDGE0000";
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-title", "index the archive"),
                ("+freeq.at/act-bid-deadline", "1788000000"),
            ],
            "#ops",
            "B1",
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: "B1",
            act_id: "B1",
            opens: true,
            venue: "#ops",
            actor: ELIZA,
            from_system: false,
            origin: None,
            timestamp: 10,
        })
        .unwrap();
        assert_eq!(db.act_task_bid_deadline("B1").unwrap(), Some(1_788_000_000));

        assert_eq!(
            bounty_step(&db, "bid", SCHOLAR, "B1", TOO_LATE, None, "#ops", 11),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::DeadlinePassed)
        );
        assert!(matches!(
            bounty_step(&db, "bid", SCHOLAR, "B1", AT_EDGE, None, "#ops", 12),
            ActWrite::Filed { .. }
        ));
        // Bidding closing does not stop the poster picking: the award is
        // bound by act-deadline, which this offer never named.
        assert!(matches!(
            bounty_step(
                &db,
                "award",
                ELIZA,
                "B1",
                TOO_LATE,
                Some(AT_EDGE),
                "#ops",
                13
            ),
            ActWrite::Filed { .. }
        ));
        assert_eq!(
            db.act_task("B1").unwrap().unwrap().assignee.as_deref(),
            Some(SCHOLAR)
        );
    }

    /// A bounty whose offer named no cutoff takes bids for as long as it
    /// stands.
    #[test]
    fn a_bounty_with_no_cutoff_takes_bids_whenever_they_arrive() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        assert_eq!(db.act_task_bid_deadline("B1").unwrap(), None);
        assert!(matches!(
            bounty_step(
                &db,
                "bid",
                SCHOLAR,
                "B1",
                "01M16HSC58ACCEPTTOOLATE000",
                None,
                "#ops",
                11
            ),
            ActWrite::Filed { .. }
        ));
    }

    /// An award points at one event, and only a bid on this action answers.
    /// The bounty's own opener is not one, whatever else it is.
    #[test]
    fn an_award_naming_the_bounty_itself_is_refused() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_step(&db, "bid", SCHOLAR, "B1", "BID0", None, "#ops", 11);
        assert_eq!(
            bounty_step(&db, "award", ELIZA, "B1", "AW", Some("B1"), "#ops", 20),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::AcceptsNotABid)
        );
        assert_eq!(db.act_task("B1").unwrap().unwrap().state, "open");
    }

    /// A bid is a bid on one bounty. Naming another bounty's — or one nobody
    /// ever filed — takes nothing here.
    #[test]
    fn an_award_naming_a_bid_on_another_bounty_is_refused() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_offer(&db, "B2", "#ops", 11);
        bounty_step(&db, "bid", SCHOLAR, "B2", "ELSEWHERE", None, "#ops", 12);
        for named in ["ELSEWHERE", "NEVERFILED"] {
            assert_eq!(
                bounty_step(&db, "award", ELIZA, "B1", "AW", Some(named), "#ops", 20),
                ActWrite::Refused(freeq_sdk::act_transitions::Refusal::AcceptsNotABid),
                "{named}"
            );
        }
        assert_eq!(db.act_task("B1").unwrap().unwrap().state, "open");
    }

    /// The server still never picks: it checks that the named event is a bid
    /// on this action and nothing further. A bid nobody would have taken is
    /// still one the poster may take.
    #[test]
    fn the_poster_takes_whichever_bid_they_name() {
        let db = Db::open_memory().unwrap();
        bounty_offer(&db, "B1", "#ops", 10);
        bounty_step(&db, "bid", SCHOLAR, "B1", "BID0", None, "#ops", 11);
        bounty_step(&db, "bid", MALLORY, "B1", "BID1", None, "#ops", 12);
        assert!(matches!(
            bounty_step(&db, "award", ELIZA, "B1", "AW", Some("BID1"), "#ops", 20),
            ActWrite::Filed { .. }
        ));
        assert_eq!(
            db.act_task("B1").unwrap().unwrap().assignee.as_deref(),
            Some(MALLORY)
        );
    }

    // ── the revival relation ──────────────────────────────────────────────

    /// An opener that names a finished action it revives.
    fn re_offer(db: &Db, id: &str, venue: &str, replaces: &str, ts: i64) -> ActWrite {
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-replaces", replaces),
            ],
            venue,
            id,
        );
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: None,
            timestamp: ts,
        })
        .unwrap()
    }

    /// A dead handoff, re-offered. The link is on the new action; the old one
    /// is untouched, because nothing un-applies.
    #[test]
    fn a_re_offer_carries_the_link_to_the_action_it_revives() {
        let db = Db::open_memory().unwrap();
        offer(&db, ONE, "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, ONE, "E1", "#ops", 11);
        follow_up(&db, "fail", SCHOLAR, ONE, "E2", "#ops", 12);
        assert_eq!(db.act_task(ONE).unwrap(), None, "the first one is finished");

        assert!(matches!(
            re_offer(&db, TWO, "#ops", ONE, 20),
            ActWrite::Filed { .. }
        ));
        let revived = db.act_task(TWO).unwrap().unwrap();
        assert_eq!(revived.replaces.as_deref(), Some(ONE));
        assert_eq!(
            db.act_task_events(ONE).unwrap().len(),
            3,
            "and the action it replaces keeps exactly the history it had"
        );
    }

    /// Reviving something still running would leave two live actions each
    /// claiming to be the work.
    #[test]
    fn an_action_still_running_is_not_something_to_revive() {
        let db = Db::open_memory().unwrap();
        offer(&db, ONE, "#ops", Some(SCHOLAR), 10);
        assert_eq!(
            re_offer(&db, TWO, "#ops", ONE, 20),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::ReplacesNotTerminal)
        );
        assert_eq!(db.act_task(TWO).unwrap(), None, "and nothing was filed");
    }

    /// The rule that is load-bearing for federation: a link to an action this
    /// server never filed is annotation, not a claim to check.
    #[test]
    fn a_link_to_an_action_this_server_never_saw_is_annotated_not_refused() {
        let db = Db::open_memory().unwrap();
        assert!(matches!(
            re_offer(&db, ONE, "#ops", NEVER_SEEN, 10),
            ActWrite::Filed { .. }
        ));
        assert_eq!(
            db.act_task(ONE).unwrap().unwrap().replaces.as_deref(),
            Some(NEVER_SEEN)
        );
    }

    #[test]
    fn a_step_on_an_action_revives_nothing() {
        let db = Db::open_memory().unwrap();
        offer(&db, ONE, "#ops", Some(SCHOLAR), 10);
        offer(&db, TWO, "#ops", None, 11);
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "accept"),
                ("+freeq.at/from", SCHOLAR),
                ("+freeq.at/act-id", ONE),
                ("+freeq.at/act-replaces", TWO),
            ],
            "#ops",
            "E1",
        );
        let written = db
            .apply_act_event(&ActEvent {
                canonical: &canonical,
                signature: Some("ed25519:kid:sig"),
                event_id: "E1",
                act_id: ONE,
                opens: false,
                venue: "#ops",
                actor: SCHOLAR,
                from_system: false,
                origin: None,
                timestamp: 12,
            })
            .unwrap();
        assert_eq!(
            written,
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::ReplacesNotOpener)
        );
        assert_eq!(db.act_task(ONE).unwrap().unwrap().state, "offered");
    }

    #[test]
    fn a_value_that_is_not_an_action_id_names_no_action() {
        let db = Db::open_memory().unwrap();
        assert_eq!(
            re_offer(&db, ONE, "#ops", "not-a-ulid", 10),
            ActWrite::Refused(freeq_sdk::act_transitions::Refusal::ReplacesMalformed)
        );
    }

    /// The whole point of deriving the view: replaying the log reproduces it.
    /// A mismatch means something wrote the view without going through the
    /// log, and the log would have stopped being the record.
    #[test]
    fn the_view_rebuilt_from_the_log_equals_the_live_view() {
        const BID_ONE: &str = "01M16HSB601BD0000000000000";
        const BID_TWO: &str = "01M16HSB602BD1000000000000";
        const AWARD: &str = "01M16HSB603AWARD0000000000";
        const PROGRESS: &str = "01M16HSB604PRGRESS00000000";
        const SUBMIT: &str = "01M16HSB605SBMT0000000000A";
        const REVISE: &str = "01M16HSB606REVSE0000000000";
        const SUBMIT_AGAIN: &str = "01M16HSB607SBMT0000000000B";

        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        receipt(&db, "T1", "E1", "R1", "#ops", true, 11);
        follow_up(&db, "progress", SCHOLAR, "T1", "E2", "#ops", 12);

        offer(&db, "T2", "#ops", None, 20);
        follow_up(&db, "claim", MALLORY, "T2", "E3", "#ops", 21);

        offer(&db, ONE, "#other", Some(SCHOLAR), 30);
        follow_up(&db, "decline", SCHOLAR, ONE, "E4", "#other", 31);
        // A receipt for the event that ended a task — the rebuild has to pass
        // over it exactly as ingress did, or the replay would try to apply a
        // verb no kind has.
        receipt(&db, ONE, "E4", "R2", "#other", true, 31);
        // …and the declined one re-offered, so the rebuild has to reproduce
        // the link as well as the row.
        re_offer(&db, "T5", "#other", ONE, 32);

        offer(&db, "T4", "#ops", None, 40);

        // A bounty too: its award assigns the author of the bid it names
        // rather than the sender, and that is a fact the rebuild has to look
        // up in the log exactly as ingress did. A rebuild that read the
        // sender, or the first bid, would disagree with the live row on
        // exactly that column — so there are two bids and the second is taken.
        bounty_offer(&db, "B1", "#ops", 50);
        // …and one whose offer named a bid cutoff, which the rebuild has to
        // read back out of the opener exactly as ingress did.
        bounty_offer_with_cutoff(&db, "B3", "#ops", 1_788_000_000, 50);
        bounty_step(
            &db,
            "bid",
            SCHOLAR,
            "B3",
            "01M16HSB60ACCEPTATEDGE0000",
            None,
            "#ops",
            51,
        );
        // The ids are mint-ordered, because that is the order a rebuild
        // replays in: an award names a bid, and a bid it has not reached yet
        // is a bid it cannot resolve.
        bounty_step(&db, "bid", SCHOLAR, "B1", BID_ONE, None, "#ops", 51);
        bounty_step(&db, "bid", MALLORY, "B1", BID_TWO, None, "#ops", 52);
        bounty_step(&db, "award", ELIZA, "B1", AWARD, Some(BID_TWO), "#ops", 53);
        bounty_step(&db, "progress", MALLORY, "B1", PROGRESS, None, "#ops", 54);
        // …and into review and back out again, so the rebuild replays the
        // states only a bounty has.
        bounty_step(&db, "submit", MALLORY, "B1", SUBMIT, None, "#ops", 55);
        bounty_step(&db, "revise", ELIZA, "B1", REVISE, None, "#ops", 56);
        bounty_step(&db, "submit", MALLORY, "B1", SUBMIT_AGAIN, None, "#ops", 57);

        let venues = vec!["#ops".to_string(), "#other".to_string()];
        let mut live = db.act_tasks(&venues, None, None, None, 100).unwrap();
        live.sort_by(|a, b| a.act_id.cmp(&b.act_id));
        let mut rebuilt = db.rebuild_act_actions().unwrap();
        rebuilt.sort_by(|a, b| a.act_id.cmp(&b.act_id));

        assert_eq!(
            live.len(),
            6,
            "the declined one left the view; its revival and the bounties did not"
        );
        assert_eq!(rebuilt, live);
    }

    /// A rebuild replays in **mint** order, which is the event id's order.
    ///
    /// The row timestamp is when *this* server took delivery, and it differs
    /// on every server that took the same events — ordering by it makes the
    /// rebuilt view a function of who was up when. A signed event id is a
    /// ULID, so its byte order is the order its signer minted in, and every
    /// server reads the same order out of it.
    ///
    /// Here delivery order and id order disagree. Replayed by timestamp, the
    /// completion arrives before the acceptance that makes it legal, gets
    /// dropped, and the task survives in the view; replayed by id, the task
    /// completes and leaves — which is what the live view shows.
    #[test]
    fn a_rebuild_replays_in_mint_order_and_not_delivery_order() {
        let db = Db::open_memory().unwrap();
        // The opener's id deliberately sorts *after* both follow-ups: a task's
        // opener has to be applied first whatever its id, and nothing about
        // sorting by id guarantees that on its own.
        const OPENER: &str = "01ZOPENER00000000000000000";
        offer(&db, OPENER, "#ops", Some(SCHOLAR), 100);
        assert_eq!(
            follow_up(&db, "accept", SCHOLAR, OPENER, "01ACCEPT", "#ops", 300),
            ActWrite::Filed {
                was: Some("offered".into()),
                state: "assigned".into()
            }
        );
        assert_eq!(
            follow_up(&db, "complete", SCHOLAR, OPENER, "01COMPLETE", "#ops", 200),
            ActWrite::Filed {
                was: Some("assigned".into()),
                state: "completed".into()
            }
        );

        let live = db
            .act_tasks(&["#ops".to_string()], None, None, None, 100)
            .unwrap();
        assert!(live.is_empty(), "the task completed and left the live view");
        assert_eq!(
            db.rebuild_act_actions().unwrap(),
            live,
            "the rebuilt view must agree — by id the completion lands, by \
             delivery time it arrives too early and is dropped"
        );
    }

    /// A signed event the rules refuse does not enter a rebuilt view.
    ///
    /// The log is not a list of legal moves. A transition on a task another
    /// server owns is filed here without being ruled on — that server referees
    /// it — so the log genuinely holds events this server never checked. A
    /// rebuild that assumed otherwise would let one of them in.
    #[test]
    fn a_peers_illegal_event_does_not_enter_the_rebuilt_view() {
        let db = Db::open_memory().unwrap();
        relayed_offer(&db, "R1", "#ops", "peer-b", 10);
        relayed_follow_up(&db, "claim", SCHOLAR, "R1", "R2", "#ops", "peer-b", 11);

        // Filed unruled, both of them: completion by someone who is not the
        // assignee, and expiry by someone who is not a server.
        assert_eq!(
            relayed_follow_up(&db, "complete", MALLORY, "R1", "R3", "#ops", "peer-b", 12),
            ActWrite::StoredNotApplied
        );
        assert_eq!(
            relayed_follow_up(&db, "expire", MALLORY, "R1", "R4", "#ops", "peer-b", 13),
            ActWrite::StoredNotApplied
        );
        assert_eq!(
            db.act_task_events("R1").unwrap().len(),
            4,
            "all four are in the log, which is what makes this the hard case"
        );

        let rebuilt = db.rebuild_act_actions().unwrap();
        let task = rebuilt
            .iter()
            .find(|t| t.act_id == "R1")
            .expect("the task is still live: neither refused event moved it");
        assert_ne!(
            task.state, "completed",
            "a completion by someone who is not the assignee is not a completion"
        );
        assert_ne!(
            task.state, "expired",
            "and only a server may expire — an actor that is not one never counts \
             as the system"
        );
    }

    /// A server's own expiry still rebuilds, because a server *is* the system.
    ///
    /// The counterpart to the test above: deriving `is_system` from the actor
    /// has to keep saying yes to the one sender the rule was written for.
    #[test]
    fn a_servers_own_expiry_rebuilds_as_the_system_event_it_is() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "T2", "#ops", 11);
        // Filed the way the expiry sweep files its own: signed by the server,
        // under the server's identity.
        let server = crate::server::server_did("irc.example");
        let canonical = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "expire"),
                ("+freeq.at/from", server.as_str()),
                ("+freeq.at/act-id", "T1"),
            ],
            "#ops",
            "T3",
        );
        assert_eq!(
            db.apply_act_event(&ActEvent {
                canonical: &canonical,
                signature: Some("ed25519:kid:sig"),
                event_id: "T3",
                act_id: "T1",
                opens: false,
                venue: "#ops",
                actor: &server,
                from_system: true,
                origin: None,
                timestamp: 12,
            })
            .unwrap(),
            ActWrite::Filed {
                was: Some("assigned".into()),
                state: "expired".into()
            },
            "the sweep's own event is a system event"
        );

        assert!(
            db.rebuild_act_actions()
                .unwrap()
                .iter()
                .all(|t| t.act_id != "T1"),
            "an expired task is gone from the rebuilt view too"
        );
    }

    #[test]
    fn the_listing_filters_by_kind_assignee_and_state() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        follow_up(&db, "accept", SCHOLAR, "T1", "E1", "#ops", 11);
        offer(&db, "T2", "#ops", None, 20);

        let venues = vec!["#ops".to_string()];
        let all = db.act_tasks(&venues, None, None, None, 100).unwrap();
        assert_eq!(all.len(), 2);

        let assigned = db
            .act_tasks(&venues, None, None, Some("assigned"), 100)
            .unwrap();
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].act_id, "T1");

        let scholars = db
            .act_tasks(&venues, None, Some(SCHOLAR), None, 100)
            .unwrap();
        assert_eq!(scholars.len(), 1);

        let handoffs = db
            .act_tasks(&venues, Some("handoff"), None, None, 100)
            .unwrap();
        assert_eq!(handoffs.len(), 2);
        let bounties = db
            .act_tasks(&venues, Some("bounty"), None, None, 100)
            .unwrap();
        assert!(bounties.is_empty());
    }

    /// A venue the reader may not see contributes nothing, which is what the
    /// endpoints lean on to keep DM tasks private.
    #[test]
    fn the_listing_answers_only_for_the_venues_it_was_given() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T1", "#ops", Some(SCHOLAR), 10);
        offer(&db, "T2", "dm:did:plc:a,did:plc:b", Some(SCHOLAR), 20);

        let public = db
            .act_tasks(&["#ops".to_string()], None, None, None, 100)
            .unwrap();
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].act_id, "T1");
        assert!(db.act_tasks(&[], None, None, None, 100).unwrap().is_empty());
    }

    // ── The sweeps' candidates ────────────────────────────────────────────

    /// An opener filed from a peer's relay. Every other opener in these tests
    /// leaves `origin` empty, the way a task created here carries it; this one
    /// names the server the task belongs to.
    fn remote_offer(
        db: &Db,
        tags: &[(&str, &str)],
        id: &str,
        venue: &str,
        home: &str,
        ts: i64,
    ) -> ActWrite {
        let canonical = act_doc(tags, venue, id);
        db.apply_act_event(&ActEvent {
            canonical: &canonical,
            signature: Some("ed25519:kid:sig"),
            event_id: id,
            act_id: id,
            opens: true,
            venue,
            actor: ELIZA,
            from_system: false,
            origin: Some(home),
            timestamp: ts,
        })
        .unwrap()
    }

    /// Expiry belongs to the server that created a task: the sweep must not
    /// offer up a task another server's event opened, however idle it is.
    #[test]
    fn the_idle_sweep_names_only_tasks_created_here() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T-local", "#ops", Some(SCHOLAR), 10);
        remote_offer(
            &db,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-to", SCHOLAR),
            ],
            "T-remote",
            "#ops",
            "peer.example",
            10,
        );

        let states = freeq_sdk::act_transitions::review_timeout_states();
        let idle = db.act_tasks_idle_outside_states(&states, 100, 10).unwrap();
        let ids: Vec<&str> = idle.iter().map(|t| t.act_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["T-local"],
            "only the task created here is a sweep candidate"
        );
    }

    /// The other clock, the same rule: the auto-accept a closed review window
    /// files is the home server's own signed event, so a bounty another
    /// server opened is not this one's to accept, however long its poster has
    /// been silent.
    #[test]
    fn the_review_sweep_leaves_another_servers_bounty_under_review() {
        let db = Db::open_memory().unwrap();

        // Two bounties handed in and never answered: one opened here, one
        // opened on the server it names.
        bounty_offer(&db, "B-local", "#ops", 10);
        remote_offer(
            &db,
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ELIZA),
                ("+freeq.at/act-title", "index the archive"),
            ],
            "B-remote",
            "#ops",
            "peer.example",
            10,
        );
        bounty_step(
            &db,
            "bid",
            SCHOLAR,
            "B-local",
            "B-local-BID",
            None,
            "#ops",
            11,
        );
        bounty_step(
            &db,
            "award",
            ELIZA,
            "B-local",
            "B-local-AW",
            Some("B-local-BID"),
            "#ops",
            12,
        );
        bounty_step(
            &db,
            "submit",
            SCHOLAR,
            "B-local",
            "B-local-S",
            None,
            "#ops",
            13,
        );
        // The peer's bounty is under review because its own home put it
        // there. It cannot be driven there from here: a move that changes
        // where another server's task stands is filed and not applied, so the
        // row is set to what that server says it is.
        db.conn
            .execute(
                "UPDATE act_actions SET state = 'under_review', assignee = ?2, updated = 13 \
                 WHERE act_id = ?1",
                params!["B-remote", SCHOLAR],
            )
            .unwrap();

        let states = freeq_sdk::act_transitions::review_timeout_states();
        let waiting = db.act_tasks_idle_in_states(&states, 100, 10).unwrap();
        let ids: Vec<&str> = waiting.iter().map(|t| t.act_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["B-local"],
            "only the bounty opened here is up for auto-accept"
        );

        // The sweep accepts what that query hands it and nothing else, so the
        // peer's bounty is still on file, still waiting on its own home.
        assert_eq!(
            db.act_task("B-remote").unwrap().unwrap().state,
            "under_review"
        );
    }

    /// The dropped-unchecked count is a receipt on the task's row: it bumps
    /// only where a row exists, and a task moving does not erase it.
    #[test]
    fn the_dropped_unchecked_count_sticks_to_its_task() {
        let db = Db::open_memory().unwrap();
        offer(&db, "T-drop", "#ops", Some(SCHOLAR), 10);

        assert!(db.bump_act_dropped_unchecked("T-drop").unwrap());
        assert!(
            !db.bump_act_dropped_unchecked("T-nowhere").unwrap(),
            "no row, nothing to mark"
        );
        assert_eq!(db.act_dropped_unchecked("T-drop").unwrap(), 1);
        assert_eq!(db.act_dropped_unchecked("T-nowhere").unwrap(), 0);

        // The task moves on — an accept by its offeree — and the count stays.
        let accept = act_doc(
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "accept"),
                ("+freeq.at/from", SCHOLAR),
                ("+freeq.at/act-id", "T-drop"),
            ],
            "#ops",
            "T-drop-accept",
        );
        db.apply_act_event(&ActEvent {
            canonical: &accept,
            signature: Some("ed25519:kid:sig"),
            event_id: "T-drop-accept",
            act_id: "T-drop",
            opens: false,
            venue: "#ops",
            actor: SCHOLAR,
            from_system: false,
            origin: None,
            timestamp: 20,
        })
        .unwrap();
        assert_eq!(
            db.act_task("T-drop").unwrap().unwrap().state,
            "assigned",
            "the follow-up applied"
        );
        assert_eq!(
            db.act_dropped_unchecked("T-drop").unwrap(),
            1,
            "and the count survived it"
        );
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
        db.insert_message(
            "#c",
            "a!a@h",
            "original",
            100,
            &HashMap::new(),
            Some("DUPID"),
            None,
        )
        .unwrap();
        // Same msgid arriving again (an S2S re-delivery, or a raced client
        // mint slipping past the pre-insert lookup): first write wins, the
        // second is a no-op, not an error and not a second row.
        db.insert_message(
            "#c",
            "a!a@h",
            "impostor",
            200,
            &HashMap::new(),
            Some("DUPID"),
            None,
        )
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
        db.insert_message(
            "#c",
            "a!a@h",
            "kept words",
            100,
            &HashMap::new(),
            Some("DUPFTS"),
            None,
        )
        .unwrap();
        db.insert_message(
            "#c",
            "a!a@h",
            "phantom words",
            200,
            &HashMap::new(),
            Some("DUPFTS"),
            None,
        )
        .unwrap();
        assert!(
            db.search_messages("#c", "phantom", 10, None)
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.search_messages("#c", "kept", 10, None).unwrap().len(), 1);
    }

    #[test]
    fn edit_claiming_spent_msgid_is_ignored() {
        let db = Db::open_memory().unwrap();
        db.insert_message(
            "#c",
            "a!a@h",
            "one",
            100,
            &HashMap::new(),
            Some("SPENT"),
            None,
        )
        .unwrap();
        db.insert_message(
            "#c",
            "a!a@h",
            "two",
            150,
            &HashMap::new(),
            Some("ORIG"),
            None,
        )
        .unwrap();
        // A revision row may not take over an id already on file.
        db.insert_edit(
            "#c",
            "a!a@h",
            "two edited",
            200,
            &HashMap::new(),
            "SPENT",
            "ORIG",
            None,
        )
        .unwrap();
        let n: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE msgid = 'SPENT'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let text: String = db
            .conn
            .query_row("SELECT text FROM messages WHERE msgid = 'SPENT'", [], |r| {
                r.get(0)
            })
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
            .query_row("SELECT id FROM messages WHERE msgid = 'm1'", [], |r| {
                r.get(0)
            })
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
                crate::migrations::ladder_top() as i64,
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
            crate::migrations::ladder_top() as i64
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
            crate::migrations::ladder_top() as i64
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
            crate::migrations::ladder_top() as i64
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

    // ── msgid-anchored history paging ────────────────────────────────────

    /// `n` messages in one channel all stamped the same second — the case a
    /// timestamp anchor cannot page through.
    fn same_second_burst(db: &Db, channel: &str, n: usize, ts: u64) -> Vec<String> {
        (0..n)
            .map(|i| {
                let id = format!("01BURST{:019}", i);
                msg(db, channel, &format!("burst {i}"), ts, &id);
                id
            })
            .collect()
    }

    #[test]
    fn msgid_cursor_pages_a_same_second_burst_completely_and_once() {
        let db = Db::open_memory().unwrap();
        let ids = same_second_burst(&db, "#burst", 25, 1_700_000_000);

        // Walk back from the newest row, five at a time, anchoring each page
        // on the oldest row of the one before it.
        let mut anchor = ids.last().unwrap().clone();
        let mut seen: Vec<String> = vec![anchor.clone()];
        loop {
            let (ts, id) = db.history_cursor("#burst", &anchor).unwrap().unwrap();
            let page = db.get_messages_before_cursor("#burst", ts, &id, 5).unwrap();
            if page.is_empty() {
                break;
            }
            // Walking backwards, so each page is stacked newest-row-first and
            // the whole list is flipped at the end.
            for row in page.iter().rev() {
                seen.push(row.msgid.clone().unwrap());
            }
            anchor = page[0].msgid.clone().unwrap();
        }

        seen.reverse();
        assert_eq!(seen, ids, "every row exactly once, in stored order");
    }

    #[test]
    fn msgid_cursor_walks_forward_through_a_same_second_burst() {
        let db = Db::open_memory().unwrap();
        let ids = same_second_burst(&db, "#fwd", 12, 1_700_000_100);

        let mut anchor = ids.first().unwrap().clone();
        let mut seen: Vec<String> = vec![anchor.clone()];
        loop {
            let (ts, id) = db.history_cursor("#fwd", &anchor).unwrap().unwrap();
            let page = db.get_messages_after_cursor("#fwd", ts, &id, 5).unwrap();
            if page.is_empty() {
                break;
            }
            for row in &page {
                seen.push(row.msgid.clone().unwrap());
            }
            anchor = page.last().unwrap().msgid.clone().unwrap();
        }

        assert_eq!(seen, ids);
    }

    #[test]
    fn msgid_cursor_crosses_a_second_boundary() {
        let db = Db::open_memory().unwrap();
        msg(
            &db,
            "#mix",
            "older",
            1_700_000_200,
            "01MIX0000000000000000000001",
        );
        msg(
            &db,
            "#mix",
            "same a",
            1_700_000_201,
            "01MIX0000000000000000000002",
        );
        msg(
            &db,
            "#mix",
            "same b",
            1_700_000_201,
            "01MIX0000000000000000000003",
        );

        let (ts, id) = db
            .history_cursor("#mix", "01MIX0000000000000000000003")
            .unwrap()
            .unwrap();
        let page = db.get_messages_before_cursor("#mix", ts, &id, 10).unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["older", "same a"]);
    }

    /// Insert one row with a chosen msgid at a chosen second, so a test can
    /// make insert order and msgid order disagree the way concurrent senders
    /// do.
    fn msg_at(db: &Db, channel: &str, msgid: &str, ts: u64) {
        msg(db, channel, &format!("text for {msgid}"), ts, msgid);
    }

    /// Walk a channel backwards the way a client does: anchor on the OLDEST
    /// row it holds in ITS order — `(timestamp, msgid)` — ask for the page
    /// before that, merge, and re-anchor. Returns the ids it ends up holding,
    /// oldest first, and stops if the anchor ever fails to move.
    fn walk_like_a_client(db: &Db, channel: &str, limit: usize) -> Vec<String> {
        let mut held: Vec<(u64, String)> = db
            .get_messages(channel, limit, None)
            .unwrap()
            .into_iter()
            .map(|r| (r.timestamp, r.msgid.unwrap()))
            .collect();
        held.sort();
        for _ in 0..50 {
            let (ts, anchor) = held
                .first()
                .cloned()
                .expect("the opening page is not empty");
            let (cts, cid) = match db.history_cursor(channel, &anchor).unwrap() {
                Some(c) => c,
                None => break,
            };
            let page = db
                .get_messages_before_cursor(channel, cts, &cid, limit)
                .unwrap();
            if page.is_empty() {
                break;
            }
            for row in page {
                let key = (row.timestamp, row.msgid.unwrap());
                if !held.contains(&key) {
                    held.push(key);
                }
            }
            held.sort();
            // The client re-anchors on its own oldest row. If the page did not
            // move it, asking again sends the identical request — the walk is
            // jammed and the reader cannot get past this boundary.
            if held.first().map(|(t, m)| (*t, m.clone())) == Some((ts, anchor)) {
                break;
            }
        }
        held.into_iter().map(|(_, m)| m).collect()
    }

    #[test]
    fn paging_survives_a_burst_whose_msgid_order_fights_its_insert_order() {
        // Concurrent senders in one second get their rows written in an order
        // that has nothing to do with their msgids — verified in production
        // data. A client sorts by `(timestamp, msgid)`, so a page boundary on
        // one of those disagreements can hand back only rows the client files
        // ABOVE its anchor: the anchor does not move, the next request is
        // identical, and the reader is stuck at that boundary for good.
        let db = Db::open_memory().unwrap();
        const T: u64 = 1_700_100_000;
        // Insert order is the rowid order; the msgids deliberately are not.
        let inserts = [
            "01CLASH00000000000000000M10",
            "01CLASH00000000000000000M20",
            "01CLASH00000000000000000M30",
            "01CLASH00000000000000000M05", // sorts first, written fourth
            "01CLASH00000000000000000M40",
            "01CLASH00000000000000000M50",
        ];
        for id in inserts {
            msg_at(&db, "#clash", id, T);
        }

        let mut expected: Vec<String> = inserts.iter().map(|s| s.to_string()).collect();
        expected.sort();

        // Two at a time, so a boundary lands on the disagreement.
        let walked = walk_like_a_client(&db, "#clash", 2);

        assert_eq!(walked, expected, "the whole channel, in the client's order");
    }

    #[test]
    fn the_opening_page_and_the_pages_after_it_cut_on_one_order() {
        // The opening page a client gets is `get_messages`, and everything
        // after it is the msgid cursor. If those two are cut on different
        // orders, a boundary inside a second leaves rows on the far side that
        // the client sorts NEWER than anything it holds — so paging backwards
        // can never reach them and they are lost for the session.
        let db = Db::open_memory().unwrap();
        const T: u64 = 1_700_200_000;
        // Three seconds, twelve rows each, msgids interleaved across the
        // second the way concurrent senders interleave them.
        let mut all: Vec<String> = Vec::new();
        for second in 0..3u64 {
            for sender in 0..4u64 {
                for i in 0..3u64 {
                    // Insert grouped by sender, but number the msgids so that
                    // the two orders disagree inside every second.
                    let id = format!("01OPEN{:021}", second * 100 + i * 10 + sender);
                    msg_at(&db, "#opening", &id, T + second);
                    all.push(id);
                }
            }
        }
        all.sort();

        let walked = walk_like_a_client(&db, "#opening", 10);

        assert_eq!(walked, all, "every row, however the opening page was cut");
    }

    #[test]
    fn around_cursor_splits_the_page_across_the_anchor() {
        let db = Db::open_memory().unwrap();
        let ids = same_second_burst(&db, "#around", 20, 1_700_000_500);

        // Anchored on the middle row, with an even limit: half the page is
        // older than the anchor, and the rest starts at the anchor itself.
        let (ts, id) = db.history_cursor("#around", &ids[10]).unwrap().unwrap();
        let page = db
            .get_messages_around_cursor("#around", ts, &id, 10)
            .unwrap();
        let got: Vec<String> = page.iter().map(|r| r.msgid.clone().unwrap()).collect();
        assert_eq!(
            got,
            ids[5..15],
            "five older, then the anchor and four newer"
        );
    }

    #[test]
    fn around_cursor_at_an_end_returns_what_there_is() {
        let db = Db::open_memory().unwrap();
        let ids = same_second_burst(&db, "#aroundend", 6, 1_700_000_600);

        // Oldest row: nothing older to serve, so only the newer half comes
        // back. The page is short, not padded from the other side.
        let (ts, id) = db.history_cursor("#aroundend", &ids[0]).unwrap().unwrap();
        let page = db
            .get_messages_around_cursor("#aroundend", ts, &id, 6)
            .unwrap();
        let got: Vec<String> = page.iter().map(|r| r.msgid.clone().unwrap()).collect();
        assert_eq!(got, ids[0..3]);

        // Newest row: the older half is served in full, and the newer half
        // is the anchor alone. The short half is not padded from the other.
        let (ts, id) = db
            .history_cursor("#aroundend", ids.last().unwrap())
            .unwrap()
            .unwrap();
        let page = db
            .get_messages_around_cursor("#aroundend", ts, &id, 6)
            .unwrap();
        let got: Vec<String> = page.iter().map(|r| r.msgid.clone().unwrap()).collect();
        assert_eq!(got, ids[2..6]);
    }

    #[test]
    fn around_cursor_page_skips_deleted_rows_but_a_deleted_row_still_anchors() {
        let db = Db::open_memory().unwrap();
        for i in 0..5 {
            msg(
                &db,
                "#arounddel",
                &format!("row {i}"),
                1_700_000_700 + i as u64,
                &format!("01ARDEL{:019}", i),
            );
        }
        db.soft_delete_message("#arounddel", "01ARDEL0000000000000000002")
            .unwrap();

        let (ts, id) = db
            .history_cursor("#arounddel", "01ARDEL0000000000000000002")
            .unwrap()
            .expect("a deleted row still names a place in the order");
        let page = db
            .get_messages_around_cursor("#arounddel", ts, &id, 4)
            .unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            vec!["row 0", "row 1", "row 3", "row 4"],
            "the deleted anchor is not served, the rows around it are"
        );
    }

    #[test]
    fn around_timestamp_splits_on_plain_time() {
        let db = Db::open_memory().unwrap();
        for i in 0..8 {
            msg(
                &db,
                "#aroundts",
                &format!("row {i}"),
                1_700_000_800 + i as u64,
                &format!("01ARTS{:020}", i),
            );
        }

        // A time that is a row's own second: that row belongs to the newer
        // half, so no row falls between the two halves.
        let page = db
            .get_messages_around("#aroundts", 1_700_000_804, 4)
            .unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["row 2", "row 3", "row 4", "row 5"]);

        // A time no row carries splits between neighbours.
        let page = db
            .get_messages_around("#aroundts", 1_700_000_850, 4)
            .unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["row 6", "row 7"]);
    }

    #[test]
    fn around_pages_are_contiguous_with_what_a_walk_from_them_reaches() {
        let db = Db::open_memory().unwrap();
        let ids = same_second_burst(&db, "#aroundwalk", 30, 1_700_000_900);

        let (ts, id) = db.history_cursor("#aroundwalk", &ids[15]).unwrap().unwrap();
        let page = db
            .get_messages_around_cursor("#aroundwalk", ts, &id, 8)
            .unwrap();
        let mut walked: Vec<String> = page.iter().map(|r| r.msgid.clone().unwrap()).collect();

        // Paging out of an around page in both directions reaches every row
        // exactly once: the two edges of the page are ordinary cursors.
        let (ts, id) = db
            .history_cursor("#aroundwalk", walked.first().unwrap())
            .unwrap()
            .unwrap();
        let older = db
            .get_messages_before_cursor("#aroundwalk", ts, &id, 100)
            .unwrap();
        let (ts, id) = db
            .history_cursor("#aroundwalk", walked.last().unwrap())
            .unwrap()
            .unwrap();
        let newer = db
            .get_messages_after_cursor("#aroundwalk", ts, &id, 100)
            .unwrap();

        let mut all: Vec<String> = older.iter().map(|r| r.msgid.clone().unwrap()).collect();
        all.append(&mut walked);
        all.extend(newer.iter().map(|r| r.msgid.clone().unwrap()));
        assert_eq!(all, ids, "every row exactly once, in stored order");
    }

    #[test]
    fn history_cursor_is_none_for_an_unknown_msgid() {
        let db = Db::open_memory().unwrap();
        msg(
            &db,
            "#unk",
            "only",
            1_700_000_300,
            "01UNK0000000000000000000001",
        );

        assert!(
            db.history_cursor("#unk", "01UNK0000000000000000000009")
                .unwrap()
                .is_none()
        );
        // A msgid from another channel is unknown here too — a cursor is only
        // meaningful inside the order it names a place in.
        msg(
            &db,
            "#other",
            "elsewhere",
            1_700_000_301,
            "01OTH0000000000000000000001",
        );
        assert!(
            db.history_cursor("#unk", "01OTH0000000000000000000001")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cursor_page_skips_deleted_rows_but_a_deleted_row_still_anchors() {
        let db = Db::open_memory().unwrap();
        msg(
            &db,
            "#del",
            "keep",
            1_700_000_400,
            "01DEL0000000000000000000001",
        );
        msg(
            &db,
            "#del",
            "gone",
            1_700_000_401,
            "01DEL0000000000000000000002",
        );
        msg(
            &db,
            "#del",
            "newest",
            1_700_000_402,
            "01DEL0000000000000000000003",
        );
        db.soft_delete_message("#del", "01DEL0000000000000000000002")
            .unwrap();

        let (ts, id) = db
            .history_cursor("#del", "01DEL0000000000000000000002")
            .unwrap()
            .expect("a deleted row still names a place in the order");
        let page = db.get_messages_before_cursor("#del", ts, &id, 10).unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["keep"]);

        let (ts, id) = db
            .history_cursor("#del", "01DEL0000000000000000000001")
            .unwrap()
            .unwrap();
        let page = db.get_messages_after_cursor("#del", ts, &id, 10).unwrap();
        let texts: Vec<&str> = page.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["newest"], "the deleted row is not served");
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
        db.store_reaction_by(
            subject,
            "#t",
            "alice",
            Some("did:plc:aaa"),
            "👍",
            1000,
            Some(&react_ev),
        )
        .unwrap();
        assert!(
            db.get_event("01EVREACT00000000000000001")
                .unwrap()
                .is_some(),
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
            .remove_reaction_by(
                subject,
                "alice",
                Some("did:plc:aaa"),
                "👍",
                "#t",
                Some(&unreact_ev),
            )
            .unwrap();
        assert_eq!(removed, 1, "the reaction row itself must go");
        assert!(
            db.get_event("01EVUNREACT000000000000001")
                .unwrap()
                .is_some(),
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
            db.get_event("01EVDELETE0000000000000001")
                .unwrap()
                .is_some(),
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

    // ── task events: the log, and the live-task view derived from it ────────

    /// Apply an accepted task event: check it against the task's current
    /// state, file it in the log, and update the view — all in one critical
    /// section.
    ///
    /// The three have to happen together. `with_db` holds the database mutex
    /// for the whole closure, so a caller that reads state, decides, and
    /// writes inside a single call is serialized against every other
    /// connection; split across two calls, two agents claiming the same open
    /// task could both read `open` and both win. That race is what the
    /// two-claims test exists to pin.
    ///
    /// The checker is the shared one from `freeq_sdk::act_transitions`, fed
    /// from the view row — so the server and a bot pre-checking the same move
    /// reach the same verdict from the same rules file.
    pub fn apply_act_event(&self, ev: &ActEvent<'_>) -> SqlResult<ActWrite> {
        use freeq_sdk::act_transitions as rules;

        let tx = self.conn.unchecked_transaction()?;
        let Some(view) = crate::events::derive_act_view(ev.canonical) else {
            return Ok(ActWrite::NotATaskEvent);
        };

        // ── A receipt ──
        //
        // Answered before the task's own state machine, because a receipt is
        // not a move on the task: it is one server's word that an event it
        // holds is the one that won. A receipt carries no state of its own —
        // the state comes from running the event it names through the shared
        // rules here — and it is filed with no confirm column, being the answer
        // rather than something awaiting one. Only a server writes one, so a
        // sender's confirm is refused here as it is at the gate; this path is
        // also reached from a peer and from a replay.
        if rules::is_confirmation(&view.verb) {
            if !ev.from_system {
                return Ok(ActWrite::Refused(rules::Refusal::ClientConfirm));
            }
            let subject = view
                .fields
                .get(rules::confirmation_subject_tag())
                .map(String::as_str)
                .unwrap_or_default();

            // ── authority is the link ──
            //
            // A receipt counts as the home's word only when the authenticated
            // peer it arrived from is the server the task was opened on. Our
            // own receipts carry no origin at all, and those count for a task
            // of ours. Anything else is somebody claiming an authority the
            // link does not give them: kept, because a signed claim is
            // evidence, and applied to nothing.
            //
            // A task whose opener this server has never seen has no home we
            // can name, and its subject cannot be on file either — so the
            // receipt waits for the subject rather than being judged against
            // an origin nobody knows.
            let Some(home) = self.act_task_origin(ev.act_id)? else {
                return Ok(ActWrite::ReceiptBeforeSubject);
            };
            let from_home = match ev.origin {
                None => home.is_empty(),
                Some(peer) => home == peer,
            };
            let record = EventRecord {
                shape: EventShape::Document(ev.canonical),
                signature: ev.signature,
                ctx: self.act_context(ev, None),
                timestamp: ev.timestamp as u64,
            };
            if !from_home {
                if !self.insert_event(&record)? {
                    return Ok(ActWrite::Duplicate);
                }
                tx.commit()?;
                return Ok(ActWrite::ReceiptIgnored);
            }

            // ── the event it names ──
            //
            // Not on file: the receipt overtook it, which an uneven mesh
            // makes ordinary. Nothing is written, and the caller holds it
            // until the subject lands.
            let Some(named) = self.get_event(subject)?.filter(|e| e.kind == "act") else {
                return Ok(ActWrite::ReceiptBeforeSubject);
            };
            // Already settled — our own move, or a receipt we have already
            // followed. Appending the record is the whole of it: confirming
            // twice must not move anything twice.
            if !self.act_event_is_unconfirmed(subject)? {
                if !self.insert_event(&record)? {
                    return Ok(ActWrite::Duplicate);
                }
                tx.commit()?;
                return Ok(ActWrite::Recorded);
            }

            if !self.insert_event(&record)? {
                return Ok(ActWrite::Duplicate);
            }
            return match self.apply_confirmed_event(ev.act_id, &named)? {
                // The home's word and the shared rules disagree. The rules
                // decide what this server's view says, and the receipt stays
                // on file as the signed evidence of the disagreement.
                Err(refusal) => {
                    tx.commit()?;
                    Ok(ActWrite::ReceiptRefused(refusal))
                }
                Ok(landed) => {
                    self.confirm_act_event(subject)?;
                    self.supersede_refused_act_events(ev.act_id, subject)?;
                    tx.commit()?;
                    Ok(ActWrite::Confirmed { state: landed })
                }
            };
        }

        // ── The revival relation ──
        //
        // Answered before the move itself, because it is a claim about a
        // *different* action: whether this event may carry the link at all,
        // and whether the action it names is in a fit state to be revived. An
        // action nobody here ever filed is accepted and annotated — a client's
        // typo today, and under federation the ordinary case, since the
        // predecessor lived on another machine.
        if let Some(named) = view.replaces.as_deref() {
            let predecessor = match self.act_task(named)? {
                Some(_) => rules::Predecessor::Live,
                None => match self.act_task_is_on_file(named)? {
                    true => rules::Predecessor::Finished,
                    false => rules::Predecessor::Unknown,
                },
            };
            if let Err(refusal) = rules::check_revival(ev.opens, named, predecessor) {
                return Ok(ActWrite::Refused(refusal));
            }
        }

        // What the event does to the task, where the task stood before it, and
        // what it looks like now.
        //
        // `kind` is the *task's*, which for an opener is the one the event
        // declares and for a follow-up is the one already on file. They should
        // agree, and nothing downstream depends on their agreeing: a step that
        // named the wrong kind is refereed by the task's rules and
        // materialized by them too, rather than by whatever the sender wrote.
        let mut was: Option<String> = None;
        let mut kind = view.kind.clone();
        // Who the step assigns, when the row takes its assignee from the bid
        // the event names rather than from the actor.
        let mut assignee_named: Option<String> = None;
        let landed = if ev.opens {
            // The opener's own id is the task's id. A second opener under the
            // same id is the log's duplicate case, handled by the write below.
            match rules::check_open(&view.kind, &view.verb, view.to.is_some(), false) {
                Ok(state) => state.to_string(),
                Err(refusal) => return Ok(ActWrite::Refused(refusal)),
            }
        } else {
            let Some(task) = self.act_task(ev.act_id)? else {
                // No live row. The view holds only unfinished work, so a task
                // the log knows is one that finished — a different answer from
                // one nobody ever opened, and the sender deserves the true
                // one. The log is the record; this is what it is for.
                return Ok(match self.act_task_is_on_file(ev.act_id)? {
                    true => ActWrite::Refused(rules::Refusal::TerminalTask),
                    false => ActWrite::UnknownTask,
                });
            };
            // A follow-up belongs to its task's conversation. Without this a
            // signed event could move a task from a room its participants
            // cannot see.
            if task.venue != ev.venue {
                return Ok(ActWrite::WrongVenue);
            }
            // Whether this event arrived on the link of the server that
            // referees the task. Our own events carry no origin at all, and a
            // task of ours has no home to hear from — we are it — so an empty
            // origin on either side is never a match.
            let from_home = !task.origin.is_empty() && ev.origin == Some(task.origin.as_str());
            // The one transition on a foreign task that needs no receipt: one
            // the home itself authored — an expiry, a closed review window —
            // which already carries the signature of the server whose word
            // settles the task. A participant's move gains that signature
            // through a receipt; the home's move was born with it.
            let home_authored = from_home && ev.from_system;

            // ── whose task is it ──
            //
            // A task another server opened is that server's to referee. An
            // event that would move it is filed here and goes no further:
            // deciding it would make two servers the authority over one task,
            // and disagreeing about which. An additive move carries no state
            // decision to usurp, so it takes the ordinary path below. Which is
            // which comes out of the rules file, never a list of verbs here.
            if !task.origin.is_empty()
                && !home_authored
                && rules::is_additive(&task.kind, &view.verb) == Some(false)
            {
                let record = EventRecord {
                    shape: EventShape::Document(ev.canonical),
                    signature: ev.signature,
                    ctx: self.act_context(ev, Some(crate::events::ConfirmState::Unconfirmed)),
                    timestamp: ev.timestamp as u64,
                };
                if !self.insert_event(&record)? {
                    return Ok(ActWrite::Duplicate);
                }
                tx.commit()?;
                return Ok(ActWrite::StoredNotApplied);
            }
            let present: Vec<&str> = view.fields.keys().map(String::as_str).collect();
            // The bid an award takes, resolved before the checker is asked:
            // the checker reads no log, so the lookup is ours. Only a bid
            // filed against this same action answers, which is what makes an
            // award naming the opener — or a bid on somebody else's bounty —
            // take nothing.
            let accepts = view.fields.get("act-accepts").map(String::as_str);
            let bid_author = match accepts {
                Some(named) => self.act_bid_author(ev.act_id, named)?,
                None => None,
            };
            let event = rules::Event {
                verb: &view.verb,
                msgid: ev.event_id,
                accepts,
                fields: &present,
            };
            let sender = rules::Sender {
                did: ev.actor,
                // The server itself, and only where a server may be speaking
                // as one: our own events (no origin), or the home's about its
                // own task. A peer relaying an event signed under some
                // `did:web:` name is not thereby the system here — without
                // this, any peer whose key we hold could expire our tasks.
                is_system: ev.from_system && (ev.origin.is_none() || from_home),
                accepted_bid: bid_author
                    .as_deref()
                    .map(|author| rules::AcceptedBid { author }),
            };
            let checked = rules::Task {
                kind: &task.kind,
                state: &task.state,
                offerer: &task.offerer,
                offeree: task.offeree.as_deref(),
                assignee: task.assignee.as_deref(),
                deadline: task.deadline,
                // Read back out of the opener rather than carried in a
                // column: it is one of the open set of act tags, and the view
                // holds only what it needs to referee. The bytes are the
                // record and they still have it.
                bid_deadline: self.act_task_bid_deadline(ev.act_id)?,
            };
            match rules::check(&checked, &event, &sender) {
                Ok(state) => {
                    was = Some(task.state.clone());
                    kind = task.kind.clone();
                    assignee_named = bid_author;
                    state.to_string()
                }
                Err(refusal) => return Ok(ActWrite::Refused(refusal)),
            }
        };

        // The log is append-only and first-write-wins. If it declines the id,
        // the view must not move either — one of them showing an event the
        // other does not is the disagreement this path exists to prevent.
        let record = EventRecord {
            shape: EventShape::Document(ev.canonical),
            signature: ev.signature,
            ctx: self.act_context(ev, Some(crate::events::ConfirmState::Confirmed)),
            timestamp: ev.timestamp as u64,
        };
        if !self.insert_event(&record)? {
            return Ok(ActWrite::Duplicate);
        }
        self.materialize_act(
            ev,
            &view,
            &kind,
            was.as_deref(),
            &landed,
            assignee_named.as_deref(),
        )?;
        // Whatever else this move did, it may have outrun something. An event
        // of this task still waiting on its home, which the rules no longer
        // admit, is a loser: it leaves the pending set here rather than
        // waiting for a confirmation that can never come.
        self.supersede_refused_act_events(ev.act_id, ev.event_id)?;
        tx.commit()?;
        Ok(ActWrite::Filed { was, state: landed })
    }

    /// Re-run one stored event of `act_id` through the rules against where the
    /// task now stands, and, when the rules take it, move the view to match.
    ///
    /// This is what a receipt makes happen: the receipt says which event won,
    /// and the state comes from running that event through the shared rules
    /// here — never from the receipt, which carries none. A home whose receipt
    /// the rules refuse gets the refusal back, and this server's view is left
    /// exactly where the rules put it.
    ///
    /// `named` is the stored subject: its own actor, venue and receipt time,
    /// so the view records the move as it happened rather than as of the
    /// moment the receipt arrived.
    fn apply_confirmed_event(
        &self,
        act_id: &str,
        named: &StoredEvent,
    ) -> SqlResult<Result<String, freeq_sdk::act_transitions::Refusal>> {
        use freeq_sdk::act_transitions as rules;

        let Some(view) = crate::events::derive_act_view(&named.canonical) else {
            return Ok(Err(rules::Refusal::UnknownVerb));
        };
        // No live row means the task has finished, and a finished task admits
        // nothing at all.
        let Some(task) = self.act_task(act_id)? else {
            return Ok(Err(rules::Refusal::TerminalTask));
        };
        let actor = named.actor_did.clone().unwrap_or_default();
        let present: Vec<&str> = view.fields.keys().map(String::as_str).collect();
        let accepts = view.fields.get("act-accepts").map(String::as_str);
        let bid_author = match accepts {
            Some(bid) => self.act_bid_author(act_id, bid)?,
            None => None,
        };
        let landed = match rules::check(
            &rules::Task {
                kind: &task.kind,
                state: &task.state,
                offerer: &task.offerer,
                offeree: task.offeree.as_deref(),
                assignee: task.assignee.as_deref(),
                deadline: task.deadline,
                bid_deadline: self.act_task_bid_deadline(act_id)?,
            },
            &rules::Event {
                verb: &view.verb,
                msgid: &named.event_id,
                accepts,
                fields: &present,
            },
            &rules::Sender {
                did: &actor,
                // Read off the actor, the way a rebuild reads it. A server
                // acts under `did:web:`; a person does not.
                is_system: crate::server::is_system_actor(&actor),
                accepted_bid: bid_author
                    .as_deref()
                    .map(|author| rules::AcceptedBid { author }),
            },
        ) {
            Ok(state) => state.to_string(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        // The event as it was filed, so the view records the move at the time
        // this server took it rather than at the moment the receipt arrived.
        let confirmed = ActEvent {
            canonical: &named.canonical,
            signature: named.signature.as_deref(),
            event_id: &named.event_id,
            act_id,
            opens: false,
            venue: &named.venue,
            actor: &actor,
            from_system: crate::server::is_system_actor(&actor),
            origin: named.origin.as_deref(),
            timestamp: named.timestamp as i64,
        };
        self.materialize_act(
            &confirmed,
            &view,
            &task.kind,
            Some(&task.state),
            &landed,
            bid_author.as_deref(),
        )?;
        Ok(Ok(landed))
    }

    /// Mark one task event as ruled on by its task's home.
    ///
    /// Returns whether a row moved: `false` when the id is not on file, or
    /// when it was confirmed already and there is nothing to change.
    fn confirm_act_event(&self, event_id: &str) -> SqlResult<bool> {
        self.conn.execute(
            "UPDATE events SET confirm_state = 'confirmed'
              WHERE event_id = ?1 AND kind = 'act'
                AND (confirm_state IS NULL OR confirm_state <> 'confirmed')",
            params![event_id],
        )?;
        Ok(self.conn.changes() > 0)
    }

    /// Drop from the pending set every unconfirmed event of this task the
    /// rules no longer admit — the losing half of a race, once the winner has
    /// been ruled in.
    ///
    /// Re-checked rather than swept: an unconfirmed event that is still a
    /// legal move has simply not been ruled on yet, and calling it a loser
    /// because something else landed first would drop a claim its home may
    /// still confirm. The log row is untouched either way; only the flag moves.
    fn supersede_refused_act_events(&self, act_id: &str, keep: &str) -> SqlResult<usize> {
        use freeq_sdk::act_transitions as rules;

        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, actor_did FROM events
              WHERE kind = 'act' AND subject = ?1 AND confirm_state = 'unconfirmed'
                AND event_id <> ?2",
        )?;
        let pending: Vec<(String, String, String)> = stmt
            .query_map(params![act_id, keep], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                ))
            })?
            .collect::<SqlResult<_>>()?;
        if pending.is_empty() {
            return Ok(0);
        }

        // No live row means the task finished, and a finished task admits
        // nothing at all.
        let task = self.act_task(act_id)?;
        let bid_deadline = self.act_task_bid_deadline(act_id)?;
        let mut dropped = 0usize;
        for (event_id, canonical, actor) in pending {
            let Some(view) = crate::events::derive_act_view(&canonical) else {
                continue;
            };
            let present: Vec<&str> = view.fields.keys().map(String::as_str).collect();
            let accepts = view.fields.get("act-accepts").map(String::as_str);
            let bid_author = match accepts {
                Some(bid) => self.act_bid_author(act_id, bid)?,
                None => None,
            };
            let still_legal = task.as_ref().is_some_and(|task| {
                rules::check(
                    &rules::Task {
                        kind: &task.kind,
                        state: &task.state,
                        offerer: &task.offerer,
                        offeree: task.offeree.as_deref(),
                        assignee: task.assignee.as_deref(),
                        deadline: task.deadline,
                        bid_deadline,
                    },
                    &rules::Event {
                        verb: &view.verb,
                        msgid: &event_id,
                        accepts,
                        fields: &present,
                    },
                    &rules::Sender {
                        did: &actor,
                        is_system: crate::server::is_system_actor(&actor),
                        accepted_bid: bid_author
                            .as_deref()
                            .map(|author| rules::AcceptedBid { author }),
                    },
                )
                .is_ok()
            });
            if still_legal {
                continue;
            }
            self.conn.execute(
                "UPDATE events SET confirm_state = 'superseded' WHERE event_id = ?1",
                params![event_id],
            )?;
            dropped += self.conn.changes() as usize;
        }
        Ok(dropped)
    }

    /// Count one more event about this task that the defer queue threw away
    /// unchecked. Returns whether a task row was there to mark — an event
    /// whose task is not on file leaves only the eviction log.
    ///
    /// A receipt fact, not part of the task's state machine: never relayed,
    /// never in the signed log, and not reproducible by a rebuild (the
    /// dropped event is precisely what the log never received).
    pub fn bump_act_dropped_unchecked(&self, act_id: &str) -> SqlResult<bool> {
        self.conn.execute(
            "UPDATE act_actions SET dropped_unchecked = dropped_unchecked + 1
              WHERE act_id = ?1",
            params![act_id],
        )?;
        Ok(self.conn.changes() > 0)
    }

    /// How many events about this task the defer queue threw away unchecked.
    /// Zero for a task with no row — nothing was recorded against it.
    pub fn act_dropped_unchecked(&self, act_id: &str) -> SqlResult<i64> {
        self.conn
            .query_row(
                "SELECT dropped_unchecked FROM act_actions WHERE act_id = ?1",
                params![act_id],
                |r| r.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0))
    }

    /// The receipt facts for a task event's log row: this server checked the
    /// signature itself before calling, a relayed event says which link it came
    /// in on, so a reader can tell a local event from a federated one, and
    /// `confirm` is whether the rules were run on it or it is still waiting on
    /// its task's home. `None` for a receipt, which is the answer rather than
    /// something awaiting one.
    fn act_context(
        &self,
        ev: &ActEvent<'_>,
        confirm: Option<crate::events::ConfirmState>,
    ) -> crate::events::EventContext {
        crate::events::EventContext {
            sig_state: crate::events::SigState::Valid,
            origin: ev.origin.map(str::to_string),
            confirm,
        }
    }

    /// Move the view to match an event that was just accepted.
    ///
    /// The rules, in full: an opener creates the row and sets what the offer
    /// declared; a step that moves a task into `assigned` names its assignee;
    /// a terminal state removes the row, because the view holds live tasks and
    /// the log holds the history.
    ///
    /// `was` is the state the task came from — what the rules file is asked
    /// about when it says where a transition's assignee comes from, and
    /// `named` is who the caller resolved the event's `act-accepts` to when
    /// the row takes its assignee from a bid.
    fn materialize_act(
        &self,
        ev: &ActEvent<'_>,
        view: &crate::events::ActView,
        kind: &str,
        was: Option<&str>,
        landed: &str,
        named: Option<&str>,
    ) -> SqlResult<()> {
        if freeq_sdk::act_transitions::is_terminal(kind, landed) {
            self.conn.execute(
                "DELETE FROM act_actions WHERE act_id = ?1",
                params![ev.act_id],
            )?;
            return Ok(());
        }
        if ev.opens {
            self.conn.execute(
                // The count of events the defer queue threw away unchecked
                // is carried over rather than reset: it is a fact about what
                // this server never received, and replacing the row — which a
                // rebuild does for every task — must not quietly say the
                // record is whole again.
                "INSERT OR REPLACE INTO act_actions
                     (act_id, kind, venue, origin, state, offerer, offeree, caps, deadline,
                      replaces, updated, dropped_unchecked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         COALESCE((SELECT dropped_unchecked FROM act_actions
                                    WHERE act_id = ?1), 0))",
                params![
                    ev.act_id,
                    kind,
                    ev.venue,
                    ev.origin.unwrap_or(""),
                    landed,
                    ev.actor,
                    view.to,
                    view.caps,
                    view.deadline,
                    view.replaces,
                    ev.timestamp,
                ],
            )?;
            return Ok(());
        }
        // A step that moves a task into `assigned` names its assignee — and
        // only the first one does, so a progress report does not reassign the
        // work it is reporting on.
        //
        // Who it names is data. Accepting and claiming make the actor the
        // assignee; a bounty's award takes the bid it names, and the work goes
        // to whoever wrote that bid, because the poster picks rather than
        // becomes. A row whose source resolves to nobody leaves the work
        // unassigned — fail closed, though the checker refusing the step is
        // what actually keeps that from happening.
        let assignee: Option<&str> = match freeq_sdk::act_transitions::assignee_source(
            kind,
            &view.verb,
            was.unwrap_or_default(),
        ) {
            freeq_sdk::act_transitions::AssigneeSource::Actor => Some(ev.actor),
            freeq_sdk::act_transitions::AssigneeSource::AuthorOf(_) => named,
            freeq_sdk::act_transitions::AssigneeSource::Field(name) => {
                view.fields.get(name).map(String::as_str)
            }
        };
        self.conn.execute(
            "UPDATE act_actions
                SET state = ?2,
                    assignee = CASE WHEN assignee IS NULL AND ?3 = 'assigned'
                                    THEN ?4 ELSE assignee END,
                    updated = ?5
              WHERE act_id = ?1",
            params![ev.act_id, landed, landed, assignee, ev.timestamp],
        )?;
        Ok(())
    }

    /// Whether `event_id` names a task event in the log.
    ///
    /// Asked by the delete and edit paths. Task events are immutable: the
    /// lifecycle is the only way a task changes, and a later event supersedes
    /// an earlier one rather than erasing it. A message row is not consulted,
    /// because a task event has none — which is exactly how the DM path used
    /// to end up relaying such a delete instead of refusing it.
    pub fn is_act_event(&self, event_id: &str) -> SqlResult<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'act' AND event_id = ?1",
            params![event_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Whether the log has ever held an event opening this task.
    ///
    /// Asked only on the refusal path, to tell a finished task apart from one
    /// that never existed. The view cannot answer it: it drops a task the
    /// moment the task ends.
    pub fn act_task_is_on_file(&self, act_id: &str) -> SqlResult<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'act' AND event_id = ?1",
            params![act_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Where a task was opened, read off the opener's own log row: the empty
    /// string when this server opened it, and `None` when the log has never
    /// held that opener at all.
    ///
    /// The view answers the same question while a task is live and forgets it
    /// the moment the task ends — which is precisely when the last move on it
    /// is the one still needing an answer.
    pub fn act_task_origin(&self, act_id: &str) -> SqlResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT COALESCE(origin, '') FROM events
                  WHERE kind = 'act' AND event_id = ?1",
                params![act_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// The conversation a task happens in, read off its opener's own log row.
    ///
    /// The venue every one of its events binds, and the one thing that lets a
    /// receiver rebuild the document a `did:web:` server signed: a home signs
    /// the task's venue, and a DM venue derived from the *signer* would be a
    /// pair of DIDs the home is not one of. `None` when the log has never held
    /// that opener.
    pub fn act_task_venue(&self, act_id: &str) -> SqlResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT venue FROM events WHERE kind = 'act' AND event_id = ?1",
                params![act_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// The receipt this server holds for one event, or `None` when it holds
    /// none.
    ///
    /// What a peer asking again about a transition is answered with: the
    /// receipt was written down when it was made, so saying it again is reading
    /// it back rather than deciding anything a second time.
    pub fn act_receipt_for_subject(&self, subject: &str) -> SqlResult<Option<ActLoggedEvent>> {
        let tag = freeq_sdk::act_transitions::confirmation_subject_tag();
        Ok(self.act_events_naming(subject)?.into_iter().find(|e| {
            match crate::events::derive_act_view(&e.canonical) {
                Some(view) => {
                    freeq_sdk::act_transitions::is_confirmation(&view.verb)
                        && view.fields.get(tag).map(String::as_str) == Some(subject)
                }
                None => false,
            }
        }))
    }

    /// Every task event whose document mentions `subject` in the confirmation
    /// tag — read as every event of that event's task, because a receipt is
    /// filed under the task, not under what it names.
    fn act_events_naming(&self, subject: &str) -> SqlResult<Vec<ActLoggedEvent>> {
        let act_id: Option<String> = self
            .conn
            .query_row(
                "SELECT COALESCE(subject, event_id) FROM events
                  WHERE kind = 'act' AND event_id = ?1",
                params![subject],
                |r| r.get(0),
            )
            .optional()?;
        match act_id {
            Some(act_id) => self.act_task_events(&act_id),
            None => Ok(Vec::new()),
        }
    }

    /// Whether one task event is still waiting on a ruling from its task's
    /// home.
    ///
    /// `false` once the home has confirmed it, once something that outran it
    /// has superseded it, and for an id that is not on file at all — three
    /// different histories with one thing in common: nothing is owed on this
    /// event any more.
    pub fn act_event_is_unconfirmed(&self, event_id: &str) -> SqlResult<bool> {
        let raw: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT confirm_state FROM events WHERE event_id = ?1 AND kind = 'act'",
                params![event_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.is_some_and(|column| {
            crate::events::ConfirmState::from_column(column.as_deref())
                == crate::events::ConfirmState::Unconfirmed
        }))
    }

    /// One live task by id. `None` once it has finished — the log keeps the
    /// history, the view keeps the work.
    pub fn act_task(&self, act_id: &str) -> SqlResult<Option<ActTask>> {
        self.conn
            .query_row(
                "SELECT act_id, kind, venue, origin, state, offerer, offeree, assignee,
                        caps, deadline, replaces, updated
                 FROM act_actions WHERE act_id = ?1",
                params![act_id],
                |row| {
                    Ok(ActTask {
                        act_id: row.get(0)?,
                        kind: row.get(1)?,
                        venue: row.get(2)?,
                        origin: row.get(3)?,
                        state: row.get(4)?,
                        offerer: row.get(5)?,
                        offeree: row.get(6)?,
                        assignee: row.get(7)?,
                        caps: row.get(8)?,
                        deadline: row.get(9)?,
                        replaces: row.get(10)?,
                        updated: row.get(11)?,
                    })
                },
            )
            .optional()
    }

    /// Live tasks, newest movement first, filtered by whatever the caller
    /// named. `venues` bounds the answer to conversations the reader may see.
    pub fn act_tasks(
        &self,
        venues: &[String],
        kind: Option<&str>,
        assignee: Option<&str>,
        state: Option<&str>,
        limit: usize,
    ) -> SqlResult<Vec<ActTask>> {
        if venues.is_empty() {
            return Ok(Vec::new());
        }
        let places = venues.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT act_id, kind, venue, origin, state, offerer, offeree, assignee,
                    caps, deadline, replaces, updated
               FROM act_actions
              WHERE venue IN ({places})
                AND (?{k} IS NULL OR kind = ?{k})
                AND (?{a} IS NULL OR assignee = ?{a})
                AND (?{s} IS NULL OR state = ?{s})
              ORDER BY updated DESC, act_id
              LIMIT ?{l}",
            k = venues.len() + 1,
            a = venues.len() + 2,
            s = venues.len() + 3,
            l = venues.len() + 4,
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        for v in venues {
            args.push(Box::new(v.clone()));
        }
        args.push(Box::new(kind.map(str::to_string)));
        args.push(Box::new(assignee.map(str::to_string)));
        args.push(Box::new(state.map(str::to_string)));
        args.push(Box::new(limit as i64));
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(refs.as_slice(), |row| {
            Ok(ActTask {
                act_id: row.get(0)?,
                kind: row.get(1)?,
                venue: row.get(2)?,
                origin: row.get(3)?,
                state: row.get(4)?,
                offerer: row.get(5)?,
                offeree: row.get(6)?,
                assignee: row.get(7)?,
                caps: row.get(8)?,
                deadline: row.get(9)?,
                replaces: row.get(10)?,
                updated: row.get(11)?,
            })
        })?;
        rows.collect()
    }

    /// Live tasks whose last movement is older than `cutoff` and whose state
    /// is one of `states` — the review sweep's candidates, among the tasks
    /// created here.
    ///
    /// `updated` is what is measured, so a task that anyone touched recently
    /// is not abandoned however old its opener is. On a review window that is
    /// exactly the behaviour wanted: asking for changes moves the task, which
    /// stops the clock, and the next submission starts a fresh one.
    pub fn act_tasks_idle_in_states(
        &self,
        states: &[&str],
        cutoff: i64,
        limit: usize,
    ) -> SqlResult<Vec<ActTask>> {
        self.act_tasks_idle(states, true, cutoff, limit)
    }

    /// Live tasks idle since `cutoff` whose state is **not** one of `states` —
    /// the expiry sweep's candidates, among the tasks created here.
    ///
    /// The complement of the query above, so the two clocks cannot both claim
    /// a task. They pull in opposite directions: a review window favours the
    /// worker and the idle limit is neutral, so a task sitting inside its
    /// review window must not be expired out from under it by whichever of
    /// the two numbers an operator happened to set lower.
    pub fn act_tasks_idle_outside_states(
        &self,
        states: &[&str],
        cutoff: i64,
        limit: usize,
    ) -> SqlResult<Vec<ActTask>> {
        self.act_tasks_idle(states, false, cutoff, limit)
    }

    /// Both sweeps' candidates, and both are limited to tasks created here.
    ///
    /// A sweep files an event of the server's own — an expiry, or a review
    /// window deemed closed — and that belongs to the server the task was
    /// created on, which is the one that orders what happens to it. `origin`
    /// is empty for a task opened here and names the home server otherwise,
    /// so the filter changes nothing while every stored task is local, and
    /// starts carrying weight the moment a peer's task is stored.
    fn act_tasks_idle(
        &self,
        states: &[&str],
        within: bool,
        cutoff: i64,
        limit: usize,
    ) -> SqlResult<Vec<ActTask>> {
        // A state name is a rules-file constant, never anything a sender
        // wrote, but the list is built at runtime — so the placeholders are
        // counted rather than the values interpolated. Numbered rather than
        // bare: SQLite numbers a bare `?` from the highest index it has seen,
        // which would collide with the `?2` the LIMIT further down already
        // holds.
        let holes = (0..states.len())
            .map(|i| format!("?{}", i + 3))
            .collect::<Vec<_>>()
            .join(",");
        let test = match (states.is_empty(), within) {
            // Nothing to be within, and everything is outside nothing.
            (true, true) => "0".to_string(),
            (true, false) => "1".to_string(),
            (false, true) => format!("state IN ({holes})"),
            (false, false) => format!("state NOT IN ({holes})"),
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT act_id, kind, venue, origin, state, offerer, offeree, assignee,
                    caps, deadline, replaces, updated
               FROM act_actions
              WHERE updated < ?1 AND origin = '' AND {test}
              ORDER BY updated
              LIMIT ?2"
        ))?;
        let limit = limit as i64;
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&cutoff, &limit];
        for state in states {
            args.push(state);
        }
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |row| {
            Ok(ActTask {
                act_id: row.get(0)?,
                kind: row.get(1)?,
                venue: row.get(2)?,
                origin: row.get(3)?,
                state: row.get(4)?,
                offerer: row.get(5)?,
                offeree: row.get(6)?,
                assignee: row.get(7)?,
                caps: row.get(8)?,
                deadline: row.get(9)?,
                replaces: row.get(10)?,
                updated: row.get(11)?,
            })
        })?;
        rows.collect()
    }

    /// The title an offer declared, read back out of the opener's bytes.
    ///
    /// Not a column: `act-title` is one of the open set of act tags, and the
    /// view holds only what it needs to referee. The expiry notice is the one
    /// place a human-readable name is wanted, and the log has it.
    pub fn act_task_title(&self, act_id: &str) -> SqlResult<Option<String>> {
        let canonical: Option<String> = self
            .conn
            .query_row(
                "SELECT canonical FROM events WHERE kind = 'act' AND event_id = ?1",
                params![act_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(canonical.and_then(|c| {
            serde_json::from_str::<serde_json::Value>(&c)
                .ok()?
                .get("act-title")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        }))
    }

    /// The bid cutoff an offer declared, read back out of the opener's bytes.
    ///
    /// The same reading `act_task_title` does, for the same reason: a second
    /// deadline is one of the open set of act tags, and the view carries only
    /// the columns it referees on. A value nobody can read as a number is a
    /// cutoff this server cannot enforce, so it answers as absent — the tag
    /// stays in the canonical either way.
    pub fn act_task_bid_deadline(&self, act_id: &str) -> SqlResult<Option<i64>> {
        let canonical: Option<String> = self
            .conn
            .query_row(
                "SELECT canonical FROM events WHERE kind = 'act' AND event_id = ?1",
                params![act_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(canonical.and_then(|c| {
            serde_json::from_str::<serde_json::Value>(&c)
                .ok()?
                .get("act-bid-deadline")
                .and_then(|v| v.as_str())?
                .parse::<i64>()
                .ok()
        }))
    }

    /// Every venue that currently holds a live task.
    ///
    /// The listing endpoint runs each of these through the same authorization
    /// a channel read gets, so the answer is bounded by what the caller may
    /// already see rather than by a second, parallel rule.
    pub fn act_venues(&self) -> SqlResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT venue FROM act_actions ORDER BY venue")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    /// The task events stored for one venue within `[from_ts, to_ts]`, the
    /// newest `limit` of them, returned oldest first.
    ///
    /// What replay emits. The window and limit come from the request being
    /// answered — a JOIN burst or a CHATHISTORY subcommand — never from the
    /// message rows that happened to come back, so a task posted after the
    /// last chat line is still served.
    pub fn act_events_for_venue(
        &self,
        venue: &str,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> SqlResult<Vec<ActLoggedEvent>> {
        // Newest first under the cap — a reader catching up wants the latest
        // events, not the oldest `limit` of them — then oldest first to the
        // caller, which interleaves them with messages in time order.
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, actor_did, venue, confirm_state,
                    timestamp
               FROM events
              WHERE kind = 'act' AND venue = ?1
                AND timestamp >= ?2 AND timestamp <= ?3
              ORDER BY timestamp DESC, event_id DESC
              LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![venue, from_ts, to_ts, limit as i64], |row| {
            let canonical: String = row.get(1)?;
            Ok(ActLoggedEvent {
                event_id: row.get(0)?,
                confirm: match is_receipt_document(&canonical) {
                    true => None,
                    false => Some(crate::events::ConfirmState::from_column(
                        row.get::<_, Option<String>>(5)?.as_deref(),
                    )),
                },
                canonical,
                signature: row.get(2)?,
                actor_did: row.get(3)?,
                venue: row.get(4)?,
                timestamp: row.get(6)?,
            })
        })?;
        let mut events: Vec<ActLoggedEvent> = rows.collect::<SqlResult<_>>()?;
        events.reverse();
        Ok(events)
    }

    /// Who wrote the bid `event_id` names on this action, or `None` when it
    /// names something else.
    ///
    /// What an award's `act-accepts` resolves to, and the reason the checker
    /// can stay a function of its arguments: the log answers here, once, and
    /// hands the checker a fact. The search runs over the action's own events,
    /// so an id filed against another action answers `None` for the same
    /// reason a non-bid does — this award has nothing to take.
    fn act_bid_author(&self, act_id: &str, event_id: &str) -> SqlResult<Option<String>> {
        Ok(self
            .act_task_events(act_id)?
            .into_iter()
            .find(|e| e.event_id == event_id)
            .and_then(|e| {
                let view = crate::events::derive_act_view(&e.canonical)?;
                match view.verb == freeq_sdk::act_transitions::BID_VERB {
                    true => e.actor_did,
                    false => None,
                }
            }))
    }

    /// Every stored event of one task, oldest first: the opener, then each
    /// follow-up. This is the history a reader gets, and it outlives the view.
    pub fn act_task_events(&self, act_id: &str) -> SqlResult<Vec<ActLoggedEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, signature, actor_did, venue, confirm_state,
                    timestamp
               FROM events
              WHERE kind = 'act' AND (event_id = ?1 OR subject = ?1)
              ORDER BY timestamp, event_id",
        )?;
        let rows = stmt.query_map(params![act_id], |row| {
            let canonical: String = row.get(1)?;
            Ok(ActLoggedEvent {
                event_id: row.get(0)?,
                confirm: match is_receipt_document(&canonical) {
                    true => None,
                    false => Some(crate::events::ConfirmState::from_column(
                        row.get::<_, Option<String>>(5)?.as_deref(),
                    )),
                },
                canonical,
                signature: row.get(2)?,
                actor_did: row.get(3)?,
                venue: row.get(4)?,
                timestamp: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Rebuild the whole view from the log, replaying every task event in
    /// order — the proof that the view is derived and not authored.
    ///
    /// Used by the test that compares a rebuild against the live table. A
    /// mismatch means some path wrote the view without going through the log,
    /// which is the one thing that would make the log stop being the record.
    pub fn rebuild_act_actions(&self) -> SqlResult<Vec<ActTask>> {
        // Mint order, not delivery order. `timestamp` is when *this* server
        // took the event, which differs on every server that took the same
        // events; a signed event id is a ULID, so its byte order is the order
        // its signers minted in and every server reads the same one out of it.
        let mut stmt = self.conn.prepare(
            "SELECT event_id, canonical, actor_did, venue, subject, origin,
                    confirm_state, timestamp
               FROM events WHERE kind = 'act' ORDER BY event_id",
        )?;
        struct Row {
            event_id: String,
            canonical: String,
            actor: String,
            venue: String,
            subject: Option<String>,
            origin: Option<String>,
            confirm: crate::events::ConfirmState,
            timestamp: i64,
        }
        let mut rows: Vec<Row> = stmt
            .query_map([], |row| {
                Ok(Row {
                    event_id: row.get(0)?,
                    canonical: row.get(1)?,
                    actor: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    venue: row.get(3)?,
                    subject: row.get(4)?,
                    origin: row.get(5)?,
                    confirm: crate::events::ConfirmState::from_column(
                        row.get::<_, Option<String>>(6)?.as_deref(),
                    ),
                    timestamp: row.get(7)?,
                })
            })?
            .collect::<SqlResult<_>>()?;

        // Each task's opener, ahead of that task's follow-ups. In the field it
        // already is — an opener's id is minted before the events that name it
        // — but nothing about sorting by id *guarantees* it, and a follow-up
        // replayed ahead of its opener names a task that does not exist yet
        // and is silently dropped. A stable sort, so mint order survives
        // inside each task; tasks are independent of one another here, so the
        // grouping this imposes across them changes nothing.
        rows.sort_by(|a, b| {
            let key = |r: &Row| {
                let act_id = r.subject.clone().unwrap_or_else(|| r.event_id.clone());
                (act_id, r.subject.is_some())
            };
            key(a).cmp(&key(b))
        });

        let mut live: std::collections::BTreeMap<String, ActTask> =
            std::collections::BTreeMap::new();
        // The bids replayed so far, by the action they were filed against and
        // their own id. This is the rebuild's copy of the lookup ingress does
        // against the log: events come back in id order and a bid is always
        // filed before the award that names it, so by the time an award is
        // replayed its bid is here.
        let mut bids: std::collections::BTreeMap<(String, String), String> =
            std::collections::BTreeMap::new();
        // And each opener's bid cutoff, which ingress reads back out of the
        // opener's bytes. Kept here rather than looked up, because the bytes
        // in question are the ones this replay has already passed.
        let mut bid_deadlines: std::collections::BTreeMap<String, i64> =
            std::collections::BTreeMap::new();
        for row in rows {
            let Some(view) = crate::events::derive_act_view(&row.canonical) else {
                continue;
            };
            // A receipt moves nothing — the event it names did the moving, and
            // is in this same log. A rebuild passes over it exactly as the
            // ingress path does, or replaying the log would try to apply a
            // verb no kind has.
            if freeq_sdk::act_transitions::is_confirmation(&view.verb) {
                continue;
            }
            let act_id = row.subject.clone().unwrap_or_else(|| row.event_id.clone());
            let opens = row.subject.is_none();
            let mut was: Option<String> = None;
            let mut kind = view.kind.clone();
            // The same fact ingress resolves before it asks the checker: who
            // wrote the bid this event names, when it names one.
            let mut named: Option<String> = None;
            let landed = if opens {
                match freeq_sdk::act_transitions::check_open(
                    &view.kind,
                    &view.verb,
                    view.to.is_some(),
                    false,
                ) {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                }
            } else {
                let Some(task) = live.get(&act_id) else {
                    continue;
                };
                // A task another server owns moves on that server's receipts
                // and on nothing else. An event still waiting on one is on
                // file and decides nothing, so a rebuild passes over it
                // exactly as the live path did when it filed it — which is
                // what makes the two agree about a foreign task.
                if !task.origin.is_empty() && row.confirm != crate::events::ConfirmState::Confirmed
                {
                    continue;
                }
                was = Some(task.state.clone());
                kind = task.kind.clone();
                let present: Vec<&str> = view.fields.keys().map(String::as_str).collect();
                let accepts = view.fields.get("act-accepts").map(String::as_str);
                named = accepts
                    .and_then(|id| bids.get(&(act_id.clone(), id.to_string())))
                    .cloned();
                match freeq_sdk::act_transitions::check(
                    &freeq_sdk::act_transitions::Task {
                        kind: &task.kind,
                        state: &task.state,
                        offerer: &task.offerer,
                        offeree: task.offeree.as_deref(),
                        assignee: task.assignee.as_deref(),
                        deadline: task.deadline,
                        bid_deadline: bid_deadlines.get(&act_id).copied(),
                    },
                    &freeq_sdk::act_transitions::Event {
                        verb: &view.verb,
                        msgid: &row.event_id,
                        accepts,
                        fields: &present,
                    },
                    &freeq_sdk::act_transitions::Sender {
                        did: &row.actor,
                        // Read off the actor, never assumed. The log is not a
                        // list of legal moves: an event on a task another
                        // server owns is filed here unruled, so a rebuild that
                        // took every row for pre-checked would let one in. A
                        // server acts under `did:web:`; a person does not.
                        is_system: crate::server::is_system_actor(&row.actor),
                        accepted_bid: named
                            .as_deref()
                            .map(|author| freeq_sdk::act_transitions::AcceptedBid { author }),
                    },
                ) {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                }
            };
            // Filed, so it is one of the action's bids from here on.
            if view.verb == freeq_sdk::act_transitions::BID_VERB {
                bids.insert((act_id.clone(), row.event_id.clone()), row.actor.clone());
            }
            if freeq_sdk::act_transitions::is_terminal(&kind, &landed) {
                live.remove(&act_id);
                continue;
            }
            if opens {
                if let Some(cutoff) = view
                    .fields
                    .get("act-bid-deadline")
                    .and_then(|v| v.parse::<i64>().ok())
                {
                    bid_deadlines.insert(act_id.clone(), cutoff);
                }
                live.insert(
                    act_id.clone(),
                    ActTask {
                        act_id,
                        kind: kind.clone(),
                        venue: row.venue.clone(),
                        origin: row.origin.clone().unwrap_or_default(),
                        state: landed,
                        offerer: row.actor.clone(),
                        offeree: view.to.clone(),
                        assignee: None,
                        caps: view.caps.clone(),
                        deadline: view.deadline,
                        replaces: view.replaces.clone(),
                        updated: row.timestamp,
                    },
                );
            } else if let Some(task) = live.get_mut(&act_id) {
                if task.assignee.is_none() && landed == "assigned" {
                    // The same reading ingress does: who a step assigns is
                    // what the rules file says — the actor unless a row names
                    // a field instead.
                    task.assignee = match freeq_sdk::act_transitions::assignee_source(
                        &kind,
                        &view.verb,
                        was.as_deref().unwrap_or_default(),
                    ) {
                        freeq_sdk::act_transitions::AssigneeSource::Actor => {
                            Some(row.actor.clone())
                        }
                        freeq_sdk::act_transitions::AssigneeSource::AuthorOf(_) => named.clone(),
                        freeq_sdk::act_transitions::AssigneeSource::Field(name) => {
                            view.fields.get(name).cloned()
                        }
                    };
                }
                task.state = landed;
                task.updated = row.timestamp;
            }
        }
        Ok(live.into_values().collect())
    }

    /// A coordination event by id, whatever kind it is.
    pub fn coordination_event(&self, event_id: &str) -> SqlResult<Option<CoordinationEventRow>> {
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

    /// Get all events referencing a task ID.
    pub fn get_task_events(&self, task_id: &str) -> Vec<CoordinationEventRow> {
        self.query_coordination_events("", None, Some(task_id), None, None, 1000)
            .into_iter()
            .collect()
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
            ChatDoc::mutation(
                Mutation::Delete,
                ALICE,
                "01AAAA0000000000000000000F",
                "#room",
                root,
            )
            .canonical(),
            ChatDoc::mutation(
                Mutation::React,
                ALICE,
                "01AAAA0000000000000000000G",
                "#room",
                root,
            )
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
                file(
                    &db,
                    canonical,
                    Some("ed25519:kid:sig"),
                    EventContext::verified(),
                    i as u64
                ),
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
        let canonical =
            ChatDoc::message(ALICE, "01DRIFT000000000000000000A", "#room", "hi").canonical();
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
        assert!(!file(
            &db,
            "{\"nope\":true}",
            None,
            EventContext::default(),
            1
        ));
        assert!(db.all_events().unwrap().is_empty());
    }

    /// A verdict is about a signature. With none on file, nothing has been
    /// concluded — whatever the caller passed.
    #[test]
    fn a_row_with_no_signature_is_unsigned_whatever_the_caller_claimed() {
        let db = Db::open_memory().unwrap();
        let canonical =
            ChatDoc::message(ALICE, "01NOSIG000000000000000000A", "#room", "hi").canonical();
        file(&db, &canonical, None, EventContext::verified(), 1);
        assert_eq!(
            db.get_event("01NOSIG000000000000000000A")
                .unwrap()
                .unwrap()
                .sig_state,
            SigState::Unsigned
        );
    }

    /// A caller that did not check gets the state that claims least — never
    /// `valid` by omission.
    #[test]
    fn a_signature_nobody_checked_files_as_unverifiable() {
        let db = Db::open_memory().unwrap();
        let canonical =
            ChatDoc::message(ALICE, "01UNCHK000000000000000000A", "#room", "hi").canonical();
        file(
            &db,
            &canonical,
            Some("ed25519:kid:sig"),
            EventContext::default(),
            1,
        );
        assert_eq!(
            db.get_event("01UNCHK000000000000000000A")
                .unwrap()
                .unwrap()
                .sig_state,
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
        assert!(
            !file(&db, &second, None, EventContext::default(), 2),
            "first write wins"
        );

        db.record_event_conflict(id, &crate::events::fingerprint(&second))
            .unwrap();
        let row = db.get_event(id).unwrap().unwrap();
        assert_eq!(
            row.canonical, first,
            "the row still holds what arrived first"
        );
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
            file(
                &db,
                &canonical,
                None,
                EventContext::default(),
                i as u64 * 1000,
            );
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
        db.insert_message(
            "#Room",
            "a!u@h",
            "hello",
            10,
            &HashMap::new(),
            Some("M1"),
            Some(ALICE),
        )
        .unwrap();
        db.insert_message(
            "#Room",
            "g!u@h",
            "guest here",
            11,
            &HashMap::new(),
            Some("M2"),
            None,
        )
        .unwrap();
        db.insert_edit(
            "#Room",
            "a!u@h",
            "revised",
            12,
            &HashMap::new(),
            "M3",
            "M1",
            Some(ALICE),
        )
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
        assert_eq!(
            (edit.kind.as_str(), edit.subject.as_deref()),
            ("edit", Some("M1"))
        );
    }

    /// The log holds hashes, never bodies. A table that quietly accumulated a
    /// second copy of every private message would be a liability.
    #[test]
    fn no_body_ever_reaches_the_log() {
        let db = Db::open_memory().unwrap();
        let secret = "the passphrase is hunter2";
        db.insert_message(
            "#Room",
            "a!u@h",
            secret,
            10,
            &HashMap::new(),
            Some("M1"),
            Some(ALICE),
        )
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
            db.get_event("M1")
                .unwrap()
                .unwrap()
                .canonical
                .contains("sha256:"),
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
                ..Default::default()
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
        assert!(
            db.insert_message(
                "#Room",
                "a!u@h",
                "what I said",
                10,
                &HashMap::new(),
                Some("M1"),
                Some(ALICE)
            )
            .unwrap()
        );
        assert!(
            !db.insert_message(
                "#Room",
                "a!u@h",
                "what they claim",
                11,
                &HashMap::new(),
                Some("M1"),
                Some(ALICE)
            )
            .unwrap()
        );

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
        db2.insert_message(
            "#Room",
            "a!u@h",
            "same",
            10,
            &HashMap::new(),
            Some("M9"),
            Some(ALICE),
        )
        .unwrap();
        db2.insert_message(
            "#Room",
            "a!u@h",
            "same",
            10,
            &HashMap::new(),
            Some("M9"),
            Some(ALICE),
        )
        .unwrap();
        assert_eq!(db2.get_event("M9").unwrap().unwrap().conflict, None);
    }

    /// The message row and its event are one write. A message that reached
    /// history with no event would be a hole nothing later could distinguish
    /// from a message that never happened.
    #[test]
    fn the_pair_is_written_together_or_not_at_all() {
        let db = Db::open_memory().unwrap();
        db.insert_message(
            "#Room",
            "a!u@h",
            "hi",
            10,
            &HashMap::new(),
            Some("M1"),
            Some(ALICE),
        )
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
        db.insert_message(
            "#Room",
            "a!u@h",
            "different",
            11,
            &HashMap::new(),
            Some("M1"),
            Some(ALICE),
        )
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
            db.insert_message(
                "#Room",
                "a!u@h",
                "same body",
                10,
                &HashMap::new(),
                Some("M1"),
                Some(ALICE),
            )
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
    let digest =
        freeq_sdk::chatsig::body_hash(&format!("{verb}\u{0}{channel}\u{0}{msgid}\u{0}{at}"));
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
