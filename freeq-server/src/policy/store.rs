//! Database storage for policy framework objects.
//!
//! Uses SQLite (via rusqlite) alongside the existing IRC database.
//!
//! # Channel-key normalization
//!
//! Channel names are case-insensitive in IRC (`#Foo` == `#foo`), but callers
//! reach this store through paths with different casing conventions (the IRC
//! JOIN gate uses the raw user-typed name, the REST API lowercases, S2S
//! passes whatever the origin used). Every method that takes a `channel_id`
//! therefore normalizes it with [`canonical_channel_id`] — both for the key
//! column and, on writes, for the `channel_id` field embedded in the stored
//! document *before* hashing, so content hashes are computed over the
//! canonical form. `migrate()` lowercases the key columns of any
//! pre-normalization rows so old databases stay reachable.

use super::canonical;
use super::types::*;
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};

/// Canonical key for a channel: IRC channel names are case-insensitive, so
/// all channel-keyed rows are stored and queried under the lowercased name.
pub(crate) fn canonical_channel_id(channel: &str) -> String {
    channel.trim().to_lowercase()
}

pub struct PolicyStore {
    db: Mutex<Connection>,
}

impl PolicyStore {
    /// Open or create the policy database.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let store = PolicyStore {
            db: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                effective_at TEXT NOT NULL,
                previous_policy_hash TEXT,
                authority_set_hash TEXT NOT NULL,
                document_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(channel_id, version)
            );

            CREATE INDEX IF NOT EXISTS idx_policies_channel ON policies(channel_id);

            CREATE TABLE IF NOT EXISTS authority_sets (
                authority_set_hash TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                document_json TEXT NOT NULL,
                previous_authority_set_hash TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_authority_sets_channel ON authority_sets(channel_id);

            CREATE TABLE IF NOT EXISTS join_receipts (
                join_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'JOIN_PENDING',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_join_receipts_channel ON join_receipts(channel_id);
            CREATE INDEX IF NOT EXISTS idx_join_receipts_did ON join_receipts(subject_did);

            CREATE TABLE IF NOT EXISTS membership_attestations (
                attestation_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                authority_set_hash TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                role TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                join_id TEXT,
                issuer_did TEXT NOT NULL,
                attestation_json TEXT NOT NULL,
                attestation_hash TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'VALID',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_attestations_channel ON membership_attestations(channel_id);
            CREATE INDEX IF NOT EXISTS idx_attestations_did ON membership_attestations(subject_did);
            CREATE INDEX IF NOT EXISTS idx_attestations_channel_did ON membership_attestations(channel_id, subject_did);

            CREATE TABLE IF NOT EXISTS transparency_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_version INTEGER NOT NULL DEFAULT 1,
                channel_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                attestation_hash TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                issuer_authority_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_tlog_channel ON transparency_log(channel_id);

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_did TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                issuer TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                issued_at TEXT NOT NULL DEFAULT (datetime('now')),
                revoked INTEGER NOT NULL DEFAULT 0,
                UNIQUE(subject_did, credential_type, issuer)
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_did ON credentials(subject_did);

            CREATE TABLE IF NOT EXISTS signed_tree_heads (
                log_id TEXT NOT NULL,
                tree_size INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (log_id, tree_size)
            );

            -- Human-readable rules text, content-addressed by its sha256 hash.
            -- The hash remains the source of truth for verification (stored in
            -- the policy's ACCEPT requirement); this table is auxiliary, letting
            -- clients read back the plaintext an op typed at SET time. Identical
            -- rules dedupe naturally since the hash is the primary key.
            CREATE TABLE IF NOT EXISTS rules_texts (
                rules_hash TEXT PRIMARY KEY,
                rules_text TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;
        self.migrate_lowercase_channel_ids(&db)?;
        Ok(())
    }

    /// Lowercase the `channel_id` key columns of rows written before
    /// channel-key normalization existed. Idempotent (no-op when everything
    /// is already lowercase), so it runs on every open.
    ///
    /// Only the key columns are rewritten — the embedded document JSON keeps
    /// its original `channel_id`, since rewriting it would invalidate the
    /// stored content hashes and attestation HMAC signatures. Lookups are by
    /// key column, so old rows become reachable again under any casing.
    ///
    /// `policies` has UNIQUE(channel_id, version): `UPDATE OR REPLACE` drops
    /// the losing row if two casings of the same channel+version collide
    /// (shouldn't happen in practice; logged if it does).
    fn migrate_lowercase_channel_ids(&self, db: &Connection) -> Result<(), rusqlite::Error> {
        let mut total = db.execute(
            "UPDATE OR REPLACE policies SET channel_id = LOWER(channel_id)
             WHERE channel_id <> LOWER(channel_id)",
            [],
        )?;
        for table in [
            "authority_sets",
            "join_receipts",
            "membership_attestations",
            "transparency_log",
        ] {
            total += db.execute(
                &format!(
                    "UPDATE {table} SET channel_id = LOWER(channel_id)
                     WHERE channel_id <> LOWER(channel_id)"
                ),
                [],
            )?;
        }
        if total > 0 {
            tracing::info!(
                rows = total,
                "policy store: lowercased legacy mixed-case channel keys"
            );
        }
        Ok(())
    }

    // ─── Policy Documents ────────────────────────────────────────────────

    /// Store a policy document. Computes policy_id from JCS hash.
    pub fn store_policy(&self, mut policy: PolicyDocument) -> Result<PolicyDocument, PolicyError> {
        // Normalize BEFORE hashing so content hashes are casing-independent
        // and all federation peers compute the same policy_id.
        policy.channel_id = canonical_channel_id(&policy.channel_id);
        // Compute policy_id by hashing the document without the policy_id field
        policy.policy_id = None;
        let policy_id = canonical::hash_canonical(&policy)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;
        policy.policy_id = Some(policy_id.clone());

        let json = serde_json::to_string(&policy)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;

        let db = self.db.lock();
        db.execute(
            "INSERT INTO policies (policy_id, channel_id, version, effective_at, previous_policy_hash, authority_set_hash, document_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                policy_id,
                policy.channel_id,
                policy.version,
                policy.effective_at,
                policy.previous_policy_hash,
                policy.authority_set_hash,
                json,
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        Ok(policy)
    }

    /// Get the current (latest version) policy for a channel.
    pub fn get_current_policy(
        &self,
        channel_id: &str,
    ) -> Result<Option<PolicyDocument>, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let json: Option<String> = db
            .query_row(
                "SELECT document_json FROM policies WHERE channel_id = ?1 ORDER BY version DESC LIMIT 1",
                params![channel_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        match json {
            Some(j) => {
                let doc: PolicyDocument = serde_json::from_str(&j)
                    .map_err(|e| PolicyError::Serialization(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Get a policy by its hash.
    pub fn get_policy_by_hash(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyDocument>, PolicyError> {
        let db = self.db.lock();
        let json: Option<String> = db
            .query_row(
                "SELECT document_json FROM policies WHERE policy_id = ?1",
                params![policy_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        match json {
            Some(j) => {
                let doc: PolicyDocument = serde_json::from_str(&j)
                    .map_err(|e| PolicyError::Serialization(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Get all policy versions for a channel, oldest first.
    pub fn get_policy_chain(&self, channel_id: &str) -> Result<Vec<PolicyDocument>, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let mut stmt = db
            .prepare(
                "SELECT document_json FROM policies WHERE channel_id = ?1 ORDER BY version ASC",
            )
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        let docs = stmt
            .query_map(params![channel_id], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(|e| PolicyError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .filter_map(|j| serde_json::from_str::<PolicyDocument>(&j).ok())
            .collect();

        Ok(docs)
    }

    // ─── Authority Sets ──────────────────────────────────────────────────

    /// Store an authority set. Computes hash from JCS.
    pub fn store_authority_set(
        &self,
        mut auth_set: AuthoritySet,
    ) -> Result<AuthoritySet, PolicyError> {
        auth_set.channel_id = canonical_channel_id(&auth_set.channel_id);
        auth_set.authority_set_hash = None;
        let hash = canonical::hash_canonical(&auth_set)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;
        auth_set.authority_set_hash = Some(hash.clone());

        let json = serde_json::to_string(&auth_set)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;

        let db = self.db.lock();
        db.execute(
            "INSERT OR IGNORE INTO authority_sets (authority_set_hash, channel_id, document_json, previous_authority_set_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                hash,
                auth_set.channel_id,
                json,
                auth_set.previous_authority_set_hash,
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        Ok(auth_set)
    }

    /// Get an authority set by its hash.
    pub fn get_authority_set(&self, hash: &str) -> Result<Option<AuthoritySet>, PolicyError> {
        let db = self.db.lock();
        let json: Option<String> = db
            .query_row(
                "SELECT document_json FROM authority_sets WHERE authority_set_hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        match json {
            Some(j) => {
                let doc: AuthoritySet = serde_json::from_str(&j)
                    .map_err(|e| PolicyError::Serialization(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    // ─── Rules Text ──────────────────────────────────────────────────────

    /// Store the human-readable rules text keyed by its sha256 hash.
    /// Content-addressed, so identical rules dedupe (INSERT OR IGNORE).
    /// Auxiliary to the hash, which stays the verification source of truth.
    pub fn store_rules_text(&self, hash: &str, text: &str) -> Result<(), PolicyError> {
        let db = self.db.lock();
        db.execute(
            "INSERT OR IGNORE INTO rules_texts (rules_hash, rules_text) VALUES (?1, ?2)",
            params![hash, text],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get the human-readable rules text for a given hash, if stored.
    /// Returns None for hashes with no stored text (e.g. legacy policies set
    /// before rules text was persisted, or policies received over S2S which
    /// only carry the hash).
    pub fn get_rules_text(&self, hash: &str) -> Result<Option<String>, PolicyError> {
        let db = self.db.lock();
        let text: Option<String> = db
            .query_row(
                "SELECT rules_text FROM rules_texts WHERE rules_hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;
        Ok(text)
    }

    // ─── Join Receipts ───────────────────────────────────────────────────

    /// Store a join receipt.
    pub fn store_join_receipt(&self, receipt: &JoinReceipt) -> Result<(), PolicyError> {
        let mut receipt = receipt.clone();
        receipt.channel_id = canonical_channel_id(&receipt.channel_id);
        let json = serde_json::to_string(&receipt)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;

        let db = self.db.lock();
        db.execute(
            "INSERT OR REPLACE INTO join_receipts (join_id, channel_id, policy_id, subject_did, receipt_json, state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'JOIN_PENDING', datetime('now'))",
            params![
                receipt.join_id,
                receipt.channel_id,
                receipt.policy_id,
                receipt.subject_did,
                json,
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update join state.
    pub fn update_join_state(&self, join_id: &str, state: JoinState) -> Result<(), PolicyError> {
        let state_str = serde_json::to_value(state)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?
            .as_str()
            .unwrap_or("JOIN_FAILED")
            .to_string();

        let db = self.db.lock();
        db.execute(
            "UPDATE join_receipts SET state = ?1, updated_at = datetime('now') WHERE join_id = ?2",
            params![state_str, join_id],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get a join receipt by join_id.
    pub fn get_join_receipt(&self, join_id: &str) -> Result<Option<JoinReceipt>, PolicyError> {
        let db = self.db.lock();
        let json: Option<String> = db
            .query_row(
                "SELECT receipt_json FROM join_receipts WHERE join_id = ?1",
                params![join_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        match json {
            Some(j) => {
                let doc: JoinReceipt = serde_json::from_str(&j)
                    .map_err(|e| PolicyError::Serialization(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    // ─── Membership Attestations ─────────────────────────────────────────

    /// Store a membership attestation and add to transparency log.
    pub fn store_attestation(
        &self,
        attestation: &MembershipAttestation,
    ) -> Result<(), PolicyError> {
        // Normalization is a no-op for engine-produced attestations (the
        // engine canonicalizes before signing, so the HMAC stays valid);
        // it matters for any direct store callers.
        let mut attestation = attestation.clone();
        attestation.channel_id = canonical_channel_id(&attestation.channel_id);
        let attestation = &attestation;
        let json = serde_json::to_string(attestation)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;
        let attestation_hash = canonical::hash_canonical(attestation)
            .map_err(|e| PolicyError::Serialization(e.to_string()))?;

        let db = self.db.lock();

        // Store attestation
        db.execute(
            "INSERT INTO membership_attestations
             (attestation_id, channel_id, policy_id, authority_set_hash, subject_did, role, issued_at, expires_at, join_id, issuer_did, attestation_json, attestation_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                attestation.attestation_id,
                attestation.channel_id,
                attestation.policy_id,
                attestation.authority_set_hash,
                attestation.subject_did,
                attestation.role,
                attestation.issued_at,
                attestation.expires_at,
                attestation.join_id,
                attestation.issuer_did,
                json,
                attestation_hash,
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        // Add to transparency log
        db.execute(
            "INSERT INTO transparency_log (entry_version, channel_id, policy_id, attestation_hash, issued_at, issuer_authority_id)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                attestation.channel_id,
                attestation.policy_id,
                attestation_hash,
                attestation.issued_at,
                attestation.issuer_did,
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get the current valid attestation for a user in a channel.
    pub fn get_attestation(
        &self,
        channel_id: &str,
        subject_did: &str,
    ) -> Result<Option<MembershipAttestation>, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let json: Option<String> = db
            .query_row(
                "SELECT attestation_json FROM membership_attestations
                 WHERE channel_id = ?1 AND subject_did = ?2 AND state = 'VALID'
                 ORDER BY issued_at DESC LIMIT 1",
                params![channel_id, subject_did],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        match json {
            Some(j) => {
                let doc: MembershipAttestation = serde_json::from_str(&j)
                    .map_err(|e| PolicyError::Serialization(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Get all valid members of a channel.
    pub fn get_channel_members(
        &self,
        channel_id: &str,
    ) -> Result<Vec<MembershipAttestation>, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let mut stmt = db
            .prepare(
                "SELECT attestation_json FROM membership_attestations
                 WHERE channel_id = ?1 AND state = 'VALID'
                 ORDER BY issued_at ASC",
            )
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        let members = stmt
            .query_map(params![channel_id], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(|e| PolicyError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .filter_map(|j| serde_json::from_str::<MembershipAttestation>(&j).ok())
            .collect();

        Ok(members)
    }

    /// Get expired attestations (continuous validity model, past their expires_at).
    pub fn get_expired_attestations(&self) -> Result<Vec<MembershipAttestation>, PolicyError> {
        let db = self.db.lock();
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = db
            .prepare(
                "SELECT attestation_json FROM membership_attestations
                 WHERE state = 'VALID' AND expires_at IS NOT NULL AND expires_at < ?1",
            )
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        let expired = stmt
            .query_map(params![now], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(|e| PolicyError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .filter_map(|j| serde_json::from_str::<MembershipAttestation>(&j).ok())
            .collect();

        Ok(expired)
    }

    /// Mark an attestation as invalid (expired/revoked).
    pub fn invalidate_attestation(&self, attestation_id: &str) -> Result<(), PolicyError> {
        let db = self.db.lock();
        db.execute(
            "UPDATE membership_attestations SET state = 'INVALID' WHERE attestation_id = ?1",
            params![attestation_id],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;
        Ok(())
    }

    // ─── Policy Removal ────────────────────────────────────────────────

    /// Remove all policy data for a channel.
    /// Returns true if anything was removed.
    pub fn remove_channel_policy(&self, channel_id: &str) -> Result<bool, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let total: usize = [
            "policies",
            "membership_attestations",
            "join_receipts",
            "transparency_log",
        ]
        .iter()
        .map(|table| {
            db.execute(
                &format!("DELETE FROM {} WHERE channel_id = ?1", table),
                params![channel_id],
            )
            .unwrap_or(0)
        })
        .sum();
        Ok(total > 0)
    }

    /// Distinct channel IDs that have at least one policy version stored.
    pub fn list_policy_channels(&self) -> Result<Vec<String>, PolicyError> {
        let db = self.db.lock();
        let mut stmt = db
            .prepare("SELECT DISTINCT channel_id FROM policies")
            .map_err(|e| PolicyError::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| PolicyError::Database(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| PolicyError::Database(e.to_string()))?);
        }
        Ok(out)
    }

    // ─── Transparency Log ────────────────────────────────────────────────

    /// Get transparency log entries for a channel.
    pub fn get_log_entries(
        &self,
        channel_id: &str,
        since: Option<i64>,
    ) -> Result<Vec<TransparencyLogEntry>, PolicyError> {
        let channel_id = canonical_channel_id(channel_id);
        let db = self.db.lock();
        let mut stmt = db
            .prepare(
                "SELECT entry_version, channel_id, policy_id, attestation_hash, issued_at, issuer_authority_id
                 FROM transparency_log
                 WHERE channel_id = ?1 AND id > ?2
                 ORDER BY id ASC",
            )
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        let entries = stmt
            .query_map(params![channel_id, since.unwrap_or(0)], |row| {
                Ok(TransparencyLogEntry {
                    entry_version: row.get(0)?,
                    channel_id: row.get(1)?,
                    policy_id: row.get(2)?,
                    attestation_hash: row.get(3)?,
                    issued_at: row.get(4)?,
                    issuer_authority_id: row.get(5)?,
                })
            })
            .map_err(|e| PolicyError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }
    // ─── Credentials ───────────────────────────────────────────────────

    /// Store a verified credential for a user.
    /// Upserts (replaces if same did+type+issuer exists).
    pub fn store_credential(
        &self,
        subject_did: &str,
        credential_type: &str,
        issuer: &str,
        metadata: &serde_json::Value,
    ) -> Result<(), PolicyError> {
        let db = self.db.lock();
        db.execute(
            "INSERT INTO credentials (subject_did, credential_type, issuer, metadata_json, issued_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))
             ON CONFLICT(subject_did, credential_type, issuer)
             DO UPDATE SET metadata_json = ?4, issued_at = datetime('now'), revoked = 0",
            params![
                subject_did,
                credential_type,
                issuer,
                serde_json::to_string(metadata).unwrap_or_default(),
            ],
        )
        .map_err(|e| PolicyError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get all valid (non-revoked) credentials for a user.
    pub fn get_credentials(&self, subject_did: &str) -> Result<Vec<StoredCredential>, PolicyError> {
        let db = self.db.lock();
        let mut stmt = db
            .prepare(
                "SELECT credential_type, issuer, metadata_json, issued_at
                 FROM credentials
                 WHERE subject_did = ?1 AND revoked = 0",
            )
            .map_err(|e| PolicyError::Database(e.to_string()))?;

        let creds = stmt
            .query_map(params![subject_did], |row| {
                Ok(StoredCredential {
                    credential_type: row.get(0)?,
                    issuer: row.get(1)?,
                    metadata_json: row.get(2)?,
                    issued_at: row.get(3)?,
                })
            })
            .map_err(|e| PolicyError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(creds)
    }

    /// Revoke a credential.
    pub fn revoke_credential(
        &self,
        subject_did: &str,
        credential_type: &str,
        issuer: &str,
    ) -> Result<bool, PolicyError> {
        let db = self.db.lock();
        let n = db.execute(
            "UPDATE credentials SET revoked = 1 WHERE subject_did = ?1 AND credential_type = ?2 AND issuer = ?3",
            params![subject_did, credential_type, issuer],
        ).map_err(|e| PolicyError::Database(e.to_string()))?;
        Ok(n > 0)
    }
}

/// A stored credential from the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCredential {
    pub credential_type: String,
    pub issuer: String,
    pub metadata_json: String,
    pub issued_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_store() -> PolicyStore {
        PolicyStore::open(":memory:").unwrap()
    }

    fn make_policy(channel: &str, version: i64, previous: Option<String>) -> PolicyDocument {
        PolicyDocument {
            channel_id: channel.to_string(),
            policy_id: None,
            version,
            effective_at: "2026-01-01T00:00:00Z".to_string(),
            previous_policy_hash: previous,
            authority_set_hash: "authhash".to_string(),
            requirements: Requirement::Accept {
                hash: "deadbeef".to_string(),
            },
            role_requirements: BTreeMap::new(),
            validity_model: ValidityModel::JoinTime,
            receipt_embedding: ReceiptEmbedding::Require,
            policy_locations: vec![],
            limits: None,
            transparency: None,
            credential_endpoints: BTreeMap::new(),
            agent_budget: None,
            agent_budgets: BTreeMap::new(),
        }
    }

    #[test]
    fn policy_lookup_is_case_insensitive() {
        let store = test_store();
        let stored = store.store_policy(make_policy("#FooBar", 1, None)).unwrap();
        // Stored document is canonicalized (lowercase) BEFORE hashing.
        assert_eq!(stored.channel_id, "#foobar");

        for q in ["#foobar", "#FooBar", "#FOOBAR"] {
            let p = store.get_current_policy(q).unwrap().expect("policy found");
            assert_eq!(p.policy_id, stored.policy_id);
        }
    }

    #[test]
    fn versions_chain_across_casings() {
        let store = test_store();
        let v1 = store.store_policy(make_policy("#Chan", 1, None)).unwrap();
        // v2 set with a different casing must land on the same logical channel.
        let v2 = store
            .store_policy(make_policy("#CHAN", 2, v1.policy_id.clone()))
            .unwrap();

        let current = store.get_current_policy("#chan").unwrap().unwrap();
        assert_eq!(current.version, 2);
        assert_eq!(current.policy_id, v2.policy_id);
        assert_eq!(current.previous_policy_hash, v1.policy_id);

        let chain = store.get_policy_chain("#cHaN").unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].version, 1);
        assert_eq!(chain[1].version, 2);
    }

    #[test]
    fn remove_policy_is_case_insensitive() {
        let store = test_store();
        store.store_policy(make_policy("#Gone", 1, None)).unwrap();
        assert!(store.remove_channel_policy("#GONE").unwrap());
        assert!(store.get_current_policy("#gone").unwrap().is_none());
    }

    #[test]
    fn attestation_lookup_is_case_insensitive() {
        let store = test_store();
        let att = MembershipAttestation {
            attestation_id: "att1".into(),
            channel_id: "#MixedCase".into(),
            policy_id: "p1".into(),
            authority_set_hash: "a1".into(),
            subject_did: "did:plc:u1".into(),
            role: "member".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
            join_id: Some("j1".into()),
            signature: "sig".into(),
            issuer_did: "did:plc:issuer".into(),
        };
        store.store_attestation(&att).unwrap();

        for q in ["#mixedcase", "#MixedCase", "#MIXEDCASE"] {
            assert!(
                store.get_attestation(q, "did:plc:u1").unwrap().is_some(),
                "attestation found via {q}"
            );
        }
        let members = store.get_channel_members("#MIXEDCASE").unwrap();
        assert_eq!(members.len(), 1);
        // Transparency log is keyed the same way.
        let log = store.get_log_entries("#MixedCase", None).unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn legacy_mixed_case_rows_are_migrated() {
        // Simulate a pre-normalization database: rows whose channel_id key
        // column is mixed-case. The migration at open() lowercases the key
        // columns (leaving embedded JSON untouched).
        let store = test_store();
        {
            let db = store.db.lock();
            db.execute(
                "INSERT INTO policies (policy_id, channel_id, version, effective_at, previous_policy_hash, authority_set_hash, document_json)
                 VALUES ('legacyhash', '#LegacyChan', 1, '2025-01-01T00:00:00Z', NULL, 'ah', '{}')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO transparency_log (entry_version, channel_id, policy_id, attestation_hash, issued_at, issuer_authority_id)
                 VALUES (1, '#LegacyChan', 'legacyhash', 'ath', '2025-01-01T00:00:00Z', 'did:plc:x')",
                [],
            )
            .unwrap();
        }
        // Run the migration step directly (open() already ran it as a no-op).
        {
            let db = store.db.lock();
            store.migrate_lowercase_channel_ids(&db).unwrap();
        }
        // Reachable under the lowercase key now. (document_json is the legacy
        // '{}' — deserialization would fail, so check the key column directly.)
        {
            let db = store.db.lock();
            let key: String = db
                .query_row(
                    "SELECT channel_id FROM policies WHERE policy_id = 'legacyhash'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(key, "#legacychan");
            let log_key: String = db
                .query_row(
                    "SELECT channel_id FROM transparency_log WHERE policy_id = 'legacyhash'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(log_key, "#legacychan");
        }
        // And get_log_entries (which selects by the key column) finds it.
        let log = store.get_log_entries("#legacychan", None).unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn list_policy_channels() {
        let store = test_store();
        store.store_policy(make_policy("#A", 1, None)).unwrap();
        store.store_policy(make_policy("#b", 1, None)).unwrap();
        let mut channels = store.list_policy_channels().unwrap();
        channels.sort();
        assert_eq!(channels, vec!["#a".to_string(), "#b".to_string()]);
    }
}
