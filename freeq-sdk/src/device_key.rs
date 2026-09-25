//! A device's own signing key, kept across connects, and publishing it to the
//! account.
//!
//! Without a store the client mints a fresh session key on every connect.
//! With one, the device presents the same key every time, so it can be
//! published once as an `at.freeq.deviceKey` record. The client app supplies
//! the store (a file, the Keychain, the Android Keystore) and the write
//! (`Enrollment`), since only the app holds a session that can write to the
//! account; the SDK decides when to call it.

use crate::identity_records::DeviceKeyRecord;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

/// The device key as a store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeviceKey {
    /// The ed25519 private key's 32-byte seed.
    pub seed: [u8; 32],
    /// When the key was made, RFC 3339; the published record carries it.
    pub created_at: String,
    /// The `at://` URI of the record that publishes the key, once written.
    pub record_uri: Option<String>,
    /// The server refused the key as expired (`FAIL MSGSIG KEY_EXPIRED`):
    /// the next fresh sign-in replaces it without reading the account.
    pub refused: bool,
}

/// Where a device keeps its signing keys between connects: one per account,
/// named by the signed-in DID. The client reads it only once SASL has named
/// the account.
pub trait DeviceKeyStore: Send + Sync {
    /// `did`'s key on this device, or `None` when it has none yet.
    fn load(&self, did: &str) -> Result<Option<StoredDeviceKey>>;
    /// Replace `did`'s key on this device.
    fn save(&self, did: &str, key: &StoredDeviceKey) -> Result<()>;
}

/// A bot's store: the ed25519 key its did:key names, handed back for every
/// sign-in, so the bot signs with the one key its DID already is and keeps
/// one key row on each server. A save is kept in memory for the process's
/// life. Without an [`Enrollment`] nothing is published.
///
/// Twin of bot-kit's `MemoryDeviceKeyStore` over `importDidKeyPair(seed)`.
pub struct DidKeyDeviceKeyStore {
    key: std::sync::Mutex<StoredDeviceKey>,
}

impl DidKeyDeviceKeyStore {
    /// The store for `key` when `did` is that ed25519 key's own did:key;
    /// `None` for any other DID or a secp256k1 key.
    pub fn for_did_key(
        did: &str,
        key: &crate::crypto::PrivateKey,
    ) -> Option<std::sync::Arc<dyn DeviceKeyStore>> {
        let crate::crypto::PrivateKey::Ed25519(signing) = key else {
            return None;
        };
        if did != format!("did:key:{}", key.public_key_multibase()) {
            return None;
        }
        let stored = StoredDeviceKey {
            seed: signing.to_bytes(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            record_uri: None,
            refused: false,
        };
        Some(std::sync::Arc::new(Self {
            key: std::sync::Mutex::new(stored),
        }))
    }
}

impl DeviceKeyStore for DidKeyDeviceKeyStore {
    fn load(&self, _did: &str) -> Result<Option<StoredDeviceKey>> {
        Ok(Some(
            self.key
                .lock()
                .map_err(|_| anyhow::anyhow!("did:key store poisoned"))?
                .clone(),
        ))
    }

    fn save(&self, _did: &str, key: &StoredDeviceKey) -> Result<()> {
        *self
            .key
            .lock()
            .map_err(|_| anyhow::anyhow!("did:key store poisoned"))? = key.clone();
        Ok(())
    }
}

/// What publishing a device key came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// The record was written; `uri` names it.
    Published { uri: String },
    /// The app's session cannot write the record; the user has to sign in
    /// again with the grant.
    NeedsSignIn,
    /// Anything else. Tried again on the next connect.
    Failed(String),
}

/// Writes a device key record to the account. Supplied by the client app.
pub trait Enrollment: Send + Sync {
    fn publish(
        &self,
        record: DeviceKeyRecord,
        signer_public_key: String,
    ) -> Pin<Box<dyn Future<Output = EnrollOutcome> + Send>>;
}

/// The file form: the seed as base64url, as the session file keeps its
/// DPoP key.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    seed: String,
    created_at: String,
    #[serde(default)]
    record_uri: Option<String>,
    /// Absent in a file from before the flag, which reads as not refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    refused: bool,
}

/// A [`DeviceKeyStore`] in one JSON file, readable by its owner only. The
/// file holds one key, whatever DID asks: its owner gives each sign-in its
/// own path.
pub struct FileDeviceKeyStore {
    path: PathBuf,
}

impl FileDeviceKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl DeviceKeyStore for FileDeviceKeyStore {
    fn load(&self, _did: &str) -> Result<Option<StoredDeviceKey>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading the device key file"),
        };
        let file: KeyFile = serde_json::from_str(&text).context("device key file is not JSON")?;
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&file.seed)
            .context("device key seed is not base64url")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("device key seed is not 32 bytes"))?;
        Ok(Some(StoredDeviceKey {
            seed,
            created_at: file.created_at,
            record_uri: file.record_uri,
            refused: file.refused,
        }))
    }

    fn save(&self, _did: &str, key: &StoredDeviceKey) -> Result<()> {
        let json = serde_json::to_string_pretty(&KeyFile {
            seed: URL_SAFE_NO_PAD.encode(key.seed),
            created_at: key.created_at.clone(),
            record_uri: key.record_uri.clone(),
            refused: key.refused,
        })?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        // A file made before this code, or by hand, keeps its old mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        std::io::Write::write_all(&mut file, json.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:alice";

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("freeq-device-key-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("nested").join("device-key.json")
    }

    #[test]
    fn a_missing_file_holds_no_key() {
        let store = FileDeviceKeyStore::new(temp_path("missing"));
        assert_eq!(store.load(DID).unwrap(), None);
    }

    #[test]
    fn the_file_store_round_trips() {
        let path = temp_path("round-trip");
        let store = FileDeviceKeyStore::new(&path);
        let key = StoredDeviceKey {
            seed: [7; 32],
            created_at: "2026-09-11T10:00:00.000Z".to_string(),
            record_uri: None,
            refused: false,
        };
        store.save(DID, &key).unwrap();
        assert_eq!(store.load(DID).unwrap(), Some(key.clone()));

        let published = StoredDeviceKey {
            record_uri: Some("at://did:plc:alice/at.freeq.deviceKey/3k".to_string()),
            ..key
        };
        store.save(DID, &published).unwrap();
        assert_eq!(
            FileDeviceKeyStore::new(&path).load(DID).unwrap(),
            Some(published)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A file that already exists with a wide mode is narrowed on save.
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let store = FileDeviceKeyStore::new(&path);
        store
            .save(
                DID,
                &StoredDeviceKey {
                    seed: [1; 32],
                    created_at: "2026-09-11T10:00:00.000Z".to_string(),
                    record_uri: None,
                    refused: false,
                },
            )
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let fresh = temp_path("mode-fresh");
        FileDeviceKeyStore::new(&fresh)
            .save(
                DID,
                &StoredDeviceKey {
                    seed: [2; 32],
                    created_at: "2026-09-11T10:00:00.000Z".to_string(),
                    record_uri: None,
                    refused: false,
                },
            )
            .unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
        let _ = std::fs::remove_dir_all(fresh.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn a_seed_of_the_wrong_length_is_an_error() {
        let path = temp_path("short");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"seed":"AAAA","created_at":"2026-09-11T10:00:00.000Z"}"#,
        )
        .unwrap();
        assert!(FileDeviceKeyStore::new(&path).load(DID).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn keeps_a_refused_keys_flag_through_a_save_and_a_load() {
        let path = temp_path("refused");
        let store = FileDeviceKeyStore::new(&path);
        let key = StoredDeviceKey {
            seed: [3; 32],
            created_at: "2026-09-11T10:00:00.000Z".to_string(),
            record_uri: Some("at://did:plc:alice/at.freeq.deviceKey/3k".to_string()),
            refused: true,
        };
        store.save(DID, &key).unwrap();
        assert_eq!(FileDeviceKeyStore::new(&path).load(DID).unwrap(), Some(key));
    }

    #[test]
    fn a_file_from_before_the_flag_reads_as_not_refused() {
        let path = temp_path("before-refused");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!(
                r#"{{"seed":"{}","created_at":"2026-09-11T10:00:00.000Z","record_uri":null}}"#,
                URL_SAFE_NO_PAD.encode([4u8; 32])
            ),
        )
        .unwrap();
        let loaded = FileDeviceKeyStore::new(&path).load(DID).unwrap().unwrap();
        assert!(!loaded.refused);
        assert_eq!(loaded.seed, [4; 32]);
    }
}
