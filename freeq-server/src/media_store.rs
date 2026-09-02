//! Private media storage.
//!
//! Media uploaded to a channel or DM is **private by default**: the bytes are
//! stored encrypted-at-rest on the freeq server's local disk (never on the
//! public PDS blob store) and served only through signed *capability URLs*.
//!
//! A capability URL has the shape
//! `{origin}/api/v1/media/{id}/{sig}/{filename}` where `sig` is an HMAC-SHA256
//! tag over `id`. The signature is unforgeable without the server's media key,
//! so possession of a valid URL — which only reaches members of the
//! conversation it was posted to — is the access grant. The URL is
//! non-expiring so CHATHISTORY replay of old messages keeps rendering.
//!
//! Bytes at rest are encrypted with AES-256-GCM (same primitive the DB uses).
//! The 10 MB upload cap keeps whole-file decrypt-in-memory cheap, which lets
//! the serving path support HTTP Range requests without a streaming cipher.

use std::path::{Path, PathBuf};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Cap on media size.
/// Whole files are decrypted in memory, which is what keeps this modest.
pub const MAX_MEDIA_BYTES: usize = 10 * 1024 * 1024;

/// Derive a 32-byte key for `domain` from the server signing seed.
/// Mirrors `server::derive_key_from_signing` but with per-use domain separation.
fn derive(signing_seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(signing_seed).expect("HMAC accepts any key length");
    mac.update(domain);
    let mut key = [0u8; 32];
    key.copy_from_slice(&mac.finalize().into_bytes());
    key
}

/// Derive the AES-256-GCM key used to encrypt stored media blobs at rest.
pub fn derive_enc_key(signing_seed: &[u8; 32]) -> [u8; 32] {
    derive(signing_seed, b"freeq-media-encryption-v1")
}

/// Derive the HMAC key used to sign media capability URLs.
pub fn derive_cap_key(signing_seed: &[u8; 32]) -> [u8; 32] {
    derive(signing_seed, b"freeq-media-cap-v1")
}

/// Generate an opaque, unguessable media id (128 bits, base64url).
pub fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Sanitize a client-supplied filename for use as the trailing URL segment.
/// Keeps the basename's alphanumerics plus `.`, `-`, `_`; everything else
/// becomes `_`. Never returns an empty string.
pub fn sanitize_filename(name: &str) -> String {
    // Drop any path components a client may have smuggled in.
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    }
}

/// Disk-backed store for private media. Cheap to clone (Arc-free: all fields Copy/owned).
#[derive(Clone)]
pub struct MediaStore {
    dir: PathBuf,
    enc_key: [u8; 32],
    cap_key: [u8; 32],
}

impl MediaStore {
    /// Create the store, ensuring `dir` exists with owner-only permissions.
    pub fn new(dir: PathBuf, enc_key: [u8; 32], cap_key: [u8; 32]) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        tighten_dir(&dir);
        Ok(Self {
            dir,
            enc_key,
            cap_key,
        })
    }

    /// Sign a media id, returning the base64url HMAC capability tag.
    pub fn sign(&self, id: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.cap_key).expect("HMAC accepts any key length");
        mac.update(id.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verify a capability signature for `id` in constant time.
    pub fn verify(&self, id: &str, sig: &str) -> bool {
        let Ok(provided) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig) else {
            return false;
        };
        let mut mac =
            HmacSha256::new_from_slice(&self.cap_key).expect("HMAC accepts any key length");
        mac.update(id.as_bytes());
        mac.verify_slice(&provided).is_ok()
    }

    /// Build the public capability URL for a stored object.
    pub fn capability_url(&self, origin: &str, id: &str, filename: &str) -> String {
        let sig = self.sign(id);
        let fname = sanitize_filename(filename);
        format!(
            "{}/api/v1/media/{}/{}/{}",
            origin.trim_end_matches('/'),
            id,
            sig,
            fname
        )
    }

    /// On-disk path for `id`, sharded by the first two id chars to keep
    /// directory fan-out reasonable.
    fn path_for(&self, id: &str) -> PathBuf {
        let shard: String = id.chars().take(2).collect();
        let shard = if shard.is_empty() {
            "_".to_string()
        } else {
            shard
        };
        self.dir.join(shard).join(id)
    }

    /// Encrypt `data` and write it to disk under `id`.
    pub fn put(&self, id: &str, data: &[u8]) -> std::io::Result<()> {
        let path = self.path_for(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let blob = encrypt(&self.enc_key, data);
        std::fs::write(&path, blob)?;
        tighten_file(&path);
        Ok(())
    }

    /// Read and decrypt the bytes stored under `id`.
    pub fn get(&self, id: &str) -> std::io::Result<Vec<u8>> {
        let blob = std::fs::read(self.path_for(id))?;
        decrypt(&self.enc_key, &blob).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "media decryption failed (wrong key or corrupt blob)",
            )
        })
    }

    /// Best-effort physical removal of a stored object.
    pub fn remove(&self, id: &str) {
        let _ = std::fs::remove_file(self.path_for(id));
    }
}

/// AES-256-GCM encrypt, prepending the random 12-byte nonce. Panics on failure
/// (a broken key/AES impl), matching the at-rest policy in `db.rs`.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-256-GCM encryption failed — invalid key");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// AES-256-GCM decrypt a `[nonce | ciphertext]` blob. Returns None on any failure.
fn decrypt(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    if blob.len() <= 12 {
        return None;
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(key.into());
    cipher.decrypt(nonce, &blob[12..]).ok()
}

#[cfg(unix)]
fn tighten_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
fn tighten_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn tighten_dir(_path: &Path) {}

#[cfg(not(unix))]
fn tighten_file(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (MediaStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [7u8; 32];
        let store = MediaStore::new(
            tmp.path().join("media"),
            derive_enc_key(&seed),
            derive_cap_key(&seed),
        )
        .unwrap();
        (store, tmp)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (store, _tmp) = test_store();
        let id = new_id();
        let sig = store.sign(&id);
        assert!(store.verify(&id, &sig));
    }

    #[test]
    fn verify_rejects_tampered_sig_and_id() {
        let (store, _tmp) = test_store();
        let id = new_id();
        let sig = store.sign(&id);
        assert!(!store.verify(&id, "AAAA"));
        assert!(!store.verify("different-id", &sig));
        assert!(!store.verify(&id, "not base64!!"));
    }

    #[test]
    fn verify_rejects_other_key() {
        let (store, _tmp) = test_store();
        let id = new_id();
        let sig = store.sign(&id);
        let other = MediaStore::new(
            _tmp.path().join("media2"),
            derive_enc_key(&[9u8; 32]),
            derive_cap_key(&[9u8; 32]),
        )
        .unwrap();
        assert!(!other.verify(&id, &sig));
    }

    #[test]
    fn put_get_roundtrip_encrypts_on_disk() {
        let (store, _tmp) = test_store();
        let id = new_id();
        let data = b"the quick brown fox \x00\x01\x02";
        store.put(&id, data).unwrap();
        // Round-trips through decrypt.
        assert_eq!(store.get(&id).unwrap(), data);
        // Raw on-disk bytes are NOT the plaintext.
        let raw = std::fs::read(store.path_for(&id)).unwrap();
        assert_ne!(raw, data);
        assert!(raw.len() > data.len()); // nonce + GCM tag overhead
    }

    #[test]
    fn get_missing_is_err() {
        let (store, _tmp) = test_store();
        assert!(store.get("nope").is_err());
    }

    #[test]
    fn sanitize_strips_paths_and_unsafe_chars() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("my photo!.jpg"), "my_photo_.jpg");
        assert_eq!(sanitize_filename("a/b/c.png"), "c.png");
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename("..."), "file");
    }

    #[test]
    fn capability_url_shape() {
        let (store, _tmp) = test_store();
        let id = "abc123";
        let url = store.capability_url("https://irc.freeq.at/", id, "pic.jpg");
        let sig = store.sign(id);
        assert_eq!(
            url,
            format!("https://irc.freeq.at/api/v1/media/{id}/{sig}/pic.jpg")
        );
    }
}
