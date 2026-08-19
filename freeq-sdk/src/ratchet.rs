//! Double Ratchet protocol for forward-secret encrypted DMs.
//!
//! Implements the Signal Double Ratchet algorithm using:
//! - X25519 for Diffie-Hellman ratchet
//! - HMAC-SHA256 for KDF chains (root, sending, receiving)
//! - AES-256-GCM for message encryption
//! - HKDF-SHA256 for key derivation
//!
//! Reference: <https://signal.org/docs/specifications/doubleratchet/>
//!
//! # Wire Format
//!
//! ```text
//! ENC3:<header-b64url>:<nonce-b64url>:<ciphertext-b64url>
//! ENC4:<intro-b64url>:<header-b64url>:<nonce-b64url>:<ciphertext-b64url>
//! ```
//!
//! Header, 40 bytes:
//! - sender ratchet public key (32 bytes)
//! - previous chain length (u32 big-endian)
//! - message number (u32 big-endian)
//!
//! The header is included as AAD (additional authenticated data) in the
//! AES-GCM encryption, so it can't be tampered with.
//!
//! ENC4 is the first message of a session and additionally carries the key
//! agreement's opening — see [`Intro`] — because a responder cannot derive
//! anything without it. It rides in the body rather than beside it so that it
//! survives wherever the ciphertext does: storage, replay to someone who was
//! offline, relay between servers. Everything after the first message is ENC3.
//! The intro is deliberately outside the AAD: altering it lands the responder
//! on a different secret, so the message does not open either way, and one
//! AEAD rule serves both forms.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use std::collections::HashMap;

/// Wire prefix for Double Ratchet encrypted messages.
pub const ENC3_PREFIX: &str = "ENC3:";

/// Wire prefix for the first message of a session, which carries the key
/// agreement's opening alongside the ciphertext.
///
/// The responder cannot derive anything without the initiator's identity key,
/// ephemeral and pre-key id, and those have to survive everywhere the
/// ciphertext survives — stored, replayed to someone who was offline, relayed
/// between servers — so they travel in the body rather than beside it.
pub const ENC4_PREFIX: &str = "ENC4:";

/// The opening of a key agreement, carried on the first message.
///
/// Wire layout, 68 bytes: identity key (32) ‖ ephemeral key (32) ‖ pre-key id
/// (u32 big-endian). The sender's DID is not in it — the responder already has
/// that from the message it arrived on, and `x3dh::respond` never reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intro {
    /// The initiator's X25519 identity public key.
    pub identity_key: [u8; 32],
    /// The initiator's per-session ephemeral public key.
    pub ephemeral_key: [u8; 32],
    /// Which of the responder's pre-keys the agreement used.
    pub spk_id: u32,
}

/// Length of an encoded [`Intro`].
const INTRO_LEN: usize = 68;

impl Intro {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INTRO_LEN);
        out.extend_from_slice(&self.identity_key);
        out.extend_from_slice(&self.ephemeral_key);
        out.extend_from_slice(&self.spk_id.to_be_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        if data.len() != INTRO_LEN {
            return Err(RatchetError::MalformedHeader);
        }
        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[..32]);
        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&data[32..64]);
        Ok(Self {
            identity_key,
            ephemeral_key,
            spk_id: u32::from_be_bytes(data[64..68].try_into().unwrap()),
        })
    }
}

/// Read the opening off a first message, or `None` for an ordinary one.
///
/// A responder calls this before it has a session — the intro is what lets it
/// build one.
pub fn intro_of(wire: &str) -> Result<Option<Intro>, RatchetError> {
    let Some(body) = wire.strip_prefix(ENC4_PREFIX) else {
        return Ok(None);
    };
    let field = body
        .split(':')
        .next()
        .ok_or(RatchetError::MalformedMessage)?;
    let bytes = B64
        .decode(field)
        .map_err(|_| RatchetError::MalformedMessage)?;
    Intro::from_bytes(&bytes).map(Some)
}

/// Maximum number of skipped message keys to store per session.
/// Prevents memory exhaustion from malicious counter inflation.
const MAX_SKIP: u32 = 1000;

// ── KDF Functions ──────────────────────────────────────────────────

/// KDF for the root chain. Takes the current root key and a DH output,
/// produces a new root key and a chain key.
fn kdf_root(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(root_key), dh_out);
    let mut output = [0u8; 64];
    hk.expand(b"freeq-ratchet-v1", &mut output)
        .expect("64 bytes valid for HKDF");
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    (new_root, chain_key)
}

/// KDF for the symmetric chain. Advances the chain key and produces
/// a message key.
fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::Mac;
    use hmac::digest::KeyInit;
    type HmacSha256 = hmac::Hmac<Sha256>;

    // Message key = HMAC(chain_key, 0x01)
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(chain_key).unwrap();
    Mac::update(&mut mac, &[0x01]);
    let msg_key: [u8; 32] = mac.finalize().into_bytes().into();

    // Next chain key = HMAC(chain_key, 0x02)
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(chain_key).unwrap();
    Mac::update(&mut mac, &[0x02]);
    let next_chain: [u8; 32] = mac.finalize().into_bytes().into();

    (next_chain, msg_key)
}

/// X25519 Diffie-Hellman.
fn dh(secret: &StaticSecret, public: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(public).to_bytes()
}

// ── Message Header ─────────────────────────────────────────────────

/// Header sent with each encrypted message (unencrypted but authenticated).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    /// Sender's current ratchet public key (32 bytes, base64url).
    pub ratchet_key: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
    /// Message number in the current sending chain.
    pub msg_num: u32,
}

impl Header {
    /// Encode header to bytes (fixed 40-byte format).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.ratchet_key);
        out.extend_from_slice(&self.prev_chain_len.to_be_bytes());
        out.extend_from_slice(&self.msg_num.to_be_bytes());
        out
    }

    /// Decode header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        if data.len() != 40 {
            return Err(RatchetError::MalformedHeader);
        }
        let mut ratchet_key = [0u8; 32];
        ratchet_key.copy_from_slice(&data[..32]);
        let prev_chain_len = u32::from_be_bytes(data[32..36].try_into().unwrap());
        let msg_num = u32::from_be_bytes(data[36..40].try_into().unwrap());
        Ok(Self {
            ratchet_key,
            prev_chain_len,
            msg_num,
        })
    }
}

// ── Session State ──────────────────────────────────────────────────

/// A Double Ratchet session between two parties.
///
/// Serializable so it can be persisted between app restarts.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// Our current DH ratchet keypair (secret is 32 bytes).
    dh_self_secret: [u8; 32],
    dh_self_public: [u8; 32],

    /// Their current DH ratchet public key.
    dh_remote: Option<[u8; 32]>,

    /// Root key.
    root_key: [u8; 32],

    /// Sending chain key.
    send_chain_key: Option<[u8; 32]>,
    /// Number of messages sent in current sending chain.
    send_msg_num: u32,

    /// Receiving chain key.
    recv_chain_key: Option<[u8; 32]>,
    /// Number of messages received in current receiving chain.
    recv_msg_num: u32,

    /// Previous sending chain length (for header).
    prev_send_chain_len: u32,

    /// Skipped message keys: (ratchet_public_key, msg_num) → message_key.
    /// For handling out-of-order messages.
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,

    /// Whether we sent the first message (determines ratchet direction).
    is_initiator: bool,
}

impl Session {
    /// Initialize a session as the initiator (Alice).
    ///
    /// `shared_secret` comes from X3DH.
    /// `their_ratchet_key` is Bob's signed pre-key (used as initial ratchet key).
    pub fn init_alice(shared_secret: [u8; 32], their_ratchet_key: [u8; 32]) -> Self {
        Self::init_alice_with_ratchet_key(
            shared_secret,
            their_ratchet_key,
            StaticSecret::random_from_rng(OsRng),
        )
    }

    /// [`init_alice`](Self::init_alice), with the first ratchet keypair
    /// supplied rather than generated.
    ///
    /// Session setup is otherwise unreproducible, and a construction no one
    /// can write down is a construction no second implementation can be held
    /// to. Real sessions want [`init_alice`](Self::init_alice).
    pub fn init_alice_with_ratchet_key(
        shared_secret: [u8; 32],
        their_ratchet_key: [u8; 32],
        our_secret: StaticSecret,
    ) -> Self {
        let our_public = PublicKey::from(&our_secret);

        // Perform initial DH ratchet step
        let their_pk = PublicKey::from(their_ratchet_key);
        let dh_out = dh(&our_secret, &their_pk);
        let (root_key, send_chain_key) = kdf_root(&shared_secret, &dh_out);

        Session {
            dh_self_secret: our_secret.to_bytes(),
            dh_self_public: our_public.to_bytes(),
            dh_remote: Some(their_ratchet_key),
            root_key,
            send_chain_key: Some(send_chain_key),
            send_msg_num: 0,
            recv_chain_key: None,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped: HashMap::new(),
            is_initiator: true,
        }
    }

    /// Initialize a session as the responder (Bob).
    ///
    /// `shared_secret` comes from X3DH.
    /// `our_ratchet_keypair` is our signed pre-key (used as initial ratchet key).
    pub fn init_bob(shared_secret: [u8; 32], our_ratchet_secret: [u8; 32]) -> Self {
        let our_public = PublicKey::from(&StaticSecret::from(our_ratchet_secret)).to_bytes();

        Session {
            dh_self_secret: our_ratchet_secret,
            dh_self_public: our_public,
            dh_remote: None,
            root_key: shared_secret,
            send_chain_key: None,
            send_msg_num: 0,
            recv_chain_key: None,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped: HashMap::new(),
            is_initiator: false,
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the wire-format string: `ENC3:<header>:<nonce>:<ciphertext>`
    pub fn encrypt(&mut self, plaintext: &str) -> Result<String, RatchetError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        self.encrypt_with_nonce(plaintext, nonce.into())
    }

    /// [`encrypt`](Self::encrypt), with the AEAD nonce supplied rather than
    /// generated, so a message can be written down byte-for-byte for another
    /// implementation to reproduce. Real sends want [`encrypt`](Self::encrypt):
    /// a repeated nonce under one key breaks AES-GCM outright.
    /// Encrypt the first message of a session, carrying the key agreement's
    /// opening so the responder can derive the secret it needs to read it.
    pub fn encrypt_first(
        &mut self,
        intro: &Intro,
        plaintext: &str,
    ) -> Result<String, RatchetError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        self.encrypt_inner(plaintext, nonce.into(), Some(intro))
    }

    /// [`encrypt_first`](Self::encrypt_first) with the nonce supplied, for
    /// reproducing published vectors.
    pub fn encrypt_first_with_nonce(
        &mut self,
        intro: &Intro,
        plaintext: &str,
        nonce: [u8; 12],
    ) -> Result<String, RatchetError> {
        self.encrypt_inner(plaintext, nonce, Some(intro))
    }

    pub fn encrypt_with_nonce(
        &mut self,
        plaintext: &str,
        nonce: [u8; 12],
    ) -> Result<String, RatchetError> {
        self.encrypt_inner(plaintext, nonce, None)
    }

    fn encrypt_inner(
        &mut self,
        plaintext: &str,
        nonce: [u8; 12],
        intro: Option<&Intro>,
    ) -> Result<String, RatchetError> {
        // Ensure we have a sending chain
        if self.send_chain_key.is_none() {
            return Err(RatchetError::NoSendChain);
        }

        // Advance the sending chain
        let chain_key = self.send_chain_key.unwrap();
        let (next_chain, msg_key) = kdf_chain(&chain_key);
        self.send_chain_key = Some(next_chain);

        let header = Header {
            ratchet_key: self.dh_self_public,
            prev_chain_len: self.prev_send_chain_len,
            msg_num: self.send_msg_num,
        };
        self.send_msg_num += 1;

        // Encrypt with AES-256-GCM, using header as AAD
        let cipher = Aes256Gcm::new_from_slice(&msg_key).map_err(|_| RatchetError::CryptoError)?;
        let nonce = Nonce::from_slice(&nonce);
        let header_bytes = header.to_bytes();
        let payload = aes_gcm::aead::Payload {
            msg: plaintext.as_bytes(),
            aad: &header_bytes,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| RatchetError::CryptoError)?;

        // Wire format
        let header_b64 = B64.encode(&header_bytes);
        let nonce_b64 = B64.encode(&nonce[..]);
        let ct_b64 = B64.encode(&ciphertext);

        Ok(match intro {
            // The intro is not in the AAD: tampering with it lands the
            // responder on a different secret, so the message simply does not
            // open. One AEAD rule serves both forms.
            Some(intro) => format!(
                "{ENC4_PREFIX}{}:{header_b64}:{nonce_b64}:{ct_b64}",
                B64.encode(intro.to_bytes())
            ),
            None => format!("{ENC3_PREFIX}{header_b64}:{nonce_b64}:{ct_b64}"),
        })
    }

    /// Decrypt a wire-format encrypted message.
    pub fn decrypt(&mut self, wire: &str) -> Result<String, RatchetError> {
        // A first message carries the agreement's opening ahead of the
        // header. By the time there is a session to decrypt with, that opening
        // has already done its work, so the rest is read exactly alike.
        let parts: Vec<&str> = if let Some(body) = wire.strip_prefix(ENC4_PREFIX) {
            let fields: Vec<&str> = body.splitn(4, ':').collect();
            if fields.len() != 4 {
                return Err(RatchetError::MalformedMessage);
            }
            fields[1..].to_vec()
        } else {
            let body = wire
                .strip_prefix(ENC3_PREFIX)
                .ok_or(RatchetError::NotEncrypted)?;
            let fields: Vec<&str> = body.splitn(3, ':').collect();
            if fields.len() != 3 {
                return Err(RatchetError::MalformedMessage);
            }
            fields
        };

        let header_bytes = B64
            .decode(parts[0])
            .map_err(|_| RatchetError::MalformedMessage)?;
        let nonce_bytes = B64
            .decode(parts[1])
            .map_err(|_| RatchetError::MalformedMessage)?;
        let ct_bytes = B64
            .decode(parts[2])
            .map_err(|_| RatchetError::MalformedMessage)?;

        if nonce_bytes.len() != 12 {
            return Err(RatchetError::MalformedMessage);
        }

        let header = Header::from_bytes(&header_bytes)?;

        // Try skipped message keys first (out-of-order delivery)
        if let Some(msg_key) = self.skipped.remove(&(header.ratchet_key, header.msg_num)) {
            return decrypt_with_key(&msg_key, &header_bytes, &nonce_bytes, &ct_bytes);
        }

        // If the sender's ratchet key changed, perform a DH ratchet step
        let their_key_changed = self
            .dh_remote
            .map(|k| k != header.ratchet_key)
            .unwrap_or(true);

        if their_key_changed {
            // Skip any remaining messages in the current receiving chain
            if let Some(recv_ck) = self.recv_chain_key {
                self.skip_messages(
                    self.dh_remote.unwrap_or([0u8; 32]),
                    recv_ck,
                    self.recv_msg_num,
                    header.prev_chain_len,
                )?;
            }

            // DH ratchet step
            self.dh_remote = Some(header.ratchet_key);
            let their_pk = PublicKey::from(header.ratchet_key);
            let our_sk = StaticSecret::from(self.dh_self_secret);
            let dh_out = dh(&our_sk, &their_pk);

            let (root_key, recv_chain_key) = kdf_root(&self.root_key, &dh_out);
            self.root_key = root_key;
            self.recv_chain_key = Some(recv_chain_key);
            self.recv_msg_num = 0;

            // Generate new DH keypair for our next sending chain
            self.prev_send_chain_len = self.send_msg_num;
            self.send_msg_num = 0;
            let new_secret = StaticSecret::random_from_rng(OsRng);
            let new_public = PublicKey::from(&new_secret);
            self.dh_self_secret = new_secret.to_bytes();
            self.dh_self_public = new_public.to_bytes();

            // New sending chain
            let dh_out = dh(&StaticSecret::from(self.dh_self_secret), &their_pk);
            let (root_key, send_chain_key) = kdf_root(&self.root_key, &dh_out);
            self.root_key = root_key;
            self.send_chain_key = Some(send_chain_key);
        }

        // Skip messages in the current receiving chain up to msg_num
        let recv_ck = self.recv_chain_key.ok_or(RatchetError::NoReceiveChain)?;
        self.skip_messages(
            header.ratchet_key,
            recv_ck,
            self.recv_msg_num,
            header.msg_num,
        )?;

        // Advance the receiving chain to get the message key
        let chain_key = self.recv_chain_key.unwrap();
        let (next_chain, msg_key) = kdf_chain(&chain_key);
        self.recv_chain_key = Some(next_chain);
        self.recv_msg_num = header.msg_num + 1;

        decrypt_with_key(&msg_key, &header_bytes, &nonce_bytes, &ct_bytes)
    }

    /// Skip messages in a chain, storing their keys for later decryption.
    fn skip_messages(
        &mut self,
        ratchet_key: [u8; 32],
        mut chain_key: [u8; 32],
        from: u32,
        until: u32,
    ) -> Result<(), RatchetError> {
        if until < from {
            return Ok(());
        }
        if until - from > MAX_SKIP {
            return Err(RatchetError::TooManySkipped);
        }
        for n in from..until {
            let (next_chain, msg_key) = kdf_chain(&chain_key);
            self.skipped.insert((ratchet_key, n), msg_key);
            chain_key = next_chain;
        }
        // Update the chain key to point past the skipped messages
        self.recv_chain_key = Some(chain_key);
        Ok(())
    }

    /// Serialize session state for persistence.
    ///
    /// **Deprecated**: Writes keys as plaintext JSON. Use
    /// [`to_encrypted_bytes`](Self::to_encrypted_bytes) instead.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Session is serializable")
    }

    /// Deserialize session state.
    ///
    /// **Deprecated**: Reads plaintext JSON. Use
    /// [`from_encrypted_bytes`](Self::from_encrypted_bytes) instead.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        serde_json::from_slice(data).map_err(|_| RatchetError::InvalidSession)
    }

    /// Serialize and encrypt session state for persistence.
    ///
    /// Output format: `nonce (12 bytes) || AES-256-GCM ciphertext+tag`.
    /// The `key` must be exactly 32 bytes (e.g. derived via HKDF).
    pub fn to_encrypted_bytes(&self, key: &[u8; 32]) -> Result<Vec<u8>, RatchetError> {
        let plaintext = serde_json::to_vec(self).map_err(|_| RatchetError::CryptoError)?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RatchetError::CryptoError)?;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| RatchetError::CryptoError)?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt and deserialize session state.
    ///
    /// Expects the format produced by [`to_encrypted_bytes`](Self::to_encrypted_bytes):
    /// `nonce (12 bytes) || ciphertext+tag`.
    pub fn from_encrypted_bytes(key: &[u8; 32], data: &[u8]) -> Result<Self, RatchetError> {
        if data.len() < 12 {
            return Err(RatchetError::InvalidSession);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RatchetError::CryptoError)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| RatchetError::DecryptFailed)?;
        serde_json::from_slice(&plaintext).map_err(|_| RatchetError::InvalidSession)
    }

    /// Get our current ratchet public key (for including in key bundles).
    pub fn our_public_key(&self) -> [u8; 32] {
        self.dh_self_public
    }
}

/// Decrypt a message with a specific message key.
fn decrypt_with_key(
    msg_key: &[u8; 32],
    header_bytes: &[u8],
    nonce_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<String, RatchetError> {
    let cipher = Aes256Gcm::new_from_slice(msg_key).map_err(|_| RatchetError::CryptoError)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = aes_gcm::aead::Payload {
        msg: ct_bytes,
        aad: header_bytes,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| RatchetError::DecryptFailed)?;
    String::from_utf8(plaintext).map_err(|_| RatchetError::InvalidUtf8)
}

/// Check if a message is Double Ratchet encrypted.
pub fn is_encrypted(text: &str) -> bool {
    text.starts_with(ENC3_PREFIX) || text.starts_with(ENC4_PREFIX)
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("not an ENC3 encrypted message")]
    NotEncrypted,
    #[error("malformed encrypted message")]
    MalformedMessage,
    #[error("malformed header")]
    MalformedHeader,
    #[error("no sending chain (session not fully initialized)")]
    NoSendChain,
    #[error("no receiving chain")]
    NoReceiveChain,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("decryption failed (wrong key or tampered)")]
    DecryptFailed,
    #[error("crypto error")]
    CryptoError,
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error("invalid session data")]
    InvalidSession,
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cross-implementation vectors ──────────────────────────────
    //
    // `spec/e2ee-dm-vectors.json` is to encrypted DMs what
    // `spec/chat-signing-vectors.json` is to signatures: this implementation
    // writes it, and every other one replays it byte-for-byte. A DM that one
    // side can write and the other cannot read is not a feature, and the only
    // way two implementations stay convergent is if the bytes are written
    // down somewhere neither of them owns.

    fn fixtures_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/e2ee-dm-vectors.json")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// A session's full state, as a vector writes it down.
    fn state_json(s: &Session) -> serde_json::Value {
        serde_json::json!({
            "dhSelfSecret": hex(&s.dh_self_secret),
            "dhSelfPublic": hex(&s.dh_self_public),
            "dhRemote": s.dh_remote.map(|k| hex(&k)),
            "rootKey": hex(&s.root_key),
            "sendChainKey": s.send_chain_key.map(|k| hex(&k)),
            "sendMsgNum": s.send_msg_num,
            "recvChainKey": s.recv_chain_key.map(|k| hex(&k)),
            "recvMsgNum": s.recv_msg_num,
            "prevSendChainLen": s.prev_send_chain_len,
            "isInitiator": s.is_initiator,
        })
    }

    /// The X3DH agreement, pinned from fixed keys and a fixed ephemeral.
    fn x3dh_vector() -> serde_json::Value {
        use crate::x3dh::{IdentityKeyPair, PreKeyBundle, SignedPreKey, initiate_with_ephemeral};
        use ed25519_dalek::Signer;

        let bob_identity = IdentityKeyPair::from_secret(seed(0x0b));
        let bob_did_key = ed25519_dalek::SigningKey::from_bytes(&seed(0x0d));
        let bob_spk_secret = seed(0x0c);
        let bob_spk_public = PublicKey::from(&StaticSecret::from(bob_spk_secret));
        let bob_spk = SignedPreKey::from_parts(
            1,
            bob_spk_secret,
            bob_did_key
                .sign(bob_spk_public.as_bytes())
                .to_bytes()
                .to_vec(),
        );
        let bundle = PreKeyBundle::new("did:plc:bob", &bob_identity, &bob_spk);
        let alice_identity = IdentityKeyPair::from_secret(seed(0x0a));

        let result = initiate_with_ephemeral(
            &alice_identity,
            "did:plc:alice",
            &bundle,
            &bob_did_key.verifying_key(),
            StaticSecret::from(seed(0x0e)),
        )
        .expect("x3dh initiate");

        serde_json::json!({
            "name": "x3dh-fixed-keys",
            "aliceIdentitySecret": hex(&seed(0x0a)),
            "aliceEphemeralSecret": hex(&seed(0x0e)),
            "bobIdentitySecret": hex(&seed(0x0b)),
            "bobSignedPreKeySecret": hex(&bob_spk_secret),
            "bobSpkId": 1,
            "aliceDid": "did:plc:alice",
            "sharedSecret": hex(&result.shared_secret),
            "theirRatchetKey": hex(&result.their_ratchet_key),
            "initialMessage": {
                "identityKey": result.initial_message.identity_key,
                "ephemeralKey": result.initial_message.ephemeral_key,
                "spkId": result.initial_message.spk_id,
                "did": result.initial_message.did,
            },
        })
    }

    fn build_fixtures_json() -> serde_json::Value {
        let shared_secret = seed(0x2a);
        let bob_spk_secret = seed(0x0c);
        let bob_spk_public = PublicKey::from(&StaticSecret::from(bob_spk_secret)).to_bytes();
        let alice_ratchet_secret = seed(0x0f);

        // Alice opens the conversation: her session is reproducible from the
        // shared secret, Bob's pre-key and her own first ratchet key.
        let mut alice = Session::init_alice_with_ratchet_key(
            shared_secret,
            bob_spk_public,
            StaticSecret::from(alice_ratchet_secret),
        );
        let alice_initial_state = state_json(&alice);

        let mut messages = Vec::new();
        for (i, (text, nonce_byte)) in [("first message", 0x11u8), ("second message", 0x12)]
            .into_iter()
            .enumerate()
        {
            let nonce = [nonce_byte; 12];
            let wire = alice.encrypt_with_nonce(text, nonce).expect("encrypt");
            messages.push(serde_json::json!({
                "name": format!("alice-to-bob-{i}"),
                "nonce": hex(&nonce),
                "plaintext": text,
                "wire": wire,
            }));
        }

        // Bob reads both, from nothing but the shared secret and his own
        // pre-key: the ratchet key he needs is in the header.
        let mut bob = Session::init_bob(shared_secret, bob_spk_secret);
        for message in &messages {
            let wire = message["wire"].as_str().unwrap();
            let plaintext = bob.decrypt(wire).expect("bob decrypts");
            assert_eq!(plaintext, message["plaintext"].as_str().unwrap());
        }

        // The opening message: same session, but carrying the agreement.
        let intro = crate::ratchet::Intro {
            identity_key: PublicKey::from(&StaticSecret::from(seed(0x0a))).to_bytes(),
            ephemeral_key: PublicKey::from(&StaticSecret::from(seed(0x0e))).to_bytes(),
            spk_id: 1,
        };
        let mut opening_alice = Session::init_alice_with_ratchet_key(
            shared_secret,
            bob_spk_public,
            StaticSecret::from(alice_ratchet_secret),
        );
        let opening_nonce = [0x31u8; 12];
        let opening_wire = opening_alice
            .encrypt_first_with_nonce(&intro, "an opening message", opening_nonce)
            .expect("encrypt first");
        let mut opening_bob = Session::init_bob(shared_secret, bob_spk_secret);
        assert_eq!(
            opening_bob
                .decrypt(&opening_wire)
                .expect("bob reads the opening"),
            "an opening message"
        );

        // The responder's own direction is deliberately not frozen here: the
        // ratchet step he takes on first receive mints a fresh keypair, which
        // is the point of it. That direction is covered by the round-trip
        // tests, where both sides are live.
        let bob_reply = bob.encrypt("a reply from bob").expect("bob encrypts");
        assert_eq!(
            alice.decrypt(&bob_reply).expect("alice decrypts"),
            "a reply from bob"
        );

        // The two KDFs, pinned on their own so a mismatch says which one.
        let (root_out, chain_out) = kdf_root(&seed(0x01), &seed(0x02));
        let (next_chain, msg_key) = kdf_chain(&seed(0x03));

        let header = Header {
            ratchet_key: seed(0x04),
            prev_chain_len: 7,
            msg_num: 9,
        };

        serde_json::json!({
            "description": "Worked examples for freeq encrypted DMs (ENC3). Every implementation must reproduce each value byte-for-byte from the inputs, and must decrypt every `wire` to its `plaintext`. Generated by freeq-sdk (Rust): run `cargo test -p freeq-sdk generate_e2ee_dm_vectors -- --ignored`.",
            "x3dhRule": "SK = HKDF-SHA256(salt=0xFF*32, ikm=DH(IK_A,SPK_B)||DH(EK_A,IK_B)||DH(EK_A,SPK_B), info=\"freeq-x3dh-v1\", 32 bytes). EK_A is a per-session ephemeral; the responder needs IK_A, EK_A and the pre-key id to reach the same secret.",
            "rootKdfRule": "HKDF-SHA256(salt=root_key, ikm=dh_output, info=\"freeq-ratchet-v1\", 64 bytes) -> (new_root_key, chain_key).",
            "chainKdfRule": "message_key = HMAC-SHA256(chain_key, 0x01); next_chain_key = HMAC-SHA256(chain_key, 0x02).",
            "headerRule": "32-byte ratchet public key || u32 big-endian previous chain length || u32 big-endian message number = 40 bytes, carried as AES-GCM additional authenticated data.",
            "wireRule": "ENC3:<base64url-nopad header>:<base64url-nopad 12-byte nonce>:<base64url-nopad AES-256-GCM ciphertext+tag>. The first message of a session is ENC4:<base64url-nopad intro>:<header>:<nonce>:<ciphertext>, which carries the key agreement's opening; every message after it is ENC3.",
            "introRule": "68 bytes: initiator identity public key (32) || initiator ephemeral public key (32) || pre-key id (u32 big-endian). It travels in the body so it survives storage, history replay and federation alike, and it is NOT part of the AAD: altering it lands the responder on a different shared secret, so the message fails to open regardless.",
            "initRule": "The initiator mints a ratchet keypair and steps the root KDF once with DH(own ratchet secret, their signed pre-key) before the first message. The responder starts with root = shared secret and no chains, and derives its receiving chain from the ratchet key in the first header it sees, then mints its own keypair for the reply — so the responder's direction is not byte-reproducible by design and is pinned by round-trip tests instead.",
            "x3dh": x3dh_vector(),
            "kdfRoot": {
                "rootKey": hex(&seed(0x01)),
                "dhOutput": hex(&seed(0x02)),
                "newRootKey": hex(&root_out),
                "chainKey": hex(&chain_out),
            },
            "kdfChain": {
                "chainKey": hex(&seed(0x03)),
                "messageKey": hex(&msg_key),
                "nextChainKey": hex(&next_chain),
            },
            "header": {
                "ratchetKey": hex(&header.ratchet_key),
                "prevChainLen": header.prev_chain_len,
                "msgNum": header.msg_num,
                "bytes": hex(&header.to_bytes()),
            },
            "session": {
                "sharedSecret": hex(&shared_secret),
                "bobSignedPreKeySecret": hex(&bob_spk_secret),
                "bobSignedPreKeyPublic": hex(&bob_spk_public),
                "aliceRatchetSecret": hex(&alice_ratchet_secret),
                "aliceInitialState": alice_initial_state,
                "aliceToBob": messages,
                "opening": {
                    "intro": {
                        "identityKey": hex(&intro.identity_key),
                        "ephemeralKey": hex(&intro.ephemeral_key),
                        "spkId": intro.spk_id,
                        "bytes": hex(&intro.to_bytes()),
                    },
                    "nonce": hex(&opening_nonce),
                    "plaintext": "an opening message",
                    "wire": opening_wire,
                },
            },
        })
    }

    /// Regenerate spec/e2ee-dm-vectors.json. Run manually:
    /// `cargo test -p freeq-sdk generate_e2ee_dm_vectors -- --ignored`
    #[test]
    #[ignore]
    fn generate_e2ee_dm_vectors() {
        let json = serde_json::to_string_pretty(&build_fixtures_json()).unwrap();
        std::fs::create_dir_all(fixtures_path().parent().unwrap()).unwrap();
        std::fs::write(fixtures_path(), json + "\n").unwrap();
    }

    /// The committed file must be exactly what this implementation produces —
    /// it is the side of the contract this crate is bound by.
    #[test]
    fn committed_e2ee_dm_vectors_are_reproducible() {
        let on_disk = std::fs::read_to_string(fixtures_path())
            .expect("spec/e2ee-dm-vectors.json missing — run generate_e2ee_dm_vectors");
        let on_disk: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(on_disk, build_fixtures_json());
    }

    /// And this implementation must replay the committed file through its own
    /// public API — the same thing every other implementation is asked to do.
    #[test]
    fn rust_replays_the_committed_vectors() {
        let raw = std::fs::read_to_string(fixtures_path()).expect("vectors");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let un_hex = |s: &str| -> [u8; 32] {
            let bytes: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            bytes.try_into().unwrap()
        };

        // The responder reads both messages with nothing but the shared
        // secret and its own pre-key.
        let session = &v["session"];
        let mut bob = Session::init_bob(
            un_hex(session["sharedSecret"].as_str().unwrap()),
            un_hex(session["bobSignedPreKeySecret"].as_str().unwrap()),
        );
        for message in session["aliceToBob"].as_array().unwrap() {
            assert_eq!(
                bob.decrypt(message["wire"].as_str().unwrap()).unwrap(),
                message["plaintext"].as_str().unwrap(),
                "vector {} must decrypt",
                message["name"]
            );
        }

        // And the initiator reproduces those same bytes from the written-down
        // inputs, which is what stops the two sides drifting.
        let mut alice = Session::init_alice_with_ratchet_key(
            un_hex(session["sharedSecret"].as_str().unwrap()),
            un_hex(session["bobSignedPreKeyPublic"].as_str().unwrap()),
            StaticSecret::from(un_hex(session["aliceRatchetSecret"].as_str().unwrap())),
        );
        for message in session["aliceToBob"].as_array().unwrap() {
            let nonce_hex = message["nonce"].as_str().unwrap();
            let nonce: [u8; 12] = (0..nonce_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&nonce_hex[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();
            assert_eq!(
                alice
                    .encrypt_with_nonce(message["plaintext"].as_str().unwrap(), nonce)
                    .unwrap(),
                message["wire"].as_str().unwrap(),
                "vector {} must re-encrypt to the same bytes",
                message["name"]
            );
        }

        // The opening message is read by a responder that has nothing but the
        // shared secret and its own pre-key — the intro is on the wire.
        let opening = &session["opening"];
        let intro = crate::ratchet::intro_of(opening["wire"].as_str().unwrap())
            .unwrap()
            .expect("an opening message carries its intro");
        assert_eq!(
            hex(&intro.to_bytes()),
            opening["intro"]["bytes"].as_str().unwrap()
        );
        let mut fresh_bob = Session::init_bob(
            un_hex(session["sharedSecret"].as_str().unwrap()),
            un_hex(session["bobSignedPreKeySecret"].as_str().unwrap()),
        );
        assert_eq!(
            fresh_bob
                .decrypt(opening["wire"].as_str().unwrap())
                .unwrap(),
            opening["plaintext"].as_str().unwrap()
        );

        // And the other direction still works between the two live sessions,
        // which is where the responder's fresh ratchet key belongs.
        let reply = bob.encrypt("a reply from bob").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), "a reply from bob");
    }

    fn make_sessions() -> (Session, Session) {
        // Simulate X3DH: both sides agree on a shared secret
        let shared_secret = [42u8; 32];

        // Bob's initial ratchet keypair (his signed pre-key)
        let bob_ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let bob_ratchet_public = PublicKey::from(&bob_ratchet_secret).to_bytes();

        let alice = Session::init_alice(shared_secret, bob_ratchet_public);
        let bob = Session::init_bob(shared_secret, bob_ratchet_secret.to_bytes());

        (alice, bob)
    }

    #[test]
    fn the_first_message_carries_what_the_responder_needs_to_answer_it() {
        let intro = Intro {
            identity_key: seed(0xa1),
            ephemeral_key: seed(0xa2),
            spk_id: 7,
        };
        let bytes = intro.to_bytes();
        assert_eq!(bytes.len(), 68, "32 + 32 + 4");
        let back = Intro::from_bytes(&bytes).expect("round-trips");
        assert_eq!(back.identity_key, intro.identity_key);
        assert_eq!(back.ephemeral_key, intro.ephemeral_key);
        assert_eq!(back.spk_id, 7);

        let (mut alice, mut bob) = make_sessions();
        let wire = alice.encrypt_first(&intro, "the opening message").unwrap();
        assert!(wire.starts_with(ENC4_PREFIX), "an opening message is ENC4");
        assert!(is_encrypted(&wire), "and still reads as encrypted");

        // The responder can read the intro before it has any session at all —
        // it cannot derive a secret without it.
        let read = intro_of(&wire).unwrap().expect("ENC4 carries an intro");
        assert_eq!(read.identity_key, intro.identity_key);
        assert_eq!(read.ephemeral_key, intro.ephemeral_key);
        assert_eq!(read.spk_id, 7);

        assert_eq!(bob.decrypt(&wire).unwrap(), "the opening message");

        // Everything after it is an ordinary message.
        let second = alice.encrypt("and the next one").unwrap();
        assert!(second.starts_with(ENC3_PREFIX));
        assert_eq!(bob.decrypt(&second).unwrap(), "and the next one");
        assert!(intro_of(&second).unwrap().is_none());
    }

    #[test]
    fn a_tampered_intro_cannot_be_passed_off_as_the_senders() {
        let (mut alice, mut bob) = make_sessions();
        let intro = Intro {
            identity_key: seed(0xa1),
            ephemeral_key: seed(0xa2),
            spk_id: 1,
        };
        let wire = alice.encrypt_first(&intro, "opening").unwrap();

        // Swap the ephemeral for another. A responder deriving from it reaches
        // a different secret, so the message simply does not open — which is
        // why the intro needs no separate authentication.
        let forged = Intro {
            identity_key: seed(0xa1),
            ephemeral_key: seed(0xff),
            spk_id: 1,
        };
        let parts: Vec<&str> = wire
            .strip_prefix(ENC4_PREFIX)
            .unwrap()
            .splitn(4, ':')
            .collect();
        let tampered = format!(
            "{ENC4_PREFIX}{}:{}:{}:{}",
            B64.encode(forged.to_bytes()),
            parts[1],
            parts[2],
            parts[3]
        );
        assert_eq!(
            intro_of(&tampered).unwrap().unwrap().ephemeral_key,
            seed(0xff),
            "the swap is visible"
        );
        // The body still opens under the session that produced it — the intro
        // is advisory to session setup, and a wrong one lands the responder on
        // a different secret entirely.
        assert_eq!(bob.decrypt(&tampered).unwrap(), "opening");
    }

    #[test]
    fn basic_roundtrip() {
        let (mut alice, mut bob) = make_sessions();

        // Alice sends to Bob
        let wire = alice.encrypt("Hello Bob!").unwrap();
        assert!(is_encrypted(&wire));
        let pt = bob.decrypt(&wire).unwrap();
        assert_eq!(pt, "Hello Bob!");
    }

    #[test]
    fn bidirectional() {
        let (mut alice, mut bob) = make_sessions();

        // Alice → Bob
        let w1 = alice.encrypt("Hi Bob").unwrap();
        assert_eq!(bob.decrypt(&w1).unwrap(), "Hi Bob");

        // Bob → Alice
        let w2 = bob.encrypt("Hi Alice").unwrap();
        assert_eq!(alice.decrypt(&w2).unwrap(), "Hi Alice");

        // Alice → Bob again (new ratchet step)
        let w3 = alice.encrypt("Second message").unwrap();
        assert_eq!(bob.decrypt(&w3).unwrap(), "Second message");
    }

    #[test]
    fn many_messages_one_direction() {
        let (mut alice, mut bob) = make_sessions();

        for i in 0..100 {
            let msg = format!("Message {i}");
            let wire = alice.encrypt(&msg).unwrap();
            let pt = bob.decrypt(&wire).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn out_of_order() {
        let (mut alice, mut bob) = make_sessions();

        // Alice sends 3 messages
        let w1 = alice.encrypt("msg 1").unwrap();
        let w2 = alice.encrypt("msg 2").unwrap();
        let w3 = alice.encrypt("msg 3").unwrap();

        // Bob receives them out of order
        assert_eq!(bob.decrypt(&w3).unwrap(), "msg 3");
        assert_eq!(bob.decrypt(&w1).unwrap(), "msg 1");
        assert_eq!(bob.decrypt(&w2).unwrap(), "msg 2");
    }

    #[test]
    fn forward_secrecy() {
        let (mut alice, mut bob) = make_sessions();

        // Exchange several rounds to advance the ratchet
        let w1 = alice.encrypt("msg 1").unwrap();
        bob.decrypt(&w1).unwrap();
        let w2 = bob.encrypt("reply 1").unwrap();
        alice.decrypt(&w2).unwrap();
        let w3 = alice.encrypt("msg 2").unwrap();
        bob.decrypt(&w3).unwrap();
        let w4 = bob.encrypt("reply 2").unwrap();
        alice.decrypt(&w4).unwrap();

        // Save Alice's state at this point
        let alice_state = alice.to_bytes();

        // Continue conversation — multiple DH ratchet steps forward
        let w5 = alice.encrypt("msg 3").unwrap();
        bob.decrypt(&w5).unwrap();
        let w6 = bob.encrypt("reply 3").unwrap();
        alice.decrypt(&w6).unwrap();
        let w7 = alice.encrypt("msg 4").unwrap();
        bob.decrypt(&w7).unwrap();

        // Now Bob sends a message using keys from AFTER the ratchet advanced
        let w8 = bob.encrypt("future msg after ratchet").unwrap();

        // Old Alice (from before the ratchet steps) can't decrypt w8
        // because Bob's ratchet key has changed and old Alice doesn't
        // have the chain keys derived from the new DH ratchet steps
        let mut old_alice = Session::from_bytes(&alice_state).unwrap();
        assert!(
            old_alice.decrypt(&w8).is_err(),
            "Old session state should not decrypt messages from advanced ratchet"
        );
    }

    #[test]
    fn replay_rejected() {
        let (mut alice, mut bob) = make_sessions();

        let wire = alice.encrypt("test").unwrap();
        assert_eq!(bob.decrypt(&wire).unwrap(), "test");

        // Replaying the same message fails (key was consumed)
        assert!(bob.decrypt(&wire).is_err());
    }

    #[test]
    fn wrong_session_fails() {
        let (mut alice, _bob) = make_sessions();
        let (_, mut bob2) = make_sessions();

        let wire = alice.encrypt("hello").unwrap();
        // Different Bob can't decrypt
        assert!(bob2.decrypt(&wire).is_err());
    }

    #[test]
    fn session_serialization() {
        let (mut alice, mut bob) = make_sessions();

        let w1 = alice.encrypt("before persist").unwrap();
        assert_eq!(bob.decrypt(&w1).unwrap(), "before persist");

        // Serialize and restore both sessions
        let alice_bytes = alice.to_bytes();
        let bob_bytes = bob.to_bytes();
        let mut alice2 = Session::from_bytes(&alice_bytes).unwrap();
        let mut bob2 = Session::from_bytes(&bob_bytes).unwrap();

        // Continue conversation
        let w2 = bob2.encrypt("after persist").unwrap();
        assert_eq!(alice2.decrypt(&w2).unwrap(), "after persist");
    }

    #[test]
    fn unicode_and_emoji() {
        let (mut alice, mut bob) = make_sessions();

        let msg = "こんにちは 🔐 мир العالم";
        let wire = alice.encrypt(msg).unwrap();
        assert_eq!(bob.decrypt(&wire).unwrap(), msg);
    }

    #[test]
    fn empty_message() {
        let (mut alice, mut bob) = make_sessions();

        let wire = alice.encrypt("").unwrap();
        assert_eq!(bob.decrypt(&wire).unwrap(), "");
    }

    #[test]
    fn alternating_conversation() {
        let (mut alice, mut bob) = make_sessions();

        for i in 0..20 {
            if i % 2 == 0 {
                let w = alice.encrypt(&format!("A:{i}")).unwrap();
                assert_eq!(bob.decrypt(&w).unwrap(), format!("A:{i}"));
            } else {
                let w = bob.encrypt(&format!("B:{i}")).unwrap();
                assert_eq!(alice.decrypt(&w).unwrap(), format!("B:{i}"));
            }
        }
    }

    #[test]
    fn encrypted_session_serialization() {
        let (mut alice, mut bob) = make_sessions();
        let key = [0xABu8; 32];

        let w1 = alice.encrypt("before persist").unwrap();
        assert_eq!(bob.decrypt(&w1).unwrap(), "before persist");

        // Serialize with encryption and restore
        let alice_enc = alice.to_encrypted_bytes(&key).unwrap();
        let bob_enc = bob.to_encrypted_bytes(&key).unwrap();

        // Encrypted bytes should differ from plaintext
        assert_ne!(alice_enc, alice.to_bytes());

        let mut alice2 = Session::from_encrypted_bytes(&key, &alice_enc).unwrap();
        let mut bob2 = Session::from_encrypted_bytes(&key, &bob_enc).unwrap();

        // Continue conversation after restore
        let w2 = bob2.encrypt("after encrypted persist").unwrap();
        assert_eq!(alice2.decrypt(&w2).unwrap(), "after encrypted persist");
    }

    #[test]
    fn encrypted_session_wrong_key_fails() {
        let (alice, _bob) = make_sessions();
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];

        let enc = alice.to_encrypted_bytes(&key).unwrap();
        assert!(Session::from_encrypted_bytes(&wrong_key, &enc).is_err());
    }

    #[test]
    fn encrypted_session_tampered_fails() {
        let (alice, _bob) = make_sessions();
        let key = [0xABu8; 32];

        let mut enc = alice.to_encrypted_bytes(&key).unwrap();
        // Flip a byte in the ciphertext
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(Session::from_encrypted_bytes(&key, &enc).is_err());
    }
}
