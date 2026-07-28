//! Sender-keys group encryption with VC-gated, server-blind key distribution (EG1).
//!
//! This is the intended replacement for the broken [`crate::e2ee_did`] `GroupKey`
//! (ENC2), whose key was derived purely from *public* data (member DIDs + channel
//! name), so the server — or anyone who can enumerate membership — could
//! recompute it. That scheme provides **no** confidentiality against the host.
//!
//! EG1 fixes this: the channel's group key is a **random 32-byte secret** that
//! only members ever hold. It is distributed to each member out-of-band of the
//! server's view by *sealing* it to that member's X25519 public key (published
//! in their pre-key bundle). The server relays the sealed blob but can never
//! open it. Membership is gated by the policy/VC framework — the "key steward"
//! only seals to a member after their JOIN cleared policy (e.g. a Google/SAML
//! credential), so authorization and key access share one source of truth.
//!
//! # Roles
//!
//! - **Steward** — an op client (or a company-run bot) that holds the current
//!   [`GroupState`] and seals it to each admitted member. There is no server
//!   custody of the key.
//! - **Member** — holds a long-lived X25519 identity key. Receives a
//!   [`SealedGroupKey`] control message, [`GroupState::open`]s it, then
//!   encrypts/decrypts channel traffic with the recovered [`GroupState`].
//!
//! # Wire formats
//!
//! Channel message (rides in a `+encrypted` PRIVMSG, like ENC1/ENC2):
//! ```text
//! EG1:<epoch>:<nonce-b64>:<ciphertext-b64>
//! ```
//!
//! Sealed key-wrap control message (steward → one member):
//! ```text
//! EGK1:<channel>:<epoch>:<ephemeral-pub-b64>:<nonce-b64>:<ciphertext-b64>
//! ```
//!
//! # Rotation & revocation (the property ENC1/ENC2 lack)
//!
//! On any membership change (leave, kick, or VC expiry — e.g. an offboarded
//! employee), the steward calls [`GroupState::rotate`] to mint a *fresh* random
//! secret at `epoch+1` and re-seals only to the remaining members. The departed
//! member never receives the new epoch's key, so they cannot read new traffic —
//! forward secrecy against membership change. Old ciphertext they already saw
//! stays readable to them (that is inherent to any group scheme without
//! per-message ratcheting; see the doc for the MLS upgrade path).

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Channel-message prefix (EG1 = "encrypted group v1").
pub const EG1_PREFIX: &str = "EG1:";
/// Sealed key-wrap control-message prefix.
pub const EGK1_PREFIX: &str = "EGK1:";

/// The confidential state a member needs to read/write a channel at one epoch.
///
/// The `secret` is 32 bytes of CSPRNG output — **not** derived from any public
/// value. Cloneable so a steward can seal the same epoch to many members.
#[derive(Clone)]
pub struct GroupState {
    /// Channel name (lowercased for domain separation).
    pub channel: String,
    /// Key epoch; increments on every membership change.
    pub epoch: u64,
    /// The random group secret. Never leaves a member's device unsealed.
    secret: [u8; 32],
}

impl GroupState {
    /// Steward: create a brand-new group at epoch 1 with a random secret.
    pub fn create(channel: &str) -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            channel: channel.to_lowercase(),
            epoch: 1,
            secret,
        }
    }

    /// Steward: mint the next epoch with a fresh random secret. Call this on
    /// every membership change, then re-seal to the *remaining* members only.
    pub fn rotate(&self) -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            channel: self.channel.clone(),
            epoch: self.epoch + 1,
            secret,
        }
    }

    /// Per-epoch, per-channel AES-256 message key. Domain-separates epochs so a
    /// nonce collision across epochs can't cross-decrypt, and binds ciphertext
    /// to the channel it was sent in.
    fn message_key(&self) -> [u8; 32] {
        let salt = Sha256::digest(self.channel.as_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.secret);
        let info = format!("freeq-group-msg-v1-{}", self.epoch);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .expect("32 is a valid HKDF-SHA256 length");
        key
    }

    /// Encrypt a channel message → `EG1:<epoch>:<nonce>:<ct>`.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, GroupError> {
        let key = self.message_key();
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| GroupError::BadKey)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| GroupError::Crypto)?;
        Ok(format!(
            "{EG1_PREFIX}{}:{}:{}",
            self.epoch,
            B64.encode(&nonce[..]),
            B64.encode(&ct)
        ))
    }

    /// Decrypt an `EG1:` channel message. Errors on epoch mismatch so the caller
    /// knows it needs the sealed key for a different epoch.
    pub fn decrypt(&self, wire: &str) -> Result<String, GroupError> {
        let body = wire.strip_prefix(EG1_PREFIX).ok_or(GroupError::NotEg1)?;
        let parts: Vec<&str> = body.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(GroupError::Malformed);
        }
        let epoch: u64 = parts[0].parse().map_err(|_| GroupError::Malformed)?;
        if epoch != self.epoch {
            return Err(GroupError::EpochMismatch {
                have: self.epoch,
                got: epoch,
            });
        }
        let nonce_bytes = B64.decode(parts[1]).map_err(|_| GroupError::Malformed)?;
        let ct = B64.decode(parts[2]).map_err(|_| GroupError::Malformed)?;
        if nonce_bytes.len() != 12 {
            return Err(GroupError::Malformed);
        }
        let key = self.message_key();
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| GroupError::BadKey)?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref())
            .map_err(|_| GroupError::Crypto)?;
        String::from_utf8(pt).map_err(|_| GroupError::Utf8)
    }

    /// Steward: seal this epoch's secret to one member's X25519 public key.
    ///
    /// Uses ephemeral-static ECIES: a fresh ephemeral keypair per seal, ECDH to
    /// the member's static key, HKDF to a wrapping key, AES-256-GCM over the
    /// secret. The ephemeral public key travels in the clear (it's public). Only
    /// the holder of the member's static secret can rederive the wrapping key.
    pub fn seal_for(&self, member_pub: &[u8; 32]) -> SealedGroupKey {
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph_secret);
        let member_pub = PublicKey::from(*member_pub);
        let shared = eph_secret.diffie_hellman(&member_pub);

        let wrap_key = wrap_key(shared.as_bytes(), &self.channel, self.epoch);
        let cipher = Aes256Gcm::new_from_slice(&wrap_key).expect("32-byte key");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, self.secret.as_ref())
            .expect("AES-GCM seal cannot fail on valid inputs");

        SealedGroupKey {
            channel: self.channel.clone(),
            epoch: self.epoch,
            ephemeral_pub: eph_pub.to_bytes(),
            nonce: nonce.into(),
            ciphertext: ct,
        }
    }

    /// Member: recover the group state from a sealed key-wrap using your X25519
    /// static secret. This is the only way to obtain the secret — the server,
    /// which relays the [`SealedGroupKey`], cannot.
    pub fn open(sealed: &SealedGroupKey, my_secret: &StaticSecret) -> Result<Self, GroupError> {
        let eph_pub = PublicKey::from(sealed.ephemeral_pub);
        let shared = my_secret.diffie_hellman(&eph_pub);
        let wrap_key = wrap_key(shared.as_bytes(), &sealed.channel, sealed.epoch);
        let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| GroupError::BadKey)?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_ref())
            .map_err(|_| GroupError::Crypto)?;
        let secret: [u8; 32] = pt.try_into().map_err(|_| GroupError::Malformed)?;
        Ok(Self {
            channel: sealed.channel.clone(),
            epoch: sealed.epoch,
            secret,
        })
    }
}

/// A group secret sealed to exactly one member's X25519 public key.
///
/// Safe for the server to store and relay: without the member's static secret
/// it is an opaque AEAD blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedGroupKey {
    pub channel: String,
    pub epoch: u64,
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl SealedGroupKey {
    /// Serialize to `EGK1:<channel>:<epoch>:<eph-pub>:<nonce>:<ct>`.
    pub fn to_wire(&self) -> String {
        format!(
            "{EGK1_PREFIX}{}:{}:{}:{}:{}",
            self.channel,
            self.epoch,
            B64.encode(self.ephemeral_pub),
            B64.encode(self.nonce),
            B64.encode(&self.ciphertext),
        )
    }

    /// Parse an `EGK1:` control message. Channel names cannot contain ':', which
    /// holds for IRC channels, so a fixed field split is unambiguous.
    pub fn from_wire(wire: &str) -> Result<Self, GroupError> {
        let body = wire.strip_prefix(EGK1_PREFIX).ok_or(GroupError::NotEgk1)?;
        let parts: Vec<&str> = body.splitn(5, ':').collect();
        if parts.len() != 5 {
            return Err(GroupError::Malformed);
        }
        let channel = parts[0].to_string();
        let epoch: u64 = parts[1].parse().map_err(|_| GroupError::Malformed)?;
        let ephemeral_pub: [u8; 32] = B64
            .decode(parts[2])
            .map_err(|_| GroupError::Malformed)?
            .try_into()
            .map_err(|_| GroupError::Malformed)?;
        let nonce: [u8; 12] = B64
            .decode(parts[3])
            .map_err(|_| GroupError::Malformed)?
            .try_into()
            .map_err(|_| GroupError::Malformed)?;
        let ciphertext = B64.decode(parts[4]).map_err(|_| GroupError::Malformed)?;
        Ok(Self {
            channel,
            epoch,
            ephemeral_pub,
            nonce,
            ciphertext,
        })
    }
}

/// Derive the AEAD wrapping key from an ECDH shared secret, bound to the channel
/// and epoch so a sealed blob can't be replayed onto a different channel/epoch.
fn wrap_key(shared: &[u8; 32], channel: &str, epoch: u64) -> [u8; 32] {
    let salt = Sha256::digest(channel.to_lowercase().as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let info = format!("freeq-group-keywrap-v1-{epoch}");
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
        .expect("32 is a valid HKDF-SHA256 length");
    key
}

impl GroupState {
    /// Steward helper: seal the current epoch to a set of members, returning
    /// `(member_did, EGK1-wire)` pairs ready to `POST /channels/{c}/groupkeys`
    /// as `{ epoch, keys: { member_did: wire } }`. One call per membership
    /// snapshot; call again after [`GroupState::rotate`] to re-key.
    pub fn seal_batch(&self, members: &[(String, [u8; 32])]) -> Vec<(String, String)> {
        members
            .iter()
            .map(|(did, pk)| (did.clone(), self.seal_for(pk).to_wire()))
            .collect()
    }
}

/// Member helper: from the sealed keys the server returned for us (each an
/// `(epoch, EGK1-wire)` pair, any order), recover the [`GroupState`] for the
/// **newest** epoch we can actually open. Older epochs remain available via
/// [`GroupState::open`] for decrypting history.
pub fn open_best(
    candidates: &[(u64, String)],
    my_secret: &StaticSecret,
) -> Result<GroupState, GroupError> {
    let mut sorted: Vec<&(u64, String)> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.0)); // newest epoch first
    for (_epoch, wire) in sorted {
        if let Ok(sealed) = SealedGroupKey::from_wire(wire)
            && let Ok(state) = GroupState::open(&sealed, my_secret)
        {
            return Ok(state);
        }
    }
    Err(GroupError::Crypto)
}

/// True if `text` is an EG1 channel message.
pub fn is_group_encrypted(text: &str) -> bool {
    text.starts_with(EG1_PREFIX)
}

/// Parse the epoch from an EG1 message without decrypting, so a member can tell
/// whether it already holds the right sealed key.
pub fn parse_epoch(wire: &str) -> Option<u64> {
    wire.strip_prefix(EG1_PREFIX)?
        .split(':')
        .next()?
        .parse()
        .ok()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupError {
    #[error("not an EG1 group message")]
    NotEg1,
    #[error("not an EGK1 sealed key")]
    NotEgk1,
    #[error("malformed message")]
    Malformed,
    #[error("invalid key")]
    BadKey,
    #[error("epoch mismatch: have {have}, got {got} (need the sealed key for that epoch)")]
    EpochMismatch { have: u64, got: u64 },
    #[error("AEAD open failed (wrong recipient, wrong key, or tampered)")]
    Crypto,
    #[error("decrypted data is not valid UTF-8")]
    Utf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn steward_seals_and_member_opens_then_reads() {
        let steward = GroupState::create("#eng");
        let (alice_sk, alice_pk) = member();

        // Steward seals the current epoch to Alice and posts an encrypted message.
        let sealed = steward.seal_for(&alice_pk);
        let msg = steward.encrypt("quarterly numbers attached").unwrap();

        // Server relays both blindly; Alice recovers the key and reads.
        let alice = GroupState::open(&sealed, &alice_sk).unwrap();
        assert_eq!(alice.epoch, steward.epoch);
        assert_eq!(alice.decrypt(&msg).unwrap(), "quarterly numbers attached");
    }

    #[test]
    fn secret_is_not_derivable_from_public_data() {
        // Two channels with the SAME name but independently created must NOT
        // share a key — proving the secret is random, not a function of the
        // (public) channel name the way the broken ENC2 GroupKey was.
        let a = GroupState::create("#eng");
        let b = GroupState::create("#eng");
        let wire = a.encrypt("secret").unwrap();
        // Same epoch, same channel name, but different random secret → fails.
        assert_eq!(a.epoch, b.epoch);
        assert!(matches!(b.decrypt(&wire), Err(GroupError::Crypto)));
    }

    #[test]
    fn wrong_member_cannot_open_the_seal() {
        let steward = GroupState::create("#eng");
        let (_alice_sk, alice_pk) = member();
        let (mallory_sk, _mallory_pk) = member();

        let sealed = steward.seal_for(&alice_pk);
        // Mallory was never sealed to; her static secret can't recover the key.
        assert!(matches!(
            GroupState::open(&sealed, &mallory_sk),
            Err(GroupError::Crypto)
        ));
    }

    #[test]
    fn rotation_revokes_the_departed_member() {
        // Bob is a member at epoch 1, then leaves. Steward rotates to epoch 2
        // and re-seals only to Alice. Bob cannot read epoch-2 traffic.
        let e1 = GroupState::create("#eng");
        let (alice_sk, alice_pk) = member();
        let (bob_sk, bob_pk) = member();

        let bob_e1 = GroupState::open(&e1.seal_for(&bob_pk), &bob_sk).unwrap();
        let msg_e1 = e1.encrypt("visible to bob").unwrap();
        assert_eq!(bob_e1.decrypt(&msg_e1).unwrap(), "visible to bob");

        // Bob leaves → rotate, seal only to Alice.
        let e2 = e1.rotate();
        assert_eq!(e2.epoch, 2);
        let alice_e2 = GroupState::open(&e2.seal_for(&alice_pk), &alice_sk).unwrap();
        let msg_e2 = e2.encrypt("post-offboarding secret").unwrap();

        // Alice reads epoch 2; Bob (still holding only epoch 1) cannot.
        assert_eq!(
            alice_e2.decrypt(&msg_e2).unwrap(),
            "post-offboarding secret"
        );
        assert!(matches!(
            bob_e1.decrypt(&msg_e2),
            Err(GroupError::EpochMismatch { have: 1, got: 2 })
        ));
    }

    #[test]
    fn sealed_key_wire_roundtrips() {
        let steward = GroupState::create("#secret-room");
        let (_sk, pk) = member();
        let sealed = steward.seal_for(&pk);
        let wire = sealed.to_wire();
        assert!(wire.starts_with(EGK1_PREFIX));
        assert_eq!(SealedGroupKey::from_wire(&wire).unwrap(), sealed);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let steward = GroupState::create("#eng");
        let mut wire = steward.encrypt("integrity matters").unwrap();
        // Flip the last base64 char of the ciphertext.
        let last = wire.pop().unwrap();
        wire.push(if last == 'A' { 'B' } else { 'A' });
        assert!(steward.decrypt(&wire).is_err());
    }

    #[test]
    fn parse_epoch_and_detect() {
        let steward = GroupState::create("#eng").rotate().rotate(); // epoch 3
        let wire = steward.encrypt("hi").unwrap();
        assert!(is_group_encrypted(&wire));
        assert_eq!(parse_epoch(&wire), Some(3));
        assert_eq!(parse_epoch("ENC1:x:y"), None);
    }
}
