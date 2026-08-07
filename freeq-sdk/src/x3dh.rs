//! Extended Triple Diffie-Hellman (X3DH) key agreement.
//!
//! Establishes a shared secret between two parties for initializing
//! a Double Ratchet session. One party (Bob) publishes a pre-key bundle;
//! the other (Alice) uses it to derive a shared secret and send an
//! initial message without Bob being online.
//!
//! Reference: <https://signal.org/docs/specifications/x3dh/>
//!
//! # Key Types
//!
//! - **Identity Key (IK)**: Long-term X25519 key, derived from or
//!   bound to the user's DID. Published in pre-key bundle.
//! - **Signed Pre-Key (SPK)**: Medium-term X25519 key, signed by
//!   the identity key. Rotated periodically.
//! - **Ephemeral Key (EK)**: Single-use X25519 key generated per session.
//!
//! # Protocol
//!
//! Alice (initiator) fetches Bob's pre-key bundle and computes:
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)
//! DH2 = DH(EK_A, IK_B)
//! DH3 = DH(EK_A, SPK_B)
//! SK  = HKDF(DH1 || DH2 || DH3)
//! ```
//!
//! Bob computes the same when he receives Alice's initial message.
//!
//! # Wire Format for Pre-Key Bundle
//!
//! Published at the server or via TAGMSG:
//! ```json
//! {
//!   "did": "did:plc:...",
//!   "identity_key": "<base64url 32 bytes>",
//!   "signed_pre_key": "<base64url 32 bytes>",
//!   "spk_signature": "<base64url 64 bytes>",
//!   "spk_id": 1
//! }
//! ```
//!
//! # Wire Format for Initial Message
//!
//! Sent as a TAGMSG or prepended to first encrypted PRIVMSG:
//! ```json
//! {
//!   "identity_key": "<base64url 32 bytes>",
//!   "ephemeral_key": "<base64url 32 bytes>",
//!   "spk_id": 1
//! }
//! ```

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, Verifier};
use x25519_dalek::{PublicKey, StaticSecret};

use aes_gcm::aead::OsRng;

/// A user's long-term encryption identity.
///
/// Includes the X25519 identity key and the current signed pre-key.
/// The identity key is separate from the DID signing key, but bound
/// to it via a signature in the pre-key bundle.
#[derive(Clone)]
pub struct IdentityKeyPair {
    /// X25519 secret key for identity.
    pub secret: StaticSecret,
    /// X25519 public key for identity.
    pub public: PublicKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Restore from a 32-byte secret.
    pub fn from_secret(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the secret key bytes (for persistence).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

/// A signed pre-key pair.
#[derive(Clone)]
pub struct SignedPreKey {
    pub id: u32,
    pub secret: StaticSecret,
    pub public: PublicKey,
    /// Ed25519 signature over the pre-key public bytes, by the DID key.
    pub signature: Vec<u8>,
}

impl SignedPreKey {
    /// Generate and sign a new pre-key.
    pub fn generate(id: u32, did_signing_key: &ed25519_dalek::SigningKey) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let signature = did_signing_key.sign(public.as_bytes()).to_bytes().to_vec();
        Self {
            id,
            secret,
            public,
            signature,
        }
    }

    /// Restore from stored data.
    pub fn from_parts(id: u32, secret_bytes: [u8; 32], signature: Vec<u8>) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self {
            id,
            secret,
            public,
            signature,
        }
    }
}

/// A pre-key bundle published by the responder (Bob).
/// Fetched by the initiator (Alice) to start a session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// The user's DID.
    pub did: String,
    /// X25519 identity public key (base64url).
    pub identity_key: String,
    /// X25519 signed pre-key public key (base64url).
    pub signed_pre_key: String,
    /// Ed25519 signature over the signed pre-key (base64url).
    pub spk_signature: String,
    /// Pre-key ID (for rotation tracking).
    pub spk_id: u32,
}

impl PreKeyBundle {
    /// Build a bundle from key material.
    pub fn new(did: &str, identity: &IdentityKeyPair, spk: &SignedPreKey) -> Self {
        Self {
            did: did.to_string(),
            identity_key: B64.encode(identity.public.as_bytes()),
            signed_pre_key: B64.encode(spk.public.as_bytes()),
            spk_signature: B64.encode(&spk.signature),
            spk_id: spk.id,
        }
    }

    /// Extract the identity public key.
    pub fn identity_public(&self) -> Result<PublicKey, X3dhError> {
        let bytes = B64
            .decode(&self.identity_key)
            .map_err(|_| X3dhError::InvalidBundle)?;
        if bytes.len() != 32 {
            return Err(X3dhError::InvalidBundle);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }

    /// Extract the signed pre-key public key.
    pub fn signed_pre_key_public(&self) -> Result<PublicKey, X3dhError> {
        let bytes = B64
            .decode(&self.signed_pre_key)
            .map_err(|_| X3dhError::InvalidBundle)?;
        if bytes.len() != 32 {
            return Err(X3dhError::InvalidBundle);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }

    /// Verify the signed pre-key signature using a DID ed25519 verifying key.
    pub fn verify_spk_signature(
        &self,
        did_verify_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), X3dhError> {
        let spk_bytes = B64
            .decode(&self.signed_pre_key)
            .map_err(|_| X3dhError::InvalidBundle)?;
        let sig_bytes = B64
            .decode(&self.spk_signature)
            .map_err(|_| X3dhError::InvalidBundle)?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| X3dhError::InvalidSignature)?;
        did_verify_key
            .verify(&spk_bytes, &signature)
            .map_err(|_| X3dhError::InvalidSignature)
    }
}

/// The initial message sent by Alice to Bob to establish the session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InitialMessage {
    /// Alice's X25519 identity public key (base64url).
    pub identity_key: String,
    /// Alice's ephemeral public key (base64url).
    pub ephemeral_key: String,
    /// Which of Bob's pre-keys was used.
    pub spk_id: u32,
    /// Alice's DID (for Bob to resolve her identity key).
    pub did: String,
}

/// Result of X3DH key agreement from the initiator's side.
pub struct InitiatorResult {
    /// Shared secret for Double Ratchet initialization.
    pub shared_secret: [u8; 32],
    /// Bob's signed pre-key (used as initial ratchet key for Alice).
    pub their_ratchet_key: [u8; 32],
    /// Initial message to send to Bob.
    pub initial_message: InitialMessage,
}

/// Initiator (Alice) performs X3DH with Bob's pre-key bundle.
pub fn initiate(
    our_identity: &IdentityKeyPair,
    our_did: &str,
    their_bundle: &PreKeyBundle,
    their_did_verify_key: &ed25519_dalek::VerifyingKey,
) -> Result<InitiatorResult, X3dhError> {
    initiate_with_ephemeral(
        our_identity,
        our_did,
        their_bundle,
        their_did_verify_key,
        StaticSecret::random_from_rng(OsRng),
    )
}

/// [`initiate`], with the ephemeral supplied rather than generated.
///
/// The agreement is otherwise unreproducible: a fresh ephemeral means a fresh
/// secret every run, so nothing can be written down for another implementation
/// to be held to. Callers doing real key agreement want [`initiate`] — an
/// ephemeral reused across sessions is no longer ephemeral.
pub fn initiate_with_ephemeral(
    our_identity: &IdentityKeyPair,
    our_did: &str,
    their_bundle: &PreKeyBundle,
    their_did_verify_key: &ed25519_dalek::VerifyingKey,
    ek_secret: StaticSecret,
) -> Result<InitiatorResult, X3dhError> {
    // Verify the signed pre-key signature before using the bundle
    their_bundle.verify_spk_signature(their_did_verify_key)?;

    let ik_b = their_bundle.identity_public()?;
    let spk_b = their_bundle.signed_pre_key_public()?;

    let ek_public = PublicKey::from(&ek_secret);

    // X3DH: three DH computations
    let dh1 = our_identity.secret.diffie_hellman(&spk_b); // DH(IK_A, SPK_B)
    if dh1.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }
    let dh2 = ek_secret.diffie_hellman(&ik_b); // DH(EK_A, IK_B)
    if dh2.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }
    let dh3 = ek_secret.diffie_hellman(&spk_b); // DH(EK_A, SPK_B)
    if dh3.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }

    // Concatenate and derive shared secret
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let shared_secret = kdf_x3dh(&ikm)?;

    let initial_message = InitialMessage {
        identity_key: B64.encode(our_identity.public.as_bytes()),
        ephemeral_key: B64.encode(ek_public.as_bytes()),
        spk_id: their_bundle.spk_id,
        did: our_did.to_string(),
    };

    Ok(InitiatorResult {
        shared_secret,
        their_ratchet_key: *spk_b.as_bytes(),
        initial_message,
    })
}

/// Responder (Bob) completes X3DH from Alice's initial message.
pub fn respond(
    our_identity: &IdentityKeyPair,
    our_spk: &SignedPreKey,
    initial_msg: &InitialMessage,
) -> Result<([u8; 32], [u8; 32]), X3dhError> {
    let ik_a_bytes = B64
        .decode(&initial_msg.identity_key)
        .map_err(|_| X3dhError::InvalidBundle)?;
    let ek_a_bytes = B64
        .decode(&initial_msg.ephemeral_key)
        .map_err(|_| X3dhError::InvalidBundle)?;

    if ik_a_bytes.len() != 32 || ek_a_bytes.len() != 32 {
        return Err(X3dhError::InvalidBundle);
    }

    let mut ik_a_arr = [0u8; 32];
    ik_a_arr.copy_from_slice(&ik_a_bytes);
    let ik_a = PublicKey::from(ik_a_arr);

    let mut ek_a_arr = [0u8; 32];
    ek_a_arr.copy_from_slice(&ek_a_bytes);
    let ek_a = PublicKey::from(ek_a_arr);

    // Verify pre-key ID matches
    if initial_msg.spk_id != our_spk.id {
        return Err(X3dhError::PreKeyMismatch);
    }

    // X3DH: three DH computations (Bob's side, reversed)
    let dh1 = our_spk.secret.diffie_hellman(&ik_a); // DH(SPK_B, IK_A)
    if dh1.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }
    let dh2 = our_identity.secret.diffie_hellman(&ek_a); // DH(IK_B, EK_A)
    if dh2.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }
    let dh3 = our_spk.secret.diffie_hellman(&ek_a); // DH(SPK_B, EK_A)
    if dh3.as_bytes().iter().all(|&b| b == 0) {
        return Err(X3dhError::SmallSubgroupAttack);
    }

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let shared_secret = kdf_x3dh(&ikm)?;

    // Bob's SPK secret is used as the initial ratchet key
    Ok((shared_secret, our_spk.secret.to_bytes()))
}

/// Derive shared secret from X3DH DH outputs via HKDF.
fn kdf_x3dh(ikm: &[u8]) -> Result<[u8; 32], X3dhError> {
    // 32 bytes of 0xFF as salt (per Signal spec)
    let salt = [0xFF; 32];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), ikm);
    let mut shared = [0u8; 32];
    hk.expand(b"freeq-x3dh-v1", &mut shared)
        .map_err(|_| X3dhError::KdfFailed)?;
    Ok(shared)
}

#[derive(Debug, thiserror::Error)]
pub enum X3dhError {
    #[error("invalid pre-key bundle")]
    InvalidBundle,
    #[error("invalid signature on pre-key")]
    InvalidSignature,
    #[error("pre-key ID mismatch")]
    PreKeyMismatch,
    #[error("KDF failed")]
    KdfFailed,
    #[error("DH computation produced zero shared secret (possible small subgroup attack)")]
    SmallSubgroupAttack,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agreement has to be reproducible from written-down inputs, or no
    /// other implementation can be held to it: same keys, same ephemeral,
    /// same secret, every time — and the same secret the responder reaches.
    #[test]
    fn a_chosen_ephemeral_makes_the_agreement_reproducible() {
        let bob_identity = IdentityKeyPair::from_secret([0x0b; 32]);
        let bob_did_key = ed25519_dalek::SigningKey::from_bytes(&[0x0d; 32]);
        let bob_spk = SignedPreKey::from_parts(
            1,
            [0x0c; 32],
            bob_did_key
                .sign(PublicKey::from(&StaticSecret::from([0x0c; 32])).as_bytes())
                .to_bytes()
                .to_vec(),
        );
        let bob_bundle = PreKeyBundle::new("did:plc:bob", &bob_identity, &bob_spk);
        let alice_identity = IdentityKeyPair::from_secret([0x0a; 32]);

        let first = initiate_with_ephemeral(
            &alice_identity,
            "did:plc:alice",
            &bob_bundle,
            &bob_did_key.verifying_key(),
            StaticSecret::from([0x0e; 32]),
        )
        .unwrap();
        let again = initiate_with_ephemeral(
            &alice_identity,
            "did:plc:alice",
            &bob_bundle,
            &bob_did_key.verifying_key(),
            StaticSecret::from([0x0e; 32]),
        )
        .unwrap();

        assert_eq!(
            first.shared_secret, again.shared_secret,
            "a chosen ephemeral must remove every source of variation"
        );

        let (bob_shared, _) = respond(&bob_identity, &bob_spk, &first.initial_message).unwrap();
        assert_eq!(
            first.shared_secret, bob_shared,
            "the responder must still reach the same secret"
        );
    }

    #[test]
    fn full_x3dh_handshake() {
        // Bob generates keys
        let bob_identity = IdentityKeyPair::generate();
        let bob_did_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let bob_spk = SignedPreKey::generate(1, &bob_did_key);
        let bob_bundle = PreKeyBundle::new("did:plc:bob", &bob_identity, &bob_spk);

        // Verify signature
        let bob_verify_key = bob_did_key.verifying_key();
        bob_bundle.verify_spk_signature(&bob_verify_key).unwrap();

        // Alice initiates
        let alice_identity = IdentityKeyPair::generate();
        let result = initiate(
            &alice_identity,
            "did:plc:alice",
            &bob_bundle,
            &bob_verify_key,
        )
        .unwrap();

        // Bob responds
        let (bob_shared, bob_ratchet_secret) =
            respond(&bob_identity, &bob_spk, &result.initial_message).unwrap();

        // Both derived the same shared secret
        assert_eq!(result.shared_secret, bob_shared);

        // Initialize Double Ratchet sessions
        let mut alice_session =
            crate::ratchet::Session::init_alice(result.shared_secret, result.their_ratchet_key);
        let mut bob_session = crate::ratchet::Session::init_bob(bob_shared, bob_ratchet_secret);

        // Exchange messages
        let w1 = alice_session.encrypt("Hello from X3DH!").unwrap();
        assert_eq!(bob_session.decrypt(&w1).unwrap(), "Hello from X3DH!");

        let w2 = bob_session.encrypt("X3DH works!").unwrap();
        assert_eq!(alice_session.decrypt(&w2).unwrap(), "X3DH works!");
    }

    #[test]
    fn wrong_spk_signature_rejected() {
        let bob_identity = IdentityKeyPair::generate();
        let bob_did_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let bob_spk = SignedPreKey::generate(1, &bob_did_key);
        let bob_bundle = PreKeyBundle::new("did:plc:bob", &bob_identity, &bob_spk);

        // Verify with wrong key
        let wrong_key = ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key();
        assert!(bob_bundle.verify_spk_signature(&wrong_key).is_err());
    }

    #[test]
    fn bundle_serialization() {
        let identity = IdentityKeyPair::generate();
        let did_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let spk = SignedPreKey::generate(1, &did_key);
        let bundle = PreKeyBundle::new("did:plc:test", &identity, &spk);

        let json = serde_json::to_string(&bundle).unwrap();
        let restored: PreKeyBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.did, "did:plc:test");
        assert_eq!(restored.spk_id, 1);
        assert_eq!(restored.identity_key, bundle.identity_key);
    }
}
