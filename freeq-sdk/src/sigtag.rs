//! The `+freeq.at/sig` tag format — shared by every freeq signing profile.
//!
//! One format, several profiles. A profile (see [`crate::act`] for actions,
//! [`crate::chatsig`] for chat) decides *what bytes* get signed; this module
//! decides how the signature travels and how the key that made it is named:
//!
//! ```text
//! +freeq.at/sig=ed25519:<kid>:<base64url-nopad signature>
//! ```
//!
//! `kid` is the base64url (unpadded) encoding of the first 16 bytes of
//! SHA-256 over the raw 32-byte ed25519 public key. A hash-derived key id is
//! self-certifying: whatever key a lookup returns can be checked against the
//! kid the signature named, so a key server cannot *substitute* a different
//! key under an existing signature without the substitution being detectable.
//! (It can still lie at registration time about which key belongs to a DID —
//! that binding gap closes only with DID-document anchoring.)
//!
//! ## Invalid is not unverifiable
//!
//! [`SigError::is_unverifiable`] draws the line the act RFC insists on: a
//! *bad* signature is evidence of tampering and may be rejected, while a
//! signature we merely cannot check yet — an algorithm this build doesn't
//! know, a key we can't currently resolve — must never be reported as
//! forgery. Callers that classify verdicts go through that method rather
//! than matching variants, so the classification lives in one place.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Wire name of the signature tag (also accepted without the leading `+`).
pub const SIG_TAG: &str = "+freeq.at/sig";

/// Why a signature did not verify.
#[derive(Debug, PartialEq, Eq)]
pub enum SigError {
    /// The tag value is not `alg:kid:sig`, or the signature is not 64 bytes.
    BadFormat,
    /// The tag names an algorithm this implementation does not know.
    /// **Unverifiable, not invalid** — a newer signer, not a forger.
    UnsupportedAlgorithm(String),
    /// The supplied public key does not hash to the kid the signature names,
    /// i.e. this is not the key that signed. **Unverifiable, not invalid** —
    /// a lookup-layer miss, not evidence about the bytes.
    KidMismatch,
    /// The named key was used and the bytes still don't verify: something
    /// covered was added, stripped or altered — or the signature is forged.
    Invalid,
}

impl SigError {
    /// Whether this failure means "cannot check yet" rather than "bad".
    ///
    /// Only [`SigError::Invalid`] is evidence about the signed bytes.
    /// `BadFormat` is malformed input rather than a verdict on a signer, and
    /// is grouped with unverifiable so a garbled relay is never reported as
    /// forgery.
    pub fn is_unverifiable(&self) -> bool {
        !matches!(self, SigError::Invalid)
    }
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigError::BadFormat => write!(f, "sig tag is not alg:kid:sig"),
            SigError::UnsupportedAlgorithm(a) => write!(f, "unsupported sig algorithm {a}"),
            SigError::KidMismatch => write!(f, "public key does not match the sig's kid"),
            SigError::Invalid => write!(f, "signature does not verify over the signed bytes"),
        }
    }
}

impl std::error::Error for SigError {}

/// Derive the key id from a raw ed25519 public key: base64url (unpadded) of
/// the first 16 bytes of SHA-256 over the raw key bytes.
///
/// Takes raw bytes (not a parsed [`VerifyingKey`]) so a key store can derive
/// the same kid for any stored 32-byte blob without curve validation — one kid
/// source shared by every canonical, every store, and the test vectors.
pub fn derive_kid_bytes(pubkey: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pubkey);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Derive the key id for a public key (see [`derive_kid_bytes`]).
pub fn derive_kid(key: &VerifyingKey) -> String {
    derive_kid_bytes(key.as_bytes())
}

/// Parse a sig tag value into (kid, signature bytes).
pub fn parse(sig_tag: &str) -> Result<(&str, [u8; 64]), SigError> {
    use base64::Engine;
    let mut parts = sig_tag.splitn(3, ':');
    let alg = parts.next().ok_or(SigError::BadFormat)?;
    let kid = parts.next().ok_or(SigError::BadFormat)?;
    let sig_b64 = parts.next().ok_or(SigError::BadFormat)?;
    if alg != "ed25519" {
        return Err(SigError::UnsupportedAlgorithm(alg.to_string()));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| SigError::BadFormat)?;
    let sig: [u8; 64] = bytes.try_into().map_err(|_| SigError::BadFormat)?;
    Ok((kid, sig))
}

/// Sign canonical bytes, returning the sig tag value.
pub fn sign_canonical(canonical: &str, key: &SigningKey) -> String {
    use base64::Engine;
    let sig = key.sign(canonical.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("ed25519:{}:{}", derive_kid(&key.verifying_key()), sig_b64)
}

/// Verify a sig tag value over canonical bytes, with `key` as the candidate
/// signer. The kid is checked first, so "wrong key" is distinguishable from
/// "right key, bad bytes" — see [`SigError::is_unverifiable`].
pub fn verify_canonical(
    canonical: &str,
    sig_tag: &str,
    key: &VerifyingKey,
) -> Result<(), SigError> {
    let (kid, sig_bytes) = parse(sig_tag)?;
    if derive_kid(key) != kid {
        return Err(SigError::KidMismatch);
    }
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key.verify(canonical.as_bytes(), &sig)
        .map_err(|_| SigError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn kid_is_22_chars_base64url_and_key_specific() {
        let kid1 = derive_kid(&test_key(1).verifying_key());
        let kid2 = derive_kid(&test_key(2).verifying_key());
        assert_eq!(kid1.len(), 22); // 16 bytes → 22 base64url chars unpadded
        assert_ne!(kid1, kid2);
        assert!(
            kid1.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key(7);
        let tag = sign_canonical("{\"a\":1}", &key);
        assert!(tag.starts_with("ed25519:"));
        verify_canonical("{\"a\":1}", &tag, &key.verifying_key()).unwrap();
    }

    #[test]
    fn altered_bytes_are_invalid_and_only_that_is_a_verdict() {
        let key = test_key(7);
        let tag = sign_canonical("{\"a\":1}", &key);
        let err = verify_canonical("{\"a\":2}", &tag, &key.verifying_key()).unwrap_err();
        assert_eq!(err, SigError::Invalid);
        assert!(!err.is_unverifiable(), "altered bytes are a real verdict");
    }

    #[test]
    fn wrong_key_unknown_algorithm_and_garbage_are_unverifiable() {
        let key = test_key(7);
        let tag = sign_canonical("{\"a\":1}", &key);

        // Right bytes, wrong key: a lookup miss, not forgery evidence.
        let mismatch =
            verify_canonical("{\"a\":1}", &tag, &test_key(8).verifying_key()).unwrap_err();
        assert_eq!(mismatch, SigError::KidMismatch);
        assert!(mismatch.is_unverifiable());

        // A signer using an algorithm we don't know yet.
        let future =
            verify_canonical("{\"a\":1}", "ml-dsa-44:kid:c2ln", &key.verifying_key()).unwrap_err();
        assert_eq!(future, SigError::UnsupportedAlgorithm("ml-dsa-44".into()));
        assert!(future.is_unverifiable());

        // Malformed input, at both the shape and the length guard.
        assert!(
            verify_canonical("{\"a\":1}", "ed25519:onlyonecolon", &key.verifying_key())
                .unwrap_err()
                .is_unverifiable()
        );
        let kid = derive_kid(&key.verifying_key());
        assert_eq!(
            verify_canonical(
                "{\"a\":1}",
                &format!("ed25519:{kid}:AAAA"),
                &key.verifying_key()
            ),
            Err(SigError::BadFormat)
        );
    }
}
