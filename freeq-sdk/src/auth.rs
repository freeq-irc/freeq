//! AT Protocol authentication helpers.
//!
//! Handles:
//! - Challenge decoding/encoding for SASL ATPROTO-CHALLENGE
//! - ChallengeSigner trait for pluggable signing backends
//! - KeySigner: real cryptographic signing (secp256k1/ed25519)
//! - PdsSessionSigner: PDS session-based authentication (app-password or OAuth)

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::crypto::PrivateKey;
use crate::oauth::DpopKey;

/// The challenge sent by the server during SASL ATPROTO-CHALLENGE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub session_id: String,
    pub nonce: String,
    pub timestamp: i64,
}

/// The response we send back to the server.
///
/// - `method` absent or `"crypto"`: `signature` is a base64url cryptographic signature.
/// - `method` = `"pds-session"`: `signature` is a PDS access JWT (Bearer token, no DPoP).
/// - `method` = `"pds-oauth"`: `signature` is a DPoP-bound access token,
///   `dpop_proof` is a DPoP proof for the PDS getSession endpoint.
///
/// For PDS methods, `challenge_nonce` **must** contain the nonce from the
/// server's challenge.  This binds the PDS-verified session to the specific
/// challenge issued for this connection, preventing token replay across
/// different servers or sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub did: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pds_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_proof: Option<String>,
    /// Echo of the server's challenge nonce.  Required for `pds-session` and
    /// `pds-oauth` methods so the server can verify the response is bound to
    /// the challenge it issued (the PDS itself has no knowledge of our nonce).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_nonce: Option<String>,
    /// The account this agent acts for, whose agent records can admit it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_did: Option<String>,
}

/// Decode a base64url-encoded challenge from the server.
pub fn decode_challenge(encoded: &str) -> anyhow::Result<Challenge> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let challenge: Challenge = serde_json::from_slice(&bytes)?;
    Ok(challenge)
}

/// Decode base64url challenge to raw bytes (for signing).
pub fn decode_challenge_bytes(encoded: &str) -> anyhow::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(encoded)?)
}

/// One SASL chunk, per IRCv3; a full chunk tells the server more is coming.
pub const SASL_CHUNK_LEN: usize = 400;

/// Ceiling on a response, matching what the server will reassemble.
pub const MAX_SASL_RESPONSE_LEN: usize = 8192;

/// The `AUTHENTICATE` lines that carry an encoded response: 400-byte chunks,
/// with a bare `+` after a response that fills its last chunk.
pub fn sasl_response_lines(encoded: &str) -> Vec<String> {
    let mut lines: Vec<String> = encoded
        .as_bytes()
        .chunks(SASL_CHUNK_LEN)
        .map(|c| {
            format!(
                "AUTHENTICATE {}",
                std::str::from_utf8(c).expect("base64url is ASCII")
            )
        })
        .collect();
    if encoded.len().is_multiple_of(SASL_CHUNK_LEN) {
        lines.push("AUTHENTICATE +".to_string());
    }
    lines
}

/// Encode a challenge response as base64url for sending via AUTHENTICATE.
pub fn encode_response(response: &ChallengeResponse) -> String {
    let json = serde_json::to_vec(response).expect("response serialization");
    URL_SAFE_NO_PAD.encode(&json)
}

/// Trait for signing challenges.
pub trait ChallengeSigner: Send + Sync {
    /// The DID this signer authenticates as.
    fn did(&self) -> &str;

    /// Produce the SASL response for the given challenge bytes.
    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse>;

    /// Update the DPoP nonce for PDS OAuth signers. Default is a no-op.
    fn set_dpop_nonce(&self, _nonce: &str) {}
}

/// A real cryptographic signer using a private key.
pub struct KeySigner {
    did: String,
    private_key: PrivateKey,
}

impl KeySigner {
    pub fn new(did: String, private_key: PrivateKey) -> Self {
        Self { did, private_key }
    }
}

impl ChallengeSigner for KeySigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        let signature = self.private_key.sign_base64url(challenge_bytes);
        Ok(ChallengeResponse {
            did: self.did.clone(),
            signature,
            method: None,
            pds_url: None,
            dpop_proof: None,
            challenge_nonce: None, // Not needed: crypto method signs the full challenge
            owner_did: None,
        })
    }
}

/// PDS session-based signer for Bluesky/AT Protocol users.
///
/// Supports two modes:
/// - App-password sessions (plain Bearer token, no DPoP)
/// - OAuth sessions (DPoP-bound token, includes proof for server to forward)
///
/// Token refresh: call `refresh()` to obtain a new access token using
/// the stored refresh JWT. This is useful for long-lived IRC sessions
/// where the access token may expire (typically ~2 hours).
pub struct PdsSessionSigner {
    did: String,
    access_token: std::sync::RwLock<String>,
    refresh_token: std::sync::RwLock<Option<String>>,
    pds_url: String,
    dpop_key: Option<DpopKey>,
    dpop_nonce: std::sync::RwLock<Option<String>>,
}

impl PdsSessionSigner {
    /// Create a signer for an app-password session (no DPoP).
    pub fn new(did: String, access_token: String, pds_url: String) -> Self {
        Self {
            did,
            access_token: std::sync::RwLock::new(access_token),
            refresh_token: std::sync::RwLock::new(None),
            pds_url,
            dpop_key: None,
            dpop_nonce: std::sync::RwLock::new(None),
        }
    }

    /// Create a signer for an app-password session, with refresh token.
    pub fn new_with_refresh(
        did: String,
        access_token: String,
        refresh_token: String,
        pds_url: String,
    ) -> Self {
        Self {
            did,
            access_token: std::sync::RwLock::new(access_token),
            refresh_token: std::sync::RwLock::new(Some(refresh_token)),
            pds_url,
            dpop_key: None,
            dpop_nonce: std::sync::RwLock::new(None),
        }
    }

    /// Create a signer for an OAuth session (with DPoP).
    pub fn new_oauth(
        did: String,
        access_token: String,
        pds_url: String,
        dpop_key: DpopKey,
        dpop_nonce: Option<String>,
    ) -> Self {
        Self {
            did,
            access_token: std::sync::RwLock::new(access_token),
            refresh_token: std::sync::RwLock::new(None),
            pds_url,
            dpop_key: Some(dpop_key),
            dpop_nonce: std::sync::RwLock::new(dpop_nonce),
        }
    }

    /// Get the current access token.
    pub fn access_token(&self) -> String {
        self.access_token.read().unwrap().clone()
    }

    /// Get the PDS URL.
    pub fn pds_url(&self) -> &str {
        &self.pds_url
    }

    /// Update the DPoP nonce (used when the PDS rotates nonces during SASL).
    pub fn set_dpop_nonce(&self, nonce: String) {
        *self.dpop_nonce.write().unwrap() = Some(nonce);
    }

    /// Refresh the session using the stored refresh token.
    ///
    /// Returns `Ok(())` if the token was refreshed, `Err` if no refresh
    /// token is stored or the PDS rejected it.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let refresh_jwt = self
            .refresh_token
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;

        let new_session = crate::pds::refresh_session(&self.pds_url, &refresh_jwt).await?;

        *self.access_token.write().unwrap() = new_session.access_jwt;
        *self.refresh_token.write().unwrap() = Some(new_session.refresh_jwt);

        Ok(())
    }
}

impl ChallengeSigner for PdsSessionSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn set_dpop_nonce(&self, nonce: &str) {
        *self.dpop_nonce.write().unwrap() = Some(nonce.to_string());
    }

    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        let access_token = self.access_token.read().unwrap().clone();

        // Extract the nonce from the challenge so we can echo it back,
        // binding this response to the specific challenge the server issued.
        let challenge_nonce = serde_json::from_slice::<Challenge>(challenge_bytes)
            .ok()
            .map(|c| c.nonce);

        if let Some(ref dpop_key) = self.dpop_key {
            // OAuth mode: create a DPoP proof targeting the PDS getSession endpoint.
            let get_session_url = format!(
                "{}/xrpc/com.atproto.server.getSession",
                self.pds_url.trim_end_matches('/')
            );

            let dpop_nonce = self.dpop_nonce.read().unwrap().clone();
            let dpop_proof = if let Some(ref nonce) = dpop_nonce {
                dpop_key.proof("GET", &get_session_url, Some(nonce), Some(&access_token))?
            } else {
                dpop_key.proof("GET", &get_session_url, None, Some(&access_token))?
            };

            Ok(ChallengeResponse {
                did: self.did.clone(),
                signature: access_token,
                method: Some("pds-oauth".to_string()),
                pds_url: Some(self.pds_url.clone()),
                dpop_proof: Some(dpop_proof),
                challenge_nonce,
                owner_did: None,
            })
        } else {
            // App-password mode: plain Bearer token
            Ok(ChallengeResponse {
                did: self.did.clone(),
                signature: access_token,
                method: Some("pds-session".to_string()),
                pds_url: Some(self.pds_url.clone()),
                dpop_proof: None,
                challenge_nonce,
                owner_did: None,
            })
        }
    }
}

/// A stub signer for testing only. Returns an error in its respond() method
/// to ensure it can never be used to bypass authentication.
/// Only available in test builds.
#[cfg(test)]
pub struct StubSigner {
    pub did: String,
}

#[cfg(test)]
impl ChallengeSigner for StubSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn respond(&self, _challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        anyhow::bail!(
            "StubSigner cannot produce real signatures; use KeySigner or PdsSessionSigner"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;

    #[test]
    fn key_signer_produces_valid_signature() {
        let private_key = PrivateKey::generate_secp256k1();
        let public_key = private_key.public_key();

        let signer = KeySigner::new("did:plc:test".to_string(), private_key);

        let challenge_bytes = b"test challenge data";
        let response = signer.respond(challenge_bytes).unwrap();

        assert!(response.method.is_none());
        assert!(response.dpop_proof.is_none());
        let sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
        public_key.verify(challenge_bytes, &sig_bytes).unwrap();
    }

    #[test]
    fn pds_session_signer_bearer() {
        let signer = PdsSessionSigner::new(
            "did:plc:test".to_string(),
            "jwt-token-here".to_string(),
            "https://pds.example.com".to_string(),
        );

        let challenge = Challenge {
            session_id: "sess-1".to_string(),
            nonce: "test-nonce-abc".to_string(),
            timestamp: 1000,
        };
        let challenge_bytes = serde_json::to_vec(&challenge).unwrap();
        let response = signer.respond(&challenge_bytes).unwrap();
        assert_eq!(response.method.as_deref(), Some("pds-session"));
        assert!(response.dpop_proof.is_none());
        assert_eq!(response.signature, "jwt-token-here");
        assert_eq!(response.challenge_nonce.as_deref(), Some("test-nonce-abc"));
    }

    #[test]
    fn pds_session_signer_oauth_dpop() {
        let dpop_key = DpopKey::generate();
        let signer = PdsSessionSigner::new_oauth(
            "did:plc:test".to_string(),
            "dpop-bound-token".to_string(),
            "https://pds.example.com".to_string(),
            dpop_key,
            Some("test-nonce".to_string()),
        );

        let challenge = Challenge {
            session_id: "sess-2".to_string(),
            nonce: "test-nonce-def".to_string(),
            timestamp: 2000,
        };
        let challenge_bytes = serde_json::to_vec(&challenge).unwrap();
        let response = signer.respond(&challenge_bytes).unwrap();
        assert_eq!(response.method.as_deref(), Some("pds-oauth"));
        assert!(response.dpop_proof.is_some());
        assert_eq!(response.pds_url.as_deref(), Some("https://pds.example.com"));
        assert_eq!(response.challenge_nonce.as_deref(), Some("test-nonce-def"));
    }

    #[test]
    fn challenge_response_roundtrip() {
        let resp = ChallengeResponse {
            did: "did:plc:abc".to_string(),
            signature: "dGVzdA".to_string(),
            method: None,
            pds_url: None,
            dpop_proof: None,
            challenge_nonce: None,
            owner_did: None,
        };
        let encoded = encode_response(&resp);
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let decoded: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.did, resp.did);
        assert!(decoded.method.is_none());
        assert!(decoded.dpop_proof.is_none());
    }

    #[test]
    fn pds_oauth_response_roundtrip() {
        let resp = ChallengeResponse {
            did: "did:plc:abc".to_string(),
            signature: "dpop.bound.token".to_string(),
            method: Some("pds-oauth".to_string()),
            pds_url: Some("https://pds.example.com".to_string()),
            dpop_proof: Some("dpop.proof.jwt".to_string()),
            challenge_nonce: Some("server-nonce-xyz".to_string()),
            owner_did: None,
        };
        let encoded = encode_response(&resp);
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let decoded: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.method.as_deref(), Some("pds-oauth"));
        assert_eq!(decoded.dpop_proof.as_deref(), Some("dpop.proof.jwt"));
    }
}
