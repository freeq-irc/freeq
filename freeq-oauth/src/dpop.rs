//! DPoP (Demonstrating Proof-of-Possession, RFC 9449) key + proof JWT.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

use crate::generate_random_string;

/// A P-256 keypair used to sign DPoP proofs. The private key is
/// serializable (base64url) so a flow can persist it across the
/// authorization redirect and later refreshes.
#[derive(Debug, Clone)]
pub struct DpopKey {
    signing_key: SigningKey,
}

impl DpopKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut rand::thread_rng()),
        }
    }

    /// Serialize the private key as base64url (unpadded) for caching.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes())
    }

    /// Deserialize from base64url.
    pub fn from_base64url(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        let signing_key =
            SigningKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("Invalid DPoP key: {e}"))?;
        Ok(Self { signing_key })
    }

    fn jwk(&self) -> serde_json::Value {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    /// Create a DPoP proof JWT for a request.
    ///
    /// When `access_token` is provided, includes the `ath` (access-token
    /// hash) claim required by RFC 9449 §4.2 when the proof accompanies a
    /// bearer token to a resource server.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<String> {
        use p256::ecdsa::{Signature, signature::Signer};

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.jwk(),
        });
        let mut payload = serde_json::json!({
            "jti": generate_random_string(16),
            "htm": method,
            "htu": url,
            "iat": chrono::Utc::now().timestamp(),
        });
        if let Some(nonce) = nonce {
            payload["nonce"] = serde_json::Value::String(nonce.to_string());
        }
        if let Some(token) = access_token {
            payload["ath"] =
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(jwt: &str) -> serde_json::Value {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn base64url_round_trip() {
        let key = DpopKey::generate();
        let restored = DpopKey::from_base64url(&key.to_base64url()).unwrap();
        assert_eq!(key.to_base64url(), restored.to_base64url());
    }

    #[test]
    fn from_base64url_rejects_garbage() {
        assert!(DpopKey::from_base64url("not-a-key").is_err());
    }

    #[test]
    fn proof_claims_and_ath() {
        let key = DpopKey::generate();
        let p = payload(
            &key.proof("POST", "https://pds/token", Some("N1"), Some("ATOK"))
                .unwrap(),
        );
        assert_eq!(p["htm"], "POST");
        assert_eq!(p["htu"], "https://pds/token");
        assert_eq!(p["nonce"], "N1");
        assert_eq!(
            p["ath"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"ATOK"))
        );

        let p2 = payload(&key.proof("GET", "https://x", None, None).unwrap());
        assert!(p2.get("ath").is_none());
        assert!(p2.get("nonce").is_none());

        // Header carries the public JWK (typ/alg fixed).
        let key3 = DpopKey::generate();
        let proof = key3.proof("POST", "https://x", None, None).unwrap();
        let header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(proof.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["crv"], "P-256");
    }
}
