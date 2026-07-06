//! AT Protocol OAuth engine shared by the freeq server, the standalone
//! auth broker, and the client SDK.
//!
//! This crate is deliberately **pure protocol**: it holds the DPoP key
//! type, PKCE/nonce helpers, client-id construction, the auth-server
//! metadata shapes, and (in `flow`) the discovery / PAR / code-exchange /
//! refresh dance. It never constructs its own `reqwest::Client` — every
//! network function takes an injected client so the caller owns the
//! SSRF / timeout / DNS-pinning policy:
//!
//!   - `freeq-server` injects an SSRF-guarded, DNS-pinned client,
//!   - `freeq-auth-broker` injects a bounded-timeout client,
//!   - `freeq-sdk` (loopback CLI) injects a plain client.
//!
//! It must never depend on `freeq-sdk` — that would drag the SDK (and its
//! e2ee/ratchet/av modules) into the slim broker binary, defeating the
//! reason this crate exists.

mod dpop;

pub use dpop::DpopKey;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The union of OAuth scopes any freeq flow may request, advertised in
/// `client-metadata.json` and the loopback `client_id`. Individual flows
/// request narrower scopes (login asks for `atproto` only); this union
/// exists because the AT Protocol OAuth spec requires that any scope used
/// at `/authorize` also appear in the client metadata.
///
/// `transition:generic` is kept for the refresh-token grace period: refresh
/// tokens issued under the old wide grant must still be refreshable, and
/// some PDSes verify the original grant scope is still permitted by current
/// metadata. Fresh `/authorize` requests never ask for it. Remove once the
/// PDS ecosystem has fully sunset transitional scopes.
pub const CLIENT_METADATA_SCOPE: &str =
    "atproto blob:image/* repo:blue.irc.media?action=create repo:app.bsky.feed.post transition:generic";

/// Generate a PKCE (verifier, S256 challenge) pair.
pub fn generate_pkce() -> (String, String) {
    use sha2::{Digest, Sha256};
    let verifier = generate_random_string(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Generate `len` random bytes, base64url-encoded (unpadded).
pub fn generate_random_string(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Percent-encode a string for use in a URL query component.
pub fn urlencode(s: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Build the OAuth `client_id`.
///
/// Loopback origins (`http://127.*`, `http://192.168.*`, `http://10.*`)
/// use the `http://localhost?redirect_uri=…&scope=…` form the AT Protocol
/// spec defines for development clients; everything else uses the URL of
/// the hosted `client-metadata.json` document. The advertised scope is the
/// full [`CLIENT_METADATA_SCOPE`] union in both cases.
pub fn build_client_id(web_origin: &str, redirect_uri: &str) -> String {
    if web_origin.starts_with("http://127.")
        || web_origin.starts_with("http://192.168.")
        || web_origin.starts_with("http://10.")
    {
        format!(
            "http://localhost?redirect_uri={}&scope={}",
            urlencode(redirect_uri),
            urlencode(CLIENT_METADATA_SCOPE),
        )
    } else {
        format!("{web_origin}/client-metadata.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_loopback_vs_production() {
        assert_eq!(
            build_client_id("https://auth.freeq.at", "https://auth.freeq.at/auth/callback"),
            "https://auth.freeq.at/client-metadata.json"
        );
        let local = build_client_id("http://127.0.0.1:8081", "http://127.0.0.1:8081/auth/callback");
        assert!(local.starts_with("http://localhost?redirect_uri="));
        assert!(local.contains("scope="));
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        use sha2::{Digest, Sha256};
        let (verifier, challenge) = generate_pkce();
        assert_eq!(challenge, URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
    }
}
