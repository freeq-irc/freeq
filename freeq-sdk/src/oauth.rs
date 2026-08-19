//! AT Protocol OAuth 2.0 authentication flow.
//!
//! Implements the browser-based OAuth flow for Bluesky/AT Protocol:
//! 1. Resolve user's PDS and authorization server
//! 2. Start a local HTTP server for the OAuth callback
//! 3. Open the user's browser to authorize
//! 4. Exchange the auth code for tokens (with DPoP binding)
//!
//! No passwords are entered in the terminal — the user authorizes
//! in their browser where they may already be logged in.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail};
// base64 + Digest are only used by the test helpers now that DpopKey/PKCE
// moved to freeq-oauth; Sha256 is still used at module level (HKDF).
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::Digest;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::did::DidResolver;
use crate::pds;

/// Result of a successful OAuth login.
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub did: String,
    pub handle: String,
    pub access_token: String,
    pub pds_url: String,
    pub dpop_key: DpopKey,
    /// DPoP nonce for the PDS (discovered during token exchange or pre-flight).
    pub dpop_nonce: Option<String>,
}

/// Serializable form of an OAuth session for disk caching.
#[derive(Serialize, Deserialize)]
struct CachedSession {
    did: String,
    handle: String,
    access_token: String,
    pds_url: String,
    dpop_key: String,
    dpop_nonce: Option<String>,
}

impl OAuthSession {
    /// Save session to a JSON file (plaintext).
    ///
    /// **Deprecated**: Writes tokens as plaintext JSON. Use
    /// [`save_encrypted`](Self::save_encrypted) instead.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let cached = CachedSession {
            did: self.did.clone(),
            handle: self.handle.clone(),
            access_token: self.access_token.clone(),
            pds_url: self.pds_url.clone(),
            dpop_key: self.dpop_key.to_base64url(),
            dpop_nonce: self.dpop_nonce.clone(),
        };
        let json = serde_json::to_string_pretty(&cached)?;

        // Create parent dirs
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write with restrictive permissions (contains tokens)
        std::fs::write(path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Save session encrypted with AES-256-GCM.
    ///
    /// The `key` must be 32 bytes. Use [`derive_session_key`] to derive one
    /// from a DID and machine-specific material.
    ///
    /// File format: `nonce (12 bytes) || ciphertext+tag`.
    pub fn save_encrypted(&self, path: &std::path::Path, key: &[u8; 32]) -> Result<()> {
        let cached = CachedSession {
            did: self.did.clone(),
            handle: self.handle.clone(),
            access_token: self.access_token.clone(),
            pds_url: self.pds_url.clone(),
            dpop_key: self.dpop_key.to_base64url(),
            dpop_nonce: self.dpop_nonce.clone(),
        };
        let plaintext = serde_json::to_vec(&cached)?;

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        // Create parent dirs
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, &out)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load session from a JSON file (plaintext).
    ///
    /// **Deprecated**: Reads plaintext JSON. Use
    /// [`load_encrypted`](Self::load_encrypted) instead.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let cached: CachedSession = serde_json::from_str(&json)?;
        let dpop_key = DpopKey::from_base64url(&cached.dpop_key)?;
        Ok(Self {
            did: cached.did,
            handle: cached.handle,
            access_token: cached.access_token,
            pds_url: cached.pds_url,
            dpop_key,
            dpop_nonce: cached.dpop_nonce,
        })
    }

    /// Load session from an encrypted file.
    ///
    /// Expects the format produced by [`save_encrypted`](Self::save_encrypted):
    /// `nonce (12 bytes) || ciphertext+tag`.
    pub fn load_encrypted(path: &std::path::Path, key: &[u8; 32]) -> Result<Self> {
        let data = std::fs::read(path)?;
        anyhow::ensure!(data.len() >= 12, "encrypted session file too short");

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption failed (wrong key or tampered file)"))?;

        let cached: CachedSession = serde_json::from_slice(&plaintext)?;
        let dpop_key = DpopKey::from_base64url(&cached.dpop_key)?;
        Ok(Self {
            did: cached.did,
            handle: cached.handle,
            access_token: cached.access_token,
            pds_url: cached.pds_url,
            dpop_key,
            dpop_nonce: cached.dpop_nonce,
        })
    }

    /// Validate the cached session by probing the PDS.
    /// Returns an updated session with a fresh DPoP nonce, or an error.
    pub async fn validate(mut self) -> Result<Self> {
        let nonce = probe_dpop_nonce(&self.pds_url, &self.access_token, &self.dpop_key).await;
        self.dpop_nonce = nonce;

        // Try actually calling getSession to verify the token still works
        let client = reqwest::Client::new();
        let url = format!(
            "{}/xrpc/com.atproto.server.getSession",
            self.pds_url.trim_end_matches('/')
        );
        let proof = self.dpop_key.proof(
            "GET",
            &url,
            self.dpop_nonce.as_deref(),
            Some(&self.access_token),
        )?;
        let resp = client
            .get(&url)
            .header("Authorization", format!("DPoP {}", self.access_token))
            .header("DPoP", &proof)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Cached session is no longer valid ({})", resp.status());
        }

        Ok(self)
    }
}

/// Default path for the cached session file.
pub fn default_session_path(handle: &str) -> std::path::PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    config_dir
        .join("freeq-tui")
        .join(format!("{handle}.session.json"))
}

/// Derive a 32-byte encryption key from a DID and machine-specific material.
///
/// Uses HKDF-SHA256 with the `machine_secret` as input key material and the
/// DID as salt. The `machine_secret` should be something unique to this
/// machine (e.g. a random value stored once, or derived from OS keychain
/// material).
///
/// ```ignore
/// let key = derive_session_key(b"machine-specific-secret", "did:plc:abc123");
/// session.save_encrypted(&path, &key)?;
/// ```
pub fn derive_session_key(machine_secret: &[u8], did: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(did.as_bytes()), machine_secret);
    let mut key = [0u8; 32];
    hk.expand(b"freeq-session-encryption", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Token response from the authorization server.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    sub: Option<String>,
}

// DPoP key + proof now live in the shared engine crate. Re-exported so the
// `freeq_sdk::oauth::DpopKey` path stays stable for downstream consumers
// (freeq-server, freeq-sdk-ffi, etc.).
pub use freeq_oauth::DpopKey;

/// Perform the full OAuth login flow for a Bluesky/AT Protocol handle.
///
/// Opens the user's browser for authorization. Returns an OAuthSession
/// that can be used to create a PdsSessionSigner.
pub async fn login(handle: &str) -> Result<OAuthSession> {
    let resolver = DidResolver::http();

    // 1. Resolve handle → DID → PDS
    tracing::info!("Resolving handle: {handle}");
    let did = resolver
        .resolve_handle(handle)
        .await
        .context("Failed to resolve handle")?;
    let did_doc = resolver
        .resolve(&did)
        .await
        .context("Failed to resolve DID document")?;
    let pds_url = pds::pds_endpoint(&did_doc).context("No PDS service endpoint in DID document")?;
    tracing::info!(did = %did, pds = %pds_url, "Resolved identity");

    // 2. Discover authorization server
    let auth_meta = discover_auth_server(&pds_url).await?;
    tracing::info!(issuer = %auth_meta.issuer, "Found authorization server");

    // 3. Start local callback server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // AT Protocol loopback OAuth:
    // client_id = http://localhost with query params declaring scopes and redirect_uri
    // The auth server infers metadata from these params for loopback clients.
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    // Identity-only scope. Matches the freeq-server's `Login` purpose.
    // Programs that need broader PDS permissions (e.g. blob upload) call
    // their own `step_up()` with a wider scope; this default keeps the
    // CLI consent screen narrow for the common case.
    let scope = "atproto";
    let client_id = format!(
        "http://localhost?redirect_uri={}&scope={}",
        urlencod(&redirect_uri),
        urlencod(scope),
    );

    // 4. Generate PKCE and DPoP key
    let (code_verifier, code_challenge) = generate_pkce();
    let dpop_key = DpopKey::generate();
    let state = generate_random_string(16);

    // 5. PAR (Pushed Authorization Request) — required by Bluesky
    let par_endpoint = auth_meta
        .pushed_authorization_request_endpoint
        .as_deref()
        .context("Authorization server does not support PAR")?;

    let auth_url = push_authorization_request(
        par_endpoint,
        &auth_meta.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &state,
        handle,
        &dpop_key,
    )
    .await?;

    // 6. Open browser
    eprintln!("\nOpening browser for authorization...");
    eprintln!("If the browser doesn't open, visit:\n  {auth_url}\n");
    let _ = open::that(&auth_url);

    // 7. Wait for callback
    let auth_code = wait_for_callback(listener, &state).await?;
    eprintln!("Authorization received. Exchanging token...");

    // 8. Exchange code for tokens
    let (access_token, token_did) = exchange_code(
        &auth_meta.token_endpoint,
        &auth_code,
        &code_verifier,
        &redirect_uri,
        &client_id,
        &dpop_key,
    )
    .await?;

    // 9. Verify DID matches
    check_token_did(&did, token_did.as_deref())?;

    // 10. Probe PDS getSession to discover the DPoP nonce
    //     The PDS will reject our first call but return the nonce we need.
    let dpop_nonce = probe_dpop_nonce(&pds_url, &access_token, &dpop_key).await;

    tracing::info!(did = %did, dpop_nonce = ?dpop_nonce, "OAuth login successful");
    Ok(OAuthSession {
        did,
        handle: handle.to_string(),
        access_token,
        pds_url,
        dpop_key,
        dpop_nonce,
    })
}

/// Verify that the DID asserted by the token response (`sub`), when present,
/// matches the DID we resolved from the user's handle. A mismatch means the
/// authorization server issued a token for someone else — reject it.
fn check_token_did(resolved_did: &str, token_did: Option<&str>) -> Result<()> {
    if let Some(token_did) = token_did
        && token_did != resolved_did
    {
        bail!("DID mismatch: resolved {resolved_did} but token is for {token_did}");
    }
    Ok(())
}

/// Discover the authorization server for a PDS. Thin wrapper over the shared
/// engine; the loopback CLI flow talks only to the user's own PDS, so a plain
/// client (no SSRF guard) is fine.
async fn discover_auth_server(pds_url: &str) -> Result<freeq_oauth::discovery::AuthServerMetadata> {
    freeq_oauth::discovery::discover_auth_server(
        &freeq_oauth::SharedClient(reqwest::Client::new()),
        pds_url,
    )
    .await
}

/// Pushed Authorization Request (PAR). Delegates the request + DPoP nonce
/// dance to the shared engine, then builds the authorization URL to open.
#[allow(clippy::too_many_arguments)]
async fn push_authorization_request(
    par_endpoint: &str,
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    login_hint: &str,
    dpop_key: &DpopKey,
) -> Result<String> {
    let par = freeq_oauth::discovery::pushed_authorization_request(
        &reqwest::Client::new(),
        par_endpoint,
        client_id,
        redirect_uri,
        code_challenge,
        state,
        login_hint,
        // Narrow scope; SDK callers that need PDS write access do a separate
        // wider-scope auth round rather than asking for it on every login.
        "atproto",
        dpop_key,
    )
    .await?;
    Ok(format!(
        "{authorization_endpoint}?client_id={}&request_uri={}",
        urlencod(client_id),
        urlencod(&par.request_uri),
    ))
}

/// Wait for the OAuth callback on the local HTTP server.
async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        let first_line = request.lines().next().unwrap_or("");
        let path = first_line.split_whitespace().nth(1).unwrap_or("/");

        // Parse query string from path
        let query = if let Some(q) = path.split('?').nth(1) {
            q
        } else {
            // Not a callback with query params — send 404 and keep waiting
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
            continue;
        };

        let params: HashMap<&str, &str> = query
            .split('&')
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                Some((parts.next()?, parts.next()?))
            })
            .collect();

        // Check for errors
        if let Some(error) = params.get("error") {
            let desc = params.get("error_description").unwrap_or(&"Unknown error");
            let body = format!(
                "<html><body><h1>Authorization Failed</h1>\
                 <p>{error}: {desc}</p>\
                 <p>You can close this tab.</p></body></html>"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
            bail!("Authorization failed: {error}: {desc}");
        }

        if let (Some(code), Some(state)) = (params.get("code"), params.get("state")) {
            if *state != expected_state {
                bail!("State mismatch in OAuth callback");
            }

            let body = "<html><body><h1>Authorization Successful</h1>\
                        <p>You can close this tab and return to your terminal.</p>\
                        </body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;

            return Ok(code.to_string());
        }

        // No code/state — keep waiting
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }
}

/// Exchange an authorization code for tokens.
async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
    dpop_key: &DpopKey,
) -> Result<(String, Option<String>)> {
    // Shared engine handles the DPoP nonce-retry dance; the loopback CLI
    // flow has no SSRF concern (it talks to the user's own PDS) so a plain
    // client is fine.
    let exchanged = freeq_oauth::flow::exchange_code(
        &reqwest::Client::new(),
        token_endpoint,
        code,
        code_verifier,
        redirect_uri,
        client_id,
        dpop_key,
        None,
    )
    .await?;
    let token_resp: TokenResponse = serde_json::from_value(exchanged.token_response)
        .context("Failed to parse token response")?;
    Ok((token_resp.access_token, token_resp.sub))
}

// ── Helpers ─────────────────────────────────────────────────────────

// PKCE + random-string generation are byte-identical to the shared engine;
// re-use them. (This file keeps its own `urlencod` for now — it preserves
// `-_.~` where the engine's percent-encodes them, and this flow's exact wire
// output isn't covered by the characterization suite yet.)
use freeq_oauth::{generate_pkce, generate_random_string};

/// Probe the PDS getSession endpoint to discover the required DPoP nonce.
/// Returns None if no nonce is required or if the probe fails.
async fn probe_dpop_nonce(pds_url: &str, access_token: &str, dpop_key: &DpopKey) -> Option<String> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.server.getSession",
        pds_url.trim_end_matches('/')
    );

    // Make a request without a nonce — the PDS will reject it but return the nonce
    let proof = dpop_key.proof("GET", &url, None, Some(access_token)).ok()?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", &proof)
        .send()
        .await
        .ok()?;

    resp.headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn urlencod(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Form;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── Mock PDS / auth-server infrastructure ──────────────────────

    /// Serve an axum router on an ephemeral loopback port.
    /// Returns the base URL (e.g. `http://127.0.0.1:54321`).
    async fn spawn_app(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        base
    }

    /// Like `spawn_app`, but the router builder gets the server's own base
    /// URL (needed when metadata responses must reference the server itself).
    async fn spawn_app_with_base(build: impl FnOnce(String) -> Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = build(base.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        base
    }

    /// Decode the payload (claims) segment of a DPoP proof JWT.
    fn proof_payload(proof: &str) -> serde_json::Value {
        let payload_b64 = proof
            .split('.')
            .nth(1)
            .expect("JWT must have a payload segment");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("payload is base64url");
        serde_json::from_slice(&bytes).expect("payload is JSON")
    }

    fn dpop_header(headers: &HeaderMap) -> String {
        headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    /// A mock PDS `getSession` endpoint that behaves like a real one:
    /// - rejects a wrong Authorization header outright (403);
    /// - demands the DPoP proof carry `nonce == "fresh-nonce"`, replying
    ///   401 + `DPoP-Nonce` header + `use_dpop_nonce` body otherwise;
    /// - demands the `ath` claim (RFC 9449 §4.2);
    /// - returns a session document on success.
    fn mock_pds_router(expected_token: &'static str) -> Router {
        Router::new().route(
            "/xrpc/com.atproto.server.getSession",
            get(move |headers: HeaderMap| async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if auth != format!("DPoP {expected_token}") {
                    return (StatusCode::FORBIDDEN, r#"{"error":"InvalidToken"}"#).into_response();
                }
                let payload = proof_payload(&dpop_header(&headers));
                if payload.get("nonce").and_then(|n| n.as_str()) != Some("fresh-nonce") {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [("dpop-nonce", "fresh-nonce")],
                        r#"{"error":"use_dpop_nonce","message":"DPoP nonce required"}"#,
                    )
                        .into_response();
                }
                if payload.get("ath").is_none() {
                    return (StatusCode::UNAUTHORIZED, r#"{"error":"missing ath claim"}"#)
                        .into_response();
                }
                (
                    StatusCode::OK,
                    r#"{"did":"did:plc:test","handle":"alice.test"}"#,
                )
                    .into_response()
            }),
        )
    }

    fn test_session(pds_url: String, access_token: &str) -> OAuthSession {
        OAuthSession {
            did: "did:plc:test".to_string(),
            handle: "alice.test".to_string(),
            access_token: access_token.to_string(),
            pds_url,
            dpop_key: DpopKey::generate(),
            dpop_nonce: None,
        }
    }

    // ── DpopKey ─────────────────────────────────────────────────────

    #[test]
    fn dpop_key_base64url_roundtrip() {
        let key = DpopKey::generate();
        let encoded = key.to_base64url();
        let decoded = DpopKey::from_base64url(&encoded).expect("roundtrip");
        assert_eq!(
            key.to_base64url(),
            decoded.to_base64url(),
            "private key must survive roundtrip"
        );
    }

    #[test]
    fn dpop_key_rejects_garbage() {
        assert!(DpopKey::from_base64url("!!!not base64url!!!").is_err());
        // valid base64url but not a valid P-256 scalar (wrong length)
        let short = URL_SAFE_NO_PAD.encode([0u8; 5]);
        assert!(DpopKey::from_base64url(&short).is_err());
        // all-zero 32-byte scalar is not a valid private key
        let zeros = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(DpopKey::from_base64url(&zeros).is_err());
    }

    #[test]
    fn dpop_proof_structure_and_signature_verify() {
        use p256::ecdsa::signature::Verifier;

        let key = DpopKey::generate();
        let proof = key
            .proof(
                "GET",
                "https://pds.example/xrpc/com.atproto.server.getSession",
                Some("nonce-123"),
                Some("my-access-token"),
            )
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "DPoP proof must be a 3-part JWT");

        // Header
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");

        // Payload
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["htm"], "GET");
        assert_eq!(
            payload["htu"],
            "https://pds.example/xrpc/com.atproto.server.getSession"
        );
        assert_eq!(payload["nonce"], "nonce-123");
        assert!(payload["jti"].as_str().is_some_and(|j| !j.is_empty()));
        let iat = payload["iat"].as_i64().unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!((now - iat).abs() < 30, "iat must be roughly now");
        // ath = base64url(SHA-256(access_token)) per RFC 9449 §4.2
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(b"my-access-token"));
        assert_eq!(payload["ath"], expected_ath);

        // Signature verifies against the embedded JWK
        let x = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(header["jwk"]["y"].as_str().unwrap())
            .unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("ES256 signature must verify against embedded JWK");
    }

    #[test]
    fn dpop_proof_omits_optional_claims() {
        let key = DpopKey::generate();
        let proof = key
            .proof("POST", "https://as.example/par", None, None)
            .unwrap();
        let payload = proof_payload(&proof);
        assert!(payload.get("nonce").is_none(), "no nonce claim when None");
        assert!(payload.get("ath").is_none(), "no ath claim when no token");
    }

    // ── DID mismatch check (login step 9) ───────────────────────────

    #[test]
    fn token_did_match_accepted() {
        assert!(check_token_did("did:plc:abc", Some("did:plc:abc")).is_ok());
    }

    #[test]
    fn token_did_absent_accepted() {
        // Token responses without `sub` are tolerated (sub is optional).
        assert!(check_token_did("did:plc:abc", None).is_ok());
    }

    #[test]
    fn token_did_mismatch_rejected() {
        let err = check_token_did("did:plc:abc", Some("did:plc:evil")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("DID mismatch"), "got: {msg}");
        assert!(msg.contains("did:plc:evil"), "got: {msg}");
    }

    // ── Session persistence ─────────────────────────────────────────

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("freeq-oauth-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn session_save_load_roundtrip() {
        let path = temp_path("plain.session.json");
        let session = test_session("https://pds.example".into(), "tok-1");
        session.save(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
        }

        let loaded = OAuthSession::load(&path).unwrap();
        assert_eq!(loaded.did, session.did);
        assert_eq!(loaded.handle, session.handle);
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.pds_url, session.pds_url);
        assert_eq!(
            loaded.dpop_key.to_base64url(),
            session.dpop_key.to_base64url()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_save_encrypted_load_roundtrip() {
        let path = temp_path("enc.session.bin");
        let key = derive_session_key(b"machine-secret", "did:plc:test");
        let mut session = test_session("https://pds.example".into(), "tok-2");
        session.dpop_nonce = Some("cached-nonce".into());
        session.save_encrypted(&path, &key).unwrap();

        // Ciphertext on disk must not leak the token
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(b"tok-2".len()).any(|w| w == b"tok-2"),
            "access token must not appear in plaintext on disk"
        );

        let loaded = OAuthSession::load_encrypted(&path, &key).unwrap();
        assert_eq!(loaded.access_token, "tok-2");
        assert_eq!(loaded.dpop_nonce.as_deref(), Some("cached-nonce"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_load_encrypted_wrong_key_fails() {
        let path = temp_path("wrongkey.session.bin");
        let key = derive_session_key(b"machine-secret", "did:plc:test");
        let wrong = derive_session_key(b"other-secret", "did:plc:test");
        test_session("https://pds.example".into(), "tok-3")
            .save_encrypted(&path, &key)
            .unwrap();
        let err = OAuthSession::load_encrypted(&path, &wrong).unwrap_err();
        assert!(err.to_string().contains("decryption failed"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_load_encrypted_truncated_fails() {
        let path = temp_path("truncated.session.bin");
        std::fs::write(&path, [0u8; 7]).unwrap();
        let key = derive_session_key(b"machine-secret", "did:plc:test");
        let err = OAuthSession::load_encrypted(&path, &key).unwrap_err();
        assert!(err.to_string().contains("too short"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn derive_session_key_deterministic_and_distinct() {
        let a = derive_session_key(b"secret", "did:plc:alice");
        let b = derive_session_key(b"secret", "did:plc:alice");
        assert_eq!(a, b, "same inputs derive the same key");
        assert_ne!(a, derive_session_key(b"secret", "did:plc:bob"));
        assert_ne!(a, derive_session_key(b"other", "did:plc:alice"));
    }

    // ── OAuthSession::validate against a mock PDS ───────────────────

    #[tokio::test]
    async fn validate_succeeds_and_learns_dpop_nonce() {
        // The probe (no nonce) gets 401 + DPoP-Nonce; validate then calls
        // getSession with the fresh nonce and succeeds.
        let base = spawn_app(mock_pds_router("good-token")).await;
        let session = test_session(base, "good-token");
        let validated = session.validate().await.expect("validate should succeed");
        assert_eq!(validated.dpop_nonce.as_deref(), Some("fresh-nonce"));
    }

    #[tokio::test]
    async fn validate_rejects_expired_token() {
        // PDS that 401s every request without offering a nonce — the way a
        // real PDS answers a token that is simply expired.
        let router = Router::new().route(
            "/xrpc/com.atproto.server.getSession",
            get(|| async {
                (StatusCode::UNAUTHORIZED, r#"{"error":"ExpiredToken"}"#).into_response()
            }),
        );
        let base = spawn_app(router).await;
        let err = test_session(base, "stale-token")
            .validate()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no longer valid"), "got: {err}");
    }

    #[tokio::test]
    async fn validate_rejects_wrong_token() {
        let base = spawn_app(mock_pds_router("the-real-token")).await;
        let err = test_session(base, "attacker-token")
            .validate()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no longer valid"), "got: {err}");
    }

    #[tokio::test]
    async fn validate_unreachable_pds_is_error_not_panic() {
        // Bind a port and immediately free it so nothing is listening.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let result = test_session(base, "tok").validate().await;
        assert!(result.is_err());
    }

    // ── discover_auth_server ────────────────────────────────────────

    #[tokio::test]
    async fn discover_auth_server_happy_path() {
        let base = spawn_app_with_base(|base| {
            let pr_base = base.clone();
            let as_base = base.clone();
            Router::new()
                .route(
                    "/.well-known/oauth-protected-resource",
                    get(move || {
                        let base = pr_base.clone();
                        async move {
                            axum::Json(serde_json::json!({
                                "authorization_servers": [base]
                            }))
                        }
                    }),
                )
                .route(
                    "/.well-known/oauth-authorization-server",
                    get(move || {
                        let base = as_base.clone();
                        async move {
                            axum::Json(serde_json::json!({
                                "issuer": base,
                                "authorization_endpoint": format!("{base}/authorize"),
                                "token_endpoint": format!("{base}/token"),
                                "pushed_authorization_request_endpoint": format!("{base}/par"),
                            }))
                        }
                    }),
                )
        })
        .await;

        let meta = discover_auth_server(&base).await.unwrap();
        assert_eq!(meta.issuer, base);
        assert_eq!(meta.authorization_endpoint, format!("{base}/authorize"));
        assert_eq!(meta.token_endpoint, format!("{base}/token"));
        assert_eq!(
            meta.pushed_authorization_request_endpoint.as_deref(),
            Some(format!("{base}/par").as_str())
        );
    }

    #[tokio::test]
    async fn discover_auth_server_empty_list_is_error() {
        let router = Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { axum::Json(serde_json::json!({"authorization_servers": []})) }),
        );
        let base = spawn_app(router).await;
        let err = discover_auth_server(&base).await.unwrap_err();
        assert!(
            err.to_string().contains("No authorization servers"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn discover_auth_server_malformed_json_is_error() {
        let router = Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { "this is not json" }),
        );
        let base = spawn_app(router).await;
        let err = discover_auth_server(&base).await.unwrap_err();
        assert!(
            err.to_string().contains("protected resource metadata"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn discover_auth_server_http_error_is_error() {
        let router = Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response() }),
        );
        let base = spawn_app(router).await;
        assert!(discover_auth_server(&base).await.is_err());
    }

    // ── exchange_code ───────────────────────────────────────────────

    /// Build a token endpoint whose behavior is driven by the DPoP proof:
    /// without `nonce == required_nonce` it replies 400 + DPoP-Nonce header;
    /// with it, 200 + token JSON. Counts requests.
    fn mock_token_endpoint(required_nonce: &'static str, hits: Arc<AtomicUsize>) -> Router {
        Router::new().route(
            "/token",
            post(
                move |headers: HeaderMap, Form(params): Form<HashMap<String, String>>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if params.get("grant_type").map(String::as_str)
                            != Some("authorization_code")
                        {
                            return (StatusCode::IM_A_TEAPOT, "wrong grant_type").into_response();
                        }
                        let payload = proof_payload(&dpop_header(&headers));
                        if payload.get("nonce").and_then(|n| n.as_str()) != Some(required_nonce) {
                            return (
                                StatusCode::BAD_REQUEST,
                                [("dpop-nonce", required_nonce)],
                                r#"{"error":"use_dpop_nonce"}"#,
                            )
                                .into_response();
                        }
                        (
                            StatusCode::OK,
                            r#"{"access_token":"minted-token","sub":"did:plc:test"}"#,
                        )
                            .into_response()
                    }
                },
            ),
        )
    }

    #[tokio::test]
    async fn exchange_code_success_first_try() {
        let router = Router::new().route(
            "/token",
            post(|Form(params): Form<HashMap<String, String>>| async move {
                if params.get("code").map(String::as_str) != Some("auth-code-1") {
                    return (StatusCode::BAD_REQUEST, "wrong code").into_response();
                }
                (
                    StatusCode::OK,
                    r#"{"access_token":"minted-token","sub":"did:plc:test"}"#,
                )
                    .into_response()
            }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let (token, sub) = exchange_code(
            &format!("{base}/token"),
            "auth-code-1",
            "verifier",
            "http://127.0.0.1:1/callback",
            "client-id",
            &key,
        )
        .await
        .unwrap();
        assert_eq!(token, "minted-token");
        assert_eq!(sub.as_deref(), Some("did:plc:test"));
    }

    #[tokio::test]
    async fn exchange_code_use_dpop_nonce_triggers_retry_with_new_nonce() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = spawn_app(mock_token_endpoint("server-nonce-1", hits.clone())).await;
        let key = DpopKey::generate();
        let (token, sub) = exchange_code(
            &format!("{base}/token"),
            "code",
            "verifier",
            "http://127.0.0.1:1/callback",
            "client-id",
            &key,
        )
        .await
        .expect("retry with fresh nonce should succeed");
        assert_eq!(token, "minted-token");
        assert_eq!(sub.as_deref(), Some("did:plc:test"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "exactly one retry: first attempt without nonce, second with it"
        );
    }

    #[tokio::test]
    async fn exchange_code_retry_is_bounded_no_infinite_loop() {
        // Endpoint that ALWAYS rejects with use_dpop_nonce + a header.
        // A buggy client would loop forever; ours must stop after one retry.
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let router = Router::new().route(
            "/token",
            post(move |_headers: HeaderMap| {
                let hits = hits_c.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::BAD_REQUEST,
                        [("dpop-nonce", "always-stale")],
                        r#"{"error":"use_dpop_nonce"}"#,
                    )
                        .into_response()
                }
            }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let err = exchange_code(
            &format!("{base}/token"),
            "code",
            "verifier",
            "http://127.0.0.1:1/callback",
            "client-id",
            &key,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("Token exchange failed"),
            "got: {err}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "must stop after the single nonce retry"
        );
    }

    #[tokio::test]
    async fn exchange_code_malformed_json_is_error_not_panic() {
        let router = Router::new().route(
            "/token",
            post(|| async { (StatusCode::OK, "garbage{{{not-json").into_response() }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let err = exchange_code(
            &format!("{base}/token"),
            "code",
            "verifier",
            "http://127.0.0.1:1/callback",
            "client-id",
            &key,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse token response"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn exchange_code_http_error_without_nonce_is_error() {
        let router = Router::new().route(
            "/token",
            post(|| async {
                (StatusCode::FORBIDDEN, r#"{"error":"access_denied"}"#).into_response()
            }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let err = exchange_code(
            &format!("{base}/token"),
            "code",
            "verifier",
            "http://127.0.0.1:1/callback",
            "client-id",
            &key,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Token exchange failed"), "got: {msg}");
        assert!(msg.contains("403"), "status should be surfaced, got: {msg}");
    }

    // ── push_authorization_request ──────────────────────────────────

    fn mock_par_endpoint(required_nonce: &'static str, hits: Arc<AtomicUsize>) -> Router {
        Router::new().route(
            "/par",
            post(
                move |headers: HeaderMap, Form(params): Form<HashMap<String, String>>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if params.get("response_type").map(String::as_str) != Some("code")
                            || params.get("code_challenge_method").map(String::as_str)
                                != Some("S256")
                        {
                            return (StatusCode::IM_A_TEAPOT, "bad params").into_response();
                        }
                        let payload = proof_payload(&dpop_header(&headers));
                        if payload.get("nonce").and_then(|n| n.as_str()) != Some(required_nonce) {
                            return (
                                StatusCode::BAD_REQUEST,
                                [("dpop-nonce", required_nonce)],
                                r#"{"error":"use_dpop_nonce"}"#,
                            )
                                .into_response();
                        }
                        (
                            StatusCode::CREATED,
                            r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc123"}"#,
                        )
                            .into_response()
                    }
                },
            ),
        )
    }

    #[tokio::test]
    async fn par_success_returns_authorization_url() {
        let router = Router::new().route(
            "/par",
            post(|| async {
                (
                    StatusCode::CREATED,
                    r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc123"}"#,
                )
                    .into_response()
            }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let url = push_authorization_request(
            &format!("{base}/par"),
            "https://as.example/authorize",
            "client-id",
            "http://127.0.0.1:1/callback",
            "challenge",
            "state-1",
            "alice.test",
            &key,
        )
        .await
        .unwrap();
        assert!(
            url.starts_with("https://as.example/authorize?"),
            "got: {url}"
        );
        assert!(url.contains(&urlencod("client-id")), "got: {url}");
        assert!(
            url.contains(&urlencod("urn:ietf:params:oauth:request_uri:abc123")),
            "got: {url}"
        );
    }

    #[tokio::test]
    async fn par_use_dpop_nonce_triggers_retry() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = spawn_app(mock_par_endpoint("par-nonce-1", hits.clone())).await;
        let key = DpopKey::generate();
        let url = push_authorization_request(
            &format!("{base}/par"),
            "https://as.example/authorize",
            "client-id",
            "http://127.0.0.1:1/callback",
            "challenge",
            "state-1",
            "alice.test",
            &key,
        )
        .await
        .expect("nonce retry should succeed");
        assert!(url.contains("request_uri"), "got: {url}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry with the nonce");
    }

    #[tokio::test]
    async fn par_missing_request_uri_is_error() {
        let router = Router::new().route(
            "/par",
            post(|| async { (StatusCode::CREATED, r#"{"expires_in":60}"#).into_response() }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let err = push_authorization_request(
            &format!("{base}/par"),
            "https://as.example/authorize",
            "client-id",
            "http://127.0.0.1:1/callback",
            "challenge",
            "state-1",
            "alice.test",
            &key,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("No request_uri"), "got: {err}");
    }

    // ── probe_dpop_nonce ────────────────────────────────────────────

    #[tokio::test]
    async fn probe_returns_nonce_from_rejection_header() {
        let router = Router::new().route(
            "/xrpc/com.atproto.server.getSession",
            get(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    [("dpop-nonce", "probe-nonce-1")],
                    r#"{"error":"use_dpop_nonce"}"#,
                )
                    .into_response()
            }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        let nonce = probe_dpop_nonce(&base, "tok", &key).await;
        assert_eq!(nonce.as_deref(), Some("probe-nonce-1"));
    }

    #[tokio::test]
    async fn probe_returns_none_without_nonce_header() {
        let router = Router::new().route(
            "/xrpc/com.atproto.server.getSession",
            get(|| async { (StatusCode::OK, r#"{"did":"did:plc:test"}"#).into_response() }),
        );
        let base = spawn_app(router).await;
        let key = DpopKey::generate();
        assert_eq!(probe_dpop_nonce(&base, "tok", &key).await, None);
    }

    #[tokio::test]
    async fn probe_returns_none_when_pds_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let key = DpopKey::generate();
        assert_eq!(probe_dpop_nonce(&base, "tok", &key).await, None);
    }

    // ── wait_for_callback (loopback redirect handler) ───────────────

    async fn send_raw_request(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 8192];
        match stream.read(&mut buf).await {
            Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
            Err(_) => String::new(), // server may bail before responding
        }
    }

    #[tokio::test]
    async fn callback_returns_code_on_matching_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { wait_for_callback(listener, "state-ok").await });
        let resp = send_raw_request(addr, "/callback?code=the-code&state=state-ok").await;
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        assert!(resp.contains("Authorization Successful"), "got: {resp}");
        let code = task.await.unwrap().unwrap();
        assert_eq!(code, "the-code");
    }

    #[tokio::test]
    async fn callback_rejects_state_mismatch() {
        // CSRF guard: a forged callback with the wrong state must fail.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { wait_for_callback(listener, "expected").await });
        let _ = send_raw_request(addr, "/callback?code=evil&state=forged").await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("State mismatch"), "got: {err}");
    }

    #[tokio::test]
    async fn callback_propagates_authorization_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { wait_for_callback(listener, "state-x").await });
        let resp =
            send_raw_request(addr, "/callback?error=access_denied&error_description=nope").await;
        assert!(resp.contains("Authorization Failed"), "got: {resp}");
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("access_denied"), "got: {err}");
    }

    #[tokio::test]
    async fn callback_ignores_unrelated_requests_then_accepts() {
        // Favicon probes etc. must get a 404 and not consume the flow.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { wait_for_callback(listener, "state-ok").await });
        let resp = send_raw_request(addr, "/favicon.ico").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let resp = send_raw_request(addr, "/callback?code=real-code&state=state-ok").await;
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        assert_eq!(task.await.unwrap().unwrap(), "real-code");
    }

    // ── Helpers ─────────────────────────────────────────────────────

    #[test]
    fn urlencod_passes_unreserved_and_escapes_the_rest() {
        assert_eq!(urlencod("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(urlencod("a b"), "a%20b");
        assert_eq!(urlencod("http://x?y=z&w"), "http%3A%2F%2Fx%3Fy%3Dz%26w");
        // multi-byte UTF-8 is escaped per byte
        assert_eq!(urlencod("é"), "%C3%A9");
    }

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let (verifier, challenge) = generate_pkce();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        assert!(!challenge.contains('='), "must be unpadded base64url");
        // 32 random bytes encode to 43 chars
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn random_strings_are_unique_and_url_safe() {
        let a = generate_random_string(16);
        let b = generate_random_string(16);
        assert_ne!(a, b);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
