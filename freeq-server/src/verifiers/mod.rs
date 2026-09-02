//! Credential verifiers — architecturally separate from the core protocol.
//!
//! Each verifier is a self-contained module that:
//! 1. Has its own OAuth/API credentials (from env vars)
//! 2. Serves routes under /verify/{provider}/
//! 3. Issues signed VerifiableCredentials
//! 4. POSTs credentials back to a callback URL
//!
//! The freeq protocol knows nothing about these providers.
//! Policies reference verifiers by issuer DID and endpoint URL.
//! Verifiers could run on a completely separate server — they're
//! colocated here for convenience, not coupling.

pub mod bluesky;
pub mod github;
pub mod moderation;
pub mod oidc;

use axum::Router;
use ed25519_dalek::SigningKey;
use std::sync::Arc;

/// Serve a verifier result page. The page's inline script has to carry this
/// nonce; `onclick`-style attributes won't run at all.
pub(crate) fn result_page(html: String, nonce: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [
            ("content-type", "text/html; charset=utf-8".to_string()),
            (
                "content-security-policy",
                format!(
                    "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; \
                     img-src 'self' https: data:"
                ),
            ),
        ],
        html,
    )
        .into_response()
}

/// A single-use nonce for one result page's inline script.
pub(crate) fn script_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Escape text for interpolation into HTML.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─── Shared upstream-fetch helpers ───────────────────────────────────────────

/// Error classification for calls to upstream APIs (Bluesky AppView/PDS,
/// GitHub, …). The distinction matters because verifiers must NEVER collapse
/// a transient failure into a negative answer: "we couldn't reach the API"
/// is not "the user doesn't follow the account".
#[derive(Debug, Clone, PartialEq)]
pub enum FetchError {
    /// 429 / 5xx / network failure — worth retrying, and if retries are
    /// exhausted the user must see a retryable error, not a denial.
    Transient(String),
    /// 4xx (other than 429) or unparseable response — retrying won't help.
    Permanent(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Transient(m) => write!(f, "transient upstream error: {m}"),
            FetchError::Permanent(m) => write!(f, "upstream error: {m}"),
        }
    }
}

impl FetchError {
    /// Classify an HTTP status for retry purposes. `None` = success.
    pub fn from_status(status: reqwest::StatusCode) -> Option<FetchError> {
        if status.is_success() {
            None
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            Some(FetchError::Transient(format!("HTTP {status}")))
        } else {
            Some(FetchError::Permanent(format!("HTTP {status}")))
        }
    }
}

/// Run `f` with bounded retries on [`FetchError::Transient`].
/// Permanent errors return immediately. `base_delay` scales linearly per
/// attempt (attempt 1 sleeps `base_delay`, attempt 2 `2×base_delay`, …);
/// pass `Duration::ZERO` in tests.
pub async fn retry_loop<T, F, Fut>(
    mut f: F,
    max_retries: usize,
    base_delay: std::time::Duration,
) -> Result<T, FetchError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, FetchError>>,
{
    let mut attempt = 0usize;
    loop {
        match f().await {
            Err(e @ FetchError::Transient(_)) if attempt < max_retries => {
                attempt += 1;
                let delay = base_delay * attempt as u32;
                tracing::debug!(attempt, error = %e, "retrying transient upstream error");
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            other => return other,
        }
    }
}

/// GET `url` as JSON with retries on 429/5xx/network errors.
pub async fn get_json_with_retries(
    http: &reqwest::Client,
    url: &str,
    max_retries: usize,
    base_delay: std::time::Duration,
) -> Result<serde_json::Value, FetchError> {
    retry_loop(
        || async {
            let resp = http
                .get(url)
                .header("User-Agent", "freeq-verifier")
                .send()
                .await
                .map_err(|e| FetchError::Transient(format!("request failed: {e}")))?;
            if let Some(err) = FetchError::from_status(resp.status()) {
                return Err(err);
            }
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| FetchError::Permanent(format!("invalid JSON: {e}")))
        },
        max_retries,
        base_delay,
    )
    .await
}

/// Shared state for all verifiers.
pub struct VerifierState {
    /// Ed25519 signing key for issuing credentials.
    pub signing_key: SigningKey,
    /// DID for this verifier instance.
    pub issuer_did: String,
    /// GitHub OAuth credentials (if configured).
    pub github: Option<GitHubConfig>,
    /// OIDC / Google Workspace verifier config (if configured via env).
    pub oidc: Option<oidc::OidcConfig>,
    /// Pending verification flows: state_token → PendingVerification.
    pub pending: parking_lot::Mutex<std::collections::HashMap<String, PendingVerification>>,
    /// Moderator roster: channel → active appointments.
    pub mod_roster: parking_lot::Mutex<moderation::ModRoster>,
}

#[derive(Clone)]
pub struct GitHubConfig {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct PendingVerification {
    pub subject_did: String,
    pub callback_url: String,
    pub provider_params: serde_json::Value,
    pub created_at: std::time::Instant,
}

/// Load or generate a persistent signing key from the given path.
fn load_or_generate_signing_key(path: &std::path::Path) -> SigningKey {
    if path.exists() {
        crate::secrets::tighten_permissions(path);
        if let Ok(data) = std::fs::read(path)
            && let Ok(bytes) = <[u8; 32]>::try_from(data.as_slice())
        {
            let key = SigningKey::from_bytes(&bytes);
            tracing::info!(
                "Loaded existing verifier signing key from {}",
                path.display()
            );
            return key;
        }
        tracing::warn!("Corrupt signing key at {}, regenerating", path.display());
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    if let Err(e) = crate::secrets::write_secret(path, &key.to_bytes()) {
        tracing::error!("Failed to persist signing key to {}: {}", path.display(), e);
    } else {
        tracing::info!(
            "Generated and persisted new verifier signing key to {}",
            path.display()
        );
    }
    key
}

/// Build the verifier router. Returns None if no verifiers are configured.
pub fn router(
    issuer_did: String,
    github: Option<GitHubConfig>,
    data_dir: &std::path::Path,
) -> Option<(Router<()>, Arc<VerifierState>)> {
    let key_path = data_dir.join("verifier-signing-key.secret");
    let signing_key = load_or_generate_signing_key(&key_path);
    let public_key = signing_key.verifying_key();
    let public_key_multibase = format!(
        "z{}",
        bs58::encode([&[0xed, 0x01], public_key.as_bytes().as_slice()].concat()).into_string()
    );

    tracing::info!(
        "Credential verifier initialized: did={}, pubkey={}",
        issuer_did,
        public_key_multibase
    );

    let oidc = oidc::OidcConfig::from_env();
    if let Some(cfg) = &oidc {
        tracing::info!(domain = %cfg.allowed_domain, "OIDC/SSO verifier configured");
    }

    let state = Arc::new(VerifierState {
        signing_key,
        issuer_did: issuer_did.clone(),
        github,
        oidc,
        pending: parking_lot::Mutex::new(std::collections::HashMap::new()),
        mod_roster: parking_lot::Mutex::new(moderation::ModRoster {
            channels: std::collections::HashMap::new(),
        }),
    });

    let mut app = Router::new()
        // DID document — any client can resolve this to get our public key
        // Serve at both .well-known path and did:web spec path (/verify/did.json)
        .route(
            "/verify/.well-known/did.json",
            axum::routing::get(did_document),
        )
        .route("/verify/did.json", axum::routing::get(did_document));

    // Bluesky follower verifier — always available (uses public API, no config needed)
    app = app.merge(bluesky::routes());

    // Moderation verifier — always available
    app = app.merge(moderation::routes());

    // OIDC / SSO verifier — only if OIDC_* env vars are configured
    if state.oidc.is_some() {
        app = app.merge(oidc::routes());
    }

    // GitHub verifier — only if OAuth credentials are configured
    if state.github.is_some() {
        app = app.merge(github::routes());
    }

    let app = app.with_state(Arc::clone(&state));

    Some((app, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn retry_loop_succeeds_after_transient_failures() {
        let calls = AtomicUsize::new(0);
        let result = retry_loop(
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(FetchError::Transient("429".into()))
                    } else {
                        Ok("ok")
                    }
                }
            },
            3,
            std::time::Duration::ZERO,
        )
        .await;
        assert_eq!(result, Ok("ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_loop_gives_up_after_max_retries() {
        let calls = AtomicUsize::new(0);
        let result: Result<(), FetchError> = retry_loop(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(FetchError::Transient("503".into())) }
            },
            2,
            std::time::Duration::ZERO,
        )
        .await;
        assert!(matches!(result, Err(FetchError::Transient(_))));
        // 1 initial + 2 retries
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_loop_does_not_retry_permanent_errors() {
        let calls = AtomicUsize::new(0);
        let result: Result<(), FetchError> = retry_loop(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(FetchError::Permanent("404".into())) }
            },
            5,
            std::time::Duration::ZERO,
        )
        .await;
        assert!(matches!(result, Err(FetchError::Permanent(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn status_classification() {
        assert_eq!(FetchError::from_status(reqwest::StatusCode::OK), None);
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
            Some(FetchError::Transient(_))
        ));
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::BAD_GATEWAY),
            Some(FetchError::Transient(_))
        ));
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::NOT_FOUND),
            Some(FetchError::Permanent(_))
        ));
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::FORBIDDEN),
            Some(FetchError::Permanent(_))
        ));
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(
            html_escape("</code><script>alert(1)</script>"),
            "&lt;/code&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(html_escape(r#"" onload=""#), "&quot; onload=&quot;");
        assert_eq!(html_escape("' onload='"), "&#39; onload=&#39;");
    }

    #[test]
    fn a_result_page_admits_only_its_own_nonce() {
        let nonce = script_nonce();
        let resp = result_page("<p>ok</p>".into(), &nonce);
        let csp = resp
            .headers()
            .get("content-security-policy")
            .expect("result pages must carry their own CSP")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            csp.contains(&format!("script-src 'nonce-{nonce}'")),
            "{csp}"
        );
        // 'unsafe-inline' here would re-admit injected <script> and onclick=.
        assert!(!csp.contains("script-src 'unsafe-inline'"), "{csp}");
    }

    #[test]
    fn script_nonces_are_single_use() {
        assert_ne!(script_nonce(), script_nonce());
    }
}

/// Serve the verifier's DID document with Ed25519 public key.
async fn did_document(
    axum::extract::State(state): axum::extract::State<Arc<VerifierState>>,
) -> impl axum::response::IntoResponse {
    let public_key = state.signing_key.verifying_key();
    let public_key_multibase = format!(
        "z{}",
        bs58::encode([&[0xed, 0x01], public_key.as_bytes().as_slice()].concat()).into_string()
    );
    let key_id = format!("{}#key-1", state.issuer_did);

    axum::Json(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": state.issuer_did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Multikey",
            "controller": state.issuer_did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "assertionMethod": [key_id],
        "authentication": [key_id],
    }))
}
