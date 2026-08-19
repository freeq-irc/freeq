//! Authorization-server discovery + Pushed Authorization Request (PAR).
//!
//! Discovery walks two attacker-influenced URLs, so it takes a
//! [`ClientProvider`](crate::ClientProvider) and asks for a client per URL —
//! multi-tenant callers return a fresh SSRF-validated, DNS-pinned client each
//! time; loopback callers reuse one. PAR hits a single endpoint the caller has
//! already validated, so it takes that client directly.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{ClientProvider, DpopKey};

/// Authorization server metadata (RFC 8414 / AT Protocol extensions).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub pushed_authorization_request_endpoint: Option<String>,
}

/// Protected-resource metadata for discovering the authorization server.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// Discover a PDS's authorization server: fetch its
/// `.well-known/oauth-protected-resource`, then that server's
/// `.well-known/oauth-authorization-server`.
///
/// Both URLs are attacker-influenced (the PDS is named by a user-controlled
/// DID document, and it in turn names the auth server), so the client for
/// each hop comes from `provider` — a multi-tenant caller returns a fresh
/// SSRF-validated, DNS-pinned client per URL; a loopback caller reuses one.
pub async fn discover_auth_server<P: ClientProvider>(
    provider: &P,
    pds_url: &str,
) -> Result<AuthServerMetadata> {
    let pr_url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_url.trim_end_matches('/')
    );
    let pr_client = provider.client_for(&pr_url).await?;
    let pr_meta: ProtectedResourceMetadata = pr_client
        .get(&pr_url)
        .send()
        .await
        .context("Failed to fetch protected resource metadata")?
        .error_for_status()
        .context("Protected resource metadata request failed")?
        .json()
        .await
        .context("Failed to parse protected resource metadata")?;

    let auth_server = pr_meta
        .authorization_servers
        .first()
        .context("No authorization servers listed")?;

    let as_url = format!(
        "{}/.well-known/oauth-authorization-server",
        auth_server.trim_end_matches('/')
    );
    let as_client = provider.client_for(&as_url).await?;
    let auth_meta: AuthServerMetadata = as_client
        .get(&as_url)
        .send()
        .await
        .context("Failed to fetch authorization server metadata")?
        .error_for_status()
        .context("Authorization server metadata request failed")?
        .json()
        .await
        .context("Failed to parse authorization server metadata")?;

    Ok(auth_meta)
}

/// Result of a Pushed Authorization Request.
pub struct PushedAuthRequest {
    /// The `request_uri` to hand to the authorization endpoint.
    pub request_uri: String,
    /// The DPoP nonce in force after PAR. Callers that carry it into the
    /// later code exchange (the broker) avoid a wasted nonce round-trip;
    /// callers that don't (the server) may ignore it.
    pub dpop_nonce: Option<String>,
}

/// Perform a Pushed Authorization Request with the DPoP `use_dpop_nonce`
/// retry dance.
///
/// The retry fires only on a 400 whose body carries the canonical
/// `use_dpop_nonce` error (not merely any 400 with a DPoP-Nonce header) —
/// a 400 for a different reason must not be retried into a timeout. This is
/// the standalone broker's (reference) behavior.
#[allow(clippy::too_many_arguments)]
pub async fn pushed_authorization_request(
    client: &reqwest::Client,
    par_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    login_hint: &str,
    scope: &str,
    dpop_key: &DpopKey,
) -> Result<PushedAuthRequest> {
    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("scope", scope),
        ("state", state),
        ("login_hint", login_hint),
    ];

    let dpop_proof = dpop_key.proof("POST", par_endpoint, None, None)?;
    let resp = client
        .post(par_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .context("PAR request failed")?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let first_body = resp.text().await.unwrap_or_default();

    let par_json: serde_json::Value = if status.as_u16() == 400
        && dpop_nonce.is_some()
        && first_body.contains("use_dpop_nonce")
    {
        let nonce = dpop_nonce.as_deref().unwrap();
        let dpop_proof2 = dpop_key.proof("POST", par_endpoint, Some(nonce), None)?;
        let resp2 = client
            .post(par_endpoint)
            .header("DPoP", &dpop_proof2)
            .form(&params)
            .send()
            .await
            .context("PAR retry request failed")?;
        if !resp2.status().is_success() {
            let status = resp2.status();
            let text = resp2.text().await.unwrap_or_default();
            anyhow::bail!("PAR failed ({status}): {text}");
        }
        resp2.json().await.context("Failed to parse PAR response")?
    } else if status.is_success() {
        serde_json::from_str(&first_body).context("Failed to parse PAR response")?
    } else {
        anyhow::bail!("PAR failed ({status}): {first_body}");
    };

    let request_uri = par_json["request_uri"]
        .as_str()
        .context("No request_uri in PAR response")?
        .to_string();

    Ok(PushedAuthRequest {
        request_uri,
        dpop_nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::{get, post};

    async fn spawn(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://127.0.0.1:{port}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    // ── discover_auth_server ────────────────────────────────────────────

    /// A PDS that points at its own origin as the authorization server.
    fn pds_router(as_meta: serde_json::Value) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("127.0.0.1")
                        .to_string();
                    axum::Json(serde_json::json!({
                        "authorization_servers": [format!("http://{host}")],
                    }))
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(move || {
                    let m = as_meta.clone();
                    async move { axum::Json(m) }
                }),
            )
    }

    #[tokio::test]
    async fn discovers_endpoints() {
        let base = spawn(pds_router(serde_json::json!({
            "issuer": "https://as.example",
            "authorization_endpoint": "https://as.example/authorize",
            "token_endpoint": "https://as.example/token",
            "pushed_authorization_request_endpoint": "https://as.example/par",
        })))
        .await;
        let meta = discover_auth_server(&crate::SharedClient(client()), &base)
            .await
            .unwrap();
        assert_eq!(meta.issuer, "https://as.example");
        assert_eq!(meta.token_endpoint, "https://as.example/token");
        assert_eq!(
            meta.pushed_authorization_request_endpoint.as_deref(),
            Some("https://as.example/par")
        );
    }

    #[tokio::test]
    async fn empty_authorization_servers_is_error() {
        let base = spawn(Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { axum::Json(serde_json::json!({ "authorization_servers": [] })) }),
        ))
        .await;
        assert!(
            discover_auth_server(&crate::SharedClient(client()), &base)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn protected_resource_http_error_is_error() {
        // No routes → 404 on the well-known fetch.
        let base = spawn(Router::new()).await;
        assert!(
            discover_auth_server(&crate::SharedClient(client()), &base)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn malformed_metadata_is_error_not_panic() {
        let base = spawn(Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { "not json" }),
        ))
        .await;
        assert!(
            discover_auth_server(&crate::SharedClient(client()), &base)
                .await
                .is_err()
        );
    }

    // ── pushed_authorization_request ────────────────────────────────────

    async fn par(base: &str) -> Result<PushedAuthRequest> {
        pushed_authorization_request(
            &client(),
            &format!("{base}/par"),
            "client-id",
            "https://app/callback",
            "challenge",
            "state123",
            "alice.test",
            "atproto",
            &DpopKey::generate(),
        )
        .await
    }

    #[tokio::test]
    async fn par_success_first_try() {
        let base = spawn(Router::new().route(
            "/par",
            post(|| async { axum::Json(serde_json::json!({ "request_uri": "urn:req:1" })) }),
        ))
        .await;
        assert_eq!(par(&base).await.unwrap().request_uri, "urn:req:1");
    }

    #[tokio::test]
    async fn par_missing_request_uri_is_error() {
        let base = spawn(Router::new().route(
            "/par",
            post(|| async { axum::Json(serde_json::json!({ "no_uri": true })) }),
        ))
        .await;
        assert!(par(&base).await.is_err());
    }

    #[tokio::test]
    async fn par_retries_only_on_use_dpop_nonce() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = Arc::new(AtomicU32::new(0));
        let h = hits.clone();
        let base = spawn(Router::new().route(
            "/par",
            post(move || {
                let h = h.clone();
                async move {
                    let n = h.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        // First: 400 use_dpop_nonce + nonce header → must retry.
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            [("DPoP-Nonce", "NONCE1")],
                            axum::Json(serde_json::json!({ "error": "use_dpop_nonce" })),
                        )
                            .into_response()
                    } else {
                        axum::response::IntoResponse::into_response(axum::Json(
                            serde_json::json!({ "request_uri": "urn:req:2" }),
                        ))
                    }
                }
            }),
        ))
        .await;
        use axum::response::IntoResponse;
        let out = par(&base).await.unwrap();
        assert_eq!(out.request_uri, "urn:req:2");
        assert_eq!(out.dpop_nonce.as_deref(), Some("NONCE1"));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn par_does_not_retry_non_nonce_400() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = Arc::new(AtomicU32::new(0));
        let h = hits.clone();
        let base = spawn(Router::new().route(
            "/par",
            post(move || {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    // 400 with a nonce header but a DIFFERENT error — must NOT retry.
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        [("DPoP-Nonce", "NONCE1")],
                        axum::Json(serde_json::json!({ "error": "invalid_client_metadata" })),
                    )
                }
            }),
        ))
        .await;
        assert!(par(&base).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "must not have retried");
    }
}
