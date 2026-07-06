use std::sync::Arc;
use std::time::SystemTime;

use axum::http::Method;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Clone)]
pub struct BrokerConfig {
    pub public_url: String,
    pub freeq_server_url: String,
    pub shared_secret: String,
    pub _db_path: String,
    pub encryption_key: [u8; 32],
}

pub struct BrokerState {
    pub config: BrokerConfig,
    pub pending: Mutex<std::collections::HashMap<String, PendingAuth>>,
    pub db: Mutex<rusqlite::Connection>,
    /// Per-broker-token refresh serialization. AT Proto refresh tokens are
    /// single-use (rotating): the PDS invalidates the old one when it issues a
    /// new one. Concurrent `/session` calls for the same token — which the
    /// reconnect loop and multiple app instances trigger — would each try to
    /// use the same token, and all but the first get `invalid_grant`, wedging
    /// the session. Holding a per-token async lock across the refresh + store
    /// makes concurrent calls queue and reuse the freshly-rotated token
    /// instead of racing it. (Root cause of the 2026-07-03 fast session death.)
    pub refresh_locks: Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

#[derive(Clone)]
pub struct PendingAuth {
    pub handle: String,
    pub did: String,
    pub pds_url: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub dpop_key_b64: String,
    pub dpop_nonce: Option<String>,
    pub mobile: bool,
    pub return_to: Option<String>,
    pub popup: bool,
}

// DPoP key + proof now live in the shared engine crate. Re-exported so
// this crate's `DpopKey` path (and the characterization tests) stay stable.
pub use freeq_oauth::DpopKey;

#[derive(Debug, Deserialize)]
struct DidDocument {
    #[serde(default)]
    service: Vec<DidService>,
}

#[derive(Debug, Deserialize)]
struct DidService {
    #[serde(rename = "type")]
    service_type: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
}

/// Hard-bounded client for every upstream call the broker makes during
/// `/auth/login`. Default reqwest waits forever; if bsky.social or a
/// user's `.well-known` server is slow we'd accumulate stuck requests
/// until the platform's gateway times out — and meanwhile the user
/// stares at a spinner with no actionable error.
///
/// `pool_max_idle_per_host(0)` disables connection reuse — the
/// observed failure mode was the *second* POST to bsky.social/oauth/par
/// (DPoP nonce retry) consistently dying with "error sending request"
/// while the first POST on the same client succeeded. Each call now
/// uses a fresh TCP/TLS connection, which dodges that.
///
/// `http1_only()` similarly avoids HTTP/2 stream-state weirdness; the
/// request volume from this endpoint is tiny so the perf cost is
/// irrelevant.
fn upstream_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        // 30s overall. Individual calls to bsky.social are normally
        // fast (~600ms from a healthy network) but Miren's egress can
        // be slow, so we keep headroom.
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(8))
        // Miren's egress can't reliably open a SECOND TCP connection
        // to bsky.social inside the same login flow — the connect
        // phase consistently `TimedOut`. Reusing the first connection
        // via HTTP/2 multiplexing avoids opening a second TCP socket
        // at all. We explicitly enable keep-alive idle pooling so the
        // second POST piggybacks on the open connection from the first.
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()?)
}

async fn resolve_handle(handle: &str) -> Result<String, anyhow::Error> {
    let client = upstream_client()?;
    // Try HTTPS well-known first
    let url = format!("https://{handle}/.well-known/atproto-did");
    if let Ok(resp) = client.get(&url).send().await
        && resp.status().is_success()
    {
        let did = resp.text().await?.trim().to_string();
        if did.starts_with("did:") {
            return Ok(did);
        }
    }

    // Fallback to public API (DNS TXT)
    let api_url = format!(
        "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={}",
        handle
    );
    let json: serde_json::Value = client.get(&api_url).send().await?.json().await?;
    let did = json["did"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No DID in response"))?;
    Ok(did.to_string())
}

async fn resolve_did(did: &str) -> Result<DidDocument, anyhow::Error> {
    let client = upstream_client()?;
    if did.starts_with("did:plc:") {
        let url = format!("https://plc.directory/{did}");
        let doc: DidDocument = client.get(&url).send().await?.json().await?;
        return Ok(doc);
    }
    if did.starts_with("did:web:") {
        let domain = did.trim_start_matches("did:web:").replace(':', "/");
        let url = format!("https://{domain}/.well-known/did.json");

        // SSRF protection: resolve hostname and reject private IPs
        let host = domain.split('/').next().unwrap_or(&domain);
        reject_private_host(host).await?;

        let doc: DidDocument = client.get(&url).send().await?.json().await?;
        return Ok(doc);
    }
    Err(anyhow::anyhow!("Unsupported DID method"))
}

/// SSRF protection: resolve a hostname and reject private/loopback IPs.
async fn reject_private_host(host: &str) -> Result<(), anyhow::Error> {
    let host_lower = host.to_lowercase();
    if host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".localhost")
    {
        anyhow::bail!("SSRF blocked: private hostname {host}");
    }

    // If the host is an IP literal, check directly
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            anyhow::bail!("SSRF blocked: private IP {ip}");
        }
        return Ok(());
    }

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(format!("{host}:443"))
        .await?
        .collect();
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            anyhow::bail!(
                "SSRF blocked: {} resolves to private IP {}",
                host,
                addr.ip()
            );
        }
    }
    Ok(())
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

fn pds_endpoint(doc: &DidDocument) -> Option<String> {
    doc.service.iter().find_map(|svc| {
        if svc.service_type == "AtprotoPersonalDataServer" {
            Some(svc.service_endpoint.clone())
        } else {
            None
        }
    })
}

#[derive(Deserialize)]
struct AuthLoginQuery {
    handle: String,
    mobile: Option<String>,
    return_to: Option<String>,
    popup: Option<String>,
}

fn is_truthy(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("yes"))
}

#[derive(Deserialize)]
struct AuthCallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    _iss: Option<String>,
}

#[derive(Deserialize)]
struct BrokerSessionRequest {
    broker_token: String,
}

#[derive(Serialize)]
struct BrokerSessionResponse {
    token: String,
    nick: String,
    did: String,
    handle: String,
}

#[derive(Serialize)]
struct BrokerSessionRecord {
    broker_token: String,
    did: String,
    handle: String,
    pds_url: String,
    token_endpoint: String,
    refresh_token: String,
    dpop_key_b64: String,
    dpop_nonce: Option<String>,
    created_at: i64,
    updated_at: i64,
}

/// Build the broker's axum router over shared state. Used by the
/// standalone binary and by the characterization tests; embedding
/// servers mount this in the unification plan's Phase 3.
pub fn router(state: Arc<BrokerState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/health-v3", get(health_v3))
        .route("/client-metadata.json", get(client_metadata))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/session", post(session))
        .route("/api/graph/follow", post(graph_follow))
        .route("/api/graph/unfollow", post(graph_unfollow))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list([
                    "https://irc.freeq.at".parse().unwrap(),
                    "https://revenant-watch.boxd.sh".parse().unwrap(),
                    "http://localhost:5173".parse().unwrap(),
                    "http://localhost:8000".parse().unwrap(),
                    "http://127.0.0.1:5173".parse().unwrap(),
                ]))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(AllowHeaders::any()),
        )
        .with_state(state)
}

const GIT_COMMIT_FILE: &str = include_str!("../git_commit.txt");

fn git_commit() -> String {
    if let Ok(v) = std::env::var("GIT_HASH")
        && !v.is_empty()
    {
        return v;
    }
    let trimmed = GIT_COMMIT_FILE.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    let built_in = env!("GIT_HASH");
    if !built_in.is_empty() {
        return built_in.to_string();
    }
    "unknown".to_string()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "git_commit": git_commit(),
    }))
}

async fn health_v3() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "git_commit": git_commit(),
    }))
}

async fn client_metadata(State(state): State<Arc<BrokerState>>) -> Json<serde_json::Value> {
    let redirect_uri = format!(
        "{}/auth/callback",
        state.config.public_url.trim_end_matches('/')
    );
    let client_id = build_client_id(&state.config.public_url, &redirect_uri);
    Json(serde_json::json!({
        "client_id": client_id,
        "client_name": "freeq-auth-broker",
        "client_uri": state.config.public_url,
        "logo_uri": format!("{}/freeq.png", state.config.public_url),
        "tos_uri": state.config.public_url,
        "policy_uri": state.config.public_url,
        "redirect_uris": [redirect_uri],
        // Union of scopes the broker may ever request, plus
        // `transition:generic` for backward compat with refresh tokens
        // issued before this change. We never request it at /authorize
        // — the broker only asks for `atproto`. Remove transition:generic
        // once the PDS grace period closes.
        "scope": "atproto blob:image/* repo:blue.irc.media?action=create repo:app.bsky.feed.post transition:generic",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
        "dpop_bound_access_tokens": true
    }))
}

async fn auth_login(
    Query(q): Query<AuthLoginQuery>,
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
) -> Result<Redirect, (StatusCode, String)> {
    let handle = q.handle.trim().to_string();
    let did = resolve_handle(&handle).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Cannot resolve handle: {e}"),
        )
    })?;
    let did_doc = resolve_did(&did)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cannot resolve DID: {e}")))?;
    let pds_url = pds_endpoint(&did_doc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No PDS in DID document".to_string(),
        )
    })?;

    let client = upstream_client().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("upstream client init: {e}"),
        )
    })?;
    let pr_url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_url.trim_end_matches('/')
    );
    let pr_meta: serde_json::Value = client
        .get(&pr_url)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PDS metadata fetch failed: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PDS metadata parse failed: {e}"),
            )
        })?;
    let auth_server = pr_meta["authorization_servers"][0]
        .as_str()
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "No authorization server".to_string(),
            )
        })?;

    let as_url = format!(
        "{}/.well-known/oauth-authorization-server",
        auth_server.trim_end_matches('/')
    );
    let as_resp = client.get(&as_url).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Auth server metadata failed: {e:#?}"),
        )
    })?;
    let as_status = as_resp.status();
    let as_body = as_resp.text().await.unwrap_or_default();
    let auth_meta: serde_json::Value = serde_json::from_str(&as_body).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!(
                "Auth server metadata parse failed: {e} (status={as_status}, body_len={}, body_preview={:?})",
                as_body.len(),
                as_body.chars().take(200).collect::<String>(),
            ),
        )
    })?;

    let authorization_endpoint = auth_meta["authorization_endpoint"]
        .as_str()
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "No authorization_endpoint".to_string(),
            )
        })?;
    let token_endpoint = auth_meta["token_endpoint"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No token_endpoint".to_string()))?;
    let par_endpoint = auth_meta["pushed_authorization_request_endpoint"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No PAR endpoint".to_string()))?;

    let redirect_uri = format!(
        "{}/auth/callback",
        state.config.public_url.trim_end_matches('/')
    );
    // Identity-only scope. The broker's job is to mint a session token
    // for SASL — that needs nothing more than `atproto`. PDS-touching
    // features (image upload, Bluesky cross-post) are step-ups served
    // by the freeq-server's `/auth/step-up`, never the broker.
    let scope = "atproto";
    let client_id = build_client_id(&state.config.public_url, &redirect_uri);

    let dpop_key = DpopKey::generate();
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_random_string(16);

    let params = [
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", &redirect_uri),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("scope", scope),
        ("state", &oauth_state),
        ("login_hint", &handle),
    ];

    let dpop_proof = dpop_key
        .proof("POST", par_endpoint, None, None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DPoP proof failed: {e}"),
            )
        })?;
    let resp = client
        .post(par_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR failed: {e}")))?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Surface the first-PAR response body in logs and require the
    // canonical `use_dpop_nonce` error code before retrying — a 400
    // with an incidental DPoP-Nonce header but a different error
    // (e.g. invalid_client_metadata) should NOT be retried into a
    // timeout; the underlying problem isn't going to resolve.
    let first_body = resp.text().await.unwrap_or_default();
    let body_preview = first_body.chars().take(300).collect::<String>();
    tracing::info!(
        status = %status,
        has_nonce = dpop_nonce.is_some(),
        body = %body_preview,
        "first PAR response"
    );
    let par_resp: serde_json::Value = if status.as_u16() == 400
        && dpop_nonce.is_some()
        && first_body.contains("use_dpop_nonce")
    {
        let nonce = dpop_nonce.as_deref().unwrap();
        let dpop_proof2 = dpop_key
            .proof("POST", par_endpoint, Some(nonce), None)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("DPoP retry failed: {e}"),
                )
            })?;
        // Reuse the SAME client for the retry. Miren's egress couldn't
        // open a second TCP connection to bsky.social within 30s, so
        // we lean on HTTP/2 multiplexing over the first call's still-
        // open connection. Connection pooling is enabled in
        // `upstream_client`.
        let resp2 = client
            .post(par_endpoint)
            .header("DPoP", &dpop_proof2)
            .form(&params)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR retry failed: {e:#?}")))?;
        if !resp2.status().is_success() {
            let text = resp2.text().await.unwrap_or_default();
            return Err((StatusCode::BAD_GATEWAY, format!("PAR failed: {text}")));
        }
        resp2
            .json()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR parse failed: {e}")))?
    } else if status.is_success() {
        serde_json::from_str(&first_body)
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR parse failed: {e}")))?
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("PAR failed ({status}): {first_body}"),
        ));
    };

    let request_uri = par_resp["request_uri"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "No request_uri in PAR response".to_string(),
        )
    })?;

    let _now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut return_to = q.return_to.clone();
    let is_popup = is_truthy(q.popup.as_deref());
    let is_mobile = is_truthy(q.mobile.as_deref());

    // C-6: Validate return_to against allowlist to prevent open redirects
    if let Some(ref rt) = return_to
        && !is_valid_return_to(rt)
    {
        tracing::warn!(return_to = %rt, "Rejected invalid return_to URL");
        return Err((StatusCode::BAD_REQUEST, "Invalid return_to URL".to_string()));
    }

    if return_to.is_none()
        && let Some(referer) = headers.get("referer").and_then(|v| v.to_str().ok())
        && let Ok(url) = url::Url::parse(referer)
    {
        let origin = url.origin().ascii_serialization();
        if is_valid_return_to(&origin) {
            return_to = Some(origin);
        }
    }
    if return_to.is_none() && !is_mobile {
        return_to = Some("https://irc.freeq.at".to_string());
    }

    tracing::info!(handle = %handle, did = %did, popup = %is_popup, return_to = ?return_to, "BROKER_LOGIN_PARAMS_V3");

    state.pending.lock().await.insert(
        oauth_state.clone(),
        PendingAuth {
            handle: handle.clone(),
            did: did.clone(),
            pds_url: pds_url.clone(),
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            client_id: client_id.clone(),
            token_endpoint: token_endpoint.to_string(),
            dpop_key_b64: dpop_key.to_base64url(),
            dpop_nonce: dpop_nonce.clone(),
            mobile: is_mobile,
            return_to,
            popup: is_popup,
        },
    );

    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_endpoint,
        urlencod(&client_id),
        urlencod(request_uri)
    );

    Ok(Redirect::temporary(&auth_url))
}

async fn auth_callback(
    Query(q): Query<AuthCallbackQuery>,
    State(state): State<Arc<BrokerState>>,
) -> Result<Response, (StatusCode, String)> {
    if let Some(err) = q.error.as_deref() {
        let detail = q.error_description.as_deref().unwrap_or(err);
        return Ok(
            Html(oauth_result_page(&format!("OAuth error: {detail}"), None)).into_response(),
        );
    }

    let state_value = match q.state.as_deref() {
        Some(s) => s,
        None => {
            return Ok(
                Html(oauth_result_page("OAuth callback missing state", None)).into_response(),
            );
        }
    };
    let code = match q.code.as_deref() {
        Some(c) => c,
        None => {
            return Ok(Html(oauth_result_page("OAuth callback missing code", None)).into_response());
        }
    };

    let pending = {
        let mut pending_map = state.pending.lock().await;
        pending_map.remove(state_value)
    };
    let pending = match pending {
        Some(p) => p,
        None => return Ok(Html(oauth_result_page("Invalid OAuth state", None)).into_response()),
    };
    tracing::info!(popup = %pending.popup, return_to = ?pending.return_to, "BROKER_CALLBACK_PARAMS_V3");
    let return_to = pending
        .return_to
        .clone()
        .unwrap_or_else(|| "https://irc.freeq.at".to_string());

    let dpop_key = DpopKey::from_base64url(&pending.dpop_key_b64).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid DPoP key: {e}"),
        )
    })?;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", pending.redirect_uri.as_str()),
        ("client_id", pending.client_id.as_str()),
        ("code_verifier", pending.code_verifier.as_str()),
    ];

    let client = reqwest::Client::new();
    // CRITICAL: include any nonce we already have from the PAR step on the FIRST
    // attempt. The PDS consumes the auth code on a failed token request even when
    // the failure is "use_dpop_nonce", so a retry with a fresh nonce gets
    // `invalid_grant: Invalid code`. Sending the known nonce up front avoids this.
    let dpop_proof = dpop_key
        .proof(
            "POST",
            &pending.token_endpoint,
            pending.dpop_nonce.as_deref(),
            None,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DPoP proof failed: {e}"),
            )
        })?;
    let resp = client
        .post(&pending.token_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Token exchange failed: {e}"),
            )
        })?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(pending.dpop_nonce.clone());

    let token_resp: serde_json::Value = if (status.as_u16() == 400 || status.as_u16() == 401)
        && dpop_nonce.is_some()
    {
        let nonce = dpop_nonce.as_deref().unwrap();
        tracing::info!(nonce = %nonce, "DPoP nonce retry for token exchange");
        let dpop_proof2 = dpop_key
            .proof("POST", &pending.token_endpoint, Some(nonce), None)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("DPoP retry failed: {e}"),
                )
            })?;
        let resp2 = client
            .post(&pending.token_endpoint)
            .header("DPoP", &dpop_proof2)
            .form(&params)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token retry failed: {e}")))?;
        let resp2_status = resp2.status();
        if !resp2_status.is_success() {
            let text = resp2.text().await.unwrap_or_default();
            tracing::error!(status = %resp2_status, body = %text, "Token exchange retry failed");
            let err_msg = format!("Token exchange failed: {text}");
            if pending.mobile {
                let redirect = format!("freeq://auth?error={}", urlencod(&err_msg));
                return Ok(axum::response::Redirect::to(&redirect).into_response());
            }
            return Ok(Html(oauth_result_page(&err_msg, None)).into_response());
        }
        resp2
            .json()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {e}")))?
    } else if status.is_success() {
        resp.json()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {e}")))?
    } else {
        let text = resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %text, "Token exchange failed");
        let err_msg = format!("Token exchange failed ({status}): {text}");
        if pending.mobile {
            let redirect = format!("freeq://auth?error={}", urlencod(&err_msg));
            return Ok(axum::response::Redirect::to(&redirect).into_response());
        }
        return Ok(Html(oauth_result_page(&err_msg, None)).into_response());
    };

    let refresh_token = token_resp["refresh_token"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "No refresh_token".to_string()))?;

    let broker_token = generate_random_string(32);
    let now = chrono::Utc::now().timestamp();
    // C-5: Encrypt sensitive fields before storing in DB
    let enc_key = &state.config.encryption_key;
    let encrypted_refresh = encrypt_field(enc_key, refresh_token);
    let encrypted_dpop = encrypt_field(enc_key, &pending.dpop_key_b64);
    let encrypted_nonce = dpop_nonce.as_deref().map(|n| encrypt_field(enc_key, n));
    {
        let db = state.db.lock().await;
        db.execute(
            "INSERT INTO sessions (broker_token, did, handle, pds_url, token_endpoint, refresh_token, dpop_key_b64, dpop_nonce, created_at, updated_at)\
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)\
             ON CONFLICT(broker_token) DO UPDATE SET refresh_token=excluded.refresh_token, updated_at=excluded.updated_at",
            rusqlite::params![
                broker_token,
                pending.did,
                pending.handle,
                pending.pds_url,
                pending.token_endpoint,
                encrypted_refresh,
                encrypted_dpop,
                encrypted_nonce,
                now,
                now
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Mint a one-time web-token + web session on the freeq server. Optional:
    // a standalone broker (not trusted by irc.freeq.at's shared secret) just
    // can't mint one — the verified DID + handle + broker_token are enough for
    // identity-only consumers, so degrade gracefully instead of failing login.
    let (web_token, nick) = mint_web_token(&state.config, &pending.did, &pending.handle)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "web-token mint failed — continuing identity-only");
            (String::new(), pending.handle.clone())
        });

    if let Err(e) = push_web_session(&state.config, &pending, &token_resp, dpop_nonce.clone()).await
    {
        tracing::warn!(error = %e, "Failed to push web session to server");
    }

    if pending.mobile {
        let redirect = format!(
            "freeq://auth?token={}&broker_token={}&nick={}&did={}&handle={}",
            urlencod(&web_token),
            urlencod(&broker_token),
            urlencod(&nick),
            urlencod(&pending.did),
            urlencod(&pending.handle),
        );
        // Must be a 302 redirect — ASWebAuthenticationSession only intercepts
        // HTTP redirects with the custom scheme, not JS/meta-refresh in HTML.
        return Ok(axum::response::Redirect::to(&redirect).into_response());
    }

    let result = serde_json::json!({
        "token": web_token,
        "broker_token": broker_token,
        "nick": nick,
        "did": pending.did,
        "handle": pending.handle,
        "pds_url": pending.pds_url,
    });

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&result).unwrap_or_default());
    let redirect = format!("{return_to}#oauth={payload}");
    tracing::info!(redirect_base = %return_to, "OAuth callback redirecting to app");
    Ok(Redirect::temporary(&redirect).into_response())
}

const ALLOWED_ORIGINS: &[&str] = &[
    "https://irc.freeq.at",
    "https://revenant-watch.boxd.sh",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:5173",
];

async fn session(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(req): Json<BrokerSessionRequest>,
) -> Result<Json<BrokerSessionResponse>, (StatusCode, String)> {
    // M-13: CSRF protection — reject requests from disallowed origins
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && !ALLOWED_ORIGINS.contains(&origin)
    {
        tracing::warn!(origin = %origin, "Rejected /session request from disallowed origin");
        return Err((StatusCode::FORBIDDEN, "Origin not allowed".to_string()));
    }

    // Serialize refresh for this token so concurrent /session calls (reconnect
    // loop, multiple devices) queue and reuse the rotated refresh token rather
    // than racing single-use rotation into `invalid_grant`.
    let token_lock = {
        let mut locks = state.refresh_locks.lock().await;
        locks
            .entry(req.broker_token.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _refresh_guard = token_lock.lock().await;

    // Read the record INSIDE the lock — a caller we queued behind may have just
    // rotated the refresh token, so the on-disk copy is the one to use.
    let record = get_session(&state, &req.broker_token)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid broker token".to_string()))?;

    let (access_token, refresh_token, dpop_nonce, granted_scope) =
        refresh_access_token(&state.config, &record)
            .await
            .map_err(|e| match e {
                // Dead session → 401 so the client shows sign-in, not a retry loop.
                RefreshError::InvalidGrant => (
                    StatusCode::UNAUTHORIZED,
                    "Session expired — re-authentication required".to_string(),
                ),
                RefreshError::Transient(err) => {
                    (StatusCode::BAD_GATEWAY, format!("Refresh failed: {err}"))
                }
            })?;

    // Update stored refresh token + nonce (C-5: encrypt before storing)
    let now = chrono::Utc::now().timestamp();
    let enc_key = &state.config.encryption_key;
    let encrypted_refresh = encrypt_field(enc_key, &refresh_token);
    let encrypted_nonce = dpop_nonce.as_deref().map(|n| encrypt_field(enc_key, n));
    {
        let db = state.db.lock().await;
        db.execute(
            "UPDATE sessions SET refresh_token = ?1, dpop_nonce = ?2, updated_at = ?3 WHERE broker_token = ?4",
            rusqlite::params![encrypted_refresh, encrypted_nonce, now, record.broker_token],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let (web_token, nick) = mint_web_token(&state.config, &record.did, &record.handle)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "web-token mint failed — continuing identity-only");
            (String::new(), record.handle.clone())
        });

    let pending = PendingAuth {
        handle: record.handle.clone(),
        did: record.did.clone(),
        pds_url: record.pds_url.clone(),
        code_verifier: String::new(),
        redirect_uri: String::new(),
        client_id: String::new(),
        token_endpoint: record.token_endpoint.clone(),
        dpop_key_b64: record.dpop_key_b64.clone(),
        dpop_nonce: dpop_nonce.clone(),
        mobile: true,
        return_to: None,
        popup: false,
    };
    if let Err(e) = push_web_session_with_token(
        &state.config,
        &pending,
        &access_token,
        dpop_nonce.clone(),
        // Forward the actually-granted scope from the refresh response so
        // the freeq-server's per-purpose checks see the truth, not a
        // hard-coded narrow assumption.
        &granted_scope,
    )
    .await
    {
        tracing::warn!(error = %e, "Failed to refresh web session on server");
    }

    Ok(Json(BrokerSessionResponse {
        token: web_token,
        nick,
        did: record.did,
        handle: record.handle,
    }))
}

// ── Graph delegation: follow / unfollow ────────────────────────────────────
//
// The client never holds the AT access token (it's DPoP-bound to the broker's
// key anyway). Instead the broker performs the two graph writes on the user's
// own PDS on their behalf, authenticated by the same broker_token as /session.

#[derive(Deserialize)]
struct GraphFollowRequest {
    broker_token: String,
    /// DID of the account to follow.
    #[serde(default)]
    subject_did: Option<String>,
    /// For unfollow: the at:// URI of the existing follow record (the client
    /// already has it from app.bsky.graph.getRelationships).
    #[serde(default)]
    follow_uri: Option<String>,
}

/// Authenticate a broker token and produce a fresh access token, persisting
/// the rotated refresh token — the same discipline as `/session` (shared
/// per-token lock, read-inside-lock, encrypt-before-store).
async fn authed_access_token(
    state: &Arc<BrokerState>,
    broker_token: &str,
) -> Result<(BrokerSessionRecord, String, Option<String>), (StatusCode, String)> {
    let token_lock = {
        let mut locks = state.refresh_locks.lock().await;
        locks
            .entry(broker_token.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _refresh_guard = token_lock.lock().await;

    let record = get_session(state, broker_token)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid broker token".to_string()))?;

    let (access_token, refresh_token, dpop_nonce, _scope) =
        refresh_access_token(&state.config, &record)
            .await
            .map_err(|e| match e {
                RefreshError::InvalidGrant => (
                    StatusCode::UNAUTHORIZED,
                    "Session expired — re-authentication required".to_string(),
                ),
                RefreshError::Transient(err) => {
                    (StatusCode::BAD_GATEWAY, format!("Refresh failed: {err}"))
                }
            })?;

    let now = chrono::Utc::now().timestamp();
    let enc_key = &state.config.encryption_key;
    let encrypted_refresh = encrypt_field(enc_key, &refresh_token);
    let encrypted_nonce = dpop_nonce.as_deref().map(|n| encrypt_field(enc_key, n));
    {
        let db = state.db.lock().await;
        db.execute(
            "UPDATE sessions SET refresh_token = ?1, dpop_nonce = ?2, updated_at = ?3 WHERE broker_token = ?4",
            rusqlite::params![encrypted_refresh, encrypted_nonce, now, record.broker_token],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok((record, access_token, dpop_nonce))
}

/// DPoP-authenticated POST to the user's PDS, with the standard
/// `use_dpop_nonce` retry dance resource servers require.
async fn pds_dpop_post(
    record: &BrokerSessionRecord,
    access_token: &str,
    nonce: Option<String>,
    url: &str,
    body: serde_json::Value,
) -> Result<(reqwest::StatusCode, String), anyhow::Error> {
    let dpop_key = DpopKey::from_base64url(&record.dpop_key_b64)?;
    let client = upstream_client()?;

    let proof = dpop_key.proof("POST", url, nonce.as_deref(), Some(access_token))?;
    let resp = client
        .post(url)
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", &proof)
        .json(&body)
        .send()
        .await?;

    let fresh_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if (status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::BAD_REQUEST)
        && text.contains("use_dpop_nonce")
        && fresh_nonce.is_some()
    {
        let proof2 = dpop_key.proof("POST", url, fresh_nonce.as_deref(), Some(access_token))?;
        let resp2 = client
            .post(url)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof2)
            .json(&body)
            .send()
            .await?;
        let status2 = resp2.status();
        let text2 = resp2.text().await.unwrap_or_default();
        return Ok((status2, text2));
    }

    Ok((status, text))
}

/// POST /api/graph/follow {broker_token, subject_did} — create an
/// app.bsky.graph.follow record in the user's own repo.
async fn graph_follow(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(req): Json<GraphFollowRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && !ALLOWED_ORIGINS.contains(&origin)
    {
        return Err((StatusCode::FORBIDDEN, "Origin not allowed".to_string()));
    }
    let subject = req
        .subject_did
        .as_deref()
        .filter(|d| d.starts_with("did:"))
        .ok_or((StatusCode::BAD_REQUEST, "subject_did required".to_string()))?;

    let (record, access_token, nonce) = authed_access_token(&state, &req.broker_token).await?;
    if subject == record.did {
        return Err((StatusCode::BAD_REQUEST, "Cannot follow yourself".to_string()));
    }

    let url = format!("{}/xrpc/com.atproto.repo.createRecord", record.pds_url);
    let body = serde_json::json!({
        "repo": record.did,
        "collection": "app.bsky.graph.follow",
        "record": {
            "$type": "app.bsky.graph.follow",
            "subject": subject,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let (status, text) = pds_dpop_post(&record, &access_token, nonce, &url, body)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PDS call failed: {e}")))?;

    if !status.is_success() {
        tracing::warn!(did = %record.did, status = %status, "follow createRecord failed");
        return Err((StatusCode::BAD_GATEWAY, format!("PDS rejected follow: {text}")));
    }
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({}));
    Ok(Json(serde_json::json!({ "ok": true, "uri": parsed.get("uri") })))
}

/// POST /api/graph/unfollow {broker_token, follow_uri} — delete the follow
/// record named by the at:// URI (must live in the caller's own repo).
async fn graph_unfollow(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(req): Json<GraphFollowRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && !ALLOWED_ORIGINS.contains(&origin)
    {
        return Err((StatusCode::FORBIDDEN, "Origin not allowed".to_string()));
    }
    let uri = req
        .follow_uri
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "follow_uri required".to_string()))?;

    let (record, access_token, nonce) = authed_access_token(&state, &req.broker_token).await?;

    // at://did:plc:xxx/app.bsky.graph.follow/rkey — the repo DID must be the
    // caller's own (you can only delete your own follow records).
    let rest = uri
        .strip_prefix("at://")
        .ok_or((StatusCode::BAD_REQUEST, "Invalid follow_uri".to_string()))?;
    let mut parts = rest.split('/');
    let (repo_did, collection, rkey) = (parts.next(), parts.next(), parts.next());
    match (repo_did, collection, rkey) {
        (Some(d), Some("app.bsky.graph.follow"), Some(rkey))
            if d == record.did && !rkey.is_empty() =>
        {
            let url = format!("{}/xrpc/com.atproto.repo.deleteRecord", record.pds_url);
            let body = serde_json::json!({
                "repo": record.did,
                "collection": "app.bsky.graph.follow",
                "rkey": rkey,
            });
            let (status, text) = pds_dpop_post(&record, &access_token, nonce, &url, body)
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PDS call failed: {e}")))?;
            if !status.is_success() {
                tracing::warn!(did = %record.did, status = %status, "unfollow deleteRecord failed");
                return Err((StatusCode::BAD_GATEWAY, format!("PDS rejected unfollow: {text}")));
            }
            Ok(Json(serde_json::json!({ "ok": true })))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "follow_uri must be an app.bsky.graph.follow record in your own repo".to_string(),
        )),
    }
}

async fn get_session(state: &Arc<BrokerState>, broker_token: &str) -> Option<BrokerSessionRecord> {
    let db = state.db.lock().await;
    let enc_key = &state.config.encryption_key;
    let mut stmt = db.prepare(
        "SELECT broker_token, did, handle, pds_url, token_endpoint, refresh_token, dpop_key_b64, dpop_nonce, created_at, updated_at FROM sessions WHERE broker_token = ?1"
    ).ok()?;
    let mut rows = stmt.query(rusqlite::params![broker_token]).ok()?;
    if let Some(row) = rows.next().ok().flatten() {
        let encrypted_refresh: String = row.get(5).ok()?;
        let encrypted_dpop: String = row.get(6).ok()?;
        let encrypted_nonce: Option<String> = row.get(7).ok()?;
        // C-5: Decrypt sensitive fields after reading from DB
        let refresh_token = decrypt_field(enc_key, &encrypted_refresh)
            .map_err(|e| tracing::error!("Failed to decrypt refresh_token: {e}"))
            .ok()?;
        let dpop_key_b64 = decrypt_field(enc_key, &encrypted_dpop)
            .map_err(|e| tracing::error!("Failed to decrypt dpop_key_b64: {e}"))
            .ok()?;
        let dpop_nonce = encrypted_nonce
            .map(|n| decrypt_field(enc_key, &n))
            .transpose()
            .map_err(|e| tracing::error!("Failed to decrypt dpop_nonce: {e}"))
            .ok()?;
        Some(BrokerSessionRecord {
            broker_token: row.get(0).ok()?,
            did: row.get(1).ok()?,
            handle: row.get(2).ok()?,
            pds_url: row.get(3).ok()?,
            token_endpoint: row.get(4).ok()?,
            refresh_token,
            dpop_key_b64,
            dpop_nonce,
            created_at: row.get(8).ok()?,
            updated_at: row.get(9).ok()?,
        })
    } else {
        None
    }
}

/// Returns `(access_token, refresh_token, dpop_nonce, granted_scope)`.
///
/// `granted_scope` is read from the refresh response's `scope` field
/// when present. When the PDS omits it (some implementations do for
/// refreshes), we default to `transition:generic`. That is intentionally
/// conservative: the only refresh tokens the broker holds today were
/// originally granted under `atproto transition:generic` (the broker
/// only started narrowing to `atproto` in this same release), so the
/// pre-existing grant is wide. After this release, every NEW broker
/// session's first refresh response will carry the narrow scope
/// explicitly and we'll record it correctly.
/// Distinguishes a permanently-dead session from a transient failure so the
/// `/session` handler can return the right status. Mapping every failure to
/// 502 (as the old code did) made a revoked/expired refresh token
/// indistinguishable from "PDS briefly down" — clients retried a dead token
/// forever and never reached sign-in (the 2026-07-03 "Reconnecting… forever"
/// bug).
enum RefreshError {
    /// The refresh token is revoked/expired (OAuth `invalid_grant`). The user
    /// MUST re-authenticate — surface as 401 so the client drops to sign-in.
    InvalidGrant,
    /// Network error, PDS 5xx, malformed response, etc. — retryable; 502.
    Transient(anyhow::Error),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::InvalidGrant => write!(f, "refresh token invalid_grant (re-auth required)"),
            RefreshError::Transient(e) => write!(f, "{e}"),
        }
    }
}

impl From<anyhow::Error> for RefreshError {
    fn from(e: anyhow::Error) -> Self {
        RefreshError::Transient(e)
    }
}

impl From<reqwest::Error> for RefreshError {
    fn from(e: reqwest::Error) -> Self {
        RefreshError::Transient(e.into())
    }
}

/// True when an OAuth token-endpoint error body signals a permanently-dead
/// grant: `{"error":"invalid_grant"}` (RFC 6749 §5.2). Also treats an
/// explicit `invalid_request`/`unauthorized_client` on the refresh grant as
/// dead, since retrying won't help.
fn is_invalid_grant(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .map(|err| matches!(err.as_str(), "invalid_grant" | "unauthorized_client"))
        .unwrap_or(false)
}

async fn refresh_access_token(
    config: &BrokerConfig,
    record: &BrokerSessionRecord,
) -> Result<(String, String, Option<String>, String), RefreshError> {
    let dpop_key = DpopKey::from_base64url(&record.dpop_key_b64)?;
    let redirect_uri = format!("{}/auth/callback", config.public_url.trim_end_matches('/'));
    let client_id = build_client_id(&config.public_url, &redirect_uri);
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", record.refresh_token.as_str()),
        ("client_id", client_id.as_str()),
    ];

    let client = upstream_client()?;
    let dpop_proof = dpop_key.proof("POST", &record.token_endpoint, None, None)?;
    let resp = client
        .post(&record.token_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await?;
    let status = resp.status();
    let mut dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(record.dpop_nonce.clone());

    let token_resp: serde_json::Value =
        if (status.as_u16() == 400 || status.as_u16() == 401) && dpop_nonce.is_some() {
            let nonce = dpop_nonce.as_deref().unwrap();
            let dpop_proof2 = dpop_key.proof("POST", &record.token_endpoint, Some(nonce), None)?;
            let resp2 = client
                .post(&record.token_endpoint)
                .header("DPoP", &dpop_proof2)
                .form(&params)
                .send()
                .await?;
            if !resp2.status().is_success() {
                let body = resp2.text().await.unwrap_or_default();
                if is_invalid_grant(&body) {
                    return Err(RefreshError::InvalidGrant);
                }
                return Err(RefreshError::Transient(anyhow::anyhow!("Refresh failed: {body}")));
            }
            resp2.json().await.map_err(|e| RefreshError::Transient(e.into()))?
        } else if status.is_success() {
            resp.json().await.map_err(|e| RefreshError::Transient(e.into()))?
        } else {
            // Read the error body to classify. A dead refresh token comes back
            // as 400 invalid_grant on the FIRST try when no DPoP nonce dance
            // is needed (or the nonce was already fresh).
            let body = resp.text().await.unwrap_or_default();
            if is_invalid_grant(&body) {
                return Err(RefreshError::InvalidGrant);
            }
            return Err(RefreshError::Transient(anyhow::anyhow!("Refresh failed ({status}): {body}")));
        };

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token"))?
        .to_string();
    let refresh_token = token_resp["refresh_token"]
        .as_str()
        .unwrap_or(&record.refresh_token)
        .to_string();
    dpop_nonce = token_resp
        .get("dpop_nonce")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or(dpop_nonce);
    // Conservative default explained on the function signature: refresh
    // tokens stored in the broker today were originally granted under
    // `transition:generic`, so a missing `scope` in the response means
    // "preserve the existing wide grant".
    let granted_scope = token_resp["scope"]
        .as_str()
        .unwrap_or("atproto transition:generic")
        .to_string();

    Ok((access_token, refresh_token, dpop_nonce, granted_scope))
}

async fn mint_web_token(
    config: &BrokerConfig,
    did: &str,
    handle: &str,
) -> Result<(String, String), anyhow::Error> {
    let body = serde_json::json!({"did": did, "handle": handle});
    let (sig, ts) = sign_body(&config.shared_secret, &body)?;
    let url = format!(
        "{}/auth/broker/web-token",
        config.freeq_server_url.trim_end_matches('/')
    );
    let client = upstream_client()?;
    let resp = client
        .post(&url)
        .header("X-Broker-Signature", sig)
        .header("X-Broker-Timestamp", ts)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "web-token failed: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    let json: serde_json::Value = resp.json().await?;
    let token = json["token"].as_str().unwrap_or_default().to_string();
    let nick = json["nick"].as_str().unwrap_or_default().to_string();
    Ok((token, nick))
}

async fn push_web_session(
    config: &BrokerConfig,
    pending: &PendingAuth,
    token_resp: &serde_json::Value,
    dpop_nonce: Option<String>,
) -> Result<(), anyhow::Error> {
    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token"))?;
    // Read the actually-granted scope from the token response. Older
    // PDSes may downgrade us to `transition:generic`. Defaults to
    // `atproto` only when missing — that's the scope this broker now
    // requests at /authorize, so it's the right narrow assumption for
    // a code-exchange where the response forgot to echo the scope.
    let granted_scope = token_resp["scope"].as_str().unwrap_or("atproto");
    push_web_session_with_token(config, pending, access_token, dpop_nonce, granted_scope).await
}

async fn push_web_session_with_token(
    config: &BrokerConfig,
    pending: &PendingAuth,
    access_token: &str,
    dpop_nonce: Option<String>,
    granted_scope: &str,
) -> Result<(), anyhow::Error> {
    let body = serde_json::json!({
        "did": pending.did,
        "handle": pending.handle,
        "pds_url": pending.pds_url,
        "access_token": access_token,
        "dpop_key_b64": pending.dpop_key_b64,
        "dpop_nonce": dpop_nonce,
        "granted_scope": granted_scope,
    });
    let (sig, ts) = sign_body(&config.shared_secret, &body)?;
    let url = format!(
        "{}/auth/broker/session",
        config.freeq_server_url.trim_end_matches('/')
    );
    let client = upstream_client()?;
    let resp = client
        .post(&url)
        .header("X-Broker-Signature", sig)
        .header("X-Broker-Timestamp", ts)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "session push failed: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

/// Derive a 256-bit encryption key from the shared secret using HKDF-SHA256.
pub fn derive_encryption_key(shared_secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"freeq-broker-session-encryption-v1", &mut key)
        .expect("HKDF expand failed");
    key
}

/// Encrypt a plaintext string with AES-256-GCM. Returns base64url(nonce || ciphertext).
pub fn encrypt_field(key: &[u8; 32], plaintext: &str) -> String {
    use rand::RngCore;
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("AES-GCM encryption failed");
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined)
}

/// Decrypt a field previously encrypted with encrypt_field.
pub fn decrypt_field(key: &[u8; 32], encoded: &str) -> Result<String, anyhow::Error> {
    let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))?;
    if combined.len() < 13 {
        return Err(anyhow::anyhow!("encrypted field too short"));
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("UTF-8 decode failed: {e}"))
}

/// Validate return_to against an allowlist to prevent open redirects.
pub fn is_valid_return_to(url: &str) -> bool {
    // Allow relative URLs
    if url.starts_with('/') {
        return true;
    }
    // Allow known origins
    let allowed = [
        "https://irc.freeq.at",
        "https://staging.freeq.at",
        "https://revenant-watch.boxd.sh",
        "http://localhost:",
        "http://localhost/",
        "http://127.0.0.1:",
        "http://127.0.0.1/",
    ];
    allowed.iter().any(|prefix| url.starts_with(prefix))
}

/// Sign a request body with HMAC-SHA256. Returns (signature, timestamp) pair.
/// The MAC covers `ts={timestamp}\n` || body_bytes to prevent replay attacks.
pub fn sign_body(secret: &str, body: &serde_json::Value) -> Result<(String, String), anyhow::Error> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())?;
    let bytes = serde_json::to_vec(body)?;
    mac.update(format!("ts={timestamp}\n").as_bytes());
    mac.update(&bytes);
    Ok((
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        timestamp,
    ))
}

pub fn init_db(db: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
            broker_token TEXT PRIMARY KEY,
            did TEXT NOT NULL,
            handle TEXT NOT NULL,
            pds_url TEXT NOT NULL,
            token_endpoint TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            dpop_key_b64 TEXT NOT NULL,
            dpop_nonce TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

fn oauth_result_page(message: &str, _result: Option<&serde_json::Value>) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>freeq auth</title>
        <style>
        body {{ font-family: system-ui; background: #1e1e2e; color: #cdd6f4; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .box {{ text-align: center; }}
        h1 {{ color: #89b4fa; font-size: 20px; }}
        p {{ color: #a6adc8; }}
        </style></head>
        <body><div class="box"><h1>freeq</h1><p>{message}</p></div></body></html>"#
    )
}

// PKCE, random strings, URL encoding, and client_id construction now live
// in the shared engine crate. Kept as thin re-exports/aliases so call sites
// in this file don't churn.
pub use freeq_oauth::{build_client_id, generate_random_string};
use freeq_oauth::{generate_pkce, urlencode as urlencod};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_grant_body_is_detected() {
        // A dead/revoked refresh token → PDS returns this → must be 401, not 502.
        assert!(is_invalid_grant(r#"{"error":"invalid_grant","error_description":"token has been revoked"}"#));
        assert!(is_invalid_grant(r#"{"error":"unauthorized_client"}"#));
    }

    #[test]
    fn transient_bodies_are_not_invalid_grant() {
        // Retryable conditions must NOT trip the sign-in path.
        assert!(!is_invalid_grant(r#"{"error":"use_dpop_nonce"}"#));
        assert!(!is_invalid_grant(r#"{"error":"server_error"}"#));
        assert!(!is_invalid_grant(r#"{"error":"temporarily_unavailable"}"#));
        assert!(!is_invalid_grant("Bad Gateway"));       // non-JSON upstream error page
        assert!(!is_invalid_grant(""));                   // empty body
        assert!(!is_invalid_grant("{}"));                 // JSON without error field
        assert!(!is_invalid_grant(r#"{"error":123}"#));   // error not a string
    }

    #[test]
    fn refresh_error_maps_display() {
        assert!(RefreshError::InvalidGrant.to_string().contains("re-auth"));
    }
}
