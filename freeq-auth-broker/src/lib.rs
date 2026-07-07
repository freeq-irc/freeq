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
}

pub struct BrokerState {
    pub config: BrokerConfig,
    /// Where minted sessions are published. Standalone uses [`RemoteWriter`]
    /// (HMAC push to the freeq-server); an embedding server supplies its own
    /// in-process writer.
    pub writer: Arc<dyn SessionWriter>,
    /// Where broker sessions are kept: [`SqliteStore`] (standalone) or
    /// [`InMemoryStore`] (embedded default).
    pub store: Arc<dyn SessionStore>,
    pub pending: Mutex<std::collections::HashMap<String, PendingAuth>>,
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

/// Hard-bounded client for the broker's PDS calls (session refresh, graph
/// writes). Default reqwest waits forever; a slow PDS would otherwise pile up
/// stuck requests until the gateway times out. Connection pooling + keep-alive
/// are left on so a request and its DPoP `use_dpop_nonce` retry reuse one
/// connection to the same host rather than opening a second socket.
fn upstream_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(8))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()?)
}

/// [`ClientProvider`] for the login flow's discovery + PAR hops, which all
/// reach user-controlled PDS / auth-server hosts. Validates each URL against
/// SSRF policy and DNS-pins a fresh client to the resolved addresses. The PAR
/// nonce-retry still shares one connection because the engine reuses the
/// single client we hand it (pinned clients keep reqwest's default pooling).
struct SsrfClients;

impl ClientProvider for SsrfClients {
    async fn client_for(&self, url: &str) -> anyhow::Result<reqwest::Client> {
        let parsed = url::Url::parse(url)?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            anyhow::bail!("unsupported URL scheme");
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
        let addrs = freeq_ssrf::resolve_and_check(host, port).await?;
        Ok(freeq_ssrf::pinned_client(
            host,
            &addrs,
            std::time::Duration::from_secs(30),
        )?)
    }
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

/// A durable broker session — the record `/session` refreshes from. Fields
/// are plaintext here; `SqliteStore` encrypts the sensitive ones at rest.
#[derive(Serialize, Clone)]
pub struct BrokerSessionRecord {
    pub broker_token: String,
    pub did: String,
    pub handle: String,
    pub pds_url: String,
    pub token_endpoint: String,
    pub refresh_token: String,
    pub dpop_key_b64: String,
    pub dpop_nonce: Option<String>,
    /// The OAuth `client_id` this grant was issued to. Refresh must reuse it.
    /// Empty for sessions created before this field existed — refresh then
    /// falls back to rebuilding it from broker config (standalone's origin is
    /// static, so that matches). Embedded sessions always store it, because
    /// the origin is per-request.
    pub client_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Where broker sessions (`broker_token → refresh_token/dpop`) are kept.
/// [`SqliteStore`] is durable (standalone; or embedded opt-in);
/// [`InMemoryStore`] is ephemeral (embedded default).
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, broker_token: &str) -> Option<BrokerSessionRecord>;
    async fn insert(&self, rec: &BrokerSessionRecord) -> anyhow::Result<()>;
    /// Persist a rotated refresh token + DPoP nonce (single-use rotation).
    async fn update_refresh(
        &self,
        broker_token: &str,
        refresh_token: &str,
        dpop_nonce: Option<&str>,
    ) -> anyhow::Result<()>;
}

/// Durable SQLite store with AES-GCM field encryption at rest. Owns the key.
pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
    enc_key: [u8; 32],
}

impl SqliteStore {
    pub fn open(path: &str, enc_key: [u8; 32]) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        init_db(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            enc_key,
        })
    }

    /// Wrap an already-open connection (the standalone binary opens it with a
    /// mount-retry loop; tests pass `:memory:`).
    pub fn from_connection(conn: rusqlite::Connection, enc_key: [u8; 32]) -> Self {
        Self {
            conn: Mutex::new(conn),
            enc_key,
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for SqliteStore {
    async fn get(&self, broker_token: &str) -> Option<BrokerSessionRecord> {
        let db = self.conn.lock().await;
        let enc_key = &self.enc_key;
        let mut stmt = db.prepare(
            "SELECT broker_token, did, handle, pds_url, token_endpoint, refresh_token, dpop_key_b64, dpop_nonce, created_at, updated_at, client_id FROM sessions WHERE broker_token = ?1"
        ).ok()?;
        let mut rows = stmt.query(rusqlite::params![broker_token]).ok()?;
        let row = rows.next().ok().flatten()?;
        let encrypted_refresh: String = row.get(5).ok()?;
        let encrypted_dpop: String = row.get(6).ok()?;
        let encrypted_nonce: Option<String> = row.get(7).ok()?;
        // C-5: decrypt sensitive fields after reading from DB.
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
            // Empty for pre-migration rows (column default '').
            client_id: row.get::<_, Option<String>>(10).ok()?.unwrap_or_default(),
        })
    }

    async fn insert(&self, rec: &BrokerSessionRecord) -> anyhow::Result<()> {
        let enc_key = &self.enc_key;
        let encrypted_refresh = encrypt_field(enc_key, &rec.refresh_token);
        let encrypted_dpop = encrypt_field(enc_key, &rec.dpop_key_b64);
        let encrypted_nonce = rec.dpop_nonce.as_deref().map(|n| encrypt_field(enc_key, n));
        let db = self.conn.lock().await;
        db.execute(
            "INSERT INTO sessions (broker_token, did, handle, pds_url, token_endpoint, refresh_token, dpop_key_b64, dpop_nonce, created_at, updated_at, client_id)\
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)\
             ON CONFLICT(broker_token) DO UPDATE SET refresh_token=excluded.refresh_token, updated_at=excluded.updated_at",
            rusqlite::params![
                rec.broker_token, rec.did, rec.handle, rec.pds_url, rec.token_endpoint,
                encrypted_refresh, encrypted_dpop, encrypted_nonce, rec.created_at, rec.updated_at,
                rec.client_id,
            ],
        )?;
        Ok(())
    }

    async fn update_refresh(
        &self,
        broker_token: &str,
        refresh_token: &str,
        dpop_nonce: Option<&str>,
    ) -> anyhow::Result<()> {
        let enc_key = &self.enc_key;
        let encrypted_refresh = encrypt_field(enc_key, refresh_token);
        let encrypted_nonce = dpop_nonce.map(|n| encrypt_field(enc_key, n));
        let now = chrono::Utc::now().timestamp();
        let db = self.conn.lock().await;
        db.execute(
            "UPDATE sessions SET refresh_token = ?1, dpop_nonce = ?2, updated_at = ?3 WHERE broker_token = ?4",
            rusqlite::params![encrypted_refresh, encrypted_nonce, now, broker_token],
        )?;
        Ok(())
    }
}

/// Ephemeral in-memory store — no persistence, no at-rest encryption (never
/// leaves RAM). Default for embedded mode: `/session` works within the
/// server's uptime, resets on restart.
#[derive(Default)]
pub struct InMemoryStore {
    sessions: Mutex<std::collections::HashMap<String, BrokerSessionRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl SessionStore for InMemoryStore {
    async fn get(&self, broker_token: &str) -> Option<BrokerSessionRecord> {
        self.sessions.lock().await.get(broker_token).cloned()
    }

    async fn insert(&self, rec: &BrokerSessionRecord) -> anyhow::Result<()> {
        self.sessions
            .lock()
            .await
            .insert(rec.broker_token.clone(), rec.clone());
        Ok(())
    }

    async fn update_refresh(
        &self,
        broker_token: &str,
        refresh_token: &str,
        dpop_nonce: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(r) = self.sessions.lock().await.get_mut(broker_token) {
            r.refresh_token = refresh_token.to_string();
            r.dpop_nonce = dpop_nonce.map(str::to_string);
            r.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }
}

/// Build the broker's axum router over shared state. Used by the
/// standalone binary and by the characterization tests; embedding
/// servers mount this when embedding the broker in-process.
/// The durable-session routes an embedding server lacks: `/session` (refresh)
/// and Bluesky graph delegation. Returned un-stated so a host can `.merge()` it
/// into its own router (its layers/CORS then apply); the standalone [`router`]
/// includes these plus the login endpoints.
fn session_routes() -> Router<Arc<BrokerState>> {
    Router::new()
        .route("/session", post(session))
        .route("/api/graph/follow", post(graph_follow))
        .route("/api/graph/unfollow", post(graph_unfollow))
}

/// Ready-to-mount `/session` + `/api/graph/*` router for an embedding server.
/// The host supplies a [`BrokerState`] with its own writer + store and applies
/// its own CORS.
pub fn session_router(state: Arc<BrokerState>) -> Router {
    session_routes().with_state(state)
}

pub fn router(state: Arc<BrokerState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/health-v3", get(health_v3))
        .route("/client-metadata.json", get(client_metadata))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .merge(session_routes())
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

    // Discovery + PAR reach user-controlled PDS / auth-server hosts, so each
    // hop goes through the SSRF-validating, DNS-pinning provider (closes audit
    // M-8). The PAR nonce-retry still reuses its connection: the engine reuses
    // the single client we hand it.
    let auth_meta = freeq_oauth::discovery::discover_auth_server(&SsrfClients, &pds_url)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Auth server discovery failed: {e}"),
            )
        })?;
    let authorization_endpoint = auth_meta.authorization_endpoint.as_str();
    let token_endpoint = auth_meta.token_endpoint.as_str();
    let par_endpoint = auth_meta
        .pushed_authorization_request_endpoint
        .as_deref()
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

    // PAR over an SSRF-validated, DNS-pinned client for the auth-server host.
    // One client is reused for the initial POST and the nonce-retry (the
    // engine reuses it), preserving the connection-reuse the PAR retry needs.
    let par_client = SsrfClients
        .client_for(par_endpoint)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR client init: {e}")))?;
    let par = freeq_oauth::discovery::pushed_authorization_request(
        &par_client,
        par_endpoint,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &oauth_state,
        &handle,
        scope,
        &dpop_key,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR failed: {e}")))?;
    let request_uri = par.request_uri.as_str();
    let dpop_nonce = par.dpop_nonce;

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

    // Shared engine performs the code exchange + DPoP nonce-retry dance.
    // We pass the PAR-step nonce as `initial_nonce`: the PDS consumes the
    // auth code even on a `use_dpop_nonce` failure, so sending the known
    // nonce up front avoids a retry landing on `invalid_grant: Invalid code`.
    // On failure, render the caller-specific page/redirect (mobile clients
    // need a `freeq://` custom-scheme redirect, not HTML).
    let client = reqwest::Client::new();
    let exchanged = match freeq_oauth::flow::exchange_code(
        &client,
        &pending.token_endpoint,
        code,
        &pending.code_verifier,
        &pending.redirect_uri,
        &pending.client_id,
        &dpop_key,
        pending.dpop_nonce.as_deref(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            let err_msg = e.to_string();
            tracing::error!(error = %err_msg, "Token exchange failed");
            if pending.mobile {
                let redirect = format!("freeq://auth?error={}", urlencod(&err_msg));
                return Ok(axum::response::Redirect::to(&redirect).into_response());
            }
            return Ok(Html(oauth_result_page(&err_msg, None)).into_response());
        }
    };
    let token_resp = exchanged.token_response;
    let dpop_nonce = exchanged.dpop_nonce;

    let refresh_token = token_resp["refresh_token"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "No refresh_token".to_string()))?;

    let broker_token = generate_random_string(32);
    let now = chrono::Utc::now().timestamp();
    // Persist the durable session; the store encrypts sensitive fields at rest.
    state
        .store
        .insert(&BrokerSessionRecord {
            broker_token: broker_token.clone(),
            did: pending.did.clone(),
            handle: pending.handle.clone(),
            pds_url: pending.pds_url.clone(),
            token_endpoint: pending.token_endpoint.clone(),
            refresh_token: refresh_token.to_string(),
            dpop_key_b64: pending.dpop_key_b64.clone(),
            dpop_nonce: dpop_nonce.clone(),
            client_id: pending.client_id.clone(),
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Mint a one-time web-token + web session on the freeq server. Optional:
    // a standalone broker (not trusted by irc.freeq.at's shared secret) just
    // can't mint one — the verified DID + handle + broker_token are enough for
    // identity-only consumers, so degrade gracefully instead of failing login.
    let (web_token, nick) = state
        .writer
        .mint_web_token(&pending.did, &pending.handle)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "web-token mint failed — continuing identity-only");
            (String::new(), pending.handle.clone())
        });

    // Read the actually-granted scope from the token response; older PDSes may
    // downgrade to `transition:generic`. Default to `atproto` (what the broker
    // requests at /authorize) when the response omits it.
    let granted_scope = token_resp["scope"].as_str().unwrap_or("atproto");
    let access_token = token_resp["access_token"].as_str().unwrap_or_default();
    if let Err(e) = state
        .writer
        .push_session(&SessionPush {
            did: &pending.did,
            handle: &pending.handle,
            pds_url: &pending.pds_url,
            access_token,
            dpop_key_b64: &pending.dpop_key_b64,
            dpop_nonce: dpop_nonce.as_deref(),
            granted_scope,
        })
        .await
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
    // rotated the refresh token, so the stored copy is the one to use.
    let record = state
        .store
        .get(&req.broker_token)
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

    // Persist the rotated refresh token + nonce (store encrypts at rest).
    state
        .store
        .update_refresh(&record.broker_token, &refresh_token, dpop_nonce.as_deref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (web_token, nick) = state
        .writer
        .mint_web_token(&record.did, &record.handle)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "web-token mint failed — continuing identity-only");
            (String::new(), record.handle.clone())
        });

    // Forward the actually-granted scope from the refresh response so the
    // server's per-purpose checks see the truth, not a hard-coded assumption.
    if let Err(e) = state
        .writer
        .push_session(&SessionPush {
            did: &record.did,
            handle: &record.handle,
            pds_url: &record.pds_url,
            access_token: &access_token,
            dpop_key_b64: &record.dpop_key_b64,
            dpop_nonce: dpop_nonce.as_deref(),
            granted_scope: &granted_scope,
        })
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

    let record = state
        .store
        .get(broker_token)
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

    state
        .store
        .update_refresh(&record.broker_token, &refresh_token, dpop_nonce.as_deref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

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

// Refresh + dead-vs-transient classification now live in the shared engine.
use freeq_oauth::ClientProvider;
use freeq_oauth::flow::RefreshError;

/// Refresh a stored broker session's PDS access token.
///
/// Thin adapter over [`freeq_oauth::flow::refresh_access_token`]: reuses the
/// grant's stored `client_id` and injects the broker's bounded HTTP client,
/// then returns the tuple the `/session` and graph handlers expect. Returns
/// `(access_token, refresh_token, dpop_nonce, granted_scope)`.
async fn refresh_access_token(
    config: &BrokerConfig,
    record: &BrokerSessionRecord,
) -> Result<(String, String, Option<String>, String), RefreshError> {
    let dpop_key = DpopKey::from_base64url(&record.dpop_key_b64)?;
    // Reuse the client_id the grant was issued to. Pre-migration rows have
    // none, so fall back to rebuilding from config (standalone's origin is
    // static, so it matches what login used).
    let client_id = if record.client_id.is_empty() {
        let redirect_uri = format!("{}/auth/callback", config.public_url.trim_end_matches('/'));
        build_client_id(&config.public_url, &redirect_uri)
    } else {
        record.client_id.clone()
    };
    let client = upstream_client()?;
    let t = freeq_oauth::flow::refresh_access_token(
        &client,
        &record.token_endpoint,
        &client_id,
        &dpop_key,
        &record.refresh_token,
        record.dpop_nonce.as_deref(),
    )
    .await?;
    Ok((t.access_token, t.refresh_token, t.dpop_nonce, t.granted_scope))
}

/// The server-side web session a writer installs: a fresh PDS access token plus
/// the DPoP key bound to it, for server-proxied PDS operations.
pub struct SessionPush<'a> {
    pub did: &'a str,
    pub handle: &'a str,
    pub pds_url: &'a str,
    pub access_token: &'a str,
    pub dpop_key_b64: &'a str,
    pub dpop_nonce: Option<&'a str>,
    pub granted_scope: &'a str,
}

/// How a freshly-minted session reaches the freeq-server. Standalone pushes
/// over HTTP+HMAC ([`RemoteWriter`]); an embedding server writes in-process.
#[async_trait::async_trait]
pub trait SessionWriter: Send + Sync {
    /// Mint a one-time SASL web-token for this identity → `(token, nick)`.
    async fn mint_web_token(&self, did: &str, handle: &str)
    -> Result<(String, String), anyhow::Error>;
    /// Install / refresh the server-side web session for proxied PDS ops.
    async fn push_session(&self, push: &SessionPush<'_>) -> Result<(), anyhow::Error>;
}

/// [`SessionWriter`] for the standalone broker: HMAC-signed HTTP POSTs to the
/// freeq-server's `/auth/broker/*` receiver endpoints.
pub struct RemoteWriter {
    pub freeq_server_url: String,
    pub shared_secret: String,
}

#[async_trait::async_trait]
impl SessionWriter for RemoteWriter {
    async fn mint_web_token(
        &self,
        did: &str,
        handle: &str,
    ) -> Result<(String, String), anyhow::Error> {
        let body = serde_json::json!({"did": did, "handle": handle});
        let (sig, ts) = sign_body(&self.shared_secret, &body)?;
        let url = format!(
            "{}/auth/broker/web-token",
            self.freeq_server_url.trim_end_matches('/')
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

    async fn push_session(&self, push: &SessionPush<'_>) -> Result<(), anyhow::Error> {
        let body = serde_json::json!({
            "did": push.did,
            "handle": push.handle,
            "pds_url": push.pds_url,
            "access_token": push.access_token,
            "dpop_key_b64": push.dpop_key_b64,
            "dpop_nonce": push.dpop_nonce,
            "granted_scope": push.granted_scope,
        });
        let (sig, ts) = sign_body(&self.shared_secret, &body)?;
        let url = format!(
            "{}/auth/broker/session",
            self.freeq_server_url.trim_end_matches('/')
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
///
/// Matches on the parsed URL's scheme + host (exactly), not a string prefix.
/// A prefix match let `https://irc.freeq.at.evil.example` through — it starts
/// with `https://irc.freeq.at` — sending the token-bearing `#oauth=` fragment
/// to an attacker origin (residual SECURITY-AUDIT C-6).
pub fn is_valid_return_to(url: &str) -> bool {
    // Relative, same-origin URLs. Reject protocol-relative (`//host`) and the
    // `/\host` backslash trick, which browsers treat as off-origin.
    if url.starts_with('/') {
        return !(url.starts_with("//") || url.starts_with("/\\"));
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match (parsed.scheme(), parsed.host_str()) {
        ("https", Some("irc.freeq.at" | "staging.freeq.at" | "revenant-watch.boxd.sh")) => true,
        // Loopback dev origins, any port.
        ("http", Some("localhost" | "127.0.0.1")) => true,
        _ => false,
    }
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
            updated_at INTEGER NOT NULL,
            client_id TEXT NOT NULL DEFAULT ''
        );",
    )?;
    // Migration for DBs created before `client_id` existed. SQLite has no
    // ADD COLUMN IF NOT EXISTS, so ignore the duplicate-column error.
    if let Err(e) =
        db.execute("ALTER TABLE sessions ADD COLUMN client_id TEXT NOT NULL DEFAULT ''", [])
        && !e.to_string().contains("duplicate column")
    {
        return Err(e);
    }
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

// The refresh-classification unit tests (invalid_grant detection, RefreshError
// display) moved with their code into freeq-oauth's `flow` module. This crate's
// request-path coverage lives in tests/characterization.rs.

#[cfg(test)]
mod tests {
    use super::*;

    // The SSRF provider guards the (hermetically-untestable) auth_login
    // discovery/PAR hops; pin its policy here.
    #[tokio::test]
    async fn ssrf_provider_refuses_private_targets() {
        for url in [
            "http://127.0.0.1:1/",
            "http://10.0.0.1/",
            "http://localhost:9999/",
            "http://169.254.169.254/", // cloud metadata
        ] {
            assert!(
                SsrfClients.client_for(url).await.is_err(),
                "must refuse private target {url}"
            );
        }
    }

    #[tokio::test]
    async fn ssrf_provider_rejects_bad_urls() {
        assert!(SsrfClients.client_for("not a url").await.is_err());
        assert!(SsrfClients.client_for("ftp://example.com").await.is_err());
    }

    #[tokio::test]
    async fn ssrf_provider_allows_public_host() {
        // An IP literal that is public passes validation and yields a client
        // (no network I/O — resolution short-circuits on the literal).
        assert!(SsrfClients.client_for("https://8.8.8.8/").await.is_ok());
    }

    fn record(refresh: &str) -> BrokerSessionRecord {
        BrokerSessionRecord {
            broker_token: "BT".into(),
            did: "did:plc:x".into(),
            handle: "h".into(),
            pds_url: "https://pds".into(),
            token_endpoint: "https://pds/token".into(),
            refresh_token: refresh.into(),
            dpop_key_b64: DpopKey::generate().to_base64url(),
            dpop_nonce: None,
            client_id: "cid".into(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn in_memory_store_roundtrips_and_updates() {
        let store = InMemoryStore::new();
        assert!(store.get("BT").await.is_none());
        store.insert(&record("R0")).await.unwrap();
        assert_eq!(store.get("BT").await.unwrap().refresh_token, "R0");
        store.update_refresh("BT", "R1", Some("N1")).await.unwrap();
        let r = store.get("BT").await.unwrap();
        assert_eq!(r.refresh_token, "R1");
        assert_eq!(r.dpop_nonce.as_deref(), Some("N1"));
    }

    #[tokio::test]
    async fn sqlite_store_encrypts_refresh_token_at_rest() {
        let key = derive_encryption_key("k");
        let path = std::env::temp_dir().join(format!("freeq-broker-test-{}.db", std::process::id()));
        std::fs::remove_file(&path).ok();
        let path_str = path.to_str().unwrap();
        {
            let store = SqliteStore::open(path_str, key).unwrap();
            store.insert(&record("SECRET")).await.unwrap();
            // Round-trips through decryption.
            assert_eq!(store.get("BT").await.unwrap().refresh_token, "SECRET");
        }
        // A separate raw connection sees ciphertext, not the plaintext token.
        let raw = rusqlite::Connection::open(path_str).unwrap();
        let stored: String = raw
            .query_row(
                "SELECT refresh_token FROM sessions WHERE broker_token='BT'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(stored, "SECRET");
        assert_eq!(decrypt_field(&key, &stored).unwrap(), "SECRET");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn sqlite_store_migrates_legacy_schema_without_client_id() {
        // A DB created before the client_id column existed.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (broker_token TEXT PRIMARY KEY, did TEXT NOT NULL, handle TEXT NOT NULL,
             pds_url TEXT NOT NULL, token_endpoint TEXT NOT NULL, refresh_token TEXT NOT NULL,
             dpop_key_b64 TEXT NOT NULL, dpop_nonce TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);",
        ).unwrap();
        // init_db (via from_connection? no — call it directly) adds the column.
        init_db(&conn).unwrap();
        let store = SqliteStore::from_connection(conn, derive_encryption_key("k"));
        store.insert(&record("R")).await.unwrap();
        let got = store.get("BT").await.unwrap();
        assert_eq!(got.refresh_token, "R");
        assert_eq!(got.client_id, "cid");
    }
}
