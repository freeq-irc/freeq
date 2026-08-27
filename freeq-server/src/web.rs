//! WebSocket IRC transport and read-only REST API.
//!
//! The WebSocket endpoint (`/irc`) upgrades to a WebSocket connection, then
//! bridges it to the IRC connection handler via a `DuplexStream`. From the
//! server's perspective, a WebSocket client is just another async stream.
//!
//! The REST API exposes read-only data backed by the persistence layer.
//! No write endpoints — if you want to act on the server, speak IRC.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use axum::Router;
use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Redirect};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tower_http::cors::CorsLayer;

use crate::server::SharedState;
// OAuth primitives now live in the shared engine crate. `generate_random_string`
// is re-exported because `crate::web::generate_random_string` is referenced from
// connection::login; `urlencod` is the local alias for the engine's `urlencode`.
pub use freeq_oauth::generate_random_string;
use freeq_oauth::{ClientProvider, build_client_id, generate_pkce, urlencode as urlencod};

// ── WebSocket ↔ IRC bridge ─────────────────────────────────────────────

/// A WebSocket bridged as `AsyncRead + AsyncWrite` for the IRC handler.
///
/// Uses a `tokio::io::DuplexStream` pair with two background tasks:
/// - **rx task:** reads WebSocket frames → appends `\r\n` → writes to bridge
/// - **tx task:** reads from bridge → splits on `\r\n` → sends as WS text frames
pub struct WsBridge {
    pub reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    pub writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

/// Create a bridged stream from a WebSocket.
///
/// Spawns two async tasks that shuttle data between the WebSocket and a
/// DuplexStream. The returned `WsBridge` implements `AsyncRead + AsyncWrite`
/// and can be passed directly to `handle_generic()`.
fn bridge_ws(socket: WebSocket) -> WsBridge {
    // Split WebSocket into two halves via a channel so each task owns one.
    let (ws_tx, ws_rx) = tokio::sync::mpsc::channel::<WsMessage>(64);

    // DuplexStream: irc_side is what the IRC handler reads/writes.
    // bridge_side is what our background tasks read/write.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (irc_read, irc_write) = tokio::io::split(irc_side);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // We need the WebSocket as a single owner. Use an Arc<Mutex> for sends,
    // and move the socket into the rx task which also handles sends.
    // Actually simpler: move socket into one task, use channel for the other direction.

    // Task 1: owns the WebSocket, reads frames → bridge_write, reads ws_rx → sends frames
    tokio::spawn(async move {
        let mut socket = socket;
        let mut ws_rx = ws_rx;
        let ws_send_timeout = tokio::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                // Read from WebSocket → write to bridge (→ IRC handler reads)
                frame = socket.recv() => {
                    match frame {
                        Some(Ok(WsMessage::Text(text))) => {
                            let mut bytes = text.as_bytes().to_vec();
                            bytes.extend_from_slice(b"\r\n");
                            if bridge_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Binary(data))) => {
                            let mut bytes = data.to_vec();
                            if !bytes.ends_with(b"\r\n") {
                                bytes.extend_from_slice(b"\r\n");
                            }
                            if bridge_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) | None => break,
                        Some(Ok(_)) => {} // Ping/Pong handled by axum
                        Some(Err(_)) => break,
                    }
                }
                // Read from channel → send as WebSocket frame (with timeout to detect dead sockets)
                msg = ws_rx.recv() => {
                    match msg {
                        Some(ws_msg) => {
                            match tokio::time::timeout(ws_send_timeout, socket.send(ws_msg)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) | Err(_) => {
                                    tracing::debug!("WebSocket send failed or timed out, closing bridge");
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        let _ = bridge_write.shutdown().await;
        let _ = socket.send(WsMessage::Close(None)).await;
    });

    // Task 2: reads from bridge (← IRC handler writes) → sends as WS text frames via channel
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut line_buf = Vec::new();
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    line_buf.extend_from_slice(&buf[..n]);
                    // Send complete lines as text frames
                    while let Some(pos) = line_buf.windows(2).position(|w| w == b"\r\n") {
                        let line = String::from_utf8_lossy(&line_buf[..pos]).to_string();
                        line_buf.drain(..pos + 2);
                        if ws_tx.send(WsMessage::Text(line.into())).await.is_err() {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    WsBridge {
        reader: irc_read,
        writer: irc_write,
    }
}

impl AsyncRead for WsBridge {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsBridge {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

// ── Axum router ────────────────────────────────────────────────────────

/// Build the axum router with WebSocket and REST endpoints.
pub fn router(state: Arc<SharedState>) -> Router {
    // Stamp boot time before serving anything, so `uptime_secs` measures uptime.
    let _ = START_TIME.get_or_init(SystemTime::now);
    let mut app = Router::new()
        // WebSocket IRC transport
        .route("/irc", get(ws_upgrade))
        // OAuth endpoints for web client
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        // Phase-2 incremental authorization: drive a second OAuth flow
        // for a specific purpose (image upload, Bluesky cross-post)
        // without replacing the user's primary login session.
        .route("/auth/step-up", get(auth_step_up))
        .route("/auth/broker/web-token", post(auth_broker_web_token))
        .route("/auth/broker/session", post(auth_broker_session))
        .route("/client-metadata.json", get(client_metadata))
        // Machine-readable descriptions of this server, for agents:
        // the OpenAPI contract and the llms.txt index.
        .route("/api/v1/openapi.json", get(crate::openapi::openapi_json))
        .route("/api/v1/openapi.yaml", get(crate::openapi::openapi_yaml))
        .route("/llms.txt", get(crate::openapi::llms_txt))
        // Private media spaces. Returns a 404 if the feature is unconfigured.
        .route("/.well-known/did.json", get(media_space_did_doc))
        .route(
            "/xrpc/com.atproto.simplespace.checkUserAccess",
            get(xrpc_check_user_access),
        )
        .route("/api/v1/media-space", get(api_media_space))
        .route("/api/v1/space-media/{ref}/{filename}", get(api_space_media))
        // REST API (read-only, v1)
        .route("/api/v1/health", get(api_health))
        // The mediated, metered model path: the server holds the provider
        // credential, the caller holds only an identity and a budget.
        .route(
            "/api/v1/model/chat/completions",
            post(crate::model_proxy::chat_completions),
        )
        .route("/metrics", get(api_metrics))
        .route("/api/v1/actions", get(api_act_tasks))
        .route("/api/v1/actions/{act_id}", get(api_act_task))
        .route("/api/v1/channels", get(api_channels))
        .route("/api/v1/channels/{name}/history", get(api_channel_history))
        .route("/api/v1/search", get(api_search))
        .route("/api/v1/messages/{msgid}", get(api_message_by_id))
        .route("/api/v1/channels/{name}/export", get(api_channel_export))
        .route("/api/v1/channels/{name}/topic", get(api_channel_topic))
        .route("/api/v1/channels/{name}/pins", get(api_channel_pins))
        .route(
            "/api/v1/favorites",
            get(api_get_favorites).put(api_set_favorites),
        )
        .route("/api/v1/users/{nick}", get(api_user))
        .route("/api/v1/users/{nick}/whois", get(api_user_whois))
        .route("/api/v1/upload", axum::routing::post(api_upload))
        .route("/api/v1/blob", get(api_blob_proxy))
        // Private media: serve an encrypted-at-rest blob via a signed capability
        // URL. The trailing {filename} is cosmetic (preserves the extension so
        // clients render it); only {id}/{sig} are authoritative.
        .route("/api/v1/media/{id}/{sig}/{filename}", get(api_media_serve))
        .route("/api/v1/og", get(api_og_preview))
        .route("/api/v1/keys/{did}", get(api_get_keys))
        .route("/api/v1/keys", axum::routing::post(api_upload_keys))
        .route(
            "/api/v1/channels/{name}/groupkeys",
            get(api_get_group_keys).post(api_put_group_keys),
        )
        .route("/api/v1/signing-key", get(api_signing_key))
        .route("/api/v1/signing-keys/{did}", get(api_did_signing_key))
        .route(
            "/api/v1/signing-keys/{did}/{kid}",
            get(api_did_signing_key_by_kid),
        )
        .route("/api/v1/verify/{msgid}", get(api_verify_message))
        .route(
            "/api/v1/channels/{name}/evidence",
            get(api_channel_evidence),
        )
        .route("/api/v1/actors/{did}", get(api_actor_identity))
        .route(
            "/api/v1/channels/{name}/agent-capabilities",
            get(api_agent_capabilities),
        )
        .route(
            "/api/v1/channels/{name}/approvals",
            get(api_pending_approvals),
        )
        .route("/api/v1/channels/{name}/events", get(api_channel_events))
        .route("/api/v1/channels/{name}/audit", get(api_channel_audit))
        .route("/api/v1/tasks/{task_id}", get(api_task))
        .route("/api/v1/agents/manifests", get(api_list_manifests))
        .route("/api/v1/agents/manifests/{did}", get(api_get_manifest))
        .route("/api/v1/agents/spawned", get(api_spawned_agents))
        .route("/api/v1/channels/{name}/budget", get(api_channel_budget))
        .route("/api/v1/channels/{name}/spend", get(api_channel_spend))
        // AV call page + assets (served here so it's accessible through Miren's HTTPS)
        .route("/av/call", get(av_call_page))
        .route("/av/call.html", get(av_call_page))
        .route("/av/assets/{filename}", get(av_asset))
        // AV SFU WebSocket endpoint (MoQ over WebSocket for browser/native clients)
        .route("/av/moq", get(av_moq_ws_root))
        .route("/av/moq/{*path}", get(av_moq_ws))
        .route("/api/v1/av/sessions/{id}/token", get(api_av_session_token))
        // AV sessions
        .route("/api/v1/sessions", get(api_sessions_list))
        .route("/api/v1/sessions/{id}", get(api_session_detail))
        .route(
            "/api/v1/sessions/{id}/artifacts",
            get(api_session_artifacts).post(api_create_artifact),
        )
        .route(
            "/api/v1/channels/{name}/sessions",
            get(api_channel_sessions),
        )
        .route("/auth/mobile", get(auth_mobile_redirect))
        .route("/join/{channel}", get(channel_invite_page))
        .layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024)) // 12MB
        .layer({
            use axum::http::{Method, header};
            use tower_http::cors::AllowOrigin;
            let origins = [
                "https://irc.freeq.at",
                "https://auth.freeq.at",
                "https://freeq.at",
                "http://127.0.0.1:5173", // vite dev
                "http://localhost:5173",
            ];
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(
                    origins.iter().filter_map(|o| o.parse().ok()),
                ))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::CONTENT_TYPE,
                    header::AUTHORIZATION,
                    "X-Broker-Signature".parse().unwrap(),
                ])
                .allow_credentials(true)
        });

    // Policy API endpoints
    if state.policy_engine.is_some() {
        app = app.merge(crate::policy::api::routes());
    }

    // Agent Assistance Interface (.well-known/agent.json + /agent/tools/*)
    app = app.merge(crate::agent_assist::api::routes());

    // Build verifier router (stashed, merged after .with_state())
    let verifier_router = {
        let github_config =
            state
                .config
                .github_client_id
                .as_ref()
                .map(|id| crate::verifiers::GitHubConfig {
                    client_id: id.clone(),
                    client_secret: state
                        .config
                        .github_client_secret
                        .clone()
                        .unwrap_or_default(),
                });
        let issuer_did = format!("did:web:{}:verify", state.config.server_name);
        let data_dir = state
            .config
            .db_path
            .as_ref()
            .map(|p| {
                std::path::Path::new(p)
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
            })
            .unwrap_or(std::path::Path::new("."));
        crate::verifiers::router(issuer_did, github_config, data_dir).map(|(r, _)| r)
    };

    // Loud failure for unmounted verifier routes. The SPA fallback below
    // serves index.html for any unmatched path — including /verify/github/*
    // when the GitHub verifier isn't configured (GITHUB_CLIENT_ID unset).
    // That made a missing verifier look like a working one (the web app
    // loads, no credential is ever issued, the join silently fails forever).
    // Return 503 instead. Concrete verifier routes are more specific than
    // this wildcard, so mounted verifiers are unaffected.
    app = app.route(
        "/verify/{*unmounted}",
        get(unmounted_verifier).post(unmounted_verifier),
    );

    // Startup warnings: verifiers referenced by stored policies but not
    // mounted on this server. A channel gated on an unmounted verifier can
    // never be newly joined — existing credential holders still get in,
    // which is exactly the "works for some people, not others" symptom.
    warn_about_unmounted_verifiers(&state);

    // Serve static web client files if the directory exists
    if let Some(ref web_dir) = state.config.web_static_dir {
        let dir = std::path::PathBuf::from(web_dir);
        if dir.exists() {
            tracing::info!("Serving web client from {}", dir.display());
            // SPA fallback: serve index.html for any path not matching a static file
            let index_path = dir.join("index.html");
            let serve = tower_http::services::ServeDir::new(&dir)
                .append_index_html_on_directories(true)
                .fallback(tower_http::services::ServeFile::new(index_path));
            app = app.fallback_service(serve);
        } else {
            tracing::warn!("Web static dir not found: {}", dir.display());
        }
    }

    // Apply state, then merge verifier (which has its own state already applied)
    let mut final_app = app.with_state(state.clone());
    if let Some(vr) = verifier_router {
        final_app = final_app.merge(vr);
    }
    // Embedded broker: with no separate broker configured (BROKER_SHARED_SECRET
    // unset), serve the broker's /session + graph endpoints in-process, backed
    // by an ephemeral in-memory store and a LocalWriter into our own state. A
    // separate broker (secret set) uses the /auth/broker/* receiver path instead.
    if let Some(store) = state.embedded_session_store.clone() {
        let broker_state = Arc::new(freeq_auth_broker::BrokerState {
            // client_id is stored per-session, so these are unused by the
            // /session + graph paths.
            config: freeq_auth_broker::BrokerConfig {
                public_url: String::new(),
                freeq_server_url: String::new(),
                shared_secret: String::new(),
            },
            writer: Arc::new(LocalWriter {
                state: state.clone(),
            }),
            // Same store instance auth_callback persists into.
            store,
            pending: tokio::sync::Mutex::new(Default::default()),
            completed: tokio::sync::Mutex::new(Default::default()),
            callback_locks: tokio::sync::Mutex::new(Default::default()),
            refresh_locks: tokio::sync::Mutex::new(Default::default()),
        });
        final_app = final_app.merge(freeq_auth_broker::session_router(broker_state));
    }
    // Security headers as outermost layer so they apply to all responses
    // including static files served via fallback_service
    final_app.layer(axum::middleware::from_fn(security_headers))
}

/// Handler for /verify/* paths with no mounted verifier (e.g. GitHub when
/// GITHUB_CLIENT_ID is unset). Returns 503 with a clear message instead of
/// letting the SPA fallback pretend everything is fine.
async fn unmounted_verifier(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    // Only the first path segment is used for the provider hint, and the
    // user-controlled path is never echoed into the HTML unescaped.
    let provider = path.split('/').next().unwrap_or("").to_string();
    let provider = if provider
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        provider
    } else {
        "unknown".to_string()
    };
    tracing::warn!(provider = %provider, "request hit unmounted /verify route");
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Verifier not configured</title>
<style>
body {{ font-family: system-ui; max-width: 500px; margin: 40px auto; padding: 0 20px; background: #0a0a1a; color: #e0e0e0; }}
.card {{ background: #1a1a2e; border-radius: 16px; padding: 32px; }}
h1 {{ color: #e74c3c; font-size: 20px; }}
code {{ background: #000; padding: 2px 6px; border-radius: 4px; }}
</style></head><body>
<div class="card">
<h1>✗ Verification provider not configured</h1>
<p>The <code>{provider}</code> verifier is not enabled on this server, so this
channel's requirements cannot be verified right now.</p>
<p>Please tell the server operator: this usually means
<code>GITHUB_CLIENT_ID</code>/<code>GITHUB_CLIENT_SECRET</code> (or the OIDC
equivalent) is missing from the server configuration.</p>
</div>
</body></html>"#,
    );
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::response::Html(html),
    )
}

/// Log a loud startup warning for every stored policy whose credential
/// endpoints point at verifier routes this server hasn't mounted (GitHub
/// without GITHUB_CLIENT_ID, OIDC without OIDC_CLIENT_ID). Such channels are
/// silently unjoinable for new members — exactly the "sometimes users can't
/// join" symptom — so the operator needs to hear about it at boot.
fn warn_about_unmounted_verifiers(state: &Arc<SharedState>) {
    let github_mounted = state.config.github_client_id.is_some();
    let oidc_mounted = crate::verifiers::oidc::OidcConfig::from_env().is_some();

    if !github_mounted {
        tracing::warn!(
            "GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET not configured — /verify/github/* is disabled; \
             channels gated on github_repo/github_membership credentials cannot verify new members"
        );
    }

    let Some(ref engine) = state.policy_engine else {
        return;
    };
    let channels = match engine.store().list_policy_channels() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "could not scan policies for unmounted verifiers");
            return;
        }
    };
    for channel in channels {
        let Ok(Some(policy)) = engine.store().get_current_policy(&channel) else {
            continue;
        };
        for (cred_type, ep) in &policy.credential_endpoints {
            let url = &ep.url;
            if !github_mounted && url.starts_with("/verify/github/") {
                tracing::error!(
                    channel = %channel,
                    credential_type = %cred_type,
                    endpoint = %url,
                    "POLICY DEAD-END: channel requires a credential whose verifier is NOT mounted \
                     (GitHub OAuth is not configured). New members cannot join. \
                     Set GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET and restart."
                );
            }
            if !oidc_mounted && url.starts_with("/verify/oidc/") {
                tracing::error!(
                    channel = %channel,
                    credential_type = %cred_type,
                    endpoint = %url,
                    "POLICY DEAD-END: channel requires a credential whose verifier is NOT mounted \
                     (OIDC is not configured). New members cannot join."
                );
            }
        }
    }
}

// ── WebSocket handler ──────────────────────────────────────────────────

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<SharedState>>,
) -> impl IntoResponse {
    let ip = addr.ip();
    // Per-IP connection limit for WebSocket (same limit as TCP)
    const MAX_CONNS_PER_IP: u32 = 20;
    {
        let ip_conns = state.ip_connections.lock();
        if ip_conns.get(&ip).copied().unwrap_or(0) >= MAX_CONNS_PER_IP {
            tracing::warn!(%ip, "WebSocket connection rejected: per-IP limit reached");
            return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    ws.on_upgrade(move |socket| handle_ws(socket, state, ip))
        .into_response()
}

async fn handle_ws(socket: WebSocket, state: Arc<SharedState>, ip: std::net::IpAddr) {
    {
        let mut ip_conns = state.ip_connections.lock();
        *ip_conns.entry(ip).or_insert(0) += 1;
    }
    let stream = bridge_ws(socket);
    if let Err(e) = crate::connection::handle_generic(stream, state.clone()).await {
        tracing::error!("WebSocket connection error: {e}");
    }
    // Decrement on disconnect
    let mut ip_conns = state.ip_connections.lock();
    if let Some(count) = ip_conns.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            ip_conns.remove(&ip);
        }
    }
}

// ── REST types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    server_name: String,
    version: &'static str,
    git_commit: &'static str,
    connections: usize,
    channels: usize,
    uptime_secs: u64,
    /// Whether calls can actually be placed: the binary was built with
    /// `--features av-native` *and* the SFU came up.
    ///
    /// Reported because there is no other cheap way to tell from outside. A
    /// server built without the feature looks entirely healthy — IRC, history
    /// and the web client all work — while every AV endpoint answers 503. That
    /// shipped to production once, and the only signal was a user trying a call.
    av: bool,
    /// Whether private media spaces are configured.
    media_spaces: bool,
}

#[derive(Serialize)]
struct ChannelInfo {
    name: String,
    members: usize,
    topic: Option<String>,
}

#[derive(Serialize)]
struct ChannelTopicResponse {
    channel: String,
    topic: Option<String>,
    set_by: Option<String>,
    set_at: Option<u64>,
}

#[derive(Serialize)]
struct MessageResponse {
    id: i64,
    sender: String,
    text: String,
    timestamp: u64,
    tags: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    msgid: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
    before: Option<u64>,
}

#[derive(Deserialize)]
struct SearchQuery {
    channel: String,
    q: String,
    limit: Option<usize>,
    before: Option<u64>,
}

#[derive(Serialize)]
struct UserResponse {
    nick: String,
    online: bool,
    did: Option<String>,
    handle: Option<String>,
}

#[derive(Serialize)]
struct WhoisResponse {
    nick: String,
    online: bool,
    did: Option<String>,
    handle: Option<String>,
    channels: Vec<String>,
}

// ── REST handlers ──────────────────────────────────────────────────────

/// Server start time, stamped when the HTTP router is built — i.e. at boot.
///
/// It used to be initialized by `api_health` itself, which made `uptime_secs`
/// mean "seconds since someone first asked", not seconds since start: after a
/// restart the first poll always read 0 and the counter began from whenever
/// monitoring happened to notice. Stamping it at router construction is the
/// answer the field claims to give.
static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

/// Public endpoint: returns the server's message signing public key.
/// Clients and federated servers use this to verify `+freeq.at/sig` tags.
async fn api_signing_key(State(state): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let vk = state.msg_signing_key.verifying_key();
    use base64::Engine;
    let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.as_bytes());
    Json(serde_json::json!({
        "algorithm": "ed25519",
        "public_key": pubkey_b64,
        "encoding": "base64url",
        "usage": "message-signing",
        "canonical_form": "jcs-per-event-kind",
        "spec": "https://github.com/freeq-irc/freeq/blob/main/spec/chat-signing-vectors.json",
        "sig_tag_format": "ed25519:<kid>:<base64url-nopad signature>",
        "tag": "+freeq.at/sig"
    }))
}

/// Per-DID signing key: the DID's latest registered signing key, from the
/// durable store (the single source of truth — survives restart, covers every
/// DID that ever registered). A specific historical key is fetched via
/// `/{did}/{kid}`.
async fn api_did_signing_key(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    use base64::Engine;
    let did_decoded = urlencoding::decode(&did).unwrap_or(std::borrow::Cow::Borrowed(&did));
    match state
        .with_db(|db| db.get_signing_key(did_decoded.as_ref()))
        .flatten()
    {
        Some(pubkey) => Ok(Json(serde_json::json!({
            "did": did_decoded.as_ref(),
            "algorithm": "ed25519",
            "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey),
            "encoding": "base64url",
            "source": "key-store"
        }))),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

/// Per-DID, per-kid signing key: the exact historical key the DID registered
/// under `kid`, from the durable store. This is the lookup a verifier uses when
/// a signature names its kid — the key stays available after the signer's
/// session ends, unlike `/{did}` which is the current one.
async fn api_did_signing_key_by_kid(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path((did, kid)): axum::extract::Path<(String, String)>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    use base64::Engine;
    let did_decoded = urlencoding::decode(&did).unwrap_or(std::borrow::Cow::Borrowed(&did));
    let kid_decoded = urlencoding::decode(&kid).unwrap_or(std::borrow::Cow::Borrowed(&kid));
    match state
        .with_db(|db| db.get_signing_key_by_kid(did_decoded.as_ref(), kid_decoded.as_ref()))
        .flatten()
    {
        Some(pubkey) => Ok(Json(serde_json::json!({
            "did": did_decoded.as_ref(),
            "kid": kid_decoded.as_ref(),
            "algorithm": "ed25519",
            "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey),
            "encoding": "base64url",
            "source": "key-store"
        }))),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

/// Verify a message's cryptographic signature by msgid.
/// Returns the message, signature, verification result, and the math to prove it.
/// GET /api/v1/channels/{name}/agent-capabilities — list active capability grants.
async fn api_agent_capabilities(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // What this channel's agents are permitted to do.
    authorize_channel_read(&state, &name, &headers)?;
    let channel = format!("#{name}");
    let grants: Vec<serde_json::Value> = state
        .with_db(|db| {
            // Get all agents in the channel
            let members: Vec<String> = {
                let channels = state.channels.lock();
                channels
                    .get(&channel.to_lowercase())
                    .map(|ch| ch.members.iter().cloned().collect())
                    .unwrap_or_default()
            };
            let dids: Vec<String> = {
                let sd = state.session_dids.lock();
                members
                    .iter()
                    .filter_map(|sid| sd.get(sid).cloned())
                    .collect()
            };
            let mut all = Vec::new();
            for did in &dids {
                for g in db.get_capabilities(&channel.to_lowercase(), did) {
                    all.push(serde_json::json!({
                        "id": g.id,
                        "agent_did": g.agent_did,
                        "capability": g.capability,
                        "scope": g.scope,
                        "ttl_seconds": g.ttl_seconds,
                        "requires_approval": g.requires_approval,
                        "rate_limit": g.rate_limit,
                        "granted_by": g.granted_by,
                        "granted_at": g.granted_at,
                        "expires_at": g.expires_at,
                    }));
                }
            }
            Ok(all)
        })
        .unwrap_or_default();
    Ok(Json(
        serde_json::json!({ "channel": channel, "capabilities": grants }),
    ))
}

/// GET /api/v1/channels/{name}/approvals — list pending approvals.
async fn api_pending_approvals(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // What a private channel is waiting on a human to decide.
    authorize_channel_read(&state, &name, &headers)?;
    let channel = format!("#{name}");
    let approvals: Vec<serde_json::Value> = state
        .with_db(|db| {
            Ok(db
                .get_pending_approvals(&channel.to_lowercase())
                .into_iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "agent_did": a.agent_did,
                        "capability": a.capability,
                        "resource": a.resource,
                        "requested_at": a.requested_at,
                        "expires_at": a.expires_at,
                    })
                })
                .collect::<Vec<_>>())
        })
        .unwrap_or_default();
    Ok(Json(
        serde_json::json!({ "channel": channel, "approvals": approvals }),
    ))
}

/// GET /api/v1/channels/{name}/events — query coordination events.
async fn api_channel_events(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Signed task cards and agent activity — private-channel coordination must
    // not be world-readable.
    let channel = authorize_channel_read(&state, &name, &headers)?;
    let event_type = params.get("type").map(|s| s.as_str());
    let ref_id = params.get("ref_id").map(|s| s.as_str());
    let actor = params.get("actor").map(|s| s.as_str());
    let since = params.get("since").and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp())
            .or_else(|| s.parse::<i64>().ok())
    });
    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize);

    let events: Vec<serde_json::Value> = state
        .with_db(|db| {
            Ok(db.query_coordination_events(&channel.to_lowercase(), event_type, ref_id, actor, since, limit)
                .into_iter()
                .map(|e| serde_json::json!({
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "actor_did": e.actor_did,
                    "channel": e.channel,
                    "ref_id": e.ref_id,
                    "payload": serde_json::from_str::<serde_json::Value>(&e.payload_json).unwrap_or(serde_json::json!({})),
                    "signature": e.signature,
                    "timestamp": e.timestamp,
                }))
                .collect::<Vec<_>>())
        })
        .unwrap_or_default();
    Ok(Json(
        serde_json::json!({ "channel": channel, "events": events }),
    ))
}

/// Whether the caller may read what happens in `venue`.
///
/// A channel goes through the same check a channel read gets. A direct
/// conversation is readable only by its two participants — channel
/// authorization says nothing about DMs, and without this the listing would
/// publish who is tasking whom.
fn authorize_venue_read(state: &SharedState, venue: &str, headers: &axum::http::HeaderMap) -> bool {
    match venue.strip_prefix("dm:") {
        Some(pair) => caller_did_from_bearer(state, headers)
            .is_some_and(|did| pair.split(',').any(|p| p == did)),
        None => authorize_channel_read(state, venue, headers).is_ok(),
    }
}

/// One task as this server answers for it.
///
/// `orphaned` is this server's own reading of the task's home — see
/// [`crate::act_relay::reads_orphaned`]. When it holds, `state` says
/// `orphaned` so a client sees honest liveness instead of forever-fresh work,
/// and `stored_state` still carries what the task's own record says, because
/// the annotation changes nothing about the task itself.
fn act_task_json(
    task: &crate::db::ActTask,
    orphaned: bool,
    dropped_unchecked: i64,
) -> serde_json::Value {
    serde_json::json!({
        "act_id": task.act_id,
        "kind": task.kind,
        "venue": task.venue,
        "origin": task.origin,
        "state": if orphaned { crate::act_relay::ORPHANED } else { task.state.as_str() },
        "stored_state": task.state,
        "offerer": task.offerer,
        "offeree": task.offeree,
        "assignee": task.assignee,
        "caps": task.caps,
        "deadline": task.deadline,
        // The finished action this one revives, when its opener named one.
        // Null otherwise, and null is the honest answer for an action that
        // revives nothing — the same shape `offeree` and `caps` already have.
        "replaces": task.replaces,
        "updated": task.updated,
        // How many events about this task were dropped from the defer queue
        // unchecked — this server's own count, never relayed: a reader's
        // notice that the record here may be incomplete.
        "dropped_unchecked": dropped_unchecked,
    })
}

/// Which of these task homes this server has lost contact with, by the
/// operator's `act_orphan_secs` threshold.
///
/// Own tasks (an empty origin) are never asked about — we are their home.
async fn homes_out_of_contact<'a>(
    state: &Arc<SharedState>,
    origins: impl Iterator<Item = &'a str>,
) -> std::collections::HashSet<String> {
    let ttl = std::time::Duration::from_secs(state.config.act_orphan_secs);
    let wanted: std::collections::HashSet<String> = origins
        .filter(|o| !o.is_empty())
        .map(str::to_string)
        .collect();
    if ttl.is_zero() || wanted.is_empty() {
        return std::collections::HashSet::new();
    }
    let Some(manager) = state.s2s_manager.lock().clone() else {
        // Federation is switched off, so every one of these homes is
        // unreachable and will stay that way until an operator says otherwise.
        // No grace period: the threshold measures how long a link has been
        // down, and a server with no federation at all has no link to time.
        // Waiting a day to admit that would be the forever-fresh lie this
        // annotation exists to stop.
        return wanted;
    };
    let mut gone = std::collections::HashSet::new();
    for home in wanted {
        if manager.peer_out_of_contact(&home, ttl).await {
            gone.insert(home);
        }
    }
    gone
}

/// GET /api/v1/actions — the live tasks this caller may see.
///
/// Filters: `kind`, `assignee`, `state`. Open work is the question this
/// answers, so finished tasks are not here — their history is at the
/// single-task endpoint, which still serves them from the log.
async fn api_act_tasks(
    State(state): State<Arc<SharedState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let venues: Vec<String> = state
        .with_db(|db| db.act_venues())
        .unwrap_or_default()
        .into_iter()
        .filter(|v| authorize_venue_read(&state, v, &headers))
        .collect();

    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize)
        .min(500);
    let rows = state
        .with_db(|db| {
            db.act_tasks(
                &venues,
                params.get("kind").map(|s| s.as_str()),
                params.get("assignee").map(|s| s.as_str()),
                params.get("state").map(|s| s.as_str()),
                limit,
            )
        })
        .unwrap_or_default();
    // One pass over the homes named here, rather than one lock pair per row:
    // every task a given server minted has the same answer.
    let gone = homes_out_of_contact(&state, rows.iter().map(|t| t.origin.as_str())).await;
    let tasks: Vec<serde_json::Value> = rows
        .iter()
        .map(|t| {
            act_task_json(
                t,
                crate::act_relay::reads_orphaned(
                    &t.origin,
                    &t.kind,
                    &t.state,
                    gone.contains(&t.origin),
                ),
                state
                    .with_db(|db| db.act_dropped_unchecked(&t.act_id))
                    .unwrap_or(0),
            )
        })
        .collect();

    Ok(Json(serde_json::json!({ "tasks": tasks })))
}

/// GET /api/v1/actions/{act_id} — one task and every event of it.
///
/// Serves a finished task too: the view drops it, the log keeps it, and the
/// history is what a reader came for. `task` is null once it has ended.
async fn api_act_task(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(act_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let events = state
        .with_db(|db| db.act_task_events(&act_id))
        .unwrap_or_default();
    // The venue comes from the events themselves, so a finished task is
    // authorized by where it happened rather than by a row that is gone.
    let Some(venue) = events.first().map(|e| e.venue.clone()) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !authorize_venue_read(&state, &venue, &headers) {
        return Err(StatusCode::FORBIDDEN);
    }

    let row = state.with_db(|db| db.act_task(&act_id)).flatten();
    let gone = homes_out_of_contact(&state, row.iter().map(|t| t.origin.as_str())).await;
    let task = row.as_ref().map(|t| {
        act_task_json(
            t,
            crate::act_relay::reads_orphaned(
                &t.origin,
                &t.kind,
                &t.state,
                gone.contains(&t.origin),
            ),
            state
                .with_db(|db| db.act_dropped_unchecked(&t.act_id))
                .unwrap_or(0),
        )
    });
    let history: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "event_id": e.event_id,
                "canonical": e.canonical,
                "signature": e.signature,
                "actor_did": e.actor_did,
                "venue": e.venue,
                // Whose ruling this event carries. A reader has to be able to
                // tell an event that decided something from one that is on
                // file and waiting on the server that owns the task:
                // "confirmed", "unconfirmed", or "superseded" — the last being
                // a move a confirmed one outran. Absent for a receipt, which
                // is the answer itself and has no state of its own.
                "confirm_state": e.confirm.map(crate::events::ConfirmState::as_str),
                "timestamp": e.timestamp,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "act_id": act_id,
        "venue": venue,
        "task": task,
        "events": history,
    })))
}

/// GET /api/v1/tasks/{task_id} — task detail with all related events.
async fn api_task(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let result = state.with_db(|db| {
        let task = db.get_task(&task_id);
        let events = db.get_task_events_all_channels(&task_id);
        Ok((task, events))
    });

    match result {
        Some((Some(task), events)) => {
            let status = events
                .iter()
                .rev()
                .find(|e| e.event_type == "task_complete" || e.event_type == "task_failed")
                .map(|e| e.event_type.clone())
                .unwrap_or_else(|| "in_progress".to_string());
            let evidence: Vec<serde_json::Value> = events.iter()
                .filter(|e| e.event_type == "evidence_attach")
                .map(|e| serde_json::json!({
                    "event_id": e.event_id,
                    "payload": serde_json::from_str::<serde_json::Value>(&e.payload_json).unwrap_or(serde_json::json!({})),
                    "timestamp": e.timestamp,
                }))
                .collect();
            let all_events: Vec<serde_json::Value> = events.iter()
                .map(|e| serde_json::json!({
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "actor_did": e.actor_did,
                    "payload": serde_json::from_str::<serde_json::Value>(&e.payload_json).unwrap_or(serde_json::json!({})),
                    "signature": e.signature,
                    "timestamp": e.timestamp,
                }))
                .collect();
            Json(serde_json::json!({
                "task_id": task.event_id,
                "description": serde_json::from_str::<serde_json::Value>(&task.payload_json)
                    .ok().and_then(|v| v.get("description").cloned())
                    .unwrap_or(serde_json::json!(null)),
                "status": status,
                "actor_did": task.actor_did,
                "channel": task.channel,
                "created_at": task.timestamp,
                "events": all_events,
                "evidence": evidence,
            }))
        }
        _ => Json(serde_json::json!({ "error": "Task not found" })),
    }
}

/// GET /api/v1/channels/{name}/audit — unified audit timeline.
async fn api_channel_audit(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // The audit timeline is the governance history of the room: coordination
    // events, actor DIDs, signatures and payloads. Same access rules as history.
    let channel = authorize_channel_read(&state, &name, &headers)?;
    let actor = params.get("actor").map(|s| s.as_str());
    let since = params.get("since").and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp())
            .or_else(|| s.parse::<i64>().ok())
    });
    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200usize);

    let mut timeline: Vec<serde_json::Value> = Vec::new();

    // 1. Coordination events
    if let Some(events) = state.with_db(|db| {
        Ok(db.query_coordination_events(&channel.to_lowercase(), None, None, actor, since, limit))
    }) {
        for e in events {
            timeline.push(serde_json::json!({
                "timestamp": e.timestamp,
                "category": "coordination",
                "event": e.event_type,
                "actor_did": e.actor_did,
                "details": serde_json::from_str::<serde_json::Value>(&e.payload_json).unwrap_or(serde_json::json!({})),
                "signature": e.signature,
                "event_id": e.event_id,
            }));
        }
    }

    // 2. Governance log
    if let Some(entries) = state.with_db(|db| {
        Ok(db
            .query_governance_log(Some(&channel), limit)
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "category": "governance",
                    "event": e.action,
                    "actor_did": e.target_did,
                    "details": {
                        "issued_by": e.issued_by,
                        "reason": e.reason,
                    },
                })
            })
            .collect::<Vec<_>>())
    }) {
        timeline.extend(entries);
    }

    // A row says who acted, not what their identifier is. Resolve every actor
    // the same way the rest of the server does — a client can only name a DID
    // it has seen, and an audit row's actor is usually an agent that is long
    // gone. `display_nick_for_did` returns the DID itself when it resolves
    // nothing, and sending that as a name would put a raw identifier on
    // screen; an unresolved actor carries no name instead, leaving the client
    // free to compact it.
    for row in &mut timeline {
        let Some(did) = row
            .get("actor_did")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            continue;
        };
        let name = state.display_nick_for_did(&did);
        if name != did {
            row["actor_name"] = serde_json::json!(name);
        }
    }

    // Sort by timestamp
    timeline.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        ta.cmp(&tb)
    });
    if timeline.len() > limit {
        timeline.truncate(limit);
    }

    Ok(Json(
        serde_json::json!({ "channel": channel, "timeline": timeline }),
    ))
}

/// GET /api/v1/agents/manifests — list all registered manifests.
async fn api_list_manifests(State(state): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let manifests: Vec<serde_json::Value> = state
        .with_db(|db| {
            Ok(db
                .list_manifests()
                .into_iter()
                .map(|(did, json, ts)| {
                    let parsed = serde_json::from_str::<serde_json::Value>(&json)
                        .unwrap_or(serde_json::json!({}));
                    serde_json::json!({
                        "agent_did": did,
                        "manifest": parsed,
                        "registered_at": ts,
                    })
                })
                .collect::<Vec<_>>())
        })
        .unwrap_or_default();
    Json(serde_json::json!({ "manifests": manifests }))
}

/// GET /api/v1/agents/manifests/{did} — get a specific manifest.
async fn api_get_manifest(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let did_decoded = did.replace("%3A", ":").replace("%3a", ":");
    match state.with_db(|db| Ok(db.get_manifest(&did_decoded))) {
        Some(Some(json)) => {
            let parsed =
                serde_json::from_str::<serde_json::Value>(&json).unwrap_or(serde_json::json!({}));
            Json(serde_json::json!({ "agent_did": did_decoded, "manifest": parsed }))
        }
        _ => Json(serde_json::json!({ "error": "Manifest not found" })),
    }
}

/// GET /api/v1/agents/spawned — list all active spawned agents.
async fn api_spawned_agents(State(state): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let agents: Vec<serde_json::Value> = state
        .spawned_agents
        .lock()
        .values()
        .map(|sa| {
            serde_json::json!({
                "child_did": sa.child_did,
                "parent_did": sa.parent_did,
                "nick": sa.nick,
                "channel": sa.channel,
                "capabilities": sa.capabilities,
                "ttl": sa.ttl,
                "task_ref": sa.task_ref,
                "spawned_at": sa.spawned_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "spawned_agents": agents }))
}

/// GET /api/v1/channels/{name}/budget — budget status.
async fn api_channel_budget(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Spend limits and burn-down for a private channel's agents.
    authorize_channel_read(&state, &name, &headers)?;
    let channel = format!("#{name}");
    let budget_json = state
        .with_db(|db| Ok(db.get_budget(&channel.to_lowercase(), None)))
        .flatten();
    Ok(match budget_json {
        Some(bj) => {
            if let Ok(budget) = serde_json::from_str::<crate::policy::types::BudgetPolicy>(&bj) {
                let period_start = crate::connection::budget_period_start(&budget.period);
                let total_spent = state
                    .with_db(|db| {
                        Ok(db.sum_spend(&channel.to_lowercase(), None, &budget.unit, period_start))
                    })
                    .unwrap_or(0.0);
                let by_agent: Vec<serde_json::Value> = state
                    .with_db(|db| {
                        Ok(db
                            .spend_by_agent(&channel.to_lowercase(), &budget.unit, period_start)
                            .into_iter()
                            .map(|(did, spent, count)| {
                                serde_json::json!({
                                    "agent_did": did,
                                    "spent": spent,
                                    "items": count,
                                })
                            })
                            .collect::<Vec<_>>())
                    })
                    .unwrap_or_default();
                let remaining = budget.max_amount - total_spent;
                let pct = if budget.max_amount > 0.0 {
                    total_spent / budget.max_amount * 100.0
                } else {
                    0.0
                };
                Json(serde_json::json!({
                    "channel": channel,
                    "policy": serde_json::from_str::<serde_json::Value>(&bj).unwrap_or_default(),
                    "current_period": {
                        "total_spent": total_spent,
                        "remaining": remaining,
                        "percent_used": pct,
                        "by_agent": by_agent,
                    },
                }))
            } else {
                Json(serde_json::json!({ "channel": channel, "error": "Invalid budget policy" }))
            }
        }
        None => Json(serde_json::json!({ "channel": channel, "budget": null })),
    })
}

/// GET /api/v1/channels/{name}/spend — spend records.
async fn api_channel_spend(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authorize_channel_read(&state, &name, &headers)?;
    let channel = format!("#{name}");
    let agent = params.get("agent").map(|s| s.as_str());
    let since = params.get("since").and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp())
            .or_else(|| s.parse::<i64>().ok())
    });
    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize);

    let records: Vec<serde_json::Value> = state
        .with_db(|db| {
            Ok(db
                .query_spend(&channel.to_lowercase(), agent, since, limit)
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "agent_did": r.agent_did,
                        "amount": r.amount,
                        "unit": r.unit,
                        "description": r.description,
                        "task_ref": r.task_ref,
                        "timestamp": r.timestamp,
                    })
                })
                .collect::<Vec<_>>())
        })
        .unwrap_or_default();
    Ok(Json(
        serde_json::json!({ "channel": channel, "spend": records }),
    ))
}

/// GET /api/v1/actors/{did} — identity card for any actor (human or agent).
async fn api_actor_identity(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // URL-decode the DID (colons may be encoded)
    let did = urlencoding::decode(&did)
        .unwrap_or(std::borrow::Cow::Borrowed(&did))
        .to_string();

    // Find session(s) for this DID
    let sessions: Vec<String> = state
        .session_dids
        .lock()
        .iter()
        .filter(|(_, d)| d.as_str() == did)
        .map(|(sid, _)| sid.clone())
        .collect();

    let online = !sessions.is_empty();

    // Actor class (from first active session, or default to human)
    let actor_class = sessions
        .iter()
        .find_map(|sid| state.session_actor_class.lock().get(sid).copied())
        .unwrap_or(crate::connection::ActorClass::Human);

    // Nick — prefer the live nick from an active session; fall back to
    // the persistent `identities` table for offline DIDs so callers like
    // the freeq-app provenance card can resolve e.g. a moderator's
    // did:key to "lobot" even when the moderator process isn't running.
    // Without this fallback, sub-agent provenance cards rendered the
    // raw "did:key:z6Mk…" string for any creator whose process had
    // exited since the sub-agent was spawned.
    let nick = {
        let nts = state.nick_to_session.lock();
        let live = sessions
            .iter()
            .find_map(|sid| nts.get_nick(sid).map(|n| n.to_string()));
        drop(nts);
        live.or_else(|| {
            state
                .with_db(|db| db.get_identity_by_did(&did))
                .flatten()
                .map(|row| row.nick)
        })
    };

    // Handle
    let handle = sessions
        .iter()
        .find_map(|sid| state.session_handles.lock().get(sid).cloned());

    // Channels
    let channels: Vec<String> = {
        let chs = state.channels.lock();
        chs.iter()
            .filter(|(_, ch)| sessions.iter().any(|sid| ch.members.contains(sid)))
            .map(|(name, _)| name.clone())
            .collect()
    };

    // Provenance
    let provenance = state.provenance_declarations.lock().get(&did).cloned();

    // Presence (from first session with presence)
    let presence = sessions
        .iter()
        .find_map(|sid| state.agent_presence.lock().get(sid).cloned());

    // Heartbeat
    let heartbeat = sessions.iter().find_map(|sid| {
        state.agent_heartbeats.lock().get(sid).map(|(last, ttl)| {
            let now = chrono::Utc::now().timestamp();
            let elapsed = now - last;
            serde_json::json!({
                "last_seen": last,
                "ttl_seconds": ttl,
                "healthy": elapsed <= (*ttl as i64),
                "elapsed_seconds": elapsed,
            })
        })
    });

    // Check if this is a spawned agent (by DID or nick)
    let spawned = state
        .spawned_agents
        .lock()
        .values()
        .find(|sa| sa.child_did == did || sa.nick.eq_ignore_ascii_case(&did))
        .cloned();

    if let Some(sa) = spawned {
        // Return spawned agent identity card
        let parent_nick = {
            let nts = state.nick_to_session.lock();
            nts.get_nick(&sa.parent_session).map(|n| n.to_string())
        };
        let parent_provenance = state
            .provenance_declarations
            .lock()
            .get(&sa.parent_did)
            .cloned();
        let result = serde_json::json!({
            "did": sa.child_did,
            "actor_class": "agent",
            "online": true,
            "nick": sa.nick,
            "spawned": true,
            "parent_did": sa.parent_did,
            "parent_nick": parent_nick,
            "channel": sa.channel,
            "capabilities": sa.capabilities,
            "ttl": sa.ttl,
            "task": sa.task_ref,
            "spawned_at": sa.spawned_at,
            "provenance": parent_provenance,
        });
        return Ok(Json(result));
    }

    let mut result = serde_json::json!({
        "did": did,
        "actor_class": actor_class.to_string(),
        "online": online,
    });
    let obj = result.as_object_mut().unwrap();

    if let Some(nick) = nick {
        obj.insert("nick".into(), serde_json::json!(nick));
    }
    if let Some(handle) = handle {
        obj.insert("handle".into(), serde_json::json!(handle));
    }
    if !channels.is_empty() {
        obj.insert("channels".into(), serde_json::json!(channels));
    }
    if let Some(prov) = provenance {
        obj.insert("provenance".into(), prov);
    }
    if let Some(pres) = presence {
        obj.insert(
            "presence".into(),
            serde_json::to_value(&pres).unwrap_or_default(),
        );
    }
    if let Some(hb) = heartbeat {
        obj.insert("heartbeat".into(), hb);
    }

    Ok(Json(result))
}

/// GET /api/v1/channels/{name}/evidence?limit=&before=
///
/// Exports a self-contained, offline-verifiable evidence bundle for a channel:
/// the message range with each message's tags (so the document can be rebuilt),
/// the signing keys addressed by `kid`, the server signing key, and a server
/// signature over the whole bundle. `freeq-verify` (the offline CLI) rebuilds
/// each message's signed document with the shared `freeq_sdk::chatsig` builder
/// and checks the signatures with no server contact — confirming the content
/// was not altered, given the bundled key material is the authors'. (Binding a
/// key to its DID is asserted by the server at registration; confirming that
/// independently needs DID-document resolution, which the offline tool does
/// not do.) Legacy bare-base64 signatures on old history keep the retired
/// `{did}\0{channel}\0{text}\0{timestamp}` check via `did_keys`.
///
/// Authorization mirrors CHATHISTORY/search: public channels export openly,
/// restricted (+i/+k) channels require a member Bearer.
async fn api_channel_evidence(
    State(state): State<Arc<SharedState>>,
    Path(name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let channel = authorize_channel_read(&state, &name, &headers)
        .map_err(|code| (code, "not authorized to read this channel".to_string()))?;

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(5000);
    let before = params.get("before").and_then(|s| s.parse::<u64>().ok());

    let rows = state
        .with_db(|db| db.get_messages(&channel, limit, before))
        .unwrap_or_default();

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Signing keys the bundle needs. A current signature names the exact key
    // that made it (its `kid`), and a DID may have rotated keys, so keys are
    // addressed by kid. `did_keys` (latest key per DID) is kept only for the
    // legacy bare-base64 signatures on pre-cutover history, which carry no kid.
    let mut did_keys = serde_json::Map::new();
    {
        let by_did = state.did_msg_keys.lock();
        for row in &rows {
            if let Some(did) = &row.sender_did
                && !did_keys.contains_key(did)
                && let Some(pk) = by_did.get(did)
            {
                did_keys.insert(did.clone(), serde_json::Value::String(pk.clone()));
            }
        }
    }
    // Keys addressed by kid, looked up after the in-memory map's lock is dropped
    // (each is a separate DB read).
    let mut keys = serde_json::Map::new();
    for row in &rows {
        let Some(did) = &row.sender_did else { continue };
        if let Some(sig) = row.tags.get("+freeq.at/sig")
            && let Ok((kid, _)) = freeq_sdk::sigtag::parse(sig)
            && !keys.contains_key(kid)
            && let Some(bytes) = state
                .with_db(|db| db.get_signing_key_by_kid(did, kid))
                .flatten()
        {
            keys.insert(
                kid.to_string(),
                serde_json::Value::String(b64.encode(bytes)),
            );
        }
    }

    // The full tag map rides with each message so the offline verifier rebuilds
    // the signed document with the same `freeq_sdk::chatsig` builder the client
    // signed with — venue, reply, edit and covered coordination tags — instead
    // of a canonical the server hands it. Reconstruction from parts is what
    // keeps the check independent of this server.
    let messages: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let tags: serde_json::Map<String, serde_json::Value> = r
                .tags
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            serde_json::json!({
                "msgid": r.msgid,
                "channel": r.channel,
                "sender": r.sender,
                "sender_did": r.sender_did,
                "text": r.text,
                "timestamp": r.timestamp,
                "signature": r.tags.get("+freeq.at/sig"),
                // A federated edit carries its edit link only in this column —
                // S2S filters the tag map, so `+draft/edit` is not in `tags`.
                "replaces_msgid": r.replaces_msgid,
                "tags": tags,
            })
        })
        .collect();

    let server_pubkey = b64.encode(state.msg_signing_key.verifying_key().as_bytes());

    // Everything except the signature, canonicalized, then server-signed so the
    // bundle itself is tamper-evident.
    let mut bundle = serde_json::json!({
        "bundle_version": "2",
        "server_name": state.server_name,
        "server_public_key": server_pubkey,
        "channel": channel,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "message_count": messages.len(),
        "keys": keys,
        "did_keys": did_keys,
        "messages": messages,
    });

    let canonical = freeq_sdk::canonical::canonicalize(&bundle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("canonicalize: {e}"),
        )
    })?;
    let sig = {
        use ed25519_dalek::Signer;
        state.msg_signing_key.sign(canonical.as_bytes())
    };
    if let Some(obj) = bundle.as_object_mut() {
        obj.insert(
            "bundle_signature".to_string(),
            serde_json::Value::String(b64.encode(sig.to_bytes())),
        );
    }

    Ok(Json(bundle))
}

/// Classify a stored message's signature: `(verdict, verified_by, client key)`.
///
/// Three verdicts, never two. `invalid` is a statement about the bytes — the
/// key the signature names was found and the signature does not check out. A
/// signature this server merely *cannot* check is `unverifiable`, and the
/// distinction is not academic here: the two commonest cases are a legacy
/// signature over the retired canonical (never checkable by anyone, ours
/// included) and a key we don't hold. Reporting either as invalid would
/// present our own history, or a missing key, as forgery.
fn classify_message_signature(
    state: &Arc<SharedState>,
    sender_did: Option<&str>,
    canonical: Option<&str>,
    sig_tag: Option<&str>,
) -> (&'static str, &'static str, Option<String>) {
    let Some(sig_tag) = sig_tag else {
        return ("unverifiable", "unsigned", None);
    };
    // No sender DID means no document: the signature covers who sent it, and
    // we cannot rebuild a document around an unknown signer.
    let Some(canonical) = canonical else {
        return ("unverifiable", "unverifiable-unknown-sender", None);
    };
    let kid = match freeq_sdk::sigtag::parse(sig_tag) {
        Ok((kid, _)) => kid,
        // A signer using an algorithm this build doesn't know is a newer
        // client, not a forger.
        Err(freeq_sdk::sigtag::SigError::UnsupportedAlgorithm(_)) => {
            return ("unverifiable", "unverifiable-unknown-algorithm", None);
        }
        // Otherwise: a legacy signature, a bare base64 blob over
        // `did\0target\0text\0timestamp`, whose timestamp the client minted
        // and never transmitted. Never checkable, by anyone.
        Err(_) => return ("unverifiable", "unverifiable-legacy-format", None),
    };

    let server_vk = state.msg_signing_key.verifying_key();
    let key = if kid == freeq_sdk::sigtag::derive_kid(&server_vk) {
        Some((server_vk, "server-key"))
    } else {
        sender_did
            .and_then(|did| {
                state
                    .with_db(|db| db.get_signing_key_by_kid(did, kid))
                    .flatten()
            })
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .map(|vk| (vk, "client-session-key"))
    };
    let Some((vk, which)) = key else {
        return ("unverifiable", "unverifiable-unknown-key", None);
    };

    use base64::Engine;
    let client_public_key = (which == "client-session-key")
        .then(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.as_bytes()));
    match freeq_sdk::sigtag::verify_canonical(canonical, sig_tag, &vk) {
        Ok(()) => ("valid", which, client_public_key),
        Err(e) if e.is_unverifiable() => (
            "unverifiable",
            "unverifiable-unusable-signature",
            client_public_key,
        ),
        Err(_) => ("invalid", which, client_public_key),
    }
}

async fn api_verify_message(
    State(state): State<Arc<SharedState>>,
    axum::extract::Path(msgid): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // The database first: its row is authoritative about the venue and the
    // sender's DID, both of which the signed document covers. In-memory
    // history is the fallback for a server running without a database.
    let mut venue = String::new();
    let mut sender_did: Option<String> = None;
    let mut found: Option<crate::server::HistoryMessage> = None;
    // The message this row revises, as a column rather than a tag. A local edit
    // files `+draft/edit` among its tags; one that arrived over S2S carries the
    // linkage only in `replaces_msgid`, because the relayed tag map is filtered
    // to `+freeq.at/*`. `edit` is a covered field either way, so reading only
    // the tag rebuilt a document without it and reported an honest federated
    // edit as *invalid* — the accusation the three-state design exists to avoid.
    let mut revises: Option<String> = None;
    if let Some(row) = state
        .with_db(|db| db.find_message_by_msgid(&msgid))
        .flatten()
    {
        venue = row.channel.clone();
        sender_did = row.sender_did.clone();
        revises = row.replaces_msgid.clone();
        found = Some(crate::server::HistoryMessage {
            from: row.sender,
            text: row.text,
            timestamp: row.timestamp,
            tags: row.tags,
            msgid: row.msgid,
            edited: row.replaces_msgid.is_some(),
        });
    }
    if found.is_none() {
        let channels = state.channels.lock();
        for (ch_name, ch) in channels.iter() {
            if let Some(msg) = ch
                .history
                .iter()
                .find(|m| m.msgid.as_deref() == Some(msgid.as_str()))
            {
                venue = ch_name.clone();
                found = Some(msg.clone());
                break;
            }
        }
    }

    // Not a message this server can serve — but perhaps an event on file: a
    // delete, a reaction or its removal, or a deleted message's own log row.
    // The log stores the exact bytes that were signed, so the answer is read
    // back, not rebuilt — and it is hash-only: facts about the act, never a
    // body.
    let msg = match found {
        Some(msg) => msg,
        None => {
            if let Some(ev) = state.with_db(|db| db.get_event(&msgid)).flatten() {
                let canonical = (!ev.canonical.is_empty()).then_some(ev.canonical.as_str());
                let (verdict, verified_by, client_public_key) = classify_message_signature(
                    &state,
                    ev.actor_did.as_deref(),
                    canonical,
                    ev.signature.as_deref(),
                );
                let server_pubkey = {
                    use base64::Engine;
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(state.msg_signing_key.verifying_key().as_bytes())
                };
                let canonical_hex = canonical.map(|c| {
                    c.as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                });
                return Ok(Json(serde_json::json!({
                    "event_id": ev.event_id,
                    "kind": ev.kind,
                    "channel": ev.venue,
                    "actor_did": ev.actor_did,
                    "subject": ev.subject,
                    "emoji": ev.emoji,
                    "body_hash": ev.body_hash,
                    "timestamp": ev.timestamp,
                    "signature": ev.signature,
                    "canonical_form": canonical,
                    "canonical_hex": canonical_hex,
                    "verification": {
                        "valid": verdict == "valid",
                        "verdict": verdict,
                        "verified_by": verified_by,
                        "server_public_key": server_pubkey,
                        "client_public_key": client_public_key,
                    },
                    "how_to_verify": "The canonical_form is JCS over the signed document; the signature tag is ed25519:<kid>:<base64url sig> over its UTF-8 bytes"
                })));
            }
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Message {msgid} not found"),
            ));
        }
    };
    let sig_tag = msg.tags.get(freeq_sdk::sigtag::SIG_TAG).cloned();

    // The `account` tag is the origin's own statement of who sent this, which
    // is what the document binds. A row that carries neither it nor a stored
    // sender names nobody, and this endpoint says so — `unverifiable-unknown-
    // sender` below. Resolving the nick against our own records instead
    // rebuilt the document around whoever holds that nick *here*, which is a
    // verdict about a message the named identity may never have sent.
    if sender_did.is_none() {
        sender_did = msg.tags.get("account").cloned();
    }

    // Rebuild the exact document the signer signed, through the one builder
    // that does it — the same call the event log files with, so a reader's
    // answer and the log's row can never disagree about what was signed.
    //
    // The venue is the stored channel key folded: a local row is filed under a
    // normalized channel, but a row that arrived over S2S keeps the spelling
    // the origin's user typed, and a mixed-case federated channel would
    // otherwise rebuild a venue no signer ever signed and report honest
    // messages as invalid.
    venue = crate::events::venue_of(&venue);
    let canonical = sender_did.as_ref().map(|did| {
        crate::events::message_canonical(
            did,
            &msgid,
            &venue,
            &msg.text,
            &msg.tags,
            revises.as_deref(),
        )
    });

    let (verdict, verified_by, client_public_key) = classify_message_signature(
        &state,
        sender_did.as_deref(),
        canonical.as_deref(),
        sig_tag.as_deref(),
    );

    // A signer whose key we do not hold — typically someone on another
    // server, reached through history rather than through the link their
    // message arrived on. Ask for the key so the next read of this message
    // gets a real verdict; this read reports what is true right now.
    if verified_by == "unverifiable-unknown-key"
        && let (Some(did), Some(sig)) = (sender_did.as_deref(), sig_tag.as_deref())
    {
        crate::peer_keys::fetch_from_any_peer(&state, did, sig);
    }
    let server_vk = state.msg_signing_key.verifying_key();

    let server_pubkey = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_vk.as_bytes())
    };
    let verification = serde_json::json!({
        // `valid` stays for older clients; `verdict` is the honest three-way.
        "valid": verdict == "valid",
        "verdict": verdict,
        "verified_by": verified_by,
        "server_public_key": server_pubkey,
        "client_public_key": client_public_key,
    });

    let canonical_hex = canonical.as_ref().map(|c: &String| {
        c.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    Ok(Json(serde_json::json!({
        "msgid": msgid,
        "channel": venue,
        "from": msg.from,
        "text": msg.text,
        "timestamp": msg.timestamp,
        "sender_did": sender_did,
        "signature": sig_tag,
        "canonical_form": canonical,
        "canonical_hex": canonical_hex,
        "verification": verification,
        "how_to_verify": "The canonical_form is JCS over the signed document; the signature tag is ed25519:<kid>:<base64url sig> over its UTF-8 bytes"
    })))
}

/// Can this server carry a call? Both halves have to hold: the `av-native`
/// feature was compiled in, and `init_sfu` succeeded at boot. Either one missing
/// means the AV endpoints answer 503, which is invisible from every other
/// endpoint.
#[cfg(feature = "av-native")]
fn av_available(state: &Arc<SharedState>) -> bool {
    state.sfu_state.lock().is_some()
}

#[cfg(not(feature = "av-native"))]
fn av_available(_state: &Arc<SharedState>) -> bool {
    false
}

async fn api_health(State(state): State<Arc<SharedState>>) -> Json<HealthResponse> {
    // Initialized in `router`; the fallback keeps a hand-built app (tests) sane.
    let start = START_TIME.get_or_init(SystemTime::now);
    let uptime = start.elapsed().unwrap_or_default().as_secs();
    let connections = state.connections.lock().len();
    // Count only channels with members (not empty shells)
    let channels = state
        .channels
        .lock()
        .values()
        .filter(|ch| !ch.members.is_empty() || !ch.remote_members.is_empty())
        .count();
    Json(HealthResponse {
        server_name: state.server_name.clone(),
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("GIT_HASH"),
        connections,
        channels,
        uptime_secs: uptime,
        av: av_available(&state),
        media_spaces: state.media_space.is_some(),
    })
}

async fn api_channels(State(state): State<Arc<SharedState>>) -> Json<Vec<ChannelInfo>> {
    let channels = state.channels.lock();
    let mut list: Vec<ChannelInfo> = channels
        .iter()
        .filter(|(name, ch)| {
            // This endpoint is UNAUTHENTICATED — only ever expose channels that
            // carry no access restriction (+i/+k/+E/policy). Private channels
            // must not leak their name/topic/count to the open internet.
            if !state.channel_is_discoverable(name, ch) {
                return false;
            }
            // Show channels with members, or with a topic set
            let has_members = !ch.members.is_empty() || !ch.remote_members.is_empty();
            let has_topic = ch.topic.is_some();
            has_members || has_topic
        })
        .map(|(name, ch)| ChannelInfo {
            name: name.clone(),
            members: ch.members.len() + ch.remote_members.len(),
            topic: ch.topic.as_ref().map(|t| t.text.clone()),
        })
        .collect();
    // Sort: most members first, then alphabetically
    list.sort_by(|a, b| b.members.cmp(&a.members).then(a.name.cmp(&b.name)));
    Json(list)
}

/// GET /api/v1/favorites — the authenticated user's roaming favorite channels
/// (in saved order). Per-DID, so a user's favorites follow them across all
/// their devices. Requires a Bearer session.
async fn api_get_favorites(
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(did) = caller_did_from_bearer(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Bearer session required" })),
        );
    };
    let favs = state
        .with_db(|db| db.get_user_favorites(&did))
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "favorites": favs })),
    )
}

/// PUT /api/v1/favorites {"favorites": ["#a", "#b", ...]} — replace the
/// authenticated user's roaming favorites (order preserved). Channel names
/// only; capped at 200 to bound abuse. Returns the stored list.
async fn api_set_favorites(
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(did) = caller_did_from_bearer(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Bearer session required" })),
        );
    };
    let favs: Vec<String> = body
        .get("favorites")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter(|c| c.starts_with('#') || c.starts_with('&'))
                .map(|c| c.to_lowercase())
                .take(200)
                .collect()
        })
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.with_db(|db| db.set_user_favorites(&did, &favs, now));
    (
        StatusCode::OK,
        Json(serde_json::json!({ "favorites": favs })),
    )
}

/// Resolve the authenticated caller DID from a `Bearer <session-id>` header.
pub(crate) fn caller_did_from_bearer(
    state: &crate::server::SharedState,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    let sid = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    state.session_dids.lock().get(sid).cloned()
}

/// POST /api/v1/channels/{name}/groupkeys — a channel steward (founder or
/// DID-op) uploads group secrets sealed to each member's X25519 key. The server
/// stores opaque `EGK1:` blobs; it can never open them (server-blind key
/// distribution for VC-bootstrapped E2E channels). Body:
/// `{ "epoch": <n>, "keys": { "<member_did>": "EGK1:...", ... } }`.
async fn api_put_group_keys(
    Path(name): Path<String>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let channel = if name.starts_with('#') {
        name
    } else {
        format!("#{name}")
    };

    let Some(caller) = caller_did_from_bearer(&state, &headers) else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "Bearer session required" })),
        );
    };

    // Steward authorization: only the channel founder or a DID-op may distribute
    // group keys — the same DID authorities the policy layer already trusts.
    {
        let channels = state.channels.lock();
        let Some(ch) = channels.get(&channel.to_lowercase()) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({ "error": "Unknown channel" })),
            );
        };
        let is_authority =
            ch.founder_did.as_deref() == Some(caller.as_str()) || ch.did_ops.contains(&caller);
        if !is_authority {
            return (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "Only the channel founder or a DID-op may distribute group keys"
                })),
            );
        }
    }

    let (Some(epoch), Some(keys)) = (
        body.get("epoch").and_then(|v| v.as_i64()),
        body.get("keys").and_then(|v| v.as_object()),
    ) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "Expected { epoch: <n>, keys: { member_did: sealed } }"
            })),
        );
    };

    let mut stored = 0usize;
    for (member_did, sealed) in keys {
        if let Some(sealed_wire) = sealed.as_str() {
            let (ch, md, sw) = (channel.clone(), member_did.clone(), sealed_wire.to_string());
            state.with_db(|db| db.save_group_key(&ch, &md, epoch, &sw));
            stored += 1;
        }
    }

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "ok": true, "epoch": epoch, "stored": stored })),
    )
}

/// GET /api/v1/channels/{name}/groupkeys — a member fetches the group keys
/// sealed to THEIR DID across all retained epochs (newest first), so they can
/// read live traffic and decrypt history across rotations. Only blobs the
/// caller can actually open are returned.
async fn api_get_group_keys(
    Path(name): Path<String>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let channel = if name.starts_with('#') {
        name
    } else {
        format!("#{name}")
    };

    let Some(caller) = caller_did_from_bearer(&state, &headers) else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "Bearer session required" })),
        );
    };

    let rows = state
        .with_db(|db| db.get_group_keys_for_member(&channel, &caller))
        .unwrap_or_default();

    let keys: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(epoch, sealed)| serde_json::json!({ "epoch": epoch, "sealed": sealed }))
        .collect();

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "channel": channel, "keys": keys })),
    )
}

async fn api_channel_history(
    Path(name): Path<String>,
    Query(params): Query<HistoryQuery>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<MessageResponse>>, StatusCode> {
    // Public channels read anonymously; restricted ones require a member Bearer.
    let channel = authorize_channel_read(&state, &name, &headers)?;

    let limit = params.limit.unwrap_or(50).min(200);

    // Try database first for full history
    let messages = state.with_db(|db| db.get_messages(&channel, limit, params.before));

    match messages {
        Some(rows) => {
            let resp: Vec<MessageResponse> = rows
                .into_iter()
                .map(|r| MessageResponse {
                    id: r.id,
                    sender: r.sender,
                    text: r.text,
                    timestamp: r.timestamp,
                    msgid: r.msgid,
                    tags: r.tags,
                })
                .collect();
            Ok(Json(resp))
        }
        None => {
            // No database — fall back to in-memory history
            let channels = state.channels.lock();
            match channels.get(&channel) {
                Some(ch) => {
                    let resp: Vec<MessageResponse> = ch
                        .history
                        .iter()
                        .filter(|m| params.before.is_none_or(|b| m.timestamp < b))
                        .rev()
                        .take(limit)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .enumerate()
                        .map(|(i, m)| MessageResponse {
                            id: i as i64,
                            sender: m.from.clone(),
                            text: m.text.clone(),
                            timestamp: m.timestamp,
                            msgid: m.msgid.clone(),
                            tags: m.tags.clone(),
                        })
                        .collect();
                    Ok(Json(resp))
                }
                None => Err(StatusCode::NOT_FOUND),
            }
        }
    }
}

/// Authorize a REST read of a channel's messages (history / search / export /
/// permalink). Returns the normalized `#channel` on success.
///
/// - **Public** channels (no `+i`/`+k`/`+E`/policy restriction) are readable
///   anonymously — same as before.
/// - **Restricted** channels require an authenticated Bearer session whose DID
///   is a member, DID-op, or founder. This replaces the old all-or-nothing
///   `+i`/`+k` gate with real member-scoped access, matching IRC `CHATHISTORY`.
/// - **Fails CLOSED**: a channel not resident in memory returns 404 rather than
///   serving history openly (channels are loaded from the DB at boot, so a
///   resident miss means we can't verify access controls). DM keys are refused.
fn authorize_channel_read(
    state: &SharedState,
    name: &str,
    headers: &axum::http::HeaderMap,
) -> Result<String, StatusCode> {
    let channel = if name.starts_with('#') {
        name.to_string()
    } else {
        format!("#{name}")
    };
    let key = channel.to_lowercase();
    if key.contains("dm:") {
        return Err(StatusCode::FORBIDDEN);
    }

    let caller = caller_did_from_bearer(state, headers);
    // Snapshot what we need under the channels lock, then release it before
    // touching session_dids (avoids nested lock-order coupling).
    let (restricted, members, founder, did_ops) = {
        let channels = state.channels.lock();
        let Some(ch) = channels.get(&key) else {
            return Err(StatusCode::NOT_FOUND); // fail closed
        };
        (
            !state.channel_is_discoverable(&key, ch),
            ch.members.clone(),
            ch.founder_did.clone(),
            ch.did_ops.clone(),
        )
    };

    if !restricted {
        return Ok(channel);
    }
    let Some(did) = caller else {
        return Err(StatusCode::FORBIDDEN);
    };
    if founder.as_deref() == Some(did.as_str()) || did_ops.contains(&did) {
        return Ok(channel);
    }
    let session_dids = state.session_dids.lock();
    let is_member = members
        .iter()
        .any(|sid| session_dids.get(sid).map(|d| d == &did).unwrap_or(false));
    if is_member {
        Ok(channel)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// ── Private media spaces ───────────────────────────────────────────────

/// GET /.well-known/did.json — the did:web document for this server's
/// managing-app identity. The spaces PDS resolves `did:web:{server_name}`
/// here to find the checkUserAccess endpoint.
async fn media_space_did_doc(
    State(state): State<Arc<SharedState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if state.media_space.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:web:{}", state.server_name),
        "service": [{
            "id": format!("#{}", crate::media_space::MANAGING_APP_FRAGMENT),
            "type": "FreeqMediaManagingApp",
            "serviceEndpoint": format!("https://{}", state.server_name),
        }],
    })))
}

#[derive(serde::Deserialize)]
struct CheckUserAccessParams {
    space: String,
    user: String,
    #[serde(rename = "clientId")]
    #[allow(dead_code)]
    client_id: Option<String>,
}

/// GET /xrpc/com.atproto.simplespace.checkUserAccess — the managing-app
/// callback the spaces PDS invokes when minting a space credential. The
/// answer comes from the live channel roster: current member DID, founder,
/// or DID-op of the channel owning the space.
async fn xrpc_check_user_access(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<CheckUserAccessParams>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(mgr) = state.media_space.clone() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "MethodNotImplemented"})),
        ));
    };
    let jwt = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "AuthMissing"})),
        ))?;
    if let Err(err) = crate::media_space::verify_service_auth(
        &state.did_resolver,
        jwt,
        &mgr.authority_did,
        &mgr.managing_app(),
        "com.atproto.simplespace.checkUserAccess",
    )
    .await
    {
        tracing::warn!(error = %err, space = %q.space, "rejected checkUserAccess service auth");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "AuthenticationRequired"})),
        ));
    }
    let authorized = media_space_member(&state, &mgr, &q.space, &q.user);
    Ok(Json(serde_json::json!({ "authorized": authorized })))
}

/// Whether `user_did` may access `space`: the space must be one this server
/// is the authority for, and the DID must currently hold the owning channel
/// (member session, founder, or DID-op). Guests have no DID and never match.
fn media_space_member(
    state: &SharedState,
    mgr: &crate::media_space::MediaSpaceManager,
    space: &str,
    user_did: &str,
) -> bool {
    let Some(key) = mgr.parse_space_key(space) else {
        return false;
    };
    // This server reads its own spaces to serve media to members it has
    // already authorized.
    if user_did == mgr.authority_did {
        return true;
    }
    // Snapshot under the channels lock, resolve sessions under session_dids
    // (same lock order as authorize_channel_read).
    let (members, founder, did_ops) = {
        let channels = state.channels.lock();
        let Some(ch) = channels
            .values()
            .find(|c| c.media_space_key.as_deref() == Some(key))
        else {
            return false;
        };
        (
            ch.members.clone(),
            ch.founder_did.clone(),
            ch.did_ops.clone(),
        )
    };
    if founder.as_deref() == Some(user_did) || did_ops.contains(user_did) {
        return true;
    }
    let session_dids = state.session_dids.lock();
    members.iter().any(|sid| {
        session_dids
            .get(sid)
            .map(|d| d == user_did)
            .unwrap_or(false)
    })
}

#[derive(serde::Deserialize)]
struct MediaSpaceParams {
    channel: String,
}

/// GET /api/v1/media-space?channel=… — the channel's space ref, creating the
/// space on first use. Authorization mirrors channel history reads.
async fn api_media_space(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<MediaSpaceParams>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(mgr) = state.media_space.clone() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let channel = authorize_channel_read(&state, &q.channel, &headers)?;
    let key = channel_space_key(&state, &mgr, &channel).await?;
    Ok(Json(serde_json::json!({
        "space": mgr.space_ref(&key),
        "type": crate::media_space::SPACE_TYPE,
    })))
}

/// The channel's media space key.
/// The space is created the first time media is uploaded.
async fn channel_space_key(
    state: &Arc<SharedState>,
    mgr: &crate::media_space::MediaSpaceManager,
    channel: &str,
) -> Result<String, StatusCode> {
    let key = channel.to_lowercase();
    let stored = |key: &str| {
        state
            .channels
            .lock()
            .get(key)
            .and_then(|c| c.media_space_key.clone())
    };
    if let Some(k) = stored(&key) {
        return Ok(k);
    }

    let _creating = mgr.create_lock.lock().await;
    if let Some(k) = stored(&key) {
        return Ok(k);
    }
    let new_key = ulid::Ulid::new().to_string();
    if let Err(err) = mgr.create_space(&state.did_resolver, &new_key).await {
        tracing::error!(error = %err, channel = %channel, "media space creation failed");
        return Err(StatusCode::BAD_GATEWAY);
    }
    let snapshot = {
        let mut channels = state.channels.lock();
        let Some(ch) = channels.get_mut(&key) else {
            return Err(StatusCode::NOT_FOUND);
        };
        ch.media_space_key = Some(new_key.clone());
        ch.clone()
    };
    state.with_db(|db| db.save_channel(&key, &snapshot));
    Ok(new_key)
}

/// GET /api/v1/space-media/{ref}/{filename} — serve a private space media
/// file to a member of the channel that owns the space.
///
/// `ref` is the record's `at://` URI, base64url-encoded so it survives a path
/// segment; the trailing filename gives clients the extension they use to
/// decide how to render, exactly like the private-store capability URLs.
async fn api_space_media(
    State(state): State<Arc<SharedState>>,
    Path((encoded_ref, _filename)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let Some(mgr) = state.media_space.clone() else {
        return Err(StatusCode::NOT_FOUND);
    };
    use base64::Engine;
    let uri = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_ref.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let Some(rec) = mgr.parse_record_uri(&uri) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    // Which channel owns this space, and may the caller read it? Reuse the
    // channel-history rule so restricted channels stay restricted.
    let channel = {
        let channels = state.channels.lock();
        channels
            .iter()
            .find(|(_, c)| c.media_space_key.as_deref() == Some(rec.space_key.as_str()))
            .map(|(name, _)| name.clone())
    };
    let Some(channel) = channel else {
        return Err(StatusCode::NOT_FOUND);
    };
    authorize_channel_read(&state, &channel, &headers)?;

    let (bytes, mime) = mgr
        .fetch_media(&state.did_resolver, &rec)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, uri = %uri, "space media fetch failed");
            StatusCode::BAD_GATEWAY
        })?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (
                axum::http::header::CACHE_CONTROL,
                "private, max-age=300".to_string(),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// GET /api/v1/messages/{msgid} — permalink resolution. Returns the message
/// plus its channel so clients can deep-link `irc.example.org/#/{channel}`
/// scrolled to the msgid. Same access rules as channel history.
async fn api_message_by_id(
    Path(msgid): Path<String>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let row = state
        .with_db(|db| db.find_message_by_msgid(&msgid))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    authorize_channel_read(&state, &row.channel, &headers)?;
    Ok(Json(serde_json::json!({
        "channel": row.channel,
        "msgid": row.msgid,
        "sender": row.sender,
        "sender_did": row.sender_did,
        "text": row.text,
        "timestamp": row.timestamp,
        "tags": row.tags,
        "replaces_msgid": row.replaces_msgid,
    })))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    limit: Option<usize>,
    before: Option<u64>,
}

/// Render messages as a readable markdown transcript.
fn format_export_markdown(channel: &str, rows: &[crate::db::MessageRow]) -> String {
    let mut out = format!("# {channel} — exported transcript\n\n");
    for r in rows {
        let ts = chrono::DateTime::from_timestamp(r.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");
        let sender = r.sender.split('!').next().unwrap_or(&r.sender);
        let msgid = r.msgid.as_deref().unwrap_or("-");
        // Indent continuation lines so multiline messages stay readable.
        let body = r.text.replace('\n', "\n    ");
        out.push_str(&format!("- `{ts}` **{sender}** ({msgid}): {body}\n"));
    }
    out
}

/// GET /api/v1/channels/{name}/export?format=json|markdown — bulk export of
/// a public channel's stored history, oldest-first. "The conversation is the
/// commit": conversations must be extractable, not trapped in the database.
async fn api_channel_export(
    Path(name): Path<String>,
    Query(params): Query<ExportQuery>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse as _;
    let channel = authorize_channel_read(&state, &name, &headers)?;

    let limit = params.limit.unwrap_or(1000).min(10_000);
    let rows = state
        .with_db(|db| db.get_messages(&channel, limit, params.before))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    match params.format.as_deref().unwrap_or("json") {
        "markdown" | "md" => Ok((
            [(
                axum::http::header::CONTENT_TYPE,
                "text/markdown; charset=utf-8",
            )],
            format_export_markdown(&channel, &rows),
        )
            .into_response()),
        _ => {
            let resp: Vec<MessageResponse> = rows
                .into_iter()
                .map(|r| MessageResponse {
                    id: r.id,
                    sender: r.sender,
                    text: r.text,
                    timestamp: r.timestamp,
                    msgid: r.msgid,
                    tags: r.tags,
                })
                .collect();
            Ok(Json(resp).into_response())
        }
    }
}

/// Render Prometheus text exposition format (version 0.0.4).
fn format_metrics(
    connections: usize,
    channels: usize,
    s2s_peers: usize,
    messages_total: u64,
    sasl_success_total: u64,
    sasl_failure_total: u64,
    act_events_total: u64,
    uptime_seconds: u64,
) -> String {
    format!(
        "# HELP freeq_connections Currently connected sessions\n\
         # TYPE freeq_connections gauge\n\
         freeq_connections {connections}\n\
         # HELP freeq_channels Channels known to this server\n\
         # TYPE freeq_channels gauge\n\
         freeq_channels {channels}\n\
         # HELP freeq_s2s_peers Authenticated federation peers\n\
         # TYPE freeq_s2s_peers gauge\n\
         freeq_s2s_peers {s2s_peers}\n\
         # HELP freeq_messages_total PRIVMSG/NOTICE handled since start\n\
         # TYPE freeq_messages_total counter\n\
         freeq_messages_total {messages_total}\n\
         # HELP freeq_sasl_success_total Successful SASL authentications since start\n\
         # TYPE freeq_sasl_success_total counter\n\
         freeq_sasl_success_total {sasl_success_total}\n\
         # HELP freeq_sasl_failure_total Failed SASL authentications since start\n\
         # TYPE freeq_sasl_failure_total counter\n\
         freeq_sasl_failure_total {sasl_failure_total}\n\
         # HELP freeq_act_events_total Task events received since start\n\
         # TYPE freeq_act_events_total counter\n\
         freeq_act_events_total {act_events_total}\n\
         # HELP freeq_uptime_seconds Seconds since process start\n\
         # TYPE freeq_uptime_seconds gauge\n\
         freeq_uptime_seconds {uptime_seconds}\n"
    )
}

/// GET /metrics — Prometheus scrape endpoint.
async fn api_metrics(State(state): State<Arc<SharedState>>) -> impl axum::response::IntoResponse {
    use std::sync::atomic::Ordering::Relaxed;
    let connections = state.connections.lock().len();
    let channels = state.channels.lock().len();
    let s2s = state.s2s_manager.lock().clone();
    let s2s_peers = match s2s {
        Some(mgr) => mgr.authenticated_peers.lock().await.len(),
        None => 0,
    };
    let body = format_metrics(
        connections,
        channels,
        s2s_peers,
        state.metrics.messages_total.load(Relaxed),
        state.metrics.sasl_success_total.load(Relaxed),
        state.metrics.sasl_failure_total.load(Relaxed),
        state.metrics.act_events_total.load(Relaxed),
        state.metrics.started_at.elapsed().as_secs(),
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// GET /api/v1/search?channel=#name&q=terms — full-text history search.
/// Channels only: DM search requires DID auth and goes through the IRC
/// SEARCH command. Access rules mirror /channels/{name}/history: channels
/// with +i or +k return 403.
async fn api_search(
    Query(params): Query<SearchQuery>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<MessageResponse>>, StatusCode> {
    // Public channels search anonymously; restricted ones require a member
    // Bearer (DM keys refused, non-resident channels fail closed).
    let channel = authorize_channel_read(&state, &params.channel, &headers)?;

    let limit = params.limit.unwrap_or(25).min(100);
    let rows = state
        .with_db(|db| db.search_messages(&channel, &params.q, limit, params.before))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| MessageResponse {
                id: r.id,
                sender: r.sender,
                text: r.text,
                timestamp: r.timestamp,
                // A hit is addressed by its root — the id clients hold the
                // message under — not the matching revision's own id.
                msgid: r.root_msgid.or(r.msgid),
                tags: r.tags,
            })
            .collect(),
    ))
}

async fn api_channel_topic(
    Path(name): Path<String>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ChannelTopicResponse>, StatusCode> {
    // Mode-restricted channels (+i/+k/encrypted) are not public: the topic of a
    // private room routinely names the thing the room exists to discuss.
    let channel = authorize_channel_read(&state, &name, &headers)?;

    let channels = state.channels.lock();
    match channels.get(&channel) {
        Some(ch) => Ok(Json(ChannelTopicResponse {
            channel,
            topic: ch.topic.as_ref().map(|t| t.text.clone()),
            set_by: ch.topic.as_ref().map(|t| t.set_by.clone()),
            set_at: ch.topic.as_ref().map(|t| t.set_at),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn api_channel_pins(
    Path(name): Path<String>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Pins quote message text, so this is a history read by another name.
    let channel = authorize_channel_read(&state, &name, &headers)?;
    let pin_list = {
        let channels = state.channels.lock();
        match channels.get(&channel) {
            Some(ch) => ch.pins.clone(),
            None => return Err(StatusCode::NOT_FOUND),
        }
    };

    let mut pins: Vec<serde_json::Value> = Vec::new();
    for p in &pin_list {
        // Try in-memory history first, fall back to DB
        let (from, text, timestamp) = {
            let channels = state.channels.lock();
            let ch = channels.get(&channel);
            ch.and_then(|c| {
                c.history
                    .iter()
                    .find(|m| m.msgid.as_deref() == Some(&p.msgid))
                    .map(|msg| (msg.from.clone(), msg.text.clone(), msg.timestamp))
            })
        }
        .or_else(|| {
            // The pin names the message, not a revision of it: quote the text
            // the author last wrote, not whichever row carries the pinned id.
            state
                .with_db(|db| db.current_revision(&p.msgid))
                .flatten()
                .map(|row| (row.sender, row.text, row.timestamp))
        })
        .unwrap_or_else(|| {
            (
                "unknown".to_string(),
                "[message not found]".to_string(),
                p.pinned_at,
            )
        });

        pins.push(serde_json::json!({
            "msgid": p.msgid,
            "from": from,
            "text": text,
            "timestamp": chrono::DateTime::from_timestamp(timestamp as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            "pinned_by": p.pinned_by,
            "pinned_at": p.pinned_at,
        }));
    }

    Ok(Json(
        serde_json::json!({ "channel": channel, "pins": pins }),
    ))
}

async fn api_user(
    Path(nick): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<UserResponse>, StatusCode> {
    let session = state
        .nick_to_session
        .lock()
        .get_session(&nick)
        .map(|s| s.to_string());
    let online = session.is_some();

    let (did, handle) = if let Some(ref session_id) = session {
        let did = state.session_dids.lock().get(session_id).cloned();
        let handle = state.session_handles.lock().get(session_id).cloned();
        (did, handle)
    } else {
        let did = state.nick_owners.lock().get(&nick.to_lowercase()).cloned();
        (did, None)
    };

    if !online && did.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(UserResponse {
        nick,
        online,
        did,
        handle,
    }))
}

async fn api_user_whois(
    Path(nick): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<WhoisResponse>, StatusCode> {
    let session = state
        .nick_to_session
        .lock()
        .get_session(&nick)
        .map(|s| s.to_string());
    let online = session.is_some();

    let (did, handle) = if let Some(ref session_id) = session {
        let did = state.session_dids.lock().get(session_id).cloned();
        let handle = state.session_handles.lock().get(session_id).cloned();
        (did, handle)
    } else {
        let did = state.nick_owners.lock().get(&nick.to_lowercase()).cloned();
        (did, None)
    };

    if !online && did.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let channels = if let Some(ref session_id) = session {
        let chans = state.channels.lock();
        chans
            .iter()
            .filter(|(_, ch)| ch.members.contains(session_id))
            .map(|(name, _)| name.clone())
            .collect()
    } else {
        vec![]
    };

    Ok(Json(WhoisResponse {
        nick,
        online,
        did,
        handle,
        channels,
    }))
}

// ── Auth broker endpoints ───────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
struct BrokerTokenRequest {
    did: String,
    handle: String,
}

#[derive(Deserialize, Serialize)]
struct BrokerSessionRequest {
    did: String,
    handle: String,
    pds_url: String,
    access_token: String,
    dpop_key_b64: String,
    dpop_nonce: Option<String>,
    /// What the PDS actually granted (read from the token endpoint's `scope`
    /// field). Defaults to `transition:generic` for backward compat with
    /// older broker builds that don't send this field — those brokers
    /// always asked for the legacy broad scope so this is conservative.
    #[serde(default = "default_legacy_scope")]
    granted_scope: String,
}

fn default_legacy_scope() -> String {
    "atproto transition:generic".to_string()
}

#[derive(Serialize)]
struct BrokerTokenResponse {
    token: String,
    nick: String,
    did: String,
    handle: String,
}

async fn auth_broker_web_token(
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<BrokerTokenResponse>, (StatusCode, String)> {
    let secret = state.config.broker_shared_secret.clone().ok_or((
        StatusCode::FORBIDDEN,
        "Broker auth not configured".to_string(),
    ))?;
    verify_broker_signature_raw(&secret, &headers, &body)?;
    let req: BrokerTokenRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")))?;

    let token = generate_random_string(32);
    state.web_auth_tokens.lock().insert(
        token.clone(),
        (
            req.did.clone(),
            req.handle.clone(),
            std::time::Instant::now(),
        ),
    );
    let nick = mobile_nick_from_handle(&req.handle);
    Ok(Json(BrokerTokenResponse {
        token,
        nick,
        did: req.did,
        handle: req.handle,
    }))
}

/// [`freeq_auth_broker::SessionWriter`] that writes into this server's own
/// in-process state — the embedded equivalent of the standalone broker's
/// HMAC push. Mirrors the `/auth/broker/*` receiver bodies.
pub struct LocalWriter {
    pub state: Arc<SharedState>,
}

#[async_trait::async_trait]
impl freeq_auth_broker::SessionWriter for LocalWriter {
    async fn mint_web_token(
        &self,
        did: &str,
        handle: &str,
    ) -> Result<(String, String), anyhow::Error> {
        let token = generate_random_string(32);
        self.state.web_auth_tokens.lock().insert(
            token.clone(),
            (
                did.to_string(),
                handle.to_string(),
                std::time::Instant::now(),
            ),
        );
        Ok((token, mobile_nick_from_handle(handle)))
    }

    async fn push_session(
        &self,
        p: &freeq_auth_broker::SessionPush<'_>,
    ) -> Result<(), anyhow::Error> {
        self.state.web_sessions.lock().insert(
            (p.did.to_string(), crate::server::OauthPurpose::Login),
            crate::server::WebSession {
                did: p.did.to_string(),
                handle: p.handle.to_string(),
                pds_url: p.pds_url.to_string(),
                access_token: p.access_token.to_string(),
                dpop_key_b64: p.dpop_key_b64.to_string(),
                dpop_nonce: p.dpop_nonce.map(str::to_string),
                created_at: std::time::Instant::now(),
                granted_scope: p.granted_scope.to_string(),
            },
        );
        // Upload token for mobile clients that can't prove session ownership
        // via WebSocket session_dids (stored server-side, 5-min TTL).
        let upload_token = generate_random_string(32);
        self.state
            .upload_tokens
            .lock()
            .insert(upload_token, (p.did.to_string(), std::time::Instant::now()));
        Ok(())
    }
}

async fn auth_broker_session(
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let secret = state.config.broker_shared_secret.clone().ok_or((
        StatusCode::FORBIDDEN,
        "Broker auth not configured".to_string(),
    ))?;
    verify_broker_signature_raw(&secret, &headers, &body)?;
    let req: BrokerSessionRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")))?;

    tracing::info!(did = %req.did, scope = %req.granted_scope, "Broker pushed web session");
    state.web_sessions.lock().insert(
        (req.did.clone(), crate::server::OauthPurpose::Login),
        crate::server::WebSession {
            did: req.did.clone(),
            handle: req.handle.clone(),
            pds_url: req.pds_url.clone(),
            access_token: req.access_token.clone(),
            dpop_key_b64: req.dpop_key_b64.clone(),
            dpop_nonce: req.dpop_nonce.clone(),
            created_at: std::time::Instant::now(),
            granted_scope: req.granted_scope.clone(),
        },
    );

    // Mint an upload token for this DID (5 min TTL, used by mobile clients
    // that can't prove session ownership via WebSocket session_dids).
    let upload_token = generate_random_string(32);
    state.upload_tokens.lock().insert(
        upload_token.clone(),
        (req.did.clone(), std::time::Instant::now()),
    );

    Ok(Json(
        serde_json::json!({"ok": true, "upload_token": upload_token}),
    ))
}

/// Verify HMAC-SHA256 signature over raw request bytes with replay protection.
/// The broker must include X-Broker-Timestamp (unix seconds). Requests older
/// than 60 seconds are rejected.
fn verify_broker_signature_raw(
    secret: &str,
    headers: &axum::http::HeaderMap,
    body_bytes: &[u8],
) -> Result<(), (StatusCode, String)> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let sig = headers
        .get("x-broker-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing broker signature".to_string(),
        ))?;

    // Replay protection: require timestamp and enforce ≤60s skew.
    let ts_str = headers
        .get("x-broker-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-Broker-Timestamp header".to_string(),
        ))?;
    let ts: u64 = ts_str.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid X-Broker-Timestamp".to_string(),
        )
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(ts) > 60 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Broker request expired (timestamp > 60s)".to_string(),
        ));
    }

    // MAC covers ts={timestamp}\n || body to bind the timestamp to the signature.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "HMAC init failed".to_string(),
        )
    })?;
    mac.update(format!("ts={ts_str}\n").as_bytes());
    mac.update(body_bytes);
    let expected =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    if expected != sig {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid broker signature".to_string(),
        ));
    }
    Ok(())
}

// ── OAuth client metadata ──────────────────────────────────────────────

/// Serves the AT Protocol OAuth client-metadata.json document.
/// The client_id for non-localhost origins is `{origin}/client-metadata.json`.
async fn client_metadata(
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (web_origin, _) = derive_web_origin(&headers);
    let redirect_uri = format!("{web_origin}/auth/callback");
    let client_id = build_client_id(&web_origin, &redirect_uri);
    // Advertise every scope any flow may request in the metadata.
    let mut scope = "atproto blob:image/* repo:blue.irc.media?action=create repo:app.bsky.feed.post transition:generic".to_string();
    if let Some(ref mgr) = state.media_space {
        scope.push(' ');
        scope.push_str(&crate::media_space::space_scope(&mgr.authority_did));
    }

    Json(serde_json::json!({
        "client_id": client_id,
        "client_name": "freeq",
        "client_uri": web_origin,
        "logo_uri": format!("{web_origin}/freeq.png"),
        "tos_uri": web_origin,
        "policy_uri": web_origin,
        "redirect_uris": [redirect_uri],
        // Advertise the union of scopes any flow may request. The AT
        // Proto OAuth spec requires that scopes used at /authorize time
        // appear here. Actual per-flow requests are narrower:
        //   - Login (default sign-in)        → "atproto" only
        //   - BlobUpload step-up             → "atproto blob:image/*"
        //   - BlueskyPost step-up            → "atproto repo:app.bsky.feed.post"
        //
        // `transition:generic` is included for the grace-period: existing
        // refresh tokens issued under the old wide grant must still be
        // refreshable, and some PDSes verify that the original grant scope
        // remains permitted by the current client metadata. We never ask
        // for it on a fresh /authorize. Remove this entry once the PDS
        // ecosystem has fully sunset transitional scopes.
        "scope": scope,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
        "dpop_bound_access_tokens": true
    }))
}

/// Derive web origin and scheme from Host header.
/// Validate a URL we're about to fetch from on behalf of an OAuth flow.
///
/// Returns a DNS-pinned `reqwest::Client` and the parsed URL. Refuses
/// URLs that:
///   - aren't http/https,
///   - have no host,
///   - resolve to a loopback / private / link-local / metadata-service
///     IP (per `freeq_sdk::ssrf::resolve_and_check`).
///
/// This is the SSRF guard for the OAuth chain: every URL after the
/// first call (DID document → PDS URL → auth-server → token-endpoint)
/// is fully attacker-controlled in the worst case, so we validate at
/// every hop. Returns a generic error message that does NOT echo the
/// host or IP back to the requester (info-leak hardening).
async fn safe_outbound_client(
    url_str: &str,
    timeout: std::time::Duration,
) -> Result<(url::Url, reqwest::Client), (StatusCode, &'static str)> {
    let parsed = url::Url::parse(url_str)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Refused: malformed URL"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Refused: URL scheme must be http or https",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "Refused: URL has no host"))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let addrs = freeq_sdk::ssrf::resolve_and_check(&host, port)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Refused: target is not publicly routable",
            )
        })?;

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    for addr in &addrs {
        builder = builder.resolve(&host, *addr);
    }
    let client = builder
        .build()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "client build failed"))?;
    Ok((parsed, client))
}

/// An outbound refusal carrying the exact `(status, message)`
/// [`safe_outbound_client`] would have returned, so the engine's generic
/// `anyhow` error can be mapped back to the original response at the handler
/// boundary (preserving the CTF-07/08/09 4xx-fast-generic behavior).
#[derive(Debug, thiserror::Error)]
#[error("{msg}")]
struct OutboundRefused {
    status: StatusCode,
    msg: &'static str,
}

/// [`freeq_oauth::ClientProvider`] backed by [`safe_outbound_client`]: SSRF
/// validation + DNS pinning per URL. Used for OAuth discovery, where every hop
/// (PDS → auth server) is attacker-influenced.
struct SsrfClients {
    timeout: std::time::Duration,
}

impl freeq_oauth::ClientProvider for SsrfClients {
    async fn client_for(&self, url: &str) -> anyhow::Result<reqwest::Client> {
        match safe_outbound_client(url, self.timeout).await {
            Ok((_parsed, client)) => Ok(client),
            Err((status, msg)) => Err(OutboundRefused { status, msg }.into()),
        }
    }
}

/// Map an engine discovery/validation error back to an HTTP response. An SSRF
/// refusal keeps its original `(status, message)`; a metadata fetch/parse
/// failure (which happens over an already-validated client) is a generic 502.
fn map_outbound_err(e: anyhow::Error) -> (StatusCode, String) {
    if let Some(r) = e.downcast_ref::<OutboundRefused>() {
        (r.status, r.msg.to_string())
    } else {
        (
            StatusCode::BAD_GATEWAY,
            "Upstream metadata fetch failed".to_string(),
        )
    }
}

fn derive_web_origin(headers: &axum::http::HeaderMap) -> (String, String) {
    let raw_host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8080");
    let host = raw_host.replace("localhost", "127.0.0.1");
    let scheme =
        if host.starts_with("127.") || host.starts_with("192.168.") || host.starts_with("10.") {
            "http"
        } else {
            "https"
        };
    let origin = format!("{scheme}://{host}");
    (origin, scheme.to_string())
}

/// Derive web origin from server config (for startup-time use, no headers available).
#[allow(dead_code)]
fn derive_web_origin_from_config(config: &crate::config::ServerConfig) -> (String, String) {
    let addr = config.web_addr.as_deref().unwrap_or("127.0.0.1:8080");
    let host = addr.replace("localhost", "127.0.0.1");
    let scheme = if host.starts_with("127.") || host.starts_with("0.0.0.0") {
        "http"
    } else {
        "https"
    };
    (format!("{scheme}://{host}"), scheme.to_string())
}

// ── OAuth endpoints for web client ─────────────────────────────────────

#[derive(Deserialize)]
struct AuthLoginQuery {
    handle: String,
    /// If "1", callback redirects to freeq:// URL scheme for mobile apps.
    mobile: Option<String>,
    /// If set, this is an IRC `/login` command — complete auth on the IRC session.
    irc_state: Option<String>,
}

/// GET /auth/login?handle=user.bsky.social
///
/// Initiates the AT Protocol OAuth flow. Resolves the handle, does PAR,
/// and redirects the browser to the authorization server.
/// Serves a page that reads #oauth=base64json from the hash fragment,
/// parses it, and redirects to freeq://auth?token=...&broker_token=...
/// This is used by the iOS app because the broker's HTML redirect has
/// broken JS (escaped quotes in raw strings) and ASWebAuthenticationSession
/// doesn't intercept JS-initiated custom scheme navigations.
async fn auth_mobile_redirect() -> impl IntoResponse {
    let html = r##"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>freeq</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui;background:#1e1e2e;color:#cdd6f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center}
h1{color:#89b4fa;font-size:24px}
p{color:#a6adc8;font-size:15px}
a{color:#89b4fa;font-size:17px;font-weight:600;text-decoration:none;display:inline-block;margin-top:16px;padding:12px 32px;background:#89b4fa22;border-radius:12px}
</style></head>
<body><div class="box" id="box">
<h1>freeq</h1>
<p id="status">Connecting...</p>
<a id="link" style="display:none" href="#">Open freeq</a>
</div>
<script>
try {
  var h = location.hash;
  if (h && h.indexOf('#oauth=') === 0) {
    var b64 = h.substring(7).replace(/-/g,'+').replace(/_/g,'/');
    while(b64.length%4) b64+='=';
    var json = JSON.parse(atob(b64));
    var t = json.token || json.web_token || json.access_jwt || '';
    var bt = json.broker_token || '';
    var n = json.nick || json.handle || '';
    var d = json.did || '';
    var ha = json.handle || '';
    var url = 'freeq://auth?token=' + encodeURIComponent(t)
      + '&broker_token=' + encodeURIComponent(bt)
      + '&nick=' + encodeURIComponent(n)
      + '&did=' + encodeURIComponent(d)
      + '&handle=' + encodeURIComponent(ha);
    document.getElementById('link').href = url;
    document.getElementById('link').style.display = 'inline-block';
    document.getElementById('status').textContent = 'Tap to return to freeq';
    window.location.href = url;
  } else {
    document.getElementById('status').textContent = 'Authentication failed.';
  }
} catch(e) {
  document.getElementById('status').textContent = 'Error: ' + e.message;
}
</script></body></html>"##;
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            ),
        ],
        html,
    )
}

async fn auth_login(
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthLoginQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<Redirect, (StatusCode, String)> {
    let handle = q.handle.trim().to_string();

    // Derive the origin from the Host header so redirect_uri matches what the browser sees
    let (web_origin, _scheme) = derive_web_origin(&headers);

    // Resolve handle → DID → PDS via the *configured* resolver so tests
    // can swap implementations and so any future federation-aware
    // resolver setting is honoured. (Was previously hardcoded to
    // DidResolver::http().)
    let resolver = state.did_resolver.clone();
    let did = resolver.resolve_handle(&handle).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Cannot resolve handle: {e}"),
        )
    })?;
    let did_doc = resolver
        .resolve(&did)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cannot resolve DID: {e}")))?;
    let pds_url = freeq_sdk::pds::pds_endpoint(&did_doc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No PDS in DID document".to_string(),
        )
    })?;

    // Discover the authorization server through the shared engine. Every hop
    // (PDS → auth server) is attacker-influenced via the DID document, so the
    // provider SSRF-validates + DNS-pins a fresh client per URL. CTF-07/08/09
    // regression tests pin this.
    let provider = SsrfClients {
        timeout: std::time::Duration::from_secs(8),
    };
    let auth_meta = freeq_oauth::discovery::discover_auth_server(&provider, &pds_url)
        .await
        .map_err(map_outbound_err)?;
    let authorization_endpoint = auth_meta.authorization_endpoint.as_str();
    let token_endpoint = auth_meta.token_endpoint.as_str();
    let par_endpoint = auth_meta
        .pushed_authorization_request_endpoint
        .as_deref()
        .ok_or((StatusCode::BAD_GATEWAY, "No PAR endpoint".to_string()))?;
    // Validate the endpoints the auth-server metadata named — these go straight
    // from PDS-controlled JSON into URLs we redirect to / POST credentials to,
    // so the SSRF surface extends past the metadata fetches.
    provider
        .client_for(authorization_endpoint)
        .await
        .map_err(map_outbound_err)?;
    provider
        .client_for(token_endpoint)
        .await
        .map_err(map_outbound_err)?;
    let par_client = SsrfClients {
        timeout: std::time::Duration::from_secs(10),
    }
    .client_for(par_endpoint)
    .await
    .map_err(map_outbound_err)?;

    // Build redirect URI and client_id. Default purpose for `/auth/login`
    // is `Login` — narrow `atproto` scope only. Phase-2 step-up flows
    // (image upload, Bluesky cross-post) hit `/auth/step-up` instead and
    // request additional scopes there.
    let redirect_uri = format!("{web_origin}/auth/callback");
    let purpose = crate::server::OauthPurpose::Login;
    let scope = purpose.requested_scope(None);
    let client_id = build_client_id(&web_origin, &redirect_uri);

    // Generate PKCE + DPoP key + state
    let dpop_key = freeq_sdk::oauth::DpopKey::generate();
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_random_string(16);

    // Shared engine performs the PAR + DPoP nonce dance over the
    // SSRF-validated par_client (DNS-pinned + timeout). The error is mapped to
    // a generic string — the PDS body must not be reflected into our response.
    let par = freeq_oauth::discovery::pushed_authorization_request(
        &par_client,
        par_endpoint,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &oauth_state,
        &handle,
        &scope,
        &dpop_key,
    )
    .await
    .map_err(|_| (StatusCode::BAD_GATEWAY, "PAR failed".to_string()))?;
    let request_uri = par.request_uri.as_str();

    // Store pending session
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.oauth_pending.lock().insert(
        oauth_state.clone(),
        crate::server::OAuthPending {
            handle: handle.clone(),
            did: did.clone(),
            pds_url: pds_url.clone(),
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            client_id: client_id.clone(),
            token_endpoint: token_endpoint.to_string(),
            dpop_key_b64: dpop_key.to_base64url(),
            created_at: now,
            mobile: q.mobile.as_deref() == Some("1"),
            irc_state: q.irc_state.clone(),
            purpose,
            requested_scope: scope.to_string(),
        },
    );

    // Redirect to authorization server
    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_endpoint,
        urlencod(&client_id),
        urlencod(request_uri),
    );

    tracing::info!(handle = %handle, did = %did, "OAuth login started, redirecting to auth server");
    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
struct AuthStepUpQuery {
    /// `blob_upload`, `bluesky_post`, or `media_space` — see
    /// [`crate::server::OauthPurpose`].
    purpose: String,
    /// DID to step up. Must match an active Login session on this server,
    /// otherwise the step-up is refused (we'd have nothing to "upgrade").
    did: String,
    /// If `1`, send a freeq:// custom-scheme redirect on completion (mobile).
    mobile: Option<String>,
}

/// `GET /auth/step-up?purpose=blob_upload&did=did:plc:…`
///
/// Drives a second OAuth flow with a wider scope than the original login,
/// without replacing the primary `Login` session. The callback at
/// `/auth/callback` lands in the [`OauthPurpose::BlobUpload`] (or
/// `BlueskyPost`) slot rather than overwriting `Login`, so the user can
/// log out of media-upload permission later without losing their chat
/// session.
///
/// Returns a temporary redirect to the PDS authorization endpoint.
async fn auth_step_up(
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthStepUpQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<Redirect, (StatusCode, String)> {
    // Validate the requested purpose. Login is *not* a valid step-up
    // purpose — that's what `/auth/login` is for.
    let purpose = crate::server::OauthPurpose::parse(&q.purpose).ok_or((
        StatusCode::BAD_REQUEST,
        format!("Unknown purpose: {}", q.purpose),
    ))?;
    if matches!(purpose, crate::server::OauthPurpose::MediaSpace) && state.media_space.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Private media is not enabled on this server".to_string(),
        ));
    }
    if matches!(purpose, crate::server::OauthPurpose::Login) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Use /auth/login for the primary login flow.".to_string(),
        ));
    }

    // Require an existing Login session for this DID so step-up can't be
    // used as a primary login backdoor by an unauthenticated caller.
    let login_session = state
        .web_sessions
        .lock()
        .get(&(q.did.clone(), crate::server::OauthPurpose::Login))
        .cloned();
    let login_session = login_session.ok_or((
        StatusCode::UNAUTHORIZED,
        "Step-up requires an active login session for this DID.".to_string(),
    ))?;

    let (web_origin, _) = derive_web_origin(&headers);

    // Discover the PDS authorization server. Reuse the resolver path
    // from auth_login — it's a couple of well-known fetches. Use the
    // *configured* resolver so tests can swap implementations.
    let resolver = state.did_resolver.clone();
    let did_doc = resolver
        .resolve(&q.did)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cannot resolve DID: {e}")))?;
    let pds_url = freeq_sdk::pds::pds_endpoint(&did_doc).ok_or((
        StatusCode::BAD_REQUEST,
        "No PDS in DID document".to_string(),
    ))?;
    // SSRF guard: validate every external URL before fetching, and use a
    // DNS-pinned client with a hard timeout. The DID document is
    // attacker-controlled (anyone can register a DID with whatever PDS
    // URL they like), so without these the server happily fetches from
    // 127.0.0.1, 169.254.169.254 (cloud metadata service), 10.x.x.x,
    // etc. CTF-07 regression test pins this.
    // Discover through the shared engine; the provider SSRF-validates + pins
    // each attacker-influenced hop. Same path as auth_login. CTF-07 pins this.
    let provider = SsrfClients {
        timeout: std::time::Duration::from_secs(8),
    };
    let auth_meta = freeq_oauth::discovery::discover_auth_server(&provider, &pds_url)
        .await
        .map_err(map_outbound_err)?;
    let authorization_endpoint = auth_meta.authorization_endpoint.as_str();
    let token_endpoint = auth_meta.token_endpoint.as_str();
    let par_endpoint = auth_meta
        .pushed_authorization_request_endpoint
        .as_deref()
        .ok_or((StatusCode::BAD_GATEWAY, "No PAR endpoint".to_string()))?;
    // The auth-server metadata is attacker-controlled too — validate the
    // endpoints it named before we redirect a user to / POST credentials to them.
    provider
        .client_for(authorization_endpoint)
        .await
        .map_err(map_outbound_err)?;
    provider
        .client_for(token_endpoint)
        .await
        .map_err(map_outbound_err)?;
    let par_client = SsrfClients {
        timeout: std::time::Duration::from_secs(10),
    }
    .client_for(par_endpoint)
    .await
    .map_err(map_outbound_err)?;

    let redirect_uri = format!("{web_origin}/auth/callback");
    let scope =
        purpose.requested_scope(state.media_space.as_ref().map(|m| m.authority_did.as_str()));
    let client_id = build_client_id(&web_origin, &redirect_uri);

    let dpop_key = freeq_sdk::oauth::DpopKey::generate();
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_random_string(16);

    // Shared engine performs the PAR + DPoP nonce dance over the
    // SSRF-validated par_client (DNS-pinned + timeout). The error is mapped to
    // a generic string so we don't reflect attacker-controlled body/URLs back.
    let par = freeq_oauth::discovery::pushed_authorization_request(
        &par_client,
        par_endpoint,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &oauth_state,
        &login_session.handle,
        &scope,
        &dpop_key,
    )
    .await
    .map_err(|_| (StatusCode::BAD_GATEWAY, "PAR failed".to_string()))?;
    let request_uri = par.request_uri.as_str();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.oauth_pending.lock().insert(
        oauth_state.clone(),
        crate::server::OAuthPending {
            handle: login_session.handle.clone(),
            did: q.did.clone(),
            pds_url,
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            client_id: client_id.clone(),
            token_endpoint: token_endpoint.to_string(),
            dpop_key_b64: dpop_key.to_base64url(),
            created_at: now,
            mobile: q.mobile.as_deref() == Some("1"),
            irc_state: None,
            purpose,
            requested_scope: scope.to_string(),
        },
    );

    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_endpoint,
        urlencod(&client_id),
        urlencod(request_uri),
    );
    tracing::info!(
        did = %q.did, purpose = purpose.as_str(), scope = %scope,
        "OAuth step-up started, redirecting to auth server",
    );
    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
struct AuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// GET /auth/callback?code=...&state=...
///
/// OAuth callback from the authorization server. Exchanges the code for
/// tokens and returns an HTML page that posts the result to the parent window.
async fn auth_callback(
    Query(q): Query<AuthCallbackQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<impl axum::response::IntoResponse, (StatusCode, String)> {
    // Check for error
    if let Some(error) = &q.error {
        let desc = q.error_description.as_deref().unwrap_or("Unknown error");
        return Ok(oauth_result_page(&format!("Error: {error}: {desc}"), None));
    }

    let code = q
        .code
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing code".to_string()))?;
    let oauth_state = q
        .state
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing state".to_string()))?;

    // Look up pending session
    let pending = state
        .oauth_pending
        .lock()
        .remove(oauth_state)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Unknown or expired OAuth state".to_string(),
            )
        })?;

    // Check expiry. Step-up flows live in a popup that the user might
    // ignore briefly to read what Bluesky's consent screen says, so
    // give them a longer window than primary login. Pre-existing
    // primary-login behaviour (5 min) is preserved.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ttl = if matches!(pending.purpose, crate::server::OauthPurpose::Login) {
        300
    } else {
        600
    };
    if now - pending.created_at > ttl {
        return Err((StatusCode::BAD_REQUEST, "OAuth session expired".to_string()));
    }

    // Exchange code for token
    let dpop_key =
        freeq_sdk::oauth::DpopKey::from_base64url(&pending.dpop_key_b64).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DPoP key error: {e}"),
            )
        })?;

    // Shared engine performs the code exchange + DPoP nonce-retry dance.
    // No SSRF client here: the token_endpoint was already SSRF-validated in
    // auth_login/auth_step_up before it was stored in `pending`. On failure
    // render the OAuth result page (this handler has no mobile-redirect
    // branch — that happens later, after the identity is known).
    let client = reqwest::Client::new();
    let exchanged = match freeq_oauth::flow::exchange_code(
        &client,
        &pending.token_endpoint,
        code,
        &pending.code_verifier,
        &pending.redirect_uri,
        &pending.client_id,
        &dpop_key,
        None,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return Ok(oauth_result_page(&e.to_string(), None)),
    };
    let token_resp = exchanged.token_response;
    let dpop_nonce = exchanged.dpop_nonce;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No access_token".to_string()))?;
    // The PDS reports back which scope it actually granted. May not match
    // what we requested — older PDSes downgrade granular requests to
    // `transition:generic`. Store it so per-purpose checks can be honest.
    let granted_scope = token_resp["scope"]
        .as_str()
        .unwrap_or(pending.requested_scope.as_str())
        .to_string();

    let is_step_up = !matches!(pending.purpose, crate::server::OauthPurpose::Login);

    // Mint a one-time SASL web-token only for the primary login flow.
    // Step-ups produce *additional* PDS grants for the same already-
    // logged-in user — we don't want to issue a second SASL token and
    // confuse the IRC layer into thinking the identity changed.
    let web_token = if is_step_up {
        None
    } else {
        let token = generate_random_string(32);
        state.web_auth_tokens.lock().insert(
            token.clone(),
            (
                pending.did.clone(),
                pending.handle.clone(),
                std::time::Instant::now(),
            ),
        );
        Some(token)
    };

    // Embedded durable session (Login only): persist the broker session
    // (refresh token + client_id) into the in-process store and issue a
    // broker_token, so /session can silently refresh without a re-login.
    let broker_token = match (is_step_up, state.embedded_session_store.as_ref()) {
        (false, Some(store)) => {
            if let Some(refresh_token) = token_resp["refresh_token"].as_str() {
                let bt = generate_random_string(32);
                let now = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let rec = freeq_auth_broker::BrokerSessionRecord {
                    broker_token: bt.clone(),
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
                };
                match store.insert(&rec).await {
                    Ok(()) => Some(bt),
                    Err(e) => {
                        tracing::warn!(error = %e, "embedded session persist failed");
                        None
                    }
                }
            } else {
                None
            }
        }
        _ => None,
    };

    let result = crate::server::OAuthResult {
        did: pending.did.clone(),
        handle: pending.handle.clone(),
        access_jwt: access_token.to_string(),
        pds_url: pending.pds_url.clone(),
        web_token,
        broker_token,
        created_at: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    // Store web session for server-proxied operations under the purpose
    // this OAuth flow was started for (Login, BlobUpload, etc.). A user
    // with both Login and BlobUpload sessions has two independent grants.
    state.web_sessions.lock().insert(
        (pending.did.clone(), pending.purpose),
        crate::server::WebSession {
            did: pending.did.clone(),
            handle: pending.handle.clone(),
            pds_url: pending.pds_url.clone(),
            access_token: access_token.to_string(),
            dpop_key_b64: pending.dpop_key_b64.clone(),
            dpop_nonce: dpop_nonce.clone(),
            created_at: std::time::Instant::now(),
            granted_scope: granted_scope.clone(),
        },
    );

    tracing::info!(
        did = %pending.did, handle = %pending.handle, mobile = pending.mobile,
        purpose = pending.purpose.as_str(), scope = %granted_scope,
        "OAuth callback: token obtained, session stored",
    );

    // IRC /login command — complete auth on the IRC connection
    if let Some(ref irc_state) = pending.irc_state {
        // Look up the IRC session that initiated this login
        let session_id = state.login_pending.lock().remove(irc_state);
        if let Some(session_id) = session_id {
            crate::connection::login::complete_irc_login(
                &state,
                &session_id,
                &pending.did,
                &pending.handle,
            );
            // Return a simple HTML page telling the user to go back to IRC
            let html = format!(
                r#"<!DOCTYPE html>
<html><head><style>
body {{ font-family: system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
.card {{ background: #16162a; border: 1px solid #2a2a4a; border-radius: 16px; padding: 40px; text-align: center; max-width: 400px; }}
h1 {{ color: #6c63ff; font-size: 24px; margin: 0 0 12px 0; }}
p {{ color: #a0a0b0; margin: 8px 0; }}
.did {{ font-family: monospace; font-size: 12px; color: #888; word-break: break-all; }}
</style></head><body>
<div class="card">
<h1>✓ Authenticated</h1>
<p>You are now logged in as <strong>@{handle}</strong></p>
<p class="did">{did}</p>
<p style="margin-top: 20px; color: #6c63ff;">You can close this tab and return to your IRC client.</p>
</div></body></html>"#,
                handle = pending.handle,
                did = pending.did,
            );
            return Ok((
                [
                    ("content-type", "text/html; charset=utf-8"),
                    (
                        "content-security-policy",
                        "default-src 'none'; style-src 'unsafe-inline'",
                    ),
                ],
                html,
            ));
        }
        // If session not found (expired/disconnected), fall through to normal web flow
    }

    // Step-up flow: don't post a new identity to the parent window.
    // Just signal "step-up complete for purpose=X" so the web client
    // can retry whatever it was doing (e.g. re-POST the upload).
    if is_step_up {
        // Mobile clients use ASWebAuthenticationSession with a freeq://
        // callback — the BroadcastChannel HTML doesn't reach them. Send a
        // custom-scheme redirect they can intercept and resume the upload.
        if pending.mobile {
            let redirect = format!(
                "freeq://step-up?ok=1&purpose={}",
                urlencod(pending.purpose.as_str()),
            );
            let html = format!(
                r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={redirect}"></head><body><script>window.location.href = "{redirect}";</script><p>Returning to freeq…</p></body></html>"#
            );
            return Ok((
                [
                    ("content-type", "text/html; charset=utf-8"),
                    (
                        "content-security-policy",
                        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
                    ),
                ],
                html,
            ));
        }
        return Ok(step_up_result_page(pending.purpose.as_str()));
    }

    // Mobile apps get a redirect to freeq:// custom scheme
    if pending.mobile {
        let nick = mobile_nick_from_handle(&pending.handle);
        let redirect = format!(
            "freeq://auth?token={}&broker_token={}&nick={}&did={}&handle={}",
            urlencod(result.web_token.as_deref().unwrap_or("")),
            urlencod(result.broker_token.as_deref().unwrap_or("")),
            urlencod(&nick),
            urlencod(&result.did),
            urlencod(&result.handle),
        );
        let html = format!(
            r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={redirect}"></head><body><script>window.location.href = "{redirect}";</script><p>Redirecting to freeq app...</p></body></html>"#
        );
        return Ok((
            [
                ("content-type", "text/html; charset=utf-8"),
                (
                    "content-security-policy",
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
                ),
            ],
            html,
        ));
    }

    // Return HTML page that posts result to parent window
    Ok(oauth_result_page(
        "Authentication successful!",
        Some(&result),
    ))
}

/// HTML page returned to the popup at the end of a step-up OAuth flow.
/// Carries no identity — only signals that the caller (the same logged-in
/// user) gained the additional purpose's permission. The web app picks
/// this up via `BroadcastChannel('freeq-oauth-step-up')` and retries
/// whatever it was doing.
fn step_up_result_page(purpose: &str) -> ([(&'static str, &'static str); 2], String) {
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"/><title>freeq</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0;
       display: flex; justify-content: center; align-items: center;
       min-height: 100vh; margin: 0; }}
.card {{ background: #16162a; border: 1px solid #2a2a4a; border-radius: 16px;
        padding: 32px; text-align: center; max-width: 380px; }}
h1 {{ color: #6c63ff; font-size: 20px; margin: 0 0 12px 0; }}
p {{ color: #a0a0b0; margin: 6px 0; font-size: 14px; }}
</style></head><body>
<div class="card">
<h1>✓ Permission granted</h1>
<p>You can close this window — freeq will continue automatically.</p>
</div>
<script>
try {{
  const msg = {{ type: 'freeq-oauth-step-up', purpose: '{purpose}' }};
  try {{ const bc = new BroadcastChannel('freeq-oauth-step-up'); bc.postMessage(msg); bc.close(); }} catch(e) {{}}
  if (window.opener) {{
    try {{ window.opener.postMessage(msg, window.location.origin); }} catch(e) {{}}
  }}
  setTimeout(() => window.close(), 800);
}} catch(e) {{}}
</script></body></html>"#,
    );
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            ),
        ],
        html,
    )
}

/// Generate the HTML page returned by the OAuth callback.
/// If result is Some, it posts the credentials to the parent window via postMessage.
/// Returns (headers, html) tuple so the CSP allows inline scripts (the global middleware
/// skips setting CSP when the handler already provides one).
fn oauth_result_page(
    message: &str,
    result: Option<&crate::server::OAuthResult>,
) -> ([(&'static str, &'static str); 2], String) {
    let html = oauth_result_html(message, result);
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            ),
        ],
        html,
    )
}

fn oauth_result_html(message: &str, result: Option<&crate::server::OAuthResult>) -> String {
    let script = if let Some(r) = result {
        let json = serde_json::to_string(r).unwrap_or_default();
        format!(
            r#"<script>
            // Store result in localStorage with timestamp (used by polling fallback and Tauri redirect)
            try {{
                var resultWithTs = {json};
                resultWithTs._ts = Date.now();
                localStorage.setItem('freeq-oauth-result', JSON.stringify(resultWithTs));
            }} catch(e) {{}}
            // BroadcastChannel delivers result to main window (works cross-origin)
            try {{
                const bc = new BroadcastChannel('freeq-oauth');
                bc.postMessage({{ type: 'freeq-oauth', result: {json} }});
                bc.close();
            }} catch(e) {{}}
            // Try postMessage to opener as secondary channel
            if (window.opener) {{
                try {{ window.opener.postMessage({{ type: 'freeq-oauth', result: {json} }}, window.location.origin); }} catch(e) {{}}
            }}
            // Try to close this window after a delay (gives BroadcastChannel time to deliver).
            // The main window will also try popup.close() when it receives the result.
            // If close fails (not a popup), check for Tauri and redirect.
            setTimeout(() => {{
                document.querySelector('#hint').textContent = 'You can close this window.';
                window.close();
                // If we're still here after close(), check if this is Tauri (same-window flow)
                setTimeout(() => {{
                    if (window.__TAURI_INTERNALS__ || !window.opener && window.name !== 'freeq-auth') {{
                        window.location.href = '/';
                    }}
                }}, 500);
            }}, 1500);
            </script>"#
        )
    } else {
        String::new()
    };

    // SECURITY: HTML-escape the message before interpolating it into
    // the page body. `message` may carry attacker-controlled content
    // — most directly via /auth/callback?error=<script>… (anyone can
    // land a victim on that URL), but also via PDS-controlled error
    // bodies. The page's CSP allows inline scripts so any unescaped
    // `<script>` would actually execute. CTF-11 regression test pins
    // this.
    fn html_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#x27;"),
                _ => out.push(c),
            }
        }
        out
    }
    let safe_message = html_escape(message);

    // Show different text depending on whether this is a popup or same-window flow
    let close_hint = if result.is_some() {
        "<p id=\"hint\" style=\"color:#6c7086\">Connecting...</p>\
<div style=\"margin-top:16px\"><svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" \
style=\"animation:spin 1s linear infinite\"><style>@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>\
<circle cx=\"12\" cy=\"12\" r=\"10\" stroke=\"#6c7086\" stroke-width=\"3\" fill=\"none\" \
stroke-dasharray=\"31.4 31.4\" stroke-linecap=\"round\"/></svg></div>\
<script>if(window.opener)document.getElementById('hint').textContent='You can close this window.';</script>"
    } else {
        "<p style=\"color:#f38ba8\">Please close this window and try again.</p>"
    };
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>freeq auth</title>
<style>
body {{ font-family: system-ui; background: #1e1e2e; color: #cdd6f4; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
.box {{ text-align: center; }}
h1 {{ color: #89b4fa; font-size: 20px; }}
p {{ color: #a6adc8; }}
</style></head>
<body><div class="box"><h1>freeq</h1><p>{safe_message}</p>{close_hint}</div>
{script}
</body></html>"#
    )
}

/// Derive an IRC nick from an AT Protocol handle.
/// Custom domains use the full handle; standard hosting suffixes are stripped.
fn mobile_nick_from_handle(handle: &str) -> String {
    let standard_suffixes = [".bsky.social", ".bsky.app", ".bsky.team", ".bsky.network"];
    for suffix in &standard_suffixes {
        if let Some(stripped) = handle.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    handle.to_string()
}

// ── Media upload endpoint ───────────────────────────────────────────

/// POST /api/v1/upload
/// Multipart form: `file` (binary), `did` (text), `alt` (optional text), `channel` (optional text).
/// Server proxies the upload to the user's PDS using their stored OAuth credentials.
/// Returns JSON: `{ "url": "...", "content_type": "...", "size": N }`.
async fn api_upload(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !state.rest_rate_limiter.check(addr.ip()) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded".to_string(),
        ));
    }
    let mut file_data: Option<Vec<u8>> = None;
    let mut content_type = String::from("application/octet-stream");
    let mut did = String::new();
    let mut alt = None::<String>;
    let mut channel = None::<String>;
    let mut filename = None::<String>;
    // Two independent opt-in share toggles (default: private-only).
    // `share_bluesky` (feed post) implies `share_pds` since the feed embed
    // references the PDS blob. `cross_post` is the legacy alias for it.
    let mut share_pds = false;
    // Store the file in the user's own repo inside this channel's media
    // space instead of the server's private store.
    let mut space_media = false;
    let mut share_bluesky = false;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                if let Some(ct) = field.content_type() {
                    content_type = ct.to_string();
                }
                if let Some(fname) = field.file_name() {
                    filename = Some(fname.to_string());
                }
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("File read error: {e}")))?;
                if bytes.len() > 10 * 1024 * 1024 {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "File too large (max 10MB)".into(),
                    ));
                }
                file_data = Some(bytes.to_vec());
            }
            "did" => {
                did = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("DID read error: {e}")))?;
            }
            "alt" => {
                alt = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Alt read error: {e}")))?,
                );
            }
            "channel" => {
                channel =
                    Some(field.text().await.map_err(|e| {
                        (StatusCode::BAD_REQUEST, format!("Channel read error: {e}"))
                    })?);
            }
            "share_pds" => {
                let val = field.text().await.unwrap_or_default();
                share_pds = val == "true" || val == "1";
            }
            "share_bluesky" | "cross_post" => {
                let val = field.text().await.unwrap_or_default();
                share_bluesky = val == "true" || val == "1";
            }
            "space_media" => {
                let val = field.text().await.unwrap_or_default();
                space_media = val == "true" || val == "1";
            }
            _ => {}
        }
    }

    let file_data =
        file_data.ok_or_else(|| (StatusCode::BAD_REQUEST, "No file provided".into()))?;
    if did.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No DID provided".into()));
    }
    // A Bluesky feed post needs the blob on the PDS, so it implies share_pds.
    let share_pds = share_pds || share_bluesky;

    // ── Upload auth: verify the caller owns this DID ────────────────────
    // Accept either:
    //   1. X-Upload-Token header (HMAC-SHA256 over DID, minted by broker session push)
    //   2. DID must have an active WebSocket session on this server
    // This prevents arbitrary callers from using stored PDS credentials.
    let has_upload_token = headers
        .get("x-upload-token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|token| {
            state
                .upload_tokens
                .lock()
                .get(token)
                .is_some_and(|(t_did, created)| t_did == &did && created.elapsed().as_secs() < 300)
        });
    let has_active_session = {
        let session_dids = state.session_dids.lock();
        session_dids.values().any(|d| d == &did)
    };
    if !has_upload_token && !has_active_session {
        tracing::warn!(did = %did, "Upload rejected: no active WebSocket session or upload token");
        return Err((
            StatusCode::UNAUTHORIZED,
            "Upload requires an active connection for this DID".into(),
        ));
    }

    // ── Private media space ─────────────────────────────────────────────
    // The file goes into the uploader's own repo inside the channel's space.
    // Nothing is stored here, so this returns before the private store.
    if space_media {
        let Some(mgr) = state.media_space.clone() else {
            return Err((
                StatusCode::NOT_FOUND,
                "Private media spaces are not enabled on this server".into(),
            ));
        };
        let Some(channel) = channel.clone().filter(|c| c.starts_with('#')) else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Private media spaces are per-channel; no channel given".into(),
            ));
        };
        let session = {
            let sessions = state.web_sessions.lock();
            let purpose = crate::server::OauthPurpose::MediaSpace;
            sessions
                .get(&(did.clone(), purpose))
                .or_else(|| sessions.get(&(did.clone(), crate::server::OauthPurpose::Login)))
                .filter(|s| crate::server::scope_satisfies_purpose(&s.granted_scope, purpose))
                .cloned()
        };
        let Some(session) = session else {
            let has_login = state
                .web_sessions
                .lock()
                .contains_key(&(did.clone(), crate::server::OauthPurpose::Login));
            let body = if has_login {
                serde_json::json!({
                    "error": "step_up_required",
                    "purpose": "media_space",
                    "step_up_url": "/auth/step-up?purpose=media_space",
                    "message": "Storing this file privately on your PDS needs an \
                                additional permission. Authorize once and we'll proceed.",
                })
            } else {
                serde_json::json!({
                    "error": "not_authenticated",
                    "message": "No active session for this DID — please log in.",
                })
            };
            return Err((
                if has_login {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::UNAUTHORIZED
                },
                body.to_string(),
            ));
        };

        let space_key = channel_space_key(&state, &mgr, &channel)
            .await
            .map_err(|s| {
                (
                    s,
                    "Could not resolve this channel's media space".to_string(),
                )
            })?;
        let dpop_key = freeq_sdk::oauth::DpopKey::from_base64url(&session.dpop_key_b64)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP key: {e}")))?;
        let result = freeq_sdk::media::upload_media_to_space(
            &session.pds_url,
            &session.did,
            &session.access_token,
            Some(&dpop_key),
            session.dpop_nonce.as_deref(),
            &mgr.space_ref(&space_key),
            crate::media_space::MEDIA_COLLECTION,
            &content_type,
            &file_data,
            alt.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(did = %did, channel = %channel, error = %e, "space media upload failed");
            (StatusCode::BAD_GATEWAY, format!("{e}"))
        })?;

        tracing::info!(did = %did, channel = %channel, uri = %result.uri, "Space media stored");
        let (origin, _) = derive_web_origin(&headers);
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.uri.as_bytes());
        let name = pick_media_filename(filename.as_deref(), &content_type);
        return Ok(Json(serde_json::json!({
            "url": format!("{origin}/api/v1/space-media/{encoded}/{name}"),
            "uri": result.uri,
            "private": true,
            "space": true,
            "mime": result.mime_type,
            "size": result.size,
        })));
    }

    // ── Opt-in PDS authorization ────────────────────────────────────────
    // Private uploads (the default) never touch the PDS, so they need NO blob
    // scope. Only when the user opts to share do we resolve a blob-upload
    // session and, if absent, ask the client to step up. We check this BEFORE
    // storing privately so a step-up retry doesn't leave an orphaned blob.
    let pds_session = if share_pds {
        // Prefer the dedicated BlobUpload session (Phase 2 step-up); fall back
        // to the primary Login session only when its granted scope already
        // covers blob upload (legacy wide grant).
        let session = {
            let sessions = state.web_sessions.lock();
            let purpose = crate::server::OauthPurpose::BlobUpload;
            if let Some(s) = sessions.get(&(did.clone(), purpose)) {
                Some(s.clone())
            } else if let Some(s) = sessions.get(&(did.clone(), crate::server::OauthPurpose::Login))
                && crate::server::scope_satisfies_purpose(&s.granted_scope, purpose)
            {
                Some(s.clone())
            } else {
                None
            }
        };
        match session {
            Some(s) => Some(s),
            None => {
                let has_login = state
                    .web_sessions
                    .lock()
                    .contains_key(&(did.clone(), crate::server::OauthPurpose::Login));
                let body = if has_login {
                    serde_json::json!({
                        "error": "step_up_required",
                        "purpose": "blob_upload",
                        "step_up_url": "/auth/step-up?purpose=blob_upload",
                        "message": "Sharing this file to your PDS needs an additional \
                                    permission. Authorize once and we'll proceed.",
                    })
                } else {
                    serde_json::json!({
                        "error": "not_authenticated",
                        "message": "No active session for this DID — please log in.",
                    })
                };
                tracing::warn!(did = %did, has_login, "Share denied: no blob-upload-capable session");
                return Err((
                    if has_login {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::UNAUTHORIZED
                    },
                    body.to_string(),
                ));
            }
        }
    } else {
        None
    };

    // ── Private storage (always) ────────────────────────────────────────
    // Store the bytes encrypted-at-rest and mint a signed capability URL. The
    // in-channel message always references this URL regardless of sharing, so
    // the conversation renders consistently and nothing leaks publicly by
    // default.
    let (Some(store), Some(db)) = (state.media_store.as_ref(), state.db.as_ref()) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Private media storage is unavailable on this server".into(),
        ));
    };
    let media_id = crate::media_store::new_id();
    let stored_filename = pick_media_filename(filename.as_deref(), &content_type);
    let size = file_data.len() as u64;
    let scope = channel.clone().unwrap_or_default();
    store.put(&media_id, &file_data).map_err(|e| {
        tracing::error!(media_id = %media_id, error = %e, "Failed to write private media blob");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store media".into(),
        )
    })?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(e) = db.lock().insert_media(
        &media_id,
        &did,
        &scope,
        &content_type,
        size,
        alt.as_deref(),
        &stored_filename,
        created_at,
    ) {
        // Roll back the orphaned blob so we don't leave unreferenced bytes.
        store.remove(&media_id);
        tracing::error!(media_id = %media_id, error = %e, "Failed to record media metadata");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store media".into(),
        ));
    }
    let (origin, _) = derive_web_origin(&headers);
    let client_url = store.capability_url(&origin, &media_id, &stored_filename);

    // ── Opt-in PDS / Bluesky share (best-effort) ────────────────────────
    // A failure here does NOT fail the upload: the private copy already
    // succeeded and the channel message will render. We only warn.
    if let Some(session) = pds_session {
        match freeq_sdk::oauth::DpopKey::from_base64url(&session.dpop_key_b64) {
            Ok(dpop_key) => {
                match freeq_sdk::media::upload_media_to_pds(
                    &session.pds_url,
                    &session.did,
                    &session.access_token,
                    Some(&dpop_key),
                    session.dpop_nonce.as_deref(),
                    &content_type,
                    &file_data,
                    alt.as_deref(),
                    channel.as_deref(),
                    share_bluesky,
                )
                .await
                {
                    Ok(result) => {
                        // Persist the refreshed DPoP nonce for next time.
                        if let Some(ref new_nonce) = result.updated_nonce {
                            let mut sessions = state.web_sessions.lock();
                            let blob_key = (did.clone(), crate::server::OauthPurpose::BlobUpload);
                            if let Some(s) = sessions.get_mut(&blob_key) {
                                s.dpop_nonce = Some(new_nonce.clone());
                            } else if let Some(s) =
                                sessions.get_mut(&(did.clone(), crate::server::OauthPurpose::Login))
                            {
                                s.dpop_nonce = Some(new_nonce.clone());
                            }
                        }
                        tracing::info!(
                            did = %did, share_bluesky,
                            "Media also shared to PDS"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(did = %did, error = %format!("{e:#}"), "PDS share failed (private copy kept)");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "PDS share skipped: bad DPoP key");
            }
        }
    }

    tracing::info!(did = %did, url = %client_url, size, share_pds, "Private media stored");

    Ok(Json(serde_json::json!({
        "url": client_url,
        "content_type": content_type,
        "size": size,
        "private": !share_pds,
    })))
}

/// Choose a stored filename that keeps a usable extension, so the capability
/// URL's trailing segment lets clients detect the media type by extension.
fn pick_media_filename(provided: Option<&str>, mime: &str) -> String {
    let ext = match mime {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "video/mp4" => ".mp4",
        "video/quicktime" => ".mov",
        "video/webm" => ".webm",
        "audio/mpeg" => ".mp3",
        "audio/mp4" | "audio/x-m4a" => ".m4a",
        "audio/ogg" => ".ogg",
        "audio/wav" | "audio/x-wav" => ".wav",
        "application/pdf" => ".pdf",
        _ => "",
    };
    match provided {
        Some(n) if n.contains('.') => n.to_string(),
        Some(n) if !n.is_empty() => format!("{n}{ext}"),
        _ => format!("media{ext}"),
    }
}

// ── Channel invite page ────────────────────────────────────────────────

/// Escape user-controlled strings for safe embedding in HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// WebSocket MoQ endpoint (root path) — upgrades to MoQ session through the SFU cluster.
/// The `?jwt=` query param carries the session token (mirrors the QUIC
/// transport, where `AuthParams::from_url` parses the same param).
#[cfg(feature = "av-native")]
async fn av_moq_ws_root(
    ws: axum::extract::WebSocketUpgrade,
    Query(query): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<crate::server::SharedState>>,
) -> impl IntoResponse {
    let jwt = query.get("jwt").filter(|v| !v.is_empty()).cloned();
    // Self-declared AV instance id — keys server-side media revocation on
    // roster teardown (audit F6).
    let inst = query.get("inst").filter(|v| !v.is_empty()).cloned();
    let sfu = state.sfu_state.lock().clone();
    match sfu {
        // qmux requires "webtransport" subprotocol for MoQ framing over WebSocket
        Some(sfu) => ws
            .protocols(["webtransport"])
            .on_upgrade(move |socket| {
                crate::av_sfu::handle_ws_moq(sfu, String::new(), jwt, inst, socket)
            })
            .into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "SFU not initialized",
        )
            .into_response(),
    }
}

#[cfg(not(feature = "av-native"))]
async fn av_moq_ws_root() -> impl IntoResponse {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "AV not enabled",
    )
}

/// WebSocket MoQ endpoint with path — upgrades to MoQ session through the SFU cluster.
/// Path format: {session_id}/{nick} for publish, {session_id} for subscribe.
#[cfg(feature = "av-native")]
async fn av_moq_ws(
    ws: axum::extract::WebSocketUpgrade,
    Path(path): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<crate::server::SharedState>>,
) -> impl IntoResponse {
    tracing::info!(path = %path, "MoQ WebSocket upgrade with path");

    let jwt = query.get("jwt").filter(|v| !v.is_empty()).cloned();
    let inst = query.get("inst").filter(|v| !v.is_empty()).cloned();
    let sfu = state.sfu_state.lock().clone();
    match sfu {
        Some(sfu) => ws
            .protocols(["webtransport"])
            .on_upgrade(move |socket| crate::av_sfu::handle_ws_moq(sfu, path, jwt, inst, socket))
            .into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "SFU not initialized",
        )
            .into_response(),
    }
}

#[cfg(not(feature = "av-native"))]
async fn av_moq_ws() -> impl IntoResponse {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "AV not enabled",
    )
}

/// GET /api/v1/av/sessions/{id}/token — mint a MoQ access token for an AV
/// session. Requires a Bearer IRC session whose DID is an active participant
/// (clients av-join over IRC before dialing the SFU, so this always holds by
/// the time they need a token). The same token is also pushed over IRC as a
/// `+freeq.at/av-token` TAGMSG on av-start/av-join; this endpoint exists for
/// clients that find request/response easier than tag parsing (the web app).
#[cfg(feature = "av-native")]
async fn api_av_session_token(
    Path(id): Path<String>,
    State(state): State<Arc<crate::server::SharedState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let Some(caller) = caller_did_from_bearer(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Bearer session required" })),
        );
    };

    let is_active_participant = {
        let mgr = state.av_sessions.lock();
        mgr.get(&id)
            .map(|s| {
                s.participants
                    .values()
                    .any(|p| p.did == caller && p.left_at.is_none())
            })
            .unwrap_or(false)
    };
    if !is_active_participant {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "not an active participant of this session" })),
        );
    }

    let sfu = state.sfu_state.lock().clone();
    let Some(token) = sfu.and_then(|sfu| sfu.mint_session_token(&id)) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "SFU token minting unavailable" })),
        );
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": token,
            "expires_in": crate::av_sfu::AV_TOKEN_TTL_SECS,
        })),
    )
}

#[cfg(not(feature = "av-native"))]
async fn api_av_session_token() -> impl IntoResponse {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "AV not enabled",
    )
}

/// Serve the AV call page (SFU web UI for browser audio).
/// Sets its own CSP to allow inline scripts (the global middleware skips when CSP is already set).
async fn av_call_page() -> impl IntoResponse {
    (
        axum::http::StatusCode::OK,
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' blob:; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: https:; media-src 'self' blob:; img-src 'self' data:; worker-src 'self' blob:",
            ),
        ],
        include_str!("../static/av/call.html"),
    )
}

/// Serve AV JS assets (moq-publish, moq-watch, etc).
async fn av_asset(Path(filename): Path<String>) -> impl IntoResponse {
    let files: &[(&str, &str)] = &[
        // Rebuilt 2026-05-25 as component-only bundles (side-effect
        // imports of @moq/publish/element and @moq/watch/element).
        //
        // Previous bundles (watch-DdXJRVCU.js / publish-CKcN3504.js)
        // were built from iroh-live-relay/web's demo app — they
        // include the demo wrapper that does
        // `document.getElementById("publish")` and throws on missing
        // element. That's why the browser console showed:
        //   "missing <moq-publish> element"
        //   "Cannot read properties of null (reading 'addEventListener')"
        // No amount of placeholder elements in moq-loader.ts could
        // satisfy the demo wrapper, because it looks for IDs
        // ("publish", "watch", "landing", ...) not tag names.
        //
        // Build source: /tmp/moq-components-bundle (a minimal Vite
        // project with src/{publish,watch}-elem.ts each containing
        // just `import "@moq/{publish,watch}/element"`). Built with
        // @moq/hang pinned to 0.2.5 because 0.2.6 transitively
        // depends on @moq/loc which is unpublished on npm.
        (
            "watch-CTz_Tjt7.js",
            include_str!("../static/av/assets/watch-CTz_Tjt7.js"),
        ),
        (
            "publish-Du5ksDQe.js",
            include_str!("../static/av/assets/publish-Du5ksDQe.js"),
        ),
        (
            "time-D4Xqna_f.js",
            include_str!("../static/av/assets/time-D4Xqna_f.js"),
        ),
        (
            "main-DGBFe0O7-CIZu5tmC.js",
            include_str!("../static/av/assets/main-DGBFe0O7-CIZu5tmC.js"),
        ),
        (
            "main-DGBFe0O7-DQ8if_La.js",
            include_str!("../static/av/assets/main-DGBFe0O7-DQ8if_La.js"),
        ),
        (
            "libav-opus-af-BlMWboA7-B4GfDr9_.js",
            include_str!("../static/av/assets/libav-opus-af-BlMWboA7-B4GfDr9_.js"),
        ),
        (
            "libav-opus-af-BlMWboA7-CFTeN5TA.js",
            include_str!("../static/av/assets/libav-opus-af-BlMWboA7-CFTeN5TA.js"),
        ),
    ];
    for (name, body) in files {
        if filename == *name {
            return (
                axum::http::StatusCode::OK,
                [(
                    "content-type",
                    "application/javascript; charset=utf-8".to_string(),
                )],
                body.to_string(),
            )
                .into_response();
        }
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        [("content-type", "text/plain".to_string())],
        "not found".to_string(),
    )
        .into_response()
}

async fn channel_invite_page(
    Path(channel): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> impl IntoResponse {
    let channel = if channel.starts_with('#') || channel.starts_with("%23") {
        channel.replace("%23", "#")
    } else {
        format!("#{channel}")
    };

    // Get channel info
    let (member_count, topic_text) = {
        let channels = state.channels.lock();
        let key = channel.to_lowercase();
        match channels.get(&key) {
            Some(ch) => (ch.members.len(), ch.topic.as_ref().map(|t| t.text.clone())),
            None => (0, None),
        }
    };

    let server = &state.config.server_name;
    let topic_html = html_escape(topic_text.as_deref().unwrap_or("No topic set"));
    let channel_display = html_escape(channel.trim_start_matches('#'));
    let channel_escaped = html_escape(&channel);
    let member_word = if member_count == 1 {
        "member"
    } else {
        "members"
    };

    Html(format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{channel_escaped} — freeq</title>
<meta property="og:title" content="{channel_escaped} on freeq">
<meta property="og:description" content="{topic_html} — {member_count} {member_word} online">
<meta property="og:type" content="website">
<meta property="og:url" content="https://{server}/join/{channel_display}">
<meta property="og:image" content="https://{server}/freeq.png">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{channel_escaped} on freeq">
<meta name="twitter:description" content="{topic_html} — {member_count} {member_word} online">
<meta name="twitter:image" content="https://{server}/freeq.png">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0c0c0f;color:#e8e8ed;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#131318;border:1px solid #1e1e2e;border-radius:20px;padding:48px;max-width:460px;width:90vw;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5)}}
.logo{{width:64px;height:64px;margin:0 auto 16px}}
h1{{font-size:28px;margin-bottom:4px}}
h1 .accent{{color:#00d4aa}}
.channel{{font-size:36px;font-weight:800;color:#00d4aa;margin:24px 0 8px;letter-spacing:-0.5px}}
.topic{{color:#9898b0;font-size:15px;margin-bottom:24px;line-height:1.5}}
.stats{{color:#555570;font-size:13px;margin-bottom:32px}}
.stats span{{color:#9898b0}}
.btn{{display:inline-block;background:#00d4aa;color:#000;font-size:18px;font-weight:700;padding:14px 40px;border-radius:12px;text-decoration:none;transition:all 0.2s}}
.btn:hover{{background:#00f0c0;box-shadow:0 0 24px rgba(0,212,170,0.2)}}
.alt{{color:#555570;font-size:12px;margin-top:20px}}
.alt a{{color:#00d4aa;text-decoration:none}}
.alt a:hover{{text-decoration:underline}}
.badge{{display:inline-flex;align-items:center;gap:4px;background:#00d4aa15;color:#00d4aa;font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;margin-bottom:16px}}
</style>
</head>
<body>
<div class="card">
  <img src="/freeq.png" alt="freeq" class="logo">
  <div class="badge">IRC + AT Protocol</div>
  <h1><span class="accent">free</span>q</h1>
  <div class="channel">#{channel_display}</div>
  <div class="topic">{topic_html}</div>
  <div class="stats"><span>{member_count}</span> {member_word} online on <span>{server}</span></div>
  <a href="https://{server}/#auto-join={channel_escaped}" class="btn">Join Channel</a>
  <div class="alt">
    Or connect with any IRC client: <code>{server}:6667</code><br>
    <a href="https://freeq.at" target="_blank">Learn more about freeq</a>
  </div>
</div>
</body>
</html>"##)).into_response()
}

// ── OG metadata proxy (replaces allorigins.win privacy leak) ──────────

#[derive(Deserialize)]
struct OgQuery {
    url: String,
}

// ── Blob proxy endpoint ───────────────────────────────────────────

/// GET /api/v1/blob?url=<pds-blob-url>
/// Proxies PDS blob downloads, stripping Content-Disposition: attachment
/// and sandbox CSP headers that prevent browser/AVPlayer playback.
/// Supports Range requests for video seeking / AVPlayer compatibility.
async fn api_blob_proxy(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !state.rest_rate_limiter.check(addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }
    let Some(url) = q.get("url") else {
        return (StatusCode::BAD_REQUEST, "missing url parameter").into_response();
    };

    // Only proxy known PDS blob URLs — strict host validation to prevent SSRF
    let parsed = match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" => u,
        _ => return (StatusCode::BAD_REQUEST, "invalid URL").into_response(),
    };
    let host = parsed.host_str().unwrap_or("");
    let is_pds_blob = parsed.path().starts_with("/xrpc/com.atproto.sync.getBlob")
        && (host.ends_with(".host.bsky.network")
            || host.ends_with(".bsky.network")
            || host == "bsky.social");
    let is_cdn = host == "cdn.bsky.app";
    if !is_pds_blob && !is_cdn {
        return (StatusCode::BAD_REQUEST, "not a valid blob URL").into_response();
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    // Forward Range header if present (needed for AVPlayer / video seeking)
    let mut req = client.get(url);
    if let Some(range) = headers.get(axum::http::header::RANGE)
        && let Ok(range_str) = range.to_str()
    {
        req = req.header("Range", range_str);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "Blob proxy fetch failed");
            return (StatusCode::BAD_GATEWAY, "fetch failed").into_response();
        }
    };

    let upstream_status = resp.status();
    if !upstream_status.is_success() && upstream_status.as_u16() != 206 {
        return (StatusCode::BAD_GATEWAY, "upstream error").into_response();
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let content_range = resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_length = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_GATEWAY, "read failed").into_response(),
    };

    let status = if upstream_status.as_u16() == 206 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        content_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    resp_headers.insert(
        axum::http::header::CACHE_CONTROL,
        "public, max-age=86400".parse().unwrap(),
    );
    resp_headers.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());

    if let Some(cr) = content_range
        && let Ok(val) = cr.parse()
    {
        resp_headers.insert(axum::http::header::CONTENT_RANGE, val);
    }
    if let Some(cl) = content_length
        && let Ok(val) = cl.parse()
    {
        resp_headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }

    (status, resp_headers, bytes).into_response()
}

/// Serve a privately-stored media blob via a signed capability URL.
///
/// Path: `/api/v1/media/{id}/{sig}/{filename}`. The signature gates access —
/// possession of a valid URL (which only reaches members of the conversation
/// it was posted to) is the grant. Bytes are decrypted from disk and streamed
/// with HTTP Range support for video/audio seeking.
async fn api_media_serve(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<SharedState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((id, sig, _filename)): axum::extract::Path<(String, String, String)>,
) -> impl IntoResponse {
    if !state.rest_rate_limiter.check(addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }
    let Some(store) = state.media_store.as_ref() else {
        return (StatusCode::NOT_FOUND, "media storage unavailable").into_response();
    };
    // Capability check first — never reveal whether an id exists to callers
    // without a valid signature.
    if !store.verify(&id, &sig) {
        return (StatusCode::FORBIDDEN, "invalid capability").into_response();
    }
    // Look up live (non-deleted) metadata.
    let row = match state.db.as_ref() {
        Some(db) => match db.lock().get_media(&id) {
            Ok(Some(r)) => r,
            Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
            Err(e) => {
                tracing::warn!(media_id = %id, error = %e, "media metadata lookup failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
            }
        },
        None => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let bytes = match store.get(&id) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(media_id = %id, error = %e, "media blob read failed");
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
    };

    let content_type: axum::http::HeaderValue = row
        .mime
        .parse()
        .unwrap_or_else(|_| "application/octet-stream".parse().unwrap());
    let total = bytes.len() as u64;

    // Optional HTTP Range (single range only — sufficient for media players).
    if let Some(range) = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        && let Some((start, end)) = parse_single_range(range, total)
    {
        let slice = bytes[start as usize..=end as usize].to_vec();
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::CONTENT_TYPE, content_type);
        h.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
        h.insert(
            axum::http::header::CACHE_CONTROL,
            "private, max-age=31536000, immutable".parse().unwrap(),
        );
        if let Ok(cr) = format!("bytes {start}-{end}/{total}").parse() {
            h.insert(axum::http::header::CONTENT_RANGE, cr);
        }
        return (StatusCode::PARTIAL_CONTENT, h, slice).into_response();
    }

    let mut h = axum::http::HeaderMap::new();
    h.insert(axum::http::header::CONTENT_TYPE, content_type);
    h.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
    h.insert(
        axum::http::header::CACHE_CONTROL,
        "private, max-age=31536000, immutable".parse().unwrap(),
    );
    (StatusCode::OK, h, bytes).into_response()
}

/// Parse a single-range `Range: bytes=start-end` header against a known total
/// length. Returns an inclusive `(start, end)` byte range, or None if the
/// header is absent/unsatisfiable/multi-range.
fn parse_single_range(header: &str, total: u64) -> Option<(u64, u64)> {
    if total == 0 {
        return None;
    }
    let spec = header.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // multi-range not supported
    }
    let (s, e) = spec.split_once('-')?;
    let (start, end) = match (s.trim(), e.trim()) {
        ("", "") => return None,
        ("", suffix) => {
            // `-N` → last N bytes
            let n: u64 = suffix.parse().ok()?;
            if n == 0 {
                return None;
            }
            (total.saturating_sub(n), total - 1)
        }
        (start, "") => (start.parse().ok()?, total - 1),
        (start, end) => {
            let st: u64 = start.parse().ok()?;
            let en: u64 = end.parse().ok()?;
            (st, en.min(total - 1))
        }
    };
    if start > end || start >= total {
        return None;
    }
    Some((start, end))
}

/// Fetch OpenGraph metadata from a URL and return as JSON.
/// Avoids clients leaking browsing data to third-party proxy services.
async fn api_og_preview(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<SharedState>>,
    Query(q): Query<OgQuery>,
) -> impl IntoResponse {
    if !state.rest_rate_limiter.check(addr.ip()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Rate limit exceeded"})),
        )
            .into_response();
    }
    // Validate URL
    let url = match url::Url::parse(&q.url) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => u,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid URL"})),
            )
                .into_response();
        }
    };

    // Block SSRF: resolve hostname, reject private IPs, and pin DNS to
    // prevent TOCTOU / DNS-rebinding between validation and fetch.
    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No host in URL"})),
            )
                .into_response();
        }
    };
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addrs = match freeq_sdk::ssrf::resolve_and_check(&host, port).await {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Blocked: {e}")})),
            )
                .into_response();
        }
    };

    // Build a DNS-pinned client so reqwest uses the validated IPs
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(3));
    for addr in &addrs {
        builder = builder.resolve(&host, *addr);
    }
    let client = builder.build().unwrap();

    let resp = match client
        .get(url.as_str())
        .header("User-Agent", "freeq/1.0 (link preview)")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Fetch failed"})),
            )
                .into_response();
        }
    };

    // Only process HTML
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.contains("text/html") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Not HTML"})),
        )
            .into_response();
    }

    // Limit body size to 256KB
    let body = match resp.bytes().await {
        Ok(b) if b.len() <= 256 * 1024 => String::from_utf8_lossy(&b).to_string(),
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Body too large"})),
            )
                .into_response();
        }
    };

    // Parse OG tags
    let get_meta = |prop: &str| -> Option<String> {
        let patterns = [
            format!(r#"<meta[^>]*(?:property|name)=["']{prop}["'][^>]*content=["']([^"']*)["']"#),
            format!(r#"<meta[^>]*content=["']([^"']*)["'][^>]*(?:property|name)=["']{prop}["']"#),
        ];
        for pat in &patterns {
            if let Ok(re) = regex::Regex::new(pat)
                && let Some(caps) = re.captures(&body)
            {
                return caps.get(1).map(|m| decode_html_entities(m.as_str()));
            }
        }
        None
    };

    // Also try <title> tag
    let title = get_meta("og:title").or_else(|| {
        regex::Regex::new(r"<title[^>]*>([^<]+)</title>")
            .ok()
            .and_then(|re| re.captures(&body))
            .and_then(|caps| caps.get(1))
            .map(|m| decode_html_entities(m.as_str()))
    });

    Json(serde_json::json!({
        "title": title,
        "description": get_meta("og:description").or_else(|| get_meta("description")),
        "image": get_meta("og:image"),
        "site_name": get_meta("og:site_name"),
    }))
    .into_response()
}

fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
        .replace("&nbsp;", " ")
}

// ── E2EE Pre-Key Bundle API ────────────────────────────────────────

/// GET /api/v1/keys/{did} — Fetch a user's pre-key bundle.
async fn api_get_keys(
    State(state): State<Arc<crate::server::SharedState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    // Check in-memory cache first, then fall back to DB
    let bundle = {
        let bundles = state.prekey_bundles.lock();
        bundles.get(&did).cloned()
    };
    let bundle = bundle.or_else(|| state.with_db(|db| db.get_prekey_bundle(&did)).flatten());
    match bundle {
        Some(b) => (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({ "bundle": b })),
        ),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "No pre-key bundle for this DID" })),
        ),
    }
}

/// POST /api/v1/keys — Upload a pre-key bundle.
///
/// Body: `{ "did": "did:plc:...", "bundle": { ... } }`
///
/// The DID must match the authenticated session. In practice, this is
/// called after SASL authentication when the client generates encryption keys.
async fn api_upload_keys(
    State(state): State<Arc<crate::server::SharedState>>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    let did = body.get("did").and_then(|v| v.as_str());
    let bundle = body.get("bundle");

    let (Some(did), Some(bundle)) = (did, bundle) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "Missing 'did' or 'bundle'" })),
        );
    };

    // SECURITY (CTF-19): the requester must prove they OWN the named
    // DID, not just that the DID is logged in somewhere on this server.
    // Previously this endpoint accepted any anonymous request as long
    // as the named DID had any active session — letting an unauth'd
    // attacker overwrite the victim's pre-key bundle and decrypt the
    // victim's next DMs. Require a Bearer session id whose DID matches
    // the body's `did`.
    let bearer_session = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let caller_did = bearer_session.and_then(|sid| state.session_dids.lock().get(sid).cloned());
    let owned = caller_did.as_deref() == Some(did);
    if !owned {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "Pre-key upload requires Bearer auth as the named DID."
            })),
        );
    }

    state
        .prekey_bundles
        .lock()
        .insert(did.to_string(), bundle.clone());
    // Persist to DB so bundles survive server restart
    let bundle_json = serde_json::to_string(bundle).unwrap_or_default();
    let did_owned = did.to_string();
    state.with_db(|db| db.save_prekey_bundle(&did_owned, &bundle_json));
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "ok": true })),
    )
}

// ── Per-IP rate limiting ──────────────────────────────────────────────

/// Simple per-IP sliding-window rate limiter.
/// Tracks (window_start_secs, request_count) per IP. Resets each window.
pub struct IpRateLimiter {
    max_requests: u32,
    window_secs: u64,
    state: parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            state: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.state.lock();
        let entry = map.entry(ip).or_insert((now, 0));
        if now - entry.0 >= self.window_secs {
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= self.max_requests
        }
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    /// Evict entries older than 1 hour to prevent unbounded growth.
    pub fn prune(&self, now_secs: u64) {
        let mut map = self.state.lock();
        map.retain(|_, (ts, _)| now_secs.saturating_sub(*ts) < 3600);
    }
}

/// Security headers middleware.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    // Only set CSP if the handler didn't already set one (e.g. /auth/mobile needs inline scripts)
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' https: data: blob:; media-src 'self' https: blob:; connect-src 'self' wss: https:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'".parse().unwrap(),
        );
    }
    resp
}

// ── AV Sessions REST API ────────────────────────────────────────────

/// GET /api/v1/sessions — list all active sessions.
async fn api_sessions_list(State(state): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let mgr = state.av_sessions.lock();
    let sessions: Vec<serde_json::Value> = mgr
        .active_sessions()
        .into_iter()
        .map(|s| session_to_json(s, &mgr))
        .collect();
    Json(serde_json::json!({ "sessions": sessions }))
}

/// GET /api/v1/sessions/{id} — session details.
///
/// `?debug=1` adds `announced`: the broadcast paths the SFU is currently
/// announcing under this session's prefix, beside the roster. The two are the
/// call's two sources of truth (web subscribes from the roster, every native
/// client from the announcements), and every class-A incident has been a
/// disagreement between them — so this makes that disagreement one request to
/// see, live, during an incident instead of a log archaeology exercise. A
/// binary without `av-native` has no SFU to ask: `announced` is null and
/// `announced_note` says why.
async fn api_session_detail(
    State(state): State<Arc<SharedState>>,
    Path(id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let mut body = {
        let mgr = state.av_sessions.lock();
        let session = mgr.get(&id).ok_or((
            axum::http::StatusCode::NOT_FOUND,
            "Session not found".to_string(),
        ))?;
        session_to_json(session, &mgr)
    };

    if params.get("debug").map(String::as_str) == Some("1") {
        // Taken after the av_sessions guard is dropped — sfu_state is never
        // acquired while av_sessions is held (the single lock-order rule).
        #[cfg(feature = "av-native")]
        {
            let sfu = state.sfu_state.lock().clone();
            match sfu {
                Some(sfu) => {
                    let paths = sfu.announced_paths(&format!("{id}/"));
                    body["announced"] = serde_json::json!(paths);
                }
                None => {
                    body["announced"] = serde_json::Value::Null;
                    body["announced_note"] =
                        serde_json::json!("SFU not initialized on this server");
                }
            }
        }
        #[cfg(not(feature = "av-native"))]
        {
            body["announced"] = serde_json::Value::Null;
            body["announced_note"] = serde_json::json!("binary built without --features av-native");
        }
    }

    Ok(Json(body))
}

/// GET /api/v1/sessions/{id}/artifacts — list session artifacts.
async fn api_session_artifacts(
    State(state): State<Arc<SharedState>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let artifacts = state
        .with_db(|db| db.list_av_artifacts(&id))
        .unwrap_or_default();
    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "session_id": a.session_id,
                "kind": a.kind,
                "created_at": a.created_at,
                "created_by": a.created_by,
                "content_ref": a.content_ref,
                "content_type": a.content_type,
                "visibility": a.visibility,
                "title": a.title,
            })
        })
        .collect();
    Json(serde_json::json!({ "artifacts": items }))
}

/// POST /api/v1/sessions/{id}/artifacts — attach an artifact to a session.
async fn api_create_artifact(
    State(state): State<Arc<SharedState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // This endpoint writes to the provenance store AND broadcasts a NOTICE into
    // the session's channel, so it must be authenticated. Previously it took no
    // headers at all: anyone who knew a session id could forge an artifact
    // attributed to someone else (`created_by` came from the request body) and
    // inject caller-controlled text into the channel.
    let caller = caller_did_from_bearer(&state, &headers).ok_or((
        axum::http::StatusCode::UNAUTHORIZED,
        "authentication required".to_string(),
    ))?;

    // Verify session exists, and capture what we need to authorize.
    let (session_channel, is_participant) = {
        let mgr = state.av_sessions.lock();
        let session = mgr.get(&id).ok_or((
            axum::http::StatusCode::NOT_FOUND,
            "Session not found".to_string(),
        ))?;
        (
            session.channel.clone(),
            session.participants.contains_key(&caller),
        )
    };

    // Participants may always attach an artifact. Otherwise fall back to the
    // bound channel's read rule, so an op or member can attach a summary after
    // leaving the call. Ad-hoc sessions with no channel: participants only.
    if !is_participant {
        match session_channel.as_deref() {
            Some(channel) => {
                authorize_channel_read(&state, channel, &headers)
                    .map_err(|status| (status, "not authorized for this session".to_string()))?;
            }
            None => {
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "not a participant in this session".to_string(),
                ));
            }
        }
    }

    let kind_str = body["kind"].as_str().unwrap_or("summary");
    let kind: crate::av::ArtifactKind = serde_json::from_str(&format!("\"{kind_str}\""))
        .unwrap_or(crate::av::ArtifactKind::Summary);
    let content_ref = body["content_ref"].as_str().ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "content_ref required".to_string(),
    ))?;
    let content_type = body["content_type"].as_str().unwrap_or("text/plain");
    let visibility_str = body["visibility"].as_str().unwrap_or("participants");
    let visibility: crate::av::ArtifactVisibility =
        serde_json::from_str(&format!("\"{visibility_str}\""))
            .unwrap_or(crate::av::ArtifactVisibility::Participants);
    let title = body["title"].as_str();
    // Attribution comes from the authenticated caller, never from the body:
    // a provenance record whose author is self-asserted is worthless.
    let created_by = Some(caller.as_str());

    let artifact = crate::av::AvArtifact {
        id: ulid::Ulid::new().to_string(),
        session_id: id.clone(),
        kind,
        created_at: chrono::Utc::now().timestamp(),
        created_by: created_by.map(|s| s.to_string()),
        content_ref: content_ref.to_string(),
        content_type: content_type.to_string(),
        visibility,
        title: title.map(|s| s.to_string()),
    };

    state.with_db(|db| db.save_av_artifact(&artifact));

    // If session is bound to a channel, post a notice about the new artifact
    let channel = {
        let mgr = state.av_sessions.lock();
        mgr.get(&id).and_then(|s| s.channel.clone())
    };
    if let Some(channel) = channel {
        let kind_label = kind_str;
        let title_display = title.unwrap_or(kind_label);
        crate::connection::messaging::broadcast_av_notice(
            &state,
            &channel,
            &format!("Session artifact available: {title_display} ({kind_label})"),
        );
    }

    Ok(Json(serde_json::json!({
        "id": artifact.id,
        "session_id": artifact.session_id,
        "kind": artifact.kind,
        "created_at": artifact.created_at,
    })))
}

/// GET /api/v1/channels/{name}/sessions — sessions in a channel (active + recent).
async fn api_channel_sessions(
    State(state): State<Arc<SharedState>>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Who is (or was) in a private channel's calls is itself sensitive.
    // Use the *normalized* channel the guard returns: sessions are stored under
    // the `#`-prefixed name, so looking up the raw path segment found nothing
    // and this endpoint reported "no calls" for every channel unless the caller
    // happened to URL-encode the `#`.
    let channel = authorize_channel_read(&state, &name, &headers)?;
    let mgr = state.av_sessions.lock();

    // Active session (if any)
    let active = mgr
        .active_session_for_channel(&channel)
        .map(|s| session_to_json(s, &mgr));

    // Recent ended sessions from DB
    let recent = state
        .with_db(|db| db.list_channel_av_sessions(&channel, 20))
        .unwrap_or_default();
    let recent_json: Vec<serde_json::Value> = recent
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "created_by": s.created_by,
                "created_at": s.created_at,
                "state": s.state,
                "title": s.title,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "active": active,
        "recent": recent_json,
    })))
}

fn session_to_json(
    s: &crate::av::AvSession,
    mgr: &crate::av::AvSessionManager,
) -> serde_json::Value {
    let participants: Vec<serde_json::Value> = s
        .participants
        .values()
        .filter(|p| p.left_at.is_none())
        .map(|p| {
            serde_json::json!({
                "did": p.did,
                "nick": p.nick,
                "role": p.role,
                "joined_at": p.joined_at,
                // Per-device suffix; required by the web client to build the
                // MoQ broadcast path `{session_id}/{nick}~{instance_id}` so
                // two devices on one DID get distinct watch subscriptions.
                "instance_id": p.instance_id,
            })
        })
        .collect();
    serde_json::json!({
        "id": s.id,
        "channel": s.channel,
        "created_by": s.created_by,
        "created_by_nick": s.created_by_nick,
        "created_at": s.created_at,
        "state": s.state,
        "title": s.title,
        "participants": participants,
        "participant_count": mgr.active_participant_count(&s.id),
        "media_backend": s.media_backend,
        "recording_enabled": s.recording_enabled,
        "iroh_ticket": s.iroh_ticket,
    })
}

#[cfg(test)]
mod export_tests {
    use super::format_export_markdown;
    use std::collections::HashMap;

    fn row(sender: &str, text: &str, ts: u64, msgid: &str) -> crate::db::MessageRow {
        crate::db::MessageRow {
            id: 1,
            channel: "#x".into(),
            sender: sender.into(),
            text: text.into(),
            timestamp: ts,
            tags: HashMap::new(),
            msgid: Some(msgid.into()),
            replaces_msgid: None,
            root_msgid: Some(msgid.into()),
            deleted_at: None,
            sender_did: None,
        }
    }

    #[test]
    fn markdown_export_renders_transcript() {
        let rows = vec![
            row("alice!a@h", "hello world", 1750000000, "01A"),
            row("bob!b@h", "line one\nline two", 1750000060, "01B"),
        ];
        let md = format_export_markdown("#dev", &rows);
        assert!(md.starts_with("# #dev — exported transcript\n"));
        assert!(md.contains("**alice** (01A): hello world\n"));
        // Hostmask stripped to nick; multiline bodies indented, not split
        // into separate top-level entries.
        assert!(md.contains("**bob** (01B): line one\n    line two\n"));
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::format_metrics;

    #[test]
    fn exposition_format_is_well_formed() {
        let out = format_metrics(3, 7, 2, 100, 5, 1, 9, 42);
        assert!(out.contains("freeq_connections 3\n"));
        assert!(out.contains("freeq_channels 7\n"));
        assert!(out.contains("freeq_s2s_peers 2\n"));
        assert!(out.contains("freeq_messages_total 100\n"));
        assert!(out.contains("freeq_sasl_success_total 5\n"));
        assert!(out.contains("freeq_sasl_failure_total 1\n"));
        assert!(out.contains("freeq_act_events_total 9\n"));
        assert!(out.contains("freeq_uptime_seconds 42\n"));
        // Every metric line is preceded by HELP + TYPE comments.
        for name in [
            "freeq_connections",
            "freeq_channels",
            "freeq_s2s_peers",
            "freeq_messages_total",
            "freeq_sasl_success_total",
            "freeq_sasl_failure_total",
            "freeq_act_events_total",
            "freeq_uptime_seconds",
        ] {
            assert!(
                out.contains(&format!("# HELP {name} ")),
                "missing HELP for {name}"
            );
            assert!(
                out.contains(&format!("# TYPE {name} ")),
                "missing TYPE for {name}"
            );
        }
        assert!(out.ends_with('\n'));
    }
}

#[cfg(test)]
mod orphan_view_tests {
    //! What the view says about a remote task on a server with federation
    //! switched off — the case where there is no link to the task's home and
    //! no prospect of one.

    use super::homes_out_of_contact;
    use crate::act_relay::reads_orphaned;
    use crate::server::SharedState;
    use std::sync::Arc;

    /// A peer server's endpoint id, as a foreign task's origin holds it.
    const HOME: &str = "44f1415cdeadbeef";

    /// A server with no S2S manager — `test_state_with_config` never starts
    /// one, which is exactly the shape being tested.
    fn state(act_orphan_secs: u64) -> Arc<SharedState> {
        crate::server::test_state_with_config(crate::config::ServerConfig {
            act_orphan_secs,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn a_remote_task_reads_orphaned_when_federation_is_off() {
        let state = state(86_400);
        let gone = homes_out_of_contact(&state, ["", HOME].into_iter()).await;
        assert!(
            gone.contains(HOME),
            "a server that cannot reach any peer is out of contact with this task's home"
        );
        assert!(
            reads_orphaned(HOME, "handoff", "open", gone.contains(HOME)),
            "so the work it left behind must not read as fresh"
        );
    }

    #[tokio::test]
    async fn our_own_task_is_untouched_by_federation_being_off() {
        let state = state(86_400);
        let gone = homes_out_of_contact(&state, [""].into_iter()).await;
        assert!(
            gone.is_empty(),
            "an empty origin is our own task — we are its home"
        );
        assert!(!reads_orphaned("", "handoff", "open", false));
    }

    #[tokio::test]
    async fn the_threshold_at_zero_still_turns_the_annotation_off() {
        let state = state(0);
        let gone = homes_out_of_contact(&state, [HOME].into_iter()).await;
        assert!(
            gone.is_empty(),
            "zero is the operator switching the annotation off, federation or no federation"
        );
    }
}

#[cfg(test)]
mod signing_key_endpoint_tests {
    use super::{api_did_signing_key, api_did_signing_key_by_kid};
    use crate::server::test_state_with_db;
    use axum::extract::{Path, State};
    use base64::Engine;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// The `/api/v1/signing-keys/{did}` and `/{did}/{kid}` endpoints serve the
    /// durable key store: `/{did}` returns the latest, `/{did}/{kid}` returns a
    /// specific historical key, and misses are 404. Drives the real handlers.
    #[tokio::test]
    async fn endpoints_serve_the_durable_store() {
        let state = test_state_with_db();
        let did = "did:plc:endpoint";
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        let kid1 = freeq_sdk::act::derive_kid_bytes(&k1);
        let kid2 = freeq_sdk::act::derive_kid_bytes(&k2);
        state
            .with_db(|db| {
                db.save_signing_key(did, &k1)?;
                db.save_signing_key(did, &k2)?;
                Ok(())
            })
            .expect("db present");

        // /{did} → latest (k2), from the key store.
        let latest = api_did_signing_key(State(state.clone()), Path(did.to_string()))
            .await
            .expect("200");
        assert_eq!(latest.0["public_key"], b64(&k2));
        assert_eq!(latest.0["source"], "key-store");

        // /{did}/{kid} → each specific historical key.
        let by1 =
            api_did_signing_key_by_kid(State(state.clone()), Path((did.to_string(), kid1.clone())))
                .await
                .expect("200 kid1");
        assert_eq!(by1.0["public_key"], b64(&k1));
        assert_eq!(by1.0["kid"], kid1);

        let by2 = api_did_signing_key_by_kid(State(state.clone()), Path((did.to_string(), kid2)))
            .await
            .expect("200 kid2");
        assert_eq!(by2.0["public_key"], b64(&k2));

        // Unknown kid → 404.
        let miss_kid = api_did_signing_key_by_kid(
            State(state.clone()),
            Path((did.to_string(), "nope".to_string())),
        )
        .await;
        assert_eq!(miss_kid.unwrap_err(), axum::http::StatusCode::NOT_FOUND);

        // Unknown DID → 404.
        let miss_did = api_did_signing_key(State(state), Path("did:plc:nobody".to_string())).await;
        assert_eq!(miss_did.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
mod signature_verdict_tests {
    use super::classify_message_signature;
    use crate::server::test_state_with_db;
    use crate::web::api_verify_message;
    use ed25519_dalek::SigningKey;
    use freeq_sdk::chatsig::ChatDoc;

    const DID: &str = "did:plc:verdict";
    const MSGID: &str = "01KYVT5Z8Q0000000000000000";

    fn doc() -> ChatDoc<'static> {
        ChatDoc::message(DID, MSGID, "#freeq", "the original text")
    }

    /// A device signature over the document verifies, and is reported as the
    /// sender's own — the only outcome that carries non-repudiation.
    #[test]
    fn a_device_signature_over_the_document_is_valid() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        state
            .with_db(|db| db.save_signing_key(DID, key.verifying_key().as_bytes()))
            .expect("test state has a database");

        let canonical = doc().canonical();
        let sig = doc().sign(&key);
        let (verdict, by, client_key) =
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(&sig));
        assert_eq!((verdict, by), ("valid", "client-session-key"));
        assert!(client_key.is_some(), "the key that verified is reported");
    }

    /// The server's own fallback signature verifies too, and is labelled as
    /// what it is: this server vouching, not the sender's device.
    #[test]
    fn a_server_signature_is_valid_but_labelled_as_the_servers() {
        let state = test_state_with_db();
        let canonical = doc().canonical();
        let sig = doc().sign(&state.msg_signing_key);
        let (verdict, by, client_key) =
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(&sig));
        assert_eq!((verdict, by), ("valid", "server-key"));
        assert_eq!(client_key, None);
    }

    /// Altered text is the one case that is a verdict about the bytes.
    #[test]
    fn altered_text_is_invalid_not_unverifiable() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        state
            .with_db(|db| db.save_signing_key(DID, key.verifying_key().as_bytes()))
            .expect("test state has a database");

        let sig = doc().sign(&key);
        let tampered = ChatDoc::message(DID, MSGID, "#freeq", "the edited text").canonical();
        let (verdict, by, _) =
            classify_message_signature(&state, Some(DID), Some(&tampered), Some(&sig));
        assert_eq!((verdict, by), ("invalid", "client-session-key"));
    }

    /// Re-venuing is caught for exactly the same reason: the venue is inside
    /// the document, so presenting a private line as public breaks the sig.
    #[test]
    fn a_re_venued_message_is_invalid() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        state
            .with_db(|db| db.save_signing_key(DID, key.verifying_key().as_bytes()))
            .expect("test state has a database");

        let sig = ChatDoc::message(DID, MSGID, "#private-team", "the number is 12").sign(&key);
        let elsewhere = ChatDoc::message(DID, MSGID, "#public", "the number is 12").canonical();
        let (verdict, _, _) =
            classify_message_signature(&state, Some(DID), Some(&elsewhere), Some(&sig));
        assert_eq!(verdict, "invalid");
    }

    /// A message that arrived from another server, read back through the real
    /// endpoint. The verdict is this server's own — its key store, its
    /// document rebuild — and says the sender's device signed it.
    #[tokio::test]
    async fn a_federated_message_verifies_from_our_own_key_store() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let did = "did:plc:federatedsender";
        let msgid = "01KYVT5Z8Q0000000000FEDER8";
        state
            .with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))
            .expect("test state has a database");

        // Stored the way the S2S receive path stores one: the origin's
        // channel spelling, the sender DID the origin stamped, and the
        // client's own signature relayed unchanged.
        let sig = ChatDoc::message(
            did,
            msgid,
            &freeq_sdk::chatsig::channel_venue("#Federated"),
            "across the hop",
        )
        .sign(&key);
        let tags = std::collections::HashMap::from([
            (freeq_sdk::sigtag::SIG_TAG.to_string(), sig),
            ("+freeq.at/origin".to_string(), "other-server".to_string()),
        ]);
        state
            .with_db(|db| {
                db.insert_message(
                    "#Federated",
                    "remote!u@s2s",
                    "across the hop",
                    0,
                    &tags,
                    Some(msgid),
                    Some(did),
                )
            })
            .expect("test state has a database");

        let out = api_verify_message(
            axum::extract::State(state),
            axum::extract::Path(msgid.to_string()),
        )
        .await
        .expect("the message is on file");
        assert_eq!(out.0["verification"]["verdict"], "valid");
        assert_eq!(out.0["verification"]["verified_by"], "client-session-key");
        assert_eq!(out.0["sender_did"], did);
    }

    /// The classifier resolves the key the signature's `kid` names, never the
    /// identity's newest. The third of the three chat paths that must agree
    /// on this (the other two are pinned in `server.rs`): a reader coming back
    /// to old history after the signer reconnected must still get a verdict
    /// about the message, not about which key is current.
    #[test]
    fn the_classifier_resolves_a_key_by_kid_not_by_latest() {
        let state = test_state_with_db();
        let old = SigningKey::from_bytes(&[21u8; 32]);
        let newer = SigningKey::from_bytes(&[22u8; 32]);
        for key in [&old, &newer] {
            state
                .with_db(|db| db.save_signing_key(DID, key.verifying_key().as_bytes()))
                .expect("test state has a database");
        }

        let canonical = doc().canonical();
        let sig = doc().sign(&old);
        let (verdict, by, _) =
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(&sig));
        assert_eq!(
            (verdict, by),
            ("valid", "client-session-key"),
            "a signature from a retired key must still verify"
        );
    }

    /// A row that names no sender is answered as one, not guessed at. The
    /// endpoint used to fall back to whoever holds the sender's nick on this
    /// server, which rebuilt a document around a DID the signer never signed
    /// — and then reported the mismatch as a verdict about the message.
    #[tokio::test]
    async fn a_row_with_no_sender_did_is_unverifiable_not_attributed_by_nick() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let local = "did:plc:holdsthenick";
        let msgid = "01KYVT5Z8Q00000000NONAME00";
        state
            .with_db(|db| db.save_signing_key(local, key.verifying_key().as_bytes()))
            .expect("test state has a database");
        // The nick belongs to a local identity here…
        state
            .nick_owners
            .lock()
            .insert("stranger".to_string(), local.to_string());

        // …but the row names no sender, and carries a signature by whoever
        // did write it. Nothing here can say who that was.
        let sig = ChatDoc::message(
            local,
            msgid,
            &freeq_sdk::chatsig::channel_venue("#nameless"),
            "who wrote this",
        )
        .sign(&key);
        let tags = std::collections::HashMap::from([(freeq_sdk::sigtag::SIG_TAG.to_string(), sig)]);
        state
            .with_db(|db| {
                db.insert_message(
                    "#nameless",
                    "stranger!u@s2s",
                    "who wrote this",
                    0,
                    &tags,
                    Some(msgid),
                    None,
                )
            })
            .expect("test state has a database");

        let out = api_verify_message(
            axum::extract::State(state),
            axum::extract::Path(msgid.to_string()),
        )
        .await
        .expect("the message is on file");
        assert_eq!(out.0["verification"]["verdict"], "unverifiable");
        assert_eq!(
            out.0["verification"]["verified_by"], "unverifiable-unknown-sender",
            "a nick is not an identity, and the endpoint must say so rather \
             than answer with whoever holds it: {:?}",
            out.0["verification"]
        );
    }

    /// A federated *edit*: the linkage it signs lives in the row's
    /// `replaces_msgid` column, because the relayed tag map is filtered to
    /// `+freeq.at/*` and `+draft/edit` never crosses. Reading only the tag
    /// rebuilt a four-key document and called an honest edit forged.
    #[tokio::test]
    async fn a_federated_edit_verifies_from_the_row_it_revises() {
        let state = test_state_with_db();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let did = "did:plc:federatededitor";
        let root = "01KYVT5Z8Q0000000000ROOT01";
        let edit_msgid = "01KYVT5Z8Q0000000000EDIT01";
        state
            .with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))
            .expect("test state has a database");

        let sig = ChatDoc::message(
            did,
            edit_msgid,
            &freeq_sdk::chatsig::channel_venue("#edits"),
            "revised across the hop",
        )
        .with_edit(root)
        .sign(&key);
        // Exactly the tag set the S2S receive path files: no `+draft/edit`.
        let tags = std::collections::HashMap::from([
            (freeq_sdk::sigtag::SIG_TAG.to_string(), sig),
            ("+freeq.at/origin".to_string(), "other-server".to_string()),
        ]);
        state
            .with_db(|db| {
                db.insert_edit(
                    "#edits",
                    "remote!u@s2s",
                    "revised across the hop",
                    0,
                    &tags,
                    edit_msgid,
                    root,
                    Some(did),
                )
            })
            .expect("test state has a database");

        let out = api_verify_message(
            axum::extract::State(state),
            axum::extract::Path(edit_msgid.to_string()),
        )
        .await
        .expect("the edit is on file");
        assert_eq!(
            out.0["verification"]["verdict"], "valid",
            "an edit's covered reference must come from the row when the tag is \
             absent: {}",
            out.0
        );
        assert_eq!(out.0["verification"]["verified_by"], "client-session-key");
    }

    /// Reading a message signed by someone we hold no key for asks a peer for
    /// it. The read itself still answers honestly — uncheckable, not forged —
    /// because a lookup is never waited on.
    #[tokio::test]
    async fn reading_an_unknown_signers_message_asks_a_peer_for_the_key() {
        let did = "did:plc:readerlookup";
        let msgid = "01KYVT5Z8Q00000000000READ1";
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());

        let state = crate::server::test_state_with_config(crate::config::ServerConfig {
            s2s_peer_api: vec!["peer=http://127.0.0.1:1".to_string()],
            ..Default::default()
        });
        let sig = ChatDoc::message(did, msgid, "#unknownkey", "who signed this").sign(&key);
        state
            .with_db(|db| {
                db.insert_message(
                    "#unknownkey",
                    "remote!u@s2s",
                    "who signed this",
                    0,
                    &std::collections::HashMap::from([(
                        freeq_sdk::sigtag::SIG_TAG.to_string(),
                        sig,
                    )]),
                    Some(msgid),
                    Some(did),
                )
            })
            .expect("test state has a database");

        let out = api_verify_message(
            axum::extract::State(state),
            axum::extract::Path(msgid.to_string()),
        )
        .await
        .expect("the message is on file");

        assert_eq!(
            out.0["verification"]["verified_by"], "unverifiable-unknown-key",
            "the read reports what is true now, not what a lookup might find"
        );
        assert!(
            crate::peer_keys::lookup_pending(did, &kid),
            "reading it must have asked a peer for the key"
        );
    }

    /// Everything we cannot check reads as unverifiable, each with its own
    /// reason — a legacy signature, an unknown key, an unknown sender, no
    /// signature at all. None of these may be reported as forgery.
    #[test]
    fn what_cannot_be_checked_is_unverifiable_with_a_reason() {
        let state = test_state_with_db();
        let canonical = doc().canonical();

        // Pre-cutover history: a bare base64 blob over the retired canonical.
        let legacy =
            "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZg";
        assert_eq!(
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(legacy)).0,
            "unverifiable"
        );
        assert_eq!(
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(legacy)).1,
            "unverifiable-legacy-format"
        );

        // A key we don't hold — the signer's session ended before we saw it.
        let stranger = SigningKey::from_bytes(&[11u8; 32]);
        let sig = doc().sign(&stranger);
        assert_eq!(
            classify_message_signature(&state, Some(DID), Some(&canonical), Some(&sig)),
            (
                "unverifiable",
                "unverifiable-unknown-key",
                None::<String>.clone()
            )
        );

        // No sender DID → no document to rebuild.
        assert_eq!(
            classify_message_signature(&state, None, None, Some(&sig)).1,
            "unverifiable-unknown-sender"
        );

        // And an unsigned message is not a failed one.
        assert_eq!(
            classify_message_signature(&state, Some(DID), Some(&canonical), None),
            ("unverifiable", "unsigned", None)
        );
    }

    /// A signer using an algorithm this build doesn't know is a newer client,
    /// not a forger.
    #[test]
    fn an_unknown_algorithm_is_unverifiable() {
        let state = test_state_with_db();
        let canonical = doc().canonical();
        let (verdict, by, _) = classify_message_signature(
            &state,
            Some(DID),
            Some(&canonical),
            Some("ml-dsa-44:somekid:c2ln"),
        );
        assert_eq!(verdict, "unverifiable");
        assert_eq!(by, "unverifiable-unknown-algorithm");
    }
}

#[cfg(test)]
mod audit_actor_name_tests {
    use crate::server::test_state_with_db;

    /// The audit timeline is read by people, so a row says who acted. A DID
    /// this server can resolve gets a name; one it cannot gets none at all.
    ///
    /// The second half is the trap worth pinning: `display_nick_for_did`
    /// answers with the DID itself when every source misses, so passing its
    /// result straight through would send a raw identifier as though it were
    /// a name — and a client showing `actor_name` verbatim would print it,
    /// which is worse than the compact form it would otherwise render.
    #[test]
    fn an_actor_is_named_only_when_the_name_is_really_a_name() {
        let state = test_state_with_db();
        state.bind_identity("did:key:zBOT", "taskbot");

        let known = state.display_nick_for_did("did:key:zBOT");
        assert_eq!(known, "taskbot");
        assert_ne!(known, "did:key:zBOT", "a resolved actor carries a name");

        // Never seen here: the resolver hands back what it was given, and the
        // audit row must send no name rather than that.
        let stranger = "did:key:zNEVERSEEN";
        assert_eq!(
            state.display_nick_for_did(stranger),
            stranger,
            "an unknown DID resolves to itself — the audit row must treat this as no name",
        );
    }
}

#[cfg(test)]
mod verify_catchall_tests {
    use axum::{Router, response::Html, routing::get};

    /// The /verify/{*unmounted} catchall must 503 unmounted verifier routes
    /// (so the SPA fallback can't silently swallow them) while leaving
    /// mounted verifier routes untouched. This also proves axum allows the
    /// wildcard to coexist with more-specific concrete routes.
    #[tokio::test]
    async fn catchall_503s_unmounted_but_mounted_routes_win() {
        let app = Router::new()
            .route(
                "/verify/{*unmounted}",
                get(super::unmounted_verifier).post(super::unmounted_verifier),
            )
            // Concrete verifier route, merged AFTER the wildcard exactly
            // like verifiers::router is merged into final_app.
            .merge(Router::new().route(
                "/verify/bluesky/start",
                get(|| async { Html("bluesky start page") }),
            ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();

        // Mounted verifier route wins over the wildcard.
        let resp = client
            .get(format!("http://{addr}/verify/bluesky/start?subject_did=x"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "bluesky start page");

        // Unmounted verifier route → loud 503 (was: 200 SPA index.html).
        let resp = client
            .get(format!("http://{addr}/verify/github/start?repo=foo/bar"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        let body = resp.text().await.unwrap();
        assert!(body.contains("not configured"), "got: {body}");
        assert!(body.contains("github"), "names the provider: {body}");

        // Unknown provider names are sanitized before being echoed.
        let resp = client
            .get(format!("http://{addr}/verify/%3Cscript%3E/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        assert!(!resp.text().await.unwrap().contains("<script"));
    }
}
