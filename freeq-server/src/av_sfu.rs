//! AV SFU (Selective Forwarding Unit).
//!
//! Accepts MoQ connections via:
//! - QUIC/WebTransport (direct UDP, for native clients or when ports are exposed)
//! - WebSocket (through the HTTP server, works through any reverse proxy)
//!
//! Uses moq_relay::Cluster to route audio streams between all participants.

#[cfg(feature = "av-native")]
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

// Per-session announcement scoping (S2) — the server half is IMPLEMENTED
// below (`moq_scope_path`, honored by both transport handlers). It's
// backward-compatible: `/av/moq` still roots at "" (global) for today's
// clients. The client half (dial `/av/moq/s/{session}` + publish relative)
// is dormant behind `SCOPED_SESSIONS` in freeq-sdk-ffi; flip native+web+iOS
// together AFTER this server is deployed. Until then the native FFI's
// client-side `belongs_to_session` filter is the interim leak mitigation
// (patched clients only; iOS/old builds still leak until the flip).

/// Extract the MoQ auth ROOT path shared by BOTH transports from a dialed
/// URL path. This is the session-scoping mechanism (S2):
///
/// - Today's clients dial `/av/moq` → `""` → the token roots at the cluster
///   root → all broadcasts announced to all subscribers (backward compatible).
/// - Scoped clients dial `/av/moq/s/{session}` → `"s/{session}"` → the relay
///   only announces broadcasts under that session, so a client in call A can
///   no longer subscribe to (and play) call B's media — enforced server-side
///   for EVERY client regardless of version, closing the 2026-07-03 leak.
///
/// Both transports MUST normalize identically or they root at different paths
/// and become mutually invisible (the earlier native/web disjoint-namespace
/// bug). WS gets the suffix from the axum `{*path}` capture; QUIC gets the
/// full URL path, so this strips the `/av/moq` mount prefix to match.
///
/// Not feature-gated (pure string logic, no AV deps) so it stays unit-testable
/// under default features.
pub fn moq_scope_path(url_path: &str) -> String {
    let trimmed = url_path.trim_start_matches('/');
    trimmed
        .strip_prefix("av/moq")
        .unwrap_or(trimmed)
        .trim_matches('/')
        .to_string()
}

/// Default lifetime of a minted session token. Long enough to cover any
/// realistic call (tokens are only checked at connect/redial time), short
/// enough that a leaked token goes stale within a day.
#[cfg(feature = "av-native")]
pub const AV_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;

/// Shared SFU state, accessible from the web server for WebSocket MoQ connections.
#[cfg(feature = "av-native")]
pub struct SfuState {
    pub cluster: moq_relay::Cluster,
    pub auth: moq_relay::Auth,
    pub conn_id: AtomicU64,
    /// HS256 key used to mint per-session MoQ access tokens (None if key
    /// setup failed — the SFU then runs open, as before tokens existed).
    pub token_key: Option<Arc<moq_token::Key>>,
    /// When true (FREEQ_AV_REQUIRE_TOKEN=1), connections without a valid
    /// `?jwt=` token are rejected. When false the SFU stays open for
    /// legacy clients while tokens are minted, delivered, and honored.
    pub require_token: bool,

    /// Media-connection revocation registry: AV instance id → notify handle
    /// shared by every live media connection that declared that instance
    /// (`?inst=` on the dial URL). When the roster tears an instance down
    /// (grace expiry, orphan reap, session end) the server closes its media
    /// connections too — without this, a participant whose IRC died kept
    /// streaming into the call: announcement-driven clients (native) heard a
    /// roster-ghost forever while roster-driven clients (web) didn't, i.e.
    /// class-C asymmetry (see docs/AV-SESSION-AUDIT.md F6). Cooperative
    /// attribution (self-declared) — malicious clients are the token flag's
    /// concern, not this registry's.
    pub media_conns:
        parking_lot::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
}

#[cfg(feature = "av-native")]
impl SfuState {
    /// Register a live media connection for an AV instance. The returned
    /// notify fires if the server revokes the instance's media (roster
    /// teardown); the connection handler selects on it and closes the socket.
    pub fn register_media_conn(&self, instance: &str) -> Arc<tokio::sync::Notify> {
        self.media_conns
            .lock()
            .entry(instance.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone()
    }

    /// Drop a connection's registration after it closes naturally. Removes
    /// the map entry once no other live connection shares it (strong count 2
    /// = the map's Arc + the caller's) so the registry can't grow unbounded.
    pub fn unregister_media_conn(&self, instance: &str, handle: &Arc<tokio::sync::Notify>) {
        let mut conns = self.media_conns.lock();
        if let Some(n) = conns.get(instance)
            && Arc::ptr_eq(n, handle)
            && Arc::strong_count(n) <= 2
        {
            conns.remove(instance);
        }
    }

    /// Close every media connection that declared this AV instance. Called
    /// when the roster tears the instance down, so media membership can
    /// never outlive roster membership (audit F6).
    pub fn revoke_media(&self, instance: &str) {
        if instance.is_empty() {
            return;
        }
        if let Some(n) = self.media_conns.lock().remove(instance) {
            tracing::info!(instance = %instance, "AV: revoking media connection(s) for torn-down roster slot");
            n.notify_waiters();
        }
    }

    /// Every broadcast path the relay is currently announcing under
    /// `{prefix}` — i.e. exactly what an announcement-driven client (macOS,
    /// iOS, bots) would subscribe to right now.
    ///
    /// This is the other half of the class-A picture. The roster answers "who
    /// does the server think is in the call"; this answers "who is actually on
    /// the wire". When they disagree, roster-driven clients (web) silently
    /// lose whoever the roster misdescribes while announcement-driven clients
    /// keep hearing them — the asymmetric split that took three production
    /// incidents to name (see docs/AV-SESSION-AUDIT.md §1).
    ///
    /// Snapshot semantics: a fresh consumer is announced every live broadcast
    /// at subscribe time (`consume_initial`), so draining its non-blocking
    /// queue yields the current set and nothing else. Closed broadcasts have
    /// already been removed from the origin tree, so they can't show up here.
    /// We read `primary` (what local clients publish) rather than `combined`
    /// because combined is fed by an async shovel task and lags by a tick.
    pub fn announced_paths(&self, prefix: &str) -> Vec<String> {
        let mut consumer = self.cluster.primary.consume();
        let mut live = std::collections::BTreeSet::new();
        while let Some((path, broadcast)) = consumer.try_announced() {
            let path = path.to_string();
            if broadcast.is_some() {
                live.insert(path);
            } else {
                live.remove(&path);
            }
        }
        live.into_iter().filter(|p| p.starts_with(prefix)).collect()
    }

    /// Mint a session-scoped MoQ JWT. The claims grant publish+subscribe
    /// under BOTH namespaces a client may root at — `{sid}/…` (legacy
    /// clients dialing `/av/moq` with absolute broadcast paths) and
    /// `s/{sid}/…` (S2 scoped clients dialing `/av/moq/s/{sid}` with
    /// relative paths) — and nothing else. A token for call A can never
    /// reach call B's media, closing the guessable-broadcast-name hole.
    pub fn mint_session_token(&self, session_id: &str) -> Option<String> {
        let key = self.token_key.as_ref()?;
        let now = std::time::SystemTime::now();
        let claims = moq_token::Claims {
            root: String::new(),
            publish: vec![session_id.to_string(), format!("s/{session_id}")],
            subscribe: vec![session_id.to_string(), format!("s/{session_id}")],
            cluster: false,
            expires: Some(now + std::time::Duration::from_secs(AV_TOKEN_TTL_SECS)),
            issued: Some(now),
        };
        match key.encode(&claims) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(session = %session_id, "failed to mint AV token: {e}");
                None
            }
        }
    }
}

/// Load the SFU token-minting key from `{data_dir}/av-token-key.secret`,
/// generating (and persisting with 0600) a fresh HS256 key on first run.
#[cfg(feature = "av-native")]
fn load_or_generate_token_key(path: &std::path::Path) -> anyhow::Result<moq_token::Key> {
    if path.exists() {
        crate::secrets::tighten_permissions(path);
        match moq_token::Key::from_file(path) {
            Ok(k) => return Ok(k),
            Err(e) => tracing::warn!(
                path = %path.display(),
                "Corrupt AV token key, regenerating: {e}"
            ),
        }
    }
    let key = moq_token::Key::generate(moq_token::Algorithm::HS256, None)?;
    // Same base64url(JSON) format Key::to_file writes, but through
    // secrets::write_secret so the file lands with 0600.
    let json = key.to_str()?;
    let encoded = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    };
    crate::secrets::write_secret(path, encoded.as_bytes())?;
    tracing::info!(path = %path.display(), "Generated AV SFU token key");
    Ok(key)
}

/// Initialize the SFU cluster and return shared state.
/// Also spawns the QUIC accept loop if a port is provided.
#[cfg(feature = "av-native")]
pub async fn init_sfu(quic_port: Option<u16>, data_dir: &str) -> anyhow::Result<Arc<SfuState>> {
    use moq_relay::{Auth, AuthConfig, Cluster, ClusterConfig};

    // QUIC server config (also used for cluster's internal client)
    let mut client_config = moq_native::ClientConfig::default();
    client_config.max_streams = Some(moq_relay::DEFAULT_MAX_STREAMS);
    let client = client_config.init()?;

    // Token key: minted per session, delivered to participants over IRC
    // (`+freeq.at/av-token` TAGMSG) and REST, verified by the relay via
    // the `?jwt=` query param on both QUIC and WebSocket transports.
    let key_path = std::path::Path::new(data_dir).join("av-token-key.secret");
    let token_key = match load_or_generate_token_key(&key_path) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            tracing::error!("AV token key setup failed (SFU stays open): {e}");
            None
        }
    };

    let require_token = std::env::var("FREEQ_AV_REQUIRE_TOKEN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut auth_config = AuthConfig::default();
    if token_key.is_some() {
        auth_config.key = Some(key_path.to_string_lossy().into_owned());
    }
    if require_token && token_key.is_some() {
        // Enforcing: every connection must present a valid session token.
        auth_config.public = None;
        tracing::info!("AV SFU auth: session tokens REQUIRED (FREEQ_AV_REQUIRE_TOKEN)");
    } else {
        // Migration mode: tokenless (legacy) clients still connect at the
        // public root; token-bearing clients get scoped claims. Flip
        // FREEQ_AV_REQUIRE_TOKEN=1 once all clients send tokens.
        auth_config.public = Some("/".to_string());
        tracing::warn!(
            "AV SFU auth: OPEN (legacy clients allowed). Tokens are minted and \
             verified; set FREEQ_AV_REQUIRE_TOKEN=1 to enforce once clients are updated."
        );
    }
    let auth = Auth::new(auth_config).await?;

    let cluster = Cluster::new(ClusterConfig::default(), client);
    let cluster_run = cluster.clone();
    tokio::spawn(async move {
        if let Err(e) = cluster_run.run().await {
            tracing::error!("SFU cluster failed: {e}");
        }
    });

    let state = Arc::new(SfuState {
        cluster,
        auth,
        conn_id: AtomicU64::new(0),
        token_key,
        require_token,
        media_conns: parking_lot::Mutex::new(std::collections::HashMap::new()),
    });

    // Optionally start QUIC accept loop (for direct connections bypassing HTTP proxy)
    if let Some(port) = quic_port {
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_quic_accept(port, state2).await {
                // QUIC is optional — WebSocket MoQ still works without it
                tracing::warn!("SFU QUIC listener failed (WebSocket still active): {e}");
            }
        });
    }

    tracing::info!("AV SFU initialized (WebSocket enabled)");
    Ok(state)
}

#[cfg(feature = "av-native")]
async fn run_quic_accept(port: u16, state: Arc<SfuState>) -> anyhow::Result<()> {
    let mut server_config = moq_native::ServerConfig::default();
    server_config.bind = Some(format!("[::]:{port}").parse()?);
    server_config.backend = Some(moq_native::QuicBackend::Noq);
    server_config.max_streams = Some(moq_relay::DEFAULT_MAX_STREAMS);

    // QUIC/WebTransport TLS. With a publicly-trusted cert (FREEQ_AV_TLS_CERT
    // / FREEQ_AV_TLS_KEY) browsers can WebTransport straight to this
    // listener — the proper low-latency media transport. Without it we
    // fall back to a self-signed cert, which only native clients (cert
    // verification disabled) can use; browsers are stuck on the staticky
    // MoQ-over-WebSocket path. See docs/AV-QUIC-MIGRATION.md.
    match (
        std::env::var("FREEQ_AV_TLS_CERT"),
        std::env::var("FREEQ_AV_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => {
            tracing::info!(%cert, %key, "AV SFU QUIC: using configured TLS cert");
            server_config.tls.cert = vec![cert.into()];
            server_config.tls.key = vec![key.into()];
        }
        _ => {
            tracing::warn!(
                "AV SFU QUIC: FREEQ_AV_TLS_CERT/KEY unset — self-signed cert \
                 (native clients only; browsers cannot WebTransport)"
            );
            server_config.tls.generate = vec!["localhost".to_string()];
        }
    }

    let mut server = server_config.init()?;
    tracing::info!("AV SFU QUIC on :{port} (WebTransport + MoQ)");

    while let Some(request) = server.accept().await {
        let id = state.conn_id.fetch_add(1, Ordering::Relaxed);
        let cluster = state.cluster.clone();
        let auth = state.auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic_connection(id, request, cluster, auth).await {
                tracing::debug!(conn = id, "SFU QUIC session ended: {e}");
            }
        });
    }

    Ok(())
}

#[cfg(feature = "av-native")]
async fn handle_quic_connection(
    id: u64,
    request: moq_native::Request,
    cluster: moq_relay::Cluster,
    auth: moq_relay::Auth,
) -> anyhow::Result<()> {
    use moq_relay::AuthParams;

    let transport = request.transport();
    // Root the connection at the SESSION-SCOPE path derived from the dialed
    // URL, normalized the SAME way the WebSocket entry point normalizes its
    // `{*path}` capture (`moq_scope_path`). Both transports must agree, or
    // native (QUIC) and web (WebSocket) clients root at different paths and
    // become mutually invisible — the disjoint-namespace bug. `/av/moq` →
    // "" (unchanged global behavior for today's clients); `/av/moq/s/{sess}`
    // → per-session isolation (S2). `AuthParams::from_url` still parses any
    // jwt/register query params.
    let params = match request.url() {
        Some(url) => {
            let mut p = AuthParams::from_url(url);
            p.path = moq_scope_path(url.path());
            p
        }
        None => AuthParams::default(),
    };

    let token = auth.verify(&params)?;
    let publish = cluster.publisher(&token);
    let subscribe = cluster.subscriber(&token);
    let _registration = cluster.register(&token);

    tracing::info!(conn = id, %transport, "SFU: client connected (QUIC)");

    let mut request = request;
    if let Some(p) = publish {
        request = request.with_consume(p);
    }
    if let Some(s) = subscribe {
        request = request.with_publish(s);
    }
    let session = request.ok().await?;

    tracing::info!(conn = id, "SFU: session active");
    let _ = session.closed().await;
    tracing::info!(conn = id, "SFU: session closed");

    Ok(())
}

/// Handle a WebSocket upgrade for MoQ — called from the web server's route handler.
/// `jwt` is the session token from the `?jwt=` query param, if the client sent one.
#[cfg(feature = "av-native")]
pub async fn handle_ws_moq(
    state: Arc<SfuState>,
    path: String,
    jwt: Option<String>,
    inst: Option<String>,
    socket: axum::extract::ws::WebSocket,
) {
    use futures::{SinkExt, StreamExt};

    let id = state.conn_id.fetch_add(1, Ordering::Relaxed);

    // Normalize the axum {*path} capture the same way the QUIC handler
    // normalizes its URL path, so both transports root identically.
    let params = moq_relay::AuthParams {
        path: moq_scope_path(&path),
        jwt,
        register: None,
    };

    let token = match state.auth.verify(&params) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(conn = id, "SFU WS auth failed: {e}");
            return;
        }
    };

    let publish = state.cluster.publisher(&token);
    let subscribe = state.cluster.subscriber(&token);
    let _registration = state.cluster.register(&token);

    // Convert axum WebSocket to tungstenite format for qmux
    let socket = socket
        .map(axum_to_tungstenite)
        .sink_map_err(|err| {
            tracing::warn!(%err, "WebSocket error");
            qmux::tungstenite::Error::ConnectionClosed
        })
        .with(tungstenite_to_axum);

    let ws = qmux::ws::accept(socket, None);
    // moq_lite::Server semantics (opposite of moq_native::Request):
    //   with_publish(subscribe) = send cluster's subscriber stream TO the client
    //   with_consume(publish) = consume client's stream and feed INTO cluster publisher
    let session = match moq_lite::Server::new()
        .with_publish(subscribe)
        .with_consume(publish)
        .accept(ws)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(conn = id, "SFU WS session setup failed: {e}");
            return;
        }
    };

    tracing::info!(conn = id, inst = ?inst, "SFU: client connected (WebSocket)");
    // Park until the client closes — or the server revokes this instance's
    // media because its roster slot was torn down (see `revoke_media`).
    match inst.as_deref().filter(|i| !i.is_empty()) {
        Some(instance) => {
            let notify = state.register_media_conn(instance);
            tokio::select! {
                _ = session.closed() => {}
                _ = notify.notified() => {
                    tracing::info!(conn = id, instance = %instance, "SFU: session revoked (roster teardown)");
                }
            }
            state.unregister_media_conn(instance, &notify);
        }
        None => {
            let _ = session.closed().await;
        }
    }
    tracing::info!(conn = id, "SFU: session closed (WebSocket)");
}

// ── WebSocket message conversion (axum ↔ tungstenite) ─────────────

#[cfg(feature = "av-native")]
#[allow(clippy::result_large_err)]
fn axum_to_tungstenite(
    message: Result<axum::extract::ws::Message, axum::Error>,
) -> Result<qmux::tungstenite::Message, qmux::tungstenite::Error> {
    use qmux::tungstenite;
    match message {
        Ok(msg) => Ok(match msg {
            axum::extract::ws::Message::Text(text) => {
                tungstenite::Message::Text(text.to_string().into())
            }
            axum::extract::ws::Message::Binary(bin) => {
                tungstenite::Message::Binary(Vec::from(bin).into())
            }
            axum::extract::ws::Message::Ping(ping) => {
                tungstenite::Message::Ping(Vec::from(ping).into())
            }
            axum::extract::ws::Message::Pong(pong) => {
                tungstenite::Message::Pong(Vec::from(pong).into())
            }
            axum::extract::ws::Message::Close(close) => {
                tungstenite::Message::Close(close.map(|c| tungstenite::protocol::CloseFrame {
                    code: c.code.into(),
                    reason: c.reason.to_string().into(),
                }))
            }
        }),
        Err(_err) => Err(qmux::tungstenite::Error::ConnectionClosed),
    }
}

#[cfg(feature = "av-native")]
#[allow(clippy::result_large_err)]
fn tungstenite_to_axum(
    message: qmux::tungstenite::Message,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<axum::extract::ws::Message, qmux::tungstenite::Error>,
            > + Send
            + Sync,
    >,
> {
    use qmux::tungstenite;
    Box::pin(async move {
        Ok(match message {
            tungstenite::Message::Text(text) => {
                axum::extract::ws::Message::Text(text.to_string().into())
            }
            tungstenite::Message::Binary(bin) => {
                axum::extract::ws::Message::Binary(Vec::from(bin).into())
            }
            tungstenite::Message::Ping(ping) => {
                axum::extract::ws::Message::Ping(Vec::from(ping).into())
            }
            tungstenite::Message::Pong(pong) => {
                axum::extract::ws::Message::Pong(Vec::from(pong).into())
            }
            tungstenite::Message::Frame(_) => unreachable!(),
            tungstenite::Message::Close(close) => {
                axum::extract::ws::Message::Close(close.map(|c| axum::extract::ws::CloseFrame {
                    code: c.code.into(),
                    reason: c.reason.to_string().into(),
                }))
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::moq_scope_path;

    #[test]
    fn unscoped_mount_is_global_root() {
        // Today's clients dial /av/moq → "" → cluster root (backward compat).
        assert_eq!(moq_scope_path("/av/moq"), "");
        assert_eq!(moq_scope_path("av/moq"), "");
        assert_eq!(moq_scope_path("/av/moq/"), "");
        assert_eq!(moq_scope_path(""), "");
        assert_eq!(moq_scope_path("/"), "");
    }

    #[test]
    fn scoped_mount_roots_at_session() {
        // Scoped clients dial /av/moq/s/{session} → isolated per session.
        assert_eq!(moq_scope_path("/av/moq/s/01KWSESSION"), "s/01KWSESSION");
        assert_eq!(moq_scope_path("av/moq/s/01KWSESSION"), "s/01KWSESSION");
        assert_eq!(moq_scope_path("/av/moq/s/01KWSESSION/"), "s/01KWSESSION");
    }

    #[test]
    fn ws_route_capture_is_idempotent() {
        // The WS handler passes the axum {*path} capture (already the suffix);
        // normalizing it again must not double-strip or corrupt it.
        assert_eq!(moq_scope_path("s/01KWSESSION"), "s/01KWSESSION");
        assert_eq!(moq_scope_path("s/01KWSESSION/"), "s/01KWSESSION");
        assert_eq!(moq_scope_path(""), "");
    }

    #[test]
    fn distinct_sessions_get_distinct_roots() {
        assert_ne!(
            moq_scope_path("/av/moq/s/aaa"),
            moq_scope_path("/av/moq/s/bbb")
        );
    }
}

/// Token mint/verify round-trips against the same `moq_relay::Auth` the
/// SFU runs — proving a session token opens exactly its own session (in
/// both legacy and scoped namespaces) and nothing else.
#[cfg(all(test, feature = "av-native"))]
mod token_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    async fn state_with_key(dir: &std::path::Path, require: bool) -> Arc<SfuState> {
        let key_path = dir.join("av-token-key.secret");
        let key = super::load_or_generate_token_key(&key_path).expect("key");

        let mut auth_config = moq_relay::AuthConfig::default();
        auth_config.key = Some(key_path.to_string_lossy().into_owned());
        auth_config.public = if require { None } else { Some("/".to_string()) };
        let auth = moq_relay::Auth::new(auth_config).await.expect("auth");

        let mut client_config = moq_native::ClientConfig::default();
        client_config.max_streams = Some(moq_relay::DEFAULT_MAX_STREAMS);
        let client = client_config.init().expect("client");
        let cluster = moq_relay::Cluster::new(moq_relay::ClusterConfig::default(), client);

        Arc::new(SfuState {
            cluster,
            auth,
            conn_id: AtomicU64::new(0),
            token_key: Some(Arc::new(key)),
            require_token: require,
            media_conns: parking_lot::Mutex::new(std::collections::HashMap::new()),
        })
    }

    #[tokio::test]
    async fn key_persists_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("av-token-key.secret");
        let k1 = super::load_or_generate_token_key(&key_path).unwrap();
        let k2 = super::load_or_generate_token_key(&key_path).unwrap();
        // A token minted before "restart" still verifies after.
        let claims = moq_token::Claims {
            publish: vec!["sid".into()],
            subscribe: vec!["sid".into()],
            ..Default::default()
        };
        let token = k1.encode(&claims).unwrap();
        assert!(k2.decode(&token).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token key must be 0600");
        }
    }

    #[tokio::test]
    async fn token_opens_own_session_both_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_key(dir.path(), true).await;
        let token = state.mint_session_token("01SESSION").expect("mint");

        // Legacy dial: /av/moq (root "") with absolute broadcast paths.
        let verified = state
            .auth
            .verify(&moq_relay::AuthParams {
                path: moq_scope_path("/av/moq"),
                jwt: Some(token.clone()),
                register: None,
            })
            .expect("legacy dial should verify");
        let can = |paths: &[moq_lite::PathOwned], p: &str| {
            use moq_lite::AsPath;
            paths.iter().any(|allowed| p.as_path().has_prefix(allowed))
        };
        assert!(can(&verified.publish, "01SESSION/alice~i1"));
        assert!(can(&verified.subscribe, "01SESSION/bob~i2"));
        assert!(!can(&verified.publish, "01OTHER/alice~i1"));
        assert!(!can(&verified.subscribe, "01OTHER/bob~i2"));

        // Scoped dial: /av/moq/s/{sid} with relative paths.
        let verified = state
            .auth
            .verify(&moq_relay::AuthParams {
                path: moq_scope_path("/av/moq/s/01SESSION"),
                jwt: Some(token.clone()),
                register: None,
            })
            .expect("scoped dial should verify");
        assert!(can(&verified.publish, "alice~i1"));
        assert!(can(&verified.subscribe, "bob~i2"));

        // Scoped dial into a DIFFERENT session: the connection is admitted
        // (root "" is a prefix of every path) but claim reduction strips
        // every publish/subscribe grant — zero access to that session's
        // media, which is the security property we need.
        let other = state
            .auth
            .verify(&moq_relay::AuthParams {
                path: moq_scope_path("/av/moq/s/01OTHER"),
                jwt: Some(token),
                register: None,
            })
            .expect("cross-session dial verifies but must carry no grants");
        assert!(
            other.publish.is_empty() && other.subscribe.is_empty(),
            "token for one session must grant nothing in another: {other:?}"
        );
    }

    #[tokio::test]
    async fn tokenless_rejected_when_required_allowed_when_open() {
        let dir = tempfile::tempdir().unwrap();

        let enforcing = state_with_key(dir.path(), true).await;
        assert!(
            enforcing
                .auth
                .verify(&moq_relay::AuthParams {
                    path: moq_scope_path("/av/moq"),
                    jwt: None,
                    register: None,
                })
                .is_err(),
            "tokenless connect must be rejected in enforcing mode"
        );

        let open = state_with_key(dir.path(), false).await;
        assert!(
            open.auth
                .verify(&moq_relay::AuthParams {
                    path: moq_scope_path("/av/moq"),
                    jwt: None,
                    register: None,
                })
                .is_ok(),
            "tokenless connect stays allowed in migration mode"
        );

        // Garbage token is rejected in BOTH modes (never falls back to public).
        assert!(
            open.auth
                .verify(&moq_relay::AuthParams {
                    path: moq_scope_path("/av/moq"),
                    jwt: Some("garbage".into()),
                    register: None,
                })
                .is_err(),
            "invalid token must not fall back to public access"
        );
    }
}
