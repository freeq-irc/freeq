//! Characterization tests for the standalone auth broker.
//!
//! These pin the broker's CURRENT behavior — it is the reference
//! implementation for the auth unification work. They must stay green,
//! unchanged, through every later refactor.
//!
//! `/auth/login`'s discovery+PAR chain resolves handles/DIDs against
//! hardcoded public hosts and is not reachable from a hermetic test;
//! its behavior gets characterized at the engine boundary (freeq-oauth tests).
//! Everything downstream of resolution (callback, session refresh,
//! graph delegation, push contract) is covered here against mock
//! upstreams.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use base64::Engine;
use freeq_auth_broker::{
    BrokerConfig, BrokerSessionRecord, BrokerState, DpopKey, PendingAuth, RemoteWriter,
    SqliteStore, build_client_id, decrypt_field, derive_encryption_key, encrypt_field,
    is_valid_return_to, router, sign_body,
};
use tokio::sync::Mutex;

const SECRET: &str = "test-shared-secret";

// ── Harness ────────────────────────────────────────────────────────────

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

fn broker_state(freeq_server_url: &str) -> Arc<BrokerState> {
    let store = Arc::new(SqliteStore::open(":memory:", derive_encryption_key(SECRET)).unwrap());
    Arc::new(BrokerState {
        config: BrokerConfig {
            public_url: "https://auth.test.example".to_string(),
            freeq_server_url: freeq_server_url.to_string(),
            shared_secret: SECRET.to_string(),
        },
        writer: Arc::new(RemoteWriter {
            freeq_server_url: freeq_server_url.to_string(),
            shared_secret: SECRET.to_string(),
        }),
        store,
        pending: Mutex::new(std::collections::HashMap::new()),
        completed: Mutex::new(std::collections::HashMap::new()),
        callback_locks: Mutex::new(std::collections::HashMap::new()),
        refresh_locks: Mutex::new(std::collections::HashMap::new()),
    })
}

/// reqwest client that does NOT follow redirects — we assert on Location.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// Decode the payload segment of a JWS (e.g. a DPoP proof).
fn jwt_payload(jwt: &str) -> serde_json::Value {
    serde_json::from_slice(&b64url_decode(jwt.split('.').nth(1).unwrap())).unwrap()
}

/// Decode the `#oauth=<base64url json>` fragment from a redirect Location.
fn fragment_payload(location: &str) -> serde_json::Value {
    let (_, frag) = location.split_once("#oauth=").unwrap();
    serde_json::from_slice(&b64url_decode(frag)).unwrap()
}

fn pending(token_endpoint: &str, pds_url: &str) -> PendingAuth {
    PendingAuth {
        handle: "alice.test".to_string(),
        did: "did:plc:alice123".to_string(),
        pds_url: pds_url.to_string(),
        code_verifier: "test-verifier".to_string(),
        redirect_uri: "https://auth.test.example/auth/callback".to_string(),
        client_id: "https://auth.test.example/client-metadata.json".to_string(),
        token_endpoint: token_endpoint.to_string(),
        dpop_key_b64: DpopKey::generate().to_base64url(),
        dpop_nonce: None,
        mobile: false,
        return_to: Some("https://irc.freeq.at".to_string()),
        popup: false,
    }
}

async fn seed_pending(state: &Arc<BrokerState>, oauth_state: &str, p: PendingAuth) {
    state
        .pending
        .lock()
        .await
        .insert(oauth_state.to_string(), p);
}

async fn seed_session(
    state: &Arc<BrokerState>,
    broker_token: &str,
    refresh_token: &str,
    token_endpoint: &str,
    pds_url: &str,
) {
    state
        .store
        .insert(&BrokerSessionRecord {
            broker_token: broker_token.to_string(),
            did: "did:plc:alice123".to_string(),
            handle: "alice.test".to_string(),
            pds_url: pds_url.to_string(),
            token_endpoint: token_endpoint.to_string(),
            refresh_token: refresh_token.to_string(),
            dpop_key_b64: DpopKey::generate().to_base64url(),
            dpop_nonce: None,
            client_id: "https://auth.test.example/client-metadata.json".to_string(),
            created_at: 0,
            updated_at: 0,
        })
        .await
        .unwrap();
}

// ── Mock freeq-server (broker push receiver) ───────────────────────────

#[derive(Default)]
struct ServerCapture {
    web_token_bodies: Vec<serde_json::Value>,
    session_bodies: Vec<serde_json::Value>,
    fail_web_token: bool,
}

/// Verify the broker's HMAC push signature exactly the way
/// freeq-server's `verify_broker_signature_raw` does. Returning false on
/// mismatch makes any signature drift fail the happy-path tests.
fn verify_push_signature(headers: &HeaderMap, body: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    let (Some(sig), Some(ts)) = (
        headers
            .get("x-broker-signature")
            .and_then(|v| v.to_str().ok()),
        headers
            .get("x-broker-timestamp")
            .and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let Ok(ts_num) = ts.parse::<u64>() else {
        return false;
    };
    if now.abs_diff(ts_num) > 60 {
        return false;
    }
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("ts={ts}\n").as_bytes());
    mac.update(body);
    b64url(&mac.finalize().into_bytes()) == sig
}

fn mock_freeq_server(cap: Arc<std::sync::Mutex<ServerCapture>>) -> axum::Router {
    use axum::routing::post;
    let cap_wt = cap.clone();
    let cap_sess = cap;
    axum::Router::new()
        .route(
            "/auth/broker/web-token",
            post(move |headers: HeaderMap, body: Bytes| {
                let cap = cap_wt.clone();
                async move {
                    if !verify_push_signature(&headers, &body) {
                        return (axum::http::StatusCode::UNAUTHORIZED, "bad signature")
                            .into_response();
                    }
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let mut c = cap.lock().unwrap();
                    c.web_token_bodies.push(json);
                    if c.fail_web_token {
                        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
                            .into_response();
                    }
                    axum::Json(serde_json::json!({"token": "WEBTOK", "nick": "alice"}))
                        .into_response()
                }
            }),
        )
        .route(
            "/auth/broker/session",
            post(move |headers: HeaderMap, body: Bytes| {
                let cap = cap_sess.clone();
                async move {
                    if !verify_push_signature(&headers, &body) {
                        return (axum::http::StatusCode::UNAUTHORIZED, "bad signature")
                            .into_response();
                    }
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    cap.lock().unwrap().session_bodies.push(json);
                    axum::Json(serde_json::json!({"ok": true, "upload_token": "UPTOK"}))
                        .into_response()
                }
            }),
        )
}

use axum::response::IntoResponse;

// ── Mock token endpoint (code exchange) ────────────────────────────────

#[derive(Default)]
struct ExchangeCapture {
    /// (form fields, DPoP proof payload) per request, in order.
    requests: Vec<(std::collections::HashMap<String, String>, serde_json::Value)>,
    /// If set: reject proofs lacking this nonce with 400 use_dpop_nonce
    /// + DPoP-Nonce header (the standard resource-server dance).
    require_nonce: Option<String>,
    /// Artificial latency on the exchange, to open the window a concurrent
    /// duplicate callback would race into.
    delay_ms: u64,
}

fn mock_token_endpoint(cap: Arc<std::sync::Mutex<ExchangeCapture>>) -> axum::Router {
    use axum::routing::post;
    axum::Router::new().route(
        "/token",
        post(move |headers: HeaderMap, body: Bytes| {
            let cap = cap.clone();
            async move {
                let form: std::collections::HashMap<String, String> =
                    serde_urlencoded::from_bytes(&body).unwrap();
                let proof = jwt_payload(headers.get("dpop").unwrap().to_str().unwrap());
                let proof_nonce = proof
                    .get("nonce")
                    .and_then(|n| n.as_str())
                    .map(String::from);
                let (required, delay_ms) = {
                    let mut c = cap.lock().unwrap();
                    c.requests.push((form, proof));
                    (c.require_nonce.clone(), c.delay_ms)
                };
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                if let Some(required) = required
                    && proof_nonce.as_deref() != Some(required.as_str())
                {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        [("DPoP-Nonce", required)],
                        axum::Json(serde_json::json!({"error": "use_dpop_nonce"})),
                    )
                        .into_response();
                }
                axum::Json(serde_json::json!({
                    "access_token": "ACCESS1",
                    "refresh_token": "REFRESH1",
                    "scope": "atproto",
                    "sub": "did:plc:alice123",
                }))
                .into_response()
            }
        }),
    )
}

// ── Mock token endpoint (refresh grant, single-use rotation) ───────────

enum RefreshMode {
    /// Enforce single-use rotation: a refresh token may be seen once;
    /// reuse → 400 invalid_grant (what a real PDS does).
    Rotate,
    InvalidGrant,
    ServerError,
}

struct RefreshState {
    mode: RefreshMode,
    valid: HashSet<String>,
    counter: u32,
    /// Include `scope` in the response? (Some PDSes omit it on refresh.)
    scope: Option<String>,
    seen: Vec<String>,
}

fn mock_refresh_endpoint(state: Arc<std::sync::Mutex<RefreshState>>) -> axum::Router {
    use axum::routing::post;
    axum::Router::new().route(
        "/token",
        post(move |body: Bytes| {
            let state = state.clone();
            async move {
                let form: std::collections::HashMap<String, String> =
                    serde_urlencoded::from_bytes(&body).unwrap();
                let token = form.get("refresh_token").cloned().unwrap_or_default();
                assert_eq!(
                    form.get("grant_type").map(String::as_str),
                    Some("refresh_token")
                );
                let mut s = state.lock().unwrap();
                s.seen.push(token.clone());
                match s.mode {
                    RefreshMode::InvalidGrant => (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response(),
                    RefreshMode::ServerError => {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "oops").into_response()
                    }
                    RefreshMode::Rotate => {
                        if !s.valid.remove(&token) {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({"error": "invalid_grant"})),
                            )
                                .into_response();
                        }
                        s.counter += 1;
                        let next = format!("R{}", s.counter);
                        s.valid.insert(next.clone());
                        let mut resp = serde_json::json!({
                            "access_token": format!("A{}", s.counter),
                            "refresh_token": next,
                        });
                        if let Some(scope) = &s.scope {
                            resp["scope"] = serde_json::Value::String(scope.clone());
                        }
                        axum::Json(resp).into_response()
                    }
                }
            }
        }),
    )
}

// ── Mock PDS (graph writes) ────────────────────────────────────────────

#[derive(Default)]
struct PdsCapture {
    /// (xrpc method, Authorization header, DPoP proof payload, body)
    calls: Vec<(String, String, serde_json::Value, serde_json::Value)>,
}

fn mock_pds(cap: Arc<std::sync::Mutex<PdsCapture>>) -> axum::Router {
    use axum::extract::Path;
    use axum::routing::post;
    axum::Router::new().route(
        "/xrpc/{method}",
        post(
            move |Path(method): Path<String>, headers: HeaderMap, body: Bytes| {
                let cap = cap.clone();
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let proof = jwt_payload(headers.get("dpop").unwrap().to_str().unwrap());
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    cap.lock().unwrap().calls.push((method, auth, proof, json));
                    axum::Json(serde_json::json!({
                        "uri": "at://did:plc:alice123/app.bsky.graph.follow/3kabc",
                        "cid": "bafyfake",
                    }))
                    .into_response()
                }
            },
        ),
    )
}

// ═══ Pure helpers ══════════════════════════════════════════════════════

#[test]
fn return_to_allowlist() {
    // Relative URLs allowed.
    assert!(is_valid_return_to("/app"));
    // Known origins allowed.
    assert!(is_valid_return_to("https://irc.freeq.at"));
    assert!(is_valid_return_to("https://irc.freeq.at/some/path"));
    assert!(is_valid_return_to("https://staging.freeq.at"));
    assert!(is_valid_return_to("https://freeqworld.boxd.sh"));
    // FreeqWorld's own domain (world.freeq.at). The OAuth allowlist is compiled
    // in, so serving the world from a new host requires this entry or Bluesky
    // sign-in fails with a raw "Invalid return_to URL".
    assert!(is_valid_return_to("https://world.freeq.at"));
    assert!(is_valid_return_to("https://world.freeq.at/id"));
    assert!(is_valid_return_to("https://pfp.freeq.at"));
    assert!(is_valid_return_to("http://localhost:5173"));
    assert!(is_valid_return_to("http://127.0.0.1:8000/x"));
    // Everything else rejected — incl. http downgrades of allowed hosts.
    assert!(!is_valid_return_to("https://evil.example"));
    assert!(!is_valid_return_to("http://irc.freeq.at"));

    // Open-redirect fix (was SECURITY-AUDIT C-6): the suffix attack that
    // passed a prefix match must now be rejected — matching is on the parsed
    // scheme+host, not a string prefix.
    assert!(!is_valid_return_to("https://irc.freeq.at.evil.example"));
    // Protocol-relative and backslash tricks are off-origin.
    assert!(!is_valid_return_to("//evil.example"));
    assert!(!is_valid_return_to("/\\evil.example"));
}

#[test]
fn client_id_loopback_vs_production() {
    let prod = build_client_id(
        "https://auth.freeq.at",
        "https://auth.freeq.at/auth/callback",
    );
    assert_eq!(prod, "https://auth.freeq.at/client-metadata.json");
    let local = build_client_id(
        "http://127.0.0.1:8081",
        "http://127.0.0.1:8081/auth/callback",
    );
    assert!(local.starts_with("http://localhost?redirect_uri="));
    assert!(local.contains("scope="));
}

#[test]
fn field_encryption_round_trip_and_tamper() {
    let key = derive_encryption_key(SECRET);
    let enc = encrypt_field(&key, "hunter2");
    assert_ne!(enc, "hunter2");
    assert_eq!(decrypt_field(&key, &enc).unwrap(), "hunter2");
    // Key derivation is deterministic (sessions must survive restarts).
    assert_eq!(derive_encryption_key(SECRET), key);
    // Tampered ciphertext must not decrypt.
    let mut bytes = b64url_decode(&enc);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert!(decrypt_field(&key, &b64url(&bytes)).is_err());
    // Wrong key must not decrypt.
    assert!(decrypt_field(&derive_encryption_key("other"), &enc).is_err());
}

#[test]
fn sign_body_wire_format() {
    // Pins the exact MAC construction the freeq-server receiver expects:
    // HMAC-SHA256(secret, "ts={timestamp}\n" || canonical-json-bytes),
    // base64url unpadded.
    use hmac::{Hmac, Mac};
    let body = serde_json::json!({"did": "did:plc:x", "handle": "h.test"});
    let (sig, ts) = sign_body(SECRET, &body).unwrap();
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("ts={ts}\n").as_bytes());
    mac.update(&serde_json::to_vec(&body).unwrap());
    assert_eq!(sig, b64url(&mac.finalize().into_bytes()));
}

#[tokio::test]
async fn dpop_proof_shape() {
    let key = DpopKey::generate();
    // Round-trips through base64url.
    let restored = DpopKey::from_base64url(&key.to_base64url()).unwrap();
    let proof = restored
        .proof(
            "POST",
            "https://pds.example/token",
            Some("N1"),
            Some("ATOK"),
        )
        .unwrap();
    let payload = jwt_payload(&proof);
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], "https://pds.example/token");
    assert_eq!(payload["nonce"], "N1");
    // `ath` = base64url(SHA-256(access token)), present only when bound.
    use sha2::Digest;
    assert_eq!(
        payload["ath"].as_str().unwrap(),
        b64url(&sha2::Sha256::digest(b"ATOK"))
    );
    let no_ath = key.proof("POST", "https://x.example", None, None).unwrap();
    let p2 = jwt_payload(&no_ath);
    assert!(p2.get("ath").is_none());
    assert!(p2.get("nonce").is_none());
}

// ═══ /health + /client-metadata.json ═══════════════════════════════════

#[tokio::test]
async fn health_endpoints() {
    let base = spawn(router(broker_state("http://unused.example"))).await;
    for path in ["/health", "/health-v3"] {
        let resp = http().get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["version"].is_string());
    }
}

#[tokio::test]
async fn client_metadata_document() {
    let base = spawn(router(broker_state("http://unused.example"))).await;
    let json: serde_json::Value = http()
        .get(format!("{base}/client-metadata.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        json["client_id"],
        "https://auth.test.example/client-metadata.json"
    );
    assert_eq!(
        json["redirect_uris"],
        serde_json::json!(["https://auth.test.example/auth/callback"])
    );
    // The advertised scope union (incl. transition:generic grace period).
    assert_eq!(
        json["scope"],
        "atproto blob:image/* repo:app.bsky.actor.profile repo:blue.irc.media?action=create repo:app.bsky.feed.post transition:generic"
    );
    assert_eq!(
        json["grant_types"],
        serde_json::json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(json["token_endpoint_auth_method"], "none");
    assert_eq!(json["dpop_bound_access_tokens"], true);
}

// ═══ /auth/callback ════════════════════════════════════════════════════

#[tokio::test]
async fn callback_happy_path_web() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap.clone())).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch.clone())).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state.clone())).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=st1&code=CODE1"))
        .send()
        .await
        .unwrap();

    // Redirects to return_to with the #oauth= fragment payload.
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    let loc = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(loc.starts_with("https://irc.freeq.at#oauth="), "{loc}");
    let payload = fragment_payload(&loc);
    assert_eq!(payload["token"], "WEBTOK");
    assert_eq!(payload["nick"], "alice");
    assert_eq!(payload["did"], "did:plc:alice123");
    assert_eq!(payload["handle"], "alice.test");
    assert_eq!(payload["pds_url"], "https://pds.example");
    let broker_token = payload["broker_token"].as_str().unwrap().to_string();
    assert!(!broker_token.is_empty());

    // Token exchange carried the right grant + PKCE verifier.
    {
        let c = exch.lock().unwrap();
        assert_eq!(c.requests.len(), 1);
        let (form, _proof) = &c.requests[0];
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "CODE1");
        assert_eq!(form["code_verifier"], "test-verifier");
        assert_eq!(
            form["client_id"],
            "https://auth.test.example/client-metadata.json"
        );
        assert_eq!(
            form["redirect_uri"],
            "https://auth.test.example/auth/callback"
        );
    }

    // Both pushes hit the server with VALID HMAC signatures (the mock
    // rejects bad ones) and the granted scope was forwarded verbatim.
    {
        let c = server_cap.lock().unwrap();
        assert_eq!(c.web_token_bodies.len(), 1);
        assert_eq!(c.web_token_bodies[0]["did"], "did:plc:alice123");
        assert_eq!(c.session_bodies.len(), 1);
        assert_eq!(c.session_bodies[0]["access_token"], "ACCESS1");
        assert_eq!(c.session_bodies[0]["granted_scope"], "atproto");
    }

    // The session persisted and round-trips through the store (encryption at
    // rest is pinned separately by the SqliteStore unit test in lib.rs).
    {
        let rec = state
            .store
            .get(&broker_token)
            .await
            .expect("session stored");
        assert_eq!(rec.refresh_token, "REFRESH1");
        assert_eq!(rec.did, "did:plc:alice123");
    }

    // The code is single-use, but the callback is IDEMPOTENT: replaying the
    // same state replays the first request's redirect (not an error), because
    // browsers/proxies re-request the callback URL and the first already
    // completed the login. Regression pin for the 2026-07-10 web-login bug
    // (the same state hit the callback 3× in 2s → "Invalid OAuth state").
    let replay = http()
        .get(format!("{base}/auth/callback?state=st1&code=CODE1"))
        .send()
        .await
        .unwrap();
    assert!(
        replay.status().is_redirection(),
        "replay got {}",
        replay.status()
    );
    let replay_loc = replay.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(
        replay_loc, loc,
        "duplicate callback replays the same redirect"
    );
    // ...and did NOT re-run the single-use token exchange.
    assert_eq!(
        exch.lock().unwrap().requests.len(),
        1,
        "replay must not re-exchange the code"
    );
}

// ── Idempotency: duplicate callbacks (browsers/proxies re-request the URL) ──

/// A SEQUENTIAL duplicate — the first callback has fully finished before the
/// second arrives (the observed real pattern: 3 hits ~1s apart). The second
/// must replay the first's redirect, not error.
#[tokio::test]
async fn callback_sequential_duplicate_replays_and_no_reexchange() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch.clone())).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state)).await;

    let first = http()
        .get(format!("{base}/auth/callback?state=st1&code=CODE1"))
        .send()
        .await
        .unwrap();
    let first_loc = first.headers()["location"].to_str().unwrap().to_string();

    // Three more hits with the same state — all replay the same redirect.
    for i in 0..3 {
        let dup = http()
            .get(format!("{base}/auth/callback?state=st1&code=CODE1"))
            .send()
            .await
            .unwrap();
        assert!(
            dup.status().is_redirection(),
            "dup {i} got {}",
            dup.status()
        );
        assert_eq!(
            dup.headers()["location"].to_str().unwrap(),
            first_loc,
            "dup {i} redirect"
        );
    }
    // The single-use code was exchanged exactly once across all four requests.
    assert_eq!(
        exch.lock().unwrap().requests.len(),
        1,
        "code exchanged more than once"
    );
}

/// CONCURRENT duplicates — two callbacks for the same state arrive WHILE the
/// first is still mid-exchange (mock delayed 300ms). The naive cache-after-
/// success loses this race: the second finds pending consumed but the result
/// not yet cached. Both must still succeed, and the code must be exchanged
/// exactly once.
#[tokio::test]
async fn callback_concurrent_duplicates_both_succeed() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    exch.lock().unwrap().delay_ms = 300;
    let token_url = spawn(mock_token_endpoint(exch.clone())).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state)).await;

    let url = format!("{base}/auth/callback?state=st1&code=CODE1");
    let (a, b) = tokio::join!(async { http().get(&url).send().await.unwrap() }, async {
        // Stagger slightly so B lands inside A's exchange window.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        http().get(&url).send().await.unwrap()
    },);

    for (name, resp) in [("A", a), ("B", b)] {
        assert!(
            resp.status().is_redirection(),
            "{name} got {} (expected redirect)",
            resp.status()
        );
        let loc = resp.headers()["location"].to_str().unwrap();
        assert!(
            loc.starts_with("https://irc.freeq.at#oauth="),
            "{name} redirect: {loc}"
        );
    }
    // Exactly one code exchange despite two concurrent callbacks.
    assert_eq!(
        exch.lock().unwrap().requests.len(),
        1,
        "concurrent duplicates re-exchanged the code"
    );
}

/// A genuinely unknown state (never seen) must STILL error — idempotency
/// must not turn every unknown state into a success.
#[tokio::test]
async fn callback_unknown_state_still_errors() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let state = broker_state(&server_url);
    let base = spawn(router(state)).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=never-seen&code=X"))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_redirection(),
        "unknown state must not redirect"
    );
    assert!(resp.text().await.unwrap().contains("Invalid OAuth state"));
}

/// A completed state must not let a DIFFERENT unknown state ride its replay.
#[tokio::test]
async fn callback_replay_is_scoped_to_its_state() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch)).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state)).await;

    // Complete st1, then hit a DIFFERENT unknown state — it must error.
    let _ = http()
        .get(format!("{base}/auth/callback?state=st1&code=CODE1"))
        .send()
        .await
        .unwrap();
    let other = http()
        .get(format!("{base}/auth/callback?state=st2&code=CODE1"))
        .send()
        .await
        .unwrap();
    assert!(!other.status().is_redirection());
    assert!(other.text().await.unwrap().contains("Invalid OAuth state"));
}

#[tokio::test]
async fn callback_sends_known_nonce_on_first_attempt() {
    // The PDS consumes the auth code even on a use_dpop_nonce failure, so
    // the broker MUST send an already-known nonce up front rather than
    // relying on the retry dance. Regression pin for the invalid-code bug.
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch.clone())).await;

    let state = broker_state(&server_url);
    let mut p = pending(&format!("{token_url}/token"), "https://pds.example");
    p.dpop_nonce = Some("KNOWN-NONCE".to_string());
    seed_pending(&state, "st1", p).await;
    let base = spawn(router(state)).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=st1&code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_redirection());

    let c = exch.lock().unwrap();
    assert_eq!(c.requests.len(), 1, "no retry should have been needed");
    assert_eq!(c.requests[0].1["nonce"], "KNOWN-NONCE");
}

#[tokio::test]
async fn callback_nonce_retry_dance() {
    // No known nonce: first attempt is rejected with use_dpop_nonce +
    // DPoP-Nonce header; the retry must carry that nonce and succeed.
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture {
        require_nonce: Some("FRESH-NONCE".to_string()),
        ..Default::default()
    }));
    let token_url = spawn(mock_token_endpoint(exch.clone())).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state)).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=st1&code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_redirection());

    let c = exch.lock().unwrap();
    assert_eq!(c.requests.len(), 2);
    assert!(c.requests[0].1.get("nonce").is_none());
    assert_eq!(c.requests[1].1["nonce"], "FRESH-NONCE");
}

#[tokio::test]
async fn callback_mobile_is_http_redirect_to_custom_scheme() {
    // ASWebAuthenticationSession only intercepts HTTP redirects — a JS or
    // meta-refresh page breaks iOS login. Must stay a 3xx.
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch)).await;

    let state = broker_state(&server_url);
    let mut p = pending(&format!("{token_url}/token"), "https://pds.example");
    p.mobile = true;
    seed_pending(&state, "st1", p).await;
    let base = spawn(router(state)).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=st1&code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    let loc = resp.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with("freeq://auth?token="), "{loc}");
    for key in ["token=", "broker_token=", "nick=", "did=", "handle="] {
        assert!(loc.contains(key), "missing {key} in {loc}");
    }
}

#[tokio::test]
async fn callback_degrades_to_identity_only_when_server_push_fails() {
    // A broker that isn't trusted by the target server (bad/missing shared
    // secret, server down) must still complete login — verified DID +
    // broker_token are enough for identity-only consumers.
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture {
        fail_web_token: true,
        ..Default::default()
    }));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let exch = Arc::new(std::sync::Mutex::new(ExchangeCapture::default()));
    let token_url = spawn(mock_token_endpoint(exch)).await;

    let state = broker_state(&server_url);
    seed_pending(
        &state,
        "st1",
        pending(&format!("{token_url}/token"), "https://pds.example"),
    )
    .await;
    let base = spawn(router(state)).await;

    let resp = http()
        .get(format!("{base}/auth/callback?state=st1&code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_redirection());
    let payload = fragment_payload(resp.headers()["location"].to_str().unwrap());
    assert_eq!(payload["token"], ""); // no web-token
    assert!(!payload["broker_token"].as_str().unwrap().is_empty());
    // Falls back to handle as nick.
    assert_eq!(payload["nick"], "alice.test");
}

#[tokio::test]
async fn callback_error_paths() {
    let base = spawn(router(broker_state("http://unused.example"))).await;

    // Upstream OAuth error → friendly page, no crash.
    let resp = http()
        .get(format!(
            "{base}/auth/callback?error=access_denied&error_description=nope"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("nope"));

    // Missing state / unknown state.
    let resp = http()
        .get(format!("{base}/auth/callback?code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.text().await.unwrap().contains("missing state"));
    let resp = http()
        .get(format!("{base}/auth/callback?state=nope&code=C"))
        .send()
        .await
        .unwrap();
    assert!(resp.text().await.unwrap().contains("Invalid OAuth state"));
}

// ═══ POST /session ═════════════════════════════════════════════════════

fn rotate_state(scope: Option<&str>) -> Arc<std::sync::Mutex<RefreshState>> {
    Arc::new(std::sync::Mutex::new(RefreshState {
        mode: RefreshMode::Rotate,
        valid: HashSet::from(["R0".to_string()]),
        counter: 0,
        scope: scope.map(String::from),
        seen: Vec::new(),
    }))
}

async fn session_call(base: &str, broker_token: &str) -> reqwest::Response {
    http()
        .post(format!("{base}/session"))
        .json(&serde_json::json!({"broker_token": broker_token}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn session_refresh_rotates_and_persists() {
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap.clone())).await;
    let refresh = rotate_state(Some("atproto blob:image/*"));
    let token_url = spawn(mock_refresh_endpoint(refresh.clone())).await;

    let state = broker_state(&server_url);
    seed_session(
        &state,
        "BT1",
        "R0",
        &format!("{token_url}/token"),
        "https://pds.example",
    )
    .await;
    let base = spawn(router(state)).await;

    // First call refreshes R0 → R1.
    let resp = session_call(&base, "BT1").await;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["token"], "WEBTOK");
    assert_eq!(json["nick"], "alice");
    assert_eq!(json["did"], "did:plc:alice123");
    assert_eq!(json["handle"], "alice.test");

    // Second call must use the ROTATED token R1 (persisted encrypted),
    // not replay R0 — the mock enforces single-use.
    let resp2 = session_call(&base, "BT1").await;
    assert_eq!(resp2.status(), 200);
    assert_eq!(refresh.lock().unwrap().seen, vec!["R0", "R1"]);

    // The actually-granted scope was forwarded to the server on each push.
    let c = server_cap.lock().unwrap();
    assert_eq!(c.session_bodies.len(), 2);
    assert_eq!(c.session_bodies[0]["granted_scope"], "atproto blob:image/*");
}

#[tokio::test]
async fn session_concurrent_calls_serialize_on_refresh_lock() {
    // AT Proto refresh tokens are single-use. Concurrent /session calls
    // (reconnect loop, multiple devices) must queue on the per-token lock
    // and each use the freshly-rotated token — racing would wedge the
    // session with invalid_grant. (Root cause of the 2026-07-03 outage.)
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap)).await;
    let refresh = rotate_state(None);
    let token_url = spawn(mock_refresh_endpoint(refresh.clone())).await;

    let state = broker_state(&server_url);
    seed_session(
        &state,
        "BT1",
        "R0",
        &format!("{token_url}/token"),
        "https://pds.example",
    )
    .await;
    let base = spawn(router(state)).await;

    let calls = (0..5).map(|_| {
        let base = base.clone();
        tokio::spawn(async move { session_call(&base, "BT1").await.status().as_u16() })
    });
    for handle in calls {
        assert_eq!(handle.await.unwrap(), 200);
    }
    // Strict rotation order proves serialization: R0, R1, R2, R3, R4.
    assert_eq!(
        refresh.lock().unwrap().seen,
        vec!["R0", "R1", "R2", "R3", "R4"]
    );
}

#[tokio::test]
async fn session_invalid_grant_is_401() {
    // Dead/revoked refresh token → 401 so clients drop to sign-in instead
    // of retrying forever (the "Reconnecting… forever" class).
    let server_url = spawn(mock_freeq_server(Default::default())).await;
    let refresh = Arc::new(std::sync::Mutex::new(RefreshState {
        mode: RefreshMode::InvalidGrant,
        valid: HashSet::new(),
        counter: 0,
        scope: None,
        seen: Vec::new(),
    }));
    let token_url = spawn(mock_refresh_endpoint(refresh)).await;

    let state = broker_state(&server_url);
    seed_session(
        &state,
        "BT1",
        "R0",
        &format!("{token_url}/token"),
        "https://pds.example",
    )
    .await;
    let base = spawn(router(state)).await;

    let resp = session_call(&base, "BT1").await;
    assert_eq!(resp.status(), 401);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("re-authentication required")
    );
}

#[tokio::test]
async fn session_transient_failure_is_502() {
    // PDS 5xx / non-JSON → 502 so clients retry rather than discarding
    // their broker token.
    let server_url = spawn(mock_freeq_server(Default::default())).await;
    let refresh = Arc::new(std::sync::Mutex::new(RefreshState {
        mode: RefreshMode::ServerError,
        valid: HashSet::new(),
        counter: 0,
        scope: None,
        seen: Vec::new(),
    }));
    let token_url = spawn(mock_refresh_endpoint(refresh)).await;

    let state = broker_state(&server_url);
    seed_session(
        &state,
        "BT1",
        "R0",
        &format!("{token_url}/token"),
        "https://pds.example",
    )
    .await;
    let base = spawn(router(state)).await;

    assert_eq!(session_call(&base, "BT1").await.status(), 502);
}

#[tokio::test]
async fn session_unknown_token_is_401() {
    let base = spawn(router(broker_state("http://unused.example"))).await;
    assert_eq!(session_call(&base, "NOPE").await.status(), 401);
}

#[tokio::test]
async fn session_rejects_disallowed_origin() {
    // CSRF guard: browser requests from unknown origins are refused;
    // requests with no Origin (native apps, curl) pass.
    let base = spawn(router(broker_state("http://unused.example"))).await;
    let resp = http()
        .post(format!("{base}/session"))
        .header("origin", "https://evil.example")
        .json(&serde_json::json!({"broker_token": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn session_missing_scope_defaults_to_wide_legacy_grant() {
    // When the PDS omits `scope` in a refresh response, the broker must
    // report the conservative legacy default so per-purpose checks on the
    // server don't wrongly deny pre-narrowing sessions.
    let server_cap = Arc::new(std::sync::Mutex::new(ServerCapture::default()));
    let server_url = spawn(mock_freeq_server(server_cap.clone())).await;
    let refresh = rotate_state(None); // response carries NO scope field
    let token_url = spawn(mock_refresh_endpoint(refresh)).await;

    let state = broker_state(&server_url);
    seed_session(
        &state,
        "BT1",
        "R0",
        &format!("{token_url}/token"),
        "https://pds.example",
    )
    .await;
    let base = spawn(router(state)).await;

    assert_eq!(session_call(&base, "BT1").await.status(), 200);
    let c = server_cap.lock().unwrap();
    assert_eq!(
        c.session_bodies[0]["granted_scope"],
        "atproto transition:generic"
    );
}

// ═══ /api/graph/follow + /api/graph/unfollow ═══════════════════════════

async fn graph_setup() -> (String, Arc<std::sync::Mutex<PdsCapture>>) {
    let server_url = spawn(mock_freeq_server(Default::default())).await;
    let refresh = rotate_state(None);
    let token_url = spawn(mock_refresh_endpoint(refresh)).await;
    let pds_cap = Arc::new(std::sync::Mutex::new(PdsCapture::default()));
    let pds_url = spawn(mock_pds(pds_cap.clone())).await;

    let state = broker_state(&server_url);
    seed_session(&state, "BT1", "R0", &format!("{token_url}/token"), &pds_url).await;
    (spawn(router(state)).await, pds_cap)
}

// ── PFP avatar delegation ──────────────────────────────────────────────

#[derive(Default)]
struct PfpPdsCapture {
    upload_blobs: usize,
    get_record_hits: usize,
    put_record: Option<serde_json::Value>,
    create_record: Option<serde_json::Value>,
}

fn mock_pds_pfp(cap: Arc<std::sync::Mutex<PfpPdsCapture>>) -> axum::Router {
    use axum::routing::{get, post};
    let c1 = cap.clone();
    let c2 = cap.clone();
    let c3 = cap.clone();
    let c4 = cap;
    axum::Router::new()
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(move |headers: HeaderMap, body: Bytes| {
                let c = c1.clone();
                async move {
                    // binary body, DPoP-authenticated, correct content-type
                    assert_eq!(headers.get("content-type").unwrap(), "image/png");
                    assert!(headers.get("dpop").is_some());
                    assert!(!body.is_empty());
                    c.lock().unwrap().upload_blobs += 1;
                    axum::Json(serde_json::json!({
                        "blob": {"$type":"blob","ref":{"$link":"bafyblob"},"mimeType":"image/png","size": body.len()}
                    }))
                }
            }),
        )
        .route(
            "/xrpc/com.atproto.repo.getRecord",
            get(move || {
                let c = c2.clone();
                async move {
                    c.lock().unwrap().get_record_hits += 1;
                    axum::Json(serde_json::json!({
                        "uri": "at://did:plc:alice123/app.bsky.actor.profile/self",
                        "cid": "bafyprofile",
                        "value": {"$type":"app.bsky.actor.profile","displayName":"Alice","description":"keep me"}
                    }))
                }
            }),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(move |body: Bytes| {
                let c = c3.clone();
                async move {
                    c.lock().unwrap().put_record = Some(serde_json::from_slice(&body).unwrap());
                    axum::Json(serde_json::json!({"uri":"at://did:plc:alice123/app.bsky.actor.profile/self","cid":"c"}))
                }
            }),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(move |body: Bytes| {
                let c = c4.clone();
                async move {
                    c.lock().unwrap().create_record = Some(serde_json::from_slice(&body).unwrap());
                    axum::Json(serde_json::json!({"uri":"at://did:plc:alice123/app.bsky.feed.post/3kpost","cid":"c"}))
                }
            }),
        )
}

async fn pfp_setup() -> (String, Arc<std::sync::Mutex<PfpPdsCapture>>) {
    let server_url = spawn(mock_freeq_server(Default::default())).await;
    let refresh = rotate_state(None);
    let token_url = spawn(mock_refresh_endpoint(refresh)).await;
    let pds_cap = Arc::new(std::sync::Mutex::new(PfpPdsCapture::default()));
    let pds_url = spawn(mock_pds_pfp(pds_cap.clone())).await;
    let state = broker_state(&server_url);
    seed_session(&state, "BT1", "R0", &format!("{token_url}/token"), &pds_url).await;
    (spawn(router(state)).await, pds_cap)
}

fn tiny_png_b64() -> String {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&[0u8; 64]);
    base64::engine::general_purpose::STANDARD.encode(&v)
}

#[tokio::test]
async fn pfp_set_avatar_preserves_profile_and_posts() {
    let (base, cap) = pfp_setup().await;
    let resp = http()
        .post(format!("{base}/api/pfp/set-avatar"))
        .json(
            &serde_json::json!({"broker_token": "BT1", "image_b64": tiny_png_b64(), "post": true}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["posted"], true);

    let c = cap.lock().unwrap();
    // two uploads: one for the avatar, one for the post embed
    assert_eq!(c.upload_blobs, 2);
    assert!(c.get_record_hits >= 1);
    // profile write swaps avatar but keeps the existing fields
    let put = c.put_record.as_ref().unwrap();
    assert_eq!(put["collection"], "app.bsky.actor.profile");
    assert_eq!(put["rkey"], "self");
    assert_eq!(put["record"]["displayName"], "Alice");
    assert_eq!(put["record"]["description"], "keep me");
    assert_eq!(put["record"]["avatar"]["$type"], "blob");
    // the post carries the image + a link facet whose bytes land on the URL
    let post = c.create_record.as_ref().unwrap();
    assert_eq!(post["collection"], "app.bsky.feed.post");
    assert!(post["record"]["embed"]["images"][0]["image"]["$type"] == "blob");
    let text = post["record"]["text"].as_str().unwrap();
    let f = &post["record"]["facets"][0]["index"];
    let (s, e) = (
        f["byteStart"].as_u64().unwrap() as usize,
        f["byteEnd"].as_u64().unwrap() as usize,
    );
    assert_eq!(&text.as_bytes()[s..e], b"pfp.freeq.at");
    assert_eq!(
        post["record"]["facets"][0]["features"][0]["uri"],
        "https://pfp.freeq.at"
    );
}

#[tokio::test]
async fn pfp_set_avatar_rejections() {
    let (base, _) = pfp_setup().await;
    // bad broker token → 401
    let resp = http()
        .post(format!("{base}/api/pfp/set-avatar"))
        .json(&serde_json::json!({"broker_token": "WRONG", "image_b64": tiny_png_b64()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    // non-PNG bytes → 400 before any auth work
    let resp = http()
        .post(format!("{base}/api/pfp/set-avatar"))
        .json(&serde_json::json!({"broker_token": "BT1", "image_b64": base64::engine::general_purpose::STANDARD.encode(b"not a png")}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
    // disallowed browser origin → 403
    let resp = http()
        .post(format!("{base}/api/pfp/set-avatar"))
        .header("origin", "https://evil.example")
        .json(&serde_json::json!({"broker_token": "BT1", "image_b64": tiny_png_b64()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn graph_follow_creates_record_with_dpop() {
    let (base, pds_cap) = graph_setup().await;
    let resp = http()
        .post(format!("{base}/api/graph/follow"))
        .json(&serde_json::json!({"broker_token": "BT1", "subject_did": "did:plc:bob456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["ok"], true);
    assert!(json["uri"].as_str().unwrap().starts_with("at://"));

    let c = pds_cap.lock().unwrap();
    assert_eq!(c.calls.len(), 1);
    let (method, auth, proof, body) = &c.calls[0];
    assert_eq!(method, "com.atproto.repo.createRecord");
    // Access token bound via DPoP scheme + ath claim in the proof.
    assert_eq!(auth, "DPoP A1");
    assert!(proof.get("ath").is_some());
    assert_eq!(body["repo"], "did:plc:alice123");
    assert_eq!(body["collection"], "app.bsky.graph.follow");
    assert_eq!(body["record"]["subject"], "did:plc:bob456");
}

#[tokio::test]
async fn graph_follow_rejections() {
    let (base, _) = graph_setup().await;
    // Self-follow refused.
    let resp = http()
        .post(format!("{base}/api/graph/follow"))
        .json(&serde_json::json!({"broker_token": "BT1", "subject_did": "did:plc:alice123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Non-DID subject refused.
    let resp = http()
        .post(format!("{base}/api/graph/follow"))
        .json(&serde_json::json!({"broker_token": "BT1", "subject_did": "bob.test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Bad broker token → 401.
    let resp = http()
        .post(format!("{base}/api/graph/follow"))
        .json(&serde_json::json!({"broker_token": "WRONG", "subject_did": "did:plc:bob456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    // Disallowed browser origin → 403 before any work.
    let resp = http()
        .post(format!("{base}/api/graph/follow"))
        .header("origin", "https://evil.example")
        .json(&serde_json::json!({"broker_token": "BT1", "subject_did": "did:plc:bob456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn graph_unfollow_only_own_repo_records() {
    let (base, pds_cap) = graph_setup().await;
    // Deleting a follow record in someone ELSE's repo is refused.
    let resp = http()
        .post(format!("{base}/api/graph/unfollow"))
        .json(&serde_json::json!({
            "broker_token": "BT1",
            "follow_uri": "at://did:plc:someoneelse/app.bsky.graph.follow/3kabc"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Wrong collection refused.
    let resp = http()
        .post(format!("{base}/api/graph/unfollow"))
        .json(&serde_json::json!({
            "broker_token": "BT1",
            "follow_uri": "at://did:plc:alice123/app.bsky.feed.post/3kabc"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Own-repo record deletes via deleteRecord with the parsed rkey.
    let resp = http()
        .post(format!("{base}/api/graph/unfollow"))
        .json(&serde_json::json!({
            "broker_token": "BT1",
            "follow_uri": "at://did:plc:alice123/app.bsky.graph.follow/3kabc"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let c = pds_cap.lock().unwrap();
    let (method, _, _, body) = c.calls.last().unwrap();
    assert_eq!(method, "com.atproto.repo.deleteRecord");
    assert_eq!(body["rkey"], "3kabc");
    assert_eq!(body["repo"], "did:plc:alice123");
}
