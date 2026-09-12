//! Characterization of the embedded server's `/auth/callback` behaviors
//! that have no standalone-broker counterpart and must survive the auth
//! unification (see docs/AUTH-BROKER-UNIFICATION.md):
//!
//!   - mobile callback → `freeq://auth?...` custom-scheme redirect,
//!   - IRC `/login` completion via the `irc_state` back-channel,
//!   - primary-login web session + one-time web-token minting.
//!
//! These drive the real handler by seeding `oauth_pending` (via the
//! test-only `start_with_web_state`) and pointing its `token_endpoint`
//! at a mock, so the OAuth code exchange is hermetic — no bsky.social.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;
use freeq_sdk::did::DidResolver;
use freeq_sdk::oauth::DpopKey;
use freeq_server::server::{OAuthPending, OauthPurpose, Server, SharedState};

// ── Harness ────────────────────────────────────────────────────────────

async fn start() -> (SocketAddr, Arc<SharedState>) {
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-embedded-auth".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = Server::with_resolver(config, resolver);
    let (_irc, web, _handle, state) = server.start_with_web_state().await.unwrap();
    (web, state)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Mock PDS token endpoint: accepts the code-exchange POST and returns a
/// minimal token response. Pins the DID via `sub` to the pending DID.
async fn mock_token_endpoint() -> String {
    mock_token_endpoint_granting("atproto").await
}

/// Same mock, answering with the scope the PDS decided to grant.
async fn mock_token_endpoint_granting(scope: &str) -> String {
    let scope = scope.to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/token",
        post(move |_headers: HeaderMap, _body: Bytes| {
            let scope = scope.clone();
            async move {
                axum::Json(serde_json::json!({
                    "access_token": "ACCESS-EMB",
                    "refresh_token": "REFRESH-EMB",
                    "scope": scope,
                    "sub": "did:plc:embedded1",
                }))
                .into_response()
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}/token")
}

fn seed_pending(
    state: &Arc<SharedState>,
    oauth_state: &str,
    token_endpoint: &str,
    mobile: bool,
    irc_state: Option<String>,
) {
    seed_pending_with_scope(
        state,
        oauth_state,
        token_endpoint,
        mobile,
        irc_state,
        "atproto",
    );
}

/// Same seed, for a login started with a wider `requested_scope`.
fn seed_pending_with_scope(
    state: &Arc<SharedState>,
    oauth_state: &str,
    token_endpoint: &str,
    mobile: bool,
    irc_state: Option<String>,
    requested_scope: &str,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    state.oauth_pending.lock().insert(
        oauth_state.to_string(),
        OAuthPending {
            handle: "alice.bsky.social".to_string(),
            did: "did:plc:embedded1".to_string(),
            pds_url: "https://pds.example".to_string(),
            code_verifier: "verifier".to_string(),
            redirect_uri: "https://irc.test.example/auth/callback".to_string(),
            client_id: "https://irc.test.example/client-metadata.json".to_string(),
            token_endpoint: token_endpoint.to_string(),
            dpop_key_b64: DpopKey::generate().to_base64url(),
            created_at: now,
            mobile,
            irc_state,
            purpose: OauthPurpose::Login,
            requested_scope: requested_scope.to_string(),
        },
    );
}

// ── Tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn mobile_callback_redirects_to_custom_scheme() {
    // Mobile primary login must end in an HTTP page that lands the app on
    // `freeq://auth?token=…` — the fields native clients parse. Standard
    // (non-broker) suffix here strips to a bare nick.
    let (web, state) = start().await;
    let token = mock_token_endpoint().await;
    seed_pending(&state, "st-mobile", &token, true, None);

    let resp = http()
        .get(format!("http://{web}/auth/callback?state=st-mobile&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("freeq://auth?token="), "body: {body}");
    assert!(body.contains("did%3Aplc%3Aembedded1") || body.contains("did:plc:embedded1"));
    // .bsky.social suffix stripped to the bare nick.
    assert!(body.contains("nick=alice"));
    assert!(!body.contains("nick=alice.bsky.social"));

    // A web-token was minted for the mobile client to SASL with.
    assert_eq!(state.web_auth_tokens.lock().len(), 1);
}

#[tokio::test]
async fn web_callback_stores_session_and_mints_token() {
    // Non-mobile primary login: HTML result page carrying the OAuth result
    // to the opener, a stored Login web-session, and a one-time web-token.
    let (web, state) = start().await;
    let token = mock_token_endpoint().await;
    seed_pending(&state, "st-web", &token, false, None);

    let resp = http()
        .get(format!("http://{web}/auth/callback?state=st-web&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("freeq-oauth"));

    // Session stored under (DID, Login); one-time web-token minted.
    assert!(
        state
            .web_sessions
            .lock()
            .contains_key(&("did:plc:embedded1".to_string(), OauthPurpose::Login))
    );
    assert_eq!(state.web_auth_tokens.lock().len(), 1);

    // One-time state: replay is refused.
    let replay = http()
        .get(format!("http://{web}/auth/callback?state=st-web&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400);
}

#[tokio::test]
async fn irc_login_completion_via_irc_state() {
    // `/login` from an IRC client parks its session under `login_pending`
    // keyed by the oauth state; the callback must consume it and return
    // the "return to your IRC client" page rather than the web result page.
    let (web, state) = start().await;
    let token = mock_token_endpoint().await;
    seed_pending(&state, "st-irc", &token, false, Some("st-irc".to_string()));
    state
        .login_pending
        .lock()
        .insert("st-irc".to_string(), "session-xyz".to_string());

    let resp = http()
        .get(format!("http://{web}/auth/callback?state=st-irc&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("return to your IRC client"), "body: {body}");
    assert!(body.contains("alice.bsky.social"));

    // The login_pending entry was consumed.
    assert!(!state.login_pending.lock().contains_key("st-irc"));
}

#[tokio::test]
async fn callback_upstream_error_renders_page() {
    let (web, _state) = start().await;
    let resp = http()
        .get(format!(
            "http://{web}/auth/callback?error=access_denied&error_description=user+said+no"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("user said no"));
}

/// The record the mock PDS says it wrote.
const ENROLLED_URI: &str = "at://did:plc:embedded1/at.freeq.deviceKey/3kmockrecord";

/// Mock PDS: answers `com.atproto.repo.createRecord` with a uri and cid.
async fn mock_pds() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/xrpc/com.atproto.repo.createRecord",
        post(|_headers: HeaderMap, _body: Bytes| async {
            axum::Json(serde_json::json!({
                "uri": ENROLLED_URI,
                "cid": "bafyreimockrecord",
            }))
            .into_response()
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

/// An `intent=enroll` sign-in against `pds_url` that the token endpoint
/// answers granting `granted`. Mobile, so the result page carries the broker
/// token in its `freeq://` redirect; returns that token.
async fn enroll_sign_in(
    web: SocketAddr,
    state: &Arc<SharedState>,
    oauth_state: &str,
    granted: &str,
    pds_url: &str,
) -> String {
    let token = mock_token_endpoint_granting(granted).await;
    seed_pending_with_scope(
        state,
        oauth_state,
        &token,
        true,
        None,
        freeq_oauth::ENROLL_SCOPE,
    );
    state
        .oauth_pending
        .lock()
        .get_mut(oauth_state)
        .unwrap()
        .pds_url = pds_url.to_string();

    let resp = http()
        .get(format!(
            "http://{web}/auth/callback?state={oauth_state}&code=C"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    let start = html.find("freeq://auth?").expect("freeq:// redirect");
    let rest = &html[start..];
    let end = rest.find(['"', '\'']).unwrap_or(rest.len());
    url::Url::parse(&rest[..end])
        .expect("valid freeq:// URL")
        .query_pairs()
        .find(|(k, _)| k == "broker_token")
        .map(|(_, v)| v.into_owned())
        .expect("broker_token param")
}

/// POST a device key record, built by the SDK, to `/enroll`.
async fn enroll_device_key(web: SocketAddr, broker_token: &str) -> (reqwest::StatusCode, String) {
    let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[42u8; 32]).unwrap();
    let record = freeq_sdk::identity_records::build_device_record(
        &key,
        "did:plc:embedded1",
        "2026-09-13T00:00:00.000Z",
        Some("test device"),
    )
    .unwrap();
    let resp = http()
        .post(format!("http://{web}/enroll"))
        .json(&serde_json::json!({
            "broker_token": broker_token,
            "record": record,
            "signer_public_key": key.public_key_multibase(),
        }))
        .send()
        .await
        .unwrap();
    (resp.status(), resp.text().await.unwrap())
}

#[tokio::test]
async fn an_enroll_sign_in_publishes_a_device_key_through_enroll() {
    // The grant asked for at sign-in is the one /enroll checks: granted, the
    // record reaches the account's PDS and its uri comes back.
    let (web, state) = start().await;
    let pds = mock_pds().await;
    let broker_token = enroll_sign_in(
        web,
        &state,
        "st-enroll-publish",
        freeq_oauth::ENROLL_SCOPE,
        &pds,
    )
    .await;

    let (status, body) = enroll_device_key(web, &broker_token).await;
    assert_eq!(status, 200, "enroll answered: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["uri"], ENROLLED_URI);
}

#[tokio::test]
async fn a_sign_in_granted_only_atproto_cannot_enroll() {
    let (web, state) = start().await;
    let pds = mock_pds().await;
    let broker_token = enroll_sign_in(web, &state, "st-enroll-refused", "atproto", &pds).await;

    let (status, body) = enroll_device_key(web, &broker_token).await;
    assert_eq!(status, 403, "enroll answered: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"], "insufficient_scope");
}

#[tokio::test]
async fn enroll_login_still_mints_token_and_stores_the_wider_grant() {
    // An `intent=enroll` sign-in is still purpose Login: it mints the SASL
    // web token and stores a Login session, with the key grants recorded.
    let (web, state) = start().await;
    let token = mock_token_endpoint_granting(freeq_oauth::ENROLL_SCOPE).await;
    seed_pending_with_scope(
        &state,
        "st-enroll",
        &token,
        false,
        None,
        freeq_oauth::ENROLL_SCOPE,
    );

    let resp = http()
        .get(format!("http://{web}/auth/callback?state=st-enroll&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    assert_eq!(state.web_auth_tokens.lock().len(), 1);
    let sessions = state.web_sessions.lock();
    let session = sessions
        .get(&("did:plc:embedded1".to_string(), OauthPurpose::Login))
        .expect("Login session stored");
    let granted: std::collections::HashSet<&str> =
        session.granted_scope.split_whitespace().collect();
    assert!(granted.contains("repo:at.freeq.deviceKey?action=create"));
    assert!(granted.contains("repo:at.freeq.agentKey?action=create"));
}
