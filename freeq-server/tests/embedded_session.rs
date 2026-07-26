//! End-to-end test for embedded durable sessions.
//!
//! In embedded mode (no separate broker) the server mounts the broker's
//! `/session` endpoint backed by an in-process InMemoryStore, and its
//! `auth_callback` persists a session + issues a broker_token. This drives the
//! full loop: login callback → persist → `/session` refresh → fresh web-token —
//! against a mock PDS token endpoint, with no bsky.social.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::response::IntoResponse;
use axum::routing::post;
use freeq_sdk::did::DidResolver;
use freeq_sdk::oauth::DpopKey;
use freeq_server::server::{OAuthPending, OauthPurpose, Server, SharedState};

async fn start_embedded() -> (SocketAddr, Arc<SharedState>) {
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-embedded-session".to_string(),
        challenge_timeout_secs: 60,
        // broker_shared_secret is None by default → embedded mode.
        ..Default::default()
    };
    let server = Server::with_resolver(config, resolver);
    let (_irc, web, _h, state) = server.start_with_web_state().await.unwrap();
    (web, state)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Mock PDS token endpoint handling BOTH grants: the code exchange (returns a
/// refresh token) and the refresh grant (rotates it).
async fn mock_token_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/token",
        post(|body: Bytes| async move {
            let form: HashMap<String, String> = serde_urlencoded::from_bytes(&body).unwrap();
            let grant = form.get("grant_type").map(String::as_str).unwrap_or("");
            match grant {
                "authorization_code" => axum::Json(serde_json::json!({
                    "access_token": "ACCESS-1",
                    "refresh_token": "REFRESH-1",
                    "scope": "atproto",
                    "sub": "did:plc:embedded1",
                }))
                .into_response(),
                "refresh_token" => axum::Json(serde_json::json!({
                    "access_token": "ACCESS-2",
                    "refresh_token": "REFRESH-2",
                    "scope": "atproto",
                }))
                .into_response(),
                _ => (axum::http::StatusCode::BAD_REQUEST, "bad grant").into_response(),
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}/token")
}

fn seed_login_pending(state: &Arc<SharedState>, oauth_state: &str, token_endpoint: &str) {
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
            mobile: true, // mobile → broker_token lands in the freeq:// redirect
            irc_state: None,
            purpose: OauthPurpose::Login,
            requested_scope: "atproto".to_string(),
        },
    );
}

/// Pull the `broker_token` query param out of the mobile callback's
/// `freeq://auth?...` redirect, URL-decoding it the way a real client would.
fn broker_token_from_html(html: &str) -> String {
    let start = html.find("freeq://auth?").expect("freeq:// redirect");
    let rest = &html[start..];
    let end = rest.find(['"', '\'']).unwrap_or(rest.len());
    let url = url::Url::parse(&rest[..end]).expect("valid freeq:// URL");
    url.query_pairs()
        .find(|(k, _)| k == "broker_token")
        .map(|(_, v)| v.into_owned())
        .expect("broker_token param")
}

#[tokio::test]
async fn embedded_session_full_roundtrip() {
    let (web, state) = start_embedded().await;
    // Sanity: embedded mode created the in-memory store.
    assert!(
        state.embedded_session_store.is_some(),
        "embedded mode should have a session store"
    );

    let token = mock_token_endpoint().await;
    seed_login_pending(&state, "st-1", &token);

    // 1. Login callback: exchanges the code, persists the session, issues a
    //    broker_token in the freeq:// redirect.
    let resp = http()
        .get(format!("http://{web}/auth/callback?state=st-1&code=C"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    let broker_token = broker_token_from_html(&html);
    assert!(
        !broker_token.is_empty(),
        "callback must issue a broker_token"
    );

    // 2. /session with the broker_token: refreshes against the PDS and mints a
    //    fresh web-token — no re-login. Sends a same-origin `Origin` header, as
    //    a browser does, to exercise the CSRF guard (the embedded web client is
    //    always same-origin).
    let resp = http()
        .post(format!("http://{web}/session"))
        .header("origin", format!("http://{web}"))
        .json(&serde_json::json!({ "broker_token": broker_token }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "unexpected /session response: {body}");
    let session: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session["did"], "did:plc:embedded1");
    assert_eq!(session["handle"], "alice.bsky.social");
    let web_token = session["token"].as_str().unwrap();
    assert!(
        !web_token.is_empty(),
        "/session must mint a fresh web-token"
    );
    // The minted web-token is installed for SASL.
    assert!(state.web_auth_tokens.lock().contains_key(web_token));
}

#[tokio::test]
async fn session_endpoint_absent_when_not_embedded() {
    // With a broker shared secret set (separate-broker mode), the embedded
    // store is absent and /session is not mounted.
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-not-embedded".to_string(),
        challenge_timeout_secs: 60,
        broker_shared_secret: Some("secret".to_string()),
        ..Default::default()
    };
    let server = Server::with_resolver(config, resolver);
    let (_irc, web, _h, state) = server.start_with_web_state().await.unwrap();
    assert!(state.embedded_session_store.is_none());

    let resp = http()
        .post(format!("http://{web}/session"))
        .json(&serde_json::json!({ "broker_token": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "/session must not be mounted in broker mode"
    );
}
