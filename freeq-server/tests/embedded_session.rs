//! End-to-end test for embedded durable sessions.
//!
//! In embedded mode (no separate broker) the server mounts the broker's
//! `/session` endpoint backed by an in-process InMemoryStore, and its
//! `auth_callback` persists a session + issues a broker_token. This drives the
//! full loop: login callback → persist → `/session` refresh → fresh web-token —
//! against a mock PDS token endpoint, with no bsky.social.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::response::IntoResponse;
use axum::routing::post;
use freeq_sdk::did::DidResolver;
use freeq_sdk::oauth::DpopKey;
use freeq_server::server::{OAuthPending, OauthPurpose, Server, SharedState};

async fn start_embedded() -> (SocketAddr, Arc<SharedState>) {
    let (_irc, web, state) = start_embedded_with_irc().await;
    (web, state)
}

/// The same embedded server, with its IRC listener and a database — the
/// sign-out route retires a row, which needs one.
async fn start_embedded_with_irc() -> (SocketAddr, SocketAddr, Arc<SharedState>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp); // outlives the server
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-embedded-session".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        // broker_shared_secret is None by default → embedded mode.
        ..Default::default()
    };
    let server = Server::with_resolver(config, resolver);
    let (irc, web, _h, state) = server.start_with_web_state().await.unwrap();
    (irc, web, state)
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

// ── Signing a device out ───────────────────────────────────────────────

/// A raw IRC client that authenticates with a web token, so a test can drive
/// the connection the browser makes.
struct Irc {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    /// The `API-BEARER` notice's session id — the REST bearer.
    bearer: String,
}

impl Irc {
    fn connect(addr: SocketAddr, nick: &str, web_token: &str) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let writer = s.try_clone().unwrap();
        let mut c = Self {
            reader: BufReader::new(s),
            writer,
            bearer: String::new(),
        };
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx("CAP REQ :sasl message-tags");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let payload = serde_json::json!({
            "did": "",
            "method": "web-token",
            "signature": web_token,
        });
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        c.tx(&format!("AUTHENTICATE {encoded}"));
        let notice = c.rx(|l| l.contains("API-BEARER"), "API-BEARER");
        c.bearer = notice
            .rsplit_once("API-BEARER ")
            .expect("API-BEARER token")
            .1
            .trim()
            .to_string();
        c.tx("CAP END");
        c.rx(|l| l.split_whitespace().nth(1) == Some("001"), "001");
        c
    }

    /// Register a signing key and return its kid.
    fn msgsig(&mut self, key: &ed25519_dalek::SigningKey) -> String {
        use base64::Engine;
        let vk = key.verifying_key();
        let pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.as_bytes());
        self.tx(&format!("MSGSIG {pubkey}"));
        self.rx(|l| l.contains("MSGSIG OK"), "MSGSIG OK");
        freeq_sdk::sigtag::derive_kid(&vk)
    }

    fn tx(&mut self, l: &str) {
        writeln!(self.writer, "{l}\r").unwrap();
        self.writer.flush().ok();
    }

    fn rx(&mut self, p: impl Fn(&str) -> bool, what: &str) -> String {
        let mut b = String::new();
        loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => panic!("EOF waiting for {what}"),
                Ok(_) => {
                    let l = b.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {t}\r");
                        let _ = self.writer.flush();
                        continue;
                    }
                    if p(l) {
                        return l.to_string();
                    }
                }
                Err(e) => panic!("{what}: {e}"),
            }
        }
    }

    /// True once the server has closed this connection.
    fn closed_within(&mut self, ms: u64) -> bool {
        self.writer
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
        let mut b = String::new();
        loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    }
}

/// Log in through the embedded callback: the broker token it issued, and the
/// one-time web token it minted.
async fn login(web: SocketAddr, state: &Arc<SharedState>, oauth_state: &str) -> (String, String) {
    let token_endpoint = mock_token_endpoint().await;
    seed_login_pending(state, oauth_state, &token_endpoint);
    let resp = http()
        .get(format!(
            "http://{web}/auth/callback?state={oauth_state}&code=C"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let broker_token = broker_token_from_html(&resp.text().await.unwrap());
    let web_token = state
        .web_auth_tokens
        .lock()
        .keys()
        .next()
        .cloned()
        .expect("callback minted a web token");
    (broker_token, web_token)
}

/// A second web token for the same identity — another already-signed-in
/// session, which is who presses Sign out.
fn second_web_token(state: &Arc<SharedState>) -> String {
    let token = "WEBTOKEN-SECOND".to_string();
    state.web_auth_tokens.lock().insert(
        token.clone(),
        (
            "did:plc:embedded1".to_string(),
            "alice.bsky.social".to_string(),
            std::time::Instant::now(),
            None,
        ),
    );
    token
}

async fn sign_out(web: SocketAddr, bearer: &str, kid: &str) -> reqwest::Response {
    http()
        .post(format!("http://{web}/api/v1/devices/sign-out"))
        .header("authorization", format!("Bearer {bearer}"))
        .json(&serde_json::json!({ "kid": kid }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn sign_out_retires_the_key_closes_the_session_and_ends_its_token() {
    let (irc, web, state) = start_embedded_with_irc().await;
    let (broker_token, web_token) = login(web, &state, "st-signout").await;
    let other_token = second_web_token(&state);

    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let (mut device, kid) = tokio::task::spawn_blocking(move || {
        let mut c = Irc::connect(irc, "alice", &web_token);
        let kid = c.msgsig(&key);
        (c, kid)
    })
    .await
    .unwrap();

    let kid_for_conn = kid.clone();
    let mut other = tokio::task::spawn_blocking(move || Irc::connect(irc, "alice2", &other_token))
        .await
        .unwrap();

    let resp = sign_out(web, &other.bearer, &kid_for_conn).await;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "sign-out answered: {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["sessions_closed"], 1);
    assert_eq!(body["tokens_revoked"], 1);

    // The key row is retired.
    let removed = state
        .with_db(|db| db.get_signing_key_row("did:plc:embedded1", &kid))
        .flatten()
        .expect("key row")
        .removed_at;
    assert!(removed.is_some(), "sign-out must stamp removed_at");

    // That device's connection is gone; the one that pressed Sign out is not.
    assert!(
        tokio::task::spawn_blocking(move || device.closed_within(3000))
            .await
            .unwrap(),
        "the signed-out device's connection must be closed"
    );

    // Its login token no longer opens a session.
    let resp = http()
        .post(format!("http://{web}/session"))
        .header("origin", format!("http://{web}"))
        .json(&serde_json::json!({ "broker_token": broker_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "the signed-out device's token must die");

    let _ = &mut other;
}

#[tokio::test]
async fn sign_out_for_a_kid_this_server_never_saw_is_ok_and_closes_nothing() {
    // The caller is already that account and the retirement is public, so
    // saying there was nothing here to end reveals nothing.
    let (irc, web, state) = start_embedded_with_irc().await;
    let (_broker_token, web_token) = login(web, &state, "st-unknown").await;

    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let mut device = tokio::task::spawn_blocking(move || {
        let mut c = Irc::connect(irc, "alice", &web_token);
        c.msgsig(&key);
        c
    })
    .await
    .unwrap();

    let resp = sign_out(web, &device.bearer, "kid-that-never-existed").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "ok": true, "sessions_closed": 0, "tokens_revoked": 0 })
    );

    assert!(
        !tokio::task::spawn_blocking(move || device.closed_within(500))
            .await
            .unwrap(),
        "a sign-out that found nothing must close nothing"
    );
}

#[tokio::test]
async fn sign_out_by_another_did_closes_nothing() {
    let (irc, web, state) = start_embedded_with_irc().await;
    let (_broker_token, web_token) = login(web, &state, "st-stranger").await;

    let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let (mut device, kid) = tokio::task::spawn_blocking(move || {
        let mut c = Irc::connect(irc, "alice", &web_token);
        let kid = c.msgsig(&key);
        (c, kid)
    })
    .await
    .unwrap();

    // A session of a different DID asking to sign out alice's key.
    let stranger = "WEBTOKEN-STRANGER".to_string();
    state.web_auth_tokens.lock().insert(
        stranger.clone(),
        (
            "did:plc:stranger".to_string(),
            "mallory.bsky.social".to_string(),
            std::time::Instant::now(),
            None,
        ),
    );
    let mut mallory = tokio::task::spawn_blocking(move || Irc::connect(irc, "mallory", &stranger))
        .await
        .unwrap();

    // The stranger's own account has no such key here: the same answer as for
    // a kid nobody registered, so it learns nothing about alice's.
    let resp = sign_out(web, &mallory.bearer, &kid).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "ok": true, "sessions_closed": 0, "tokens_revoked": 0 })
    );

    assert!(
        !tokio::task::spawn_blocking(move || device.closed_within(500))
            .await
            .unwrap(),
        "a stranger's request must close nothing"
    );
    let _ = &mut mallory;
}
