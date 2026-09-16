//! Signing a device out where the broker is a separate service.
//!
//! The device's login token is refused here from then on, including after a
//! restart on the same database, and the broker is asked to delete the
//! session behind it.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;
use freeq_auth_broker::token_hash;
use freeq_sdk::did::DidResolver;
use freeq_server::server::SharedState;

const SECRET: &str = "test-signout-shared-secret";

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

/// A broker that checks the signature the way the real one does, then records
/// the hash it was asked to delete.
async fn fake_broker() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/session/delete",
        post(move |headers: HeaderMap, body: Bytes| {
            let cap = Arc::clone(&cap);
            async move {
                let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
                if freeq_auth_broker::verify_signed_body(
                    SECRET,
                    header("x-broker-timestamp"),
                    header("x-broker-signature"),
                    &body,
                )
                .is_err()
                {
                    return (axum::http::StatusCode::UNAUTHORIZED, "bad signature").into_response();
                }
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                cap.lock()
                    .unwrap()
                    .push(json["token_hash"].as_str().unwrap().to_string());
                axum::Json(serde_json::json!({ "ok": true })).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{port}"), seen)
}

/// A server in standalone-broker mode on `db_path`, pointed at `broker_url`.
async fn start(db_path: &str, broker_url: &str) -> (SocketAddr, SocketAddr, Arc<SharedState>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-signout".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.to_string()),
        broker_shared_secret: Some(SECRET.to_string()),
        auth_broker_url: Some(broker_url.to_string()),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(
        config,
        DidResolver::static_map(HashMap::new()),
    );
    let (irc, web, _handle, state) = server.start_with_web_state().await.unwrap();
    (irc, web, state)
}

/// The broker's web-token push, signed as the real broker signs it.
async fn push_web_token(web: SocketAddr, broker_token: Option<&str>) -> reqwest::Response {
    let body = serde_json::json!({
        "did": "did:plc:signout",
        "handle": "alice.bsky.social",
        "broker_token": broker_token,
    });
    let (sig, ts) = freeq_auth_broker::sign_body(SECRET, &body).unwrap();
    http()
        .post(format!("http://{web}/auth/broker/web-token"))
        .header("X-Broker-Signature", sig)
        .header("X-Broker-Timestamp", ts)
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// The same push, for a device that is expected to get a token.
async fn web_token(web: SocketAddr, broker_token: Option<&str>) -> String {
    let resp = push_web_token(web, broker_token).await;
    assert_eq!(resp.status(), 200, "the push must mint a token");
    let json: serde_json::Value = resp.json().await.unwrap();
    json["token"].as_str().unwrap().to_string()
}

/// Wait up to five seconds for `cond`.
async fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cond()
}

/// A raw IRC client that authenticates with a web token.
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
}

#[tokio::test]
async fn signing_a_device_out_deletes_its_broker_session_and_outlives_a_restart() {
    let (broker_url, seen) = fake_broker().await;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp); // outlives both servers
    let (irc, web, _state) = start(&db_path, &broker_url).await;

    // The device: a login token, a connection, a signing key.
    let device_token = web_token(web, Some("BT-DEVICE")).await;
    let key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let kid = tokio::task::spawn_blocking(move || {
        let mut c = Irc::connect(irc, "alice", &device_token);
        c.msgsig(&key)
    })
    .await
    .unwrap();

    // Another session of the same account presses Sign out.
    let other_token = web_token(web, None).await;
    let other = tokio::task::spawn_blocking(move || Irc::connect(irc, "alice2", &other_token))
        .await
        .unwrap();
    let resp = http()
        .post(format!("http://{web}/api/v1/devices/sign-out"))
        .header("authorization", format!("Bearer {}", other.bearer))
        .json(&serde_json::json!({ "kid": kid }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "sign-out answered: {body}");
    assert_eq!(body["tokens_revoked"], 1);

    // The broker is asked to delete that session, by hash.
    let hash = token_hash("BT-DEVICE");
    assert!(
        wait_for(|| seen.lock().unwrap().contains(&hash)).await,
        "the broker must be asked to delete the device's session"
    );

    // The device's next web-token push is refused.
    assert_eq!(push_web_token(web, Some("BT-DEVICE")).await.status(), 401);

    // And so is the one after a restart on the same database.
    let (_irc2, web2, _state2) = start(&db_path, &broker_url).await;
    assert_eq!(
        push_web_token(web2, Some("BT-DEVICE")).await.status(),
        401,
        "a restart must not forget the sign-out"
    );
    // A token that was never signed out still works there.
    assert_eq!(push_web_token(web2, Some("BT-OTHER")).await.status(), 200);
}
