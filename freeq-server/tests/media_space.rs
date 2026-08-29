//! Private media spaces: the feature flag, lazy exactly-once space creation,
//! the space-ref API, and the checkUserAccess membership callback with
//! service-auth verification.
//!
//! The spaces PDS is mocked with a local HTTP server; the DID directory is a
//! static resolver, so no network leaves the machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{DidDocument, DidResolver, make_test_did_document};
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

const AUTHORITY_DID: &str = "did:plc:mediaauthority";
const SERVER_NAME: &str = "test-media";
const LXM: &str = "com.atproto.simplespace.checkUserAccess";

fn managing_app() -> String {
    format!("did:web:{SERVER_NAME}#freeq_media")
}

/// A mock spaces PDS: createSession always succeeds, createSpace succeeds and
/// counts its calls.
async fn mock_pds() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    mock_pds_inner(false).await
}

/// Same as above, but the first createSpace fails the way an aged-out session
/// does: a 400 carrying `ExpiredToken`.
async fn mock_pds_expiring_session() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    mock_pds_inner(true).await
}

async fn mock_pds_inner(expire_first: bool) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let created = Arc::new(AtomicUsize::new(0));
    let counter = created.clone();
    let expired_once = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route(
            "/xrpc/com.atproto.server.createSession",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "accessJwt": "test-token",
                    "refreshJwt": "test-refresh",
                    "did": AUTHORITY_DID,
                    "handle": "media.test",
                }))
            }),
        )
        .route(
            "/xrpc/com.atproto.simplespace.createSpace",
            axum::routing::post(move || {
                let counter = counter.clone();
                let expired_once = expired_once.clone();
                async move {
                    if expire_first && expired_once.fetch_add(1, Ordering::SeqCst) == 0 {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "ExpiredToken",
                                "message": "Token has expired",
                            })),
                        )
                            .into_response();
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({ "uri": "at://created" })).into_response()
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, created)
}

struct Fixture {
    web: std::net::SocketAddr,
    irc: std::net::SocketAddr,
    created: Arc<AtomicUsize>,
    authority_key: PrivateKey,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Boot a server with the feature on: a mock spaces PDS, an authority DID
/// with a known secp256k1 key, and `extra_ids` resolvable for SASL.
async fn fixture_with_ids(extra_ids: &[(&str, &PrivateKey)]) -> Fixture {
    let (pds_addr, created) = mock_pds().await;
    let authority_key = PrivateKey::generate_secp256k1();
    let mut docs: HashMap<String, DidDocument> = HashMap::new();
    docs.insert(
        AUTHORITY_DID.to_string(),
        make_test_did_document(AUTHORITY_DID, &authority_key.public_key_multibase()),
    );
    for (did, key) in extra_ids {
        docs.insert(
            did.to_string(),
            make_test_did_document(did, &key.public_key_multibase()),
        );
    }
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: SERVER_NAME.to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        media_space_did: Some(AUTHORITY_DID.to_string()),
        media_space_password: Some("hunter2".to_string()),
        media_space_pds: Some(format!("http://{pds_addr}")),
        ..Default::default()
    };
    let (irc, web, server) =
        freeq_server::server::Server::with_resolver(config, DidResolver::static_map(docs))
            .start_with_web()
            .await
            .unwrap();
    Fixture {
        web,
        irc,
        created,
        authority_key,
        server,
    }
}

const MEMBER_DID: &str = "did:plc:spacemember";

/// Boot a fixture whose `#open` channel has one authenticated member, and
/// return that member's handle, events and API bearer. Minting a space is a
/// members-only action, so every test that mints one needs this.
async fn fixture_with_member() -> (Fixture, freeq_sdk::client::ClientHandle, String) {
    let key = PrivateKey::generate_ed25519();
    let fx = fixture_with_ids(&[(MEMBER_DID, &key)]).await;
    let (h, bearer) = join_as_member(&fx.irc, MEMBER_DID, &key, "member", "#open").await;
    (fx, h, bearer)
}

/// Connect an authenticated client, join `channel`, and return its bearer.
async fn join_as_member(
    irc: &std::net::SocketAddr,
    did: &str,
    key: &PrivateKey,
    nick: &str,
    channel: &str,
) -> (freeq_sdk::client::ClientHandle, String) {
    let cfg = ConnectConfig {
        server_addr: irc.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (h, mut events) = client::connect(cfg, Some(signer_for(did, key)));
    let bearer = wait_for_bearer(&mut events).await;
    expect_event(
        &mut events,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    h.join(channel).await.unwrap();
    expect_event(&mut events, |e| matches!(e, Event::Joined { .. }), "joined").await;
    // The events receiver is dropped, so the session stays up but unread.
    std::mem::forget(events);
    (h, bearer)
}

/// The API bearer the server hands an authenticated session, from the
/// `API-BEARER <session>` notice that follows SASL success. REST reads of a
/// channel are authorized by this, so a test that wants to act as a member
/// has to hold it.
async fn wait_for_bearer(events: &mut mpsc::Receiver<Event>) -> String {
    timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(Event::ServerNotice { text }) => {
                    if let Some(b) = text.split_whitespace().nth(1)
                        && text.starts_with("API-BEARER")
                    {
                        return b.to_string();
                    }
                }
                Some(_) => continue,
                None => panic!("stream ended before the API bearer arrived"),
            }
        }
    })
    .await
    .expect("timeout waiting for the API bearer")
}

/// A member's GET: the session bearer is what proves channel membership.
async fn get_as(web: std::net::SocketAddr, bearer: &str, path: &str) -> (u16, serde_json::Value) {
    let r = reqwest::Client::new()
        .get(format!("http://{web}{path}"))
        .bearer_auth(bearer)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

fn signer_for(did: &str, key: &PrivateKey) -> Arc<dyn ChallengeSigner> {
    let key = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    Arc::new(KeySigner::new(did.to_string(), key))
}

async fn expect_event(
    events: &mut mpsc::Receiver<Event>,
    pred: impl Fn(&Event) -> bool,
    what: &str,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(e) if pred(&e) => return,
                Some(_) => continue,
                None => panic!("stream ended waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {what}"));
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Mint a service-auth JWT the way the spaces PDS does: signed by `key`,
/// issued by the authority, addressed to this server's managing app.
fn service_jwt(key: &PrivateKey, aud: &str, lxm: &str, exp_offset_secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = b64(br#"{"typ":"JWT","alg":"ES256K"}"#);
    let payload = b64(serde_json::json!({
        "iss": AUTHORITY_DID,
        "aud": aud,
        "lxm": lxm,
        "exp": now + exp_offset_secs,
    })
    .to_string()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(&sig))
}

async fn get(web: std::net::SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let r = reqwest::Client::new()
        .get(format!("http://{web}{path}"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn check_access(
    web: std::net::SocketAddr,
    jwt: Option<&str>,
    space: &str,
    user: &str,
) -> (u16, serde_json::Value) {
    let url = format!(
        "http://{web}/xrpc/com.atproto.simplespace.checkUserAccess?space={}&user={}",
        urlencoding_encode(space),
        urlencoding_encode(user),
    );
    let mut req = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(5));
    if let Some(jwt) = jwt {
        req = req.bearer_auth(jwt);
    }
    let r = req.send().await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// Minimal percent-encoding for the query values used here.
fn urlencoding_encode(s: &str) -> String {
    s.replace('%', "%25")
        .replace('#', "%23")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

// ── Feature off ────────────────────────────────────────────────────────

#[tokio::test]
async fn feature_off_answers_404_everywhere() {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-media-off".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    let (_irc, web, server) = freeq_server::server::Server::with_resolver(
        config,
        DidResolver::static_map(HashMap::new()),
    )
    .start_with_web()
    .await
    .unwrap();

    let (s1, _) = get(web, "/.well-known/did.json").await;
    let (s2, _) = get(web, "/api/v1/media-space?channel=%23open").await;
    let (s3, _) = check_access(web, None, "at://x/space/at.freeq.media/k", "did:plc:x").await;
    assert_eq!((s1, s2, s3), (404, 404, 404));
    server.abort();
}

// ── did:web document ───────────────────────────────────────────────────

#[tokio::test]
async fn did_web_document_names_the_managing_app_service() {
    let fx = fixture_with_ids(&[]).await;
    let (status, doc) = get(fx.web, "/.well-known/did.json").await;
    assert_eq!(status, 200);
    assert_eq!(doc["id"], format!("did:web:{SERVER_NAME}"));
    assert_eq!(doc["service"][0]["id"], "#freeq_media");
    assert_eq!(
        doc["service"][0]["serviceEndpoint"],
        format!("https://{SERVER_NAME}")
    );
    fx.server.abort();
}

// ── OAuth scope surface ────────────────────────────────────────────────

#[tokio::test]
async fn client_metadata_advertises_the_space_scope_only_when_enabled() {
    let fx = fixture_with_ids(&[]).await;
    let (s, meta) = get(fx.web, "/client-metadata.json").await;
    assert_eq!(s, 200);
    let scope = meta["scope"].as_str().unwrap();
    let expected = format!("space:*?authority={AUTHORITY_DID}&collection=*");
    assert!(
        scope.split_whitespace().any(|t| t == expected),
        "feature-on metadata must advertise the space scope; got: {scope}"
    );
    fx.server.abort();

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-media-off".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    let (_irc, web, server) = freeq_server::server::Server::with_resolver(
        config,
        DidResolver::static_map(HashMap::new()),
    )
    .start_with_web()
    .await
    .unwrap();
    let (s, meta) = get(web, "/client-metadata.json").await;
    assert_eq!(s, 200);
    assert!(
        !meta["scope"].as_str().unwrap().contains("space:"),
        "feature-off metadata must not advertise any space scope"
    );
    server.abort();
}

// ── Serving space media ────────────────────────────────────────────────

/// The PDS reports an aged-out session as a 400 carrying `ExpiredToken`.
/// The stale token is dropped and the request made again.
#[tokio::test]
async fn an_expired_authority_session_is_renewed_and_the_space_still_created() {
    let (pds_addr, created) = mock_pds_expiring_session().await;
    let authority_key = PrivateKey::generate_secp256k1();
    let member_key = PrivateKey::generate_ed25519();
    let mut docs: HashMap<String, DidDocument> = HashMap::new();
    docs.insert(
        AUTHORITY_DID.to_string(),
        make_test_did_document(AUTHORITY_DID, &authority_key.public_key_multibase()),
    );
    docs.insert(
        MEMBER_DID.to_string(),
        make_test_did_document(MEMBER_DID, &member_key.public_key_multibase()),
    );
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: SERVER_NAME.to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        media_space_did: Some(AUTHORITY_DID.to_string()),
        media_space_password: Some("hunter2".to_string()),
        media_space_pds: Some(format!("http://{pds_addr}")),
        ..Default::default()
    };
    let (irc, web, server) =
        freeq_server::server::Server::with_resolver(config, DidResolver::static_map(docs))
            .start_with_web()
            .await
            .unwrap();

    let (h, bearer) = join_as_member(&irc, MEMBER_DID, &member_key, "member", "#open").await;

    let (status, body) = get_as(web, &bearer, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(
        status, 200,
        "an expired session must not fail the request: {body}"
    );
    assert!(body["space"].as_str().unwrap().contains("at.freeq.media"));
    assert_eq!(created.load(Ordering::SeqCst), 1, "created after the retry");

    h.quit(None).await.ok();
    server.abort();
}

/// Ensure that an authenticated client can send media and non-members
/// are refused.
#[tokio::test]
async fn only_members_can_post_space_media() {
    let member_key = PrivateKey::generate_ed25519();
    let outsider_key = PrivateKey::generate_ed25519();
    let outsider_did = "did:plc:spaceoutsider";
    let fx = fixture_with_ids(&[(MEMBER_DID, &member_key), (outsider_did, &outsider_key)]).await;
    let (h, _bearer) = join_as_member(&fx.irc, MEMBER_DID, &member_key, "member", "#open").await;

    let post = |did: &str| {
        let form = reqwest::multipart::Form::new()
            .text("did", did.to_string())
            .text("channel", "#open".to_string())
            .text("space_media", "true".to_string())
            .part(
                "file",
                reqwest::multipart::Part::bytes(b"not really a png".to_vec())
                    .file_name("x.png")
                    .mime_str("image/png")
                    .unwrap(),
            );
        reqwest::Client::new()
            .post(format!("http://{}/api/v1/upload", fx.web))
            .multipart(form)
            .timeout(Duration::from_secs(5))
            .send()
    };

    // A DID with no session at all cannot upload anywhere.
    let r = post(outsider_did).await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    assert!(
        status == 401 || status == 403,
        "a stranger must not post: {status} {body}"
    );
    assert_eq!(fx.created.load(Ordering::SeqCst), 0, "nothing was created");

    // An authenticated non-member is refused by the membership gate, not by
    // the step-up path: they are told they are not in the channel.
    let (outsider, _b) = join_as_member(
        &fx.irc,
        outsider_did,
        &outsider_key,
        "outsider",
        "#elsewhere",
    )
    .await;
    let r = post(outsider_did).await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    assert_eq!(status, 403, "non-member: {body}");
    assert!(
        body.contains("Only channel members"),
        "a non-member must be told why, not sent to a step-up: {body}"
    );
    assert_eq!(fx.created.load(Ordering::SeqCst), 0);

    // The member gets past membership and lands on the real next step: they
    // have no space grant yet, so the server asks for one.
    let r = post(MEMBER_DID).await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    assert!(
        body.contains("step_up_required") || body.contains("not_authenticated"),
        "a member must pass the gate and be asked for the grant: {status} {body}"
    );

    outsider.quit(None).await.ok();
    h.quit(None).await.ok();
    fx.server.abort();
}

#[tokio::test]
async fn space_media_urls_carry_no_spaces() {
    let name = freeq_server::media_store::sanitize_filename("Image filename with spaces.png");
    assert!(
        !name.contains(' '),
        "sanitized filename kept a space: {name}"
    );
    assert!(name.ends_with(".png"), "extension must survive: {name}");
}

/// base64url-encode a record URI the way the serve route expects it.
fn encode_ref(uri: &str) -> String {
    URL_SAFE_NO_PAD.encode(uri.as_bytes())
}

#[tokio::test]
async fn space_media_route_rejects_refs_that_are_not_ours() {
    let fx = fixture_with_ids(&[]).await;
    for uri in [
        "at://did:plc:someoneelse/space/at.freeq.media/K1/did:plc:a/at.freeq.media.item/3k",
        "at://did:plc:mediaauthority/space/com.example.other/K1/did:plc:a/c/3k",
        "at://did:plc:mediaauthority/space/at.freeq.media/K1",
    ] {
        let (status, _) = get(
            fx.web,
            &format!("/api/v1/space-media/{}/x.png", encode_ref(uri)),
        )
        .await;
        assert_eq!(status, 400, "must refuse a ref that is not ours: {uri}");
    }
    // Not base64 at all.
    let (status, _) = get(fx.web, "/api/v1/space-media/!!!not-base64!!!/x.png").await;
    assert_eq!(status, 400);
    fx.server.abort();
}

#[tokio::test]
async fn space_media_route_404s_for_an_unknown_space() {
    let fx = fixture_with_ids(&[]).await;
    // Well-formed and ours, but no channel owns this space key.
    let uri = format!(
        "at://{AUTHORITY_DID}/space/at.freeq.media/NOSUCHKEY/did:plc:a/at.freeq.media.item/3k"
    );
    let (status, _) = get(
        fx.web,
        &format!("/api/v1/space-media/{}/x.png", encode_ref(&uri)),
    )
    .await;
    assert_eq!(status, 404);
    fx.server.abort();
}

#[tokio::test]
async fn space_media_route_refuses_anonymous_reads_of_a_restricted_channel() {
    let member_key = PrivateKey::generate_ed25519();
    let fx = fixture_with_ids(&[(MEMBER_DID, &member_key)]).await;
    let (h, bearer) = join_as_member(&fx.irc, MEMBER_DID, &member_key, "own", "#priv").await;

    // Mint the space while the channel is still public, then lock it.
    let (s, body) = get_as(fx.web, &bearer, "/api/v1/media-space?channel=%23priv").await;
    assert_eq!(s, 200);
    let space = body["space"].as_str().unwrap().to_string();
    let key = space.rsplit('/').next().unwrap().to_string();
    h.mode("#priv", "+k", Some("sekrit")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let uri =
        format!("at://{AUTHORITY_DID}/space/at.freeq.media/{key}/did:plc:a/at.freeq.media.item/3k");
    let (status, _) = get(
        fx.web,
        &format!("/api/v1/space-media/{}/x.png", encode_ref(&uri)),
    )
    .await;
    assert_eq!(
        status, 403,
        "an anonymous caller must not read a restricted channel's media"
    );

    h.quit(None).await.ok();
    fx.server.abort();
}

#[tokio::test]
async fn health_reports_whether_media_spaces_are_configured() {
    let fx = fixture_with_ids(&[]).await;
    let (s, body) = get(fx.web, "/api/v1/health").await;
    assert_eq!(s, 200);
    assert_eq!(body["media_spaces"], true);
    fx.server.abort();

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-media-off".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    let (_irc, web, server) = freeq_server::server::Server::with_resolver(
        config,
        DidResolver::static_map(HashMap::new()),
    )
    .start_with_web()
    .await
    .unwrap();
    let (s, body) = get(web, "/api/v1/health").await;
    assert_eq!(s, 200);
    assert_eq!(body["media_spaces"], false);
    // And the serve route is gone entirely.
    let (status, _) = get(web, "/api/v1/space-media/abc/x.png").await;
    assert_eq!(status, 404);
    server.abort();
}

// ── Lazy creation via the space-ref API ────────────────────────────────

#[tokio::test]
async fn first_use_creates_exactly_one_space_and_persists_it() {
    let (fx, h, bearer) = fixture_with_member().await;

    // Two concurrent first requests race the creation.
    let (a, b) = tokio::join!(
        get_as(fx.web, &bearer, "/api/v1/media-space?channel=%23open"),
        get_as(fx.web, &bearer, "/api/v1/media-space?channel=%23open"),
    );
    assert_eq!(a.0, 200, "first: {:?}", a.1);
    assert_eq!(b.0, 200, "second: {:?}", b.1);
    assert_eq!(
        a.1["space"], b.1["space"],
        "both callers must see one space"
    );
    assert_eq!(a.1["type"], "at.freeq.media");
    let space = a.1["space"].as_str().unwrap().to_string();
    assert!(
        space.starts_with(&format!("at://{AUTHORITY_DID}/space/at.freeq.media/")),
        "unexpected space ref: {space}"
    );
    assert_eq!(fx.created.load(Ordering::SeqCst), 1, "createSpace ran once");

    // A later request returns the stored ref without creating again.
    let (s, body) = get_as(fx.web, &bearer, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(s, 200);
    assert_eq!(body["space"].as_str().unwrap(), space);
    assert_eq!(fx.created.load(Ordering::SeqCst), 1);

    h.quit(None).await.ok();
    fx.server.abort();
}

/// Minting a space writes to the operator's PDS, so only a member may cause
/// one. A public channel is readable by anyone, which is exactly why the
/// read rule alone is not enough here.
#[tokio::test]
async fn only_members_can_mint_a_space() {
    let (fx, h, bearer) = fixture_with_member().await;

    let (status, _) = get(fx.web, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(
        status, 401,
        "an anonymous caller must not be able to create a space"
    );
    assert_eq!(fx.created.load(Ordering::SeqCst), 0, "nothing was created");

    let (status, _) = get_as(
        fx.web,
        "not-a-real-bearer",
        "/api/v1/media-space?channel=%23open",
    )
    .await;
    assert_eq!(status, 401, "an unknown bearer must not either");
    assert_eq!(fx.created.load(Ordering::SeqCst), 0);

    // The member can.
    let (status, _) = get_as(fx.web, &bearer, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(status, 200);
    assert_eq!(fx.created.load(Ordering::SeqCst), 1);

    h.quit(None).await.ok();
    fx.server.abort();
}

#[tokio::test]
async fn space_key_survives_a_server_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("media.db").to_str().unwrap().to_string();
    let (pds_addr, created) = mock_pds().await;
    let authority_key = PrivateKey::generate_secp256k1();
    let member_key = PrivateKey::generate_ed25519();
    let mut docs: HashMap<String, DidDocument> = HashMap::new();
    docs.insert(
        AUTHORITY_DID.to_string(),
        make_test_did_document(AUTHORITY_DID, &authority_key.public_key_multibase()),
    );
    docs.insert(
        MEMBER_DID.to_string(),
        make_test_did_document(MEMBER_DID, &member_key.public_key_multibase()),
    );
    let config = || freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: SERVER_NAME.to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.clone()),
        media_space_did: Some(AUTHORITY_DID.to_string()),
        media_space_password: Some("hunter2".to_string()),
        media_space_pds: Some(format!("http://{pds_addr}")),
        ..Default::default()
    };

    // First boot: hold #open resident, mint its space.
    let (irc, web, server) = freeq_server::server::Server::with_resolver(
        config(),
        DidResolver::static_map(docs.clone()),
    )
    .start_with_web()
    .await
    .unwrap();
    let (h, bearer) = join_as_member(&irc, MEMBER_DID, &member_key, "member", "#open").await;
    let (s, body) = get_as(web, &bearer, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(s, 200);
    let space = body["space"].as_str().unwrap().to_string();
    h.quit(None).await.ok();
    server.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second boot: the channel has no history, topic, or modes — only its
    // space key. The empty-channel prune must keep it, and the same space
    // ref must come back without another createSpace on the PDS.
    let (irc2, web2, server2) =
        freeq_server::server::Server::with_resolver(config(), DidResolver::static_map(docs))
            .start_with_web()
            .await
            .unwrap();
    let (h2, bearer2) = join_as_member(&irc2, MEMBER_DID, &member_key, "member", "#open").await;
    let (s, body) = get_as(web2, &bearer2, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(s, 200, "channel with a space must survive the boot prune");
    assert_eq!(
        body["space"].as_str().unwrap(),
        space,
        "space key must persist"
    );
    assert_eq!(created.load(Ordering::SeqCst), 1, "no second createSpace");
    h2.quit(None).await.ok();
    server2.abort();
}

#[tokio::test]
async fn space_ref_api_refuses_anonymous_reads_of_restricted_channels() {
    let fx = fixture_with_ids(&[]).await;
    let config = ConnectConfig {
        server_addr: fx.irc.to_string(),
        nick: "own".to_string(),
        user: "own".to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (h, mut events) = client::connect(config, None);
    expect_event(
        &mut events,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    h.join("#priv").await.unwrap();
    expect_event(&mut events, |e| matches!(e, Event::Joined { .. }), "joined").await;
    h.mode("#priv", "+k", Some("sekrit")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (status, _) = get(fx.web, "/api/v1/media-space?channel=%23priv").await;
    assert_eq!(
        status, 403,
        "anonymous caller got a restricted channel's space ref"
    );
    assert_eq!(
        fx.created.load(Ordering::SeqCst),
        0,
        "no space for refused request"
    );

    h.quit(None).await.ok();
    fx.server.abort();
}

// ── checkUserAccess ────────────────────────────────────────────────────

#[tokio::test]
async fn check_user_access_follows_live_channel_membership() {
    let alice_key = PrivateKey::generate_ed25519();
    let alice_did = "did:plc:alicemedia";
    let fx = fixture_with_ids(&[(alice_did, &alice_key)]).await;

    // A guest creates and holds #open (guest founder: nobody's DID owns it),
    // then authenticated alice joins.
    let guest_cfg = ConnectConfig {
        server_addr: fx.irc.to_string(),
        nick: "holder".to_string(),
        user: "holder".to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (guest, mut guest_events) = client::connect(guest_cfg, None);
    expect_event(
        &mut guest_events,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    guest.join("#open").await.unwrap();
    expect_event(
        &mut guest_events,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    let alice_cfg = ConnectConfig {
        server_addr: fx.irc.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (alice, mut alice_events) =
        client::connect(alice_cfg, Some(signer_for(alice_did, &alice_key)));
    let alice_bearer = wait_for_bearer(&mut alice_events).await;
    expect_event(
        &mut alice_events,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    alice.join("#open").await.unwrap();
    expect_event(
        &mut alice_events,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    let (s, body) = get_as(fx.web, &alice_bearer, "/api/v1/media-space?channel=%23open").await;
    assert_eq!(s, 200);
    let space = body["space"].as_str().unwrap().to_string();
    let jwt = service_jwt(&fx.authority_key, &managing_app(), LXM, 60);

    // Member: authorized.
    let (s, body) = check_access(fx.web, Some(&jwt), &space, alice_did).await;
    assert_eq!(s, 200);
    assert_eq!(
        body["authorized"], true,
        "member must be authorized: {body}"
    );

    // A DID that never joined: denied.
    let (s, body) = check_access(fx.web, Some(&jwt), &space, "did:plc:stranger").await;
    assert_eq!(s, 200);
    assert_eq!(body["authorized"], false, "stranger must be denied");

    // A space this server is not the authority for: denied.
    let (s, body) = check_access(
        fx.web,
        Some(&jwt),
        "at://did:plc:other/space/at.freeq.media/xyz",
        alice_did,
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(body["authorized"], false, "foreign space must be denied");

    // Alice parts: access ends with membership.
    alice.raw("PART #open").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (s, body) = check_access(fx.web, Some(&jwt), &space, alice_did).await;
    assert_eq!(s, 200);
    assert_eq!(
        body["authorized"], false,
        "departed member must be denied: {body}"
    );

    alice.quit(None).await.ok();
    guest.quit(None).await.ok();
    fx.server.abort();
}

#[tokio::test]
async fn check_user_access_rejects_bad_service_auth() {
    let fx = fixture_with_ids(&[]).await;
    let space = format!("at://{AUTHORITY_DID}/space/at.freeq.media/somekey");

    // No token.
    let (s, _) = check_access(fx.web, None, &space, "did:plc:x").await;
    assert_eq!(s, 401);

    // Signed by the wrong key.
    let wrong = PrivateKey::generate_secp256k1();
    let (s, _) = check_access(
        fx.web,
        Some(&service_jwt(&wrong, &managing_app(), LXM, 60)),
        &space,
        "did:plc:x",
    )
    .await;
    assert_eq!(s, 401, "foreign signature must be rejected");

    // Wrong audience.
    let (s, _) = check_access(
        fx.web,
        Some(&service_jwt(
            &fx.authority_key,
            "did:web:elsewhere#other",
            LXM,
            60,
        )),
        &space,
        "did:plc:x",
    )
    .await;
    assert_eq!(s, 401, "wrong-audience token must be rejected");

    // Wrong method binding.
    let (s, _) = check_access(
        fx.web,
        Some(&service_jwt(
            &fx.authority_key,
            &managing_app(),
            "com.atproto.other.method",
            60,
        )),
        &space,
        "did:plc:x",
    )
    .await;
    assert_eq!(s, 401, "wrong-lxm token must be rejected");

    // Expired.
    let (s, _) = check_access(
        fx.web,
        Some(&service_jwt(&fx.authority_key, &managing_app(), LXM, -60)),
        &space,
        "did:plc:x",
    )
    .await;
    assert_eq!(s, 401, "expired token must be rejected");

    fx.server.abort();
}
