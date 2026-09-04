//! REST authorization: private-channel data must not be readable by anonymous
//! HTTP callers.
//!
//! `/history`, `/export`, `/evidence` and `/messages/{msgid}` all funnel through
//! `authorize_channel_read`, which fails closed for a mode-restricted channel
//! (`+i`, `+k`, or encrypted-only) unless the bearer resolves to a member, op or
//! founder. Several sibling endpoints were added later and never wired to it —
//! some don't even accept `headers`, so they *cannot* authorize.
//!
//! These tests pin the rule for every channel-scoped read endpoint, and include
//! public-channel controls so a fix can't simply lock everything down.

use std::collections::HashMap;
use std::time::Duration;

use std::sync::Arc;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn start_test_server_with_web(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-rest-authz".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start_with_web()
        .await
        .unwrap()
}

fn empty_resolver() -> DidResolver {
    DidResolver::static_map(HashMap::new())
}

async fn expect_event(
    events: &mut mpsc::Receiver<Event>,
    ms: u64,
    predicate: impl Fn(&Event) -> bool,
    what: &str,
) {
    let deadline = Duration::from_millis(ms);
    let start = tokio::time::Instant::now();
    loop {
        let left = deadline.saturating_sub(start.elapsed());
        assert!(!left.is_zero(), "timeout waiting for {what}");
        match timeout(left, events.recv()).await {
            Ok(Some(e)) if predicate(&e) => return,
            Ok(Some(_)) => continue,
            _ => panic!("stream ended waiting for {what}"),
        }
    }
}

/// Bring up a server + a `+k`-locked channel with a topic, and a public control
/// channel. Returns the web address.
async fn fixture() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (addr, web_addr, handle) = start_test_server_with_web(empty_resolver()).await;

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (h, mut events) = client::connect(config, None);
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;

    // Private: mode-restricted via a channel key. The creator holds ops.
    h.join("#secretplan").await.unwrap();
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "joined #secretplan",
    )
    .await;
    h.topic("#secretplan", "acquisition of Initech — do not leak")
        .await
        .unwrap();
    h.mode("#secretplan", "+k", Some("hunter2")).await.unwrap();

    // Public control channel.
    h.join("#townsquare").await.unwrap();
    h.topic("#townsquare", "welcome all").await.unwrap();

    // Let the mode/topic settle before anyone reads over HTTP.
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.quit(None).await.ok();
    (web_addr, handle)
}

async fn get(web: std::net::SocketAddr, path: &str) -> (u16, String) {
    let r = reqwest::Client::new()
        .get(format!("http://{web}{path}"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.text().await.unwrap_or_default())
}

/// The web app refuses to start sign-in unless `<auth origin>/health` answers
/// OK. On a server with embedded auth that origin is the server itself, so
/// `/health` must be a real route, not a path the SPA fallback happens to
/// answer for.
#[tokio::test]
async fn health_is_served_at_the_root_for_the_sign_in_preflight() {
    let (_addr, web, _handle) = start_test_server_with_web(empty_resolver()).await;
    let (status, body) = get(web, "/health").await;
    assert_eq!(status, 200, "GET /health answered {status}: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("health is JSON");
    assert!(
        json.get("git_commit").is_some(),
        "health carries the build: {body}"
    );
}

#[tokio::test]
async fn private_channel_topic_is_not_public() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/secretplan/topic").await;
    assert!(
        status == 403 || status == 404,
        "anonymous GET of a +k channel's topic returned {status}: {body}\n\
         api_channel_topic takes no headers, so it cannot authorize — it hands \
         out the topic of any channel, including mode-restricted ones."
    );
    assert!(
        !body.contains("Initech"),
        "private topic text leaked to an anonymous caller: {body}"
    );
    server.abort();
}

#[tokio::test]
async fn private_channel_audit_log_is_not_public() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/secretplan/audit").await;
    assert!(
        status == 403 || status == 404,
        "anonymous GET of a +k channel's AUDIT timeline returned {status}: {body}\n\
         api_channel_audit takes no headers. The audit timeline carries \
         coordination events, actor DIDs, signatures and payloads — the \
         governance history of a private room."
    );
    server.abort();
}

#[tokio::test]
async fn private_channel_coordination_events_are_not_public() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/secretplan/events").await;
    assert!(
        status == 403 || status == 404,
        "anonymous GET of a +k channel's coordination events returned {status}: {body}\n\
         api_channel_events takes no headers — signed task cards and agent \
         activity for a private channel are world-readable."
    );
    server.abort();
}

#[tokio::test]
async fn private_channel_pins_are_not_public() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/secretplan/pins").await;
    assert!(
        status == 403 || status == 404,
        "anonymous GET of a +k channel's pins returned {status}: {body}"
    );
    server.abort();
}

#[tokio::test]
async fn private_channel_sessions_are_not_public() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/secretplan/sessions").await;
    assert!(
        status == 403 || status == 404,
        "anonymous GET of a +k channel's session/member list returned {status}: {body}\n\
         membership of a private channel is itself sensitive."
    );
    server.abort();
}

/// Control: the endpoints that were already wired to `authorize_channel_read`
/// must keep refusing. If this ever fails, the shared guard regressed.
#[tokio::test]
async fn private_channel_history_and_export_stay_locked() {
    let (web, server) = fixture().await;
    for path in [
        "/api/v1/channels/secretplan/history",
        "/api/v1/channels/secretplan/export",
    ] {
        let (status, body) = get(web, path).await;
        assert!(
            status == 403 || status == 404,
            "{path} should be locked for anonymous callers, got {status}: {body}"
        );
    }
    server.abort();
}

/// Control: locking the private endpoints must not break public channels.
#[tokio::test]
async fn public_channel_reads_still_work() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels/townsquare/topic").await;
    assert_eq!(
        status, 200,
        "public channel topic must stay readable, got {status}: {body}"
    );
    assert!(
        body.contains("welcome all"),
        "public topic missing from response: {body}"
    );
    for path in [
        "/api/v1/channels/townsquare/events",
        "/api/v1/channels/townsquare/audit",
        "/api/v1/channels/townsquare/pins",
    ] {
        let (status, body) = get(web, path).await;
        assert_eq!(
            status, 200,
            "public channel {path} must stay readable, got {status}: {body}"
        );
    }
    server.abort();
}

/// The governance family: approvals, budget, spend and agent capabilities.
/// None of these accepted a `HeaderMap` either, so a private channel's
/// operational state — what its agents may do, what it has spent, what is
/// awaiting a human decision — was readable by anyone.
#[tokio::test]
async fn private_channel_governance_endpoints_are_not_public() {
    let (web, server) = fixture().await;
    for path in [
        "/api/v1/channels/secretplan/approvals",
        "/api/v1/channels/secretplan/budget",
        "/api/v1/channels/secretplan/spend",
        "/api/v1/channels/secretplan/agent-capabilities",
    ] {
        let (status, body) = get(web, path).await;
        assert!(
            status == 403 || status == 404,
            "anonymous GET {path} returned {status}: {body}"
        );
    }
    server.abort();
}

/// Control: the same governance endpoints must keep working for a public
/// channel, so the fix doesn't blind legitimate dashboards.
#[tokio::test]
async fn public_channel_governance_endpoints_still_work() {
    let (web, server) = fixture().await;
    for path in [
        "/api/v1/channels/townsquare/approvals",
        "/api/v1/channels/townsquare/budget",
        "/api/v1/channels/townsquare/spend",
        "/api/v1/channels/townsquare/agent-capabilities",
    ] {
        let (status, body) = get(web, path).await;
        assert_eq!(status, 200, "public {path} returned {status}: {body}");
    }
    server.abort();
}

/// The unauthenticated channel *list* must not name a private channel.
/// (`api_channels` already filters on `channel_is_discoverable`; this pins it,
/// because it's the one place a private channel's existence would leak wholesale.)
#[tokio::test]
async fn channel_list_hides_private_channels() {
    let (web, server) = fixture().await;
    let (status, body) = get(web, "/api/v1/channels").await;
    assert_eq!(status, 200, "channel list should be public: {body}");
    assert!(
        !body.contains("secretplan"),
        "private channel leaked into the public channel list: {body}"
    );
    assert!(
        body.contains("townsquare"),
        "public channel missing from the list: {body}"
    );
    server.abort();
}

/// `POST /api/v1/sessions/{id}/artifacts` took no auth at all. Three problems,
/// all reachable by anyone who knows a session id (which channel members see in
/// av-* TAGMSGs, and which the sessions endpoint hands out for public channels):
///
///   1. unauthenticated write into the AV/provenance store;
///   2. `created_by` is read straight from the request body, so the caller
///      chooses whose DID the artifact is attributed to — attribution forgery in
///      the layer whose entire value proposition is verifiable authorship; and
///   3. it broadcasts a NOTICE into the session's channel with caller-controlled
///      text, i.e. unauthenticated message injection into a room.
#[tokio::test]
async fn creating_a_session_artifact_requires_auth() {
    let (irc_addr, web, server) = start_test_server_with_web(empty_resolver()).await;

    // AV sessions require an authenticated DID — guests cannot start calls.
    let private_key = PrivateKey::generate_ed25519();
    let did = format!("did:key:{}", private_key.public_key_multibase());
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did, private_key));
    let config = ConnectConfig {
        server_addr: irc_addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (h, mut events) = client::connect(config, Some(signer));
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "authenticated",
    )
    .await;
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    h.join("#callroom").await.unwrap();
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    // Start a real AV session so the handler can't refuse with a plain 404.
    let mut tags = HashMap::new();
    tags.insert("+freeq.at/av-start".to_string(), String::new());
    tags.insert("+freeq.at/av-instance".to_string(), "aaaa1111".to_string());
    h.send_tagmsg("#callroom", tags).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (status, body) = get(web, "/api/v1/channels/callroom/sessions").await;
    assert_eq!(status, 200, "sessions list for a public channel: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let session_id = v["active"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no active session in {body}"))
        .to_string();

    // Anonymous caller forges an artifact attributed to someone else, with text
    // it controls, into a channel it is not even a member of.
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{web}/api/v1/sessions/{session_id}/artifacts"
        ))
        .json(&serde_json::json!({
            "kind": "summary",
            "content_ref": "https://evil.example/payload",
            "title": "URGENT: verify your account at evil.example",
            "created_by": "did:plc:chadfowler-impersonated",
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status == 401 || status == 403,
        "anonymous POST of a session artifact returned {status}: {body}\n\
         No authentication, and created_by comes from the request body."
    );

    // …and nothing may have been injected into the channel.
    let injected = {
        let deadline = Duration::from_millis(800);
        let start = tokio::time::Instant::now();
        let mut seen = false;
        loop {
            let left = deadline.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            match timeout(left, events.recv()).await {
                Ok(Some(Event::ServerNotice { text, .. })) if text.contains("evil.example") => {
                    seen = true;
                    break;
                }
                Ok(Some(Event::Message { text, .. })) if text.contains("evil.example") => {
                    seen = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        seen
    };
    assert!(
        !injected,
        "an unauthenticated HTTP caller injected text into #callroom via the \
         artifact NOTICE broadcast"
    );

    h.quit(None).await.ok();
    server.abort();
}

/// Every other channel endpoint takes a bare name and prefixes `#` itself.
/// `api_channel_sessions` passed the raw path segment straight to
/// `active_session_for_channel` / `list_channel_av_sessions`, while sessions are
/// stored under the `#`-prefixed channel — so it reported "no calls" for every
/// channel unless the caller URL-encoded the `#`.
#[tokio::test]
async fn channel_sessions_endpoint_accepts_a_bare_channel_name() {
    let (irc_addr, web, server) = start_test_server_with_web(empty_resolver()).await;

    let private_key = PrivateKey::generate_ed25519();
    let did = format!("did:key:{}", private_key.public_key_multibase());
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did, private_key));
    let config = ConnectConfig {
        server_addr: irc_addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (h, mut events) = client::connect(config, Some(signer));
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "authenticated",
    )
    .await;
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    h.join("#callroom").await.unwrap();
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;
    let mut tags = HashMap::new();
    tags.insert("+freeq.at/av-start".to_string(), String::new());
    tags.insert("+freeq.at/av-instance".to_string(), "aaaa1111".to_string());
    h.send_tagmsg("#callroom", tags).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (status, body) = get(web, "/api/v1/channels/callroom/sessions").await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["active"].get("id").and_then(|i| i.as_str()).is_some(),
        "bare channel name found no active session, but one is running: {body}\n\
         (the same request with %23callroom does return it)"
    );

    h.quit(None).await.ok();
    server.abort();
}
