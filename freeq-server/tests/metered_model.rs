//! The metered model path: where authority becomes spend.
//!
//! freeq could describe a loan of capacity long before it could make one. A channel
//! budget named a sponsor, limits followed the delegation chain, and spend reports
//! were signed — but an agent called the model with its own credential and then told
//! freeq what it claimed to have cost. The budget system was metered and unmediated;
//! the one path holding a provider key was mediated and unmetered.
//!
//! These tests pin the join. A mock provider stands in for OpenAI so the whole
//! round trip is exercised: the server holds the credential, the caller holds only
//! an identity, the budget is checked *before* dispatch, and the charge is computed
//! from the provider's token counts rather than the caller's word.
//!
//! The distinction that matters throughout: a refusal here means no upstream request
//! is made. That is verified directly by counting the mock's hits, because "we asked
//! the agent to stop" and "no money was spent" are different claims.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// A stand-in provider that counts how many times it was actually called.
#[derive(Clone)]
struct MockProvider {
    hits: Arc<AtomicUsize>,
    prompt_tokens: u64,
    completion_tokens: u64,
}

async fn start_mock_provider(
    prompt_tokens: u64,
    completion_tokens: u64,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let mock = MockProvider {
        hits: hits.clone(),
        prompt_tokens,
        completion_tokens,
    };
    let app = axum::Router::new()
        .route(
            "/chat/completions",
            axum::routing::post(
                |axum::extract::State(m): axum::extract::State<MockProvider>,
                 headers: axum::http::HeaderMap,
                 axum::Json(_body): axum::Json<serde_json::Value>| async move {
                    m.hits.fetch_add(1, Ordering::SeqCst);
                    // The proxy must present the server's credential, not the
                    // caller's; a caller that could reach upstream directly would
                    // make the whole exercise pointless.
                    assert!(
                        headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|v| v.contains("server-side-secret")),
                        "proxy did not present the server's provider credential"
                    );
                    axum::Json(serde_json::json!({
                        "id": "chatcmpl-mock",
                        "choices": [{ "message": { "role": "assistant", "content": "ok" } }],
                        "usage": {
                            "prompt_tokens": m.prompt_tokens,
                            "completion_tokens": m.completion_tokens,
                        }
                    }))
                },
            ),
        )
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, hits, handle)
}

async fn start_server(
    provider: SocketAddr,
) -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let mut model_prices = HashMap::new();
    model_prices.insert(
        "test-model".to_string(),
        freeq_server::model_proxy::ModelPrice {
            input_per_1k: 1.0,
            output_per_1k: 2.0,
        },
    );
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-metered".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        llm_api_key: Some("server-side-secret".to_string()),
        llm_base_url: Some(format!("http://{provider}")),
        model_prices,
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, DidResolver::static_map(HashMap::new()))
        .start_with_web()
        .await
        .unwrap()
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

/// Connect a did:key client and return (did, handle, events, session bearer).
///
/// The bearer is the session id, which the server volunteers as
/// `NOTICE * :API-BEARER <session_id>` right after SASL succeeds. REST callers need
/// it because the HTTP side authenticates a session rather than re-doing SASL.
async fn connect(
    addr: SocketAddr,
    nick: &str,
) -> (String, client::ClientHandle, mpsc::Receiver<Event>, String) {
    let private_key = PrivateKey::generate_ed25519();
    let multibase = private_key.public_key_multibase();
    let did = format!("did:key:{multibase}");
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.clone(), private_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("{nick} test"),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;

    // Collect the bearer while waiting for authentication to land.
    let mut bearer = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(4000);
    let mut authed = false;
    while tokio::time::Instant::now() < deadline && (!authed || bearer.is_empty()) {
        match timeout(Duration::from_millis(400), events.recv()).await {
            Ok(Some(e)) => {
                if matches!(e, Event::Authenticated { .. }) {
                    authed = true;
                }
                let text = format!("{e:?}");
                if let Some(idx) = text.find("API-BEARER ") {
                    let rest = &text[idx + "API-BEARER ".len()..];
                    bearer = rest
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\\')
                        .collect();
                }
            }
            _ => continue,
        }
    }
    assert!(authed, "{nick} did not authenticate");
    assert!(!bearer.is_empty(), "{nick} never received an API bearer");
    (did, handle, events, bearer)
}

async fn post_model(
    web: SocketAddr,
    bearer: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let r = reqwest::Client::new()
        .post(format!("http://{web}/api/v1/model/chat/completions"))
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    let v: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// The whole point: a caller with no provider credential gets a model answer, and
/// the cost lands on the channel's budget computed from the provider's own counts.
#[tokio::test]
async fn a_metered_call_is_charged_to_the_channel_budget() {
    let (provider, hits, _p) = start_mock_provider(2000, 1000).await;
    let (irc, web, server) = start_server(provider).await;

    let (_did, c, mut ev, bearer) = connect(irc, "borrower").await;
    c.join("#lend").await.unwrap();
    expect_event(&mut ev, 2000, |e| matches!(e, Event::Joined { .. }), "join").await;
    c.raw("BUDGET #lend max=10;unit=usd;period=per_day;hard=true")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (status, body) = post_model(
        web,
        &bearer,
        serde_json::json!({
            "channel": "#lend",
            "model": "test-model",
            "messages": [{ "role": "user", "content": "hello" }]
        }),
    )
    .await;

    assert_eq!(status, 200, "metered call rejected: {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "provider not called once");
    // 2000 input @ 1.0/1k + 1000 output @ 2.0/1k = 2.0 + 2.0
    let charged = body["freeq"]["charged"].as_f64().unwrap_or(-1.0);
    assert!(
        (charged - 4.0).abs() < 1e-9,
        "charge not computed from provider usage: {body}"
    );
    assert_eq!(body["freeq"]["unit"], "usd");

    c.quit(None).await.ok();
    server.abort();
}

/// A hard limit has to mean the call does not happen. Anything else is a request.
#[tokio::test]
async fn an_exhausted_budget_stops_the_call_before_any_money_is_spent() {
    let (provider, hits, _p) = start_mock_provider(2000, 1000).await;
    let (irc, web, server) = start_server(provider).await;

    let (_did, c, mut ev, bearer) = connect(irc, "spender").await;
    c.join("#tight").await.unwrap();
    expect_event(&mut ev, 2000, |e| matches!(e, Event::Joined { .. }), "join").await;
    // A budget smaller than one call costs.
    c.raw("BUDGET #tight max=1;unit=usd;period=per_day;hard=true")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (status, body) = post_model(
        web,
        &bearer,
        serde_json::json!({
            "channel": "#tight",
            "model": "test-model",
            "messages": [{ "role": "user", "content": "hello" }],
            "max_tokens": 1000
        }),
    )
    .await;

    assert_eq!(
        status, 402,
        "expected payment required, got {status}: {body}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream was called despite the budget refusing it"
    );

    c.quit(None).await.ok();
    server.abort();
}

/// Fail closed. Without a budget nobody has authorised any spending.
#[tokio::test]
async fn no_budget_means_no_capacity() {
    let (provider, hits, _p) = start_mock_provider(10, 10).await;
    let (irc, web, server) = start_server(provider).await;

    let (_did, c, mut ev, bearer) = connect(irc, "hopeful").await;
    c.join("#unfunded").await.unwrap();
    expect_event(&mut ev, 2000, |e| matches!(e, Event::Joined { .. }), "join").await;

    let (status, body) = post_model(
        web,
        &bearer,
        serde_json::json!({
            "channel": "#unfunded",
            "model": "test-model",
            "messages": [{ "role": "user", "content": "hi" }]
        }),
    )
    .await;

    assert_eq!(status, 402, "unfunded channel served capacity: {body}");
    assert_eq!(body["detail"]["reason"], "no_budget");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream called with no budget"
    );

    c.quit(None).await.ok();
    server.abort();
}

/// Naming a channel you are not in must not draw on its budget, or a loan is
/// available to anyone who can guess a channel name.
#[tokio::test]
async fn an_outsider_cannot_draw_on_a_channels_budget() {
    let (provider, hits, _p) = start_mock_provider(10, 10).await;
    let (irc, web, server) = start_server(provider).await;

    let (_owner_did, owner, mut owner_ev, _owner_bearer) = connect(irc, "funder").await;
    owner.join("#members").await.unwrap();
    expect_event(
        &mut owner_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "owner join",
    )
    .await;
    owner
        .raw("BUDGET #members max=100;unit=usd;period=per_day;hard=true")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A different authenticated identity, not in the channel.
    let (_out_did, outsider, _out_ev, out_bearer) = connect(irc, "stranger").await;

    let (status, body) = post_model(
        web,
        &out_bearer,
        serde_json::json!({
            "channel": "#members",
            "model": "test-model",
            "messages": [{ "role": "user", "content": "hi" }]
        }),
    )
    .await;

    assert_eq!(status, 403, "outsider drew on a budget: {body}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream called for an outsider"
    );

    outsider.quit(None).await.ok();
    owner.quit(None).await.ok();
    server.abort();
}

/// An unauthenticated caller gets nothing. The credential lives on the server, so
/// an open proxy would be a gift to the whole internet.
#[tokio::test]
async fn an_anonymous_caller_gets_no_capacity() {
    let (provider, hits, _p) = start_mock_provider(10, 10).await;
    let (_irc, web, server) = start_server(provider).await;

    let r = reqwest::Client::new()
        .post(format!("http://{web}/api/v1/model/chat/completions"))
        .json(&serde_json::json!({
            "channel": "#anything",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(r.status(), 401, "anonymous caller was served");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream called anonymously"
    );

    server.abort();
}

/// Spend accumulates, and a budget can be overshot by at most one call.
///
/// The true cost isn't known until the provider answers, so the gate decides on an
/// estimate. When a caller declares `max_tokens` the estimate bounds the overshoot
/// (see the exhausted-budget test, where the call never happens). When it doesn't,
/// a call whose real cost exceeds the guess can carry spend past the ceiling, and
/// the *next* call is refused.
///
/// This is the honest granularity of the limit: enforced per call, against what has
/// already been spent. Claiming otherwise would require metering tokens as they
/// stream, which is a different design.
#[tokio::test]
async fn spend_accumulates_and_the_budget_refuses_once_it_is_exceeded() {
    // Each call reports 1000 prompt tokens @ 1.0/1k = 1.0, regardless of the
    // request, which is exactly the case where a cheap estimate under-counts.
    let (provider, hits, _p) = start_mock_provider(1000, 0).await;
    let (irc, web, server) = start_server(provider).await;

    let (_did, c, mut ev, bearer) = connect(irc, "grinder").await;
    c.join("#accrue").await.unwrap();
    expect_event(&mut ev, 2000, |e| matches!(e, Event::Joined { .. }), "join").await;
    c.raw("BUDGET #accrue max=2.5;unit=usd;period=per_day;hard=true")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let call = serde_json::json!({
        "channel": "#accrue",
        "model": "test-model",
        "messages": [{ "role": "user", "content": "x" }],
        "max_tokens": 0
    });

    // 0.0 -> 1.0 -> 2.0, each under the 2.5 ceiling when the call is decided.
    for i in 1..=3 {
        let (status, body) = post_model(web, &bearer, call.clone()).await;
        assert_eq!(status, 200, "call {i} refused early: {body}");
    }
    // Spend is now 3.0, past the ceiling, so the next one cannot proceed.
    let (status, body) = post_model(web, &bearer, call.clone()).await;
    assert_eq!(status, 402, "fourth call was not refused: {body}");
    assert_eq!(body["detail"]["reason"], "budget_exhausted");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "upstream hit count does not match the three allowed calls"
    );

    c.quit(None).await.ok();
    server.abort();
}

/// A declared `max_tokens` is what stops an overshoot, so the estimate has to be
/// believed even when it is much larger than the eventual cost.
#[tokio::test]
async fn a_large_declared_call_is_refused_against_a_thin_remainder() {
    let (provider, hits, _p) = start_mock_provider(10, 10).await;
    let (irc, web, server) = start_server(provider).await;

    let (_did, c, mut ev, bearer) = connect(irc, "declarer").await;
    c.join("#thin").await.unwrap();
    expect_event(&mut ev, 2000, |e| matches!(e, Event::Joined { .. }), "join").await;
    c.raw("BUDGET #thin max=0.5;unit=usd;period=per_day;hard=true")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 100k output tokens @ 2.0/1k = 200.0 estimated, against 0.5 remaining.
    let (status, body) = post_model(
        web,
        &bearer,
        serde_json::json!({
            "channel": "#thin",
            "model": "test-model",
            "messages": [{ "role": "user", "content": "x" }],
            "max_tokens": 100000
        }),
    )
    .await;

    assert_eq!(status, 402, "oversized call was allowed: {body}");
    assert_eq!(body["detail"]["reason"], "would_exceed");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "upstream called anyway");

    c.quit(None).await.ok();
    server.abort();
}
