//! Integration tests: server + SDK client in-process.
//!
//! These tests start a real TCP server, connect real SDK clients, and verify
//! the full SASL ATPROTO-CHALLENGE flow end-to-end.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Helper: start a server on a random port with a static DID resolver.
async fn start_test_server(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

/// Helper: wait for a specific event, with timeout.
async fn expect_event(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    predicate: impl Fn(&Event) -> bool,
    description: &str,
) -> Event {
    let deadline = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    loop {
        match timeout(deadline.saturating_sub(start.elapsed()), events.recv()).await {
            Ok(Some(event)) => {
                if predicate(&event) {
                    return event;
                }
                // Not the event we want, keep going
            }
            Ok(None) => panic!("Channel closed while waiting for: {description}"),
            Err(_) => panic!("Timeout waiting for: {description}"),
        }
    }
}

fn empty_resolver() -> DidResolver {
    DidResolver::static_map(HashMap::new())
}

/// Consume everything currently queued. Required before asserting on a
/// *reply*: the SDK negotiates `echo-message`, so a sender's own PRIVMSG is
/// sitting in its own event queue and will otherwise satisfy a later
/// "did history contain X?" scan (a false positive that hides real bugs).
async fn drain_events(events: &mut mpsc::Receiver<Event>) {
    while let Ok(Some(_)) = timeout(Duration::from_millis(50), events.recv()).await {}
}

/// Like `expect_event`, but returns `false` on timeout instead of panicking.
/// Needed to assert the *absence* of a message (e.g. "history must not replay
/// a deleted message"), which `expect_event` cannot express.
async fn saw_event(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    predicate: impl Fn(&Event) -> bool,
) -> bool {
    let deadline = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    loop {
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return false;
        }
        match timeout(remaining, events.recv()).await {
            Ok(Some(event)) => {
                if predicate(&event) {
                    return true;
                }
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

// ── Test: Guest connection (no SASL) ────────────────────────────────

#[tokio::test]
async fn guest_connection() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "guest1".to_string(),
        user: "guest1".to_string(),
        realname: "Guest User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, None);

    // Should get Connected then Registered
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;
    let reg = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    if let Event::Registered { nick } = reg {
        assert_eq!(nick, "guest1");
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: VERSION includes git hash ─────────────────────────────────

#[tokio::test]
async fn version_includes_git_hash() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "vercheck".to_string(),
        user: "vercheck".to_string(),
        realname: "Version Check".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, None);
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    handle.raw("VERSION").await.unwrap();

    // VERSION reply (351) should contain "freeq-" and a git hash
    let version_evt = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("351")),
        "VERSION reply",
    )
    .await;

    if let Event::RawLine(line) = &version_evt {
        assert!(
            line.contains("freeq-"),
            "VERSION should contain 'freeq-', got: {line}"
        );
        // Should have version-hash format (e.g. freeq-0.1.0-3a6d138)
        assert!(
            line.contains("freeq-0.") && line.matches('-').count() >= 2,
            "VERSION should have version-hash format, got: {line}"
        );
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated connection with secp256k1 ───────────────────

#[tokio::test]
async fn authenticated_secp256k1() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testsecp256k1";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "authuser".to_string(),
        user: "authuser".to_string(),
        realname: "Auth User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;
    let auth = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;

    if let Event::Authenticated { did } = auth {
        assert_eq!(did, did_str);
    }

    let reg = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    if let Event::Registered { nick } = reg {
        assert_eq!(nick, "authuser");
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated connection with ed25519 ─────────────────────

#[tokio::test]
async fn authenticated_ed25519() {
    let private_key = PrivateKey::generate_ed25519();
    let did_str = "did:plc:tested25519";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "eduser".to_string(),
        user: "eduser".to_string(),
        realname: "Ed25519 User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Auth fails with wrong key ─────────────────────────────────

#[tokio::test]
async fn auth_fails_wrong_key() {
    // DID document has one key, client signs with a different key
    let doc_key = PrivateKey::generate_secp256k1();
    let signer_key = PrivateKey::generate_secp256k1();

    let did_str = "did:plc:wrongkey";
    let doc = did::make_test_did_document(did_str, &doc_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), signer_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "baduser".to_string(),
        user: "baduser".to_string(),
        realname: "Bad User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;

    // Should get AuthFailed
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::AuthFailed { .. }),
        "AuthFailed",
    )
    .await;

    // Should still register as guest (fallback)
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered as guest",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Auth fails with unknown DID ───────────────────────────────

#[tokio::test]
async fn auth_fails_unknown_did() {
    // Resolver has no documents — DID can't be resolved
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let private_key = PrivateKey::generate_secp256k1();
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        "did:plc:doesnotexist".to_string(),
        private_key,
    ));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "unknown".to_string(),
        user: "unknown".to_string(),
        realname: "Unknown DID".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::AuthFailed { .. }),
        "AuthFailed",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered as guest",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Two clients in the same channel can exchange messages ──────

#[tokio::test]
async fn channel_messaging() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect client 1
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Connect client 2
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    // Both join #test
    handle1.join("#test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#test" && nick == "alice"),
        "Alice joined",
    )
    .await;

    handle2.join("#test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#test" && nick == "bob"),
        "Bob joined",
    )
    .await;

    // Alice also sees Bob join
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#test" && nick == "bob"),
        "Alice sees Bob join",
    )
    .await;

    // Alice sends a message
    handle1.privmsg("#test", "hello bob!").await.unwrap();

    // Bob should receive it (skip echo-message from alice if any)
    let msg = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Message { from, target, .. } if target == "#test" && from == "alice"),
        "Bob receives message",
    )
    .await;

    if let Event::Message {
        from, target, text, ..
    } = msg
    {
        assert_eq!(from, "alice");
        assert_eq!(target, "#test");
        assert_eq!(text, "hello bob!");
    }

    // Bob replies
    handle2.privmsg("#test", "hi alice!").await.unwrap();

    // Alice receives bob's reply (skip echo of her own message)
    let msg = expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Message { from, target, .. } if target == "#test" && from == "bob"),
        "Alice receives reply",
    )
    .await;

    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "bob");
        assert_eq!(text, "hi alice!");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated + guest in same channel ─────────────────────

#[tokio::test]
async fn mixed_auth_and_guest_in_channel() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:mixedtest";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Authenticated client
    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));
    let config_auth = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "authed".to_string(),
        user: "authed".to_string(),
        realname: "Authenticated".to_string(),
        ..Default::default()
    };
    let (handle_auth, mut events_auth) = client::connect(config_auth, Some(signer));
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Auth",
    )
    .await;
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Reg",
    )
    .await;

    // Guest client
    let config_guest = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "guest".to_string(),
        user: "guest".to_string(),
        realname: "Guest".to_string(),
        ..Default::default()
    };
    let (handle_guest, mut events_guest) = client::connect(config_guest, None);
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Guest reg",
    )
    .await;

    // Both join
    handle_auth.join("#mixed").await.unwrap();
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Auth join",
    )
    .await;

    handle_guest.join("#mixed").await.unwrap();
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Guest join",
    )
    .await;

    // Guest sends message, authed user receives it (filter by sender)
    handle_guest.privmsg("#mixed", "from guest").await.unwrap();
    let msg = expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Message { from, target, .. } if target == "#mixed" && from == "guest"),
        "Authed receives from guest",
    )
    .await;
    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "guest");
        assert_eq!(text, "from guest");
    }

    // Authed sends message, guest receives it (filter by sender)
    handle_auth.privmsg("#mixed", "from authed").await.unwrap();
    let msg = expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Message { from, target, .. } if target == "#mixed" && from == "authed"),
        "Guest receives from authed",
    )
    .await;
    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "authed");
        assert_eq!(text, "from authed");
    }

    handle_auth.quit(None).await.unwrap();
    handle_guest.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Nick collision ────────────────────────────────────────────

#[tokio::test]
async fn nick_collision() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "samename".to_string(),
        user: "user1".to_string(),
        realname: "User 1".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "User1 registered",
    )
    .await;

    // Second client with same nick — should get a raw 433 (ERR_NICKNAMEINUSE)
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "samename".to_string(),
        user: "user2".to_string(),
        realname: "User 2".to_string(),
        ..Default::default()
    };
    let (_handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Connected),
        "User2 connected",
    )
    .await;

    // Should see a 433 in the raw lines
    let found_433 = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("433")),
        "Nick in use error",
    )
    .await;
    assert!(matches!(found_433, Event::RawLine(_)));

    handle1.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TOPIC ─────────────────────────────────────────────────────

#[tokio::test]
async fn channel_topic() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect user1
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Join channel
    handle1.join("#test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Set topic
    handle1.raw("TOPIC #test :Hello World").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Topic set",
    ).await;

    // Query topic
    handle1.raw("TOPIC #test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Topic query returned",
    ).await;

    // Connect user2 — should see topic on join
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    handle2.join("#test").await.unwrap();

    // Bob should receive the topic on join
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Bob sees topic on join",
    ).await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Channel ops (auto-op creator, +o/-o, KICK) ────────────────

#[tokio::test]
async fn channel_ops_and_kick() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel — should be auto-opped
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    handle1.join("#ops-test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Verify Alice has @ in NAMES
    let names_event = expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Names { channel, .. } if channel == "#ops-test"),
        "Alice NAMES",
    )
    .await;
    if let Event::Names { nicks, .. } = names_event {
        assert!(
            nicks.iter().any(|n| n == "@alice"),
            "Alice should be @alice, got: {nicks:?}"
        );
    }

    // Bob joins — not opped
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    handle2.join("#ops-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Bob tries to kick Alice — should fail (not op)
    handle2.raw("KICK #ops-test alice :bye").await.unwrap();
    let err = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("482")),
        "Bob gets chanop error",
    )
    .await;
    assert!(matches!(err, Event::RawLine(_)));

    // Alice ops Bob
    handle1.raw("MODE #ops-test +o bob").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+o" && arg.as_deref() == Some("bob")),
        "Alice sees +o bob",
    ).await;

    // Charlie joins
    let config3 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "charlie".to_string(),
        user: "charlie".to_string(),
        realname: "Charlie".to_string(),
        ..Default::default()
    };
    let (handle3, mut events3) = client::connect(config3, None);
    expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Charlie registered",
    )
    .await;

    handle3.join("#ops-test").await.unwrap();
    expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Charlie joined",
    )
    .await;

    // Bob (now op) kicks Charlie
    handle2
        .raw("KICK #ops-test charlie :troublemaker")
        .await
        .unwrap();
    let kick_event = expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Kicked { nick, by, .. } if nick == "charlie" && by == "bob"),
        "Charlie sees kick",
    )
    .await;
    assert!(matches!(kick_event, Event::Kicked { reason, .. } if reason == "troublemaker"));

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    handle3.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn topic_lock_mode() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel (auto-op)
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#lock-test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Bob joins
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#lock-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Channel now has +nt by default. Alice removes +t so Bob can test topic setting.
    handle1.raw("MODE #lock-test -t").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "-t"),
        "Alice removes +t",
    )
    .await;

    // Bob can set topic (no +t now)
    handle2.raw("TOPIC #lock-test :Bob's topic").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic == "Bob's topic"),
        "Bob sets topic",
    )
    .await;

    // Alice re-locks topic (+t)
    handle1.raw("MODE #lock-test +t").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+t"),
        "Alice sees +t",
    )
    .await;

    // Bob tries to set topic — should fail
    handle2.raw("TOPIC #lock-test :Nope").await.unwrap();
    let err = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("482")),
        "Bob gets chanop error on topic",
    )
    .await;
    assert!(matches!(err, Event::RawLine(_)));

    // Alice can still set topic
    handle1
        .raw("TOPIC #lock-test :Alice's topic")
        .await
        .unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic == "Alice's topic"),
        "Alice sets topic with +t",
    )
    .await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Ban (hostmask and DID-based) ──────────────────────────────

#[tokio::test]
async fn ban_hostmask() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#ban-test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Ban bob's hostmask pattern
    handle1.raw("MODE #ban-test +b bob!*@*").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+b"),
        "Ban set",
    )
    .await;

    // Bob tries to join — should be banned
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    handle2.join("#ban-test").await.unwrap();
    // Should get 474 ERR_BANNEDFROMCHAN
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "Bob banned",
    )
    .await;

    // Alice removes ban
    handle1.raw("MODE #ban-test -b bob!*@*").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "-b"),
        "Ban removed",
    )
    .await;

    // Bob can now join
    handle2.join("#ban-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joins after unban",
    )
    .await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn ban_by_did() {
    // Set up a resolver with a DID for alice
    let private_key = PrivateKey::generate_secp256k1();
    let did = "did:plc:testban123";
    let did_doc = did::make_test_did_document(did, &private_key.public_key_multibase());

    let mut map = HashMap::new();
    map.insert(did.to_string(), did_doc);
    let resolver = DidResolver::static_map(map);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Bob creates channel (no auth)
    let config_bob = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle_bob, mut events_bob) = client::connect(config_bob, None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle_bob.join("#did-ban").await.unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Alice connects with auth
    let signer = Arc::new(KeySigner::new(did.to_string(), private_key));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer));
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice joins
    handle_alice.join("#did-ban").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Bob bans Alice by DID
    handle_bob
        .raw(&format!("MODE #did-ban +b {did}"))
        .await
        .unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+b"),
        "DID ban set",
    )
    .await;

    // Kick Alice
    handle_bob
        .raw("KICK #did-ban alice :DID banned")
        .await
        .unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Kicked { .. }),
        "Alice kicked",
    )
    .await;

    // Alice tries to rejoin — should be DID-banned
    handle_alice.join("#did-ban").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "Alice DID-banned",
    )
    .await;

    handle_bob.quit(None).await.unwrap();
    handle_alice.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Invite-only channel ───────────────────────────────────────

#[tokio::test]
async fn invite_only_channel() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel, sets +i
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#invite-test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    handle1.raw("MODE #invite-test +i").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    )
    .await;

    // Bob tries to join — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    handle2.join("#invite-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "Bob rejected (invite only)",
    )
    .await;

    // Alice invites Bob
    handle1.raw("INVITE bob #invite-test").await.unwrap();

    // Bob should receive invite notification
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Invited { channel, .. } if channel == "#invite-test"),
        "Bob invited",
    )
    .await;

    // Now Bob can join
    handle2.join("#invite-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joins after invite",
    )
    .await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: +I (invite-exception) admits without consumable invite ───
//
// Alice creates a channel, sets +i, then sets +I on Bob's nick. Bob
// joins without an explicit INVITE (the +I list grants persistent
// admission). Bob parts and rejoins — the +I entry is sticky and not
// consumed on join, so the rejoin still works.

#[tokio::test]
async fn invite_exception_admits_and_persists() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates the channel and sets +i + +I.
    let alice_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (alice_handle, mut alice_events) = client::connect(alice_cfg, None);
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    alice_handle.join("#invex-test").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    alice_handle.raw("MODE #invex-test +i").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    )
    .await;

    // Set +I on a hostmask that matches Bob's connection.
    alice_handle
        .raw("MODE #invex-test +I *!*@freeq/guest")
        .await
        .unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+I" && arg.as_deref() == Some("*!*@freeq/guest")),
        "+I set",
    )
    .await;

    // Bob connects. NO explicit INVITE issued.
    let bob_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (bob_handle, mut bob_events) = client::connect(bob_cfg, None);
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    // Bob joins the +i channel — should be admitted via +I match.
    bob_handle.join("#invex-test").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#invex-test"),
        "Bob admitted via +I (first join)",
    )
    .await;

    // Bob parts and rejoins. The +I entry is sticky — it must NOT have
    // been consumed by the first join.
    bob_handle.raw("PART #invex-test").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Parted { channel, nick } if channel == "#invex-test" && nick == "bob"),
        "Bob parted",
    )
    .await;

    bob_handle.join("#invex-test").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#invex-test"),
        "Bob admitted via +I (second join — sticky)",
    )
    .await;

    alice_handle.quit(None).await.unwrap();
    bob_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: +I list / -I removal ──────────────────────────────────────
//
// Adding then removing a +I entry; verify a removed entry no longer
// admits a previously-allowed user.

#[tokio::test]
async fn invite_exception_removal_revokes_admission() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let alice_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (alice_handle, mut alice_events) = client::connect(alice_cfg, None);
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    alice_handle.join("#invex-revoke").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    alice_handle.raw("MODE #invex-revoke +i").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    )
    .await;

    alice_handle
        .raw("MODE #invex-revoke +I *!*@freeq/guest")
        .await
        .unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+I"),
        "+I set",
    )
    .await;

    // Now remove the entry.
    alice_handle
        .raw("MODE #invex-revoke -I *!*@freeq/guest")
        .await
        .unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "-I"),
        "-I set",
    )
    .await;

    // Bob tries to join — entry was removed, no invite, should be rejected.
    let bob_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (bob_handle, mut bob_events) = client::connect(bob_cfg, None);
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    bob_handle.join("#invex-revoke").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "Bob rejected (473 ERR_INVITEONLYCHAN)",
    )
    .await;

    alice_handle.quit(None).await.unwrap();
    bob_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: +I list reply (MODE #foo +I with no arg) ─────────────────
//
// Adding two +I entries, then sending `MODE #foo +I` should produce
// one RPL_INVITELIST (346) per entry plus a single RPL_ENDOFINVITELIST
// (347) sentinel.

#[tokio::test]
async fn invite_exception_list_via_mode() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(cfg, None);
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    handle.join("#invex-list").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    // Add two entries.
    handle
        .raw("MODE #invex-list +I *!*@a.example")
        .await
        .unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+I" && arg.as_deref() == Some("*!*@a.example")),
        "+I a set",
    )
    .await;
    handle
        .raw("MODE #invex-list +I *!*@b.example")
        .await
        .unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+I" && arg.as_deref() == Some("*!*@b.example")),
        "+I b set",
    )
    .await;

    // Query the list.
    handle.raw("MODE #invex-list +I").await.unwrap();

    // Expect both entries listed via 346 and a 347 sentinel.
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains(" 346 ") && line.contains("*!*@a.example")),
        "346 lists a.example",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains(" 346 ") && line.contains("*!*@b.example")),
        "346 lists b.example",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains(" 347 ") && line.contains("#invex-list")),
        "347 end-of-list",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: +I with DID-form mask admits authenticated bot ───────────
//
// Alice (op) puts a `did:` mask on +I; Bob (authenticated with that DID)
// joins the +i channel without an INVITE — admitted by DID match, not
// hostmask match.

#[tokio::test]
async fn invite_exception_did_form_admits_authenticated() {
    // Alice creates channel as guest. Bob authenticates with a known DID.
    let bob_key = PrivateKey::generate_ed25519();
    let bob_did = "did:plc:botforinvex";
    let bob_doc = did::make_test_did_document(bob_did, &bob_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(bob_did.to_string(), bob_doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Alice (guest) creates the channel.
    let alice_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (alice_handle, mut alice_events) = client::connect(alice_cfg, None);
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    alice_handle.join("#invex-did").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;
    alice_handle.raw("MODE #invex-did +i").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    )
    .await;

    // Add Bob's DID to +I.
    alice_handle
        .raw(&format!("MODE #invex-did +I {bob_did}"))
        .await
        .unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+I" && arg.as_deref() == Some(bob_did)),
        "+I did set",
    )
    .await;

    // Bob authenticates and joins.
    let bob_signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(bob_did.to_string(), bob_key));
    let bob_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bobbot".to_string(),
        user: "bobbot".to_string(),
        realname: "Bob bot".to_string(),
        ..Default::default()
    };
    let (bob_handle, mut bob_events) = client::connect(bob_cfg, Some(bob_signer));
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Authenticated { did } if did == bob_did),
        "Bob authenticated",
    )
    .await;
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    bob_handle.join("#invex-did").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#invex-did"),
        "Bob admitted via DID-form +I",
    )
    .await;

    alice_handle.quit(None).await.unwrap();
    bob_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: non-op cannot set +I ─────────────────────────────────────
//
// Bob joins a channel as a regular member (no ops); Bob tries `MODE +I`
// and gets ERR_CHANOPRIVSNEEDED (482). The +I list must remain empty.

#[tokio::test]
async fn invite_exception_non_op_rejected() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates the channel and is auto-op.
    let alice_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (alice_handle, mut alice_events) = client::connect(alice_cfg, None);
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    alice_handle.join("#invex-noop").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Bob joins as a regular member (no ops).
    let bob_cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (bob_handle, mut bob_events) = client::connect(bob_cfg, None);
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    bob_handle.join("#invex-noop").await.unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Bob tries MODE +I — should be rejected (482 ERR_CHANOPRIVSNEEDED).
    bob_handle
        .raw("MODE #invex-noop +I *!*@anywhere")
        .await
        .unwrap();
    expect_event(
        &mut bob_events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains(" 482 ")),
        "Bob gets 482 ERR_CHANOPRIVSNEEDED",
    )
    .await;

    // Verify the list is still empty by querying it as Alice.
    alice_handle.raw("MODE #invex-noop +I").await.unwrap();
    expect_event(
        &mut alice_events,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains(" 347 ")),
        "list end (no 346 entries)",
    )
    .await;

    alice_handle.quit(None).await.unwrap();
    bob_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: +I survives server restart ───────────────────────────────
//
// Set +I on a channel, kill the server, restart against the same DB,
// confirm the entry is still in the loaded ChannelState.

#[tokio::test]
async fn invite_exception_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First instance: set +I and shut down.
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "op".to_string(),
            user: "op".to_string(),
            realname: "Op".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#invex-restart").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { .. }),
            "Joined",
        )
        .await;

        handle
            .raw("MODE #invex-restart +I *!*@trusted.example")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify +I is in the database directly.
    {
        let db = freeq_server::db::Db::open(db_str).unwrap();
        let channels = db.load_channels().unwrap();
        let ch = channels.get("#invex-restart").unwrap();
        assert_eq!(ch.invite_exceptions.len(), 1);
        assert_eq!(ch.invite_exceptions[0].mask, "*!*@trusted.example");
    }
}

// ── Test: duplicate +I masks coalesce to a single entry ────────────

#[tokio::test]
async fn invite_exception_duplicate_prevented() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(cfg, None);
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    handle.join("#invex-dup").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    // Set the same mask twice.
    handle
        .raw("MODE #invex-dup +I *!*@x.example")
        .await
        .unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+I"),
        "first +I",
    )
    .await;
    handle
        .raw("MODE #invex-dup +I *!*@x.example")
        .await
        .unwrap();
    // Sleep instead of waiting for a ModeChanged: the duplicate path skips
    // the broadcast (the list didn't actually change), so no event fires.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Query — expect exactly one 346 entry.
    handle.raw("MODE #invex-dup +I").await.unwrap();
    let mut count = 0;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(evt)) = tokio::time::timeout(Duration::from_millis(100), events.recv()).await
        {
            match evt {
                Event::RawLine(line)
                    if line.contains(" 346 ") && line.contains("*!*@x.example") =>
                {
                    count += 1;
                }
                Event::RawLine(line) if line.contains(" 347 ") => break,
                _ => {}
            }
        }
    }
    assert_eq!(count, 1, "expected exactly one +I entry, found {count}");

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: empty/whitespace mask is silently dropped ────────────────

#[tokio::test]
async fn invite_exception_empty_mask_dropped() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let cfg = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(cfg, None);
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "registered",
    )
    .await;
    handle.join("#invex-empty").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    // Whitespace-only mask: server silently drops the entry, no broadcast.
    handle.raw("MODE #invex-empty +I    ").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // List the +I entries — expect none.
    handle.raw("MODE #invex-empty +I").await.unwrap();
    let mut entries = 0;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(evt)) = tokio::time::timeout(Duration::from_millis(100), events.recv()).await
        {
            match evt {
                Event::RawLine(line) if line.contains(" 346 ") => entries += 1,
                Event::RawLine(line) if line.contains(" 347 ") => break,
                _ => {}
            }
        }
    }
    assert_eq!(
        entries, 0,
        "empty mask must not create an entry, found {entries}"
    );

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Founder bypasses +i on rejoin ─────────────────────────────
//
// Standard IRC behavior: the channel founder (and DID-ops) can rejoin a
// `+i` channel without an invite. freeq currently rejects everyone
// without an invite — including the founder of the channel — which is
// the bug this test exercises.

#[tokio::test]
async fn founder_bypasses_invite_only_on_rejoin() {
    let private_key = PrivateKey::generate_ed25519();
    let did_str = "did:plc:founderbypass";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authenticated",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice creates #founder-i — becomes founder (founder_did set on JOIN
    // when authenticated and channel didn't previously exist).
    handle.join("#founder-i").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#founder-i"),
        "Alice joined as founder",
    )
    .await;

    // Lock the channel down with +i.
    handle.raw("MODE #founder-i +i").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    )
    .await;

    // Alice leaves the channel.
    handle.raw("PART #founder-i").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Parted { channel, nick } if channel == "#founder-i" && nick == "alice"),
        "Alice parted",
    )
    .await;

    // Alice rejoins. As founder, she should bypass +i without needing an
    // invite. Currently the server emits ERR_INVITEONLYCHAN (473).
    handle.join("#founder-i").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#founder-i"),
        "founder rejoined +i channel without invite",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Founder bypasses +m on speak ──────────────────────────────
//
// Standard IRC behavior: the channel founder (and DID-ops) can speak in
// a `+m` (moderated) channel without needing explicit voice/op status.
// freeq currently gates speak on ops/halfops/voiced membership only —
// founders without an explicit op grant are silenced in their own
// moderated channel.

#[tokio::test]
async fn founder_bypasses_moderated_on_speak() {
    let private_key = PrivateKey::generate_ed25519();
    let did_str = "did:plc:foundermoderated";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authenticated",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice creates #founder-m as founder. On create, the JOIN handler
    // auto-ops her at the *session* level (ch.ops contains her session id),
    // so to actually exercise the founder-bypass we deop her — then her
    // ability to speak depends purely on founder_did matching her DID.
    handle.join("#founder-m").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#founder-m"),
        "Alice joined as founder",
    )
    .await;

    // Set +m first (while still op — can't change modes after deop).
    handle.raw("MODE #founder-m +m").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+m"),
        "+m set",
    )
    .await;

    // Now drop Alice's session-level op grant. founder_did is unchanged.
    handle.raw("MODE #founder-m -o alice").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "-o"),
        "alice de-opped",
    )
    .await;

    // Alice tries to speak in her own moderated channel — without ops,
    // halfops, or voice. Should pass via founder DID bypass.
    handle.privmsg("#founder-m", "hello").await.unwrap();

    // The bot's own message should round-trip back via echo-message tag,
    // confirming the server accepted and relayed the PRIVMSG. If the +m
    // gate rejects, we'd get an ERR_CANNOTSENDTOCHAN (404) RawLine
    // instead and the matcher would never fire.
    expect_event(
        &mut events,
        2000,
        |e| {
            matches!(e, Event::Message { from, target, text, .. }
                     if from == "alice" && target == "#founder-m" && text == "hello")
        },
        "founder spoke in +m channel",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Message history replay on JOIN ────────────────────────────

#[tokio::test]
async fn message_history_replay() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice joins and sends messages
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#history").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    handle1.privmsg("#history", "first message").await.unwrap();
    handle1.privmsg("#history", "second message").await.unwrap();
    // Small delay so messages are stored
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Bob joins — should see replayed messages
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#history").await.unwrap();

    // Bob should receive the history as messages
    let msg1 = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "first message"),
        "Bob sees first history message",
    )
    .await;
    assert!(matches!(msg1, Event::Message { .. }));

    let msg2 = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "second message"),
        "Bob sees second history message",
    )
    .await;
    assert!(matches!(msg2, Event::Message { .. }));

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Nick ownership by DID ─────────────────────────────────────

#[tokio::test]
async fn nick_ownership() {
    let private_key = PrivateKey::generate_secp256k1();
    let did = "did:plc:nickowner";
    let doc = did::make_test_did_document(did, &private_key.public_key_multibase());

    let mut map = HashMap::new();
    map.insert(did.to_string(), doc);
    let resolver = DidResolver::static_map(map);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Alice authenticates and claims nick "alice"
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.to_string(), private_key));
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, Some(signer));
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice disconnects
    handle1.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Guest tries to take "alice" — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "imposter".to_string(),
        realname: "Imposter".to_string(),
        ..Default::default()
    };
    let (_handle2, mut events2) = client::connect(config2, None);

    // Guest enters CAP negotiation (message-tags), so nick is provisionally allowed.
    // At registration, the nick ownership check renames them to GuestXXXX.
    // They should get a Registered event with a Guest nick, not "alice".
    let reg = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { nick } if nick != "alice"),
        "Imposter registered with different nick",
    )
    .await;
    if let Event::Registered { nick } = reg {
        assert!(nick.starts_with("Guest"), "Expected GuestXXXX, got {nick}");
    }

    server_handle.abort();
}

// ── Test: QUIT broadcast ────────────────────────────────────────────

#[tokio::test]
async fn quit_broadcast() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#quit-test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#quit-test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Drain bob's join event from alice's stream
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"),
        "Alice sees bob join",
    )
    .await;

    // Bob quits
    handle2.quit(Some("goodbye")).await.unwrap();

    // Alice should see bob's QUIT
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == "bob"),
        "Alice sees bob quit",
    )
    .await;

    handle1.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Expired challenge is rejected ─────────────────────────────

#[tokio::test]
async fn auth_fails_expired_challenge() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testexpired";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    // Server with 1-second challenge timeout
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 1,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    let (addr, server_handle) = server.start().await.unwrap();

    // Use raw TCP to introduce a delay between receiving challenge and sending response
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    wr.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr.write_all(b"NICK expired\r\n").await.unwrap();
    wr.write_all(b"USER expired 0 * :Expired\r\n")
        .await
        .unwrap();

    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") {
            break;
        }
    }

    wr.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("ACK") {
            break;
        }
    }

    wr.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
        .await
        .unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") {
            break;
        }
    }

    let challenge_b64 = line
        .trim()
        .strip_prefix("AUTHENTICATE ")
        .unwrap()
        .to_string();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge_b64).unwrap();

    // Wait for the challenge to expire (1s timeout, need > 1s with whole-second timestamps)
    tokio::time::sleep(Duration::from_millis(2100)).await;

    // Now sign and send the response
    let signature = private_key.sign(&challenge_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let response = serde_json::json!({
        "did": did_str,
        "method": "crypto",
        "signature": sig_b64,
    });
    let response_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&response).unwrap());

    wr.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes())
        .await
        .unwrap();

    // Should get 904 (SASL failure) due to expired challenge
    let mut got_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("904") {
                    got_failure = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(
        got_failure,
        "Expected 904 SASL failure for expired challenge"
    );

    wr.write_all(b"CAP END\r\n").await.unwrap();

    // Should still complete registration as guest
    let mut got_welcome = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("001") {
                    got_welcome = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(got_welcome, "Expected 001 welcome after failed SASL");

    wr.write_all(b"QUIT\r\n").await.unwrap();
    server_handle.abort();
}

// ── Test: Replayed nonce is rejected ────────────────────────────────

#[tokio::test]
async fn auth_fails_replayed_nonce() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testreplay";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // First: do a legitimate auth via raw TCP and capture the response
    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    wr.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr.write_all(b"NICK replaytest\r\n").await.unwrap();
    wr.write_all(b"USER replaytest 0 * :Test\r\n")
        .await
        .unwrap();

    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") {
            break;
        }
    }

    wr.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("ACK") {
            break;
        }
    }

    wr.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
        .await
        .unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") {
            break;
        }
    }

    let challenge_b64 = line
        .trim()
        .strip_prefix("AUTHENTICATE ")
        .unwrap()
        .to_string();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge_b64).unwrap();

    let signature = private_key.sign(&challenge_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let response = serde_json::json!({
        "did": did_str,
        "method": "crypto",
        "signature": sig_b64,
    });
    let response_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&response).unwrap());

    wr.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes())
        .await
        .unwrap();

    // Read until 903 (success)
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("903") {
            break;
        }
    }

    wr.write_all(b"CAP END\r\nQUIT\r\n").await.unwrap();
    drop(wr);

    // Brief pause to let server clean up
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection: try to replay the same SASL response
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let (rd2, mut wr2) = stream2.into_split();
    let mut reader2 = BufReader::new(rd2);

    wr2.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr2.write_all(b"NICK replaytest2\r\n").await.unwrap();
    wr2.write_all(b"USER replaytest2 0 * :Test\r\n")
        .await
        .unwrap();

    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") {
            break;
        }
    }

    wr2.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.contains("ACK") {
            break;
        }
    }

    wr2.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
        .await
        .unwrap();
    // Get the NEW challenge (different nonce)
    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") {
            break;
        }
    }

    // Replay the OLD response (signed over old challenge bytes, not this new one)
    wr2.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes())
        .await
        .unwrap();

    // Should get 904 (SASL failure) — signature doesn't match new challenge
    let mut got_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader2.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("904") {
                    got_failure = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(got_failure, "Expected 904 SASL failure for replayed nonce");

    wr2.write_all(b"QUIT\r\n").await.unwrap();
    server_handle.abort();
}

// ── Test: Channel key (+k) ──────────────────────────────────────────

#[tokio::test]
async fn channel_key() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates a channel and sets a key
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#secret").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Set channel key
    handle1.raw("MODE #secret +k hunter2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob tries to join without key — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#secret").await.unwrap();

    // Bob should get a RawLine with 475 (ERR_BADCHANNELKEY)
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("475")),
        "Bob gets 475 ERR_BADCHANNELKEY",
    )
    .await;

    // Bob tries again with the correct key
    handle2.raw("JOIN #secret hunter2").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#secret" && nick == "bob"),
        "Bob joined with key",
    )
    .await;

    // Alice removes the key
    handle1.raw("MODE #secret -k").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Carol can join without a key now
    let config3 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "carol".to_string(),
        user: "carol".to_string(),
        realname: "Carol".to_string(),
        ..Default::default()
    };
    let (handle3, mut events3) = client::connect(config3, None);
    expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Carol registered",
    )
    .await;
    handle3.join("#secret").await.unwrap();
    expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#secret" && nick == "carol"),
        "Carol joined",
    )
    .await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    handle3.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TLS connection ────────────────────────────────────────────

#[tokio::test]
async fn tls_connection() {
    use std::io::Write;

    // Ensure a crypto provider is installed (iroh may bring ring)
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    // Generate self-signed cert using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    // Write to temp files
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key_pem.as_bytes())
        .unwrap();

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        tls_listen_addr: "127.0.0.1:0".to_string(),
        tls_cert: Some(cert_path.to_str().unwrap().to_string()),
        tls_key: Some(key_path.to_str().unwrap().to_string()),
        server_name: "test-tls".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };

    let server = freeq_server::server::Server::with_resolver(config, empty_resolver());
    let (addr, tls_addr, server_handle) = server.start_tls().await.unwrap();

    // Connect via TLS using the SDK
    let tls_config = ConnectConfig {
        server_addr: tls_addr.to_string(),
        nick: "tlsuser".to_string(),
        user: "tlsuser".to_string(),
        realname: "TLS User".to_string(),
        tls: true,
        tls_insecure: true, // Self-signed cert
        ..Default::default()
    };

    let (handle, mut events) = client::connect(tls_config, None);

    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Connected),
        "Connected via TLS",
    )
    .await;
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered via TLS",
    )
    .await;

    // Also verify the plain port still works
    let plain_config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "plainuser".to_string(),
        user: "plainuser".to_string(),
        realname: "Plain User".to_string(),
        ..Default::default()
    };

    let (handle2, mut events2) = client::connect(plain_config, None);
    expect_event(
        &mut events2,
        3000,
        |e| matches!(e, Event::Connected),
        "Connected via plain",
    )
    .await;
    expect_event(
        &mut events2,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered via plain",
    )
    .await;

    handle.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Rich media tags passthrough ───────────────────────────────

#[tokio::test]
async fn media_tags_passthrough() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice connects
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#media").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    // Bob connects
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#media").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Drain bob's join from alice's stream
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"),
        "Alice sees bob",
    )
    .await;

    // Alice sends a media message with tags
    let media = freeq_sdk::media::MediaAttachment {
        content_type: "image/jpeg".to_string(),
        url: "https://cdn.example.com/photo.jpg".to_string(),
        alt: Some("A sunset".to_string()),
        width: Some(1200),
        height: Some(800),
        blurhash: None,
        size: Some(45000),
        filename: None,
    };
    handle1.send_media("#media", &media).await.unwrap();

    // Bob should receive the message with tags
    let msg = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Message { from, target, .. } if from == "alice" && target == "#media"),
        "Bob receives media message",
    ).await;

    if let Event::Message { tags, text, .. } = msg {
        // Tags should be present (both clients negotiated message-tags)
        assert_eq!(
            tags.get("content-type").map(|s| s.as_str()),
            Some("image/jpeg")
        );
        assert_eq!(
            tags.get("media-url").map(|s| s.as_str()),
            Some("https://cdn.example.com/photo.jpg")
        );
        assert_eq!(tags.get("media-alt").map(|s| s.as_str()), Some("A sunset"));
        assert_eq!(tags.get("media-w").map(|s| s.as_str()), Some("1200"));
        // Fallback text should contain the URL
        assert!(text.contains("https://cdn.example.com/photo.jpg"));
    } else {
        panic!("Expected Message event");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn tagmsg_and_reactions() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle1.join("#react").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle2.join("#react").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Drain bob's join from alice
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"),
        "Alice sees bob",
    )
    .await;

    // Alice sends a reaction via TAGMSG
    let reaction = freeq_sdk::media::Reaction {
        emoji: "🔥".to_string(),
        msgid: None,
    };
    handle1
        .send_tagmsg("#react", reaction.to_tags())
        .await
        .unwrap();

    // Bob should receive the TAGMSG with reaction tags
    let msg = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::TagMsg { from, target, .. } if from == "alice" && target == "#react"),
        "Bob receives TAGMSG",
    ).await;

    if let Event::TagMsg { tags, .. } = msg {
        let parsed = freeq_sdk::media::Reaction::from_tags(&tags).unwrap();
        assert_eq!(parsed.emoji, "🔥");
    } else {
        panic!("Expected TagMsg event");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: a DM TAGMSG echoes back to a sender with echo-message ──
//
// The channel branch echoes TAGMSG to senders holding echo-message; the
// user-target branch must too, or a client that renders reactions from its
// echo (rather than optimistically) never shows the sender their own
// reaction in a DM thread.
#[tokio::test]
async fn dm_tagmsg_echoes_to_sender() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (_handle2, mut events2) = client::connect(config2, None);
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    let reaction = freeq_sdk::media::Reaction {
        emoji: "🔥".to_string(),
        msgid: None,
    };
    handle1
        .send_tagmsg("bob", reaction.to_tags())
        .await
        .unwrap();

    // Recipient delivery (already worked).
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::TagMsg { from, target, .. } if from == "alice" && target == "bob"),
        "Bob receives DM TAGMSG",
    )
    .await;

    // Sender echo — the SDK negotiates echo-message, so alice must see her
    // own TAGMSG back, same as she would in a channel.
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TagMsg { from, target, .. } if from == "alice" && target == "bob"),
        "Alice receives her own DM TAGMSG echo",
    )
    .await;

    handle1.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TAGMSG with +freeq.at/unreact removes a previously stored reaction
//
// Wire shape: TAGMSG <channel> +freeq.at/unreact=<emoji> +reply=<msgid>
// - The TAGMSG must relay to channel members like any other.
// - The server must call db::remove_reaction so CHATHISTORY no longer carries
//   the reaction in +freeq.at/reactions.
//
// This test covers the protocol contract end-to-end. The DB primitive itself
// is unit-tested in db.rs.
#[tokio::test]
async fn tagmsg_unreact_removes_persisted_reaction() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("unreact.db");
    let db_str = db_path.to_str().unwrap();

    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, None);
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;
    handle_alice.join("#unreact").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    let config_bob = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle_bob, mut events_bob) = client::connect(config_bob, None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;
    handle_bob.join("#unreact").await.unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bob joined",
    )
    .await;

    // Drain Bob's join from Alice's stream.
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"),
        "Alice sees Bob join",
    )
    .await;

    // Alice posts a message; Bob receives it and we extract its msgid.
    handle_alice
        .privmsg("#unreact", "react to me")
        .await
        .unwrap();
    let msg_evt = expect_event(
        &mut events_bob,
        2000,
        |e| {
            matches!(e, Event::Message { from, target, text, .. }
            if from == "alice" && target == "#unreact" && text == "react to me")
        },
        "Bob receives Alice's message",
    )
    .await;
    let msgid = if let Event::Message { tags, .. } = &msg_evt {
        tags.get("msgid")
            .cloned()
            .expect("server should attach msgid")
    } else {
        unreachable!()
    };

    // Bob reacts.
    let mut react_tags = HashMap::new();
    react_tags.insert("+react".to_string(), "🔥".to_string());
    react_tags.insert("+reply".to_string(), msgid.clone());
    handle_bob
        .send_tagmsg("#unreact", react_tags)
        .await
        .unwrap();

    // Alice sees Bob's reaction relay (sanity).
    expect_event(
        &mut events_alice,
        2000,
        |e| {
            matches!(e, Event::TagMsg { from, tags, .. }
            if from == "bob" && tags.get("+react").map(|s| s.as_str()) == Some("🔥"))
        },
        "Alice receives Bob's reaction",
    )
    .await;

    // Bob unreacts.
    let mut unreact_tags = HashMap::new();
    unreact_tags.insert("+freeq.at/unreact".to_string(), "🔥".to_string());
    unreact_tags.insert("+reply".to_string(), msgid.clone());
    handle_bob
        .send_tagmsg("#unreact", unreact_tags)
        .await
        .unwrap();

    // Alice sees the unreact relay — same channel TAGMSG path as react.
    expect_event(
        &mut events_alice,
        2000,
        |e| {
            matches!(e, Event::TagMsg { from, tags, .. }
            if from == "bob"
            && tags.get("+freeq.at/unreact").map(|s| s.as_str()) == Some("🔥"))
        },
        "Alice receives Bob's unreact",
    )
    .await;

    // Give the server a beat to finish the DB delete before we ask for history.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // CHATHISTORY should now show the message with no 🔥 in +freeq.at/reactions.
    handle_alice.history_latest("#unreact", 50).await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| {
            matches!(e, Event::BatchStart { batch_type, .. }
            if batch_type == "chathistory")
        },
        "history batch start",
    )
    .await;
    let hist = expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "react to me"),
        "history replays Alice's message",
    )
    .await;
    if let Event::Message { tags, .. } = &hist {
        let reactions = tags.get("+freeq.at/reactions");
        let still_has_fire = reactions.map(|s| s.contains("🔥")).unwrap_or(false);
        assert!(
            !still_has_fire,
            "after unreact, history should not carry 🔥 in +freeq.at/reactions; got: {reactions:?}"
        );
    } else {
        unreachable!()
    }

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Persistence tests ───────────────────────────────────────────────

/// Helper: start a server with persistence enabled (SQLite file).
async fn start_test_server_with_db(
    resolver: DidResolver,
    db_path: &str,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.to_string()),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

#[tokio::test]
async fn persistence_messages_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First server instance: send a message
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "alice".to_string(),
            user: "alice".to_string(),
            realname: "Alice".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#persist").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { channel, .. } if channel == "#persist"),
            "Joined",
        )
        .await;

        handle
            .privmsg("#persist", "hello from first server")
            .await
            .unwrap();
        // Give time for the message to be stored
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second server instance: join channel, should see history
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "bob".to_string(),
            user: "bob".to_string(),
            realname: "Bob".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#persist").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { channel, .. } if channel == "#persist"),
            "Joined",
        )
        .await;

        // Should receive the replayed message from the first server instance
        let msg = expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Message { text, .. } if text == "hello from first server"),
            "History replay from persisted DB",
        )
        .await;

        if let Event::Message {
            from, target, text, ..
        } = msg
        {
            assert!(
                from.contains("alice"),
                "Message should be from alice, got: {from}"
            );
            assert_eq!(target, "#persist");
            assert_eq!(text, "hello from first server");
        }

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}

#[tokio::test]
async fn persistence_topic_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First instance: set a topic
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "alice".to_string(),
            user: "alice".to_string(),
            realname: "Alice".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#topictest").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { channel, .. } if channel == "#topictest"),
            "Joined",
        )
        .await;

        handle
            .raw("TOPIC #topictest :Persistent topic!")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second instance: join, should see persisted topic
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "bob".to_string(),
            user: "bob".to_string(),
            realname: "Bob".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#topictest").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { channel, .. } if channel == "#topictest"),
            "Joined",
        )
        .await;

        // Should receive the topic on join
        let _topic = expect_event(
            &mut events, 2000,
            |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#topictest" && topic == "Persistent topic!"),
            "Persisted topic on join",
        ).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}

#[tokio::test]
async fn persistence_bans_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First instance: set a ban
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "op".to_string(),
            user: "op".to_string(),
            realname: "Op".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.join("#btest").await.unwrap();
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Joined { channel, .. } if channel == "#btest"),
            "Joined",
        )
        .await;

        // As channel creator, we're op — set a ban
        handle.raw("MODE #btest +b bad!*@*").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify the ban is in the database directly
    {
        let db = freeq_server::db::Db::open(db_str).unwrap();
        let channels = db.load_channels().unwrap();
        let ch = channels.get("#btest").unwrap();
        assert_eq!(ch.bans.len(), 1);
        assert_eq!(ch.bans[0].mask, "bad!*@*");
    }
}

#[tokio::test]
async fn persistence_nick_ownership_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testpersist";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs.clone());

    // First instance: authenticate and claim nick
    {
        let (addr, server_handle) = start_test_server_with_db(resolver, db_str).await;

        let signer: Arc<dyn ChallengeSigner> =
            Arc::new(KeySigner::new(did_str.to_string(), private_key));
        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "claimed".to_string(),
            user: "claimed".to_string(),
            realname: "Claimed".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, Some(signer));
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;
        expect_event(
            &mut events,
            3000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second instance: guest tries to use claimed nick — should be renamed
    {
        let resolver2 = DidResolver::static_map(docs);
        let (addr, server_handle) = start_test_server_with_db(resolver2, db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "claimed".to_string(),
            user: "claimed".to_string(),
            realname: "Guest".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Connected),
            "Connected",
        )
        .await;

        // The registered event should show a different nick (Guest*)
        let reg = expect_event(
            &mut events,
            2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        )
        .await;

        if let Event::Registered { nick, .. } = reg {
            assert!(
                nick.starts_with("Guest"),
                "Guest should be renamed, got: {nick}"
            );
        }

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}

// ── Test: Halfop (+h) behavior ──────────────────────────────────────

#[tokio::test]
async fn halfop_mode() {
    let (addr, _server_handle) = start_test_server(empty_resolver()).await;

    // Op creates channel
    let config_op = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "halftest_op".to_string(),
        user: "halftest_op".to_string(),
        realname: "Op".to_string(),
        ..Default::default()
    };
    let (handle_op, mut events_op) = client::connect(config_op, None);
    expect_event(
        &mut events_op,
        5000,
        |e| matches!(e, Event::Registered { .. }),
        "op registered",
    )
    .await;
    handle_op.join("#halftest").await.unwrap();
    expect_event(
        &mut events_op,
        5000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#halftest"),
        "op joined",
    )
    .await;

    // Halfop user joins
    let config_half = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "halftest_mod".to_string(),
        user: "halftest_mod".to_string(),
        realname: "Mod".to_string(),
        ..Default::default()
    };
    let (handle_half, mut events_half) = client::connect(config_half, None);
    expect_event(
        &mut events_half,
        5000,
        |e| matches!(e, Event::Registered { .. }),
        "mod registered",
    )
    .await;
    handle_half.join("#halftest").await.unwrap();
    expect_event(
        &mut events_half,
        5000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#halftest"),
        "mod joined",
    )
    .await;

    // Regular user joins
    let config_user = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "halftest_user".to_string(),
        user: "halftest_user".to_string(),
        realname: "User".to_string(),
        ..Default::default()
    };
    let (handle_user, mut events_user) = client::connect(config_user, None);
    expect_event(
        &mut events_user,
        5000,
        |e| matches!(e, Event::Registered { .. }),
        "user registered",
    )
    .await;
    handle_user.join("#halftest").await.unwrap();
    expect_event(
        &mut events_user,
        5000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#halftest"),
        "user joined",
    )
    .await;

    // Drain any pending events
    tokio::time::sleep(Duration::from_millis(200)).await;
    while events_op.try_recv().is_ok() {}
    while events_half.try_recv().is_ok() {}
    while events_user.try_recv().is_ok() {}

    // Op grants +h to mod
    handle_op
        .raw("MODE #halftest +h halftest_mod")
        .await
        .unwrap();
    expect_event(&mut events_half, 5000, |e| matches!(e, Event::ModeChanged { channel, mode, .. } if channel == "#halftest" && mode == "+h"), "mod gets +h").await;

    // Halfop can kick regular user
    handle_half
        .raw("KICK #halftest halftest_user :moderated")
        .await
        .unwrap();
    expect_event(
        &mut events_user,
        5000,
        |e| matches!(e, Event::Kicked { channel, .. } if channel == "#halftest"),
        "user kicked by halfop",
    )
    .await;

    // User rejoins
    handle_user.join("#halftest").await.unwrap();
    expect_event(
        &mut events_user,
        5000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#halftest"),
        "user rejoined",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    while events_half.try_recv().is_ok() {}

    // Halfop CANNOT kick op
    handle_half
        .raw("KICK #halftest halftest_op :nope")
        .await
        .unwrap();
    expect_event(
        &mut events_half,
        5000,
        |e| matches!(e, Event::ServerNotice { text } if text.contains("operator")),
        "halfop can't kick op",
    )
    .await;

    // Halfop can set +v
    handle_half
        .raw("MODE #halftest +v halftest_user")
        .await
        .unwrap();
    expect_event(
        &mut events_user,
        5000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+v"),
        "halfop sets +v",
    )
    .await;

    // Halfop CANNOT set +o
    handle_half
        .raw("MODE #halftest +o halftest_user")
        .await
        .unwrap();
    expect_event(
        &mut events_half,
        5000,
        |e| matches!(e, Event::ServerNotice { text } if text.contains("Moderators can only set")),
        "halfop can't set +o",
    )
    .await;

    // Halfop CANNOT set +m
    handle_half.raw("MODE #halftest +m").await.unwrap();
    expect_event(
        &mut events_half,
        5000,
        |e| matches!(e, Event::ServerNotice { text } if text.contains("Moderators can only set")),
        "halfop can't set +m",
    )
    .await;

    // Op sets +m, halfop can still speak
    handle_op.raw("MODE #halftest +m").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    while events_op.try_recv().is_ok() {}
    while events_half.try_recv().is_ok() {}

    handle_half
        .privmsg("#halftest", "halfop can speak")
        .await
        .unwrap();
    expect_event(
        &mut events_op,
        5000,
        |e| matches!(e, Event::Message { text, .. } if text == "halfop can speak"),
        "halfop speaks in +m",
    )
    .await;
}

// ── Test: Message signing for DID-authenticated users ───────────────

#[tokio::test]
async fn message_signing_authenticated_user() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:sigtest";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Authenticated user
    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "signer".to_string(),
        user: "signer".to_string(),
        realname: "Signer".to_string(),
        ..Default::default()
    };
    let (handle_auth, mut events_auth) = client::connect(config, Some(signer));
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "auth registered",
    )
    .await;

    // Guest user (to receive messages and check for sig tag)
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "observer".to_string(),
        user: "observer".to_string(),
        realname: "Observer".to_string(),
        ..Default::default()
    };
    let (handle_guest, mut events_guest) = client::connect(config2, None);
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "guest registered",
    )
    .await;

    // Both join channel
    handle_auth.join("#sigtest").await.unwrap();
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#sigtest"),
        "auth joined",
    )
    .await;
    handle_guest.join("#sigtest").await.unwrap();
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#sigtest"),
        "guest joined",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    while events_auth.try_recv().is_ok() {}
    while events_guest.try_recv().is_ok() {}

    // Authenticated user sends message
    handle_auth
        .privmsg("#sigtest", "signed hello")
        .await
        .unwrap();

    // Guest should receive message WITH sig tag
    let msg = expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "signed hello"),
        "guest got signed msg",
    )
    .await;

    if let Event::Message { tags, .. } = &msg {
        assert!(
            tags.contains_key("+freeq.at/sig"),
            "Message from authenticated user should have +freeq.at/sig tag. Tags: {:?}",
            tags
        );
        let sig = tags.get("+freeq.at/sig").unwrap();
        assert!(!sig.is_empty(), "Signature should not be empty");
    }

    // Guest sends a message — should NOT have sig tag
    handle_guest
        .privmsg("#sigtest", "unsigned hello")
        .await
        .unwrap();
    let msg2 = expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "unsigned hello"),
        "auth got unsigned msg",
    )
    .await;

    if let Event::Message { tags, .. } = &msg2 {
        assert!(
            !tags.contains_key("+freeq.at/sig"),
            "Message from guest should NOT have +freeq.at/sig tag. Tags: {:?}",
            tags
        );
    }

    handle_auth.quit(None).await.unwrap();
    handle_guest.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: IRCv3 account-tag — channel + DM, gated on cap negotiation ──

#[tokio::test]
async fn account_tag_on_channel_and_dm() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:accounttagtest";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Authenticated sender
    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));
    let config_auth = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "authsender".to_string(),
        user: "authsender".to_string(),
        realname: "Auth".to_string(),
        ..Default::default()
    };
    let (handle_auth, mut events_auth) = client::connect(config_auth, Some(signer));
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "auth authenticated",
    )
    .await;
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "auth registered",
    )
    .await;

    // Receiver — guest, but the SDK still negotiates account-tag, so they should
    // see the `account` tag on messages from the authenticated sender.
    let config_recv = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "receiver".to_string(),
        user: "receiver".to_string(),
        realname: "Receiver".to_string(),
        ..Default::default()
    };
    let (handle_recv, mut events_recv) = client::connect(config_recv, None);
    expect_event(
        &mut events_recv,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "receiver registered",
    )
    .await;

    // ── Channel case ──
    handle_auth.join("#acct").await.unwrap();
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#acct"),
        "auth joined channel",
    )
    .await;
    handle_recv.join("#acct").await.unwrap();
    expect_event(
        &mut events_recv,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#acct"),
        "receiver joined channel",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    while events_auth.try_recv().is_ok() {}
    while events_recv.try_recv().is_ok() {}

    handle_auth.privmsg("#acct", "channel hello").await.unwrap();

    let chan_msg = expect_event(
        &mut events_recv,
        2000,
        |e| matches!(e, Event::Message { text, target, .. } if text == "channel hello" && target == "#acct"),
        "receiver got channel msg",
    )
    .await;

    if let Event::Message { tags, .. } = &chan_msg {
        let account = tags.get("account");
        assert_eq!(
            account.map(|s| s.as_str()),
            Some(did_str),
            "channel message from authenticated user should carry account=<did>. Tags: {:?}",
            tags
        );
    }

    // ── DM case ──
    handle_auth.privmsg("receiver", "dm hello").await.unwrap();

    let dm_msg = expect_event(
        &mut events_recv,
        2000,
        |e| matches!(e, Event::Message { text, target, .. } if text == "dm hello" && target == "receiver"),
        "receiver got DM",
    )
    .await;

    if let Event::Message { tags, .. } = &dm_msg {
        let account = tags.get("account");
        assert_eq!(
            account.map(|s| s.as_str()),
            Some(did_str),
            "DM from authenticated user should carry account=<did>. Tags: {:?}",
            tags
        );
    }

    // ── Negative case: guest sender ──
    // The receiver should NOT see an account tag for messages from a guest
    // (no DID = no account tag), even though it negotiated account-tag.
    handle_recv.privmsg("#acct", "from guest").await.unwrap();
    let guest_msg = expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "from guest"),
        "auth got guest msg",
    )
    .await;
    if let Event::Message { tags, .. } = &guest_msg {
        assert!(
            !tags.contains_key("account"),
            "Message from guest should NOT carry account tag. Tags: {:?}",
            tags
        );
    }

    handle_auth.quit(None).await.unwrap();
    handle_recv.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Client-signed message can be verified by server's /api/v1/signing-keys/{did} ──

#[tokio::test]
async fn client_signature_verification() {
    use base64::Engine;

    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:clientsigtest";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Authenticated user
    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_str.to_string(), private_key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "csigner".to_string(),
        user: "csigner".to_string(),
        realname: "Client Signer".to_string(),
        ..Default::default()
    };
    let (handle_auth, mut events_auth) = client::connect(config, Some(signer));
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "auth registered",
    )
    .await;

    // Guest observer
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "verifier".to_string(),
        user: "verifier".to_string(),
        realname: "Verifier".to_string(),
        ..Default::default()
    };
    let (handle_guest, mut events_guest) = client::connect(config2, None);
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "guest registered",
    )
    .await;

    // Both join
    handle_auth.join("#csigtest").await.unwrap();
    expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#csigtest"),
        "auth joined",
    )
    .await;
    handle_guest.join("#csigtest").await.unwrap();
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#csigtest"),
        "guest joined",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    while events_auth.try_recv().is_ok() {}
    while events_guest.try_recv().is_ok() {}

    // Send a message
    handle_auth.privmsg("#csigtest", "verify me").await.unwrap();

    let msg = expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "verify me"),
        "got signed message",
    )
    .await;

    if let Event::Message { tags, .. } = &msg {
        assert!(
            tags.contains_key("+freeq.at/sig"),
            "Should have sig tag: {:?}",
            tags
        );
        // The signature should be present and non-empty
        let sig_b64 = tags.get("+freeq.at/sig").unwrap();
        assert!(!sig_b64.is_empty());
        // Verify it's a valid base64url-encoded 64-byte ed25519 signature
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");
    }

    handle_auth.quit(None).await.unwrap();
    handle_guest.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: DM history for authenticated users ────────────────────────

#[tokio::test]
async fn dm_history_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("dm_hist.db");
    let db_str = db_path.to_str().unwrap();

    // Set up two authenticated users
    let key_alice = PrivateKey::generate_secp256k1();
    let did_alice = "did:plc:dmhistalice";
    let doc_alice = did::make_test_did_document(did_alice, &key_alice.public_key_multibase());

    let key_bob = PrivateKey::generate_secp256k1();
    let did_bob = "did:plc:dmhistbob";
    let doc_bob = did::make_test_did_document(did_bob, &key_bob.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_alice.to_string(), doc_alice);
    docs.insert(did_bob.to_string(), doc_bob);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server_with_db(resolver, db_str).await;

    // Alice connects and authenticates
    let signer_alice: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_alice.to_string(), key_alice));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "dmalice".to_string(),
        user: "dmalice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer_alice));
    expect_event(
        &mut events_alice,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Bob connects and authenticates
    let signer_bob: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_bob.to_string(), key_bob));
    let config_bob = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "dmbob".to_string(),
        user: "dmbob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle_bob, mut events_bob) = client::connect(config_bob, Some(signer_bob));
    expect_event(
        &mut events_bob,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Bob authed",
    )
    .await;
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    // Alice sends a DM to Bob
    handle_alice.privmsg("dmbob", "hey bob!").await.unwrap();

    // Bob receives the DM
    let dm = expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Message { from, text, .. } if from == "dmalice" && text == "hey bob!"),
        "Bob receives DM",
    )
    .await;
    assert!(matches!(dm, Event::Message { .. }));

    // Small delay to ensure persistence
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice requests DM history with Bob
    handle_alice.history_latest("dmbob", 50).await.unwrap();

    // Alice should receive a batch with the DM
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchStart { batch_type, .. } if batch_type == "chathistory"),
        "Alice gets chathistory batch start",
    )
    .await;

    let hist_msg = expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "hey bob!"),
        "Alice sees DM in history",
    )
    .await;
    if let Event::Message { tags, .. } = &hist_msg {
        assert!(
            tags.contains_key("batch"),
            "History message should have batch tag"
        );
    }

    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchEnd { .. }),
        "Alice gets batch end",
    )
    .await;

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: CHATHISTORY includes account (DID) tag ─────────────────────

#[tokio::test]
async fn chathistory_includes_account_tag() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("acct_tag.db");
    let db_str = db_path.to_str().unwrap();

    let key_alice = PrivateKey::generate_secp256k1();
    let did_alice = "did:plc:acctalice";
    let doc_alice = did::make_test_did_document(did_alice, &key_alice.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_alice.to_string(), doc_alice);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server_with_db(resolver, db_str).await;

    // Alice connects and authenticates
    let signer_alice: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_alice.to_string(), key_alice));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "acctalice".to_string(),
        user: "acctalice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer_alice));
    expect_event(
        &mut events_alice,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice joins a channel and sends a message
    handle_alice.join("#accttest").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    handle_alice
        .privmsg("#accttest", "hello from alice")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Request CHATHISTORY
    handle_alice.history_latest("#accttest", 50).await.unwrap();

    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchStart { batch_type, .. } if batch_type == "chathistory"),
        "Chathistory batch start",
    )
    .await;

    let hist_msg = expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "hello from alice"),
        "Alice sees message in history",
    )
    .await;

    // The history message should have the account tag with Alice's DID
    if let Event::Message { tags, .. } = &hist_msg {
        let account = tags.get("account");
        assert_eq!(
            account.map(|s| s.as_str()),
            Some(did_alice),
            "CHATHISTORY message should include account tag with sender DID, got tags: {tags:?}"
        );
    } else {
        panic!("Expected Message event");
    }

    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchEnd { .. }),
        "Chathistory batch end",
    )
    .await;

    handle_alice.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: JOIN history replay includes account (DID) tag ─────────────

#[tokio::test]
async fn join_history_includes_account_tag() {
    let key_alice = PrivateKey::generate_secp256k1();
    let did_alice = "did:plc:joinhist";
    let doc_alice = did::make_test_did_document(did_alice, &key_alice.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_alice.to_string(), doc_alice);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Alice connects and authenticates
    let signer_alice: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_alice.to_string(), key_alice));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "joinalice".to_string(),
        user: "joinalice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer_alice));
    expect_event(
        &mut events_alice,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Alice joins and sends a message
    handle_alice.join("#joinhisttest").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Alice joined",
    )
    .await;

    handle_alice
        .privmsg("#joinhisttest", "hello from alice")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob joins as guest — should see Alice's message in JOIN history replay
    let config_bob = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "joinbob".to_string(),
        user: "joinbob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle_bob, mut events_bob) = client::connect(config_bob, None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Bob registered",
    )
    .await;

    handle_bob.join("#joinhisttest").await.unwrap();

    // Bob should see Alice's message in the JOIN history replay with account tag
    let hist_msg = expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "hello from alice"),
        "Bob sees Alice's message in JOIN history",
    )
    .await;

    if let Event::Message { tags, .. } = &hist_msg {
        assert_eq!(
            tags.get("account").map(|s| s.as_str()),
            Some(did_alice),
            "JOIN history should include account tag, got tags: {tags:?}"
        );
        assert!(
            tags.contains_key("msgid"),
            "JOIN history should include msgid tag, got tags: {tags:?}"
        );
        assert!(
            tags.contains_key("time"),
            "JOIN history should include time tag, got tags: {tags:?}"
        );
        assert!(
            tags.contains_key("batch"),
            "JOIN history should include batch tag, got tags: {tags:?}"
        );
    } else {
        panic!("Expected Message event");
    }

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Guest cannot access DM history ─────────────────────────────

#[tokio::test]
async fn dm_history_rejected_for_guest() {
    let key_alice = PrivateKey::generate_secp256k1();
    let did_alice = "did:plc:dmguest";
    let doc_alice = did::make_test_did_document(did_alice, &key_alice.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_alice.to_string(), doc_alice);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Alice authenticates
    let signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(did_alice.to_string(), key_alice));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "dmauth".to_string(),
        user: "dmauth".to_string(),
        realname: "Auth".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer));
    expect_event(
        &mut events_alice,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Alice authed",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Alice registered",
    )
    .await;

    // Guest connects
    let config_guest = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "dmguest".to_string(),
        user: "dmguest".to_string(),
        realname: "Guest".to_string(),
        ..Default::default()
    };
    let (handle_guest, mut events_guest) = client::connect(config_guest, None);
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Guest registered",
    )
    .await;

    // Guest requests DM history — should fail with ACCOUNT_REQUIRED
    handle_guest
        .raw("CHATHISTORY LATEST dmauth * 50")
        .await
        .unwrap();

    // Should get a FAIL notice about authentication
    expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::ServerNotice { text } if text.contains("authenticated")),
        "Guest gets auth error",
    )
    .await;

    handle_alice.quit(None).await.unwrap();
    handle_guest.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: a delete addressed to the wrong target must not desync views ──
//
// `handle_delete` resolves the original row through
// `find_original_message`, whose last resort is a *global* msgid lookup with
// no target constraint (a ULID is unique, and authorship is re-checked). But
// the rest of `handle_delete` decides what to clean up from `is_channel`,
// derived from the WIRE target:
//
//   - the DB soft-delete uses `storage_key` = the row's REAL channel, while
//   - the in-memory `ch.history` / `ch.pins` purge is gated on `is_channel`.
//
// So a `+draft/delete` sent to a DM target for a msgid that lives in a
// channel deletes the row in the DB but leaves it in the channel's in-memory
// history. CHATHISTORY is DB-backed and JOIN replay is memory-backed
// (channel.rs reads `ch.history`), so the two views disagree and the
// "deleted" message resurrects for every new joiner until a restart.
//
// The invariant asserted here is deliberately NOT "the delete took effect" —
// it's "both views agree", which holds whether the server honours or rejects
// the cross-target delete. That keeps the test valid under either fix.
#[tokio::test]
async fn cross_target_delete_does_not_desync_channel_views() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("xdelete.db");
    let db_str = db_path.to_str().unwrap();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

    let mk = |nick: &str| ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };

    let (handle_alice, mut events_alice) = client::connect(mk("alice"), None);
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "alice registered",
    )
    .await;
    handle_alice.join("#xdelete").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "alice joined",
    )
    .await;

    let (handle_bob, mut events_bob) = client::connect(mk("bob"), None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "bob registered",
    )
    .await;
    handle_bob.join("#xdelete").await.unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bob joined",
    )
    .await;
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"),
        "alice sees bob join",
    )
    .await;

    // Alice posts in the channel; Bob's copy carries the server-assigned msgid.
    handle_alice
        .privmsg("#xdelete", "resurrect me")
        .await
        .unwrap();
    let msg_evt = expect_event(
        &mut events_bob,
        2000,
        |e| {
            matches!(e, Event::Message { from, target, text, .. }
            if from == "alice" && target == "#xdelete" && text == "resurrect me")
        },
        "bob receives alice's channel message",
    )
    .await;
    let msgid = if let Event::Message { tags, .. } = &msg_evt {
        tags.get("msgid")
            .cloned()
            .expect("server should attach msgid")
    } else {
        unreachable!()
    };

    // The attack/bug shape: delete addressed to a DM target ("bob"), for a
    // msgid that lives in "#xdelete".
    let mut del_tags = HashMap::new();
    del_tags.insert("+draft/delete".to_string(), msgid.clone());
    handle_alice.send_tagmsg("bob", del_tags).await.unwrap();

    // Let the server finish any DB write before we compare the two views.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // What the DB now believes, which is the authority the two live views are
    // supposed to agree with.
    let db_says_deleted = {
        let db = freeq_server::db::Db::open(db_str).unwrap();
        db.get_message_by_msgid("#xdelete", &msgid)
            .unwrap()
            .and_then(|r| r.deleted_at)
            .is_some()
    };

    // View 1 — CHATHISTORY, served from the DB (`get_messages` filters
    // `deleted_at IS NULL`). Drain first, then anchor on the batch opener, so
    // this cannot match Alice's own echo-message copy.
    drain_events(&mut events_alice).await;
    handle_alice.history_latest("#xdelete", 50).await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchStart { batch_type, .. } if batch_type == "chathistory"),
        "chathistory batch start",
    )
    .await;
    let in_chathistory = saw_event(
        &mut events_alice,
        1500,
        |e| matches!(e, Event::Message { text, .. } if text == "resurrect me"),
    )
    .await;

    // View 2 — a fresh joiner's replay, served from in-memory ch.history.
    let (handle_carol, mut events_carol) = client::connect(mk("carol"), None);
    expect_event(
        &mut events_carol,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "carol registered",
    )
    .await;
    handle_carol.join("#xdelete").await.unwrap();
    let in_join_replay = saw_event(
        &mut events_carol,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "resurrect me"),
    )
    .await;

    // The invariant: the DB and every live view must tell the same story.
    // Whether the server honours the cross-target delete or rejects it, these
    // three must agree — otherwise a message is "deleted" in one view and
    // alive in another.
    assert_eq!(
        in_chathistory, in_join_replay,
        "channel views disagree after a cross-target delete: \
         CHATHISTORY(db-backed)={in_chathistory} vs JOIN-replay(memory-backed)={in_join_replay}"
    );
    assert_eq!(
        db_says_deleted, !in_join_replay,
        "DB and live channel view disagree: db_says_deleted={db_says_deleted} but the \
         channel still replays the message to new joiners (in_join_replay={in_join_replay}). \
         A delete addressed to a DM target soft-deleted a CHANNEL row in the DB while \
         `handle_delete` skipped the in-memory history/pin purge (it gates that on \
         `is_channel`, derived from the wire target) and broadcast the removal to the DM \
         recipient instead of the channel. Net effect: the message is gone from search and \
         from history after the next restart, but every current member still sees it, and \
         nobody in the channel was told."
    );

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    handle_carol.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TAGMSG must treat channel names case-insensitively ────────────
//
// IRC channel names are case-insensitive, and `process_privmsg` normalizes its
// target (`normalize_channel`) before storing — so messages always land under
// the lowercased key. `handle_tagmsg` does NOT normalize: it hands the raw wire
// target to `handle_delete` / the reaction paths. A client that preserves the
// display case it joined with (e.g. "#Case") therefore addresses a key that
// doesn't exist, and:
//
//   - delete/edit fail with MESSAGE_NOT_FOUND — you cannot delete your own
//     message, and
//   - reactions persist under the un-normalized key, orphaned from the message
//     they annotate.
//
// Asserted here on delete, because "the author asked to delete it and it is
// still there" is the least ambiguous failure.
#[tokio::test]
async fn delete_honours_case_insensitive_channel_names() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("casedel.db");
    let db_str = db_path.to_str().unwrap();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

    let mk = |nick: &str| ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };

    let (handle_alice, mut events_alice) = client::connect(mk("alice"), None);
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "alice registered",
    )
    .await;
    let (handle_bob, mut events_bob) = client::connect(mk("bob"), None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "bob registered",
    )
    .await;

    // Both join using mixed case; the server normalizes JOIN, so the channel
    // itself lives under "#case".
    handle_alice.join("#Case").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "alice joined",
    )
    .await;
    handle_bob.join("#Case").await.unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bob joined",
    )
    .await;

    handle_alice.privmsg("#Case", "delete me").await.unwrap();
    let msg_evt = expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "delete me"),
        "bob receives the message",
    )
    .await;
    let msgid = if let Event::Message { tags, .. } = &msg_evt {
        tags.get("msgid").cloned().expect("msgid")
    } else {
        unreachable!()
    };

    // The author deletes it, addressing the channel the way their client
    // displays it.
    let mut del_tags = HashMap::new();
    del_tags.insert("+draft/delete".to_string(), msgid.clone());
    handle_alice.send_tagmsg("#Case", del_tags).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // It must be gone from the DB…
    let db_deleted = {
        let db = freeq_server::db::Db::open(db_str).unwrap();
        db.get_message_by_msgid("#case", &msgid)
            .unwrap()
            .and_then(|r| r.deleted_at)
            .is_some()
    };
    // …and from the live view a new joiner is served.
    let (handle_carol, mut events_carol) = client::connect(mk("carol"), None);
    expect_event(
        &mut events_carol,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "carol registered",
    )
    .await;
    handle_carol.join("#case").await.unwrap();
    let replayed_to_new_joiner = saw_event(
        &mut events_carol,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "delete me"),
    )
    .await;

    assert!(
        db_deleted,
        "author's delete addressed to \"#Case\" did not delete the row stored under \"#case\": \
         handle_tagmsg passes the raw wire target through, so the msgid lookup misses and the \
         server answers MESSAGE_NOT_FOUND. PRIVMSG normalizes its target; TAGMSG must too."
    );
    assert!(
        !replayed_to_new_joiner,
        "deleted message is still replayed from in-memory history to new joiners"
    );

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    handle_carol.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: deleting an edited message must remove the edit too ────────────
//
// An edit is stored as a NEW row carrying `replaces_msgid = <original>`
// (db.rs INSERT ... replaces_msgid). `soft_delete_message` marks only the row
// whose `msgid` matches exactly, and `get_messages` returns every row with
// `deleted_at IS NULL` — including edit rows.
//
// Clients keep the ORIGINAL msgid as the message's identity (that is the whole
// point of `+draft/edit=<original>`), so a delete names the original. If the
// edit row isn't swept with it, the latest text — the version the user actually
// wants gone — survives in history. That's a delete that reports success and
// leaves the content readable.
#[tokio::test]
async fn deleting_an_edited_message_removes_the_edit_revision() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("editdel.db");
    let db_str = db_path.to_str().unwrap();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

    let mk = |nick: &str| ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };

    let (handle_alice, mut events_alice) = client::connect(mk("alice"), None);
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "alice registered",
    )
    .await;
    let (handle_bob, mut events_bob) = client::connect(mk("bob"), None);
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "bob registered",
    )
    .await;
    handle_alice.join("#editdel").await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "alice joined",
    )
    .await;
    handle_bob.join("#editdel").await.unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bob joined",
    )
    .await;

    // v1 → capture the identity the client will keep using.
    handle_alice.privmsg("#editdel", "secret v1").await.unwrap();
    let first = expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "secret v1"),
        "bob receives v1",
    )
    .await;
    let original_msgid = if let Event::Message { tags, .. } = &first {
        tags.get("msgid").cloned().expect("msgid")
    } else {
        unreachable!()
    };

    // v2 — an edit of that message.
    handle_alice
        .edit_message("#editdel", &original_msgid, "secret v2")
        .await
        .unwrap();
    expect_event(
        &mut events_bob,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "secret v2"),
        "bob receives the edit",
    )
    .await;

    // The author deletes the message, naming it the only way a client can.
    handle_alice
        .delete_message("#editdel", &original_msgid)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Nothing about this message may survive in history.
    drain_events(&mut events_alice).await;
    handle_alice.history_latest("#editdel", 50).await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchStart { batch_type, .. } if batch_type == "chathistory"),
        "chathistory batch start",
    )
    .await;
    let v1_survives = saw_event(
        &mut events_alice,
        1200,
        |e| matches!(e, Event::Message { text, .. } if text == "secret v1"),
    )
    .await;
    drain_events(&mut events_alice).await;
    handle_alice.history_latest("#editdel", 50).await.unwrap();
    expect_event(
        &mut events_alice,
        2000,
        |e| matches!(e, Event::BatchStart { batch_type, .. } if batch_type == "chathistory"),
        "chathistory batch start (2)",
    )
    .await;
    let v2_survives = saw_event(
        &mut events_alice,
        1200,
        |e| matches!(e, Event::Message { text, .. } if text == "secret v2"),
    )
    .await;

    assert!(
        !v1_survives,
        "original revision still in history after delete"
    );
    assert!(
        !v2_survives,
        "the EDIT revision (\"secret v2\") survived a delete of its original msgid. \
         soft_delete_message only marks the exact msgid, and edits are separate rows \
         carrying replaces_msgid — so the latest text, the version the user most wants \
         gone, stays readable in CHATHISTORY and in search."
    );

    handle_alice.quit(None).await.unwrap();
    handle_bob.quit(None).await.unwrap();
    server_handle.abort();
}
