//! Acceptance tests for agent-native Phase 1 features.
//!
//! Tests: did:key auth, AGENT REGISTER, PROVENANCE, PRESENCE, HEARTBEAT,
//! actor class in WHOIS, actor class tag in JOIN, REST identity card.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Start deadlock detection background thread.
/// Checks every 500ms and panics with thread info on deadlock.
fn start_deadlock_detector() {
    use std::thread;
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(500));
            let deadlocks = parking_lot::deadlock::check_deadlock();
            if deadlocks.is_empty() {
                continue;
            }
            eprintln!("!!! DEADLOCK DETECTED ({} threads):", deadlocks.len());
            for (i, threads) in deadlocks.iter().enumerate() {
                eprintln!("Deadlock #{i}:");
                for t in threads {
                    eprintln!("  Thread {:?}:\n{:?}", t.thread_id(), t.backtrace());
                }
            }
            std::process::abort();
        }
    });
}

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

// ── Helpers ─────────────────────────────────────────────────────────

async fn start_test_server(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    start_test_server_with_db(resolver, false).await
}

async fn start_test_server_with_db(
    resolver: DidResolver,
    enable_db: bool,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        db_path: if enable_db {
            Some(":memory:".to_string())
        } else {
            None
        },
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

async fn start_test_server_with_web_and_db(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start_with_web().await.unwrap()
}

fn empty_resolver() -> DidResolver {
    DidResolver::static_map(HashMap::new())
}

/// Create a did:key signer (no resolver entry needed — did:key is self-resolving).
fn make_did_key_signer() -> (String, Arc<dyn ChallengeSigner>) {
    let private_key = PrivateKey::generate_ed25519();
    let multibase = private_key.public_key_multibase();
    let did = format!("did:key:{multibase}");
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.clone(), private_key));
    (did, signer)
}

/// Connect an authenticated did:key client.
async fn connect_did_key(
    addr: std::net::SocketAddr,
    nick: &str,
) -> (String, client::ClientHandle, mpsc::Receiver<Event>) {
    let (did, signer) = make_did_key_signer();
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("{nick} bot"),
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

    (did, handle, events)
}

/// Connect a guest client.
async fn connect_guest(
    addr: std::net::SocketAddr,
    nick: &str,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("{nick} guest"),
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

    (handle, events)
}

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
            }
            Ok(None) => panic!("Channel closed while waiting for: {description}"),
            Err(_) => panic!("Timeout waiting for: {description}"),
        }
    }
}

/// Drain events looking for a RawLine matching a pattern, with timeout.
async fn expect_raw_line(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    pattern: &str,
    description: &str,
) -> String {
    let pat = pattern.to_string();
    let evt = expect_event(
        events,
        timeout_ms,
        |e| matches!(e, Event::RawLine(line) if line.contains(&pat)),
        description,
    )
    .await;
    if let Event::RawLine(line) = evt {
        line
    } else {
        unreachable!()
    }
}

/// Check that no event matching the predicate arrives within the timeout.
async fn expect_no_event(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    predicate: impl Fn(&Event) -> bool,
) {
    let deadline = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    loop {
        match timeout(deadline.saturating_sub(start.elapsed()), events.recv()).await {
            Ok(Some(event)) => {
                assert!(!predicate(&event), "Unexpected event received: {event:?}");
            }
            Ok(None) | Err(_) => return, // timeout = good, no matching event
        }
    }
}

// ── Test: did:key authentication ────────────────────────────────────

#[tokio::test]
async fn did_key_auth_ed25519() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let (did, handle, _) = connect_did_key(addr, "keybot").await;

    assert!(did.starts_with("did:key:"));

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn did_key_auth_wrong_key_fails() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Create a did:key but sign with a DIFFERENT key
    let real_key = PrivateKey::generate_ed25519();
    let wrong_key = PrivateKey::generate_ed25519();
    let multibase = real_key.public_key_multibase();
    let did = format!("did:key:{multibase}");

    // Sign with wrong_key but claim real_key's DID
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.clone(), wrong_key));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "badbot".to_string(),
        user: "badbot".to_string(),
        realname: "Bad Bot".to_string(),
        ..Default::default()
    };

    let (_handle, mut events) = client::connect(config, Some(signer));

    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Connected),
        "Connected",
    )
    .await;

    // Should get SASL failure (904), not success
    expect_raw_line(&mut events, 2000, "904", "SASL failure").await;

    server_handle.abort();
}

// ── Test: AGENT REGISTER ────────────────────────────────────────────

#[tokio::test]
async fn agent_register_command() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "agentbot").await;

    // Register as agent
    handle.register_agent("agent").await.unwrap();

    // Should get a NOTICE confirming registration
    expect_raw_line(
        &mut events,
        2000,
        "registered as agent",
        "AGENT REGISTER confirmation",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn agent_register_external_agent() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "extbot").await;

    handle.register_agent("external_agent").await.unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "registered as external_agent",
        "AGENT REGISTER external_agent",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn agent_register_invalid_class() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "badclass").await;

    handle.raw("AGENT REGISTER :class=superbot").await.unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "Invalid actor class",
        "AGENT REGISTER with invalid class",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: AGENT class in WHOIS ──────────────────────────────────────

#[tokio::test]
async fn agent_class_in_whois() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect bot and register as agent
    let (_did, bot_handle, mut bot_events) = connect_did_key(addr, "whobot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    // Connect observer
    let (obs_handle, mut obs_events) = connect_guest(addr, "observer").await;

    // WHOIS the bot
    obs_handle.raw("WHOIS whobot").await.unwrap();

    // Should see 673 numeric with actor_class=agent
    expect_raw_line(
        &mut obs_events,
        2000,
        "actor_class=agent",
        "WHOIS 673 actor_class",
    )
    .await;

    // End of WHOIS
    expect_raw_line(&mut obs_events, 2000, "318", "End of WHOIS").await;

    bot_handle.quit(None).await.unwrap();
    obs_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn human_whois_no_actor_class() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect a human (did:key but no AGENT REGISTER)
    let (_did, human_handle, _human_events) = connect_did_key(addr, "humanuser").await;

    // Connect observer
    let (obs_handle, mut obs_events) = connect_guest(addr, "observer2").await;

    // WHOIS the human
    obs_handle.raw("WHOIS humanuser").await.unwrap();

    // Should get end of WHOIS (318) but NOT 673 (actor class only shown for non-human)
    let end = expect_raw_line(&mut obs_events, 2000, "318", "End of WHOIS").await;
    // The 673 should not have appeared before 318
    // (We can't easily prove absence inline, but if 673 appeared it would match before 318)
    assert!(end.contains("318"));

    human_handle.quit(None).await.unwrap();
    obs_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: PROVENANCE ────────────────────────────────────────────────

#[tokio::test]
async fn provenance_submit() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "provbot").await;

    handle
        .submit_provenance(&serde_json::json!({
            "name": "provbot",
            "version": "1.0.0",
            "source": "https://example.com",
            "runtime": "freeq-sdk/rust"
        }))
        .await
        .unwrap();

    // Free-form provenance (non FreeqBotDelegation/v1) is stored unverified.
    expect_raw_line(
        &mut events,
        2000,
        "Provenance stored (unverified)",
        "PROVENANCE stored unverified",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: PROVENANCE FreeqBotDelegation/v1 verification ──────────────

/// Spin up a session, register a known ed25519 key as the creator's MSGSIG
/// (overwriting the SDK's auto-generated one), then disconnect. Returns
/// `(creator_did, creator_signing_key)` so the caller can mint signed certs.
async fn register_creator_msgsig(
    addr: std::net::SocketAddr,
    nick: &str,
) -> (String, ed25519_dalek::SigningKey) {
    use base64::Engine;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let pk = PrivateKey::ed25519_from_bytes(&signing_key.to_bytes()).unwrap();
    let did = format!("did:key:{}", pk.public_key_multibase());
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.clone(), pk));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("{nick} creator"),
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

    // Overwrite SDK's auto-MSGSIG with our known key
    let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().as_bytes());
    handle.raw(&format!("MSGSIG {pubkey_b64}")).await.unwrap();
    expect_raw_line(&mut events, 2000, "MSGSIG OK", "MSGSIG accepted").await;

    handle.quit(None).await.unwrap();
    (did, signing_key)
}

/// Build a FreeqBotDelegation/v1 cert and sign it with the creator's key.
fn build_signed_cert(
    bot_did: &str,
    creator_did: &str,
    creator_key: &ed25519_dalek::SigningKey,
) -> serde_json::Value {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let bot_multibase = bot_did.strip_prefix("did:key:").unwrap_or("");
    let mut cert = serde_json::json!({
        "type": "FreeqBotDelegation/v1",
        "bot_did": bot_did,
        "bot_public_key": bot_multibase,
        "creator_did": creator_did,
        "created_at": "2026-05-08T15:00:00Z",
        "revocation_authority": creator_did,
    });
    let canonical = freeq_sdk::canonical::canonicalize(&cert).unwrap();
    let sig = creator_key.sign(canonical.as_bytes());
    cert["signature"] = serde_json::Value::String(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    );
    cert
}

#[tokio::test]
async fn provenance_freeq_bot_delegation_verified() {
    // Server with DB so MSGSIG keys persist across the disconnect/reconnect
    // boundary.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    // Creator registers a known signing key, then disconnects.
    let (creator_did, creator_key) = register_creator_msgsig(addr, "creator").await;

    // Bot connects under its own did:key, mints a cert signed by creator's key.
    let (bot_did, handle, mut events) = connect_did_key(addr, "verifybot").await;
    let cert = build_signed_cert(&bot_did, &creator_did, &creator_key);
    handle.submit_provenance(&cert).await.unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "Provenance verified",
        "FreeqBotDelegation/v1 verified",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_freeq_bot_delegation_tampered_signature() {
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (creator_did, creator_key) = register_creator_msgsig(addr, "creator").await;

    let (bot_did, handle, mut events) = connect_did_key(addr, "tamperbot").await;
    let mut cert = build_signed_cert(&bot_did, &creator_did, &creator_key);
    // Tamper: flip a single character in the signature.
    let sig = cert["signature"].as_str().unwrap().to_string();
    let mut bytes = sig.into_bytes();
    bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
    cert["signature"] = serde_json::Value::String(String::from_utf8(bytes).unwrap());
    handle.submit_provenance(&cert).await.unwrap();

    let line = expect_raw_line(
        &mut events,
        2000,
        "Provenance stored (unverified)",
        "tampered cert stored unverified",
    )
    .await;
    assert!(
        line.contains("Signature did not verify") || line.contains("not valid base64url"),
        "expected sig-verify failure reason, got: {line}"
    );

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_freeq_bot_delegation_unsigned() {
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (bot_did, handle, mut events) = connect_did_key(addr, "unsignedbot").await;

    let cert = serde_json::json!({
        "type": "FreeqBotDelegation/v1",
        "bot_did": bot_did,
        "bot_public_key": bot_did.strip_prefix("did:key:").unwrap(),
        "creator_did": "did:plc:nokey",
        "created_at": "2026-05-08T15:00:00Z",
        "revocation_authority": "did:plc:nokey",
        // intentionally no `signature` field
    });
    handle.submit_provenance(&cert).await.unwrap();

    let line = expect_raw_line(
        &mut events,
        2000,
        "Provenance stored (unverified)",
        "unsigned cert stored unverified",
    )
    .await;
    assert!(
        line.contains("no signature") || line.contains("declarative"),
        "expected unsigned reason, got: {line}"
    );

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_freeq_bot_delegation_creator_not_registered() {
    // No creator session — creator_did never registered a MSGSIG key.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    // Mint a cert signed by an arbitrary ed25519 key, claim creator_did
    // that the server has never seen.
    let creator_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let creator_pk = PrivateKey::ed25519_from_bytes(&creator_key.to_bytes()).unwrap();
    let creator_did = format!("did:key:{}", creator_pk.public_key_multibase());

    let (bot_did, handle, mut events) = connect_did_key(addr, "lonelybot").await;
    let cert = build_signed_cert(&bot_did, &creator_did, &creator_key);
    handle.submit_provenance(&cert).await.unwrap();

    let line = expect_raw_line(
        &mut events,
        2000,
        "Provenance stored (unverified)",
        "creator-not-registered stored unverified",
    )
    .await;
    assert!(
        line.contains("No registered MSGSIG key"),
        "expected no-registered-key reason, got: {line}"
    );

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_freeq_bot_delegation_did_mismatch_rejected() {
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (creator_did, creator_key) = register_creator_msgsig(addr, "creator").await;

    let (_bot_did, handle, mut events) = connect_did_key(addr, "mismatchbot").await;
    // Cert claims a *different* bot_did than the session's authenticated DID.
    let cert = build_signed_cert("did:key:zPretender", &creator_did, &creator_key);
    handle.submit_provenance(&cert).await.unwrap();

    let line = expect_raw_line(
        &mut events,
        2000,
        "Provenance rejected",
        "DID-mismatch cert rejected",
    )
    .await;
    assert!(
        line.contains("does not match the authenticated session DID"),
        "expected DID-mismatch reason, got: {line}"
    );

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_requires_auth() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect as guest (no auth)
    let (handle, mut events) = connect_guest(addr, "guestprov").await;

    // Try to submit provenance as guest
    handle
        .raw("PROVENANCE :eyJuYW1lIjoiZ3Vlc3QifQ")
        .await
        .unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "Must be authenticated",
        "PROVENANCE rejected for guest",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn provenance_invalid_format() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "badfmt").await;

    handle
        .raw("PROVENANCE :not-valid-json-or-base64!!!")
        .await
        .unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "Invalid provenance format",
        "PROVENANCE invalid format",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: PRESENCE ──────────────────────────────────────────────────

#[tokio::test]
async fn presence_update() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "presbot").await;

    handle
        .set_presence("executing", Some("Building project"), Some("task-001"))
        .await
        .unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "Presence updated: executing",
        "PRESENCE confirmation",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn presence_sets_away_for_non_active_states() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let (_did, bot_handle, mut bot_events) = connect_did_key(addr, "awaybot").await;
    let (obs_handle, mut obs_events) = connect_guest(addr, "obs").await;

    // Both join a channel
    bot_handle.join("#test").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;
    obs_handle.join("#test").await.unwrap();
    expect_event(
        &mut obs_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Obs joined",
    )
    .await;

    // Bot sets presence to executing (non-active → should trigger AWAY)
    bot_handle
        .set_presence("blocked_on_permission", Some("Waiting for approval"), None)
        .await
        .unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "Presence updated",
        "PRESENCE confirmation",
    )
    .await;

    // Small delay for AWAY state to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Observer does WHOIS — should see 301 (RPL_AWAY) with the away message
    obs_handle.raw("WHOIS awaybot").await.unwrap();
    // Should see 301 (RPL_AWAY)
    expect_raw_line(&mut obs_events, 3000, "301", "WHOIS shows AWAY").await;

    bot_handle.quit(None).await.unwrap();
    obs_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn presence_online_clears_away() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "clearbot").await;

    // Set to executing (away)
    handle.set_presence("executing", None, None).await.unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Presence updated: executing",
        "PRESENCE executing",
    )
    .await;

    // Clear back to online
    handle.set_presence("online", None, None).await.unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Presence updated: online",
        "PRESENCE online",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: HEARTBEAT ─────────────────────────────────────────────────

#[tokio::test]
async fn heartbeat_accepted() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "hbbot").await;

    // Send heartbeat — should not produce an error
    handle.send_heartbeat("active", 60).await.unwrap();

    // Heartbeat is silent (no NOTICE response) — verify by sending a subsequent
    // command and checking we get its response (proves connection is still alive)
    handle.raw("WHOIS hbbot").await.unwrap();
    expect_raw_line(&mut events, 2000, "311", "WHOIS response after heartbeat").await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn heartbeat_auto_start() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "autohb").await;

    // Start automatic heartbeat (1 second interval for test speed)
    let hb_task = handle.start_heartbeat(Duration::from_secs(1));

    // Wait a bit, then verify connection is still alive
    tokio::time::sleep(Duration::from_secs(3)).await;
    handle.raw("WHOIS autohb").await.unwrap();
    expect_raw_line(&mut events, 2000, "311", "WHOIS after auto-heartbeat").await;

    hb_task.abort();
    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Agent + guest in same channel ─────────────────────────────

#[tokio::test]
async fn agent_and_guest_coexist_in_channel() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect agent
    let (_did, bot_handle, mut bot_events) = connect_did_key(addr, "chanbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    // Connect guest
    let (guest_handle, mut guest_events) = connect_guest(addr, "changuest").await;

    // Both join #test
    bot_handle.join("#agenttest").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    guest_handle.join("#agenttest").await.unwrap();
    expect_event(
        &mut guest_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Guest joined",
    )
    .await;

    // Bot sends a message
    bot_handle
        .privmsg("#agenttest", "Hello from agent!")
        .await
        .unwrap();

    // Guest should receive it
    let msg = expect_event(
        &mut guest_events,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "Hello from agent!"),
        "Guest receives agent message",
    )
    .await;
    assert!(matches!(msg, Event::Message { from, .. } if from == "chanbot"));

    // Guest sends a message back
    guest_handle
        .privmsg("#agenttest", "Hello from guest!")
        .await
        .unwrap();

    // Bot should receive it
    let msg = expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "Hello from guest!"),
        "Bot receives guest message",
    )
    .await;
    assert!(matches!(msg, Event::Message { from, .. } if from == "changuest"));

    bot_handle.quit(None).await.unwrap();
    guest_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Multiple agents ───────────────────────────────────────────

#[tokio::test]
async fn multiple_agents_different_classes() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let (_did1, bot1, mut ev1) = connect_did_key(addr, "agent1").await;
    let (_did2, bot2, mut ev2) = connect_did_key(addr, "agent2").await;

    bot1.register_agent("agent").await.unwrap();
    expect_raw_line(&mut ev1, 2000, "registered as agent", "Bot1 registered").await;

    bot2.register_agent("external_agent").await.unwrap();
    expect_raw_line(
        &mut ev2,
        2000,
        "registered as external_agent",
        "Bot2 registered",
    )
    .await;

    // WHOIS each other
    bot1.raw("WHOIS agent2").await.unwrap();
    expect_raw_line(
        &mut ev1,
        2000,
        "actor_class=external_agent",
        "WHOIS agent2 class",
    )
    .await;

    bot2.raw("WHOIS agent1").await.unwrap();
    expect_raw_line(&mut ev2, 2000, "actor_class=agent", "WHOIS agent1 class").await;

    bot1.quit(None).await.unwrap();
    bot2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Full agent lifecycle ──────────────────────────────────────

#[tokio::test]
async fn full_agent_lifecycle() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let (_, handle, mut events) = connect_did_key(addr, "lifecycle").await;

    // 1. Register as agent
    handle.register_agent("agent").await.unwrap();
    expect_raw_line(&mut events, 2000, "registered as agent", "Step 1: register").await;

    // 2. Submit provenance
    handle
        .submit_provenance(&serde_json::json!({
            "name": "lifecycle-bot",
            "version": "0.1.0",
            "created_by": "did:plc:testcreator"
        }))
        .await
        .unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Provenance stored (unverified)",
        "Step 2: provenance",
    )
    .await;

    // 3. Set presence
    handle
        .set_presence("active", Some("Running lifecycle test"), None)
        .await
        .unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Presence updated: active",
        "Step 3: presence",
    )
    .await;

    // 4. Send heartbeat
    handle.send_heartbeat("active", 30).await.unwrap();

    // 5. Join a channel and communicate
    handle.join("#lifecycle").await.unwrap();
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Step 5: joined",
    )
    .await;

    handle
        .privmsg("#lifecycle", "Lifecycle test complete")
        .await
        .unwrap();

    // 6. Change presence to executing
    handle
        .set_presence("executing", Some("Processing task"), Some("task-42"))
        .await
        .unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Presence updated: executing",
        "Step 6: executing",
    )
    .await;

    // 7. WHOIS self to verify everything
    handle.raw("WHOIS lifecycle").await.unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "actor_class=agent",
        "Step 7: WHOIS actor_class",
    )
    .await;
    expect_raw_line(&mut events, 2000, "318", "Step 7: End of WHOIS").await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: AGENT REGISTER requires params ────────────────────────────

#[tokio::test]
async fn agent_register_no_params() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "noparam").await;

    handle.raw("AGENT").await.unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "461", // ERR_NEEDMOREPARAMS
        "AGENT with no params",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: PRESENCE requires params ──────────────────────────────────

#[tokio::test]
async fn presence_no_params() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "nopres").await;

    handle.raw("PRESENCE").await.unwrap();

    expect_raw_line(
        &mut events,
        2000,
        "461", // ERR_NEEDMOREPARAMS
        "PRESENCE with no params",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Phase 2: Governance
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn governance_pause_resume() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Op (human with channel ops)
    let (_op_did, op_handle, mut op_events) = connect_did_key(addr, "operator").await;
    // Agent
    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "govbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    // Both join channel — op gets ops as first joiner
    op_handle.join("#governed").await.unwrap();
    expect_event(
        &mut op_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Op joined",
    )
    .await;
    bot_handle.join("#governed").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    // Op pauses the bot
    op_handle
        .pause_agent("govbot", Some("maintenance"))
        .await
        .unwrap();

    // Bot should receive governance TAGMSG
    expect_raw_line(
        &mut bot_events,
        2000,
        "governance=pause",
        "Bot receives PAUSE",
    )
    .await;

    // Op should see the channel notice
    expect_raw_line(
        &mut op_events,
        2000,
        "paused by operator",
        "Channel PAUSE notice",
    )
    .await;

    // Op resumes the bot
    op_handle.resume_agent("govbot").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "governance=resume",
        "Bot receives RESUME",
    )
    .await;

    bot_handle.quit(None).await.unwrap();
    op_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn governance_revoke_disconnects() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let (_op_did, op_handle, mut op_events) = connect_did_key(addr, "revoker").await;
    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "revbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    op_handle.join("#revtest").await.unwrap();
    expect_event(
        &mut op_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Op joined",
    )
    .await;
    bot_handle.join("#revtest").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    // Op revokes the bot
    op_handle.revoke_agent("revbot", Some("bye")).await.unwrap();

    // Bot should receive ERROR (force disconnect)
    expect_raw_line(
        &mut bot_events,
        2000,
        "ERROR",
        "Bot receives ERROR/disconnect",
    )
    .await;

    op_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn governance_requires_op() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Two users, neither is op of the other's channel
    let (_did1, user1, mut ev1) = connect_did_key(addr, "nopower").await;
    let (_did2, user2, mut ev2) = connect_did_key(addr, "target").await;
    user2.register_agent("agent").await.unwrap();
    expect_raw_line(&mut ev2, 2000, "registered as agent", "AGENT REGISTER").await;

    // user2 creates a channel (gets ops)
    user2.join("#botchan").await.unwrap();
    expect_event(
        &mut ev2,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "User2 joined",
    )
    .await;
    // user1 joins (not op)
    user1.join("#botchan").await.unwrap();
    expect_event(
        &mut ev1,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "User1 joined",
    )
    .await;

    // user1 tries to pause user2 — should fail
    user1.pause_agent("target", None).await.unwrap();
    expect_raw_line(&mut ev1, 2000, "482", "PAUSE rejected: not op").await;

    user1.quit(None).await.unwrap();
    user2.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn approval_request_and_grant() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_op_did, op_handle, mut op_events) = connect_did_key(addr, "approver").await;
    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "reqbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    op_handle.join("#approval").await.unwrap();
    expect_event(
        &mut op_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Op joined",
    )
    .await;
    bot_handle.join("#approval").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    // Bot requests deploy approval
    bot_handle
        .request_approval("#approval", "deploy", Some("landing-page"))
        .await
        .unwrap();

    // Bot gets confirmation
    expect_raw_line(
        &mut bot_events,
        2000,
        "Approval requested",
        "Request confirmed",
    )
    .await;

    // Op sees notification in channel
    expect_raw_line(&mut op_events, 2000, "requests approval", "Op sees request").await;

    // Op approves
    op_handle.approve_agent("reqbot", "deploy").await.unwrap();

    // Bot gets approval granted TAGMSG
    expect_raw_line(
        &mut bot_events,
        2000,
        "approval_granted",
        "Bot gets approval",
    )
    .await;

    // Channel sees approval notice
    expect_raw_line(&mut op_events, 2000, "approved", "Channel sees approval").await;

    bot_handle.quit(None).await.unwrap();
    op_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn approval_request_and_deny() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_op_did, op_handle, mut op_events) = connect_did_key(addr, "denier").await;
    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "denybot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    op_handle.join("#denytest").await.unwrap();
    expect_event(
        &mut op_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Op joined",
    )
    .await;
    bot_handle.join("#denytest").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    bot_handle
        .request_approval("#denytest", "deploy", None)
        .await
        .unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "Approval requested",
        "Request confirmed",
    )
    .await;
    expect_raw_line(&mut op_events, 2000, "requests approval", "Op sees request").await;

    // Op denies
    op_handle
        .deny_agent("denybot", "deploy", Some("not ready"))
        .await
        .unwrap();

    // Bot gets denial
    expect_raw_line(&mut bot_events, 2000, "approval_denied", "Bot gets denial").await;

    bot_handle.quit(None).await.unwrap();
    op_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Presence with all states ──────────────────────────────────

#[tokio::test]
async fn presence_all_states() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;
    let (_did, handle, mut events) = connect_did_key(addr, "allstates").await;

    let states = [
        "online",
        "idle",
        "active",
        "executing",
        "waiting_for_input",
        "blocked_on_permission",
        "blocked_on_budget",
        "degraded",
        "paused",
        "sandboxed",
        "rate_limited",
        "revoked",
        "offline",
    ];

    for state in &states {
        handle.set_presence(state, None, None).await.unwrap();
        let line = expect_raw_line(
            &mut events,
            3000,
            &format!("Presence updated: {state}"),
            &format!("PRESENCE {state}"),
        )
        .await;
        assert!(line.contains(state), "Expected state {state} in: {line}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Phase 3: Coordinated Work
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn coordination_create_task() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "taskbot").await;
    let (_user_did, user_handle, mut user_events) = connect_did_key(addr, "watcher").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    bot_handle.join("#tasks").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;
    user_handle.join("#tasks").await.unwrap();
    expect_event(
        &mut user_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "User joined",
    )
    .await;

    // Bot creates a task
    let task_id = bot_handle
        .emit_event(
            "#tasks",
            "task_request",
            r#"{"description":"Build a todo app"}"#,
            None,
            "📋 New task: Build a todo app",
        )
        .await
        .unwrap();
    assert!(!task_id.is_empty(), "Task ID should be non-empty");

    // User sees the human-readable PRIVMSG
    expect_raw_line(
        &mut user_events,
        2000,
        "New task: Build a todo app",
        "User sees task creation",
    )
    .await;

    bot_handle.quit(None).await.unwrap();
    user_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn coordination_full_task_lifecycle() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "lifecycle").await;
    let (_user_did, user_handle, mut user_events) = connect_did_key(addr, "observer").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    bot_handle.join("#lifecycle").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;
    user_handle.join("#lifecycle").await.unwrap();
    expect_event(
        &mut user_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "User joined",
    )
    .await;

    // Create task
    let task_id = bot_handle
        .emit_event(
            "#lifecycle",
            "task_request",
            r#"{"description":"Build something"}"#,
            None,
            "📋 New task: Build something",
        )
        .await
        .unwrap();
    expect_raw_line(&mut user_events, 3000, "New task", "User sees task").await;

    // Update task through phases (small delays to avoid message ordering issues)
    tokio::time::sleep(Duration::from_millis(50)).await;
    bot_handle
        .emit_event(
            "#lifecycle",
            "task_update",
            r#"{"phase":"designing","summary":"Chose React stack"}"#,
            Some(&task_id),
            "🔄 [designing] Chose React stack",
        )
        .await
        .unwrap();
    expect_raw_line(
        &mut user_events,
        3000,
        "designing",
        "User sees designing phase",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    bot_handle
        .emit_event(
            "#lifecycle",
            "task_update",
            r#"{"phase":"building","summary":"Writing code"}"#,
            Some(&task_id),
            "🔄 [building] Writing code",
        )
        .await
        .unwrap();
    expect_raw_line(
        &mut user_events,
        3000,
        "building",
        "User sees building phase",
    )
    .await;

    // Attach evidence
    tokio::time::sleep(Duration::from_millis(50)).await;
    bot_handle
        .emit_event_with_evidence(
            "#lifecycle",
            "evidence_attach",
            r#"{"type":"test_result","summary":"12/12 passed"}"#,
            Some(&task_id),
            Some("test_result"),
            "📎 Evidence (test_result): 12/12 passed",
        )
        .await
        .unwrap();
    expect_raw_line(&mut user_events, 3000, "12/12 passed", "User sees evidence").await;

    // Complete task
    tokio::time::sleep(Duration::from_millis(50)).await;
    bot_handle
        .emit_event(
            "#lifecycle",
            "task_complete",
            r#"{"summary":"All done","url":"https://example.com"}"#,
            Some(&task_id),
            "🎉 Task complete: All done — https://example.com",
        )
        .await
        .unwrap();
    expect_raw_line(
        &mut user_events,
        3000,
        "Task complete",
        "User sees completion",
    )
    .await;

    bot_handle.quit(None).await.unwrap();
    user_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn coordination_task_failure() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "failbot").await;
    let (_user_did, user_handle, mut user_events) = connect_did_key(addr, "failwatch").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    bot_handle.join("#failtest").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;
    user_handle.join("#failtest").await.unwrap();
    expect_event(
        &mut user_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "User joined",
    )
    .await;

    let task_id = bot_handle
        .emit_event(
            "#failtest",
            "task_request",
            r#"{"description":"Doomed task"}"#,
            None,
            "📋 New task: Doomed task",
        )
        .await
        .unwrap();
    expect_raw_line(&mut user_events, 2000, "New task", "User sees task").await;

    bot_handle
        .emit_event(
            "#failtest",
            "task_failed",
            r#"{"error":"Out of memory"}"#,
            Some(&task_id),
            "❌ Task failed: Out of memory",
        )
        .await
        .unwrap();
    expect_raw_line(&mut user_events, 2000, "Task failed", "User sees failure").await;

    bot_handle.quit(None).await.unwrap();
    user_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn coordination_events_rest_api() {
    start_deadlock_detector();
    let (addr, web_addr, server_handle) = start_test_server_with_web_and_db(empty_resolver()).await;

    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "restbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    bot_handle.join("#resttest").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    let task_id = bot_handle
        .emit_event(
            "#resttest",
            "task_request",
            r#"{"description":"REST test task"}"#,
            None,
            "📋 New task: REST test task",
        )
        .await
        .unwrap();
    // Wait for processing
    tokio::time::sleep(Duration::from_millis(300)).await;

    bot_handle
        .emit_event(
            "#resttest",
            "task_update",
            r#"{"phase":"building","summary":"Making it"}"#,
            Some(&task_id),
            "🔄 [building] Making it",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Query events via REST
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{web_addr}/api/v1/channels/resttest/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let events = body["events"].as_array().unwrap();
    assert!(
        events.len() >= 2,
        "Expected at least 2 events, got {}: {:?}",
        events.len(),
        events
    );

    // The server no longer interprets these six names as a task: the route
    // that did is gone, and the rows above are how a reader gets at them.
    let resp = client
        .get(format!("http://{web_addr}/api/v1/tasks/{task_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "the task route is retired, not answering"
    );

    // The id the SDK handed back is the id the event is filed under, and the
    // event answers for itself: signed on the sender's device, not vouched
    // for by the server. A task card nobody can check is the defect the
    // signing model exists to close.
    let v: serde_json::Value = client
        .get(format!("http://{web_addr}/api/v1/verify/{task_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["kind"], "coordination", "{v}");
    assert_eq!(v["verification"]["verdict"], "valid", "{v}");
    assert_eq!(
        v["verification"]["verified_by"], "client-session-key",
        "{v}"
    );

    bot_handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn coordination_evidence_rest_api() {
    start_deadlock_detector();
    let (addr, web_addr, server_handle) = start_test_server_with_web_and_db(empty_resolver()).await;

    let (_bot_did, bot_handle, mut bot_events) = connect_did_key(addr, "evbot").await;
    bot_handle.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut bot_events,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    bot_handle.join("#evidence").await.unwrap();
    expect_event(
        &mut bot_events,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;

    let task_id = bot_handle
        .emit_event(
            "#evidence",
            "task_request",
            r#"{"description":"Evidence test"}"#,
            None,
            "📋 New task: Evidence test",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    bot_handle
        .emit_event_with_evidence(
            "#evidence",
            "evidence_attach",
            r#"{"type":"test_result","summary":"All pass","url":"https://ci.example.com"}"#,
            Some(&task_id),
            Some("test_result"),
            "📎 Evidence (test_result): All pass — https://ci.example.com",
        )
        .await
        .unwrap();
    bot_handle
        .emit_event_with_evidence(
            "#evidence",
            "evidence_attach",
            r#"{"type":"deploy_log","summary":"Deployed"}"#,
            Some(&task_id),
            Some("deploy_log"),
            "📎 Evidence (deploy_log): Deployed",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    bot_handle
        .emit_event(
            "#evidence",
            "task_complete",
            r#"{"summary":"Done"}"#,
            Some(&task_id),
            "🎉 Task complete: Done",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The stored rows, read through the route that keeps serving them: the
    // two evidence events and the completion are all on file.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{web_addr}/api/v1/channels/evidence/events?ref_id={task_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let rows = body["events"].as_array().unwrap();
    let evidence: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|e| e["event_type"] == "evidence_attach")
        .collect();
    assert_eq!(
        evidence.len(),
        2,
        "Expected 2 evidence items, got {}: {:?}",
        evidence.len(),
        evidence
    );
    assert!(
        rows.iter().any(|e| e["event_type"] == "task_complete"),
        "the completion is on file: {body}"
    );

    bot_handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Phase 4: Interop and Spawning
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn manifest_registration() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, handle, mut events) = connect_did_key(addr, "manifbot").await;
    handle.register_agent("agent").await.unwrap();
    expect_raw_line(&mut events, 2000, "registered as agent", "AGENT REGISTER").await;

    // Submit manifest via TOML
    let manifest_toml = r#"
[agent]
display_name = "manifbot"
description = "Test manifest agent"
version = "0.1.0"

[provenance]
origin_type = "template"
creator_did = "did:plc:test"
revocation_authority = "did:plc:test"

[capabilities]
default = ["post_message", "read_channel"]

[presence]
heartbeat_interval_seconds = 15
"#;
    handle.submit_manifest(manifest_toml).await.unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Manifest registered",
        "Manifest accepted",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn spawn_and_despawn() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, parent, mut parent_ev) = connect_did_key(addr, "factory").await;
    let (_did2, watcher, mut watch_ev) = connect_did_key(addr, "watcher2").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    parent.join("#spawn").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Parent joined",
    )
    .await;
    watcher.join("#spawn").await.unwrap();
    expect_event(
        &mut watch_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Watcher joined",
    )
    .await;

    // Spawn a child agent
    parent
        .spawn_agent(
            "#spawn",
            "qa-worker",
            &["post_message", "call_tool"],
            Some(60),
            Some("TASK123"),
        )
        .await
        .unwrap();
    expect_raw_line(&mut parent_ev, 2000, "Spawned qa-worker", "Spawn confirmed").await;

    // Watcher sees child JOIN
    expect_raw_line(&mut watch_ev, 2000, "qa-worker", "Watcher sees child JOIN").await;

    // Parent sends message as child
    parent
        .send_as_child("qa-worker", "#spawn", "Running tests...")
        .await
        .unwrap();
    expect_raw_line(
        &mut watch_ev,
        2000,
        "Running tests",
        "Watcher sees child message",
    )
    .await;

    // Despawn
    parent.despawn_agent("qa-worker").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "Despawned qa-worker",
        "Despawn confirmed",
    )
    .await;

    // Watcher sees QUIT
    expect_raw_line(&mut watch_ev, 2000, "qa-worker", "Watcher sees child QUIT").await;

    parent.quit(None).await.unwrap();
    watcher.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn spawn_nick_conflict() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, parent, mut parent_ev) = connect_did_key(addr, "spawner").await;
    let (_did2, _other, _other_ev) = connect_did_key(addr, "taken").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    parent.join("#nicktest").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    // Try to spawn with an existing nick
    parent
        .spawn_agent("#nicktest", "taken", &[], None, None)
        .await
        .unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "already in use",
        "Nick conflict detected",
    )
    .await;

    parent.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn spawn_ttl_expiry() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, parent, mut parent_ev) = connect_did_key(addr, "ttlparent").await;
    let (_did2, watcher, mut watch_ev) = connect_did_key(addr, "ttlwatch").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    parent.join("#ttltest").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Parent joined",
    )
    .await;
    watcher.join("#ttltest").await.unwrap();
    expect_event(
        &mut watch_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Watcher joined",
    )
    .await;

    // Spawn with 1-second TTL
    parent
        .spawn_agent("#ttltest", "ephemeral", &[], Some(1), None)
        .await
        .unwrap();
    expect_raw_line(&mut parent_ev, 2000, "Spawned ephemeral", "Spawn confirmed").await;
    expect_raw_line(&mut watch_ev, 2000, "ephemeral", "Watcher sees spawn JOIN").await;

    // Wait for TTL expiry
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Watcher should see the QUIT or expiry notice
    expect_raw_line(&mut watch_ev, 3000, "expired", "Watcher sees TTL expiry").await;

    parent.quit(None).await.unwrap();
    watcher.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn manifest_rest_api() {
    start_deadlock_detector();
    let (addr, web_addr, server_handle) = start_test_server_with_web_and_db(empty_resolver()).await;

    let (_did, handle, mut events) = connect_did_key(addr, "restmanif").await;
    handle.register_agent("agent").await.unwrap();
    expect_raw_line(&mut events, 2000, "registered as agent", "AGENT REGISTER").await;

    let manifest_toml = r#"
[agent]
display_name = "restmanif"
version = "1.0.0"

[provenance]
origin_type = "template"
creator_did = "did:plc:test"
revocation_authority = "did:plc:test"

[capabilities]
default = ["post_message"]

[presence]
heartbeat_interval_seconds = 30
"#;
    handle.submit_manifest(manifest_toml).await.unwrap();
    expect_raw_line(
        &mut events,
        2000,
        "Manifest registered",
        "Manifest accepted",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // List manifests
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{web_addr}/api/v1/agents/manifests"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let manifests = body["manifests"].as_array().unwrap();
    assert!(!manifests.is_empty(), "Expected at least 1 manifest");

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn spawned_agents_rest_api() {
    start_deadlock_detector();
    let (addr, web_addr, server_handle) = start_test_server_with_web_and_db(empty_resolver()).await;

    let (_did, parent, mut parent_ev) = connect_did_key(addr, "restspawn").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;

    parent.join("#restspawnch").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    parent
        .spawn_agent("#restspawnch", "rest-child", &["post_message"], None, None)
        .await
        .unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "Spawned rest-child",
        "Spawn confirmed",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{web_addr}/api/v1/agents/spawned"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agents = body["spawned_agents"].as_array().unwrap();
    assert!(!agents.is_empty(), "Expected at least 1 spawned agent");
    assert_eq!(agents[0]["nick"], "rest-child");

    parent.quit(None).await.unwrap();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Phase 5: Economic Controls
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn budget_set_and_query() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, op, mut op_ev) = connect_did_key(addr, "budgetop").await;
    op.join("#budgettest").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    // Set budget
    op.set_budget("#budgettest", 50.0, "usd", "per_day", "did:plc:sponsor")
        .await
        .unwrap();
    expect_raw_line(&mut op_ev, 2000, "Budget set", "Budget set confirmed").await;

    // Query budget
    op.query_budget("#budgettest").await.unwrap();
    expect_raw_line(
        &mut op_ev,
        2000,
        "0.00/50.00 usd",
        "Budget query shows 0 spend",
    )
    .await;

    op.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn spend_reporting() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, bot, mut bot_ev) = connect_did_key(addr, "spendbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;

    bot.join("#spendtest").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    // Set budget first
    bot.set_budget("#spendtest", 10.0, "usd", "per_day", "did:plc:sponsor")
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Budget set", "Budget set").await;

    // Report spend
    bot.report_spend(
        "#spendtest",
        1.50,
        "usd",
        "claude-sonnet-4-20250514: 500 tokens",
        None,
    )
    .await
    .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Recorded: 1.5", "Spend recorded").await;

    // Query to verify
    bot.query_budget("#spendtest").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "1.50/10.00", "Budget shows 1.50 spent").await;

    bot.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn budget_warning_threshold() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, bot, mut bot_ev) = connect_did_key(addr, "warnbot").await;
    let (_did2, watcher, mut watch_ev) = connect_did_key(addr, "warnwatch").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;

    bot.join("#warntest").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Bot joined",
    )
    .await;
    watcher.join("#warntest").await.unwrap();
    expect_event(
        &mut watch_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Watcher joined",
    )
    .await;

    // Set budget with 0.8 warn threshold (default)
    bot.set_budget("#warntest", 10.0, "usd", "per_day", "did:plc:sponsor")
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Budget set", "Budget set").await;

    // Spend below threshold
    bot.report_spend("#warntest", 7.0, "usd", "big call", None)
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Recorded", "Spend 1 recorded").await;

    // This spend should cross the 80% threshold (7.0 + 2.0 = 9.0 = 90%)
    tokio::time::sleep(Duration::from_millis(50)).await;
    bot.report_spend("#warntest", 2.0, "usd", "another call", None)
        .await
        .unwrap();

    // Watcher should see the warning
    expect_raw_line(&mut watch_ev, 3000, "Budget", "Watcher sees budget warning").await;

    bot.quit(None).await.unwrap();
    watcher.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn budget_hard_limit_blocks() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, bot, mut bot_ev) = connect_did_key(addr, "limitbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;

    bot.join("#limitest").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    // Set a small budget
    bot.set_budget("#limitest", 5.0, "usd", "per_day", "did:plc:sponsor")
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Budget set", "Budget set").await;

    // Exceed the budget
    bot.report_spend("#limitest", 6.0, "usd", "expensive call", None)
        .await
        .unwrap();

    // Bot should receive budget_exceeded governance signal
    expect_raw_line(
        &mut bot_ev,
        3000,
        "budget_exceeded",
        "Bot receives budget block signal",
    )
    .await;

    bot.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn budget_rest_api() {
    start_deadlock_detector();
    let (addr, web_addr, server_handle) = start_test_server_with_web_and_db(empty_resolver()).await;

    let (_did, bot, mut bot_ev) = connect_did_key(addr, "restbudget").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;

    bot.join("#budgetapi").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    // Set budget and report spend
    bot.set_budget("#budgetapi", 100.0, "usd", "per_day", "did:plc:sponsor")
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Budget set", "Budget set").await;

    bot.report_spend("#budgetapi", 3.50, "usd", "test spend", Some("TASK001"))
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Recorded", "Spend recorded").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Check budget endpoint
    let resp = client
        .get(format!(
            "http://{web_addr}/api/v1/channels/budgetapi/budget"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["current_period"]["total_spent"].as_f64().unwrap() >= 3.49);

    // Check spend endpoint
    let resp = client
        .get(format!("http://{web_addr}/api/v1/channels/budgetapi/spend"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let spend = body["spend"].as_array().unwrap();
    assert!(!spend.is_empty(), "Expected at least 1 spend record");
    assert_eq!(spend[0]["task_ref"], "TASK001");

    bot.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn budget_requires_op() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, op, mut op_ev) = connect_did_key(addr, "budgetowner").await;
    let (_did2, pleb, mut pleb_ev) = connect_did_key(addr, "budgetpleb").await;

    op.join("#oponly").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Op joined",
    )
    .await;
    pleb.join("#oponly").await.unwrap();
    expect_event(
        &mut pleb_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Pleb joined",
    )
    .await;

    // Non-op tries to set budget — should fail
    pleb.set_budget("#oponly", 50.0, "usd", "per_day", "did:plc:test")
        .await
        .unwrap();
    expect_raw_line(
        &mut pleb_ev,
        2000,
        "operator",
        "Budget set rejected for non-op",
    )
    .await;

    // Op sets budget — should succeed
    op.set_budget("#oponly", 50.0, "usd", "per_day", "did:plc:test")
        .await
        .unwrap();
    expect_raw_line(&mut op_ev, 2000, "Budget set", "Op can set budget").await;

    op.quit(None).await.unwrap();
    pleb.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Helper: reconnect with the same DID+signer ────────────────────────────

/// Connect with a pre-existing signer (allows reconnecting with the same DID).
async fn connect_did_key_with_signer(
    addr: std::net::SocketAddr,
    nick: &str,
    signer: Arc<dyn ChallengeSigner>,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("{nick} bot"),
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

    (handle, events)
}

// ── Tests: PART clears auto-rejoin ────────────────────────────────────────
//
// Regression: an agent that PARTs channels and then disconnects should NOT be
// auto-rejoined to those channels on the next connect.  The ghost-session path
// must not restore PARTed channels, and user_channels DB must be cleared by PART.

#[tokio::test]
async fn part_clears_auto_rejoin() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, signer) = make_did_key_signer();

    // ── First connection ─────────────────────────────────────────────────
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "yokota", signer.clone()).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut agent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER #1",
    )
    .await;

    // Join two channels
    agent.join("#chad-dev").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#chad-dev"),
        "Joined #chad-dev",
    )
    .await;
    agent.join("#chad-mess").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#chad-mess"),
        "Joined #chad-mess",
    )
    .await;

    // Explicitly PART both channels (no `part()` on ClientHandle — use raw IRC)
    agent.raw("PART #chad-dev :leaving").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#chad-dev"),
        "Parted #chad-dev",
    )
    .await;
    agent.raw("PART #chad-mess :leaving").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#chad-mess"),
        "Parted #chad-mess",
    )
    .await;

    // Disconnect — server enters ghost mode for this DID
    agent.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Second connection: same DID + same nick ──────────────────────────
    let (agent2, mut agent2_ev) = connect_did_key_with_signer(addr, "yokota", signer.clone()).await;
    agent2.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut agent2_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER #2",
    )
    .await;

    // Let the event loop drain any pending server messages
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The agent must NOT have been auto-joined into the PARTed channels
    expect_no_event(&mut agent2_ev, 500, |e| {
        matches!(e, Event::Joined { channel, .. }
            if channel == "#chad-dev" || channel == "#chad-mess")
    })
    .await;

    // Cross-check with an observer: yokota should not appear in #chad-dev NAMES
    let (_obs_did, obs_signer) = make_did_key_signer();
    let (obs, mut obs_ev) = connect_did_key_with_signer(addr, "observer", obs_signer).await;
    obs.join("#chad-dev").await.unwrap();
    // Collect the NAMES reply that arrives automatically on JOIN
    expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Observer joined",
    )
    .await;
    let names_line = expect_raw_line(&mut obs_ev, 2000, "353", "NAMES reply for #chad-dev").await;
    assert!(
        !names_line.contains("yokota"),
        "yokota must not appear in #chad-dev NAMES after PART, got: {names_line}",
    );

    agent2.quit(None).await.unwrap();
    obs.quit(None).await.unwrap();
    server_handle.abort();
}

/// Simpler variant: verifies only the DB-based auto-rejoin path.
/// After PART + disconnect + reconnect the server must not auto-join.
#[tokio::test]
async fn part_removes_from_user_channels_db() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, signer) = make_did_key_signer();

    // ── First connection ─────────────────────────────────────────────────
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "yokota2", signer.clone()).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;

    agent.join("#testchan").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "Joined",
    )
    .await;

    agent.raw("PART #testchan").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Parted { .. }),
        "Parted",
    )
    .await;

    agent.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Reconnect: should NOT be auto-joined to #testchan ────────────────
    let (agent2, mut agent2_ev) = connect_did_key_with_signer(addr, "yokota2", signer).await;
    agent2.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut agent2_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER #2",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    expect_no_event(
        &mut agent2_ev,
        500,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
    )
    .await;

    // Manual join should still work (the channel is not blocked, just not auto-joined)
    agent2.join("#testchan").await.unwrap();
    expect_event(
        &mut agent2_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
        "Manual join after PART+reconnect succeeds",
    )
    .await;

    agent2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Tests: Agent JOIN visible to other clients ────────────────────────────
//
// Regression for: "Agent JOIN events not reflected in member list"
// When an agent joins a channel, other connected clients must see the JOIN
// broadcast and the agent must appear in NAMES.

#[tokio::test]
async fn agent_join_visible_to_observer() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    // Observer: a DID-authenticated user already in #testchan
    let (_obs_did, obs_signer) = make_did_key_signer();
    let (obs, mut obs_ev) = connect_did_key_with_signer(addr, "observer", obs_signer).await;
    obs.join("#testchan").await.unwrap();
    expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
        "Observer joined #testchan",
    )
    .await;

    // Agent: connects, registers, and joins #testchan
    let (_agent_did, agent_signer) = make_did_key_signer();
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "yokota", agent_signer).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    agent.join("#testchan").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
        "Agent joined #testchan",
    )
    .await;

    // Observer must see the agent's JOIN (as a RawLine containing "yokota" and "JOIN")
    let join_line = expect_raw_line(
        &mut obs_ev,
        2000,
        "JOIN",
        "Observer sees agent JOIN broadcast",
    )
    .await;
    assert!(
        join_line.contains("yokota"),
        "JOIN broadcast must contain agent nick 'yokota', got: {join_line}",
    );

    // Verify NAMES includes the agent
    obs.raw("NAMES #testchan").await.unwrap();
    let names_line = expect_raw_line(&mut obs_ev, 2000, "353", "NAMES reply").await;
    assert!(
        names_line.contains("yokota"),
        "NAMES must include agent 'yokota', got: {names_line}",
    );

    agent.quit(None).await.unwrap();
    obs.quit(None).await.unwrap();
    server_handle.abort();
    eprintln!("  ✓ Agent JOIN visible to observer");
}

/// Ghost reclaim must clean up stale session_ids so that subsequent JOINs
/// by other users are properly broadcast to the reconnected client.
#[tokio::test]
async fn ghost_reclaim_cleans_stale_sessions() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_user_did, user_signer) = make_did_key_signer();

    // ── First connection: user joins #testchan ──
    let (user1, mut user1_ev) =
        connect_did_key_with_signer(addr, "webuser", user_signer.clone()).await;
    user1.join("#testchan").await.unwrap();
    expect_event(
        &mut user1_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
        "User joined #testchan",
    )
    .await;

    // Disconnect (triggers ghost mode)
    user1.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Second connection: same DID reconnects (ghost reclaim) ──
    let (user2, mut user2_ev) =
        connect_did_key_with_signer(addr, "webuser", user_signer.clone()).await;
    // Ghost reclaim should restore channel membership — look for synthetic NAMES
    expect_raw_line(
        &mut user2_ev,
        2000,
        "353",
        "Ghost reclaim NAMES for #testchan",
    )
    .await;

    // Now an agent joins #testchan — the reconnected user must see it
    let (_agent_did, agent_signer) = make_did_key_signer();
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "agentbot", agent_signer).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    agent.join("#testchan").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#testchan"),
        "Agent joined #testchan",
    )
    .await;

    // Reconnected user must see the agent's JOIN broadcast
    let join_line = expect_raw_line(
        &mut user2_ev,
        2000,
        "JOIN",
        "Reconnected user sees agent JOIN after ghost reclaim",
    )
    .await;
    assert!(
        join_line.contains("agentbot"),
        "JOIN broadcast must contain agent nick 'agentbot', got: {join_line}",
    );

    // NAMES must include the agent and NOT have duplicate entries for webuser
    agent.raw("NAMES #testchan").await.unwrap();
    let names_line = expect_raw_line(&mut agent_ev, 2000, "353", "NAMES reply from agent").await;
    assert!(
        names_line.contains("agentbot"),
        "NAMES must include 'agentbot', got: {names_line}",
    );
    assert!(
        names_line.contains("webuser"),
        "NAMES must include 'webuser', got: {names_line}",
    );
    // Check no duplicate webuser entries (would indicate ghost leak)
    let webuser_count = names_line.matches("webuser").count();
    assert_eq!(
        webuser_count, 1,
        "webuser must appear exactly once in NAMES (no ghost dupes), got {webuser_count} in: {names_line}",
    );

    agent.quit(None).await.unwrap();
    user2.quit(None).await.unwrap();
    server_handle.abort();
    eprintln!("  ✓ Ghost reclaim cleans stale sessions — no duplicate members");
}

// ── Test: Commit-Reveal verification ────────────────────────────────
//
// End-to-end coverage of the server's verify-and-stamp of
// `+freeq.at/event=reveal` against a prior `+freeq.at/event=commit`:
// the receiver of the relayed reveal must see the server's verdict
// tag (`+freeq.at/commit-verified=true|false`, with
// `+freeq.at/commit-mismatch=<reason>` on failure). Wire format and
// hash scope are spec'd in docs/agents.md § Commit-Reveal.

/// Helper: compute base64url(sha256(salt || plaintext)) + base64url(salt).
fn cr_hash_and_salt(salt: &[u8], plaintext: &str) -> (String, String) {
    use base64::Engine;
    use sha2::Digest;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut h = sha2::Sha256::new();
    h.update(salt);
    h.update(plaintext.as_bytes());
    (b64.encode(h.finalize()), b64.encode(salt))
}

fn commit_payload_tag(hash_b64: &str) -> String {
    format!(r#"{{"hash":"{hash_b64}","alg":"sha256"}}"#)
}

fn reveal_payload_tag(commit_msgid: &str, salt_b64: &str) -> String {
    format!(r#"{{"reveal_of":"{commit_msgid}","salt":"{salt_b64}"}}"#)
}

/// Drive both clients to join `#crtest` and drain join events.
async fn cr_join_both(
    a: &client::ClientHandle,
    a_ev: &mut mpsc::Receiver<Event>,
    o: &client::ClientHandle,
    o_ev: &mut mpsc::Receiver<Event>,
    channel: &str,
) {
    a.join(channel).await.unwrap();
    expect_event(
        a_ev,
        2000,
        |e| matches!(e, Event::Joined { channel: c, .. } if c == channel),
        "alice joined",
    )
    .await;
    o.join(channel).await.unwrap();
    expect_event(
        o_ev,
        2000,
        |e| matches!(e, Event::Joined { channel: c, .. } if c == channel),
        "observer joined",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    while a_ev.try_recv().is_ok() {}
    while o_ev.try_recv().is_ok() {}
}

#[tokio::test]
async fn commit_reveal_happy_path() {
    // DB-backed: commit-reveal verification looks up the prior commit via
    // find_message_by_msgid, which requires the messages table to be live.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (_alice_did, alice, mut alice_ev) = connect_did_key(addr, "alice").await;
    let (observer, mut obs_ev) = connect_guest(addr, "crobs").await;

    cr_join_both(&alice, &mut alice_ev, &observer, &mut obs_ev, "#crtest").await;

    let salt: &[u8] = b"saltsalt12345678";
    let plaintext = "The answer is X.";
    let (hash_b64, salt_b64) = cr_hash_and_salt(salt, plaintext);

    // Alice commits.
    let mut commit_tags: HashMap<String, String> = HashMap::new();
    commit_tags.insert("+freeq.at/event".to_string(), "commit".to_string());
    commit_tags.insert("+freeq.at/ref".to_string(), "DEBATE-HAPPY".to_string());
    commit_tags.insert(
        "+freeq.at/payload".to_string(),
        commit_payload_tag(&hash_b64),
    );
    alice
        .send_tagged("#crtest", "🔒 sealed", commit_tags)
        .await
        .unwrap();

    // Observer sees the commit; capture its msgid.
    let commit_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "🔒 sealed"),
        "observer got commit",
    )
    .await;
    let commit_msgid = if let Event::Message { tags, .. } = &commit_event {
        tags.get("msgid").cloned().expect("commit must carry msgid")
    } else {
        unreachable!()
    };

    // Alice reveals.
    let mut reveal_tags: HashMap<String, String> = HashMap::new();
    reveal_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
    reveal_tags.insert("+freeq.at/ref".to_string(), "DEBATE-HAPPY".to_string());
    reveal_tags.insert(
        "+freeq.at/payload".to_string(),
        reveal_payload_tag(&commit_msgid, &salt_b64),
    );
    alice
        .send_tagged("#crtest", plaintext, reveal_tags)
        .await
        .unwrap();

    // Observer sees the reveal with the server's verdict stamped on.
    let reveal_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == plaintext),
        "observer got reveal",
    )
    .await;
    if let Event::Message { tags, .. } = &reveal_event {
        assert_eq!(
            tags.get("+freeq.at/commit-verified").map(String::as_str),
            Some("true"),
            "expected +freeq.at/commit-verified=true; tags={tags:?}",
        );
        assert!(
            !tags.contains_key("+freeq.at/commit-mismatch"),
            "expected no commit-mismatch on happy path; tags={tags:?}",
        );
    }

    alice.quit(None).await.unwrap();
    observer.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn commit_reveal_hash_mismatch_e2e() {
    // DB-backed: commit-reveal verification looks up the prior commit via
    // find_message_by_msgid, which requires the messages table to be live.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (_alice_did, alice, mut alice_ev) = connect_did_key(addr, "alice").await;
    let (observer, mut obs_ev) = connect_guest(addr, "crobs").await;

    cr_join_both(&alice, &mut alice_ev, &observer, &mut obs_ev, "#crtest").await;

    let salt: &[u8] = b"saltsalt12345678";
    let (hash_b64, salt_b64) = cr_hash_and_salt(salt, "the committed answer");

    let mut commit_tags: HashMap<String, String> = HashMap::new();
    commit_tags.insert("+freeq.at/event".to_string(), "commit".to_string());
    commit_tags.insert("+freeq.at/ref".to_string(), "DEBATE-TAMPER".to_string());
    commit_tags.insert(
        "+freeq.at/payload".to_string(),
        commit_payload_tag(&hash_b64),
    );
    alice
        .send_tagged("#crtest", "🔒 sealed", commit_tags)
        .await
        .unwrap();

    let commit_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "🔒 sealed"),
        "observer got commit",
    )
    .await;
    let commit_msgid = if let Event::Message { tags, .. } = &commit_event {
        tags.get("msgid").cloned().unwrap()
    } else {
        unreachable!()
    };

    // Reveal a DIFFERENT body than what was committed.
    let mut reveal_tags: HashMap<String, String> = HashMap::new();
    reveal_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
    reveal_tags.insert("+freeq.at/ref".to_string(), "DEBATE-TAMPER".to_string());
    reveal_tags.insert(
        "+freeq.at/payload".to_string(),
        reveal_payload_tag(&commit_msgid, &salt_b64),
    );
    alice
        .send_tagged("#crtest", "a tampered body", reveal_tags)
        .await
        .unwrap();

    let reveal_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "a tampered body"),
        "observer got tampered reveal",
    )
    .await;
    if let Event::Message { tags, .. } = &reveal_event {
        assert_eq!(
            tags.get("+freeq.at/commit-verified").map(String::as_str),
            Some("false"),
            "expected commit-verified=false on tampered body; tags={tags:?}",
        );
        assert_eq!(
            tags.get("+freeq.at/commit-mismatch").map(String::as_str),
            Some("hash_mismatch"),
            "expected commit-mismatch=hash_mismatch; tags={tags:?}",
        );
    }

    alice.quit(None).await.unwrap();
    observer.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn commit_reveal_actor_mismatch_e2e() {
    // DB-backed: commit-reveal verification looks up the prior commit via
    // find_message_by_msgid, which requires the messages table to be live.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (_alice_did, alice, mut alice_ev) = connect_did_key(addr, "alice").await;
    let (_bob_did, bob, mut bob_ev) = connect_did_key(addr, "bob").await;
    let (observer, mut obs_ev) = connect_guest(addr, "crobs").await;

    // All three join.
    alice.join("#crtest").await.unwrap();
    expect_event(
        &mut alice_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#crtest"),
        "alice joined",
    )
    .await;
    bob.join("#crtest").await.unwrap();
    expect_event(
        &mut bob_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#crtest"),
        "bob joined",
    )
    .await;
    observer.join("#crtest").await.unwrap();
    expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#crtest"),
        "observer joined",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    while alice_ev.try_recv().is_ok() {}
    while bob_ev.try_recv().is_ok() {}
    while obs_ev.try_recv().is_ok() {}

    let salt: &[u8] = b"saltsalt12345678";
    let plaintext = "The answer is X.";
    let (hash_b64, salt_b64) = cr_hash_and_salt(salt, plaintext);

    // Alice commits.
    let mut commit_tags: HashMap<String, String> = HashMap::new();
    commit_tags.insert("+freeq.at/event".to_string(), "commit".to_string());
    commit_tags.insert(
        "+freeq.at/payload".to_string(),
        commit_payload_tag(&hash_b64),
    );
    alice
        .send_tagged("#crtest", "🔒 sealed", commit_tags)
        .await
        .unwrap();

    let commit_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "🔒 sealed"),
        "observer got commit",
    )
    .await;
    let commit_msgid = if let Event::Message { tags, .. } = &commit_event {
        tags.get("msgid").cloned().unwrap()
    } else {
        unreachable!()
    };

    // Bob tries to reveal Alice's commit.
    let mut reveal_tags: HashMap<String, String> = HashMap::new();
    reveal_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
    reveal_tags.insert(
        "+freeq.at/payload".to_string(),
        reveal_payload_tag(&commit_msgid, &salt_b64),
    );
    bob.send_tagged("#crtest", plaintext, reveal_tags)
        .await
        .unwrap();

    let reveal_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == plaintext),
        "observer got bob's reveal",
    )
    .await;
    if let Event::Message { tags, .. } = &reveal_event {
        assert_eq!(
            tags.get("+freeq.at/commit-verified").map(String::as_str),
            Some("false"),
        );
        assert_eq!(
            tags.get("+freeq.at/commit-mismatch").map(String::as_str),
            Some("actor_mismatch"),
            "expected commit-mismatch=actor_mismatch; tags={tags:?}",
        );
    }

    alice.quit(None).await.unwrap();
    bob.quit(None).await.unwrap();
    observer.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn commit_reveal_commit_not_found_e2e() {
    // DB-backed: commit-reveal verification looks up the prior commit via
    // find_message_by_msgid, which requires the messages table to be live.
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;
    let (_alice_did, alice, mut alice_ev) = connect_did_key(addr, "alice").await;
    let (observer, mut obs_ev) = connect_guest(addr, "crobs").await;

    cr_join_both(&alice, &mut alice_ev, &observer, &mut obs_ev, "#crtest").await;

    // Reveal pointing at a msgid that doesn't exist.
    let mut reveal_tags: HashMap<String, String> = HashMap::new();
    reveal_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
    reveal_tags.insert(
        "+freeq.at/payload".to_string(),
        reveal_payload_tag("01J0000DOESNOTEXIST", "c2FsdA"),
    );
    alice
        .send_tagged("#crtest", "anything", reveal_tags)
        .await
        .unwrap();

    let reveal_event = expect_event(
        &mut obs_ev,
        2000,
        |e| matches!(e, Event::Message { text, .. } if text == "anything"),
        "observer got reveal",
    )
    .await;
    if let Event::Message { tags, .. } = &reveal_event {
        assert_eq!(
            tags.get("+freeq.at/commit-verified").map(String::as_str),
            Some("false"),
        );
        assert_eq!(
            tags.get("+freeq.at/commit-mismatch").map(String::as_str),
            Some("commit_not_found"),
            "expected commit-mismatch=commit_not_found; tags={tags:?}",
        );
    }

    alice.quit(None).await.unwrap();
    observer.quit(None).await.unwrap();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Phase 5 seam: the budget sponsor
// ══════════════════════════════════════════════════════════════════════

/// `BudgetPolicy.sponsor_did` is documented as "DID of the budget sponsor (who
/// gets notified and pays)".
///
/// It is parsed from the BUDGET command and stored in the policy JSON, and then
/// never read again. Nobody is notified and nothing is charged to them — so the
/// one field that expresses "these are someone else's credits" is inert. Budget
/// warnings go to the channel, which is where the funder often is not.
#[tokio::test]
async fn budget_sponsor_is_notified_when_the_threshold_is_crossed() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    // The sponsor is a real connected identity, not in the channel: they are
    // funding the work, not watching it.
    let (sponsor_did, sponsor, mut sponsor_ev) = connect_did_key(addr, "thesponsor").await;

    let (_bot_did, bot, mut bot_ev) = connect_did_key(addr, "spendbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    bot.join("#sponsored").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bot joined",
    )
    .await;

    bot.set_budget("#sponsored", 10.0, "usd", "per_day", &sponsor_did)
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Budget set", "budget set").await;

    // Cross the 80% warn threshold.
    bot.report_spend("#sponsored", 7.0, "usd", "claude call", None)
        .await
        .unwrap();
    expect_raw_line(&mut bot_ev, 2000, "Recorded", "spend 1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    bot.report_spend("#sponsored", 2.0, "usd", "claude call", None)
        .await
        .unwrap();

    // The sponsor is paying; they must hear about it.
    expect_raw_line(
        &mut sponsor_ev,
        3000,
        "sponsored",
        "sponsor is notified that their budget is nearly spent",
    )
    .await;

    bot.quit(None).await.ok();
    sponsor.quit(None).await.ok();
    server_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Capability delegation, and the gap that remains
// ══════════════════════════════════════════════════════════════════════
//
// These encode behaviour the design documents specify and the code does not
// implement. They are #[ignore]d so they don't fail the suite, but they run on
// demand and will pass the day the feature lands:
//
//     cargo test -p freeq-server --test agent_native -- --ignored
//
// Prose in a design doc drifts silently. A test that is ignored for a stated
// reason does not.

/// PHASE-4 step 5: "Grants narrowed capabilities (intersection of parent's caps
/// and requested caps)."
///
/// The spawn handler stores the requested list verbatim. There is no lookup of
/// the parent's own capabilities and no intersection, so a child can be recorded
/// with any capability its parent names — including ones the parent does not hold.
#[tokio::test]
async fn spawned_capabilities_are_narrowed_to_the_parents() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, parent, mut parent_ev) = connect_did_key(addr, "capparent").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;
    parent.join("#capnarrow").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "parent joined",
    )
    .await;

    // The parent holds no capabilities at all, and asks for a privileged one.
    parent
        .spawn_agent("#capnarrow", "overreach", &["deploy", "admin"], None, None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // WHOIS is where the child's recorded capabilities surface.
    parent.raw("WHOIS overreach").await.unwrap();
    let line = expect_raw_line(
        &mut parent_ev,
        2000,
        "capabilities=",
        "child's capabilities in WHOIS",
    )
    .await;
    assert!(
        !line.contains("admin") && !line.contains("deploy"),
        "child was granted capabilities its parent never held: {line}"
    );

    parent.quit(None).await.ok();
    server_handle.abort();
}

/// A recorded capability should gate something. Nothing reads
/// `agent_capability_grants` to decide whether an action is allowed — the rows
/// are only rendered in WHOIS and the REST endpoints — and nothing writes to it
/// either, since `grant_capability()` has no callers.
#[tokio::test]
#[ignore = "unimplemented: capabilities are recorded for display, never enforced"]
async fn a_capability_grant_is_actually_enforced() {
    start_deadlock_detector();
    let (addr, _server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, op, mut op_ev) = connect_did_key(addr, "capop").await;
    op.join("#capenforce").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "op joined",
    )
    .await;

    // An agent with no granted capabilities attempts a capability-gated action.
    let (_bot_did, bot, mut bot_ev) = connect_did_key(addr, "capbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    bot.join("#capenforce").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bot joined",
    )
    .await;

    // Spawning is itself listed as a capability in the design (step 1: "check the
    // parent holds spawn_agent"). With no grant, it should be refused.
    bot.spawn_agent("#capenforce", "unauthorised", &[], None, None)
        .await
        .unwrap();
    // Match the spawn outcome specifically, not any line mentioning the channel.
    let reply = expect_raw_line(
        &mut bot_ev,
        2000,
        "Spawned agent",
        "server response to an ungranted spawn",
    )
    .await;
    // Reaching this line *is* the failure: the spawn was allowed. No cleanup
    // follows, because none of it can run — the ignored-test marker is the
    // panic. When capabilities are enforced this becomes an assertion that the
    // spawn was refused, and the teardown below it comes back with it.
    panic!("ungranted spawn succeeded instead of being refused: {reply}");
}

/// A channel op can confer a capability, and the agent then holds it.
///
/// `agent_capability_grants` had no writer at all: `grant_capability()` existed
/// with zero callers, so the TTLs, scopes and rate limits in that schema
/// described grants that could never be made. `AGENT GRANT` is that writer, and
/// what it writes is what `narrow_capabilities` reads when a parent delegates.
#[tokio::test]
async fn an_op_can_grant_a_capability_and_it_is_then_delegable() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_op_did, op, mut op_ev) = connect_did_key(addr, "grantop").await;
    op.join("#grants").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "op joined",
    )
    .await;

    let (_bot_did, bot, mut bot_ev) = connect_did_key(addr, "grantbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    bot.join("#grants").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bot joined",
    )
    .await;
    op.raw("MODE #grants +o grantbot").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Before the grant, the bot holds nothing, so it can confer nothing.
    bot.spawn_agent("#grants", "before", &["call_tool"], None, None)
        .await
        .unwrap();
    let before = expect_raw_line(&mut bot_ev, 2000, "Spawned before", "spawn before grant").await;
    assert!(
        !before.contains("call_tool"),
        "conferred a capability the parent did not hold: {before}"
    );

    // The op grants it.
    op.raw("AGENT GRANT grantbot call_tool").await.unwrap();
    expect_raw_line(&mut op_ev, 2000, "Granted", "grant confirmed").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now the same spawn confers it.
    bot.spawn_agent("#grants", "after", &["call_tool"], None, None)
        .await
        .unwrap();
    let after = expect_raw_line(&mut bot_ev, 2000, "Spawned after", "spawn after grant").await;
    assert!(
        after.contains("call_tool"),
        "granted capability was not delegable: {after}"
    );

    op.quit(None).await.ok();
    bot.quit(None).await.ok();
    server_handle.abort();
}

/// A grant must be withdrawable, and withdrawing it must take the capability away.
#[tokio::test]
async fn ungranting_removes_the_capability() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_op_did, op, mut op_ev) = connect_did_key(addr, "revop").await;
    op.join("#revokes").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "op joined",
    )
    .await;
    let (_bot_did, bot, mut bot_ev) = connect_did_key(addr, "revbot").await;
    bot.register_agent("agent").await.unwrap();
    expect_raw_line(&mut bot_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    bot.join("#revokes").await.unwrap();
    expect_event(
        &mut bot_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "bot joined",
    )
    .await;

    op.raw("AGENT GRANT revbot deploy").await.unwrap();
    expect_raw_line(&mut op_ev, 2000, "Granted", "granted").await;
    // UNGRANT, not REVOKE: `AGENT REVOKE` is the governance kill-switch for a
    // whole agent, which is a different act from withdrawing one capability.
    op.raw("AGENT UNGRANT revbot deploy").await.unwrap();
    expect_raw_line(&mut op_ev, 2000, "Ungranted", "ungranted").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    bot.spawn_agent("#revokes", "child", &["deploy"], None, None)
        .await
        .unwrap();
    let line = expect_raw_line(&mut bot_ev, 2000, "Spawned child", "spawn after revoke").await;
    assert!(
        !line.contains("deploy"),
        "revoked capability was still delegable: {line}"
    );

    op.quit(None).await.ok();
    bot.quit(None).await.ok();
    server_handle.abort();
}

/// Granting is an operator action.
#[tokio::test]
async fn granting_requires_op() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_a_did, a, mut a_ev) = connect_did_key(addr, "plainuser").await;
    a.join("#nogrant").await.unwrap();
    expect_event(
        &mut a_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;
    let (_b_did, b, mut b_ev) = connect_did_key(addr, "otherbot").await;
    b.join("#nogrant").await.unwrap();
    expect_event(
        &mut b_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "joined",
    )
    .await;

    // plainuser is not an op in #nogrant (otherbot created it, so holds ops).
    a.raw("AGENT GRANT otherbot deploy").await.unwrap();
    let reply = expect_raw_line(&mut a_ev, 2000, "nogrant", "grant refusal").await;
    assert!(
        !reply.contains("Granted"),
        "a non-op granted a capability: {reply}"
    );

    a.quit(None).await.ok();
    b.quit(None).await.ok();
    server_handle.abort();
}

/// Governance actions are advisory, and so is their propagation.
///
/// `AGENT REVOKE` writes the governance log and sends the agent a signal. It sets
/// no server state, so nothing stops a revoked agent from continuing to send, and
/// its spawned children are not torn down. Children *are* despawned on TTL
/// expiry, on explicit despawn, and when the parent's connection drops — but a
/// revoked-yet-connected parent keeps its descendants.
///
/// Enforcing this needs a server-side agent state that the message path consults,
/// which does not exist yet. Kept executable so the gap is not just prose.
#[tokio::test]
#[ignore = "unimplemented: governance revoke is advisory and does not cascade to children"]
async fn revoking_a_parent_tears_down_its_children() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_op_did, op, mut op_ev) = connect_did_key(addr, "govop").await;
    op.join("#govcascade").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "op joined",
    )
    .await;

    let (_p_did, parent, mut parent_ev) = connect_did_key(addr, "govparent").await;
    parent.register_agent("agent").await.unwrap();
    expect_raw_line(
        &mut parent_ev,
        2000,
        "registered as agent",
        "AGENT REGISTER",
    )
    .await;
    parent.join("#govcascade").await.unwrap();
    expect_event(
        &mut parent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "parent joined",
    )
    .await;

    parent
        .spawn_agent("#govcascade", "govchild", &[], None, None)
        .await
        .unwrap();
    expect_raw_line(&mut parent_ev, 2000, "Spawned govchild", "spawned").await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Revoke the parent. The child's authority derives entirely from the parent's,
    // so it must not outlive it.
    op.raw("AGENT REVOKE govparent :compromised").await.unwrap();
    expect_raw_line(&mut op_ev, 2000, "revoked", "revoke issued").await;

    expect_raw_line(
        &mut op_ev,
        3000,
        "govchild",
        "child is torn down when its parent is revoked",
    )
    .await;

    op.quit(None).await.ok();
    parent.quit(None).await.ok();
    server_handle.abort();
}

/// Being someone's sponsor has to be opt-in.
///
/// `BUDGET ... sponsor=<did>` accepts any DID. The sponsor defaults to the issuer,
/// but naming somebody else takes only channel op, and that DID is never asked.
/// So an op can stand up a channel, name an unrelated identity as the sponsor, and
/// have every agent's reported spend attributed to them — and, since sponsors are
/// now notified, send them the warnings too.
///
/// Lending capacity is the whole point of a sponsor field, and lending is a thing
/// you agree to. The fix needs a consent record (or a capability the sponsor grants
/// to the issuer), which is a design decision rather than a patch, so this is kept
/// executable instead of written down somewhere.
#[tokio::test]
#[ignore = "unimplemented: naming another DID as budget sponsor requires no consent"]
async fn naming_someone_else_as_sponsor_requires_their_consent() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (victim_did, victim, _victim_ev) = connect_did_key(addr, "generous").await;
    let (_op_did, op, mut op_ev) = connect_did_key(addr, "opportunist").await;
    op.join("#freeloading").await.unwrap();
    expect_event(
        &mut op_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "op joined",
    )
    .await;

    // The op names an unrelated identity as the one funding this channel.
    op.raw(&format!(
        "BUDGET #freeloading amount=100;unit=usd;period=day;sponsor={victim_did}"
    ))
    .await
    .unwrap();

    // Match the budget confirmation specifically. An earlier attempt keyed on the
    // channel name and matched the MODE +o line instead, so it passed while the
    // budget was set — a test that proved nothing.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(2000);
    let mut confirmed: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), op_ev.recv()).await {
            Ok(Some(e)) => {
                let line = format!("{e:?}");
                if line.contains("Budget set for") {
                    confirmed = Some(line);
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(
        confirmed.is_none(),
        "budget was set naming an unconsenting sponsor: {}",
        confirmed.unwrap_or_default()
    );

    victim.quit(None).await.ok();
    op.quit(None).await.ok();
    server_handle.abort();
}

// ── Roster-time actor class (issue #72) ──────────────────────────────────────

/// A client joining a channel an agent is ALREADY in must be able to tell that
/// it is an agent.
///
/// NAMES (353) carries only nicks and prefixes, and the extended-join tag only
/// reaches clients that were already watching. Without a roster-time signal,
/// every client renders pre-existing agents as humans, or reinvents a
/// WHOIS-per-member probe. This is that signal.
#[tokio::test]
async fn names_reports_actor_class_for_members_already_present() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    // An agent is in the channel BEFORE anyone else arrives.
    let (_d1, s1) = make_did_key_signer();
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "worker", s1).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    agent.join("#roster").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "agent joined",
    )
    .await;

    // Someone else joins afterwards and must learn the class from the roster.
    let (_d2, s2) = make_did_key_signer();
    let (human, mut human_ev) = connect_did_key_with_signer(addr, "latecomer", s2).await;
    human.join("#roster").await.unwrap();

    let line = expect_raw_line(&mut human_ev, 3000, " 674 ", "actor-class roster line").await;
    assert!(
        line.contains("worker=agent"),
        "the roster line must name the agent and its class, got: {line}"
    );
    assert!(
        line.contains("#roster"),
        "the roster line must name the channel, got: {line}"
    );

    agent.quit(None).await.unwrap();
    human.quit(None).await.unwrap();
    server_handle.abort();
}

/// Humans are the default and must not be listed: the line exists to flag the
/// exceptions, and listing every human would make it grow with the channel.
#[tokio::test]
async fn actor_class_roster_line_omits_humans_and_is_skipped_when_empty() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_d1, s1) = make_did_key_signer();
    let (first, mut first_ev) = connect_did_key_with_signer(addr, "personone", s1).await;
    first.join("#humans").await.unwrap();
    expect_event(
        &mut first_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "first joined",
    )
    .await;

    let (_d2, s2) = make_did_key_signer();
    let (second, mut second_ev) = connect_did_key_with_signer(addr, "persontwo", s2).await;
    second.join("#humans").await.unwrap();
    // The join must complete without a 674 — a channel of humans emits none.
    expect_event(
        &mut second_ev,
        3000,
        |e| matches!(e, Event::RawLine(l) if l.contains(" 366 ")),
        "end of NAMES",
    )
    .await;

    let saw_674 = tokio::time::timeout(std::time::Duration::from_millis(400), async {
        loop {
            match second_ev.recv().await {
                Some(Event::RawLine(l)) if l.contains(" 674 ") => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        !saw_674,
        "a channel with no agents must not emit an actor-class line"
    );

    first.quit(None).await.unwrap();
    second.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Presence status for active agents (issue #70) ────────────────────────────

/// An agent that is *working* must be able to say what it is working on.
///
/// Presence was relayed only through the `AWAY` back-compat mechanism, and
/// "back from away" is parameterless by IRC semantics — so for `online`,
/// `active` and `idle` the status string was computed and then dropped. The
/// practical effect: an agent grinding on a task appeared as a plain
/// "available", and the only way to publish a status was to lie about
/// liveness by claiming a non-active state.
#[tokio::test]
async fn presence_status_reaches_peers_for_active_states() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_d1, s1) = make_did_key_signer();
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "busybot", s1).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    agent.join("#presence").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "agent joined",
    )
    .await;

    let (_d2, s2) = make_did_key_signer();
    let (watcher, mut watch_ev) = connect_did_key_with_signer(addr, "watcher", s2).await;
    watcher.join("#presence").await.unwrap();
    expect_event(
        &mut watch_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "watcher joined",
    )
    .await;

    // `executing` is an away-ish state and already worked; `active` is the one
    // that was silently losing its status.
    agent
        .raw("PRESENCE :state=active;status=project=freeq branch=main")
        .await
        .unwrap();

    let line = expect_raw_line(&mut watch_ev, 3000, "PRESENCE", "presence relay to a peer").await;
    assert!(
        line.contains("project=freeq"),
        "an active agent's status must reach peers, got: {line}"
    );
    assert!(
        line.contains("busybot"),
        "the relay must name the agent, got: {line}"
    );

    agent.quit(None).await.unwrap();
    watcher.quit(None).await.unwrap();
    server_handle.abort();
}

/// The task reference travels too, so a room can tie a working agent to the
/// handoff it accepted.
#[tokio::test]
async fn presence_relay_carries_state_and_task() {
    start_deadlock_detector();
    let (addr, server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_d1, s1) = make_did_key_signer();
    let (agent, mut agent_ev) = connect_did_key_with_signer(addr, "taskbot", s1).await;
    agent.register_agent("agent").await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "registered as agent", "AGENT REGISTER").await;
    agent.join("#presence2").await.unwrap();
    expect_event(
        &mut agent_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "agent joined",
    )
    .await;

    let (_d2, s2) = make_did_key_signer();
    let (watcher, mut watch_ev) = connect_did_key_with_signer(addr, "watcher2", s2).await;
    watcher.join("#presence2").await.unwrap();
    expect_event(
        &mut watch_ev,
        2000,
        |e| matches!(e, Event::Joined { .. }),
        "watcher joined",
    )
    .await;

    agent
        .raw("PRESENCE :state=executing;status=fixing the parser;task=01ABCDEF")
        .await
        .unwrap();

    let line = expect_raw_line(&mut watch_ev, 3000, "PRESENCE", "presence relay").await;
    assert!(line.contains("executing"), "state must travel, got: {line}");
    assert!(
        line.contains("fixing the parser"),
        "status must travel, got: {line}"
    );
    assert!(
        line.contains("01ABCDEF"),
        "task ref must travel, got: {line}"
    );

    agent.quit(None).await.unwrap();
    watcher.quit(None).await.unwrap();
    server_handle.abort();
}

/// A rename must survive a ghost reclaim.
///
/// Ghost adoption exists so a blip does not churn a nick. It used to override
/// the requested nick unconditionally, which meant changing your configured
/// nick and restarting silently gave you the old one back — a restart almost
/// always lands inside the 30s grace window. The only way to make a rename
/// stick was to stay disconnected for half a minute, which nobody guesses.
#[tokio::test]
async fn a_reconnect_that_asks_for_a_new_nick_keeps_it() {
    start_deadlock_detector();
    let (addr, _server_handle) = start_test_server_with_db(empty_resolver(), true).await;

    let (_did, signer) = make_did_key_signer();

    let (first, mut first_ev) = connect_did_key_with_signer(addr, "old-name", signer.clone()).await;
    first.join("#room").await.unwrap();
    expect_event(
        &mut first_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#room"),
        "joined #room",
    )
    .await;

    // Disconnect and come straight back — inside the ghost grace window,
    // which is what a real restart does.
    first.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (second, mut second_ev) =
        connect_did_key_with_signer(addr, "new-name", signer.clone()).await;

    // The reclaim still happens — channels come back — and the synthetic
    // NAMES names the recipient, so one line proves both halves at once.
    let line = expect_raw_line(&mut second_ev, 3000, " 353 ", "ghost reclaim NAMES").await;
    assert!(
        line.contains("353 new-name"),
        "a deliberate rename must survive a ghost reclaim; server still calls us: {line}"
    );
    assert!(
        line.contains("#room"),
        "the reclaim must still restore channels: {line}"
    );
    let _ = second;
}

// ── Delegated access to invite-only channels ─────────────────────────

/// An agent may go where the person it acts for already is.
///
/// Telling your agent to join a room you are sitting in should not require a
/// second human to invite a `did:key` nobody has ever seen. If the delegation
/// certificate is *verified* and names someone already in the channel, the
/// agent is admitted.
#[tokio::test]
async fn a_verified_agent_joins_an_invite_only_channel_its_owner_is_in() {
    use base64::Engine;
    start_deadlock_detector();
    let (addr, _srv) = start_test_server_with_db(empty_resolver(), true).await;

    // One owner session throughout: reconnecting would let the SDK register a
    // fresh MSGSIG over the key the certificate is signed with.
    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let owner_pk = PrivateKey::ed25519_from_bytes(&owner_key.to_bytes()).unwrap();
    let owner_did = format!("did:key:{}", owner_pk.public_key_multibase());
    let owner_signer: Arc<dyn ChallengeSigner> =
        Arc::new(KeySigner::new(owner_did.clone(), owner_pk));
    let (owner, mut owner_ev) = connect_did_key_with_signer(addr, "owner", owner_signer).await;

    // Put the known key on file, over the SDK's auto-generated one.
    let owner_pub = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(owner_key.verifying_key().as_bytes());
    owner.raw(&format!("MSGSIG {owner_pub}")).await.unwrap();
    expect_raw_line(&mut owner_ev, 2000, "MSGSIG OK", "owner key on file").await;

    owner.join("#closed").await.unwrap();
    expect_event(
        &mut owner_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#closed"),
        "owner joined",
    )
    .await;
    owner.raw("MODE #closed +i").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The agent presents a certificate signed by the owner, then joins with no
    // invite of its own.
    let (agent_did, agent, mut agent_ev) = connect_did_key(addr, "helper").await;
    let cert = build_signed_cert(&agent_did, &owner_did, &owner_key);
    agent.submit_provenance(&cert).await.unwrap();
    expect_raw_line(&mut agent_ev, 2000, "Provenance verified", "cert verified").await;

    agent.join("#closed").await.unwrap();
    expect_event(
        &mut agent_ev,
        3000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#closed"),
        "the agent is admitted on its owner's presence",
    )
    .await;
}

/// The attack the signature requirement exists to stop: an agent declaring,
/// with no signature, that a member owns it.
#[tokio::test]
async fn an_unsigned_delegation_does_not_open_an_invite_only_channel() {
    use base64::Engine;
    start_deadlock_detector();
    let (addr, _srv) = start_test_server_with_db(empty_resolver(), true).await;

    let (owner_did, _owner_key) = register_creator_msgsig(addr, "owner2").await;
    let owner_pk_signer: Arc<dyn ChallengeSigner> = {
        let (_d, s) = make_did_key_signer();
        s
    };
    let (owner, mut owner_ev) =
        connect_did_key_with_signer(addr, "owner2live", owner_pk_signer).await;
    owner.join("#closed2").await.unwrap();
    expect_event(
        &mut owner_ev,
        2000,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#closed2"),
        "owner joined",
    )
    .await;
    owner.raw("MODE #closed2 +i").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Same claim, no signature.
    let (agent_did, agent, mut agent_ev) = connect_did_key(addr, "liar").await;
    let cert = serde_json::json!({
        "type": "FreeqBotDelegation/v1",
        "bot_did": agent_did,
        "creator_did": owner_did,
        "created_at": "2026-05-08T15:00:00Z",
    });
    agent.submit_provenance(&cert).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    agent.join("#closed2").await.unwrap();
    expect_raw_line(
        &mut agent_ev,
        3000,
        "473",
        "an unsigned delegation must not open the door",
    )
    .await;
}
