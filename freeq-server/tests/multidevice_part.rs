//! Multi-device PART: one device leaving is not the identity leaving.
//!
//! Reported as: "when I play freeqworld something weird happens with my channel
//! memberships — I just lost #freeq and I wasn't even using it."
//!
//! Server logs showed several short-lived web sessions authenticating as the same
//! DID as the desktop app (`Attaching additional session for DID … existing=2`),
//! and `user_channels` still listed `#freeq` afterwards. So the subscription was
//! intact and the loss was in what the server *said* on the wire.
//!
//! A PART is broadcast to every member of the channel and identifies the leaver by
//! nick alone. Every session signed in as one identity shares that nick. So when one
//! device parted while another stayed, the server told the whole channel that nick
//! had left — which is false, the identity was still there via the other session —
//! and told the user's own remaining devices that *they* had left a channel they
//! were still in.
//!
//! The rule these tests pin: a PART is only news to the channel when the leaving
//! session is the identity's last one in that channel. The parting client always
//! gets its own echo, because it asked.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn start_test_server(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-multidevice".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(":memory:".to_string()),
        ..Default::default()
    };
    let (addr, handle) = freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap();
    (addr, handle)
}

fn empty_resolver() -> DidResolver {
    DidResolver::static_map(HashMap::new())
}

fn make_signer() -> (String, Arc<dyn ChallengeSigner>) {
    let private_key = PrivateKey::generate_ed25519();
    let multibase = private_key.public_key_multibase();
    let did = format!("did:key:{multibase}");
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.clone(), private_key));
    (did, signer)
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

async fn connect_with(
    addr: std::net::SocketAddr,
    nick: &str,
    signer: Arc<dyn ChallengeSigner>,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
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
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
    (handle, events)
}

/// Collect raw lines for a while and return them, so a test can assert on absence.
async fn drain(events: &mut mpsc::Receiver<Event>, ms: u64) -> Vec<String> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(150), events.recv()).await {
            Ok(Some(e)) => seen.push(format!("{e:?}")),
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    seen
}

/// An observer must not be told the user left while another of their devices is
/// still in the channel — otherwise every roster in the room is wrong.
#[tokio::test]
async fn one_device_parting_is_not_announced_while_another_remains() {
    let (addr, server) = start_test_server(empty_resolver()).await;
    let (_did, signer) = make_signer();

    // Two devices, one identity.
    let (dev_a, mut ev_a) = connect_with(addr, "multi", signer.clone()).await;
    dev_a.join("#shared").await.unwrap();
    expect_event(
        &mut ev_a,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "A joined",
    )
    .await;

    let (dev_b, mut ev_b) = connect_with(addr, "multi", signer.clone()).await;
    dev_b.join("#shared").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Somebody else in the room.
    let (_odid, osigner) = make_signer();
    let (observer, mut ev_o) = connect_with(addr, "watcher", osigner).await;
    observer.join("#shared").await.unwrap();
    expect_event(
        &mut ev_o,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "observer joined",
    )
    .await;
    let _ = drain(&mut ev_o, 300).await;
    let _ = drain(&mut ev_b, 300).await;

    // Device A leaves. The identity has not left: device B is still there.
    dev_a.raw("PART #shared").await.unwrap();

    let observed = drain(&mut ev_o, 900).await;
    let part_lines: Vec<&String> = observed
        .iter()
        .filter(|l| l.contains("PART") && l.contains("multi"))
        .collect();
    assert!(
        part_lines.is_empty(),
        "observer was told the user left while another device remained: {part_lines:?}"
    );

    // And the sibling device must not be told it left a channel it is still in.
    let sibling = drain(&mut ev_b, 400).await;
    let sibling_parts: Vec<&String> = sibling
        .iter()
        .filter(|l| l.contains("PART") && l.contains("multi"))
        .collect();
    assert!(
        sibling_parts.is_empty(),
        "sibling device was told it had left: {sibling_parts:?}"
    );

    dev_a.quit(None).await.ok();
    dev_b.quit(None).await.ok();
    observer.quit(None).await.ok();
    server.abort();
}

/// The parting client still needs its own echo, or it cannot tell whether the
/// request was honoured.
#[tokio::test]
async fn the_parting_device_still_receives_its_own_part() {
    let (addr, server) = start_test_server(empty_resolver()).await;
    let (_did, signer) = make_signer();

    let (dev_a, mut ev_a) = connect_with(addr, "echoer", signer.clone()).await;
    dev_a.join("#echo").await.unwrap();
    expect_event(
        &mut ev_a,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "A joined",
    )
    .await;

    let (dev_b, _ev_b) = connect_with(addr, "echoer", signer.clone()).await;
    dev_b.join("#echo").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = drain(&mut ev_a, 300).await;

    dev_a.raw("PART #echo").await.unwrap();

    let seen = drain(&mut ev_a, 900).await;
    assert!(
        seen.iter()
            .any(|l| l.contains("PART") && l.contains("echo")),
        "parting device never saw its own PART: {seen:?}"
    );

    dev_a.quit(None).await.ok();
    dev_b.quit(None).await.ok();
    server.abort();
}

/// The ordinary case must not change: with one device, leaving is real news.
#[tokio::test]
async fn a_last_device_parting_is_announced_normally() {
    let (addr, server) = start_test_server(empty_resolver()).await;

    let (_did, signer) = make_signer();
    let (solo, mut ev_s) = connect_with(addr, "solo", signer).await;
    solo.join("#normal").await.unwrap();
    expect_event(
        &mut ev_s,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "solo joined",
    )
    .await;

    let (_odid, osigner) = make_signer();
    let (observer, mut ev_o) = connect_with(addr, "onlooker", osigner).await;
    observer.join("#normal").await.unwrap();
    expect_event(
        &mut ev_o,
        3000,
        |e| matches!(e, Event::Joined { .. }),
        "observer joined",
    )
    .await;
    let _ = drain(&mut ev_o, 300).await;

    solo.raw("PART #normal").await.unwrap();

    let observed = drain(&mut ev_o, 1200).await;
    assert!(
        observed
            .iter()
            .any(|l| l.contains("PART") && l.contains("solo")),
        "a genuine last-device PART was not announced: {observed:?}"
    );

    solo.quit(None).await.ok();
    observer.quit(None).await.ok();
    server.abort();
}
