//! Multi-device session tests.
//!
//! Tests ghost session recovery, multi-device channel sync, and
//! the attach_same_did flow with two authenticated SDK clients.

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

const DID: &str = "did:plc:multidev";
const TIMEOUT_MS: u64 = 5000;

async fn start(
    key: &PrivateKey,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let doc = did::make_test_did_document(DID, &key.public_key_multibase());
    let mut docs = HashMap::new();
    docs.insert(DID.to_string(), doc);
    let resolver = DidResolver::static_map(docs);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-multidev".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

async fn connect_as_did(
    addr: std::net::SocketAddr,
    nick: &str,
    key: PrivateKey,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(DID.to_string(), key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "multi-device test".to_string(),
        ..Default::default()
    };
    client::connect(config, Some(signer))
}

async fn wait_event(
    rx: &mut mpsc::Receiver<Event>,
    pred: impl Fn(&Event) -> bool,
    desc: &str,
) -> Event {
    timeout(Duration::from_millis(TIMEOUT_MS), async {
        loop {
            match rx.recv().await {
                Some(e) if pred(&e) => return e,
                Some(_) => continue,
                None => panic!("Channel closed: {desc}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Timeout: {desc}"))
}

async fn wait_registered(rx: &mut mpsc::Receiver<Event>) -> String {
    match wait_event(rx, |e| matches!(e, Event::Registered { .. }), "Registered").await {
        Event::Registered { nick } => nick,
        _ => unreachable!(),
    }
}

async fn wait_auth(rx: &mut mpsc::Receiver<Event>) {
    wait_event(
        rx,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
}

// ═══════════════════════════════════════════════════════════════
// GHOST SESSION: disconnect and reconnect within grace period
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn ghost_reconnect_within_grace_period() {
    let key = PrivateKey::generate_ed25519();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _h) = start(&key).await;

    // Device 1: connect, auth, join channel
    let (h1, mut rx1) = connect_as_did(addr, "ghostuser", key).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#ghost").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#ghost"),
        "Joined",
    )
    .await;
    h1.privmsg("#ghost", "before disconnect").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Disconnect (triggers ghost mode)
    h1.quit(None).await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Device 2: reconnect with same DID within 30s grace period
    let (h2, mut rx2) = connect_as_did(addr, "ghostuser", key2).await;
    wait_auth(&mut rx2).await;
    let nick = wait_registered(&mut rx2).await;
    assert_eq!(nick.to_lowercase(), "ghostuser", "Should reclaim same nick");

    // Should be able to send to #ghost (membership restored)
    h2.privmsg("#ghost", "after reconnect").await.unwrap();
    // If we get an echo or no error, membership was restored
    tokio::time::sleep(Duration::from_millis(500)).await;

    h2.quit(None).await.ok();
}

// ═══════════════════════════════════════════════════════════════
// MULTI-DEVICE: two clients, same DID, simultaneous
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn two_devices_same_did_both_authenticated() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _h) = start(&key).await;

    // Device 1
    let (h1, mut rx1) = connect_as_did(addr, "dev1", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#multi").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#multi"),
        "D1 Joined",
    )
    .await;

    // Device 2 (same DID)
    let (h2, mut rx2) = connect_as_did(addr, "dev1", key2).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;

    // Device 2 should be auto-attached to #multi (from device 1's membership)
    // It gets synthetic JOINs during attach_same_did
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Device 1 sends message — device 2 should receive it
    h1.privmsg("#multi", "from device 1").await.unwrap();
    let msg = wait_event(
        &mut rx2,
        |e| matches!(e, Event::Message { text, .. } if text == "from device 1"),
        "D2 receives D1 msg",
    )
    .await;
    assert!(matches!(msg, Event::Message { text, .. } if text == "from device 1"));

    // Device 2 sends message — device 1 should receive it
    h2.privmsg("#multi", "from device 2").await.unwrap();
    let msg = wait_event(
        &mut rx1,
        |e| matches!(e, Event::Message { text, .. } if text == "from device 2"),
        "D1 receives D2 msg",
    )
    .await;
    assert!(matches!(msg, Event::Message { text, .. } if text == "from device 2"));

    h1.quit(None).await.ok();
    h2.quit(None).await.ok();
}

#[tokio::test]
async fn multi_device_one_disconnects_other_continues() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _h) = start(&key).await;

    let (h1, mut rx1) = connect_as_did(addr, "persist", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#persist").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#persist"),
        "Joined",
    )
    .await;

    let (h2, mut rx2) = connect_as_did(addr, "persist", key2).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Device 1 disconnects
    h1.quit(None).await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Device 2 should still work — send message
    h2.privmsg("#persist", "still here").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    h2.quit(None).await.ok();
}

// ═══════════════════════════════════════════════════════════════
// GUEST + AUTH: guest cannot claim authenticated nick
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn guest_cannot_claim_did_owned_nick() {
    let key = PrivateKey::generate_ed25519();
    let key_copy = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _h) = start(&key).await;

    // Authenticated user claims "owner" nick
    let (h1, mut rx1) = connect_as_did(addr, "owner", key_copy).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Guest tries to use same nick
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "owner".to_string(),
        user: "guest".to_string(),
        realname: "guest".to_string(),
        ..Default::default()
    };
    let (_h2, mut rx2) = client::connect(config, None);
    let nick = wait_registered(&mut rx2).await;
    // Guest should get a different nick (renamed to Guest*)
    assert_ne!(
        nick.to_lowercase(),
        "owner",
        "Guest should not get DID-owned nick, got: {nick}"
    );

    h1.quit(None).await.ok();
}

// ═══════════════════════════════════════════════════════════════════
// LEAVE-CHANNEL ADVERSARIAL: cross-device + case + persistence
// ═══════════════════════════════════════════════════════════════════
//
// Real user-reported bug: "I constantly have problems with not being
// able to leave channels. Channel list is not consistent across
// web/iOS." These tests probe the persistence layer + multi-device
// behaviour where local optimistic state and the server's auto-rejoin
// DB can diverge.

/// Start a server and return its address + the SQLite path it persists to,
/// so tests can read user_channels rows directly to verify what the next
/// reconnect would auto-rejoin.
async fn start_with_db_path(
    key: &PrivateKey,
) -> (
    std::net::SocketAddr,
    String,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let doc = did::make_test_did_document(DID, &key.public_key_multibase());
    let mut docs = HashMap::new();
    docs.insert(DID.to_string(), doc);
    let resolver = DidResolver::static_map(docs);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-leave".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.clone()),
        ..Default::default()
    };
    let (addr, handle) = freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap();
    (addr, db_path, handle)
}

/// Read the persisted auto-rejoin channels for a DID.
fn db_user_channels(db_path: &str, did: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    let mut stmt = conn
        .prepare("SELECT channel FROM user_channels WHERE did = ?1")
        .unwrap();
    let rows = stmt
        .query_map(rusqlite::params![did], |row| row.get::<_, String>(0))
        .unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #1: solo part → DB cleared, reconnect does not rejoin
// (Sanity baseline — should already pass.)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn solo_part_clears_db_and_reconnect_does_not_rejoin() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    let (h1, mut rx1) = connect_as_did(addr, "leaver", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#leaveme").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#leaveme"),
        "Joined",
    )
    .await;

    // DB should now have the channel.
    let before = db_user_channels(&db_path, DID);
    assert!(
        before.iter().any(|c| c == "#leaveme"),
        "after JOIN the DB must persist the channel for auto-rejoin, got {before:?}"
    );

    h1.raw("PART #leaveme").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#leaveme"),
        "Parted",
    )
    .await;

    // DB must be empty for this DID/channel after PART.
    let after = db_user_channels(&db_path, DID);
    assert!(
        !after.iter().any(|c| c == "#leaveme"),
        "after PART the DB must remove the channel so the next reconnect doesn't rejoin, got {after:?}"
    );

    h1.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #2: PART is case-insensitive vs JOIN
// JOIN #FREEQ then PART #freeq must actually leave.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case_insensitive_part_leaves_channel() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    let (h1, mut rx1) = connect_as_did(addr, "casechk", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.raw("JOIN #FREEQ").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel.eq_ignore_ascii_case("#FREEQ")),
        "Joined",
    )
    .await;

    // PART with the lower-case form — should still leave.
    h1.raw("PART #freeq").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel.eq_ignore_ascii_case("#freeq")),
        "Parted",
    )
    .await;

    // DB must be empty: regardless of how the channel was stored, a part
    // for the same channel under any casing should clear the auto-rejoin
    // entry. Otherwise the user's next reconnect silently puts them back.
    let after = db_user_channels(&db_path, DID);
    assert!(
        after.iter().all(|c| !c.eq_ignore_ascii_case("#freeq")),
        "PART must clear user_channels regardless of channel-name casing; DB still has {after:?}"
    );

    h1.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #3: multi-device part must not strand the other session
// Two devices both in #foo. Device A parts. Device B is still in #foo
// (correct: PART is per-session). But the DB has been cleared, which
// means the moment B reconnects (or B's ghost expires), B can never
// auto-rejoin a channel it never explicitly left.
//
// This is the "channel list inconsistent across web/iOS" failure mode
// a user reports when they leave on one device and the channel
// reappears or disappears unexpectedly on the other.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn multi_device_part_keeps_db_for_other_session() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    // Device A joins #shared.
    let (h1, mut rx1) = connect_as_did(addr, "shared", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#shared").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#shared"),
        "A Joined",
    )
    .await;

    // DB has #shared.
    assert!(
        db_user_channels(&db_path, DID)
            .iter()
            .any(|c| c == "#shared"),
        "after A's JOIN, DB must persist #shared"
    );

    // Device B (same DID) attaches — silently picks up #shared via attach_same_did.
    let (h2, mut rx2) = connect_as_did(addr, "shared", key2).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Confirm B can talk in #shared (i.e., B is actually in the channel).
    h2.privmsg("#shared", "B is here").await.unwrap();
    let _ = wait_event(
        &mut rx1,
        |e| matches!(e, Event::Message { text, .. } if text == "B is here"),
        "A receives B's message proving B is in #shared",
    )
    .await;

    // Device A parts #shared. Per-session leave: B should still be in.
    h1.raw("PART #shared").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#shared"),
        "A Parted",
    )
    .await;

    // B is still in #shared — confirm via a fresh message round-trip.
    tokio::time::sleep(Duration::from_millis(200)).await;
    h2.privmsg("#shared", "B still here").await.unwrap();
    // (We don't wait on rx1 because A parted; we just check B can still send.)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The bug under test: A's PART unconditionally removed (DID, #shared)
    // from user_channels, even though B (same DID) is currently a member.
    // If both devices later reconnect, neither will be auto-rejoined to a
    // channel that one of them never left.
    let after = db_user_channels(&db_path, DID);
    assert!(
        after.iter().any(|c| c == "#shared"),
        "after A parts but B is still in #shared, DB must keep the auto-rejoin entry; \
         got {after:?} — B never explicitly left, so the next reconnect must restore #shared"
    );

    h1.quit(None).await.ok();
    h2.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #4: end-to-end — multi-device part, B's reconnect
// should restore #room because B never explicitly left it.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn multi_device_part_does_not_strand_other_session_on_reconnect() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2a = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2b = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _db_path, _h) = start_with_db_path(&key).await;

    // A joins #room. B attaches.
    let (h1, mut rx1) = connect_as_did(addr, "stayer", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#room").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#room"),
        "A Joined",
    )
    .await;

    let (h2, mut rx2) = connect_as_did(addr, "stayer", key2a).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A parts; B is still in.
    h1.raw("PART #room").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#room"),
        "A Parted",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // B disconnects (A still alive → no ghost mode for B).
    h2.quit(None).await.ok();
    drop(rx2);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B reconnects fresh — must be auto-rejoined to #room because B
    // never explicitly parted. Pre-fix the DB row was already nuked
    // by A's PART, so this would silently drop B from #room forever.
    let (h2b, mut rx2b) = connect_as_did(addr, "stayer", key2b).await;
    wait_auth(&mut rx2b).await;
    wait_registered(&mut rx2b).await;

    timeout(Duration::from_millis(2000), async {
        loop {
            match rx2b.recv().await {
                Some(Event::Joined { channel, .. }) if channel == "#room" => return,
                Some(_) => continue,
                None => panic!("rx2b closed before #room rejoin"),
            }
        }
    })
    .await
    .expect("B must be auto-rejoined to #room after reconnect — never parted from there");

    h1.quit(None).await.ok();
    h2b.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #5: KICK must clear the kicked user's auto-rejoin entry.
// Otherwise the kicked user reconnects and is silently put back in
// the channel they were kicked from.
// ───────────────────────────────────────────────────────────────────

const DID_VICTIM: &str = "did:plc:kickvic";

async fn start_with_two_dids(
    key_op: &PrivateKey,
    key_victim: &PrivateKey,
) -> (
    std::net::SocketAddr,
    String,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let mut docs = HashMap::new();
    docs.insert(
        DID.to_string(),
        did::make_test_did_document(DID, &key_op.public_key_multibase()),
    );
    docs.insert(
        DID_VICTIM.to_string(),
        did::make_test_did_document(DID_VICTIM, &key_victim.public_key_multibase()),
    );
    let resolver = DidResolver::static_map(docs);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-kick".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.clone()),
        ..Default::default()
    };
    let (addr, handle) = freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap();
    (addr, db_path, handle)
}

async fn connect_did(
    addr: std::net::SocketAddr,
    did_str: &str,
    nick: &str,
    key: PrivateKey,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did_str.to_string(), key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "kick test".to_string(),
        ..Default::default()
    };
    client::connect(config, Some(signer))
}

#[tokio::test]
async fn kick_clears_victim_auto_rejoin_entry() {
    let key_op = PrivateKey::generate_ed25519();
    let key_op_use = PrivateKey::ed25519_from_bytes(&key_op.secret_bytes()).unwrap();
    let key_victim = PrivateKey::generate_ed25519();
    let key_victim_use = PrivateKey::ed25519_from_bytes(&key_victim.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_two_dids(&key_op, &key_victim).await;

    // Operator (founder, auto-op) joins #room.
    let (h_op, mut rx_op) = connect_did(addr, DID, "op", key_op_use).await;
    wait_auth(&mut rx_op).await;
    wait_registered(&mut rx_op).await;
    h_op.join("#room").await.unwrap();
    wait_event(
        &mut rx_op,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#room"),
        "op Joined",
    )
    .await;

    // Victim joins.
    let (h_v, mut rx_v) = connect_did(addr, DID_VICTIM, "victim", key_victim_use).await;
    wait_auth(&mut rx_v).await;
    wait_registered(&mut rx_v).await;
    h_v.join("#room").await.unwrap();
    wait_event(
        &mut rx_v,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#room"),
        "victim Joined",
    )
    .await;

    // Sanity: victim's auto-rejoin DB row exists.
    assert!(
        db_user_channels(&db_path, DID_VICTIM)
            .iter()
            .any(|c| c == "#room"),
        "after victim's JOIN, DB must persist #room for victim"
    );

    // Op kicks victim.
    h_op.raw("KICK #room victim :be gone").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The bug: KICK leaves the victim's user_channels row in place, so
    // the next time the victim reconnects, the server silently auto-rejoins
    // them to the channel they were just kicked from.
    let after = db_user_channels(&db_path, DID_VICTIM);
    assert!(
        !after.iter().any(|c| c == "#room"),
        "KICK must clear the victim's user_channels row; got {after:?} — \
         otherwise the victim's next reconnect silently restores #room and the kick is undone"
    );

    h_op.quit(None).await.ok();
    h_v.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #6: PART on a channel where the SERVER thinks the user
// isn't currently a member, but the DB still has it for auto-rejoin.
//
// User scenario: device A (web) joined #foo while device B (iOS) was
// offline. B comes online, gets attach_same_did → B is in #foo. Now
// A disconnects (ghost mode). B is still in #foo. Long enough that
// A's ghost expired. Now B's view of "channels I'm in" matches
// reality. User PARTs on B. With current behaviour we always run PART
// through the in-memory check; this test confirms the typical multi-
// device flow at least leaves both the in-memory channel and DB in a
// consistent state — i.e. PART from B clears the DB row when B was
// the only remaining session.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn part_after_other_session_quit_clears_db() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    // A joins, B attaches.
    let (h1, mut rx1) = connect_as_did(addr, "soloparter", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;
    h1.join("#solo").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#solo"),
        "A Joined",
    )
    .await;

    let (h2, mut rx2) = connect_as_did(addr, "soloparter", key2).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A disconnects; B is the only session left and still in #solo.
    h1.quit(None).await.ok();
    drop(rx1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        db_user_channels(&db_path, DID).iter().any(|c| c == "#solo"),
        "after A's QUIT (ghost mode preserves channels) DB must still have #solo"
    );

    // B parts #solo. Now no session for DID is in #solo → DB must clear.
    h2.raw("PART #solo").await.unwrap();
    wait_event(
        &mut rx2,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#solo"),
        "B Parted",
    )
    .await;
    let after = db_user_channels(&db_path, DID);
    assert!(
        !after.iter().any(|c| c == "#solo"),
        "PART by the last remaining session must clear DB; got {after:?}"
    );

    h2.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL #7: JOIN then PART then JOIN — DB and in-memory must
// stay consistent across the round trip. (Probe for INSERT-OR-IGNORE
// vs DELETE timing bugs.)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rapid_join_part_join_keeps_db_consistent() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    let (h1, mut rx1) = connect_as_did(addr, "rapid", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;

    h1.join("#x").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#x"),
        "Joined1",
    )
    .await;
    h1.raw("PART #x").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#x"),
        "Parted",
    )
    .await;
    h1.join("#x").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#x"),
        "Joined2",
    )
    .await;

    let final_db = db_user_channels(&db_path, DID);
    assert!(
        final_db.iter().any(|c| c == "#x"),
        "after JOIN-PART-JOIN the DB must reflect #x as joined; got {final_db:?}"
    );
    assert_eq!(
        final_db.iter().filter(|c| c.as_str() == "#x").count(),
        1,
        "DB must not contain duplicate rows after JOIN-PART-JOIN; got {final_db:?}"
    );

    h1.quit(None).await.ok();
}

// ───────────────────────────────────────────────────────────────────
// ADVERSARIAL: Client reconnect after PART must NOT auto-rejoin
//
// This test verifies the end-to-end behavior that iOS clients rely on:
// after PART + disconnect + reconnect, the server must not auto-join
// the PARTed channel. This exercises the DB cleanup path that the
// iOS client's `autoJoinChannels` UserDefaults state mirrors.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn part_then_reconnect_does_not_auto_rejoin() {
    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap(); // clone for second connection
    let (addr, db_path, _h) = start_with_db_path(&key).await;

    // First connection
    let (h1, mut rx1) = connect_as_did(addr, "leaver", key1).await;
    wait_auth(&mut rx1).await;
    wait_registered(&mut rx1).await;

    h1.join("#stay").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#stay"),
        "Joined #stay",
    )
    .await;
    h1.join("#leaved").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#leaved"),
        "Joined #leaved",
    )
    .await;

    // Verify both channels are in DB
    let before = db_user_channels(&db_path, DID);
    assert!(
        before.iter().any(|c| c == "#stay"),
        "before: #stay should be in DB"
    );
    assert!(
        before.iter().any(|c| c == "#leaved"),
        "before: #leaved should be in DB"
    );

    // PART the channel we want to leave
    h1.raw("PART #leaved").await.unwrap();
    wait_event(
        &mut rx1,
        |e| matches!(e, Event::Parted { channel, .. } if channel == "#leaved"),
        "Parted",
    )
    .await;

    // Verify DB was cleaned up
    let after_part = db_user_channels(&db_path, DID);
    assert!(
        after_part.iter().any(|c| c == "#stay"),
        "after PART: #stay should still be in DB"
    );
    assert!(
        !after_part.iter().any(|c| c == "#leaved"),
        "after PART: #leaved must NOT be in DB"
    );

    // Disconnect
    h1.quit(None).await.ok();

    // Reconnection
    let (h2, mut rx2) = connect_as_did(addr, "leaver", key2).await;
    wait_auth(&mut rx2).await;
    wait_registered(&mut rx2).await;

    // Allow events to settle
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Collect any auto-join events
    let joined_stay = wait_for_event_timeout(
        &mut rx2,
        500,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#stay"),
    )
    .await;

    let joined_leaved = wait_for_event_timeout(
        &mut rx2,
        200,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#leaved"),
    )
    .await;

    // Must have joined #stay (was not PARTed)
    assert!(joined_stay.is_some(), "should auto-join #stay on reconnect");

    // Must NOT have joined #leaved (was PARTed)
    assert!(
        joined_leaved.is_none(),
        "should NOT auto-join #leaved after PART"
    );

    h2.quit(None).await.ok();
}

// Helper to wait for an event with timeout, returning None on timeout
async fn wait_for_event_timeout<F>(
    rx: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    pred: F,
) -> Option<Event>
where
    F: Fn(&Event) -> bool,
{
    use tokio::time::{Duration, timeout};
    timeout(Duration::from_millis(timeout_ms), async {
        loop {
            if let Some(e) = rx.recv().await
                && pred(&e)
            {
                return e;
            }
        }
    })
    .await
    .ok()
}

// ═══════════════════════════════════════════════════════════════
// REGRESSION: nick_to_session must be populated even when a previous
// session for the same DID left a stale entry. Triggered by the
// half-registered-session bug where actor.nick is None on the REST
// endpoint while online=true.
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_to_session_recovers_when_stale_entry_lingers() {
    // The bug: attach_same_did's "first session for DID" path used
    // `if !nts.contains_nick(nick)` which skipped insert when a stale
    // entry from a dead session still occupied the nick. Result: new
    // session ends up in session_dids but NOT in nick_to_session, so
    // WHOIS by nick can't find the DID and DM routing breaks.
    //
    // Repro: connect → drop without QUIT → manipulate state to leave
    // a stale nick_to_session entry → reconnect → assert the nick is
    // mapped to the new session_id.
    //
    // We don't have direct test access to the SharedState, so this
    // test exercises the realistic scenario instead: a second session
    // for the same DID arriving when the first session's nick mapping
    // is in an unusual state. The fallback branch in attach_same_did
    // (multi-device path with no canonical_nick) handles this.

    let key = PrivateKey::generate_ed25519();
    let key1 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let key2 = PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap();
    let (addr, _h) = start(&key).await;

    // Session A registers.
    let (h1, mut rx1) = connect_as_did(addr, "alpha", key1).await;
    wait_auth(&mut rx1).await;
    let nick1 = wait_registered(&mut rx1).await;
    assert_eq!(nick1.to_lowercase(), "alpha");

    // Session B for the same DID — should adopt the same nick via
    // multi-device attach (canonical_nick path).
    let (h2, mut rx2) = connect_as_did(addr, "alpha", key2).await;
    wait_auth(&mut rx2).await;
    let nick2 = wait_registered(&mut rx2).await;
    assert_eq!(
        nick2.to_lowercase(),
        "alpha",
        "both sessions share the nick"
    );

    // Both sessions should resolve via WHOIS from a third (guest) probe.
    // We use a raw IRC conversation so we can drive WHOIS and parse 401/311.
    let probe_nick = "probe";
    let probe_config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: probe_nick.to_string(),
        user: probe_nick.to_string(),
        realname: "regression probe".to_string(),
        ..Default::default()
    };
    let (h_probe, mut rx_probe) = client::connect(probe_config, None);
    wait_registered(&mut rx_probe).await;
    h_probe.raw("WHOIS alpha").await.unwrap();
    let mut got_311 = false;
    let mut got_401 = false;
    let _ = timeout(Duration::from_millis(2000), async {
        while let Some(e) = rx_probe.recv().await {
            if let Event::RawLine(line) = e {
                if line.contains(" 311 probe alpha ") {
                    got_311 = true;
                }
                if line.contains(" 401 probe alpha ") {
                    got_401 = true;
                }
                if line.contains(" 318 probe alpha ") {
                    break; // end of WHOIS
                }
            }
        }
    })
    .await;

    assert!(
        got_311,
        "WHOIS alpha must return 311 (RPL_WHOISUSER) — \
        if 401 instead, the bug is back: nick→session mapping is missing."
    );
    assert!(
        !got_401,
        "WHOIS alpha returned 401 — half-state bug regressed."
    );

    h_probe.quit(None).await.ok();
    h1.quit(None).await.ok();
    h2.quit(None).await.ok();
}

// ═══════════════════════════════════════════════════════════════
// DID WIRE TARGETS (Element B): a PRIVMSG addressed to `did:plc:x`
// delivers to every local session bound to that DID, and the
// recipient sees the DID as the target (no per-server nick rewrite).
// Nick-addressed DMs must still fan out to all devices too.
// ═══════════════════════════════════════════════════════════════

const DID_SENDER: &str = "did:plc:didsender";
const DID_RECIP: &str = "did:plc:didrecip";

async fn start_sender_recip(
    key_sender: &PrivateKey,
    key_recip: &PrivateKey,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let mut docs = HashMap::new();
    docs.insert(
        DID_SENDER.to_string(),
        did::make_test_did_document(DID_SENDER, &key_sender.public_key_multibase()),
    );
    docs.insert(
        DID_RECIP.to_string(),
        did::make_test_did_document(DID_RECIP, &key_recip.public_key_multibase()),
    );
    let resolver = DidResolver::static_map(docs);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-didtarget".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

#[tokio::test]
async fn dm_to_did_target_reaches_all_recipient_devices() {
    let key_s = PrivateKey::generate_ed25519();
    let key_s_use = PrivateKey::ed25519_from_bytes(&key_s.secret_bytes()).unwrap();
    let key_r = PrivateKey::generate_ed25519();
    let key_r1 = PrivateKey::ed25519_from_bytes(&key_r.secret_bytes()).unwrap();
    let key_r2 = PrivateKey::ed25519_from_bytes(&key_r.secret_bytes()).unwrap();
    let (addr, _h) = start_sender_recip(&key_s, &key_r).await;

    // Recipient: two devices, same DID.
    let (hr1, mut rxr1) = connect_did(addr, DID_RECIP, "recip", key_r1).await;
    wait_auth(&mut rxr1).await;
    wait_registered(&mut rxr1).await;
    let (hr2, mut rxr2) = connect_did(addr, DID_RECIP, "recip", key_r2).await;
    wait_auth(&mut rxr2).await;
    wait_registered(&mut rxr2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Sender addresses the recipient's DID, not its nick.
    let (hs, mut rxs) = connect_did(addr, DID_SENDER, "sender", key_s_use).await;
    wait_auth(&mut rxs).await;
    wait_registered(&mut rxs).await;
    hs.privmsg(DID_RECIP, "hello by did").await.unwrap();

    // Both recipient devices receive it, with the DID echoed as the target.
    for (rx, dev) in [(&mut rxr1, "device 1"), (&mut rxr2, "device 2")] {
        let msg = wait_event(
            rx,
            |e| matches!(e, Event::Message { text, .. } if text == "hello by did"),
            dev,
        )
        .await;
        assert!(
            matches!(msg, Event::Message { target, .. } if target == DID_RECIP),
            "{dev}: recipient must see the DID as the PRIVMSG target (no nick rewrite)"
        );
    }

    // Regression: a nick-addressed DM must still fan out to both devices.
    hs.privmsg("recip", "hello by nick").await.unwrap();
    for (rx, dev) in [(&mut rxr1, "device 1"), (&mut rxr2, "device 2")] {
        wait_event(
            rx,
            |e| matches!(e, Event::Message { text, .. } if text == "hello by nick"),
            dev,
        )
        .await;
    }

    hs.quit(None).await.ok();
    hr1.quit(None).await.ok();
    hr2.quit(None).await.ok();
}

// ═══════════════════════════════════════════════════════════════
// DID-KEYED DM PERSISTENCE (Element C): the sender's own server
// keeps its copy of a DID-addressed DM, keyed by canonical_dm_key.
// Before, the send-side persist only ran when nick_owners resolved
// the target, so a `did:`-addressed DM left no sender-side history.
// ═══════════════════════════════════════════════════════════════

async fn start_sender_recip_db(
    key_sender: &PrivateKey,
    key_recip: &PrivateKey,
) -> (
    std::net::SocketAddr,
    String,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let mut docs = HashMap::new();
    docs.insert(
        DID_SENDER.to_string(),
        did::make_test_did_document(DID_SENDER, &key_sender.public_key_multibase()),
    );
    docs.insert(
        DID_RECIP.to_string(),
        did::make_test_did_document(DID_RECIP, &key_recip.public_key_multibase()),
    );
    let resolver = DidResolver::static_map(docs);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-didpersist".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.clone()),
        ..Default::default()
    };
    let (addr, handle) = freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap();
    (addr, db_path, handle)
}

#[tokio::test]
async fn sender_persists_its_own_copy_of_a_did_addressed_dm() {
    let key_s = PrivateKey::generate_ed25519();
    let key_s_use = PrivateKey::ed25519_from_bytes(&key_s.secret_bytes()).unwrap();
    let key_r = PrivateKey::generate_ed25519();
    let key_r1 = PrivateKey::ed25519_from_bytes(&key_r.secret_bytes()).unwrap();
    let (addr, db_path, _h) = start_sender_recip_db(&key_s, &key_r).await;

    // Recipient online so the send completes cleanly.
    let (hr, mut rxr) = connect_did(addr, DID_RECIP, "recip", key_r1).await;
    wait_auth(&mut rxr).await;
    wait_registered(&mut rxr).await;

    let (hs, mut rxs) = connect_did(addr, DID_SENDER, "sender", key_s_use).await;
    wait_auth(&mut rxs).await;
    wait_registered(&mut rxs).await;
    hs.privmsg(DID_RECIP, "kept on the sender").await.unwrap();

    // Recipient receiving it confirms the send path ran.
    wait_event(
        &mut rxr,
        |e| matches!(e, Event::Message { text, .. } if text == "kept on the sender"),
        "recipient receives DID-addressed DM",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The sender's server persisted its copy under the DID-keyed dm_key. The
    // message body is encrypted-at-rest, but the `channel` key column is
    // plaintext — and keying under canonical_dm_key(sender, recipient) is
    // exactly what Element C guarantees. Exactly one DM was sent.
    let dm_key = freeq_server::db::canonical_dm_key(DID_SENDER, DID_RECIP);
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE channel = ?1",
            rusqlite::params![dm_key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "sender's server must keep its own copy of a DID-addressed DM under the \
         DID-keyed dm_key {dm_key}"
    );

    hs.quit(None).await.ok();
    hr.quit(None).await.ok();
}
