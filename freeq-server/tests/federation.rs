//! Two-server federation harness.
//!
//! Boots two **real** `freeq-server` binaries, S2S-peered over iroh on
//! localhost, and drives them with SDK clients — end-to-end cross-server
//! coverage (DID-addressed delivery, DM persistence, dedup, TAGMSG relay)
//! that the in-process suites cannot provide.
//!
//! Excluded from the default suite: every test is `#[ignore]`, run explicitly
//! with `cargo test -p freeq-server --test federation -- --ignored`
//! (CI: `.github/workflows/federation.yml`, path-filtered).
//!
//! Design notes — subprocess (not in-process) so that a future job can pit
//! mixed *versions* of the server against each other, which linking two
//! versions of one crate into a single test binary can never do. Key mechanics:
//! - iroh endpoint identity is derived from a pre-seeded key file, so both
//!   endpoint IDs are known *before* either server boots (no log parsing).
//! - peers dial by `id@127.0.0.1:port` (the direct-addr `--s2s-peers` form),
//!   so peering is hermetic localhost, not public discovery.
//! - DIDs resolve from `--did-resolver-static` (offline auth for test users).
//! - waits are event/DB-driven with a timeout; never a fixed sleep.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to keep retrying a cross-server assertion while the S2S link and
/// peer state settle. Behavioural readiness — no fixed pre-sleep.
const S2S_SETTLE: Duration = Duration::from_secs(20);

// ── test identities ──────────────────────────────────────────────

/// A test DID + its keypair, resolvable offline via `--did-resolver-static`.
struct TestId {
    did: String,
    key: PrivateKey,
}

impl TestId {
    fn new(did: &str) -> Self {
        TestId {
            did: did.to_string(),
            key: PrivateKey::generate_ed25519(),
        }
    }
    /// `did=<publicKeyMultibase>` entry for `--did-resolver-static`.
    fn resolver_entry(&self) -> String {
        format!("{}={}", self.did, self.key.public_key_multibase())
    }
    /// A fresh signer over the same key (KeySigner consumes the key).
    fn signer(&self) -> Arc<dyn ChallengeSigner> {
        let key = PrivateKey::ed25519_from_bytes(&self.key.secret_bytes()).unwrap();
        Arc::new(KeySigner::new(self.did.clone(), key))
    }
}

// ── server process management ────────────────────────────────────

/// A running `freeq-server` subprocess. `Drop` kills it and removes its tempdir.
struct TestServer {
    _dir: tempfile::TempDir,
    child: Child,
    irc_addr: String,
    db_path: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bind an ephemeral port, read it, release it. Small reuse race; startup
/// failure is retried by the caller if it bites.
fn alloc_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Deterministic iroh identity: write the hex key file the server loads, and
/// derive the endpoint ID from the same bytes so we know it before boot.
fn seed_iroh_identity(dir: &std::path::Path, seed: u8) -> (String, u16) {
    let bytes = [seed; 32];
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("iroh-key.secret"), hex).unwrap();
    let id = iroh::SecretKey::from_bytes(&bytes).public().to_string();
    (id, alloc_port())
}

/// Plan for one server before spawning — identity/ports known so peers can
/// reference each other.
struct ServerPlan {
    dir: tempfile::TempDir,
    irc_port: u16,
    iroh_id: String,
    iroh_port: u16,
    seed: u8,
}

fn plan_server(seed: u8) -> ServerPlan {
    let dir = tempfile::TempDir::new().unwrap();
    let (iroh_id, iroh_port) = seed_iroh_identity(dir.path(), seed);
    ServerPlan {
        dir,
        irc_port: alloc_port(),
        iroh_id,
        iroh_port,
        seed,
    }
}

/// The identity + direct address one server needs to dial another. Cloned out
/// of a `ServerPlan` before the plan (which owns a tempdir) is moved into spawn.
struct PeerRef {
    iroh_id: String,
    iroh_port: u16,
}

impl PeerRef {
    fn of(plan: &ServerPlan) -> Self {
        PeerRef {
            iroh_id: plan.iroh_id.clone(),
            iroh_port: plan.iroh_port,
        }
    }
}

/// Spawn one server from its plan, peered to `peer`, resolving `resolver_entries`.
fn spawn_server(plan: ServerPlan, peer: &PeerRef, resolver_entries: &str) -> TestServer {
    let db_path = plan
        .dir
        .path()
        .join("server.db")
        .to_str()
        .unwrap()
        .to_string();
    let irc_addr = format!("127.0.0.1:{}", plan.irc_port);
    let peer_spec = format!("{}@127.0.0.1:{}", peer.iroh_id, peer.iroh_port);

    let child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
        .args([
            "--listen-addr",
            &irc_addr,
            "--iroh",
            "--iroh-port",
            &plan.iroh_port.to_string(),
            "--data-dir",
            plan.dir.path().to_str().unwrap(),
            "--db-path",
            &db_path,
            "--s2s-peers",
            &peer_spec,
            "--s2s-allowed-peers",
            &peer.iroh_id,
            "--did-resolver-static",
            resolver_entries,
            "--server-name",
            &format!("test-fed-{}", plan.seed),
        ])
        .env("RUST_LOG", "freeq_server=warn")
        .spawn()
        .expect("spawn freeq-server");

    TestServer {
        _dir: plan.dir,
        child,
        irc_addr,
        db_path,
    }
}

/// Boot two mutually-peered servers, both resolving every `ids` DID offline.
/// Blocks until both IRC ports accept connections.
async fn spawn_pair(ids: &[&TestId]) -> (TestServer, TestServer) {
    let a_plan = plan_server(0xA1);
    let b_plan = plan_server(0xB2);
    let resolver: String = ids
        .iter()
        .map(|i| i.resolver_entry())
        .collect::<Vec<_>>()
        .join(",");

    // Capture each identity before moving the plans into their servers, so the
    // two can cross-reference for peering.
    let a_ref = PeerRef::of(&a_plan);
    let b_ref = PeerRef::of(&b_plan);
    let a = spawn_server(a_plan, &b_ref, &resolver);
    let b = spawn_server(b_plan, &a_ref, &resolver);

    wait_port(&a.irc_addr).await;
    wait_port(&b.irc_addr).await;
    (a, b)
}

/// Poll a TCP port until it accepts (server IRC listener up).
async fn wait_port(addr: &str) {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("server at {addr} never became ready");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── client helpers (mirrors multi_device.rs) ─────────────────────

fn connect(
    server: &TestServer,
    id: &TestId,
    nick: &str,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: server.irc_addr.clone(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "federation test".to_string(),
        ..Default::default()
    };
    client::connect(config, Some(id.signer()))
}

async fn wait_event(
    rx: &mut mpsc::Receiver<Event>,
    pred: impl Fn(&Event) -> bool,
    desc: &str,
) -> Event {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(e) if pred(&e) => return e,
                Some(_) => continue,
                None => panic!("channel closed waiting for {desc}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {desc}"))
}

async fn wait_auth_and_register(rx: &mut mpsc::Receiver<Event>) {
    wait_event(
        rx,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
    wait_event(rx, |e| matches!(e, Event::Registered { .. }), "Registered").await;
}

/// Best-effort: wait up to `dur` for a matching `Message`, returning its target
/// (the value the recipient sees). `None` on timeout/close — never panics.
async fn try_recv_message(
    rx: &mut mpsc::Receiver<Event>,
    text: &str,
    dur: Duration,
) -> Option<String> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(Event::Message {
                    text: t, target, ..
                }) if t == text => return Some(target),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Resend a DID-addressed DM until `rx` receives it (or the settle window
/// elapses), asserting the recipient sees the DID echoed as the target. Returns
/// once delivery is confirmed — the shared "the S2S link is up" gate, with no
/// fixed pre-sleep. Drains the delivered probe(s) from `rx`.
async fn warm_link(
    sender: &client::ClientHandle,
    target_did: &str,
    rx: &mut mpsc::Receiver<Event>,
) {
    let probe = "link-warmup-probe";
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        sender.privmsg(target_did, probe).await.ok();
        if try_recv_message(rx, probe, Duration::from_secs(2))
            .await
            .is_some()
        {
            // Drain any duplicate probe deliveries (bidirectional dial flap).
            while try_recv_message(rx, probe, Duration::from_millis(300))
                .await
                .is_some()
            {}
            return;
        }
    }
    panic!("S2S link never delivered a probe within {S2S_SETTLE:?}");
}

/// Read the number of persisted message rows under a DM key on a server's DB.
/// The `channel` column (the `canonical_dm_key`) is plaintext even with
/// encryption-at-rest, so this needs no decryption key.
fn dm_row_count(db_path: &str, dm_key: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE channel = ?1",
        rusqlite::params![dm_key],
        |r| r.get(0),
    )
    .expect("count dm rows")
}

// ── DID-addressed DM crosses the S2S link (Element B receive path) ──

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn did_target_dm_crosses_servers() {
    let alice = TestId::new("did:plc:alicefed");
    let bob = TestId::new("did:plc:bobfed");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob is on server B.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;

    // Alice is on server A; she addresses Bob by DID.
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // The S2S link may still be settling; resend until Bob receives it (or the
    // settle window elapses). No fixed pre-sleep.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut target = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg(&bob.did, "hello across servers").await.ok();
        if let Some(t) =
            try_recv_message(&mut rxb, "hello across servers", Duration::from_secs(2)).await
        {
            target = Some(t);
            break;
        }
    }
    assert_eq!(
        target.expect("bob received the DID-addressed DM across servers"),
        bob.did,
        "recipient sees the DID echoed as target, not a rewritten nick"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── multi-device fan-out across servers ──────────────────────────

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn did_dm_reaches_all_recipient_devices_across_servers() {
    let alice = TestId::new("did:plc:alicemd");
    let bob = TestId::new("did:plc:bobmd");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob on two devices, both on server B (same DID → multi-device attach).
    let (hb1, mut rxb1) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb1).await;
    let (hb2, mut rxb2) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb2).await;

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // Warm on device 1, then a single real send must fan out to BOTH devices.
    warm_link(&ha, &bob.did, &mut rxb1).await;
    ha.privmsg(&bob.did, "to all my devices").await.unwrap();

    for (rx, dev) in [(&mut rxb1, "device 1"), (&mut rxb2, "device 2")] {
        assert!(
            try_recv_message(rx, "to all my devices", EVENT_TIMEOUT)
                .await
                .is_some(),
            "{dev} did not receive the DID-addressed DM"
        );
    }

    ha.quit(None).await.ok();
    hb1.quit(None).await.ok();
    hb2.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── receiver persists the DID-keyed DM (Element C stamp path) ─────

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn did_dm_persists_on_receiver_under_dm_key() {
    let alice = TestId::new("did:plc:alicep");
    let bob = TestId::new("did:plc:bobp");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.privmsg(&bob.did, "persist me").await.unwrap();
    assert!(
        try_recv_message(&mut rxb, "persist me", EVENT_TIMEOUT)
            .await
            .is_some(),
        "bob must receive the message"
    );

    // The receiving server keyed it under canonical_dm_key(alice, bob): the
    // origin stamped recipient_did, B reconciled it against its local
    // resolution, and persisted. Poll — the write follows delivery.
    let dm_key = freeq_server::db::canonical_dm_key(&alice.did, &bob.did);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while dm_row_count(&srv_b.db_path, &dm_key) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        dm_row_count(&srv_b.db_path, &dm_key) >= 1,
        "server B must persist the cross-server DM under {dm_key}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
    // Note: the stamp *mismatch* path (a wrong recipient_did → no durable row)
    // can't be driven from a black-box client — the origin always stamps
    // correctly. It is unit-covered by
    // `connection::routing::tests::reconcile_recipient_did_honors_stamp_but_refuses_mismatch`.
}

// ── nick-addressed DM to a remote-only user (no recipient stamp) ──
//
// A DID-addressed DM always carries the origin's recipient_did stamp. A
// *nick*-addressed DM to a user the origin doesn't own carries none — the
// origin can't authoritatively resolve a nick it doesn't own, so it attaches
// no recipient DID. The receiver must still deliver it, and — because it *does*
// own that nick — key the durable copy from its own local resolution, exactly
// as it did before the stamp existed. This drives the reconcile "no stamp →
// local wins" branch end-to-end; the DID tests only cover the stamped branch.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn nick_dm_to_remote_user_crosses_and_persists_without_a_stamp() {
    let alice = TestId::new("did:plc:alicens");
    let bob = TestId::new("did:plc:bobns");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob only on B, alice only on A. A does not own bob's nick, so a
    // nick-addressed DM from A crosses with recipient_did = None.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // Resend the nick-addressed DM until it lands (also warms the S2S link).
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut target = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("bob", "nick across servers").await.ok();
        if let Some(t) =
            try_recv_message(&mut rxb, "nick across servers", Duration::from_secs(2)).await
        {
            target = Some(t);
            break;
        }
    }
    assert_eq!(
        target.expect("bob received the nick-addressed DM across servers"),
        "bob",
        "recipient sees the nick echoed as target"
    );

    // B owns bob's nick, so it reconciles the absent stamp to its own local
    // resolution and persists under canonical_dm_key(alice, bob) — the
    // pre-stamp behaviour, still intact when no stamp arrives.
    let dm_key = freeq_server::db::canonical_dm_key(&alice.did, &bob.did);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while dm_row_count(&srv_b.db_path, &dm_key) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        dm_row_count(&srv_b.db_path, &dm_key) >= 1,
        "server B must persist the unstamped nick DM under {dm_key} via local resolution"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── TAGMSG to a remote-only DID relays as a structured Tagmsg ─────
//
// Regression guard for the cross-server TAGMSG gap: a reaction addressed to a
// DID that lives *only* on the peer must cross as a structured `Tagmsg` (tags
// intact), not degrade to a `Privmsg` ACTION fallback. Before the fix, the DM
// branch routed through `relay_to_nick` (PRIVMSG-shaped) and dropped the tags;
// now it delivers locally and always broadcasts an `S2sMessage::Tagmsg`.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn tagmsg_to_remote_did_relays_as_structured_tagmsg() {
    let alice = TestId::new("did:plc:alicetag");
    let bob = TestId::new("did:plc:bobtag");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob is only on server B; alice only on A.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    warm_link(&ha, &bob.did, &mut rxb).await;

    // Alice reacts to bob's DID; bob (on the other server) must receive a
    // structured TAGMSG carrying the reaction tag.
    let got = timeout(EVENT_TIMEOUT, async {
        loop {
            ha.raw(&format!("@+react=\u{1F44D} TAGMSG {}", bob.did))
                .await
                .ok();
            if let Ok(Some(())) = timeout(Duration::from_secs(2), async {
                loop {
                    match rxb.recv().await {
                        Some(Event::TagMsg { tags, .. }) if tags.contains_key("+react") => {
                            return Some(());
                        }
                        Some(_) => continue,
                        None => return None,
                    }
                }
            })
            .await
            {
                return true;
            }
        }
    })
    .await;
    assert!(
        got.is_ok(),
        "a reaction TAGMSG to a remote-only DID must cross as a structured Tagmsg"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a single send is delivered exactly once (event_id dedup) ─────

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn single_send_delivered_exactly_once() {
    let alice = TestId::new("did:plc:aliced");
    let bob = TestId::new("did:plc:bobd");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // Establish the link first, so the real message is sent exactly once (no
    // retries) — the bidirectional dial must not double-deliver it.
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.privmsg(&bob.did, "once and only once").await.unwrap();

    assert!(
        try_recv_message(&mut rxb, "once and only once", EVENT_TIMEOUT)
            .await
            .is_some(),
        "bob must receive the message"
    );
    // No second copy within a generous window (event_id dedup across the two
    // link generations).
    assert!(
        try_recv_message(&mut rxb, "once and only once", Duration::from_secs(3))
            .await
            .is_none(),
        "the single send must not be delivered twice"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}
