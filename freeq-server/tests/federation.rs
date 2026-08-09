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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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
/// One test at a time: each test boots two servers, and running the file in
/// parallel (22 servers at once) starves the machine — clients time out before
/// first auth and the whole batch fails. Taken in `spawn_pair`, which every
/// test goes through, so they queue regardless of cargo's `--test-threads`.
static ONE_TEST_AT_A_TIME: Mutex<()> = Mutex::new(());

struct TestServer {
    _dir: tempfile::TempDir,
    child: Child,
    irc_addr: String,
    web_addr: String,
    db_path: String,
    /// The argv this server was spawned with, so it can be stopped and
    /// started again on the same data — which is what "a peer went away and
    /// came back" means.
    args: Vec<String>,
    /// Held by server A for the test's lifetime; see `ONE_TEST_AT_A_TIME`.
    serial: Option<MutexGuard<'static, ()>>,
}

impl TestServer {
    /// Stop the process, leaving its database and identity on disk.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Start it again on the same data, same identity, same ports.
    async fn start_again(&mut self) {
        self.child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
            .args(&self.args)
            .env("RUST_LOG", "freeq_server=warn")
            .spawn()
            .expect("respawn freeq-server");
        wait_port(&self.irc_addr).await;
    }
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
    /// REST/WebSocket listener. Real deployments run one, and cross-server
    /// key lookup reaches a peer through it.
    web_port: u16,
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
        web_port: alloc_port(),
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
    web_port: u16,
}

impl PeerRef {
    fn of(plan: &ServerPlan) -> Self {
        PeerRef {
            iroh_id: plan.iroh_id.clone(),
            iroh_port: plan.iroh_port,
            web_port: plan.web_port,
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
    let web_addr = format!("127.0.0.1:{}", plan.web_port);
    let peer_spec = format!("{}@127.0.0.1:{}", peer.iroh_id, peer.iroh_port);
    // Where this server looks for the peer's users' signing keys. Operator
    // configuration in production; here, the peer's own REST listener.
    let peer_api = format!("{}=http://127.0.0.1:{}", peer.iroh_id, peer.web_port);

    let args: Vec<String> = [
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
        "--web-addr",
        &web_addr,
        "--s2s-peer-api",
        &peer_api,
        "--did-resolver-static",
        resolver_entries,
        "--server-name",
        &format!("test-fed-{}", plan.seed),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
        .args(&args)
        .env("RUST_LOG", "freeq_server=warn")
        .spawn()
        .expect("spawn freeq-server");

    TestServer {
        _dir: plan.dir,
        child,
        irc_addr,
        web_addr,
        db_path,
        args,
        serial: None,
    }
}

/// Boot two mutually-peered servers, both resolving every `ids` DID offline.
/// Blocks until both IRC ports accept connections.
async fn spawn_pair(ids: &[&TestId]) -> (TestServer, TestServer) {
    // A failed test poisons the lock; the next test's servers are unaffected,
    // so take it anyway.
    let serial = ONE_TEST_AT_A_TIME
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // A fresh iroh identity per pair. Every pair used to boot as the same two
    // node IDs, so two pairs alive at once — the previous test's servers still
    // exiting, or anything that runs this file without the lock above — were, to
    // iroh, the same two nodes reachable at two addresses. The lock makes that
    // rare rather than impossible; distinct identities make it harmless.
    static NEXT_SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let n = NEXT_SEED.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    let a_plan = plan_server(n);
    let b_plan = plan_server(n.wrapping_add(1));
    let resolver: String = ids
        .iter()
        .map(|i| i.resolver_entry())
        .collect::<Vec<_>>()
        .join(",");

    // Capture each identity before moving the plans into their servers, so the
    // two can cross-reference for peering.
    let a_ref = PeerRef::of(&a_plan);
    let b_ref = PeerRef::of(&b_plan);
    let mut a = spawn_server(a_plan, &b_ref, &resolver);
    let b = spawn_server(b_plan, &a_ref, &resolver);
    a.serial = Some(serial);

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

// ── a mutation TAGMSG's signature tag crosses the hop byte-identical ─────
//
// Message signatures cross S2S in a dedicated field of `S2sMessage::Privmsg`
// (and the PRIVMSG tag-relay helper deliberately strips `+freeq.at/sig`,
// since the field carries it). A TAGMSG mutation has no such field — its
// signature rides the raw `Tagmsg` tag map, and nothing else asserts that
// path. One route-through-the-filter refactor would silently drop mutation
// signatures in flight, and a signed delete arriving without its signature is
// indistinguishable from tampering.
//
// The signature is the sender's real one: the origin now checks a mutation's
// signature at ingress and refuses to relay one it cannot stand behind, so an
// invented tag no longer travels at all — it is stripped at the source, which
// is a different property, pinned separately in the ingress tests.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn mutation_sig_tag_crosses_the_hop_byte_identical() {
    let alice = TestId::new("did:plc:alicesigtag");
    let bob = TestId::new("did:plc:bobsigtag");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#fsig").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#fsig").await.unwrap();

    // Land a message so the reaction points at something both servers hold.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut msgid = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("#fsig", "react to me").await.ok();
        if let Some(id) = recv_channel_msgid(&mut rxb, "react to me", Duration::from_secs(2)).await
        {
            msgid = Some(id);
            break;
        }
    }
    let msgid = msgid.expect("bob's server received the channel message");

    // A reaction, signed by alice's own device through the SDK.
    ha.react("#fsig", "\u{1F44D}", &msgid).await.unwrap();

    async fn reaction_sig(rx: &mut mpsc::Receiver<Event>) -> Option<String> {
        timeout(EVENT_TIMEOUT, async {
            loop {
                match rx.recv().await {
                    Some(Event::TagMsg { tags, .. }) if tags.contains_key("+react") => {
                        return tags.get("+freeq.at/sig").cloned();
                    }
                    Some(_) => continue,
                    None => return None,
                }
            }
        })
        .await
        .expect("the reaction TAGMSG never arrived")
    }

    // The origin's own copy (echo-message), then the peer's.
    let origin_sig = reaction_sig(&mut rxa).await;
    let relayed_sig = reaction_sig(&mut rxb).await;

    assert!(
        origin_sig.is_some(),
        "the origin must relay a verified mutation's own signature"
    );
    assert_eq!(
        relayed_sig, origin_sig,
        "a mutation's +freeq.at/sig must cross S2S byte-identical"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a PRIVMSG's stamped signature crosses the hop byte-identical ─────
//
// The companion path to the mutation test above. PRIVMSG signatures cross
// S2S through machinery of their own: the origin server verifies-or-stamps
// `+freeq.at/sig` at ingress, the tag-relay helper strips the tag, and a
// dedicated field on `S2sMessage::Privmsg` carries it across; the receive
// side reattaches it. Nothing asserted that round trip end to end. The
// contract: whatever signature the origin broadcast to its own members,
// the peer's members receive byte-identical — or downstream verification
// fails in a way that looks exactly like tampering.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn privmsg_sig_crosses_the_hop_byte_identical() {
    let alice = TestId::new("did:plc:alicepmsig");
    let bob = TestId::new("did:plc:bobpmsig");
    let carol = TestId::new("did:plc:carolpmsig");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob, &carol]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#psig").await.unwrap();

    // Carol is the origin-side observer: what she receives is what server A
    // broadcast, stamped signature included.
    let (hc, mut rxc) = connect(&srv_a, &carol, "carol");
    wait_auth_and_register(&mut rxc).await;
    hc.join("#psig").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#psig").await.unwrap();

    // Unique text per attempt so both observations are matched to the same
    // send — every attempt gets a fresh signature, so comparing sigs from
    // two different attempts would be meaningless.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut crossed = None;
    let mut attempt = 0u32;
    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let text = format!("sig probe {attempt}");
        ha.privmsg("#psig", &text).await.ok();
        let got = timeout(Duration::from_secs(2), async {
            loop {
                match rxb.recv().await {
                    Some(Event::Message { text: t, tags, .. }) if t == text => {
                        return Some(tags.get("+freeq.at/sig").cloned());
                    }
                    Some(_) => continue,
                    None => return None,
                }
            }
        })
        .await;
        if let Ok(Some(sig)) = got {
            crossed = Some((text, sig));
            break;
        }
    }
    let (text, b_sig) = crossed.expect("no channel message crossed the hop");

    // Find the origin broadcast of that same send.
    let a_sig = timeout(EVENT_TIMEOUT, async {
        loop {
            match rxc.recv().await {
                Some(Event::Message { text: t, tags, .. }) if t == text => {
                    return tags.get("+freeq.at/sig").cloned();
                }
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .expect("carol never saw the origin broadcast");

    assert!(
        a_sig.is_some(),
        "the origin server must stamp +freeq.at/sig on an authenticated sender's channel message"
    );
    assert_eq!(
        b_sig, a_sig,
        "a PRIVMSG's +freeq.at/sig must arrive at the peer byte-identical to the origin broadcast"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    hc.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the receiving server reaches its own verdict ─────────────────
//
// The one that matters: a message signed by a client on server A, checked by
// server B, using a key B fetched from A's key endpoint. Server A's assurance
// plays no part — B rebuilds the document from what arrived, looks up the key
// the signature names, and answers for itself. Nothing here asserts on A.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn the_receiving_server_verifies_a_signature_for_itself() {
    let alice = TestId::new("did:plc:aliceverifies");
    let bob = TestId::new("did:plc:bobverifies");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#verified").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#verified").await.unwrap();

    // Land a signed message on B and learn the id B filed it under.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut landed = None;
    let mut attempt = 0u32;
    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let text = format!("verify me {attempt}");
        ha.privmsg("#verified", &text).await.ok();
        if let Some(msgid) = recv_channel_msgid(&mut rxb, &text, Duration::from_secs(2)).await {
            landed = Some(msgid);
            break;
        }
    }
    let msgid = landed.expect("alice's signed message never reached bob's server");

    // B's own answer, from B's own endpoint. The key lookup runs off the
    // delivery path, so the first read may still say "cannot check" — poll
    // until B has what it needs, then insist on a real verdict.
    let url = format!("http://{}/api/v1/verify/{msgid}", srv_b.web_addr);
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut last = serde_json::Value::Null;
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send().await
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            last = body;
            if last["verification"]["verdict"] == "valid" {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert_eq!(
        last["verification"]["verdict"], "valid",
        "the receiving server must reach a valid verdict on its own: {last}"
    );
    assert_eq!(
        last["verification"]["verified_by"], "client-session-key",
        "and it must be the sender's device that signed, not a server: {last}"
    );
    assert_eq!(last["sender_did"], alice.did);

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// The receiving server's own answer for `msgid`, polled until it reaches a
/// verdict. The key lookup runs off the delivery path, so the first read can
/// still honestly say "cannot check"; this waits for the server to have what
/// it needs and returns the last body read either way.
async fn poll_verify(web_addr: &str, msgid: &str) -> serde_json::Value {
    let url = format!("http://{web_addr}/api/v1/verify/{msgid}");
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut last = serde_json::Value::Null;
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send().await
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            last = body;
            if last["verification"]["verdict"] == "valid" {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    last
}

// ── a mutation that crossed the hop is on file at the receiver ───
//
// A reaction is durable state asserted under a user's name, and the receiving
// server applies it. Applying an act without recording it left that server's
// log unable to rebuild its own derived state, and its verify endpoint
// answering 404 for something it had itself accepted — so a bystander could
// check a federated *message* and not a federated *reaction*.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_reaction_that_crossed_the_hop_verifies_at_the_receiver() {
    let alice = TestId::new("did:plc:alicereacts");
    let bob = TestId::new("did:plc:bobreacts");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#reactverify").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#reactverify").await.unwrap();

    // A message for the reaction to act on, and the id B filed it under.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut landed = None;
    let mut attempt = 0u32;
    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let text = format!("react to me {attempt}");
        ha.privmsg("#reactverify", &text).await.ok();
        if let Some(msgid) = recv_channel_msgid(&mut rxb, &text, Duration::from_secs(2)).await {
            landed = Some(msgid);
            break;
        }
    }
    let msgid = landed.expect("alice's message never reached bob's server");

    // The reaction's own event id, learned the way any receiver learns it:
    // off the wire, from the tag the signature covers.
    let event_id = timeout(S2S_SETTLE, async {
        loop {
            ha.react("#reactverify", "\u{1F44D}", &msgid).await.ok();
            if let Ok(Some(id)) = timeout(Duration::from_secs(2), async {
                loop {
                    match rxb.recv().await {
                        Some(Event::TagMsg { tags, .. }) if tags.contains_key("+react") => {
                            return tags.get(freeq_sdk::chatsig::EVENT_ID_TAG).cloned();
                        }
                        Some(_) => continue,
                        None => return None,
                    }
                }
            })
            .await
            {
                return id;
            }
        }
    })
    .await
    .expect("the reaction never reached bob's server with an id");

    let v = poll_verify(&srv_b.web_addr, &event_id).await;
    assert_eq!(
        v["kind"], "react",
        "the receiving server must hold the act it applied, not 404 on it: {v}"
    );
    assert_eq!(v["actor_did"], alice.did);
    assert_eq!(v["subject"], msgid.as_str());
    assert_eq!(v["channel"], "#reactverify");
    assert_eq!(
        v["verification"]["verdict"], "valid",
        "and reach its own verdict on the signature: {v}"
    );
    assert_eq!(
        v["verification"]["verified_by"], "client-session-key",
        "signed on alice's device, not vouched by either server: {v}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a signed reply and a signed edit survive the hop ─────────────
//
// A plain message's document has four keys; a reply and an edit each add a
// covered field that has to cross the link intact and be *stored* intact, or
// the receiving server rebuilds a different document and reports an honest
// message as tampering. The transport half is unit-pinned
// (`privmsg_sig_crosses_the_hop_byte_identical`); this is the end-to-end half,
// from a real client's signature to the receiving server's own verdict.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_signed_reply_and_a_signed_edit_reach_valid_at_the_receiver() {
    let alice = TestId::new("did:plc:alicethreads");
    let bob = TestId::new("did:plc:bobthreads");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#threaded").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#threaded").await.unwrap();

    // The message the reply and the edit both refer to. Retried until it
    // lands, which is also what proves the channel is joined on both sides.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut landed = None;
    let mut attempt = 0u32;
    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let text = format!("root {attempt}");
        ha.privmsg("#threaded", &text).await.ok();
        if let Some(msgid) = recv_channel_msgid(&mut rxb, &text, Duration::from_secs(2)).await {
            landed = Some(msgid);
            break;
        }
    }
    let root = landed.expect("alice's message never reached bob's server");

    // A reply: the document covers `reply`, so the reference has to arrive
    // and be filed under the same spelling the signer used.
    ha.reply("#threaded", &root, "replying to that")
        .await
        .unwrap();
    let reply_msgid = recv_channel_msgid(&mut rxb, "replying to that", EVENT_TIMEOUT)
        .await
        .expect("alice's reply never reached bob's server");
    let verified = poll_verify(&srv_b.web_addr, &reply_msgid).await;
    assert_eq!(
        verified["verification"]["verdict"], "valid",
        "a signed reply must verify at the receiving server: {verified}"
    );
    assert_eq!(
        verified["verification"]["verified_by"], "client-session-key",
        "and it must be alice's device that signed it: {verified}"
    );
    assert_eq!(verified["sender_did"], alice.did);

    // An edit: same shape, but the covered field is `edit`, and the event is
    // filed as a revision of the message it names.
    ha.edit_message("#threaded", &root, "revised text")
        .await
        .unwrap();
    let edit_msgid = recv_channel_msgid(&mut rxb, "revised text", EVENT_TIMEOUT)
        .await
        .expect("alice's edit never reached bob's server");
    assert_ne!(edit_msgid, root, "an edit is its own event, with its own id");
    let verified = poll_verify(&srv_b.web_addr, &edit_msgid).await;
    assert_eq!(
        verified["verification"]["verdict"], "valid",
        "a signed edit must verify at the receiving server: {verified}"
    );
    assert_eq!(
        verified["verification"]["verified_by"], "client-session-key",
        "and it must be alice's device that signed it: {verified}"
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

// ── federated edits and deletes ──────────────────────────────────
//
// A message's identity is its original msgid on BOTH servers. These cover the
// two halves that used to stop at the origin: an edit arriving as linked
// revision rather than a second message, and a delete actually deleting.

/// Wait for a channel message whose text matches, returning its `msgid` tag.
async fn recv_channel_msgid(
    rx: &mut mpsc::Receiver<Event>,
    text: &str,
    dur: Duration,
) -> Option<String> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(Event::Message { text: t, tags, .. }) if t == text => {
                    return tags.get("msgid").cloned();
                }
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Rows for `channel` on this server that a delete hasn't struck. Like
/// `dm_row_count`, this reads the plaintext `channel` column, so it needs no
/// decryption key.
fn live_row_count(db_path: &str, channel: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE channel = ?1 AND deleted_at IS NULL",
        rusqlite::params![channel],
        |r| r.get(0),
    )
    .expect("count live rows")
}

/// Wait for a server's stored copy of `channel` to go empty. Poll rather than
/// sleep: how long a delete takes to cross is exactly what we can't assume.
async fn wait_rows_cleared(db_path: &str, channel: &str) -> bool {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        if live_row_count(db_path, channel) == 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Everything a fresh joiner on this server is replayed for `channel`.
async fn replayed_texts(server: &TestServer, id: &TestId, nick: &str, channel: &str) -> Vec<String> {
    let (h, mut rx) = connect(server, id, nick);
    wait_auth_and_register(&mut rx).await;
    h.join(channel).await.unwrap();
    let mut seen = Vec::new();
    // Replay arrives before the NAMES reply; collect until it goes quiet.
    while let Ok(Some(e)) = timeout(Duration::from_secs(2), rx.recv()).await {
        if let Event::Message { text, target, .. } = e
            && target.eq_ignore_ascii_case(channel)
        {
            seen.push(text);
        }
    }
    h.quit(None).await.ok();
    seen
}

/// An edit that crosses the hop must revise the peer's copy, not add a second
/// message to it.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn channel_edit_crosses_without_duplicating() {
    let alice = TestId::new("did:plc:aliceedit");
    let bob = TestId::new("did:plc:bobedit");
    let carol = TestId::new("did:plc:caroledit");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob, &carol]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#fedit").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#fedit").await.unwrap();

    // Send until Bob's server has it, then capture the identity Alice's server
    // assigned — the id both servers must agree on.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut msgid = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("#fedit", "before").await.ok();
        if let Some(id) = recv_channel_msgid(&mut rxb, "before", Duration::from_secs(2)).await {
            msgid = Some(id);
            break;
        }
    }
    let msgid = msgid.expect("bob's server received the channel message");

    ha.edit_message("#fedit", &msgid, "after").await.unwrap();
    assert!(
        try_recv_message(&mut rxb, "after", EVENT_TIMEOUT)
            .await
            .is_some(),
        "the edit never crossed the hop"
    );

    // The peer holds ONE message, carrying the newest text.
    let replayed = replayed_texts(&srv_b, &carol, "carol", "#fedit").await;
    let versions: Vec<&String> = replayed
        .iter()
        .filter(|t| *t == "before" || *t == "after")
        .collect();
    assert_eq!(
        versions,
        vec![&"after".to_string()],
        "a joiner on the peer must see the edited message once, not both \
         revisions: {replayed:?}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// A delete has to cross too — relaying it only to the origin's own clients
/// left the message readable on every other server, forever.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn channel_delete_crosses_the_hop() {
    let alice = TestId::new("did:plc:alicedel");
    let bob = TestId::new("did:plc:bobdel");
    let carol = TestId::new("did:plc:caroldel");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob, &carol]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#feddel").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#feddel").await.unwrap();

    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut msgid = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("#feddel", "regrettable").await.ok();
        if let Some(id) = recv_channel_msgid(&mut rxb, "regrettable", Duration::from_secs(2)).await
        {
            msgid = Some(id);
            break;
        }
    }
    let msgid = msgid.expect("bob's server received the channel message");

    ha.delete_message("#feddel", &msgid).await.unwrap();
    assert!(
        wait_rows_cleared(&srv_b.db_path, "#feddel").await,
        "the delete never reached the peer's storage — it stays readable there \
         through CHATHISTORY and every restart"
    );

    // …and it's out of the memory a joiner is replayed from, too.
    let replayed = replayed_texts(&srv_b, &carol, "carol", "#feddel").await;
    assert!(
        !replayed.iter().any(|t| t == "regrettable"),
        "the deleted message survived on the peer: {replayed:?}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// Every msgid stored under a DM key on this server, oldest first.
fn dm_msgids(db_path: &str, dm_key: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    let mut stmt = conn
        .prepare(
            "SELECT msgid FROM messages
             WHERE channel = ?1 AND msgid IS NOT NULL
             ORDER BY id",
        )
        .expect("prepare");
    let rows = stmt
        .query_map(rusqlite::params![dm_key], |r| r.get::<_, String>(0))
        .expect("query");
    rows.collect::<Result<Vec<_>, _>>().expect("collect msgids")
}

/// Rows belonging to ONE logical message — every revision shares the root.
/// Scoped this way because `warm_link` leaves its own probe messages in the
/// same thread; a thread-wide count would answer a different question.
fn rows_for_root(db_path: &str, dm_key: &str, root: &str, live_only: bool) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    let sql = if live_only {
        "SELECT COUNT(*) FROM messages
         WHERE channel = ?1 AND root_msgid = ?2 AND deleted_at IS NULL"
    } else {
        "SELECT COUNT(*) FROM messages WHERE channel = ?1 AND root_msgid = ?2"
    };
    conn.query_row(sql, rusqlite::params![dm_key, root], |r| r.get(0))
        .expect("count rows for root")
}

/// Rows under a DM key that a delete hasn't struck.
#[allow(dead_code)]
fn live_dm_row_count(db_path: &str, dm_key: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE channel = ?1 AND deleted_at IS NULL",
        rusqlite::params![dm_key],
        |r| r.get(0),
    )
    .expect("count live dm rows")
}

/// Poll until both servers have `want` rows under the DM key.
async fn wait_dm_rows(a: &TestServer, b: &TestServer, dm_key: &str, want: i64) -> bool {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        if dm_row_count(&a.db_path, dm_key) >= want && dm_row_count(&b.db_path, dm_key) >= want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// The same DM must be one message on both servers.
///
/// The relay used to send no msgid at all for a recipient who isn't local, so
/// the receiving server minted its own. Nothing that names a message across
/// servers — an edit, a delete, a reaction — can work while the two ends
/// disagree about what the message *is*.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn cross_server_dm_keeps_one_identity() {
    let alice = TestId::new("did:plc:aliceid");
    let bob = TestId::new("did:plc:bobid");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.privmsg(&bob.did, "one identity").await.unwrap();
    assert!(
        try_recv_message(&mut rxb, "one identity", EVENT_TIMEOUT)
            .await
            .is_some(),
        "bob must receive the DM"
    );

    let dm_key = freeq_server::db::canonical_dm_key(&alice.did, &bob.did);
    assert!(
        wait_dm_rows(&srv_a, &srv_b, &dm_key, 1).await,
        "both servers must persist the DM"
    );

    let sender_side = dm_msgids(&srv_a.db_path, &dm_key);
    let peer_side = dm_msgids(&srv_b.db_path, &dm_key);
    assert!(
        peer_side.iter().any(|id| sender_side.contains(id)),
        "the two servers hold this DM under different ids — sender {sender_side:?}, \
         peer {peer_side:?}. Every later edit, delete or reaction names an id \
         the other end cannot resolve."
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// A DM edit crossing the hop revises the recipient's copy.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn dm_edit_crosses_with_linkage_intact() {
    let alice = TestId::new("did:plc:alicedmed");
    let bob = TestId::new("did:plc:bobdmed");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.privmsg(&bob.did, "dm before").await.unwrap();
    let msgid = recv_channel_msgid(&mut rxb, "dm before", EVENT_TIMEOUT)
        .await
        .expect("bob received the DM with a msgid");

    ha.edit_message(&bob.did, &msgid, "dm after").await.unwrap();
    let edit_msgid = recv_channel_msgid(&mut rxb, "dm after", EVENT_TIMEOUT)
        .await
        .expect("the DM edit never crossed");
    assert_ne!(edit_msgid, msgid, "an edit travels under its own wire id");

    let dm_key = freeq_server::db::canonical_dm_key(&alice.did, &bob.did);
    // Two rows under ONE identity: the original and its revision.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline
        && rows_for_root(&srv_b.db_path, &dm_key, &msgid, false) < 2
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        rows_for_root(&srv_b.db_path, &dm_key, &msgid, false),
        2,
        "the peer must hold the original and its revision under {msgid}"
    );
    assert_eq!(
        rows_for_root(&srv_b.db_path, &dm_key, &edit_msgid, false),
        0,
        "the peer filed the edit as its own message instead of a revision \
         of {msgid}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// A DM delete has to cross too, or it only ever hides the message from the
/// author's own client.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn dm_delete_crosses_the_hop() {
    let alice = TestId::new("did:plc:alicedmdel");
    let bob = TestId::new("did:plc:bobdmdel");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.privmsg(&bob.did, "regrettable dm").await.unwrap();
    let msgid = recv_channel_msgid(&mut rxb, "regrettable dm", EVENT_TIMEOUT)
        .await
        .expect("bob received the DM with a msgid");

    let dm_key = freeq_server::db::canonical_dm_key(&alice.did, &bob.did);
    assert!(
        wait_dm_rows(&srv_a, &srv_b, &dm_key, 1).await,
        "both servers must persist the DM first"
    );

    // The rest of the thread (warm-up probes) must survive — a delete acts on
    // one message, not on a conversation.
    let thread_before = dm_msgids(&srv_b.db_path, &dm_key).len();
    ha.delete_message(&bob.did, &msgid).await.unwrap();

    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut cleared = false;
    while tokio::time::Instant::now() < deadline {
        if rows_for_root(&srv_b.db_path, &dm_key, &msgid, true) == 0 {
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        cleared,
        "the deleted DM is still readable on the recipient's server"
    );
    assert_eq!(
        dm_msgids(&srv_b.db_path, &dm_key).len(),
        thread_before,
        "the delete removed rows other than the message it named"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the sender's own other device, on the server that receives ────

/// One person signed in on both servers. When they DM a third party from
/// server A, their session on server B has to see it live.
///
/// The origin fans a DM out to the sender's own devices on its send path.
/// A server receiving that DM over S2S runs different code, and it used to
/// resolve only the addressed user — so the sender's other device, sitting on
/// the receiving server, learned nothing until its next history refetch. The
/// same gap applied to reactions, which travel as a separate S2S event.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_dm_reaches_the_senders_own_session_on_the_receiving_server() {
    let alice = TestId::new("did:plc:alicesib");
    let bob = TestId::new("did:plc:bobsib");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob — the person being written to — is on server B.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;

    // Alice is signed in on both. The device on B is what this test is about:
    // she never sends from it, and it must still see what she sends from A.
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    let (ha_b, mut rxa_b) = connect(&srv_b, &alice, "alice");
    wait_auth_and_register(&mut rxa_b).await;

    warm_link(&ha, &bob.did, &mut rxb).await;

    const TEXT: &str = "sent from my other device";
    ha.privmsg(&bob.did, TEXT).await.unwrap();

    let msgid = recv_channel_msgid(&mut rxb, TEXT, EVENT_TIMEOUT)
        .await
        .expect("bob received the DM");
    assert!(
        try_recv_message(&mut rxa_b, TEXT, EVENT_TIMEOUT)
            .await
            .is_some(),
        "alice's own session on the receiving server never saw the DM she \
         sent from the other one"
    );

    // A reaction crosses as its own event and needs the same fan-out.
    ha.raw(&format!(
        "@+react=\u{1F44D};+reply={msgid} TAGMSG {}",
        bob.did
    ))
    .await
    .unwrap();

    assert!(saw_reaction(&mut rxb).await, "bob never saw the reaction");
    assert!(
        saw_reaction(&mut rxa_b).await,
        "alice's own session on the receiving server never saw the reaction \
         she made from the other one"
    );

    ha.quit(None).await.ok();
    ha_b.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// Did a reaction TAGMSG arrive on this session within the event timeout?
async fn saw_reaction(rx: &mut mpsc::Receiver<Event>) -> bool {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(Event::TagMsg { tags, .. }) if tags.contains_key("+react") => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

// ── a peer that was away comes back and is told what it missed ────
//
// The end-to-end half of catch-up: a real link, a real outage, a real replay.
// What returns is the *log* — the events, each verified by the receiver
// against the bytes it travelled with. Derived state is deliberately not
// backfilled from a replay: showing a user messages that arrive hours late,
// interleaved into a channel they have been reading, is a product decision
// nobody has made.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_returning_peer_is_told_what_it_missed() {
    let alice = TestId::new("did:plc:alicecatchup");
    let bob = TestId::new("did:plc:bobcatchup");
    let (srv_a, mut srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#missed").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#missed").await.unwrap();

    // Prove the link works before breaking it, so a failure below is about
    // catch-up and not about the channel never having been joined.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut live = false;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("#missed", "you are here").await.ok();
        if recv_channel_msgid(&mut rxb, "you are here", Duration::from_secs(2))
            .await
            .is_some()
        {
            live = true;
            break;
        }
    }
    assert!(live, "the link must be live before the outage");

    // B goes away.
    hb.quit(None).await.ok();
    srv_b.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // A keeps going. B is down, so none of this reaches it live.
    const MISSED: &str = "sent while you were gone";
    ha.privmsg("#missed", MISSED).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B comes back on the same data and the same identity.
    srv_b.start_again().await;

    // What B now holds under that body hash can only have come from a replay.
    let want = freeq_sdk::chatsig::body_hash(MISSED);
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut caught_up = None;
    while tokio::time::Instant::now() < deadline {
        if let Some(row) = event_by_body_hash(&srv_b.db_path, &want) {
            caught_up = Some(row);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let (venue, sig_state, origin) =
        caught_up.expect("the returning peer must be told what it missed");
    assert_eq!(venue, "#missed");
    assert_eq!(
        sig_state, "valid",
        "and must have checked it for itself, not taken the replaying peer's word"
    );
    assert!(origin.is_some(), "recording which peer replayed it");

    // Replaying is idempotent: the second link-up files nothing new.
    let before = event_count(&srv_b.db_path);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        event_count(&srv_b.db_path),
        before,
        "a duplicate replay is a no-op"
    );

    ha.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// One event on a server, looked up by the body hash its document carries.
fn event_by_body_hash(db_path: &str, body_hash: &str) -> Option<(String, String, Option<String>)> {
    let conn = rusqlite::Connection::open(db_path).ok()?;
    conn.query_row(
        "SELECT venue, sig_state, origin FROM events WHERE body_hash = ?1",
        rusqlite::params![body_hash],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

fn event_count(db_path: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0)
}

// ── attachments across a federation link ─────────────────────────
//
// The relay carries vendor-prefixed client tags and drops everything else, so
// what an SDK names its attachment fields with decides whether a peer sees an
// attachment at all. This SDK wrote bare names, which meant its media and its
// link previews rendered for a reader on the same server and reached nobody
// on another one.

/// Wait for a message whose body matches, and hand back its tags.
async fn recv_tags(
    rx: &mut mpsc::Receiver<Event>,
    text: &str,
    dur: Duration,
) -> Option<std::collections::HashMap<String, String>> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(Event::Message { text: t, tags, .. }) if t == text => return Some(tags),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn an_attachment_reaches_a_reader_on_a_peer_server() {
    let alice = TestId::new("did:plc:aliceatt");
    let bob = TestId::new("did:plc:bobatt");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    hb.join("#attach").await.ok();
    ha.join("#attach").await.ok();

    let media = freeq_sdk::media::MediaAttachment {
        content_type: "image/png".to_string(),
        url: "https://cdn.example/cat.png".to_string(),
        alt: Some("a cat".to_string()),
        width: Some(640),
        height: Some(480),
        blurhash: None,
        size: Some(1024),
        filename: None,
    };
    let preview = freeq_sdk::media::LinkPreview {
        url: "https://example.com/post".to_string(),
        title: Some("A post".to_string()),
        description: Some("about things".to_string()),
        thumb_url: Some("https://cdn.example/og.png".to_string()),
    };

    // Resend until the link settles, as the other tests here do.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut seen_media = None;
    while tokio::time::Instant::now() < deadline {
        ha.send_media("#attach", &media).await.ok();
        if let Some(tags) =
            recv_tags(&mut rxb, &media.fallback_text(), Duration::from_secs(2)).await
        {
            seen_media = Some(tags);
            break;
        }
    }
    let tags = seen_media.expect("bob received the media message across servers");
    let parsed = freeq_sdk::media::MediaAttachment::from_tags(&tags).unwrap_or_else(|| {
        panic!("a reader on the peer server sees no attachment at all: {tags:?}")
    });
    assert_eq!(parsed.url, media.url, "{tags:?}");
    assert_eq!(parsed.content_type, "image/png", "{tags:?}");
    assert_eq!(parsed.alt.as_deref(), Some("a cat"), "{tags:?}");
    assert!(parsed.is_image(), "{tags:?}");

    let fallback = "🔗 A post — about things (https://example.com/post)";
    let mut seen_preview = None;
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        ha.send_link_preview("#attach", &preview).await.ok();
        if let Some(tags) = recv_tags(&mut rxb, fallback, Duration::from_secs(2)).await {
            seen_preview = Some(tags);
            break;
        }
    }
    let tags = seen_preview.expect("bob received the link preview across servers");
    let parsed = freeq_sdk::media::LinkPreview::from_tags(&tags)
        .unwrap_or_else(|| panic!("a reader on the peer server sees no preview: {tags:?}"));
    assert_eq!(parsed.url, preview.url, "{tags:?}");
    assert_eq!(parsed.title.as_deref(), Some("A post"), "{tags:?}");
    assert_eq!(parsed.description.as_deref(), Some("about things"), "{tags:?}");
    assert_eq!(
        parsed.thumb_url.as_deref(),
        Some("https://cdn.example/og.png"),
        "{tags:?}"
    );
    // And it is a preview, not an attachment wearing one's tags.
    assert!(
        freeq_sdk::media::MediaAttachment::from_tags(&tags).is_none(),
        "{tags:?}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a federated multiline edit is stored as the bytes its signature covers ──
//
// The S2S hop escapes a multiline body to literal `\n` for the wire, and the
// receiver verifies the signature over the UN-escaped body — then must file
// that same body. Filing the escaped wire form instead leaves the two servers
// holding different bytes for one message, with every signature still
// passing: verifiers un-escape before checking, so nothing fails loudly.
// REST, search, and the FTS index read the stored form raw.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn federated_multiline_edit_stores_the_verified_body() {
    let alice = TestId::new("did:plc:alicemledit");
    let bob = TestId::new("did:plc:bobmledit");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#mledit").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#mledit").await.unwrap();

    let original = "first line\nsecond line\nthird line";
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut msgid = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("#mledit", original).await.ok();
        if let Some(id) = recv_channel_msgid(&mut rxb, original, Duration::from_secs(2)).await {
            msgid = Some(id);
            break;
        }
    }
    let msgid = msgid.expect("bob's server received the multiline message");

    let edited = "first line\nsecond line\nthird line, revised";
    ha.edit_message("#mledit", &msgid, edited).await.unwrap();
    recv_channel_msgid(&mut rxb, edited, EVENT_TIMEOUT)
        .await
        .expect("bob's client received the edit assembled");

    // The receiver's stored bodies, read back through its own REST search —
    // the surface REST consumers actually see (the store is encrypted at
    // rest, so the server's own read path is the honest witness).
    let rows: Vec<serde_json::Value> = reqwest::get(format!(
        "http://{}/api/v1/search?channel=%23mledit&q=line",
        srv_b.web_addr
    ))
    .await
    .expect("search reachable")
    .json::<serde_json::Value>()
    .await
    .map(|v| match v {
        serde_json::Value::Array(a) => a,
        other => other["results"].as_array().cloned().unwrap_or_default(),
    })
    .expect("search answered");
    let text_of = |pred: &dyn Fn(&serde_json::Value) -> bool| -> Option<String> {
        rows.iter()
            .find(|r| pred(r))
            .and_then(|r| r["text"].as_str().map(String::from))
    };
    // Root-identity semantics: the row under the original msgid serves the
    // CURRENT text — the edit — so one assertion covers filing and unescaping.
    let stored = text_of(&|r| r["msgid"].as_str() == Some(msgid.as_str()));
    assert_eq!(
        stored.as_deref(),
        Some(edited),
        "the receiver must file the body its verifier checked, not the escaped wire form"
    );
    assert!(
        rows.iter()
            .all(|r| !r["text"].as_str().unwrap_or_default().contains("\\n")),
        "no stored body may hold the escaped wire form: {rows:?}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}
