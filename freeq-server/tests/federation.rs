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
    /// Where this server's stderr (its tracing output) is captured, so a test
    /// can assert on what the server itself concluded — e.g. the observe-only
    /// verdict it logs for a relayed task event.
    log_path: String,
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
        let log = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)
            .expect("reopen server log");
        let log_err = log.try_clone().expect("clone server log handle");
        self.child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
            .args(&self.args)
            .env("RUST_LOG", HARNESS_RUST_LOG)
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err))
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

/// Quiet by default, plus the observe-only task-event verdict lines, which
/// one test reads back out of the server's captured log.
const HARNESS_RUST_LOG: &str = "freeq_server=warn,freeq_server::act_relay=info";

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
///
/// `extra` is appended verbatim, for a test that needs one side started with a
/// setting the other does not have.
fn spawn_server(
    plan: ServerPlan,
    peer: &PeerRef,
    resolver_entries: &str,
    extra: &[&str],
) -> TestServer {
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
    .chain(extra.iter())
    .map(|s| s.to_string())
    .collect();

    let log_path = plan
        .dir
        .path()
        .join("server.log")
        .to_str()
        .unwrap()
        .to_string();
    let log = std::fs::File::create(&log_path).expect("create server log");
    let log_err = log.try_clone().expect("clone server log handle");
    let child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
        .args(&args)
        .env("RUST_LOG", HARNESS_RUST_LOG)
        // Tracing writes to stdout; panics land on stderr. Both belong in
        // the capture.
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err))
        .spawn()
        .expect("spawn freeq-server");

    TestServer {
        _dir: plan.dir,
        child,
        irc_addr,
        web_addr,
        db_path,
        log_path,
        args,
        serial: None,
    }
}

/// A server's captured tracing output, ANSI stripped so assertions can match
/// the plain field text.
fn server_log(server: &TestServer) -> String {
    let raw = std::fs::read_to_string(&server.log_path).unwrap_or_default();
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip an escape sequence through its final letter.
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Boot two mutually-peered servers, both resolving every `ids` DID offline.
/// Blocks until both IRC ports accept connections.
async fn spawn_pair(ids: &[&TestId]) -> (TestServer, TestServer) {
    // A fresh iroh identity per pair. Every pair used to boot as the same two
    // node IDs, so two pairs alive at once — the previous test's servers still
    // exiting, or anything that runs this file without the serial lock — were, to
    // iroh, the same two nodes reachable at two addresses. The lock makes that
    // rare rather than impossible; distinct identities make it harmless.
    static NEXT_SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let n = NEXT_SEED.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    spawn_pair_with_seeds(ids, n, n.wrapping_add(1)).await
}

/// The same, with both iroh identities chosen by the caller.
///
/// Which of two simultaneous links survives is decided by comparing the two
/// endpoint IDs, and an endpoint ID is derived from the seed — so the seeds a
/// pair boots with decide which server keeps its outgoing link and which keeps
/// its incoming one. Seeds handed out in sequence make that orientation a
/// function of how many pairs booted earlier in the run, which is no basis for
/// a test that cares. A test that cares picks its own.
async fn spawn_pair_with_seeds(
    ids: &[&TestId],
    seed_a: u8,
    seed_b: u8,
) -> (TestServer, TestServer) {
    spawn_pair_with_seeds_and_args(ids, seed_a, seed_b, &[], &[]).await
}

/// The same again, with extra argv for each server — a setting one side of the
/// pair needs and the other does not.
async fn spawn_pair_with_seeds_and_args(
    ids: &[&TestId],
    seed_a: u8,
    seed_b: u8,
    extra_a: &[&str],
    extra_b: &[&str],
) -> (TestServer, TestServer) {
    // A failed test poisons the lock; the next test's servers are unaffected,
    // so take it anyway.
    let serial = ONE_TEST_AT_A_TIME
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a_plan = plan_server(seed_a);
    let b_plan = plan_server(seed_b);
    let resolver: String = ids
        .iter()
        .map(|i| i.resolver_entry())
        .collect::<Vec<_>>()
        .join(",");

    // Capture each identity before moving the plans into their servers, so the
    // two can cross-reference for peering.
    let a_ref = PeerRef::of(&a_plan);
    let b_ref = PeerRef::of(&b_plan);
    let mut a = spawn_server(a_plan, &b_ref, &resolver, extra_a);
    let b = spawn_server(b_plan, &a_ref, &resolver, extra_b);
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

/// A client with no identity — the other end of a thread that can never have
/// a signed venue.
fn connect_guest(server: &TestServer, nick: &str) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: server.irc_addr.clone(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "federation test".to_string(),
        ..Default::default()
    };
    client::connect(config, None)
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

/// The sender's *own* other device, signed in on the receiving server.
///
/// The origin fans a DM out to the sender's other sessions on its send path;
/// that code never runs on the far side of a link, so the far side unions the
/// addressed user's sessions with the sessions of whoever the event names.
/// That union is delivery into the named identity's own client, so it happens
/// only on a signature this server checked — and this is the honest case that
/// must keep working: alice really did send it, and her client really did
/// sign it.
#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_signed_dm_reaches_the_senders_own_device_on_the_far_server() {
    let alice = TestId::new("did:plc:alicefanout");
    let bob = TestId::new("did:plc:bobfanout");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    // Bob on B; alice on A, and also signed in on B — the device that only
    // the far side's fan-out can reach.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha2, mut rxa2) = connect(&srv_b, &alice, "alice2");
    wait_auth_and_register(&mut rxa2).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // Warming the link also gets alice's signing key onto B, which is what
    // makes the signature checkable there rather than merely present.
    warm_link(&ha, &bob.did, &mut rxb).await;

    // Resend until her own far-side device sees it: the key lookup runs off
    // the delivery path, so the first send can land before the key does.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut reached = false;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg(&bob.did, "sent from my other device").await.ok();
        if try_recv_message(
            &mut rxa2,
            "sent from my other device",
            Duration::from_secs(2),
        )
        .await
        .is_some()
        {
            reached = true;
            break;
        }
    }
    assert!(
        reached,
        "a signed cross-server DM never reached the sender's own device on the \
         receiving server"
    );

    ha.quit(None).await.ok();
    ha2.quit(None).await.ok();
    hb.quit(None).await.ok();
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

// ── a DM with a guest on the peer keeps its mutations ────────────
//
// The signature requirement asks for proof only where proof could exist. A
// guest has no DID, so a DM thread with one has no venue: neither end can
// build the document, so no signature can ever accompany a delete or an edit
// there. The rule exempts that case locally; a relayed one arrives
// account-stamped from the origin's authenticated sender and venue-less all
// the same, and must be exempt on the receiving side too — otherwise the
// delete applies where it was typed and nowhere else, and the two servers
// hold different history for good.

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_dm_with_a_guest_on_the_peer_keeps_its_deletes() {
    let alice = TestId::new("did:plc:aliceguestdm");
    let (srv_a, srv_b) = spawn_pair(&[&alice]).await;

    // A guest on B, an identity on A. Nothing about this thread is signable.
    let (hg, mut rxg) = connect_guest(&srv_b, "gbob");
    wait_event(
        &mut rxg,
        |e| matches!(e, Event::Registered { .. }),
        "guest registered",
    )
    .await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;

    // Resend until it lands, which also warms the link.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut delivered = None;
    while tokio::time::Instant::now() < deadline {
        ha.privmsg("gbob", "across to a guest").await.ok();
        delivered = msgid_of_message(&mut rxg, "across to a guest", Duration::from_secs(2)).await;
        if delivered.is_some() {
            break;
        }
    }
    let msgid = delivered.expect("the guest received the cross-server DM");

    // Alice deletes it. Neither server can check a signature that cannot
    // exist, and both must apply the delete rather than demand one.
    let mut del_tags = std::collections::HashMap::new();
    del_tags.insert("+draft/delete".to_string(), msgid.clone());
    ha.send_tagmsg("gbob", del_tags).await.unwrap();

    let seen = wait_for_tagmsg(&mut rxg, "+draft/delete", EVENT_TIMEOUT).await;
    assert!(
        seen,
        "a delete in a venue-less DM must cross the hop and apply at the far end"
    );

    ha.quit(None).await.ok();
    hg.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// Wait for a message with `text`, returning its msgid.
async fn msgid_of_message(
    rx: &mut mpsc::Receiver<Event>,
    text: &str,
    within: Duration,
) -> Option<String> {
    timeout(within, async {
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
    .unwrap_or(None)
}

/// Whether a TAGMSG carrying `tag` arrives within the window.
async fn wait_for_tagmsg(rx: &mut mpsc::Receiver<Event>, tag: &str, within: Duration) -> bool {
    timeout(within, async {
        loop {
            match rx.recv().await {
                Some(Event::TagMsg { tags, .. }) if tags.contains_key(tag) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
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

/// A raw IRC connection, so a test can negotiate a capability the SDK client
/// does not know about. The servers here are subprocesses, so blocking reads
/// are safe inside these tests.
struct Raw {
    reader: std::io::BufReader<std::net::TcpStream>,
    writer: std::net::TcpStream,
}

impl Raw {
    /// A guest holding exactly `caps`. Guests may hold `freeq.at/act` — the
    /// capability says what a client can render, not who it is.
    fn guest(addr: &str, nick: &str, caps: &str) -> Self {
        let sock = std::net::TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let writer = sock.try_clone().unwrap();
        let mut c = Raw {
            reader: std::io::BufReader::new(sock),
            writer,
        };
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :raw"));
        c.tx(&format!("CAP REQ :{caps}"));
        c.wait(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c.wait(|l| l.split_whitespace().nth(1) == Some("001"), "001");
        c
    }

    fn tx(&mut self, line: &str) {
        use std::io::Write;
        writeln!(self.writer, "{line}\r").unwrap();
        self.writer.flush().ok();
    }

    fn wait(&mut self, pred: impl Fn(&str) -> bool, what: &str) -> String {
        use std::io::BufRead;
        let mut buf = String::new();
        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => panic!("EOF waiting for {what}"),
                Ok(_) => {
                    let l = buf.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x").to_string();
                        self.tx(&format!("PONG {t}"));
                        continue;
                    }
                    if pred(l) {
                        return l.to_string();
                    }
                }
                Err(e) => panic!("{what}: {e}"),
            }
        }
    }

    fn join(&mut self, channel: &str) {
        self.tx(&format!("JOIN {channel}"));
        self.wait(
            |l| l.split_whitespace().nth(1) == Some("366"),
            "end of names",
        );
    }

    /// Up to `ms` for a matching line; `None` if it never comes.
    fn maybe(&mut self, pred: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        use std::io::BufRead;
        self.writer
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
        let sock = self.reader.get_ref();
        sock.set_read_timeout(Some(Duration::from_millis(ms))).ok();
        let mut buf = String::new();
        let found = loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => break None,
                Ok(_) => {
                    let l = buf.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x").to_string();
                        self.tx(&format!("PONG {t}"));
                        continue;
                    }
                    if pred(l) {
                        break Some(l.to_string());
                    }
                }
                Err(_) => break None,
            }
        };
        let sock = self.reader.get_ref();
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        found
    }
}

// ── an accepted task message crosses the hop with its signature ─────
//
// A task message is a TAGMSG, so it crosses in the raw `Tagmsg` tag map with
// nothing stripped — the signature and the signer-minted id included. Both
// have to survive: the act canonical is rebuilt from the act tags, the venue
// and that id, so a peer that receives the message without the id cannot
// check the signature at all, and one that receives it without the signature
// has an unattributable task event.
//
// Phase 5 is what makes the far side *act* on one. This pins that the bytes
// it will need are already crossing.

// Multi-threaded on purpose: the raw observers below block their thread on
// socket reads, and the SDK handle's writer task has to keep running while
// they do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn act_tagmsg_crosses_the_hop_with_its_signature() {
    let alice = TestId::new("did:plc:aliceact");
    let bob = TestId::new("did:plc:bobact");
    let (srv_a, srv_b) = spawn_pair(&[&alice, &bob]).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#fact").await.unwrap();

    // The receiving side gates task messages on the capability, so the
    // observer that must see one asks for it; the SDK client does not.
    let mut watcher = Raw::guest(
        &srv_b.irc_addr,
        "watcher",
        "message-tags server-time freeq.at/act",
    );
    watcher.join("#fact");
    // …and one that did not ask, to prove the gate rather than assume it.
    let mut deaf = Raw::guest(&srv_b.irc_addr, "deaf", "message-tags server-time");
    deaf.join("#fact");

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#fact").await.unwrap();

    // A signing key of the test's own, so it can build the act canonical the
    // way a task-sending client would. MSGSIG persists the key by (DID, kid),
    // so it is findable however the session map happens to be ordered.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let pubkey = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes())
    };
    ha.raw(&format!("MSGSIG {pubkey}")).await.ok();

    /// Sign and send one fresh handoff offer into #fact; returns (sig, id).
    async fn send_signed_offer(
        ha: &client::ClientHandle,
        from_did: &str,
        venue: &str,
        signing: &ed25519_dalek::SigningKey,
    ) -> (String, String) {
        let id = freeq_sdk::chatsig::new_event_id();
        let act_tags: Vec<(&str, &str)> = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", from_did),
            ("+freeq.at/act-title", "cross-the-hop"),
        ];
        let sig = freeq_sdk::act::sign_act(act_tags.clone(), venue, &id, signing)
            .expect("act tags present");
        let wire: Vec<String> = act_tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .chain([
                format!("{}={id}", freeq_sdk::chatsig::EVENT_ID_TAG),
                format!("+freeq.at/sig={sig}"),
            ])
            .collect();
        ha.raw(&format!("@{} TAGMSG #fact", wire.join(";")))
            .await
            .ok();
        (sig, id)
    }

    let venue = freeq_sdk::chatsig::channel_venue("#fact");
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut crossed: Option<(String, String)> = None;
    while tokio::time::Instant::now() < deadline {
        let (sig, id) = send_signed_offer(&ha, &alice.did, &venue, &signing).await;

        if let Some(line) = watcher.maybe(|l| l.contains("+freeq.at/act="), 2000) {
            assert!(
                line.contains(&format!("+freeq.at/sig={sig}")),
                "the signature must cross byte-identical: {line}"
            );
            assert!(
                line.contains(&format!("{}={id}", freeq_sdk::chatsig::EVENT_ID_TAG)),
                "the id the signature covers must cross too, or nobody can \
                 rebuild the document: {line}"
            );
            crossed = Some((sig.clone(), id.clone()));
            break;
        }
    }
    assert!(
        crossed.is_some(),
        "an accepted task message must reach a capability-holding peer client"
    );

    // The same message, on the same server, to a client that did not ask:
    // nothing. Relayed task messages are gated exactly as local ones are.
    assert!(
        deaf.maybe(|l| l.contains("+freeq.at/act"), 800).is_none(),
        "a relayed task message must not reach a connection without the capability"
    );

    // ── the receiving server's own verdict ──────────────────────────
    //
    // Server B checks every relayed task event and logs a verdict, observe-
    // only. The first arrivals can honestly be unverifiable — B holds no key
    // for this signer until its fetch-on-miss (triggered by exactly that
    // verdict) fills the store off the delivery path — so keep sending fresh
    // signed events until one earns B's own VALID. Reaching it proves the
    // whole receive-side chain against a real hop: key fetched from the
    // origin, venue and id rebuilt, signature checked by the receiver itself.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut valid_seen = false;
    while tokio::time::Instant::now() < deadline {
        let log = server_log(&srv_b);
        if log
            .lines()
            .any(|l| l.contains("verdict=valid") && l.contains("target=#fact"))
        {
            valid_seen = true;
            break;
        }
        // Another signed event, in case every earlier one arrived before the
        // key did.
        send_signed_offer(&ha, &alice.did, &venue, &signing).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        valid_seen,
        "the receiving server must reach its own VALID verdict for a relayed \
         task event; its log says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── and a valid verdict is what puts it on file ─────────────────
    //
    // The verdict decides: valid means stored, under the id the signer minted
    // rather than one B made up, so B can answer for a task it did not host
    // and a later replay recognises the event instead of reading it as a
    // second claim. B holds A's key by now — that is what the loop above
    // waited for — so one more offer is judged valid on arrival.
    let (_, stored_id) = send_signed_offer(&ha, &alice.did, &venue, &signing).await;
    let url = format!("http://{}/api/v1/actions/{stored_id}", srv_b.web_addr);
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut stored = serde_json::Value::Null;
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            stored = body;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        stored["act_id"], stored_id,
        "the receiving server must hold the crossed task event under the \
         signer's own id: {stored}"
    );
    assert_eq!(
        stored["task"]["offerer"], alice.did,
        "filed against the identity that signed it: {stored}"
    );
    assert_eq!(stored["task"]["venue"], "#fact", "{stored}");
    assert_ne!(
        stored["task"]["origin"], "",
        "and stamped with the server that owns the task, which is not this \
         one: {stored}"
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
    assert_ne!(
        edit_msgid, root,
        "an edit is its own event, with its own id"
    );
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
async fn replayed_texts(
    server: &TestServer,
    id: &TestId,
    nick: &str,
    channel: &str,
) -> Vec<String> {
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

    // A reaction crosses as its own event and needs the same fan-out. Sent
    // through the client rather than as a raw line, because a reaction names
    // the message it acts on and therefore has to carry the reactor's
    // signature — a raw line skips the one place that signs it.
    ha.react(&bob.did, "\u{1F44D}", &msgid).await.unwrap();

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
    // Pinned identities, because the outage this test stages is only a real
    // test of catch-up if the link comes back — and whether it does depends on
    // which server keeps its outgoing link, which is decided by comparing
    // endpoint IDs. Left to sequence-allocated seeds, that comparison changes
    // with the test's position in the run, so the same code passed or failed
    // depending on how many pairs booted before it. These two put the server
    // that stays up on the harder side of it.
    const SEED_A: u8 = 202;
    const SEED_B: u8 = 203;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_a < id_b,
        "the server that stays up keeps its outgoing link"
    );

    let alice = TestId::new("did:plc:alicecatchup");
    let bob = TestId::new("did:plc:bobcatchup");
    let (srv_a, mut srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

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

// ── a peer that comes back is linked again ───────────────────────
//
// Two servers that list each other both dial, so they end up holding two
// connections and a total order on their endpoint IDs decides which one they
// keep: the lower ID keeps its outgoing, the higher keeps its incoming. That
// rule is about two links that both ends can see. A server whose peer was
// killed can see neither — what it holds is a connection to a process that no
// longer exists, and nothing tells it so until the idle timeout does.
//
// Seeded so the server that stays up is the lower ID, which is the case that
// has to dial to recover: its half of the surviving link is the outgoing one.

/// How many federation peers a server has completed a handshake with, read off
/// its Prometheus endpoint. A server counts none until a link comes up, so
/// after a restart this is the plainest "am I linked?" there is — no client, no
/// channel, no message.
async fn s2s_peer_count(web_addr: &str) -> u32 {
    let url = format!("http://{web_addr}/metrics");
    let Ok(resp) = reqwest::get(&url).await else {
        return 0;
    };
    let body = resp.text().await.unwrap_or_default();
    body.lines()
        .find_map(|l| l.strip_prefix("freeq_s2s_peers "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_peer_that_comes_back_is_linked_again() {
    // The seeds decide the endpoint IDs and the endpoint IDs decide who keeps
    // what, so assert the orientation rather than trusting seeds to keep
    // deriving it.
    const SEED_A: u8 = 200;
    const SEED_B: u8 = 201;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_a < id_b,
        "this test is about the server that keeps its outgoing link being the one left holding a dead one"
    );

    let alice = TestId::new("did:plc:alicerelink");
    let bob = TestId::new("did:plc:bobrelink");
    let (srv_a, mut srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;

    // B goes away without a closing handshake — what a crash, a kill and a
    // machine going down all look like from the other end.
    hb.quit(None).await.ok();
    srv_b.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;
    srv_b.start_again().await;

    // A server counts a peer only once a link has come up and been handshaken,
    // so on a server that just restarted this goes above zero exactly when it
    // has been linked again.
    let back = tokio::time::Instant::now();
    let mut linked = None;
    while back.elapsed() < S2S_SETTLE {
        if s2s_peer_count(&srv_b.web_addr).await > 0 {
            linked = Some(back.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        linked.is_some(),
        "the peer that came back was never linked again within {S2S_SETTLE:?} — \
         the server that stayed up is holding a connection to the process that died"
    );

    ha.quit(None).await.ok();
    drop((srv_a, srv_b));
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
    assert_eq!(
        parsed.description.as_deref(),
        Some("about things"),
        "{tags:?}"
    );
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

// ── a server that was away heals its task view, not just its log ──
//
// The end-to-end half of feeding caught-up task events through the same
// judgment live receiving uses. A server that misses a task's events while it
// is down has to come back answering for that task the way a server that
// stayed linked answers — same state, same origin, same events on file. Filing
// the log row and stopping there left it holding every event of a task while
// its REST view said there was no such task.
//
// Two servers rather than three: the harness peers a *pair*, and a third
// server would need new peering plumbing and, worse, a signing key it has no
// link to fetch from — a caught-up event whose signer's key is unknown is
// skipped by design. The server that goes away has already been handed the
// signer's key by the live path, so a restart stages the real thing without
// any of that.
//
// The comparison is against the twin task this same server received live,
// which is the honest reference: server A minted both tasks, so A referees
// them and B does not — B's view of a task of A's is frozen at the opener
// whether it arrived live or by replay, and that is precisely what must match.

/// One task as a server answers for it.
async fn act_task(web_addr: &str, act_id: &str) -> Option<serde_json::Value> {
    let url = format!("http://{web_addr}/api/v1/actions/{act_id}");
    let resp = reqwest::get(&url).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.json::<serde_json::Value>().await.ok()?;
    body["task"].is_object().then_some(body)
}

/// Poll until a server answers for `act_id`, or give up.
async fn await_act_task(web_addr: &str, act_id: &str) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        if let Some(body) = act_task(web_addr, act_id).await {
            return Some(body);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_server_that_was_away_heals_its_task_view() {
    // The server that stays up must keep its outgoing link, which is decided
    // by comparing endpoint IDs — so the seeds are pinned and the orientation
    // asserted rather than left to the order tests happen to run in.
    const SEED_A: u8 = 204;
    const SEED_B: u8 = 205;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_a < id_b,
        "the server that stays up keeps its outgoing link"
    );

    let alice = TestId::new("did:plc:aliceheal");
    let bob = TestId::new("did:plc:bobheal");
    let (srv_a, mut srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#heal").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#heal").await.unwrap();

    // A signing key of the test's own, so it builds the act canonical the way
    // a task-sending client does.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
    let pubkey = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes())
    };
    ha.raw(&format!("MSGSIG {pubkey}")).await.ok();
    let venue = freeq_sdk::chatsig::channel_venue("#heal");

    /// Sign and send one act TAGMSG into #heal; returns its event id.
    async fn send_act(
        ha: &client::ClientHandle,
        venue: &str,
        signing: &ed25519_dalek::SigningKey,
        act_tags: &[(&str, &str)],
    ) -> String {
        let id = freeq_sdk::chatsig::new_event_id();
        let sig = freeq_sdk::act::sign_act(act_tags.iter().copied(), venue, &id, signing)
            .expect("act tags present");
        let wire: Vec<String> = act_tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .chain([
                format!("{}={id}", freeq_sdk::chatsig::EVENT_ID_TAG),
                format!("+freeq.at/sig={sig}"),
            ])
            .collect();
        ha.raw(&format!("@{} TAGMSG #heal", wire.join(";")))
            .await
            .ok();
        id
    }

    /// An open offer, then a claim on it — one task's whole life here.
    async fn run_lifecycle(
        ha: &client::ClientHandle,
        venue: &str,
        signing: &ed25519_dalek::SigningKey,
        from: &str,
        title: &str,
    ) -> String {
        let act_id = send_act(
            ha,
            venue,
            signing,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", from),
                ("+freeq.at/act-title", title),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        send_act(
            ha,
            venue,
            signing,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "claim"),
                ("+freeq.at/from", from),
                ("+freeq.at/act-id", act_id.as_str()),
            ],
        )
        .await;
        act_id
    }

    // ── the reference: a task B takes live ──────────────────────────
    //
    // B holds no key for alice until its fetch-on-miss fills the store off the
    // delivery path, so the first offers can honestly be unverifiable. Keep
    // running lifecycles until one lands on B; that one is the reference.
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut live_id = String::new();
    while tokio::time::Instant::now() < deadline {
        let id = run_lifecycle(&ha, &venue, &signing, &alice.did, "taken-live").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_task(&srv_b.web_addr, &id).await.is_some() {
            live_id = id;
            break;
        }
    }
    assert!(
        !live_id.is_empty(),
        "the link must carry task events before the outage, or the outage \
         proves nothing; B's log says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // Settled before it is used as the reference: B follows the home's receipt
    // on the claim, and comparing a settled view against one still in flight
    // would be comparing two different moments.
    await_assignee(&srv_b.web_addr, &live_id, S2S_SETTLE).await;
    let live_view = act_task(&srv_b.web_addr, &live_id)
        .await
        .expect("B answers for the task it took live");

    // ── B goes away, and a whole task happens without it ────────────
    hb.quit(None).await.ok();
    srv_b.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;

    let healed_id = run_lifecycle(&ha, &venue, &signing, &alice.did, "healed-later").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        act_task(&srv_a.web_addr, &healed_id).await.is_some(),
        "the server that stayed up holds the task it minted"
    );

    // ── B comes back on the same data and the same identity ─────────
    srv_b.start_again().await;

    let mut healed = await_act_task(&srv_b.web_addr, &healed_id)
        .await
        .unwrap_or_else(|| {
            panic!(
                "a server that healed a task must answer for it, not just hold \
                 its log; B's log says: {}",
                server_log(&srv_b)
                    .lines()
                    .filter(|l| l.contains("catch-up") || l.contains("catchup"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        });

    // Every event of the task reached the log, in mint order or the follow-up
    // would have named a task nothing had opened — the opener, the claim, and
    // the home's own receipt for the claim.
    //
    // The receipt is signed under the home's `did:web:` identity, whose key
    // this server may not hold when the batch lands. It is held rather than
    // skipped, and the key's arrival applies it — which is why this is a poll
    // and not a single read.
    let healed_events = |body: &serde_json::Value| -> Vec<String> {
        body["events"]
            .as_array()
            .map(|events| {
                events
                    .iter()
                    .filter_map(|e| {
                        let doc: serde_json::Value =
                            serde_json::from_str(e["canonical"].as_str()?).ok()?;
                        Some(doc["act-verb"].as_str()?.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        if healed_events(&healed) == ["offer", "claim", "confirm"] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        healed = act_body(&srv_b.web_addr, &healed_id)
            .await
            .unwrap_or(healed);
    }
    assert_eq!(
        healed_events(&healed),
        ["offer", "claim", "confirm"],
        "the opener, the claim and the home's receipt for it are all on file, in \
         that order: {healed}"
    );

    // The origin names the server that MINTED the task — the one that
    // referees it — and not merely the peer that replayed it. Here they are
    // the same server, and the field has to say so.
    assert_eq!(
        healed["task"]["origin"].as_str(),
        Some(id_a.as_str()),
        "the healed task must name the server that minted it: {healed}"
    );

    // And the healed view is the view staying connected would have produced:
    // same kind, same venue, same offerer, same state, same assignee, same
    // origin. State and assignee included — B did not decide either of them,
    // it followed the home's receipt, and a receipt replays like any other
    // event.
    for field in ["kind", "venue", "offerer", "state", "origin", "assignee"] {
        assert_eq!(
            healed["task"][field], live_view["task"][field],
            "healing must land where staying connected lands ({field}): \
             healed={healed} live={live_view}"
        );
    }

    // And where the home stands is where the healed server stands. Nothing
    // asked A about this task again: what B replayed was the record, receipt
    // included.
    let on_a = act_task(&srv_a.web_addr, &healed_id)
        .await
        .expect("A answers for its own task");
    assert_eq!(on_a["task"]["state"].as_str(), Some("assigned"));
    assert_eq!(
        healed["task"]["state"].as_str(),
        Some("assigned"),
        "a healed server reaches the state its home confirmed the task into: {healed}"
    );

    ha.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a task event whose key cannot be fetched yet ──────────────────────────
//
// A signature this server cannot check is not a verdict about the sender. A
// key server that is down, or a key that has not been published yet, is a
// fact about this server's reach — so the event waits instead of being
// refused, and nothing about it is shown or filed while it waits. Then the
// key becomes fetchable and the wait ends by itself: the server asks again on
// its own backoff, judges the event, applies it and delivers it, without its
// sender ever saying anything more.
//
// The far server's key source is pointed at an address nothing answers on,
// which is what makes the wait real; the stand-in key server is started only
// when the test wants the key to become fetchable.

/// A stand-in for a peer's key server, serving one key to anything that asks.
///
/// Started late on purpose: until it is, the address in the far server's
/// `--s2s-peer-api` refuses connections, and every signature by this signer is
/// honestly uncheckable there.
async fn serve_signing_key(port: u16, pubkey_b64: String) -> tokio::task::JoinHandle<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind the stand-in key server");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = format!(
                r#"{{"algorithm":"ed25519","public_key":"{pubkey_b64}","encoding":"base64url"}}"#
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            // The request is read and discarded: the answer does not depend on
            // it, and the key id in it is checked by the caller against the
            // key itself.
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    })
}

/// Sign and send one act TAGMSG into `channel`; returns the event id it minted.
async fn send_act_as(
    handle: &client::ClientHandle,
    channel: &str,
    signing: &ed25519_dalek::SigningKey,
    act_tags: &[(&str, &str)],
) -> String {
    let venue = freeq_sdk::chatsig::channel_venue(channel);
    let id = freeq_sdk::chatsig::new_event_id();
    let sig = freeq_sdk::act::sign_act(act_tags.iter().copied(), &venue, &id, signing)
        .expect("act tags present");
    let wire: Vec<String> = act_tags
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .chain([
            format!("{}={id}", freeq_sdk::chatsig::EVENT_ID_TAG),
            format!("+freeq.at/sig={sig}"),
        ])
        .collect();
    handle
        .raw(&format!("@{} TAGMSG {channel}", wire.join(";")))
        .await
        .ok();
    id
}

/// Register a session signing key the way a task-sending client does, so the
/// other server can fetch it when a signature names it.
async fn register_key(handle: &client::ClientHandle, signing: &ed25519_dalek::SigningKey) {
    use base64::Engine;
    let pubkey =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    handle.raw(&format!("MSGSIG {pubkey}")).await.ok();
}

/// Ask for the task capability, after registering, and wait for the ACK.
///
/// Task messages reach only the connections that negotiated `freeq.at/act` —
/// everyone else in the room sees the companion prose and none of the machine
/// half. The Rust SDK does not ask for it (no Rust client consumes task events
/// yet), so a test that watches for a delivered task event asks in the raw,
/// the way a task-aware client does.
async fn request_act_cap(handle: &client::ClientHandle, rx: &mut mpsc::Receiver<Event>) {
    handle.raw("CAP REQ :freeq.at/act").await.ok();
    wait_event(
        rx,
        |e| matches!(e, Event::RawLine(l) if l.contains(" ACK ") && l.contains("freeq.at/act")),
        "the task capability ACK",
    )
    .await;
}

/// How many times a session is handed the TAGMSG carrying `event_id`.
///
/// Waits up to `within` for the first, then a further `quiet` for a second
/// that must never come — an event delivered twice is the bug, so the wait
/// after the first delivery is the assertion.
async fn tagmsg_deliveries(
    rx: &mut mpsc::Receiver<Event>,
    event_id: &str,
    within: Duration,
    quiet: Duration,
) -> usize {
    let mut seen = 0usize;
    let matches = |tags: &std::collections::HashMap<String, String>| {
        tags.get(freeq_sdk::chatsig::EVENT_ID_TAG)
            .map(String::as_str)
            == Some(event_id)
    };

    let deadline = tokio::time::Instant::now() + within;
    while seen == 0 && tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(250), rx.recv()).await {
            Ok(Some(Event::TagMsg { tags, .. })) if matches(&tags) => seen += 1,
            Ok(Some(_)) => continue,
            Ok(None) => return seen,
            Err(_) => continue,
        }
    }
    if seen == 0 {
        return 0;
    }
    let quiet_until = tokio::time::Instant::now() + quiet;
    while tokio::time::Instant::now() < quiet_until {
        match timeout(Duration::from_millis(250), rx.recv()).await {
            Ok(Some(Event::TagMsg { tags, .. })) if matches(&tags) => seen += 1,
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    seen
}

/// How many rows a server's event log holds under one event id.
fn event_rows(db_path: &str, event_id: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_id = ?1",
        rusqlite::params![event_id],
        |r| r.get(0),
    )
    .expect("count event rows")
}

/// Every verdict this server logged about one relayed task event, in order.
fn verdicts_for(server: &TestServer, event_id: &str) -> Vec<String> {
    server_log(server)
        .lines()
        .filter(|l| l.contains(event_id) && l.contains("verdict="))
        .map(|l| {
            l.split("verdict=")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// Poll a server's answer for `act_id` for as long as `within`.
async fn await_act_task_within(
    web_addr: &str,
    act_id: &str,
    within: Duration,
) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if let Some(body) = act_task(web_addr, act_id).await {
            return Some(body);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_task_event_waits_for_a_key_it_cannot_fetch_and_applies_when_it_arrives() {
    const SEED_A: u8 = 216;
    const SEED_B: u8 = 217;
    // Long enough for the first backoff step — thirty seconds — plus the
    // fetch and the judging that follow it.
    const PAST_THE_FIRST_RETRY: Duration = Duration::from_secs(90);
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let alice = TestId::new("did:plc:alicedefer");
    let bob = TestId::new("did:plc:bobdefer");

    // Nothing listens here yet. B is told this is where A's users' keys live,
    // so its lookups fail until the test says otherwise.
    let key_port = alloc_port();
    let key_api = format!("{id_a}=http://127.0.0.1:{key_port}");
    let (srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &[],
        &["--s2s-peer-api", &key_api],
    )
    .await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    request_act_cap(&hb, &mut rxb).await;
    hb.join("#defer").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#defer").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[47u8; 32]);
    register_key(&ha, &key_a).await;
    let pubkey = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_a.verifying_key().as_bytes())
    };

    // ── the event nobody there can check yet ────────────────────────
    let parked = send_act_as(
        &ha,
        "#defer",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-title", "waits-for-a-key"),
        ],
    )
    .await;

    // The home holds it, because the home checked it against a key it has.
    assert!(
        await_act_task(&srv_a.web_addr, &parked).await.is_some(),
        "the server the task was minted on files it"
    );

    // The far server does not: not shown to anyone, not written down, not
    // answered for. This is a wait, not a refusal — the difference shows in
    // the verdict, which says the event could not be checked rather than that
    // it failed.
    assert_eq!(
        tagmsg_deliveries(
            &mut rxb,
            &parked,
            Duration::from_secs(3),
            Duration::from_millis(500)
        )
        .await,
        0,
        "an event that cannot be checked is not shown to anyone"
    );
    assert_eq!(
        event_rows(&srv_b.db_path, &parked),
        0,
        "nor written into the log"
    );
    assert!(
        act_task(&srv_b.web_addr, &parked).await.is_none(),
        "nor answered for over REST"
    );
    assert_eq!(
        verdicts_for(&srv_b, &parked),
        vec!["unverifiable".to_string()],
        "and the far server says why in the one verdict it has reached: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── the key becomes fetchable ───────────────────────────────────
    //
    // Nothing else is sent. The far server asks again for the key its parked
    // event is waiting on, on its own backoff, and that ask is what ends the
    // wait.
    let key_server = serve_signing_key(key_port, pubkey).await;

    let body = await_act_task_within(&srv_b.web_addr, &parked, PAST_THE_FIRST_RETRY)
        .await
        .unwrap_or_else(|| {
            panic!(
                "a parked event must be judged when its key becomes fetchable, \
                 without being re-sent; B's verdicts: {}",
                server_log(&srv_b)
                    .lines()
                    .filter(|l| l.contains("verdict=") || l.contains("waiting"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        });
    assert_eq!(
        body["task"]["state"].as_str(),
        Some("open"),
        "and applied through the rules like any other event: {body}"
    );
    assert_eq!(
        body["task"]["origin"].as_str(),
        Some(id_a.as_str()),
        "still owned by the server that minted it: {body}"
    );
    assert_eq!(
        event_rows(&srv_b.db_path, &parked),
        1,
        "filed once, under the id its signer minted"
    );
    assert_eq!(
        tagmsg_deliveries(&mut rxb, &parked, S2S_SETTLE, Duration::from_millis(1000)).await,
        1,
        "and delivered to the room, once, on release"
    );
    assert_eq!(
        verdicts_for(&srv_b, &parked),
        vec!["unverifiable".to_string(), "valid".to_string()],
        "the same event, judged twice: once with no key to check it against, \
         and once with one"
    );

    key_server.abort();
    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a transition authored on one server, applied by the task's home ───────
//
// A task minted on A is claimed by an agent on B. B files the claim and
// decides nothing — the task is not B's to decide — and carries it to A. A
// verifies it exactly as it verifies any relayed task event, runs the rules,
// applies it, and writes down that it did: the receipt it owes for a move it
// made. B's copy stays on file, marked as waiting, because nothing has told it
// otherwise.

/// One task's REST answer, whether the task is live or finished.
async fn act_body(web_addr: &str, act_id: &str) -> Option<serde_json::Value> {
    let url = format!("http://{web_addr}/api/v1/actions/{act_id}");
    let resp = reqwest::get(&url).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

/// A field of one stored task event's signed document.
fn doc_field(event: &serde_json::Value, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(event["canonical"].as_str().unwrap_or("{}"))
        .ok()
        .and_then(|doc| doc.get(key).and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// Every event of a task as `(verb, confirm_state)`, in the order the log
/// holds them.
fn verb_states(body: &serde_json::Value) -> Vec<(String, String)> {
    body["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|e| {
            (
                doc_field(e, "act-verb"),
                e["confirm_state"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Poll one server until it names an assignee for the task, or give up.
async fn await_assignee(web_addr: &str, act_id: &str, within: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + within;
    let mut last = None;
    while tokio::time::Instant::now() < deadline {
        last = act_task(web_addr, act_id)
            .await
            .and_then(|t| t["task"]["assignee"].as_str().map(str::to_string));
        if last.is_some() {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last
}

/// Offer a handoff on A and wait for B to hold it, retrying the offer until
/// it lands.
///
/// The offer is re-sent until the far server holds it: a server has no key for
/// a stranger until its own fetch fills the store, and an event it cannot
/// verify yet is not filed. The healing test warms up the same way.
async fn offer_until_the_peer_holds_it(
    ha: &client::ClientHandle,
    channel: &str,
    key_a: &ed25519_dalek::SigningKey,
    alice_did: &str,
    title: &str,
    peer_web: &str,
) -> String {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            ha,
            channel,
            key_a,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", alice_did),
                ("+freeq.at/act-title", title),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_task(peer_web, &id).await.is_some() {
            return id;
        }
    }
    String::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_claim_authored_on_a_peer_is_applied_by_the_task_home() {
    const SEED_A: u8 = 206;
    const SEED_B: u8 = 207;
    let alice = TestId::new("did:plc:aliceroute");
    let bob = TestId::new("did:plc:bobroute");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#route").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#route").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#route",
        &key_a,
        &alice.did,
        "cross-server-claim",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the offer must reach B before its agent can claim it; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // B's agent claims a task B does not own.
    let claim = send_act_as(
        &hb,
        "#route",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    // The home applies it, and that is the only view that moves.
    let on_a = await_assignee(&srv_a.web_addr, &act_id, S2S_SETTLE).await;
    assert_eq!(
        on_a.as_deref(),
        Some(bob.did.as_str()),
        "the server that owns the task runs the rules on the claim carried to it; \
         A's log: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("verdict=") || l.contains(&claim))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // …and B follows it, because the home's receipt reached B. B did not decide
    // anything: it re-ran the claim its own agent authored through the shared
    // rules when the receipt naming it arrived.
    let on_b = await_assignee(&srv_b.web_addr, &act_id, S2S_SETTLE).await;
    assert_eq!(
        on_b.as_deref(),
        Some(bob.did.as_str()),
        "B follows the receipt of the server that owns the task; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("receipt") || l.contains(&claim))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let body_a = act_body(&srv_a.web_addr, &act_id)
        .await
        .expect("A answers for the task");
    let body_b = act_body(&srv_b.web_addr, &act_id)
        .await
        .expect("B answers for the task");

    // The receipt is in both logs, signed by the server that made it, and it
    // names the event it rules in.
    for (name, body) in [("A", &body_a), ("B", &body_b)] {
        let receipts: Vec<(String, String)> = body["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| doc_field(e, "act-verb") == "confirm")
            .map(|e| (doc_field(e, "from"), doc_field(e, "act-subject")))
            .collect();
        assert_eq!(
            receipts,
            vec![(format!("did:web:test-fed-{SEED_A}"), claim.clone())],
            "{name} holds the home's receipt, naming the event it confirms: {:?}",
            verb_states(body)
        );
        assert_eq!(
            body["events"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .find(|e| doc_field(e, "act-verb") == "confirm")
                .and_then(|e| e["confirm_state"].as_str().map(str::to_string)),
            None,
            "and it carries no confirm state of its own on {name}: {:?}",
            verb_states(body)
        );
        assert_eq!(
            verb_states(body)
                .iter()
                .find(|(verb, _)| verb == "claim")
                .map(|(_, state)| state.as_str()),
            Some("confirmed"),
            "{name} shows the claim as confirmed: {:?}",
            verb_states(body)
        );
    }

    // ── and on to the end of the work ───────────────────────────────
    //
    // The assignee finishes it from the server that does not own the task.
    // The home orders that too, so the task leaves both live views on the
    // same word — a lifecycle carried the whole way across the link, not a
    // claim and a shrug.
    send_act_as(
        &hb,
        "#route",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "complete"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;
    for (name, addr) in [("A", &srv_a.web_addr), ("B", &srv_b.web_addr)] {
        assert!(
            await_task_gone(addr, &act_id, S2S_SETTLE).await,
            "{name} must end the task on the home's word; {name} says: {:?}",
            act_body(addr, &act_id).await.map(|b| verb_states(&b))
        );
        let body = act_body(addr, &act_id)
            .await
            .expect("the log outlives the task");
        assert_eq!(
            verb_states(&body)
                .iter()
                .find(|(verb, _)| verb == "complete")
                .map(|(_, state)| state.as_str()),
            Some("confirmed"),
            "and {name} shows the completion as ruled on: {:?}",
            verb_states(&body)
        );
    }

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a claim made while the task's home is away ───────────────────────────
//
// The never-lose guarantee, watched end to end. A task minted on one server is
// claimed by someone on another while the first is down. The claim is a signed
// record and is treated as one — filed at once, kept, shown — but it decides
// nothing, because the server that orders this task's moves is not there to
// order it. The home comes back, is asked again, and applies it.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_claim_made_while_the_home_is_away_reaches_it_when_it_returns() {
    // B is the server that stays up, so it must be the one that keeps its
    // outgoing link — the orientation the orphan test pins, for the same
    // reason: B is what has to reach A again.
    const SEED_A: u8 = 218;
    const SEED_B: u8 = 219;
    // Long enough for the backoff to come round after the home is back: the
    // attempt that failed while it was down is deliberately not retried at
    // once.
    const PAST_THE_BACKOFF: Duration = Duration::from_secs(150);
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_b < id_a,
        "the server that stays up keeps its outgoing link"
    );

    let alice = TestId::new("did:plc:aliceaway");
    let bob = TestId::new("did:plc:bobaway");
    let (mut srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#away").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#away").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[53u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[59u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#away",
        &key_a,
        &alice.did,
        "claimed-while-nobody-was-home",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the offer must cross before the outage, or the outage proves nothing; \
         B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── the home goes away, and the task is claimed anyway ──────────
    ha.quit(None).await.ok();
    srv_a.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;

    send_act_as(
        &hb,
        "#away",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    // Filed, kept, and deciding nothing: the claim is on the record with its
    // flag down, and the task still stands where its home left it.
    let filed = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut away = serde_json::Value::Null;
    while tokio::time::Instant::now() < filed {
        away = act_body(&srv_b.web_addr, &act_id).await.unwrap_or_default();
        if verb_states(&away).iter().any(|(v, _)| v == "claim") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        verb_states(&away)
            .iter()
            .find(|(verb, _)| verb == "claim")
            .map(|(_, state)| state.as_str()),
        Some("unconfirmed"),
        "a claim made while the home is away is on file and waiting on it: {:?}",
        verb_states(&away)
    );
    assert_eq!(
        away["task"]["state"].as_str(),
        Some("open"),
        "and changes nothing about the task until the home has ruled: {away}"
    );

    // ── the home comes back and is asked again ──────────────────────
    srv_a.start_again().await;
    let (ha2, mut rxa2) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa2).await;
    warm_link(&ha2, &bob.did, &mut rxb).await;

    let on_a = await_assignee(&srv_a.web_addr, &act_id, PAST_THE_BACKOFF).await;
    assert_eq!(
        on_a.as_deref(),
        Some(bob.did.as_str()),
        "a claim made while the home was away has to reach it when it returns; \
         A says {:?} and B says {:?}",
        act_body(&srv_a.web_addr, &act_id)
            .await
            .map(|b| verb_states(&b)),
        act_body(&srv_b.web_addr, &act_id)
            .await
            .map(|b| verb_states(&b))
    );

    // …and the receipt comes back to the server that had been holding the
    // claim. Without that half B would have carried a claim it authored,
    // watched the home decide it, and never learnt the answer.
    let on_b = await_assignee(&srv_b.web_addr, &act_id, S2S_SETTLE).await;
    let body_b = act_body(&srv_b.web_addr, &act_id)
        .await
        .expect("B answers for the task");
    assert_eq!(
        on_b.as_deref(),
        Some(bob.did.as_str()),
        "B follows the receipt once its home is back: {:?}",
        verb_states(&body_b)
    );
    assert_eq!(
        verb_states(&body_b)
            .iter()
            .find(|(verb, _)| verb == "claim")
            .map(|(_, state)| state.as_str()),
        Some("confirmed"),
        "and the claim it was holding is no longer waiting on anybody: {:?}",
        verb_states(&body_b)
    );

    ha2.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the cases a two-server pair is the only place to watch ────────────────
//
// Everything below needs two servers with a real link between them: a task
// whose home is the far side, a race whose outcome depends on which server
// heard what first, an ending only the home can author, and a bounty whose
// award has to resolve a bid that was written somewhere else.

/// Poll both servers until each names an assignee for the task, and hand back
/// the two answers.
async fn await_assignees(a: &str, b: &str, act_id: &str) -> (Option<String>, Option<String>) {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut last = (None, None);
    while tokio::time::Instant::now() < deadline {
        let on_a = act_task(a, act_id)
            .await
            .and_then(|t| t["task"]["assignee"].as_str().map(str::to_string));
        let on_b = act_task(b, act_id)
            .await
            .and_then(|t| t["task"]["assignee"].as_str().map(str::to_string));
        last = (on_a, on_b);
        if last.0.is_some() && last.0 == last.1 {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last
}

/// The verbs a server has confirmed for a task, in the order it holds them.
fn confirmed_verbs(body: &serde_json::Value) -> Vec<String> {
    body["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| e["confirm_state"].as_str() == Some("confirmed"))
                .map(|e| doc_field(e, "act-verb"))
                .collect()
        })
        .unwrap_or_default()
}

/// Poll one server until the task has left the live view, or give up.
async fn await_task_gone(web_addr: &str, act_id: &str, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if act_task(web_addr, act_id)
            .await
            .is_none_or(|body| body["task"].is_null())
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Offer a bounty on one server and wait for the far one to hold it, retrying
/// until it lands — the same key warm-up the handoff offers do.
async fn bounty_until_the_peer_holds_it(
    handle: &client::ClientHandle,
    channel: &str,
    key: &ed25519_dalek::SigningKey,
    did: &str,
    title: &str,
    peer_web: &str,
) -> String {
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            handle,
            channel,
            key,
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", did),
                ("+freeq.at/act-title", title),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_task(peer_web, &id).await.is_some() {
            return id;
        }
    }
    String::new()
}

// ── two agents, one task, two servers ─────────────────────────────────────
//
// The race the whole ordering design exists for. Exactly one claim wins,
// both servers name the same winner, and nothing anywhere is left waiting on
// a decision that has already been made — the loser is refused at the home and
// marked superseded where it was authored.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn two_claims_on_one_task_leave_both_servers_naming_one_winner() {
    const SEED_A: u8 = 222;
    const SEED_B: u8 = 223;
    let alice = TestId::new("did:plc:aliceraced");
    let bob = TestId::new("did:plc:bobraced");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#raced").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#raced").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[79u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let mut raced = String::new();
    let mut both: (Option<String>, Option<String>) = (None, None);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while raced.is_empty() && tokio::time::Instant::now() < deadline {
        let id = offer_until_the_peer_holds_it(
            &ha,
            "#raced",
            &key_a,
            &alice.did,
            "contested",
            &srv_b.web_addr,
        )
        .await;
        if id.is_empty() {
            continue;
        }
        let claim_a = [
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", id.as_str()),
        ];
        let claim_b = [
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", id.as_str()),
        ];
        let (_, _) = tokio::join!(
            send_act_as(&hb, "#raced", &key_b, &claim_b),
            send_act_as(&ha, "#raced", &key_a, &claim_a),
        );
        both = await_assignees(&srv_a.web_addr, &srv_b.web_addr, &id).await;
        if both.0.is_some() && both.0 == both.1 {
            raced = id;
        }
    }

    assert!(
        !raced.is_empty(),
        "two claims on one task must leave both servers naming one winner; \
         A said {:?} and B said {:?}",
        both.0,
        both.1
    );
    let winner = both.0.clone().expect("a winner");

    // Exactly one confirmed claim on each server, and it is the same one — but
    // what the loser looks like differs by server, which is why both are
    // asked. The home refused it at its own ingress, and a refused event is
    // never filed; the server whose agent authored it filed it before anyone
    // had decided, and dropped it from the pending set when the receipt landed.
    let mut per_server: Vec<Vec<(String, String)>> = Vec::new();
    for (name, addr) in [("A", &srv_a.web_addr), ("B", &srv_b.web_addr)] {
        let body = act_body(addr, &raced)
            .await
            .unwrap_or_else(|| panic!("{name} answers for the task"));
        let claims: Vec<(String, String)> = body["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| doc_field(e, "act-verb") == "claim")
            .map(|e| {
                (
                    doc_field(e, "from"),
                    e["confirm_state"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let confirmed: Vec<&String> = claims
            .iter()
            .filter(|(_, state)| state == "confirmed")
            .map(|(did, _)| did)
            .collect();
        assert_eq!(
            confirmed,
            vec![&winner],
            "{name} must show exactly one confirmed claim, the winner's: {claims:?}"
        );
        assert!(
            claims.iter().all(|(_, state)| state != "unconfirmed"),
            "{name} left a claim waiting on a decision that has already been \
             made: {claims:?}"
        );
        per_server.push(claims);
    }
    let (on_a, on_b) = (&per_server[0], &per_server[1]);
    assert_eq!(
        on_a.len(),
        1,
        "the home files nothing for a claim it refuses: {on_a:?}"
    );
    // Alice sends on A and bob on B, so a losing bob is the case where the
    // loser was authored somewhere other than the home — and therefore the
    // only case where a copy of it exists anywhere to be marked.
    if winner == alice.did {
        assert_eq!(
            on_b.iter()
                .find(|(did, _)| did == &bob.did)
                .map(|(_, state)| state.as_str()),
            Some("superseded"),
            "B keeps the claim its own agent lost, dropped from the pending \
             set rather than deleted: {on_b:?}"
        );
    }

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a task whose home is the far server ───────────────────────────────────
//
// The mirror of the lifecycle test, and the one that shows this server is not
// quietly deciding its own answers: every move is authored here and every
// receipt comes from there.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_task_minted_on_the_far_server_moves_where_that_server_says() {
    const SEED_A: u8 = 224;
    const SEED_B: u8 = 225;
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();

    // Bob offers the work from B, which makes B the server that referees it.
    // Alice, on A, is the one who does it.
    let alice = TestId::new("did:plc:alicemirror");
    let bob = TestId::new("did:plc:bobmirror");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    ha.join("#mirror").await.unwrap();

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    warm_link(&hb, &alice.did, &mut rxa).await;
    hb.join("#mirror").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[83u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[89u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = offer_until_the_peer_holds_it(
        &hb,
        "#mirror",
        &key_b,
        &bob.did,
        "the-other-direction",
        &srv_a.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "a task offered on B must reach A; A's log says: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Which server referees it, said from both ends: B by saying nothing — an
    // empty origin is "minted here" — and A by naming B.
    for (name, addr, home) in [
        ("A", &srv_a.web_addr, id_b.as_str()),
        ("B", &srv_b.web_addr, ""),
    ] {
        let body = act_task(addr, &act_id)
            .await
            .unwrap_or_else(|| panic!("{name} answers for the task"));
        assert_eq!(
            body["task"]["origin"].as_str(),
            Some(home),
            "the far server is the home of this one: {body}"
        );
    }

    // Taken by the user on the server that does not own it.
    send_act_as(
        &ha,
        "#mirror",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    let (on_a, on_b) = await_assignees(&srv_a.web_addr, &srv_b.web_addr, &act_id).await;
    assert_eq!(
        on_a.as_deref(),
        Some(alice.did.as_str()),
        "the home confirmed the claim and both servers followed it; A said \
         {on_a:?} and B said {on_b:?}. A's log: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("receipt") || l.contains("verdict="))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(on_b, on_a, "and the server that owns it says the same");

    // A did not decide that — it cannot, the task is not its own. Its copy
    // reading confirmed is the far server's receipt having arrived.
    let body_a = act_body(&srv_a.web_addr, &act_id)
        .await
        .expect("A answers for the task");
    assert_eq!(
        verb_states(&body_a)
            .iter()
            .find(|(verb, _)| verb == "claim")
            .map(|(_, state)| state.as_str()),
        Some("confirmed"),
        "the mover follows a receipt it did not make: {:?}",
        verb_states(&body_a)
    );

    // ── and on to the end of the work ───────────────────────────────
    //
    // The same lifecycle, run the other way: the person who took the work
    // finishes it here, and the far server — the one that owns the task —
    // is what ends it on both.
    send_act_as(
        &ha,
        "#mirror",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "complete"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;
    for (name, addr) in [("A", &srv_a.web_addr), ("B", &srv_b.web_addr)] {
        assert!(
            await_task_gone(addr, &act_id, S2S_SETTLE).await,
            "{name} must end the task on the far server's word; {name} says: {:?}",
            act_body(addr, &act_id).await.map(|b| verb_states(&b))
        );
        let body = act_body(addr, &act_id)
            .await
            .expect("the log outlives the task");
        assert_eq!(
            verb_states(&body)
                .iter()
                .find(|(verb, _)| verb == "complete")
                .map(|(_, state)| state.as_str()),
            Some("confirmed"),
            "and {name} shows the completion as ruled on: {:?}",
            verb_states(&body)
        );
    }

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a cancel and an accept sent at once ───────────────────────────────────
//
// The creator's cancel and the offeree's accept, sent together on different
// servers. The home orders them, and the ordinary result is that the cancel
// wins: it is filed at the home with no hop to cross while the accept has to
// travel. When the other order happens anyway the attempt is retried on a
// fresh task rather than asserted against — that is a different question.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_cancel_and_an_accept_at_once_leave_the_creator_the_winner() {
    const SEED_A: u8 = 226;
    const SEED_B: u8 = 227;
    let alice = TestId::new("did:plc:alicetie");
    let bob = TestId::new("did:plc:bobtie");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#tie").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#tie").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[97u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[101u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let mut settled = String::new();
    let mut other_order = 0usize;
    let mut never_filed = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while settled.is_empty() && tokio::time::Instant::now() < deadline {
        // A fresh directed offer, repeated until the far server holds it.
        let id = send_act_as(
            &ha,
            "#tie",
            &key_a,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", alice.did.as_str()),
                ("+freeq.at/act-to", bob.did.as_str()),
                ("+freeq.at/act-title", "pulled-and-taken-at-once"),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_task(&srv_b.web_addr, &id).await.is_none() {
            continue;
        }

        // Both moves, together.
        let cancel_tags = [
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "cancel"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", id.as_str()),
        ];
        let accept_tags = [
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "accept"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", id.as_str()),
        ];
        let (_, _) = tokio::join!(
            send_act_as(&ha, "#tie", &key_a, &cancel_tags),
            send_act_as(&hb, "#tie", &key_b, &accept_tags),
        );

        // Settled when both servers have confirmed the cancel and neither is
        // still holding anything on this task waiting to be decided.
        let settle = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut on_a = serde_json::Value::Null;
        let mut on_b = serde_json::Value::Null;
        while tokio::time::Instant::now() < settle {
            on_a = act_body(&srv_a.web_addr, &id).await.unwrap_or_default();
            on_b = act_body(&srv_b.web_addr, &id).await.unwrap_or_default();
            let settled = |body: &serde_json::Value| {
                confirmed_verbs(body).iter().any(|v| v == "cancel")
                    && verb_states(body).iter().all(|(_, s)| s != "unconfirmed")
            };
            if settled(&on_a) && settled(&on_b) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // The other arrival order — the accept reached the home first and was
        // confirmed before the cancel the home had not yet seen. A legal
        // history, and not the one under test.
        if verb_states(&on_a).iter().any(|(verb, _)| verb == "accept") {
            other_order += 1;
            continue;
        }
        // The cancel reached the far server before its own user's accept was
        // filed, so there is no losing copy anywhere to be marked. Also not
        // the case under test.
        if !verb_states(&on_b).iter().any(|(verb, _)| verb == "accept") {
            never_filed += 1;
            continue;
        }

        // The creator's cancel stands, on both servers.
        for (name, body) in [("A", &on_a), ("B", &on_b)] {
            assert_eq!(
                confirmed_verbs(body),
                vec!["offer".to_string(), "cancel".to_string()],
                "{name} must end the task on the creator's cancel and nothing \
                 else: {:?}",
                verb_states(body)
            );
            assert!(
                body["task"].is_null(),
                "a cancelled task is out of the live view on {name}: {body}"
            );
        }
        // The home refuses a move on a task that has already finished, and a
        // refused event is not filed at all — so there is no accept there to
        // rule in or to mark.
        assert_eq!(
            verb_states(&on_a)
                .iter()
                .filter(|(verb, _)| verb == "accept")
                .count(),
            0,
            "the home files nothing for the accept it refused: {:?}",
            verb_states(&on_a)
        );
        // The server whose user sent it keeps the record and drops the flag.
        assert_eq!(
            verb_states(&on_b)
                .iter()
                .find(|(verb, _)| verb == "accept")
                .map(|(_, state)| state.as_str()),
            Some("superseded"),
            "the losing accept stays on file where it was authored, marked as \
             outrun rather than deleted: {:?}",
            verb_states(&on_b)
        );
        settled = id;
    }

    assert!(
        !settled.is_empty(),
        "no attempt produced the arrival order under test in the time allowed \
         ({other_order} reached the home accept-first, {never_filed} never \
         filed an accept at all); B's log says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("task") || l.contains("verdict="))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the ending only the home can author ───────────────────────────────────
//
// A task nobody moves is expired by its home's sweep. The peer holding it has
// no sweep of its own for somebody else's task, so without the home's event
// crossing, that row stays live on the peer for ever.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn an_expiry_ends_the_task_on_the_peer_holding_it() {
    const SEED_A: u8 = 228;
    const SEED_B: u8 = 229;
    let alice = TestId::new("did:plc:aliceexpire");
    let bob = TestId::new("did:plc:bobexpire");
    // A's abandonment limit is one second, so the sweep fires while the test
    // is watching. B's is left alone — it must not be the one that ends this.
    let (srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &["--act-expiry-secs", "1"],
        &[],
    )
    .await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#expiry").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#expiry").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[103u8; 32]);
    register_key(&ha, &key_a).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#expiry",
        &key_a,
        &alice.did,
        "left-to-rot",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the offer must reach B before it can be watched ending there; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    assert!(
        await_task_gone(&srv_a.web_addr, &act_id, S2S_SETTLE).await,
        "the home's own sweep ends the task it opened"
    );
    assert!(
        await_task_gone(&srv_b.web_addr, &act_id, S2S_SETTLE).await,
        "and the ending crosses, or B holds a live row for a task that is over; \
         B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("expire") || l.contains(&act_id))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    let body_b = act_body(&srv_b.web_addr, &act_id)
        .await
        .expect("B still answers for the finished task");
    assert_eq!(
        confirmed_verbs(&body_b),
        vec!["offer".to_string(), "expire".to_string()],
        "B holds the whole life of the task, ending included: {:?}",
        verb_states(&body_b)
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the relations that ride along ─────────────────────────────────────────
//
// Two things a task event can carry that are about something other than the
// task's own state: the finished action it revives, and, on a bounty, the bid
// an award takes. Both have to survive a hop.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_revival_relation_crosses_a_link() {
    const SEED_A: u8 = 230;
    const SEED_B: u8 = 231;
    let alice = TestId::new("did:plc:alicerevive");
    let bob = TestId::new("did:plc:bobrevive");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#revive").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#revive").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[107u8; 32]);
    register_key(&ha, &key_a).await;

    // One task, cancelled — a finished action is what a revival may name.
    let first = offer_until_the_peer_holds_it(
        &ha,
        "#revive",
        &key_a,
        &alice.did,
        "first-attempt",
        &srv_b.web_addr,
    )
    .await;
    assert!(!first.is_empty(), "the first offer must reach B");
    send_act_as(
        &ha,
        "#revive",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "cancel"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", first.as_str()),
        ],
    )
    .await;
    assert!(
        await_task_gone(&srv_b.web_addr, &first, S2S_SETTLE).await,
        "the cancel has to cross before the revival can name a finished action"
    );

    // And its successor, which names it.
    let second = send_act_as(
        &ha,
        "#revive",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-title", "second-attempt"),
            ("+freeq.at/act-replaces", first.as_str()),
        ],
    )
    .await;

    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    let mut on_b = None;
    while tokio::time::Instant::now() < deadline {
        on_b = act_task(&srv_b.web_addr, &second).await;
        if on_b.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let on_b = on_b.expect("the successor reaches B");
    assert_eq!(
        on_b["task"]["replaces"].as_str(),
        Some(first.as_str()),
        "the relation to the action it revives crosses with it: {on_b}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_bid_from_a_remote_bidder_is_awarded_at_the_home() {
    const SEED_A: u8 = 232;
    const SEED_B: u8 = 233;
    let alice = TestId::new("did:plc:alicebounty");
    let bob = TestId::new("did:plc:bobbounty");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#bounty").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#bounty").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[109u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[113u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = bounty_until_the_peer_holds_it(
        &ha,
        "#bounty",
        &key_a,
        &alice.did,
        "paid-work",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the bounty must reach B before its user can bid; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Bob bids from B. A bid is additive — it leaves the bounty open, so it
    // decides nothing exclusive and is applied wherever it lands. The award
    // below resolves it from the home's own log, which is exactly why the bid
    // has to have reached the home first.
    let mut bid = String::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            &hb,
            "#bounty",
            &key_b,
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "bid"),
                ("+freeq.at/from", bob.did.as_str()),
                ("+freeq.at/act-id", act_id.as_str()),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let on_a = act_body(&srv_a.web_addr, &act_id).await.unwrap_or_default();
        if on_a["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|e| e["event_id"].as_str() == Some(&id)))
        {
            bid = id;
            break;
        }
    }
    assert!(
        !bid.is_empty(),
        "the bid has to reach the home, or there is nothing for the award to \
         take; A's log: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("verdict="))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Alice awards it from A, naming the bid.
    send_act_as(
        &ha,
        "#bounty",
        &key_a,
        &[
            ("+freeq.at/act", "bounty"),
            ("+freeq.at/act-verb", "award"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
            ("+freeq.at/act-accepts", bid.as_str()),
        ],
    )
    .await;

    let (on_a, on_b) = await_assignees(&srv_a.web_addr, &srv_b.web_addr, &act_id).await;
    assert_eq!(
        on_a.as_deref(),
        Some(bob.did.as_str()),
        "the award goes to whoever wrote the bid it names, wherever they are; \
         A said {on_a:?} and B said {on_b:?}"
    );
    assert_eq!(
        on_b, on_a,
        "and the server the bidder is on follows the home's receipt"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the review window closing across a hop ────────────────────────────────
//
// The other event a server signs itself. Work handed in and never answered is
// deemed accepted by the server that owns the bounty, under a verb of its own
// — and a peer that never hears it holds a live row for work that has been
// accepted, which is the same hole the expiry test closes for abandoned work.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_closed_review_window_accepts_the_work_on_the_peer_holding_it() {
    const SEED_A: u8 = 234;
    const SEED_B: u8 = 235;
    let alice = TestId::new("did:plc:alicereview");
    let bob = TestId::new("did:plc:bobreview");
    // A's review window is one second, so the sweep fires while the test is
    // watching. B's is left alone — it must not be the one that closes this.
    let (srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &["--act-review-secs", "1"],
        &[],
    )
    .await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#review").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#review").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[149u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[151u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = bounty_until_the_peer_holds_it(
        &ha,
        "#review",
        &key_a,
        &alice.did,
        "handed-in-and-ignored",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the bounty must reach B before its user can bid; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Bob bids, alice awards it, bob hands the work in — and then nobody says
    // anything, which is what the window is for.
    let mut bid = String::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while bid.is_empty() && tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            &hb,
            "#review",
            &key_b,
            &[
                ("+freeq.at/act", "bounty"),
                ("+freeq.at/act-verb", "bid"),
                ("+freeq.at/from", bob.did.as_str()),
                ("+freeq.at/act-id", act_id.as_str()),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let on_a = act_body(&srv_a.web_addr, &act_id).await.unwrap_or_default();
        if on_a["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|e| e["event_id"].as_str() == Some(&id)))
        {
            bid = id;
        }
    }
    assert!(
        !bid.is_empty(),
        "the bid has to reach the home to be awarded"
    );

    send_act_as(
        &ha,
        "#review",
        &key_a,
        &[
            ("+freeq.at/act", "bounty"),
            ("+freeq.at/act-verb", "award"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
            ("+freeq.at/act-accepts", bid.as_str()),
        ],
    )
    .await;
    assert_eq!(
        await_assignee(&srv_b.web_addr, &act_id, S2S_SETTLE)
            .await
            .as_deref(),
        Some(bob.did.as_str()),
        "the award has to be settled on both sides before the work goes in"
    );

    send_act_as(
        &hb,
        "#review",
        &key_b,
        &[
            ("+freeq.at/act", "bounty"),
            ("+freeq.at/act-verb", "submit"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    // The window closes on the server that owns the bounty…
    assert!(
        await_task_gone(&srv_a.web_addr, &act_id, S2S_SETTLE).await,
        "the poster's own server deems unanswered work accepted; A's log: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("review") || l.contains(&act_id))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );
    // …and the event that closed it crosses, so the worker's own server stops
    // showing the work as still under review.
    assert!(
        await_task_gone(&srv_b.web_addr, &act_id, S2S_SETTLE).await,
        "the close has to cross, or B holds a live row for accepted work; \
         B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("auto-accept") || l.contains(&act_id))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    let body_b = act_body(&srv_b.web_addr, &act_id)
        .await
        .expect("B still answers for the finished bounty");
    assert!(
        confirmed_verbs(&body_b).last().map(String::as_str) == Some("auto-accept"),
        "B holds the whole life of the bounty, the close included: {:?}",
        verb_states(&body_b)
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the stopgap coordination family across a hop ──────────────────────────
//
// The older family, which carries its own signed document and has no task
// view. It is not part of the act lifecycle and nothing here rules on it —
// what it owes is that a peer receiving one verifies it and files it, so an
// agent's activity on one server is readable on the other.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_stopgap_coordination_event_is_stored_on_the_peer_that_receives_it() {
    const SEED_A: u8 = 236;
    const SEED_B: u8 = 237;
    let alice = TestId::new("did:plc:alicestopgap");
    let bob = TestId::new("did:plc:bobstopgap");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#stopgap").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#stopgap").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[157u8; 32]);
    register_key(&ha, &key_a).await;

    // Repeated until it lands: B holds no key for alice until its own fetch
    // fills the store, and an event it cannot verify yet is not filed.
    let mut stored = None;
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while stored.is_none() && tokio::time::Instant::now() < deadline {
        let task_id = ha
            .create_task("#stopgap", "read the far server's copy")
            .await
            .expect("the event goes out");
        tokio::time::sleep(Duration::from_millis(500)).await;
        stored = channel_events(&srv_b.web_addr, "stopgap")
            .await
            .into_iter()
            .find(|e| e["event_id"].as_str() == Some(task_id.as_str()));
    }

    let stored = stored.unwrap_or_else(|| {
        panic!(
            "a coordination event has to reach the peer's store; B's log: {}",
            server_log(&srv_b)
                .lines()
                .filter(|l| l.contains("verdict=") || l.contains("coordination"))
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        )
    });
    assert_eq!(
        stored["event_type"].as_str(),
        Some("task_request"),
        "filed as what it is: {stored}"
    );
    assert_eq!(
        stored["actor_did"].as_str(),
        Some(alice.did.as_str()),
        "under the identity that signed it, not the peer that relayed it: {stored}"
    );
    assert!(
        stored["signature"].as_str().is_some_and(|s| !s.is_empty()),
        "with the signature it travelled under: {stored}"
    );
    assert_eq!(
        stored["payload"]["description"].as_str(),
        Some("read the far server's copy"),
        "and the payload the signature covers: {stored}"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

/// The stopgap coordination events one server holds for a channel.
async fn channel_events(web_addr: &str, channel: &str) -> Vec<serde_json::Value> {
    let url = format!("http://{web_addr}/api/v1/channels/{channel}/events");
    let Ok(resp) = reqwest::get(&url).await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return Vec::new();
    };
    body["events"].as_array().cloned().unwrap_or_default()
}

// ── a task whose home server vanished ─────────────────────────────────────
//
// A task is refereed by the server it was created on. While that server is
// gone nothing can rule on the task, and a peer showing it as fresh open work
// is lying by omission. So a peer annotates it `orphaned` in its own view —
// its own reading, never a transition, never relayed, never in the signed log
// — and the annotation lifts by itself when the home comes back.
//
// Read through REST, because that is where the RFC puts the promise: clients
// see honest liveness rather than a forever-fresh offer.

/// One task's row in a server's task listing — the surface a client's inbox
/// actually reads.
async fn listed_task(web_addr: &str, act_id: &str) -> Option<serde_json::Value> {
    let url = format!("http://{web_addr}/api/v1/actions");
    let body = reqwest::get(&url)
        .await
        .ok()?
        .json::<serde_json::Value>()
        .await
        .ok()?;
    body["tasks"]
        .as_array()?
        .iter()
        .find(|t| t["act_id"].as_str() == Some(act_id))
        .cloned()
}

/// Poll a server's answer for `act_id` until its state is `want`, or give up
/// and return what it last said.
async fn await_task_state(web_addr: &str, act_id: &str, want: &str, within: Duration) -> String {
    let deadline = tokio::time::Instant::now() + within;
    let mut last = String::from("<no answer>");
    while tokio::time::Instant::now() < deadline {
        if let Some(body) = act_task(web_addr, act_id).await {
            last = body["task"]["state"]
                .as_str()
                .unwrap_or("<absent>")
                .to_string();
            if last == want {
                return last;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_task_reads_orphaned_while_its_home_is_away_and_live_again_when_it_returns() {
    // B is the server that stays up, so it is the one that must keep its
    // outgoing link — the same orientation rule the away-home test pins, for
    // the same reason: B is what has to reach A again.
    const SEED_A: u8 = 208;
    const SEED_B: u8 = 209;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_b < id_a,
        "the server that stays up keeps its outgoing link"
    );

    // Seconds rather than the shipped day, which is the whole reason the
    // threshold is configurable.
    const ORPHAN_SECS: &str = "5";

    let alice = TestId::new("did:plc:aliceorphan");
    let bob = TestId::new("did:plc:boborphan");
    let (mut srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &[],
        &["--act-orphan-secs", ORPHAN_SECS],
    )
    .await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#orphan").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#orphan").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    register_key(&ha, &key_a).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#orphan",
        &key_a,
        &alice.did,
        "outlives-its-home",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the link must carry the task before the outage, or the outage proves \
         nothing; B's log says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── while the home is up, the task reads as it stands ────────────
    let before = act_task(&srv_b.web_addr, &act_id)
        .await
        .expect("B answers for the task it took live");
    assert_eq!(
        before["task"]["state"].as_str(),
        Some("open"),
        "a task whose home is right there is not orphaned: {before}"
    );
    assert_eq!(before["task"]["origin"].as_str(), Some(id_a.as_str()));
    let events_before = before["events"].as_array().map(Vec::len);

    // ── the home goes away ───────────────────────────────────────────
    ha.quit(None).await.ok();
    srv_a.stop();

    let state = await_task_state(
        &srv_b.web_addr,
        &act_id,
        "orphaned",
        Duration::from_secs(45),
    )
    .await;
    assert_eq!(
        state,
        "orphaned",
        "past the threshold, a task nobody can rule on must say so; B's log \
         says: {}",
        server_log(&srv_b)
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The annotation is this server's reading, not a change to the task.
    let away = act_task(&srv_b.web_addr, &act_id)
        .await
        .expect("B still answers for the task");
    assert_eq!(
        away["task"]["stored_state"].as_str(),
        Some("open"),
        "the task's own record is untouched: {away}"
    );
    assert_eq!(
        away["events"].as_array().map(Vec::len),
        events_before,
        "and nothing was written to the log to say it: {away}"
    );
    let listed = listed_task(&srv_b.web_addr, &act_id)
        .await
        .expect("the task is still listed while its home is away");
    assert_eq!(
        listed["state"].as_str(),
        Some("orphaned"),
        "the listing an inbox reads says the same thing: {listed}"
    );
    assert_eq!(listed["stored_state"].as_str(), Some("open"));

    // ── the home comes back and speaks ───────────────────────────────
    srv_a.start_again().await;
    let (ha2, mut rxa2) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa2).await;
    warm_link(&ha2, &bob.did, &mut rxb).await;

    let state = await_task_state(&srv_b.web_addr, &act_id, "open", S2S_SETTLE).await;
    assert_eq!(
        state, "open",
        "the annotation lifts by itself when the home is reachable again"
    );

    // No residue: same record, same log, and the listing back in step.
    let listed = listed_task(&srv_b.web_addr, &act_id)
        .await
        .expect("and it is listed once the home is back");
    assert_eq!(listed["state"].as_str(), Some("open"));
    let back = act_task(&srv_b.web_addr, &act_id)
        .await
        .expect("B answers for the task once more");
    assert_eq!(back["task"]["stored_state"].as_str(), Some("open"));
    assert_eq!(back["events"].as_array().map(Vec::len), events_before);
    assert_eq!(
        back["task"]["origin"].as_str(),
        Some(id_a.as_str()),
        "and it still names the server that referees it: {back}"
    );

    // Authority resumed with contact: the home's own ruling on the task now
    // crosses the link it came back on, and B follows it.
    ha2.join("#orphan").await.unwrap();
    register_key(&ha2, &key_a).await;
    send_act_as(
        &ha2,
        "#orphan",
        &key_a,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "cancel"),
            ("+freeq.at/from", alice.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;
    assert!(
        await_task_gone(&srv_b.web_addr, &act_id, S2S_SETTLE).await,
        "the home's word ends the task on the peer that was reading it orphaned"
    );

    ha2.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a directed task for an identity that is on both servers ───────────────
//
// The motivating case for federating tasks at all: one agent, signed in from
// two places at once, offered work by name. The offer is minted on one server
// and has to reach every session that identity holds — the one beside the
// sender and the one a hop away — and reach each of them once. Two servers
// showing the same task, and one of them showing it twice, is the failure
// this pins against: an event id is what tells a session it has already been
// handed this event, and it is the same id on both sides of the link because
// the signer minted it.

/// How many rows a server's task listing holds for `act_id` — one, or the
/// server is showing the same task twice.
async fn listed_rows(web_addr: &str, act_id: &str) -> usize {
    let url = format!("http://{web_addr}/api/v1/actions");
    let Ok(resp) = reqwest::get(&url).await else {
        return 0;
    };
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return 0;
    };
    body["tasks"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|t| t["act_id"].as_str() == Some(act_id))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_directed_task_reaches_both_homes_of_one_identity() {
    const SEED_A: u8 = 212;
    const SEED_B: u8 = 213;
    let alice = TestId::new("did:plc:alicedirect");
    // One identity, two servers, two devices — the same DID signed in on both.
    let agent = TestId::new("did:plc:agentmultihome");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &agent], SEED_A, SEED_B).await;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();

    // The agent's far session first, so the link has both ends of the room
    // before anything is offered.
    let (h_far, mut rx_far) = connect(&srv_b, &agent, "agentfar");
    wait_auth_and_register(&mut rx_far).await;
    request_act_cap(&h_far, &mut rx_far).await;
    h_far.join("#multi").await.unwrap();

    let (h_near, mut rx_near) = connect(&srv_a, &agent, "agentnear");
    wait_auth_and_register(&mut rx_near).await;
    request_act_cap(&h_near, &mut rx_near).await;
    h_near.join("#multi").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &agent.did, &mut rx_far).await;
    ha.join("#multi").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[37u8; 32]);
    register_key(&ha, &key_a).await;

    // ── the offer, by name ──────────────────────────────────────────
    //
    // Repeated until B holds it, the same key warm-up every act test here
    // does. Deliveries are counted by event id afterwards, so the warm-up's
    // earlier offers cannot be mistaken for a second copy of this one.
    let mut act_id = String::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            &ha,
            "#multi",
            &key_a,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", alice.did.as_str()),
                ("+freeq.at/act-to", agent.did.as_str()),
                ("+freeq.at/act-title", "for-an-agent-in-two-places"),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_task(&srv_b.web_addr, &id).await.is_some() {
            act_id = id;
            break;
        }
    }
    assert!(
        !act_id.is_empty(),
        "a directed offer must reach the far server; B's log says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── every session of that identity, once each ───────────────────
    let near = tagmsg_deliveries(
        &mut rx_near,
        &act_id,
        S2S_SETTLE,
        Duration::from_millis(1500),
    )
    .await;
    assert_eq!(
        near, 1,
        "the session on the offering server is handed the event exactly once"
    );
    let far = tagmsg_deliveries(
        &mut rx_far,
        &act_id,
        S2S_SETTLE,
        Duration::from_millis(1500),
    )
    .await;
    assert_eq!(
        far, 1,
        "and so is the session a hop away — one event, one delivery, \
         recognized by the id its signer minted"
    );

    // ── one task, one row, one state, on both servers ───────────────
    //
    // The home names itself by saying nothing: an empty origin is "minted
    // here", and only a server that did not mint a task writes down whose it
    // is.
    for (name, addr, home) in [
        ("A", &srv_a.web_addr, ""),
        ("B", &srv_b.web_addr, id_a.as_str()),
    ] {
        let body = act_task(addr, &act_id)
            .await
            .unwrap_or_else(|| panic!("{name} answers for the task"));
        assert_eq!(
            body["task"]["state"].as_str(),
            Some("offered"),
            "a directed offer stands as offered on {name}: {body}"
        );
        assert_eq!(
            body["task"]["offeree"].as_str(),
            Some(agent.did.as_str()),
            "and names the identity it was directed at on {name}: {body}"
        );
        assert_eq!(
            body["task"]["origin"].as_str(),
            Some(home),
            "both servers agree which one referees the task: {body}"
        );
        assert_eq!(
            body["events"].as_array().map(Vec::len),
            Some(1),
            "one offer, filed once, on {name}: {body}"
        );
        assert_eq!(
            listed_rows(addr, &act_id).await,
            1,
            "and the listing an inbox reads shows it once on {name}"
        );
    }

    ha.quit(None).await.ok();
    h_near.quit(None).await.ok();
    h_far.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a task that lives in a direct conversation ────────────────────────────
//
// One task's whole life — offered, accepted, completed — between two people
// on different servers, held in a DM rather than a channel.
//
// What a DM changes is the venue. A signature covers the canonical DM key —
// the sorted DID pair, which both ends and any peer rebuild identically — and
// never the wire target, which is whichever name the sender happened to
// address: a `did:` one way, a nick the other. So the receiving server has to
// file the event under the two-person key rather than under what it was
// addressed to, the same re-keying a relayed delete already does. Get that
// wrong and every peer files a venue no signer signed.
//
// The home's receipts are held to the same rule from the other side. A server
// signs under a `did:web:` name, which is not one of the conversation's two
// participants, so a venue derived from that signer would be a pair of DIDs
// the conversation never had: a receipt's venue is the task's own, read from
// the log.
//
// Read through REST as a participant: a DM venue answers to the two people in
// it and nobody else, so each server is asked with the bearer of the user who
// is actually on it.

/// Register, keeping the API bearer the server hands out at SASL success.
///
/// The bearer is the connection's session id, which the client learns only
/// from that notice — and it is what authorizes a REST read of a venue that
/// is not public, a DM above all.
async fn wait_auth_and_bearer(rx: &mut mpsc::Receiver<Event>) -> String {
    let mut bearer = String::new();
    timeout(EVENT_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(Event::ServerNotice { text }) => {
                    if let Some(sid) = text.strip_prefix("API-BEARER ") {
                        bearer = sid.trim().to_string();
                    }
                }
                Some(Event::Registered { .. }) => return,
                Some(_) => continue,
                None => panic!("channel closed before registration"),
            }
        }
    })
    .await
    .expect("timeout waiting for registration");
    assert!(
        !bearer.is_empty(),
        "the server hands out an API bearer on SASL success"
    );
    bearer
}

/// One task's whole REST answer as a caller the venue admits — the live row,
/// the event log, or both.
///
/// Unlike [`act_task`] this does not require a live row: a finished task
/// answers `task: null` beside the history that outlives it, and that answer
/// is exactly what a terminal state looks like here.
async fn act_body_as(web_addr: &str, act_id: &str, bearer: &str) -> Option<serde_json::Value> {
    let url = format!("http://{web_addr}/api/v1/actions/{act_id}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

/// Poll a server, as a caller the venue admits, until the task's state is
/// `want`; return what it last said.
async fn await_state_as(
    web_addr: &str,
    act_id: &str,
    bearer: &str,
    want: &str,
    within: Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + within;
    let mut last = String::from("<no answer>");
    while tokio::time::Instant::now() < deadline {
        if let Some(body) = act_body_as(web_addr, act_id, bearer).await {
            last = match body["task"]["state"].as_str() {
                Some(state) => state.to_string(),
                // A finished task drops out of the view and keeps its log.
                None if body["events"].as_array().is_some_and(|e| !e.is_empty()) => {
                    "<finished>".to_string()
                }
                None => "<absent>".to_string(),
            };
            if last == want {
                return last;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last
}

/// Sign one act TAGMSG for a direct conversation and send it.
///
/// The signed venue is the canonical DM key built from the two DIDs — never
/// `target`, which is only how the sender addressed the other person.
async fn send_act_dm(
    handle: &client::ClientHandle,
    sender_did: &str,
    other_did: &str,
    target: &str,
    signing: &ed25519_dalek::SigningKey,
    act_tags: &[(&str, &str)],
) -> String {
    let venue = freeq_sdk::chatsig::dm_venue(sender_did, other_did);
    let id = freeq_sdk::chatsig::new_event_id();
    let sig = freeq_sdk::act::sign_act(act_tags.iter().copied(), &venue, &id, signing)
        .expect("act tags present");
    let wire: Vec<String> = act_tags
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .chain([
            format!("{}={id}", freeq_sdk::chatsig::EVENT_ID_TAG),
            format!("+freeq.at/sig={sig}"),
        ])
        .collect();
    handle
        .raw(&format!("@{} TAGMSG {target}", wire.join(";")))
        .await
        .ok();
    id
}

/// One event of a task, by the verb its signed document names.
fn event_with_verb<'a>(body: &'a serde_json::Value, verb: &str) -> Option<&'a serde_json::Value> {
    body["events"]
        .as_array()?
        .iter()
        .find(|e| doc_field(e, "act-verb") == verb)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_task_in_a_direct_message_runs_its_whole_life_across_servers() {
    const SEED_A: u8 = 210;
    const SEED_B: u8 = 211;
    let alice = TestId::new("did:plc:alicedmtask");
    let bob = TestId::new("did:plc:bobdmtask");
    let (srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    let bearer_b = wait_auth_and_bearer(&mut rxb).await;
    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    let bearer_a = wait_auth_and_bearer(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    let _ = &mut rxa;

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    // The one string both servers must arrive at, from opposite ends and
    // opposite wire targets.
    let dm_venue = freeq_sdk::chatsig::dm_venue(&alice.did, &bob.did);

    // ── the offer, directed at the person on the other server ───────
    //
    // Repeated until B holds it: B has no key for alice until its own
    // fetch fills the store off the delivery path, and an event it cannot
    // check yet is parked rather than filed. The same warm-up every act test
    // here does.
    let mut act_id = String::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_dm(
            &ha,
            &alice.did,
            &bob.did,
            &bob.did,
            &key_a,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", alice.did.as_str()),
                ("+freeq.at/act-to", bob.did.as_str()),
                ("+freeq.at/act-title", "a-task-in-a-dm"),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if act_body_as(&srv_b.web_addr, &id, &bearer_b)
            .await
            .is_some_and(|b| b["task"].is_object())
        {
            act_id = id;
            break;
        }
    }
    assert!(
        !act_id.is_empty(),
        "a task offered in a DM must reach the other person's server; B's log \
         says: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Both servers file it under the canonical DM key rather than under the
    // name it was addressed to — which is what makes the signature check out
    // on both.
    for (name, addr, bearer) in [
        ("A", &srv_a.web_addr, &bearer_a),
        ("B", &srv_b.web_addr, &bearer_b),
    ] {
        let body = act_body_as(addr, &act_id, bearer)
            .await
            .unwrap_or_else(|| panic!("{name} answers for the task"));
        assert_eq!(
            body["venue"].as_str(),
            Some(dm_venue.as_str()),
            "{name} must file a DM task under the two-person key: {body}"
        );
        assert_eq!(
            body["task"]["state"].as_str(),
            Some("offered"),
            "a directed offer opens as offered on {name}: {body}"
        );
        assert_eq!(body["task"]["offeree"].as_str(), Some(bob.did.as_str()));
    }

    // ── accepted from the other end of the conversation ─────────────
    //
    // Bob answers to a `did:` too, and his server derives the same venue from
    // the other side of the pair. The task is A's, so B files his accept and
    // carries it home rather than ruling on it.
    send_act_dm(
        &hb,
        &bob.did,
        &alice.did,
        &alice.did,
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "accept"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    for (name, addr, bearer) in [
        ("A", &srv_a.web_addr, &bearer_a),
        ("B", &srv_b.web_addr, &bearer_b),
    ] {
        let state = await_state_as(addr, &act_id, bearer, "assigned", S2S_SETTLE).await;
        assert_eq!(
            state,
            "assigned",
            "{name} must follow the home's ruling on the accept; B's log says: {}",
            server_log(&srv_b)
                .lines()
                .filter(|l| l.contains("task") || l.contains("verdict="))
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        );
        let body = act_body_as(addr, &act_id, bearer).await.expect("an answer");
        assert_eq!(body["task"]["assignee"].as_str(), Some(bob.did.as_str()));
    }

    // ── and finished by the person who took it ──────────────────────
    send_act_dm(
        &hb,
        &bob.did,
        &alice.did,
        &alice.did,
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "complete"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    for (name, addr, bearer) in [
        ("A", &srv_a.web_addr, &bearer_a),
        ("B", &srv_b.web_addr, &bearer_b),
    ] {
        // A finished task leaves the live view and keeps its whole log: that
        // pair — no row, every event still there — is what terminal looks
        // like here.
        let state = await_state_as(addr, &act_id, bearer, "<finished>", S2S_SETTLE).await;
        assert_eq!(
            state, "<finished>",
            "{name} must end the task where its home ended it"
        );
        let body = act_body_as(addr, &act_id, bearer).await.expect("an answer");
        assert!(
            body["task"].is_null(),
            "a completed task is out of the live view on {name}: {body}"
        );
        assert_eq!(
            body["events"].as_array().map(Vec::len),
            Some(5),
            "{name} holds the offer, the accept, the completion and the home's \
             word about each of the two moves: {body}"
        );
        assert_eq!(
            body["venue"].as_str(),
            Some(dm_venue.as_str()),
            "the finished task is still answered for under the DM key on {name}"
        );
        let complete = event_with_verb(&body, "complete")
            .unwrap_or_else(|| panic!("{name} holds the completion"));
        assert_eq!(
            complete["confirm_state"].as_str(),
            Some("confirmed"),
            "the home ruled on the completion, and {name} says so: {complete}"
        );
        // The home signs under a name that is not one of this conversation's
        // two participants, and its receipt still belongs to the conversation.
        for receipt in body["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| doc_field(e, "act-verb") == "confirm")
        {
            assert_eq!(
                receipt["venue"].as_str(),
                Some(dm_venue.as_str()),
                "a receipt takes the task's venue, not one built from its \
                 signer, on {name}: {receipt}"
            );
        }
    }

    // A DM answers to the two people in it and to nobody else: an
    // unauthenticated caller is refused outright rather than served a
    // conversation they are not in.
    let anon = reqwest::get(&format!(
        "http://{}/api/v1/actions/{act_id}",
        srv_b.web_addr
    ))
    .await
    .expect("the endpoint answers");
    assert_eq!(
        anon.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a DM task must not be readable without a participant's bearer"
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── work finished while the task's home is away ───────────────────────────
//
// The never-lose guarantee at the one point where losing would matter most:
// the event that ends the work. A task assigned across the link is completed
// by its worker while the server that referees it is down. The completion is
// signed, so it is filed and kept and shown at once — and it decides nothing,
// because the only server that can order it is not there. The home comes back
// and orders it, and both servers end the task on the home's word.
//
// Distinct from the claim case above: a claim can be re-offered to somebody
// else if it is lost, and a completion cannot. Work that was done and whose
// record went missing is the state this design exists to make impossible.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_completion_signed_while_the_home_is_away_is_ordered_when_it_returns() {
    // B is the server that stays up, so it must be the one that keeps its
    // outgoing link: B is what has to reach A again.
    const SEED_A: u8 = 220;
    const SEED_B: u8 = 221;
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_b < id_a,
        "the server that stays up keeps its outgoing link"
    );

    let alice = TestId::new("did:plc:alicedone");
    let bob = TestId::new("did:plc:bobdone");
    let (mut srv_a, srv_b) = spawn_pair_with_seeds(&[&alice, &bob], SEED_A, SEED_B).await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#done").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#done").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[67u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#done",
        &key_a,
        &alice.did,
        "finished-while-nobody-was-refereeing",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the offer must reach B while the home is still up; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── the work is taken, and the home says so, while it still can ──
    send_act_as(
        &hb,
        "#done",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;
    let (on_a, on_b) = await_assignees(&srv_a.web_addr, &srv_b.web_addr, &act_id).await;
    assert_eq!(
        (on_a.as_deref(), on_b.as_deref()),
        (Some(bob.did.as_str()), Some(bob.did.as_str())),
        "both servers must hold the task assigned before the outage, or the \
         completion below has nothing to end"
    );

    // ── the home goes away, and the work is finished anyway ──────────
    ha.quit(None).await.ok();
    srv_a.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;

    send_act_as(
        &hb,
        "#done",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "complete"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    let filed = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut away = serde_json::Value::Null;
    while tokio::time::Instant::now() < filed {
        away = act_body(&srv_b.web_addr, &act_id).await.unwrap_or_default();
        if verb_states(&away).iter().any(|(v, _)| v == "complete") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        verb_states(&away)
            .iter()
            .find(|(verb, _)| verb == "complete")
            .map(|(_, state)| state.as_str()),
        Some("unconfirmed"),
        "the finished work is on file at once and waiting on its home: {:?}",
        verb_states(&away)
    );
    assert_eq!(
        away["task"]["state"].as_str(),
        Some("assigned"),
        "and the task is not over until the home says it is: {away}"
    );

    // ── the home comes back and orders it ────────────────────────────
    srv_a.start_again().await;
    let (ha2, mut rxa2) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa2).await;
    warm_link(&ha2, &bob.did, &mut rxb).await;

    for (name, addr) in [("A", &srv_a.web_addr), ("B", &srv_b.web_addr)] {
        assert!(
            await_task_gone(addr, &act_id, Duration::from_secs(150)).await,
            "{name} must end the task once its home has ordered the \
             completion; {name} says: {:?}",
            act_body(addr, &act_id).await.map(|b| verb_states(&b))
        );
        let body = act_body(addr, &act_id)
            .await
            .expect("the log outlives the task");
        assert_eq!(
            verb_states(&body)
                .iter()
                .find(|(verb, _)| verb == "complete")
                .map(|(_, state)| state.as_str()),
            Some("confirmed"),
            "and the work that was done while nobody could order it is \
             ordered now, on {name}: {:?}",
            verb_states(&body)
        );
    }

    ha2.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── a peer that does not speak task events ────────────────────────────────
//
// The capability gate, watched between two real servers. A peer that never
// declared `act` is never sent a task-tagged Tagmsg: a relay that stripped
// tags it does not understand would break the signature over them, and
// downstream that reads as forgery when the real cause is an old server. So
// the events are withheld and the withholding is logged, while everything
// else — the plain-text companion line a bot posts beside its task events
// above all — crosses as it always did.
//
// The far server is made an onlooker with `--s2s-undeclared-capabilities`,
// which is how this harness reproduces a peer predating a capability without
// an older build to run.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_peer_that_never_declared_act_stays_an_onlooker() {
    const SEED_A: u8 = 214;
    const SEED_B: u8 = 215;
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    let alice = TestId::new("did:plc:aliceonlook");
    let bob = TestId::new("did:plc:bobonlook");
    let (srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &[],
        &["--s2s-undeclared-capabilities", "act"],
    )
    .await;

    // Bob asks for the task capability, so that if B held the event at all it
    // would be handed to him. It never is, and that is the point.
    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    request_act_cap(&hb, &mut rxb).await;
    hb.join("#onlook").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#onlook").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[71u8; 32]);
    register_key(&ha, &key_a).await;

    // The offer is not repeated until the far server holds it, the way every
    // other test's is: the far server is never going to hold it. It is
    // repeated until *this* server does, which needs no key it has to fetch.
    let mut act_id = String::new();
    let deadline = tokio::time::Instant::now() + S2S_SETTLE;
    while tokio::time::Instant::now() < deadline {
        let id = send_act_as(
            &ha,
            "#onlook",
            &key_a,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", alice.did.as_str()),
                ("+freeq.at/act-title", "not-for-an-old-peer"),
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        if act_task(&srv_a.web_addr, &id).await.is_some() {
            act_id = id;
            break;
        }
    }
    assert!(
        !act_id.is_empty(),
        "the offering server must hold its own task; A's log: {}",
        server_log(&srv_a)
            .lines()
            .filter(|l| l.contains("verdict=") || l.contains("act"))
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The prose a bot posts beside its task events is an ordinary message and
    // crosses like one. Sent after the task event, so its arrival also says
    // the link carried everything that went before it.
    const COMPANION: &str = "alice offers: not-for-an-old-peer";
    ha.privmsg("#onlook", COMPANION).await.ok();
    assert_eq!(
        try_recv_message(&mut rxb, COMPANION, S2S_SETTLE).await,
        Some("#onlook".to_string()),
        "an onlooker still reads the human half of what happens in the room"
    );

    // And never the machine half.
    assert_eq!(
        tagmsg_deliveries(
            &mut rxb,
            &act_id,
            Duration::from_millis(1500),
            Duration::from_millis(500)
        )
        .await,
        0,
        "a session on a peer that never declared act is handed no task event"
    );
    assert!(
        act_task(&srv_b.web_addr, &act_id).await.is_none(),
        "and its server files none: {:?}",
        act_body(&srv_b.web_addr, &act_id).await
    );

    // A wrong capability declaration must never fail silent, so the server
    // that withheld the event names both the peer it withheld it from and the
    // event it withheld, by the id its signer minted.
    let log_a = server_log(&srv_a);
    let withheld = log_a
        .lines()
        .filter(|l| l.contains("task event withheld"))
        .any(|l| l.contains(&id_b) && l.contains(&act_id));
    assert!(
        withheld,
        "the withholding is logged, naming the peer and the task event; \
         A's log: {}",
        log_a
            .lines()
            .filter(|l| l.contains("withheld") || l.contains("capabilit"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    ha.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}

// ── the addressed route, with nothing else able to carry it ───────────────
//
// The away-home test proves a home learns of a transition made while it was
// down; it does not prove *which* path carried it, because a returning server
// asks its peers for what it missed within a few seconds and the first route
// retry is not due for thirty. Here the peer that stays up declares no
// `catchup`, so the returning home never asks it for anything — and the
// addressed route is then the only thing left that can carry the claim. The
// home learning it at all is the proof.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e federation harness; run with --ignored"]
async fn a_transition_reaches_an_absent_home_by_the_route_when_nothing_else_can() {
    // B stays up, so B keeps its outgoing link — B is what has to reach A.
    const SEED_A: u8 = 238;
    const SEED_B: u8 = 239;
    // The first retry is not due for thirty seconds and each failed attempt
    // pushes the next one further out, so the home's return has to be waited
    // through rather than watched for.
    const PAST_THE_BACKOFF: Duration = Duration::from_secs(150);
    let id_a = iroh::SecretKey::from_bytes(&[SEED_A; 32])
        .public()
        .to_string();
    let id_b = iroh::SecretKey::from_bytes(&[SEED_B; 32])
        .public()
        .to_string();
    assert!(
        id_b < id_a,
        "the server that stays up keeps its outgoing link"
    );

    let alice = TestId::new("did:plc:aliceroutealone");
    let bob = TestId::new("did:plc:bobroutealone");
    let (mut srv_a, srv_b) = spawn_pair_with_seeds_and_args(
        &[&alice, &bob],
        SEED_A,
        SEED_B,
        &[],
        &["--s2s-undeclared-capabilities", "catchup"],
    )
    .await;

    let (hb, mut rxb) = connect(&srv_b, &bob, "bob");
    wait_auth_and_register(&mut rxb).await;
    hb.join("#routealone").await.unwrap();

    let (ha, mut rxa) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa).await;
    warm_link(&ha, &bob.did, &mut rxb).await;
    ha.join("#routealone").await.unwrap();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[79u8; 32]);
    register_key(&ha, &key_a).await;
    register_key(&hb, &key_b).await;

    let act_id = offer_until_the_peer_holds_it(
        &ha,
        "#routealone",
        &key_a,
        &alice.did,
        "carried-and-nothing-else",
        &srv_b.web_addr,
    )
    .await;
    assert!(
        !act_id.is_empty(),
        "the offer must reach B before the outage; B's log: {}",
        server_log(&srv_b)
            .lines()
            .filter(|l| l.contains("verdict="))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ── the home goes away, and the task is claimed anyway ───────────
    ha.quit(None).await.ok();
    srv_a.stop();
    tokio::time::sleep(Duration::from_secs(1)).await;

    send_act_as(
        &hb,
        "#routealone",
        &key_b,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", bob.did.as_str()),
            ("+freeq.at/act-id", act_id.as_str()),
        ],
    )
    .await;

    // ── the home comes back, and asks nobody ─────────────────────────
    srv_a.start_again().await;
    let (ha2, mut rxa2) = connect(&srv_a, &alice, "alice");
    wait_auth_and_register(&mut rxa2).await;
    warm_link(&ha2, &bob.did, &mut rxb).await;

    let on_a = await_assignee(&srv_a.web_addr, &act_id, PAST_THE_BACKOFF).await;
    assert_eq!(
        on_a.as_deref(),
        Some(bob.did.as_str()),
        "with catch-up impossible against this peer, the only thing that can \
         have carried the claim is the route addressed to the task's home; A \
         says {:?}",
        act_body(&srv_a.web_addr, &act_id)
            .await
            .map(|b| verb_states(&b))
    );

    // And the answer still comes back the other way, which is the half a
    // route exists for: B authored the claim and has to learn it stood.
    let on_b = await_assignee(&srv_b.web_addr, &act_id, S2S_SETTLE).await;
    assert_eq!(
        on_b.as_deref(),
        Some(bob.did.as_str()),
        "B follows the home's receipt: {:?}",
        act_body(&srv_b.web_addr, &act_id)
            .await
            .map(|b| verb_states(&b))
    );

    ha2.quit(None).await.ok();
    hb.quit(None).await.ok();
    drop((srv_a, srv_b));
}
