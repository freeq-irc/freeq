//! L1 — the AV session-layer chaos suite (`docs/AV-MAP.md` §7).
//!
//! A real server and real `freeq-sdk` clients driving the call state machine
//! through the events that broke it in production: a blip, a joiner arriving
//! during that blip, a join into a session that already ended, two starts in
//! the same tick, a server restart mid-call, a rename mid-call.
//!
//! No media and no `av-native` needed. This layer proves the state machine's
//! *temporal* behavior — who is on the roster, at which instant, under which
//! session id — which is exactly the part of an AV call that has no audio in
//! it and therefore no excuse to be untested in CI. Hearing is L2's job
//! (`freeq-av-client/src/bin/avharness.rs`).
//!
//! Every assertion below names the invariant it enforces (I1–I6 in
//! `docs/AV-TEST-PLAN.md` §1) and the scenario it automates (§5.x).
//!
//! Timing: the AV disconnect grace is `--av-grace-secs`, and these tests run
//! the server at [`GRACE_SECS`] so crossing the expiry boundary costs a second
//! instead of the production half-minute. Budgets are generous on purpose —
//! a timing test that flakes teaches people to re-run instead of to look.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};
use freeq_sdk::event::Event;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The AV disconnect grace these tests run the server at. Production is 30 s
/// (`docs/AV-MAP.md` §2); the boundary behavior is identical, only the wait is
/// shorter. Long enough that a test doing two round trips inside the window
/// isn't racing the timer on a loaded machine.
const GRACE_SECS: u64 = 3;

/// How long after grace expiry teardown is allowed to take. I4 in the test
/// plan says "within grace+5 s".
const TEARDOWN_BUDGET: Duration = Duration::from_secs(GRACE_SECS + 5);

/// I4's other half: a *clean* leave has no grace to wait out, so the roster
/// must follow within a couple of seconds.
const ROSTER_BUDGET: Duration = Duration::from_secs(2);

// ── rig ─────────────────────────────────────────────────────────────

/// A test identity the server can verify without touching the network.
struct Id {
    did: String,
    secret: Vec<u8>,
}

impl Id {
    fn new(name: &str) -> Self {
        let key = PrivateKey::generate_ed25519();
        Id {
            did: format!("did:plc:avlife_{name}"),
            secret: key.secret_bytes(),
        }
    }

    fn key(&self) -> PrivateKey {
        PrivateKey::ed25519_from_bytes(&self.secret).unwrap()
    }

    fn signer(&self) -> Arc<dyn ChallengeSigner> {
        Arc::new(KeySigner::new(self.did.clone(), self.key()))
    }
}

fn resolver(ids: &[&Id]) -> DidResolver {
    let mut docs = HashMap::new();
    for id in ids {
        docs.insert(
            id.did.clone(),
            did::make_test_did_document(&id.did, &id.key().public_key_multibase()),
        );
    }
    DidResolver::static_map(docs)
}

/// A server with both listeners up. The `SharedState` comes back because
/// scenario 8 has to install an SFU the way `run()` does — `start_with_web`
/// is the in-process path and never initializes one.
struct Rig {
    irc: SocketAddr,
    web: SocketAddr,
    #[allow(dead_code)]
    state: Arc<freeq_server::server::SharedState>,
    _handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start_rig(name: &str, resolver: DidResolver) -> Rig {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: format!("test-avlife-{name}"),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        av_grace_secs: GRACE_SECS,
        ..Default::default()
    };
    let (irc, web, handle, state) = freeq_server::server::Server::with_resolver(config, resolver)
        .start_with_web_state()
        .await
        .unwrap();
    Rig {
        irc,
        web,
        state,
        _handle: handle,
    }
}

// ── clients ─────────────────────────────────────────────────────────

/// One connected client plus the bits of its stream the tests care about.
struct Peer {
    nick: String,
    inst: String,
    handle: ClientHandle,
    events: mpsc::Receiver<Event>,
    /// This connection's REST bearer, learned from the `API-BEARER` notice the
    /// server emits on SASL success. Empty for guests (they have no DID, so
    /// no bearer identity to hand out).
    bearer: String,
}

async fn connect_guest(addr: SocketAddr, nick: &str) -> Peer {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(config, None);
    wait_for(&mut events, 5000, |e| matches!(e, Event::Registered { .. }))
        .await
        .unwrap_or_else(|| panic!("{nick}: never registered"));
    Peer {
        nick: nick.to_string(),
        inst: instance_for(nick),
        handle,
        events,
        bearer: String::new(),
    }
}

async fn connect_did(addr: SocketAddr, id: &Id, nick: &str) -> Peer {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(config, Some(id.signer()));
    let mut bearer = String::new();
    let mut authed = false;
    let mut registered = false;
    // Both facts arrive as separate lines and the bearer rides a raw NOTICE,
    // so collect until we have all three rather than waiting on one event.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while !(authed && registered && !bearer.is_empty()) {
        let Some(e) = next_before(&mut events, deadline).await else {
            panic!(
                "{nick}: registration incomplete (auth={authed} reg={registered} bearer={})",
                !bearer.is_empty()
            );
        };
        match e {
            Event::Authenticated { .. } => authed = true,
            Event::Registered { .. } => registered = true,
            Event::RawLine(l) => {
                if let Some(i) = l.find("API-BEARER ") {
                    bearer = l[i + "API-BEARER ".len()..].trim().to_string();
                }
            }
            _ => {}
        }
    }
    Peer {
        nick: nick.to_string(),
        inst: instance_for(nick),
        handle,
        events,
        bearer,
    }
}

/// A stable per-nick instance id. Real clients randomize; tests want the
/// roster assertions to name something a failure message can print.
fn instance_for(nick: &str) -> String {
    format!("inst-{nick}")
}

impl Peer {
    async fn join(&mut self, channel: &str) {
        self.handle.join(channel).await.unwrap();
        wait_for(
            &mut self.events,
            5000,
            |e| matches!(e, Event::Joined { channel: c, .. } if c == channel),
        )
        .await
        .unwrap_or_else(|| panic!("{}: never joined {channel}", self.nick));
    }

    async fn av_start(&self, channel: &str) {
        self.handle
            .av_start(channel, &self.inst, None)
            .await
            .unwrap();
    }

    async fn av_join(&self, channel: &str, session: &str) {
        self.handle
            .av_join(channel, session, &self.inst)
            .await
            .unwrap();
    }

    async fn av_leave(&self, channel: &str, session: &str) {
        self.handle
            .av_leave(channel, session, &self.inst)
            .await
            .unwrap();
    }

    /// Wait for an `av-state` TAGMSG with the given action, returning its tags.
    async fn expect_av_state(&mut self, action: &str, ms: u64) -> HashMap<String, String> {
        let got = wait_for(&mut self.events, ms, |e| {
            av_tags(e)
                .is_some_and(|t| t.get("+freeq.at/av-state").map(String::as_str) == Some(action))
        })
        .await;
        match got {
            Some(e) => av_tags(&e).unwrap().clone(),
            None => panic!("{}: no av-state={action} within {ms}ms", self.nick),
        }
    }

    /// Wait for an `av-error` TAGMSG, returning its tags.
    async fn expect_av_error(&mut self, ms: u64) -> HashMap<String, String> {
        let got = wait_for(&mut self.events, ms, |e| {
            av_tags(e).is_some_and(|t| t.contains_key("+freeq.at/av-error"))
        })
        .await;
        match got {
            Some(e) => av_tags(&e).unwrap().clone(),
            None => panic!("{}: no +freeq.at/av-error within {ms}ms", self.nick),
        }
    }
}

fn av_tags(e: &Event) -> Option<&HashMap<String, String>> {
    match e {
        Event::TagMsg { tags, .. } => Some(tags),
        _ => None,
    }
}

async fn wait_for(
    events: &mut mpsc::Receiver<Event>,
    ms: u64,
    pred: impl Fn(&Event) -> bool,
) -> Option<Event> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let e = next_before(events, deadline).await?;
        if pred(&e) {
            return Some(e);
        }
    }
}

async fn next_before(
    events: &mut mpsc::Receiver<Event>,
    deadline: tokio::time::Instant,
) -> Option<Event> {
    let now = tokio::time::Instant::now();
    if now >= deadline {
        return None;
    }
    timeout(deadline - now, events.recv()).await.ok().flatten()
}

// ── the blip ────────────────────────────────────────────────────────

/// A loopback relay between a client and the server, with a cut switch.
///
/// §5.2's blip is a socket that *goes away* — a phone entering a tunnel, a
/// laptop lid closing — not a user quitting. The distinction is the whole
/// scenario: a QUIT tears the call down immediately, a vanished socket is
/// supposed to keep the roster slot for the grace window. The SDK owns its
/// stream once connected, so the only place to cut is in between.
struct Blip {
    addr: SocketAddr,
    cut: Arc<tokio::sync::Notify>,
}

impl Blip {
    async fn to(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cut = Arc::new(tokio::sync::Notify::new());
        let cut_for_loop = cut.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let Ok(mut server) = TcpStream::connect(upstream).await else {
                    break;
                };
                let cut = cut_for_loop.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        _ = cut.notified() => {}
                    }
                    // Both halves drop here. The server's read returns EOF with
                    // no QUIT ahead of it — which is exactly what it sees when
                    // a real client's network drops out from under it.
                });
            }
        });
        Blip { addr, cut }
    }

    fn cut(&self) {
        self.cut.notify_waiters();
    }
}

// ── roster (the REST view web subscribes from) ──────────────────────

async fn session_json(web: SocketAddr, sid: &str, debug: bool) -> serde_json::Value {
    let q = if debug { "?debug=1" } else { "" };
    reqwest::Client::new()
        .get(format!("http://{web}/api/v1/sessions/{sid}{q}"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("session detail request")
        .json()
        .await
        .expect("session detail json")
}

/// The set of instance ids the roster currently lists as in the call. This is
/// the thing web computes broadcast paths from, so it is the roster in the
/// sense that matters.
fn roster_instances(v: &serde_json::Value) -> BTreeSet<String> {
    v["participants"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p["instance_id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn roster_nicks(v: &serde_json::Value) -> BTreeSet<String> {
    v["participants"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p["nick"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Poll the roster until it satisfies `pred`, or fail naming what it looked
/// like when the budget ran out. The budget is the assertion: "converges" is
/// only interesting with a deadline on it.
async fn await_roster(
    web: SocketAddr,
    sid: &str,
    budget: Duration,
    pred: impl Fn(&serde_json::Value) -> bool,
    desc: &str,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let last = session_json(web, sid, false).await;
        if pred(&last) {
            return last;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "roster never converged: {desc} (budget {budget:?}); last = {}",
                serde_json::to_string(&last).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Active sessions the server admits to, filtered to one channel.
async fn active_sessions_for(web: SocketAddr, channel: &str) -> Vec<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{web}/api/v1/sessions"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("sessions list")
        .json()
        .await
        .expect("sessions json");
    body["sessions"]
        .as_array()
        .map(|ss| {
            ss.iter()
                .filter(|s| {
                    s["channel"]
                        .as_str()
                        .is_some_and(|c| c.eq_ignore_ascii_case(channel))
                })
                .filter_map(|s| s["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ════════════════════════════════════════════════════════════════════
// §5.1 — start, join, leave: the roster follows, under one session id
// ════════════════════════════════════════════════════════════════════

/// A, B, C in one call. Asserts I2 (the roster lists exactly the live
/// participants, with their instances), I5 (everyone holds the same session
/// id), and I4 on the clean-leave path (a leave leaves the roster within
/// [`ROSTER_BUDGET`]). The last leave ends the session and the `ended`
/// broadcast reaches the people still in the channel — the transition whose
/// absence, in production, left clients publishing into a dead session.
#[tokio::test]
async fn start_join_leave_converges() {
    let rig = start_rig("converge", DidResolver::static_map(HashMap::new())).await;
    let chan = "#av-converge";

    let mut a = connect_guest(rig.irc, "conv_a").await;
    let mut b = connect_guest(rig.irc, "conv_b").await;
    let mut c = connect_guest(rig.irc, "conv_c").await;
    a.join(chan).await;
    b.join(chan).await;
    c.join(chan).await;

    a.av_start(chan).await;
    let started = a.expect_av_state("started", 5000).await;
    let sid = started["+freeq.at/av-id"].clone();

    // B and C see the same id A was handed (I5) before they join it.
    let b_sees = b.expect_av_state("started", 5000).await;
    let c_sees = c.expect_av_state("started", 5000).await;
    assert_eq!(b_sees["+freeq.at/av-id"], sid, "I5: B holds A's session id");
    assert_eq!(c_sees["+freeq.at/av-id"], sid, "I5: C holds A's session id");

    b.av_join(chan, &sid).await;
    b.expect_av_state("joined", 5000).await;
    c.av_join(chan, &sid).await;
    c.expect_av_state("joined", 5000).await;

    // I2: exactly {A,B,C}, each under its own instance. An extra row here is
    // a ghost tile on every web client; a missing one is silence in one
    // direction only.
    let roster = await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| roster_instances(v).len() == 3,
        "three participants after two joins",
    )
    .await;
    assert_eq!(
        roster_nicks(&roster),
        BTreeSet::from(["conv_a".into(), "conv_b".into(), "conv_c".into()]),
        "I2: roster nicks"
    );
    assert_eq!(
        roster_instances(&roster),
        BTreeSet::from([a.inst.clone(), b.inst.clone(), c.inst.clone()]),
        "I2: roster instances (web builds broadcast paths from these)"
    );

    // I4, clean-leave half: A leaves, and the roster stops describing A.
    a.av_leave(chan, &sid).await;
    let roster = await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| !roster_instances(v).contains(&a.inst),
        "A's slot gone after av-leave",
    )
    .await;
    assert_eq!(
        roster_instances(&roster),
        BTreeSet::from([b.inst.clone(), c.inst.clone()]),
        "I2: only B and C remain"
    );

    // Last one out ends the session, and the people still in the channel are
    // told. A client that misses this keeps publishing into a dead id (F3).
    b.av_leave(chan, &sid).await;
    b.expect_av_state("left", 5000).await;
    c.av_leave(chan, &sid).await;
    let ended_b = b.expect_av_state("ended", 5000).await;
    let ended_c = c.expect_av_state("ended", 5000).await;
    assert_eq!(ended_b["+freeq.at/av-id"], sid);
    assert_eq!(ended_c["+freeq.at/av-id"], sid);

    let after = session_json(rig.web, &sid, false).await;
    assert!(
        roster_instances(&after).is_empty(),
        "an ended session has nobody on it: {after}"
    );
    assert!(
        active_sessions_for(rig.web, chan).await.is_empty(),
        "the channel has no active session once everyone leaves"
    );
}

// ════════════════════════════════════════════════════════════════════
// §5.2 / F2 — a blip, and a joiner arriving during it
// ════════════════════════════════════════════════════════════════════

/// The regression that produced the reported symptom. A's IRC drops without a
/// QUIT while A's media keeps flowing; B joins the call a moment later. The
/// join-time orphan reaper used to take A's slot on the spot, so every
/// roster-driven client (web) lost A's audio while announcement-driven clients
/// (native) kept hearing them — one-way deafness, class A.
///
/// Two assertions, one on each side of the boundary in `docs/AV-MAP.md` §2:
/// inside the grace the slot survives a join; at expiry it drops *and* the
/// channel is told (`av-state=left` carrying A's instance, which is what
/// clients key teardown on).
#[tokio::test]
async fn blip_with_joiner_keeps_slot() {
    // A must be a DID user: grace is only extended to an authenticated user's
    // last connection (`av::av_disconnect_deferred`) — a guest's slot is torn
    // down immediately, which is a different scenario.
    let alice = Id::new("blip");
    let rig = start_rig("blip", resolver(&[&alice])).await;
    let chan = "#av-blip";

    let blip = Blip::to(rig.irc).await;
    let mut a = connect_did(blip.addr, &alice, "blip_a").await;
    let mut b = connect_guest(rig.irc, "blip_b").await;
    a.join(chan).await;
    b.join(chan).await;

    a.av_start(chan).await;
    let started = a.expect_av_state("started", 5000).await;
    let sid = started["+freeq.at/av-id"].clone();
    b.expect_av_state("started", 5000).await;
    await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| roster_instances(v).contains(&a.inst),
        "A on the roster before the blip",
    )
    .await;

    // The tunnel. No QUIT, no av-leave — the socket is simply gone.
    blip.cut();

    // B joins while A is inside the grace window. This is the exact moment
    // that used to reap A.
    b.av_join(chan, &sid).await;
    b.expect_av_state("joined", 5000).await;

    let during = session_json(rig.web, &sid, false).await;
    assert!(
        roster_instances(&during).contains(&a.inst),
        "F2/I2: a grace-pending participant must survive the join-time reap — \
         roster was {during}"
    );
    assert!(
        roster_instances(&during).contains(&b.inst),
        "B is in the call too: {during}"
    );

    // Now let the grace expire. I4: the slot drops and the channel hears about
    // it within grace+5 s, naming A's instance.
    let left = b
        .expect_av_state("left", TEARDOWN_BUDGET.as_millis() as u64)
        .await;
    assert_eq!(left["+freeq.at/av-id"], sid);
    assert_eq!(
        left.get("+freeq.at/av-instance").map(String::as_str),
        Some(a.inst.as_str()),
        "the `left` must name the instance, not just the nick — clients key \
         teardown on the instance because it matches the media path"
    );

    let after = await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| !roster_instances(v).contains(&a.inst),
        "A's slot dropped at grace expiry",
    )
    .await;
    assert_eq!(
        roster_instances(&after),
        BTreeSet::from([b.inst.clone()]),
        "I2: only B remains after A's grace expires"
    );
}

// ════════════════════════════════════════════════════════════════════
// §5.3 / F3 — joining a session that already ended
// ════════════════════════════════════════════════════════════════════

/// A session that *was* real and has ended answers `join-failed` with its own
/// id echoed, so the joining client can match the failure to the call it
/// thinks it's in and tear down instead of ghost-publishing.
///
/// The other half of F3 — a session id that never existed at all — is pinned
/// in `av_error_signal.rs::rejected_join_emits_machine_readable_av_error`.
/// This is the half that actually happened in production on Jul 21: a live
/// call was force-ended under a client that had backgrounded, and its next
/// join went into the dead id.
#[tokio::test]
async fn dead_session_join_answers_error() {
    let rig = start_rig("dead", DidResolver::static_map(HashMap::new())).await;
    let chan = "#av-dead";

    let mut a = connect_guest(rig.irc, "dead_a").await;
    a.join(chan).await;
    a.av_start(chan).await;
    let started = a.expect_av_state("started", 5000).await;
    let sid = started["+freeq.at/av-id"].clone();

    // Solo call: A leaving ends it.
    a.av_leave(chan, &sid).await;
    a.expect_av_state("ended", 5000).await;
    assert!(
        active_sessions_for(rig.web, chan).await.is_empty(),
        "the session is gone before we try to join it"
    );

    // The client that missed the `ended` and still holds the id.
    a.av_join(chan, &sid).await;
    let err = a.expect_av_error(5000).await;
    assert_eq!(
        err.get("+freeq.at/av-error").map(String::as_str),
        Some("join-failed"),
        "machine-readable, not just a NOTICE — a NOTICE is invisible to code"
    );
    assert_eq!(
        err.get("+freeq.at/av-id").map(String::as_str),
        Some(sid.as_str()),
        "the av-id must echo the dead session so the client can match it to \
         the call state it needs to tear down"
    );
    assert!(
        err.contains_key("+freeq.at/av-reason"),
        "a human-readable reason rides along for the log"
    );
}

// ════════════════════════════════════════════════════════════════════
// §5.5 / F4 — two starts in the same tick
// ════════════════════════════════════════════════════════════════════

/// Both clients hit start before either round-trips. Exactly one session may
/// exist afterwards (I5), and the loser must be told which one won by id —
/// not left to guess from a timeout, and not left wedged in a solo call
/// nobody else is in.
///
/// Which one wins is nondeterministic and that is fine: the invariant is about
/// convergence, not about who gets there first.
#[tokio::test]
async fn concurrent_start_converges() {
    let rig = start_rig("race", DidResolver::static_map(HashMap::new())).await;
    let chan = "#av-race";

    let mut a = connect_guest(rig.irc, "race_a").await;
    let mut b = connect_guest(rig.irc, "race_b").await;
    a.join(chan).await;
    b.join(chan).await;

    // Same tick: neither send is awaited before the other goes out.
    let (ra, rb) = tokio::join!(
        a.handle.av_start(chan, &a.inst, None),
        b.handle.av_start(chan, &b.inst, None)
    );
    ra.unwrap();
    rb.unwrap();

    // Collect from both streams for a moment; one of them is the winner and
    // one holds a collision.
    let (a_states, a_errs) = drain_av(&mut a.events, 3000).await;
    let (b_states, b_errs) = drain_av(&mut b.events, 3000).await;

    let started: BTreeSet<String> = a_states
        .iter()
        .chain(b_states.iter())
        .filter(|t| t.get("+freeq.at/av-state").map(String::as_str) == Some("started"))
        .filter_map(|t| t.get("+freeq.at/av-id").cloned())
        .collect();
    assert_eq!(
        started.len(),
        1,
        "I5: exactly one session may be started by a simultaneous pair, got {started:?}"
    );
    let winner = started.into_iter().next().unwrap();

    let collisions: Vec<&HashMap<String, String>> = a_errs
        .iter()
        .chain(b_errs.iter())
        .filter(|t| t.get("+freeq.at/av-error").map(String::as_str) == Some("start-collision"))
        .collect();
    assert_eq!(
        collisions.len(),
        1,
        "exactly one starter loses the race, got {} collisions",
        collisions.len()
    );
    assert_eq!(
        collisions[0].get("+freeq.at/av-id").map(String::as_str),
        Some(winner.as_str()),
        "the collision must name the WINNING session so the loser can join it \
         instead of sitting in a call of one"
    );

    let active = active_sessions_for(rig.web, chan).await;
    assert_eq!(
        active,
        vec![winner.clone()],
        "I5: one channel, one session — a split here is mutual pairwise silence"
    );

    // And the loser converging on the named id lands in the same call.
    let loser = if a_errs.is_empty() { &mut b } else { &mut a };
    loser.av_join(chan, &winner).await;
    loser.expect_av_state("joined", 5000).await;
    await_roster(
        rig.web,
        &winner,
        ROSTER_BUDGET,
        |v| roster_instances(v).len() == 2,
        "both racers in the one surviving session",
    )
    .await;
}

/// Read `av-state` and `av-error` tag maps off a stream for `ms`, ignoring
/// everything else. Used where the interesting thing is the *set* of signals a
/// client got, not the first one.
async fn drain_av(
    events: &mut mpsc::Receiver<Event>,
    ms: u64,
) -> (Vec<HashMap<String, String>>, Vec<HashMap<String, String>>) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let (mut states, mut errs) = (Vec::new(), Vec::new());
    while let Some(e) = next_before(events, deadline).await {
        if let Some(t) = av_tags(&e) {
            if t.contains_key("+freeq.at/av-state") {
                states.push(t.clone());
            }
            if t.contains_key("+freeq.at/av-error") {
                errs.push(t.clone());
            }
        }
    }
    (states, errs)
}

// ════════════════════════════════════════════════════════════════════
// §5.4 / F5 — a rename mid-call
// ════════════════════════════════════════════════════════════════════

/// The roster path web subscribes to is `{session}/{nick}~{instance}`, so a
/// nick that changes mid-call points every roster-driven subscriber at a dead
/// path until the roster catches up. The contract is: re-send `av-join` with
/// the *same* instance and the slot is rejoined in place under the new nick —
/// one row, not two.
///
/// A DID user, because that is the case F5 describes (the server's own
/// custom-domain dot-strip renames authenticated users on reconnect) and
/// because a DID keeps the participant key stable across the rename.
#[tokio::test]
async fn rename_mid_call_updates_roster() {
    let alice = Id::new("rename");
    let rig = start_rig("rename", resolver(&[&alice])).await;
    let chan = "#av-rename";

    let mut a = connect_did(rig.irc, &alice, "ren_a").await;
    let mut b = connect_guest(rig.irc, "ren_b").await;
    a.join(chan).await;
    b.join(chan).await;

    a.av_start(chan).await;
    let started = a.expect_av_state("started", 5000).await;
    let sid = started["+freeq.at/av-id"].clone();
    b.av_join(chan, &sid).await;
    b.expect_av_state("joined", 5000).await;
    await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| roster_nicks(v).contains("ren_a"),
        "A on the roster under its original nick",
    )
    .await;

    a.handle.raw("NICK ren_a_renamed").await.unwrap();
    wait_for(
        &mut a.events,
        5000,
        |e| matches!(e, Event::NickChanged { new_nick, .. } if new_nick == "ren_a_renamed"),
    )
    .await
    .expect("A's rename never landed");

    // What every client must do after a mid-call rename: re-announce the same
    // instance so the roster follows the wire.
    a.av_join(chan, &sid).await;

    let roster = await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| roster_nicks(v).contains("ren_a_renamed"),
        "the roster follows the rename within 2s",
    )
    .await;
    assert!(
        !roster_nicks(&roster).contains("ren_a"),
        "F5: no orphan row under the old nick — roster-driven subscribers \
         would watch that dead path forever: {roster}"
    );
    assert_eq!(
        roster_instances(&roster),
        BTreeSet::from([a.inst.clone(), b.inst.clone()]),
        "the rename must not mint a second slot for the same instance: {roster}"
    );
    let a_rows = roster["participants"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter(|p| p["instance_id"].as_str() == Some(a.inst.as_str()))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(a_rows, 1, "exactly one row for A's instance: {roster}");
}

// ════════════════════════════════════════════════════════════════════
// §5.6 / B4 — the server restarts under a live call
// ════════════════════════════════════════════════════════════════════

/// A real `freeq-server` process, so it can be killed the way a crash kills
/// one and started again on the same data. The in-process rig can't do this:
/// AV session recovery from the database lives in `Server::run`, which is the
/// production boot path, not `start_with_web`.
struct Proc {
    _dir: tempfile::TempDir,
    child: std::process::Child,
    irc: String,
    web: String,
    args: Vec<String>,
}

impl Proc {
    fn spawn(args: Vec<String>, irc: String, web: String, dir: tempfile::TempDir) -> Self {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_freeq-server"))
            .args(&args)
            .env("RUST_LOG", "freeq_server=warn")
            .spawn()
            .expect("spawn freeq-server");
        Proc {
            _dir: dir,
            child,
            irc,
            web,
            args,
        }
    }

    /// SIGKILL — no shutdown hook, no last-gasp persistence. What a crash or
    /// an OOM kill looks like.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    async fn restart(&mut self) {
        self.child = std::process::Command::new(env!("CARGO_BIN_EXE_freeq-server"))
            .args(&self.args)
            .env("RUST_LOG", "freeq_server=warn")
            .spawn()
            .expect("respawn freeq-server");
        wait_port(&self.irc).await;
        wait_port(&self.web).await;
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn alloc_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_port(addr: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server at {addr} never became ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The only unautomated CRITICAL left from the July incident: three people in
/// a call, the server goes away, everybody reconnects. The legal outcomes are
/// "the same session came back" and "everyone landed in the same new one".
/// The illegal one — the one that happened — is a split, where some clients
/// resurrect the old id and the rest start a fresh one, and the two halves are
/// mutually silent because the SFU prefixes don't match (I5, class B).
///
/// The test doesn't care which legal outcome it gets; it drives the recovery a
/// real client drives (re-join the cached id, and if that's refused, converge
/// on whatever the channel has) and then asserts there is exactly one call.
#[tokio::test]
async fn restart_mid_call_one_session() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = dir.path().join("server.db").to_str().unwrap().to_string();
    let irc = format!("127.0.0.1:{}", alloc_port());
    let web = format!("127.0.0.1:{}", alloc_port());
    let args: Vec<String> = [
        "--listen-addr",
        &irc,
        "--web-addr",
        &web,
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--db-path",
        &db,
        "--av-grace-secs",
        &GRACE_SECS.to_string(),
        "--server-name",
        "test-avlife-restart",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let mut proc = Proc::spawn(args, irc.clone(), web.clone(), dir);
    wait_port(&irc).await;
    wait_port(&web).await;
    let irc_addr: SocketAddr = irc.parse().unwrap();
    let web_addr: SocketAddr = web.parse().unwrap();
    let chan = "#av-restart";
    let nicks = ["res_a", "res_b", "res_c"];

    // Three in a call, the ordinary way.
    let mut peers = Vec::new();
    for n in nicks {
        let mut p = connect_guest(irc_addr, n).await;
        p.join(chan).await;
        peers.push(p);
    }
    peers[0].av_start(chan).await;
    let started = peers[0].expect_av_state("started", 5000).await;
    let old_sid = started["+freeq.at/av-id"].clone();
    for p in peers.iter_mut().skip(1) {
        p.av_join(chan, &old_sid).await;
        p.expect_av_state("joined", 5000).await;
    }
    await_roster(
        web_addr,
        &old_sid,
        ROSTER_BUDGET,
        |v| roster_instances(v).len() == 3,
        "three in the call before the restart",
    )
    .await;

    // The crash. Clients' sockets die with it; drop them so nothing is left
    // half-talking to a dead port.
    proc.kill();
    drop(peers);
    proc.restart().await;

    // Everyone reconnects and tries the id they were holding — which is what
    // every client does, because the id is what its call state is keyed on.
    let mut peers = Vec::new();
    let mut refused = Vec::new();
    for n in nicks {
        let mut p = connect_guest(irc_addr, n).await;
        p.join(chan).await;
        p.av_join(chan, &old_sid).await;
        let outcome = wait_for(&mut p.events, 5000, |e| {
            av_tags(e).is_some_and(|t| {
                t.contains_key("+freeq.at/av-error")
                    || t.get("+freeq.at/av-state").map(String::as_str) == Some("joined")
            })
        })
        .await
        .unwrap_or_else(|| panic!("{n}: av-join after restart neither joined nor failed"));
        let tags = av_tags(&outcome).unwrap();
        if let Some(code) = tags.get("+freeq.at/av-error") {
            assert_eq!(
                code, "join-failed",
                "a lost session must be refused as join-failed, not silently"
            );
            assert_eq!(
                tags.get("+freeq.at/av-id").map(String::as_str),
                Some(old_sid.as_str()),
                "the refusal names the dead id so the client can drop it"
            );
            refused.push(n);
        }
        peers.push(p);
    }
    println!(
        "restart_mid_call_one_session: {} of 3 clients had their cached id \
         refused after the restart",
        refused.len()
    );

    // Anyone refused does what a real client does next: rediscover. `av-join`
    // with no id joins whatever the channel has; if the channel has nothing,
    // one client starts and the rest follow it.
    if !refused.is_empty() {
        if active_sessions_for(web_addr, chan).await.is_empty() {
            peers[0].av_start(chan).await;
            peers[0].expect_av_state("started", 5000).await;
        }
        for p in peers.iter_mut() {
            p.handle
                .send_tagmsg(
                    chan,
                    HashMap::from([
                        ("+freeq.at/av-join".to_string(), String::new()),
                        ("+freeq.at/av-instance".to_string(), p.inst.clone()),
                    ]),
                )
                .await
                .unwrap();
        }
    }

    // The assertion that matters: one call, everyone in it.
    let active = active_sessions_for(web_addr, chan).await;
    assert_eq!(
        active.len(),
        1,
        "I5/B4: a restart must not split the call — channel {chan} has sessions {active:?}"
    );
    let sid = active[0].clone();
    let roster = await_roster(
        web_addr,
        &sid,
        TEARDOWN_BUDGET,
        |v| roster_instances(v).len() == 3,
        "all three back in one session after the restart",
    )
    .await;
    assert_eq!(
        roster_nicks(&roster),
        BTreeSet::from(["res_a".into(), "res_b".into(), "res_c".into()]),
        "I2: the recovered roster is exactly the three who came back"
    );

    // If the old session didn't survive, it must be *dead*, not lingering as
    // a second thing clients could still join into.
    if sid != old_sid {
        let mut stray = connect_guest(irc_addr, "res_stray").await;
        stray.join(chan).await;
        stray.av_join(chan, &old_sid).await;
        let err = stray.expect_av_error(5000).await;
        assert_eq!(
            err.get("+freeq.at/av-error").map(String::as_str),
            Some("join-failed"),
            "the pre-restart id must be refused, or a late client ghosts into it"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// F7 rail — the token every join is supposed to receive
// ════════════════════════════════════════════════════════════════════

/// Natives dial the SFU with `?jwt=…`, so a start or join that doesn't hand
/// back a token is a call that breaks the day `FREEQ_AV_REQUIRE_TOKEN=1` is
/// set (E2 in the map). Two delivery paths exist and both must work: the
/// `+freeq.at/av-token` TAGMSG, and the REST fallback the web app uses. They
/// have to agree about what the token grants.
///
/// Without `av-native` there is no SFU to mint anything: the documented
/// behavior is no token tag and a 503 from REST, and that is what gets
/// asserted (E1 — a binary built without the feature must fail *loudly*, not
/// half-work).
#[tokio::test]
async fn token_minted_on_join() {
    let alice = Id::new("tok_a");
    let bob = Id::new("tok_b");
    let rig = start_rig("token", resolver(&[&alice, &bob])).await;
    let chan = "#av-token";

    #[cfg(feature = "av-native")]
    install_test_sfu(&rig).await;

    let mut a = connect_did(rig.irc, &alice, "tok_a").await;
    let mut b = connect_did(rig.irc, &bob, "tok_b").await;
    a.join(chan).await;
    b.join(chan).await;

    // The token and the state broadcast arrive in opposite orders on the two
    // paths — av-start broadcasts `started` before minting, av-join mints
    // before broadcasting `joined` — so both are collected from one pass over
    // the stream rather than waited for in a guessed sequence.
    a.av_start(chan).await;
    let a_saw = collect_av(&mut a.events, 5000, |seen| {
        state_id(seen, "started").is_some() && token_in(seen).is_some()
    })
    .await;
    let sid = state_id(&a_saw, "started").expect("av-start must broadcast av-state=started");
    let a_token = token_in(&a_saw);

    b.av_join(chan, &sid).await;
    let b_saw = collect_av(&mut b.events, 5000, |seen| {
        state_id(seen, "joined").is_some() && token_in(seen).is_some()
    })
    .await;
    assert!(
        state_id(&b_saw, "joined").as_deref() == Some(sid.as_str()),
        "B joined the session A started"
    );
    let b_token = token_in(&b_saw);

    let rest = reqwest::Client::new()
        .get(format!("http://{}/api/v1/av/sessions/{sid}/token", rig.web))
        .header("Authorization", format!("Bearer {}", b.bearer))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("token request");
    let rest_status = rest.status().as_u16();
    let rest_body: serde_json::Value = rest.json().await.unwrap_or(serde_json::Value::Null);

    #[cfg(feature = "av-native")]
    {
        let a_token = a_token.expect("av-start must deliver +freeq.at/av-token");
        let b_token = b_token.expect("av-join must deliver +freeq.at/av-token");
        assert_eq!(rest_status, 200, "REST fallback: {rest_body}");
        let rest_token = rest_body["token"]
            .as_str()
            .expect("REST token field")
            .to_string();

        // "Agree" means the same grants, not the same bytes: each mint stamps
        // its own iat/exp, so comparing strings would pin the clock instead of
        // the claim. What matters is that the two paths open the same door.
        let grants = |jwt: &str| -> serde_json::Value {
            let payload = jwt.split('.').nth(1).expect("JWT payload segment");
            use base64::Engine;
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("base64url payload");
            let mut v: serde_json::Value = serde_json::from_slice(&raw).expect("payload json");
            if let Some(o) = v.as_object_mut() {
                o.remove("iat");
                o.remove("exp");
            }
            v
        };
        assert_eq!(
            grants(&a_token),
            grants(&b_token),
            "both participants' tokens grant the same session"
        );
        assert_eq!(
            grants(&b_token),
            grants(&rest_token),
            "F7: the REST fallback and the TAGMSG must agree about what the \
             token opens, or web and native end up with different access"
        );
        let g = grants(&rest_token);
        assert!(
            g["put"]
                .as_array()
                .is_some_and(|v| v.iter().any(|p| p == &serde_json::json!(sid))),
            "the token is scoped to this session: {g}"
        );
    }

    #[cfg(not(feature = "av-native"))]
    {
        println!(
            "token_minted_on_join: no av-native in this binary — asserting the \
             documented no-AV contract (E1) instead of token issuance"
        );
        assert!(
            a_token.is_none() && b_token.is_none(),
            "a server with no SFU must not pretend to mint tokens"
        );
        assert_eq!(
            rest_status, 503,
            "the token endpoint says 'AV not enabled' rather than half-working: {rest_body}"
        );
    }
}

/// Collect AV tag maps until `done` is satisfied or `ms` runs out. For cases
/// where two signals both have to arrive and the order between them is the
/// server's business, not the test's.
async fn collect_av(
    events: &mut mpsc::Receiver<Event>,
    ms: u64,
    done: impl Fn(&[HashMap<String, String>]) -> bool,
) -> Vec<HashMap<String, String>> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut seen: Vec<HashMap<String, String>> = Vec::new();
    while !done(&seen) {
        let Some(e) = next_before(events, deadline).await else {
            break;
        };
        if let Some(t) = av_tags(&e) {
            seen.push(t.clone());
        }
    }
    seen
}

fn state_id(seen: &[HashMap<String, String>], action: &str) -> Option<String> {
    seen.iter()
        .find(|t| t.get("+freeq.at/av-state").map(String::as_str) == Some(action))
        .and_then(|t| t.get("+freeq.at/av-id").cloned())
}

fn token_in(seen: &[HashMap<String, String>]) -> Option<String> {
    seen.iter()
        .find_map(|t| t.get("+freeq.at/av-token").cloned())
}

// ════════════════════════════════════════════════════════════════════
// F6 rail — the roster leave and the media revocation, at one boundary
// ════════════════════════════════════════════════════════════════════

/// Media must not outlive the roster. When a blipped participant's grace
/// expires, three things have to happen together: the roster drops the slot,
/// the channel is told, and the SFU closes the instance's media connections —
/// otherwise announcement-driven clients keep hearing a roster-ghost (class C,
/// audit F6).
///
/// What this proves and what it doesn't: the media *transport* here isn't real
/// — that's L2's job. What is real is the server side of the contract. We
/// register a media connection for the instance exactly the way the MoQ
/// WebSocket handler does (`SfuState::register_media_conn`), publish a
/// broadcast under the roster path so the relay is actually announcing
/// something, and close it when revocation fires, which is what
/// `handle_ws_moq` does when its notify wakes. Then the class-A X-ray
/// (`?debug=1`) has to show no announced path left for the departed instance.
#[cfg(feature = "av-native")]
#[tokio::test]
async fn media_revocation_ordering() {
    let alice = Id::new("revoke");
    let rig = start_rig("revoke", resolver(&[&alice])).await;
    let chan = "#av-revoke";
    let sfu = install_test_sfu(&rig).await;

    let blip = Blip::to(rig.irc).await;
    let mut a = connect_did(blip.addr, &alice, "rev_a").await;
    let mut b = connect_guest(rig.irc, "rev_b").await;
    a.join(chan).await;
    b.join(chan).await;

    a.av_start(chan).await;
    let started = a.expect_av_state("started", 5000).await;
    let sid = started["+freeq.at/av-id"].clone();
    b.av_join(chan, &sid).await;
    b.expect_av_state("joined", 5000).await;

    // A dials the SFU: declares its instance and publishes under the roster
    // path. This is the state the F6 ghost was stuck in.
    let path = format!("{sid}/{}~{}", a.nick, a.inst);
    let revoked = sfu.register_media_conn(&a.inst);
    let broadcast = moq_lite::Broadcast::produce();
    sfu.cluster
        .primary
        .publish_broadcast(path.as_str(), broadcast.consume());

    // Stand in for `handle_ws_moq`'s park: hold the broadcast open until the
    // revocation notify fires, then drop it — which is what returning from
    // that handler does. `Notify::notify_waiters` only wakes waiters that are
    // already registered, so the future is enabled (and the readiness
    // acknowledged) before anything can revoke.
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let notified = revoked.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let _ = armed_tx.send(());
        notified.await;
        drop(broadcast);
        let _ = closed_tx.send(());
    });
    armed_rx.await.expect("media-conn stand-in armed");

    let debug = session_json(rig.web, &sid, true).await;
    let announced: Vec<String> = debug["announced"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| panic!("?debug=1 must carry `announced` under av-native: {debug}"));
    assert!(
        announced.contains(&path),
        "the X-ray must see what the relay is announcing, or it can't show a \
         class-A divergence: announced={announced:?} expected={path}"
    );

    // The blip, then the grace expiry.
    blip.cut();
    let left = b
        .expect_av_state("left", TEARDOWN_BUDGET.as_millis() as u64)
        .await;
    assert_eq!(
        left.get("+freeq.at/av-instance").map(String::as_str),
        Some(a.inst.as_str()),
        "the roster leave names A's instance"
    );

    // The revocation reached A's media connection and it closed.
    timeout(Duration::from_secs(5), closed_rx)
        .await
        .expect("F6: grace expiry must revoke the instance's media, not just its roster slot")
        .expect("media-conn stand-in dropped without closing");

    await_roster(
        rig.web,
        &sid,
        ROSTER_BUDGET,
        |v| !roster_instances(v).contains(&a.inst),
        "A's roster slot dropped at grace expiry",
    )
    .await;

    // The X-ray agrees: no announced path for the departed instance. Roster
    // and announcements are back in step, which is the whole point.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let debug = session_json(rig.web, &sid, true).await;
        let announced: Vec<String> = debug["announced"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !announced
            .iter()
            .any(|p| p.ends_with(&format!("~{}", a.inst)))
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("announced path survived the revocation: {announced:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The in-process rig never boots an SFU (that lives in `Server::run`, behind
/// an iroh endpoint), so the tests that need one install it the same way.
#[cfg(feature = "av-native")]
async fn install_test_sfu(rig: &Rig) -> Arc<freeq_server::av_sfu::SfuState> {
    let dir = tempfile::tempdir().unwrap();
    let sfu = freeq_server::av_sfu::init_sfu(None, dir.path().to_str().unwrap())
        .await
        .expect("SFU init");
    // The key file is all the tempdir held; the SFU has it in memory now.
    std::mem::forget(dir);
    *rig.state.sfu_state.lock() = Some(sfu.clone());
    sfu
}

/// Without `av-native` there is no SFU and no revocation to order. Say so out
/// loud rather than passing silently — a skipped guarantee that looks like a
/// green test is how the "AV disabled in prod" outage lasted two hours.
#[cfg(not(feature = "av-native"))]
#[tokio::test]
async fn media_revocation_ordering() {
    println!(
        "media_revocation_ordering: SKIPPED — this binary has no av-native, so \
         there is no SFU to revoke media on and no `announced` to compare the \
         roster against. Run `cargo test -p freeq-server --features av-native \
         --test av_lifecycle` (or scripts/avharness.sh) for this one."
    );
    // The one thing that IS assertable here: the debug field degrades
    // honestly instead of disappearing.
    let rig = start_rig("revoke-noav", DidResolver::static_map(HashMap::new())).await;
    let chan = "#av-revoke";
    let mut a = connect_guest(rig.irc, "rev_a").await;
    a.join(chan).await;
    a.av_start(chan).await;
    let sid = a.expect_av_state("started", 5000).await["+freeq.at/av-id"].clone();

    let debug = session_json(rig.web, &sid, true).await;
    assert!(
        debug["announced"].is_null(),
        "no SFU means no announcements to report: {debug}"
    );
    assert!(
        debug["announced_note"]
            .as_str()
            .is_some_and(|n| n.contains("av-native")),
        "and the reason must be in the response, not only in the source: {debug}"
    );
}
