//! Two-in-process-server end-to-end tests for the eliza bot.
//!
//! Each test spins up one or two real `freeq-server` instances in-process
//! on ephemeral ports (no S2S federation — the servers are independent),
//! points the bot at one of them via `freeq_eliza::irc::run`,
//! and asserts on the IRC/TAGMSG control plane by attaching a *witness*
//! SDK client to the same channel.
//!
//! The MoQ subscriber side is intentionally NOT exercised: with no real
//! SFU reachable, the bot's `AvSession` task fails to connect to
//! `/av/moq` and logs a warning. That failure is isolated in a spawned
//! task and must not stop the bot from av-joining the call or posting
//! its `[transcript] session ended.` line. These tests pin exactly that.
//!
//! The `stt` feature stays OFF — `stt::Whisper` is a no-op that returns
//! empty transcriptions, which is fine because we never reach the audio
//! path here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use freeq_eliza::identity::{self, Identity};
use freeq_eliza::irc::{RunConfig, run};
use freeq_eliza::stt::SttEngine;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;
use tokio::sync::mpsc::Receiver;

// ───────────────────────────── server bootstrap ─────────────────────────────

/// A running in-process `freeq-server`.
///
/// The server runs on its own dedicated single-thread tokio runtime,
/// pinned to a background OS thread. This matters for scenario 5
/// ("server restart"): `freeq-server::Server::start()` returns only the
/// *accept-loop* `JoinHandle` — each accepted connection is handled in a
/// *detached* `tokio::spawn`, so aborting the accept handle alone would
/// leave the bot's already-established connection wired up forever.
///
/// By giving the server its own runtime, `kill()` (and `Drop`) signals
/// the host thread to drop that runtime, which cancels *every* task it
/// owns — accept loop and all detached connection handlers — and closes
/// their sockets. The bot then observes a real disconnect, exactly like
/// a process crash.
struct TestServer {
    addr: std::net::SocketAddr,
    /// Sender side of the shutdown signal — sending (or dropping) it
    /// wakes the host thread, which then drops the runtime.
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    /// The host thread; joined after the runtime is dropped.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    /// `host:port` string the bot / witness clients pass as `server_addr`.
    fn addr_str(&self) -> String {
        self.addr.to_string()
    }

    /// Simulate a crash: tear down the server's runtime. Every server
    /// task — accept loop and all detached connection handlers — is
    /// cancelled and their sockets close, so connected clients see the
    /// connection drop. Blocks until the host thread has fully exited.
    fn kill(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        // Dropping the Sender is itself a shutdown signal (the receiver's
        // `recv()` returns `Err`), so an explicit `send` is belt-and-
        // braces.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spin up a fresh `freeq-server` on an ephemeral 127.0.0.1 port.
///
/// We model the in-process spinup on the existing pattern from
/// `freeq-server/tests/sdk_client.rs` (`Server::new(cfg).start()` →
/// `(SocketAddr, JoinHandle)`), but run it on a dedicated, separately-
/// owned runtime so the whole server — connections included — can be
/// torn down on demand (see [`TestServer`]).
///
/// The runtime is built *and dropped* on its own OS thread. A tokio
/// `Runtime` may not be dropped from within an async context, and after
/// the worker thread's `block_on` returns it is no longer in one — so
/// the drop there is legal and cancels all server tasks.
///
/// The bot authenticates with a `did:key:` identity, and `did:key`
/// resolves purely from the DID string (no network), so the default
/// HTTP resolver built by `Server::new` is sufficient and never reaches
/// out. Each server gets a unique `server_name` for log clarity.
fn spawn_server(name: &str) -> TestServer {
    let name = name.to_string();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<std::net::SocketAddr>();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let config = freeq_server::config::ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                server_name: name,
                challenge_timeout_secs: 60,
                ..Default::default()
            };
            let (addr, _accept_handle) = freeq_server::server::Server::new(config)
                .start()
                .await
                .expect("server failed to start");
            addr_tx.send(addr).expect("ship server addr");
            // Park until the test signals shutdown (or drops the
            // sender). The server's accept loop + connection tasks run
            // detached on this same runtime in the meantime.
            let _ = tokio::task::spawn_blocking(move || {
                let _ = shutdown_rx.recv();
            })
            .await;
        });
        // `block_on` has returned → not in an async context → dropping
        // `rt` here is legal and cancels every server task.
        drop(rt);
    });

    let addr = addr_rx.recv().expect("server address");
    TestServer {
        addr,
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
    }
}

// ───────────────────────────── test helpers ─────────────────────────────────

/// Generous CI-friendly ceiling for "the bot should have done X by now".
const SETTLE: Duration = Duration::from_secs(20);

/// Build a throwaway `did:key` identity for the bot, rooted in a tempdir
/// so we never touch `$HOME/.freeq`. Returns the identity plus the
/// tempdir guard (kept alive by the caller for the test's lifetime).
fn mint_identity(name: &str) -> (Identity, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ident = identity::load_or_create_in(name, tmp.path()).expect("mint identity");
    (ident, tmp)
}

/// A guest (non-SASL) SDK client used to observe what the bot puts on
/// the wire. `signer: None` → the server lets it in as a guest.
struct Witness {
    handle: ClientHandle,
    events: Receiver<Event>,
}

impl Witness {
    /// Connect a guest client and wait until it's registered + joined
    /// `channel`. Panics on timeout — a witness that can't get on the
    /// channel makes every downstream assertion meaningless.
    async fn join(server: &str, nick: &str, channel: &str) -> Witness {
        let config = ConnectConfig {
            server_addr: server.to_string(),
            nick: nick.to_string(),
            user: nick.to_string(),
            realname: "witness".to_string(),
            tls: false,
            tls_insecure: false,
            web_token: None,
            websocket_url: None,
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);

        // Wait for registration.
        let deadline = Instant::now() + SETTLE;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Some(Event::Registered { .. })) => break,
                Ok(Some(_)) => continue,
                Ok(None) => panic!("witness {nick}: connection closed before registration"),
                Err(_) => panic!("witness {nick}: timed out waiting for registration"),
            }
        }
        handle.join(channel).await.expect("witness join");

        // Wait until our own Joined lands so the channel is live.
        let deadline = Instant::now() + SETTLE;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Some(Event::Joined {
                    channel: c,
                    nick: n,
                    ..
                })) if c.eq_ignore_ascii_case(channel) && n.eq_ignore_ascii_case(nick) => {
                    break;
                }
                Ok(Some(_)) => continue,
                Ok(None) => panic!("witness {nick}: connection closed before join"),
                Err(_) => panic!("witness {nick}: timed out joining {channel}"),
            }
        }
        Witness { handle, events }
    }

    /// Drain events up to `SETTLE` (or `dur`), feeding each into `f`.
    /// Stops early as soon as `f` returns `Some`. Returns `None` on
    /// timeout. This is the "wait until N events seen or timeout"
    /// primitive the tests use instead of fixed sleeps.
    async fn wait_for<T>(
        &mut self,
        dur: Duration,
        mut f: impl FnMut(&Event) -> Option<T>,
    ) -> Option<T> {
        let deadline = Instant::now() + dur;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.events.recv()).await {
                Ok(Some(ev)) => {
                    if let Some(v) = f(&ev) {
                        return Some(v);
                    }
                }
                Ok(None) => return None, // connection closed
                Err(_) => return None,   // timed out
            }
        }
    }

    /// Drain every event currently buffered (non-blocking), invoking `f`
    /// on each. Used after a quiet period to assert "the bot sent
    /// nothing".
    fn drain_now(&mut self, mut f: impl FnMut(&Event)) {
        while let Ok(ev) = self.events.try_recv() {
            f(&ev);
        }
    }
}

/// Spawn the bot's `irc::run` against `server` for `channels`. Returns the
/// `JoinHandle` so a test can `timeout` it (scenario 5). The bot uses a
/// fresh tempdir-rooted `did:key` identity; the tempdir guard is returned
/// so the caller keeps it alive.
fn spawn_bot(
    server: &str,
    channels: Vec<String>,
    bot_name: &str,
) -> (
    tokio::task::JoinHandle<anyhow::Result<()>>,
    tempfile::TempDir,
) {
    let (ident, tmp) = mint_identity(bot_name);
    let cfg = RunConfig {
        server: server.to_string(),
        channels,
        nick: bot_name.to_string(),
        ident,
        // stt feature is off → Whisper::load is a no-op that accepts any
        // path and `transcribe` always returns "". We never reach the
        // audio path in these tests anyway.
        stt: Arc::new(SttEngine::noop()),
        window_secs: 10.0,
        summary_model: "claude-sonnet-4-5".to_string(),
        // No ANTHROPIC key in test env → no summary path.
        anthropic_key: None,
        // These tests drive av-start from a separate publisher client;
        // the bot itself only watches.
        start_session_in: None,
        sfu_url_override: None,
        // No Deepgram key in test env → batched-Whisper (noop) path.
        stt_streaming_key: None,
        // No Groq/ElevenLabs keys in test env → Q&A/TTS disabled; these
        // tests only exercise the IRC/TAGMSG control plane.
        groq_api_key: None,
        groq_chat_model: "llama-3.3-70b-versatile".to_string(),
        groq_answer_model: "groq/compound".to_string(),
        voice_answer_model: "llama-3.3-70b-versatile".to_string(),
        voice_search_model: "groq/compound-mini".to_string(),
        elevenlabs_api_key: None,
        elevenlabs_voice_id: "aj0fZfXTBc7E3By4X8L2".to_string(),
        elevenlabs_model: "eleven_turbo_v2_5".to_string(),
        image_ai: None,
        owner: None,
        summary_enabled: false,
        vision_model: "meta-llama/llama-4-scout-17b-16e-instruct".to_string(),
        // Proactive/ambient monitors poll LLMs — keep them off so these
        // control-plane tests stay deterministic and offline.
        proactive_enabled: false,
        ambient_enabled: false,
        research_enabled: false,
        render_backend: "svg".to_string(),
        ghostly_character: "eliza".to_string(),
        ghostly_pack: None,
        character_system_prompt: None,
        persona_hello_line: None,
        peer_agents: Vec::new(),
        // Own-brain mode; no yokota socket in these tests.
        external_brain: false,
        external_brain_text: false,
        brain_sock: None,
        no_video: false,
        no_voice_dsp: false,
    };
    let handle = tokio::spawn(run(cfg));
    (handle, tmp)
}

/// True iff `ev` is evidence that `bot_nick` av-joined a call.
///
/// The bot's `+freeq.at/av-join` TAGMSG is *consumed* server-side (it's
/// an AV action tag, not a relay tag): the server records the join and
/// instead broadcasts an `av-state=joined` TAGMSG attributed to the
/// joiner via `+freeq.at/av-actor`. That broadcast — carrying the same
/// `av-id` the bot joined with — is the on-the-wire witness of the bot's
/// av-join.
fn is_bot_av_join(ev: &Event, bot_nick: &str) -> bool {
    match ev {
        Event::TagMsg { tags, .. } => {
            tags.get("+freeq.at/av-state").map(String::as_str) == Some("joined")
                && tags
                    .get("+freeq.at/av-actor")
                    .map(|a| a.eq_ignore_ascii_case(bot_nick))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// Send a publisher-side `+freeq.at/av-start` TAGMSG. The server consumes
/// this and broadcasts back an `av-state=started` TAGMSG carrying the
/// server-generated ULID `av-id`.
async fn publisher_start(pub_handle: &ClientHandle, channel: &str, instance: &str) {
    let mut tags = HashMap::new();
    tags.insert("+freeq.at/av-start".to_string(), String::new());
    tags.insert("+freeq.at/av-instance".to_string(), instance.to_string());
    tags.insert("+freeq.at/av-title".to_string(), "test session".to_string());
    pub_handle
        .send_tagmsg(channel, tags)
        .await
        .expect("publisher av-start");
}

/// Send a publisher-side `av-state=started` TAGMSG *directly* (carrying a
/// known `av-id`). `av-state` is a relay tag, not an AV action, so the
/// server forwards it verbatim to channel members — the bot sees it as a
/// session start. Used by the dedup / malformed scenarios where we need
/// precise control over the tags.
async fn publisher_av_state(
    pub_handle: &ClientHandle,
    channel: &str,
    state: &str,
    av_id: Option<&str>,
) {
    let mut tags = HashMap::new();
    tags.insert("+freeq.at/av-state".to_string(), state.to_string());
    if let Some(id) = av_id {
        tags.insert("+freeq.at/av-id".to_string(), id.to_string());
    }
    pub_handle
        .send_tagmsg(channel, tags)
        .await
        .expect("publisher av-state");
}

/// Connect a guest publisher and join `channel`.
async fn connect_publisher(server: &str, nick: &str, channel: &str) -> Witness {
    Witness::join(server, nick, channel).await
}

/// Wait for the server's `av-state=started` broadcast and return its
/// server-generated `av-id`. The publisher needs this ULID to later
/// resend an identical event (dedup test) or end the session.
async fn wait_started_av_id(witness: &mut Witness) -> String {
    witness
        .wait_for(SETTLE, |ev| match ev {
            Event::TagMsg { tags, .. }
                if tags.get("+freeq.at/av-state").map(String::as_str) == Some("started") =>
            {
                tags.get("+freeq.at/av-id").cloned()
            }
            _ => None,
        })
        .await
        .expect("never saw an av-state=started broadcast")
}

// ───────────────────────────── scenario 1 ───────────────────────────────────

/// Idle: bot joins `#avtest`, no call ever starts. A witness sees the bot
/// in the channel and the bot emits no av-* TAGMSGs.
#[tokio::test]
async fn scenario_1_idle_no_call() {
    let server = spawn_server("idle-srv");
    let addr = server.addr_str();

    let mut witness = Witness::join(&addr, "watcher1", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "idlebot");

    // Witness should see the bot join the channel.
    let saw_bot = witness
        .wait_for(SETTLE, |ev| match ev {
            Event::Joined { nick, channel, .. } if channel.eq_ignore_ascii_case("#avtest") => {
                if nick.eq_ignore_ascii_case("idlebot") {
                    Some(())
                } else {
                    None
                }
            }
            _ => None,
        })
        .await;
    assert!(saw_bot.is_some(), "witness never saw the bot join #avtest");

    // Give the bot a beat to (mis)behave, then assert it stayed silent.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut av_tagmsgs = 0;
    witness.drain_now(|ev| {
        if let Event::TagMsg { tags, .. } = ev {
            if tags.keys().any(|k| k.starts_with("+freeq.at/av-")) {
                av_tagmsgs += 1;
            }
        }
    });
    assert_eq!(av_tagmsgs, 0, "idle bot sent {av_tagmsgs} av-* TAGMSGs");
}

// ───────────────────────────── scenario 2 ───────────────────────────────────

/// Cross-server isolation: the bot lives on server A; a publisher starts a
/// call in server B's `#avtest`. The bot must not react — it isn't even
/// connected to B.
#[tokio::test]
async fn scenario_2_cross_server_isolation() {
    let server_a = spawn_server("iso-srv-a");
    let server_b = spawn_server("iso-srv-b");
    let addr_a = server_a.addr_str();
    let addr_b = server_b.addr_str();

    // Bot + a witness on A.
    let mut witness_a = Witness::join(&addr_a, "watcherA", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr_a, vec!["#avtest".to_string()], "isobot");

    // Wait for the bot to be present on A.
    let saw = witness_a
        .wait_for(SETTLE, |ev| match ev {
            Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("isobot") => Some(()),
            _ => None,
        })
        .await;
    assert!(saw.is_some(), "bot never joined A");

    // Publisher on B starts a call in B's #avtest.
    let pub_b = connect_publisher(&addr_b, "pubB", "#avtest").await;
    publisher_start(&pub_b.handle, "#avtest", "bbbb1111").await;

    // The bot (on A) must send nothing — give it a real window.
    let av_join = witness_a
        .wait_for(SETTLE, |ev| is_bot_av_join(ev, "isobot").then_some(()))
        .await;
    assert!(
        av_join.is_none(),
        "bot reacted to a call on a server it isn't connected to",
    );
}

// ───────────────────────────── scenario 3 ───────────────────────────────────

/// Happy path: publisher starts a call and the bot av-joins it
/// (witnessed via the `av-state=joined` reflection). Then the publisher
/// ends the call; the bot posts `[transcript] session ended.` (no
/// ANTHROPIC key → no summary).
#[tokio::test]
async fn scenario_3_happy_path() {
    let server = spawn_server("happy-srv");
    let addr = server.addr_str();

    let mut witness = Witness::join(&addr, "watcher3", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "happybot");

    // Bot present.
    assert!(
        witness
            .wait_for(SETTLE, |ev| match ev {
                Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("happybot") => Some(()),
                _ => None,
            })
            .await
            .is_some(),
        "bot never joined",
    );

    // Publisher starts a call.
    let publisher = connect_publisher(&addr, "pub3", "#avtest").await;
    publisher_start(&publisher.handle, "#avtest", "deadbeef").await;

    // The bot's `+freeq.at/av-join` is consumed server-side and reflected
    // as an `av-state=joined` TAGMSG attributed to the bot, carrying the
    // session's `av-id`. That's our wire witness of the av-join.
    let av_id = witness
        .wait_for(SETTLE, |ev| match ev {
            Event::TagMsg { tags, .. } if is_bot_av_join(ev, "happybot") => {
                let id = tags.get("+freeq.at/av-id").cloned();
                assert!(id.is_some(), "bot av-join broadcast missing av-id tag");
                id
            }
            _ => None,
        })
        .await
        .expect("bot never av-joined the call");
    assert!(!av_id.is_empty(), "av-join av-id is empty");

    // Publisher ends the call with the matching av-id.
    publisher_av_state(&publisher.handle, "#avtest", "ended", Some(&av_id)).await;

    // Bot must post the closing line.
    let ended = witness
        .wait_for(SETTLE, |ev| match ev {
            Event::Message { text, .. } if text.contains("[transcript] session ended") => Some(()),
            _ => None,
        })
        .await;
    assert!(
        ended.is_some(),
        "bot never posted '[transcript] session ended.'"
    );
}

// ───────────────────────────── scenario 4 ───────────────────────────────────

/// Already-in-call: the bot lives in two channels. A call starts in
/// `#avtest`; after the bot av-joins, a second call starts in `#avtest2`.
/// The bot transcribes at most one call at a time, so it must NOT av-join
/// the second. Count av-joins across both channels via two witnesses.
#[tokio::test]
async fn scenario_4_already_in_call() {
    let server = spawn_server("busy-srv");
    let addr = server.addr_str();

    let mut w1 = Witness::join(&addr, "watch4a", "#avtest").await;
    let mut w2 = Witness::join(&addr, "watch4b", "#avtest2").await;
    let (_bot, _tmp) = spawn_bot(
        &addr,
        vec!["#avtest".to_string(), "#avtest2".to_string()],
        "busybot",
    );

    // Wait for the bot to be in #avtest.
    assert!(
        w1.wait_for(SETTLE, |ev| match ev {
            Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("busybot") => Some(()),
            _ => None,
        })
        .await
        .is_some(),
        "bot never joined #avtest",
    );

    // First call in #avtest → bot av-joins there.
    let pub1 = connect_publisher(&addr, "pub4a", "#avtest").await;
    publisher_start(&pub1.handle, "#avtest", "11112222").await;
    assert!(
        w1.wait_for(SETTLE, |ev| is_bot_av_join(ev, "busybot").then_some(()))
            .await
            .is_some(),
        "bot never av-joined the first call",
    );

    // Second call in #avtest2 while the first is still active.
    let pub2 = connect_publisher(&addr, "pub4b", "#avtest2").await;
    publisher_start(&pub2.handle, "#avtest2", "33334444").await;

    // The bot must NOT av-join #avtest2.
    let second = w2
        .wait_for(SETTLE, |ev| is_bot_av_join(ev, "busybot").then_some(()))
        .await;
    assert!(
        second.is_none(),
        "bot av-joined a second concurrent call — only one at a time allowed",
    );
}

// ───────────────────────────── scenario 5 ───────────────────────────────────

/// Server restart: the bot connects to A, then A is killed. The bot's
/// `run` future must *resolve* (not hang, not panic) once the socket
/// drops — we wrap it in a timeout and assert it completed.
#[tokio::test]
async fn scenario_5_server_restart() {
    let server = spawn_server("restart-srv");
    let addr = server.addr_str();

    let mut witness = Witness::join(&addr, "watcher5", "#avtest").await;
    let (bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "restartbot");

    // Make sure the bot has fully connected + joined before we pull the
    // rug — otherwise we'd be testing the registration-timeout path.
    assert!(
        witness
            .wait_for(SETTLE, |ev| match ev {
                Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("restartbot") => Some(()),
                _ => None,
            })
            .await
            .is_some(),
        "bot never joined before restart",
    );

    // Crash server A.
    server.kill();

    // The bot's run() future must complete. We don't care whether it's
    // Ok or Err — only that it didn't hang or panic.
    let outcome = tokio::time::timeout(SETTLE, bot).await;
    let join_result = outcome.expect("bot's run() future hung after server crash");
    // The spawned task itself must not have panicked.
    assert!(
        join_result.is_ok(),
        "bot task panicked after server crash: {:?}",
        join_result.err(),
    );
}

// ───────────────────────────── scenario 6 ───────────────────────────────────

/// av-state dedup: the publisher sends two identical `av-state=started`
/// TAGMSGs for the same session. The bot must av-join exactly once.
#[tokio::test]
async fn scenario_6_av_state_dedup() {
    let server = spawn_server("dedup-srv");
    let addr = server.addr_str();

    let mut witness = Witness::join(&addr, "watcher6", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "dedupbot");

    assert!(
        witness
            .wait_for(SETTLE, |ev| match ev {
                Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("dedupbot") => Some(()),
                _ => None,
            })
            .await
            .is_some(),
        "bot never joined",
    );

    // Create a real session via av-start so the bot's later av-join
    // actually resolves. The server broadcasts an `av-state=started`
    // carrying a ULID `av-id` — capture it.
    let mut publisher = connect_publisher(&addr, "pub6", "#avtest").await;
    publisher_start(&publisher.handle, "#avtest", "66667777").await;
    let av_id = wait_started_av_id(&mut publisher).await;

    // First av-join must arrive (the bot reacts to the server's
    // `av-state=started`).
    assert!(
        witness
            .wait_for(SETTLE, |ev| is_bot_av_join(ev, "dedupbot").then_some(()))
            .await
            .is_some(),
        "bot never av-joined the session",
    );

    // Now resend an IDENTICAL `av-state=started` for the SAME session
    // id. The bot already has an active call, so it must ignore this
    // duplicate rather than av-join a second time.
    publisher_av_state(&publisher.handle, "#avtest", "started", Some(&av_id)).await;

    // No SECOND av-join may follow within a generous window.
    let second = witness
        .wait_for(Duration::from_secs(5), |ev| {
            is_bot_av_join(ev, "dedupbot").then_some(())
        })
        .await;
    assert!(
        second.is_none(),
        "bot av-joined twice for a duplicated av-state=started",
    );
}

// ───────────────────────────── scenario 7 ───────────────────────────────────

/// Malformed event: `av-state=started` with no `av-id` tag. The classifier
/// requires `av-id`, so the bot must ignore it — no av-join, no panic.
#[tokio::test]
async fn scenario_7_malformed_event() {
    let server = spawn_server("malformed-srv");
    let addr = server.addr_str();

    let mut witness = Witness::join(&addr, "watcher7", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "malbot");

    assert!(
        witness
            .wait_for(SETTLE, |ev| match ev {
                Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("malbot") => Some(()),
                _ => None,
            })
            .await
            .is_some(),
        "bot never joined",
    );

    let publisher = connect_publisher(&addr, "pub7", "#avtest").await;
    // av-state=started with NO av-id tag.
    publisher_av_state(&publisher.handle, "#avtest", "started", None).await;

    let av_join = witness
        .wait_for(SETTLE, |ev| is_bot_av_join(ev, "malbot").then_some(()))
        .await;
    assert!(
        av_join.is_none(),
        "bot reacted to an av-state=started with no av-id",
    );
}

// ───────────────────────────── scenario 8 ───────────────────────────────────

/// Foreign channel: a call starts in a channel the bot is NOT in. The
/// classifier rejects `started` events whose target isn't one of the
/// bot's channels, so the bot must ignore it.
#[tokio::test]
async fn scenario_8_foreign_channel() {
    let server = spawn_server("foreign-srv");
    let addr = server.addr_str();

    // Bot is only in #avtest.
    let mut bot_witness = Witness::join(&addr, "watch8bot", "#avtest").await;
    let (_bot, _tmp) = spawn_bot(&addr, vec!["#avtest".to_string()], "foreignbot");
    assert!(
        bot_witness
            .wait_for(SETTLE, |ev| match ev {
                Event::Joined { nick, .. } if nick.eq_ignore_ascii_case("foreignbot") => Some(()),
                _ => None,
            })
            .await
            .is_some(),
        "bot never joined #avtest",
    );

    // A call starts in #elsewhere — a channel the bot is not in.
    let mut foreign_witness = Witness::join(&addr, "watch8for", "#elsewhere").await;
    let publisher = connect_publisher(&addr, "pub8", "#elsewhere").await;
    publisher_start(&publisher.handle, "#elsewhere", "88889999").await;

    // Neither the bot's channel nor the foreign channel may see an
    // av-join from the bot.
    let in_foreign = foreign_witness
        .wait_for(SETTLE, |ev| is_bot_av_join(ev, "foreignbot").then_some(()))
        .await;
    assert!(
        in_foreign.is_none(),
        "bot av-joined a foreign channel's call"
    );

    let mut bot_av_joins = 0;
    bot_witness.drain_now(|ev| {
        if is_bot_av_join(ev, "foreignbot") {
            bot_av_joins += 1;
        }
    });
    assert_eq!(
        bot_av_joins, 0,
        "bot sent an av-join into its own channel for a foreign-channel call",
    );
}
