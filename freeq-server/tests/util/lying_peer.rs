//! A federated peer that lies.
//!
//! Every S2S authorization rule in the server — who may delete a message, who
//! may edit one, who may kick, set a mode, or change a locked topic — protects
//! against exactly one thing: a peer that sends an event a well-behaved server
//! never would. Those rules were covered only by in-process unit tests calling
//! the check functions directly, which cannot catch a check that is *not
//! reached* on the wire path. (One such gap shipped: federated edits arrived
//! with no authorship check at all.)
//!
//! This harness closes that gap. It boots a real `freeq-server` subprocess,
//! then dials it as a peer, completes the genuine handshake — real iroh
//! endpoint identity, real allowlist entry, real ed25519-signed envelopes —
//! and from there transmits arbitrary [`S2sMessage`] values verbatim. Every
//! byte on the link is what a legitimate peer would produce; only the
//! *content* of the events is forged. A rule that the receiving server fails
//! to enforce therefore shows up here as state that actually changed.
//!
//! The peer is an in-process tokio task rather than a second server process:
//! it must send events no server binary can be made to send.
//!
//! ```ignore
//! let victim = TestId::new("did:plc:victim");
//! let (srv, mut peer) = spawn_server_with_peer(&[&victim]).await;
//! peer.forge(peer.join("mallory", "#room", None)).await;
//! ```

use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use base64::Engine;
use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use freeq_server::s2s::{S2S_ALPN, S2sMessage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::timeout;

pub const READY_TIMEOUT: Duration = Duration::from_secs(15);
pub const EVENT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to keep retrying an assertion while the S2S link settles.
pub const SETTLE: Duration = Duration::from_secs(20);
/// How long to wait before concluding a forged event produced *no* effect.
/// A rejected event emits nothing, so this window is pure elapsed time; keep
/// it short enough that four tests don't add a minute to the suite, long
/// enough that a slow-but-real effect is not mistaken for a rejection. The
/// tests pair it with a positive control on the same link.
pub const NO_EFFECT_WINDOW: Duration = Duration::from_secs(3);

// ── test identities ──────────────────────────────────────────────

/// A test DID + its keypair, resolvable offline via `--did-resolver-static`.
pub struct TestId {
    pub did: String,
    key: PrivateKey,
}

impl TestId {
    pub fn new(did: &str) -> Self {
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

/// One test at a time. Each test boots a server and binds a second iroh
/// endpoint; running the file in parallel starves the machine and the S2S
/// link never settles. Taken in `spawn_server_with_peer`, which every test
/// goes through, so they queue regardless of cargo's `--test-threads`.
static ONE_TEST_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A running `freeq-server` subprocess. `Drop` kills it and removes its dir.
pub struct TestServer {
    _dir: tempfile::TempDir,
    child: Child,
    pub irc_addr: String,
    pub db_path: String,
    _serial: MutexGuard<'static, ()>,
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

/// Deterministic iroh identity from a seed: the endpoint ID is known before
/// anything binds, so the server can allowlist the lying peer at boot and the
/// peer can dial the server without discovery.
fn identity(seed: u8) -> (iroh::SecretKey, String) {
    let key = iroh::SecretKey::from_bytes(&[seed; 32]);
    let id = key.public().to_string();
    (key, id)
}

/// Boot a server that accepts exactly one peer — the lying one — and dial it.
///
/// The server is *not* given `--s2s-peers`: it never dials out, so the only
/// link is the one the harness opens. Every DID in `ids` resolves offline via
/// `--did-resolver-static`, so local clients can authenticate with no network.
pub async fn spawn_server_with_peer(ids: &[&TestId]) -> (TestServer, LyingPeer) {
    // A failed test poisons the lock; the next test's server is unaffected.
    let serial = ONE_TEST_AT_A_TIME
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    // Fresh identities per test: two live endpoints sharing one node ID are,
    // to iroh, one node at two addresses.
    static NEXT_SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0x90);
    let seed = NEXT_SEED.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    let (_server_key, server_id) = identity(seed);
    let (peer_key, peer_id) = identity(seed.wrapping_add(1));

    let dir = tempfile::TempDir::new().unwrap();
    // The server loads its endpoint key from this file, so its ID matches the
    // one we derived above and the peer can dial it by direct address.
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("iroh-key.secret"), hex).unwrap();

    let irc_port = alloc_port();
    let iroh_port = alloc_port();
    let irc_addr = format!("127.0.0.1:{irc_port}");
    let db_path = dir.path().join("server.db").to_str().unwrap().to_string();
    let resolver: String = ids
        .iter()
        .map(|i| i.resolver_entry())
        .collect::<Vec<_>>()
        .join(",");

    let child = Command::new(env!("CARGO_BIN_EXE_freeq-server"))
        .args([
            "--listen-addr",
            &irc_addr,
            "--iroh",
            "--iroh-port",
            &iroh_port.to_string(),
            "--data-dir",
            dir.path().to_str().unwrap(),
            "--db-path",
            &db_path,
            "--s2s-allowed-peers",
            &peer_id,
            "--did-resolver-static",
            &resolver,
            "--server-name",
            &format!("test-lying-{seed}"),
        ])
        .env("RUST_LOG", "freeq_server=warn")
        .spawn()
        .expect("spawn freeq-server");

    let server = TestServer {
        _dir: dir,
        child,
        irc_addr,
        db_path,
        _serial: serial,
    };
    wait_port(&server.irc_addr).await;

    let peer = LyingPeer::dial(peer_key, peer_id, &server_id, iroh_port).await;
    (server, peer)
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

// ── the lying peer ───────────────────────────────────────────────

/// A peer link that speaks the real protocol and sends unreal events.
pub struct LyingPeer {
    /// Our iroh endpoint ID — the `origin` and `signer` on everything we send.
    pub id: String,
    key: iroh::SecretKey,
    send: iroh::endpoint::SendStream,
    counter: u64,
    /// Held so the QUIC connection and endpoint outlive the stream.
    _conn: iroh::endpoint::Connection,
    _endpoint: iroh::Endpoint,
}

impl LyingPeer {
    /// Dial the server under test and complete the handshake.
    ///
    /// The `Hello` is sent unsigned, which is what a real peer does — the
    /// handshake frames are the ones exempted from the signing requirement.
    /// Everything after it goes through [`LyingPeer::forge`] and is signed
    /// with this endpoint's key, so the receiver's signer-vs-transport
    /// identity check passes.
    async fn dial(key: iroh::SecretKey, id: String, server_id: &str, server_port: u16) -> Self {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(key.clone())
            .bind()
            .await
            .expect("bind lying-peer endpoint");

        let target: iroh::EndpointId = server_id.parse().expect("server endpoint id");
        let addr = iroh::EndpointAddr::new(target).with_ip_addr(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            server_port,
        )));

        // Retry the dial: the server's endpoint binds a moment after its IRC
        // listener, and that is the readiness signal we have.
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        let conn = loop {
            match endpoint.connect(addr.clone(), S2S_ALPN).await {
                Ok(c) => break c,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        panic!("lying peer could not dial server: {e}");
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        };

        let (send, recv) = conn.open_bi().await.expect("open_bi to server");

        // Drain whatever the server sends us (its Hello, HelloAck, SyncRequest
        // and every event it relays). Nothing here reads it, but an unread
        // stream eventually stalls the server's writer behind flow control.
        tokio::spawn(async move {
            let mut recv = recv;
            let mut buf = vec![0u8; 4096];
            while let Ok(Some(_)) = recv.read(&mut buf).await {}
        });

        let mut peer = LyingPeer {
            id: id.clone(),
            key,
            send,
            counter: 0,
            _conn: conn,
            _endpoint: endpoint,
        };

        peer.write(&S2sMessage::Hello {
            peer_id: id,
            server_name: "lying-peer".to_string(),
            protocol_version: 2,
            trust_level: Some("full".to_string()),
        })
        .await;

        peer
    }

    /// Send a message inside a valid signed envelope — the shape every
    /// non-handshake S2S message arrives in.
    pub async fn forge(&mut self, msg: S2sMessage) {
        let payload_json = serde_json::to_string(&msg).expect("serialize forged message");
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.key.sign(payload_json.as_bytes()).to_bytes());
        let envelope = S2sMessage::Signed {
            payload,
            signature,
            signer: self.id.clone(),
        };
        self.write(&envelope).await;
    }

    async fn write(&mut self, msg: &S2sMessage) {
        let json = serde_json::to_string(msg).expect("serialize s2s message");
        self.send
            .write_all(format!("{json}\n").as_bytes())
            .await
            .expect("write to s2s link");
        self.send.flush().await.expect("flush s2s link");
    }

    fn next_event_id(&mut self) -> String {
        self.counter += 1;
        format!("{}:{}", self.id, self.counter)
    }

    // ── event builders ───────────────────────────────────────────
    //
    // Each fills `origin` and `event_id` the way a real peer would, so a
    // rejection in a test is never just the dedup or self-origin filter.

    /// A remote user joining a channel. Also the harness's readiness probe:
    /// local members receive a JOIN line, which is proof the link is up and
    /// the server is processing our events.
    pub fn join(&mut self, nick: &str, channel: &str, did: Option<&str>) -> S2sMessage {
        S2sMessage::Join {
            event_id: self.next_event_id(),
            nick: nick.to_string(),
            channel: channel.to_string(),
            did: did.map(str::to_string),
            handle: None,
            is_op: false,
            actor_class: None,
            origin: self.id.clone(),
        }
    }

    /// A delete of `msgid`, claimed by `from` and (optionally) `account`.
    pub fn delete(
        &mut self,
        from: &str,
        target: &str,
        msgid: &str,
        account: Option<&str>,
    ) -> S2sMessage {
        S2sMessage::Tagmsg {
            event_id: self.next_event_id(),
            from: from.to_string(),
            target: target.to_string(),
            tags: HashMap::from([("+draft/delete".to_string(), msgid.to_string())]),
            origin: self.id.clone(),
            account: account.map(str::to_string),
        }
    }

    /// An edit that rewrites `replaces` with `text`.
    pub fn edit(
        &mut self,
        from: &str,
        target: &str,
        text: &str,
        replaces: &str,
        account: Option<&str>,
    ) -> S2sMessage {
        S2sMessage::Privmsg {
            event_id: self.next_event_id(),
            from: from.to_string(),
            target: target.to_string(),
            text: text.to_string(),
            origin: self.id.clone(),
            msgid: Some(format!("forged{}", self.counter)),
            sig: None,
            account: account.map(str::to_string),
            recipient_did: None,
            replaces_msgid: Some(replaces.to_string()),
            tags: HashMap::new(),
            multiline_lines: None,
        }
    }

    /// A plain message — the positive control that proves the link carries
    /// events at the moment a forged one was ignored.
    pub fn privmsg(
        &mut self,
        from: &str,
        target: &str,
        text: &str,
        account: Option<&str>,
    ) -> S2sMessage {
        S2sMessage::Privmsg {
            event_id: self.next_event_id(),
            from: from.to_string(),
            target: target.to_string(),
            text: text.to_string(),
            origin: self.id.clone(),
            msgid: None,
            sig: None,
            account: account.map(str::to_string),
            recipient_did: None,
            replaces_msgid: None,
            tags: HashMap::new(),
            multiline_lines: None,
        }
    }

    /// A message carrying a signature — the shape a peer uses to attribute
    /// signed words to someone. `msgid` is the event id the signature would
    /// have covered.
    #[allow(clippy::too_many_arguments)]
    pub fn signed_privmsg(
        &mut self,
        from: &str,
        target: &str,
        text: &str,
        account: Option<&str>,
        msgid: &str,
        sig: &str,
    ) -> S2sMessage {
        S2sMessage::Privmsg {
            event_id: self.next_event_id(),
            from: from.to_string(),
            target: target.to_string(),
            text: text.to_string(),
            origin: self.id.clone(),
            msgid: Some(msgid.to_string()),
            sig: Some(sig.to_string()),
            account: account.map(str::to_string),
            recipient_did: None,
            replaces_msgid: None,
            tags: HashMap::new(),
            multiline_lines: None,
        }
    }

    pub fn kick(&mut self, by: &str, nick: &str, channel: &str) -> S2sMessage {
        S2sMessage::Kick {
            event_id: self.next_event_id(),
            nick: nick.to_string(),
            channel: channel.to_string(),
            by: by.to_string(),
            reason: "forged".to_string(),
            origin: self.id.clone(),
        }
    }

    pub fn mode(
        &mut self,
        set_by: &str,
        channel: &str,
        mode: &str,
        arg: Option<&str>,
    ) -> S2sMessage {
        S2sMessage::Mode {
            event_id: self.next_event_id(),
            channel: channel.to_string(),
            mode: mode.to_string(),
            arg: arg.map(str::to_string),
            set_by: set_by.to_string(),
            origin: self.id.clone(),
        }
    }

    pub fn topic(&mut self, set_by: &str, channel: &str, topic: &str) -> S2sMessage {
        S2sMessage::Topic {
            event_id: self.next_event_id(),
            channel: channel.to_string(),
            topic: topic.to_string(),
            set_by: set_by.to_string(),
            origin: self.id.clone(),
        }
    }
}

// ── client helpers ───────────────────────────────────────────────

pub fn connect(
    server: &TestServer,
    id: &TestId,
    nick: &str,
) -> (client::ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: server.irc_addr.clone(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "lying peer test".to_string(),
        ..Default::default()
    };
    client::connect(config, Some(id.signer()))
}

pub async fn wait_event(
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

pub async fn wait_auth_and_register(rx: &mut mpsc::Receiver<Event>) {
    wait_event(
        rx,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
    wait_event(rx, |e| matches!(e, Event::Registered { .. }), "Registered").await;
}

/// Best-effort: wait up to `dur` for an event matching `pred`. `None` on
/// timeout — the shape every "this must NOT happen" assertion needs.
pub async fn try_event(
    rx: &mut mpsc::Receiver<Event>,
    pred: impl Fn(&Event) -> bool,
    dur: Duration,
) -> Option<Event> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(e) if pred(&e) => return Some(e),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Drive the lying peer's link until a local client sees its effect: send
/// `mallory`'s JOIN until the JOIN line arrives. The S2S link comes up
/// asynchronously after the dial, and this is the behavioural gate for it —
/// no fixed sleep. Every test starts here, so a later forged event that
/// produces nothing is known to have travelled a working link.
pub async fn warm_link(peer: &mut LyingPeer, nick: &str, channel: &str, rx: &mut mpsc::Receiver<Event>) {
    let deadline = tokio::time::Instant::now() + SETTLE;
    while tokio::time::Instant::now() < deadline {
        let join = peer.join(nick, channel, None);
        peer.forge(join).await;
        let seen = try_event(
            rx,
            |e| matches!(e, Event::Joined { nick: n, .. } if n.eq_ignore_ascii_case(nick)),
            Duration::from_secs(2),
        )
        .await;
        if seen.is_some() {
            return;
        }
    }
    panic!("lying peer's JOIN never reached a local client — S2S link never came up");
}

/// The `msgid` a local client saw on a message it received.
pub fn msgid_of(event: &Event) -> String {
    match event {
        Event::Message { tags, .. } => tags
            .get("msgid")
            .cloned()
            .expect("server stamps msgid on every PRIVMSG"),
        other => panic!("not a message: {other:?}"),
    }
}

/// Is this message row soft-deleted in the server's database? Panics if the
/// row is absent — a missing row is a different failure than a deleted one.
pub fn is_deleted(db_path: &str, msgid: &str) -> bool {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT deleted_at IS NOT NULL FROM messages WHERE msgid = ?1",
        rusqlite::params![msgid],
        |r| r.get(0),
    )
    .expect("message row exists")
}

/// The key id of a signing key `did` has registered with this server.
///
/// A forged signature has to name a key the receiver actually holds, or the
/// verdict is "cannot check" and nothing is proven about the strip. Reading it
/// out of the server's own store is how a test gets one without ever holding
/// the private half.
pub fn registered_kid(db_path: &str, did: &str) -> Option<String> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT kid FROM signing_keys WHERE did = ?1 ORDER BY registered_at DESC LIMIT 1",
        rusqlite::params![did],
        |r| r.get(0),
    )
    .ok()
}

/// How many rows make up the logical message `root` — the original plus one
/// per applied revision. An edit that was rejected leaves this at 1.
pub fn revision_count(db_path: &str, root: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE msgid = ?1 OR root_msgid = ?1",
        rusqlite::params![root],
        |r| r.get(0),
    )
    .expect("count revisions")
}
