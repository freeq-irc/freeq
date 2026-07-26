//! Acceptance tests for the IRCv3 `draft/read-marker` extension (MARKREAD).
//!
//! Exercises the wire protocol end-to-end over a real TCP connection:
//! set/get roundtrip, forward-only (monotonic) enforcement, cross-connection
//! broadcast to the same DID (multi-device), guest session-local behavior,
//! DID persistence across reconnect, and malformed-input FAIL replies.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:rm_alice";
const DID_BOB: &str = "did:plc:rm_bob";

fn resolver_with(entries: Vec<(&str, &PrivateKey)>) -> DidResolver {
    let mut docs = HashMap::new();
    for (did, key) in entries {
        docs.insert(
            did.to_string(),
            did::make_test_did_document(did, &key.public_key_multibase()),
        );
    }
    DidResolver::static_map(docs)
}

async fn start(resolver: DidResolver) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    // Read markers for DID users persist in SQLite — the server needs a DB.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-readmarker".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

async fn run(addr: SocketAddr, f: impl FnOnce(SocketAddr) + Send + 'static) {
    tokio::task::spawn_blocking(move || f(addr)).await.unwrap();
}

// ── Raw IRC client with read-marker cap ──

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl C {
    /// Guest connection that negotiates the read-marker cap.
    fn guest(addr: SocketAddr, nick: &str) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        let mut c = Self {
            reader: BufReader::new(s),
            writer: w,
        };
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx("CAP REQ :message-tags server-time draft/read-marker");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c
    }

    /// DID-authenticated connection that negotiates the read-marker cap.
    /// `key_bytes` is the raw ed25519 secret so a caller can spin up multiple
    /// connections for the same identity (`PrivateKey` isn't `Clone`).
    fn sasl(addr: SocketAddr, nick: &str, did: &str, key_bytes: &[u8]) -> Self {
        let key = PrivateKey::ed25519_from_bytes(key_bytes).unwrap();
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        let mut c = Self {
            reader: BufReader::new(s),
            writer: w,
        };
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx("CAP REQ :sasl message-tags server-time draft/read-marker");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let challenge_line = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let challenge = challenge_line.strip_prefix("AUTHENTICATE ").unwrap();
        let bytes = auth::decode_challenge_bytes(challenge).unwrap();
        let signer = KeySigner::new(did.to_string(), key);
        let resp = signer.respond(&bytes).unwrap();
        c.tx(&format!("AUTHENTICATE {}", auth::encode_response(&resp)));
        c.num("903");
        c.tx("CAP END");
        c
    }

    fn tx(&mut self, l: &str) {
        writeln!(self.writer, "{l}\r").unwrap();
        self.writer.flush().ok();
    }
    fn rx(&mut self, p: impl Fn(&str) -> bool, d: &str) -> String {
        let mut b = String::new();
        loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => panic!("EOF: {d}"),
                Ok(_) => {
                    let l = b.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {t}\r");
                        let _ = self.writer.flush();
                        continue;
                    }
                    if p(l) {
                        return l.to_string();
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    panic!("Timeout: {d}")
                }
                Err(e) => panic!("{d}: {e}"),
            }
        }
    }
    fn num(&mut self, c: &str) -> String {
        self.rx(|l| l.split_whitespace().nth(1) == Some(c), c)
    }
    fn reg(&mut self) {
        self.num("001");
    }
    fn drain(&mut self) {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(300)))
            .ok();
        let mut b = String::new();
        loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => break,
                Ok(_) => {
                    if b.starts_with("PING") {
                        let t = b.trim_end().strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {t}\r");
                        let _ = self.writer.flush();
                    }
                }
                Err(_) => break,
            }
        }
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
    }
    fn maybe(&mut self, p: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
        let mut b = String::new();
        let r = loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => break None,
                Ok(_) => {
                    let l = b.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {t}\r");
                        let _ = self.writer.flush();
                        continue;
                    }
                    if p(l) {
                        break Some(l.to_string());
                    }
                }
                Err(_) => break None,
            }
        };
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        r
    }
}

// ═══════════════════════════════════════════════════════════════
// GET / SET roundtrip
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn get_with_no_marker_returns_star() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_star");
        a.reg();
        a.drain();
        a.tx("MARKREAD #room");
        let line = a.rx(|l| l.starts_with("MARKREAD"), "marker reply");
        assert_eq!(line, "MARKREAD #room *", "no marker → star: {line}");
    })
    .await;
}

#[tokio::test]
async fn set_then_get_roundtrip() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_rt");
        a.reg();
        a.drain();
        a.tx("MARKREAD #room timestamp=2026-07-02T10:00:00.000Z");
        let set = a.rx(|l| l.starts_with("MARKREAD"), "set reply");
        assert_eq!(set, "MARKREAD #room timestamp=2026-07-02T10:00:00.000Z");

        a.tx("MARKREAD #room");
        let got = a.rx(|l| l.starts_with("MARKREAD"), "get reply");
        assert_eq!(got, "MARKREAD #room timestamp=2026-07-02T10:00:00.000Z");
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// Forward-only (monotonic) enforcement
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn stale_timestamp_does_not_regress_marker() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_fwd");
        a.reg();
        a.drain();
        // Set to a newer value first.
        a.tx("MARKREAD #room timestamp=2026-07-02T12:00:00.000Z");
        a.rx(|l| l.starts_with("MARKREAD"), "set newer");

        // Attempt to move it BACK — server must reply with the stored (newer)
        // value and NOT regress.
        a.tx("MARKREAD #room timestamp=2026-07-02T09:00:00.000Z");
        let reply = a.rx(|l| l.starts_with("MARKREAD"), "stale reply");
        assert_eq!(
            reply, "MARKREAD #room timestamp=2026-07-02T12:00:00.000Z",
            "stale set must return the newer stored value: {reply}"
        );

        // Confirm via GET that the marker is still the newer value.
        a.tx("MARKREAD #room");
        let got = a.rx(|l| l.starts_with("MARKREAD"), "get after stale");
        assert_eq!(got, "MARKREAD #room timestamp=2026-07-02T12:00:00.000Z");
    })
    .await;
}

#[tokio::test]
async fn equal_timestamp_is_not_an_advance() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_eq");
        a.reg();
        a.drain();
        a.tx("MARKREAD #room timestamp=2026-07-02T12:00:00.000Z");
        a.rx(|l| l.starts_with("MARKREAD"), "set");
        // Re-sending the same value is a no-op advance; still replies current.
        a.tx("MARKREAD #room timestamp=2026-07-02T12:00:00.000Z");
        let reply = a.rx(|l| l.starts_with("MARKREAD"), "equal reply");
        assert_eq!(reply, "MARKREAD #room timestamp=2026-07-02T12:00:00.000Z");
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// Cross-connection broadcast (multi-device, same DID)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn marker_broadcasts_to_other_connections_of_same_did() {
    let key = PrivateKey::generate_ed25519();
    let kb = key.secret_bytes();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &key)])).await;
    run(addr, move |addr| {
        // Two devices, same DID.
        let mut dev1 = C::sasl(addr, "alice", DID_ALICE, &kb);
        dev1.reg();
        dev1.drain();
        let mut dev2 = C::sasl(addr, "alice", DID_ALICE, &kb);
        dev2.reg();
        dev2.drain();

        // dev1 advances the marker.
        dev1.tx("MARKREAD #team timestamp=2026-07-02T15:30:00.000Z");
        let ack = dev1.rx(|l| l.starts_with("MARKREAD"), "dev1 ack");
        assert_eq!(ack, "MARKREAD #team timestamp=2026-07-02T15:30:00.000Z");

        // dev2 receives the marker broadcast without asking.
        let pushed = dev2.rx(|l| l.starts_with("MARKREAD"), "dev2 broadcast");
        assert_eq!(
            pushed, "MARKREAD #team timestamp=2026-07-02T15:30:00.000Z",
            "other device should receive the pushed marker: {pushed}"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// DID persistence across reconnect
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn did_marker_persists_across_reconnect() {
    let key = PrivateKey::generate_ed25519();
    let kb = key.secret_bytes();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &key)])).await;
    run(addr, move |addr| {
        {
            let mut dev = C::sasl(addr, "alice", DID_ALICE, &kb);
            dev.reg();
            dev.drain();
            dev.tx("MARKREAD #persist timestamp=2026-07-02T18:00:00.000Z");
            dev.rx(|l| l.starts_with("MARKREAD"), "set");
            dev.tx("QUIT");
        }
        // Reconnect as the same DID; the marker should still be there.
        let mut again = C::sasl(addr, "alice", DID_ALICE, &kb);
        again.reg();
        again.drain();
        again.tx("MARKREAD #persist");
        let got = again.rx(|l| l.starts_with("MARKREAD"), "get after reconnect");
        assert_eq!(
            got, "MARKREAD #persist timestamp=2026-07-02T18:00:00.000Z",
            "marker must survive reconnect: {got}"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// Guest behavior (session-local, no cross-session leak)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn guest_markers_are_session_local() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut g1 = C::guest(addr, "guest_one");
        g1.reg();
        g1.drain();
        g1.tx("MARKREAD #g timestamp=2026-07-02T20:00:00.000Z");
        g1.rx(|l| l.starts_with("MARKREAD"), "g1 set");

        // A separate guest connection shares no identity — it sees no marker.
        let mut g2 = C::guest(addr, "guest_two");
        g2.reg();
        g2.drain();
        g2.tx("MARKREAD #g");
        let got = g2.rx(|l| l.starts_with("MARKREAD"), "g2 get");
        assert_eq!(got, "MARKREAD #g *", "guest markers must not leak: {got}");
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// Malformed input → FAIL
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn missing_params_fails() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_np");
        a.reg();
        a.drain();
        a.tx("MARKREAD");
        let fail = a.rx(|l| l.contains("FAIL MARKREAD"), "fail reply");
        assert!(
            fail.contains("NEED_MORE_PARAMS"),
            "missing target → NEED_MORE_PARAMS: {fail}"
        );
    })
    .await;
}

#[tokio::test]
async fn malformed_timestamp_fails() {
    let (addr, _h) = start(resolver_with(vec![])).await;
    run(addr, |addr| {
        let mut a = C::guest(addr, "rm_bad");
        a.reg();
        a.drain();
        // Not an ISO timestamp.
        a.tx("MARKREAD #room timestamp=nonsense");
        let fail = a.rx(|l| l.contains("FAIL MARKREAD"), "fail reply");
        assert!(
            fail.contains("INVALID_PARAMS"),
            "bad timestamp → INVALID_PARAMS: {fail}"
        );

        // Missing the `timestamp=` prefix entirely is also invalid.
        a.tx("MARKREAD #room 2026-07-02T20:00:00.000Z");
        let fail2 = a.rx(|l| l.contains("FAIL MARKREAD"), "fail reply 2");
        assert!(
            fail2.contains("INVALID_PARAMS"),
            "unprefixed → INVALID: {fail2}"
        );

        // A bad set must not have created a marker.
        a.tx("MARKREAD #room");
        let got = a.maybe(|l| l.starts_with("MARKREAD #room"), 1500);
        assert_eq!(got.as_deref(), Some("MARKREAD #room *"));
    })
    .await;
}

/// A DM read marker is tied to the conversation, not the alias used to
/// address it. A marker set addressing the peer by DID must be readable
/// addressing them by nick (both resolve to the canonical dm key).
#[tokio::test]
async fn dm_marker_keys_by_conversation_not_alias() {
    let key_a = PrivateKey::generate_ed25519();
    let key_b = PrivateKey::generate_ed25519();
    let ka = key_a.secret_bytes();
    let kb = key_b.secret_bytes();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &key_a), (DID_BOB, &key_b)])).await;
    run(addr, move |addr| {
        // Bob connects so the server learns his nick<->DID binding.
        let mut bob = C::sasl(addr, "bob", DID_BOB, &kb);
        bob.reg();
        bob.drain();

        let mut alice = C::sasl(addr, "alice", DID_ALICE, &ka);
        alice.reg();
        alice.drain();

        // Set the marker addressing Bob by his DID.
        alice.tx(&format!(
            "MARKREAD {DID_BOB} timestamp=2026-07-02T21:00:00.000Z"
        ));
        alice.rx(|l| l.starts_with("MARKREAD"), "set by DID");

        // Read it back addressing Bob by his nick — same conversation.
        alice.tx("MARKREAD bob");
        let got = alice.rx(|l| l.starts_with("MARKREAD bob"), "get by nick");
        assert_eq!(
            got, "MARKREAD bob timestamp=2026-07-02T21:00:00.000Z",
            "DM marker set by DID must be readable by nick: {got}"
        );
    })
    .await;
}
