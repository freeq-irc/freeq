//! SEARCH command acceptance tests.
//!
//! Covers membership gating, DM auth requirements, DM privacy (search runs
//! against the requester's own canonical DM key), result batching, and
//! parameter validation.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_A: &str = "did:plc:search_alice";
const DID_B: &str = "did:plc:search_bob";
const DID_C: &str = "did:plc:search_eve";

fn resolver(entries: Vec<(&str, &PrivateKey)>) -> DidResolver {
    let mut docs = HashMap::new();
    for (did, key) in entries {
        docs.insert(
            did.to_string(),
            did::make_test_did_document(did, &key.public_key_multibase()),
        );
    }
    DidResolver::static_map(docs)
}

async fn start(r: DidResolver) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-search".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, r)
        .start()
        .await
        .unwrap()
}

async fn run(addr: SocketAddr, f: impl FnOnce(SocketAddr) + Send + 'static) {
    tokio::task::spawn_blocking(move || f(addr)).await.unwrap();
}

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl C {
    fn with_caps(addr: SocketAddr, nick: &str) -> Self {
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
        c.tx("CAP REQ :message-tags server-time batch");
        c.rx(|l| l.contains("ACK"), "ACK");
        c.tx("CAP END");
        c
    }
    fn with_sasl(addr: SocketAddr, nick: &str, did: &str, key: PrivateKey) -> Self {
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
        c.tx("CAP REQ :sasl message-tags server-time batch");
        c.rx(|l| l.contains("ACK"), "ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let ch = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let bytes =
            auth::decode_challenge_bytes(ch.strip_prefix("AUTHENTICATE ").unwrap()).unwrap();
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
    /// Collect all PRIVMSG lines from a search batch response.
    fn collect_batch_messages(&mut self) -> Vec<String> {
        let mut msgs = Vec::new();
        self.rx(|l| l.contains("BATCH +"), "BATCH start");
        loop {
            let line = self.rx(|_| true, "batch line");
            if line.contains("BATCH -") {
                break;
            }
            if line.contains("PRIVMSG") {
                msgs.push(line);
            }
        }
        msgs
    }
}

fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

// ═══════════════════════════════════════════════════════════════
// CHANNEL SEARCH
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn search_finds_channel_messages_for_member() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "alice");
        alice.reg();
        alice.tx("JOIN #search");
        alice.drain();
        alice.tx("PRIVMSG #search :the deploy failed loudly");
        alice.tx("PRIVMSG #search :lunch plans anyone");
        alice.tx("PRIVMSG #search :deploy is green now");
        settle();
        alice.drain();

        alice.tx("SEARCH #search :deploy");
        let msgs = alice.collect_batch_messages();
        assert_eq!(msgs.len(), 2, "expected 2 deploy matches, got: {msgs:?}");
        assert!(msgs[0].contains("deploy failed loudly"));
        assert!(msgs[1].contains("deploy is green now"));
        // Results carry msgid tags for permalinking.
        assert!(msgs[0].contains("msgid="), "no msgid tag: {}", msgs[0]);
    })
    .await;
}

/// A hit on an edited message is addressed by the root msgid — the id every
/// client holds the message under — not the matching revision's own id.
#[tokio::test]
async fn search_hit_for_edited_message_carries_the_root_msgid() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "alice");
        let mut bob = C::with_caps(addr, "bob");
        alice.reg();
        bob.reg();
        alice.tx("JOIN #edits");
        bob.tx("JOIN #edits");
        settle();
        alice.drain();
        bob.drain();

        alice.tx("PRIVMSG #edits :original wording here");
        // bob's copy carries the server-assigned msgid — the root.
        let line = bob.rx(|l| l.contains("original wording here"), "original at bob");
        let root = line
            .split("msgid=")
            .nth(1)
            .expect("broadcast carries msgid")
            .split([';', ' '])
            .next()
            .unwrap()
            .to_string();

        alice.tx(&format!(
            "@+draft/edit={root} PRIVMSG #edits :revised wording here"
        ));
        settle();
        alice.drain();
        bob.drain();

        alice.tx("SEARCH #edits :revised");
        let msgs = alice.collect_batch_messages();
        assert_eq!(msgs.len(), 1, "one hit for the current text: {msgs:?}");
        assert!(msgs[0].contains("revised wording here"));
        assert!(
            msgs[0].contains(&format!("msgid={root}")),
            "hit must be addressed by the root id {root}: {}",
            msgs[0]
        );
    })
    .await;
}

#[tokio::test]
async fn search_uses_dedicated_batch_type() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "alice");
        alice.reg();
        alice.tx("JOIN #batchtype");
        alice.drain();
        alice.tx("PRIVMSG #batchtype :findme please");
        settle();
        alice.drain();

        alice.tx("SEARCH #batchtype :findme");
        let opener = alice.rx(|l| l.contains("BATCH +"), "BATCH start");
        assert!(
            opener.contains("freeq.at/search"),
            "wrong batch type: {opener}"
        );
    })
    .await;
}

#[tokio::test]
async fn search_rejects_non_member() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "alice");
        alice.reg();
        alice.tx("JOIN #private-ish");
        alice.drain();
        alice.tx("PRIVMSG #private-ish :sensitive content");
        settle();

        let mut eve = C::with_caps(addr, "eve");
        eve.reg();
        eve.tx("SEARCH #private-ish :sensitive");
        let fail = eve.rx(|l| l.contains("FAIL SEARCH"), "FAIL");
        assert!(fail.contains("INVALID_TARGET"), "got: {fail}");
    })
    .await;
}

#[tokio::test]
async fn search_requires_params() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "alice");
        alice.reg();
        alice.tx("SEARCH #whatever");
        let fail = alice.rx(|l| l.contains("FAIL SEARCH"), "FAIL");
        assert!(fail.contains("NEED_MORE_PARAMS"), "got: {fail}");
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// DM SEARCH
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn dm_search_requires_authentication() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, |addr| {
        let mut guest = C::with_caps(addr, "guest");
        guest.reg();
        guest.tx("SEARCH someone :anything");
        let fail = guest.rx(|l| l.contains("FAIL SEARCH"), "FAIL");
        assert!(fail.contains("ACCOUNT_REQUIRED"), "got: {fail}");
    })
    .await;
}

#[tokio::test]
async fn dm_search_finds_own_conversation_only() {
    let ka = PrivateKey::generate_ed25519();
    let kb = PrivateKey::generate_ed25519();
    let kc = PrivateKey::generate_ed25519();
    let r = resolver(vec![(DID_A, &ka), (DID_B, &kb), (DID_C, &kc)]);
    let (addr, _h) = start(r).await;
    run(addr, move |addr| {
        let mut alice = C::with_sasl(addr, "alice", DID_A, ka);
        alice.reg();
        let mut bob = C::with_sasl(addr, "bob", DID_B, kb);
        bob.reg();
        let mut eve = C::with_sasl(addr, "eve", DID_C, kc);
        eve.reg();

        alice.tx("PRIVMSG bob :secret rendezvous at noon");
        settle();
        alice.drain();
        bob.drain();

        // Bob searches his DM with alice — finds it.
        bob.tx("SEARCH alice :rendezvous");
        let msgs = bob.collect_batch_messages();
        assert_eq!(msgs.len(), 1, "bob should find the DM: {msgs:?}");
        assert!(msgs[0].contains("secret rendezvous"));

        // Eve searches *her* DM key with alice — sees nothing of alice↔bob.
        eve.tx("SEARCH alice :rendezvous");
        let msgs = eve.collect_batch_messages();
        assert!(msgs.is_empty(), "eve must not see alice/bob DMs: {msgs:?}");
    })
    .await;
}
