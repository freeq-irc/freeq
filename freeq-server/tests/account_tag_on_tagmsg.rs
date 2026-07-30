//! `account` on TAGMSG delivery.
//!
//! account-tag was added scoped to PRIVMSG/NOTICE, when nothing about a
//! TAGMSG was a trust decision. Client-side authorship gates changed that:
//! a client deciding whether the sender of a delete may delete the message
//! reads `account` off the event, and a nick is not an identity. The IRCv3
//! account-tag spec is explicit that the tag belongs on everything — "the
//! tag MUST be added by the ircd to all commands sent by a user (e.g.
//! PRIVMSG, MODE, NOTICE, and all others)" — so the narrower reading was
//! the deviation.
//!
//! Delivery is per-recipient: only sessions that negotiated `account-tag`
//! get it, and a guest sender has no DID to name.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:acct_tag_alice";

/// Caps a recipient asks for. `account-tag` is the variable under test.
const CAPS_WITH_ACCOUNT: &str = "sasl message-tags server-time echo-message account-tag";
const CAPS_WITHOUT_ACCOUNT: &str = "sasl message-tags server-time echo-message";

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
    // Deletes look the original message up by msgid, so a database is required.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp); // outlive the server
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-acct-tag".to_string(),
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

// ── raw IRC client ───────────────────────────────────────────────

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl C {
    /// A guest — no SASL, so the server has no DID for them.
    fn guest(addr: SocketAddr, nick: &str, caps: &str) -> Self {
        let mut c = Self::open(addr, nick, caps);
        c.tx("CAP END");
        c
    }

    /// An authenticated client, so the server has a DID to put in `account`.
    fn authed(addr: SocketAddr, nick: &str, caps: &str, did: &str, key: PrivateKey) -> Self {
        let mut c = Self::open(addr, nick, caps);
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let line = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let challenge = line.strip_prefix("AUTHENTICATE ").unwrap();
        let bytes = auth::decode_challenge_bytes(challenge).unwrap();
        let resp = KeySigner::new(did.to_string(), key).respond(&bytes).unwrap();
        c.tx(&format!("AUTHENTICATE {}", auth::encode_response(&resp)));
        c.num("903");
        c.tx("CAP END");
        c
    }

    fn open(addr: SocketAddr, nick: &str, caps: &str) -> Self {
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
        c.tx(&format!("CAP REQ :{caps}"));
        c.rx(|l| l.contains("ACK"), "CAP ACK");
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
                Ok(0) => panic!("EOF waiting for {d}"),
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
                Err(e) => panic!("waiting for {d}: {e}"),
            }
        }
    }

    fn num(&mut self, c: &str) -> String {
        self.rx(|l| l.split_whitespace().nth(1) == Some(c), c)
    }

    fn reg(&mut self) {
        self.num("001");
    }

    fn join(&mut self, channel: &str) {
        self.tx(&format!("JOIN {channel}"));
        self.num("366");
        self.drain();
    }

    fn drain(&mut self) {
        self.set_timeout(300);
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
        self.set_timeout(5000);
    }

    /// Best-effort read: `None` if nothing matching arrives in `ms`.
    fn maybe(&mut self, p: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        self.set_timeout(ms);
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
        self.set_timeout(5000);
        r
    }

    fn set_timeout(&mut self, ms: u64) {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
    }

    fn extract_msgid(line: &str) -> String {
        line.strip_prefix('@')
            .and_then(|s| s.split_once(' ').map(|(t, _)| t))
            .and_then(|tags| {
                tags.split(';')
                    .find_map(|t| t.strip_prefix("msgid=").map(str::to_string))
            })
            .unwrap_or_default()
    }
}

/// The `account` tag value on an IRC line, if it carries one. Matches the
/// whole tag so `account=` is not confused with `+freeq.at/account-ish`.
fn account_of(line: &str) -> Option<String> {
    line.strip_prefix('@')
        .and_then(|s| s.split_once(' ').map(|(t, _)| t))
        .and_then(|tags| {
            tags.split(';')
                .find_map(|t| t.strip_prefix("account=").map(str::to_string))
        })
}

// ── delete ───────────────────────────────────────────────────────

#[tokio::test]
async fn delete_names_the_sender_for_a_recipient_that_asked_for_account_tag() {
    let key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::authed(addr, "at_alice", CAPS_WITH_ACCOUNT, DID_ALICE, key);
        alice.reg();
        alice.drain();
        let mut bob = C::guest(addr, "at_bob", CAPS_WITH_ACCOUNT);
        bob.reg();
        bob.drain();
        alice.join("#atd");
        bob.join("#atd");

        alice.tx("PRIVMSG #atd :a message to delete");
        let seen = bob.rx(|l| l.contains("a message to delete"), "alice's message");
        let msgid = C::extract_msgid(&seen);
        assert!(!msgid.is_empty(), "no msgid on the message: {seen}");
        bob.drain();

        alice.tx(&format!("@+draft/delete={msgid} TAGMSG #atd"));
        let del = bob
            .maybe(|l| l.contains("TAGMSG") && l.contains("+draft/delete"), 2000)
            .expect("bob receives the delete");
        assert_eq!(
            account_of(&del).as_deref(),
            Some(DID_ALICE),
            "the delete must name who sent it: {del}"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_omits_account_for_a_recipient_that_did_not_ask() {
    let key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::authed(addr, "at2_alice", CAPS_WITH_ACCOUNT, DID_ALICE, key);
        alice.reg();
        alice.drain();
        // Bob negotiated message-tags but NOT account-tag.
        let mut bob = C::guest(addr, "at2_bob", CAPS_WITHOUT_ACCOUNT);
        bob.reg();
        bob.drain();
        alice.join("#atd2");
        bob.join("#atd2");

        alice.tx("PRIVMSG #atd2 :another message");
        let seen = bob.rx(|l| l.contains("another message"), "alice's message");
        let msgid = C::extract_msgid(&seen);
        bob.drain();

        alice.tx(&format!("@+draft/delete={msgid} TAGMSG #atd2"));
        let del = bob
            .maybe(|l| l.contains("TAGMSG") && l.contains("+draft/delete"), 2000)
            .expect("bob still receives the delete itself");
        assert_eq!(
            account_of(&del),
            None,
            "a client that never asked for account-tag must not be sent one: {del}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_guests_delete_carries_no_account() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        // No SASL: the server has no DID for this sender, so there is nothing
        // to name — and naming the nick instead would be exactly the guess the
        // tag exists to replace.
        let mut alice = C::guest(addr, "at3_alice", CAPS_WITH_ACCOUNT);
        alice.reg();
        alice.drain();
        let mut bob = C::guest(addr, "at3_bob", CAPS_WITH_ACCOUNT);
        bob.reg();
        bob.drain();
        alice.join("#atd3");
        bob.join("#atd3");

        alice.tx("PRIVMSG #atd3 :guest message");
        let seen = bob.rx(|l| l.contains("guest message"), "alice's message");
        let msgid = C::extract_msgid(&seen);
        bob.drain();

        alice.tx(&format!("@+draft/delete={msgid} TAGMSG #atd3"));
        let del = bob
            .maybe(|l| l.contains("TAGMSG") && l.contains("+draft/delete"), 2000)
            .expect("bob receives the guest's delete");
        assert_eq!(
            account_of(&del),
            None,
            "a guest has no account to tag: {del}"
        );
    })
    .await;
}

// ── the generic TAGMSG relay ─────────────────────────────────────

#[tokio::test]
async fn a_channel_reaction_names_the_sender() {
    let key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::authed(addr, "at4_alice", CAPS_WITH_ACCOUNT, DID_ALICE, key);
        alice.reg();
        alice.drain();
        let mut bob = C::guest(addr, "at4_bob", CAPS_WITH_ACCOUNT);
        bob.reg();
        bob.drain();
        alice.join("#atr");
        bob.join("#atr");

        bob.tx("PRIVMSG #atr :react to this");
        let seen = alice.rx(|l| l.contains("react to this"), "bob's message");
        let msgid = C::extract_msgid(&seen);
        bob.drain();

        alice.tx(&format!("@+react=\u{1F44D};+reply={msgid} TAGMSG #atr"));
        let tagmsg = bob
            .maybe(|l| l.contains("TAGMSG") && l.contains("+react"), 2000)
            .expect("bob receives the reaction");
        assert_eq!(
            account_of(&tagmsg).as_deref(),
            Some(DID_ALICE),
            "a reaction must name who made it: {tagmsg}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_direct_tagmsg_names_the_sender() {
    let key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::authed(addr, "at5_alice", CAPS_WITH_ACCOUNT, DID_ALICE, key);
        alice.reg();
        alice.drain();
        let mut bob = C::guest(addr, "at5_bob", CAPS_WITH_ACCOUNT);
        bob.reg();
        bob.drain();

        // A DM, not a channel — the other delivery branch.
        alice.tx("@+typing=active TAGMSG at5_bob");
        let tagmsg = bob
            .maybe(|l| l.contains("TAGMSG") && l.contains("+typing"), 2000)
            .expect("bob receives the direct TAGMSG");
        assert_eq!(
            account_of(&tagmsg).as_deref(),
            Some(DID_ALICE),
            "a directed TAGMSG must name who sent it: {tagmsg}"
        );
    })
    .await;
}
