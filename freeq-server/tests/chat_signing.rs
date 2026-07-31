//! Acceptance tests for signer-minted event ids (`+freeq.at/eventid`).
//!
//! A signed chat event signs its own id, and a client cannot sign an id the
//! server invents after it sends. So the sender mints the id and the server
//! either adopts it — making the signed value and the filed value the same
//! value — or refuses it and says why, never quietly filing the event under a
//! substitute the signature doesn't cover.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::chatsig::EVENT_ID_TAG;
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:sig_alice";

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
    // A database is the point: adoption has to refuse an id already on file.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp); // outlives the server
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-sig".to_string(),
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

/// A raw IRC client, so a test can put any tag on the wire.
struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl C {
    fn guest(addr: SocketAddr, nick: &str) -> Self {
        let mut c = Self::open(addr);
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx("CAP REQ :message-tags server-time echo-message draft/chathistory");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c.num("001");
        c
    }

    fn authenticated(addr: SocketAddr, nick: &str, did: &str, key: PrivateKey) -> Self {
        let mut c = Self::open(addr);
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx("CAP REQ :sasl message-tags server-time echo-message draft/chathistory");
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
        c.num("001");
        c
    }

    fn open(addr: SocketAddr) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        Self {
            reader: BufReader::new(s),
            writer: w,
        }
    }

    fn tx(&mut self, l: &str) {
        writeln!(self.writer, "{l}\r").unwrap();
        self.writer.flush().ok();
    }

    fn rx(&mut self, p: impl Fn(&str) -> bool, what: &str) -> String {
        let mut b = String::new();
        loop {
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => panic!("EOF waiting for {what}"),
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
                Err(e) => panic!("{what}: {e}"),
            }
        }
    }

    fn num(&mut self, code: &str) -> String {
        self.rx(|l| l.split_whitespace().nth(1) == Some(code), code)
    }

    /// Wait up to `ms` for a matching line, `None` if it never comes.
    fn maybe(&mut self, p: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
        let mut b = String::new();
        let found = loop {
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
        found
    }

    fn join(&mut self, channel: &str) {
        self.tx(&format!("JOIN {channel}"));
        self.rx(|l| l.contains(&format!("JOIN {channel}")), "JOIN echo");
        self.num("366");
    }

    fn send_with_id(&mut self, id: &str, target: &str, text: &str) {
        self.tx(&format!("@{EVENT_ID_TAG}={id} PRIVMSG {target} :{text}"));
    }

    fn msgid_of(line: &str) -> Option<String> {
        line.strip_prefix('@')
            .and_then(|s| s.split_once(' ').map(|(t, _)| t))
            .and_then(|tags| {
                tags.split(';')
                    .find_map(|t| t.strip_prefix("msgid=").map(|v| v.to_string()))
            })
    }
}

fn key() -> PrivateKey {
    PrivateKey::generate_ed25519()
}

/// A well-formed id whose embedded timestamp is `offset_ms` from now.
fn id_at_offset(offset_ms: i64) -> String {
    // Mint a real id, then splice in a timestamp the server should judge.
    let id = freeq_server::msgid::generate();
    let now = freeq_server::msgid::timestamp_ms(&id).unwrap() as i64;
    let target = (now + offset_ms).max(0) as u64;
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut head = [0u8; 10];
    let mut t = target;
    for i in (0..10).rev() {
        head[i] = CROCKFORD[(t & 0x1F) as usize];
        t >>= 5;
    }
    format!("{}{}", std::str::from_utf8(&head).unwrap(), &id[10..])
}

#[tokio::test]
async fn an_authenticated_sender_keeps_the_id_it_minted() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, k);
        alice.join("#sig");

        let minted = freeq_server::msgid::generate();
        alice.send_with_id(&minted, "#sig", "signed and filed");

        // The echo names the id the sender minted, not one the server invented.
        let echo = alice.rx(
            |l| l.contains("PRIVMSG #sig") && l.contains("signed and filed"),
            "echo",
        );
        assert_eq!(
            C::msgid_of(&echo).as_deref(),
            Some(minted.as_str()),
            "server must file the message under the sender's id: {echo}"
        );

        // And history agrees — the id a signature covers is the id that lasts.
        alice.tx("CHATHISTORY LATEST #sig * 10");
        let replayed = alice.rx(
            |l| l.contains("PRIVMSG #sig") && l.contains("signed and filed"),
            "history",
        );
        assert_eq!(C::msgid_of(&replayed).as_deref(), Some(minted.as_str()));
    })
    .await;
}

#[tokio::test]
async fn the_adopted_id_travels_as_msgid_and_not_as_two_tags() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#sig");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#sig");

        let minted = freeq_server::msgid::generate();
        alice.send_with_id(&minted, "#sig", "one id, one tag");

        let seen = bob.rx(|l| l.contains("one id, one tag"), "delivery");
        assert_eq!(C::msgid_of(&seen).as_deref(), Some(minted.as_str()));
        assert!(
            !seen.contains("eventid"),
            "the id must travel once, as msgid: {seen}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_message_without_the_tag_still_gets_a_server_minted_id() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, k);
        alice.join("#sig");
        alice.tx("PRIVMSG #sig :no id of my own");
        let echo = alice.rx(|l| l.contains("no id of my own"), "echo");
        let msgid = C::msgid_of(&echo).expect("server mints an id when the client doesn't");
        assert!(
            freeq_server::msgid::timestamp_ms(&msgid).is_some(),
            "server-minted id is a ULID: {msgid}"
        );
    })
    .await;
}

#[tokio::test]
async fn an_id_already_on_file_is_refused_and_the_message_is_not_delivered() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, k);
        alice.join("#sig");

        let minted = freeq_server::msgid::generate();
        alice.send_with_id(&minted, "#sig", "first use");
        alice.rx(|l| l.contains("first use"), "first echo");

        // Reusing it must not overwrite, shadow, or silently re-id anything.
        alice.send_with_id(&minted, "#sig", "second use");
        let fail = alice
            .maybe(|l| l.contains("FAIL") && l.contains("EVENTID_IN_USE"), 2000)
            .expect("a reused event id is refused");
        assert!(fail.contains("PRIVMSG"), "FAIL names the command: {fail}");
        assert!(
            alice.maybe(|l| l.contains("second use"), 500).is_none(),
            "the refused message must not be delivered"
        );
    })
    .await;
}

#[tokio::test]
async fn a_malformed_id_is_refused_as_malformed() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, k);
        alice.join("#sig");
        for bad in ["nope", "01kyvt5z8q0000000000000000", "0000"] {
            alice.send_with_id(bad, "#sig", "malformed");
            let fail = alice
                .maybe(
                    |l| l.contains("FAIL") && l.contains("INVALID_EVENTID"),
                    2000,
                )
                .unwrap_or_else(|| panic!("{bad} should be refused as malformed"));
            assert!(fail.contains("PRIVMSG"));
            assert!(alice.maybe(|l| l.contains("malformed"), 300).is_none());
        }
    })
    .await;
}

#[tokio::test]
async fn a_clock_far_from_the_servers_is_skew_not_forgery() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, k);
        alice.join("#sig");

        // A minute out either way is fine: federated clocks drift, and we have
        // the scars from pretending otherwise.
        for offset in [-60_000i64, 60_000] {
            let id = id_at_offset(offset);
            alice.send_with_id(&id, "#sig", &format!("drift {offset}"));
            let echo = alice.rx(|l| l.contains(&format!("drift {offset}")), "echo");
            assert_eq!(C::msgid_of(&echo).as_deref(), Some(id.as_str()));
        }

        // An hour out is not.
        let far = id_at_offset(3_600_000);
        alice.send_with_id(&far, "#sig", "from the future");
        let fail = alice
            .maybe(
                |l| l.contains("FAIL") && l.contains("EVENTID_CLOCK_SKEW"),
                2000,
            )
            .expect("an id an hour out is refused for skew");
        assert!(fail.contains("PRIVMSG"));
        assert!(
            alice
                .maybe(|l| l.contains("from the future"), 300)
                .is_none()
        );
    })
    .await;
}

#[tokio::test]
async fn a_guest_may_not_mint_ids() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, move |addr| {
        let mut guest = C::guest(addr, "nobody");
        guest.join("#sig");
        let minted = freeq_server::msgid::generate();
        guest.send_with_id(&minted, "#sig", "unsigned and unowned");
        let fail = guest
            .maybe(
                |l| l.contains("FAIL") && l.contains("EVENTID_NOT_AUTHENTICATED"),
                2000,
            )
            .expect("a guest has no identity to mint under");
        assert!(fail.contains("PRIVMSG"));
        // …and a guest sending no id is unaffected.
        guest.tx("PRIVMSG #sig :plain guest line");
        let echo = guest.rx(|l| l.contains("plain guest line"), "echo");
        assert!(C::msgid_of(&echo).is_some());
    })
    .await;
}

#[tokio::test]
async fn a_dm_is_filed_under_the_senders_own_id() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);

        let minted = freeq_server::msgid::generate();
        alice.send_with_id(&minted, "bob", "for your eyes only");

        let delivered = bob.rx(|l| l.contains("for your eyes only"), "DM");
        assert_eq!(
            C::msgid_of(&delivered).as_deref(),
            Some(minted.as_str()),
            "a DM crosses under the sender's id too: {delivered}"
        );
    })
    .await;
}
