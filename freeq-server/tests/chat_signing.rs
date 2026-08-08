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

use ed25519_dalek::SigningKey;
use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::chatsig::{ChatDoc, EVENT_ID_TAG, channel_venue};
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

    /// Register a message-signing key for this session, as every signing
    /// client does once after auth.
    fn msgsig(&mut self, key: &SigningKey) {
        use base64::Engine;
        let pubkey =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        self.tx(&format!("MSGSIG {pubkey}"));
        self.rx(|l| l.contains("MSGSIG"), "MSGSIG ack");
    }

    fn send_signed(&mut self, id: &str, target: &str, text: &str, sig_tag: &str) {
        self.tx(&format!(
            "@{EVENT_ID_TAG}={id};+freeq.at/sig={sig_tag} PRIVMSG {target} :{text}"
        ));
    }

    fn sig_of(line: &str) -> Option<String> {
        line.strip_prefix('@')
            .and_then(|s| s.split_once(' ').map(|(t, _)| t))
            .and_then(|tags| {
                tags.split(';')
                    .find_map(|t| t.strip_prefix("+freeq.at/sig=").map(|v| v.to_string()))
            })
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

// ── The signature itself ────────────────────────────────────────────

#[tokio::test]
async fn a_signature_the_sender_made_travels_exactly_as_the_sender_made_it() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#sig");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#sig");

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let id = freeq_server::msgid::generate();
        let body = "signed on my own device";
        let sig = ChatDoc::message(DID_ALICE, &id, &channel_venue("#sig"), body).sign(&signing);
        alice.send_signed(&id, "#sig", body, &sig);

        let seen = bob.rx(|l| l.contains(body), "delivery");
        assert_eq!(
            C::sig_of(&seen).as_deref(),
            Some(sig.as_str()),
            "the sender's signature must be relayed byte-for-byte, not re-made: {seen}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_signature_that_fails_is_not_quietly_replaced_with_the_servers() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#sig");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#sig");

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        // A signature over a *different* body than the one sent — what a
        // tampering relay, or a client with the wrong canonical, produces.
        let id = freeq_server::msgid::generate();
        let sig = ChatDoc::message(DID_ALICE, &id, &channel_venue("#sig"), "what I signed")
            .sign(&signing);
        alice.send_signed(&id, "#sig", "what I sent", &sig);

        let seen = bob.rx(|l| l.contains("what I sent"), "delivery");
        assert_eq!(
            C::sig_of(&seen),
            None,
            "a signature that didn't check out must not be laundered into a \
             server signature: {seen}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_signed_venue_is_the_folded_channel_not_the_case_the_sender_typed() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#sig");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#sig");

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        // Sent with the case the user typed, signed with the folded venue:
        // verifies, because that is the rule.
        let id = freeq_server::msgid::generate();
        let folded = ChatDoc::message(DID_ALICE, &id, "#sig", "typed in mixed case").sign(&signing);
        alice.send_signed(&id, "#SIG", "typed in mixed case", &folded);
        let seen = bob.rx(|l| l.contains("typed in mixed case"), "delivery");
        assert_eq!(C::sig_of(&seen).as_deref(), Some(folded.as_str()));

        // Signing the unfolded name does not, so the rule is unambiguous
        // rather than "whatever the sender happened to type".
        let id2 = freeq_server::msgid::generate();
        let unfolded =
            ChatDoc::message(DID_ALICE, &id2, "#SIG", "signed the wrong venue").sign(&signing);
        alice.send_signed(&id2, "#SIG", "signed the wrong venue", &unfolded);
        let seen2 = bob.rx(|l| l.contains("signed the wrong venue"), "delivery");
        assert_eq!(
            C::sig_of(&seen2),
            None,
            "a venue that isn't the folded one is not the venue: {seen2}"
        );
    })
    .await;
}

#[tokio::test]
async fn an_unsigned_message_from_an_identity_is_signed_by_the_server_instead() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#sig");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#sig");

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);
        alice.tx("PRIVMSG #sig :I didn't sign this");

        let seen = bob.rx(|l| l.contains("I didn't sign this"), "delivery");
        let sig = C::sig_of(&seen).expect("the server signs on an identity's behalf");
        let (kid, _) = freeq_sdk::sigtag::parse(&sig).expect("sig tag is alg:kid:sig");
        assert_ne!(
            kid,
            freeq_sdk::sigtag::derive_kid(&signing.verifying_key()),
            "a server signature must not claim to be the sender's key: {seen}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_guests_message_is_not_signed_by_anyone() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, move |addr| {
        let mut watcher = C::guest(addr, "watcher");
        watcher.join("#sig");
        let mut guest = C::guest(addr, "nobody");
        guest.join("#sig");
        // Even a guest that *invents* a signature tag must not have it relayed:
        // an unverifiable signature on the wire is a lock badge for free.
        guest.tx(
            "@+freeq.at/sig=ed25519:AAAAAAAAAAAAAAAAAAAAAA:AAAA PRIVMSG #sig :no identity, no signature",
        );
        let seen = watcher.rx(|l| l.contains("no identity, no signature"), "delivery");
        assert_eq!(
            C::sig_of(&seen),
            None,
            "there is nothing to vouch for: {seen}"
        );
    })
    .await;
}

/// The full loop, with no test-only shortcuts in the middle: the SDK client
/// signs a message, the server verifies it and relays the sender's own
/// signature, and a third party rebuilds the document and checks it against
/// the public key the server publishes for that (DID, kid).
///
/// This is the property the whole canonical exists for — verification by
/// someone who was not there when the message was sent.
#[tokio::test]
async fn a_third_party_can_verify_an_sdk_clients_signature_from_the_wire_alone() {
    use freeq_sdk::client::{self, ConnectConfig};
    use freeq_sdk::event::Event;
    use std::sync::Arc;

    let k = key();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-sig-web".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    let (irc_addr, web_addr, _h) =
        freeq_server::server::Server::with_resolver(config, resolver_with(vec![(DID_ALICE, &k)]))
            .start_with_web()
            .await
            .unwrap();

    // A watcher on raw IRC sees exactly what crosses the wire. A guest will
    // do — the point is what a bystander receives, not who they are.
    let watcher_addr = irc_addr;
    let watcher = tokio::task::spawn_blocking(move || {
        let mut c = C::guest(watcher_addr, "watcher");
        c.join("#sig");
        c
    })
    .await
    .unwrap();

    // Alice sends through the SDK, which signs on her device.
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(DID_ALICE.to_string(), k));
    let (handle, mut events) = client::connect(
        ConnectConfig {
            server_addr: irc_addr.to_string(),
            nick: "alice".to_string(),
            user: "alice".to_string(),
            realname: "Alice".to_string(),
            ..Default::default()
        },
        Some(signer),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(e) = events.recv().await {
            if matches!(e, Event::Registered { .. }) {
                break;
            }
        }
    })
    .await
    .unwrap();
    handle.join("#sig").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    handle
        .privmsg("#sig", "verifiable by anyone")
        .await
        .unwrap();

    let mut watcher = watcher;
    let seen = tokio::task::spawn_blocking(move || {
        let line = watcher.rx(|l| l.contains("verifiable by anyone"), "delivery");
        (line, watcher)
    })
    .await
    .unwrap()
    .0;

    let sig_tag = C::sig_of(&seen).expect("the message is signed");
    let msgid = C::msgid_of(&seen).expect("the message has an id");
    let (kid, _) = freeq_sdk::sigtag::parse(&sig_tag).expect("sig tag is alg:kid:sig");

    // The key the signature names, fetched from the durable store the same way
    // any third party would.
    let resp = reqwest::get(format!("http://{web_addr}/api/v1/signing-keys/{DID_ALICE}"))
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    let key_json: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|_| panic!("key lookup for kid {kid} was {status}: {body}"));
    let pubkey = {
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key_json["public_key"].as_str().unwrap())
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&raw.try_into().unwrap()).unwrap()
    };

    // Rebuilt from the wire alone: sender, venue, body, id.
    ChatDoc::message(
        DID_ALICE,
        &msgid,
        &channel_venue("#sig"),
        "verifiable by anyone",
    )
    .verify(&sig_tag, &pubkey)
    .expect("a stranger can verify this message");

    // And the server's own verify endpoint agrees it was the device, not itself.
    let verdict: serde_json::Value =
        reqwest::get(format!("http://{web_addr}/api/v1/verify/{msgid}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(verdict["verification"]["verdict"], "valid");
    assert_eq!(
        verdict["verification"]["verified_by"], "client-session-key",
        "signed on the sender's device, not by the server: {verdict}"
    );
}

// ── Signed mutations at client ingress ──────────────────────────────
//
// A delete or a reaction is durable state asserted under a user's name. The
// server checks the sender's signature against the event as it arrived,
// refuses one that fails, and relays a verified one verbatim so every
// receiver — local or federated — can attribute the act for itself.

/// The tag block a signed mutation puts on the wire.
fn signed_mutation_tags(
    kind: freeq_sdk::chatsig::Mutation,
    subject_tag: &str,
    subject: &str,
    emoji: Option<&str>,
    channel: &str,
    event_id: &str,
    signing: &SigningKey,
) -> String {
    signed_mutation_tags_in(
        kind,
        subject_tag,
        subject,
        emoji,
        &channel_venue(channel),
        event_id,
        signing,
    )
}

/// [`signed_mutation_tags`] for a venue the caller names, because a DM's venue
/// is the sorted DID pair — a string no wire target spells.
fn signed_mutation_tags_in(
    kind: freeq_sdk::chatsig::Mutation,
    subject_tag: &str,
    subject: &str,
    emoji: Option<&str>,
    venue: &str,
    event_id: &str,
    signing: &SigningKey,
) -> String {
    let mut doc = ChatDoc::mutation(kind, DID_ALICE, event_id, venue, subject);
    if let Some(emoji) = emoji {
        doc = doc.with_emoji(emoji);
    }
    let sig = doc.sign(signing);
    let mut tags = match emoji {
        Some(e) => format!("{subject_tag}={e};+reply={subject}"),
        None => format!("{subject_tag}={subject}"),
    };
    tags.push_str(&format!(";{EVENT_ID_TAG}={event_id};+freeq.at/sig={sig}"));
    tags
}

/// Alice, Bob, a channel they share, and a message of Alice's to act on.
/// Returns (bob, alice, alice's session signing key, the message's msgid).
fn two_in_a_channel(
    addr: SocketAddr,
    ka: PrivateKey,
    kb: PrivateKey,
    did_bob: &str,
    channel: &str,
) -> (C, C, SigningKey, String) {
    let mut bob = C::authenticated(addr, "bob", did_bob, kb);
    bob.join(channel);
    let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
    alice.join(channel);
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    alice.msgsig(&signing);

    let msgid = freeq_server::msgid::generate();
    alice.send_with_id(&msgid, channel, "act on me");
    bob.rx(|l| l.contains("act on me"), "the message to act on");
    (bob, alice, signing, msgid)
}

#[tokio::test]
async fn a_signed_delete_relays_the_senders_own_signature() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#del");

        let event_id = freeq_server::msgid::generate();
        let tags = signed_mutation_tags(
            Mutation::Delete,
            "+draft/delete",
            &msgid,
            None,
            "#del",
            &event_id,
            &signing,
        );
        alice.tx(&format!("@{tags} TAGMSG #del"));

        let seen = bob.rx(|l| l.contains("+draft/delete"), "the delete");
        let sig = tags
            .split(';')
            .find_map(|t| t.strip_prefix("+freeq.at/sig="))
            .unwrap();
        assert_eq!(
            C::sig_of(&seen).as_deref(),
            Some(sig),
            "the sender's signature must be relayed byte-for-byte: {seen}"
        );
        assert!(
            seen.contains(&format!("{EVENT_ID_TAG}={event_id}")),
            "and the id it covers must travel with it, or nobody can rebuild \
             the document: {seen}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_signed_reaction_and_its_removal_relay_their_signatures() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#react");

        for (kind, tag) in [
            (Mutation::React, "+react"),
            (Mutation::Unreact, "+freeq.at/unreact"),
        ] {
            let event_id = freeq_server::msgid::generate();
            let tags = signed_mutation_tags(
                kind,
                tag,
                &msgid,
                Some("👍"),
                "#react",
                &event_id,
                &signing,
            );
            alice.tx(&format!("@{tags} TAGMSG #react"));

            let seen = bob.rx(|l| l.contains(tag), "the reaction");
            let sig = tags
                .split(';')
                .find_map(|t| t.strip_prefix("+freeq.at/sig="))
                .unwrap();
            assert_eq!(
                C::sig_of(&seen).as_deref(),
                Some(sig),
                "{kind:?} must relay the sender's own signature: {seen}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_mutation_signature_that_fails_is_refused_and_never_relayed() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#forged");

        // Signed over a different subject than the one sent — what a relay
        // swapping the victim's message produces.
        let event_id = freeq_server::msgid::generate();
        let sig = ChatDoc::mutation(
            Mutation::Delete,
            DID_ALICE,
            &event_id,
            &channel_venue("#forged"),
            "01SOMEONEELSESMESSAGE00000",
        )
        .sign(&signing);
        alice.tx(&format!(
            "@+draft/delete={msgid};{EVENT_ID_TAG}={event_id};+freeq.at/sig={sig} TAGMSG #forged"
        ));

        alice.rx(|l| l.contains("SIGNATURE_INVALID"), "FAIL to the sender");
        assert!(
            bob.maybe(|l| l.contains("+draft/delete"), 500).is_none(),
            "an event whose signature failed must not reach anyone"
        );
        // And the message it named is still there.
        alice.tx("CHATHISTORY LATEST #forged * 10");
        assert!(
            alice.maybe(|l| l.contains("act on me"), 1000).is_some(),
            "a refused delete must not have deleted anything"
        );
    })
    .await;
}

#[tokio::test]
async fn a_guest_cannot_attach_a_mutation_signature() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, move |addr| {
        let mut watcher = C::guest(addr, "watcher");
        watcher.join("#guestreact");
        let mut guest = C::guest(addr, "nobody");
        guest.join("#guestreact");

        guest.tx(
            "@+react=👍;+reply=01SOMEMESSAGE000000000000;\
             +freeq.at/sig=ed25519:AAAAAAAAAAAAAAAAAAAAAA:AAAA TAGMSG #guestreact",
        );
        let seen = watcher.rx(|l| l.contains("+react"), "the reaction");
        assert_eq!(
            C::sig_of(&seen),
            None,
            "there is no identity here to vouch for: {seen}"
        );
    })
    .await;
}

/// An unsigned mutation from an identity is vouched for by the server, the
/// same way an unsigned message is. The note means the same thing in both
/// cases — *this server saw this authenticated account do this* — and a
/// reader tells a vouch from a device's proof by the key each names.
#[tokio::test]
async fn an_unsigned_delete_is_vouched_for_by_the_server() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#plain");

        alice.tx(&format!("@+draft/delete={msgid} TAGMSG #plain"));
        let seen = bob.rx(|l| l.contains("+draft/delete"), "the delete");
        let sig = C::sig_of(&seen).expect("the server vouches for it");
        let (kid, _) = freeq_sdk::sigtag::parse(&sig).expect("sig tag is alg:kid:sig");
        assert_ne!(
            kid,
            freeq_sdk::sigtag::derive_kid(&signing.verifying_key()),
            "a server vouch must not claim to be the sender's key: {seen}"
        );
        assert!(
            seen.contains(EVENT_ID_TAG),
            "a signature covers an id, so the act gets one: {seen}"
        );
        assert!(seen.contains(&msgid), "the delete still names its subject: {seen}");
    })
    .await;
}

/// A guest has no identity to bind, so there is nothing to vouch for and
/// nothing is attached.
#[tokio::test]
async fn a_guests_delete_is_vouched_for_by_nobody() {
    let (addr, _h) = start(DidResolver::static_map(HashMap::new())).await;
    run(addr, move |addr| {
        let mut watcher = C::guest(addr, "watcher");
        watcher.join("#guestdel");
        let mut guest = C::guest(addr, "nobody");
        guest.join("#guestdel");

        guest.tx("PRIVMSG #guestdel :delete me");
        let posted = watcher.rx(|l| l.contains("delete me"), "the message");
        let msgid = C::msgid_of(&posted).expect("the server minted an id for it");

        guest.tx(&format!("@+draft/delete={msgid} TAGMSG #guestdel"));
        let seen = watcher.rx(|l| l.contains("+draft/delete"), "the delete");
        assert_eq!(
            C::sig_of(&seen),
            None,
            "there is no identity here to vouch for: {seen}"
        );
    })
    .await;
}

/// A coordination event's signature covers a different document, verified by
/// a different profile. The mutation path must leave it alone rather than
/// judge it by a canonical it was never signed under.
#[tokio::test]
async fn a_coordination_events_signature_is_left_alone() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#coord");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#coord");

        alice.tx(
            "@+freeq.at/event=task_request;+freeq.at/task-id=01TASK00000000000000000000;\
             +freeq.at/sig=ed25519:someotherprofile00000A:c2ln TAGMSG #coord",
        );
        let seen = bob.rx(|l| l.contains("+freeq.at/event"), "the coordination event");
        assert_eq!(
            C::sig_of(&seen).as_deref(),
            Some("ed25519:someotherprofile00000A:c2ln"),
            "another profile's signature is not the mutation path's to strip: {seen}"
        );
    })
    .await;
}

// ── Replayed history keeps its signatures ───────────────────────────
//
// A signature is only useful for as long as someone can still check it. Live
// delivery is the easy half; the half that matters is a client that wasn't
// there — joining later, or reloading — asking for history and being able to
// reach the same verdict from the replayed lines alone.

/// A reader who was not present when the message was sent: connects after the
/// fact, joins, and asks for history. Its only copy of the message is the
/// replay, so nothing here can be satisfied by a live frame.
fn history_of(addr: SocketAddr, channel: &str, needle: &str) -> Option<String> {
    let mut reader = C::guest(addr, "reader");
    reader.join(channel);
    reader.tx(&format!("CHATHISTORY LATEST {channel} * 20"));
    reader.maybe(|l| l.contains(needle), 2000)
}

#[tokio::test]
async fn replayed_history_carries_a_signature_a_reader_can_check() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#replay");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#replay");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let id = freeq_server::msgid::generate();
        let body = "still checkable tomorrow";
        let sig = ChatDoc::message(DID_ALICE, &id, &channel_venue("#replay"), body).sign(&signing);
        alice.send_signed(&id, "#replay", body, &sig);
        bob.rx(|l| l.contains(body), "live delivery");

        let replayed = history_of(addr, "#replay", body).expect("history replays the message");
        let replayed_sig = C::sig_of(&replayed).unwrap_or_else(|| {
            panic!("a replayed signed message must still carry its signature: {replayed}")
        });
        let replayed_id = C::msgid_of(&replayed).expect("and the id it covers");

        // Rebuilt from the replayed line alone.
        ChatDoc::message(DID_ALICE, &replayed_id, &channel_venue("#replay"), body)
            .verify(&replayed_sig, &signing.verifying_key())
            .expect("the reader reaches the same verdict from history alone");
    })
    .await;
}

#[tokio::test]
async fn replayed_history_carries_the_servers_signature_too() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#serversigned");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#serversigned");

        // No client signature: the server signs on her behalf, and that
        // attestation is what history has to keep.
        alice.tx("PRIVMSG #serversigned :the server vouched for this");
        let live = bob.rx(|l| l.contains("the server vouched"), "live delivery");
        let live_sig = C::sig_of(&live).expect("the server signs for an identity");

        let replayed = history_of(addr, "#serversigned", "the server vouched")
            .expect("history replays the message");
        assert_eq!(
            C::sig_of(&replayed).as_deref(),
            Some(live_sig.as_str()),
            "history must carry the same attestation the live frame did: {replayed}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_signature_that_failed_is_not_replayed_by_history() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#notlaundered");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#notlaundered");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let id = freeq_server::msgid::generate();
        let sig = ChatDoc::message(DID_ALICE, &id, &channel_venue("#notlaundered"), "what I signed")
            .sign(&signing);
        alice.send_signed(&id, "#notlaundered", "what I sent", &sig);
        let live = bob.rx(|l| l.contains("what I sent"), "live delivery");
        assert_eq!(C::sig_of(&live), None, "live delivery strips it: {live}");

        let replayed =
            history_of(addr, "#notlaundered", "what I sent").expect("history replays the message");
        assert_eq!(
            C::sig_of(&replayed),
            None,
            "and history must not resurrect a signature the server refused to \
             stand behind: {replayed}"
        );
    })
    .await;
}

#[tokio::test]
async fn replayed_history_names_one_id_not_two() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#oneid");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#oneid");

        let id = freeq_server::msgid::generate();
        alice.send_with_id(&id, "#oneid", "one identity");
        bob.rx(|l| l.contains("one identity"), "live delivery");

        let replayed = history_of(addr, "#oneid", "one identity").expect("history replays it");
        assert_eq!(C::msgid_of(&replayed).as_deref(), Some(id.as_str()));
        assert!(
            !replayed.contains(EVENT_ID_TAG),
            "the adopted id *is* the msgid; two tags that must agree forever is \
             the ambiguity signing exists to remove: {replayed}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_replayed_edit_carries_the_signature_over_its_own_revision() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#editreplay");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#editreplay");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let root = freeq_server::msgid::generate();
        alice.send_with_id(&root, "#editreplay", "first draft");
        bob.rx(|l| l.contains("first draft"), "the original");

        // An edit is its own event: its own id, and a document that names the
        // message it revises.
        let edit_id = freeq_server::msgid::generate();
        let revised = "second draft";
        let sig = ChatDoc::message(
            DID_ALICE,
            &edit_id,
            &channel_venue("#editreplay"),
            revised,
        )
        .with_edit(&root)
        .sign(&signing);
        alice.tx(&format!(
            "@{EVENT_ID_TAG}={edit_id};+draft/edit={root};+freeq.at/sig={sig} \
             PRIVMSG #editreplay :{revised}"
        ));
        let live = bob.rx(|l| l.contains(revised), "the edit");
        assert_eq!(
            C::sig_of(&live).as_deref(),
            Some(sig.as_str()),
            "the sender's signature relays as made: {live}"
        );

        let replayed =
            history_of(addr, "#editreplay", revised).expect("history replays the revision");
        let replayed_sig = C::sig_of(&replayed)
            .unwrap_or_else(|| panic!("a replayed edit must keep its signature: {replayed}"));
        let replayed_id = C::msgid_of(&replayed).expect("and its own id");
        assert!(
            !replayed.contains(EVENT_ID_TAG),
            "one id, not two — the minted id *is* the msgid: {replayed}"
        );
        ChatDoc::message(
            DID_ALICE,
            &replayed_id,
            &channel_venue("#editreplay"),
            revised,
        )
        .with_edit(&root)
        .verify(&replayed_sig, &signing.verifying_key())
        .expect("a reader rebuilds and checks the revision from history alone");
    })
    .await;
}

// ── The record a mutation leaves ────────────────────────────────────
//
// A delete used to record no actor and an unreaction used to delete the
// reaction row outright, so the fact that anyone had ever reacted — let alone
// that they took it back — survived nowhere. The log is where it survives now.

/// Read the event log of a running test server, the way an auditor would.
fn events_in(db_path: &str, venue: &str) -> Vec<(String, String, Option<String>, Option<String>)> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    let mut stmt = conn
        .prepare(
            "SELECT kind, event_id, actor_did, signature FROM events
             WHERE venue = ?1 ORDER BY timestamp ASC, event_id ASC",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![venue], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}

/// A server whose database file the test can read back.
async fn start_with_db(
    resolver: DidResolver,
) -> (SocketAddr, String, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-sig-log".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.clone()),
        ..Default::default()
    };
    let (addr, h) = freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap();
    (addr, db_path, h)
}

#[tokio::test]
async fn a_delete_records_the_actor_who_asked_for_it() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, db_path, _h) =
        start_with_db(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    let db_for_test = db_path.clone();
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#actor");

        let event_id = freeq_server::msgid::generate();
        let tags = signed_mutation_tags(
            Mutation::Delete,
            "+draft/delete",
            &msgid,
            None,
            "#actor",
            &event_id,
            &signing,
        );
        alice.tx(&format!("@{tags} TAGMSG #actor"));
        bob.rx(|l| l.contains("+draft/delete"), "the delete");
    })
    .await;

    // Give the write a moment to land, then read the log as an auditor would.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = events_in(&db_for_test, "#actor");
    let delete = events
        .iter()
        .find(|(kind, ..)| kind == "delete")
        .unwrap_or_else(|| panic!("the delete is on file: {events:?}"));
    assert_eq!(
        delete.2.as_deref(),
        Some(DID_ALICE),
        "the row records who asked, which no message row ever did: {delete:?}"
    );
    assert!(
        delete.3.is_some(),
        "with the signature that proves the request came from them: {delete:?}"
    );
}

#[tokio::test]
async fn an_unreaction_leaves_the_event_that_removed_the_reaction() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, db_path, _h) =
        start_with_db(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    let db_for_test = db_path.clone();
    run(addr, move |addr| {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(addr, ka, kb, did_bob, "#undone");

        for (kind, tag) in [
            (Mutation::React, "+react"),
            (Mutation::Unreact, "+freeq.at/unreact"),
        ] {
            let event_id = freeq_server::msgid::generate();
            let tags = signed_mutation_tags(
                kind,
                tag,
                &msgid,
                Some("👍"),
                "#undone",
                &event_id,
                &signing,
            );
            alice.tx(&format!("@{tags} TAGMSG #undone"));
            bob.rx(|l| l.contains(tag), "the reaction");
        }
    })
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = events_in(&db_for_test, "#undone");
    let kinds: Vec<&str> = events.iter().map(|(k, ..)| k.as_str()).collect();
    assert!(
        kinds.contains(&"react") && kinds.contains(&"unreact"),
        "both halves are on file — the reaction row is gone, the record is not: {events:?}"
    );
    for (kind, _, actor, signature) in &events {
        if kind == "react" || kind == "unreact" {
            assert_eq!(actor.as_deref(), Some(DID_ALICE), "{kind} names its actor");
            assert!(signature.is_some(), "{kind} keeps the signature that made it");
        }
    }

    // And the derived tally really is empty — the log is not a duplicate of
    // live state, it is the record of how live state got here.
    let conn = rusqlite::Connection::open(&db_for_test).unwrap();
    let live: i64 = conn
        .query_row("SELECT COUNT(*) FROM reactions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(live, 0, "the reaction was taken back");
}

/// The log records events, not signatures. A guest has no identity to bind and
/// nothing to sign with — and their acts still happened, so they are still on
/// file: a server-minted id, no signature, no canonical, and honest about all
/// three.
#[tokio::test]
async fn a_guests_mutations_are_on_file_unsigned() {
    let (addr, db_path, _h) = start_with_db(DidResolver::static_map(HashMap::new())).await;
    let db_for_test = db_path.clone();
    run(addr, move |addr| {
        let mut watcher = C::guest(addr, "watcher");
        watcher.join("#guestlog");
        let mut guest = C::guest(addr, "nobody");
        guest.join("#guestlog");

        guest.tx("PRIVMSG #guestlog :something to act on");
        let posted = watcher.rx(|l| l.contains("something to act on"), "the message");
        let msgid = C::msgid_of(&posted).expect("the server minted an id");

        guest.tx(&format!("@+react=👍;+reply={msgid} TAGMSG #guestlog"));
        watcher.rx(|l| l.contains("+react"), "the reaction");

        guest.tx(&format!("@+draft/delete={msgid} TAGMSG #guestlog"));
        watcher.rx(|l| l.contains("+draft/delete"), "the delete");
    })
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let rows = full_events_in(&db_for_test, "#guestlog");
    for kind in ["react", "delete"] {
        let row = rows
            .iter()
            .find(|r| r.kind == kind)
            .unwrap_or_else(|| panic!("a guest's {kind} is on file too: {rows:?}"));
        assert_eq!(row.actor_did, None, "a guest has no identity to bind");
        assert_eq!(row.signature, None, "and nothing to sign with");
        assert_eq!(row.canonical, "", "so there are no signed bytes to store");
        assert_eq!(row.sig_state, "unsigned", "stated, not implied");
        assert!(
            !row.event_id.is_empty(),
            "the act still needs an identity, and the server mints one"
        );
    }
}

#[derive(Debug)]
struct EventRow {
    kind: String,
    event_id: String,
    actor_did: Option<String>,
    signature: Option<String>,
    canonical: String,
    sig_state: String,
}

fn full_events_in(db_path: &str, venue: &str) -> Vec<EventRow> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    let mut stmt = conn
        .prepare(
            "SELECT kind, event_id, actor_did, signature, canonical, sig_state
             FROM events WHERE venue = ?1 ORDER BY timestamp ASC, event_id ASC",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![venue], |r| {
        Ok(EventRow {
            kind: r.get(0)?,
            event_id: r.get(1)?,
            actor_did: r.get(2)?,
            signature: r.get(3)?,
            canonical: r.get(4)?,
            sig_state: r.get(5)?,
        })
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}

/// The verify endpoint answers for a mutation's own event id.
///
/// A reaction files a signed event; a bystander with only the event id can
/// ask the server what act it was, who performed it, against what subject,
/// and whether the signature verifies as the actor's own device — without
/// database access. The log stores the exact signed bytes, so the answer is
/// read, not rebuilt, and stays hash-only (facts, never a body).
#[tokio::test]
async fn the_verify_endpoint_answers_for_a_mutation_event() {
    use freeq_sdk::chatsig::Mutation;
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-sig-ev".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    let (irc_addr, web_addr, _h) = freeq_server::server::Server::with_resolver(
        config,
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
    )
    .start_with_web()
    .await
    .unwrap();

    let (event_id, msgid) = tokio::task::spawn_blocking(move || {
        let (mut bob, mut alice, signing, msgid) =
            two_in_a_channel(irc_addr, ka, kb, did_bob, "#evverify");
        let event_id = freeq_server::msgid::generate();
        let tags = signed_mutation_tags(
            Mutation::React,
            "+react",
            &msgid,
            Some("👍"),
            "#evverify",
            &event_id,
            &signing,
        );
        alice.tx(&format!("@{tags} TAGMSG #evverify"));
        bob.rx(|l| l.contains("+react"), "the reaction");
        (event_id, msgid)
    })
    .await
    .unwrap();

    // The broadcast races the row by a hair; give the write a beat.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let v: serde_json::Value =
        reqwest::get(format!("http://{web_addr}/api/v1/verify/{event_id}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(v["kind"], "react", "the filed act, by name: {v}");
    assert_eq!(v["actor_did"], DID_ALICE);
    assert_eq!(v["subject"], msgid.as_str());
    assert_eq!(v["emoji"], "👍");
    assert_eq!(
        v["channel"], "#evverify",
        "a channel mutation files under the folded channel, unchanged: {v}"
    );
    assert_eq!(v["verification"]["verdict"], "valid");
    assert_eq!(
        v["verification"]["verified_by"], "client-session-key",
        "signed on the actor's device, not vouched by the server: {v}"
    );

    // An id nobody minted still answers 404 — the fallthrough reads the
    // log, it doesn't invent.
    let missing = reqwest::get(format!(
        "http://{web_addr}/api/v1/verify/01H000000000000000NOPE0000"
    ))
    .await
    .unwrap();
    assert_eq!(missing.status(), 404);
}

// ── The venue a DM mutation is filed under ──────────────────────────
//
// A DM's venue is the sorted DID pair, never the wire target: that target is a
// nick or a `did:` depending on who addressed whom, so it is not a string a
// verifier can reproduce. Filing the event under the wire target stores a
// canonical that is not the bytes the stored signature covers — and the verify
// endpoint then calls an honest act forged, which is the one answer the
// three-state verdict exists to prevent.

#[tokio::test]
async fn a_signed_dm_mutation_is_filed_under_the_venue_its_signature_covers() {
    use freeq_sdk::chatsig::{Mutation, dm_venue};
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-sig-dm".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    let (irc_addr, web_addr, _h) = freeq_server::server::Server::with_resolver(
        config,
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
    )
    .start_with_web()
    .await
    .unwrap();

    let venue = dm_venue(DID_ALICE, did_bob);
    let signed_venue = venue.clone();
    let filed = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let msgid = freeq_server::msgid::generate();
        alice.send_with_id(&msgid, "bob", "act on me");
        bob.rx(|l| l.contains("act on me"), "the DM to act on");

        // Addressed to the nick, signed over the pair. The delete goes last so
        // the react and its removal act on a message that is still there.
        let mut filed = Vec::new();
        for (kind, name, tag, emoji) in [
            (Mutation::React, "react", "+react", Some("👍")),
            (Mutation::Unreact, "unreact", "+freeq.at/unreact", Some("👍")),
            (Mutation::Delete, "delete", "+draft/delete", None),
        ] {
            let event_id = freeq_server::msgid::generate();
            let tags = signed_mutation_tags_in(
                kind,
                tag,
                &msgid,
                emoji,
                &signed_venue,
                &event_id,
                &signing,
            );
            alice.tx(&format!("@{tags} TAGMSG bob"));
            bob.rx(|l| l.contains(tag), name);
            filed.push((name, event_id));
        }
        filed
    })
    .await
    .unwrap();

    // The broadcast races the row by a hair; give the writes a beat.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for (name, event_id) in filed {
        let v: serde_json::Value =
            reqwest::get(format!("http://{web_addr}/api/v1/verify/{event_id}"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(v["kind"], name, "the filed act, by name: {v}");
        assert_eq!(v["actor_did"], DID_ALICE);
        assert_eq!(
            v["channel"], venue,
            "a {name} files under the venue its signature covers, not the nick \
             it was addressed to: {v}"
        );
        assert_eq!(
            v["verification"]["verdict"], "valid",
            "an honest {name} must not read as forged: {v}"
        );
        assert_eq!(
            v["verification"]["verified_by"], "client-session-key",
            "signed on the actor's device, not vouched by the server: {v}"
        );
    }
}

// ── Coordination events ─────────────────────────────────────────────
//
// A coordination event is the artifact the server *stores* and serves back:
// task cards, the audit timeline. An audit row nobody can check is the defect
// this signing model exists to close, so the event signs standalone — over its
// own document, under its own id — and the server files it under the id the
// signature covers.

/// A server with a database and a web API, for the tests that read a stored
/// row back through the verify endpoint.
async fn start_web(
    resolver: DidResolver,
    name: &str,
) -> (SocketAddr, SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp); // outlives the server
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: name.to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start_with_web()
        .await
        .unwrap()
}

/// The tags of a signed coordination event, as an emitter puts them on the
/// wire: the event type, the payload as transmitted, an optional reference,
/// and the id the signature covers.
fn signed_coordination_tags(
    channel: &str,
    event_id: &str,
    event_type: &str,
    payload: &str,
    ref_id: Option<&str>,
    signing: &SigningKey,
) -> String {
    let venue = channel_venue(channel);
    let mut doc =
        ChatDoc::coordination(DID_ALICE, event_id, &venue, event_type).with_payload(payload);
    if let Some(ref_id) = ref_id {
        doc = doc.with_ref(ref_id);
    }
    let sig = doc.sign(signing);
    let mut tags =
        format!("+freeq.at/event={event_type};+freeq.at/payload={payload};{EVENT_ID_TAG}={event_id}");
    if let Some(ref_id) = ref_id {
        tags.push_str(&format!(";+freeq.at/ref={ref_id}"));
    }
    tags.push_str(&format!(";+freeq.at/sig={sig}"));
    tags
}

#[tokio::test]
async fn a_signed_coordination_event_is_filed_under_the_id_it_signed() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (irc_addr, web_addr, _h) = start_web(
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
        "test-coord",
    )
    .await;

    let (task_id, done_id) = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        bob.join("#coordsig");
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        alice.join("#coordsig");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let task_id = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@{} TAGMSG #coordsig",
            signed_coordination_tags(
                "#coordsig",
                &task_id,
                "task_request",
                "%7B%22description%22%3A%22ship%20it%22%7D",
                None,
                &signing,
            )
        ));
        bob.rx(|l| l.contains("task_request"), "the task request");

        // And the event that refers to it, so the linkage is a signed claim
        // too rather than a tag anyone could re-point.
        let done_id = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@{} TAGMSG #coordsig",
            signed_coordination_tags(
                "#coordsig",
                &done_id,
                "task_complete",
                "%7B%22summary%22%3A%22done%22%7D",
                Some(&task_id),
                &signing,
            )
        ));
        bob.rx(|l| l.contains("task_complete"), "the completion");
        (task_id, done_id)
    })
    .await
    .unwrap();

    // The broadcast races the row by a hair; give the writes a beat.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let v: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/verify/{task_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v["event_id"], task_id,
        "the id the sender signed is the id on file: {v}"
    );
    assert_eq!(v["kind"], "coordination", "{v}");
    assert_eq!(v["actor_did"], DID_ALICE, "{v}");
    assert_eq!(v["channel"], "#coordsig", "{v}");
    assert_eq!(v["verification"]["verdict"], "valid", "{v}");
    assert_eq!(
        v["verification"]["verified_by"], "client-session-key",
        "signed on the sender's device, not vouched by the server: {v}"
    );

    // The reference survives as the event's subject, so a reader can walk
    // from a completion to the work it completed.
    let done: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/verify/{done_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(done["subject"], task_id, "{done}");
    assert_eq!(done["verification"]["verdict"], "valid", "{done}");

    // …and the task API reaches the same linkage from the other end.
    let task: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/tasks/{task_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(task["task_id"], task_id, "{task}");
    assert_eq!(task["status"], "task_complete", "{task}");
}

/// A signature that fails against the key it names is not a coordination
/// event this server will keep, relay, or answer for.
#[tokio::test]
async fn a_coordination_event_whose_signature_fails_is_refused() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (irc_addr, web_addr, _h) = start_web(
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
        "test-coord-bad",
    )
    .await;

    let event_id = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        bob.join("#coordbad");
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        alice.join("#coordbad");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        // Signed over one payload, sent with another — the rewrite in flight
        // this signature exists to expose.
        let event_id = freeq_server::msgid::generate();
        let honest = signed_coordination_tags(
            "#coordbad",
            &event_id,
            "task_complete",
            "%7B%22paid%22%3A1%7D",
            None,
            &signing,
        );
        alice.tx(&format!(
            "@{} TAGMSG #coordbad",
            honest.replace("%7B%22paid%22%3A1%7D", "%7B%22paid%22%3A9%7D")
        ));
        alice.rx(|l| l.contains("SIGNATURE_INVALID"), "the refusal");
        assert!(
            bob.maybe(|l| l.contains("task_complete"), 500).is_none(),
            "a refused event must not reach the room either"
        );
        event_id
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    let missing = reqwest::get(format!("http://{web_addr}/api/v1/verify/{event_id}"))
        .await
        .unwrap();
    assert_eq!(
        missing.status(),
        404,
        "nothing was filed under the refused event's id"
    );
}

/// The event id is the *client's*, so two actors can name the same one. The
/// first to file it keeps it: reusing someone else's id changed their stored
/// event — its actor, its payload, all of it — into yours.
#[tokio::test]
async fn an_event_id_another_actor_filed_cannot_be_overwritten() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (irc_addr, web_addr, _h) = start_web(
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
        "test-coord-steal",
    )
    .await;

    let event_id = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        bob.join("#coordsteal");
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        alice.join("#coordsteal");

        let event_id = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@+freeq.at/event=task_request;msgid={event_id};\
             +freeq.at/payload=%7B%22budget%22%3A1%7D TAGMSG #coordsteal"
        ));
        bob.rx(|l| l.contains("task_request"), "alice's task");

        bob.tx(&format!(
            "@+freeq.at/event=task_request;msgid={event_id};\
             +freeq.at/payload=%7B%22budget%22%3A9999%7D TAGMSG #coordsteal"
        ));
        alice.rx(|l| l.contains("budget"), "bob's attempt reaches the room");
        event_id
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events: serde_json::Value = reqwest::get(format!(
        "http://{web_addr}/api/v1/channels/coordsteal/events"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let filed: Vec<&serde_json::Value> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event_id"] == event_id.as_str())
        .collect();
    assert_eq!(filed.len(), 1, "one id, one row: {events}");
    assert_eq!(
        filed[0]["actor_did"], DID_ALICE,
        "the actor who filed it keeps it: {events}"
    );
    assert_eq!(
        filed[0]["payload"]["budget"], 1,
        "and the payload they filed: {events}"
    );

    // And the log agrees with the card — the second actor's claim did not
    // reach either one.
    let v: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/verify/{event_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["actor_did"], DID_ALICE, "{v}");
    assert_eq!(v["kind"], "coordination", "{v}");
}

/// An unsigned coordination event is still stored and still answers — it just
/// answers honestly. What it must not do is carry a signature nobody checked:
/// storing the tag as it arrived put whatever the client typed in the column a
/// reader takes for evidence.
#[tokio::test]
async fn an_unsigned_coordination_event_is_filed_without_a_signature() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (irc_addr, web_addr, _h) = start_web(
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
        "test-coord-plain",
    )
    .await;

    let event_id = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        bob.join("#coordplain");
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        alice.join("#coordplain");

        let event_id = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@+freeq.at/event=task_request;msgid={event_id};\
             +freeq.at/payload=%7B%7D;+freeq.at/sig=ed25519:nobodyskid00000000000A:c2ln \
             TAGMSG #coordplain"
        ));
        bob.rx(|l| l.contains("task_request"), "the event still relays");
        event_id
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events: serde_json::Value = reqwest::get(format!(
        "http://{web_addr}/api/v1/channels/coordplain/events"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let row = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event_id"] == event_id.as_str())
        .unwrap_or_else(|| panic!("the event is still filed: {events}"));
    assert!(
        row["signature"].is_null(),
        "a signature this server never checked is not evidence: {events}"
    );

    let v: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/verify/{event_id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["verification"]["verdict"], "unverifiable", "{v}");
    assert_eq!(v["verification"]["verified_by"], "unsigned", "{v}");
}

/// A second claim on one event id is three situations, and the card and the
/// log have to reach the same answer in all of them — the card replacing
/// itself while the log ignored the second write left the two describing
/// different events, and the verify endpoint attesting bytes the card no
/// longer showed.
#[tokio::test]
async fn a_re_filed_event_leaves_the_card_and_the_log_agreeing() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (irc_addr, web_addr, _h) = start_web(
        resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)]),
        "test-coord-refile",
    )
    .await;

    let (same, differing) = tokio::task::spawn_blocking(move || {
        let mut bob = C::authenticated(irc_addr, "bob", did_bob, kb);
        bob.join("#refile");
        let mut alice = C::authenticated(irc_addr, "alice", DID_ALICE, ka);
        alice.join("#refile");

        // An event, then the same event again — a re-emit, which must be
        // harmless.
        let same = freeq_server::msgid::generate();
        let line = format!(
            "@+freeq.at/event=task_request;msgid={same};\
             +freeq.at/payload=%7B%22budget%22%3A1%7D TAGMSG #refile"
        );
        alice.tx(&line);
        bob.rx(|l| l.contains("task_request"), "the event");
        alice.tx(&line);

        // And an id already on file, re-filed by its own actor with different
        // content — the case that used to rewrite the card underneath the log.
        let differing = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@+freeq.at/event=task_request;msgid={differing};\
             +freeq.at/payload=%7B%22budget%22%3A1%7D TAGMSG #refile"
        ));
        bob.rx(|l| l.contains("budget"), "the second event");
        alice.tx(&format!(
            "@+freeq.at/event=task_request;msgid={differing};\
             +freeq.at/payload=%7B%22budget%22%3A9999%7D TAGMSG #refile"
        ));
        // A refused event is not relayed, so bob seeing nothing proves
        // nothing. Fence on an ordinary message instead: the server reads one
        // connection in order, so once this comes back the events before it
        // have been decided.
        alice.tx("PRIVMSG #refile :fence");
        bob.rx(|l| l.contains("fence"), "the fence");
        (same, differing)
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;
    let events: serde_json::Value =
        reqwest::get(format!("http://{web_addr}/api/v1/channels/refile/events"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let rows = events["events"].as_array().unwrap();

    for id in [&same, &differing] {
        let filed: Vec<&serde_json::Value> =
            rows.iter().filter(|e| e["event_id"] == id.as_str()).collect();
        assert_eq!(filed.len(), 1, "one id, one card: {events}");
        assert_eq!(
            filed[0]["payload"]["budget"], 1,
            "the first claim is the one on file: {events}"
        );

        // And the log says the same. It answers for the id either way; what
        // it must never do is describe a different event than the card.
        let v: serde_json::Value = reqwest::get(format!("http://{web_addr}/api/v1/verify/{id}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["event_id"], id.as_str(), "{v}");
        assert_eq!(v["kind"], "coordination", "{v}");
        assert_eq!(v["actor_did"], DID_ALICE, "{v}");
    }
}

/// Both halves of a signed pair reach other members carrying the field that
/// names the event — the TAGMSG's tags are relayed verbatim, the message's
/// are rebuilt, and only one of those two paths was ever exercised.
#[tokio::test]
async fn both_halves_of_a_signed_pair_relay_the_id_that_joins_them() {
    let (ka, kb) = (key(), key());
    let did_bob = "did:plc:sig_bob";
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (did_bob, &kb)])).await;
    run(addr, move |addr| {
        let mut bob = C::authenticated(addr, "bob", did_bob, kb);
        bob.join("#pairrelay");
        let mut alice = C::authenticated(addr, "alice", DID_ALICE, ka);
        alice.join("#pairrelay");
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        alice.msgsig(&signing);

        let event_id = freeq_server::msgid::generate();
        alice.tx(&format!(
            "@{} TAGMSG #pairrelay",
            signed_coordination_tags(
                "#pairrelay",
                &event_id,
                "task_request",
                "%7B%7D",
                None,
                &signing,
            )
        ));
        let tagmsg = bob.rx(|l| l.contains("TAGMSG"), "the event");
        assert!(
            tagmsg.contains(&format!("{EVENT_ID_TAG}={event_id}")),
            "the TAGMSG carries the id its signature covers: {tagmsg}"
        );

        // The companion: an ordinary message naming the event in a covered
        // tag, signed over a document that includes it. If the server's
        // covered set did not include that tag it would rebuild a different
        // document, reach `invalid`, and relay the message unsigned — so the
        // surviving signature is what proves both ends agree.
        let message_id = freeq_server::msgid::generate();
        let body = "📋 New task";
        let venue = channel_venue("#pairrelay");
        let doc = ChatDoc::message(DID_ALICE, &message_id, &venue, body)
            .with_coord([
                ("+freeq.at/event", "task_request"),
                ("+freeq.at/coordid", event_id.as_str()),
            ]);
        // Both this test and the server build the document through the same
        // covered set, so a set that dropped the tag would have them agree on
        // a document without it and prove nothing. Pin the bytes.
        assert!(
            doc.canonical().contains(r#""coordid""#),
            "the message document must cover the tag: {}",
            doc.canonical()
        );
        let sig = doc.sign(&signing);
        alice.tx(&format!(
            "@{EVENT_ID_TAG}={message_id};+freeq.at/event=task_request;\
             +freeq.at/coordid={event_id};+freeq.at/sig={sig} PRIVMSG #pairrelay :{body}"
        ));
        let privmsg = bob.rx(|l| l.contains(body), "the companion");
        assert!(
            privmsg.contains(&format!("+freeq.at/coordid={event_id}")),
            "the companion carries the id that joins it to the event: {privmsg}"
        );
        assert_eq!(
            C::sig_of(&privmsg).as_deref(),
            Some(sig.as_str()),
            "the sender's own signature survives, so the server rebuilt the \
             same document — the new tag included: {privmsg}"
        );
    })
    .await;
}
