//! Acceptance tests for the server's task-message gate.
//!
//! A message carrying `act-` tags is a task event. It is accepted only from a
//! logged-in sender whose signature checks out over the document the signer
//! built — the act tags, the venue, and the id it minted — and only for a kind
//! and a verb the rules file lists. Everything else is refused by name.
//!
//! Nothing is stored here: this step is recognition and delivery.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::chatsig::{EVENT_ID_TAG, channel_venue};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:act_alice";
const DID_BOB: &str = "did:plc:act_bob";
/// A ULID whose embedded time is close enough to now for id adoption.
fn fresh_id() -> String {
    freeq_sdk::chatsig::new_event_id()
}

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
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-act".to_string(),
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
    fn open(addr: SocketAddr) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        Self {
            reader: BufReader::new(s),
            writer: w,
        }
    }

    fn guest(addr: SocketAddr, nick: &str, caps: &str) -> Self {
        let mut c = Self::open(addr);
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx(&format!("CAP REQ :{caps}"));
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c.num("001");
        c
    }

    fn authenticated(addr: SocketAddr, nick: &str, did: &str, key: PrivateKey, caps: &str) -> Self {
        let mut c = Self::open(addr);
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx(&format!("CAP REQ :sasl {caps}"));
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

    /// Register a message-signing key for this session, as every signing
    /// client does once after auth.
    fn msgsig(&mut self, key: &SigningKey) {
        use base64::Engine;
        let pubkey =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        self.tx(&format!("MSGSIG {pubkey}"));
        self.rx(|l| l.contains("MSGSIG"), "MSGSIG ack");
    }

    /// The FAIL this server sent for the last thing we did.
    fn fail(&mut self) -> String {
        self.rx(|l| l.contains(" FAIL TAGMSG "), "FAIL")
    }

    fn fail_code(&mut self) -> String {
        let line = self.fail();
        line.split_whitespace()
            .nth(3)
            .expect("FAIL carries a code")
            .to_string()
    }
}

fn key() -> PrivateKey {
    PrivateKey::generate_ed25519()
}

/// The tags of a directed offer, minus the signature. Values carry no spaces
/// or semicolons, so the escaped wire form and the signed value are the same
/// bytes and the test is about the gate rather than about IRC escaping.
fn offer_tags() -> Vec<(String, String)> {
    vec![
        ("+freeq.at/act".into(), "handoff".into()),
        ("+freeq.at/act-verb".into(), "offer".into()),
        ("+freeq.at/act-from".into(), DID_ALICE.into()),
        ("+freeq.at/act-to".into(), DID_BOB.into()),
        ("+freeq.at/act-title".into(), "review-the-deploy".into()),
    ]
}

/// Sign `tags` for `venue` under `id`, and return the whole wire line.
fn signed_line(tags: &[(String, String)], target: &str, id: &str, key: &SigningKey) -> String {
    let venue = channel_venue(target);
    let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let sig = freeq_sdk::act::sign_act(pairs, &venue, id, key).expect("act tags present");
    line_with_sig(tags, target, id, &sig)
}

fn line_with_sig(tags: &[(String, String)], target: &str, id: &str, sig: &str) -> String {
    let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
    wire.push(format!("{EVENT_ID_TAG}={id}"));
    wire.push(format!("+freeq.at/sig={sig}"));
    format!("@{} TAGMSG {target}", wire.join(";"))
}

/// Every client in these tests negotiates message-tags; the act capability is
/// named separately so a test can hold one and not the other.
const BASE_CAPS: &str = "message-tags server-time echo-message";
const ACT_CAPS: &str = "message-tags server-time echo-message freeq.at/act";

// ── the capability ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_act_capability_is_advertised_and_acknowledged() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut c = C::open(addr);
        c.tx("CAP LS 302");
        c.tx("NICK caps");
        c.tx("USER caps 0 * :test");
        let ls = c.rx(|l| l.contains("CAP") && l.contains("LS"), "CAP LS");
        assert!(
            ls.contains("freeq.at/act"),
            "the capability must be advertised: {ls}"
        );
        c.tx("CAP REQ :message-tags freeq.at/act");
        let ack = c.rx(|l| l.contains("ACK") || l.contains("NAK"), "CAP reply");
        assert!(
            ack.contains("ACK"),
            "must be acknowledged, not NAKed: {ack}"
        );
        assert!(ack.contains("freeq.at/act"), "{ack}");
    })
    .await;
}

// ── the gate ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_guest_cannot_send_a_task_message() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut guest = C::guest(addr, "guest", ACT_CAPS);
        guest.join("#ops");
        // A guest has no key to sign with, so the signature is beside the
        // point — the sender check comes first.
        let tags = offer_tags();
        let line = line_with_sig(&tags, "#ops", &fresh_id(), "ed25519:nope:nope");
        guest.tx(&line);
        assert_eq!(guest.fail_code(), "ACCOUNT_REQUIRED");
    })
    .await;
}

#[tokio::test]
async fn a_task_message_without_a_signature_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        let tags = offer_tags();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={}", fresh_id()));
        a.tx(&format!("@{} TAGMSG #ops", wire.join(";")));
        assert_eq!(a.fail_code(), "SIGNATURE_REQUIRED");
    })
    .await;
}

#[tokio::test]
async fn a_signature_that_does_not_verify_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.join("#other");
        // Signed for one room, sent to another: the key is on file, the kid
        // matches, and the bytes do not.
        let id = fresh_id();
        let tags = offer_tags();
        let venue = channel_venue("#other");
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &id, &signing).unwrap();
        a.tx(&line_with_sig(&tags, "#ops", &id, &sig));
        assert_eq!(a.fail_code(), "SIGNATURE_INVALID");
    })
    .await;
}

#[tokio::test]
async fn a_signature_naming_a_key_this_server_does_not_have_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        // Never registered through MSGSIG, so no key answers to this kid.
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        a.tx(&signed_line(&offer_tags(), "#ops", &fresh_id(), &stranger));
        assert_eq!(a.fail_code(), "SIGNATURE_UNVERIFIABLE");
    })
    .await;
}

#[tokio::test]
async fn a_kind_the_rules_file_does_not_list_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let mut tags = offer_tags();
        tags[0].1 = "bounty".into(); // a real kind, not one this server has
        a.tx(&signed_line(&tags, "#ops", &fresh_id(), &signing));
        assert_eq!(a.fail_code(), "UNKNOWN_KIND");
    })
    .await;
}

#[tokio::test]
async fn a_verb_the_kind_does_not_have_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let mut tags = offer_tags();
        tags[1].1 = "award".into(); // bounty's verb, not handoff's
        a.tx(&signed_line(&tags, "#ops", &fresh_id(), &signing));
        assert_eq!(a.fail_code(), "UNKNOWN_VERB");
    })
    .await;
}

#[tokio::test]
async fn a_malformed_signature_tag_is_refused_as_invalid() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        // Not `alg:kid:sig`, so it names no key at all. It cannot be a
        // key-availability problem, and it will never become checkable.
        a.tx(&line_with_sig(
            &offer_tags(),
            "#ops",
            &fresh_id(),
            "garbage",
        ));
        assert_eq!(a.fail_code(), "SIGNATURE_INVALID");
    })
    .await;
}

#[tokio::test]
async fn a_task_message_to_someone_without_an_account_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        // A guest has no DID, so the conversation has no venue any verifier
        // could rebuild — no task message can ever be signed there.
        let _carol = C::guest(addr, "carol", BASE_CAPS);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        let tags = offer_tags();
        let id = fresh_id();
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, "dm:whatever", &id, &signing).unwrap();
        a.tx(&line_with_sig(&tags, "carol", &id, &sig));
        assert_eq!(a.fail_code(), "INVALID_TARGET");
    })
    .await;
}

// ── one message, one job ────────────────────────────────────────────────────

#[tokio::test]
async fn act_tags_on_a_message_with_a_body_are_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        a.tx("@+freeq.at/act=handoff;+freeq.at/act-verb=offer PRIVMSG #ops :also a body");
        let line = a.rx(|l| l.contains(" FAIL "), "FAIL");
        assert!(line.contains("MIXED_TAGS"), "{line}");
    })
    .await;
}

#[tokio::test]
async fn act_tags_mixed_with_a_delete_are_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        a.tx("@+freeq.at/act=handoff;+freeq.at/act-verb=offer;+draft/delete=01ABC TAGMSG #ops");
        assert_eq!(a.fail_code(), "MIXED_TAGS");
    })
    .await;
}

#[tokio::test]
async fn act_tags_mixed_with_a_reaction_are_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        a.tx("@+freeq.at/act=handoff;+freeq.at/act-verb=offer;+react=x;+reply=01ABC TAGMSG #ops");
        assert_eq!(a.fail_code(), "MIXED_TAGS");
    })
    .await;
}

#[tokio::test]
async fn act_tags_mixed_with_a_stopgap_event_are_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.join("#ops");
        a.tx("@+freeq.at/act=handoff;+freeq.at/act-verb=offer;+freeq.at/event=task_request TAGMSG #ops");
        assert_eq!(a.fail_code(), "MIXED_TAGS");
    })
    .await;
}

// ── delivery ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_accepted_task_message_reaches_only_the_capability_holders() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        // Holds the capability.
        let mut watcher = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        watcher.join("#ops");
        // Does not.
        let mut plain = C::guest(addr, "carol", BASE_CAPS);
        plain.join("#ops");

        let id = fresh_id();
        a.tx(&signed_line(&offer_tags(), "#ops", &id, &signing));

        let seen = watcher.rx(|l| l.contains("TAGMSG"), "task message");
        assert!(seen.contains("+freeq.at/act=handoff"), "{seen}");
        assert!(
            seen.contains("+freeq.at/sig="),
            "the signature rides: {seen}"
        );
        assert!(
            seen.contains(&format!("{EVENT_ID_TAG}={id}")),
            "the id the signature covers rides too: {seen}"
        );

        assert!(
            plain.maybe(|l| l.contains("+freeq.at/act"), 400).is_none(),
            "a connection that did not ask for the capability receives nothing"
        );
    })
    .await;
}

// ── flood ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn task_messages_share_the_stopgap_flood_counter() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");

        // Three of the stopgap family…
        for i in 0..3 {
            a.tx(&format!(
                "@+freeq.at/event=task_request;+freeq.at/payload=%7B%7D;msgid=stop{i} TAGMSG #ops"
            ));
        }
        // …then three task messages. One budget, not two: the sixth is over.
        for _ in 0..2 {
            a.tx(&signed_line(&offer_tags(), "#ops", &fresh_id(), &signing));
        }
        a.tx(&signed_line(&offer_tags(), "#ops", &fresh_id(), &signing));
        let line = a.fail();
        assert!(
            line.contains("RATE_LIMITED"),
            "the two families share one counter, so the combined rate cannot \
             double: {line}"
        );
        assert!(
            line.ends_with("At most 5 events per 2 seconds per session"),
            "one sentence for both families: {line}"
        );
    })
    .await;
}
