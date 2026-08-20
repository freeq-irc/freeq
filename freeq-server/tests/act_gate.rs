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
use freeq_sdk::chatsig::{ChatDoc, EVENT_ID_TAG, Mutation, channel_venue};
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
    start_with_expiry(resolver, 604_800).await
}

async fn start_with_expiry(
    resolver: DidResolver,
    act_expiry_secs: u64,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-act".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        act_expiry_secs,
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
        // Set the read timeout on the reader's own fd. Setting it on a writer
        // clone also works — both fds dup the same socket, and the timeout is a
        // socket property — but reading from the fd we set it on is clearer.
        self.reader
            .get_ref()
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
        self.reader
            .get_ref()
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

    /// The FAIL for a command other than TAGMSG — a delete or an edit.
    fn fail_code_of(&mut self, command: &str) -> String {
        let line = self.rx(|l| l.contains(&format!(" FAIL {command} ")), "FAIL");
        line.split_whitespace()
            .nth(3)
            .expect("FAIL carries a code")
            .to_string()
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
        ("+freeq.at/from".into(), DID_ALICE.into()),
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
        tags[0].1 = "approval".into(); // a real kind, not one this server has
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

/// Not `alg:kid:sig`, so it names no key and no check can run. Invalid is
/// reserved for bytes that contradict a key; a check that never ran produced
/// no such evidence — unverifiable, the same reading the chat profile gives
/// an unparseable or legacy signature format. (This test asserted
/// SIGNATURE_INVALID until 2026-08-20; that pinned the wrong half of the
/// frozen invalid/unverifiable split.)
#[tokio::test]
async fn a_malformed_signature_tag_reads_unverifiable() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx(&line_with_sig(
            &offer_tags(),
            "#ops",
            &fresh_id(),
            "garbage",
        ));
        assert_eq!(a.fail_code(), "SIGNATURE_UNVERIFIABLE");
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

#[tokio::test]
async fn a_task_message_naming_someone_else_as_its_actor_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        // A correctly signed message whose act-from names somebody else. The
        // signature proves who sent it; act-from claims who acted, and the
        // two have to be the same person.
        let mut tags = offer_tags();
        tags[2].1 = DID_BOB.into();
        a.tx(&signed_line(&tags, "#ops", &fresh_id(), &signing));
        assert_eq!(a.fail_code(), "ACTOR_MISMATCH");
    })
    .await;
}

/// A task message that names no actor at all. Distinct from naming the wrong
/// one: the storage layer refuses such bytes as unreadable, and without this
/// the sender would learn nothing about why its event vanished.
#[tokio::test]
async fn a_task_message_naming_no_actor_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        // An actor-less document cannot even be signed since the realignment
        // (`from` is mandatory), so this line carries a real signature over
        // the full tags with the from tag then stripped from the wire — the
        // shape a stripping relay would produce. The gate answers before any
        // signature check runs.
        let id = fresh_id();
        let full = offer_tags();
        let pairs: Vec<(&str, &str)> = full.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &channel_venue("#ops"), &id, &signing)
            .expect("act tags present");
        let tags: Vec<(String, String)> = full
            .into_iter()
            .filter(|(k, _)| k != "+freeq.at/from")
            .collect();
        a.tx(&line_with_sig(&tags, "#ops", &id, &sig));
        assert_eq!(a.fail_code(), "ACTOR_REQUIRED");
    })
    .await;
}

/// The invalid/unverifiable split, at the gate: a signature naming an
/// algorithm this server has never heard of cannot be checked, and that is
/// not evidence about the sender — the answer is SIGNATURE_UNVERIFIABLE,
/// never SIGNATURE_INVALID. Until 2026-08-20 this case was answered as
/// invalid, telling a sender with a future algorithm its signature was
/// forged.
#[tokio::test]
async fn an_unknown_signature_algorithm_reads_unverifiable_not_invalid() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let id = fresh_id();
        let tags = offer_tags();
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let real = freeq_sdk::act::sign_act(pairs, &channel_venue("#ops"), &id, &signing)
            .expect("act tags present");
        let swapped = format!("rsa4096:{}", real.split_once(':').expect("alg:kid:sig").1);
        a.tx(&line_with_sig(&tags, "#ops", &id, &swapped));
        assert_eq!(a.fail_code(), "SIGNATURE_UNVERIFIABLE");
    })
    .await;
}

#[tokio::test]
async fn a_task_message_without_an_event_id_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        // The signature covers the id, so without one there is nothing to
        // rebuild — and the sender should hear that rather than a signature
        // complaint about a document it never built.
        let tags = offer_tags();
        let venue = channel_venue("#ops");
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &fresh_id(), &signing).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG #ops", wire.join(";")));
        assert_eq!(a.fail_code(), "EVENTID_REQUIRED");
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

// ── refereeing, once a task is on file ──────────────────────────────────────

/// Open a task and return its id, so a test can then act on it.
fn open_task(c: &mut C, signing: &SigningKey, channel: &str, to: Option<&str>) -> String {
    let id = fresh_id();
    let mut tags = offer_tags();
    if to.is_none() {
        tags.retain(|(k, _)| k != "+freeq.at/act-to");
    }
    c.tx(&signed_line(&tags, channel, &id, signing));
    // The sender holds the capability, so it sees its own accepted event echo.
    c.rx(
        |l| l.contains("+freeq.at/act=") && l.contains(&id),
        "the offer",
    );
    id
}

/// A follow-up naming `task`, signed for `channel`.
fn follow_up_line(
    verb: &str,
    from: &str,
    task: &str,
    channel: &str,
    id: &str,
    key: &SigningKey,
) -> String {
    let tags: Vec<(String, String)> = vec![
        ("+freeq.at/act".into(), "handoff".into()),
        ("+freeq.at/act-verb".into(), verb.into()),
        ("+freeq.at/from".into(), from.into()),
        ("+freeq.at/act-id".into(), task.into()),
    ];
    signed_line(&tags, channel, id, key)
}

#[tokio::test]
async fn a_follow_up_naming_a_task_this_server_has_never_filed_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx(&follow_up_line(
            "accept",
            DID_ALICE,
            "01JNOSUCHTASK00000000000X",
            "#ops",
            &fresh_id(),
            &signing,
        ));
        assert_eq!(a.fail_code(), "UNKNOWN_TASK");
    })
    .await;
}

#[tokio::test]
async fn a_follow_up_posted_in_another_conversation_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.join("#elsewhere");
        let task = open_task(&mut a, &signing, "#ops", None);
        a.tx(&follow_up_line(
            "claim",
            DID_ALICE,
            &task,
            "#elsewhere",
            &fresh_id(),
            &signing,
        ));
        assert_eq!(a.fail_code(), "WRONG_VENUE");
    })
    .await;
}

#[tokio::test]
async fn a_step_the_task_state_does_not_allow_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);
        // Nobody has claimed it, so there is no work to complete.
        a.tx(&follow_up_line(
            "complete",
            DID_ALICE,
            &task,
            "#ops",
            &fresh_id(),
            &signing,
        ));
        assert_eq!(a.fail_code(), "ILLEGAL_STEP");
    })
    .await;
}

#[tokio::test]
async fn a_step_that_is_not_the_senders_to_take_is_refused() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        // Offered to bob; alice cannot accept on his behalf, and the accept
        // she signs names herself, so it is her own step to take or not.
        let task = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        a.tx(&follow_up_line(
            "accept",
            DID_ALICE,
            &task,
            "#ops",
            &fresh_id(),
            &alice_key,
        ));
        assert_eq!(a.fail_code(), "WRONG_SENDER");
    })
    .await;
}

#[tokio::test]
async fn a_finished_task_takes_no_further_steps() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let task = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        b.tx(&follow_up_line(
            "decline",
            DID_BOB,
            &task,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        b.rx(|l| l.contains("act-verb=decline"), "the decline");

        b.tx(&follow_up_line(
            "accept",
            DID_BOB,
            &task,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        assert_eq!(b.fail_code(), "TERMINAL_TASK");
    })
    .await;
}

#[tokio::test]
async fn an_accept_after_the_offers_deadline_is_refused() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        // A deadline already in the past. The accept's own id carries the
        // clock, and a freshly minted one is well past it.
        let id = fresh_id();
        let mut tags = offer_tags();
        tags.push(("+freeq.at/act-deadline".into(), "1000000000".into()));
        a.tx(&signed_line(&tags, "#ops", &id, &alice_key));
        a.rx(|l| l.contains(&id), "the offer");

        b.tx(&follow_up_line(
            "accept",
            DID_BOB,
            &id,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        assert_eq!(b.fail_code(), "DEADLINE_PASSED");
    })
    .await;
}

/// The whole point: a task that is offered, accepted and completed, with each
/// step landing where the rules say it should.
#[tokio::test]
async fn a_task_runs_from_offer_to_completion() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let task = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        for (verb, key) in [
            ("accept", &bob_key),
            ("progress", &bob_key),
            ("complete", &bob_key),
        ] {
            b.tx(&follow_up_line(
                verb,
                DID_BOB,
                &task,
                "#ops",
                &fresh_id(),
                key,
            ));
            b.rx(
                |l| l.contains(&format!("act-verb={verb}")),
                "the step is accepted and echoed",
            );
        }
        // Finished: the task has left the live view, and the log is what
        // still knows it existed — so the answer is that it is finished, not
        // that nobody ever opened it.
        b.tx(&follow_up_line(
            "progress",
            DID_BOB,
            &task,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        assert_eq!(b.fail_code(), "TERMINAL_TASK");
    })
    .await;
}

// ── receipts ────────────────────────────────────────────────────────────────

/// The `act-subject` of a receipt line, if the line is one.
fn receipt_subject(line: &str) -> Option<String> {
    if !line.contains("+freeq.at/act-verb=confirm") {
        return None;
    }
    line.trim_start_matches('@')
        .split(&[' ', ';'][..])
        .find_map(|t| t.strip_prefix("+freeq.at/act-subject="))
        .map(str::to_string)
}

/// The home's word about a move it filed: signed under `did:web:`, naming the
/// event it confirms, and verifying against the key that server publishes.
#[tokio::test]
async fn a_state_transition_earns_a_receipt_the_home_signed() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let task = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        let accept_id = fresh_id();
        b.tx(&follow_up_line(
            "accept", DID_BOB, &task, "#ops", &accept_id, &bob_key,
        ));

        let receipt = b
            .maybe(|l| l.contains("+freeq.at/act-verb=confirm"), 3_000)
            .expect("the home confirms a move it filed");
        assert_eq!(
            receipt_subject(&receipt).as_deref(),
            Some(accept_id.as_str()),
            "the receipt names the event it confirms: {receipt}"
        );
        assert!(
            receipt.contains(&format!("+freeq.at/act-id={task}")),
            "and the action it belongs to: {receipt}"
        );
        assert!(
            receipt.contains("+freeq.at/from=did:web:test-act"),
            "signed under this server's own identity: {receipt}"
        );
        assert!(
            receipt.contains("+freeq.at/sig=ed25519:"),
            "with a signature: {receipt}"
        );
    })
    .await;
}

/// One receipt per move, and none for anything that moved nothing: an opener
/// (opening is the action), a progress report (`from` and `to` are the same
/// state), or the server's own expiry (home-signed already).
#[tokio::test]
async fn only_a_move_earns_a_receipt_and_it_earns_exactly_one() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        // The offer opens the task; nothing raced it, so nothing confirms it.
        let task = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        assert!(
            b.maybe(|l| l.contains("act-verb=confirm"), 600).is_none(),
            "an opener is not confirmed"
        );

        let mut confirmed: Vec<String> = Vec::new();
        for (verb, expect_receipt) in [("accept", true), ("progress", false), ("complete", true)] {
            let id = fresh_id();
            b.tx(&follow_up_line(verb, DID_BOB, &task, "#ops", &id, &bob_key));
            match expect_receipt {
                true => {
                    let line = b
                        .maybe(|l| l.contains("act-verb=confirm"), 3_000)
                        .unwrap_or_else(|| panic!("{verb} moved the task and earns a receipt"));
                    assert_eq!(receipt_subject(&line).as_deref(), Some(id.as_str()));
                    confirmed.push(id);
                }
                // A report that leaves the task where it stood has no move to
                // confirm. Waited out against the *next* step's receipt, which
                // is what would arrive if this one were wrong.
                false => assert!(
                    b.maybe(|l| l.contains("act-verb=confirm"), 800).is_none(),
                    "{verb} leaves the task where it stood and earns no receipt"
                ),
            }
        }
        assert_eq!(confirmed.len(), 2, "one receipt each, and no more");
    })
    .await;
}

/// A sender writing the home's verb is refused before any kind's table is
/// consulted — not with UNKNOWN_VERB, which would say the kind is merely
/// missing a row for it.
#[tokio::test]
async fn a_confirmation_from_a_sender_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "confirm".into()),
            ("+freeq.at/from".into(), DID_ALICE.into()),
            ("+freeq.at/act-id".into(), task.clone()),
            ("+freeq.at/act-subject".into(), task.clone()),
        ];
        a.tx(&signed_line(&tags, "#ops", &fresh_id(), &signing));
        let line = a.fail();
        assert!(line.contains(" WRONG_SENDER "), "{line}");
        assert!(
            line.ends_with("Only the action's home confirms it"),
            "the approved sentence: {line}"
        );
    })
    .await;
}

/// A task in a direct conversation is confirmed too, and to both ends of it.
/// The line names the thread from the sender's side — the same limitation the
/// expiry notice carries, since a server-authored line has only the one target
/// to write.
#[tokio::test]
async fn a_receipt_in_a_direct_conversation_reaches_both_participants() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);

        let venue = freeq_sdk::chatsig::dm_venue(DID_ALICE, DID_BOB);
        let id = fresh_id();
        let tags = offer_tags();
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &id, &alice_key).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG {DID_BOB}", wire.join(";")));
        b.rx(|l| l.contains("+freeq.at/act="), "the DM task reaches bob");

        // Bob accepts, in the same conversation, addressing alice.
        let accept_id = fresh_id();
        let steps: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "accept".into()),
            ("+freeq.at/from".into(), DID_BOB.into()),
            ("+freeq.at/act-id".into(), id.clone()),
        ];
        let pairs: Vec<(&str, &str)> = steps
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &accept_id, &bob_key).unwrap();
        let mut wire: Vec<String> = steps.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={accept_id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        b.tx(&format!("@{} TAGMSG {DID_ALICE}", wire.join(";")));

        for c in [&mut a, &mut b] {
            let line = c
                .maybe(|l| l.contains("act-verb=confirm"), 3_000)
                .expect("both ends of the conversation hear the receipt");
            assert_eq!(receipt_subject(&line).as_deref(), Some(accept_id.as_str()));
        }
    })
    .await;
}

/// Replay is where a late arrival learns what happened, receipts included —
/// and a connection that did not ask for the capability gets none of it.
#[tokio::test]
async fn replay_carries_the_receipts_to_capability_holders_only() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let task = open_task(&mut a, &alice_key, "#ops", None);
        let claim_id = fresh_id();
        a.tx(&follow_up_line(
            "claim", DID_ALICE, &task, "#ops", &claim_id, &alice_key,
        ));
        a.maybe(|l| l.contains("act-verb=confirm"), 3_000)
            .expect("the claim is confirmed");
        // A message too: the join replay interleaves task events with message
        // history, so the batch needs one of each.
        a.tx("PRIVMSG #ops :a line about it");

        let mut late = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        late.tx("JOIN #ops");
        let replayed = late
            .maybe(|l| l.contains("act-verb=confirm"), 3_000)
            .expect("the receipt replays like any other stored task event");
        assert_eq!(
            receipt_subject(&replayed).as_deref(),
            Some(claim_id.as_str())
        );
        assert!(
            replayed.contains("+freeq.at/sig="),
            "with its signature, so a late arrival can check it: {replayed}"
        );

        let mut plain = C::guest(addr, "carol", BASE_CAPS);
        plain.tx("JOIN #ops");
        let ended = plain.rx(
            |l| l.contains("+freeq.at/act") || l.split_whitespace().nth(1) == Some("366"),
            "a task event, or the end of the burst",
        );
        assert!(
            !ended.contains("+freeq.at/act"),
            "no capability, no receipts either: {ended}"
        );
    })
    .await;
}

// ── bounty: the second kind, and no code of its own ─────────────────────────

/// A bounty step, signed. `accepts` is the bid an award takes.
fn bounty_line(
    verb: &str,
    from: &str,
    task: Option<&str>,
    accepts: Option<&str>,
    channel: &str,
    id: &str,
    key: &SigningKey,
) -> String {
    let mut tags: Vec<(String, String)> = vec![
        ("+freeq.at/act".into(), "bounty".into()),
        ("+freeq.at/act-verb".into(), verb.into()),
        ("+freeq.at/from".into(), from.into()),
    ];
    match task {
        Some(t) => tags.push(("+freeq.at/act-id".into(), t.into())),
        None => tags.push(("+freeq.at/act-title".into(), "index-the-archive".into())),
    }
    if let Some(accepts) = accepts {
        tags.push(("+freeq.at/act-accepts".into(), accepts.into()));
    }
    signed_line(&tags, channel, id, key)
}

/// Open a bounty and return its id.
fn open_bounty(c: &mut C, signing: &SigningKey, channel: &str) -> String {
    let id = fresh_id();
    c.tx(&bounty_line(
        "offer", DID_ALICE, None, None, channel, &id, signing,
    ));
    c.rx(|l| l.contains(&id), "the bounty opens");
    id
}

/// Open a bounty, take bob's bid on it, and return its id — the setup every
/// test of the review half starts from.
fn award_to_bob(
    a: &mut C,
    b: &mut C,
    alice_key: &SigningKey,
    bob_key: &SigningKey,
    channel: &str,
) -> String {
    let bounty = open_bounty(a, alice_key, channel);
    let bid = fresh_id();
    b.tx(&bounty_line(
        "bid",
        DID_BOB,
        Some(&bounty),
        None,
        channel,
        &bid,
        bob_key,
    ));
    b.rx(|l| l.contains(&bid), "the bid is accepted");
    let award = fresh_id();
    a.tx(&bounty_line(
        "award",
        DID_ALICE,
        Some(&bounty),
        Some(&bid),
        channel,
        &award,
        alice_key,
    ));
    b.rx(|l| l.contains(&award), "the award is accepted");
    bounty
}

/// A bounty opener carrying a recipient, which is the one thing it cannot do.
fn directed_bounty_line(from: &str, channel: &str, id: &str, key: &SigningKey) -> String {
    let tags: Vec<(String, String)> = vec![
        ("+freeq.at/act".into(), "bounty".into()),
        ("+freeq.at/act-verb".into(), "offer".into()),
        ("+freeq.at/from".into(), from.into()),
        ("+freeq.at/act-title".into(), "index-the-archive".into()),
        ("+freeq.at/act-to".into(), DID_BOB.into()),
    ];
    signed_line(&tags, channel, id, key)
}

/// The test of generality: a second kind that needed a table row and no code.
/// Bids pile up without moving anything, the poster takes one of them, and its
/// author — not the poster who took it — is the one who can finish the work.
#[tokio::test]
async fn a_bounty_awards_the_bid_it_names_and_the_bidder_becomes_assignee() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let bounty = fresh_id();
        a.tx(&bounty_line(
            "offer", DID_ALICE, None, None, "#ops", &bounty, &alice_key,
        ));
        a.rx(|l| l.contains(&bounty), "the bounty opens");

        // Two bids, from two agents, neither of which moves it.
        let mut bids = Vec::new();
        for (did, k) in [(DID_ALICE, &alice_key), (DID_BOB, &bob_key)] {
            let bid = fresh_id();
            let line = bounty_line("bid", did, Some(&bounty), None, "#ops", &bid, k);
            match did == DID_ALICE {
                true => a.tx(&line),
                false => b.tx(&line),
            }
            b.rx(|l| l.contains(&bid), "the bid is accepted");
            bids.push(bid);
        }

        // The poster takes bob's bid — the second one, so the assignee cannot
        // have come from the sender or from whichever bid arrived first.
        let award = fresh_id();
        a.tx(&bounty_line(
            "award",
            DID_ALICE,
            Some(&bounty),
            Some(&bids[1]),
            "#ops",
            &award,
            &alice_key,
        ));
        b.rx(|l| l.contains(&award), "the award is accepted");

        // The loser cannot hand in work that is not theirs…
        a.tx(&bounty_line(
            "submit",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &alice_key,
        ));
        assert_eq!(a.fail_code(), "WRONG_SENDER");

        // …and the winner can.
        let done = fresh_id();
        b.tx(&bounty_line(
            "submit",
            DID_BOB,
            Some(&bounty),
            None,
            "#ops",
            &done,
            &bob_key,
        ));
        b.rx(|l| l.contains(&done), "the winner hands it in");
    })
    .await;
}

/// The bounty's own half of the lifecycle, on the wire: the worker hands the
/// work in, the poster sends it back once, the worker hands it in again, and
/// the poster takes it. The poster's word ends it, not the worker's — which is
/// the whole difference from a handoff.
#[tokio::test]
async fn submitted_work_is_sent_back_once_and_then_accepted_by_the_poster() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");
        let bounty = award_to_bob(&mut a, &mut b, &alice_key, &bob_key, "#ops");

        for verb in ["revise", "accept-work"] {
            let handed_in = fresh_id();
            b.tx(&bounty_line(
                "submit",
                DID_BOB,
                Some(&bounty),
                None,
                "#ops",
                &handed_in,
                &bob_key,
            ));
            b.rx(|l| l.contains(&handed_in), "the work is handed in");

            let answer = fresh_id();
            a.tx(&bounty_line(
                verb,
                DID_ALICE,
                Some(&bounty),
                None,
                "#ops",
                &answer,
                &alice_key,
            ));
            b.rx(|l| l.contains(&answer), verb);
        }

        // Accepted is terminal: there is nothing further to hand in.
        b.tx(&bounty_line(
            "submit",
            DID_BOB,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        assert_eq!(b.fail_code(), "TERMINAL_TASK");
    })
    .await;
}

/// Once the work is in, the poster's only moves are taking it and sending it
/// back — and signing off on the work is not the worker's to do.
#[tokio::test]
async fn delivered_work_is_neither_withdrawn_nor_self_accepted() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");
        let bounty = award_to_bob(&mut a, &mut b, &alice_key, &bob_key, "#ops");

        let handed_in = fresh_id();
        b.tx(&bounty_line(
            "submit",
            DID_BOB,
            Some(&bounty),
            None,
            "#ops",
            &handed_in,
            &bob_key,
        ));
        b.rx(|l| l.contains(&handed_in), "the work is handed in");

        a.tx(&bounty_line(
            "cancel",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &alice_key,
        ));
        assert_eq!(a.fail_code(), "ILLEGAL_STEP");

        b.tx(&bounty_line(
            "accept-work",
            DID_BOB,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &bob_key,
        ));
        assert_eq!(b.fail_code(), "WRONG_SENDER");
    })
    .await;
}

/// A bounty is not a handoff, and its worker has no verb that ends it. The
/// two that would are ones the kind's table simply does not list.
#[tokio::test]
async fn a_bounty_has_no_complete_and_no_fail() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let bounty = open_bounty(&mut a, &signing, "#ops");
        for verb in ["complete", "fail"] {
            a.tx(&bounty_line(
                verb,
                DID_ALICE,
                Some(&bounty),
                None,
                "#ops",
                &fresh_id(),
                &signing,
            ));
            assert_eq!(a.fail_code(), "UNKNOWN_VERB", "{verb}");
        }
    })
    .await;
}

/// The worker's exit, from either state they may hold the work in.
#[tokio::test]
async fn the_worker_forfeits_the_work_and_the_bounty_is_finished() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let bounty = award_to_bob(&mut a, &mut b, &alice_key, &bob_key, "#ops");

        // Not the poster's to give up on the worker's behalf.
        a.tx(&bounty_line(
            "forfeit",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &alice_key,
        ));
        assert_eq!(a.fail_code(), "WRONG_SENDER");

        let gone = fresh_id();
        b.tx(&bounty_line(
            "forfeit",
            DID_BOB,
            Some(&bounty),
            None,
            "#ops",
            &gone,
            &bob_key,
        ));
        b.rx(|l| l.contains(&gone), "the worker walks away");

        a.tx(&bounty_line(
            "revise",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &alice_key,
        ));
        assert_eq!(a.fail_code(), "TERMINAL_TASK");
    })
    .await;
}

/// An award naming no bid takes nothing, so the row's `requires` refuses it —
/// and the sentence names the field rather than the verb, because which field
/// a step needs is the rules file's to say.
#[tokio::test]
async fn an_award_that_names_no_bid_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");

        let bounty = fresh_id();
        a.tx(&bounty_line(
            "offer", DID_ALICE, None, None, "#ops", &bounty, &signing,
        ));
        a.rx(|l| l.contains(&bounty), "the bounty opens");

        a.tx(&bounty_line(
            "award",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &fresh_id(),
            &signing,
        ));
        let line = a.fail();
        assert!(line.contains(" MISSING_REQUIREMENT "), "{line}");
        assert!(
            line.ends_with("That step must carry act-accepts"),
            "the approved sentence names the missing field: {line}"
        );
    })
    .await;
}

/// An award points at one event, and only a bid on the same action answers.
/// The bounty's own opener is not one, and neither is an id nobody filed.
#[tokio::test]
async fn an_award_naming_a_non_bid_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");

        let bounty = fresh_id();
        a.tx(&bounty_line(
            "offer", DID_ALICE, None, None, "#ops", &bounty, &signing,
        ));
        a.rx(|l| l.contains(&bounty), "the bounty opens");

        let bid = fresh_id();
        a.tx(&bounty_line(
            "bid",
            DID_ALICE,
            Some(&bounty),
            None,
            "#ops",
            &bid,
            &signing,
        ));
        a.rx(|l| l.contains(&bid), "the bid is accepted");

        // The opener, and then an id this server never filed at all.
        for named in [bounty.clone(), fresh_id()] {
            a.tx(&bounty_line(
                "award",
                DID_ALICE,
                Some(&bounty),
                Some(&named),
                "#ops",
                &fresh_id(),
                &signing,
            ));
            let line = a.fail();
            assert!(line.contains(" ACCEPTS_NOT_A_BID "), "{named}: {line}");
            assert!(
                line.ends_with("The award names an event that is not a bid on this action"),
                "{line}"
            );
        }

        // …and the bid itself still works, so the refusals were about what
        // was named and not about the award.
        let done = fresh_id();
        a.tx(&bounty_line(
            "award",
            DID_ALICE,
            Some(&bounty),
            Some(&bid),
            "#ops",
            &done,
            &signing,
        ));
        a.rx(|l| l.contains(&done), "the award is accepted");
    })
    .await;
}

/// A bounty is open by construction — a directed one is just a handoff — so
/// an opener carrying a recipient is a step the kind cannot take.
#[tokio::test]
async fn a_bounty_opened_to_one_recipient_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx(&directed_bounty_line(
            DID_ALICE,
            "#ops",
            &fresh_id(),
            &signing,
        ));
        assert_eq!(a.fail_code(), "ILLEGAL_STEP");
    })
    .await;
}

// ── the revival relation ────────────────────────────────────────────────────

/// An opener that names the finished action it revives.
fn re_offer_line(from: &str, replaces: &str, channel: &str, id: &str, key: &SigningKey) -> String {
    let tags: Vec<(String, String)> = vec![
        ("+freeq.at/act".into(), "handoff".into()),
        ("+freeq.at/act-verb".into(), "offer".into()),
        ("+freeq.at/from".into(), from.into()),
        (
            "+freeq.at/act-title".into(),
            "review-the-deploy-again".into(),
        ),
        ("+freeq.at/act-replaces".into(), replaces.into()),
    ];
    signed_line(&tags, channel, id, key)
}

/// A failed handoff, re-offered: the new action carries the link and the old
/// one is left exactly as it ended.
#[tokio::test]
async fn a_re_offer_carries_the_link_to_the_action_it_revives() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);
        a.join("#ops");
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&bob_key);
        b.join("#ops");

        let dead = open_task(&mut a, &alice_key, "#ops", Some(DID_BOB));
        for verb in ["accept", "fail"] {
            b.tx(&follow_up_line(
                verb,
                DID_BOB,
                &dead,
                "#ops",
                &fresh_id(),
                &bob_key,
            ));
            b.rx(|l| l.contains(&format!("act-verb={verb}")), verb);
        }

        let revived = fresh_id();
        a.tx(&re_offer_line(
            DID_ALICE, &dead, "#ops", &revived, &alice_key,
        ));
        let line = a.rx(|l| l.contains(&revived), "the re-offer is accepted");
        assert!(
            line.contains(&format!("+freeq.at/act-replaces={dead}")),
            "the link rides the wire, inside the signature: {line}"
        );
    })
    .await;
}

/// Reviving something still running would leave two live actions each
/// claiming to be the work.
#[tokio::test]
async fn a_re_offer_naming_a_live_action_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let live = open_task(&mut a, &signing, "#ops", None);

        a.tx(&re_offer_line(
            DID_ALICE,
            &live,
            "#ops",
            &fresh_id(),
            &signing,
        ));
        let line = a.fail();
        assert!(line.contains(" REPLACES_NOT_TERMINAL "), "{line}");
        assert!(
            line.ends_with("The action it replaces is not finished"),
            "the approved sentence: {line}"
        );
    })
    .await;
}

/// The relation belongs to an opener. A step on an action that already exists
/// names no other.
#[tokio::test]
async fn a_step_that_carries_the_revival_relation_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "claim".into()),
            ("+freeq.at/from".into(), DID_ALICE.into()),
            ("+freeq.at/act-id".into(), task.clone()),
            ("+freeq.at/act-replaces".into(), task.clone()),
        ];
        a.tx(&signed_line(&tags, "#ops", &fresh_id(), &signing));
        let line = a.fail();
        assert!(line.contains(" REPLACES_NOT_OPENER "), "{line}");
        assert!(
            line.ends_with("Only a new action replaces an earlier one"),
            "the approved sentence: {line}"
        );
    })
    .await;
}

/// A value that could not be an action id is answered as itself, rather than
/// as a link to an action nobody filed.
#[tokio::test]
async fn a_revival_naming_something_that_is_not_an_action_id_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx(&re_offer_line(
            DID_ALICE,
            "the-last-one",
            "#ops",
            &fresh_id(),
            &signing,
        ));
        let line = a.fail();
        assert!(line.contains(" REPLACES_MALFORMED "), "{line}");
        assert!(
            line.ends_with("That is not the id of an action"),
            "the approved sentence: {line}"
        );
    })
    .await;
}

// ── task history cannot be rewritten ────────────────────────────────────────

#[tokio::test]
async fn a_delete_aimed_at_a_task_event_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        // Signed like any real delete: once signing enforcement is on, an
        // unsigned mutation is refused at the signature gate before the act
        // gate is ever consulted — and a signed one must still be refused here.
        let del_id = fresh_id();
        let sig = ChatDoc::mutation(
            Mutation::Delete,
            DID_ALICE,
            &del_id,
            &channel_venue("#ops"),
            &task,
        )
        .sign(&signing);
        a.tx(&format!(
            "@+draft/delete={task};{EVENT_ID_TAG}={del_id};+freeq.at/sig={sig} TAGMSG #ops"
        ));
        assert_eq!(a.fail_code_of("DELETE"), "IMMUTABLE_EVENT");
    })
    .await;
}

#[tokio::test]
async fn an_edit_aimed_at_a_task_event_is_refused() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        a.tx(&format!("@+draft/edit={task} PRIVMSG #ops :rewritten"));
        assert_eq!(a.fail_code_of("EDIT"), "IMMUTABLE_EVENT");
    })
    .await;
}

/// The DM path had no row to find for an unpersisted thread and relayed the
/// delete live rather than refusing it. A task event is on file whether or not
/// a message row is, so the log is what decides.
#[tokio::test]
async fn a_delete_aimed_at_a_task_event_in_a_dm_is_refused() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.msgsig(&SigningKey::from_bytes(&[8u8; 32]));
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&alice_key);

        // A task in the conversation between the two of them.
        let id = fresh_id();
        let venue = freeq_sdk::chatsig::dm_venue(DID_ALICE, DID_BOB);
        let tags = offer_tags();
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &id, &alice_key).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG {DID_BOB}", wire.join(";")));
        b.rx(|l| l.contains("+freeq.at/act="), "the DM task reaches bob");

        // Signed for the same reason as the channel variant above.
        let del_id = fresh_id();
        let sig =
            ChatDoc::mutation(Mutation::Delete, DID_ALICE, &del_id, &venue, &id).sign(&alice_key);
        a.tx(&format!(
            "@+draft/delete={id};{EVENT_ID_TAG}={del_id};+freeq.at/sig={sig} TAGMSG {DID_BOB}"
        ));
        assert_eq!(a.fail_code_of("DELETE"), "IMMUTABLE_EVENT");
        assert!(
            b.maybe(|l| l.contains("+draft/delete"), 500).is_none(),
            "and the delete does not reach the other side either"
        );
    })
    .await;
}

/// The plain-text line a bot posts beside a task is an ordinary message — a
/// rendering of the event, not the event — and stays deletable.
#[tokio::test]
async fn a_companion_line_beside_a_task_stays_deletable() {
    let k = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        // The companion, linked to the task the way a companion links.
        let companion = fresh_id();
        a.tx(&format!(
            "@{EVENT_ID_TAG}={companion};+freeq.at/ref={task} PRIVMSG #ops :alice offered: a task"
        ));
        a.rx(|l| l.contains("alice offered"), "the companion");

        a.tx(&format!("@+draft/delete={companion} TAGMSG #ops"));
        assert!(
            a.maybe(|l| l.contains("IMMUTABLE_EVENT"), 500).is_none(),
            "a companion line is a message and deletes like one"
        );
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

// ── replay ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_joiner_holding_the_capability_replays_the_task_events() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);
        // A message too, so the batch carries both kinds.
        a.tx("PRIVMSG #ops :a line about it");

        // Someone arriving afterwards, holding the capability. The replay
        // arrives before the end-of-names numeric, so the JOIN is not waited
        // out first — doing that would read straight past it.
        let mut late = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        late.tx("JOIN #ops");
        let replayed = late.rx(|l| l.contains("+freeq.at/act="), "the task event replays");
        assert!(
            replayed.contains(&task),
            "the task's own id rides: {replayed}"
        );
        assert!(
            replayed.contains("+freeq.at/sig="),
            "with its signature: {replayed}"
        );
        assert!(
            replayed.contains("+freeq.at/act-verb=offer"),
            "and its act tags: {replayed}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_joiner_without_the_capability_replays_no_task_events() {
    let ka = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        open_task(&mut a, &signing, "#ops", None);
        a.tx("PRIVMSG #ops :a line about it");

        let mut late = C::guest(addr, "carol", BASE_CAPS);
        late.tx("JOIN #ops");
        // The ordinary message still replays…
        late.rx(|l| l.contains("a line about it"), "the message replays");
        // …and the end of the join burst arrives with no task event in it.
        let ended = late.rx(
            |l| l.contains("+freeq.at/act") || l.split_whitespace().nth(1) == Some("366"),
            "a task event, or the end of the burst",
        );
        assert!(
            !ended.contains("+freeq.at/act"),
            "a connection that did not ask receives no task events, replayed either: {ended}"
        );
    })
    .await;
}

#[tokio::test]
async fn chathistory_carries_task_events_to_capability_holders() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx("PRIVMSG #ops :before");
        let task = open_task(&mut a, &signing, "#ops", None);

        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.join("#ops");
        b.tx("CHATHISTORY LATEST #ops * 50");
        let replayed = b.rx(
            |l| l.contains("+freeq.at/act="),
            "the task event in history",
        );
        assert!(replayed.contains(&task), "{replayed}");
    })
    .await;
}

/// Wait for the wall clock to tick into the next second, so the next thing
/// stored lands on a later timestamp than the last — the boundary a replay
/// window derived from message timestamps used to cut on.
fn next_second() {
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };
    let start = now();
    while now() == start {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The task is the newest thing in the room: no chat line follows it. A
/// joiner still gets it — the replay answers for the channel, not for the
/// span of the messages that happened to be in the buffer.
#[tokio::test]
async fn a_task_posted_after_the_last_message_replays_to_a_joiner() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx("PRIVMSG #ops :the last word, for now");
        a.rx(|l| l.contains("the last word"), "the message echoes");
        next_second();
        let task = open_task(&mut a, &signing, "#ops", None);

        let mut late = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        late.tx("JOIN #ops");
        let replayed = late.rx(|l| l.contains("+freeq.at/act="), "the task event replays");
        assert!(replayed.contains(&task), "{replayed}");
    })
    .await;
}

/// Nobody has chatted in the room at all — it is only tasks. A joiner who
/// asked for them gets them.
#[tokio::test]
async fn a_room_with_only_task_events_replays_them_to_a_joiner() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        let mut late = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        late.tx("JOIN #ops");
        let replayed = late.rx(|l| l.contains("+freeq.at/act="), "the task event replays");
        assert!(replayed.contains(&task), "{replayed}");
    })
    .await;
}

/// The same for an explicit history request: LATEST answers with the newest
/// task events under its own limit, whether or not a message follows them.
#[tokio::test]
async fn chathistory_carries_a_task_posted_after_the_last_message() {
    let ka = key();
    let kb = key();
    let (addr, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, ka, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        a.tx("PRIVMSG #ops :before");
        a.rx(|l| l.contains("before"), "the message echoes");
        next_second();
        let task = open_task(&mut a, &signing, "#ops", None);

        let mut b = C::authenticated(addr, "bob", DID_BOB, kb, ACT_CAPS);
        b.join("#ops");
        b.tx("CHATHISTORY LATEST #ops * 50");
        let replayed = b.rx(
            |l| l.contains("+freeq.at/act="),
            "the task event in history",
        );
        assert!(replayed.contains(&task), "{replayed}");
    })
    .await;
}

// ── expiry ──────────────────────────────────────────────────────────────────

/// Everything at once: the sweep signs its own event under the server's
/// identity, that signature resolves through the ordinary key store, the
/// event lands like any other, and the room is told in the approved words.
#[tokio::test]
async fn an_abandoned_task_expires_and_the_room_is_told() {
    let k = key();
    // Every task is abandoned the moment it exists.
    let (addr, _h) = start_with_expiry(resolver_with(vec![(DID_ALICE, &k)]), 1).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");

        let id = fresh_id();
        let tags = offer_tags();
        a.tx(&signed_line(&tags, "#ops", &id, &signing));
        a.rx(|l| l.contains(&id), "the offer");

        // The sweep runs on its own clock; give it room.
        let notice = a.maybe(
            |l| l.contains("NOTICE") && l.contains("Task expired"),
            90_000,
        );
        let notice = notice.expect("the room hears about the expiry");
        assert!(
            notice.ends_with("Task expired without completion: review-the-deploy"),
            "the approved sentence, with the offer's own title: {notice}"
        );
    })
    .await;
}

/// The notice carries a title its sender chose, so the title cannot be allowed
/// to end the line. A title holding a whole second IRC line must arrive as text
/// inside the one notice, never as a line of its own.
#[tokio::test]
async fn a_title_cannot_put_a_second_line_on_the_wire() {
    let k = key();
    let (addr, _h) = start_with_expiry(resolver_with(vec![(DID_ALICE, &k)]), 1).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");

        // A real CRLF and a complete IRC line, signed by the offerer like any
        // other title — the signature is no obstacle to its own author.
        let mut tags = offer_tags();
        tags[4].1 = "done\r\n:ghost!g@g PRIVMSG #ops :forged".into();
        let id = fresh_id();
        let venue = channel_venue("#ops");
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &id, &signing).expect("act tags present");
        // The control bytes ride the wire escaped, as the tag encoding requires;
        // the server unescapes them back to the bytes the signature covers.
        let mut wire: Vec<String> = tags
            .iter()
            .map(|(k, v)| {
                let escaped = v
                    .replace('\\', "\\\\")
                    .replace(';', "\\:")
                    .replace(' ', "\\s")
                    .replace('\r', "\\r")
                    .replace('\n', "\\n");
                format!("{k}={escaped}")
            })
            .collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG #ops", wire.join(";")));
        a.rx(|l| l.contains(&id), "the offer");

        let notice = a
            .maybe(|l| l.contains("Task expired"), 90_000)
            .expect("the room hears about the expiry");
        // The line the author wrote is still there — as text, inside the one
        // notice, its line break gone. That is the whole property: a title can
        // say anything, and none of it can become a line.
        assert_eq!(
            notice,
            ":test-act NOTICE #ops :Task expired without completion: \
             done:ghost!g@g PRIVMSG #ops :forged",
            "the title arrives as inert text on the approved sentence"
        );
        assert!(
            a.maybe(|l| l.contains("forged"), 1_000).is_none(),
            "no line the title author wrote may arrive on its own"
        );
    })
    .await;
}

/// The expiry event itself: filed, signed by the server, and refereed like
/// anything else — so the task is finished and takes no further steps.
#[tokio::test]
async fn an_expired_task_is_finished_and_its_event_is_the_servers() {
    let k = key();
    let (addr, _h) = start_with_expiry(resolver_with(vec![(DID_ALICE, &k)]), 1).await;
    run(addr, move |addr| {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut a = C::authenticated(addr, "alice", DID_ALICE, k, ACT_CAPS);
        a.msgsig(&signing);
        a.join("#ops");
        let task = open_task(&mut a, &signing, "#ops", None);

        let expiry = a
            .maybe(
                |l| l.contains("act-verb=expire") || l.contains("Task expired"),
                90_000,
            )
            .expect("the sweep runs");
        // Whichever arrived first, the task is now finished.
        let _ = expiry;
        a.tx(&follow_up_line(
            "claim",
            DID_ALICE,
            &task,
            "#ops",
            &fresh_id(),
            &signing,
        ));
        assert_eq!(a.fail_code(), "TERMINAL_TASK");
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
