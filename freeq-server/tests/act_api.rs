//! The two read endpoints for tasks.
//!
//! Open work is queryable, and a task in a direct conversation is readable
//! only by the two people in it — the listing and the single fetch enforce
//! that separately, because channel authorization says nothing about DMs and
//! leaving it out would publish who is tasking whom.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::chatsig::{EVENT_ID_TAG, channel_venue};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:api_alice";
const DID_BOB: &str = "did:plc:api_bob";
const CAPS: &str = "message-tags server-time echo-message freeq.at/act";

async fn start(
    resolver: DidResolver,
) -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        web_addr: Some("127.0.0.1:0".to_string()),
        server_name: "test-act-api".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start_with_web()
        .await
        .unwrap()
}

fn resolver_with(entries: Vec<(&str, &PrivateKey)>) -> DidResolver {
    let mut docs = HashMap::new();
    for (d, k) in entries {
        docs.insert(
            d.to_string(),
            did::make_test_did_document(d, &k.public_key_multibase()),
        );
    }
    DidResolver::static_map(docs)
}

async fn get(web: SocketAddr, path: &str, bearer: Option<&str>) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .get(format!("http://{web}{path}"))
        .timeout(Duration::from_secs(5));
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let r = req.send().await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// One counter's value, read off `/metrics` the way a scraper would.
async fn metric(web: SocketAddr, name: &str) -> u64 {
    let body = reqwest::Client::new()
        .get(format!("http://{web}/metrics"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    body.lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("{name} is not published:\n{body}"))
        .trim()
        .parse()
        .unwrap()
}

/// A raw IRC client, so a test can put a signed task message on the wire.
struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    /// The session id the server hands back, which doubles as the API bearer.
    bearer: String,
}

impl C {
    fn authenticated(addr: SocketAddr, nick: &str, did: &str, key: PrivateKey) -> Self {
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let writer = sock.try_clone().unwrap();
        let mut c = C {
            reader: BufReader::new(sock),
            writer,
            bearer: String::new(),
        };
        c.tx("CAP LS 302");
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c.tx(&format!("CAP REQ :sasl {CAPS}"));
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let line = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let bytes =
            auth::decode_challenge_bytes(line.strip_prefix("AUTHENTICATE ").unwrap()).unwrap();
        let resp = KeySigner::new(did.to_string(), key)
            .respond(&bytes)
            .unwrap();
        c.tx(&format!("AUTHENTICATE {}", auth::encode_response(&resp)));
        c.rx(|l| l.split_whitespace().nth(1) == Some("903"), "903");
        let bearer_line = c.rx(|l| l.contains("API-BEARER"), "the API bearer");
        c.bearer = bearer_line
            .rsplit("API-BEARER ")
            .next()
            .unwrap()
            .trim()
            .to_string();
        c.tx("CAP END");
        c.rx(|l| l.split_whitespace().nth(1) == Some("001"), "001");
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
                        let t = l.strip_prefix("PING ").unwrap_or(":x").to_string();
                        self.tx(&format!("PONG {t}"));
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

    fn join(&mut self, channel: &str) {
        self.tx(&format!("JOIN {channel}"));
        self.rx(|l| l.split_whitespace().nth(1) == Some("366"), "366");
    }

    fn msgsig(&mut self, key: &SigningKey) {
        use base64::Engine;
        let pubkey =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        self.tx(&format!("MSGSIG {pubkey}"));
        self.rx(|l| l.contains("MSGSIG"), "MSGSIG ack");
    }

    /// Open a task in `target`, whose venue is `venue`, and return its id.
    fn offer(&mut self, target: &str, venue: &str, from: &str, key: &SigningKey) -> String {
        let id = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "offer".into()),
            ("+freeq.at/from".into(), from.into()),
            ("+freeq.at/act-caps".into(), "freeq.at/web-search".into()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, venue, &id, key).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        self.tx(&format!("@{} TAGMSG {target}", wire.join(";")));
        self.rx(|l| l.contains(&id), "the offer is accepted and echoed");
        id
    }

    /// Open a handoff directed at `to`, so the offeree can `accept` it.
    fn offer_to(
        &mut self,
        target: &str,
        venue: &str,
        to: &str,
        from: &str,
        key: &SigningKey,
    ) -> String {
        let id = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "offer".into()),
            ("+freeq.at/from".into(), from.into()),
            ("+freeq.at/act-to".into(), to.into()),
            ("+freeq.at/act-title".into(), "Cite 3 sources".into()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, venue, &id, key).unwrap();
        // The title has spaces in it, which a tag value carries escaped.
        let mut wire: Vec<String> = tags
            .iter()
            .map(|(k, v)| format!("{k}={}", v.replace(' ', "\\s")))
            .collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        self.tx(&format!("@{} TAGMSG {target}", wire.join(";")));
        self.rx(
            |l| l.contains(&id),
            "the directed offer is accepted and echoed",
        );
        id
    }

    /// Move the task `act_id` along with `verb`, and return the event's id.
    fn step(
        &mut self,
        target: &str,
        venue: &str,
        act_id: &str,
        verb: &str,
        from: &str,
        key: &SigningKey,
    ) -> String {
        let id = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), verb.into()),
            ("+freeq.at/from".into(), from.into()),
            ("+freeq.at/act-id".into(), act_id.into()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, venue, &id, key).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        self.tx(&format!("@{} TAGMSG {target}", wire.join(";")));
        self.rx(|l| l.contains(&id), "the step is accepted and echoed");
        id
    }
}

fn ids(body: &serde_json::Value) -> Vec<String> {
    body["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["act_id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn the_listing_answers_with_open_work_and_its_declared_fields() {
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    let task = tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");
        a.offer("#work", &channel_venue("#work"), DID_ALICE, &signing)
    })
    .await
    .unwrap();

    let (status, body) = get(web, "/api/v1/actions", None).await;
    assert_eq!(status, 200);
    assert_eq!(ids(&body), vec![task.clone()]);
    let row = &body["tasks"][0];
    assert_eq!(row["kind"], "handoff");
    assert_eq!(row["state"], "open");
    assert_eq!(row["offerer"], DID_ALICE);
    assert_eq!(row["venue"], "#work");
    assert_eq!(row["caps"], "freeq.at/web-search", "stored and filterable");
    assert_eq!(row["origin"], "", "created here");
    assert_eq!(
        row["dropped_unchecked"], 0,
        "no event about this task was ever dropped unchecked"
    );
    assert_eq!(
        row["stored_state"], "open",
        "the row's own state rides alongside, so a reader can tell the task's \
         record from this server's reading of it"
    );

    // The same count on the single-task answer: a reader who opens one task
    // must be told what a reader of the list is told.
    let (status, one) = get(web, &format!("/api/v1/actions/{task}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(one["task"]["dropped_unchecked"], 0);
}

/// A task this server minted answers as it stands, whatever any peer is doing:
/// we are its home, so there is no home to be out of contact with.
#[tokio::test]
async fn our_own_task_never_reads_orphaned() {
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    let task = tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");
        a.offer("#work", &channel_venue("#work"), DID_ALICE, &signing)
    })
    .await
    .unwrap();

    let (_, listing) = get(web, "/api/v1/actions", None).await;
    assert_eq!(listing["tasks"][0]["state"], "open");
    let (status, one) = get(web, &format!("/api/v1/actions/{task}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(one["task"]["state"], "open");
    assert_eq!(one["task"]["stored_state"], "open");
}

#[tokio::test]
async fn the_listing_filters_by_kind_and_state() {
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");
        a.offer("#work", &channel_venue("#work"), DID_ALICE, &signing);
    })
    .await
    .unwrap();

    let (_, open) = get(web, "/api/v1/actions?state=open", None).await;
    assert_eq!(open["tasks"].as_array().unwrap().len(), 1);
    let (_, assigned) = get(web, "/api/v1/actions?state=assigned", None).await;
    assert!(assigned["tasks"].as_array().unwrap().is_empty());
    let (_, bounty) = get(web, "/api/v1/actions?kind=bounty", None).await;
    assert!(bounty["tasks"].as_array().unwrap().is_empty());
}

/// The one that would leak: a task in a direct conversation must not appear
/// for anyone outside it, on either endpoint.
#[tokio::test]
async fn a_task_in_a_direct_conversation_is_private_to_its_two_participants() {
    let ka = PrivateKey::generate_ed25519();
    let kb = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    // Both connections stay open for the whole test: a bearer is a live
    // session id, and a closed connection takes its session with it.
    let (task, alice_bearer, bob_bearer, _a, _b) = tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let b = C::authenticated(irc, "bob", DID_BOB, kb);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, ka);
        a.msgsig(&signing);
        let venue = freeq_sdk::chatsig::dm_venue(DID_ALICE, DID_BOB);
        let id = a.offer(DID_BOB, &venue, DID_ALICE, &signing);
        let (ab, bb) = (a.bearer.clone(), b.bearer.clone());
        (id, ab, bb, a, b)
    })
    .await
    .unwrap();

    // Anonymous sees nothing of it.
    let (_, anon) = get(web, "/api/v1/actions", None).await;
    assert!(
        ids(&anon).is_empty(),
        "a DM task must not appear for an anonymous caller: {anon}"
    );
    let (status, _) = get(web, &format!("/api/v1/actions/{task}"), None).await;
    assert_eq!(status, 403);

    eprintln!("DEBUG alice_bearer={alice_bearer:?} bob_bearer={bob_bearer:?}");
    // Both participants see it.
    for bearer in [&alice_bearer, &bob_bearer] {
        let (_, body) = get(web, "/api/v1/actions", Some(bearer)).await;
        assert_eq!(ids(&body), vec![task.clone()]);
        let (status, one) = get(web, &format!("/api/v1/actions/{task}"), Some(bearer)).await;
        assert_eq!(status, 200);
        assert_eq!(one["task"]["venue"], one["venue"]);
    }
}

#[tokio::test]
async fn one_task_comes_back_with_its_whole_event_history() {
    let ka = PrivateKey::generate_ed25519();
    let kb = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    let task = tokio::task::spawn_blocking(move || {
        let alice_key = SigningKey::from_bytes(&[21u8; 32]);
        let bob_key = SigningKey::from_bytes(&[22u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, ka);
        a.msgsig(&alice_key);
        a.join("#work");
        let mut b = C::authenticated(irc, "bob", DID_BOB, kb);
        b.msgsig(&bob_key);
        b.join("#work");

        let id = a.offer("#work", &channel_venue("#work"), DID_ALICE, &alice_key);
        for verb in ["claim", "progress", "complete"] {
            let ev = freeq_sdk::chatsig::new_event_id();
            let tags: Vec<(String, String)> = vec![
                ("+freeq.at/act".into(), "handoff".into()),
                ("+freeq.at/act-verb".into(), verb.into()),
                ("+freeq.at/from".into(), DID_BOB.into()),
                ("+freeq.at/act-id".into(), id.clone()),
            ];
            let pairs: Vec<(&str, &str)> =
                tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let sig =
                freeq_sdk::act::sign_act(pairs, &channel_venue("#work"), &ev, &bob_key).unwrap();
            let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
            wire.push(format!("{EVENT_ID_TAG}={ev}"));
            wire.push(format!("+freeq.at/sig={sig}"));
            b.tx(&format!("@{} TAGMSG #work", wire.join(";")));
            b.rx(|l| l.contains(&ev), "the step is accepted");
        }
        id
    })
    .await
    .unwrap();

    let (status, body) = get(web, &format!("/api/v1/actions/{task}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["events"].as_array().unwrap().len(),
        6,
        "the offer, its three follow-ups, and a receipt for each of the two \
         that moved the task"
    );
    assert!(
        body["events"][0]["canonical"]
            .as_str()
            .unwrap()
            .contains("act-verb"),
        "each event comes back as the bytes its signature covers"
    );
    assert!(body["events"][0]["signature"].is_string());
    assert!(
        body["task"].is_null(),
        "the task finished, so it has left the live view — its history has not"
    );

    // …and it is gone from the open-work listing.
    let (_, listing) = get(web, "/api/v1/actions", None).await;
    assert!(ids(&listing).is_empty());
}

/// A receipt is served from the log like any other event, and the bytes served
/// are the bytes signed: this checks the stored canonical against the very key
/// the server publishes as its own, which is the whole worth of a receipt.
#[tokio::test]
async fn the_event_list_carries_the_receipts_and_their_signatures_verify() {
    use base64::Engine;

    let ka = PrivateKey::generate_ed25519();
    let kb = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    let (task, accept_id) = tokio::task::spawn_blocking(move || {
        let alice_key = SigningKey::from_bytes(&[21u8; 32]);
        let bob_key = SigningKey::from_bytes(&[22u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, ka);
        a.msgsig(&alice_key);
        a.join("#work");
        let mut b = C::authenticated(irc, "bob", DID_BOB, kb);
        b.msgsig(&bob_key);
        b.join("#work");

        let id = a.offer("#work", &channel_venue("#work"), DID_ALICE, &alice_key);
        let ev = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "claim".into()),
            ("+freeq.at/from".into(), DID_BOB.into()),
            ("+freeq.at/act-id".into(), id.clone()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &channel_venue("#work"), &ev, &bob_key).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={ev}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        b.tx(&format!("@{} TAGMSG #work", wire.join(";")));
        b.rx(|l| l.contains(&ev), "the claim is accepted");
        (id, ev)
    })
    .await
    .unwrap();

    let (_, own) = get(web, "/api/v1/signing-key", None).await;
    let published = own["publicKey"]
        .as_str()
        .or_else(|| own["public_key"].as_str())
        .or_else(|| own["pubkey"].as_str())
        .expect("the server publishes its key");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(published)
        .expect("base64url");
    let key = ed25519_dalek::VerifyingKey::from_bytes(&raw.try_into().unwrap()).unwrap();

    let (_, body) = get(web, &format!("/api/v1/actions/{task}"), None).await;
    let events = body["events"].as_array().unwrap();
    let receipt = events
        .iter()
        .find(|e| {
            e["canonical"]
                .as_str()
                .is_some_and(|c| c.contains(r#""act-verb":"confirm""#))
        })
        .expect("the receipt is on file and served");

    let canonical = receipt["canonical"].as_str().unwrap();
    assert!(
        canonical.contains(&format!(r#""act-subject":"{accept_id}""#)),
        "it names the event it confirms: {canonical}"
    );
    assert!(
        canonical.contains(r#""from":"did:web:test-act-api""#),
        "signed under the server's own identity: {canonical}"
    );
    freeq_sdk::sigtag::verify_canonical(
        canonical,
        receipt["signature"].as_str().expect("a receipt is signed"),
        &key,
    )
    .expect("the receipt verifies against the key the server publishes");
}

/// The server signs the expiry events it makes, and a signature is only worth
/// anything if a verifier can look its key up. This proves boot puts that key
/// where every other signer's key lives, under the server's own identity.
#[tokio::test]
async fn the_servers_own_signing_key_is_registered_at_boot() {
    let k = PrivateKey::generate_ed25519();
    let (_irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;

    let (status, body) = get(web, "/api/v1/signing-keys/did:web:test-act-api", None).await;
    assert_eq!(
        status, 200,
        "the server's own key resolves after boot: {body}"
    );
    let published = body["publicKey"]
        .as_str()
        .or_else(|| body["public_key"].as_str())
        .or_else(|| body["pubkey"].as_str())
        .expect("the answer carries a key");
    assert!(!published.is_empty());

    // …and it is the same key the server publishes as its own.
    let (_, own) = get(web, "/api/v1/signing-key", None).await;
    let mine = own["publicKey"]
        .as_str()
        .or_else(|| own["public_key"].as_str())
        .or_else(|| own["pubkey"].as_str())
        .expect("the server publishes its key");
    assert_eq!(published, mine, "one key, one identity");
}

/// The counter against a running server, not against the formatter.
///
/// The formatting test hands `format_metrics` numbers it made up, so it passes
/// whether or not anything increments — which is exactly how a counter can read
/// zero in production while its test stays green. This one sends a real task
/// message and reads the number back off the endpoint.
#[tokio::test]
async fn a_task_event_moves_the_counter_on_the_metrics_endpoint() {
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;

    let before = metric(web, "freeq_act_events_total").await;
    assert_eq!(before, 0, "nothing has been sent yet");

    tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");
        a.offer("#work", &channel_venue("#work"), DID_ALICE, &signing);
    })
    .await
    .unwrap();

    assert_eq!(
        metric(web, "freeq_act_events_total").await,
        1,
        "one task event arrived, so the published number says one"
    );
}

/// The revival relation is a fact about the new action, so it reads off the
/// action rather than out of the opener's bytes — in the listing and on the
/// single fetch alike. An action that revives nothing says so.
#[tokio::test]
async fn a_revived_action_shows_what_it_replaces_on_both_endpoints() {
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    let (dead, revived, unrelated) = tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");

        let venue = channel_venue("#work");
        let dead = a.offer("#work", &venue, DID_ALICE, &signing);
        // The poster withdraws it, which finishes it.
        let ev = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "cancel".into()),
            ("+freeq.at/from".into(), DID_ALICE.into()),
            ("+freeq.at/act-id".into(), dead.clone()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &ev, &signing).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={ev}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG #work", wire.join(";")));
        a.rx(|l| l.contains(&ev), "the cancel is accepted");

        // Re-listed, naming what it revives.
        let revived = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "offer".into()),
            ("+freeq.at/from".into(), DID_ALICE.into()),
            ("+freeq.at/act-replaces".into(), dead.clone()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &revived, &signing).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={revived}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG #work", wire.join(";")));
        a.rx(|l| l.contains(&revived), "the re-offer is accepted");

        let unrelated = a.offer("#work", &venue, DID_ALICE, &signing);
        (dead, revived, unrelated)
    })
    .await
    .unwrap();

    let (_, listing) = get(web, "/api/v1/actions", None).await;
    let rows = listing["tasks"].as_array().unwrap();
    let row = rows
        .iter()
        .find(|t| t["act_id"] == serde_json::json!(revived))
        .expect("the revived action is live");
    assert_eq!(row["replaces"], serde_json::json!(dead));
    let other = rows
        .iter()
        .find(|t| t["act_id"] == serde_json::json!(unrelated))
        .unwrap();
    assert!(
        other["replaces"].is_null(),
        "an action that revives nothing says so: {other}"
    );

    let (status, one) = get(web, &format!("/api/v1/actions/{revived}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(one["task"]["replaces"], serde_json::json!(dead));

    // …and the action it replaces is exactly as it ended.
    let (_, old) = get(web, &format!("/api/v1/actions/{dead}"), None).await;
    assert!(old["task"].is_null(), "cancelled, so it left the view");
    assert_eq!(
        old["events"].as_array().unwrap().len(),
        3,
        "the offer, the cancel, and the receipt for the cancel — nothing added \
         by the revival"
    );
}

/// The rule that is load-bearing for federation: a link to an action this
/// server never filed is annotated, not refused, and the annotation is served.
#[tokio::test]
async fn a_link_to_an_action_this_server_never_saw_is_annotated_and_served() {
    const NEVER_SEEN: &str = "01M16E7TC0NEVERSEEN0000000";
    let k = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    let revived = tokio::task::spawn_blocking(move || {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let mut a = C::authenticated(irc, "alice", DID_ALICE, k);
        a.msgsig(&signing);
        a.join("#work");

        let venue = channel_venue("#work");
        let id = freeq_sdk::chatsig::new_event_id();
        let tags: Vec<(String, String)> = vec![
            ("+freeq.at/act".into(), "handoff".into()),
            ("+freeq.at/act-verb".into(), "offer".into()),
            ("+freeq.at/from".into(), DID_ALICE.into()),
            ("+freeq.at/act-replaces".into(), NEVER_SEEN.into()),
        ];
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let sig = freeq_sdk::act::sign_act(pairs, &venue, &id, &signing).unwrap();
        let mut wire: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        wire.push(format!("{EVENT_ID_TAG}={id}"));
        wire.push(format!("+freeq.at/sig={sig}"));
        a.tx(&format!("@{} TAGMSG #work", wire.join(";")));
        a.rx(|l| l.contains(&id), "the re-offer is accepted anyway");
        id
    })
    .await
    .unwrap();

    let (_, listing) = get(web, "/api/v1/actions", None).await;
    assert_eq!(ids(&listing), vec![revived.clone()]);
    assert_eq!(listing["tasks"][0]["replaces"], NEVER_SEEN);
}

#[tokio::test]
async fn a_task_nobody_ever_opened_is_not_found() {
    let k = PrivateKey::generate_ed25519();
    let (_irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &k)])).await;
    let (status, _) = get(web, "/api/v1/actions/01JNOSUCHTASK00000000000X", None).await;
    assert_eq!(status, 404);
}

/// The audit timeline is where a room's history is read, and a task event is
/// part of that history: the signed steps appear there with their verb, their
/// actor, their signed fields and the receipt the home wrote for them, under
/// the same filters every other row obeys.
#[tokio::test]
async fn the_audit_timeline_carries_the_channel_s_task_events() {
    let ka = PrivateKey::generate_ed25519();
    let kb = PrivateKey::generate_ed25519();
    let (irc, web, _h) = start(resolver_with(vec![(DID_ALICE, &ka), (DID_BOB, &kb)])).await;
    let (offer_id, accept_id, complete_id, bearer, _a, _b) =
        tokio::task::spawn_blocking(move || {
            let alice_key = SigningKey::from_bytes(&[21u8; 32]);
            let bob_key = SigningKey::from_bytes(&[22u8; 32]);
            let mut a = C::authenticated(irc, "alice", DID_ALICE, ka);
            a.msgsig(&alice_key);
            a.join("#work");
            let mut b = C::authenticated(irc, "bob", DID_BOB, kb);
            b.msgsig(&bob_key);
            b.join("#work");

            let venue = channel_venue("#work");
            let offer = a.offer_to("#work", &venue, DID_BOB, DID_ALICE, &alice_key);
            let accept = b.step("#work", &venue, &offer, "accept", DID_BOB, &bob_key);
            let complete = b.step("#work", &venue, &offer, "complete", DID_BOB, &bob_key);
            let bearer = a.bearer.clone();
            (offer, accept, complete, bearer, a, b)
        })
        .await
        .unwrap();

    let acts = |body: &serde_json::Value| -> Vec<serde_json::Value> {
        body["timeline"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["category"] == "act")
            .cloned()
            .collect()
    };

    let (status, body) = get(web, "/api/v1/channels/work/audit", Some(&bearer)).await;
    assert_eq!(status, 200);
    let rows = acts(&body);
    // One row per step somebody took. The two receipts this server minted are
    // not rows: each rides on the step it rules on.
    assert_eq!(
        rows.iter()
            .map(|r| r["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["offer", "accept", "complete"],
        "{body}"
    );
    assert_eq!(
        rows.iter()
            .map(|r| r["event_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![offer_id.as_str(), accept_id.as_str(), complete_id.as_str()]
    );
    for row in &rows {
        assert_eq!(row["details"]["act_id"], offer_id, "{row}");
        assert_eq!(row["details"]["kind"], "handoff", "{row}");
        assert_eq!(row["details"]["confirm_state"], "confirmed", "{row}");
        // Every row names its task, not only the one that opened it.
        assert_eq!(row["details"]["title"], "Cite 3 sources", "{row}");
    }
    assert_eq!(rows[0]["details"]["to"], DID_BOB);
    assert_eq!(rows[0]["actor_did"], DID_ALICE);
    assert_eq!(rows[1]["actor_did"], DID_BOB);

    // The offer was applied on arrival and no receipt was written for it; the
    // two steps that moved the task each carry theirs, with enough to check
    // the home's signature over the ruling itself.
    assert!(rows[0]["details"].get("receipt").is_none(), "{}", rows[0]);
    let steps = [offer_id.as_str(), accept_id.as_str(), complete_id.as_str()];
    for row in &rows[1..] {
        let receipt = &row["details"]["receipt"];
        let id = receipt["event_id"].as_str().unwrap_or_default();
        assert_eq!(id.len(), 26, "{row}");
        assert!(!steps.contains(&id), "a receipt has its own id: {row}");
        assert!(receipt["timestamp"].is_i64(), "{row}");
        assert!(!receipt["signature"].is_null(), "{row}");
    }

    // `actor` filters task rows the way it filters every other row — and a
    // step's receipt rides with it, though the receipt is the home's.
    let (status, only_bob) = get(
        web,
        &format!("/api/v1/channels/work/audit?actor={DID_BOB}"),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, 200);
    let bob_rows = acts(&only_bob);
    assert_eq!(
        bob_rows
            .iter()
            .map(|r| r["event_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        vec![accept_id.clone(), complete_id.clone()],
        "{only_bob}"
    );
    for row in &bob_rows {
        assert!(row["details"]["receipt"]["event_id"].is_string(), "{row}");
    }

    // So does `since`: a window that opens after the offer does not carry it.
    let offer_ts = rows[0]["timestamp"].as_i64().unwrap();
    let (status, later) = get(
        web,
        &format!("/api/v1/channels/work/audit?since={}", offer_ts + 1),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        !acts(&later)
            .iter()
            .any(|r| r["event_id"] == serde_json::json!(offer_id)),
        "{later}"
    );
}
