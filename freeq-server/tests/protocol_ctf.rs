//! Adversarial tests for the IRC protocol surface — round 3 CTF.
//!
//! Findings:
//!
//! - **CTF-19 (HIGH)**: pre-key bundle hijacking via `/api/v1/keys`.
//!   The endpoint requires zero caller auth — only checks "is the
//!   named DID logged in *somewhere* on this server". An anonymous
//!   attacker can replace any online user's E2EE pre-key bundle,
//!   then receive their next DMs in plaintext. Persisted to DB so
//!   it outlives the victim's disconnect.
//!
//! - **CTF-20 (MED)**: unbounded coordination-event payload. Any
//!   authenticated user can store arbitrarily large `+freeq.at/event`
//!   payloads into the DB via TAGMSG with `+freeq.at/payload=…`.
//!   Disk-exhaustion DoS by an authenticated user.
//!
//! - **CTF-21 (MED)**: channel `+E` enforces only that the
//!   `+encrypted` tag is present, not that the body is actually
//!   ciphertext. A malicious client can send `@+encrypted PRIVMSG
//!   #ch :plaintext-leak` and bypass the encryption invariant —
//!   logger bots that don't decrypt see plaintext.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

use freeq_server::server::{ChannelState, SharedState};

const DID_VICTIM: &str = "did:plc:ctfvictim";
const DID_ATTACKER: &str = "did:plc:ctfattacker";

// ─── Fixtures ───────────────────────────────────────────────────────────

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

async fn start(
    resolver: DidResolver,
) -> (
    SocketAddr,
    SocketAddr,
    Arc<SharedState>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let tmp = tempfile::Builder::new()
        .prefix("freeq-protocol-ctf-")
        .suffix(".db")
        .tempfile()
        .unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "protocol-ctf".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    let (irc, web, handle, state) = server.start_with_web_state().await.unwrap();
    (irc, web, state, handle)
}

// ─── Raw IRC client ─────────────────────────────────────────────────────

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl C {
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
        c.tx("CAP REQ :sasl message-tags server-time echo-message");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let challenge_line = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let challenge = challenge_line.strip_prefix("AUTHENTICATE ").unwrap();
        let bytes = auth::decode_challenge_bytes(challenge).unwrap();
        let signer = KeySigner::new(did.to_string(), key);
        let resp = signer.respond(&bytes).unwrap();
        c.tx(&format!("AUTHENTICATE {}", auth::encode_response(&resp)));
        c.rx(|l| l.contains(" 903 "), "SASL success");
        c.tx("CAP END");
        c.rx(|l| l.contains(" 001 "), "registered");
        c
    }
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
        c.tx("CAP REQ :message-tags server-time echo-message");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c.rx(|l| l.contains(" 001 "), "registered");
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
                    if p(l) {
                        return l.to_string();
                    }
                }
                Err(e) => panic!("read err: {e:?}: {d}"),
            }
        }
    }
    /// Like rx but with a hard deadline; returns None on timeout.
    fn maybe(&mut self, p: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        let mut b = String::new();
        loop {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            b.clear();
            match self.reader.read_line(&mut b) {
                Ok(0) => return None,
                Ok(_) => {
                    let l = b.trim_end();
                    if p(l) {
                        return Some(l.to_string());
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

// ─── CTF-19: pre-key bundle hijacking ────────────────────────────────────

#[tokio::test]
async fn ctf_19_unauthenticated_attacker_cannot_overwrite_anothers_prekey_bundle() {
    let victim_key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_VICTIM, &victim_key)]);
    let (irc, web, _, _h) = start(resolver).await;

    // 1. Victim authenticates so the server has a session_dids entry
    //    for them. (The bug is that the upload endpoint considers
    //    "anyone-logged-in-as-this-DID" sufficient — even when the
    //    upload itself comes from an unauthenticated stranger.)
    let irc_addr = irc;
    let _victim = tokio::task::spawn_blocking(move || {
        C::with_sasl(irc_addr, "victim", DID_VICTIM, victim_key)
    })
    .await
    .unwrap();

    // 2. Attacker uploads a malicious bundle for the victim's DID,
    //    with no auth header at all.
    let evil_bundle = serde_json::json!({
        "identity_key": "EVIL_ATTACKER_KEY",
        "signed_pre_key": "EVIL_SPK",
        "spk_signature": "EVIL_SIG",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{web}/api/v1/keys"))
        .json(&serde_json::json!({
            "did": DID_VICTIM,
            "bundle": evil_bundle,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();

    // 3. Read back the stored bundle.
    let stored: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{web}/api/v1/keys/{DID_VICTIM}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or_default();

    // After fix: the upload must be REFUSED (anonymous attacker has no
    // proof they own the DID) — 401 or 403. The stored bundle (if
    // there is one) must NOT contain the evil payload.
    assert!(
        status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN,
        "CTF-19: anonymous /api/v1/keys upload for someone else's DID must be \
         refused with 401/403; got {status}. This is E2EE confidentiality — an \
         attacker who hijacks the bundle receives the victim's next DMs in \
         plaintext."
    );
    let stored_str = serde_json::to_string(&stored).unwrap_or_default();
    assert!(
        !stored_str.contains("EVIL_ATTACKER_KEY"),
        "CTF-19: server stored the attacker's bundle anyway. Pre-key API \
         must verify that the *requesting connection* is the named DID \
         (Bearer session id → DID), not just that the DID is logged in \
         somewhere. Stored bundle: {stored_str}"
    );
}

// ─── CTF-20: TAGMSG event-storage flood ────────────────────────────────

#[tokio::test]
async fn ctf_20_tagmsg_event_storage_is_rate_limited() {
    // PRIVMSG has a per-session 5-msgs-per-2s flood cap. TAGMSG does
    // not — and since TAGMSG with `+freeq.at/event=…` writes a row to
    // the coordination_events table, an authenticated user can spam
    // hundreds of TAGMSGs per second to fill the DB.
    let key = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ATTACKER, &key)]);
    let (irc_addr, _web, _state, _h) = start(resolver).await;

    let irc = irc_addr;
    let saw_throttle = tokio::task::spawn_blocking(move || {
        let mut c = C::with_sasl(irc, "spammer", DID_ATTACKER, key);
        // Spam 30 event TAGMSGs with no pause. After the fix the
        // server should send a FAIL line for at least one of them
        // (rate-limited) — currently all 30 succeed silently.
        for i in 0..30 {
            c.tx(&format!(
                "@+freeq.at/event=spam;+freeq.at/payload=p;msgid=01HZX5MK0WJYM3MQRJSP3K1X{:02X} TAGMSG #freeq",
                i
            ));
        }
        // Drain for ~600 ms looking for ANY FAIL / RATE / 404.
        c.maybe(
            |l| {
                l.contains("FAIL") || l.contains("RATE") || l.contains("flood") || l.contains(" 404 ")
            },
            600,
        )
    })
    .await
    .unwrap();

    assert!(
        saw_throttle.is_some(),
        "CTF-20: TAGMSG event-storage must be rate-limited per session. \
         Currently 30 events/sec all silently store to the DB — \
         disk-exhaustion DoS by an authenticated user."
    );
}

// ─── CTF-21: +E mode body validation ────────────────────────────────────

#[tokio::test]
async fn ctf_21_plus_e_channel_rejects_plaintext_with_encrypted_tag() {
    let resolver = resolver_with(vec![]);
    let (irc_addr, _web, state, _h) = start(resolver).await;

    // Plant an encrypted-only channel (+E) with one member.
    {
        let mut channels = state.channels.lock();
        let mut members = HashSet::new();
        members.insert("ctf-fixture-session".to_string());
        channels.insert(
            "#secret".to_string(),
            ChannelState {
                members,
                remote_members: HashMap::new(),
                ops: HashSet::new(),
                halfops: HashSet::new(),
                voiced: HashSet::new(),
                founder_did: None,
                did_ops: HashSet::new(),
                created_at: 0,
                bans: vec![],
                invite_only: false,
                invites: HashSet::new(),
                invite_exceptions: vec![],
                history: std::collections::VecDeque::new(),
                topic: None,
                topic_locked: false,
                no_ext_msg: false,
                moderated: false,
                encrypted_only: true,
                key: None,
                pins: vec![],
                media_space_key: None,
            },
        );
    }

    let irc = irc_addr;
    let result = tokio::task::spawn_blocking(move || {
        let mut c = C::with_caps(irc, "attacker");
        c.tx("JOIN #secret");
        c.rx(|l| l.contains("JOIN") && l.contains("#secret"), "joined");
        // Send PRIVMSG with `+encrypted` tag set but a plaintext body
        // (NO ENC1: prefix). The server currently accepts because it
        // only checks tag presence; a logger bot would log "leaked
        // plaintext" thinking it was opaque ciphertext.
        c.tx("@+encrypted PRIVMSG #secret :leaked plaintext");
        // After the fix: server should send a FAIL / 404 for not
        // matching the ENC1: prefix. (Empty plaintext after the tag,
        // or non-ENC1 prefix, both invalid.)
        c.maybe(
            |l| {
                l.contains(" 404 ")
                    || l.contains("FAIL")
                    || l.contains("not encrypted")
                    || l.contains("ENC1")
            },
            500,
        )
    })
    .await
    .unwrap();

    assert!(
        result.is_some(),
        "CTF-21: server must reject PRIVMSG to +E channel when the body is not \
         ENC1-prefixed ciphertext, even when the +encrypted tag is present. \
         Otherwise a malicious client can leak plaintext to clients/loggers \
         that don't decrypt and just log the body."
    );
}
