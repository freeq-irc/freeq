//! Adversarial SASL authentication tests.
//!
//! Tests the full challenge→sign→verify→authenticate state machine
//! with malicious inputs, wrong keys, expired challenges, mid-session
//! re-auth, and protocol violations.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};
use freeq_sdk::event::Event;

const DID_A: &str = "did:plc:sasl_test_alice";
const DID_B: &str = "did:plc:sasl_test_bob";

fn make_resolver(entries: Vec<(&str, &PrivateKey)>) -> DidResolver {
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
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-sasl".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

async fn start_short_timeout(
    resolver: DidResolver,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-sasl-short".to_string(),
        challenge_timeout_secs: 1, // 1 second!
        ..Default::default()
    };
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

// ── Raw TCP helper (same pattern as legacy_irc.rs) ──

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl C {
    fn raw(addr: SocketAddr) -> Self {
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
    /// Do CAP negotiation + NICK/USER, get challenge, return challenge string
    fn start_sasl(&mut self, nick: &str) -> String {
        self.tx("CAP LS 302");
        self.tx(&format!("NICK {nick}"));
        self.tx(&format!("USER {nick} 0 * :test"));
        self.tx("CAP REQ :sasl");
        self.rx(|l| l.contains("ACK"), "CAP ACK");
        self.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let auth_line = self.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        // Extract challenge (everything after "AUTHENTICATE ")
        auth_line
            .strip_prefix("AUTHENTICATE ")
            .unwrap_or(&auth_line)
            .to_string()
    }
}

async fn run(addr: SocketAddr, f: impl FnOnce(SocketAddr) + Send + 'static) {
    tokio::task::spawn_blocking(move || f(addr)).await.unwrap();
}

// ═══════════════════════════════════════════════════════════════
// HAPPY PATH: verify the SDK auth flow works
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sasl_ed25519_happy_path() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;

    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(DID_A.to_string(), key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "sasl_ed".to_string(),
        user: "sasl_ed".to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (_handle, mut events) = client::connect(config, Some(signer));
    let auth = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(e) = events.recv().await {
                if matches!(e, Event::Authenticated { .. }) {
                    return e;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(auth, Event::Authenticated { did } if did == DID_A));
}

#[tokio::test]
async fn sasl_secp256k1_happy_path() {
    let key = PrivateKey::generate_secp256k1();
    let resolver = make_resolver(vec![(DID_B, &key)]);
    let (addr, _h) = start(resolver).await;

    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(DID_B.to_string(), key));
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "sasl_secp".to_string(),
        user: "sasl_secp".to_string(),
        realname: "test".to_string(),
        ..Default::default()
    };
    let (_handle, mut events) = client::connect(config, Some(signer));
    let auth = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(e) = events.recv().await {
                if matches!(e, Event::Authenticated { .. }) {
                    return e;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(auth, Event::Authenticated { did } if did == DID_B));
}

// ═══════════════════════════════════════════════════════════════
// ADVERSARIAL: raw TCP SASL abuse
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sasl_garbage_base64_returns_904() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        c.start_sasl("garb");
        c.tx("AUTHENTICATE !!!not-valid-base64!!!");
        c.num("904"); // SASL failed
        // Should still be able to register as guest
        c.tx("CAP END");
        c.num("001"); // Registered
    })
    .await;
}

#[tokio::test]
async fn sasl_wrong_did_returns_904() {
    let key_a = PrivateKey::generate_ed25519();
    let key_b = PrivateKey::generate_ed25519();
    // Only DID_A in resolver, but signer uses DID that doesn't exist
    let resolver = make_resolver(vec![(DID_A, &key_a)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        let challenge = c.start_sasl("wrongdid");
        // Decode challenge bytes
        let challenge_bytes = auth::decode_challenge_bytes(&challenge).unwrap();
        // Sign with key_b but claim DID_A → signature won't verify against DID_A's key
        let signer = KeySigner::new(DID_A.to_string(), key_b);
        let response = signer.respond(&challenge_bytes).unwrap();
        let encoded = auth::encode_response(&response);
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("904"); // Signature doesn't match
    })
    .await;
}

#[tokio::test]
async fn sasl_unknown_did_returns_904() {
    let key = PrivateKey::generate_ed25519();
    // Resolver has NO DIDs — resolution will fail
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        let challenge = c.start_sasl("unknowndid");
        let challenge_bytes = auth::decode_challenge_bytes(&challenge).unwrap();
        let signer = KeySigner::new("did:plc:nonexistent".to_string(), key);
        let response = signer.respond(&challenge_bytes).unwrap();
        let encoded = auth::encode_response(&response);
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("904"); // DID resolution failed
    })
    .await;
}

#[tokio::test]
async fn sasl_three_failures_disconnect() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK failthree");
        c.tx("USER failthree 0 * :test");
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACP ACK");

        let bad_response = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "did": "did:plc:fake",
                    "signature": "AAAA"
                })
                .to_string()
                .as_bytes(),
            )
        };

        for i in 0..3 {
            c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
            c.rx(
                |l| l.starts_with("AUTHENTICATE "),
                &format!("challenge {i}"),
            );
            c.tx(&format!("AUTHENTICATE {bad_response}"));
            c.num("904");
        }
        // After 3rd failure, should get ERROR and disconnect
        let err = c.maybe(|l| l.starts_with("ERROR"), 2000);
        assert!(err.is_some(), "Should get ERROR after 3 SASL failures");
    })
    .await;
}

#[tokio::test]
async fn sasl_valid_after_one_failure() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK recover");
        c.tx("USER recover 0 * :test");
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACK");

        // First attempt: garbage → 904
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge 1");
        c.tx("AUTHENTICATE GARBAGE");
        c.num("904");

        // Second attempt: valid → 903 (success)
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let challenge = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge 2");
        let challenge_str = challenge.strip_prefix("AUTHENTICATE ").unwrap();
        let challenge_bytes = auth::decode_challenge_bytes(challenge_str).unwrap();
        let signer = KeySigner::new(DID_A.to_string(), key);
        let response = signer.respond(&challenge_bytes).unwrap();
        let encoded = auth::encode_response(&response);
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("903"); // SASL success
        c.tx("CAP END");
        c.num("001"); // Registered
    })
    .await;
}

/// A client that chunks its response may send the terminator whether or not
/// the last chunk already ended it, and released clients do exactly that. The
/// terminator arrives after 903, when no exchange is in progress.
#[tokio::test]
async fn sasl_trailing_terminator_after_success_is_ignored() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        let challenge_str = c.start_sasl("plustail");
        let challenge_bytes = auth::decode_challenge_bytes(&challenge_str).unwrap();
        let signer = KeySigner::new(DID_A.to_string(), key);
        let response = signer.respond(&challenge_bytes).unwrap();
        c.tx(&format!(
            "AUTHENTICATE {}",
            auth::encode_response(&response)
        ));
        c.num("903");

        c.tx("AUTHENTICATE +");
        assert!(
            c.maybe(|l| l.split_whitespace().nth(1) == Some("904"), 300)
                .is_none(),
            "a trailing terminator must not fail an authentication that succeeded"
        );

        // The connection is still usable.
        c.tx("CAP END");
        c.num("001");
    })
    .await;
}

#[tokio::test]
async fn sasl_challenge_expired() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    // 1-second timeout
    let (addr, _h) = start_short_timeout(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        let challenge = c.start_sasl("expired");
        // Wait for challenge to expire (1 second + margin)
        std::thread::sleep(Duration::from_secs(2));
        // Now respond with valid signature
        let challenge_bytes = auth::decode_challenge_bytes(&challenge).unwrap();
        let signer = KeySigner::new(DID_A.to_string(), key);
        let response = signer.respond(&challenge_bytes).unwrap();
        let encoded = auth::encode_response(&response);
        c.tx(&format!("AUTHENTICATE {encoded}"));
        // Should fail — challenge expired
        c.num("904");
    })
    .await;
}

#[tokio::test]
async fn sasl_challenge_replay() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        let challenge = c.start_sasl("replay");
        let challenge_bytes = auth::decode_challenge_bytes(&challenge).unwrap();
        let signer = KeySigner::new(DID_A.to_string(), key);
        let response = signer.respond(&challenge_bytes).unwrap();
        let encoded = auth::encode_response(&response);
        // First response — succeeds
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("903"); // Success

        // Try to re-authenticate with same response (replay)
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let _new_challenge = c.rx(|l| l.starts_with("AUTHENTICATE "), "new challenge");
        // Send the OLD response to the NEW challenge
        c.tx(&format!("AUTHENTICATE {encoded}"));
        // Should fail — signature is over the OLD challenge, not the new one
        c.num("904");
    })
    .await;
}

#[tokio::test]
async fn sasl_abort_with_star() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK aborttest");
        c.tx("USER aborttest 0 * :test");
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        // Abort with *
        c.tx("AUTHENTICATE *");
        c.num("904"); // SASL aborted
        // Should still be able to register as guest
        c.tx("CAP END");
        c.num("001");
    })
    .await;
}

#[tokio::test]
async fn sasl_authenticate_before_cap_req() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        // Send AUTHENTICATE without CAP REQ sasl first
        c.tx("NICK nocap");
        c.tx("USER nocap 0 * :test");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        // Should get a challenge anyway (server doesn't require CAP REQ)
        let result = c.maybe(
            |l| l.starts_with("AUTHENTICATE ") || l.split_whitespace().nth(1) == Some("904"),
            2000,
        );
        if let Some(line) = result {
            if line.starts_with("AUTHENTICATE ") {
                // Got challenge — sign it
                let challenge = line.strip_prefix("AUTHENTICATE ").unwrap();
                let challenge_bytes = auth::decode_challenge_bytes(challenge).unwrap();
                let signer = KeySigner::new(DID_A.to_string(), key);
                let response = signer.respond(&challenge_bytes).unwrap();
                c.tx(&format!(
                    "AUTHENTICATE {}",
                    auth::encode_response(&response)
                ));
                c.num("903"); // Should succeed even without CAP REQ
            }
        }
    })
    .await;
}

#[tokio::test]
async fn sasl_double_challenge_request() {
    let key = PrivateKey::generate_ed25519();
    let resolver = make_resolver(vec![(DID_A, &key)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK dblchal");
        c.tx("USER dblchal 0 * :test");
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACK");

        // Request challenge twice — second should replace first
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge 1");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let challenge2 = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge 2");

        // Sign challenge2 (the current one)
        let ch2 = challenge2.strip_prefix("AUTHENTICATE ").unwrap();
        let ch2_bytes = auth::decode_challenge_bytes(ch2).unwrap();
        let signer = KeySigner::new(DID_A.to_string(), key);
        let response = signer.respond(&ch2_bytes).unwrap();
        c.tx(&format!(
            "AUTHENTICATE {}",
            auth::encode_response(&response)
        ));
        c.num("903"); // Should succeed with second challenge
    })
    .await;
}

#[tokio::test]
async fn sasl_response_with_empty_did() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        let _challenge = c.start_sasl("emptydid");
        // Craft a response with empty DID
        use base64::Engine;
        let resp = serde_json::json!({"did": "", "signature": "AAAA"});
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&resp).unwrap());
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("904"); // Invalid DID format
    })
    .await;
}

#[tokio::test]
async fn sasl_response_with_invalid_did_format() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        let _challenge = c.start_sasl("baddid");
        use base64::Engine;
        let resp = serde_json::json!({"did": "not-a-did", "signature": "AAAA"});
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&resp).unwrap());
        c.tx(&format!("AUTHENTICATE {encoded}"));
        c.num("904"); // Invalid DID format (doesn't start with "did:")
    })
    .await;
}

#[tokio::test]
async fn sasl_empty_authenticate_parameter() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK emptyauth");
        c.tx("USER emptyauth 0 * :test");
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        // Send AUTHENTICATE with empty parameter
        c.tx("AUTHENTICATE ");
        // Should get 904 or be silently ignored
        let _ = c.maybe(|l| l.split_whitespace().nth(1) == Some("904"), 1000);
        // Either way, should be able to continue
        c.tx("CAP END");
        c.num("001");
    })
    .await;
}

#[tokio::test]
async fn guest_can_register_without_sasl() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        // No CAP negotiation at all — pure legacy IRC
        c.tx("NICK pureguest");
        c.tx("USER pureguest 0 * :test");
        c.num("001");
    })
    .await;
}

#[tokio::test]
async fn cap_end_without_sasl_registers_as_guest() {
    let resolver = make_resolver(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut c = C::raw(addr);
        c.tx("CAP LS 302");
        c.tx("NICK capguest");
        c.tx("USER capguest 0 * :test");
        // Request SASL cap but never AUTHENTICATE — just CAP END
        c.tx("CAP REQ :sasl");
        c.rx(|l| l.contains("ACK"), "ACK");
        c.tx("CAP END");
        c.num("001"); // Registered as guest
    })
    .await;
}
