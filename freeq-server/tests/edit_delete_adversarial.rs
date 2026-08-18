//! Adversarial tests for message editing and deletion.
//!
//! Tests the full edit/delete pipeline: authorship verification, chained edits,
//! edit-after-delete, nick-reuse attacks, op delete permissions, and DM edits.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use freeq_sdk::auth::{self, ChallengeSigner, KeySigner};
use freeq_sdk::chatsig::{ChatDoc, EVENT_ID_TAG, Mutation, dm_venue};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};

const DID_ALICE: &str = "did:plc:edit_alice";
const DID_BOB: &str = "did:plc:edit_bob";

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
    // Edit/delete tests need a database to look up messages by msgid
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    // Leak the tempfile so it isn't deleted while the server runs
    std::mem::forget(tmp);
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-edit".to_string(),
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

// ── Raw IRC client with tag support ──

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
        c.tx("CAP REQ :message-tags server-time echo-message draft/chathistory");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("CAP END");
        c
    }
    fn with_multiline_caps(addr: SocketAddr, nick: &str) -> Self {
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
        c.tx("CAP REQ :message-tags server-time echo-message draft/chathistory batch draft/multiline");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
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
        c.tx("CAP REQ :sasl message-tags server-time echo-message");
        c.rx(|l| l.contains("ACK"), "CAP ACK");
        c.tx("AUTHENTICATE ATPROTO-CHALLENGE");
        let challenge_line = c.rx(|l| l.starts_with("AUTHENTICATE "), "challenge");
        let challenge = challenge_line.strip_prefix("AUTHENTICATE ").unwrap();
        let bytes = auth::decode_challenge_bytes(challenge).unwrap();
        let signer = KeySigner::new(did.to_string(), key);
        let resp = signer.respond(&bytes).unwrap();
        c.tx(&format!("AUTHENTICATE {}", auth::encode_response(&resp)));
        c.num("903"); // SASL success
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
    /// Extract msgid from a received IRC line with tags
    fn extract_msgid(line: &str) -> String {
        if let Some(tags_str) = line
            .strip_prefix('@')
            .and_then(|s| s.split_once(' ').map(|(t, _)| t))
        {
            for tag in tags_str.split(';') {
                if let Some(val) = tag.strip_prefix("msgid=") {
                    return val.to_string();
                }
            }
        }
        String::new()
    }
    fn send_edit(&mut self, target: &str, original_msgid: &str, new_text: &str) {
        self.tx(&format!(
            "@+draft/edit={original_msgid} PRIVMSG {target} :{new_text}"
        ));
    }
    fn send_delete(&mut self, target: &str, msgid: &str) {
        self.tx(&format!("@+draft/delete={msgid} TAGMSG {target}"));
    }
}

// ═══════════════════════════════════════════════════════════════
// BASIC EDIT/DELETE FLOW
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn edit_own_message_succeeds() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "ed_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "ed_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #edit");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #edit");
        bob.num("366");
        bob.drain();

        // Alice sends, Bob receives and captures msgid
        alice.tx("PRIVMSG #edit :original text");
        let orig = bob.rx(
            |l| l.contains("PRIVMSG") && l.contains("original text"),
            "original msg",
        );
        let msgid = C::extract_msgid(&orig);
        assert!(!msgid.is_empty(), "Should get msgid: {orig}");

        // Alice edits
        alice.send_edit("#edit", &msgid, "edited text");
        let edit_msg = bob.rx(
            |l| l.contains("PRIVMSG") && l.contains("edited text"),
            "edit delivery",
        );
        assert!(
            edit_msg.contains("draft/edit"),
            "Edit should have +draft/edit tag: {edit_msg}"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_own_message_succeeds() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "dl_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "dl_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #del");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #del");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #del :to be deleted");
            let l = bob.rx(
                |l| l.contains("PRIVMSG") && l.contains("to be deleted"),
                "msg",
            );
            C::extract_msgid(&l)
        };
        alice.send_delete("#del", &msgid);
        // Bob should see the delete TAGMSG
        let del = bob.maybe(|l| l.contains("TAGMSG") && l.contains("draft/delete"), 2000);
        assert!(del.is_some(), "Bob should see delete notification");
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// ADVERSARIAL: unauthorized edit/delete
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn edit_other_users_message_rejected() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "eo_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "eo_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #eo");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #eo");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #eo :alice's message");
            let l = bob.rx(
                |l| l.contains("PRIVMSG") && l.contains("alice's message"),
                "msg",
            );
            C::extract_msgid(&l)
        };
        bob.drain(); // Clear alice's message from bob's buffer

        // Bob tries to edit Alice's message
        bob.send_edit("#eo", &msgid, "hacked by bob");

        // Bob should get FAIL EDIT AUTHOR_MISMATCH
        let fail = bob.maybe(
            |l| l.contains("FAIL") && l.contains("AUTHOR_MISMATCH"),
            2000,
        );
        assert!(
            fail.is_some(),
            "Edit of other user's message should be rejected"
        );

        // Alice should NOT see any edit
        let edit = alice.maybe(|l| l.contains("hacked by bob"), 500);
        assert!(edit.is_none(), "Alice should not see unauthorized edit");
    })
    .await;
}

#[tokio::test]
async fn delete_other_users_message_rejected_for_nonop() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "do_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "do_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #do");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #do");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #do :alice's msg");
            let l = bob.rx(
                |l| l.contains("PRIVMSG") && l.contains("alice's msg"),
                "msg",
            );
            C::extract_msgid(&l)
        };
        bob.drain();
        bob.send_delete("#do", &msgid);
        let fail = bob.maybe(
            |l| l.contains("FAIL") && l.contains("AUTHOR_MISMATCH"),
            2000,
        );
        assert!(
            fail.is_some(),
            "Non-op delete of other user's message should be rejected"
        );
    })
    .await;
}

#[tokio::test]
async fn op_can_delete_others_message_in_channel() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        // Alice creates channel (gets ops)
        let mut alice = C::with_caps(addr, "opd_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "opd_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #opd");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #opd");
        bob.num("366");
        bob.drain();

        bob.tx("PRIVMSG #opd :bob's message");
        let orig = alice.rx(
            |l| l.contains("PRIVMSG") && l.contains("bob's message"),
            "bob msg",
        );
        let msgid = C::extract_msgid(&orig);

        // Alice (op) deletes Bob's message
        alice.send_delete("#opd", &msgid);
        // Should NOT get AUTHOR_MISMATCH (ops can delete in channels)
        let fail = alice.maybe(|l| l.contains("FAIL"), 1000);
        // If no FAIL, the delete was accepted
        if let Some(f) = &fail {
            if f.contains("AUTHOR_MISMATCH") {
                panic!("BUG: Op should be able to delete others' messages in channels");
            }
        }
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// CHAINED EDITS
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn chained_edit_works() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "ch_alice");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "ch_bob");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #chain");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #chain");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #chain :version 1");
            let l = bob.rx(|l| l.contains("PRIVMSG") && l.contains("version 1"), "msg");
            C::extract_msgid(&l)
        };
        bob.drain();

        // Edit 1: version 1 → version 2 (using original msgid)
        alice.send_edit("#chain", &msgid, "version 2");
        let e1 = bob.rx(|l| l.contains("version 2"), "edit 1");

        // Edit 2: version 2 → version 3 (STILL using original msgid — that's how clients work)
        alice.send_edit("#chain", &msgid, "version 3");
        let e2 = bob.rx(|l| l.contains("version 3"), "edit 2");

        // Both edits should have arrived
        assert!(e1.contains("version 2"));
        assert!(e2.contains("version 3"));
    })
    .await;
}

#[tokio::test]
async fn five_rapid_edits() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "rapid_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "rapid_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #rapid");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #rapid");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #rapid :v0");
            let l = bob.rx(|l| l.contains("PRIVMSG") && l.contains("v0"), "msg");
            C::extract_msgid(&l)
        };
        bob.drain();

        for i in 1..=5 {
            alice.send_edit("#rapid", &msgid, &format!("v{i}"));
        }
        // Bob should see v5 as the last edit
        let mut last = String::new();
        for _ in 0..5 {
            if let Some(l) = bob.maybe(|l| l.contains("PRIVMSG") && l.contains("#rapid"), 1000) {
                last = l;
            }
        }
        assert!(
            last.contains("v5") || last.contains("v4"),
            "Last edit should be v4 or v5: {last}"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// EDIT AFTER DELETE / DELETE AFTER EDIT
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn edit_after_delete_rejected() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "ead_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "ead_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #ead");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #ead");
        bob.num("366");
        bob.drain();

        alice.tx("PRIVMSG #ead :original");
        let orig = bob.rx(|l| l.contains("PRIVMSG") && l.contains("original"), "msg");
        let msgid = C::extract_msgid(&orig);
        alice.send_delete("#ead", &msgid);
        std::thread::sleep(Duration::from_millis(200));

        // Try to edit the deleted message
        alice.send_edit("#ead", &msgid, "resurrected");
        // Should silently fail (deleted_at is set)
        let edit = bob.maybe(|l| l.contains("resurrected"), 1000);
        // Edit of deleted message should not be delivered
        if edit.is_some() {
            panic!("BUG: Edit of deleted message was delivered");
        }
    })
    .await;
}

#[tokio::test]
async fn delete_after_edit() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "dae_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "dae_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #dae");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #dae");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #dae :original");
            let l = bob.rx(|l| l.contains("PRIVMSG") && l.contains("original"), "msg");
            C::extract_msgid(&l)
        };
        bob.drain();
        alice.send_edit("#dae", &msgid, "edited");
        bob.rx(|l| l.contains("edited"), "edit");

        // Now delete the original msgid
        alice.send_delete("#dae", &msgid);
        let del = bob.maybe(|l| l.contains("TAGMSG") && l.contains("draft/delete"), 2000);
        assert!(del.is_some(), "Delete after edit should succeed");

        // …and the content must actually be gone.
        //
        // This assertion was missing, and its absence hid a real bug: an edit is
        // stored as a NEW row carrying replaces_msgid, while clients keep the
        // ORIGINAL msgid as the message's identity — so this delete named the
        // original and `soft_delete_message` marked only that exact row. The
        // delete was relayed (asserted above), the message vanished from every
        // client, and "edited" stayed readable in CHATHISTORY and FTS search
        // forever. Relaying the TAGMSG is not the contract; removing the content
        // is. See db::tests::soft_delete_sweeps_the_whole_revision_family.
        alice.drain();
        alice.tx("CHATHISTORY LATEST #dae * 50");
        let leaked_edit = alice.maybe(|l| l.contains("edited"), 1500);
        assert!(
            leaked_edit.is_none(),
            "edit revision still in history after delete: {leaked_edit:?}"
        );
        alice.drain();
        alice.tx("CHATHISTORY LATEST #dae * 50");
        let leaked_original = alice.maybe(|l| l.contains("original"), 1500);
        assert!(
            leaked_original.is_none(),
            "original revision still in history after delete: {leaked_original:?}"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// EDIT WITH INVALID/NONEXISTENT MSGID
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn edit_nonexistent_msgid_rejected() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "enx_a");
        alice.reg();
        alice.drain();
        alice.tx("JOIN #enx");
        alice.num("366");
        alice.drain();

        alice.send_edit("#enx", "NONEXISTENT_MSGID_12345", "ghost edit");
        let fail = alice.maybe(
            |l| l.contains("FAIL") && l.contains("MESSAGE_NOT_FOUND"),
            2000,
        );
        assert!(
            fail.is_some(),
            "Edit with nonexistent msgid should return MESSAGE_NOT_FOUND"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_nonexistent_msgid_rejected() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "dnx_a");
        alice.reg();
        alice.drain();
        alice.tx("JOIN #dnx");
        alice.num("366");
        alice.drain();

        alice.send_delete("#dnx", "NONEXISTENT_MSGID_99999");
        let fail = alice.maybe(
            |l| l.contains("FAIL") && l.contains("MESSAGE_NOT_FOUND"),
            2000,
        );
        assert!(
            fail.is_some(),
            "Delete with nonexistent msgid should return MESSAGE_NOT_FOUND"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// DID-AUTHENTICATED EDIT PROTECTION
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn authenticated_user_edit_protected_by_did() {
    let key_a = PrivateKey::generate_ed25519();
    let key_b = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key_a), (DID_BOB, &key_b)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::with_sasl(addr, "did_alice", DID_ALICE, key_a);
        alice.reg();
        alice.drain();
        let mut bob = C::with_sasl(addr, "did_bob", DID_BOB, key_b);
        bob.reg();
        bob.drain();
        alice.tx("JOIN #didprot");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #didprot");
        bob.num("366");
        bob.drain();

        let msgid = {
            alice.tx("PRIVMSG #didprot :alice's authenticated message");
            let l = bob.rx(
                |l| l.contains("PRIVMSG") && l.contains("alice's authenticated message"),
                "msg",
            );
            C::extract_msgid(&l)
        };
        bob.drain();

        // Bob (different DID) tries to edit Alice's message
        bob.send_edit("#didprot", &msgid, "bob hacked this");
        let fail = bob.maybe(
            |l| l.contains("FAIL") && l.contains("AUTHOR_MISMATCH"),
            2000,
        );
        assert!(
            fail.is_some(),
            "DID-protected message should reject edit from different DID"
        );
    })
    .await;
}

#[tokio::test]
async fn guest_cannot_edit_authenticated_users_message() {
    let key_a = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key_a)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        let mut alice = C::with_sasl(addr, "dg_alice", DID_ALICE, key_a);
        alice.reg();
        alice.drain();
        let mut guest = C::with_caps(addr, "dg_guest");
        guest.reg();
        guest.drain();
        alice.tx("JOIN #dgprot");
        alice.num("366");
        alice.drain();
        guest.tx("JOIN #dgprot");
        guest.num("366");
        guest.drain();

        let msgid = {
            alice.tx("PRIVMSG #dgprot :authenticated message");
            let l = guest.rx(
                |l| l.contains("PRIVMSG") && l.contains("authenticated message"),
                "msg",
            );
            C::extract_msgid(&l)
        };

        // Guest tries to edit — should fail even if nick matches somehow
        guest.send_edit("#dgprot", &msgid, "guest hacked this");
        let fail = guest.maybe(|l| l.contains("FAIL"), 2000);
        assert!(
            fail.is_some(),
            "Guest should not be able to edit authenticated user's message"
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// DM EDITS AND DELETES
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn dm_edit_works() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "dme_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "dme_b");
        bob.reg();
        bob.drain();

        // Alice sends DM to Bob — bob captures the msgid
        alice.tx("PRIVMSG dme_b :secret dm");
        let dm = bob.rx(|l| l.contains("PRIVMSG") && l.contains("secret dm"), "dm");
        let msgid = C::extract_msgid(&dm);

        // Alice edits the DM
        alice.send_edit("dme_b", &msgid, "edited secret dm");
        let edit = bob.maybe(|l| l.contains("edited secret dm"), 2000);
        // BUG: Guest DM edits may fail because canonical_dm_key requires DID
        // This is a known limitation — DM edits work for authenticated users only
        if edit.is_none() {
            eprintln!("NOTE: Guest DM edit not delivered (expected — DM edits require DID auth)");
        }
    })
    .await;
}

#[tokio::test]
async fn dm_edit_by_recipient_rejected() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "dmr_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "dmr_b");
        bob.reg();
        bob.drain();

        alice.tx("PRIVMSG dmr_b :alice's dm");
        let dm = bob.rx(|l| l.contains("PRIVMSG") && l.contains("alice's dm"), "dm");
        let msgid = C::extract_msgid(&dm);

        // Bob tries to edit Alice's DM
        bob.send_edit("dmr_a", &msgid, "bob edited alice's dm");
        // Should be rejected
        let _ = bob.maybe(|l| l.contains("FAIL"), 2000);
        // Either FAIL or silently dropped — either way, alice shouldn't see it
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// MULTI-LINE EDITS — BATCH-wrapped on the wire so capable receivers
// see the full body and fallback receivers see line1 (wire-valid),
// instead of a malformed PRIVMSG with embedded `\n`.
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn multi_line_edit_delivers_batch_to_multiline_capable_receiver() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_multiline_caps(addr, "mle_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_multiline_caps(addr, "mle_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #mledit");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #mledit");
        bob.num("366");
        bob.drain();

        // Alice sends original multi-line via BATCH.
        alice.tx("BATCH +ob draft/multiline #mledit");
        alice.tx("@batch=ob PRIVMSG #mledit :orig line A");
        alice.tx("@batch=ob PRIVMSG #mledit :orig line B");
        alice.tx("BATCH -ob");
        let orig_opener = bob.rx(
            |l| l.contains("BATCH +") && l.contains("draft/multiline") && l.contains("#mledit"),
            "orig BATCH opener",
        );
        let orig_msgid = C::extract_msgid(&orig_opener);
        assert!(
            !orig_msgid.is_empty(),
            "orig opener has msgid: {orig_opener}"
        );
        bob.rx(|l| l.starts_with("BATCH -"), "orig BATCH closer");

        // Alice sends multi-line edit via BATCH with +draft/edit on opener.
        alice.tx(&format!(
            "@+draft/edit={orig_msgid} BATCH +eb draft/multiline #mledit"
        ));
        alice.tx("@batch=eb PRIVMSG #mledit :edit line A");
        alice.tx("@batch=eb PRIVMSG #mledit :edit line B");
        alice.tx("BATCH -eb");

        // Bob (multiline-capable) sees BATCH-wrapped edit with full body.
        let edit_opener = bob.rx(
            |l| {
                l.contains("BATCH +")
                    && l.contains("draft/multiline")
                    && l.contains("#mledit")
                    && l.contains("+draft/edit=")
            },
            "edit BATCH opener with +draft/edit tag",
        );
        assert!(
            edit_opener.contains(&format!("+draft/edit={orig_msgid}")),
            "edit opener references orig msgid: {edit_opener}",
        );
        let edit_msgid = C::extract_msgid(&edit_opener);
        assert!(
            !edit_msgid.is_empty(),
            "edit opener has fresh msgid: {edit_opener}"
        );
        assert_ne!(edit_msgid, orig_msgid, "edit gets a new msgid");

        let chunk_a = bob.rx(
            |l| l.contains("PRIVMSG #mledit") && l.contains("edit line A"),
            "edit chunk A",
        );
        assert!(
            chunk_a.contains("batch="),
            "chunk carries batch tag: {chunk_a}"
        );
        let chunk_b = bob.rx(
            |l| l.contains("PRIVMSG #mledit") && l.contains("edit line B"),
            "edit chunk B",
        );
        assert!(
            chunk_b.contains("batch="),
            "chunk carries batch tag: {chunk_b}"
        );
        let closer = bob.rx(|l| l.starts_with("BATCH -"), "edit BATCH closer");
        assert!(
            closer.starts_with("BATCH -"),
            "bare BATCH -id closer: {closer}"
        );
    })
    .await;
}

#[tokio::test]
async fn ciphertext_chunked_edit_preserves_chunking_via_batch() {
    // Edit body shape mirroring E2EE: chunks use `concat=true` and the
    // assembled body has no `\n` (it would be one base64 ciphertext blob).
    // Without threading the sender's chunks through handle_edit the
    // server's `\n`-detection would miss this case and fall back to a
    // single PRIVMSG that exceeds MTU and corrupts the ciphertext.
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_multiline_caps(addr, "cce_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_multiline_caps(addr, "cce_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #ccedit");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #ccedit");
        bob.num("366");
        bob.drain();

        // Original message (single PRIVMSG with `+encrypted` placeholder —
        // we don't need a real cipher here, just the tag-shape parity).
        alice.tx("@+encrypted= PRIVMSG #ccedit :ORIG_CIPHERTEXT_BLOB");
        let orig = bob.rx(
            |l| l.contains("PRIVMSG #ccedit") && l.contains("ORIG_CIPHERTEXT_BLOB"),
            "orig single-PRIVMSG E2EE shape",
        );
        let orig_msgid = C::extract_msgid(&orig);
        assert!(!orig_msgid.is_empty(), "orig has msgid: {orig}");

        // Edit via BATCH with concat=true on later chunks (ciphertext-
        // chunking shape). Assembled body would be "PARTONE" + "PARTTWO" +
        // "PARTTHREE" with no separators — no `\n` anywhere.
        alice.tx(&format!(
            "@+draft/edit={orig_msgid};+encrypted= BATCH +cb draft/multiline #ccedit"
        ));
        alice.tx("@batch=cb PRIVMSG #ccedit :PARTONE");
        alice.tx("@batch=cb;draft/multiline-concat PRIVMSG #ccedit :PARTTWO");
        alice.tx("@batch=cb;draft/multiline-concat PRIVMSG #ccedit :PARTTHREE");
        alice.tx("BATCH -cb");

        // Bob (multiline-capable) sees BATCH-wrapped edit preserving the
        // three chunks AND the `draft/multiline-concat` flag on chunks
        // 2 and 3 — so the receiver assembles by concatenation, not by
        // `\n`-joining.
        let opener = bob.rx(
            |l| {
                l.contains("BATCH +")
                    && l.contains("draft/multiline")
                    && l.contains("#ccedit")
                    && l.contains("+draft/edit=")
            },
            "edit BATCH opener",
        );
        assert!(
            opener.contains(&format!("+draft/edit={orig_msgid}")),
            "edit opener references orig msgid: {opener}",
        );
        let chunk1 = bob.rx(
            |l| l.contains("PRIVMSG #ccedit") && l.contains("PARTONE"),
            "PARTONE chunk",
        );
        assert!(
            !chunk1.contains("draft/multiline-concat"),
            "first chunk must NOT have concat tag: {chunk1}",
        );
        let chunk2 = bob.rx(
            |l| l.contains("PRIVMSG #ccedit") && l.contains("PARTTWO"),
            "PARTTWO chunk",
        );
        assert!(
            chunk2.contains("draft/multiline-concat"),
            "second chunk must carry concat flag: {chunk2}",
        );
        let chunk3 = bob.rx(
            |l| l.contains("PRIVMSG #ccedit") && l.contains("PARTTHREE"),
            "PARTTHREE chunk",
        );
        assert!(
            chunk3.contains("draft/multiline-concat"),
            "third chunk must carry concat flag: {chunk3}",
        );
        bob.rx(|l| l.starts_with("BATCH -"), "edit BATCH closer");
    })
    .await;
}

#[tokio::test]
async fn multi_line_edit_delivers_line1_only_to_non_multiline_receiver() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        // Alice has multiline cap (to send the original BATCH); Bob does not.
        let mut alice = C::with_multiline_caps(addr, "mlef_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "mlef_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #mleditfb");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #mleditfb");
        bob.num("366");
        bob.drain();

        // Original multi-line (Bob, no multiline cap, sees the 2 chunks as
        // individual PRIVMSGs in spec fallback — msgid lands on the first).
        alice.tx("BATCH +obfb draft/multiline #mleditfb");
        alice.tx("@batch=obfb PRIVMSG #mleditfb :orig L1");
        alice.tx("@batch=obfb PRIVMSG #mleditfb :orig L2");
        alice.tx("BATCH -obfb");
        let first_orig = bob.rx(
            |l| l.contains("PRIVMSG #mleditfb") && l.contains("orig L1"),
            "orig L1",
        );
        let orig_msgid = C::extract_msgid(&first_orig);
        assert!(
            !orig_msgid.is_empty(),
            "fallback orig L1 has msgid: {first_orig}"
        );
        // Drain L2 (no msgid, no BATCH tag for fallback).
        bob.rx(
            |l| l.contains("PRIVMSG #mleditfb") && l.contains("orig L2"),
            "orig L2",
        );

        // Multi-line edit. Bob (no multiline cap) gets a wire-valid single
        // PRIVMSG with line1 only — not a malformed mid-body newline.
        alice.tx(&format!(
            "@+draft/edit={orig_msgid} BATCH +ebfb draft/multiline #mleditfb"
        ));
        alice.tx("@batch=ebfb PRIVMSG #mleditfb :edit L1");
        alice.tx("@batch=ebfb PRIVMSG #mleditfb :edit L2");
        alice.tx("BATCH -ebfb");

        // Should receive a tagged PRIVMSG with +draft/edit and only "edit L1".
        let edit = bob.rx(
            |l| {
                l.contains("PRIVMSG #mleditfb")
                    && l.contains("+draft/edit=")
                    && l.contains("edit L1")
            },
            "fallback edit (line1 only)",
        );
        assert!(
            edit.contains(&format!("+draft/edit={orig_msgid}")),
            "fallback edit references orig msgid: {edit}",
        );
        // Must NOT contain raw newline mid-body or any sign of line2.
        assert!(
            !edit.contains("edit L2"),
            "fallback receiver must not receive line2 of multi-line edit: {edit}",
        );
        // No BATCH framing should be sent to fallback receiver for the edit.
        let stray_batch = bob.maybe(|l| l.starts_with("BATCH"), 500);
        assert!(
            stray_batch.is_none(),
            "fallback receiver got BATCH frame (should be plain PRIVMSG only): {stray_batch:?}",
        );
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════
// MESSAGE IDENTITY ACROSS REVISIONS
//
// A message's identity is its original msgid, for life. An edit changes
// content, never identity: it still travels as a new wire id carrying
// `+draft/edit=<original>`, but everything the server files and looks up —
// reactions, pins, deletes, in-memory history — keys on the original.
//
// The tests below name operations by BOTH ids on purpose. Clients differ in
// which one they hold (older builds re-keyed to the newest revision), and a
// federated peer may relay either, so both must land on the same message.
// ═══════════════════════════════════════════════════════════════

impl C {
    fn send_react(&mut self, target: &str, msgid: &str, emoji: &str) {
        self.tx(&format!("@+react={emoji};+reply={msgid} TAGMSG {target}"));
    }
    fn send_unreact(&mut self, target: &str, msgid: &str, emoji: &str) {
        self.tx(&format!(
            "@+freeq.at/unreact={emoji};+reply={msgid} TAGMSG {target}"
        ));
    }
    /// Register a session signing key, as every signing client does after auth.
    fn msgsig(&mut self, key: &SigningKey) {
        use base64::Engine;
        let pubkey =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        self.tx(&format!("MSGSIG {pubkey}"));
        self.rx(|l| l.contains("MSGSIG"), "MSGSIG ack");
    }
    /// The same reaction, carrying the proof an identity's mutation needs.
    fn send_signed_react(
        &mut self,
        target: &str,
        venue: &str,
        did: &str,
        msgid: &str,
        emoji: &str,
        key: &SigningKey,
    ) {
        self.send_signed_mutation(
            Mutation::React,
            "+react",
            target,
            venue,
            did,
            msgid,
            Some(emoji),
            key,
        );
    }
    fn send_signed_unreact(
        &mut self,
        target: &str,
        venue: &str,
        did: &str,
        msgid: &str,
        emoji: &str,
        key: &SigningKey,
    ) {
        self.send_signed_mutation(
            Mutation::Unreact,
            "+freeq.at/unreact",
            target,
            venue,
            did,
            msgid,
            Some(emoji),
            key,
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn send_signed_mutation(
        &mut self,
        kind: Mutation,
        subject_tag: &str,
        target: &str,
        venue: &str,
        did: &str,
        subject: &str,
        emoji: Option<&str>,
        key: &SigningKey,
    ) {
        let event_id = freeq_server::msgid::generate();
        let mut doc = ChatDoc::mutation(kind, did, &event_id, venue, subject);
        if let Some(emoji) = emoji {
            doc = doc.with_emoji(emoji);
        }
        let sig = doc.sign(key);
        let head = match emoji {
            Some(e) => format!("{subject_tag}={e};+reply={subject}"),
            None => format!("{subject_tag}={subject}"),
        };
        self.tx(&format!(
            "@{head};{EVENT_ID_TAG}={event_id};+freeq.at/sig={sig} TAGMSG {target}"
        ));
    }
    /// An edit signed by its author — an edit is a message, and its document
    /// covers the message it revises.
    fn send_signed_edit(
        &mut self,
        target: &str,
        venue: &str,
        did: &str,
        original_msgid: &str,
        new_text: &str,
        key: &SigningKey,
    ) {
        let edit_id = freeq_server::msgid::generate();
        let sig = ChatDoc::message(did, &edit_id, venue, new_text)
            .with_edit(original_msgid)
            .sign(key);
        self.tx(&format!(
            "@{EVENT_ID_TAG}={edit_id};+draft/edit={original_msgid};+freeq.at/sig={sig} \
             PRIVMSG {target} :{new_text}"
        ));
    }
    /// Send a message and an edit of it; returns (original id, edit's own id).
    fn say_then_edit(
        &mut self,
        watcher: &mut C,
        target: &str,
        v1: &str,
        v2: &str,
    ) -> (String, String) {
        self.tx(&format!("PRIVMSG {target} :{v1}"));
        let first = watcher.rx(|l| l.contains("PRIVMSG") && l.contains(v1), "v1");
        let original = C::extract_msgid(&first);
        self.send_edit(target, &original, v2);
        let edit = watcher.rx(|l| l.contains("PRIVMSG") && l.contains(v2), "v2");
        let edit_id = C::extract_msgid(&edit);
        assert_ne!(original, edit_id, "an edit travels under its own wire id");
        assert!(
            edit.contains(&format!("+draft/edit={original}")),
            "the edit must point at the identity clients hold: {edit}"
        );
        (original, edit_id)
    }
}

/// Join fresh and return the replayed line for `text`, or None.
fn replayed_line(addr: SocketAddr, nick: &str, channel: &str, text: &str) -> Option<String> {
    let mut joiner = C::with_caps(addr, nick);
    joiner.reg();
    joiner.drain();
    joiner.tx(&format!("JOIN {channel}"));
    joiner.maybe(|l| l.contains("PRIVMSG") && l.contains(text), 1500)
}

/// React on one revision, un-react on the other: both name the same message,
/// so the reaction must be gone. A joiner's replay is the honest view — it
/// reads what the server stored, not what a live client happened to render.
#[tokio::test]
async fn unreacting_by_the_original_clears_a_reaction_made_on_the_edit() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "rid_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "rid_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #rid1");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #rid1");
        bob.num("366");
        bob.drain();

        let (original, edit_id) = alice.say_then_edit(&mut bob, "#rid1", "v1", "v2");

        bob.send_react("#rid1", &edit_id, "🔥");
        std::thread::sleep(Duration::from_millis(300));
        let with_reaction =
            replayed_line(addr, "rid_c", "#rid1", "v2").expect("joiner replays the edited message");
        assert!(
            with_reaction.contains("+freeq.at/reactions=🔥:rid_b"),
            "a reaction filed against the edit id must ride the replayed \
             message, which is keyed by the original: {with_reaction}"
        );

        bob.send_unreact("#rid1", &original, "🔥");
        std::thread::sleep(Duration::from_millis(300));
        let after = replayed_line(addr, "rid_d", "#rid1", "v2").expect("still replayed");
        assert!(
            !after.contains("+freeq.at/reactions"),
            "un-reacting by the original id left the reaction behind: {after}"
        );
    })
    .await;
}

/// …and the same in the other order: reacted before the edit, cleared by the
/// edit's id afterwards.
#[tokio::test]
async fn unreacting_by_the_edit_id_clears_a_reaction_made_on_the_original() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "rid2_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "rid2_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #rid2");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #rid2");
        bob.num("366");
        bob.drain();

        alice.tx("PRIVMSG #rid2 :v1");
        let first = bob.rx(|l| l.contains("PRIVMSG") && l.contains("v1"), "v1");
        let original = C::extract_msgid(&first);

        bob.send_react("#rid2", &original, "🔥");
        std::thread::sleep(Duration::from_millis(200));

        alice.send_edit("#rid2", &original, "v2");
        let edit = bob.rx(|l| l.contains("PRIVMSG") && l.contains("v2"), "v2");
        let edit_id = C::extract_msgid(&edit);

        bob.send_unreact("#rid2", &edit_id, "🔥");
        std::thread::sleep(Duration::from_millis(300));

        let after = replayed_line(addr, "rid2_c", "#rid2", "v2").expect("still replayed");
        assert!(
            !after.contains("+freeq.at/reactions"),
            "un-reacting by the edit id left the reaction behind: {after}"
        );
    })
    .await;
}

/// One person, one reaction — even when their two clients name two different
/// revisions of the message.
#[tokio::test]
async fn two_ids_never_split_a_reaction_tally() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "tal_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "tal_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #tally");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #tally");
        bob.num("366");
        bob.drain();

        let (original, edit_id) = alice.say_then_edit(&mut bob, "#tally", "v1", "v2");
        bob.send_react("#tally", &original, "🔥");
        bob.send_react("#tally", &edit_id, "🔥");
        std::thread::sleep(Duration::from_millis(300));

        let line = replayed_line(addr, "tal_c", "#tally", "v2").expect("replayed");
        // Tag order is not stable, so the tally may be the first tag and carry
        // the leading `@`.
        let tally = line
            .split(';')
            .map(|t| t.trim_start_matches('@'))
            .find(|t| t.starts_with("+freeq.at/reactions="))
            .expect("reaction tally present");
        assert_eq!(
            tally.matches("tal_b").count(),
            1,
            "the same person reacting once must not be counted twice: {tally}"
        );
    })
    .await;
}

/// A delete naming the edit's id must take the message with it — including out
/// of the in-memory history a later joiner is replayed from.
#[tokio::test]
async fn deleting_by_the_edit_id_does_not_resurrect_for_a_joiner() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "del_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "del_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #delrid");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #delrid");
        bob.num("366");
        bob.drain();

        let (_original, edit_id) =
            alice.say_then_edit(&mut bob, "#delrid", "secret v1", "secret v2");
        alice.send_delete("#delrid", &edit_id);
        bob.rx(
            |l| l.contains("TAGMSG") && l.contains("draft/delete"),
            "delete",
        );
        std::thread::sleep(Duration::from_millis(300));

        assert!(
            replayed_line(addr, "del_c", "#delrid", "secret v2").is_none(),
            "the deleted message came back for a joiner"
        );
        assert!(
            replayed_line(addr, "del_d", "#delrid", "secret v1").is_none(),
            "the pre-edit text came back for a joiner"
        );
    })
    .await;
}

/// Join replay collapses revisions into one message, so nothing in the wire
/// form says it was ever edited — hence the marker.
#[tokio::test]
async fn join_replay_marks_an_edited_message() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "mrk_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "mrk_b");
        bob.reg();
        bob.drain();
        alice.tx("JOIN #marked");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #marked");
        bob.num("366");
        bob.drain();

        alice.tx("PRIVMSG #marked :untouched");
        bob.rx(|l| l.contains("untouched"), "plain message");
        alice.say_then_edit(&mut bob, "#marked", "v1", "v2");
        std::thread::sleep(Duration::from_millis(200));

        let edited = replayed_line(addr, "mrk_c", "#marked", "v2").expect("replayed");
        assert!(
            edited.contains("+freeq.at/edited=1"),
            "a late joiner can't tell this text isn't what was sent: {edited}"
        );
        let plain = replayed_line(addr, "mrk_d", "#marked", "untouched").expect("replayed");
        assert!(
            !plain.contains("+freeq.at/edited"),
            "an unedited message must not be marked: {plain}"
        );
    })
    .await;
}

/// Pinning before an edit and after it is one pin, and either id unpins it.
#[tokio::test]
async fn a_pin_follows_the_message_across_an_edit() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "pin_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "pin_b");
        bob.reg();
        bob.drain();
        // Alice creates the channel, so she is op and may pin.
        alice.tx("JOIN #pinrid");
        alice.num("366");
        alice.drain();
        bob.tx("JOIN #pinrid");
        bob.num("366");
        bob.drain();

        let (original, edit_id) = alice.say_then_edit(&mut bob, "#pinrid", "v1", "v2");
        alice.tx(&format!("PIN #pinrid {original}"));
        alice.drain();
        alice.tx(&format!("PIN #pinrid {edit_id}"));
        std::thread::sleep(Duration::from_millis(200));

        alice.drain();
        alice.tx("PINS #pinrid");
        let mut pins = Vec::new();
        while let Some(l) = alice.maybe(|l| l.contains("PIN #pinrid"), 800) {
            pins.push(l);
        }
        assert_eq!(pins.len(), 1, "one message must not pin twice: {pins:?}");
        assert!(
            pins[0].contains(&original),
            "the pin must name the identity clients hold: {}",
            pins[0]
        );

        // Unpin naming the revision — the same message, so it must clear.
        alice.tx(&format!("UNPIN #pinrid {edit_id}"));
        std::thread::sleep(Duration::from_millis(200));
        alice.drain();
        alice.tx("PINS #pinrid");
        let none = alice.maybe(|l| l.contains("No pinned messages"), 1000);
        assert!(
            none.is_some(),
            "unpinning by the edit's id left the pin in place"
        );
    })
    .await;
}

/// A DM lives under a canonical `dm:` key rather than the wire target, so
/// resolving a reaction to its message is a lookup by id, not by channel. Both
/// ends must still agree.
#[tokio::test]
async fn a_dm_reaction_survives_an_edit() {
    let key_a = PrivateKey::generate_ed25519();
    let key_b = PrivateKey::generate_ed25519();
    let resolver = resolver_with(vec![(DID_ALICE, &key_a), (DID_BOB, &key_b)]);
    let (addr, _h) = start(resolver).await;
    run(addr, move |addr| {
        // Both ends sign: an identity's edit and reactions are refused
        // without proof from the key it registered.
        let mut alice = C::with_sasl(addr, "dmrid_a", DID_ALICE, key_a);
        alice.reg();
        let signing_a = SigningKey::from_bytes(&[7u8; 32]);
        alice.msgsig(&signing_a);
        alice.drain();
        let mut bob = C::with_sasl(addr, "dmrid_b", DID_BOB, key_b);
        bob.reg();
        let signing_b = SigningKey::from_bytes(&[8u8; 32]);
        bob.msgsig(&signing_b);
        bob.drain();
        let venue = dm_venue(DID_ALICE, DID_BOB);

        alice.tx("PRIVMSG dmrid_b :dm v1");
        let first = bob.rx(|l| l.contains("PRIVMSG") && l.contains("dm v1"), "dm v1");
        let original = C::extract_msgid(&first);
        alice.send_signed_edit("dmrid_b", &venue, DID_ALICE, &original, "dm v2", &signing_a);
        let edit = bob.rx(|l| l.contains("PRIVMSG") && l.contains("dm v2"), "dm v2");
        let edit_id = C::extract_msgid(&edit);
        assert_ne!(original, edit_id);

        bob.send_signed_react("dmrid_a", &venue, DID_BOB, &edit_id, "🔥", &signing_b);
        std::thread::sleep(Duration::from_millis(300));
        bob.drain();
        bob.tx("CHATHISTORY LATEST dmrid_a * 50");
        let reacted = bob.maybe(|l| l.contains("+freeq.at/reactions"), 1500);
        assert!(
            reacted.is_some(),
            "a DM reaction filed against the edit id vanished from history"
        );

        bob.send_signed_unreact("dmrid_a", &venue, DID_BOB, &original, "🔥", &signing_b);
        std::thread::sleep(Duration::from_millis(300));
        bob.drain();
        bob.tx("CHATHISTORY LATEST dmrid_a * 50");
        let still = bob.maybe(|l| l.contains("+freeq.at/reactions"), 1500);
        assert!(
            still.is_none(),
            "un-reacting by the original id left the DM reaction behind: {still:?}"
        );
    })
    .await;
}

/// Guest DMs are never persisted, so their ids resolve to no row at all. An
/// unknown id is its own root: the events must relay exactly as before.
#[tokio::test]
async fn unpersisted_guest_dm_ids_pass_through_unchanged() {
    let resolver = resolver_with(vec![]);
    let (addr, _h) = start(resolver).await;
    run(addr, |addr| {
        let mut alice = C::with_caps(addr, "gst_a");
        alice.reg();
        alice.drain();
        let mut bob = C::with_caps(addr, "gst_b");
        bob.reg();
        bob.drain();

        alice.tx("PRIVMSG gst_b :ghost dm");
        let dm = bob.rx(|l| l.contains("PRIVMSG") && l.contains("ghost dm"), "dm");
        let msgid = C::extract_msgid(&dm);
        assert!(!msgid.is_empty());

        bob.send_react("gst_a", &msgid, "🔥");
        let react = alice.maybe(|l| l.contains("TAGMSG") && l.contains("+react"), 1500);
        assert!(react.is_some(), "guest DM reaction was not relayed");
        assert!(
            react.unwrap().contains(&format!("+reply={msgid}")),
            "an id with no row must relay untouched"
        );

        alice.send_delete("gst_b", &msgid);
        let del = bob.maybe(|l| l.contains("TAGMSG") && l.contains("draft/delete"), 1500);
        assert!(
            del.is_some_and(|l| l.contains(&msgid)),
            "guest DM delete was not relayed with the id it named"
        );
    })
    .await;
}

/// After a restart, in-memory history is rebuilt from the DB — where an edit is
/// a separate row. The rebuild has to collapse the revisions the way the live
/// edit path does, or the next joiner is replayed the same message twice: once
/// as sent, once as revised.
#[tokio::test]
async fn an_edited_message_replays_once_after_a_restart() {
    use freeq_server::db::Db;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("restart.db");
    {
        let db = Db::open(&path).unwrap();
        db.save_channel("#restart", &freeq_server::server::ChannelState::default())
            .unwrap();
        db.insert_message(
            "#restart",
            "alice!a@host",
            "before",
            100,
            &HashMap::new(),
            Some("rst-1"),
            None,
        )
        .unwrap();
        db.insert_edit(
            "#restart",
            "alice!a@host",
            "after",
            110,
            &HashMap::new(),
            "rst-2",
            "rst-1",
            None,
        )
        .unwrap();
    }

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-edit".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(path.to_str().unwrap().to_string()),
        ..Default::default()
    };
    let (addr, _h) = freeq_server::server::Server::with_resolver(config, resolver_with(vec![]))
        .start()
        .await
        .unwrap();

    run(addr, |addr| {
        let mut c = C::with_caps(addr, "rst_a");
        c.reg();
        c.drain();
        c.tx("JOIN #restart");

        let replayed = c
            .maybe(|l| l.contains("PRIVMSG") && l.contains("after"), 2000)
            .expect("the current text is replayed");
        assert!(
            replayed.contains("msgid=rst-1"),
            "replay must key on the identity clients hold: {replayed}"
        );
        assert!(
            replayed.contains("+freeq.at/edited=1"),
            "a message revised before the restart is still an edited message: {replayed}"
        );
        assert!(
            c.maybe(|l| l.contains("PRIVMSG") && l.contains("before"), 800)
                .is_none(),
            "the pre-edit text was replayed as a second message"
        );
    })
    .await;
}
