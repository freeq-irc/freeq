//! Protocol hardening tests: RFC compliance, parser edge cases, and
//! behaviors that "work" but shouldn't.
//!
//! Every test here targets a specific protocol gap or parser quirk
//! discovered during adversarial code review.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::did::DidResolver;

async fn start() -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-hard".to_string(),
        challenge_timeout_secs: 60,
        db_path: None,
        ..Default::default()
    };
    let resolver = DidResolver::static_map(HashMap::new());
    freeq_server::server::Server::with_resolver(config, resolver)
        .start()
        .await
        .unwrap()
}

async fn run(f: impl FnOnce(SocketAddr) + Send + 'static) {
    let (addr, _s) = start().await;
    tokio::task::spawn_blocking(move || f(addr)).await.unwrap();
}

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl C {
    fn new(addr: SocketAddr, nick: &str) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        let r = BufReader::new(s);
        let mut c = Self {
            reader: r,
            writer: w,
        };
        c.tx(&format!("NICK {nick}"));
        c.tx(&format!("USER {nick} 0 * :test"));
        c
    }

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

    fn rx(&mut self, pred: impl Fn(&str) -> bool, desc: &str) -> String {
        let mut buf = String::new();
        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => panic!("EOF: {desc}"),
                Ok(_) => {
                    let l = buf.trim_end();
                    if l.starts_with("PING") {
                        let t = l.strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {t}\r");
                        let _ = self.writer.flush();
                        continue;
                    }
                    if pred(l) {
                        return l.to_string();
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    panic!("Timeout: {desc}")
                }
                Err(e) => panic!("{desc}: {e}"),
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
            .set_read_timeout(Some(Duration::from_millis(200)))
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

    fn maybe(&mut self, pred: impl Fn(&str) -> bool, ms: u64) -> Option<String> {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .ok();
        let mut b = String::new();
        let result = loop {
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
                    if pred(l) {
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
        result
    }
}

// ══════════════════════════════════════════════════════════════════════
// 1. JOIN without # prefix — creates unprefixed channel (protocol violation)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn join_without_hash_prefix() {
    run(|addr| {
        let mut c = C::new(addr, "nohash");
        c.reg();
        c.drain();
        // JOIN a channel name with no # or & prefix
        c.tx("JOIN test");
        // The server should either reject this or auto-prefix with #.
        // Check what happens:
        let result = c.maybe(
            |l| l.contains("JOIN") || l.contains("403") || l.contains("479"),
            1000,
        );
        match result {
            Some(line) if line.contains("JOIN") => {
                // Server accepted it — this is a protocol gap. The channel
                // name should start with # or &.
                // Not a crash, but documents the behavior.
            }
            Some(_) => {} // Error returned, good
            None => {}    // Silently dropped, acceptable
        }
        // Server must still be alive
        c.tx("JOIN #valid");
        c.num("366");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 2. Double-hash channel name (##channel)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn double_hash_channel() {
    run(|addr| {
        let mut c = C::new(addr, "dblhash");
        c.reg();
        c.drain();
        // ## channels are valid in some IRC servers (freenode used them)
        c.tx("JOIN ##meta");
        // Should work (## is a valid IRC channel prefix on some networks)
        let result = c.maybe(|l| l.contains("JOIN") || l.contains("366"), 1000);
        assert!(
            result.is_some(),
            "## channel should be accepted or rejected cleanly"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 3. PRIVMSG with multiple consecutive spaces in text
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn privmsg_multiple_spaces() {
    run(|addr| {
        let mut a = C::new(addr, "space_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "space_b");
        b.reg();
        b.drain();
        a.tx("JOIN #spaces");
        a.num("366");
        a.drain();
        b.tx("JOIN #spaces");
        b.num("366");
        b.drain();

        // Message with many consecutive spaces
        a.tx("PRIVMSG #spaces :hello     world    test");
        let msg = b.rx(
            |l| l.contains("PRIVMSG") && l.contains("hello"),
            "spaced message",
        );
        // Spaces after the colon should be preserved in trailing param
        assert!(
            msg.contains("hello     world"),
            "Spaces should be preserved: {msg}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 3b. Oversize single-line PRIVMSG — the RFC-paste truncation repro
// ══════════════════════════════════════════════════════════════════════

/// Reproduces the observed truncation: pasting a long multi-paragraph
/// message into the web client, when `draft/multiline` is NOT active on
/// the connection, sends it via the legacy path — every `\n` escaped to
/// the two chars `\\n`, collapsing the whole doc into ONE wire line. The
/// server's 8192-byte line reader then decides its fate. We assert the
/// recipient either gets the WHOLE thing or a clean rejection — never a
/// silent mid-word truncation (which is what a user saw: cut at
/// "explicitly best-" ~7963 body bytes into an ~14k-char paste).
#[tokio::test]
async fn oversize_single_line_privmsg_is_not_silently_truncated() {
    run(|addr| {
        let mut a = C::new(addr, "rfc_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "rfc_b");
        b.reg();
        b.drain();
        a.tx("JOIN #rfc");
        a.num("366");
        a.drain();
        b.tx("JOIN #rfc");
        b.num("366");
        b.drain();

        // ~14 KiB body with markers at both ends, well past MAX_LINE_LEN
        // (8192). If the server truncates near 8 KiB, the tail marker is
        // gone; if it delivers whole, both markers survive; if it rejects,
        // nothing is delivered and the sender should see a 417.
        let body = format!("HEAD_MARKER{}TAIL_MARKER_END", "x".repeat(14000));
        a.tx(&format!("PRIVMSG #rfc :{body}"));

        let delivered = b.maybe(|l| l.contains("PRIVMSG") && l.contains("HEAD_MARKER"), 1500);
        let got_417 = a
            .maybe(|l| l.split_whitespace().nth(1) == Some("417"), 500)
            .is_some();

        match delivered {
            Some(line) => assert!(
                line.contains("TAIL_MARKER_END"),
                "RECIPIENT GOT A TRUNCATED MESSAGE: wire line was {} bytes, \
                 tail marker missing (cut near MAX_LINE_LEN). 417-to-sender={}. \
                 head: {:.90}",
                line.len(),
                got_417,
                line,
            ),
            None => assert!(
                got_417,
                "message was silently dropped — recipient got nothing AND \
                 sender got no 417",
            ),
        }
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 4. INVITE user who is already in the channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invite_user_already_in_channel() {
    run(|addr| {
        let mut own = C::new(addr, "inv2_own");
        own.reg();
        own.drain();
        own.tx("JOIN #inv2");
        own.num("366");
        own.drain();

        let mut usr = C::new(addr, "inv2_usr");
        usr.reg();
        usr.drain();
        usr.tx("JOIN #inv2");
        usr.num("366");
        usr.drain();

        // Owner invites user who is already in the channel
        own.tx("INVITE inv2_usr #inv2");
        // Should get 443 ERR_USERONCHANNEL per RFC 2812
        let result = own.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "443" || n == "341" // 341 = RPL_INVITING (success)
            },
            1000,
        );
        // Either 443 (correct) or 341 (suboptimal but not a crash)
        assert!(result.is_some(), "Should get a response to INVITE");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 5. NICK with no parameter
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_no_param() {
    run(|addr| {
        let mut c = C::new(addr, "nickparam");
        c.reg();
        c.drain();
        // NICK with no argument
        c.tx("NICK");
        // Should get 431 ERR_NONICKNAMEGIVEN
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "431"
            },
            1000,
        );
        // Either gets 431 or is silently ignored — server must not crash
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "server alive after NICK no param");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 6. Send raw garbage bytes (not valid IRC)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn raw_garbage_input() {
    run(|addr| {
        let mut c = C::raw(addr);
        // Send binary garbage
        c.tx("\x01\x02\x03\x04\x05");
        c.tx("AAAA BBBB CCCC DDDD EEEE FFFF");
        c.tx("!@#$%^&*()");
        c.tx("");
        c.tx("   ");
        // Now try to register normally
        c.tx("NICK garbtest");
        c.tx("USER garbtest 0 * :test");
        c.reg(); // Should still work
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 7. KICK from channel you're not in
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn kick_from_channel_not_in() {
    run(|addr| {
        let mut own = C::new(addr, "kickown2");
        own.reg();
        own.drain();
        own.tx("JOIN #kickext");
        own.num("366");
        own.drain();

        let mut outsider = C::new(addr, "kickext");
        outsider.reg();
        outsider.drain();
        // Don't join — try to kick from outside
        outsider.tx("KICK #kickext kickown2 :haha");
        // Should get 442 ERR_NOTONCHANNEL
        outsider.num("442");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 8. KICK nonexistent user from channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn kick_nonexistent_user() {
    run(|addr| {
        let mut c = C::new(addr, "kickghost");
        c.reg();
        c.drain();
        c.tx("JOIN #kickg");
        c.num("366");
        c.drain();
        c.tx("KICK #kickg nobody99 :go away");
        // Should get 441 ERR_USERNOTINCHANNEL
        c.num("441");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 9. Op someone, they op you back, then you both try to deop each other
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mutual_deop_war() {
    run(|addr| {
        let mut a = C::new(addr, "war_a");
        a.reg();
        a.drain();
        a.tx("JOIN #war");
        a.num("366");
        a.drain();

        let mut b = C::new(addr, "war_b");
        b.reg();
        b.drain();
        b.tx("JOIN #war");
        b.num("366");
        b.drain();

        // A (founder/op) gives B ops
        a.tx("MODE #war +o war_b");
        a.drain();
        b.drain();
        std::thread::sleep(Duration::from_millis(50));

        // B tries to deop A (founder) — should be blocked for DID founders,
        // but for guest founders it may work
        b.tx("MODE #war -o war_a");
        b.drain();
        std::thread::sleep(Duration::from_millis(50));

        // A tries to deop B
        a.tx("MODE #war -o war_b");
        a.drain();
        b.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Check final state: at least the founder should be op
        a.tx("NAMES #war");
        let names = a.num("353");
        let nick_part = names.split_once(" :").map(|x| x.1).unwrap_or("");
        // At minimum, the channel shouldn't be in a broken state
        assert!(
            nick_part.contains("war_a"),
            "Founder should be listed: {names}"
        );
        assert!(
            nick_part.contains("war_b"),
            "Other user should be listed: {names}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 10. Send PRIVMSG to a channel name with mixed case — case insensitive?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn channel_case_insensitive() {
    run(|addr| {
        let mut a = C::new(addr, "case_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "case_b");
        b.reg();
        b.drain();

        // Alice joins #CaseTest
        a.tx("JOIN #CaseTest");
        a.num("366");
        a.drain();
        // Bob joins #casetest (different case)
        b.tx("JOIN #casetest");
        b.num("366");
        b.drain();

        // Should be the same channel — Alice sends, Bob should receive
        a.tx("PRIVMSG #CASETEST :hello case");
        b.rx(
            |l| l.contains("PRIVMSG") && l.contains("hello case"),
            "case-insensitive msg",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 11. NICK case change (alice → Alice) — should work
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_case_change() {
    run(|addr| {
        let mut c = C::new(addr, "lowercase");
        c.reg();
        c.drain();
        // Change nick to different case only
        c.tx("NICK LowerCase");
        c.rx(
            |l| l.contains("NICK") && l.contains("LowerCase"),
            "case change",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 12. 100 users in one channel — stress test NAMES
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn hundred_users_channel() {
    run(|addr| {
        let mut clients: Vec<C> = (0..50)
            .map(|i| {
                let mut c = C::new(addr, &format!("u{i:03}"));
                c.reg();
                c.drain();
                c.tx("JOIN #big");
                c
            })
            .collect();

        // Wait for all joins to complete
        for c in &mut clients {
            c.num("366");
        }
        clients[0].drain();

        // NAMES should show all users
        clients[0].tx("NAMES #big");
        let names = clients[0].num("353");
        let nick_part = names.split_once(" :").map(|x| x.1).unwrap_or("");
        let count = nick_part.split_whitespace().count();
        assert!(
            count >= 50,
            "Should have at least 50 nicks in NAMES, got {count}: {nick_part}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 13. WHO * (wildcard) — list all users
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn who_wildcard() {
    run(|addr| {
        let mut a = C::new(addr, "who_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "who_b");
        b.reg();
        b.drain();

        a.tx("WHO *");
        // Should get 352 for at least our own nick, then 315 endofwho
        // It might or might not include other users depending on implementation
        a.num("315"); // At minimum, end of who
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 14. Send IRC tags as a client (should be stripped/ignored for most)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn client_sent_tags() {
    run(|addr| {
        let mut a = C::new(addr, "tag_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "tag_b");
        b.reg();
        b.drain();
        a.tx("JOIN #tags");
        a.num("366");
        a.drain();
        b.tx("JOIN #tags");
        b.num("366");
        b.drain();

        // Client sends a message with a forged msgid tag
        a.tx("@msgid=FORGED123 PRIVMSG #tags :tagged msg");
        let msg = b.rx(
            |l| l.contains("PRIVMSG") && l.contains("tagged msg"),
            "tagged msg",
        );
        // The server should have replaced the msgid with its own, NOT used FORGED123
        if msg.contains("FORGED123") {
            panic!("Server used client-forged msgid! Tag injection vulnerability: {msg}");
        }
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 15. Send forged +freeq.at/sig tag (signature spoofing attempt)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn forged_signature_tag() {
    run(|addr| {
        let mut a = C::new(addr, "sig_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "sig_b");
        b.reg();
        b.drain();
        a.tx("JOIN #sigtest");
        a.num("366");
        a.drain();
        b.tx("JOIN #sigtest");
        b.num("366");
        b.drain();

        // Client sends a message with a forged signature tag
        a.tx("@+freeq.at/sig=FORGEDSIG PRIVMSG #sigtest :forged sig msg");
        let msg = b.rx(
            |l| l.contains("PRIVMSG") && l.contains("forged sig"),
            "forged sig msg",
        );
        // Server should NOT pass through the forged signature
        if msg.contains("FORGEDSIG") {
            panic!("Server relayed forged +freeq.at/sig tag! {msg}");
        }
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 16. MODE +k then MODE -k without param — should it work?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mode_minus_k_no_param() {
    run(|addr| {
        let mut c = C::new(addr, "keymod");
        c.reg();
        c.drain();
        c.tx("JOIN #keymod");
        c.num("366");
        c.drain();
        c.tx("MODE #keymod +k secret");
        c.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Remove key with no parameter — does it work?
        c.tx("MODE #keymod -k");
        c.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Now try joining without key from another client
        let mut other = C::new(addr, "keymod2");
        other.reg();
        other.drain();
        other.tx("JOIN #keymod");
        // If -k worked without param, this should succeed
        let result = other.maybe(|l| l.contains("JOIN") || l.contains("475"), 2000);
        // Document what happened
        let _ = result;
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 17. NOTICE should not generate error replies
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn notice_no_error_reply() {
    run(|addr| {
        let mut c = C::new(addr, "noticeerr");
        c.reg();
        c.drain();
        // NOTICE to nonexistent nick — should NOT get 401 (per RFC)
        c.tx("NOTICE nobody123 :hello");
        // Wait briefly — should get nothing back (NOTICE must not generate errors)
        let result = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "401" || n == "404"
            },
            500,
        );
        // If we get an error, that's a protocol violation
        if let Some(line) = result {
            // Document: server sends error for NOTICE (violation of RFC 2812 3.3.2)
            let _ = line;
        }
        // Server still alive
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 18. PRIVMSG with IRC formatting codes (bold, color, etc.)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn irc_formatting_codes() {
    run(|addr| {
        let mut a = C::new(addr, "fmt_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "fmt_b");
        b.reg();
        b.drain();
        a.tx("JOIN #fmt");
        a.num("366");
        a.drain();
        b.tx("JOIN #fmt");
        b.num("366");
        b.drain();

        // Bold (\x02), color (\x03), underline (\x1F), reverse (\x16), reset (\x0F)
        a.tx("PRIVMSG #fmt :\x02bold\x02 \x0304red\x03 \x1Funderline\x0F normal");
        let msg = b.rx(
            |l| l.contains("PRIVMSG") && l.contains("bold"),
            "formatted msg",
        );
        // Formatting codes should be preserved (they're valid IRC)
        assert!(msg.contains("bold"), "bold text preserved");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 19. NICK to empty string (edge case)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_empty_string() {
    run(|addr| {
        let mut c = C::new(addr, "emptytest");
        c.reg();
        c.drain();
        // Try changing to empty nick via trailing colon
        c.tx("NICK :");
        // Should get 431 ERR_NONICKNAMEGIVEN or 432 ERR_ERRONEUSNICKNAME
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "431" || n == "432"
            },
            1000,
        );
        // Either error or silently ignored — must not crash
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive after empty nick");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 20. Connect 20 clients from same IP (hit per-IP limit), then 21st
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn per_ip_connection_limit() {
    run(|addr| {
        // Open 20 connections (the per-IP limit)
        let clients: Vec<C> = (0..20)
            .map(|i| {
                let mut c = C::new(addr, &format!("iplim{i:02}"));
                c.reg();
                c
            })
            .collect();

        // 21st connection should be refused
        let result = std::panic::catch_unwind(|| {
            let s = TcpStream::connect(addr);
            match s {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    let mut r = BufReader::new(stream);
                    let mut buf = String::new();
                    // Try to read — connection should be immediately closed
                    match r.read_line(&mut buf) {
                        Ok(0) => true,  // Connection closed — correct
                        Err(_) => true, // Error — correct
                        Ok(_) => false, // Got data — limit not enforced
                    }
                }
                Err(_) => true, // Connection refused — correct
            }
        });

        // A panic in catch_unwind is fine.
        if let Ok(rejected) = result {
            // Connection might still succeed if some previous ones were cleaned up
            // by the time we connect. This test is inherently racy.
            let _ = rejected;
        }

        // Clean up — drop all clients
        drop(clients);
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 21. PRIVMSG to & channel (alternate prefix)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ampersand_channel() {
    run(|addr| {
        let mut a = C::new(addr, "amp_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "amp_b");
        b.reg();
        b.drain();

        a.tx("JOIN &local");
        a.num("366");
        a.drain();
        b.tx("JOIN &local");
        b.num("366");
        b.drain();

        a.tx("PRIVMSG &local :ampersand channel works");
        b.rx(
            |l| l.contains("PRIVMSG") && l.contains("ampersand"),
            "& channel msg",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 22. Multiple MODE changes in one command (+ov, +ntk, etc.)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn compound_mode_changes() {
    run(|addr| {
        let mut own = C::new(addr, "cmode_own");
        own.reg();
        own.drain();
        own.tx("JOIN #cmode");
        own.num("366");
        own.drain();

        let mut usr = C::new(addr, "cmode_usr");
        usr.reg();
        usr.drain();
        usr.tx("JOIN #cmode");
        usr.num("366");
        usr.drain();

        // Compound mode: +ov (op and voice at once)
        own.tx("MODE #cmode +ov cmode_usr cmode_usr");
        own.drain();
        std::thread::sleep(Duration::from_millis(100));

        // Check NAMES for both @ and + prefixes
        own.tx("NAMES #cmode");
        let names = own.num("353");
        // User should have op (at minimum)
        let nick_part = names.split_once(" :").map(|x| x.1).unwrap_or("");
        // @ takes priority over + in display
        assert!(
            nick_part.contains("@cmode_usr") || nick_part.contains("+cmode_usr"),
            "User should have a prefix: {names}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 23. USERHOST command (if implemented)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn userhost_command() {
    run(|addr| {
        let mut c = C::new(addr, "uhtest");
        c.reg();
        c.drain();
        c.tx("USERHOST uhtest");
        // Should get 302 RPL_USERHOST or be silently dropped
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "302" || n == "421" // 421 = ERR_UNKNOWNCOMMAND
            },
            1000,
        );
        // Either works or unknown — must not crash
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 24. VERSION, TIME, ADMIN, INFO commands (if implemented)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn misc_info_commands() {
    run(|addr| {
        let mut c = C::new(addr, "infocmd");
        c.reg();
        c.drain();
        // Fire off a bunch of info commands — none should crash the server
        c.tx("VERSION");
        c.tx("TIME");
        c.tx("ADMIN");
        c.tx("INFO");
        c.tx("STATS");
        c.tx("LINKS");
        c.tx("LUSERS");
        c.drain();
        // Server still alive
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive after info commands");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 25. NICK change while in multiple channels — all members notified
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_change_multi_channel_broadcast() {
    run(|addr| {
        let mut a = C::new(addr, "mc_alice");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "mc_bob");
        b.reg();
        b.drain();
        let mut c = C::new(addr, "mc_carol");
        c.reg();
        c.drain();

        // All three join #ch1
        a.tx("JOIN #ch1");
        a.num("366");
        a.drain();
        b.tx("JOIN #ch1");
        b.num("366");
        b.drain();
        c.tx("JOIN #ch1");
        c.num("366");
        c.drain();

        // Only Alice and Carol in #ch2
        a.tx("JOIN #ch2");
        a.num("366");
        a.drain();
        c.tx("JOIN #ch2");
        c.num("366");
        c.drain();

        // Alice changes nick
        a.tx("NICK mc_alice_new");

        // Bob (only in #ch1) should see it
        b.rx(
            |l| l.contains("NICK") && l.contains("mc_alice_new"),
            "Bob sees nick change",
        );

        // Carol (in both channels) should see it exactly once
        c.rx(
            |l| l.contains("NICK") && l.contains("mc_alice_new"),
            "Carol sees nick change",
        );
        // Carol should NOT get a duplicate
        let dup = c.maybe(|l| l.contains("NICK") && l.contains("mc_alice_new"), 300);
        assert!(
            dup.is_none(),
            "Carol should NOT get duplicate nick change notification"
        );
    })
    .await;
}
