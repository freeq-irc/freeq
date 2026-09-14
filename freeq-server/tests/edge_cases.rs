//! Hairy edge-case tests targeting protocol boundary conditions, race conditions,
//! and behaviors likely to break under real-world abuse.
//!
//! These use raw TCP (like a hostile or buggy IRC client would) to poke at the
//! server's handling of malformed input, concurrent state mutations, and protocol
//! violations that normal clients would never trigger.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::did::DidResolver;

async fn start_server() -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-edge".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let resolver = DidResolver::static_map(HashMap::new());
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

async fn run(f: impl FnOnce(SocketAddr) + Send + 'static) {
    let (addr, _server) = start_server().await;
    tokio::task::spawn_blocking(move || f(addr)).await.unwrap();
}

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl C {
    fn connect(addr: SocketAddr, nick: &str) -> Self {
        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let writer = stream.try_clone().unwrap();
        let reader = BufReader::new(stream);
        let mut c = Self { reader, writer };
        c.send(&format!("NICK {nick}"));
        c.send(&format!("USER {nick} 0 * :test"));
        c
    }

    fn raw(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let writer = stream.try_clone().unwrap();
        let reader = BufReader::new(stream);
        Self { reader, writer }
    }

    fn send(&mut self, line: &str) {
        writeln!(self.writer, "{line}\r").unwrap();
        self.writer.flush().ok();
    }

    fn expect(&mut self, pred: impl Fn(&str) -> bool, desc: &str) -> String {
        let mut buf = String::new();
        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => panic!("EOF waiting for: {desc}"),
                Ok(_) => {
                    let line = buf.trim_end();
                    if line.starts_with("PING") {
                        let tok = line.strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {tok}\r");
                        let _ = self.writer.flush();
                        continue;
                    }
                    if pred(line) {
                        return line.to_string();
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    panic!("Timeout for: {desc}")
                }
                Err(e) => panic!("Error for {desc}: {e}"),
            }
        }
    }

    fn num(&mut self, code: &str) -> String {
        self.expect(|l| l.split_whitespace().nth(1) == Some(code), code)
    }

    fn reg(&mut self) -> String {
        self.num("001")
    }

    fn drain(&mut self) {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let mut buf = String::new();
        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if buf.starts_with("PING") {
                        let tok = buf.trim_end().strip_prefix("PING ").unwrap_or(":x");
                        let _ = writeln!(self.writer, "PONG {tok}\r");
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

    /// Check if the connection is closed (returns true if read would return 0/error).
    fn is_closed(&mut self) -> bool {
        self.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        let mut buf = String::new();
        let result = match self.reader.read_line(&mut buf) {
            Ok(0) => true,
            Err(_) => true,
            Ok(_) => false,
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
// 1. Commands before registration should be silently dropped (not crash)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn privmsg_before_registration() {
    run(|addr| {
        let mut c = C::raw(addr);
        // Send PRIVMSG before NICK/USER — should not crash server
        c.send("PRIVMSG #test :hello");
        c.send("JOIN #test");
        c.send("PART #test");
        c.send("MODE #test");
        c.send("TOPIC #test :test");
        c.send("KICK #test someone");
        c.send("WHO #test");
        c.send("WHOIS someone");
        c.send("LIST");
        // Now register normally — should still work
        c.send("NICK preregtest");
        c.send("USER preregtest 0 * :test");
        let w = c.reg();
        assert!(
            w.contains("preregtest"),
            "Should register normally after pre-reg commands"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 2. Empty PRIVMSG text (`:` with nothing after)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_privmsg_text() {
    run(|addr| {
        let mut a = C::connect(addr, "empty_a");
        a.reg();
        a.drain();
        let mut b = C::connect(addr, "empty_b");
        b.reg();
        b.drain();
        a.send("JOIN #emptymsg");
        a.num("366");
        a.drain();
        b.send("JOIN #emptymsg");
        b.num("366");
        b.drain();

        // Empty text after colon — server should accept and relay
        a.send("PRIVMSG #emptymsg :");
        // Bob should either receive the empty message or server should silently drop it.
        // Either way, the server must not crash.
        // Give a short timeout — if nothing comes, that's OK too.
        b.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        let mut buf = String::new();
        let _ = b.reader.read_line(&mut buf); // Don't care if timeout
        b.writer
            .try_clone()
            .unwrap()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        // Server still alive — send another message
        a.send("PRIVMSG #emptymsg :still alive");
        b.expect(
            |l| l.contains("still alive"),
            "server still works after empty msg",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 3. PRIVMSG to channel with +n from non-member (should be rejected)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn privmsg_to_plus_n_channel_from_nonmember() {
    run(|addr| {
        let mut owner = C::connect(addr, "nowner");
        owner.reg();
        owner.drain();
        owner.send("JOIN #nochat");
        owner.num("366");
        owner.drain();
        // Channel gets +nt by default for new channels

        let mut outsider = C::connect(addr, "nout");
        outsider.reg();
        outsider.drain();
        // Don't join — just send to channel
        outsider.send("PRIVMSG #nochat :I'm not a member!");
        // Should get 404 ERR_CANNOTSENDTOCHAN
        outsider.num("404");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 4. Double JOIN to same channel (should be silently ignored)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn double_join_same_channel() {
    run(|addr| {
        let mut c = C::connect(addr, "dblj");
        c.reg();
        c.drain();
        c.send("JOIN #double");
        c.num("366");
        c.drain();

        // Second JOIN — should be silently ignored
        c.send("JOIN #double");
        // Send something else to verify server is responsive
        c.send("NAMES #double");
        let names = c.num("353");
        assert!(names.contains("dblj"));
        // Should NOT get a second JOIN echo or second 366
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 5. PART from channel you're not in
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn part_channel_not_in() {
    run(|addr| {
        let mut c = C::connect(addr, "partghost");
        c.reg();
        c.drain();
        // PART from a channel we never joined — should get 442 ERR_NOTONCHANNEL
        c.send("PART #neverjoinedthis");
        c.num("442");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 6. KICK from non-op (should fail)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn kick_from_non_op() {
    run(|addr| {
        let mut owner = C::connect(addr, "kickown");
        owner.reg();
        owner.drain();
        owner.send("JOIN #kickfail");
        owner.num("366");
        owner.drain();

        let mut a = C::connect(addr, "kicka");
        a.reg();
        a.drain();
        a.send("JOIN #kickfail");
        a.num("366");
        a.drain();

        let mut b = C::connect(addr, "kickb");
        b.reg();
        b.drain();
        b.send("JOIN #kickfail");
        b.num("366");
        b.drain();

        // Non-op 'a' tries to kick 'b' — should fail
        a.send("KICK #kickfail kickb :nope");
        a.num("482"); // ERR_CHANOPRIVSNEEDED
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 7. TOPIC on +t channel from non-op (should fail)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn topic_on_locked_channel_from_nonop() {
    run(|addr| {
        let mut owner = C::connect(addr, "topicown");
        owner.reg();
        owner.drain();
        owner.send("JOIN #topiclock");
        owner.num("366");
        owner.drain();
        // Channel gets +t by default

        let mut user = C::connect(addr, "topicusr2");
        user.reg();
        user.drain();
        user.send("JOIN #topiclock");
        user.num("366");
        user.drain();

        // Non-op tries to set topic
        user.send("TOPIC #topiclock :my topic");
        user.num("482"); // ERR_CHANOPRIVSNEEDED
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 8. Channel key (+k): wrong key, no key, correct key
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn channel_key_enforcement() {
    run(|addr| {
        let mut owner = C::connect(addr, "keyown");
        owner.reg();
        owner.drain();
        owner.send("JOIN #keyed");
        owner.num("366");
        owner.drain();
        // Set channel key
        owner.send("MODE #keyed +k secret123");
        owner.drain();
        std::thread::sleep(Duration::from_millis(50));

        // User with wrong key
        let mut bad = C::connect(addr, "keybad");
        bad.reg();
        bad.drain();
        bad.send("JOIN #keyed wrongkey");
        bad.num("475"); // ERR_BADCHANNELKEY

        // User with no key
        let mut nokey = C::connect(addr, "keyno");
        nokey.reg();
        nokey.drain();
        nokey.send("JOIN #keyed");
        nokey.num("475"); // ERR_BADCHANNELKEY

        // User with correct key
        let mut good = C::connect(addr, "keygood");
        good.reg();
        good.drain();
        good.send("JOIN #keyed secret123");
        good.expect(
            |l| l.contains("JOIN") && l.contains("#keyed"),
            "JOIN with correct key",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 9. SASL with garbage base64 (should not crash, not count as failure)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sasl_garbage_base64() {
    run(|addr| {
        let mut c = C::raw(addr);
        c.send("CAP LS 302");
        c.send("NICK saslgarb");
        c.send("USER saslgarb 0 * :test");
        // Request SASL
        c.send("CAP REQ :sasl");
        c.expect(|l| l.contains("ACK"), "CAP ACK");
        c.send("AUTHENTICATE ATPROTO-CHALLENGE");
        // Wait for the challenge
        c.expect(|l| l.contains("AUTHENTICATE"), "challenge");
        // Send garbage instead of valid base64 response
        c.send("AUTHENTICATE !!!not-valid-base64!!!");
        // Should get 904 ERR_SASLFAIL
        c.num("904");
        // Should still be able to end CAP and register as guest
        c.send("CAP END");
        c.reg();
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 10. Three SASL failures should disconnect
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn three_sasl_failures_disconnect() {
    run(|addr| {
        let mut c = C::raw(addr);
        c.send("CAP LS 302");
        c.send("NICK saslfail3");
        c.send("USER saslfail3 0 * :test");
        c.send("CAP REQ :sasl");
        c.expect(|l| l.contains("ACK"), "CAP ACK");

        // We need to send valid base64 JSON that will fail verification.
        // The response must decode as JSON but have an invalid DID.
        let bad_response = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "did": "did:key:z6MkBogus",
                "signature": "AAAA"
            })
            .to_string()
            .as_bytes(),
        );

        for i in 0..3 {
            c.send("AUTHENTICATE ATPROTO-CHALLENGE");
            c.expect(|l| l.contains("AUTHENTICATE"), &format!("challenge {i}"));
            c.send(&format!("AUTHENTICATE {bad_response}"));
            c.num("904");
        }
        // After 3rd failure, should get ERROR and disconnect
        c.expect(
            |l| l.contains("ERROR") || l.contains("Too many"),
            "ERROR after 3 failures",
        );
        // Connection should be closed
        assert!(
            c.is_closed(),
            "Connection should be closed after 3 SASL failures"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 11. Unicode nick and messages
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn unicode_nick_and_messages() {
    run(|addr| {
        // Unicode nick (should work — our validator allows non-control, non-special chars)
        let mut c = C::connect(addr, "caf\u{00e9}user");
        c.reg();
        c.drain();
        c.send("JOIN #unicode");
        c.num("366");
        c.drain();

        // Unicode message
        c.send("PRIVMSG #unicode :\u{1F600} emoji message \u{4e16}\u{754c}");
        // Server should relay — check via NAMES that we're still connected
        c.send("NAMES #unicode");
        let names = c.num("353");
        assert!(
            names.contains("caf\u{00e9}user"),
            "Unicode nick preserved: {names}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 12. Rapid nick changes (potential race condition)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn rapid_nick_changes() {
    run(|addr| {
        let mut c = C::connect(addr, "rapid0");
        c.reg();
        c.drain();
        c.send("JOIN #rapid");
        c.num("366");
        c.drain();

        // Rapid-fire nick changes
        for i in 1..=10 {
            c.send(&format!("NICK rapid{i}"));
        }
        // Drain all nick change echoes
        c.drain();
        // Verify final nick via NAMES
        c.send("NAMES #rapid");
        let names = c.num("353");
        assert!(
            names.contains("rapid10"),
            "Final nick should be rapid10: {names}"
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 13. NICK change to currently-in-use nick (not yours)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_change_to_in_use() {
    run(|addr| {
        let mut a = C::connect(addr, "taken_nick");
        a.reg();
        a.drain();
        let mut b = C::connect(addr, "wannabe");
        b.reg();
        b.drain();

        b.send("NICK taken_nick");
        b.num("433"); // ERR_NICKNAMEINUSE
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 14. Invite-only channel (+i) without invite
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invite_only_channel_rejected() {
    run(|addr| {
        let mut owner = C::connect(addr, "invown");
        owner.reg();
        owner.drain();
        owner.send("JOIN #invonly");
        owner.num("366");
        owner.drain();
        owner.send("MODE #invonly +i");
        owner.drain();
        std::thread::sleep(Duration::from_millis(50));

        let mut outsider = C::connect(addr, "invout");
        outsider.reg();
        outsider.drain();
        outsider.send("JOIN #invonly");
        outsider.num("473"); // ERR_INVITEONLYCHAN
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 15. Mode change by non-op (should fail)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mode_change_by_non_op() {
    run(|addr| {
        let mut owner = C::connect(addr, "modeown");
        owner.reg();
        owner.drain();
        owner.send("JOIN #modelock");
        owner.num("366");
        owner.drain();

        let mut user = C::connect(addr, "modeusr");
        user.reg();
        user.drain();
        user.send("JOIN #modelock");
        user.num("366");
        user.drain();

        // Non-op tries to set mode
        user.send("MODE #modelock +m");
        user.num("482"); // ERR_CHANOPRIVSNEEDED
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 16. PRIVMSG to self (should work)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn privmsg_to_self() {
    run(|addr| {
        let mut c = C::connect(addr, "selfmsg");
        c.reg();
        c.drain();
        c.send("PRIVMSG selfmsg :talking to myself");
        c.expect(
            |l| l.contains("PRIVMSG") && l.contains("talking to myself"),
            "self-DM",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 17. Very long message (near 512-byte IRC limit, and beyond)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn long_message() {
    run(|addr| {
        let mut a = C::connect(addr, "long_a");
        a.reg();
        a.drain();
        let mut b = C::connect(addr, "long_b");
        b.reg();
        b.drain();
        a.send("JOIN #longmsg");
        a.num("366");
        a.drain();
        b.send("JOIN #longmsg");
        b.num("366");
        b.drain();

        // Send a 4000-char message (well under 8KB line limit)
        let long_text = "x".repeat(4000);
        a.send(&format!("PRIVMSG #longmsg :{long_text}"));
        let msg = b.expect(|l| l.contains("PRIVMSG") && l.contains("xxxx"), "long msg");
        // Verify it's actually long
        assert!(msg.len() > 3000, "Message should be long: {}", msg.len());
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 18. Concurrent JOINs to same new channel (race for founder ops)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn concurrent_joins_founder_race() {
    run(|addr| {
        // Create 5 clients, all join a new channel at the same time.
        // Exactly ONE should get ops (the first to actually create the channel).
        let mut clients: Vec<C> = (0..5)
            .map(|i| {
                let mut c = C::connect(addr, &format!("racer{i}"));
                c.reg();
                c.drain();
                c
            })
            .collect();

        for c in &mut clients {
            c.send("JOIN #racetest");
        }
        // Wait for all to join
        for c in &mut clients {
            c.num("366");
        }
        // Check NAMES for exactly one @
        clients[0].drain();
        clients[0].send("NAMES #racetest");
        let names = clients[0].num("353");
        let op_count = names.matches('@').count();
        assert_eq!(op_count, 1, "Exactly one founder should have ops: {names}");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 19. WHOIS for nonexistent user
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn whois_nonexistent_user() {
    run(|addr| {
        let mut c = C::connect(addr, "whoisqry");
        c.reg();
        c.drain();
        c.send("WHOIS ghostuser999");
        // Should get 401 ERR_NOSUCHNICK then 318 ENDOFWHOIS
        c.num("401");
        c.num("318");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 20. Flood protection: 6 messages in 2 seconds to same channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn flood_protection_kicks_in() {
    run(|addr| {
        let mut a = C::connect(addr, "flooder");
        a.reg();
        a.drain();
        a.send("JOIN #flood");
        a.num("366");
        a.drain();

        // Rapidly send 6 messages (limit is 5 per 2 seconds)
        for i in 0..6 {
            a.send(&format!("PRIVMSG #flood :flood {i}"));
        }
        // Should get 404 ERR_CANNOTSENDTOCHAN for the 6th message
        a.expect(
            |l| l.split_whitespace().nth(1) == Some("404"),
            "flood protection 404",
        );
    })
    .await;
}

use base64::Engine;
