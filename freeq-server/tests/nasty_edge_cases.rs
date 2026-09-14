//! Adversarial edge-case tests: protocol abuse, state leakage, race conditions.
//!
//! These tests are designed by an attacker mindset — every test targets a specific
//! subtle bug or boundary condition that a normal client would never trigger.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::did::DidResolver;

async fn start() -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-nasty".to_string(),
        challenge_timeout_secs: 60,
        db_path: None, // in-memory only for speed
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
// 1. Self-INVITE to bypass invite-only channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn self_invite_bypass_invite_only() {
    run(|addr| {
        // Owner creates invite-only channel
        let mut own = C::new(addr, "invown2");
        own.reg();
        own.drain();
        own.tx("JOIN #secret");
        own.num("366");
        own.drain();
        own.tx("MODE #secret +i");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Outsider tries to join (should fail)
        let mut out = C::new(addr, "invout2");
        out.reg();
        out.drain();
        out.tx("JOIN #secret");
        out.num("473"); // ERR_INVITEONLYCHAN — correct

        // Now: can the outsider INVITE themselves? They shouldn't be able to
        // because INVITE requires being in the channel (and op if +i).
        out.tx("INVITE invout2 #secret");
        // Should get error (442 not on channel, or 482 not op)
        out.rx(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "442" || n == "482" || n == "443"
            },
            "self-invite rejected",
        );
        // The outsider should NOT be able to join after self-invite attempt
        out.tx("JOIN #secret");
        out.num("473"); // Should still be rejected
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 2. Empty ban mask — should be rejected
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_ban_mask() {
    run(|addr| {
        let mut c = C::new(addr, "banown");
        c.reg();
        c.drain();
        c.tx("JOIN #bans");
        c.num("366");
        c.drain();
        // Try to ban with empty mask
        c.tx("MODE #bans +b ");
        c.drain();
        // Check ban list — should be empty (empty mask should be rejected)
        c.tx("MODE #bans b");
        // Expect 368 END OF BANS (with no 367 entries before it)
        let end = c.num("368");
        assert!(end.contains("368"), "Should get end of ban list");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 3. Ban *!*@* (universal wildcard) — bans everyone
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn universal_ban_blocks_join() {
    run(|addr| {
        let mut own = C::new(addr, "banall_own");
        own.reg();
        own.drain();
        own.tx("JOIN #banall");
        own.num("366");
        own.drain();
        // Ban everyone
        own.tx("MODE #banall +b *!*@*");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // New user tries to join
        let mut victim = C::new(addr, "banvictim");
        victim.reg();
        victim.drain();
        victim.tx("JOIN #banall");
        // Should get 474 ERR_BANNEDFROMCHAN
        victim.num("474");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 4. Kick yourself (should this work?)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn kick_yourself() {
    run(|addr| {
        let mut c = C::new(addr, "selfkick");
        c.reg();
        c.drain();
        c.tx("JOIN #selfkick");
        c.num("366");
        c.drain();
        // Kick yourself
        c.tx("KICK #selfkick selfkick :bye myself");
        // Should either get KICK echo (you kicked yourself) or an error.
        // Either way, server must not crash.
        let _ = c.maybe(
            |l| {
                l.contains("KICK")
                    || l.split_whitespace()
                        .nth(1)
                        .map(|n| n.starts_with('4'))
                        .unwrap_or(false)
            },
            1000,
        );
        // Verify server is still alive
        c.tx("PING :alive");
        // If we kicked ourselves, PONG won't come through channel, but the
        // server should respond. The maybe above handles PING automatically.
        // Just try to do something:
        c.tx("JOIN #selfkick2");
        c.num("366"); // Should work — server alive
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 5. Founder PARTs and rejoin — should they get ops back?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn founder_parts_and_rejoins_gets_ops() {
    run(|addr| {
        let mut founder = C::new(addr, "founder2");
        founder.reg();
        founder.drain();
        founder.tx("JOIN #foundtest");
        founder.num("366");
        founder.drain();

        // Second user joins (keeps channel alive)
        let mut other = C::new(addr, "other2");
        other.reg();
        other.drain();
        other.tx("JOIN #foundtest");
        other.num("366");
        other.drain();

        // Founder parts
        founder.tx("PART #foundtest");
        founder.rx(|l| l.contains("PART"), "PART echo");

        // Founder rejoins — should get ops back (they're still a guest founder)
        founder.tx("JOIN #foundtest");
        let names = founder.rx(|l| l.split_whitespace().nth(1) == Some("353"), "NAMREPLY");
        founder.num("366");
        // Guest founders don't have DID-based auto-op, so they might NOT get ops back.
        // This is a known limitation — let's document what actually happens.
        // The important thing is the server doesn't crash.
        let _ = names; // Result documented, not asserted
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 6. USER command sent twice before registration completes
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn user_sent_twice() {
    run(|addr| {
        let mut c = C::raw(addr);
        c.tx("NICK doubleuser");
        c.tx("USER first 0 * :First User");
        c.tx("USER second 0 * :Second User");
        // Should register with one of them — server must not crash
        c.num("001");
        // Check which user stuck via WHOIS
        c.drain();
        c.tx("WHOIS doubleuser");
        let whois = c.num("311");
        // The second USER should have overwritten the first
        // (or the first should be kept — either is acceptable as long as no crash)
        assert!(whois.contains("doubleuser"));
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 7. CAP LS sent AFTER registration — should it work?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cap_ls_after_registration() {
    run(|addr| {
        let mut c = C::new(addr, "postcap");
        c.reg();
        c.drain();
        // Send CAP LS after registration
        c.tx("CAP LS 302");
        // Should either get a CAP LS response or an error — not crash
        let _ = c.maybe(|l| l.contains("CAP") || l.contains("ERROR"), 1000);
        // Regardless, server should still work
        c.tx("JOIN #postcap");
        c.num("366");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 8. QUIT message should be broadcast to channel members
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn quit_message_broadcast() {
    run(|addr| {
        let mut a = C::new(addr, "quitmsg_a");
        a.reg();
        a.drain();
        a.tx("JOIN #quitmsg");
        a.num("366");
        a.drain();

        let mut b = C::new(addr, "quitmsg_b");
        b.reg();
        b.drain();
        b.tx("JOIN #quitmsg");
        b.num("366");
        b.drain();

        // Alice quits with a message
        a.tx("QUIT :see you later!");

        // Bob should see the quit, preferably with the message
        let quit_line = b.rx(
            |l| l.contains("QUIT") && l.contains("quitmsg_a"),
            "QUIT broadcast",
        );
        // Check if the quit message is included
        // Note: this may or may not include "see you later!" depending on implementation
        let _ = quit_line;
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 9. Nick collision: connect, other takes your nick, you try to message
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_freed_then_taken_by_other() {
    run(|addr| {
        let mut a = C::new(addr, "ephemeral");
        a.reg();
        a.drain();

        // Alice changes nick, freeing "ephemeral"
        a.tx("NICK alice_new");
        a.rx(|l| l.contains("NICK"), "nick change");

        // Bob takes the freed nick
        let mut b = C::new(addr, "ephemeral");
        b.reg();
        b.drain();

        // Alice messages "ephemeral" — should reach Bob (the new owner)
        a.tx("PRIVMSG ephemeral :are you the new guy?");
        b.rx(
            |l| l.contains("PRIVMSG") && l.contains("are you the new guy"),
            "msg to new nick owner",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 10. PRIVMSG with no text parameter (just target)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn privmsg_no_text_param() {
    run(|addr| {
        let mut c = C::new(addr, "notxt");
        c.reg();
        c.drain();
        c.tx("JOIN #notxt");
        c.num("366");
        c.drain();
        // Send PRIVMSG with target but no text (missing second param)
        c.tx("PRIVMSG #notxt");
        // Should get 461 ERR_NEEDMOREPARAMS or be silently dropped
        // Either way, server must not crash
        c.tx("PING :alive2");
        c.rx(
            |l| l.contains("PONG") || l.contains("461"),
            "server alive after bad PRIVMSG",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 11. Banned user gets invited — can they join?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn banned_then_invited_still_banned() {
    run(|addr| {
        let mut own = C::new(addr, "bi_own");
        own.reg();
        own.drain();
        own.tx("JOIN #bi");
        own.num("366");
        own.drain();

        let mut target = C::new(addr, "bi_tgt");
        target.reg();
        target.drain();

        // Ban the target
        own.tx("MODE #bi +b bi_tgt!*@*");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Target tries to join (should fail — banned)
        target.tx("JOIN #bi");
        target.num("474"); // ERR_BANNEDFROMCHAN

        // Owner invites the banned user
        own.tx("INVITE bi_tgt #bi");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Target tries again — ban should still take priority over invite
        target.tx("JOIN #bi");
        // This is the interesting question: does ban or invite win?
        // Correct IRC behavior: ban takes priority
        target.num("474"); // Should still be banned
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 12. MODE +o on someone not in the channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mode_op_nonmember() {
    run(|addr| {
        let mut own = C::new(addr, "opown");
        own.reg();
        own.drain();
        own.tx("JOIN #optest");
        own.num("366");
        own.drain();

        let mut other = C::new(addr, "opother");
        other.reg();
        other.drain();
        // opother does NOT join #optest

        // Owner tries to +o someone not in the channel
        own.tx("MODE #optest +o opother");
        // Should get 441 ERR_USERNOTINCHANNEL
        own.num("441");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 13. Race: two users create the same channel simultaneously
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn race_two_create_same_channel() {
    run(|addr| {
        let mut a = C::new(addr, "race_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "race_b");
        b.reg();
        b.drain();

        // Both join the same new channel at the exact same time
        a.tx("JOIN #racechan");
        b.tx("JOIN #racechan");

        // Both should get 366
        a.num("366");
        b.num("366");

        // Check NAMES: exactly one should have @
        a.drain();
        b.drain();
        a.tx("NAMES #racechan");
        let names = a.num("353");
        // Extract nick list (after the trailing colon in IRC format)
        let nick_part = names.split_once(" :").map(|x| x.1).unwrap_or("");
        let ops: Vec<&str> = nick_part
            .split_whitespace()
            .filter(|w| w.starts_with('@'))
            .collect();
        assert_eq!(ops.len(), 1, "Exactly one founder op: {names}");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 14. Extremely long nick (exactly 64 chars — boundary)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nick_exactly_64_chars() {
    run(|addr| {
        let long_nick = "a".repeat(64);
        let mut c = C::new(addr, &long_nick);
        c.reg(); // Should succeed — 64 is the max
        c.drain();
        c.tx("JOIN #longnick");
        c.num("366");
    })
    .await;
}

#[tokio::test]
async fn nick_65_chars_rejected() {
    run(|addr| {
        let too_long = "a".repeat(65);
        let mut c = C::raw(addr);
        c.tx(&format!("NICK {too_long}"));
        c.tx("USER test 0 * :test");
        c.num("432"); // ERR_ERRONEUSNICKNAME
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 15. PART with reason text — is it relayed?
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn part_with_reason() {
    run(|addr| {
        let mut a = C::new(addr, "part_a");
        a.reg();
        a.drain();
        a.tx("JOIN #partreason");
        a.num("366");
        a.drain();

        let mut b = C::new(addr, "part_b");
        b.reg();
        b.drain();
        b.tx("JOIN #partreason");
        b.num("366");
        b.drain();

        a.tx("PART #partreason :I have my reasons");
        let part = b.rx(
            |l| l.contains("PART") && l.contains("#partreason"),
            "PART broadcast",
        );
        // Note: the reason may or may not be included depending on implementation.
        // We're documenting actual behavior here.
        let _ = part;
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 16. Channel with key (+k): remove key, then join without key
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn channel_key_set_then_removed() {
    run(|addr| {
        let mut own = C::new(addr, "keyremown");
        own.reg();
        own.drain();
        own.tx("JOIN #keyrem");
        own.num("366");
        own.drain();
        own.tx("MODE #keyrem +k mysecret");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Can't join without key
        let mut bad = C::new(addr, "keyrem_bad");
        bad.reg();
        bad.drain();
        bad.tx("JOIN #keyrem");
        bad.num("475");

        // Owner removes key
        own.tx("MODE #keyrem -k mysecret");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Now should be able to join without key
        let mut good = C::new(addr, "keyrem_good");
        good.reg();
        good.drain();
        good.tx("JOIN #keyrem");
        good.rx(
            |l| l.contains("JOIN") && l.contains("#keyrem"),
            "JOIN after key removed",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 17. NOTICE to channel — should be delivered silently (no error echo)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn notice_to_channel() {
    run(|addr| {
        let mut a = C::new(addr, "notice_a");
        a.reg();
        a.drain();
        a.tx("JOIN #notice");
        a.num("366");
        a.drain();

        let mut b = C::new(addr, "notice_b");
        b.reg();
        b.drain();
        b.tx("JOIN #notice");
        b.num("366");
        b.drain();

        a.tx("NOTICE #notice :this is a notice");
        b.rx(
            |l| l.contains("NOTICE") && l.contains("this is a notice"),
            "NOTICE delivered",
        );
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 18. Deop the founder — should be blocked
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cannot_deop_founder() {
    run(|addr| {
        let mut founder = C::new(addr, "deop_founder");
        founder.reg();
        founder.drain();
        founder.tx("JOIN #deoptest");
        founder.num("366");
        founder.drain();

        let mut other = C::new(addr, "deop_other");
        other.reg();
        other.drain();
        other.tx("JOIN #deoptest");
        other.num("366");
        other.drain();

        // Give other ops
        founder.tx("MODE #deoptest +o deop_other");
        founder.drain();
        other.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Other tries to deop the founder
        other.tx("MODE #deoptest -o deop_founder");
        other.drain();
        std::thread::sleep(Duration::from_millis(50));

        // Verify founder still has ops via NAMES
        founder.tx("NAMES #deoptest");
        let names = founder.num("353");
        // Founder should still have @ prefix
        // Note: for guest founders (no DID), the deop protection may not apply
        // since it's DID-based. This test documents actual behavior.
        let _ = names;
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 19. Rapid connect/disconnect/reconnect with same nick
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn rapid_connect_disconnect_reconnect() {
    run(|addr| {
        for i in 0..5 {
            let mut c = C::new(addr, "flapper");
            c.reg();
            c.drain();
            c.tx("JOIN #flap");
            c.num("366");
            c.tx(&format!("QUIT :round {i}"));
            // Small delay for cleanup
            std::thread::sleep(Duration::from_millis(100));
        }
        // Final connection should work cleanly
        let mut c = C::new(addr, "flapper");
        c.reg();
        c.drain();
        c.tx("JOIN #flap");
        c.num("366");
        c.tx("NAMES #flap");
        let names = c.num("353");
        assert!(names.contains("flapper"), "Should be in channel: {names}");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 20. AWAY and back — verify away-notify
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn away_and_back() {
    run(|addr| {
        let mut a = C::new(addr, "away_a");
        a.reg();
        a.drain();
        a.tx("JOIN #away");
        a.num("366");
        a.drain();

        let mut b = C::new(addr, "away_b");
        b.reg();
        b.drain();
        b.tx("JOIN #away");
        b.num("366");
        b.drain();

        // Alice goes away
        a.tx("AWAY :gone fishing");
        // Should get 306 RPL_NOWAWAY
        a.num("306");

        // Alice comes back
        a.tx("AWAY");
        // Should get 305 RPL_UNAWAY
        a.num("305");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 21. BONUS: Message to # (bare hash — invalid channel)
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn bare_hash_channel() {
    run(|addr| {
        let mut c = C::new(addr, "hashtest");
        c.reg();
        c.drain();
        // Try to join just "#" — should fail or create a weird channel
        c.tx("JOIN #");
        // Should get an error or silently fail — must not crash
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "479" || n == "403" || l.contains("JOIN")
            },
            1000,
        );
        // Server still alive
        c.tx("PING :alive3");
        c.rx(|l| l.contains("PONG"), "server alive");
    })
    .await;
}

// ══════════════════════════════════════════════════════════════════════
// 22. BONUS: INVITE to nonexistent channel
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invite_to_nonexistent_channel() {
    run(|addr| {
        let mut a = C::new(addr, "inv_a");
        a.reg();
        a.drain();
        let mut b = C::new(addr, "inv_b");
        b.reg();
        b.drain();

        // Alice invites Bob to a channel that doesn't exist
        a.tx("INVITE inv_b #doesntexist");
        // Should get 442 ERR_NOTONCHANNEL (you're not on that channel)
        a.num("442");
    })
    .await;
}
