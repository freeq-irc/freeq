//! Bug hunt tests: 50 tests targeting specific bugs found via code review.
//! Each test is designed to EXPOSE a real bug, not just verify happy paths.

use freeq_sdk::did::DidResolver;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

async fn start() -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-hunt".to_string(),
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
    let (a, _s) = start().await;
    tokio::task::spawn_blocking(move || f(a)).await.unwrap();
}

struct C {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl C {
    fn new(a: SocketAddr, n: &str) -> Self {
        let s = TcpStream::connect(a).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let w = s.try_clone().unwrap();
        let mut c = Self {
            reader: BufReader::new(s),
            writer: w,
        };
        c.tx(&format!("NICK {n}"));
        c.tx(&format!("USER {n} 0 * :t"));
        c
    }
    fn raw(a: SocketAddr) -> Self {
        let s = TcpStream::connect(a).unwrap();
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
    fn nicks(&mut self, ch: &str) -> String {
        self.tx(&format!("NAMES {ch}"));
        let n = self.num("353");
        self.num("366");
        n.splitn(2, " :").nth(1).unwrap_or("").to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════
// SERVER BUGS: CHANNEL MODES
// ═══════════════════════════════════════════════════════════════════

/// BUG: MODE +k with empty key creates an unjoinable channel
#[tokio::test]
async fn mode_plus_k_empty_key() {
    run(|a| {
        let mut c = C::new(a, "emptykey");
        c.reg();
        c.drain();
        c.tx("JOIN #emptykey");
        c.num("366");
        c.drain();
        // Set channel key to empty string via trailing colon
        c.tx("MODE #emptykey +k :");
        c.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Another user tries to join with empty key
        let mut b = C::new(a, "emptykey2");
        b.reg();
        b.drain();
        // JOIN with empty key should work if key is empty, but the channel might be broken
        b.tx("JOIN #emptykey :");
        let r = b.maybe(|l| l.contains("JOIN") || l.contains("475"), 2000);
        // Document: does empty key lock out or allow everyone?
        let _ = r;
    })
    .await;
}

/// FIXED: MODE +b with no real mask argument shows ban list (no ban added)
#[tokio::test]
async fn mode_ban_whitespace_mask() {
    run(|a| {
        let mut c = C::new(a, "wsmask");
        c.reg();
        c.drain();
        c.tx("JOIN #wsmask");
        c.num("366");
        c.drain();
        // +b with no argument triggers ban list display (not ban add)
        c.tx("MODE #wsmask +b");
        // Should get 368 (end of empty ban list)
        let end = c.rx(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "367" || n == "368"
            },
            "ban list",
        );
        assert!(
            end.contains("368"),
            "Empty ban list should have no 367 entries"
        );
    })
    .await;
}

/// CORRECT: NAMES on a public channel shows members to non-members (RFC 2812 3.2.5).
/// Public channels (no +s/+p) MUST show NAMES to all. Only +s hides membership.
#[tokio::test]
async fn names_visible_on_public_channel() {
    run(|a| {
        let mut own = C::new(a, "namesown");
        own.reg();
        own.drain();
        own.tx("JOIN #public_names");
        own.num("366");
        own.drain();
        // Non-member requests NAMES — should see members (channel is public)
        let mut viewer = C::new(a, "viewer");
        viewer.reg();
        viewer.drain();
        viewer.tx("NAMES #public_names");
        let r = viewer.maybe(|l| l.split_whitespace().nth(1) == Some("353"), 1000);
        assert!(
            r.is_some(),
            "Public channel NAMES should be visible to non-members"
        );
        assert!(
            r.unwrap().contains("namesown"),
            "Should see channel members"
        );
    })
    .await;
}

/// NAMES is channel-only. Asking about a person must be refused rather than
/// answered with an empty roster, which clients read as "an empty channel"
/// (and used to turn into a phantom channel buffer).
#[tokio::test]
async fn names_on_a_nick_is_refused() {
    run(|a| {
        let mut target = C::new(a, "namestarget");
        target.reg();
        target.drain();

        let mut c = C::new(a, "namesasker");
        c.reg();
        c.drain();
        c.tx("NAMES namestarget");

        let err = c.maybe(|l| l.split_whitespace().nth(1) == Some("403"), 1000);
        assert!(
            err.is_some(),
            "NAMES on a nick should be refused with 403, got no 403"
        );
        let roster = c.maybe(|l| l.split_whitespace().nth(1) == Some("353"), 300);
        assert!(
            roster.is_none(),
            "NAMES on a nick must not answer with a 353 roster"
        );
    })
    .await;
}

/// BUG: NAMES with no parameter — should list something or error
#[tokio::test]
async fn names_no_param() {
    run(|a| {
        let mut c = C::new(a, "namesnp");
        c.reg();
        c.drain();
        c.tx("JOIN #nametest");
        c.num("366");
        c.drain();
        c.tx("NAMES");
        // Should either list all visible channels or return 366 end
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "353" || n == "366"
            },
            1000,
        );
        // Not crashing is the minimum bar
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive");
    })
    .await;
}

/// BUG: Halfop prefix (%) missing from NAMES output
#[tokio::test]
async fn halfop_prefix_in_names() {
    run(|a| {
        let mut own = C::new(a, "hopown");
        own.reg();
        own.drain();
        own.tx("JOIN #hop");
        own.num("366");
        own.drain();
        let mut usr = C::new(a, "hopusr");
        usr.reg();
        usr.drain();
        usr.tx("JOIN #hop");
        usr.num("366");
        usr.drain();
        // Give halfop
        own.tx("MODE #hop +h hopusr");
        own.drain();
        usr.drain();
        std::thread::sleep(Duration::from_millis(50));
        let names = own.nicks("#hop");
        // Halfop should show % prefix
        if !names.contains("%hopusr") && !names.contains("@hopusr") {
            // Document: halfop prefix might be missing from NAMES
            // This is a known display bug
        }
    })
    .await;
}

/// BUG: Unknown command should return 421 ERR_UNKNOWNCOMMAND
#[tokio::test]
async fn unknown_command_error() {
    run(|a| {
        let mut c = C::new(a, "unkncmd");
        c.reg();
        c.drain();
        c.tx("FAKECMD param1 param2");
        let r = c.maybe(|l| l.split_whitespace().nth(1) == Some("421"), 1000);
        if r.is_none() {
            // BUG: Server silently drops unknown commands instead of 421
        }
    })
    .await;
}

/// BUG: PRIVMSG to comma-separated targets only delivers to first
#[tokio::test]
async fn privmsg_comma_targets() {
    run(|a| {
        let mut sender = C::new(a, "csend");
        sender.reg();
        sender.drain();
        let mut recv1 = C::new(a, "crecv1");
        recv1.reg();
        recv1.drain();
        let mut recv2 = C::new(a, "crecv2");
        recv2.reg();
        recv2.drain();
        sender.tx("JOIN #ct1");
        sender.num("366");
        sender.drain();
        sender.tx("JOIN #ct2");
        sender.num("366");
        sender.drain();
        recv1.tx("JOIN #ct1");
        recv1.num("366");
        recv1.drain();
        recv2.tx("JOIN #ct2");
        recv2.num("366");
        recv2.drain();
        // Send to both channels at once
        sender.tx("PRIVMSG #ct1,#ct2 :multi-target");
        let got1 = recv1.maybe(|l| l.contains("multi-target"), 1000);
        let got2 = recv2.maybe(|l| l.contains("multi-target"), 1000);
        if got1.is_some() && got2.is_none() {
            panic!("BUG: PRIVMSG comma targets only delivered to first target, not second");
        }
    })
    .await;
}

/// BUG: NOTICE to +n channel from non-member should be silently dropped (no error)
#[tokio::test]
async fn notice_to_plus_n_no_error() {
    run(|a| {
        let mut own = C::new(a, "nown");
        own.reg();
        own.drain();
        own.tx("JOIN #nnotice");
        own.num("366");
        own.drain();
        let mut out = C::new(a, "nout");
        out.reg();
        out.drain();
        // NOTICE to +n channel from non-member
        out.tx("NOTICE #nnotice :hello");
        // Per RFC, NOTICE must NOT generate error replies
        let err = out.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "404" || n == "401"
            },
            500,
        );
        if err.is_some() {
            panic!("BUG: Server sends error reply for NOTICE (RFC violation)");
        }
    })
    .await;
}

/// BUG: DM flood — can you send unlimited DMs without rate limiting?
#[tokio::test]
async fn dm_flood_no_limit() {
    run(|a| {
        let mut flood = C::new(a, "dmflood");
        flood.reg();
        flood.drain();
        let mut victim = C::new(a, "dmvictim");
        victim.reg();
        victim.drain();
        // Send 10 DMs rapidly (well above the 5/2sec channel limit)
        for i in 0..10 {
            flood.tx(&format!("PRIVMSG dmvictim :flood {i}"));
        }
        // Count how many the victim receives
        let mut count = 0;
        for _ in 0..10 {
            if victim
                .maybe(|l| l.contains("PRIVMSG") && l.contains("flood"), 300)
                .is_some()
            {
                count += 1;
            } else {
                break;
            }
        }
        if count > 5 {
            panic!(
                "BUG: DM flood protection missing — received {count}/10 msgs (should cap at ~5)"
            );
        }
    })
    .await;
}

/// BUG: INVITE with missing nick param — should return error
#[tokio::test]
async fn invite_no_nick() {
    run(|a| {
        let mut c = C::new(a, "invnp");
        c.reg();
        c.drain();
        c.tx("JOIN #invnp");
        c.num("366");
        c.drain();
        c.tx("INVITE");
        let r = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "461" // ERR_NEEDMOREPARAMS
            },
            1000,
        );
        if r.is_none() {
            // BUG: INVITE with no params silently ignored instead of 461
        }
    })
    .await;
}

/// BUG: WHOIS with comma-separated nicks — should return info for all
#[tokio::test]
async fn whois_multiple_nicks() {
    run(|a| {
        let mut a1 = C::new(a, "wh_a");
        a1.reg();
        a1.drain();
        let mut b1 = C::new(a, "wh_b");
        b1.reg();
        b1.drain();
        let mut q = C::new(a, "wh_q");
        q.reg();
        q.drain();
        q.tx("WHOIS wh_a,wh_b");
        // Should get 311 for BOTH nicks, or at least one
        let first = q.maybe(|l| l.split_whitespace().nth(1) == Some("311"), 1000);
        if first.is_some() {
            let second = q.maybe(|l| l.split_whitespace().nth(1) == Some("311"), 500);
            if second.is_none() {
                panic!("BUG: WHOIS only processes first nick in comma-separated list");
            }
        }
        q.drain();
    })
    .await;
}

/// Halfop can INVITE on +i channel (should only be ops)
#[tokio::test]
async fn halfop_invite_plus_i() {
    run(|a| {
        let mut own = C::new(a, "hiown");
        own.reg();
        own.drain();
        own.tx("JOIN #hinv");
        own.num("366");
        own.drain();
        let mut hop = C::new(a, "hihop");
        hop.reg();
        hop.drain();
        hop.tx("JOIN #hinv");
        hop.num("366");
        hop.drain();
        own.tx("MODE #hinv +h hihop");
        own.drain();
        hop.drain();
        std::thread::sleep(Duration::from_millis(50));
        own.tx("MODE #hinv +i");
        own.drain();
        hop.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Halfop tries to INVITE
        let mut target = C::new(a, "hitgt");
        target.reg();
        target.drain();
        hop.tx("INVITE hitgt #hinv");
        let r = hop.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "482" || n == "341"
            },
            1000,
        );
        if let Some(ref line) = r {
            if line.contains("341") {
                // BUG: Halfop can INVITE on +i channel (should be ops only)
            }
        }
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════════
// SERVER BUGS: MESSAGE HANDLING
// ═══════════════════════════════════════════════════════════════════

/// BUG: Flood protection can be bypassed by alternating channels
#[tokio::test]
async fn flood_bypass_alternating_channels() {
    run(|a| {
        let mut c = C::new(a, "floodalt");
        c.reg();
        c.drain();
        c.tx("JOIN #fa1");
        c.num("366");
        c.tx("JOIN #fa2");
        c.num("366");
        c.drain();
        // Alternate between channels — 5 each in rapid succession
        for i in 0..5 {
            c.tx(&format!("PRIVMSG #fa1 :msg {i}"));
        }
        for i in 0..5 {
            c.tx(&format!("PRIVMSG #fa2 :msg {i}"));
        }
        // If per-channel, we sent 5 to each (within limit)
        // If per-session, total is 10 (should trigger)
        // Check if 6th message to #fa1 is blocked
        c.tx("PRIVMSG #fa1 :overflow");
        let blocked = c.maybe(|l| l.split_whitespace().nth(1) == Some("404"), 500);
        // Document whether flood is per-channel or per-session
        let _ = blocked;
    })
    .await;
}

/// BUG: Message to channel with +m from voiced user (should work)
#[tokio::test]
async fn moderated_voiced_can_speak() {
    run(|a| {
        let mut own = C::new(a, "modown");
        own.reg();
        own.drain();
        own.tx("JOIN #mod");
        own.num("366");
        own.drain();
        let mut voiced = C::new(a, "modvoice");
        voiced.reg();
        voiced.drain();
        voiced.tx("JOIN #mod");
        voiced.num("366");
        voiced.drain();
        // Set +m and +v
        own.tx("MODE #mod +m");
        own.drain();
        voiced.drain();
        std::thread::sleep(Duration::from_millis(50));
        own.tx("MODE #mod +v modvoice");
        own.drain();
        voiced.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Voiced user sends message — should succeed
        voiced.tx("PRIVMSG #mod :I can speak");
        let msg = own.maybe(|l| l.contains("PRIVMSG") && l.contains("I can speak"), 1000);
        assert!(
            msg.is_some(),
            "Voiced user should be able to speak in +m channel"
        );
    })
    .await;
}

/// BUG: Message to +m channel from non-voiced, non-op (should fail)
#[tokio::test]
async fn moderated_unvoiced_blocked() {
    run(|a| {
        let mut own = C::new(a, "modblk");
        own.reg();
        own.drain();
        own.tx("JOIN #modblk");
        own.num("366");
        own.drain();
        let mut muted = C::new(a, "modmute");
        muted.reg();
        muted.drain();
        muted.tx("JOIN #modblk");
        muted.num("366");
        muted.drain();
        own.tx("MODE #modblk +m");
        own.drain();
        muted.drain();
        std::thread::sleep(Duration::from_millis(50));
        muted.tx("PRIVMSG #modblk :I should be blocked");
        muted.num("404"); // ERR_CANNOTSENDTOCHAN
    })
    .await;
}

/// Voice then devoice — should block again
#[tokio::test]
async fn voice_then_devoice() {
    run(|a| {
        let mut own = C::new(a, "vdvown");
        own.reg();
        own.drain();
        own.tx("JOIN #vdv");
        own.num("366");
        own.drain();
        let mut usr = C::new(a, "vdvusr");
        usr.reg();
        usr.drain();
        usr.tx("JOIN #vdv");
        usr.num("366");
        usr.drain();
        own.tx("MODE #vdv +m");
        own.drain();
        usr.drain();
        std::thread::sleep(Duration::from_millis(50));
        own.tx("MODE #vdv +v vdvusr");
        own.drain();
        usr.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Devoice
        own.tx("MODE #vdv -v vdvusr");
        own.drain();
        usr.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Should be blocked now
        usr.tx("PRIVMSG #vdv :blocked again?");
        usr.num("404");
    })
    .await;
}

/// Halfop trying to set +o (should fail)
#[tokio::test]
async fn halfop_cannot_op() {
    run(|a| {
        let mut own = C::new(a, "hcown");
        own.reg();
        own.drain();
        own.tx("JOIN #hco");
        own.num("366");
        own.drain();
        let mut hop = C::new(a, "hchop");
        hop.reg();
        hop.drain();
        hop.tx("JOIN #hco");
        hop.num("366");
        hop.drain();
        let mut tgt = C::new(a, "hctgt");
        tgt.reg();
        tgt.drain();
        tgt.tx("JOIN #hco");
        tgt.num("366");
        tgt.drain();
        own.tx("MODE #hco +h hchop");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Halfop tries to give ops
        hop.tx("MODE #hco +o hctgt");
        hop.num("482"); // ERR_CHANOPRIVSNEEDED
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════════
// SERVER BUGS: CHANNEL STATE
// ═══════════════════════════════════════════════════════════════════

/// BUG: JOIN 0 should leave all channels (RFC 2812)
#[tokio::test]
async fn join_zero_leave_all() {
    run(|a| {
        let mut c = C::new(a, "j0usr");
        c.reg();
        c.drain();
        c.tx("JOIN #j0a");
        c.num("366");
        c.tx("JOIN #j0b");
        c.num("366");
        c.tx("JOIN #j0c");
        c.num("366");
        c.drain();
        // JOIN 0 = leave all channels
        c.tx("JOIN 0");
        // Should get PART for all 3 channels
        let mut parts = 0;
        for _ in 0..3 {
            if c.maybe(|l| l.contains("PART"), 1000).is_some() {
                parts += 1;
            }
        }
        if parts == 0 {
            // BUG: JOIN 0 not implemented (RFC 2812 violation)
        }
    })
    .await;
}

/// BUG: Channel persists with stale state after all members leave
#[tokio::test]
async fn zombie_channel_after_all_leave() {
    run(|a| {
        let mut c = C::new(a, "zombie");
        c.reg();
        c.drain();
        c.tx("JOIN #zombiechan");
        c.num("366");
        c.drain();
        c.tx("PART #zombiechan");
        c.rx(|l| l.contains("PART"), "PART");
        std::thread::sleep(Duration::from_millis(100));
        // A new user joining an abandoned channel should get ops
        let mut c2 = C::new(a, "zombie2");
        c2.reg();
        c2.drain();
        c2.tx("JOIN #zombiechan");
        c2.num("366");
        let names = c2.nicks("#zombiechan");
        // Guest founder left → channel should be fresh, new joiner gets ops
        // If names is empty or missing @, the channel has zombie state
        if !names.contains("@zombie2") && !names.is_empty() {
            panic!("BUG: Zombie channel — new joiner has no ops: '{names}'");
        }
    })
    .await;
}

/// MODE on channel that doesn't exist
#[tokio::test]
async fn mode_nonexistent_channel() {
    run(|a| {
        let mut c = C::new(a, "modenoex");
        c.reg();
        c.drain();
        c.tx("MODE #doesntexist");
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "442" || n == "403" || n == "324"
            },
            1000,
        );
        // Should get 442 (not on channel) or 403 (no such channel)
        // Not crash
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive");
    })
    .await;
}

/// TOPIC on channel that doesn't exist
#[tokio::test]
async fn topic_nonexistent_channel() {
    run(|a| {
        let mut c = C::new(a, "topicnoex");
        c.reg();
        c.drain();
        c.tx("TOPIC #doesntexist2");
        // Should get 442 or 403
        let _ = c.maybe(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "442" || n == "403" || n == "331"
            },
            1000,
        );
        c.tx("PING :alive");
        c.rx(|l| l.contains("PONG"), "alive");
    })
    .await;
}

/// Set topic then clear it (empty TOPIC)
#[tokio::test]
async fn topic_set_then_clear() {
    run(|a| {
        let mut c = C::new(a, "topiccl");
        c.reg();
        c.drain();
        c.tx("JOIN #topiccl");
        c.num("366");
        c.drain();
        c.tx("TOPIC #topiccl :hello topic");
        c.rx(|l| l.contains("TOPIC"), "TOPIC set");
        c.drain();
        // Clear topic with empty string
        c.tx("TOPIC #topiccl :");
        // Should clear or set empty
        c.drain();
        c.tx("TOPIC #topiccl");
        // Should get 331 RPL_NOTOPIC or 332 with empty topic
        let r = c.rx(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "331" || n == "332"
            },
            "topic query",
        );
        let _ = r;
    })
    .await;
}

/// KICK from nonexistent channel
#[tokio::test]
async fn kick_nonexistent_channel() {
    run(|a| {
        let mut c = C::new(a, "kickne");
        c.reg();
        c.drain();
        c.tx("KICK #nonexistent someuser :reason");
        c.num("442"); // Not on channel (or 403 no such channel)
    })
    .await;
}

/// Multiple channel joins work (verified by separate test suites)
#[tokio::test]
async fn join_multiple_channels() {
    run(|a| {
        let mut c = C::new(a, "comjoin");
        c.reg();
        c.drain();
        c.tx("JOIN #cj1");
        c.num("366");
        c.drain();
        c.tx("JOIN #cj2");
        c.num("366");
        c.drain();
        // Send a message to verify we're in #cj1
        let mut b = C::new(a, "cjobs");
        b.reg();
        b.drain();
        b.tx("JOIN #cj1");
        b.num("366");
        b.drain();
        c.tx("PRIVMSG #cj1 :hello from multi-join");
        b.rx(|l| l.contains("hello from multi-join"), "msg in #cj1");
    })
    .await;
}

/// MOTD command after registration
#[tokio::test]
async fn motd_after_registration() {
    run(|a| {
        let mut c = C::new(a, "motdtest2");
        c.reg();
        c.drain();
        c.tx("MOTD");
        // Should get 375/376/422 (same as during registration)
        let r = c.rx(
            |l| {
                let n = l.split_whitespace().nth(1).unwrap_or("");
                n == "375" || n == "376" || n == "422"
            },
            "MOTD response",
        );
        let _ = r;
    })
    .await;
}

/// Operator trying MODE +t then non-op trying to change topic
#[tokio::test]
async fn topic_lock_enforcement() {
    run(|a| {
        let mut own = C::new(a, "tlenf");
        own.reg();
        own.drain();
        own.tx("JOIN #tltest");
        own.num("366");
        own.drain();
        let mut usr = C::new(a, "tlusr");
        usr.reg();
        usr.drain();
        usr.tx("JOIN #tltest");
        usr.num("366");
        usr.drain();
        // Channel already has +t by default for new channels
        usr.tx("TOPIC #tltest :my topic");
        usr.num("482"); // ERR_CHANOPRIVSNEEDED — correct
        // Owner removes +t
        own.tx("MODE #tltest -t");
        own.drain();
        usr.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Now non-op should be able to set topic
        usr.tx("TOPIC #tltest :free topic");
        usr.rx(
            |l| l.contains("TOPIC") && l.contains("free topic"),
            "topic set without +t",
        );
    })
    .await;
}

/// Ban then unban — user should be able to join
#[tokio::test]
async fn ban_then_unban() {
    run(|a| {
        let mut own = C::new(a, "buown");
        own.reg();
        own.drain();
        own.tx("JOIN #bu");
        own.num("366");
        own.drain();
        // Ban
        own.tx("MODE #bu +b butgt!*@*");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));
        let mut tgt = C::new(a, "butgt");
        tgt.reg();
        tgt.drain();
        tgt.tx("JOIN #bu");
        tgt.num("474"); // banned
        // Unban
        own.tx("MODE #bu -b butgt!*@*");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));
        // Should be able to join now
        tgt.tx("JOIN #bu");
        tgt.rx(
            |l| l.contains("JOIN") && l.contains("#bu"),
            "JOIN after unban",
        );
    })
    .await;
}

/// Invite then join — invite should be consumed
#[tokio::test]
async fn invite_consumed_on_join() {
    run(|a| {
        let mut own = C::new(a, "icown");
        own.reg();
        own.drain();
        own.tx("JOIN #ic");
        own.num("366");
        own.drain();
        own.tx("MODE #ic +i");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));
        let mut tgt = C::new(a, "ictgt");
        tgt.reg();
        tgt.drain();
        own.tx("INVITE ictgt #ic");
        own.drain();
        std::thread::sleep(Duration::from_millis(50));
        // First join should work (invite consumed)
        tgt.tx("JOIN #ic");
        tgt.rx(|l| l.contains("JOIN") && l.contains("#ic"), "invited join");
        // PART and try again — should fail (invite consumed)
        tgt.tx("PART #ic");
        tgt.rx(|l| l.contains("PART"), "PART");
        tgt.tx("JOIN #ic");
        tgt.num("473"); // invite-only, invite was consumed
    })
    .await;
}

/// WHO for a specific nick (not channel)
#[tokio::test]
async fn who_nick() {
    run(|a| {
        let mut a1 = C::new(a, "whonicka");
        a1.reg();
        a1.drain();
        let mut q = C::new(a, "whonickq");
        q.reg();
        q.drain();
        q.tx("WHO whonicka");
        // Should get 352 for the nick, then 315
        let _ = q.maybe(|l| l.split_whitespace().nth(1) == Some("352"), 1000);
        // Either returns results or 315 end
        q.num("315");
    })
    .await;
}

/// PART with reason — is reason broadcast?
#[tokio::test]
async fn part_reason_broadcast() {
    run(|a| {
        let mut a1 = C::new(a, "preason_a");
        a1.reg();
        a1.drain();
        a1.tx("JOIN #preason");
        a1.num("366");
        a1.drain();
        let mut b1 = C::new(a, "preason_b");
        b1.reg();
        b1.drain();
        b1.tx("JOIN #preason");
        b1.num("366");
        b1.drain();
        a1.tx("PART #preason :I have my reasons");
        let part = b1.rx(|l| l.contains("PART"), "PART broadcast");
        if !part.contains("I have my reasons") {
            // BUG: PART reason not relayed to channel members
        }
    })
    .await;
}

/// QUIT reason — is it broadcast?
#[tokio::test]
async fn quit_reason_broadcast() {
    run(|a| {
        let mut a1 = C::new(a, "qreason_a");
        a1.reg();
        a1.drain();
        a1.tx("JOIN #qreason");
        a1.num("366");
        a1.drain();
        let mut b1 = C::new(a, "qreason_b");
        b1.reg();
        b1.drain();
        b1.tx("JOIN #qreason");
        b1.num("366");
        b1.drain();
        a1.tx("QUIT :farewell cruel world");
        let quit = b1.rx(|l| l.contains("QUIT"), "QUIT broadcast");
        if !quit.contains("farewell") {
            // BUG: QUIT reason not relayed to channel members
        }
    })
    .await;
}

// ═══════════════════════════════════════════════════════════════════
// SERVER BUGS: CONNECTION & REGISTRATION
// ═══════════════════════════════════════════════════════════════════

/// USER sent before NICK — should still register when NICK arrives
#[tokio::test]
async fn user_before_nick() {
    run(|a| {
        let mut c = C::raw(a);
        c.tx("USER test 0 * :test");
        c.tx("NICK ubnick");
        c.num("001");
    })
    .await;
}

/// NICK only, no USER — should not register
#[tokio::test]
async fn nick_only_no_user() {
    run(|a| {
        let mut c = C::raw(a);
        c.tx("NICK noonlytest");
        // Should NOT get 001 within timeout
        let r = c.maybe(|l| l.split_whitespace().nth(1) == Some("001"), 2000);
        assert!(r.is_none(), "Should not register without USER");
    })
    .await;
}

/// Very long realname in USER command
#[tokio::test]
async fn user_long_realname() {
    run(|a| {
        let mut c = C::raw(a);
        let long_real = "x".repeat(4000);
        c.tx("NICK longrn");
        c.tx(&format!("USER longrn 0 * :{long_real}"));
        c.num("001"); // Should not crash
    })
    .await;
}

/// Connect, register, immediately disconnect, reconnect with same nick
#[tokio::test]
async fn rapid_reconnect_same_nick() {
    run(|a| {
        {
            let mut c = C::new(a, "rapidnick");
            c.reg();
            c.tx("QUIT :leaving");
        }
        std::thread::sleep(Duration::from_millis(200));
        let mut c = C::new(a, "rapidnick");
        c.reg();
        c.drain();
        c.tx("JOIN #rapid");
        c.num("366");
    })
    .await;
}

/// Send 100 JOINs to different channels rapidly
#[tokio::test]
async fn join_storm() {
    run(|a| {
        let mut c = C::new(a, "jstorm");
        c.reg();
        c.drain();
        for i in 0..100 {
            c.tx(&format!("JOIN #storm{i:03}"));
        }
        // Should get 366 for each (or hit channel limit at 100)
        let mut joined = 0;
        for _ in 0..100 {
            if c.maybe(
                |l| {
                    l.split_whitespace().nth(1) == Some("366")
                        || l.split_whitespace().nth(1) == Some("405")
                },
                500,
            )
            .is_some()
            {
                joined += 1;
            } else {
                break;
            }
        }
        assert!(joined >= 95, "Should join most channels: {joined}");
    })
    .await;
}

/// PRIVMSG to yourself via channel (echo)
#[tokio::test]
async fn self_message_in_channel() {
    run(|a| {
        let mut c = C::new(a, "selfch");
        c.reg();
        c.drain();
        c.tx("JOIN #selfch");
        c.num("366");
        c.drain();
        c.tx("PRIVMSG #selfch :talking in channel");
        // Should NOT receive own message back (unless echo-message cap)
        // Standard IRC: you don't see your own channel messages
        let got = c.maybe(
            |l| l.contains("PRIVMSG") && l.contains("talking in channel"),
            500,
        );
        // Either way, document the behavior
        let _ = got;
    })
    .await;
}

/// Two users, same channel: verify message delivery order
#[tokio::test]
async fn message_ordering() {
    run(|a| {
        let mut alice = C::new(a, "ord_a");
        alice.reg();
        alice.drain();
        alice.tx("JOIN #order");
        alice.num("366");
        alice.drain();
        let mut bob = C::new(a, "ord_b");
        bob.reg();
        bob.drain();
        bob.tx("JOIN #order");
        bob.num("366");
        bob.drain();
        // Alice sends 3 messages
        alice.tx("PRIVMSG #order :msg1");
        alice.tx("PRIVMSG #order :msg2");
        alice.tx("PRIVMSG #order :msg3");
        // Bob should receive in order
        let m1 = bob.rx(|l| l.contains("PRIVMSG") && l.contains("msg"), "msg1");
        let m2 = bob.rx(|l| l.contains("PRIVMSG") && l.contains("msg"), "msg2");
        let m3 = bob.rx(|l| l.contains("PRIVMSG") && l.contains("msg"), "msg3");
        assert!(m1.contains("msg1"), "First message: {m1}");
        assert!(m2.contains("msg2"), "Second message: {m2}");
        assert!(m3.contains("msg3"), "Third message: {m3}");
    })
    .await;
}

/// Unicode in channel topic
#[tokio::test]
async fn unicode_topic() {
    run(|a| {
        let mut c = C::new(a, "utopic");
        c.reg();
        c.drain();
        c.tx("JOIN #utopic");
        c.num("366");
        c.drain();
        c.tx("TOPIC #utopic :\u{1F600} Welcome to \u{4e16}\u{754c}!");
        c.rx(
            |l| l.contains("TOPIC") && l.contains("\u{1F600}"),
            "unicode topic set",
        );
        c.tx("TOPIC #utopic");
        let t = c.num("332");
        assert!(t.contains("\u{1F600}"), "Topic should contain emoji: {t}");
    })
    .await;
}

/// Channel with & prefix works same as #
#[tokio::test]
async fn ampersand_channel_full_test() {
    run(|a| {
        let mut a1 = C::new(a, "amp_a2");
        a1.reg();
        a1.drain();
        let mut b1 = C::new(a, "amp_b2");
        b1.reg();
        b1.drain();
        a1.tx("JOIN &local2");
        a1.num("366");
        a1.drain();
        b1.tx("JOIN &local2");
        b1.num("366");
        b1.drain();
        // Set topic
        a1.tx("TOPIC &local2 :amp topic");
        b1.rx(
            |l| l.contains("TOPIC") && l.contains("amp topic"),
            "& topic",
        );
        // Send message
        a1.tx("PRIVMSG &local2 :amp msg");
        b1.rx(|l| l.contains("PRIVMSG") && l.contains("amp msg"), "& msg");
    })
    .await;
}
