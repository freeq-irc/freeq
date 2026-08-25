//! Non-members must not be able to enumerate the roster of a restricted
//! (+i/+k/+E) channel via NAMES or WHO. Both answer exactly as they would
//! for a channel that does not exist, so the reply also does not reveal
//! whether the name is in use.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use freeq_sdk::did::DidResolver;

async fn start_server() -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-names-who".to_string(),
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

    /// Read until the given end numeric arrives, returning every line of the
    /// other numeric collected on the way. Used to assert a WHO/NAMES answer
    /// carries no roster rows before its end marker.
    fn collect_until(&mut self, collect: &str, end: &str) -> Vec<String> {
        let mut rows = Vec::new();
        loop {
            let line = self.expect(
                |l| {
                    let code = l.split_whitespace().nth(1);
                    code == Some(collect) || code == Some(end)
                },
                &format!("{collect} or {end}"),
            );
            if line.split_whitespace().nth(1) == Some(end) {
                return rows;
            }
            rows.push(line);
        }
    }
}

/// Create a channel with the given restrictive mode and one member (alice).
fn restricted_channel(addr: SocketAddr, channel: &str, mode: &str) -> C {
    let mut alice = C::connect(addr, "alice");
    alice.reg();
    alice.send(&format!("JOIN {channel}"));
    alice.num("366");
    alice.send(&format!("MODE {channel} {mode}"));
    alice.expect(
        |l| l.contains("MODE") && l.contains(channel),
        "mode confirmation",
    );
    alice
}

#[tokio::test]
async fn names_on_keyed_channel_hides_members_from_non_members() {
    run(|addr| {
        let _alice = restricted_channel(addr, "#priv", "+k sekrit");
        let mut bob = C::connect(addr, "bob");
        bob.reg();
        bob.send("NAMES #priv");
        let rows = bob.collect_until("353", "366");
        for row in rows {
            assert!(
                !row.contains("alice"),
                "non-member NAMES leaked roster: {row}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn names_on_invite_only_channel_hides_members_from_non_members() {
    run(|addr| {
        let _alice = restricted_channel(addr, "#invite", "+i");
        let mut bob = C::connect(addr, "bob");
        bob.reg();
        bob.send("NAMES #invite");
        let rows = bob.collect_until("353", "366");
        for row in rows {
            assert!(
                !row.contains("alice"),
                "non-member NAMES leaked roster: {row}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn names_on_restricted_channel_matches_nonexistent_channel() {
    run(|addr| {
        let _alice = restricted_channel(addr, "#priv", "+k sekrit");
        let mut bob = C::connect(addr, "bob");
        bob.reg();

        bob.send("NAMES #priv");
        let restricted_rows = bob.collect_until("353", "366");
        bob.send("NAMES #no-such-channel");
        let missing_rows = bob.collect_until("353", "366");

        let strip = |rows: Vec<String>| -> Vec<String> {
            rows.into_iter()
                .map(|r| r.split(':').next_back().unwrap_or_default().to_string())
                .collect()
        };
        assert_eq!(
            strip(restricted_rows),
            strip(missing_rows),
            "restricted channel is distinguishable from a nonexistent one"
        );
    })
    .await;
}

#[tokio::test]
async fn who_on_keyed_channel_hides_members_from_non_members() {
    run(|addr| {
        let _alice = restricted_channel(addr, "#priv", "+k sekrit");
        let mut bob = C::connect(addr, "bob");
        bob.reg();
        bob.send("WHO #priv");
        let rows = bob.collect_until("352", "315");
        assert!(rows.is_empty(), "non-member WHO leaked roster: {rows:?}");
    })
    .await;
}

#[tokio::test]
async fn who_on_invite_only_channel_hides_members_from_non_members() {
    run(|addr| {
        let _alice = restricted_channel(addr, "#invite", "+i");
        let mut bob = C::connect(addr, "bob");
        bob.reg();
        bob.send("WHO #invite");
        let rows = bob.collect_until("352", "315");
        assert!(rows.is_empty(), "non-member WHO leaked roster: {rows:?}");
    })
    .await;
}

#[tokio::test]
async fn members_still_see_restricted_channel_roster() {
    run(|addr| {
        let mut alice = restricted_channel(addr, "#priv", "+k sekrit");
        let mut bob = C::connect(addr, "bob");
        bob.reg();
        bob.send("JOIN #priv sekrit");
        bob.num("366");

        bob.send("NAMES #priv");
        let names = bob.collect_until("353", "366");
        assert!(
            names.iter().any(|r| r.contains("alice")),
            "member NAMES lost the roster: {names:?}"
        );

        bob.send("WHO #priv");
        let who = bob.collect_until("352", "315");
        assert!(
            who.iter().any(|r| r.contains("alice")),
            "member WHO lost the roster: {who:?}"
        );

        // The member who set the mode still sees it too.
        alice.send("NAMES #priv");
        let names = alice.collect_until("353", "366");
        assert!(names.iter().any(|r| r.contains("bob")));
    })
    .await;
}

#[tokio::test]
async fn public_channel_roster_stays_visible_to_non_members() {
    run(|addr| {
        let mut alice = C::connect(addr, "alice");
        alice.reg();
        alice.send("JOIN #open");
        alice.num("366");

        let mut bob = C::connect(addr, "bob");
        bob.reg();

        bob.send("NAMES #open");
        let names = bob.collect_until("353", "366");
        assert!(
            names.iter().any(|r| r.contains("alice")),
            "public NAMES broke for non-members: {names:?}"
        );

        bob.send("WHO #open");
        let who = bob.collect_until("352", "315");
        assert!(
            who.iter().any(|r| r.contains("alice")),
            "public WHO broke for non-members: {who:?}"
        );
    })
    .await;
}
