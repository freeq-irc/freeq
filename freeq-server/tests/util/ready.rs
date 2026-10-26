//! Waiting for a spawned `freeq-server` to be serving.
//!
//! Every harness that boots the binary wanted the same three things and had
//! its own copy of two of them: the addresses the server bound, a poll of the
//! TCP ones until they accept, and — the part none of them had — a look at
//! whether the child is still alive. A server that died at `bind` was
//! therefore reported as a server that was slow, after the whole timeout, with
//! the real cause sitting in a log the harness printed at `Drop` if at all.
//!
//! The addresses come out of the server's own startup lines, which name the
//! address it bound rather than the one it was configured with. That is what
//! lets a harness hand the child `127.0.0.1:0` and let the kernel pick: a port
//! a live socket holds can never be issued to anything else, so there is no
//! window between picking a port and binding it.

use std::net::SocketAddr;
use std::process::Child;
use std::time::Duration;

/// How long a server gets to bind every listener it was asked for.
///
/// One value where there were two — 15 s in `federation.rs` and
/// `lying_peer.rs`, 30 s in `av_lifecycle.rs` and `avharness.rs`. The longer
/// one, because with the liveness check below a dead child is reported the
/// moment it dies, so the only thing this number buys is tolerance for a
/// genuinely slow boot under a parallel workspace run.
pub const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// One of the listeners a server logs as it binds it.
#[derive(Clone, Copy)]
pub enum Listener {
    Irc,
    Web,
    Iroh,
}

impl Listener {
    /// The part of the server's startup line that precedes the address.
    fn logged_as(self) -> &'static str {
        match self {
            Listener::Irc => "Plain listener on ",
            Listener::Web => "HTTP/WebSocket listener on ",
            Listener::Iroh => "Iroh endpoint ID: ",
        }
    }
}

/// What a server bound, as its own log reports it. A field is set only if its
/// listener was asked for.
#[derive(Default)]
pub struct Bound {
    pub irc: String,
    pub web: String,
    /// The iroh endpoint's IPv4 UDP port. Nothing polls it — a UDP socket has
    /// nothing to accept — so the line's appearance is its readiness.
    pub iroh_port: u16,
}

/// Wait until a spawned server has bound every listener in `want` and every
/// TCP one accepts, and give back what it bound.
///
/// Panics with the server's own log if the child exits first, and with the log
/// again if it is still alive but silent past [`READY_TIMEOUT`]. The log is in
/// the panic because two of the three callers destroy the directory holding it
/// when the test ends.
///
/// A still-alive child is killed before that second panic. `Child` does not
/// kill on drop, and two of the callers wait before the struct whose `Drop`
/// kills it exists — so the panic used to unwind past a live server and leave
/// it running for the rest of the run. (On the first panic `try_wait` has
/// already reaped it.)
pub async fn wait_ready(child: &mut Child, log_path: &str, want: &[Listener]) -> Bound {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "server exited with {status} before it was serving\n\
                 ── its log ──\n{}── end log ──",
                read_log(log_path)
            );
        }
        let log = read_log(log_path);
        if let Some(bound) = bound_in(&log, want)
            && [bound.irc.as_str(), bound.web.as_str()]
                .iter()
                .all(|addr| addr.is_empty() || std::net::TcpStream::connect(addr).is_ok())
        {
            return bound;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "server never became ready in {READY_TIMEOUT:?}\n\
                 ── its log ──\n{log}── end log ──"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The addresses `want` names, once the log has all of them.
fn bound_in(log: &str, want: &[Listener]) -> Option<Bound> {
    let mut bound = Bound::default();
    for listener in want {
        // The last match, not the first: a restart appends to the same log, so
        // the earlier matches are the previous boot's.
        let rest = log
            .lines()
            .filter_map(|line| line.split_once(listener.logged_as()))
            .map(|(_, rest)| rest)
            .next_back()?;
        match listener {
            Listener::Irc => bound.irc = addr_at(rest)?.to_string(),
            Listener::Web => bound.web = addr_at(rest)?.to_string(),
            Listener::Iroh => bound.iroh_port = iroh_port_in(rest)?,
        }
    }
    Some(bound)
}

/// The address a listener line ends with.
fn addr_at(rest: &str) -> Option<SocketAddr> {
    rest.split_whitespace().next()?.parse().ok()
}

/// The IPv4 UDP port out of the iroh line's `addr=[0.0.0.0:39248, [::]:42420]`
/// field. The endpoint binds both families and, on port 0, gets a different
/// port for each; the v4 one is what a peer on this machine dials.
fn iroh_port_in(rest: &str) -> Option<u16> {
    rest.split_once("addr=[")?
        .1
        .trim_end_matches(']')
        .split(", ")
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .find(SocketAddr::is_ipv4)
        .map(|addr| addr.port())
}

/// A server's captured log, ANSI stripped so assertions and the parsing above
/// read the plain field text.
///
/// `avharness.rs`'s copy of this wait strips the same escapes the same way;
/// the crate boundary stops the two sharing one function, so they agree by
/// being kept identical.
pub fn read_log(path: &str) -> String {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip an escape sequence through its final letter.
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Put the address a server bound into the argv it was spawned with, replacing
/// the `127.0.0.1:0` that was handed in, so starting it again on the same argv
/// rebinds the same port — which is what "the same server came back" means to
/// a test that restarts one.
pub fn pin_addr(args: &mut [String], flag: &str, addr: &str) {
    if let Some(i) = args.iter().position(|a| a == flag)
        && let Some(slot) = args.get_mut(i + 1)
    {
        *slot = addr.to_string();
    }
}
