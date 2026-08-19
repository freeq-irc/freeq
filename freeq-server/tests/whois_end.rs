//! Acceptance tests for the end of a WHOIS.
//!
//! Real TCP server, real SDK clients. Every other WHOIS event reports
//! something the server found; this one reports that it has nothing more to
//! say. That distinction is the whole difference between "this person has no
//! account" and "the answer hasn't arrived yet" — a client with only the
//! former can either guess with a timer or claim someone is unidentified
//! before anyone has asked. Both are wrong, and both shipped.

use std::collections::HashMap;
use std::time::Duration;

use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn start_test_server() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-whois-end".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(
        config,
        DidResolver::static_map(HashMap::new()),
    );
    server.start().await.unwrap()
}

async fn connect_guest(
    addr: std::net::SocketAddr,
    nick: &str,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: nick.to_string(),
        ..Default::default()
    };
    let (handle, mut events) = client::connect(config, None);
    expect_event(
        &mut events,
        3000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;
    (handle, events)
}

async fn expect_event(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    predicate: impl Fn(&Event) -> bool,
    description: &str,
) -> Event {
    let deadline = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    loop {
        match timeout(deadline.saturating_sub(start.elapsed()), events.recv()).await {
            Ok(Some(event)) => {
                if predicate(&event) {
                    return event;
                }
            }
            Ok(None) => panic!("Channel closed while waiting for: {description}"),
            Err(_) => panic!("Timeout waiting for: {description}"),
        }
    }
}

/// A guest is the case the signal exists for: the server answers, names no
/// account, and finishes. Only the finish tells a caller that no account is
/// the answer rather than the wait.
#[tokio::test]
async fn a_whois_over_a_guest_ends_and_names_no_account() {
    let (addr, _server) = start_test_server().await;
    let (_subject, _subject_events) = connect_guest(addr, "whoisguest").await;
    let (asker, mut asker_events) = connect_guest(addr, "whoisasker").await;

    asker.whois("whoisguest").await.unwrap();

    // Drain until the end arrives, remembering whether an account binding
    // showed up on the way. For a guest it must not.
    let mut saw_account = false;
    let deadline = Duration::from_millis(3000);
    let start = tokio::time::Instant::now();
    loop {
        match timeout(
            deadline.saturating_sub(start.elapsed()),
            asker_events.recv(),
        )
        .await
        {
            Ok(Some(Event::MemberDid { nick, .. })) if nick.eq_ignore_ascii_case("whoisguest") => {
                saw_account = true;
            }
            Ok(Some(Event::WhoisEnd { nick })) => {
                assert!(
                    nick.eq_ignore_ascii_case("whoisguest"),
                    "the end names the nick it ends: got {nick}"
                );
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed before the WHOIS ended"),
            Err(_) => panic!("no end-of-WHOIS arrived; a caller can only guess with a timer"),
        }
    }

    assert!(
        !saw_account,
        "a guest has no account, so no binding may be reported for one"
    );
}

/// A nick nobody is holding still ends. Without this the asking surface waits
/// out its whole budget for an answer that already came.
#[tokio::test]
async fn a_whois_over_a_nick_that_is_not_here_still_ends() {
    let (addr, _server) = start_test_server().await;
    let (asker, mut asker_events) = connect_guest(addr, "whoisasker2").await;

    asker.whois("nobodyhome").await.unwrap();

    expect_event(
        &mut asker_events,
        3000,
        |e| matches!(e, Event::WhoisEnd { nick } if nick.eq_ignore_ascii_case("nobodyhome")),
        "WhoisEnd for a nick with no holder",
    )
    .await;
}
