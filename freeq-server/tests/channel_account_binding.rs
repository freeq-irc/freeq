//! A channel message's `account` tag teaches the nick↔DID binding.
//!
//! Real TCP server, real SDK clients. A session that joins a room after
//! someone is already in it never sees their JOIN (extended-join) and NAMES
//! carries no DIDs — so the only thing that can name that person without a
//! WHOIS is the account tag the server stamps on every authenticated
//! message. The JS SDK learned from it only on DMs, and the Rust SDK had the
//! same venue gate; both meant a cold session could render a DID where a
//! nick was knowable.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

async fn start_test_server(
    resolver: DidResolver,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-account-binding".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

fn connect(
    addr: std::net::SocketAddr,
    nick: &str,
    signer: Option<Arc<dyn ChallengeSigner>>,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: "account binding test".to_string(),
        ..Default::default()
    };
    client::connect(config, signer)
}

async fn wait_event(
    rx: &mut mpsc::Receiver<Event>,
    pred: impl Fn(&Event) -> bool,
    desc: &str,
) -> Event {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(ev) if pred(&ev) => return ev,
                Some(_) => continue,
                None => panic!("event stream ended while waiting for {desc}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {desc}"))
}

#[tokio::test]
async fn a_channel_message_teaches_a_binding_the_join_never_did() {
    let did = "did:plc:tagteachertesttesttest00";
    let key = PrivateKey::generate_ed25519();
    let mut map = HashMap::new();
    map.insert(
        did.to_string(),
        freeq_sdk::did::make_test_did_document(did, &key.public_key_multibase()),
    );
    let (addr, _server) = start_test_server(DidResolver::static_map(map)).await;

    // The authenticated sender is in the room first.
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        did.to_string(),
        PrivateKey::ed25519_from_bytes(&key.secret_bytes()).unwrap(),
    ));
    let (sender, mut sender_rx) = connect(addr, "teacher", Some(signer));
    wait_event(&mut sender_rx, |e| matches!(e, Event::Registered { .. }), "sender registered").await;
    sender.join("#lesson").await.unwrap();
    wait_event(
        &mut sender_rx,
        |e| matches!(e, Event::Joined { channel, .. } if channel == "#lesson"),
        "sender joined",
    )
    .await;

    // The cold session arrives after — it never sees the sender's JOIN, and
    // NAMES carries no DIDs, so at this point it cannot name the sender.
    let (receiver, mut receiver_rx) = connect(addr, "coldseat", None);
    wait_event(&mut receiver_rx, |e| matches!(e, Event::Registered { .. }), "receiver registered").await;
    receiver.join("#lesson").await.unwrap();
    wait_event(
        &mut receiver_rx,
        |e| matches!(e, Event::Joined { channel, nick, .. } if channel == "#lesson" && nick == "coldseat"),
        "receiver joined",
    )
    .await;

    // The sender speaks in the channel. The server stamps the account tag on
    // that message, and the tag is the receiver's first and only chance to
    // learn who "teacher" is without asking.
    sender.privmsg("#lesson", "the tag is the lesson").await.unwrap();

    let ev = wait_event(
        &mut receiver_rx,
        |e| matches!(e, Event::MemberDid { nick, .. } if nick.eq_ignore_ascii_case("teacher")),
        "MemberDid learned from the channel message's account tag",
    )
    .await;
    if let Event::MemberDid { did: learned, .. } = ev {
        assert_eq!(learned, did);
    }
}
