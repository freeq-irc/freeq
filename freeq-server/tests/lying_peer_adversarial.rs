//! What a federated peer can and cannot do to this server's state.
//!
//! Each test drives a real S2S link (see `util::lying_peer`) and sends events
//! a well-behaved server never sends: a delete of someone else's message, an
//! edit of someone else's message, a kick and a mode from a user who holds no
//! op anywhere, a topic change into a `+t` channel. The assertion is always
//! the same shape — the forged event changed nothing, and a legitimate event
//! sent over the same link right afterwards still arrives, so "nothing
//! happened" is a rejection and not a dead link.
//!
//! Every test also states, in its name, which rule it is pinning. Two of them
//! pin a rule the server does *not* currently enforce; those say so.

use std::time::Duration;

use freeq_sdk::event::Event;

#[path = "util/mod.rs"]
mod util;

use util::lying_peer::{
    registered_kid,
    LyingPeer, NO_EFFECT_WINDOW, TestId, TestServer, connect, is_deleted, msgid_of, revision_count,
    spawn_server_with_peer, try_event, wait_auth_and_register, wait_event, warm_link,
};
use tokio::sync::mpsc;

/// A DID the lying peer asserts but has never proven — the shape of a forged
/// `account` on the wire. Deliberately not in `--did-resolver-static`: a peer
/// gets to claim any string here, which is the whole point.
const FORGED_DID: &str = "did:plc:mallorytheliar";

/// Common opening: an authenticated author and an authenticated watcher, both
/// in `#room`, plus a lying peer whose `mallory` has joined it. Returns after
/// the link has demonstrably delivered one of the peer's events.
///
/// The watcher exists because the author's own client does not echo its
/// messages back — the watcher is where `msgid` and "did anything arrive"
/// observations come from.
async fn open_room(
    author: &TestId,
    watcher: &TestId,
) -> (
    TestServer,
    LyingPeer,
    freeq_sdk::client::ClientHandle,
    mpsc::Receiver<Event>,
) {
    let (srv, mut peer) = spawn_server_with_peer(&[author, watcher]).await;

    let (ha, mut rxa) = connect(&srv, author, "author");
    wait_auth_and_register(&mut rxa).await;
    ha.join("#room").await.unwrap();
    wait_event(&mut rxa, |e| matches!(e, Event::Joined { .. }), "author join").await;

    let (hw, mut rxw) = connect(&srv, watcher, "watcher");
    wait_auth_and_register(&mut rxw).await;
    hw.join("#room").await.unwrap();
    wait_event(
        &mut rxw,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "watcher"),
        "watcher join",
    )
    .await;

    warm_link(&mut peer, "mallory", "#room", &mut rxw).await;
    // `ha` is returned so the author's session stays alive for the test; the
    // watcher's receiver is the one every assertion reads.
    (srv, peer, ha, rxw)
}

/// Post a message as the author and return the msgid the server assigned it.
async fn post(
    author: &freeq_sdk::client::ClientHandle,
    rxw: &mut mpsc::Receiver<Event>,
    text: &str,
) -> String {
    author.privmsg("#room", text).await.unwrap();
    let seen = wait_event(
        rxw,
        |e| matches!(e, Event::Message { text: t, .. } if t == text),
        "author's message",
    )
    .await;
    msgid_of(&seen)
}

/// Prove the link is alive right now: the peer sends an ordinary message and
/// a local client receives it. Run after a forged event, so "the forged event
/// did nothing" cannot be confused with "the link stopped working".
async fn assert_link_alive(peer: &mut LyingPeer, rxw: &mut mpsc::Receiver<Event>, probe: &str) {
    let msg = peer.privmsg("mallory", "#room", probe, Some(FORGED_DID));
    peer.forge(msg).await;
    let seen = try_event(
        rxw,
        |e| matches!(e, Event::Message { text: t, .. } if t == probe),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(
        seen.is_some(),
        "the peer's own legitimate message never arrived — the link is dead, \
         so nothing this test observed about a forged event means anything"
    );
}

// ── delete ───────────────────────────────────────────────────────

/// A peer that names a DID which did not write the message cannot delete it,
/// whether it asserts the wrong DID or asserts none at all.
#[tokio::test]
async fn a_peer_cannot_delete_a_message_authored_by_someone_else() {
    let author = TestId::new("did:plc:lpauthor1");
    let watcher = TestId::new("did:plc:lpwatcher1");
    let (srv, mut peer, ha, mut rxw) = open_room(&author, &watcher).await;

    let msgid = post(&ha, &mut rxw, "the original").await;

    // (1) A forged `account`: a DID the peer asserts, which is not the author's.
    let forged = peer.delete("mallory", "#room", &msgid, Some(FORGED_DID));
    peer.forge(forged).await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-account").await;
    assert!(
        !is_deleted(&srv.db_path, &msgid),
        "a peer asserting an unrelated DID deleted another user's message"
    );

    // (2) No `account` at all, from a nick this server has never heard of.
    let forged = peer.delete("mallory", "#room", &msgid, None);
    peer.forge(forged).await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-absent-account").await;
    assert!(
        !is_deleted(&srv.db_path, &msgid),
        "a peer asserting no DID at all deleted another user's message"
    );

    // The delete never reached a client either — a rejected event is dropped
    // before fan-out, not relayed and then ignored locally.
    let leaked = try_event(
        &mut rxw,
        |e| matches!(e, Event::TagMsg { tags, .. } if tags.contains_key("+draft/delete")),
        Duration::from_millis(500),
    )
    .await;
    assert!(leaked.is_none(), "a rejected delete was still fanned out to clients");
}

/// A peer that puts a *local* user's nick in `from` and sends no `account`
/// used to have the delete authorized: with no DID on the event, the receiver
/// looked the nick up in its own `nick_owners` map, resolved it to the local
/// user who owns it, and concluded the author was acting. A nick is
/// peer-assertable, so that was an impersonation route.
///
/// The receiver no longer answers "who is this" from a nick a peer chose.
/// Without a DID the event is a stranger's, and a stranger cannot delete
/// someone else's message.
#[tokio::test]
async fn a_peer_impersonating_a_local_nick_cannot_delete_that_users_message() {
    let author = TestId::new("did:plc:lpauthor2");
    let watcher = TestId::new("did:plc:lpwatcher2");
    let (srv, mut peer, ha, mut rxw) = open_room(&author, &watcher).await;

    let msgid = post(&ha, &mut rxw, "impersonation target").await;

    let forged = peer.delete("author", "#room", &msgid, None);
    peer.forge(forged).await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-nick-impersonation").await;

    assert!(
        !is_deleted(&srv.db_path, &msgid),
        "a peer wearing a local user's nick deleted that user's message"
    );
}

/// The sharpest version of the impersonation: the peer stamps the victim's
/// **real** DID on a mutation, which is the one identity every authorization
/// check here will accept. Naming it is free — a peer chooses what it sends —
/// so the only thing separating the claim from the act is a signature by the
/// key that DID registered.
///
/// Neither shape gets through: no signature at all, and one that names a key
/// this server really holds but does not verify against it.
#[tokio::test]
async fn a_peer_stamping_the_victims_did_on_a_mutation_is_refused() {
    let author = TestId::new("did:plc:lpstamped");
    let watcher = TestId::new("did:plc:lpstampedwatch");
    let (srv, mut peer, ha, mut rxw) = open_room(&author, &watcher).await;

    // Posting registers the author's signing key here, so a forged signature
    // can name a kid this server can actually resolve — a real failure rather
    // than "cannot check".
    let msgid = post(&ha, &mut rxw, "theirs to delete").await;
    let kid = registered_kid(&srv.db_path, &author.did)
        .expect("the author's client registered a signing key");
    let forged_sig = format!("ed25519:{kid}:{}", "A".repeat(86));

    // (1) A delete under the victim's DID, unsigned.
    let forged = peer.delete("mallory", "#room", &msgid, Some(&author.did));
    peer.forge(forged).await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-unsigned-stamped-delete").await;
    assert!(
        !is_deleted(&srv.db_path, &msgid),
        "an unsigned delete stamped with the victim's DID deleted their message"
    );

    // (2) The same delete, carrying a signature that does not verify against
    // the DID it names.
    let forged = peer.signed_delete(
        "mallory",
        "#room",
        &msgid,
        Some(&author.did),
        &forged_sig,
    );
    peer.forge(forged).await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-stamped-delete").await;
    assert!(
        !is_deleted(&srv.db_path, &msgid),
        "a delete whose signature failed against the victim's own key still applied"
    );

    // (3) Reactions and their removal, both shapes, under the victim's DID.
    for (label, event) in [
        (
            "unsigned react",
            peer.react("mallory", "#room", &msgid, "👍", Some(&author.did), None),
        ),
        (
            "forged react",
            peer.react(
                "mallory",
                "#room",
                &msgid,
                "👍",
                Some(&author.did),
                Some(&forged_sig),
            ),
        ),
        (
            "unsigned unreact",
            peer.unreact("mallory", "#room", &msgid, "👍", Some(&author.did), None),
        ),
        (
            "forged unreact",
            peer.unreact(
                "mallory",
                "#room",
                &msgid,
                "👍",
                Some(&author.did),
                Some(&forged_sig),
            ),
        ),
    ] {
        peer.forge(event).await;
        let leaked = try_event(
            &mut rxw,
            |e| matches!(e, Event::TagMsg { tags, .. } if tags.contains_key("+react")
                || tags.contains_key("+freeq.at/unreact")),
            NO_EFFECT_WINDOW,
        )
        .await;
        assert!(
            leaked.is_none(),
            "a {label} stamped with the victim's DID reached a local client: {leaked:?}"
        );
    }
    assert_link_alive(&mut peer, &mut rxw, "probe-after-stamped-reactions").await;
}

// ── signatures ───────────────────────────────────────────────────

/// A peer that attaches a signature which does not check out. Nothing
/// arrives: the words and the proof came together and disagreed, and relaying
/// the words alone would put text under the author's name that the evidence
/// on the wire says is not theirs.
///
/// The forged signature names a key this server really holds (the author's own
/// registered key id), so the verdict is a genuine failure rather than "cannot
/// check". Only the private half is missing, which is exactly the attacker's
/// position.
#[tokio::test]
async fn a_peer_cannot_attach_a_signature_that_does_not_check_out() {
    let author = TestId::new("did:plc:lpsigauthor");
    let watcher = TestId::new("did:plc:lpsigwatcher");
    let (srv, mut peer, ha, mut rxw) = open_room(&author, &watcher).await;

    // Posting registers the author's session signing key with this server.
    post(&ha, &mut rxw, "something the author really said").await;
    let kid = registered_kid(&srv.db_path, &author.did)
        .expect("the author's client registered a signing key");

    // Right kid, wrong bytes: 64 bytes of base64url that are not a signature
    // over anything.
    let forged = format!("ed25519:{kid}:{}", "A".repeat(86));
    let msg = peer.signed_privmsg(
        "mallory",
        "#room",
        "words with a forged seal",
        Some(&author.did),
        "01LYINGPEERFORGEDSIG000000",
        &forged,
    );
    peer.forge(msg).await;

    let leaked = try_event(
        &mut rxw,
        |e| matches!(e, Event::Message { text: t, .. } if t == "words with a forged seal"),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(
        leaked.is_none(),
        "a message whose signature failed verification reached a local client: {leaked:?}"
    );

    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-signature").await;
}

/// The other half of the rule, on the same wire: a signature this server
/// cannot judge is left exactly as it arrived. Stripping it would destroy
/// something a holder of the key could still check, and would report "cannot
/// tell" as if it were "forged".
#[tokio::test]
async fn a_peer_relaying_an_uncheckable_signature_keeps_it_intact() {
    let author = TestId::new("did:plc:lpsigauthor2");
    let watcher = TestId::new("did:plc:lpsigwatcher2");
    let (_srv, mut peer, _ha, mut rxw) = open_room(&author, &watcher).await;

    // A key id this server has never seen, so there is nothing to check
    // against — and no key server is configured for this peer either.
    let uncheckable = format!("ed25519:{}:{}", "unknownkid0000000000AA", "B".repeat(86));
    let msg = peer.signed_privmsg(
        "mallory",
        "#room",
        "signed by a stranger",
        Some(FORGED_DID),
        "01LYINGPEERUNKNOWNKEY00000",
        &uncheckable,
    );
    peer.forge(msg).await;

    let seen = wait_event(
        &mut rxw,
        |e| matches!(e, Event::Message { text: t, .. } if t == "signed by a stranger"),
        "the peer's uncheckable message",
    )
    .await;
    let Event::Message { tags, .. } = &seen else {
        unreachable!("matched above")
    };
    assert_eq!(
        tags.get("+freeq.at/sig").map(String::as_str),
        Some(uncheckable.as_str()),
        "an uncheckable signature must be relayed exactly as it arrived"
    );
}

// ── edit ─────────────────────────────────────────────────────────

/// A peer cannot rewrite a message it did not write. Unlike a delete there is
/// no op route for an edit: rewriting would put other words under the
/// author's name.
#[tokio::test]
async fn a_peer_cannot_edit_a_message_authored_by_someone_else() {
    let author = TestId::new("did:plc:lpauthor3");
    let watcher = TestId::new("did:plc:lpwatcher3");
    let (srv, mut peer, ha, mut rxw) = open_room(&author, &watcher).await;

    let msgid = post(&ha, &mut rxw, "what the author actually said").await;

    for (case, account) in [("forged-did", Some(FORGED_DID)), ("no-did", None)] {
        let text = format!("rewritten by a peer ({case})");
        let forged = peer.edit("mallory", "#room", &text, &msgid, account);
        peer.forge(forged).await;

        let applied = try_event(
            &mut rxw,
            |e| matches!(e, Event::Message { text: t, .. } if *t == text),
            NO_EFFECT_WINDOW,
        )
        .await;
        assert!(applied.is_none(), "a forged edit ({case}) was fanned out to clients");
        assert_eq!(
            revision_count(&srv.db_path, &msgid),
            1,
            "a forged edit ({case}) was stored as a revision of another user's message"
        );
    }

    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-edits").await;
}

// ── kick / mode ──────────────────────────────────────────────────

/// A remote user who is an op nowhere cannot kick a local member, nor grant
/// itself or anyone else channel privileges.
#[tokio::test]
async fn a_peer_whose_actor_is_not_an_op_cannot_kick_or_set_modes() {
    let author = TestId::new("did:plc:lpauthor4");
    let watcher = TestId::new("did:plc:lpwatcher4");
    let (_srv, mut peer, _ha, mut rxw) = open_room(&author, &watcher).await;

    // `mallory` holds no op: the receiver derives op status from its own
    // founder/did_ops state, and never from the peer's claim.
    let forged = peer.kick("mallory", "watcher", "#room");
    peer.forge(forged).await;
    let kicked = try_event(
        &mut rxw,
        |e| matches!(e, Event::Kicked { nick, .. } if nick == "watcher"),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(kicked.is_none(), "a non-op remote user kicked a local member");

    // Same actor, now trying to op the watcher — a privilege grant, which is
    // the more damaging of the two because it persists.
    let forged = peer.mode("mallory", "#room", "+o", Some("watcher"));
    peer.forge(forged).await;
    let moded = try_event(
        &mut rxw,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode.contains('o')),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(moded.is_none(), "a non-op remote user granted channel ops");

    // And a channel-wide mode: dropping +n would let anyone message the room.
    let forged = peer.mode("mallory", "#room", "-n", None);
    peer.forge(forged).await;
    let moded = try_event(
        &mut rxw,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode.contains('n')),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(moded.is_none(), "a non-op remote user changed a channel mode");

    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-kick-and-modes").await;
}

// ── topic ────────────────────────────────────────────────────────

/// `#room` is `+t` from creation. A remote non-op cannot set its topic.
#[tokio::test]
async fn a_peer_whose_actor_is_not_an_op_cannot_set_a_locked_topic() {
    let author = TestId::new("did:plc:lpauthor5");
    let watcher = TestId::new("did:plc:lpwatcher5");
    let (_srv, mut peer, _ha, mut rxw) = open_room(&author, &watcher).await;

    let forged = peer.topic("mallory", "#room", "topic set by a liar");
    peer.forge(forged).await;

    let changed = try_event(
        &mut rxw,
        |e| matches!(e, Event::TopicChanged { .. }),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(
        changed.is_none(),
        "a non-op remote user set the topic of a +t channel"
    );

    assert_link_alive(&mut peer, &mut rxw, "probe-after-forged-topic").await;
}
