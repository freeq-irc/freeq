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

use tokio::sync::mpsc;
use util::lying_peer::{
    LyingPeer, NO_EFFECT_WINDOW, SETTLE, TestId, TestServer, connect, is_deleted, msgid_of,
    registered_kid,
    revision_count, spawn_server_with_peer, try_event, wait_auth_and_register, wait_event,
    warm_link,
};

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
    wait_event(
        &mut rxa,
        |e| matches!(e, Event::Joined { .. }),
        "author join",
    )
    .await;

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
    assert!(
        leaked.is_none(),
        "a rejected delete was still fanned out to clients"
    );
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
    let forged = peer.signed_delete("mallory", "#room", &msgid, Some(&author.did), &forged_sig);
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
            |e| {
                matches!(e, Event::TagMsg { tags, .. } if tags.contains_key("+react")
                || tags.contains_key("+freeq.at/unreact"))
            },
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

/// A DM the peer says a *local* user sent.
///
/// The receiving server unions the addressed user's sessions with the
/// sessions of whoever the `account` names, so the sender's own devices see a
/// message they sent from elsewhere. A peer that stamps a local user's DID on
/// its own DM therefore reaches that user's client — and reaches it in the
/// sender's position, as a line in their outbox that they never wrote.
#[tokio::test]
async fn a_peer_cannot_put_a_dm_in_a_local_users_outbox() {
    let victim = TestId::new("did:plc:lpdmvictim");
    let addressee = TestId::new("did:plc:lpdmaddressee");
    let (srv, mut peer) = spawn_server_with_peer(&[&victim, &addressee]).await;

    let (hv, mut rxv) = connect(&srv, &victim, "victim");
    wait_auth_and_register(&mut rxv).await;
    let (ha, mut rxa) = connect(&srv, &addressee, "addressee");
    wait_auth_and_register(&mut rxa).await;

    // Warm the link through a channel both share, so "nothing arrived" below
    // cannot be a link that was never up.
    hv.join("#room").await.unwrap();
    wait_event(
        &mut rxv,
        |e| matches!(e, Event::Joined { .. }),
        "victim join",
    )
    .await;
    warm_link(&mut peer, "mallory", "#room", &mut rxv).await;

    // The peer's own DM to the addressee, stamped as the victim's.
    let forged = peer.privmsg(
        "mallory",
        "addressee",
        "did I send this?",
        Some(&victim.did),
    );
    peer.forge(forged).await;

    let echoed = try_event(
        &mut rxv,
        |e| matches!(e, Event::Message { text: t, .. } if t == "did I send this?"),
        NO_EFFECT_WINDOW,
    )
    .await;
    assert!(
        echoed.is_none(),
        "a peer's DM stamped with a local user's DID reached that user's own \
         session, where it reads as a message they sent: {echoed:?}"
    );

    assert_link_alive(&mut peer, &mut rxv, "probe-after-outbox-forgery").await;
    hv.quit(None).await.ok();
    ha.quit(None).await.ok();
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
        assert!(
            applied.is_none(),
            "a forged edit ({case}) was fanned out to clients"
        );
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
    assert!(
        kicked.is_none(),
        "a non-op remote user kicked a local member"
    );

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
    assert!(
        moded.is_none(),
        "a non-op remote user changed a channel mode"
    );

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

// ── a peer that says it is a task's home ──────────────────────────

/// The server the task under test was minted at — the only one whose word
/// moves it, and not the peer that connects here.
///
/// A full-length endpoint id, because that is what the field carries and what
/// the receive path truncates to.
const OTHER_HOME: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Register a signing key the way a client does, so the server can verify what
/// this test signs. The private half never leaves the test.
async fn register_key(
    handle: &freeq_sdk::client::ClientHandle,
    signing: &ed25519_dalek::SigningKey,
) {
    use base64::Engine;
    let pubkey =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    handle.raw(&format!("MSGSIG {pubkey}")).await.ok();
}

/// One signed act event: the id its signer minted, the exact bytes the
/// signature covers, the signature tag, and the wire tag map that carries all
/// three.
fn act_event(
    signing: &ed25519_dalek::SigningKey,
    venue: &str,
    act_tags: &[(&str, &str)],
) -> (
    String,
    String,
    String,
    std::collections::HashMap<String, String>,
) {
    let id = freeq_sdk::chatsig::new_event_id();
    let canonical = freeq_sdk::act::act_canonical(act_tags.iter().copied(), venue, &id)
        .expect("act tags present");
    let sig = freeq_sdk::act::sign_act(act_tags.iter().copied(), venue, &id, signing)
        .expect("act tags present");
    let mut tags: std::collections::HashMap<String, String> = act_tags
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    tags.insert(freeq_sdk::chatsig::EVENT_ID_TAG.to_string(), id.clone());
    tags.insert("+freeq.at/sig".to_string(), sig.clone());
    (id, canonical, sig, tags)
}

/// A task's row as the server holds it: where it says the task lives, what
/// state it is in, and who holds it.
fn task_row(db_path: &str, act_id: &str) -> Option<(String, String, Option<String>)> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT origin, state, assignee FROM act_actions WHERE act_id = ?1",
        rusqlite::params![act_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

/// The link a stored task event arrived on — the peer this server
/// authenticated, never the origin a payload claimed. The outer `None` says
/// the event is not on file at all; the inner one says it came from no peer.
fn event_origin(db_path: &str, event_id: &str) -> Option<Option<String>> {
    let conn = rusqlite::Connection::open(db_path).expect("open server db");
    conn.query_row(
        "SELECT origin FROM events WHERE event_id = ?1",
        rusqlite::params![event_id],
        |r| r.get(0),
    )
    .ok()
}

/// A task minted somewhere else is refereed there, and a peer does not get to
/// say it is that somewhere else.
///
/// The `origin` on a relayed event is a field in a JSON payload the sender
/// fills in. The decision it feeds is the one that matters most about a task:
/// whether this event is the task's home ruling, which is what applies a
/// transition rather than merely filing it, what flips an event already on
/// file to confirmed, and what lets a `did:web:` actor speak as the system.
/// So the field is worth exactly nothing on its own, and the identity the
/// transport authenticated is what the decision reads.
///
/// The setup uses catch-up on purpose: replay is the one path where an event
/// may legitimately name a server that is not the one handing it over — a
/// task healed through a third party still has to name the server that
/// referees it. That is what gives this server a task homed at `OTHER_HOME`
/// for the live path to then be lied to about.
#[tokio::test]
async fn a_peer_claiming_to_be_a_tasks_home_does_not_rule_on_its_task() {
    let agent = TestId::new("did:plc:lptaskagent");
    let watcher = TestId::new("did:plc:lptaskwatcher");
    let (srv, mut peer) = spawn_server_with_peer(&[&agent, &watcher]).await;

    let (ha, mut rxa) = connect(&srv, &agent, "agent");
    wait_auth_and_register(&mut rxa).await;
    ha.join("#room").await.unwrap();
    wait_event(
        &mut rxa,
        |e| matches!(e, Event::Joined { .. }),
        "agent join",
    )
    .await;

    let (hw, mut rxw) = connect(&srv, &watcher, "watcher");
    wait_auth_and_register(&mut rxw).await;
    hw.join("#room").await.unwrap();
    wait_event(
        &mut rxw,
        |e| matches!(e, Event::Joined { nick, .. } if nick == "watcher"),
        "watcher join",
    )
    .await;

    warm_link(&mut peer, "mallory", "#room", &mut rxw).await;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
    register_key(&ha, &signing).await;
    // SETTLE, not a hand-rolled 5s: this waits on a *persisted* row, and the
    // suite runs ~20 server test binaries at once (on a 2-core CI runner, not
    // this laptop). The loop exits the moment the row lands, so a longer
    // ceiling costs nothing when the machine is idle and removes a false
    // failure when it is not.
    let deadline = tokio::time::Instant::now() + SETTLE;
    while registered_kid(&srv.db_path, &agent.did).is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the agent's signing key must be on file, or nothing this test \
             signs can be checked here"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let venue = freeq_sdk::chatsig::channel_venue("#room");

    // ── a task this server holds, homed somewhere else ──────────────
    //
    // Handed over by catch-up, which is where an event may name a minter
    // other than the peer replaying it.
    let (offer_id, offer_canonical, offer_sig, _) = act_event(
        &signing,
        &venue,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", agent.did.as_str()),
            ("+freeq.at/act-title", "minted-somewhere-else"),
        ],
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    peer.forge(freeq_server::s2s::S2sMessage::CatchupEvents {
        origin: peer.id.clone(),
        events: vec![freeq_server::s2s::ReplayedEvent {
            event_id: offer_id.clone(),
            canonical: offer_canonical,
            signature: Some(offer_sig),
            kind: "act".to_string(),
            venue: venue.clone(),
            actor_did: Some(agent.did.clone()),
            subject: None,
            emoji: None,
            // The task's true home, which replay is allowed to name.
            origin: OTHER_HOME.to_string(),
            timestamp: now,
        }],
        more: false,
    })
    .await;

    let deadline = tokio::time::Instant::now() + SETTLE;
    let mut row = None;
    while tokio::time::Instant::now() < deadline {
        row = task_row(&srv.db_path, &offer_id);
        if row.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let row = row.expect("the replayed offer opened a task here");
    assert_eq!(
        (row.0.as_str(), row.1.as_str()),
        (OTHER_HOME, "open"),
        "the task must be on file as open and homed elsewhere, or the lie \
         below has nothing to claim"
    );

    // ── the lie: a transition, stamped with the home's id ───────────
    let (claim_id, _, _, claim_tags) = act_event(
        &signing,
        &venue,
        &[
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "claim"),
            ("+freeq.at/from", agent.did.as_str()),
            ("+freeq.at/act-id", offer_id.as_str()),
        ],
    );
    peer.forge(freeq_server::s2s::S2sMessage::Tagmsg {
        event_id: format!("{}:claim-1", peer.id),
        from: "mallory".to_string(),
        target: "#room".to_string(),
        tags: claim_tags.clone(),
        // The whole of the attack: a field the sender filled in.
        origin: OTHER_HOME.to_string(),
        account: Some(agent.did.clone()),
    })
    .await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-claimed-home-transition").await;

    assert_eq!(
        event_origin(&srv.db_path, &claim_id),
        Some(Some(peer.id.clone())),
        "a transition on someone else's task is filed, and the row names the \
         link it came in on rather than the origin the peer stamped"
    );
    assert_eq!(
        task_row(&srv.db_path, &offer_id).map(|r| (r.1, r.2)),
        Some(("open".to_string(), None)),
        "and the task it names has not moved"
    );

    // ── the same lie again, which is how an unconfirmed event flips ──
    //
    // The second arrival of an event already on file is what a real home's
    // ruling looks like, so it is the shape a liar reaches for.
    peer.forge(freeq_server::s2s::S2sMessage::Tagmsg {
        event_id: format!("{}:claim-2", peer.id),
        from: "mallory".to_string(),
        target: "#room".to_string(),
        tags: claim_tags,
        origin: OTHER_HOME.to_string(),
        account: Some(agent.did.clone()),
    })
    .await;
    assert_link_alive(&mut peer, &mut rxw, "probe-after-repeated-claimed-home").await;

    assert_eq!(
        event_origin(&srv.db_path, &claim_id),
        Some(Some(peer.id.clone())),
        "and saying it twice is not a ruling either"
    );
    assert_eq!(
        task_row(&srv.db_path, &offer_id).map(|r| (r.1, r.2)),
        Some(("open".to_string(), None)),
        "so the task is still where its own server left it"
    );

    ha.quit(None).await.ok();
    hw.quit(None).await.ok();
}
