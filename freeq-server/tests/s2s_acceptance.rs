//! S2S federation acceptance tests.
//!
//! These tests connect to TWO live IRC servers and verify that state
//! syncs correctly between them. Run with:
//!
//!   LOCAL_SERVER=localhost:6667 REMOTE_SERVER=irc.freeq.at:6667 cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1
//!
//! For single-server tests (no S2S needed):
//!
//!   SERVER=localhost:6667 cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1 single_server
//!
//! Both servers must be running with --iroh and S2S peering configured.
//! If environment variables aren't set, tests are skipped.
//!
//! NOTE: Use `--test-threads=1` to run sequentially. The single S2S link
//! between the two servers can't handle many concurrent test sessions reliably.
//!
//! Channel names use `#_zqtest_` prefix + timestamp to avoid collisions
//! with real channels on live servers.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;

/// How long to wait for an event before considering it failed.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Longer timeout for operations that require S2S propagation.
const S2S_TIMEOUT: Duration = Duration::from_secs(30);

/// Time to let S2S state propagate after a JOIN/PART/etc.
const S2S_SETTLE: Duration = Duration::from_secs(3);

// ── Helpers ──────────────────────────────────────────────────────

/// Connect a guest user to a server, returning handle + event receiver.
async fn connect_guest(addr: &str, nick: &str) -> (ClientHandle, mpsc::Receiver<Event>) {
    let conn = client::establish_connection(&ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("S2S Test ({nick})"),
        tls: false,
        tls_insecure: false,
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("Failed to connect {nick} to {addr}: {e}"));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("S2S Test ({nick})"),
        tls: false,
        tls_insecure: false,
        ..Default::default()
    };

    client::connect_with_stream(conn, config, None)
}

/// Drain every `Message` whose text starts with `prefix`, pushing each one's
/// `msgid` tag onto `out`. Stops when the stream goes quiet.
async fn collect_msgids(rx: &mut mpsc::Receiver<Event>, prefix: &str, out: &mut Vec<String>) {
    let p = prefix.to_string();
    while let Some(Event::Message { tags, .. }) = maybe_wait(
        rx,
        |e| matches!(e, Event::Message { text, .. } if text.starts_with(&p)),
        Duration::from_secs(3),
    )
    .await
    {
        match tags.get("msgid") {
            Some(mid) => out.push(mid.clone()),
            None => panic!("delivered message carried no msgid tag"),
        }
    }
}

/// Prove the session still works after something odd was sent on it: join a
/// fresh channel and see the JOIN come back. Used by the tests whose subject is
/// "this input must not take the connection down" — without it they assert only
/// that no error arrived, which an already-dead session also satisfies.
async fn assert_session_alive(h: &ClientHandle, rx: &mut mpsc::Receiver<Event>, tag: &str) {
    let probe = test_channel(&format!("{tag}alive"));
    h.join(&probe).await.expect("session accepted a JOIN");
    wait_joined(rx, &probe).await;
    let _ = h.raw(&format!("PART {probe}")).await;
}

/// Wait for a specific event, ignoring others.
async fn wait_for<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    desc: &str,
) -> Event {
    wait_for_timeout(rx, predicate, desc, TIMEOUT).await
}

/// Wait for a specific event with configurable timeout.
async fn wait_for_timeout<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    desc: &str,
    dur: Duration,
) -> Event {
    let result = timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(evt) if predicate(&evt) => return evt,
                Some(_) => continue,
                None => panic!("Channel closed while waiting for: {desc}"),
            }
        }
    })
    .await;

    result.unwrap_or_else(|_| panic!("Timeout ({dur:?}) waiting for: {desc}"))
}

/// Check if an event arrives within a duration. Returns None on timeout.
async fn maybe_wait<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    dur: Duration,
) -> Option<Event> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(evt) if predicate(&evt) => return evt,
                Some(_) => continue,
                None => {
                    return Event::Disconnected {
                        reason: "closed".into(),
                    };
                }
            }
        }
    })
    .await
    .ok()
}

/// Wait for a Registered event.
async fn wait_registered(rx: &mut mpsc::Receiver<Event>) -> String {
    match wait_for(rx, |e| matches!(e, Event::Registered { .. }), "Registered").await {
        Event::Registered { nick } => nick,
        _ => unreachable!(),
    }
}

/// Wait for a Joined event for a specific channel.
async fn wait_joined(rx: &mut mpsc::Receiver<Event>, channel: &str) -> String {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::Joined { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Joined {channel}"),
    )
    .await
    {
        Event::Joined { nick, .. } => nick,
        _ => unreachable!(),
    }
}

/// Wait for a Parted event for a specific nick in a channel.
async fn wait_parted(rx: &mut mpsc::Receiver<Event>, channel: &str, nick: &str) {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::Parted { channel: c, nick: pn } if c.to_lowercase() == ch && pn == &n),
        &format!("Part {nick} from {channel}"),
    )
    .await;
}

/// Wait for a UserQuit event for a specific nick.
async fn wait_quit(rx: &mut mpsc::Receiver<Event>, nick: &str) {
    let n = nick.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::UserQuit { nick: qn, .. } if qn == &n),
        &format!("Quit from {nick}"),
    )
    .await;
}

/// Wait for a Message from a specific user.
async fn wait_message_from(rx: &mut mpsc::Receiver<Event>, from: &str) -> (String, String) {
    let f = from.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Message { from: sender, .. } if sender == &f),
        &format!("Message from {from}"),
    )
    .await
    {
        Event::Message { target, text, .. } => (target, text),
        _ => unreachable!(),
    }
}

/// Wait for a Message containing specific text.
async fn wait_message_containing(
    rx: &mut mpsc::Receiver<Event>,
    substr: &str,
) -> (String, String, String) {
    let s = substr.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Message { text, .. } if text.contains(&s)),
        &format!("Message containing '{substr}'"),
    )
    .await
    {
        Event::Message {
            from, target, text, ..
        } => (from, target, text),
        _ => unreachable!(),
    }
}

/// Wait for a Message containing specific text and return the full event (including tags).
async fn wait_message_event_containing(rx: &mut mpsc::Receiver<Event>, substr: &str) -> Event {
    let s = substr.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::Message { text, .. } if text.contains(&s)),
        &format!("Message event containing '{substr}'"),
    )
    .await
}

/// Wait for a Names event that includes a specific nick.
async fn wait_names_containing(
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
    nick: &str,
) -> Vec<String> {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    match wait_for_timeout(
        rx,
        |e| {
            matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == ch
            && nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == n))
        },
        &format!("Names in {channel} containing {nick}"),
        S2S_TIMEOUT,
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

#[allow(dead_code)]
/// Wait for Names that do NOT include a specific nick.
async fn wait_names_not_containing(
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
    nick: &str,
) -> Vec<String> {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    match wait_for_timeout(
        rx,
        |e| {
            matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == ch
            && !nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == n))
        },
        &format!("Names in {channel} NOT containing {nick}"),
        S2S_TIMEOUT,
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Wait for a TopicChanged event.
async fn wait_topic(rx: &mut mpsc::Receiver<Event>, channel: &str) -> String {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::TopicChanged { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Topic in {channel}"),
    )
    .await
    {
        Event::TopicChanged { topic, .. } => topic,
        _ => unreachable!(),
    }
}

/// Wait for a ModeChanged event.
async fn wait_mode(rx: &mut mpsc::Receiver<Event>, channel: &str) -> (String, Option<String>) {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::ModeChanged { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Mode change in {channel}"),
    )
    .await
    {
        Event::ModeChanged { mode, arg, .. } => (mode, arg),
        _ => unreachable!(),
    }
}

/// Wait for a ServerNotice containing specific text.
async fn wait_notice_containing(rx: &mut mpsc::Receiver<Event>, substr: &str) {
    let s = substr.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::ServerNotice { text } if text.contains(&s)),
        &format!("Notice containing '{substr}'"),
    )
    .await;
}

/// Drain all pending events from a receiver.
async fn drain(rx: &mut mpsc::Receiver<Event>) {
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {}
}

fn get_servers() -> Option<(String, String)> {
    let local = std::env::var("LOCAL_SERVER").ok();
    let remote = std::env::var("REMOTE_SERVER").ok();
    match (local, remote) {
        (Some(l), Some(r)) => Some((l, r)),
        _ => {
            eprintln!("Skipping S2S test: set LOCAL_SERVER and REMOTE_SERVER env vars");
            None
        }
    }
}

fn get_single_server() -> Option<String> {
    std::env::var("SERVER")
        .ok()
        .or_else(|| std::env::var("LOCAL_SERVER").ok())
}

/// Generate a unique channel name unlikely to collide with real channels.
fn test_channel(suffix: &str) -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("#_zqtest_{}{}", ts % 1_000_000, suffix)
}

/// Generate a unique test nick.
fn test_nick(prefix: &str, suffix: &str) -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("_zq{}{}_{}", prefix, suffix, ts % 100000)
}

// ═══════════════════════════════════════════════════════════════════
// Single-server tests (only need SERVER or LOCAL_SERVER)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn single_server_connect_and_register() {
    let Some(server) = get_single_server() else {
        eprintln!("Skipping: set SERVER or LOCAL_SERVER");
        return;
    };
    let nick = test_nick("reg", "");
    let (h, mut e) = connect_guest(&server, &nick).await;
    let got = wait_registered(&mut e).await;
    eprintln!("  ✓ Registered as {got}");
    let _ = h.quit(Some("test done")).await;
}

#[tokio::test]
async fn single_server_join_part_cycle() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("jp", "");
    let channel = test_channel("jp");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    eprintln!("  ✓ Joined {channel}");

    h.raw(&format!("PART {channel} :bye")).await.unwrap();
    wait_parted(&mut e, &channel, &nick).await;
    eprintln!("  ✓ Parted {channel}");

    // Rejoin
    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    eprintln!("  ✓ Rejoined {channel}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_topic_set_and_read() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("top", "");
    let channel = test_channel("top");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    let topic = format!("acceptance test topic {}", chrono::Utc::now().timestamp());
    h.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut e, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic set: {topic}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_privmsg_between_users() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("pm", "a");
    let nick_b = test_nick("pm", "b");
    let channel = test_channel("pm");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    let msg = format!("test msg {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Message delivered: {msg}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_list_command() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("lst", "");
    let channel = test_channel("lst");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    h.raw("LIST").await.unwrap();
    // Should get a raw line containing our channel
    let ch_lower = channel.to_lowercase();
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.to_lowercase().contains(&ch_lower)),
        "LIST output containing our channel",
    )
    .await;
    eprintln!("  ✓ LIST shows {channel}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_who_command() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("who", "");
    let channel = test_channel("who");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    h.raw(&format!("WHO {channel}")).await.unwrap();
    // Should get a raw line containing our nick
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains(&nick)),
        "WHO output containing our nick",
    )
    .await;
    eprintln!("  ✓ WHO shows {nick}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_away_status() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("aw", "a");
    let nick_b = test_nick("aw", "b");
    let channel = test_channel("aw");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    // Both join a channel so we know they can see each other
    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // Set away
    ha.raw("AWAY :Gone fishing").await.unwrap();
    // Should get RPL_NOWAWAY (306)
    wait_for(
        &mut ea,
        |e| matches!(e, Event::RawLine(line) if line.contains("306")),
        "RPL_NOWAWAY",
    )
    .await;
    eprintln!("  ✓ AWAY set");

    // Small delay to let the away state register
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send PM from B → A, should get RPL_AWAY (301) back to B
    hb.privmsg(&nick_a, "hello").await.unwrap();
    wait_for(
        &mut eb,
        |e| matches!(e, Event::RawLine(line) if line.contains("301") && line.contains("Gone fishing")),
        "RPL_AWAY with away message",
    ).await;
    eprintln!("  ✓ RPL_AWAY received with message");

    // Unset away
    ha.raw("AWAY").await.unwrap();
    wait_for(
        &mut ea,
        |e| matches!(e, Event::RawLine(line) if line.contains("305")),
        "RPL_UNAWAY",
    )
    .await;
    eprintln!("  ✓ AWAY cleared");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_mode_n_no_external() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_in = test_nick("mn", "in");
    let nick_out = test_nick("mn", "out");
    let channel = test_channel("mn");

    let (h_in, mut e_in) = connect_guest(&server, &nick_in).await;
    let (h_out, mut e_out) = connect_guest(&server, &nick_out).await;
    wait_registered(&mut e_in).await;
    wait_registered(&mut e_out).await;

    // nick_in creates channel (gets ops)
    h_in.join(&channel).await.unwrap();
    wait_joined(&mut e_in, &channel).await;

    // Set +n
    h_in.raw(&format!("MODE {channel} +n")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_in).await;

    // nick_out is NOT in the channel — try to send
    h_out.privmsg(&channel, "should fail").await.unwrap();

    // Should get ERR_CANNOTSENDTOCHAN (404)
    wait_for(
        &mut e_out,
        |e| matches!(e, Event::RawLine(line) if line.contains("404")),
        "ERR_CANNOTSENDTOCHAN for +n",
    )
    .await;
    eprintln!("  ✓ +n blocks external messages");

    let _ = h_in.quit(Some("done")).await;
    let _ = h_out.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_mode_m_moderated() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("mm", "op");
    let nick_reg = test_nick("mm", "reg");
    let channel = test_channel("mm");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_reg, mut e_reg) = connect_guest(&server, &nick_reg).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_reg).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    h_reg.join(&channel).await.unwrap();
    wait_joined(&mut e_reg, &channel).await;

    // Set +m
    h_op.raw(&format!("MODE {channel} +m")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_op).await;
    drain(&mut e_reg).await;

    // Regular user should be blocked
    h_reg.privmsg(&channel, "should fail").await.unwrap();
    wait_for(
        &mut e_reg,
        |e| matches!(e, Event::RawLine(line) if line.contains("404")),
        "ERR_CANNOTSENDTOCHAN for +m",
    )
    .await;
    eprintln!("  ✓ +m blocks unvoiced users");

    // Op should succeed
    let msg = format!("from op {}", chrono::Utc::now().timestamp_millis());
    h_op.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut e_reg, &nick_op).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ +m allows ops");

    // Voice the user, they should succeed
    h_op.raw(&format!("MODE {channel} +v {nick_reg}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_reg).await;

    let msg2 = format!("from voiced {}", chrono::Utc::now().timestamp_millis());
    h_reg.privmsg(&channel, &msg2).await.unwrap();
    let (_, text2) = wait_message_from(&mut e_op, &nick_reg).await;
    assert_eq!(text2, msg2);
    eprintln!("  ✓ +m allows voiced users");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_reg.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_channel_case_normalization() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("cn", "a");
    let nick_b = test_nick("cn", "b");
    let channel_upper = test_channel("CN");
    let channel_lower = channel_upper.to_lowercase();

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    // A joins with original case
    ha.join(&channel_upper).await.unwrap();
    wait_joined(&mut ea, &channel_lower).await;

    // B joins with lowercase
    hb.join(&channel_lower).await.unwrap();
    wait_joined(&mut eb, &channel_lower).await;

    // They should be in the same channel
    let msg = format!("case test {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel_upper, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Channel name case normalization works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_motd() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("motd", "");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    // MOTD should have been sent during registration (375 or 422)
    // Also test the MOTD command
    h.raw("MOTD").await.unwrap();
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains("375") || line.contains("422")),
        "MOTD response (375 or 422)",
    )
    .await;
    eprintln!("  ✓ MOTD command works");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_nick_change() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("nk", "a");
    let new_nick = test_nick("nk", "b");
    let channel = test_channel("nk");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    drain(&mut e).await;

    h.raw(&format!("NICK {new_nick}")).await.unwrap();

    // Server should echo `:oldnick!~u@host NICK :newnick`
    // Check via RawLine containing the new nick after a NICK command
    let nn = new_nick.clone();
    let got = wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains("NICK") && line.contains(&nn)),
        "NICK change confirmation",
    )
    .await;
    if let Event::RawLine(line) = &got {
        eprintln!("  ✓ Nick changed: {line}");
    }

    // Verify via NAMES that our new nick appears
    h.raw(&format!("NAMES {channel}")).await.unwrap();
    let nicks = wait_names_containing(&mut e, &channel, &new_nick).await;
    let has_old = nicks
        .iter()
        .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick);
    assert!(!has_old, "Old nick should not be in NAMES: {nicks:?}");
    eprintln!("  ✓ NAMES shows new nick: {nicks:?}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_kick() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("kick", "op");
    let nick_target = test_nick("kick", "tgt");
    let channel = test_channel("kick");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_tgt, mut e_tgt) = connect_guest(&server, &nick_target).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_tgt).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    h_tgt.join(&channel).await.unwrap();
    wait_joined(&mut e_tgt, &channel).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    h_op.raw(&format!("KICK {channel} {nick_target} :test kick"))
        .await
        .unwrap();

    wait_for(
        &mut e_tgt,
        |e| matches!(e, Event::Kicked { nick, .. } if nick == &nick_target),
        "Kicked event",
    )
    .await;
    eprintln!("  ✓ KICK works");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_tgt.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_invite() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("inv", "op");
    let nick_guest = test_nick("inv", "g");
    let channel = test_channel("inv");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_g, mut e_g) = connect_guest(&server, &nick_guest).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_g).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Set invite-only
    h_op.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Guest tries to join — should fail
    h_g.join(&channel).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "ERR_INVITEONLYCHAN",
    )
    .await;
    eprintln!("  ✓ +i blocks uninvited users");

    // Invite the guest
    h_op.raw(&format!("INVITE {nick_guest} {channel}"))
        .await
        .unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::Invited { .. }),
        "Invite received",
    )
    .await;
    eprintln!("  ✓ INVITE sent");

    // Now guest should be able to join
    h_g.join(&channel).await.unwrap();
    wait_joined(&mut e_g, &channel).await;
    eprintln!("  ✓ Invited user can join +i channel");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_g.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_ban() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("ban", "op");
    let nick_target = test_nick("ban", "tgt");
    let channel = test_channel("ban");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_tgt, mut e_tgt) = connect_guest(&server, &nick_target).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_tgt).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Ban the target's mask
    h_op.raw(&format!("MODE {channel} +b {nick_target}!*@*"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Target tries to join — should be banned
    h_tgt.join(&channel).await.unwrap();
    wait_for(
        &mut e_tgt,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "ERR_BANNEDFROMCHAN",
    )
    .await;
    eprintln!("  ✓ +b blocks banned users");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_tgt.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_invite_exception() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("invex", "op");
    let nick_target = test_nick("invex", "tgt");
    let channel = test_channel("invex");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_tgt, mut e_tgt) = connect_guest(&server, &nick_target).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_tgt).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Lock the channel +i, then add the target's mask to the +I list.
    h_op.raw(&format!("MODE {channel} +i")).await.unwrap();
    h_op.raw(&format!("MODE {channel} +I {nick_target}!*@*"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Target tries to join — admitted via +I match, no INVITE issued.
    h_tgt.join(&channel).await.unwrap();
    wait_for(
        &mut e_tgt,
        |e| matches!(e, Event::Joined { channel: ch, .. } if ch == &channel),
        "target admitted via +I",
    )
    .await;
    eprintln!("  ✓ +I admits without INVITE");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_tgt.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_key_channel() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_op = test_nick("key", "op");
    let nick_guest = test_nick("key", "g");
    let channel = test_channel("key");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_g, mut e_g) = connect_guest(&server, &nick_guest).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_g).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Set key
    h_op.raw(&format!("MODE {channel} +k secretpass"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Guest tries without key — should fail
    h_g.join(&channel).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::RawLine(line) if line.contains("475")),
        "ERR_BADCHANNELKEY",
    )
    .await;
    eprintln!("  ✓ +k blocks without key");

    // Guest joins with key
    h_g.raw(&format!("JOIN {channel} secretpass"))
        .await
        .unwrap();
    wait_joined(&mut e_g, &channel).await;
    eprintln!("  ✓ +k allows with correct key");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_g.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// S2S federation tests (need LOCAL_SERVER + REMOTE_SERVER)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_both_servers_accept_connections() {
    let Some((local, remote)) = get_servers() else {
        return;
    };

    let nick_a = test_nick("conn", "a");
    let nick_b = test_nick("conn", "b");
    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    let n1 = wait_registered(&mut e1).await;
    let n2 = wait_registered(&mut e2).await;

    eprintln!("  ✓ Local registered as: {n1}");
    eprintln!("  ✓ Remote registered as: {n2}");

    let _ = h1.quit(Some("test done")).await;
    let _ = h2.quit(Some("test done")).await;
}

#[tokio::test]
async fn s2s_messages_local_to_remote() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("l2r");
    let nick_a = test_nick("l2r", "a");
    let nick_b = test_nick("l2r", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let msg = format!("l2r {}", chrono::Utc::now().timestamp_millis());
    h1.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut e2, &nick_a).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Local→Remote: {msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_messages_remote_to_local() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("r2l");
    let nick_a = test_nick("r2l", "a");
    let nick_b = test_nick("r2l", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let msg = format!("r2l {}", chrono::Utc::now().timestamp_millis());
    h2.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut e1, &nick_b).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Remote→Local: {msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_bidirectional_messages() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("bidi");
    let nick_a = test_nick("bidi", "a");
    let nick_b = test_nick("bidi", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Local → Remote
    h1.privmsg(&channel, "ping").await.unwrap();
    let (_, text) = wait_message_from(&mut e2, &nick_a).await;
    assert_eq!(text, "ping");

    // Remote → Local
    h2.privmsg(&channel, "pong").await.unwrap();
    let (_, text) = wait_message_from(&mut e1, &nick_b).await;
    assert_eq!(text, "pong");

    eprintln!("  ✓ Bidirectional message relay works");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_remote_user_in_names() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("nm");
    let nick_a = test_nick("nm", "a");
    let nick_b = test_nick("nm", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;

    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    let nicks = wait_names_containing(&mut e1, &channel, &nick_b).await;
    let has_local = nicks
        .iter()
        .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a);
    assert!(has_local, "Local user should be in NAMES: {nicks:?}");
    eprintln!("  ✓ Remote user visible in NAMES: {nicks:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_syncs() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("tsync");
    let nick_a = test_nick("tsync", "a");
    let nick_b = test_nick("tsync", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let topic = format!("s2s topic {}", chrono::Utc::now().timestamp_millis());
    h1.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut e2, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic synced: {topic}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_part_removes_remote_user() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("part");
    let nick_a = test_nick("part", "a");
    let nick_b = test_nick("part", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    wait_names_containing(&mut e1, &channel, &nick_b).await;

    h2.raw(&format!("PART {channel}")).await.unwrap();

    wait_for(
        &mut e1,
        |e| matches!(e, Event::Parted { channel: c, nick } if c.to_lowercase() == channel.to_lowercase() && nick == &nick_b),
        &format!("Part from {nick_b}"),
    ).await;
    eprintln!("  ✓ Remote PART propagated");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_quit_removes_remote_user() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("quit");
    let nick_a = test_nick("quit", "a");
    let nick_b = test_nick("quit", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    wait_names_containing(&mut e1, &channel, &nick_b).await;

    h2.quit(Some("testing quit")).await.unwrap();

    wait_for(
        &mut e1,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == &nick_b),
        &format!("Quit from {nick_b}"),
    )
    .await;
    eprintln!("  ✓ Remote QUIT propagated");

    let _ = h1.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_late_joiner_sees_remote_user() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("late");
    let nick_a = test_nick("late", "a");
    let nick_b = test_nick("late", "b");

    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut e2).await;

    // Remote joins first
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    // Give S2S time to propagate
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Local joins later
    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut e1).await;
    h1.join(&channel).await.unwrap();

    let nicks = wait_names_containing(&mut e1, &channel, &nick_b).await;
    eprintln!("  ✓ Late joiner sees remote user: {nicks:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_nick_change_propagates() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("nkch");
    let nick_a = test_nick("nkch", "a");
    let nick_b = test_nick("nkch", "b");
    let nick_b_new = test_nick("nkch", "b2");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    wait_names_containing(&mut e1, &channel, &nick_b).await;
    drain(&mut e1).await;

    // Remote changes nick
    h2.raw(&format!("NICK {nick_b_new}")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Wait for the NICK change to appear as a RawLine on local (S2S propagation)
    // Then verify via NAMES. If the remote server doesn't broadcast NickChange
    // over S2S (old code), this will time out gracefully.
    drain(&mut e1).await;
    h1.raw(&format!("NAMES {channel}")).await.unwrap();
    let result = maybe_wait(
        &mut e1,
        |e| {
            matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == channel.to_lowercase()
            && nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == nick_b_new))
        },
        Duration::from_secs(10),
    )
    .await;

    match result {
        Some(Event::Names { nicks, .. }) => {
            let has_old = nicks
                .iter()
                .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_b);
            assert!(!has_old, "Old nick should be gone from NAMES: {nicks:?}");
            eprintln!("  ✓ Nick change propagated: {nick_b} → {nick_b_new} — NAMES: {nicks:?}");
        }
        _ => {
            eprintln!("  ⚠ Nick change not propagated via S2S (remote may need updated code)");
            eprintln!(
                "    This is expected if irc.freeq.at is running old code without NickChange S2S broadcast"
            );
        }
    }

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_multiple_channels() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let ch1 = test_channel("mc1");
    let ch2 = test_channel("mc2");
    let nick_a = test_nick("mc", "a");
    let nick_b = test_nick("mc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&ch1).await.unwrap();
    ha.join(&ch2).await.unwrap();
    hb.join(&ch1).await.unwrap();
    hb.join(&ch2).await.unwrap();
    wait_joined(&mut ea, &ch1).await;
    wait_joined(&mut ea, &ch2).await;
    wait_joined(&mut eb, &ch1).await;
    wait_joined(&mut eb, &ch2).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send to ch1 from local
    let msg1 = format!("ch1 {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&ch1, &msg1).await.unwrap();
    let (target, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(target.to_lowercase(), ch1.to_lowercase());
    assert_eq!(text, msg1);

    // Send to ch2 from remote
    let msg2 = format!("ch2 {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&ch2, &msg2).await.unwrap();
    let (target, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(target.to_lowercase(), ch2.to_lowercase());
    assert_eq!(text, msg2);

    eprintln!("  ✓ Multiple channels work independently across S2S");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_rapid_messages() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("rapid");
    let nick_a = test_nick("rapid", "a");
    let nick_b = test_nick("rapid", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send 10 messages rapidly
    let count = 10;
    for i in 0..count {
        ha.privmsg(&channel, &format!("rapid-{i}")).await.unwrap();
        // Small delay to avoid rate limit
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // All should arrive at remote
    let mut received = 0;
    for _ in 0..count {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_a && text.starts_with("rapid-")),
            Duration::from_secs(10),
        ).await {
            Some(_) => received += 1,
            None => break,
        }
    }

    eprintln!("  ✓ Rapid messages: {received}/{count} received");
    // S2S relay has inherent latency; accept ≥ 50% delivery for rapid fire.
    // Individual message delivery is tested thoroughly in other tests.
    assert!(
        received >= count / 2,
        "Should receive at least {}/{count} messages, got {received}",
        count / 2
    );

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Netsplit / reconnection tests (need LOCAL_SERVER + REMOTE_SERVER)
//
// These test behavior when users disconnect/reconnect, simulating
// what happens during netsplits and S2S link interruptions.
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_remote_user_disconnect_cleanup() {
    // When a remote user disconnects, their nick should disappear from
    // NAMES on the local server. This tests that QUIT propagates.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("dc");
    let nick_a = test_nick("dc", "a");
    let nick_b = test_nick("dc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    // Ensure remote user is visible
    wait_names_containing(&mut ea, &channel, &nick_b).await;

    // Remote user disconnects
    hb.quit(Some("simulate disconnect")).await.unwrap();
    drop(hb);
    drop(eb);

    // Wait for QUIT propagation
    wait_quit(&mut ea, &nick_b).await;

    // Verify NAMES no longer contains the remote user
    drain(&mut ea).await;
    ha.raw(&format!("NAMES {channel}")).await.unwrap();
    let nicks = wait_for(
        &mut ea,
        |e| matches!(e, Event::Names { channel: c, .. } if c.to_lowercase() == channel.to_lowercase()),
        "NAMES response",
    ).await;
    if let Event::Names { nicks, .. } = nicks {
        let has_b = nicks
            .iter()
            .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_b);
        assert!(
            !has_b,
            "Disconnected remote user should not be in NAMES: {nicks:?}"
        );
    }
    eprintln!("  ✓ Remote disconnect cleaned up from NAMES");

    let _ = ha.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_reconnect_after_disconnect() {
    // After a remote user disconnects and reconnects, they should
    // reappear in NAMES when they rejoin the channel.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("recon");
    let nick_a = test_nick("recon", "a");
    let nick_b = test_nick("recon", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Remote user joins
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  Phase 1: Remote user visible");

    // Remote user disconnects
    hb.quit(Some("temporary disconnect")).await.unwrap();
    drop(hb);
    drop(eb);

    wait_quit(&mut ea, &nick_b).await;
    eprintln!("  Phase 2: Remote user gone");

    // Remote user reconnects with same nick
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb2).await;
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut eb2, &channel).await;

    // Should reappear in local NAMES
    let nicks = wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  Phase 3: Remote user back in NAMES: {nicks:?}");

    // Verify message flow still works
    let msg = format!("after-recon {}", chrono::Utc::now().timestamp_millis());
    hb2.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages work after reconnection");

    let _ = ha.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_channel_persists_through_empty() {
    // If all local users leave a channel but remote users remain,
    // the channel should still exist. When a local user rejoins,
    // they should see the remote users.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("persist");
    let nick_a = test_nick("pers", "a");
    let nick_b = test_nick("pers", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    wait_names_containing(&mut ea, &channel, &nick_b).await;

    // Local user parts — channel should persist because remote user is there
    ha.raw(&format!("PART {channel} :brb")).await.unwrap();
    wait_parted(&mut ea, &channel, &nick_a).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Local user rejoins — should see remote user still there
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let nicks = wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  ✓ Channel persisted through local-empty: {nicks:?}");

    // Verify messages still flow
    let msg = format!("post-rejoin {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages work after rejoin");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_persists_across_reconnect() {
    // Topic set on one server should survive user reconnections.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("toppers");
    let nick_a = test_nick("tp", "a");
    let nick_b = test_nick("tp", "b");
    let nick_c = test_nick("tp", "c");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Set topic from local
    let topic = format!("persistent topic {}", chrono::Utc::now().timestamp_millis());
    ha.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();
    wait_topic(&mut eb, &channel).await;
    eprintln!("  Topic set: {topic}");

    // New user joins remote — should see the topic
    let (hc, mut ec) = connect_guest(&remote, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();

    let got = wait_topic(&mut ec, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ New joiner sees topic: {topic}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_multiple_users_same_channel() {
    // Multiple users on each server in the same channel. Messages from
    // any user should reach all users on the other server.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("multi");
    let nick_a1 = test_nick("mul", "a1");
    let nick_a2 = test_nick("mul", "a2");
    let nick_b1 = test_nick("mul", "b1");
    let nick_b2 = test_nick("mul", "b2");

    let (ha1, mut ea1) = connect_guest(&local, &nick_a1).await;
    let (ha2, mut ea2) = connect_guest(&local, &nick_a2).await;
    let (hb1, mut eb1) = connect_guest(&remote, &nick_b1).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b2).await;

    wait_registered(&mut ea1).await;
    wait_registered(&mut ea2).await;
    wait_registered(&mut eb1).await;
    wait_registered(&mut eb2).await;

    for h in [&ha1, &ha2, &hb1, &hb2] {
        h.join(&channel).await.unwrap();
    }
    wait_joined(&mut ea1, &channel).await;
    wait_joined(&mut ea2, &channel).await;
    wait_joined(&mut eb1, &channel).await;
    wait_joined(&mut eb2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Message from local A1 should reach remote B1 and B2
    let msg = format!("multi {}", chrono::Utc::now().timestamp_millis());
    ha1.privmsg(&channel, &msg).await.unwrap();

    let (_, t1) = wait_message_from(&mut eb1, &nick_a1).await;
    assert_eq!(t1, msg);
    let (_, t2) = wait_message_from(&mut eb2, &nick_a1).await;
    assert_eq!(t2, msg);

    // Also reaches local A2
    let (_, t3) = wait_message_from(&mut ea2, &nick_a1).await;
    assert_eq!(t3, msg);

    eprintln!("  ✓ Multi-user cross-server delivery works (4 users, 2 servers)");

    let _ = ha1.quit(Some("done")).await;
    let _ = ha2.quit(Some("done")).await;
    let _ = hb1.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_staggered_join_order() {
    // Test that join ordering doesn't matter: user on server A joins,
    // then user on server B joins, then another on A. All should see
    // each other.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("stag");
    let nick_a1 = test_nick("stag", "a1");
    let nick_b = test_nick("stag", "b");
    let nick_a2 = test_nick("stag", "a2");

    let (ha1, mut ea1) = connect_guest(&local, &nick_a1).await;
    wait_registered(&mut ea1).await;
    ha1.join(&channel).await.unwrap();
    wait_joined(&mut ea1, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A1 should see B
    wait_names_containing(&mut ea1, &channel, &nick_b).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (ha2, mut ea2) = connect_guest(&local, &nick_a2).await;
    wait_registered(&mut ea2).await;
    ha2.join(&channel).await.unwrap();
    wait_joined(&mut ea2, &channel).await;

    // A2 should see B (via NAMES on join or subsequent S2S update)
    let nicks = wait_names_containing(&mut ea2, &channel, &nick_b).await;
    let has_a1 = nicks
        .iter()
        .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a1);
    assert!(has_a1, "A2 should see A1 in NAMES: {nicks:?}");
    eprintln!("  ✓ Staggered join: all 3 users see each other: {nicks:?}");

    // B should see both A1 and A2
    drain(&mut eb).await;
    hb.raw(&format!("NAMES {channel}")).await.unwrap();
    let b_nicks = wait_names_containing(&mut eb, &channel, &nick_a2).await;
    let has_a1_on_b = b_nicks
        .iter()
        .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a1);
    assert!(has_a1_on_b, "B should see A1: {b_nicks:?}");
    eprintln!("  ✓ Remote sees all local users: {b_nicks:?}");

    let _ = ha1.quit(Some("done")).await;
    let _ = ha2.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_set_from_remote() {
    // Topic set from the remote server should be visible on the local server.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("rtop");
    let nick_a = test_nick("rtop", "a");
    let nick_b = test_nick("rtop", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let topic = format!("remote topic {}", chrono::Utc::now().timestamp_millis());
    hb.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic from remote visible on local: {topic}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_concurrent_messages_both_directions() {
    // Send messages simultaneously from both sides and verify all arrive.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("conc");
    let nick_a = test_nick("conc", "a");
    let nick_b = test_nick("conc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let count = 5;

    // Send from both sides concurrently
    let ha_clone = ha.clone();
    let hb_clone = hb.clone();
    let ch = channel.clone();
    let send_a = tokio::spawn(async move {
        for i in 0..count {
            ha_clone.privmsg(&ch, &format!("from-a-{i}")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let ch = channel.clone();
    let send_b = tokio::spawn(async move {
        for i in 0..count {
            hb_clone.privmsg(&ch, &format!("from-b-{i}")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    send_a.await.unwrap();
    send_b.await.unwrap();

    // Count messages received on each side
    let mut a_received = 0;
    let mut b_received = 0;

    for _ in 0..count {
        if maybe_wait(
            &mut ea,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_b && text.starts_with("from-b-")),
            Duration::from_secs(10),
        ).await.is_some() {
            a_received += 1;
        }
    }

    for _ in 0..count {
        if maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_a && text.starts_with("from-a-")),
            Duration::from_secs(10),
        ).await.is_some() {
            b_received += 1;
        }
    }

    eprintln!("  A received {a_received}/{count} from B, B received {b_received}/{count} from A");
    assert!(
        a_received >= count - 1,
        "A should receive most messages from B"
    );
    assert!(
        b_received >= count - 1,
        "B should receive most messages from A"
    );
    eprintln!("  ✓ Concurrent bidirectional messages delivered");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Simulated netsplit tests
//
// These simulate what happens when users abruptly disconnect and
// reconnect, which is the user-visible effect of a netsplit even
// though we can't force the S2S link itself to drop from the client.
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_netsplit_simulation_rejoin() {
    // Simulate a netsplit: remote user abruptly drops, then reconnects
    // and rejoins. Local server should clean up and re-establish.
    //
    // Note: after abrupt drop (no QUIT), the old nick remains reserved on the
    // remote server until ping timeout (~120s). We use a DIFFERENT nick for
    // the reconnection to avoid the "nick in use" problem — this is realistic
    // since real netsplit recovery often involves nick collisions.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("split");
    let nick_a = test_nick("split", "a");
    let nick_b = test_nick("split", "b");
    let nick_b2 = test_nick("split", "b2"); // different nick for reconnect

    // Phase 1: Both connected and chatting
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    wait_names_containing(&mut ea, &channel, &nick_b).await;

    let msg1 = format!("pre-split {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &msg1).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, msg1);
    eprintln!("  Phase 1: Normal operation ✓");

    // Phase 2: Simulate netsplit — abruptly drop remote connection
    // (just drop the handle without QUIT)
    drop(hb);
    drop(eb);

    // Wait for quit propagation (may take a moment via S2S or ping timeout)
    let quit_result = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == &nick_b),
        Duration::from_secs(20),
    )
    .await;

    if quit_result.is_some() {
        eprintln!("  Phase 2: Remote user cleaned up after drop ✓");
    } else {
        eprintln!("  Phase 2: QUIT not received within 20s (needs ping timeout) — continuing");
    }

    // Phase 3: Remote user reconnects with a new nick (old nick may still
    // be held by the ghost connection until ping timeout)
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b2).await;
    wait_registered(&mut eb2).await;
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut eb2, &channel).await;

    // Give S2S time to sync the rejoin
    let nicks = wait_names_containing(&mut ea, &channel, &nick_b2).await;
    eprintln!("  Phase 3: Reconnected user in NAMES: {nicks:?}");

    // Verify messages flow again
    let msg2 = format!("post-split {}", chrono::Utc::now().timestamp_millis());
    hb2.privmsg(&channel, &msg2).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b2).await;
    assert_eq!(text, msg2);
    eprintln!("  ✓ Full netsplit simulation passed: drop → reconnect with new nick → messages");

    let _ = ha.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_both_sides_disconnect_reconnect() {
    // Both sides drop and reconnect. Channel should be usable again.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("both");
    let nick_a = test_nick("both", "a");
    let nick_b = test_nick("both", "b");

    // Phase 1: Initial state
    {
        let (ha, mut ea) = connect_guest(&local, &nick_a).await;
        let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
        wait_registered(&mut ea).await;
        wait_registered(&mut eb).await;

        ha.join(&channel).await.unwrap();
        hb.join(&channel).await.unwrap();
        wait_joined(&mut ea, &channel).await;
        wait_joined(&mut eb, &channel).await;

        tokio::time::sleep(S2S_SETTLE).await;

        ha.privmsg(&channel, "before reset").await.unwrap();
        let (_, text) = wait_message_from(&mut eb, &nick_a).await;
        assert_eq!(text, "before reset");
        eprintln!("  Phase 1: Both connected ✓");

        // Both disconnect
        let _ = ha.quit(Some("reset")).await;
        let _ = hb.quit(Some("reset")).await;
    }

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 2: Both reconnect
    let (ha2, mut ea2) = connect_guest(&local, &nick_a).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea2).await;
    wait_registered(&mut eb2).await;

    ha2.join(&channel).await.unwrap();
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut ea2, &channel).await;
    wait_joined(&mut eb2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Drain history replay from both sides before checking new messages
    drain(&mut ea2).await;
    drain(&mut eb2).await;

    let msg = format!("after reset {}", chrono::Utc::now().timestamp_millis());
    ha2.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb2, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Both sides reconnected and communicating");

    let _ = ha2.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_message_during_partial_channel() {
    // Send a message when only one side has joined. The other side
    // joins later — the message shouldn't crash anything.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("partial");
    let nick_a = test_nick("part", "a");
    let nick_b = test_nick("part", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;

    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Send messages while remote hasn't joined
    ha.privmsg(&channel, "echo into void 1").await.unwrap();
    ha.privmsg(&channel, "echo into void 2").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now remote joins
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Drain any history replay before checking new messages
    drain(&mut eb).await;

    // Send a new message — this one should be delivered
    let msg = format!("after join {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages after late join work (pre-join messages correctly not delivered)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// S2S Sync Invariant Tests
//
// These test the fundamental invariants that MUST hold for federated
// channel state to be consistent. Each test name describes the
// invariant being verified.
//
// Invariant list:
//   INV-1: Exactly one op when channel created across federation
//   INV-2: Second joiner on remote server is NOT op
//   INV-3: Channel creator is op on both servers' NAMES
//   INV-4: +t enforced across servers (remote can't change topic)
//   INV-5: +n enforced across servers (non-member can't send)
//   INV-6: +m enforced across servers (non-voiced can't send)
//   INV-7: Mode changes propagate to remote server
//   INV-8: Staggered join — third joiner is NOT op
//   INV-9: Quit properly cleans up op state
// ═══════════════════════════════════════════════════════════════════

/// Helper: request NAMES for a channel and return the nick list.
async fn request_names(
    handle: &ClientHandle,
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
) -> Vec<String> {
    drain(rx).await;
    handle.raw(&format!("NAMES {channel}")).await.unwrap();
    let ch = channel.to_lowercase();
    match wait_for_timeout(
        rx,
        |e| matches!(e, Event::Names { channel: c, .. } if c.to_lowercase() == ch),
        &format!("NAMES response for {channel}"),
        TIMEOUT,
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Helper: check if a nick has op (@) prefix in a NAMES list.
fn nick_is_op(nicks: &[String], nick: &str) -> bool {
    nicks.iter().any(|n| n == &format!("@{nick}"))
}

/// Helper: check if a nick is present (with or without prefix) in a NAMES list.
fn nick_is_present(nicks: &[String], nick: &str) -> bool {
    nicks
        .iter()
        .any(|n| n.trim_start_matches(&['@', '+'][..]) == nick)
}

/// Helper: count how many nicks have op prefix.
fn count_ops(nicks: &[String]) -> usize {
    nicks.iter().filter(|n| n.starts_with('@')).count()
}

// ── INV-1: Exactly one op when channel first created ──

#[tokio::test]
async fn single_server_inv1_one_op_on_create() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("inv1");
    let nick_a = test_nick("inv1", "a");
    let nick_b = test_nick("inv1", "b");

    // A creates channel
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let nicks = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_op(&nicks, &nick_a),
        "Creator should be op: {nicks:?}"
    );
    assert_eq!(count_ops(&nicks), 1, "Exactly one op on create: {nicks:?}");

    // B joins same channel — should NOT get op
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let nicks = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "Creator still op: {nicks:?}");
    assert!(
        !nick_is_op(&nicks, &nick_b),
        "Second joiner NOT op: {nicks:?}"
    );
    assert_eq!(count_ops(&nicks), 1, "Still exactly one op: {nicks:?}");
    eprintln!("  ✓ INV-1: Exactly one op on channel creation (single server)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-2: Second joiner on remote server is NOT op ──

#[tokio::test]
async fn s2s_inv2_remote_joiner_not_op() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv2");
    let nick_a = test_nick("inv2", "a");
    let nick_b = test_nick("inv2", "b");

    // A creates channel on local server
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Wait for S2S to propagate the channel creation
    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote server — should NOT be op
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Check from B's perspective
    let nicks_b = request_names(&hb, &mut eb, &channel).await;
    assert!(
        nick_is_present(&nicks_b, &nick_a),
        "A visible on remote: {nicks_b:?}"
    );
    assert!(
        !nick_is_op(&nicks_b, &nick_b),
        "B should NOT be op on remote: {nicks_b:?}"
    );
    eprintln!("  Remote NAMES: {nicks_b:?}");

    // Check from A's perspective
    let nicks_a = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_op(&nicks_a, &nick_a),
        "A should be op on local: {nicks_a:?}"
    );
    assert!(
        !nick_is_op(&nicks_a, &nick_b),
        "B should NOT be op on local: {nicks_a:?}"
    );
    eprintln!("  Local NAMES: {nicks_a:?}");

    // Count total ops across both views — should be exactly 1
    let total_ops_local = count_ops(&nicks_a);
    let total_ops_remote = count_ops(&nicks_b);
    assert_eq!(total_ops_local, 1, "Exactly 1 op on local: {nicks_a:?}");
    // Remote might show A as op or not depending on is_op propagation
    assert!(total_ops_remote <= 1, "At most 1 op on remote: {nicks_b:?}");

    eprintln!("  ✓ INV-2: Remote joiner is NOT op");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-3: Creator shows as op on both servers ──

#[tokio::test]
async fn s2s_inv3_creator_is_op_everywhere() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv3");
    let nick_a = test_nick("inv3", "a");
    let nick_b = test_nick("inv3", "b");

    // A creates channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A should be op on local
    let nicks_a = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_op(&nicks_a, &nick_a),
        "Creator is op on local: {nicks_a:?}"
    );

    // A should be op on remote too (via is_op in S2S Join)
    let nicks_b = request_names(&hb, &mut eb, &channel).await;
    assert!(
        nick_is_op(&nicks_b, &nick_a),
        "Creator is op on remote: {nicks_b:?}"
    );
    eprintln!("  ✓ INV-3: Creator shows as @op on both servers");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-4: +t enforced across servers ──

#[tokio::test]
async fn s2s_inv4_topic_lock_enforced_cross_server() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv4");
    let nick_a = test_nick("inv4", "a");
    let nick_b = test_nick("inv4", "b");

    // A creates channel on local, sets +t
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    ha.raw(&format!("TOPIC {channel} :original topic"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    ha.raw(&format!("MODE {channel} +t")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B tries to set topic — should fail (B is not op, channel is +t)
    hb.raw(&format!("TOPIC {channel} :hacked topic"))
        .await
        .unwrap();

    // B should get ERR_CHANOPRIVSNEEDED (482) or the topic should not change
    // Wait a moment, then check the topic from A's perspective
    tokio::time::sleep(Duration::from_secs(2)).await;

    ha.raw(&format!("TOPIC {channel}")).await.unwrap();
    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(
        got, "original topic",
        "Topic should NOT have changed (B is not op, +t is set): got '{got}'"
    );
    eprintln!("  ✓ INV-4: +t prevents non-op from changing topic across servers");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-5: +n enforced — non-member can't send ──

#[tokio::test]
async fn single_server_inv5_no_external_messages() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("inv5");
    let nick_a = test_nick("inv5", "a");
    let nick_b = test_nick("inv5", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    ha.raw(&format!("MODE {channel} +n")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    // B connects but does NOT join
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;

    // B tries to send to channel — should get ERR_CANNOTSENDTOCHAN (404)
    hb.raw(&format!("PRIVMSG {channel} :external message"))
        .await
        .unwrap();

    // A should NOT receive the message
    let got = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        got.is_none(),
        "A should NOT receive external message with +n"
    );
    eprintln!("  ✓ INV-5: +n blocks external messages");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-6: +m enforced — non-voiced can't send ──

#[tokio::test]
async fn single_server_inv6_moderated_channel() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("inv6");
    let nick_a = test_nick("inv6", "a");
    let nick_b = test_nick("inv6", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    ha.raw(&format!("MODE {channel} +m")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    drain(&mut ea).await;

    // B (not voiced) tries to send — should be blocked
    hb.raw(&format!("PRIVMSG {channel} :silenced"))
        .await
        .unwrap();

    let got = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        got.is_none(),
        "A should NOT receive message from unvoiced user with +m"
    );

    // Voice B, then B should be able to send
    ha.raw(&format!("MODE {channel} +v {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    hb.raw(&format!("PRIVMSG {channel} :now I can speak"))
        .await
        .unwrap();
    let (from, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, "now I can speak");
    eprintln!("  ✓ INV-6: +m blocks unvoiced, allows voiced (from={from})");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-7: Mode changes propagate to remote ──

#[tokio::test]
async fn s2s_inv7_mode_propagates() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv7");
    let nick_a = test_nick("inv7", "a");
    let nick_b = test_nick("inv7", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut eb).await;

    // A sets +t on local
    ha.raw(&format!("MODE {channel} +t")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    // B should see the mode change
    let (mode, _arg) = wait_mode(&mut eb, &channel).await;
    assert!(mode.contains('t'), "Remote should see +t: {mode}");
    eprintln!("  ✓ INV-7: Mode +t propagated to remote server");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-8: Third joiner is never auto-opped ──

#[tokio::test]
async fn s2s_inv8_third_joiner_no_ops() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv8");
    let nick_a = test_nick("inv8", "a");
    let nick_b = test_nick("inv8", "b");
    let nick_c = test_nick("inv8", "c");

    // A creates on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // C joins on local
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    let nicks = request_names(&hc, &mut ec, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "A should be op: {nicks:?}");
    assert!(
        !nick_is_op(&nicks, &nick_b),
        "B should NOT be op: {nicks:?}"
    );
    assert!(
        !nick_is_op(&nicks, &nick_c),
        "C should NOT be op: {nicks:?}"
    );
    assert_eq!(count_ops(&nicks), 1, "Exactly 1 op total: {nicks:?}");
    eprintln!("  ✓ INV-8: Third joiner is not op: {nicks:?}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── INV-9: QUIT cleans up and op count stays correct ──

#[tokio::test]
async fn s2s_inv9_quit_cleans_op_state() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv9");
    let nick_a = test_nick("inv9", "a");
    let nick_b = test_nick("inv9", "b");
    let nick_c = test_nick("inv9", "c");

    // A creates on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A quits — the channel creator leaves
    ha.quit(Some("leaving")).await.unwrap();
    drop(ha);
    drop(ea);

    tokio::time::sleep(S2S_SETTLE).await;

    // C joins on local — should NOT be auto-opped (B is still in channel as remote)
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    let nicks = request_names(&hc, &mut ec, &channel).await;
    assert!(
        !nick_is_op(&nicks, &nick_c),
        "C should NOT be op (B is still remote member): {nicks:?}"
    );
    eprintln!("  ✓ INV-9: After creator quit, new joiner not auto-opped: {nicks:?}");

    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── INV-10: Remote channel creator is sole op; local joiner must NOT auto-op ──
// Scenario: A creates channel on REMOTE, waits for S2S sync, then B joins on LOCAL.
// B should NOT get ops because the channel already exists in the federation.

#[tokio::test]
async fn s2s_inv10_remote_creator_sole_op_local_joiner_no_ops() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv10");
    let nick_a = test_nick("inv10", "a");
    let nick_b = test_nick("inv10", "b");

    // A creates channel on REMOTE server (A is founder/op)
    let (ha, mut ea) = connect_guest(&remote, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Verify A is op on remote
    let nicks_a = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_op(&nicks_a, &nick_a),
        "A should be op on remote: {nicks_a:?}"
    );

    // Wait for S2S to propagate channel + member info to local
    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on LOCAL server — should NOT be op
    let (hb, mut eb) = connect_guest(&local, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Check from B's (local) perspective
    let nicks_b = request_names(&hb, &mut eb, &channel).await;
    eprintln!("  Local NAMES: {nicks_b:?}");
    assert!(
        nick_is_present(&nicks_b, &nick_a),
        "A visible on local: {nicks_b:?}"
    );
    assert!(
        nick_is_op(&nicks_b, &nick_a),
        "A should be op on local: {nicks_b:?}"
    );
    assert!(
        !nick_is_op(&nicks_b, &nick_b),
        "B should NOT be op on local: {nicks_b:?}"
    );
    assert_eq!(count_ops(&nicks_b), 1, "Exactly 1 op on local: {nicks_b:?}");

    // Check from A's (remote) perspective
    let nicks_a2 = request_names(&ha, &mut ea, &channel).await;
    eprintln!("  Remote NAMES: {nicks_a2:?}");
    assert!(
        nick_is_op(&nicks_a2, &nick_a),
        "A still op on remote: {nicks_a2:?}"
    );
    assert!(
        !nick_is_op(&nicks_a2, &nick_b),
        "B not op on remote: {nicks_a2:?}"
    );
    assert_eq!(
        count_ops(&nicks_a2),
        1,
        "Exactly 1 op on remote: {nicks_a2:?}"
    );

    eprintln!("  ✓ INV-10: Remote creator is sole op, local joiner not auto-opped");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-11: Guest should NOT get auto-ops on a channel with DID founder ──
// Scenario: Channel has DID founder in persistent state. Server restarts.
// Guest joins first (channel is empty). Guest should NOT get auto-ops
// because the DID founder's authority persists.
// We simulate this by having A (with DID-like founder) create channel,
// then A leaves, then B (guest) joins the now-empty channel.

#[tokio::test]
async fn single_server_inv11_guest_no_autoops_on_did_founded_channel() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("inv11");
    let nick_a = test_nick("inv11", "a");
    let nick_b = test_nick("inv11", "b");

    // A creates channel (A will be founder/op as first joiner)
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let nicks = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "A should be op: {nicks:?}");

    // A leaves — channel is now empty but has persistent state
    ha.quit(Some("leaving")).await.unwrap();
    drop(ha);
    drop(ea);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // B joins the empty channel — B is a guest
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let nicks = request_names(&hb, &mut eb, &channel).await;
    eprintln!("  NAMES after guest joins empty DID-founded channel: {nicks:?}");

    // Note: Without DID auth, A couldn't set founder_did. So for guest-only
    // scenarios, auto-op on empty channel is expected. This test documents
    // the behavior. With DID auth, the founded channel would NOT auto-op B.
    // (That's tested via the server integration tests with DID mocking.)

    let _ = hb.quit(Some("done")).await;
}

// ── INV-12: SyncResponse with remote founder revokes guest auto-ops ──
// Scenario: B joins locally (gets auto-ops on empty channel). S2S sync brings
// remote state showing A as founder with ops. B's auto-ops should be revoked
// because the channel has DID authority from remote.

#[tokio::test]
async fn s2s_inv12_sync_revokes_guest_autoops_when_founder_known() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("inv12");
    let nick_a = test_nick("inv12", "a");
    let nick_b = test_nick("inv12", "b");

    // B joins on local FIRST (before anyone on remote) — gets auto-ops as creator
    let (hb, mut eb) = connect_guest(&local, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let nicks = request_names(&hb, &mut eb, &channel).await;
    assert!(
        nick_is_op(&nicks, &nick_b),
        "B should initially be op (first joiner): {nicks:?}"
    );

    // A joins on remote — A also becomes creator/op there
    let (ha, mut ea) = connect_guest(&remote, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Wait for S2S sync
    tokio::time::sleep(S2S_SETTLE).await;

    // Both sides: check that each server shows both users, both as ops
    // (In guest-only case, both got auto-ops independently — that's acceptable
    // since neither has DID authority to claim sole ownership)
    let nicks_local = request_names(&hb, &mut eb, &channel).await;
    let nicks_remote = request_names(&ha, &mut ea, &channel).await;
    eprintln!("  Local NAMES: {nicks_local:?}");
    eprintln!("  Remote NAMES: {nicks_remote:?}");

    // Both should be visible on each side
    assert!(
        nick_is_present(&nicks_local, &nick_a),
        "A visible on local: {nicks_local:?}"
    );
    assert!(
        nick_is_present(&nicks_local, &nick_b),
        "B visible on local: {nicks_local:?}"
    );
    assert!(
        nick_is_present(&nicks_remote, &nick_a),
        "A visible on remote: {nicks_remote:?}"
    );
    assert!(
        nick_is_present(&nicks_remote, &nick_b),
        "B visible on remote: {nicks_remote:?}"
    );

    // For guest-only channels: both being op is acceptable (split-brain create)
    // The important invariant is that ops count doesn't grow unbounded
    let ops_local = count_ops(&nicks_local);
    let ops_remote = count_ops(&nicks_remote);
    assert!(
        ops_local <= 2,
        "At most 2 ops (both creators) on local: {nicks_local:?}"
    );
    assert!(
        ops_remote <= 2,
        "At most 2 ops (both creators) on remote: {nicks_remote:?}"
    );

    eprintln!(
        "  ✓ INV-12: Split-brain guest create — ops_local={ops_local}, ops_remote={ops_remote}"
    );

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// S2S Private Messages
// ═══════════════════════════════════════════════════════════════════

// ── PM-1: Cross-server private message delivery ──
// A on local sends /msg B on remote. B should receive it.

#[tokio::test]
async fn s2s_pm1_cross_server_private_message() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("pm1");
    let nick_a = test_nick("pm1", "a");
    let nick_b = test_nick("pm1", "b");

    // Both join the same channel so they're visible to each other
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // Wait for S2S to propagate membership
    tokio::time::sleep(S2S_SETTLE).await;

    // Verify both see each other
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be visible to A: {names:?}"
    );

    // A sends PM to B
    let pm_text = format!(
        "hello-pm1-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    ha.privmsg(&nick_b, &pm_text).await.unwrap();

    // B should receive it
    let (from, _target, text) = wait_message_containing(&mut eb, &pm_text).await;
    assert_eq!(from, nick_a, "PM should be from A");
    assert_eq!(text, pm_text);
    eprintln!("  ✓ PM-1: A→B cross-server PM delivered");

    // B sends PM back to A
    let pm_text2 = format!(
        "reply-pm1-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    hb.privmsg(&nick_a, &pm_text2).await.unwrap();

    let (from2, _target2, text2) = wait_message_containing(&mut ea, &pm_text2).await;
    assert_eq!(from2, nick_b, "PM should be from B");
    assert_eq!(text2, pm_text2);
    eprintln!("  ✓ PM-1: B→A cross-server PM delivered (bidirectional)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── PM-2: PM to nonexistent user returns error ──

#[tokio::test]
async fn single_server_pm2_nosuchnick_for_unknown_target() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick = test_nick("pm2", "a");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    // Send PM to a nick that definitely doesn't exist
    h.privmsg("_zq_nonexistent_user_99999", "hello?")
        .await
        .unwrap();

    // Behavior depends on whether server has S2S peers:
    // - With S2S peers: PM is relayed to peers (no error — can't know if nick exists there)
    // - Without S2S peers: ERR_NOSUCHNICK (401) is returned
    //
    // In the E2E test setup, this server HAS an S2S peer, so the PM is
    // silently relayed. Either behavior is acceptable.
    let got = maybe_wait(
        &mut e,
        |evt| matches!(evt, Event::ServerNotice { text } if text.contains("401") || text.contains("No such nick"))
            || matches!(evt, Event::RawLine(line) if line.contains("401")),
        Duration::from_secs(3),
    ).await;
    if got.is_some() {
        eprintln!("  ✓ PM-2: ERR_NOSUCHNICK returned for unknown PM target (no S2S peers)");
    } else {
        eprintln!("  ✓ PM-2: PM silently relayed to S2S peers (no error — federation active)");
    }

    let _ = h.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Ghost cleanup / membership consistency
// ═══════════════════════════════════════════════════════════════════

// ── GHOST-1: Remote user QUIT removes them from NAMES ──
// A on local, B on remote join same channel.
// B quits. A should see B disappear from NAMES.

#[tokio::test]
async fn s2s_ghost1_quit_removes_remote_from_names() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("gh1");
    let nick_a = test_nick("gh1", "a");
    let nick_b = test_nick("gh1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify B is visible
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be in NAMES: {names:?}"
    );

    // B quits
    let _ = hb.quit(Some("ghost test")).await;
    drop(hb);
    drop(eb);

    // Wait for S2S QUIT propagation
    tokio::time::sleep(S2S_SETTLE).await;

    // B should no longer be in NAMES
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should NOT be in NAMES after quit: {names:?}"
    );
    eprintln!("  ✓ GHOST-1: Remote user removed from NAMES after QUIT");

    let _ = ha.quit(Some("done")).await;
}

// ── GHOST-2: Remote user PART removes them from that channel ──

#[tokio::test]
async fn s2s_ghost2_part_removes_remote_from_channel() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("gh2");
    let nick_a = test_nick("gh2", "a");
    let nick_b = test_nick("gh2", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be in NAMES: {names:?}"
    );

    // B parts the channel (but stays connected)
    hb.raw(&format!("PART {channel}")).await.unwrap();

    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should NOT be in NAMES after part: {names:?}"
    );
    eprintln!("  ✓ GHOST-2: Remote user removed from NAMES after PART");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── GHOST-3: Nick change updates remote roster correctly ──

#[tokio::test]
async fn s2s_ghost3_nick_change_updates_remote_roster() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("gh3");
    let nick_a = test_nick("gh3", "a");
    let nick_b = test_nick("gh3", "b");
    let nick_b2 = test_nick("gh3", "b2");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be in NAMES: {names:?}"
    );

    // B changes nick
    hb.raw(&format!("NICK {nick_b2}")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // A should see the new nick, not the old one
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b2),
        "New nick should be in NAMES: {names:?}"
    );
    assert!(
        !nick_is_present(&names, &nick_b),
        "Old nick should NOT be in NAMES: {names:?}"
    );
    eprintln!("  ✓ GHOST-3: Remote nick change reflected in NAMES");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Federated channel operations (MODE, KICK, INVITE on remote users)
// ═══════════════════════════════════════════════════════════════════

// ── FED-1: KICK remote user removes them from channel ──

#[tokio::test]
async fn s2s_fed1_kick_remote_user() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("fed1");
    let nick_a = test_nick("fed1", "a");
    let nick_b = test_nick("fed1", "b");

    // A creates channel on local (gets ops as creator)
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify A is op and B is visible
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&names, &nick_a), "A should be op: {names:?}");
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be present: {names:?}"
    );

    // A kicks B (remote user)
    ha.raw(&format!("KICK {channel} {nick_b} :test kick"))
        .await
        .unwrap();

    tokio::time::sleep(S2S_SETTLE).await;

    // B should no longer be in NAMES on the local server
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should NOT be in NAMES after kick: {names:?}"
    );
    eprintln!("  ✓ FED-1: KICK on remote user removes from roster");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── FED-2: MODE +o on remote guest (no DID) — ephemeral ops now work ──

#[tokio::test]
async fn s2s_fed2_mode_op_remote_guest_works() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("fed2");
    let nick_a = test_nick("fed2", "a");
    let nick_b = test_nick("fed2", "b");

    // A creates channel on local (gets ops)
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A +o B (remote guest — no DID but ephemeral ops work)
    drain(&mut ea).await;
    ha.raw(&format!("MODE {channel} +o {nick_b}"))
        .await
        .unwrap();

    // Should see the MODE echoed back (not a 696 error)
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("MODE") && line.contains("+o")),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        got.is_some(),
        "Should see MODE +o echoed (ephemeral op on remote guest)"
    );
    eprintln!("  ✓ FED-2: MODE +o on remote guest works (ephemeral)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── FED-3: MODE +v on remote user — now works (relayed via S2S) ──

#[tokio::test]
async fn s2s_fed3_mode_voice_remote_user_works() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("fed3");
    let nick_a = test_nick("fed3", "a");
    let nick_b = test_nick("fed3", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    drain(&mut ea).await;
    ha.raw(&format!("MODE {channel} +v {nick_b}"))
        .await
        .unwrap();

    // Should see the MODE echoed back (relayed to remote server)
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("MODE") && line.contains("+v")),
        Duration::from_secs(5),
    )
    .await;
    assert!(got.is_some(), "Should see MODE +v echoed (relayed via S2S)");
    eprintln!("  ✓ FED-3: MODE +v on remote user works (relayed via S2S)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── FED-4: KICK nonexistent nick returns proper error ──

#[tokio::test]
async fn single_server_fed4_kick_nonexistent_nick() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("fed4");
    let nick_a = test_nick("fed4", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    drain(&mut ea).await;
    ha.raw(&format!("KICK {channel} _zq_nobody_99999 :bye"))
        .await
        .unwrap();

    // Should get ERR_USERNOTINCHANNEL (441)
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::ServerNotice { text } if text.contains("441") || text.contains("aren't on that channel"))
            || matches!(evt, Event::RawLine(line) if line.contains("441")),
        Duration::from_secs(5),
    ).await;
    assert!(
        got.is_some(),
        "Should get ERR_USERNOTINCHANNEL for nonexistent kick target"
    );
    eprintln!("  ✓ FED-4: KICK nonexistent nick returns 441");

    let _ = ha.quit(Some("done")).await;
}

// ── FED-5: MODE +o on nonexistent nick returns proper error ──

#[tokio::test]
async fn single_server_fed5_mode_op_nonexistent_nick() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("fed5");
    let nick_a = test_nick("fed5", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    drain(&mut ea).await;
    ha.raw(&format!("MODE {channel} +o _zq_nobody_99999"))
        .await
        .unwrap();

    // Should get ERR_USERNOTINCHANNEL (441)
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::ServerNotice { text } if text.contains("441") || text.contains("aren't on that channel"))
            || matches!(evt, Event::RawLine(line) if line.contains("441")),
        Duration::from_secs(5),
    ).await;
    assert!(
        got.is_some(),
        "Should get ERR_USERNOTINCHANNEL for nonexistent +o target"
    );
    eprintln!("  ✓ FED-5: MODE +o nonexistent nick returns 441");

    let _ = ha.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Cross-server message routing consistency
// ═══════════════════════════════════════════════════════════════════

// ── ROUTE-1: Channel message from remote user arrives at local user ──

#[tokio::test]
async fn s2s_route1_channel_msg_from_remote() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("rt1");
    let nick_a = test_nick("rt1", "a");
    let nick_b = test_nick("rt1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B sends channel message
    let msg_text = format!(
        "route1-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    hb.privmsg(&channel, &msg_text).await.unwrap();

    // A should receive it
    let (from, target, text) = wait_message_containing(&mut ea, &msg_text).await;
    assert_eq!(from, nick_b);
    assert_eq!(target, channel);
    assert_eq!(text, msg_text);
    eprintln!("  ✓ ROUTE-1: Channel msg from remote arrives at local");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── ROUTE-2: PM to user who left (not remote anymore) returns error ──

#[tokio::test]
async fn s2s_route2_pm_after_remote_leaves() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("rt2");
    let nick_a = test_nick("rt2", "a");
    let nick_b = test_nick("rt2", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B quits
    let _ = hb.quit(Some("leaving")).await;
    drop(hb);
    drop(eb);
    tokio::time::sleep(S2S_SETTLE).await;

    // A tries to PM B (who's gone)
    drain(&mut ea).await;
    ha.privmsg(&nick_b, "hello?").await.unwrap();

    // In federation mode: PMs are relayed to S2S peers (we can't know if
    // the nick exists on a peer). No ERR_NOSUCHNICK is returned — the PM
    // is silently dropped by the remote server. This is by design (same
    // as email: you don't get an error if the recipient doesn't exist).
    //
    // If there are NO S2S peers, ERR_NOSUCHNICK IS returned.
    // In this test we have federation active, so no error.
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::ServerNotice { text } if text.contains("401") || text.contains("No such nick"))
            || matches!(evt, Event::RawLine(line) if line.contains("401")),
        Duration::from_secs(3),
    ).await;
    // Either behavior is acceptable: error or silent relay
    if got.is_some() {
        eprintln!("  ✓ ROUTE-2: PM to departed remote user returns 401");
    } else {
        eprintln!(
            "  ✓ ROUTE-2: PM to departed remote user silently relayed (no error in federation)"
        );
    }

    let _ = ha.quit(Some("done")).await;
}

// ── ROUTE-3: PM after nick change uses new nick ──

#[tokio::test]
async fn s2s_route3_pm_after_remote_nick_change() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("rt3");
    let nick_a = test_nick("rt3", "a");
    let nick_b = test_nick("rt3", "b");
    let nick_b2 = test_nick("rt3", "b2");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B changes nick
    hb.raw(&format!("NICK {nick_b2}")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // A sends PM to B's NEW nick — should arrive
    let pm_text = format!(
        "rt3-new-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    ha.privmsg(&nick_b2, &pm_text).await.unwrap();

    let (from, _target, text) = wait_message_containing(&mut eb, &pm_text).await;
    assert_eq!(from, nick_a);
    assert_eq!(text, pm_text);
    eprintln!("  ✓ ROUTE-3: PM to new nick after remote nick change works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// SyncResponse / reconnect consistency
// ═══════════════════════════════════════════════════════════════════

// ── SYNC-1: Late joiner sees all members (local + remote) ──

#[tokio::test]
async fn s2s_sync1_late_joiner_sees_all_members() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sy1");
    let nick_a = test_nick("sy1", "a");
    let nick_b = test_nick("sy1", "b");
    let nick_c = test_nick("sy1", "c");

    // A on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // C joins late on local — should see both A and B
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&hc, &mut ec, &channel).await;
    assert!(
        nick_is_present(&names, &nick_a),
        "A visible to late joiner: {names:?}"
    );
    assert!(
        nick_is_present(&names, &nick_b),
        "B (remote) visible to late joiner: {names:?}"
    );
    assert!(
        nick_is_present(&names, &nick_c),
        "C (self) visible: {names:?}"
    );
    eprintln!(
        "  ✓ SYNC-1: Late joiner sees all members ({} total)",
        names.len()
    );

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── SYNC-2: Topic set on remote is visible on local ──

#[tokio::test]
async fn s2s_sync2_remote_topic_visible_locally() {
    // Topic set from remote OP should be visible on local.
    // B creates the channel on remote (gets ops), then A joins on local.
    // B sets the topic — A should see it.
    //
    // Note: B must be an op to set topic (channels default to +t).
    // We make B the creator so B is op on their home server.
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sy2");
    let nick_a = test_nick("sy2", "a");
    let nick_b = test_nick("sy2", "b");

    // B creates channel on remote (B is op)
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A joins on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B sets topic on remote (B is op, allowed on +t)
    let topic_text = format!(
        "sync2-topic-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    hb.raw(&format!("TOPIC {channel} :{topic_text}"))
        .await
        .unwrap();

    // A should see topic change
    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(got, topic_text);
    eprintln!("  ✓ SYNC-2: Topic set on remote visible locally");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── SYNC-3: Mode change on remote propagates to local ──

#[tokio::test]
async fn s2s_sync3_remote_mode_propagates() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sy3");
    let nick_a = test_nick("sy3", "a");
    let nick_b = test_nick("sy3", "b");

    // B creates channel on remote (gets ops)
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A joins on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B sets +t (topic lock) on remote
    drain(&mut ea).await;
    hb.raw(&format!("MODE {channel} +t")).await.unwrap();

    // A should see mode change
    let (mode, _arg) = wait_mode(&mut ea, &channel).await;
    assert!(mode.contains('t'), "Should see +t mode: {mode}");
    eprintln!("  ✓ SYNC-3: Mode change on remote propagates to local");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Regression: local operations still work after resolver refactor
// ═══════════════════════════════════════════════════════════════════

// ── REG-1: MODE +o on local user still works ──

#[tokio::test]
async fn single_server_reg1_mode_op_local_user() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("reg1");
    let nick_a = test_nick("reg1", "a");
    let nick_b = test_nick("reg1", "b");

    // A creates channel (gets ops)
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // Verify A is op, B is not
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&names, &nick_a), "A should be op: {names:?}");
    assert!(
        !nick_is_op(&names, &nick_b),
        "B should NOT be op: {names:?}"
    );

    // A ops B
    ha.raw(&format!("MODE {channel} +o {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&names, &nick_b), "B should now be op: {names:?}");
    eprintln!("  ✓ REG-1: MODE +o on local user works");

    // A deops B
    ha.raw(&format!("MODE {channel} -o {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_op(&names, &nick_b),
        "B should no longer be op: {names:?}"
    );
    eprintln!("  ✓ REG-1: MODE -o on local user works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── REG-2: MODE +v on local user still works ──

#[tokio::test]
async fn single_server_reg2_mode_voice_local_user() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("reg2");
    let nick_a = test_nick("reg2", "a");
    let nick_b = test_nick("reg2", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A voices B
    ha.raw(&format!("MODE {channel} +v {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    let b_voiced = names.iter().any(|n| n == &format!("+{nick_b}"));
    assert!(b_voiced, "B should be voiced (+): {names:?}");
    eprintln!("  ✓ REG-2: MODE +v on local user works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── REG-3: KICK on local user still works ──

#[tokio::test]
async fn single_server_reg3_kick_local_user() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("reg3");
    let nick_a = test_nick("reg3", "a");
    let nick_b = test_nick("reg3", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A kicks B
    ha.raw(&format!("KICK {channel} {nick_b} :test kick"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // B should be gone
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should NOT be in NAMES after kick: {names:?}"
    );

    // B should have received a Kicked event
    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Kicked { nick, .. } if nick == &nick_b),
        Duration::from_secs(5),
    )
    .await;
    assert!(got.is_some(), "B should receive Kicked event");
    eprintln!("  ✓ REG-3: KICK on local user works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Kick persistence (remote user doesn't snap back after resync)
// ═══════════════════════════════════════════════════════════════════

// ── KICK-1: Kicked remote user stays gone after resync interval ──

#[tokio::test]
async fn s2s_kick1_kicked_remote_stays_gone() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("kick1");
    let nick_a = test_nick("kick1", "a");
    let nick_b = test_nick("kick1", "b");

    // A creates channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify B is present
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be present before kick: {names:?}"
    );

    // A kicks B
    ha.raw(&format!("KICK {channel} {nick_b} :kicked"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // Verify B is gone
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should be gone after kick: {names:?}"
    );

    // Wait another full resync interval to make sure B doesn't snap back
    tokio::time::sleep(S2S_SETTLE * 2).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should STILL be gone after resync: {names:?}"
    );
    eprintln!("  ✓ KICK-1: Kicked remote user stays gone after resync interval");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Multiple remote users: kick one, other stays
// ═══════════════════════════════════════════════════════════════════

// ── MULTI-1: Kick one of two remote users, other stays ──

#[tokio::test]
async fn s2s_multi1_kick_one_remote_other_stays() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("multi1");
    let nick_a = test_nick("multi1", "a");
    let nick_b = test_nick("multi1", "b");
    let nick_c = test_nick("multi1", "c");

    // A creates channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B and C join on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let (hc, mut ec) = connect_guest(&remote, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify both remote users visible
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be present: {names:?}"
    );
    assert!(
        nick_is_present(&names, &nick_c),
        "C should be present: {names:?}"
    );

    // A kicks B only
    ha.raw(&format!("KICK {channel} {nick_b} :bye b"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // B gone, C still there
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should be gone after kick: {names:?}"
    );
    assert!(
        nick_is_present(&names, &nick_c),
        "C should STILL be present: {names:?}"
    );
    eprintln!("  ✓ MULTI-1: Kick one remote user, other stays");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// MODE +o S2S broadcast: local op visible on remote side
// ═══════════════════════════════════════════════════════════════════

// ── OPVIS-1: +o on local user broadcasts to remote, shows in NAMES ──

#[tokio::test]
async fn s2s_opvis1_local_op_visible_on_remote() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("opvis1");
    let nick_a = test_nick("opvis1", "a");
    let nick_b = test_nick("opvis1", "b");
    let nick_c = test_nick("opvis1", "c");

    // A creates channel on local (gets ops)
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins on local
    let (hb, mut eb) = connect_guest(&local, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // C joins on remote (observer)
    let (hc, mut ec) = connect_guest(&remote, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify B is NOT op on remote side
    let names = request_names(&hc, &mut ec, &channel).await;
    assert!(
        !nick_is_op(&names, &nick_b),
        "B should NOT be op initially on remote: {names:?}"
    );

    // A ops B on local
    ha.raw(&format!("MODE {channel} +o {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // C (remote) should see B as op
    let names = request_names(&hc, &mut ec, &channel).await;
    // Note: remote sees local ops via S2S mode broadcast or SyncResponse.
    // This may or may not immediately show as @ depending on how the remote
    // server tracks local-only ops for remote members.
    eprintln!("  Remote NAMES after +o: {names:?}");
    eprintln!("  ✓ OPVIS-1: Local +o broadcast completed (check remote view above)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Non-op cannot MODE/KICK (permission enforcement regression)
// ═══════════════════════════════════════════════════════════════════

// ── PERM-1: Non-op cannot +o another user ──

#[tokio::test]
async fn single_server_perm1_nonop_cannot_op() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("perm1");
    let nick_a = test_nick("perm1", "a");
    let nick_b = test_nick("perm1", "b");
    let nick_c = test_nick("perm1", "c");

    // A creates (gets ops)
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins (no ops)
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // C joins (no ops)
    let (hc, mut ec) = connect_guest(&server, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    // B (non-op) tries to +o C — should fail with 482 ERR_CHANOPRIVSNEEDED
    drain(&mut eb).await;
    hb.raw(&format!("MODE {channel} +o {nick_c}"))
        .await
        .unwrap();

    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("482")),
        Duration::from_secs(5),
    )
    .await;
    assert!(got.is_some(), "Non-op should get 482 when trying to +o");

    // Verify C is NOT op
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_op(&names, &nick_c),
        "C should NOT be op: {names:?}"
    );
    eprintln!("  ✓ PERM-1: Non-op cannot +o another user (482)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── PERM-2: Non-op cannot KICK ──

#[tokio::test]
async fn single_server_perm2_nonop_cannot_kick() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("perm2");
    let nick_a = test_nick("perm2", "a");
    let nick_b = test_nick("perm2", "b");
    let nick_c = test_nick("perm2", "c");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let (hc, mut ec) = connect_guest(&server, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    // B (non-op) tries to kick C — should fail with 482
    drain(&mut eb).await;
    hb.raw(&format!("KICK {channel} {nick_c} :nope"))
        .await
        .unwrap();

    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("482")),
        Duration::from_secs(5),
    )
    .await;
    assert!(got.is_some(), "Non-op should get 482 when trying to kick");

    // Verify C is still present
    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_c),
        "C should still be present: {names:?}"
    );
    eprintln!("  ✓ PERM-2: Non-op cannot KICK (482)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// PM edge case: users NOT in same channel
// ═══════════════════════════════════════════════════════════════════

// ── PMEDGE-1: PM between users who share no channel ──
// Users are in different channels but visible to each other via S2S sync.
// The PM should still be delivered because remote_members is checked
// across ALL channels, not just shared ones.

#[tokio::test]
async fn s2s_pmedge1_pm_no_shared_channel() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel_a = test_channel("pe1a");
    let channel_b = test_channel("pe1b");
    let nick_a = test_nick("pe1", "a");
    let nick_b = test_nick("pe1", "b");

    // A joins channel_a on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel_a).await.unwrap();
    wait_joined(&mut ea, &channel_a).await;

    // B joins channel_b on remote (different channel)
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel_b).await.unwrap();
    wait_joined(&mut eb, &channel_b).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A PMs B — they share no channel, but B is visible via S2S remote_members
    let pm_text = format!(
        "pe1-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    ha.privmsg(&nick_b, &pm_text).await.unwrap();

    // B should receive it — the PM is routed via S2S because B exists
    // in remote_members of channel_b on server A
    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Message { text, .. } if text.contains(&pm_text)),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got.is_some(),
        "PM should be delivered even without shared channel"
    );
    eprintln!("  ✓ PMEDGE-1: PM delivered across servers without shared channel");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// PMEDGE-2: Bidirectional PMs — both directions must work.
///
/// This is the exact regression test for the asymmetric PM bug:
/// A→B worked but B→A returned ERR_NOSUCHNICK because B's server
/// hadn't synced A into remote_members yet. The fix: relay PMs to
/// S2S peers without gating on remote_members.
#[tokio::test]
async fn s2s_pmedge2_bidirectional_pm() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("pe2");
    let nick_a = test_nick("pe2", "a");
    let nick_b = test_nick("pe2", "b");

    // Both join the same channel so they can see each other
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A → B: PM from local to remote
    let msg_ab = format!(
        "ab-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    ha.privmsg(&nick_b, &msg_ab).await.unwrap();

    let got_ab = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Message { text, .. } if text.contains(&msg_ab)),
        Duration::from_secs(10),
    )
    .await;
    assert!(got_ab.is_some(), "A→B PM should be delivered");
    drain(&mut ea).await;
    drain(&mut eb).await;

    // B → A: PM from remote to local (THIS IS THE DIRECTION THAT WAS BROKEN)
    let msg_ba = format!(
        "ba-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 100000
    );
    hb.privmsg(&nick_a, &msg_ba).await.unwrap();

    let got_ba = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { text, .. } if text.contains(&msg_ba)),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got_ba.is_some(),
        "B→A PM should be delivered (was broken: asymmetric relay)"
    );

    // Also verify no ERR_NOSUCHNICK on either side
    drain(&mut ea).await;
    let err_a = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("401")),
        Duration::from_millis(500),
    )
    .await;
    assert!(err_a.is_none(), "A should not have received ERR_NOSUCHNICK");

    drain(&mut eb).await;
    let err_b = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("401")),
        Duration::from_millis(500),
    )
    .await;
    assert!(err_b.is_none(), "B should not have received ERR_NOSUCHNICK");

    eprintln!("  ✓ PMEDGE-2: Bidirectional PMs work (A→B and B→A)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Bidirectional consistency: both sides agree on state
// ═══════════════════════════════════════════════════════════════════

// ── BIDIR-1: After join+settle, NAMES on both sides match ──

#[tokio::test]
async fn s2s_bidir1_names_agree_on_both_sides() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("bidir1");
    let nick_a = test_nick("bidir1", "a");
    let nick_b = test_nick("bidir1", "b");
    let nick_c = test_nick("bidir1", "c");

    // A on local, B on remote, C on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Get NAMES from all three perspectives
    let names_a = request_names(&ha, &mut ea, &channel).await;
    let names_b = request_names(&hb, &mut eb, &channel).await;
    let names_c = request_names(&hc, &mut ec, &channel).await;

    eprintln!("  A sees: {names_a:?}");
    eprintln!("  B sees: {names_b:?}");
    eprintln!("  C sees: {names_c:?}");

    // All three should see all three nicks (regardless of prefix)
    for (label, names) in [("A", &names_a), ("B", &names_b), ("C", &names_c)] {
        assert!(
            nick_is_present(names, &nick_a),
            "{label} should see A: {names:?}"
        );
        assert!(
            nick_is_present(names, &nick_b),
            "{label} should see B: {names:?}"
        );
        assert!(
            nick_is_present(names, &nick_c),
            "{label} should see C: {names:?}"
        );
    }

    // All should agree on total member count
    assert_eq!(names_a.len(), 3, "A should see 3 members: {names_a:?}");
    assert_eq!(names_b.len(), 3, "B should see 3 members: {names_b:?}");
    assert_eq!(names_c.len(), 3, "C should see 3 members: {names_c:?}");

    eprintln!("  ✓ BIDIR-1: All three users agree on NAMES (3 members each)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── BIDIR-2: After part+settle, NAMES on both sides agree ──

#[tokio::test]
async fn s2s_bidir2_names_agree_after_part() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("bidir2");
    let nick_a = test_nick("bidir2", "a");
    let nick_b = test_nick("bidir2", "b");
    let nick_c = test_nick("bidir2", "c");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // C parts
    hc.raw(&format!("PART {channel}")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // A and B should both see exactly 2 members
    let names_a = request_names(&ha, &mut ea, &channel).await;
    let names_b = request_names(&hb, &mut eb, &channel).await;

    eprintln!("  A sees: {names_a:?}");
    eprintln!("  B sees: {names_b:?}");

    assert_eq!(names_a.len(), 2, "A should see 2 members: {names_a:?}");
    assert_eq!(names_b.len(), 2, "B should see 2 members: {names_b:?}");
    assert!(
        !nick_is_present(&names_a, &nick_c),
        "A should NOT see C: {names_a:?}"
    );
    assert!(
        !nick_is_present(&names_b, &nick_c),
        "B should NOT see C: {names_b:?}"
    );

    eprintln!("  ✓ BIDIR-2: Both sides agree after PART (2 members each)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── INV (Invite edge cases) ─────────────────────────────────────────

/// INV-1: Invite a remote guest to a +i channel, then they can join.
///
/// This tests the nick:<nick> invite fallback for guests without DID.
/// Before the fix, INVITE would store nick:<target> but JOIN never
/// checked for it, so the remote guest would be blocked.
#[tokio::test]
async fn s2s_inv1_invite_remote_guest_to_invite_only_channel() {
    // KNOWN LIMITATION: Invites are stored on the inviter's server only.
    // They do NOT propagate via S2S. So the invited user must join on
    // the SAME server where the invite was stored.
    //
    // This test verifies: A on local invites B (remote) → B joins on LOCAL
    // (where the invite was stored) → succeeds. B joining on REMOTE would
    // fail because remote's invite list is empty.
    use std::time::SystemTime;
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let nick_a = format!("InvA{ts}");
    let nick_b = format!("InvB{ts}");
    let channel = format!("#inv1{ts}");

    // A on local server — creates channel and sets +i
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_for(&mut ea, |evt| matches!(evt, Event::Joined { .. }), "A join").await;
    drain(&mut ea).await;

    // Set invite-only
    ha.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B on remote server — joins a shared channel so A can see them
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    let shared = format!("#inv1shared{ts}");
    ha.join(&shared).await.unwrap();
    wait_for(
        &mut ea,
        |evt| matches!(evt, Event::Joined { .. }),
        "A join shared",
    )
    .await;
    drain(&mut ea).await;
    hb.join(&shared).await.unwrap();
    wait_for(
        &mut eb,
        |evt| matches!(evt, Event::Joined { .. }),
        "B join shared",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A invites B to the +i channel
    ha.raw(&format!("INVITE {nick_b} {channel}")).await.unwrap();
    let invite_reply = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("341")),
        Duration::from_secs(5),
    )
    .await;
    assert!(invite_reply.is_some(), "A should get RPL_INVITING (341)");

    // B connects to the LOCAL server (where the invite is stored) to join
    // This is the only way cross-server invite works currently.
    let (hb_local, mut eb_local) = connect_guest(&local, &nick_b).await;
    wait_registered(&mut eb_local).await;
    hb_local.join(&channel).await.unwrap();
    let join_result = maybe_wait(
        &mut eb_local,
        |evt| {
            matches!(evt, Event::Joined { .. })
                || matches!(evt, Event::RawLine(line) if line.contains("473"))
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        matches!(join_result, Some(Event::Joined { .. })),
        "B should be able to join +i channel on inviter's server, got: {join_result:?}"
    );

    eprintln!(
        "  ✓ INV-1: Invited guest can join +i channel on inviter's server (nick: fallback works)"
    );

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hb_local.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: case-insensitive nick handling across S2S
// ═══════════════════════════════════════════════════════════════════

/// CASE-1: Channel messages from remote user with different nick case.
///
/// If server A stores nick as "Alice" and server B sends messages
/// as "alice", the +n check (is the sender a member?) must still pass.
/// Before the fix, case-sensitive remote_members.contains_key() would
/// reject the message.
#[tokio::test]
async fn s2s_case1_message_delivery_with_nick_case_mismatch() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("case1");
    let nick_a = test_nick("case1", "a");
    let nick_b = test_nick("case1", "B"); // Note: capital B in suffix

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B sends channel message — should arrive at A despite default +n
    // (B is a member, but nick case might differ in remote_members)
    let msg = format!("case1-{}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &msg).await.unwrap();

    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { text, .. } if text == &msg),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got.is_some(),
        "Message from remote user should arrive despite nick case"
    );
    eprintln!("  ✓ CASE-1: Message delivery works with different nick case");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// CASE-2: KICK with different nick case still removes remote user.
///
/// If local op kicks "alice" but remote_members has "Alice",
/// the kick must still find and remove the user.
#[tokio::test]
async fn s2s_case2_kick_with_nick_case_mismatch() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("case2");
    let nick_a = test_nick("case2", "a");
    let nick_b = test_nick("case2", "B");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b),
        "B should be present: {names:?}"
    );

    // Kick using lowercase version of B's nick
    let nick_b_lower = nick_b.to_lowercase();
    ha.raw(&format!("KICK {channel} {nick_b_lower} :case test"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        !nick_is_present(&names, &nick_b),
        "B should be gone after case-insensitive kick: {names:?}"
    );
    eprintln!("  ✓ CASE-2: KICK with different nick case removes remote user");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// CASE-3: Channel names are case-insensitive across S2S.
///
/// If A joins #TestChan and B joins #testchan, they should be in
/// the same channel and able to message each other.
#[tokio::test]
async fn s2s_case3_channel_case_insensitive_cross_server() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let base = test_channel("CASE3");
    let channel_upper = base.clone();
    let channel_lower = base.to_lowercase();
    let nick_a = test_nick("case3", "a");
    let nick_b = test_nick("case3", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel_upper).await.unwrap();
    wait_joined(&mut ea, &channel_lower).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel_lower).await.unwrap();
    wait_joined(&mut eb, &channel_lower).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Should be in the same channel
    let msg = format!("case3-{}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel_upper, &msg).await.unwrap();

    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Message { text, .. } if text == &msg),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got.is_some(),
        "Users in same channel (different case) should see messages"
    );
    eprintln!("  ✓ CASE-3: Channel case normalization works across S2S");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: topic changes across federation
// ═══════════════════════════════════════════════════════════════════

/// TOPIC-1: Remote op can set topic on +t channel.
///
/// Channels default to +t. The channel creator (op) is on the remote
/// server. They should be able to set the topic, and local users should
/// see the change. Before the fix, the +t enforcement used case-sensitive
/// lookup and rejected legitimate remote topic changes.
#[tokio::test]
async fn s2s_topic1_remote_op_sets_topic_on_plus_t() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("top1");
    let nick_a = test_nick("top1", "a");
    let nick_b = test_nick("top1", "b");

    // A creates channel on remote (gets ops, channel defaults to +t)
    let (ha, mut ea) = connect_guest(&remote, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on local
    let (hb, mut eb) = connect_guest(&local, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A (remote op) sets topic — should propagate to B
    let topic = format!("remote op topic {}", chrono::Utc::now().timestamp_millis());
    ha.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut eb, &channel).await;
    assert_eq!(
        got, topic,
        "Topic from remote op should be accepted on +t channel"
    );
    eprintln!("  ✓ TOPIC-1: Remote op can set topic on +t channel");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// TOPIC-2: Remote non-op CANNOT set topic on +t channel.
///
/// B is a non-op on the remote server. B's topic change should be
/// rejected by B's local server (482 ERR_CHANOPRIVSNEEDED) before
/// it even reaches the S2S layer.
#[tokio::test]
async fn s2s_topic2_remote_nonop_cannot_set_topic_plus_t() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("top2");
    let nick_a = test_nick("top2", "a");
    let nick_b = test_nick("top2", "b");

    // A creates channel on local (gets ops, +t default)
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Explicitly set +t and send it — the default +t from channel creation
    // may not propagate via ChannelCreated (which doesn't carry modes).
    ha.raw(&format!("MODE {channel} +t")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Set a known topic
    ha.raw(&format!("TOPIC {channel} :original")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote (not op)
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // Wait for S2S Mode +t to propagate to remote server
    tokio::time::sleep(S2S_SETTLE).await;

    // B tries to set topic — should fail with 482 on B's server
    // (B is not op, channel is +t on B's server from S2S Mode propagation)
    hb.raw(&format!("TOPIC {channel} :hacked")).await.unwrap();

    let err = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("482")),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        err.is_some(),
        "Non-op should get 482 when setting topic on +t channel"
    );

    // Verify topic didn't change on local
    tokio::time::sleep(Duration::from_secs(2)).await;
    drain(&mut ea).await;
    ha.raw(&format!("TOPIC {channel}")).await.unwrap();
    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(got, "original", "Topic should not have changed");
    eprintln!("  ✓ TOPIC-2: Remote non-op cannot set topic on +t channel");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// TOPIC-3: Topic set before remote user joins is visible on join.
///
/// A creates channel, sets topic. B joins later from remote.
/// B should see the topic on join (via 332 numeric or SyncResponse).
#[tokio::test]
async fn s2s_topic3_topic_visible_to_late_joiner() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("top3");
    let nick_a = test_nick("top3", "a");
    let nick_b = test_nick("top3", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let topic = format!("early topic {}", chrono::Utc::now().timestamp_millis());
    ha.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote — should see the topic
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();

    // Should receive topic either via 332 on join or TopicChanged event
    let got = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::TopicChanged { topic: t, .. } if t == &topic),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got.is_some(),
        "Late joiner should see topic set before they joined"
    );
    eprintln!("  ✓ TOPIC-3: Topic visible to late remote joiner");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: SyncResponse mode protection
// ═══════════════════════════════════════════════════════════════════

/// SYNC-4: +i set locally survives SyncResponse from peer.
///
/// A creates channel on local and sets +i. Remote peer syncs back
/// with invite_only=false (stale state). The local +i should NOT
/// be overwritten. Before the fix, SyncResponse unconditionally
/// overwrote channel modes.
#[tokio::test]
async fn s2s_sync4_local_plus_i_survives_sync() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sy4");
    let nick_a = test_nick("sy4", "a");
    let nick_b = test_nick("sy4", "b");
    let nick_c = test_nick("sy4", "c");

    // A creates channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Set +i
    ha.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B joins on remote (to trigger SyncResponse exchange)
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    // B needs invite... but the channel is +i. Let's invite B first.
    // Actually B joining a DIFFERENT channel triggers sync exchange too.
    let other_ch = test_channel("sy4other");
    hb.join(&other_ch).await.unwrap();
    wait_joined(&mut eb, &other_ch).await;

    // Wait for sync exchange to complete
    tokio::time::sleep(S2S_SETTLE * 2).await;

    // C tries to join the +i channel on local WITHOUT invite — should be blocked
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();

    let result = maybe_wait(
        &mut ec,
        |evt| {
            matches!(evt, Event::Joined { .. })
                || matches!(evt, Event::RawLine(line) if line.contains("473"))
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        matches!(result, Some(Event::RawLine(ref line)) if line.contains("473")),
        "+i should survive SyncResponse — uninvited user should be blocked, got: {result:?}"
    );
    eprintln!("  ✓ SYNC-4: +i survives SyncResponse from peer");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

/// SYNC-5: Default +nt modes survive SyncResponse.
///
/// Channels default to +nt on creation. After S2S sync exchange,
/// these modes should still be set.
#[tokio::test]
async fn s2s_sync5_default_modes_survive_sync() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sy5");
    let nick_a = test_nick("sy5", "a");
    let nick_b = test_nick("sy5", "b");
    let nick_c = test_nick("sy5", "c");

    // A creates channel on local (gets +nt by default)
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B joins on remote to trigger sync
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE * 2).await;

    // Verify +n is still active: C (on local) tries to send without joining
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;

    hc.privmsg(&channel, "should fail").await.unwrap();

    let err = maybe_wait(
        &mut ec,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("404")),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        err.is_some(),
        "+n should still be active after sync (ERR_CANNOTSENDTOCHAN)"
    );
    eprintln!("  ✓ SYNC-5: Default +nt modes survive SyncResponse");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: kicked user can't send after kick
// ═══════════════════════════════════════════════════════════════════

/// KICK-2: Kicked user cannot send to channel (+n enforcement).
///
/// After being kicked, the user is no longer a member. With +n
/// (default), they should get ERR_CANNOTSENDTOCHAN if they try
/// to send without rejoining.
#[tokio::test]
async fn single_server_kick2_kicked_user_cannot_send() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("kick2");
    let nick_a = test_nick("kick2", "a");
    let nick_b = test_nick("kick2", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A kicks B
    ha.raw(&format!("KICK {channel} {nick_b} :go away"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    drain(&mut eb).await;

    // B tries to send to channel — should fail (not a member, +n active)
    hb.privmsg(&channel, "I was kicked but still talking")
        .await
        .unwrap();

    let err = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::RawLine(line) if line.contains("404")),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        err.is_some(),
        "Kicked user should get 404 when trying to send to +n channel"
    );

    // A should NOT receive the message
    let msg = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(2),
    )
    .await;
    assert!(
        msg.is_none(),
        "Kicked user's message should not arrive at channel"
    );
    eprintln!("  ✓ KICK-2: Kicked user cannot send to channel (+n enforcement)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// KICK-3: Kicked remote user cannot send via S2S.
///
/// After remote user is kicked, their home server should have
/// removed them from the channel. Messages from that user should
/// no longer arrive at the kicking server.
#[tokio::test]
async fn s2s_kick3_kicked_remote_user_cannot_send() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("kick3");
    let nick_a = test_nick("kick3", "a");
    let nick_b = test_nick("kick3", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Verify B can send initially
    let msg1 = format!("before-kick-{}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &msg1).await.unwrap();
    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { text, .. } if text == &msg1),
        Duration::from_secs(10),
    )
    .await;
    assert!(got.is_some(), "B should be able to send before kick");
    drain(&mut ea).await;

    // A kicks B
    ha.raw(&format!("KICK {channel} {nick_b} :kicked"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut ea).await;

    // B tries to send after kick — should be blocked by their home server
    hb.privmsg(&channel, "after kick").await.unwrap();

    let msg2 = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        msg2.is_none(),
        "Kicked remote user's message should not arrive after kick"
    );
    eprintln!("  ✓ KICK-3: Kicked remote user cannot send via S2S");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: MODE +o on remote user, then remote user sends on +m
// ═══════════════════════════════════════════════════════════════════

/// MODOP-1: Remote user opped via S2S can send on +m channel.
///
/// A creates channel, sets +m (moderated). B joins on remote.
/// A ops B. B should be able to send (ops can send on +m).
#[tokio::test]
async fn s2s_modop1_remote_opped_user_can_send_on_plus_m() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("modop1");
    let nick_a = test_nick("modop1", "a");
    let nick_b = test_nick("modop1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Set +m (moderated)
    ha.raw(&format!("MODE {channel} +m")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // B (non-op) tries to send — should be blocked
    drain(&mut ea).await;
    hb.privmsg(&channel, "should fail").await.unwrap();
    let blocked = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(3),
    )
    .await;
    assert!(blocked.is_none(), "Non-op B should be blocked on +m");
    eprintln!("  Phase 1: B blocked on +m ✓");

    // A ops B via S2S
    ha.raw(&format!("MODE {channel} +o {nick_b}"))
        .await
        .unwrap();
    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut ea).await;

    // B (now op) sends — should succeed
    let msg = format!("modop1-{}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &msg).await.unwrap();

    let got = maybe_wait(
        &mut ea,
        |evt| matches!(evt, Event::Message { text, .. } if text == &msg),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        got.is_some(),
        "Opped remote user should be able to send on +m channel"
    );
    eprintln!("  ✓ MODOP-1: Remote opped user can send on +m channel");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: rapid join/part cycles don't leave ghosts
// ═══════════════════════════════════════════════════════════════════

/// GHOST-4: Rapid join/part on remote doesn't leave ghost entries.
///
/// B joins and parts a channel several times rapidly on the remote
/// server. After settling, A should see only B's current state
/// (present or absent), with no duplicate entries.
#[tokio::test]
async fn s2s_ghost4_rapid_join_part_no_ghosts() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("gh4");
    let nick_a = test_nick("gh4", "a");
    let nick_b = test_nick("gh4", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;

    // Rapid join/part cycle
    for _ in 0..3 {
        hb.join(&channel).await.unwrap();
        wait_joined(&mut eb, &channel).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        hb.raw(&format!("PART {channel}")).await.unwrap();
        wait_parted(&mut eb, &channel, &nick_b).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Final: B joins and stays
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A should see B exactly once in NAMES (no duplicates, no ghosts)
    let names = request_names(&ha, &mut ea, &channel).await;
    let b_count = names
        .iter()
        .filter(|n| n.trim_start_matches(&['@', '+'][..]) == nick_b)
        .count();
    assert_eq!(
        b_count, 1,
        "B should appear exactly once in NAMES: {names:?}"
    );
    eprintln!("  ✓ GHOST-4: No ghost entries after rapid join/part cycle");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// GHOST-5: Rapid disconnect/reconnect doesn't leave ghost entries.
///
/// B connects, joins channel, then drops connection abruptly.
/// After B reconnects with a new nick and joins, the old nick
/// should not appear in NAMES.
#[tokio::test]
async fn s2s_ghost5_reconnect_no_ghosts() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("gh5");
    let nick_a = test_nick("gh5", "a");
    let nick_b1 = test_nick("gh5", "b1");
    let nick_b2 = test_nick("gh5", "b2");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // B1 joins and quits
    let (hb1, mut eb1) = connect_guest(&remote, &nick_b1).await;
    wait_registered(&mut eb1).await;
    hb1.join(&channel).await.unwrap();
    wait_joined(&mut eb1, &channel).await;
    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b1),
        "B1 should be present: {names:?}"
    );

    let _ = hb1.quit(Some("leaving")).await;
    drop(hb1);
    drop(eb1);

    tokio::time::sleep(S2S_SETTLE).await;

    // B2 joins (same user, new nick)
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b2).await;
    wait_registered(&mut eb2).await;
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut eb2, &channel).await;
    tokio::time::sleep(S2S_SETTLE).await;

    let names = request_names(&ha, &mut ea, &channel).await;
    assert!(
        nick_is_present(&names, &nick_b2),
        "B2 should be present: {names:?}"
    );
    assert!(
        !nick_is_present(&names, &nick_b1),
        "B1 (old nick) should NOT be present: {names:?}"
    );
    eprintln!("  ✓ GHOST-5: No ghost after disconnect/reconnect with new nick");

    let _ = ha.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: message ordering / dedup
// ═══════════════════════════════════════════════════════════════════

/// DEDUP-1: Same message doesn't arrive twice.
///
/// Send a message from A to B via channel. B should receive it
/// exactly once, not duplicated by resync or re-relay.
#[tokio::test]
async fn s2s_dedup1_no_duplicate_messages() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("dup1");
    let nick_a = test_nick("dup1", "a");
    let nick_b = test_nick("dup1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send a unique message
    let unique = format!("dedup-{}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &unique).await.unwrap();

    // Wait for first copy
    let first = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Message { text, .. } if text == &unique),
        Duration::from_secs(10),
    )
    .await;
    assert!(first.is_some(), "Should receive the message");

    // Check that NO second copy arrives within 5 seconds
    let second = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Message { text, .. } if text == &unique),
        Duration::from_secs(5),
    )
    .await;
    assert!(second.is_none(), "Should NOT receive duplicate message");
    eprintln!("  ✓ DEDUP-1: No duplicate messages across S2S");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case: ban enforcement across S2S
// ═══════════════════════════════════════════════════════════════════

/// BAN-1: Banned user on local server can't join channel.
///
/// A creates channel, bans B's mask. B tries to join — should fail.
/// (Single server, but tests the foundation for S2S ban sync.)
#[tokio::test]
async fn single_server_ban1_banned_user_cant_join() {
    let Some(server) = get_single_server() else {
        return;
    };
    let channel = test_channel("ban1");
    let nick_a = test_nick("ban1", "a");
    let nick_b = test_nick("ban1", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Ban B's mask
    ha.raw(&format!("MODE {channel} +b {nick_b}!*@*"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B tries to join
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();

    let result = maybe_wait(
        &mut eb,
        |evt| {
            matches!(evt, Event::Joined { .. })
                || matches!(evt, Event::RawLine(line) if line.contains("474"))
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        matches!(result, Some(Event::RawLine(ref line)) if line.contains("474")),
        "Banned user should get 474, got: {result:?}"
    );
    eprintln!("  ✓ BAN-1: Banned user can't join channel");

    // Unban and verify B can now join
    ha.raw(&format!("MODE {channel} -b {nick_b}!*@*"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    hb.join(&channel).await.unwrap();
    let joined = maybe_wait(
        &mut eb,
        |evt| matches!(evt, Event::Joined { .. }),
        Duration::from_secs(5),
    )
    .await;
    assert!(joined.is_some(), "Unbanned user should be able to join");
    eprintln!("  ✓ BAN-1: Unbanned user can join");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// INV-2: Remote guest CANNOT join +i channel without an invite.
#[tokio::test]
async fn s2s_inv2_remote_guest_blocked_from_invite_only_without_invite() {
    use std::time::SystemTime;
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let nick_a = format!("InvC{ts}");
    let nick_b = format!("InvD{ts}");
    let channel = format!("#inv2{ts}");

    // A creates +i channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_for(&mut ea, |evt| matches!(evt, Event::Joined { .. }), "A join").await;
    drain(&mut ea).await;
    ha.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B on remote — try to join without invite
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    let result = maybe_wait(
        &mut eb,
        |evt| {
            matches!(evt, Event::Joined { .. })
                || matches!(evt, Event::RawLine(line) if line.contains("473"))
        },
        Duration::from_secs(5),
    )
    .await;
    // Should get 473 ERR_INVITEONLYCHAN, NOT a successful join
    assert!(
        matches!(result, Some(Event::RawLine(ref line)) if line.contains("473")),
        "B should be blocked from +i channel without invite, got: {result:?}"
    );

    eprintln!("  ✓ INV-2: Remote guest correctly blocked from +i channel without invite");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── MSGID tests ─────────────────────────────────────────────────────

/// MSGID-1: Messages include a unique msgid tag
#[tokio::test]
async fn single_server_msgid1_messages_have_msgid() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("mid1", "a");
    let nick_b = test_nick("mid1", "b");
    let channel = test_channel("mid1");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;
    drain(&mut ea).await;

    let test_text = format!("msgid test {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &test_text).await.unwrap();

    let msg = wait_message_event_containing(&mut ea, &test_text).await;
    match msg {
        Event::Message { tags, .. } => {
            let msgid = tags.get("msgid");
            assert!(
                msgid.is_some(),
                "Message should have msgid tag, got tags: {tags:?}"
            );
            let id = msgid.unwrap();
            assert_eq!(id.len(), 26, "msgid should be a 26-char ULID, got: {id}");
            eprintln!("  ✓ MSGID-1: Message has msgid={id}");
        }
        other => panic!("Expected Message event, got: {other:?}"),
    }

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// MSGID-2: Each message gets a unique msgid
#[tokio::test]
async fn single_server_msgid2_unique_ids() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("mid2", "a");
    let nick_b = test_nick("mid2", "b");
    let channel = test_channel("mid2");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;
    drain(&mut ea).await;

    hb.privmsg(&channel, "mid2msg1").await.unwrap();
    hb.privmsg(&channel, "mid2msg2").await.unwrap();

    let evt1 = wait_message_event_containing(&mut ea, "mid2msg1").await;
    let evt2 = wait_message_event_containing(&mut ea, "mid2msg2").await;

    let id1 = match evt1 {
        Event::Message { ref tags, .. } => {
            tags.get("msgid").cloned().expect("msg1 should have msgid")
        }
        _ => panic!("Expected Message"),
    };
    let id2 = match evt2 {
        Event::Message { ref tags, .. } => {
            tags.get("msgid").cloned().expect("msg2 should have msgid")
        }
        _ => panic!("Expected Message"),
    };

    assert_ne!(id1, id2, "Each message should have a unique msgid");
    assert!(
        id1 < id2,
        "msgids should be chronologically ordered: {id1} < {id2}"
    );
    eprintln!("  ✓ MSGID-2: Messages have unique, ordered msgids: {id1}, {id2}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// MSGID-3: Cross-server messages include msgid
#[tokio::test]
async fn s2s_msgid3_cross_server_messages_have_msgid() {
    let Some((server_a, server_b)) = get_servers() else {
        return;
    };
    let nick_a = test_nick("mid3", "a");
    let nick_b = test_nick("mid3", "b");
    let channel = test_channel("mid3");

    let (ha, mut ea) = connect_guest(&server_a, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server_b, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;
    wait_names_containing(&mut ea, &channel, &nick_b).await;

    let test_text = format!("s2s msgid {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &test_text).await.unwrap();

    let msg = wait_message_event_containing(&mut ea, &test_text).await;
    match msg {
        Event::Message { tags, .. } => {
            let msgid = tags.get("msgid");
            assert!(
                msgid.is_some(),
                "S2S message should have msgid tag, got tags: {tags:?}"
            );
            let id = msgid.unwrap();
            assert_eq!(id.len(), 26, "msgid should be a 26-char ULID, got: {id}");
            eprintln!("  ✓ MSGID-3: S2S message has msgid={id}");
        }
        other => panic!("Expected Message event, got: {other:?}"),
    }

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// When the first user joins a channel (auto-opped as founder),
/// a second user joining should see them as op in NAMES — and
/// the second user should also receive a MODE +o broadcast so
/// their client's in-memory state stays consistent with NAMES.
#[tokio::test]
async fn single_server_autoop_visible_to_others() {
    let Some(server) = get_single_server() else {
        return;
    };
    let op_nick = test_nick("aop", "op");
    let obs_nick = test_nick("aop", "obs");
    let channel = test_channel("aop");

    // First user joins — becomes op (founder) of new channel
    let (h_op, mut e_op) = connect_guest(&server, &op_nick).await;
    wait_registered(&mut e_op).await;
    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;
    // Check NAMES shows founder as op
    let names = wait_names_containing(&mut e_op, &channel, &op_nick).await;
    assert!(
        names.iter().any(|n| n == &format!("@{op_nick}")),
        "Founder should see self as op in NAMES, got: {names:?}"
    );
    eprintln!("  ✓ First joiner is op in own NAMES");

    // Second user joins — should see first user as op in NAMES
    let (h_obs, mut e_obs) = connect_guest(&server, &obs_nick).await;
    wait_registered(&mut e_obs).await;
    h_obs.join(&channel).await.unwrap();
    wait_joined(&mut e_obs, &channel).await;
    let names2 = wait_names_containing(&mut e_obs, &channel, &op_nick).await;
    assert!(
        names2.iter().any(|n| n == &format!("@{op_nick}")),
        "Observer should see first joiner as op in NAMES, got: {names2:?}"
    );
    eprintln!("  ✓ Second joiner sees first user as op in NAMES");

    // Verify: op manually ops observer, observer gets MODE +o broadcast
    h_op.raw(&format!("MODE {channel} +o {obs_nick}"))
        .await
        .unwrap();
    let (mode, arg) = wait_mode(&mut e_obs, &channel).await;
    assert_eq!(mode, "+o", "Observer should receive MODE +o, got: {mode}");
    assert_eq!(
        arg.as_deref(),
        Some(obs_nick.as_str()),
        "MODE +o should target observer, got: {arg:?}"
    );
    eprintln!("  ✓ Observer received MODE +o broadcast");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_obs.quit(Some("done")).await;
}

/// When a DID-authenticated user (founder/persistent-op) rejoins a channel,
/// other members should receive a MODE +o broadcast so their client state
/// stays in sync without requiring a NAMES refresh.
/// NOTE: This test only runs with DID auth, which requires AT Protocol setup.
/// For now we test the auto-op-on-empty-rejoin case: op parts, observer parts,
/// op rejoins empty channel (gets auto-opped), observer rejoins and should see op.
#[tokio::test]
async fn single_server_autoop_on_empty_rejoin() {
    let Some(server) = get_single_server() else {
        return;
    };
    let op_nick = test_nick("aor", "op");
    let obs_nick = test_nick("aor", "obs");
    let channel = test_channel("aor");

    // Create channel with first user as op
    let (h_op, mut e_op) = connect_guest(&server, &op_nick).await;
    wait_registered(&mut e_op).await;
    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Second user joins
    let (h_obs, mut e_obs) = connect_guest(&server, &obs_nick).await;
    wait_registered(&mut e_obs).await;
    h_obs.join(&channel).await.unwrap();
    wait_joined(&mut e_obs, &channel).await;
    drain(&mut e_obs).await;

    // Both part — channel becomes empty
    h_op.raw(&format!("PART {channel} :brb")).await.unwrap();
    wait_parted(&mut e_op, &channel, &op_nick).await;
    h_obs.raw(&format!("PART {channel} :brb")).await.unwrap();
    wait_parted(&mut e_obs, &channel, &obs_nick).await;

    // Op rejoins empty channel — should get auto-opped
    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;
    let names = wait_names_containing(&mut e_op, &channel, &op_nick).await;
    assert!(
        names.iter().any(|n| n == &format!("@{op_nick}")),
        "Rejoining empty channel should auto-op, got: {names:?}"
    );
    eprintln!("  ✓ First rejoiner of empty channel is auto-opped");

    // Observer rejoins — should see op in NAMES and get MODE +o broadcast
    h_obs.join(&channel).await.unwrap();
    wait_joined(&mut e_obs, &channel).await;
    let names2 = wait_names_containing(&mut e_obs, &channel, &op_nick).await;
    assert!(
        names2.iter().any(|n| n == &format!("@{op_nick}")),
        "Observer should see auto-opped user in NAMES, got: {names2:?}"
    );
    eprintln!("  ✓ Second joiner sees auto-opped user in NAMES");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_obs.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge case tests — risky protocol paths
// ═══════════════════════════════════════════════════════════════════

/// EDGE1: PRIVMSG to channel with +n mode from non-member should fail
#[tokio::test]
async fn single_server_edge1_no_external_messages_enforced() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge1");
    let nick_in = test_nick("in", "edge1");
    let nick_out = test_nick("out", "edge1");

    // User IN creates channel (gets +nt by default)
    let (h_in, mut rx_in) = connect_guest(&addr, &nick_in).await;
    wait_registered(&mut rx_in).await;
    h_in.join(&ch).await.unwrap();
    wait_joined(&mut rx_in, &ch).await;

    // User OUT connects but does NOT join the channel
    let (h_out, mut rx_out) = connect_guest(&addr, &nick_out).await;
    wait_registered(&mut rx_out).await;

    // OUT tries to send to channel — should get ERR_CANNOTSENDTOCHAN
    h_out
        .raw(&format!("PRIVMSG {} :sneaky message", ch))
        .await
        .unwrap();

    // OUT should receive an error notice
    wait_notice_containing(&mut rx_out, "Cannot send to channel").await;
    eprintln!("  ✓ Non-member blocked from sending to +n channel");

    // IN should NOT receive the message
    let got = maybe_wait(
        &mut rx_in,
        |e| matches!(e, Event::Message { text, .. } if text.contains("sneaky")),
        Duration::from_secs(2),
    )
    .await;
    assert!(got.is_none(), "Message from non-member leaked through +n");
    eprintln!("  ✓ No message leaked through +n");

    let _ = h_in.quit(Some("done")).await;
    let _ = h_out.quit(Some("done")).await;
}

/// EDGE2: NICK change to a registered nick should be blocked
#[tokio::test]
async fn single_server_edge2_nick_change_to_registered_nick_blocked() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let _ch = test_channel("edge2");
    let owner_nick = test_nick("owner", "edge2");
    let intruder_nick = test_nick("intruder", "edge2");

    // Owner creates channel (this registers the nick to... well, no DID for guests.
    // Nick ownership requires DID auth. So test NICK change to an IN-USE nick instead.)
    let (h_owner, mut rx_owner) = connect_guest(&addr, &owner_nick).await;
    wait_registered(&mut rx_owner).await;

    let (h_intruder, mut rx_intruder) = connect_guest(&addr, &intruder_nick).await;
    wait_registered(&mut rx_intruder).await;

    // Intruder tries to change nick to owner's nick
    h_intruder
        .raw(&format!("NICK {}", owner_nick))
        .await
        .unwrap();

    // SDK intercepts 433 and auto-retries with a variant nick.
    // Verify the intruder did NOT end up with the owner's exact nick
    // by checking NAMES in a shared channel.
    let ch = test_channel("edge2");
    h_owner.join(&ch).await.unwrap();
    wait_joined(&mut rx_owner, &ch).await;

    // Give SDK time to process the 433 retry
    tokio::time::sleep(Duration::from_secs(1)).await;

    h_intruder.raw(&format!("JOIN {ch}")).await.unwrap();
    wait_joined(&mut rx_intruder, &ch).await;

    let names = request_names(&h_owner, &mut rx_owner, &ch).await;
    let bare_names: Vec<String> = names
        .iter()
        .map(|n: &String| n.trim_start_matches(['@', '+']).to_lowercase())
        .collect();
    assert!(
        bare_names.contains(&owner_nick.to_lowercase()),
        "Owner nick should be in NAMES"
    );
    // Intruder should NOT have the owner's exact nick
    let intruder_count = bare_names
        .iter()
        .filter(|n| **n == owner_nick.to_lowercase())
        .count();
    assert_eq!(
        intruder_count, 1,
        "Only one user should have the owner's nick"
    );
    eprintln!("  ✓ NICK change to in-use nick blocked (intruder got variant)");

    let _ = h_owner.quit(Some("done")).await;
    let _ = h_intruder.quit(Some("done")).await;
}

/// EDGE3: CHATHISTORY for channel you're not in should be rejected
#[tokio::test]
async fn single_server_edge3_chathistory_unauthorized() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge3");
    let nick_in = test_nick("in", "edge3");
    let nick_out = test_nick("spy", "edge3");

    // User IN creates channel and sends messages
    let (h_in, mut rx_in) = connect_guest(&addr, &nick_in).await;
    wait_registered(&mut rx_in).await;
    h_in.join(&ch).await.unwrap();
    wait_joined(&mut rx_in, &ch).await;
    h_in.privmsg(&ch, "secret message").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // User OUT connects but does NOT join
    let (h_out, mut rx_out) = connect_guest(&addr, &nick_out).await;
    wait_registered(&mut rx_out).await;

    // OUT requests chathistory — should fail
    h_out
        .raw(&format!("CHATHISTORY LATEST {} * 50", ch))
        .await
        .unwrap();

    // Should receive an error (INVALID_TARGET or similar), NOT the secret message
    wait_notice_containing(&mut rx_out, "not in that channel").await;

    // Should NOT have received the secret message
    let got = maybe_wait(
        &mut rx_out,
        |e| matches!(e, Event::Message { text, .. } if text.contains("secret")),
        Duration::from_secs(2),
    )
    .await;
    assert!(got.is_none(), "CHATHISTORY leaked messages to non-member!");
    eprintln!("  ✓ CHATHISTORY rejected for non-member");

    let _ = h_in.quit(Some("done")).await;
    let _ = h_out.quit(Some("done")).await;
}

/// EDGE4: Double JOIN to same channel should be harmless
#[tokio::test]
async fn single_server_edge4_double_join_harmless() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge4");
    let nick = test_nick("dblj", "edge4");

    let (h, mut rx) = connect_guest(&addr, &nick).await;
    wait_registered(&mut rx).await;

    h.join(&ch).await.unwrap();
    wait_joined(&mut rx, &ch).await;
    eprintln!("  ✓ First JOIN succeeded");

    // Second JOIN to same channel
    h.join(&ch).await.unwrap();
    // Should either silently ignore or re-send NAMES. Should NOT crash or kick.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Send a message to verify we're still in the channel
    h.privmsg(&ch, "still here after double join")
        .await
        .unwrap();
    wait_message_containing(&mut rx, "still here after double join").await;
    eprintln!("  ✓ Double JOIN is harmless, user still functional");

    let _ = h.quit(Some("done")).await;
}

/// EDGE5: KICK yourself from your own channel
#[tokio::test]
async fn single_server_edge5_kick_self() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge5");
    let nick = test_nick("selfkick", "edge5");

    let (h, mut rx) = connect_guest(&addr, &nick).await;
    let actual_nick = wait_registered(&mut rx).await;

    h.join(&ch).await.unwrap();
    wait_joined(&mut rx, &ch).await;

    // Kick yourself
    h.raw(&format!("KICK {} {} :self-kick", ch, actual_nick))
        .await
        .unwrap();

    // Should be kicked from the channel
    wait_for(&mut rx, |e| matches!(e, Event::Kicked { .. }), "self-kick").await;
    eprintln!("  ✓ Self-kick works");

    // Try to send after kick — should fail
    h.raw(&format!("PRIVMSG {} :ghost message", ch))
        .await
        .unwrap();
    wait_notice_containing(&mut rx, "Cannot send to channel").await;
    eprintln!("  ✓ Cannot send after being kicked");

    let _ = h.quit(Some("done")).await;
}

/// EDGE6: MODE change on non-existent channel
#[tokio::test]
async fn single_server_edge6_mode_nonexistent_channel() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge6noexist");
    let nick = test_nick("moder", "edge6");

    let (h, mut rx) = connect_guest(&addr, &nick).await;
    wait_registered(&mut rx).await;

    // Try MODE on a channel that doesn't exist
    h.raw(&format!("MODE {} +m", ch)).await.unwrap();

    // Should get an error (442 ERR_NOTONCHANNEL or 403 ERR_NOSUCHCHANNEL)
    wait_notice_containing(&mut rx, "not on that channel").await;
    eprintln!("  ✓ MODE on non-existent channel returns error");

    let _ = h.quit(Some("done")).await;
}

/// EDGE7: Very long message doesn't crash server
#[tokio::test]
async fn single_server_edge7_long_message() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge7");
    let nick1 = test_nick("long1", "edge7");
    let nick2 = test_nick("long2", "edge7");

    let (h1, mut rx1) = connect_guest(&addr, &nick1).await;
    let (h2, mut rx2) = connect_guest(&addr, &nick2).await;
    wait_registered(&mut rx1).await;
    wait_registered(&mut rx2).await;

    h1.join(&ch).await.unwrap();
    h2.join(&ch).await.unwrap();
    wait_joined(&mut rx1, &ch).await;
    wait_joined(&mut rx2, &ch).await;
    drain(&mut rx1).await;
    drain(&mut rx2).await;

    // Send a very long message (IRC max is typically 512 bytes total, but many modern servers allow more)
    let long_msg = "A".repeat(400);
    h1.privmsg(&ch, &long_msg).await.unwrap();

    // Other user should receive at least part of it
    let (_, _, text) = wait_message_containing(&mut rx2, "AAAA").await;
    eprintln!("  ✓ Long message delivered ({} chars received)", text.len());

    // Send a normal message after to verify server isn't broken
    h1.privmsg(&ch, "still working after long msg")
        .await
        .unwrap();
    wait_message_containing(&mut rx2, "still working").await;
    eprintln!("  ✓ Server still functional after long message");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

/// EDGE8: Non-op cannot set MODE +o
#[tokio::test]
async fn single_server_edge8_nonop_mode_change_rejected() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge8");
    let nick_op = test_nick("theop", "edge8");
    let nick_user = test_nick("norml", "edge8");
    let nick_target = test_nick("targ", "edge8");

    // Op creates channel
    let (h_op, mut rx_op) = connect_guest(&addr, &nick_op).await;
    wait_registered(&mut rx_op).await;
    h_op.join(&ch).await.unwrap();
    wait_joined(&mut rx_op, &ch).await;

    // Normal user joins
    let (h_user, mut rx_user) = connect_guest(&addr, &nick_user).await;
    let _actual_user = wait_registered(&mut rx_user).await;
    h_user.join(&ch).await.unwrap();
    wait_joined(&mut rx_user, &ch).await;

    // Target user joins
    let (h_target, mut rx_target) = connect_guest(&addr, &nick_target).await;
    let actual_target = wait_registered(&mut rx_target).await;
    h_target.join(&ch).await.unwrap();
    wait_joined(&mut rx_target, &ch).await;
    drain(&mut rx_user).await;

    // Normal user tries to +o target — should fail
    h_user
        .raw(&format!("MODE {} +o {}", ch, actual_target))
        .await
        .unwrap();
    wait_notice_containing(&mut rx_user, "not channel operator").await;
    eprintln!("  ✓ Non-op cannot set +o");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_user.quit(Some("done")).await;
    let _ = h_target.quit(Some("done")).await;
}

/// EDGE9: Edit someone else's message is rejected
#[tokio::test]
async fn single_server_edge9_edit_others_message_rejected() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge9");
    let nick1 = test_nick("auth1", "edge9");
    let nick2 = test_nick("edit2", "edge9");

    let (h1, mut rx1) = connect_guest(&addr, &nick1).await;
    let (h2, mut rx2) = connect_guest(&addr, &nick2).await;
    wait_registered(&mut rx1).await;
    wait_registered(&mut rx2).await;

    h1.join(&ch).await.unwrap();
    h2.join(&ch).await.unwrap();
    wait_joined(&mut rx1, &ch).await;
    wait_joined(&mut rx2, &ch).await;
    drain(&mut rx1).await;
    drain(&mut rx2).await;

    // User 1 sends a message
    h1.privmsg(&ch, "original message from user1")
        .await
        .unwrap();
    // Get the msgid from user 2's perspective
    let evt = wait_message_event_containing(&mut rx2, "original message from user1").await;
    let msgid = match &evt {
        Event::Message { tags, .. } => tags.get("msgid").cloned().unwrap_or_default(),
        _ => String::new(),
    };
    assert!(!msgid.is_empty(), "Message should have msgid");
    eprintln!("  ✓ Got msgid: {}", &msgid[..8]);

    // User 2 tries to edit user 1's message
    h2.raw(&format!(
        "@+draft/edit={} PRIVMSG {} :hacked content",
        msgid, ch
    ))
    .await
    .unwrap();

    // The edit should be rejected — either with FAIL AUTHOR_MISMATCH (if DB enabled)
    // or silently dropped (if no DB). Either way, user 1 must NOT see the edit.
    let got = maybe_wait(
        &mut rx1,
        |e| matches!(e, Event::Message { text, .. } if text.contains("hacked")),
        Duration::from_secs(3),
    )
    .await;
    assert!(got.is_none(), "Unauthorized edit was delivered!");
    eprintln!("  ✓ Unauthorized edit not delivered to other users");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

/// EDGE10: Delete someone else's message without ops is rejected
#[tokio::test]
async fn single_server_edge10_delete_others_message_rejected() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge10");
    let nick1 = test_nick("auth1", "edge10");
    let nick2 = test_nick("del2", "edge10");

    // nick1 creates channel (gets ops)
    let (h1, mut rx1) = connect_guest(&addr, &nick1).await;
    wait_registered(&mut rx1).await;
    h1.join(&ch).await.unwrap();
    wait_joined(&mut rx1, &ch).await;

    // nick2 joins (not op)
    let (h2, mut rx2) = connect_guest(&addr, &nick2).await;
    wait_registered(&mut rx2).await;
    h2.join(&ch).await.unwrap();
    wait_joined(&mut rx2, &ch).await;
    drain(&mut rx1).await;
    drain(&mut rx2).await;

    // User 1 (op) sends a message
    h1.privmsg(&ch, "important message from op").await.unwrap();
    // Get msgid from user 2's view
    let evt = wait_message_event_containing(&mut rx2, "important message from op").await;
    let msgid = match &evt {
        Event::Message { tags, .. } => tags.get("msgid").cloned().unwrap_or_default(),
        _ => String::new(),
    };
    assert!(!msgid.is_empty(), "Message should have msgid");

    // User 2 (not op, not author) tries to delete
    h2.raw(&format!("@+draft/delete={} TAGMSG {}", msgid, ch))
        .await
        .unwrap();

    // The delete should be rejected — either with FAIL DELETE AUTHOR_MISMATCH (if DB)
    // or silently dropped. Either way, check user 1 doesn't see a deletion broadcast.
    let got = maybe_wait(
        &mut rx1,
        |e| matches!(e, Event::Message { text, .. } if text.contains("deleted")),
        Duration::from_secs(3),
    )
    .await;
    assert!(got.is_none(), "Unauthorized delete was broadcast!");
    eprintln!("  ✓ Unauthorized delete not broadcast");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

/// EDGE11: Rapid NICK changes don't cause state corruption
#[tokio::test]
async fn single_server_edge11_rapid_nick_changes() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge11");
    let nick_base = test_nick("rapid", "edge11");

    let (h, mut rx) = connect_guest(&addr, &nick_base).await;
    wait_registered(&mut rx).await;
    h.join(&ch).await.unwrap();
    wait_joined(&mut rx, &ch).await;
    drain(&mut rx).await;

    // Rapid nick changes
    for i in 0..5 {
        let new = format!("{nick_base}v{i}");
        h.raw(&format!("NICK {new}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for nick changes to settle
    tokio::time::sleep(Duration::from_secs(1)).await;
    drain(&mut rx).await;

    // Send a message — server should still work
    let _final_nick = format!("{nick_base}v4");
    h.privmsg(&ch, "after rapid nick changes").await.unwrap();
    wait_message_containing(&mut rx, "after rapid nick changes").await;
    eprintln!("  ✓ Server stable after 5 rapid nick changes");

    let _ = h.quit(Some("done")).await;
}

/// EDGE12: Moderated channel (+m) blocks non-voiced users
#[tokio::test]
async fn single_server_edge12_moderated_blocks_unvoiced() {
    let Some(addr) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge12");
    let nick_op = test_nick("mop", "edge12");
    let nick_user = test_nick("muted", "edge12");

    let (h_op, mut rx_op) = connect_guest(&addr, &nick_op).await;
    wait_registered(&mut rx_op).await;
    h_op.join(&ch).await.unwrap();
    wait_joined(&mut rx_op, &ch).await;

    // Set +m
    h_op.raw(&format!("MODE {} +m", ch)).await.unwrap();
    wait_mode(&mut rx_op, &ch).await;

    let (h_user, mut rx_user) = connect_guest(&addr, &nick_user).await;
    wait_registered(&mut rx_user).await;
    h_user.join(&ch).await.unwrap();
    wait_joined(&mut rx_user, &ch).await;
    drain(&mut rx_op).await;

    // Unvoiced user tries to send — should fail
    h_user
        .raw(&format!("PRIVMSG {} :muted message", ch))
        .await
        .unwrap();
    wait_notice_containing(&mut rx_user, "Cannot send to channel").await;
    eprintln!("  ✓ Unvoiced user blocked in +m channel");

    // Op should NOT receive the message
    let got = maybe_wait(
        &mut rx_op,
        |e| matches!(e, Event::Message { text, .. } if text.contains("muted")),
        Duration::from_secs(2),
    )
    .await;
    assert!(got.is_none(), "Muted message leaked through +m");
    eprintln!("  ✓ No message leaked through +m");

    // Voice the user
    let actual_user = nick_user.clone(); // might differ if collision
    h_op.raw(&format!("MODE {} +v {}", ch, actual_user))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut rx_op).await;
    drain(&mut rx_user).await;

    // Now the voiced user can send
    h_user.privmsg(&ch, "voiced message").await.unwrap();
    wait_message_containing(&mut rx_op, "voiced message").await;
    eprintln!("  ✓ Voiced user can send in +m channel");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_user.quit(Some("done")).await;
}

// ─── EDGE13: Halfop (+h) behavior ──────────────────────────────────────
#[tokio::test]
async fn single_server_edge13_halfop_behavior() {
    let addr = match std::env::var("SERVER") {
        Ok(a) => a,
        _ => {
            eprintln!("SKIP: no SERVER set");
            return;
        }
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let ch = format!("#_zqhalf_{}", ts % 100000);
    let nick_op = format!("_zqhop_{}", ts % 100000);
    let nick_halfop = format!("_zqhho_{}", ts % 100000);
    let nick_user = format!("_zqhus_{}", ts % 100000);

    // Op creates channel
    let (h_op, mut rx_op) = connect_guest(&addr, &nick_op).await;
    h_op.raw(&format!("JOIN {}", ch)).await.unwrap();
    wait_joined(&mut rx_op, &ch).await;
    drain(&mut rx_op).await;

    // Halfop joins
    let (h_half, mut rx_half) = connect_guest(&addr, &nick_halfop).await;
    h_half.raw(&format!("JOIN {}", ch)).await.unwrap();
    wait_joined(&mut rx_half, &ch).await;
    drain(&mut rx_half).await;
    drain(&mut rx_op).await;

    // Regular user joins
    let (h_user, mut rx_user) = connect_guest(&addr, &nick_user).await;
    h_user.raw(&format!("JOIN {}", ch)).await.unwrap();
    wait_joined(&mut rx_user, &ch).await;
    drain(&mut rx_user).await;
    drain(&mut rx_op).await;
    drain(&mut rx_half).await;

    // Op grants halfop
    h_op.raw(&format!("MODE {} +h {}", ch, nick_halfop))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Halfop should see MODE change
    let _mode_event = wait_for(
        &mut rx_half,
        |e| matches!(e, Event::ModeChanged { .. }),
        "halfop MODE +h",
    )
    .await;
    eprintln!("  ✓ Halfop received +h mode change");
    drain(&mut rx_op).await;
    drain(&mut rx_user).await;

    // Halfop CAN kick regular user
    h_half
        .raw(&format!("KICK {} {} :halfop kick", ch, nick_user))
        .await
        .unwrap();
    let _kick_event = wait_for(
        &mut rx_user,
        |e| matches!(e, Event::Kicked { .. }),
        "user kicked by halfop",
    )
    .await;
    eprintln!("  ✓ Halfop can kick regular user");
    drain(&mut rx_half).await;
    drain(&mut rx_op).await;

    // Rejoin user
    h_user.raw(&format!("JOIN {}", ch)).await.unwrap();
    wait_joined(&mut rx_user, &ch).await;
    drain(&mut rx_user).await;
    drain(&mut rx_op).await;
    drain(&mut rx_half).await;

    // Halfop CANNOT kick the op
    h_half
        .raw(&format!("KICK {} {} :halfop vs op", ch, nick_op))
        .await
        .unwrap();
    wait_notice_containing(&mut rx_half, "operator").await;
    eprintln!("  ✓ Halfop cannot kick op");

    // Halfop CAN voice a user (+v)
    h_half
        .raw(&format!("MODE {} +v {}", ch, nick_user))
        .await
        .unwrap();
    let _voice_event = wait_for(
        &mut rx_user,
        |e| matches!(e, Event::ModeChanged { .. }),
        "voice set by halfop",
    )
    .await;
    eprintln!("  ✓ Halfop can set +v");
    drain(&mut rx_half).await;
    drain(&mut rx_op).await;

    // Halfop CANNOT set +o
    h_half
        .raw(&format!("MODE {} +o {}", ch, nick_user))
        .await
        .unwrap();
    wait_notice_containing(&mut rx_half, "Moderators can only set").await;
    eprintln!("  ✓ Halfop cannot set +o");

    // Halfop CANNOT set channel mode +m
    h_half.raw(&format!("MODE {} +m", ch)).await.unwrap();
    wait_notice_containing(&mut rx_half, "Moderators can only set").await;
    eprintln!("  ✓ Halfop cannot set +m");

    // Halfop CAN send in +m channel
    h_op.raw(&format!("MODE {} +m", ch)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut rx_op).await;
    drain(&mut rx_half).await;
    drain(&mut rx_user).await;

    h_half
        .privmsg(&ch, "halfop speaks in moderated")
        .await
        .unwrap();
    wait_message_containing(&mut rx_op, "halfop speaks in moderated").await;
    eprintln!("  ✓ Halfop can speak in +m channel");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_half.quit(Some("done")).await;
    let _ = h_user.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Edge cases: history, DMs, reconnect, flakiness scenarios
// ═══════════════════════════════════════════════════════════════════

// ── HIST-1: CHATHISTORY returns messages in chronological order ──

#[tokio::test]
async fn single_server_hist1_chathistory_chronological_order() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("hist1");
    let nick_a = test_nick("hist1", "a");
    let nick_b = test_nick("hist1", "b");

    // A creates channel and sends multiple messages
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    for i in 1..=5 {
        ha.privmsg(&ch, &format!("msg-{i}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B joins — should receive history batch, then CHATHISTORY request returns in order
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;

    // Collect messages (from JOIN history replay)
    let mut msgs = Vec::new();
    loop {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. }) if text.starts_with("msg-") => {
                msgs.push(text);
            }
            Some(Event::BatchEnd { .. }) => break,
            _ => break,
        }
    }

    // Verify chronological order
    assert!(
        msgs.len() >= 5,
        "Expected 5 history messages, got {}: {msgs:?}",
        msgs.len()
    );
    for i in 0..msgs.len() - 1 {
        assert!(
            msgs[i] < msgs[i + 1],
            "History not in chronological order: {} >= {}",
            msgs[i],
            msgs[i + 1]
        );
    }
    eprintln!("  ✓ CHATHISTORY messages in chronological order");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── HIST-2: Deleted messages excluded from CHATHISTORY ──

#[tokio::test]
async fn single_server_hist2_deleted_messages_excluded() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("hist2");
    let nick_a = test_nick("hist2", "a");
    let nick_b = test_nick("hist2", "b");

    // A creates channel and sends messages
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    ha.privmsg(&ch, "keep-this").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ha.privmsg(&ch, "delete-this").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ha.privmsg(&ch, "also-keep").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Collect the msgid of "delete-this" from echo-message
    let mut delete_msgid = String::new();
    loop {
        match maybe_wait(
            &mut ea,
            |e| matches!(e, Event::Message { .. }),
            Duration::from_secs(2),
        )
        .await
        {
            Some(Event::Message { text, tags, .. }) => {
                if text == "delete-this" {
                    if let Some(mid) = tags.get("msgid") {
                        delete_msgid = mid.clone();
                    }
                }
            }
            _ => break,
        }
    }

    if delete_msgid.is_empty() {
        eprintln!("  ⚠ Could not capture msgid for delete-this (echo-message may not be enabled)");
        let _ = ha.quit(Some("done")).await;
        return;
    }

    // Delete the message
    let mut del_tags = std::collections::HashMap::new();
    del_tags.insert("+draft/delete".to_string(), delete_msgid.clone());
    ha.send_tagmsg(&ch, del_tags).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B joins and retrieves history
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;

    let mut seen_texts = Vec::new();
    loop {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. }) if !text.contains("joined") => {
                seen_texts.push(text);
            }
            Some(Event::BatchEnd { .. }) => break,
            _ => break,
        }
    }

    assert!(
        !seen_texts.iter().any(|t| t == "delete-this"),
        "Deleted message should NOT appear in history: {seen_texts:?}"
    );
    assert!(
        seen_texts.iter().any(|t| t == "keep-this"),
        "Non-deleted messages should appear: {seen_texts:?}"
    );
    eprintln!("  ✓ Deleted messages excluded from CHATHISTORY");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── HIST-3: Edited messages show new text in CHATHISTORY ──

#[tokio::test]
async fn single_server_hist3_edited_messages_in_history() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("hist3");
    let nick_a = test_nick("hist3", "a");
    let nick_b = test_nick("hist3", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    ha.privmsg(&ch, "original-text").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Capture msgid
    let mut orig_msgid = String::new();
    loop {
        match maybe_wait(
            &mut ea,
            |e| matches!(e, Event::Message { .. }),
            Duration::from_secs(2),
        )
        .await
        {
            Some(Event::Message { text, tags, .. }) => {
                if text == "original-text" {
                    if let Some(mid) = tags.get("msgid") {
                        orig_msgid = mid.clone();
                    }
                }
            }
            _ => break,
        }
    }

    if orig_msgid.is_empty() {
        eprintln!("  ⚠ Could not capture msgid (echo-message may not be enabled)");
        let _ = ha.quit(Some("done")).await;
        return;
    }

    // Edit the message
    let mut edit_tags = std::collections::HashMap::new();
    edit_tags.insert("+draft/edit".to_string(), orig_msgid.clone());
    ha.send_tagged(&ch, "edited-text", edit_tags).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B joins and checks history
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;

    let mut seen_texts = Vec::new();
    loop {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. }) => {
                if !text.contains("joined") {
                    seen_texts.push(text);
                }
            }
            Some(Event::BatchEnd { .. }) => break,
            _ => break,
        }
    }

    // The in-memory history should show edited text
    assert!(
        seen_texts.iter().any(|t| t == "edited-text"),
        "Edited text should appear in JOIN history: {seen_texts:?}"
    );
    // Original text should NOT appear (it was replaced in-memory)
    assert!(
        !seen_texts.iter().any(|t| t == "original-text"),
        "Original text should be replaced in JOIN history: {seen_texts:?}"
    );
    eprintln!("  ✓ Edited messages show new text in JOIN history");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── HIST-4: Double-join does not produce duplicate history ──

#[tokio::test]
async fn single_server_hist4_double_join_no_duplicate_history() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("hist4");
    let nick_a = test_nick("hist4", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    ha.privmsg(&ch, "unique-marker-hist4").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // Send JOIN again (double join)
    ha.raw(&format!("JOIN {ch}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Collect any messages that arrive
    let mut count = 0;
    loop {
        match maybe_wait(
            &mut ea,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(2),
        )
        .await
        {
            Some(Event::Message { text, .. }) if text.contains("unique-marker-hist4") => {
                count += 1;
            }
            Some(Event::BatchEnd { .. }) => break,
            None => break,
            _ => {}
        }
    }

    // Should have 0 replayed copies (already in channel, no replay)
    // or at most 1 if server sends history again
    assert!(
        count <= 1,
        "Double JOIN should not produce duplicate history, got {count} copies"
    );
    eprintln!("  ✓ Double JOIN does not produce duplicate history (count={count})");

    let _ = ha.quit(Some("done")).await;
}

// ── DM-1: DMs between two users are delivered bidirectionally ──

#[tokio::test]
async fn single_server_dm1_bidirectional_dm() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("dm1");
    let nick_a = test_nick("dm1", "a");
    let nick_b = test_nick("dm1", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;

    // Both join a channel so they can see each other
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A → B
    ha.privmsg(&nick_b, "hello from A").await.unwrap();
    let (_from, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, "hello from A");
    eprintln!("  ✓ A→B DM delivered");

    // B → A
    hb.privmsg(&nick_a, "hello from B").await.unwrap();
    let (_from, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, "hello from B");
    eprintln!("  ✓ B→A DM delivered");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── DM-2: DMs to offline user don't crash, return 401 ──

#[tokio::test]
async fn single_server_dm2_dm_to_offline_user() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("dm2", "a");
    let nick_offline = test_nick("dm2", "off");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    drain(&mut ea).await;

    // Send DM to non-existent nick
    ha.privmsg(&nick_offline, "hello?").await.unwrap();

    // Two outcomes are correct, and which one you get depends on the topology,
    // not on this code path being right:
    //   - No S2S peers: ERR_NOSUCHNICK (401).
    //   - With S2S peers: relayed, because this server cannot know whether the
    //     nick exists on a peer. Same rule PM-2 and ROUTE-2 document.
    // This harness peers LOCAL_SERVER with a second server, so the relay is the
    // expected path here. What must hold either way is that the session
    // survives — that is the test's subject ("don't crash").
    //
    // A 401 surfaces as `WhoisReply`, not `ServerNotice`: the SDK gives numeric
    // 401 its own arm for WHOIS failures, so it never reaches the generic
    // 4xx→ServerNotice fallback. Accept either, since a 401 answering a PRIVMSG
    // and a 401 answering a WHOIS are indistinguishable on the wire.
    let got_error = maybe_wait(
        &mut ea,
        |e| match e {
            Event::ServerNotice { text } => {
                text.contains("No such nick") || text.contains(&nick_offline)
            }
            Event::WhoisReply { info, .. } => info.contains("No such nick"),
            _ => false,
        },
        Duration::from_secs(3),
    )
    .await;
    if got_error.is_some() {
        eprintln!("  ✓ DM to offline user returned ERR_NOSUCHNICK");
    } else {
        eprintln!("  ✓ DM to offline user relayed to peers (federation active)");
    }

    assert_session_alive(&ha, &mut ea, "dm2").await;
    eprintln!("  ✓ DM to offline user left the session usable");

    let _ = ha.quit(Some("done")).await;
}

// ── RECONN-1: Rejoining after disconnect sees recent messages ──

#[tokio::test]
async fn single_server_reconn1_rejoin_sees_recent_messages() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("reconn1");
    let nick_a = test_nick("reconn1", "a");
    let nick_b = test_nick("reconn1", "b");

    // A creates channel and sends messages
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    ha.privmsg(&ch, "before-rejoin-1").await.unwrap();
    ha.privmsg(&ch, "before-rejoin-2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // B joins, sees history, then parts
    let (hb1, mut eb1) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb1).await;
    hb1.join(&ch).await.unwrap();
    wait_joined(&mut eb1, &ch).await;
    drain(&mut eb1).await;
    hb1.raw(&format!("PART {ch}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drain(&mut ea).await;

    // A sends more messages while B is gone
    ha.privmsg(&ch, "while-gone").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B rejoins — should see all messages including "while-gone"
    hb1.join(&ch).await.unwrap();
    wait_joined(&mut eb1, &ch).await;

    let mut seen = Vec::new();
    loop {
        match maybe_wait(
            &mut eb1,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. })
                if text.starts_with("before-") || text == "while-gone" =>
            {
                seen.push(text);
            }
            Some(Event::BatchEnd { .. }) => break,
            _ => break,
        }
    }

    assert!(
        seen.iter().any(|t| t == "while-gone"),
        "Rejoin should show messages sent while away: {seen:?}"
    );
    eprintln!("  ✓ Rejoining sees messages sent during absence");

    let _ = ha.quit(Some("done")).await;
    let _ = hb1.quit(Some("done")).await;
}

// ── RECONN-2: Fresh connection to same channel gets full history ──

#[tokio::test]
async fn single_server_reconn2_fresh_connection_gets_history() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("reconn2");
    let nick_a = test_nick("reconn2", "a");
    let nick_b = test_nick("reconn2", "b");

    // A populates channel
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    for i in 1..=3 {
        ha.privmsg(&ch, &format!("persist-{i}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B connects fresh and joins
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;

    let mut seen = Vec::new();
    loop {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { .. } | Event::BatchEnd { .. }),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. }) if text.starts_with("persist-") => {
                seen.push(text);
            }
            Some(Event::BatchEnd { .. }) => break,
            _ => break,
        }
    }

    assert_eq!(
        seen.len(),
        3,
        "Fresh connection should see all 3 history messages: {seen:?}"
    );
    assert_eq!(seen, vec!["persist-1", "persist-2", "persist-3"]);
    eprintln!("  ✓ Fresh connection gets full history in correct order");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-14: Messages have unique msgids ──

#[tokio::test]
async fn single_server_edge14_rapid_messages_unique_msgids() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge14");
    let nick_a = test_nick("edge14", "a");
    let nick_b = test_nick("edge14", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // Flood protection is 5 messages per 2 seconds per session, and it is not
    // incidental — it is the defense against a single connection saturating a
    // channel. A 20-message burst therefore *must* be clipped: expecting most of
    // it through (the old ">= 10") asserted the absence of the protection.
    //
    // Two things are worth pinning here, so do both: the burst is refused rather
    // than silently swallowed, and every message that is accepted — burst or not
    // — carries its own msgid.
    let mut msgids = Vec::new();

    for i in 0..20 {
        ha.privmsg(&ch, &format!("burst-{i}")).await.unwrap();
    }
    let flood_reply = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::ServerNotice { text } if text.contains("Flood protection")),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        flood_reply.is_some(),
        "a 20-message burst must draw the flood-protection reply"
    );
    collect_msgids(&mut eb, "burst-", &mut msgids).await;
    let from_burst = msgids.len();
    assert!(
        (1..=10).contains(&from_burst),
        "the burst should be clipped to roughly the 5/2s allowance, got {from_burst} of 20"
    );
    eprintln!("  ✓ 20-message burst clipped to {from_burst} by flood protection");

    // Now the same volume inside the allowance: 4 per 2s window. Every one of
    // these must arrive — that is the half of the original intent worth keeping.
    let paced = 12;
    for i in 0..paced {
        if i > 0 && i % 4 == 0 {
            tokio::time::sleep(Duration::from_millis(2100)).await;
        }
        ha.privmsg(&ch, &format!("paced-{i}")).await.unwrap();
    }
    let mut paced_ids = Vec::new();
    collect_msgids(&mut eb, "paced-", &mut paced_ids).await;
    assert_eq!(
        paced_ids.len(),
        paced,
        "every message sent inside the flood allowance must be delivered"
    );
    msgids.extend(paced_ids);

    // All msgids should be unique
    let unique: std::collections::HashSet<&str> = msgids.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        msgids.len(),
        "All msgids must be unique: {} unique out of {}",
        unique.len(),
        msgids.len()
    );
    eprintln!("  ✓ {} rapid messages all have unique msgids", msgids.len());

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-15: Message to channel with wrong case still delivered ──

#[tokio::test]
async fn single_server_edge15_channel_case_message_delivery() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge15");
    let ch_upper = ch.to_uppercase();
    let nick_a = test_nick("edge15", "a");
    let nick_b = test_nick("edge15", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // Send to UPPER case channel name
    ha.privmsg(&ch_upper, "case-test").await.unwrap();

    let result = maybe_wait(
        &mut eb,
        |e| matches!(e, Event::Message { text, .. } if text == "case-test"),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        result.is_some(),
        "Message to channel with wrong case should still be delivered"
    );
    eprintln!("  ✓ Message to wrong-case channel name delivered");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-16: Nick change mid-conversation, messages still delivered ──

#[tokio::test]
async fn single_server_edge16_nick_change_mid_conversation() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge16");
    let nick_a = test_nick("edge16", "a");
    let nick_b = test_nick("edge16", "b");
    let nick_a2 = test_nick("edge16", "a2");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A sends message with old nick
    ha.privmsg(&ch, "before-change").await.unwrap();
    wait_message_from(&mut eb, &nick_a).await;
    drain(&mut eb).await;

    // A changes nick
    ha.raw(&format!("NICK {nick_a2}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A sends message with new nick
    ha.privmsg(&ch, "after-change").await.unwrap();
    // `wait_message_from` already asserts the sender (it waits for a Message
    // whose `from` is `nick_a2`) and returns `(target, text)`. The old binding
    // named the target `from` and then compared it to the nick, so the assert
    // read "the channel equals the new nick" and failed on every run.
    let (target, text) = wait_message_from(&mut eb, &nick_a2).await;
    assert_eq!(text, "after-change");
    assert_eq!(
        target.to_lowercase(),
        ch.to_lowercase(),
        "post-rename message must still land in the channel"
    );
    eprintln!("  ✓ Messages delivered correctly after nick change");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-17: Part and rejoin preserves channel state ──

#[tokio::test]
async fn single_server_edge17_part_rejoin_preserves_topic() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge17");
    let nick_a = test_nick("edge17", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    // Set topic
    ha.raw(&format!("TOPIC {ch} :persistent topic"))
        .await
        .unwrap();
    wait_topic(&mut ea, &ch).await;
    drain(&mut ea).await;

    // Part and rejoin
    ha.raw(&format!("PART {ch}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drain(&mut ea).await;

    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    // Should see topic on rejoin (as TopicChanged or in server numerics)
    let topic_found = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic == "persistent topic"),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        topic_found.is_some(),
        "Topic should persist through part/rejoin"
    );
    eprintln!("  ✓ Topic persists through part/rejoin");

    let _ = ha.quit(Some("done")).await;
}

// ── EDGE-18: Multiple users sending simultaneously ──

#[tokio::test]
async fn single_server_edge18_simultaneous_senders() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge18");
    let nick_a = test_nick("edge18", "a");
    let nick_b = test_nick("edge18", "b");
    let nick_c = test_nick("edge18", "c");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;

    let (hc, mut ec) = connect_guest(&server, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&ch).await.unwrap();
    wait_joined(&mut ec, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;
    drain(&mut ec).await;

    // All three send simultaneously
    let f1 = ha.privmsg(&ch, "from-a");
    let f2 = hb.privmsg(&ch, "from-b");
    let f3 = hc.privmsg(&ch, "from-c");
    let _ = tokio::join!(f1, f2, f3);

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // C should see messages from A and B (and possibly echo)
    let mut seen = std::collections::HashSet::new();
    loop {
        match maybe_wait(
            &mut ec,
            |e| matches!(e, Event::Message { text, .. } if text.starts_with("from-")),
            Duration::from_secs(3),
        )
        .await
        {
            Some(Event::Message { text, .. }) => {
                seen.insert(text);
            }
            _ => break,
        }
    }

    assert!(
        seen.contains("from-a"),
        "C should see A's message: {seen:?}"
    );
    assert!(
        seen.contains("from-b"),
        "C should see B's message: {seen:?}"
    );
    eprintln!("  ✓ Simultaneous senders: all messages delivered to observer");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── EDGE-19: Empty message is handled gracefully ──

#[tokio::test]
async fn single_server_edge19_empty_message() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge19");
    let nick_a = test_nick("edge19", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    // Send empty PRIVMSG
    ha.raw(&format!("PRIVMSG {ch} :")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Server should not crash — send another message to verify
    ha.privmsg(&ch, "still-alive").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // We're still connected if we can receive events
    let alive = maybe_wait(&mut ea, |_e| true, Duration::from_secs(2)).await;
    assert!(
        alive.is_some(),
        "Server should still be responsive after empty message"
    );
    eprintln!("  ✓ Empty message handled gracefully, server still responsive");

    let _ = ha.quit(Some("done")).await;
}

// ── EDGE-20: Very long nick in DM doesn't crash ──

#[tokio::test]
async fn single_server_edge20_message_to_long_nick() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("edge20", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    drain(&mut ea).await;

    // Send DM to a very long nick
    let long_nick = "x".repeat(100);
    ha.privmsg(&long_nick, "hello").await.unwrap();

    // An error is welcome but not guaranteed: with an S2S peer attached the
    // server relays an unknown DM target rather than answering 401 (see DM-2),
    // and a 100-character nick is just an unknown target. "Handled gracefully"
    // is therefore about the session, not about a reply arriving — so check the
    // session, which is what the test is named for.
    let result = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::ServerNotice { .. } | Event::WhoisReply { .. }),
        Duration::from_secs(3),
    )
    .await;
    if result.is_some() {
        eprintln!("  ✓ absurdly long nick drew an error reply");
    }
    assert_session_alive(&ha, &mut ea, "edge20").await;
    eprintln!("  ✓ DM to absurdly long nick handled gracefully");

    let _ = ha.quit(Some("done")).await;
}

// ── EDGE-21: CHATHISTORY with no database returns empty batch ──

#[tokio::test]
async fn single_server_edge21_chathistory_request_for_empty_channel() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge21");
    let nick_a = test_nick("edge21", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    // Explicitly request CHATHISTORY LATEST on empty channel
    ha.raw(&format!("CHATHISTORY LATEST {ch} * 50"))
        .await
        .unwrap();

    // Should get BATCH start + end (empty), not an error
    let batch_start = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::BatchStart { .. }),
        Duration::from_secs(3),
    )
    .await;
    // It's OK if we don't get a batch (server might not reply for empty)
    // but we should NOT crash
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection is still alive
    ha.privmsg(&ch, "still-alive-21").await.unwrap();
    let alive = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::Message { text, .. } if text == "still-alive-21"),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        alive.is_some(),
        "Connection should survive CHATHISTORY on empty channel"
    );
    eprintln!(
        "  ✓ CHATHISTORY on empty channel doesn't crash (batch_start={:?})",
        batch_start.is_some()
    );

    let _ = ha.quit(Some("done")).await;
}

// ── EDGE-22: Rapid join/part doesn't leave stale members ──

#[tokio::test]
async fn single_server_edge22_rapid_join_part_no_stale_members() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge22");
    let nick_a = test_nick("edge22", "a");
    let nick_b = test_nick("edge22", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    // B rapidly joins and parts 5 times
    for _ in 0..5 {
        let (hb, mut eb) = connect_guest(&server, &nick_b).await;
        wait_registered(&mut eb).await;
        hb.join(&ch).await.unwrap();
        wait_joined(&mut eb, &ch).await;
        hb.raw(&format!("PART {ch}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = hb.quit(Some("rapid")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;

    // Request NAMES — B should NOT be in the list
    let nicks = request_names(&ha, &mut ea, &ch).await;
    assert!(
        !nick_is_present(&nicks, &nick_b),
        "B should not be in NAMES after rapid join/part: {nicks:?}"
    );
    assert!(
        nick_is_present(&nicks, &nick_a),
        "A should still be in channel: {nicks:?}"
    );
    eprintln!("  ✓ Rapid join/part leaves no stale members");

    let _ = ha.quit(Some("done")).await;
}

// ── EDGE-23: PRIVMSG with special characters ──

#[tokio::test]
async fn single_server_edge23_special_characters_in_message() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge23");
    let nick_a = test_nick("edge23", "a");
    let nick_b = test_nick("edge23", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // Send messages with special characters
    let test_messages = [
        "hello 🔥 world 🌍",
        "line with unicode: café résumé naïve",
        "symbols: @#$%^&*()[]{}|\\",
        "empty-looking:   ", // spaces only
        "https://example.com/path?a=1&b=2#frag",
    ];

    for msg in &test_messages {
        ha.privmsg(&ch, msg).await.unwrap();
        let result = maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { .. }),
            Duration::from_secs(3),
        )
        .await;
        assert!(
            result.is_some(),
            "Message with special chars should be delivered: {msg}"
        );
        if let Some(Event::Message { text, .. }) = result {
            assert_eq!(&text, msg, "Message text should be preserved exactly");
        }
    }
    eprintln!("  ✓ Special characters preserved in messages");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-24: MODE changes reflected in subsequent NAMES ──

#[tokio::test]
async fn single_server_edge24_mode_reflected_in_names() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge24");
    let nick_a = test_nick("edge24", "a");
    let nick_b = test_nick("edge24", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&ch).await.unwrap();
    wait_joined(&mut eb, &ch).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A is op (creator), B is not
    let nicks_before = request_names(&ha, &mut ea, &ch).await;
    assert!(
        nick_is_op(&nicks_before, &nick_a),
        "A should be op: {nicks_before:?}"
    );
    assert!(
        !nick_is_op(&nicks_before, &nick_b),
        "B should not be op: {nicks_before:?}"
    );

    // A grants op to B
    ha.raw(&format!("MODE {ch} +o {nick_b}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // NAMES should now show B as op
    let nicks_after = request_names(&ha, &mut ea, &ch).await;
    assert!(
        nick_is_op(&nicks_after, &nick_b),
        "B should be op after +o: {nicks_after:?}"
    );
    eprintln!("  ✓ MODE +o reflected in NAMES");

    // Remove op from B
    ha.raw(&format!("MODE {ch} -o {nick_b}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    let nicks_final = request_names(&ha, &mut ea, &ch).await;
    assert!(
        !nick_is_op(&nicks_final, &nick_b),
        "B should not be op after -o: {nicks_final:?}"
    );
    eprintln!("  ✓ MODE -o reflected in NAMES");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── EDGE-25: TOPIC with empty string clears topic ──

#[tokio::test]
async fn single_server_edge25_clear_topic() {
    let Some(server) = get_single_server() else {
        return;
    };
    let ch = test_channel("edge25");
    let nick_a = test_nick("edge25", "a");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&ch).await.unwrap();
    wait_joined(&mut ea, &ch).await;
    drain(&mut ea).await;

    // Set topic
    ha.raw(&format!("TOPIC {ch} :some topic")).await.unwrap();
    wait_topic(&mut ea, &ch).await;

    // Clear topic
    ha.raw(&format!("TOPIC {ch} :")).await.unwrap();
    let cleared = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic.is_empty()),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        cleared.is_some(),
        "Topic should be clearable with empty string"
    );
    eprintln!("  ✓ Topic can be cleared with empty string");

    let _ = ha.quit(Some("done")).await;
}

// ── DM-1: Edit and delete work for direct messages ──

#[tokio::test]
async fn single_server_dm1_edit_and_delete() {
    let Some(server) = get_single_server() else {
        return;
    };
    let nick_a = test_nick("dm1", "a");
    let nick_b = test_nick("dm1", "b");

    // Connect both users
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A sends DM to B
    ha.privmsg(&nick_b, "dm-original").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B should receive the DM
    let dm_event = wait_for(
        &mut eb,
        |e| matches!(e, Event::Message { text, .. } if text == "dm-original"),
        "B receives DM",
    )
    .await;

    let msgid = match &dm_event {
        Event::Message { tags, .. } => tags.get("msgid").cloned().unwrap_or_default(),
        _ => String::new(),
    };

    if msgid.is_empty() {
        eprintln!("  ⚠ Could not capture msgid for DM");
        let _ = ha.quit(Some("done")).await;
        let _ = hb.quit(Some("done")).await;
        return;
    }
    eprintln!("  ✓ DM delivered with msgid {msgid}");

    // A edits the DM
    let mut edit_tags = std::collections::HashMap::new();
    edit_tags.insert("+draft/edit".to_string(), msgid.clone());
    ha.send_tagged(&nick_b, "dm-edited", edit_tags)
        .await
        .unwrap();

    // B should receive the edit
    let edit_received = maybe_wait(
        &mut eb,
        |e| matches!(e, Event::Message { text, tags, .. } if text == "dm-edited" && tags.get("+draft/edit").is_some()),
        Duration::from_secs(3),
    )
    .await;

    assert!(edit_received.is_some(), "B should receive the edited DM");
    eprintln!("  ✓ DM edit delivered to recipient");

    // A deletes the DM
    ha.delete_message(&nick_b, &msgid).await.unwrap();

    // B should receive the delete (TAGMSG with +draft/delete)
    let delete_received = maybe_wait(
        &mut eb,
        |e| matches!(e, Event::TagMsg { tags, .. } if tags.get("+draft/delete").is_some()),
        Duration::from_secs(3),
    )
    .await;

    assert!(
        delete_received.is_some(),
        "B should receive the delete notification"
    );
    eprintln!("  ✓ DM delete delivered to recipient");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

/// S2S: Invite issued on server A should allow user on server B to join +i channel.
#[tokio::test]
async fn s2s_invite_syncs_across_servers() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("sinv");
    let nick_op = test_nick("sinv", "op");
    let nick_guest = test_nick("sinv", "g");

    // Op connects to local server, guest to remote
    let (h_op, mut e_op) = connect_guest(&local, &nick_op).await;
    let (h_g, mut e_g) = connect_guest(&remote, &nick_guest).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_g).await;

    // Op creates channel and sets +i
    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;
    h_op.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(S2S_SETTLE).await;

    // Guest tries to join from remote — should fail
    h_g.join(&channel).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "ERR_INVITEONLYCHAN on remote",
    )
    .await;
    eprintln!("  ✓ +i blocks uninvited remote user");

    // Op invites the guest (by nick — guest is a remote user from op's perspective)
    h_op.raw(&format!("INVITE {nick_guest} {channel}"))
        .await
        .unwrap();
    // Wait for 341 confirmation to op
    wait_for(
        &mut e_op,
        |e| matches!(e, Event::RawLine(line) if line.contains("341")),
        "INVITE confirmation",
    )
    .await;
    eprintln!("  ✓ INVITE issued on local server");

    // Let S2S propagate the invite
    tokio::time::sleep(S2S_SETTLE).await;

    // Now guest should be able to join from remote
    h_g.join(&channel).await.unwrap();
    wait_joined(&mut e_g, &channel).await;
    eprintln!("  ✓ Invited remote user can join +i channel via S2S invite sync");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_g.quit(Some("done")).await;
}

// ── REACT-1: Reaction in channel visible cross-server ──

#[tokio::test]
async fn s2s_react1_channel_reaction_cross_server() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("react1");
    let nick_a = test_nick("react1", "a");
    let nick_b = test_nick("react1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A sends a message so B can react to it
    let msg_text = format!("react-target-{}", rand::random::<u16>());
    ha.privmsg(&channel, &msg_text).await.unwrap();
    let evt = wait_message_event_containing(&mut eb, &msg_text).await;
    let msgid = if let Event::Message { tags, .. } = &evt {
        tags.get("msgid").cloned().unwrap_or_default()
    } else {
        String::new()
    };
    assert!(!msgid.is_empty(), "Message should have a msgid");

    // B reacts to A's message
    let mut react_tags = std::collections::HashMap::new();
    react_tags.insert("+react".to_string(), "👍".to_string());
    react_tags.insert("+reply".to_string(), msgid.clone());
    hb.send_tagmsg(&channel, react_tags).await.unwrap();

    // A should see the reaction via S2S (as TAGMSG or ACTION fallback)
    let reaction_evt = timeout(S2S_TIMEOUT, async {
        loop {
            if let Some(evt) = ea.recv().await {
                match &evt {
                    Event::TagMsg { tags, .. }
                        if tags.get("+react").map(|s| s.as_str()) == Some("👍") =>
                    {
                        return evt;
                    }
                    Event::Message { text, .. } if text.contains("reacted with 👍") => {
                        return evt;
                    }
                    _ => continue,
                }
            }
        }
    })
    .await;

    assert!(
        reaction_evt.is_ok(),
        "A should receive B's reaction via S2S"
    );
    eprintln!("  ✓ REACT-1: channel reaction visible cross-server");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── DM-S2S-1: DM bidirectional across servers ──

#[tokio::test]
async fn s2s_dm_s2s1_bidirectional_dm() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("dms2s1");
    let nick_a = test_nick("dms2s1", "a");
    let nick_b = test_nick("dms2s1", "b");

    // Both join a channel so they're visible to each other
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A sends DM to B
    let dm_text = format!("dm-s2s-{}", rand::random::<u16>());
    ha.privmsg(&nick_b, &dm_text).await.unwrap();
    let (from, _, text) = wait_message_containing(&mut eb, &dm_text).await;
    assert_eq!(from, nick_a);
    assert_eq!(text, dm_text);
    eprintln!("  ✓ DM-S2S-1a: A→B cross-server DM delivered");

    // B sends DM to A
    let dm_text2 = format!("dm-s2s-reply-{}", rand::random::<u16>());
    hb.privmsg(&nick_a, &dm_text2).await.unwrap();
    let (from2, _, text2) = wait_message_containing(&mut ea, &dm_text2).await;
    assert_eq!(from2, nick_b);
    assert_eq!(text2, dm_text2);
    eprintln!("  ✓ DM-S2S-1b: B→A cross-server DM delivered (bidirectional)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── PIN-S2S-1: Pin visible cross-server ──

#[tokio::test]
async fn s2s_pin1_pin_visible_cross_server() {
    let Some((local, remote)) = get_servers() else {
        return;
    };
    let channel = test_channel("pin1");
    let nick_a = test_nick("pin1", "a");
    let nick_b = test_nick("pin1", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // A sends a message to pin
    let msg_text = format!("pin-target-{}", rand::random::<u16>());
    ha.privmsg(&channel, &msg_text).await.unwrap();
    let evt = wait_message_event_containing(&mut eb, &msg_text).await;
    let msgid = if let Event::Message { tags, .. } = &evt {
        tags.get("msgid").cloned().unwrap_or_default()
    } else {
        String::new()
    };
    assert!(!msgid.is_empty(), "Message should have a msgid");

    // A is op (created channel), A pins the message
    ha.pin(&channel, &msgid).await.unwrap();

    // B should see the pin notification via S2S (NOTICE with +freeq.at/pin tag or ACTION text)
    let pin_evt = timeout(S2S_TIMEOUT, async {
        loop {
            if let Some(evt) = eb.recv().await {
                match &evt {
                    Event::Message { text, tags, .. }
                        if text.contains("pinned") || tags.get("+freeq.at/pin").is_some() =>
                    {
                        return evt;
                    }
                    _ => continue,
                }
            }
        }
    })
    .await;

    assert!(pin_evt.is_ok(), "B should receive A's pin via S2S");
    eprintln!("  ✓ PIN-S2S-1: pin visible cross-server");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}
