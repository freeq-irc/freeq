#![allow(clippy::too_many_arguments)]
//! Query commands: WHOIS, WHO, LUSERS, AWAY.

use super::Connection;
use super::helpers::normalize_channel;
use crate::irc::{self, Message};
use crate::server::SharedState;
use std::sync::Arc;

pub(super) fn handle_whois(
    conn: &Connection,
    target_nick: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let my_nick = conn.nick_or_star();

    // Find target's session
    let target_session = state
        .nick_to_session
        .lock()
        .get_session(target_nick)
        .map(|s| s.to_string());

    let Some(target_session) = target_session else {
        // Check if this is a remote user (from S2S)
        let remote_info: Option<crate::server::RemoteMember> = {
            let channels = state.channels.lock();
            channels
                .values()
                .find_map(|ch| ch.remote_members.get(target_nick).cloned())
        };

        if let Some(rm) = remote_info {
            // Remote user — show what we know
            // Realname is a human-name slot: use the handle when known, never
            // the raw DID (clients render realname as a display name; the DID
            // travels machine-readable in its own 330 numeric below).
            let realname = match &rm.handle {
                Some(h) => format!("{h} (via S2S federation)"),
                None => "Remote user (via S2S federation)".to_string(),
            };
            let whoisuser = Message::from_server(
                server_name,
                irc::RPL_WHOISUSER,
                vec![my_nick, target_nick, target_nick, "s2s", "*", &realname],
            );
            send(state, session_id, format!("{whoisuser}\r\n"));

            let whoisserver = Message::from_server(
                server_name,
                irc::RPL_WHOISSERVER,
                vec![
                    my_nick,
                    target_nick,
                    "s2s",
                    &format!(
                        "Connected via S2S ({}…)",
                        &rm.origin[..16.min(rm.origin.len())]
                    ),
                ],
            );
            send(state, session_id, format!("{whoisserver}\r\n"));

            // Show AT Protocol handle
            if let Some(ref handle) = rm.handle {
                let handle_line = Message::from_server(
                    server_name,
                    "671",
                    vec![
                        my_nick,
                        target_nick,
                        &format!("AT Protocol handle: {handle}"),
                    ],
                );
                send(state, session_id, format!("{handle_line}\r\n"));
            }

            // Show DID
            if let Some(ref d) = rm.did {
                let did_line = Message::from_server(
                    server_name,
                    irc::RPL_WHOISACCOUNT,
                    vec![my_nick, target_nick, d, "is authenticated as"],
                );
                send(state, session_id, format!("{did_line}\r\n"));
            }

            // Show channels they're in
            let user_channels: Vec<String> = {
                let channels = state.channels.lock();
                channels
                    .iter()
                    .filter(|(_, ch)| ch.remote_members.contains_key(target_nick))
                    .map(|(name, ch)| {
                        let is_op = rm.did.as_ref().is_some_and(|d| {
                            ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                        });
                        if is_op {
                            format!("@{name}")
                        } else {
                            name.clone()
                        }
                    })
                    .collect()
            };
            if !user_channels.is_empty() {
                let channels_line = Message::from_server(
                    server_name,
                    "319", // RPL_WHOISCHANNELS
                    vec![my_nick, target_nick, &user_channels.join(" ")],
                );
                send(state, session_id, format!("{channels_line}\r\n"));
            }

            let end = Message::from_server(
                server_name,
                irc::RPL_ENDOFWHOIS,
                vec![my_nick, target_nick, "End of /WHOIS list"],
            );
            send(state, session_id, format!("{end}\r\n"));
        } else {
            // Check if this is a spawned (virtual) agent
            let spawned = state
                .spawned_agents
                .lock()
                .values()
                .find(|sa| sa.nick.eq_ignore_ascii_case(target_nick))
                .cloned();

            if let Some(sa) = spawned {
                let parent_nick = state
                    .nick_to_session
                    .lock()
                    .get_nick(&sa.parent_session)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| sa.parent_did.clone());

                let realname = format!("Spawned agent (parent: {parent_nick})");
                let whoisuser = Message::from_server(
                    server_name,
                    irc::RPL_WHOISUSER,
                    vec![my_nick, target_nick, "spawn", "freeq/spawn", "*", &realname],
                );
                send(state, session_id, format!("{whoisuser}\r\n"));

                let whoisserver = Message::from_server(
                    server_name,
                    irc::RPL_WHOISSERVER,
                    vec![my_nick, target_nick, server_name, "freeq"],
                );
                send(state, session_id, format!("{whoisserver}\r\n"));

                // Show DID
                let did_line = Message::from_server(
                    server_name,
                    "330",
                    vec![my_nick, target_nick, &sa.child_did, "is authenticated as"],
                );
                send(state, session_id, format!("{did_line}\r\n"));

                // Show actor class
                let class_line = Message::from_server(
                    server_name,
                    "673",
                    vec![my_nick, target_nick, "actor_class=agent"],
                );
                send(state, session_id, format!("{class_line}\r\n"));

                // Show spawn info
                let caps_str = if sa.capabilities.is_empty() {
                    "none".to_string()
                } else {
                    sa.capabilities.join(", ")
                };
                let spawn_info = format!(
                    "parent={parent_nick}, capabilities={caps_str}, task={}",
                    sa.task_ref.as_deref().unwrap_or("-")
                );
                let spawn_line = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![my_nick, &format!("Spawned agent: {spawn_info}")],
                );
                send(state, session_id, format!("{spawn_line}\r\n"));

                let end = Message::from_server(
                    server_name,
                    irc::RPL_ENDOFWHOIS,
                    vec![my_nick, target_nick, "End of /WHOIS list"],
                );
                send(state, session_id, format!("{end}\r\n"));
            } else {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_NOSUCHNICK,
                    vec![my_nick, target_nick, "No such nick"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                let end = Message::from_server(
                    server_name,
                    irc::RPL_ENDOFWHOIS,
                    vec![my_nick, target_nick, "End of /WHOIS list"],
                );
                send(state, session_id, format!("{end}\r\n"));
            }
        }
        return;
    };

    let did = state.session_dids.lock().get(&target_session).cloned();

    // 311 RPL_WHOISUSER — host is the target's cloak (DID-derived, or the
    // guest cloak), matching what JOIN/PRIVMSG hostmasks already show.
    let cloak = super::cloak_for_did(did.as_deref());
    let whoisuser = Message::from_server(
        server_name,
        irc::RPL_WHOISUSER,
        vec![my_nick, target_nick, "~u", &cloak, "*", "IRC User"],
    );
    send(state, session_id, format!("{whoisuser}\r\n"));

    // 312 RPL_WHOISSERVER
    let whoisserver = Message::from_server(
        server_name,
        irc::RPL_WHOISSERVER,
        vec![my_nick, target_nick, server_name, "freeq"],
    );
    send(state, session_id, format!("{whoisserver}\r\n"));

    // 330 RPL_WHOISACCOUNT — show DID if authenticated

    if let Some(ref did) = did {
        let whoisaccount = Message::from_server(
            server_name,
            irc::RPL_WHOISACCOUNT,
            vec![my_nick, target_nick, did, "is authenticated as"],
        );
        send(state, session_id, format!("{whoisaccount}\r\n"));
    }

    // Show Bluesky handle if resolved
    if did.is_some() {
        let handle = state.session_handles.lock().get(&target_session).cloned();
        if let Some(handle) = handle {
            // Use a server notice (not a standard numeric, but informational)
            let notice = Message::from_server(
                server_name,
                "671", // RPL_WHOISSECURE (repurposed for extra info)
                vec![
                    my_nick,
                    target_nick,
                    &format!("AT Protocol handle: {handle}"),
                ],
            );
            send(state, session_id, format!("{notice}\r\n"));
        }
    }

    // Show iroh endpoint ID if connected via iroh
    let iroh_id = state.session_iroh_ids.lock().get(&target_session).cloned();
    if let Some(iroh_id) = iroh_id {
        let iroh_notice = Message::from_server(
            server_name,
            "672", // Custom numeric for iroh info
            vec![my_nick, target_nick, &format!("iroh endpoint: {iroh_id}")],
        );
        send(state, session_id, format!("{iroh_notice}\r\n"));
    }

    // Show actor class if not human (673 = custom RPL_ACTORCLASS)
    {
        let actor_class = state
            .session_actor_class
            .lock()
            .get(&target_session)
            .copied();
        if let Some(class) = actor_class
            && class != crate::connection::ActorClass::Human
        {
            let class_line = Message::from_server(
                server_name,
                "673",
                vec![my_nick, target_nick, &format!("actor_class={class}")],
            );
            send(state, session_id, format!("{class_line}\r\n"));
        }
    }

    // Show linked identities (e.g., GitHub)
    if let Some(ref did) = did {
        let identities = state.linked_identities.lock();
        if let Some(links) = identities.get(did.as_str()) {
            for link in links {
                let link_line = Message::from_server(
                    server_name,
                    "671",
                    vec![
                        my_nick,
                        target_nick,
                        &format!("linked {}: {}", link.provider, link.identity),
                    ],
                );
                send(state, session_id, format!("{link_line}\r\n"));
            }
        }
    }

    // Show client software
    // Look up the target connection to get client_info
    // We need to find the connection object — it's not in shared state directly,
    // so we'll store client_info per-session.
    if let Some(ref client) = state.session_client_info.lock().get(&target_session) {
        let client_line = Message::from_server(
            server_name,
            "671", // RPL_WHOISSECURE (informational)
            vec![my_nick, target_nick, &format!("client: {client}")],
        );
        send(state, session_id, format!("{client_line}\r\n"));
    }

    // 319 RPL_WHOISCHANNELS — the channels they share, with membership prefix.
    //
    // The remote-member branch above has always sent this; the local branch never
    // did, so `/whois` on someone on your own server told you nothing about where
    // they are or what they can do there. Uses the same folded, DID-aware answer
    // as NAMES and WHO so all three agree.
    {
        // Snapshot and release before taking `channels`; never hold two of
        // these at once (see the lock-order note in channel.rs::handle_names).
        let dids_snapshot = state.session_dids.lock().clone();
        let target_did = dids_snapshot.get(&target_session).cloned();
        let channels = state.channels.lock();
        let mut listed: Vec<String> = channels
            .iter()
            .filter_map(|(name, ch)| {
                // Every session belonging to this person, not just the resolved one.
                let sessions: Vec<String> = ch
                    .members
                    .iter()
                    .filter(|s| {
                        *s == &target_session
                            || target_did
                                .as_ref()
                                .is_some_and(|d| dids_snapshot.get(*s) == Some(d))
                    })
                    .cloned()
                    .collect();
                if sessions.is_empty() {
                    return None;
                }
                let (is_op, is_voiced) = super::helpers::folded_membership(
                    &sessions,
                    &ch.ops,
                    &ch.voiced,
                    ch.founder_did.as_deref(),
                    &ch.did_ops,
                    &dids_snapshot,
                );
                let prefix = if is_op {
                    "@"
                } else if is_voiced {
                    "+"
                } else {
                    ""
                };
                Some(format!("{prefix}{name}"))
            })
            .collect();
        drop(channels);
        listed.sort();
        if !listed.is_empty() {
            let chans = Message::from_server(
                server_name,
                "319",
                vec![my_nick, target_nick, &listed.join(" ")],
            );
            send(state, session_id, format!("{chans}\r\n"));
        }
    }

    // 301 RPL_AWAY — show away message if target is away
    if let Some(away_msg) = state.session_away.lock().get(&target_session) {
        let away = Message::from_server(
            server_name,
            irc::RPL_AWAY,
            vec![my_nick, target_nick, away_msg],
        );
        send(state, session_id, format!("{away}\r\n"));
    }

    // 318 RPL_ENDOFWHOIS
    let end = Message::from_server(
        server_name,
        irc::RPL_ENDOFWHOIS,
        vec![my_nick, target_nick, "End of /WHOIS list"],
    );
    send(state, session_id, format!("{end}\r\n"));
}

pub(super) fn handle_who(
    conn: &Connection,
    target: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    if target.starts_with('#') || target.starts_with('&') {
        let channel = normalize_channel(target);
        // Snapshot before taking channels/nick_to_session — see the lock-order
        // note in channel.rs::handle_names.
        let dids_snapshot = state.session_dids.lock().clone();
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(&channel) {
            let n2s = state.nick_to_session.lock();
            let away = state.session_away.lock();

            // One row per PERSON, not per socket. Group this channel's sessions
            // by nick first: a user signed in on two devices was emitted twice,
            // with whichever flags each socket happened to carry.
            let mut by_nick: Vec<(String, Vec<String>)> = Vec::new();
            for session in &ch.members {
                let Some(n) = n2s.get_nick(session) else {
                    continue;
                };
                let lower = n.to_lowercase();
                match by_nick.iter_mut().find(|(k, _)| k.to_lowercase() == lower) {
                    Some((_, sessions)) => sessions.push(session.clone()),
                    None => by_nick.push((n.to_string(), vec![session.clone()])),
                }
            }

            for (member_nick, sessions) in &by_nick {
                {
                    let member_nick = member_nick.as_str();
                    let session = &sessions[0];
                    let user = "~u";
                    let host = super::cloak_for_did(dids_snapshot.get(session).map(|s| s.as_str()));
                    // Away only when every device is away: reachable on one
                    // device means reachable.
                    let away_flag = if sessions.iter().all(|s| away.contains_key(s)) {
                        "G"
                    } else {
                        "H"
                    };
                    let (is_op, is_voiced) = super::helpers::folded_membership(
                        sessions,
                        &ch.ops,
                        &ch.voiced,
                        ch.founder_did.as_deref(),
                        &ch.did_ops,
                        &dids_snapshot,
                    );
                    let op_flag = if is_op {
                        "@"
                    } else if is_voiced {
                        "+"
                    } else {
                        ""
                    };
                    let flags = format!("{away_flag}{op_flag}");
                    // Include DID in realname if authenticated
                    let did_info = dids_snapshot.get(session).cloned();
                    let realname = match did_info {
                        Some(did) => format!("0 {did}"),
                        None => "0 IRC User".to_string(),
                    };
                    let reply = Message::from_server(
                        server_name,
                        irc::RPL_WHOREPLY,
                        vec![
                            nick,
                            &channel,
                            user,
                            &host,
                            server_name,
                            member_nick,
                            &flags,
                            &realname,
                        ],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                }
            }
        }
        let end = Message::from_server(
            server_name,
            irc::RPL_ENDOFWHO,
            vec![nick, &channel, "End of /WHO list"],
        );
        send(state, session_id, format!("{end}\r\n"));
    } else {
        // WHO for a nick
        let target_session = state
            .nick_to_session
            .lock()
            .get_session(target)
            .map(|s| s.to_string());
        if let Some(ref session) = target_session {
            let away = state.session_away.lock();
            let away_flag = if away.contains_key(session) { "G" } else { "H" };
            let did_info = state.session_dids.lock().get(session).cloned();
            let host = super::cloak_for_did(did_info.as_deref());
            let realname = match did_info {
                Some(did) => format!("0 {did}"),
                None => "0 IRC User".to_string(),
            };
            let reply = Message::from_server(
                server_name,
                irc::RPL_WHOREPLY,
                vec![
                    nick,
                    "*",
                    "~u",
                    &host,
                    server_name,
                    target,
                    away_flag,
                    &realname,
                ],
            );
            send(state, session_id, format!("{reply}\r\n"));
        }
        let end = Message::from_server(
            server_name,
            irc::RPL_ENDOFWHO,
            vec![nick, target, "End of /WHO list"],
        );
        send(state, session_id, format!("{end}\r\n"));
    }
}

// ── AWAY command ────────────────────────────────────────────────────

pub(super) fn handle_lusers(
    conn: &Connection,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();
    let user_count = state.connections.lock().len();
    let channel_count = state.channels.lock().len();

    // Count remote users across all channels (deduplicated)
    let remote_count = {
        let channels = state.channels.lock();
        let mut remote_nicks = std::collections::HashSet::new();
        for ch in channels.values() {
            for nick in ch.remote_members.keys() {
                remote_nicks.insert(nick.clone());
            }
        }
        remote_nicks.len()
    };

    let total = user_count + remote_count;
    let r1 = Message::from_server(
        server_name,
        irc::RPL_LUSERCLIENT,
        vec![
            nick,
            &format!("There are {total} users on 1 server ({remote_count} remote)"),
        ],
    );
    let r2 = Message::from_server(
        server_name,
        irc::RPL_LUSEROP,
        vec![nick, "0", "operator(s) online"],
    );
    let r3 = Message::from_server(
        server_name,
        irc::RPL_LUSERCHANNELS,
        vec![nick, &channel_count.to_string(), "channels formed"],
    );
    let r4 = Message::from_server(
        server_name,
        irc::RPL_LUSERME,
        vec![nick, &format!("I have {user_count} clients and 0 servers")],
    );
    for r in [r1, r2, r3, r4] {
        send(state, session_id, format!("{r}\r\n"));
    }
}

pub(super) fn handle_away(
    conn: &Connection,
    away_msg: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();
    let hostmask = conn.hostmask();

    match away_msg {
        Some(msg) if !msg.is_empty() => {
            state
                .session_away
                .lock()
                .insert(session_id.to_string(), msg.to_string());
            let reply = Message::from_server(
                server_name,
                irc::RPL_NOWAWAY,
                vec![nick, "You have been marked as being away"],
            );
            send(state, session_id, format!("{reply}\r\n"));

            // away-notify: broadcast to shared channel members
            broadcast_away(state, session_id, &hostmask, Some(msg));
        }
        _ => {
            state.session_away.lock().remove(session_id);
            let reply = Message::from_server(
                server_name,
                irc::RPL_UNAWAY,
                vec![nick, "You are no longer marked as being away"],
            );
            send(state, session_id, format!("{reply}\r\n"));

            // away-notify: broadcast un-away to shared channel members
            broadcast_away(state, session_id, &hostmask, None);
        }
    }
}

/// Broadcast AWAY change to all channel members who negotiated away-notify.
fn broadcast_away(
    state: &Arc<SharedState>,
    session_id: &str,
    hostmask: &str,
    away_msg: Option<&str>,
) {
    let away_caps = state.cap_away_notify.lock();
    if away_caps.is_empty() {
        return;
    }

    // Build the AWAY line: ":nick!user@host AWAY :reason" or ":nick!user@host AWAY"
    let line = match away_msg {
        Some(msg) => format!(":{hostmask} AWAY :{msg}\r\n"),
        None => format!(":{hostmask} AWAY\r\n"),
    };

    // Find all channels this user is in, collect their members
    let mut targets = std::collections::HashSet::new();
    let channels = state.channels.lock();
    for ch in channels.values() {
        if ch.members.contains(session_id) {
            for member in &ch.members {
                if member != session_id && away_caps.contains(member) {
                    targets.insert(member.clone());
                }
            }
        }
    }
    drop(channels);

    let conns = state.connections.lock();
    for sid in &targets {
        if let Some(tx) = conns.get(sid) {
            let _ = tx.try_send(line.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Run handle_whois against a test state, capturing every line sent.
    fn whois_lines(state: &Arc<SharedState>, requester: &Connection, target: &str) -> Vec<String> {
        let out = RefCell::new(Vec::new());
        let send = |_s: &Arc<SharedState>, _sid: &str, line: String| {
            out.borrow_mut().push(line);
        };
        handle_whois(
            requester,
            target,
            state,
            "test-server",
            &requester.id,
            &send,
        );
        out.into_inner()
    }

    fn test_conn(id: &str, nick: &str) -> Connection {
        let mut c = Connection::new(id.to_string());
        c.nick = Some(nick.to_string());
        c.registered = true;
        c
    }

    #[test]
    fn whois_311_carries_the_cloaked_host_not_placeholders() {
        let state = crate::server::test_state();
        // Target: a DID-authenticated local user.
        state.nick_to_session.lock().insert("bob", "sess-bob");
        state
            .session_dids
            .lock()
            .insert("sess-bob".to_string(), "did:plc:bobbobbob123".to_string());

        let requester = test_conn("sess-alice", "alice");
        let lines = whois_lines(&state, &requester, "bob");
        let l311 = lines
            .iter()
            .find(|l| l.contains(" 311 "))
            .expect("311 present");
        assert!(
            l311.contains("freeq/plc/bobbobbo"),
            "311 must carry the DID-derived cloak, got: {l311}"
        );
        assert!(
            !l311.contains(" host "),
            "311 must not use the literal placeholder host: {l311}"
        );
    }

    #[test]
    fn whois_311_for_guests_shows_the_guest_cloak() {
        let state = crate::server::test_state();
        state.nick_to_session.lock().insert("guesty", "sess-g");

        let requester = test_conn("sess-alice", "alice");
        let lines = whois_lines(&state, &requester, "guesty");
        let l311 = lines
            .iter()
            .find(|l| l.contains(" 311 "))
            .expect("311 present");
        assert!(
            l311.contains("freeq/guest"),
            "guest 311 must carry the guest cloak, got: {l311}"
        );
    }

    #[test]
    fn remote_whois_realname_is_not_a_raw_did() {
        let state = crate::server::test_state();
        // A remote (S2S) member with a DID but no handle — the case that used
        // to put the raw DID into the realname, which clients rendered as the
        // user's display name.
        let mut ch = crate::server::ChannelState::default();
        ch.remote_members.insert(
            "fedbot".to_string(),
            crate::server::RemoteMember {
                origin: "remoteorigin1234".to_string(),
                did: Some("did:key:z6MkRemoteBot".to_string()),
                handle: None,
                is_op: false,
                actor_class: None,
            },
        );
        state.channels.lock().insert("#fed".to_string(), ch);

        let requester = test_conn("sess-alice", "alice");
        let lines = whois_lines(&state, &requester, "fedbot");
        let l311 = lines
            .iter()
            .find(|l| l.contains(" 311 "))
            .expect("311 present");
        assert!(
            !l311.contains("did:key:"),
            "realname must not be a raw DID, got: {l311}"
        );
        // The DID still travels in its own numeric (330), machine-readable.
        let l330 = lines
            .iter()
            .find(|l| l.contains(" 330 "))
            .expect("330 present");
        assert!(
            l330.contains("did:key:z6MkRemoteBot"),
            "330 carries the DID: {l330}"
        );
    }
}
