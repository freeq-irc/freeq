#![allow(clippy::too_many_arguments)]
//! Channel operations: join, part, mode, topic, kick, invite, names, list.

use super::Connection;
use super::helpers::{
    broadcast_to_channel, make_extended_join, make_extended_join_with_class, make_standard_join,
    s2s_broadcast, s2s_broadcast_mode, s2s_next_event_id,
};
use crate::irc::{self, Message};
use crate::server::SharedState;
use std::sync::Arc;

pub(super) fn handle_join(
    conn: &Connection,
    channel: &str,
    supplied_key: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick.as_deref().unwrap();
    let hostmask = conn.hostmask();
    let did = conn.authenticated_did.as_deref();

    // Reject excessively long channel names to prevent memory abuse.
    if channel.len() > 64 {
        let reply = Message::from_server(
            server_name,
            "479",
            vec![nick, channel, "Channel name too long (max 64 characters)"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Per-user channel limit to prevent memory exhaustion
    const MAX_CHANNELS_PER_USER: usize = 100;
    if !conn.is_oper {
        let channels = state.channels.lock();
        let current_count = channels
            .values()
            .filter(|ch| ch.members.contains(session_id))
            .count();
        if current_count >= MAX_CHANNELS_PER_USER {
            let reply = Message::from_server(
                server_name,
                irc::ERR_TOOMANYCHANNELS,
                vec![nick, channel, "You have joined too many channels"],
            );
            send(state, session_id, format!("{reply}\r\n"));
            return;
        }
    }

    // A channel is "new" only if it doesn't exist at all — not locally,
    // not via S2S. If remote members are present (from S2S sync), the
    // channel already exists on the federation and the joining user
    // should NOT get auto-ops (unless they have DID-based authority).
    let is_new_channel = {
        let channels = state.channels.lock();
        match channels.get(channel) {
            None => true,
            Some(ch) => {
                // Channel entry exists but has nobody and no persistent state —
                // treat as effectively new (e.g. leftover from cleanup)
                ch.members.is_empty()
                    && ch.remote_members.is_empty()
                    && ch.founder_did.is_none()
                    && ch.topic.is_none()
                    && ch.ops.is_empty()
            }
        }
    };

    if !is_new_channel {
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(channel) {
            // Already in channel — silently ignore (prevents double-join on reconnect)
            if ch.members.contains(session_id) {
                return;
            }
            // Founder + persistent DID-ops bypass admission gates (+k, +b, +i).
            // Standard IRC behavior: the channel's authority figures can always
            // rejoin their own channel. Without this bypass, a founder who sets
            // +i and then disconnects is locked out of their own channel.
            let is_did_authority =
                did.is_some_and(|d| ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d));
            // Check channel key (+k)
            if !is_did_authority
                && let Some(ref key) = ch.key
                && supplied_key != Some(key.as_str())
            {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_BADCHANNELKEY,
                    vec![nick, channel, "Cannot join channel (+k)"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }
            // Check bans
            if !is_did_authority && ch.is_banned(&hostmask, did) {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_BANNEDFROMCHAN,
                    vec![nick, channel, "Cannot join channel (+b)"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }
            // Check invite-only
            if !is_did_authority && ch.invite_only {
                let has_invite = ch.invites.contains(session_id)
                    || did.is_some_and(|d| ch.invites.contains(d))
                    || ch.invites.contains(&format!("nick:{nick}"));
                let on_invite_exception = ch.is_invite_excepted(&hostmask, did);
                if !has_invite && !on_invite_exception {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_INVITEONLYCHAN,
                        vec![nick, channel, "Cannot join channel (+i)"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                }
                // Consume the invite ONLY if that's how we got in (sticky +I
                // entries are persistent and must NOT be consumed).
                if has_invite {
                    drop(channels);
                    let mut channels = state.channels.lock();
                    if let Some(ch) = channels.get_mut(channel) {
                        ch.invites.remove(session_id);
                        if let Some(d) = did {
                            ch.invites.remove(d);
                        }
                        ch.invites.remove(&format!("nick:{nick}"));
                    }
                }
            }
        }
    }

    // ─── Policy check ─────────────────────────────────────────────────
    // If the channel has a policy, check if the user has a valid attestation.
    // Channels without policies are open (backwards compatible).
    // `policy_role` captures the attestation role for mode mapping after join.
    let mut policy_role: Option<String> = None;
    if let Some(ref engine) = state.policy_engine
        && let Ok(Some(_policy)) = engine.get_policy(channel)
    {
        // Channel has a policy — user must have a valid attestation
        match did {
            Some(user_did) => {
                // DID ops and founders bypass policy checks
                let is_did_op = {
                    let channels = state.channels.lock();
                    channels
                        .get(&channel.to_ascii_lowercase())
                        .is_some_and(|ch| {
                            ch.founder_did.as_deref() == Some(user_did)
                                || ch.did_ops.contains(user_did)
                        })
                };
                if is_did_op {
                    policy_role = Some("op".to_string());
                } else {
                    match engine.check_membership(channel, user_did) {
                        Ok(Some(attestation)) => {
                            // Valid attestation — allow join, capture role
                            policy_role = Some(attestation.role.clone());
                        }
                        Ok(None) => {
                            // No attestation — reject with informative message
                            let reply = Message::from_server(
                                server_name,
                                "477", // ERR_NEEDREGGEDNICK (repurposed: need policy acceptance)
                                vec![
                                    nick,
                                    channel,
                                    "This channel requires policy acceptance — use POLICY <channel> ACCEPT",
                                ],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(channel, did = user_did, error = %e, "Policy check failed");
                            // Fail-open on engine errors (don't break IRC)
                        }
                    }
                } // end else (non-DID-op)
            }
            None => {
                // Guest user (no DID) — check if policy allows unauthenticated join
                // For now, guests cannot join policy-gated channels
                let reply = Message::from_server(
                    server_name,
                    "477",
                    vec![
                        nick,
                        channel,
                        "This channel requires authentication — sign in to join",
                    ],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }
        }
    }

    {
        let mut channels = state.channels.lock();
        let ch = channels.entry(channel.to_string()).or_default();
        ch.members.insert(session_id.to_string());
        // NOTE: Presence is NOT in CRDT (avoids ghost users on crash).
        // It's tracked by S2S events + periodic resync only.

        if is_new_channel {
            // New channel: set founder if authenticated
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ch.created_at = now;
            if let Some(d) = did {
                ch.founder_did = Some(d.to_string());
                ch.did_ops.insert(d.to_string());
                // CRDT updates (async) — spawn to avoid blocking
                let state_c = Arc::clone(state);
                let channel_c = channel.to_string();
                let did_c = d.to_string();
                tokio::spawn(async move {
                    state_c.crdt_set_founder(&channel_c, &did_c).await;
                    state_c.crdt_grant_op(&channel_c, &did_c, None).await;
                });
            }
            ch.ops.insert(session_id.to_string());
            // Default channel modes: +nt (standard IRC behavior)
            // +n = no external messages (only members can send)
            // +t = only ops can change topic
            ch.no_ext_msg = true;
            ch.topic_locked = true;
            let ch_clone = ch.clone();
            drop(channels);
            state.with_db(|db| db.save_channel(channel, &ch_clone));
        } else {
            // Existing channel: auto-op if user's DID has persistent ops
            let should_op =
                did.is_some_and(|d| ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d));
            // Auto-op the first user to join a truly empty channel (e.g. after
            // server restart when the channel was loaded from DB with no members).
            // This prevents orphaned channels where nobody has ops.
            // BUT: if there are remote members (from S2S), the channel isn't
            // orphaned — someone else already has ops on another server.
            // AND: if the channel has a policy with role_requirements, the policy
            // governs who gets ops — don't hand out ops to random first joiners.
            let has_any_ops = !ch.ops.is_empty() || ch.remote_members.values().any(|rm| rm.is_op);
            let has_policy_roles = state.policy_engine.as_ref().is_some_and(|engine| {
                engine
                    .get_policy(channel)
                    .ok()
                    .flatten()
                    .is_some_and(|p| !p.role_requirements.is_empty())
            });
            let is_truly_empty = ch.members.len() == 1
                && ch.remote_members.is_empty()
                && !has_any_ops
                && !has_policy_roles;
            if should_op || is_truly_empty {
                ch.ops.insert(session_id.to_string());
            }
        }
    }

    // ─── Policy role → IRC mode mapping ────────────────────────────────
    // If user joined via policy and has an elevated role, grant IRC modes.
    if let Some(ref role) = policy_role {
        let mut channels = state.channels.lock();
        if let Some(ch) = channels.get_mut(channel) {
            match role.as_str() {
                "op" | "admin" | "owner" => {
                    ch.ops.insert(session_id.to_string());
                    if let Some(d) = did {
                        ch.did_ops.insert(d.to_string());
                    }
                }
                "moderator" | "halfop" => {
                    ch.halfops.insert(session_id.to_string());
                }
                "voice" | "voiced" | "speaker" => {
                    ch.voiced.insert(session_id.to_string());
                }
                _ => {} // "member" gets no special mode
            }
        }
    }

    // Plugin on_join hook
    state.plugin_manager.on_join(&crate::plugin::JoinEvent {
        nick: nick.to_string(),
        channel: channel.to_string(),
        did: did.map(|d| d.to_string()),
        session_id: session_id.to_string(),
        is_new_channel,
    });

    let std_join = make_standard_join(&hostmask, channel);
    let realname = conn.realname.as_deref().unwrap_or(nick);
    let ext_join = make_extended_join(&hostmask, channel, did, realname);
    let ext_join_class =
        make_extended_join_with_class(&hostmask, channel, did, realname, conn.actor_class);

    let members: Vec<String> = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();

    let ext_set = state.cap_extended_join.lock();
    let tag_set = state.cap_message_tags.lock();
    let conns = state.connections.lock();
    for member_session in &members {
        if let Some(tx) = conns.get(member_session) {
            let result = if ext_set.contains(member_session) {
                // Clients with message-tags get the actor class tag
                if tag_set.contains(member_session) {
                    tx.try_send(ext_join_class.clone())
                } else {
                    tx.try_send(ext_join.clone())
                }
            } else {
                tx.try_send(std_join.clone())
            };
            if let Err(e) = result {
                tracing::warn!(
                    channel = %channel,
                    session = %member_session,
                    nick = %nick,
                    error = %e,
                    "JOIN broadcast failed — client may have stale member list"
                );
            }
        } else {
            tracing::debug!(
                channel = %channel,
                session = %member_session,
                nick = %nick,
                "JOIN broadcast: session in ch.members but not in connections (ghost?)"
            );
        }
    }
    drop(conns);
    drop(tag_set);
    drop(ext_set);

    // Announce an auto-op/-halfop AFTER the JOIN, never before.
    //
    // A DID in the channel's persistent `did_ops` is re-opped as part of joining.
    // Sending that MODE before the JOIN meant members already in the channel got
    // an op change for a nick they did not yet know was present, and clients
    // rightly ignore modes for unknown members (otherwise a stray MODE invents
    // phantom members). The op was therefore dropped by everyone already sitting
    // in the channel, while anyone who connected later saw it correctly in their
    // NAMES reply — two clients disagreeing about who is an op.
    {
        let (is_op, is_halfop, is_voiced) = state
            .channels
            .lock()
            .get(channel)
            .map(|ch| {
                (
                    ch.ops.contains(session_id),
                    ch.halfops.contains(session_id),
                    ch.voiced.contains(session_id),
                )
            })
            .unwrap_or((false, false, false));
        let modes = auto_modes_for(is_op, is_halfop, is_voiced);
        if !modes.is_empty() {
            let members: Vec<String> = state
                .channels
                .lock()
                .get(channel)
                .map(|ch| ch.members.iter().cloned().collect())
                .unwrap_or_default();
            let conns = state.connections.lock();
            for mode in modes {
                let mode_msg = format!(":{server_name} MODE {channel} +{mode} {nick}\r\n");
                for member_session in &members {
                    if let Some(tx) = conns.get(member_session) {
                        let _ = tx.try_send(mode_msg.clone());
                    }
                }
            }
        }
    }

    // Broadcast JOIN to S2S peers
    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
    // Look up AT handle for the joining user
    let handle = state.session_handles.lock().get(session_id).cloned();
    let user_is_op = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.ops.contains(session_id))
        .unwrap_or(false);
    let actor_class = state
        .session_actor_class
        .lock()
        .get(session_id)
        .map(|c| c.to_string());
    s2s_broadcast(
        state,
        crate::s2s::S2sMessage::Join {
            event_id: s2s_next_event_id(state),
            nick: nick.to_string(),
            channel: channel.to_string(),
            did: did.map(|d| d.to_string()),
            handle,
            is_op: user_is_op,
            actor_class,
            origin: origin.clone(),
        },
    );

    // If this was a new channel creation, broadcast founder info
    if is_new_channel {
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(channel) {
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::ChannelCreated {
                    event_id: s2s_next_event_id(state),
                    channel: channel.to_string(),
                    founder_did: ch.founder_did.clone(),
                    did_ops: ch.did_ops.iter().cloned().collect(),
                    created_at: ch.created_at,
                    origin: origin.clone(),
                },
            );
        }
    }

    // Persist channel membership for auto-rejoin
    if let Some(did) = did {
        let did_owned = did.to_string();
        let channel_owned = channel.to_string();
        state.with_db(|db| db.add_user_channel(&did_owned, &channel_owned));
    }

    // Send topic if set (332 + 333)
    {
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(channel)
            && let Some(ref topic) = ch.topic
        {
            let rpl_topic = Message::from_server(
                server_name,
                irc::RPL_TOPIC,
                vec![nick, channel, &topic.text],
            );
            send(state, session_id, format!("{rpl_topic}\r\n"));

            let rpl_topicwhotime = Message::from_server(
                server_name,
                irc::RPL_TOPICWHOTIME,
                vec![nick, channel, &topic.set_by, &topic.set_at.to_string()],
            );
            send(state, session_id, format!("{rpl_topicwhotime}\r\n"));
        }
    }

    // Replay recent message history with server-time + batch when supported
    {
        let has_tags_cap = state.cap_message_tags.lock().contains(session_id);
        let has_time_cap = state.cap_server_time.lock().contains(session_id);
        let has_batch_cap = state.cap_batch.lock().contains(session_id);
        let has_multiline_cap = state.cap_draft_multiline.lock().contains(session_id);

        // Clone the history out so the DB call (reactions lookup) can
        // happen without holding the channels lock — and so the per-row
        // emit loop below isn't holding the lock either.
        let history: Vec<crate::server::HistoryMessage> = {
            let channels = state.channels.lock();
            channels
                .get(channel)
                .map(|ch| ch.history.iter().cloned().collect())
                .unwrap_or_default()
        };

        // The channel's task events, for a joiner that asked for them: the
        // newest MAX_HISTORY, the same cap the messages get. Fetched on their
        // own terms, not within the span of the message buffer — a task
        // posted after the last chat line, or into a room nobody has chatted
        // in, replays too.
        let batch_id = format!("hist{}", crate::msgid::generate());
        let mut act_lines = super::act::replay_lines(
            state,
            session_id,
            &crate::events::venue_of(channel),
            channel,
            0,
            i64::MAX,
            crate::server::MAX_HISTORY,
            has_time_cap,
            has_batch_cap.then_some(batch_id.as_str()),
        );
        act_lines.reverse();

        if !history.is_empty() || !act_lines.is_empty() {
            // Fetch persisted reactions for this batch so they ride on
            // the replayed messages — mirrors the explicit CHATHISTORY
            // emission path (messaging.rs). Without this, joiners see
            // history with no reaction chips until a live TAGMSG
            // arrives.
            let msgids: Vec<&str> = history.iter().filter_map(|h| h.msgid.as_deref()).collect();
            let reactions: std::collections::HashMap<String, Vec<crate::db::ReactionRow>> =
                if has_tags_cap && !msgids.is_empty() {
                    state
                        .with_db(|db| db.get_reactions_for_messages(&msgids))
                        .unwrap_or_default()
                } else {
                    std::collections::HashMap::new()
                };

            // Start batch if client supports it
            if has_batch_cap {
                let batch_start =
                    format!(":{server_name} BATCH +{batch_id} chathistory {channel}\r\n");
                send(state, session_id, batch_start);
            }

            // Messages and task events interleave in time order: each task
            // event goes out before the first message that landed after it.

            for hist in &history {
                while act_lines
                    .last()
                    .is_some_and(|(ts, _)| *ts <= hist.timestamp as i64)
                {
                    let (_, line) = act_lines.pop().expect("just checked");
                    send(state, session_id, line);
                }
                let mut msg_tags = if has_tags_cap {
                    hist.tags.clone()
                } else {
                    std::collections::HashMap::new()
                };

                // Replay carries one entry per logical message, so an edited
                // message arrives as its current text with no `+draft/edit` to
                // hint at the revision — this is what lets a late joiner render
                // "(edited)".
                if has_tags_cap && hist.edited {
                    msg_tags.insert("+freeq.at/edited".to_string(), "1".to_string());
                }

                // Add msgid tag if available
                if has_tags_cap && let Some(ref mid) = hist.msgid {
                    msg_tags.insert("msgid".to_string(), mid.clone());
                    // Include persisted reactions as `+freeq.at/reactions`
                    // (format: `emoji1:nick1,nick2;emoji2:nick3`).
                    if let Some(reaction_rows) = reactions.get(mid) {
                        let mut by_emoji: std::collections::HashMap<&str, Vec<&str>> =
                            std::collections::HashMap::new();
                        for r in reaction_rows {
                            by_emoji.entry(&r.emoji).or_default().push(&r.reactor_nick);
                        }
                        if !by_emoji.is_empty() {
                            let encoded: Vec<String> = by_emoji
                                .iter()
                                .map(|(emoji, nicks)| format!("{}:{}", emoji, nicks.join(",")))
                                .collect();
                            msg_tags.insert("+freeq.at/reactions".to_string(), encoded.join(";"));
                        }
                    }
                }

                // Add server-time tag
                if has_time_cap {
                    let ts = chrono::DateTime::from_timestamp(hist.timestamp as i64, 0)
                        .unwrap_or_default()
                        .format("%Y-%m-%dT%H:%M:%S.000Z")
                        .to_string();
                    msg_tags.insert("time".to_string(), ts);
                }

                // Add batch tag
                if has_batch_cap {
                    msg_tags.insert("batch".to_string(), batch_id.clone());
                }

                // Multi-line stored bodies: emitting `\n` raw in a
                // PRIVMSG terminates the IRC line mid-text. Mirror the
                // explicit CHATHISTORY emission path — nested
                // `draft/multiline` BATCH for capable receivers, split
                // PRIVMSGs otherwise.
                let bodies: Vec<&str> = hist.text.split('\n').collect();
                let is_multiline = bodies.len() > 1;
                if is_multiline && has_multiline_cap && has_batch_cap {
                    let ml_id = format!("ml{}", crate::msgid::generate());
                    let opener = irc::Message {
                        tags: msg_tags.clone(),
                        prefix: Some(hist.from.clone()),
                        command: "BATCH".to_string(),
                        params: vec![
                            format!("+{ml_id}"),
                            "draft/multiline".to_string(),
                            channel.to_string(),
                        ],
                    };
                    send(state, session_id, format!("{opener}\r\n"));
                    for body in &bodies {
                        let mut chunk_tags = std::collections::HashMap::new();
                        chunk_tags.insert("batch".to_string(), ml_id.clone());
                        let chunk = irc::Message {
                            tags: chunk_tags,
                            prefix: Some(hist.from.clone()),
                            command: "PRIVMSG".to_string(),
                            params: vec![channel.to_string(), body.to_string()],
                        };
                        send(state, session_id, format!("{chunk}\r\n"));
                    }
                    let mut closer_tags = std::collections::HashMap::new();
                    if let Some(b) = msg_tags.get("batch") {
                        closer_tags.insert("batch".to_string(), b.clone());
                    }
                    let closer = irc::Message {
                        tags: closer_tags,
                        prefix: None,
                        command: "BATCH".to_string(),
                        params: vec![format!("-{ml_id}")],
                    };
                    send(state, session_id, format!("{closer}\r\n"));
                    continue;
                }
                if is_multiline {
                    // Fallback: split at \n into N PRIVMSGs. msgid +
                    // client tags ride on the first chunk; later chunks
                    // carry only the chathistory batch tag so they stay
                    // grouped under the same replay unit.
                    for (i, body) in bodies.iter().enumerate() {
                        let chunk_tags = if i == 0 {
                            msg_tags.clone()
                        } else {
                            let mut t = std::collections::HashMap::new();
                            if has_batch_cap {
                                t.insert("batch".to_string(), batch_id.clone());
                            }
                            t
                        };
                        if !chunk_tags.is_empty() && has_tags_cap {
                            let chunk = irc::Message {
                                tags: chunk_tags,
                                prefix: Some(hist.from.clone()),
                                command: "PRIVMSG".to_string(),
                                params: vec![channel.to_string(), body.to_string()],
                            };
                            send(state, session_id, format!("{chunk}\r\n"));
                        } else {
                            let line = format!(":{} PRIVMSG {} :{}\r\n", hist.from, channel, body);
                            send(state, session_id, line);
                        }
                    }
                    continue;
                }

                if !msg_tags.is_empty() && has_tags_cap {
                    let tag_msg = irc::Message {
                        tags: msg_tags,
                        prefix: Some(hist.from.clone()),
                        command: "PRIVMSG".to_string(),
                        params: vec![channel.to_string(), hist.text.clone()],
                    };
                    send(state, session_id, format!("{tag_msg}\r\n"));
                } else {
                    let line = format!(":{} PRIVMSG {} :{}\r\n", hist.from, channel, hist.text);
                    send(state, session_id, line);
                }
            }

            // Whatever happened after the last message — sent whether or not
            // this client batches, since the events are the point and the
            // batch is only how they are framed.
            while let Some((_, line)) = act_lines.pop() {
                send(state, session_id, line);
            }

            // End batch
            if has_batch_cap {
                let batch_end = format!(":{server_name} BATCH -{batch_id}\r\n");
                send(state, session_id, batch_end);
            }
        }
    }

    let nick_list: Vec<String> = {
        let channels = state.channels.lock();
        let (member_sessions, remote_members, ops, voiced) = match channels.get(channel) {
            Some(ch) => (
                ch.members.clone(),
                ch.remote_members.clone(),
                ch.ops.clone(),
                ch.voiced.clone(),
            ),
            None => Default::default(),
        };
        drop(channels);
        // Local members: look up nick from session ID (deduplicated for multi-device)
        let nicks = state.nick_to_session.lock();
        let mut seen_nicks = std::collections::HashSet::new();
        let member_count = member_sessions.len();
        let mut list: Vec<String> = member_sessions
            .iter()
            .filter_map(|s| {
                let nick_result = nicks.get_nick(s);
                if nick_result.is_none() {
                    tracing::warn!(
                        channel = %channel,
                        session = %s,
                        "NAMES: session in ch.members but not in nick_to_session"
                    );
                }
                nick_result.and_then(|n| {
                    let nick_lower = n.to_lowercase();
                    if !seen_nicks.insert(nick_lower) {
                        return None;
                    }
                    let prefix = if ops.contains(s) {
                        "@"
                    } else if voiced.contains(s) {
                        "+"
                    } else {
                        ""
                    };
                    Some(format!("{prefix}{n}"))
                })
            })
            .collect();
        if list.is_empty() && member_count > 0 {
            tracing::warn!(
                channel = %channel,
                member_count = member_count,
                "NAMES: all members resolved to empty list!"
            );
        }
        // Release `nick_to_session` before touching `channels` again.
        //
        // LOCK ORDER: this held nick_to_session and then took channels, while
        // WHO (queries.rs) takes channels and then nick_to_session. That is an
        // AB/BA deadlock, and a JOIN racing a WHO wedged both. It does not look
        // like a hang from the client's side: the server has already inserted
        // the member and broadcast the JOIN, so messages keep arriving — only
        // the 353/366 never come, leaving a channel you are demonstrably in with
        // an empty member list.
        drop(nicks);

        // Remote members from S2S peers (with @ prefix if op on home server or DID-based)
        let channels_lock = state.channels.lock();
        let ch_state = channels_lock.get(channel);
        for (nick, rm) in &remote_members {
            let is_op = rm.is_op
                || rm.did.as_ref().is_some_and(|d| {
                    ch_state.is_some_and(|ch| {
                        ch.founder_did.as_deref() == Some(d.as_str()) || ch.did_ops.contains(d)
                    })
                });
            let prefix = if is_op { "@" } else { "" };
            list.push(format!("{prefix}{nick}"));
        }
        drop(channels_lock);
        list
    };

    let names = Message::from_server(
        server_name,
        irc::RPL_NAMREPLY,
        vec![nick, "=", channel, &nick_list.join(" ")],
    );
    let end_names = Message::from_server(
        server_name,
        irc::RPL_ENDOFNAMES,
        vec![nick, channel, "End of /NAMES list"],
    );
    send(state, session_id, format!("{names}\r\n"));
    send(state, session_id, format!("{end_names}\r\n"));

    // Notify joining client about active AV session in this channel (if any)
    {
        let mgr = state.av_sessions.lock();
        if let Some(av_session) = mgr.active_session_for_channel(channel) {
            let participant_count = av_session
                .participants
                .values()
                .filter(|p| p.left_at.is_none())
                .count();
            let title = av_session.title.as_deref().unwrap_or("");
            let mut tags = std::collections::HashMap::new();
            tags.insert("+freeq.at/av-state".to_string(), "started".to_string());
            tags.insert("+freeq.at/av-id".to_string(), av_session.id.clone());
            tags.insert(
                "+freeq.at/av-participants".to_string(),
                participant_count.to_string(),
            );
            tags.insert(
                "+freeq.at/av-actor".to_string(),
                av_session.created_by_nick.clone(),
            );
            if !title.is_empty() {
                tags.insert("+freeq.at/av-title".to_string(), title.to_string());
            }
            let time_tag = chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S.000Z")
                .to_string();
            tags.insert("time".to_string(), time_tag);
            let tag_msg = irc::Message {
                tags,
                prefix: Some(server_name.to_string()),
                command: "TAGMSG".to_string(),
                params: vec![channel.to_string()],
            };
            // Only send if client supports message-tags
            if state.cap_message_tags.lock().contains(session_id) {
                send(state, session_id, format!("{tag_msg}\r\n"));
            } else {
                // Fallback: human-readable notice
                let notice_text = format!(
                    "Active voice session ({} participants) — use /av to join",
                    participant_count
                );
                let notice =
                    Message::from_server(server_name, "NOTICE", vec![channel, &notice_text]);
                send(state, session_id, format!("{notice}\r\n"));
            }
        }
    }
}

pub(super) fn handle_mode(
    conn: &Connection,
    channel: &str,
    mode_str: Option<&str>,
    mode_arg: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify user is in the channel
    let in_channel = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.contains(session_id))
        .unwrap_or(false);

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let Some(mode_str) = mode_str else {
        // Query channel modes
        let channels = state.channels.lock();
        let modes = if let Some(ch) = channels.get(channel) {
            let mut m = String::from("+");
            if ch.no_ext_msg {
                m.push('n');
            }
            if ch.topic_locked {
                m.push('t');
            }
            if ch.invite_only {
                m.push('i');
            }
            if ch.moderated {
                m.push('m');
            }
            if ch.encrypted_only {
                m.push('E');
            }
            if ch.key.is_some() {
                m.push('k');
            }
            m
        } else {
            "+".to_string()
        };
        let reply = Message::from_server(
            server_name,
            irc::RPL_CHANNELMODEIS,
            vec![nick, channel, &modes],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    };

    // Check privileges: ops can do anything, halfops can set +v only
    let (is_op, is_halfop) = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| (ch.ops.contains(session_id), ch.halfops.contains(session_id)))
        .unwrap_or((false, false));

    // Server operators (OPER) can always change modes
    let is_server_oper = state.server_opers.lock().contains(session_id);
    if !is_op && !is_halfop && !is_server_oper {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Halfops can only set +v/-v — not +o, +h, +m, +t, +i, +k, +n
    if is_halfop && !is_op && !is_server_oper {
        let has_restricted = mode_str
            .chars()
            .any(|c| matches!(c, 'o' | 'h' | 'm' | 't' | 'i' | 'k' | 'n' | 'E'));
        if has_restricted {
            let reply = Message::from_server(
                server_name,
                irc::ERR_CHANOPRIVSNEEDED,
                vec![nick, channel, "Moderators can only set +v/-v"],
            );
            send(state, session_id, format!("{reply}\r\n"));
            return;
        }
    }

    // Parse mode string: +o, -o, +v, -v, +t, -t
    let mut adding = true;
    for ch in mode_str.chars() {
        match ch {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'h' | 'v' => {
                let Some(target_nick) = mode_arg else {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![nick, "MODE", "Not enough parameters"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                };

                // Resolve target via federated channel roster (local + remote)
                use super::helpers::{ChannelTarget, resolve_channel_target};
                match resolve_channel_target(state, channel, target_nick) {
                    ChannelTarget::Local {
                        session_id: target_session,
                    } => {
                        // Apply the mode locally
                        {
                            let mut channels = state.channels.lock();
                            if let Some(chan) = channels.get_mut(channel) {
                                let set = match ch {
                                    'o' => &mut chan.ops,
                                    'h' => &mut chan.halfops,
                                    _ => &mut chan.voiced,
                                };
                                if adding {
                                    set.insert(target_session.clone());
                                } else {
                                    set.remove(&target_session);
                                }

                                // DID-based persistent ops: +o/-o on an authenticated
                                // user also updates did_ops, so ops survive reconnects
                                // and work across S2S servers.
                                if ch == 'o' {
                                    let target_did =
                                        state.session_dids.lock().get(&target_session).cloned();
                                    if let Some(did) = target_did {
                                        // Don't allow de-opping the founder
                                        if !adding && chan.founder_did.as_deref() == Some(&did) {
                                            // Silently ignore — founder can't be de-opped
                                        } else if adding {
                                            chan.did_ops.insert(did.clone());
                                            // CRDT grant so it propagates across federation
                                            let granter_did =
                                                state.session_dids.lock().get(session_id).cloned();
                                            let state_clone = Arc::clone(state);
                                            let channel_name = channel.to_string();
                                            tokio::spawn(async move {
                                                state_clone
                                                    .crdt_grant_op(
                                                        &channel_name,
                                                        &did,
                                                        granter_did.as_deref(),
                                                    )
                                                    .await;
                                                state_clone.crdt_broadcast_sync().await;
                                            });
                                        } else {
                                            chan.did_ops.remove(&did);
                                            let state_clone = Arc::clone(state);
                                            let channel_name = channel.to_string();
                                            let did_clone = did.clone();
                                            tokio::spawn(async move {
                                                state_clone
                                                    .crdt_revoke_op(&channel_name, &did_clone)
                                                    .await;
                                                state_clone.crdt_broadcast_sync().await;
                                            });
                                        }
                                        // Persist the updated DID ops
                                        let ch_clone = chan.clone();
                                        let channel_name = channel.to_string();
                                        drop(channels);
                                        state.with_db(|db| {
                                            db.save_channel(&channel_name, &ch_clone)
                                        });
                                    }
                                }
                            }
                        }

                        // Broadcast mode change to local channel + S2S
                        let sign = if adding { "+" } else { "-" };
                        let hostmask = conn.hostmask();
                        let mode_msg =
                            format!(":{hostmask} MODE {channel} {sign}{ch} {target_nick}\r\n");
                        broadcast_to_channel(state, channel, &mode_msg);
                        s2s_broadcast_mode(
                            state,
                            conn,
                            channel,
                            &format!("{sign}{ch}"),
                            Some(target_nick),
                        );
                    }

                    ChannelTarget::Remote(rm) => {
                        // Apply ephemeral op/voice on the remote member locally
                        {
                            let mut channels = state.channels.lock();
                            if let Some(chan) = channels.get_mut(channel)
                                && ch == 'o'
                                && let Some(remote) = chan.remote_members.get_mut(target_nick)
                            {
                                remote.is_op = adding;
                            }
                            // +v: no is_voiced on RemoteMember, but we still
                            // broadcast the mode so the remote server can apply it.
                        }

                        // If the user has a DID, also update did_ops for persistence + CRDT
                        if ch == 'o'
                            && let Some(ref did) = rm.did
                        {
                            {
                                let mut channels = state.channels.lock();
                                if let Some(chan) = channels.get_mut(channel) {
                                    if !adding && chan.founder_did.as_deref() == Some(did.as_str())
                                    {
                                        // Founder can't be de-opped
                                    } else if adding {
                                        chan.did_ops.insert(did.clone());
                                    } else {
                                        chan.did_ops.remove(did);
                                    }
                                    let ch_clone = chan.clone();
                                    let channel_name = channel.to_string();
                                    drop(channels);
                                    state.with_db(|db| db.save_channel(&channel_name, &ch_clone));
                                }
                            }

                            // CRDT propagation (persistent)
                            let granter_did = state.session_dids.lock().get(session_id).cloned();
                            let state_clone = Arc::clone(state);
                            let channel_name = channel.to_string();
                            let did_clone = did.clone();
                            tokio::spawn(async move {
                                if adding {
                                    state_clone
                                        .crdt_grant_op(
                                            &channel_name,
                                            &did_clone,
                                            granter_did.as_deref(),
                                        )
                                        .await;
                                } else {
                                    state_clone.crdt_revoke_op(&channel_name, &did_clone).await;
                                }
                                state_clone.crdt_broadcast_sync().await;
                            });
                        }
                        // Guest without DID: ephemeral op still applied above
                        // (is_op flag on remote_members). Won't survive reconnect
                        // but works for the session — same as regular IRC.

                        // Broadcast mode change to local channel + S2S
                        let sign = if adding { "+" } else { "-" };
                        let hostmask = conn.hostmask();
                        let mode_msg =
                            format!(":{hostmask} MODE {channel} {sign}{ch} {target_nick}\r\n");
                        broadcast_to_channel(state, channel, &mode_msg);
                        s2s_broadcast_mode(
                            state,
                            conn,
                            channel,
                            &format!("{sign}{ch}"),
                            Some(target_nick),
                        );
                    }

                    ChannelTarget::NotPresent => {
                        let reply = Message::from_server(
                            server_name,
                            irc::ERR_USERNOTINCHANNEL,
                            vec![nick, target_nick, channel, "They aren't on that channel"],
                        );
                        send(state, session_id, format!("{reply}\r\n"));
                        return;
                    }
                }
            }
            'b' => {
                use crate::server::BanEntry;

                if !adding && mode_arg.is_none() {
                    // -b with no arg is invalid, ignore
                    return;
                }

                if adding && mode_arg.is_none() {
                    // +b with no arg: list bans
                    let channels = state.channels.lock();
                    if let Some(chan) = channels.get(channel) {
                        for ban in &chan.bans {
                            let reply = Message::from_server(
                                server_name,
                                irc::RPL_BANLIST,
                                vec![
                                    nick,
                                    channel,
                                    &ban.mask,
                                    &ban.set_by,
                                    &ban.set_at.to_string(),
                                ],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                        }
                    }
                    let end = Message::from_server(
                        server_name,
                        irc::RPL_ENDOFBANLIST,
                        vec![nick, channel, "End of channel ban list"],
                    );
                    send(state, session_id, format!("{end}\r\n"));
                    return;
                }

                let mask = mode_arg.unwrap().trim();
                if mask.is_empty() {
                    return; // Reject empty/whitespace-only ban masks
                }
                if adding {
                    let entry = BanEntry::new(mask.to_string(), conn.hostmask());
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        // Per-channel ban limit to prevent resource exhaustion
                        const MAX_BANS_PER_CHANNEL: usize = 500;
                        if chan.bans.len() >= MAX_BANS_PER_CHANNEL {
                            drop(channels);
                            let reply = Message::from_server(
                                server_name,
                                "478",
                                vec![nick, channel, "Channel ban list is full"],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                            return;
                        }
                        // Don't duplicate
                        if !chan.bans.iter().any(|b| b.mask == mask) {
                            chan.bans.push(entry.clone());
                            drop(channels);
                            state.with_db(|db| db.add_ban(channel, &entry));
                        }
                    }
                } else {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.bans.retain(|b| b.mask != mask);
                    }
                    drop(channels);
                    state.with_db(|db| db.remove_ban(channel, mask));
                }

                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}b {mask}\r\n");
                broadcast_to_channel(state, channel, &mode_msg);

                // S2S: propagate ban to peers
                {
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::Ban {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            mask: mask.to_string(),
                            set_by: nick.to_string(),
                            adding,
                            origin,
                        },
                    );
                }
            }
            'I' => {
                use crate::server::InviteExceptionEntry;

                if !adding && mode_arg.is_none() {
                    // -I with no arg is invalid, ignore
                    return;
                }

                if adding && mode_arg.is_none() {
                    // +I with no arg: list invite exceptions
                    let channels = state.channels.lock();
                    if let Some(chan) = channels.get(channel) {
                        for entry in &chan.invite_exceptions {
                            let reply = Message::from_server(
                                server_name,
                                irc::RPL_INVITELIST,
                                vec![
                                    nick,
                                    channel,
                                    &entry.mask,
                                    &entry.set_by,
                                    &entry.set_at.to_string(),
                                ],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                        }
                    }
                    let end = Message::from_server(
                        server_name,
                        irc::RPL_ENDOFINVITELIST,
                        vec![nick, channel, "End of channel invite list"],
                    );
                    send(state, session_id, format!("{end}\r\n"));
                    return;
                }

                let mask = mode_arg.unwrap().trim();
                if mask.is_empty() {
                    return;
                }
                if adding {
                    let entry = InviteExceptionEntry::new(mask.to_string(), conn.hostmask());
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        const MAX_INVITE_EXCEPTIONS_PER_CHANNEL: usize = 500;
                        if chan.invite_exceptions.len() >= MAX_INVITE_EXCEPTIONS_PER_CHANNEL {
                            drop(channels);
                            let reply = Message::from_server(
                                server_name,
                                "478",
                                vec![nick, channel, "Channel invite-exception list is full"],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                            return;
                        }
                        if !chan.invite_exceptions.iter().any(|e| e.mask == mask) {
                            chan.invite_exceptions.push(entry.clone());
                            drop(channels);
                            state.with_db(|db| db.add_invite_exception(channel, &entry));
                        }
                    }
                } else {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.invite_exceptions.retain(|e| e.mask != mask);
                    }
                    drop(channels);
                    state.with_db(|db| db.remove_invite_exception(channel, mask));
                }

                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}I {mask}\r\n");
                broadcast_to_channel(state, channel, &mode_msg);

                // S2S: propagate the invite-exception change to peers
                {
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::InviteException {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            mask: mask.to_string(),
                            set_by: nick.to_string(),
                            adding,
                            origin,
                        },
                    );
                }
            }
            'i' => {
                {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.invite_only = adding;
                        if !adding {
                            chan.invites.clear();
                        }
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}i\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
                s2s_broadcast_mode(state, conn, channel, &format!("{sign}i"), None);
            }
            't' => {
                {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.topic_locked = adding;
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}t\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
                s2s_broadcast_mode(state, conn, channel, &format!("{sign}t"), None);
            }
            'k' => {
                if adding {
                    let Some(key) = mode_arg else {
                        let reply = Message::from_server(
                            server_name,
                            irc::ERR_NEEDMOREPARAMS,
                            vec![nick, "MODE", "Not enough parameters"],
                        );
                        send(state, session_id, format!("{reply}\r\n"));
                        return;
                    };
                    {
                        let mut channels = state.channels.lock();
                        if let Some(chan) = channels.get_mut(channel) {
                            chan.key = Some(key.to_string());
                            let ch_clone = chan.clone();
                            drop(channels);
                            state.with_db(|db| db.save_channel(channel, &ch_clone));
                        }
                    }
                    let hostmask = conn.hostmask();
                    let mode_msg = format!(":{hostmask} MODE {channel} +k {key}\r\n");
                    broadcast_to_channel(state, channel, &mode_msg);
                    s2s_broadcast_mode(state, conn, channel, "+k", Some(key));
                } else {
                    let old_key = {
                        let mut channels = state.channels.lock();
                        if let Some(chan) = channels.get_mut(channel) {
                            let k = chan.key.take();
                            let ch_clone = chan.clone();
                            drop(channels);
                            state.with_db(|db| db.save_channel(channel, &ch_clone));
                            k
                        } else {
                            None
                        }
                    };
                    if let Some(key) = old_key {
                        let hostmask = conn.hostmask();
                        let mode_msg = format!(":{hostmask} MODE {channel} -k {key}\r\n");
                        broadcast_to_channel(state, channel, &mode_msg);
                        s2s_broadcast_mode(state, conn, channel, "-k", Some(&key));
                    }
                }
            }
            'n' => {
                {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.no_ext_msg = adding;
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}n\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
                s2s_broadcast_mode(state, conn, channel, &format!("{sign}n"), None);
            }
            'm' => {
                {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.moderated = adding;
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}m\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
                s2s_broadcast_mode(state, conn, channel, &format!("{sign}m"), None);
            }
            'E' => {
                {
                    let mut channels = state.channels.lock();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.encrypted_only = adding;
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}E\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
                s2s_broadcast_mode(state, conn, channel, &format!("{sign}E"), None);
            }
            _ => {
                let mode_char = ch.to_string();
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_UNKNOWNMODE,
                    vec![nick, &mode_char, "is unknown mode char to me"],
                );
                send(state, session_id, format!("{reply}\r\n"));
            }
        }
    }
}

pub(super) fn handle_kick(
    conn: &Connection,
    channel: &str,
    target_nick: &str,
    reason: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify kicker is in the channel and is an op or halfop
    let (in_channel, is_op, is_halfop) = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| {
            (
                ch.members.contains(session_id),
                ch.ops.contains(session_id),
                ch.halfops.contains(session_id),
            )
        })
        .unwrap_or((false, false, false));

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let is_server_oper = state.server_opers.lock().contains(session_id);
    if !is_op && !is_halfop && !is_server_oper {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Halfops cannot kick ops or other halfops
    if is_halfop && !is_op && !is_server_oper {
        let target_is_protected = state
            .channels
            .lock()
            .get(channel)
            .map(|ch| {
                // Find target session ID
                let n2s = state.nick_to_session.lock();
                n2s.get_session(target_nick)
                    .map(|sid| ch.ops.contains(sid) || ch.halfops.contains(sid))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if target_is_protected {
            let reply = Message::from_server(
                server_name,
                irc::ERR_CHANOPRIVSNEEDED,
                vec![nick, channel, "Cannot kick a channel operator or moderator"],
            );
            send(state, session_id, format!("{reply}\r\n"));
            return;
        }
    }

    // Resolve target via federated channel roster
    use super::helpers::{ChannelTarget, resolve_channel_target};
    match resolve_channel_target(state, channel, target_nick) {
        ChannelTarget::Local {
            session_id: target_session,
        } => {
            // Broadcast KICK, then remove from channel
            let hostmask = conn.hostmask();
            let kick_msg = format!(":{hostmask} KICK {channel} {target_nick} :{reason}\r\n");
            broadcast_to_channel(state, channel, &kick_msg);

            // Remove target from channel
            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(channel) {
                    ch.members.remove(&target_session);
                    ch.ops.remove(&target_session);
                    ch.voiced.remove(&target_session);
                    ch.halfops.remove(&target_session);
                }
            }

            // Clear the victim's auto-rejoin entry — same per-DID rule as
            // PART. Otherwise the kicked user reconnects and the server
            // silently puts them right back in the channel they were
            // kicked from. Skip the clear if another session for that DID
            // is still a member (multi-device: only this device was kicked).
            let victim_did = state.session_dids.lock().get(&target_session).cloned();
            if let Some(did) = victim_did {
                let other_session_still_member = {
                    let did_sessions = state.did_sessions.lock();
                    let channels = state.channels.lock();
                    match (did_sessions.get(&did), channels.get(channel)) {
                        (Some(sessions), Some(ch)) => sessions
                            .iter()
                            .any(|sid| sid != &target_session && ch.members.contains(sid)),
                        _ => false,
                    }
                };
                if !other_session_still_member {
                    let did_owned = did.clone();
                    let channel_owned = channel.to_string();
                    state.with_db(|db| db.remove_user_channel(&did_owned, &channel_owned));
                }
            }
        }

        ChannelTarget::Remote(_rm) => {
            // Broadcast KICK locally so local users see it
            let hostmask = conn.hostmask();
            let kick_msg = format!(":{hostmask} KICK {channel} {target_nick} :{reason}\r\n");
            broadcast_to_channel(state, channel, &kick_msg);

            // Remove from our remote_members tracking (case-insensitive)
            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(channel) {
                    ch.remove_remote_member(target_nick);
                }
            }

            // Relay as a proper S2S Kick so remote server can enforce it
            // (carries kick reason, kicker identity — not a generic Part)
            let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::Kick {
                    event_id: s2s_next_event_id(state),
                    nick: target_nick.to_string(),
                    channel: channel.to_string(),
                    by: conn.nick.as_deref().unwrap_or("*").to_string(),
                    reason: reason.to_string(),
                    origin,
                },
            );
        }

        ChannelTarget::NotPresent => {
            let reply = Message::from_server(
                server_name,
                irc::ERR_USERNOTINCHANNEL,
                vec![nick, target_nick, channel, "They aren't on that channel"],
            );
            send(state, session_id, format!("{reply}\r\n"));
        }
    }
}

/// Handle INVITE command.
pub(super) fn handle_invite(
    conn: &Connection,
    target_nick: &str,
    channel: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify inviter is in the channel and is an op
    let (in_channel, is_op, is_invite_only) = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| {
            (
                ch.members.contains(session_id),
                ch.ops.contains(session_id),
                ch.invite_only,
            )
        })
        .unwrap_or((false, false, false));

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // If channel is +i, only ops can invite
    let is_server_oper = state.server_opers.lock().contains(session_id);
    if is_invite_only && !is_op && !is_server_oper {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Resolve target via federated network roster.
    // INVITE doesn't require the target to be in the channel — they just
    // need to exist somewhere (locally or as a known remote user).
    use super::helpers::{NetworkTarget, resolve_network_target};
    match resolve_network_target(state, target_nick) {
        NetworkTarget::Local {
            session_id: target_sid,
        } => {
            // Add invite by session ID + DID (with limit)
            let s2s_invitee = {
                let mut channels = state.channels.lock();
                let did = state.session_dids.lock().get(&target_sid).cloned();
                if let Some(ch) = channels.get_mut(channel) {
                    const MAX_INVITES: usize = 500;
                    if ch.invites.len() < MAX_INVITES {
                        ch.invites.insert(target_sid.clone());
                        if let Some(ref d) = did {
                            ch.invites.insert(d.clone());
                        }
                    }
                }
                // For S2S, prefer DID over nick-based token
                did.unwrap_or_else(|| format!("nick:{target_nick}"))
            };

            // Notify inviter
            let reply = Message::from_server(server_name, "341", vec![nick, target_nick, channel]);
            send(state, session_id, format!("{reply}\r\n"));

            // Notify target
            let hostmask = conn.hostmask();
            let invite_msg = format!(":{hostmask} INVITE {target_nick} {channel}\r\n");
            if let Some(tx) = state.connections.lock().get(&target_sid) {
                let _ = tx.try_send(invite_msg);
            }

            // Broadcast invite to S2S peers
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::Invite {
                    event_id: s2s_next_event_id(state),
                    channel: channel.to_string(),
                    invitee: s2s_invitee,
                    invited_by: nick.to_string(),
                    origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                },
            );
        }

        NetworkTarget::Remote(rm) => {
            // Add invite by DID if available (so it survives reconnect/rejoin)
            let s2s_invitee = {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(channel) {
                    if let Some(ref did) = rm.did {
                        ch.invites.insert(did.clone());
                    }
                    ch.invites.insert(format!("nick:{target_nick}"));
                }
                rm.did
                    .clone()
                    .unwrap_or_else(|| format!("nick:{target_nick}"))
            };

            // Notify inviter (remote target can't be notified directly)
            let reply = Message::from_server(server_name, "341", vec![nick, target_nick, channel]);
            send(state, session_id, format!("{reply}\r\n"));

            // Broadcast invite to S2S peers
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::Invite {
                    event_id: s2s_next_event_id(state),
                    channel: channel.to_string(),
                    invitee: s2s_invitee,
                    invited_by: nick.to_string(),
                    origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                },
            );
        }

        NetworkTarget::Unknown => {
            let reply = Message::from_server(
                server_name,
                irc::ERR_NOSUCHNICK,
                vec![nick, target_nick, "No such nick"],
            );
            send(state, session_id, format!("{reply}\r\n"));
        }
    }
}

/// Handle TOPIC command.
pub(super) fn handle_topic(
    conn: &Connection,
    channel: &str,
    new_topic: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    use crate::server::TopicInfo;

    let nick = conn.nick_or_star();

    // Verify user is in the channel
    let in_channel = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.contains(session_id))
        .unwrap_or(false);

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    match new_topic {
        Some(text) => {
            // Enforce topic length limit to prevent memory abuse.
            if text.len() > 512 {
                let reply = Message::from_server(
                    server_name,
                    "FAIL",
                    vec!["TOPIC", "TOO_LONG", "Topic too long (max 512 characters)"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }
            // Check +t: if topic_locked, only ops can set topic
            let (is_op, is_locked) = {
                let channels = state.channels.lock();
                channels
                    .get(channel)
                    .map(|ch| (ch.ops.contains(session_id), ch.topic_locked))
                    .unwrap_or((false, false))
            };
            let is_server_oper = state.server_opers.lock().contains(session_id);
            if is_locked && !is_op && !is_server_oper {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_CHANOPRIVSNEEDED,
                    vec![nick, channel, "You're not channel operator"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }

            // Set the topic
            let topic = TopicInfo::new(text.to_string(), conn.hostmask());

            // Store it
            state
                .channels
                .lock()
                .entry(channel.to_string())
                .and_modify(|ch| {
                    ch.topic = Some(topic);
                });

            // CRDT update (async, source of truth for topic convergence)
            {
                let state_c = Arc::clone(state);
                let channel_c = channel.to_string();
                let text_c = text.to_string();
                let nick_c = nick.to_string();
                let did_c = state.session_dids.lock().get(session_id).cloned();
                tokio::spawn(async move {
                    state_c
                        .crdt_set_topic(&channel_c, &text_c, &nick_c, did_c.as_deref())
                        .await;
                });
            }

            // Persist channel state
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(channel) {
                    let ch_clone = ch.clone();
                    drop(channels);
                    state.with_db(|db| db.save_channel(channel, &ch_clone));
                }
            }

            // Broadcast TOPIC change to all channel members
            let hostmask = conn.hostmask();
            let topic_msg = format!(":{hostmask} TOPIC {channel} :{text}\r\n");

            let members: Vec<String> = state
                .channels
                .lock()
                .get(channel)
                .map(|ch| ch.members.iter().cloned().collect())
                .unwrap_or_default();

            let conns = state.connections.lock();
            for member_session in &members {
                if let Some(tx) = conns.get(member_session) {
                    let _ = tx.try_send(topic_msg.clone());
                }
            }

            // Broadcast TOPIC to S2S peers
            let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
            s2s_broadcast(
                state,
                crate::s2s::S2sMessage::Topic {
                    event_id: s2s_next_event_id(state),
                    channel: channel.to_string(),
                    topic: text.to_string(),
                    set_by: conn.nick.as_deref().unwrap_or("*").to_string(),
                    origin,
                },
            );
        }
        None => {
            // Query the topic
            let channels = state.channels.lock();
            if let Some(ch) = channels.get(channel) {
                if let Some(ref topic) = ch.topic {
                    let rpl = Message::from_server(
                        server_name,
                        irc::RPL_TOPIC,
                        vec![nick, channel, &topic.text],
                    );
                    send(state, session_id, format!("{rpl}\r\n"));

                    let rpl_who = Message::from_server(
                        server_name,
                        irc::RPL_TOPICWHOTIME,
                        vec![nick, channel, &topic.set_by, &topic.set_at.to_string()],
                    );
                    send(state, session_id, format!("{rpl_who}\r\n"));
                } else {
                    let rpl = Message::from_server(
                        server_name,
                        irc::RPL_NOTOPIC,
                        vec![nick, channel, "No topic is set"],
                    );
                    send(state, session_id, format!("{rpl}\r\n"));
                }
            }
        }
    }
}

pub(super) fn handle_part(
    conn: &Connection,
    channel: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify user is in the channel
    let in_channel = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.contains(session_id))
        .unwrap_or(false);
    if !in_channel {
        let reply = Message::from_server(
            server_name,
            crate::irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let hostmask = conn.hostmask();
    let part_msg = format!(":{hostmask} PART {channel}\r\n");

    // Is the *identity* leaving, or just this device?
    //
    // A PART names the leaver by nick, and every session signed in as one identity
    // shares that nick. So announcing a device's PART to the channel while another
    // of that identity's sessions is still a member states something false: the nick
    // is still present. Everyone's roster drops a user who is still there, and the
    // user's own other devices are told they left a channel they are still in —
    // which they then act on, because a self-nick PART is indistinguishable from
    // their own.
    //
    // The same reasoning already governs the auto-rejoin row below. This applies it
    // to the wire.
    let sibling_still_member = match conn.authenticated_did {
        Some(ref did) => {
            let did_sessions = state.did_sessions.lock();
            let channels = state.channels.lock();
            match (did_sessions.get(did), channels.get(channel)) {
                (Some(sessions), Some(ch)) => sessions
                    .iter()
                    .any(|sid| sid != session_id && ch.members.contains(sid)),
                _ => false,
            }
        }
        None => false,
    };

    if sibling_still_member {
        // Echo to the asking client only: it needs to know the request was honoured,
        // and nobody else's view of the channel has changed.
        tracing::debug!(
            session = %session_id, channel = %channel,
            "PART not announced: another session for this DID remains in the channel"
        );
        send(state, session_id, part_msg.clone());
    } else {
        let members: Vec<String> = state
            .channels
            .lock()
            .get(channel)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let conns = state.connections.lock();
        for member_session in &members {
            if let Some(tx) = conns.get(member_session) {
                let _ = tx.try_send(part_msg.clone());
            }
        }
        drop(conns);
    }

    state
        .channels
        .lock()
        .entry(channel.to_string())
        .and_modify(|ch| {
            ch.members.remove(session_id);
        });

    // NOTE: Presence is NOT in CRDT (avoids ghost users on crash)

    // Remove from auto-rejoin list — but only when no OTHER session for this
    // DID is still a member of the channel. Otherwise the user has another
    // device that never PARTed, and clearing the row would silently make
    // that channel non-restorable on the next reconnect (the cross-device
    // "I left on web but iOS keeps showing it / can't get rid of it"
    // failure mode).
    if let Some(ref did) = conn.authenticated_did {
        let other_session_still_member = {
            let did_sessions = state.did_sessions.lock();
            let channels = state.channels.lock();
            match (did_sessions.get(did), channels.get(channel)) {
                (Some(sessions), Some(ch)) => sessions
                    .iter()
                    .any(|sid| sid != session_id && ch.members.contains(sid)),
                _ => false,
            }
        };
        if !other_session_still_member {
            let did_owned = did.clone();
            let channel_owned = channel.to_string();
            state.with_db(|db| db.remove_user_channel(&did_owned, &channel_owned));
        }
    }

    // Broadcast PART to S2S peers — unless this identity is still in the channel on
    // another session here, in which case peers would remove a nick from their
    // remote_members while it is still present locally.
    if !sibling_still_member {
        let event_id = s2s_next_event_id(state);
        let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
        s2s_broadcast(
            state,
            crate::s2s::S2sMessage::Part {
                event_id,
                nick: conn.nick.as_deref().unwrap_or("*").to_string(),
                channel: channel.to_string(),
                origin,
            },
        );
    }
}

pub(super) fn handle_names(
    conn: &Connection,
    channel: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // NAMES is channel-only. Answering for a nick with an empty roster reads
    // as "that person is an empty room", which is how clients ended up minting
    // phantom channel buffers from a DM target.
    if !channel.starts_with('#') && !channel.starts_with('&') {
        let err = irc::Message::from_server(
            server_name,
            irc::ERR_NOSUCHCHANNEL,
            vec![nick, channel, "No such channel"],
        );
        send(state, session_id, format!("{err}\r\n"));
        return;
    }

    let multi_prefix = state.cap_multi_prefix.lock().contains(session_id);

    // Snapshot session→DID FIRST and release the lock immediately.
    //
    // LOCK ORDER: registration holds `session_dids` and then takes
    // `nick_to_session`. Taking them in the opposite order here (as this did
    // when it first gained DID awareness) is an AB/BA deadlock: a NAMES racing
    // a registration wedges both. The visible symptom is a client that joins,
    // receives messages — those are written by other tasks — and never gets a
    // member list. Hold at most one of these at a time.
    let session_dids_snapshot = state.session_dids.lock().clone();

    let nick_list: Vec<String> = {
        let channels = state.channels.lock();
        let (member_sessions, remote_members, ops, voiced) = match channels.get(channel) {
            Some(ch) if state.channel_visible_to(channel, ch, session_id) => (
                ch.members.clone(),
                ch.remote_members.clone(),
                ch.ops.clone(),
                ch.voiced.clone(),
            ),
            _ => Default::default(),
        };
        // Read from the guard already held; re-locking here deadlocks
        // (parking_lot mutexes are not reentrant).
        let ch_did_authority = channels
            .get(channel)
            .map(|ch| (ch.founder_did.clone(), ch.did_ops.clone()));
        drop(channels);
        let nicks = state.nick_to_session.lock();
        let mut seen_nicks = std::collections::HashSet::new();
        // Fold every session of a nick together before deciding its prefix.
        //
        // `ch.ops`/`ch.voiced` are keyed by SESSION, but a person can be signed
        // in on several devices and a MODE is applied to just one of those
        // sessions. Taking the flags from whichever session was enumerated first
        // made the prefix depend on hash order: the same op rendered with or
        // without `@` from one NAMES to the next, and disagreed with the
        // permission checks, which resolve by DID. Union the sessions, then apply
        // the same DID authority the remote-member branch below already uses.
        let session_dids = &session_dids_snapshot;
        let mut folded: Vec<(String, bool, bool)> = Vec::new();
        for s in member_sessions.iter() {
            let Some(n) = nicks.get_nick(s) else { continue };
            let is_op = ops.contains(s)
                || session_dids.get(s).is_some_and(|d| {
                    ch_did_authority.as_ref().is_some_and(|(founder, did_ops)| {
                        founder.as_deref() == Some(d.as_str()) || did_ops.contains(d)
                    })
                });
            let is_voiced = voiced.contains(s);
            let nick_lower = n.to_lowercase();
            if seen_nicks.insert(nick_lower.clone()) {
                folded.push((n.to_string(), is_op, is_voiced));
            } else if let Some(e) = folded
                .iter_mut()
                .find(|(existing, _, _)| existing.to_lowercase() == nick_lower)
            {
                e.1 |= is_op;
                e.2 |= is_voiced;
            }
        }
        let mut list: Vec<String> = folded
            .into_iter()
            .map(|(n, is_op, is_voiced)| {
                let prefix = if multi_prefix {
                    let mut p = String::new();
                    if is_op {
                        p.push('@');
                    }
                    if is_voiced {
                        p.push('+');
                    }
                    p
                } else if is_op {
                    "@".to_string()
                } else if is_voiced {
                    "+".to_string()
                } else {
                    String::new()
                };
                format!("{prefix}{n}")
            })
            .collect();
        let channels_lock = state.channels.lock();
        let ch_state = channels_lock.get(channel);
        for (nick, rm) in &remote_members {
            let is_op = rm.is_op
                || rm.did.as_ref().is_some_and(|d| {
                    ch_state.is_some_and(|ch| {
                        ch.founder_did.as_deref() == Some(d.as_str()) || ch.did_ops.contains(d)
                    })
                });
            let prefix = if is_op { "@" } else { "" };
            list.push(format!("{prefix}{nick}"));
        }
        drop(channels_lock);
        list
    };

    let names = irc::Message::from_server(
        server_name,
        irc::RPL_NAMREPLY,
        vec![nick, "=", channel, &nick_list.join(" ")],
    );
    let end_names = irc::Message::from_server(
        server_name,
        irc::RPL_ENDOFNAMES,
        vec![nick, channel, "End of /NAMES list"],
    );
    send(state, session_id, format!("{names}\r\n"));
    send(state, session_id, format!("{end_names}\r\n"));
}

pub(super) fn handle_list(
    conn: &Connection,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();
    let channels = state.channels.lock();
    for (name, ch) in channels.iter() {
        // Don't advertise restricted (+i/+k/+E/policy-gated) channels to
        // non-members — listing them only leaks a private channel's existence,
        // name, and topic. Members still see their own channels.
        if !state.channel_visible_to(name, ch, session_id) {
            continue;
        }
        let count = ch.members.len() + ch.remote_members.len();
        let topic = ch.topic.as_ref().map(|t| t.text.as_str()).unwrap_or("");
        let reply = Message::from_server(
            server_name,
            irc::RPL_LIST,
            vec![nick, name, &count.to_string(), topic],
        );
        send(state, session_id, format!("{reply}\r\n"));
    }
    let end = Message::from_server(server_name, irc::RPL_LISTEND, vec![nick, "End of /LIST"]);
    send(state, session_id, format!("{end}\r\n"));
}

// ── WHO command ─────────────────────────────────────────────────────

/// Membership modes a JOIN must announce, in stable order.
///
/// Every mode the join path *grants* has to be announced, or clients' member
/// lists silently disagree with the server. Two ways that used to break:
/// a policy role of "voice" inserted into `ch.voiced` and was never announced at
/// all, and the old if/else-if chain announced at most one mode, so a member who
/// was both opped and voiced lost the `+v`.
pub(super) fn auto_modes_for(is_op: bool, is_halfop: bool, is_voiced: bool) -> Vec<&'static str> {
    let mut modes = Vec::new();
    if is_op {
        modes.push("o");
    }
    if is_halfop {
        modes.push("h");
    }
    if is_voiced {
        modes.push("v");
    }
    modes
}

#[cfg(test)]
mod auto_mode_tests {
    //! Which membership modes a JOIN must announce.
    //!
    //! Granting a mode without announcing it leaves every client's member list
    //! disagreeing with the server — the same failure as announcing it in the
    //! wrong order, just with no message at all to mis-order.
    use super::auto_modes_for;

    #[test]
    fn op_is_announced() {
        assert_eq!(auto_modes_for(true, false, false), vec!["o"]);
    }

    #[test]
    fn halfop_is_announced() {
        assert_eq!(auto_modes_for(false, true, false), vec!["h"]);
    }

    #[test]
    fn voice_is_announced() {
        // A policy role of "voice"/"speaker" inserts into ch.voiced on join, but
        // the announce path only ever considered op and halfop — so a voiced
        // member was granted voice that nobody, including them, was told about.
        // In a +m channel that is the difference between being able to speak and
        // silently appearing unable to.
        assert_eq!(auto_modes_for(false, false, true), vec!["v"]);
    }

    #[test]
    fn combined_grants_are_all_announced() {
        // The old else-if chain announced at most one mode, so an op who was also
        // voiced lost the +v.
        assert_eq!(auto_modes_for(true, false, true), vec!["o", "v"]);
        assert_eq!(auto_modes_for(false, true, true), vec!["h", "v"]);
        assert_eq!(auto_modes_for(true, true, true), vec!["o", "h", "v"]);
    }

    #[test]
    fn a_plain_member_announces_nothing() {
        assert!(auto_modes_for(false, false, false).is_empty());
    }
}
