#![allow(clippy::too_many_arguments)]
//! IRC registration (NICK/USER completion).

use super::Connection;
use crate::irc::{self, Message};
use crate::server::SharedState;
use std::sync::Arc;

/// How long a probed session has to answer the liveness PING before it is
/// presumed to be a zombie socket and evicted.
const LIVENESS_PROBE_SECS: u64 = 10;

/// The sibling sessions to probe for liveness when a session attaches for a
/// DID: every *other* session currently registered under that DID, minus any
/// already known to be stale (e.g. a ghost's session id being reclaimed).
///
/// Pure so the selection policy is unit-testable without a live socket map.
/// Deduplicates so a session listed twice isn't PINGed twice.
pub(super) fn siblings_to_probe(
    all_for_did: &[String],
    new_session: &str,
    exclude: &[&str],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for sid in all_for_did {
        if sid == new_session || exclude.contains(&sid.as_str()) {
            continue;
        }
        if !out.iter().any(|s| s == sid) {
            out.push(sid.clone());
        }
    }
    out
}

/// Send a liveness PING to every existing session of a DID that just gained
/// a new session, and evict any that have not answered with PONG after
/// [`LIVENESS_PROBE_SECS`]. Eviction notifies the session's kill signal, so
/// teardown runs the session's own cleanup path (QUIT broadcast, membership
/// removal, ghost-session grace) exactly as a ping timeout would.
fn probe_sibling_liveness(
    state: &Arc<SharedState>,
    siblings: &[String],
    new_session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    if siblings.is_empty() {
        return;
    }
    {
        let now = std::time::Instant::now();
        let mut probes = state.liveness_probes.lock();
        for sid in siblings {
            // entry(): never extend an already-running probe's deadline.
            probes.entry(sid.clone()).or_insert(now);
        }
    }
    for sid in siblings {
        send(state, sid, "PING :liveness-probe\r\n".to_string());
    }

    let state = Arc::clone(state);
    let siblings = siblings.to_vec();
    let trigger = new_session_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(LIVENESS_PROBE_SECS)).await;
        for sid in &siblings {
            // Still pending = no PONG arrived; the PONG handler removes the
            // entry, so remove() doubles as the answered/unanswered check.
            if state.liveness_probes.lock().remove(sid).is_none() {
                continue;
            }
            let kill = state.session_kill.lock().get(sid).cloned();
            if let Some(kill) = kill {
                tracing::info!(
                    zombie = %sid, trigger = %trigger,
                    "Liveness probe unanswered — evicting zombie session"
                );
                kill.notify_one();
            }
        }
    });
}

/// Attach a new session to existing sessions with the same DID.
/// Instead of ghosting (killing) old sessions, this enables multi-device:
/// - The new session shares the same nick
/// - The new session is added to all channels the DID is already in
/// - Messages fan out to all sessions for the DID
/// - The user appears once in member lists
///
/// Called at SASL success time.
pub(super) fn attach_same_did(
    conn: &mut Connection,
    state: &Arc<SharedState>,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let did = match conn.authenticated_did.as_ref() {
        Some(d) => d.clone(),
        None => return,
    };

    // Register this session in did_sessions
    state
        .did_sessions
        .lock()
        .entry(did.clone())
        .or_default()
        .insert(session_id.to_string());

    // Check for ghost session (recently disconnected — reclaim without join/part churn)
    let ghost = state.ghost_sessions.lock().remove(&did);
    if let Some(ghost) = ghost {
        // Cancel the deferred QUIT broadcast
        let _ = ghost.cancel.send(());
        let elapsed = ghost.disconnect_time.elapsed();
        tracing::info!(
            did = %did, nick = %ghost.nick, session = %session_id,
            elapsed_ms = elapsed.as_millis() as u64,
            channels = ghost.channels.len(),
            "Reclaimed ghost session — suppressing quit/join churn"
        );

        // Adopt the ghost's nick
        if conn.nick.as_ref().map(|n| n.to_lowercase()) != Some(ghost.nick.to_lowercase()) {
            if let Some(ref old_nick) = conn.nick {
                state.nick_to_session.lock().remove_by_nick(old_nick);
            }
            conn.nick = Some(ghost.nick.clone());
        }
        // Point the nick at the new session
        state.nick_to_session.lock().insert(&ghost.nick, session_id);

        // Re-join all channels the ghost was in (silently — no broadcast).
        // Remove the stale ghost session_id and replace with the new one.
        let mut channels = state.channels.lock();
        for (ch_name, was_op, was_voiced, was_halfop) in &ghost.channels {
            if let Some(ch) = channels.get_mut(&ch_name.to_lowercase()) {
                // Remove the ghost's stale session_id from all membership sets
                ch.members.remove(&ghost.session_id);
                ch.ops.remove(&ghost.session_id);
                ch.voiced.remove(&ghost.session_id);
                ch.halfops.remove(&ghost.session_id);

                // Insert the new session_id
                ch.members.insert(session_id.to_string());
                // Restore ops from ghost state, OR grant via DID authority
                let should_op = *was_op
                    || ch.founder_did.as_deref() == Some(did.as_str())
                    || ch.did_ops.contains(&did);
                if should_op {
                    ch.ops.insert(session_id.to_string());
                }
                if *was_voiced {
                    ch.voiced.insert(session_id.to_string());
                }
                if *was_halfop {
                    ch.halfops.insert(session_id.to_string());
                }
            }
        }
        drop(channels);

        // Also clean up the ghost's stale sid_to_nick entry
        state
            .nick_to_session
            .lock()
            .remove_by_session(&ghost.session_id);

        // A ghost reclaim short-circuits the multi-device probe below, so any
        // OTHER live sessions for this DID (a half-open zombie that never sent
        // QUIT — distinct from the cleanly-ghosted session we just reclaimed)
        // would otherwise never be probed and would linger until the ~60s
        // server ping timeout. Probe them here too, excluding the ghost's own
        // (already removed) session id.
        let zombies = {
            let session_dids = state.session_dids.lock();
            let all: Vec<String> = session_dids
                .iter()
                .filter(|(_, d)| d.as_str() == did)
                .map(|(sid, _)| sid.clone())
                .collect();
            siblings_to_probe(&all, session_id, &[ghost.session_id.as_str()])
        };
        probe_sibling_liveness(state, &zombies, session_id, send);

        // Store reclaimed channel names so try_complete_registration can send
        // synthetic state AFTER the client is fully registered (needed for CHATHISTORY).
        conn.ghost_channels = Some(
            ghost
                .channels
                .iter()
                .map(|(name, _, _, _)| name.clone())
                .collect(),
        );

        return;
    }

    // Find existing sessions for this DID
    let existing_sessions: Vec<String> = {
        let session_dids = state.session_dids.lock();
        let all: Vec<String> = session_dids
            .iter()
            .filter(|(_, d)| d.as_str() == did)
            .map(|(sid, _)| sid.clone())
            .collect();
        siblings_to_probe(&all, session_id, &[])
    };

    if existing_sessions.is_empty() {
        // First session for this DID — normal registration.
        //
        // Ensure nick is in nick_to_session. The previous version skipped
        // when contains_nick(nick) was true, which is wrong: the existing
        // entry can be a stale mapping pointing to a dead session_id (e.g.
        // a previous connection that closed without proper cleanup, or
        // surfaced after a server restart in some other path). Skipping
        // the insert leaves us with `online: true` (session_dids has us)
        // but `nick: None` (nick_to_session does not), which silently
        // breaks WHOIS, NAMES, and DM routing.
        //
        // Safe-to-claim rule:
        //   - free nick → claim
        //   - held by a session with the SAME authenticated DID as us
        //     → claim (multi-device sibling, NickMap.insert preserves siblings)
        //   - held by a session with no DID in session_dids → stale dead
        //     entry → claim (overwrite)
        //   - held by a session with a DIFFERENT live DID → leave alone;
        //     try_complete_registration's ownership check renames us to
        //     a Guest nick before the connection finishes registering.
        if let Some(ref nick) = conn.nick {
            let mut nts = state.nick_to_session.lock();
            let safe_to_claim = match nts.get_session(nick) {
                None => true,
                Some(other_sid) => {
                    let other_sid_owned = other_sid.to_string();
                    drop(nts);
                    let session_dids = state.session_dids.lock();
                    let conflict = matches!(
                        session_dids.get(&other_sid_owned),
                        Some(other_did) if other_did != &did,
                    );
                    nts = state.nick_to_session.lock();
                    !conflict
                }
            };
            if safe_to_claim {
                nts.insert(nick, session_id);
                tracing::info!(nick = %nick, "Registered nick for DID {did}");
            }
        }
        // Reclaim if we got a fallback nick with trailing '_'
        let reclaim = conn
            .nick
            .as_ref()
            .filter(|n| n.ends_with('_'))
            .map(|n| (n.clone(), n.trim_end_matches('_').to_string()));
        if let Some((current_nick, desired)) = reclaim {
            let mut nts = state.nick_to_session.lock();
            if !nts.contains_nick(&desired) {
                nts.remove_by_nick(&current_nick);
                nts.insert(&desired, session_id);
                tracing::info!(old = %current_nick, new = %desired, "Reclaimed nick");
                conn.nick = Some(desired);
            }
        }
        return;
    }

    // Multi-device attach: existing sessions exist for this DID
    tracing::info!(did = %did, session = %session_id, existing = ?existing_sessions.len(),
                   "Attaching additional session for DID");

    // Probe the existing sessions for liveness. A frozen-then-resumed agent
    // VM (boxd pause/resume) leaves a zombie TCP session that would otherwise
    // hold nick + channel state until the ping timeout (~90s) and crash-loop
    // the reconnecting agent. Healthy multi-device siblings answer the PING
    // immediately and are untouched; sessions that stay silent past the
    // deadline are evicted through their normal cleanup path.
    probe_sibling_liveness(state, &existing_sessions, session_id, send);

    // Find the canonical nick from existing sessions
    let canonical_nick = {
        let nts = state.nick_to_session.lock();
        let sd = state.session_dids.lock();
        nts.iter()
            .find(|&(_, sid)| {
                let sid_str: &str = sid;
                sd.get(sid_str) == Some(&did)
            })
            .map(|(nick, _)| nick.to_string())
    };

    // Adopt the canonical nick and ensure this session is in nick_to_session
    if let Some(ref canon) = canonical_nick {
        let mut nts = state.nick_to_session.lock();
        if conn.nick.as_ref().map(|n| n.to_lowercase()) != Some(canon.to_lowercase()) {
            // Remove this session's old nick mapping (not all sessions with that nick)
            nts.remove_by_session(session_id);
            conn.nick = Some(canon.clone());
        }
        // Ensure this session_id → nick mapping exists so NAMES can resolve it.
        // For multi-device, multiple sessions share the same nick. NickMap.insert()
        // now supports this: it adds sid→nick without evicting other sessions.
        nts.insert(canon, session_id);
    } else if let Some(ref nick) = conn.nick {
        // Fallback: existing sessions for this DID exist but NONE has a
        // nick_to_session mapping. That can happen if a prior session
        // landed in the half-registered state (the original bug). We can
        // self-heal here: insert our session under the nick we asked for.
        // NickMap.insert is multi-device safe.
        let mut nts = state.nick_to_session.lock();
        nts.insert(nick, session_id);
        tracing::warn!(
            did = %did, nick = %nick, session = %session_id,
            "Multi-device attach found no canonical nick — recovering by inserting requested nick"
        );
    }

    // Find all channels the DID is in via existing sessions
    let channels_to_join: Vec<String> = {
        let channels = state.channels.lock();
        channels
            .iter()
            .filter(|(_, ch)| existing_sessions.iter().any(|sid| ch.members.contains(sid)))
            .map(|(name, _)| name.clone())
            .collect()
    };

    // Snapshot session→DID once, before any channel or nick lock.
    //
    // LOCK ORDER: this function holds `session_dids` while taking
    // `nick_to_session` (above), so any path that grabs them the other way round
    // is an AB/BA deadlock. Snapshot once here and hold nothing later.
    let dids_snapshot = state.session_dids.lock().clone();

    // Add this session to those channels (silently — no JOIN broadcast)
    {
        let mut channels = state.channels.lock();
        for ch_name in &channels_to_join {
            if let Some(ch) = channels.get_mut(ch_name) {
                ch.members.insert(session_id.to_string());
                // Copy op/voice status from existing session, OR grant via DID authority
                let is_op = existing_sessions.iter().any(|s| ch.ops.contains(s))
                    || ch.founder_did.as_deref() == Some(did.as_str())
                    || ch.did_ops.contains(&did);
                let is_voiced = existing_sessions.iter().any(|s| ch.voiced.contains(s));
                if is_op {
                    ch.ops.insert(session_id.to_string());
                }
                if is_voiced {
                    ch.voiced.insert(session_id.to_string());
                }
            }
        }
    }

    // Send the new session a replay of channel state so it knows where it is
    let nick = conn.nick.as_deref().unwrap_or("*");
    let server_name = &state.server_name;
    for ch_name in &channels_to_join {
        // Synthesize JOIN for the client
        let host = super::helpers::cloaked_host_for_did(Some(did.as_str()));
        send(
            state,
            session_id,
            format!(":{nick}!~u@{host} JOIN {ch_name}\r\n"),
        );

        // Send topic
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(ch_name) {
            if let Some(ref topic) = ch.topic {
                let topic_msg = crate::irc::Message::from_server(
                    server_name,
                    crate::irc::RPL_TOPIC,
                    vec![nick, ch_name, &topic.text],
                );
                send(state, session_id, format!("{topic_msg}\r\n"));
            }
            // Send NAMES
            let nts = state.nick_to_session.lock();
            let mut names: Vec<String> = Vec::new();
            let mut seen_nicks = std::collections::HashSet::new();
            // Group this channel's sessions by nick before deciding prefixes.
            // Reading the session-keyed sets per session made the answer depend
            // on which of a multi-device member's sockets came first in hash
            // order, so an op could be announced to an attaching device as a
            // plain member. Same folded, DID-aware answer as NAMES/WHO/WHOIS.
            let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
            for member_sid in &ch.members {
                let Some(member_nick) = nts.get_nick(member_sid) else {
                    continue;
                };
                let nick_lower = member_nick.to_lowercase();
                match grouped
                    .iter_mut()
                    .find(|(k, _)| k.to_lowercase() == nick_lower)
                {
                    Some((_, sids)) => sids.push(member_sid.clone()),
                    None => {
                        seen_nicks.insert(nick_lower);
                        grouped.push((member_nick.to_string(), vec![member_sid.clone()]));
                    }
                }
            }
            for (member_nick, sids) in &grouped {
                let (is_op, is_voiced) = super::helpers::folded_membership(
                    sids,
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
                names.push(format!("{prefix}{member_nick}"));
            }
            drop(channels);
            let names_str = names.join(" ");
            let names_msg = crate::irc::Message::from_server(
                server_name,
                crate::irc::RPL_NAMREPLY,
                vec![nick, "=", ch_name, &names_str],
            );
            let end_msg = crate::irc::Message::from_server(
                server_name,
                crate::irc::RPL_ENDOFNAMES,
                vec![nick, ch_name, "End of /NAMES list"],
            );
            send(state, session_id, format!("{names_msg}\r\n{end_msg}\r\n"));
        } else {
            drop(channels);
        }
    }

    tracing::info!(did = %did, channels = ?channels_to_join.len(),
                   "Session attached to {} existing channels", channels_to_join.len());
}

pub(super) fn try_complete_registration(
    conn: &mut Connection,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    if conn.registered || conn.cap_negotiating || conn.sasl_in_progress {
        return;
    }
    if conn.nick.is_none() || conn.user.is_none() {
        return;
    }

    // Enforce nick ownership at registration time.
    // If the user claimed a registered nick during CAP negotiation
    // but didn't authenticate as the owner, force-rename them.
    if let Some(nick) = conn.nick.clone() {
        let nick_lower = nick.to_lowercase();
        let owner_did = state.nick_owners.lock().get(&nick_lower).cloned();
        if let Some(owner) = owner_did {
            let auth_did = conn.authenticated_did.clone();
            let is_owner = auth_did.as_deref() == Some(owner.as_str());
            if !is_owner {
                if let Some(did) = auth_did {
                    // Authenticated as a different DID than the nick's
                    // owner: assign a deterministic, durably-persisted
                    // derived nick (stable across reconnects/restarts)
                    // rather than a throwaway Guest. They are NOT being
                    // asked to "authenticate" — they already did; the
                    // name simply belongs to another identity.
                    let assigned = state.bind_identity_with_fallback(&did, &nick_lower);
                    let notice = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            "*",
                            &format!(
                                "{nick} is registered to another identity. You are {assigned} (tied to your account)."
                            ),
                        ],
                    );
                    send(state, session_id, format!("{notice}\r\n"));
                    state.nick_to_session.lock().remove_by_nick(&nick);
                    state.nick_to_session.lock().insert(&assigned, session_id);
                    conn.nick = Some(assigned);
                } else {
                    // Unauthenticated squatter — temp Guest nick.
                    // The web client detects Guest rename and disconnects (no ghost).
                    // The iOS client continues with the temp nick and auto-joins channels.
                    let guest_id: u32 = rand::random::<u32>() % 100000;
                    let guest_nick = format!("Guest{guest_id}");
                    let notice = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            "*",
                            &format!(
                                "Nick {nick} is registered — renamed to {guest_nick}. Authenticate to reclaim."
                            ),
                        ],
                    );
                    send(state, session_id, format!("{notice}\r\n"));
                    state.nick_to_session.lock().remove_by_nick(&nick);
                    state.nick_to_session.lock().insert(&guest_nick, session_id);
                    conn.nick = Some(guest_nick);
                }
            }
        }
    }

    // Multi-device attach is handled at SASL success time (cap.rs).
    // This catch-all covers edge cases where registration completes
    // without going through the SASL path.
    attach_same_did(conn, state, session_id, send);

    // Refuse guest (unauthenticated) connections when the instance requires
    // authentication (opt-in --no-guest). Server operators are DID-authenticated
    // anyway, so this only turns away truly anonymous connections.
    if conn.authenticated_did.is_none() && state.config.no_guest {
        send(
            state,
            session_id,
            "ERROR :This server requires authentication (guest connections disabled)\r\n"
                .to_string(),
        );
        tracing::info!(%session_id, "guest connection refused (--no-guest)");
        return;
    }

    conn.registered = true;
    let nick = conn.nick.as_deref().unwrap();

    // Store iroh endpoint ID in shared state for WHOIS lookups
    if let Some(ref iroh_id) = conn.iroh_endpoint_id {
        state
            .session_iroh_ids
            .lock()
            .insert(session_id.to_string(), iroh_id.clone());
    }

    let auth_info = match &conn.authenticated_did {
        Some(did) => format!(" (authenticated as {did})"),
        None => " (guest)".to_string(),
    };

    let welcome = Message::from_server(
        server_name,
        irc::RPL_WELCOME,
        vec![
            nick,
            &format!("Welcome to {server_name}, {nick}{auth_info}"),
        ],
    );
    let yourhost = Message::from_server(
        server_name,
        irc::RPL_YOURHOST,
        vec![
            nick,
            &format!("Your host is {server_name}, running freeq 0.1"),
        ],
    );
    let boot_str = state
        .boot_timestamp
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let created = Message::from_server(
        server_name,
        irc::RPL_CREATED,
        vec![nick, &format!("This server was started {boot_str}")],
    );
    let myinfo = Message::from_server(
        server_name,
        irc::RPL_MYINFO,
        vec![nick, server_name, "freeq-0.1", "o", "o"],
    );

    for msg in [welcome, yourhost, created, myinfo] {
        send(state, session_id, format!("{msg}\r\n"));
    }

    // Send MOTD
    if let Some(ref motd) = state.config.motd {
        let start = Message::from_server(
            server_name,
            irc::RPL_MOTDSTART,
            vec![nick, &format!("- {server_name} Message of the day -")],
        );
        send(state, session_id, format!("{start}\r\n"));
        for line in motd.lines() {
            let motd_line =
                Message::from_server(server_name, irc::RPL_MOTD, vec![nick, &format!("- {line}")]);
            send(state, session_id, format!("{motd_line}\r\n"));
        }
        let end = Message::from_server(
            server_name,
            irc::RPL_ENDOFMOTD,
            vec![nick, "End of /MOTD command"],
        );
        send(state, session_id, format!("{end}\r\n"));
    } else {
        let no_motd = Message::from_server(
            server_name,
            irc::ERR_NOMOTD,
            vec![nick, "MOTD File is missing"],
        );
        send(state, session_id, format!("{no_motd}\r\n"));
    }

    // Send server restart notice if the server booted recently (within 5 minutes)
    {
        let uptime = state.boot_time.elapsed();
        if uptime.as_secs() < 300 {
            let boot_ts = state.boot_timestamp.format("%Y-%m-%d %H:%M:%S UTC");
            let ago = if uptime.as_secs() < 60 {
                format!("{}s ago", uptime.as_secs())
            } else {
                format!("{}m {}s ago", uptime.as_secs() / 60, uptime.as_secs() % 60)
            };
            let notice = format!(
                ":{server_name} NOTICE {nick} :⚡ Server restarted at {boot_ts} ({ago})\r\n"
            );
            send(state, session_id, notice);
        }
    }

    // Send synthetic state for ghost-reclaimed channels (now that registration is complete,
    // so the client can issue CHATHISTORY after receiving ENDOFNAMES).
    if let Some(ghost_chs) = conn.ghost_channels.take() {
        let nick = conn.nick.as_deref().unwrap_or("*").to_string();
        for ch_name in &ghost_chs {
            // Send JOIN to the client so it knows it's in the channel
            let hostmask = conn.hostmask();
            send(state, session_id, format!(":{hostmask} JOIN {ch_name}\r\n"));

            // Topic
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&ch_name.to_lowercase())
                    && let Some(ref topic) = ch.topic
                {
                    let topic_msg = crate::irc::Message::from_server(
                        server_name,
                        crate::irc::RPL_TOPIC,
                        vec![&nick, ch_name, &topic.text],
                    );
                    send(state, session_id, format!("{topic_msg}\r\n"));
                }
            }

            // Names (sends NAMREPLY + ENDOFNAMES → triggers client CHATHISTORY request)
            super::channel::handle_names(conn, ch_name, state, server_name, session_id, send);
        }
    }

    // Auto-rejoin channels for DID-authenticated users.
    // Skip channels already joined via attach_same_did (multi-device).
    if let Some(ref did) = conn.authenticated_did {
        let did = did.clone();
        if let Some(channels) = state.with_db(|db| db.get_user_channels(&did)) {
            // Filter out channels this session is already in (from multi-device attach)
            let already_in: std::collections::HashSet<String> = {
                let chs = state.channels.lock();
                chs.iter()
                    .filter(|(_, ch)| ch.members.contains(session_id))
                    .map(|(name, _)| name.to_lowercase())
                    .collect()
            };
            let to_join: Vec<String> = channels
                .into_iter()
                .filter(|ch| !already_in.contains(&ch.to_lowercase()))
                .collect();
            if !to_join.is_empty() {
                tracing::info!(%session_id, %did, count = to_join.len(), "Auto-rejoining saved channels");
                for channel in to_join {
                    super::channel::handle_join(
                        conn,
                        &channel,
                        None,
                        state,
                        server_name,
                        session_id,
                        send,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::siblings_to_probe;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn excludes_the_new_session() {
        // The attaching session must never probe itself.
        let all = v(&["a", "b", "new"]);
        assert_eq!(siblings_to_probe(&all, "new", &[]), v(&["a", "b"]));
    }

    #[test]
    fn excludes_named_stale_sessions() {
        // Ghost-reclaim path: the ghost's own (already-removed) session id is
        // excluded so we don't probe a session we just tore down.
        let all = v(&["ghost", "zombie", "new"]);
        assert_eq!(
            siblings_to_probe(&all, "new", &["ghost"]),
            v(&["zombie"]),
            "ghost excluded, the real zombie still gets probed"
        );
    }

    #[test]
    fn empty_when_new_session_is_only_one() {
        let all = v(&["solo"]);
        assert!(siblings_to_probe(&all, "solo", &[]).is_empty());
    }

    #[test]
    fn dedups_repeated_ids() {
        let all = v(&["a", "a", "b"]);
        assert_eq!(siblings_to_probe(&all, "x", &[]), v(&["a", "b"]));
    }

    #[test]
    fn multiple_exclusions() {
        let all = v(&["a", "b", "c", "new"]);
        assert_eq!(siblings_to_probe(&all, "new", &["a", "c"]), v(&["b"]));
    }

    #[test]
    fn healthy_multidevice_sibling_is_returned_for_probing() {
        // A genuine second device (laptop + phone) is probed too — but it
        // answers the PING immediately and is spared eviction. Only silence
        // past the deadline evicts, so this never breaks multi-device.
        let all = v(&["laptop", "phone"]);
        assert_eq!(siblings_to_probe(&all, "phone", &[]), v(&["laptop"]));
    }
}
