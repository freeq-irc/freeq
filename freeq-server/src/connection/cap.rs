#![allow(clippy::too_many_arguments)]
//! CAP capability negotiation and SASL authentication.

use super::Connection;
use super::helpers::broadcast_account_notify;
use super::registration::try_complete_registration;
use crate::irc::{self, Message};
use crate::sasl;
use crate::server::SharedState;
use freeq_sdk::auth::{MAX_SASL_RESPONSE_LEN, SASL_CHUNK_LEN};
use std::sync::Arc;

/// What a single `AUTHENTICATE` line contributed to the response.
enum Reassembly {
    /// A piece landed and the rest is still coming.
    Partial,
    /// The whole response, ready to decode.
    Complete(String),
    /// More than any real response could need.
    TooLong,
}

/// Join the pieces of a SASL response. A short piece, a bare `+`, or a full
/// chunk that already decodes ends it.
fn accumulate_response(conn: &mut Connection, param: &str) -> Reassembly {
    let chunk = if param == "+" { "" } else { param };
    if conn.sasl_response_buf.len() + chunk.len() > MAX_SASL_RESPONSE_LEN {
        conn.sasl_response_buf.clear();
        return Reassembly::TooLong;
    }
    conn.sasl_response_buf.push_str(chunk);
    if chunk.len() == SASL_CHUNK_LEN
        && sasl::decode_response_explained(&conn.sasl_response_buf).is_err()
    {
        return Reassembly::Partial;
    }
    Reassembly::Complete(std::mem::take(&mut conn.sasl_response_buf))
}

/// Close the connection once it has failed SASL three times.
fn close_after_too_many_failures(
    conn: &Connection,
    state: &Arc<SharedState>,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    if conn.sasl_failures >= 3 {
        send(
            state,
            session_id,
            "ERROR :Too many SASL failures\r\n".to_string(),
        );
        // Drop the send channel to force-close the connection.
        state.connections.lock().remove(session_id);
    }
}

pub(super) fn handle_cap(
    conn: &mut Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let subcmd = msg.params.first().map(|s| s.to_ascii_uppercase());
    match subcmd.as_deref() {
        Some("LS") => {
            conn.cap_negotiating = true;
            // Build capability list, including iroh endpoint ID if available
            // `freeq.at/msgsig` says this server verifies the chat signing
            // document (JCS over an enumerated per-kind document, signed over
            // the sender's own event id — see `freeq_sdk::chatsig`). Clients
            // use it to decide which canonical to sign: without it, signing
            // the document form would be verified by nobody. The server needs
            // no per-session state for it, because the signature tag says
            // which form it is (`ed25519:<kid>:<sig>` vs a bare blob).
            // `freeq.at/act` says this server understands task messages, and
            // asks to be sent them. It gates delivery in both directions:
            // without it a client neither receives task events live nor gets
            // them replayed, only the human-readable companion lines. A client
            // that cannot render a task card has no use for the machine half.
            let mut caps = String::from(
                "sasl message-tags multi-prefix echo-message server-time batch draft/chathistory account-notify account-tag extended-join away-notify draft/read-marker freeq.at/msgsig freeq.at/act",
            );
            // Advertise draft/multiline with our policy limits (spec requires
            // max-bytes; max-lines is recommended). See `draft_multiline` module
            // for the actual enforcement.
            caps.push_str(&format!(
                " draft/multiline=max-bytes={},max-lines={}",
                crate::connection::draft_multiline::MAX_BYTES,
                crate::connection::draft_multiline::MAX_LINES,
            ));
            if let Some(ref iroh_id) = *state.server_iroh_id.lock() {
                caps.push_str(&format!(" iroh={iroh_id}"));
            }
            let reply =
                Message::from_server(server_name, "CAP", vec![conn.nick_or_star(), "LS", &caps]);
            send(state, session_id, format!("{reply}\r\n"));
        }
        Some("REQ") => {
            if let Some(caps) = msg.params.get(1) {
                let requested: Vec<&str> = caps.split_whitespace().collect();
                let mut acked = Vec::new();
                let mut all_ok = true;

                for cap in &requested {
                    match cap.to_ascii_lowercase().as_str() {
                        "sasl" => {
                            conn.cap_sasl_requested = true;
                            acked.push("sasl");
                        }
                        "message-tags" => {
                            conn.cap_message_tags = true;
                            state.cap_message_tags.lock().insert(session_id.to_string());
                            acked.push("message-tags");
                        }
                        "multi-prefix" => {
                            conn.cap_multi_prefix = true;
                            state.cap_multi_prefix.lock().insert(session_id.to_string());
                            acked.push("multi-prefix");
                        }
                        "echo-message" => {
                            conn.cap_echo_message = true;
                            state.cap_echo_message.lock().insert(session_id.to_string());
                            acked.push("echo-message");
                        }
                        "server-time" => {
                            conn.cap_server_time = true;
                            state.cap_server_time.lock().insert(session_id.to_string());
                            acked.push("server-time");
                        }
                        "batch" => {
                            conn.cap_batch = true;
                            state.cap_batch.lock().insert(session_id.to_string());
                            acked.push("batch");
                        }
                        "freeq.at/msgsig" => {
                            // Acknowledged so a client can confirm the server
                            // understands document signatures; nothing to
                            // track, since each signature declares its own
                            // format.
                            acked.push("freeq.at/msgsig");
                        }
                        "draft/multiline" => {
                            // Per spec, `draft/multiline` depends on `batch`.
                            // The spec doesn't strictly require us to enforce
                            // negotiation order, but we soft-warn: if the client
                            // hasn't also requested batch in the same REQ
                            // (or earlier), they can ACK multiline but it
                            // won't work until batch is also negotiated. We
                            // still ACK it so the client knows we support it.
                            conn.cap_draft_multiline = true;
                            state
                                .cap_draft_multiline
                                .lock()
                                .insert(session_id.to_string());
                            acked.push("draft/multiline");
                        }
                        "draft/chathistory" => {
                            conn.cap_chathistory = true;
                            acked.push("draft/chathistory");
                        }
                        "account-notify" => {
                            conn.cap_account_notify = true;
                            state
                                .cap_account_notify
                                .lock()
                                .insert(session_id.to_string());
                            acked.push("account-notify");
                        }
                        "account-tag" => {
                            conn.cap_account_tag = true;
                            state.cap_account_tag.lock().insert(session_id.to_string());
                            acked.push("account-tag");
                        }
                        "extended-join" => {
                            conn.cap_extended_join = true;
                            state
                                .cap_extended_join
                                .lock()
                                .insert(session_id.to_string());
                            acked.push("extended-join");
                        }
                        "away-notify" => {
                            conn.cap_away_notify = true;
                            state.cap_away_notify.lock().insert(session_id.to_string());
                            acked.push("away-notify");
                        }
                        "freeq.at/act" => {
                            conn.cap_act = true;
                            state.cap_act.lock().insert(session_id.to_string());
                            acked.push("freeq.at/act");
                        }
                        "draft/read-marker" => {
                            conn.cap_read_marker = true;
                            state.cap_read_marker.lock().insert(session_id.to_string());
                            acked.push("draft/read-marker");
                        }
                        _ => {
                            all_ok = false;
                        }
                    }
                }

                if all_ok && !acked.is_empty() {
                    let ack_str = acked.join(" ");
                    let reply = Message::from_server(
                        server_name,
                        "CAP",
                        vec![conn.nick_or_star(), "ACK", &ack_str],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                } else {
                    let reply = Message::from_server(
                        server_name,
                        "CAP",
                        vec![conn.nick_or_star(), "NAK", caps],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                }
            }
        }
        Some("END") => {
            conn.cap_negotiating = false;
            try_complete_registration(conn, state, server_name, session_id, send);
        }
        _ => {}
    }
}

/// A DID as the wire may carry it: `did:` plus printable ASCII.
fn is_wire_did(s: &str) -> bool {
    s.starts_with("did:") && s.len() > 4 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Handles the case where the allowlist has never heard of an agent's own
/// `did:key` but the owner it names claims it and is allowed.
async fn delegated_admit(
    state: &Arc<SharedState>,
    session_id: &str,
    agent_did: &str,
    owner_did: Option<&str>,
) -> Result<(), String> {
    let Some(owner) = owner_did else {
        return Err("no owner named".to_string());
    };
    if !is_wire_did(owner) {
        return Err("owner_did is not a DID".to_string());
    }
    if !state.config.allow_delegated_agents {
        return Err("this server does not admit delegated agents".to_string());
    }
    if !agent_did.starts_with("did:key:") {
        return Err("only an agent with a did:key can be delegated".to_string());
    }
    if owner.starts_with("did:key:") {
        return Err("an owner must be an account with a repository".to_string());
    }
    let refusal = format!("the agent records of {owner} do not admit this agent");
    if !state.did_is_allowed_resolved(owner, None).await {
        tracing::warn!(agent = %agent_did, %owner, "delegated connect refused: the owner is not allowed here");
        return Err(refusal);
    }
    let links = super::provenance::read_owner_links(state, owner)
        .await
        .map_err(|e| {
            tracing::warn!(agent = %agent_did, %owner, error = %e, "delegated connect: could not read the owner's agent records");
            format!("could not read the agent records of {owner}")
        })?;
    let Some(link) = links.into_iter().find(|l| l.link.agent_did == agent_did) else {
        tracing::warn!(agent = %agent_did, %owner, "delegated connect refused: the owner's records do not name the agent");
        return Err(refusal);
    };
    let key = (owner.to_string(), agent_did.to_string());
    state
        .agent_links
        .lock()
        .insert(key.clone(), (std::time::Instant::now(), link.uri.clone()));
    state
        .delegated_sessions
        .lock()
        .insert(session_id.to_string(), key);
    tracing::info!(
        agent = %agent_did, %owner, uri = %link.uri,
        "admitting an agent on its owner's agent record"
    );
    Ok(())
}

pub(super) async fn handle_authenticate(
    conn: &mut Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let param = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    if conn.sasl_failures >= 3 {
        // Already sent ERROR for too many failures; ignore further AUTHENTICATE attempts.
        return;
    }

    if param == "*" {
        // SASL abort — client is cancelling the authentication attempt
        conn.sasl_in_progress = false;
        conn.sasl_response_buf.clear();
        let fail = Message::from_server(
            server_name,
            irc::ERR_SASLFAIL,
            vec![conn.nick_or_star(), "SASL authentication aborted"],
        );
        send(state, session_id, format!("{fail}\r\n"));
        return;
    }

    // Handles a stray terminator with nothing to end, after a short chunk or a
    // re-issued challenge.
    if param == "+" && conn.sasl_response_buf.is_empty() {
        return;
    }

    if param.eq_ignore_ascii_case("ATPROTO-CHALLENGE") {
        conn.sasl_in_progress = true;
        conn.dpop_retries = 0; // Reset DPoP retry counter on new SASL attempt
        conn.sasl_response_buf.clear();
        let encoded = state.challenge_store.create(session_id);
        let reply = Message::new("AUTHENTICATE", vec![&encoded]);
        send(state, session_id, format!("{reply}\r\n"));
    } else if conn.sasl_in_progress {
        let full = match accumulate_response(conn, param) {
            Reassembly::Partial => return,
            Reassembly::TooLong => {
                conn.sasl_in_progress = false;
                conn.sasl_failures += 1;
                crate::server::Metrics::bump(&state.metrics.sasl_failure_total);
                let fail = Message::from_server(
                    server_name,
                    irc::ERR_SASLFAIL,
                    vec![conn.nick_or_star(), "SASL response too long"],
                );
                send(state, session_id, format!("{fail}\r\n"));
                tracing::warn!(%session_id, "SASL response exceeded the reassembly limit");
                close_after_too_many_failures(conn, state, session_id, send);
                return;
            }
            Reassembly::Complete(full) => full,
        };
        let param = full.as_str();
        let decoded = sasl::decode_response_explained(param);
        if let Ok(response) = decoded {
            // Check for web-token method first (server-side OAuth pre-verified)
            let mut web_handle: Option<String> = None;
            let web_token_result = if response.method.as_deref() == Some("web-token") {
                let mut tokens = state.web_auth_tokens.lock();
                if let Some((did, handle, created, broker_token)) =
                    tokens.remove(&response.signature)
                {
                    // Single-use: token consumed on first authentication.
                    // 5-minute TTL limits exposure if a token is leaked.
                    // Broker issues fresh tokens on each /session call for reconnects.
                    if created.elapsed() < std::time::Duration::from_secs(300) {
                        web_handle = Some(handle);
                        // Keep the login token behind this connection, so a
                        // key it registers can be tied back to it.
                        conn.broker_token = broker_token;
                        Some(Ok(did.clone()))
                    } else {
                        Some(Err("Web auth token expired".to_string()))
                    }
                } else {
                    Some(Err("Invalid web auth token".to_string()))
                }
            } else {
                None
            };

            let taken = state.challenge_store.take(session_id);
            match taken {
                Some((challenge, challenge_bytes)) => {
                    let verify_result = if let Some(result) = web_token_result {
                        result
                    } else {
                        sasl::verify_response(
                            &challenge,
                            &challenge_bytes,
                            &response,
                            &state.did_resolver,
                        )
                        .await
                    };
                    // An agent the allowlist does not know may still come in on
                    // the owner it names.
                    let mut refusal = "Not authorized to connect to this server".to_string();
                    let mut delegated = false;
                    // Connect-time allowlist, if the instance opted in. A web
                    // token brings its handle along; the challenge path doesn't.
                    let allowed = match &verify_result {
                        Ok(did) => {
                            state
                                .did_is_allowed_resolved(did, web_handle.as_deref())
                                .await
                                || match delegated_admit(
                                    state,
                                    session_id,
                                    did,
                                    response.owner_did.as_deref(),
                                )
                                .await
                                {
                                    Ok(()) => {
                                        delegated = true;
                                        true
                                    }
                                    Err(reason) => {
                                        if response.owner_did.is_some() {
                                            refusal = format!("{refusal}: {reason}");
                                        }
                                        false
                                    }
                                }
                        }
                        Err(_) => true,
                    };
                    match verify_result {
                        Ok(did) if !allowed => {
                            conn.sasl_in_progress = false;
                            conn.sasl_failures += 1;
                            crate::server::Metrics::bump(&state.metrics.sasl_failure_total);
                            let fail = Message::from_server(
                                server_name,
                                irc::ERR_SASLFAIL,
                                vec![conn.nick_or_star(), refusal.as_str()],
                            );
                            send(state, session_id, format!("{fail}\r\n"));
                            tracing::warn!(
                                %did,
                                method = response.method.as_deref().unwrap_or("crypto"),
                                "connection denied by connect allowlist"
                            );
                            close_after_too_many_failures(conn, state, session_id, send);
                        }
                        Ok(did) => {
                            // A sign-in with a one-time web token whose login
                            // token is not on file for any key here is a fresh
                            // sign-in (or the first connect of that login since
                            // a restart). One that names no login, as an
                            // older broker sends, counts as fresh too. The
                            // account's device keys are read again from its
                            // data server (the PDS) before the SASL success
                            // reply (903), so the device's own check right
                            // after it reads a copy that holds any sign-out
                            // made since. The read waits no longer than the
                            // server's other key reads; one that fails or runs
                            // out of time leaves the saved copy as it was.
                            if response.method.as_deref() == Some("web-token") {
                                let unseen = match conn.broker_token.as_deref() {
                                    Some(token) => {
                                        !state.device_key_tokens.lock().values().any(|t| t == token)
                                    }
                                    None => true,
                                };
                                if unseen {
                                    let listed = tokio::time::timeout(
                                        crate::peer_keys::FETCH_TIMEOUT,
                                        state.key_lookup.reader().list_record_entries(
                                            &did,
                                            freeq_sdk::identity_records::DEVICE_KEY_TYPE,
                                            None,
                                        ),
                                    )
                                    .await;
                                    match listed {
                                        Ok(Ok(_)) => {}
                                        Ok(Err(e)) => {
                                            tracing::debug!(%did, error = %e, "Could not read the account's device keys at a new login");
                                        }
                                        Err(_) => {
                                            tracing::debug!(%did, "The account's device keys did not answer in time at a new login");
                                        }
                                    }
                                }
                            }
                            conn.authenticated_did = Some(did.clone());
                            conn.sasl_in_progress = false;
                            // Handles a connection that was let in on an owner's record and
                            // has since authenticated as a DID the allowlist accepts directly.
                            if !delegated {
                                state.delegated_sessions.lock().remove(session_id);
                            }
                            state
                                .session_dids
                                .lock()
                                .insert(session_id.to_string(), did.clone());

                            // Attach to existing sessions with same DID (multi-device).
                            // If no existing sessions, this just registers the nick normally.
                            super::registration::attach_same_did(conn, state, session_id, send);

                            // Bind nick to DID (in-memory + persistent),
                            // ownership-preserving. A nick stashed during the
                            // CAP/SASL negotiation window may be owned by a
                            // different DID; bind_identity refuses that case
                            // so the in-memory maps + DB stay consistent and
                            // the existing registration force-rename handles
                            // the session.
                            if let Some(ref nick) = conn.nick {
                                match state.bind_identity(&did, nick) {
                                    crate::server::BindOutcome::Bound => {
                                        let nick_l = nick.to_lowercase();
                                        let did_c = did.clone();
                                        let state_c = Arc::clone(state);
                                        tokio::spawn(async move {
                                            state_c.crdt_set_nick_owner(&nick_l, &did_c).await;
                                        });
                                    }
                                    crate::server::BindOutcome::ConflictOwnedByOther {
                                        owner_did,
                                    } => {
                                        tracing::warn!(
                                            %session_id, %did, nick = %nick,
                                            %owner_did,
                                            "SASL bind refused: nick owned by another DID (will be force-renamed at registration)"
                                        );
                                    }
                                }
                            }

                            // Resolve handle from DID document for WHOIS display,
                            // then run plugins with the resolved handle.
                            {
                                let did_clone = did.clone();
                                let state_clone = Arc::clone(state);
                                let sid = session_id.to_string();
                                let nick_for_plugin = conn.nick.clone().unwrap_or_default();
                                tokio::spawn(async move {
                                    let mut resolved_handle: Option<String> = None;
                                    if let Ok(doc) =
                                        state_clone.did_resolver.resolve(&did_clone).await
                                    {
                                        for aka in &doc.also_known_as {
                                            if let Some(handle) = aka.strip_prefix("at://") {
                                                resolved_handle = Some(handle.to_string());
                                                state_clone
                                                    .session_handles
                                                    .lock()
                                                    .insert(sid.clone(), handle.to_string());
                                                break;
                                            }
                                        }
                                    }

                                    // Run plugins after handle resolution
                                    let auth_event = crate::plugin::AuthEvent {
                                        did: did_clone.clone(),
                                        handle: resolved_handle,
                                        nick: nick_for_plugin,
                                        session_id: sid.clone(),
                                    };
                                    let result = state_clone.plugin_manager.on_auth(&auth_event);
                                    if let Some(override_did) = result.override_did {
                                        state_clone
                                            .session_dids
                                            .lock()
                                            .insert(sid.clone(), override_did);
                                    }
                                    if let Some(override_handle) = result.override_handle {
                                        state_clone
                                            .session_handles
                                            .lock()
                                            .insert(sid.clone(), override_handle);
                                    }
                                });
                            }

                            let nick = conn.nick_or_star().to_string();

                            // Auto-OPER for configured DIDs (before using nick ref)
                            if state.config.oper_dids.iter().any(|d| d == &did) {
                                conn.is_oper = true;
                                state.server_opers.lock().insert(session_id.to_string());
                                let oper_notice =
                                    Message::from_server(server_name, "MODE", vec![&nick, "+o"]);
                                send(state, session_id, format!("{oper_notice}\r\n"));
                                tracing::info!(%did, nick = %nick, "Auto-OPER granted via oper_dids config");
                            }

                            let hostmask = conn.hostmask();
                            let logged_in = Message::from_server(
                                server_name,
                                irc::RPL_LOGGEDIN,
                                vec![
                                    &nick,
                                    &hostmask,
                                    &did,
                                    &format!("You are now logged in as {did}"),
                                ],
                            );
                            send(state, session_id, format!("{logged_in}\r\n"));

                            let success = Message::from_server(
                                server_name,
                                irc::RPL_SASLSUCCESS,
                                vec![&nick, "SASL authentication successful"],
                            );
                            send(state, session_id, format!("{success}\r\n"));
                            tracing::info!(%session_id, %did, nick = %nick, "SASL authentication successful");
                            crate::server::Metrics::bump(&state.metrics.sasl_success_total);

                            // Surface the API bearer for this connection so the
                            // bot can hit /agent/tools/* with the same identity
                            // it just authenticated to IRC with. Without this,
                            // bots have no way to discover their own session_id
                            // and every diagnostic call comes in as anonymous.
                            //
                            // Format: `NOTICE * :API-BEARER <session_id>` — chosen
                            // so it's a single greppable line that doesn't collide
                            // with any standard IRC numeric or NOTICE format.
                            // Clients that don't need the bearer can ignore it
                            // (their pre-existing notice handling will display
                            // it as a server message; harmless).
                            let bearer_notice = Message::from_server(
                                server_name,
                                "NOTICE",
                                vec!["*", &format!("API-BEARER {session_id}")],
                            );
                            send(state, session_id, format!("{bearer_notice}\r\n"));

                            // Broadcast account-notify to shared channels
                            broadcast_account_notify(state, session_id, &nick, &did);
                        }
                        Err(reason) if reason.starts_with("DPOP_NONCE:") => {
                            conn.dpop_retries += 1;
                            if conn.dpop_retries > 3 {
                                tracing::warn!(%session_id, retries = conn.dpop_retries, "DPoP nonce retry limit exceeded");
                                conn.sasl_in_progress = false;
                                conn.sasl_failures += 1;
                                crate::server::Metrics::bump(&state.metrics.sasl_failure_total);
                                let fail = Message::from_server(
                                    server_name,
                                    irc::ERR_SASLFAIL,
                                    vec![
                                        conn.nick_or_star(),
                                        "SASL authentication failed (DPoP nonce retry limit exceeded)",
                                    ],
                                );
                                send(state, session_id, format!("{fail}\r\n"));
                                close_after_too_many_failures(conn, state, session_id, send);
                            } else {
                                // DPoP nonce rotation: PDS requires a fresh nonce.
                                // Re-issue a challenge so the client can retry with the nonce.
                                let nonce = &reason["DPOP_NONCE:".len()..];
                                tracing::info!(%session_id, %nonce, retry = conn.dpop_retries, "DPoP nonce required, re-issuing challenge");

                                send(
                                    state,
                                    session_id,
                                    format!(
                                        ":{server_name} NOTICE {} :DPOP_NONCE {nonce}\r\n",
                                        conn.nick_or_star()
                                    ),
                                );

                                // Issue a new challenge for retry
                                let encoded = state.challenge_store.create(session_id);
                                send(state, session_id, format!("AUTHENTICATE {encoded}\r\n"));
                            }
                        }
                        Err(reason) => {
                            tracing::warn!(%session_id, "SASL auth failed: {reason}");
                            conn.sasl_in_progress = false;
                            conn.sasl_failures += 1;
                            crate::server::Metrics::bump(&state.metrics.sasl_failure_total);
                            let fail = Message::from_server(
                                server_name,
                                irc::ERR_SASLFAIL,
                                vec![conn.nick_or_star(), "SASL authentication failed"],
                            );
                            send(state, session_id, format!("{fail}\r\n"));
                            close_after_too_many_failures(conn, state, session_id, send);
                        }
                    }
                }
                None => {
                    conn.sasl_in_progress = false;
                    let fail = Message::from_server(
                        server_name,
                        irc::ERR_SASLFAIL,
                        vec![
                            conn.nick_or_star(),
                            "SASL authentication failed (no challenge)",
                        ],
                    );
                    send(state, session_id, format!("{fail}\r\n"));
                }
            }
        } else {
            conn.sasl_in_progress = false;
            // Say what was wrong with it: a bare "bad response" reads as "your
            // signature is wrong" and sent agents in circles (sasl.rs).
            let why = decoded.err().unwrap_or_default();
            let text = format!("SASL authentication failed (bad response: {why})");
            let fail = Message::from_server(
                server_name,
                irc::ERR_SASLFAIL,
                vec![conn.nick_or_star(), &text],
            );
            send(state, session_id, format!("{fail}\r\n"));
        }
    } else {
        let fail = Message::from_server(
            server_name,
            irc::ERR_SASLFAIL,
            vec![conn.nick_or_star(), "Unsupported SASL mechanism"],
        );
        send(state, session_id, format!("{fail}\r\n"));
    }
}

#[cfg(test)]
mod sasl_reassembly_tests {
    use super::*;

    fn conn() -> Connection {
        Connection::new("sess-1".to_string())
    }

    fn complete(r: Reassembly) -> Option<String> {
        match r {
            Reassembly::Complete(s) => Some(s),
            _ => None,
        }
    }

    #[test]
    fn a_response_shorter_than_a_chunk_arrives_whole() {
        let mut c = conn();
        assert_eq!(
            complete(accumulate_response(&mut c, "abc")),
            Some("abc".to_string())
        );
        assert!(c.sasl_response_buf.is_empty());
    }

    #[test]
    fn a_full_chunk_waits_for_more() {
        let mut c = conn();
        let chunk = "x".repeat(SASL_CHUNK_LEN);
        assert!(matches!(
            accumulate_response(&mut c, &chunk),
            Reassembly::Partial
        ));
        assert_eq!(c.sasl_response_buf.len(), SASL_CHUNK_LEN);
    }

    #[test]
    fn pieces_are_joined_in_order() {
        let mut c = conn();
        let first = "a".repeat(SASL_CHUNK_LEN);
        accumulate_response(&mut c, &first);
        let joined = complete(accumulate_response(&mut c, "bbb")).unwrap();
        assert_eq!(joined, format!("{first}bbb"));
        assert!(c.sasl_response_buf.is_empty());
    }

    #[test]
    fn a_bare_plus_ends_a_response_that_fills_its_last_chunk() {
        let mut c = conn();
        let chunk = "y".repeat(SASL_CHUNK_LEN);
        accumulate_response(&mut c, &chunk);
        assert_eq!(complete(accumulate_response(&mut c, "+")), Some(chunk));
    }

    #[test]
    fn an_endless_stream_is_refused_and_dropped() {
        let mut c = conn();
        let chunk = "z".repeat(SASL_CHUNK_LEN);
        let mut refused = false;
        for _ in 0..(MAX_SASL_RESPONSE_LEN / SASL_CHUNK_LEN + 2) {
            if matches!(accumulate_response(&mut c, &chunk), Reassembly::TooLong) {
                refused = true;
                break;
            }
        }
        assert!(refused, "an unbounded stream of chunks must be refused");
        assert!(c.sasl_response_buf.is_empty());
    }
}

#[cfg(test)]
mod delegated_admit_tests {
    use super::*;
    use freeq_sdk::crypto::PrivateKey;
    use freeq_sdk::identity_records::{
        AGENT_KEY_TYPE, DEVICE_KEY_TYPE, build_agent_record, build_agent_retirement,
        build_device_record,
    };
    use freeq_sdk::test_support::StubRepo;

    const AGENT: &str = "did:key:z6MkAgent";
    const OTHER_AGENT: &str = "did:key:z6MkOther";
    const OWNER: &str = "did:plc:owner";
    const STRANGER: &str = "did:plc:stranger";

    fn hours_ago(hours: i64) -> String {
        static NOW: std::sync::LazyLock<chrono::DateTime<chrono::Utc>> =
            std::sync::LazyLock::new(chrono::Utc::now);
        (*NOW - chrono::TimeDelta::hours(hours))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    fn owner_key() -> PrivateKey {
        PrivateKey::ed25519_from_bytes(&[62; 32]).unwrap()
    }

    fn value(record: &impl serde::Serialize) -> serde_json::Value {
        serde_json::to_value(record).unwrap()
    }

    fn claim(owner: &str, bot: &str, hours: i64) -> serde_json::Value {
        value(&build_agent_record(&owner_key(), owner, bot, &hours_ago(hours), None).unwrap())
    }

    fn removal(owner: &str, bot: &str, hours: i64) -> serde_json::Value {
        value(&build_agent_retirement(&owner_key(), owner, bot, &hours_ago(hours)).unwrap())
    }

    /// `owner`'s repository, holding their device record and `agents`.
    fn repo_of(owner: &str, agents: &[serde_json::Value]) -> Arc<parking_lot::Mutex<StubRepo>> {
        let mut repo = StubRepo::new(owner);
        repo.add(
            DEVICE_KEY_TYPE,
            &value(&build_device_record(&owner_key(), owner, &hours_ago(48), None).unwrap()),
        );
        for record in agents {
            repo.add(AGENT_KEY_TYPE, record);
        }
        Arc::new(parking_lot::Mutex::new(repo))
    }

    /// An instance that allows `allowed` and nobody else, serving `repos`.
    async fn state_allowing(
        allow_delegated: bool,
        allowed: &[&str],
        repos: Vec<Arc<parking_lot::Mutex<StubRepo>>>,
    ) -> Arc<SharedState> {
        let pds = crate::peer_keys::stub_pds_repos(repos).await;
        let state = crate::server::test_state_with_resolver(
            crate::config::ServerConfig {
                allowed_dids: allowed.iter().map(|d| d.to_string()).collect(),
                allow_delegated_agents: allow_delegated,
                ..Default::default()
            },
            pds.resolver.clone(),
        );
        state
            .owner_read_reuse_ms
            .store(0, std::sync::atomic::Ordering::SeqCst);
        state
    }

    async fn state_allowing_owner(
        allow_delegated: bool,
        repos: Vec<Arc<parking_lot::Mutex<StubRepo>>>,
    ) -> Arc<SharedState> {
        state_allowing(allow_delegated, &[OWNER], repos).await
    }

    async fn admit(state: &Arc<SharedState>, owner: Option<&str>) -> Result<(), String> {
        delegated_admit(state, "sess-1", AGENT, owner).await
    }

    #[tokio::test]
    async fn an_agent_its_allowed_owner_claims_is_admitted_and_kept_for_the_recheck() {
        let repo = repo_of(OWNER, &[claim(OWNER, OTHER_AGENT, 20)]);
        let own = repo.lock().add(AGENT_KEY_TYPE, &claim(OWNER, AGENT, 24));
        let state = state_allowing_owner(true, vec![repo]).await;
        assert_eq!(admit(&state, Some(OWNER)).await, Ok(()));
        let key = (OWNER.to_string(), AGENT.to_string());
        assert_eq!(state.delegated_sessions.lock().get("sess-1"), Some(&key));
        let kept = state
            .agent_links
            .lock()
            .get(&key)
            .map(|(_, uri)| uri.clone());
        assert_eq!(kept.as_deref(), Some(own.as_str()));
    }

    /// The attack this exists to stop: naming an allowed owner who has not
    /// claimed you.
    #[tokio::test]
    async fn an_owner_whose_records_name_other_agents_admits_nobody() {
        let state =
            state_allowing_owner(true, vec![repo_of(OWNER, &[claim(OWNER, OTHER_AGENT, 24)])])
                .await;
        let refused = admit(&state, Some(OWNER)).await.unwrap_err();
        assert!(refused.contains("do not admit this agent"), "{refused}");
        assert!(state.delegated_sessions.lock().is_empty());
    }

    #[tokio::test]
    async fn a_claim_the_owner_withdrew_admits_nobody() {
        let records = [claim(OWNER, AGENT, 24), removal(OWNER, AGENT, 12)];
        let state = state_allowing_owner(true, vec![repo_of(OWNER, &records)]).await;
        let refused = admit(&state, Some(OWNER)).await.unwrap_err();
        assert!(refused.contains("do not admit this agent"), "{refused}");
    }

    /// A record lifted into the listing without the repository's proof.
    #[tokio::test]
    async fn a_claim_whose_proof_fails_admits_nobody() {
        let repo = repo_of(OWNER, &[]);
        repo.lock().add_forged(
            AGENT_KEY_TYPE,
            &claim(OWNER, AGENT, 24),
            &claim(OWNER, OTHER_AGENT, 30),
        );
        let state = state_allowing_owner(true, vec![repo]).await;
        let refused = admit(&state, Some(OWNER)).await.unwrap_err();
        assert!(refused.contains("do not admit this agent"), "{refused}");
    }

    /// Delegation carries the owner's standing, so it cannot exceed it.
    #[tokio::test]
    async fn a_claim_from_an_owner_who_is_not_allowed_admits_nobody() {
        let state =
            state_allowing_owner(true, vec![repo_of(STRANGER, &[claim(STRANGER, AGENT, 24)])])
                .await;
        let refused = admit(&state, Some(STRANGER)).await.unwrap_err();
        assert!(refused.contains("do not admit this agent"), "{refused}");
    }

    #[tokio::test]
    async fn an_owner_who_is_not_allowed_is_not_read() {
        let pds = crate::peer_keys::stub_pds_repos(vec![repo_of(
            STRANGER,
            &[claim(STRANGER, AGENT, 24)],
        )])
        .await;
        let state = crate::server::test_state_with_resolver(
            crate::config::ServerConfig {
                allowed_dids: vec![OWNER.to_string()],
                allow_delegated_agents: true,
                ..Default::default()
            },
            pds.resolver.clone(),
        );
        assert!(admit(&state, Some(STRANGER)).await.is_err());
        assert_eq!(pds.arrivals.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_owner_that_is_not_a_did_is_refused_before_anything_else() {
        let state = state_allowing_owner(true, vec![]).await;
        for owner in [
            "alice.example",
            "did:",
            "did:plc:bad\r\nQUIT",
            "did:plc:with space",
        ] {
            let refused = admit(&state, Some(owner)).await.unwrap_err();
            assert!(refused.contains("not a DID"), "{owner:?}: {refused}");
        }
    }

    #[tokio::test]
    async fn the_instance_must_opt_in() {
        let state =
            state_allowing_owner(false, vec![repo_of(OWNER, &[claim(OWNER, AGENT, 24)])]).await;
        let refused = admit(&state, Some(OWNER)).await.unwrap_err();
        assert!(refused.contains("does not admit"), "{refused}");
    }

    #[tokio::test]
    async fn an_agent_naming_no_owner_admits_nobody() {
        let state = state_allowing_owner(true, vec![]).await;
        assert!(admit(&state, None).await.is_err());
    }

    /// A did:key has no repository to read.
    #[tokio::test]
    async fn an_agent_naming_itself_admits_nobody() {
        let state = state_allowing(true, &[AGENT], vec![]).await;
        let refused = admit(&state, Some(AGENT)).await.unwrap_err();
        assert!(refused.contains("account with a repository"), "{refused}");
    }

    #[tokio::test]
    async fn only_an_agent_with_a_did_key_is_delegated() {
        let person = "did:plc:someone";
        let state =
            state_allowing_owner(true, vec![repo_of(OWNER, &[claim(OWNER, person, 24)])]).await;
        let refused = delegated_admit(&state, "sess-1", person, Some(OWNER))
            .await
            .unwrap_err();
        assert!(refused.contains("did:key"), "{refused}");
    }

    #[tokio::test]
    async fn a_refusal_does_not_say_whether_the_named_owner_is_allowed() {
        let allowed = state_allowing_owner(true, vec![repo_of(OWNER, &[])]).await;
        let not_allowed = state_allowing(true, &[STRANGER], vec![repo_of(OWNER, &[])]).await;
        assert_eq!(
            admit(&allowed, Some(OWNER)).await,
            admit(&not_allowed, Some(OWNER)).await
        );
    }
}
