#![allow(clippy::too_many_arguments)]
//! CAP capability negotiation and SASL authentication.

use super::Connection;
use super::helpers::broadcast_account_notify;
use super::registration::try_complete_registration;
use crate::irc::{self, Message};
use crate::sasl;
use crate::server::SharedState;
use std::sync::Arc;

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
        let fail = Message::from_server(
            server_name,
            irc::ERR_SASLFAIL,
            vec![conn.nick_or_star(), "SASL authentication aborted"],
        );
        send(state, session_id, format!("{fail}\r\n"));
        return;
    }

    if param.eq_ignore_ascii_case("ATPROTO-CHALLENGE") {
        conn.sasl_in_progress = true;
        conn.dpop_retries = 0; // Reset DPoP retry counter on new SASL attempt
        let encoded = state.challenge_store.create(session_id);
        let reply = Message::new("AUTHENTICATE", vec![&encoded]);
        send(state, session_id, format!("{reply}\r\n"));
    } else if conn.sasl_in_progress {
        if let Some(response) = sasl::decode_response(param) {
            // Check for web-token method first (server-side OAuth pre-verified)
            let mut web_handle: Option<String> = None;
            let web_token_result = if response.method.as_deref() == Some("web-token") {
                let mut tokens = state.web_auth_tokens.lock();
                if let Some((did, handle, created)) = tokens.remove(&response.signature) {
                    // Single-use: token consumed on first authentication.
                    // 5-minute TTL limits exposure if a token is leaked.
                    // Broker issues fresh tokens on each /session call for reconnects.
                    if created.elapsed() < std::time::Duration::from_secs(300) {
                        web_handle = Some(handle);
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
                    // Connect-time allowlist, if the instance opted in. A web
                    // token brings its handle along; the challenge path doesn't.
                    let allowed = match &verify_result {
                        Ok(did) => {
                            state
                                .did_is_allowed_resolved(did, web_handle.as_deref())
                                .await
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
                                vec![
                                    conn.nick_or_star(),
                                    "Not authorized to connect to this server",
                                ],
                            );
                            send(state, session_id, format!("{fail}\r\n"));
                            tracing::warn!(
                                %did,
                                method = response.method.as_deref().unwrap_or("crypto"),
                                "connection denied by connect allowlist"
                            );
                        }
                        Ok(did) => {
                            conn.authenticated_did = Some(did.clone());
                            conn.sasl_in_progress = false;
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
                                if conn.sasl_failures >= 3 {
                                    send(
                                        state,
                                        session_id,
                                        "ERROR :Too many SASL failures\r\n".to_string(),
                                    );
                                    // Drop the send channel to force-close the connection.
                                    state.connections.lock().remove(session_id);
                                }
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
            let fail = Message::from_server(
                server_name,
                irc::ERR_SASLFAIL,
                vec![
                    conn.nick_or_star(),
                    "SASL authentication failed (bad response)",
                ],
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
