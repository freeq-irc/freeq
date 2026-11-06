//! LOGIN command — browser-based AT Protocol authentication for legacy IRC clients.
//!
//! Flow:
//! 1. User sends `LOGIN <handle>` (e.g., `/login chadfowler.com`)
//! 2. Server generates an OAuth URL and sends it as a NOTICE
//! 3. User opens URL in browser → completes AT Protocol OAuth
//! 4. Server callback detects pending IRC login, binds DID to the session
//! 5. Server sends RPL_SASLSUCCESS (903) and account-notify to the connection

use super::Connection;
use crate::irc::{self, Message};
use crate::server::SharedState;
use std::sync::Arc;

/// Handle the LOGIN command from an IRC client.
pub(super) fn handle_login(
    conn: &mut Connection,
    handle: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star().to_string();

    // Already authenticated?
    if conn.authenticated_did.is_some() {
        let reply = Message::from_server(
            server_name,
            "NOTICE",
            vec![&nick, "You are already authenticated."],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    if handle.is_empty() {
        let reply = Message::from_server(
            server_name,
            "NOTICE",
            vec![
                &nick,
                "Usage: LOGIN <handle> (e.g., LOGIN yourname.bsky.social)",
            ],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Generate a unique state token for this login attempt
    let oauth_state = crate::web::generate_random_string(16);

    // Store the mapping: oauth_state → session_id
    state
        .login_pending
        .lock()
        .insert(oauth_state.clone(), session_id.to_string());

    // Build the login URL — point to our own /auth/login endpoint
    // with a special `irc_state` parameter so the callback knows to complete via IRC
    let web_origin = format!("https://{}", state.server_name);
    let login_url = format!(
        "{}/auth/login?handle={}&irc_state={}",
        web_origin,
        urlencoding::encode(handle),
        urlencoding::encode(&oauth_state),
    );

    let notice1 = Message::from_server(
        server_name,
        "NOTICE",
        vec![
            &nick,
            &format!("To authenticate as @{handle}, open this URL in your browser:"),
        ],
    );
    let notice2 = Message::from_server(server_name, "NOTICE", vec![&nick, &login_url]);
    let notice3 = Message::from_server(
        server_name,
        "NOTICE",
        vec![&nick, "This link expires in 5 minutes."],
    );
    send(state, session_id, format!("{notice1}\r\n"));
    send(state, session_id, format!("{notice2}\r\n"));
    send(state, session_id, format!("{notice3}\r\n"));

    tracing::info!(nick = %nick, handle = %handle, session = %session_id, "LOGIN: OAuth URL sent to client");
}

/// Pending login completion — stored by OAuth callback, consumed by connection loop.
#[derive(Debug, Clone)]
pub struct LoginCompletion {
    pub did: String,
    pub handle: String,
    /// Set when the bind collided and the session was assigned a
    /// deterministic derived nick; the connection loop applies it to
    /// `conn.nick`.
    pub renamed_nick: Option<String>,
}

/// Called from the OAuth callback when `irc_state` is present.
/// Stores the completion and sends a signal to the IRC connection.
pub fn complete_irc_login(state: &Arc<SharedState>, session_id: &str, did: &str, handle: &str) {
    let server_name = &state.server_name;

    // Connect-time allowlist (opt-in). On a restricted instance, reject DIDs
    // that aren't on the allowlist / whose handle domain isn't permitted.
    if !state.did_is_allowed(did, Some(handle)) {
        let text = "Not authorized to connect to this server";
        super::send_fail(
            state,
            session_id,
            &super::send_to,
            "LOGIN",
            freeq_sdk::refusal::NOT_ALLOWED,
            text,
        );
        let fail = Message::from_server(server_name, irc::ERR_SASLFAIL, vec!["*", text]);
        super::send_to(state, session_id, format!("{fail}\r\n"));
        tracing::warn!(%did, %handle, "connection denied by --allowed-dids/--allowed-did-domains");
        return;
    }

    // Store DID and handle in session maps
    state
        .session_dids
        .lock()
        .insert(session_id.to_string(), did.to_string());
    state
        .session_handles
        .lock()
        .insert(session_id.to_string(), handle.to_string());

    // Look up the nick for this session
    let nick = state
        .nick_to_session
        .lock()
        .get_nick(session_id)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "*".to_string());

    // Durably bind the nick to this DID. On collision with a different
    // DID, bind_identity_with_fallback assigns a deterministic derived
    // nick (persisted, resolves offline) instead of the previous
    // in-memory-only overwrite that silently hijacked the nick and was
    // lost on restart.
    let nick_lower = nick.to_lowercase();
    let assigned = state.bind_identity_with_fallback(did, &nick_lower);
    let renamed = assigned != nick_lower;

    let cloak = super::helpers::cloaked_host_for_did(Some(did));
    if renamed {
        // Move the session server-side and tell the client. They are
        // NOT asked to "authenticate" — they just did; the requested
        // nick simply belongs to another identity.
        state.nick_to_session.lock().remove_by_nick(&nick);
        state.nick_to_session.lock().insert(&assigned, session_id);
        let nick_line = format!(":{nick}!~u@{cloak} NICK {assigned}\r\n");
        let renamed_notice = Message::from_server(
            server_name,
            "NOTICE",
            vec![
                &assigned,
                &format!(
                    "{nick} is registered to another identity. You are {assigned} (tied to your account)."
                ),
            ],
        );
        if let Some(tx) = state.connections.lock().get(session_id) {
            let _ = tx.try_send(nick_line);
            let _ = tx.try_send(format!("{renamed_notice}\r\n"));
        }
    }

    // Send success notices to the IRC connection
    let success = Message::from_server(
        server_name,
        irc::RPL_SASLSUCCESS,
        vec![&assigned, "SASL authentication successful"],
    );
    let account_notice = Message::from_server(
        server_name,
        "NOTICE",
        vec![
            &assigned,
            &format!("You are now authenticated as {did} (@{handle})"),
        ],
    );

    if let Some(tx) = state.connections.lock().get(session_id) {
        let _ = tx.try_send(format!("{success}\r\n"));
        let _ = tx.try_send(format!("{account_notice}\r\n"));
    }

    // Store the completion so the connection loop can update
    // conn.authenticated_did (and conn.nick if we renamed).
    state.login_completions.lock().insert(
        session_id.to_string(),
        LoginCompletion {
            did: did.to_string(),
            handle: handle.to_string(),
            renamed_nick: if renamed {
                Some(assigned.clone())
            } else {
                None
            },
        },
    );

    // Broadcast account-notify to channels
    {
        let hostmask = format!("{assigned}!~u@{cloak}");
        let account_line = format!(":{hostmask} ACCOUNT {did}\r\n");
        let channels = state.channels.lock();
        let account_caps = state.cap_account_notify.lock();
        let conns = state.connections.lock();
        for ch in channels.values() {
            if ch.members.contains(session_id) {
                for member_sid in &ch.members {
                    if member_sid != session_id
                        && account_caps.contains(member_sid)
                        && let Some(tx) = conns.get(member_sid)
                    {
                        let _ = tx.try_send(account_line.clone());
                    }
                }
            }
        }
    }

    // Auto-op in channels where the DID is founder or in did_ops
    {
        let mut channels = state.channels.lock();
        let conns = state.connections.lock();
        for (ch_name, ch) in channels.iter_mut() {
            if !ch.members.contains(session_id) {
                continue;
            }
            let should_op = ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did);
            if should_op && !ch.ops.contains(session_id) {
                ch.ops.insert(session_id.to_string());
                // Broadcast MODE +o
                let mode_line = format!(":{} MODE {} +o {}\r\n", server_name, ch_name, assigned);
                for member_sid in &ch.members {
                    if let Some(tx) = conns.get(member_sid) {
                        let _ = tx.try_send(mode_line.clone());
                    }
                }
            }
        }
    }

    tracing::info!(nick = %assigned, did = %did, handle = %handle, session = %session_id, "LOGIN completed via browser OAuth");
}
