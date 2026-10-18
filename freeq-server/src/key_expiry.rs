//! Closing connections whose signing key has expired or was retired.
//!
//! A key's row says when it expires (`signing_keys.expires_at`) and, once the
//! key is signed out, when it was retired (`signing_keys.removed_at`). A
//! device is refused at registration once its key has expired or is marked
//! retired; one that stays connected across either is found here, once a
//! minute, and closed the way a device signed out from elsewhere is
//! (`web::api_device_sign_out`), with the words the web shows so it lands on
//! sign-in. It is also refused the same way at its next `PRIVMSG`, `NOTICE`,
//! `BATCH` or signed `TAGMSG`, which the read loop checks with
//! `refuse_if_retired_or_expired`; a `TAGMSG` without the client's signature
//! is not checked.

use std::sync::Arc;
use std::time::Duration;

use crate::server::SharedState;

/// How often connected keys are checked against their expiry and their
/// row's retirement mark.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// The configured lifetime of a key this server files, in seconds.
pub fn lifetime_secs(state: &SharedState) -> i64 {
    i64::try_from(state.config.signing_key_lifetime_days)
        .unwrap_or(i64::MAX / 86_400)
        .saturating_mul(24 * 60 * 60)
}

/// Sweep at start and every minute after. A server with no database files
/// no expiries, so it runs nothing.
pub fn spawn(state: Arc<SharedState>) {
    if state.db.is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            sweep(&state).await;
            tokio::time::sleep(SWEEP_EVERY).await;
        }
    });
}

/// Close every connection whose registered key has reached its expiry or is
/// marked retired, with [`refuse_if_retired_or_expired`]. Returns how many
/// were refused.
pub async fn sweep(state: &Arc<SharedState>) -> usize {
    if state.db.is_none() {
        return 0;
    }
    let connected: Vec<(String, String, String)> = {
        let dids = state.session_dids.lock();
        let keys = state.session_msg_keys.lock();
        keys.iter()
            .filter_map(|(sid, vk)| {
                dids.get(sid)
                    .map(|did| (sid.clone(), did.clone(), freeq_sdk::sigtag::derive_kid(vk)))
            })
            .collect()
    };
    let mut refused = 0;
    for (sid, did, kid) in connected {
        if refuse_if_retired_or_expired(state, &sid, &did, &kid)
            .await
            .is_some()
        {
            refused += 1;
        }
    }
    refused
}

/// If the key `kid` that session `sid` registered under `did` is marked
/// retired on its row, whatever the date, or has reached its expiry: send
/// `FAIL MSGSIG KEY_RETIRED` or `KEY_EXPIRED`, as registration does, drop the
/// session's key (so a close that finds the session already gone is not
/// refused again), end the login token behind the key, and close the
/// session. Returns how many login tokens it ended, or `None` when it did not
/// refuse. The once-a-minute sweep calls it for every connected key, the read
/// loop for each message line from a session holding a key, and the sign-out
/// route for each session of the key it signs out.
pub async fn refuse_if_retired_or_expired(
    state: &Arc<SharedState>,
    sid: &str,
    did: &str,
    kid: &str,
) -> Option<usize> {
    let now = chrono::Utc::now().timestamp();
    let row = state
        .with_db(|db| db.get_signing_key_row(did, kid))
        .flatten();
    let (code, words, reason) = match row {
        Some(row) if row.removed_at.is_some() => (
            "KEY_RETIRED",
            crate::connection::KEY_RETIRED_WORDS,
            "Signing key retired",
        ),
        Some(row) if row.expired_at(now) => (
            "KEY_EXPIRED",
            crate::connection::KEY_EXPIRED_WORDS,
            "Signing key expired",
        ),
        _ => return None,
    };
    // The session may have registered another key since it was listed.
    {
        let mut keys = state.session_msg_keys.lock();
        let still_this_key = keys
            .get(sid)
            .is_some_and(|vk| freeq_sdk::sigtag::derive_kid(vk) == kid);
        if !still_this_key {
            return None;
        }
        keys.remove(sid);
    }
    let reply =
        crate::irc::Message::from_server(&state.server_name, "FAIL", vec!["MSGSIG", code, words]);
    if let Some(tx) = state.connections.lock().get(sid) {
        let _ = tx.try_send(format!("{reply}\r\n"));
    }
    let ended = end_login_tokens_of_key(state, did, kid).await;
    crate::connection::close_session(state, sid, reason);
    if code == "KEY_RETIRED" {
        tracing::info!(session = %sid, %did, %kid, "Closed a session whose signing key was retired");
    } else {
        tracing::info!(session = %sid, %did, %kid, "Closed a session whose signing key expired");
    }
    Some(ended)
}

/// End the login token filed for `did`'s key `kid` when a connection
/// registered it, and drop it from the map. Returns how many it ended.
pub(crate) async fn end_login_tokens_of_key(
    state: &Arc<SharedState>,
    did: &str,
    kid: &str,
) -> usize {
    let tokens: Vec<String> = {
        let mut linked = state.device_key_tokens.lock();
        let mut found = Vec::new();
        linked.retain(|(d, k), token| {
            if d == did && k == kid {
                found.push(token.clone());
                false
            } else {
                true
            }
        });
        found
    };
    for token in &tokens {
        crate::connection::end_login_token(state, token).await;
    }
    tokens.len()
}
