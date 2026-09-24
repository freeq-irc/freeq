//! Closing connections whose signing key has expired.
//!
//! A key's row says when it expires (`signing_keys.expires_at`). A device is
//! refused at registration once that date has passed; one that stays
//! connected across it is found here, once a minute, and closed the way a
//! device signed out from elsewhere is (`web::api_device_sign_out`), with the
//! words the web shows so it lands on sign-in.

use std::sync::Arc;
use std::time::Duration;

use crate::server::SharedState;

/// How often connected keys are checked against their expiry.
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

/// Close every connection whose registered key has reached its expiry: send
/// `FAIL MSGSIG KEY_EXPIRED`, drop the session's key (so a close that finds
/// the session already gone is not refused again), end the login token behind
/// the key, and close the session. Returns how many were refused.
pub async fn sweep(state: &Arc<SharedState>) -> usize {
    if state.db.is_none() {
        return 0;
    }
    let now = chrono::Utc::now().timestamp();
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
        let expired = state
            .with_db(|db| db.get_signing_key_row(&did, &kid))
            .flatten()
            .is_some_and(|row| row.expired_at(now));
        if !expired {
            continue;
        }
        // The session may have registered another key since it was listed.
        {
            let mut keys = state.session_msg_keys.lock();
            let still_this_key = keys
                .get(&sid)
                .is_some_and(|vk| freeq_sdk::sigtag::derive_kid(vk) == kid);
            if !still_this_key {
                continue;
            }
            keys.remove(&sid);
        }
        let reply = crate::irc::Message::from_server(
            &state.server_name,
            "FAIL",
            vec![
                "MSGSIG",
                "KEY_EXPIRED",
                crate::connection::KEY_EXPIRED_WORDS,
            ],
        );
        if let Some(tx) = state.connections.lock().get(&sid) {
            let _ = tx.try_send(format!("{reply}\r\n"));
        }
        let tokens: Vec<String> = {
            let mut linked = state.device_key_tokens.lock();
            let mut found = Vec::new();
            linked.retain(|(d, k), token| {
                if d == &did && k == &kid {
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
        crate::connection::close_session(state, &sid, "Signing key expired");
        tracing::info!(session = %sid, %did, %kid, "Closed a session whose signing key expired");
        refused += 1;
    }
    refused
}
