//! Ending a signed-out device's login at a standalone broker.
//!
//! Signing a device out writes the hash of its login token, refuses that
//! token here from then on, and asks the broker to delete the session behind
//! it. The two halves are deliberate: the broker's delete is what actually
//! ends the login (its `/enroll` and `/session` never ask this server), and
//! the filed hash is what keeps the refusal true while the broker is
//! unreachable and across a restart.
//!
//! Deliveries run one at a time on a single task, so a token has at most one
//! delete in flight and a queue of them cannot stampede a broker that is
//! already struggling.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::server::SharedState;

/// How long to wait after the first failed delete; doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How long a revocation is kept before it is forgotten.
const KEEP_DAYS: i64 = 90;
/// How often the keep window is applied.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// A broker that does not answer within this is a failure to retry.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A sign-out waiting to reach the broker.
pub struct PendingDelete {
    /// When to try next.
    pub due: Instant,
    /// How long to wait after the next failure.
    pub backoff: Duration,
    pub failures: u32,
}

/// The broker address and the secret to sign with, when a delete can be sent
/// at all. Embedded mode has neither and ends the session in its own store.
fn broker_target(state: &SharedState) -> Option<(String, String)> {
    let url = state.config.auth_broker_url.clone()?;
    let secret = state.config.broker_shared_secret.clone()?;
    Some((url, secret))
}

/// Queue a sign-out for delivery and wake the task. An entry already queued
/// keeps its place, so a repeated sign-out cannot reset a backoff.
pub(crate) fn queue_delete(state: &Arc<SharedState>, hash: String) {
    if broker_target(state).is_none() {
        return;
    }
    state
        .broker_deletes
        .lock()
        .entry(hash)
        .or_insert_with(|| PendingDelete {
            due: Instant::now(),
            backoff: FIRST_BACKOFF,
            failures: 0,
        });
    state.broker_delete_wake.notify_one();
}

/// Start the delivery and pruning task.
pub fn spawn(state: Arc<SharedState>) {
    if state.config.broker_shared_secret.is_some() {
        if state.db.is_none() {
            tracing::warn!(
                "No database configured: device sign-outs are remembered in memory only, \
                 and a restart forgets them"
            );
        }
        if state.config.auth_broker_url.is_none() {
            tracing::warn!(
                "No --auth-broker-url configured: a signed-out device is refused here, \
                 but the session behind it is not deleted at the broker"
            );
        }
    }
    tokio::spawn(async move {
        prune(&state);
        // A sign-out filed before this process started still has a session to
        // end; the hash is all the delete needs.
        let undelivered = state
            .with_db(|db| db.undelivered_broker_token_revocations())
            .unwrap_or_default();
        for hash in undelivered {
            queue_delete(&state, hash);
        }

        let mut prune_at = tokio::time::Instant::now() + PRUNE_EVERY;
        loop {
            let next_due = deliver_due(&state).await;
            let wake_at = match next_due {
                Some(due) => tokio::time::Instant::from_std(due).min(prune_at),
                None => prune_at,
            };
            tokio::select! {
                _ = state.broker_delete_wake.notified() => {}
                _ = tokio::time::sleep_until(wake_at) => {}
            }
            if tokio::time::Instant::now() >= prune_at {
                prune(&state);
                prune_at = tokio::time::Instant::now() + PRUNE_EVERY;
            }
        }
    });
}

/// Send every queued delete that is due, one at a time, and answer when the
/// earliest one still queued comes due.
async fn deliver_due(state: &Arc<SharedState>) -> Option<std::time::Instant> {
    loop {
        let now = Instant::now();
        let due_now = {
            let pending = state.broker_deletes.lock();
            pending
                .iter()
                .find(|(_, p)| p.due <= now)
                .map(|(hash, _)| hash.clone())
        };
        let Some(hash) = due_now else { break };

        match send_delete(state, &hash).await {
            Ok(()) => {
                state.broker_deletes.lock().remove(&hash);
                let at = chrono::Utc::now().timestamp();
                state.with_db(|db| db.mark_broker_token_revocation_delivered(&hash, at));
                tracing::info!("signed-out device's broker session deleted");
            }
            Err(e) => {
                let mut pending = state.broker_deletes.lock();
                if let Some(entry) = pending.get_mut(&hash) {
                    entry.failures += 1;
                    entry.due = Instant::now() + entry.backoff;
                    entry.backoff = (entry.backoff * 2).min(MAX_BACKOFF);
                    if entry.failures == 1 {
                        tracing::info!(
                            error = %e,
                            "could not delete a signed-out device's broker session; retrying"
                        );
                    }
                }
            }
        }
    }
    state.broker_deletes.lock().values().map(|p| p.due).min()
}

/// Ask the broker to delete the session whose token hashes to `hash`.
async fn send_delete(state: &SharedState, hash: &str) -> anyhow::Result<()> {
    let Some((url, secret)) = broker_target(state) else {
        anyhow::bail!("no broker address configured");
    };
    let body = serde_json::json!({ "token_hash": hash });
    let (sig, ts) = freeq_auth_broker::sign_body(&secret, &body)?;
    // The broker's address is operator configuration, not user input, so this
    // call needs no SSRF guard.
    let resp = reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .build()?
        .post(format!("{}/session/delete", url.trim_end_matches('/')))
        .header("X-Broker-Signature", sig)
        .header("X-Broker-Timestamp", ts)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("broker answered {}", resp.status());
    }
    Ok(())
}

/// Forget revocations past the keep window. A row that old outlives any
/// session it could refuse.
fn prune(state: &SharedState) {
    let cutoff = chrono::Utc::now().timestamp() - KEEP_DAYS * 24 * 60 * 60;
    if let Some(forgotten) = state.with_db(|db| db.prune_broker_token_revocations(cutoff))
        && forgotten > 0
    {
        tracing::info!(count = forgotten, "forgot sign-outs past the keep window");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use freeq_auth_broker::token_hash;

    const SECRET: &str = "test-signout-secret";

    #[derive(Default)]
    struct Fake {
        /// The hashes it was asked to delete, in order.
        seen: Vec<String>,
        /// Answer 500 to this many calls before taking them.
        fail_first: usize,
    }

    /// A broker that checks the signature the way the real one does, then
    /// records the hash it was asked to delete.
    async fn fake_broker(cap: Arc<std::sync::Mutex<Fake>>) -> String {
        let app = axum::Router::new().route(
            "/session/delete",
            post(move |headers: HeaderMap, body: Bytes| {
                let cap = cap.clone();
                async move {
                    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
                    if freeq_auth_broker::verify_signed_body(
                        SECRET,
                        header("x-broker-timestamp"),
                        header("x-broker-signature"),
                        &body,
                    )
                    .is_err()
                    {
                        return (axum::http::StatusCode::UNAUTHORIZED, "bad signature")
                            .into_response();
                    }
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let hash = json["token_hash"].as_str().unwrap().to_string();
                    let mut c = cap.lock().unwrap();
                    c.seen.push(hash);
                    if c.fail_first > 0 {
                        c.fail_first -= 1;
                        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "no")
                            .into_response();
                    }
                    axum::Json(serde_json::json!({ "ok": true })).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://127.0.0.1:{port}")
    }

    /// Standalone-broker mode, pointed at `broker_url`.
    fn config(broker_url: Option<&str>) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            broker_shared_secret: Some(SECRET.to_string()),
            auth_broker_url: broker_url.map(str::to_string),
            ..Default::default()
        }
    }

    /// Wait up to five seconds for `cond`.
    async fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        cond()
    }

    /// Wait longer, for a delivery that has to wait out the first backoff.
    async fn wait_through_backoff(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + FIRST_BACKOFF + Duration::from_secs(8);
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        cond()
    }

    fn delivered(state: &Arc<SharedState>, hash: &str) -> Option<Option<i64>> {
        state
            .with_db(|db| db.broker_token_revocation(hash))
            .flatten()
            .map(|(_, delivered_at)| delivered_at)
    }

    #[tokio::test]
    async fn a_sign_out_files_the_hash_and_the_broker_deletes_that_session() {
        let cap = Arc::new(std::sync::Mutex::new(Fake::default()));
        let url = fake_broker(cap.clone()).await;
        let state = crate::server::test_state_with_config(config(Some(&url)));
        spawn(Arc::clone(&state));

        crate::connection::end_login_token(&state, "BT-GONE").await;
        let hash = token_hash("BT-GONE");

        // Refused here from the moment of the sign-out, before any call.
        assert!(state.revoked_token_hashes.lock().contains(&hash));
        assert_eq!(
            state
                .with_db(|db| db.revoked_broker_token_hashes())
                .unwrap(),
            vec![hash.clone()],
            "the token is filed only as its hash"
        );

        assert!(
            wait_for(|| cap.lock().unwrap().seen.contains(&hash)).await,
            "the broker must be asked to delete that session"
        );
        assert!(
            wait_for(|| matches!(delivered(&state, &hash), Some(Some(_)))).await,
            "a delete the broker took is stamped delivered"
        );
    }

    #[tokio::test]
    async fn a_refused_delete_stays_undelivered_and_the_retry_lands_it() {
        let cap = Arc::new(std::sync::Mutex::new(Fake {
            seen: Vec::new(),
            fail_first: 1,
        }));
        let url = fake_broker(cap.clone()).await;
        let state = crate::server::test_state_with_config(config(Some(&url)));
        spawn(Arc::clone(&state));

        crate::connection::end_login_token(&state, "BT-RETRY").await;
        let hash = token_hash("BT-RETRY");

        assert!(
            wait_for(|| cap.lock().unwrap().seen.len() == 1).await,
            "the first call happens"
        );
        assert_eq!(
            delivered(&state, &hash),
            Some(None),
            "a refused delete is not delivered"
        );

        assert!(
            wait_through_backoff(|| matches!(delivered(&state, &hash), Some(Some(_)))).await,
            "the retry must deliver it"
        );
        assert!(cap.lock().unwrap().seen.len() >= 2);
    }

    #[tokio::test]
    async fn an_undelivered_row_is_retried_when_the_server_starts() {
        // What a restart finds: a sign-out filed, its session never deleted.
        let cap = Arc::new(std::sync::Mutex::new(Fake::default()));
        let url = fake_broker(cap.clone()).await;
        let state = crate::server::test_state_with_config(config(Some(&url)));
        let hash = token_hash("BT-FROM-BEFORE");
        // Inside the keep window: an older row is forgotten, not retried.
        let filed_at = chrono::Utc::now().timestamp();
        state.with_db(|db| db.record_broker_token_revocation(&hash, filed_at));

        spawn(Arc::clone(&state));

        assert!(
            wait_for(|| cap.lock().unwrap().seen.contains(&hash)).await,
            "an undelivered row is retried from its hash alone"
        );
        assert!(wait_for(|| matches!(delivered(&state, &hash), Some(Some(_)))).await);
    }

    #[tokio::test]
    async fn without_a_database_the_sign_out_still_reaches_the_broker() {
        let cap = Arc::new(std::sync::Mutex::new(Fake::default()));
        let url = fake_broker(cap.clone()).await;
        let state = crate::server::test_state_without_db(config(Some(&url)));
        spawn(Arc::clone(&state));

        crate::connection::end_login_token(&state, "BT-NO-DB").await;
        let hash = token_hash("BT-NO-DB");

        assert!(state.revoked_token_hashes.lock().contains(&hash));
        assert!(
            wait_for(|| cap.lock().unwrap().seen.contains(&hash)).await,
            "with no database the queue is memory, and it still delivers"
        );
    }

    #[tokio::test]
    async fn revocations_older_than_the_keep_window_are_forgotten() {
        // No broker URL: nothing to deliver, so only the pruning runs.
        let state = crate::server::test_state_with_config(config(None));
        let now = chrono::Utc::now().timestamp();
        let old = now - (KEEP_DAYS + 1) * 24 * 60 * 60;
        state.with_db(|db| db.record_broker_token_revocation("OLD", old));
        state.with_db(|db| db.record_broker_token_revocation("RECENT", now));

        spawn(Arc::clone(&state));

        assert!(
            wait_for(|| state
                .with_db(|db| db.revoked_broker_token_hashes())
                .is_some_and(|h| h == vec!["RECENT".to_string()]))
            .await,
            "the keep window forgets the old row and keeps the recent one"
        );
    }
}
