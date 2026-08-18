//! Bluesky follower gate verifier.
//!
//! Checks the public AT Protocol social graph — no OAuth needed.
//! If the user follows the target handle, issues a signed credential.
//!
//! Routes:
//!   GET /verify/bluesky/start?subject_did=...&target=handle&callback=...
//!     → Check follow via public API, issue credential or show follow prompt
//!   GET /verify/bluesky/check?subject_did=...&target=handle&callback=...
//!     → Re-check (after user has followed)
//!
//! Correctness notes (learned the hard way — see git history):
//!
//! 1. **No pagination cap.** The follows list is walked until exhaustion.
//!    An earlier version stopped after 10 pages (1,000 follows), which
//!    falsely denied anyone whose follow of the target sat deeper in their
//!    list — i.e. exactly the heavy users of this network.
//!
//! 2. **Errors are not "no".** A 429/5xx/timeout from the AppView or PDS is
//!    reported to the user as a retryable failure, never as "you don't
//!    follow @target".
//!
//! 3. **The subject's own repo is authoritative.** We first walk the
//!    `app.bsky.graph.follow` records on the subject's PDS (no AppView
//!    indexing lag — a follow is visible the moment it's written), falling
//!    back to the public AppView `getFollows` only if the PDS can't be
//!    reached.

use super::{FetchError, VerifierState, get_json_with_retries};
use crate::policy::credentials;
use crate::policy::types::VerifiableCredential;
use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<Arc<VerifierState>> {
    Router::new()
        .route("/verify/bluesky/start", get(start))
        .route("/verify/bluesky/check", get(check))
}

/// Safety bound on pagination: 100 pages × 100 entries = 10,000 follows.
/// Hitting the cap is an Error (retryable/support), NEVER a "not following".
/// Accounts with more follows than this are vanishingly rare, and unbounded
/// crawling would let one HTTP request fan out into thousands of upstream
/// requests.
const MAX_PAGES: usize = 100;
const PAGE_SIZE: usize = 100;

#[derive(Deserialize)]
struct StartQuery {
    subject_did: String,
    target: String, // handle to follow (e.g. "chadfowler.com")
    #[serde(default)]
    callback: String,
}

/// The result of a follow-relationship check.
///
/// The distinction between `NotFollowing` and `Error` is the whole ballgame:
/// `NotFollowing` shows the "go follow them" prompt, `Error` shows a
/// retryable failure page. Collapsing the two (the old behavior) turned every
/// AppView rate limit into a false denial.
#[derive(Debug, Clone, PartialEq)]
pub enum FollowCheck {
    /// The subject follows the target.
    Follows,
    /// The full follow list was walked and the target is not in it.
    NotFollowing,
    /// The check could not be completed (upstream error / list too large).
    Error(String),
}

/// One page of a follows listing, from any source.
#[derive(Debug, Clone, PartialEq)]
struct Page {
    /// DIDs appearing on this page.
    dids: Vec<String>,
    /// Cursor for the next page; `None` = last page.
    cursor: Option<String>,
}

/// Walk a paginated follows listing looking for `target_did`.
///
/// Generic over the page source so the AppView and PDS walks (and tests)
/// share one driver. Pages until the cursor is exhausted; `MAX_PAGES` bounds
/// total work.
async fn walk_for_target<F, Fut>(target_did: &str, mut fetch_page: F) -> FollowCheck
where
    F: FnMut(Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<Page, String>>,
{
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        match fetch_page(cursor).await {
            Ok(page) => {
                if page.dids.iter().any(|d| d == target_did) {
                    return FollowCheck::Follows;
                }
                match page.cursor {
                    Some(next) => cursor = Some(next),
                    None => return FollowCheck::NotFollowing,
                }
            }
            Err(e) => return FollowCheck::Error(e),
        }
    }
    FollowCheck::Error(format!(
        "follow list too large to verify (>{} entries); please contact the server operator",
        MAX_PAGES * PAGE_SIZE
    ))
}

// ─── AppView (public.api.bsky.app) source ────────────────────────────────────

fn appview_page_url(actor_did: &str, cursor: Option<&str>) -> String {
    let mut url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.graph.getFollows?actor={}&limit={}",
        urlencoding::encode(actor_did),
        PAGE_SIZE
    );
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
    }
    url
}

/// Parse an `app.bsky.graph.getFollows` response into a [`Page`].
fn parse_appview_page(json: &serde_json::Value) -> Page {
    let dids = json["follows"]
        .as_array()
        .map(|follows| {
            follows
                .iter()
                .filter_map(|f| f["did"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Page {
        dids,
        cursor: json["cursor"].as_str().map(String::from),
    }
}

// ─── PDS (subject's own repo) source ─────────────────────────────────────────

/// Build the DID-document URL for a did:plc or did:web DID.
fn did_doc_url(did: &str) -> Option<String> {
    if did.starts_with("did:plc:") {
        Some(format!("https://plc.directory/{did}"))
    } else if let Some(rest) = did.strip_prefix("did:web:") {
        // did:web:example.com            → https://example.com/.well-known/did.json
        // did:web:example.com:u:alice    → https://example.com/u/alice/did.json
        // Colons separate path segments; percent-encoding is decoded.
        let segments: Vec<String> = rest
            .split(':')
            .filter_map(|s| urlencoding::decode(s).ok().map(|c| c.into_owned()))
            .collect();
        let host = segments.first()?.clone();
        if segments.len() == 1 {
            Some(format!("https://{host}/.well-known/did.json"))
        } else {
            Some(format!("https://{host}/{}/did.json", segments[1..].join("/")))
        }
    } else {
        None
    }
}

/// Extract the atproto_pds service endpoint from a DID document.
fn pds_endpoint_from_doc(doc: &serde_json::Value) -> Option<String> {
    doc["service"].as_array()?.iter().find_map(|s| {
        let id = s["id"].as_str().unwrap_or("");
        let ty = s["type"].as_str().unwrap_or("");
        if id.ends_with("#atproto_pds") || ty == "AtprotoPersonalDataServer" {
            s["serviceEndpoint"].as_str().map(String::from)
        } else {
            None
        }
    })
}

/// Resolve the PDS endpoint for a DID (did:plc via plc.directory, did:web via
/// its well-known/path document). Returns None for unsupported methods or on
/// any fetch/parse failure — callers fall back to the AppView.
async fn resolve_pds_endpoint(http: &reqwest::Client, did: &str) -> Option<String> {
    let url = did_doc_url(did)?;
    let json = get_json_with_retries(http, &url, 2, Duration::from_millis(300))
        .await
        .ok()?;
    pds_endpoint_from_doc(&json)
}

fn pds_page_url(pds: &str, repo_did: &str, cursor: Option<&str>) -> String {
    let mut url = format!(
        "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.graph.follow&limit={}",
        pds.trim_end_matches('/'),
        urlencoding::encode(repo_did),
        PAGE_SIZE
    );
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
    }
    url
}

/// Parse a `com.atproto.repo.listRecords` response into a [`Page`].
/// Each follow record's `value.subject` is the DID of the followed account.
fn parse_pds_page(json: &serde_json::Value) -> Page {
    let dids = json["records"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .filter_map(|r| r["value"]["subject"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Page {
        dids,
        cursor: json["cursor"].as_str().map(String::from),
    }
}

// ─── The check itself ────────────────────────────────────────────────────────

/// Check whether `actor_did` follows `target_did`.
///
/// Strategy:
/// 1. Walk the follow records in the subject's own repo on their PDS —
///    authoritative and free of AppView indexing lag, so a follow the user
///    made 2 seconds ago counts.
/// 2. If the PDS can't be resolved or walked, fall back to the public
///    AppView `getFollows` listing.
///
/// Both walks page until exhaustion (bounded by [`MAX_PAGES`]).
async fn check_follows(http: &reqwest::Client, actor_did: &str, target_did: &str) -> FollowCheck {
    // 1) Authoritative source: the subject's own repo.
    match resolve_pds_endpoint(http, actor_did).await {
        Some(pds) => {
            let result = walk_for_target(target_did, |cursor| {
                let url = pds_page_url(&pds, actor_did, cursor.as_deref());
                async move {
                    let json = get_json_with_retries(http, &url, 2, Duration::from_millis(400))
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(parse_pds_page(&json))
                }
            })
            .await;
            match result {
                FollowCheck::Error(e) => {
                    // Repo walk failed partway — we can't trust a negative,
                    // so try the AppView before giving up.
                    tracing::warn!(
                        actor = %actor_did,
                        error = %e,
                        "PDS follow walk failed; falling back to AppView"
                    );
                }
                other => return other,
            }
        }
        None => {
            tracing::debug!(actor = %actor_did, "No PDS endpoint in DID document; using AppView");
        }
    }

    // 2) Fallback: public AppView follows listing.
    walk_for_target(target_did, |cursor| {
        let url = appview_page_url(actor_did, cursor.as_deref());
        async move {
            let json = get_json_with_retries(http, &url, 2, Duration::from_millis(400))
                .await
                .map_err(|e| e.to_string())?;
            Ok(parse_appview_page(&json))
        }
    })
    .await
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

/// Resolve a handle to a DID via the public Bluesky API.
async fn resolve_handle(http: &reqwest::Client, handle: &str) -> Result<String, FetchError> {
    let url = format!(
        "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={}",
        urlencoding::encode(handle)
    );
    let json = get_json_with_retries(http, &url, 2, Duration::from_millis(300)).await?;
    json["did"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FetchError::Permanent("response had no DID".into()))
}

/// Resolve a DID to a handle via public API (display purposes only).
async fn resolve_did_to_handle(http: &reqwest::Client, did: &str) -> Option<String> {
    let url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}",
        urlencoding::encode(did)
    );
    let json = get_json_with_retries(http, &url, 2, Duration::from_millis(300))
        .await
        .ok()?;
    json["handle"].as_str().map(String::from)
}

async fn start(
    Query(q): Query<StartQuery>,
    State(state): State<Arc<VerifierState>>,
) -> impl IntoResponse {
    do_check(&q.subject_did, &q.target, &q.callback, &state, true).await
}

async fn check(
    Query(q): Query<StartQuery>,
    State(state): State<Arc<VerifierState>>,
) -> impl IntoResponse {
    do_check(&q.subject_did, &q.target, &q.callback, &state, false).await
}

async fn do_check(
    subject_did: &str,
    target: &str,
    callback: &str,
    state: &Arc<VerifierState>,
    _is_initial: bool,
) -> axum::response::Response {
    let http = reqwest::Client::new();

    // Resolve target handle → DID
    let target_handle = target.trim_start_matches('@');
    let target_did = match resolve_handle(&http, target_handle).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(target = %target_handle, error = %e, "Bluesky handle resolution failed");
            return retry_page(
                &format!(
                    "/verify/bluesky/check?subject_did={}&target={}&callback={}",
                    urlencoding::encode(subject_did),
                    urlencoding::encode(target_handle),
                    urlencoding::encode(callback),
                ),
                &format!("Could not resolve @{target_handle} on Bluesky ({e})."),
            );
        }
    };

    // Resolve subject DID → handle (for display)
    let subject_handle = resolve_did_to_handle(&http, subject_did)
        .await
        .unwrap_or_else(|| subject_did.to_string());

    tracing::info!(
        subject = %subject_did,
        subject_handle = %subject_handle,
        target = %target_handle,
        "Checking Bluesky follow relationship"
    );

    let check_url = format!(
        "/verify/bluesky/check?subject_did={}&target={}&callback={}",
        urlencoding::encode(subject_did),
        urlencoding::encode(target_handle),
        urlencoding::encode(callback),
    );

    match check_follows(&http, subject_did, &target_did).await {
        FollowCheck::Follows => {
            // Issue credential
            let mut vc = VerifiableCredential {
                credential_type_tag: "FreeqCredential/v1".into(),
                issuer: state.issuer_did.clone(),
                subject: subject_did.to_string(),
                credential_type: "bluesky_follower".into(),
                claims: serde_json::json!({
                    "handle": subject_handle,
                    "follows": target_handle,
                    "follows_did": target_did,
                }),
                issued_at: chrono::Utc::now().to_rfc3339(),
                expires_at: Some((chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()),
                signature: String::new(),
            };
            credentials::sign_credential(&mut vc, &state.signing_key).unwrap();

            tracing::info!(
                subject = %subject_did,
                handle = %subject_handle,
                target = %target_handle,
                "Bluesky follow verified, credential issued"
            );

            // POST credential to callback
            let callback_ok = if !callback.is_empty() {
                match http
                    .post(callback)
                    .json(&serde_json::json!({ "credential": vc }))
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => true,
                    Ok(r) => {
                        tracing::warn!(status = %r.status(), "Bluesky credential callback failed");
                        false
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Bluesky credential callback request failed");
                        false
                    }
                }
            } else {
                false
            };

            let callback_msg = if callback_ok {
                "<p class='success'>✓ Verified! Credential delivered. You can close this window.</p>"
            } else {
                "<p>Credential issued but not auto-delivered.</p>"
            };

            let html = format!(
                r#"<!DOCTYPE html><html><head><title>freeq — Verified</title>
<style>
body {{ font-family: system-ui; max-width: 500px; margin: 40px auto; padding: 0 20px; background: #0a0a1a; color: #e0e0e0; }}
.card {{ background: #1a1a2e; border-radius: 16px; padding: 32px; text-align: center; }}
h1 {{ color: #00d4aa; margin-bottom: 8px; }}
.badge {{ display: inline-flex; align-items: center; gap: 8px; background: #00d4aa22; border: 1px solid #00d4aa44;
          padding: 8px 16px; border-radius: 20px; margin: 16px 0; }}
.badge img {{ width: 24px; height: 24px; border-radius: 12px; }}
.success {{ color: #00d4aa; font-weight: 600; }}
</style>
<script>
if (window.opener) {{
    window.opener.postMessage({{ type: 'freeq-credential', status: 'verified', credential_type: 'bluesky_follower' }}, '*');
}}
</script>
</head><body>
<div class="card">
<h1>✓ Verified</h1>
<p style="color:#999">@{subject_handle} follows @{target_handle}</p>
<div class="badge">🦋 Bluesky Follower</div>
{callback_msg}
</div>
</body></html>"#,
            );

            axum::response::Html(html).into_response()
        }
        FollowCheck::NotFollowing => {
            // Not following — show prompt
            let html = format!(
                r#"<!DOCTYPE html><html><head><title>freeq — Follow Required</title>
<style>
body {{ font-family: system-ui; max-width: 500px; margin: 40px auto; padding: 0 20px; background: #0a0a1a; color: #e0e0e0; }}
.card {{ background: #1a1a2e; border-radius: 16px; padding: 32px; text-align: center; }}
h1 {{ color: #fff; margin-bottom: 8px; font-size: 22px; }}
.sub {{ color: #999; margin-bottom: 24px; }}
.target {{ display: inline-flex; align-items: center; gap: 8px; background: #1185fe22; border: 1px solid #1185fe44;
           padding: 12px 20px; border-radius: 12px; margin: 16px 0; font-size: 18px; color: #1185fe; font-weight: 600;
           text-decoration: none; }}
.target:hover {{ background: #1185fe33; }}
.recheck {{ display: inline-block; margin-top: 20px; background: #00d4aa; color: #000; font-weight: 700;
            padding: 12px 32px; border-radius: 10px; text-decoration: none; font-size: 16px; }}
.recheck:hover {{ background: #00e4ba; }}
.hint {{ color: #666; font-size: 13px; margin-top: 16px; }}
</style></head><body>
<div class="card">
<h1>Follow Required</h1>
<p class="sub">This channel requires you to follow a Bluesky account</p>
<a href="https://bsky.app/profile/{target_handle}" target="_blank" class="target">
🦋 @{target_handle}
</a>
<br>
<a href="{check_url}" class="recheck">I followed — check again</a>
<p class="hint">Follow @{target_handle} on Bluesky, then click the button above.</p>
</div>
</body></html>"#,
            );

            axum::response::Html(html).into_response()
        }
        FollowCheck::Error(e) => {
            // Upstream failure — NOT a denial. Tell the user to retry.
            tracing::warn!(
                subject = %subject_did,
                target = %target_handle,
                error = %e,
                "Bluesky follow check could not complete"
            );
            retry_page(
                &check_url,
                "We couldn't verify your follow right now (the Bluesky API is \
                 rate-limiting or unreachable). This is temporary — your follow \
                 still counts. Please try again in a moment.",
            )
        }
    }
}

/// Retryable-error page: the check itself failed, so the user should retry —
/// unlike the follow prompt, this asserts nothing about the follow state.
fn retry_page(check_url: &str, msg: &str) -> axum::response::Response {
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Try Again</title>
<style>
body {{ font-family: system-ui; max-width: 500px; margin: 40px auto; padding: 0 20px; background: #0a0a1a; color: #e0e0e0; }}
.card {{ background: #1a1a2e; border-radius: 16px; padding: 32px; text-align: center; }}
h1 {{ color: #f0ad4e; margin-bottom: 8px; font-size: 22px; }}
.sub {{ color: #999; margin-bottom: 24px; }}
.recheck {{ display: inline-block; margin-top: 20px; background: #00d4aa; color: #000; font-weight: 700;
            padding: 12px 32px; border-radius: 10px; text-decoration: none; font-size: 16px; }}
.recheck:hover {{ background: #00e4ba; }}
</style></head><body>
<div class="card">
<h1>⚠ Verification temporarily unavailable</h1>
<p class="sub">{msg}</p>
<a href="{check_url}" class="recheck">Try again</a>
</div>
</body></html>"#,
    );
    axum::response::Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use super::super::retry_loop;
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── Pagination driver ────────────────────────────────────────────────

    /// Build a scripted page source: pages of DIDs, erroring on `fail_on_page`
    /// if given (0-indexed).
    fn scripted_source(
        pages: Vec<Vec<String>>,
        fail_on_page: Option<usize>,
    ) -> impl FnMut(Option<String>) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Page, String>> + Send>,
    > {
        let state = Arc::new(Mutex::new((pages, 0usize)));
        move |_cursor| {
            let state = Arc::clone(&state);
            Box::pin(async move {
                let mut guard = state.lock().unwrap();
                let (pages, idx) = &mut *guard;
                let i = *idx;
                *idx += 1;
                if Some(i) == fail_on_page {
                    return Err("simulated upstream failure".into());
                }
                if i >= pages.len() {
                    panic!("fetch_page called more times than there are pages");
                }
                let dids = pages[i].clone();
                let cursor = if i + 1 < pages.len() {
                    Some(format!("cursor-{i}"))
                } else {
                    None
                };
                Ok(Page { dids, cursor })
            })
        }
    }

    #[tokio::test]
    async fn finds_target_beyond_the_old_1000_follow_cap() {
        // 15 pages × 100 follows; the target sits on the last page — the
        // pre-fix code (10-page cap) would have falsely denied this user.
        let mut pages: Vec<Vec<String>> = (0..14)
            .map(|p| {
                (0..100)
                    .map(|i| format!("did:plc:user-p{p}-{i}"))
                    .collect()
            })
            .collect();
        pages.push(vec!["did:plc:target".to_string()]);

        let result = walk_for_target("did:plc:target", scripted_source(pages, None)).await;
        assert_eq!(result, FollowCheck::Follows);
    }

    #[tokio::test]
    async fn not_following_only_when_list_exhausted() {
        let pages = vec![
            vec!["did:plc:a".to_string()],
            vec!["did:plc:b".to_string()],
        ];
        let result = walk_for_target("did:plc:target", scripted_source(pages, None)).await;
        assert_eq!(result, FollowCheck::NotFollowing);
    }

    #[tokio::test]
    async fn mid_walk_error_is_error_not_denial() {
        // Fails on page 2 — before the fix this returned "false" (denial).
        let pages = vec![
            vec!["did:plc:a".to_string()],
            vec!["did:plc:b".to_string()],
            vec!["did:plc:target".to_string()],
        ];
        let result = walk_for_target("did:plc:target", scripted_source(pages, Some(1))).await;
        assert!(matches!(result, FollowCheck::Error(_)));
    }

    #[tokio::test]
    async fn hitting_page_cap_is_error_not_denial() {
        // A follow list longer than MAX_PAGES pages must surface as an
        // error, never as "not following". Infinite source: the driver must
        // stop at MAX_PAGES with an Error.
        let counter = AtomicUsize::new(0);
        let fetch = move |_cursor| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(Page {
                    dids: vec![format!("did:plc:user-{n}")],
                    cursor: Some("more".into()),
                })
            }) as std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Page, String>> + Send>,
            >
        };
        let result = walk_for_target("did:plc:target", fetch).await;
        assert!(matches!(result, FollowCheck::Error(ref m) if m.contains("too large")));
    }

    // ── Response parsing ─────────────────────────────────────────────────

    #[test]
    fn parses_appview_page() {
        let json = serde_json::json!({
            "follows": [
                {"did": "did:plc:a", "handle": "a.bsky.social"},
                {"did": "did:plc:b", "handle": "b.bsky.social"}
            ],
            "cursor": "abc123"
        });
        let page = parse_appview_page(&json);
        assert_eq!(page.dids, vec!["did:plc:a", "did:plc:b"]);
        assert_eq!(page.cursor.as_deref(), Some("abc123"));
    }

    #[test]
    fn parses_appview_page_without_cursor() {
        let json = serde_json::json!({"follows": []});
        let page = parse_appview_page(&json);
        assert!(page.dids.is_empty());
        assert_eq!(page.cursor, None);
    }

    #[test]
    fn parses_pds_page() {
        let json = serde_json::json!({
            "records": [
                {"uri": "at://did:plc:me/app.bsky.graph.follow/aaa",
                 "value": {"subject": "did:plc:a", "createdAt": "2024-01-01T00:00:00Z"}},
                {"uri": "at://did:plc:me/app.bsky.graph.follow/bbb",
                 "value": {"subject": "did:plc:b", "createdAt": "2024-01-02T00:00:00Z"}}
            ],
            "cursor": "xyz"
        });
        let page = parse_pds_page(&json);
        assert_eq!(page.dids, vec!["did:plc:a", "did:plc:b"]);
        assert_eq!(page.cursor.as_deref(), Some("xyz"));
    }

    #[test]
    fn pds_page_skips_malformed_records() {
        let json = serde_json::json!({
            "records": [
                {"uri": "at://x", "value": {"noSubject": true}},
                {"uri": "at://y", "value": {"subject": "did:plc:ok"}}
            ]
        });
        let page = parse_pds_page(&json);
        assert_eq!(page.dids, vec!["did:plc:ok"]);
    }

    // ── DID document handling ────────────────────────────────────────────

    #[test]
    fn did_doc_urls() {
        assert_eq!(
            did_doc_url("did:plc:abc123").as_deref(),
            Some("https://plc.directory/did:plc:abc123")
        );
        assert_eq!(
            did_doc_url("did:web:example.com").as_deref(),
            Some("https://example.com/.well-known/did.json")
        );
        assert_eq!(
            did_doc_url("did:web:example.com:u:alice").as_deref(),
            Some("https://example.com/u/alice/did.json")
        );
        assert_eq!(did_doc_url("did:key:zSomething"), None);
    }

    #[test]
    fn extracts_pds_endpoint() {
        let doc = serde_json::json!({
            "id": "did:plc:abc",
            "service": [
                {"id": "did:plc:abc#atproto_pds",
                 "type": "AtprotoPersonalDataServer",
                 "serviceEndpoint": "https://pds.example.com"}
            ]
        });
        assert_eq!(
            pds_endpoint_from_doc(&doc).as_deref(),
            Some("https://pds.example.com")
        );
    }

    #[test]
    fn pds_endpoint_missing_when_no_service() {
        let doc = serde_json::json!({"id": "did:plc:abc", "service": []});
        assert_eq!(pds_endpoint_from_doc(&doc), None);
    }

    #[test]
    fn pds_page_url_encodes_params() {
        let url = pds_page_url("https://pds.example.com/", "did:plc:me", Some("cur/sor+x".into()));
        assert_eq!(
            url,
            "https://pds.example.com/xrpc/com.atproto.repo.listRecords?repo=did%3Aplc%3Ame&collection=app.bsky.graph.follow&limit=100&cursor=cur%2Fsor%2Bx"
        );
    }

    // ── Retries ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn retries_eventually_succeed() {
        let calls = AtomicUsize::new(0);
        let result = retry_loop(
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(FetchError::Transient("429 rate limited".into()))
                    } else {
                        Ok(42)
                    }
                }
            },
            3,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
