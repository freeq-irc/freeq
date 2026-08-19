//! GitHub verifier — org membership OR repo collaborator.
//!
//! Routes:
//!   GET /verify/github/start?subject_did=...&org=...&callback=...
//!     → Redirect to GitHub OAuth (org membership check)
//!   GET /verify/github/start?subject_did=...&repo=owner/repo&callback=...
//!     → Redirect to GitHub OAuth (repo collaborator check)
//!   GET /verify/github/callback
//!     → Exchange code, verify membership/collaborator, sign credential, POST to callback

use super::{FetchError, PendingVerification, VerifierState, retry_loop};
use crate::policy::credentials;
use crate::policy::types::VerifiableCredential;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;

pub fn routes() -> Router<Arc<VerifierState>> {
    Router::new()
        .route("/verify/github/start", get(start))
        .route("/verify/github/callback", get(callback))
}

#[derive(Deserialize)]
struct StartQuery {
    /// DID of the user (proven via AT Protocol auth on the freeq server).
    subject_did: String,
    /// GitHub org to verify membership for (mutually exclusive with repo).
    #[serde(default)]
    org: Option<String>,
    /// GitHub repo (owner/name) to verify collaborator access for.
    #[serde(default)]
    repo: Option<String>,
    /// URL to POST the signed credential to after verification.
    #[serde(default)]
    callback: String,
}

async fn start(
    Query(q): Query<StartQuery>,
    State(state): State<Arc<VerifierState>>,
) -> Result<Redirect, (StatusCode, String)> {
    let github = state.github.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "GitHub not configured".into(),
    ))?;

    if q.org.is_none() && q.repo.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Must specify org= or repo=".into()));
    }

    let state_token = hex::encode(rand::random::<[u8; 16]>());

    let mut params = serde_json::Map::new();
    if let Some(ref org) = q.org {
        params.insert("org".into(), serde_json::Value::String(org.clone()));
    }
    if let Some(ref repo) = q.repo {
        params.insert("repo".into(), serde_json::Value::String(repo.clone()));
    }

    state.pending.lock().insert(
        state_token.clone(),
        PendingVerification {
            subject_did: q.subject_did,
            callback_url: q.callback,
            provider_params: serde_json::Value::Object(params),
            created_at: std::time::Instant::now(),
        },
    );

    // Scopes: read:org for org membership, repo for collaborator check
    let scope = if q.repo.is_some() { "repo" } else { "read:org" };

    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&scope={}&state={}",
        github.client_id, scope, state_token,
    );

    Ok(Redirect::temporary(&url))
}

async fn callback(
    Query(q): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<VerifierState>>,
) -> impl IntoResponse {
    let code = match q.get("code") {
        Some(c) => c.clone(),
        None => return error_page("No authorization code from GitHub"),
    };
    let oauth_state = match q.get("state") {
        Some(s) => s.clone(),
        None => return error_page("Missing state parameter"),
    };

    // Look up pending
    let pending = state.pending.lock().remove(&oauth_state);
    let pending = match pending {
        Some(p) if p.created_at.elapsed() < std::time::Duration::from_secs(300) => p,
        Some(_) => return error_page("Verification expired. Please try again."),
        None => return error_page("Unknown or expired verification"),
    };

    let github = match &state.github {
        Some(g) => g,
        None => return error_page("GitHub not configured"),
    };

    let org = pending
        .provider_params
        .get("org")
        .and_then(|v| v.as_str())
        .map(String::from);

    let repo = pending
        .provider_params
        .get("repo")
        .and_then(|v| v.as_str())
        .map(String::from);

    let http = reqwest::Client::new();

    // Exchange code for token
    let token_json: serde_json::Value = match http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", github.client_id.as_str()),
            ("client_secret", github.client_secret.as_str()),
            ("code", &code),
        ])
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => return error_page(&format!("Token exchange failed: {e}")),
    };

    let access_token = match token_json["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => {
            let err = token_json["error_description"]
                .as_str()
                .or(token_json["error"].as_str())
                .unwrap_or("unknown error");
            return error_page(&format!("GitHub OAuth failed: {err}"));
        }
    };

    // Get authenticated username (this proves identity — not self-attested)
    let user_json: serde_json::Value = match http
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "freeq-verifier")
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => return error_page(&format!("GitHub API error: {e}")),
    };

    let username = match user_json["login"].as_str() {
        Some(u) => u.to_string(),
        None => return error_page("Could not determine GitHub username"),
    };

    // Route to the appropriate verification
    if let Some(ref repo_name) = repo {
        return verify_repo_collaborator(
            &state,
            &http,
            &access_token,
            &username,
            repo_name,
            &pending,
        )
        .await;
    }

    if let Some(ref org_name) = org {
        return verify_org_membership(&state, &http, &access_token, &username, org_name, &pending)
            .await;
    }

    error_page("No org or repo specified")
}

/// Verify org membership using the authenticated user's token.
/// This can see private memberships because the token has read:org scope.
async fn verify_org_membership(
    state: &Arc<VerifierState>,
    http: &reqwest::Client,
    access_token: &str,
    username: &str,
    org: &str,
    pending: &PendingVerification,
) -> axum::response::Response {
    // Authenticated membership endpoint (sees private memberships).
    // Single request: 200 → inspect the record's state; 404 → no record.
    let membership = match get_status_and_json(
        http,
        &format!("https://api.github.com/user/memberships/orgs/{org}"),
        access_token,
    )
    .await
    {
        Ok((status, Some(body))) if status.is_success() => parse_membership_state(&body),
        Ok((status, _)) => classify_yes_no_status(status),
        Err(e) => ApiCheck::Error(e.to_string()),
    };

    let is_member = match membership {
        ApiCheck::Yes => true,
        ApiCheck::Error(e) => {
            tracing::warn!(org = %org, error = %e, "GitHub org membership check failed");
            return error_page(&format!(
                "GitHub is having trouble answering right now ({e}).\n\n\
                 This is temporary — please go back and try the verification again."
            ));
        }
        ApiCheck::No => {
            // Fall back to the public membership check (covers members who
            // flaunt their membership publicly but lack read:org scope).
            // NOTE: unauthenticated — 60 req/hr per server IP. A 403 here is
            // almost certainly rate limiting, so surface it as an Error.
            match get_status_with_retries(
                http,
                &format!("https://api.github.com/orgs/{org}/public_members/{username}"),
                None,
            )
            .await
            {
                Ok(status) => match classify_yes_no_status(status) {
                    ApiCheck::Yes => true,
                    ApiCheck::No => false,
                    ApiCheck::Error(e) => {
                        tracing::warn!(org = %org, error = %e, "GitHub public membership check failed");
                        return error_page(&format!(
                            "GitHub is having trouble answering right now ({e}).\n\n\
                             This is temporary — please go back and try the verification again."
                        ));
                    }
                },
                Err(e) => {
                    tracing::warn!(org = %org, error = %e, "GitHub public membership check failed");
                    return error_page(&format!(
                        "GitHub is having trouble answering right now ({e}).\n\n\
                         This is temporary — please go back and try the verification again."
                    ));
                }
            }
        }
    };

    if !is_member {
        return error_page(&format!(
            "{username} is not a member of the {org} organization.\n\n\
             Options:\n\
             • If you were recently invited, accept the invitation first\n\
             • Make your membership public at https://github.com/orgs/{org}/people\n\
             • Ask the channel to accept repo collaborator verification instead:\n\
               /POLICY #channel REQUIRE github_repo issuer=... url=.../verify/github/start repo=owner/repo"
        ));
    }

    issue_credential(
        state,
        http,
        pending,
        username,
        "github_membership",
        serde_json::json!({
            "github_username": username,
            "org": org,
        }),
        &format!("{username} is a member of {org}"),
        &format!("{org} (org)"),
    )
    .await
}

/// Verify repo collaborator access. The user's token must have access to the repo.
async fn verify_repo_collaborator(
    state: &Arc<VerifierState>,
    http: &reqwest::Client,
    access_token: &str,
    username: &str,
    repo: &str,
    pending: &PendingVerification,
) -> axum::response::Response {
    // Check if the user is a collaborator on the repo
    // GET /repos/{owner}/{repo}/collaborators/{username} → 204 if yes, 404 if no.
    // Anything else (429/5xx/network) is a retryable error, NOT a denial.
    let collaborator_url = format!("https://api.github.com/repos/{repo}/collaborators/{username}");
    let is_collaborator =
        match get_status_with_retries(http, &collaborator_url, Some(access_token)).await {
            Ok(status) => match classify_yes_no_status(status) {
                ApiCheck::Yes => ApiCheck::Yes,
                ApiCheck::No => {
                    // Also check if they have push access via the repo endpoint
                    // (covers permission shapes the collaborators endpoint misses).
                    match get_json_checked(
                        http,
                        &format!("https://api.github.com/repos/{repo}"),
                        access_token,
                    )
                    .await
                    {
                        Ok(repo_json) => {
                            let has_push = repo_json
                                .get("permissions")
                                .and_then(|p| p.get("push"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if has_push {
                                ApiCheck::Yes
                            } else {
                                ApiCheck::No
                            }
                        }
                        Err(e) => ApiCheck::Error(e.to_string()),
                    }
                }
                ApiCheck::Error(e) => ApiCheck::Error(e),
            },
            Err(e) => ApiCheck::Error(e.to_string()),
        };

    match is_collaborator {
        ApiCheck::Yes => {
            issue_credential(
                state,
                http,
                pending,
                username,
                "github_repo",
                serde_json::json!({
                    "github_username": username,
                    "repo": repo,
                }),
                &format!("{username} has access to {repo}"),
                repo,
            )
            .await
        }
        ApiCheck::No => error_page(&format!(
            "{username} is not a collaborator on {repo}.\n\n\
             You need push access or collaborator status on this repository."
        )),
        ApiCheck::Error(e) => {
            tracing::warn!(repo = %repo, error = %e, "GitHub collaborator check failed");
            error_page(&format!(
                "GitHub is having trouble answering right now ({e}).\n\n\
                 This is temporary — please go back and try the verification again."
            ))
        }
    }
}

/// Issue a signed credential and POST it to the callback URL.
async fn issue_credential(
    state: &Arc<VerifierState>,
    http: &reqwest::Client,
    pending: &PendingVerification,
    username: &str,
    credential_type: &str,
    claims: serde_json::Value,
    verified_msg: &str,
    _badge_label: &str,
) -> axum::response::Response {
    let mut vc = VerifiableCredential {
        credential_type_tag: "FreeqCredential/v1".into(),
        issuer: state.issuer_did.clone(),
        subject: pending.subject_did.clone(),
        credential_type: credential_type.into(),
        claims,
        issued_at: chrono::Utc::now().to_rfc3339(),
        expires_at: Some((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()),
        signature: String::new(),
    };
    credentials::sign_credential(&mut vc, &state.signing_key).unwrap();

    tracing::info!(
        subject = %pending.subject_did,
        github = %username,
        credential_type = %credential_type,
        "GitHub verification complete, credential issued"
    );

    // POST credential to callback URL
    let callback_result = if !pending.callback_url.is_empty() {
        tracing::info!(callback_url = %pending.callback_url, "POSTing credential to callback");
        match http
            .post(&pending.callback_url)
            .json(&serde_json::json!({ "credential": vc }))
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if status.is_success() {
                    tracing::info!("Credential callback succeeded");
                    true
                } else {
                    tracing::warn!(status = %status, body = %body, "Credential callback failed");
                    false
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Credential callback request failed");
                false
            }
        }
    } else {
        tracing::warn!("No callback URL — credential not auto-delivered");
        false
    };

    let vc_json = serde_json::to_string_pretty(&vc).unwrap_or_default();
    let (callback_status, auto_close_js) = if callback_result {
        (
            "<p style='color:#0a0'>✓ Verified! This window will close automatically.</p>",
            "setTimeout(function() { window.close(); }, 1500);",
        )
    } else {
        (
            "<p>Credential was not auto-delivered. Copy it and present manually.</p>",
            "",
        )
    };

    let html = format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Verified</title>
<style>
body {{ font-family: system-ui; max-width: 600px; margin: 40px auto; padding: 0 20px; background: #0a0a1a; color: #e0e0e0; }}
h1 {{ color: #0f0; }}
.badge {{ background: #0a0; color: white; padding: 3px 10px; border-radius: 10px; font-size: 14px; }}
pre {{ background: #1a1a2e; color: #0f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 11px; max-height: 200px; }}
button {{ background: #333; color: #fff; border: 1px solid #555; padding: 8px 16px; border-radius: 4px; cursor: pointer; }}
button:hover {{ background: #444; }}
</style>
<script>
if (window.opener) {{
    window.opener.postMessage({{ type: 'freeq-credential', status: 'verified', credential_type: '{credential_type}' }}, '*');
    // Auto-close popup after a brief delay if credential was auto-delivered
    {auto_close_js}
}}
</script>
</head><body>
<h1>✓ Verified</h1>
<p><span class="badge">{username}</span> — {verified_msg}</p>
<p>Credential issued for: <code>{did}</code></p>
{callback_status}
<details><summary>Credential JSON</summary>
<pre id="vc">{vc_json}</pre>
<button onclick="navigator.clipboard.writeText(document.getElementById('vc').textContent)">📋 Copy</button>
</details>
</body></html>"#,
        did = pending.subject_did,
    );

    axum::response::Html(html).into_response()
}

/// The result of a GitHub API yes/no check.
///
/// `Error` must never be presented to the user as "you don't have access" —
/// a rate limit or 5xx is not a denial (the old code collapsed these, which
/// produced intermittent false rejections whenever GitHub hiccuped).
#[derive(Debug, Clone, PartialEq)]
enum ApiCheck {
    Yes,
    No,
    Error(String),
}

/// Classify the status of a "204 = yes, 404 = no" GitHub endpoint.
/// Anything else (429, 5xx, …) is an Error, not a No.
fn classify_yes_no_status(status: reqwest::StatusCode) -> ApiCheck {
    match status.as_u16() {
        204 | 200 => ApiCheck::Yes,
        404 => ApiCheck::No,
        _ => match FetchError::from_status(status) {
            Some(e) => ApiCheck::Error(e.to_string()),
            None => ApiCheck::Error(format!("unexpected HTTP {status}")),
        },
    }
}

/// Interpret the body of GET /user/memberships/orgs/{org}.
/// 200 means a membership record exists; `state` distinguishes an active
/// member from someone holding an unaccepted invitation.
fn parse_membership_state(body: &serde_json::Value) -> ApiCheck {
    match body["state"].as_str() {
        Some("active") => ApiCheck::Yes,
        Some("pending") => ApiCheck::No,
        // 200 with an unrecognized body shape: the membership record exists,
        // so treat as Yes (backwards-compatible with older API responses).
        _ => ApiCheck::Yes,
    }
}

/// GET a GitHub API endpoint, returning the final status code, with bounded
/// retries on 429/5xx/network errors. Err(_) means the request could not be
/// completed at all — callers must surface that as a retryable error.
async fn get_status_with_retries(
    http: &reqwest::Client,
    url: &str,
    access_token: Option<&str>,
) -> Result<reqwest::StatusCode, FetchError> {
    retry_loop(
        || async {
            let mut req = http.get(url).header("User-Agent", "freeq-verifier");
            if let Some(token) = access_token {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
            let resp = req
                .send()
                .await
                .map_err(|e| FetchError::Transient(format!("request failed: {e}")))?;
            if let Some(err) = FetchError::from_status(resp.status()) {
                return Err(err);
            }
            Ok(resp.status())
        },
        2,
        std::time::Duration::from_millis(400),
    )
    .await
}

/// GET a GitHub API endpoint and parse JSON, with bounded retries.
async fn get_json_checked(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<serde_json::Value, FetchError> {
    retry_loop(
        || async {
            let resp = http
                .get(url)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "freeq-verifier")
                .send()
                .await
                .map_err(|e| FetchError::Transient(format!("request failed: {e}")))?;
            if let Some(err) = FetchError::from_status(resp.status()) {
                return Err(err);
            }
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| FetchError::Permanent(format!("invalid JSON: {e}")))
        },
        2,
        std::time::Duration::from_millis(400),
    )
    .await
}

/// GET a GitHub API endpoint, returning the final status and (on success)
/// the parsed JSON body, with bounded retries on 429/5xx/network errors.
/// Non-2xx statuses (e.g. 404) are returned, not treated as errors.
async fn get_status_and_json(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<(reqwest::StatusCode, Option<serde_json::Value>), FetchError> {
    retry_loop(
        || async {
            let resp = http
                .get(url)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "freeq-verifier")
                .send()
                .await
                .map_err(|e| FetchError::Transient(format!("request failed: {e}")))?;
            if let Some(err) = FetchError::from_status(resp.status()) {
                return Err(err);
            }
            let status = resp.status();
            if !status.is_success() {
                return Ok((status, None));
            }
            let body = resp
                .json::<serde_json::Value>()
                .await
                .map_err(|e| FetchError::Permanent(format!("invalid JSON: {e}")))?;
            Ok((status, Some(body)))
        },
        2,
        std::time::Duration::from_millis(400),
    )
    .await
}

fn error_page(msg: &str) -> axum::response::Response {
    let safe_msg = msg
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Error</title>
<style>
body {{ font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; background: #0a0a1a; color: #e0e0e0; }}
h1 {{ color: #f44; }}
p {{ white-space: pre-wrap; text-align: left; }}
</style></head><body>
<h1>Verification Failed</h1>
<p>{safe_msg}</p>
</body></html>"#,
    );
    axum::response::Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_collaborator_status() {
        use reqwest::StatusCode;
        assert_eq!(
            classify_yes_no_status(StatusCode::NO_CONTENT),
            ApiCheck::Yes
        );
        assert_eq!(classify_yes_no_status(StatusCode::NOT_FOUND), ApiCheck::No);
        // Rate limits and server errors are Errors, never a denial.
        assert!(matches!(
            classify_yes_no_status(StatusCode::TOO_MANY_REQUESTS),
            ApiCheck::Error(_)
        ));
        assert!(matches!(
            classify_yes_no_status(StatusCode::INTERNAL_SERVER_ERROR),
            ApiCheck::Error(_)
        ));
        // Even 403 (rate-limited unauthenticated) is an Error, not a No.
        assert!(matches!(
            classify_yes_no_status(StatusCode::FORBIDDEN),
            ApiCheck::Error(_)
        ));
    }

    #[test]
    fn membership_state_active_counts_pending_does_not() {
        assert_eq!(
            parse_membership_state(&serde_json::json!({"state": "active"})),
            ApiCheck::Yes
        );
        assert_eq!(
            parse_membership_state(&serde_json::json!({"state": "pending"})),
            ApiCheck::No
        );
        // Unknown shape on a 200 → membership record exists → Yes.
        assert_eq!(
            parse_membership_state(&serde_json::json!({})),
            ApiCheck::Yes
        );
    }
}
