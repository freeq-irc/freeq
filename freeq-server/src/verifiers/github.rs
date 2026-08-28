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
    let answer = authenticated_membership(http, access_token, org).await;

    match &answer {
        MembershipAnswer::Transient(e) => {
            tracing::warn!(org = %org, error = %e, "GitHub org membership check failed");
            return retry_page(e);
        }
        MembershipAnswer::Failed(e) => {
            tracing::warn!(org = %org, error = %e, "GitHub org membership check failed");
            return error_page(&format!(
                "GitHub could not answer whether {username} belongs to {org} ({e}).\n\n\
                 Start the verification again from the beginning so GitHub can \
                 re-authorize this app."
            ));
        }
        _ => {}
    }

    // A refusal is not a "no" — the token simply isn't allowed to answer for
    // this org, and the public roster still settles it for members who show
    // their membership publicly.
    let mut is_member = matches!(answer, MembershipAnswer::Member);
    if !is_member {
        // Unauthenticated — 60 req/hr per server IP. A 403 here is almost
        // certainly rate limiting, so surface it as an error, not a denial.
        let public = get_status_with_retries(
            http,
            &format!("https://api.github.com/orgs/{org}/public_members/{username}"),
            None,
        )
        .await
        .map_or_else(|e| ApiCheck::Error(e.to_string()), classify_yes_no_status);

        match public {
            ApiCheck::Yes => is_member = true,
            ApiCheck::No => {}
            ApiCheck::Error(e) => {
                tracing::warn!(org = %org, error = %e, "GitHub public membership check failed");
                // With a refusal in hand, fall through to it instead.
                if !matches!(answer, MembershipAnswer::Refused(_)) {
                    return retry_page(&e);
                }
            }
        }
    }

    if !is_member {
        if let MembershipAnswer::Refused(detail) = &answer {
            tracing::warn!(
                org = %org, github = %username, detail = %detail,
                "GitHub refused to answer the org membership check"
            );
            return error_page(&format!(
                "GitHub would not confirm whether {username} belongs to {org}.\n\n\
                 GitHub said: {detail}\n\n\
                 This usually means {org} restricts OAuth app access and this app is \
                 not approved. An org owner can approve it at\n\
                 https://github.com/orgs/{org}/settings/oauth_application_policy\n\n\
                 Failing that, make your membership public at\n\
                 https://github.com/orgs/{org}/people\n\
                 and run the verification again."
            ));
        }
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

/// What the authenticated membership endpoint said about a user and an org.
#[derive(Debug, Clone, PartialEq)]
enum MembershipAnswer {
    Member,
    NotMember,
    /// GitHub has the answer but won't give it to this token — the org
    /// restricts OAuth apps, or a SAML session hasn't been authorized.
    /// Carries GitHub's own explanation.
    Refused(String),
    /// Rate limit, 5xx, or a network failure. Never a denial.
    Transient(String),
    /// A revoked token or a malformed request. Never a denial, and no use retrying.
    Failed(String),
}

/// Ask the authenticated membership endpoint about `org`. This sees private
/// memberships because the token carries `read:org`.
async fn authenticated_membership(
    http: &reqwest::Client,
    access_token: &str,
    org: &str,
) -> MembershipAnswer {
    let url = format!("https://api.github.com/user/memberships/orgs/{org}");
    match get_status_and_body(http, &url, access_token).await {
        Ok((status, body)) => classify_membership(status, &body),
        Err(e) => MembershipAnswer::Transient(e.to_string()),
    }
}

/// Turn a response from `/user/memberships/orgs/{org}` into an answer.
fn classify_membership(status: reqwest::StatusCode, body: &str) -> MembershipAnswer {
    if status.is_success() {
        // A 200 carrying something other than JSON is a proxy or captive portal
        // talking, not GitHub. `parse_membership_state` reads an empty record as
        // a member, so it must never see one we invented.
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
            return MembershipAnswer::Transient("membership response was not JSON".into());
        };
        return match parse_membership_state(&parsed) {
            ApiCheck::Yes => MembershipAnswer::Member,
            _ => MembershipAnswer::NotMember,
        };
    }

    // 429 and 5xx never reach here: `get_status_and_body` retries those and
    // reports them as `Err`. What's left is permanent.
    match status.as_u16() {
        403 => MembershipAnswer::Refused(github_message(body)),
        404 => MembershipAnswer::NotMember,
        _ => MembershipAnswer::Failed(format!("HTTP {status} — {}", github_message(body))),
    }
}

/// Pull the human-readable `message` out of a GitHub error body.
fn github_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(String::from))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "no explanation given".into())
}

/// The page for a failure that really might succeed on a retry.
fn retry_page(err: &str) -> axum::response::Response {
    error_page(&format!(
        "GitHub is having trouble answering right now ({err}).\n\n\
         This is temporary — please go back and try the verification again."
    ))
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
                        // A token that can't see the repo has answered the question.
                        Err(FetchError::Permanent(_)) => ApiCheck::No,
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

    // The DID and repo arrive on the query string that starts the flow and are
    // never validated, so treat everything interpolated here as hostile.
    let nonce = super::script_nonce();
    let username_html = super::html_escape(username);
    let verified_msg_html = super::html_escape(verified_msg);
    let did_html = super::html_escape(&pending.subject_did);
    let vc_json_html = super::html_escape(&vc_json);
    let credential_type_js =
        serde_json::to_string(credential_type).unwrap_or_else(|_| "\"\"".into());

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
</head><body>
<h1>✓ Verified</h1>
<p><span class="badge">{username_html}</span> — {verified_msg_html}</p>
<p>Credential issued for: <code>{did_html}</code></p>
{callback_status}
<details><summary>Credential JSON</summary>
<pre id="vc">{vc_json_html}</pre>
<button id="copy">📋 Copy</button>
</details>
<script nonce="{nonce}">
(function () {{
    var vc = document.getElementById('vc');
    document.getElementById('copy').addEventListener('click', function () {{
        navigator.clipboard.writeText(vc.textContent);
    }});
    if (window.opener) {{
        window.opener.postMessage({{ type: 'freeq-credential', status: 'verified', credential_type: {credential_type_js} }}, '*');
        // Auto-close popup after a brief delay if credential was auto-delivered
        {auto_close_js}
    }}
}})();
</script>
</body></html>"#,
    );

    super::result_page(html, &nonce)
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
/// retries on 429/5xx/network errors. A 4xx comes back as `Ok` for the caller
/// to interpret; `Err(_)` means the request never completed.
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
            let status = resp.status();
            if let Some(err @ FetchError::Transient(_)) = FetchError::from_status(status) {
                return Err(err);
            }
            Ok(status)
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

/// GET a GitHub API endpoint, returning the final status and the raw body,
/// with bounded retries on 429/5xx/network errors. 4xx bodies are handed back
/// rather than discarded — GitHub explains its refusals there, and the caller
/// needs that text to tell the user what to do about it.
async fn get_status_and_body(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<(reqwest::StatusCode, String), FetchError> {
    retry_loop(
        || async {
            let resp = http
                .get(url)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "freeq-verifier")
                .send()
                .await
                .map_err(|e| FetchError::Transient(format!("request failed: {e}")))?;
            let status = resp.status();
            if let Some(err @ FetchError::Transient(_)) = FetchError::from_status(status) {
                return Err(err);
            }
            let body = resp
                .text()
                .await
                .map_err(|e| FetchError::Permanent(format!("unreadable body: {e}")))?;
            Ok((status, body))
        },
        2,
        std::time::Duration::from_millis(400),
    )
    .await
}

fn error_page(msg: &str) -> axum::response::Response {
    let safe_msg = super::html_escape(msg);
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

    /// What GitHub actually returns when an org gates OAuth apps.
    const OAUTH_RESTRICTED: &str = r#"{"message":"Although you appear to have the correct authorization credentials, the `Z-Space-Society` organization has enabled OAuth App access restrictions, meaning that data access to third-parties is limited.","documentation_url":"https://docs.github.com/articles/restricting-access-to-your-organization-s-data/"}"#;

    #[test]
    fn active_membership_record_is_a_member() {
        assert_eq!(
            classify_membership(reqwest::StatusCode::OK, r#"{"state":"active"}"#),
            MembershipAnswer::Member
        );
    }

    #[test]
    fn pending_invitation_is_not_a_member() {
        assert_eq!(
            classify_membership(reqwest::StatusCode::OK, r#"{"state":"pending"}"#),
            MembershipAnswer::NotMember
        );
    }

    #[test]
    fn missing_membership_record_is_not_a_member() {
        assert_eq!(
            classify_membership(reqwest::StatusCode::NOT_FOUND, r#"{"message":"Not Found"}"#),
            MembershipAnswer::NotMember
        );
    }

    #[test]
    fn oauth_app_restriction_is_a_refusal_carrying_githubs_reason() {
        match classify_membership(reqwest::StatusCode::FORBIDDEN, OAUTH_RESTRICTED) {
            MembershipAnswer::Refused(detail) => {
                assert!(detail.contains("OAuth App access restrictions"), "{detail}")
            }
            other => panic!("403 must be a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_is_never_reported_as_not_a_member() {
        let answer = classify_membership(reqwest::StatusCode::FORBIDDEN, OAUTH_RESTRICTED);
        assert_ne!(answer, MembershipAnswer::NotMember);
        assert_ne!(answer, MembershipAnswer::Member);
    }

    #[test]
    fn a_rate_limit_is_retried_upstream_not_classified_here() {
        // Why `classify_membership` has no 429/5xx arm: the fetch helper retries
        // those and hands the caller an `Err`, so only permanent statuses arrive.
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
            Some(FetchError::Transient(_))
        ));
        assert!(matches!(
            FetchError::from_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            Some(FetchError::Transient(_))
        ));
    }

    #[test]
    fn a_200_that_is_not_json_is_never_a_member() {
        // A captive portal or proxy page must not read as a membership record.
        match classify_membership(reqwest::StatusCode::OK, "<html>captive portal</html>") {
            MembershipAnswer::Transient(_) => {}
            other => panic!("an unparseable 200 must not grant membership, got {other:?}"),
        }
    }

    #[test]
    fn a_revoked_token_is_a_permanent_failure_not_a_retry() {
        match classify_membership(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"message":"Bad credentials"}"#,
        ) {
            MembershipAnswer::Failed(detail) => {
                assert!(detail.contains("Bad credentials"), "{detail}")
            }
            other => panic!("401 must be a permanent failure, got {other:?}"),
        }
    }

    #[test]
    fn a_public_roster_miss_is_an_answer_not_an_error() {
        // GitHub answers "not a public member" with 404.
        assert_eq!(
            classify_yes_no_status(reqwest::StatusCode::NOT_FOUND),
            ApiCheck::No
        );
    }

    #[test]
    fn github_message_falls_back_when_the_body_is_unhelpful() {
        assert_eq!(
            github_message(r#"{"message":"Bad credentials"}"#),
            "Bad credentials"
        );
        assert_eq!(github_message("not json at all"), "no explanation given");
        assert_eq!(github_message(r#"{"message":""}"#), "no explanation given");
    }

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
