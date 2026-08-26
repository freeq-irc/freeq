//! Tests for the narrow-scope + step-up OAuth changes (Phase 1 + Phase 2).
//!
//! Phase 1 invariants:
//!   - The published client-metadata.json does NOT advertise the legacy
//!     `transition:generic` scope. It declares the union of narrow scopes
//!     this client may request across all flows.
//!
//! Phase 2 invariants:
//!   - `/auth/step-up` rejects requests with no active Login session
//!     for the named DID (so it can't be used as a primary login).
//!   - `/auth/step-up` rejects unknown purposes and the `login` purpose.
//!   - `scope_satisfies_purpose` correctly accepts both granular and
//!     legacy `transition:generic` grants for upload, and only the
//!     specific `repo:app.bsky.feed.post` grant for cross-post.

use freeq_sdk::did::DidResolver;
use std::collections::HashMap;
use std::net::SocketAddr;

use freeq_server::server::{OauthPurpose, scope_satisfies_purpose};

async fn start_server() -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-oauth-scope".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start_with_web().await.unwrap()
}

fn url(http: SocketAddr, path: &str) -> String {
    format!("http://{http}{path}")
}

// ─── Phase 1 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn client_metadata_advertises_narrow_scopes() {
    let (_irc, http, _h) = start_server().await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(url(http, "/client-metadata.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let scope = body["scope"].as_str().expect("scope field present");
    let tokens: std::collections::HashSet<&str> = scope.split_whitespace().collect();
    assert!(
        tokens.contains("atproto"),
        "metadata must include `atproto` for identity proof; got: {scope}"
    );
    assert!(
        tokens.iter().any(|t| t.starts_with("blob:image/")),
        "metadata must include the granular blob upload scope so step-up can request it; got: {scope}"
    );
    assert!(
        tokens.contains("repo:app.bsky.feed.post"),
        "metadata must include the granular Bluesky cross-post scope; got: {scope}"
    );
    // (transition:generic remains until the grace period closes — see
    // `metadata_keeps_transition_generic_for_refresh_grace_period`.)
}

// ─── Phase 2 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_rejects_when_no_login_session_exists() {
    // The endpoint is meant for *upgrading* an existing login. Without a
    // primary login it must refuse — otherwise it would be a back-door
    // sign-in that skips the consent screen for chat permissions.
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(
            http,
            "/auth/step-up?purpose=blob_upload&did=did:plc:notlogged",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn step_up_rejects_unknown_purpose() {
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(
            http,
            "/auth/step-up?purpose=become_admin&did=did:plc:abc",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn step_up_refuses_login_purpose() {
    // `login` is a valid OauthPurpose internally but isn't a step-up —
    // the primary login endpoint already covers it. Refuse to avoid
    // confusing dual paths.
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(http, "/auth/step-up?purpose=login&did=did:plc:abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ─── Scope predicate ─────────────────────────────────────────────────────

#[test]
fn scope_satisfies_login_with_granular_grant() {
    assert!(scope_satisfies_purpose("atproto", OauthPurpose::Login));
    assert!(scope_satisfies_purpose(
        "atproto blob:image/*",
        OauthPurpose::Login
    ));
}

#[test]
fn scope_satisfies_blob_upload_with_granular_grant() {
    // BlobUpload requires both a blob:* grant AND a repo:blue.irc.media
    // grant — the upload path creates a record alongside the blob.
    assert!(scope_satisfies_purpose(
        "atproto blob:image/* repo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload
    ));
    assert!(scope_satisfies_purpose(
        "atproto blob:*/* repo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload
    ));
    // Identity-only grant must NOT be enough for upload.
    assert!(!scope_satisfies_purpose(
        "atproto",
        OauthPurpose::BlobUpload
    ));
    // Blob grant alone (no record) must NOT be enough — record creation
    // would fail at the PDS.
    assert!(!scope_satisfies_purpose(
        "atproto blob:image/*",
        OauthPurpose::BlobUpload
    ));
}

#[test]
fn scope_satisfies_legacy_transition_generic_for_anything() {
    // Older PDSes downgrade granular requests to transition:generic.
    // Treat that as satisfying any purpose for backward compatibility.
    assert!(scope_satisfies_purpose(
        "atproto transition:generic",
        OauthPurpose::BlobUpload
    ));
    assert!(scope_satisfies_purpose(
        "atproto transition:generic",
        OauthPurpose::BlueskyPost
    ));
}

#[test]
fn scope_does_not_satisfy_bluesky_post_with_blob_only() {
    assert!(!scope_satisfies_purpose(
        "atproto blob:image/*",
        OauthPurpose::BlueskyPost
    ));
    assert!(scope_satisfies_purpose(
        "atproto repo:app.bsky.feed.post",
        OauthPurpose::BlueskyPost
    ));
}

#[test]
fn purpose_round_trips_through_string() {
    for p in [
        OauthPurpose::Login,
        OauthPurpose::BlobUpload,
        OauthPurpose::BlueskyPost,
    ] {
        let s = p.as_str();
        assert_eq!(OauthPurpose::parse(s), Some(p));
    }
    assert_eq!(OauthPurpose::parse("nonsense"), None);
}

#[test]
fn requested_scopes_are_narrow_not_transition_generic() {
    for p in [
        OauthPurpose::Login,
        OauthPurpose::BlobUpload,
        OauthPurpose::BlueskyPost,
        OauthPurpose::MediaSpace,
    ] {
        let s = p.requested_scope(Some("did:plc:testauthority"));
        assert!(
            !s.contains("transition:generic"),
            "purpose {:?} requests legacy scope: {s}",
            p
        );
        assert!(
            s.contains("atproto"),
            "purpose {:?} missing atproto: {s}",
            p
        );
    }
}

// ─── Adversarial: scope predicate edge cases ─────────────────────────────

#[test]
fn scope_predicate_handles_extra_whitespace() {
    // Real PDS responses sometimes have multiple spaces; tabs are unusual
    // but let's be tolerant. BlobUpload needs blob: + repo:blue.irc.media.
    assert!(scope_satisfies_purpose(
        "atproto    blob:image/*    repo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload,
    ));
    assert!(scope_satisfies_purpose(
        "atproto\tblob:image/*\trepo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload,
    ));
    assert!(scope_satisfies_purpose(
        "\n  atproto  \n",
        OauthPurpose::Login
    ));
}

#[test]
fn scope_predicate_is_case_sensitive_per_spec() {
    // OAuth scope strings are case-sensitive. ATPROTO (uppercase) is not
    // a valid scope; predicate must reject so we don't wrongly accept a
    // typo or a confused PDS.
    assert!(!scope_satisfies_purpose("ATPROTO", OauthPurpose::Login));
    assert!(!scope_satisfies_purpose(
        "atproto BLOB:image/*",
        OauthPurpose::BlobUpload,
    ));
}

#[test]
fn scope_predicate_rejects_empty_or_unrelated() {
    assert!(!scope_satisfies_purpose("", OauthPurpose::Login));
    assert!(!scope_satisfies_purpose(
        "openid email",
        OauthPurpose::Login
    ));
    assert!(!scope_satisfies_purpose(
        "atproto",
        OauthPurpose::BlobUpload
    ));
    assert!(!scope_satisfies_purpose(
        "atproto blob:audio/*",
        OauthPurpose::BlobUpload,
    ));
}

#[test]
fn scope_predicate_accepts_blob_image_subtype_grant() {
    // bsky.social may grant `blob:image/png` (subtype-narrowed) instead
    // of the wildcard. We accept it — the user has SOME image-upload
    // permission. NOTE: this is intentionally permissive; the upload
    // path doesn't enforce per-MIME beyond what the PDS itself enforces
    // at the uploadBlob call. The repo:blue.irc.media grant is still
    // required for the accompanying record creation.
    assert!(scope_satisfies_purpose(
        "atproto blob:image/png repo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload,
    ));
    assert!(scope_satisfies_purpose(
        "atproto blob:image/jpeg repo:blue.irc.media?action=create",
        OauthPurpose::BlobUpload,
    ));
}

#[test]
fn scope_predicate_treats_repo_wildcard_as_satisfying_post() {
    // `repo:*` is the "all collections" grant. Satisfies any specific
    // repo: requirement.
    assert!(scope_satisfies_purpose(
        "atproto repo:*",
        OauthPurpose::BlueskyPost,
    ));
}

// ─── Adversarial: legacy granted_scope from old PDSes ───────────────────

#[test]
fn legacy_transition_generic_satisfies_all_purposes_for_grace_period() {
    // The whole point of accepting transition:generic: an existing
    // session originally granted under the old wide scope must keep
    // working post-deploy until the user re-authenticates.
    for p in [
        OauthPurpose::Login,
        OauthPurpose::BlobUpload,
        OauthPurpose::BlueskyPost,
    ] {
        assert!(
            scope_satisfies_purpose("atproto transition:generic", p),
            "legacy wide grant should satisfy {:?}",
            p
        );
    }
    // Solo `transition:generic` (without atproto) is unusual but seen in
    // the wild — accept it for the grace period.
    assert!(scope_satisfies_purpose(
        "transition:generic",
        OauthPurpose::BlobUpload,
    ));
}

// ─── Adversarial: step-up endpoint quirks ────────────────────────────────

#[tokio::test]
async fn step_up_purpose_is_case_sensitive() {
    // `BLOB_UPLOAD` (uppercase) must not be treated as `blob_upload`,
    // otherwise URL fuzzers could discover unintended branches and a
    // typo would silently work in some places and not others.
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(
            http,
            "/auth/step-up?purpose=BLOB_UPLOAD&did=did:plc:abc",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn step_up_missing_did_query_returns_4xx() {
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(http, "/auth/step-up?purpose=blob_upload"))
        .send()
        .await
        .unwrap();
    // axum returns 400 for missing required query params; we just want
    // the request to not crash or 500.
    assert!(
        resp.status().is_client_error(),
        "missing did should be a client error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn step_up_with_garbage_did_is_unauthorized() {
    // No active Login session for "abc" → 401. Treats the malformed DID
    // the same as any other unknown DID — the endpoint never tries to
    // resolve / contact a remote.
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(http, "/auth/step-up?purpose=blob_upload&did=abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ─── Adversarial: client metadata superset must include every requested ──

#[tokio::test]
async fn metadata_scope_contains_every_requested_purpose_scope() {
    let (_irc, http, _h) = start_server().await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(url(http, "/client-metadata.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let metadata_scope: std::collections::HashSet<&str> =
        body["scope"].as_str().unwrap().split_whitespace().collect();
    for p in [
        OauthPurpose::Login,
        OauthPurpose::BlobUpload,
        OauthPurpose::BlueskyPost,
    ] {
        for token in p.requested_scope(None).split_whitespace() {
            assert!(
                metadata_scope.contains(token),
                "client-metadata.json scope ({:?}) is missing token `{token}` requested by purpose {:?}; \
                 PDSes that verify metadata-superset will reject the /authorize call",
                metadata_scope,
                p,
            );
        }
    }
}

#[tokio::test]
async fn metadata_keeps_transition_generic_for_refresh_grace_period() {
    // Existing refresh tokens in the broker DB were issued under the
    // legacy wide scope. Some PDSes reject refresh requests when the
    // current client metadata no longer permits the original grant
    // scope. Until the grace period closes we keep advertising it.
    let (_irc, http, _h) = start_server().await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(url(http, "/client-metadata.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let scope = body["scope"].as_str().unwrap();
    assert!(
        scope.split_whitespace().any(|s| s == "transition:generic"),
        "metadata must still list transition:generic during grace period, got: {scope}"
    );
}
