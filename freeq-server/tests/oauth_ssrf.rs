//! Adversarial tests for the OAuth/step-up surface — round 2 CTF.
//!
//! The OAuth flow makes outbound HTTP requests to URLs derived from
//! attacker-controlled inputs:
//!
//!   /auth/login (or /auth/step-up)
//!     → DidResolver.resolve(did)            ← resolves did:plc:foo to
//!                                             a DID document. The
//!                                             document's `service[]`
//!                                             can name *any* PDS URL.
//!     → GET <pds>/.well-known/oauth-protected-resource
//!     → GET <auth-server>/.well-known/oauth-authorization-server
//!     → POST <par-endpoint>
//!     → (callback) POST <token-endpoint>
//!
//! Every URL after the first is **fully attacker-controlled** in the
//! worst case — the attacker registers a public DID with a malicious
//! PDS URL, and the entire chain points wherever they want.
//!
//! Findings:
//!
//! - **CTF-07 (HIGH)**: SSRF via DID-document-controlled PDS URL. The
//!   server happily fetches `http://127.0.0.1:1/...` if the DID
//!   document says so.
//!
//! - **CTF-10 (MED)**: outbound HTTP has no timeout. A slow attacker
//!   PDS holds the server task open indefinitely.
//!
//! Both are fixed by routing every external fetch in
//! /auth/login + /auth/step-up through `freeq_sdk::ssrf` (private-IP
//! block + DNS pinning) and giving every outbound `reqwest::Client`
//! an explicit `timeout`.

use freeq_sdk::did::{self, DidResolver};
use freeq_sdk::oauth::DpopKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use freeq_server::server::{OauthPurpose, SharedState, WebSession};

const VICTIM_DID: &str = "did:plc:victim";
const ADMIN_DID: &str = "did:plc:ssrftester";
const ADMIN_SESSION: &str = "ssrf-test-session";

/// Spin up a server with a static DID resolver pre-loaded with a DID
/// document whose PDS service endpoint is `pds_url`. Plant a Login
/// session for `VICTIM_DID` so /auth/step-up will accept the probe.
async fn start_server_with_malicious_pds(
    pds_url: &str,
) -> (
    SocketAddr,
    Arc<SharedState>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let key = freeq_sdk::crypto::PrivateKey::generate_ed25519();
    let mut docs = HashMap::new();
    docs.insert(
        VICTIM_DID.to_string(),
        did::make_test_did_document_with_pds(
            VICTIM_DID,
            &key.public_key_multibase(),
            Some(pds_url),
        ),
    );
    let resolver = DidResolver::static_map(docs);

    let tmp = tempfile::Builder::new()
        .prefix("freeq-oauth-ssrf-")
        .suffix(".db")
        .tempfile()
        .unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    std::mem::forget(tmp);

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "ssrf-ctf".to_string(),
        challenge_timeout_secs: 60,
        oper_dids: vec![ADMIN_DID.to_string()],
        db_path: Some(db_path),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    let (_irc, http, handle, state) = server.start_with_web_state().await.unwrap();

    state
        .session_dids
        .lock()
        .insert(ADMIN_SESSION.to_string(), ADMIN_DID.to_string());

    // Plant a Login session so /auth/step-up accepts the request.
    state.web_sessions.lock().insert(
        (VICTIM_DID.to_string(), OauthPurpose::Login),
        WebSession {
            did: VICTIM_DID.to_string(),
            handle: "victim.example".into(),
            pds_url: pds_url.to_string(),
            access_token: "tok".into(),
            dpop_key_b64: DpopKey::generate().to_base64url(),
            dpop_nonce: None,
            created_at: Instant::now(),
            granted_scope: "atproto".into(),
        },
    );

    (http, state, handle)
}

fn url(http: SocketAddr, path: &str) -> String {
    format!("http://{http}{path}")
}

// ─── CTF-07: loopback / private PDS URL must be refused ─────────────────

#[tokio::test]
async fn ctf_07_step_up_refuses_loopback_pds_url() {
    // DID document says the PDS lives at 127.0.0.1:1 (a closed port
    // on localhost). Without an SSRF block the server tries to fetch
    // it, gets a connection error, and the response leaks the
    // internal address back to the attacker.
    let (http, _state, _h) = start_server_with_malicious_pds("http://127.0.0.1:1/").await;

    // Warm the process first. The refusal itself takes well under a
    // millisecond, but the *first* outbound-client construction in a process
    // pays a one-time cost (on macOS, loading the system TLS trust store) of
    // seconds. Measuring that made this assertion a coin flip against its own 3s
    // budget — it failed under load while the code under test was doing exactly
    // the right thing, sub-millisecond. Warmed, the same request is ~0.5ms, so
    // the budget below can be tight enough to actually catch a connect-then-fail.
    let warm = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    assert!(
        warm.status().is_client_error(),
        "warm-up request should already be refused: {}",
        warm.status()
    );

    let started = Instant::now();
    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    let elapsed = started.elapsed();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    // After fix: fast 4xx with a generic refusal — no internal info reflected.
    assert!(
        status.is_client_error(),
        "step-up to a loopback PDS must be refused with a 4xx; got {status}: {body}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "step-up to a loopback PDS must fail fast (URL validation, not connect-then-fail); \
         elapsed = {elapsed:?}"
    );
    assert!(
        !body.contains("127.0.0.1") && !body.contains("connection"),
        "response must not echo the internal address or the connect-error wording. Body: {body:?}"
    );
}

#[tokio::test]
async fn ctf_07_step_up_refuses_rfc1918_pds_url() {
    let (http, _state, _h) = start_server_with_malicious_pds("http://10.0.0.1/").await;

    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status.is_client_error(),
        "RFC1918 PDS URL must be refused; got {status}: {body}"
    );
    assert!(
        !body.contains("10.0.0.1"),
        "must not reflect the private address. Body: {body:?}"
    );
}

#[tokio::test]
async fn ctf_07_step_up_refuses_localhost_hostname() {
    // Even when the URL uses the literal `localhost` hostname (DNS
    // would resolve to 127.0.0.1), the SSRF check must catch it
    // before any DNS lookup or connect.
    let (http, _state, _h) = start_server_with_malicious_pds("http://localhost:9999/").await;

    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status.is_client_error(),
        "`localhost` PDS hostname must be refused; got {status}: {body}"
    );
    assert!(
        !body.contains("localhost") && !body.contains(":9999"),
        "must not reflect the private hostname/port. Body: {body:?}"
    );
}

#[tokio::test]
async fn ctf_07_step_up_refuses_link_local() {
    // 169.254.169.254 is the AWS / GCP metadata service. Any cloud-
    // hosted freeq with this unblocked is one DID document away from
    // having its instance credentials exfiltrated.
    let (http, _state, _h) = start_server_with_malicious_pds("http://169.254.169.254/").await;

    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status.is_client_error(),
        "link-local / cloud-metadata IP must be refused; got {status}: {body}"
    );
    assert!(
        !body.contains("169.254"),
        "must not reflect the metadata-service address. Body: {body:?}"
    );
}

// ─── CTF-07 sanity: scheme validation ───────────────────────────────────

// ─── CTF-12: Host header used to build redirect_uri ────────────────────

#[tokio::test]
async fn ctf_12_oauth_login_host_header_with_attacker_value() {
    // The server reads the Host header to build redirect_uri + the
    // loopback client_id (which embeds the redirect_uri). An attacker
    // who can spoof Host (some reverse-proxy configs forward it
    // unchanged) could try to redirect the OAuth callback to their
    // domain. This test pins current behaviour: the server must NOT
    // emit a redirect URL whose host is something other than what
    // the request actually arrived on. We don't test against a
    // non-loopback Host because the resolver path needs network; we
    // settle for confirming that Host="evil.example" doesn't crash
    // and doesn't get reflected into a Location pointing at evil.
    let (http, _state, _h) = start_server_with_malicious_pds("https://example.com/").await;
    let resp = reqwest::Client::new()
        .get(url(http, "/auth/login?handle=victim.example"))
        .header("Host", "evil.example.com")
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().await.unwrap_or_default();
    // Acceptable: 4xx/5xx (couldn't resolve / pds unreachable / etc.)
    // because the public Host doesn't match server bind. UNACCEPTABLE:
    // a 30x Location whose query carries `redirect_uri=…evil.example…`
    // because that would be a step-up to a domain the user can't
    // control.
    if status.is_redirection() {
        assert!(
            !location.contains("evil.example"),
            "CTF-12: redirect Location echoed the attacker-controlled Host \
             into redirect_uri / client_id: {location}"
        );
    } else {
        // Even on the error path, the body must not echo the
        // attacker Host (info leak / phishing).
        assert!(
            !body.contains("evil.example"),
            "CTF-12: response body echoed attacker-controlled Host: {body}"
        );
    }
}

// ─── CTF-11: stored XSS via OAuth callback error params ────────────────

#[tokio::test]
async fn ctf_11_oauth_callback_html_escapes_error_params() {
    // /auth/callback?error=...&error_description=... interpolates both
    // verbatim into the HTML page (`<p>{message}</p>`). The page's
    // CSP allows inline scripts, so a `<script>` payload in `error`
    // gets executed in the user's browser. Anyone can land a victim
    // on this URL.
    let (http, _state, _h) = start_server_with_malicious_pds("https://example.com/").await;

    let payload = "<script>alert(1)</script>";
    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!(
                "/auth/callback?error={}&error_description=hi",
                urlencoding::encode(payload)
            ),
        ))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains(payload),
        "CTF-11: OAuth callback page reflected a raw <script> tag from the \
         `error` query parameter. Anyone can XSS a victim by linking to \
         /auth/callback?error=… . Body should HTML-escape the message; \
         got: {body}"
    );
    // The escaped form should appear instead — so the user still sees
    // the error context, just safely.
    assert!(
        body.contains("&lt;script&gt;") || body.contains("&#x3C;script&#x3E;"),
        "CTF-11: expected the `<` to be HTML-escaped; got: {body}"
    );
}

#[tokio::test]
async fn ctf_07_step_up_refuses_non_http_scheme() {
    // file:// or gopher:// or ftp:// — anything outside http(s) should
    // bounce immediately. Most reqwest builds don't enable file: but
    // belt-and-braces: explicit scheme check.
    let (http, _state, _h) = start_server_with_malicious_pds("file:///etc/passwd").await;

    let resp = reqwest::Client::new()
        .get(url(
            http,
            &format!("/auth/step-up?purpose=blob_upload&did={VICTIM_DID}"),
        ))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "non-http scheme PDS URL must be refused; got {}",
        resp.status()
    );
}
