//! OIDC / Google Workspace verifier — proves a user controls an email at an
//! allowed domain (e.g. `@acme.com`), then issues a signed credential that the
//! policy framework uses to gate channel JOIN.
//!
//! This is the "company SSO" path: a firm running Google Workspace (or any
//! OIDC IdP — Okta, Entra ID, Auth0) points a channel policy at this verifier,
//! and only staff whose IdP login resolves to the company domain can join. The
//! resulting `oidc_domain` credential is *also* the signal a group-key steward
//! checks before sealing the channel key to a new member (see
//! `freeq-sdk::e2ee_group`), so SSO admission and E2E key access share one
//! source of truth — no shared passphrase.
//!
//! Routes:
//!   GET /verify/oidc/start?subject_did=...&callback=...
//!     → Redirect to the IdP authorization endpoint (scope: openid email).
//!   GET /verify/oidc/callback
//!     → Exchange code, read the ID token, check the domain, sign + POST the VC.
//!
//! Config (env, read in `verifiers::router`):
//!   OIDC_CLIENT_ID, OIDC_CLIENT_SECRET   — IdP OAuth client
//!   OIDC_ALLOWED_DOMAIN                   — e.g. "acme.com" (required)
//!   OIDC_REDIRECT_URL                     — this verifier's /verify/oidc/callback URL
//!   OIDC_AUTH_URL, OIDC_TOKEN_URL         — default to Google's endpoints
//!   OIDC_JWKS_URL, OIDC_ISSUER            — default to Google's; a non-Google
//!                                           IdP MUST set both or verification fails
//!
//! SECURITY: the ID token's signature is verified against the IdP's JWKS
//! (RS256/ES256 family only — HS* is refused), and `aud` == client_id,
//! `iss` == OIDC_ISSUER, `exp`, and the per-request `nonce` are all
//! validated before any claim is trusted. Fail-closed: a JWKS fetch error
//! or any validation failure aborts credential issuance.

use super::{PendingVerification, VerifierState};
use crate::policy::credentials;
use crate::policy::types::VerifiableCredential;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;

/// IdP + domain configuration for the OIDC verifier.
#[derive(Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Only users whose verified email is at this domain are issued a credential.
    pub allowed_domain: String,
    /// This verifier's own callback URL, registered with the IdP.
    pub redirect_url: String,
    pub auth_url: String,
    pub token_url: String,
    /// JWK Set URL used to verify the ID token's signature.
    pub jwks_url: String,
    /// Expected `iss` claim.
    pub issuer: String,
}

impl OidcConfig {
    /// Load from env. Returns None unless client id/secret and allowed domain
    /// are all set. Auth/token URLs default to Google.
    pub fn from_env() -> Option<Self> {
        let client_id = std::env::var("OIDC_CLIENT_ID").ok()?;
        let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok()?;
        let allowed_domain = std::env::var("OIDC_ALLOWED_DOMAIN").ok()?;
        if client_id.is_empty() || client_secret.is_empty() || allowed_domain.is_empty() {
            return None;
        }
        Some(Self {
            client_id,
            client_secret,
            allowed_domain,
            redirect_url: std::env::var("OIDC_REDIRECT_URL").unwrap_or_default(),
            auth_url: std::env::var("OIDC_AUTH_URL")
                .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".into()),
            token_url: std::env::var("OIDC_TOKEN_URL")
                .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
            jwks_url: std::env::var("OIDC_JWKS_URL")
                .unwrap_or_else(|_| "https://www.googleapis.com/oauth2/v3/certs".into()),
            issuer: std::env::var("OIDC_ISSUER")
                .unwrap_or_else(|_| "https://accounts.google.com".into()),
        })
    }
}

pub fn routes() -> Router<Arc<VerifierState>> {
    Router::new()
        .route("/verify/oidc/start", get(start))
        .route("/verify/oidc/callback", get(callback))
}

#[derive(Deserialize)]
struct StartQuery {
    /// DID of the user (already proven via AT Protocol auth on the freeq server).
    subject_did: String,
    /// URL to POST the signed credential to after verification.
    #[serde(default)]
    callback: String,
}

async fn start(
    Query(q): Query<StartQuery>,
    State(state): State<Arc<VerifierState>>,
) -> Result<Redirect, (StatusCode, String)> {
    let oidc = state.oidc.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OIDC verifier not configured".into(),
    ))?;

    let state_token = hex::encode(rand::random::<[u8; 16]>());
    // Per-request nonce, echoed back inside the *signed* ID token — binds
    // the token to this verification attempt (replay defense that `state`
    // alone can't provide, since `state` never enters the token).
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    state.pending.lock().insert(
        state_token.clone(),
        PendingVerification {
            subject_did: q.subject_did,
            callback_url: q.callback,
            provider_params: serde_json::json!({ "nonce": nonce }),
            created_at: std::time::Instant::now(),
        },
    );

    // `hd` hints Google to prefer the company domain; the callback still
    // enforces the domain regardless of this hint.
    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}&hd={}",
        oidc.auth_url,
        urlencoding_encode(&oidc.client_id),
        urlencoding_encode(&oidc.redirect_url),
        state_token,
        nonce,
        urlencoding_encode(&oidc.allowed_domain),
    );
    Ok(Redirect::temporary(&url))
}

async fn callback(
    Query(q): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<VerifierState>>,
) -> Response {
    let code = match q.get("code") {
        Some(c) => c.clone(),
        None => return error_page("No authorization code from the identity provider"),
    };
    let oauth_state = match q.get("state") {
        Some(s) => s.clone(),
        None => return error_page("Missing state parameter"),
    };

    let pending = match state.pending.lock().remove(&oauth_state) {
        Some(p) if p.created_at.elapsed() < std::time::Duration::from_secs(300) => p,
        Some(_) => return error_page("Verification expired. Please try again."),
        None => return error_page("Unknown or expired verification"),
    };

    let oidc = match &state.oidc {
        Some(c) => c,
        None => return error_page("OIDC verifier not configured"),
    };

    let http = reqwest::Client::new();
    let token_json: serde_json::Value = match http
        .post(&oidc.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", oidc.client_id.as_str()),
            ("client_secret", oidc.client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", oidc.redirect_url.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => return error_page(&format!("Token exchange failed: {e}")),
    };

    let id_token = match token_json["id_token"].as_str() {
        Some(t) => t.to_string(),
        None => {
            let err = token_json["error_description"]
                .as_str()
                .or(token_json["error"].as_str())
                .unwrap_or("no id_token in response");
            return error_page(&format!("IdP login failed: {err}"));
        }
    };

    // Verify the ID token for real: signature against the IdP JWKS, plus
    // aud == client_id, iss, exp, and the per-request nonce minted in
    // start(). Fail-closed — any error aborts issuance.
    let jwks = match fetch_jwks(&http, &oidc.jwks_url).await {
        Ok(j) => j,
        Err(e) => return error_page(&format!("Could not fetch the IdP signing keys: {e}")),
    };
    let expected_nonce = pending.provider_params["nonce"]
        .as_str()
        .map(str::to_string);
    let claims = match verify_with_jwks(
        &jwks,
        &id_token,
        &oidc.client_id,
        &oidc.issuer,
        expected_nonce.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => return error_page(&format!("ID token verification failed: {e}")),
    };

    let email = claims["email"].as_str().unwrap_or_default().to_lowercase();
    let email_verified = claims["email_verified"].as_bool().unwrap_or(false)
        || claims["email_verified"].as_str() == Some("true");
    // Google sets `hd` (hosted domain) for Workspace accounts; fall back to the
    // email's domain part for generic OIDC IdPs.
    let domain = claims["hd"]
        .as_str()
        .map(str::to_lowercase)
        .unwrap_or_else(|| email.rsplit('@').next().unwrap_or_default().to_string());

    if email.is_empty() || !email_verified {
        return error_page("The identity provider did not return a verified email.");
    }
    if domain != oidc.allowed_domain.to_lowercase() {
        return error_page(&format!(
            "{email} is at '{domain}', not the required domain '{}'.",
            oidc.allowed_domain
        ));
    }

    issue_credential(&state, &http, &pending, &email, &domain).await
}

/// Sign an `oidc_domain` credential and POST it to the callback URL.
async fn issue_credential(
    state: &Arc<VerifierState>,
    http: &reqwest::Client,
    pending: &PendingVerification,
    email: &str,
    domain: &str,
) -> Response {
    let mut vc = VerifiableCredential {
        credential_type_tag: "FreeqCredential/v1".into(),
        issuer: state.issuer_did.clone(),
        subject: pending.subject_did.clone(),
        credential_type: "oidc_domain".into(),
        claims: serde_json::json!({ "email": email, "domain": domain }),
        issued_at: chrono::Utc::now().to_rfc3339(),
        // Short TTL: re-auth through SSO picks up offboarding quickly, so an
        // ex-employee's credential lapses and they miss the next key epoch.
        expires_at: Some((chrono::Utc::now() + chrono::Duration::hours(12)).to_rfc3339()),
        signature: String::new(),
    };
    if let Err(e) = credentials::sign_credential(&mut vc, &state.signing_key) {
        return error_page(&format!("Failed to sign credential: {e}"));
    }

    tracing::info!(
        subject = %pending.subject_did,
        email = %email,
        domain = %domain,
        "OIDC verification complete, credential issued"
    );

    if !pending.callback_url.is_empty() {
        match http
            .post(&pending.callback_url)
            .json(&serde_json::json!({ "credential": vc }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => tracing::warn!(status = %r.status(), "OIDC credential callback failed"),
            Err(e) => tracing::warn!(error = %e, "OIDC credential callback request failed"),
        }
    }

    let safe_email = html_escape(email);
    let safe_domain = html_escape(domain);
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Verified</title>
<style>body{{font-family:system-ui;max-width:560px;margin:60px auto;text-align:center;background:#0a0a1a;color:#e0e0e0}}h1{{color:#0f0}}</style>
<script>if(window.opener){{window.opener.postMessage({{type:'freeq-credential',status:'verified',credential_type:'oidc_domain'}},'*');setTimeout(function(){{window.close()}},1500);}}</script>
</head><body><h1>✓ Verified</h1><p>{safe_email} confirmed at <code>{safe_domain}</code>.</p>
<p>You can close this window and return to freeq.</p></body></html>"#
    ))
    .into_response()
}

/// Fetch the IdP's JWK Set. The URL is operator config (env), never user input.
async fn fetch_jwks(
    http: &reqwest::Client,
    url: &str,
) -> Result<jsonwebtoken::jwk::JwkSet, String> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch failed: {e}"))?;
    resp.json()
        .await
        .map_err(|e| format!("JWKS parse failed: {e}"))
}

/// Verify an OIDC ID token against a JWK Set: signature, `aud` == client_id,
/// `iss` == issuer, `exp`, and (when expected) the per-request `nonce`.
/// Returns the verified claims. Asymmetric algorithms only — HS* is refused
/// outright, since an HMAC "signature" could be forged by anyone who knows
/// the (public) client id and would let a malicious IdP response mint
/// company credentials.
fn verify_with_jwks(
    jwks: &jsonwebtoken::jwk::JwkSet,
    id_token: &str,
    client_id: &str,
    issuer: &str,
    expected_nonce: Option<&str>,
) -> Result<serde_json::Value, String> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header = decode_header(id_token).map_err(|e| format!("bad token header: {e}"))?;
    let alg = match header.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512
        | Algorithm::ES256
        | Algorithm::ES384 => header.alg,
        other => return Err(format!("refusing ID token algorithm {other:?}")),
    };

    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None => jwks.keys.first(),
    }
    .ok_or_else(|| "no matching key in the IdP JWKS".to_string())?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| format!("unusable JWK: {e}"))?;

    let mut validation = Validation::new(alg);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer]);
    let data = decode::<serde_json::Value>(id_token, &key, &validation)
        .map_err(|e| format!("signature/claims validation failed: {e}"))?;

    if let Some(want) = expected_nonce {
        if data.claims["nonce"].as_str() != Some(want) {
            return Err("nonce mismatch — token was not minted for this request".into());
        }
    }

    Ok(data.claims)
}

/// Minimal percent-encoding for query-string values (avoids a new dependency).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn error_page(msg: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>freeq — Error</title>
<style>body{{font-family:system-ui;max-width:500px;margin:80px auto;text-align:center;background:#0a0a1a;color:#e0e0e0}}h1{{color:#f44}}p{{white-space:pre-wrap;text-align:left}}</style>
</head><body><h1>Verification Failed</h1><p>{}</p></body></html>"#,
        html_escape(msg)
    );
    Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    /// Throwaway RSA key generated FOR THESE TESTS ONLY (never trusts
    /// anything real): lets us sign tokens and verify them against the
    /// matching JWK, exactly the way an IdP + JWKS pair works.
    const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAu9IR/iy0asHfX6PXbr8VIMGQVwcNzjFH5BD3x2u4BmuFj3mE
IUQ0prMkVvfNVcUnCwaoqTZO+KD6qJ85Q95nGQr45pdqAw2VaIDoHqSrXVvAp0yR
8zi+qicwFNuxwrzSZzoQMYLi1vQnwhAlbHOAxE0WjHT2kqeVAZZ57DiH2TyNLfQT
rThucM51fFC2OiZXHOlRa4JY54QNcnJHBBTojncT9doSYI5OxBHqC6Dc2guk+0dw
42EUDcyIDws/qLBk5zrePA/8xkTFVbR3qrgrXMigfV0Jy3yyi7XxeU3Jqw+03P2e
+T8mVQshRqK+8ib7t73GoyxUCaRutDuN6JLS4wIDAQABAoIBAQC5jzXPlIM65ge2
Cb0R4R8SmantET8Gc5G/NTRXhYjubtQph7iO1T/fYiWI9pGbJ4kHT7DaXJlw8joy
1fxRnSzmhPybdQR7t7Pg51psy+ux9LBFmVSoo2tb2BOcx+C7sKl+6tKM1+8cx2Nw
S1tt5j9VsYORiQ0CnyaLxwr14nP0njhKtWRhIGH3YB9Ys3qEMQsoFmyBz8xTB47e
XjYsS0BZ/ppN4Zc1oxLdCDL689pt8KqnbxgWB/TGM19lrevXEdRAHPBd9aSPmITY
ODqo2lSDRBFPd1StMZ4jw7Mojcb+P17OhFe8heN66bUCjp/yM8RJcCzZEOGOW9My
7jDPv/MhAoGBAOctN089LksmRbFPgO7RWbHBV8B4QxLvtrYrkPC8PIFSGsXgAg+R
cQYdRm+CmhjfrJeajRDW4RrJXrknxuXQs1i8lNS1XWfEKP9RaZB6nDoOsPnFOPcF
5IG8VRni3QMAFu8wNKz7GOTU7CGoZFZMcRWnJPv2A8cJ8bwyJb7Ui3zlAoGBAM/9
C7hgZTiQQUluKh5EfVHVVs9/itBa8qQxtxvBMH28X2NGlib/R0FYMnuVGRcAIa/k
32JywrPcoip4EL11oJxQaRVsa7BEx+t20l1Gg+wAKzZau+oDnMumnYd3kM20nBNJ
zRyQUpHmzeIC2HBEVnXN1tdjCq5vYRW8xQ7GJtwnAoGAEW65cwI8EXKrYrmKEXg7
+UmJInxvImhtMMOMRHsNXPsiBbXksePX0Aw5GYORtzp2u1/uL0zk4K46tF+pgf8A
5zohRwD+MCr8pHQxL7HvQfmFovAaYZZSKu5WxIL1A5roH9VUw46Ty/26aLdYCaHu
DSHzigR9OG8piXWGnyNL+XkCgYEAzJR7hcUTazrBbQf2V8VIe0jcVcd/dAgxaP4Z
vSwelV7HeLACm6M3pHerWFHE1xHjEM+QRpbZGu+ndxyYYrMj4v1ZD6CQoFZXSy2a
J/NnaaiU2KcQ9VLOVKazhn8+KIhBiNtr7G+tOCQNWQUxfeRKIx/v9fZOmFun5CjE
sA6KRLsCgYEAo+rreJxnfqo3rXn6FdzShFXAbGWZyz7cIMUB4G6xAXL5Y81SAVQ6
dQC7msWeoFpAFZrO280EKTQ+ksKLigIJVLLlA/3jkaogEgbax+Folzi3YsQnMxVM
W3K0eJYUi/dwfH6BmLOf9bjPDuMkwaDakGhul0d54zTPL5j6vvaQATc=
-----END RSA PRIVATE KEY-----";

    const TEST_RSA_N: &str = "u9IR_iy0asHfX6PXbr8VIMGQVwcNzjFH5BD3x2u4BmuFj3mEIUQ0prMkVvfNVcUnCwaoqTZO-KD6qJ85Q95nGQr45pdqAw2VaIDoHqSrXVvAp0yR8zi-qicwFNuxwrzSZzoQMYLi1vQnwhAlbHOAxE0WjHT2kqeVAZZ57DiH2TyNLfQTrThucM51fFC2OiZXHOlRa4JY54QNcnJHBBTojncT9doSYI5OxBHqC6Dc2guk-0dw42EUDcyIDws_qLBk5zrePA_8xkTFVbR3qrgrXMigfV0Jy3yyi7XxeU3Jqw-03P2e-T8mVQshRqK-8ib7t73GoyxUCaRutDuN6JLS4w";

    const CLIENT_ID: &str = "test-client";
    const ISSUER: &str = "https://idp.example";
    const KID: &str = "test-key-1";

    fn test_jwks() -> jsonwebtoken::jwk::JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": KID,
                "n": TEST_RSA_N,
                "e": "AQAB",
            }]
        }))
        .expect("test JWKS parses")
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn sign_claims(claims: &serde_json::Value) -> String {
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("test key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.into());
        encode(&header, claims, &key).expect("sign")
    }

    fn good_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": now() + 300,
            "iat": now(),
            "nonce": "nonce-123",
            "email": "jane@acme.com",
            "email_verified": true,
            "hd": "acme.com",
        })
    }

    #[test]
    fn accepts_properly_signed_token() {
        let token = sign_claims(&good_claims());
        let claims = verify_with_jwks(&test_jwks(), &token, CLIENT_ID, ISSUER, Some("nonce-123"))
            .expect("valid token verifies");
        assert_eq!(claims["email"], "jane@acme.com");
        assert_eq!(claims["hd"], "acme.com");
    }

    #[test]
    fn rejects_tampered_payload() {
        let token = sign_claims(&good_claims());
        // Swap the payload for one claiming a different email; signature
        // no longer matches.
        use base64::Engine;
        let mut evil = good_claims();
        evil["email"] = serde_json::json!("mallory@acme.com");
        let parts: Vec<&str> = token.split('.').collect();
        let forged_payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(evil.to_string().as_bytes());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert!(
            verify_with_jwks(&test_jwks(), &forged, CLIENT_ID, ISSUER, Some("nonce-123")).is_err()
        );
    }

    #[test]
    fn rejects_wrong_audience_and_issuer() {
        let mut c = good_claims();
        c["aud"] = serde_json::json!("some-other-client");
        assert!(
            verify_with_jwks(&test_jwks(), &sign_claims(&c), CLIENT_ID, ISSUER, None).is_err(),
            "wrong aud must fail"
        );

        let mut c = good_claims();
        c["iss"] = serde_json::json!("https://evil.example");
        assert!(
            verify_with_jwks(&test_jwks(), &sign_claims(&c), CLIENT_ID, ISSUER, None).is_err(),
            "wrong iss must fail"
        );
    }

    #[test]
    fn rejects_expired_token() {
        let mut c = good_claims();
        c["exp"] = serde_json::json!(now() - 600);
        assert!(verify_with_jwks(&test_jwks(), &sign_claims(&c), CLIENT_ID, ISSUER, None).is_err());
    }

    #[test]
    fn rejects_nonce_mismatch_and_missing_nonce() {
        let token = sign_claims(&good_claims());
        assert!(
            verify_with_jwks(&test_jwks(), &token, CLIENT_ID, ISSUER, Some("other-nonce")).is_err(),
            "nonce mismatch must fail"
        );

        let mut c = good_claims();
        c.as_object_mut().unwrap().remove("nonce");
        assert!(
            verify_with_jwks(
                &test_jwks(),
                &sign_claims(&c),
                CLIENT_ID,
                ISSUER,
                Some("nonce-123")
            )
            .is_err(),
            "missing nonce must fail when one is expected"
        );
    }

    #[test]
    fn refuses_hmac_algorithms() {
        // A token HMAC-signed with a guessable secret must be refused by
        // algorithm before any key lookup happens.
        let key = EncodingKey::from_secret(CLIENT_ID.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &good_claims(), &key).unwrap();
        let err = verify_with_jwks(&test_jwks(), &token, CLIENT_ID, ISSUER, Some("nonce-123"))
            .unwrap_err();
        assert!(err.contains("refusing"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_kid() {
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rotated-away".into());
        let token = encode(&header, &good_claims(), &key).unwrap();
        assert!(
            verify_with_jwks(&test_jwks(), &token, CLIENT_ID, ISSUER, None).is_err(),
            "kid not in JWKS must fail"
        );
    }

    #[test]
    fn query_encoding_escapes_reserved() {
        assert_eq!(urlencoding_encode("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(urlencoding_encode("acme.com"), "acme.com");
    }
}
