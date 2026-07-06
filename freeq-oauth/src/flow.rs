//! Token-endpoint flows: refresh (with dead-vs-transient classification).
//!
//! These take an injected `reqwest::Client` so the caller owns the SSRF /
//! timeout policy (see the crate docs). The refresh logic is the standalone
//! broker's — the reference implementation for the auth unification.

use crate::DpopKey;

/// Outcome of a successful refresh-token grant.
pub struct RefreshedTokens {
    pub access_token: String,
    /// The rotated refresh token, or the input token if the PDS omitted one.
    pub refresh_token: String,
    pub dpop_nonce: Option<String>,
    /// The scope the PDS actually granted. Defaults to
    /// `atproto transition:generic` when the response omits `scope`:
    /// conservative, because refresh tokens the broker holds today were
    /// originally granted under the wide transitional scope, so a missing
    /// field means "preserve the existing grant".
    pub granted_scope: String,
}

/// Distinguishes a permanently-dead session from a transient failure so the
/// caller can return the right status. Mapping every failure to a retryable
/// error makes a revoked/expired refresh token indistinguishable from "PDS
/// briefly down" — clients then retry a dead token forever and never reach
/// sign-in (the 2026-07-03 "Reconnecting… forever" bug).
#[derive(Debug)]
pub enum RefreshError {
    /// The refresh token is revoked/expired (OAuth `invalid_grant`). The user
    /// MUST re-authenticate — callers surface this as 401.
    InvalidGrant,
    /// Network error, PDS 5xx, malformed response, etc. — retryable (502).
    Transient(anyhow::Error),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::InvalidGrant => {
                write!(f, "refresh token invalid_grant (re-auth required)")
            }
            RefreshError::Transient(e) => write!(f, "{e}"),
        }
    }
}

impl From<anyhow::Error> for RefreshError {
    fn from(e: anyhow::Error) -> Self {
        RefreshError::Transient(e)
    }
}

impl From<reqwest::Error> for RefreshError {
    fn from(e: reqwest::Error) -> Self {
        RefreshError::Transient(e.into())
    }
}

/// True when an OAuth token-endpoint error body signals a permanently-dead
/// grant: `{"error":"invalid_grant"}` (RFC 6749 §5.2). Also treats an
/// explicit `unauthorized_client` on the refresh grant as dead, since
/// retrying won't help.
pub fn is_invalid_grant(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .map(|err| matches!(err.as_str(), "invalid_grant" | "unauthorized_client"))
        .unwrap_or(false)
}

/// Outcome of an authorization-code exchange: the raw token-endpoint JSON
/// (callers extract `access_token` / `sub` / `refresh_token` / `scope` as
/// they need) plus the DPoP nonce in force after the exchange.
pub struct ExchangedTokens {
    pub token_response: serde_json::Value,
    pub dpop_nonce: Option<String>,
}

/// Exchange an authorization code for tokens, performing the DPoP
/// `use_dpop_nonce` retry dance (retry once on 400/401 when the response
/// carries a nonce).
///
/// `initial_nonce` is any DPoP nonce the caller already holds from an earlier
/// step (e.g. the PAR response). Passing it makes the FIRST attempt carry the
/// nonce — important because the PDS consumes the auth code even on a
/// `use_dpop_nonce` failure, so a naive retry-with-fresh-nonce gets
/// `invalid_grant: Invalid code`. It is also the fallback nonce if the
/// responses carry none.
///
/// On any non-success terminal response the error carries the endpoint's
/// body text so the caller can render its own page / redirect.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
    dpop_key: &DpopKey,
    initial_nonce: Option<&str>,
) -> anyhow::Result<ExchangedTokens> {
    use anyhow::Context;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    let dpop_proof = dpop_key.proof("POST", token_endpoint, initial_nonce, None)?;
    let resp = client
        .post(token_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .context("Token exchange request failed")?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| initial_nonce.map(str::to_string));

    let token_response: serde_json::Value =
        if (status.as_u16() == 400 || status.as_u16() == 401) && dpop_nonce.is_some() {
            let nonce = dpop_nonce.as_deref().unwrap();
            let dpop_proof2 = dpop_key.proof("POST", token_endpoint, Some(nonce), None)?;
            let resp2 = client
                .post(token_endpoint)
                .header("DPoP", &dpop_proof2)
                .form(&params)
                .send()
                .await
                .context("Token exchange retry failed")?;
            if !resp2.status().is_success() {
                let status = resp2.status();
                let text = resp2.text().await.unwrap_or_default();
                anyhow::bail!("Token exchange failed ({status}): {text}");
            }
            resp2.json().await.context("Failed to parse token response")?
        } else if status.is_success() {
            resp.json().await.context("Failed to parse token response")?
        } else {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Token exchange failed ({status}): {text}");
        };

    Ok(ExchangedTokens {
        token_response,
        dpop_nonce,
    })
}

/// Exchange a refresh token for a fresh access token, performing the DPoP
/// `use_dpop_nonce` retry dance. `client_id` and `dpop_key` must match the
/// original grant; `current_nonce` is the last DPoP nonce the caller holds
/// for this session (used both to seed the first attempt's retry and as the
/// fallback if the response carries none).
pub async fn refresh_access_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    dpop_key: &DpopKey,
    refresh_token: &str,
    current_nonce: Option<&str>,
) -> Result<RefreshedTokens, RefreshError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];

    let dpop_proof = dpop_key.proof("POST", token_endpoint, None, None)?;
    let resp = client
        .post(token_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await?;
    let status = resp.status();
    let mut dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| current_nonce.map(str::to_string));

    let token_resp: serde_json::Value =
        if (status.as_u16() == 400 || status.as_u16() == 401) && dpop_nonce.is_some() {
            let nonce = dpop_nonce.as_deref().unwrap();
            let dpop_proof2 = dpop_key.proof("POST", token_endpoint, Some(nonce), None)?;
            let resp2 = client
                .post(token_endpoint)
                .header("DPoP", &dpop_proof2)
                .form(&params)
                .send()
                .await?;
            if !resp2.status().is_success() {
                let body = resp2.text().await.unwrap_or_default();
                if is_invalid_grant(&body) {
                    return Err(RefreshError::InvalidGrant);
                }
                return Err(RefreshError::Transient(anyhow::anyhow!(
                    "Refresh failed: {body}"
                )));
            }
            resp2
                .json()
                .await
                .map_err(|e| RefreshError::Transient(e.into()))?
        } else if status.is_success() {
            resp.json()
                .await
                .map_err(|e| RefreshError::Transient(e.into()))?
        } else {
            // Classify the error body. A dead refresh token comes back as 400
            // invalid_grant on the FIRST try when no DPoP nonce dance is needed
            // (or the nonce was already fresh).
            let body = resp.text().await.unwrap_or_default();
            if is_invalid_grant(&body) {
                return Err(RefreshError::InvalidGrant);
            }
            return Err(RefreshError::Transient(anyhow::anyhow!(
                "Refresh failed ({status}): {body}"
            )));
        };

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token"))?
        .to_string();
    let rotated_refresh = token_resp["refresh_token"]
        .as_str()
        .unwrap_or(refresh_token)
        .to_string();
    dpop_nonce = token_resp
        .get("dpop_nonce")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or(dpop_nonce);
    let granted_scope = token_resp["scope"]
        .as_str()
        .unwrap_or("atproto transition:generic")
        .to_string();

    Ok(RefreshedTokens {
        access_token,
        refresh_token: rotated_refresh,
        dpop_nonce,
        granted_scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_grant_body_is_detected() {
        assert!(is_invalid_grant(
            r#"{"error":"invalid_grant","error_description":"token has been revoked"}"#
        ));
        assert!(is_invalid_grant(r#"{"error":"unauthorized_client"}"#));
    }

    #[test]
    fn transient_bodies_are_not_invalid_grant() {
        assert!(!is_invalid_grant(r#"{"error":"use_dpop_nonce"}"#));
        assert!(!is_invalid_grant(r#"{"error":"server_error"}"#));
        assert!(!is_invalid_grant(r#"{"error":"temporarily_unavailable"}"#));
        assert!(!is_invalid_grant("Bad Gateway"));
        assert!(!is_invalid_grant(""));
        assert!(!is_invalid_grant("{}"));
        assert!(!is_invalid_grant(r#"{"error":123}"#));
    }

    #[test]
    fn refresh_error_maps_display() {
        assert!(RefreshError::InvalidGrant.to_string().contains("re-auth"));
    }
}
