//! AT Protocol PDS (Personal Data Server) client.
//!
//! Handles:
//! - Session creation (login with handle + app password)
//! - Session verification (for server-side SASL checks)
//! - PDS service endpoint discovery from DID documents

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::did::{DidDocument, DidResolver};

/// A PDS session obtained by authenticating with an app password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdsSession {
    pub did: String,
    pub handle: String,
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
}

/// Response from getSession — verifies a session is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
}

/// Extract the PDS service endpoint URL from a DID document.
pub fn pds_endpoint(doc: &DidDocument) -> Option<String> {
    doc.service.iter().find_map(|svc| {
        if svc.service_type == "AtprotoPersonalDataServer" {
            Some(svc.service_endpoint.clone())
        } else {
            None
        }
    })
}

/// Authenticate to a PDS and get a session.
///
/// This is the standard AT Protocol login flow using an app password.
///
/// Steps:
/// 1. If `identifier` is a handle, resolve it to find the PDS
/// 2. Authenticate via `com.atproto.server.createSession`
/// 3. Return the session with DID, handle, and access JWT
pub async fn create_session(
    identifier: &str,
    password: &str,
    resolver: &DidResolver,
) -> Result<(PdsSession, String)> {
    let client = reqwest::Client::new();

    // Resolve identifier to DID and find PDS
    let did = if identifier.starts_with("did:") {
        identifier.to_string()
    } else {
        // It's a handle — resolve to DID
        resolver
            .resolve_handle(identifier)
            .await
            .context("Failed to resolve handle to DID")?
    };

    // Resolve DID document to find PDS endpoint
    let did_doc = resolver
        .resolve(&did)
        .await
        .context("Failed to resolve DID document")?;

    let pds_url =
        pds_endpoint(&did_doc).context("No PDS service endpoint found in DID document")?;

    tracing::info!(did = %did, pds = %pds_url, "Authenticating to PDS");

    // Call createSession
    let url = format!("{pds_url}/xrpc/com.atproto.server.createSession");
    let body = serde_json::json!({
        "identifier": identifier,
        "password": password,
    });

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to connect to PDS")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("PDS authentication failed ({status}): {text}");
    }

    let session: PdsSession = resp
        .json()
        .await
        .context("Failed to parse PDS session response")?;

    tracing::info!(did = %session.did, handle = %session.handle, "PDS session created");
    Ok((session, pds_url))
}

/// Refresh a PDS session using its refresh token.
///
/// Returns a new session with fresh access and refresh JWTs.
/// The old refresh token is invalidated.
pub async fn refresh_session(pds_url: &str, refresh_jwt: &str) -> Result<PdsSession> {
    let client = reqwest::Client::new();
    let url = format!("{pds_url}/xrpc/com.atproto.server.refreshSession");

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {refresh_jwt}"))
        .send()
        .await
        .context("Failed to connect to PDS for session refresh")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("PDS session refresh failed ({status}): {text}");
    }

    let session: PdsSession = resp
        .json()
        .await
        .context("Failed to parse PDS refresh response")?;

    tracing::info!(did = %session.did, "PDS session refreshed");
    Ok(session)
}

/// A PDS that answered getSession with something other than success. Its
/// status says whether the token was refused (4xx) or the PDS could not
/// answer (5xx, 429).
#[derive(Debug)]
pub struct SessionRefused {
    /// The HTTP status the PDS answered.
    pub status: u16,
    status_line: String,
    body: String,
}

impl std::fmt::Display for SessionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PDS session verification failed ({}): {}",
            self.status_line, self.body
        )
    }
}

impl std::error::Error for SessionRefused {}

/// Verify a PDS session by calling getSession.
///
/// Used by the server to verify a client's PDS session token.
/// Returns the session info (DID, handle) if valid. A PDS that answers with
/// another status gives a [`SessionRefused`].
pub async fn verify_session(pds_url: &str, access_jwt: &str) -> Result<SessionInfo> {
    let client = reqwest::Client::new();
    let url = format!("{pds_url}/xrpc/com.atproto.server.getSession");

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_jwt}"))
        .send()
        .await
        .context("Failed to connect to PDS for session verification")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(SessionRefused {
            status: status.as_u16(),
            status_line: status.to_string(),
            body,
        }
        .into());
    }

    let info: SessionInfo = resp
        .json()
        .await
        .context("Failed to parse PDS session info")?;

    Ok(info)
}

/// A Bluesky user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueskyProfile {
    pub did: String,
    pub handle: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub avatar: Option<String>,
    #[serde(rename = "followersCount")]
    pub followers_count: Option<u64>,
    #[serde(rename = "followsCount")]
    pub follows_count: Option<u64>,
    #[serde(rename = "postsCount")]
    pub posts_count: Option<u64>,
}

/// Fetch a Bluesky profile from the public API.
/// This uses the public AppView endpoint (no auth needed).
pub async fn fetch_profile(actor: &str) -> Result<BlueskyProfile> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}",
        percent_encode(actor),
    );

    let resp = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .context("Failed to fetch Bluesky profile")?;

    let profile: BlueskyProfile = resp
        .json()
        .await
        .context("Failed to parse Bluesky profile")?;

    Ok(profile)
}

fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                result.push(*byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Format a profile for display in WHOIS-style output.
impl BlueskyProfile {
    pub fn format_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        let name = self.display_name.as_deref().unwrap_or(&self.handle);
        lines.push(format!("📇 {name} (@{})", self.handle));

        if let Some(ref desc) = self.description {
            // Truncate to first line or 200 chars
            let short = desc.lines().next().unwrap_or(desc);
            let short = if short.len() > 200 {
                format!("{}…", &short[..200])
            } else {
                short.to_string()
            };
            lines.push(format!("  {short}"));
        }

        let followers = self.followers_count.unwrap_or(0);
        let following = self.follows_count.unwrap_or(0);
        let posts = self.posts_count.unwrap_or(0);
        lines.push(format!(
            "  {followers} followers · {following} following · {posts} posts"
        ));

        if let Some(ref avatar) = self.avatar {
            lines.push(format!("  🖼 {avatar}"));
        }

        lines
    }
}
