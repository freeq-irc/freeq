//! Private media via AT Protocol spaces.
//!
//! Each channel that shares private media owns one space,
//! `at://{authority}/space/at.freeq.media/{key}`, on the operator's
//! spaces-capable PDS. The space is created the first time media
//! is shared and the live channel roster is the access list.
//! Clients write to and read from members' own permissioned repos.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use freeq_sdk::did::DidResolver;

/// NSID of the space type. Part of every space ref this server creates.
pub const SPACE_TYPE: &str = "at.freeq.media";

/// Service fragment under which the managing-app endpoint is published in
/// this server's `did:web` document.
pub const MANAGING_APP_FRAGMENT: &str = "freeq_media";

/// Client for the spaces PDS plus the identity this server manages spaces as.
pub struct MediaSpaceManager {
    pub authority_did: String,
    password: String,
    /// PDS base URL; when unset, resolved from the authority's DID document.
    pds_override: Option<String>,
    pds_url: tokio::sync::Mutex<Option<String>>,
    session: tokio::sync::Mutex<Option<String>>,
    pub create_lock: tokio::sync::Mutex<()>,
    http: reqwest::Client,
    server_name: String,
}

impl MediaSpaceManager {
    pub fn new(
        authority_did: String,
        password: String,
        pds_override: Option<String>,
        server_name: String,
    ) -> Self {
        Self {
            authority_did,
            password,
            pds_override,
            pds_url: tokio::sync::Mutex::new(None),
            session: tokio::sync::Mutex::new(None),
            create_lock: tokio::sync::Mutex::new(()),
            http: reqwest::Client::new(),
            server_name,
        }
    }

    pub fn managing_app(&self) -> String {
        format!("did:web:{}#{}", self.server_name, MANAGING_APP_FRAGMENT)
    }

    pub fn space_ref(&self, key: &str) -> String {
        format!("at://{}/space/{}/{}", self.authority_did, SPACE_TYPE, key)
    }

    pub fn parse_space_key<'a>(&self, space: &'a str) -> Option<&'a str> {
        let rest = space.strip_prefix("at://")?;
        let mut parts = rest.split('/');
        let did = parts.next()?;
        let marker = parts.next()?;
        let space_type = parts.next()?;
        let key = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        (did == self.authority_did
            && marker == "space"
            && space_type == SPACE_TYPE
            && !key.is_empty())
        .then_some(key)
    }

    async fn pds_url(&self, resolver: &DidResolver) -> Result<String> {
        if let Some(ref url) = self.pds_override {
            return Ok(url.trim_end_matches('/').to_string());
        }
        let mut cached = self.pds_url.lock().await;
        if let Some(ref url) = *cached {
            return Ok(url.clone());
        }
        let doc = resolver
            .resolve(&self.authority_did)
            .await
            .context("resolving media space authority DID")?;
        let url = doc
            .service
            .iter()
            .find(|s| s.id.ends_with("#atproto_pds"))
            .map(|s| s.service_endpoint.trim_end_matches('/').to_string())
            .context("authority DID document has no #atproto_pds service")?;
        *cached = Some(url.clone());
        Ok(url)
    }

    async fn session_token(&self, resolver: &DidResolver) -> Result<String> {
        let mut session = self.session.lock().await;
        if let Some(ref token) = *session {
            return Ok(token.clone());
        }
        let pds = self.pds_url(resolver).await?;
        let res = self
            .http
            .post(format!("{pds}/xrpc/com.atproto.server.createSession"))
            .json(&serde_json::json!({
                "identifier": self.authority_did,
                "password": self.password,
            }))
            .send()
            .await
            .context("createSession request to spaces PDS")?;
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            bail!("createSession failed: {status} {body}");
        }
        let body: serde_json::Value = res.json().await.context("createSession response")?;
        let token = body["accessJwt"]
            .as_str()
            .context("createSession response missing accessJwt")?
            .to_string();
        *session = Some(token.clone());
        Ok(token)
    }

    /// Create the space for a channel key on the spaces PDS, with the
    /// managing-app policy pointing back at this server. An already-existing
    /// space (crash after create, before persist) is success.
    pub async fn create_space(&self, resolver: &DidResolver, key: &str) -> Result<()> {
        let pds = self.pds_url(resolver).await?;
        // One retry with a fresh session: the cached token may have expired.
        for attempt in 0..2 {
            if attempt > 0 {
                *self.session.lock().await = None;
            }
            let token = self.session_token(resolver).await?;
            let res = self
                .http
                .post(format!("{pds}/xrpc/com.atproto.simplespace.createSpace"))
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "type": SPACE_TYPE,
                    "skey": key,
                    "policy": {
                        "$type": "com.atproto.simplespace.defs#managingAppPolicy",
                        "managingApp": self.managing_app(),
                    },
                    "appAccess": { "$type": "com.atproto.simplespace.defs#open" },
                }))
                .send()
                .await
                .context("createSpace request to spaces PDS")?;
            let status = res.status();
            if status.is_success() {
                return Ok(());
            }
            let body = res.text().await.unwrap_or_default();
            if body.contains("SpaceAlreadyExists") {
                return Ok(());
            }
            if status.as_u16() == 401 && attempt == 0 {
                continue;
            }
            bail!("createSpace failed: {status} {body}");
        }
        unreachable!("createSpace retry loop always returns or bails");
    }
}

pub async fn verify_service_auth(
    resolver: &DidResolver,
    jwt: &str,
    authority_did: &str,
    expected_aud: &str,
    expected_lxm: &str,
) -> Result<()> {
    let mut parts = jwt.splitn(3, '.');
    let (Some(header), Some(payload), Some(sig)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("malformed JWT");
    };
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .context("JWT payload base64")?,
    )
    .context("JWT payload JSON")?;

    if claims["iss"].as_str() != Some(authority_did) {
        bail!("service auth iss is not the space authority");
    }
    if claims["aud"].as_str() != Some(expected_aud) {
        bail!("service auth aud is not this managing app");
    }
    if claims["lxm"].as_str() != Some(expected_lxm) {
        bail!("service auth lxm mismatch");
    }
    let exp = claims["exp"].as_i64().context("service auth missing exp")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if exp < now {
        bail!("service auth expired");
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .context("JWT signature base64")?;
    let signing_input = format!("{header}.{payload}");
    let doc = resolver
        .resolve(authority_did)
        .await
        .context("resolving space authority DID for service auth")?;
    // The signing key is in verificationMethod (atproto documents publish it
    // as #atproto). Accept any key the document lists.
    let mut keys: Vec<freeq_sdk::crypto::PublicKey> = doc
        .verification_method
        .iter()
        .filter_map(|vm| vm.public_key_multibase.as_deref())
        .filter_map(|mb| freeq_sdk::crypto::PublicKey::from_multibase(mb).ok())
        .collect();
    keys.extend(doc.authentication_keys().into_iter().map(|(_, k)| k));
    if keys.is_empty() {
        bail!("authority DID document lists no usable keys");
    }
    for key in &keys {
        if key.verify(signing_input.as_bytes(), &sig_bytes).is_ok() {
            return Ok(());
        }
    }
    bail!("service auth signature did not verify against any authority key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> MediaSpaceManager {
        MediaSpaceManager::new(
            "did:plc:authority123".to_string(),
            "pw".to_string(),
            None,
            "irc.example.org".to_string(),
        )
    }

    #[test]
    fn space_ref_round_trips_through_parse() {
        let m = mgr();
        let r = m.space_ref("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(
            r,
            "at://did:plc:authority123/space/at.freeq.media/01ARZ3NDEKTSV4RRFFQ69G5FAV"
        );
        assert_eq!(m.parse_space_key(&r), Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
    }

    #[test]
    fn parse_rejects_foreign_authority() {
        let m = mgr();
        assert_eq!(
            m.parse_space_key("at://did:plc:someoneelse/space/at.freeq.media/k1"),
            None
        );
    }

    #[test]
    fn parse_rejects_other_space_type() {
        let m = mgr();
        assert_eq!(
            m.parse_space_key("at://did:plc:authority123/space/com.example.other/k1"),
            None
        );
    }

    #[test]
    fn parse_rejects_record_uris_and_malformed_refs() {
        let m = mgr();
        // A URI naming a record within the space is not a space ref.
        assert_eq!(
            m.parse_space_key(
                "at://did:plc:authority123/space/at.freeq.media/k1/did:plc:x/at.freeq.media.item/3k"
            ),
            None
        );
        assert_eq!(
            m.parse_space_key("at://did:plc:authority123/space/at.freeq.media/"),
            None
        );
        assert_eq!(m.parse_space_key("not-a-uri"), None);
        assert_eq!(m.parse_space_key("at://did:plc:authority123"), None);
    }

    #[test]
    fn managing_app_is_did_web_of_this_server() {
        assert_eq!(mgr().managing_app(), "did:web:irc.example.org#freeq_media");
    }
}
