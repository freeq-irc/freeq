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

use crate::media_store::MAX_MEDIA_BYTES;

/// NSID of the space type. Part of every space ref this server creates.
pub const SPACE_TYPE: &str = "at.freeq.media";

/// Service fragment under which the managing-app endpoint is published in
/// this server's `did:web` document.
pub const MANAGING_APP_FRAGMENT: &str = "freeq_media";

/// Collection holding one media item per record inside a media space.
pub const MEDIA_COLLECTION: &str = "at.freeq.media.item";

/// Call timeout on a repo host.
const REPO_HOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// The OAuth scopes an upload to this server's media spaces takes:
/// `blob:*/*` for the bytes, which go up through the ordinary uploadBlob,
/// and the space scope for the record that pins them.
///
/// The type is `*` because a named one must resolve to a published lexicon,
/// and [`SPACE_TYPE`] is not published.
pub fn space_scope(authority_did: &str) -> String {
    format!("blob:*/* space:*?authority={authority_did}&collection=*")
}

/// Check for a stale cached session token.
fn session_expired(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED || body.contains("ExpiredToken")
}

/// Client for the spaces PDS plus the identity this server manages spaces as.
pub struct MediaSpaceManager {
    pub authority_did: String,
    password: String,
    /// PDS base URL; when unset, resolved from the authority's DID document.
    pds_override: Option<String>,
    pds_url: tokio::sync::Mutex<Option<String>>,
    session: tokio::sync::Mutex<Option<String>>,
    pub create_lock: tokio::sync::Mutex<()>,
    credentials: tokio::sync::Mutex<std::collections::HashMap<String, CachedCredential>>,
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
            credentials: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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
            if session_expired(status, &body) && attempt == 0 {
                continue;
            }
            bail!("createSpace failed: {status} {body}");
        }
        unreachable!("createSpace retry loop always returns or bails");
    }

    /// Parse a record URI naming a record in one of this server's spaces:
    /// `at://{authority}/space/{type}/{skey}/{author}/{collection}/{rkey}`.
    pub fn parse_record_uri(&self, uri: &str) -> Option<SpaceRecordRef> {
        let rest = uri.strip_prefix("at://")?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [did, marker, space_type, skey, author, collection, rkey] = parts[..] else {
            return None;
        };
        if did != self.authority_did
            || marker != "space"
            || space_type != SPACE_TYPE
            || skey.is_empty()
            || !author.starts_with("did:")
            || collection.is_empty()
            || rkey.is_empty()
        {
            return None;
        }
        Some(SpaceRecordRef {
            space: self.space_ref(skey),
            space_key: skey.to_string(),
            author_did: author.to_string(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
        })
    }

    /// A space credential for reading `space`, minted for this server's own
    /// authority identity and bound to a DPoP key.
    ///
    /// The server reads on behalf of members it has already authorized.
    async fn space_credential(
        &self,
        resolver: &DidResolver,
        space: &str,
    ) -> Result<(String, freeq_sdk::oauth::DpopKey)> {
        {
            let cache = self.credentials.lock().await;
            if let Some(entry) = cache.get(space)
                && entry.good_until > now_secs()
            {
                return Ok((
                    entry.credential.clone(),
                    freeq_sdk::oauth::DpopKey::from_base64url(&entry.dpop_key_b64)?,
                ));
            }
        }

        let pds = self.pds_url(resolver).await?;
        // Step 1: our PDS creates a delegation token for the space.
        let mut delegation = None;
        for attempt in 0..2 {
            if attempt > 0 {
                *self.session.lock().await = None;
            }
            let token = self.session_token(resolver).await?;
            let res = self
                .http
                .get(format!("{pds}/xrpc/com.atproto.space.getDelegationToken"))
                .query(&[("space", space)])
                .bearer_auth(&token)
                .send()
                .await
                .context("getDelegationToken request")?;
            let status = res.status();
            if status.is_success() {
                delegation = res.json::<serde_json::Value>().await?["token"]
                    .as_str()
                    .map(str::to_string);
                break;
            }
            let body = res.text().await.unwrap_or_default();
            if session_expired(status, &body) && attempt == 0 {
                continue;
            }
            bail!("getDelegationToken failed: {status} {body}");
        }
        let delegation = delegation.context("getDelegationToken returned no token")?;

        // Step 2: the authority exchanges it for a credential bound to our
        // DPoP key. Presenting the proof here is what sets that binding.
        let dpop_key = freeq_sdk::oauth::DpopKey::generate();
        let url = format!("{pds}/xrpc/com.atproto.space.getSpaceCredential");
        let mut nonce: Option<String> = None;
        let mut credential = None;
        for attempt in 0..3 {
            let proof = dpop_key.proof("POST", &url, nonce.as_deref(), None)?;
            let res = self
                .http
                .post(&url)
                .header("Authorization", format!("Bearer {delegation}"))
                .header("DPoP", proof)
                .json(&serde_json::json!({ "space": space }))
                .send()
                .await
                .context("getSpaceCredential request")?;
            if let Some(n) = res
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
            {
                nonce = Some(n.to_string());
            }
            let status = res.status();
            if status.is_success() {
                credential = res.json::<serde_json::Value>().await?["credential"]
                    .as_str()
                    .map(str::to_string);
                break;
            }
            let body = res.text().await.unwrap_or_default();
            // The first call to a host has no nonce yet and is expected to
            // fail once with the nonce we then use.
            if (status == 401 || status == 400) && attempt < 2 {
                continue;
            }
            bail!("getSpaceCredential failed: {status} {body}");
        }
        let credential = credential.context("getSpaceCredential returned no credential")?;

        self.credentials.lock().await.insert(
            space.to_string(),
            CachedCredential {
                credential: credential.clone(),
                dpop_key_b64: dpop_key.to_base64url(),
                good_until: now_secs() + 1800,
            },
        );
        Ok((credential, dpop_key))
    }

    /// Fetch a media record and its blob from the author's PDS. Returns the
    /// bytes and the MIME type the record declares.
    pub async fn fetch_media(
        &self,
        resolver: &DidResolver,
        rec: &SpaceRecordRef,
    ) -> Result<(Vec<u8>, String)> {
        let (credential, dpop_key) = self.space_credential(resolver, &rec.space).await?;
        let author_doc = resolver
            .resolve(&rec.author_did)
            .await
            .context("resolving media author's DID")?;
        let repo_host = author_doc
            .service
            .iter()
            .find(|s| s.id.ends_with("#atproto_pds"))
            .map(|s| s.service_endpoint.trim_end_matches('/').to_string())
            .context("media author's DID document has no PDS")?;

        let record = self
            .space_get_json(
                &format!("{repo_host}/xrpc/com.atproto.space.getRecord"),
                &[
                    ("space", rec.space.as_str()),
                    ("repo", rec.author_did.as_str()),
                    ("collection", rec.collection.as_str()),
                    ("rkey", rec.rkey.as_str()),
                ],
                &credential,
                &dpop_key,
            )
            .await
            .context("fetching space media record")?;
        let value = &record["value"];
        let cid = value["blob"]["ref"]["$link"]
            .as_str()
            .context("media record has no blob reference")?;
        let mime = value["mimeType"]
            .as_str()
            .unwrap_or("application/octet-stream")
            .to_string();

        let bytes = self
            .space_get_bytes(
                &format!("{repo_host}/xrpc/com.atproto.space.getBlob"),
                &[
                    ("space", rec.space.as_str()),
                    ("repo", rec.author_did.as_str()),
                    ("cid", cid),
                ],
                &credential,
                &dpop_key,
            )
            .await
            .context("fetching space media blob")?;
        Ok((bytes, mime))
    }

    async fn space_get_json(
        &self,
        url: &str,
        params: &[(&str, &str)],
        credential: &str,
        dpop_key: &freeq_sdk::oauth::DpopKey,
    ) -> Result<serde_json::Value> {
        let bytes = self
            .space_get_bytes(url, params, credential, dpop_key)
            .await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// A credential-authenticated XRPC GET, with the DPoP nonce handshake the
    /// first call to a host always needs.
    async fn space_get_bytes(
        &self,
        url: &str,
        params: &[(&str, &str)],
        credential: &str,
        dpop_key: &freeq_sdk::oauth::DpopKey,
    ) -> Result<Vec<u8>> {
        // An SSRF check is needed here as the DID document can point anywhere.
        let (_, client) = crate::web::safe_outbound_client(url, REPO_HOST_TIMEOUT)
            .await
            .map_err(|(_, msg)| anyhow::anyhow!("{msg}"))?;
        let mut nonce: Option<String> = None;
        for attempt in 0..3 {
            let proof = dpop_key.proof("GET", url, nonce.as_deref(), Some(credential))?;
            let res = client
                .get(url)
                .query(params)
                .header("Authorization", format!("DPoP {credential}"))
                .header("DPoP", proof)
                .send()
                .await?;
            if let Some(n) = res
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
            {
                nonce = Some(n.to_string());
            }
            let status = res.status();
            if status.is_success() {
                if let Some(len) = res.content_length()
                    && len > MAX_MEDIA_BYTES as u64
                {
                    bail!("media is larger than the {} byte ceiling", MAX_MEDIA_BYTES);
                }
                // Read in chunks until we hit MAX_MEDIA_BYTES.
                let mut res = res;
                let mut body: Vec<u8> = Vec::new();
                while let Some(chunk) = res.chunk().await? {
                    if body.len() + chunk.len() > MAX_MEDIA_BYTES {
                        bail!("media is larger than the {} byte ceiling", MAX_MEDIA_BYTES);
                    }
                    body.extend_from_slice(&chunk);
                }
                return Ok(body);
            }
            if (status == 401 || status == 400) && attempt < 2 {
                continue;
            }
            let body = res.text().await.unwrap_or_default();
            bail!("{status}: {body}");
        }
        bail!("space request failed after retries")
    }
}

/// A record inside one of this server's spaces, as named by an `at://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRecordRef {
    /// The space the record lives in, without the record tail.
    pub space: String,
    pub space_key: String,
    pub author_did: String,
    pub collection: String,
    pub rkey: String,
}

struct CachedCredential {
    credential: String,
    dpop_key_b64: String,
    good_until: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    fn parses_a_record_uri_in_one_of_our_spaces() {
        let m = mgr();
        let rec = m
            .parse_record_uri(
                "at://did:plc:authority123/space/at.freeq.media/K1/did:plc:alice/at.freeq.media.item/3kx",
            )
            .expect("well-formed record uri");
        assert_eq!(rec.space_key, "K1");
        assert_eq!(rec.author_did, "did:plc:alice");
        assert_eq!(rec.collection, "at.freeq.media.item");
        assert_eq!(rec.rkey, "3kx");
        assert_eq!(rec.space, m.space_ref("K1"));
    }

    #[test]
    fn record_uri_parsing_rejects_anything_not_ours() {
        let m = mgr();
        for uri in [
            // Someone else's authority.
            "at://did:plc:other/space/at.freeq.media/K1/did:plc:alice/at.freeq.media.item/3kx",
            // A different space type.
            "at://did:plc:authority123/space/com.example.other/K1/did:plc:alice/c/3kx",
            // A bare space ref carries no record.
            "at://did:plc:authority123/space/at.freeq.media/K1",
            // The author must be a DID.
            "at://did:plc:authority123/space/at.freeq.media/K1/alice/at.freeq.media.item/3kx",
            // Trailing junk beyond the record tail.
            "at://did:plc:authority123/space/at.freeq.media/K1/did:plc:alice/c/3kx/extra",
            "not-a-uri",
        ] {
            assert!(
                m.parse_record_uri(uri).is_none(),
                "must not parse as one of our records: {uri}"
            );
        }
    }

    #[test]
    fn space_scope_names_this_authority() {
        assert_eq!(
            space_scope("did:plc:authority123"),
            "blob:*/* space:*?authority=did:plc:authority123&collection=*"
        );
    }

    #[test]
    fn managing_app_is_did_web_of_this_server() {
        assert_eq!(mgr().managing_app(), "did:web:irc.example.org#freeq_media");
    }
}
