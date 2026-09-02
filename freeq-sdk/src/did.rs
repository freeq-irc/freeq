//! DID document resolution for AT Protocol identities.
//!
//! Supports:
//! - did:plc (via plc.directory)
//! - did:web (via .well-known/did.json)
//! - Handle resolution (via HTTP .well-known/atproto-did)
//!
//! Also provides a static resolver for testing.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::PublicKey;

/// A DID document (subset of fields relevant to authentication).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(default, rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,

    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default)]
    pub authentication: Vec<StringOrMap>,

    #[serde(default, rename = "assertionMethod")]
    pub assertion_method: Vec<StringOrMap>,

    #[serde(default)]
    pub service: Vec<Service>,
}

/// A service entry in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,

    #[serde(rename = "type")]
    pub service_type: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// A verification method entry in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub method_type: String,

    #[serde(default)]
    pub controller: String,

    #[serde(default, rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
}

/// Authentication/assertionMethod entries can be strings (references) or inline objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrMap {
    Reference(String),
    Inline(VerificationMethod),
}

impl DidDocument {
    /// Extract public keys that are acceptable for authentication.
    ///
    /// Looks at `authentication` entries first, then `assertionMethod` as fallback.
    /// Returns keys from `verificationMethod` that are referenced by those sections.
    pub fn authentication_keys(&self) -> Vec<(String, PublicKey)> {
        let mut keys = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        // Collect from authentication
        for entry in &self.authentication {
            if let Some((id, key)) = self.resolve_key_reference(entry)
                && seen_ids.insert(id.clone())
            {
                keys.push((id, key));
            }
        }

        // Fallback: also check assertionMethod
        for entry in &self.assertion_method {
            if let Some((id, key)) = self.resolve_key_reference(entry)
                && seen_ids.insert(id.clone())
            {
                keys.push((id, key));
            }
        }

        keys
    }

    fn resolve_key_reference(&self, entry: &StringOrMap) -> Option<(String, PublicKey)> {
        match entry {
            StringOrMap::Reference(id) => {
                // Find in verificationMethod by id
                let vm = self.verification_method.iter().find(|vm| &vm.id == id)?;
                let multibase = vm.public_key_multibase.as_deref()?;
                let key = PublicKey::from_multibase(multibase).ok()?;
                Some((id.clone(), key))
            }
            StringOrMap::Inline(vm) => {
                let multibase = vm.public_key_multibase.as_deref()?;
                let key = PublicKey::from_multibase(multibase).ok()?;
                Some((vm.id.clone(), key))
            }
        }
    }
}

/// Is this a syntactically valid AT Protocol handle?
///
/// A handle is a bare domain name. Anything else names a different host once
/// it lands in a URL or gets suffix-matched against an allowed domain.
pub fn is_valid_handle(handle: &str) -> bool {
    if handle.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = handle.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().enumerate().all(|(i, label)| {
        let valid_chars = label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        let is_tld = i + 1 == labels.len();
        (1..=63).contains(&label.len())
            && valid_chars
            && !label.starts_with('-')
            && !label.ends_with('-')
            && (!is_tld || label.starts_with(|c: char| c.is_ascii_alphabetic()))
    })
}

/// DID resolver — resolves DIDs to DID documents.
///
/// Use `DidResolver::http()` for production, `DidResolver::static_map()` for tests.
#[derive(Clone)]
pub enum DidResolver {
    Http(HttpResolver),
    Static(StaticResolver),
}

impl DidResolver {
    /// Create a resolver that uses HTTP to resolve did:plc and did:web.
    pub fn http() -> Self {
        DidResolver::Http(HttpResolver {
            client: reqwest::Client::new(),
            plc_directory: "https://plc.directory".to_string(),
        })
    }

    /// Create a resolver with pre-loaded DID documents (for testing).
    pub fn static_map(documents: HashMap<String, DidDocument>) -> Self {
        DidResolver::Static(StaticResolver {
            documents,
            handles: HashMap::new(),
        })
    }

    /// Like `static_map`, plus an explicit handle to DID table (for testing).
    /// When two documents claim the same handle and the test needs to know who
    /// owns it.
    pub fn static_map_with_handles(
        documents: HashMap<String, DidDocument>,
        handles: HashMap<String, String>,
    ) -> Self {
        DidResolver::Static(StaticResolver { documents, handles })
    }

    /// Resolve a DID to its DID document.
    pub async fn resolve(&self, did: &str) -> Result<DidDocument> {
        match self {
            DidResolver::Http(r) => r.resolve(did).await,
            DidResolver::Static(r) => r.resolve(did),
        }
    }

    /// Resolve a handle (e.g. "alice.bsky.social") to a DID.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String> {
        match self {
            DidResolver::Http(r) => r.resolve_handle(handle).await,
            DidResolver::Static(r) => r.resolve_handle(handle),
        }
    }
}

#[derive(Clone)]
pub struct HttpResolver {
    client: reqwest::Client,
    plc_directory: String,
}

impl HttpResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        if did.starts_with("did:plc:") {
            self.resolve_plc(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_web(did).await
        } else if did.starts_with("did:key:") {
            resolve_did_key(did)
        } else {
            bail!("Unsupported DID method: {did}");
        }
    }

    async fn resolve_plc(&self, did: &str) -> Result<DidDocument> {
        let url = format!("{}/{did}", self.plc_directory);
        tracing::debug!("Resolving did:plc via {url}");
        let doc: DidDocument = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch DID document from PLC directory")?
            .error_for_status()
            .context("PLC directory returned error")?
            .json()
            .await
            .context("Failed to parse DID document")?;
        Ok(doc)
    }

    async fn resolve_web(&self, did: &str) -> Result<DidDocument> {
        let domain_path = did
            .strip_prefix("did:web:")
            .context("Invalid did:web format")?;

        // did:web:example.com -> https://example.com/.well-known/did.json
        // did:web:example.com:path:to -> https://example.com/path/to/did.json
        let url = if domain_path.contains(':') {
            let parts: Vec<&str> = domain_path.splitn(2, ':').collect();
            let domain = parts[0];
            let path = parts[1].replace(':', "/");
            format!("https://{domain}/{path}/did.json")
        } else {
            format!("https://{domain_path}/.well-known/did.json")
        };

        tracing::debug!("Resolving did:web via {url}");

        // SSRF protection: resolve the hostname and reject private IPs
        let parsed = url::Url::parse(&url).context("Invalid did:web URL")?;
        let host = parsed.host_str().context("did:web URL has no host")?;
        let port = parsed.port().unwrap_or(443);
        let addrs = crate::ssrf::resolve_and_check(host, port)
            .await
            .context("did:web SSRF check failed")?;

        // Use a DNS-pinned client to prevent rebinding between check and fetch
        let pinned = crate::ssrf::pinned_client(host, &addrs, std::time::Duration::from_secs(10))
            .context("Failed to build pinned HTTP client")?;

        let doc: DidDocument = pinned
            .get(&url)
            .send()
            .await
            .context("Failed to fetch DID document")?
            .error_for_status()?
            .json()
            .await
            .context("Failed to parse DID document")?;
        Ok(doc)
    }

    async fn resolve_handle(&self, handle: &str) -> Result<String> {
        if !is_valid_handle(handle) {
            bail!("Not a valid handle: {handle}");
        }
        // Try HTTP well-known first (self-hosted domains)
        let url = format!("https://{handle}/.well-known/atproto-did");
        tracing::debug!("Resolving handle {handle} via {url}");
        let well_known_result = async {
            let did = self
                .client
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .context("HTTP request failed")?
                .error_for_status()?
                .text()
                .await
                .context("Failed to read response")?;
            let did = did.trim().to_string();
            if !did.starts_with("did:") {
                bail!("Invalid DID: {did}");
            }
            Ok::<String, anyhow::Error>(did)
        }
        .await;

        if let Ok(did) = well_known_result {
            return Ok(did);
        }

        // Fall back to public Bluesky API (resolves via DNS TXT _atproto.{handle})
        tracing::debug!("Well-known failed for {handle}, falling back to public API");
        let api_url = format!(
            "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={}",
            handle
        );
        let resp: serde_json::Value = self
            .client
            .get(&api_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .context("Failed to resolve handle via public API")?
            .error_for_status()
            .context("Public API returned error")?
            .json()
            .await
            .context("Failed to parse public API response")?;
        let did = resp["did"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No DID in public API response"))?
            .to_string();
        if !did.starts_with("did:") {
            bail!("Public API returned invalid DID: {did}");
        }
        Ok(did)
    }
}

#[derive(Clone)]
pub struct StaticResolver {
    documents: HashMap<String, DidDocument>,
    handles: HashMap<String, String>,
}

impl StaticResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument> {
        // did:key can always be resolved from the DID itself
        if did.starts_with("did:key:") {
            return resolve_did_key(did);
        }
        self.documents
            .get(did)
            .cloned()
            .context(format!("DID not found in static resolver: {did}"))
    }

    /// Check the explicit handle table first, then fall back to the
    /// document that claims `handle` in its `alsoKnownAs`.
    fn resolve_handle(&self, handle: &str) -> Result<String> {
        if let Some(did) = self.handles.get(handle) {
            return Ok(did.clone());
        }
        let aka = format!("at://{handle}");
        self.documents
            .values()
            .find(|doc| doc.also_known_as.contains(&aka))
            .map(|doc| doc.id.clone())
            .context(format!("Handle not found in static resolver: {handle}"))
    }
}

/// Resolve a did:key by extracting the public key from the DID string itself.
///
/// did:key encodes the public key directly: `did:key:<multibase-public-key>`
/// No network fetch needed — the DID *is* the key.
pub fn resolve_did_key(did: &str) -> Result<DidDocument> {
    let multibase = did
        .strip_prefix("did:key:")
        .context("Invalid did:key format")?;

    // Verify the key is parseable
    crate::crypto::PublicKey::from_multibase(multibase).context("Invalid public key in did:key")?;

    let key_id = format!("{did}#{multibase}");
    Ok(DidDocument {
        id: did.to_string(),
        also_known_as: vec![],
        verification_method: vec![VerificationMethod {
            id: key_id.clone(),
            method_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(multibase.to_string()),
        }],
        authentication: vec![StringOrMap::Reference(key_id.clone())],
        assertion_method: vec![StringOrMap::Reference(key_id)],
        service: vec![],
    })
}

/// Helper to create a minimal DID document for testing.
pub fn make_test_did_document(did: &str, public_key_multibase: &str) -> DidDocument {
    make_test_did_document_with_pds(did, public_key_multibase, None)
}

/// Helper to create a DID document with an optional PDS service endpoint.
pub fn make_test_did_document_with_pds(
    did: &str,
    public_key_multibase: &str,
    pds_url: Option<&str>,
) -> DidDocument {
    let key_id = format!("{did}#atproto");
    let mut service = Vec::new();
    if let Some(url) = pds_url {
        service.push(Service {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: url.to_string(),
        });
    }
    DidDocument {
        id: did.to_string(),
        also_known_as: vec![],
        verification_method: vec![VerificationMethod {
            id: key_id.clone(),
            method_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(public_key_multibase.to_string()),
        }],
        authentication: vec![StringOrMap::Reference(key_id.clone())],
        assertion_method: vec![StringOrMap::Reference(key_id)],
        service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;

    #[test]
    fn test_did_document_key_extraction() {
        let key = PrivateKey::generate_secp256k1();
        let multibase = key.public_key_multibase();
        let did = "did:plc:test123";
        let doc = make_test_did_document(did, &multibase);

        let auth_keys = doc.authentication_keys();
        assert_eq!(auth_keys.len(), 1);
        assert_eq!(auth_keys[0].0, "did:plc:test123#atproto");
        assert_eq!(auth_keys[0].1.key_type(), "secp256k1");

        // Verify the extracted key can verify signatures
        let message = b"hello";
        let sig = key.sign(message);
        auth_keys[0].1.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_static_resolver() {
        let key = PrivateKey::generate_ed25519();
        let did = "did:plc:ed25519test";
        let doc = make_test_did_document(did, &key.public_key_multibase());

        let mut map = HashMap::new();
        map.insert(did.to_string(), doc);

        let resolver = DidResolver::static_map(map);
        // Can't easily test async in a sync test, but the static resolver
        // is simple enough to test via the struct directly
        let static_resolver = match &resolver {
            DidResolver::Static(r) => r,
            _ => unreachable!(),
        };

        let resolved = static_resolver.resolve(did).unwrap();
        assert_eq!(resolved.id, did);
        assert_eq!(resolved.authentication_keys().len(), 1);
    }

    #[test]
    fn resolve_did_key_ed25519() {
        let key = PrivateKey::generate_ed25519();
        let multibase = key.public_key_multibase();
        let did = format!("did:key:{multibase}");
        let doc = resolve_did_key(&did).unwrap();
        assert_eq!(doc.id, did);
        let auth_keys = doc.authentication_keys();
        assert_eq!(auth_keys.len(), 1);
        assert_eq!(auth_keys[0].1.key_type(), "ed25519");

        // Verify the extracted key can verify signatures from the original key
        let message = b"hello did:key";
        let sig = key.sign(message);
        auth_keys[0].1.verify(message, &sig).unwrap();
    }

    #[test]
    fn resolve_did_key_secp256k1() {
        let key = PrivateKey::generate_secp256k1();
        let multibase = key.public_key_multibase();
        let did = format!("did:key:{multibase}");
        let doc = resolve_did_key(&did).unwrap();
        assert_eq!(doc.id, did);
        let auth_keys = doc.authentication_keys();
        assert_eq!(auth_keys.len(), 1);
        assert_eq!(auth_keys[0].1.key_type(), "secp256k1");
    }

    #[test]
    fn resolve_did_key_invalid() {
        assert!(resolve_did_key("did:key:zINVALID").is_err());
        assert!(resolve_did_key("did:key:").is_err());
        assert!(resolve_did_key("did:plc:abc").is_err());
    }

    #[test]
    fn accepts_ordinary_handles() {
        assert!(is_valid_handle("alice.bsky.social"));
        assert!(is_valid_handle("acme.com"));
        assert!(is_valid_handle("a-b.acme.com"));
        assert!(is_valid_handle("xn--80ak6aa92e.com"));
        assert!(is_valid_handle("8bit.acme.com"));
    }

    #[test]
    fn rejects_anything_that_would_redirect_the_url_to_another_host() {
        assert!(!is_valid_handle("evil.com/x.acme.com"));
        assert!(!is_valid_handle("evil.com?x.acme.com"));
        assert!(!is_valid_handle("evil.com#x.acme.com"));
        assert!(!is_valid_handle("evil.com:8443"));
        assert!(!is_valid_handle("user@evil.com"));
        assert!(!is_valid_handle("evil.com\\x.acme.com"));
    }

    #[test]
    fn rejects_malformed_domains() {
        assert!(!is_valid_handle("acme"));
        assert!(!is_valid_handle("acme.com."));
        assert!(!is_valid_handle(".acme.com"));
        assert!(!is_valid_handle("alice..acme.com"));
        assert!(!is_valid_handle("-alice.acme.com"));
        assert!(!is_valid_handle("alice-.acme.com"));
        assert!(!is_valid_handle("alice.acme.123"));
        assert!(!is_valid_handle(&format!("{}.com", "a".repeat(64))));
        assert!(!is_valid_handle(&format!("{}.com", "a.".repeat(200))));
    }

    #[tokio::test]
    async fn resolve_handle_refuses_to_build_a_url_from_a_bad_handle() {
        let resolver = HttpResolver {
            client: reqwest::Client::new(),
            plc_directory: "https://plc.directory".to_string(),
        };
        let err = resolver
            .resolve_handle("evil.com/x.acme.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Not a valid handle"));
    }

    #[test]
    fn static_resolver_handles_did_key() {
        let resolver = StaticResolver {
            documents: HashMap::new(),
            handles: HashMap::new(),
        };
        let key = PrivateKey::generate_ed25519();
        let did = format!("did:key:{}", key.public_key_multibase());
        let doc = resolver.resolve(&did).unwrap();
        assert_eq!(doc.id, did);
    }

    #[tokio::test]
    async fn sasl_roundtrip_with_did_key() {
        // Full SASL challenge-response flow using did:key
        let key = PrivateKey::generate_ed25519();
        let multibase = key.public_key_multibase();
        let did = format!("did:key:{multibase}");

        // did:key resolves without network, so use the main resolver
        let resolver = DidResolver::static_map(HashMap::new()); // empty — did:key doesn't need it

        let doc = resolver.resolve(&did).await.unwrap();
        assert_eq!(doc.id, did);

        let auth_keys = doc.authentication_keys();
        assert_eq!(auth_keys.len(), 1);

        // Simulate SASL: sign a challenge, verify it
        let challenge = b"session-id:nonce:timestamp";
        let sig = key.sign(challenge);
        auth_keys[0].1.verify(challenge, &sig).unwrap();
    }

    #[test]
    fn parse_real_did_document_json() {
        let json = r#"{
            "id": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
            "alsoKnownAs": ["at://jay.bsky.team"],
            "verificationMethod": [{
                "id": "did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto",
                "type": "Multikey",
                "controller": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "publicKeyMultibase": "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
            }],
            "authentication": ["did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto"],
            "assertionMethod": ["did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto"],
            "service": []
        }"#;

        let doc: DidDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.id, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");

        let auth_keys = doc.authentication_keys();
        assert_eq!(auth_keys.len(), 1);
        assert_eq!(auth_keys[0].1.key_type(), "secp256k1");
    }
}
