//! Finding a signer's public key from the key id a signature names.
//!
//! The key is looked for where the signer published it, most direct first:
//! the signer's own identity records, then, for a did:web signer, its DID
//! document, and last the origin server's key store. Whichever source
//! answers, the key must hash to the kid, or it is refused.

use crate::crypto::PublicKey;
use crate::identity_records::RecordReader;
use crate::sigtag::derive_kid_bytes;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use freeq_oauth::ClientProvider;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Where a key was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A live `at.freeq.deviceKey` record in the signer's repository.
    IdentityRecord,
    /// A `verificationMethod` of the signer's own did:web document.
    DidDocument,
    /// The origin server's `/api/v1/signing-keys/{did}/{kid}`.
    OriginServer,
}

/// An ed25519 public key that hashes to the kid asked for, and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundKey {
    pub public_key: [u8; 32],
    pub source: KeySource,
}

/// Looks keys up by (DID, kid), caching each answer for `ttl`: a key found,
/// or a miss, when every source answered without the key.
pub struct KeyLookup<P: ClientProvider> {
    reader: RecordReader<P>,
    origin_base: Option<String>,
    ttl: Duration,
    cache: Mutex<HashMap<(String, String), CachedAnswer>>,
}

/// A cached answer and when it was found: a key, or `None` for a miss.
type CachedAnswer = (Option<FoundKey>, Instant);

/// The one field of the origin's answer read here.
#[derive(serde::Deserialize)]
struct OriginKey {
    public_key: String,
}

impl<P: ClientProvider> KeyLookup<P> {
    /// `origin_base` is the origin server's base URL; the same client
    /// provider as the reader's serves its requests.
    pub fn new(reader: RecordReader<P>, origin_base: Option<String>, ttl: Duration) -> Self {
        Self {
            reader,
            origin_base,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The key `did` signs with under `kid`, or `None` when no source has it.
    ///
    /// A source that fails is skipped and the next one asked; the first
    /// failure is returned only if no later source finds the key. A miss is
    /// remembered only when no source failed, since a failed source did not
    /// say it lacks the key.
    pub async fn key_for(&self, did: &str, kid: &str) -> Result<Option<FoundKey>> {
        let slot = (did.to_string(), kid.to_string());
        if let Some((answer, at)) = self.cache.lock().get(&slot).copied()
            && at.elapsed() < self.ttl
        {
            return Ok(answer);
        }

        let mut failure = None;
        let mut take = |answer: Result<Option<[u8; 32]>>, source| match answer {
            Ok(Some(key)) if derive_kid_bytes(&key) == kid => Some(FoundKey {
                public_key: key,
                source,
            }),
            Ok(_) => None,
            Err(e) => {
                failure.get_or_insert(e);
                None
            }
        };

        let mut found = take(self.in_records(did, kid).await, KeySource::IdentityRecord);
        if found.is_none() && did.starts_with("did:web:") {
            found = take(self.in_document(did, kid).await, KeySource::DidDocument);
        }
        if found.is_none()
            && let Some(base) = &self.origin_base
        {
            found = take(
                self.at_origin(base, did, kid).await,
                KeySource::OriginServer,
            );
        }

        match (found, failure) {
            (Some(found), _) => {
                self.cache
                    .lock()
                    .insert(slot, (Some(found), Instant::now()));
                Ok(Some(found))
            }
            (None, Some(e)) => Err(e),
            (None, None) => {
                self.cache.lock().insert(slot, (None, Instant::now()));
                Ok(None)
            }
        }
    }

    /// Clear a remembered miss for `(did, kid)`, so the next lookup asks the
    /// sources again. A key found stays cached.
    pub fn forget(&self, did: &str, kid: &str) {
        let slot = (did.to_string(), kid.to_string());
        let mut cache = self.cache.lock();
        if cache.get(&slot).is_some_and(|(answer, _)| answer.is_none()) {
            cache.remove(&slot);
        }
    }

    async fn in_records(&self, did: &str, kid: &str) -> Result<Option<[u8; 32]>> {
        let live = self.reader.live_device_keys(did, Utc::now()).await?;
        Ok(live
            .iter()
            .find(|k| k.kid == kid)
            .and_then(|k| ed25519_raw(&k.public_key_multibase)))
    }

    async fn in_document(&self, did: &str, kid: &str) -> Result<Option<[u8; 32]>> {
        let doc = self.reader.resolver.resolve(did).await?;
        Ok(doc
            .verification_method
            .iter()
            .filter_map(|m| m.public_key_multibase.as_deref().and_then(ed25519_raw))
            .find(|key| derive_kid_bytes(key) == kid))
    }

    async fn at_origin(&self, base: &str, did: &str, kid: &str) -> Result<Option<[u8; 32]>> {
        let mut url = url::Url::parse(base).context("invalid origin base URL")?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("origin base URL cannot take a path"))?
            .pop_if_empty()
            .extend(["api", "v1", "signing-keys", did, kid]);
        let client = self.reader.clients.client_for(url.as_str()).await?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .context("request to the origin key store failed")?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let answer: OriginKey = response
            .error_for_status()
            .context("the origin key store answered with an error")?
            .json()
            .await
            .context("the origin key store answer is not a key")?;
        // A key that does not decode to 32 bytes is refused like a wrong one.
        Ok(URL_SAFE_NO_PAD
            .decode(&answer.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok()))
    }
}

/// The raw bytes of a `z6Mk…` ed25519 key; anything else is not a signing key here.
fn ed25519_raw(multibase: &str) -> Option<[u8; 32]> {
    match PublicKey::from_multibase(multibase).ok()? {
        PublicKey::Ed25519(k) => Some(*k.as_bytes()),
        PublicKey::Secp256k1(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::did::{DidDocument, DidResolver, make_test_did_document_with_pds};
    use crate::identity_records::{DEVICE_KEY_TYPE, build_device_record};
    use crate::sigtag::derive_kid_bytes;
    use axum::extract::{Path, Query};
    use axum::http::StatusCode;
    use axum::routing::get;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ALICE: &str = "did:plc:k2n3e2vsihf3farequ44t5j7";
    const WEB_SIGNER: &str = "did:web:bot.example.com";
    const T0: &str = "2026-01-01T00:00:00Z";
    const HOUR: Duration = Duration::from_secs(3600);

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::ed25519_from_bytes(&[seed; 32]).unwrap()
    }

    fn raw(seed: u8) -> [u8; 32] {
        match key(seed) {
            PrivateKey::Ed25519(k) => *k.verifying_key().as_bytes(),
            _ => unreachable!(),
        }
    }

    fn kid_of(seed: u8) -> String {
        derive_kid_bytes(&raw(seed))
    }

    /// A stub server on a loopback port, counting the requests it answers.
    struct Stub {
        base: String,
        hits: Arc<AtomicUsize>,
    }

    impl Stub {
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    async fn serve(router: axum::Router, hits: Arc<AtomicUsize>) -> Stub {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Stub { base, hits }
    }

    /// A PDS listing `records` as the account's device keys, in one page.
    async fn pds(records: Vec<serde_json::Value>) -> Stub {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let records = Arc::new(records);
        let router = axum::Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move |Query(q): Query<HashMap<String, String>>| {
                counter.fetch_add(1, Ordering::SeqCst);
                let records = records.clone();
                async move {
                    let listed: Vec<serde_json::Value> =
                        if q.get("collection").map(String::as_str) == Some(DEVICE_KEY_TYPE) {
                            records
                                .iter()
                                .map(|value| json!({"uri": "at://x", "cid": "bafyreistub", "value": value}))
                                .collect()
                        } else {
                            Vec::new()
                        };
                    axum::Json(json!({ "records": listed }))
                }
            }),
        );
        serve(router, hits).await
    }

    /// An origin server whose key store holds `keys` by (did, kid).
    async fn origin(keys: Vec<(&str, String, [u8; 32])>) -> Stub {
        let keys = keys
            .into_iter()
            .map(|(did, kid, key)| ((did.to_string(), kid), key))
            .collect();
        origin_holding(Arc::new(parking_lot::Mutex::new(keys))).await
    }

    type HeldKeys = Arc<parking_lot::Mutex<HashMap<(String, String), [u8; 32]>>>;

    /// An origin server answering from `keys`, which a test can change.
    async fn origin_holding(keys: HeldKeys) -> Stub {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let router = axum::Router::new().route(
            "/api/v1/signing-keys/{did}/{kid}",
            get(move |Path((did, kid)): Path<(String, String)>| {
                counter.fetch_add(1, Ordering::SeqCst);
                let keys = keys.clone();
                async move {
                    let key = keys
                        .lock()
                        .get(&(did.clone(), kid.clone()))
                        .copied()
                        .ok_or(StatusCode::NOT_FOUND)?;
                    Ok::<_, StatusCode>(axum::Json(json!({
                        "did": did,
                        "kid": kid,
                        "algorithm": "ed25519",
                        "public_key": URL_SAFE_NO_PAD.encode(key),
                        "encoding": "base64url",
                        "source": "key-store",
                    })))
                }
            }),
        );
        serve(router, hits).await
    }

    fn lookup(
        documents: Vec<DidDocument>,
        origin: Option<&Stub>,
        ttl: Duration,
    ) -> KeyLookup<freeq_oauth::SharedClient> {
        let resolver = DidResolver::static_map(
            documents
                .into_iter()
                .map(|doc| (doc.id.clone(), doc))
                .collect(),
        );
        let reader = RecordReader::new(resolver, freeq_oauth::SharedClient(reqwest::Client::new()));
        KeyLookup::new(reader, origin.map(|o| o.base.clone()), ttl)
    }

    fn alice_on(pds: &Stub) -> DidDocument {
        make_test_did_document_with_pds(ALICE, &key(50).public_key_multibase(), Some(&pds.base))
    }

    fn device_record(seed: u8) -> serde_json::Value {
        serde_json::to_value(build_device_record(&key(seed), ALICE, T0, None).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_kid_in_the_records_never_asks_the_origin() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![(ALICE, kid_of(1), raw(1))]).await;
        let found = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .key_for(ALICE, &kid_of(1))
            .await
            .unwrap();
        assert_eq!(
            found,
            Some(FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord
            })
        );
        assert_eq!(origin.hits(), 0);
    }

    #[tokio::test]
    async fn a_kid_absent_from_the_records_asks_the_origin() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let found = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .key_for(ALICE, &kid_of(2))
            .await
            .unwrap();
        assert_eq!(
            found,
            Some(FoundKey {
                public_key: raw(2),
                source: KeySource::OriginServer
            })
        );
        assert_eq!(origin.hits(), 1);
    }

    #[tokio::test]
    async fn a_key_from_the_origin_that_does_not_hash_to_the_kid_is_refused() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(3))]).await;
        let found = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .key_for(ALICE, &kid_of(2))
            .await
            .unwrap();
        assert_eq!(found, None);
        assert_eq!(origin.hits(), 1);
    }

    #[tokio::test]
    async fn a_key_from_the_records_that_does_not_hash_to_the_kid_is_refused() {
        // The record names kid 2 but carries key 1, signed by key 1.
        let mut record = build_device_record(&key(1), ALICE, T0, None).unwrap();
        record.kid = kid_of(2);
        record.binding_sig =
            key(1).sign_base64url(&crate::identity_records::record_signed_bytes(&record));
        let pds = pds(vec![serde_json::to_value(record).unwrap()]).await;
        let found = lookup(vec![alice_on(&pds)], None, HOUR)
            .key_for(ALICE, &kid_of(2))
            .await
            .unwrap();
        assert_eq!(found, None);
    }

    #[tokio::test]
    async fn a_did_web_signer_is_found_in_its_own_document() {
        let origin = origin(vec![]).await;
        let mut doc =
            make_test_did_document_with_pds(WEB_SIGNER, &key(60).public_key_multibase(), None);
        doc.verification_method
            .push(crate::did::VerificationMethod {
                id: format!("{WEB_SIGNER}#freeq"),
                method_type: "Multikey".to_string(),
                controller: WEB_SIGNER.to_string(),
                public_key_multibase: Some(key(4).public_key_multibase()),
            });
        let found = lookup(vec![doc], Some(&origin), HOUR)
            .key_for(WEB_SIGNER, &kid_of(4))
            .await
            .unwrap();
        assert_eq!(
            found,
            Some(FoundKey {
                public_key: raw(4),
                source: KeySource::DidDocument
            })
        );
        assert_eq!(origin.hits(), 0);
    }

    #[tokio::test]
    async fn a_failing_pds_still_leaves_the_origin_to_ask() {
        let hits = Arc::new(AtomicUsize::new(0));
        let down = axum::Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let pds = serve(down, hits).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let with_origin = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        let found = with_origin.key_for(ALICE, &kid_of(2)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));
        // With nothing else to ask, the failure is the answer.
        let alone = lookup(vec![alice_on(&pds)], None, HOUR);
        assert!(alone.key_for(ALICE, &kid_of(2)).await.is_err());
    }

    #[tokio::test]
    async fn two_misses_inside_the_ttl_make_one_round_of_requests() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![]).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!((pds.hits(), origin.hits()), (1, 1));
    }

    #[tokio::test]
    async fn a_key_that_appears_after_a_miss_is_found_once_the_ttl_passes() {
        let pds = pds(vec![]).await;
        let held: HeldKeys = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let origin = origin_holding(held.clone()).await;
        let keys = lookup(
            vec![alice_on(&pds)],
            Some(&origin),
            Duration::from_millis(50),
        );
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);

        held.lock().insert((ALICE.to_string(), kid_of(2)), raw(2));
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2)).await.unwrap(),
            None,
            "inside the ttl the miss stands"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let found = keys.key_for(ALICE, &kid_of(2)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));
        assert_eq!(origin.hits(), 2);
    }

    #[tokio::test]
    async fn forgetting_a_miss_lets_the_next_lookup_ask_again() {
        let pds = pds(vec![]).await;
        let held: HeldKeys = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let origin = origin_holding(held.clone()).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);

        held.lock().insert((ALICE.to_string(), kid_of(2)), raw(2));
        keys.forget(ALICE, &kid_of(2));
        let found = keys.key_for(ALICE, &kid_of(2)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));
        assert_eq!(origin.hits(), 2);
    }

    /// Only a miss is forgotten: a key found stays cached.
    #[tokio::test]
    async fn forgetting_leaves_a_found_key_cached() {
        let pds = pds(vec![device_record(1)]).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);
        keys.key_for(ALICE, &kid_of(1)).await.unwrap().unwrap();
        keys.forget(ALICE, &kid_of(1));
        keys.key_for(ALICE, &kid_of(1)).await.unwrap().unwrap();
        assert_eq!(pds.hits(), 1);
    }

    #[tokio::test]
    async fn a_second_lookup_inside_the_ttl_makes_no_request() {
        let pds = pds(vec![device_record(1)]).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);
        let first = keys.key_for(ALICE, &kid_of(1)).await.unwrap();
        assert_eq!(pds.hits(), 1);
        let second = keys.key_for(ALICE, &kid_of(1)).await.unwrap();
        assert_eq!(second, first);
        assert_eq!(pds.hits(), 1);
    }

    #[tokio::test]
    async fn a_lookup_after_the_ttl_asks_again() {
        let pds = pds(vec![device_record(1)]).await;
        let keys = lookup(vec![alice_on(&pds)], None, Duration::from_millis(50));
        keys.key_for(ALICE, &kid_of(1)).await.unwrap().unwrap();
        assert_eq!(pds.hits(), 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        keys.key_for(ALICE, &kid_of(1)).await.unwrap().unwrap();
        assert_eq!(pds.hits(), 2);
    }
}
