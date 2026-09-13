//! Finding a signer's public key from the key id a signature names.
//!
//! The key is looked for where the signer published it, most direct first:
//! the signer's own identity records, then, for a did:web signer, its DID
//! document, and last the origin server's key store. Whichever source
//! answers, the key must hash to the kid, or it is refused.

use crate::crypto::PublicKey;
use crate::identity_records::{DEVICE_KEY_TYPE, RecordReader, device_key_history};
use crate::sigtag::derive_kid_bytes;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use freeq_oauth::ClientProvider;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::OnceLock;
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
    /// When the key was retired, unix seconds: by a retirement in the signer's
    /// records, or the date the origin server says it was removed.
    pub retired_at: Option<i64>,
}

/// Looks keys up by (DID, kid), caching each answer for `ttl`: a key found,
/// or a miss, when every source answered without the key.
pub struct KeyLookup<P: ClientProvider> {
    pub(crate) reader: RecordReader<P>,
    origin_base: Option<String>,
    default_origin: OnceLock<String>,
    ttl: Duration,
    cache: Mutex<HashMap<(String, String), Cached>>,
}

/// One (DID, kid)'s cached answer: the signer's device records as listed,
/// folded again at whatever time is asked, and what the other sources said,
/// once they have been asked.
#[derive(Clone)]
struct Cached {
    records: Vec<serde_json::Value>,
    other: Option<Option<FoundKey>>,
    at: Instant,
}

/// The fields of the origin's answer read here.
#[derive(serde::Deserialize)]
struct OriginKey {
    public_key: String,
    #[serde(default)]
    removed_at: Option<i64>,
}

impl<P: ClientProvider> KeyLookup<P> {
    /// `origin_base` is the origin server's base URL; the same client
    /// provider as the reader's serves its requests.
    pub fn new(reader: RecordReader<P>, origin_base: Option<String>, ttl: Duration) -> Self {
        Self {
            reader,
            origin_base,
            default_origin: OnceLock::new(),
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The origin to ask when none was given at construction. Set once; a
    /// client sets it to the server it connected to.
    pub fn set_default_origin_base(&self, base: String) {
        let _ = self.default_origin.set(base);
    }

    /// The origin server this lookup asks: the one given, else the default.
    pub fn origin_base(&self) -> Option<&str> {
        self.origin_base
            .as_deref()
            .or_else(|| self.default_origin.get().map(String::as_str))
    }

    /// The key `did` signs with under `kid` now; see [`Self::key_for_at`].
    pub async fn key_for(&self, did: &str, kid: &str) -> Result<Option<FoundKey>> {
        self.key_for_at(did, kid, Utc::now()).await
    }

    /// The key `did` signed with under `kid` at `at`, or `None` when no
    /// source has it. The signer's records are folded at `at`, so a record
    /// key counts only if it was live then; the other sources are not dated.
    ///
    /// A source that fails is skipped and the next one asked; the first
    /// failure is returned only if no later source finds the key. A miss is
    /// remembered only when no source failed, since a failed source did not
    /// say it lacks the key.
    pub async fn key_for_at(
        &self,
        did: &str,
        kid: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<FoundKey>> {
        let slot = (did.to_string(), kid.to_string());
        let cached = self
            .cache
            .lock()
            .get(&slot)
            .filter(|c| c.at.elapsed() < self.ttl)
            .cloned();

        let mut failure = None;
        let records = match cached.as_ref() {
            Some(c) => c.records.clone(),
            None => match self.reader.list_records(did, DEVICE_KEY_TYPE).await {
                Ok(records) => records,
                Err(e) => {
                    failure = Some(e);
                    Vec::new()
                }
            },
        };
        if let Some(found) = in_records(did, kid, &records, at) {
            if failure.is_none() && cached.is_none() {
                self.remember(slot, records, None);
            }
            return Ok(Some(found));
        }
        if let Some(other) = cached.as_ref().and_then(|c| c.other) {
            return Ok(other);
        }

        let mut take = |answer: Result<Option<[u8; 32]>>, source, retired_at| match answer {
            Ok(Some(key)) if derive_kid_bytes(&key) == kid => Some(FoundKey {
                public_key: key,
                source,
                retired_at,
            }),
            Ok(_) => None,
            Err(e) => {
                failure.get_or_insert(e);
                None
            }
        };
        let mut found = None;
        if did.starts_with("did:web:") {
            found = take(
                self.in_document(did, kid).await,
                KeySource::DidDocument,
                None,
            );
        }
        if found.is_none()
            && let Some(base) = self.origin_base()
        {
            let answer = self.at_origin(base, did, kid).await;
            let (key, removed_at) = match answer {
                Ok(Some((key, removed_at))) => (Ok(Some(key)), removed_at),
                Ok(None) => (Ok(None), None),
                Err(e) => (Err(e), None),
            };
            found = take(key, KeySource::OriginServer, removed_at);
        }

        match (found, failure) {
            (Some(found), _) => {
                self.remember(slot, records, Some(Some(found)));
                Ok(Some(found))
            }
            (None, Some(e)) => Err(e),
            (None, None) => {
                self.remember(slot, records, Some(None));
                Ok(None)
            }
        }
    }

    /// Clear a remembered miss for `(did, kid)`, so the next lookup asks the
    /// sources again. A key found stays cached.
    pub fn forget(&self, did: &str, kid: &str) {
        let slot = (did.to_string(), kid.to_string());
        let mut cache = self.cache.lock();
        let found = cache.get(&slot).is_some_and(|c| {
            matches!(c.other, Some(Some(_)))
                || in_records(did, kid, &c.records, Utc::now()).is_some()
        });
        if !found {
            cache.remove(&slot);
        }
    }

    fn remember(
        &self,
        slot: (String, String),
        records: Vec<serde_json::Value>,
        other: Option<Option<FoundKey>>,
    ) {
        self.cache.lock().insert(
            slot,
            Cached {
                records,
                other,
                at: Instant::now(),
            },
        );
    }

    async fn in_document(&self, did: &str, kid: &str) -> Result<Option<[u8; 32]>> {
        let doc = self.reader.resolver.resolve(did).await?;
        Ok(doc
            .verification_method
            .iter()
            .filter_map(|m| m.public_key_multibase.as_deref().and_then(ed25519_raw))
            .find(|key| derive_kid_bytes(key) == kid))
    }

    /// The key the origin holds for `(did, kid)`, and when it was removed.
    async fn at_origin(
        &self,
        base: &str,
        did: &str,
        kid: &str,
    ) -> Result<Option<([u8; 32], Option<i64>)>> {
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
            .and_then(|bytes| bytes.try_into().ok())
            .map(|key| (key, answer.removed_at)))
    }
}

/// The key `kid` names among `did`'s device records at `at`: live then, or
/// retired at or before then, carrying the retirement the fold accepted. A key
/// the records retire is answered here, so no other source is asked for it.
fn in_records(
    did: &str,
    kid: &str,
    records: &[serde_json::Value],
    at: DateTime<Utc>,
) -> Option<FoundKey> {
    let key = device_key_history(did, records)
        .into_iter()
        .find(|k| k.kid == kid)?;
    if key.created_at > at {
        return None;
    }
    let public_key =
        ed25519_raw(&key.public_key_multibase).filter(|raw| derive_kid_bytes(raw) == kid)?;
    Some(FoundKey {
        public_key,
        source: KeySource::IdentityRecord,
        // Unix seconds, like the origin's removal date.
        retired_at: key.retired_at.filter(|r| *r <= at).map(|r| r.timestamp()),
    })
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
                source: KeySource::IdentityRecord,
                retired_at: None,
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
                source: KeySource::OriginServer,
                retired_at: None,
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
                source: KeySource::DidDocument,
                retired_at: None,
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

    #[tokio::test]
    async fn a_lookup_at_a_time_folds_the_records_at_that_time() {
        use crate::identity_records::build_device_retirement;
        let retirement = serde_json::to_value(
            build_device_retirement(&key(1), ALICE, &kid_of(1), "2026-03-01T00:00:00Z").unwrap(),
        )
        .unwrap();
        let pds = pds(vec![device_record(1), retirement]).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);
        let at = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&Utc)
        };
        let live = keys
            .key_for_at(ALICE, &kid_of(1), at("2026-02-01T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            live,
            Some(FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord,
                retired_at: None,
            })
        );
        assert_eq!(
            keys.key_for_at(ALICE, &kid_of(1), at("2026-04-01T00:00:00Z"))
                .await
                .unwrap(),
            Some(FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord,
                retired_at: Some(at("2026-03-01T00:00:00Z").timestamp()),
            }),
            "after its retirement the records still name the key, with the date"
        );
        assert_eq!(
            keys.key_for_at(ALICE, &kid_of(1), at("2025-12-01T00:00:00Z"))
                .await
                .unwrap(),
            None,
            "before its record the key is not in the records"
        );
        assert_eq!(pds.hits(), 1, "one listing answers every time asked");
    }

    #[tokio::test]
    async fn a_key_the_records_retire_is_retired_and_the_origin_is_not_asked() {
        use crate::identity_records::build_device_retirement;
        let retirement = serde_json::to_value(
            build_device_retirement(&key(1), ALICE, &kid_of(1), "2026-03-01T00:00:00Z").unwrap(),
        )
        .unwrap();
        let pds = pds(vec![device_record(1), retirement]).await;
        // The origin still holds the same key and knows nothing of the retirement.
        let origin = origin(vec![(ALICE, kid_of(1), raw(1))]).await;
        let at = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&Utc)
        };
        let found = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .key_for_at(ALICE, &kid_of(1), at("2026-04-01T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            found,
            Some(FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord,
                retired_at: Some(at("2026-03-01T00:00:00Z").timestamp()),
            })
        );
        assert_eq!(origin.hits(), 0);
    }

    #[tokio::test]
    async fn a_key_the_origin_removed_carries_the_date() {
        let hits = Arc::new(AtomicUsize::new(0));
        let router = axum::Router::new().route(
            "/api/v1/signing-keys/{did}/{kid}",
            get(move |Path((did, kid)): Path<(String, String)>| async move {
                axum::Json(json!({
                    "did": did,
                    "kid": kid,
                    "public_key": URL_SAFE_NO_PAD.encode(raw(2)),
                    "registered_at": 1_700_000_000,
                    "removed_at": 1_780_000_000,
                }))
            }),
        );
        let origin = serve(router, hits).await;
        let pds = pds(vec![]).await;
        let found = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .key_for(ALICE, &kid_of(2))
            .await
            .unwrap();
        assert_eq!(
            found,
            Some(FoundKey {
                public_key: raw(2),
                source: KeySource::OriginServer,
                retired_at: Some(1_780_000_000),
            })
        );
    }

    #[tokio::test]
    async fn the_default_origin_base_is_used_when_none_was_given() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);
        assert_eq!(keys.origin_base(), None);
        keys.set_default_origin_base(origin.base.clone());
        assert_eq!(keys.origin_base(), Some(origin.base.as_str()));
        let found = keys.key_for(ALICE, &kid_of(2)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));

        let given = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        given.set_default_origin_base("https://elsewhere.example".to_string());
        assert_eq!(given.origin_base(), Some(origin.base.as_str()));
    }
}
