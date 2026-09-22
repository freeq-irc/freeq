//! Identity records and repository proofs this server has read, kept so they
//! can be served again.
//!
//! The retired-key check and the peer key fetch already list signers'
//! device-key records and check their repository proofs; the lookup's reader
//! reports each listing and each proof that checks here, and both are kept in
//! memory and in the database. A listing is served for `record_cache_secs`
//! before the PDS is listed again; when the PDS cannot be read the last copy
//! is served, marked stale. A proof is served only for a record the current
//! listing names, and only if it checked under the repo key that listing's
//! DID document names.
//!
//! Only accounts that have appeared on this server are answered for (see
//! [`seen`]), and only the two identity-record collections. Clients check
//! every proof themselves against the DID document they resolve, so this
//! cache can withhold or serve stale, never forge.

use std::collections::HashMap;
use std::sync::Arc;

use freeq_sdk::identity_records::{
    AGENT_KEY_TYPE, Cid, DEVICE_KEY_TYPE, RecordEntry, RecordReader, record_cid,
};
use parking_lot::Mutex;

use crate::db::{Db, RecordProofRow};
use crate::server::SharedState;

/// The collections this cache keeps and serves.
pub const CACHED_COLLECTIONS: [&str; 2] = [DEVICE_KEY_TYPE, AGENT_KEY_TYPE];

/// One account's listing of one collection.
#[derive(Debug, Clone, PartialEq)]
pub struct CachedListing {
    pub entries: Vec<RecordEntry>,
    /// The `#atproto` publicKeyMultibase of the DID document it was listed
    /// under; empty when the document had none.
    pub repo_key: String,
    pub fetched_at: i64,
}

/// A listing as served: the copy, and whether it is older than the period
/// because the PDS could not be read.
#[derive(Debug, Clone, PartialEq)]
pub struct ServedListing {
    pub listing: CachedListing,
    pub stale: bool,
}

/// Why nothing was served.
#[derive(Debug)]
pub enum Refusal {
    /// The account has not appeared here, the collection is not kept, or the
    /// current listing does not name the record.
    NotHere,
    /// The PDS could not be read, or its proof did not check, and there is no
    /// copy to serve.
    Unreadable(String),
}

/// A listing in flight, whose outcome every ask waiting on it shares.
type Relisting = Arc<tokio::sync::OnceCell<Result<(), String>>>;

/// The cache: a memory copy in front of the `record_listings` and
/// `record_proofs` tables, or the memory copy alone with no database. Rows
/// are loaded into memory on first use and every change is written through.
pub struct RecordCache {
    db: Option<Arc<Mutex<Db>>>,
    period_secs: i64,
    prune_days: i64,
    /// Per (DID, collection), the listing.
    listings: Mutex<HashMap<(String, String), CachedListing>>,
    /// Per record CID, the proof.
    proofs: Mutex<HashMap<String, RecordProofRow>>,
    /// Per DID, when it was last asked about.
    asked: Mutex<HashMap<String, i64>>,
    /// One listing in flight per (DID, collection), shared by every ask that
    /// finds the kept copy too old meanwhile.
    in_flight: Mutex<HashMap<(String, String), Relisting>>,
}

impl RecordCache {
    pub fn new(db: Option<Arc<Mutex<Db>>>, config: &crate::config::ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            db,
            period_secs: config.record_cache_secs as i64,
            prune_days: config.record_cache_prune_days as i64,
            listings: Mutex::new(HashMap::new()),
            proofs: Mutex::new(HashMap::new()),
            asked: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
        })
    }

    /// Run `f` with the database, if there is one; an error is logged, not
    /// returned, as `SharedState::with_db` does.
    fn with_db<R>(&self, f: impl FnOnce(&Db) -> rusqlite::Result<R>) -> Option<R> {
        let db = self.db.as_ref()?.lock();
        f(&db)
            .map_err(|e| tracing::error!("Record cache database error: {e}"))
            .ok()
    }

    /// Keep a listing the reader made.
    pub fn keep_listing(
        &self,
        did: &str,
        collection: &str,
        repo_key: &str,
        entries: &[RecordEntry],
    ) {
        self.keep_listing_at(did, collection, repo_key, entries, now());
    }

    /// Keep a listing made at `at`, and forget the proofs of records it no
    /// longer names.
    pub(crate) fn keep_listing_at(
        &self,
        did: &str,
        collection: &str,
        repo_key: &str,
        entries: &[RecordEntry],
        at: i64,
    ) {
        if !CACHED_COLLECTIONS.contains(&collection) {
            return;
        }
        let asked_at = *self.asked.lock().entry(did.to_string()).or_insert(at);
        let named: Vec<String> = entries
            .iter()
            .filter_map(|entry| record_cid(&entry.value).ok())
            .map(|cid| cid.to_string())
            .collect();
        let entries_json = serde_json::Value::Array(
            entries
                .iter()
                .map(|e| serde_json::json!({ "uri": e.uri, "cid": e.cid, "value": e.value }))
                .collect(),
        )
        .to_string();
        self.with_db(|db| {
            db.save_record_listing(did, collection, &entries_json, repo_key, at, asked_at)?;
            db.drop_record_proofs_except(did, collection, &named)
        });
        self.listings.lock().insert(
            (did.to_string(), collection.to_string()),
            CachedListing {
                entries: entries.to_vec(),
                repo_key: repo_key.to_string(),
                fetched_at: at,
            },
        );
        self.proofs.lock().retain(|cid, proof| {
            proof.did != did || proof.collection != collection || named.contains(cid)
        });
    }

    /// Keep a proof the reader checked.
    pub fn keep_proof(
        &self,
        did: &str,
        collection: &str,
        rkey: &str,
        cid: &Cid,
        repo_key: &str,
        car: &[u8],
    ) {
        self.keep_proof_at(did, collection, rkey, cid, repo_key, car, now());
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn keep_proof_at(
        &self,
        did: &str,
        collection: &str,
        rkey: &str,
        cid: &Cid,
        repo_key: &str,
        car: &[u8],
        at: i64,
    ) {
        if !CACHED_COLLECTIONS.contains(&collection) {
            return;
        }
        let proof = RecordProofRow {
            cid: cid.to_string(),
            did: did.to_string(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            car: car.to_vec(),
            repo_key: repo_key.to_string(),
            fetched_at: at,
        };
        self.with_db(|db| db.save_record_proof(&proof));
        self.proofs.lock().insert(proof.cid.clone(), proof);
    }

    /// The kept listing of `did`'s `collection`, from memory or the database.
    pub fn stored_listing(&self, did: &str, collection: &str) -> Option<CachedListing> {
        let key = (did.to_string(), collection.to_string());
        if let Some(listing) = self.listings.lock().get(&key) {
            return Some(listing.clone());
        }
        let row = self
            .with_db(|db| db.record_listing(did, collection))
            .flatten()?;
        let entries: Vec<RecordEntry> = serde_json::from_str(&row.entries_json)
            .map_err(|e| tracing::error!(%did, %collection, "Kept listing does not parse: {e}"))
            .ok()?;
        let listing = CachedListing {
            entries,
            repo_key: row.repo_key,
            fetched_at: row.fetched_at,
        };
        self.asked
            .lock()
            .entry(did.to_string())
            .and_modify(|at| *at = (*at).max(row.last_asked_at))
            .or_insert(row.last_asked_at);
        self.listings.lock().insert(key, listing.clone());
        Some(listing)
    }

    /// The kept proof of the record with `cid`, from memory or the database.
    pub fn stored_proof(&self, cid: &str) -> Option<RecordProofRow> {
        if let Some(proof) = self.proofs.lock().get(cid) {
            return Some(proof.clone());
        }
        let proof = self.with_db(|db| db.record_proof(cid)).flatten()?;
        self.proofs.lock().insert(cid.to_string(), proof.clone());
        Some(proof)
    }

    /// Stamp `did` as asked about at `at`.
    fn touch(&self, did: &str, at: i64) {
        self.asked.lock().insert(did.to_string(), at);
        self.with_db(|db| db.touch_record_listings(did, at));
    }

    /// Forget every account nobody has asked about for the pruning period
    /// before `at`. Returns how many were forgotten.
    pub(crate) fn prune_at(&self, at: i64) -> usize {
        let cutoff = at - self.prune_days * 24 * 60 * 60;
        let mut forgotten: std::collections::HashSet<String> = self
            .with_db(|db| db.prune_record_cache(cutoff))
            .unwrap_or_default()
            .into_iter()
            .collect();
        self.asked.lock().retain(|did, asked_at| {
            if *asked_at < cutoff {
                forgotten.insert(did.clone());
                false
            } else {
                !forgotten.contains(did)
            }
        });
        self.listings
            .lock()
            .retain(|(did, _), _| !forgotten.contains(did));
        self.proofs
            .lock()
            .retain(|_, proof| !forgotten.contains(&proof.did));
        forgotten.len()
    }

    /// A new listing of `did`'s `collection` through `reader`, which keeps it
    /// here through its callback; asks racing on one collection share one
    /// listing.
    async fn relist(
        &self,
        reader: &RecordReader<crate::peer_keys::LookupClients>,
        did: &str,
        collection: &str,
    ) -> Result<(), String> {
        let key = (did.to_string(), collection.to_string());
        let cell = self
            .in_flight
            .lock()
            .entry(key.clone())
            .or_default()
            .clone();
        let listed = cell
            .get_or_init(|| async {
                reader
                    .list_record_entries(did, collection)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("{e:#}"))
            })
            .await
            .clone();
        let mut in_flight = self.in_flight.lock();
        if in_flight.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
            in_flight.remove(&key);
        }
        listed
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Whether `did` has appeared on this server: signed in now, a signing key
/// registered or fetched, or a stored message. A server with no database
/// knows only live sessions and keys registered since it started.
pub fn seen(state: &SharedState, did: &str) -> bool {
    state.did_sessions.lock().contains_key(did)
        || state.did_msg_keys.lock().contains_key(did)
        || state.with_db(|db| db.did_appears(did)).unwrap_or(false)
}

/// `did`'s listing of `collection`: the kept copy while it is younger than
/// the period, else a new listing through the lookup's reader, else the kept
/// copy marked stale.
pub async fn listing(
    state: &SharedState,
    did: &str,
    collection: &str,
) -> Result<ServedListing, Refusal> {
    if !CACHED_COLLECTIONS.contains(&collection) || !seen(state, did) {
        return Err(Refusal::NotHere);
    }
    let cache = &state.record_cache;
    cache.touch(did, now());
    let fresh = |listing: &CachedListing| now() - listing.fetched_at < cache.period_secs;
    let kept = cache.stored_listing(did, collection);
    if let Some(listing) = kept.as_ref().filter(|l| fresh(l)) {
        return Ok(ServedListing {
            listing: listing.clone(),
            stale: false,
        });
    }
    let listed = cache
        .relist(state.key_lookup.reader(), did, collection)
        .await;
    match (listed, cache.stored_listing(did, collection)) {
        // A listing that went through was kept by the reader's callback.
        (Ok(()), Some(listing)) => Ok(ServedListing {
            listing,
            stale: false,
        }),
        (Ok(()), None) => Err(Refusal::Unreadable("the listing was not kept".to_string())),
        (Err(_), Some(listing)) => Ok(ServedListing {
            listing,
            stale: true,
        }),
        (Err(e), None) => Err(Refusal::Unreadable(e)),
    }
}

/// The proof of `did`'s record at `collection/rkey`, for a record the current
/// listing names: the kept CAR when it checked under that listing's repo key,
/// else a fresh proof through the lookup's reader.
pub async fn proof(
    state: &SharedState,
    did: &str,
    collection: &str,
    rkey: &str,
) -> Result<RecordProofRow, Refusal> {
    let listing = listing(state, did, collection).await?.listing;
    let uri = format!("at://{did}/{collection}/{rkey}");
    let cid = listing
        .entries
        .iter()
        .find(|entry| entry.uri == uri)
        .and_then(|entry| record_cid(&entry.value).ok())
        .ok_or(Refusal::NotHere)?;
    let cache = &state.record_cache;
    if let Some(proof) = cache
        .stored_proof(&cid.to_string())
        .filter(|p| p.repo_key == listing.repo_key)
    {
        return Ok(proof);
    }
    let outcome = state
        .key_lookup
        .reader()
        .verify_record(did, collection, rkey, &cid)
        .await
        .map_err(|e| Refusal::Unreadable(format!("{e:#}")))?;
    if !outcome.verified() {
        return Err(Refusal::Unreadable("the proof does not check".to_string()));
    }
    // A proof that checked was kept by the reader's callback.
    cache
        .stored_proof(&cid.to_string())
        .ok_or_else(|| Refusal::Unreadable("the proof was not kept".to_string()))
}

/// How often kept accounts are checked against the pruning period.
const PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Start the pruning task: once now, then every hour.
pub fn spawn(state: Arc<SharedState>) {
    if state.db.is_none() {
        tracing::warn!(
            "No database configured: identity records and proofs are cached in memory only, \
             and a restart forgets them"
        );
    }
    tokio::spawn(async move {
        loop {
            let forgotten = state.record_cache.prune_at(now());
            if forgotten > 0 {
                tracing::info!(
                    count = forgotten,
                    "forgot cached records nobody asked about"
                );
            }
            tokio::time::sleep(PRUNE_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use freeq_sdk::did::DidResolver;
    use freeq_sdk::identity_records::verify_proof;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DID: &str = "did:plc:recordcachetest";
    const DAY: i64 = 24 * 60 * 60;

    fn device_record(seed: u8) -> serde_json::Value {
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[seed; 32]).unwrap();
        serde_json::to_value(
            freeq_sdk::identity_records::build_device_record(
                &key,
                DID,
                "2026-01-01T00:00:00Z",
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn count(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }

    fn config(record_cache_secs: u64) -> ServerConfig {
        ServerConfig {
            record_cache_secs,
            ..Default::default()
        }
    }

    fn rkey_of(entry: &RecordEntry) -> String {
        entry.uri.rsplit('/').next().unwrap().to_string()
    }

    /// A stub PDS listing `records` as DID's device keys, with its listing
    /// and proof counts.
    async fn pds(
        records: Vec<serde_json::Value>,
    ) -> (DidResolver, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        crate::peer_keys::stub_pds_counting(DID, Arc::new(Mutex::new(records))).await
    }

    /// A resolver whose document for DID names a PDS nothing answers at.
    async fn dead_pds() -> DidResolver {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let key = freeq_sdk::crypto::PrivateKey::generate_secp256k1();
        let doc = freeq_sdk::did::make_test_did_document_with_pds(
            DID,
            &key.public_key_multibase(),
            Some(&base),
        );
        DidResolver::static_map(HashMap::from([(DID.to_string(), doc)]))
    }

    /// DID has a signing key on file, so it has appeared here.
    fn appear(state: &SharedState) {
        state.with_db(|db| db.save_signing_key_from(DID, &[7u8; 32], "local-session"));
    }

    /// A state on an in-memory database where DID has appeared.
    fn state_on_db(config: ServerConfig, resolver: DidResolver) -> Arc<SharedState> {
        let state =
            crate::server::test_state_on(Some(Db::open_memory().unwrap()), config, resolver);
        appear(&state);
        state
    }

    #[tokio::test]
    async fn two_asks_inside_the_period_make_one_listing() {
        let (resolver, listings, _) = pds(vec![device_record(1), device_record(2)]).await;
        let state = state_on_db(config(3600), resolver);

        let first = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        let second = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        assert_eq!(count(&listings), 1);
        assert_eq!(first.listing.entries.len(), 2);
        assert!(!first.listing.repo_key.is_empty());
        assert!(!first.stale && !second.stale);
        assert_eq!(first, second);

        let row = state
            .with_db(|db| db.record_listing(DID, DEVICE_KEY_TYPE))
            .flatten()
            .expect("the listing is in the table");
        assert_eq!(row.repo_key, first.listing.repo_key);
        assert_eq!(row.fetched_at, first.listing.fetched_at);
    }

    #[tokio::test]
    async fn two_collections_asked_at_once_are_each_listed() {
        let (resolver, listings, _) = pds(vec![device_record(1)]).await;
        let state = state_on_db(config(3600), resolver);

        let (devices, agents) = tokio::join!(
            listing(&state, DID, DEVICE_KEY_TYPE),
            listing(&state, DID, AGENT_KEY_TYPE),
        );
        assert_eq!(devices.unwrap().listing.entries.len(), 1);
        assert!(agents.unwrap().listing.entries.is_empty());
        assert_eq!(count(&listings), 2);
    }

    #[tokio::test]
    async fn an_ask_past_the_period_lists_again() {
        let (resolver, listings, _) = pds(vec![device_record(1)]).await;
        let state = state_on_db(config(0), resolver);

        listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        let second = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        assert_eq!(count(&listings), 2);
        assert!(!second.stale);
    }

    #[tokio::test]
    async fn a_pds_that_fails_serves_the_old_copy_marked_stale() {
        let state = state_on_db(config(60), dead_pds().await);
        let entries = vec![RecordEntry {
            uri: format!("at://{DID}/{DEVICE_KEY_TYPE}/a"),
            cid: String::new(),
            value: device_record(1),
        }];
        let at = now() - 100;
        state
            .record_cache
            .keep_listing_at(DID, DEVICE_KEY_TYPE, "zRepoKey", &entries, at);

        let served = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        assert!(served.stale);
        assert_eq!(
            served.listing,
            CachedListing {
                entries,
                repo_key: "zRepoKey".to_string(),
                fetched_at: at,
            }
        );
    }

    #[tokio::test]
    async fn a_first_ask_for_a_pds_that_fails_is_an_error() {
        let state = state_on_db(config(60), dead_pds().await);
        assert!(matches!(
            listing(&state, DID, DEVICE_KEY_TYPE).await,
            Err(Refusal::Unreadable(_))
        ));
    }

    #[tokio::test]
    async fn a_proof_is_fetched_once_then_served_from_the_table() {
        let (resolver, _, proofs) = pds(vec![device_record(1)]).await;
        let state = state_on_db(config(3600), resolver);
        let listed = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap().listing;
        let rkey = rkey_of(&listed.entries[0]);

        let first = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        let second = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        assert_eq!(count(&proofs), 1);
        assert_eq!(first, second);

        let cid = record_cid(&listed.entries[0].value).unwrap();
        assert_eq!(
            state
                .with_db(|db| db.record_proof(&cid.to_string()))
                .flatten(),
            Some(first.clone())
        );
        assert_eq!(first.repo_key, listed.repo_key);
        let key = freeq_sdk::crypto::PublicKey::from_multibase(&listed.repo_key).unwrap();
        let outcome = verify_proof(&first.car, DID, DEVICE_KEY_TYPE, &rkey, &cid, &key)
            .await
            .unwrap();
        assert!(outcome.verified(), "the kept bytes are the PDS's proof");
    }

    #[tokio::test]
    async fn a_restarted_server_serves_the_listing_and_proof_from_its_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("irc.db");
        let config = ServerConfig {
            server_name: "record-cache-test".to_string(),
            data_dir: Some(dir.path().to_str().unwrap().to_string()),
            db_path: Some(path.to_str().unwrap().to_string()),
            ..Default::default()
        };
        let (resolver, listings, proofs) = pds(vec![device_record(1)]).await;

        let (listed, proved) = {
            let state = crate::server::test_state_on(
                Some(Db::open(&path).unwrap()),
                config.clone(),
                resolver.clone(),
            );
            appear(&state);
            let listed = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
            let rkey = rkey_of(&listed.listing.entries[0]);
            let proved = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
            (listed, proved)
        };
        assert_eq!((count(&listings), count(&proofs)), (1, 1));

        // The server as the binary builds it. Its clients refuse loopback, so
        // anything it served came from the database.
        let state = crate::server::Server::with_resolver(config, resolver)
            .build_state()
            .unwrap();
        let relisted = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        assert_eq!(relisted, listed);
        let rkey = rkey_of(&relisted.listing.entries[0]);
        let reproved = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        assert_eq!(reproved, proved);
        assert_eq!(
            (count(&listings), count(&proofs)),
            (1, 1),
            "nothing is asked of the PDS after the restart"
        );
    }

    #[tokio::test]
    async fn a_record_dropped_from_a_newer_listing_loses_its_proof() {
        let (resolver, _, _) = pds(vec![device_record(1), device_record(2)]).await;
        let state = state_on_db(config(3600), resolver);
        let listed = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap().listing;
        let rkey = rkey_of(&listed.entries[0]);
        proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        let cid = record_cid(&listed.entries[0].value).unwrap().to_string();
        assert!(state.record_cache.stored_proof(&cid).is_some());

        // The newer listing, as the reader reports it.
        state.record_cache.keep_listing(
            DID,
            DEVICE_KEY_TYPE,
            &listed.repo_key,
            &listed.entries[1..],
        );
        assert!(state.record_cache.stored_proof(&cid).is_none());
        assert!(
            state
                .with_db(|db| db.record_proof(&cid))
                .flatten()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_proof_kept_under_another_repo_key_is_fetched_afresh() {
        let (resolver, _, proofs) = pds(vec![device_record(1)]).await;
        let state = state_on_db(config(3600), resolver);
        let listed = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap().listing;
        let rkey = rkey_of(&listed.entries[0]);
        let cid = record_cid(&listed.entries[0].value).unwrap();
        state.record_cache.keep_proof(
            DID,
            DEVICE_KEY_TYPE,
            &rkey,
            &cid,
            "zAnEarlierRepoKey",
            b"a proof signed before a rotation",
        );

        let served = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        assert_eq!(count(&proofs), 1);
        assert_eq!(served.repo_key, listed.repo_key);
        assert_ne!(served.car, b"a proof signed before a rotation".to_vec());
    }

    #[tokio::test]
    async fn an_account_nobody_asked_about_for_the_period_is_pruned() {
        let state = crate::server::test_state_on(
            Some(Db::open_memory().unwrap()),
            config(3600),
            DidResolver::static_map(HashMap::new()),
        );
        let now = now();
        let (old, recent) = ("did:plc:asked31daysago", "did:plc:asked29daysago");
        let mut cids = HashMap::new();
        for (did, at) in [(old, now - 31 * DAY), (recent, now - 29 * DAY)] {
            let entries = vec![RecordEntry {
                uri: format!("at://{did}/{DEVICE_KEY_TYPE}/r"),
                cid: String::new(),
                value: serde_json::json!({ "account": did }),
            }];
            let cid = record_cid(&entries[0].value).unwrap();
            let cache = &state.record_cache;
            cache.keep_listing_at(did, DEVICE_KEY_TYPE, "zRepoKey", &entries, at);
            cache.keep_proof_at(did, DEVICE_KEY_TYPE, "r", &cid, "zRepoKey", b"car", at);
            cids.insert(did, cid.to_string());
        }

        assert_eq!(state.record_cache.prune_at(now), 1);
        for (did, kept) in [(old, false), (recent, true)] {
            let cid = &cids[did];
            let cache = &state.record_cache;
            assert_eq!(cache.stored_listing(did, DEVICE_KEY_TYPE).is_some(), kept);
            assert_eq!(cache.stored_proof(cid).is_some(), kept);
            let rows = state
                .with_db(|db| {
                    Ok((
                        db.record_listing(did, DEVICE_KEY_TYPE)?.is_some(),
                        db.record_proof(cid)?.is_some(),
                    ))
                })
                .unwrap();
            assert_eq!(rows, (kept, kept), "{did}");
        }
    }

    #[tokio::test]
    async fn an_account_that_never_appeared_is_not_fetched() {
        let (resolver, listings, proofs) = pds(vec![device_record(1)]).await;
        let state =
            crate::server::test_state_on(Some(Db::open_memory().unwrap()), config(3600), resolver);

        assert!(!seen(&state, DID));
        assert!(matches!(
            listing(&state, DID, DEVICE_KEY_TYPE).await,
            Err(Refusal::NotHere)
        ));
        assert!(matches!(
            proof(&state, DID, DEVICE_KEY_TYPE, "anything").await,
            Err(Refusal::NotHere)
        ));
        assert_eq!((count(&listings), count(&proofs)), (0, 0));
    }

    #[tokio::test]
    async fn an_account_with_a_stored_message_has_appeared() {
        let state = crate::server::test_state_on(
            Some(Db::open_memory().unwrap()),
            config(3600),
            DidResolver::static_map(HashMap::new()),
        );
        assert!(!seen(&state, DID));
        state.with_db(|db| {
            db.insert_message(
                "#room",
                "nick",
                "hello",
                1,
                &HashMap::new(),
                None,
                Some(DID),
            )
        });
        assert!(seen(&state, DID));
    }

    #[tokio::test]
    async fn only_the_identity_record_collections_are_served() {
        let (resolver, listings, _) = pds(vec![device_record(1)]).await;
        let state = state_on_db(config(3600), resolver);
        assert!(matches!(
            listing(&state, DID, "app.bsky.feed.post").await,
            Err(Refusal::NotHere)
        ));
        assert_eq!(count(&listings), 0);
    }

    #[tokio::test]
    async fn a_state_with_no_database_keeps_the_same_cache_in_memory() {
        let (resolver, listings, proofs) = pds(vec![device_record(1)]).await;
        let state = crate::server::test_state_on(None, config(3600), resolver);
        assert!(matches!(
            listing(&state, DID, DEVICE_KEY_TYPE).await,
            Err(Refusal::NotHere)
        ));
        state.did_sessions.lock().insert(
            DID.to_string(),
            std::collections::HashSet::from(["session-1".to_string()]),
        );

        let first = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        let second = listing(&state, DID, DEVICE_KEY_TYPE).await.unwrap();
        assert_eq!(first, second);
        let rkey = rkey_of(&first.listing.entries[0]);
        let proved = proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap();
        assert_eq!(
            proof(&state, DID, DEVICE_KEY_TYPE, &rkey).await.unwrap(),
            proved
        );
        assert_eq!((count(&listings), count(&proofs)), (1, 1));
    }
}
