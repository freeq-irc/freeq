//! Finding a signer's public key from the key id a signature names.
//!
//! The key is looked for where the signer published it, most direct first:
//! the signer's own identity records, then, for a did:web signer, its DID
//! document, and last the origin server's key store. Whichever source
//! answers, the key must hash to the kid, or it is refused.

use crate::crypto::PublicKey;
use crate::identity_records::{
    AGENT_KEY_TYPE, DEVICE_KEY_TYPE, RecordEntry, RecordReader, device_key_history,
    retirement_closure,
};
use crate::sigtag::derive_kid_bytes;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use freeq_oauth::ClientProvider;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Where a key was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A live `at.freeq.deviceKey` record in the signer's repository.
    IdentityRecord,
    /// A `verificationMethod` of the signer's own did:web document.
    DidDocument,
    /// The origin server's `/api/v1/signing-keys/{did}/{kid}`.
    OriginServer,
    /// The signer's own `did:key` DID, which is the key: read from the DID
    /// ([`did_key_answer`]), never asked for and never kept.
    DidKey,
}

/// A `did:key` signer's key, read from the DID itself when `kid` is that
/// key's: no request, no retirement date (a did:key has none; ruling 20
/// exempts it), and nothing kept, since it costs nothing to read again.
/// `None` for any other DID, one that does not decode to an ed25519 key,
/// or a kid that is not its key's (a bot on bot-kit before it signed with
/// its did:key), which a lookup answers as before.
pub fn did_key_answer(did: &str, kid: &str) -> Option<FoundKey> {
    let multibase = did.strip_prefix("did:key:")?;
    let crate::crypto::PublicKey::Ed25519(key) =
        crate::crypto::PublicKey::from_multibase(multibase).ok()?
    else {
        return None;
    };
    let public_key = key.to_bytes();
    (derive_kid_bytes(&public_key) == kid).then_some(FoundKey {
        public_key,
        source: KeySource::DidKey,
        retired_at: None,
        created_at: None,
        expires_at: None,
    })
}

/// An ed25519 public key that hashes to the kid asked for, and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundKey {
    pub public_key: [u8; 32],
    pub source: KeySource,
    /// When the key stopped counting, unix seconds. From the signer's
    /// records: its retirement or expiry, only when at or before the instant
    /// asked about. From the origin server: the earlier of its removal and
    /// its expiry, which may be later than that instant.
    pub retired_at: Option<i64>,
    /// When the key was made, unix seconds: its record's `createdAt`. Only
    /// the records give one.
    pub created_at: Option<i64>,
    /// When the key stops counting, unix seconds: its record's expiry, told
    /// whether or not it has passed at the instant asked about. Only the
    /// records give one.
    pub expires_at: Option<i64>,
}

/// Looks keys up by (DID, kid). A miss, when every source answered without
/// the key, is cached for `ttl`; a key found is cached without expiry, and
/// one found in the records takes the DID's listing again once that is older
/// than `ttl`, so a retirement since lands on it. A miss the origin answered
/// is asked again at the origin at each retry delay before it is remembered.
/// A signer's device records are listed and proven per DID, shared by the
/// lookups for every kid of that DID; a kid the held listing lacks lists the
/// DID again at most once per `ttl`.
///
/// Twin of the JS `KeyLookup`.
pub struct KeyLookup<P: ClientProvider> {
    pub(crate) reader: RecordReader<P>,
    origin_base: Option<String>,
    default_origin: OnceLock<String>,
    ttl: Duration,
    cache: Arc<Mutex<HashMap<(String, String), Cached>>>,
    /// One lookup in flight per (DID, kid).
    in_flight: Mutex<HashMap<(String, String), InFlight>>,
    /// Each DID's proven device records as last listed, kept for `ttl`.
    records: Arc<Mutex<HashMap<String, ListedRecords>>>,
    /// When each DID was last listed for a key lookup, so a kid the held
    /// listing lacks lists it again at most once per `ttl`.
    refreshed: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    /// One listing, with its proofs, in flight per DID.
    listing: Mutex<HashMap<String, Listing>>,
    /// For each record type but device keys, keyed by (type, DID): each
    /// DID's proven records as last listed, and the listing in flight.
    /// Device records stay in `records` and `listing`, which key lookups and
    /// the snapshot read; no other type is ever put there, nor saved.
    other_records: Mutex<HashMap<(String, String), HeldEntries>>,
    other_listing: Mutex<HashMap<(String, String), Listing>>,
    /// The prefetch in flight for each DID, so two batches closing together
    /// make one request. Several DIDs share one entry.
    prefetching: Mutex<HashMap<String, Arc<Prefetch>>>,
    /// One batch key request in flight per (DID, kid), so prefetches racing
    /// on a key share one request: held locked while the request runs.
    prefetching_keys: Mutex<HashMap<(String, String), KeyPrefetch>>,
    /// CIDs of records whose repository proof has checked, so each is fetched
    /// once however often the records are listed.
    proven: Arc<Mutex<HashSet<crate::identity_records::Cid>>>,
    /// Proofs in flight, so listings racing on a record share one fetch.
    proving: crate::identity_records::ProofsInFlight,
    /// Per DID, how many times `refresh_account` has dropped its answers.
    refreshes: Mutex<HashMap<String, u64>>,
    /// Test only: run once where `settle` has checked the refresh count and
    /// is about to remember an answer from the other sources, with the count
    /// still locked.
    #[cfg(test)]
    before_remember: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    retry_after: Vec<Duration>,
    /// The origin answered its batch key route with a 404: a server from
    /// before it, asked key by key for the rest of this lookup's life.
    batch_route_missing: std::sync::atomic::AtomicBool,
    /// Each ruling referee's key list as its own site last listed it, by
    /// `did:web:` name; see [`Self::own_host_answer`].
    referees: Arc<Mutex<HashMap<String, RefereeKeys>>>,
    /// How long a referee's site that could not answer is answered for
    /// without asking; zero unless set (`with_cannot_answer_for`).
    cannot_answer_for: Duration,
    own_host_wait: Duration,
    #[cfg(any(test, feature = "test-support"))]
    own_host_base: Option<OwnHostBase>,
    /// Where the cache is kept between launches, and whether it has been
    /// taken in yet. The snapshot is read once, before the first lookup,
    /// once `after` (another lookup's flush) has settled.
    writer: Arc<Writer>,
    loaded: tokio::sync::OnceCell<()>,
    after: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
}

/// The least time between two writes of a lookup's snapshot.
pub const SAVE_EVERY: Duration = Duration::from_secs(2);

/// A lookup's store, and when it was written.
struct Writer {
    store: Arc<dyn KeyLookupStore>,
    /// Held across each write, so writes land one after another.
    writing: tokio::sync::Mutex<()>,
    timing: Mutex<Timing>,
}

#[derive(Default)]
struct Timing {
    /// When the last write was begun.
    last: Option<tokio::time::Instant>,
    /// A save asked for and not written yet.
    owed: bool,
    /// A write is held until [`SAVE_EVERY`] after the last.
    held: bool,
    /// Set by `flush`: nothing is written after it.
    flushed: bool,
}

impl Writer {
    fn new(store: Arc<dyn KeyLookupStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            writing: tokio::sync::Mutex::new(()),
            timing: Mutex::new(Timing::default()),
        })
    }

    /// Write the snapshot of `held` as it is now, if a save is owed; a write
    /// that fails is logged and dropped.
    async fn write_owed(&self, held: &Held) {
        let _writing = self.writing.lock().await;
        if !std::mem::take(&mut self.timing.lock().owed) {
            return;
        }
        let Ok(text) = serde_json::to_string(&held.snapshot()) else {
            return;
        };
        if let Err(e) = self.store.save(&text) {
            tracing::debug!("keeping the key lookup snapshot failed: {e:#}");
        }
    }
}

/// What a snapshot is taken from, shared with a write held for later.
struct Held {
    cache: Arc<Mutex<HashMap<(String, String), Cached>>>,
    referees: Arc<Mutex<HashMap<String, RefereeKeys>>>,
    records: Arc<Mutex<HashMap<String, ListedRecords>>>,
    refreshed: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    proven: Arc<Mutex<HashSet<crate::identity_records::Cid>>>,
}

impl Held {
    /// Each account's records once: the DID's held listing where there is
    /// one, else the records its first answer holds.
    fn snapshot(&self) -> KeyLookupSnapshot {
        let mut accounts: HashMap<String, Vec<serde_json::Value>> = self
            .records
            .lock()
            .iter()
            .map(|(did, (records, _))| (did.clone(), records.clone()))
            .collect();
        let keys = self
            .cache
            .lock()
            .iter()
            .map(|(slot, c)| {
                accounts
                    .entry(slot.0.clone())
                    .or_insert_with(|| c.records.clone());
                (
                    slot.clone(),
                    CachedKey {
                        other: c.other.map(|o| o.map(FoundKeySnapshot::of)),
                        at: c.at.timestamp_millis(),
                    },
                )
            })
            .collect();
        KeyLookupSnapshot {
            version: SNAPSHOT_VERSION,
            accounts: accounts.into_iter().collect(),
            keys,
            records: self
                .records
                .lock()
                .iter()
                .map(|(did, (_, at))| (did.clone(), at.timestamp_millis()))
                .collect(),
            refreshed: self
                .refreshed
                .lock()
                .iter()
                .map(|(did, at)| (did.clone(), at.timestamp_millis()))
                .collect(),
            proven: self
                .proven
                .lock()
                .iter()
                .map(|cid| cid.to_string())
                .collect(),
            referees: self
                .referees
                .lock()
                .iter()
                .map(|(did, referee)| {
                    (
                        did.clone(),
                        RefereeSnapshot {
                            keys: referee
                                .keys
                                .iter()
                                .map(|(kid, (key, retired_at))| {
                                    (kid.clone(), URL_SAFE_NO_PAD.encode(key), *retired_at)
                                })
                                .collect(),
                            read_for: referee.read_for.iter().cloned().collect(),
                        },
                    )
                })
                .collect(),
        }
    }
}

/// When a miss the origin answered is asked again, counted from the first
/// ask: the origin may still be fetching the key from the signer's home
/// server. Only the origin is asked again; the first ask listed the records.
pub const MISS_RETRY_AFTER: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(6),
    Duration::from_secs(15),
];

/// How recently a line must have been signed for its missing key to be asked
/// again at the retry delays: a line that just arrived may name a key its
/// server is still fetching; a replayed one settles on its first miss.
pub const FRESH_LINE: Duration = Duration::from_secs(120);

/// Most keys one request to the origin's batch key route names.
pub const MAX_KEYS_PER_REQUEST: usize = 50;

/// How a key is asked for; see [`KeyLookup::key_for_at_with`].
#[derive(Debug, Clone, Copy)]
pub struct KeyAsk {
    /// Ask a fresh line's miss again at the retry delays.
    pub retry: bool,
    /// The DID is a server's, which has no device records: none are listed.
    pub server: bool,
}

impl Default for KeyAsk {
    fn default() -> Self {
        Self {
            retry: true,
            server: false,
        }
    }
}

/// A key to prefetch: its DID and kid, and whether the DID is a server's,
/// which has no device records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub did: String,
    pub kid: String,
    pub server: bool,
}

impl KeyPair {
    /// A signer's key.
    pub fn new(did: impl Into<String>, kid: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            kid: kid.into(),
            server: false,
        }
    }

    /// A server's own key.
    pub fn server(did: impl Into<String>, kid: impl Into<String>) -> Self {
        Self {
            server: true,
            ..Self::new(did, kid)
        }
    }
}

/// A key the origin answered: its bytes, `None` when they do not decode, and
/// when it stopped counting.
type OriginAnswer = (Option<[u8; 32]>, Option<i64>);

/// One (DID, kid)'s cached answer: the signer's device records as listed,
/// folded again at whatever time is asked, and what the other sources said,
/// once they have been asked.
#[derive(Clone)]
struct Cached {
    records: Vec<serde_json::Value>,
    other: Option<Option<FoundKey>>,
    /// Wall clock, so a snapshot of the cache can carry it.
    at: DateTime<Utc>,
}

/// What one lookup settled on, shared by every ask that awaited it.
#[derive(Clone)]
struct Settled {
    records: Vec<serde_json::Value>,
    /// What the other sources said; `None` when they were not asked.
    other: Option<Option<FoundKey>>,
    failure: Option<Arc<anyhow::Error>>,
}

/// A batch key request in flight, locked until it settles.
type KeyPrefetch = Arc<tokio::sync::Mutex<()>>;

/// A lookup in flight, which every ask for its (DID, kid) awaits.
type InFlight = Arc<tokio::sync::OnceCell<Settled>>;

/// One DID's proven device records, and when they were listed.
type ListedRecords = (Vec<serde_json::Value>, DateTime<Utc>);

/// What a lookup keeps between launches: each account's proven device
/// records once (`accounts`); each (DID, kid) answer, a key found or a miss
/// with the time it was settled (a miss answers for the ttl), reading its
/// DID's records from `accounts`; when each DID's held listing was taken and
/// when it was last listed for a key lookup; and the CIDs of records whose
/// proof checked. Failures and lookups in flight are not kept. A snapshot of
/// another `version` is not read. Times are unix milliseconds.
///
/// Twin of the JS `KeyLookupSnapshot` in shape; the JSON differs (a Rust slot
/// is a two-element array where the JS slot is a string, and the key is
/// base64url here), and neither side reads the other's file.
#[derive(Default, Serialize, Deserialize)]
pub struct KeyLookupSnapshot {
    pub version: u32,
    pub accounts: Vec<(String, Vec<serde_json::Value>)>,
    pub keys: Vec<((String, String), CachedKey)>,
    pub records: Vec<(String, i64)>,
    pub refreshed: Vec<(String, i64)>,
    pub proven: Vec<String>,
    /// Each ruling referee's key list as its own site listed it. Absent from
    /// a snapshot written before lists were kept.
    #[serde(default)]
    pub referees: Vec<(String, RefereeSnapshot)>,
}

/// One referee's key list as a snapshot carries it: each key by kid,
/// base64url, with when it stopped counting, and the kids the list was read
/// for.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RefereeSnapshot {
    pub keys: Vec<(String, String, Option<i64>)>,
    pub read_for: Vec<String>,
}

/// The snapshot shape this code reads and writes.
pub const SNAPSHOT_VERSION: u32 = 2;

/// A cached answer as a snapshot carries it: what the other sources said
/// (absent when they were not asked, `null` for a miss), and when.
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedKey {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub other: Option<Option<FoundKeySnapshot>>,
    pub at: i64,
}

/// A field that is present, `null` included, is `Some`; serde's default
/// reads `null` as absent.
fn present<'de, D, T>(de: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(de).map(Some)
}

/// A found key as a snapshot carries it; the key is base64url, as the origin
/// route writes it. The JS snapshot holds a `Uint8Array` there instead, so
/// neither side reads the other's file.
#[derive(Clone, Serialize, Deserialize)]
pub struct FoundKeySnapshot {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub source: String,
    #[serde(rename = "retiredAt")]
    pub retired_at: Option<i64>,
}

impl FoundKeySnapshot {
    fn of(found: FoundKey) -> Self {
        Self {
            public_key: URL_SAFE_NO_PAD.encode(found.public_key),
            source: match found.source {
                KeySource::IdentityRecord => "IdentityRecord",
                KeySource::DidDocument => "DidDocument",
                KeySource::OriginServer => "OriginServer",
                KeySource::DidKey => "DidKey",
            }
            .to_string(),
            retired_at: found.retired_at,
        }
    }

    fn into_found(self) -> Option<FoundKey> {
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()?
            .try_into()
            .ok()?;
        Some(FoundKey {
            public_key,
            source: match self.source.as_str() {
                "IdentityRecord" => KeySource::IdentityRecord,
                "DidDocument" => KeySource::DidDocument,
                "OriginServer" => KeySource::OriginServer,
                "DidKey" => KeySource::DidKey,
                _ => return None,
            },
            retired_at: self.retired_at,
            // A snapshot's answer is a document's or the origin's, and
            // neither gives these; a records answer is folded from the
            // records again.
            created_at: None,
            expires_at: None,
        })
    }
}

/// Where a key lookup keeps its snapshot, one JSON string.
pub trait KeyLookupStore: Send + Sync {
    /// The snapshot held, or `None` when there is none.
    fn load(&self) -> Result<Option<String>>;
    /// Replace the snapshot held.
    fn save(&self, snapshot: &str) -> Result<()>;
}

/// A store that forgets when the process ends; the default.
#[derive(Default)]
pub struct MemoryKeyLookupStore(Mutex<Option<String>>);

impl KeyLookupStore for MemoryKeyLookupStore {
    fn load(&self) -> Result<Option<String>> {
        Ok(self.0.lock().clone())
    }

    fn save(&self, snapshot: &str) -> Result<()> {
        *self.0.lock() = Some(snapshot.to_string());
        Ok(())
    }
}

/// A [`KeyLookupStore`] in one JSON file, beside [`crate::device_key::FileDeviceKeyStore`].
pub struct FileKeyLookupStore {
    path: std::path::PathBuf,
}

impl FileKeyLookupStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl KeyLookupStore for FileKeyLookupStore {
    fn load(&self) -> Result<Option<String>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading the key lookup snapshot"),
        }
    }

    fn save(&self, snapshot: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Through a temp file, so a crash mid-write leaves the last snapshot.
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, snapshot)?;
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

/// A listing of one DID's proven device records in flight, which every
/// lookup for that DID awaits.
type Listing = Arc<tokio::sync::OnceCell<Result<Vec<RecordEntry>, Arc<anyhow::Error>>>>;

/// A held listing of a record type other than device keys: its proven
/// entries, with their uris, and when it was taken.
type HeldEntries = (Vec<RecordEntry>, DateTime<Utc>);

/// The records' values, as device callers take them.
fn values(entries: Vec<RecordEntry>) -> Vec<serde_json::Value> {
    entries.into_iter().map(|e| e.value).collect()
}

/// Held values as entries, with no uri or CID: a held device listing keeps
/// values only.
fn unnamed(records: Vec<serde_json::Value>) -> Vec<RecordEntry> {
    records
        .into_iter()
        .map(|value| RecordEntry {
            uri: String::new(),
            cid: String::new(),
            value,
        })
        .collect()
}

/// The entries whose values `proven` holds, in listing order:
/// `proven_records` keeps the listing's order and drops the rest.
fn proven_entries(entries: Vec<RecordEntry>, proven: &[serde_json::Value]) -> Vec<RecordEntry> {
    let mut next = proven.iter().peekable();
    entries
        .into_iter()
        .filter(|entry| {
            if next.peek() == Some(&&entry.value) {
                next.next();
                true
            } else {
                false
            }
        })
        .collect()
}

/// One prefetch in flight, shared by every DID it asked for. Setting the
/// entry and running the request are two steps, so the caller that runs it
/// need not be the one that set it: the list of DIDs travels with the cell.
struct Prefetch {
    /// The DIDs this request names, whoever ends up making it.
    asked: Vec<String>,
    /// Set once the request has settled, whatever it served.
    cell: tokio::sync::OnceCell<()>,
}

/// The fields of the origin's answer read here. The dates are read as any
/// JSON value, so one that is not a number counts as absent rather than
/// failing the answer.
#[derive(serde::Deserialize)]
struct OriginKey {
    public_key: String,
    #[serde(default)]
    removed_at: serde_json::Value,
    #[serde(default)]
    expires_at: serde_json::Value,
}

impl OriginKey {
    /// When the key stopped counting: the earlier of its removal and its
    /// expiry, whole seconds rounded down. A server from before expiries
    /// sends no `expires_at`, and its keys are taken as not expiring.
    fn retired_at(&self) -> Option<i64> {
        [&self.removed_at, &self.expires_at]
            .into_iter()
            .filter_map(|date| date.as_f64())
            .map(|secs| secs.floor() as i64)
            .min()
    }
}

/// A key from a server's key list: its bytes, and when it stopped counting.
pub(crate) type ListedKey = ([u8; 32], Option<i64>);

/// The keys a server's key list (`/api/v1/signing-keys/{did}`) holds, by
/// kid, each with when it stopped counting: every `keys[]` entry, and the
/// top-level `public_key`, the only key a server from before the list sends.
/// A key is filed under the kid its bytes hash to. `None` for a body that is
/// not a key list.
pub(crate) fn key_list(body: &serde_json::Value) -> Option<HashMap<String, ListedKey>> {
    let entries = body.get("keys").and_then(|keys| keys.as_array());
    let current = body.get("public_key").and_then(|key| key.as_str());
    if entries.is_none() && current.is_none() {
        return None;
    }
    let mut keys: HashMap<String, ListedKey> = entries
        .into_iter()
        .flatten()
        .filter_map(|entry| serde_json::from_value::<OriginKey>(entry.clone()).ok())
        .filter_map(|entry| Some((decode_key(&entry.public_key)?, entry.retired_at())))
        .map(|(key, retired_at)| (derive_kid_bytes(&key), (key, retired_at)))
        .collect();
    if let Some(key) = current.and_then(decode_key) {
        keys.entry(derive_kid_bytes(&key)).or_insert((key, None));
    }
    Some(keys)
}

/// What a ruling referee's own site says about one of its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnHostAnswer {
    /// Its key list holds the key. `retired_at`: when it stopped counting,
    /// unix seconds.
    Listed {
        public_key: [u8; 32],
        retired_at: Option<i64>,
    },
    /// Its key list, read since the key was first asked about, lacks it.
    NotListed,
    /// The name is not a plain public host, or the list could not be read.
    CannotAnswer,
}

/// Where a `did:web:` host's key list is read, given the host.
#[cfg(any(test, feature = "test-support"))]
type OwnHostBase = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// The longest one read of a referee's key list may take.
pub const OWN_HOST_WAIT: Duration = Duration::from_secs(5);

/// Most referees whose key lists are kept at once.
const REFEREES_HELD: usize = 1024;

/// Most kids a referee's list is remembered as read for, oldest out. One
/// is added per ruling naming a key the list lacks, so only a misbehaving
/// referee or server comes near it; a kid that falls out is read for once
/// more if it is named again.
const READ_FOR_HELD: usize = 256;

/// One referee's key list, as its own site last listed it: the server's key
/// set (`SignatureChecker`'s `ServerKeySet`) for a server not connected to.
#[derive(Default)]
struct RefereeKeys {
    keys: HashMap<String, ListedKey>,
    /// Kids the list has been read for, once each, oldest first, at most
    /// [`READ_FOR_HELD`].
    read_for: std::collections::VecDeque<String>,
    /// The read in flight, shared by every ask meanwhile; `true` once read.
    reading: Option<Arc<tokio::sync::OnceCell<bool>>>,
    /// When a read last failed.
    failed_at: Option<tokio::time::Instant>,
    /// When last asked about, for the bound.
    used: Option<tokio::time::Instant>,
}

/// The host of a `did:web:` name that is a plain host: no port, no path.
fn plain_did_web_host(did: &str) -> Option<&str> {
    let host = did.strip_prefix("did:web:")?;
    (!host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    .then_some(host)
}

impl RefereeKeys {
    /// Remember that the list was read for `kid`, dropping the oldest kid
    /// past [`READ_FOR_HELD`].
    fn note_read_for(&mut self, kid: String) {
        if self.read_for.contains(&kid) {
            return;
        }
        self.read_for.push_back(kid);
        while self.read_for.len() > READ_FOR_HELD {
            self.read_for.pop_front();
        }
    }
}

/// Drop the referees asked about longest ago until at most `cap` are left;
/// one being read is never dropped.
fn bound_referees(held: &mut HashMap<String, RefereeKeys>, cap: usize) {
    if held.len() <= cap {
        return;
    }
    let mut aged: Vec<(Option<tokio::time::Instant>, String)> = held
        .iter()
        .filter(|(_, referee)| referee.reading.is_none())
        .map(|(did, referee)| (referee.used, did.clone()))
        .collect();
    aged.sort();
    let over = held.len() - cap;
    for (_, did) in aged.into_iter().take(over) {
        held.remove(&did);
    }
}

impl<P: ClientProvider> KeyLookup<P> {
    /// `origin_base` is the origin server's base URL; the same client
    /// provider as the reader's serves its requests.
    pub fn new(reader: RecordReader<P>, origin_base: Option<String>, ttl: Duration) -> Self {
        if let Some(base) = &origin_base {
            reader.set_home_base(base);
        }
        Self {
            reader,
            origin_base,
            default_origin: OnceLock::new(),
            ttl,
            cache: Default::default(),
            in_flight: Mutex::new(HashMap::new()),
            records: Default::default(),
            refreshed: Default::default(),
            listing: Mutex::new(HashMap::new()),
            other_records: Mutex::new(HashMap::new()),
            other_listing: Mutex::new(HashMap::new()),
            prefetching: Mutex::new(HashMap::new()),
            prefetching_keys: Mutex::new(HashMap::new()),
            proven: Default::default(),
            proving: Default::default(),
            refreshes: Mutex::new(HashMap::new()),
            #[cfg(test)]
            before_remember: Mutex::new(None),
            retry_after: MISS_RETRY_AFTER.to_vec(),
            batch_route_missing: Default::default(),
            referees: Default::default(),
            cannot_answer_for: Duration::ZERO,
            own_host_wait: OWN_HOST_WAIT,
            #[cfg(any(test, feature = "test-support"))]
            own_host_base: None,
            writer: Writer::new(Arc::new(MemoryKeyLookupStore::default())),
            loaded: tokio::sync::OnceCell::new(),
            after: Mutex::new(None),
        }
    }

    /// Keep the cache in `store`, so a lookup built on the same store starts
    /// with the found keys, proven records, listing times and proven CIDs it
    /// last held.
    pub fn with_store(mut self, store: Arc<dyn KeyLookupStore>) -> Self {
        self.writer = Writer::new(store);
        self
    }

    /// Read the store only once `after` has settled: the flush of the lookup
    /// that used the same store before, so its last write lands before this
    /// one reads.
    pub fn with_load_after(self, after: impl Future<Output = ()> + Send + 'static) -> Self {
        *self.after.lock() = Some(Box::pin(after));
        self
    }

    /// Take in what the store holds, once; a store that cannot be read, or a
    /// snapshot that does not parse or is of another version, leaves the
    /// cache as it is.
    async fn load(&self) {
        self.loaded
            .get_or_init(|| async {
                let after = self.after.lock().take();
                if let Some(after) = after {
                    after.await;
                }
                let Ok(Some(text)) = self.writer.store.load() else {
                    return;
                };
                #[derive(Deserialize)]
                struct Version {
                    #[serde(default)]
                    version: u32,
                }
                if !serde_json::from_str::<Version>(&text)
                    .is_ok_and(|v| v.version == SNAPSHOT_VERSION)
                {
                    tracing::debug!("the key lookup snapshot is of another shape; starting empty");
                    return;
                }
                let Ok(snapshot) = serde_json::from_str::<KeyLookupSnapshot>(&text) else {
                    tracing::debug!("the key lookup snapshot does not parse; starting empty");
                    return;
                };
                let at = |ms: i64| DateTime::from_timestamp_millis(ms).unwrap_or_else(Utc::now);
                let accounts: HashMap<String, Vec<serde_json::Value>> =
                    snapshot.accounts.into_iter().collect();
                let records_of = |did: &str| accounts.get(did).cloned().unwrap_or_default();
                {
                    let mut cache = self.cache.lock();
                    for (slot, held) in snapshot.keys {
                        let other = match held.other {
                            None => None,
                            Some(None) => Some(None),
                            Some(Some(found)) => match found.into_found() {
                                Some(found) => Some(Some(found)),
                                // A key that does not decode is not a key.
                                None => continue,
                            },
                        };
                        let records = records_of(&slot.0);
                        cache.entry(slot).or_insert(Cached {
                            records,
                            other,
                            at: at(held.at),
                        });
                    }
                }
                {
                    let mut records = self.records.lock();
                    for (did, ms) in snapshot.records {
                        let listed = records_of(&did);
                        records.entry(did).or_insert((listed, at(ms)));
                    }
                }
                {
                    let mut refreshed = self.refreshed.lock();
                    for (did, ms) in snapshot.refreshed {
                        refreshed.entry(did).or_insert(at(ms));
                    }
                }
                {
                    let mut proven = self.proven.lock();
                    for cid in snapshot.proven {
                        if let Ok(cid) = cid.parse() {
                            proven.insert(cid);
                        }
                    }
                }
                {
                    let mut referees = self.referees.lock();
                    for (did, kept) in snapshot.referees {
                        let referee = referees.entry(did).or_default();
                        for (kid, key, retired_at) in kept.keys {
                            // A key that does not decode is not a key.
                            if let Some(key) = decode_key(&key) {
                                referee.keys.entry(kid).or_insert((key, retired_at));
                            }
                        }
                        for kid in kept.read_for {
                            referee.note_read_for(kid);
                        }
                    }
                    bound_referees(&mut referees, REFEREES_HELD);
                }
            })
            .await;
    }

    /// What a snapshot is taken from.
    fn held(&self) -> Held {
        Held {
            cache: self.cache.clone(),
            referees: self.referees.clone(),
            records: self.records.clone(),
            refreshed: self.refreshed.clone(),
            proven: self.proven.clone(),
        }
    }

    /// Write the snapshot to the store, at most once every [`SAVE_EVERY`]: a
    /// save inside that time is held and written when it ends, with whatever
    /// is held then. Nothing is written after `flush`.
    async fn save(&self) {
        let now = tokio::time::Instant::now();
        let wait = {
            let mut timing = self.writer.timing.lock();
            if timing.flushed {
                return;
            }
            timing.owed = true;
            if timing.held {
                return;
            }
            let wait = timing
                .last
                .map(|last| (last + SAVE_EVERY).saturating_duration_since(now))
                .unwrap_or_default();
            if wait.is_zero() {
                timing.last = Some(now);
            } else {
                timing.held = true;
            }
            wait
        };
        if wait.is_zero() {
            self.writer.write_owed(&self.held()).await;
            return;
        }
        let (writer, held) = (self.writer.clone(), self.held());
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            {
                let mut timing = writer.timing.lock();
                timing.held = false;
                if timing.flushed {
                    return;
                }
                timing.last = Some(tokio::time::Instant::now());
            }
            writer.write_owed(&held).await;
        });
    }

    /// Write a held save now, wait for every write to land, and write nothing
    /// after. Called before another lookup on the same store loads it, so
    /// that load sees this lookup's last answers and no later write of this
    /// one replaces what the other writes.
    ///
    /// A lookup set aside before it ever loaded still holds the flush it was
    /// given (`with_load_after`): that runs first, so flushes chain however
    /// many lookups were set aside unloaded.
    pub async fn flush(&self) {
        let after = self.after.lock().take();
        if let Some(after) = after {
            after.await;
        }
        self.writer.timing.lock().flushed = true;
        self.writer.write_owed(&self.held()).await;
    }

    /// When a miss the origin answered is asked again, counted from the first
    /// ask; [`MISS_RETRY_AFTER`] unless set here.
    pub fn with_retry_delays(mut self, after_first_ask: Vec<Duration>) -> Self {
        self.retry_after = after_first_ask;
        self
    }

    /// Answer a referee whose site could not be read as unable to answer for
    /// `window` after the failed read, without reading again.
    pub fn with_cannot_answer_for(mut self, window: Duration) -> Self {
        self.cannot_answer_for = window;
        self
    }

    /// Read a `did:web:` host's key list at the base `base` gives for the
    /// host, not at `https://<host>`, without the private-address check: for
    /// tests, whose stubs serve on loopback.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_own_host_base(
        mut self,
        base: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.own_host_base = Some(Arc::new(base));
        self
    }

    #[cfg(test)]
    fn with_own_host_wait(mut self, wait: Duration) -> Self {
        self.own_host_wait = wait;
        self
    }

    /// The record reader this lookup lists and proves through, with whatever
    /// callbacks it was built with.
    pub fn reader(&self) -> &RecordReader<P> {
        &self.reader
    }

    /// The origin to ask when none was given at construction. Set once; a
    /// client sets it to the server it connected to.
    pub fn set_default_origin_base(&self, base: String) {
        self.reader.set_home_base(&base);
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
    /// say it lacks the key. Asks for one (did, kid) while a lookup for it
    /// runs await that lookup.
    pub async fn key_for_at(
        &self,
        did: &str,
        kid: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<FoundKey>> {
        self.key_for_at_with(did, kid, at, KeyAsk::default()).await
    }

    /// [`Self::key_for_at`], asked as `ask` says: `retry: false` settles a
    /// fresh line's miss without the retry delays; `server: true` names a
    /// server's DID, which has no device records: none are listed. A line
    /// signed more than [`FRESH_LINE`] before now is never asked about
    /// again. A did:key signer's own key is read from its DID
    /// ([`did_key_answer`]) before anything held is looked at or any source
    /// asked, and is never kept.
    pub async fn key_for_at_with(
        &self,
        did: &str,
        kid: &str,
        at: DateTime<Utc>,
        ask: KeyAsk,
    ) -> Result<Option<FoundKey>> {
        if let Some(found) = did_key_answer(did, kid) {
            return Ok(Some(found));
        }
        self.load().await;
        let slot = (did.to_string(), kid.to_string());
        loop {
            let hit = self.cache.lock().get(&slot).cloned();
            let mut cached = hit.clone().filter(|c| self.inside_ttl(c.at));
            // A found key does not expire; one found in the records takes the
            // DID's listing again past the ttl, so a retirement since lands
            // on it. A remembered miss (`Some(None)`) stands until the ttl.
            if cached.is_none()
                && let Some(hit) = hit
                && hit.other != Some(None)
            {
                cached = Some(match hit.other {
                    None => self.relisted(&slot, did, kid, hit).await,
                    Some(_) => hit,
                });
            }
            if let Some(c) = cached.as_ref() {
                if let Some(found) = in_records(did, kid, &c.records, at) {
                    return Ok(Some(found));
                }
                if let Some(other) = c.other {
                    return Ok(other);
                }
            }

            let cell = self
                .in_flight
                .lock()
                .entry(slot.clone())
                .or_default()
                .clone();
            let settled = cell
                .get_or_init(|| self.settle(&slot, did, kid, at, cached, ask))
                .await
                .clone();
            {
                let mut in_flight = self.in_flight.lock();
                if in_flight.get(&slot).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
                    in_flight.remove(&slot);
                }
            }

            // Each ask folds the records at its own time.
            if let Some(found) = in_records(did, kid, &settled.records, at) {
                return Ok(Some(found));
            }
            match (settled.other, settled.failure) {
                (Some(Some(found)), _) => return Ok(Some(found)),
                (_, Some(e)) => return Err(anyhow::anyhow!("{e:#}")),
                (Some(None), None) => return Ok(None),
                // The other sources were not asked, since the lookup found the
                // key in the records at its own time: ask them now.
                (None, None) => {}
            }
        }
    }

    /// Ask every source, and again at each retry delay while the origin
    /// answers with a miss; then remember what was settled.
    async fn settle(
        &self,
        slot: &(String, String),
        did: &str,
        kid: &str,
        at: DateTime<Utc>,
        cached: Option<Cached>,
        ask: KeyAsk,
    ) -> Settled {
        let started = tokio::time::Instant::now();
        let refreshes = self.refresh_count(did);
        let listed = cached.is_none();
        // A server's DID has no device records to list.
        let held = cached
            .map(|c| c.records)
            .or_else(|| ask.server.then(Vec::new));
        let mut settled = self.ask(did, kid, at, held, false).await;
        // Only a line signed just now is asked about again.
        let fresh = (Utc::now() - at)
            .to_std()
            .map_or(true, |since| since <= FRESH_LINE);
        let retries: &[Duration] = if ask.retry && fresh {
            &self.retry_after
        } else {
            &[]
        };
        for after in retries {
            let missed = matches!(settled.other, Some(None))
                && settled.failure.is_none()
                && self.origin_base().is_some();
            if !missed {
                break;
            }
            tokio::time::sleep_until(started + *after).await;
            // The first ask listed the records; a retry asks the origin only.
            settled = self.ask(did, kid, at, Some(settled.records), true).await;
        }
        match (&settled.other, &settled.failure) {
            (None, None) if listed => self.remember(slot.clone(), settled.records.clone(), None),
            (Some(Some(_)), _) | (Some(None), None) => {
                // An account refreshed since this lookup began has dropped
                // the answers its new records can change; one from before
                // stays dropped. The count is held while the answer is
                // written, so a refresh cannot drop answers in between.
                let counts = self.refreshes.lock();
                if counts.get(did).copied().unwrap_or(0) == refreshes {
                    #[cfg(test)]
                    if let Some(hook) = self.before_remember.lock().take() {
                        hook();
                    }
                    self.remember(slot.clone(), settled.records.clone(), settled.other);
                }
            }
            _ => {}
        }
        self.save().await;
        settled
    }

    /// One round: the records (`held` when given, else the DID's records),
    /// then the other sources, or the origin alone when `origin_only`.
    async fn ask(
        &self,
        did: &str,
        kid: &str,
        at: DateTime<Utc>,
        held: Option<Vec<serde_json::Value>>,
        origin_only: bool,
    ) -> Settled {
        let mut failure = None;
        let records = match held {
            Some(records) => records,
            None => match self.device_records(did, kid).await {
                Ok(records) => records,
                Err(e) => {
                    failure = Some(e);
                    Vec::new()
                }
            },
        };
        if in_records(did, kid, &records, at).is_some() {
            return Settled {
                records,
                other: None,
                failure: failure.map(Arc::new),
            };
        }

        let mut take = |answer: Result<Option<[u8; 32]>>, source, retired_at| match answer {
            Ok(Some(key)) if derive_kid_bytes(&key) == kid => Some(FoundKey {
                public_key: key,
                source,
                retired_at,
                created_at: None,
                expires_at: None,
            }),
            Ok(_) => None,
            Err(e) => {
                failure.get_or_insert(e);
                None
            }
        };
        let mut found = None;
        if !origin_only && did.starts_with("did:web:") {
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
            let (key, retired_at) = match answer {
                Ok(Some((key, retired_at))) => (Ok(Some(key)), retired_at),
                Ok(None) => (Ok(None), None),
                Err(e) => (Err(e), None),
            };
            found = take(key, KeySource::OriginServer, retired_at);
        }
        Settled {
            records,
            other: Some(found),
            failure: failure.map(Arc::new),
        }
    }

    /// `did`'s device key records whose repository proof checks, listed afresh
    /// or by a listing already in flight, through this lookup's cache of
    /// proven records, so each record's proof is fetched once.
    pub async fn proven_device_records(&self, did: &str) -> Result<Vec<serde_json::Value>> {
        self.load().await;
        Ok(values(
            self.list_records_of(did, DEVICE_KEY_TYPE, false).await?,
        ))
    }

    /// `did`'s proven device records listed afresh at the PDS, for a caller
    /// that must see a record written since the last listing: the home
    /// server's copy may predate it.
    pub async fn refresh_device_records(&self, did: &str) -> Result<Vec<serde_json::Value>> {
        self.load().await;
        Ok(values(
            self.list_records_of(did, DEVICE_KEY_TYPE, true).await?,
        ))
    }

    /// `did`'s agent records whose repository proof checks, claims and
    /// removals alike, each with its uri, read as device records are: the
    /// held listing while inside the ttl, else a listing, the home server's
    /// copy first. Held apart from the device records, and never saved.
    pub async fn proven_agent_records(&self, did: &str) -> Result<Vec<RecordEntry>> {
        self.load().await;
        let key = (AGENT_KEY_TYPE.to_string(), did.to_string());
        let held = self
            .other_records
            .lock()
            .get(&key)
            .filter(|(_, at)| self.inside_ttl(*at))
            .map(|(entries, _)| entries.clone());
        if let Some(entries) = held {
            return Ok(entries);
        }
        self.list_records_of(did, AGENT_KEY_TYPE, false).await
    }

    /// `did`'s proven agent records listed afresh at the PDS, as
    /// [`Self::refresh_device_records`] lists device records.
    pub async fn refresh_agent_records(&self, did: &str) -> Result<Vec<RecordEntry>> {
        self.load().await;
        self.list_records_of(did, AGENT_KEY_TYPE, true).await
    }

    /// Ask the origin's batch key route for the keys of `pairs`, in one
    /// request per [`MAX_KEYS_PER_REQUEST`], for the pairs no answer is held
    /// for: not a key found, not a miss inside the ttl, not a key the DID's
    /// held records name, not a pair whose lookup is in flight. A pair
    /// another prefetch is asking for is not asked again; its answer is
    /// waited for. A key the origin answers is kept as its answer; a pair it
    /// leaves out is kept as a miss only when the DID's records are held (or
    /// it is a did:key or a server's DID, which have none). A request that
    /// fails, or is answered 429 or 5xx, keeps nothing, since it said nothing
    /// about the keys. Against a server without the route (a 404) nothing is
    /// asked. Never fails.
    pub async fn prefetch_keys(&self, pairs: &[KeyPair]) {
        self.load().await;
        let Some(base) = self.origin_base() else {
            return;
        };
        if self
            .batch_route_missing
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let now = Utc::now();
        let mut asked: Vec<KeyPair> = Vec::new();
        let mut waits: Vec<KeyPrefetch> = Vec::new();
        // Held while this call's request runs, so a prefetch naming one of
        // its keys meanwhile waits for it instead of asking again.
        let mine: KeyPrefetch = Arc::new(tokio::sync::Mutex::new(()));
        let asking = mine.clone().try_lock_owned().expect("a new lock is free");
        for pair in pairs {
            let (did, kid) = (&pair.did, &pair.kid);
            let slot = (did.clone(), kid.clone());
            if asked.iter().any(|p| p.did == *did && p.kid == *kid)
                || self.in_flight.lock().contains_key(&slot)
            {
                continue;
            }
            let hit = self.cache.lock().get(&slot).cloned();
            if let Some(hit) = &hit {
                let answered = match hit.other {
                    Some(Some(_)) => true,
                    Some(None) => self.inside_ttl(hit.at),
                    None => false,
                };
                if answered {
                    continue;
                }
            }
            let held = if pair.server {
                None
            } else {
                self.records
                    .lock()
                    .get(did)
                    .map(|(records, _)| records.clone())
                    .or(hit.map(|h| h.records))
            };
            if held.is_some_and(|records| in_records(did, kid, &records, now).is_some()) {
                continue;
            }
            {
                let mut prefetching = self.prefetching_keys.lock();
                if let Some(other) = prefetching.get(&slot) {
                    if !waits.iter().any(|w| Arc::ptr_eq(w, other)) {
                        waits.push(other.clone());
                    }
                    continue;
                }
                prefetching.insert(slot, mine.clone());
            }
            asked.push(pair.clone());
        }
        let kept = self.ask_batch_route_for(base, &asked).await;
        {
            let mut prefetching = self.prefetching_keys.lock();
            for pair in &asked {
                let slot = (pair.did.clone(), pair.kid.clone());
                if prefetching
                    .get(&slot)
                    .is_some_and(|m| Arc::ptr_eq(m, &mine))
                {
                    prefetching.remove(&slot);
                }
            }
        }
        drop(asking);
        if kept {
            self.save().await;
        }
        for other in waits {
            let _ = other.lock().await;
        }
    }

    /// `prefetch_keys`' requests for the pairs it asks; whether any answer
    /// was kept.
    async fn ask_batch_route_for(&self, base: &str, asked: &[KeyPair]) -> bool {
        let mut kept = false;
        for chunk in asked.chunks(MAX_KEYS_PER_REQUEST) {
            let slots: Vec<(String, String)> = chunk
                .iter()
                .map(|p| (p.did.clone(), p.kid.clone()))
                .collect();
            let answered = match self.ask_batch_route(base, &slots).await {
                Ok(Some(answered)) => answered,
                // The route is missing: nothing more is asked through it.
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "batch key request failed");
                    continue;
                }
            };
            for pair in chunk {
                let (did, kid) = (&pair.did, &pair.kid);
                let slot = (did.clone(), kid.clone());
                let found = answered.get(&slot).and_then(|(key, retired_at)| {
                    key.filter(|key| derive_kid_bytes(key) == *kid)
                        .map(|public_key| FoundKey {
                            public_key,
                            source: KeySource::OriginServer,
                            retired_at: *retired_at,
                            created_at: None,
                            expires_at: None,
                        })
                });
                let records = if pair.server {
                    Some(Vec::new())
                } else {
                    self.records
                        .lock()
                        .get(did)
                        .map(|(records, _)| records.clone())
                };
                // A miss counts only when the account's records were read:
                // without them, the line's own lookup lists the account.
                if found.is_none() && records.is_none() && !did.starts_with("did:key:") {
                    continue;
                }
                self.remember(slot, records.unwrap_or_default(), Some(found));
                kept = true;
            }
        }
        kept
    }

    /// The origin's batch key route's answer for `pairs`, by (DID, kid);
    /// `None` when the origin has no such route (a 404), which is remembered.
    /// An error for anything else that is not a success.
    async fn ask_batch_route(
        &self,
        base: &str,
        pairs: &[(String, String)],
    ) -> Result<Option<HashMap<(String, String), OriginAnswer>>> {
        let mut url = url::Url::parse(base).context("invalid origin base URL")?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("origin base URL cannot take a path"))?
            .pop_if_empty()
            .extend(["api", "v1", "signing-keys"]);
        let encode =
            |part: &str| url::form_urlencoded::byte_serialize(part.as_bytes()).collect::<String>();
        let keys: Vec<String> = pairs
            .iter()
            .map(|(did, kid)| format!("{}/{}", encode(did), encode(kid)))
            .collect();
        url.set_query(Some(&format!("keys={}", keys.join(","))));
        let client = self.reader.clients.client_for(url.as_str()).await?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .context("request to the origin key store failed")?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.batch_route_missing
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct Answer {
            keys: Vec<serde_json::Value>,
        }
        let answer: Answer = response
            .error_for_status()
            .context("the origin key store answered with an error")?
            .json()
            .await
            .context("the origin answer is not a key list")?;
        let mut out = HashMap::new();
        for entry in answer.keys {
            let (Some(did), Some(kid)) = (
                entry
                    .get("did")
                    .and_then(|d| d.as_str())
                    .map(str::to_string),
                entry
                    .get("kid")
                    .and_then(|k| k.as_str())
                    .map(str::to_string),
            ) else {
                continue;
            };
            let Ok(key) = serde_json::from_value::<OriginKey>(entry) else {
                continue;
            };
            out.insert((did, kid), (decode_key(&key.public_key), key.retired_at()));
        }
        Ok(Some(out))
    }

    /// Take the device records of `dids` from the origin, the home server, in
    /// one request per [`MAX_ACCOUNTS_PER_REQUEST`] accounts, for the DIDs
    /// whose listing is not held inside the ttl, and that can have one at all
    /// (a `did:key` is the key, so it is never asked for): each account the server
    /// returns is proven from the proofs it carries (a record whose proof is
    /// missing or fails is proven at the PDS) and kept with the server's
    /// listing time. An account the server leaves out is not read here; its
    /// first lookup lists it. A DID with a prefetch already in flight is
    /// awaited rather than asked for again. Nothing is asked without an
    /// origin. Never fails.
    pub async fn prefetch(&self, dids: &[String]) {
        self.load().await;
        let Some(home) = self.origin_base() else {
            return;
        };
        // The prefetches to await: the one this call starts, if any, and the
        // ones already in flight for DIDs it was given.
        let mut flights: Vec<Arc<Prefetch>> = Vec::new();
        {
            let mut asked: Vec<String> = Vec::new();
            let held = self.records.lock();
            let listing = self.listing.lock();
            let mut prefetching = self.prefetching.lock();
            for did in dids {
                // A did:key has no repository to list: the DID is the key.
                if did.starts_with("did:key:") {
                    continue;
                }
                if asked.contains(did) {
                    continue;
                }
                if let Some(flight) = prefetching.get(did) {
                    if !flights.iter().any(|f| Arc::ptr_eq(f, flight)) {
                        flights.push(flight.clone());
                    }
                    continue;
                }
                if listing.contains_key(did) {
                    continue;
                }
                if held.get(did).is_some_and(|(_, at)| self.inside_ttl(*at)) {
                    continue;
                }
                asked.push(did.clone());
            }
            if !asked.is_empty() {
                let flight = Arc::new(Prefetch {
                    asked: asked.clone(),
                    cell: tokio::sync::OnceCell::new(),
                });
                for did in &asked {
                    prefetching.insert(did.clone(), flight.clone());
                }
                flights.push(flight);
            }
        }
        if flights.is_empty() {
            return;
        }
        for flight in &flights {
            self.settle_prefetch(home, flight).await;
        }
        let mut prefetching = self.prefetching.lock();
        for flight in &flights {
            for did in &flight.asked {
                if prefetching.get(did).is_some_and(|f| Arc::ptr_eq(f, flight)) {
                    prefetching.remove(did);
                }
            }
        }
    }

    /// Run `flight`'s request, or await it when another caller runs it:
    /// whichever reaches the cell first makes the request. A request that
    /// served nothing sets the cell too, so nothing is left in flight for the
    /// next prefetch to await.
    async fn settle_prefetch(&self, home: &str, flight: &Prefetch) {
        flight
            .cell
            .get_or_init(|| async {
                let accounts = self
                    .reader
                    .fetch_accounts(home, &flight.asked, DEVICE_KEY_TYPE)
                    .await;
                let served = !accounts.is_empty();
                for (did, account) in accounts {
                    self.proven_from_home(&did, DEVICE_KEY_TYPE, &account).await;
                }
                if served {
                    self.save().await;
                }
            })
            .await;
    }

    /// Prove one account the home server served, and keep it as that DID's
    /// listing at the server's listing time. A record whose proof the server
    /// did not carry, or whose proof does not check, is proven at the PDS.
    async fn proven_from_home(
        &self,
        did: &str,
        collection: &str,
        account: &crate::identity_records::HomeAccount,
    ) -> Vec<RecordEntry> {
        let records = self
            .reader
            .proven_records(
                did,
                collection,
                account.entries.clone(),
                &self.proven,
                &self.proving,
                Some(&account.proofs),
                self.origin_base(),
            )
            .await;
        // The server's listing time, never later than now.
        let at = DateTime::from_timestamp(account.fetched_at, 0)
            .filter(|at| *at <= Utc::now())
            .unwrap_or_else(Utc::now);
        let kept = self.keep_entries(
            did,
            collection,
            proven_entries(account.entries.clone(), &records),
            at,
        );
        // A listing for key lookups, like the one `device_records` makes,
        // unless a newer one is held.
        if collection == DEVICE_KEY_TYPE
            && self
                .records
                .lock()
                .get(did)
                .is_some_and(|(_, held)| *held == at)
        {
            self.refreshed.lock().insert(did.to_string(), at);
        }
        kept
    }

    /// The proven records that decide whether `did`'s device key `kid` is
    /// retired (`retirement_closure`), from a new listing. Only those records
    /// are proven, through this lookup's proven set; the listing is not kept
    /// as the account's records, since it holds only part of them.
    pub async fn proven_retirement_closure(
        &self,
        did: &str,
        kid: &str,
    ) -> Result<Vec<serde_json::Value>> {
        self.load().await;
        let home = self.origin_base();
        let listed = self
            .reader
            .list_record_entries(did, DEVICE_KEY_TYPE, home)
            .await?;
        let closure = retirement_closure(did, kid, listed, |entry| &entry.value);
        if closure.is_empty() {
            return Ok(Vec::new());
        }
        let records = self
            .reader
            .proven_records(
                did,
                DEVICE_KEY_TYPE,
                closure,
                &self.proven,
                &self.proving,
                None,
                home,
            )
            .await;
        self.save().await;
        Ok(records)
    }

    /// `did`'s proven device records: the last listing while inside the ttl,
    /// if it names `kid` or the DID was already listed for a lookup inside
    /// the ttl; else a listing, so a key published since is found within the
    /// ttl. A `did:key` has none, and is answered without a request.
    async fn device_records(&self, did: &str, kid: &str) -> Result<Vec<serde_json::Value>> {
        // A did:key has no repository to list: the DID is the key. Answering
        // before anything is looked up or asked for keeps the records step
        // from making a request the server can only answer empty.
        if did.starts_with("did:key:") {
            return Ok(Vec::new());
        }
        let kept = self
            .records
            .lock()
            .get(did)
            .filter(|(_, at)| self.inside_ttl(*at))
            .map(|(records, _)| records.clone());
        if let Some(records) = kept {
            if device_key_history(did, &records)
                .iter()
                .any(|k| k.kid == kid)
            {
                return Ok(records);
            }
            let refreshed = self.refreshed.lock().get(did).copied();
            if refreshed.is_some_and(|at| self.inside_ttl(at)) {
                return Ok(records);
            }
        }
        self.refreshed.lock().insert(did.to_string(), Utc::now());
        Ok(values(
            self.list_records_of(did, DEVICE_KEY_TYPE, false).await?,
        ))
    }

    /// Whether `at` is less than the ttl ago. A time in the future, from a
    /// snapshot written under a clock ahead of this one, counts as now.
    fn inside_ttl(&self, at: DateTime<Utc>) -> bool {
        match (Utc::now() - at).to_std() {
            Ok(since) => since < self.ttl,
            // `at` is in the future.
            Err(_) => true,
        }
    }

    /// `did`'s proven records of `collection`, each with its uri, from the
    /// listing in flight, else a new one: the one read for every record
    /// type, device keys and agents. A listing that fails is not kept.
    ///
    /// For device records, a prefetch in flight for the account is waited
    /// for first, and its listing used when it brought one inside the ttl
    /// (held device records carry no uri).
    ///
    /// `direct` lists at the PDS, the home server skipped, and always starts
    /// a new listing, which lookups starting meanwhile join. Either way a
    /// listing is kept only if none newer is held (`keep_entries`), and is
    /// dated from before its request.
    async fn list_records_of(
        &self,
        did: &str,
        collection: &str,
        direct: bool,
    ) -> Result<Vec<RecordEntry>> {
        let device = collection == DEVICE_KEY_TYPE;
        let prefetching = self.prefetching.lock().get(did).cloned();
        if device
            && !direct
            && let Some(flight) = prefetching
            && let Some(home) = self.origin_base()
        {
            self.settle_prefetch(home, &flight).await;
            let held = self
                .records
                .lock()
                .get(did)
                .filter(|(_, at)| self.inside_ttl(*at))
                .map(|(records, _)| records.clone());
            if let Some(records) = held {
                return Ok(unnamed(records));
            }
        }
        let key = (collection.to_string(), did.to_string());
        let cell = match (device, direct) {
            (true, true) => {
                let cell = Listing::default();
                self.listing.lock().insert(did.to_string(), cell.clone());
                cell
            }
            (true, false) => self
                .listing
                .lock()
                .entry(did.to_string())
                .or_default()
                .clone(),
            (false, true) => {
                let cell = Listing::default();
                self.other_listing.lock().insert(key.clone(), cell.clone());
                cell
            }
            (false, false) => self
                .other_listing
                .lock()
                .entry(key.clone())
                .or_default()
                .clone(),
        };
        let listed = cell
            .get_or_init(|| async {
                let home = if direct { None } else { self.origin_base() };
                // Nothing held for this account: its records and proofs
                // together, in one request.
                if let Some(home) = home
                    && !self.holds(did, collection)
                    && let Some(account) = self
                        .reader
                        .fetch_accounts(home, &[did.to_string()], collection)
                        .await
                        .remove(did)
                {
                    return Ok(self.proven_from_home(did, collection, &account).await);
                }
                let at = Utc::now();
                match self
                    .reader
                    .list_record_entries_dated(did, collection, home)
                    .await
                {
                    Ok((entries, fetched_at)) => {
                        // What the home server hands over is dated with its
                        // own listing time, never later than now, as the
                        // batch route's is; a PDS listing with this client's
                        // time from before the request.
                        let at = match fetched_at {
                            Some(secs) => DateTime::from_timestamp(secs, 0)
                                .filter(|t| *t <= Utc::now())
                                .unwrap_or_else(Utc::now),
                            None => at,
                        };
                        let records = self
                            .reader
                            .proven_records(
                                did,
                                collection,
                                entries.clone(),
                                &self.proven,
                                &self.proving,
                                None,
                                home,
                            )
                            .await;
                        Ok(self.keep_entries(
                            did,
                            collection,
                            proven_entries(entries, &records),
                            at,
                        ))
                    }
                    Err(e) => Err(Arc::new(e)),
                }
            })
            .await
            .clone();
        if device {
            let mut listing = self.listing.lock();
            if listing.get(did).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
                listing.remove(did);
            }
        } else {
            let mut listing = self.other_listing.lock();
            if listing.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
                listing.remove(&key);
            }
        }
        listed.map_err(|e| anyhow::anyhow!("{e:#}"))
    }

    /// Whether a listing of `collection` is held for `did`.
    fn holds(&self, did: &str, collection: &str) -> bool {
        if collection == DEVICE_KEY_TYPE {
            self.records.lock().contains_key(did)
        } else {
            self.other_records
                .lock()
                .contains_key(&(collection.to_string(), did.to_string()))
        }
    }

    /// Clear a remembered miss for `(did, kid)`, so the next lookup asks the
    /// sources again. A key found stays cached.
    ///
    /// The DID's refresh time goes too, or the next lookup would answer a kid
    /// the held listing lacks from that listing and never see a record
    /// published since — which is the whole point of the caller's retry
    /// (`freeq-server/src/peer_keys.rs:184`).
    pub fn forget(&self, did: &str, kid: &str) {
        self.forget_with(did, kid, true);
    }

    /// [`Self::forget`]; `relist: false` keeps the DID's refresh time, for a
    /// caller whose miss was listed just now.
    pub fn forget_with(&self, did: &str, kid: &str, relist: bool) {
        let slot = (did.to_string(), kid.to_string());
        let mut cache = self.cache.lock();
        let found = cache.get(&slot).is_some_and(|c| {
            matches!(c.other, Some(Some(_)))
                || in_records(did, kid, &c.records, Utc::now()).is_some()
        });
        if !found {
            cache.remove(&slot);
            if relist {
                self.refreshed.lock().remove(did);
            }
        }
    }

    /// Whether the answer held for `(did, kid)` came from the origin server:
    /// a key the server vouched for, which a listing of the account's records
    /// could turn into a published one. Reads the stored snapshot first.
    pub async fn holds_origin_answer(&self, did: &str, kid: &str) -> bool {
        self.load().await;
        self.cache
            .lock()
            .get(&(did.to_string(), kid.to_string()))
            .is_some_and(|c| {
                matches!(
                    c.other,
                    Some(Some(FoundKey {
                        source: KeySource::OriginServer,
                        ..
                    }))
                )
            })
    }

    /// Whether a miss for `(did, kid)` is remembered inside the ttl. Reads
    /// the stored snapshot first.
    pub async fn holds_miss(&self, did: &str, kid: &str) -> bool {
        self.load().await;
        self.cache
            .lock()
            .get(&(did.to_string(), kid.to_string()))
            .is_some_and(|c| c.other == Some(None) && self.inside_ttl(c.at))
    }

    /// List `did`'s account at the PDS now, however recently it was listed:
    /// this client has just published a device key record of its own, and
    /// the home server's copy may predate it. Then drops the cached answers a
    /// new record can change — a remembered miss, and one the origin server
    /// answered — including any a lookup already running would keep. An
    /// answer found in the records stands. A listing that fails changes
    /// nothing. Never fails.
    pub async fn refresh_account(&self, did: &str) {
        self.load().await;
        if did.starts_with("did:key:") {
            return;
        }
        if let Err(e) = self.list_records_of(did, DEVICE_KEY_TYPE, true).await {
            tracing::debug!(%did, error = %e, "account not listed again");
            return;
        }
        self.refreshed.lock().insert(did.to_string(), Utc::now());
        {
            // Bumped and dropped under one lock, which `settle` holds while
            // it checks the count and writes an answer.
            let mut counts = self.refreshes.lock();
            *counts.entry(did.to_string()).or_default() += 1;
            self.cache.lock().retain(|(held, _), cached| {
                held != did
                    || !matches!(
                        cached.other,
                        Some(None)
                            | Some(Some(FoundKey {
                                source: KeySource::OriginServer,
                                ..
                            }))
                    )
            });
        }
        self.save().await;
    }

    /// When the answer held for `(did, kid)` is a key the origin server
    /// vouched for, take `did`'s records again as any lookup does past the
    /// ttl (`device_records`: through the home server, at most once per DID
    /// per ttl), so a key published since is answered from them; one still
    /// unpublished keeps the server's answer. For a task's opening post,
    /// which only a published key lets name its referee. Never fails.
    pub async fn relist_vouched(&self, did: &str, kid: &str) {
        if !self.holds_origin_answer(did, kid).await {
            return;
        }
        let slot = (did.to_string(), kid.to_string());
        let Some(hit) = self.cache.lock().get(&slot).cloned() else {
            return;
        };
        self.relisted(&slot, did, kid, hit).await;
    }

    /// How long a miss and a listing are held.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many times `refresh_account` has dropped `did`'s answers.
    fn refresh_count(&self, did: &str) -> u64 {
        self.refreshes.lock().get(did).copied().unwrap_or(0)
    }

    /// Hold `entries`, listed at `at`, as `did`'s listing of `collection`
    /// unless a newer one is held; the listing held after, for a lookup to
    /// use. Device records are held as values only, in `records`.
    fn keep_entries(
        &self,
        did: &str,
        collection: &str,
        entries: Vec<RecordEntry>,
        at: DateTime<Utc>,
    ) -> Vec<RecordEntry> {
        if collection == DEVICE_KEY_TYPE {
            let records = values(entries.clone());
            let kept = self.keep_listing(did, records.clone(), at);
            return if kept == records {
                entries
            } else {
                unnamed(kept)
            };
        }
        let mut held = self.other_records.lock();
        let key = (collection.to_string(), did.to_string());
        if let Some((kept, held_at)) = held.get(&key)
            && *held_at > at
        {
            return kept.clone();
        }
        held.insert(key, (entries.clone(), at));
        entries
    }

    /// Hold `records`, listed at `at`, as `did`'s listing unless a newer one
    /// is held; the listing held after, for a lookup to use.
    fn keep_listing(
        &self,
        did: &str,
        records: Vec<serde_json::Value>,
        at: DateTime<Utc>,
    ) -> Vec<serde_json::Value> {
        let mut held = self.records.lock();
        if let Some((kept, held_at)) = held.get(did)
            && *held_at > at
        {
            return kept.clone();
        }
        held.insert(did.to_string(), (records.clone(), at));
        records
    }

    /// A found key's cached answer with the DID's current proven records: the
    /// last listing while inside the ttl, else a new one. The answer held
    /// beside the records (the origin's) stands unless the records now hold
    /// the key. A listing that fails leaves `hit` as it was.
    async fn relisted(&self, slot: &(String, String), did: &str, kid: &str, hit: Cached) -> Cached {
        let Ok(records) = self.device_records(did, kid).await else {
            return hit;
        };
        let other = match device_key_history(did, &records)
            .iter()
            .any(|k| k.kid == kid)
        {
            true => None,
            false => hit.other,
        };
        self.remember(slot.clone(), records, other);
        self.save().await;
        self.cache.lock().get(slot).cloned().unwrap_or(hit)
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
                at: Utc::now(),
            },
        );
    }

    async fn in_document(&self, did: &str, kid: &str) -> Result<Option<[u8; 32]>> {
        let doc = self.reader.resolve_document(did).await?;
        Ok(doc
            .verification_method
            .iter()
            .filter_map(|m| m.public_key_multibase.as_deref().and_then(ed25519_raw))
            .find(|key| derive_kid_bytes(key) == kid))
    }

    /// The key the origin holds for `(did, kid)`, and when it stopped
    /// counting: through the batch key route, or the per-kid route on a
    /// server without it.
    async fn at_origin(
        &self,
        base: &str,
        did: &str,
        kid: &str,
    ) -> Result<Option<([u8; 32], Option<i64>)>> {
        if !self
            .batch_route_missing
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let pair = [(did.to_string(), kid.to_string())];
            if let Some(answered) = self.ask_batch_route(base, &pair).await? {
                return Ok(answered
                    .get(&pair[0])
                    .and_then(|(key, retired_at)| key.map(|key| (key, *retired_at))));
            }
        }
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
        Ok(decode_key(&answer.public_key).map(|key| (key, answer.retired_at())))
    }

    /// What a ruling referee's own site says about its key `kid`: its key
    /// list at `https://<host>/api/v1/signing-keys/<did>`, read whole and
    /// kept for the life of the lookup, as the connected server's key set
    /// is kept for a connection. A kid on the list is answered from it; a
    /// kid not on it reads the list once more, once per kid, and is not
    /// listed if still missing. A read that fails is not kept, unless
    /// `with_cannot_answer_for` says otherwise. One read per referee at a
    /// time; asks meanwhile share it. Never fails.
    pub async fn own_host_answer(&self, did: &str, kid: &str) -> OwnHostAnswer {
        let Some(host) = plain_did_web_host(did) else {
            return OwnHostAnswer::CannotAnswer;
        };
        self.load().await;
        let asked_at = tokio::time::Instant::now();
        loop {
            let (read, started_here) = {
                let mut referees = self.referees.lock();
                if !referees.contains_key(did) {
                    bound_referees(&mut referees, REFEREES_HELD - 1);
                }
                let referee = referees.entry(did.to_string()).or_default();
                referee.used = Some(asked_at);
                if let Some(answer) = self.held_answer(referee, kid) {
                    return answer;
                }
                match &referee.reading {
                    Some(read) => (read.clone(), false),
                    None => {
                        let read = Arc::new(tokio::sync::OnceCell::new());
                        referee.reading = Some(read.clone());
                        (read, true)
                    }
                }
            };
            let read_ok = *read
                .get_or_init(|| async {
                    let keys =
                        tokio::time::timeout(self.own_host_wait, self.read_referee_list(host, did))
                            .await
                            .ok()
                            .flatten();
                    let mut referees = self.referees.lock();
                    let referee = referees.entry(did.to_string()).or_default();
                    referee.reading = None;
                    match keys {
                        Some(keys) => {
                            // A later list's dates win: a key retired since
                            // is learned at the next read.
                            referee.keys.extend(keys);
                            referee.note_read_for(kid.to_string());
                            referee.failed_at = None;
                            true
                        }
                        None => {
                            referee.failed_at = Some(tokio::time::Instant::now());
                            false
                        }
                    }
                })
                .await;
            if !read_ok {
                return OwnHostAnswer::CannotAnswer;
            }
            // A read this ask started, or one for the same kid, has answered
            // it. One that was already under way for another kid may predate
            // the key: the loop reads once more for this one.
            let answer = {
                let mut referees = self.referees.lock();
                let referee = referees.entry(did.to_string()).or_default();
                match self.held_answer(referee, kid) {
                    Some(answer) => Some(answer),
                    None if started_here => {
                        referee.note_read_for(kid.to_string());
                        Some(OwnHostAnswer::NotListed)
                    }
                    None => None,
                }
            };
            if let Some(answer) = answer {
                // Kept with the found keys, under the same write rule.
                self.save().await;
                return answer;
            }
        }
    }

    /// What is held about a referee's key `kid`, without asking: listed or
    /// not listed as its key list last said, cannot answer inside the
    /// `with_cannot_answer_for` window after a failed read and at once for a
    /// name that is not a plain host, else `None`.
    pub fn held_own_host_answer(&self, did: &str, kid: &str) -> Option<OwnHostAnswer> {
        if plain_did_web_host(did).is_none() {
            return Some(OwnHostAnswer::CannotAnswer);
        }
        let referees = self.referees.lock();
        self.held_answer(referees.get(did)?, kid)
    }

    fn held_answer(&self, referee: &RefereeKeys, kid: &str) -> Option<OwnHostAnswer> {
        if let Some((public_key, retired_at)) = referee.keys.get(kid) {
            return Some(OwnHostAnswer::Listed {
                public_key: *public_key,
                retired_at: *retired_at,
            });
        }
        if referee.read_for.iter().any(|read| read == kid) {
            return Some(OwnHostAnswer::NotListed);
        }
        referee
            .failed_at
            .is_some_and(|at| at.elapsed() < self.cannot_answer_for)
            .then_some(OwnHostAnswer::CannotAnswer)
    }

    /// One read of a referee's key list. `None` when the host is, or
    /// resolves to, a private address, the request fails or is refused, or
    /// the body is not a key list.
    async fn read_referee_list(&self, host: &str, did: &str) -> Option<HashMap<String, ListedKey>> {
        #[cfg(any(test, feature = "test-support"))]
        let base = self.own_host_base.as_ref().map(|base| base(host));
        #[cfg(not(any(test, feature = "test-support")))]
        let base: Option<String> = None;
        // The name comes off a line anyone can send: a host that is, or
        // resolves to, a private address is not asked, and the read goes to
        // the addresses checked, following no redirect, as the did:web
        // document read does (`did.rs`).
        let (base, client) = match base {
            Some(base) => (
                base,
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(self.own_host_wait)
                    .build()
                    .ok()?,
            ),
            None => {
                let addrs = crate::ssrf::resolve_and_check(host, 443).await.ok()?;
                let client = crate::ssrf::pinned_client(host, &addrs, self.own_host_wait).ok()?;
                (format!("https://{host}"), client)
            }
        };
        let url = format!("{}/api/v1/signing-keys/{did}", base.trim_end_matches('/'));
        let response = client.get(&url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        key_list(&response.json::<serde_json::Value>().await.ok()?)
    }
}

/// The raw bytes of a base64url key the origin sent. A key that does not
/// decode to 32 bytes is refused like a wrong one.
fn decode_key(public_key: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
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
        created_at: Some(key.created_at.timestamp()),
        // Not filtered by `at`: a caller files the date the key will expire.
        expires_at: Some(key.expires_at.timestamp()),
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Instant;

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
        /// A PDS stub's account repository, whose key signs its proofs.
        repo: Option<Arc<parking_lot::Mutex<crate::test_support::StubRepo>>>,
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
        Stub {
            base,
            hits,
            repo: None,
        }
    }

    /// A PDS for ALICE listing `records` as her device keys, in one page, each
    /// with a repository proof. `hits` counts listings, not proofs.
    async fn pds(records: Vec<serde_json::Value>) -> Stub {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        for record in &records {
            repo.add(DEVICE_KEY_TYPE, record);
        }
        pds_holding(repo).await
    }

    /// A PDS answering from `repo`.
    async fn pds_holding(repo: crate::test_support::StubRepo) -> Stub {
        use axum::response::IntoResponse;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let repo = Arc::new(parking_lot::Mutex::new(repo));
        let answering = repo.clone();
        let router = axum::Router::new().fallback(
            move |uri: axum::http::Uri, Query(q): Query<HashMap<String, String>>| {
                if uri.path() == "/xrpc/com.atproto.repo.listRecords" {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let answer = answering.lock().respond(uri.path(), &q);
                async move {
                    match answer {
                        Some((status, content_type, body)) => (
                            StatusCode::from_u16(status).unwrap(),
                            [("content-type", content_type)],
                            body,
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            },
        );
        let mut stub = serve(router, hits).await;
        stub.repo = Some(repo);
        stub
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

    /// What a fake home server answers with, per route.
    #[derive(Default)]
    struct HomeHits {
        batch: AtomicUsize,
        listing: AtomicUsize,
        proof: AtomicUsize,
    }

    /// A fake home server serving the four record routes from stub
    /// repositories, one per account, counting the requests per route. `down`
    /// makes every route answer 429.
    struct Home {
        base: String,
        hits: Arc<HomeHits>,
        down: Arc<std::sync::atomic::AtomicBool>,
        /// Accounts this server has not seen, so it leaves them out.
        unseen: Arc<parking_lot::Mutex<std::collections::HashSet<String>>>,
        /// The DIDs each batch request named, in the order they arrived.
        batches: Arc<parking_lot::Mutex<Vec<Vec<String>>>>,
        /// Accounts whose proofs this server serves from another repository
        /// for the same DID, so the CAR does not check under the repository
        /// key the account's document names.
        forged: HomeRepos,
        /// Set to answer 404 on every route, as a server with no record cache
        /// does.
        not_found: Arc<std::sync::atomic::AtomicBool>,
        /// The signing keys this server hands out, as the origin route does;
        /// the home server and the origin are one server in production.
        keys: HeldKeys,
        /// Set to serve the first listing (and its `fetched_at`) of each
        /// (DID, collection) again on the batch and listing routes, as a
        /// server cache not yet refreshed does. Proofs still come from the
        /// repository.
        frozen: Arc<std::sync::atomic::AtomicBool>,
        /// How long the batch route waits before answering, in milliseconds.
        batch_delay_ms: Arc<AtomicU64>,
        /// How long the signing-key route waits before answering, in
        /// milliseconds.
        keys_delay_ms: Arc<AtomicU64>,
    }

    impl Home {
        fn counts(&self) -> (usize, usize, usize) {
            (
                self.hits.batch.load(Ordering::SeqCst),
                self.hits.listing.load(Ordering::SeqCst),
                self.hits.proof.load(Ordering::SeqCst),
            )
        }
    }

    type HomeRepos = Arc<parking_lot::Mutex<HashMap<String, crate::test_support::StubRepo>>>;

    /// The listing and the proofs a home server holds for one account, in the
    /// shape `/api/v1/records` answers with.
    fn home_collection(
        repo: &mut crate::test_support::StubRepo,
        collection: &str,
    ) -> Option<serde_json::Value> {
        use base64::engine::general_purpose::STANDARD;
        let query = HashMap::from([
            ("repo".to_string(), repo.did().to_string()),
            ("collection".to_string(), collection.to_string()),
        ]);
        let (_, _, body) = repo.respond("/xrpc/com.atproto.repo.listRecords", &query)?;
        let listed: serde_json::Value = serde_json::from_slice(&body).ok()?;
        let records = listed.get("records")?.as_array()?.clone();
        let mut proofs = Vec::new();
        for entry in &records {
            let uri = entry.get("uri")?.as_str()?;
            let rkey = uri.rsplit('/').next()?.to_string();
            let query = HashMap::from([
                ("did".to_string(), repo.did().to_string()),
                ("collection".to_string(), collection.to_string()),
                ("rkey".to_string(), rkey.clone()),
            ]);
            // The home server serves proofs it checked itself; a stub that
            // cannot serve one just leaves it out, as the server does.
            if let Some((200, _, car)) = repo.respond("/xrpc/com.atproto.sync.getRecord", &query) {
                proofs.push(json!({ "rkey": rkey, "cid": "", "fetched_at": 0, "car": STANDARD.encode(&car) }));
            }
        }
        // A real listing time, as the server sends: a listing dated 1970 is
        // stale the moment it arrives.
        let fetched_at = Utc::now().timestamp();
        Some(
            json!({ "fetched_at": fetched_at, "stale": false, "records": records, "proofs": proofs }),
        )
    }

    /// The first listings served per (DID, collection), for a frozen server.
    type FrozenCopies = Arc<parking_lot::Mutex<HashMap<(String, String), serde_json::Value>>>;

    /// `home_collection`, or while `frozen` is set, the first answer it gave
    /// for this (DID, collection).
    fn served_collection(
        repo: &mut crate::test_support::StubRepo,
        collection: &str,
        frozen: &std::sync::atomic::AtomicBool,
        copies: &FrozenCopies,
    ) -> Option<serde_json::Value> {
        if !frozen.load(Ordering::SeqCst) {
            return home_collection(repo, collection);
        }
        let slot = (repo.did().to_string(), collection.to_string());
        if let Some(copy) = copies.lock().get(&slot) {
            return Some(copy.clone());
        }
        let served = home_collection(repo, collection)?;
        copies.lock().insert(slot, served.clone());
        Some(served)
    }

    /// A home server holding `repos` by DID.
    async fn home(repos: HomeRepos) -> Home {
        use axum::response::IntoResponse;
        let hits = Arc::new(HomeHits::default());
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unseen: Arc<parking_lot::Mutex<std::collections::HashSet<String>>> =
            Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));
        let batches: Arc<parking_lot::Mutex<Vec<Vec<String>>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let forged: HomeRepos = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let not_found = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keys: HeldKeys = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let copies: FrozenCopies = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let batch_delay_ms = Arc::new(AtomicU64::new(0));
        let keys_delay_ms = Arc::new(AtomicU64::new(0));
        let router = axum::Router::new()
            .route(
                "/api/v1/records",
                get({
                    let (repos, hits, down, unseen, batches, forged, not_found) = (
                        repos.clone(),
                        hits.clone(),
                        down.clone(),
                        unseen.clone(),
                        batches.clone(),
                        forged.clone(),
                        not_found.clone(),
                    );
                    let (frozen, copies, delay) =
                        (frozen.clone(), copies.clone(), batch_delay_ms.clone());
                    move |Query(q): Query<HashMap<String, String>>| {
                        hits.batch.fetch_add(1, Ordering::SeqCst);
                        let (repos, down, unseen, batches, forged, not_found) = (
                            repos.clone(),
                            down.clone(),
                            unseen.clone(),
                            batches.clone(),
                            forged.clone(),
                            not_found.clone(),
                        );
                        let (frozen, copies, delay) = (frozen.clone(), copies.clone(), delay.clone());
                        async move {
                            let wait = delay.load(Ordering::SeqCst);
                            if wait > 0 {
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                            }
                            let collection = q.get("collection").cloned().unwrap_or_default();
                            let named: Vec<String> = q
                                .get("dids")
                                .map(|d| d.split(',').map(str::to_string).collect())
                                .unwrap_or_default();
                            batches.lock().push(named.clone());
                            if not_found.load(Ordering::SeqCst) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            if down.load(Ordering::SeqCst) {
                                return StatusCode::TOO_MANY_REQUESTS.into_response();
                            }
                            if named.is_empty() || named.len() > 50 {
                                return StatusCode::BAD_REQUEST.into_response();
                            }
                            let mut held = repos.lock();
                            let mut forged = forged.lock();
                            let withheld = unseen.lock().clone();
                            let accounts: Vec<serde_json::Value> = named
                                .iter()
                                .filter(|did| !withheld.contains(*did))
                                .filter_map(|did| {
                                    // A forged copy stands in for the whole
                                    // account: same records, proofs signed by
                                    // another repository key.
                                    let repo = match forged.get_mut(did) {
                                        Some(repo) => repo,
                                        None => held.get_mut(did)?,
                                    };
                                    let served =
                                        served_collection(repo, &collection, &frozen, &copies)?;
                                    Some(json!({ "did": did, "collections": { &collection: served } }))
                                })
                                .collect();
                            axum::Json(json!({ "accounts": accounts })).into_response()
                        }
                    }
                }),
            )
            .route(
                "/api/v1/records/{did}/{collection}",
                get({
                    let (repos, hits, down, unseen, not_found) = (
                        repos.clone(),
                        hits.clone(),
                        down.clone(),
                        unseen.clone(),
                        not_found.clone(),
                    );
                    let (frozen, copies) = (frozen.clone(), copies.clone());
                    move |Path((did, collection)): Path<(String, String)>| {
                        hits.listing.fetch_add(1, Ordering::SeqCst);
                        let (repos, down, unseen, not_found) =
                            (repos.clone(), down.clone(), unseen.clone(), not_found.clone());
                        let (frozen, copies) = (frozen.clone(), copies.clone());
                        async move {
                            if not_found.load(Ordering::SeqCst) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            if down.load(Ordering::SeqCst) {
                                return StatusCode::TOO_MANY_REQUESTS.into_response();
                            }
                            if unseen.lock().contains(&did) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            let mut held = repos.lock();
                            let Some(repo) = held.get_mut(&did) else {
                                return StatusCode::NOT_FOUND.into_response();
                            };
                            let Some(served) =
                                served_collection(repo, &collection, &frozen, &copies)
                            else {
                                return StatusCode::BAD_GATEWAY.into_response();
                            };
                            axum::Json(json!({
                                "did": did,
                                "collection": collection,
                                "fetched_at": served["fetched_at"],
                                "stale": false,
                                "records": served["records"],
                            }))
                            .into_response()
                        }
                    }
                }),
            )
            .route(
                "/api/v1/records/{did}/{collection}/{rkey}/proof",
                get({
                    let (repos, hits, down, unseen, not_found) = (
                        repos.clone(),
                        hits.clone(),
                        down.clone(),
                        unseen.clone(),
                        not_found.clone(),
                    );
                    move |Path((did, collection, rkey)): Path<(String, String, String)>| {
                        hits.proof.fetch_add(1, Ordering::SeqCst);
                        let (repos, down, unseen, not_found) =
                            (repos.clone(), down.clone(), unseen.clone(), not_found.clone());
                        async move {
                            if not_found.load(Ordering::SeqCst) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            if down.load(Ordering::SeqCst) {
                                return StatusCode::TOO_MANY_REQUESTS.into_response();
                            }
                            if unseen.lock().contains(&did) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            let mut held = repos.lock();
                            let Some(repo) = held.get_mut(&did) else {
                                return StatusCode::NOT_FOUND.into_response();
                            };
                            let query = HashMap::from([
                                ("did".to_string(), did.clone()),
                                ("collection".to_string(), collection),
                                ("rkey".to_string(), rkey),
                            ]);
                            match repo.respond("/xrpc/com.atproto.sync.getRecord", &query) {
                                Some((200, _, car)) => {
                                    ([("content-type", "application/vnd.ipld.car")], car)
                                        .into_response()
                                }
                                _ => StatusCode::NOT_FOUND.into_response(),
                            }
                        }
                    }
                }),
            )
            // The origin's batch key route, from the same keys.
            .route(
                "/api/v1/signing-keys",
                get({
                    let keys = keys.clone();
                    move |Query(q): Query<HashMap<String, String>>| {
                        let held = keys.lock().clone();
                        async move {
                            let found: Vec<serde_json::Value> = q
                                .get("keys")
                                .map(|k| k.split(',').collect::<Vec<_>>())
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|pair| {
                                    let (did, kid) = pair.split_once('/')?;
                                    let key = held.get(&(did.to_string(), kid.to_string()))?;
                                    Some(json!({
                                        "did": did,
                                        "kid": kid,
                                        "public_key": URL_SAFE_NO_PAD.encode(key),
                                    }))
                                })
                                .collect();
                            axum::Json(json!({ "keys": found }))
                        }
                    }
                }),
            )
            // The origin's key route: one server answers both in production.
            .route(
                "/api/v1/signing-keys/{did}/{kid}",
                get({
                    let (keys, delay) = (keys.clone(), keys_delay_ms.clone());
                    move |Path((did, kid)): Path<(String, String)>| {
                        let (keys, delay) = (keys.clone(), delay.clone());
                        async move {
                            let wait = delay.load(Ordering::SeqCst);
                            if wait > 0 {
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                            }
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
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Home {
            base,
            hits,
            down,
            unseen,
            batches,
            forged,
            not_found,
            keys,
            frozen,
            batch_delay_ms,
            keys_delay_ms,
        }
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
        // No retries, unless a test turns them on.
        KeyLookup::new(reader, origin.map(|o| o.base.clone()), ttl).with_retry_delays(Vec::new())
    }

    /// Retries 20, 60 and 150 ms after the first ask.
    fn retrying(
        lookup: KeyLookup<freeq_oauth::SharedClient>,
    ) -> KeyLookup<freeq_oauth::SharedClient> {
        lookup.with_retry_delays(vec![
            Duration::from_millis(20),
            Duration::from_millis(60),
            Duration::from_millis(150),
        ])
    }

    /// ALICE's DID document on `pds`, naming the key that signs its proofs. A
    /// stub with no repository signs nothing, so any key will do.
    fn alice_on(pds: &Stub) -> DidDocument {
        match pds.repo.as_ref() {
            Some(repo) => repo.lock().document(&pds.base),
            None => make_test_did_document_with_pds(
                ALICE,
                &key(50).public_key_multibase(),
                Some(&pds.base),
            ),
        }
    }

    /// A day before one instant fixed for the test run, so records built
    /// twice match and a key made then is live now and for the next 89 days.
    fn recent() -> String {
        static NOW: std::sync::LazyLock<chrono::DateTime<Utc>> = std::sync::LazyLock::new(Utc::now);
        (*NOW - chrono::TimeDelta::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// A key record of ALICE's made a day ago.
    fn device_record(seed: u8) -> serde_json::Value {
        device_record_on(seed, &recent())
    }

    fn device_record_on(seed: u8, created_at: &str) -> serde_json::Value {
        serde_json::to_value(build_device_record(&key(seed), ALICE, created_at, None).unwrap())
            .unwrap()
    }

    /// The dates a key record made at `created_at` gives a found key.
    fn dates_of(created_at: &str) -> FoundKey {
        let made = DateTime::parse_from_rfc3339(created_at)
            .unwrap()
            .with_timezone(&Utc);
        FoundKey {
            public_key: [0; 32],
            source: KeySource::IdentityRecord,
            retired_at: None,
            created_at: Some(made.timestamp()),
            expires_at: Some((made + crate::identity_records::KEY_LIFETIME).timestamp()),
        }
    }

    #[tokio::test]
    async fn the_reader_is_the_one_the_lookup_was_built_with() {
        let doc = make_test_did_document_with_pds(ALICE, &key(1).public_key_multibase(), None);
        let listings = Arc::new(AtomicUsize::new(0));
        let counted = listings.clone();
        let reader = RecordReader::new(
            DidResolver::static_map(HashMap::from([(ALICE.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        )
        .on_listing(move |_, _, _, _| {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let lookup = KeyLookup::new(reader, None, HOUR);
        lookup
            .reader()
            .list_record_entries(ALICE, DEVICE_KEY_TYPE, None)
            .await
            .unwrap();
        assert_eq!(listings.load(Ordering::SeqCst), 1);
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
                ..dates_of(&recent())
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
                created_at: None,
                expires_at: None,
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
                created_at: None,
                expires_at: None,
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

    /// The client's own account right after it publishes a device key: the
    /// listing was taken before the record existed, and the hourly rule would
    /// otherwise hold the miss for an hour.
    #[tokio::test]
    async fn refresh_account_lists_again_and_finds_a_record_published_since() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![]).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(pds.hits(), 1);

        // The record is published while the listing is held.
        pds.repo
            .as_ref()
            .unwrap()
            .lock()
            .add(DEVICE_KEY_TYPE, &device_record(2));
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2)).await.unwrap(),
            None,
            "inside the ttl the miss stands"
        );
        assert_eq!(pds.hits(), 1, "and nothing is listed again");

        keys.refresh_account(ALICE).await;
        assert_eq!(pds.hits(), 2, "the refresh lists the account");
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(pds.hits(), 2, "and the lookup lists nothing more");
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
    async fn a_key_that_appears_at_the_origin_after_the_first_ask_is_found_before_the_ttl() {
        let pds = pds(vec![]).await;
        let held: HeldKeys = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let origin = origin_holding(held.clone()).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_retry_delays(vec![
            Duration::from_millis(200),
            Duration::from_millis(600),
            Duration::from_millis(1500),
        ]);
        let kid = kid_of(2);
        let (found, ()) = tokio::join!(keys.key_for(ALICE, &kid), async {
            while origin.hits() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // Past the first answer, well before the first retry.
            tokio::time::sleep(Duration::from_millis(50)).await;
            held.lock().insert((ALICE.to_string(), kid_of(2)), raw(2));
        });
        assert_eq!(
            found.unwrap().map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(origin.hits(), 2, "found on the first retry");

        // The miss was not remembered: the cache holds the key found.
        held.lock().clear();
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(origin.hits(), 2);
    }

    #[tokio::test]
    async fn a_key_absent_on_every_ask_is_asked_four_times_then_again_only_after_the_ttl() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let keys = retrying(lookup(
            vec![alice_on(&pds)],
            Some(&origin),
            Duration::from_millis(500),
        ));
        let started = Instant::now();
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert_eq!(
            (pds.hits(), origin.hits()),
            (1, 4),
            "one listing; the retries ask the origin only"
        );

        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(
            (pds.hits(), origin.hits()),
            (1, 4),
            "inside the ttl the miss stands"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(
            (pds.hits(), origin.hits()),
            (2, 8),
            "after the ttl, a new lookup with its retries"
        );
    }

    #[tokio::test]
    async fn ten_concurrent_asks_for_one_absent_kid_make_one_round_of_requests() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let keys = Arc::new(retrying(lookup(vec![alice_on(&pds)], Some(&origin), HOUR)));
        let asks: Vec<_> = (0..10)
            .map(|_| {
                let keys = keys.clone();
                tokio::spawn(async move { keys.key_for(ALICE, &kid_of(2)).await.unwrap() })
            })
            .collect();
        for ask in asks {
            assert_eq!(ask.await.unwrap(), None);
        }
        assert_eq!(
            (pds.hits(), origin.hits()),
            (1, 4),
            "one lookup and its retries"
        );
    }

    #[tokio::test]
    async fn fifty_concurrent_asks_for_fifty_kids_of_one_signer_make_one_listing_and_one_proof_per_record()
     {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        let uris: Vec<String> = (1..=5)
            .map(|seed| repo.add(DEVICE_KEY_TYPE, &device_record(seed)))
            .collect();
        let pds = pds_holding(repo).await;
        let origin = origin(vec![]).await;
        let keys = Arc::new(lookup(vec![alice_on(&pds)], Some(&origin), HOUR));
        let proofs = || {
            let repo = pds.repo.as_ref().unwrap().lock();
            uris.iter().map(|uri| repo.proof_reads(uri)).sum::<usize>()
        };
        let asks: Vec<_> = (101..151)
            .map(|seed| {
                let keys = keys.clone();
                tokio::spawn(async move { keys.key_for(ALICE, &kid_of(seed)).await.unwrap() })
            })
            .collect();
        for ask in asks {
            assert_eq!(ask.await.unwrap(), None);
        }
        assert_eq!(
            (pds.hits(), proofs()),
            (1, 5),
            "one listing, one proof per record"
        );

        assert_eq!(keys.key_for(ALICE, &kid_of(151)).await.unwrap(), None);
        assert_eq!(
            (pds.hits(), proofs()),
            (1, 5),
            "a kid the held listing lacks is answered from it inside the ttl"
        );
    }

    #[tokio::test]
    async fn a_kid_the_held_listing_lacks_is_answered_from_it_inside_the_ttl_and_relisted_after() {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        let first = repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let pds = pds_holding(repo).await;
        let origin = origin(vec![]).await;
        // Room for the first lookup's listing and proof on a loaded machine:
        // the held listing has to still be inside the ttl below.
        let keys = lookup(
            vec![alice_on(&pds)],
            Some(&origin),
            Duration::from_millis(400),
        );
        let found = keys.key_for(ALICE, &kid_of(1)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::IdentityRecord));
        assert_eq!(pds.hits(), 1);

        let second = pds
            .repo
            .as_ref()
            .unwrap()
            .lock()
            .add(DEVICE_KEY_TYPE, &device_record(2));
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2)).await.unwrap(),
            None,
            "inside the ttl the held listing stands"
        );
        assert_eq!(
            (pds.hits(), origin.hits()),
            (1, 1),
            "the kid the listing lacks was not listed again"
        );

        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2)).await.unwrap(),
            Some(FoundKey {
                public_key: raw(2),
                source: KeySource::IdentityRecord,
                retired_at: None,
                ..dates_of(&recent())
            })
        );
        let proofs = {
            let repo = pds.repo.as_ref().unwrap().lock();
            (repo.proof_reads(&first), repo.proof_reads(&second))
        };
        assert_eq!(
            (pds.hits(), proofs, origin.hits()),
            (2, (1, 1), 1),
            "one more listing past the ttl, the new record proven"
        );
    }

    #[tokio::test]
    async fn a_kid_the_held_listing_lacks_lists_the_did_again_at_most_once_per_ttl() {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let pds = pds_holding(repo).await;
        let origin = origin(vec![]).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        // The first lookup lists, and that listing is the refresh for the ttl.
        assert!(keys.key_for(ALICE, &kid_of(1)).await.unwrap().is_some());
        assert_eq!(pds.hits(), 1);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(keys.key_for(ALICE, &kid_of(3)).await.unwrap(), None);
        assert_eq!(pds.hits(), 1, "neither kid listed the account again");
    }

    #[tokio::test]
    async fn a_found_key_is_answered_after_the_ttl_with_no_request() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let keys = lookup(
            vec![alice_on(&pds)],
            Some(&origin),
            Duration::from_millis(400),
        );
        let found = keys.key_for(ALICE, &kid_of(2)).await.unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));
        let asked = (pds.hits(), origin.hits());

        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(
            (pds.hits(), origin.hits()),
            asked,
            "a found key does not expire"
        );
    }

    #[tokio::test]
    async fn a_record_keys_account_is_relisted_after_the_ttl_and_a_retirement_lands() {
        use crate::identity_records::build_device_retirement;
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let pds = pds_holding(repo).await;
        let keys = lookup(vec![alice_on(&pds)], None, Duration::from_millis(400));
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1)).await.unwrap().unwrap(),
            FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord,
                retired_at: None,
                ..dates_of(&recent())
            }
        );
        assert_eq!(pds.hits(), 1);

        // Every date from the record's, so the key is live for the whole run.
        let made = DateTime::parse_from_rfc3339(&recent())
            .unwrap()
            .with_timezone(&Utc);
        let retired_at = made + chrono::TimeDelta::hours(12);
        let retirement = serde_json::to_value(
            build_device_retirement(
                &key(1),
                ALICE,
                &kid_of(1),
                &retired_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .unwrap(),
        )
        .unwrap();
        pds.repo
            .as_ref()
            .unwrap()
            .lock()
            .add(DEVICE_KEY_TYPE, &retirement);
        tokio::time::sleep(Duration::from_millis(600)).await;
        let at = made + chrono::TimeDelta::hours(20);
        assert_eq!(
            keys.key_for_at(ALICE, &kid_of(1), at).await.unwrap(),
            Some(FoundKey {
                public_key: raw(1),
                source: KeySource::IdentityRecord,
                retired_at: Some(retired_at.timestamp()),
                ..dates_of(&recent())
            }),
            "the relisting past the ttl brings the retirement"
        );
        assert_eq!(pds.hits(), 2, "one more listing");
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

    /// The defer queue's retry (`freeq-server/src/peer_keys.rs:184`) turns on
    /// this: a forgotten miss must read the records again, not answer from
    /// the listing already held.
    #[tokio::test]
    async fn forgetting_a_miss_lists_the_account_again() {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let pds = pds_holding(repo).await;
        let origin = origin(vec![]).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(pds.hits(), 1);

        // Published after the listing the lookup holds.
        pds.repo
            .as_ref()
            .unwrap()
            .lock()
            .add(DEVICE_KEY_TYPE, &device_record(2));
        keys.forget(ALICE, &kid_of(2));
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(pds.hits(), 2, "the forgotten miss listed the account again");
    }

    /// A caller whose miss was listed just now drops the miss but keeps the
    /// listing: the next lookup answers from it rather than listing again.
    #[tokio::test]
    async fn forgetting_a_miss_while_keeping_the_listing_does_not_list_again() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![]).await;
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert!(keys.holds_miss(ALICE, &kid_of(2)).await);
        keys.forget_with(ALICE, &kid_of(2), false);
        assert!(!keys.holds_miss(ALICE, &kid_of(2)).await);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(
            (pds.hits(), origin.hits()),
            (1, 2),
            "the origin asked again, the account not listed again"
        );
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
        let pds = pds(vec![device_record_on(1, T0), retirement]).await;
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
                ..dates_of(T0)
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
                ..dates_of(T0)
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
        let pds = pds(vec![device_record_on(1, T0), retirement]).await;
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
                ..dates_of(T0)
            })
        );
        assert_eq!(origin.hits(), 0);
    }

    #[tokio::test]
    async fn a_listed_record_the_repository_does_not_hold_is_ignored_and_a_proof_is_fetched_once() {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        let genuine_uri = repo.add(DEVICE_KEY_TYPE, &device_record(1));
        // Signed by its own key, so it passes every record check but the proof.
        repo.add_forged(DEVICE_KEY_TYPE, &device_record(2), &device_record(1));
        let pds = pds_holding(repo).await;
        // A ttl of zero lists the records afresh on every lookup.
        let keys = lookup(vec![alice_on(&pds)], None, Duration::ZERO);
        assert_eq!(keys.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        for _ in 0..3 {
            assert_eq!(
                keys.key_for(ALICE, &kid_of(1))
                    .await
                    .unwrap()
                    .map(|f| f.source),
                Some(KeySource::IdentityRecord)
            );
        }
        assert_eq!(
            pds.repo.as_ref().unwrap().lock().proof_reads(&genuine_uri),
            1
        );
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
                created_at: None,
                expires_at: None,
            })
        );
    }

    /// An origin whose key routes answer with the entries of `keys`, by
    /// (did, kid): each entry's own fields, `public_key` and the dates, as
    /// the server writes them.
    struct KeyServer {
        base: String,
        keys: Arc<parking_lot::Mutex<HashMap<(String, String), serde_json::Value>>>,
        /// Each request, `kid` or `batch`, in the order they arrived.
        asked: Arc<parking_lot::Mutex<Vec<&'static str>>>,
        /// The DID/kid pairs each batch request named.
        batches: Arc<parking_lot::Mutex<Vec<Vec<String>>>>,
        /// Set to answer the batch route with this status.
        batch_status: Arc<parking_lot::Mutex<Option<u16>>>,
    }

    impl KeyServer {
        fn asked(&self) -> Vec<&'static str> {
            self.asked.lock().clone()
        }

        fn hold(&self, did: &str, kid: String, entry: serde_json::Value) {
            self.keys.lock().insert((did.to_string(), kid), entry);
        }
    }

    /// A key as the origin's routes answer with it, with no dates.
    fn key_entry(seed: u8) -> serde_json::Value {
        json!({ "public_key": URL_SAFE_NO_PAD.encode(raw(seed)) })
    }

    async fn key_server() -> KeyServer {
        use axum::response::IntoResponse;
        let keys: Arc<parking_lot::Mutex<HashMap<(String, String), serde_json::Value>>> =
            Default::default();
        let asked: Arc<parking_lot::Mutex<Vec<&'static str>>> = Default::default();
        let batches: Arc<parking_lot::Mutex<Vec<Vec<String>>>> = Default::default();
        let batch_status: Arc<parking_lot::Mutex<Option<u16>>> = Default::default();
        let answer = |keys: &HashMap<(String, String), serde_json::Value>, did: &str, kid: &str| {
            keys.get(&(did.to_string(), kid.to_string())).map(|entry| {
                let mut entry = entry.clone();
                entry["did"] = json!(did);
                entry["kid"] = json!(kid);
                entry
            })
        };
        let router = axum::Router::new()
            .route(
                "/api/v1/signing-keys/{did}/{kid}",
                get({
                    let (keys, asked) = (keys.clone(), asked.clone());
                    move |Path((did, kid)): Path<(String, String)>| {
                        asked.lock().push("kid");
                        let found = answer(&keys.lock(), &did, &kid);
                        async move {
                            match found {
                                Some(entry) => axum::Json(entry).into_response(),
                                None => StatusCode::NOT_FOUND.into_response(),
                            }
                        }
                    }
                }),
            )
            .route(
                "/api/v1/signing-keys",
                get({
                    let (keys, asked, batches, status) = (
                        keys.clone(),
                        asked.clone(),
                        batches.clone(),
                        batch_status.clone(),
                    );
                    move |Query(q): Query<HashMap<String, String>>| {
                        asked.lock().push("batch");
                        let named: Vec<String> = q
                            .get("keys")
                            .map(|k| k.split(',').map(str::to_string).collect())
                            .unwrap_or_default();
                        batches.lock().push(named.clone());
                        let status = *status.lock();
                        let held = keys.lock().clone();
                        async move {
                            if let Some(status) = status {
                                return StatusCode::from_u16(status).unwrap().into_response();
                            }
                            if named.is_empty() || named.len() > 50 {
                                return StatusCode::BAD_REQUEST.into_response();
                            }
                            let found: Vec<serde_json::Value> = named
                                .iter()
                                .filter_map(|pair| {
                                    let (did, kid) = pair.rsplit_once('/')?;
                                    answer(&held, did, kid)
                                })
                                .collect();
                            axum::Json(json!({ "keys": found })).into_response()
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        KeyServer {
            base,
            keys,
            asked,
            batches,
            batch_status,
        }
    }

    /// A lookup for ALICE whose origin is `server`.
    fn lookup_at(pds: &Stub, server: &KeyServer) -> KeyLookup<freeq_oauth::SharedClient> {
        let resolver = DidResolver::static_map(HashMap::from([(ALICE.to_string(), alice_on(pds))]));
        let reader = RecordReader::new(resolver, freeq_oauth::SharedClient(reqwest::Client::new()));
        KeyLookup::new(reader, Some(server.base.clone()), HOUR).with_retry_delays(Vec::new())
    }

    #[tokio::test]
    async fn takes_a_keys_retirement_from_the_earlier_of_its_removal_and_its_expiry() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        let dated = |seed: u8, dates: serde_json::Value| {
            let mut entry = key_entry(seed);
            for (name, date) in dates.as_object().unwrap() {
                entry[name] = date.clone();
            }
            entry
        };
        server.hold(
            ALICE,
            kid_of(2),
            dated(2, json!({ "removed_at": 2_000, "expires_at": 1_000 })),
        );
        server.hold(ALICE, kid_of(3), dated(3, json!({ "removed_at": 2_000 })));
        server.hold(
            ALICE,
            kid_of(4),
            dated(4, json!({ "removed_at": null, "expires_at": null })),
        );
        let keys = lookup_at(&pds, &server);
        let retired = |seed| {
            let keys = &keys;
            async move {
                keys.key_for(ALICE, &kid_of(seed))
                    .await
                    .unwrap()
                    .map(|f| f.retired_at)
            }
        };
        assert_eq!(retired(2).await, Some(Some(1_000)));
        assert_eq!(
            retired(3).await,
            Some(Some(2_000)),
            "an old server sends no expiry"
        );
        assert_eq!(retired(4).await, Some(None));
    }

    #[tokio::test]
    async fn reads_the_origins_dates_leniently() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        let dated = |seed: u8, dates: serde_json::Value| {
            let mut entry = key_entry(seed);
            for (name, date) in dates.as_object().unwrap() {
                entry[name] = date.clone();
            }
            entry
        };
        server.hold(ALICE, kid_of(2), dated(2, json!({})));
        server.hold(
            ALICE,
            kid_of(3),
            dated(
                3,
                json!({ "removed_at": "2026-01-01", "expires_at": 3_000 }),
            ),
        );
        server.hold(ALICE, kid_of(4), dated(4, json!({ "expires_at": 4_000.9 })));
        let keys = lookup_at(&pds, &server);
        let retired = |seed| {
            let keys = &keys;
            async move {
                keys.key_for(ALICE, &kid_of(seed))
                    .await
                    .unwrap()
                    .map(|f| f.retired_at)
            }
        };
        assert_eq!(
            retired(2).await,
            Some(None),
            "neither date: the key does not end"
        );
        assert_eq!(
            retired(3).await,
            Some(Some(3_000)),
            "a date that is not a number counts as absent"
        );
        assert_eq!(
            retired(4).await,
            Some(Some(4_000)),
            "a fractional date, rounded down"
        );
    }

    #[tokio::test]
    async fn prefetches_keys_in_one_request_per_50_and_answers_them_and_their_misses_without_asking_again()
     {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        server.hold(ALICE, kid_of(2), key_entry(2));
        server.hold(WEB_SIGNER, kid_of(3), key_entry(3));
        let keys = lookup_at(&pds, &server);
        let mut pairs = vec![
            KeyPair::new(ALICE, kid_of(2)),
            KeyPair::new(WEB_SIGNER, kid_of(3)),
        ];
        pairs.extend((0..58).map(|i| KeyPair::new(ALICE, format!("absent{i}"))));
        // Alice's records are held, so a key of hers the origin leaves out is
        // a miss.
        keys.proven_device_records(ALICE).await.unwrap();
        let listed = pds.hits();
        keys.prefetch_keys(&pairs).await;
        assert_eq!(server.asked(), vec!["batch", "batch"]);
        let sizes: Vec<usize> = server.batches.lock().iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![50, 10]);

        let then = Utc::now() - chrono::TimeDelta::hours(1);
        assert_eq!(
            keys.key_for_at(ALICE, &kid_of(2), then).await.unwrap(),
            Some(FoundKey {
                public_key: raw(2),
                source: KeySource::OriginServer,
                retired_at: None,
                created_at: None,
                expires_at: None,
            })
        );
        assert_eq!(
            keys.key_for_at(WEB_SIGNER, &kid_of(3), then)
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(keys.key_for_at(ALICE, "absent7", then).await.unwrap(), None);
        assert_eq!(
            server.asked(),
            vec!["batch", "batch"],
            "nothing asked again"
        );
        assert_eq!(pds.hits(), listed, "nor listed again");

        keys.prefetch_keys(&pairs).await;
        assert_eq!(
            server.asked(),
            vec!["batch", "batch"],
            "a second prefetch asks nothing"
        );
    }

    #[tokio::test]
    async fn prefetches_no_key_the_held_records_name() {
        let pds = pds(vec![device_record(1)]).await;
        let server = key_server().await;
        let keys = lookup_at(&pds, &server);
        keys.proven_device_records(ALICE).await.unwrap();
        keys.prefetch_keys(&[KeyPair::new(ALICE, kid_of(1))]).await;
        assert!(server.asked().is_empty());
    }

    #[tokio::test]
    async fn asks_the_per_kid_route_after_a_404_from_the_batch_route_and_the_batch_route_no_more() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        server.hold(ALICE, kid_of(2), key_entry(2));
        server.hold(ALICE, kid_of(3), key_entry(3));
        *server.batch_status.lock() = Some(404);
        let keys = lookup_at(&pds, &server);
        for seed in [2, 3] {
            assert_eq!(
                keys.key_for(ALICE, &kid_of(seed))
                    .await
                    .unwrap()
                    .map(|f| f.source),
                Some(KeySource::OriginServer)
            );
        }
        assert_eq!(server.asked(), vec!["batch", "kid", "kid"]);
        keys.prefetch_keys(&[KeyPair::new(ALICE, kid_of(4))]).await;
        assert_eq!(
            server.asked(),
            vec!["batch", "kid", "kid"],
            "after a 404 the prefetch asks nothing"
        );
    }

    #[tokio::test]
    async fn counts_a_429_or_a_5xx_from_the_batch_route_as_a_failure_not_a_miss() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        server.hold(ALICE, kid_of(2), key_entry(2));
        let keys = lookup_at(&pds, &server);
        keys.proven_device_records(ALICE).await.unwrap();
        for status in [429, 503] {
            *server.batch_status.lock() = Some(status);
            keys.prefetch_keys(&[KeyPair::new(ALICE, kid_of(2))]).await;
        }
        *server.batch_status.lock() = None;
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(server.asked(), vec!["batch", "batch", "batch"]);
    }

    #[tokio::test]
    async fn asks_a_replayed_lines_missing_key_once_and_a_fresh_lines_again_at_each_retry() {
        let pds = pds(vec![]).await;
        let delays = vec![
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
        ];
        let replayed = key_server().await;
        let late = lookup_at(&pds, &replayed).with_retry_delays(delays.clone());
        let hour_ago = Utc::now() - chrono::TimeDelta::hours(1);
        assert_eq!(
            late.key_for_at(ALICE, "gone", hour_ago).await.unwrap(),
            None
        );
        assert_eq!(replayed.asked().len(), 1);

        let fresh = key_server().await;
        let live = lookup_at(&pds, &fresh).with_retry_delays(delays);
        let just_now = Utc::now() - chrono::TimeDelta::seconds(1);
        assert_eq!(
            live.key_for_at(ALICE, "gone", just_now).await.unwrap(),
            None
        );
        assert_eq!(fresh.asked().len(), 4);
    }

    #[tokio::test]
    async fn skips_the_retries_when_asked_to() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        let keys = lookup_at(&pds, &server)
            .with_retry_delays(vec![Duration::from_millis(1), Duration::from_millis(2)]);
        let found = keys
            .key_for_at_with(
                ALICE,
                "gone",
                Utc::now(),
                KeyAsk {
                    retry: false,
                    ..KeyAsk::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(found, None);
        assert_eq!(server.asked().len(), 1, "a fresh line, asked once");
    }

    #[tokio::test]
    async fn keeps_a_miss_in_the_store_so_a_later_lookup_does_not_ask_for_it_inside_the_ttl() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        let store = Arc::new(MemoryKeyLookupStore::default());
        let first = lookup_at(&pds, &server).with_store(store.clone());
        assert_eq!(first.key_for(ALICE, &kid_of(2)).await.unwrap(), None);

        server.hold(ALICE, kid_of(2), key_entry(2));
        first.flush().await;
        let second = lookup_at(&pds, &server).with_store(store);
        assert_eq!(second.key_for(ALICE, &kid_of(2)).await.unwrap(), None);
        assert_eq!(server.asked().len(), 1);
    }

    #[tokio::test]
    async fn two_prefetches_racing_on_one_key_share_one_request() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        server.hold(ALICE, kid_of(2), key_entry(2));
        let keys = lookup_at(&pds, &server);
        let pair = [KeyPair::new(ALICE, kid_of(2))];
        tokio::join!(keys.prefetch_keys(&pair), keys.prefetch_keys(&pair));
        assert_eq!(server.asked(), vec!["batch"]);
    }

    #[tokio::test]
    async fn keeps_a_servers_missing_key_as_a_miss() {
        let pds = pds(vec![]).await;
        let server = key_server().await;
        let keys = lookup_at(&pds, &server);
        keys.prefetch_keys(&[KeyPair::server("did:web:peer.example", kid_of(2))])
            .await;
        assert!(keys.holds_miss("did:web:peer.example", &kid_of(2)).await);
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

    // ─── through the home server ────────────────────────────────────────

    const BOB: &str = "did:plc:bobbobbobbobbobbobbobbob";
    const CAROL: &str = "did:plc:carolcarolcarolcarolcaro";

    /// A device key record for `did`, signed by `seed`'s key.
    fn record_for(did: &str, seed: u8) -> serde_json::Value {
        serde_json::to_value(build_device_record(&key(seed), did, T0, None).unwrap()).unwrap()
    }

    /// Three accounts, each with one device key record, on one PDS stub and
    /// one home server holding copies of all three.
    async fn three_signers() -> (Home, Stub, HomeRepos, Vec<DidDocument>) {
        let pds_hits = Arc::new(AtomicUsize::new(0));
        // One set of repositories behind both stubs: the home server serves a
        // copy of the same repository, so its proofs check under the same
        // repository key the account's document names.
        let repos: HomeRepos = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        for (i, did) in [ALICE, BOB, CAROL].iter().enumerate() {
            let mut repo = crate::test_support::StubRepo::new(did);
            repo.add(DEVICE_KEY_TYPE, &record_for(did, i as u8 + 1));
            repos.lock().insert((*did).to_string(), repo);
        }
        let pds = serve_repos(repos.clone(), pds_hits.clone()).await;
        let docs = [ALICE, BOB, CAROL]
            .iter()
            .map(|did| repos.lock().get(*did).unwrap().document(&pds.base))
            .collect();
        let home = home(repos.clone()).await;
        (home, pds, repos, docs)
    }

    /// A PDS answering for several accounts from `repos`, counting listings.
    async fn serve_repos(repos: HomeRepos, hits: Arc<AtomicUsize>) -> Stub {
        use axum::response::IntoResponse;
        let counter = hits.clone();
        let router = axum::Router::new().fallback(
            move |uri: axum::http::Uri, Query(q): Query<HashMap<String, String>>| {
                if uri.path() == "/xrpc/com.atproto.repo.listRecords" {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let repos = repos.clone();
                let path = uri.path().to_string();
                async move {
                    let did = q.get("repo").or(q.get("did")).cloned().unwrap_or_default();
                    let answer = repos
                        .lock()
                        .get_mut(&did)
                        .and_then(|r| r.respond(&path, &q));
                    match answer {
                        Some((status, content_type, body)) => (
                            StatusCode::from_u16(status).unwrap(),
                            [("content-type", content_type)],
                            body,
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            },
        );
        Stub {
            repo: None,
            ..serve(router, hits).await
        }
    }

    fn lookup_at_home(
        documents: Vec<DidDocument>,
        home: &Home,
    ) -> KeyLookup<freeq_oauth::SharedClient> {
        lookup_at_home_for(documents, home, HOUR)
    }

    /// [`lookup_at_home`] with a ttl of `ttl`.
    fn lookup_at_home_for(
        documents: Vec<DidDocument>,
        home: &Home,
        ttl: Duration,
    ) -> KeyLookup<freeq_oauth::SharedClient> {
        let resolver = DidResolver::static_map(
            documents
                .into_iter()
                .map(|doc| (doc.id.clone(), doc))
                .collect(),
        );
        let reader = RecordReader::new(resolver, freeq_oauth::SharedClient(reqwest::Client::new()));
        KeyLookup::new(reader, Some(home.base.clone()), ttl).with_retry_delays(Vec::new())
    }

    #[tokio::test]
    async fn a_cold_lookup_for_three_signers_makes_one_batch_request_and_no_pds_request() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[ALICE.to_string(), BOB.to_string(), CAROL.to_string()])
            .await;
        for (i, did) in [ALICE, BOB, CAROL].iter().enumerate() {
            assert_eq!(
                keys.key_for(did, &kid_of(i as u8 + 1))
                    .await
                    .unwrap()
                    .map(|f| f.source),
                Some(KeySource::IdentityRecord),
                "{did}"
            );
        }
        assert_eq!(home_server.counts(), (1, 0, 0), "one batch request");
        assert_eq!(pds.hits(), 0, "the PDS was not asked");
    }

    /// The key ALICE publishes after the home server's copy was taken.
    fn publish_alice_4(repos: &HomeRepos) {
        repos
            .lock()
            .get_mut(ALICE)
            .unwrap()
            .add(DEVICE_KEY_TYPE, &record_for(ALICE, 4));
    }

    async fn source_of(keys: &KeyLookup<freeq_oauth::SharedClient>, seed: u8) -> Option<KeySource> {
        keys.key_for(ALICE, &kid_of(seed))
            .await
            .unwrap()
            .map(|f| f.source)
    }

    /// Requests to the home server's batch and listing routes together.
    fn home_listings(home: &Home) -> usize {
        let (batch, listing, _) = home.counts();
        batch + listing
    }

    /// A key held as the origin vouched for it, published since the
    /// account's listing went past the ttl: taking the records again lists
    /// them once, through the home server and not at the PDS, and the key is
    /// then held as found in them.
    #[tokio::test]
    async fn relist_vouched_lists_through_the_home_server_and_finds_a_key_published_since() {
        let (home_server, pds, repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((ALICE.to_string(), kid_of(4)), raw(4));
        let keys = lookup_at_home_for(docs, &home_server, Duration::from_secs(1));
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::OriginServer));
        publish_alice_4(&repos);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let listed = home_listings(&home_server);
        keys.relist_vouched(ALICE, &kid_of(4)).await;
        assert_eq!(home_listings(&home_server), listed + 1, "one listing");
        assert_eq!(pds.hits(), 0, "the PDS was not asked");
        assert!(!keys.holds_origin_answer(ALICE, &kid_of(4)).await);
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
    }

    /// A key held as the origin vouched for it and still unpublished stays
    /// held so after the records are taken again, and they are taken again
    /// at most once per ttl.
    #[tokio::test]
    async fn relist_vouched_keeps_the_origins_key_while_it_is_unpublished() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((ALICE.to_string(), kid_of(4)), raw(4));
        let keys = lookup_at_home_for(docs, &home_server, Duration::from_secs(1));
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::OriginServer));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let listed = home_listings(&home_server);
        keys.relist_vouched(ALICE, &kid_of(4)).await;
        assert_eq!(home_listings(&home_server), listed + 1, "one listing");
        assert!(keys.holds_origin_answer(ALICE, &kid_of(4)).await);
        keys.relist_vouched(ALICE, &kid_of(4)).await;
        assert_eq!(
            home_listings(&home_server),
            listed + 1,
            "none again inside the ttl"
        );
        assert!(keys.holds_origin_answer(ALICE, &kid_of(4)).await);
        assert_eq!(pds.hits(), 0, "the PDS was not asked");
    }

    #[tokio::test]
    async fn refresh_account_lists_the_pds_while_the_home_server_serves_an_older_copy() {
        let (home_server, pds, repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        home_server.frozen.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string()]).await;

        publish_alice_4(&repos);
        keys.refresh_account(ALICE).await;
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
        assert_eq!(pds.hits(), 1, "one listing, at the PDS");
    }

    #[tokio::test]
    async fn refresh_account_replaces_an_origin_answer_in_memory_and_in_the_store() {
        let (home_server, _pds, repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((ALICE.to_string(), kid_of(4)), raw(4));
        let store = Arc::new(MemoryKeyLookupStore::default());
        let keys = lookup_at_home(docs.clone(), &home_server).with_store(store.clone());
        home_server.frozen.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string()]).await;
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::OriginServer));

        publish_alice_4(&repos);
        keys.refresh_account(ALICE).await;
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));

        keys.flush().await;
        let second = lookup_at_home(docs, &home_server).with_store(store);
        assert_eq!(
            source_of(&second, 4).await,
            Some(KeySource::IdentityRecord),
            "the store holds the new answer"
        );
    }

    #[tokio::test]
    async fn a_fresh_listing_is_kept_when_an_older_listing_through_the_home_server_lands_after_it()
    {
        let (home_server, _pds, repos, docs) = three_signers().await;
        home_server.frozen.store(true, Ordering::SeqCst);
        // The server's copy is taken before the publish.
        lookup_at_home(docs.clone(), &home_server)
            .prefetch(&[ALICE.to_string()])
            .await;
        home_server.batch_delay_ms.store(300, Ordering::SeqCst);

        let keys = lookup_at_home(docs, &home_server);
        let alice = [ALICE.to_string()];
        tokio::join!(keys.prefetch(&alice), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            publish_alice_4(&repos);
            keys.refresh_account(ALICE).await;
        });
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
    }

    #[tokio::test]
    async fn an_origin_answer_from_a_lookup_begun_before_refresh_account_is_not_kept() {
        let (home_server, _pds, repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((ALICE.to_string(), kid_of(4)), raw(4));
        let keys = lookup_at_home(docs, &home_server);
        home_server.frozen.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string()]).await;
        home_server.keys_delay_ms.store(300, Ordering::SeqCst);

        let kid = kid_of(4);
        let (first, ()) = tokio::join!(keys.key_for(ALICE, &kid), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            publish_alice_4(&repos);
            keys.refresh_account(ALICE).await;
        });
        first.unwrap();
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
    }

    /// The count check and the write in `settle` are one step: a refresh on
    /// another thread cannot drop the answers between them, so an origin
    /// answer from before the refresh is never kept after it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refresh_on_another_thread_cannot_run_between_the_count_check_and_the_write() {
        let (home_server, _pds, repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((ALICE.to_string(), kid_of(4)), raw(4));
        let keys = Arc::new(lookup_at_home(docs, &home_server));
        home_server.frozen.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string()]).await;

        // Park the lookup where it has checked the count, until the refresh
        // is done or two seconds pass.
        let (parked_tx, parked_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        *keys.before_remember.lock() = Some(Box::new(move || {
            parked_tx.send(()).unwrap();
            tokio::task::block_in_place(|| {
                let _ = done_rx.recv_timeout(Duration::from_secs(2));
            });
        }));
        let first = tokio::spawn({
            let keys = keys.clone();
            async move { keys.key_for(ALICE, &kid_of(4)).await }
        });
        tokio::task::spawn_blocking(move || parked_rx.recv())
            .await
            .unwrap()
            .unwrap();

        publish_alice_4(&repos);
        let refresh = tokio::spawn({
            let keys = keys.clone();
            async move {
                keys.refresh_account(ALICE).await;
                let _ = done_tx.send(());
            }
        });
        first.await.unwrap().unwrap();
        refresh.await.unwrap();

        let kept = keys
            .cache
            .lock()
            .get(&(ALICE.to_string(), kid_of(4)))
            .and_then(|c| c.other)
            .flatten()
            .map(|f| f.source);
        assert_ne!(
            kept,
            Some(KeySource::OriginServer),
            "the origin answer is not kept"
        );
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
    }

    /// A listing the home server's per-DID route serves is dated with the
    /// server's `fetched_at`, so its older copy loses to a PDS listing the
    /// client made since.
    #[tokio::test]
    async fn a_home_listing_after_a_refresh_is_dated_by_the_server_and_does_not_replace_it() {
        let (home_server, _pds, repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        home_server.frozen.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string()]).await;

        publish_alice_4(&repos);
        keys.refresh_account(ALICE).await;
        let listings = home_server.counts().1;
        // A listing held, so this one goes through the per-DID route.
        let listed = keys.proven_device_records(ALICE).await.unwrap();
        assert_eq!(home_server.counts().1, listings + 1, "the per-DID route");
        assert_eq!(listed.len(), 2, "the PDS listing is kept");
        assert_eq!(source_of(&keys, 4).await, Some(KeySource::IdentityRecord));
    }

    #[tokio::test]
    async fn asks_for_no_device_records_of_a_server() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        const PEER: &str = "did:web:peer.example";
        home_server
            .keys
            .lock()
            .insert((PEER.to_string(), kid_of(7)), raw(7));
        let keys = lookup_at_home(docs, &home_server);
        let found = keys
            .key_for_at_with(
                PEER,
                &kid_of(7),
                Utc::now(),
                KeyAsk {
                    retry: false,
                    server: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(found.map(|f| f.source), Some(KeySource::OriginServer));
        assert_eq!(home_server.counts(), (0, 0, 0), "no records asked for");
        assert!(home_server.batches.lock().is_empty());
        assert_eq!(pds.hits(), 0);
    }

    #[tokio::test]
    async fn answers_a_line_during_its_accounts_prefetch_from_that_prefetch_with_no_second_request()
    {
        let (home_server, pds, _repos, docs) = three_signers().await;
        // The batch answer takes a while, so the line arrives while it is out.
        home_server.batch_delay_ms.store(200, Ordering::SeqCst);
        let keys = lookup_at_home(docs, &home_server);
        let signers = [ALICE.to_string(), BOB.to_string()];
        let (_, found) = tokio::join!(keys.prefetch(&signers), async {
            // A live line from Alice while the prefetch is on the wire.
            tokio::time::sleep(Duration::from_millis(50)).await;
            keys.key_for(ALICE, &kid_of(1)).await
        });
        assert_eq!(
            found.unwrap().map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(home_server.counts(), (1, 0, 0), "one batch request");
        assert_eq!(pds.hits(), 0);
    }

    #[tokio::test]
    async fn remembers_no_key_miss_for_an_account_whose_records_the_prefetch_did_not_bring() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        // The home server has not seen Alice: her records are not prefetched,
        // and it holds no key for her either.
        home_server.unseen.lock().insert(ALICE.to_string());
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[ALICE.to_string()]).await;
        keys.prefetch_keys(&[KeyPair::new(ALICE, kid_of(1))]).await;
        // Her line lists her records itself, and finds the key published there.
        let hour_ago = Utc::now() - chrono::TimeDelta::hours(1);
        assert_eq!(
            keys.key_for_at(ALICE, &kid_of(1), hour_ago)
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
    }

    #[tokio::test]
    async fn a_did_key_signer_is_left_out_of_the_batch_and_a_did_web_one_is_asked_for() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[
            ALICE.to_string(),
            "did:key:z6MkExample".to_string(),
            "did:web:irc.example.com".to_string(),
        ])
        .await;
        assert_eq!(
            *home_server.batches.lock(),
            vec![vec![
                ALICE.to_string(),
                "did:web:irc.example.com".to_string()
            ]]
        );
    }

    /// A did:key bot signs with the key its DID names: there is no
    /// repository to list, so the records step must ask nothing anywhere —
    /// the lookup goes straight to the origin.
    #[tokio::test]
    async fn a_did_key_signer_reads_no_records_anywhere() {
        const BOT: &str = "did:key:z6MkExampleBotSigner";
        let (home_server, pds, _repos, docs) = three_signers().await;
        home_server
            .keys
            .lock()
            .insert((BOT.to_string(), kid_of(7)), raw(7));
        let keys = lookup_at_home(docs, &home_server);
        assert_eq!(
            keys.key_for(BOT, &kid_of(7))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(
            home_server.counts(),
            (0, 0, 0),
            "no batch, listing or proof request"
        );
        assert_eq!(pds.hits(), 0, "the PDS was not asked");
    }

    /// A did:key signer's own key is read from its DID: the lookup answers it
    /// with no request and keeps nothing, though the origin holds a copy.
    /// Under any other kid it is asked for as before.
    #[tokio::test]
    async fn a_did_key_signers_own_key_is_read_from_the_did_and_another_kid_asked_for() {
        let bot = format!("did:key:{}", key(7).public_key_multibase());
        let origin = origin(vec![
            (bot.as_str(), kid_of(7), raw(7)),
            (bot.as_str(), kid_of(8), raw(8)),
        ])
        .await;
        let keys = lookup(vec![], Some(&origin), HOUR);
        let own = keys.key_for(&bot, &kid_of(7)).await.unwrap();
        assert_eq!(
            own.map(|f| (f.source, f.public_key)),
            Some((KeySource::DidKey, raw(7)))
        );
        assert_eq!(origin.hits(), 0, "no request");
        assert!(keys.cache.lock().is_empty(), "nothing kept");
        let other = keys.key_for(&bot, &kid_of(8)).await.unwrap();
        assert_eq!(other.map(|f| f.source), Some(KeySource::OriginServer));
        assert_eq!(origin.hits(), 1, "asked as before");
    }

    #[tokio::test]
    async fn a_batch_of_did_key_signers_alone_asks_nothing() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&["did:key:z6MkExample".to_string()]).await;
        assert_eq!(home_server.counts().0, 0, "no batch request");
    }

    #[tokio::test]
    async fn two_prefetches_for_the_same_signers_share_one_batch_request() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        let first = [ALICE.to_string(), BOB.to_string()];
        let second = [BOB.to_string(), ALICE.to_string()];
        tokio::join!(keys.prefetch(&first), keys.prefetch(&second));
        keys.prefetch(&[ALICE.to_string()]).await;
        assert_eq!(home_server.counts().0, 1, "one batch request for the lot");
    }

    #[tokio::test]
    async fn a_prefetch_that_fails_leaves_nothing_in_flight() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        home_server.down.store(true, Ordering::SeqCst);
        keys.prefetch(&[ALICE.to_string(), BOB.to_string()]).await;
        assert_eq!(
            home_server.counts().0,
            1,
            "the request was made and refused"
        );
        assert_eq!(
            keys.prefetching.lock().len(),
            0,
            "a prefetch that served nothing leaves nothing in flight"
        );
    }

    #[tokio::test]
    async fn a_home_proof_that_does_not_check_is_fetched_from_the_pds() {
        let (home_server, _pds, repos, docs) = three_signers().await;
        // The same record under a fresh repository key: same rkey, same CID,
        // a commit signature the account's document does not name. Only the
        // home server serves it, so a proof read on the real repository can
        // only have come from the PDS.
        let mut forged = crate::test_support::StubRepo::new(ALICE);
        forged.add(DEVICE_KEY_TYPE, &record_for(ALICE, 1));
        home_server.forged.lock().insert(ALICE.to_string(), forged);
        let uri = alice_record_uri(&repos);
        assert_eq!(proof_reads(&repos, &uri), 0, "nothing read yet");

        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[ALICE.to_string()]).await;
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord),
            "the key is found"
        );
        assert_eq!(home_server.counts().0, 1, "one batch request");
        assert_eq!(
            proof_reads(&repos, &uri),
            1,
            "the home proof did not check, so the PDS was asked for it"
        );
    }

    /// The `at://` uri of ALICE's one device key record.
    fn alice_record_uri(repos: &HomeRepos) -> String {
        let query = HashMap::from([
            ("repo".to_string(), ALICE.to_string()),
            ("collection".to_string(), DEVICE_KEY_TYPE.to_string()),
        ]);
        let mut held = repos.lock();
        let repo = held.get_mut(ALICE).expect("ALICE is in the repositories");
        let (_, _, body) = repo
            .respond("/xrpc/com.atproto.repo.listRecords", &query)
            .expect("the stub lists records");
        let listed: serde_json::Value = serde_json::from_slice(&body).expect("a listing");
        listed["records"][0]["uri"]
            .as_str()
            .expect("one record with a uri")
            .to_string()
    }

    /// How often the proof for `uri` was asked for on the real repository.
    fn proof_reads(repos: &HomeRepos, uri: &str) -> usize {
        repos
            .lock()
            .get(ALICE)
            .expect("ALICE is in the repositories")
            .proof_reads(uri)
    }

    #[tokio::test]
    async fn a_home_server_answering_404_everywhere_falls_through_to_the_pds() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        home_server.not_found.store(true, Ordering::SeqCst);
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[ALICE.to_string()]).await;
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(pds.hits(), 1, "the listing came from the PDS");
    }

    #[tokio::test]
    async fn fifty_one_signers_go_in_two_batch_requests() {
        let (home_server, _pds, _repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        let dids: Vec<String> = (0..51)
            .map(|i| format!("did:plc:batchfill{i:036}"))
            .collect();
        keys.prefetch(&dids).await;
        let batches = home_server.batches.lock().clone();
        assert_eq!(batches.len(), 2, "two requests");
        assert_eq!(batches[0].len(), 50, "the first names fifty");
        assert_eq!(batches[1].len(), 1, "the second names the fifty-first");
    }

    #[tokio::test]
    async fn a_signer_the_home_server_leaves_out_is_listed_at_the_pds() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        home_server.unseen.lock().insert(CAROL.to_string());
        let keys = lookup_at_home(docs, &home_server);
        keys.prefetch(&[ALICE.to_string(), BOB.to_string(), CAROL.to_string()])
            .await;
        assert_eq!(
            keys.key_for(CAROL, &kid_of(3))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(pds.hits(), 1, "only the account left out was listed");
    }

    #[tokio::test]
    async fn a_home_429_sends_the_lookup_to_the_pds_and_pauses_the_home_server() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        home_server.down.store(true, Ordering::SeqCst);
        let keys = lookup_at_home(docs, &home_server);
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord),
            "the PDS answered"
        );
        let asked = home_server.counts();
        assert_eq!(pds.hits(), 1);

        // Inside the minute the home server is not asked again.
        home_server.down.store(false, Ordering::SeqCst);
        keys.forget(BOB, &kid_of(2));
        let _ = keys.key_for(BOB, &kid_of(2)).await;
        assert_eq!(
            home_server.counts(),
            asked,
            "the paused home server was not asked again"
        );
        assert!(
            keys.reader().paused_until(&home_server.base).is_some(),
            "the home server is paused"
        );
    }

    #[tokio::test]
    async fn the_hourly_relist_is_one_listing_request() {
        let (home_server, pds, _repos, docs) = three_signers().await;
        let resolver =
            DidResolver::static_map(docs.into_iter().map(|doc| (doc.id.clone(), doc)).collect());
        let reader = RecordReader::new(resolver, freeq_oauth::SharedClient(reqwest::Client::new()));
        // The server's listing time is whole seconds, so a listing arrives
        // looking up to a second old; the ttl has to clear that.
        let keys = KeyLookup::new(
            reader,
            Some(home_server.base.clone()),
            Duration::from_millis(1500),
        )
        .with_retry_delays(Vec::new());
        keys.prefetch(&[ALICE.to_string()]).await;
        assert!(keys.key_for(ALICE, &kid_of(1)).await.unwrap().is_some());
        assert_eq!(home_server.counts(), (1, 0, 0));

        tokio::time::sleep(Duration::from_millis(1800)).await;
        assert!(keys.key_for(ALICE, &kid_of(1)).await.unwrap().is_some());
        assert_eq!(
            home_server.counts(),
            (1, 1, 0),
            "the re-list is the listing route, and its proofs are proven already"
        );
        assert_eq!(pds.hits(), 0);
    }

    #[tokio::test]
    async fn the_retirement_closure_check_reads_the_home_routes() {
        use crate::identity_records::build_device_retirement;
        let (home_server, pds, repos, docs) = three_signers().await;
        let retirement = serde_json::to_value(
            build_device_retirement(&key(1), ALICE, &kid_of(1), "2026-03-01T00:00:00Z").unwrap(),
        )
        .unwrap();
        repos
            .lock()
            .get_mut(ALICE)
            .unwrap()
            .add(DEVICE_KEY_TYPE, &retirement);
        let keys = lookup_at_home(docs, &home_server);
        let closure = keys
            .proven_retirement_closure(ALICE, &kid_of(1))
            .await
            .unwrap();
        assert_eq!(closure.len(), 2, "the record and the retirement");
        let (batch, listing, proof) = home_server.counts();
        assert_eq!(
            (batch, listing),
            (0, 1),
            "one listing through the home route"
        );
        assert!(proof > 0, "the closure's proofs came from the home server");
        assert_eq!(pds.hits(), 0);
    }

    // ─── the store ──────────────────────────────────────────────────────

    fn snapshot_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "freeq-key-lookup-{}-{}-{}",
            std::process::id(),
            name,
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("nested").join("key-lookup.json")
    }

    #[tokio::test]
    async fn a_second_lookup_on_the_same_store_answers_a_found_key_with_no_request() {
        let pds = pds(vec![device_record(1)]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let store: Arc<dyn KeyLookupStore> =
            Arc::new(FileKeyLookupStore::new(snapshot_path("found")));
        let doc = alice_on(&pds);

        let first = lookup(vec![doc.clone()], Some(&origin), HOUR).with_store(store.clone());
        assert_eq!(
            first
                .key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord),
            "found in the records"
        );
        assert_eq!(
            first
                .key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer),
            "found at the origin"
        );
        let asked = (pds.hits(), origin.hits());

        first.flush().await;
        let second = lookup(vec![doc], Some(&origin), HOUR).with_store(store);
        assert_eq!(
            second
                .key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
        assert_eq!(
            second
                .key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(
            (pds.hits(), origin.hits()),
            asked,
            "the snapshot answered both"
        );
    }

    #[tokio::test]
    async fn a_snapshot_that_does_not_parse_leaves_the_cache_empty_and_is_overwritten() {
        let path = snapshot_path("garbage");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json at all").unwrap();
        let pds = pds(vec![device_record(1)]).await;
        let store: Arc<dyn KeyLookupStore> = Arc::new(FileKeyLookupStore::new(path.clone()));

        let keys = lookup(vec![alice_on(&pds)], None, HOUR).with_store(store);
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord),
            "the lookup starts empty and reads the PDS"
        );
        assert_eq!(pds.hits(), 1);
        keys.flush().await;
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            serde_json::from_str::<KeyLookupSnapshot>(&written).is_ok(),
            "the next save overwrote it: {written}"
        );
    }

    #[tokio::test]
    async fn a_snapshot_carries_the_proven_records_so_no_proof_is_fetched_again() {
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        let uri = repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let pds = pds_holding(repo).await;
        let store: Arc<dyn KeyLookupStore> =
            Arc::new(FileKeyLookupStore::new(snapshot_path("proofs")));
        let doc = alice_on(&pds);

        let first = lookup(vec![doc.clone()], None, HOUR).with_store(store.clone());
        assert!(first.key_for(ALICE, &kid_of(1)).await.unwrap().is_some());
        let proofs = || pds.repo.as_ref().unwrap().lock().proof_reads(&uri);
        assert_eq!((pds.hits(), proofs()), (1, 1));

        first.flush().await;
        let second = lookup(vec![doc], None, HOUR).with_store(store);
        assert!(second.key_for(ALICE, &kid_of(1)).await.unwrap().is_some());
        assert_eq!(
            (pds.hits(), proofs()),
            (1, 1),
            "neither the listing nor the proof was asked for again"
        );
    }

    /// A store that counts its writes and keeps each one.
    #[derive(Default)]
    struct CountingStore {
        held: MemoryKeyLookupStore,
        writes: parking_lot::Mutex<Vec<String>>,
    }

    impl KeyLookupStore for CountingStore {
        fn load(&self) -> Result<Option<String>> {
            self.held.load()
        }

        fn save(&self, snapshot: &str) -> Result<()> {
            self.writes.lock().push(snapshot.to_string());
            self.held.save(snapshot)
        }
    }

    impl CountingStore {
        fn writes(&self) -> usize {
            self.writes.lock().len()
        }

        fn last(&self) -> KeyLookupSnapshot {
            serde_json::from_str(self.writes.lock().last().expect("a write")).unwrap()
        }
    }

    /// An instant long past, so no miss for a line signed then is retried.
    fn long_ago() -> DateTime<Utc> {
        Utc::now() - chrono::TimeDelta::hours(10)
    }

    #[tokio::test]
    async fn gives_back_the_accounts_answers_listing_times_and_proven_cids_it_saved() {
        let snapshot = KeyLookupSnapshot {
            version: SNAPSHOT_VERSION,
            accounts: vec![
                (ALICE.to_string(), vec![device_record(1)]),
                (BOB.to_string(), vec![]),
            ],
            keys: vec![
                (
                    (ALICE.to_string(), kid_of(1)),
                    CachedKey {
                        other: None,
                        at: 1_000,
                    },
                ),
                (
                    (BOB.to_string(), kid_of(2)),
                    CachedKey {
                        other: Some(Some(FoundKeySnapshot::of(FoundKey {
                            public_key: raw(2),
                            source: KeySource::OriginServer,
                            retired_at: Some(1_780_000_000),
                            created_at: None,
                            expires_at: None,
                        }))),
                        at: 2_000,
                    },
                ),
                (
                    (BOB.to_string(), kid_of(3)),
                    CachedKey {
                        other: Some(None),
                        at: 3_000,
                    },
                ),
            ],
            records: vec![(ALICE.to_string(), 1_000)],
            refreshed: vec![(ALICE.to_string(), 1_000)],
            proven: vec!["bafyreiproven".to_string()],
            referees: Vec::new(),
        };
        let store = FileKeyLookupStore::new(snapshot_path("round-trip"));
        let text = serde_json::to_string(&snapshot).unwrap();
        store.save(&text).unwrap();
        let loaded: KeyLookupSnapshot =
            serde_json::from_str(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(serde_json::to_string(&loaded).unwrap(), text);
        let others: Vec<_> = loaded.keys.iter().map(|(_, k)| k.other.is_some()).collect();
        assert_eq!(
            others,
            vec![false, true, true],
            "a miss comes back a miss, not unasked"
        );
        assert!(matches!(loaded.keys[2].1.other, Some(None)));
    }

    #[tokio::test]
    async fn reads_only_once_a_given_wait_has_settled() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let store = Arc::new(MemoryKeyLookupStore::default());
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let keys = Arc::new(
            lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
                .with_store(store.clone())
                .with_load_after(async move {
                    let _ = wait.await;
                }),
        );
        let asking = tokio::spawn({
            let keys = keys.clone();
            async move { keys.key_for(ALICE, &kid_of(2)).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !asking.is_finished(),
            "nothing is read before the wait settles"
        );

        // What lands meanwhile is what the lookup reads.
        let found = FoundKey {
            public_key: raw(2),
            source: KeySource::OriginServer,
            retired_at: None,
            created_at: None,
            expires_at: None,
        };
        let later = KeyLookupSnapshot {
            version: SNAPSHOT_VERSION,
            keys: vec![(
                (ALICE.to_string(), kid_of(2)),
                CachedKey {
                    other: Some(Some(FoundKeySnapshot::of(found))),
                    at: Utc::now().timestamp_millis(),
                },
            )],
            ..Default::default()
        };
        store.save(&serde_json::to_string(&later).unwrap()).unwrap();
        release.send(()).unwrap();
        assert_eq!(asking.await.unwrap(), Some(found));
        assert_eq!((pds.hits(), origin.hits()), (0, 0), "read from the store");
    }

    #[tokio::test]
    async fn keeps_an_accounts_records_once_however_many_of_its_keys_are_held() {
        let records = vec![device_record(1), device_record(2), device_record(3)];
        let signature = records[0]["bindingSig"].as_str().unwrap().to_string();
        let pds = pds(records).await;
        let store = Arc::new(CountingStore::default());
        let keys = lookup(vec![alice_on(&pds)], None, HOUR).with_store(store.clone());
        for seed in [1, 2, 3] {
            assert_eq!(
                keys.key_for(ALICE, &kid_of(seed))
                    .await
                    .unwrap()
                    .map(|f| f.source),
                Some(KeySource::IdentityRecord)
            );
        }
        keys.flush().await;
        let saved = store.writes.lock().last().unwrap().clone();
        assert_eq!(
            saved.matches(&signature).count(),
            1,
            "the first record, once"
        );
    }

    #[tokio::test]
    async fn writes_the_store_at_most_once_every_two_seconds() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let store = Arc::new(CountingStore::default());
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_store(store.clone());
        for i in 0..10 {
            assert_eq!(
                keys.key_for_at(ALICE, &format!("gone{i}"), long_ago())
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(store.writes(), 1, "ten settles, one write");
        tokio::time::sleep(SAVE_EVERY + Duration::from_millis(300)).await;
        assert_eq!(
            store.writes(),
            2,
            "and one more once two seconds have passed"
        );
        assert_eq!(store.last().keys.len(), 10, "holding all ten");
    }

    #[tokio::test]
    async fn starts_empty_from_a_snapshot_of_the_old_shape() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![(ALICE, kid_of(2), raw(2))]).await;
        let store = Arc::new(MemoryKeyLookupStore::default());
        // Records copied into every key's slot, and no version.
        let old = json!({
            "keys": [[[ALICE, kid_of(2)], {
                "records": [],
                "other": {
                    "publicKey": URL_SAFE_NO_PAD.encode(raw(2)),
                    "source": "OriginServer",
                    "retiredAt": null,
                },
                "at": Utc::now().timestamp_millis(),
            }]],
            "records": [],
            "refreshed": [],
            "proven": [],
        });
        store.save(&old.to_string()).unwrap();
        let keys = lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_store(store);
        assert_eq!(
            keys.key_for(ALICE, &kid_of(2))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::OriginServer)
        );
        assert_eq!(origin.hits(), 1, "asked, not read from the old snapshot");
    }

    #[tokio::test]
    async fn lands_an_old_lookups_held_write_before_a_new_lookups_load_once_flushed_and_writes_nothing_after()
     {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let store = Arc::new(CountingStore::default());
        let old = lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_store(store.clone());
        assert_eq!(
            old.key_for_at(ALICE, "first", long_ago()).await.unwrap(),
            None
        );
        assert_eq!(
            old.key_for_at(ALICE, &kid_of(2), long_ago()).await.unwrap(),
            None
        );
        assert_eq!(store.writes(), 1, "the second write is held");
        old.flush().await;
        assert_eq!(store.writes(), 2);

        let next = lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_store(store.clone());
        let asked = origin.hits();
        assert_eq!(
            next.key_for_at(ALICE, &kid_of(2), long_ago())
                .await
                .unwrap(),
            None
        );
        assert_eq!(origin.hits(), asked, "the held miss came through");

        assert_eq!(
            old.key_for_at(ALICE, "late", long_ago()).await.unwrap(),
            None
        );
        tokio::time::sleep(SAVE_EVERY + Duration::from_millis(300)).await;
        assert_eq!(
            store.writes(),
            2,
            "nothing from the old lookup after its flush"
        );
    }

    /// A lookup set aside without ever loading still holds the flush of the
    /// one before it: flushing it must run that flush too, or the older
    /// lookup's held write lands on its own timer, after the next one read.
    #[tokio::test]
    async fn a_lookup_set_aside_unloaded_passes_on_the_flush_it_was_given() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let store = Arc::new(CountingStore::default());
        let first =
            Arc::new(lookup(vec![alice_on(&pds)], Some(&origin), HOUR).with_store(store.clone()));
        assert_eq!(
            first.key_for_at(ALICE, "first", long_ago()).await.unwrap(),
            None
        );
        assert_eq!(
            first
                .key_for_at(ALICE, &kid_of(2), long_ago())
                .await
                .unwrap(),
            None
        );
        assert_eq!(store.writes(), 1, "the second write is held");

        // Set aside at once, never loaded.
        let second = Arc::new(
            lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
                .with_store(store.clone())
                .with_load_after({
                    let first = first.clone();
                    async move { first.flush().await }
                }),
        );
        let third = lookup(vec![alice_on(&pds)], Some(&origin), HOUR)
            .with_store(store.clone())
            .with_load_after({
                let second = second.clone();
                async move { second.flush().await }
            });
        let asked = origin.hits();
        assert_eq!(
            third
                .key_for_at(ALICE, &kid_of(2), long_ago())
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            origin.hits(),
            asked,
            "the first lookup's held miss was written before the third read"
        );

        assert_eq!(
            first.key_for_at(ALICE, "late", long_ago()).await.unwrap(),
            None
        );
        tokio::time::sleep(SAVE_EVERY + Duration::from_millis(300)).await;
        assert!(
            store.writes.lock().iter().all(|w| !w.contains("late")),
            "nothing from the first lookup after its flush"
        );
    }

    #[tokio::test]
    async fn keeps_a_miss_in_the_store_for_the_ttl_across_a_new_lookup_then_asks_once_more() {
        let pds = pds(vec![]).await;
        let origin = origin(vec![]).await;
        let store = Arc::new(MemoryKeyLookupStore::default());
        let ttl = Duration::from_millis(400);
        let first = lookup(vec![alice_on(&pds)], Some(&origin), ttl).with_store(store.clone());
        assert_eq!(
            first.key_for_at(ALICE, "gone", long_ago()).await.unwrap(),
            None
        );
        assert_eq!(origin.hits(), 1);

        first.flush().await;
        let second = lookup(vec![alice_on(&pds)], Some(&origin), ttl).with_store(store.clone());
        assert_eq!(
            second.key_for_at(ALICE, "gone", long_ago()).await.unwrap(),
            None
        );
        assert_eq!(origin.hits(), 1, "the saved miss answers");

        tokio::time::sleep(Duration::from_millis(600)).await;
        second.flush().await;
        let third = lookup(vec![alice_on(&pds)], Some(&origin), ttl).with_store(store);
        assert_eq!(
            third.key_for_at(ALICE, "gone", long_ago()).await.unwrap(),
            None
        );
        assert_eq!(origin.hits(), 2, "past the ttl, asked once");
    }

    fn agent_claim(bot_seed: u8) -> (String, serde_json::Value) {
        use crate::identity_records::build_agent_record;
        let bot = format!("did:key:{}", key(bot_seed).public_key_multibase());
        let claim = build_agent_record(&key(1), ALICE, &bot, &recent(), None).unwrap();
        (bot, serde_json::to_value(claim).unwrap())
    }

    /// Agent records come through the same read as device records: the
    /// stored read takes the home server's copy, the refresh lists the PDS.
    #[tokio::test]
    async fn refresh_agent_records_lists_the_pds_while_the_home_server_serves_an_older_copy() {
        use crate::identity_records::AGENT_KEY_TYPE;
        let (home_server, _pds, repos, docs) = three_signers().await;
        let keys = lookup_at_home(docs, &home_server);
        home_server.frozen.store(true, Ordering::SeqCst);
        assert!(keys.proven_agent_records(ALICE).await.unwrap().is_empty());

        let (_, claim) = agent_claim(20);
        let uri = repos
            .lock()
            .get_mut(ALICE)
            .unwrap()
            .add(AGENT_KEY_TYPE, &claim);
        assert!(
            keys.proven_agent_records(ALICE).await.unwrap().is_empty(),
            "the home server still serves its old listing"
        );
        let fresh = keys.refresh_agent_records(ALICE).await.unwrap();
        let listed: Vec<(String, serde_json::Value)> =
            fresh.into_iter().map(|e| (e.uri, e.value)).collect();
        assert_eq!(listed, vec![(uri, claim)]);
    }

    /// An agent read never puts agent records where key lookups read device
    /// records.
    #[tokio::test]
    async fn an_agent_read_leaves_the_device_records_as_they_were() {
        use crate::identity_records::AGENT_KEY_TYPE;
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        repo.add(DEVICE_KEY_TYPE, &device_record(1));
        repo.add(AGENT_KEY_TYPE, &agent_claim(20).1);
        let pds = pds_holding(repo).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);

        assert_eq!(keys.refresh_agent_records(ALICE).await.unwrap().len(), 1);
        assert_eq!(
            keys.proven_device_records(ALICE).await.unwrap(),
            vec![device_record(1)],
            "only device records held"
        );
        assert_eq!(
            keys.key_for(ALICE, &kid_of(1))
                .await
                .unwrap()
                .map(|f| f.source),
            Some(KeySource::IdentityRecord)
        );
    }

    /// ALICE's live agent claims named with their records' uris, folded from
    /// what the shared read returns: a claim whose proof fails is left out.
    #[tokio::test]
    async fn live_agent_claims_are_named_with_their_uris_and_an_unproven_one_is_dropped() {
        use crate::identity_records::{AGENT_KEY_TYPE, proven_agent_links};
        let mut repo = crate::test_support::StubRepo::new(ALICE);
        repo.add(DEVICE_KEY_TYPE, &device_record(1));
        let (bot, claim) = agent_claim(20);
        let proven_uri = repo.add(AGENT_KEY_TYPE, &claim);
        // Listed with a proof that holds another record at its path.
        repo.add_forged(AGENT_KEY_TYPE, &agent_claim(21).1, &agent_claim(22).1);
        let pds = pds_holding(repo).await;
        let keys = lookup(vec![alice_on(&pds)], None, HOUR);

        let devices = keys.refresh_device_records(ALICE).await.unwrap();
        let agents = keys.refresh_agent_records(ALICE).await.unwrap();
        let named: Vec<(String, String)> = proven_agent_links(ALICE, &devices, &agents, Utc::now())
            .into_iter()
            .map(|l| (l.link.agent_did, l.uri))
            .collect();
        assert_eq!(named, vec![(bot, proven_uri)]);
    }

    // ── a ruling referee's own key list ───────────────────────────────────
    //
    // A ruling's key counts only when its referee's own site lists it. The
    // list is read whole, kept, and read again only for a kid not on it.

    const REFEREE: &str = "did:web:referee.example";

    /// A referee's site serving its key list at `/api/v1/signing-keys/{did}`
    /// with `body`, or `status` when set, after `delay`; `hits` counts reads.
    struct RefereeSite {
        base: String,
        body: Arc<parking_lot::Mutex<serde_json::Value>>,
        status: Arc<parking_lot::Mutex<Option<u16>>>,
        delay: Arc<parking_lot::Mutex<Duration>>,
        hits: Arc<AtomicUsize>,
    }

    impl RefereeSite {
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        /// List these keys, each `(seed, removed_at, expires_at)`.
        fn list(&self, keys: &[(u8, Option<i64>, Option<i64>)]) {
            let keys: Vec<serde_json::Value> = keys
                .iter()
                .map(|(seed, removed_at, expires_at)| {
                    json!({
                        "kid": kid_of(*seed),
                        "public_key": URL_SAFE_NO_PAD.encode(raw(*seed)),
                        "removed_at": removed_at,
                        "expires_at": expires_at,
                    })
                })
                .collect();
            *self.body.lock() = json!({ "did": REFEREE, "public_key": null, "keys": keys });
        }
    }

    async fn referee_site() -> RefereeSite {
        use axum::response::IntoResponse;
        let body: Arc<parking_lot::Mutex<serde_json::Value>> =
            Arc::new(parking_lot::Mutex::new(json!({ "keys": [] })));
        let status: Arc<parking_lot::Mutex<Option<u16>>> = Default::default();
        let delay: Arc<parking_lot::Mutex<Duration>> = Default::default();
        let hits: Arc<AtomicUsize> = Default::default();
        let router = axum::Router::new().route(
            "/api/v1/signing-keys/{did}",
            get({
                let (body, status, delay, hits) =
                    (body.clone(), status.clone(), delay.clone(), hits.clone());
                move |Path(did): Path<String>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(did, REFEREE, "asked for another DID's list");
                    let (body, status, delay) =
                        (body.lock().clone(), *status.lock(), *delay.lock());
                    async move {
                        tokio::time::sleep(delay).await;
                        match status {
                            Some(status) => StatusCode::from_u16(status).unwrap().into_response(),
                            None => axum::Json(body).into_response(),
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        RefereeSite {
            base,
            body,
            status,
            delay,
            hits,
        }
    }

    /// A lookup whose referee.example key list is `site`'s, with `ttl` for
    /// the general cache.
    fn referee_lookup(site: &RefereeSite, ttl: Duration) -> KeyLookup<freeq_oauth::SharedClient> {
        let reader = RecordReader::new(
            DidResolver::static_map(HashMap::new()),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let base = site.base.clone();
        KeyLookup::new(reader, None, ttl).with_own_host_base(move |host| {
            assert_eq!(host, "referee.example", "asked another host");
            base.clone()
        })
    }

    fn listed(seed: u8, retired_at: Option<i64>) -> OwnHostAnswer {
        OwnHostAnswer::Listed {
            public_key: raw(seed),
            retired_at,
        }
    }

    #[tokio::test]
    async fn a_listed_referee_key_is_kept_and_never_asked_again() {
        let site = referee_site().await;
        site.list(&[(70, None, None)]);
        // The general cache's ttl has no say over a referee's keys.
        let keys = referee_lookup(&site, Duration::from_millis(1));
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(70)).await,
            listed(70, None)
        );
        assert_eq!(site.hits(), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(70)).await,
            listed(70, None)
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(70)),
            Some(listed(70, None))
        );
        assert_eq!(site.hits(), 1, "a listed key is never asked again");
    }

    #[tokio::test]
    async fn a_kid_not_on_file_reads_the_whole_list_once_with_its_retired_keys() {
        let site = referee_site().await;
        site.list(&[
            (71, None, None),
            (72, Some(1_700_000_000), None),
            (73, Some(1_700_000_000), Some(1_650_000_000)),
        ]);
        let keys = referee_lookup(&site, HOUR);
        assert_eq!(keys.held_own_host_answer(REFEREE, &kid_of(71)), None);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, None)
        );
        assert_eq!(site.hits(), 1);
        // The rest of the list came with it, each key with when it stopped
        // counting: the earlier of its removal and its expiry.
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(72)).await,
            listed(72, Some(1_700_000_000))
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(73)),
            Some(listed(73, Some(1_650_000_000)))
        );
        assert_eq!(site.hits(), 1, "one read of the whole list");
    }

    #[tokio::test]
    async fn a_kid_still_missing_after_its_read_is_not_listed_and_not_asked_again() {
        let site = referee_site().await;
        site.list(&[(71, None, None)]);
        let keys = referee_lookup(&site, HOUR);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(74)).await,
            OwnHostAnswer::NotListed
        );
        assert_eq!(site.hits(), 1);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(74)).await,
            OwnHostAnswer::NotListed
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(74)),
            Some(OwnHostAnswer::NotListed)
        );
        assert_eq!(site.hits(), 1, "read once for that kid");
        // Another kid not on file reads the list once more.
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(75)).await,
            OwnHostAnswer::NotListed
        );
        assert_eq!(site.hits(), 2);
    }

    /// The kids a referee's list was read for and lacked are bounded, oldest
    /// out, as the referees themselves are: each one is a ruling naming a
    /// key the list does not hold, so only a misbehaving referee or server
    /// grows them.
    #[tokio::test]
    async fn a_referees_kids_not_found_are_bounded_oldest_out() {
        let site = referee_site().await;
        site.list(&[(71, None, None)]);
        let keys = referee_lookup(&site, HOUR);
        for i in 0..=READ_FOR_HELD {
            assert_eq!(
                keys.own_host_answer(REFEREE, &format!("missing-{i}")).await,
                OwnHostAnswer::NotListed
            );
        }
        assert_eq!(site.hits(), READ_FOR_HELD + 1);
        assert_eq!(
            keys.held_own_host_answer(REFEREE, "missing-0"),
            None,
            "the oldest went"
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &format!("missing-{READ_FOR_HELD}")),
            Some(OwnHostAnswer::NotListed)
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(71)),
            Some(listed(71, None)),
            "a found key is not among them"
        );
    }

    #[tokio::test]
    async fn a_read_for_a_new_kid_learns_a_held_keys_retirement() {
        let site = referee_site().await;
        site.list(&[(71, None, None)]);
        let keys = referee_lookup(&site, HOUR);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, None)
        );
        // The referee retires 71 and rules under 76.
        site.list(&[(71, Some(1_700_000_000), None), (76, None, None)]);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(76)).await,
            listed(76, None)
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(71)),
            Some(listed(71, Some(1_700_000_000)))
        );
        assert_eq!(site.hits(), 2);
    }

    /// A referee's list is kept with the found keys: a lookup built on the
    /// same store answers a listed key, and a kid already read for, with no
    /// read; a snapshot written before lists were kept still loads.
    #[tokio::test]
    async fn a_referees_list_is_kept_in_the_snapshot() {
        let site = referee_site().await;
        site.list(&[(71, Some(1_700_000_000), None)]);
        let store: Arc<dyn KeyLookupStore> = Arc::new(MemoryKeyLookupStore::default());
        let first = referee_lookup(&site, HOUR).with_store(store.clone());
        assert_eq!(
            first.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, Some(1_700_000_000))
        );
        assert_eq!(
            first.own_host_answer(REFEREE, &kid_of(74)).await,
            OwnHostAnswer::NotListed
        );
        first.flush().await;
        assert_eq!(site.hits(), 2);

        let second = referee_lookup(&site, HOUR).with_store(store.clone());
        assert_eq!(
            second.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, Some(1_700_000_000))
        );
        assert_eq!(
            second.own_host_answer(REFEREE, &kid_of(74)).await,
            OwnHostAnswer::NotListed
        );
        assert_eq!(site.hits(), 2, "answered from the snapshot, with no read");

        // Written before lists were kept: no `referees` field.
        let mut old: serde_json::Value =
            serde_json::from_str(&store.load().unwrap().unwrap()).unwrap();
        old.as_object_mut().unwrap().remove("referees");
        let older: Arc<dyn KeyLookupStore> = Arc::new(MemoryKeyLookupStore::default());
        older.save(&old.to_string()).unwrap();
        let third = referee_lookup(&site, HOUR).with_store(older);
        assert_eq!(
            third.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, Some(1_700_000_000))
        );
        assert_eq!(site.hits(), 3, "read again, the old snapshot loading");
    }

    #[tokio::test]
    async fn a_failed_read_cannot_answer_and_the_next_ask_reads_again() {
        let site = referee_site().await;
        let keys = referee_lookup(&site, HOUR);
        for (status, body) in [
            (Some(503), json!({})),
            (Some(404), json!({})),
            (None, json!({ "error": "not a key list" })),
        ] {
            *site.status.lock() = status;
            *site.body.lock() = body;
            let before = site.hits();
            assert_eq!(
                keys.own_host_answer(REFEREE, &kid_of(71)).await,
                OwnHostAnswer::CannotAnswer,
                "{status:?}"
            );
            assert_eq!(
                keys.held_own_host_answer(REFEREE, &kid_of(71)),
                None,
                "not kept"
            );
            assert_eq!(site.hits(), before + 1);
        }
        *site.status.lock() = None;
        site.list(&[(71, None, None)]);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, None)
        );
        assert_eq!(site.hits(), 4, "each ask after a failure read again");
    }

    #[tokio::test]
    async fn a_failed_read_is_not_repeated_inside_the_cannot_answer_window() {
        let site = referee_site().await;
        *site.status.lock() = Some(503);
        let keys = referee_lookup(&site, HOUR).with_cannot_answer_for(Duration::from_millis(300));
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            OwnHostAnswer::CannotAnswer
        );
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            OwnHostAnswer::CannotAnswer
        );
        // The window is the referee's, whichever kid is asked.
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(72)).await,
            OwnHostAnswer::CannotAnswer
        );
        assert_eq!(
            keys.held_own_host_answer(REFEREE, &kid_of(72)),
            Some(OwnHostAnswer::CannotAnswer)
        );
        assert_eq!(site.hits(), 1, "not read again inside the window");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(keys.held_own_host_answer(REFEREE, &kid_of(71)), None);
        *site.status.lock() = None;
        site.list(&[(71, None, None)]);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            listed(71, None)
        );
        assert_eq!(site.hits(), 2, "read again after it");
    }

    #[tokio::test]
    async fn ten_concurrent_asks_make_one_read() {
        let site = referee_site().await;
        site.list(&[(71, None, None)]);
        *site.delay.lock() = Duration::from_millis(100);
        let keys = Arc::new(referee_lookup(&site, HOUR));
        for (kid, answer) in [
            (kid_of(71), listed(71, None)),
            (kid_of(77), OwnHostAnswer::NotListed),
        ] {
            let before = site.hits();
            let asks: Vec<_> = (0..10)
                .map(|_| {
                    let (keys, kid) = (keys.clone(), kid.clone());
                    tokio::spawn(async move { keys.own_host_answer(REFEREE, &kid).await })
                })
                .collect();
            for ask in asks {
                assert_eq!(ask.await.unwrap(), answer);
            }
            assert_eq!(site.hits(), before + 1, "one read for ten asks");
        }
    }

    #[tokio::test]
    async fn concurrent_asks_share_a_failed_read() {
        let site = referee_site().await;
        *site.status.lock() = Some(503);
        *site.delay.lock() = Duration::from_millis(100);
        let keys = Arc::new(referee_lookup(&site, HOUR));
        let asks: Vec<_> = (0..10)
            .map(|_| {
                let keys = keys.clone();
                tokio::spawn(async move { keys.own_host_answer(REFEREE, &kid_of(71)).await })
            })
            .collect();
        for ask in asks {
            assert_eq!(ask.await.unwrap(), OwnHostAnswer::CannotAnswer);
        }
        assert_eq!(site.hits(), 1);
    }

    #[tokio::test]
    async fn an_old_servers_single_key_answer_lists_that_key() {
        let site = referee_site().await;
        *site.body.lock() = json!({
            "did": REFEREE,
            "algorithm": "ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(raw(78)),
            "encoding": "base64url",
            "source": "key-store",
        });
        let keys = referee_lookup(&site, HOUR);
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(78)).await,
            listed(78, None)
        );
    }

    #[tokio::test]
    async fn a_read_that_never_answers_cannot_answer_within_the_wait() {
        let site = referee_site().await;
        *site.delay.lock() = Duration::from_secs(30);
        let keys = referee_lookup(&site, HOUR).with_own_host_wait(Duration::from_millis(200));
        let asked = tokio::time::timeout(
            Duration::from_secs(5),
            keys.own_host_answer(REFEREE, &kid_of(71)),
        )
        .await
        .expect("the read is bounded");
        assert_eq!(asked, OwnHostAnswer::CannotAnswer);
    }

    /// A referee's site answering with a redirect is not followed: the
    /// read is of the site checked, and no other.
    #[tokio::test]
    async fn a_redirect_from_the_referees_site_is_not_followed() {
        let elsewhere = referee_site().await;
        elsewhere.list(&[(71, None, None)]);
        let target = format!("{}/api/v1/signing-keys/{REFEREE}", elsewhere.base);
        let router = axum::Router::new().route(
            "/api/v1/signing-keys/{did}",
            get(move || {
                let target = target.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }),
        );
        let hits: Arc<AtomicUsize> = Default::default();
        let site = serve(router, hits).await;
        let reader = RecordReader::new(
            DidResolver::static_map(HashMap::new()),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let base = site.base.clone();
        let keys = KeyLookup::new(reader, None, HOUR).with_own_host_base(move |_| base.clone());
        assert_eq!(
            keys.own_host_answer(REFEREE, &kid_of(71)).await,
            OwnHostAnswer::CannotAnswer
        );
        assert_eq!(elsewhere.hits(), 0, "the redirect was not followed");
    }

    /// Hands out a plain client and counts every request it is asked for.
    struct CountingClients(Arc<AtomicUsize>);

    impl freeq_oauth::ClientProvider for CountingClients {
        async fn client_for(&self, _url: &str) -> anyhow::Result<reqwest::Client> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(reqwest::Client::new())
        }
    }

    #[tokio::test]
    async fn a_name_that_is_not_a_plain_public_host_asks_nothing() {
        let site = referee_site().await;
        let keys = referee_lookup(&site, HOUR);
        for did in [
            "did:web:referee.example%3A8443",
            "did:web:referee.example:people:bot",
            "did:web:",
            "did:plc:k2n3e2vsihf3farequ44t5j7",
        ] {
            assert_eq!(
                keys.own_host_answer(did, &kid_of(71)).await,
                OwnHostAnswer::CannotAnswer,
                "{did}"
            );
            assert_eq!(
                keys.held_own_host_answer(did, &kid_of(71)),
                Some(OwnHostAnswer::CannotAnswer),
                "{did}"
            );
        }
        assert_eq!(site.hits(), 0);
        // Without the test base, the host is checked before any request.
        let requests: Arc<AtomicUsize> = Default::default();
        let reader = RecordReader::new(
            DidResolver::static_map(HashMap::new()),
            CountingClients(requests.clone()),
        );
        let keys = KeyLookup::new(reader, None, HOUR);
        for did in ["did:web:localhost", "did:web:127.0.0.1", "did:web:10.0.0.1"] {
            assert_eq!(
                keys.own_host_answer(did, &kid_of(71)).await,
                OwnHostAnswer::CannotAnswer,
                "{did}"
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 0, "nothing was asked");
    }

    #[test]
    fn the_referees_held_are_bounded_and_one_being_read_stays() {
        let now = tokio::time::Instant::now();
        let mut held: HashMap<String, RefereeKeys> = HashMap::new();
        for n in 0..10u64 {
            held.insert(
                format!("did:web:r{n}.example"),
                RefereeKeys {
                    used: Some(now - Duration::from_secs(100 - n)),
                    ..Default::default()
                },
            );
        }
        held.get_mut("did:web:r0.example").unwrap().reading =
            Some(Arc::new(tokio::sync::OnceCell::new()));
        bound_referees(&mut held, 5);
        assert_eq!(held.len(), 5);
        assert!(
            held.contains_key("did:web:r0.example"),
            "a read in flight stays"
        );
        for n in 6..10u64 {
            assert!(held.contains_key(&format!("did:web:r{n}.example")));
        }
    }
}
