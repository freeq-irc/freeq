//! Getting the signing key of someone who authenticated to another server.
//!
//! A relayed message is signed by a device this server has never met. The
//! signer's home server already publishes its users' keys — `signing_keys` is
//! kid-addressed and append-only, served at `/api/v1/signing-keys/{did}/{kid}`
//! — so a lookup on miss is all that stands between "we hold a signature we
//! cannot check" and a real verdict.
//!
//! Two rules shape everything here:
//!
//! **A lookup never delays a message.** Chat does not hold an event back to
//! retry verification. The first message from an unknown signer delivers
//! immediately, labeled `unverifiable-unknown-key`; the fetch runs off the
//! delivery path and fills the store, and the signer's next message — and any
//! later re-check of this one, such as `/api/v1/verify/{msgid}` — verifies.
//!
//! **The signer's own publications come first.** The lookup reads the
//! signer's identity records from their PDS (and a did:web signer's own
//! document) through `freeq_sdk::key_lookup`. That address comes from a DID
//! document anyone can write, so those requests go through the SSRF-checked
//! client. Only when the signer publishes no such key are peers asked.
//!
//! **Which peer to ask is operator configuration, not something a peer
//! says.** `--s2s-peer-api <endpoint-id>=<base-url>` maps an S2S peer to the
//! server that vouches for its users. Nothing on the wire names a URL, so no
//! peer can aim this server's outbound requests. A signer with no records
//! whose peer has no entry stays uncheckable, which is honest, and never
//! becomes invalid.
//!
//! Every key is filed with where it came from: `identity-record`,
//! `did-document`, or `origin-server` for a peer's key server.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use freeq_sdk::did::DidResolver;
use freeq_sdk::identity_records::RecordReader;
use freeq_sdk::key_lookup::{KeyLookup, KeySource};

use crate::server::SharedState;

/// A key server that does not answer promptly is treated as unreachable. This
/// runs off the delivery path, so the bound is about not accumulating tasks.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// `(did, kid)` lookups in flight or recently finished without a key.
///
/// Process-static, like the S2S rate limiter: it guards outbound requests, and
/// that concern belongs to the process rather than to any one server state.
static LOOKUPS: LazyLock<Mutex<HashMap<(String, String), Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// How many times the batch key route asked `key_for` about a DID (tests).
#[cfg(test)]
static DOCUMENT_FETCHES: LazyLock<Mutex<HashMap<String, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
pub(crate) fn document_fetches(did: &str) -> usize {
    DOCUMENT_FETCHES.lock().get(did).copied().unwrap_or(0)
}

/// The HTTP clients the record lookup uses: SSRF-checked in the running
/// server, a plain shared client in tests, whose stub servers are on loopback.
pub(crate) enum LookupClients {
    Checked(crate::web::SsrfClients),
    #[cfg(test)]
    Plain(freeq_oauth::SharedClient),
}

impl freeq_oauth::ClientProvider for LookupClients {
    async fn client_for(&self, url: &str) -> anyhow::Result<reqwest::Client> {
        match self {
            LookupClients::Checked(clients) => clients.client_for(url).await,
            #[cfg(test)]
            LookupClients::Plain(clients) => clients.client_for(url).await,
        }
    }
}

/// The record-first key lookup a server state holds: no origin base (peers
/// are asked here, per operator configuration), found keys cached for
/// `ttl_secs`, and every listing and checked proof its reader makes kept in
/// `cache`.
pub(crate) fn key_lookup(
    resolver: DidResolver,
    clients: LookupClients,
    ttl_secs: u64,
    cache: Arc<crate::record_cache::RecordCache>,
) -> KeyLookup<LookupClients> {
    let listed = cache.clone();
    let reader = RecordReader::new(resolver, clients)
        .on_listing(move |did, collection, repo_key, entries| {
            listed.keep_listing(did, collection, repo_key, entries)
        })
        .on_checked_proof(move |did, collection, rkey, cid, repo_key, car| {
            cache.keep_proof(did, collection, rkey, cid, repo_key, car)
        });
    KeyLookup::new(reader, None, Duration::from_secs(ttl_secs))
}

/// The client provider for the running server's record lookups.
pub(crate) fn checked_clients() -> LookupClients {
    LookupClients::Checked(crate::web::SsrfClients {
        timeout: FETCH_TIMEOUT,
    })
}

/// Parse `--s2s-peer-api` entries: `<endpoint-id>=<base-url>`.
///
/// `=` rather than the `:` that `--s2s-peer-trust` uses, because a URL has
/// colons of its own. Entries that are malformed, or name a scheme this does
/// not speak, are dropped with a warning: a typo must not silently become a
/// peer whose messages are all uncheckable *and* whose misconfiguration is
/// invisible.
pub fn parse_peer_api_config(entries: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.split_once('=') {
            Some((peer, base))
                if !peer.trim().is_empty()
                    && (base.starts_with("http://") || base.starts_with("https://")) =>
            {
                map.insert(
                    peer.trim().to_string(),
                    base.trim().trim_end_matches('/').to_string(),
                );
            }
            _ => tracing::warn!(
                entry = %entry,
                "Ignoring --s2s-peer-api entry: expected <endpoint-id>=<http(s)://base>"
            ),
        }
    }
    map
}

/// The key server for a peer, if the operator named one.
fn base_for_origin(state: &Arc<SharedState>, origin: &str) -> Option<String> {
    parse_peer_api_config(&state.config.s2s_peer_api)
        .get(origin)
        .cloned()
}

/// Whether this peer has a key server at all (`--s2s-peer-api`).
///
/// A peer with none can never have its signatures checked here, which is
/// honest for a message — it is labeled and delivered — but decides the fate
/// of a mutation, which is refused when it cannot be checked. The refusal is
/// worth naming the reason for: without this, an operator sees mutations from
/// one peer quietly doing nothing and has no way to tell a forgery from a
/// line missing from the command line.
pub fn has_key_source(state: &Arc<SharedState>, origin: &str) -> bool {
    base_for_origin(state, origin).is_some()
}

/// Look up the key a relayed signature names, without holding anything up.
///
/// Call when a relayed event was uncheckable for want of a key. Returns
/// immediately; at most one request per `(did, kid)` is outstanding, and a
/// lookup that finds nothing is not asked again for `--peer-key-retry-secs`.
pub fn fetch_on_miss(state: &Arc<SharedState>, origin: &str, did: &str, sig_tag: &str) {
    let Ok((kid, _)) = freeq_sdk::sigtag::parse(sig_tag) else {
        return;
    };
    let bases: Vec<String> = base_for_origin(state, origin).into_iter().collect();
    if bases.is_empty() {
        tracing::debug!(
            origin = %origin,
            "No key server configured for this peer (--s2s-peer-api); only the signer's records are asked"
        );
    }
    start_lookup(state, bases, did, kid);
}

/// Ask a peer's key server again for a key that task events are parked on.
///
/// **Which governs: the backoff, not the window.** The remembered-miss window
/// exists so a busy channel does not open a request per message; the defer
/// queue asks at most once per key per backoff step, which is the same job
/// done better, and letting the window veto it would leave a quiet signer's
/// parked events waiting out the queue after their key server came back. So
/// the remembered miss is forgotten here and the lookup runs. Nothing races:
/// a fetch gives up after [`FETCH_TIMEOUT`], well inside the shortest step
/// the backoff ever asks on.
pub fn fetch_again(state: &Arc<SharedState>, origin: &str, did: &str, kid: &str) {
    let bases: Vec<String> = base_for_origin(state, origin).into_iter().collect();
    LOOKUPS.lock().remove(&(did.to_string(), kid.to_string()));
    // The record lookup's remembered miss goes too, so the signer's records
    // are read again rather than answered from the cache.
    state.key_lookup.forget(did, kid);
    start_lookup(state, bases, did, kid);
}

/// Look up a key without knowing which peer the signer belongs to.
///
/// For readers of stored history — `/api/v1/verify/{msgid}` reaches a message
/// long after the link it arrived on, and what is filed alongside it is the
/// origin's display name, not the endpoint id the config is keyed by. Asking
/// every configured peer is safe for the same reason a single answer is: the
/// key id is a hash of the key, so only a server holding the right key can
/// answer the question at all.
pub fn fetch_from_any_peer(state: &Arc<SharedState>, did: &str, sig_tag: &str) {
    let Ok((kid, _)) = freeq_sdk::sigtag::parse(sig_tag) else {
        return;
    };
    let bases: Vec<String> = parse_peer_api_config(&state.config.s2s_peer_api)
        .into_values()
        .collect();
    start_lookup(state, bases, did, kid);
}

/// One lookup for `kid`: the signer's own records first, then `bases` in turn.
fn start_lookup(state: &Arc<SharedState>, bases: Vec<String>, did: &str, kid: &str) {
    let entry = (did.to_string(), kid.to_string());
    {
        // How long a fruitless lookup is remembered: an unreachable key server
        // is asked once a window rather than once per message.
        let retry_after = Duration::from_secs(state.config.peer_key_retry_secs);
        let mut lookups = LOOKUPS.lock();
        lookups.retain(|_, at| at.elapsed() < retry_after);
        if lookups.contains_key(&entry) {
            return;
        }
        lookups.insert(entry.clone(), Instant::now());
    }

    let state = state.clone();
    tokio::spawn(async move {
        let (did, kid) = entry;
        match state.key_lookup.key_for(&did, &kid).await {
            Ok(Some(found)) => {
                file_found(&state, &did, &kid, &found);
                return;
            }
            Ok(None) => {}
            Err(e) => tracing::debug!(
                did = %did, kid = %kid, error = %e,
                "Could not read the signer's own records for this key"
            ),
        }
        for base in &bases {
            match fetch_key(base, &did, &kid).await {
                Ok(peer) => {
                    let dates = peer_copy_dates(
                        &peer,
                        crate::key_expiry::lifetime_secs(&state),
                        answered_by_own_host(base, &did),
                    );
                    key_landed(
                        &state,
                        &did,
                        &kid,
                        &peer.pubkey,
                        "origin-server",
                        dates,
                        None,
                    );
                    return;
                }
                Err(e) => tracing::debug!(
                    did = %did, kid = %kid, base = %base, error = %e,
                    "Could not fetch a signing key here"
                ),
            }
        }
        tracing::debug!(
            did = %did, kid = %kid,
            "No configured peer served this key; the sender's messages stay uncheckable"
        );
    });
}

/// File a key `key_for` found, with the dates and retirement its source
/// gives it.
fn file_found(
    state: &Arc<SharedState>,
    did: &str,
    kid: &str,
    found: &freeq_sdk::key_lookup::FoundKey,
) {
    let source = match found.source {
        KeySource::IdentityRecord => "identity-record",
        KeySource::DidDocument => "did-document",
        KeySource::OriginServer => "origin-server",
    };
    let now = chrono::Utc::now().timestamp();
    let (dates, retired_at) = match found.source {
        // A published key keeps its record's dates. A key the records retire
        // is filed retired, and no peer is then asked for a live copy; one
        // they only let expire is not stamped, since an expiry is not a
        // retirement.
        KeySource::IdentityRecord => (
            KeyDates {
                registered_at: found.created_at.unwrap_or(now),
                expires_at: found.expires_at,
            },
            found
                .retired_at
                .filter(|at| found.expires_at.is_none_or(|exp| *at < exp)),
        ),
        // Its own document's key: its owner rotates it.
        KeySource::DidDocument => (
            KeyDates {
                registered_at: now,
                expires_at: None,
            },
            None,
        ),
        KeySource::OriginServer => (
            KeyDates {
                registered_at: now,
                expires_at: Some(now + crate::key_expiry::lifetime_secs(state)),
            },
            None,
        ),
    };
    key_landed(
        state,
        did,
        kid,
        &found.public_key,
        source,
        dates,
        retired_at,
    );
}

/// Most `did:web:` documents one batch key request fetches.
const MAX_BATCH_FETCHES: usize = 5;

/// For the batch key route: look up `did:web:` keys the database does not
/// hold, the signer's records first and then its own document, and file any
/// found. A pair inside the remembered-miss window is skipped, and each pair
/// asked enters it; at most five are asked, concurrently, all under one
/// [`FETCH_TIMEOUT`]. Returns when they are filed or the time is up.
pub(crate) async fn fetch_missing_server_keys(
    state: &Arc<SharedState>,
    pairs: Vec<(String, String)>,
) {
    let chosen: Vec<(String, String)> = {
        let retry_after = Duration::from_secs(state.config.peer_key_retry_secs);
        let mut lookups = LOOKUPS.lock();
        lookups.retain(|_, at| at.elapsed() < retry_after);
        let mut chosen = Vec::new();
        for pair in pairs {
            if chosen.len() == MAX_BATCH_FETCHES {
                break;
            }
            if lookups.contains_key(&pair) {
                continue;
            }
            lookups.insert(pair.clone(), Instant::now());
            chosen.push(pair);
        }
        chosen
    };
    if chosen.is_empty() {
        return;
    }
    let mut fetches = tokio::task::JoinSet::new();
    for (did, kid) in chosen {
        #[cfg(test)]
        {
            *DOCUMENT_FETCHES.lock().entry(did.clone()).or_default() += 1;
        }
        let state = state.clone();
        fetches.spawn(async move {
            match state.key_lookup.key_for(&did, &kid).await {
                Ok(Some(found)) => file_found(&state, &did, &kid, &found),
                Ok(None) => {}
                Err(e) => tracing::debug!(
                    did = %did, kid = %kid, error = %e,
                    "Could not fetch a server's key from its document"
                ),
            }
        });
    }
    let all = async { while fetches.join_next().await.is_some() {} };
    if tokio::time::timeout(FETCH_TIMEOUT, all).await.is_err() {
        // Dropping the set cancels what is still running; those pairs stay
        // remembered as misses for the window.
        tracing::debug!("A batch key request's document fetches ran out of time");
    }
}

/// When a filed key was first seen and when it expires, unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyDates {
    pub registered_at: i64,
    /// None: the key never expires.
    pub expires_at: Option<i64>,
}

/// File a key that answered a lookup and release what was waiting on it.
pub(crate) fn key_landed(
    state: &Arc<SharedState>,
    did: &str,
    kid: &str,
    pubkey: &[u8; 32],
    source: &str,
    dates: KeyDates,
    retired_at: Option<i64>,
) {
    // Append-only and keyed by (did, kid), the same store a local registration
    // writes to. The kid is a hash of the key bytes, so a fetched key cannot
    // displace a different key already on file under that id.
    state.with_db(|db| {
        db.save_signing_key_from(did, pubkey, source, dates.registered_at, dates.expires_at)
    });
    // Stamped before anything parked on the key is judged against it.
    if let Some(retired_at) = retired_at {
        state.with_db(|db| db.retire_signing_key(did, kid, retired_at));
    }
    LOOKUPS.lock().remove(&(did.to_string(), kid.to_string()));
    tracing::info!(did = %did, kid = %kid, source = %source, "Fetched a signing key");
    // This lookup was started because something could not be checked without
    // the key. Whatever is parked on it can be judged now, which is what makes
    // deferring a delay rather than a loss.
    crate::server::retry_deferred_task_events(state, did, kid);
}

/// The dates a peer's copy of a key is filed with. A key its own did:web host
/// answered never expires. Otherwise an expiry the peer sent, a date or null,
/// is kept as sent: its null is its own exemption, trusted. Without one, the
/// key expires `lifetime` after the peer's `registered_at`, or, from a peer
/// that sends no dates, after now, when this server copied it.
fn peer_copy_dates(peer: &PeerKey, lifetime: i64, own_host: bool) -> KeyDates {
    let now = chrono::Utc::now().timestamp();
    let registered_at = peer.registered_at.unwrap_or(now);
    let expires_at = match peer.expires_at {
        _ if own_host => None,
        Some(sent) => sent,
        None => Some(registered_at + lifetime),
    };
    KeyDates {
        registered_at,
        expires_at,
    }
}

/// Whether the key server at `base` is `did`'s own host: `did` is a
/// `did:web:` name and the base URL's host is the part after `did:web:`,
/// ignoring case. A server's own key, answered by that server, never expires;
/// relayed by any other host, it keeps the lifetime rule.
fn answered_by_own_host(base: &str, did: &str) -> bool {
    let Some(named) = did.strip_prefix("did:web:") else {
        return false;
    };
    url::Url::parse(base)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.eq_ignore_ascii_case(named)))
        .unwrap_or(false)
}

/// A key a peer's key server answered, with the dates it sent.
struct PeerKey {
    pubkey: [u8; 32],
    /// The peer's `registered_at`, if it sent one.
    registered_at: Option<i64>,
    /// The peer's `expires_at`: None when it sent none (a server from before
    /// expiries), `Some(None)` when it sent null (a key it never expires).
    expires_at: Option<Option<i64>>,
}

/// One request to a peer's key server.
///
/// The returned key must hash to the id we asked for. Without that check a
/// key server could answer any request with a key of its choosing and every
/// signature by that key would verify — the kid is what binds the answer to
/// the question.
async fn fetch_key(base: &str, did: &str, kid: &str) -> anyhow::Result<PeerKey> {
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?;
    fetch_key_with(&client, base, did, kid).await
}

/// [`fetch_key`] through a client the caller chose.
async fn fetch_key_with(
    client: &reqwest::Client,
    base: &str,
    did: &str,
    kid: &str,
) -> anyhow::Result<PeerKey> {
    use base64::Engine;

    let url = format!(
        "{base}/api/v1/signing-keys/{}/{}",
        urlencoding::encode(did),
        urlencoding::encode(kid)
    );
    let body: serde_json::Value = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let encoded = body
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("response carries no public_key"))?;
    let bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public_key is not 32 bytes"))?;

    anyhow::ensure!(
        freeq_sdk::sigtag::derive_kid_bytes(&bytes) == kid,
        "key server answered with a key that does not hash to the requested kid"
    );
    Ok(PeerKey {
        pubkey: bytes,
        registered_at: body.get("registered_at").and_then(|v| v.as_i64()),
        // Only a JSON null means "never"; a value that is neither null nor an
        // integer is read as none sent, so the lifetime rule applies.
        expires_at: body.get("expires_at").and_then(|v| {
            if v.is_null() {
                Some(None)
            } else {
                v.as_i64().map(Some)
            }
        }),
    })
}

/// Once at startup, off the startup path: ask each `did:web:` key on file
/// with an expiry, other than this server's own, from its own host, and clear
/// the expiry of every key that host confirms. Copies filed before a server's
/// own key was exempt carry an expiry, and the row does not say which host
/// answered, so the owner is asked again.
pub(crate) async fn confirm_own_host_keys(state: &Arc<SharedState>) {
    let clients = checked_clients();
    confirm_own_host_keys_with(state, &clients, |host| format!("https://{host}")).await;
}

/// [`confirm_own_host_keys`] through `clients`, asking a host's key API at
/// `api_base(host)`.
async fn confirm_own_host_keys_with(
    state: &Arc<SharedState>,
    clients: &LookupClients,
    api_base: impl Fn(&str) -> String,
) {
    let own_did = crate::server::server_did(&state.server_name);
    let keys = state
        .with_db(|db| db.did_web_keys_with_expiry(&own_did))
        .unwrap_or_default();
    for (did, row) in keys {
        match own_host_key(state, clients, &api_base, &did, &row.kid).await {
            Ok(key) if key == row.pubkey => {
                state.with_db(|db| db.set_signing_key_expiry(&did, &row.kid, None));
                tracing::info!(did = %did, kid = %row.kid, "Its own host confirmed a server key; it no longer expires");
            }
            Ok(_) => tracing::info!(
                did = %did, kid = %row.kid,
                "Its own host answered with a different key; the expiry stays"
            ),
            Err(e) => tracing::info!(
                did = %did, kid = %row.kid, error = %e,
                "Its own host did not confirm the key; the expiry stays"
            ),
        }
    }
}

/// The key `did`'s own host gives for `kid`: from its document, else from the
/// key API at that host answering for its own DID.
async fn own_host_key(
    state: &Arc<SharedState>,
    clients: &LookupClients,
    api_base: &impl Fn(&str) -> String,
    did: &str,
    kid: &str,
) -> anyhow::Result<[u8; 32]> {
    use freeq_oauth::ClientProvider;

    let in_document = match state.did_resolver.resolve(did).await {
        Ok(doc) => doc
            .verification_method
            .iter()
            .filter_map(|m| m.public_key_multibase.as_deref())
            .filter_map(|multibase| {
                match freeq_sdk::crypto::PublicKey::from_multibase(multibase).ok()? {
                    freeq_sdk::crypto::PublicKey::Ed25519(key) => Some(*key.as_bytes()),
                    freeq_sdk::crypto::PublicKey::Secp256k1(_) => None,
                }
            })
            .find(|key| freeq_sdk::sigtag::derive_kid_bytes(key) == kid),
        Err(_) => None,
    };
    if let Some(key) = in_document {
        return Ok(key);
    }
    // A path-bearing did:web names no host on its own, so it has no key API.
    let host = did
        .strip_prefix("did:web:")
        .filter(|host| !host.contains(':'))
        .ok_or_else(|| anyhow::anyhow!("not in its document, and it names no host"))?;
    let base = api_base(host);
    let client = clients.client_for(&base).await?;
    Ok(fetch_key_with(&client, &base, did, kid).await?.pubkey)
}

/// A PDS on a loopback port listing `records` as `did`'s device keys, and a
/// resolver whose document for `did` names it.
#[cfg(test)]
pub(crate) async fn stub_pds_resolver(did: &str, records: Vec<serde_json::Value>) -> DidResolver {
    stub_pds_holding(did, Arc::new(Mutex::new(records))).await.0
}

/// [`stub_pds_resolver`] over records a test can change, with a count of the
/// listing requests the stub has answered. Each record is listed with a
/// repository proof signed by the key the document names under `#atproto`;
/// a record pushed after the stub starts is listed from the next request on.
#[cfg(test)]
pub(crate) async fn stub_pds_holding(
    did: &str,
    records: Arc<Mutex<Vec<serde_json::Value>>>,
) -> (DidResolver, Arc<std::sync::atomic::AtomicUsize>) {
    let (resolver, hits, _) = stub_pds_counting(did, records).await;
    (resolver, hits)
}

/// [`stub_pds_holding`], with a count of the record proofs it answered as well.
#[cfg(test)]
pub(crate) async fn stub_pds_counting(
    did: &str,
    records: Arc<Mutex<Vec<serde_json::Value>>>,
) -> (
    DidResolver,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use axum::response::IntoResponse;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    let proofs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let proof_counter = proofs.clone();
    let repo = Arc::new(Mutex::new(freeq_sdk::test_support::StubRepo::new(did)));
    let answering = repo.clone();
    let added = Arc::new(Mutex::new(0usize));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(
        move |uri: axum::http::Uri,
              axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
            {
                let records = records.lock();
                let mut added = added.lock();
                let mut repo = answering.lock();
                for record in &records[*added..] {
                    repo.add(freeq_sdk::identity_records::DEVICE_KEY_TYPE, record);
                }
                *added = records.len();
            }
            if uri.path() == "/xrpc/com.atproto.repo.listRecords" {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            if uri.path() == "/xrpc/com.atproto.sync.getRecord" {
                proof_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let answer = answering.lock().respond(uri.path(), &q);
            async move {
                match answer {
                    Some((status, content_type, body)) => (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        [("content-type", content_type)],
                        body,
                    )
                        .into_response(),
                    None => axum::http::StatusCode::NOT_FOUND.into_response(),
                }
            }
        },
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let doc = repo.lock().document(&base);
    (
        DidResolver::static_map(HashMap::from([(did.to_string(), doc)])),
        hits,
        proofs,
    )
}

/// Whether a `(did, kid)` lookup is currently remembered — in flight, or
/// recently finished without a key.
#[cfg(test)]
pub(crate) fn lookup_pending(did: &str, kid: &str) -> bool {
    LOOKUPS
        .lock()
        .contains_key(&(did.to_string(), kid.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_api_config_parses_pairs_and_drops_junk() {
        let parsed = parse_peer_api_config(&[
            "peer-a=https://irc.example.com".to_string(),
            "peer-b=http://127.0.0.1:8080/".to_string(),
            // Junk: no separator, empty peer, and a scheme we don't speak.
            "peer-c".to_string(),
            "=https://nobody.example".to_string(),
            "peer-d=ftp://files.example".to_string(),
            "  ".to_string(),
        ]);

        assert_eq!(
            parsed.get("peer-a").map(String::as_str),
            Some("https://irc.example.com")
        );
        // The trailing slash is normalized away so path joining stays simple.
        assert_eq!(
            parsed.get("peer-b").map(String::as_str),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(parsed.len(), 2, "malformed entries must not become peers");
    }

    /// A peer with no configured key server still has the signer's own
    /// records to ask. A signer whose DID does not resolve stores nothing, and
    /// the lookup is remembered so the next message does not ask again.
    #[tokio::test]
    async fn an_unconfigured_peer_asks_only_the_signers_records() {
        let did = "did:plc:unconfiguredpeer";
        let state = crate::server::test_state_with_db();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let sig = freeq_sdk::sigtag::sign_canonical("{}", &key);

        fetch_on_miss(&state, "some-unconfigured-peer", did, &sig);
        assert!(lookup_pending(did, &kid));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            state
                .with_db(|db| db.get_signing_key_by_kid(did, &kid))
                .flatten()
                .is_none()
        );
    }

    /// A legacy signature is a bare blob naming no key, so there is nothing to
    /// ask any server for.
    #[tokio::test]
    async fn a_legacy_signature_triggers_no_lookup() {
        let did = "did:plc:legacysigner";
        let state = crate::server::test_state_with_db();
        fetch_on_miss(&state, "peer", did, "bm90LWEtc2lndGFn");
        assert!(
            !LOOKUPS.lock().keys().any(|(d, _)| d == did),
            "a signature naming no key must not queue a lookup"
        );
    }

    // ── against a real key server ────────────────────────────────

    const PEER: &str = "the-other-server";

    /// Serve `state`'s real REST API on an ephemeral port and return its base
    /// URL. The endpoint under test is the one a freeq server already
    /// publishes, so these tests pin the actual interop shape, not a mock of
    /// it.
    async fn serve_api(state: Arc<SharedState>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, crate::web::router(state)).await;
        });
        format!("http://{addr}")
    }

    /// A server that looks to `PEER` for keys.
    fn state_pointed_at(base: &str) -> Arc<SharedState> {
        crate::server::test_state_with_config(crate::config::ServerConfig {
            s2s_peer_api: vec![format!("{PEER}={base}")],
            ..Default::default()
        })
    }

    /// Wait up to a second for `did`'s key to appear in the store. The lookup
    /// is deliberately off the delivery path, so a test observes it landing
    /// rather than being handed it.
    async fn wait_for_key(state: &Arc<SharedState>, did: &str, kid: &str) -> Option<[u8; 32]> {
        for _ in 0..100 {
            if let Some(k) = state
                .with_db(|db| db.get_signing_key_by_kid(did, kid))
                .flatten()
            {
                return Some(k);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    #[tokio::test]
    async fn a_key_is_fetched_from_the_peer_that_serves_it() {
        let did = "did:plc:fetchme";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = *key.verifying_key().as_bytes();
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());

        // The signer's home server, holding the key its user registered.
        let home = crate::server::test_state_with_db();
        home.with_db(|db| db.save_signing_key(did, &pubkey))
            .expect("db present");
        let base = serve_api(home).await;

        // This server, which has never seen the signer.
        let state = state_pointed_at(&base);
        assert!(
            state
                .with_db(|db| db.get_signing_key_by_kid(did, &kid))
                .flatten()
                .is_none()
        );

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );

        assert_eq!(
            wait_for_key(&state, did, &kid).await,
            Some(pubkey),
            "the signer's key must arrive from its own server"
        );
    }

    /// The origin is unreachable. The lookup fails quietly — nothing is
    /// stored, nothing is rejected, and the entry stays remembered so the
    /// next message does not open another connection.
    #[tokio::test]
    async fn an_unreachable_key_server_stores_nothing() {
        let did = "did:plc:unreachable";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());

        // A port nothing is listening on: bind it, learn the number, drop it.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let state = state_pointed_at(&format!("http://127.0.0.1:{dead}"));

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            state
                .with_db(|db| db.get_signing_key_by_kid(did, &kid))
                .flatten()
                .is_none(),
            "an unreachable key server must leave the store untouched"
        );
        assert!(
            lookup_pending(did, &kid),
            "a failed lookup stays remembered, so the next message does not retry immediately"
        );
    }

    /// A signer whose home server has no such key: a 404 is an answer, and it
    /// means the signature stays uncheckable rather than becoming invalid.
    #[tokio::test]
    async fn a_key_the_peer_does_not_have_stores_nothing() {
        let did = "did:plc:notthere";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());

        let base = serve_api(crate::server::test_state_with_db()).await;
        let state = state_pointed_at(&base);

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            state
                .with_db(|db| db.get_signing_key_by_kid(did, &kid))
                .flatten()
                .is_none()
        );
    }

    /// Several messages from the same unknown signer ask once. Without this
    /// a busy channel would open a request per message.
    #[tokio::test]
    async fn repeated_misses_ask_the_peer_once() {
        let did = "did:plc:askonce";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let sig = freeq_sdk::sigtag::sign_canonical("{}", &key);

        // A counting stand-in for a key server: every request increments, and
        // none of them answer with a key, so the entry stays remembered.
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/api/v1/signing-keys/{did}/{kid}",
                axum::routing::get(move || {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { axum::http::StatusCode::NOT_FOUND }
                }),
            );
            let _ = axum::serve(listener, app).await;
        });
        let state = state_pointed_at(&format!("http://{addr}"));

        for _ in 0..5 {
            fetch_on_miss(&state, PEER, did, &sig);
        }

        // Wait for the single lookup to land rather than assuming a fixed
        // round-trip time. The property under test is "exactly one lookup",
        // not "within 300 ms": a cold client on a loaded box can take well
        // over a few hundred milliseconds to complete the request, and a
        // fixed sleep as the only sync point makes this test flaky there
        // (same bounded-wait idiom as wait_for_key above).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while hits.load(std::sync::atomic::Ordering::SeqCst) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "five messages from one unknown signer must produce one lookup"
        );
        assert!(lookup_pending(did, &kid));
    }

    /// A reader who knows only the DID — not which peer the signer belongs to
    /// — still gets the key, because every configured peer is asked and only
    /// one can answer with a key that hashes to the id.
    #[tokio::test]
    async fn a_lookup_without_an_origin_asks_every_configured_peer() {
        let did = "did:plc:anypeer";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = *key.verifying_key().as_bytes();
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());

        let holder = crate::server::test_state_with_db();
        holder
            .with_db(|db| db.save_signing_key(did, &pubkey))
            .expect("db present");
        let holder_base = serve_api(holder).await;
        // An unrelated peer, listed first, that has never heard of this DID.
        let stranger_base = serve_api(crate::server::test_state_with_db()).await;

        let state = crate::server::test_state_with_config(crate::config::ServerConfig {
            s2s_peer_api: vec![
                format!("peer-stranger={stranger_base}"),
                format!("peer-holder={holder_base}"),
            ],
            ..Default::default()
        });

        fetch_from_any_peer(&state, did, &freeq_sdk::sigtag::sign_canonical("{}", &key));

        assert_eq!(wait_for_key(&state, did, &kid).await, Some(pubkey));
    }

    /// A key server that answers with a key other than the one asked for.
    /// The key id is a hash of the key, so the answer is checked against the
    /// question and a substituted key never reaches the store.
    #[tokio::test]
    async fn a_key_that_does_not_hash_to_the_requested_id_is_refused() {
        let did = "did:plc:substituted";
        let wanted = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&wanted.verifying_key());
        // What the liar serves instead.
        let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let other_pub = *other.verifying_key().as_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other_pub);
            let app = axum::Router::new().route(
                "/api/v1/signing-keys/{did}/{kid}",
                axum::routing::get(move || {
                    let encoded = encoded.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "public_key": encoded,
                            "algorithm": "ed25519",
                        }))
                    }
                }),
            );
            let _ = axum::serve(listener, app).await;
        });
        let state = state_pointed_at(&format!("http://{addr}"));

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &wanted),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            state
                .with_db(|db| db.get_signing_key_by_kid(did, &kid))
                .flatten()
                .is_none(),
            "a key that does not hash to the requested id must be refused"
        );
    }

    // ── the signer's own records, before any peer ─────────────────

    /// A key server on a loopback port that counts its requests and answers
    /// every one with `key`, or 404 without one.
    async fn counting_key_server(
        key: Option<[u8; 32]>,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use base64::Engine;
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/api/v1/signing-keys/{did}/{kid}",
            axum::routing::get(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    let key = key.ok_or(axum::http::StatusCode::NOT_FOUND)?;
                    Ok::<_, axum::http::StatusCode>(axum::Json(serde_json::json!({
                        "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
                        "algorithm": "ed25519",
                    })))
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), hits)
    }

    /// A server that looks to `PEER` at `base` for keys and resolves DIDs
    /// through `resolver`.
    fn state_with(base: &str, resolver: freeq_sdk::did::DidResolver) -> Arc<SharedState> {
        crate::server::test_state_with_resolver(
            crate::config::ServerConfig {
                s2s_peer_api: vec![format!("{PEER}={base}")],
                ..Default::default()
            },
            resolver,
        )
    }

    fn device_record(did: &str, key: &ed25519_dalek::SigningKey) -> serde_json::Value {
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&key.to_bytes()).unwrap();
        let record = freeq_sdk::identity_records::build_device_record(
            &key,
            did,
            "2026-01-01T00:00:00Z",
            None,
        )
        .unwrap();
        serde_json::to_value(record).unwrap()
    }

    fn source_of(state: &Arc<SharedState>, did: &str, kid: &str) -> Option<String> {
        state
            .with_db(|db| db.get_signing_key_row(did, kid))
            .flatten()
            .and_then(|row| row.source)
    }

    #[tokio::test]
    async fn a_key_in_the_signers_records_is_used_before_any_peer() {
        let did = "did:plc:recordfirst";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let resolver = stub_pds_resolver(did, vec![device_record(did, &key)]).await;
        let (base, peer_hits) = counting_key_server(Some(*key.verifying_key().as_bytes())).await;
        let state = state_with(&base, resolver);

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );

        assert_eq!(
            wait_for_key(&state, did, &kid).await,
            Some(*key.verifying_key().as_bytes())
        );
        assert_eq!(
            source_of(&state, did, &kid).as_deref(),
            Some("identity-record")
        );
        assert_eq!(peer_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_key_the_signers_records_retire_is_filed_retired_and_no_peer_is_asked() {
        let did = "did:plc:recordretired";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let signer = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&key.to_bytes()).unwrap();
        let retirement = serde_json::to_value(
            freeq_sdk::identity_records::build_device_retirement(
                &signer,
                did,
                &kid,
                "2026-03-01T00:00:00Z",
            )
            .unwrap(),
        )
        .unwrap();
        let resolver = stub_pds_resolver(did, vec![device_record(did, &key), retirement]).await;
        // A peer that still serves the key, knowing nothing of the retirement.
        let (base, peer_hits) = counting_key_server(Some(*key.verifying_key().as_bytes())).await;
        let state = state_with(&base, resolver);

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );

        assert!(wait_for_key(&state, did, &kid).await.is_some());
        let retired_at = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .timestamp();
        let mut removed_at = None;
        for _ in 0..100 {
            removed_at = state
                .with_db(|db| db.get_signing_key_row(did, &kid))
                .flatten()
                .and_then(|row| row.removed_at);
            if removed_at.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(removed_at, Some(retired_at), "the key is filed retired");
        assert_eq!(peer_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_signer_with_no_records_is_looked_up_at_its_peer() {
        let did = "did:plc:norecords";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let resolver = stub_pds_resolver(did, vec![]).await;
        let (base, peer_hits) = counting_key_server(Some(*key.verifying_key().as_bytes())).await;
        let state = state_with(&base, resolver);

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );

        assert!(wait_for_key(&state, did, &kid).await.is_some());
        assert_eq!(
            source_of(&state, did, &kid).as_deref(),
            Some("origin-server")
        );
        assert_eq!(peer_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A did:web signer, such as a peer server, whose own document carries its
    /// key under `#freeq`, the way a freeq server publishes its receipt key.
    /// Found there with no peer base configured.
    #[tokio::test]
    async fn a_did_web_signers_key_comes_from_its_own_document() {
        let did = "did:web:peer-server.example";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let key_id = format!("{did}#freeq");
        let doc = freeq_sdk::did::DidDocument {
            id: did.to_string(),
            also_known_as: vec![],
            verification_method: vec![freeq_sdk::did::VerificationMethod {
                id: key_id.clone(),
                method_type: "Multikey".to_string(),
                controller: did.to_string(),
                public_key_multibase: Some(
                    freeq_sdk::crypto::PublicKey::Ed25519(key.verifying_key()).to_multibase(),
                ),
            }],
            authentication: vec![],
            assertion_method: vec![freeq_sdk::did::StringOrMap::Reference(key_id)],
            service: vec![],
        };
        let resolver =
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(did.to_string(), doc)]));
        let state = crate::server::test_state_with_resolver(
            crate::config::ServerConfig::default(),
            resolver,
        );

        // Signed the way a server signs a receipt: a canonical document under its key.
        let receipt = r#"{"did":"did:web:peer-server.example","kind":"receipt"}"#;
        fetch_on_miss(
            &state,
            "a-peer-server",
            did,
            &freeq_sdk::sigtag::sign_canonical(receipt, &key),
        );

        assert_eq!(
            wait_for_key(&state, did, &kid).await,
            Some(*key.verifying_key().as_bytes())
        );
        assert_eq!(
            source_of(&state, did, &kid).as_deref(),
            Some("did-document")
        );
        // Another server's own key: its owner rotates it, so it never expires.
        let row = state
            .with_db(|db| db.get_signing_key_row(did, &kid))
            .flatten()
            .unwrap();
        assert_eq!(row.expires_at, None);
    }

    /// A parked event's retry reads the signer's records again, even inside
    /// the window the lookup remembers a miss for.
    #[tokio::test]
    async fn a_retry_reads_the_signers_records_again() {
        let did = "did:plc:recordlater";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let records = Arc::new(Mutex::new(Vec::new()));
        let (resolver, pds_hits) = stub_pds_holding(did, records.clone()).await;
        let state = crate::server::test_state_with_resolver(
            crate::config::ServerConfig::default(),
            resolver,
        );

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );
        // The first lookup finds no record and remembers the miss.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while pds_hits.load(std::sync::atomic::Ordering::SeqCst) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(state.key_lookup.key_for(did, &kid).await.unwrap().is_none());
        assert_eq!(
            pds_hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the miss is remembered"
        );

        records.lock().push(device_record(did, &key));
        fetch_again(&state, PEER, did, &kid);

        assert_eq!(
            wait_for_key(&state, did, &kid).await,
            Some(*key.verifying_key().as_bytes())
        );
        assert_eq!(
            source_of(&state, did, &kid).as_deref(),
            Some("identity-record")
        );
        assert_eq!(pds_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_record_whose_key_does_not_hash_to_the_kid_is_ignored() {
        let did = "did:plc:wrongrecord";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        // A record naming this kid but carrying another key, signed by it.
        let other = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[8u8; 32]).unwrap();
        let mut record = freeq_sdk::identity_records::build_device_record(
            &other,
            did,
            "2026-01-01T00:00:00Z",
            None,
        )
        .unwrap();
        record.kid = kid.clone();
        record.binding_sig =
            other.sign_base64url(&freeq_sdk::identity_records::record_signed_bytes(&record));
        let resolver = stub_pds_resolver(did, vec![serde_json::to_value(record).unwrap()]).await;
        let (base, peer_hits) = counting_key_server(Some(*key.verifying_key().as_bytes())).await;
        let state = state_with(&base, resolver);

        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );

        assert_eq!(
            wait_for_key(&state, did, &kid).await,
            Some(*key.verifying_key().as_bytes())
        );
        assert_eq!(
            source_of(&state, did, &kid).as_deref(),
            Some("origin-server")
        );
        assert_eq!(peer_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // ── the dates a copied key is filed with ─────────────────────

    const DAY: i64 = 24 * 60 * 60;

    /// A key server answering every request with `key` and the extra `fields`.
    async fn dated_key_server(key: [u8; 32], fields: serde_json::Value) -> String {
        use base64::Engine;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/api/v1/signing-keys/{did}/{kid}",
            axum::routing::get(move || {
                let mut body = serde_json::json!({
                    "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
                    "algorithm": "ed25519",
                });
                for (name, value) in fields.as_object().unwrap() {
                    body[name] = value.clone();
                }
                async move { axum::Json(body) }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// The row a peer copy of a fresh key is filed with, from a key server
    /// that sends `fields`.
    async fn peer_copy(fields: serde_json::Value) -> crate::db::SigningKeyRow {
        peer_copy_of(&format!("did:plc:dated{}", rand::random::<u32>()), fields).await
    }

    /// The row a peer copy of a fresh key under `did` is filed with, from a
    /// key server on 127.0.0.1 that sends `fields`.
    async fn peer_copy_of(did: &str, fields: serde_json::Value) -> crate::db::SigningKeyRow {
        let did = did.to_string();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let base = dated_key_server(*key.verifying_key().as_bytes(), fields).await;
        let state = state_with(&base, stub_pds_resolver(&did, vec![]).await);
        fetch_on_miss(
            &state,
            PEER,
            &did,
            &freeq_sdk::sigtag::sign_canonical("{}", &key),
        );
        assert!(wait_for_key(&state, &did, &kid).await.is_some());
        state
            .with_db(|db| db.get_signing_key_row(&did, &kid))
            .flatten()
            .unwrap()
    }

    #[tokio::test]
    async fn a_peer_copy_keeps_the_dates_its_origin_sent() {
        let row = peer_copy(serde_json::json!({
            "registered_at": 1_700_000_000,
            "expires_at": 1_800_000_000,
        }))
        .await;
        assert_eq!(row.registered_at, 1_700_000_000);
        assert_eq!(row.expires_at, Some(1_800_000_000));
    }

    #[tokio::test]
    async fn a_peer_copy_the_origin_never_expires_is_filed_without_an_expiry() {
        let row = peer_copy(serde_json::json!({
            "registered_at": 1_700_000_000,
            "expires_at": null,
        }))
        .await;
        assert_eq!(row.registered_at, 1_700_000_000);
        assert_eq!(row.expires_at, None);
    }

    #[tokio::test]
    async fn a_peer_expiry_that_is_not_a_date_or_null_counts_as_none_sent() {
        for sent in [serde_json::json!("soon"), serde_json::json!(1.8e9)] {
            let row = peer_copy(serde_json::json!({
                "registered_at": 1_700_000_000,
                "expires_at": sent,
            }))
            .await;
            assert_eq!(
                row.expires_at,
                Some(1_700_000_000 + 90 * DAY),
                "expires_at {sent} is not a never-expires null"
            );
        }
    }

    #[tokio::test]
    async fn a_peer_copy_with_only_a_registration_date_expires_a_lifetime_after_it() {
        let row = peer_copy(serde_json::json!({ "registered_at": 1_700_000_000 })).await;
        assert_eq!(row.registered_at, 1_700_000_000);
        assert_eq!(row.expires_at, Some(1_700_000_000 + 90 * DAY));
    }

    #[tokio::test]
    async fn a_copy_from_a_peer_that_sends_no_dates_counts_from_when_it_was_copied() {
        let before = chrono::Utc::now().timestamp();
        let row = peer_copy(serde_json::json!({})).await;
        let after = chrono::Utc::now().timestamp();
        assert!((before..=after).contains(&row.registered_at), "{row:?}");
        assert_eq!(row.expires_at, Some(row.registered_at + 90 * DAY));
    }

    /// A server's own key, answered by that server's key API with no expiry
    /// sent, never expires.
    #[tokio::test]
    async fn a_did_web_key_its_own_host_answers_is_filed_without_an_expiry() {
        let row = peer_copy_of(
            "did:web:127.0.0.1",
            serde_json::json!({ "registered_at": 1_700_000_000 }),
        )
        .await;
        assert_eq!(row.registered_at, 1_700_000_000);
        assert_eq!(row.expires_at, None);
    }

    /// The host is compared ignoring case.
    #[test]
    fn the_own_host_is_compared_ignoring_case() {
        assert!(answered_by_own_host(
            "https://IRC.Freeq.at",
            "did:web:irc.freeq.AT"
        ));
        assert!(answered_by_own_host(
            "http://127.0.0.1:8080",
            "did:web:127.0.0.1"
        ));
        assert!(!answered_by_own_host(
            "https://irc.zerosum.org",
            "did:web:irc.freeq.at"
        ));
        assert!(!answered_by_own_host(
            "https://example.com",
            "did:web:example.com:u:alice"
        ));
        assert!(!answered_by_own_host(
            "https://irc.freeq.at",
            "did:plc:irc.freeq.at"
        ));
    }

    /// Another server's key relayed by a host that is not its own keeps the
    /// lifetime rule.
    #[tokio::test]
    async fn a_did_web_key_relayed_by_another_host_keeps_its_expiry() {
        let row = peer_copy_of(
            "did:web:server-y.example",
            serde_json::json!({ "registered_at": 1_700_000_000 }),
        )
        .await;
        assert_eq!(row.expires_at, Some(1_700_000_000 + 90 * DAY));
    }

    /// A did:web document listing `keys` under `did`.
    fn document_listing(did: &str, keys: &[[u8; 32]]) -> freeq_sdk::did::DidDocument {
        freeq_sdk::did::DidDocument {
            id: did.to_string(),
            also_known_as: vec![],
            verification_method: keys
                .iter()
                .enumerate()
                .map(|(i, key)| freeq_sdk::did::VerificationMethod {
                    id: format!("{did}#k{i}"),
                    method_type: "Multikey".to_string(),
                    controller: did.to_string(),
                    public_key_multibase: Some(
                        freeq_sdk::crypto::PublicKey::Ed25519(
                            ed25519_dalek::VerifyingKey::from_bytes(key).unwrap(),
                        )
                        .to_multibase(),
                    ),
                })
                .collect(),
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
        }
    }

    fn fresh_key() -> [u8; 32] {
        *ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .as_bytes()
    }

    fn expiry_of(state: &Arc<SharedState>, did: &str, key: &[u8; 32]) -> Option<i64> {
        let kid = freeq_sdk::act::derive_kid_bytes(key);
        state
            .with_db(|db| db.get_signing_key_row(did, &kid))
            .flatten()
            .unwrap()
            .expires_at
    }

    /// The startup check clears a did:web key's expiry only when the DID's
    /// own host confirms the key, by its document or its key API; a did:plc
    /// key and a key the host does not confirm keep theirs.
    #[tokio::test]
    async fn the_startup_check_clears_only_a_confirmed_row() {
        // Confirmed by the key API at its own host.
        let by_api = fresh_key();
        // Confirmed by its own document.
        let by_doc = fresh_key();
        let doc_did = "did:web:doc-host.example";
        // A did:web person's session key: their document lists their sign-in
        // key, not it, and their host runs no key API.
        let session = fresh_key();
        let person = "did:web:person.example";
        let sign_in = fresh_key();
        // A key whose host answers with another key.
        let other = fresh_key();
        let mismatched = "did:web:mismatch.example";
        let user = fresh_key();

        let resolver = freeq_sdk::did::DidResolver::static_map(HashMap::from([
            (doc_did.to_string(), document_listing(doc_did, &[by_doc])),
            (person.to_string(), document_listing(person, &[sign_in])),
            (mismatched.to_string(), document_listing(mismatched, &[])),
        ]));
        let state = crate::server::test_state_with_resolver(
            crate::config::ServerConfig::default(),
            resolver,
        );
        let api = dated_key_server(by_api, serde_json::json!({})).await;
        let wrong = dated_key_server(other, serde_json::json!({})).await;
        let rows = [
            ("did:web:127.0.0.1", by_api, "origin-server"),
            (doc_did, by_doc, "origin-server"),
            (person, session, "local-session"),
            (mismatched, user, "origin-server"),
            ("did:plc:someone", user, "local-session"),
        ];
        for (did, key, source) in rows {
            state
                .with_db(|db| db.save_signing_key_from(did, &key, source, 1, Some(2_000_000_000)))
                .unwrap();
        }

        let clients = LookupClients::Plain(freeq_oauth::SharedClient(reqwest::Client::new()));
        confirm_own_host_keys_with(&state, &clients, |host| match host {
            "127.0.0.1" => api.clone(),
            "mismatch.example" => wrong.clone(),
            // No key API there.
            _ => "http://127.0.0.1:9".to_string(),
        })
        .await;

        assert_eq!(expiry_of(&state, "did:web:127.0.0.1", &by_api), None);
        assert_eq!(expiry_of(&state, doc_did, &by_doc), None);
        assert_eq!(expiry_of(&state, person, &session), Some(2_000_000_000));
        assert_eq!(expiry_of(&state, mismatched, &user), Some(2_000_000_000));
        assert_eq!(
            expiry_of(&state, "did:plc:someone", &user),
            Some(2_000_000_000)
        );
    }

    /// A key record of `did` made at `created_at` and expiring at `expires_at`.
    fn dated_record(
        did: &str,
        key: &ed25519_dalek::SigningKey,
        created_at: &str,
        expires_at: &str,
    ) -> serde_json::Value {
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&key.to_bytes()).unwrap();
        serde_json::to_value(
            freeq_sdk::identity_records::build_device_record_with_expiry(
                &key, did, created_at, expires_at, None,
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// The row a key found in `did`'s records is filed with.
    async fn record_copy(
        did: &str,
        key: &ed25519_dalek::SigningKey,
        records: Vec<serde_json::Value>,
    ) -> crate::db::SigningKeyRow {
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let (base, _) = counting_key_server(None).await;
        let state = state_with(&base, stub_pds_resolver(did, records).await);
        fetch_on_miss(
            &state,
            PEER,
            did,
            &freeq_sdk::sigtag::sign_canonical("{}", key),
        );
        assert!(wait_for_key(&state, did, &kid).await.is_some());
        // The retirement stamp, if any, lands just after the row.
        tokio::time::sleep(Duration::from_millis(50)).await;
        state
            .with_db(|db| db.get_signing_key_row(did, &kid))
            .flatten()
            .unwrap()
    }

    #[tokio::test]
    async fn a_key_found_in_the_records_is_filed_with_its_records_dates() {
        let did = "did:plc:recorddates";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let made = chrono::Utc::now() - chrono::TimeDelta::days(2);
        let created_at = made.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // A later expiry than the default: the record's date is kept, uncapped.
        let row = record_copy(
            did,
            &key,
            vec![dated_record(did, &key, &created_at, "2099-01-01T00:00:00Z")],
        )
        .await;
        assert_eq!(row.registered_at, made.timestamp());
        assert_eq!(
            row.expires_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .timestamp()
            )
        );
        assert_eq!(row.removed_at, None);
    }

    #[tokio::test]
    async fn a_key_its_records_let_expire_is_filed_expired_not_retired() {
        let did = "did:plc:recordexpired";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let row = record_copy(
            did,
            &key,
            vec![dated_record(
                did,
                &key,
                "2026-01-01T00:00:00Z",
                "2026-02-01T00:00:00Z",
            )],
        )
        .await;
        assert_eq!(
            row.expires_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
                    .unwrap()
                    .timestamp()
            )
        );
        assert_eq!(row.removed_at, None, "only a retirement stamps removed_at");
    }
}
