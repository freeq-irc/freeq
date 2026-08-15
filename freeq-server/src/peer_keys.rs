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
//! **Where to fetch from is operator configuration, not something a peer
//! says.** `--s2s-peer-api <endpoint-id>=<base-url>` maps an S2S peer to the
//! server that vouches for its users. Nothing on the wire names a URL, so no
//! peer can aim this server's outbound requests. A peer with no entry simply
//! has no key source: its traffic stays uncheckable, which is honest, and
//! never becomes invalid.
//!
//! Known limit, stated rather than hidden: a key vouched for by the signer's
//! own server cannot survive that server colluding. Keys anchored in the DID
//! document are the real fix; the key id is already in the signature format,
//! so moving the lookup there changes nothing on the wire.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::server::SharedState;

/// How long a lookup that produced nothing is remembered before another is
/// attempted, so an unreachable peer is asked once a minute rather than once
/// per message.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A key server that does not answer promptly is treated as unreachable. This
/// runs off the delivery path, so the bound is about not accumulating tasks.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// `(did, kid)` lookups in flight or recently finished without a key.
///
/// Process-static, like the S2S rate limiter: it guards outbound requests, and
/// that concern belongs to the process rather than to any one server state.
static LOOKUPS: LazyLock<Mutex<HashMap<(String, String), Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
/// lookup that finds nothing is not retried for [`RETRY_AFTER`].
pub fn fetch_on_miss(state: &Arc<SharedState>, origin: &str, did: &str, sig_tag: &str) {
    match base_for_origin(state, origin) {
        Some(base) => start_lookup(state, vec![base], did, sig_tag),
        None => tracing::debug!(
            origin = %origin,
            "No key server configured for this peer (--s2s-peer-api); its signatures stay uncheckable"
        ),
    }
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
    let bases: Vec<String> = parse_peer_api_config(&state.config.s2s_peer_api)
        .into_values()
        .collect();
    if !bases.is_empty() {
        start_lookup(state, bases, did, sig_tag);
    }
}

/// One lookup for the key `sig_tag` names, tried against `bases` in turn.
fn start_lookup(state: &Arc<SharedState>, bases: Vec<String>, did: &str, sig_tag: &str) {
    let Ok((kid, _)) = freeq_sdk::sigtag::parse(sig_tag) else {
        return;
    };

    let entry = (did.to_string(), kid.to_string());
    {
        let mut lookups = LOOKUPS.lock();
        lookups.retain(|_, at| at.elapsed() < RETRY_AFTER);
        if lookups.contains_key(&entry) {
            return;
        }
        lookups.insert(entry.clone(), Instant::now());
    }

    let state = state.clone();
    tokio::spawn(async move {
        let (did, kid) = entry;
        for base in &bases {
            match fetch_key(base, &did, &kid).await {
                Ok(pubkey) => {
                    // Append-only and keyed by (did, kid), the same store a
                    // local registration writes to. The kid is a hash of the
                    // key bytes, so a fetched key cannot displace a different
                    // key already on file under that id.
                    state.with_db(|db| db.save_signing_key(&did, &pubkey));
                    LOOKUPS.lock().remove(&(did.clone(), kid.clone()));
                    tracing::info!(did = %did, kid = %kid, "Fetched a signing key from its home server");
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

/// One request to a peer's key server.
///
/// The returned key must hash to the id we asked for. Without that check a
/// key server could answer any request with a key of its choosing and every
/// signature by that key would verify — the kid is what binds the answer to
/// the question.
async fn fetch_key(base: &str, did: &str, kid: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;

    let url = format!(
        "{base}/api/v1/signing-keys/{}/{}",
        urlencoding::encode(did),
        urlencoding::encode(kid)
    );
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?;
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
    Ok(bytes)
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

    /// A peer with no configured key server produces no outbound request and
    /// no remembered lookup — nothing to retry, nothing to leak.
    #[tokio::test]
    async fn an_unconfigured_peer_triggers_no_lookup() {
        let state = crate::server::test_state_with_db();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let sig = freeq_sdk::sigtag::sign_canonical("{}", &key);

        fetch_on_miss(&state, "some-unconfigured-peer", "did:plc:unconfiguredpeer", &sig);
        assert!(!lookup_pending("did:plc:unconfiguredpeer", &kid));
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

        fetch_on_miss(&state, PEER, did, &freeq_sdk::sigtag::sign_canonical("{}", &key));

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

        fetch_on_miss(&state, PEER, did, &freeq_sdk::sigtag::sign_canonical("{}", &key));
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

        fetch_on_miss(&state, PEER, did, &freeq_sdk::sigtag::sign_canonical("{}", &key));
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
        tokio::time::sleep(Duration::from_millis(300)).await;

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
            let encoded =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other_pub);
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
}
