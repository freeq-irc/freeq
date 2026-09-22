//! The record-cache REST routes, over HTTP against a running server.
//!
//! A running server's record reader refuses private addresses, so it cannot
//! reach a loopback stub PDS. These tests fill the cache through the same
//! entry points the reader's callbacks call (`keep_listing`, `keep_proof`),
//! with a listing and a proof a stub repository produced, and check what the
//! routes serve. The fetch from a PDS is covered by the server's unit tests.

use std::collections::HashMap;
use std::sync::Arc;

use freeq_sdk::did::DidResolver;
use freeq_sdk::identity_records::{DEVICE_KEY_TYPE, RecordEntry, record_cid, verify_proof};
use freeq_sdk::test_support::StubRepo;
use freeq_server::server::SharedState;

const DID: &str = "did:plc:recordcacheroutes";

fn device_record(seed: u8) -> serde_json::Value {
    let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[seed; 32]).unwrap();
    serde_json::to_value(
        freeq_sdk::identity_records::build_device_record(&key, DID, "2026-01-01T00:00:00Z", None)
            .unwrap(),
    )
    .unwrap()
}

/// What a stub repository serves for DID: its repo key, its listing, and the
/// proof of each listed record by rkey.
struct Served {
    repo_key: String,
    entries: Vec<RecordEntry>,
    proofs: HashMap<String, Vec<u8>>,
    resolver: DidResolver,
}

fn stub_repo(records: &[serde_json::Value]) -> Served {
    let mut repo = StubRepo::new(DID);
    for record in records {
        repo.add(DEVICE_KEY_TYPE, record);
    }
    // A loopback PDS: a running server's reader refuses to reach it.
    let doc = repo.document("http://127.0.0.1:9");
    let repo_key = doc
        .verification_method
        .iter()
        .find(|m| m.id.ends_with("#atproto"))
        .and_then(|m| m.public_key_multibase.clone())
        .unwrap();
    let query = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let (_, _, body) = repo
        .respond(
            "/xrpc/com.atproto.repo.listRecords",
            &query(&[("repo", DID), ("collection", DEVICE_KEY_TYPE)]),
        )
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries: Vec<RecordEntry> = serde_json::from_value(page["records"].clone()).unwrap();
    let mut proofs = HashMap::new();
    for entry in &entries {
        let rkey = rkey_of(&entry.uri);
        let (status, _, car) = repo
            .respond(
                "/xrpc/com.atproto.sync.getRecord",
                &query(&[
                    ("did", DID),
                    ("collection", DEVICE_KEY_TYPE),
                    ("rkey", &rkey),
                ]),
            )
            .unwrap();
        assert_eq!(status, 200);
        proofs.insert(rkey, car);
    }
    Served {
        repo_key,
        entries,
        proofs,
        resolver: DidResolver::static_map(HashMap::from([(DID.to_string(), doc)])),
    }
}

fn rkey_of(uri: &str) -> String {
    uri.rsplit('/').next().unwrap().to_string()
}

fn config() -> freeq_server::config::ServerConfig {
    freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-record-cache".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    }
}

/// A running server with no database, and its state.
async fn start(
    config: freeq_server::config::ServerConfig,
    resolver: DidResolver,
) -> (std::net::SocketAddr, Arc<SharedState>) {
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    let (_irc, http, _handle, state) = server.start_with_web_state().await.unwrap();
    (http, state)
}

/// Keep the stub's listing and every proof, as the reader's callbacks would.
fn fill(state: &SharedState, served: &Served) {
    let cache = &state.record_cache;
    cache.keep_listing(DID, DEVICE_KEY_TYPE, &served.repo_key, &served.entries);
    for entry in &served.entries {
        let rkey = rkey_of(&entry.uri);
        cache.keep_proof(
            DID,
            DEVICE_KEY_TYPE,
            &rkey,
            &record_cid(&entry.value).unwrap(),
            &served.repo_key,
            &served.proofs[&rkey],
        );
    }
}

fn sign_in(state: &SharedState) {
    state.did_sessions.lock().insert(
        DID.to_string(),
        std::collections::HashSet::from(["session".to_string()]),
    );
}

async fn get(http: std::net::SocketAddr, path: &str) -> reqwest::Response {
    reqwest::get(format!("http://{http}{path}")).await.unwrap()
}

fn listing_path(did: &str, collection: &str) -> String {
    format!(
        "/api/v1/records/{}/{}",
        urlencoding::encode(did),
        urlencoding::encode(collection)
    )
}

fn proof_path(did: &str, rkey: &str) -> String {
    format!("{}/{rkey}/proof", listing_path(did, DEVICE_KEY_TYPE))
}

fn account_path(did: &str) -> String {
    format!("/api/v1/records/{}", urlencoding::encode(did))
}

fn batch_path(dids: &[&str]) -> String {
    format!(
        "/api/v1/records?dids={}",
        urlencoding::encode(&dids.join(","))
    )
}

/// The listing served is the PDS's, each value exactly as listed.
async fn assert_listing(http: std::net::SocketAddr, served: &Served) {
    let response = get(http, &listing_path(DID, DEVICE_KEY_TYPE)).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["did"], DID);
    assert_eq!(body["collection"], DEVICE_KEY_TYPE);
    assert_eq!(body["stale"], false);
    assert!(body["fetched_at"].is_i64());
    let records: Vec<RecordEntry> = serde_json::from_value(body["records"].clone()).unwrap();
    assert_eq!(records, served.entries);
}

/// Each proof served is the CAR bytes, and they verify under the stub's
/// repo key with the SDK's own check.
async fn assert_proofs(http: std::net::SocketAddr, served: &Served) {
    let key = freeq_sdk::crypto::PublicKey::from_multibase(&served.repo_key).unwrap();
    for entry in &served.entries {
        let rkey = rkey_of(&entry.uri);
        let response = get(http, &proof_path(DID, &rkey)).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "application/vnd.ipld.car"
        );
        let fetched_at: i64 = response.headers()["x-freeq-fetched-at"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(fetched_at > 0);
        let car = response.bytes().await.unwrap();
        assert_eq!(car.as_ref(), served.proofs[&rkey].as_slice());
        let cid = record_cid(&entry.value).unwrap();
        let outcome = verify_proof(&car, DID, DEVICE_KEY_TYPE, &rkey, &cid, &key)
            .await
            .unwrap();
        assert!(outcome.verified(), "{rkey}");
    }
}

#[tokio::test]
async fn the_listing_and_its_proofs_are_served_as_the_pds_gave_them() {
    let served = stub_repo(&[device_record(1), device_record(2)]);
    let (http, state) = start(config(), served.resolver.clone()).await;
    sign_in(&state);
    fill(&state, &served);

    assert_listing(http, &served).await;
    assert_proofs(http, &served).await;
}

#[tokio::test]
async fn a_batch_serves_each_account_it_can_with_its_proofs() {
    use base64::Engine;
    let served = stub_repo(&[device_record(1), device_record(2)]);
    let (http, state) = start(config(), served.resolver.clone()).await;
    sign_in(&state);
    fill(&state, &served);

    let response = get(http, &batch_path(&["did:plc:neverappearedhere", DID])).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let accounts = body["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1, "the account not seen here is left out");
    assert_eq!(accounts[0]["did"], DID);
    let devices = &accounts[0]["collections"][DEVICE_KEY_TYPE];
    assert_eq!(devices["stale"], false);
    let records: Vec<RecordEntry> = serde_json::from_value(devices["records"].clone()).unwrap();
    assert_eq!(records, served.entries);

    let key = freeq_sdk::crypto::PublicKey::from_multibase(&served.repo_key).unwrap();
    let proofs = devices["proofs"].as_array().unwrap();
    assert_eq!(proofs.len(), served.entries.len());
    for (proof, entry) in proofs.iter().zip(&served.entries) {
        let rkey = rkey_of(&entry.uri);
        assert_eq!(proof["rkey"], rkey);
        let car = base64::engine::general_purpose::STANDARD
            .decode(proof["car"].as_str().unwrap())
            .unwrap();
        assert_eq!(car, served.proofs[&rkey]);
        let cid = record_cid(&entry.value).unwrap();
        assert_eq!(proof["cid"], cid.to_string());
        let outcome = verify_proof(&car, DID, DEVICE_KEY_TYPE, &rkey, &cid, &key)
            .await
            .unwrap();
        assert!(outcome.verified(), "{rkey}");
    }
}

#[tokio::test]
async fn each_refusal_has_its_status() {
    let served = stub_repo(&[device_record(1)]);
    let (http, state) = start(config(), served.resolver.clone()).await;
    let rkey = rkey_of(&served.entries[0].uri);

    // Not signed in, no key, no message: not seen here, though cached.
    fill(&state, &served);
    let stranger = "did:plc:neverappearedhere";
    for path in [
        listing_path(DID, DEVICE_KEY_TYPE),
        proof_path(DID, &rkey),
        listing_path(stranger, DEVICE_KEY_TYPE),
    ] {
        assert_eq!(get(http, &path).await.status(), 404, "{path}");
    }

    sign_in(&state);
    for path in [
        listing_path(DID, "app.bsky.feed.post"),
        proof_path(DID, "notlisted"),
    ] {
        assert_eq!(get(http, &path).await.status(), 404, "{path}");
    }
}

#[tokio::test]
async fn no_copy_and_an_unreadable_pds_is_a_bad_gateway() {
    let served = stub_repo(&[device_record(1)]);
    let (http, state) = start(config(), served.resolver.clone()).await;
    sign_in(&state);
    let rkey = rkey_of(&served.entries[0].uri);

    assert_eq!(
        get(http, &listing_path(DID, DEVICE_KEY_TYPE))
            .await
            .status(),
        502
    );
    assert_eq!(get(http, &proof_path(DID, &rkey)).await.status(), 502);

    // A listing kept, its proof not: the proof cannot be fetched.
    state
        .record_cache
        .keep_listing(DID, DEVICE_KEY_TYPE, &served.repo_key, &served.entries);
    assert_eq!(get(http, &proof_path(DID, &rkey)).await.status(), 502);
}

/// The record routes' own per-IP limit: 600 requests a minute.
const RECORD_LIMIT: usize = 600;

#[tokio::test]
async fn the_record_routes_share_their_own_limiter_of_600_a_minute() {
    let served = stub_repo(&[device_record(1)]);
    let (http, state) = start(config(), served.resolver.clone()).await;
    let stranger = "did:plc:neverappearedhere";
    // Each record route, with what it answers for an account not seen here.
    let routes = [
        (listing_path(stranger, DEVICE_KEY_TYPE), 404),
        (proof_path(stranger, "r"), 404),
        (account_path(stranger), 404),
        (batch_path(&[stranger]), 200),
    ];

    for i in 0..RECORD_LIMIT {
        // In turn: the routes draw on one budget.
        let (path, status) = &routes[i % routes.len()];
        assert_eq!(
            get(http, path).await.status(),
            *status,
            "request {i} to {path}"
        );
    }
    for (path, _) in &routes {
        assert_eq!(get(http, path).await.status(), 429, "{path}");
    }

    // The limiter the other REST routes share was not drawn on.
    assert!(state.rest_rate_limiter.check("127.0.0.1".parse().unwrap()));
}

#[tokio::test]
async fn a_restarted_server_serves_what_it_kept() {
    let dir = tempfile::tempdir().unwrap();
    let config = freeq_server::config::ServerConfig {
        data_dir: Some(dir.path().to_str().unwrap().to_string()),
        db_path: Some(dir.path().join("irc.db").to_str().unwrap().to_string()),
        ..config()
    };
    let served = stub_repo(&[device_record(1), device_record(2)]);
    {
        let (_http, state) = start(config.clone(), served.resolver.clone()).await;
        state.with_db(|db| db.save_signing_key_from(DID, &[7u8; 32], "local-session"));
        fill(&state, &served);
    }

    let (http, _state) = start(config, served.resolver.clone()).await;
    assert_listing(http, &served).await;
    assert_proofs(http, &served).await;
}
