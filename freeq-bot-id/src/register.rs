//! `freeq-bot-id register`: record from the command line that bots belong to
//! an account, as the web app's Agents section does.
//!
//! The owner signs in once through the browser, as the terminal client does,
//! asking to create the two key records. This machine keeps a device key of
//! the owner's in its own file, published as a device record the first time;
//! each bot gets one `at.freeq.agentKey` record signed by that key. The
//! session is not saved, so no token outlives the run.

use anyhow::{Context, Result, bail};
use freeq_sdk::device_key::{DeviceKeyStore, StoredDeviceKey};
use freeq_sdk::identity_records::{
    DEVICE_KEY_TYPE, RecordReader, build_agent_record, build_device_record, device_key_history,
    fold_device_records, publish_record,
};
use std::path::PathBuf;

/// The label this machine's device record carries in the owner's Devices
/// list: the program and the machine, as the terminal client names its
/// device by the machine, so two machines that ran `register` read apart.
fn device_label(host: Option<&str>) -> String {
    match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(host) => format!("freeq-bot-id on {host}"),
        None => "freeq-bot-id".to_string(),
    }
}

/// What one run wrote: the device record's uri when it published this
/// machine's key, and one agent record's uri per bot.
#[derive(Debug, PartialEq, Eq)]
pub struct Registered {
    pub device_record: Option<String>,
    pub agent_records: Vec<String>,
}

/// Where this machine keeps its device key for `owner`: its own file, apart
/// from the terminal client's, so the machine is its own row in Devices.
pub fn device_key_path(owner: &str) -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("could not determine the config directory")?
        .join("freeq-bot-id")
        .join(format!("{owner}.device-key.json")))
}

/// Sign in as `owner` and register each of `bot_dids` under the account.
pub async fn register(owner: &str, bot_dids: &[String], name: Option<&str>) -> Result<()> {
    let path = device_key_path(owner)?;
    let session = freeq_sdk::oauth::login(owner, freeq_oauth::ENROLL_SCOPE)
        .await
        .context("sign-in failed")?;
    let store = freeq_sdk::device_key::FileDeviceKeyStore::new(&path);
    let reader = RecordReader::new(
        freeq_sdk::did::DidResolver::http(),
        freeq_oauth::SharedClient(reqwest::Client::new()),
    );
    let registered = register_with(&session, &store, &reader, bot_dids, name).await?;
    println!("Device key: {}", path.display());
    if let Some(uri) = &registered.device_record {
        println!("Published this machine's key: {uri}");
    }
    for (bot, uri) in bot_dids.iter().zip(&registered.agent_records) {
        println!("{bot}: {uri}");
    }
    Ok(())
}

/// Register `bot_dids` under `session`'s account, signing with the device
/// key in `store`. A key past its lifetime, refused, or retired by the
/// account is replaced first; a key the account holds no live record for is
/// published. Each agent record is dated now, at or after its signing key's
/// record, so the key is live at the record's date.
pub async fn register_with<P: freeq_oauth::ClientProvider>(
    session: &freeq_sdk::oauth::OAuthSession,
    store: &dyn DeviceKeyStore,
    reader: &RecordReader<P>,
    bot_dids: &[String],
    name: Option<&str>,
) -> Result<Registered> {
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    if name.is_some() && bot_dids.len() != 1 {
        bail!("--name names one bot: give one DID with it");
    }
    if let Some(bad) = bot_dids.iter().find(|d| !d.starts_with("did:")) {
        bail!("not a DID: {bad}");
    }
    let did = &session.did;
    let mut stored = freeq_sdk::device_key::load_or_make(store, did)?;
    let records = reader
        .list_records(did, DEVICE_KEY_TYPE)
        .await
        .context("could not read the account's device records")?;
    let now = chrono::Utc::now();
    let kid = kid_of(&stored);
    let retired = device_key_history(did, &records)
        .iter()
        .any(|k| k.kid == kid && k.retired_or_expired(now));
    if retired {
        stored = StoredDeviceKey::generate();
        store.save(did, &stored)?;
    }
    let kid = kid_of(&stored);
    let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&stored.seed)?;

    let live = fold_device_records(did, &records, now)
        .iter()
        .any(|k| k.kid == kid);
    let device_record = if live {
        None
    } else {
        let host = whoami::fallible::hostname().ok();
        let label = device_label(host.as_deref());
        let record = build_device_record(&key, did, &stored.created_at, Some(&label))?;
        let uri = publish(session, &serde_json::to_value(record)?).await?;
        store.save(
            did,
            &StoredDeviceKey {
                record_uri: Some(uri.clone()),
                ..stored.clone()
            },
        )?;
        Some(uri)
    };

    let mut agent_records = Vec::new();
    for bot in bot_dids {
        let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let record = build_agent_record(&key, did, bot, &at, name)?;
        agent_records.push(publish(session, &serde_json::to_value(record)?).await?);
    }
    Ok(Registered {
        device_record,
        agent_records,
    })
}

fn kid_of(stored: &StoredDeviceKey) -> String {
    freeq_sdk::sigtag::derive_kid(
        &ed25519_dalek::SigningKey::from_bytes(&stored.seed).verifying_key(),
    )
}

async fn publish(
    session: &freeq_sdk::oauth::OAuthSession,
    record: &serde_json::Value,
) -> Result<String> {
    publish_record(session, record).await.map_err(|e| match e {
        freeq_sdk::identity_records::PublishError::NeedsSignIn(reason) => anyhow::anyhow!(
            "the account did not let this sign-in write the record ({reason}); run register again"
        ),
        freeq_sdk::identity_records::PublishError::Failed(e) => e.context("writing a record"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use freeq_sdk::identity_records::{
        AGENT_KEY_TYPE, DEVICE_KEY_TYPE, RecordReader, fold_agent_records,
    };
    use freeq_sdk::test_support::StubRepo;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const OWNER: &str = "did:plc:registerowner";

    /// A PDS for OWNER answering listings and proofs from `repo`, and filing
    /// each `createRecord` into it; the count of records created per
    /// collection.
    async fn stub_pds(repo: Arc<Mutex<StubRepo>>) -> (String, Arc<Mutex<HashMap<String, usize>>>) {
        let created: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let (filing, counting) = (repo.clone(), created.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .route(
                "/xrpc/com.atproto.repo.createRecord",
                axum::routing::post(
                    move |headers: axum::http::HeaderMap,
                          axum::Json(body): axum::Json<serde_json::Value>| {
                        let (filing, counting) = (filing.clone(), counting.clone());
                        async move {
                            assert!(headers.contains_key("dpop"), "a DPoP proof is sent");
                            let collection = body["collection"].as_str().unwrap().to_string();
                            let uri = filing.lock().unwrap().add(&collection, &body["record"]);
                            *counting.lock().unwrap().entry(collection).or_default() += 1;
                            axum::Json(serde_json::json!({ "uri": uri, "cid": "bafy" }))
                        }
                    },
                ),
            )
            .fallback(
                move |uri: axum::http::Uri,
                      axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
                    let answer = repo.lock().unwrap().respond(uri.path(), &q);
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
        (base, created)
    }

    fn session(pds: &str) -> freeq_sdk::oauth::OAuthSession {
        freeq_sdk::oauth::OAuthSession {
            did: OWNER.to_string(),
            handle: "owner.test".to_string(),
            access_token: "tok".to_string(),
            pds_url: pds.to_string(),
            dpop_key: freeq_sdk::oauth::DpopKey::generate(),
            dpop_nonce: None,
            scope: freeq_oauth::ENROLL_SCOPE.to_string(),
        }
    }

    fn bot(seed: u8) -> String {
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[seed; 32]).unwrap();
        format!("did:key:{}", key.public_key_multibase())
    }

    #[tokio::test]
    async fn one_run_writes_a_device_record_and_an_agent_record_per_bot_and_the_next_no_device_record()
     {
        let repo = Arc::new(Mutex::new(StubRepo::new(OWNER)));
        let (pds, created) = stub_pds(repo.clone()).await;
        let doc = repo.lock().unwrap().document(&pds);
        let reader = RecordReader::new(
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(OWNER.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let dir = tempfile::tempdir().unwrap();
        let store = freeq_sdk::device_key::FileDeviceKeyStore::new(dir.path().join("key.json"));

        let first = register_with(&session(&pds), &store, &reader, &[bot(1), bot(2)], None)
            .await
            .unwrap();
        assert!(first.device_record.is_some());
        assert_eq!(first.agent_records.len(), 2);
        let counts = created.lock().unwrap().clone();
        assert_eq!(counts.get(DEVICE_KEY_TYPE), Some(&1));
        assert_eq!(counts.get(AGENT_KEY_TYPE), Some(&2));

        let second = register_with(&session(&pds), &store, &reader, &[bot(3)], None)
            .await
            .unwrap();
        assert_eq!(second.device_record, None, "the key's record is live");
        let counts = created.lock().unwrap().clone();
        assert_eq!(counts.get(DEVICE_KEY_TYPE), Some(&1));
        assert_eq!(counts.get(AGENT_KEY_TYPE), Some(&3));

        // Every claim counts under the fold, signed by the one device key.
        let devices = reader.list_records(OWNER, DEVICE_KEY_TYPE).await.unwrap();
        let agents = reader.list_records(OWNER, AGENT_KEY_TYPE).await.unwrap();
        let mut live: Vec<String> =
            fold_agent_records(OWNER, &devices, &agents, chrono::Utc::now())
                .into_iter()
                .map(|l| l.agent_did)
                .collect();
        live.sort();
        let mut want = vec![bot(1), bot(2), bot(3)];
        want.sort();
        assert_eq!(live, want);
    }

    #[test]
    fn the_device_is_named_after_the_machine_when_it_has_a_name() {
        assert_eq!(
            device_label(Some("ubuntu-dev")),
            "freeq-bot-id on ubuntu-dev"
        );
        assert_eq!(device_label(None), "freeq-bot-id");
        assert_eq!(device_label(Some("  ")), "freeq-bot-id");
    }

    #[tokio::test]
    async fn a_bot_given_with_a_name_is_named_and_one_without_is_not() {
        let repo = Arc::new(Mutex::new(StubRepo::new(OWNER)));
        let (pds, _created) = stub_pds(repo.clone()).await;
        let doc = repo.lock().unwrap().document(&pds);
        let reader = RecordReader::new(
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(OWNER.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let dir = tempfile::tempdir().unwrap();
        let store = freeq_sdk::device_key::FileDeviceKeyStore::new(dir.path().join("key.json"));

        register_with(&session(&pds), &store, &reader, &[bot(4)], Some("helper"))
            .await
            .unwrap();
        register_with(&session(&pds), &store, &reader, &[bot(5)], None)
            .await
            .unwrap();

        let agents = reader.list_records(OWNER, AGENT_KEY_TYPE).await.unwrap();
        let label_of = |did: &str| {
            agents
                .iter()
                .find(|a| a["agentDid"] == did)
                .map(|a| a.get("label").and_then(|l| l.as_str()).map(str::to_string))
        };
        assert_eq!(label_of(&bot(4)), Some(Some("helper".to_string())));
        assert_eq!(label_of(&bot(5)), Some(None));
    }

    #[tokio::test]
    async fn a_name_with_more_than_one_bot_is_refused_before_anything_is_written() {
        let repo = Arc::new(Mutex::new(StubRepo::new(OWNER)));
        let (pds, created) = stub_pds(repo.clone()).await;
        let doc = repo.lock().unwrap().document(&pds);
        let reader = RecordReader::new(
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(OWNER.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let dir = tempfile::tempdir().unwrap();
        let store = freeq_sdk::device_key::FileDeviceKeyStore::new(dir.path().join("key.json"));

        let err = register_with(
            &session(&pds),
            &store,
            &reader,
            &[bot(6), bot(7)],
            Some("helper"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--name"), "{err}");
        assert!(created.lock().unwrap().is_empty(), "nothing written");
    }

    #[tokio::test]
    async fn a_key_the_account_retired_is_replaced_before_it_signs() {
        let repo = Arc::new(Mutex::new(StubRepo::new(OWNER)));
        let (pds, created) = stub_pds(repo.clone()).await;
        let doc = repo.lock().unwrap().document(&pds);
        let reader = RecordReader::new(
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(OWNER.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let dir = tempfile::tempdir().unwrap();
        let store = freeq_sdk::device_key::FileDeviceKeyStore::new(dir.path().join("key.json"));
        register_with(&session(&pds), &store, &reader, &[bot(1)], None)
            .await
            .unwrap();

        // Signed out from another device.
        let stored = freeq_sdk::device_key::DeviceKeyStore::load(&store, OWNER)
            .unwrap()
            .unwrap();
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&stored.seed).unwrap();
        let kid = freeq_sdk::sigtag::derive_kid(
            &ed25519_dalek::SigningKey::from_bytes(&stored.seed).verifying_key(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let retirement =
            freeq_sdk::identity_records::build_device_retirement(&key, OWNER, &kid, &now).unwrap();
        repo.lock()
            .unwrap()
            .add(DEVICE_KEY_TYPE, &serde_json::to_value(retirement).unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let again = register_with(&session(&pds), &store, &reader, &[bot(2)], None)
            .await
            .unwrap();
        assert!(again.device_record.is_some(), "a new key is published");
        assert_eq!(created.lock().unwrap().get(DEVICE_KEY_TYPE), Some(&2));
        let devices = reader.list_records(OWNER, DEVICE_KEY_TYPE).await.unwrap();
        let agents = reader.list_records(OWNER, AGENT_KEY_TYPE).await.unwrap();
        let live: Vec<String> = fold_agent_records(OWNER, &devices, &agents, chrono::Utc::now())
            .into_iter()
            .map(|l| l.agent_did)
            .collect();
        assert!(live.contains(&bot(2)), "the new claim counts: {live:?}");
    }

    #[tokio::test]
    async fn a_retirement_dated_ahead_of_the_clock_replaces_the_stored_key() {
        let at = |hours: i64| {
            (chrono::Utc::now() + chrono::TimeDelta::hours(hours))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let made = at(-2);
        let key = freeq_sdk::crypto::PrivateKey::ed25519_from_bytes(&[9; 32]).unwrap();
        let kid = freeq_sdk::sigtag::derive_kid(
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key(),
        );
        let repo = Arc::new(Mutex::new(StubRepo::new(OWNER)));
        for record in [
            serde_json::to_value(
                freeq_sdk::identity_records::build_device_record(&key, OWNER, &made, None).unwrap(),
            )
            .unwrap(),
            serde_json::to_value(
                freeq_sdk::identity_records::build_device_retirement(&key, OWNER, &kid, &at(1))
                    .unwrap(),
            )
            .unwrap(),
        ] {
            repo.lock().unwrap().add(DEVICE_KEY_TYPE, &record);
        }
        let (pds, _created) = stub_pds(repo.clone()).await;
        let doc = repo.lock().unwrap().document(&pds);
        let reader = RecordReader::new(
            freeq_sdk::did::DidResolver::static_map(HashMap::from([(OWNER.to_string(), doc)])),
            freeq_oauth::SharedClient(reqwest::Client::new()),
        );
        let dir = tempfile::tempdir().unwrap();
        let store = freeq_sdk::device_key::FileDeviceKeyStore::new(dir.path().join("key.json"));
        store
            .save(
                OWNER,
                &StoredDeviceKey {
                    seed: [9; 32],
                    created_at: made,
                    record_uri: None,
                    refused: false,
                },
            )
            .unwrap();

        register_with(&session(&pds), &store, &reader, &[bot(8)], None)
            .await
            .unwrap();

        let signing = store.load(OWNER).unwrap().unwrap();
        assert_ne!(signing.seed, [9; 32], "the stored key is replaced");
    }
}
