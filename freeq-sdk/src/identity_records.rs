//! Identity records: what a person publishes in their own repository about
//! which signing keys and which bots are theirs.
//!
//! Two record types, both public entries in the account's AT Protocol
//! repository: `at.freeq.deviceKey` announces a signing key a device holds,
//! or retires one; `at.freeq.agentKey` announces a bot the account claims as
//! its own, or retires that claim. The PDS writes them into a signed commit;
//! that part happens elsewhere. This module builds the entries, reads them
//! back from the account's PDS, and folds a list of them into the set that is
//! live at an instant.
//!
//! Every record carries a `bindingSig`: an ed25519 signature made by the key
//! the record is about (a device key) or by a device key of the account
//! (everything else), over the JCS canonical form of the record itself. That
//! is the recipe every other freeq document signature uses — chat documents,
//! task events, the bot certificate, policy credentials — and it puts every
//! field of the record under the signature, so a record lifted out of one
//! account's repository, or altered in any field, says nothing.

use crate::crypto::{PrivateKey, PublicKey};
use crate::did::DidResolver;
use crate::pds::pds_endpoint;
use crate::sigtag::derive_kid_bytes;
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Record type for a signing key a device publishes, and for retiring one.
pub const DEVICE_KEY_TYPE: &str = "at.freeq.deviceKey";

/// Record type for a bot an account claims as its own, and for retiring one.
pub const AGENT_KEY_TYPE: &str = "at.freeq.agentKey";

/// An `at.freeq.deviceKey` entry: either a key the account publishes
/// (`publicKeyMultibase`) or a retirement of one (`revokes`), never both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyRecord {
    #[serde(rename = "$type")]
    pub record_type: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revokes: Option<String>,
    /// The key id of the key that signed this entry.
    pub kid: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub binding_sig: String,
}

/// An `at.freeq.agentKey` entry: either a bot the account claims (`agentDid`)
/// or a retirement of that claim (`revokes`), never both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentKeyRecord {
    #[serde(rename = "$type")]
    pub record_type: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revokes: Option<String>,
    /// The key id of the owner's device key that signed this entry.
    pub kid: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub binding_sig: String,
}

/// A device key that is live at the instant asked about, and the record it
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDeviceKey {
    pub kid: String,
    pub public_key_multibase: String,
    pub created_at: DateTime<Utc>,
    pub record: serde_json::Value,
}

/// A bot the account claims at the instant asked about, and the record it
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAgentLink {
    pub agent_did: String,
    pub kid: String,
    pub created_at: DateTime<Utc>,
    pub record: serde_json::Value,
}

// ─── the signed bytes ───────────────────────────────────────────────────

/// The bytes a record signs: its JCS (RFC 8785) canonical form with the
/// `bindingSig` field removed. Takes the record either way — a record being
/// built has no signature yet, one read off the wire has one.
///
/// Verifiers pass the value exactly as received, never a re-serialized copy,
/// so any field that changed in transit fails the signature.
pub fn record_signed_bytes<T: Serialize>(record: &T) -> Vec<u8> {
    let mut value = serde_json::to_value(record).expect("a record serializes");
    if let Some(object) = value.as_object_mut() {
        object.remove("bindingSig");
    }
    crate::canonical::canonicalize(&value)
        .expect("a JSON value canonicalizes")
        .into_bytes()
}

// ─── the builders ───────────────────────────────────────────────────────

/// Announce `key` as a signing key of `did`.
pub fn build_device_record(
    key: &PrivateKey,
    did: &str,
    created_at: &str,
    label: Option<&str>,
) -> Result<DeviceKeyRecord> {
    let raw = ed25519_public_bytes(key)?;
    let mut record = DeviceKeyRecord {
        record_type: DEVICE_KEY_TYPE.to_string(),
        did: did.to_string(),
        public_key_multibase: Some(key.public_key_multibase()),
        revokes: None,
        kid: derive_kid_bytes(&raw),
        created_at: created_at.to_string(),
        label: label.map(str::to_string),
        binding_sig: String::new(),
    };
    record.binding_sig = key.sign_base64url(&record_signed_bytes(&record));
    Ok(record)
}

/// Retire the device key named by `revokes_kid`, signing with `signer` —
/// the retired key itself, or any other key of the same account.
pub fn build_device_retirement(
    signer: &PrivateKey,
    did: &str,
    revokes_kid: &str,
    created_at: &str,
) -> Result<DeviceKeyRecord> {
    let raw = ed25519_public_bytes(signer)?;
    let mut record = DeviceKeyRecord {
        record_type: DEVICE_KEY_TYPE.to_string(),
        did: did.to_string(),
        public_key_multibase: None,
        revokes: Some(revokes_kid.to_string()),
        kid: derive_kid_bytes(&raw),
        created_at: created_at.to_string(),
        label: None,
        binding_sig: String::new(),
    };
    record.binding_sig = signer.sign_base64url(&record_signed_bytes(&record));
    Ok(record)
}

/// Claim `agent_did` as a bot of `owner_did`, signed by one of its keys.
pub fn build_agent_record(
    owner_key: &PrivateKey,
    owner_did: &str,
    agent_did: &str,
    created_at: &str,
    label: Option<&str>,
) -> Result<AgentKeyRecord> {
    let raw = ed25519_public_bytes(owner_key)?;
    let mut record = AgentKeyRecord {
        record_type: AGENT_KEY_TYPE.to_string(),
        did: owner_did.to_string(),
        agent_did: Some(agent_did.to_string()),
        revokes: None,
        kid: derive_kid_bytes(&raw),
        created_at: created_at.to_string(),
        label: label.map(str::to_string),
        binding_sig: String::new(),
    };
    record.binding_sig = owner_key.sign_base64url(&record_signed_bytes(&record));
    Ok(record)
}

/// Withdraw the claim on `agent_did`.
pub fn build_agent_retirement(
    owner_key: &PrivateKey,
    owner_did: &str,
    agent_did: &str,
    created_at: &str,
) -> Result<AgentKeyRecord> {
    let raw = ed25519_public_bytes(owner_key)?;
    let mut record = AgentKeyRecord {
        record_type: AGENT_KEY_TYPE.to_string(),
        did: owner_did.to_string(),
        agent_did: None,
        revokes: Some(agent_did.to_string()),
        kid: derive_kid_bytes(&raw),
        created_at: created_at.to_string(),
        label: None,
        binding_sig: String::new(),
    };
    record.binding_sig = owner_key.sign_base64url(&record_signed_bytes(&record));
    Ok(record)
}

// ─── the folds ──────────────────────────────────────────────────────────

/// A checked device key record, with the retirement that ended it once the
/// retirements have been applied.
struct Candidate {
    kid: String,
    public_key_multibase: String,
    public_key: PublicKey,
    created_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
    record: serde_json::Value,
}

/// A checked agent claim, with the retirement that ended it.
struct LinkCandidate {
    agent_did: String,
    kid: String,
    created_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
    record: serde_json::Value,
}

/// The device keys of `did` that are live at `at`, earliest first.
///
/// Records arrive as JSON because they come off the wire that way, and one
/// malformed entry must be dropped rather than fail the whole read.
pub fn fold_device_records(
    did: &str,
    records: &[serde_json::Value],
    at: DateTime<Utc>,
) -> Vec<LiveDeviceKey> {
    device_state(did, records)
        .into_iter()
        .filter(|k| k.created_at <= at && k.retired_at.is_none_or(|r| r > at))
        .map(|k| LiveDeviceKey {
            kid: k.kid,
            public_key_multibase: k.public_key_multibase,
            created_at: k.created_at,
            record: k.record,
        })
        .collect()
}

/// The bots `did` claims at `at`, earliest first. A claim counts only if the
/// owner key that signed it was itself live under the device fold when the
/// claim was written.
pub fn fold_agent_records(
    did: &str,
    device_records: &[serde_json::Value],
    agent_records: &[serde_json::Value],
    at: DateTime<Utc>,
) -> Vec<LiveAgentLink> {
    let devices = device_state(did, device_records);
    let mut links: Vec<LinkCandidate> = Vec::new();
    let mut retirements: Vec<(AgentKeyRecord, DateTime<Utc>, &serde_json::Value)> = Vec::new();

    for value in agent_records {
        let Some((record, created_at)) = parse_agent(value, did) else {
            continue;
        };
        match (record.agent_did.as_deref(), record.revokes.as_deref()) {
            (Some(agent_did), None) => {
                let Some(public_key) = signer_live_at(&devices, &record.kid, created_at) else {
                    continue;
                };
                if !verify_binding(public_key, &record_signed_bytes(value), &record.binding_sig) {
                    continue;
                }
                links.push(LinkCandidate {
                    agent_did: agent_did.to_string(),
                    kid: record.kid.clone(),
                    created_at,
                    retired_at: None,
                    record: value.clone(),
                });
            }
            (None, Some(_)) => retirements.push((record, created_at, value)),
            _ => continue,
        }
    }

    // One entry per bot: the earliest claim wins, so re-claiming a bot cannot
    // move the date a retirement is measured against.
    links.sort_by(|a, b| (&a.agent_did, a.created_at).cmp(&(&b.agent_did, b.created_at)));
    links.dedup_by(|a, b| a.agent_did == b.agent_did);

    retirements.sort_by(|a, b| (a.1, &a.0.binding_sig).cmp(&(b.1, &b.0.binding_sig)));
    for (record, created_at, value) in retirements {
        let revokes = record.revokes.as_deref().unwrap_or_default();
        let Some(target) = links.iter().position(|l| l.agent_did == revokes) else {
            continue;
        };
        if created_at <= links[target].created_at {
            continue;
        }
        let Some(public_key) = signer_live_at(&devices, &record.kid, created_at) else {
            continue;
        };
        if !verify_binding(public_key, &record_signed_bytes(value), &record.binding_sig) {
            continue;
        }
        let retired = &mut links[target].retired_at;
        if retired.is_none_or(|r| r > created_at) {
            *retired = Some(created_at);
        }
    }

    links.sort_by(|a, b| (a.created_at, &a.agent_did).cmp(&(b.created_at, &b.agent_did)));
    links
        .into_iter()
        .filter(|l| l.created_at <= at && l.retired_at.is_none_or(|r| r > at))
        .map(|l| LiveAgentLink {
            agent_did: l.agent_did,
            kid: l.kid,
            created_at: l.created_at,
            record: l.record,
        })
        .collect()
}

/// Every device key record of one account, checked, each carrying the
/// retirement that ended it. Both folds read the account's key history from
/// here, so they cannot disagree about who was live when.
fn device_state(did: &str, records: &[serde_json::Value]) -> Vec<Candidate> {
    let mut keys: Vec<Candidate> = Vec::new();
    let mut retirements: Vec<(DeviceKeyRecord, DateTime<Utc>, &serde_json::Value)> = Vec::new();

    for value in records {
        let Some((record, created_at)) = parse_device(value, did) else {
            continue;
        };
        match (
            record.public_key_multibase.as_deref(),
            record.revokes.as_deref(),
        ) {
            (Some(multibase), None) => {
                let Some((public_key, raw)) = ed25519_from_multibase(multibase) else {
                    continue;
                };
                // The record signs itself with its own key, so a wrong kid is
                // signed too: it is checked against the key it names.
                if record.kid != derive_kid_bytes(&raw) {
                    continue;
                }
                if !verify_binding(
                    &public_key,
                    &record_signed_bytes(value),
                    &record.binding_sig,
                ) {
                    continue;
                }
                keys.push(Candidate {
                    kid: record.kid.clone(),
                    public_key_multibase: multibase.to_string(),
                    public_key,
                    created_at,
                    retired_at: None,
                    record: value.clone(),
                });
            }
            (None, Some(_)) => retirements.push((record, created_at, value)),
            _ => continue,
        }
    }

    // One entry per key id: the earliest record wins, so republishing a key
    // cannot revive it or move the date a retirement is measured against.
    keys.sort_by(|a, b| (&a.kid, a.created_at).cmp(&(&b.kid, b.created_at)));
    keys.dedup_by(|a, b| a.kid == b.kid);

    // Retirements take effect in date order, because whether one counts turns
    // on its signer still being live when it was written. Retirements sharing
    // an instant are ordered by signature so every implementation agrees.
    retirements.sort_by(|a, b| (a.1, &a.0.binding_sig).cmp(&(b.1, &b.0.binding_sig)));
    for (record, created_at, value) in retirements {
        let revokes = record.revokes.as_deref().unwrap_or_default();
        let Some(target) = keys.iter().position(|k| k.kid == revokes) else {
            continue;
        };
        if created_at <= keys[target].created_at {
            continue;
        }
        let Some(signer) = keys.iter().position(|k| k.kid == record.kid) else {
            continue;
        };
        if keys[signer].created_at > created_at {
            continue;
        }
        // A key counts as live for signing its own retirement.
        if signer != target && keys[signer].retired_at.is_some_and(|r| r <= created_at) {
            continue;
        }
        let message = record_signed_bytes(value);
        if !verify_binding(&keys[signer].public_key, &message, &record.binding_sig) {
            continue;
        }
        let retired = &mut keys[target].retired_at;
        if retired.is_none_or(|r| r > created_at) {
            *retired = Some(created_at);
        }
    }

    keys.sort_by(|a, b| (a.created_at, &a.kid).cmp(&(b.created_at, &b.kid)));
    keys
}

/// The public key of `kid`, if that key of the account was live at `when`.
fn signer_live_at<'a>(
    devices: &'a [Candidate],
    kid: &str,
    when: DateTime<Utc>,
) -> Option<&'a PublicKey> {
    devices
        .iter()
        .find(|d| d.kid == kid)
        .filter(|d| d.created_at <= when && d.retired_at.is_none_or(|r| r > when))
        .map(|d| &d.public_key)
}

fn parse_device(value: &serde_json::Value, did: &str) -> Option<(DeviceKeyRecord, DateTime<Utc>)> {
    let record: DeviceKeyRecord = serde_json::from_value(value.clone()).ok()?;
    if record.record_type != DEVICE_KEY_TYPE || record.did != did {
        return None;
    }
    let created_at = parse_instant(&record.created_at)?;
    Some((record, created_at))
}

fn parse_agent(value: &serde_json::Value, did: &str) -> Option<(AgentKeyRecord, DateTime<Utc>)> {
    let record: AgentKeyRecord = serde_json::from_value(value.clone()).ok()?;
    if record.record_type != AGENT_KEY_TYPE || record.did != did {
        return None;
    }
    let created_at = parse_instant(&record.created_at)?;
    Some((record, created_at))
}

fn parse_instant(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn ed25519_public_bytes(key: &PrivateKey) -> Result<[u8; 32]> {
    match key {
        PrivateKey::Ed25519(k) => Ok(*k.verifying_key().as_bytes()),
        _ => bail!("identity records are signed with ed25519 keys only"),
    }
}

/// Decode a `z6Mk…` public key, refusing anything that is not ed25519.
fn ed25519_from_multibase(multibase: &str) -> Option<(PublicKey, [u8; 32])> {
    match PublicKey::from_multibase(multibase).ok()? {
        PublicKey::Ed25519(k) => {
            let raw = *k.as_bytes();
            Some((PublicKey::Ed25519(k), raw))
        }
        _ => None,
    }
}

fn verify_binding(public_key: &PublicKey, message: &[u8], binding_sig: &str) -> bool {
    let Ok(signature) = URL_SAFE_NO_PAD.decode(binding_sig) else {
        return false;
    };
    public_key.verify(message, &signature).is_ok()
}

// ─── reading from the account's PDS ─────────────────────────────────────

/// Reads an account's identity records from its PDS, unauthenticated.
///
/// The PDS address comes from a DID document anyone can write, so the HTTP
/// client for each URL comes from the caller's provider: the server hands in
/// one that refuses private addresses, other callers a plain shared client.
pub struct RecordReader<P: freeq_oauth::ClientProvider> {
    resolver: DidResolver,
    clients: P,
}

/// One page of a `com.atproto.repo.listRecords` answer.
#[derive(Deserialize)]
struct ListRecordsPage {
    records: Vec<ListedRecord>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct ListedRecord {
    value: serde_json::Value,
}

impl<P: freeq_oauth::ClientProvider> RecordReader<P> {
    pub fn new(resolver: DidResolver, clients: P) -> Self {
        Self { resolver, clients }
    }

    /// Every record of `collection` in `did`'s repository, as the PDS lists
    /// them. A DID whose document names no PDS has none.
    pub async fn list_records(
        &self,
        did: &str,
        collection: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let doc = self.resolver.resolve(did).await?;
        let Some(pds) = pds_endpoint(&doc) else {
            return Ok(Vec::new());
        };
        let endpoint = format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            pds.trim_end_matches('/')
        );
        let mut records = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = url::Url::parse(&endpoint).context("invalid PDS endpoint")?;
            url.query_pairs_mut()
                .append_pair("repo", did)
                .append_pair("collection", collection)
                .append_pair("limit", "100");
            if let Some(cursor) = &cursor {
                url.query_pairs_mut().append_pair("cursor", cursor);
            }
            let page: ListRecordsPage = self
                .get(&url)
                .await?
                .json()
                .await
                .context("listRecords answer is not a record list")?;
            // An empty page ends the listing even if it carries a cursor, so a
            // PDS cannot keep the reader asking forever for nothing.
            let empty = page.records.is_empty();
            records.extend(page.records.into_iter().map(|r| r.value));
            match page.cursor {
                Some(next) if !empty => cursor = Some(next),
                _ => break,
            }
        }
        Ok(records)
    }

    /// The device keys of `did` that are live at `at`.
    pub async fn live_device_keys(
        &self,
        did: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<LiveDeviceKey>> {
        let records = self.list_records(did, DEVICE_KEY_TYPE).await?;
        Ok(fold_device_records(did, &records, at))
    }

    /// The bots `did` claims at `at`.
    pub async fn live_agent_links(
        &self,
        did: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<LiveAgentLink>> {
        let devices = self.list_records(did, DEVICE_KEY_TYPE).await?;
        let agents = self.list_records(did, AGENT_KEY_TYPE).await?;
        Ok(fold_agent_records(did, &devices, &agents, at))
    }

    /// GET `url` with the provider's client for it; an HTTP error status is
    /// an error.
    async fn get(&self, url: &url::Url) -> Result<reqwest::Response> {
        let client = self.clients.client_for(url.as_str()).await?;
        client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("request to {} failed", url.path()))?
            .error_for_status()
            .with_context(|| format!("{} answered with an error", url.path()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ALICE: &str = "did:plc:k2n3e2vsihf3farequ44t5j7";
    const T0: &str = "2026-01-01T00:00:00Z";
    const T1: &str = "2026-02-01T00:00:00Z";
    const T2: &str = "2026-03-01T00:00:00Z";
    const T3: &str = "2026-04-01T00:00:00Z";

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::ed25519_from_bytes(&[seed; 32]).unwrap()
    }

    fn kid_of(seed: u8) -> String {
        derive_kid_bytes(&ed25519_public_bytes(&key(seed)).unwrap())
    }

    /// The bot in the agent vectors: a real did:key from a fixed seed.
    fn agent_did() -> String {
        format!("did:key:{}", key(9).public_key_multibase())
    }

    fn value(record: &impl Serialize) -> serde_json::Value {
        serde_json::to_value(record).unwrap()
    }

    fn instant(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn hex_seed(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    fn fixtures_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../spec/identity-record-vectors.json")
    }

    // ─── the builders ───────────────────────────────────────────────────

    #[test]
    fn a_built_device_record_is_live_through_the_fold() {
        let record = value(&build_device_record(&key(1), ALICE, T0, Some("laptop")).unwrap());
        let live = fold_device_records(ALICE, std::slice::from_ref(&record), instant(T1));
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].kid, kid_of(1));
        assert_eq!(live[0].public_key_multibase, key(1).public_key_multibase());
        assert_eq!(live[0].created_at, instant(T0));
        assert_eq!(live[0].record, record);
    }

    #[test]
    fn a_device_record_is_not_live_before_its_own_date() {
        let record = value(&build_device_record(&key(1), ALICE, T1, None).unwrap());
        assert!(fold_device_records(ALICE, &[record], instant(T0)).is_empty());
    }

    #[test]
    fn a_device_record_belongs_to_one_account_only() {
        let record = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        assert!(fold_device_records("did:plc:someoneelse", &[record], instant(T1)).is_empty());
    }

    #[test]
    fn an_absent_label_is_omitted_rather_than_null() {
        let record = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        assert_eq!(record["$type"], DEVICE_KEY_TYPE);
        assert!(record.get("label").is_none());
        assert!(record.get("revokes").is_none());
    }

    #[test]
    fn a_tampered_binding_signature_drops_the_record() {
        let mut record = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        let sig = record["bindingSig"].as_str().unwrap().to_string();
        record["bindingSig"] = json!(format!("A{}", &sig[1..]));
        assert!(fold_device_records(ALICE, &[record], instant(T1)).is_empty());
    }

    #[test]
    fn a_built_agent_record_is_live_through_the_fold() {
        let device = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        let agent = agent_did();
        let link = value(&build_agent_record(&key(1), ALICE, &agent, T1, Some("helper")).unwrap());
        let live = fold_agent_records(
            ALICE,
            std::slice::from_ref(&device),
            std::slice::from_ref(&link),
            instant(T2),
        );
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].agent_did, agent);
        assert_eq!(live[0].kid, kid_of(1));
        assert_eq!(live[0].created_at, instant(T1));
        assert_eq!(live[0].record, link);
    }

    #[test]
    fn an_altered_field_drops_the_record() {
        let record = value(&build_device_record(&key(1), ALICE, T0, Some("laptop")).unwrap());
        for field in ["createdAt", "label", "kid", "did", "$type"] {
            let mut altered = record.clone();
            altered[field] = json!("2026-06-01T00:00:00Z");
            assert!(
                fold_device_records(ALICE, &[altered], instant(T1)).is_empty(),
                "{field} was changed and the record still folded live"
            );
        }
    }

    #[test]
    fn a_link_signature_is_not_a_retirement_signature() {
        let agent = agent_did();
        let device = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        let link = value(&build_agent_record(&key(1), ALICE, &agent, T1, None).unwrap());
        // The same fields, with the agent DID moved into `revokes`: a forged
        // retirement wearing the link's own signature.
        let forged = json!({
            "$type": AGENT_KEY_TYPE,
            "did": ALICE,
            "revokes": agent,
            "kid": kid_of(1),
            "createdAt": T1,
            "bindingSig": link["bindingSig"].clone(),
        });
        let live = fold_agent_records(ALICE, &[device], &[link, forged], instant(T2));
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].agent_did, agent);
    }

    #[test]
    fn builders_refuse_a_non_ed25519_key() {
        let k = PrivateKey::generate_secp256k1();
        assert!(build_device_record(&k, ALICE, T0, None).is_err());
        assert!(build_device_retirement(&k, ALICE, &kid_of(1), T1).is_err());
        assert!(build_agent_record(&k, ALICE, &agent_did(), T1, None).is_err());
        assert!(build_agent_retirement(&k, ALICE, &agent_did(), T2).is_err());
    }

    // ─── the folds ──────────────────────────────────────────────────────

    struct FoldCase {
        name: &'static str,
        at: &'static str,
        device_records: Vec<serde_json::Value>,
        agent_records: Vec<serde_json::Value>,
        live_device_kids: Vec<String>,
        live_agent_dids: Vec<String>,
    }

    fn fold_cases() -> Vec<FoldCase> {
        let agent = agent_did();

        let k1_record = value(&build_device_record(&key(1), ALICE, T0, Some("laptop")).unwrap());
        let k2_record = value(&build_device_record(&key(2), ALICE, T0, Some("phone")).unwrap());
        let self_retirement =
            value(&build_device_retirement(&key(1), ALICE, &kid_of(1), T1).unwrap());
        let peer_retirement =
            value(&build_device_retirement(&key(2), ALICE, &kid_of(1), T1).unwrap());
        let stranger_retirement =
            value(&build_device_retirement(&key(3), ALICE, &kid_of(1), T1).unwrap());
        // The signature covers the DID, not the kid, so a rewritten kid is
        // caught only by checking it against the key it claims to name.
        let mut mismatched_kid = value(&build_device_record(&key(1), ALICE, T0, None).unwrap());
        mismatched_kid["kid"] = json!(kid_of(3));

        let link_t1 =
            value(&build_agent_record(&key(1), ALICE, &agent, T1, Some("helper")).unwrap());
        let link_t2 = value(&build_agent_record(&key(1), ALICE, &agent, T2, None).unwrap());
        let link_retirement = value(&build_agent_retirement(&key(1), ALICE, &agent, T2).unwrap());

        vec![
            FoldCase {
                name: "device-key-retired-by-itself",
                at: T2,
                device_records: vec![k1_record.clone(), self_retirement.clone()],
                agent_records: vec![],
                live_device_kids: vec![],
                live_agent_dids: vec![],
            },
            FoldCase {
                name: "device-key-retired-by-a-second-key",
                at: T2,
                device_records: vec![k1_record.clone(), k2_record.clone(), peer_retirement],
                agent_records: vec![],
                live_device_kids: vec![kid_of(2)],
                live_agent_dids: vec![],
            },
            FoldCase {
                name: "retirement-signed-by-a-key-with-no-record",
                at: T2,
                device_records: vec![k1_record.clone(), stranger_retirement],
                agent_records: vec![],
                live_device_kids: vec![kid_of(1)],
                live_agent_dids: vec![],
            },
            FoldCase {
                name: "device-key-whose-kid-does-not-match",
                at: T2,
                device_records: vec![mismatched_kid, k2_record],
                agent_records: vec![],
                live_device_kids: vec![kid_of(2)],
                live_agent_dids: vec![],
            },
            FoldCase {
                name: "agent-link-from-a-live-key",
                at: T2,
                device_records: vec![k1_record.clone()],
                agent_records: vec![link_t1.clone()],
                live_device_kids: vec![kid_of(1)],
                live_agent_dids: vec![agent.clone()],
            },
            FoldCase {
                name: "agent-link-from-a-retired-key",
                at: T3,
                device_records: vec![k1_record.clone(), self_retirement],
                agent_records: vec![link_t2],
                live_device_kids: vec![],
                live_agent_dids: vec![],
            },
            FoldCase {
                name: "agent-link-retired",
                at: T3,
                device_records: vec![k1_record],
                agent_records: vec![link_t1, link_retirement],
                live_device_kids: vec![kid_of(1)],
                live_agent_dids: vec![],
            },
        ]
    }

    fn run_fold_case(name: &str) {
        let case = fold_cases().into_iter().find(|c| c.name == name).unwrap();
        let at = instant(case.at);
        let kids: Vec<String> = fold_device_records(ALICE, &case.device_records, at)
            .into_iter()
            .map(|k| k.kid)
            .collect();
        assert_eq!(kids, case.live_device_kids, "{name}: live device keys");
        let dids: Vec<String> =
            fold_agent_records(ALICE, &case.device_records, &case.agent_records, at)
                .into_iter()
                .map(|l| l.agent_did)
                .collect();
        assert_eq!(dids, case.live_agent_dids, "{name}: live agent links");
    }

    #[test]
    fn a_key_that_retires_itself_stops_being_live() {
        run_fold_case("device-key-retired-by-itself");
    }

    #[test]
    fn a_second_live_key_can_retire_the_first() {
        run_fold_case("device-key-retired-by-a-second-key");
    }

    #[test]
    fn a_retirement_from_a_key_with_no_record_is_ignored() {
        run_fold_case("retirement-signed-by-a-key-with-no-record");
    }

    #[test]
    fn a_key_record_whose_kid_does_not_match_is_ignored() {
        run_fold_case("device-key-whose-kid-does-not-match");
    }

    #[test]
    fn an_agent_link_signed_by_a_live_key_is_live() {
        run_fold_case("agent-link-from-a-live-key");
    }

    #[test]
    fn an_agent_link_signed_by_a_retired_key_is_not_live() {
        run_fold_case("agent-link-from-a-retired-key");
    }

    #[test]
    fn an_agent_retirement_ends_the_link() {
        run_fold_case("agent-link-retired");
    }

    // ─── the shared vectors ─────────────────────────────────────────────

    fn vector_entry(name: &str, seed: u8, record: serde_json::Value) -> serde_json::Value {
        let signed_bytes = record_signed_bytes(&record);
        let mut entry = json!({
            "name": name,
            "seed": hex_seed(seed),
            "publicKeyMultibase": key(seed).public_key_multibase(),
            "kid": kid_of(seed),
            "did": record["did"].clone(),
            "createdAt": record["createdAt"].clone(),
            "signedBytes": String::from_utf8(signed_bytes).unwrap(),
            "bindingSig": record["bindingSig"].clone(),
            "record": record.clone(),
        });
        if let Some(label) = record.get("label") {
            entry["label"] = label.clone();
        }
        entry
    }

    fn vectors() -> Vec<serde_json::Value> {
        let agent = agent_did();
        vec![
            vector_entry(
                "device-key",
                1,
                value(&build_device_record(&key(1), ALICE, T0, Some("laptop")).unwrap()),
            ),
            vector_entry(
                "device-retirement-signed-by-the-retired-key",
                1,
                value(&build_device_retirement(&key(1), ALICE, &kid_of(1), T1).unwrap()),
            ),
            vector_entry(
                "device-retirement-signed-by-a-second-key",
                2,
                value(&build_device_retirement(&key(2), ALICE, &kid_of(1), T1).unwrap()),
            ),
            vector_entry(
                "agent-link",
                1,
                value(&build_agent_record(&key(1), ALICE, &agent, T1, Some("helper")).unwrap()),
            ),
            vector_entry(
                "agent-retirement",
                1,
                value(&build_agent_retirement(&key(1), ALICE, &agent, T2).unwrap()),
            ),
        ]
    }

    fn folds() -> Vec<serde_json::Value> {
        fold_cases()
            .into_iter()
            .map(|case| {
                json!({
                    "name": case.name,
                    "at": case.at,
                    "deviceRecords": case.device_records,
                    "agentRecords": case.agent_records,
                    "liveDeviceKids": case.live_device_kids,
                    "liveAgentDids": case.live_agent_dids,
                })
            })
            .collect()
    }

    fn build_fixtures_json() -> serde_json::Value {
        json!({
            "description": "Identity records a person publishes in their own AT Protocol repository. `at.freeq.deviceKey` announces a signing key a device holds, or retires one; `at.freeq.agentKey` announces a bot the account claims as its own, or retires that claim. `bindingSig` is an ed25519 signature, base64url without padding, over the UTF-8 bytes of the JCS (RFC 8785) canonical form of the record with its `bindingSig` field removed, and `signedBytes` is that canonical form. This is the recipe every freeq document signature uses: chat documents (freeq-sdk/src/chatsig.rs), task events (freeq-sdk/src/act.rs), the bot certificate (freeq-bot-id/src/main.rs, verified in freeq-server/src/connection/provenance.rs and minted in TypeScript by freeq-bot-kit-js/src/delegation.ts) and policy credentials (freeq-server/src/policy/credentials.rs). Absent fields are absent rather than null, so they are not in the canonical form, and `kid` is base64url-nopad(sha256(raw 32-byte ed25519 public key)[0..16]). Every implementation must rebuild each vector's `record`, `signedBytes` and `bindingSig` from its `seed`, and must fold each case's records at its `at` into exactly `liveDeviceKids` and `liveAgentDids`.",
            "vectors": vectors(),
            "folds": folds(),
        })
    }

    /// Regenerate spec/identity-record-vectors.json. Run manually:
    /// `cargo test -p freeq-sdk generate_identity_record_vectors -- --ignored`
    #[test]
    #[ignore]
    fn generate_identity_record_vectors() {
        let json = serde_json::to_string_pretty(&build_fixtures_json()).unwrap();
        std::fs::create_dir_all(fixtures_path().parent().unwrap()).unwrap();
        std::fs::write(fixtures_path(), json + "\n").unwrap();
    }

    /// The committed fixture file must be exactly what this implementation
    /// produces — the cross-language byte-compatibility contract.
    #[test]
    fn committed_identity_record_vectors_are_reproducible() {
        let on_disk = std::fs::read_to_string(fixtures_path()).expect(
            "spec/identity-record-vectors.json missing — run generate_identity_record_vectors",
        );
        let on_disk: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(on_disk, build_fixtures_json());
    }

    /// …and the fold cases in the file are run, not just compared: the file
    /// states what the records fold to, and this is the run that proves it.
    #[test]
    fn the_committed_fold_cases_run_from_the_file() {
        let spec: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixtures_path()).unwrap()).unwrap();
        let cases = spec["folds"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let device = case["deviceRecords"].as_array().unwrap();
            let agent = case["agentRecords"].as_array().unwrap();
            let at = instant(case["at"].as_str().unwrap());
            let kids: Vec<String> = fold_device_records(ALICE, device, at)
                .into_iter()
                .map(|k| k.kid)
                .collect();
            assert_eq!(
                json!(kids),
                case["liveDeviceKids"],
                "{name}: live device keys"
            );
            let dids: Vec<String> = fold_agent_records(ALICE, device, agent, at)
                .into_iter()
                .map(|l| l.agent_did)
                .collect();
            assert_eq!(
                json!(dids),
                case["liveAgentDids"],
                "{name}: live agent links"
            );
        }
    }

    // ─── reading from a PDS ─────────────────────────────────────────────

    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Serve `router` on an ephemeral loopback port and return its base URL.
    async fn spawn_stub(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        base
    }

    /// A stub PDS answering `listRecords` in two pages per collection: the
    /// first half of the records with a cursor, then the rest without one.
    fn list_records_router(
        did: &str,
        collections: HashMap<String, Vec<serde_json::Value>>,
    ) -> axum::Router {
        let did = did.to_string();
        let collections = Arc::new(collections);
        axum::Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let did = did.clone();
                let collections = collections.clone();
                async move {
                    if q.get("repo") != Some(&did)
                        || q.get("limit").map(String::as_str) != Some("100")
                    {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    let collection = q.get("collection").cloned().unwrap_or_default();
                    let records = collections.get(&collection).cloned().unwrap_or_default();
                    let half = records.len().div_ceil(2);
                    let (page, cursor) = match q.get("cursor").map(String::as_str) {
                        None => (&records[..half], Some("page-2")),
                        Some("page-2") => (&records[half..], None),
                        Some(_) => return Err(StatusCode::BAD_REQUEST),
                    };
                    let listed: Vec<serde_json::Value> = page
                        .iter()
                        .enumerate()
                        .map(|(i, value)| {
                            json!({
                                "uri": format!("at://{did}/{collection}/{i}"),
                                "cid": "bafyreistub",
                                "value": value,
                            })
                        })
                        .collect();
                    let mut body = json!({ "records": listed });
                    if let Some(cursor) = cursor {
                        body["cursor"] = json!(cursor);
                    }
                    Ok(axum::Json(body))
                }
            }),
        )
    }

    fn reader_for(did: &str, pds: Option<&str>) -> RecordReader<freeq_oauth::SharedClient> {
        let doc =
            crate::did::make_test_did_document_with_pds(did, &key(1).public_key_multibase(), pds);
        let resolver = DidResolver::static_map(HashMap::from([(did.to_string(), doc)]));
        RecordReader::new(resolver, freeq_oauth::SharedClient(reqwest::Client::new()))
    }

    #[tokio::test]
    async fn records_read_across_two_pages_fold_to_each_vector_live_set() {
        let spec: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixtures_path()).unwrap()).unwrap();
        for case in spec["folds"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let collections = HashMap::from([
                (
                    DEVICE_KEY_TYPE.to_string(),
                    case["deviceRecords"].as_array().unwrap().clone(),
                ),
                (
                    AGENT_KEY_TYPE.to_string(),
                    case["agentRecords"].as_array().unwrap().clone(),
                ),
            ]);
            let base = spawn_stub(list_records_router(ALICE, collections)).await;
            let reader = reader_for(ALICE, Some(&base));
            let at = instant(case["at"].as_str().unwrap());

            let listed = reader.list_records(ALICE, DEVICE_KEY_TYPE).await.unwrap();
            assert_eq!(
                &json!(listed),
                &case["deviceRecords"],
                "{name}: listed records"
            );

            let kids: Vec<String> = reader
                .live_device_keys(ALICE, at)
                .await
                .unwrap()
                .into_iter()
                .map(|k| k.kid)
                .collect();
            assert_eq!(
                json!(kids),
                case["liveDeviceKids"],
                "{name}: live device keys"
            );
            let dids: Vec<String> = reader
                .live_agent_links(ALICE, at)
                .await
                .unwrap()
                .into_iter()
                .map(|l| l.agent_did)
                .collect();
            assert_eq!(
                json!(dids),
                case["liveAgentDids"],
                "{name}: live agent links"
            );
        }
    }

    #[tokio::test]
    async fn a_did_with_no_pds_has_no_records() {
        let reader = reader_for(ALICE, None);
        assert!(
            reader
                .list_records(ALICE, DEVICE_KEY_TYPE)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .live_device_keys(ALICE, instant(T1))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .live_agent_links(ALICE, instant(T1))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_pds_answering_500_is_an_error() {
        let router = axum::Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let base = spawn_stub(router).await;
        let reader = reader_for(ALICE, Some(&base));
        assert!(reader.list_records(ALICE, DEVICE_KEY_TYPE).await.is_err());
        assert!(reader.live_device_keys(ALICE, instant(T1)).await.is_err());
        assert!(reader.live_agent_links(ALICE, instant(T1)).await.is_err());
    }
}
