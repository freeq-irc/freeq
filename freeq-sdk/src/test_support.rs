//! Test support: a stub account repository whose listed records come with
//! repository proofs, for tests of code that checks them. Built for this
//! crate's tests and, for other crates' tests, with the `test-support`
//! feature.
//!
//! Each proof is its own one-leaf tree under a commit signed by the stub's
//! secp256k1 repository key. Rkeys are chosen at MST layer 0, so a one-leaf
//! tree is a valid tree for the key it holds.

use std::collections::HashMap;

use atrium_repo::Multihash;
use atrium_repo::blockstore::{DAG_CBOR, SHA2_256};
use sha2::{Digest, Sha256};

use crate::crypto::PrivateKey;
use crate::did::DidDocument;
use crate::identity_records::{Cid, record_cid};

/// A stub repository for one account.
pub struct StubRepo {
    did: String,
    key: PrivateKey,
    listed: HashMap<String, Vec<serde_json::Value>>,
    proofs: HashMap<String, Vec<u8>>,
    reads: HashMap<String, usize>,
    next: usize,
}

impl StubRepo {
    /// A repository for `did` with a fresh repository key.
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_string(),
            key: PrivateKey::generate_secp256k1(),
            listed: HashMap::new(),
            proofs: HashMap::new(),
            reads: HashMap::new(),
            next: 0,
        }
    }

    /// The account this repository belongs to.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// A DID document naming the repository key and the PDS at `pds`.
    pub fn document(&self, pds: &str) -> DidDocument {
        crate::did::make_test_did_document_with_pds(
            &self.did,
            &self.key.public_key_multibase(),
            Some(pds),
        )
    }

    /// List `record` at a fresh rkey, with a proof that holds it; its uri.
    pub fn add(&mut self, collection: &str, record: &serde_json::Value) -> String {
        self.list(collection, record, record)
    }

    /// List `record` at a fresh rkey, served with a proof that holds `held`
    /// there instead; its uri.
    pub fn add_forged(
        &mut self,
        collection: &str,
        record: &serde_json::Value,
        held: &serde_json::Value,
    ) -> String {
        self.list(collection, record, held)
    }

    /// How many times the proof for the record at `uri` was asked for.
    pub fn proof_reads(&self, uri: &str) -> usize {
        // `at://<did>/<collection>/<rkey>`: the part after the DID.
        let path = uri.splitn(4, '/').nth(3).unwrap_or_default();
        self.reads.get(path).copied().unwrap_or(0)
    }

    /// Answer a request for this account at `path` with `query`: the status,
    /// content type and body, or `None` for a path it does not serve.
    pub fn respond(
        &mut self,
        path: &str,
        query: &HashMap<String, String>,
    ) -> Option<(u16, &'static str, Vec<u8>)> {
        match path {
            "/xrpc/com.atproto.repo.listRecords" => {
                if query.get("repo") != Some(&self.did) {
                    return None;
                }
                let collection = query.get("collection").cloned().unwrap_or_default();
                let records = self.listed.get(&collection).cloned().unwrap_or_default();
                let body = serde_json::to_vec(&serde_json::json!({ "records": records })).ok()?;
                Some((200, "application/json", body))
            }
            "/xrpc/com.atproto.sync.getRecord" => {
                if query.get("did") != Some(&self.did) {
                    return None;
                }
                let path = format!(
                    "{}/{}",
                    query.get("collection").cloned().unwrap_or_default(),
                    query.get("rkey").cloned().unwrap_or_default()
                );
                *self.reads.entry(path.clone()).or_default() += 1;
                Some(match self.proofs.get(&path) {
                    Some(car) => (200, "application/vnd.ipld.car", car.clone()),
                    None => (400, "text/plain", b"RecordNotFound".to_vec()),
                })
            }
            _ => None,
        }
    }

    fn list(
        &mut self,
        collection: &str,
        record: &serde_json::Value,
        held: &serde_json::Value,
    ) -> String {
        let rkey = self.layer_zero_rkey(collection);
        let uri = format!("at://{}/{collection}/{rkey}", self.did);
        let cid = record_cid(record).expect("a record encodes as DAG-CBOR");
        self.listed
            .entry(collection.to_string())
            .or_default()
            .push(serde_json::json!({ "uri": uri, "cid": cid.to_string(), "value": record }));
        let car = self.proof_holding(collection, &rkey, held);
        self.proofs.insert(format!("{collection}/{rkey}"), car);
        uri
    }

    fn layer_zero_rkey(&mut self, collection: &str) -> String {
        loop {
            let rkey = format!("3kstub{:x}", self.next);
            self.next += 1;
            // Layer 0: fewer than two leading zero bits.
            if Sha256::digest(format!("{collection}/{rkey}"))[0] >= 0x40 {
                return rkey;
            }
        }
    }

    fn proof_holding(&self, collection: &str, rkey: &str, record: &serde_json::Value) -> Vec<u8> {
        // A commit's `rev` is a TID: 13 characters, which the reader checks.
        const REV: &str = "3jzfcijpj2z2a";
        let record_bytes = serde_ipld_dagcbor::to_vec(record).expect("a record encodes");
        let record_cid = sha256_cid(&record_bytes);
        let node = mst_node(&format!("{collection}/{rkey}"), &record_cid);
        let node_cid = sha256_cid(&node);
        let unsigned = commit_bytes(&self.did, REV, &node_cid, None);
        let sig = self.key.sign(&unsigned);
        let commit = commit_bytes(&self.did, REV, &node_cid, Some(&sig));
        let commit_cid = sha256_cid(&commit);
        car_file(&[
            (commit_cid, commit),
            (node_cid, node),
            (record_cid, record_bytes),
        ])
    }
}

fn sha256_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(
        DAG_CBOR,
        Multihash::wrap(SHA2_256, &Sha256::digest(bytes)).expect("a SHA-256 digest fits"),
    )
}

fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    let major = major << 5;
    match n {
        0..24 => out.push(major | n as u8),
        24..256 => out.extend([major | 24, n as u8]),
        256..65536 => {
            out.push(major | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

fn cbor_text(text: &str, out: &mut Vec<u8>) {
    cbor_head(3, text.len(), out);
    out.extend(text.as_bytes());
}

fn cbor_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, bytes.len(), out);
    out.extend(bytes);
}

fn cbor_link(cid: &Cid, out: &mut Vec<u8>) {
    out.extend([0xd8, 42]);
    let mut bytes = vec![0];
    bytes.extend(cid.to_bytes());
    cbor_bytes(&bytes, out);
}

/// An MST node holding one leaf and no left subtree.
fn mst_node(key: &str, value: &Cid) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_head(5, 2, &mut out);
    cbor_text("e", &mut out);
    cbor_head(4, 1, &mut out);
    cbor_head(5, 4, &mut out);
    cbor_text("k", &mut out);
    cbor_bytes(key.as_bytes(), &mut out);
    cbor_text("p", &mut out);
    cbor_head(0, 0, &mut out);
    cbor_text("t", &mut out);
    out.push(0xf6);
    cbor_text("v", &mut out);
    cbor_link(value, &mut out);
    cbor_text("l", &mut out);
    out.push(0xf6);
    out
}

/// A repository commit for `did` whose tree root is `data`: the unsigned
/// form without `sig`, or the signed form with it. Keys in DAG-CBOR order.
fn commit_bytes(did: &str, rev: &str, data: &Cid, sig: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_head(5, if sig.is_some() { 6 } else { 5 }, &mut out);
    cbor_text("did", &mut out);
    cbor_text(did, &mut out);
    cbor_text("rev", &mut out);
    cbor_text(rev, &mut out);
    if let Some(sig) = sig {
        cbor_text("sig", &mut out);
        cbor_bytes(sig, &mut out);
    }
    cbor_text("data", &mut out);
    cbor_link(data, &mut out);
    cbor_text("prev", &mut out);
    out.push(0xf6);
    cbor_text("version", &mut out);
    cbor_head(0, 3, &mut out);
    out
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// A CAR file rooted at the first block.
fn car_file(blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let mut header = Vec::new();
    cbor_head(5, 2, &mut header);
    cbor_text("roots", &mut header);
    cbor_head(4, 1, &mut header);
    cbor_link(&blocks[0].0, &mut header);
    cbor_text("version", &mut header);
    cbor_head(0, 1, &mut header);
    let mut out = Vec::new();
    varint(header.len(), &mut out);
    out.extend(header);
    for (cid, data) in blocks {
        let cid = cid.to_bytes();
        varint(cid.len() + data.len(), &mut out);
        out.extend(cid);
        out.extend(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKey;
    use crate::identity_records::{DEVICE_KEY_TYPE, verify_proof};

    /// The stub's own proofs verify under the key its document names, so a
    /// test built on them is testing the code under test, not the stub.
    #[tokio::test]
    async fn a_stub_proof_verifies_under_the_stub_repository_key() {
        let did = "did:plc:stubrepository";
        let mut repo = StubRepo::new(did);
        let record = serde_json::json!({ "$type": DEVICE_KEY_TYPE, "label": "stub" });
        let uri = repo.add(DEVICE_KEY_TYPE, &record);
        let rkey = uri.rsplit('/').next().unwrap().to_string();
        let car = repo.proofs[&format!("{DEVICE_KEY_TYPE}/{rkey}")].clone();
        let doc = repo.document("http://unused.example");
        let key = PublicKey::from_multibase(
            doc.verification_method[0]
                .public_key_multibase
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        let outcome = verify_proof(
            &car,
            did,
            DEVICE_KEY_TYPE,
            &rkey,
            &record_cid(&record).unwrap(),
            &key,
        )
        .await;
        assert_eq!(
            format!("{outcome:?}"),
            "Ok(ProofOutcome { commit_did_matches: true, signature_valid: true, record_present: true })"
        );
    }
}
