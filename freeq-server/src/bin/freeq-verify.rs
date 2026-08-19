//! `freeq-verify` — offline verifier for a channel evidence bundle.
//!
//! Reads a bundle JSON (as produced by the `/api/v1/channels/{name}/evidence`
//! export endpoint), and checks two things with no server contact:
//!
//! 1. **Bundle integrity** — the server's signature over the canonical bundle
//!    (every field except `bundle_signature`), proving the export wasn't altered.
//! 2. **Per-message authenticity** — each message's client signature. A current
//!    signature (`ed25519:<kid>:<sig>`) is checked by rebuilding the document
//!    with the same `freeq_sdk::chatsig` builder the client signed with, using
//!    the key named by its `kid` from `keys`. A legacy bare-base64 signature is
//!    checked over the retired `{sender_did}\0{channel}\0{text}\0{timestamp}`
//!    canonical, using the key in `did_keys`.
//!
//! Prints a human summary and exits 0 only if everything verifies. On any failure
//! it prints `INVALID`/`TAMPERED` (to stdout, so tooling can scrape it) and exits 1.
//!
//! What this proves and does not: that the content was not altered *given* the
//! key material in the bundle is the author's, plus the server's own attestation
//! (the bundle signature). It does not prove the signing key belongs to the DID
//! it claims — that binding is asserted by the server at key-registration time,
//! and confirming it independently needs DID-document resolution (the trust-root
//! work), which this offline tool does not do.
//!
//! Usage: `freeq-verify [--verbose] <bundle.json>`

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::process::exit;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn decode_key(s: &str) -> Result<VerifyingKey, String> {
    let bytes = b64()
        .decode(s)
        .map_err(|e| format!("bad base64 public key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("not a valid ed25519 key: {e}"))
}

fn decode_sig(s: &str) -> Result<Signature, String> {
    let bytes = b64()
        .decode(s)
        .map_err(|e| format!("bad base64 signature: {e}"))?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&arr))
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing string field `{key}`"))
}

fn verify(bundle: &serde_json::Value, verbose: bool) -> Result<(), String> {
    // 1. Bundle integrity: server signature over the canonical bundle sans the
    //    signature field itself (the exact bytes the exporter signed).
    let server_key = decode_key(field(bundle, "server_public_key")?)?;
    let bundle_sig = decode_sig(field(bundle, "bundle_signature")?)?;
    let mut unsigned = bundle.clone();
    unsigned
        .as_object_mut()
        .ok_or("bundle is not a JSON object")?
        .remove("bundle_signature");
    let canonical =
        freeq_sdk::canonical::canonicalize(&unsigned).map_err(|e| format!("canonicalize: {e}"))?;
    server_key
        .verify(canonical.as_bytes(), &bundle_sig)
        .map_err(|_| "bundle signature INVALID — the export was altered".to_string())?;
    if verbose {
        println!("bundle signature VERIFIED (server key)");
    }

    // 2. Per-message authenticity: each client signature over its document.
    let empty = serde_json::Map::new();
    // Current signatures name their key by `kid`; legacy bare-base64 ones carry
    // no kid and fall back to the latest key per DID.
    let keys = bundle
        .get("keys")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let did_keys = bundle
        .get("did_keys")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let server_vk = decode_key(field(bundle, "server_public_key")?)?;
    let server_kid = freeq_sdk::sigtag::derive_kid(&server_vk);
    let messages = bundle
        .get("messages")
        .and_then(|v| v.as_array())
        .ok_or("missing array field `messages`")?;
    for (i, m) in messages.iter().enumerate() {
        // A message may carry no signature (an unsigned or guest message);
        // there is nothing to authenticate, and a guest row has no `sender_did`
        // — so this skip must come before that field is required.
        let Some(sig_tag) = m.get("signature").and_then(|v| v.as_str()) else {
            if verbose {
                println!("message {i}: unsigned — nothing to check");
            }
            continue;
        };
        let did = field(m, "sender_did")?;
        let channel = field(m, "channel")?;
        let text = field(m, "text")?;

        match freeq_sdk::sigtag::parse(sig_tag) {
            // Current format `ed25519:<kid>:<sig>`: rebuild the document with
            // the same builder the client signed with, so the check is
            // independent of whatever the server put in the bundle.
            Ok((kid, _)) => {
                let venue = freeq_sdk::chatsig::channel_venue(channel);
                let tags = m.get("tags").and_then(|v| v.as_object()).unwrap_or(&empty);
                let msgid = field(m, "msgid")?;
                let reply = tags
                    .get("+reply")
                    .or_else(|| tags.get("+draft/reply"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty());
                // A federated edit's link lives only in `replaces_msgid`, not
                // the tag map (S2S strips `+draft/edit`), so fall back to it —
                // the same rule the server's own rebuild follows.
                let edit = tags
                    .get("+draft/edit")
                    .and_then(|v| v.as_str())
                    .or_else(|| m.get("replaces_msgid").and_then(|v| v.as_str()))
                    .filter(|s| !s.is_empty());
                let coord: Vec<(&str, &str)> = tags
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                    .collect();
                let mut doc = freeq_sdk::chatsig::ChatDoc::message(did, msgid, &venue, text);
                if let Some(r) = reply {
                    doc = doc.with_reply(r);
                }
                if let Some(e) = edit {
                    doc = doc.with_edit(e);
                }
                doc = doc.with_coord(coord.iter().copied());
                let canonical = doc.canonical();

                let (vk, which) = if kid == server_kid {
                    (server_vk, "server key")
                } else {
                    let key_b64 = keys.get(kid).and_then(|v| v.as_str()).ok_or_else(|| {
                        format!("message {i} ({did}): no key in bundle for kid {kid}")
                    })?;
                    (decode_key(key_b64)?, "client key")
                };
                freeq_sdk::sigtag::verify_canonical(&canonical, sig_tag, &vk).map_err(|_| {
                    format!("message {i} ({did}): TAMPERED — signature does not verify")
                })?;
                if verbose {
                    println!("message {i} ({did}): VERIFIED ({which})");
                }
            }
            // Legacy bare-base64 over the retired `did\0channel\0text\0ts`
            // canonical, on pre-cutover history only.
            Err(_) => {
                let ts = m
                    .get("timestamp")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("message {i}: missing integer field `timestamp`"))?;
                let sig = decode_sig(sig_tag)?;
                let key_b64 = did_keys
                    .get(did)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("message {i}: no public key in did_keys for {did}"))?;
                let client_key = decode_key(key_b64)?;
                let msg_canonical = format!("{did}\0{channel}\0{text}\0{ts}");
                client_key
                    .verify(msg_canonical.as_bytes(), &sig)
                    .map_err(|_| {
                        format!("message {i} ({did}): TAMPERED — signature does not verify")
                    })?;
                if verbose {
                    println!("message {i} ({did}): VERIFIED (legacy client key)");
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let mut verbose = false;
    let mut path: Option<String> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--verbose" | "-v" => verbose = true,
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: freeq-verify [--verbose] <bundle.json>");
        exit(2);
    };

    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) => {
            println!("cannot read {path}: {e}");
            exit(1);
        }
    };
    let bundle: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            println!("INVALID — not valid JSON: {e}");
            exit(1);
        }
    };

    match verify(&bundle, verbose) {
        Ok(()) => {
            let count = bundle
                .get("messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            println!("✓ VERIFIED — bundle intact, {count} message(s) authentic");
        }
        Err(msg) => {
            println!("{msg}");
            exit(1);
        }
    }
}
