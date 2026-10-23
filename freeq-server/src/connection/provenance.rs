//! Provenance declaration verification.
//!
//! Today this only handles `FreeqBotDelegation/v1` certs. Other provenance
//! shapes (free-form JSON metadata) flow through unverified.
//!
//! The verifier matches the canonical form used by `freeq-bot-id` (see S3):
//! the cert is JCS-canonicalized with the `signature` field removed, then
//! the bytes are checked against an ed25519 signature using the creator's
//! registered MSGSIG public keys (looked up via `db.get_signing_key_set`).
//! A key its owner retired before the cert's own `created_at` is skipped: it
//! could not have signed a cert made after it was withdrawn.
//!
//! Verification is fully synchronous — no DID resolution, no network I/O,
//! no async — so it runs inside the IRC command handler without blocking.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::db::Db;

/// Outcome of a verification attempt.
#[derive(Debug, Clone)]
pub(super) struct VerificationOutcome {
    /// True only if the signature checked against a registered creator key.
    pub verified: bool,
    /// One-line reason. Always populated; useful for logs and the IRC NOTICE.
    pub reason: String,
    /// DID whose registered key signed off. Only set on successful verify.
    pub verifier_key_did: Option<String>,
}

impl VerificationOutcome {
    fn ok(creator_did: String) -> Self {
        Self {
            verified: true,
            reason: format!("Verified against creator key for {creator_did}"),
            verifier_key_did: Some(creator_did),
        }
    }
    fn unverified(reason: impl Into<String>) -> Self {
        Self {
            verified: false,
            reason: reason.into(),
            verifier_key_did: None,
        }
    }
}

/// If `json` is a `FreeqBotDelegation/v1` cert, attempt to verify it.
/// For any other shape, return an `unverified` outcome (caller can still store).
///
/// Returns `Err` only when `submitter_did` and `cert.bot_did` disagree —
/// that's a hard reject (someone is trying to register a cert that doesn't
/// belong to their own session).
pub(super) fn verify_provenance(
    json: &Value,
    submitter_did: &str,
    db: Option<&Db>,
) -> Result<VerificationOutcome, String> {
    // Free-form provenance (anything that's not FreeqBotDelegation/v1) is
    // accepted as unverified — preserves the v0 behavior for other shapes.
    let type_tag = json.get("type").and_then(|v| v.as_str());
    if type_tag != Some("FreeqBotDelegation/v1") {
        return Ok(VerificationOutcome::unverified(
            "Not a FreeqBotDelegation/v1 cert; stored as-is",
        ));
    }

    // Sanity: cert.bot_did MUST match the submitter (the SASL-authenticated
    // session). Mismatch means the wrong agent is presenting this cert.
    let bot_did = json.get("bot_did").and_then(|v| v.as_str()).unwrap_or("");
    if bot_did.is_empty() {
        return Ok(VerificationOutcome::unverified("Cert is missing bot_did"));
    }
    if bot_did != submitter_did {
        return Err(format!(
            "Cert bot_did ({bot_did}) does not match the authenticated session DID ({submitter_did})"
        ));
    }

    // Required fields for verification
    let creator_did = match json.get("creator_did").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return Ok(VerificationOutcome::unverified(
                "Cert is missing creator_did",
            ));
        }
    };
    let sig_b64 = match json.get("signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        // An unsigned certificate is proven only by the owner's agent record,
        // read after this reply, so the reason names how to publish one. A
        // bot that stays unverified is not read again until it reconnects.
        _ => {
            return Ok(VerificationOutcome::unverified(format!(
                "Unsigned certificate: unverified until the owner adds this bot \
                 ({bot_did}) under Settings → Agents in the freeq web app, or with \
                 `freeq-bot-id register`, and then restarts the bot"
            )));
        }
    };

    // Look up the creator's registered ed25519 signing key
    let Some(db) = db else {
        return Ok(VerificationOutcome::unverified(
            "Server has no DB; cannot look up creator key",
        ));
    };
    // Every key the creator has ever registered, not just the newest. A cert
    // is signed once and presented for months; the web client registers a
    // fresh MSGSIG key per session. Checking only the latest key rejected
    // every cert older than the owner's last browser tab.
    let registered = match db.get_signing_key_set(&creator_did) {
        Ok(keys) if keys.is_empty() => {
            return Ok(VerificationOutcome::unverified(format!(
                "No registered MSGSIG key for {creator_did}; creator must register one before signing"
            )));
        }
        Ok(keys) => keys,
        Err(e) => {
            return Ok(VerificationOutcome::unverified(format!(
                "DB error looking up signing key: {e}"
            )));
        }
    };

    // The cert says when it was made, so a key retired or expired before that
    // date is not a candidate — its owner had withdrawn it by then. A key retired later
    // still is: the cert was made while it was live, and retiring a key does
    // not undo what it signed beforehand. An undated cert cannot be judged
    // this way at all, so it is not verified.
    let Some(created_at) = json
        .get("created_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp())
    else {
        return Ok(VerificationOutcome::unverified(
            "Cert created_at is not RFC 3339",
        ));
    };
    // An expiry counts like a retirement: a key past it had stopped counting.
    let candidate_keys: Vec<[u8; 32]> = registered
        .iter()
        .filter(|row| row.removed_at.is_none_or(|removed| removed > created_at))
        .filter(|row| row.expires_at.is_none_or(|expires| expires > created_at))
        .map(|row| row.pubkey)
        .collect();
    if candidate_keys.is_empty() {
        return Ok(VerificationOutcome::unverified(format!(
            "Every registered key for {creator_did} was retired before this certificate was made"
        )));
    }

    // Build the canonical form: cert with the `signature` field removed.
    // This mirrors freeq-bot-id main.rs at sign-time, where `signature` is
    // `skip_serializing_if = Option::is_none` and is None when canonicalizing.
    let mut canonical_json = json.clone();
    if let Some(obj) = canonical_json.as_object_mut() {
        obj.remove("signature");
    }
    let canonical_bytes = match freeq_sdk::canonical::canonicalize(&canonical_json) {
        Ok(s) => s,
        Err(e) => {
            return Ok(VerificationOutcome::unverified(format!(
                "Failed to canonicalize cert for verification: {e}"
            )));
        }
    };

    let sig_bytes = match URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return Ok(VerificationOutcome::unverified(format!(
                "Signature is not valid base64url: {e}"
            )));
        }
    };
    if sig_bytes.len() != 64 {
        return Ok(VerificationOutcome::unverified(format!(
            "Signature has wrong length: expected 64, got {}",
            sig_bytes.len()
        )));
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = Signature::from_bytes(&sig_arr);

    let verified = candidate_keys.iter().any(|bytes| {
        VerifyingKey::from_bytes(bytes)
            .map(|vk| vk.verify(canonical_bytes.as_bytes(), &sig).is_ok())
            .unwrap_or(false)
    });
    if verified {
        Ok(VerificationOutcome::ok(creator_did))
    } else {
        Ok(VerificationOutcome::unverified(format!(
            "Signature did not verify against any of the creator's {} registered key(s)",
            candidate_keys.len()
        )))
    }
}

/// Annotate the provenance JSON with server-side verification metadata.
/// Mutates in place; reads stay backwards-compatible (extra fields only).
pub(super) fn annotate(json: &mut Value, outcome: &VerificationOutcome) {
    let Some(obj) = json.as_object_mut() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    obj.insert("_verified".to_string(), Value::Bool(outcome.verified));
    obj.insert(
        "_verification_reason".to_string(),
        Value::String(outcome.reason.clone()),
    );
    if outcome.verified {
        obj.insert("_verified_at".to_string(), Value::Number(now.into()));
    }
    if let Some(ref vk_did) = outcome.verifier_key_did {
        obj.insert(
            "_verifier_key_did".to_string(),
            Value::String(vk_did.clone()),
        );
    }
}

/// The (owner DID, bot DID) of a `FreeqBotDelegation/v1` certificate that
/// did not verify, whose owner's records may yet prove it.
pub(super) fn record_lookup_target(
    json: &Value,
    outcome: &VerificationOutcome,
) -> Option<(String, String)> {
    if outcome.verified
        || json.get("type").and_then(|v| v.as_str()) != Some("FreeqBotDelegation/v1")
    {
        return None;
    }
    let field = |name: &str| {
        json.get(name)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Some((field("creator_did")?, field("bot_did")?))
}

/// The outcome of finding the owner's live agent record at `uri`.
pub(super) fn record_outcome(uri: &str) -> VerificationOutcome {
    VerificationOutcome {
        verified: true,
        reason: format!("Owner's agent record {uri} names this bot"),
        verifier_key_did: None,
    }
}

/// How long a finished read of an owner's records is reused.
pub(crate) const OWNER_READ_REUSE: std::time::Duration = std::time::Duration::from_secs(10);

/// One owner's read gate: held for the length of a read, and holding the
/// last answer with when it was read.
pub(crate) type OwnerReadCell = std::sync::Arc<
    tokio::sync::Mutex<
        Option<(
            std::time::Instant,
            Vec<freeq_sdk::identity_records::ProvenAgentLink>,
        )>,
    >,
>;

/// The owner's live agent links, read from their account.
///
/// Every read of an owner's records goes through here, from a bot's connect
/// and from the hourly re-check. Any bot can name any DID as its owner, so
/// without a bound any connected bot could make this server read any
/// person's account as often as it sends PROVENANCE. Reads are bounded per
/// owner: one at a time (a second caller waits for the read in flight and
/// takes its answer), and an answer finished under `owner_read_reuse_ms`
/// ago (10 s) is reused, so a "fresh" read on connect is at most that old.
/// This is a mitigation for now (nap, 2026-09-28), not a limit per bot or
/// per connection. A failed read is not kept; the next caller tries again.
pub(super) async fn read_owner_links(
    state: &crate::server::SharedState,
    owner_did: &str,
) -> anyhow::Result<Vec<freeq_sdk::identity_records::ProvenAgentLink>> {
    let cell = state
        .owner_reads
        .lock()
        .entry(owner_did.to_string())
        .or_default()
        .clone();
    let reuse = std::time::Duration::from_millis(
        state
            .owner_read_reuse_ms
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    let mut last = cell.lock().await;
    if let Some((at, links)) = last.as_ref()
        && at.elapsed() < reuse
    {
        return Ok(links.clone());
    }
    // Both read fresh, at the owner's PDS, through the one record read the
    // clients use for their own lists.
    let devices = state.key_lookup.refresh_device_records(owner_did).await?;
    let agents = state.key_lookup.refresh_agent_records(owner_did).await?;
    let links = freeq_sdk::identity_records::proven_agent_links(
        owner_did,
        &devices,
        &agents,
        chrono::Utc::now(),
    );
    *last = Some((std::time::Instant::now(), links.clone()));
    state.owner_read_failures.lock().remove(owner_did);
    Ok(links)
}

/// Drop the read gates of owners with no read in flight and no answer still
/// inside the reuse window, so naming many owners does not grow the map.
fn prune_owner_reads(state: &crate::server::SharedState) {
    let reuse = std::time::Duration::from_millis(
        state
            .owner_read_reuse_ms
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    state.owner_reads.lock().retain(|_, cell| {
        std::sync::Arc::strong_count(cell) > 1
            || match cell.try_lock() {
                Ok(last) => last.as_ref().is_some_and(|(at, _)| at.elapsed() < reuse),
                Err(_) => true,
            }
    });
}

/// What a lookup carries to tell whether the stored declaration is still
/// the one it was started for: the declaration's sequence number, written by
/// the PROVENANCE that stored it. Not its value, since bot-kit resends the
/// same certificate on every connect and an unverified declaration carries
/// no time of its own.
pub(super) type LookupToken = u64;

/// Store `declaration` as `bot_did`'s, with a new sequence number, and
/// return that number.
pub(super) fn store_declaration(
    state: &crate::server::SharedState,
    bot_did: &str,
    declaration: Value,
) -> LookupToken {
    let seq = state
        .provenance_seq_next
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut declarations = state.provenance_declarations.lock();
    declarations.insert(bot_did.to_string(), declaration);
    state
        .provenance_seqs
        .lock()
        .insert(bot_did.to_string(), seq);
    seq
}

/// The token of `bot_did`'s stored declaration.
#[cfg(test)]
pub(super) fn lookup_token(
    state: &crate::server::SharedState,
    bot_did: &str,
) -> Option<LookupToken> {
    let _declarations = state.provenance_declarations.lock();
    state.provenance_seqs.lock().get(bot_did).copied()
}

/// Read the owner's agent and device records, proven (through the per-owner
/// gate, `read_owner_links`), and when a live link names the bot: keep the
/// result for the hourly re-check, mark the stored declaration verified if
/// it is still the one `token` names (a later PROVENANCE may have replaced
/// it meanwhile), and tell the session. Finding no link takes the bot off
/// the re-check list and changes nothing else. Every PROVENANCE reads the
/// records afresh, so a removal published since the last read counts on the
/// next connect.
pub(super) async fn verify_from_records(
    state: std::sync::Arc<crate::server::SharedState>,
    session_id: String,
    nick: String,
    owner_did: String,
    bot_did: String,
    token: LookupToken,
) {
    let key = (owner_did.clone(), bot_did.clone());
    let before = state.agent_links.lock().get(&key).cloned();
    let links = match read_owner_links(&state, &owner_did).await {
        Ok(links) => links,
        Err(e) => {
            tracing::debug!(owner = %owner_did, bot = %bot_did, error = %e, "Could not read the owner's agent records");
            return;
        }
    };
    let found = links
        .into_iter()
        .find(|l| l.link.agent_did == bot_did)
        .map(|l| l.uri);
    apply_link(&state, &session_id, &nick, &key, &token, before, found);
}

/// Act on a connect-time lookup of `key` (owner, bot) that found the link
/// at `found`, or none. `before` is the kept result when the lookup
/// started; `token` names the declaration it was started for.
pub(super) fn apply_link(
    state: &std::sync::Arc<crate::server::SharedState>,
    session_id: &str,
    nick: &str,
    key: &(String, String),
    token: &LookupToken,
    before: Option<(std::time::Instant, String)>,
    found: Option<String>,
) {
    let (owner_did, bot_did) = key;
    let Some(uri) = found else {
        // No link: nothing left for the hourly re-check to read. Removed
        // only if still the entry this lookup started from: a newer lookup
        // or a re-check may have written it meanwhile, and its answer is
        // the newer one.
        let gone = {
            let mut links = state.agent_links.lock();
            links.get(key) == before.as_ref() && links.remove(key).is_some()
        };
        if gone {
            close_delegated_sessions(
                state,
                key,
                "Delegation withdrawn: the owner's agent record no longer names this bot",
            );
        }
        return;
    };
    let outcome = record_outcome(&uri);
    let annotated = {
        let mut declarations = state.provenance_declarations.lock();
        let current = state.provenance_seqs.lock().get(bot_did).copied();
        match declarations.get_mut(bot_did) {
            Some(stored) if current == Some(*token) => {
                annotate(stored, &outcome);
                true
            }
            _ => false,
        }
    };
    {
        // A declaration marked verified here is kept for the hourly
        // re-check under the record it names, whatever the entry became
        // meanwhile: had a re-check removed it during this read, the bot
        // would stay verified and never be read again. An answer for a
        // declaration since replaced writes the entry only if it is still
        // the one this lookup started from.
        let mut links = state.agent_links.lock();
        if annotated || links.get(key) == before.as_ref() {
            links.insert(key.clone(), (std::time::Instant::now(), uri.clone()));
        }
    }
    if !annotated {
        return;
    }
    let reply = crate::irc::Message::from_server(
        &state.server_name,
        "NOTICE",
        vec![nick, &format!("Provenance verified: {}", outcome.reason)],
    );
    if let Some(tx) = state.connections.lock().get(session_id) {
        let _ = tx.try_send(format!("{reply}\r\n"));
    }
    tracing::info!(owner = %owner_did, bot = %bot_did, %uri, "Provenance verified from the owner's agent record");
}

/// A kept result: when the owner's record was found naming the bot, and
/// its uri.
type KeptLink = (std::time::Instant, String);

/// Re-read the owner's records for every bot verified from one at least
/// `older_than` ago, whether or not the bot is connected; each owner is read
/// once for all their due bots. A live link naming the bot renews the kept
/// result, under that link's record, which a declaration verified from the
/// earlier record then names too. None: the result is dropped and, if the bot's stored declaration
/// is still the one verified from that record, it is marked unverified; the
/// bot stays in any channel it is in. An entry a connect-time lookup changed
/// meanwhile is left as it is. A read that fails changes nothing, and the
/// next run tries again.
/// How many re-read periods an owner's records may stay unreadable before
/// their connected agents are closed as unverifiable.
pub(crate) const UNREADABLE_PERIODS_TO_CLOSE: u32 = 3;

pub(crate) async fn recheck_agent_links(
    state: &std::sync::Arc<crate::server::SharedState>,
    older_than: std::time::Duration,
) {
    prune_owner_reads(state);
    // Each due entry as it was when read here, grouped by owner, so an owner
    // with several bots is read once.
    let mut due: std::collections::BTreeMap<String, Vec<(String, KeptLink)>> =
        std::collections::BTreeMap::new();
    for ((owner_did, bot_did), kept) in state.agent_links.lock().iter() {
        if kept.0.elapsed() >= older_than {
            due.entry(owner_did.clone())
                .or_default()
                .push((bot_did.clone(), kept.clone()));
        }
    }
    for (owner_did, bots) in due {
        let delegated = has_delegated_sessions_of(state, &owner_did);
        // A lookup that failed says nothing; only an answer of no closes.
        if delegated && state.did_is_allowed_checked(&owner_did, None).await == Some(false) {
            for (bot_did, _) in &bots {
                close_delegated_sessions(
                    state,
                    &(owner_did.clone(), bot_did.clone()),
                    "Delegation withdrawn: the owner is no longer allowed here",
                );
            }
        }
        let links = match read_owner_links(state, &owner_did).await {
            Ok(links) => links,
            Err(e) => {
                tracing::debug!(owner = %owner_did, error = %e, "Could not re-read the owner's agent records");
                if delegated {
                    let since = *state
                        .owner_read_failures
                        .lock()
                        .entry(owner_did.clone())
                        .or_insert_with(std::time::Instant::now);
                    let window = std::time::Duration::from_secs(state.config.record_cache_secs)
                        * UNREADABLE_PERIODS_TO_CLOSE;
                    if since.elapsed() >= window {
                        for (bot_did, _) in &bots {
                            close_delegated_sessions(
                                state,
                                &(owner_did.clone(), bot_did.clone()),
                                "Delegation unverifiable: the owner's agent records could not be read",
                            );
                        }
                        state.owner_read_failures.lock().remove(&owner_did);
                    }
                }
                continue;
            }
        };
        for (bot_did, before) in bots {
            recheck_one(state, &owner_did, &bot_did, before, &links);
        }
    }
}

/// Act on a re-check of one (owner, bot) entry, `before` as it was read.
fn recheck_one(
    state: &std::sync::Arc<crate::server::SharedState>,
    owner_did: &str,
    bot_did: &str,
    before: (std::time::Instant, String),
    links: &[freeq_sdk::identity_records::ProvenAgentLink],
) {
    let key = (owner_did.to_string(), bot_did.to_string());
    let uri = before.1.clone();
    {
        // Changed only if still the entry this re-check read: a connect-time
        // lookup may have written a newer one meanwhile.
        let mut kept = state.agent_links.lock();
        if kept.get(&key) != Some(&before) {
            return;
        }
        if let Some(live) = links.iter().find(|l| l.link.agent_did == bot_did) {
            kept.insert(key, (std::time::Instant::now(), live.uri.clone()));
            drop(kept);
            if live.uri != uri {
                follow_record(state, bot_did, &uri, &live.uri);
            }
            return;
        }
        kept.remove(&key);
    }
    close_delegated_sessions(
        state,
        &key,
        "Delegation withdrawn: the owner's agent record no longer names this bot",
    );
    let verified_reason = record_outcome(&uri).reason;
    let reason = format!("Owner's agent record {uri} no longer names this bot");
    {
        let mut declarations = state.provenance_declarations.lock();
        let Some(stored) = declarations.get_mut(bot_did) else {
            return;
        };
        let from_this_record = stored.get("_verified").and_then(|v| v.as_bool()) == Some(true)
            && stored.get("_verification_reason").and_then(|v| v.as_str())
                == Some(verified_reason.as_str());
        if !from_this_record {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        if let Some(obj) = stored.as_object_mut() {
            obj.insert("_verified".to_string(), Value::Bool(false));
            obj.insert(
                "_verification_reason".to_string(),
                Value::String(reason.clone()),
            );
            obj.insert("_verified_at".to_string(), Value::Number(now.into()));
        }
    }
    tell_sessions_of(state, bot_did, &format!("Provenance unverified: {reason}"));
    tracing::info!(owner = %owner_did, bot = %bot_did, %uri, "Provenance unverified: the owner's agent record is gone");
}

/// Whether any connection was admitted on one of `owner_did`'s records.
fn has_delegated_sessions_of(state: &crate::server::SharedState, owner_did: &str) -> bool {
    state
        .delegated_sessions
        .lock()
        .values()
        .any(|(owner, _)| owner == owner_did)
}

/// Close every connection the allowlist admitted on the (owner, bot) link
/// `key`, telling it `reason`.
fn close_delegated_sessions(
    state: &std::sync::Arc<crate::server::SharedState>,
    key: &(String, String),
    reason: &str,
) {
    let sessions: Vec<String> = state
        .delegated_sessions
        .lock()
        .iter()
        .filter(|(_, link)| *link == key)
        .map(|(session_id, _)| session_id.clone())
        .collect();
    for session_id in sessions {
        super::close_session(state, &session_id, reason);
        tracing::info!(owner = %key.0, bot = %key.1, %session_id, %reason, "Closed a delegated connection");
    }
}

/// Send `text` as a NOTICE to every session `did` has connected here, if
/// any. Each map is locked on its own, one after another.
fn tell_sessions_of(state: &crate::server::SharedState, did: &str, text: &str) {
    let sessions: Vec<String> = state
        .did_sessions
        .lock()
        .get(did)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    for session_id in sessions {
        let Some(nick) = state
            .nick_to_session
            .lock()
            .get_nick(&session_id)
            .map(str::to_string)
        else {
            continue;
        };
        let reply =
            crate::irc::Message::from_server(&state.server_name, "NOTICE", vec![&nick, text]);
        if let Some(tx) = state.connections.lock().get(&session_id) {
            let _ = tx.try_send(format!("{reply}\r\n"));
        }
    }
}

/// The bot is live under a different record than the one it was verified
/// from (the owner removed it and added it again): if the stored
/// declaration is still verified from `old_uri`, name `new_uri` instead, so
/// that the next re-check recognises the declaration when the new record
/// goes.
fn follow_record(state: &crate::server::SharedState, bot_did: &str, old_uri: &str, new_uri: &str) {
    let old_reason = record_outcome(old_uri).reason;
    let mut declarations = state.provenance_declarations.lock();
    let Some(stored) = declarations.get_mut(bot_did) else {
        return;
    };
    let from_old_record = stored.get("_verified").and_then(|v| v.as_bool()) == Some(true)
        && stored.get("_verification_reason").and_then(|v| v.as_str()) == Some(old_reason.as_str());
    if let (true, Some(obj)) = (from_old_record, stored.as_object_mut()) {
        obj.insert(
            "_verification_reason".to_string(),
            Value::String(record_outcome(new_uri).reason),
        );
    }
}

/// The DID this agent claims to act for, but **only** when that claim was
/// cryptographically verified.
///
/// The distinction is the whole point. A delegation certificate is just JSON
/// until someone's key signs it: `bot_did` and `creator_did` are strings the
/// agent chose. Granting anything on an unverified claim would let any agent
/// name a channel operator as its owner and walk in — so this returns `None`
/// unless `_verified` is true, and callers get no way to ask the looser
/// question.
pub(super) fn verified_owner(
    state: &crate::server::SharedState,
    agent_did: &str,
) -> Option<String> {
    let declarations = state.provenance_declarations.lock();
    let cert = declarations.get(agent_did)?;
    if cert.get("_verified").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    // The cert must be about the DID we are asking about. Without this an
    // agent could present a certificate belonging to somebody else entirely.
    let bot_did = cert.get("bot_did").and_then(|v| v.as_str())?;
    if bot_did != agent_did {
        return None;
    }
    cert.get("creator_did")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod delegated_access_tests {
    use super::*;
    use serde_json::json;

    fn state_with(
        did: &str,
        cert: serde_json::Value,
    ) -> std::sync::Arc<crate::server::SharedState> {
        let state = crate::server::test_state();
        state
            .provenance_declarations
            .lock()
            .insert(did.to_string(), cert);
        state
    }

    const AGENT: &str = "did:key:zAgent";
    const OWNER: &str = "did:plc:owner";

    #[test]
    fn a_verified_certificate_names_its_owner() {
        let state = state_with(
            AGENT,
            json!({"bot_did": AGENT, "creator_did": OWNER, "_verified": true}),
        );
        assert_eq!(verified_owner(&state, AGENT), Some(OWNER.to_string()));
    }

    /// The attack this exists to stop: an agent declaring, without a
    /// signature, that a channel operator owns it.
    #[test]
    fn an_unsigned_claim_grants_nothing() {
        let state = state_with(
            AGENT,
            json!({"bot_did": AGENT, "creator_did": OWNER, "_verified": false}),
        );
        assert_eq!(verified_owner(&state, AGENT), None);

        // Absent flag is not a pass either.
        let state = state_with(AGENT, json!({"bot_did": AGENT, "creator_did": OWNER}));
        assert_eq!(verified_owner(&state, AGENT), None);
    }

    /// A cert that verifies but describes a different bot proves nothing about
    /// the presenter.
    #[test]
    fn a_certificate_about_someone_else_grants_nothing() {
        let state = state_with(
            AGENT,
            json!({"bot_did": "did:key:zSomeoneElse", "creator_did": OWNER, "_verified": true}),
        );
        assert_eq!(verified_owner(&state, AGENT), None);
    }

    #[test]
    fn no_certificate_at_all_grants_nothing() {
        let state = crate::server::test_state();
        assert_eq!(verified_owner(&state, AGENT), None);
    }
}
