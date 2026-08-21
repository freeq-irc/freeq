//! Verdicts for task events relayed from peer servers, and what follows from
//! each one.
//!
//! Two families of task event cross S2S as a `Tagmsg`: the act family
//! (`act-*` tags, signed under the act canonical — see [`freeq_sdk::act`])
//! and the older stopgap coordination family (`+freeq.at/event`, signed as a
//! chat-profile coordination document — see [`freeq_sdk::chatsig`]). This
//! module is where the receive side reaches its own verdict about each one.
//!
//! The verdict is three-way, the distinction is the RFC's central rule, and
//! each answer leads somewhere different:
//!
//! - **Valid** — the rebuilt document verifies against the signer's key.
//!   Stored, applied as far as the task's origin allows, and delivered.
//! - **Invalid** — the named key was found and the bytes do not verify.
//!   Evidence of tampering or forgery, never a fallback classification, and
//!   the one verdict that stops an event: not delivered, not stored.
//! - **Unverifiable** — everything else: no key on file, no key server
//!   configured for the origin, an algorithm this build does not know, a
//!   mandatory field missing. An outage or an old peer is not evidence about
//!   the sender, so none of these may ever read as invalid and none is ever
//!   refused. Neither stored nor shown: what this server cannot check it does
//!   not present as a task. Holding one for the key that would settle it is
//!   the queue's job, and the queue is a later step.
//!
//! The verdict itself consults no server state: the caller resolves the DM
//! recipient and supplies the key lookup, which is what makes the checker
//! provable against the committed vectors (`spec/act-signing-vectors.json`,
//! `spec/chat-signing-vectors.json`) without a server around it.

use std::collections::HashMap;

use crate::connection::messaging::NO_KEY_ON_FILE;

/// What this server concluded about one relayed task event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayVerdict {
    /// The rebuilt document verifies against the signer's key.
    Valid,
    /// The named key was found and the bytes do not verify.
    Invalid(&'static str),
    /// No verdict is reachable; the reason says why.
    Unverifiable(&'static str),
}

impl RelayVerdict {
    /// The word for the log's `verdict` field.
    pub(crate) fn label(self) -> &'static str {
        match self {
            RelayVerdict::Valid => "valid",
            RelayVerdict::Invalid(_) => "invalid",
            RelayVerdict::Unverifiable(_) => "unverifiable",
        }
    }

    /// The reason for the log's `reason` field.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            RelayVerdict::Valid => "signature verifies over the rebuilt document",
            RelayVerdict::Invalid(why) | RelayVerdict::Unverifiable(why) => why,
        }
    }
}

/// One structured line per relayed task event: this server's own verdict, and
/// therefore the record of why the event was stored, dropped or carried no
/// further.
///
/// `peer_declared_act` is what separates two failures that otherwise look
/// identical: a signature that fails because an old peer in the path predates
/// task events (and may have stripped tags it did not know) versus one that
/// fails on traffic a task-aware peer carried — the second is worth an
/// operator's attention, the first is a version skew.
///
/// Invalid logs at warn — a found key over bytes that do not verify is
/// evidence — and everything else at info.
pub(crate) fn log_relayed_verdict(
    verdict: RelayVerdict,
    event_id: &str,
    origin: &str,
    peer: &str,
    target: &str,
    peer_declared_act: bool,
) {
    match verdict {
        RelayVerdict::Invalid(_) => tracing::warn!(
            verdict = %verdict.label(),
            reason = %verdict.reason(),
            event_id = %event_id,
            origin = %origin,
            peer = %peer,
            target = %target,
            peer_declared_act,
            "Relayed task event checked"
        ),
        _ => tracing::info!(
            verdict = %verdict.label(),
            reason = %verdict.reason(),
            event_id = %event_id,
            origin = %origin,
            peer = %peer,
            target = %target,
            peer_declared_act,
            "Relayed task event checked"
        ),
    }
}

/// The identity a relayed task event's signature claims, and whose key the
/// lookup must use.
///
/// For the act family that is the signed document's own `from` tag — not the
/// S2S message's account stamp, which is the *relaying* server's assertion.
/// For the coordination family the document's `from` is not on the wire as a
/// tag at all; it is the account the origin stamped, which the caller passes
/// as `sender_did`.
pub(crate) fn claimed_signer<'a>(
    tags: &'a HashMap<String, String>,
    sender_did: Option<&'a str>,
) -> Option<&'a str> {
    if crate::connection::act::carries_act_tags(tags) {
        tags.get("+freeq.at/from")
            .or_else(|| tags.get("from"))
            .map(String::as_str)
    } else {
        sender_did
    }
}

/// Rebuild the venue the signer signed, from the delivery target.
///
/// Never the wire target itself: a channel is folded, and a DM binds the
/// sorted DID pair (`dm_recipient_did` is the caller's resolution of the wire
/// target — `None` when it does not resolve, which makes the event
/// unverifiable rather than wrong).
fn venue_for(target: &str, from_did: &str, dm_recipient_did: Option<&str>) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return Some(freeq_sdk::chatsig::channel_venue(target));
    }
    dm_recipient_did.map(|other| freeq_sdk::chatsig::dm_venue(from_did, other))
}

/// The coordination document a relayed `+freeq.at/event` TAGMSG's signature
/// covers, rebuilt from the wire tags exactly as local ingress builds it
/// (prefixed spellings only, `ref` falling back to `task-id`).
pub(crate) fn coordination_doc_from_tags<'a>(
    tags: &'a HashMap<String, String>,
    from: &'a str,
    event_id: &'a str,
    venue: &'a str,
    event_type: &'a str,
) -> freeq_sdk::chatsig::ChatDoc<'a> {
    let mut doc = freeq_sdk::chatsig::ChatDoc::coordination(from, event_id, venue, event_type);
    if let Some(payload) = tags.get("+freeq.at/payload") {
        doc = doc.with_payload(payload);
    }
    if let Some(reference) = tags
        .get("+freeq.at/ref")
        .or_else(|| tags.get("+freeq.at/task-id"))
    {
        doc = doc.with_ref(reference);
    }
    if let Some(evidence) = tags.get("+freeq.at/evidence-type") {
        doc = doc.with_evidence(evidence);
    }
    doc
}

/// The verdict for one relayed task event, of either family.
///
/// `tags` is the tag map as it arrived, `target` the message's delivery
/// target, `sender_did` the account the origin stamped on the S2S message,
/// and `dm_recipient_did` the caller's resolution of a non-channel target to
/// a local DID. `lookup` answers `(did, kid)` with a verifying key when one
/// is on file.
pub(crate) fn relayed_task_verdict<K>(
    tags: &HashMap<String, String>,
    target: &str,
    sender_did: Option<&str>,
    dm_recipient_did: Option<&str>,
    lookup: K,
) -> RelayVerdict
where
    K: Fn(&str, &str) -> Option<ed25519_dalek::VerifyingKey>,
{
    let is_act = crate::connection::act::carries_act_tags(tags);
    if !is_act && !tags.contains_key("+freeq.at/event") {
        return RelayVerdict::Unverifiable("not a task event");
    }

    // ── the mandatory fields, each named when missing ──
    let Some(from) = claimed_signer(tags, sender_did) else {
        return RelayVerdict::Unverifiable("missing from: the event names no actor DID");
    };
    let Some(event_id) = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .map(String::as_str)
    else {
        return RelayVerdict::Unverifiable("missing id: the event carries no signer-minted id");
    };
    let Some(venue) = venue_for(target, from, dm_recipient_did) else {
        return RelayVerdict::Unverifiable(
            "missing target: no venue resolves for the delivery target",
        );
    };

    // ── the signature, and the key it names ──
    let Some(sig_tag) = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))
        .map(String::as_str)
    else {
        return RelayVerdict::Unverifiable("the event carries no signature");
    };
    let kid = match freeq_sdk::sigtag::parse(sig_tag) {
        Ok((kid, _)) => kid,
        Err(freeq_sdk::sigtag::SigError::UnsupportedAlgorithm(_)) => {
            return RelayVerdict::Unverifiable("unsupported signature algorithm");
        }
        Err(_) => return RelayVerdict::Unverifiable("sig tag is not alg:kid:sig"),
    };
    let Some(key) = lookup(from, kid) else {
        return RelayVerdict::Unverifiable(NO_KEY_ON_FILE);
    };

    // ── the rebuilt document against the key ──
    if is_act {
        let pairs = tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        match freeq_sdk::act::verify_act(pairs, &venue, event_id, sig_tag, &key) {
            Ok(()) => RelayVerdict::Valid,
            Err(freeq_sdk::act::ActSigError::SigInvalid) => {
                RelayVerdict::Invalid("signature does not verify over the act document")
            }
            // A kid the key does not hash to, a format problem, no act tags:
            // none of these is evidence about the signed bytes.
            Err(_) => RelayVerdict::Unverifiable("unusable signature tag"),
        }
    } else {
        let event_type = tags
            .get("+freeq.at/event")
            .expect("family checked above")
            .as_str();
        let doc = coordination_doc_from_tags(tags, from, event_id, &venue, event_type);
        match doc.verify(sig_tag, &key) {
            Ok(()) => RelayVerdict::Valid,
            Err(e) if e.is_unverifiable() => RelayVerdict::Unverifiable("unusable signature tag"),
            Err(_) => {
                RelayVerdict::Invalid("signature does not verify over the coordination document")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn spec(file: &str) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../spec")
            .join(file);
        serde_json::from_str(&std::fs::read_to_string(path).expect("spec file on disk"))
            .expect("spec file parses")
    }

    fn key_of(vector: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
        let bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(vector["publicKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap()
    }

    /// A lookup holding exactly one key, under one (did, kid).
    fn one_key(
        did: &str,
        kid: &str,
        key: ed25519_dalek::VerifyingKey,
    ) -> impl Fn(&str, &str) -> Option<ed25519_dalek::VerifyingKey> {
        let did = did.to_string();
        let kid = kid.to_string();
        move |d, k| (d == did && k == kid).then_some(key)
    }

    /// The wire tag map an act vector's message would carry: the vector's own
    /// tags, plus the event id and the real signature — exactly what the
    /// sender puts on a TAGMSG.
    fn act_wire_tags(vector: &serde_json::Value) -> HashMap<String, String> {
        let mut tags: HashMap<String, String> = vector["tags"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            vector["id"].as_str().unwrap().to_string(),
        );
        tags.insert(
            "+freeq.at/sig".to_string(),
            vector["sigTag"].as_str().unwrap().to_string(),
        );
        tags
    }

    /// The delivery target and resolved DM recipient for a vector's venue: a
    /// channel venue is its own target; a `dm:` venue is delivered to a
    /// `did:` target that the receive side resolved.
    fn delivery_for(vector: &serde_json::Value, from: &str) -> (String, Option<String>) {
        let venue = vector["target"].as_str().unwrap();
        match venue.strip_prefix("dm:") {
            None => (venue.to_string(), None),
            Some(pair) => {
                let other = pair
                    .split(',')
                    .find(|did| *did != from)
                    .expect("a DM venue names two DIDs");
                (other.to_string(), Some(other.to_string()))
            }
        }
    }

    #[test]
    fn every_act_vector_rebuilds_byte_for_byte_and_verifies_valid() {
        let fixtures = spec("act-signing-vectors.json");
        for vector in fixtures["vectors"].as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let tags = act_wire_tags(vector);
            let venue = vector["target"].as_str().unwrap();
            let msgid = vector["id"].as_str().unwrap();

            // The committed canonical, rebuilt from the wire tags exactly.
            let rebuilt = freeq_sdk::act::act_canonical(
                tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                venue,
                msgid,
            )
            .unwrap();
            assert_eq!(rebuilt, vector["canonical"].as_str().unwrap(), "{name}");

            let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
            let (target, dm_recipient) = delivery_for(vector, from);
            let verdict = relayed_task_verdict(
                &tags,
                &target,
                // The relay origin's account stamp: irrelevant to an act
                // event's key lookup, which uses the document's own from.
                Some("did:plc:relaystamp"),
                dm_recipient.as_deref(),
                one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
            );
            assert_eq!(verdict, RelayVerdict::Valid, "{name}");
        }
    }

    #[test]
    fn a_tampered_act_tag_is_invalid() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.insert(
            "+freeq.at/act-title".to_string(),
            "Cite 4 sources on X".to_string(),
        );
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert!(
            matches!(verdict, RelayVerdict::Invalid(_)),
            "tampering is evidence, and only tampering reads as invalid: {verdict:?}"
        );
    }

    #[test]
    fn an_unknown_kid_is_unverifiable_never_invalid() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
    }

    #[test]
    fn a_missing_from_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.remove("+freeq.at/from");
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            // The account stamp does not stand in for an act event's from:
            // the document names its own actor or it names nobody.
            Some("did:plc:relaystamp"),
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("from"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_missing_id_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("id"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn an_unresolvable_dm_target_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        // A DM delivery whose recipient this server cannot resolve to a DID:
        // no venue, no document, no verdict about the sender.
        let verdict = relayed_task_verdict(&tags, "somenick", None, None, |_, _| None);
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("target"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_algorithm_is_unverifiable() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.insert("+freeq.at/sig".to_string(), "rsa:somekid:AAAA".to_string());
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(
            verdict,
            RelayVerdict::Unverifiable("unsupported signature algorithm"),
            "a newer signer is not a forger"
        );
    }

    // ── the stopgap coordination family ──

    /// The wire tag map a coordination vector's TAGMSG would carry.
    fn coordination_wire_tags(vector: &serde_json::Value) -> HashMap<String, String> {
        let input = vector["input"].as_object().unwrap();
        let mut tags = HashMap::new();
        tags.insert(
            "+freeq.at/event".to_string(),
            input["eventType"].as_str().unwrap().to_string(),
        );
        if let Some(payload) = input.get("payload").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/payload".to_string(), payload.to_string());
        }
        if let Some(reference) = input.get("ref").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/ref".to_string(), reference.to_string());
        }
        if let Some(evidence) = input.get("evidence").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/evidence-type".to_string(), evidence.to_string());
        }
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            input["msgid"].as_str().unwrap().to_string(),
        );
        tags.insert(
            "+freeq.at/sig".to_string(),
            vector["sigTag"].as_str().unwrap().to_string(),
        );
        tags
    }

    fn coordination_vectors(fixtures: &serde_json::Value) -> Vec<&serde_json::Value> {
        let vectors = fixtures["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["name"].as_str().unwrap().starts_with("coordination"))
            .collect::<Vec<_>>();
        assert!(
            !vectors.is_empty(),
            "the spec file carries coordination vectors"
        );
        vectors
    }

    #[test]
    fn every_coordination_vector_rebuilds_byte_for_byte_and_verifies_valid() {
        let fixtures = spec("chat-signing-vectors.json");
        for vector in coordination_vectors(&fixtures) {
            let name = vector["name"].as_str().unwrap();
            let input = &vector["input"];
            let tags = coordination_wire_tags(vector);
            let from = input["from"].as_str().unwrap();
            let target = input["target"].as_str().unwrap();

            let venue = freeq_sdk::chatsig::channel_venue(target);
            let doc = coordination_doc_from_tags(
                &tags,
                from,
                input["msgid"].as_str().unwrap(),
                &venue,
                input["eventType"].as_str().unwrap(),
            );
            assert_eq!(
                doc.canonical(),
                vector["canonical"].as_str().unwrap(),
                "{name}"
            );

            let verdict = relayed_task_verdict(
                &tags,
                target,
                Some(from),
                None,
                one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
            );
            assert_eq!(verdict, RelayVerdict::Valid, "{name}");
        }
    }

    #[test]
    fn a_tampered_coordination_payload_is_invalid() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.insert("+freeq.at/payload".to_string(), "%7B%7D".to_string());
        let from = input["from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(from),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert!(
            matches!(verdict, RelayVerdict::Invalid(_)),
            "an altered covered field is evidence: {verdict:?}"
        );
    }

    #[test]
    fn a_coordination_event_with_no_key_on_file_is_unverifiable() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let verdict = relayed_task_verdict(
            &coordination_wire_tags(vector),
            input["target"].as_str().unwrap(),
            Some(input["from"].as_str().unwrap()),
            None,
            |_, _| None,
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
    }

    #[test]
    fn a_coordination_event_naming_no_sender_is_unverifiable_and_names_from() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        // A guest's relay, or an old peer omitting the account field: the
        // document's from is unknowable, so there is nothing to rebuild.
        let verdict = relayed_task_verdict(
            &coordination_wire_tags(vector),
            input["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("from"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_coordination_event_with_no_id_is_unverifiable_and_names_id() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(input["from"].as_str().unwrap()),
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("id"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_coordination_event_with_an_unknown_algorithm_is_unverifiable() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.insert("+freeq.at/sig".to_string(), "rsa:somekid:AAAA".to_string());
        let from = input["from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(from),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(
            verdict,
            RelayVerdict::Unverifiable("unsupported signature algorithm")
        );
    }

    /// The act family looks its key up under the document's own `from` tag,
    /// never under the account the relaying server stamped — the signature
    /// claims the document's identity, and a key filed under anyone else's
    /// name must stay a miss.
    #[test]
    fn act_key_lookup_uses_the_documents_own_from_not_the_account_stamp() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        // The right key, but filed under the account stamp's DID: a miss.
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            Some("did:plc:relaystamp"),
            None,
            one_key(
                "did:plc:relaystamp",
                vector["kid"].as_str().unwrap(),
                key_of(vector),
            ),
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
        // Filed under the document's from: found, and valid.
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            Some("did:plc:relaystamp"),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(verdict, RelayVerdict::Valid);
    }
}
