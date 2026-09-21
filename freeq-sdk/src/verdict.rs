//! What a client shows for a message's signature, and the words for it.
//!
//! The words live in `spec/verdict-model.json`, which both SDKs read, so a
//! change to a sentence is one edit that every client picks up.

use crate::key_lookup::KeySource;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// What checking a message's signature came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictState {
    /// Signed on the sender's device, under a key the check found.
    Device,
    /// Signed by the server on the sender's behalf.
    Server,
    /// No signature.
    Unsigned,
    /// Signed, but no source holds the key.
    Unverifiable,
    /// Signed, and the signature does not check.
    Invalid,
    /// Signed with a key retired before the message's time.
    Retired,
    /// Signed, and the key is still being looked up.
    Pending,
}

impl VerdictState {
    pub const ALL: [VerdictState; 7] = [
        VerdictState::Device,
        VerdictState::Server,
        VerdictState::Unsigned,
        VerdictState::Unverifiable,
        VerdictState::Invalid,
        VerdictState::Retired,
        VerdictState::Pending,
    ];

    /// The state's name in the model file.
    pub fn name(self) -> &'static str {
        match self {
            VerdictState::Device => "device",
            VerdictState::Server => "server",
            VerdictState::Unsigned => "unsigned",
            VerdictState::Unverifiable => "unverifiable",
            VerdictState::Invalid => "invalid",
            VerdictState::Retired => "retired",
            VerdictState::Pending => "pending",
        }
    }
}

/// Where a device key's standing comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyLayer {
    /// The sender's server, or their DID document, vouches for the key.
    Vouched,
    /// The key is published in the sender's identity record.
    Published,
}

impl KeyLayer {
    pub const ALL: [KeyLayer; 2] = [KeyLayer::Vouched, KeyLayer::Published];

    /// The layer's name in the model file.
    pub fn name(self) -> &'static str {
        match self {
            KeyLayer::Vouched => "vouched",
            KeyLayer::Published => "published",
        }
    }
}

/// A message's verdict: the state, the layer for a device signature, and
/// the key the check used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub state: VerdictState,
    pub layer: Option<KeyLayer>,
    pub kid: Option<String>,
    pub key_source: Option<KeySource>,
}

/// The word on the mark.
pub fn mark() -> &'static str {
    &model().mark
}

/// The sentence for a verdict. A layer counts only for `Device`.
pub fn sentence(state: VerdictState, layer: Option<KeyLayer>) -> &'static str {
    let model = model();
    if let (VerdictState::Device, Some(layer)) = (state, layer) {
        return &model.layers[layer.name()];
    }
    &model.states[state.name()].sentence
}

// ─── checking a received line ───────────────────────────────────────────

/// What a received line's signature covers, rebuilt from the wire.
#[derive(Debug, Clone)]
pub(crate) struct Signed {
    /// Who the document says signed it; the key is looked up under this DID.
    pub did: String,
    pub kid: String,
    pub sig_tag: String,
    /// The line's id: what a late verdict is filed under, and whose ULID
    /// time dates the signature.
    pub msgid: String,
    pub doc: SignedDoc,
}

#[derive(Debug, Clone)]
pub(crate) enum SignedDoc {
    /// A chat document's canonical bytes (message, mutation, coordination).
    Chat(String),
    /// An act event: every tag on the line, the venue and the event id, for
    /// `act::verify_act`.
    Act {
        tags: Vec<(String, String)>,
        venue: String,
        id: String,
    },
}

/// What can be said about a received line before any key is fetched.
#[derive(Debug, Clone)]
pub(crate) enum FirstLook {
    Unsigned,
    /// Signed in a form that cannot be checked: a tag that is not
    /// `alg:kid:sig`, an algorithm this build does not know, or a document
    /// the line does not carry enough to rebuild.
    Unverifiable(Option<String>),
    Check(Signed),
}

/// The line a first look is taken of.
pub(crate) struct Line<'a> {
    pub tags: &'a std::collections::HashMap<String, String>,
    /// The wire target: a channel, our nick, or (our echo) the peer's.
    pub target: &'a str,
    /// The wire body of a PRIVMSG or NOTICE; `None` for a TAGMSG.
    pub body: Option<&'a str>,
    /// This session's DID.
    pub own_did: Option<&'a str>,
    /// The DID a DM's wire target stands for, when the target is a nick.
    pub target_did: Option<&'a str>,
}

/// Rebuild what a received line's signature covers, the way the server
/// rebuilds it (`freeq-server/src/events.rs`, `message_canonical`).
pub(crate) fn first_look(line: &Line<'_>) -> FirstLook {
    let tag = |name: &str| line.tags.get(name).map(String::as_str);
    let Some(sig_tag) = tag(crate::sigtag::SIG_TAG).or_else(|| tag("freeq.at/sig")) else {
        return FirstLook::Unsigned;
    };
    let Ok((kid, _)) = crate::sigtag::parse(sig_tag) else {
        return FirstLook::Unverifiable(None);
    };
    let kid = kid.to_string();
    let unverifiable = || FirstLook::Unverifiable(Some(kid.clone()));
    let pairs = || line.tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));

    // An act event: the signer is the `from` tag, the id its own.
    if line.body.is_none()
        && let Some(act) = crate::act::parse_event(pairs())
    {
        let Some(did) = tag("+freeq.at/from").or_else(|| tag("freeq.at/from")) else {
            return unverifiable();
        };
        let Some(venue) = venue_of(line.target, did, line) else {
            return unverifiable();
        };
        return FirstLook::Check(Signed {
            did: did.to_string(),
            kid,
            sig_tag: sig_tag.to_string(),
            msgid: act.event_id.clone(),
            doc: SignedDoc::Act {
                tags: pairs()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                venue,
                id: act.event_id,
            },
        });
    }

    // Everything else names its signer in the server's `account` tag.
    let Some(did) = tag("account").filter(|d| crate::address::is_did(d)) else {
        return unverifiable();
    };
    let Some(venue) = venue_of(line.target, did, line) else {
        return unverifiable();
    };
    let event_id =
        tag(crate::chatsig::EVENT_ID_TAG).or_else(|| tag(crate::chatsig::EVENT_ID_TAG_BARE));
    let doc = match line.body {
        Some(body) => {
            let Some(msgid) = tag("msgid").or(event_id) else {
                return unverifiable();
            };
            let mut doc = crate::chatsig::ChatDoc::message(did, msgid, &venue, body);
            if let Some(reply) = tag("+reply").or_else(|| tag("+draft/reply")) {
                doc = doc.with_reply(reply);
            }
            if let Some(edit) = tag("+draft/edit") {
                doc = doc.with_edit(edit);
            }
            (msgid, doc.with_coord(pairs()).canonical())
        }
        None => {
            let Some(msgid) = event_id.or(tag("msgid")) else {
                return unverifiable();
            };
            if let Some((kind, subject, emoji)) = crate::client::mutation_in(line.tags) {
                let mut doc = crate::chatsig::ChatDoc::mutation(kind, did, msgid, &venue, &subject);
                if let Some(emoji) = emoji.as_deref() {
                    doc = doc.with_emoji(emoji);
                }
                (msgid, doc.canonical())
            } else if let Some(event) = tag("+freeq.at/event") {
                let mut doc = crate::chatsig::ChatDoc::coordination(did, msgid, &venue, event);
                if let Some(payload) = tag("+freeq.at/payload") {
                    doc = doc.with_payload(payload);
                }
                if let Some(reference) = tag("+freeq.at/ref").or_else(|| tag("+freeq.at/task-id")) {
                    doc = doc.with_ref(reference);
                }
                if let Some(evidence) = tag("+freeq.at/evidence-type") {
                    doc = doc.with_evidence(evidence);
                }
                (msgid, doc.canonical())
            } else {
                // A signed TAGMSG of no kind a document is defined for.
                return unverifiable();
            }
        }
    };
    FirstLook::Check(Signed {
        did: did.to_string(),
        kid,
        sig_tag: sig_tag.to_string(),
        msgid: doc.0.to_string(),
        doc: SignedDoc::Chat(doc.1),
    })
}

/// The venue a line was signed for: a channel folded, or the DID pair of a
/// DM — the signer and whoever the other end is.
fn venue_of(target: &str, signer: &str, line: &Line<'_>) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return Some(crate::chatsig::channel_venue(target));
    }
    let other = if line.own_did == Some(signer) {
        // Our own echo: the other end is the peer the target names.
        if target.starts_with("did:") {
            target
        } else {
            line.target_did?
        }
    } else {
        line.own_did?
    };
    Some(crate::chatsig::dm_venue(signer, other))
}

/// Whether `signed` checks under `key`: `Ok(true)` when it does,
/// `Ok(false)` when the key it names does not verify the bytes (a forgery or
/// a tamper), and `Err` when it cannot be checked with this key at all.
pub(crate) fn check(signed: &Signed, key: &[u8; 32]) -> Result<bool, ()> {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return Err(());
    };
    match &signed.doc {
        SignedDoc::Chat(canonical) => {
            match crate::sigtag::verify_canonical(canonical, &signed.sig_tag, &key) {
                Ok(()) => Ok(true),
                Err(crate::sigtag::SigError::Invalid) => Ok(false),
                Err(_) => Err(()),
            }
        }
        SignedDoc::Act { tags, venue, id } => {
            let pairs = tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));
            match crate::act::verify_act(pairs, venue, id, &signed.sig_tag, &key) {
                Ok(()) => Ok(true),
                Err(crate::act::ActSigError::SigInvalid) => Ok(false),
                Err(_) => Err(()),
            }
        }
    }
}

#[derive(Deserialize)]
struct Model {
    mark: String,
    states: HashMap<String, StateEntry>,
    layers: HashMap<String, String>,
}

#[derive(Deserialize)]
struct StateEntry {
    sentence: String,
}

fn model() -> &'static Model {
    static MODEL: OnceLock<Model> = OnceLock::new();
    MODEL.get_or_init(|| {
        serde_json::from_str(include_str!("../../spec/verdict-model.json"))
            .expect("spec/verdict-model.json must parse — it is compiled into this binary")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const FILE: &str = include_str!("../../spec/verdict-model.json");

    fn file() -> serde_json::Value {
        serde_json::from_str(FILE).unwrap()
    }

    #[test]
    fn every_state_reads_its_sentence_from_the_file() {
        let file = file();
        let states = file["states"].as_object().unwrap();
        let mut names: Vec<&str> = states.keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut ours: Vec<&str> = VerdictState::ALL.iter().map(|s| s.name()).collect();
        ours.sort_unstable();
        assert_eq!(names, ours, "the file and the enum name the same states");

        for state in VerdictState::ALL {
            assert_eq!(
                sentence(state, None),
                file["states"][state.name()]["sentence"].as_str().unwrap(),
                "{}",
                state.name()
            );
        }
        for layer in KeyLayer::ALL {
            assert_eq!(
                sentence(VerdictState::Device, Some(layer)),
                file["layers"][layer.name()].as_str().unwrap()
            );
        }
        assert_eq!(
            file["states"]["device"]["layers"],
            serde_json::json!(["vouched", "published"])
        );
        assert_eq!(mark(), file["mark"].as_str().unwrap());
    }

    #[test]
    fn a_layer_counts_only_for_a_device_signature() {
        assert_eq!(
            sentence(VerdictState::Server, Some(KeyLayer::Published)),
            sentence(VerdictState::Server, None)
        );
    }

    #[test]
    fn the_words_are_the_ruled_ones() {
        assert_eq!(mark(), "signed");
        assert_eq!(
            sentence(VerdictState::Device, Some(KeyLayer::Vouched)),
            "Signed on the sender’s device. Key vouched for by their server."
        );
        assert_eq!(
            sentence(VerdictState::Device, Some(KeyLayer::Published)),
            "Signed on the sender’s device. Key published in their identity record."
        );
        assert_eq!(
            sentence(VerdictState::Retired, None),
            "Signed after this key was retired."
        );
        assert_eq!(
            sentence(VerdictState::Pending, None),
            "This signature hasn\u{2019}t been checked yet."
        );
    }

    /// The JS SDK reads a copy of this file and checks it byte for byte
    /// against `spec/`; this pins `spec/` itself, so neither can drift
    /// without a test changing in the same commit.
    #[test]
    fn the_model_file_is_pinned() {
        let digest = Sha256::digest(FILE.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "4437a4a5a06e8caa2c516e7e177a80d2ffb9a444f231c05bfc3833d1499df4e4"
        );
    }
}
