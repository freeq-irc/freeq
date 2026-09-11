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
