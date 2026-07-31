//! Signing and verification for `freeq.at/act` action messages.
//!
//! Implements the act canonical from the act RFC (docs/HANDOFF-RFC.md, v0.4):
//! the signature covers **every `act-*` tag present** on the message — not a
//! fixed field list — JCS-canonicalized (RFC 8785) with sorted keys, signed
//! over the `act-id` ULID rather than a wall-clock timestamp. Adding or
//! stripping an `act-*` tag in transit changes the rebuilt canonical, so
//! tampering is detected by construction.
//!
//! Canonical mapping rules (frozen by the fixtures in
//! `spec/act-signing-vectors.json`, which the TS implementation must
//! reproduce byte-for-byte):
//!
//! - A tag is covered iff its name, after stripping the `+freeq.at/`
//!   client-tag prefix, is `act` or starts with `act-`. (`actor-class` does
//!   NOT match; `sig` does not match.) The unprefixed forms are accepted too.
//! - Canonical keys are the **stripped** names — the vendor prefix is wire
//!   framing, not semantics, so signatures survive a future de-vendoring of
//!   the tag names.
//! - Values are the (IRC-unescaped) tag values, verbatim, always JSON
//!   strings — `act-deadline` is not coerced to a number.
//! - The canonical bytes are the UTF-8 of `canonical::canonicalize` over
//!   that string→string map.
//!
//! The sig tag value is `ed25519:<kid>:<base64url sig>` — the format shared
//! by every freeq signing profile, which lives in [`crate::sigtag`] (kid
//! derivation, parsing, the raw sign/verify over canonical bytes) so the act
//! and chat profiles cannot disagree about it.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};

// The kid rule is shared, not act-specific: re-exported here so existing
// `freeq_sdk::act::derive_kid*` callers (the server's key store, the fixtures)
// keep working while there is exactly one implementation.
pub use crate::sigtag::{SIG_TAG, derive_kid, derive_kid_bytes};

const CLIENT_TAG_PREFIX: &str = "+freeq.at/";
const TAG_PREFIX: &str = "freeq.at/";

/// Why an act signature failed to verify.
///
/// `KidMismatch` is worth distinguishing: it means "this is not the key the
/// signature names" — a lookup-layer problem — where `SigInvalid` means the
/// named key was used and the bytes still don't verify (tampering/forgery).
#[derive(Debug, PartialEq, Eq)]
pub enum ActSigError {
    /// No `act`/`act-*` tags present — nothing to sign or verify.
    NoActTags,
    /// The sig tag is not `alg:kid:sig`.
    BadSigFormat,
    /// The sig tag names an algorithm other than `ed25519`.
    UnsupportedAlgorithm(String),
    /// The supplied public key does not hash to the kid the sig names.
    KidMismatch,
    /// Canonical rebuilt and key matched the kid, but the signature is wrong:
    /// a covered tag was added, stripped, or altered — or the sig is forged.
    SigInvalid,
}

impl std::fmt::Display for ActSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActSigError::NoActTags => write!(f, "no act-* tags present"),
            ActSigError::BadSigFormat => write!(f, "sig tag is not alg:kid:sig"),
            ActSigError::UnsupportedAlgorithm(a) => write!(f, "unsupported sig algorithm {a}"),
            ActSigError::KidMismatch => write!(f, "public key does not match the sig's kid"),
            ActSigError::SigInvalid => write!(f, "signature does not verify over the act tags"),
        }
    }
}

impl std::error::Error for ActSigError {}

impl From<crate::sigtag::SigError> for ActSigError {
    fn from(e: crate::sigtag::SigError) -> Self {
        match e {
            crate::sigtag::SigError::BadFormat => ActSigError::BadSigFormat,
            crate::sigtag::SigError::UnsupportedAlgorithm(a) => {
                ActSigError::UnsupportedAlgorithm(a)
            }
            crate::sigtag::SigError::KidMismatch => ActSigError::KidMismatch,
            crate::sigtag::SigError::Invalid => ActSigError::SigInvalid,
        }
    }
}

/// Strip the client-tag vendor prefix from a tag name, if present.
fn stripped_name(tag_name: &str) -> &str {
    tag_name
        .strip_prefix(CLIENT_TAG_PREFIX)
        .or_else(|| tag_name.strip_prefix(TAG_PREFIX))
        .unwrap_or(tag_name)
}

/// Whether a (possibly prefixed) tag name is covered by the act canonical.
fn is_act_tag(tag_name: &str) -> bool {
    let name = stripped_name(tag_name);
    name == "act" || name.starts_with("act-")
}

/// Build the canonical string over the act tags in `tags`.
///
/// `tags` is the message's tag map with wire names (prefixed or not) and
/// unescaped values. Returns `None` if no act tags are present.
pub fn act_canonical<'a, I>(tags: I) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let covered: BTreeMap<&str, &str> = tags
        .into_iter()
        .filter(|(name, _)| is_act_tag(name))
        .map(|(name, value)| (stripped_name(name), value))
        .collect();
    if covered.is_empty() {
        return None;
    }
    // BTreeMap serializes with sorted keys; canonicalize re-sorts per JCS
    // (codepoint order) and applies JSON string escaping.
    Some(crate::canonical::canonicalize(&covered).expect("string map serializes"))
}

/// Sign the act tags in `tags` with `key`. Returns the sig tag value
/// (`ed25519:<kid>:<base64url sig>`), or `None` if no act tags are present.
pub fn sign_act<'a, I>(tags: I, key: &SigningKey) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    Some(crate::sigtag::sign_canonical(&act_canonical(tags)?, key))
}

/// Parse a sig tag value into (kid, signature bytes).
pub fn parse_sig_tag(sig_tag: &str) -> Result<(&str, [u8; 64]), ActSigError> {
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)
}

/// Verify an act signature over the act tags in `tags` against `key`.
pub fn verify_act<'a, I>(tags: I, sig_tag: &str, key: &VerifyingKey) -> Result<(), ActSigError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    // Shape and kid first, so a missing canonical isn't reported as a format
    // problem and a wrong key isn't reported as tampering.
    crate::sigtag::parse(sig_tag).map_err(ActSigError::from)?;
    let canonical = act_canonical(tags).ok_or(ActSigError::NoActTags)?;
    crate::sigtag::verify_canonical(&canonical, sig_tag, key).map_err(ActSigError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// The RFC's directed-offer example, as a wire tag map (plus tags that
    /// must NOT be covered: sig, msgid, actor-class).
    fn offer_tags() -> Vec<(&'static str, &'static str)> {
        vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/act-id", "01JABCDEF000000000000000EF"),
            ("+freeq.at/act-from", "did:plc:eliza"),
            ("+freeq.at/act-to", "did:plc:scholar"),
            ("+freeq.at/act-title", "Cite 3 sources on X"),
            ("+freeq.at/act-ctx-h", "sha256:9f00"),
            ("+freeq.at/act-caps", "freeq.at/web-search"),
            ("+freeq.at/act-deadline", "1788000000"),
            ("+freeq.at/sig", "ed25519:notcovered:notcovered"),
            ("msgid", "01JSERVERMINTED0000000000"),
            ("+freeq.at/actor-class", "agent"),
        ]
    }

    #[test]
    fn canonical_covers_act_tags_only_sorted_and_stripped() {
        let canonical = act_canonical(offer_tags()).unwrap();
        assert_eq!(
            canonical,
            r#"{"act":"handoff","act-caps":"freeq.at/web-search","act-ctx-h":"sha256:9f00","act-deadline":"1788000000","act-from":"did:plc:eliza","act-id":"01JABCDEF000000000000000EF","act-title":"Cite 3 sources on X","act-to":"did:plc:scholar","act-verb":"offer"}"#
        );
    }

    #[test]
    fn actor_class_and_sig_and_msgid_are_not_covered() {
        // Same act tags with and without the extras → identical canonical.
        let with_extras = act_canonical(offer_tags()).unwrap();
        let only_act: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| is_act_tag(n))
            .collect();
        assert_eq!(with_extras, act_canonical(only_act).unwrap());
    }

    #[test]
    fn unprefixed_tag_names_are_accepted() {
        let prefixed = act_canonical(vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "accept"),
            ("+freeq.at/act-id", "01J"),
        ]);
        let bare = act_canonical(vec![
            ("freeq.at/act", "handoff"),
            ("act-verb", "accept"),
            ("act-id", "01J"),
        ]);
        assert_eq!(prefixed, bare);
    }

    #[test]
    fn no_act_tags_is_none() {
        assert_eq!(
            act_canonical(vec![("msgid", "01J"), ("account", "did:plc:x")]),
            None
        );
        assert_eq!(
            act_canonical(vec![("+freeq.at/actor-class", "agent")]),
            None
        );
    }

    #[test]
    fn values_are_json_escaped() {
        let canonical = act_canonical(vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-title", "say \"hi\"\nplease"),
        ])
        .unwrap();
        assert_eq!(
            canonical,
            r#"{"act":"handoff","act-title":"say \"hi\"\nplease"}"#
        );
    }

    #[test]
    fn kid_is_22_chars_base64url_and_key_specific() {
        let kid1 = derive_kid(&test_key(1).verifying_key());
        let kid2 = derive_kid(&test_key(2).verifying_key());
        assert_eq!(kid1.len(), 22); // 16 bytes → 22 base64url chars unpadded
        assert_ne!(kid1, kid2);
        assert!(
            kid1.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), &key).unwrap();
        assert!(sig_tag.starts_with("ed25519:"));
        verify_act(offer_tags(), &sig_tag, &key.verifying_key()).unwrap();
    }

    #[test]
    fn verify_detects_altered_added_and_stripped_tags() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), &key).unwrap();

        // Altered value
        let mut altered = offer_tags();
        altered.iter_mut().for_each(|(n, v)| {
            if *n == "+freeq.at/act-title" {
                *v = "Cite 4 sources on X";
            }
        });
        assert_eq!(
            verify_act(altered, &sig_tag, &key.verifying_key()),
            Err(ActSigError::SigInvalid)
        );

        // Added act tag
        let mut added = offer_tags();
        added.push(("+freeq.at/act-priority", "urgent"));
        assert_eq!(
            verify_act(added, &sig_tag, &key.verifying_key()),
            Err(ActSigError::SigInvalid)
        );

        // Stripped act tag
        let stripped: Vec<_> = offer_tags()
            .into_iter()
            .filter(|(n, _)| *n != "+freeq.at/act-caps")
            .collect();
        assert_eq!(
            verify_act(stripped, &sig_tag, &key.verifying_key()),
            Err(ActSigError::SigInvalid)
        );
    }

    #[test]
    fn altering_a_non_covered_tag_does_not_break_the_sig() {
        let key = test_key(1);
        let sig_tag = sign_act(offer_tags(), &key).unwrap();
        let mut relayed = offer_tags();
        relayed.iter_mut().for_each(|(n, v)| {
            if *n == "msgid" {
                *v = "01JREMINTEDBYPEER00000000";
            }
        });
        verify_act(relayed, &sig_tag, &key.verifying_key()).unwrap();
    }

    #[test]
    fn wrong_key_is_kid_mismatch_not_sig_invalid() {
        let sig_tag = sign_act(offer_tags(), &test_key(1)).unwrap();
        assert_eq!(
            verify_act(offer_tags(), &sig_tag, &test_key(2).verifying_key()),
            Err(ActSigError::KidMismatch)
        );
    }

    #[test]
    fn bad_formats_are_rejected() {
        let key = test_key(1).verifying_key();
        assert_eq!(
            verify_act(offer_tags(), "ed25519:onlyonecolon", &key),
            Err(ActSigError::BadSigFormat)
        );
        assert_eq!(
            verify_act(offer_tags(), "rsa:kid:c2ln", &key),
            Err(ActSigError::UnsupportedAlgorithm("rsa".into()))
        );
        // Correct kid, but the payload decodes to 3 bytes, not 64 → BadSigFormat
        // (parity with the TS verifier's length guard).
        let kid = derive_kid(&key);
        assert_eq!(
            verify_act(offer_tags(), &format!("ed25519:{kid}:AAAA"), &key),
            Err(ActSigError::BadSigFormat)
        );
    }

    /// The four shared vectors. Kept in one place so the generator and the
    /// checker can't drift.
    fn fixture_cases() -> Vec<(&'static str, u8, Vec<(&'static str, &'static str)>)> {
        vec![
            ("directed-offer", 1, offer_tags()),
            (
                "open-offer-no-act-to",
                2,
                vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "offer"),
                    ("+freeq.at/act-id", "01JXYZ0000000000000000000X"),
                    ("+freeq.at/act-from", "did:plc:eliza"),
                    ("+freeq.at/act-title", "Summarize today's S2S logs"),
                    ("+freeq.at/act-ctx-h", "sha256:2c00"),
                    ("+freeq.at/act-caps", "freeq.at/log-analysis"),
                ],
            ),
            (
                // A non-handoff kind carrying a field handoff never defined —
                // exercises sign-what's-present (no fixed field list).
                "approval-with-kind-specific-field",
                3,
                vec![
                    ("+freeq.at/act", "approval"),
                    ("+freeq.at/act-verb", "request"),
                    ("+freeq.at/act-id", "01KDEF0000000000000000000K"),
                    ("+freeq.at/act-from", "did:plc:factory"),
                    ("+freeq.at/act-to", "did:plc:opslead"),
                    ("+freeq.at/act-title", "Deploy factory-bot v12"),
                    ("+freeq.at/act-scope", "deploy:factory-bot"),
                    ("+freeq.at/act-ctx-h", "sha256:1a00"),
                ],
            ),
            (
                "accept-minimal-with-escaping",
                4,
                vec![
                    ("+freeq.at/act", "handoff"),
                    ("+freeq.at/act-verb", "accept"),
                    ("+freeq.at/act-id", "01JABCDEF000000000000000EF"),
                    ("+freeq.at/act-from", "did:plc:scholar"),
                    ("+freeq.at/act-ref", "01JOFFERMSGID000000000000"),
                    // Non-ASCII + JSON-escaping stress in a value.
                    ("+freeq.at/act-note", "ok — \"on it\" ✓\n(eta 5m)"),
                ],
            ),
        ]
    }

    fn fixtures_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/act-signing-vectors.json")
    }

    fn build_fixtures_json() -> serde_json::Value {
        use base64::Engine;
        let vectors: Vec<serde_json::Value> = fixture_cases()
            .into_iter()
            .map(|(name, seed_byte, tags)| {
                let key = test_key(seed_byte);
                let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(key.verifying_key().as_bytes());
                let tag_map: serde_json::Map<String, serde_json::Value> = tags
                    .iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                    .collect();
                serde_json::json!({
                    "name": name,
                    "seed": hex_seed(seed_byte),
                    "publicKey": pubkey_b64,
                    "kid": derive_kid(&key.verifying_key()),
                    "tags": tag_map,
                    "canonical": act_canonical(tags.clone()).unwrap(),
                    "sigTag": sign_act(tags, &key).unwrap(),
                })
            })
            .collect();
        serde_json::json!({
            "description": "Worked signing examples for freeq.at/act (RFC v0.4). Every implementation must reproduce canonical, kid, and sigTag byte-for-byte from tags + seed. Non-act tags in `tags` are present deliberately: they must NOT be covered.",
            "kidRule": "base64url-nopad(sha256(raw 32-byte ed25519 public key)[0..16])",
            "sigTagFormat": "ed25519:<kid>:<base64url-nopad signature over the UTF-8 canonical bytes>",
            "vectors": vectors,
        })
    }

    fn hex_seed(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    /// Regenerate spec/act-signing-vectors.json. Run manually:
    /// `cargo test -p freeq-sdk generate_signing_vectors -- --ignored`
    #[test]
    #[ignore]
    fn generate_signing_vectors() {
        let json = serde_json::to_string_pretty(&build_fixtures_json()).unwrap();
        std::fs::create_dir_all(fixtures_path().parent().unwrap()).unwrap();
        std::fs::write(fixtures_path(), json + "\n").unwrap();
    }

    /// The committed fixture file must exactly match what this implementation
    /// produces — this is the cross-language byte-compatibility contract.
    #[test]
    fn committed_signing_vectors_are_reproducible() {
        let on_disk = std::fs::read_to_string(fixtures_path())
            .expect("spec/act-signing-vectors.json missing — run generate_signing_vectors");
        let on_disk: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(on_disk, build_fixtures_json());

        // And each vector's sig actually verifies.
        for (_, seed_byte, tags) in fixture_cases() {
            let key = test_key(seed_byte);
            let sig_tag = sign_act(tags.clone(), &key).unwrap();
            verify_act(tags, &sig_tag, &key.verifying_key()).unwrap();
        }
    }

    #[test]
    fn open_offer_omits_act_to() {
        // v0.4: open/claimable = no act-to at all.
        let open = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/act-id", "01JXYZ0000000000000000000X"),
            ("+freeq.at/act-from", "did:plc:eliza"),
            ("+freeq.at/act-title", "Summarize today's S2S logs"),
            ("+freeq.at/act-caps", "freeq.at/log-analysis"),
        ];
        let key = test_key(3);
        let sig_tag = sign_act(open.clone(), &key).unwrap();
        verify_act(open, &sig_tag, &key.verifying_key()).unwrap();
    }
}
