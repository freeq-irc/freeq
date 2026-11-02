//! The refusals a freeq server sends, and how a client reads them.
//!
//! A sign-in the server refuses carries `FAIL AUTHENTICATE <code> :<sentence>`
//! just before its `904`. A refused signing key carries `FAIL MSGSIG
//! KEY_EXPIRED` or `KEY_RETIRED`. [`classify`] reads a `FAIL *` with one of
//! these codes as it reads a `FAIL AUTHENTICATE`.
//!
//! Only [`TEMPORARILY_UNAVAILABLE`] says the answer may change by itself: the
//! server could not get an answer it needs, or the challenge expired, so the
//! same credentials may get in later. Every other code is final, and so is a
//! `904` that no `FAIL` came before. The server reads the codes from here;
//! `spec/sasl-refusals.json` lists each with its command and kind, and this
//! module's tests hold the codes to it.
//!
//! A browser sign-in through `LOGIN` that the server refuses carries `FAIL
//! LOGIN NOT_ALLOWED` before its `904`. [`classify`] does not count it as a
//! refusal, so the `904` behind it decides, as a bare one: final.

/// The server could not get an answer it needs (a DID document, the handle
/// behind an allowed domain, the PDS), or the client answered after its
/// challenge expired. The one code that says to try again.
pub const TEMPORARILY_UNAVAILABLE: &str = "TEMPORARILY_UNAVAILABLE";
/// The connect allowlist refuses this identity and no delegation admits it.
pub const NOT_ALLOWED: &str = "NOT_ALLOWED";
/// The signature verifies against none of the identity's keys.
pub const SIGNATURE_INVALID: &str = "SIGNATURE_INVALID";
/// The identity's DID document cannot be used to sign in.
pub const IDENTITY_INVALID: &str = "IDENTITY_INVALID";
/// The sign-in token was refused.
pub const TOKEN_INVALID: &str = "TOKEN_INVALID";
/// The sign-in response cannot be read, or answers no challenge this
/// connection holds.
pub const BAD_RESPONSE: &str = "BAD_RESPONSE";
/// A SASL mechanism other than ATPROTO-CHALLENGE.
pub const MECHANISM_UNSUPPORTED: &str = "MECHANISM_UNSUPPORTED";
/// The client sent `AUTHENTICATE *`.
pub const ABORTED: &str = "ABORTED";
/// The server admits no guests.
pub const ACCOUNT_REQUIRED: &str = "ACCOUNT_REQUIRED";
/// An operator revoked this session.
pub const AGENT_REVOKED: &str = "AGENT_REVOKED";
/// The device's signing key ran past its lifetime.
pub const KEY_EXPIRED: &str = "KEY_EXPIRED";
/// The device's signing key was retired.
pub const KEY_RETIRED: &str = "KEY_RETIRED";

/// What a refusal tells the client to do, with the server's sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The server refused this device's signing key.
    SigningKey(String),
    /// These credentials will be refused again whatever happens.
    Final(String),
    /// The server could not decide just now; the same credentials may get in
    /// later.
    TryAgain(String),
}

impl Refusal {
    /// The server's sentence.
    pub fn sentence(&self) -> &str {
        match self {
            Refusal::SigningKey(s) | Refusal::Final(s) | Refusal::TryAgain(s) => s,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.sentence())
    }
}

impl std::error::Error for Refusal {}

/// The refusal a `FAIL` line's parameters carry (`<command> <code> ...
/// <sentence>`), if they carry one. Any other `FAIL` is not a refusal.
pub fn classify(params: &[String]) -> Option<Refusal> {
    let command = params.first()?;
    let code = params.get(1)?;
    let sentence = if params.len() > 2 {
        params[params.len() - 1].clone()
    } else {
        String::new()
    };
    match command.as_str() {
        "MSGSIG" if code == KEY_EXPIRED || code == KEY_RETIRED => {
            Some(Refusal::SigningKey(sentence))
        }
        "AUTHENTICATE" | "*" if code == TEMPORARILY_UNAVAILABLE => {
            Some(Refusal::TryAgain(sentence))
        }
        "AUTHENTICATE" | "*" => Some(Refusal::Final(sentence)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    /// Every code the shared vector lists under AUTHENTICATE or `*`
    /// classifies as the kind it gives.
    #[test]
    fn every_code_in_the_shared_vector_classifies_as_its_kind() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../spec/sasl-refusals.json")).unwrap();
        let codes = vector["codes"].as_array().expect("a codes list");
        assert!(!codes.is_empty());
        for entry in codes {
            let command = entry["command"].as_str().unwrap();
            let code = entry["code"].as_str().unwrap();
            let got = classify(&params(&[command, code, "the words"]));
            let want = match entry["kind"].as_str().unwrap() {
                "try_again" => Refusal::TryAgain("the words".into()),
                "final" => Refusal::Final("the words".into()),
                "signing_key" => Refusal::SigningKey("the words".into()),
                other => panic!("unknown kind {other}"),
            };
            assert_eq!(got, Some(want), "FAIL {command} {code}");
        }
    }

    /// The codes this module defines are the codes the shared vector lists:
    /// each constant is spelt as its name and is listed, and each listed code
    /// is a constant here. So a misspelt constant fails, and the vector test
    /// above holds each one to its kind.
    #[test]
    fn every_code_constant_is_in_the_shared_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../spec/sasl-refusals.json")).unwrap();
        let listed: std::collections::BTreeSet<&str> = vector["codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["code"].as_str().unwrap())
            .collect();
        let mut defined = std::collections::BTreeSet::new();
        for line in include_str!("refusal.rs").lines() {
            let Some(rest) = line.strip_prefix("pub const ") else {
                continue;
            };
            let (name, value) = rest.split_once(": &str = ").expect("a code constant");
            let value = value.trim_end_matches(';').trim_matches('"');
            assert_eq!(name, value, "a code spelt other than its name");
            defined.insert(value);
        }
        assert_eq!(defined, listed);
    }

    #[test]
    fn only_the_one_code_says_try_again() {
        let codes = [
            NOT_ALLOWED,
            SIGNATURE_INVALID,
            IDENTITY_INVALID,
            TOKEN_INVALID,
            BAD_RESPONSE,
            MECHANISM_UNSUPPORTED,
            ABORTED,
            ACCOUNT_REQUIRED,
            AGENT_REVOKED,
            "A_CODE_NO_ONE_HAS_SENT_YET",
        ];
        for command in ["AUTHENTICATE", "*"] {
            assert_eq!(
                classify(&params(&[command, TEMPORARILY_UNAVAILABLE, "later"])),
                Some(Refusal::TryAgain("later".into()))
            );
            for code in codes {
                assert_eq!(
                    classify(&params(&[command, code, "no"])),
                    Some(Refusal::Final("no".into())),
                    "FAIL {command} {code}"
                );
            }
        }
    }

    #[test]
    fn a_refused_key_is_its_own_kind_and_other_fails_are_not_refusals() {
        for code in [KEY_EXPIRED, KEY_RETIRED] {
            assert_eq!(
                classify(&params(&["MSGSIG", code, "sign in again"])),
                Some(Refusal::SigningKey("sign in again".into()))
            );
        }
        assert_eq!(classify(&params(&["MSGSIG", "INVALID_KEY", "no"])), None);
        assert_eq!(
            classify(&params(&["CHATHISTORY", "INVALID_TARGET", "#x", "no"])),
            None
        );
        assert_eq!(classify(&params(&["TAGMSG", NOT_ALLOWED, "no"])), None);
        assert_eq!(classify(&params(&["AUTHENTICATE"])), None);
    }

    #[test]
    fn the_sentence_is_the_last_parameter_and_the_whole_display() {
        let refusal = classify(&params(&["AUTHENTICATE", NOT_ALLOWED, "ctx", "Not here"])).unwrap();
        assert_eq!(refusal.sentence(), "Not here");
        assert_eq!(refusal.to_string(), "Not here");
        let as_error: anyhow::Error = refusal.clone().into();
        assert_eq!(as_error.downcast_ref::<Refusal>(), Some(&refusal));
    }
}
