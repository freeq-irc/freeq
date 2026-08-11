//! What a client can honestly say about who someone is.
//!
//! One rule, owned here, rendered everywhere. The clients used to carry their
//! own copies of this logic and their own caches feeding it, and the same
//! sender read differently on different clients — an absent bot read
//! "Self-created identity" on one client and "Guest" on another, from
//! identical bytes, because each client consulted a different second source.
//! This module is the single second source.
//!
//! Two questions, never mixed on one surface:
//!
//! - **A message row** answers: who was the sender when this was sent. The
//!   row's own tags come first; the live room second; a stored cache never.
//! - **A person surface** (profile, member list) answers: who is this person
//!   now. The live binding comes first, then the lookup state machine.
//!
//! The states, the precedence, and every user-facing string come from
//! `spec/identity-claims.json` — the same contract file the JS SDK loads —
//! and the vectors in that file are executed as tests on both sides, so the
//! two implementations cannot drift apart silently. Clients render what they
//! are handed and may append only platform affordance suffixes.
//!
//! The one dated constant: rows older than the spec's `stamping_epoch` read
//! Unknown when they carry no account tag and their sender is absent. Before
//! servers stamped tags, tag absence proves nothing — the sender could have
//! been authenticated, relayed, or a guest — so claiming "guest" there would
//! be an honest-sounding falsehood. Absence has no format to inspect (unlike
//! a legacy signature, which announces itself by its bare-base64 shape), so
//! the row's own timestamp against that documented epoch is the only
//! wire-derivable discriminator.

use serde::Deserialize;
use std::sync::OnceLock;

/// The six honest answers. Serialized names match the spec file and the JS SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityClaimState {
    /// A DID the server bound at SASL and the AT Protocol resolves.
    AtProtocol,
    /// A `did:key:` — real, and nothing outside vouches for who holds it.
    SelfIssued,
    /// Learned through a relaying peer rather than checked here.
    Relayed,
    /// No account behind the name — the tags or the lookup said so.
    Guest,
    /// An ask is out right now and has not been answered.
    LookingUp,
    /// No identity data reached us and none can be fetched.
    Unknown,
}

impl IdentityClaimState {
    /// The state's key in the spec file — used by the vector runner.
    #[cfg(test)]
    fn spec_key(self) -> &'static str {
        match self {
            Self::AtProtocol => "atProtocol",
            Self::SelfIssued => "selfIssued",
            Self::Relayed => "relayed",
            Self::Guest => "guest",
            Self::LookingUp => "lookingUp",
            Self::Unknown => "unknown",
        }
    }
}

/// A finished claim: the state plus everything a surface needs to render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityClaim {
    pub state: IdentityClaimState,
    /// The DID the claim is about, when one is known.
    pub did: Option<String>,
    /// The relaying peer, when the claim came through one.
    pub origin: Option<String>,
    /// The short label above the line; None for the spinner state.
    pub label: Option<String>,
    /// The one-line explanation, fully rendered; None for the spinner state.
    pub line: Option<String>,
    /// The mark IS the claim, so it appears exactly where the claim holds.
    pub shows_mark: bool,
    /// Render motion, not words.
    pub is_pending: bool,
    /// The line names "the key below", so it needs a surface showing one.
    pub needs_key_card: bool,
}

/// Inputs for a message row. Tags come from the row itself; presence and the
/// live binding come from the venue's roster — never from a stored cache.
#[derive(Debug, Default)]
pub struct MessageClaimInput<'a> {
    /// The row's `account` tag, if any.
    pub account: Option<&'a str>,
    /// The row's `+freeq.at/origin` tag, if any.
    pub origin: Option<&'a str>,
    /// Whether the sender's nick is in the venue's roster right now.
    pub sender_present: bool,
    /// The sender's live DID binding, only if present right now.
    pub sender_live_did: Option<&'a str>,
    /// The row's own timestamp (server `time` tag), unix seconds.
    pub row_time_unix: Option<u64>,
}

/// What has been done about finding out who someone is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonLookup {
    /// No ask has gone out, or the surface never asks.
    NotAsked,
    /// An ask is out and unanswered.
    InFlight,
    /// The answer came back and named no account.
    NoAccount,
    /// The server said no such nick.
    NoSuchNick,
    /// The backstop elapsed with no answer at all.
    TimedOut,
}

/// Inputs for a person surface. `seen_only_via_peer` and `binding` are
/// mutually exclusive by construction: a first-hand binding means the person
/// was seen here, not only through a peer.
#[derive(Debug)]
pub struct PersonClaimInput<'a> {
    /// The live, first-hand DID binding, if one exists right now.
    pub binding: Option<&'a str>,
    /// True when every sighting of this person came through a relaying peer.
    /// Such people are never WHOISed here — this server would answer about
    /// the wrong person.
    pub seen_only_via_peer: bool,
    /// The relaying peer's name, when known.
    pub via_peer_origin: Option<&'a str>,
    /// Whether their relayed messages carried an account.
    pub via_peer_had_account: bool,
    /// The lookup state machine, for the case where nothing is on file.
    pub lookup: PersonLookup,
}

/// The claim for a message row: who was the sender when this was sent.
pub fn claim_for_message(input: &MessageClaimInput) -> IdentityClaim {
    let account = nonblank(input.account);
    // A relayed row splits on whether an account came with it: the origin
    // stamps one for every authenticated sender, so its absence is the origin
    // saying "guest". The lookup machinery never applies to relayed senders.
    if let Some(origin) = nonblank(input.origin) {
        return match account {
            Some(did) => render(IdentityClaimState::Relayed, Some(did), Some(origin)),
            None => render(IdentityClaimState::Guest, None, Some(origin)),
        };
    }
    // The row's own tag beats the live room: a message row describes who sent
    // it then, not who holds the nick now.
    if let Some(did) = account {
        return render(by_did(did), Some(did), None);
    }
    // No tags. The live room may still answer — for rows that predate the tag
    // stampings while their author is standing right here.
    if input.sender_present {
        return match nonblank(input.sender_live_did) {
            Some(did) => render(by_did(did), Some(did), None),
            None => render(IdentityClaimState::Guest, None, None),
        };
    }
    // No tags, absent sender. Tag absence is the guest answer only on rows
    // stored after servers stamped tags; before that it proves nothing, and a
    // row that cannot prove its age is treated the same way.
    match input.row_time_unix {
        Some(t) if t >= spec().stamping_epoch_unix => {
            render(IdentityClaimState::Guest, None, None)
        }
        _ => render(IdentityClaimState::Unknown, None, None),
    }
}

/// The claim for a person surface: who is this person now.
pub fn claim_for_person(input: &PersonClaimInput) -> IdentityClaim {
    if input.seen_only_via_peer {
        let origin = nonblank(input.via_peer_origin);
        return if input.via_peer_had_account {
            render(IdentityClaimState::Relayed, None, origin)
        } else {
            render(IdentityClaimState::Guest, None, origin_or_fallback(origin))
        };
    }
    if let Some(did) = nonblank(input.binding) {
        return render(by_did(did), Some(did), None);
    }
    match input.lookup {
        PersonLookup::InFlight => render(IdentityClaimState::LookingUp, None, None),
        PersonLookup::NoAccount => render(IdentityClaimState::Guest, None, None),
        PersonLookup::NoSuchNick | PersonLookup::TimedOut | PersonLookup::NotAsked => {
            render(IdentityClaimState::Unknown, None, None)
        }
    }
}

/// The claim for a person surface anchored to a message — a profile sheet or
/// popover opened from a row. Live identity first, then the message's own
/// evidence, then the lookup machine. Differs from [`claim_for_message`] in
/// exactly one place: a live-known DID (`sender_live_did` here means any DID
/// known live — the roster, or a fresh WHOIS answer — not only a roster
/// member) outranks the row's tag, because this surface answers who the
/// person is NOW, where the row answers who sent it THEN.
pub fn claim_for_sender(input: &MessageClaimInput, lookup: PersonLookup) -> IdentityClaim {
    if nonblank(input.origin).is_some() {
        // Relayed senders never go through the local lookup — a WHOIS to this
        // server about a relayed nick answers about the wrong person.
        return claim_for_message(input);
    }
    if let Some(did) = nonblank(input.sender_live_did) {
        return render(by_did(did), Some(did), None);
    }
    let from_row = claim_for_message(&MessageClaimInput {
        account: input.account,
        origin: input.origin,
        sender_present: input.sender_present,
        sender_live_did: None,
        row_time_unix: input.row_time_unix,
    });
    // The row's evidence answered (a tag, or post-epoch absence). Only when it
    // could not — Unknown, the pre-epoch case — does the ask machinery decide.
    if from_row.state != IdentityClaimState::Unknown {
        return from_row;
    }
    claim_for_person(&PersonClaimInput {
        binding: None,
        seen_only_via_peer: false,
        via_peer_origin: None,
        via_peer_had_account: false,
        lookup,
    })
}

/// The epoch before which tag absence proves nothing, unix seconds.
pub fn stamping_epoch_unix() -> u64 {
    spec().stamping_epoch_unix
}

fn by_did(did: &str) -> IdentityClaimState {
    if did.starts_with("did:key:") {
        IdentityClaimState::SelfIssued
    } else {
        IdentityClaimState::AtProtocol
    }
}

fn nonblank<'a>(s: Option<&'a str>) -> Option<&'a str> {
    s.filter(|v| !v.trim().is_empty())
}

/// A guest claim reached through a peer keeps a name for the origin even when
/// the peer's name was never learned, mirroring the relayed line's fallback.
fn origin_or_fallback<'a>(origin: Option<&'a str>) -> Option<&'a str> {
    origin.or(Some(spec().states.relayed.origin_fallback.as_str()))
}

fn render(
    state: IdentityClaimState,
    did: Option<&str>,
    origin: Option<&str>,
) -> IdentityClaim {
    let s = spec();
    let (label, flags, line) = match state {
        IdentityClaimState::AtProtocol => {
            let st = &s.states.at_protocol;
            (st.label.clone(), st.flags(), st.line.clone())
        }
        IdentityClaimState::SelfIssued => {
            let st = &s.states.self_issued;
            (st.label.clone(), st.flags(), st.line.clone())
        }
        IdentityClaimState::Relayed => {
            let st = &s.states.relayed;
            let who = origin.unwrap_or(st.origin_fallback.as_str());
            (
                st.label.clone(),
                (st.shows_mark, st.is_pending, st.needs_key_card),
                Some(st.line.replace("{origin}", who)),
            )
        }
        IdentityClaimState::Guest => {
            let st = &s.states.guest;
            let line = match origin {
                Some(o) => st.line_relayed.replace("{origin}", o),
                None => st.line_local.clone(),
            };
            (
                st.label.clone(),
                (st.shows_mark, st.is_pending, st.needs_key_card),
                Some(line),
            )
        }
        IdentityClaimState::LookingUp => {
            let st = &s.states.looking_up;
            (st.label.clone(), st.flags(), st.line.clone())
        }
        IdentityClaimState::Unknown => {
            let st = &s.states.unknown;
            (st.label.clone(), st.flags(), st.line.clone())
        }
    };
    IdentityClaim {
        state,
        did: did.map(str::to_string),
        origin: origin.map(str::to_string),
        label,
        line,
        shows_mark: flags.0,
        is_pending: flags.1,
        needs_key_card: flags.2,
    }
}

// ── The spec file, embedded at build time ───────────────────────────────────

#[derive(Deserialize)]
struct Spec {
    stamping_epoch_unix: u64,
    states: SpecStates,
}

#[derive(Deserialize)]
struct SpecStates {
    #[serde(rename = "atProtocol")]
    at_protocol: SimpleState,
    #[serde(rename = "selfIssued")]
    self_issued: SimpleState,
    relayed: RelayedState,
    guest: GuestState,
    #[serde(rename = "lookingUp")]
    looking_up: SimpleState,
    unknown: SimpleState,
}

#[derive(Deserialize)]
struct SimpleState {
    label: Option<String>,
    shows_mark: bool,
    is_pending: bool,
    needs_key_card: bool,
    line: Option<String>,
}

impl SimpleState {
    fn flags(&self) -> (bool, bool, bool) {
        (self.shows_mark, self.is_pending, self.needs_key_card)
    }
}

#[derive(Deserialize)]
struct RelayedState {
    label: Option<String>,
    shows_mark: bool,
    is_pending: bool,
    needs_key_card: bool,
    line: String,
    origin_fallback: String,
}

#[derive(Deserialize)]
struct GuestState {
    label: Option<String>,
    shows_mark: bool,
    is_pending: bool,
    needs_key_card: bool,
    line_local: String,
    line_relayed: String,
}

fn spec() -> &'static Spec {
    static SPEC: OnceLock<Spec> = OnceLock::new();
    SPEC.get_or_init(|| {
        serde_json::from_str(include_str!("../../spec/identity-claims.json"))
            .expect("spec/identity-claims.json must parse — it is compiled into this binary")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../spec/identity-claims.json")).unwrap()
    }

    fn opt_str(v: &Value) -> Option<&str> {
        v.as_str()
    }

    fn check(claim: &IdentityClaim, expect: &Value, name: &str) {
        assert_eq!(
            claim.state.spec_key(),
            expect["state"].as_str().unwrap(),
            "state for {name}"
        );
        assert_eq!(
            claim.did.as_deref(),
            opt_str(&expect["did"]),
            "did for {name}"
        );
        assert_eq!(
            claim.line.as_deref(),
            opt_str(&expect["line"]),
            "line for {name}"
        );
    }

    #[test]
    fn every_message_vector_in_the_spec_reproduces() {
        let spec = vectors();
        for v in spec["message_vectors"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let i = &v["input"];
            let claim = claim_for_message(&MessageClaimInput {
                account: opt_str(&i["account"]),
                origin: opt_str(&i["origin"]),
                sender_present: i["sender_present"].as_bool().unwrap(),
                sender_live_did: opt_str(&i["sender_live_did"]),
                row_time_unix: i["row_time_unix"].as_u64(),
            });
            check(&claim, &v["expect"], name);
        }
    }

    #[test]
    fn every_person_vector_in_the_spec_reproduces() {
        let spec = vectors();
        for v in spec["person_vectors"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let i = &v["input"];
            let lookup = match i["lookup"].as_str().unwrap() {
                "notAsked" => PersonLookup::NotAsked,
                "inFlight" => PersonLookup::InFlight,
                "noAccount" => PersonLookup::NoAccount,
                "noSuchNick" => PersonLookup::NoSuchNick,
                "timedOut" => PersonLookup::TimedOut,
                other => panic!("unknown lookup {other} in {name}"),
            };
            let claim = claim_for_person(&PersonClaimInput {
                binding: opt_str(&i["binding"]),
                seen_only_via_peer: i["seen_only_via_peer"].as_bool().unwrap(),
                via_peer_origin: opt_str(&i["via_peer_origin"]),
                via_peer_had_account: i["via_peer_had_account"].as_bool().unwrap(),
                lookup,
            });
            check(&claim, &v["expect"], name);
        }
    }

    #[test]
    fn every_sender_vector_in_the_spec_reproduces() {
        let spec = vectors();
        for v in spec["sender_vectors"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let i = &v["input"];
            let lookup = parse_lookup(i["lookup"].as_str().unwrap(), name);
            let claim = claim_for_sender(
                &MessageClaimInput {
                    account: opt_str(&i["account"]),
                    origin: opt_str(&i["origin"]),
                    sender_present: i["sender_present"].as_bool().unwrap(),
                    sender_live_did: opt_str(&i["sender_live_did"]),
                    row_time_unix: i["row_time_unix"].as_u64(),
                },
                lookup,
            );
            check(&claim, &v["expect"], name);
        }
    }

    fn parse_lookup(s: &str, name: &str) -> PersonLookup {
        match s {
            "notAsked" => PersonLookup::NotAsked,
            "inFlight" => PersonLookup::InFlight,
            "noAccount" => PersonLookup::NoAccount,
            "noSuchNick" => PersonLookup::NoSuchNick,
            "timedOut" => PersonLookup::TimedOut,
            other => panic!("unknown lookup {other} in {name}"),
        }
    }

    #[test]
    fn labels_and_flags_come_from_the_spec() {
        let c = claim_for_message(&MessageClaimInput {
            account: Some("did:plc:abc"),
            ..Default::default()
        });
        assert_eq!(c.label.as_deref(), Some("AT Protocol identity"));
        assert!(c.shows_mark);
        assert!(c.needs_key_card);
        assert!(!c.is_pending);

        let pending = claim_for_person(&PersonClaimInput {
            binding: None,
            seen_only_via_peer: false,
            via_peer_origin: None,
            via_peer_had_account: false,
            lookup: PersonLookup::InFlight,
        });
        assert_eq!(pending.label, None);
        assert_eq!(pending.line, None);
        assert!(pending.is_pending);
        assert!(!pending.shows_mark);
    }

    #[test]
    fn the_epoch_is_the_documented_constant() {
        assert_eq!(stamping_epoch_unix(), 1_785_542_400);
    }
}
