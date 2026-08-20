//! The task lifecycle: which move is legal, from which state, and by whom.
//!
//! The rules live in `spec/act-transitions.json`, not in this file. A kind
//! names the verb that **creates** one of its tasks and the state that lands
//! in, its terminal states, and a row per legal move on a task that already
//! exists — verb, the states it may be made from, the state it lands in, and
//! the role the sender must hold. Adding a task kind is an edit to that file; this
//! module is the code that reads it, and stays the same size as kinds are
//! added. That is the whole point of the arrangement: an event whose kind the
//! file does not list is refused, so a server's enforced rules are never wider
//! than the rules somebody wrote down.
//!
//! The TypeScript package carries a byte-identical copy of the file and a
//! mirror of this checker, so a bot can pre-check a move before sending it and
//! reach the same verdict the server will.
//!
//! What is *not* here: whether the signature checked out, whether the sender
//! is a channel operator, and whether anyone's declared capabilities suit the
//! work — that last one by ruling, not omission: `act-caps` is a hint to store
//! and filter on, never a gate. This module answers one question, about one
//! event, given what the caller already knows.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// How far an event's own clock may sit from a deadline and still count as
/// inside it.
///
/// The same grace client-minted ids get (`MAX_CLIENT_SKEW_MS` in the server's
/// `msgid`), for the same reason: federated machines do not have synchronized
/// clocks. Restated here rather than imported because the server depends on
/// this crate, not the other way round; the act RFC is the source both copies
/// follow, and [`the_tolerance_matches_the_spec_file`] pins this one to the
/// data file.
///
/// [`the_tolerance_matches_the_spec_file`]: #
pub const DEADLINE_TOLERANCE_MS: u64 = 120_000;

/// Why a task event was refused.
///
/// Each variant is a different thing for the sender to do about it, which is
/// why they are distinct: an illegal step means "not now", a wrong sender
/// means "not you", and an unknown kind means the server has not been taught
/// this kind yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The kind is not in the rules file.
    UnknownKind,
    /// The kind lists no transition with this verb.
    UnknownVerb,
    /// The task is already finished. Nothing un-applies.
    TerminalTask,
    /// The verb is legal for this kind, but not from the state the task is in.
    IllegalStep,
    /// The sender does not hold the role the transition requires.
    WrongSender,
    /// The event was minted past the offer's deadline, beyond the tolerance.
    DeadlinePassed,
    /// A sender wrote the confirmation verb. Receipts are the home's.
    ClientConfirm,
    /// The revival relation rode an event that opens nothing.
    ReplacesNotOpener,
    /// The revival relation's value is not shaped like an action id.
    ReplacesMalformed,
    /// The action a revival names is on file and has not finished.
    ReplacesNotTerminal,
}

impl Refusal {
    /// The machine-readable code, and the key this reason is documented under
    /// in the rules file.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::UnknownKind => "unknown-kind",
            Refusal::UnknownVerb => "unknown-verb",
            Refusal::TerminalTask => "terminal-task",
            Refusal::IllegalStep => "illegal-step",
            Refusal::WrongSender => "wrong-sender",
            Refusal::DeadlinePassed => "deadline-passed",
            Refusal::ClientConfirm => "client-confirm",
            Refusal::ReplacesNotOpener => "replaces-not-opener",
            Refusal::ReplacesMalformed => "replaces-malformed",
            Refusal::ReplacesNotTerminal => "replaces-not-terminal",
        }
    }

    /// The sentence the rules file documents this reason with.
    pub fn describe(self) -> &'static str {
        spec()
            .refusals
            .get(self.code())
            .map(String::as_str)
            .unwrap_or("refused")
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for Refusal {}

/// A task as the caller currently understands it.
///
/// `assignee` is empty until somebody accepts or claims, and `deadline` is the
/// offer's `act-deadline` in unix seconds, empty when it named none.
///
/// No capabilities here: `act-caps` is a self-declared hint the server stores,
/// relays and can filter on, never a gate. A claim is open to any logged-in
/// sender and the first valid one wins.
#[derive(Debug, Clone)]
pub struct Task<'a> {
    pub kind: &'a str,
    pub state: &'a str,
    pub offerer: &'a str,
    pub offeree: Option<&'a str>,
    pub assignee: Option<&'a str>,
    pub deadline: Option<i64>,
}

/// The event being checked.
#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
    pub verb: &'a str,
    /// The id the signer minted. Its embedded ULID millisecond is the clock a
    /// deadline is measured against — every verifier then compares the same
    /// number instead of its own wall clock.
    pub msgid: &'a str,
}

/// Who sent it.
#[derive(Debug, Clone, Copy)]
pub struct Sender<'a> {
    pub did: &'a str,
    /// The server itself, signing under its own identity — the only actor a
    /// `system` transition allows.
    pub is_system: bool,
}

/// The state a new task of `kind` starts in.
///
/// A directed offer (one naming a recipient) and an open one start in
/// different states, which is why the file names both.
pub fn initial_state(kind: &str, directed: bool) -> Option<&'static str> {
    let opens = &spec().kinds.get(kind)?.opens;
    match directed {
        true => opens.directed.as_deref(),
        false => Some(opens.open.as_str()),
    }
}

/// The verb that creates a task of this kind.
pub fn opening_verb(kind: &str) -> Option<&'static str> {
    spec().kinds.get(kind).map(|k| k.opens.verb.as_str())
}

/// The verb an action's home writes its receipts under.
pub fn confirmation_verb() -> &'static str {
    spec().confirmation.verb.as_str()
}

/// The tag a receipt names the event it confirms in.
pub fn confirmation_subject_tag() -> &'static str {
    spec().confirmation.subject.as_str()
}

/// Whether this verb is the home's receipt verb.
///
/// Asked before any kind's table is consulted, by every caller that reads a
/// verb at all. A receipt is a statement about an event, not a move on a task:
/// no kind lists `confirm`, and letting one fall through to the per-kind
/// lookup would answer "that kind has no such step" — which reads as an
/// invitation to add the row, and the row must not exist.
pub fn is_confirmation(verb: &str) -> bool {
    verb == confirmation_verb()
}

/// The tag a new action names the finished one it revives in.
pub fn revival_tag() -> &'static str {
    spec().revival.tag.as_str()
}

/// What the caller's log knows about the action a revival names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predecessor {
    /// Never filed here. Accepted and annotated — see [`check_revival`].
    Unknown,
    /// On file, and still running.
    Live,
    /// On file, and finished.
    Finished,
}

/// Whether `id` is shaped like an event id: a 26-character Crockford ULID.
///
/// Shape only. Whether anything was ever filed under it is the log's answer,
/// not this one's.
pub fn is_event_id(id: &str) -> bool {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    id.len() == 26 && id.bytes().all(|b| CROCKFORD.contains(&b))
}

/// Decide whether an event may carry the revival relation
/// ([`revival_tag`]), given what the caller's log knows about the action it
/// names.
///
/// Three rules, cheapest first. Only an opener revives anything: a step on an
/// action that already exists names no other. The value names an action, so it
/// is shaped like one. And the action it names must have finished — reviving
/// something still running would leave two live actions each claiming to be
/// the work.
///
/// [`Predecessor::Unknown`] is accepted, and that is the load-bearing part:
/// receivers must tolerate a link to an action they never filed and annotate
/// rather than refuse. On one server that is a client's typo; under federation
/// it is the ordinary case, because the predecessor lived on somebody else's
/// machine. A caller with no log at all — a bot pre-checking its own move —
/// passes `Unknown` and gets the two rules a message decides on its own.
pub fn check_revival(opens: bool, named: &str, predecessor: Predecessor) -> Result<(), Refusal> {
    if !opens {
        return Err(Refusal::ReplacesNotOpener);
    }
    if !is_event_id(named) {
        return Err(Refusal::ReplacesMalformed);
    }
    match predecessor {
        Predecessor::Live => Err(Refusal::ReplacesNotTerminal),
        Predecessor::Unknown | Predecessor::Finished => Ok(()),
    }
}

/// Decide whether an event may open a new task of `kind`.
///
/// The move the transitions table cannot describe, because there is no task
/// yet to move — and the one a server needs first, since nothing else can
/// happen until something has been opened.
///
/// There is no sender to check: **any logged-in sender may open**, and
/// opening is what makes them the offerer. `directed` is whether the message
/// named a recipient; `names_task` is whether it also carried an `act-id`,
/// which an opener never does — its own event id is the task's id, so an
/// opener naming a task is describing two at once.
pub fn check_open(
    kind: &str,
    verb: &str,
    directed: bool,
    names_task: bool,
) -> Result<&'static str, Refusal> {
    // Before the kind is even looked up: a receipt opens nothing, and the
    // answer must not depend on which kind it named.
    if is_confirmation(verb) {
        return Err(Refusal::ClientConfirm);
    }
    let k = spec().kinds.get(kind).ok_or(Refusal::UnknownKind)?;
    if k.opens.verb != verb {
        // A verb the kind moves tasks with is known but cannot start one;
        // a verb it has never heard of is a different answer entirely.
        return Err(match k.transitions.iter().any(|t| t.verb == verb) {
            true => Refusal::IllegalStep,
            false => Refusal::UnknownVerb,
        });
    }
    if names_task {
        return Err(Refusal::IllegalStep);
    }
    match directed {
        // A kind with no directed form cannot be opened to one recipient.
        true => k.opens.directed.as_deref().ok_or(Refusal::IllegalStep),
        false => Ok(k.opens.open.as_str()),
    }
}

/// Whether the rules file lists this kind at all.
///
/// The question a server asks before anything else about a task event: a kind
/// nobody wrote down is refused rather than stored unrefereed, so adding a
/// kind is an edit to the file and not a thing that happens by accident.
pub fn knows_kind(kind: &str) -> bool {
    spec().kinds.contains_key(kind)
}

/// Whether `kind`'s table has a transition with this verb, from any state.
///
/// Asked without reference to a particular task: "this kind has no such step"
/// is a different answer from "not from where that task is now", and only the
/// first can be given before any state exists.
pub fn knows_verb(kind: &str, verb: &str) -> bool {
    spec()
        .kinds
        .get(kind)
        .is_some_and(|k| k.transitions.iter().any(|t| t.verb == verb))
}

/// Whether `state` is one this kind never leaves.
pub fn is_terminal(kind: &str, state: &str) -> bool {
    spec()
        .kinds
        .get(kind)
        .is_some_and(|k| k.terminal.iter().any(|t| t == state))
}

/// The millisecond a ULID event id was minted at, or `None` if it is not one.
pub fn event_time_ms(msgid: &str) -> Option<u64> {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    if msgid.len() != 26 {
        return None;
    }
    let mut ms: u64 = 0;
    for b in msgid.bytes().take(10) {
        ms = (ms << 5) | CROCKFORD.iter().position(|c| *c == b)? as u64;
    }
    Some(ms)
}

/// Decide whether `event` from `sender` may be applied to `task`.
///
/// On success, the state the task lands in. The checks run identity-of-the-move
/// first and authority-over-it second — reporting "not you" for a step that is
/// illegal for everybody would send the sender after the wrong problem.
pub fn check(
    task: &Task<'_>,
    event: &Event<'_>,
    sender: &Sender<'_>,
) -> Result<&'static str, Refusal> {
    // The receipt verb, before the kind lookup and before anything about this
    // task: a confirmation is not a move, and no table has a row for it. The
    // home files its own receipts past this checker entirely.
    if is_confirmation(event.verb) {
        return Err(Refusal::ClientConfirm);
    }
    let kind = spec().kinds.get(task.kind).ok_or(Refusal::UnknownKind)?;

    // Is this a move the kind has at all? Asked before anything about this
    // particular task, because "we have never heard of that verb" and "not
    // from here" are different things to tell a sender.
    let rows: Vec<&Transition> = kind
        .transitions
        .iter()
        .filter(|t| t.verb == event.verb)
        .collect();
    if rows.is_empty() {
        return Err(Refusal::UnknownVerb);
    }

    // A finished task is finished for everyone, the expiry sweep included.
    if kind.terminal.iter().any(|t| t == task.state) {
        return Err(Refusal::TerminalTask);
    }

    let row = rows
        .into_iter()
        .find(|t| t.from.matches(task.state, kind))
        .ok_or(Refusal::IllegalStep)?;

    // Authority second: who the sender is only matters once the move itself
    // makes sense.
    match row.who.as_str() {
        "offerer" if sender.did != task.offerer => return Err(Refusal::WrongSender),
        "offeree" if task.offeree != Some(sender.did) => return Err(Refusal::WrongSender),
        "assignee" if task.assignee != Some(sender.did) => return Err(Refusal::WrongSender),
        "system" if !sender.is_system => return Err(Refusal::WrongSender),
        // `anyone` is a real answer, not a missing check: an open post is
        // claimable by any logged-in sender, first valid one wins.
        "offerer" | "offeree" | "assignee" | "system" | "anyone" => {}
        // A role this checker does not implement grants nothing. Refusing
        // beats waving through a rule we cannot enforce.
        _ => return Err(Refusal::WrongSender),
    }

    if row.before_deadline
        && let Some(deadline) = task.deadline
    {
        let limit = deadline
            .saturating_mul(1_000)
            .saturating_add(DEADLINE_TOLERANCE_MS as i64);
        // Fail closed: an id whose clock cannot be read cannot be shown to be
        // inside the deadline.
        let minted = event_time_ms(event.msgid).ok_or(Refusal::DeadlinePassed)?;
        if minted as i64 > limit {
            return Err(Refusal::DeadlinePassed);
        }
    }

    Ok(row.to.as_str())
}

// ── The rules file, embedded at build time ──────────────────────────────────

#[derive(Deserialize)]
struct Spec {
    kinds: BTreeMap<String, Kind>,
    confirmation: Confirmation,
    revival: Revival,
    refusals: BTreeMap<String, String>,
    #[allow(dead_code)]
    deadline_rule: DeadlineRule,
}

/// The receipt verb, and the tag a receipt names its subject in. Outside
/// `kinds` because it belongs to none of them.
#[derive(Deserialize)]
struct Confirmation {
    verb: String,
    subject: String,
}

/// The tag a new action names the finished one it revives in. Outside `kinds`
/// for the same reason: the relation is every kind's, so it is none's.
#[derive(Deserialize)]
struct Revival {
    tag: String,
}

#[derive(Deserialize)]
struct Kind {
    opens: Opens,
    terminal: Vec<String>,
    transitions: Vec<Transition>,
}

/// How a task of this kind comes into being: the verb that creates one, and
/// the state it lands in — which of the two depends on whether the message
/// named a recipient.
///
/// A kind that can only be opened to the room at large carries no `directed`.
#[derive(Deserialize)]
struct Opens {
    verb: String,
    directed: Option<String>,
    open: String,
}

#[derive(Deserialize)]
struct Transition {
    verb: String,
    from: FromStates,
    to: String,
    who: String,
    #[serde(default)]
    before_deadline: bool,
}

/// A transition's `from`: one state, several, or every non-terminal one.
#[derive(Deserialize)]
#[serde(untagged)]
enum FromStates {
    One(String),
    Many(Vec<String>),
}

const ANY_NONTERMINAL: &str = "*nonterminal";

impl FromStates {
    fn matches(&self, state: &str, kind: &Kind) -> bool {
        match self {
            FromStates::One(s) if s == ANY_NONTERMINAL => !kind.terminal.iter().any(|t| t == state),
            FromStates::One(s) => s == state,
            FromStates::Many(states) => states.iter().any(|s| s == state),
        }
    }
}

#[derive(Deserialize)]
struct DeadlineRule {
    /// Read only by the test that pins it to [`DEADLINE_TOLERANCE_MS`]. That
    /// is its whole job: the constant is what the comparison uses, and this
    /// is what stops the file and the code drifting apart.
    #[allow(dead_code)]
    tolerance_ms: u64,
}

fn spec() -> &'static Spec {
    static SPEC: OnceLock<Spec> = OnceLock::new();
    SPEC.get_or_init(|| {
        serde_json::from_str(include_str!("../../spec/act-transitions.json"))
            .expect("spec/act-transitions.json must parse — it is compiled into this binary")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELIZA: &str = "did:plc:eliza";
    const SCHOLAR: &str = "did:plc:scholar";
    const MALLORY: &str = "did:plc:mallory";
    const SERVER: &str = "did:web:irc.example";
    /// A ULID minted well before any deadline these tests use.
    const NOW: &str = "01M08R03G0EVENT00000000000";

    fn directed(state: &'static str) -> Task<'static> {
        Task {
            kind: "handoff",
            state,
            offerer: ELIZA,
            offeree: Some(SCHOLAR),
            assignee: None,
            deadline: None,
        }
    }

    fn ev(verb: &'static str) -> Event<'static> {
        Event { verb, msgid: NOW }
    }

    fn who(did: &'static str) -> Sender<'static> {
        Sender {
            did,
            is_system: false,
        }
    }

    // ── the table, read back ────────────────────────────────────────────────

    #[test]
    fn a_kind_names_its_two_initial_states() {
        assert_eq!(initial_state("handoff", true), Some("offered"));
        assert_eq!(initial_state("handoff", false), Some("open"));
        assert_eq!(initial_state("bounty", false), None, "not a listed kind");
    }

    // ── opening a task ──────────────────────────────────────────────────────

    /// The move the transitions table cannot describe, because there is no
    /// task yet to move. Anyone logged in may make it, and making it is what
    /// makes them the offerer.
    #[test]
    fn the_opening_verb_creates_a_task_for_any_sender() {
        assert_eq!(opening_verb("handoff"), Some("offer"));
        assert_eq!(check_open("handoff", "offer", true, false), Ok("offered"));
        assert_eq!(check_open("handoff", "offer", false, false), Ok("open"));
    }

    /// Whether the offer names a recipient is what decides which state it
    /// lands in — the one question the opener asks about its own message.
    #[test]
    fn naming_a_recipient_is_what_makes_an_offer_directed() {
        assert_ne!(
            check_open("handoff", "offer", true, false),
            check_open("handoff", "offer", false, false)
        );
    }

    /// An opener's own event id *is* the task's id, so an opener that also
    /// names a task is describing two tasks at once.
    #[test]
    fn an_opener_that_names_an_existing_task_is_refused() {
        assert_eq!(
            check_open("handoff", "offer", true, true),
            Err(Refusal::IllegalStep)
        );
        assert_eq!(
            check_open("handoff", "offer", false, true),
            Err(Refusal::IllegalStep)
        );
    }

    /// The two ways a verb can fail to open, kept apart: one the kind has
    /// never heard of, and one it knows but cannot start with.
    #[test]
    fn a_verb_that_does_not_open_is_refused_by_whether_the_kind_knows_it() {
        assert_eq!(
            check_open("handoff", "post", false, false),
            Err(Refusal::UnknownVerb),
            "a verb this kind has no row for at all"
        );
        for verb in ["accept", "complete", "cancel", "expire"] {
            assert_eq!(
                check_open("handoff", verb, true, false),
                Err(Refusal::IllegalStep),
                "{verb} moves a task; it cannot start one"
            );
        }
    }

    #[test]
    fn opening_a_kind_the_file_does_not_list_is_refused() {
        assert_eq!(
            check_open("bounty", "offer", false, false),
            Err(Refusal::UnknownKind)
        );
        assert_eq!(opening_verb("bounty"), None);
    }

    /// The states an opener lands in are the states the transitions move from
    /// — otherwise a task could be created into a state nothing can act on.
    #[test]
    fn every_opening_state_is_one_some_transition_moves_from() {
        for (name, kind) in &spec().kinds {
            for state in [
                kind.opens.directed.as_deref(),
                Some(kind.opens.open.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                assert!(
                    kind.transitions.iter().any(|t| t.from.matches(state, kind)),
                    "{name}: nothing can be done to a task opened into {state}"
                );
            }
        }
    }

    /// What a server asks before a task has any state to reason about.
    #[test]
    fn a_kind_and_a_verb_can_be_recognized_without_a_task() {
        assert!(knows_kind("handoff"));
        assert!(!knows_kind("bounty"), "a real kind this file does not list");
        assert!(!knows_kind("approval"), "deferred");

        for verb in [
            "accept", "decline", "claim", "progress", "complete", "fail", "cancel", "expire",
        ] {
            assert!(knows_verb("handoff", verb), "{verb}");
        }
        assert!(
            !knows_verb("handoff", "award"),
            "bounty's verb, not handoff's"
        );
        assert!(!knows_verb("bounty", "award"), "no table, no verbs");
    }

    #[test]
    fn the_terminal_states_are_exactly_the_five_the_file_names() {
        for state in ["completed", "failed", "cancelled", "declined", "expired"] {
            assert!(is_terminal("handoff", state), "{state} is terminal");
        }
        for state in ["offered", "open", "assigned"] {
            assert!(!is_terminal("handoff", state), "{state} is not terminal");
        }
    }

    #[test]
    fn the_approval_kind_is_not_in_the_file() {
        // Deferred: it gets added as its own table if and when something needs
        // it. Until then an approval event is refused, not half-handled.
        assert!(spec().kinds.get("approval").is_none());
        assert_eq!(spec().kinds.len(), 1, "handoff is the only kind so far");
    }

    // ── the receipt verb ────────────────────────────────────────────────────

    /// A receipt is the home's word about an event, so a sender's `confirm`
    /// is refused wherever it appears — opening or moving, whatever kind it
    /// names, and even when the sender claims to be the server. The home
    /// files its own past this checker.
    #[test]
    fn a_sender_never_writes_a_confirmation() {
        assert_eq!(confirmation_verb(), "confirm");
        assert_eq!(
            check(&directed("offered"), &ev("confirm"), &who(SCHOLAR)),
            Err(Refusal::ClientConfirm)
        );
        let system = Sender {
            did: SERVER,
            is_system: true,
        };
        assert_eq!(
            check(&directed("offered"), &ev("confirm"), &system),
            Err(Refusal::ClientConfirm)
        );
        assert_eq!(
            check_open("handoff", "confirm", false, false),
            Err(Refusal::ClientConfirm)
        );
    }

    /// The answer must not read as "this kind has no such row yet", which
    /// would say a kind could add one. It cannot: the verb is recognized
    /// before any kind is consulted, unlisted kinds included.
    #[test]
    fn a_confirmation_never_reads_as_a_verb_a_kind_could_add() {
        let unlisted = Task {
            kind: "no-such-kind",
            ..directed("offered")
        };
        assert_eq!(
            check(&unlisted, &ev("confirm"), &who(SCHOLAR)),
            Err(Refusal::ClientConfirm),
            "not unknown-kind either — the verb is answered first"
        );
        assert_eq!(
            check_open("no-such-kind", "confirm", false, false),
            Err(Refusal::ClientConfirm)
        );
        for (name, kind) in &spec().kinds {
            assert!(
                !kind.transitions.iter().any(|t| is_confirmation(&t.verb)),
                "{name} claims the receipt verb, which belongs to no kind"
            );
            assert!(!is_confirmation(&kind.opens.verb), "{name}");
        }
    }

    // ── the revival relation ────────────────────────────────────────────────

    /// The two rules a message decides on its own, and the one that needs the
    /// log. An unknown predecessor is accepted on purpose — see
    /// [`super::check_revival`].
    #[test]
    fn only_an_opener_revives_a_finished_action() {
        const DEAD: &str = "01M16E7TC0ENDED00000000000";
        assert_eq!(revival_tag(), "act-replaces");
        assert_eq!(check_revival(true, DEAD, Predecessor::Finished), Ok(()));
        assert_eq!(check_revival(true, DEAD, Predecessor::Unknown), Ok(()));
        assert_eq!(
            check_revival(true, DEAD, Predecessor::Live),
            Err(Refusal::ReplacesNotTerminal)
        );
        assert_eq!(
            check_revival(false, DEAD, Predecessor::Finished),
            Err(Refusal::ReplacesNotOpener)
        );
        for bad in [
            "",
            "not-a-ulid",
            "01M16E7TC0SHRT",
            &format!("{DEAD}X"),
            "01M16E7TC0ended00000000000",
        ] {
            assert_eq!(
                check_revival(true, bad, Predecessor::Unknown),
                Err(Refusal::ReplacesMalformed),
                "{bad}"
            );
        }
    }

    /// Shape, and nothing about whether anything was filed under it.
    #[test]
    fn an_action_id_is_twenty_six_crockford_characters() {
        assert!(is_event_id("01M16E7TC0ENDED00000000000"));
        assert!(!is_event_id("01M16E7TC0ENDED0000000000"), "too short");
        assert!(!is_event_id("01M16E7TC0ENDED000000000000"), "too long");
        // I, L, O and U are not in the alphabet, which is what keeps a ULID
        // from being confused for something typed by hand.
        for c in ['I', 'L', 'O', 'U', 'a', '-'] {
            assert!(
                !is_event_id(&format!("01M16E7TC0ENDED0000000000{c}")),
                "{c}"
            );
        }
    }

    #[test]
    fn every_refusal_reason_is_documented_in_the_file() {
        for r in [
            Refusal::UnknownKind,
            Refusal::UnknownVerb,
            Refusal::TerminalTask,
            Refusal::IllegalStep,
            Refusal::WrongSender,
            Refusal::DeadlinePassed,
            Refusal::ClientConfirm,
            Refusal::ReplacesNotOpener,
            Refusal::ReplacesMalformed,
            Refusal::ReplacesNotTerminal,
        ] {
            assert!(
                spec().refusals.contains_key(r.code()),
                "{} has no entry in the rules file",
                r.code()
            );
            assert_ne!(r.describe(), "refused");
        }
    }

    /// A `who` the checker does not implement refuses everything, which would
    /// read as a broken kind rather than a typo. Catch it here instead.
    #[test]
    fn every_who_value_in_the_file_is_a_role_the_checker_knows() {
        const ROLES: [&str; 5] = ["offerer", "offeree", "assignee", "anyone", "system"];
        for (name, kind) in &spec().kinds {
            for t in &kind.transitions {
                assert!(
                    ROLES.contains(&t.who.as_str()),
                    "{name}/{}: {}",
                    t.verb,
                    t.who
                );
                // And every state a transition names must be one the kind can
                // actually be in.
                let states: Vec<&String> = match &t.from {
                    FromStates::One(s) => vec![s],
                    FromStates::Many(v) => v.iter().collect(),
                };
                for s in states {
                    assert!(
                        s == ANY_NONTERMINAL
                            || kind.terminal.contains(s)
                            || kind.opens.directed.as_ref() == Some(s)
                            || &kind.opens.open == s
                            || kind.transitions.iter().any(|other| &other.to == s),
                        "{name}/{}: no transition or initial state reaches {s}",
                        t.verb
                    );
                }
            }
        }
    }

    #[test]
    fn the_tolerance_matches_the_spec_file() {
        assert_eq!(DEADLINE_TOLERANCE_MS, spec().deadline_rule.tolerance_ms);
        // …and the value the server gives client-minted ids, restated because
        // the dependency runs the other way.
        assert_eq!(DEADLINE_TOLERANCE_MS, 120_000);
    }

    // ── the happy path ──────────────────────────────────────────────────────

    #[test]
    fn a_directed_offer_runs_from_accept_to_complete() {
        assert_eq!(
            check(&directed("offered"), &ev("accept"), &who(SCHOLAR)),
            Ok("assigned")
        );
        let mut assigned = directed("assigned");
        assigned.assignee = Some(SCHOLAR);
        assert_eq!(
            check(&assigned, &ev("progress"), &who(SCHOLAR)),
            Ok("assigned")
        );
        assert_eq!(
            check(&assigned, &ev("complete"), &who(SCHOLAR)),
            Ok("completed")
        );
        assert_eq!(check(&assigned, &ev("fail"), &who(SCHOLAR)), Ok("failed"));
    }

    #[test]
    fn the_offerer_may_cancel_from_either_live_state() {
        assert_eq!(
            check(&directed("offered"), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
        assert_eq!(
            check(&directed("assigned"), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
    }

    // ── the refusals, one test each ─────────────────────────────────────────

    #[test]
    fn only_the_offeree_may_accept() {
        assert_eq!(
            check(&directed("offered"), &ev("accept"), &who(MALLORY)),
            Err(Refusal::WrongSender)
        );
        // Not even the person who wrote the offer.
        assert_eq!(
            check(&directed("offered"), &ev("accept"), &who(ELIZA)),
            Err(Refusal::WrongSender)
        );
    }

    #[test]
    fn only_the_assignee_may_report_on_the_work() {
        let mut assigned = directed("assigned");
        assigned.assignee = Some(SCHOLAR);
        assert_eq!(
            check(&assigned, &ev("complete"), &who(MALLORY)),
            Err(Refusal::WrongSender)
        );
        assert_eq!(
            check(&assigned, &ev("progress"), &who(ELIZA)),
            Err(Refusal::WrongSender),
            "the offerer is not the worker"
        );
    }

    #[test]
    fn only_the_server_may_expire_a_task() {
        assert_eq!(
            check(&directed("assigned"), &ev("expire"), &who(ELIZA)),
            Err(Refusal::WrongSender)
        );
        let system = Sender {
            did: SERVER,
            is_system: true,
        };
        assert_eq!(
            check(&directed("assigned"), &ev("expire"), &system),
            Ok("expired")
        );
        // A user cannot borrow the move by claiming the server's name.
        assert_eq!(
            check(&directed("assigned"), &ev("expire"), &who(SERVER)),
            Err(Refusal::WrongSender)
        );
    }

    #[test]
    fn an_illegal_step_is_refused() {
        // Legal verb for the kind, wrong state to make it from.
        assert_eq!(
            check(&directed("offered"), &ev("complete"), &who(SCHOLAR)),
            Err(Refusal::IllegalStep)
        );
        let mut assigned = directed("assigned");
        assigned.assignee = Some(SCHOLAR);
        assert_eq!(
            check(&assigned, &ev("accept"), &who(SCHOLAR)),
            Err(Refusal::IllegalStep),
            "a task cannot be accepted twice"
        );
    }

    /// The state is checked before the sender: a step nobody may make now
    /// should not read as "you are the wrong person".
    #[test]
    fn an_illegal_step_reads_as_illegal_even_from_a_stranger() {
        assert_eq!(
            check(&directed("offered"), &ev("complete"), &who(MALLORY)),
            Err(Refusal::IllegalStep)
        );
    }

    #[test]
    fn a_terminal_task_takes_no_further_events() {
        for state in ["completed", "failed", "cancelled", "declined", "expired"] {
            let done = Task {
                state,
                ..directed("completed")
            };
            assert_eq!(
                check(&done, &ev("progress"), &who(SCHOLAR)),
                Err(Refusal::TerminalTask),
                "{state}"
            );
            let system = Sender {
                did: SERVER,
                is_system: true,
            };
            assert_eq!(
                check(&done, &ev("expire"), &system),
                Err(Refusal::TerminalTask),
                "not even the sweep re-finishes a finished task ({state})"
            );
        }
    }

    #[test]
    fn a_verb_the_kind_does_not_list_is_refused() {
        assert_eq!(
            check(&directed("offered"), &ev("award"), &who(ELIZA)),
            Err(Refusal::UnknownVerb)
        );
    }

    #[test]
    fn a_kind_the_file_does_not_list_is_refused() {
        let bounty = Task {
            kind: "bounty",
            ..directed("open")
        };
        assert_eq!(
            check(&bounty, &ev("bid"), &who(SCHOLAR)),
            Err(Refusal::UnknownKind)
        );
        // Even for a verb handoff does list — the kind is checked first.
        assert_eq!(
            check(&bounty, &ev("cancel"), &who(ELIZA)),
            Err(Refusal::UnknownKind)
        );
    }

    // ── capabilities ────────────────────────────────────────────────────────

    fn open_task() -> Task<'static> {
        Task {
            kind: "handoff",
            state: "open",
            offerer: ELIZA,
            offeree: None,
            assignee: None,
            deadline: None,
        }
    }

    /// Ruled: capabilities are a self-declared hint, never a gate. An open
    /// post is claimable by any logged-in sender, and the first valid claim
    /// wins — there is no capability check and no refusal for failing one.
    #[test]
    fn an_open_post_is_claimable_by_any_logged_in_sender() {
        for did in [SCHOLAR, MALLORY, "did:plc:nobody"] {
            assert_eq!(
                check(&open_task(), &ev("claim"), &who(did)),
                Ok("assigned"),
                "{did}"
            );
        }
    }

    /// The offerer may withdraw an open post nobody took. Without this row a
    /// mistaken post stayed claimable until the expiry sweep reached it.
    #[test]
    fn the_offerer_may_withdraw_an_open_post() {
        assert_eq!(
            check(&open_task(), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
    }

    /// …and only the offerer. Cancelling is the poster's act from every live
    /// state, open included.
    #[test]
    fn an_open_post_is_not_anyone_elses_to_withdraw() {
        for did in [SCHOLAR, MALLORY] {
            assert_eq!(
                check(&open_task(), &ev("cancel"), &who(did)),
                Err(Refusal::WrongSender),
                "{did}"
            );
        }
    }

    /// Cancel now reaches every live state the kind has.
    #[test]
    fn cancel_is_legal_from_every_live_state() {
        assert_eq!(
            check(&directed("offered"), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
        assert_eq!(
            check(&directed("assigned"), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
        assert_eq!(
            check(&open_task(), &ev("cancel"), &who(ELIZA)),
            Ok("cancelled")
        );
    }

    // ── the deadline ────────────────────────────────────────────────────────

    /// 1788000000 unix seconds, as the fixtures use it.
    const DEADLINE: i64 = 1_788_000_000;
    const IN_TIME: &str = "01M16E7TC0ACCEPTINTIME0000";
    const AT_EDGE: &str = "01M16HSB60ACCEPTATEDGE0000";
    const TOO_LATE: &str = "01M16HSC58ACCEPTTOOLATE000";

    fn with_deadline() -> Task<'static> {
        Task {
            deadline: Some(DEADLINE),
            ..directed("offered")
        }
    }

    #[test]
    fn an_event_id_carries_the_millisecond_it_was_minted() {
        assert_eq!(event_time_ms(IN_TIME), Some(1_787_996_400_000));
        assert_eq!(event_time_ms(AT_EDGE), Some(1_788_000_120_000));
        assert_eq!(event_time_ms("not-a-ulid"), None);
    }

    #[test]
    fn an_accept_after_the_deadline_is_refused() {
        let late = Event {
            verb: "accept",
            msgid: TOO_LATE,
        };
        assert_eq!(
            check(&with_deadline(), &late, &who(SCHOLAR)),
            Err(Refusal::DeadlinePassed)
        );
    }

    #[test]
    fn an_accept_inside_the_deadline_or_at_the_edge_of_the_tolerance_stands() {
        for id in [IN_TIME, AT_EDGE] {
            let e = Event {
                verb: "accept",
                msgid: id,
            };
            assert_eq!(
                check(&with_deadline(), &e, &who(SCHOLAR)),
                Ok("assigned"),
                "{id}"
            );
        }
    }

    /// A deadline bounds how long the offer stands, whichever way it was
    /// taken up — the directed path and the open one alike.
    #[test]
    fn a_claim_is_deadline_bound_exactly_as_an_accept_is() {
        let open_with_deadline = Task {
            deadline: Some(DEADLINE),
            ..open_task()
        };
        let late = Event {
            verb: "claim",
            msgid: TOO_LATE,
        };
        assert_eq!(
            check(&open_with_deadline, &late, &who(SCHOLAR)),
            Err(Refusal::DeadlinePassed)
        );
        for id in [IN_TIME, AT_EDGE] {
            let e = Event {
                verb: "claim",
                msgid: id,
            };
            assert_eq!(
                check(&open_with_deadline, &e, &who(SCHOLAR)),
                Ok("assigned"),
                "{id}"
            );
        }
    }

    /// Only the transitions marked `before_deadline` are bound by it. A
    /// declining offeree is answering, not claiming the work.
    #[test]
    fn the_deadline_binds_only_the_transitions_that_declare_it() {
        let late = Event {
            verb: "decline",
            msgid: TOO_LATE,
        };
        assert_eq!(
            check(&with_deadline(), &late, &who(SCHOLAR)),
            Ok("declined")
        );
        let late_cancel = Event {
            verb: "cancel",
            msgid: TOO_LATE,
        };
        assert_eq!(
            check(&with_deadline(), &late_cancel, &who(ELIZA)),
            Ok("cancelled")
        );
    }

    #[test]
    fn a_task_with_no_deadline_is_never_late() {
        let late = Event {
            verb: "accept",
            msgid: TOO_LATE,
        };
        assert_eq!(
            check(&directed("offered"), &late, &who(SCHOLAR)),
            Ok("assigned")
        );
    }

    /// Fail closed: an id whose clock cannot be read cannot be shown to be
    /// inside the deadline, so it is treated as outside it.
    #[test]
    fn an_unreadable_event_id_cannot_beat_a_deadline() {
        let junk = Event {
            verb: "accept",
            msgid: "not-a-ulid",
        };
        assert_eq!(
            check(&with_deadline(), &junk, &who(SCHOLAR)),
            Err(Refusal::DeadlinePassed)
        );
    }

    // ── the shared sequences ────────────────────────────────────────────────

    #[derive(Deserialize)]
    struct SeqFile {
        sequences: Vec<Sequence>,
    }

    #[derive(Deserialize)]
    struct Sequence {
        name: String,
        task: SeqTask,
        steps: Vec<SeqStep>,
    }

    #[derive(Deserialize)]
    struct SeqTask {
        kind: String,
        offer: String,
        /// Only for a kind with no `initial` to read (an unlisted one).
        state: Option<String>,
        offerer: String,
        offeree: Option<String>,
        deadline: Option<i64>,
    }

    #[derive(Deserialize)]
    struct SeqStep {
        verb: String,
        sender: String,
        event_id: Option<String>,
        #[serde(default)]
        system: bool,
        expect: Option<String>,
        expect_refused: Option<String>,
    }

    fn sequences() -> Vec<Sequence> {
        let file: SeqFile =
            serde_json::from_str(include_str!("../../spec/act-transitions.json")).unwrap();
        file.sequences
    }

    /// Replay one chain, carrying the state — and the assignee, which the
    /// accepting or claiming sender becomes — from step to step. A refused
    /// step changes nothing, which is what lets a chain show a refusal
    /// followed by the move that was legal all along.
    fn replay(seq: &Sequence) {
        let mut state = match &seq.task.state {
            Some(s) => s.clone(),
            None => initial_state(&seq.task.kind, seq.task.offer == "directed")
                .unwrap_or("open")
                .to_string(),
        };
        let mut assignee: Option<String> = None;

        for (i, step) in seq.steps.iter().enumerate() {
            let task = Task {
                kind: &seq.task.kind,
                state: &state,
                offerer: &seq.task.offerer,
                offeree: seq.task.offeree.as_deref(),
                assignee: assignee.as_deref(),
                deadline: seq.task.deadline,
            };
            let event = Event {
                verb: &step.verb,
                msgid: step.event_id.as_deref().unwrap_or(NOW),
            };
            let sender = Sender {
                did: &step.sender,
                is_system: step.system,
            };
            let where_ = format!("{} — step {} ({})", seq.name, i + 1, step.verb);

            match (
                check(&task, &event, &sender),
                &step.expect,
                &step.expect_refused,
            ) {
                (Ok(next), Some(want), None) => {
                    assert_eq!(next, want, "{where_}");
                    if assignee.is_none() && next == "assigned" {
                        assignee = Some(step.sender.clone());
                    }
                    state = next.to_string();
                }
                (Err(got), None, Some(want)) => assert_eq!(got.code(), want, "{where_}"),
                (got, expect, refused) => {
                    panic!("{where_}: got {got:?}, but the step expects {expect:?} / {refused:?}")
                }
            }
        }
    }

    #[derive(Deserialize)]
    struct OpeningFile {
        opening_sequences: Vec<Opening>,
    }

    #[derive(Deserialize)]
    struct Opening {
        name: String,
        kind: String,
        verb: String,
        directed: bool,
        #[serde(default)]
        names_task: bool,
        expect: Option<String>,
        expect_refused: Option<String>,
    }

    fn opening_sequences() -> Vec<Opening> {
        let file: OpeningFile =
            serde_json::from_str(include_str!("../../spec/act-transitions.json")).unwrap();
        file.opening_sequences
    }

    #[derive(Deserialize)]
    struct RevivalFile {
        revival_sequences: Vec<RevivalCase>,
    }

    #[derive(Deserialize)]
    struct RevivalCase {
        name: String,
        opens: bool,
        names: String,
        predecessor: String,
        expect: Option<String>,
        expect_refused: Option<String>,
    }

    fn revival_sequences() -> Vec<RevivalCase> {
        let file: RevivalFile =
            serde_json::from_str(include_str!("../../spec/act-transitions.json")).unwrap();
        file.revival_sequences
    }

    #[test]
    fn every_revival_sequence_in_the_rules_file_replays() {
        let cases = revival_sequences();
        assert!(cases.len() >= 5, "{}", cases.len());
        for c in &cases {
            let predecessor = match c.predecessor.as_str() {
                "unknown" => Predecessor::Unknown,
                "live" => Predecessor::Live,
                "finished" => Predecessor::Finished,
                other => panic!("{}: unknown predecessor {other}", c.name),
            };
            let got = check_revival(c.opens, &c.names, predecessor);
            match (&c.expect, &c.expect_refused) {
                (Some(word), None) => {
                    assert_eq!(word, "accepted", "{}", c.name);
                    assert_eq!(got, Ok(()), "{}", c.name);
                }
                (None, Some(reason)) => assert_eq!(
                    got.map_err(|r| r.code()),
                    Err(reason.as_str()),
                    "{}",
                    c.name
                ),
                _ => panic!("{}: set exactly one of expect / expect_refused", c.name),
            }
        }
    }

    #[test]
    fn every_opening_sequence_in_the_rules_file_replays() {
        let openings = opening_sequences();
        assert!(openings.len() >= 5, "{}", openings.len());
        for o in &openings {
            let got = check_open(&o.kind, &o.verb, o.directed, o.names_task);
            match (&o.expect, &o.expect_refused) {
                (Some(state), None) => assert_eq!(got, Ok(state.as_str()), "{}", o.name),
                (None, Some(reason)) => {
                    assert_eq!(
                        got.map_err(|r| r.code()),
                        Err(reason.as_str()),
                        "{}",
                        o.name
                    )
                }
                _ => panic!("{}: set exactly one of expect / expect_refused", o.name),
            }
        }
    }

    #[test]
    fn every_sequence_in_the_rules_file_replays() {
        let seqs = sequences();
        assert!(
            seqs.len() >= 20,
            "the file should carry a real set: {}",
            seqs.len()
        );
        for seq in &seqs {
            replay(seq);
        }
    }

    /// Every step must state exactly one expectation, or a typo in the file
    /// would quietly assert nothing.
    #[test]
    fn every_sequence_step_states_one_expectation() {
        for seq in sequences() {
            for (i, step) in seq.steps.iter().enumerate() {
                assert_ne!(
                    step.expect.is_some(),
                    step.expect_refused.is_some(),
                    "{} step {}: set exactly one of expect / expect_refused",
                    seq.name,
                    i + 1
                );
                if let Some(reason) = &step.expect_refused {
                    assert!(
                        spec().refusals.contains_key(reason),
                        "{} step {}: {reason} is not a documented reason",
                        seq.name,
                        i + 1
                    );
                }
            }
        }
    }

    /// The sequences have to exercise every refusal the checker can reach —
    /// otherwise the other implementation could pass them all and still get a
    /// reason wrong. Every list counts: some reasons only an opener can earn,
    /// and some only a revival can.
    #[test]
    fn the_sequences_cover_every_refusal_reason() {
        let mut seen: Vec<String> = sequences()
            .iter()
            .flat_map(|s| s.steps.iter().filter_map(|st| st.expect_refused.clone()))
            .chain(
                opening_sequences()
                    .iter()
                    .filter_map(|o| o.expect_refused.clone()),
            )
            .chain(
                revival_sequences()
                    .iter()
                    .filter_map(|r| r.expect_refused.clone()),
            )
            .collect();
        seen.sort();
        seen.dedup();
        for reason in spec().refusals.keys() {
            assert!(seen.contains(reason), "no sequence refuses with {reason}");
        }
    }
}
