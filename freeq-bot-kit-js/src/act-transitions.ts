// The task lifecycle: which move is legal, from which state, and by whom.
//
// The mirror of `freeq_sdk::act_transitions`. The rules are data, not code:
// they live in `spec/act-transitions.json`, and this package carries a
// byte-identical copy (the build root cannot reach outside `src/`) that
// act-transitions.test.ts pins. Both implementations replay the sequences in
// that file, so a bot can pre-check a move before sending it and reach the
// same verdict the server will.
//
// What is not here: whether the signature checked out, whether the sender is
// a channel operator, and whether anyone's declared capabilities suit the work
// — that last one by ruling, not omission: act-caps is a hint to store and
// filter on, never a gate.

import spec from "./act-transitions.json";

/** How far an event's own clock may sit from a deadline and still count as
 * inside it — the same grace client-minted ids get, because federated
 * machines do not have synchronized clocks. */
export const DEADLINE_TOLERANCE_MS = spec.deadline_rule.tolerance_ms;

/** Why a task event was refused. */
export type RefusalReason =
  | "unknown-kind"
  | "unknown-verb"
  | "terminal-task"
  | "illegal-step"
  | "wrong-sender"
  | "deadline-passed"
  | "client-confirm"
  | "replaces-not-opener"
  | "replaces-malformed"
  | "replaces-not-terminal"
  | "missing-requirement"
  | "accepts-not-a-bid";

/** Allowed, with the state the task lands in — or refused, with the reason. */
export type CheckResult = { ok: true; to: string } | { ok: false; reason: RefusalReason };

/** A task as the caller currently understands it. */
export interface Task {
  kind: string;
  state: string;
  offerer: string;
  /** Empty on an open offer. */
  offeree?: string | null;
  /** Empty until somebody accepts or claims. */
  assignee?: string | null;
  /** `act-deadline`, unix seconds. */
  deadline?: number | null;
  /** `act-bid-deadline`, unix seconds. A second time on the same opener,
   * compared the same way: it bounds how long a bounty collects bids, which
   * is a shorter question than how long the offer stands. */
  bidDeadline?: number | null;
}

/** The event being checked. */
export interface TaskEvent {
  verb: string;
  /** The id the signer minted; its embedded ULID millisecond is the clock a
   * deadline is measured against. */
  msgid: string;
  /** `act-accepts`: the event an award takes. Named here rather than read out
   * of `fields` because it is the one act value a caller must resolve before
   * asking — see `EventSender.acceptedBid`. */
  accepts?: string | null;
  /** The act fields the event carries, by their document names (`act-to`,
   * `act-note`, …). Presence only: what a transition's `requires` is checked
   * against. The one place this checker points at a value is
   * `assigneeSource`, which names the field rather than reading it. */
  fields?: string[];
}

/** The bid an award named, as the caller's log answered for it. */
export interface AcceptedBid {
  /** Who wrote the bid. The assignee an award's `bid-author` row lands on. */
  author: string;
}

/** Who sent it, and what their event resolved to. */
export interface EventSender {
  did: string;
  /** The server itself — the only actor a `system` transition allows. */
  isSystem?: boolean;
  /**
   * The bid this event's `act-accepts` names, when the caller found one on the
   * action. Absent when it named something that is not a bid here — including
   * an id belonging to another action, and an id nobody filed.
   *
   * This checker reads no log, so the lookup is the caller's: it resolves the
   * named event among the action's own and hands back the bid's author. A bot
   * pre-checking its own move has no log — it passes nothing and is told its
   * award takes nothing, which is the honest answer from where it stands.
   */
  acceptedBid?: AcceptedBid | null;
}

interface Transition {
  verb: string;
  from: string | string[];
  to: string;
  who: string;
  before_deadline?: boolean;
  /** Bounded by the offer's `act-bid-deadline` rather than its
   *  `act-deadline`. Data, like its sibling; the comparison is the same code. */
  before_bid_deadline?: boolean;
  /** The field naming who this transition assigns. Absent = the actor. */
  assignee_from?: string;
  /** Fields the transition is illegal without. */
  requires?: string[];
}

/** How a task of this kind comes into being: the verb that creates one, and
 * the state it lands in — which of the two depends on whether the message
 * named a recipient. A kind that can only be opened to the room at large
 * carries no `directed`. */
interface Opens {
  verb: string;
  directed?: string;
  open: string;
}

interface Kind {
  opens: Opens;
  terminal: string[];
  transitions: Transition[];
}

const ANY_NONTERMINAL = "*nonterminal";

/** The `assignee_from` value that means "the author of the bid this event
 *  names". */
const BID_AUTHOR = "bid-author";

/** The verb the event an award names must carry.
 *
 * Written down once, here, so a caller resolving `act-accepts` asks the rules
 * rather than spelling a kind's verb into itself. */
export const BID_VERB = "bid";

const kinds = spec.kinds as unknown as Record<string, Kind>;
const refusals = spec.refusals as Record<string, string>;

/** The state a new task of `kind` starts in. */
export function initialState(kind: string, directed: boolean): string | null {
  const opens = kinds[kind]?.opens;
  if (!opens) return null;
  return (directed ? opens.directed : opens.open) ?? null;
}

/** The verb that creates a task of this kind. */
export function openingVerb(kind: string): string | null {
  return kinds[kind]?.opens.verb ?? null;
}

/** The verb an action's home writes its receipts under. */
export const CONFIRMATION_VERB = spec.confirmation.verb;

/** The tag a receipt names the event it confirms in. */
export const CONFIRMATION_SUBJECT_TAG = spec.confirmation.subject;

/**
 * Whether this verb is the home's receipt verb.
 *
 * Asked before any kind's table is consulted, by every caller that reads a
 * verb at all. A receipt is a statement about an event, not a move on a task:
 * no kind lists `confirm`, and letting one fall through to the per-kind lookup
 * would answer "that kind has no such step" — which reads as an invitation to
 * add the row, and the row must not exist.
 */
export function isConfirmation(verb: string): boolean {
  return verb === CONFIRMATION_VERB;
}

/** The tag a new action names the finished one it revives in. */
export const REVIVAL_TAG = spec.revival.tag;

/** What the caller's log knows about the action a revival names. */
export type Predecessor = "unknown" | "live" | "finished";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Whether `id` is shaped like an event id: a 26-character Crockford ULID.
 *
 * Shape only. Whether anything was ever filed under it is the log's answer,
 * not this one's.
 */
export function isEventId(id: string): boolean {
  return id.length === 26 && [...id].every((c) => CROCKFORD.includes(c));
}

/** Allowed, or refused with the reason. */
export type RevivalResult = { ok: true } | { ok: false; reason: RefusalReason };

/**
 * Decide whether an event may carry the revival relation (`REVIVAL_TAG`),
 * given what the caller's log knows about the action it names.
 *
 * Three rules, cheapest first. Only an opener revives anything: a step on an
 * action that already exists names no other. The value names an action, so it
 * is shaped like one. And the action it names must have finished — reviving
 * something still running would leave two live actions each claiming to be the
 * work.
 *
 * `"unknown"` is accepted, and that is the load-bearing part: receivers must
 * tolerate a link to an action they never filed and annotate rather than
 * refuse. A bot pre-checking its own move has no log at all — it passes
 * `"unknown"` and gets the two rules a message decides on its own.
 */
export function checkRevival(
  opens: boolean,
  named: string,
  predecessor: Predecessor,
): RevivalResult {
  if (!opens) return { ok: false, reason: "replaces-not-opener" };
  if (!isEventId(named)) return { ok: false, reason: "replaces-malformed" };
  if (predecessor === "live") return { ok: false, reason: "replaces-not-terminal" };
  return { ok: true };
}

/**
 * Decide whether an event may open a new task of `kind`.
 *
 * The move the transitions table cannot describe, because there is no task yet
 * to move. There is no sender to check: any logged-in sender may open, and
 * opening is what makes them the offerer. `directed` is whether the message
 * named a recipient; `namesTask` is whether it also carried an `act-id`, which
 * an opener never does — its own event id is the task's id.
 */
export function checkOpen(
  kind: string,
  verb: string,
  directed: boolean,
  namesTask: boolean,
): CheckResult {
  // Before the kind is even looked up: a receipt opens nothing, and the answer
  // must not depend on which kind it named.
  if (isConfirmation(verb)) return { ok: false, reason: "client-confirm" };
  const k = kinds[kind];
  if (!k) return { ok: false, reason: "unknown-kind" };
  if (k.opens.verb !== verb) {
    // A verb the kind moves tasks with is known but cannot start one; a verb
    // it has never heard of is a different answer entirely.
    return k.transitions.some((t) => t.verb === verb)
      ? { ok: false, reason: "illegal-step" }
      : { ok: false, reason: "unknown-verb" };
  }
  if (namesTask) return { ok: false, reason: "illegal-step" };
  if (directed) {
    // A kind with no directed form cannot be opened to one recipient.
    return k.opens.directed
      ? { ok: true, to: k.opens.directed }
      : { ok: false, reason: "illegal-step" };
  }
  return { ok: true, to: k.opens.open };
}

/** Whether `state` is one this kind never leaves. */
export function isTerminal(kind: string, state: string): boolean {
  return kinds[kind]?.terminal.includes(state) ?? false;
}

/** The sentence the rules file documents a reason with. */
export function refusalDescription(reason: RefusalReason): string {
  return refusals[reason] ?? "refused";
}

/** The millisecond a ULID event id was minted at, or null if it is not one. */
export function eventTimeMs(msgid: string): number | null {
  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  if (msgid.length !== 26) return null;
  let ms = 0;
  for (const ch of msgid.slice(0, 10)) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) return null;
    ms = ms * 32 + v;
  }
  return ms;
}

function fromMatches(from: string | string[], state: string, kind: Kind): boolean {
  if (Array.isArray(from)) return from.includes(state);
  if (from === ANY_NONTERMINAL) return !kind.terminal.includes(state);
  return from === state;
}

/**
 * Decide whether `event` from `sender` may be applied to `task`.
 *
 * The checks run identity-of-the-move first and authority-over-it second —
 * reporting "not you" for a step that is illegal for everybody would send the
 * sender after the wrong problem.
 */
export function checkTransition(
  task: Task,
  event: TaskEvent,
  sender: EventSender,
): CheckResult {
  // The receipt verb, before the kind lookup and before anything about this
  // task: a confirmation is not a move, and no table has a row for it. The
  // home files its own receipts past this checker entirely.
  if (isConfirmation(event.verb)) return { ok: false, reason: "client-confirm" };
  const kind = kinds[task.kind];
  if (!kind) return { ok: false, reason: "unknown-kind" };

  // Is this a move the kind has at all? Asked before anything about this
  // particular task, because "we have never heard of that verb" and "not from
  // here" are different things to tell a sender.
  const rows = kind.transitions.filter((t) => t.verb === event.verb);
  if (rows.length === 0) return { ok: false, reason: "unknown-verb" };

  // A finished task is finished for everyone, the expiry sweep included.
  if (kind.terminal.includes(task.state)) return { ok: false, reason: "terminal-task" };

  const row = rows.find((t) => fromMatches(t.from, task.state, kind));
  if (!row) return { ok: false, reason: "illegal-step" };

  // What the move needs to be the move at all. Before authority for the same
  // reason the state is: an award that names no winner is malformed for
  // everybody, and "not you" would send the sender after the wrong problem.
  const present = event.fields ?? [];
  if ((row.requires ?? []).some((f) => !present.includes(f))) {
    return { ok: false, reason: "missing-requirement" };
  }

  // A row that takes its assignee from a named bid needs that bid. Whether the
  // name found one is the caller's answer, not this checker's — nothing here
  // reads a log — and a name that found nothing named something that is not a
  // bid on this action. Alongside the requirement above for the same reason:
  // an award that takes no bid is malformed for everybody.
  if (row.assignee_from === BID_AUTHOR && (!event.accepts || !sender.acceptedBid)) {
    return { ok: false, reason: "accepts-not-a-bid" };
  }

  // Authority second: who the sender is only matters once the move itself
  // makes sense.
  switch (row.who) {
    case "offerer":
      if (sender.did !== task.offerer) return { ok: false, reason: "wrong-sender" };
      break;
    case "offeree":
      if (!task.offeree || sender.did !== task.offeree)
        return { ok: false, reason: "wrong-sender" };
      break;
    case "assignee":
      if (!task.assignee || sender.did !== task.assignee)
        return { ok: false, reason: "wrong-sender" };
      break;
    case "system":
      if (!sender.isSystem) return { ok: false, reason: "wrong-sender" };
      break;
    // `anyone` is a real answer, not a missing check: an open post is
    // claimable by any logged-in sender, first valid one wins.
    case "anyone":
      break;
    // A role this checker does not implement grants nothing. Refusing beats
    // waving through a rule we cannot enforce.
    default:
      return { ok: false, reason: "wrong-sender" };
  }

  // Two deadlines, one comparison. A row declares which of the offer's times
  // bounds it: how long the offer stands, or — on a kind that collects them —
  // how long it takes bids. A time the offer never named bounds nothing.
  const bounds = [
    row.before_deadline ? task.deadline : null,
    row.before_bid_deadline ? task.bidDeadline : null,
  ];
  for (const deadline of bounds) {
    if (deadline == null) continue;
    const limit = deadline * 1000 + DEADLINE_TOLERANCE_MS;
    const minted = eventTimeMs(event.msgid);
    // Fail closed: an id whose clock cannot be read cannot be shown to be
    // inside the deadline.
    if (minted === null || minted > limit) return { ok: false, reason: "deadline-passed" };
  }

  return { ok: true, to: row.to };
}

/** Who a transition assigns the work to. */
export type AssigneeSource =
  /** Whoever took the step — what `accept` and `claim` already mean. */
  | { from: "actor" }
  /** The act field named here, read off the event. */
  | { from: "field"; field: string }
  /** Whoever wrote the bid the event names in `act-accepts`: a bounty's
   *  `award` takes one bid, and the terms live in it, so the poster names the
   *  event rather than a DID. Resolving it is the caller's — this checker
   *  reads no log — and the answer arrives as `EventSender.acceptedBid`. */
  | { from: "bid-author" };

/**
 * Where the assignee comes from when `verb` moves a `kind` task out of
 * `fromState`.
 *
 * Data, not code: a kind that assigns someone other than the actor says so in
 * its row. A verb with no row here answers `actor`, which changes nothing for
 * a transition that assigns nobody.
 */
export function assigneeSource(
  kind: string,
  verb: string,
  fromState: string,
): AssigneeSource {
  const k = kinds[kind];
  if (!k) return { from: "actor" };
  const row = k.transitions.find((t) => t.verb === verb && fromMatches(t.from, fromState, k));
  if (!row?.assignee_from) return { from: "actor" };
  if (row.assignee_from === BID_AUTHOR) return { from: "bid-author" };
  return { from: "field", field: row.assignee_from };
}
