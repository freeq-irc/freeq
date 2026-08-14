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
// a channel operator, and where a sender's declared capabilities come from.
// Those are the caller's to establish.

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
  | "caps-mismatch"
  | "deadline-passed";

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
  /** What the offer asked for. */
  caps?: string[];
  /** `act-deadline`, unix seconds. */
  deadline?: number | null;
}

/** The event being checked. */
export interface TaskEvent {
  verb: string;
  /** The id the signer minted; its embedded ULID millisecond is the clock a
   * deadline is measured against. */
  msgid: string;
}

/** Who sent it. */
export interface EventSender {
  did: string;
  /** The capabilities this sender declares. */
  caps?: string[];
  /** The server itself — the only actor a `system` transition allows. */
  isSystem?: boolean;
}

interface Transition {
  verb: string;
  from: string | string[];
  to: string;
  who: string;
  before_deadline?: boolean;
}

interface Kind {
  initial: Record<string, string>;
  terminal: string[];
  transitions: Transition[];
}

const ANY_NONTERMINAL = "*nonterminal";

const kinds = spec.kinds as unknown as Record<string, Kind>;
const refusals = spec.refusals as Record<string, string>;

/** The state a new task of `kind` starts in. */
export function initialState(kind: string, directed: boolean): string | null {
  return kinds[kind]?.initial[directed ? "directed" : "open"] ?? null;
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

  // Authority second: who the sender is only matters once the move itself
  // makes sense.
  const taskCaps = task.caps ?? [];
  const senderCaps = sender.caps ?? [];
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
    case "caps_match":
      if (!taskCaps.every((c) => senderCaps.includes(c)))
        return { ok: false, reason: "caps-mismatch" };
      break;
    // A role this checker does not implement grants nothing. Refusing beats
    // waving through a rule we cannot enforce.
    default:
      return { ok: false, reason: "wrong-sender" };
  }

  if (row.before_deadline && task.deadline != null) {
    const limit = task.deadline * 1000 + DEADLINE_TOLERANCE_MS;
    const minted = eventTimeMs(event.msgid);
    // Fail closed: an id whose clock cannot be read cannot be shown to be
    // inside the deadline.
    if (minted === null || minted > limit) return { ok: false, reason: "deadline-passed" };
  }

  return { ok: true, to: row.to };
}
