// Cross-implementation contract tests for the task transition rules.
//
// Replays every sequence in the canonical `spec/act-transitions.json` — the
// same file the Rust SDK replays — so the two checkers cannot drift apart
// silently. Also pins the copy in `src/` byte-identical to the canonical file:
// the copy exists only because this package's build root cannot reach outside
// `src/`.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  DEADLINE_TOLERANCE_MS,
  checkOpen,
  CONFIRMATION_VERB,
  REVIVAL_TAG,
  assigneeSource,
  checkRevival,
  checkTransition,
  isConfirmation,
  isEventId,
  type Predecessor,
  eventTimeMs,
  initialState,
  isTerminal,
  openingVerb,
  refusalDescription,
  type EventSender,
  type RefusalReason,
  type Task,
} from "./act-transitions.js";

const canonicalPath = fileURLToPath(
  new URL("../../spec/act-transitions.json", import.meta.url),
);
const canonical = JSON.parse(readFileSync(canonicalPath, "utf8"));

interface Step {
  verb: string;
  sender: string;
  event_id?: string;
  system?: boolean;
  /** The act fields the event carries, by document name. What a transition's
   *  `requires` is checked against. */
  tags?: string[];
  /** Who the step assigns, when it names someone other than its sender. */
  assigns?: string;
  /** `act-accepts`: the event an award takes. */
  accepts?: string;
  /** Who wrote the bid that event turned out to be. Absent when the name
   *  found no bid on this action. */
  accepted_bid?: string;
  expect?: string;
  expect_refused?: RefusalReason;
}

/** Just enough of a kind's shape for the tests that read the file directly. */
interface Kind {
  opens: { verb: string; directed?: string; open: string };
  terminal: string[];
  transitions: { verb: string; from: string | string[]; to: string; who: string }[];
}

interface Sequence {
  name: string;
  task: {
    kind: string;
    offer: string;
    state?: string;
    offerer: string;
    offeree: string | null;
    deadline: number | null;
    bid_deadline?: number | null;
  };
  steps: Step[];
}

const ELIZA = "did:plc:eliza";
const SCHOLAR = "did:plc:scholar";
const MALLORY = "did:plc:mallory";
const SERVER = "did:web:irc.example";
/** A ULID minted well before any deadline these tests use. */
const NOW = "01M08R03G0EVENT00000000000";

function directed(state: string): Task {
  return { kind: "handoff", state, offerer: ELIZA, offeree: SCHOLAR };
}

const ev = (verb: string) => ({ verb, msgid: NOW });
const who = (did: string): EventSender => ({ did });

describe("the rules file", () => {
  it("the copy this package imports is byte-identical to the canonical spec file", () => {
    const copy = readFileSync(
      fileURLToPath(new URL("./act-transitions.json", import.meta.url)),
      "utf8",
    );
    expect(
      copy,
      "refresh with: cp spec/act-transitions.json freeq-bot-kit-js/src/act-transitions.json",
    ).toBe(readFileSync(canonicalPath, "utf8"));
  });

  it("names both initial states, and nothing for an unlisted kind", () => {
    expect(initialState("handoff", true)).toBe("offered");
    expect(initialState("handoff", false)).toBe("open");
    expect(initialState("approval", false)).toBeNull();
    // A bounty opens to the room and nowhere else: it has no directed form,
    // because a directed bounty is just a handoff.
    expect(initialState("bounty", false)).toBe("open");
    expect(initialState("bounty", true)).toBeNull();
  });

  it("carries the five terminal states and no others", () => {
    for (const s of ["completed", "failed", "cancelled", "declined", "expired"]) {
      expect(isTerminal("handoff", s), s).toBe(true);
    }
    for (const s of ["offered", "open", "assigned"]) {
      expect(isTerminal("handoff", s), s).toBe(false);
    }
  });

  it("carries the two kinds it lists, and not the deferred approval", () => {
    expect(Object.keys(canonical.kinds).sort()).toEqual(["bounty", "handoff"]);
  });

  it("uses the same deadline tolerance as the Rust checker", () => {
    expect(DEADLINE_TOLERANCE_MS).toBe(120_000);
  });

  it("documents every refusal reason it uses", () => {
    // Both lists count: some reasons only an opener can earn.
    const used = new Set<string>([
      ...((canonical.sequences as Sequence[]).flatMap((s) =>
        s.steps.map((st) => st.expect_refused).filter(Boolean),
      ) as string[]),
      ...((canonical.opening_sequences as { expect_refused?: string }[])
        .map((o) => o.expect_refused)
        .filter(Boolean) as string[]),
      ...((canonical.revival_sequences as { expect_refused?: string }[])
        .map((r) => r.expect_refused)
        .filter(Boolean) as string[]),
    ]);
    for (const reason of used) {
      expect(refusalDescription(reason as RefusalReason), reason).not.toBe("refused");
    }
    // …and every documented reason is exercised by some sequence.
    for (const reason of Object.keys(canonical.refusals)) {
      expect(used.has(reason), `no sequence refuses with ${reason}`).toBe(true);
    }
  });
});

describe("opening a task", () => {
  interface Opening {
    name: string;
    kind: string;
    verb: string;
    directed: boolean;
    names_task?: boolean;
    expect?: string;
    expect_refused?: RefusalReason;
  }

  it("names the creating verb, which no transition row can", () => {
    expect(openingVerb("handoff")).toBe("offer");
    expect(openingVerb("bounty")).toBe("offer");
    expect(openingVerb("approval")).toBeNull();
  });

  it("lets any logged-in sender open, directed or not", () => {
    expect(checkOpen("handoff", "offer", true, false)).toEqual({ ok: true, to: "offered" });
    expect(checkOpen("handoff", "offer", false, false)).toEqual({ ok: true, to: "open" });
  });

  it("refuses an opener that also names an existing task", () => {
    expect(checkOpen("handoff", "offer", true, true)).toEqual({
      ok: false,
      reason: "illegal-step",
    });
  });

  it("tells an unknown verb apart from one that cannot open", () => {
    expect(checkOpen("handoff", "post", false, false)).toEqual({
      ok: false,
      reason: "unknown-verb",
    });
    for (const verb of ["accept", "complete", "cancel", "expire"]) {
      expect(checkOpen("handoff", verb, true, false), verb).toEqual({
        ok: false,
        reason: "illegal-step",
      });
    }
  });

  it("refuses to open a kind the file does not list", () => {
    expect(checkOpen("approval", "offer", false, false)).toEqual({
      ok: false,
      reason: "unknown-kind",
    });
  });

  // The answer is illegal-step and not unknown-verb: `offer` is exactly the
  // verb that opens a bounty, and naming a recipient is the part it cannot do.
  it("refuses to open a bounty to one recipient", () => {
    expect(checkOpen("bounty", "offer", false, false)).toEqual({ ok: true, to: "open" });
    expect(checkOpen("bounty", "offer", true, false)).toEqual({
      ok: false,
      reason: "illegal-step",
    });
  });

  for (const o of canonical.opening_sequences as Opening[]) {
    it(o.name, () => {
      const got = checkOpen(o.kind, o.verb, o.directed, o.names_task ?? false);
      if (o.expect !== undefined) {
        expect(got).toEqual({ ok: true, to: o.expect });
      } else {
        expect(got).toEqual({ ok: false, reason: o.expect_refused });
      }
    });
  }
});

describe("the happy path", () => {
  it("runs a directed offer from accept to complete", () => {
    expect(checkTransition(directed("offered"), ev("accept"), who(SCHOLAR))).toEqual({
      ok: true,
      to: "assigned",
    });
    const assigned: Task = { ...directed("assigned"), assignee: SCHOLAR };
    expect(checkTransition(assigned, ev("progress"), who(SCHOLAR))).toEqual({
      ok: true,
      to: "assigned",
    });
    expect(checkTransition(assigned, ev("complete"), who(SCHOLAR))).toEqual({
      ok: true,
      to: "completed",
    });
  });

  it("lets the offerer cancel from either live state", () => {
    for (const state of ["offered", "assigned"]) {
      expect(checkTransition(directed(state), ev("cancel"), who(ELIZA))).toEqual({
        ok: true,
        to: "cancelled",
      });
    }
  });
});

describe("the receipt verb", () => {
  const refused = (reason: RefusalReason) => ({ ok: false, reason });

  // A receipt is the home's word about an event, so a sender's `confirm` is
  // refused wherever it appears — opening or moving, whatever kind it names,
  // and even when the sender claims to be the server.
  it("is never a sender's to write", () => {
    expect(CONFIRMATION_VERB).toBe("confirm");
    expect(checkTransition(directed("offered"), ev("confirm"), who(SCHOLAR))).toEqual(
      refused("client-confirm"),
    );
    expect(
      checkTransition(directed("offered"), ev("confirm"), { did: SERVER, isSystem: true }),
    ).toEqual(refused("client-confirm"));
    expect(checkOpen("handoff", "confirm", false, false)).toEqual(refused("client-confirm"));
  });

  // The answer must not read as "this kind has no such row yet", which would
  // say a kind could add one. It cannot.
  it("never reads as a verb a kind could add", () => {
    expect(checkTransition({ ...directed("offered"), kind: "no-such-kind" }, ev("confirm"), who(SCHOLAR))).toEqual(
      refused("client-confirm"),
    );
    expect(checkOpen("no-such-kind", "confirm", false, false)).toEqual(refused("client-confirm"));
    for (const [name, kind] of Object.entries(canonical.kinds as Record<string, Kind>)) {
      expect(
        kind.transitions.some((t) => isConfirmation(t.verb)),
        `${name} claims the receipt verb, which belongs to no kind`,
      ).toBe(false);
      expect(isConfirmation(kind.opens.verb), name).toBe(false);
    }
  });
});

describe("the revival relation", () => {
  const refused = (reason: RefusalReason) => ({ ok: false, reason });
  const DEAD = "01M16E7TC0ENDED00000000000";

  it("only an opener revives a finished action", () => {
    expect(REVIVAL_TAG).toBe("act-replaces");
    expect(checkRevival(true, DEAD, "finished")).toEqual({ ok: true });
    expect(checkRevival(true, DEAD, "unknown")).toEqual({ ok: true });
    expect(checkRevival(true, DEAD, "live")).toEqual(refused("replaces-not-terminal"));
    expect(checkRevival(false, DEAD, "finished")).toEqual(refused("replaces-not-opener"));
    for (const bad of ["", "not-a-ulid", "01M16E7TC0SHRT", `${DEAD}X`, DEAD.toLowerCase()]) {
      expect(checkRevival(true, bad, "unknown"), bad).toEqual(refused("replaces-malformed"));
    }
  });

  it("reads an action id as twenty-six Crockford characters", () => {
    expect(isEventId(DEAD)).toBe(true);
    expect(isEventId(DEAD.slice(0, 25))).toBe(false);
    // I, L, O and U are not in the alphabet, which is what keeps a ULID from
    // being confused for something typed by hand.
    for (const c of ["I", "L", "O", "U", "a", "-"]) {
      expect(isEventId(DEAD.slice(0, 25) + c), c).toBe(false);
    }
  });

  interface RevivalCase {
    name: string;
    opens: boolean;
    names: string;
    predecessor: Predecessor;
    expect?: string;
    expect_refused?: RefusalReason;
  }

  for (const c of canonical.revival_sequences as RevivalCase[]) {
    it(c.name, () => {
      const got = checkRevival(c.opens, c.names, c.predecessor);
      if (c.expect !== undefined) {
        expect(c.expect).toBe("accepted");
        expect(got).toEqual({ ok: true });
      } else {
        expect(got).toEqual(refused(c.expect_refused!));
      }
    });
  }
});

describe("refusals", () => {
  const refused = (reason: RefusalReason) => ({ ok: false, reason });

  it("only the offeree may accept", () => {
    expect(checkTransition(directed("offered"), ev("accept"), who(MALLORY))).toEqual(
      refused("wrong-sender"),
    );
    expect(checkTransition(directed("offered"), ev("accept"), who(ELIZA))).toEqual(
      refused("wrong-sender"),
    );
  });

  it("only the assignee may report on the work", () => {
    const assigned: Task = { ...directed("assigned"), assignee: SCHOLAR };
    expect(checkTransition(assigned, ev("complete"), who(MALLORY))).toEqual(
      refused("wrong-sender"),
    );
    expect(checkTransition(assigned, ev("progress"), who(ELIZA))).toEqual(
      refused("wrong-sender"),
    );
  });

  it("only the server may expire a task", () => {
    expect(checkTransition(directed("assigned"), ev("expire"), who(ELIZA))).toEqual(
      refused("wrong-sender"),
    );
    // Claiming the server's name is not being the server.
    expect(checkTransition(directed("assigned"), ev("expire"), who(SERVER))).toEqual(
      refused("wrong-sender"),
    );
    expect(
      checkTransition(directed("assigned"), ev("expire"), { did: SERVER, isSystem: true }),
    ).toEqual({ ok: true, to: "expired" });
  });

  it("an illegal step is refused, and reads as illegal even from a stranger", () => {
    expect(checkTransition(directed("offered"), ev("complete"), who(SCHOLAR))).toEqual(
      refused("illegal-step"),
    );
    expect(checkTransition(directed("offered"), ev("complete"), who(MALLORY))).toEqual(
      refused("illegal-step"),
    );
    const assigned: Task = { ...directed("assigned"), assignee: SCHOLAR };
    expect(checkTransition(assigned, ev("accept"), who(SCHOLAR))).toEqual(
      refused("illegal-step"),
    );
  });

  it("a terminal task takes no further events", () => {
    for (const state of ["completed", "failed", "cancelled", "declined", "expired"]) {
      expect(checkTransition(directed(state), ev("progress"), who(SCHOLAR)), state).toEqual(
        refused("terminal-task"),
      );
      expect(
        checkTransition(directed(state), ev("expire"), { did: SERVER, isSystem: true }),
        state,
      ).toEqual(refused("terminal-task"));
    }
  });

  it("a verb the kind does not list is refused", () => {
    expect(checkTransition(directed("offered"), ev("award"), who(ELIZA))).toEqual(
      refused("unknown-verb"),
    );
  });

  it("a kind the file does not list is refused, before the verb is even read", () => {
    const approval: Task = { ...directed("open"), kind: "approval" };
    expect(checkTransition(approval, ev("request"), who(SCHOLAR))).toEqual(
      refused("unknown-kind"),
    );
    expect(checkTransition(approval, ev("cancel"), who(ELIZA))).toEqual(refused("unknown-kind"));
  });
});

describe("claiming an open post", () => {
  const openTask = (): Task => ({
    kind: "handoff",
    state: "open",
    offerer: ELIZA,
    offeree: null,
  });

  // Ruled: act-caps is a self-declared hint, never a gate. There is no
  // capability check and no refusal for failing one.
  it("is open to any logged-in sender, first valid claim wins", () => {
    for (const did of [SCHOLAR, MALLORY, "did:plc:nobody"]) {
      expect(checkTransition(openTask(), ev("claim"), who(did)), did).toEqual({
        ok: true,
        to: "assigned",
      });
    }
  });

  it("lets the offerer withdraw an open post, and nobody else", () => {
    expect(checkTransition(openTask(), ev("cancel"), who(ELIZA))).toEqual({
      ok: true,
      to: "cancelled",
    });
    for (const did of [SCHOLAR, MALLORY]) {
      expect(checkTransition(openTask(), ev("cancel"), who(did)), did).toEqual({
        ok: false,
        reason: "wrong-sender",
      });
    }
  });

  it("binds a claim to the deadline exactly as an accept is bound", () => {
    const withDeadline: Task = { ...openTask(), deadline: 1_788_000_000 };
    expect(
      checkTransition(withDeadline, { verb: "claim", msgid: "01M16HSC58ACCEPTTOOLATE000" }, who(SCHOLAR)),
    ).toEqual({ ok: false, reason: "deadline-passed" });
    expect(
      checkTransition(withDeadline, { verb: "claim", msgid: "01M16HSB60ACCEPTATEDGE0000" }, who(SCHOLAR)),
    ).toEqual({ ok: true, to: "assigned" });
  });
});

describe("the deadline", () => {
  const DEADLINE = 1_788_000_000;
  const IN_TIME = "01M16E7TC0ACCEPTINTIME0000";
  const AT_EDGE = "01M16HSB60ACCEPTATEDGE0000";
  const TOO_LATE = "01M16HSC58ACCEPTTOOLATE000";
  const withDeadline = (): Task => ({ ...directed("offered"), deadline: DEADLINE });

  it("an event id carries the millisecond it was minted", () => {
    expect(eventTimeMs(IN_TIME)).toBe(1_787_996_400_000);
    expect(eventTimeMs(AT_EDGE)).toBe(1_788_000_120_000);
    expect(eventTimeMs("not-a-ulid")).toBeNull();
  });

  it("an accept after the deadline is refused", () => {
    expect(
      checkTransition(withDeadline(), { verb: "accept", msgid: TOO_LATE }, who(SCHOLAR)),
    ).toEqual({ ok: false, reason: "deadline-passed" });
  });

  it("an accept inside the deadline, or at the edge of the tolerance, stands", () => {
    for (const msgid of [IN_TIME, AT_EDGE]) {
      expect(
        checkTransition(withDeadline(), { verb: "accept", msgid }, who(SCHOLAR)),
        msgid,
      ).toEqual({ ok: true, to: "assigned" });
    }
  });

  it("binds only the transitions that declare it", () => {
    expect(
      checkTransition(withDeadline(), { verb: "decline", msgid: TOO_LATE }, who(SCHOLAR)),
    ).toEqual({ ok: true, to: "declined" });
    expect(
      checkTransition(withDeadline(), { verb: "cancel", msgid: TOO_LATE }, who(ELIZA)),
    ).toEqual({ ok: true, to: "cancelled" });
  });

  it("a task with no deadline is never late", () => {
    expect(
      checkTransition(directed("offered"), { verb: "accept", msgid: TOO_LATE }, who(SCHOLAR)),
    ).toEqual({ ok: true, to: "assigned" });
  });

  it("fails closed on an event id whose clock cannot be read", () => {
    expect(
      checkTransition(withDeadline(), { verb: "accept", msgid: "not-a-ulid" }, who(SCHOLAR)),
    ).toEqual({ ok: false, reason: "deadline-passed" });
  });
});

describe("the two schema additions bounty needed", () => {
  const refused = (reason: RefusalReason) => ({ ok: false, reason });
  const bounty = (state: string): Task => ({ kind: "bounty", state, offerer: ELIZA });
  /** The bid an award names in these tests. */
  const BID = "01M16E7TC0BDTAKEN000000000";
  const award = { verb: "award", msgid: NOW, accepts: BID, fields: ["act-accepts"] };
  const took = (did: string, author: string): EventSender => ({
    did,
    acceptedBid: { author },
  });

  // Checked before authority: an award naming no bid is malformed for
  // everybody, and "not you" would send the sender after the wrong problem.
  it("an award names the bid it takes, or it is no award", () => {
    const bare = { verb: "award", msgid: NOW, fields: [] };
    expect(checkTransition(bounty("open"), bare, took(ELIZA, SCHOLAR))).toEqual(
      refused("missing-requirement"),
    );
    expect(checkTransition(bounty("open"), bare, took(MALLORY, SCHOLAR))).toEqual(
      refused("missing-requirement"),
    );
    expect(checkTransition(bounty("open"), award, took(ELIZA, SCHOLAR))).toEqual({
      ok: true,
      to: "assigned",
    });
  });

  // The award names one event and the caller resolves it. A name that found
  // no bid on this action takes nothing, and says so.
  it("an award naming something that is not a bid takes nothing", () => {
    expect(checkTransition(bounty("open"), award, who(ELIZA))).toEqual(
      refused("accepts-not-a-bid"),
    );
    expect(checkTransition(bounty("open"), award, who(MALLORY))).toEqual(
      refused("accepts-not-a-bid"),
    );
  });

  // The server still never picks: which of the bids on the table is worth
  // taking is the poster's to decide.
  it("lets the poster take whichever bid they name", () => {
    for (const author of [SCHOLAR, MALLORY, "did:plc:nobody"]) {
      expect(checkTransition(bounty("open"), award, took(ELIZA, author)), author).toEqual({
        ok: true,
        to: "assigned",
      });
    }
  });

  // The guard has to be free for every row that names nothing, which is
  // almost all of them.
  it("leaves a transition that requires nothing exactly as it was", () => {
    expect(checkTransition(directed("offered"), ev("accept"), who(SCHOLAR))).toEqual({
      ok: true,
      to: "assigned",
    });
  });

  it("says where each transition's assignee comes from", () => {
    expect(assigneeSource("bounty", "award", "open")).toEqual({
      from: "author_of",
      field: "act-accepts",
    });
    for (const [kind, verb, from] of [
      ["handoff", "accept", "offered"],
      ["handoff", "claim", "open"],
      ["bounty", "bid", "open"],
    ]) {
      expect(assigneeSource(kind, verb, from), `${kind}/${verb}`).toEqual({ from: "actor" });
    }
    expect(assigneeSource("approval", "request", "open")).toEqual({ from: "actor" });
  });

  // A bounty takes bids until its own cutoff, which is a shorter question
  // than how long the offer stands.
  it("binds a bid to the offer's bid deadline, and the award to its own", () => {
    const DEADLINE = 1_788_000_000;
    const TOO_LATE = "01M16HSC58ACCEPTTOOLATE000";
    const AT_EDGE = "01M16HSB60ACCEPTATEDGE0000";
    const takingBids: Task = { ...bounty("open"), bidDeadline: DEADLINE };
    expect(
      checkTransition(takingBids, { verb: "bid", msgid: TOO_LATE }, who(SCHOLAR)),
    ).toEqual(refused("deadline-passed"));
    expect(checkTransition(takingBids, { verb: "bid", msgid: AT_EDGE }, who(SCHOLAR))).toEqual({
      ok: true,
      to: "open",
    });
    // Bidding closing does not stop the poster picking: the award is bound by
    // the offer's own deadline, which this bounty never named.
    expect(
      checkTransition(
        takingBids,
        { verb: "award", msgid: TOO_LATE, accepts: BID, fields: ["act-accepts"] },
        took(ELIZA, SCHOLAR),
      ),
    ).toEqual({ ok: true, to: "assigned" });
    // …and no bid cutoff means no bid cutoff.
    expect(
      checkTransition(bounty("open"), { verb: "bid", msgid: TOO_LATE }, who(SCHOLAR)),
    ).toEqual({ ok: true, to: "open" });
  });

  it("takes bids additively until the work is awarded", () => {
    expect(checkTransition(bounty("open"), ev("bid"), who(SCHOLAR))).toEqual({
      ok: true,
      to: "open",
    });
    expect(checkTransition(bounty("assigned"), ev("bid"), who(MALLORY))).toEqual(
      refused("illegal-step"),
    );
  });
});

describe("the shared sequences", () => {
  const sequences = canonical.sequences as Sequence[];

  it("carries a real set", () => {
    expect(sequences.length).toBeGreaterThanOrEqual(20);
  });

  for (const seq of sequences) {
    it(seq.name, () => {
      let state = seq.task.state ?? initialState(seq.task.kind, seq.task.offer === "directed") ?? "open";
      let assignee: string | null = null;

      seq.steps.forEach((step, i) => {
        const task: Task = {
          kind: seq.task.kind,
          state,
          offerer: seq.task.offerer,
          offeree: seq.task.offeree,
          assignee,
          deadline: seq.task.deadline,
          bidDeadline: seq.task.bid_deadline,
        };
        const result = checkTransition(
          task,
          {
            verb: step.verb,
            msgid: step.event_id ?? NOW,
            accepts: step.accepts,
            fields: step.tags ?? [],
          },
          {
            did: step.sender,
            isSystem: step.system ?? false,
            // What the caller's log made of the event this one names. A step
            // that sets nothing named nothing, or named something that is not
            // a bid — the file does not distinguish, because neither does the
            // checker.
            acceptedBid: step.accepted_bid ? { author: step.accepted_bid } : null,
          },
        );
        const where = `${seq.name} — step ${i + 1} (${step.verb})`;

        if (step.expect !== undefined) {
          expect(result, where).toEqual({ ok: true, to: step.expect });
          // A refused step changes nothing; an accepted one may name the
          // assignee. Who that is, is data: the actor by default, and whoever
          // the transition's field names otherwise — a bounty's award names
          // its winner rather than becoming one.
          if (assignee === null && step.expect === "assigned") {
            const source = assigneeSource(seq.task.kind, step.verb, state);
            if (source.from === "actor") {
              assignee = step.sender;
            } else if (source.from === "author_of") {
              if (!step.accepted_bid) {
                throw new Error(
                  `${where}: this transition assigns the author of the bid it names, and none was resolved`,
                );
              }
              assignee = step.accepted_bid;
            } else if (!step.assigns) {
              throw new Error(
                `${where}: assigns is not set, but this transition takes its assignee from ${source.field}`,
              );
            } else {
              assignee = step.assigns;
            }
          }
          state = step.expect;
        } else {
          expect(result, where).toEqual({ ok: false, reason: step.expect_refused });
        }
      });
    });
  }
});
