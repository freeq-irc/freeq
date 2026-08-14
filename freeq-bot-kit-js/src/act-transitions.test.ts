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
  checkTransition,
  eventTimeMs,
  initialState,
  isTerminal,
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
  sender_caps?: string[];
  event_id?: string;
  system?: boolean;
  expect?: string;
  expect_refused?: RefusalReason;
}

interface Sequence {
  name: string;
  task: {
    kind: string;
    offer: string;
    state?: string;
    offerer: string;
    offeree: string | null;
    caps: string[];
    deadline: number | null;
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
    expect(initialState("bounty", false)).toBeNull();
  });

  it("carries the five terminal states and no others", () => {
    for (const s of ["completed", "failed", "cancelled", "declined", "expired"]) {
      expect(isTerminal("handoff", s), s).toBe(true);
    }
    for (const s of ["offered", "open", "assigned"]) {
      expect(isTerminal("handoff", s), s).toBe(false);
    }
  });

  it("does not carry the deferred approval kind", () => {
    expect(Object.keys(canonical.kinds)).toEqual(["handoff"]);
  });

  it("uses the same deadline tolerance as the Rust checker", () => {
    expect(DEADLINE_TOLERANCE_MS).toBe(120_000);
  });

  it("documents every refusal reason it uses", () => {
    const used = new Set<string>(
      (canonical.sequences as Sequence[]).flatMap((s) =>
        s.steps.map((st) => st.expect_refused).filter(Boolean),
      ) as string[],
    );
    for (const reason of used) {
      expect(refusalDescription(reason as RefusalReason), reason).not.toBe("refused");
    }
    // …and every documented reason is exercised by some sequence.
    for (const reason of Object.keys(canonical.refusals)) {
      expect(used.has(reason), `no sequence refuses with ${reason}`).toBe(true);
    }
  });
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
    const bounty: Task = { ...directed("open"), kind: "bounty" };
    expect(checkTransition(bounty, ev("bid"), who(SCHOLAR))).toEqual(refused("unknown-kind"));
    expect(checkTransition(bounty, ev("cancel"), who(ELIZA))).toEqual(refused("unknown-kind"));
  });
});

describe("capabilities", () => {
  const openTask = (caps: string[]): Task => ({
    kind: "handoff",
    state: "open",
    offerer: ELIZA,
    offeree: null,
    caps,
  });

  it("a claim needs every capability the task asked for", () => {
    const task = openTask(["freeq.at/log-analysis", "freeq.at/web-search"]);
    expect(
      checkTransition(task, ev("claim"), { did: MALLORY, caps: ["freeq.at/log-analysis"] }),
    ).toEqual({ ok: false, reason: "caps-mismatch" });
    expect(
      checkTransition(task, ev("claim"), {
        did: SCHOLAR,
        caps: ["freeq.at/web-search", "freeq.at/log-analysis", "freeq.at/spare"],
      }),
    ).toEqual({ ok: true, to: "assigned" });
  });

  it("an open task asking for nothing is claimable by anyone", () => {
    expect(checkTransition(openTask([]), ev("claim"), who(MALLORY))).toEqual({
      ok: true,
      to: "assigned",
    });
  });

  it("a missing capability reads as caps-mismatch, not wrong-sender", () => {
    expect(
      checkTransition(openTask(["freeq.at/log-analysis"]), ev("claim"), who(MALLORY)),
    ).toEqual({ ok: false, reason: "caps-mismatch" });
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
          caps: seq.task.caps,
          deadline: seq.task.deadline,
        };
        const result = checkTransition(
          task,
          { verb: step.verb, msgid: step.event_id ?? NOW },
          { did: step.sender, caps: step.sender_caps ?? [], isSystem: step.system ?? false },
        );
        const where = `${seq.name} — step ${i + 1} (${step.verb})`;

        if (step.expect !== undefined) {
          expect(result, where).toEqual({ ok: true, to: step.expect });
          // A refused step changes nothing; an accepted one may name the
          // assignee, which is the sender who moved it into `assigned`.
          if (assignee === null && step.expect === "assigned") assignee = step.sender;
          state = step.expect;
        } else {
          expect(result, where).toEqual({ ok: false, reason: step.expect_refused });
        }
      });
    });
  }
});
