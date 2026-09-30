import { describe, expect, it } from "vitest";
import { addressed, execute, parseCommand, type CommandDeps } from "./commands.js";
import type { Answer, Question, RunInfo } from "./fabro-api.js";

describe("addressed", () => {
  it.each([
    ["fabro status", "status"],
    ["fabro: approve abc123", "approve abc123"],
    ["@fabro, help", "help"],
    ["FABRO run bug-hunt", "run bug-hunt"],
    ["fabro", ""],
  ])("%s → %s", (text, rest) => expect(addressed(text, "fabro")).toBe(rest));

  it.each(["fabrocop status", "hey fabro status", "status"])("ignores %s", (text) => {
    expect(addressed(text, "fabro")).toBeNull();
  });
});

describe("parseCommand", () => {
  it("parses each verb", () => {
    expect(parseCommand("status")).toEqual({ kind: "status" });
    expect(parseCommand("run bug-hunt")).toEqual({ kind: "run", workflow: "bug-hunt", goal: undefined });
    expect(parseCommand("run feature harden   uploads")).toEqual({ kind: "run", workflow: "feature", goal: "harden uploads" });
    expect(parseCommand("approve")).toEqual({ kind: "approve", run: undefined });
    expect(parseCommand("deny x7k2qa")).toEqual({ kind: "deny", run: "x7k2qa" });
    expect(parseCommand("answer x7k2qa option_b")).toEqual({ kind: "answer", run: "x7k2qa", text: "option_b" });
    expect(parseCommand("cancel x7k2qa")).toEqual({ kind: "cancel", run: "x7k2qa" });
    expect(parseCommand("")).toEqual({ kind: "help" });
  });

  it("rejects incomplete commands", () => {
    expect(parseCommand("run").kind).toBe("unknown");
    expect(parseCommand("cancel").kind).toBe("unknown");
    expect(parseCommand("answer x7k2qa").kind).toBe("unknown");
    expect(parseCommand("rm -rf /").kind).toBe("unknown");
  });
});

// ── execute, against an in-memory Fabro ─────────────────────────────────
const gate = (over: Partial<Question> = {}): Question => ({
  id: "q1", text: "Approve plan?", stage: "approve", question_type: "confirmation",
  options: [], allow_freeform: false, ...over,
});

function fake(runs: RunInfo[], questions: Record<string, Question[]> = {}) {
  const calls: string[] = [];
  const answers: Array<[string, string, Answer]> = [];
  const deps: CommandDeps = {
    api: {
      listRuns: async () => runs,
      questions: async (id) => questions[id] ?? [],
      answer: async (id, qid, a) => { answers.push([id, qid, a]); },
      cancel: async (id) => { calls.push(`cancel ${id}`); },
      triggerAutomation: async (id) => { calls.push(`trigger ${id}`); return "01NEWRUNAAAAAAAAAAAAZZZZZZ"; },
      automationIds: async () => ["bug-hunt", "dep-audit", "test-coverage"],
    },
    launchWithGoal: async (wf, goal) => { calls.push(`launch ${wf} ${goal}`); return "01GOALRUNAAAAAAAAAAAYYYYYY"; },
    workflows: async () => ["bug-hunt", "dep-audit", "feature", "test-coverage"],
  };
  return { deps, calls, answers };
}

const R1: RunInfo = { id: "01AAAAAAAAAAAAAAAAAAX7K2QA", workflow: "feature", status: "blocked" };
const R2: RunInfo = { id: "01BBBBBBBBBBBBBBBBBBP9Z1MM", workflow: "bug-hunt", status: "running" };
const DONE: RunInfo = { id: "01CCCCCCCCCCCCCCCCCCDONE01", workflow: "dep-audit", status: "succeeded" };

describe("execute", () => {
  it("status lists active runs and what they wait on", async () => {
    const { deps } = fake([R1, R2, DONE], { [R1.id]: [gate()] });
    expect(await execute({ kind: "status" }, deps)).toEqual([
      'x7k2qa feature blocked — waiting: "Approve plan?"',
      "p9z1mm bug-hunt running",
    ]);
  });

  it("approve with no id answers the only waiting gate", async () => {
    const { deps, answers } = fake([R1, R2], { [R1.id]: [gate()] });
    expect(await execute({ kind: "approve" }, deps)).toEqual(["approved feature [x7k2qa]"]);
    expect(answers).toEqual([[R1.id, "q1", { kind: "yes" }]]);
  });

  it("deny by short id", async () => {
    const { deps, answers } = fake([R1], { [R1.id]: [gate({ question_type: "yes_no" })] });
    expect(await execute({ kind: "deny", run: "X7K2QA" }, deps)).toEqual(["denied feature [x7k2qa]"]);
    expect(answers[0][2]).toEqual({ kind: "no" });
  });

  it("asks which gate when several are waiting", async () => {
    const { deps, answers } = fake([R1, R2], { [R1.id]: [gate()], [R2.id]: [gate()] });
    const [line] = await execute({ kind: "approve" }, deps);
    expect(line).toContain("2 gates are waiting");
    expect(answers).toEqual([]);
  });

  it("points multiple-choice gates at `answer`, then maps the choice", async () => {
    const q = gate({ question_type: "multiple_choice", options: [{ key: "a", label: "Plan A" }, { key: "b", label: "Plan B" }] });
    const { deps, answers } = fake([R1], { [R1.id]: [q] });
    const [hint] = await execute({ kind: "approve" }, deps);
    expect(hint).toContain("fabro answer x7k2qa <choice>");
    expect(await execute({ kind: "answer", run: "x7k2qa", text: "plan b" }, deps)).toEqual(["answered feature [x7k2qa]"]);
    expect(answers).toEqual([[R1.id, "q1", { kind: "selected", option_key: "b" }]]);
  });

  it("refuses a choice that isn't offered", async () => {
    const q = gate({ question_type: "multiple_choice", options: [{ key: "a", label: "Plan A" }] });
    const { deps } = fake([R1], { [R1.id]: [q] });
    await expect(execute({ kind: "answer", run: "x7k2qa", text: "z" }, deps)).rejects.toThrow(/isn't one of: a/);
  });

  it("says when nothing is waiting", async () => {
    const { deps } = fake([R2]);
    expect(await execute({ kind: "approve" }, deps)).toEqual(["nothing is waiting on you"]);
  });

  it("run without a goal fires the automation", async () => {
    const { deps, calls } = fake([]);
    expect(await execute({ kind: "run", workflow: "bug-hunt" }, deps)).toEqual(["started bug-hunt [zzzzzz] from main"]);
    expect(calls).toEqual(["trigger bug-hunt"]);
  });

  it("run with a goal launches through the CLI", async () => {
    const { deps, calls } = fake([]);
    expect(await execute({ kind: "run", workflow: "feature", goal: "harden uploads" }, deps))
      .toEqual(["started feature [yyyyyy] with your goal"]);
    expect(calls).toEqual(["launch feature harden uploads"]);
  });

  it("run refuses unknown workflows and goal-less feature", async () => {
    const { deps, calls } = fake([]);
    expect((await execute({ kind: "run", workflow: "nope" }, deps))[0]).toContain('unknown workflow "nope"');
    expect((await execute({ kind: "run", workflow: "feature" }, deps))[0]).toContain("feature needs a goal");
    expect(calls).toEqual([]);
  });

  it("cancel resolves the short id; ambiguity and misses are reported", async () => {
    const { deps, calls } = fake([R1, R2]);
    expect(await execute({ kind: "cancel", run: "p9z1mm" }, deps)).toEqual(["cancelled bug-hunt [p9z1mm]"]);
    expect(calls).toEqual([`cancel ${R2.id}`]);
    expect(await execute({ kind: "cancel", run: "nomatch" }, deps)).toEqual(['no recent run matches "nomatch"']);
    const twins = fake([R1, { ...R2, id: "01BBBBBBBBBBBBBBBBBBAAX7K2QA" }]);
    expect((await execute({ kind: "cancel", run: "x7k2qa" }, twins.deps))[0]).toContain("matches 2 runs");
  });
});
