import { describe, it, expect } from "vitest";
import {
  shouldRecord,
  describeToolEvent,
  TurnRecorder,
  formatDecision,
  buildProvenance,
  parseProvenance,
  DEFAULT_PROVENANCE_TIER,
  type ProvenanceTier,
} from "./provenance.js";

const bash = (command: string) => ({ name: "bash", input: { command } });

describe("what is worth recording", () => {
  it("defaults to decisions, not a firehose", () => {
    expect(DEFAULT_PROVENANCE_TIER).toBe("decisions");
  });

  it("records changes and outbound actions", () => {
    for (const ev of [
      { name: "edit", input: { path: "src/a.ts" } },
      { name: "write", input: { path: "src/b.ts" } },
      bash("npm run deploy"),
      { name: "freeq", input: { action: "handoff", to: "pi-zapnap" } },
    ]) {
      expect(shouldRecord(ev, "decisions"), `${ev.name} should be recorded`).toBe(true);
    }
  });

  it("ignores looking around — that is how the log stays readable", () => {
    // A log that records every `ls` buries the `git push` that matters.
    for (const cmd of [
      "ls -la",
      "cat package.json",
      "grep -rn foo src/",
      "rg pattern",
      "git status",
      "git log --oneline -5",
      "git diff HEAD~1",
      "npm ls",
      "pwd",
      "wc -l file",
    ]) {
      expect(shouldRecord(bash(cmd), "decisions"), `${cmd} should be ignored`).toBe(false);
    }
  });

  it("still records a mutating git command", () => {
    for (const cmd of ["git push origin main", "git commit -m x", "git reset --hard"]) {
      expect(shouldRecord(bash(cmd), "decisions"), cmd).toBe(true);
    }
  });

  it("ignores pure reads at the decisions tier", () => {
    expect(shouldRecord({ name: "read", input: { path: "x" } }, "decisions")).toBe(false);
    expect(shouldRecord({ name: "glob" }, "decisions")).toBe(false);
  });

  it("records nothing at all when silent", () => {
    for (const ev of [{ name: "edit", input: { path: "a" } }, bash("rm -rf /")]) {
      expect(shouldRecord(ev, "silent")).toBe(false);
    }
  });

  it("records everything at firehose, including reads", () => {
    expect(shouldRecord({ name: "read", input: { path: "x" } }, "firehose")).toBe(true);
    expect(shouldRecord(bash("ls"), "firehose")).toBe(true);
  });

  it("is monotonic — a higher tier never records less", () => {
    const tiers: ProvenanceTier[] = ["silent", "decisions", "evidence", "firehose"];
    const events = [
      { name: "edit", input: { path: "a.ts" } },
      bash("ls"),
      bash("npm publish"),
      { name: "read", input: { path: "b" } },
    ];
    for (const ev of events) {
      let seen = false;
      for (const t of tiers) {
        const now = shouldRecord(ev, t);
        if (seen && !now) throw new Error(`${ev.name} recorded at a lower tier but not ${t}`);
        seen = seen || now;
      }
    }
  });
});

describe("descriptions are for humans", () => {
  it("names the file, not the path", () => {
    // Absolute paths are also a disclosure risk; the basename is enough.
    expect(describeToolEvent({ name: "edit", input: { path: "/Users/x/src/app/auth.ts" } })).toBe(
      "edited auth.ts",
    );
    expect(describeToolEvent({ name: "write", input: { path: "a/b/c.md" } })).toBe("wrote c.md");
  });

  it("summarizes a command to one line", () => {
    expect(describeToolEvent(bash("npm test\nnpm run build"))).toBe("ran: npm test…");
  });

  it("truncates a very long command", () => {
    const d = describeToolEvent(bash("x".repeat(400)));
    expect(d.length).toBeLessThan(140);
  });

  it("names the freeq action and its target", () => {
    expect(
      describeToolEvent({ name: "freeq", input: { action: "ask", to: "pi-zapnap" } }),
    ).toBe("freeq ask → pi-zapnap");
  });
});

describe("TurnRecorder", () => {
  it("says nothing about a turn that changed nothing", () => {
    const r = new TurnRecorder();
    r.record(bash("ls"), "decisions");
    r.record({ name: "read", input: { path: "a" } }, "decisions");
    expect(r.isEmpty).toBe(true);
    expect(r.summary()).toBeUndefined();
  });

  it("collapses a turn into one line", () => {
    const r = new TurnRecorder();
    r.record({ name: "edit", input: { path: "src/auth.ts" } }, "decisions");
    r.record({ name: "edit", input: { path: "src/gate.ts" } }, "decisions");
    r.record(bash("npm test"), "decisions");
    expect(r.summary()).toBe("edited auth.ts; edited gate.ts; ran: npm test");
    expect(r.files).toEqual(["auth.ts", "gate.ts"]);
  });

  it("caps a long turn instead of dumping it", () => {
    const r = new TurnRecorder();
    for (let i = 0; i < 20; i++) r.record({ name: "edit", input: { path: `f${i}.ts` } }, "decisions");
    const s = r.summary(3)!;
    expect(s).toMatch(/\+17 more$/);
  });

  it("resets between turns", () => {
    const r = new TurnRecorder();
    r.record({ name: "edit", input: { path: "a.ts" } }, "decisions");
    r.reset();
    expect(r.isEmpty).toBe(true);
    expect(r.files).toEqual([]);
  });
});

describe("decision records", () => {
  it("formats the parts a reader needs", () => {
    const out = formatDecision({
      choice: "Store handoffs in the channel, not a DM",
      rationale: "channel history gives offline replay for free",
      alternatives: "a per-agent inbox",
      evidence: "task 01M130ZXXK",
    });
    expect(out).toContain("decision: Store handoffs in the channel");
    expect(out).toContain("because: channel history gives offline replay");
    expect(out).toContain("instead of: a per-agent inbox");
    expect(out).toContain("evidence: task 01M130ZXXK");
  });

  it("works with just a choice", () => {
    expect(formatDecision({ choice: "Ship it" })).toBe("decision: Ship it");
  });
});

describe("payload round-trip and hostile input", () => {
  it("round-trips", () => {
    const p = buildProvenance({ v: 1, kind: "turn", text: "edited auth.ts", files: ["auth.ts"] });
    expect(parseProvenance(JSON.parse(JSON.stringify(p)))).toEqual(p);
  });

  it("rejects junk", () => {
    for (const junk of [null, 42, "s", {}, { v: 1 }, { v: 1, kind: "bogus", text: "x" }, { v: 1, kind: "turn", text: "  " }]) {
      expect(parseProvenance(junk)).toBeUndefined();
    }
  });

  it("caps oversized text and file lists", () => {
    const p = parseProvenance({
      v: 1,
      kind: "turn",
      text: "x".repeat(9999),
      files: Array.from({ length: 500 }, (_, i) => `f${i}`),
    });
    expect(p!.text.length).toBe(2000);
    expect(p!.files!.length).toBe(50);
  });
});
