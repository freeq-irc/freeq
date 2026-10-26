import { describe, it, expect } from "vitest";
import { gistOf, renderStatus, toolDetail, STATUS_BUDGET, type StepStatus } from "./status.js";

describe("gistOf", () => {
  it("flattens whitespace and leaves short text alone", () => {
    expect(gistOf("hello\n  world")).toBe("hello world");
  });
  it("truncates at a word boundary with an ellipsis", () => {
    const g = gistOf("looking at why reconnect drops channels on every blip", 36);
    expect(g.length).toBeLessThanOrEqual(36);
    expect(g.endsWith("…")).toBe(true);
    // The pre-ellipsis part is a whole-word prefix of the original.
    expect("looking at why reconnect drops channels on every blip".startsWith(g.slice(0, -1) + " ")).toBe(true);
    expect(g).toBe("looking at why reconnect drops…");
  });
  it("saws a single huge word rather than return nothing", () => {
    const g = gistOf("x".repeat(100), 20);
    expect(g.length).toBeLessThanOrEqual(20);
    expect(g.endsWith("…")).toBe(true);
  });
});

describe("toolDetail", () => {
  it("shows the command for bash, not the word bash", () => {
    expect(toolDetail("bash", { command: "npm run test\n--watch" })).toBe("bash: npm run test");
  });
  it("shows the basename for file tools", () => {
    expect(toolDetail("edit", { path: "/very/long/path/ui.ts" })).toBe("edit: ui.ts");
  });
  it("falls back to the tool name and caps length", () => {
    expect(toolDetail("think", undefined)).toBe("think");
    const d = toolDetail("bash", { command: "x".repeat(200) }, 18);
    expect(d.length).toBeLessThanOrEqual(18);
  });
});

describe("renderStatus", () => {
  const step: StepStatus = { phrase: "answering chad in #freeq-dev", since: 0, tool: "bash: npm test" };
  it("renders phrase, tool and elapsed inside the wire budget", () => {
    const s = renderStatus(step, 125_000);
    expect(s).toBe("answering chad in #freeq-dev · bash: npm test · 2m");
    expect(s.length).toBeLessThanOrEqual(STATUS_BUDGET);
  });
  it("omits the tool slot when there is no tool", () => {
    expect(renderStatus({ phrase: "thinking", since: 0 }, 5_000)).toBe("thinking · 5s");
  });
  it("drops the tool detail first when the budget is tight", () => {
    const s = renderStatus({ phrase: "a".repeat(40), since: 0, tool: "bash: npm test" }, 60_000, 50);
    expect(s).toBe(`${"a".repeat(40)} · 1m`);
    expect(s.length).toBeLessThanOrEqual(50);
  });
  it("never drops the elapsed time — it is how you tell thinking from stuck", () => {
    const s = renderStatus({ phrase: "p".repeat(80), since: 0, tool: "bash" }, 600_000, 30);
    expect(s.length).toBeLessThanOrEqual(30);
    expect(s.endsWith(" · 10m")).toBe(true);
  });
});
