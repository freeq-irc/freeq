import { describe, it, expect } from "vitest";
import { logoAnsi, logoCompactLines, logoLines, markForTerminal, supportsTruecolor, WORDMARK } from "./logo.js";

describe("the mark", () => {
  it("ships, is truecolor half-block art, and fits an 80-column terminal", () => {
    const lines = logoLines();
    expect(lines.length).toBeGreaterThan(20);
    expect(lines.length).toBeLessThanOrEqual(30);
    const plain = lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, ""));
    for (const p of plain) expect(p.length).toBeLessThanOrEqual(80);
    expect(new Set(plain.join("").replace(/\s/g, ""))).toEqual(new Set(["▀"]));
    expect(logoAnsi()).toContain("\x1b[38;2;"); // truecolor
    // Every line resets, so nothing bleeds into what follows.
    for (const l of lines) expect(l.endsWith("\x1b[0m")).toBe(true);
  });

  it("is only offered where it will render", () => {
    expect(supportsTruecolor({ COLORTERM: "truecolor" })).toBe(true);
    expect(supportsTruecolor({ TERM_PROGRAM: "ghostty" })).toBe(true);
    expect(supportsTruecolor({ TERM_PROGRAM: "iTerm.app" })).toBe(true);
    expect(supportsTruecolor({ TERM: "xterm-256color" })).toBe(false);
    expect(supportsTruecolor({ TERM: "dumb" })).toBe(false);
    // NO_COLOR is an instruction, not a hint.
    expect(supportsTruecolor({ NO_COLOR: "1", COLORTERM: "truecolor" })).toBe(false);
    expect(WORDMARK).toContain("freeq");
  });

  it("has a half-scale mark for terminals without the room", () => {
    const compact = logoCompactLines();
    expect(compact.length).toBeGreaterThan(8);
    expect(compact.length).toBeLessThan(logoLines().length);
    const plain = compact.map((l) => l.replace(/\x1b\[[0-9;]*m/g, ""));
    expect(new Set(plain.map((p) => p.length)).size).toBe(1); // rectangular
    expect(plain[0]!.length).toBeLessThanOrEqual(40);
  });

  it("picks the biggest mark that fits, and none when nothing does", () => {
    // pi caps string-array widgets at 10 lines, so a 27-row mark must go
    // through a component factory; height is still the real constraint.
    expect(markForTerminal(60)).toEqual(logoLines());
    expect(markForTerminal(24)).toEqual(logoCompactLines());
    expect(markForTerminal(12)).toEqual([]);
  });
});
