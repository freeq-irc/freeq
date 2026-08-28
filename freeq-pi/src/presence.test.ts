import { describe, it, expect } from "vitest";
import {
  normalizeRemote,
  formatStatus,
  parseStatus,
  describeMeta,
  collectSessionMeta,
  looksLikePath,
  type SessionMeta,
} from "./presence.js";

describe("normalizeRemote", () => {
  it("normalizes the common remote forms to host/owner/repo", () => {
    const cases: Array<[string, string]> = [
      ["git@github.com:freeq-irc/freeq.git", "github.com/freeq-irc/freeq"],
      ["https://github.com/freeq-irc/freeq.git", "github.com/freeq-irc/freeq"],
      ["https://github.com/freeq-irc/freeq", "github.com/freeq-irc/freeq"],
      ["ssh://git@github.com/freeq-irc/freeq.git", "github.com/freeq-irc/freeq"],
    ];
    for (const [input, want] of cases) expect(normalizeRemote(input)).toBe(want);
  });

  it("strips embedded credentials", () => {
    // A token in a remote URL must never reach the network as presence.
    expect(normalizeRemote("https://user:ghp_secret@github.com/o/r.git")).toBe("github.com/o/r");
    expect(normalizeRemote("https://user:ghp_secret@github.com/o/r.git")).not.toContain("ghp_secret");
  });

  it("returns undefined for empty input", () => {
    expect(normalizeRemote(undefined)).toBeUndefined();
    expect(normalizeRemote("   ")).toBeUndefined();
  });
});

describe("formatStatus / parseStatus", () => {
  it("round-trips metadata", () => {
    const meta: SessionMeta = {
      project: "freeq",
      repo: "github.com/freeq-irc/freeq",
      branch: "main",
      model: "claude-opus-5",
    };
    expect(parseStatus(formatStatus(meta))).toEqual(meta);
  });

  it("drops values containing spaces or semicolons (presence is delimited)", () => {
    expect(formatStatus({ project: "two words" })).toBe("");
    expect(formatStatus({ branch: "a;b" })).toBe("");
  });

  it("never emits an absolute path", () => {
    // Defence in depth: SessionMeta has no path field, but if one were ever
    // added, formatStatus must not leak it. (M0 leaked a path via the answer
    // path; presence must not be a second route.)
    const sneaky = { project: "/Users/chad/src/freeq" } as unknown as SessionMeta;
    expect(formatStatus(sneaky)).toBe("");
    const win = { project: "C:\\Users\\chad\\src" } as unknown as SessionMeta;
    expect(formatStatus(win)).toBe("");
  });

  it("ignores unknown keys when parsing", () => {
    expect(parseStatus("project=freeq cwd=/Users/chad evil=1")).toEqual({ project: "freeq" });
  });

  it("tolerates junk", () => {
    expect(parseStatus(undefined)).toEqual({});
    expect(parseStatus("")).toEqual({});
    expect(parseStatus("=nokey novalue=")).toEqual({});
  });
});

describe("collectSessionMeta", () => {
  it("advertises repo/branch/project but never a path", async () => {
    const meta = await collectSessionMeta({ cwd: process.cwd(), model: "test-model" });
    const serialized = JSON.stringify(meta);
    expect(serialized).not.toContain("/Users/");
    expect(serialized).not.toContain(process.cwd());
    expect(meta).not.toHaveProperty("cwd");
    // In this repo we expect real values.
    expect(meta.project).toBe("freeq");
    expect(meta.model).toBe("test-model");
  });
});

describe("describeMeta", () => {
  it("summarizes", () => {
    expect(describeMeta({ project: "freeq", branch: "main", model: "m" })).toBe("freeq @main · m");
  });
  it("handles empty", () => {
    expect(describeMeta({})).toBe("no metadata");
  });
});

describe("looksLikePath", () => {
  it("catches every absolute-path form we might leak", () => {
    for (const p of [
      "/Users/chad/src/freeq",
      "/etc/passwd",
      "~/src/freeq",
      "C:\\Users\\chad",
      "c:/Users/chad",
      "\\\\server\\share",
    ]) {
      expect(looksLikePath(p)).toBe(true);
    }
  });

  it("does not flag legitimate values", () => {
    for (const ok of ["freeq", "github.com/freeq-irc/freeq", "main", "claude-opus-5", "feat/x"]) {
      expect(looksLikePath(ok)).toBe(false);
    }
  });
});
