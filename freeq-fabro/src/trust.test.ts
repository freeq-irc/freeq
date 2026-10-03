import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseCommand } from "./commands.js";
import { allows, loadTrust, parseTrust, requiredTier, tierFor } from "./trust.js";

const OWNER = "did:plc:owner";

describe("tierFor", () => {
  it("makes the owner control and strangers nobody", () => {
    expect(tierFor(OWNER, OWNER, {})).toBe("control");
    expect(tierFor("did:plc:stranger", OWNER, {})).toBeNull();
    expect(tierFor(null, OWNER, { "did:plc:x": "control" })).toBeNull();
  });

  it("uses the table for everyone else, and can't demote the owner", () => {
    const t = { "did:plc:pal": "observe" as const, [OWNER]: "observe" as const };
    expect(tierFor("did:plc:pal", OWNER, t)).toBe("observe");
    expect(tierFor(OWNER, OWNER, t)).toBe("control");
  });
});

describe("requiredTier", () => {
  it.each([
    ["help", "observe"],
    ["status", "observe"],
    ["run bug-hunt", "request"],
    ["run feature harden uploads", "handoff"],
    ["approve", "control"],
    ["deny abc", "control"],
    ["answer abc yes", "control"],
    ["cancel abc", "control"],
  ])("%s needs %s", (text, tier) => expect(requiredTier(parseCommand(text))).toBe(tier));
});

describe("allows", () => {
  it("orders tiers like freeq-pi", () => {
    expect(allows("observe", "observe")).toBe(true);
    expect(allows("observe", "request")).toBe(false);
    expect(allows("request", "handoff")).toBe(false);
    expect(allows("handoff", "request")).toBe(true);
    expect(allows("control", "control")).toBe(true);
    expect(allows(null, "observe")).toBe(false);
  });
});

describe("trust file", () => {
  it("keeps only DID keys with known tiers", () => {
    expect(parseTrust('{"did:plc:a":"observe","did:plc:b":"root","alice":"control","did:plc:c":"request"}'))
      .toEqual({ "did:plc:a": "observe", "did:plc:c": "request" });
  });

  it("treats a missing file as owner-only and a malformed one as an error", async () => {
    const dir = await mkdtemp(join(tmpdir(), "trust-"));
    expect(await loadTrust(join(dir, "none.json"))).toEqual({});
    await writeFile(join(dir, "bad.json"), "{nope");
    await expect(loadTrust(join(dir, "bad.json"))).rejects.toThrow();
    await writeFile(join(dir, "arr.json"), "[]");
    await expect(loadTrust(join(dir, "arr.json"))).rejects.toThrow(/JSON object/);
  });
});
