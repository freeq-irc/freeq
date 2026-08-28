import { describe, it, expect } from "vitest";
import {
  normalizeConfig,
  projectOverrides,
  mergeProject,
  defaultConfig,
  modeFor,
  tierFor,
  tierAtLeast,
  DEFAULT_MODE,
} from "./config.js";

describe("normalizeConfig", () => {
  it("returns defaults for junk input", () => {
    for (const junk of [undefined, null, 42, "nope", []]) {
      expect(normalizeConfig(junk)).toEqual(defaultConfig());
    }
  });

  it("keeps valid fields and drops invalid ones", () => {
    const cfg = normalizeConfig({
      ownerDid: "did:plc:abc",
      server: "wss://example/irc",
      channels: ["#a", "#a", "nope", "#b", 7],
      modes: { "#a": "silent", "#b": "bogus" },
      trust: { "did:plc:x": "request", "not-a-did": "control", "did:plc:y": "nonsense" },
      enabled: false,
    });
    expect(cfg.ownerDid).toBe("did:plc:abc");
    expect(cfg.channels).toEqual(["#a", "#b"]); // dedup + drop non-channels
    expect(cfg.modes).toEqual({ "#a": "silent" }); // bogus mode dropped
    expect(cfg.trust).toEqual({ "did:plc:x": "request" }); // non-DID + bad tier dropped
    expect(cfg.enabled).toBe(false);
  });

  it("rejects an ownerDid that isn't a DID", () => {
    expect(normalizeConfig({ ownerDid: "chad" }).ownerDid).toBeUndefined();
  });
});

describe("project config is narrow", () => {
  it("ignores identity/server/trust from project config", () => {
    const overrides = projectOverrides({
      ownerDid: "did:plc:attacker",
      server: "wss://evil.example/irc",
      trust: { "did:plc:attacker": "control" },
      enabled: true,
      channels: ["#proj"],
      modes: { "#proj": "participant" },
    });
    expect(overrides).toEqual({ channels: ["#proj"], modes: { "#proj": "participant" } });
    expect("ownerDid" in overrides).toBe(false);
    expect("server" in overrides).toBe(false);
    expect("trust" in overrides).toBe(false);
  });

  it("merges channels additively without clobbering user config", () => {
    const user = { ...defaultConfig(), ownerDid: "did:plc:me", channels: ["#user"] };
    const merged = mergeProject(user, projectOverrides({ channels: ["#proj", "#USER"] }));
    expect(merged.channels).toEqual(["#user", "#proj"]); // case-insensitive dedup
    expect(merged.ownerDid).toBe("did:plc:me");
  });
});

describe("modeFor", () => {
  it("defaults to addressed", () => {
    expect(modeFor(defaultConfig(), "#x")).toBe(DEFAULT_MODE);
    expect(DEFAULT_MODE).toBe("addressed");
  });

  it("is case-insensitive", () => {
    const cfg = { ...defaultConfig(), modes: { "#chan": "silent" as const } };
    expect(modeFor(cfg, "#CHAN")).toBe("silent");
  });
});

describe("tierFor — the security-critical defaults", () => {
  const cfg = {
    ...defaultConfig(),
    ownerDid: "did:plc:owner",
    trust: { "did:plc:mate": "request" as const },
  };

  it("floors unknown DIDs at observe", () => {
    expect(tierFor(cfg, "did:plc:stranger")).toBe("observe");
  });

  it("floors guests (null/undefined DID) at observe", () => {
    // M0 finding: resolveSenderDid returns null for guests.
    expect(tierFor(cfg, null)).toBe("observe");
    expect(tierFor(cfg, undefined)).toBe("observe");
    expect(tierFor(cfg, "")).toBe("observe");
  });

  it("pins the owner to control even if the trust map says otherwise", () => {
    const tampered = { ...cfg, trust: { ...cfg.trust, "did:plc:owner": "observe" as const } };
    expect(tierFor(tampered, "did:plc:owner")).toBe("control");
  });

  it("honours explicit grants", () => {
    expect(tierFor(cfg, "did:plc:mate")).toBe("request");
  });

  it("orders tiers correctly", () => {
    expect(tierAtLeast("request", "message")).toBe(true);
    expect(tierAtLeast("observe", "message")).toBe(false);
    expect(tierAtLeast("control", "handoff")).toBe(true);
  });
});

describe("mute", () => {
  it("forces silent everywhere, overriding per-channel modes", () => {
    const cfg = {
      ...defaultConfig(),
      muted: true,
      modes: { "#a": "participant" as const, "#b": "addressed" as const },
    };
    expect(modeFor(cfg, "#a")).toBe("silent");
    expect(modeFor(cfg, "#b")).toBe("silent");
    expect(modeFor(cfg, "#unconfigured")).toBe("silent");
  });

  it("restores configured modes when unmuted", () => {
    const cfg = { ...defaultConfig(), muted: false, modes: { "#a": "participant" as const } };
    expect(modeFor(cfg, "#a")).toBe("participant");
    expect(modeFor(cfg, "#b")).toBe(DEFAULT_MODE);
  });

  it("round-trips through config normalization", () => {
    expect(normalizeConfig({ muted: true }).muted).toBe(true);
    expect(normalizeConfig({ muted: "yes" }).muted).toBe(false); // junk ignored
    expect(defaultConfig().muted).toBe(false);
  });

  it("is not settable from project config", () => {
    expect(projectOverrides({ muted: true })).not.toHaveProperty("muted");
  });
});
