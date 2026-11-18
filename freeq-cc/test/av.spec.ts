import { describe, expect, it } from "vitest";

import { avCandidates, SETUP_TEXT } from "../src/av.js";

describe("freeq-cc: the voice bridge launcher", () => {
  it("looks for the bridge where the install script and a clone put it, FREEQ_AV_BIN first", () => {
    const c = avCandidates({ FREEQ_AV_BIN: "/opt/av", CLAUDE_PLUGIN_DATA: "/data" });
    expect(c[0]).toBe("/opt/av");
    expect(c[1]).toBe("/data/bin/freeq-claude-mcp");
    expect(c.some((p) => p.endsWith("/.freeq/cc/bin/freeq-claude-mcp"))).toBe(true);
    expect(c.at(-1)).toMatch(/target\/release\/freeq-claude-mcp$/);
  });

  it("says how to build it when it is missing", () => {
    expect(SETUP_TEXT).toContain("freeq-cc/scripts/install-av.sh");
    expect(SETUP_TEXT).toContain("GROQ_API_KEY");
  });
});

describe("freeq-cc: plugin settings from the env", () => {
  it("reads userConfig values and treats unsubstituted ones as unset", async () => {
    const { readSettings } = await import("../src/channel.js");
    expect(
      readSettings({
        FREEQ_CC_OWNER_DID: "${user_config.owner_did}",
        FREEQ_CC_SERVER: "",
        FREEQ_CC_APPROVAL_SIGNATURE: "any",
        FREEQ_CC_RELAY_QUESTIONS: "off",
        FREEQ_CC_TEAM_CHANNEL: "team",
        FREEQ_CC_PROVENANCE: "false",
      }),
    ).toEqual({
      ownerDid: undefined,
      server: undefined,
      approvalSignature: "any",
      relayQuestions: "off",
      teamChannel: "#team",
      provenance: false,
    });
    expect(readSettings({})).toMatchObject({ approvalSignature: "device", relayQuestions: "freeq-turns", provenance: true });
  });

  it("fills in the owner from the plugin settings when the config has none", async () => {
    const { startChannel, baseConfig } = await import("./helpers.js");
    const h = await startChannel({ config: baseConfig({ ownerDid: undefined }), settings: { ownerDid: "did:plc:fromsettings" } });
    expect(h.channel.runtime.config?.ownerDid).toBe("did:plc:fromsettings");
    expect(h.client.getServerCapabilities()?.experimental?.["claude/channel/permission"]).toEqual({});
    await h.close();
  });
});
