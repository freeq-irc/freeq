import { describe, expect, it } from "vitest";

import { OWNER, PEER, baseConfig, startChannel } from "./helpers.js";

const REQUEST = {
  request_id: "abcde",
  tool_name: "Bash",
  description: "Run the test suite",
  input_preview: '{"command":"npm test"}',
};

async function permissionRequest(h: Awaited<ReturnType<typeof startChannel>>, params = REQUEST): Promise<void> {
  await h.client.notification({ method: "notifications/claude/channel/permission_request", params });
  await new Promise((r) => setTimeout(r, 20));
}

describe("freeq-cc: permission relay", () => {
  it("declares the permission capability only when an owner is configured", async () => {
    const withOwner = await startChannel({ config: baseConfig() });
    expect(withOwner.client.getServerCapabilities()?.experimental?.["claude/channel/permission"]).toEqual({});
    await withOwner.close();

    const noOwner = await startChannel({ config: baseConfig({ ownerDid: undefined }) });
    expect(noOwner.client.getServerCapabilities()?.experimental).toEqual({ "claude/channel": {} });
    await noOwner.close();
  });

  it("DMs a tool-approval prompt to the owner's DID", async () => {
    const h = await startChannel({ config: baseConfig() });
    await permissionRequest(h);
    expect(h.bot.messages()).toEqual([
      `${OWNER} Claude wants to use Bash: Run the test suite\n{"command":"npm test"}\nReply "yes abcde" or "no abcde"`,
    ]);
    await h.close();
  });

  it("turns the owner's 'yes <id>' DM into an allow, and delivers nothing", async () => {
    const h = await startChannel({ config: baseConfig() });
    await permissionRequest(h);
    await h.dm("nap", OWNER, "yes abcde");
    expect(h.verdicts).toEqual([{ request_id: "abcde", behavior: "allow" }]);
    expect(h.events).toEqual([]);
    // No reply is owed for a verdict.
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "ran the tests" });
    expect(h.bot.messages()).toHaveLength(1);
    await h.close();
  });

  it("turns 'N ABCDE' into a deny with the id lowercased", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.dm("nap", OWNER, "  N ABCDE ");
    expect(h.verdicts).toEqual([{ request_id: "abcde", behavior: "deny" }]);
    await h.close();
  });

  it("ignores a verdict from anyone but the owner, even a trusted peer", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "control" } }) });
    await h.dm("chad", PEER, "yes abcde");
    await h.dm("nap", null, "yes abcde");
    expect(h.verdicts).toEqual([]);
    // The trusted peer's text is ordinary chat.
    expect(h.events).toHaveLength(1);
    expect(h.events[0]!.content).toContain("yes abcde");
    await h.close();
  });

  it("ignores the owner's verdict in a channel", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.say("#work", "nap", OWNER, "yes abcde");
    expect(h.verdicts).toEqual([]);
    await h.close();
  });

  it("relays nothing when no owner is configured", async () => {
    const h = await startChannel({ config: baseConfig({ ownerDid: undefined }) });
    await permissionRequest(h);
    await h.dm("nap", OWNER, "yes abcde");
    expect(h.verdicts).toEqual([]);
    expect(h.bot.messages()).toEqual([]);
    await h.close();
  });
});
