import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { baseConfig, startChannel } from "./helpers.js";

beforeEach(() => {
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = String(input);
    if (url.endsWith("/api/v1/health")) return new Response(JSON.stringify({ server_name: "test" }), { status: 200 });
    if (url.includes("/api/v1/actions")) return new Response(JSON.stringify({ tasks: [] }), { status: 200 });
    return new Response(null, { status: 404 });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The doctor's lines for this channel: everything after the kit's own. */
function ccLines(text: string): string[] {
  return text
    .split("\n")
    .filter((l) => /^\s+[✓⚠✗] (channel|hooks|permission relay):/.test(l))
    .map((l) => l.trim());
}

describe("/freeq:doctor", () => {
  it("reports the hooks seen so far and relay on, and no channel line (Claude Code does not tell the server)", async () => {
    const h = await startChannel({ config: baseConfig() });
    const text = await h.command("/freeq:doctor");
    expect(text).toContain("freeq doctor");
    expect(ccLines(text)).toEqual([
      "✓ hooks: from the plugin; this session so far: UserPromptSubmit; not yet: PreToolUse, Stop",
      "✓ permission relay: on — tool approvals go to did:plc:owner by DM",
    ]);
    await h.close();
  });

  it("says all three once each has called", async () => {
    const h = await startChannel({ config: baseConfig({ ownerDid: undefined }), experimental: {} });
    await h.hook({ hook_event_name: "PreToolUse", tool_name: "Bash", command: "ls" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "" });
    const text = await h.command("/freeq:doctor");
    expect(ccLines(text)).toEqual([
      "✓ hooks: UserPromptSubmit, PreToolUse, Stop call freeq_hook",
      "⚠ permission relay: off — no owner configured (/freeq:login <did>)",
    ]);
    await h.close();
  });

  it("warns when no hook has called", async () => {
    const h = await startChannel({ config: baseConfig() });
    const lines = await h.channel.runtime.doctor();
    expect(lines.find((l) => l.name === "hooks")).toEqual({
      name: "hooks",
      status: "warn",
      detail: "no hook has called freeq_hook this session — start Claude Code with --plugin-dir <freeq-cc> (freeq-cc README)",
    });
    await h.close();
  });
});
