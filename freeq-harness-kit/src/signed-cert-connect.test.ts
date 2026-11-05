import { describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AgentRuntime } from "./runtime.js";
import { TEST_HOME } from "./test-setup.js";
import type { BotLike } from "./connection.js";
import type { Harness, NoticeLevel } from "./harness.js";

const OWNER = "did:plc:owner";

/** A bot-kit bot whose certificate is signed and already verified. */
class FakeBot implements BotLike {
  identity = { did: "did:key:zSelf" };
  delegation = { signature: "c2lnbmVk" };
  stateDir = join(TEST_HOME, ".freeq", "bots", "pi-test1234-proj");
  provenance = { verified: true, reason: "signature", text: "Provenance verified: Verified against creator key" };
  client = {
    nick: "pi-test1234-proj",
    join: () => {},
    raw: () => {},
    sendMessage: () => {},
    sendTagmsg: () => {},
    sendAct: async () => "01JTASK0000000000000000000",
    signing: { getPublicKey: () => "pk" },
  };
  on(): unknown {
    return this;
  }
  async start(): Promise<unknown> {
    return this;
  }
  async stop(): Promise<unknown> {
    return this;
  }
  setState(): void {}
  checkMention(): { kind: string } {
    return { kind: "ignore" };
  }
  async resolveSenderDid(): Promise<string | null> {
    return null;
  }
}

// First in the file on purpose: the warning is said once per process.
describe("a signed certificate at connect", () => {
  it("is reported once, and not again when authorize verify reconnects", async () => {
    const root = mkdtempSync(join(tmpdir(), "harness-kit-signed-connect-h-"));
    const agentDir = join(root, "agent");
    const cwd = join(root, "proj");
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(cwd, { recursive: true });
    writeFileSync(
      join(agentDir, "freeq.json"),
      JSON.stringify({
        ownerDid: OWNER,
        server: "ws://test.invalid/irc",
        install: "test1234",
        channels: ["#work"],
        projects: { proj: { channels: ["#work"] } },
      }),
    );
    const notices: Array<{ text: string; level: NoticeLevel }> = [];
    const harness: Harness = {
      agentDir,
      configDirName: ".pi",
      projectTrusted: () => false,
      cwd: () => cwd,
      modelId: () => "test-model",
      deliver: () => {},
      notify: (text, level) => void notices.push({ text, level }),
      confirm: async () => false,
      isIdle: () => true,
      journal: { append: () => {}, read: () => [] },
    };
    // The runtime asks the server what is assigned to it; no network here.
    vi.stubGlobal("fetch", async () => new Response(null, { status: 404 }));
    const bot = new FakeBot();
    const rt = new AgentRuntime(harness, { botFactory: async () => bot });
    await rt.start();

    const line =
      "This bot's certificate is signed with a creator key. Signed certificates will stop counting in a later release; " +
      "every server now reads agent records instead. Add this agent under Settings → Agents in the freeq web app, " +
      "or with `freeq-bot-id register --owner <handle> did:key:zSelf`, then delete the certificate at " +
      `${join(bot.stateDir, "delegation.json")}, so an unsigned certificate is made at the next start.`;
    expect(notices.filter((n) => n.text.includes("signed with a creator key"))).toEqual([
      { text: line, level: "warning" },
    ]);

    notices.length = 0;
    await rt.runCommand("authorize verify");
    expect(notices.filter((n) => n.text.includes("signed with a creator key"))).toEqual([]);
    expect(notices.at(-1)).toEqual({
      text: "freeq: Delegation verified — this installation provably acts for you.",
      level: "info",
    });
    await rt.stop();
    vi.unstubAllGlobals();
  });
});
