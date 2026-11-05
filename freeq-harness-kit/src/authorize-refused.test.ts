import { describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// HOME decides where the runtime looks for ~/.freeq, read when the runtime
// module is imported, so it points at a scratch directory first.
const home = await vi.hoisted(async () => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "harness-kit-authorize-refused-"));
  process.env.HOME = dir;
  return dir;
});

import { loadOrCreateIdentity } from "@freeq/bot-kit";
import { AgentRuntime } from "./runtime.js";
import type { BotLike } from "./connection.js";
import type { Harness, NoticeLevel } from "./harness.js";

/** A bot whose server refuses it at SASL, as an allowlisted server does
 *  before the owner has added the agent. */
class RefusedBot implements BotLike {
  identity = { did: "did:key:zRefused" };
  delegation = { signature: null as string | null };
  stateDir = join(home, ".freeq", "bots", "pi-test1234-proj");
  provenance = null;
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
    throw new Error("SASL auth failed: the agent records of did:plc:owner do not admit this agent");
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

describe("/freeq authorize before the server admits the agent", () => {
  it("shows the DID from the key file so the owner can add it", async () => {
    const root = mkdtempSync(join(tmpdir(), "harness-kit-authorize-refused-h-"));
    const agentDir = join(root, "agent");
    const cwd = join(root, "proj");
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(cwd, { recursive: true });
    writeFileSync(
      join(agentDir, "freeq.json"),
      JSON.stringify({
        ownerDid: "did:plc:owner",
        server: "ws://test.invalid/irc",
        install: "test1234",
        channels: ["#work"],
        projects: { proj: { channels: ["#work"] } },
      }),
    );
    const stateDir = join(home, ".freeq", "bots", "pi-test1234-proj");
    mkdirSync(stateDir, { recursive: true });
    const minted = await loadOrCreateIdentity({ seedPath: join(stateDir, "agent.key") });

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
    vi.stubGlobal("fetch", async () => new Response(null, { status: 404 }));
    const rt = new AgentRuntime(harness, { botFactory: async () => new RefusedBot() });
    await rt.start();
    notices.length = 0;

    await rt.runCommand("authorize");
    const shown = notices.find((n) => n.level === "info")?.text ?? "";
    expect(shown).toContain(minted.did);
    expect(notices.some((n) => /no DID to show/.test(n.text))).toBe(false);
    await rt.stop();
    vi.unstubAllGlobals();
  });

  it("says why on authorize verify, without waiting for a notice that never comes", async () => {
    const root = mkdtempSync(join(tmpdir(), "harness-kit-authorize-verify-h-"));
    const agentDir = join(root, "agent");
    const cwd = join(root, "proj");
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(cwd, { recursive: true });
    writeFileSync(
      join(agentDir, "freeq.json"),
      JSON.stringify({
        ownerDid: "did:plc:owner",
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
    vi.stubGlobal("fetch", async () => new Response(null, { status: 404 }));
    const rt = new AgentRuntime(harness, { botFactory: async () => new RefusedBot() });
    await rt.start();
    notices.length = 0;

    await rt.runCommand("authorize verify");
    expect(notices.at(-1)?.text).toContain("do not admit this agent");
    await rt.stop();
    vi.unstubAllGlobals();
  });
});
