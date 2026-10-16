import { describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// HOME decides where the runtime looks for ~/.freeq, read when the runtime
// module is imported, so it points at a scratch directory first.
const home = await vi.hoisted(async () => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "harness-kit-sign-cert-"));
  process.env.HOME = dir;
  return dir;
});

import { AgentRuntime } from "./runtime.js";
import type { BotLike } from "./connection.js";
import type { Harness, NoticeLevel } from "./harness.js";

const OWNER = "did:plc:owner";

/** A bot-kit bot whose certificate starts unsigned; the test signs it. */
class FakeBot implements BotLike {
  identity = { did: "did:key:zSelf" };
  delegation = { signature: null as string | null };
  stateDir = join(home, ".freeq", "bots", "pi-test1234-proj");
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
describe("/freeq authorize --sign-cert", () => {
  it("warns first, then prints the steps, and authorize verify does not warn again", async () => {
    const root = mkdtempSync(join(tmpdir(), "harness-kit-sign-cert-h-"));
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
    expect(notices.filter((n) => n.level === "warning")).toEqual([]);
    notices.length = 0;

    await rt.runCommand("authorize --sign-cert");
    expect(notices.map((n) => n.level)).toEqual(["warning", "info"]);
    expect(notices[0]!.text).toBe(
      "Signing certificates with a creator key is deprecated: signed certificates will stop counting in a later release, " +
        "and every server now reads agent records instead. Prefer `/freeq authorize` and add this agent under Settings → Agents.",
    );
    expect(notices[1]!.text).toMatch(/^freeq authorize --sign-cert — sign this installation's delegation\n/);
    expect(existsSync(join(home, ".freeq", "owner", "did_plc_owner", "creator.key"))).toBe(true);

    // The next connect presents the certificate signed.
    bot.delegation = { signature: "c2lnbmVk" };
    notices.length = 0;
    await rt.runCommand("authorize verify");
    expect(notices.filter((n) => /signed with a creator key|deprecated/.test(n.text))).toEqual([]);
    expect(notices.at(-1)).toEqual({
      text: "freeq: Delegation verified — this installation provably acts for you.",
      level: "info",
    });
    await rt.stop();
    vi.unstubAllGlobals();
  });
});
