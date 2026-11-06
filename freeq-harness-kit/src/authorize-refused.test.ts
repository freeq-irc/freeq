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

import { loadOrCreateIdentity, SignInRefusedError } from "@freeq/bot-kit";
import { AgentRuntime } from "./runtime.js";
import type { BotLike } from "./connection.js";
import type { Harness, NoticeLevel } from "./harness.js";

/** A bot whose start() fails as `error` says, reporting `did`: a
 *  SignInRefusedError is the server refusing it (as an allowlisted server
 *  does before the owner has added the agent); a plain Error is anything
 *  else, an unreachable server say. */
class RefusedBot implements BotLike {
  identity: { did: string };
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
  constructor(
    readonly error: Error,
    did = "did:key:zRefused",
  ) {
    this.identity = { did };
  }
  on(): unknown {
    return this;
  }
  async start(): Promise<unknown> {
    throw this.error;
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

const REFUSAL = "the agent records of did:plc:owner do not admit this agent";

/** A project with an owner set, whose bots come from `makeBot`; the runtime
 *  started, and its notices so far cleared. */
async function started(makeBot: () => RefusedBot) {
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
  let created = 0;
  const rt = new AgentRuntime(harness, {
    botFactory: async () => {
      created++;
      return makeBot();
    },
  });
  await rt.start();
  notices.length = 0;
  return { rt, notices, created: () => created };
}

async function mintedIdentity() {
  const stateDir = join(home, ".freeq", "bots", "pi-test1234-proj");
  mkdirSync(stateDir, { recursive: true });
  return await loadOrCreateIdentity({ seedPath: join(stateDir, "agent.key") });
}

describe("/freeq authorize before the server admits the agent", () => {
  it("shows the DID from the key file when the server could not be reached", async () => {
    // Not a refusal: the bot is discarded, so the DID comes from the key file.
    const minted = await mintedIdentity();
    const s = await started(() => new RefusedBot(new Error(`SASL auth failed: ${REFUSAL}`)));
    await s.rt.runCommand("authorize");
    const shown = s.notices.find((n) => n.level === "info")?.text ?? "";
    expect(shown).toContain(minted.did);
    expect(s.notices.some((n) => /no DID to show/.test(n.text))).toBe(false);
    // The held connection is still trying; showing its DID connects nothing.
    expect(s.created()).toBe(1);
    await s.rt.stop();
    vi.unstubAllGlobals();
  });

  it("shows the refused bot's DID without connecting again", async () => {
    const minted = await mintedIdentity();
    const s = await started(() => new RefusedBot(new SignInRefusedError(REFUSAL), minted.did));
    expect(s.rt.conn?.state).toBe("error");
    await s.rt.runCommand("authorize");
    const shown = s.notices.find((n) => n.level === "info")?.text ?? "";
    expect(shown).toContain(minted.did);
    expect(s.notices.some((n) => /no DID to show/.test(n.text))).toBe(false);
    expect(s.created()).toBe(1);
    await s.rt.stop();
    vi.unstubAllGlobals();
  });

  it("says why on authorize verify, once, without waiting for a notice that never comes", async () => {
    const s = await started(() => new RefusedBot(new SignInRefusedError(REFUSAL)));
    await s.rt.runCommand("authorize verify");
    expect(s.notices.at(-1)?.text).toContain("do not admit this agent");
    expect(s.notices.filter((n) => n.text.includes("do not admit this agent"))).toHaveLength(1);
    await s.rt.stop();
    vi.unstubAllGlobals();
  });

  it("never says refused on authorize verify when the server could not be reached", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      const s = await started(() => new RefusedBot(new Error("connect ECONNREFUSED")));
      let done = false;
      const verifying = s.rt.runCommand("authorize verify").finally(() => (done = true));
      // Real file I/O runs between the steps (setImmediate is not faked);
      // fake time (timers and Date) carries the 20 s wait for an answer.
      for (let i = 0; i < 400 && !done; i++) {
        await vi.advanceTimersByTimeAsync(250);
        await new Promise((r) => setImmediate(r));
      }
      await verifying;
      expect(s.notices.filter((n) => /refused/.test(n.text))).toEqual([]);
      expect(s.notices.at(-1)?.text).toBe(
        "freeq: No provenance reply seen yet. Reconnect and try again; if it persists, the cert may not have been re-sent.",
      );
      await s.rt.stop();
    } finally {
      vi.useRealTimers();
      vi.unstubAllGlobals();
    }
  }, 20_000); // the real-time limit for a test that walks 20 s of fake time; well clear of the 5s default
});
