import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadOrCreateIdentity } from "@freeq/bot-kit";
import { AgentRuntime } from "./runtime.js";
import { TEST_HOME } from "./test-setup.js";
import { deriveInstallSlug } from "./identity.js";
import type { BotLike } from "./connection.js";
import type { Harness, NoticeLevel } from "./harness.js";

const OWNER = "did:plc:owner";

class FakeBot implements BotLike {
  handlers = new Map<string, Array<(...a: never[]) => void>>();
  nickValue: string | null = "pi-test1234-proj";
  provenance = null;
  identity = { did: "did:key:zSelf" };
  client = ((self: FakeBot) => ({
    get nick() {
      return self.nickValue;
    },
    join: () => {},
    raw: () => {},
    sendMessage: () => {},
    sendTagmsg: () => {},
    sendAct: async () => "01JTASK0000000000000000000",
    signing: { getPublicKey: () => "pk" },
  }))(this);
  on(event: string, handler: (...a: never[]) => void): unknown {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
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
  emit(event: string, ...args: unknown[]): void {
    for (const h of this.handlers.get(event) ?? []) (h as (...a: unknown[]) => void)(...args);
  }
}

/** The server's HTTP API: health, and the actor record with its provenance. */
let api: (url: string) => { status: number; body?: unknown } | Error;
const fetched: string[] = [];

beforeEach(() => {
  fetched.length = 0;
  api = (url) => {
    if (url.endsWith("/api/v1/health")) return { status: 200, body: { server_name: "cc.local", version: "0.9.0" } };
    if (url.includes("/api/v1/actors/")) {
      return { status: 200, body: { online: true, provenance: { _verified: true } } };
    }
    return { status: 404 };
  };
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = String(input);
    fetched.push(url);
    const r = api(url);
    if (r instanceof Error) throw r;
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function fakeHarness(over: Partial<Harness> = {}, project = "proj") {
  const root = mkdtempSync(join(tmpdir(), "harness-kit-doctor-"));
  const agentDir = join(root, "agent");
  const cwd = join(root, project);
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(cwd, { recursive: true });
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
    ...over,
  };
  return { harness, agentDir, notices, root };
}

function writeConfig(agentDir: string, over: Record<string, unknown> = {}): void {
  writeFileSync(
    join(agentDir, "freeq.json"),
    JSON.stringify({
      ownerDid: OWNER,
      server: "ws://cc.local:9/irc",
      install: "test1234",
      channels: ["#work"],
      projects: { proj: { channels: ["#work"] } },
      ...over,
    }),
  );
}

/** The identity bot-kit would have made for project `proj`, on disk. */
async function mintIdentity(): Promise<string> {
  const dir = join(TEST_HOME, ".freeq", "bots", "pi-test1234-proj");
  mkdirSync(dir, { recursive: true });
  const id = await loadOrCreateIdentity({ seedPath: join(dir, "agent.key") });
  return id.did;
}

const norm = (text: string, ...pairs: Array<[string, string]>) =>
  pairs.reduce((t, [from, to]) => t.split(from).join(to), text);

describe("/freeq doctor", () => {
  it("runs the common checks on a connected session and appends the harness's own lines", async () => {
    const did = await mintIdentity();
    const h = fakeHarness({
      doctorLines: async () => [{ name: "harness", status: "ok", detail: "loaded" }],
    });
    writeConfig(h.agentDir);
    const bot = new FakeBot();
    bot.identity = { did };
    const rt = new AgentRuntime(h.harness, { botFactory: async () => bot });
    await rt.start();
    // The server confirms the join.
    bot.emit("channelJoined", "#work");
    h.notices.length = 0;

    await rt.runCommand("doctor");

    expect(h.notices).toHaveLength(1);
    expect(h.notices[0]!.level).toBe("warning");
    expect(norm(h.notices[0]!.text, [h.root, "<root>"], [TEST_HOME, "<home>"], [did, "<did>"])).toMatchInlineSnapshot(`
      "freeq doctor
        ✓ identity: <did> (pi-test1234-proj)
        ⚠ delegation: none at <home>/.freeq/bots/pi-test1234-proj/delegation.json — made on the next connect
        ✓ ownership: verified by the server
        ✓ owner: did:plc:owner
        ✓ config: <root>/agent/freeq.json
        ✓ server: ws://cc.local:9/irc (cc.local 0.9.0)
        ✓ connection: online: pi-test1234-proj (<did>) · proj · test-model
        ✓ channels: joined #work
        ✓ harness: loaded

      No problems, 1 warning."
    `);
    expect(fetched).toContain("http://cc.local:9/api/v1/health");
    await rt.stop();
  });

  it("reports a config it cannot parse, and does not throw", async () => {
    const h = fakeHarness();
    writeFileSync(join(h.agentDir, "freeq.json"), "{ not json");
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });

    await rt.runCommand("doctor");

    expect(h.notices).toHaveLength(1);
    expect(h.notices[0]!.level).toBe("error");
    expect(norm(h.notices[0]!.text, [h.root, "<root>"], [TEST_HOME, "<home>"], [deriveInstallSlug(), "<slug>"])).toMatchInlineSnapshot(`
      "freeq doctor
        ⚠ identity: none yet at <home>/.freeq/bots/pi-<slug>-proj/agent.key — made on the first connect in this project
        ⚠ ownership: no identity to ask the server about
        ✗ owner: not logged in — /freeq login <your did>
        ✗ config: <root>/agent/freeq.json is not valid JSON: Expected property name or '}' in JSON at position 2 (line 1 column 3)
        ⚠ server: not checked: the config could not be read
        ✗ connection: not connected
        ✓ channels: none configured

      3 problems, 3 warnings."
    `);
  });

  it("does not wake a dormant project: a check must not mint an identity", async () => {
    // A project the installation has never used (no projects entry, no
    // identity on disk, no repo).
    const h = fakeHarness({}, "scratch");
    writeConfig(h.agentDir, { projects: {} });
    let built = 0;
    const rt = new AgentRuntime(h.harness, {
      botFactory: async () => {
        built++;
        return new FakeBot();
      },
    });
    await rt.start();
    expect(rt.dormant).toBe(true);

    await rt.runCommand("doctor");

    expect(built).toBe(0);
    expect(rt.dormant).toBe(true);
    expect(h.notices.at(-1)!.text).toContain("connection: not connected — this project has no freeq identity yet");
  });

  it("is in the help", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.runCommand("help");
    expect(h.notices.at(-1)!.text).toContain("doctor");
  });
});
