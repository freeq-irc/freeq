import { afterEach, describe, it, expect, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentRuntime, httpOriginFor, type RuntimeOptions } from "./runtime.js";
import type { BotLike } from "./connection.js";
import type { Delivery, Harness, NoticeLevel } from "./harness.js";
import type { TaskNote } from "./journal.js";
import type { RoomLineInput } from "./ui.js";

const OWNER = "did:plc:owner";
const PEER = "did:plc:peer";

/** A bot-kit bot as far as the connection uses one; see connection.test.ts. */
class FakeBot implements BotLike {
  handlers = new Map<string, Array<(...a: never[]) => void>>();
  sent: Array<{ kind: string; target: string; payload: unknown }> = [];
  states: Array<{ state: string; status?: string; task?: string }> = [];
  nickValue: string | null = "pi-test1234-proj";
  provenance = null;
  identity = { did: "did:key:zSelf" };
  mention: ((text: string, nick: string) => string | null) | undefined;
  client = ((self: FakeBot) => ({
    get nick() {
      return self.nickValue;
    },
    join: (channel: string) => self.sent.push({ kind: "join", target: channel, payload: null }),
    raw: (line: string) => self.sent.push({ kind: "raw", target: "", payload: line }),
    sendMessage: (target: string, text: string) => self.sent.push({ kind: "message", target, payload: text }),
    sendTagmsg: (target: string, tags: Record<string, string>) => self.sent.push({ kind: "tagmsg", target, payload: tags }),
    sendAct: async (target: string, tags: Record<string, string>) => {
      self.sent.push({ kind: "act", target, payload: tags });
      return "01JTASK0000000000000000000";
    },
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
  setState(state: string, status?: string, task?: string): void {
    this.states.push({ state, status, task });
  }
  checkMention(_channel: string, text: string): { kind: string; stripped?: string } {
    const s = this.mention?.(text, this.nickValue ?? "") ?? null;
    return s === null ? { kind: "ignore" } : { kind: "respond", stripped: s };
  }
  async resolveSenderDid(msg: { tags?: Record<string, string> }): Promise<string | null> {
    return msg.tags?.account ?? null;
  }
  emit(event: string, ...args: unknown[]): void {
    for (const h of this.handlers.get(event) ?? []) (h as (...a: unknown[]) => void)(...args);
  }
  messages(): string[] {
    return this.sent.filter((s) => s.kind === "message").map((s) => `${s.target} ${String(s.payload)}`);
  }
}

/** A harness that records everything the runtime asks of it. */
function fakeHarness(over: Partial<Harness> = {}) {
  const root = mkdtempSync(join(tmpdir(), "harness-kit-rt-"));
  const agentDir = join(root, "agent");
  const cwd = join(root, "proj");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  const delivered: Delivery[] = [];
  const notices: Array<{ text: string; level: NoticeLevel }> = [];
  const lines: RoomLineInput[] = [];
  const notes: TaskNote[] = [];
  let idle = true;
  const harness: Harness = {
    agentDir,
    configDirName: ".pi",
    projectTrusted: () => false,
    cwd: () => cwd,
    modelId: () => "test-model",
    deliver: (m) => void delivered.push(m),
    notify: (text, level) => void notices.push({ text, level }),
    confirm: async () => false,
    isIdle: () => idle,
    journal: {
      append: (n) => void notes.push(n),
      read: (id) => notes.filter((n) => n.taskId === id),
    },
    roomLine: (l) => void lines.push(l),
    ...over,
  };
  return { harness, agentDir, delivered, notices, lines, notes, setIdle: (v: boolean) => (idle = v) };
}

function writeConfig(agentDir: string, over: Record<string, unknown> = {}): void {
  writeFileSync(
    join(agentDir, "freeq.json"),
    JSON.stringify({
      ownerDid: OWNER,
      server: "ws://test.invalid/irc",
      install: "test1234",
      channels: ["#work"],
      projects: { proj: { channels: ["#work"] } },
      ...over,
    }),
  );
}

async function started(configOver: Record<string, unknown> = {}, options: RuntimeOptions = {}) {
  const h = fakeHarness();
  writeConfig(h.agentDir, configOver);
  const bot = new FakeBot();
  const rt = new AgentRuntime(h.harness, {
    botFactory: async (o) => {
      bot.mention = o.mention.matcher;
      return bot;
    },
    ...options,
  });
  await rt.start();
  return { ...h, rt, bot };
}

const tick = () => new Promise((r) => setTimeout(r, 10));

describe("AgentRuntime: start", () => {
  it("stays silent and offline when not set up", async () => {
    const h = fakeHarness();
    const rt = new AgentRuntime(h.harness);
    await rt.start();
    expect(rt.conn).toBeUndefined();
    expect(h.notices).toEqual([]);
  });

  it("connects in a known project", async () => {
    const { rt } = await started();
    expect(rt.conn?.state).toBe("online");
    expect(rt.currentProject).toBe("proj");
    await rt.stop();
    expect(rt.conn).toBeUndefined();
  });
});

describe("AgentRuntime: delivery", () => {
  it("delivers the owner's DM, framed, as an interrupt owing a reply", async () => {
    const { bot, delivered } = await started();
    bot.emit("message", "nap", { from: "nap", text: "hello", isSelf: false, tags: { account: OWNER } });
    await tick();
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.interrupt).toBe(true);
    expect(delivered[0]!.card).toMatchObject({ kind: "chat", from: "nap", tier: "control", expectsReply: true });
    expect(delivered[0]!.content).toContain("message from your operator nap (did:plc:owner) in a direct message");
  });

  it("withholds a stranger's message, shows a room line and tells the person", async () => {
    const { bot, delivered, notices, lines, rt } = await started();
    bot.emit("message", "eve", { from: "eve", text: "hi", isSelf: false, tags: { account: "did:plc:eve" } });
    await tick();
    expect(delivered).toEqual([]);
    expect(rt.withheld.size).toBe(1);
    expect(lines[0]).toMatchObject({ direction: "in", from: "eve", note: "withheld · tier observe" });
    expect(notices[0]!.level).toBe("warning");
    expect(notices[0]!.text).toContain("/freeq trust did:plc:eve message");
  });

  it("delivers message-tier chat without interrupting", async () => {
    const { bot, delivered } = await started({ trust: { [PEER]: "message" } });
    bot.emit("message", "#work", { from: "peer", text: "pi-test1234-proj: look?", isSelf: false, tags: { account: PEER } });
    await tick();
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.interrupt).toBe(false);
  });

  it("answers an ask it cannot deliver", async () => {
    const h = fakeHarness({
      deliver: () => {
        throw new Error("busy");
      },
    });
    writeConfig(h.agentDir, { trust: { [PEER]: "request" } });
    const bot = new FakeBot();
    const rt = new AgentRuntime(h.harness, { botFactory: async () => bot });
    await rt.start();
    bot.emit("coordinationEvent", { eventType: "pi_ask", from: "peer", did: PEER, channel: "peer", payload: { req: "r1", q: "?" }, tags: {} });
    await tick();
    const reply = bot.sent.find((s) => s.kind === "tagmsg" && (s.payload as Record<string, string>)["+freeq.at/event"] === "pi_ask_reply")!;
    expect(decodeURIComponent((reply.payload as Record<string, string>)["+freeq.at/payload"]!)).toContain("local delivery failed");
    expect(h.notices.at(-1)).toEqual({ text: "freeq: could not deliver message: busy", level: "error" });
  });
});

describe("AgentRuntime: replies", () => {
  it("answers with the first text-only turn after the message, as a receipt too", async () => {
    const { bot, rt, lines } = await started();
    bot.emit("message", "nap", { from: "nap", text: "q", isSelf: false, tags: { account: OWNER } });
    await tick();
    rt.onTurnStart();
    rt.onTurnEnd("working on it", true);
    expect(bot.messages()).toEqual([]);
    rt.onTurnStart();
    rt.onTurnEnd("the answer", false);
    expect(bot.messages()).toEqual(["nap the answer"]);
    expect(lines.at(-1)).toMatchObject({ direction: "out", channel: "nap", text: "the answer" });
  });

  it("sweeps what is left when the run settles, and reports a missing answer", async () => {
    const { bot, rt, notices } = await started({ trust: { [PEER]: "request" } });
    bot.emit("coordinationEvent", { eventType: "pi_ask", from: "peer", did: PEER, channel: "peer", payload: { req: "r2", q: "?" }, tags: {} });
    await tick();
    rt.onTurnStart();
    await rt.onSettled();
    expect(notices.at(-1)).toEqual({ text: "freeq: no answer produced for peer", level: "warning" });
  });
});

describe("AgentRuntime: presence", () => {
  it("names the step from a typed prompt and clears it when settled", async () => {
    const { rt, bot } = await started();
    rt.onUserPrompt("look at the reconnect bug");
    expect(rt.step?.phrase).toBe("look at the reconnect bug");
    rt.onUserPrompt("[freeq — message from x] ignored");
    expect(rt.step?.phrase).toBe("look at the reconnect bug");
    await rt.onSettled();
    expect(rt.step).toBeUndefined();
    expect(bot.states.at(-1)?.state).toBe("active");
  });

  it("tells the harness when a step begins", async () => {
    const phrases: string[] = [];
    const h = fakeHarness({ stepBegan: (p) => void phrases.push(p) });
    writeConfig(h.agentDir);
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    rt.beginStep("reviewing");
    expect(phrases).toEqual(["reviewing"]);
  });
});

/** An act event as the SDK delivers it. */
function act(verb: string, taskId: string, over: Record<string, unknown> = {}, fields: Record<string, string> = {}) {
  return {
    channel: "#work",
    from: "boss",
    did: "did:plc:boss",
    kind: "handoff",
    verb,
    eventId: verb === "offer" ? taskId : `${taskId}-${verb}`,
    taskId,
    fields: { ...(verb === "offer" ? {} : { "act-id": taskId }), ...fields },
    tags: {},
    replayed: false,
    ...over,
  };
}

describe("AgentRuntime: handoffs", () => {
  // Act events look their signer's key up over HTTP, and every connect asks
  // the server what is assigned: neither may reach a network.
  const fetched: string[] = [];
  let tasks: unknown[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    fetched.push(String(url));
    return String(url).includes("/api/v1/actions")
      ? new Response(JSON.stringify({ tasks }), { status: 200 })
      : new Response(null, { status: 404 });
  });
  afterEach(() => {
    fetched.length = 0;
    tasks = [];
  });

  it("ignores an offer from an untrusted DID, and says so", async () => {
    const { bot, delivered, notices } = await started();
    bot.emit("actEvent", act("offer", "01JA", {}, { "act-to": "did:key:zSelf", "act-title": "t" }));
    await tick();
    expect(delivered).toEqual([]);
    expect(notices.map((n) => n.text).join("\n")).toContain("ignoring handoff from did:plc:boss");
  });

  it("accepts a trusted offer when idle, delivers the brief, journals the start", async () => {
    const { bot, delivered, notes, rt } = await started({ trust: { "did:plc:boss": "handoff" } });
    bot.emit("actEvent", act("offer", "01JB", {}, { "act-to": "did:key:zSelf", "act-title": "port it" }));
    await tick();
    const accept = bot.sent.find((s) => s.kind === "act")!;
    expect((accept.payload as Record<string, string>)["+freeq.at/act-verb"]).toBe("accept");
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.content).toContain("You have taken on a task handed off over freeq.");
    expect(notes.map((n) => [n.kind, n.text])).toEqual([["start", "took on: port it"]]);
    expect(rt.workTask).toBe("01JB");
  });

  it("checks a ruling the SDK could not check itself, as before", async () => {
    const { bot } = await started({ trust: { "did:plc:boss": "handoff" } });
    bot.emit("actEvent", act("offer", "01JR", {}, { "act-to": "did:key:zSelf", "act-title": "t", "act-home": "did:web:irc.test" }));
    await tick();
    fetched.length = 0;
    // A failing one never reaches the kit: bot-kit drops it.
    bot.emit("actEvent", act("expire", "01JR", { did: "did:web:irc.test", from: "irc.test", eventId: "01JR-expire-2", ruling: "cannot-check" }));
    await tick();
    expect(fetched.some((u) => u.includes("/api/v1/signing-key"))).toBe(true);
  });

  it("does not apply a ruling it checks itself whose key stopped counting before it was signed", async () => {
    const { generateDidKey } = await import("@freeq/sdk");
    const { signActTags, deriveKid, publicKeyFromMultibase } = await import("@freeq/bot-kit");
    const SERVER = "did:web:irc.test";
    // An id minted at `ms`: its first ten characters are the time.
    const idAt = (ms: number, tail: string) => {
      const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
      let time = "";
      for (let i = 0, t = ms; i < 10; i++, t = Math.floor(t / 32)) time = crockford[t % 32] + time;
      return `${time}${tail.padStart(16, "0")}`;
    };
    const signedAt = 1_700_000_000_000;
    // Each key's removal date, by kid, in unix seconds.
    const removedAt = new Map<string, number>();
    const keys = new Map<string, Uint8Array>();
    const prior = globalThis.fetch;
    vi.stubGlobal("fetch", async (url: string) => {
      const u = new URL(String(url));
      if (u.pathname === "/api/v1/signing-key") return Response.json({ did: SERVER });
      const kid = decodeURIComponent(u.pathname.split("/").pop() ?? "");
      const key = keys.get(kid);
      if (!u.pathname.startsWith(`/api/v1/signing-keys/${encodeURIComponent(SERVER)}/`) || !key) {
        return new Response(null, { status: 404 });
      }
      return Response.json({
        algorithm: "ed25519",
        public_key: Buffer.from(key).toString("base64url"),
        removed_at: removedAt.get(kid) ?? null,
        expires_at: null,
      });
    });
    try {
      const { bot, rt } = await started({ trust: { "did:plc:boss": "handoff" } });
      const outcome = async (task: string, removed: number) => {
        bot.emit("actEvent", act("offer", task, {}, { "act-to": "did:plc:other", "act-title": "t", "act-home": SERVER }));
        await tick();
        const key = await generateDidKey();
        const raw = publicKeyFromMultibase(key.publicKeyMultibase);
        const kid = await deriveKid(raw);
        keys.set(kid, raw);
        removedAt.set(kid, removed);
        const eventId = idAt(signedAt, String(removed));
        const tags = {
          "+freeq.at/act": "handoff",
          "+freeq.at/act-verb": "expire",
          "+freeq.at/from": SERVER,
          "+freeq.at/act-id": task,
        };
        const sigTag = (await signActTags(tags, "#work", eventId, key))!;
        bot.emit(
          "actEvent",
          act("expire", task, { did: SERVER, from: "irc.test", eventId, tags, sigTag, ruling: "cannot-check" }),
        );
        for (let i = 0; i < 50 && rt.handoffs?.get(task)?.state !== "expired"; i++) await tick();
        return rt.handoffs?.get(task)?.state;
      };
      expect(await outcome("01JRBEFORE", signedAt / 1000 + 60), "removed after it was signed").toBe("expired");
      expect(await outcome("01JRAFTER", signedAt / 1000 - 60), "removed before it was signed").toBe("offered");
    } finally {
      vi.stubGlobal("fetch", prior);
    }
  });

  it("applies a ruling the SDK found counts from the task's referee on another server, with no check of its own", async () => {
    const { bot, rt } = await started({ trust: { "did:plc:boss": "handoff" } });
    bot.emit("actEvent", act("offer", "01JC", {}, { "act-to": "did:plc:other", "act-title": "t", "act-home": "did:web:referee.test" }));
    await tick();
    fetched.length = 0;
    bot.emit("actEvent", act("expire", "01JC", { did: "did:web:referee.test", from: "referee.test", eventId: "01JC-expire", ruling: "counts" }));
    for (let i = 0; i < 50 && rt.handoffs?.get("01JC")?.state !== "expired"; i++) await tick();
    expect(rt.handoffs?.get("01JC")?.state).toBe("expired");
    expect(fetched.filter((u) => u.includes("/api/v1/signing-keys/")), "no key fetched by the kit").toEqual([]);
  });

  it("queues a trusted offer while busy", async () => {
    const { bot, delivered, rt, setIdle } = await started({ trust: { "did:plc:boss": "handoff" } });
    setIdle(false);
    bot.emit("actEvent", act("offer", "01JC", {}, { "act-to": "did:key:zSelf", "act-title": "later" }));
    await tick();
    expect(delivered).toEqual([]);
    expect(rt.offers?.has("01JC")).toBe(true);
  });

  it("tells the model to stand down when held work is cancelled", async () => {
    const { bot, delivered } = await started({ trust: { "did:plc:boss": "handoff" } });
    bot.emit("actEvent", act("offer", "01JD", {}, { "act-to": "did:key:zSelf", "act-title": "held" }));
    await tick();
    bot.emit("actEvent", act("accept", "01JD", { did: "did:key:zSelf", from: "pi-test1234-proj" }));
    await tick();
    bot.emit("actEvent", act("cancel", "01JD"));
    await tick();
    expect(delivered).toHaveLength(2);
    expect(delivered[1]!.content).toContain("was cancelled by the agent that offered it");
  });

  it("names the poster in a resumed brief, not the last actor", async () => {
    tasks = [{ act_id: "01JF", kind: "handoff", stored_state: "assigned", venue: "#work", offerer: "did:plc:boss", assignee: "did:key:zSelf" }];
    const h = fakeHarness();
    writeConfig(h.agentDir, { trust: { "did:plc:boss": "handoff" } });
    writeFileSync(
      join(h.agentDir, "freeq-handoffs.json"),
      JSON.stringify([
        { id: "01JF", kind: "handoff", state: "assigned", offerer: "did:plc:boss", offererNick: "boss", offeree: "did:key:zSelf", assignee: "did:key:zSelf", lastActor: "pi-test1234-proj", title: "t", channel: "#work", fromReplay: false, signed: true, createdAt: 0, updatedAt: 0, log: [] },
      ]),
    );
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    await tick();
    expect(h.delivered).toHaveLength(1);
    expect(h.delivered[0]!.content).toContain("message from boss (did:plc:boss)");
  });

  it("resumes assigned work on connect, with the journal", async () => {
    tasks = [{ act_id: "01JE", kind: "handoff", stored_state: "assigned", venue: "#work", offerer: "did:plc:boss", assignee: "did:key:zSelf" }];
    const h = fakeHarness();
    writeConfig(h.agentDir, { trust: { "did:plc:boss": "handoff" } });
    h.harness.journal.append({ taskId: "01JE", at: Date.UTC(2026, 8, 29, 22, 40), kind: "turn", text: "parser half done" });
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    await tick();
    expect(fetched[0]).toBe("http://test.invalid/api/v1/actions?assignee=did%3Akey%3AzSelf&state=assigned");
    expect(h.delivered).toHaveLength(1);
    expect(h.delivered[0]!.content).toContain("- 22:40 parser half done");
    expect(await rt.resumeAssigned(rt.config!, "01JE")).toBe("freeq: 01JE is already in flight here");
  });
});

describe("AgentRuntime: the freeq tool", () => {
  it("says it cannot reach peers when offline", async () => {
    const rt = new AgentRuntime(fakeHarness().harness);
    expect(await rt.runTool({ action: "peers" })).toBe("freeq is not configured — cannot reach peers right now.");
  });

  it("sends, and refuses a handoff to a nick it cannot resolve", async () => {
    const { rt, bot } = await started();
    expect(await rt.runTool({ action: "send", to: "pi-chad", message: "hi" })).toBe("Sent to pi-chad.");
    expect(bot.messages()).toEqual(["pi-chad hi"]);
    expect(await rt.runTool({ action: "handoff", to: "pi-chad", title: "x" })).toContain("Cannot resolve 'pi-chad' to a DID.");
  });

  it("offers a handoff to a DID and records it", async () => {
    const { rt } = await started();
    const out = await rt.runTool({ action: "handoff", to: "did:plc:chad", title: "fix it", brief: "details" });
    expect(out.split("\n")[0]).toBe("Handoff offered: 01JTASK0000000000000000000");
    expect(rt.handoffs?.get("01JTASK0000000000000000000")).toMatchObject({ state: "offered", offeree: "did:plc:chad", note: "details" });
    expect(await rt.runTool({ action: "handoffs" })).toContain("You offered:");
  });
});

describe("AgentRuntime: /freeq commands", () => {
  it("status names the owner, server and state", async () => {
    const { rt, notices } = await started();
    await rt.runCommand("status");
    const text = notices.at(-1)!.text.split("\n");
    expect(text[0]).toBe("owner:    did:plc:owner");
    expect(text[1]).toBe("server:   ws://test.invalid/irc");
    expect(text[2]).toMatch(/^state:    online: pi-test1234-proj \(did:key:zSelf\)/);
  });

  it("trust asks first, and grants only on yes", async () => {
    const answers = [false, true];
    const h = fakeHarness({ confirm: async () => answers.shift() ?? false });
    writeConfig(h.agentDir);
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    await rt.runCommand("trust did:plc:eve message");
    expect(rt.config!.trust).toEqual({});
    await rt.runCommand("trust did:plc:eve message");
    expect(rt.config!.trust).toEqual({ "did:plc:eve": "message" });
    expect(h.notices.map((n) => n.text)).toEqual(["freeq: trust unchanged", "freeq: did:plc:eve → message"]);
  });

  it("login with a server saves both and connects there", async () => {
    const h = fakeHarness();
    const urls: string[] = [];
    const rt = new AgentRuntime(h.harness, {
      botFactory: async (o) => {
        urls.push(o.url);
        return new FakeBot();
      },
    });
    await rt.start();
    await rt.runCommand("login did:plc:owner wss://irc.example.test/irc");
    expect(rt.config).toMatchObject({ ownerDid: "did:plc:owner", server: "wss://irc.example.test/irc" });
    expect(urls).toEqual(["wss://irc.example.test/irc"]);
    expect(rt.conn?.state).toBe("online");
  });

  it("login refuses a server that is not a websocket URL", async () => {
    const h = fakeHarness();
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    await rt.runCommand("login did:plc:owner irc.example.test");
    expect(rt.config?.ownerDid).toBeUndefined();
    expect(rt.conn).toBeUndefined();
    expect(h.notices.at(-1)).toEqual({
      text: "usage: /freeq login did:plc:… [wss://server/irc] (your own DID, and the server if not the default)",
      level: "warning",
    });
  });

  it("login with another server while online reconnects there", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const urls: string[] = [];
    const rt = new AgentRuntime(h.harness, {
      botFactory: async (o) => {
        urls.push(o.url);
        return new FakeBot();
      },
    });
    await rt.start();
    expect(rt.conn?.state).toBe("online");
    await rt.runCommand("login did:plc:owner wss://other.example.test/irc");
    expect(urls).toEqual(["ws://test.invalid/irc", "wss://other.example.test/irc"]);
    expect(rt.config?.server).toBe("wss://other.example.test/irc");
    expect(rt.conn?.state).toBe("online");
  });

  it("login without a server keeps the configured one", async () => {
    const { rt } = await started();
    await rt.runCommand("login did:plc:other");
    expect(rt.config).toMatchObject({ ownerDid: "did:plc:other", server: "ws://test.invalid/irc" });
  });

  it("join pins the project's own channel list", async () => {
    const { rt, bot } = await started();
    await rt.runCommand("join #new");
    expect(rt.config!.projects).toEqual({ proj: { channels: ["#work", "#new"] } });
    expect(bot.sent.at(-1)).toEqual({ kind: "join", target: "#new", payload: null });
  });

  it("peers goes to the harness's roster, or to a notice without one", async () => {
    const shown: Array<{ title: string; lines: string[] }> = [];
    const h = fakeHarness({ roster: (title, lines) => void shown.push({ title, lines }) });
    writeConfig(h.agentDir);
    const bot = new FakeBot();
    const rt = new AgentRuntime(h.harness, { botFactory: async () => bot });
    await rt.start();
    bot.emit("presence", { nick: "zapnap", did: OWNER, state: "online", status: "" });
    await rt.runCommand("peers");
    expect(shown[0]!.title).toBe("freeq peers (1)");
    expect(shown[0]!.lines[0]).toContain("zapnap");

    const plain = await started();
    plain.bot.emit("presence", { nick: "zapnap", did: OWNER, state: "online", status: "" });
    await plain.rt.runCommand("peers");
    expect(plain.notices.at(-1)!.text.split("\n")[0]).toBe("freeq peers (1)");
  });

  it("wakes a dormant project on first use", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir, { projects: undefined });
    const rt = new AgentRuntime(h.harness, { botFactory: async () => new FakeBot() });
    await rt.start();
    expect(rt.dormant).toBe(true);
    await rt.runCommand("mute");
    expect(rt.conn?.state).toBe("online");
    expect(h.notices[0]!.text).toBe("freeq: first use in this project — minting its identity");
  });
});

describe("AgentRuntime: harness names", () => {
  it("uses pi's names by default", async () => {
    const { rt } = await started();
    expect(rt.names.name).toBe("pi");
    expect(rt.names.hint("accept")).toBe("/freeq accept");
  });

  it("names identity, nick, hello, notices and the stop reason after the harness", async () => {
    const h = fakeHarness({ name: "cc", commandHint: (sub) => `/freeq:${sub}` });
    writeConfig(h.agentDir);
    const bot = new FakeBot();
    let created: { name: string; nick: string } | undefined;
    const stops: string[] = [];
    bot.stop = async (reason?: string) => {
      stops.push(reason ?? "");
      return bot;
    };
    const rt = new AgentRuntime(h.harness, {
      botFactory: async (o) => {
        created = { name: o.name, nick: o.nick };
        return bot;
      },
    });
    await rt.start();
    expect(created).toEqual({ name: "cc-test1234-proj", nick: "cc-test1234-proj" });

    bot.emit("channelJoined", "#work");
    const hello = bot.sent.find((s) => s.kind === "tagmsg")!;
    expect(JSON.parse(decodeURIComponent((hello.payload as Record<string, string>)["+freeq.at/payload"]!)).agent).toBe("cc");

    bot.emit("message", "eve", { from: "eve", text: "hi", isSelf: false, tags: { account: "did:plc:eve" } });
    await tick();
    expect(h.notices.at(-1)!.text).toContain("/freeq:trust did:plc:eve message");

    await rt.runCommand("drop");
    expect(h.notices.at(-1)!.text).toBe("usage: /freeq:drop <id> [reason]");

    await rt.stop();
    expect(stops).toEqual(["cc session ended"]);
  });
});

describe("httpOriginFor", () => {
  it("maps the websocket URL to the HTTP origin", () => {
    expect(httpOriginFor("wss://irc.freeq.at/irc")).toBe("https://irc.freeq.at");
    expect(httpOriginFor("ws://localhost:8080/irc")).toBe("http://localhost:8080");
    expect(httpOriginFor("not a url")).toBe("https://irc.freeq.at");
  });
});

describe("AgentRuntime: messages the harness takes", () => {
  it("does not deliver a message the harness intercepts, and delivers the rest", async () => {
    const taken: Array<{ channel: string; from: string; did: string | null; text: string }> = [];
    const h = fakeHarness({
      intercept: (m) => {
        if (m.text !== "yes abcde") return false;
        taken.push(m);
        return true;
      },
    });
    writeConfig(h.agentDir);
    const bot = new FakeBot();
    const rt = new AgentRuntime(h.harness, { botFactory: async () => bot });
    await rt.start();
    bot.emit("message", "nap", { from: "nap", text: "yes abcde", isSelf: false, tags: { account: OWNER } });
    await tick();
    expect(taken).toEqual([{ channel: "nap", from: "nap", did: OWNER, text: "yes abcde" }]);
    expect(h.delivered).toEqual([]);
    // Nothing is owed for it: a settled run sends nothing back.
    await rt.onSettled();
    expect(bot.messages()).toEqual([]);
    bot.emit("message", "nap", { from: "nap", text: "hello", isSelf: false, tags: { account: OWNER } });
    await tick();
    expect(h.delivered).toHaveLength(1);
    await rt.stop();
  });
});
