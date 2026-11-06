import { afterEach, describe, it, expect, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentRuntime, httpOriginFor, type RuntimeOptions } from "./runtime.js";
import { HandoffStore } from "./handoff.js";
import { SignInRefusedError } from "@freeq/bot-kit";
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

describe("AgentRuntime: config", () => {
  it("shares one load between two first calls at once", async () => {
    // The session start and a command typed while it reads the config: with
    // a load each, the last to finish replaced the other's copy.
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const rt = new AgentRuntime(h.harness);
    const [a, b] = await Promise.all([rt.ensureConfig(), rt.ensureConfig()]);
    expect(a).toBe(b);
    expect(rt.config).toBe(a);
  });

  it("reads the file again after a load that failed", async () => {
    const h = fakeHarness();
    writeFileSync(join(h.agentDir, "freeq.json"), "{ not json");
    const rt = new AgentRuntime(h.harness);
    await expect(rt.ensureConfig()).rejects.toThrow(/cannot read config/);
    writeConfig(h.agentDir);
    await expect(rt.ensureConfig()).resolves.toMatchObject({ ownerDid: OWNER });
  });
});

describe("AgentRuntime: handoff store and offer queue", () => {
  it("shares one load of the handoff store between two first calls at once", async () => {
    // The session start and the resume that runs when it comes online: with
    // a load each, the last to finish replaced the other's copy.
    const h = fakeHarness();
    const rt = new AgentRuntime(h.harness);
    const [a, b] = await Promise.all([rt.ensureHandoffs(), rt.ensureHandoffs()]);
    expect(a).toBe(b);
    expect(rt.handoffs).toBe(a);
  });

  it("shares one load of the offer queue between two first calls at once", async () => {
    const h = fakeHarness();
    const rt = new AgentRuntime(h.harness);
    const [a, b] = await Promise.all([rt.ensureOffers(), rt.ensureOffers()]);
    expect(a).toBe(b);
    expect(rt.offers).toBe(a);
  });
});

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

  it("keeps a task event applied while the online resume is still loading the store", async () => {
    // The start and the online resume both make a first call for the store.
    // With a load each, holding the second until the offer is applied made
    // that load land last and replace the copy holding the task.
    const load = HandoffStore.prototype.load;
    let calls = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const spy = vi.spyOn(HandoffStore.prototype, "load").mockImplementation(async function (this: HandoffStore) {
      const n = calls++;
      await load.call(this);
      if (n === 1) await held;
    });
    try {
      const { bot, rt } = await started({ trust: { "did:plc:boss": "handoff" } });
      bot.emit("actEvent", act("offer", "01JC", {}, { "act-to": "did:plc:other", "act-title": "t", "act-home": "did:web:referee.test" }));
      await tick();
      release();
      await tick();
      bot.emit("actEvent", act("expire", "01JC", { did: "did:web:referee.test", from: "referee.test", eventId: "01JC-expire", ruling: "counts" }));
      for (let i = 0; i < 50 && rt.handoffs?.get("01JC")?.state !== "expired"; i++) await tick();
      expect(rt.handoffs?.get("01JC")?.state).toBe("expired");
    } finally {
      spy.mockRestore();
    }
  });

  it("loads the store once when the start and the online resume both ask for it", async () => {
    const spy = vi.spyOn(HandoffStore.prototype, "load");
    try {
      await started();
      await tick();
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
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

/** A bot the server refuses at sign-in, as bot-kit reports it: authError,
 *  then start() rejects with SignInRefusedError. */
function refusedBot(): FakeBot {
  const bot = new FakeBot();
  bot.start = async () => {
    bot.emit("authError", "not allowed");
    throw new SignInRefusedError("not allowed");
  };
  return bot;
}

/** The one line a refusal is told in: the connection's own notice. */
const refusalLines = (notices: Array<{ text: string; level: NoticeLevel }>) =>
  notices.filter((n) => /not allowed/.test(n.text));

/** A factory that hands out `next()`'s bots and records what it was asked for. */
function countingFactory(next: () => FakeBot = () => new FakeBot()) {
  const made: Array<{ bot: FakeBot; ownerDid: string; url: string }> = [];
  const factory: NonNullable<RuntimeOptions["botFactory"]> = async (o) => {
    const bot = next();
    made.push({ bot, ownerDid: o.ownerDid, url: o.url });
    return bot;
  };
  return { factory, made };
}

const stuck = (notices: Array<{ text: string }>) =>
  notices.filter((n) => /freeq: already (error|connecting)/.test(n.text));

describe("AgentRuntime: login and connect replace a connection that is not online", () => {
  it("login reconnects a connection the server refused", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    let n = 0;
    const { factory, made } = countingFactory(() => (n++ === 0 ? refusedBot() : new FakeBot()));
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    const refused = rt.conn;
    expect(refused?.state).toBe("error");
    await rt.runCommand(`login ${OWNER}`);
    expect(made).toHaveLength(2);
    expect(refused?.state).toBe("offline");
    expect(rt.conn).not.toBe(refused);
    expect(rt.conn?.state).toBe("online");
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });

  it("login reconnects a connection that is still trying, once the old one has stopped", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const events: string[] = [];
    const first = new FakeBot();
    first.stop = async (reason?: string) => {
      events.push(`stop ${reason}`);
      await tick();
      events.push("stopped");
      return first;
    };
    let n = 0;
    const rt = new AgentRuntime(h.harness, {
      botFactory: async () => {
        events.push(`create ${++n}`);
        return n === 1 ? first : new FakeBot();
      },
    });
    await rt.start();
    first.emit("connectionStateChanged", "disconnected");
    expect(rt.conn?.state).toBe("connecting");
    await rt.runCommand(`login ${OWNER}`);
    expect(events).toEqual(["create 1", "stop login", "stopped", "create 2"]);
    expect(rt.conn?.state).toBe("online");
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });

  it("login while online for the same owner and server says so and does not reconnect", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const { factory, made } = countingFactory();
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    const held = rt.conn;
    await rt.runCommand(`login ${OWNER}`);
    await rt.runCommand(`login ${OWNER} ws://test.invalid/irc`);
    expect(made).toHaveLength(1);
    expect(rt.conn).toBe(held);
    expect(rt.conn?.state).toBe("online");
    expect(h.notices.slice(-2)).toEqual([
      { text: `freeq: already online as pi-test1234-proj for ${OWNER} on ws://test.invalid/irc`, level: "info" },
      { text: `freeq: already online as pi-test1234-proj for ${OWNER} on ws://test.invalid/irc`, level: "info" },
    ]);
    await rt.stop();
  });

  it("login while online for another owner reconnects as that owner", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const stops: string[] = [];
    const { factory, made } = countingFactory(() => {
      const bot = new FakeBot();
      bot.stop = async (reason?: string) => {
        stops.push(reason ?? "");
        return bot;
      };
      return bot;
    });
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    await rt.runCommand("login did:plc:other");
    expect(made.map((m) => m.ownerDid)).toEqual([OWNER, "did:plc:other"]);
    expect(stops).toEqual(["login"]);
    expect(rt.conn?.bot).toBe(made[1]!.bot);
    expect(rt.conn?.state).toBe("online");
    await rt.stop();
  });

  it("on replaces a refused connection, and answers an online one with its line", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    let n = 0;
    const { factory, made } = countingFactory(() => (n++ === 0 ? refusedBot() : new FakeBot()));
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    expect(rt.conn?.state).toBe("error");
    await rt.runCommand("on");
    expect(made).toHaveLength(2);
    expect(rt.conn?.state).toBe("online");
    await rt.runCommand("on");
    expect(made).toHaveLength(2);
    expect(h.notices.at(-1)).toEqual({ text: `freeq: ${rt.conn!.describe()}`, level: "info" });
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });

  it("login in a dormant project connects once", async () => {
    // Waking first would connect, be refused, and the login would then
    // connect and be refused again.
    let changes = 0;
    const h = fakeHarness({ stateChanged: () => void changes++ });
    writeConfig(h.agentDir, { projects: undefined });
    const { factory, made } = countingFactory(refusedBot);
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    expect(rt.dormant).toBe(true);
    changes = 0;
    await rt.runCommand(`login ${OWNER}`);
    expect(made).toHaveLength(1);
    expect(rt.dormant).toBe(false);
    expect(changes).toBeGreaterThan(0);
    expect(refusalLines(h.notices)).toHaveLength(1);
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });
});

describe("AgentRuntime: a try-again is told once, until the agent is in", () => {
  const WORDS = "Your identity could not be checked just now.";
  /** A bot the server cannot check just now, as bot-kit reports it:
   *  authErrorRetry, then start() resolves 'deferred'. */
  function deferredBot(): FakeBot {
    const bot = new FakeBot();
    bot.start = async () => {
      bot.emit("authErrorRetry", WORDS);
      return "deferred";
    };
    return bot;
  }
  const told = (notices: Array<{ text: string }>) => notices.filter((n) => n.text.includes(WORDS));
  const one = [{ text: `freeq: the server could not check this agent just now — ${WORDS}`, level: "warning" }];

  it("at the session start", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const rt = new AgentRuntime(h.harness, { botFactory: async () => deferredBot() });
    await rt.start();
    expect(rt.conn?.state).toBe("connecting");
    expect(told(h.notices)).toEqual(one);
    await rt.stop();
  });

  it("when a command wakes a dormant project", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir, { projects: undefined });
    const rt = new AgentRuntime(h.harness, { botFactory: async () => deferredBot() });
    await rt.start();
    await rt.runCommand("mute");
    expect(told(h.notices)).toEqual(one);
    await rt.stop();
  });

  it("from /freeq on, a login and takeover", async () => {
    for (const command of ["on", "login did:plc:other", "takeover"]) {
      // Online first; every later connect is the deferred one.
      const h = fakeHarness({ confirm: async () => true });
      writeConfig(h.agentDir);
      let n = 0;
      const rt = new AgentRuntime(h.harness, { botFactory: async () => (n++ === 0 ? new FakeBot() : deferredBot()) });
      await rt.start();
      if (command === "on") await rt.runCommand("off");
      h.notices.length = 0;
      await rt.runCommand(command);
      expect(told(h.notices), command).toEqual(one);
      await rt.stop();
    }
  });
});

describe("AgentRuntime: two connects at once", () => {
  async function overlapping(first: FakeBot, inStart: boolean) {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const second = new FakeBot();
    let releaseFirst: ((b: BotLike) => void) | undefined;
    let n = 0;
    const rt = new AgentRuntime(h.harness, {
      botFactory: (): Promise<BotLike> => {
        n++;
        if (n > 1) return Promise.resolve(second);
        if (inStart) return Promise.resolve(first);
        return new Promise((r) => (releaseFirst = r));
      },
    });
    return { h, rt, second, release: () => releaseFirst?.(first), created: () => n };
  }

  it("leaves one bot when the second starts while the first bot is being created", async () => {
    const first = new FakeBot();
    const firstLog: string[] = [];
    first.start = async () => {
      firstLog.push("start");
      return first;
    };
    first.stop = async (reason?: string) => {
      firstLog.push(`stop ${reason}`);
      return first;
    };
    const { h, rt, second, release, created } = await overlapping(first, false);
    const a = rt.connect();
    while (created() === 0) await tick();
    const b = await rt.connect();
    release();
    const aLine = await a;
    expect(firstLog).toEqual(["stop discarded"]);
    expect(rt.conn?.bot).toBe(second);
    expect(rt.conn?.state).toBe("online");
    expect(b).toBe(`freeq: ${rt.conn!.describe()}`);
    expect(aLine).toBe(b);
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });

  it("leaves one bot when the second starts while the first is inside bot.start()", async () => {
    const first = new FakeBot();
    const firstLog: string[] = [];
    let rejectStart: ((e: Error) => void) | undefined;
    first.start = () => {
      firstLog.push("start");
      return new Promise((_, reject) => (rejectStart = reject));
    };
    first.stop = async (reason?: string) => {
      firstLog.push(`stop ${reason}`);
      rejectStart?.(new Error("disconnected before ready"));
      return first;
    };
    const { h, rt, second } = await overlapping(first, true);
    const a = rt.connect();
    while (!rejectStart) await tick();
    const b = await rt.connect();
    const aLine = await a;
    expect(firstLog).toEqual(["start", "stop replaced"]);
    expect(rt.conn?.bot).toBe(second);
    expect(rt.conn?.state).toBe("online");
    expect(aLine).toBe(b);
    expect(b).toBe(`freeq: ${rt.conn!.describe()}`);
    expect(h.notices.filter((n) => /could not connect/.test(n.text))).toEqual([]);
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });

  /** Bots in the order the factory made them, each with the stops it got. */
  function recordingFactory(next: () => FakeBot = () => new FakeBot()) {
    const made: Array<{ bot: FakeBot; ownerDid: string; stops: string[] }> = [];
    const factory: NonNullable<RuntimeOptions["botFactory"]> = async (o) => {
      const bot = next();
      const stops: string[] = [];
      const stop = bot.stop.bind(bot);
      bot.stop = async (reason?: string) => {
        stops.push(reason ?? "");
        return stop(reason);
      };
      made.push({ bot, ownerDid: o.ownerDid, stops });
      return bot;
    };
    const running = () => made.filter((m) => m.stops.length === 0);
    return { factory, made, running };
  }

  it("leaves one bot when both start before either has stored its connection", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const { factory, made, running } = recordingFactory();
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    const [a, b] = await Promise.all([rt.connect(), rt.connect()]);
    expect(made).toHaveLength(1);
    expect(rt.conn?.bot).toBe(made[0]!.bot);
    expect(a).toBe(b);
    await rt.stop();
    expect(running()).toEqual([]);
  });

  it("leaves one new bot when two logins at once replace a refused connection", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    let n = 0;
    const { factory, made, running } = recordingFactory(() => (n++ === 0 ? refusedBot() : new FakeBot()));
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    expect(rt.conn?.state).toBe("error");
    await Promise.all([rt.runCommand(`login ${OWNER}`), rt.runCommand(`login ${OWNER}`)]);
    expect(made).toHaveLength(2);
    expect(rt.conn?.bot).toBe(made[1]!.bot);
    expect(rt.conn?.state).toBe("online");
    await rt.stop();
    expect(running()).toEqual([]);
  });

  it("leaves one bot when a login for another owner comes before the session start has stored its connection", async () => {
    const h = fakeHarness();
    writeConfig(h.agentDir);
    const { factory, made, running } = recordingFactory();
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await Promise.all([rt.start(), rt.runCommand("login did:plc:other")]);
    expect(made.map((m) => m.ownerDid)).toEqual(["did:plc:other"]);
    expect(rt.conn?.bot).toBe(made[0]!.bot);
    expect(rt.conn?.state).toBe("online");
    await rt.stop();
    expect(running()).toEqual([]);
  });
});

describe("AgentRuntime: a login while the session start's connect is running", () => {
  /** Start the runtime; its first bot's start() waits for `settle`, and a stop
   *  makes it reject as a real bot's does. Later bots come from `next`. */
  async function startingUp(next: () => FakeBot = () => new FakeBot(), over: Partial<Harness> = {}) {
    const h = fakeHarness(over);
    writeConfig(h.agentDir);
    const first = new FakeBot();
    const log: string[] = [];
    let settle: ((outcome: "online" | "refused") => void) | undefined;
    let rejectStart: ((e: Error) => void) | undefined;
    first.start = () => {
      log.push("start");
      return new Promise((resolve, reject) => {
        rejectStart = reject;
        settle = (outcome) => {
          if (outcome === "online") return resolve(first);
          first.emit("authError", "not allowed");
          reject(new SignInRefusedError("not allowed"));
        };
      });
    };
    first.stop = async (reason?: string) => {
      log.push(`stop ${reason}`);
      rejectStart?.(new Error("disconnected before ready"));
      return first;
    };
    const made: Array<{ bot: FakeBot; ownerDid: string }> = [];
    const rt = new AgentRuntime(h.harness, {
      botFactory: async (o) => {
        const bot = made.length === 0 ? first : next();
        made.push({ bot, ownerDid: o.ownerDid });
        return bot;
      },
    });
    const starting = rt.start();
    while (!settle) await tick();
    return { h, rt, log, made, starting, settle: (o: "online" | "refused") => settle!(o) };
  }

  /** The lines that report a connect's outcome: `freeq: <state>: …`. */
  const outcomes = (notices: Array<{ text: string; level: NoticeLevel }>) =>
    notices.filter((n) => /^freeq: (online|connecting|error|offline): /.test(n.text));
  const waiting = (notices: Array<{ text: string }>) => notices.filter((n) => /already under way/.test(n.text));

  it("a login for the same owner and server waits for it, and tells it once when it comes online", async () => {
    const s = await startingUp();
    const login = s.rt.runCommand(`login ${OWNER}`);
    await tick();
    s.settle("online");
    await Promise.all([s.starting, login]);
    expect(s.log).toEqual(["start"]);
    expect(s.made).toHaveLength(1);
    expect(s.rt.conn?.state).toBe("online");
    expect(waiting(s.h.notices)).toEqual([
      { text: `freeq: a connect for ${OWNER} on ws://test.invalid/irc is already under way; waiting for it`, level: "info" },
    ]);
    expect(outcomes(s.h.notices)).toEqual([{ text: `freeq: ${s.rt.conn!.describe()}`, level: "info" }]);
    expect(stuck(s.h.notices)).toEqual([]);
    await s.rt.stop();
  });

  it("a login for the same owner and server waits for it, and the refusal is told once, in the connection's notice", async () => {
    const s = await startingUp();
    const login = s.rt.runCommand(`login ${OWNER}`);
    await tick();
    s.settle("refused");
    await Promise.all([s.starting, login]);
    // Nothing stopped it but bot-kit: the refused bot is kept.
    expect(s.log).toEqual(["start"]);
    expect(s.made).toHaveLength(1);
    expect(s.rt.conn?.state).toBe("error");
    expect(waiting(s.h.notices)).toHaveLength(1);
    expect(outcomes(s.h.notices)).toEqual([]);
    expect(refusalLines(s.h.notices)).toEqual([{ text: "freeq: authentication failed — not allowed", level: "error" }]);
    expect(stuck(s.h.notices)).toEqual([]);
    await s.rt.stop();
  });

  it("a login for another owner replaces it, leaves one bot, and tells no false offline", async () => {
    const s = await startingUp();
    await s.rt.runCommand("login did:plc:other");
    await s.starting;
    expect(s.log).toEqual(["start", "stop login"]);
    expect(s.made.map((m) => m.ownerDid)).toEqual([OWNER, "did:plc:other"]);
    expect(s.rt.conn?.bot).toBe(s.made[1]!.bot);
    expect(s.rt.conn?.state).toBe("online");
    expect(s.h.notices.filter((n) => /freeq: offline/.test(n.text))).toEqual([]);
    expect(outcomes(s.h.notices)).toEqual([{ text: `freeq: ${s.rt.conn!.describe()}`, level: "info" }]);
    expect(stuck(s.h.notices)).toEqual([]);
    await s.rt.stop();
  });

  it("a login for another owner replaces it, and a refusal of the new owner is told once", async () => {
    const s = await startingUp(refusedBot);
    await s.rt.runCommand("login did:plc:other");
    await s.starting;
    expect(s.log).toEqual(["start", "stop login"]);
    expect(s.made.map((m) => m.ownerDid)).toEqual([OWNER, "did:plc:other"]);
    expect(s.h.notices.filter((n) => /freeq: offline/.test(n.text))).toEqual([]);
    expect(outcomes(s.h.notices)).toEqual([]);
    expect(refusalLines(s.h.notices)).toEqual([{ text: "freeq: authentication failed — not allowed", level: "error" }]);
    expect(stuck(s.h.notices)).toEqual([]);
    await s.rt.stop();
  });

  it("authorize verify replaces it, and tells no false offline", async () => {
    const s = await startingUp(() => {
      const bot = new FakeBot();
      // The server's answer to the new connection's provenance, at once,
      // so verify does not wait for it.
      (bot as { provenance: unknown }).provenance = { verified: true, reason: "ok", text: "Provenance verified: ok" };
      return bot;
    });
    await s.rt.runCommand("authorize verify");
    await s.starting;
    expect(s.log).toEqual(["start", "stop re-presenting delegation"]);
    expect(s.made).toHaveLength(2);
    expect(s.rt.conn?.bot).toBe(s.made[1]!.bot);
    expect(s.h.notices.filter((n) => /freeq: offline/.test(n.text))).toEqual([]);
    expect(s.h.notices.map((n) => n.text)).toEqual([
      "freeq: reconnecting to ask the server…",
      "freeq: Delegation verified — this installation provably acts for you.",
    ]);
    await s.rt.stop();
  });

  it("takeover replaces it, and tells no false offline", async () => {
    const s = await startingUp(undefined, { confirm: async () => true });
    await s.rt.runCommand("takeover");
    await s.starting;
    expect(s.log).toEqual(["start", "stop takeover"]);
    expect(s.made).toHaveLength(2);
    expect(s.rt.conn?.bot).toBe(s.made[1]!.bot);
    expect(s.h.notices.filter((n) => /freeq: offline/.test(n.text))).toEqual([]);
    expect(outcomes(s.h.notices)).toEqual([{ text: `freeq: ${s.rt.conn!.describe()}`, level: "info" }]);
    await s.rt.stop();
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

describe("AgentRuntime: settled", () => {
  it("resolves only after a handler's awaited step resolves", async () => {
    // Hold the server-DID read the task handler awaits, so the handler is in
    // flight for exactly as long as the test says.
    const prior = globalThis.fetch;
    let release!: (r: Response) => void;
    const held = new Promise<Response>((r) => (release = r));
    let asked = false;
    vi.stubGlobal("fetch", async (url: string) => {
      const u = String(url);
      if (u.endsWith("/api/v1/signing-key")) {
        asked = true;
        return held;
      }
      return u.includes("/api/v1/actions")
        ? new Response(JSON.stringify({ tasks: [] }), { status: 200 })
        : new Response(null, { status: 404 });
    });
    try {
      const { bot, notices, rt } = await started();
      bot.emit("actEvent", act("offer", "01JA", {}, { "act-to": "did:key:zSelf", "act-title": "t" }));
      let done = false;
      const wait = rt.settled().then(() => (done = true));
      for (let i = 0; i < 50 && !asked; i++) await tick();
      expect(asked, "the handler reached the held read").toBe(true);
      await tick();
      expect(done, "settled() while the read is held").toBe(false);
      expect(notices.map((n) => n.text).join("\n")).not.toContain("ignoring handoff");
      release(new Response(null, { status: 404 }));
      await wait;
      expect(done).toBe(true);
      expect(notices.map((n) => n.text).join("\n")).toContain("ignoring handoff from did:plc:boss");
    } finally {
      vi.stubGlobal("fetch", prior);
    }
  });

  it("a handler that throws still rejects as before, and settled() still resolves", async () => {
    const { bot, rt } = await started();
    let caught: unknown;
    const onRejection = (reason: unknown) => (caught = reason);
    process.once("unhandledRejection", onRejection);
    try {
      bot.mention = () => {
        throw new Error("mention check broke");
      };
      bot.emit("message", "#work", { from: "peer", text: "hi", isSelf: false, tags: { account: PEER } });
      await rt.settled();
      for (let i = 0; i < 50 && caught === undefined; i++) await tick();
      expect((caught as Error)?.message).toBe("mention check broke");
    } finally {
      process.off("unhandledRejection", onRejection);
    }
  });
});

describe("AgentRuntime: /freeq on in a dormant project", () => {
  it("connects once, and the refusal is told once", async () => {
    // freeq is already on. Waking first would connect and be refused, and
    // on would then connect and be refused again.
    const h = fakeHarness();
    writeConfig(h.agentDir, { projects: undefined });
    const { factory, made } = countingFactory(refusedBot);
    const rt = new AgentRuntime(h.harness, { botFactory: factory });
    await rt.start();
    expect(rt.dormant).toBe(true);
    await rt.runCommand("on");
    expect(made).toHaveLength(1);
    expect(rt.dormant).toBe(false);
    // The connection's own line for the refused connect, once.
    expect(h.notices.filter((n) => /could not connect|authentication failed/.test(n.text))).toHaveLength(1);
    expect(stuck(h.notices)).toEqual([]);
    await rt.stop();
  });
});
