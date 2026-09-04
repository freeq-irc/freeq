import { describe, it, expect, vi } from "vitest";
import { FreeqConnection, type BotLike, type ConnectionOptions } from "./connection.js";
import { PI_HELLO, PI_HELLO_ACK, buildHello, helloTags } from "./discovery.js";
import { PI_ASK, PI_ASK_REPLY, encodePayload } from "./ask.js";

/**
 * A fake bot-kit bot. Records what went on the wire and lets a test drive
 * the events a real server would send.
 *
 * The connection's reconnect/announce/ask logic is what broke in production;
 * none of it needs a socket to exercise.
 */
class FakeBot implements BotLike {
  handlers = new Map<string, Array<(...a: never[]) => void>>();
  sent: Array<{ kind: string; target: string; payload: unknown }> = [];
  states: Array<{ state: string; status?: string; task?: string }> = [];
  stopped: string[] = [];
  startCalls = 0;
  nick: string | null = "pi-test";
  pubkey: string | null = "fake-pubkey";
  mentionResult: { kind: string; stripped?: string } = { kind: "ignore" };
  senderDid: string | null = "did:key:zSender";
  failStart = false;

  identity = { did: "did:key:zSelf" };

  client = {
    get nick() {
      return self.nick;
    },
    join: (channel: string) => this.sent.push({ kind: "join", target: channel, payload: null }),
    raw: (line: string) => this.sent.push({ kind: "raw", target: "", payload: line }),
    sendMessage: (target: string, text: string) =>
      this.sent.push({ kind: "message", target, payload: text }),
    sendTagmsg: (target: string, tags: Record<string, string>) =>
      this.sent.push({ kind: "tagmsg", target, payload: tags }),
    sendAct: async (target: string, tags: Record<string, string>) => {
      this.sent.push({ kind: "act", target, payload: tags });
      return "01EVENTID";
    },
    signing: { getPublicKey: () => this.pubkey },
  };

  on(event: string, handler: (...a: never[]) => void): unknown {
    const list = this.handlers.get(event) ?? [];
    list.push(handler);
    this.handlers.set(event, list);
    return this;
  }
  async start(): Promise<unknown> {
    this.startCalls++;
    if (this.failStart) throw new Error("boom");
    return this;
  }
  async stop(reason?: string): Promise<unknown> {
    this.stopped.push(reason ?? "");
    return this;
  }
  setState(state: string, status?: string, task?: string): void {
    this.states.push({ state, status, task });
  }
  checkMention(): { kind: string; stripped?: string } {
    return this.mentionResult;
  }
  async resolveSenderDid(): Promise<string | null> {
    return this.senderDid;
  }

  /** Drive an event the way the server would. */
  emit(event: string, ...args: unknown[]): void {
    for (const h of this.handlers.get(event) ?? []) (h as (...a: unknown[]) => void)(...args);
  }
}
// `client.nick` getter needs a stable reference to the instance.
let self: FakeBot;

function mk(over: Partial<ConnectionOptions> = {}) {
  const bot = new FakeBot();
  self = bot;
  const notices: Array<{ text: string; level: string }> = [];
  const conn = new FreeqConnection({
    ownerDid: "did:plc:owner",
    server: "ws://test/irc",
    slug: "test1234",
    nick: "pi-test",
    channels: ["#work"],
    meta: { project: "freeq", branch: "main" },
    onNotice: (text, level) => notices.push({ text, level }),
    botFactory: async () => bot,
    ...over,
  });
  return { conn, bot, notices };
}

describe("connect lifecycle", () => {
  it("comes online and exposes identity", async () => {
    const { conn, bot } = mk();
    await conn.start();
    expect(conn.state).toBe("online");
    expect(conn.did).toBe("did:key:zSelf");
    expect(bot.startCalls).toBe(1);
  });

  it("is idempotent — re-entrant start() must not build a second bot", async () => {
    // The production bug: two bots meant two live sessions on one DID, which
    // the server logged as endless ghost churn.
    const { conn, bot } = mk();
    await Promise.all([conn.start(), conn.start(), conn.start()]);
    await conn.start();
    expect(bot.startCalls).toBe(1);
  });

  it("degrades without throwing when the initial connect fails", async () => {
    const { conn, bot, notices } = mk();
    bot.failStart = true;
    await expect(conn.start()).resolves.toBeUndefined();
    expect(conn.state).toBe("error");
    expect(conn.lastError).toMatch(/boom/);
    expect(notices.some((n) => /could not connect/.test(n.text))).toBe(true);
  });

  it("discards a half-built bot on failure so a retry cannot double up", async () => {
    const { conn, bot } = mk();
    bot.failStart = true;
    await conn.start();
    expect(bot.stopped).toContain("discarded");
    expect(conn.bot).toBeUndefined();
  });

  it("stop() is final — no reconnect afterwards", async () => {
    const { conn, bot } = mk();
    await conn.start();
    await conn.stop("done");
    expect(conn.state).toBe("offline");
    await conn.start();
    expect(bot.startCalls).toBe(1);
  });
});

describe("transport state handling (the churn regression)", () => {
  it("uses the REAL TransportState names", async () => {
    // TransportState is only 'disconnected' | 'connecting' | 'connected'.
    // The original code tested for 'ready' and 'closed' — branches that could
    // never fire — so a live connection never registered as online.
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("connectionStateChanged", "connected");
    expect(conn.state).toBe("online");
  });

  it("does NOT tear down the bot when the socket drops", async () => {
    // The SDK transport reconnects itself. Rebuilding here raced it and
    // produced duplicate sessions.
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("connectionStateChanged", "disconnected");
    expect(bot.stopped).toEqual([]); // nothing torn down
    expect(bot.startCalls).toBe(1); // nothing rebuilt
    expect(conn.state).toBe("connecting"); // recovering, not dead
  });

  it("recovers to online when the transport reconnects", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("connectionStateChanged", "disconnected");
    bot.emit("connectionStateChanged", "connected");
    expect(conn.state).toBe("online");
  });

  it("reports a drop once, not on every flap", async () => {
    const { conn, bot, notices } = mk();
    await conn.start();
    for (let i = 0; i < 5; i++) bot.emit("connectionStateChanged", "disconnected");
    expect(notices.filter((n) => /dropped/.test(n.text)).length).toBe(1);
  });

  it("re-arms the warning after a successful recovery", async () => {
    const { conn, bot, notices } = mk();
    await conn.start();
    bot.emit("connectionStateChanged", "disconnected");
    bot.emit("connectionStateChanged", "connected");
    bot.emit("connectionStateChanged", "disconnected");
    expect(notices.filter((n) => /dropped/.test(n.text)).length).toBe(2);
  });

  it("ignores transport noise after stop()", async () => {
    const { conn, bot, notices } = mk();
    await conn.start();
    await conn.stop("bye");
    bot.emit("connectionStateChanged", "disconnected");
    expect(notices.filter((n) => /dropped/.test(n.text)).length).toBe(0);
  });

  it("reports coming online once per gap, not once per event", async () => {
    // The host resumes assigned work here. bot.start() returning and the
    // transport's own 'connected' both mean online, and a resume that ran
    // twice for one connect would re-enter every task twice.
    const online: number[] = [];
    const { conn, bot } = mk({ onOnline: () => online.push(1) });
    await conn.start();
    bot.emit("connectionStateChanged", "connected");
    bot.emit("connectionStateChanged", "connected");
    expect(online).toHaveLength(1);

    bot.emit("connectionStateChanged", "disconnected");
    bot.emit("connectionStateChanged", "connected");
    expect(online).toHaveLength(2); // a real gap closed — resume again
  });

  it("survives a throwing online handler", async () => {
    const { conn, notices } = mk({
      onOnline: () => {
        throw new Error("resume exploded");
      },
    });
    await expect(conn.start()).resolves.toBeUndefined();
    expect(conn.state).toBe("online");
    expect(notices.some((n) => /online handler error/.test(n.text))).toBe(true);
  });
});

describe("peer discovery", () => {
  it("announces a hello when a channel is joined", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("channelJoined", "#work");
    const tagmsgs = bot.sent.filter((s) => s.kind === "tagmsg");
    expect(tagmsgs.length).toBe(1);
    expect((tagmsgs[0].payload as Record<string, string>)["+freeq.at/event"]).toBe(PI_HELLO);
  });

  it("acks a peer's hello, and records the peer", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-other",
      did: "did:key:zOther",
      eventType: PI_HELLO,
      eventId: "e1",
      payload: buildHello({ project: "theirs", branch: "dev" }, "did:key:zOther"),
      tags: {},
    });
    await vi.waitFor(() => expect(conn.peers().length).toBe(1));
    const peer = conn.peers()[0];
    expect(peer.nick).toBe("pi-other");
    expect(peer.did).toBe("did:key:zOther");
    expect(peer.isPi).toBe(true);
    expect(peer.meta.project).toBe("theirs");
    expect(
      bot.sent.some(
        (s) =>
          s.kind === "tagmsg" &&
          (s.payload as Record<string, string>)["+freeq.at/event"] === PI_HELLO_ACK,
      ),
    ).toBe(true);
  });

  it("never acks an ack — that is the storm guard", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-other",
      did: "did:key:zOther",
      eventType: PI_HELLO_ACK,
      eventId: "e2",
      payload: buildHello({}, "did:key:zOther"),
      tags: {},
    });
    await vi.waitFor(() => expect(conn.peers().length).toBe(1));
    expect(bot.sent.filter((s) => s.kind === "tagmsg").length).toBe(0);
  });

  it("ignores its own announcements", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-test", // us
      did: "did:key:zSelf",
      eventType: PI_HELLO,
      eventId: "e3",
      payload: buildHello({}, "did:key:zSelf"),
      tags: {},
    });
    expect(conn.peers().length).toBe(0);
  });

  it("prefers the server-resolved DID over the self-asserted one in the payload", async () => {
    // A peer can claim any DID in its hello; only the resolved one is used.
    const { conn, bot } = mk();
    bot.senderDid = "did:key:zTruth";
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-liar",
      did: undefined, // force a resolve
      eventType: PI_HELLO,
      eventId: "e4",
      payload: buildHello({}, "did:key:zLIE"),
      tags: {},
    });
    await vi.waitFor(() => expect(conn.peers().length).toBe(1));
    expect(conn.peers()[0].did).toBe("did:key:zTruth");
  });

  it("drops a peer that goes offline", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("presence", { nick: "pi-other", state: "online" });
    expect(conn.peers().length).toBe(1);
    bot.emit("presence", { nick: "pi-other", state: "offline" });
    expect(conn.peers().length).toBe(0);
  });

  it("presence updates liveness without erasing metadata learned from a hello", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-other",
      did: "did:key:zOther",
      eventType: PI_HELLO,
      eventId: "e5",
      payload: buildHello({ project: "keepme" }, "did:key:zOther"),
      tags: {},
    });
    await vi.waitFor(() => expect(conn.peers().length).toBe(1));
    bot.emit("presence", { nick: "pi-other", state: "executing", status: "" });
    expect(conn.peers()[0].meta.project).toBe("keepme");
    expect(conn.peers()[0].state).toBe("executing");
  });
});

describe("ask", () => {
  it("sends a request and resolves on the peer's reply", async () => {
    const { conn, bot } = mk();
    await conn.start();
    const pending = conn.ask("pi-other", "what changed?", 5000);

    const sentAsk = bot.sent.find(
      (s) =>
        s.kind === "tagmsg" &&
        (s.payload as Record<string, string>)["+freeq.at/event"] === PI_ASK,
    );
    expect(sentAsk).toBeTruthy();
    const payload = JSON.parse(
      decodeURIComponent((sentAsk!.payload as Record<string, string>)["+freeq.at/payload"]),
    );

    bot.emit("coordinationEvent", {
      channel: "pi-other",
      from: "pi-other",
      did: "did:key:zOther",
      eventType: PI_ASK_REPLY,
      eventId: "r1",
      payload: { req: payload.req, a: "the auth interface" },
      tags: {},
    });
    await expect(pending).resolves.toMatchObject({ ok: true, answer: "the auth interface" });
  });

  it("routes an inbound ask to the host", async () => {
    const asks: unknown[] = [];
    const { conn, bot } = mk({ onAsk: (a) => asks.push(a) });
    await conn.start();
    bot.emit("coordinationEvent", {
      channel: "#work",
      from: "pi-other",
      did: "did:key:zOther",
      eventType: PI_ASK,
      eventId: "a1",
      payload: { req: "req-1", q: "how many files?" },
      tags: {},
    });
    await vi.waitFor(() => expect(asks.length).toBe(1));
    expect(asks[0]).toMatchObject({ req: "req-1", from: "pi-other", question: "how many files?" });
  });

  it("fails an ask when offline instead of hanging", async () => {
    const { conn } = mk();
    await expect(conn.ask("pi-other", "hi")).resolves.toMatchObject({ ok: false });
  });

  it("cancels outstanding asks on stop", async () => {
    const { conn } = mk();
    await conn.start();
    const pending = conn.ask("pi-other", "hi", 60_000);
    await conn.stop("bye");
    await expect(pending).resolves.toMatchObject({ ok: false });
  });
});

describe("outbound redaction is unavoidable", () => {
  it("scrubs a message", async () => {
    const { conn, bot } = mk();
    await conn.start();
    conn.send("#work", "path is /Users/chad/src/secret");
    const msg = bot.sent.find((s) => s.kind === "message");
    expect(String(msg!.payload)).not.toContain("/Users/chad");
  });

  it("scrubs an ask question", async () => {
    const { conn, bot } = mk();
    await conn.start();
    void conn.ask("pi-other", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789", 1000);
    const sent = bot.sent.find(
      (s) => (s.payload as Record<string, string>)?.["+freeq.at/event"] === PI_ASK,
    );
    expect(JSON.stringify(sent!.payload)).not.toContain("ghp_");
  });

  it("scrubs act titles and notes before they are SIGNED", async () => {
    // A signature over a leaked secret makes the leak permanent AND
    // non-repudiable, so redaction has to happen before signing.
    const { conn, bot } = mk();
    await conn.start();
    await conn.sendAct("#work", "offer", undefined, {
      to: "did:key:zOther",
      title: "fix /Users/chad/src/app",
      note: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
    });
    const act = bot.sent.find((s) => s.kind === "act");
    const tags = JSON.stringify(act!.payload);
    expect(tags).not.toContain("/Users/chad");
    expect(tags).not.toContain("wJalrXUtnFEMI");
  });

  it("reports what it redacted", async () => {
    const hits: string[][] = [];
    const { conn } = mk({ onScrub: (h) => hits.push(h) });
    await conn.start();
    conn.send("#work", "see /Users/chad/x/y");
    expect(hits.length).toBe(1);
    expect(hits[0].some((h) => h.includes("path"))).toBe(true);
  });
});

describe("act events", () => {
  it("forwards task events, including our own echo", async () => {
    // Our own accept echo is what advances local state; filtering it as
    // self-traffic left an assignee unable to reach 'complete'.
    const seen: unknown[] = [];
    const { conn, bot } = mk({ onActEvent: (e) => seen.push(e) });
    await conn.start();
    bot.emit("actEvent", { from: "pi-test", verb: "accept", taskId: "t1", kind: "handoff" });
    bot.emit("actEvent", { from: "pi-other", verb: "complete", taskId: "t1", kind: "handoff" });
    expect(seen.length).toBe(2);
  });

  it("survives a throwing host handler", async () => {
    const { conn, bot, notices } = mk({
      onActEvent: () => {
        throw new Error("handler bug");
      },
    });
    await conn.start();
    expect(() =>
      bot.emit("actEvent", { from: "x", verb: "offer", taskId: "t", kind: "handoff" }),
    ).not.toThrow();
    expect(notices.some((n) => n.level === "error")).toBe(true);
  });

  it("waits for a signing key before emitting a signed event", async () => {
    const { conn, bot } = mk({ signingKeyTimeoutMs: 300 });
    bot.pubkey = null; // key not registered yet
    await conn.start();
    const result = await conn.sendAct("#work", "offer", undefined, { title: "x" });
    expect(result).toBeUndefined();
    expect(bot.sent.some((s) => s.kind === "act")).toBe(false);
  });
});

describe("work status", () => {
  it("reports state transitions to the server", async () => {
    const { conn, bot } = mk();
    await conn.start();
    conn.setWorkState("executing", "answering chad", "task-1");
    // The label rides inside the k=v presence string as 'doing=', alongside
    // the session metadata, rather than replacing it — see setWorkState.
    const last = bot.states.at(-1)!;
    expect(last.state).toBe("executing");
    expect(last.task).toBe("task-1");
    expect(last.status).toContain("doing=answering+chad");
  });

  it("is a no-op when offline rather than throwing", async () => {
    const { conn } = mk();
    expect(() => conn.setWorkState("executing", "x")).not.toThrow();
  });
});

describe("mention matching", () => {
  it("reports an addressed message", async () => {
    const { conn, bot } = mk();
    bot.mentionResult = { kind: "respond", stripped: "hello there" };
    await conn.start();
    expect(conn.checkMention("#work", "pi-test: hello there")).toEqual({
      addressed: true,
      stripped: "hello there",
      cooling: false,
    });
  });

  it("surfaces the cooldown that stops two agents ping-ponging", async () => {
    const { conn, bot } = mk();
    bot.mentionResult = { kind: "cooldown" };
    await conn.start();
    expect(conn.checkMention("#work", "pi-test: again")).toMatchObject({
      addressed: true,
      cooling: true,
    });
  });

  it("reports not-addressed when offline", () => {
    const { conn } = mk();
    expect(conn.checkMention("#work", "anything").addressed).toBe(false);
  });
});

describe("channels this session means to be in", () => {
  it("parts a channel the server rejoined us into unasked", async () => {
    const { conn, bot } = mk();
    await conn.start();
    bot.emit("channelJoined", "#somewhere-else");
    expect(bot.sent.some((m) => m.kind === "raw" && String(m.payload).startsWith("PART #somewhere-else"))).toBe(true);
    expect(conn.joinedChannels()).not.toContain("#somewhere-else");
  });

  it("keeps a channel joined after /freeq join, which the snapshot could not", async () => {
    // The regression: the guard read the channel list captured at CONNECT, so
    // a channel joined later was not in it, and every /freeq join was parted a
    // moment after the server confirmed it.
    const { conn, bot } = mk();
    await conn.start();
    conn.join("#chad-compute");
    bot.emit("channelJoined", "#chad-compute");
    expect(bot.sent.some((m) => m.kind === "raw" && String(m.payload).startsWith("PART #chad-compute"))).toBe(false);
    expect(conn.joinedChannels()).toContain("#chad-compute");
  });

  it("stops wanting a channel after leave, so a server rejoin is undone", async () => {
    const { conn, bot } = mk();
    await conn.start();
    conn.leave("#work");
    bot.emit("channelJoined", "#work");
    expect(bot.sent.some((m) => m.kind === "raw" && String(m.payload).startsWith("PART #work"))).toBe(true);
  });
});
