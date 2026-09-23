import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "./config.js";
import { FakeClient, fakeMessage as message, fakeSession as makeSession } from "./fakes.js";
import {
  ASK_EVENT,
  ASK_REPLY_EVENT,
  FreeqSession,
  defaultNick,
  encodePayload,
  type SessionMode,
} from "./session.js";

describe("status", () => {
  it("says plainly that an unconnected session proves nothing", () => {
    const { session } = makeSession();
    const s = session.status();
    expect(s.mode).toBe("offline");
    expect(s.connected).toBe(false);
    expect(s.note).toMatch(/Not connected/);
  });

  it("warns that guest messages are not attributable", async () => {
    const { session } = makeSession();
    await session.connect();
    expect(session.status().mode).toBe("guest");
    expect(session.status().note).toMatch(/not proven|not attributable/i);
    expect(session.status().note).toMatch(/FREEQ_OWNER_DID/);
  });

  it("reports the owner it acts for when authenticated", async () => {
    const { session } = makeSession({ FREEQ_OWNER_DID: "did:plc:owner" }, "authenticated");
    await session.connect();
    const s = session.status();
    expect(s.mode).toBe("authenticated");
    expect(s.did).toBe("did:key:z1");
    expect(s.note).toContain("did:plc:owner");
  });
});

describe("connect", () => {
  it("resolves once, even when called concurrently", async () => {
    const client = new FakeClient();
    const factory = vi.fn(async () => ({ client, mode: "guest" as SessionMode }));
    const session = new FreeqSession(loadConfig({}), { createClient: factory });
    await Promise.all([session.connect(), session.connect(), session.connect()]);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(session.connected).toBe(true);
  });

  it("rejects with the server's reason when SASL fails", async () => {
    const client = new FakeClient();
    client.connect = () => {
      setTimeout(() => client.emit("authError", "invalid signature"), 0);
    };
    const session = new FreeqSession(loadConfig({}), {
      createClient: async () => ({ client, mode: "authenticated" as SessionMode }),
    });
    await expect(session.connect()).rejects.toThrow(/SASL authentication failed: invalid signature/);
  });

  it("joins the configured channels once ready", async () => {
    const { client, session } = makeSession({ FREEQ_CHANNELS: "general, #dev" });
    await session.connect();
    expect(client.joined).toEqual(["#general", "#dev"]);
    expect(session.status().channels).toEqual(["#general", "#dev"]);
  });

  it("hands the SASL-issued bearer token to its owner", async () => {
    const seen: Array<string | undefined> = [];
    const { client, session } = makeSession({}, "authenticated", (t) => seen.push(t));
    client.apiBearer = "sess-abc";
    await session.connect();
    expect(seen).toContain("sess-abc");
  });
});

describe("write guards", () => {
  it("refuses to send before connecting, and says what to do", () => {
    const { session } = makeSession();
    expect(() => session.say("#x", "hi")).toThrow(/not connected.*freeq_connect/i);
  });
});

describe("say confirmation", () => {
  it("resolves confirmed once the server echoes our message", async () => {
    const { session } = makeSession();
    await session.connect();
    await expect(session.say("#x", "hi")).resolves.toEqual({ confirmed: true });
  });

  it("reports unconfirmed when no echo arrives in time", async () => {
    const { session, client } = makeSession();
    client.echo = false;
    await session.connect();
    await expect(session.say("#x", "hi", 50)).resolves.toEqual({ confirmed: false });
  });

  it("does not mistake someone else's message for the echo", async () => {
    const { session, client } = makeSession();
    client.echo = false;
    await session.connect();
    const pending = session.say("#x", "hi", 200);
    client.emit("message", "#x", message("alice", "hi"));
    await expect(pending).resolves.toEqual({ confirmed: false });
  });
});

describe("message buffer", () => {
  it("keeps what arrived while no tool was running", async () => {
    const { client, session } = makeSession();
    await session.connect();
    client.emit("message", "#general", message("alice", "hello"));
    client.emit("message", "#general", message("bob", "world"));
    const buffered = session.buffered("#general");
    expect(buffered.map((m) => m.text)).toEqual(["hello", "world"]);
    expect(buffered[0].target).toBe("#general");
  });

  it("carries the sender DID when the server stamped one", async () => {
    const { client, session } = makeSession();
    await session.connect();
    client.emit(
      "message",
      "#general",
      message("alice", "hi", { tags: { account: "did:plc:alice", msgid: "01JMSG" } }),
    );
    const [m] = session.buffered("#general");
    expect(m.did).toBe("did:plc:alice");
    expect(m.msgid).toBe("01JMSG");
  });

  it("filters by target case-insensitively", async () => {
    const { client, session } = makeSession();
    await session.connect();
    client.emit("message", "#General", message("alice", "one"));
    client.emit("message", "#other", message("bob", "two"));
    expect(session.buffered("#general").map((m) => m.text)).toEqual(["one"]);
    expect(session.buffered().length).toBe(2);
  });

  it("is bounded, so a long-lived session doesn't leak", async () => {
    const { client, session } = makeSession();
    await session.connect();
    for (let i = 0; i < 500; i++) {
      client.emit("message", "#busy", message("alice", `m${i}`));
    }
    const all = session.buffered("#busy", 1000);
    expect(all.length).toBeLessThanOrEqual(200);
    expect(all.at(-1)?.text).toBe("m499");
  });

  it("waits for the next message and ignores our own echo", async () => {
    const { client, session } = makeSession();
    await session.connect();
    const waiting = session.waitForMessage("#general", 5_000);
    client.emit("message", "#general", message("mcp-test", "mine", { isSelf: true }));
    client.emit("message", "#general", message("alice", "theirs"));
    const got = await waiting;
    expect(got?.text).toBe("theirs");
  });

  it("resolves undefined when nothing arrives in time", async () => {
    const { session } = makeSession();
    await session.connect();
    expect(await session.waitForMessage("#quiet", 500)).toBeUndefined();
  });
});

describe("ask", () => {
  function askPayload(client: FakeClient) {
    const tagmsg = client.tagmsgs.at(-1)!;
    return JSON.parse(decodeURIComponent(tagmsg.tags["+freeq.at/payload"]));
  }

  it("sends a coordination event with a minted request id", async () => {
    const { client, session } = makeSession();
    await session.connect();
    void session.ask("peer", "what version?");
    const tagmsg = client.tagmsgs.at(-1)!;
    expect(tagmsg.target).toBe("peer");
    expect(tagmsg.tags["+freeq.at/event"]).toBe(ASK_EVENT);
    expect(askPayload(client).q).toBe("what version?");
    expect(askPayload(client).req).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("resolves with the peer's reply", async () => {
    const { client, session } = makeSession();
    await session.connect();
    const pending = session.ask("peer", "q");
    const { req } = askPayload(client);
    client.emit("coordinationEvent", {
      channel: "peer",
      from: "peer",
      eventType: ASK_REPLY_EVENT,
      eventId: "01J",
      payload: { req, a: "v0.1.0" },
      tags: {},
    });
    await expect(pending).resolves.toMatchObject({ ok: true, answer: "v0.1.0", from: "peer" });
  });

  it("rejects a reply from a third party", async () => {
    // A stranger must not be able to answer someone else's question.
    const { client, session } = makeSession();
    await session.connect();
    const pending = session.ask("peer", "q", 1_000);
    const { req } = askPayload(client);
    client.emit("coordinationEvent", {
      channel: "peer",
      from: "imposter",
      eventType: ASK_REPLY_EVENT,
      eventId: "01J",
      payload: { req, a: "lies" },
      tags: {},
    });
    await expect(pending).resolves.toMatchObject({ ok: false });
  });

  it("ignores a duplicate reply after settling", async () => {
    const { client, session } = makeSession();
    await session.connect();
    const pending = session.ask("peer", "q");
    const { req } = askPayload(client);
    const reply = (a: string) =>
      client.emit("coordinationEvent", {
        channel: "peer",
        from: "peer",
        eventType: ASK_REPLY_EVENT,
        eventId: "01J",
        payload: { req, a },
        tags: {},
      });
    reply("first");
    reply("second");
    await expect(pending).resolves.toMatchObject({ answer: "first" });
  });

  it("times out with a message that names the peer", async () => {
    const { session } = makeSession();
    await session.connect();
    const result = await session.ask("peer", "q", 1_000);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/no reply from peer within 1s/);
  });

  it("fails outstanding asks when the connection drops", async () => {
    const { client, session } = makeSession();
    await session.connect();
    const pending = session.ask("peer", "q", 60_000);
    client.emit("connectionStateChanged", "disconnected");
    await expect(pending).resolves.toMatchObject({ ok: false, error: /connection dropped/ });
  });

  it("records inbound asks and answers exactly one of them", async () => {
    const { client, session } = makeSession();
    await session.connect();
    client.emit("coordinationEvent", {
      channel: "#general",
      from: "peer",
      eventType: ASK_EVENT,
      eventId: "01J",
      payload: { req: "req-1", q: "are you there?" },
      tags: {},
    });
    expect(session.inboundAsks()).toMatchObject([{ req: "req-1", from: "peer" }]);

    expect(session.replyToAsk("req-1", "yes")).toBe(true);
    const tagmsg = client.tagmsgs.at(-1)!;
    expect(tagmsg.target).toBe("peer");
    expect(tagmsg.tags["+freeq.at/event"]).toBe(ASK_REPLY_EVENT);
    expect(session.inboundAsks()).toEqual([]);
    expect(session.replyToAsk("req-1", "again")).toBe(false);
  });

  it("drops malformed coordination events instead of throwing", async () => {
    const { client, session } = makeSession();
    await session.connect();
    for (const payload of [null, {}, { req: "" }, { req: "x" }, "string"]) {
      client.emit("coordinationEvent", {
        channel: "#general",
        from: "peer",
        eventType: ASK_EVENT,
        eventId: "01J",
        payload,
        tags: {},
      });
    }
    expect(session.inboundAsks()).toEqual([]);
  });
});

describe("close", () => {
  it("quits, disconnects, and unblocks waiters", async () => {
    const { client, session } = makeSession();
    await session.connect();
    const waiting = session.waitForMessage(undefined, 60_000);
    const pending = session.ask("peer", "q", 60_000);
    await session.close("bye");
    expect(client.quitReason).toBe("bye");
    expect(client.connected).toBe(false);
    expect(await waiting).toBeUndefined();
    await expect(pending).resolves.toMatchObject({ ok: false });
    expect(session.status().mode).toBe("offline");
  });

  it("is safe to call when never connected", async () => {
    const { session } = makeSession();
    await expect(session.close()).resolves.toBeUndefined();
  });
});

describe("encodePayload", () => {
  it("leaves short payloads untouched", () => {
    const { encoded, truncated } = encodePayload({ req: "1", q: "hi" }, "q");
    expect(truncated).toBe(false);
    expect(JSON.parse(decodeURIComponent(encoded))).toEqual({ req: "1", q: "hi" });
  });

  it("shrinks against the ENCODED size, not the raw length", () => {
    // Percent-encoding can triple non-ASCII text; budgeting on raw length
    // would put a line over the server's limit and get it dropped.
    const q = "é".repeat(4000);
    const { encoded, truncated } = encodePayload({ req: "1", q }, "q", 1000);
    expect(truncated).toBe(true);
    expect(encoded.length).toBeLessThanOrEqual(1000);
    expect(decodeURIComponent(encoded)).toContain("truncated");
  });

  it("converges even when the limit is tiny", () => {
    const { encoded } = encodePayload({ req: "1", q: "x".repeat(10_000) }, "q", 60);
    expect(encoded.length).toBeLessThanOrEqual(200);
  });
});

describe("defaultNick", () => {
  it("is stable, prefixed, and does not leak the hostname", () => {
    const a = defaultNick("host\0user\0mcp");
    const b = defaultNick("host\0user\0mcp");
    expect(a).toBe(b);
    expect(a).toMatch(/^mcp-[0-9a-f]{8}$/);
    expect(a).not.toContain("host");
  });

  it("differs across machines/accounts", () => {
    expect(defaultNick("a")).not.toBe(defaultNick("b"));
  });
});

describe("identity: self-owned did:key", () => {
  it("reports selfOwned and says the agent speaks for no human", async () => {
    const { session } = makeSession({}, "authenticated", undefined, { selfOwned: true });
    await session.connect();
    const s = session.status();
    expect(s.mode).toBe("authenticated");
    expect(s.selfOwned).toBe(true);
    expect(s.note).toMatch(/self-owned did:key/);
    expect(s.note).toMatch(/speaks for no human/);
    expect(s.note).toMatch(/FREEQ_OWNER_DID/);
  });

  it("does not flag an owner-bound identity as self-owned", async () => {
    const { session } = makeSession({ FREEQ_OWNER_DID: "did:plc:owner" }, "authenticated");
    await session.connect();
    expect(session.status().selfOwned).toBe(false);
  });

  it("points guests at FREEQ_GUEST", async () => {
    const { session } = makeSession({ FREEQ_GUEST: "1" });
    await session.connect();
    expect(session.status().note).toMatch(/FREEQ_GUEST/);
  });
});

describe("connect via a factory-provided start()", () => {
  it("uses start() (bot-kit's announce sequence) instead of client.connect()", async () => {
    const client = new FakeClient();
    let started = 0;
    const session = new FreeqSession(loadConfig({ FREEQ_CHANNELS: "#dev" }), {
      createClient: async () => ({
        client,
        mode: "authenticated" as SessionMode,
        did: "did:key:z1",
        start: async () => {
          started++;
          client.connected = true;
          client.emit("ready");
          // bot-kit JOINs the configured channels itself, after PROVENANCE.
          client.join("#dev");
        },
      }),
    });
    await session.connect();
    expect(started).toBe(1);
    expect(session.connected).toBe(true);
    // The session must not double-join what the bot already joined.
    expect(client.joined).toEqual(["#dev"]);
    expect(session.status().channels).toEqual(["#dev"]);
  });

  it("propagates start()'s rejection", async () => {
    const client = new FakeClient();
    const session = new FreeqSession(loadConfig({}), {
      createClient: async () => ({
        client,
        mode: "authenticated" as SessionMode,
        start: async () => {
          throw new Error("SASL auth failed: bad signature");
        },
      }),
    });
    await expect(session.connect()).rejects.toThrow(/SASL auth failed/);
    expect(session.connected).toBe(false);
  });

  it("publishes the pre-key after connecting and uses stop() on close", async () => {
    const { session, client } = makeSession({}, "authenticated", undefined, {
      rooms: new (await import("./fakes.js")).FakeRooms(),
      extra: { stop: async (reason: string) => { client.quitReason = `stop:${reason}`; } },
    });
    await session.connect();
    expect((session.rooms as unknown as { preKeyPublished: number }).preKeyPublished).toBe(1);
    await session.close("bye");
    expect(client.quitReason).toBe("stop:bye");
    expect(session.status().mode).toBe("offline");
  });

  it("warns (to the sink, never stdout) when the pre-key publish fails", async () => {
    const warnings: string[] = [];
    const rooms = new (await import("./fakes.js")).FakeRooms();
    rooms.ensurePreKeyPublished = async () => {
      throw new Error("no API bearer");
    };
    const { session } = makeSession({}, "authenticated", undefined, { rooms, warnings });
    await session.connect();
    expect(session.connected).toBe(true);
    expect(warnings.join("\n")).toMatch(/pre-key publish failed.*no API bearer/);
  });
});

describe("rooms on the session", () => {
  it("learns a channel is a room from the server's NOTICE", async () => {
    const { session, client } = makeSession({}, "authenticated");
    await session.connect();
    expect(session.isKnownRoom("#r-a-b-c")).toBe(false);
    client.emit("raw", "", {
      command: "NOTICE",
      params: ["mcp-test", "#r-a-b-c is an end-to-end encrypted room. A member will seal the room key to you."],
    });
    expect(session.isKnownRoom("#R-A-B-C")).toBe(true);
    expect(session.hasRoomKey("#r-a-b-c")).toBe(false);
  });

  it("throws a clear error when rooms are asked of a guest", async () => {
    const { session } = makeSession({ FREEQ_GUEST: "1" });
    await session.connect();
    expect(() => session.rooms).toThrow(/FREEQ_GUEST/);
  });

  it("throws the connect hint when offline", () => {
    const { session } = makeSession();
    expect(() => session.rooms).toThrow(/freeq_connect/);
  });

  it("history rows carry the message timestamp, not the read time", async () => {
    const { FakeRooms } = await import("./fakes.js");
    const rooms = new FakeRooms();
    rooms.keys.add("#r-a-b-c");
    const { session, client } = makeSession({}, "authenticated", undefined, { rooms });
    await session.connect();
    client.history.set("#r-a-b-c", [
      message("alice", "old", { timestamp: new Date(5_000), tags: { msgid: "01X" } }),
    ]);
    const res = await session.roomRead("#r-a-b-c", { history: true });
    expect(res.ready).toBe(true);
    expect(res.messages).toMatchObject([{ msgid: "01X", at: 5_000 }]);
  });

  it("survives a client without CHATHISTORY support", async () => {
    const { FakeRooms } = await import("./fakes.js");
    const rooms = new FakeRooms();
    rooms.keys.add("#r-a-b-c");
    const { session, client } = makeSession({}, "authenticated", undefined, { rooms });
    (client as { requestHistory?: unknown }).requestHistory = undefined;
    await session.connect();
    const res = await session.roomRead("#r-a-b-c", { history: true });
    expect(res.messages).toEqual([]);
  });
});
