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
