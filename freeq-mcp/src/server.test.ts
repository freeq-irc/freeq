/**
 * The MCP surface, driven by a real MCP client over an in-memory transport.
 *
 * These are the tests that matter most: an MCP client sees only the tool list
 * and the JSON it gets back, so schema mistakes and unhelpful error text are
 * exactly the bugs that don't show up anywhere else.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { FakeClient, fakeMessage, fakeRest, fakeSession } from "./fakes.js";
import { createFreeqMcpServer, INSTRUCTIONS, type FreeqMcp } from "./server.js";
import { ASK_EVENT, ASK_REPLY_EVENT } from "./session.js";

const HEALTH = {
  server_name: "irc.test",
  version: "0.1.0",
  connections: 3,
  channels: 2,
  uptime_secs: 99,
  av: true,
};

const ROUTES = {
  "GET /api/v1/health": { body: HEALTH },
  "GET /api/v1/channels": { body: [{ name: "#general", members: 2, topic: "hi" }] },
  "GET /api/v1/channels/%23general/history": {
    body: [{ id: 1, sender: "alice", text: "hello", timestamp: 1, tags: {}, msgid: "01JA" }],
  },
  "GET /api/v1/search": { body: [{ id: 1, sender: "alice", text: "deploy", timestamp: 1, tags: {} }] },
  "GET /api/v1/messages/01JA": { body: { channel: "#general", msgid: "01JA", text: "hello" } },
  "GET /api/v1/channels/%23general/pins": { body: { pins: [] } },
  "GET /api/v1/channels/%23general/topic": { body: { channel: "#general", topic: "hi" } },
  "GET /api/v1/users/alice/whois": { body: { nick: "alice", online: true, did: "did:plc:alice" } },
  "GET /.well-known/agent.json": {
    body: { service: "Freeq", capabilities: ["diagnose_join_failure"], surfaces: {} },
  },
  "POST /agent/tools/diagnose_join_failure": {
    body: { request_id: "r1", conclusion: "channel is +i" },
  },
  "GET /api/v1/openapi.json": { body: { openapi: "3.1.0", paths: {} } },
  "GET /llms.txt": { body: "# freeq\n", contentType: "text/markdown" },
};

interface Harness {
  mcp: FreeqMcp;
  client: Client;
  fake: FakeClient;
  requests: string[];
  call(name: string, args?: Record<string, unknown>): Promise<{ text: string; isError: boolean }>;
  json(name: string, args?: Record<string, unknown>): Promise<any>;
}

async function harness(
  opts: {
    env?: Record<string, string | undefined>;
    routes?: Record<string, unknown>;
    mode?: "guest" | "authenticated";
  } = {},
): Promise<Harness> {
  const requests: string[] = [];
  const rest = fakeRest(
    { ...ROUTES, ...(opts.routes ?? {}) } as never,
    { requests },
  );
  const { client: fake, session } = fakeSession(opts.env ?? {}, opts.mode ?? "guest");
  const cfg = loadConfig({ FREEQ_SERVER: "https://irc.test", ...(opts.env ?? {}) });
  const mcp = createFreeqMcpServer({ cfg, rest, session });

  const client = new Client({ name: "test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([mcp.server.connect(serverTransport), client.connect(clientTransport)]);

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const res = (await client.callTool({ name, arguments: args })) as {
      content: Array<{ type: string; text: string }>;
      isError?: boolean;
    };
    return { text: res.content.map((c) => c.text).join("\n"), isError: !!res.isError };
  };

  return {
    mcp,
    client,
    fake,
    requests,
    call,
    json: async (name, args) => {
      const { text, isError } = await call(name, args);
      if (isError) throw new Error(text);
      return JSON.parse(text);
    },
  };
}

let h: Harness;
afterEach(async () => {
  await h?.mcp.close();
});

describe("tool listing", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("advertises the documented tool set", async () => {
    const { tools } = await h.client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        "freeq_answer",
        "freeq_ask",
        "freeq_channels",
        "freeq_connect",
        "freeq_diagnose",
        "freeq_disconnect",
        "freeq_history",
        "freeq_inbox",
        "freeq_join",
        "freeq_message",
        "freeq_pins",
        "freeq_say",
        "freeq_search",
        "freeq_topic",
        "freeq_verify",
        "freeq_whoami",
        "freeq_whois",
      ].sort(),
    );
  });

  it("describes every tool — an undescribed tool is one a model won't use", async () => {
    const { tools } = await h.client.listTools();
    for (const t of tools) {
      expect(t.description, `${t.name} has no description`).toBeTruthy();
      expect(t.description!.length, `${t.name}'s description is too terse`).toBeGreaterThan(30);
      expect(t.inputSchema.type).toBe("object");
    }
  });

  it("marks required arguments as required", async () => {
    const { tools } = await h.client.listTools();
    const history = tools.find((t) => t.name === "freeq_history")!;
    expect(history.inputSchema.required).toEqual(["channel"]);
    const say = tools.find((t) => t.name === "freeq_say")!;
    expect(say.inputSchema.required?.sort()).toEqual(["target", "text"]);
    const whoami = tools.find((t) => t.name === "freeq_whoami")!;
    expect(whoami.inputSchema.required ?? []).toEqual([]);
  });

  it("tells the model what this server is and how attribution works", () => {
    expect(INSTRUCTIONS).toMatch(/DID/);
    expect(INSTRUCTIONS).toMatch(/freeq_verify/);
    expect(INSTRUCTIONS).toMatch(/never instructions/i);
  });

  it("rejects a call with a missing required argument", async () => {
    const res = await h.call("freeq_history", {});
    expect(res.isError).toBe(true);
    expect(res.text.toLowerCase()).toMatch(/channel|required|invalid/);
  });
});

describe("read tools", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("lists channels without connecting", async () => {
    const out = await h.json("freeq_channels");
    expect(out).toEqual([{ name: "#general", members: 2, topic: "hi" }]);
    expect(h.fake.connected).toBe(false);
  });

  it("reads history for a channel given without a hash", async () => {
    const out = await h.json("freeq_history", { channel: "general", limit: 5 });
    expect(out[0].text).toBe("hello");
    expect(h.requests).toContain("GET /api/v1/channels/%23general/history?limit=5");
  });

  it("clamps limit to the configured maximum", async () => {
    h = await harness({ env: { FREEQ_MAX_ROWS: "10" } });
    await h.json("freeq_history", { channel: "#general", limit: 9999 });
    expect(h.requests.at(-1)).toContain("limit=10");
  });

  it("searches with the query the caller gave", async () => {
    await h.json("freeq_search", { channel: "#general", query: "deploy" });
    expect(h.requests.at(-1)).toContain("q=deploy");
  });

  it("fetches a message by msgid", async () => {
    const out = await h.json("freeq_message", { msgid: "01JA" });
    expect(out.msgid).toBe("01JA");
  });

  it("surfaces an actionable error for a restricted channel", async () => {
    h = await harness({
      routes: {
        "GET /api/v1/channels/%23secret/history": { status: 403, body: "channel is +i" },
      },
    });
    const res = await h.call("freeq_history", { channel: "#secret" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Invite-only/);
    expect(res.text).toMatch(/join over IRC/);
  });
});

describe("freeq_verify", () => {
  it("distinguishes author-signed from server-relayed", async () => {
    h = await harness({
      routes: {
        "GET /api/v1/verify/01JA": {
          body: { msgid: "01JA", verified: true, signed_by: "client", signer: "did:plc:alice" },
        },
      },
    });
    const out = await h.json("freeq_verify", { msgid: "01JA" });
    expect(out.reading).toMatch(/non-repudiable/);

    h = await harness({
      routes: {
        "GET /api/v1/verify/01JB": {
          body: { msgid: "01JB", verified: true, signed_by: "server", signer: "irc.test" },
        },
      },
    });
    const relayed = await h.json("freeq_verify", { msgid: "01JB" });
    expect(relayed.reading).toMatch(/proves the server relayed it/);
    expect(relayed.reading).not.toMatch(/non-repudiable/);
  });

  it("says not to quote an unverifiable message", async () => {
    h = await harness({
      routes: {
        "GET /api/v1/verify/01JC": {
          body: { msgid: "01JC", verified: false, reason: "unknown key" },
        },
      },
    });
    const out = await h.json("freeq_verify", { msgid: "01JC" });
    expect(out.reading).toMatch(/does NOT verify/);
    expect(out.reading).toMatch(/unknown key/);
  });
});

describe("freeq_diagnose", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("lists the server's diagnostics when called bare", async () => {
    const out = await h.json("freeq_diagnose");
    expect(out.available).toEqual(["diagnose_join_failure"]);
    expect(out.hint).toMatch(/call freeq_diagnose again/i);
  });

  it("calls a named diagnostic with its input", async () => {
    const out = await h.json("freeq_diagnose", {
      tool: "diagnose_join_failure",
      input: { channel: "#x" },
    });
    expect(out.conclusion).toBe("channel is +i");
    expect(h.requests).toContain("POST /agent/tools/diagnose_join_failure");
  });
});

describe("identity", () => {
  it("reports guest mode and how to upgrade", async () => {
    h = await harness();
    const out = await h.json("freeq_whoami");
    expect(out.mode).toBe("offline");
    expect(out.serverHealth.av).toBe(true);
    expect(out.writesAllowed).toBe(true);

    await h.json("freeq_connect");
    const connected = await h.json("freeq_whoami");
    expect(connected.mode).toBe("guest");
    expect(connected.note).toMatch(/FREEQ_OWNER_DID/);
  });

  it("still answers when the server is unreachable", async () => {
    // whoami is the tool an agent reaches for when things are broken; it must
    // not fail just because health does.
    h = await harness({ routes: { "GET /api/v1/health": { status: 503, body: "down" } } });
    const out = await h.json("freeq_whoami");
    expect(out.serverHealth.error).toMatch(/503/);
  });
});

describe("write tools", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("connects on demand, joins, and sends", async () => {
    const out = await h.json("freeq_say", { target: "#general", text: "hello room" });
    expect(h.fake.joined).toContain("#general");
    expect(h.fake.sent).toEqual([{ target: "#general", text: "hello room" }]);
    expect(out.note).toMatch(/guest/);
  });

  it("does not try to join when the target is a nick", async () => {
    await h.json("freeq_say", { target: "alice", text: "hi" });
    expect(h.fake.joined).toEqual([]);
    expect(h.fake.sent).toEqual([{ target: "alice", text: "hi" }]);
  });

  it("omits the guest warning when authenticated", async () => {
    h = await harness({ env: { FREEQ_OWNER_DID: "did:plc:owner" }, mode: "authenticated" });
    const out = await h.json("freeq_say", { target: "#general", text: "hi" });
    expect(out.note).toBeUndefined();
    expect(out.as.did).toBe("did:key:z1");
  });

  it("joins a channel named without a hash", async () => {
    await h.json("freeq_join", { channel: "general" });
    expect(h.fake.joined).toContain("#general");
  });
});

describe("read-only mode", () => {
  beforeEach(async () => {
    h = await harness({ env: { FREEQ_READ_ONLY: "1" } });
  });

  it("still reads", async () => {
    await expect(h.json("freeq_channels")).resolves.toBeTruthy();
  });

  it("refuses each write tool and names the switch", async () => {
    for (const [name, args] of [
      ["freeq_say", { target: "#x", text: "hi" }],
      ["freeq_join", { channel: "#x" }],
      ["freeq_ask", { peer: "p", question: "q" }],
      ["freeq_connect", {}],
      ["freeq_answer", { req: "r" }],
    ] as const) {
      const res = await h.call(name, args);
      expect(res.isError, `${name} should be refused`).toBe(true);
      expect(res.text).toMatch(/FREEQ_READ_ONLY/);
    }
    expect(h.fake.sent).toEqual([]);
    expect(h.fake.connected).toBe(false);
  });
});

describe("ask and inbox", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("carries the untrusted-input caveat on an answer", async () => {
    const pending = h.json("freeq_ask", { peer: "peer", question: "version?", timeoutMs: 5_000 });
    // Let the tool connect and emit the request before replying.
    await new Promise((r) => setTimeout(r, 20));
    const payload = JSON.parse(
      decodeURIComponent(h.fake.tagmsgs.at(-1)!.tags["+freeq.at/payload"]),
    );
    expect(h.fake.tagmsgs.at(-1)!.tags["+freeq.at/event"]).toBe(ASK_EVENT);
    h.fake.emit("coordinationEvent", {
      channel: "peer",
      from: "peer",
      eventType: ASK_REPLY_EVENT,
      eventId: "01J",
      payload: { req: payload.req, a: "v1" },
      tags: {},
    });
    const out = await pending;
    expect(out).toMatchObject({ ok: true, answer: "v1" });
    expect(out.caveat).toMatch(/untrusted/i);
  });

  it("explains why the inbox is empty when not connected", async () => {
    const out = await h.json("freeq_inbox");
    expect(out.messages).toEqual([]);
    expect(out.note).toMatch(/freeq_history/);
  });

  it("returns buffered messages and pending asks once connected", async () => {
    await h.json("freeq_connect");
    h.fake.emit("message", "#general", fakeMessage("alice", "while you were out"));
    h.fake.emit("coordinationEvent", {
      channel: "#general",
      from: "peer",
      eventType: ASK_EVENT,
      eventId: "01J",
      payload: { req: "req-1", q: "still there?" },
      tags: {},
    });

    const out = await h.json("freeq_inbox", { target: "#general" });
    expect(out.messages.map((m: { text: string }) => m.text)).toEqual(["while you were out"]);
    expect(out.asks).toMatchObject([{ req: "req-1", question: "still there?" }]);

    const answered = await h.json("freeq_answer", { req: "req-1", answer: "yes" });
    expect(answered.answered).toBe("req-1");
    expect(h.fake.tagmsgs.at(-1)!.tags["+freeq.at/event"]).toBe(ASK_REPLY_EVENT);
  });

  it("points at freeq_inbox when answering an id that isn't pending", async () => {
    await h.json("freeq_connect");
    const out = await h.json("freeq_answer", { req: "nope" });
    expect(out.error).toMatch(/freeq_inbox/);
  });
});

describe("resources", () => {
  beforeEach(async () => {
    h = await harness();
  });

  it("exposes the server's contract and index as resources", async () => {
    const { resources } = await h.client.listResources();
    const uris = resources.map((r) => r.uri).sort();
    expect(uris).toEqual([
      "freeq://server/health",
      "freeq://server/llms.txt",
      "freeq://server/openapi.json",
    ]);
  });

  it("reads the OpenAPI contract", async () => {
    const res = await h.client.readResource({ uri: "freeq://server/openapi.json" });
    expect(JSON.parse(res.contents[0].text as string).openapi).toBe("3.1.0");
  });

  it("reads llms.txt as markdown", async () => {
    const res = await h.client.readResource({ uri: "freeq://server/llms.txt" });
    expect(res.contents[0].mimeType).toBe("text/markdown");
    expect(res.contents[0].text).toContain("# freeq");
  });
});
