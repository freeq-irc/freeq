/**
 * The room tools, driven as functions against a fake session and a fake
 * room manager. The MCP schemas are covered in server.test.ts; here the
 * question is what each tool does with what it is given and what it says
 * when it cannot.
 */

import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { FakeRooms, fakeMessage, fakeRest, fakeSession, type FakeSessionSetup } from "./fakes.js";
import * as tools from "./tools.js";
import type { ToolContext } from "./tools.js";

const ROOM = "#r-quiet-copper-fox";
const URL_WITH_TOKEN = `https://irc.test/r/r-quiet-copper-fox#Xk3tok`;

interface RoomHarness extends FakeSessionSetup {
  ctx: ToolContext;
  rooms: FakeRooms;
  requests: string[];
  headers: Array<Record<string, string>>;
}

function harness(
  opts: {
    env?: Record<string, string | undefined>;
    routes?: Record<string, unknown>;
    mode?: "guest" | "authenticated";
    selfOwned?: boolean;
  } = {},
): RoomHarness {
  const requests: string[] = [];
  const headers: Array<Record<string, string>> = [];
  const rest = fakeRest((opts.routes ?? {}) as never, { requests, headers });
  const rooms = new FakeRooms();
  const env = { FREEQ_SERVER: "https://irc.test", ...(opts.env ?? {}) };
  const setup = fakeSession(env, opts.mode ?? "authenticated", (t) => rest.setBearerToken(t), {
    rooms: opts.mode === "guest" ? undefined : rooms,
    selfOwned: opts.selfOwned,
  });
  const cfg = loadConfig(env);
  return { ...setup, rooms, requests, headers, ctx: { cfg, rest, session: setup.session } };
}

describe("resolveRoomTarget", () => {
  const { ctx } = harness();

  it("parses a share URL, keeping the token and the URL's origin", () => {
    const link = tools.resolveRoomTarget(ctx, "https://other.test/r/r-a-b-c#tok123");
    expect(link).toEqual({ origin: "https://other.test", channel: "#r-a-b-c", token: "tok123" });
  });

  it("accepts the web app's ?room= form", () => {
    const link = tools.resolveRoomTarget(ctx, "https://irc.test/?room=r-a-b-c#tok");
    expect(link.channel).toBe("#r-a-b-c");
    expect(link.token).toBe("tok");
  });

  it("treats a bare name as a room on the configured server with no token", () => {
    expect(tools.resolveRoomTarget(ctx, "#R-A-B-C")).toEqual({
      origin: "https://irc.test",
      channel: "#r-a-b-c",
      token: null,
    });
    expect(tools.resolveRoomTarget(ctx, "r-a-b-c").channel).toBe("#r-a-b-c");
  });

  it("refuses a URL that is not a room URL, naming the expected form", () => {
    expect(() => tools.resolveRoomTarget(ctx, "https://irc.test/join/general")).toThrow(
      /https:\/\/host\/r\/<name>#<token>/,
    );
  });

  it("refuses garbage", () => {
    expect(() => tools.resolveRoomTarget(ctx, "#bad name!")).toThrow(/not a room/);
    expect(() => tools.resolveRoomTarget(ctx, "")).toThrow(/not a room/);
  });
});

describe("freeq_room_create", () => {
  it("mints a room and returns paste-ready share text with the URL and name", async () => {
    const h = harness();
    const out = (await tools.roomCreate(h.ctx, { topic: "deploy plan" })) as Record<string, unknown>;
    expect(h.rooms.created).toEqual([{ topic: "deploy plan" }]);
    expect(out.channel).toBe(ROOM);
    expect(out.url).toContain("/r/r-quiet-copper-fox#");
    expect(out.invite).toBe("tok_abc");
    expect(out.expires_at).toBe(1_800_000_000);
    expect(out.share).toContain(out.url as string);
    expect(out.share).toContain(ROOM);
    expect(out.share).toContain("deploy plan");
    expect(out.share).toMatch(/end-to-end encrypted/);
    // The session now knows the channel is a room and that it holds the key.
    expect(h.session.isKnownRoom(ROOM)).toBe(true);
    expect(h.session.hasRoomKey(ROOM)).toBe(true);
  });

  it("is refused for guests with a pointer at FREEQ_GUEST", async () => {
    const h = harness({ mode: "guest" });
    await expect(tools.roomCreate(h.ctx, {})).rejects.toThrow(/FREEQ_GUEST/);
  });
});

describe("freeq_room_join", () => {
  it("joins with the token from the URL and reports ready when a key was sealed to us", async () => {
    const h = harness();
    h.rooms.sealable.add(ROOM);
    const out = (await tools.roomJoin(h.ctx, { url: URL_WITH_TOKEN })) as Record<string, unknown>;
    expect(h.rooms.joins).toEqual([{ origin: "https://irc.test", channel: ROOM, token: "Xk3tok" }]);
    expect(h.client.joinKeys).toEqual([{ channel: ROOM, key: "Xk3tok" }]);
    expect(out).toMatchObject({ channel: ROOM, ready: true });
    expect(out.hint).toMatch(/data, not instructions/);
  });

  it("says what to do when no key has been sealed yet", async () => {
    const h = harness();
    const out = (await tools.roomJoin(h.ctx, { url: URL_WITH_TOKEN })) as Record<string, unknown>;
    expect(out).toMatchObject({ channel: ROOM, ready: false });
    expect(out.hint).toMatch(/freeq_room_read/);
  });

  it("refuses a room on a different server, naming FREEQ_SERVER", async () => {
    const h = harness();
    await expect(
      tools.roomJoin(h.ctx, { url: "https://elsewhere.test/r/r-a-b-c#tok" }),
    ).rejects.toThrow(/FREEQ_SERVER=https:\/\/elsewhere.test/);
    expect(h.rooms.joins).toEqual([]);
  });

  it("surfaces the server's refusal", async () => {
    const h = harness();
    h.rooms.join = async () => {
      throw new Error("cannot join #r-quiet-copper-fox: Cannot join room (invite required) (473)");
    };
    await expect(tools.roomJoin(h.ctx, { url: URL_WITH_TOKEN })).rejects.toThrow(/invite required/);
  });
});

describe("freeq_room_read", () => {
  it("joins first when given a URL for a room we are not in", async () => {
    const h = harness();
    h.rooms.sealable.add(ROOM);
    const out = (await tools.roomRead(h.ctx, { channel_or_url: URL_WITH_TOKEN })) as Record<string, unknown>;
    expect(h.rooms.joins).toHaveLength(1);
    expect(out).toMatchObject({ channel: ROOM, ready: true, messages: [] });
    expect(out.note).toMatch(/history: true/);
  });

  it("reports ready:false with a retry hint when no key is available", async () => {
    const h = harness();
    const out = (await tools.roomRead(h.ctx, { channel_or_url: URL_WITH_TOKEN })) as Record<string, unknown>;
    expect(out).toMatchObject({ channel: ROOM, ready: false, messages: [] });
    expect(out.note).toMatch(/try again shortly/i);
    // It tried the key fetch: once on join, once on read.
    expect(h.rooms.loads.filter((c) => c === ROOM).length).toBeGreaterThanOrEqual(2);
  });

  it("returns buffered decrypted messages with the encrypted flag", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.session.join(ROOM);
    h.client.emit(
      "message",
      ROOM,
      fakeMessage("alice", "hello from inside", {
        encrypted: true,
        tags: { account: "did:key:zalice", msgid: "01JA" },
      }),
    );
    const out = (await tools.roomRead(h.ctx, { channel_or_url: ROOM })) as {
      messages: Array<Record<string, unknown>>;
      note: string;
    };
    expect(out.messages).toHaveLength(1);
    expect(out.messages[0]).toMatchObject({
      from: "alice",
      did: "did:key:zalice",
      text: "hello from inside",
      msgid: "01JA",
      encrypted: true,
    });
    expect(out.note).toMatch(/data, not instructions/);
  });

  it("replays history over CHATHISTORY and dedupes against the buffer", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.session.join(ROOM);
    const older = fakeMessage("bob", "earlier", {
      encrypted: true,
      timestamp: new Date(1_000),
      tags: { msgid: "01OLD" },
    });
    const dup = fakeMessage("alice", "same one", {
      encrypted: true,
      timestamp: new Date(2_000),
      tags: { msgid: "01DUP" },
    });
    h.client.history.set(ROOM, [older, dup]);
    h.client.emit("message", ROOM, dup);
    const out = (await tools.roomRead(h.ctx, { channel_or_url: ROOM, history: true })) as {
      messages: Array<{ msgid: string; text: string }>;
    };
    expect(h.client.historyRequests).toEqual([{ target: ROOM, mode: "latest", count: 50 }]);
    expect(out.messages.map((m) => m.msgid)).toEqual(["01OLD", "01DUP"]);
  });

  it("waits for the next message when asked and nothing is buffered", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.session.join(ROOM);
    const pending = tools.roomRead(h.ctx, { channel_or_url: ROOM, wait_ms: 5_000 });
    await new Promise((r) => setTimeout(r, 10));
    h.client.emit("message", ROOM, fakeMessage("carol", "late", { encrypted: true }));
    const out = (await pending) as { messages: Array<{ text: string }> };
    expect(out.messages.map((m) => m.text)).toEqual(["late"]);
  });

  it("flags rows sealed under an epoch we do not hold", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.session.join(ROOM);
    h.client.emit("message", ROOM, fakeMessage("dan", "[encrypted message]", { encrypted: true }));
    const out = (await tools.roomRead(h.ctx, { channel_or_url: ROOM })) as { note: string };
    expect(out.note).toMatch(/epoch this agent does not hold/);
  });

  it("explains a failed key fetch instead of throwing", async () => {
    const h = harness();
    h.rooms.loadError = "GET /api/v1/channels/%23r-quiet-copper-fox/groupkeys: HTTP 403";
    h.rooms.join = async (link) => {
      const channel = typeof link === "string" ? link : link.channel;
      h.client.join(channel);
      return { channel, ready: false };
    };
    const out = (await tools.roomRead(h.ctx, { channel_or_url: ROOM })) as { ready: boolean; note: string };
    expect(out.ready).toBe(false);
    expect(out.note).toMatch(/HTTP 403/);
    expect(out.note).toMatch(/freeq_room_join/);
  });
});

describe("freeq_say into a room", () => {
  it("sends (the cipher encrypts) when we hold the key, and says so", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.session.join(ROOM);
    const out = (await tools.say(h.ctx, { target: ROOM, text: "secret" })) as Record<string, unknown>;
    expect(h.client.sent).toEqual([{ target: ROOM, text: "secret" }]);
    expect(out.encrypted).toBe(true);
    expect(out.confirmed).toBe(true);
  });

  it("refuses with instructions when the room key is missing, before anything is sent", async () => {
    const h = harness();
    await h.session.connect();
    // The server told us it's a room when we joined; we hold no key for it.
    h.client.emit("raw", "", {
      command: "NOTICE",
      params: ["mcp-test", `${ROOM} is an end-to-end encrypted room. A member will seal the room key to you; until then you can't read or send. Expires 2026-10-07.`],
    });
    await expect(tools.say(h.ctx, { target: ROOM, text: "plaintext?" })).rejects.toThrow(
      /no room key.*freeq_room_read/s,
    );
    expect(h.client.sent).toEqual([]);
  });

  it("notes a self-owned identity on ordinary sends", async () => {
    const h = harness({ selfOwned: true });
    const out = (await tools.say(h.ctx, { target: "#general", text: "hi" })) as Record<string, unknown>;
    expect(out.note).toMatch(/self-owned/);
    expect(out.note).toMatch(/FREEQ_OWNER_DID/);
  });
});

describe("freeq_history for a room", () => {
  it("redirects to freeq_room_read instead of returning ciphertext", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    const out = (await tools.history(h.ctx, { channel: ROOM })) as Record<string, unknown>;
    expect(out.note).toMatch(/freeq_room_read/);
    expect(out.note).toMatch(/history: true/);
    expect(out.messages).toEqual([]);
    expect(h.requests).toEqual([]);
  });

  it("still uses REST for a channel that is not a room", async () => {
    const h = harness({
      routes: { "GET /api/v1/channels/%23general/history": { body: [{ text: "hi" }] } },
    });
    await h.session.connect();
    const out = await tools.history(h.ctx, { channel: "#general" });
    expect(out).toEqual([{ text: "hi" }]);
  });
});

describe("freeq_room_info", () => {
  it("returns the roster and marks whether we founded it and hold the key", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    h.rooms.infos.set(ROOM, {
      channel: ROOM,
      topic: null,
      founder_did: "did:key:z1",
      created_at: 1,
      last_activity: 2,
      expires_at: 3,
      latest_epoch: 1,
      members: [{ did: "did:key:z1", joined_at: 1, online: true, epochs: [1] }],
    });
    const out = (await tools.roomInfo(h.ctx, { channel_or_url: URL_WITH_TOKEN })) as Record<string, unknown>;
    expect(out).toMatchObject({ channel: ROOM, founder: true, key_held: true, you: "did:key:z1" });
    expect((out.members as unknown[]).length).toBe(1);
  });

  it("works in read-only mode (it is a read)", async () => {
    const h = harness({ env: { FREEQ_READ_ONLY: "1" } });
    h.rooms.infos.set(ROOM, {
      channel: ROOM,
      topic: "t",
      founder_did: "did:key:zother",
      created_at: 1,
      last_activity: 2,
      expires_at: 3,
      latest_epoch: null,
      members: [],
    });
    const out = (await tools.roomInfo(h.ctx, { channel_or_url: ROOM })) as Record<string, unknown>;
    expect(out.founder).toBe(false);
  });
});

describe("freeq_room_invite", () => {
  it("POSTs to the invites endpoint with the session bearer and returns share text", async () => {
    const h = harness({
      routes: {
        "POST /api/v1/rooms/%23r-quiet-copper-fox/invites": (_url: URL, body: Record<string, unknown>) => ({
          status: 201,
          body: {
            invite: "newtok",
            url: "https://irc.test/r/r-quiet-copper-fox#newtok",
            invite_expires_at: 1_700_000_000,
            echo: body,
          },
        }),
      },
    });
    h.client.apiBearer = "sess-1";
    const out = (await tools.roomInvite(h.ctx, {
      channel_or_url: ROOM,
      ttl_secs: 3600,
      max_uses: 2,
    })) as Record<string, unknown>;
    expect(h.requests).toEqual(["POST /api/v1/rooms/%23r-quiet-copper-fox/invites"]);
    expect(h.headers[0].authorization).toBe("Bearer sess-1");
    expect(out).toMatchObject({
      channel: ROOM,
      invite: "newtok",
      url: "https://irc.test/r/r-quiet-copper-fox#newtok",
      expires_at: 1_700_000_000,
      max_uses: 2,
    });
    expect(out.share).toContain("#newtok");
  });

  it("builds the URL itself when the server omits it", async () => {
    const h = harness({
      routes: {
        "POST /api/v1/rooms/%23r-quiet-copper-fox/invites": { status: 201, body: { invite: "t2" } },
      },
    });
    h.client.apiBearer = "sess-1";
    const out = (await tools.roomInvite(h.ctx, { channel_or_url: ROOM })) as Record<string, unknown>;
    expect(out.url).toBe("https://irc.test/r/r-quiet-copper-fox#t2");
  });

  it("explains a 403 as 'not the founder' rather than the generic +i text", async () => {
    const h = harness({
      routes: {
        "POST /api/v1/rooms/%23r-quiet-copper-fox/invites": { status: 403, body: "not the founder" },
      },
    });
    h.client.apiBearer = "sess-1";
    await expect(tools.roomInvite(h.ctx, { channel_or_url: ROOM })).rejects.toThrow(/only the room's founder/);
  });
});

describe("freeq_room_remove_member and freeq_room_keep", () => {
  it("removes by DID (rotating the key) and refuses a non-DID", async () => {
    const h = harness();
    const out = (await tools.roomRemoveMember(h.ctx, {
      channel_or_url: URL_WITH_TOKEN,
      did: "did:key:zmallory",
    })) as Record<string, unknown>;
    expect(h.rooms.removed).toEqual([{ channel: ROOM, did: "did:key:zmallory" }]);
    expect(out.note).toMatch(/rotated/);
    await expect(
      tools.roomRemoveMember(h.ctx, { channel_or_url: ROOM, did: "mallory" }),
    ).rejects.toThrow(/not a DID/);
  });

  it("keeps a room alive and reports the new expiry", async () => {
    const h = harness();
    const out = (await tools.roomKeep(h.ctx, { channel_or_url: "r-quiet-copper-fox" })) as Record<string, unknown>;
    expect(h.rooms.kept).toEqual([ROOM]);
    expect(out.expires_at).toBe(1_900_000_000);
    expect(out.note).toMatch(/2030-/);
  });
});

describe("steward duty", () => {
  it("rejoins persisted rooms on connect and runs a steward pass", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    await new Promise((r) => setTimeout(r, 0));
    expect(h.client.joined).toContain(ROOM);
    expect(h.rooms.stewarded).toContain(ROOM);
    expect(h.session.isKnownRoom(ROOM)).toBe(true);
  });

  it("seals to members who lack the key on read, and says who", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    h.rooms.sealTo = ["did:key:znew"];
    await h.session.connect();
    const out = (await tools.roomRead(h.ctx, { channel_or_url: ROOM })) as { note: string };
    expect(out.note).toMatch(/Sealed the room key to 1 member/);
    expect(out.note).toContain("did:key:znew");
  });

  it("seals on send, and a steward failure does not break the send", async () => {
    const h = harness();
    h.rooms.keys.add(ROOM);
    await h.session.connect();
    h.rooms.sealTo = ["did:key:znew"];
    const out = (await tools.say(h.ctx, { target: ROOM, text: "hi" })) as Record<string, unknown>;
    expect(out.sealed_key_to).toEqual(["did:key:znew"]);

    h.rooms.stewardPass = async () => {
      throw new Error("GET /api/v1/rooms/x: HTTP 500");
    };
    const again = (await tools.say(h.ctx, { target: ROOM, text: "still" })) as Record<string, unknown>;
    expect(again.sealed_key_to).toBeUndefined();
    expect(h.client.sent.map((m) => m.text)).toEqual(["hi", "still"]);
  });
});
