import { describe, expect, it } from "vitest";
import { formatRead, parseRoomArgs, runRoomCli, ROOM_USAGE } from "./cli.js";
import { loadConfig } from "./config.js";
import { FakeRooms, fakeMessage, fakeRest, fakeSession } from "./fakes.js";
import type { ToolContext } from "./tools.js";

const ROOM = "#r-quiet-copper-fox";
const URL = "https://irc.test/r/r-quiet-copper-fox#tok";

describe("parseRoomArgs", () => {
  it("parses each subcommand", () => {
    expect(parseRoomArgs(["create"])).toEqual({ kind: "create", topic: undefined });
    expect(parseRoomArgs(["create", "--topic", "deploy plan"])).toEqual({ kind: "create", topic: "deploy plan" });
    expect(parseRoomArgs(["create", "--topic=x"])).toEqual({ kind: "create", topic: "x" });
    expect(parseRoomArgs(["join", URL])).toEqual({ kind: "join", url: URL });
    expect(parseRoomArgs(["say", ROOM, "hello", "there"])).toEqual({ kind: "say", target: ROOM, text: "hello there" });
    expect(parseRoomArgs(["read", URL, "--wait", "30", "--history", "--limit", "5"])).toEqual({
      kind: "read",
      target: URL,
      waitSecs: 30,
      history: true,
      limit: 5,
    });
    expect(parseRoomArgs(["read", ROOM])).toEqual({ kind: "read", target: ROOM, waitSecs: undefined, history: false, limit: undefined });
    expect(parseRoomArgs(["who", ROOM])).toEqual({ kind: "who", target: ROOM });
    expect(parseRoomArgs(["invite", ROOM, "--ttl", "600", "--max-uses", "1"])).toEqual({
      kind: "invite",
      target: ROOM,
      ttlSecs: 600,
      maxUses: 1,
    });
    expect(parseRoomArgs(["keep", ROOM])).toEqual({ kind: "keep", target: ROOM });
  });

  it("treats no command, help and -h as help", () => {
    expect(parseRoomArgs([])).toEqual({ kind: "help" });
    expect(parseRoomArgs(["help"])).toEqual({ kind: "help" });
    expect(parseRoomArgs(["-h"])).toEqual({ kind: "help" });
  });

  it("keeps message text after -- and text that looks like a flag", () => {
    expect(parseRoomArgs(["say", ROOM, "--", "--not-a-flag", "ok"])).toEqual({
      kind: "say",
      target: ROOM,
      text: "--not-a-flag ok",
    });
  });

  it("rejects missing arguments and unknown options with a reason", () => {
    expect(() => parseRoomArgs(["join"])).toThrow(/missing room URL/);
    expect(() => parseRoomArgs(["say", ROOM])).toThrow(/missing message text/);
    expect(() => parseRoomArgs(["read", ROOM, "--wait"])).toThrow(/--wait needs a value/);
    expect(() => parseRoomArgs(["read", ROOM, "--wait", "soon"])).toThrow(/positive integer/);
    expect(() => parseRoomArgs(["keep", ROOM, "--topic", "x"])).toThrow(/unknown option --topic/);
    expect(() => parseRoomArgs(["explode"])).toThrow(/unknown room command: explode/);
  });

  it("documents every subcommand in the usage text", () => {
    for (const cmd of ["create", "join", "say", "read", "who", "invite", "keep"]) {
      expect(ROOM_USAGE).toMatch(new RegExp(`^\\s+${cmd}\\b`, "m"));
    }
  });
});

describe("formatRead", () => {
  it("prints one line per message with the DID when known", () => {
    const out = formatRead({
      channel: ROOM,
      ready: true,
      messages: [
        { from: "alice", did: "did:key:za", text: "hi", at: 0 },
        { from: "bob", text: "two\nlines", at: 1_000 },
      ],
    });
    expect(out.split("\n")).toEqual([
      "[1970-01-01T00:00:00.000Z] <alice (did:key:za)> hi",
      "[1970-01-01T00:00:01.000Z] <bob> two",
      "    lines",
    ]);
  });

  it("says when the room is not readable yet", () => {
    expect(formatRead({ channel: ROOM, ready: false, messages: [], note: "no key" })).toMatch(/not ready — no key/);
  });
});

function cliContext(opts: { readOnly?: boolean } = {}) {
  const rest = fakeRest({});
  const rooms = new FakeRooms();
  const env = { FREEQ_SERVER: "https://irc.test", ...(opts.readOnly ? { FREEQ_READ_ONLY: "1" } : {}) };
  const { client, session } = fakeSession(env, "authenticated", (t) => rest.setBearerToken(t), { rooms });
  const ctx: ToolContext = { cfg: loadConfig(env), rest, session };
  const stdout: string[] = [];
  const stderr: string[] = [];
  const io = { stdout: (t: string) => stdout.push(t), stderr: (t: string) => stderr.push(t), context: () => ctx };
  return { ctx, rooms, client, session, stdout, stderr, io };
}

describe("runRoomCli", () => {
  it("prints usage and exits 1 on a bad invocation, without connecting", async () => {
    const h = cliContext();
    expect(await runRoomCli(["join"], h.io)).toBe(1);
    expect(h.stderr.join("")).toMatch(/missing room URL/);
    expect(h.stderr.join("")).toMatch(/usage: freeq-mcp room/);
    expect(h.client.connected).toBe(false);
  });

  it("prints help to stdout and exits 0", async () => {
    const h = cliContext();
    expect(await runRoomCli(["help"], h.io)).toBe(0);
    expect(h.stdout.join("")).toContain("usage: freeq-mcp room");
  });

  it("create: prints JSON with the share URL, then disconnects", async () => {
    const h = cliContext();
    expect(await runRoomCli(["create", "--topic", "t"], h.io)).toBe(0);
    const out = JSON.parse(h.stdout.join(""));
    expect(out.channel).toBe(ROOM);
    expect(out.share).toContain(out.url);
    expect(h.session.connected).toBe(false);
  });

  it("join: reports readiness as JSON", async () => {
    const h = cliContext();
    h.rooms.sealable.add(ROOM);
    expect(await runRoomCli(["join", URL], h.io)).toBe(0);
    expect(JSON.parse(h.stdout.join(""))).toMatchObject({ channel: ROOM, ready: true });
  });

  it("say: joins from the URL, then sends", async () => {
    const h = cliContext();
    h.rooms.sealable.add(ROOM);
    expect(await runRoomCli(["say", URL, "hello", "room"], h.io)).toBe(0);
    expect(h.client.joinKeys).toEqual([{ channel: ROOM, key: "tok" }]);
    expect(h.client.sent).toEqual([{ target: ROOM, text: "hello room" }]);
  });

  it("say: exits 1 with a retry hint when no key has been sealed", async () => {
    const h = cliContext();
    expect(await runRoomCli(["say", URL, "hello"], h.io)).toBe(1);
    expect(h.stderr.join("")).toMatch(/no room key/);
    expect(h.client.sent).toEqual([]);
  });

  it("read: prints plain lines, replaying history when asked", async () => {
    const h = cliContext();
    h.rooms.keys.add(ROOM);
    h.client.history.set(ROOM, [
      fakeMessage("alice", "earlier", { encrypted: true, timestamp: new Date(0), tags: { msgid: "01A" } }),
    ]);
    expect(await runRoomCli(["read", ROOM, "--history"], h.io)).toBe(0);
    expect(h.stdout.join("")).toBe("[1970-01-01T00:00:00.000Z] <alice> earlier\n");
  });

  it("who / keep: JSON from the room manager", async () => {
    const h = cliContext();
    h.rooms.infos.set(ROOM, {
      channel: ROOM,
      topic: null,
      founder_did: "did:key:z1",
      created_at: 1,
      last_activity: 1,
      expires_at: 1,
      latest_epoch: 1,
      members: [],
    });
    expect(await runRoomCli(["who", ROOM], h.io)).toBe(0);
    expect(JSON.parse(h.stdout.join(""))).toMatchObject({ channel: ROOM, founder: true });
    h.stdout.length = 0;
    expect(await runRoomCli(["keep", ROOM], h.io)).toBe(0);
    expect(JSON.parse(h.stdout.join("")).expires_at).toBe(1_900_000_000);
  });

  it("reports a tool error on stderr and exits 1", async () => {
    const h = cliContext({ readOnly: true });
    expect(await runRoomCli(["create"], h.io)).toBe(1);
    expect(h.stderr.join("")).toMatch(/FREEQ_READ_ONLY/);
  });
});
