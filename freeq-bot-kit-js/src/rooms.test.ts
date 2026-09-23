/**
 * RoomManager against a fake server (REST) and a fake client (IRC), with
 * real crypto: the bot's did:key, its X25519 pair, EG1/EGK1 sealing.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodeMultibaseEd25519,
  generateDidKey,
  openSealed,
  sealedFromWire,
  verifyEd25519,
  type ChannelCipher,
  type FreeqClient,
} from "@freeq/sdk";
import { loadOrCreateIdentity, type AgentIdentity } from "./identity.js";
import { RoomManager, parseRoomUrl, roomUrl, verifyBundleBinding } from "./rooms.js";

const ORIGIN = "https://rooms.test";

// ── Fake server ───────────────────────────────────────────────────────

interface Call { method: string; path: string; body: unknown }

class FakeServer {
  bundles = new Map<string, Record<string, unknown>>();
  /** channel → rows */
  groupkeys = new Map<string, Array<{ did: string; epoch: number; sealed: string }>>();
  rooms = new Map<string, { founder_did: string; members: Map<string, number>; expires_at: number; topic: string | null }>();
  bearers = new Map<string, string>(); // bearer → did
  calls: Call[] = [];
  removed: string[] = [];
  #n = 0;

  session(did: string): string {
    const b = `sid-${did.slice(-8)}-${++this.#n}`;
    this.bearers.set(b, did);
    return b;
  }

  admit(channel: string, did: string): void {
    const room = this.rooms.get(channel.toLowerCase());
    if (room && !room.members.has(did)) room.members.set(did, Date.now() / 1000);
  }

  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    this.calls.push({ method, path: url.pathname, body });
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? "";
    const caller = this.bearers.get(auth.replace(/^Bearer /, "")) ?? null;
    const json = (status: number, v: unknown): Response =>
      new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
    const seg = url.pathname.split("/").map(decodeURIComponent);

    // Pre-key bundles
    if (url.pathname === "/api/v1/keys" && method === "POST") {
      if (!caller || caller !== body.did) return json(401, { error: "Bearer session required" });
      this.bundles.set(body.did, body.bundle);
      return json(200, { ok: true });
    }
    if (seg[3] === "keys" && seg.length === 5 && method === "GET") {
      const b = this.bundles.get(seg[4]);
      return b ? json(200, { bundle: b }) : json(404, { error: "no bundle" });
    }

    if (!caller) return json(401, { error: "Bearer session required" });

    // Rooms
    if (url.pathname === "/api/v1/rooms" && method === "POST") {
      const channel = `#r-fake-room-${++this.#n}`;
      const expires_at = 1_800_000_000;
      this.rooms.set(channel, { founder_did: caller, members: new Map([[caller, 1]]), expires_at, topic: body?.topic ?? null });
      return json(201, {
        channel, invite: `tok${this.#n}`, url: `${ORIGIN}/r/${channel.slice(1)}#tok${this.#n}`,
        invite_expires_at: expires_at, room: { channel, founder_did: caller, created_at: 1, expires_at },
      });
    }
    if (seg[3] === "rooms" && seg.length >= 5) {
      const channel = seg[4].toLowerCase();
      const room = this.rooms.get(channel);
      if (!room) return json(404, { error: "no such room" });
      if (seg.length === 5 && method === "GET") {
        if (!room.members.has(caller)) return json(403, { error: "not a member" });
        const rows = this.groupkeys.get(channel) ?? [];
        const latest = rows.reduce<number | null>((m, r) => (m === null || r.epoch > m ? r.epoch : m), null);
        return json(200, {
          channel, topic: room.topic, founder_did: room.founder_did, created_at: 1, last_activity: 2,
          expires_at: room.expires_at, latest_epoch: latest,
          members: [...room.members.entries()].map(([did, joined_at]) => ({
            did, joined_at, online: true,
            epochs: [...new Set(rows.filter((r) => r.did === did).map((r) => r.epoch))].sort(),
          })),
        });
      }
      if (seg[5] === "keep" && method === "POST") {
        room.expires_at += 1000;
        return json(200, { expires_at: room.expires_at });
      }
      if (seg[5] === "members" && seg.length === 7 && method === "DELETE") {
        if (room.founder_did !== caller) return json(403, { error: "founder only" });
        room.members.delete(seg[6]);
        this.removed.push(seg[6]);
        return json(200, { removed: seg[6] });
      }
    }

    // Group keys
    if (seg[3] === "channels" && seg[5] === "groupkeys") {
      const channel = seg[4].toLowerCase();
      const room = this.rooms.get(channel);
      if (!room) return json(404, { error: "Unknown channel" });
      const rows = this.groupkeys.get(channel) ?? [];
      if (method === "GET") {
        return json(200, {
          channel,
          keys: rows.filter((r) => r.did === caller).map((r) => ({ epoch: r.epoch, sealed: r.sealed })),
        });
      }
      if (method === "POST") {
        const latest = rows.reduce((m, r) => Math.max(m, r.epoch), 0);
        if (body.epoch > latest && room.founder_did !== caller) return json(403, { error: "founder only for a new epoch" });
        if (!room.members.has(caller)) return json(403, { error: "not on the roster" });
        const skipped: string[] = [];
        let stored = 0;
        for (const [did, sealed] of Object.entries(body.keys as Record<string, string>)) {
          if (!room.members.has(did)) { skipped.push(did); continue; }
          rows.push({ did, epoch: body.epoch, sealed });
          stored++;
        }
        this.groupkeys.set(channel, rows);
        return json(200, { ok: true, epoch: body.epoch, stored, skipped });
      }
    }
    return json(404, { error: `unrouted ${method} ${url.pathname}` });
  };
}

// ── Fake client ───────────────────────────────────────────────────────

class FakeClient extends EventEmitter {
  nick = "bot";
  apiBearer: string | null = null;
  joinedChannels = new Set<string>();
  ciphers = new Map<string, ChannelCipher>();
  sent: string[] = [];
  constructor(private server: FakeServer, private did: string) { super(); }
  get serverOrigin(): string { return ORIGIN; }
  join(channel: string, key?: string): void {
    this.sent.push(key ? `JOIN ${channel} ${key}` : `JOIN ${channel}`);
    setTimeout(() => {
      const room = this.server.rooms.get(channel.toLowerCase());
      const ok = room && (room.members.has(this.did) || (key && key.startsWith("tok")));
      if (!ok) {
        this.emit("joinRejected", channel, "473", "Cannot join room (invite required)");
        return;
      }
      this.server.admit(channel, this.did);
      this.joinedChannels.add(channel.toLowerCase());
      this.emit("channelJoined", channel);
    }, 0);
  }
  setChannelCipher(ch: string, c: ChannelCipher | null): void {
    if (c) this.ciphers.set(ch.toLowerCase(), c); else this.ciphers.delete(ch.toLowerCase());
  }
  getChannelCipher(ch: string): ChannelCipher | null { return this.ciphers.get(ch.toLowerCase()) ?? null; }
  asClient(): FreeqClient { return this as unknown as FreeqClient; }
}

// ── Harness ───────────────────────────────────────────────────────────

let root: string;
let server: FakeServer;
const logs: string[] = [];

interface Actor { identity: AgentIdentity; client: FakeClient; rooms: RoomManager; dir: string }

async function actor(name: string, opts: { bearer?: boolean } = {}): Promise<Actor> {
  const dir = join(root, name);
  const identity = await loadOrCreateIdentity({ seedPath: join(dir, "agent.key") });
  const client = new FakeClient(server, identity.did);
  client.nick = name;
  if (opts.bearer !== false) client.apiBearer = server.session(identity.did);
  const rooms = new RoomManager({
    client: client.asClient(), identity, stateDir: dir, origin: ORIGIN,
    fetch: server.fetch, log: (m) => logs.push(m), timeoutMs: 2000,
  });
  return { identity, client, rooms, dir };
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "freeq-rooms-"));
  server = new FakeServer();
  logs.length = 0;
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
const toUrl = (s: string): string => Buffer.from(s, "base64").toString("base64url");

// ── Tests ─────────────────────────────────────────────────────────────

describe("parseRoomUrl / roomUrl", () => {
  it("parses the share URL and keeps the token out of the path", () => {
    expect(parseRoomUrl("https://irc.freeq.at/r/r-quiet-copper-fox#Xk3abc")).toEqual({
      origin: "https://irc.freeq.at", channel: "#r-quiet-copper-fox", token: "Xk3abc",
    });
    expect(parseRoomUrl("  https://irc.freeq.at/r/R-Quiet-Copper-Fox/  ")).toEqual({
      origin: "https://irc.freeq.at", channel: "#r-quiet-copper-fox", token: null,
    });
    expect(parseRoomUrl("http://localhost:8080/?room=r-a-b-c#t")).toEqual({
      origin: "http://localhost:8080", channel: "#r-a-b-c", token: "t",
    });
  });

  it("rejects everything that is not a room URL", () => {
    expect(parseRoomUrl("https://irc.freeq.at/join/r-a-b-c#t")).toBeNull();
    expect(parseRoomUrl("https://irc.freeq.at/r/")).toBeNull();
    expect(parseRoomUrl("https://irc.freeq.at/r/a%20b#t")).toBeNull();
    expect(parseRoomUrl("ftp://irc.freeq.at/r/r-a-b-c#t")).toBeNull();
    expect(parseRoomUrl("#r-a-b-c")).toBeNull();
    expect(parseRoomUrl("")).toBeNull();
  });

  it("roomUrl round-trips through parseRoomUrl", () => {
    const url = roomUrl("https://irc.freeq.at/", "#r-a-b-c", "T0k_en-1");
    expect(url).toBe("https://irc.freeq.at/r/r-a-b-c#T0k_en-1");
    expect(parseRoomUrl(url)).toEqual({ origin: "https://irc.freeq.at", channel: "#r-a-b-c", token: "T0k_en-1" });
  });
});

describe("X25519 identity + pre-key bundle", () => {
  it("publishes a bundle bound to the did:key, persists the pair at 0600, and is idempotent", async () => {
    const a = await actor("alpha");
    await a.rooms.ensurePreKeyPublished();
    await a.rooms.ensurePreKeyPublished();
    expect(server.calls.filter((c) => c.path === "/api/v1/keys")).toHaveLength(1);

    const bundle = server.bundles.get(a.identity.did)!;
    expect(bundle).toBeDefined();
    expect(Object.keys(bundle).sort()).toEqual(
      ["did", "identity_key", "signed_pre_key", "spk_id", "spk_signature", "signing_key"].sort(),
    );
    expect(bundle.did).toBe(a.identity.did);
    expect(bundle.spk_id).toBe(1);
    expect(unb64(bundle.identity_key as string)).toHaveLength(32);
    expect(bundle.signed_pre_key).toBe(bundle.identity_key);
    const didPub = decodeMultibaseEd25519(a.identity.did.slice("did:key:".length));
    expect(b64(didPub)).toBe(bundle.signing_key);
    expect(
      await verifyEd25519(didPub, unb64(bundle.signed_pre_key as string), toUrl(bundle.spk_signature as string)),
    ).toBe(true);

    const keyFile = join(a.dir, "x25519.json");
    const st = await stat(keyFile);
    if (process.platform !== "win32") expect(st.mode & 0o777).toBe(0o600);
    const saved = JSON.parse(await readFile(keyFile, "utf8"));
    expect(b64(unb64(saved.publicKey))).toBe(bundle.identity_key);
    expect(unb64(saved.secret)).toHaveLength(32);

    // A later process reuses the same pair.
    const again = new RoomManager({
      client: a.client.asClient(), identity: a.identity, stateDir: a.dir, origin: ORIGIN, fetch: server.fetch,
    });
    await again.ensurePreKeyPublished();
    expect(server.bundles.get(a.identity.did)!.identity_key).toBe(bundle.identity_key);
  });

  it("waits (bounded) for the API bearer", async () => {
    const a = await actor("beta", { bearer: false });
    const p = a.rooms.ensurePreKeyPublished();
    setTimeout(() => { a.client.apiBearer = server.session(a.identity.did); }, 100);
    await p;
    expect(server.bundles.has(a.identity.did)).toBe(true);

    const c = await actor("gamma", { bearer: false });
    const fast = new RoomManager({
      client: c.client.asClient(), identity: c.identity, stateDir: c.dir, origin: ORIGIN, fetch: server.fetch, timeoutMs: 100,
    });
    await expect(fast.ensurePreKeyPublished()).rejects.toThrow(/no API bearer/);
  });
});

describe("verifyBundleBinding", () => {
  it("accepts a bundle the did:key signed and rejects tampered ones", async () => {
    const a = await actor("delta");
    await a.rooms.ensurePreKeyPublished();
    const good = server.bundles.get(a.identity.did)! as { signing_key: string; spk_signature: string; signed_pre_key: string };
    expect(await verifyBundleBinding(a.identity.did, good)).toEqual({ ok: true });

    // Someone else's signing key with a valid signature by that key.
    const other = await generateDidKey();
    const spk = unb64(good.signed_pre_key);
    const otherSig = Buffer.from(await other.signer(spk), "base64url").toString("base64");
    const swapped = { ...good, signing_key: b64(decodeMultibaseEd25519(other.publicKeyMultibase)), spk_signature: otherSig };
    const r1 = await verifyBundleBinding(a.identity.did, swapped);
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.reason).toMatch(/signing_key is not the did:key/);

    // Right key, but the pre-key was replaced after signing.
    const replaced = { ...good, signed_pre_key: b64(new Uint8Array(32).fill(7)) };
    const r2 = await verifyBundleBinding(a.identity.did, replaced);
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toMatch(/does not verify/);

    // No signing key at all.
    const { signing_key: _drop, ...bare } = good;
    void _drop;
    const r3 = await verifyBundleBinding(a.identity.did, bare);
    expect(r3.ok).toBe(false);

    // did:plc: accepted as published (the documented limitation).
    expect(await verifyBundleBinding("did:plc:abc", bare)).toEqual({ ok: true });
  });
});

describe("create / join / loadKeys", () => {
  it("create() mints, joins, seals epoch 1 to itself, installs the cipher and persists", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create({ topic: "quarterly", inviteTtlSecs: 60 });

    expect(made.channel).toMatch(/^#r-fake-room-/);
    expect(made.url).toBe(`${ORIGIN}/r/${made.channel.slice(1)}#${made.invite}`);
    expect(made.expiresAt).toBe(1_800_000_000);

    const mint = server.calls.find((c) => c.path === "/api/v1/rooms")!;
    expect(mint.body).toEqual({ topic: "quarterly", invite_ttl_secs: 60 });
    expect(a.client.sent).toEqual([`JOIN ${made.channel}`]);

    const post = server.calls.find((c) => c.method === "POST" && c.path.endsWith("/groupkeys"))!;
    expect((post.body as { epoch: number }).epoch).toBe(1);
    expect(Object.keys((post.body as { keys: object }).keys)).toEqual([a.identity.did]);
    // Sealed to our own X25519 pair: we can open it back.
    const wire = (post.body as { keys: Record<string, string> }).keys[a.identity.did];
    const saved = JSON.parse(await readFile(join(a.dir, "x25519.json"), "utf8"));
    const opened = await openSealed(sealedFromWire(wire)!, { secret: unb64(saved.secret), publicKey: unb64(saved.publicKey) });
    expect(opened?.epoch).toBe(1);

    expect(a.rooms.isRoom(made.channel)).toBe(true);
    expect(a.rooms.channels()).toEqual([made.channel]);
    const cipher = a.client.getChannelCipher(made.channel)!;
    const ct = await cipher.encrypt("hello");
    expect(ct?.startsWith("EG1:1:")).toBe(true);
    expect(await cipher.decrypt(ct!)).toBe("hello");

    const file = join(a.dir, "rooms", `${made.channel.slice(1)}.json`);
    const st = await stat(file);
    if (process.platform !== "win32") expect(st.mode & 0o777).toBe(0o600);
    const persisted = JSON.parse(await readFile(file, "utf8"));
    expect(persisted.channel).toBe(made.channel);
    expect(Object.keys(persisted.epochs)).toEqual(["1"]);
    expect(b64(opened!.secret)).toBe(persisted.epochs["1"]);

    // A fresh process reads the room without any network.
    const before = server.calls.length;
    const client2 = new FakeClient(server, a.identity.did);
    const fresh = new RoomManager({ client: client2.asClient(), identity: a.identity, stateDir: a.dir, origin: ORIGIN, fetch: server.fetch });
    expect(fresh.isRoom(made.channel)).toBe(true);
    expect(await client2.getChannelCipher(made.channel)!.decrypt(ct!)).toBe("hello");
    expect(server.calls.length).toBe(before);
  });

  it("join() sends the token as the channel key, is not ready until a steward seals, then reads", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();

    const b = await actor("joiner");
    const joined = await b.rooms.join(made.url);
    expect(joined).toEqual({ channel: made.channel, ready: false });
    expect(b.client.sent).toEqual([`JOIN ${made.channel} ${made.invite}`]);
    // Published before joining, so a steward can seal on our JOIN.
    const keysIdx = server.calls.findIndex((c) => c.path === "/api/v1/keys" && c.body && (c.body as { did: string }).did === b.identity.did);
    const getIdx = server.calls.findIndex((c) => c.method === "GET" && c.path.endsWith("/groupkeys") && c.path.includes(made.channel.slice(1)));
    expect(keysIdx).toBeGreaterThanOrEqual(0);
    expect(getIdx).toBeGreaterThan(keysIdx);
    expect(b.rooms.isRoom(made.channel)).toBe(false);

    // The founder's steward pass seals epoch 1 to the joiner.
    const pass = await a.rooms.stewardPass(made.channel);
    expect(pass).toEqual({ sealed: [b.identity.did], skipped: [] });

    expect(await b.rooms.loadKeys(made.channel)).toBe(true);
    expect(b.rooms.isRoom(made.channel)).toBe(true);
    const ct = await a.client.getChannelCipher(made.channel)!.encrypt("from the founder");
    expect(await b.client.getChannelCipher(made.channel)!.decrypt(ct!)).toBe("from the founder");
    // ...and the joiner persisted it for next time.
    const persisted = JSON.parse(await readFile(join(b.dir, "rooms", `${made.channel.slice(1)}.json`), "utf8"));
    expect(Object.keys(persisted.epochs)).toEqual(["1"]);
  });

  it("join() rejects with the server's reason", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    const b = await actor("stranger");
    await expect(b.rooms.join(`${ORIGIN}/r/${made.channel.slice(1)}#bogus`)).rejects.toThrow(
      /cannot join .*invite required\) \(473\)/,
    );
    await expect(b.rooms.join("not a url")).rejects.toThrow(/not a room URL/);
  });

  it("join() on a room we are already in just loads keys", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    a.client.sent.length = 0;
    const r = await a.rooms.join(made.url);
    expect(r).toEqual({ channel: made.channel, ready: true });
    expect(a.client.sent).toEqual([]);
  });
});

describe("stewardPass", () => {
  it("seals every held epoch to members lacking the latest, verifies bindings, reports skips", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    await a.rooms.rotate(made.channel); // epochs 1 and 2 held by the founder

    const good = await actor("good");
    await good.rooms.join(made.url);
    const bad = await actor("bad");
    await bad.rooms.join(made.url);
    // Tamper: swap in a signing key that is not bad's did:key.
    const other = await generateDidKey();
    const badBundle = server.bundles.get(bad.identity.did)!;
    server.bundles.set(bad.identity.did, { ...badBundle, signing_key: b64(decodeMultibaseEd25519(other.publicKeyMultibase)) });
    // A member who never published a bundle.
    const silent = await actor("silent");
    server.admit(made.channel, silent.identity.did);

    server.calls.length = 0;
    const pass = await a.rooms.stewardPass(made.channel);
    expect(pass.sealed).toEqual([good.identity.did]);
    expect(pass.skipped).toEqual([
      { did: bad.identity.did, reason: "bundle signing_key is not the did:key's key" },
      { did: silent.identity.did, reason: "no pre-key bundle published" },
    ]);

    // Both epochs sealed to `good`, so it can read history and live traffic.
    const posts = server.calls.filter((c) => c.method === "POST" && c.path.endsWith("/groupkeys"));
    expect(posts.map((p) => (p.body as { epoch: number }).epoch)).toEqual([1, 2]);
    for (const p of posts) expect(Object.keys((p.body as { keys: object }).keys)).toEqual([good.identity.did]);
    expect(await good.rooms.loadKeys(made.channel)).toBe(true);
    for (const epoch of [1, 2]) {
      const ct = await a.client.getChannelCipher(made.channel)!.encrypt(`e${epoch}`);
      void ct;
    }
    const info = await a.rooms.info(made.channel);
    expect(info.members.find((m) => m.did === good.identity.did)?.epochs).toEqual([1, 2]);

    // Nothing left to do: a second pass is a no-op for `good`.
    const again = await a.rooms.stewardPass(made.channel);
    expect(again.sealed).toEqual([]);
  });

  it("a founder whose room has no epoch yet creates epoch 1", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    // Pretend the server lost the keys (or create() died before posting).
    server.groupkeys.delete(made.channel);
    const b = await actor("joiner");
    await b.rooms.join(made.url);

    const pass = await a.rooms.stewardPass(made.channel);
    expect(pass.sealed).toEqual([b.identity.did]);
    expect((await a.rooms.info(made.channel)).latest_epoch).toBe(1);
  });

  it("a member without the latest epoch does not hand out stale keys", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    const b = await actor("member");
    await b.rooms.join(made.url);
    await a.rooms.stewardPass(made.channel);
    await b.rooms.loadKeys(made.channel);
    await a.rooms.rotate(made.channel); // b now lacks epoch 2 (rotate seals to b too, but b has not loaded)
    const c = await actor("late");
    await c.rooms.join(made.url);

    const pass = await b.rooms.stewardPass(made.channel);
    expect(pass.sealed).toEqual([]);
    expect(pass.skipped).toEqual([{ did: c.identity.did, reason: "we do not hold epoch 2" }]);
  });

  it("runs automatically (debounced) when someone joins a room we can read", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    const b = await actor("joiner");
    await b.rooms.join(made.url);

    server.calls.length = 0;
    a.client.emit("memberJoined", made.channel, { nick: "joiner" });
    a.client.emit("memberJoined", made.channel, { nick: "joiner" });
    a.client.emit("memberJoined", made.channel, { nick: "founder" }); // ourselves: ignored
    a.client.emit("memberJoined", "#unrelated", { nick: "joiner" }); // not a room: ignored
    await new Promise((r) => setTimeout(r, 900));

    const posts = server.calls.filter((c) => c.method === "POST" && c.path.endsWith("/groupkeys"));
    expect(posts).toHaveLength(1);
    expect(Object.keys((posts[0].body as { keys: object }).keys)).toEqual([b.identity.did]);
    expect(await b.rooms.loadKeys(made.channel)).toBe(true);
  });

  it("a failing automatic pass is logged, not thrown", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    server.rooms.delete(made.channel);
    a.client.emit("memberJoined", made.channel, { nick: "x" });
    await new Promise((r) => setTimeout(r, 700));
    expect(logs.some((l) => /steward pass for .* failed/.test(l))).toBe(true);
  });
});

describe("rotate / removeMember / keep / info", () => {
  it("rotate() seals the next epoch to the whole roster and updates the cipher", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    const b = await actor("member");
    await b.rooms.join(made.url);
    await a.rooms.stewardPass(made.channel);
    await b.rooms.loadKeys(made.channel);

    expect(await a.rooms.rotate(made.channel)).toBe(2);
    const post = server.calls.filter((c) => c.method === "POST" && c.path.endsWith("/groupkeys")).at(-1)!;
    expect((post.body as { epoch: number }).epoch).toBe(2);
    expect(Object.keys((post.body as { keys: object }).keys).sort()).toEqual([a.identity.did, b.identity.did].sort());

    const ct = await a.client.getChannelCipher(made.channel)!.encrypt("new epoch");
    expect(ct?.startsWith("EG1:2:")).toBe(true);
    // b has not loaded epoch 2 yet: cannot read; after loading: can, and still reads epoch 1.
    expect(await b.client.getChannelCipher(made.channel)!.decrypt(ct!)).toBeNull();
    expect(await b.rooms.loadKeys(made.channel)).toBe(true);
    expect(await b.client.getChannelCipher(made.channel)!.decrypt(ct!)).toBe("new epoch");
    const persisted = JSON.parse(await readFile(join(b.dir, "rooms", `${made.channel.slice(1)}.json`), "utf8"));
    expect(Object.keys(persisted.epochs)).toEqual(["1", "2"]);
  });

  it("removeMember() deletes from the roster then rotates without them", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    const b = await actor("member");
    await b.rooms.join(made.url);
    await a.rooms.stewardPass(made.channel);

    await a.rooms.removeMember(made.channel, b.identity.did);
    expect(server.removed).toEqual([b.identity.did]);
    const del = server.calls.find((c) => c.method === "DELETE")!;
    expect(del.path).toBe(`/api/v1/rooms/${encodeURIComponent(made.channel)}/members/${encodeURIComponent(b.identity.did)}`);
    const post = server.calls.filter((c) => c.method === "POST" && c.path.endsWith("/groupkeys")).at(-1)!;
    expect((post.body as { epoch: number }).epoch).toBe(2);
    expect(Object.keys((post.body as { keys: object }).keys)).toEqual([a.identity.did]);
  });

  it("keep() and info()", async () => {
    const a = await actor("founder");
    const made = await a.rooms.create();
    expect(await a.rooms.keep(made.channel)).toBe(1_800_001_000);
    const info = await a.rooms.info(made.channel);
    expect(info.channel).toBe(made.channel);
    expect(info.founder_did).toBe(a.identity.did);
    expect(info.latest_epoch).toBe(1);
    expect(info.members).toEqual([{ did: a.identity.did, joined_at: 1, online: true, epochs: [1] }]);
  });

  it("surfaces the server's error text", async () => {
    const a = await actor("founder");
    await expect(a.rooms.info("#r-nope")).rejects.toThrow(/GET \/api\/v1\/rooms\/%23r-nope: no such room/);
  });
});
