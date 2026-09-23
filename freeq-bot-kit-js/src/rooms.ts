// Instant rooms for bots — see docs/INSTANT-ROOMS.md.
//
// A room is a `+i +E` channel minted by `POST /api/v1/rooms`, entered with the
// invite token from its share URL (`https://host/r/<name>#<token>`), and read
// through the EG1/EGK1 group scheme: a random secret per epoch, sealed to each
// member's X25519 pre-key and stored server-blind at
// `/api/v1/channels/{ch}/groupkeys`. `RoomManager` owns the bot's side of
// that: its X25519 identity, its published pre-key bundle, the epochs it has
// opened (persisted, so a fresh process reads without waiting for a steward),
// the `ChannelCipher` it installs on the client, and steward duty — sealing
// the current epoch to members who lack it.
//
// Nothing here logs a token or a secret.

import {
  createGroup,
  decodeMultibaseEd25519,
  makeGroupCipher,
  openSealed,
  rotate as rotateGroup,
  sealFor,
  sealedFromWire,
  sealedToWire,
  verifyEd25519,
  type FreeqClient,
  type GroupState,
  type X25519Secret,
} from "@freeq/sdk";
import type { webcrypto } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AgentIdentity } from "./identity.js";

// ── Share URLs ──────────────────────────────────────────────────────────

export interface RoomLink {
  /** `https://host` — the freeq server the room lives on. */
  origin: string;
  /** `#r-word-word-word` — the channel, with its `#`. */
  channel: string;
  /** The invite token from the URL fragment, or null when the URL had none. */
  token: string | null;
}

/**
 * Parse a room share URL: `https://host/r/<name>#<token>`. The web app's
 * `https://host/?room=<name>#<token>` form is accepted too. Returns null for
 * anything else.
 */
export function parseRoomUrl(s: string): RoomLink | null {
  let u: URL;
  try {
    u = new URL(s.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  let name: string | null = null;
  const m = u.pathname.match(/^\/r\/([^/]+)\/?$/);
  if (m) name = decodeURIComponent(m[1]);
  else if (u.searchParams.has("room")) name = u.searchParams.get("room");
  if (!name) return null;
  name = name.replace(/^#/, "");
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return null;
  const frag = u.hash.replace(/^#/, "");
  return {
    origin: `${u.protocol}//${u.host}`,
    channel: `#${name.toLowerCase()}`,
    token: frag.length > 0 ? frag : null,
  };
}

/** Build a share URL. The token rides the fragment so it never reaches a server log. */
export function roomUrl(origin: string, channel: string, token: string): string {
  const name = channel.replace(/^#/, "");
  return `${origin.replace(/\/+$/, "")}/r/${encodeURIComponent(name)}#${token}`;
}

// ── Server shapes ───────────────────────────────────────────────────────

export interface RoomMember {
  did: string;
  joined_at: number;
  online: boolean;
  /** Epochs this member already holds a sealed key for. */
  epochs: number[];
}

export interface RoomInfo {
  channel: string;
  topic: string | null;
  founder_did: string;
  created_at: number;
  last_activity: number;
  expires_at: number;
  latest_epoch: number | null;
  members: RoomMember[];
}

interface PreKeyBundle {
  did?: string;
  identity_key: string;
  signed_pre_key: string;
  spk_signature: string;
  spk_id?: number;
  signing_key?: string;
}

interface X25519Pair {
  secret: Uint8Array;
  publicKey: Uint8Array;
}

// ── Manager ─────────────────────────────────────────────────────────────

export interface RoomManagerOptions {
  client: FreeqClient;
  identity: AgentIdentity;
  /** The bot's state dir: `x25519.json` and `rooms/` live under it. */
  stateDir: string;
  /** Server origin for REST, e.g. `https://irc.freeq.at`. */
  origin: string;
  /** Injectable for tests. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Where warnings go (steward failures, unreadable state files). Default `console.warn`. */
  log?: (message: string) => void;
  /** Upper bound on waiting for a JOIN to be answered or the API bearer to arrive. Default 15 s. */
  timeoutMs?: number;
}

const STEWARD_DEBOUNCE_MS = 500;

export class RoomManager {
  readonly #client: FreeqClient;
  readonly #identity: AgentIdentity;
  readonly #stateDir: string;
  readonly #origin: string;
  readonly #fetch: typeof fetch;
  readonly #log: (message: string) => void;
  readonly #timeoutMs: number;

  /** channel (lowercase) → epoch → secret. */
  readonly #epochs = new Map<string, Map<number, Uint8Array>>();
  #x25519: Promise<X25519Pair> | null = null;
  #preKeyPublished: Promise<void> | null = null;
  readonly #stewardTimers = new Map<string, ReturnType<typeof setTimeout>>();

  constructor(opts: RoomManagerOptions) {
    this.#client = opts.client;
    this.#identity = opts.identity;
    this.#stateDir = opts.stateDir;
    this.#origin = opts.origin.replace(/\/+$/, "");
    this.#fetch = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#log = opts.log ?? ((m) => console.warn(m));
    this.#timeoutMs = opts.timeoutMs ?? 15_000;

    this.#loadPersistedRooms();
    for (const ch of this.#epochs.keys()) this.#installCipher(ch);

    // Steward duty: a newcomer in a room we can read gets the key from us.
    this.#client.on("memberJoined", (channel, member) => {
      if (!channel || !this.isRoom(channel)) return;
      if (member.nick && member.nick.toLowerCase() === this.#client.nick.toLowerCase()) return;
      this.#scheduleStewardPass(channel);
    });
  }

  // ── Public surface ────────────────────────────────────────────────────

  /** Rooms this manager holds at least one epoch for (lowercase channels). */
  channels(): string[] {
    return [...this.#epochs.keys()];
  }

  /** True when we hold a group key for this channel. */
  isRoom(channel: string): boolean {
    return this.#epochs.has(channel.toLowerCase());
  }

  /**
   * Publish our X25519 pre-key bundle under our DID so a steward can seal a
   * room key to us. `signing_key` is the bot's did:key Ed25519 public key and
   * `spk_signature` is made with it, which is what lets another member verify
   * the bundle belongs to the DID. Idempotent per process.
   */
  ensurePreKeyPublished(): Promise<void> {
    if (!this.#preKeyPublished) {
      this.#preKeyPublished = this.#publishPreKey().catch((err) => {
        this.#preKeyPublished = null; // let a later call retry
        throw err;
      });
    }
    return this.#preKeyPublished;
  }

  /** Mint a room, join it, create epoch 1 sealed to ourselves, and install the cipher. */
  async create(opts: { topic?: string; inviteTtlSecs?: number } = {}): Promise<{
    channel: string;
    invite: string;
    url: string;
    expiresAt: number;
  }> {
    await this.ensurePreKeyPublished();
    const body: Record<string, unknown> = {};
    if (opts.topic !== undefined) body.topic = opts.topic;
    if (opts.inviteTtlSecs !== undefined) body.invite_ttl_secs = opts.inviteTtlSecs;
    const res = (await this.#api("POST", "/api/v1/rooms", body)) as {
      channel: string;
      invite: string;
      url?: string;
      invite_expires_at?: number;
      room?: { expires_at?: number };
    };
    const channel = res.channel.toLowerCase();

    await this.#joinAndWait(channel, undefined);

    const state = createGroup(channel);
    await this.#postEpoch(channel, state, [[this.#identity.did, (await this.#keys()).publicKey]]);
    await this.#adopt(state);

    return {
      channel,
      invite: res.invite,
      url: res.url ?? roomUrl(this.#origin, channel, res.invite),
      expiresAt: res.room?.expires_at ?? 0,
    };
  }

  /**
   * Join a room from its share URL (or a parsed link). Resolves once the
   * server admitted us and we tried to load keys; `ready: false` means no
   * member has sealed the key to us yet — call `loadKeys()` again later.
   * Rejects with the server's reason when the JOIN is refused.
   */
  async join(link: RoomLink | string): Promise<{ channel: string; ready: boolean }> {
    const parsed = typeof link === "string" ? parseRoomUrl(link) : link;
    if (!parsed) throw new Error("not a room URL (expected https://host/r/<name>#<token>)");
    const channel = parsed.channel.toLowerCase();
    // Publish before joining: the steward's pass fires on our JOIN and needs
    // our bundle to already be there.
    await this.ensurePreKeyPublished();
    await this.#joinAndWait(channel, parsed.token ?? undefined);
    const ready = await this.loadKeys(channel);
    return { channel, ready };
  }

  /**
   * Fetch the group keys sealed to us, open every one we can, merge them into
   * what we hold, persist, and install the cipher. Returns whether we hold
   * the newest epoch the server has for us.
   */
  async loadKeys(channel: string): Promise<boolean> {
    const ch = channel.toLowerCase();
    const res = (await this.#api("GET", `/api/v1/channels/${encodeURIComponent(ch)}/groupkeys`)) as {
      keys?: Array<{ epoch: number; sealed: string }>;
    };
    const keys = res.keys ?? [];
    const secret = await this.#secret();
    let latest: number | null = null;
    let opened = false;
    for (const { epoch, sealed } of keys) {
      if (latest === null || epoch > latest) latest = epoch;
      if (this.#epochs.get(ch)?.has(epoch)) continue;
      const parsed = sealedFromWire(sealed);
      if (!parsed) continue;
      const state = await openSealed(parsed, secret);
      if (!state) continue;
      this.#remember(ch, state.epoch, state.secret);
      opened = true;
    }
    if (opened) await this.#persist(ch);
    if (this.#epochs.has(ch)) this.#installCipher(ch);
    if (latest === null) return false;
    return this.#epochs.get(ch)?.has(latest) ?? false;
  }

  /**
   * Steward pass: seal every epoch we hold to roster members who lack the
   * latest one, after checking that each member's pre-key bundle belongs to
   * their DID (mandatory for `did:key`; `did:plc` bundles are accepted as
   * published). If the room has no epoch yet and we founded it, create epoch 1.
   */
  async stewardPass(channel: string): Promise<{
    sealed: string[];
    skipped: Array<{ did: string; reason: string }>;
  }> {
    const ch = channel.toLowerCase();
    const info = await this.info(ch);
    const sealed: string[] = [];
    const skipped: Array<{ did: string; reason: string }> = [];

    let latest = info.latest_epoch;
    if (latest === null) {
      if (info.founder_did !== this.#identity.did) return { sealed, skipped };
      const state = createGroup(ch);
      await this.#postEpoch(ch, state, [[this.#identity.did, (await this.#keys()).publicKey]]);
      await this.#adopt(state);
      latest = 1;
    }

    const held = this.#states(ch);
    if (!held.some((s) => s.epoch === latest)) {
      // Not holding the current key: nothing we seal would let anyone read
      // current traffic. Say so rather than hand out stale epochs.
      for (const m of info.members) {
        if (m.did !== this.#identity.did && !m.epochs.includes(latest)) {
          skipped.push({ did: m.did, reason: `we do not hold epoch ${latest}` });
        }
      }
      return { sealed, skipped };
    }

    // epoch → { did → EGK1 wire }
    const batches = new Map<number, Record<string, string>>();
    for (const member of info.members) {
      if (member.did === this.#identity.did) continue;
      if (member.epochs.includes(latest)) continue;
      const missing = held.filter((s) => !member.epochs.includes(s.epoch));
      if (missing.length === 0) continue;

      const pub = await this.#memberIdentityKey(member.did);
      if (!pub.ok) {
        skipped.push({ did: member.did, reason: pub.reason });
        continue;
      }
      for (const state of missing) {
        const wire = sealedToWire(await sealFor(state, pub.key));
        let batch = batches.get(state.epoch);
        if (!batch) {
          batch = {};
          batches.set(state.epoch, batch);
        }
        batch[member.did] = wire;
      }
      sealed.push(member.did);
    }

    for (const [epoch, keys] of [...batches.entries()].sort((a, b) => a[0] - b[0])) {
      const res = (await this.#api("POST", `/api/v1/channels/${encodeURIComponent(ch)}/groupkeys`, {
        epoch,
        keys,
      })) as { skipped?: unknown };
      for (const did of serverSkipped(res.skipped)) {
        if (!skipped.some((s) => s.did === did)) skipped.push({ did, reason: "not on the roster" });
      }
    }
    return { sealed, skipped };
  }

  /** Founder / DID-op: mint the next epoch and seal it to the whole roster. Returns the new epoch. */
  async rotate(channel: string): Promise<number> {
    const ch = channel.toLowerCase();
    const held = this.#states(ch);
    if (held.length === 0) throw new Error(`no group key held for ${ch}; load keys first`);
    const current = held.reduce((a, b) => (b.epoch > a.epoch ? b : a));
    const next = rotateGroup(current);

    const info = await this.info(ch);
    const targets: Array<[string, Uint8Array]> = [];
    const me = await this.#keys();
    for (const member of info.members) {
      if (member.did === this.#identity.did) {
        targets.push([member.did, me.publicKey]);
        continue;
      }
      const pub = await this.#memberIdentityKey(member.did);
      if (!pub.ok) {
        this.#log(`[rooms] rotate ${ch}: not sealing epoch ${next.epoch} to ${member.did}: ${pub.reason}`);
        continue;
      }
      targets.push([member.did, pub.key]);
    }
    if (!targets.some(([did]) => did === this.#identity.did)) {
      targets.push([this.#identity.did, me.publicKey]);
    }
    await this.#postEpoch(ch, next, targets);
    await this.#adopt(next);
    return next.epoch;
  }

  /** Founder / DID-op: remove a member from the roster (server bans + kicks), then rotate. */
  async removeMember(channel: string, did: string): Promise<void> {
    const ch = channel.toLowerCase();
    await this.#api(
      "DELETE",
      `/api/v1/rooms/${encodeURIComponent(ch)}/members/${encodeURIComponent(did)}`,
    );
    await this.rotate(ch);
  }

  /** Push the room's expiry out by the idle TTL. Returns the new `expires_at`. */
  async keep(channel: string): Promise<number> {
    const ch = channel.toLowerCase();
    const res = (await this.#api("POST", `/api/v1/rooms/${encodeURIComponent(ch)}/keep`, {})) as {
      expires_at: number;
    };
    return res.expires_at;
  }

  /** The room's metadata and roster, as the server sees it. */
  async info(channel: string): Promise<RoomInfo> {
    const ch = channel.toLowerCase();
    const res = (await this.#api("GET", `/api/v1/rooms/${encodeURIComponent(ch)}`)) as RoomInfo;
    return {
      ...res,
      latest_epoch: res.latest_epoch ?? null,
      members: (res.members ?? []).map((m) => ({ ...m, epochs: m.epochs ?? [] })),
    };
  }

  // ── Steward scheduling ────────────────────────────────────────────────

  #scheduleStewardPass(channel: string): void {
    const ch = channel.toLowerCase();
    const prior = this.#stewardTimers.get(ch);
    if (prior) clearTimeout(prior);
    const timer = setTimeout(() => {
      this.#stewardTimers.delete(ch);
      this.stewardPass(ch).catch((err) => {
        this.#log(`[rooms] steward pass for ${ch} failed: ${errorMessage(err)}`);
      });
    }, STEWARD_DEBOUNCE_MS);
    // Never keep the process alive just for a pending pass.
    (timer as { unref?: () => void }).unref?.();
    this.#stewardTimers.set(ch, timer);
  }

  // ── Keys and bundles ──────────────────────────────────────────────────

  async #publishPreKey(): Promise<void> {
    const keys = await this.#keys();
    const bearer = await this.#bearer();
    const spk = keys.publicKey;
    const sigB64Url = await this.#identity.didKey.signer(spk);
    const signingKey = decodeMultibaseEd25519(this.#identity.did.slice("did:key:".length));
    const bundle = {
      did: this.#identity.did,
      identity_key: b64(keys.publicKey),
      signed_pre_key: b64(spk),
      spk_signature: b64(unb64url(sigB64Url)),
      spk_id: 1,
      signing_key: b64(signingKey),
    };
    const resp = await this.#fetch(`${this.#origin}/api/v1/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ did: this.#identity.did, bundle }),
    });
    if (!resp.ok) {
      throw new Error(`pre-key bundle upload refused: HTTP ${resp.status}`);
    }
  }

  /** A member's X25519 identity key, after checking the bundle belongs to them. */
  async #memberIdentityKey(
    did: string,
  ): Promise<{ ok: true; key: Uint8Array } | { ok: false; reason: string }> {
    let bundle: PreKeyBundle | null;
    try {
      bundle = await this.#fetchBundle(did);
    } catch (err) {
      return { ok: false, reason: `pre-key bundle fetch failed: ${errorMessage(err)}` };
    }
    if (!bundle) return { ok: false, reason: "no pre-key bundle published" };
    let identityKey: Uint8Array;
    let spk: Uint8Array;
    try {
      identityKey = unb64(bundle.identity_key);
      spk = unb64(bundle.signed_pre_key);
    } catch {
      return { ok: false, reason: "malformed pre-key bundle" };
    }
    if (identityKey.length !== 32 || spk.length !== 32) {
      return { ok: false, reason: "malformed pre-key bundle" };
    }
    const check = await verifyBundleBinding(did, bundle, spk);
    if (!check.ok) return check;
    return { ok: true, key: identityKey };
  }

  async #fetchBundle(did: string): Promise<PreKeyBundle | null> {
    const resp = await this.#fetch(`${this.#origin}/api/v1/keys/${encodeURIComponent(did)}`);
    if (resp.status === 404) return null;
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = (await resp.json()) as { bundle?: PreKeyBundle };
    return data.bundle ?? null;
  }

  #keys(): Promise<X25519Pair> {
    if (!this.#x25519) {
      this.#x25519 = loadOrCreateX25519(join(this.#stateDir, "x25519.json")).catch((err) => {
        this.#x25519 = null;
        throw err;
      });
    }
    return this.#x25519;
  }

  async #secret(): Promise<X25519Secret> {
    const k = await this.#keys();
    return { secret: k.secret, publicKey: k.publicKey };
  }

  // ── Epoch bookkeeping ─────────────────────────────────────────────────

  #states(channel: string): GroupState[] {
    const m = this.#epochs.get(channel.toLowerCase());
    if (!m) return [];
    return [...m.entries()].map(([epoch, secret]) => ({ channel: channel.toLowerCase(), epoch, secret }));
  }

  #remember(channel: string, epoch: number, secret: Uint8Array): void {
    let m = this.#epochs.get(channel);
    if (!m) {
      m = new Map();
      this.#epochs.set(channel, m);
    }
    m.set(epoch, secret);
  }

  /** Remember a state we minted or opened, persist it, and make sure the cipher is installed. */
  async #adopt(state: GroupState): Promise<void> {
    this.#remember(state.channel, state.epoch, state.secret);
    await this.#persist(state.channel);
    this.#installCipher(state.channel);
  }

  #installCipher(channel: string): void {
    const ch = channel.toLowerCase();
    if (this.#client.getChannelCipher(ch)) return; // the getter already sees new epochs
    this.#client.setChannelCipher(ch, makeGroupCipher(() => this.#states(ch)));
  }

  async #postEpoch(
    channel: string,
    state: GroupState,
    members: Array<[string, Uint8Array]>,
  ): Promise<void> {
    const keys: Record<string, string> = {};
    for (const [did, pub] of members) keys[did] = sealedToWire(await sealFor(state, pub));
    await this.#api("POST", `/api/v1/channels/${encodeURIComponent(channel)}/groupkeys`, {
      epoch: state.epoch,
      keys,
    });
  }

  // ── Persistence: <stateDir>/rooms/<name>.json, mode 0600 ──────────────

  #roomFile(channel: string): string {
    const name = channel.toLowerCase().replace(/^#/, "");
    const safe = name.replace(/[^A-Za-z0-9_.-]/g, (c) => `%${c.charCodeAt(0).toString(16)}`);
    return join(this.#stateDir, "rooms", `${safe}.json`);
  }

  async #persist(channel: string): Promise<void> {
    const ch = channel.toLowerCase();
    const m = this.#epochs.get(ch);
    if (!m) return;
    const epochs: Record<string, string> = {};
    for (const [epoch, secret] of [...m.entries()].sort((a, b) => a[0] - b[0])) {
      epochs[String(epoch)] = b64(secret);
    }
    const path = this.#roomFile(ch);
    await mkdir(join(this.#stateDir, "rooms"), { recursive: true, mode: 0o700 });
    await writeFile(path, JSON.stringify({ channel: ch, epochs }, null, 2) + "\n", { mode: 0o600 });
    await chmod(path, 0o600);
  }

  #loadPersistedRooms(): void {
    const dir = join(this.#stateDir, "rooms");
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(readFileSync(join(dir, entry), "utf8")) as {
          channel?: string;
          epochs?: Record<string, string>;
        };
        if (!raw.channel || !raw.epochs) continue;
        const ch = raw.channel.toLowerCase();
        for (const [k, v] of Object.entries(raw.epochs)) {
          const epoch = Number(k);
          if (!Number.isInteger(epoch) || epoch < 1) continue;
          const secret = unb64(v);
          if (secret.length !== 32) continue;
          this.#remember(ch, epoch, secret);
        }
      } catch {
        this.#log(`[rooms] ignoring unreadable room state file ${entry}`);
      }
    }
  }

  // ── IRC + REST plumbing ───────────────────────────────────────────────

  /** Send JOIN (with the invite token as the key) and wait for the answer. */
  async #joinAndWait(channel: string, token: string | undefined): Promise<void> {
    const ch = channel.toLowerCase();
    if (this.#client.joinedChannels.has(ch)) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`timed out waiting to join ${ch}`));
      }, this.#timeoutMs);
      const onJoined = (joined: string): void => {
        if (joined.toLowerCase() !== ch) return;
        cleanup();
        resolve();
      };
      const onRejected = (rejected: string, numeric: string, reason: string): void => {
        if (rejected.toLowerCase() !== ch) return;
        cleanup();
        reject(new Error(`cannot join ${ch}: ${reason} (${numeric})`));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.#client.off("channelJoined", onJoined);
        this.#client.off("joinRejected", onRejected);
      };
      this.#client.on("channelJoined", onJoined);
      this.#client.on("joinRejected", onRejected);
      this.#client.join(ch, token);
    });
  }

  /** The IRC session id the server handed out as `API-BEARER`; waits (bounded) for it. */
  async #bearer(): Promise<string> {
    const deadline = Date.now() + this.#timeoutMs;
    for (;;) {
      const b = this.#client.apiBearer;
      if (b) return b;
      if (Date.now() >= deadline) {
        throw new Error("no API bearer: the client is not authenticated (SASL did:key login required)");
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  async #api(method: "GET" | "POST" | "DELETE", path: string, body?: unknown): Promise<unknown> {
    const bearer = await this.#bearer();
    const headers: Record<string, string> = { Authorization: `Bearer ${bearer}` };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const resp = await this.#fetch(`${this.#origin}${path}`, init);
    let data: unknown = null;
    try {
      data = await resp.json();
    } catch {
      data = null;
    }
    if (!resp.ok) {
      const msg =
        data && typeof data === "object" && typeof (data as { error?: unknown }).error === "string"
          ? (data as { error: string }).error
          : `HTTP ${resp.status}`;
      throw new Error(`${method} ${path}: ${msg}`);
    }
    return data ?? {};
  }
}

// ── Bundle ↔ DID binding ────────────────────────────────────────────────

/**
 * Does this pre-key bundle belong to `did`? For `did:key` the answer is
 * checkable: the bundle's `signing_key` must be the DID's Ed25519 key and
 * `spk_signature` must verify over `signed_pre_key` with it. A `did:plc`
 * bundle is accepted as published (the web client cannot bind one — the
 * documented limitation) unless it is outright malformed.
 */
export async function verifyBundleBinding(
  did: string,
  bundle: { signing_key?: string; spk_signature: string; signed_pre_key: string },
  spkBytes?: Uint8Array,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let spk: Uint8Array;
  try {
    spk = spkBytes ?? unb64(bundle.signed_pre_key);
  } catch {
    return { ok: false, reason: "malformed pre-key bundle" };
  }
  if (!did.startsWith("did:key:")) {
    if (typeof bundle.spk_signature !== "string" || typeof bundle.signed_pre_key !== "string") {
      return { ok: false, reason: "malformed pre-key bundle" };
    }
    return { ok: true };
  }
  let didPub: Uint8Array;
  try {
    didPub = decodeMultibaseEd25519(did.slice("did:key:".length));
  } catch {
    return { ok: false, reason: "did:key is not an ed25519 key" };
  }
  if (!bundle.signing_key) {
    return { ok: false, reason: "bundle has no signing_key; cannot bind it to the did:key" };
  }
  let signingKey: Uint8Array;
  try {
    signingKey = unb64(bundle.signing_key);
  } catch {
    return { ok: false, reason: "malformed signing_key" };
  }
  if (!bytesEqual(signingKey, didPub)) {
    return { ok: false, reason: "bundle signing_key is not the did:key's key" };
  }
  let sigUrl: string;
  try {
    sigUrl = b64url(unb64(bundle.spk_signature));
  } catch {
    return { ok: false, reason: "malformed spk_signature" };
  }
  if (!(await verifyEd25519(didPub, spk, sigUrl))) {
    return { ok: false, reason: "spk_signature does not verify under the did:key" };
  }
  return { ok: true };
}

// ── X25519 identity file: { secret, publicKey } base64, mode 0600 ───────

async function loadOrCreateX25519(path: string): Promise<X25519Pair> {
  try {
    const raw = JSON.parse(await readFile(path, "utf8")) as { secret?: string; publicKey?: string };
    if (typeof raw.secret === "string" && typeof raw.publicKey === "string") {
      const secret = unb64(raw.secret);
      const publicKey = unb64(raw.publicKey);
      if (secret.length === 32 && publicKey.length === 32) return { secret, publicKey };
    }
    throw new Error(`${path} is not an X25519 key file; delete it to regenerate`);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const kp = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as webcrypto.CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  if (!jwk.d || !jwk.x) throw new Error("X25519 JWK export missing d/x");
  const pair = { secret: unb64url(jwk.d), publicKey: unb64url(jwk.x) };
  await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
  await writeFile(
    path,
    JSON.stringify({ secret: b64(pair.secret), publicKey: b64(pair.publicKey) }) + "\n",
    { mode: 0o600 },
  );
  await chmod(path, 0o600);
  return pair;
}

// ── Small helpers ───────────────────────────────────────────────────────

function serverSkipped(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .map((x) => (typeof x === "string" ? x : x && typeof x === "object" ? (x as { did?: unknown }).did : null))
    .filter((x): x is string => typeof x === "string");
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function unb64(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) throw new Error("not base64");
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(std, "base64"));
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function unb64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
