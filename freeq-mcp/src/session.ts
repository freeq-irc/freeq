/**
 * The live IRC side of the MCP server.
 *
 * MCP tool calls are short-lived and stateless; an IRC presence is neither.
 * This module owns the gap: one connection per process, created lazily on the
 * first tool that needs it, holding a bounded buffer of what arrived while no
 * tool was looking. Without the buffer, "read what people said to me" would
 * only ever return messages that happened to land during the call.
 *
 * Identity modes:
 *
 * - **authenticated** — a `did:key` agent identity persisted by
 *   `@freeq/bot-kit` under `~/.freeq/bots/<name>/`, with a delegation
 *   certificate. With `FREEQ_OWNER_DID` the certificate names that human as
 *   the owner; without it the certificate names the agent's own DID
 *   (`selfOwned`), which is honest about speaking for nobody while still
 *   being a real, stable, key-backed principal. This is the default.
 * - **guest** — no SASL, no key, nick only. Only when `FREEQ_GUEST=1`, for
 *   setups that must not write anything to disk. Guests cannot use rooms.
 *
 * Rooms (docs/INSTANT-ROOMS.md) ride on the bot-kit `RoomManager`: it holds
 * the group keys and installs a cipher on the client, after which the normal
 * `message` path delivers decrypted text and `sendMessage` encrypts. The
 * session only has to know which channels are rooms, so it can refuse to
 * send into one it cannot encrypt for and can point `freeq_history` at the
 * decrypted path instead of REST ciphertext.
 */

import { createHash, randomUUID } from "node:crypto";
import { unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { FreeqClient } from "@freeq/sdk";
import type { CoordinationEventPayload, Message } from "@freeq/sdk";
import type { RoomInfo, RoomLink } from "@freeq/bot-kit";
import type { FreeqMcpConfig } from "./config.js";

export const ASK_EVENT = "pi_ask";
export const ASK_REPLY_EVENT = "pi_ask_reply";

/** Server line limit is 8192 including tags; leave generous headroom. */
const MAX_ENCODED_PAYLOAD = 6000;

/** How many messages to retain per target between tool calls. */
const BUFFER_PER_TARGET = 200;

/** Upper bound on a CHATHISTORY replay (the server caps at 50 per request anyway). */
export const ROOM_HISTORY_MAX = 50;

/** How long to wait for a CHATHISTORY batch before answering without it. */
const HISTORY_TIMEOUT_MS = 10_000;

/** How long `say` waits for the server to echo our own message back. */
const SEND_CONFIRM_MS = 5_000;

export type SessionMode = "authenticated" | "guest" | "offline";

export interface BufferedMessage {
  target: string;
  from: string;
  did?: string;
  text: string;
  msgid?: string;
  at: number;
  self: boolean;
  /** True when the wire form was ciphertext (decrypted here, or not). */
  encrypted?: boolean;
}

export interface SessionStatus {
  mode: SessionMode;
  connected: boolean;
  nick?: string;
  did?: string;
  ownerDid?: string;
  /** Authenticated with a did:key whose delegation names itself as owner. */
  selfOwned?: boolean;
  channels: string[];
  hasBearerToken: boolean;
  server: string;
  /** Why the identity is what it is, in words a caller can act on. */
  note: string;
}

export interface AskResult {
  ok: boolean;
  answer?: string;
  error?: string;
  from?: string;
}

export interface RoomReadResult {
  channel: string;
  /** False when no room key has been sealed to us yet. */
  ready: boolean;
  /** Whether we hold the newest epoch the server has for us (undefined if unknown). */
  latest?: boolean;
  messages: BufferedMessage[];
  note?: string;
}

/** Minimal surface of the SDK client this module uses — so tests can fake it. */
export interface SessionClient {
  nick?: string | null;
  apiBearer?: string | null;
  on(event: string, handler: (...args: never[]) => void): unknown;
  off?(event: string, handler: (...args: never[]) => void): unknown;
  connect(): void;
  disconnect(): void;
  join(channel: string, key?: string): void;
  sendMessage(target: string, text: string): void;
  sendTagmsg(target: string, tags: Record<string, string>): void;
  requestHistory?(opts: { target: string; mode: "latest"; count?: number }): void;
  quit?(reason?: string): void;
}

/** The part of bot-kit's `RoomManager` the session and tools use. */
export interface SessionRooms {
  ensurePreKeyPublished(): Promise<void>;
  create(opts?: { topic?: string; inviteTtlSecs?: number }): Promise<{
    channel: string;
    invite: string;
    url: string;
    expiresAt: number;
  }>;
  join(link: RoomLink | string): Promise<{ channel: string; ready: boolean }>;
  loadKeys(channel: string): Promise<boolean>;
  info(channel: string): Promise<RoomInfo>;
  keep(channel: string): Promise<number>;
  removeMember(channel: string, did: string): Promise<void>;
  /** Seal the epochs we hold to roster members who lack the latest one. */
  stewardPass(channel: string): Promise<{ sealed: string[]; skipped: Array<{ did: string; reason: string }> }>;
  isRoom(channel: string): boolean;
  /** Rooms we hold at least one key for (persisted across processes). */
  channels(): string[];
}

export interface ClientFactoryResult {
  client: SessionClient;
  mode: SessionMode;
  did?: string;
  selfOwned?: boolean;
  /**
   * Connect and resolve on `ready` (reject on auth failure). When absent the
   * session calls `client.connect()` and waits for `ready` itself. bot-kit's
   * `FreeqBot.start()` goes here so the announce sequence (PROVENANCE, then
   * the configured JOINs) actually runs.
   */
  start?(): Promise<void>;
  /** Graceful shutdown; defaults to QUIT + disconnect on the client. */
  stop?(reason: string): Promise<void>;
  /** Room support; absent for guests. */
  rooms?: SessionRooms;
}

export interface SessionDeps {
  /** Build a client. Injected in tests; defaults to the real SDK/bot-kit. */
  createClient?(cfg: FreeqMcpConfig, nick: string): Promise<ClientFactoryResult>;
  /** Called whenever a bearer token becomes available (SASL success). */
  onBearerToken?(token: string | undefined): void;
  /** Diagnostics sink. Never stdout: in MCP mode stdout is the transport. */
  warn?(message: string): void;
  now?(): number;
}

interface PendingAsk {
  req: string;
  to: string;
  settled: boolean;
  timer: ReturnType<typeof setTimeout>;
  resolve(result: AskResult): void;
}

/**
 * Encode a coordination-event payload, shrinking `textKey` until the
 * percent-encoded form fits. Percent-encoding can triple the size of
 * non-ASCII text, so budgeting on raw length is wrong.
 */
export function encodePayload(
  obj: Record<string, unknown>,
  textKey: string,
  limit = MAX_ENCODED_PAYLOAD,
): { encoded: string; truncated: boolean } {
  let text = typeof obj[textKey] === "string" ? (obj[textKey] as string) : "";
  let truncated = false;
  const enc = (o: unknown) => encodeURIComponent(JSON.stringify(o));
  let encoded = enc(obj);
  while (encoded.length > limit && text.length > 0) {
    truncated = true;
    const overshoot = encoded.length / limit;
    const next = Math.max(0, Math.floor(text.length / Math.max(overshoot, 1.1)) - 16);
    text = text.slice(0, next);
    encoded = enc({ ...obj, [textKey]: text ? `${text}\n…[truncated]` : "…[truncated]" });
  }
  return { encoded, truncated };
}

/** `general` → `#general`, `#Room` → `#room`. */
export function normalizeChannel(channel: string): string {
  const name = channel.trim();
  const withHash = name.startsWith("#") || name.startsWith("&") ? name : `#${name}`;
  return withHash.toLowerCase();
}

function isChannel(target: string): boolean {
  return target.startsWith("#") || target.startsWith("&");
}

export class FreeqSession {
  #cfg: FreeqMcpConfig;
  #deps: SessionDeps;
  #client?: SessionClient;
  #mode: SessionMode = "offline";
  #did?: string;
  #selfOwned = false;
  #rooms?: SessionRooms;
  #stop?: (reason: string) => Promise<void>;
  #connected = false;
  #connecting?: Promise<void>;
  #channels = new Set<string>();
  /** Channels known to be E2EE rooms (lowercase), whether or not we hold a key. */
  #roomChannels = new Set<string>();
  #buffers = new Map<string, BufferedMessage[]>();
  #waiters: Array<{ target?: string; resolve(m: BufferedMessage | undefined): void }> = [];
  #echoWaiters: Array<{ target: string; text: string; resolve(): void }> = [];
  #asks = new Map<string, PendingAsk>();
  #inboundAsks: Array<{ req: string; from: string; question: string; at: number }> = [];
  #nick: string;

  constructor(cfg: FreeqMcpConfig, deps: SessionDeps = {}) {
    this.#cfg = cfg;
    this.#deps = deps;
    this.#nick = cfg.nick ?? defaultNick();
  }

  get connected(): boolean {
    return this.#connected;
  }

  get did(): string | undefined {
    return this.#did;
  }

  status(): SessionStatus {
    const mode = this.#mode;
    const did = this.#did ?? "did:key:…";
    let note: string;
    if (mode === "authenticated" && this.#selfOwned) {
      note = `Authenticated as ${did}: a self-owned did:key that speaks for no human (set FREEQ_OWNER_DID to bind it to you). Messages are signed with a per-session key and verifiable via /api/v1/verify/{msgid}.`;
    } else if (mode === "authenticated") {
      note = `Authenticated as ${did}, acting for ${this.#cfg.ownerDid}. Messages are signed with a per-session key and verifiable via /api/v1/verify/{msgid}.`;
    } else if (mode === "guest") {
      note =
        "Connected as a guest (FREEQ_GUEST is set): the nick is not proven, nothing you send is attributable, and rooms are unavailable. Unset FREEQ_GUEST to connect with a did:key agent identity; set FREEQ_OWNER_DID to bind it to your DID.";
    } else {
      note =
        "Not connected. Read-only tools work over REST without a connection; joining, sending, asking and rooms need one.";
    }
    return {
      mode,
      connected: this.#connected,
      nick: this.#client?.nick ?? (this.#connected ? this.#nick : undefined),
      did: this.#did,
      ownerDid: this.#cfg.ownerDid,
      selfOwned: mode === "authenticated" ? this.#selfOwned : undefined,
      channels: [...this.#channels],
      hasBearerToken: !!this.#client?.apiBearer,
      server: this.#cfg.baseUrl,
      note,
    };
  }

  /** Connect if needed. Concurrent callers share one attempt. */
  async connect(): Promise<SessionStatus> {
    if (this.#connected) return this.status();
    if (!this.#connecting) {
      this.#connecting = this.#doConnect().finally(() => {
        this.#connecting = undefined;
      });
    }
    await this.#connecting;
    return this.status();
  }

  async #doConnect(): Promise<void> {
    const factory = this.#deps.createClient ?? defaultCreateClient;
    const made = await factory(this.#cfg, this.#nick);
    this.#client = made.client;
    this.#mode = made.mode;
    this.#did = made.did;
    this.#selfOwned = made.selfOwned ?? false;
    this.#rooms = made.rooms;
    this.#stop = made.stop;
    this.#wire(made.client);

    if (made.start) {
      // bot-kit drives connect → ready → PROVENANCE → JOINs, and rejects on
      // SASL failure or timeout with its own actionable message.
      await made.start();
    } else {
      await this.#connectAndWaitReady(made.client);
      for (const channel of this.#cfg.channels) this.join(channel);
    }
    this.#connected = true;
    this.#captureBearer();

    // Publish our X25519 pre-key so a room steward can seal keys to us. It
    // waits for the API bearer (a beat after ready) and is one POST; awaiting
    // it keeps a one-shot process from quitting with the request in flight,
    // which the server would answer 403 (no such session). Room operations
    // re-run it idempotently, so a failure here only costs a retry later.
    if (this.#rooms) {
      try {
        await this.#rooms.ensurePreKeyPublished();
      } catch (err) {
        this.#warn(`pre-key publish failed (will retry on first room use): ${errorMessage(err)}`);
      }
      this.#rejoinRooms(this.#rooms);
    }
  }

  /**
   * Re-enter the rooms we hold keys for. A roster member needs no token, and
   * being inside is what makes the buffer fill and lets us seal the key to
   * newcomers — bot-kit's steward only fires on a JOIN it witnesses, so a
   * member who was away when someone arrived runs a pass now.
   */
  #rejoinRooms(rooms: SessionRooms): void {
    for (const ch of rooms.channels()) {
      this.noteRoom(ch);
      try {
        this.#client?.join(ch);
      } catch (err) {
        this.#warn(`rejoin ${ch}: ${errorMessage(err)}`);
        continue;
      }
      this.roomSteward(ch).catch(() => undefined);
    }
  }

  /**
   * Seal the room key to members who lack it, if we hold it. Never throws:
   * stewarding is a courtesy to others, and a failure must not break the
   * caller's own read or send. Returns who was sealed to.
   */
  async roomSteward(channel: string): Promise<string[]> {
    const ch = normalizeChannel(channel);
    const rooms = this.#rooms;
    if (!rooms || !rooms.isRoom(ch)) return [];
    try {
      const pass = await rooms.stewardPass(ch);
      for (const s of pass.skipped) this.#warn(`steward ${ch}: not sealing to ${s.did}: ${s.reason}`);
      return pass.sealed;
    } catch (err) {
      this.#warn(`steward pass for ${ch} failed: ${errorMessage(err)}`);
      return [];
    }
  }

  #connectAndWaitReady(client: SessionClient): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timed out connecting to ${this.#cfg.wsUrl} after 30s`)),
        30_000,
      );
      timer.unref?.();
      client.on("ready", (() => {
        clearTimeout(timer);
        resolve();
      }) as never);
      client.on("authError", ((err: string) => {
        clearTimeout(timer);
        reject(new Error(`SASL authentication failed: ${err}`));
      }) as never);
      client.connect();
    });
  }

  #wire(client: SessionClient): void {
    client.on("ready", (() => {
      // Also fires on the SDK's automatic reconnects.
      this.#connected = true;
    }) as never);

    client.on("message", ((target: string, msg: Message) => {
      this.#record(target, msg);
    }) as never);

    client.on("channelJoined", ((channel: string) => {
      this.#channels.add(channel.toLowerCase());
    }) as never);

    client.on("channelLeft", ((channel: string) => {
      this.#channels.delete(channel.toLowerCase());
    }) as never);

    client.on("authenticated", ((did: string) => {
      this.#did = did;
      this.#mode = "authenticated";
      // API-BEARER arrives as a NOTICE immediately after SASL success and the
      // SDK stashes it on the client. There is no event for it, so check just
      // after authentication rather than making the operator paste a token.
      this.#captureBearer();
    }) as never);

    client.on("connectionStateChanged", ((state: string) => {
      if (state === "disconnected" || state === "closed") {
        this.#connected = false;
        this.#failAllAsks("connection dropped");
      }
    }) as never);

    client.on("coordinationEvent", ((e: CoordinationEventPayload) => {
      this.#onCoordinationEvent(e);
    }) as never);

    // The server tells a joiner when a channel is a room. Remembering it is
    // what lets `say` refuse cleanly instead of the SDK dropping the message,
    // and lets `freeq_history` redirect to the decrypted path.
    client.on("raw", ((_line: string, parsed: { command?: string; params?: string[] }) => {
      if (parsed?.command !== "NOTICE") return;
      const text = parsed.params?.[1] ?? "";
      const m = /^([#&]\S+) is an end-to-end encrypted room/.exec(text);
      if (m) this.noteRoom(m[1]);
    }) as never);
  }

  /** Hand the SASL-issued bearer token to whoever wants it (the REST client). */
  #captureBearer(): void {
    const check = () => {
      const token = this.#client?.apiBearer ?? undefined;
      if (token) this.#deps.onBearerToken?.(token);
    };
    check();
    // The NOTICE can land a beat after `ready`; look once more rather than
    // leaving authenticated REST endpoints unusable for the whole session.
    const timer = setTimeout(check, 500);
    timer.unref?.();
  }

  /**
   * The API bearer the server issued after SASL, waiting (bounded) for it.
   * Returns undefined for guests or when it never arrives.
   */
  async bearer(timeoutMs = 5_000): Promise<string | undefined> {
    const deadline = this.#now() + timeoutMs;
    for (;;) {
      const token = this.#client?.apiBearer ?? undefined;
      if (token) {
        this.#deps.onBearerToken?.(token);
        return token;
      }
      if (this.#mode !== "authenticated" || this.#now() >= deadline) return undefined;
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  #toBuffered(target: string, msg: Message, at?: number): BufferedMessage {
    return {
      target,
      from: msg.from ?? "?",
      // The server stamps the sender's DID as an `account` tag when it knows
      // one; its absence means "unproven nick", not "no such user".
      did: msg.tags?.account,
      text: msg.text ?? "",
      msgid: msg.tags?.msgid ?? msg.id,
      at: at ?? this.#now(),
      self: msg.isSelf ?? (!!this.#client?.nick && msg.from === this.#client.nick),
      encrypted: msg.encrypted || undefined,
    };
  }

  #record(target: string, msg: Message): void {
    const entry = this.#toBuffered(target, msg);
    const buf = this.#buffers.get(target) ?? [];
    buf.push(entry);
    // Bounded: an MCP server can sit in a busy channel for days between
    // calls, and an unbounded buffer would be a slow memory leak.
    if (buf.length > BUFFER_PER_TARGET) buf.splice(0, buf.length - BUFFER_PER_TARGET);
    this.#buffers.set(target, buf);

    for (const w of [...this.#waiters]) {
      if (w.target && w.target.toLowerCase() !== target.toLowerCase()) continue;
      if (entry.self) continue;
      this.#waiters.splice(this.#waiters.indexOf(w), 1);
      w.resolve(entry);
    }
    if (entry.self) {
      // Our own echo, decrypted: match the oldest pending send to this
      // target with the same text (the echo of a room message decrypts to
      // what we sent).
      const i = this.#echoWaiters.findIndex(
        (w) => w.target.toLowerCase() === target.toLowerCase() && w.text === entry.text,
      );
      if (i >= 0) this.#echoWaiters.splice(i, 1)[0].resolve();
    }
  }

  #onCoordinationEvent(e: CoordinationEventPayload): void {
    if (e.eventType === ASK_REPLY_EVENT) {
      const reply = parseReply(e.payload);
      if (reply) this.#deliverAsk(reply, e.from);
      return;
    }
    if (e.eventType === ASK_EVENT) {
      const req = parseRequest(e.payload);
      if (!req) return;
      this.#inboundAsks.push({ req: req.req, from: e.from, question: req.q, at: this.#now() });
      if (this.#inboundAsks.length > 50) this.#inboundAsks.shift();
    }
  }

  /** Messages buffered for a target (or all targets), oldest first. */
  buffered(target?: string, limit = 50): BufferedMessage[] {
    const all: BufferedMessage[] = [];
    for (const [key, msgs] of this.#buffers) {
      if (target && key.toLowerCase() !== target.toLowerCase()) continue;
      all.push(...msgs);
    }
    all.sort((a, b) => a.at - b.at);
    return all.slice(-limit);
  }

  /** Asks other agents have sent us and we have not answered. */
  inboundAsks(): Array<{ req: string; from: string; question: string; at: number }> {
    return [...this.#inboundAsks];
  }

  join(channel: string): void {
    const name = channel.startsWith("#") || channel.startsWith("&") ? channel : `#${channel}`;
    this.#require().join(name);
    this.#channels.add(name.toLowerCase());
  }

  /** Is this channel one we have joined (as the server confirmed it)? */
  inChannel(channel: string): boolean {
    return this.#channels.has(normalizeChannel(channel));
  }

  /**
   * Send, then wait (bounded) for the server's echo of our own message.
   *
   * The SDK encrypts and signs asynchronously before anything hits the
   * socket, so "sendMessage returned" is not "sent": a one-shot process that
   * quits right after would race its own PRIVMSG and lose. The echo
   * (`echo-message` is negotiated) is the send confirmation; `confirmed`
   * is false when it did not arrive in time, which is worth telling an agent.
   * Throws synchronously when not connected or when the target is a room we
   * hold no key for, so nothing is sent that the SDK would silently drop.
   */
  say(target: string, text: string, confirmMs = SEND_CONFIRM_MS): Promise<{ confirmed: boolean }> {
    const client = this.#require();
    if (isChannel(target) && this.isKnownRoom(target) && !this.hasRoomKey(target)) {
      throw new Error(
        `${target} is an end-to-end encrypted room and no room key has been sealed to this agent yet, ` +
          `so nothing can be encrypted for it. Call freeq_room_read (it re-fetches the key) or ` +
          `freeq_room_join with the room URL, then try again.`,
      );
    }
    const echo = this.#waitForEcho(target, text, confirmMs);
    client.sendMessage(target, text);
    return echo;
  }

  #waitForEcho(target: string, text: string, timeoutMs: number): Promise<{ confirmed: boolean }> {
    if (timeoutMs <= 0) return Promise.resolve({ confirmed: false });
    return new Promise((resolve) => {
      const waiter = {
        target,
        text,
        resolve: () => {
          clearTimeout(timer);
          resolve({ confirmed: true });
        },
      };
      this.#echoWaiters.push(waiter);
      const timer = setTimeout(() => {
        const i = this.#echoWaiters.indexOf(waiter);
        if (i >= 0) this.#echoWaiters.splice(i, 1);
        resolve({ confirmed: false });
      }, timeoutMs);
      timer.unref?.();
    });
  }

  // ── Rooms ────────────────────────────────────────────────────────────

  /** The room manager, or a clear error about why there is none. */
  get rooms(): SessionRooms {
    if (this.#rooms) return this.#rooms;
    if (this.#mode === "guest") {
      throw new Error(
        "rooms need a did:key identity, and this session is a guest (FREEQ_GUEST is set). Unset it and reconnect.",
      );
    }
    throw new Error("not connected to freeq — call freeq_connect first");
  }

  /** Remember that a channel is a room (from create/join, or the server's NOTICE). */
  noteRoom(channel: string): void {
    this.#roomChannels.add(normalizeChannel(channel));
  }

  /** A room we know of: told by the server, created/joined here, or holding its key. */
  isKnownRoom(channel: string): boolean {
    const ch = normalizeChannel(channel);
    return this.#roomChannels.has(ch) || !!this.#rooms?.isRoom(ch);
  }

  /** Do we hold a group key for this room (i.e. can we read and write it)? */
  hasRoomKey(channel: string): boolean {
    return !!this.#rooms?.isRoom(normalizeChannel(channel));
  }

  async roomCreate(opts: { topic?: string; inviteTtlSecs?: number } = {}): Promise<{
    channel: string;
    invite: string;
    url: string;
    expiresAt: number;
  }> {
    const made = await this.rooms.create(opts);
    this.noteRoom(made.channel);
    this.#channels.add(normalizeChannel(made.channel));
    return made;
  }

  /**
   * Join a room from a link. A link with no token still works for a DID
   * already on the roster (a member reconnecting). Refuses a link for a
   * different server, since the connection is to this one.
   */
  async roomJoin(link: RoomLink): Promise<{ channel: string; ready: boolean }> {
    this.#checkOrigin(link.origin);
    const rooms = this.rooms;
    const res = await rooms.join(link);
    this.noteRoom(res.channel);
    this.#channels.add(normalizeChannel(res.channel));
    return res;
  }

  #checkOrigin(origin: string): void {
    let theirs: string;
    let ours: string;
    try {
      theirs = new URL(origin).host.toLowerCase();
      ours = new URL(this.#cfg.baseUrl).host.toLowerCase();
    } catch {
      return;
    }
    if (theirs !== ours) {
      throw new Error(
        `that room lives on ${origin}, but this session is connected to ${this.#cfg.baseUrl}. ` +
          `Set FREEQ_SERVER=${origin} (or run \`freeq-mcp room join <url>\` with it) to join.`,
      );
    }
  }

  /**
   * Decrypted messages from a room: what is buffered, plus (with `history`)
   * a CHATHISTORY replay of the latest rows, which the SDK decrypts on the
   * way in. Fetches keys first when we hold none, and says so when there
   * still are none rather than returning ciphertext placeholders.
   */
  async roomRead(
    channel: string,
    opts: { waitMs?: number; history?: boolean; limit?: number } = {},
  ): Promise<RoomReadResult> {
    const ch = normalizeChannel(channel);
    const rooms = this.rooms;
    const limit = Math.min(Math.max(1, Math.trunc(opts.limit ?? ROOM_HISTORY_MAX)), 200);

    // Always re-fetch: it is one GET, and it picks up a rotation (a member
    // was removed) that would otherwise leave every new row unreadable.
    let latest: boolean | undefined;
    let loadError: string | undefined;
    try {
      latest = await rooms.loadKeys(ch);
    } catch (err) {
      loadError = errorMessage(err);
    }
    if (!rooms.isRoom(ch)) {
      return {
        channel: ch,
        ready: false,
        messages: [],
        note: loadError
          ? `could not fetch the room key: ${loadError}. Are you a member of ${ch}? Join with freeq_room_join and the room URL.`
          : `no member has sealed the room key to this agent yet (a member's client does that when it sees the join, usually within seconds). Try again shortly.`,
      };
    }
    this.noteRoom(ch);
    const sealed = await this.roomSteward(ch);

    let rows: BufferedMessage[] = [];
    if (opts.history) rows = await this.#fetchHistory(ch, Math.min(limit, ROOM_HISTORY_MAX));

    let messages = mergeMessages(rows, this.buffered(ch, limit), limit);
    if (messages.length === 0 && opts.waitMs) {
      await this.waitForMessage(ch, opts.waitMs);
      messages = mergeMessages(rows, this.buffered(ch, limit), limit);
    }
    const unreadable = messages.filter((m) => m.encrypted && m.text === "[encrypted message]").length;
    const notes: string[] = [];
    if (unreadable > 0) {
      notes.push(
        `${unreadable} message(s) were sealed under an epoch this agent does not hold (sent before it joined, or after a rotation). They cannot be recovered.`,
      );
    }
    if (sealed.length > 0) notes.push(`Sealed the room key to ${sealed.length} member(s) who lacked it: ${sealed.join(", ")}.`);
    return { channel: ch, ready: true, latest, messages, note: notes.length ? notes.join(" ") : undefined };
  }

  /** CHATHISTORY LATEST over the live connection; empty on timeout or when the client cannot. */
  #fetchHistory(channel: string, count: number): Promise<BufferedMessage[]> {
    const client = this.#require();
    if (!client.requestHistory) return Promise.resolve([]);
    return new Promise((resolve) => {
      const done = (rows: BufferedMessage[]) => {
        clearTimeout(timer);
        client.off?.("historyBatch", handler as never);
        resolve(rows);
      };
      const handler = (target: string, messages: Message[]) => {
        if (target.toLowerCase() !== channel) return;
        done(
          messages.map((m) =>
            this.#toBuffered(channel, m, m.timestamp instanceof Date ? m.timestamp.getTime() : undefined),
          ),
        );
      };
      const timer = setTimeout(() => done([]), HISTORY_TIMEOUT_MS);
      timer.unref?.();
      client.on("historyBatch", handler as never);
      try {
        client.requestHistory!({ target: channel, mode: "latest", count });
      } catch (err) {
        this.#warn(`CHATHISTORY request failed: ${errorMessage(err)}`);
        done([]);
      }
    });
  }

  /**
   * Ask a peer one question and wait for exactly one reply.
   *
   * Wire-compatible with `@freeq/pi`'s `ask`: a caller-minted request id in
   * the payload, carried on the `+freeq.at/event` coordination channel.
   * Correctness never depends on IRC reply tags, and a reply from anyone but
   * the peer we asked is rejected — a third party must not be able to answer
   * someone else's question.
   */
  ask(to: string, question: string, timeoutMs?: number): Promise<AskResult> {
    const client = this.#require();
    const req = randomUUID();
    const ms = Math.min(Math.max(1_000, timeoutMs ?? this.#cfg.askTimeoutMs), 600_000);
    const promise = new Promise<AskResult>((resolve) => {
      const timer = setTimeout(() => {
        const p = this.#asks.get(req);
        if (!p || p.settled) return;
        p.settled = true;
        this.#asks.delete(req);
        resolve({ ok: false, error: `no reply from ${to} within ${Math.round(ms / 1000)}s` });
      }, ms);
      timer.unref?.();
      this.#asks.set(req, { req, to, settled: false, timer, resolve });
    });

    const { encoded } = encodePayload({ req, q: question }, "q");
    try {
      client.sendTagmsg(to, {
        "+freeq.at/event": ASK_EVENT,
        "+freeq.at/payload": encoded,
      });
    } catch (err) {
      this.#deliverAsk({ req, err: `send failed: ${(err as Error).message}` }, to);
    }
    return promise;
  }

  /** Answer an ask another agent sent us. */
  replyToAsk(req: string, answer: string, error?: string): boolean {
    const client = this.#require();
    const pending = this.#inboundAsks.find((a) => a.req === req);
    if (!pending) return false;
    const body = error ? { req, err: error } : { req, a: answer };
    const { encoded } = encodePayload(body, error ? "err" : "a");
    client.sendTagmsg(pending.from, {
      "+freeq.at/event": ASK_REPLY_EVENT,
      "+freeq.at/payload": encoded,
    });
    this.#inboundAsks = this.#inboundAsks.filter((a) => a.req !== req);
    return true;
  }

  #deliverAsk(reply: { req: string; a?: string; err?: string }, from: string): void {
    const p = this.#asks.get(reply.req);
    if (!p || p.settled) return;
    if (p.to.toLowerCase() !== from.toLowerCase()) return;
    p.settled = true;
    clearTimeout(p.timer);
    this.#asks.delete(reply.req);
    p.resolve(
      reply.err ? { ok: false, error: reply.err, from } : { ok: true, answer: reply.a ?? "", from },
    );
  }

  #failAllAsks(reason: string): void {
    for (const p of [...this.#asks.values()]) {
      if (p.settled) continue;
      p.settled = true;
      clearTimeout(p.timer);
      p.resolve({ ok: false, error: reason });
    }
    this.#asks.clear();
  }

  /** Wait for the next inbound message, optionally on one target. */
  waitForMessage(target: string | undefined, timeoutMs: number): Promise<BufferedMessage | undefined> {
    return new Promise((resolve) => {
      const waiter = { target, resolve: (m: BufferedMessage) => resolve(m) };
      this.#waiters.push(waiter);
      const timer = setTimeout(() => {
        const i = this.#waiters.indexOf(waiter);
        if (i >= 0) this.#waiters.splice(i, 1);
        resolve(undefined);
      }, Math.min(Math.max(500, timeoutMs), 600_000));
      timer.unref?.();
    });
  }

  async close(reason = "mcp server shutting down"): Promise<void> {
    this.#failAllAsks("shutting down");
    for (const w of this.#waiters.splice(0)) w.resolve(undefined);
    this.#echoWaiters.splice(0);
    const client = this.#client;
    if (!client) return;
    try {
      if (this.#stop) {
        await this.#stop(reason);
      } else {
        client.quit?.(reason);
        client.disconnect();
      }
    } catch (err) {
      this.#warn(`shutdown: ${errorMessage(err)}`);
      try {
        client.disconnect();
      } catch {
        // already gone
      }
    } finally {
      this.#connected = false;
      this.#client = undefined;
      this.#rooms = undefined;
      this.#stop = undefined;
      this.#mode = "offline";
    }
  }

  #require(): SessionClient {
    if (!this.#client || !this.#connected) {
      throw new Error("not connected to freeq — call freeq_connect first");
    }
    return this.#client;
  }

  #now(): number {
    return this.#deps.now?.() ?? Date.now();
  }

  #warn(message: string): void {
    if (this.#deps.warn) this.#deps.warn(message);
    else process.stderr.write(`freeq-mcp: ${message}\n`);
  }
}

/** Union of two message lists, deduped by msgid, oldest first, last `limit`. */
function mergeMessages(a: BufferedMessage[], b: BufferedMessage[], limit: number): BufferedMessage[] {
  const seen = new Set<string>();
  const out: BufferedMessage[] = [];
  for (const m of [...a, ...b]) {
    const key = m.msgid ?? `${m.from}\0${m.at}\0${m.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  out.sort((x, y) => x.at - y.at);
  return out.slice(-limit);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function parseRequest(raw: unknown): { req: string; q: string } | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.req !== "string" || !o.req) return undefined;
  if (typeof o.q !== "string" || !o.q.trim()) return undefined;
  return { req: o.req.slice(0, 128), q: o.q.slice(0, 8000) };
}

function parseReply(raw: unknown): { req: string; a?: string; err?: string } | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.req !== "string" || !o.req) return undefined;
  return {
    req: o.req.slice(0, 128),
    a: typeof o.a === "string" ? o.a.slice(0, 8000) : undefined,
    err: typeof o.err === "string" ? o.err.slice(0, 500) : undefined,
  };
}

/**
 * Default nick: `mcp-<8 hex>` derived from host + user, hashed.
 *
 * Hashed rather than embedded because the nick is public, and
 * "chads-macbook" tells a channel more than it needs to know.
 */
export function defaultNick(seed?: string): string {
  const material = seed ?? `${process.env.HOSTNAME ?? ""}\0${process.env.USER ?? ""}\0mcp`;
  const slug = createHash("sha256").update(material).digest("hex").slice(0, 8);
  return `mcp-${slug}`;
}

/** Where bot-kit keeps per-bot state; passed explicitly so both sides agree. */
export function botStateRoot(): string {
  return join(homedir(), ".freeq", "bots");
}

/**
 * Real client factory.
 *
 * Default: a bot-kit `did:key` identity. With `FREEQ_OWNER_DID` its delegation
 * names that human; without it the delegation names the agent itself, which
 * is a real, stable identity that is honest about acting for nobody. Only
 * `FREEQ_GUEST=1` yields a nick-only guest `FreeqClient`.
 */
export async function defaultCreateClient(
  cfg: FreeqMcpConfig,
  nick: string,
  deps: {
    botKit?: () => Promise<BotKitModule>;
    root?: string;
  } = {},
): Promise<ClientFactoryResult> {
  if (cfg.guest) {
    const client = new FreeqClient({ url: cfg.wsUrl, nick, channels: cfg.channels });
    return { client: client as unknown as SessionClient, mode: "guest" };
  }

  // Imported lazily so the guest path doesn't pay for bot-kit's disk I/O.
  const kit = await (deps.botKit ?? (() => import("@freeq/bot-kit") as Promise<BotKitModule>))();
  const root = deps.root ?? botStateRoot();
  const stateDir = join(root, nick);
  const certPath = join(stateDir, "delegation.json");

  // Learn our own DID first: a self-owned certificate has to name it, and
  // `FreeqBot.create` mints the certificate from the owner it is given.
  const identity = await kit.loadOrCreateIdentity({ seedPath: join(stateDir, "agent.key") });
  const selfOwned = !cfg.ownerDid;
  const ownerDid = cfg.ownerDid ?? identity.did;

  // A self-owned cert is unsigned and names nobody, so replacing it when an
  // owner is configured later is the upgrade the operator asked for, not data
  // loss. Any other mismatch (a different owner, or a signed cert) is left to
  // bot-kit, whose error names the file and the DIDs involved.
  if (!selfOwned) {
    const existing = await kit.loadDelegation({ certPath });
    if (existing && existing.creator_did === identity.did && !existing.signature) {
      await unlink(certPath);
    }
  }

  const bot = await kit.FreeqBot.create({
    name: nick,
    ownerDid,
    nick,
    url: cfg.wsUrl,
    serverOrigin: cfg.baseUrl,
    channels: cfg.channels,
    actorClass: "agent",
    root,
  });
  return {
    client: bot.client as unknown as SessionClient,
    mode: "authenticated",
    did: bot.identity.did,
    selfOwned,
    start: () => bot.start(),
    stop: (reason: string) => bot.stop({ reason }),
    rooms: bot.rooms,
  };
}

/** The slice of `@freeq/bot-kit` the factory needs; typed so tests can inject a fake. */
export interface BotKitModule {
  loadOrCreateIdentity(opts: { seedPath: string }): Promise<{ did: string }>;
  loadDelegation(opts: { certPath: string }): Promise<{ creator_did: string; signature: string | null } | null>;
  FreeqBot: {
    create(opts: {
      name: string;
      ownerDid: string;
      nick: string;
      url: string;
      serverOrigin?: string;
      channels?: string[];
      actorClass?: "agent" | "external_agent" | "human";
      root?: string;
    }): Promise<{
      client: unknown;
      identity: { did: string };
      rooms: SessionRooms;
      start(): Promise<void>;
      stop(opts: { reason: string }): Promise<void>;
    }>;
  };
}
