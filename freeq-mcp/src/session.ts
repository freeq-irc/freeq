/**
 * The live IRC side of the MCP server.
 *
 * MCP tool calls are short-lived and stateless; an IRC presence is neither.
 * This module owns the gap: one connection per process, created lazily on the
 * first tool that needs it, holding a bounded buffer of what arrived while no
 * tool was looking. Without the buffer, "read what people said to me" would
 * only ever return messages that happened to land during the call.
 *
 * Two identity modes, chosen by whether an owner DID is configured:
 *
 * - **authenticated** — a `did:key` agent identity persisted by
 *   `@freeq/bot-kit` under `~/.freeq/bots/<name>/`, with a delegation
 *   certificate naming the owner. This is the honest mode: the room can see
 *   which human the agent acts for.
 * - **guest** — no SASL, no key, nick only. Zero-config so the server works out
 *   of the box with no `env` block at all, and `freeq_whoami` says plainly that
 *   nothing is proven and how to upgrade.
 */

import { createHash, randomUUID } from "node:crypto";
import { FreeqClient } from "@freeq/sdk";
import type { CoordinationEventPayload, Message } from "@freeq/sdk";
import type { FreeqMcpConfig } from "./config.js";

export const ASK_EVENT = "pi_ask";
export const ASK_REPLY_EVENT = "pi_ask_reply";

/** Server line limit is 8192 including tags; leave generous headroom. */
const MAX_ENCODED_PAYLOAD = 6000;

/** How many messages to retain per target between tool calls. */
const BUFFER_PER_TARGET = 200;

export type SessionMode = "authenticated" | "guest" | "offline";

export interface BufferedMessage {
  target: string;
  from: string;
  did?: string;
  text: string;
  msgid?: string;
  at: number;
  self: boolean;
}

export interface SessionStatus {
  mode: SessionMode;
  connected: boolean;
  nick?: string;
  did?: string;
  ownerDid?: string;
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

/** Minimal surface of the SDK client this module uses — so tests can fake it. */
export interface SessionClient {
  nick?: string | null;
  apiBearer?: string | null;
  on(event: string, handler: (...args: never[]) => void): unknown;
  connect(): void;
  disconnect(): void;
  join(channel: string): void;
  sendMessage(target: string, text: string): void;
  sendTagmsg(target: string, tags: Record<string, string>): void;
  quit?(reason?: string): void;
}

export interface SessionDeps {
  /** Build a client. Injected in tests; defaults to the real SDK/bot-kit. */
  createClient?(cfg: FreeqMcpConfig, nick: string): Promise<{
    client: SessionClient;
    mode: SessionMode;
    did?: string;
  }>;
  /** Called whenever a bearer token becomes available (SASL success). */
  onBearerToken?(token: string | undefined): void;
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

export class FreeqSession {
  #cfg: FreeqMcpConfig;
  #deps: SessionDeps;
  #client?: SessionClient;
  #mode: SessionMode = "offline";
  #did?: string;
  #connected = false;
  #connecting?: Promise<void>;
  #channels = new Set<string>();
  #buffers = new Map<string, BufferedMessage[]>();
  #waiters: Array<{ target?: string; resolve(m: BufferedMessage | undefined): void }> = [];
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

  status(): SessionStatus {
    const mode = this.#mode;
    return {
      mode,
      connected: this.#connected,
      nick: this.#client?.nick ?? (this.#connected ? this.#nick : undefined),
      did: this.#did,
      ownerDid: this.#cfg.ownerDid,
      channels: [...this.#channels],
      hasBearerToken: !!this.#client?.apiBearer,
      server: this.#cfg.baseUrl,
      note:
        mode === "authenticated"
          ? `Authenticated as ${this.#did ?? "did:key:…"}, acting for ${this.#cfg.ownerDid}. Messages are signed with a per-session key and verifiable via /api/v1/verify/{msgid}.`
          : mode === "guest"
            ? "Connected as a guest: the nick is not proven and nothing you send is attributable. Set FREEQ_OWNER_DID to your DID to connect with a did:key agent identity and a delegation certificate."
            : "Not connected. Read-only tools work over REST without a connection; joining, sending and asking need one.",
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
    const { client, mode, did } = await factory(this.#cfg, this.#nick);
    this.#client = client;
    this.#mode = mode;
    this.#did = did;
    this.#wire(client);

    const ready = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timed out connecting to ${this.#cfg.wsUrl} after 30s`)),
        30_000,
      );
      timer.unref?.();
      client.on("ready", (() => {
        clearTimeout(timer);
        this.#connected = true;
        resolve();
      }) as never);
      client.on("authError", ((err: string) => {
        clearTimeout(timer);
        reject(new Error(`SASL authentication failed: ${err}`));
      }) as never);
    });

    client.connect();
    await ready;
    this.#captureBearer();
    for (const channel of this.#cfg.channels) this.join(channel);
  }

  #wire(client: SessionClient): void {
    client.on("message", ((target: string, msg: Message) => {
      this.#record(target, msg);
    }) as never);

    client.on("channelJoined", ((channel: string) => {
      this.#channels.add(channel);
    }) as never);

    client.on("channelLeft", ((channel: string) => {
      this.#channels.delete(channel);
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

  #record(target: string, msg: Message): void {
    const entry: BufferedMessage = {
      target,
      from: msg.from ?? "?",
      // The server stamps the sender's DID as an `account` tag when it knows
      // one; its absence means "unproven nick", not "no such user".
      did: msg.tags?.account,
      text: msg.text ?? "",
      msgid: msg.tags?.msgid ?? msg.id,
      at: this.#now(),
      self: msg.isSelf ?? (!!this.#client?.nick && msg.from === this.#client.nick),
    };
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
    this.#channels.add(name);
  }

  say(target: string, text: string): void {
    this.#require().sendMessage(target, text);
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
    const client = this.#client;
    if (!client) return;
    try {
      client.quit?.(reason);
      client.disconnect();
    } finally {
      this.#connected = false;
      this.#client = undefined;
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

/**
 * Real client factory: bot-kit identity when an owner DID is configured,
 * plain guest `FreeqClient` otherwise.
 */
async function defaultCreateClient(
  cfg: FreeqMcpConfig,
  nick: string,
): Promise<{ client: SessionClient; mode: SessionMode; did?: string }> {
  if (cfg.ownerDid) {
    // Imported lazily so the guest path doesn't pay for bot-kit's disk I/O.
    const { FreeqBot } = await import("@freeq/bot-kit");
    const bot = await FreeqBot.create({
      name: nick,
      ownerDid: cfg.ownerDid,
      nick,
      url: cfg.wsUrl,
      serverOrigin: cfg.baseUrl,
      channels: cfg.channels,
      actorClass: "agent",
    });
    // FreeqBot.start() does the announce sequence; the session drives
    // readiness itself, so hand back the underlying client and let it.
    return {
      client: bot.client as unknown as SessionClient,
      mode: "authenticated",
      did: bot.identity.did,
    };
  }
  const client = new FreeqClient({ url: cfg.wsUrl, nick, channels: cfg.channels });
  return { client: client as unknown as SessionClient, mode: "guest" };
}
