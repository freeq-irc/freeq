/**
 * The live IRC side of the MCP server.
 *
 * MCP tool calls are short-lived and stateless; an IRC presence is neither.
 * This module owns the gap: one connection per process, created lazily on the
 * first tool that needs it, holding a bounded buffer of what arrived while no
 * tool was looking. Without the buffer, "read what people said to me" would
 * only ever return messages that happened to land during the call.
 *
 * Two identity modes:
 *
 * - **authenticated** (the default) — a `did:key` agent identity persisted by
 *   `@freeq/bot-kit` under `~/.freeq/bots/<name>/`. With `FREEQ_OWNER_DID` its
 *   delegation certificate names that owner, and the room sees the owner once
 *   the server has verified it: the owner adds this agent's DID under
 *   Settings → Agents in the freeq web app, or with `freeq-bot-id register`,
 *   and the agent reconnects. Without an owner the certificate names the
 *   agent itself (`selfOwned`): a real, stable identity that is honest about
 *   speaking for nobody. `freeq_whoami` says which it is.
 * - **guest** — no SASL, no key, nick only, and nothing attributable. Only
 *   when `FREEQ_GUEST=1`. It used to be the zero-config default, and agents
 *   given the MCP server read "guest" from `freeq_whoami`, dropped the tools
 *   and hand-rolled SASL instead (experiments/ax FINDINGS F14).
 */

import { createHash, randomUUID } from "node:crypto";
import { mkdir, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
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
  /** Authenticated with no owner configured: the certificate names the
   *  agent's own DID, so it speaks for no human. */
  selfOwned?: boolean;
  channels: string[];
  hasBearerToken: boolean;
  server: string;
  /** With an owner configured: whether the server has verified that this
   *  agent acts for that owner. */
  ownerVerified?: boolean;
  /** Why the identity is what it is, in words a caller can act on. */
  note: string;
}

/** The server's verdict on the delegation certificate, as bot-kit reads it. */
export interface ProvenanceVerdict {
  verified: boolean;
  reason: string;
  text: string;
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
  createClient?(cfg: FreeqMcpConfig, nick: string): Promise<ClientFactoryResult>;
  /** Called whenever a bearer token becomes available (SASL success). */
  onBearerToken?(token: string | undefined): void;
  now?(): number;
}

export interface ClientFactoryResult {
    client: SessionClient;
    mode: SessionMode;
    did?: string;
    /** No owner configured: the certificate names the agent itself. */
    selfOwned?: boolean;
    /** Connects in place of `client.connect()`: bot-kit's start, which
     *  also sends the delegation certificate. */
    connect?: () => void;
    /** The server's latest verdict on the certificate, or null. */
    provenance?: () => ProvenanceVerdict | null;
    /** Closes in place of `client.quit()` and `client.disconnect()`:
     *  bot-kit's stop, which also clears its heartbeat, its NOTICE reader
     *  and its timers. */
    close?: (reason: string) => Promise<void>;
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
  #selfOwned = false;
  #provenance?: () => ProvenanceVerdict | null;
  #closeClient?: (reason: string) => Promise<void>;
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
    const verdict = this.#provenance?.() ?? null;
    const ownerVerified =
      mode === "authenticated" && this.#cfg.ownerDid ? verdict?.verified === true : undefined;
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
      ownerVerified,
      note:
        mode === "authenticated"
          ? this.#authenticatedNote(verdict)
          : mode === "guest"
            ? "Connected as a guest (FREEQ_GUEST is set): the nick is not proven and nothing you send is attributable. Unset FREEQ_GUEST to connect with a did:key agent identity; set FREEQ_OWNER_DID to bind it to your DID."
            : "Not connected. Read-only tools work over REST without a connection; joining, sending and asking need one.",
    };
  }

  #authenticatedNote(verdict: ProvenanceVerdict | null): string {
    const did = this.#did ?? "did:key:…";
    const signed =
      "Messages are signed with a per-session key and verifiable via /api/v1/verify/{msgid}.";
    const owner = this.#cfg.ownerDid;
    if (!owner) {
      return `Authenticated as ${did}: a self-owned did:key that speaks for no human (set FREEQ_OWNER_DID to bind it to you). ${signed}`;
    }
    if (verdict?.verified) {
      return `Authenticated as ${did}. The server verified that it acts for ${owner} (${verdict.reason}). ${signed}`;
    }
    // The server's reason for an unsigned certificate already gives the
    // steps below; quote only a reason that says something else, such as a
    // removal, so the note gives the steps once.
    const why = !verdict
      ? " The server has not answered yet."
      : verdict.reason.includes("Settings → Agents")
        ? ""
        : ` The server said: ${verdict.reason}.`;
    return (
      `Authenticated as ${did}. The owner link to ${owner} is not verified, so the room does not see an owner.${why} ` +
      `To verify it, the owner adds this agent's DID (${did}) under Settings → Agents in the freeq web app, ` +
      `or with \`freeq-bot-id register\`, then restarts this MCP server. ${signed}`
    );
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
    const { client, mode, did, selfOwned, connect, provenance, close } = await factory(
      this.#cfg,
      this.#nick,
    );
    this.#client = client;
    this.#mode = mode;
    this.#did = did;
    this.#selfOwned = selfOwned ?? false;
    this.#provenance = provenance;
    this.#closeClient = close;
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

    if (connect) connect();
    else client.connect();
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
    const closeClient = this.#closeClient;
    try {
      if (closeClient) {
        await closeClient(reason);
      } else {
        client.quit?.(reason);
        client.disconnect();
      }
    } finally {
      this.#connected = false;
      this.#client = undefined;
      this.#closeClient = undefined;
      this.#provenance = undefined;
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
/** `mcp-<8 hex>` from a DID: unique per key, stable for as long as it is. */
export function didNick(did: string): string {
  return `mcp-${createHash("sha256").update(did).digest("hex").slice(0, 8)}`;
}

export function defaultNick(seed?: string): string {
  const material = seed ?? `${process.env.HOSTNAME ?? ""}\0${process.env.USER ?? ""}\0mcp`;
  const slug = createHash("sha256").update(material).digest("hex").slice(0, 8);
  return `mcp-${slug}`;
}

/** Where bot-kit keeps per-bot state; matches its own default. */
export function botStateRoot(): string {
  return join(homedir(), ".freeq", "bots");
}

/** The slice of `@freeq/bot-kit` the factory needs; typed so tests can inject a fake. */
export interface BotKitModule {
  loadOrCreateIdentity(opts: { seedPath: string }): Promise<{ did: string }>;
  loadDelegation(opts: { certPath: string }): Promise<{ creator_did: string; signature?: string | null } | null>;
  FreeqBot: {
    create(opts: {
      name: string;
      ownerDid: string;
      nick: string;
      url: string;
      serverOrigin: string;
      channels: string[];
      actorClass: "agent";
      root?: string;
    }): Promise<{
      client: unknown;
      identity: { did: string };
      provenance: ProvenanceVerdict | null;
      start(): Promise<void>;
      stop(opts: { reason: string }): Promise<void>;
    }>;
  };
}

/**
 * Real client factory.
 *
 * Default: a bot-kit `did:key` identity. With `FREEQ_OWNER_DID` its
 * delegation names that human; without it the delegation names the agent
 * itself. Only `FREEQ_GUEST=1` yields a nick-only guest `FreeqClient`.
 */
export async function defaultCreateClient(
  cfg: FreeqMcpConfig,
  nick: string,
  deps: { botKit?: () => Promise<BotKitModule>; root?: string } = {},
): Promise<ClientFactoryResult> {
  if (cfg.guest) {
    const client = new FreeqClient({ url: cfg.wsUrl, nick, channels: cfg.channels });
    return { client: client as unknown as SessionClient, mode: "guest" };
  }

  // Imported lazily so the guest path doesn't pay for bot-kit's disk I/O.
  const kit = await (deps.botKit ?? (() => import("@freeq/bot-kit") as unknown as Promise<BotKitModule>))();
  const root = deps.root ?? botStateRoot();
  const stateDir = join(root, nick);
  await mkdir(stateDir, { recursive: true, mode: 0o700 });

  // Learn our own DID first: a self-owned certificate has to name it, and
  // FreeqBot.create mints the certificate from the owner it is given.
  const identity = await kit.loadOrCreateIdentity({ seedPath: join(stateDir, "agent.key") });
  const selfOwned = !cfg.ownerDid;
  const ownerDid = cfg.ownerDid ?? identity.did;

  // A self-owned cert is unsigned and names nobody, so replacing it once an
  // owner is configured is the upgrade the operator asked for, not data loss.
  // Any other mismatch (a different owner, or a signed cert) is left to
  // bot-kit, whose error names the file and the DIDs involved.
  if (!selfOwned) {
    const certPath = join(stateDir, "delegation.json");
    const existing = await kit.loadDelegation({ certPath });
    if (existing && existing.creator_did === identity.did && !existing.signature) {
      await unlink(certPath);
    }
  }

  // `nick` names the state directory and is derived from the host, so it is
  // the same in every identical container; on the wire that made concurrent
  // agents collide and bot-kit refuse to connect (experiments/ax FINDINGS
  // F19). Unless FREEQ_NICK pins one, the IRC nick comes from the key.
  const ircNick = cfg.nick ?? didNick(identity.did);

  const bot = await kit.FreeqBot.create({
    name: nick,
    ownerDid,
    nick: ircNick,
    url: cfg.wsUrl,
    serverOrigin: cfg.baseUrl,
    channels: cfg.channels,
    actorClass: "agent",
    root,
  });
  // The session drives readiness itself off the client's events, but
  // connects through FreeqBot.start(): that runs the announce sequence,
  // whose PROVENANCE sends the delegation certificate, and reads the
  // server's verdict on it. Its own failures (auth, timeout) reach the
  // session through the same client events.
  return {
    client: bot.client as unknown as SessionClient,
    mode: "authenticated",
    did: bot.identity.did,
    selfOwned,
    connect: () => {
      bot.start().catch(() => undefined);
    },
    provenance: () => bot.provenance,
    close: (reason) => bot.stop({ reason }),
  };
}
