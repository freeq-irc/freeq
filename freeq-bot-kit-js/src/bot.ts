// FreeqBot — high-level wrapper over @freeq/sdk's FreeqClient.
//
// Owns the boilerplate every bot needs:
//   - load / persist did:key identity (32-byte ed25519 seed)
//   - load / mint FreeqBotDelegation/v1 cert
//   - run the announce sequence (PROVENANCE → AGENT REGISTER → MANIFEST? →
//     PRESENCE → HEARTBEAT loop) on every `'ready'`, so reconnects re-announce
//   - own current presence/heartbeat state via `setState()`
//   - reject `start()` on auth failures / pre-ready disconnects / timeout
//
// Construction is async (the SDK's did-key derivation uses Web Crypto).
// Use the static factory: `await FreeqBot.create({...})`.
//
// Shape modeled on discord.js / bolt-js / telegraf / grammY:
//   - events register on the bot directly via `bot.on(...)` (typed delegation
//     to the underlying client)
//   - `.client` exposes the FreeqClient for anything not on the wrapper
//   - the framework does NOT install SIGINT/SIGTERM handlers — README shows
//     the snippet for the caller to wire it themselves

import {
  FreeqClient,
  type FreeqEvents,
  type NickCollisionPolicy,
  type TransportState,
} from "@freeq/sdk";
import { join } from "node:path";
import { botDir } from "./paths.js";
import { loadOrCreateIdentity, type AgentIdentity } from "./identity.js";
import { loadOrMintDelegation, type DelegationCert } from "./delegation.js";
import {
  createDidResolver,
  type DidResolver,
  type ResolveOpts,
} from "./did-resolver.js";
import { matchMention } from "./mention.js";

/** Result of `bot.checkMention(channel, text)`. */
export type MentionResult =
  | { kind: "ignore" }
  | { kind: "cooldown"; remainingMs: number }
  | { kind: "respond"; stripped: string };

/** Signature for the caller-supplied mention matcher. Receives the message
 *  text and the bot's current nick; returns the stripped text on match,
 *  or `null` to ignore. */
export type MentionMatcher = (text: string, nick: string) => string | null;

export type ActorClass = "agent" | "external_agent" | "human";

export interface FreeqBotCreateOptions {
  // ── Required ─────────────────────────────────────────────────────────
  /** Bot name — scopes state under `~/.freeq/bots/<name>/`. */
  name: string;
  /** Owner DID (e.g. `did:plc:…`). Caller-resolved. */
  ownerDid: string;
  /** IRC nickname to register with. */
  nick: string;
  /** WebSocket URL, e.g. `wss://irc.freeq.at/irc`. */
  url: string;

  // ── Optional ─────────────────────────────────────────────────────────
  /** Override the parent dir for bot state. Defaults to `~/.freeq/bots`. */
  root?: string;
  /** Path to the owner's ed25519 seed (32 bytes; the file `freeq-bot-id
   *  --creator-key` reads). When set, the delegation cert is SIGNED by the
   *  owner — the server shows `_verified: true` provided the owner has
   *  registered this key via MSGSIG. Unset → unsigned/declarative cert. */
  creatorKeyPath?: string;
  /** Actor class declared via AGENT REGISTER. Default `"agent"`. */
  actorClass?: ActorClass;
  /** Initial PRESENCE state. Default `"active"`. Carried by heartbeats
   *  until `setState()` changes it. */
  initialState?: string;
  /** Optional initial status string for PRESENCE. */
  initialStatus?: string;
  /** TOML manifest. If set, announce sends `AGENT MANIFEST` after REGISTER. */
  manifest?: string;
  /** Channels to auto-join on connect. */
  channels?: string[];
  /** Heartbeat interval (ms). Default 30_000. */
  heartbeatMs?: number;
  /** Heartbeat TTL (seconds). Default 60. */
  heartbeatTtlS?: number;
  /** Server origin for REST API calls. Defaults to the URL origin. */
  serverOrigin?: string;
  /** Policy on 433 ERR_NICKNAMEINUSE. Default `"refuse"`. */
  onNickCollision?: NickCollisionPolicy;
  /** Register a per-session message-signing key after SASL (SDK default:
   *  true). Set false to skip the mint — outbound messages then get the
   *  server's fallback signature instead of the bot's own. */
  autoMsgSig?: boolean;
  /** Sender-DID resolver tuning. Sets defaults on the per-bot resolver
   *  used by `bot.resolveSenderDid()`. Override per-call via the
   *  method's `opts` argument. */
  senderDidResolver?: {
    /** Default WHOIS race timeout in ms. Default 3000. */
    timeoutMs?: number;
    /** Cache entries expire this many ms after insert. Default 300_000
     *  (5 min). The cache may miss invalidation events for DM-only
     *  users; TTL bounds staleness regardless. */
    cacheTtlMs?: number;
  };
  /** Channel-mention tuning for `bot.checkMention()`. */
  mention?: {
    /** Per-channel cooldown in ms. After a `respond` on a channel,
     *  subsequent addressed messages on the same channel return
     *  `cooldown` until this elapses. Default 60_000. Set to 0 to
     *  disable. */
    cooldownMs?: number;
    /** Override the default addressing rule. Receives the message text
     *  and the bot's current nick; returns the stripped text on match,
     *  or `null` to ignore. Default matches `@<nick>` or `<nick>:`/
     *  `<nick>,` anywhere (with word boundary). */
    matcher?: (text: string, nick: string) => string | null;
  };
}

export interface FreeqBotStartOptions {
  /** Reject `start()` if `'ready'` isn't reached within this many ms.
   *  Default 30_000. */
  timeoutMs?: number;
}

export interface FreeqBotStopOptions {
  /** QUIT reason. Defaults to `"shutting down"`. */
  reason?: string;
  /** How long to wait after PRESENCE=offline/QUIT before disconnecting.
   *  Default 250ms. */
  drainMs?: number;
}

export class FreeqBot {
  /** Underlying SDK client — `bot.on(...)` proxies handlers here. For typed
   *  methods not surfaced on FreeqBot, call `bot.client.foo(...)`. */
  readonly client: FreeqClient;
  /** Resolved did:key identity. */
  readonly identity: AgentIdentity;
  /** FreeqBotDelegation/v1 cert binding identity to owner. */
  readonly delegation: DelegationCert;
  /** Absolute path under which this bot's state lives. */
  readonly stateDir: string;

  readonly #actorClass: ActorClass;
  readonly #manifest: string | undefined;
  readonly #heartbeatMs: number;
  readonly #heartbeatTtlS: number;

  #currentState: string;
  #currentStatus: string | undefined;
  #currentTask: string | undefined;
  #heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  #readyHandler: (() => void) | null = null;
  #started = false;
  #stopped = false;
  readonly #didResolver: DidResolver;

  readonly #mentionCooldownMs: number;
  readonly #mentionMatcher: MentionMatcher;
  readonly #mentionLastRespond = new Map<string, number>(); // channel.toLowerCase() → ms

  /** Use `FreeqBot.create(...)` instead. */
  private constructor(args: {
    client: FreeqClient;
    identity: AgentIdentity;
    delegation: DelegationCert;
    stateDir: string;
    actorClass: ActorClass;
    manifest: string | undefined;
    heartbeatMs: number;
    heartbeatTtlS: number;
    initialState: string;
    initialStatus: string | undefined;
    didResolverTimeoutMs: number | undefined;
    didResolverCacheTtlMs: number | undefined;
    mentionCooldownMs: number;
    mentionMatcher: MentionMatcher;
  }) {
    this.client = args.client;
    this.identity = args.identity;
    this.delegation = args.delegation;
    this.stateDir = args.stateDir;
    this.#actorClass = args.actorClass;
    this.#manifest = args.manifest;
    this.#heartbeatMs = args.heartbeatMs;
    this.#heartbeatTtlS = args.heartbeatTtlS;
    this.#currentState = args.initialState;
    this.#currentStatus = args.initialStatus;
    this.#didResolver = createDidResolver(this.client, {
      timeoutMs: args.didResolverTimeoutMs,
      cacheTtlMs: args.didResolverCacheTtlMs,
    });
    this.#mentionCooldownMs = args.mentionCooldownMs;
    this.#mentionMatcher = args.mentionMatcher;
  }

  /** Async factory: loads/creates identity + cert from disk, constructs the
   *  FreeqClient with crypto SASL, returns a ready-to-`.start()` bot. */
  static async create(opts: FreeqBotCreateOptions): Promise<FreeqBot> {
    const stateDir = await botDir(opts.name, { root: opts.root });
    const identity = await loadOrCreateIdentity({
      seedPath: join(stateDir, "agent.key"),
    });
    const delegation = await loadOrMintDelegation({
      certPath: join(stateDir, "delegation.json"),
      agentDid: identity.did,
      ownerDid: opts.ownerDid,
      creatorKeyPath: opts.creatorKeyPath,
    });

    const client = new FreeqClient({
      url: opts.url,
      nick: opts.nick,
      channels: opts.channels,
      serverOrigin: opts.serverOrigin,
      onNickCollision: opts.onNickCollision ?? "refuse",
      sasl: {
        did: identity.did,
        method: "crypto",
        signer: identity.didKey.signer,
        token: "",
        pdsUrl: "",
      },
      // The SDK's default per-session MSGSIG key stays on: a bot signs its
      // messages and mutations like every other client. (The did:key the bot
      // authenticates with is a separate concern — signing with it directly
      // is the DID-document-anchored model, not built yet.)
      autoMsgSig: opts.autoMsgSig,
    });

    const defaultMentionMatcher: MentionMatcher = (text, nick) => {
      const r = matchMention(nick, text);
      return r ? r.stripped : null;
    };

    return new FreeqBot({
      client,
      identity,
      delegation,
      stateDir,
      actorClass: opts.actorClass ?? "agent",
      manifest: opts.manifest,
      heartbeatMs: opts.heartbeatMs ?? 30_000,
      heartbeatTtlS: opts.heartbeatTtlS ?? 60,
      initialState: opts.initialState ?? "active",
      initialStatus: opts.initialStatus,
      didResolverTimeoutMs: opts.senderDidResolver?.timeoutMs,
      didResolverCacheTtlMs: opts.senderDidResolver?.cacheTtlMs,
      mentionCooldownMs: opts.mention?.cooldownMs ?? 60_000,
      mentionMatcher: opts.mention?.matcher ?? defaultMentionMatcher,
    });
  }

  // ── Typed event delegation ─────────────────────────────────────────────

  /** Register a handler. Typed delegation to `client.on`. */
  on<K extends keyof FreeqEvents>(event: K, handler: FreeqEvents[K]): this {
    this.client.on(event, handler);
    return this;
  }

  /** Unregister a handler. */
  off<K extends keyof FreeqEvents>(event: K, handler: FreeqEvents[K]): this {
    this.client.off(event, handler);
    return this;
  }

  /** Register a one-shot handler. */
  once<K extends keyof FreeqEvents>(event: K, handler: FreeqEvents[K]): this {
    this.client.once(event, handler);
    return this;
  }

  // ── State management ───────────────────────────────────────────────────

  /** Update the bot's current state. Sends an immediate PRESENCE update and
   *  causes subsequent heartbeats to carry the new state.
   *
   *  Valid states include: `online`, `idle`, `active`, `executing`,
   *  `waiting_for_input`, `blocked_on_permission`, `blocked_on_budget`,
   *  `degraded`, `paused`, `sandboxed`, `revoked`, `offline`. */
  setState(state: string, status?: string, task?: string): void {
    this.#currentState = state;
    this.#currentStatus = status;
    this.#currentTask = task;
    try {
      this.client.setPresence(state, status, task);
    } catch {
      // Socket may be down; next 'ready' will re-announce with current state.
    }
  }

  /** Read the bot's current state (last value passed to `setState()`). */
  get state(): string {
    return this.#currentState;
  }

  // ── Sender DID resolution ──────────────────────────────────────────────

  /** Resolve the sender's DID for a PRIVMSG. Returns null if the message
   *  has no account-tag, the cache doesn't know the sender, and WHOIS
   *  times out (or is disabled).
   *
   *  Sources, in priority order:
   *    1. `msg.tags.account` — authoritative for the message
   *    2. nick→DID cache (populated automatically by `memberDid` events;
   *       invalidated by `userRenamed` / `userQuit` and a 5-minute TTL)
   *    3. WHOIS round-trip, raced against `timeoutMs` (default 3000ms)
   *
   *  Use `opts.cache: false` for a fresh lookup every call (no stale
   *  cache); `opts.whois: false` to skip the round-trip; both false for
   *  strict mode (account-tag only). */
  async resolveSenderDid(
    msg: { from: string; tags?: Record<string, string> },
    opts?: ResolveOpts,
  ): Promise<string | null> {
    return this.#didResolver.resolve(msg, opts);
  }

  // ── Channel addressing ─────────────────────────────────────────────────

  /** Classify a channel message as addressed-to-this-bot or not.
   *
   *  Reads the bot's current nick live (so server-side renames are picked
   *  up without re-wiring) and runs the configured matcher. Default
   *  matcher accepts `@<nick>` or `<nick>:`/`<nick>,` anywhere in the
   *  message; callers can pass their own via `FreeqBot.create({mention:
   *  {matcher}})`.
   *
   *  Returns one of:
   *    - `{kind: "ignore"}` — not addressed
   *    - `{kind: "cooldown", remainingMs}` — addressed, but the bot
   *      already responded on this channel within the cooldown window
   *    - `{kind: "respond", stripped}` — bot was addressed; `stripped`
   *      is the message text with the addressing prefix removed
   *
   *  A `respond` result records "now" as the channel's last-respond
   *  timestamp before returning, so the next addressed message on the
   *  same channel within `cooldownMs` returns `cooldown`. Different
   *  channels have independent cooldowns. */
  checkMention(channel: string, text: string): MentionResult {
    const nick = this.client.nick;
    if (!nick) return { kind: "ignore" };
    const stripped = this.#mentionMatcher(text, nick);
    if (stripped === null) return { kind: "ignore" };

    const key = channel.toLowerCase();
    const now = Date.now();
    if (this.#mentionCooldownMs > 0) {
      const last = this.#mentionLastRespond.get(key);
      if (last !== undefined) {
        const remainingMs = last + this.#mentionCooldownMs - now;
        if (remainingMs > 0) return { kind: "cooldown", remainingMs };
      }
    }
    this.#mentionLastRespond.set(key, now);
    return { kind: "respond", stripped };
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  /** Connect, await `'ready'`, run the announce sequence + heartbeat loop.
   *  Rejects on SASL failure, pre-ready disconnect, or timeout. */
  async start(opts: FreeqBotStartOptions = {}): Promise<void> {
    if (this.#started) {
      throw new Error("FreeqBot.start() called more than once");
    }
    this.#started = true;
    const timeoutMs = opts.timeoutMs ?? 30_000;

    // Persistent handler: re-runs on every 'ready' so reconnects re-announce.
    this.#readyHandler = (): void => this.#announceAndHeartbeat();
    this.client.on("ready", this.#readyHandler);

    this.client.connect();

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`timeout waiting for ready (${timeoutMs}ms)`));
      }, timeoutMs);

      const onReady = (): void => {
        cleanup();
        resolve();
      };
      const onAuthError = (msg: string): void => {
        cleanup();
        reject(new Error(`SASL auth failed: ${msg}`));
      };
      const onState = (state: TransportState): void => {
        if (state === "disconnected") {
          cleanup();
          reject(new Error("disconnected before ready"));
        }
      };
      const onError = (msg: string): void => {
        cleanup();
        reject(new Error(msg));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.client.off("ready", onReady);
        this.client.off("authError", onAuthError);
        this.client.off("connectionStateChanged", onState);
        this.client.off("error", onError);
      };

      this.client.once("ready", onReady);
      this.client.once("authError", onAuthError);
      this.client.on("connectionStateChanged", onState);
      this.client.once("error", onError);
    });
  }

  /** Graceful shutdown: stop heartbeat, send PRESENCE=offline + QUIT,
   *  wait for the WebSocket send buffer to drain, then disconnect.
   *  Idempotent.
   *
   *  Note: the server applies a 30-second ghost period to DID-authenticated
   *  sessions (`QUIT_GRACE_SECS` in connection/mod.rs). The bot's channel
   *  membership is preserved for ~30s after disconnect so a quick
   *  reconnect doesn't churn JOIN/QUIT. To other clients, this looks like
   *  the bot lingering after shutdown — it's intentional server-side. */
  async stop(opts: FreeqBotStopOptions | string = {}): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;

    const { reason = "shutting down", drainMs = 2000 } =
      typeof opts === "string" ? { reason: opts } : opts;

    if (this.#heartbeatTimer) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }
    if (this.#readyHandler) {
      this.client.off("ready", this.#readyHandler);
      this.#readyHandler = null;
    }
    try {
      this.client.setPresence("offline");
      this.client.raw(`QUIT :${reason}`);
    } catch {
      // socket may already be gone; nothing to flush
    }
    // Wait for the send buffer to actually drain (poll bufferedAmount).
    // The previous fixed-250ms sleep was racy: process.exit() doesn't wait
    // for in-flight WebSocket writes, so PRESENCE/QUIT could be dropped.
    await this.client.flush(drainMs);
    this.client.disconnect();
    this.#didResolver.close();
  }

  // ── Internal ───────────────────────────────────────────────────────────

  /** Runs on every `'ready'` (initial + each reconnect). */
  #announceAndHeartbeat(): void {
    // Reset any prior heartbeat — reconnects start fresh.
    if (this.#heartbeatTimer) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }

    try {
      this.client.submitProvenance(this.delegation);
      this.client.registerAgent(this.#actorClass);
      if (this.#manifest) {
        this.client.submitManifest(this.#manifest);
      }
      this.client.setPresence(this.#currentState, this.#currentStatus, this.#currentTask);
    } catch {
      // Socket likely gone mid-announce; next 'ready' will retry.
      return;
    }

    const beat = (): void => {
      try {
        this.client.sendHeartbeat(this.#currentState, this.#heartbeatTtlS);
      } catch {
        // socket gone; next 'ready' will re-arm
      }
    };
    beat();
    this.#heartbeatTimer = setInterval(beat, this.#heartbeatMs);
  }
}
