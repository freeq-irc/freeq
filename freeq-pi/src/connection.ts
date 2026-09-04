/**
 * freeq connection lifecycle for the pi extension.
 *
 * Contract (build spec §3 M1): connection problems must NEVER break the pi
 * session. Every failure degrades to "offline" and is reported once; the
 * caller keeps working. Nothing here throws into pi's event loop.
 */

import { FreeqBot, matchMention } from "@freeq/bot-kit";
import type {
  ActEventPayload,
  CoordinationEventPayload,
  Message,
  PresencePayload,
} from "@freeq/sdk";
import { actTags } from "@freeq/sdk";
import { defaultNick, projectBotName, projectNick } from "./identity.js";
import { describeMeta, formatStatus, parseStatus, type SessionMeta } from "./presence.js";
import {
  buildHello,
  helloTags,
  parseHello,
  PI_HELLO,
  PI_HELLO_ACK,
} from "./discovery.js";
import { scrubOutbound } from "./scrub.js";
import {
  AskRegistry,
  encodePayload,
  newRequestId,
  parseAskReply,
  parseAskRequest,
  PI_ASK,
  PI_ASK_REPLY,
  type AskResult,
} from "./ask.js";

export type ConnState = "offline" | "connecting" | "online" | "error";

/**
 * The slice of bot-kit this class actually uses.
 *
 * Declared so the connection can be driven by a fake in tests. This file owns
 * the reconnect/announce/ask state machine — the part that broke in
 * production — and none of that logic needs a real socket to exercise.
 */
export interface BotLike {
  on(event: string, handler: (...args: never[]) => void): unknown;
  start(): Promise<unknown>;
  stop(reason?: string): Promise<unknown>;
  setState(state: string, status?: string, task?: string): void;
  checkMention(channel: string, text: string): { kind: string; stripped?: string };
  resolveSenderDid(msg: { from: string; tags?: Record<string, string> }): Promise<string | null>;
  readonly identity: { did: string };
  readonly client: {
    readonly nick: string | null;
    join(channel: string): void;
    raw(line: string): void;
    sendMessage(target: string, text: string): void;
    sendTagmsg(target: string, tags: Record<string, string>): void;
    sendAct(
      target: string,
      tags: Record<string, string>,
      opts?: { humanText?: string; taskId?: string },
    ): Promise<string>;
    readonly signing: { getPublicKey(): string | null };
  };
}

/** How a bot gets built. Overridden in tests. */
export type BotFactory = (opts: {
  name: string;
  ownerDid: string;
  /** Owner's creator seed; when set, bot-kit signs the delegation cert. */
  creatorKeyPath?: string;
  nick: string;
  url: string;
  root?: string;
  channels?: string[];
  actorClass: "agent";
  initialState: string;
  initialStatus: string;
  onNickCollision: "auto-suffix";
  mention: { matcher: (text: string, nick: string) => string | null };
}) => Promise<BotLike>;

export interface Peer {
  nick: string;
  /**
   * Server-resolved DID where available. A DID learned only from a peer's
   * self-asserted hello payload is NOT recorded here — see discovery.ts.
   */
  did?: string;
  state: string;
  meta: SessionMeta;
  /** Channel the peer was last seen announcing in. */
  channel?: string;
  /** True once we've seen a pi hello (i.e. it's an agent we can talk to). */
  isPi: boolean;
  /** epoch ms of last update */
  seen: number;
}

export interface ConnectionOptions {
  ownerDid: string;
  /** Owner's creator seed; when set, bot-kit signs the delegation cert. */
  creatorKeyPath?: string;
  server: string;
  slug: string;
  nick?: string;
  channels: string[];
  meta: SessionMeta;
  /** Where bot-kit stores identity/delegation. Tests override this. */
  root?: string;
  /** Reported to the host for user-visible notices. */
  onNotice?: (text: string, level: "info" | "warning" | "error") => void;
  /** Called when outbound redaction fired, so the user can be told. */
  onScrub?: (hits: string[], target: string) => void;
  /** Called when the server refuses a JOIN, with the channel and the reason. */
  onJoinRefused?: (channel: string, reason: string) => void;
  /** Called when we left a channel the server put us in unasked. */
  onUnexpectedChannel?: (channel: string) => void;
  /** Inbound channel/DM messages (routed through the tier pipeline). */
  onMessage?: (channel: string, msg: Message) => void;
  /** Override how the bot is created. Tests inject a fake; production omits it. */
  botFactory?: BotFactory;
  /** How long to wait for the session signing key. Shortened in tests. */
  signingKeyTimeoutMs?: number;
  /**
   * An inbound `ask` from a peer. The host decides (via the tier pipeline)
   * whether to answer; it must call `replyToAsk` exactly once either way.
   */
  onAsk?: (ask: InboundAsk) => void;
  /** A `freeq.at/act` task event (handoffs). */
  onActEvent?: (ev: ActEventPayload) => void;
  /**
   * We are online, on the first connect and after every reconnect.
   *
   * The transport recovers a dropped socket on its own, so nothing above here
   * otherwise learns that a gap happened — and a session that was cut off
   * mid-task needs to ask the server what is still assigned to it.
   */
  onOnline?: () => void;
}

export interface InboundAsk {
  req: string;
  from: string;
  did: string | null;
  channel: string;
  question: string;
}

const RECONNECT_INITIAL_MS = 2_000;
const RECONNECT_MAX_MS = 60_000;

export class FreeqConnection {
  #bot: BotLike | undefined;
  #state: ConnState = "offline";
  readonly #joined = new Set<string>();
  readonly #refused = new Map<string, string>();
  #lastError: string | undefined;
  #peers = new Map<string, Peer>();
  #opts: ConnectionOptions;
  #meta: SessionMeta;
  /** The server's verdict on our delegation cert, from its PROVENANCE reply. */
  #provenanceNotice: string | undefined;
  #stopped = false;
  /** Guards against two concurrent start() calls building two bots. */
  #starting = false;
  #retry = RECONNECT_INITIAL_MS;
  #timer: NodeJS.Timeout | undefined;
  /** Notices are deduped: a flapping connection must not spam the TUI. */
  #noticed = new Set<string>();
  #asks = new AskRegistry((reason) => this.#opts.onNotice?.(`freeq ask: ${reason}`, "warning"));

  constructor(opts: ConnectionOptions) {
    this.#opts = opts;
    this.#meta = opts.meta;
  }

  get state(): ConnState {
    return this.#state;
  }
  get lastError(): string | undefined {
    return this.#lastError;
  }
  get nick(): string | undefined {
    return this.#bot?.client.nick ?? undefined;
  }
  get did(): string | undefined {
    return this.#bot?.identity.did;
  }
  /** Latest server verdict on our delegation, if any was seen this connection. */
  get provenanceNotice(): string | undefined {
    return this.#provenanceNotice;
  }

  get meta(): SessionMeta {
    return this.#meta;
  }
  get bot(): BotLike | undefined {
    return this.#bot;
  }

  /** Peers seen recently, most-recent first. */
  peers(): Peer[] {
    return [...this.#peers.values()].sort((a, b) => b.seen - a.seen);
  }

  #notice(text: string, level: "info" | "warning" | "error", key?: string): void {
    const k = key ?? text;
    if (this.#noticed.has(k)) return;
    this.#noticed.add(k);
    this.#opts.onNotice?.(text, level);
  }

  /**
   * Connect. Resolves once the attempt settles (online or scheduled retry) —
   * never rejects.
   */
  async start(): Promise<void> {
    if (this.#stopped) return;
    // One bot, one socket, one server session per installation. Re-entering
    // start() (a retry firing while a connect is in flight, session_start
    // racing /freeq login) used to build a second bot and leave both live.
    if (this.#starting || this.#bot) return;
    this.#starting = true;
    this.#state = "connecting";
    try {
      const create: BotFactory =
        this.#opts.botFactory ?? ((o) => FreeqBot.create(o) as unknown as Promise<BotLike>);
      const bot = await create({
        // Identity is per project: a music repo and a work repo are different
        // participants. The state dir and the nick both carry the project so
        // the key is stable across restarts and the name says whose and which.
        name: projectBotName(this.#opts.slug, this.#meta.project),
        ownerDid: this.#opts.ownerDid,
        creatorKeyPath: this.#opts.creatorKeyPath,
        nick: projectNick(this.#opts.nick ?? defaultNick(this.#opts.slug), this.#meta.project),
        url: this.#opts.server,
        root: this.#opts.root,
        channels: this.#opts.channels,
        actorClass: "agent",
        initialState: "active",
        initialStatus: formatStatus(this.#meta),
        // A second pi on the same box shouldn't fight over the nick.
        onNickCollision: "auto-suffix",
        // ...but auto-suffix means the server may hand us `pi-foo-a1b2` when
        // teammates were told to address `pi-foo`. Match BOTH the live nick
        // and the configured one, or a suffixed agent silently stops
        // answering to its own name. (Caught by the M3 room harness.)
        mention: { matcher: (text: string, nick: string) => this.#matchNames(text, nick) },
      });
      this.#bot = bot;

      bot.on("message", (channel: string, msg: Message) => {
        if (msg.isSelf) return;
        try {
          this.#opts.onMessage?.(channel, msg);
        } catch (err) {
          // An extension-side handler bug must not kill the connection.
          this.#opts.onNotice?.(
            `freeq: inbound handler error: ${(err as Error).message}`,
            "error",
          );
        }
      });

      bot.on("presence", (p: PresencePayload) => this.#onPresence(p));

      // The server answers PROVENANCE with one NOTICE: "Provenance verified:
      // ..." or "Provenance stored (unverified): <why>". Keep the latest so
      // /freeq authorize verify can report the server's own verdict rather
      // than guessing.
      bot.on("systemMessage", (_from: string, text: string) => {
        if (/^Provenance /.test(text)) this.#provenanceNotice = text;
      });

      // Task events (handoffs). Replayed events arrive here too, which is
      // how an offer made while we were offline reaches us.
      //
      // Unlike chat, our OWN act events are NOT filtered out. Two reasons,
      // both found the hard way: (1) the echo of our own `accept` is what
      // advances our local state — drop it and the assignee can never reach
      // `complete`; (2) after a lost or fresh view, history replay of our own
      // offers is how we rebuild them. Re-applying is safe: the store treats
      // a repeat offer as a duplicate and a repeat move as an illegal step.
      bot.on("actEvent", (ev: ActEventPayload) => {
        try {
          this.#opts.onActEvent?.(ev);
        } catch (err) {
          this.#opts.onNotice?.(`freeq: task handler error: ${(err as Error).message}`, "error");
        }
      });

      // Peer discovery rides coordination events, not presence — the server
      // drops presence status for active agents (see discovery.ts).
      bot.on("coordinationEvent", (e: CoordinationEventPayload) => {
        void this.#onCoordinationEvent(e);
      });

      // Announce into each channel once we're actually in it.
      bot.on("channelJoined", (channel: string) => {
        this.#joined.add(channel.toLowerCase());
        // The server restores a session's saved channel set on reconnect, so
        // a channel this project no longer wants comes back by itself and
        // stays for good: config asks, server remembers, server wins. Leave
        // anything we did not ask for. Announcing into it first would be
        // announcing our arrival somewhere we are about to leave.
        const wanted = this.#opts.channels.map((c) => c.toLowerCase());
        if (wanted.length && !wanted.includes(channel.toLowerCase())) {
          this.#joined.delete(channel.toLowerCase());
          this.#bot?.client.raw(`PART ${channel} :not this project's channel`);
          this.#opts.onUnexpectedChannel?.(channel);
          return;
        }
        this.#refused.delete(channel.toLowerCase());
        this.#announce(channel, PI_HELLO);
      });

      bot.on("channelLeft", (channel: string) => {
        this.#joined.delete(channel.toLowerCase());
      });

      // A JOIN that the server refuses. Without this the client sends JOIN,
      // the server says 477, nobody listens, and every surface goes on
      // reporting the channel as joined - which is how #freeq-dev sat in the
      // footer for a whole session while the agent was not in it. Being
      // wrong about where you are is worse than being nowhere.
      bot.on("joinRejected", (channel: string, numeric: string, reason: string) => {
        if (!channel) return;
        this.#joined.delete(channel.toLowerCase());
        // 477 keeps its own word because it is the one with a remedy the
        // agent can perform itself.
        this.#refused.set(channel.toLowerCase(), numeric === "477" ? "policy" : reason);
        this.#opts.onJoinRefused?.(channel, numeric === "477" ? "policy" : reason);
      });

      // Transport state is only 'connected' | 'connecting' | 'disconnected'.
      //
      // IMPORTANT: the SDK transport auto-reconnects, and bot-kit re-runs its
      // announce sequence on every 'ready'. So a dropped socket is ALREADY
      // being handled one layer down, and this handler must not start a
      // competing recovery. It previously tore the bot down and built a fresh
      // one on every 'disconnected', which raced the transport's own retry and
      // left several live sessions on one DID — the server logged endless
      // ghost-mode churn and re-registration, and peers saw a hello storm.
      bot.on("connectionStateChanged", (s: string) => {
        if (s === "connected") {
          this.#goOnline();
          this.#noticed.delete("offline");
        } else if (s === "connecting") {
          if (this.#state === "online") this.#state = "connecting";
        } else if (s === "disconnected" && !this.#stopped) {
          this.#state = "connecting";
          this.#notice(
            "freeq: connection dropped — the transport is reconnecting; pi continues normally",
            "warning",
            "offline",
          );
        }
      });

      bot.on("authError", (e: string) => {
        this.#lastError = e;
        this.#notice(`freeq: authentication failed — ${e}`, "error", "auth");
      });

      await bot.start();
      this.#goOnline();
      this.#retry = RECONNECT_INITIAL_MS;
    } catch (err) {
      // Only the INITIAL connect is retried here. Once a bot exists, the
      // transport owns reconnection (see connectionStateChanged above).
      this.#state = "error";
      this.#lastError = (err as Error).message;
      this.#notice(
        `freeq: could not connect (${this.#lastError}) — pi continues normally`,
        "warning",
        "offline",
      );
      await this.#discardBot();
      this.#scheduleInitialRetry();
    } finally {
      this.#starting = false;
    }
  }

  /**
   * Become online, telling the host once per gap.
   *
   * Both `bot.start()` returning and the transport's own 'connected' event
   * land here, and a reconnect fires the second one again — so the transition
   * is what is reported, not the event. A handler that resumes work would
   * otherwise run twice for one connect.
   */
  #goOnline(): void {
    const wasOnline = this.#state === "online";
    this.#state = "online";
    if (wasOnline) return;
    try {
      this.#opts.onOnline?.();
    } catch (err) {
      this.#opts.onNotice?.(`freeq: online handler error: ${(err as Error).message}`, "error");
    }
  }

  /** Tear down a half-built bot so a retry cannot leave two sessions live. */
  async #discardBot(): Promise<void> {
    const bot = this.#bot;
    this.#bot = undefined;
    if (!bot) return;
    try {
      await bot.stop("discarded");
    } catch {
      /* already gone */
    }
  }

  #scheduleInitialRetry(): void {
    if (this.#stopped || this.#timer || this.#bot) return;
    const delay = this.#retry;
    this.#retry = Math.min(this.#retry * 2, RECONNECT_MAX_MS);
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (this.#stopped || this.#bot) return;
      void this.start();
    }, delay);
    // Don't hold the process open just to retry a chat connection.
    this.#timer.unref?.();
  }

  #onPresence(p: PresencePayload): void {
    if (!p.nick) return;
    if (this.#isSelf(p.nick)) return;
    const key = p.nick.toLowerCase();
    if (p.state === "offline") {
      this.#peers.delete(key);
      return;
    }
    // Presence updates liveness; metadata comes from hellos (the server
    // cannot relay status for active agents). Never downgrade known metadata.
    const prev = this.#peers.get(key);
    this.#peers.set(key, {
      nick: p.nick,
      did: p.did ?? prev?.did,
      state: p.state,
      meta: prev?.meta ?? parseStatus(p.status),
      channel: prev?.channel,
      isPi: prev?.isPi ?? false,
      seen: Date.now(),
    });
  }

  #isSelf(nick: string): boolean {
    return !!this.nick && nick.toLowerCase() === this.nick.toLowerCase();
  }

  /** Poll until this session can sign act documents, or give up. */
  async #awaitSigningKey(timeoutMs = this.#opts.signingKeyTimeoutMs ?? 15_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.#bot?.client.signing.getPublicKey()) return true;
      await new Promise((r) => setTimeout(r, 250));
    }
    return !!this.#bot?.client.signing.getPublicKey();
  }

  /** Match a mention of the live nick OR the nick we asked the server for. */
  #matchNames(text: string, liveNick: string): string | null {
    const names = new Set<string>();
    if (liveNick) names.add(liveNick);
    const desired = this.#opts.nick;
    if (desired) names.add(desired);
    // The project nick is what we actually registered as; the base nick is
    // what teammates were told. "chad-bot" in a room where only
    // "chad-bot-freeq" is present should still get an answer.
    const base = this.#opts.nick ?? defaultNick(this.#opts.slug);
    names.add(projectNick(base, this.#meta.project));
    for (const name of names) {
      const hit = matchMention(name, text);
      if (hit) return hit.stripped;
    }
    return null;
  }

  /** Broadcast our hello (or an ack) into a channel. */
  #announce(channel: string, type: typeof PI_HELLO | typeof PI_HELLO_ACK): void {
    if (!this.#bot) return;
    try {
      this.#bot.client.sendTagmsg(channel, helloTags(type, buildHello(this.#meta, this.did)));
    } catch {
      /* discovery is best-effort */
    }
  }

  /** Re-announce into every joined channel (after a metadata change). */
  announceAll(): void {
    for (const channel of this.#opts.channels) this.#announce(channel, PI_HELLO);
  }

  async #onCoordinationEvent(e: CoordinationEventPayload): Promise<void> {
    if (this.#isSelf(e.from)) return;

    if (e.eventType === PI_ASK) {
      const req = parseAskRequest(e.payload);
      if (!req) return;
      const did = e.did ?? (await this.resolveSenderDid({ from: e.from, tags: e.tags }));
      this.#opts.onAsk?.({
        req: req.req,
        from: e.from,
        did,
        channel: e.channel,
        question: req.q,
      });
      return;
    }

    if (e.eventType === PI_ASK_REPLY) {
      const reply = parseAskReply(e.payload);
      if (reply) this.#asks.deliver(reply, e.from);
      return;
    }

    if (e.eventType !== PI_HELLO && e.eventType !== PI_HELLO_ACK) return;

    const hello = parseHello(e.payload);
    if (!hello) return;

    // Authoritative DID only: prefer the SDK's resolved value (account tag /
    // WHOIS), fall back to a lookup. The payload's self-asserted `did` is
    // deliberately ignored for identity.
    const did = e.did ?? (await this.resolveSenderDid({ from: e.from, tags: e.tags })) ?? undefined;

    const key = e.from.toLowerCase();
    const prev = this.#peers.get(key);
    this.#peers.set(key, {
      nick: e.from,
      did: did ?? prev?.did,
      state: prev?.state ?? "online",
      meta: hello.meta,
      channel: e.channel,
      isPi: true,
      seen: Date.now(),
    });

    // Answer a hello so the newcomer learns about us; never ack an ack.
    if (e.eventType === PI_HELLO && e.channel.startsWith("#")) {
      this.#announce(e.channel, PI_HELLO_ACK);
    }
  }

  /**
   * Report what this agent is doing right now.
   *
   * States are freeq's agent presence vocabulary (snake_case on the wire):
   * `active` when idle-but-available, `executing` while running a turn,
   * `waiting_for_input` when blocked on its human, `paused`, `degraded`, …
   *
   * Note the asymmetry documented in freeq-irc/freeq#70: the server relays
   * the status STRING for away-ish states (`executing` included) but drops it
   * for `online`/`active`/`idle`, because it rides the parameterless "back
   * from away" AWAY. So "what I'm working on" propagates while working —
   * which is exactly when it matters — and goes quiet when idle.
   *
   * `task` is an act task id, so a channel can tie a working agent to the
   * handoff it accepted.
   */
  setWorkState(state: string, status?: string, task?: string): void {
    if (!this.#bot || this.#state !== "online") return;
    try {
      // One presence slot, two things that wanted it: the session metadata
      // (project, branch, model) and the current work label. They used to
      // overwrite each other, so a peer's roster showed whichever was pushed
      // last and the metadata fields went missing the moment work started.
      // Compose instead: the label rides as 'doing=' inside the same k=v
      // string, so a peer gets both and neither is lost.
      const composed = formatStatus({ ...this.#meta, doing: status });
      this.#bot.setState(state, composed, task);
    } catch {
      /* presence is best-effort and must never break a turn */
    }
  }

  /**
   * Push updated session metadata.
   *
   * Sets presence (liveness, and status for any client that can read it) AND
   * re-announces via hello, which is what peers actually learn metadata from.
   */
  updateMeta(meta: SessionMeta): void {
    this.#meta = meta;
    try {
      this.#bot?.setState("active", formatStatus(meta));
    } catch {
      /* presence is best-effort */
    }
    this.announceAll();
  }

  /**
   * Central outbound redaction. EVERY path that puts text on the wire goes
   * through here — keeping it in one place is what makes the guarantee
   * auditable, rather than relying on each call site to remember.
   */
  /**
   * Scrub text bound for the wire by any path - a channel message, an ask, a
   * spoken line in a call. Public so the AV tool gets the same redaction as
   * everything else; a secret said out loud is still a leaked secret.
   */
  scrubForWire(text: string, target: string): string {
    return this.#clean(text, target);
  }

  #clean(text: string, target: string): string {
    const { text: scrubbed, hits } = scrubOutbound(text);
    if (hits.length) this.#opts.onScrub?.(hits, target);
    return scrubbed;
  }

  /** Channels the server has CONFIRMED we are in, not the ones we asked for. */
  joinedChannels(): string[] {
    return [...this.#joined];
  }

  /** Channels whose JOIN was refused, and why. */
  refusedChannels(): Array<{ channel: string; reason: string }> {
    return [...this.#refused].map(([channel, reason]) => ({ channel, reason }));
  }

  /** Accept a channel's join policy, then retry the join. */
  acceptPolicy(channel: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.raw(`POLICY ${channel} ACCEPT`);
    this.#bot.client.raw(`JOIN ${channel}`);
    return true;
  }

  join(channel: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.join(channel);
    return true;
  }

  leave(channel: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.raw(`PART ${channel}`);
    return true;
  }

  send(target: string, text: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.sendMessage(target, this.#clean(text, target));
    return true;
  }

  sendTags(target: string, tags: Record<string, string>): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.sendTagmsg(target, tags);
    return true;
  }

  /**
   * Ask a peer a question and wait for exactly one reply.
   *
   * The request id is minted here and carried in the payload — correctness
   * never depends on IRC reply tags.
   */
  async ask(to: string, question: string, timeoutMs?: number): Promise<AskResult> {
    if (!this.#bot || this.#state !== "online") {
      return { ok: false, error: "freeq is offline" };
    }
    const req = newRequestId();
    const { encoded } = encodePayload({ req, q: this.#clean(question, to) }, "q");
    const promise = this.#asks.create(req, to, timeoutMs);
    try {
      this.#bot.client.sendTagmsg(to, {
        "+freeq.at/event": PI_ASK,
        "+freeq.at/payload": encoded,
      });
    } catch (err) {
      this.#asks.deliver({ req, err: `send failed: ${(err as Error).message}` }, to);
    }
    return promise;
  }

  /** Answer an inbound ask. Safe to call once per ask. */
  replyToAsk(ask: InboundAsk, answer: string | undefined, error?: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    const body: Record<string, unknown> = error
      ? { req: ask.req, err: error }
      : { req: ask.req, a: this.#clean(answer ?? "", ask.from) };
    const { encoded } = encodePayload(body, error ? "err" : "a");
    try {
      this.#bot.client.sendTagmsg(ask.from, {
        "+freeq.at/event": PI_ASK_REPLY,
        "+freeq.at/payload": encoded,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Is this channel message addressed to us? Delegates to bot-kit, which
   * also applies a per-channel cooldown — that cooldown is what stops two
   * agents that mention each other from ping-ponging forever.
   */
  checkMention(channel: string, text: string): { addressed: boolean; stripped: string; cooling: boolean } {
    const r = this.#bot?.checkMention(channel, text);
    if (!r) return { addressed: false, stripped: text, cooling: false };
    // `stripped` is only meaningful on a 'respond'; fall back to the raw text
    // rather than trusting the shape (a fake or a future bot-kit may omit it).
    if (r.kind === "respond") {
      return { addressed: true, stripped: r.stripped ?? text, cooling: false };
    }
    if (r.kind === "cooldown") return { addressed: true, stripped: text, cooling: true };
    return { addressed: false, stripped: text, cooling: false };
  }

  /**
   * Emit a signed task event.
   *
   * The SDK signs the act document and posts the TAGMSG plus a
   * human-readable companion line, so a plain IRC client in the room sees
   * prose while agents see the structured event.
   *
   * `fields` are act field names WITHOUT the `+freeq.at/act-` prefix
   * (`title`, `to`, `ctx-h`, `note`, …). Returns the event id, which for an
   * opener IS the task id.
   */
  async sendAct(
    channel: string,
    verb: string,
    taskId: string | undefined,
    fields: Record<string, string>,
    humanText?: string,
  ): Promise<string | undefined> {
    if (!this.#bot || this.#state !== "online") return undefined;
    const from = this.did;
    if (!from) return undefined;

    // The session signing key is minted during SASL and registered on 001,
    // and `sendAct` signs directly rather than going through the SDK's gated
    // send queue — so an act event emitted immediately after connect can
    // race the key and fail with "a task event must be signed". Wait for the
    // key rather than surfacing a spurious error to the user.
    if (!(await this.#awaitSigningKey())) {
      this.#opts.onNotice?.(
        "freeq: no signing key available — task events must be signed, so this was not sent",
        "error",
      );
      return undefined;
    }

    // Redact free text before it is signed — a signature over a leaked
    // secret would make the leak permanent AND non-repudiable.
    const clean: Record<string, string> = {};
    for (const [k, v] of Object.entries(fields)) {
      clean[k] = k === "title" || k === "note" ? this.#clean(v, channel) : v;
    }

    const tags = actTags("handoff", verb, taskId, from, clean);
    try {
      return await this.#bot.client.sendAct(channel, tags, {
        humanText: humanText === undefined ? undefined : this.#clean(humanText, channel),
        taskId,
      });
    } catch (err) {
      this.#opts.onNotice?.(`freeq: could not send task event: ${(err as Error).message}`, "error");
      return undefined;
    }
  }

  /** Resolve a sender's DID; null for guests/unresolvable (→ lowest tier). */
  async resolveSenderDid(msg: { from: string; tags?: Record<string, string> }): Promise<string | null> {
    try {
      return (await this.#bot?.resolveSenderDid(msg)) ?? null;
    } catch {
      return null;
    }
  }

  /** One-line status for `/freeq status`. */
  describe(): string {
    const who = this.nick ? `${this.nick} (${this.did ?? "no did"})` : "not registered";
    const err = this.#lastError ? ` — last error: ${this.#lastError}` : "";
    return `${this.#state}: ${who} · ${describeMeta(this.#meta)}${err}`;
  }

  async stop(reason = "session end"): Promise<void> {
    this.#stopped = true;
    this.#asks.cancelAll("freeq connection closed");
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    try {
      await this.#bot?.stop(reason);
    } catch {
      /* shutting down anyway */
    }
    this.#bot = undefined;
    this.#state = "offline";
  }
}
