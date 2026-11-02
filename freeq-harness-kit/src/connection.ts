/**
 * freeq connection lifecycle for the pi extension.
 *
 * Contract (build spec §3 M1): connection problems must NEVER break the pi
 * session. Every failure degrades to "offline" and is reported once; the
 * caller keeps working. Nothing here throws into pi's event loop.
 */

import { FreeqBot, matchMention, type RoomLink } from "@freeq/bot-kit";
import type {
  ActEventPayload,
  CoordinationEventPayload,
  Message,
  PresencePayload,
} from "@freeq/sdk";
import { actTags } from "@freeq/sdk";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** bot-kit's default state root, mirrored so identity lookup agrees with it. */
function defaultBotsRoot(): string {
  return join(homedir(), ".freeq", "bots");
}
import { defaultNick, projectNick, resolveBotName } from "./identity.js";
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
  defaultRoomsFactory,
  httpOriginFor,
  RoomBuffer,
  roomLineOf,
  type RoomLine,
  type RoomsFactory,
  type RoomsLike,
} from "./rooms.js";
import { PI_NAMES, type HarnessNames } from "./names.js";
import { firstSignedCertificateWarning, signedCertificateLine } from "./owner-key.js";
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
  /** Remove a handler; bot-kit has it, a fake may not (history then skips). */
  off?(event: string, handler: (...args: never[]) => void): unknown;
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
    /** CHATHISTORY; answered by a `historyBatch` event. Used by room reads. */
    requestHistory?(opts: { target: string; mode: "latest"; count?: number }): void;
  };
  /** The server's latest answer to PROVENANCE, from bot-kit. */
  readonly provenance: { verified: boolean; reason: string; text: string } | null;
  /** Called with each verdict bot-kit reports, when it arrives or changes. */
  onProvenance?(handler: (verdict: { verified: boolean; reason: string }) => void): () => void;
  /** The delegation certificate bot-kit loaded or minted; a signature means
   *  it is signed with a creator key (deprecated). */
  readonly delegation?: { signature: string | null };
  /** Where bot-kit keeps this bot's identity and certificate. */
  readonly stateDir?: string;
}

/** How a bot gets built. Overridden in tests. */
export type BotFactory = (opts: {
  name: string;
  ownerDid: string;
  /** Owner's creator seed; when set, bot-kit signs the delegation cert
   *  (deprecated; to be removed in a later release). */
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
  /** False: bot-kit leaves the verdict to `onProvenance` instead of stderr. */
  logProvenance: boolean;
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
  /**
   * The harness this connection runs in: the prefix of the identity and
   * nick, the hello's `agent`, and its name in notices. Default pi's.
   */
  names?: HarnessNames;
  ownerDid: string;
  /** Owner's creator seed; when set, bot-kit signs the delegation cert
   *  (deprecated; to be removed in a later release). */
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
  /**
   * How the bot's room manager is built (docs/INSTANT-ROOMS.md). Default:
   * bot-kit's `RoomManager` over the bot. Tests inject a fake.
   */
  roomsFactory?: RoomsFactory;
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
  /**
   * The set of channels the server has confirmed we are in changed: a join
   * confirmed, a channel left, parted or refused, or membership reset by a
   * connect or a drop. A footer showing the count redraws here.
   */
  onChannelsChanged?: () => void;
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

/**
 * How long to let the server's own auto-rejoin land before we re-JOIN.
 *
 * A DID-authenticated session gets its saved channel set restored at
 * registration, and joining on top of that would be churn. But the saved set
 * is not guaranteed - a PART (including our own "not this project's channel"
 * PART), a kick, or a row that was never written leaves it empty, and then
 * nobody joins anything and the agent is simply absent while every local
 * surface still says online.
 */
const REJOIN_GRACE_MS = 3_000;
/** One late sweep, for a server that restored slowly or not at all. */
const REJOIN_SWEEP_MS = 15_000;

export class FreeqConnection {
  #bot: BotLike | undefined;
  #state: ConnState = "offline";
  readonly #joined = new Set<string>();
  /**
   * Channels this session means to be in, lowercased.
   *
   * Seeded from config and then kept live by join()/leave(). It must NOT be
   * read off #opts.channels, which is a snapshot taken at connect: a channel
   * joined later is absent from that snapshot, so the unexpected-channel guard
   * treated every /freeq join as a channel the server had foisted on us and
   * parted it a moment after joining.
   */
  readonly #wanted = new Set<string>();
  readonly #refused = new Map<string, string>();
  #lastError: string | undefined;
  #peers = new Map<string, Peer>();
  #opts: ConnectionOptions;
  #meta: SessionMeta;
  #stopped = false;
  /** Guards against two concurrent start() calls building two bots. */
  #starting = false;
  #retry = RECONNECT_INITIAL_MS;
  #timer: NodeJS.Timeout | undefined;
  /** Pending post-reconnect membership reconciliation timers. */
  #rejoinTimers: NodeJS.Timeout[] = [];
  /** Notices are deduped: a flapping connection must not spam the TUI. */
  #noticed = new Set<string>();
  #asks = new AskRegistry((reason) => this.#opts.onNotice?.(`freeq ask: ${reason}`, "warning"));
  /** Coordination handlers still running; what `settled()` waits on. */
  readonly #inFlight = new Set<Promise<unknown>>();
  /** bot-kit's room manager for this bot, when it has one. */
  #rooms: RoomsLike | undefined;
  /**
   * Channels known to be instant rooms (lowercase): created or joined here,
   * or held keys for. Wanted for good, and never announced into — a hello
   * carries project metadata, and a room's members are whoever has its link.
   */
  readonly #roomChannels = new Set<string>();
  /** Decrypted room messages the model has not read yet. */
  readonly #roomBuffer = new RoomBuffer();

  constructor(opts: ConnectionOptions) {
    // The configured list is the initial intent; join()/leave() keep it live.
    for (const c of opts.channels ?? []) if (c.trim()) this.#wanted.add(c.trim().toLowerCase());
    this.#opts = opts;
    this.#meta = opts.meta;
  }

  get #names(): HarnessNames {
    return this.#opts.names ?? PI_NAMES;
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
  /** The server's latest answer to our PROVENANCE ("Provenance verified:
   *  …", "Provenance stored (unverified): …", …), as bot-kit read it from
   *  the server's own NOTICE, so /freeq authorize verify reports the
   *  server's verdict rather than guessing. */
  get provenanceNotice(): string | undefined {
    return this.#bot?.provenance?.text;
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
        // Prefer an identity that already exists on disk: the slug format
        // changed, and renaming an agent would hand it a new DID and a new
        // nick, making it a stranger to everyone who trusts it.
        name: resolveBotName(
          this.#opts.slug,
          this.#meta.project,
          (n) => existsSync(join(this.#opts.root ?? defaultBotsRoot(), n)),
          this.#names.name,
        ),
        ownerDid: this.#opts.ownerDid,
        creatorKeyPath: this.#opts.creatorKeyPath,
        nick: projectNick(
          this.#opts.nick ?? defaultNick(this.#opts.slug, this.#names.name),
          this.#meta.project,
          this.#names.name,
        ),
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
        // bot-kit's stderr line would land on top of pi's screen; the verdict
        // is shown below as a freeq notice instead.
        logProvenance: false,
      });
      this.#bot = bot;
      // stop() stops only the bot it holds, and this one did not exist yet:
      // a connection stopped while its bot was being created tears it down
      // here, before it has a handler or a socket.
      if (this.#stopped) {
        await this.#discardBot();
        return;
      }
      this.#rooms = this.#buildRooms(bot);
      // Signed certificates will stop counting in a later release. Said once per
      // process: a retry or `authorize verify` builds a new bot and a new
      // connection, and `#notice`'s set belongs to this one.
      if (bot.delegation?.signature && firstSignedCertificateWarning()) {
        this.#opts.onNotice?.(
          signedCertificateLine({
            botDid: bot.identity.did,
            certPath: bot.stateDir ? join(bot.stateDir, "delegation.json") : undefined,
            keyPath: this.#opts.creatorKeyPath,
          }),
          "warning",
        );
      }
      bot.onProvenance?.((v) =>
        this.#opts.onNotice?.(
          `freeq: provenance ${v.verified ? "verified" : "unverified"}: ${v.reason}`,
          v.verified ? "info" : "warning",
        ),
      );

      bot.on("message", (channel: string, msg: Message) => {
        if (msg.isSelf) return;
        // Kept for the room tool's `read`, as well as handed on below: a room
        // message still goes through the host's inbound gate like any other.
        if (this.isRoom(channel)) this.#roomBuffer.push(channel, roomLineOf(msg));
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
        this.#track(this.#onCoordinationEvent(e));
      });

      // Announce into each channel once we're actually in it.
      bot.on("channelJoined", (channel: string) => {
        this.#joined.add(channel.toLowerCase());
        this.#channelsChanged();
        // The server restores a session's saved channel set on reconnect, so
        // a channel this project no longer wants comes back by itself and
        // stays for good: config asks, server remembers, server wins. Leave
        // anything we did not ask for. Announcing into it first would be
        // announcing our arrival somewhere we are about to leave.
        if (this.#wanted.size && !this.#wanted.has(channel.toLowerCase())) {
          this.#joined.delete(channel.toLowerCase());
          this.#channelsChanged();
          this.#bot?.client.raw(`PART ${channel} :not this project's channel`);
          this.#opts.onUnexpectedChannel?.(channel);
          return;
        }
        this.#refused.delete(channel.toLowerCase());
        if (!this.isRoom(channel)) this.#announce(channel, PI_HELLO);
      });

      bot.on("channelLeft", (channel: string) => {
        this.#joined.delete(channel.toLowerCase());
        this.#channelsChanged();
      });

      // A JOIN that the server refuses. Without this the client sends JOIN,
      // the server says 477, nobody listens, and every surface goes on
      // reporting the channel as joined - which is how #freeq-dev sat in the
      // footer for a whole session while the agent was not in it. Being
      // wrong about where you are is worse than being nowhere.
      bot.on("joinRejected", (channel: string, numeric: string, reason: string) => {
        if (!channel) return;
        this.#joined.delete(channel.toLowerCase());
        this.#channelsChanged();
        // 477 keeps its own word because it is the one with a remedy the
        // agent can perform itself.
        this.#refused.set(channel.toLowerCase(), numeric === "477" ? "policy" : reason);
        this.#opts.onJoinRefused?.(channel, numeric === "477" ? "policy" : reason);
      });

      // Online only once the server has let the agent in (001, which the SDK
      // reports as 'ready'), not when a socket opens: a socket the server
      // refuses before then is not online, and it does not re-arm the
      // 'connection dropped' notice, which so prints once per gap. Nothing
      // more happens once the connection is stopped, or once this bot is no
      // longer the one held (a failed start discards it before it stops it):
      // bot.stop() waits for its send buffer before it disconnects, and a
      // welcome can arrive in that wait.
      bot.on("ready", () => {
        if (this.#stopped || this.#bot !== bot) return;
        this.#goOnline();
        this.#noticed.delete("offline");
        // Rooms rejoin with the rest (they are wanted); stewarding is a
        // REST pass, owed to anyone who arrived while we were away. A start
        // still running enters them itself once bot.start() returns.
        if (!this.#starting) this.#enterRooms(false);
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
          // Membership does not survive a socket. Whatever the server ends up
          // restoring will re-announce itself through channelJoined; until
          // then we are in nothing, and saying otherwise is how the footer
          // kept listing channels an absent agent was not in.
          this.#joined.clear();
          this.#channelsChanged();
          this.#scheduleRejoin();
        } else if (s === "connecting") {
          if (this.#state === "online") this.#state = "connecting";
        } else if (s === "disconnected" && !this.#stopped) {
          this.#state = "connecting";
          this.#joined.clear();
          this.#channelsChanged();
          this.#clearRejoinTimers();
          this.#notice(
            `freeq: connection dropped — the transport is reconnecting; ${this.#names.name} continues normally`,
            "warning",
            "offline",
          );
        }
      });

      bot.on("authError", (e: string) => {
        this.#lastError = e;
        // An allowlisted server names the owner's records; that is the
        // owner's cue to add this installation as one of their agents.
        const hint = /agent records of .* do not admit this agent/.test(e)
          ? ` Run ${this.#names.hint("authorize")} to add this installation as one of your agents.`
          : "";
        this.#notice(`freeq: authentication failed — ${e}${hint}`, "error", "auth");
      });

      await bot.start();
      // A stop that lands while bot.start() runs owns what is left of it: a
      // start that still resolves, or one that rejects because the stop
      // closed its socket, says and does nothing more here.
      if (this.#stopped) return;
      this.#goOnline();
      this.#retry = RECONNECT_INITIAL_MS;
      // bot-kit joins the configured channels; rooms we hold keys for are
      // ours to re-enter.
      this.#enterRooms(true);
    } catch (err) {
      if (this.#stopped) return;
      // Only the INITIAL connect is retried here. Once a bot exists, the
      // transport owns reconnection (see connectionStateChanged above).
      this.#state = "error";
      this.#lastError = (err as Error).message;
      this.#notice(
        `freeq: could not connect (${this.#lastError}) — ${this.#names.name} continues normally`,
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
   * Both `bot.start()` returning and the bot's 'ready' event land here, and a
   * reconnect fires the second one again — so the transition is what is
   * reported, not the event. A handler that resumes work would otherwise run
   * twice for one connect.
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
    const base = this.#opts.nick ?? defaultNick(this.#opts.slug, this.#names.name);
    names.add(projectNick(base, this.#meta.project, this.#names.name));
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
      this.#bot.client.sendTagmsg(
        channel,
        helloTags(type, buildHello(this.#meta, this.did, this.#names.name)),
      );
    } catch {
      /* discovery is best-effort */
    }
  }

  /** Re-announce into every joined channel (after a metadata change). */
  announceAll(): void {
    for (const channel of this.#opts.channels) this.#announce(channel, PI_HELLO);
  }

  /**
   * Remember a coordination handler's promise until it settles. Only the
   * removal is attached: a handler that throws still surfaces as exactly one
   * unhandled rejection carrying its own error, as it did before.
   */
  #track(p: Promise<unknown>): void {
    this.#inFlight.add(p);
    void p.finally(() => this.#inFlight.delete(p));
  }

  /**
   * Resolves once every coordination handler that has started has finished,
   * including any one of them started. For tests and shutdown; never throws.
   */
  async settled(): Promise<void> {
    while (this.#inFlight.size > 0) await Promise.allSettled([...this.#inFlight]);
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

    // Answer a hello so the newcomer learns about us; never ack an ack, and
    // never into a room (see #roomChannels).
    if (e.eventType === PI_HELLO && e.channel.startsWith("#") && !this.isRoom(e.channel)) {
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

  /**
   * After a reconnect, make sure we are actually in the channels we mean to
   * be in.
   *
   * The transport recovers the socket and the server restores a
   * DID-authenticated session's saved channel set, so for a long time this
   * layer did nothing here on purpose. That holds right up until the saved set
   * is empty — a PART, a kick, or a row that was never written — and then a
   * server restart leaves the agent connected, authenticated, announced, and
   * in no channels at all, which is indistinguishable from gone to everyone
   * except the agent itself.
   *
   * So: wait for the server's own restore, then join whatever is still
   * missing, then sweep once more. Both passes are no-ops when the restore
   * worked, which is the common case.
   */
  #scheduleRejoin(): void {
    this.#clearRejoinTimers();
    for (const delay of [REJOIN_GRACE_MS, REJOIN_SWEEP_MS]) {
      const t = setTimeout(() => this.#rejoinMissing(), delay);
      t.unref?.();
      this.#rejoinTimers.push(t);
    }
  }

  #clearRejoinTimers(): void {
    for (const t of this.#rejoinTimers) clearTimeout(t);
    this.#rejoinTimers = [];
  }

  /** JOIN every wanted channel the server has not confirmed us into. */
  #rejoinMissing(): void {
    if (this.#stopped || !this.#bot || this.#state !== "online") return;
    const missing = [...this.#wanted].filter(
      // A refusal is a decision, not a gap: retrying a 477 in a loop would
      // spam the server and never succeed without the operator's consent.
      (c) => !this.#joined.has(c) && !this.#refused.has(c),
    );
    if (!missing.length) return;
    for (const channel of missing) {
      try {
        this.#bot.client.join(channel);
      } catch {
        /* the socket went again; the next connect reschedules this */
      }
    }
    this.#notice(
      `freeq: rejoining after a reconnect — ${missing.join(", ")}`,
      "info",
      "rejoin",
    );
  }

  #clean(text: string, target: string): string {
    const { text: scrubbed, hits } = scrubOutbound(text);
    if (hits.length) this.#opts.onScrub?.(hits, target);
    return scrubbed;
  }

  /** Replace the set of channels this session means to be in. */
  setWantedChannels(channels: string[]): void {
    this.#wanted.clear();
    for (const c of channels) if (c.trim()) this.#wanted.add(c.trim().toLowerCase());
    // Rooms are not configured channels; changing those must not drop them.
    for (const c of this.#roomChannels) this.#wanted.add(c);
  }

  /** Channels the server has CONFIRMED we are in, not the ones we asked for. */
  /** Tell the host the confirmed channel set changed; presentation only. */
  #channelsChanged(): void {
    try {
      this.#opts.onChannelsChanged?.();
    } catch {
      /* a footer that failed to redraw must not break the connection */
    }
  }

  joinedChannels(): string[] {
    return [...this.#joined];
  }

  /** Channels whose JOIN was refused, and why. */
  refusedChannels(): Array<{ channel: string; reason: string }> {
    return [...this.#refused].map(([channel, reason]) => ({ channel, reason }));
  }

  /** Accept a channel's join policy, then retry the join. */
  acceptPolicy(channel: string): boolean {
    this.#wanted.add(channel.toLowerCase());
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.raw(`POLICY ${channel} ACCEPT`);
    this.#bot.client.raw(`JOIN ${channel}`);
    return true;
  }

  join(channel: string): boolean {
    // Record the intent BEFORE the wire, so the join we are about to make is
    // already wanted by the time the server confirms it.
    this.#wanted.add(channel.toLowerCase());
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.join(channel);
    return true;
  }

  leave(channel: string): boolean {
    this.#wanted.delete(channel.toLowerCase());
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.raw(`PART ${channel}`);
    return true;
  }

  send(target: string, text: string): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    // A room we hold no key for cannot be written to: the SDK would drop the
    // send rather than leak plaintext, and report nothing to us.
    if (this.isRoom(target) && !this.hasRoomKey(target)) return false;
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

  // ── Instant rooms ─────────────────────────────────────────────────────

  /** The room manager, when this bot has one (a did:key bot with a state dir). */
  get rooms(): RoomsLike | undefined {
    return this.#rooms;
  }

  /** A room we know of: created or joined here, or holding its key. */
  isRoom(channel: string): boolean {
    const ch = channel.toLowerCase();
    return this.#roomChannels.has(ch) || !!this.#rooms?.isRoom(ch);
  }

  /** Do we hold a key for this room, i.e. can we read and write it? */
  hasRoomKey(channel: string): boolean {
    return !!this.#rooms?.isRoom(channel.toLowerCase());
  }

  /** Has the server confirmed we are in this channel? */
  inChannel(channel: string): boolean {
    return this.#joined.has(channel.toLowerCase());
  }

  /** Mint a room and enter it as its founder. Throws when rooms are unavailable. */
  async createRoom(opts: { topic?: string } = {}): Promise<{
    channel: string;
    invite: string;
    url: string;
    expiresAt: number;
  }> {
    const rooms = this.#requireRooms();
    const made = await rooms.create({
      topic: opts.topic === undefined ? undefined : this.#clean(opts.topic, "a new room"),
      // Wanted before the JOIN goes out, or the unexpected-channel guard
      // would part the room the moment the server confirmed it.
      beforeJoin: (channel) => this.#noteRoom(channel),
    });
    this.#noteRoom(made.channel);
    return made;
  }

  /** Enter a room from a link. `ready: false` means no key is sealed to us yet. */
  async joinRoom(link: RoomLink): Promise<{ channel: string; ready: boolean }> {
    const rooms = this.#requireRooms();
    const ch = link.channel.toLowerCase();
    const known = this.isRoom(ch);
    this.#noteRoom(ch);
    this.#refused.delete(ch);
    try {
      return await rooms.join(link);
    } catch (err) {
      if (!known && !rooms.isRoom(ch)) {
        this.#roomChannels.delete(ch);
        this.#wanted.delete(ch);
      }
      throw err;
    }
  }

  /**
   * Seal the room key to members who lack it, if we hold it. Never throws:
   * stewarding is a courtesy to others and must not break the caller's own
   * read. Returns who was sealed to; members we would not seal to are
   * reported as notices.
   */
  async stewardRoom(channel: string): Promise<string[]> {
    const ch = channel.toLowerCase();
    const rooms = this.#rooms;
    if (!rooms || !rooms.isRoom(ch)) return [];
    try {
      const pass = await rooms.stewardPass(ch);
      for (const s of pass.skipped) {
        this.#notice(`freeq: ${ch}: not sealing the room key to ${s.did} — ${s.reason}`, "warning");
      }
      return pass.sealed;
    } catch (err) {
      this.#notice(`freeq: steward pass for ${ch} failed — ${(err as Error).message}`, "warning");
      return [];
    }
  }

  /** Room messages that arrived since the last call, newest `limit`. */
  takeRoomMessages(channel: string, limit = 50): RoomLine[] {
    return this.#roomBuffer.take(channel, limit);
  }

  /** Wait (bounded) for a room message to arrive. */
  waitForRoomMessage(channel: string, ms: number): Promise<boolean> {
    return this.#roomBuffer.wait(channel, ms);
  }

  /**
   * The latest stored messages of a room, over CHATHISTORY; the SDK decrypts
   * them on the way in. Empty when the bot cannot ask or nothing answers in
   * time.
   */
  roomHistory(channel: string, count: number, timeoutMs = 5_000): Promise<RoomLine[]> {
    const bot = this.#bot;
    const ch = channel.toLowerCase();
    if (!bot?.client.requestHistory || !bot.off) return Promise.resolve([]);
    return new Promise((resolve) => {
      const handler = (target: string, messages: Message[]): void => {
        if (target.toLowerCase() !== ch) return;
        done(messages.map(roomLineOf));
      };
      const done = (rows: RoomLine[]): void => {
        clearTimeout(timer);
        bot.off?.("historyBatch", handler as (...a: never[]) => void);
        resolve(rows);
      };
      const timer = setTimeout(() => done([]), timeoutMs);
      timer.unref?.();
      bot.on("historyBatch", handler as (...a: never[]) => void);
      try {
        bot.client.requestHistory!({ target: ch, mode: "latest", count });
      } catch {
        done([]);
      }
    });
  }

  #requireRooms(): RoomsLike {
    if (!this.#bot || this.#state !== "online") throw new Error("freeq is offline");
    if (!this.#rooms) {
      throw new Error("rooms are unavailable: this connection has no did:key identity to hold room keys with");
    }
    return this.#rooms;
  }

  #noteRoom(channel: string): void {
    const ch = channel.toLowerCase();
    this.#roomChannels.add(ch);
    this.#wanted.add(ch);
  }

  #buildRooms(bot: BotLike): RoomsLike | undefined {
    try {
      const make = this.#opts.roomsFactory ?? defaultRoomsFactory;
      const rooms = make(bot, {
        origin: httpOriginFor(this.#opts.server),
        log: (m) => this.#notice(`freeq: ${m.replace(/^\[rooms\]\s*/, "")}`, "warning"),
      });
      for (const ch of rooms?.channels() ?? []) this.#noteRoom(ch);
      return rooms;
    } catch (err) {
      this.#notice(`freeq: rooms unavailable — ${(err as Error).message}`, "warning", "rooms");
      return undefined;
    }
  }

  /**
   * Re-enter the rooms we hold keys for, publish our pre-key so a steward can
   * seal to us, and steward each room. bot-kit's steward only fires on a JOIN
   * it witnesses, so a member who arrived while we were away is sealed to
   * here. `join` is false after a reconnect, where the rejoin sweep owns
   * JOINs. Fire and forget; nothing here throws.
   */
  #enterRooms(join: boolean): void {
    const rooms = this.#rooms;
    if (!rooms) return;
    const held = rooms.channels();
    if (join) {
      for (const ch of held) {
        if (this.#joined.has(ch)) continue;
        try {
          this.#bot?.client.join(ch);
        } catch {
          /* the socket went; the reconnect sweep rejoins */
        }
      }
    }
    this.#track(
      (async () => {
        try {
          await rooms.ensurePreKeyPublished();
        } catch (err) {
          this.#notice(
            `freeq: could not publish this agent's room pre-key (${(err as Error).message}) — members cannot seal room keys to it until it is`,
            "warning",
            "prekey",
          );
        }
        for (const ch of held) await this.stewardRoom(ch);
      })(),
    );
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
    this.#clearRejoinTimers();
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
