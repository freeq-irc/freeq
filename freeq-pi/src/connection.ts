/**
 * freeq connection lifecycle for the pi extension.
 *
 * Contract (build spec §3 M1): connection problems must NEVER break the pi
 * session. Every failure degrades to "offline" and is reported once; the
 * caller keeps working. Nothing here throws into pi's event loop.
 */

import { FreeqBot } from "@freeq/bot-kit";
import type { CoordinationEventPayload, Message, PresencePayload } from "@freeq/sdk";
import { botName, defaultNick } from "./identity.js";
import { describeMeta, formatStatus, parseStatus, type SessionMeta } from "./presence.js";
import {
  buildHello,
  helloTags,
  parseHello,
  PI_HELLO,
  PI_HELLO_ACK,
} from "./discovery.js";

export type ConnState = "offline" | "connecting" | "online" | "error";

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
  server: string;
  slug: string;
  nick?: string;
  channels: string[];
  meta: SessionMeta;
  /** Where bot-kit stores identity/delegation. Tests override this. */
  root?: string;
  /** Reported to the host for user-visible notices. */
  onNotice?: (text: string, level: "info" | "warning" | "error") => void;
  /** Inbound channel/DM messages (M2 wires the tiered pipeline here). */
  onMessage?: (channel: string, msg: Message) => void;
}

const RECONNECT_INITIAL_MS = 2_000;
const RECONNECT_MAX_MS = 60_000;

export class FreeqConnection {
  #bot: FreeqBot | undefined;
  #state: ConnState = "offline";
  #lastError: string | undefined;
  #peers = new Map<string, Peer>();
  #opts: ConnectionOptions;
  #meta: SessionMeta;
  #stopped = false;
  #retry = RECONNECT_INITIAL_MS;
  #timer: NodeJS.Timeout | undefined;
  /** Notices are deduped: a flapping connection must not spam the TUI. */
  #noticed = new Set<string>();

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
  get meta(): SessionMeta {
    return this.#meta;
  }
  get bot(): FreeqBot | undefined {
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
    this.#state = "connecting";
    try {
      const bot = await FreeqBot.create({
        name: botName(this.#opts.slug),
        ownerDid: this.#opts.ownerDid,
        nick: this.#opts.nick ?? defaultNick(this.#opts.slug),
        url: this.#opts.server,
        root: this.#opts.root,
        channels: this.#opts.channels,
        actorClass: "agent",
        initialState: "active",
        initialStatus: formatStatus(this.#meta),
        // A second pi on the same box shouldn't fight over the nick.
        onNickCollision: "auto-suffix",
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

      // Peer discovery rides coordination events, not presence — the server
      // drops presence status for active agents (see discovery.ts).
      bot.on("coordinationEvent", (e: CoordinationEventPayload) => {
        void this.#onCoordinationEvent(e);
      });

      // Announce into each channel once we're actually in it.
      bot.on("channelJoined", (channel: string) => {
        this.#announce(channel, PI_HELLO);
      });

      bot.on("connectionStateChanged", (s: string) => {
        if (s === "connected" || s === "ready") {
          this.#state = "online";
          this.#retry = RECONNECT_INITIAL_MS;
          this.#noticed.delete("offline");
        } else if (s === "disconnected" || s === "closed") {
          if (!this.#stopped) this.#degrade("connection lost");
        }
      });

      bot.on("authError", (e: string) => {
        this.#lastError = e;
        this.#notice(`freeq: authentication failed — ${e}`, "error", "auth");
      });

      await bot.start();
      this.#state = "online";
      this.#retry = RECONNECT_INITIAL_MS;
    } catch (err) {
      this.#degrade((err as Error).message);
    }
  }

  #degrade(reason: string): void {
    this.#state = "error";
    this.#lastError = reason;
    this.#notice(`freeq: offline (${reason}) — pi continues normally`, "warning", "offline");
    this.#scheduleRetry();
  }

  #scheduleRetry(): void {
    if (this.#stopped || this.#timer) return;
    const delay = this.#retry;
    this.#retry = Math.min(this.#retry * 2, RECONNECT_MAX_MS);
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (this.#stopped) return;
      void this.#reconnect();
    }, delay);
    // Don't hold the process open just to retry a chat connection.
    this.#timer.unref?.();
  }

  async #reconnect(): Promise<void> {
    try {
      await this.#bot?.stop("reconnect");
    } catch {
      /* ignore */
    }
    this.#bot = undefined;
    await this.start();
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
    if (e.eventType !== PI_HELLO && e.eventType !== PI_HELLO_ACK) return;
    if (this.#isSelf(e.from)) return;

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
    this.#bot.client.sendMessage(target, text);
    return true;
  }

  sendTags(target: string, tags: Record<string, string>): boolean {
    if (!this.#bot || this.#state !== "online") return false;
    this.#bot.client.sendTagmsg(target, tags);
    return true;
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
