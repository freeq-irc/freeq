/**
 * Instant rooms for a harness (docs/INSTANT-ROOMS.md).
 *
 * The room logic is bot-kit's `RoomManager`: the X25519 identity and
 * published pre-key bundle, the epochs held (persisted under the bot's state
 * dir), the cipher installed on the client, and steward duty — sealing the
 * current key to a member who joins. This module is the harness's side of
 * it: the slice of the manager the connection drives, how one is built over
 * the connection's own bot, a buffer of decrypted room messages for the
 * `freeq_room` tool's `read`, and the parsing of what the model passes as a
 * room.
 *
 * Room messages that arrive live still go through the inbound gate like any
 * other channel message (`runtime.ts` → `deliver`): a room is not a way
 * around the tier pipeline.
 */

import { RoomManager, parseRoomUrl, type AgentIdentity, type RoomInfo, type RoomLink } from "@freeq/bot-kit";
import type { FreeqClient, Message } from "@freeq/sdk";
import type { BotLike } from "./connection.js";

/** The part of bot-kit's `RoomManager` a harness uses. */
export interface RoomsLike {
  /** Rooms we hold at least one key for (lowercase channels). */
  channels(): string[];
  /** True when we hold a group key for this channel. */
  isRoom(channel: string): boolean;
  ensurePreKeyPublished(): Promise<void>;
  create(opts?: {
    topic?: string;
    inviteTtlSecs?: number;
    beforeJoin?: (channel: string) => void;
  }): Promise<{ channel: string; invite: string; url: string; expiresAt: number }>;
  join(link: RoomLink): Promise<{ channel: string; ready: boolean }>;
  loadKeys(channel: string): Promise<boolean>;
  stewardPass(channel: string): Promise<{ sealed: string[]; skipped: Array<{ did: string; reason: string }> }>;
  rotate(channel: string): Promise<number>;
  removeMember(channel: string, did: string): Promise<void>;
  keep(channel: string): Promise<number>;
  info(channel: string): Promise<RoomInfo>;
  invite(
    channel: string,
    opts?: { ttlSecs?: number; maxUses?: number },
  ): Promise<{ invite: string; url: string; expiresAt: number }>;
  revokeInvites(channel: string): Promise<number>;
}

/** How a connection gets its room manager. Tests inject a fake. */
export type RoomsFactory = (
  bot: BotLike,
  opts: { origin: string; log: (message: string) => void },
) => RoomsLike | undefined;

/**
 * Build bot-kit's `RoomManager` over the connection's bot: its client, its
 * did:key identity and its state dir, so the X25519 pair and opened room
 * keys sit next to the identity they belong to. A bot with no state dir, or
 * a client that cannot carry a channel cipher (a test fake), gets no rooms.
 * Warnings go to the harness's notices rather than stderr, which would land
 * on top of a TUI.
 */
export const defaultRoomsFactory: RoomsFactory = (bot, { origin, log }) => {
  const client = bot.client as unknown as Partial<Record<"on" | "setChannelCipher", unknown>>;
  if (!bot.stateDir || typeof client.on !== "function" || typeof client.setChannelCipher !== "function") {
    return undefined;
  }
  return new RoomManager({
    // BotLike is the slice of FreeqBot the connection is tested against; the
    // real bot behind it carries the full client and identity.
    client: bot.client as unknown as FreeqClient,
    identity: bot.identity as unknown as AgentIdentity,
    stateDir: bot.stateDir,
    origin,
    log,
  });
};

/**
 * The HTTP origin that serves the REST API, derived from the IRC websocket
 * URL (`wss://host/irc` → `https://host`).
 */
export function httpOriginFor(wsUrl: string): string {
  try {
    const u = new URL(wsUrl);
    u.protocol = u.protocol === "ws:" ? "http:" : "https:";
    u.pathname = "";
    u.search = "";
    return u.origin;
  } catch {
    return "https://irc.freeq.at";
  }
}

// ── What the model passes as a room ─────────────────────────────────────

/**
 * Turn a `room` argument into a link. A share URL carries the server and
 * (usually) an invite token; a bare name means "the room by that name on the
 * connected server", which is enough for a DID already on the roster.
 * Throws with both accepted forms spelled out.
 */
export function resolveRoomTarget(raw: string, origin: string): RoomLink {
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) {
    const link = parseRoomUrl(s);
    if (!link) {
      throw new Error(
        `not a room URL: ${s}. Expected https://host/r/<name>#<token> (the token after '#' is the invite).`,
      );
    }
    return link;
  }
  const name = s.replace(/^#/, "");
  if (!name || !/^[A-Za-z0-9_.-]+$/.test(name)) {
    throw new Error(
      `not a room: ${JSON.stringify(raw)}. Give the room's share URL (https://host/r/<name>#<token>) or its channel (#r-word-word-word).`,
    );
  }
  return { origin, channel: `#${name.toLowerCase()}`, token: null };
}

/** Whether two origins name the same host (scheme and trailing slashes aside). */
export function sameHost(a: string, b: string): boolean {
  try {
    return new URL(a).host.toLowerCase() === new URL(b).host.toLowerCase();
  } catch {
    return true; // unparseable: let the server be the judge
  }
}

/** One paragraph a person can paste to whoever should be in the room. */
export function shareText(url: string, channel: string, topic?: string): string {
  const what = topic ? `a private freeq room for "${topic}"` : "a private freeq room";
  return (
    `You're invited to ${what} (${channel}): ${url} — open that link in a browser, ` +
    `or paste it to your agent (for example: npx -y @freeq/mcp room join ${url}). ` +
    `Everything said in the room is end-to-end encrypted; the link is the key, so only share it with people you want inside.`
  );
}

// ── Decrypted messages, for `read` ──────────────────────────────────────

/** One room message, as the SDK handed it over (already decrypted). */
export interface RoomLine {
  from: string;
  /** The `account` tag when the server sent one; resolved later otherwise. */
  did: string | null;
  text: string;
  /** epoch ms */
  at: number;
  msgid?: string;
  /** True when the SDK could not decrypt it (an epoch we do not hold). */
  unreadable: boolean;
  tags: Record<string, string>;
}

/** What the SDK shows for a message it could not decrypt. */
const UNREADABLE = "[encrypted message]";

export function roomLineOf(msg: Message): RoomLine {
  return {
    from: msg.from,
    did: msg.tags?.account ?? null,
    text: msg.text,
    at: msg.timestamp instanceof Date ? msg.timestamp.getTime() : Date.now(),
    msgid: msg.tags?.msgid ?? (msg.id || undefined),
    unreadable: !!msg.encrypted && msg.text === UNREADABLE,
    tags: msg.tags ?? {},
  };
}

/** How many unread lines a room keeps before dropping the oldest. */
const BUFFER_MAX = 200;

/**
 * Messages that arrived in each room since the model last read it. Bounded:
 * a room nobody reads keeps its newest lines, not all of them.
 */
export class RoomBuffer {
  readonly #lines = new Map<string, RoomLine[]>();
  readonly #waiters = new Map<string, Set<() => void>>();

  push(channel: string, line: RoomLine): void {
    const ch = channel.toLowerCase();
    const list = this.#lines.get(ch) ?? [];
    list.push(line);
    if (list.length > BUFFER_MAX) list.splice(0, list.length - BUFFER_MAX);
    this.#lines.set(ch, list);
    for (const wake of this.#waiters.get(ch) ?? []) wake();
  }

  /** The unread lines (newest `limit`), which are then read. */
  take(channel: string, limit: number): RoomLine[] {
    const ch = channel.toLowerCase();
    const list = this.#lines.get(ch) ?? [];
    this.#lines.delete(ch);
    return list.slice(-Math.max(1, limit));
  }

  /** Resolve true when a line arrives, false after `ms`. */
  wait(channel: string, ms: number): Promise<boolean> {
    const ch = channel.toLowerCase();
    if ((this.#lines.get(ch)?.length ?? 0) > 0) return Promise.resolve(true);
    return new Promise((resolve) => {
      const set = this.#waiters.get(ch) ?? new Set();
      this.#waiters.set(ch, set);
      const done = (v: boolean): void => {
        clearTimeout(timer);
        set.delete(wake);
        resolve(v);
      };
      const wake = (): void => done(true);
      const timer = setTimeout(() => done(false), ms);
      timer.unref?.();
      set.add(wake);
    });
  }
}
