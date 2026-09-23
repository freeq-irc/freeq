/**
 * Test doubles shared by the test files.
 *
 * Excluded from the published build (see tsconfig `exclude`) — it exists so
 * the session and MCP-surface tests drive the same fake client rather than
 * keeping two subtly different ones.
 */

import type { RoomInfo, RoomLink } from "@freeq/bot-kit";
import { loadConfig, type FreeqMcpConfig } from "./config.js";
import { FreeqRest } from "./rest.js";
import {
  FreeqSession,
  type ClientFactoryResult,
  type SessionClient,
  type SessionMode,
  type SessionRooms,
} from "./session.js";

/** A hand-driven stand-in for the SDK's FreeqClient. */
export class FakeClient implements SessionClient {
  nick: string | null = "mcp-test";
  apiBearer: string | null = null;
  handlers = new Map<string, Array<(...args: never[]) => void>>();
  sent: Array<{ target: string; text: string }> = [];
  tagmsgs: Array<{ target: string; tags: Record<string, string> }> = [];
  joined: string[] = [];
  /** JOINs with the key (invite token) they carried. */
  joinKeys: Array<{ channel: string; key?: string }> = [];
  historyRequests: Array<{ target: string; mode: string; count?: number }> = [];
  /** Rows a `requestHistory` call replays, per channel (lowercase). */
  history = new Map<string, unknown[]>();
  connected = false;
  quitReason?: string;

  on(event: string, handler: (...args: never[]) => void): this {
    const list = this.handlers.get(event) ?? [];
    list.push(handler);
    this.handlers.set(event, list);
    return this;
  }

  off(event: string, handler: (...args: never[]) => void): this {
    const list = this.handlers.get(event) ?? [];
    const i = list.indexOf(handler);
    if (i >= 0) list.splice(i, 1);
    return this;
  }

  emit(event: string, ...args: unknown[]): void {
    for (const h of [...(this.handlers.get(event) ?? [])]) (h as (...a: unknown[]) => void)(...args);
  }

  connect(): void {
    this.connected = true;
    // Real clients reach `ready` asynchronously.
    setTimeout(() => this.emit("ready"), 0);
  }

  disconnect(): void {
    this.connected = false;
  }

  quit(reason?: string): void {
    this.quitReason = reason;
  }

  join(channel: string, key?: string): void {
    this.joined.push(channel);
    this.joinKeys.push({ channel, key });
    this.emit("channelJoined", channel);
  }

  /** When false, sends are never echoed back (simulates a lost message). */
  echo = true;

  sendMessage(target: string, text: string): void {
    this.sent.push({ target, text });
    if (!this.echo) return;
    // The server echoes our own PRIVMSG (echo-message); that is the send
    // confirmation the session waits for.
    setTimeout(() => {
      this.emit("message", target, { id: "01ECHO", from: this.nick, text, timestamp: new Date(), tags: {}, isSelf: true });
    }, 0);
  }

  sendTagmsg(target: string, tags: Record<string, string>): void {
    this.tagmsgs.push({ target, tags });
  }

  requestHistory(opts: { target: string; mode: "latest"; count?: number }): void {
    this.historyRequests.push(opts);
    const rows = this.history.get(opts.target.toLowerCase()) ?? [];
    setTimeout(() => this.emit("historyBatch", opts.target, rows, undefined, rows.length), 0);
  }
}

/** A `RoomManager` stand-in: records calls, holds keys for whatever `keys` names. */
export class FakeRooms implements SessionRooms {
  /** Channels we "hold a key" for. */
  keys = new Set<string>();
  /** Channels whose next `loadKeys` should succeed (a steward sealed to us). */
  sealable = new Set<string>();
  preKeyPublished = 0;
  created: Array<{ topic?: string; inviteTtlSecs?: number }> = [];
  joins: RoomLink[] = [];
  loads: string[] = [];
  removed: Array<{ channel: string; did: string }> = [];
  kept: string[] = [];
  stewarded: string[] = [];
  /** What the next steward passes report as sealed. */
  sealTo: string[] = [];
  infos = new Map<string, RoomInfo>();
  client?: FakeClient;
  /** Force `loadKeys` to throw, e.g. "GET …/groupkeys: HTTP 403". */
  loadError?: string;
  nextChannel = "#r-quiet-copper-fox";

  constructor(client?: FakeClient) {
    this.client = client;
  }

  async ensurePreKeyPublished(): Promise<void> {
    this.preKeyPublished++;
  }

  async create(opts: { topic?: string; inviteTtlSecs?: number } = {}) {
    this.created.push(opts);
    const channel = this.nextChannel;
    this.client?.join(channel);
    this.keys.add(channel);
    return {
      channel,
      invite: "tok_abc",
      url: `https://irc.test/r/${channel.slice(1)}#tok_abc`,
      expiresAt: 1_800_000_000,
    };
  }

  async join(link: RoomLink | string) {
    if (typeof link === "string") throw new Error("fake expects a parsed link");
    this.joins.push(link);
    const channel = link.channel.toLowerCase();
    this.client?.join(channel, link.token ?? undefined);
    const ready = await this.loadKeys(channel);
    return { channel, ready };
  }

  async loadKeys(channel: string): Promise<boolean> {
    const ch = channel.toLowerCase();
    this.loads.push(ch);
    if (this.loadError) throw new Error(this.loadError);
    if (this.sealable.has(ch)) this.keys.add(ch);
    return this.keys.has(ch);
  }

  async info(channel: string): Promise<RoomInfo> {
    const info = this.infos.get(channel.toLowerCase());
    if (!info) throw new Error(`GET /api/v1/rooms/${channel}: HTTP 403`);
    return info;
  }

  async keep(channel: string): Promise<number> {
    this.kept.push(channel.toLowerCase());
    return 1_900_000_000;
  }

  async removeMember(channel: string, did: string): Promise<void> {
    this.removed.push({ channel: channel.toLowerCase(), did });
  }

  async stewardPass(channel: string) {
    this.stewarded.push(channel.toLowerCase());
    return { sealed: [...this.sealTo], skipped: [] };
  }

  isRoom(channel: string): boolean {
    return this.keys.has(channel.toLowerCase());
  }

  channels(): string[] {
    return [...this.keys];
  }
}

export interface FakeRestRoute {
  status?: number;
  body?: unknown;
  contentType?: string;
}

/**
 * A `FreeqRest` backed by a route table instead of the network.
 *
 * Keys are `"<METHOD> <path>"`, e.g. `"GET /api/v1/health"`. Anything not in
 * the table 404s, which is what a real server would do and keeps a test from
 * passing because a URL was silently wrong.
 */
export function fakeRest(
  routes: Record<string, FakeRestRoute | ((url: URL, body: unknown) => FakeRestRoute)>,
  opts: { baseUrl?: string; requests?: string[]; headers?: Array<Record<string, string>> } = {},
): FreeqRest {
  const baseUrl = opts.baseUrl ?? "https://irc.test";
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input.toString();
    const url = new URL(raw);
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${url.pathname}`;
    opts.requests?.push(`${method} ${url.pathname}${url.search}`);
    opts.headers?.push((init?.headers ?? {}) as Record<string, string>);
    const entry = routes[key];
    if (!entry) {
      return new Response(`no fake route for ${key}`, { status: 404 });
    }
    const parsedBody = init?.body ? JSON.parse(init.body as string) : undefined;
    const route = typeof entry === "function" ? entry(url, parsedBody) : entry;
    const contentType = route.contentType ?? "application/json";
    const body =
      typeof route.body === "string" ? route.body : JSON.stringify(route.body ?? {});
    return new Response(body, { status: route.status ?? 200, headers: { "content-type": contentType } });
  }) as unknown as typeof fetch;
  return new FreeqRest({ baseUrl, fetchImpl });
}

export interface FakeSessionSetup {
  client: FakeClient;
  session: FreeqSession;
  cfg: FreeqMcpConfig;
  rooms?: FakeRooms;
}

export interface FakeSessionOptions {
  /** Attach a room manager (implies an authenticated, did:key session). */
  rooms?: FakeRooms;
  selfOwned?: boolean;
  /** Extra factory-result fields, e.g. a `start` that records it ran. */
  extra?: Partial<ClientFactoryResult>;
  warnings?: string[];
}

/** A `FreeqSession` wired to a `FakeClient`. */
export function fakeSession(
  env: Record<string, string | undefined> = {},
  mode: SessionMode = "guest",
  onBearerToken?: (t: string | undefined) => void,
  opts: FakeSessionOptions = {},
): FakeSessionSetup {
  const client = new FakeClient();
  const rooms = opts.rooms;
  if (rooms && !rooms.client) rooms.client = client;
  const cfg = loadConfig({ FREEQ_SERVER: "http://127.0.0.1:6668", ...env });
  const session = new FreeqSession(cfg, {
    createClient: async () => ({
      client,
      mode,
      did: mode === "authenticated" ? "did:key:z1" : undefined,
      selfOwned: opts.selfOwned,
      rooms,
      ...(opts.extra ?? {}),
    }),
    onBearerToken,
    warn: opts.warnings ? (m) => opts.warnings!.push(m) : () => undefined,
  });
  return { client, session, cfg, rooms };
}

/** A `Message`-shaped object, as the SDK would hand one over. */
export function fakeMessage(from: string, text: string, extra: Record<string, unknown> = {}) {
  return { id: "01J", from, text, timestamp: new Date(), tags: {}, ...extra };
}
