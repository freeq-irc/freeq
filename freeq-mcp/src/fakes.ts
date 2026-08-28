/**
 * Test doubles shared by the test files.
 *
 * Excluded from the published build (see tsconfig `exclude`) — it exists so
 * the session and MCP-surface tests drive the same fake client rather than
 * keeping two subtly different ones.
 */

import { loadConfig, type FreeqMcpConfig } from "./config.js";
import { FreeqRest } from "./rest.js";
import { FreeqSession, type SessionClient, type SessionMode } from "./session.js";

/** A hand-driven stand-in for the SDK's FreeqClient. */
export class FakeClient implements SessionClient {
  nick: string | null = "mcp-test";
  apiBearer: string | null = null;
  handlers = new Map<string, Array<(...args: never[]) => void>>();
  sent: Array<{ target: string; text: string }> = [];
  tagmsgs: Array<{ target: string; tags: Record<string, string> }> = [];
  joined: string[] = [];
  connected = false;
  quitReason?: string;

  on(event: string, handler: (...args: never[]) => void): this {
    const list = this.handlers.get(event) ?? [];
    list.push(handler);
    this.handlers.set(event, list);
    return this;
  }

  emit(event: string, ...args: unknown[]): void {
    for (const h of this.handlers.get(event) ?? []) (h as (...a: unknown[]) => void)(...args);
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

  join(channel: string): void {
    this.joined.push(channel);
    this.emit("channelJoined", channel);
  }

  sendMessage(target: string, text: string): void {
    this.sent.push({ target, text });
  }

  sendTagmsg(target: string, tags: Record<string, string>): void {
    this.tagmsgs.push({ target, tags });
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
  opts: { baseUrl?: string; requests?: string[] } = {},
): FreeqRest {
  const baseUrl = opts.baseUrl ?? "https://irc.test";
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input.toString();
    const url = new URL(raw);
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${url.pathname}`;
    opts.requests?.push(`${method} ${url.pathname}${url.search}`);
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
}

/** A `FreeqSession` wired to a `FakeClient`. */
export function fakeSession(
  env: Record<string, string | undefined> = {},
  mode: SessionMode = "guest",
  onBearerToken?: (t: string | undefined) => void,
): FakeSessionSetup {
  const client = new FakeClient();
  const cfg = loadConfig({ FREEQ_SERVER: "http://127.0.0.1:6668", ...env });
  const session = new FreeqSession(cfg, {
    createClient: async () => ({
      client,
      mode,
      did: mode === "authenticated" ? "did:key:z1" : undefined,
    }),
    onBearerToken,
  });
  return { client, session, cfg };
}

/** A `Message`-shaped object, as the SDK would hand one over. */
export function fakeMessage(from: string, text: string, extra: Record<string, unknown> = {}) {
  return { id: "01J", from, text, timestamp: new Date(), tags: {}, ...extra };
}
