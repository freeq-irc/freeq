/**
 * Thin client for the freeq REST API (`spec/openapi.yaml`).
 *
 * Reads go over HTTP rather than IRC on purpose: history, search and
 * verification are request/response shaped, and an MCP tool call that has to
 * connect a WebSocket, wait for a CHATHISTORY batch and reassemble it is
 * slower and more failure-prone than one GET.
 */

export interface RestError extends Error {
  status?: number;
  body?: string;
}

export interface FreeqRestOptions {
  baseUrl: string;
  bearerToken?: string;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout, ms. */
  timeoutMs?: number;
}

export interface HistoryOptions {
  limit?: number;
  before?: number;
}

export interface SearchOptions extends HistoryOptions {
  channel: string;
  q: string;
}

/** `#general` → `%23general`, and a bare `general` is treated as `#general`. */
export function channelPath(name: string): string {
  const withHash = name.startsWith("#") || name.startsWith("&") ? name : `#${name}`;
  return encodeURIComponent(withHash);
}

export class FreeqRest {
  readonly baseUrl: string;
  #token?: string;
  #fetch: typeof fetch;
  #timeoutMs: number;

  constructor(opts: FreeqRestOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.#token = opts.bearerToken;
    this.#fetch = opts.fetchImpl ?? fetch;
    this.#timeoutMs = opts.timeoutMs ?? 15_000;
  }

  /** Late-bound: the IRC session learns a bearer token after SASL succeeds. */
  setBearerToken(token: string | undefined): void {
    this.#token = token;
  }

  get hasBearerToken(): boolean {
    return !!this.#token;
  }

  async get<T = unknown>(path: string): Promise<T> {
    return this.#request<T>("GET", path);
  }

  async getText(path: string): Promise<string> {
    const res = await this.#send("GET", path);
    return res.text();
  }

  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.#request<T>("POST", path, body);
  }

  async #request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.#send(method, path, body);
    const text = await res.text();
    if (!text) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      // A JSON endpoint that answers with prose is a server bug, but the tool
      // should report the prose rather than "unexpected token".
      const err = new Error(`${method} ${path}: response was not JSON: ${text.slice(0, 200)}`) as RestError;
      err.body = text;
      throw err;
    }
  }

  async #send(method: string, path: string, body?: unknown): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.#token) headers.authorization = `Bearer ${this.#token}`;
    if (body !== undefined) headers["content-type"] = "application/json";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    let res: Response;
    try {
      res = await this.#fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (cause) {
      const err = new Error(
        `${method} ${url} failed: ${(cause as Error).message ?? String(cause)}`,
      ) as RestError;
      throw err;
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      const err = new Error(this.#explain(method, path, res.status, text)) as RestError;
      err.status = res.status;
      err.body = text;
      throw err;
    }
    return res;
  }

  /**
   * Turn a status code into something an agent can act on.
   *
   * The bare status is a dead end for a caller that cannot see the spec: 403
   * on a channel means "+i or +k", not "your token is wrong", and 503 on
   * history means "this server runs without persistence".
   */
  #explain(method: string, path: string, status: number, body: string): string {
    const detail = body.trim().slice(0, 300);
    const suffix = detail ? ` — ${detail}` : "";
    switch (status) {
      case 401:
        return `${method} ${path}: 401 unauthorized. This endpoint needs a bearer token; set FREEQ_BEARER_TOKEN or connect so SASL can issue one.${suffix}`;
      case 403:
        return `${method} ${path}: 403 forbidden. Invite-only (+i) and key-protected (+k) channels are not readable over REST; join over IRC instead.${suffix}`;
      case 404:
        return `${method} ${path}: 404 not found. The channel, message or user does not exist on this server.${suffix}`;
      case 429:
        return `${method} ${path}: 429 rate limited. Back off and retry.${suffix}`;
      case 503:
        return `${method} ${path}: 503 unavailable. This server may run without persistence (no history/search) or without AV.${suffix}`;
      default:
        return `${method} ${path}: HTTP ${status}${suffix}`;
    }
  }

  // ── Typed endpoints ────────────────────────────────────────────────

  health(): Promise<unknown> {
    return this.get("/api/v1/health");
  }

  channels(): Promise<unknown> {
    return this.get("/api/v1/channels");
  }

  history(channel: string, opts: HistoryOptions = {}): Promise<unknown> {
    return this.get(
      `/api/v1/channels/${channelPath(channel)}/history${query({ ...opts })}`,
    );
  }

  search(opts: SearchOptions): Promise<unknown> {
    const { channel, q, ...rest } = opts;
    const params = new URLSearchParams({ channel: withHash(channel), q });
    for (const [k, v] of Object.entries(rest)) {
      if (v !== undefined) params.set(k, String(v));
    }
    return this.get(`/api/v1/search?${params.toString()}`);
  }

  message(msgid: string): Promise<unknown> {
    return this.get(`/api/v1/messages/${encodeURIComponent(msgid)}`);
  }

  verify(msgid: string): Promise<unknown> {
    return this.get(`/api/v1/verify/${encodeURIComponent(msgid)}`);
  }

  pins(channel: string): Promise<unknown> {
    return this.get(`/api/v1/channels/${channelPath(channel)}/pins`);
  }

  topic(channel: string): Promise<unknown> {
    return this.get(`/api/v1/channels/${channelPath(channel)}/topic`);
  }

  whois(nick: string): Promise<unknown> {
    return this.get(`/api/v1/users/${encodeURIComponent(nick)}/whois`);
  }

  actor(did: string): Promise<unknown> {
    return this.get(`/api/v1/actors/${encodeURIComponent(did)}`);
  }

  agentDiscovery(): Promise<unknown> {
    return this.get("/.well-known/agent.json");
  }

  openapi(): Promise<unknown> {
    return this.get("/api/v1/openapi.json");
  }

  llmsTxt(): Promise<string> {
    return this.getText("/llms.txt");
  }

  /** Agent Assistance Interface: `POST /agent/tools/<tool>`. */
  assist(tool: string, input: unknown): Promise<unknown> {
    return this.post(`/agent/tools/${tool}`, input ?? {});
  }
}

function withHash(name: string): string {
  return name.startsWith("#") || name.startsWith("&") ? name : `#${name}`;
}

function query(opts: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(opts)) {
    if (v !== undefined && v !== null) params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}
