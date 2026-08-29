/**
 * Configuration for the freeq MCP server.
 *
 * An MCP server is launched by a host (Claude Desktop, Claude Code, Cursor…)
 * from a JSON stanza, so environment variables are the only realistic
 * configuration channel — there is no interactive prompt and no TTY. Every
 * setting therefore has a defensible default and the whole thing works with
 * an empty environment:
 *
 *   { "mcpServers": { "freeq": { "command": "node", "args": ["…/freeq-mcp/dist/index.js"] } } }
 */

/** Public production server. */
export const DEFAULT_SERVER = "https://irc.freeq.at";

export interface FreeqMcpConfig {
  /** Base HTTPS URL of the freeq server (no trailing slash). */
  baseUrl: string;
  /** WebSocket URL for the IRC transport, derived from `baseUrl` unless set. */
  wsUrl: string;
  /** Nick to register with. Defaults to `mcp-<8 hex>` derived from the host. */
  nick?: string;
  /**
   * Owner DID, recorded in the agent's delegation certificate.
   *
   * An agent acting for nobody is the thing freeq exists to prevent, so when
   * this is unset the identity is still a real `did:key` — it just carries no
   * delegation, and `freeq_whoami` says so plainly rather than implying it
   * speaks for a person.
   */
  ownerDid?: string;
  /** Bearer token for authenticated REST calls (uploads, favorites, budgets). */
  bearerToken?: string;
  /** Channels to join on connect. */
  channels: string[];
  /** Allow tools that write to the network (say, dm, join, ask). */
  allowWrites: boolean;
  /** Default timeout for request/reply tools, in ms. */
  askTimeoutMs: number;
  /** Cap on rows returned by history/search tools. */
  maxRows: number;
}

function normalizeBaseUrl(raw: string): string {
  let url = raw.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  return url.replace(/\/+$/, "");
}

/** `https://host` → `wss://host/irc`, `http://host` → `ws://host/irc`. */
export function deriveWsUrl(baseUrl: string): string {
  const u = new URL(baseUrl);
  u.protocol = u.protocol === "http:" ? "ws:" : "wss:";
  const path = u.pathname.replace(/\/+$/, "");
  u.pathname = `${path}/irc`;
  return u.toString();
}

export function splitChannels(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((c) => c.trim())
    .filter(Boolean)
    .map((c) => (c.startsWith("#") || c.startsWith("&") ? c : `#${c}`));
}

function boolEnv(raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw === "") return fallback;
  return !/^(0|false|no|off)$/i.test(raw.trim());
}

function intEnv(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

/**
 * Build config from an environment. Pure — takes the env rather than reading
 * `process.env` — so the tests don't have to mutate global state.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): FreeqMcpConfig {
  const baseUrl = normalizeBaseUrl(env.FREEQ_SERVER || DEFAULT_SERVER);
  return {
    baseUrl,
    wsUrl: env.FREEQ_WS_URL ? env.FREEQ_WS_URL.trim() : deriveWsUrl(baseUrl),
    nick: env.FREEQ_NICK?.trim() || undefined,
    ownerDid: env.FREEQ_OWNER_DID?.trim() || undefined,
    bearerToken: env.FREEQ_BEARER_TOKEN?.trim() || undefined,
    channels: splitChannels(env.FREEQ_CHANNELS),
    // Writes are on by default: a chat server you can only read is not much
    // use to an agent, and the host already gates tool calls with its own
    // approval UI. FREEQ_READ_ONLY=1 turns them off for untrusted setups.
    allowWrites: !boolEnv(env.FREEQ_READ_ONLY, false),
    askTimeoutMs: intEnv(env.FREEQ_ASK_TIMEOUT_MS, 120_000, 1_000, 600_000),
    maxRows: intEnv(env.FREEQ_MAX_ROWS, 200, 1, 1_000),
  };
}
