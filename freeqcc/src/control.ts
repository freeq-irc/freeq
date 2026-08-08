// Owner-driven IRC actions via a per-dispatch capability token.
//
// On launch, the daemon binds ~/.freeqcc/control.sock (mode 0600), unlinking
// any stale entry. Each accepted connection reads one JSON line of the form
//   {token, action, args}
// validates the token against the in-memory store, dispatches to an action
// handler that drives the freeq SDK client, and writes back one JSON line
// {ok, ...}. Messages go through the client's signed send path; only the
// control verbs (JOIN/PART/NICK) are written as raw lines.
//
// Tokens are minted in handleDm (daemon.ts), expire on dispatch completion
// (dispatch.ts onComplete/onError), and have a 10-min hard TTL safety net.
//
// `freeqcc send` (cli.ts) is the client side: reads token + sock from env,
// makes one round-trip.
import { createServer, createConnection, type Socket, type Server } from "node:net";
import { unlink, chmod } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { paths, ensureDir } from "./paths.js";

export interface TokenContext {
  /** Marker only; auth decisions are made via `actions` below. */
  isOwner: boolean;
  /** Action names this token is allowed to invoke. Owner gets the full set
   *  (see allowlist.OWNER_ACTIONS); allowlisted DIDs get their granted set;
   *  anyone else gets [] (and never reaches a control-socket request). */
  actions: Set<string>;
  replyTarget: string;
  /** Sender DID — for log lines and audit. */
  senderDid: string | null;
  expiresAt: number; // ms epoch
}

// 60s hard TTL: the dispatch loop expires tokens explicitly on
// onComplete/onError, so this is just a safety net for crashes that skip
// those callbacks. Single-DM dispatches almost always finish well under 60s.
const HARD_TTL_MS = 60 * 1000;

export class TokenStore {
  private map = new Map<string, TokenContext>();

  mint(ctx: Omit<TokenContext, "expiresAt" | "actions"> & { actions: Iterable<string> }): string {
    const token = randomUUID();
    this.map.set(token, {
      ...ctx,
      actions: new Set(ctx.actions),
      expiresAt: Date.now() + HARD_TTL_MS,
    });
    return token;
  }

  /** Look up a token. Returns null if unknown OR past TTL. */
  get(token: string): TokenContext | null {
    const ctx = this.map.get(token);
    if (!ctx) return null;
    if (Date.now() > ctx.expiresAt) {
      this.map.delete(token);
      return null;
    }
    return ctx;
  }

  /** Drop a token (called by dispatch.ts in onComplete/onError). */
  expire(token: string): void {
    this.map.delete(token);
  }

  /** Sweep expired tokens; called periodically as defense-in-depth. */
  sweep(): number {
    const now = Date.now();
    let removed = 0;
    for (const [t, ctx] of this.map) {
      if (now > ctx.expiresAt) {
        this.map.delete(t);
        removed++;
      }
    }
    return removed;
  }
}

// ── Wire format ──

interface Request {
  token?: string;
  action?: string;
  args?: unknown[];
}

interface Response {
  ok: boolean;
  error?: string;
  result?: unknown;
}

// ── Action dispatch ──

/** A minimal interface over the FreeqClient that we actually need. The SDK
 *  type is intentionally NOT imported here so this module can be tested in
 *  isolation. The daemon passes an object backed by the client. */
export interface IrcSink {
  /** Control verbs — JOIN, PART, NICK. Nothing a signature is about. */
  raw(line: string): void;
  /** A message under this agent's name. Goes through the client's signed
   *  send path: a hand-built line bypasses the armed session key, and the
   *  message arrives with the server vouching instead of the sender. */
  say(target: string, text: string): void;
  /** A notice under this agent's name. Signed for the same reason. */
  notice(target: string, text: string): void;
  readonly nick: string;
}

// Length caps: defense-in-depth so a runaway model can't push 100KB into a
// single IRC line (servers will truncate/disconnect, but we'd rather catch it
// here with a clean error than rely on remote behavior).
const MAX_CHANNEL_LEN = 200;
const MAX_NICK_LEN = 64;
const MAX_TEXT_LEN = 2000;

function asString(v: unknown, name: string): string {
  if (typeof v !== "string") throw new Error(`bad args: ${name} must be a string`);
  return v;
}

function asChannel(v: unknown, name: string): string {
  const s = asString(v, name);
  if (!s.startsWith("#") && !s.startsWith("&")) {
    throw new Error(`bad args: ${name} must start with # or &`);
  }
  if (/[\s,\0\r\n]/.test(s)) throw new Error(`bad args: ${name} has invalid chars`);
  if (s.length > MAX_CHANNEL_LEN) throw new Error(`bad args: ${name} > ${MAX_CHANNEL_LEN} chars`);
  return s;
}

/** Validate a user nick (no #/& prefix, no separators, length-capped). Used
 *  for privmsg-user / notice-user / nick targets. */
function asNick(v: unknown, name: string): string {
  const s = asString(v, name);
  if (s.startsWith("#") || s.startsWith("&")) {
    throw new Error(`bad args: ${name} looks like a channel; use privmsg-channel instead`);
  }
  if (/[\s,\0\r\n]/.test(s)) throw new Error(`bad args: ${name} has invalid chars`);
  if (s.length === 0) throw new Error(`bad args: ${name} cannot be empty`);
  if (s.length > MAX_NICK_LEN) throw new Error(`bad args: ${name} > ${MAX_NICK_LEN} chars`);
  return s;
}

function asText(v: unknown, name: string): string {
  const s = asString(v, name);
  // PRIVMSG/NOTICE bodies must not contain bare CR/LF (would break the wire).
  if (/[\r\n\0]/.test(s)) throw new Error(`bad args: ${name} contains control chars`);
  if (s.length > MAX_TEXT_LEN) throw new Error(`bad args: ${name} > ${MAX_TEXT_LEN} chars`);
  return s;
}

/** Run a validated action. Returns the response payload (caller adds {ok:true}). */
function runAction(action: string, args: unknown[], sink: IrcSink): Record<string, unknown> {
  switch (action) {
    case "join": {
      const channel = asChannel(args[0], "channel");
      sink.raw(`JOIN ${channel}`);
      return {};
    }
    case "part": {
      const channel = asChannel(args[0], "channel");
      const reason = args[1] !== undefined ? asText(args[1], "reason") : null;
      sink.raw(reason ? `PART ${channel} :${reason}` : `PART ${channel}`);
      return {};
    }
    case "privmsg-user": {
      const target = asNick(args[0], "nick");
      const text = asText(args[1], "text");
      sink.say(target, text);
      return {};
    }
    case "privmsg-channel": {
      const target = asChannel(args[0], "channel");
      const text = asText(args[1], "text");
      sink.say(target, text);
      return {};
    }
    case "notice-user": {
      const target = asNick(args[0], "nick");
      const text = asText(args[1], "text");
      sink.notice(target, text);
      return {};
    }
    case "notice-channel": {
      const target = asChannel(args[0], "channel");
      const text = asText(args[1], "text");
      sink.notice(target, text);
      return {};
    }
    case "nick": {
      const newnick = asNick(args[0], "newnick");
      sink.raw(`NICK ${newnick}`);
      return {};
    }
    default:
      throw new Error(`unknown action: ${action}`);
  }
}

// ── Server ──

export interface ControlServerHandle {
  close(): Promise<void>;
}

export interface ControlServerOptions {
  store: TokenStore;
  sink: IrcSink;
  /** Override the socket path (default paths.controlSock). Mostly for tests. */
  socketPath?: string;
  /** Optional logger; defaults to console.log. */
  log?: (line: string) => void;
}

export async function startControlServer(opts: ControlServerOptions): Promise<ControlServerHandle> {
  const sockPath = opts.socketPath ?? paths.controlSock;
  const log = opts.log ?? ((s: string) => console.log(s));

  await ensureDir();
  // Unlink stale socket from a previous (crashed) run
  try {
    await unlink(sockPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  const server: Server = createServer((sock: Socket) => {
    let buf = "";
    let answered = false;

    const reply = (resp: Response): void => {
      if (answered) return;
      answered = true;
      try {
        sock.write(JSON.stringify(resp) + "\n");
      } catch {
        // ignore — peer may have hung up
      }
      sock.end();
    };

    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);

      let req: Request;
      try {
        req = JSON.parse(line) as Request;
      } catch {
        return reply({ ok: false, error: "request not valid JSON" });
      }
      const { token, action } = req;
      const args = Array.isArray(req.args) ? req.args : [];
      if (typeof token !== "string" || typeof action !== "string") {
        return reply({ ok: false, error: "request missing token or action" });
      }

      const ctx = opts.store.get(token);
      if (!ctx) {
        return reply({ ok: false, error: "invalid or expired token" });
      }
      if (!ctx.actions.has(action)) {
        const grants = Array.from(ctx.actions);
        log(`[control] denied: action '${action}' not granted to ${ctx.senderDid ?? "(no DID)"} (granted: ${grants.join(",") || "none"})`);
        const have = grants.length > 0 ? grants.join(", ") : "none";
        return reply({
          ok: false,
          error: `action '${action}' not granted; you have: ${have}`,
        });
      }

      try {
        const result = runAction(action, args, opts.sink);
        const role = ctx.isOwner ? "owner" : (ctx.senderDid ?? "allowlisted");
        log(`[control] ${role} ran ${action} ${JSON.stringify(args).slice(0, 200)}`);
        reply({ ok: true, ...result });
      } catch (err) {
        const msg = (err as Error).message;
        log(`[control] action failed: ${action} — ${msg}`);
        reply({ ok: false, error: msg });
      }
    });

    sock.on("error", () => {
      // peer dropped — best effort cleanup
      reply({ ok: false, error: "socket error" });
    });

    // Cap connection lifetime so a slow client can't pin a fd.
    setTimeout(() => {
      if (!answered) reply({ ok: false, error: "request timed out" });
    }, 5000);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, () => resolve());
  });
  await chmod(sockPath, 0o600);
  log(`[control] listening on ${sockPath}`);

  // Periodic sweep of expired tokens
  const sweepTimer = setInterval(() => {
    const removed = opts.store.sweep();
    if (removed > 0) log(`[control] swept ${removed} expired tokens`);
  }, 60_000);
  sweepTimer.unref();

  return {
    async close() {
      clearInterval(sweepTimer);
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try {
        await unlink(sockPath);
      } catch {
        // ignore
      }
    },
  };
}

// ── Client side: used by `freeqcc send` ──

export async function callControl(req: Request, socketPath: string): Promise<Response> {
  return new Promise((resolve, reject) => {
    const sock = createConnection(socketPath);
    let buf = "";
    let resolved = false;

    const settle = (resp: Response): void => {
      if (resolved) return;
      resolved = true;
      try {
        sock.end();
      } catch {
        // ignore
      }
      resolve(resp);
    };

    sock.setEncoding("utf8");
    sock.on("connect", () => {
      sock.write(JSON.stringify(req) + "\n");
    });
    sock.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      try {
        settle(JSON.parse(line) as Response);
      } catch (e) {
        settle({ ok: false, error: `invalid response: ${(e as Error).message}` });
      }
    });
    sock.on("error", (err) => {
      if (resolved) return;
      resolved = true;
      reject(err);
    });
    sock.on("close", () => {
      if (!resolved) settle({ ok: false, error: "connection closed without reply" });
    });
    setTimeout(() => settle({ ok: false, error: "timed out waiting for daemon reply" }), 5000);
  });
}
