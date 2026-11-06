/**
 * `freeq-mcp room …` — the room tools as one-shot commands.
 *
 * For agents that only run commands (and for a human at a shell), the room
 * share page says `npx -y @freeq/mcp room join <url>`, so the same binary
 * has to answer that. Each invocation builds a session, connects, does one
 * thing through the same tool bodies the MCP surface uses, prints to stdout,
 * disconnects and exits. Nothing here is loaded in MCP mode, where stdout is
 * the JSON-RPC transport.
 *
 * The parser is hand-rolled: seven subcommands with two flags each do not
 * justify a dependency, and the usage text is the whole contract.
 */

import { loadConfig } from "./config.js";
import { FreeqRest } from "./rest.js";
import { FreeqSession, normalizeChannel } from "./session.js";
import * as tools from "./tools.js";
import type { ToolContext } from "./tools.js";

export type RoomCommand =
  | { kind: "create"; topic?: string }
  | { kind: "join"; url: string }
  | { kind: "say"; target: string; text: string }
  | { kind: "read"; target: string; waitSecs?: number; history: boolean; limit?: number }
  | { kind: "who"; target: string }
  | { kind: "invite"; target: string; ttlSecs?: number; maxUses?: number }
  | { kind: "keep"; target: string }
  | { kind: "help" };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export const ROOM_USAGE = `usage: freeq-mcp room <command> [options]

  create [--topic <text>]                 mint a room; prints its share URL
  join   <url>                            join a room from its share URL
  say    <url|#room> <text…>              send an (encrypted) message
  read   <url|#room> [--wait <secs>] [--history] [--limit <n>]
                                          print messages, decrypted; --history replays earlier ones
  who    <url|#room>                      roster, founder, expiry
  invite <url|#room> [--ttl <secs>] [--max-uses <n>]
                                          mint a fresh invite URL (founder only)
  keep   <url|#room>                      push the room's expiry out

Identity: a self-owned did:key under ~/.freeq/bots/<nick>/ unless FREEQ_OWNER_DID
binds it to you. Server: FREEQ_SERVER (default https://irc.freeq.at).
Output is JSON, except \`read\`, which prints one line per message.`;

/** Parse `argv` as given after `room`. Throws `UsageError` with a reason. */
export function parseRoomArgs(argv: string[]): RoomCommand {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") return { kind: "help" };

  const { flags, positional } = splitFlags(rest);
  const target = (what: string): string => {
    const t = positional[0];
    if (!t) throw new UsageError(`room ${cmd}: missing ${what}`);
    return t;
  };
  const int = (name: string): number | undefined => {
    const raw = flags.get(name);
    if (raw === undefined) return undefined;
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n) || n <= 0) throw new UsageError(`--${name} must be a positive integer, got ${JSON.stringify(raw)}`);
    return n;
  };
  const only = (...allowed: string[]) => {
    for (const name of flags.keys()) {
      if (!allowed.includes(name)) throw new UsageError(`room ${cmd}: unknown option --${name}`);
    }
  };

  switch (cmd) {
    case "create":
      only("topic");
      if (positional.length > 0) throw new UsageError(`room create takes no positional arguments (use --topic)`);
      return { kind: "create", topic: flags.get("topic") };
    case "join":
      only();
      return { kind: "join", url: target("room URL") };
    case "say": {
      only();
      const t = target("room URL or #name");
      const text = positional.slice(1).join(" ").trim();
      if (!text) throw new UsageError("room say: missing message text");
      return { kind: "say", target: t, text };
    }
    case "read":
      only("wait", "history", "limit");
      return {
        kind: "read",
        target: target("room URL or #name"),
        waitSecs: int("wait"),
        history: flags.has("history"),
        limit: int("limit"),
      };
    case "who":
      only();
      return { kind: "who", target: target("room URL or #name") };
    case "invite":
      only("ttl", "max-uses");
      return { kind: "invite", target: target("room URL or #name"), ttlSecs: int("ttl"), maxUses: int("max-uses") };
    case "keep":
      only();
      return { kind: "keep", target: target("room URL or #name") };
    default:
      throw new UsageError(`unknown room command: ${cmd}`);
  }
}

/** `--flag value`, `--flag=value`, bare `--flag` (value "true"); `--` ends flags. */
function splitFlags(args: string[]): { flags: Map<string, string>; positional: string[] } {
  const flags = new Map<string, string>();
  const positional: string[] = [];
  const valueless = new Set(["history"]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      positional.push(...args.slice(i + 1));
      break;
    }
    if (!a.startsWith("--") || a.length === 2) {
      positional.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    if (eq > 0) {
      flags.set(a.slice(2, eq), a.slice(eq + 1));
      continue;
    }
    const name = a.slice(2);
    if (valueless.has(name)) {
      flags.set(name, "true");
      continue;
    }
    const next = args[i + 1];
    if (next === undefined || next.startsWith("--")) throw new UsageError(`--${name} needs a value`);
    flags.set(name, next);
    i++;
  }
  return { flags, positional };
}

export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
  env?: Record<string, string | undefined>;
  /** Injected in tests: the context to run against instead of a real one. */
  context?(): ToolContext;
}

/** Build a real context: REST + session sharing one bearer, like the MCP server. */
export function createToolContext(env: Record<string, string | undefined> = process.env): ToolContext {
  const cfg = loadConfig(env);
  const rest = new FreeqRest({ baseUrl: cfg.baseUrl, bearerToken: cfg.bearerToken });
  const session = new FreeqSession(cfg, {
    onBearerToken: (token) => rest.setBearerToken(token),
    warn: (m) => process.stderr.write(`freeq-mcp: ${m}\n`),
  });
  return { cfg, rest, session };
}

/** Run one room command. Returns the process exit code. */
export async function runRoomCli(argv: string[], io: CliIo): Promise<number> {
  let cmd: RoomCommand;
  try {
    cmd = parseRoomArgs(argv);
  } catch (err) {
    io.stderr(`${(err as Error).message}\n\n${ROOM_USAGE}\n`);
    return 1;
  }
  if (cmd.kind === "help") {
    io.stdout(`${ROOM_USAGE}\n`);
    return 0;
  }

  const ctx = io.context ? io.context() : createToolContext(io.env ?? process.env);
  try {
    const out = await runRoomCommand(ctx, cmd);
    io.stdout(out.endsWith("\n") ? out : `${out}\n`);
    return 0;
  } catch (err) {
    io.stderr(`freeq-mcp room ${cmd.kind}: ${(err as Error).message}\n`);
    return 1;
  } finally {
    await ctx.session.close("done").catch(() => undefined);
  }
}

/** Dispatch to the tool bodies; returns what to print. */
export async function runRoomCommand(ctx: ToolContext, cmd: RoomCommand): Promise<string> {
  switch (cmd.kind) {
    case "create":
      return json(await tools.roomCreate(ctx, { topic: cmd.topic }));
    case "join":
      return json(await tools.roomJoin(ctx, { url: cmd.url }));
    case "say": {
      await ctx.session.connect();
      const link = tools.resolveRoomTarget(ctx, cmd.target);
      const joined = ctx.session.inChannel(link.channel)
        ? { channel: normalizeChannel(link.channel), ready: ctx.session.hasRoomKey(link.channel) }
        : await ctx.session.roomJoin(link);
      if (!joined.ready) {
        const again = await ctx.session.rooms.loadKeys(joined.channel);
        if (!again && !ctx.session.hasRoomKey(joined.channel)) {
          throw new Error(
            `no room key sealed to this agent yet for ${joined.channel}; a member's client seals it on join. Retry in a few seconds.`,
          );
        }
      }
      return json(await tools.say(ctx, { target: joined.channel, text: cmd.text }));
    }
    case "read": {
      const res = (await tools.roomRead(ctx, {
        channel_or_url: cmd.target,
        wait_ms: cmd.waitSecs !== undefined ? cmd.waitSecs * 1000 : undefined,
        history: cmd.history,
        limit: cmd.limit,
      })) as {
        channel: string;
        ready: boolean;
        messages: Array<{ from: string; did?: string; text: string; at: number; encrypted: boolean }>;
        note?: string;
      };
      return formatRead(res);
    }
    case "who":
      return json(await tools.roomInfo(ctx, { channel_or_url: cmd.target }));
    case "invite":
      return json(
        await tools.roomInvite(ctx, { channel_or_url: cmd.target, ttl_secs: cmd.ttlSecs, max_uses: cmd.maxUses }),
      );
    case "keep":
      return json(await tools.roomKeep(ctx, { channel_or_url: cmd.target }));
    case "help":
      return ROOM_USAGE;
  }
}

/** One line per message: `[ISO time] <nick> text`, with the DID when known. */
export function formatRead(res: {
  channel: string;
  ready: boolean;
  messages: Array<{ from: string; did?: string; text: string; at: number }>;
  note?: string;
}): string {
  if (!res.ready) return `# ${res.channel}: not ready — ${res.note ?? "no key yet"}`;
  const lines = res.messages.map((m) => {
    const who = m.did ? `${m.from} (${m.did})` : m.from;
    const text = m.text.replace(/\r?\n/g, "\n    ");
    return `[${new Date(m.at).toISOString()}] <${who}> ${text}`;
  });
  if (lines.length === 0) return `# ${res.channel}: ${res.note ?? "no messages"}`;
  return lines.join("\n");
}

function json(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
