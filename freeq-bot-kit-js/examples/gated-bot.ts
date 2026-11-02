#!/usr/bin/env node
/**
 * Gated bot — composes all four message-handling primitives in one
 * realistic-looking daemon. Use this as a template for a bot that:
 *
 *   - Only responds to its owner (and an opt-in allowlist of DIDs)
 *   - Rate-limits itself (hourly cap + per-peer cycle detection)
 *   - Handles both DMs and channel @-mentions
 *   - Persists its allowlist + gate state to disk
 *   - Ships with launch / stop / status / doctor / tail commands
 *
 * Run:
 *   npx tsx freeq-bot-kit-js/examples/gated-bot.ts launch \
 *     --owner did:plc:<your-did> --channel '#test'
 *   npx tsx freeq-bot-kit-js/examples/gated-bot.ts status
 *   npx tsx freeq-bot-kit-js/examples/gated-bot.ts doctor
 *   npx tsx freeq-bot-kit-js/examples/gated-bot.ts stop
 *
 * State lives at ~/.freeq/bots/gated-bot-example/. Delete that
 * directory to start fresh with a new did:key.
 */

import { homedir } from "node:os";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import writeFileAtomic from "write-file-atomic";
import {
  FreeqBot,
  createDaemonCLI,
  createDidMap,
  createTurnGate,
  serverApiOrigin,
  type TurnGateState,
} from "../src/index.js";

const STATE_DIR = join(homedir(), ".freeq", "bots", "gated-bot-example");
const ALLOWLIST_PATH = join(STATE_DIR, "allowlist.json");
const GATE_PATH = join(STATE_DIR, "gate.json");
const DEFAULT_SERVER = "wss://irc.freeq.at/irc";
// The server `launch` connected to, for `status` and `doctor`, which run in
// their own process without the launch flags.
const SERVER_FILE = join(STATE_DIR, "server-url");

interface AllowEntry {
  did: string;
  label?: string;
}

interface DaemonOpts {
  ownerDid: string;
  url: string;
  channel: string;
  nick: string;
}

const program = createDaemonCLI<DaemonOpts>({
  name: "gated-bot",
  paths: {
    dir: STATE_DIR,
    daemonPid: join(STATE_DIR, "daemon.pid"),
    daemonLog: join(STATE_DIR, "daemon.log"),
    agentKey: join(STATE_DIR, "agent.key"),
    delegation: join(STATE_DIR, "delegation.json"),
  },
  launchOptions: [
    { flags: "--owner <did>", description: "Owner DID (required on first launch)" },
    { flags: "--channel <channel>", description: "Channel to join (default: #test)" },
    { flags: "--nick <nick>", description: "Bot nick (default: gated-bot)" },
    { flags: "--server <url>", description: "freeq WebSocket URL" },
  ],
  preflight: async (parsed) => {
    const p = parsed as Record<string, string | undefined>;
    if (!p.owner) {
      console.error(
        "gated-bot: --owner did:plc:<your-did> is required on first launch.",
      );
      process.exit(1);
    }
    const url = p.server ?? DEFAULT_SERVER;
    await mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
    await writeFile(SERVER_FILE, url + "\n");
    return {
      ownerDid: p.owner!,
      url,
      channel: p.channel ?? "#test",
      nick: p.nick ?? "gated-bot",
    };
  },
  runDaemon: async (opts) => {
    // ── 1. Allowlist ───────────────────────────────────────────────
    // Live-reloadable DID-keyed map. Operator can edit allowlist.json
    // by hand or via the bot's own grant commands; the daemon picks
    // up changes within ~2 seconds without restart.
    const allowlist = await createDidMap<AllowEntry>({
      load: {
        path: ALLOWLIST_PATH,
        parse: (raw) => {
          const obj = JSON.parse(raw) as { entries?: AllowEntry[] };
          return obj.entries ?? [];
        },
      },
      save: async (entries) => {
        await writeFileAtomic(
          ALLOWLIST_PATH,
          JSON.stringify({ entries }, null, 2) + "\n",
          { mode: 0o600 },
        );
      },
    });

    // ── 2. Rate-limit gate ─────────────────────────────────────────
    // 30 dispatches/hr, 10-turn cycle detection at 5 min, persisted
    // to gate.json so refusal cooldowns and cycle backoffs survive
    // restarts.
    const gate = await createTurnGate({
      hourlyCap: 30,
      cyclePolicy: {
        windowMs: 5 * 60_000,
        turnCap: 10,
        backoffMs: 10 * 60_000,
      },
      load: async () => {
        try {
          return JSON.parse(await readFile(GATE_PATH, "utf8")) as TurnGateState;
        } catch {
          return {
            lastRefusalAt: [],
            lastDispatchAt: 0,
            dispatchTimestamps: [],
            perPeerDispatches: [],
            cycleBackoffUntil: [],
          };
        }
      },
      save: async (state) => {
        await writeFileAtomic(GATE_PATH, JSON.stringify(state) + "\n", {
          mode: 0o600,
        });
      },
    });

    // ── 3. The bot itself ──────────────────────────────────────────
    const bot = await FreeqBot.create({
      name: "gated-bot-example",
      ownerDid: opts.ownerDid,
      nick: opts.nick,
      url: opts.url,
      channels: [opts.channel],
    });

    // Inbound message handler — composes all four primitives.
    bot.on("message", async (channel, msg) => {
      if (msg.isSelf) return;

      const isChannel = channel.startsWith("#") || channel.startsWith("&");
      const isDm = !isChannel;
      const isBotChannel = channel.toLowerCase() === `#${opts.nick}`.toLowerCase();

      // Decide what to handle:
      //   - DMs: every message
      //   - The bot's own channel: every message (DM-surface convention)
      //   - Other channels: only when @-mentioned (uses bot.checkMention)
      let text = msg.text;
      if (isChannel && !isBotChannel) {
        const m = bot.checkMention(channel, msg.text);
        if (m.kind === "ignore") return;
        if (m.kind === "cooldown") {
          console.log(
            `[mention cooldown] ${channel}: silent (${Math.round(m.remainingMs / 1000)}s left)`,
          );
          return;
        }
        text = m.stripped || msg.text;
      }

      // Resolve sender to a DID (account-tag → cache → WHOIS with 3s timeout).
      const senderDid = await bot.resolveSenderDid({
        from: msg.from,
        tags: msg.tags,
      });

      // ── Owner-only allowlist commands (DM only) ─────────────────
      //
      // Bypasses the gate intentionally — administrative actions
      // shouldn't count toward the hourly cap. Only the owner can
      // invoke; everyone else falls through to the normal policy
      // check below.
      if (senderDid === opts.ownerDid && isDm) {
        const replyTarget = msg.from;
        const cmd = text.trim();

        const grant = /^!grant\s+(did:\S+?)(?:\s+(.+))?$/.exec(cmd);
        if (grant) {
          await allowlist.set({ did: grant[1]!, label: grant[2] });
          bot.client.sendMessage(
            replyTarget,
            `granted ${grant[1]}${grant[2] ? ` (${grant[2]})` : ""}`,
          );
          return;
        }
        const revoke = /^!revoke\s+(did:\S+)$/.exec(cmd);
        if (revoke) {
          const had = await allowlist.delete(revoke[1]!);
          bot.client.sendMessage(
            replyTarget,
            had ? `revoked ${revoke[1]}` : `${revoke[1]} was not on the allowlist`,
          );
          return;
        }
        if (cmd === "!grants") {
          const entries = allowlist.list();
          if (entries.length === 0) {
            bot.client.sendMessage(replyTarget, "(allowlist is empty)");
          } else {
            for (const e of entries) {
              bot.client.sendMessage(
                replyTarget,
                `  ${e.did}${e.label ? ` (${e.label})` : ""}`,
              );
            }
          }
          return;
        }
        if (cmd === "!help") {
          bot.client.sendMessage(
            replyTarget,
            "owner commands: !grant <did> [label] · !revoke <did> · !grants · !help",
          );
          return;
        }
      }

      // Policy: owner is always allowed; allowlisted DIDs are allowed;
      // everyone else is refused (with refuse-once-then-silent).
      const isAllowed =
        senderDid !== null &&
        (senderDid === opts.ownerDid || allowlist.has(senderDid));

      const decision = gate.evaluate({
        senderDid,
        senderNick: msg.from,
        refusalReason: isAllowed
          ? undefined
          : senderDid
            ? "not on allowlist"
            : "could not verify your identity",
        // Owner is exempt from cycle detection (humans aren't bots).
        skipCycleDetection: senderDid === opts.ownerDid,
      });

      const replyTarget = isDm ? msg.from : channel;
      switch (decision.kind) {
        case "silent":
          return;
        case "refuse":
          bot.client.sendMessage(
            replyTarget,
            `Sorry — ${decision.reason}. (This is an owner-gated bot.)`,
          );
          await gate.persist();
          return;
        case "dispatch":
          // The actual "do the work" branch. For this example we just
          // echo back with the resolved DID. A real bot would call out
          // to an LLM, run a tool, fetch a URL, etc.
          bot.client.sendMessage(
            replyTarget,
            `hi ${senderDid ?? msg.from} — you said: ${text}`,
          );
          await gate.persist();
          return;
      }
    });

    const how = await bot.start();
    console.log(
      how === "ready"
        ? `[gated-bot] up as ${bot.client.nick} (${bot.identity.did})`
        : `[gated-bot] started as ${bot.identity.did}; the server will check it shortly`,
    );
    console.log(`  owner:     ${opts.ownerDid}`);
    console.log(`  allowlist: ${allowlist.list().length} extra DID(s)`);

    return {
      stop: async (reason) => {
        await gate.persist().catch(() => {});
        allowlist.close();
        await bot.stop(reason);
      },
      stopped: bot.stopped,
    };
  },
  actorStatusUrl: async (did) => {
    const url = (await readFile(SERVER_FILE, "utf8").catch(() => DEFAULT_SERVER)).trim();
    return `${serverApiOrigin(url)}/api/v1/actors/${encodeURIComponent(did)}`;
  },
});

program.parseAsync(process.argv).catch((err) => {
  console.error(err);
  process.exit(1);
});
