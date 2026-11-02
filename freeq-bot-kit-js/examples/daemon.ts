#!/usr/bin/env node
/**
 * Daemon shape — the same echo bot from `echo-bot.ts`, wrapped in
 * `createDaemonCLI` so it ships with `launch | stop | status | doctor
 * | tail` out of the box.
 *
 * Run from the repo root after `npm run build` in this package:
 *   npx tsx freeq-bot-kit-js/examples/daemon.ts launch \
 *     --owner did:plc:<your-did> --channel '#test'
 *   npx tsx freeq-bot-kit-js/examples/daemon.ts status
 *   npx tsx freeq-bot-kit-js/examples/daemon.ts doctor
 *   npx tsx freeq-bot-kit-js/examples/daemon.ts stop
 *
 * State lives at `~/.freeq/bots/daemon-example/`. Delete that directory
 * to start over with a fresh did:key.
 */

import { join } from "node:path";
import { homedir } from "node:os";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createDaemonCLI, FreeqBot, serverApiOrigin } from "../src/index.js";

const DIR = join(homedir(), ".freeq", "bots", "daemon-example");
const DEFAULT_SERVER = "wss://irc.freeq.at/irc";
// The server `launch` connected to, for `status` and `doctor`, which run in
// their own process without the launch flags.
const SERVER_FILE = join(DIR, "server-url");

interface DaemonOpts {
  ownerDid: string;
  nick: string;
  url: string;
  channel: string;
}

const program = createDaemonCLI<DaemonOpts>({
  name: "daemon-example",
  paths: {
    dir: DIR,
    daemonPid: join(DIR, "daemon.pid"),
    daemonLog: join(DIR, "daemon.log"),
    agentKey: join(DIR, "agent.key"),
    delegation: join(DIR, "delegation.json"),
  },
  // Extra flags on `launch` — passed through to preflight.
  launchOptions: [
    { flags: "--owner <did>", description: "Owner DID (required on first launch)" },
    { flags: "--nick <nick>", description: "Bot nick (default: daemon-example)" },
    { flags: "--channel <channel>", description: "Channel to join (default: #test)" },
    { flags: "--server <url>", description: "freeq WebSocket URL" },
  ],
  // Preflight runs in BOTH the foreground (before --detach fork) and the
  // detached child. Must be idempotent. Real daemons typically read a
  // config file here; this example just maps CLI flags through.
  preflight: async (parsed) => {
    const p = parsed as Record<string, string | undefined>;
    if (!p.owner) {
      console.error(
        "daemon-example: --owner did:plc:<your-did> is required on first launch.",
      );
      process.exit(1);
    }
    const url = p.server ?? DEFAULT_SERVER;
    await mkdir(DIR, { recursive: true, mode: 0o700 });
    await writeFile(SERVER_FILE, url + "\n");
    return {
      ownerDid: p.owner!,
      nick: p.nick ?? "daemon-example",
      url,
      channel: p.channel ?? "#test",
    };
  },
  // The daemon entry point. Only runs in the daemon process — the
  // scaffold wires SIGINT/SIGTERM and calls our stop() on shutdown.
  runDaemon: async (opts) => {
    const bot = await FreeqBot.create({
      name: "daemon-example",
      ownerDid: opts.ownerDid,
      nick: opts.nick,
      url: opts.url,
      channels: [opts.channel],
    });

    bot.on("message", (channel, msg) => {
      if (msg.isSelf) return;
      if (msg.text === "!ping") {
        bot.client.sendMessage(channel, "pong");
        return;
      }
      bot.client.sendMessage(channel, `echo: ${msg.text}`);
    });

    // 'deferred': the server could not check the bot just now, and the SDK
    // keeps trying. A refusal rejects start(), or later stops the bot; the
    // scaffold then exits 0 through `stopped`.
    const how = await bot.start();
    console.log(
      how === "ready"
        ? `[daemon-example] up as ${bot.client.nick} (${bot.identity.did})`
        : `[daemon-example] started as ${bot.identity.did}; the server will check it shortly`,
    );
    return { stop: (reason) => bot.stop(reason), stopped: bot.stopped };
  },
  // Enables the built-in provenance check in `status` + `doctor`, asked of
  // the server the bot connects to.
  actorStatusUrl: async (did) => {
    const url = (await readFile(SERVER_FILE, "utf8").catch(() => DEFAULT_SERVER)).trim();
    return `${serverApiOrigin(url)}/api/v1/actors/${encodeURIComponent(did)}`;
  },
  // Caller-added checks run after the built-ins (identity, delegation,
  // server actor record).
  doctorChecks: [
    {
      name: "node version >= 22",
      run: async () => {
        const major = Number.parseInt(process.versions.node.split(".")[0]!, 10);
        return major >= 22
          ? { ok: true, detail: process.versions.node }
          : { ok: false, reason: `node ${process.versions.node} (need ≥ 22)` };
      },
    },
  ],
});

program.parseAsync(process.argv).catch((err) => {
  console.error(err);
  process.exit(1);
});
