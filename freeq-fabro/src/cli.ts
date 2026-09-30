#!/usr/bin/env node
// freeq-fabro — relays Fabro run notifications into a freeq channel.
//
// Runs next to the Fabro server (on the boxd executor VM under systemd, see
// .fabro/executor/freeq-fabro.service). Connects to freeq as its own did:key
// agent, owner-bound to FREEQ_OWNER_DID, joins FREEQ_CHANNEL, and listens on
// 127.0.0.1:FABRO_RELAY_PORT for Fabro's HTTP hooks (.fabro/project.toml).
//
// Configuration (environment):
//   FREEQ_OWNER_DID   required — the human who owns this bot
//   FREEQ_URL         default wss://irc.freeq.at/irc
//   FREEQ_CHANNEL     default #freeq-dev
//   FREEQ_NICK        default fabro
//   FABRO_RELAY_PORT  default 8091
//   FABRO_WEB_URL     optional — public Fabro web UI, for run links
//   FABRO_REPO        default freeq-irc/freeq — where run PRs are looked up
//   GITHUB_TOKEN      optional — only needed for a private repo / higher rate limit
//   FREEQ_ACCEPT_POLICY  "1" to accept the channel's join policy (POLICY <ch>
//                     ACCEPT) on the owner's behalf when a join returns 477
//   FABRO_URL         default http://127.0.0.1:32276 — the Fabro server
//   FABRO_TOKEN_FILE  default ~/.fabro/storage/server.dev-token
//   FABRO_BIN         default ~/.fabro/bin/fabro
//   FABRO_REPO_DIR    default ~/freeq — checkout used to launch goal runs
//
// It is also two-way: the owner can drive Fabro from freeq — in the channel
// by addressing the bot ("fabro status", "fabro approve x7k2qa") or by DM.
// Commands are accepted ONLY when the sender's DID (freeq's server-verified
// account tag, falling back to WHOIS) is FREEQ_OWNER_DID; anyone else is
// ignored in the channel and told so, at most hourly, in DMs.
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { FreeqBot } from "@freeq/bot-kit";
import { addressed, describeQuestion, execute, parseCommand } from "./commands.js";
import { FabroApi } from "./fabro-api.js";
import { launchWithGoal, listWorkflows } from "./launch.js";
import { findRunPr } from "./pr.js";
import { createRelay } from "./relay.js";

function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim() || fallback;
  if (!v) {
    console.error(`freeq-fabro: ${name} is required`);
    process.exit(2);
  }
  return v;
}

const ownerDid = env("FREEQ_OWNER_DID");
const url = env("FREEQ_URL", "wss://irc.freeq.at/irc");
const channel = env("FREEQ_CHANNEL", "#freeq-dev");
const nick = env("FREEQ_NICK", "fabro");
const port = Number(env("FABRO_RELAY_PORT", "8091"));
const repo = env("FABRO_REPO", "freeq-irc/freeq");
const webUrl = process.env.FABRO_WEB_URL?.trim() || undefined;
const acceptPolicy = process.env.FREEQ_ACCEPT_POLICY === "1";
const fabroUrl = env("FABRO_URL", "http://127.0.0.1:32276");
const tokenFile = env("FABRO_TOKEN_FILE", join(homedir(), ".fabro/storage/server.dev-token"));
const fabroBin = env("FABRO_BIN", join(homedir(), ".fabro/bin/fabro"));
const repoDir = env("FABRO_REPO_DIR", join(homedir(), "freeq"));

const log = (msg: string): void => console.log(`${new Date().toISOString()} ${msg}`);

const bot = await FreeqBot.create({
  name: "fabro",
  ownerDid,
  nick,
  url,
  channels: [channel],
  initialStatus: "relaying Fabro runs",
});
// Report the real join outcome. A +i channel can refuse the auto-join when it
// races the server's provenance check (see CLAUDE.md "JOIN races
// PROVENANCE"), so retry a refused join a few times, spaced out.
let joinRetries = 0;
bot.on("channelJoined", (ch) => {
  if (ch.toLowerCase() === channel.toLowerCase()) {
    joinRetries = 0;
    log(`joined ${ch}`);
  }
});
bot.on("joinRejected", (ch, numeric, reason) => {
  log(`join ${ch} refused (${numeric}): ${reason}`);
  if (ch.toLowerCase() !== channel.toLowerCase() || joinRetries >= 3) return;
  joinRetries++;
  // 477 = the channel has a join policy (rules) to accept first.
  if (numeric === "477" && acceptPolicy) {
    log(`accepting ${channel} join policy (FREEQ_ACCEPT_POLICY=1)`);
    bot.client.raw(`POLICY ${channel} ACCEPT`);
  }
  setTimeout(() => bot.client.join(channel), 5_000 * joinRetries);
});
bot.on("systemMessage", (_target, text) => {
  if (/polic/i.test(text)) log(`server: ${text}`);
});
bot.on("serverFail", (text) => log(`server FAIL: ${text}`));

await bot.start();
log(`connected as ${bot.client.nick} (${bot.identity.did})`);

// Read per call so a rotated token needs no restart.
const api = new FabroApi(fabroUrl, async () => (await readFile(tokenFile, "utf8")).trim());

// ── Owner commands ────────────────────────────────────────────────────────
const refusedAt = new Map<string, number>();
bot.on("message", (target, msg) => {
  if (msg.isSelf || msg.isSystem || msg.editOf) return;
  const isChannel = target.startsWith("#") || target.startsWith("&");
  if (isChannel && target.toLowerCase() !== channel.toLowerCase()) return;
  const body = isChannel ? addressed(msg.text, bot.client.nick || nick) : msg.text.trim();
  if (body === null) return;
  const replyTo = isChannel ? target : msg.from;
  const reply = (lines: string[]): void => {
    for (const line of lines) bot.client.sendMessage(replyTo, line);
  };

  void (async () => {
    const senderDid = await bot.resolveSenderDid({ from: msg.from, tags: msg.tags });
    if (senderDid !== ownerDid) {
      log(`ignored command from ${msg.from} (${senderDid ?? "unverified"})`);
      const last = refusedAt.get(msg.from) ?? 0;
      if (!isChannel && Date.now() - last > 3_600_000) {
        refusedAt.set(msg.from, Date.now());
        reply(["I only take commands from my owner."]);
      }
      return;
    }
    const cmd = parseCommand(body);
    log(`owner command: ${cmd.kind} ${JSON.stringify(cmd)}`);
    try {
      reply(
        await execute(cmd, {
          api,
          launchWithGoal: (wf, goal) => launchWithGoal(wf, goal, { repoDir, fabroBin }),
          workflows: () => listWorkflows(repoDir),
        }),
      );
    } catch (err) {
      log(`command failed: ${String(err)}`);
      reply([`that failed: ${String((err as Error).message ?? err).slice(0, 300)}`]);
    }
  })();
});

// The gate's question appears a moment after its stage starts; poll briefly.
async function describeGate(runId: string): Promise<string | undefined> {
  for (let i = 0; i < 10; i++) {
    const qs = await api.questions(runId).catch(() => []);
    if (qs[0]) return describeQuestion(qs[0]);
    await new Promise((r) => setTimeout(r, 3_000));
  }
  return undefined;
}

const relay = createRelay({
  post: (line) => {
    try {
      bot.client.sendMessage(channel, line);
      log(`posted: ${line}`);
    } catch (err) {
      log(`post failed (${String(err)}): ${line}`);
    }
  },
  findPr: (runId) => findRunPr(runId, { repo, token: process.env.GITHUB_TOKEN }),
  describeGate,
  webUrl,
  log,
});
relay.listen(port, "127.0.0.1", () => log(`listening on 127.0.0.1:${port}/hook`));

const shutdown = async (signal: string): Promise<void> => {
  log(`${signal} — shutting down`);
  relay.close();
  await bot.stop("freeq-fabro stopping");
  process.exit(0);
};
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
