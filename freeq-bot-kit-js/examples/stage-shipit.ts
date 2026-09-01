#!/usr/bin/env npx tsx
/**
 * Stage the #ship-it demo conversation on irc.freeq.at for client screenshots.
 *
 * Scripted participants (this process, connections held open for captures):
 *   - relay-agent : did:key bot (authenticated agent) — sets the topic, acks
 *                   the opener, opens a handoff and drives it through
 *                   progress and complete (rendered as cards in the web
 *                   client).
 *   - maya        : guest human — confirms manually, reacts 🎉 to completion.
 *
 * External participants (driven by the operator around this script):
 *   - ana  : TUI guest — speaks the opener line (via tmux send-keys).
 *   - chad : the signed-in macOS app — closes the thread.
 *
 * Flow: connect + join + topic, then WAIT for ana's opener (any message
 * containing "deploy preview", up to 120s), then play the scripted beats.
 * Holds all connections afterwards so member lists stay populated during
 * captures. SIGTERM to release.
 */
import { FreeqBot, FreeqClient } from "../src/index.js";
import { actTags } from "@freeq/sdk";

const CHANNEL = process.env.STAGE_CHANNEL || "#ship-it";
const URL = process.env.STAGE_URL || "wss://irc.freeq.at/irc";
const OWNER = process.env.STAGE_OWNER || "did:plc:4qsyxmnsblo4luuycm3572bq";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // ── relay-agent (did:key) ──
  const bot = await FreeqBot.create({
    name: "relay-agent",
    ownerDid: OWNER,
    nick: "relay-agent",
    url: URL,
    channels: [CHANNEL],
  });

  // Opener trigger: ana's line from the TUI.
  let openerSeen: () => void;
  const opener = new Promise<void>((r) => (openerSeen = r));
  bot.on("message", (_ch: string, msg: any) => {
    if (msg?.isSelf) return;
    if (/deploy preview/i.test(msg?.text || "")) openerSeen();
  });

  await bot.start();
  console.log(`[stage] relay-agent up as ${bot.client.nick} (${bot.identity.did})`);
  await sleep(1000);
  bot.client.setTopic(CHANNEL, "release train — humans + agents");

  // ── maya (guest) ──
  const maya = new FreeqClient({ url: URL, nick: "maya" });
  const mayaReady = new Promise<void>((resolve) => {
    maya.on("registered", () => {
      maya.join(CHANNEL);
      setTimeout(resolve, 800);
    });
  });
  // The card maya reacts to is the completion's companion line — an ordinary
  // message carrying the task's ref, which is what the reaction attaches to.
  let completedTask: string | null = null;
  let completionMsgId: string | null = null;
  maya.on("actEvent", (ev: any) => {
    if (ev?.verb === "complete") completedTask = ev.taskId;
  });
  maya.on("message", (_buf: string, msg: any) => {
    if (completedTask && msg?.tags?.["+freeq.at/ref"] === completedTask) {
      completionMsgId = msg.id || null;
    }
  });
  maya.connect();
  await mayaReady;
  console.log("[stage] maya joined — waiting for ana's opener (\"deploy preview…\")");

  await Promise.race([opener, sleep(120_000)]);
  console.log("[stage] opener seen (or timeout) — performing");

  await sleep(1800);
  bot.client.sendMessage(CHANNEL, "on it — running the checkout smoke suite.");
  await sleep(2600);

  const did = bot.identity.did;
  const act = (verb: string, task: string | undefined, fields: Record<string, string>, line: string) =>
    bot.client.sendAct(CHANNEL, actTags("handoff", verb, task, did, fields), {
      humanText: line,
      taskId: task,
    });

  // Opened directed at ourselves and taken, so the later steps come from the
  // assignee the rules require.
  const task = await act(
    "offer",
    undefined,
    { title: "checkout smoke suite", to: did },
    "taking the checkout smoke suite",
  );
  await act("accept", task, {}, "on it");
  await sleep(2600);

  await act("progress", task, { note: "cart → payment ok (3/5)" }, "cart → payment ok (3/5)");
  await sleep(3200);

  await act(
    "complete",
    task,
    { note: "checkout smoke suite — 5/5 green" },
    "checkout smoke suite — 5/5 green",
  );
  await sleep(2400);

  maya.sendMessage(CHANNEL, "payment flow looks good manually too 👍");
  await sleep(1600);

  if (completionMsgId) {
    maya.sendReaction(CHANNEL, "🎉", completionMsgId);
    console.log(`[stage] maya reacted to ${completionMsgId}`);
  } else {
    console.log("[stage] no completion msgid seen — skipping reaction");
  }

  console.log("[stage] STAGED — holding connections for captures (SIGTERM to release)");
  await new Promise(() => {});
}

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));
main().catch((e) => {
  console.error("[stage] FAILED:", e);
  process.exit(1);
});
