#!/usr/bin/env node
/**
 * URL-fetch worker — the canonical agent pattern on freeq.
 *
 * Joins a channel, listens for `task_request` coordination events
 * declaring a `url_fetch` capability, claims them, fetches the URL,
 * reports the result via `task_complete` or `task_failed`. State
 * transitions between `idle` and `executing` are visible to observers
 * via PRESENCE broadcasts and WHOIS.
 *
 * Fire a task from a raw IRC connection (or another bot). The event is a
 * TAGMSG — the server stores the event from that line, and workers listen
 * for it; a PRIVMSG carrying event tags is only a human-readable rendering:
 *   @+freeq.at/event=task_request;\
 *    +freeq.at/payload={"capability":"url_fetch","url":"https://httpbin.org/delay/3"} \
 *    TAGMSG #tasks
 *
 * Or in TypeScript:
 *   bot.client.emitEvent('#tasks', 'task_request', {
 *     capability: 'url_fetch',
 *     url: 'https://httpbin.org/delay/3',
 *   });
 *
 * Run:
 *   npx tsx freeq-bot-kit-js/examples/url-fetch-worker.ts \
 *     --owner did:plc:<your-did> --channel '#tasks'
 */

import { FreeqBot } from "../src/index.js";
import { parseArgs } from "node:util";

const CAPABILITY = "url_fetch";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "wss://irc.freeq.at/irc" },
    channel: { type: "string", default: "#tasks" },
    nick: { type: "string", default: "url-fetch-worker" },
    owner: { type: "string" },
    "timeout-ms": { type: "string", default: "10000" },
  },
  strict: true,
});

if (!values.owner) {
  console.error("Usage: url-fetch-worker --owner did:plc:<your-did> [--channel #tasks]");
  process.exit(1);
}

const timeoutMs = Number(values["timeout-ms"]);

interface TaskRequestPayload {
  capability?: string;
  url?: string;
  description?: string;
}

const bot = await FreeqBot.create({
  name: "url-fetch-worker",
  ownerDid: values.owner,
  nick: values.nick!,
  url: values.server!,
  channels: [values.channel!],
  initialState: "idle",
});

bot.on("coordinationEvent", async (event) => {
  if (event.eventType !== "task_request") return;
  if (event.from === bot.client.nick) return; // ignore our own emits
  const payload = event.payload as TaskRequestPayload | null;
  if (!payload || payload.capability !== CAPABILITY) return;
  if (typeof payload.url !== "string") {
    console.error(`[worker] ignoring task ${event.eventId}: payload.url is not a string`);
    return;
  }
  const url = payload.url;
  const channel = event.channel;
  const taskId = event.eventId;

  // Claim by emitting a task_claim event referencing this taskId.
  bot.client.emitEvent(channel, "task_claim", { worker: bot.identity.did }, {
    refId: taskId,
    humanText: `🙋 Claiming task: fetch ${url}`,
  });

  bot.setState("executing", `fetching ${url}`);
  console.error(`[worker] executing ${taskId}: ${url}`);

  const startedAt = Date.now();
  try {
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(abortTimer);

    const body = await response.text(); // drain so contentLength is reliable
    const elapsedMs = Date.now() - startedAt;
    const summary = `${response.status} ${response.statusText} — ${body.length}B in ${elapsedMs}ms`;

    bot.client.completeTask(channel, taskId, summary);
    console.error(`[worker] complete ${taskId}: ${summary}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    bot.client.failTask(channel, taskId, message);
    console.error(`[worker] failed ${taskId}: ${message}`);
  } finally {
    bot.setState("idle");
  }
});

await bot.start();
console.error(`[worker] up as ${bot.client.nick} — listening for task_request with capability=${CAPABILITY} on ${values.channel}`);

process.once("SIGINT",  () => bot.stop("SIGINT").then(()  => process.exit(0)));
process.once("SIGTERM", () => bot.stop("SIGTERM").then(() => process.exit(0)));
