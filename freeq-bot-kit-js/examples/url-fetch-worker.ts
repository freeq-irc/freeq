#!/usr/bin/env node
/**
 * URL-fetch worker — the canonical agent pattern on freeq.
 *
 * Joins a channel, listens for open `handoff` offers declaring a `url_fetch`
 * capability, claims them, fetches the URL named in the offer's context, and
 * reports the result with `complete` or `fail`. State transitions between
 * `idle` and `executing` are visible to observers via PRESENCE broadcasts and
 * WHOIS.
 *
 * Fire a task with the companion example:
 *   npm run example:fire-task -- --owner did:plc:<your-did> \
 *     --channel '#tasks' --url 'https://httpbin.org/delay/3'
 *
 * Or in TypeScript — an open offer is one that names no recipient, so anyone
 * in the room may claim it:
 *   bot.client.sendAct('#tasks', actTags('handoff', 'offer', undefined, myDid, {
 *     title: 'fetch https://httpbin.org/delay/3',
 *     caps: 'url_fetch',
 *     ctx: 'https://httpbin.org/delay/3',
 *   }));
 *
 * Run:
 *   npx tsx freeq-bot-kit-js/examples/url-fetch-worker.ts \
 *     --owner did:plc:<your-did> --channel '#tasks'
 */

import { FreeqBot } from "../src/index.js";
import { actTags } from "@freeq/sdk";
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

const bot = await FreeqBot.create({
  name: "url-fetch-worker",
  ownerDid: values.owner,
  nick: values.nick!,
  url: values.server!,
  channels: [values.channel!],
  initialState: "idle",
});

bot.on("actEvent", async (event) => {
  // Only open offers: an offer naming a recipient is somebody else's, and
  // every other verb is a move on a task already under way.
  if (event.kind !== "handoff" || event.verb !== "offer") return;
  if (event.fields["act-to"]) return;
  if (event.did === bot.identity.did) return; // ignore our own offers
  if (event.fields["act-caps"] !== CAPABILITY) return;
  const url = event.fields["act-ctx"];
  if (!url) {
    console.error(`[worker] ignoring task ${event.eventId}: the offer names no context to fetch`);
    return;
  }
  const channel = event.channel;
  // An opener's own event id is the task's id for the rest of its life.
  const taskId = event.taskId;
  const did = bot.identity.did;
  const send = (verb: string, fields: Record<string, string>) =>
    bot.client.sendAct(channel, actTags("handoff", verb, taskId, did, fields), { taskId });

  // First valid claim wins; the task's home server orders competing claims.
  await send("claim", { note: `fetching ${url}` });

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

    await send("complete", { note: summary, ctx: url });
    console.error(`[worker] complete ${taskId}: ${summary}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await send("fail", { note: message });
    console.error(`[worker] failed ${taskId}: ${message}`);
  } finally {
    bot.setState("idle");
  }
});

await bot.start();
console.error(`[worker] up as ${bot.client.nick} — listening for open offers with caps=${CAPABILITY} on ${values.channel}`);

process.once("SIGINT",  () => bot.stop("SIGINT").then(()  => process.exit(0)));
process.once("SIGTERM", () => bot.stop("SIGTERM").then(() => process.exit(0)));
