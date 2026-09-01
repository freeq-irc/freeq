#!/usr/bin/env node
/**
 * Helper: post a single open offer to a channel, then exit.
 *
 * Used to test url-fetch-worker. Run url-fetch-worker in one terminal,
 * then run this in another:
 *
 *   npm run example:fire-task -- --owner did:plc:<your-did> \
 *     --channel '#tasks' --url 'https://httpbin.org/delay/3'
 *
 * The offer names no recipient, so any worker in the room may claim it. The
 * worker should claim, transition to executing, fetch, then complete and
 * transition back to idle.
 */

import { FreeqBot } from "../src/index.js";
import { actTags } from "@freeq/sdk";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "wss://irc.freeq.at/irc" },
    channel: { type: "string", default: "#tasks" },
    nick: { type: "string", default: "tasker" },
    owner: { type: "string" },
    capability: { type: "string", default: "url_fetch" },
    url: { type: "string", default: "https://httpbin.org/delay/3" },
  },
  strict: true,
});

if (!values.owner) {
  console.error("Usage: fire-task --owner did:plc:<your-did> [--channel #tasks] [--url <url>]");
  process.exit(1);
}

const bot = await FreeqBot.create({
  name: "tasker",
  ownerDid: values.owner,
  nick: values.nick!,
  url: values.server!,
  channels: [values.channel!],
});

await bot.start();
console.error(`[tasker] up as ${bot.client.nick}`);

// An opener names no action — its own event id becomes the task's id.
const taskId = await bot.client.sendAct(
  values.channel!,
  actTags("handoff", "offer", undefined, bot.identity.did, {
    title: `fetch ${values.url!}`,
    // A hint so a worker can self-select. Stored and filterable, never a
    // gate: anyone in the room may claim an open offer.
    caps: values.capability!,
    ctx: values.url!,
  }),
);
console.error(`[tasker] posted offer id=${taskId} for ${values.url}`);

// Give the wire a moment so the offer and our QUIT don't collide.
await sleep(500);
await bot.stop("done");
process.exit(0);
