#!/usr/bin/env node
/**
 * Tiny freeq sender — M0 test harness.
 *
 * Connects (guest or DID-authenticated), sends one message to a channel,
 * waits for replies, prints them, exits. Used to drive the spike bot and,
 * later, as the basis for the CI ask/reply round-trip harness
 * (docs/PI-FREEQ-BUILD-SPEC.md §5).
 *
 *   npx tsx freeq-pi/spike/send.ts --channel '#playground' \
 *     --text 'pi-spike: what repo are you in?' --wait 60
 */

import { parseArgs } from "node:util";
import { FreeqClient } from "@freeq/sdk";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "wss://irc.freeq.at/irc" },
    channel: { type: "string", default: "#playground" },
    nick: { type: "string", default: "spike-driver" },
    text: { type: "string" },
    wait: { type: "string", default: "60" },
  },
  strict: true,
});

if (!values.text) {
  console.error("Usage: send.ts --text '<message>' [--channel '#playground'] [--wait 60]");
  process.exit(1);
}

const waitMs = Number(values.wait) * 1000;
const client = new FreeqClient({
  url: values.server!,
  nick: values.nick!,
  channels: [values.channel!],
});

let sent = false;

client.on("registered", (nick) => console.error(`[send] registered as ${nick}`));

client.on("channelJoined", (channel) => {
  if (sent || channel.toLowerCase() !== values.channel!.toLowerCase()) return;
  sent = true;
  console.error(`[send] joined ${channel}; sending`);
  client.sendMessage(channel, values.text!);
});

client.on("message", (channel, msg) => {
  if (msg.isSelf) return;
  console.error(`[recv] [${channel}] <${msg.from}> ${msg.text}`);
});

client.on("serverFail", (text) => console.error(`[send] server FAIL: ${text}`));
client.on("authError", (e) => console.error(`[send] auth error: ${e}`));

client.connect();

setTimeout(() => {
  console.error("[send] done waiting; quitting");
  client.quit("spike driver done");
  process.exit(0);
}, waitMs);
