#!/usr/bin/env node
/**
 * A human in the room — DID-authenticated freeq client, no pi involved.
 *
 * Used for the "humans and agents in one channel" demo. Trust is DID-keyed,
 * so a demo human must be authenticated: guests deliberately cannot be
 * granted a tier.
 *
 *   npx tsx spike/human.ts --nick chad --channel '#pi-demo' \
 *     --say 'pi-reth: what is failing in staging?' --wait 120
 *
 * With no --say it just listens, which is handy for watching a room.
 */

import { parseArgs } from "node:util";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { FreeqClient } from "@freeq/sdk";
import { loadOrCreateIdentity } from "@freeq/bot-kit";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "wss://irc.freeq.at/irc" },
    channel: { type: "string", default: "#pi-demo" },
    nick: { type: "string", default: "demo-human" },
    say: { type: "string" },
    wait: { type: "string", default: "120" },
    /** Where to persist this human's key, so the DID is stable across runs. */
    keydir: { type: "string", default: join(homedir(), ".freeq", "demo-human") },
    /** Print the DID and exit — for granting trust before the demo. */
    whoami: { type: "boolean", default: false },
  },
  strict: true,
});

await mkdir(values.keydir!, { recursive: true });
const identity = await loadOrCreateIdentity({ seedPath: join(values.keydir!, "human.key") });

if (values.whoami) {
  console.log(identity.did);
  process.exit(0);
}

const client = new FreeqClient({
  url: values.server!,
  nick: values.nick!,
  channels: [values.channel!],
  sasl: {
    did: identity.did,
    method: "crypto",
    signer: identity.didKey.signer,
    token: "",
    pdsUrl: "",
  },
});

client.on("authenticated", (did) => console.error(`[human] authenticated as ${did}`));
client.on("authError", (e) => console.error(`[human] AUTH FAILED: ${e}`));
client.on("serverFail", (t) => console.error(`[human] server: ${t}`));

let said = false;
client.on("channelJoined", (channel) => {
  console.error(`[human] joined ${channel} as ${client.nick}`);
  if (said || !values.say) return;
  said = true;
  setTimeout(() => {
    console.error(`[human] > ${values.say}`);
    client.sendMessage(channel, values.say!);
  }, 1500);
});

client.on("message", (channel, msg) => {
  if (msg.isSelf) return;
  console.error(`[${channel}] <${msg.from}> ${msg.text}`);
});

client.connect();

setTimeout(() => {
  client.quit("done");
  process.exit(0);
}, Number(values.wait) * 1000);
