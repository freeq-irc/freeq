#!/usr/bin/env node
/**
 * Watch what a channel actually learns about an agent.
 *
 * Prints every presence transition and every JOIN actor-class tag, so you can
 * confirm from the outside that a working agent reports `executing` with a
 * label rather than sitting there looking "available".
 *
 *   npx tsx spike/watch-presence.ts --channel '#pi-demo' --wait 180
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
    nick: { type: "string", default: "presence-watch" },
    wait: { type: "string", default: "180" },
    /** WHOIS each member on join to learn actor class (numeric 673). */
    whois: { type: "boolean", default: true },
    // Its OWN identity: freeq binds nicks to DIDs, so two processes sharing a
    // key file are one identity and the server renames the second one.
    keydir: { type: "string", default: join(homedir(), ".freeq", "demo-watcher") },
  },
  strict: true,
});

await mkdir(values.keydir!, { recursive: true });
const identity = await loadOrCreateIdentity({ seedPath: join(values.keydir!, "human.key") });

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

const ts = () => new Date().toISOString().slice(11, 19);

client.on("channelJoined", (channel) => {
  console.log(`${ts()} joined ${channel} as ${client.nick}`);
});

client.on("membersSync", (channel, members) => {
  console.log(
    `${ts()} members of ${channel}: ` +
      members
        .map((m) => `${m.nick}${m.actorClass ? `[${m.actorClass}]` : "[class unknown]"}`)
        .join(", "),
  );
  // NAMES (353) carries only nick + prefixes, so actor class is unknown for
  // anyone who joined before us. WHOIS fills it in via numeric 673.
  if (values.whois) {
    for (const m of members) {
      if (!m.actorClass && m.nick !== client.nick) client.raw(`WHOIS ${m.nick}`);
    }
  }
});

client.on("memberJoined", (channel, member) => {
  console.log(
    `${ts()} +join ${member.nick}` +
      (member.actorClass ? ` actor-class=${member.actorClass}` : " (no actor-class tag)") +
      (channel ? ` in ${channel}` : " (via WHOIS)"),
  );
});

client.on("presence", (p) => {
  console.log(
    `${ts()} PRESENCE ${p.nick}: state=${p.state}` +
      (p.status ? ` status="${p.status}"` : " (no status relayed)") +
      (p.task ? ` task=${p.task}` : ""),
  );
});

client.on("userAway", (nick, text) => {
  console.log(`${ts()} AWAY ${nick}: ${text === null ? "(cleared)" : text}`);
});

// Coordination events (discovery hellos, provenance, decisions) so a run can
// be inspected from outside the agent that produced it.
client.on("coordinationEvent", (e) => {
  const payload = typeof e.payload === "object" ? JSON.stringify(e.payload) : String(e.payload);
  console.log(`${ts()} EVENT ${e.eventType} from ${e.from} in ${e.channel}: ${payload.slice(0, 220)}`);
});

client.on("message", (channel, msg) => {
  if (msg.isSelf) return;
  console.log(`${ts()} [${channel}] <${msg.from}> ${msg.text.slice(0, 100)}`);
});

client.connect();
setTimeout(() => {
  client.quit("done");
  process.exit(0);
}, Number(values.wait) * 1000);
