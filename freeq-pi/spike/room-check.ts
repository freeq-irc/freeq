#!/usr/bin/env node
/**
 * M3 acceptance harness — humans in the room (Demo 2).
 *
 * A HUMAN (plain freeq client, no pi) sits in a channel with an agent and
 * @-mentions it. The agent must answer *in the room*, from its own
 * environment — and must NOT answer an untrusted human, nor anything it
 * wasn't addressed by.
 *
 *   npx tsx freeq-pi/spike/room-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAgentSession, SessionManager } from "@earendil-works/pi-coding-agent";
import { FreeqClient } from "@freeq/sdk";
import { loadOrCreateIdentity } from "@freeq/bot-kit";

import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { decideInbound, frameInbound, reachesModel } from "../src/inbound.js";
import { tierFor, modeFor, defaultConfig, type FreeqConfig } from "../src/config.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: "#pi-m3" },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-pi-m3-"));
let failed = false;
const fail = (m: string) => {
  console.error(`[m3] FAIL — ${m}`);
  failed = true;
};

// The agent's environment holds a fact the human cannot see.
const agentDir = join(root, "agent-project");
await mkdir(agentDir, { recursive: true });
const FACT = "PELICAN-4402";
await writeFile(join(agentDir, "STAGING.md"), `# Staging\n\nCurrent staging build tag: ${FACT}\n`);

const agentPi = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  cwd: agentDir,
});

let buf = "";
agentPi.session.subscribe((event) => {
  const e = event as { type?: string; assistantMessageEvent?: { type?: string; delta?: string } };
  if (e.type === "message_update" && e.assistantMessageEvent?.type === "text_delta") {
    buf += e.assistantMessageEvent.delta ?? "";
  }
});

const cfg: FreeqConfig = { ...defaultConfig(), ownerDid: values.owner };
const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });

const agent = new FreeqConnection({
  ownerDid: values.owner!,
  server: values.server!,
  slug: "m3agent1",
  nick: "pi-agent",
  channels: [values.channel!],
  meta,
  root: join(root, "agent"),
  onNotice: (t, l) => console.error(`[agent] ${l}: ${t}`),
  onScrub: (hits, target) => console.error(`[agent] REDACTED ${hits.join(",")} -> ${target}`),
  onMessage: (channel, msg) => {
    void (async () => {
      const did = await agent.resolveSenderDid(msg);
      const mention = agent.checkMention(channel, msg.text);
      const ev = {
        kind: "chat" as const,
        channel,
        from: msg.from,
        did,
        text: mention.addressed ? mention.stripped : msg.text,
        addressed: mention.addressed,
        mode: modeFor(cfg, channel),
        tier: tierFor(cfg, did),
      };
      const decision = decideInbound(ev);
      console.error(
        `[agent] <${msg.from}> addressed=${mention.addressed} tier=${ev.tier} → ${decision.action}`,
      );
      if (!reachesModel(decision.action) || !mention.addressed) return;

      buf = "";
      await agentPi.session.prompt(frameInbound(ev, { expectsReply: true }));
      const answer = buf.trim();
      if (answer) agent.send(channel, `${msg.from}: ${answer}`);
      console.error(`[agent] replied in ${channel} (${answer.length} chars)`);
    })();
  },
});

await agent.start();
console.error(`[m3] agent: ${agent.describe()}`);

// ── The human: a plain freeq client, no pi involved ───────────────────────
// DID-authenticated, because trust is DID-keyed — a guest has no durable
// identity to grant a tier to. This mirrors a real human signed in to the
// freeq web client: no pi session, no agent code, just a person in a channel.
const humanIdentity = await loadOrCreateIdentity({ seedPath: join(root, "human.key") });
const heard: string[] = [];
const human = new FreeqClient({
  url: values.server!,
  nick: "human-chad",
  channels: [values.channel!],
  sasl: {
    did: humanIdentity.did,
    method: "crypto",
    signer: humanIdentity.didKey.signer,
    token: "",
    pdsUrl: "",
  },
});
human.on("message", (_c, msg) => {
  if (!msg.isSelf) heard.push(`${msg.from}: ${msg.text}`);
});
await new Promise<void>((resolve) => {
  human.on("channelJoined", () => resolve());
  human.connect();
});
console.error(`[m3] human joined ${values.channel} as ${humanIdentity.did}`);
await new Promise((r) => setTimeout(r, 2000));

const waitForReply = async (secs: number): Promise<string | undefined> => {
  const deadline = Date.now() + secs * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    const nick = agent.nick ?? "pi-agent";
    const hit = heard.find((h) => h.toLowerCase().startsWith(`${nick.toLowerCase()}:`));
    if (hit) return hit;
  }
  return undefined;
};

// ── TEST 1: unaddressed room chatter must be ignored ──────────────────────
console.error("\n[m3] TEST 1 — unaddressed chatter (agent must stay quiet)");
heard.length = 0;
human.sendMessage(values.channel!, "morning all, deploy looks green");
if (await waitForReply(12)) fail("agent replied to a message that did not address it");
else console.error("[m3] ✓ stayed quiet");

// ── TEST 2: addressed by an UNTRUSTED human → no reply ────────────────────
console.error("\n[m3] TEST 2 — addressed by an untrusted human (must not answer)");
heard.length = 0;
human.sendMessage(values.channel!, `${agent.nick}: what is the staging build tag?`);
if (await waitForReply(15)) fail("agent answered an untrusted (observe-tier) human");
else console.error("[m3] ✓ declined to answer untrusted human");

// ── TEST 3: after trust, addressed → answers IN THE ROOM ──────────────────
console.error("\n[m3] TEST 3 — same question after granting 'message' tier");
// This is exactly what `/freeq trust <did> message` does in the product.
cfg.trust[humanIdentity.did] = "message";
console.error(`[m3] agent now trusts ${humanIdentity.did} at 'message'`);

heard.length = 0;
human.sendMessage(
  values.channel!,
  `${agent.nick}: read STAGING.md in your working directory and tell me the staging build tag`,
);
const reply = await waitForReply(120);
if (!reply) fail("agent did not answer a trusted human in the room");
else if (!reply.includes(FACT)) fail(`reply lacked the environment fact: ${reply}`);
else {
  console.error(`[m3] \u2713 answered in the room: ${reply.slice(0, 160)}`);
  console.error(`[m3] \u2713 contains ${FACT} — answered from its own environment`);
}

console.error(failed ? "\n[m3] FAILURES ABOVE" : "\n[m3] ALL CHECKS PASSED");

human.quit("m3 done");
agentPi.session.dispose();
await agent.stop("m3 done");
await rm(root, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
