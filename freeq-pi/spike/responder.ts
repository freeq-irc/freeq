#!/usr/bin/env node
/**
 * Demo responder — stands in for "the other developer's pi".
 *
 * Runs a real pi AgentSession behind a freeq identity, answers `ask` requests
 * from trusted peers using its OWN environment, and joins a channel so humans
 * can see it. This is what the far side of the two-laptop demo looks like
 * when the far side is a machine rather than a person.
 *
 * It uses the same product modules as the extension — identity, tier gate,
 * framing, redaction — so it is a faithful stand-in, not a mock.
 *
 *   npx tsx spike/responder.ts \
 *     --owner  did:plc:<owner> \
 *     --trust  did:key:<asker-agent-did> \
 *     --nick   pi-remote \
 *     --channel '#pi-demo' \
 *     --server wss://irc.freeq.at/irc
 */

import { parseArgs } from "node:util";
import { createAgentSession, SessionManager } from "@earendil-works/pi-coding-agent";

import { FreeqConnection, type InboundAsk } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { decideInbound, frameInbound, reachesModel } from "../src/inbound.js";
import { defaultConfig, modeFor, tierFor, type FreeqConfig, type Tier } from "../src/config.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "wss://irc.freeq.at/irc" },
    channel: { type: "string", default: "#pi-demo" },
    nick: { type: "string", default: "pi-remote" },
    owner: { type: "string" },
    /** DIDs to trust at `request` (repeatable). */
    trust: { type: "string", multiple: true, default: [] },
    /** Tier granted to --trust DIDs. */
    tier: { type: "string", default: "request" },
    cwd: { type: "string", default: process.cwd() },
    slug: { type: "string", default: "demoresp" },
  },
  strict: true,
});

if (!values.owner) {
  console.error("Usage: responder.ts --owner did:plc:… [--trust did:key:…] [--channel '#pi-demo']");
  process.exit(1);
}

const cfg: FreeqConfig = { ...defaultConfig(), ownerDid: values.owner };
for (const did of values.trust ?? []) cfg.trust[did] = values.tier as Tier;

const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  cwd: values.cwd,
});

let buf = "";
session.subscribe((event) => {
  const e = event as { type?: string; assistantMessageEvent?: { type?: string; delta?: string } };
  if (e.type === "message_update" && e.assistantMessageEvent?.type === "text_delta") {
    buf += e.assistantMessageEvent.delta ?? "";
  }
});

const meta = await collectSessionMeta({ cwd: values.cwd, model: "remote" });
let busy = false;

const conn: FreeqConnection = new FreeqConnection({
  ownerDid: values.owner,
  server: values.server!,
  slug: values.slug!,
  nick: values.nick!,
  channels: [values.channel!],
  meta,
  onNotice: (t, l) => console.error(`[responder] ${l}: ${t}`),
  onScrub: (hits, target) => console.error(`[responder] REDACTED ${hits.join(",")} → ${target}`),

  onAsk: (ask: InboundAsk) => void handleAsk(ask),

  onMessage: (channel, msg) => {
    void (async () => {
      const did = await conn.resolveSenderDid(msg);
      const mention = conn.checkMention(channel, msg.text);
      if (!mention.addressed || mention.cooling) return;
      const ev = {
        kind: "chat" as const,
        channel,
        from: msg.from,
        did,
        text: mention.stripped,
        addressed: true,
        mode: modeFor(cfg, channel),
        tier: tierFor(cfg, did),
      };
      const decision = decideInbound(ev);
      console.error(`[responder] <${msg.from}> tier=${ev.tier} → ${decision.action}`);
      if (!reachesModel(decision.action) || busy) return;
      busy = true;
      conn.setWorkState("executing", `answering ${msg.from}`);
      try {
        buf = "";
        await session.prompt(frameInbound(ev, { expectsReply: true }));
        const answer = buf.trim();
        if (answer) conn.send(channel, `${msg.from}: ${answer.slice(0, 1200)}`);
      } finally {
        busy = false;
        conn.setWorkState("active");
      }
    })();
  },
});

async function handleAsk(ask: InboundAsk): Promise<void> {
  const ev = {
    kind: "ask" as const,
    channel: ask.channel,
    from: ask.from,
    did: ask.did,
    text: ask.question,
    addressed: true,
    mode: "addressed" as const,
    tier: tierFor(cfg, ask.did),
  };
  const decision = decideInbound(ev);
  console.error(
    `[responder] ASK from ${ask.from} (${ask.did ?? "no did"}) tier=${ev.tier} → ${decision.action}`,
  );
  console.error(`[responder]   q: ${ask.question.slice(0, 120)}`);

  if (!reachesModel(decision.action)) {
    conn.replyToAsk(ask, undefined, `declined: ${decision.reason}`);
    return;
  }
  if (busy) {
    conn.replyToAsk(ask, undefined, "busy with another request");
    return;
  }
  busy = true;
  // Tell the room what we're doing — an agent that looks "available" while
  // grinding is worse than no presence at all.
  conn.setWorkState("executing", `answering ${ask.from}`);
  try {
    buf = "";
    await session.prompt(frameInbound(ev, { expectsReply: true }));
    const answer = buf.trim();
    conn.replyToAsk(ask, answer || undefined, answer ? undefined : "no answer produced");
    console.error(`[responder]   → replied (${answer.length} chars): ${answer.slice(0, 160)}`);
  } finally {
    busy = false;
    conn.setWorkState("active");
  }
}

await conn.start();
console.error(`[responder] ${conn.describe()}`);
console.error(`[responder] nick=${conn.nick} did=${conn.did}`);
console.error(`[responder] trusting: ${Object.entries(cfg.trust).map(([d, t]) => `${d}=${t}`).join(", ") || "(nobody)"}`);
console.error(`[responder] cwd=${values.cwd} channel=${values.channel}`);
console.error("[responder] ready — waiting for asks");

const shutdown = async (sig: string) => {
  console.error(`[responder] ${sig}`);
  session.dispose();
  await conn.stop(sig);
  process.exit(0);
};
process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
