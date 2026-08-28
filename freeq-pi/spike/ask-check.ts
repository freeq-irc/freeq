#!/usr/bin/env node
/**
 * M2 acceptance harness — cross-agent ask, end to end.
 *
 * Stands up TWO independent pi sessions, each with its own installation
 * identity and its own freeq connection, and has one ask the other a question
 * that can only be answered by inspecting the *responder's* environment.
 *
 * This is the automatable core of the v0.1 success criterion. The full
 * criterion additionally requires two people on two laptops across the
 * internet — that's the recorded demo, not something CI can assert.
 *
 *   npx tsx freeq-pi/spike/ask-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAgentSession, SessionManager } from "@earendil-works/pi-coding-agent";

import { FreeqConnection, type InboundAsk } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { decideInbound, frameInbound, reachesModel } from "../src/inbound.js";
import { tierFor, defaultConfig, type FreeqConfig } from "../src/config.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: "#pi-m2" },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
    timeout: { type: "string", default: "180" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-pi-m2-"));
const fail = (m: string) => {
  console.error(`\n[m2] FAIL — ${m}`);
  process.exitCode = 1;
};

// ── Responder's environment: a fact only IT can see ────────────────────────
// A file in the responder's cwd that the asker has no access to. This is the
// "knowledge available only to the other agent" part of the criterion.
const responderDir = join(root, "responder-project");
await mkdir(responderDir, { recursive: true });
const SECRET_FACT = "SHIPPING-VALVE-7731";
await writeFile(
  join(responderDir, "DEPLOY_NOTES.md"),
  `# Deploy notes\n\nThe staging release codename is ${SECRET_FACT}.\n`,
);

const askerDir = join(root, "asker-project");
await mkdir(askerDir, { recursive: true });

// ── Two pi sessions ────────────────────────────────────────────────────────
const responderPi = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  cwd: responderDir,
});
const askerPi = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  cwd: askerDir,
});

function captureText(session: { subscribe: (l: (e: unknown) => void) => () => void }) {
  let buf = "";
  const unsub = session.subscribe((event) => {
    const e = event as { type?: string; assistantMessageEvent?: { type?: string; delta?: string } };
    if (e.type === "message_update" && e.assistantMessageEvent?.type === "text_delta") {
      buf += e.assistantMessageEvent.delta ?? "";
    }
  });
  return { get: () => buf.trim(), reset: () => (buf = ""), unsub };
}

// ── Two freeq connections ──────────────────────────────────────────────────
const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });

// The responder trusts the asker at 'request' so it will answer.
// (In the product this is `/freeq trust <did> request`, human-confirmed.)
const responderCfg: FreeqConfig = { ...defaultConfig(), ownerDid: values.owner };
const askerCfg: FreeqConfig = { ...defaultConfig(), ownerDid: values.owner };

const responderCapture = captureText(responderPi.session);
let responderConn: FreeqConnection;
let askerConn: FreeqConnection;

async function handleAsk(ask: InboundAsk): Promise<void> {
  const tier = tierFor(responderCfg, ask.did);
  const ev = {
    kind: "ask" as const,
    channel: ask.channel,
    from: ask.from,
    did: ask.did,
    text: ask.question,
    addressed: true,
    mode: "addressed" as const,
    tier,
  };
  const decision = decideInbound(ev);
  console.error(`[responder] ask from ${ask.from} tier=${tier} → ${decision.action} (${decision.reason})`);

  if (!reachesModel(decision.action)) {
    responderConn.replyToAsk(ask, undefined, `declined: ${decision.reason}`);
    return;
  }

  responderCapture.reset();
  await responderPi.session.prompt(frameInbound(ev, { expectsReply: true }));
  const answer = responderCapture.get();
  responderConn.replyToAsk(ask, answer || undefined, answer ? undefined : "no answer produced");
  console.error(`[responder] replied (${answer.length} chars)`);
}

responderConn = new FreeqConnection({
  ownerDid: values.owner!,
  server: values.server!,
  slug: "resp0001",
  nick: "pi-responder",
  channels: [values.channel!],
  meta,
  root: join(root, "resp"),
  onNotice: (t, l) => console.error(`[responder] ${l}: ${t}`),
  onAsk: (ask) => void handleAsk(ask),
});

askerConn = new FreeqConnection({
  ownerDid: values.owner!,
  server: values.server!,
  slug: "askr0001",
  nick: "pi-asker",
  channels: [values.channel!],
  meta,
  root: join(root, "askr"),
  onNotice: (t, l) => console.error(`[asker] ${l}: ${t}`),
});

console.error(`[m2] server=${values.server} channel=${values.channel}`);
await responderConn.start();
await askerConn.start();
console.error(`[m2] responder: ${responderConn.describe()}`);
console.error(`[m2] asker:     ${askerConn.describe()}`);

// Wait for mutual discovery.
const discoveryDeadline = Date.now() + 30_000;
let responderNick: string | undefined;
while (Date.now() < discoveryDeadline) {
  await new Promise((r) => setTimeout(r, 1500));
  const peer = askerConn.peers().find((p) => p.isPi && p.nick.toLowerCase().includes("responder"));
  if (peer) {
    responderNick = peer.nick;
    break;
  }
}
if (!responderNick) {
  fail("asker never discovered the responder");
} else {
  console.error(`[m2] asker discovered ${responderNick}`);

  // ── TEST 1: untrusted ask must be declined ──────────────────────────────
  console.error("\n[m2] TEST 1 — ask from an UNTRUSTED peer (must be declined)");
  const declined = await askerConn.ask(
    responderNick,
    "What is the staging release codename in your DEPLOY_NOTES.md?",
    60_000,
  );
  if (declined.ok) {
    fail(`untrusted ask was ANSWERED — tier gate failed: ${declined.answer?.slice(0, 200)}`);
  } else if (!/declined/i.test(declined.error ?? "")) {
    fail(`untrusted ask failed for the wrong reason: ${declined.error}`);
  } else {
    console.error(`[m2] ✓ declined as expected: ${declined.error}`);
  }

  // ── TEST 2: trusted ask must be answered from the responder's env ───────
  console.error("\n[m2] TEST 2 — same ask after granting 'request' tier");
  const askerDid = askerConn.did;
  if (!askerDid) {
    fail("asker has no DID");
  } else {
    responderCfg.trust[askerDid] = "request"; // == `/freeq trust <did> request`
    console.error(`[m2] responder now trusts ${askerDid} at 'request'`);

    const answered = await askerConn.ask(
      responderNick,
      "Read DEPLOY_NOTES.md in your working directory and tell me the staging release codename. Reply with just the codename.",
      120_000,
    );

    if (!answered.ok) {
      fail(`trusted ask got no answer: ${answered.error}`);
    } else if (!answered.answer?.includes(SECRET_FACT)) {
      fail(`answer did not contain the fact only the responder could know.\nGot: ${answered.answer}`);
    } else {
      console.error(`[m2] ✓ answer: ${answered.answer.replace(/\n/g, " ").slice(0, 200)}`);
      console.error(`[m2] ✓ contains ${SECRET_FACT} — knowledge crossed the network`);
    }
  }
}

if (process.exitCode !== 1) {
  console.error("\n[m2] ALL CHECKS PASSED — cross-agent ask works, tier gate holds");
}

responderCapture.unsub();
responderPi.session.dispose();
askerPi.session.dispose();
await responderConn.stop("m2 done");
await askerConn.stop("m2 done");
await rm(root, { recursive: true, force: true });
process.exit(process.exitCode ?? 0);
