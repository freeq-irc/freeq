#!/usr/bin/env node
/**
 * M4 acceptance harness — Demo 3: a handoff survives the recipient being offline.
 *
 * This is the capability that local (same-filesystem) multiplayer extensions
 * cannot provide, so it gets the strictest test:
 *
 *   1. Bob is NOT running.
 *   2. Alice offers Bob a handoff and then DISCONNECTS.
 *   3. Bob starts for the first time, and must learn about the offer from
 *      channel history replay alone — nobody is online to tell him.
 *   4. Bob accepts and completes.
 *   5. Alice reconnects and must see the finished lifecycle.
 *   6. Alice offers a second task, Bob takes it, and Alice RETRACTS it — the
 *      cancellation must reach Bob and close the task on his side, because a
 *      task withdrawn only in conversation stays assigned forever.
 *
 *   npx tsx spike/handoff-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ActEventPayload } from "@freeq/sdk";

import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { HandoffStore, hashBrief, describeHandoff } from "../src/handoff.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: `#pi-handoff-${Date.now().toString(36)}` },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-pi-m4-"));
let failed = false;
const fail = (m: string) => {
  console.error(`[m4] FAIL — ${m}`);
  failed = true;
};
const ok = (m: string) => console.error(`[m4] ✓ ${m}`);

const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });
const channel = values.channel!;

function mkConn(slug: string, nick: string, store: HandoffStore, label: string) {
  return new FreeqConnection({
    ownerDid: values.owner!,
    server: values.server!,
    slug,
    nick,
    channels: [channel],
    meta,
    root: join(root, slug),
    onNotice: (t, l) => console.error(`[${label}] ${l}: ${t}`),
    onActEvent: (ev: ActEventPayload) => {
      const r = store.apply(ev);
      console.error(
        `[${label}] act ${ev.verb} task=${ev.taskId.slice(0, 10)} replayed=${ev.replayed} → ` +
          (r.ok ? `state=${r.record.state}` : r.benign ? `(${r.reason}, ignored)` : `REJECTED (${r.reason})`),
      );
    },
  });
}

const aliceStore = new HandoffStore(join(root, "alice.json"));
const bobStore = new HandoffStore(join(root, "bob.json"));

// ── 1 & 2. Alice offers while Bob is not running at all ───────────────────
console.error(`[m4] channel ${channel}`);
console.error("[m4] STEP 1 — Bob is offline (never started)");

const alice = mkConn("m4alice1", "pi-alice", aliceStore, "alice");
await alice.start();
if (alice.state !== "online") fail("alice could not connect");
console.error(`[m4] alice online as ${alice.nick} (${alice.did})`);

// Bob's identity has to exist to be addressed; mint it without connecting.
// Must match exactly where bot-kit will look when Bob later connects:
// <root>/<slug>/<botName(slug)>/agent.key
const { loadOrCreateIdentity } = await import("@freeq/bot-kit");
const { botName } = await import("../src/identity.js");
const bobIdentity = await loadOrCreateIdentity({
  seedPath: join(root, "m4bob1", botName("m4bob1"), "agent.key"),
});
console.error(`[m4] bob's identity (not connected): ${bobIdentity.did}`);

const brief =
  "The auth refactor renamed AuthProvider.authenticate(token) to " +
  "authenticate(session). Update the callers in your service and run the suite.";
const taskId = await alice.sendAct(channel, "offer", undefined, {
  to: bobIdentity.did,
  title: "Update auth callers for the Session change",
  "ctx-h": hashBrief(brief),
});
if (!taskId) {
  fail("alice could not send the offer");
} else {
  ok(`alice offered task ${taskId.slice(0, 10)} to an OFFLINE recipient`);
  alice.send(channel, `[handoff ${taskId.slice(0, 10)} brief] ${brief}`);
}

await new Promise((r) => setTimeout(r, 3000));

// ── 2b. Alice goes away entirely ──────────────────────────────────────────
console.error("[m4] STEP 2 — alice disconnects; nobody is online to relay anything");
await alice.stop("offer sent");
await new Promise((r) => setTimeout(r, 2000));

// ── 3. Bob starts for the first time ──────────────────────────────────────
console.error("[m4] STEP 3 — bob starts for the first time");
const bob = mkConn("m4bob1", "pi-bob", bobStore, "bob");
await bob.start();
if (bob.state !== "online") fail("bob could not connect");
console.error(`[m4] bob online as ${bob.nick} (${bob.did})`);

// Wait for history replay to deliver the offer.
const deadline = Date.now() + 30_000;
while (Date.now() < deadline && !taskId) break;
while (Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 1500));
  if (taskId && bobStore.get(taskId)) break;
}

const received = taskId ? bobStore.get(taskId) : undefined;
if (!received) {
  fail("bob never received the offer made while he was offline — offline delivery is broken");
} else {
  ok(`bob learned about the offer from replay (state=${received.state}, fromReplay=${received.fromReplay})`);
  if (!received.fromReplay) {
    console.error("[m4] note: event was not flagged as replayed; delivery still worked");
  }
  const inbox = bobStore.inboxFor(bob.did ?? bobIdentity.did);
  if (!inbox.length) fail("offer did not appear in bob's inbox");
  else ok(`it shows in bob's inbox: ${describeHandoff(inbox[0], bob.did)}`);

  // ── 4. Bob accepts, then completes ──────────────────────────────────────
  console.error("[m4] STEP 4 — bob accepts and completes");
  await bob.sendAct(channel, "accept", received.id, {});
  await new Promise((r) => setTimeout(r, 2500));
  if (bobStore.get(received.id)!.state !== "assigned") {
    // Our own events echo back to us; if not, apply locally the way the
    // extension does after a successful send.
    console.error(`[m4] (bob's local state: ${bobStore.get(received.id)!.state})`);
  }

  await bob.sendAct(channel, "complete", received.id, { note: "callers updated; suite green" });
  await new Promise((r) => setTimeout(r, 2500));
}

// ── 5. Alice comes back and must see the outcome ──────────────────────────
console.error("[m4] STEP 5 — alice reconnects and reads the outcome from history");
const aliceStore2 = new HandoffStore(join(root, "alice2.json"));
const alice2 = mkConn("m4alice1", "pi-alice", aliceStore2, "alice2");
await alice2.start();

const deadline2 = Date.now() + 30_000;
while (Date.now() < deadline2) {
  await new Promise((r) => setTimeout(r, 1500));
  const r = taskId ? aliceStore2.get(taskId) : undefined;
  if (r && (r.state === "completed" || r.state === "assigned")) break;
}

const finalRec = taskId ? aliceStore2.get(taskId) : undefined;
if (!finalRec) {
  fail("alice could not reconstruct the task from history after reconnecting");
} else {
  console.error(`[m4] alice's view after reconnect: ${describeHandoff(finalRec, alice2.did)}`);
  if (finalRec.state === "completed") {
    ok("alice sees the task COMPLETED — full lifecycle survived both sides being offline");
  } else {
    fail(`alice sees state '${finalRec.state}', expected 'completed'`);
  }
  if (finalRec.log.length >= 3) {
    ok(`signed lifecycle replayed: ${finalRec.log.map((l) => l.verb).join(" → ")}`);
  } else {
    fail(`expected the full event chain, got: ${finalRec.log.map((l) => l.verb).join(" → ")}`);
  }
  if (!finalRec.signed) fail("some event in the chain was unsigned");
  else ok("every event in the chain carried a signature");
}

// ── 6. A retraction must actually close the task on the worker's side ─────
// Withdrawing work in prose leaves the ledger saying 'assigned', which is how
// a worker ends up picking a dead task back up. Only `cancel` closes it.
console.error("[m4] STEP 6 — alice retracts work bob already holds");
const cancelId = await alice2.sendAct(channel, "offer", undefined, {
  to: bobIdentity.did,
  title: "Draft the migration notes",
});
if (!cancelId) {
  fail("alice could not send the second offer");
} else {
  const seen = Date.now() + 20_000;
  while (Date.now() < seen && !bobStore.get(cancelId)) {
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!bobStore.get(cancelId)) fail("bob never saw the second offer");

  await bob.sendAct(channel, "accept", cancelId, {});
  await new Promise((r) => setTimeout(r, 2500));
  if (bobStore.get(cancelId)?.state !== "assigned") {
    fail(`bob should hold the second task; state=${bobStore.get(cancelId)?.state}`);
  }

  const sent = await alice2.sendAct(channel, "cancel", cancelId, {
    note: "superseded — the batch was reorganised",
  });
  if (!sent) fail("alice could not send the cancellation");

  const until = Date.now() + 20_000;
  while (Date.now() < until && bobStore.get(cancelId)?.state !== "cancelled") {
    await new Promise((r) => setTimeout(r, 1000));
  }

  const cancelled = bobStore.get(cancelId);
  if (cancelled?.state !== "cancelled") {
    fail(`bob still sees '${cancelled?.state}' after the retraction — he would resume dead work`);
  } else {
    ok("the retraction reached the worker and closed the task");
    if (bobStore.inboxFor(bob.did).some((r) => r.id === cancelId)) {
      fail("the cancelled task is still in bob's inbox");
    } else {
      ok("it is gone from bob's inbox — nothing left to wander back to");
    }
    if (cancelled.log.at(-1)?.note) ok("the reason for the retraction came through");
    else fail("the cancellation note did not survive the wire");
  }
}

console.error(failed ? "\n[m4] FAILURES ABOVE" : "\n[m4] ALL CHECKS PASSED — handoffs survive offline");

await bob.stop("done");
await alice2.stop("done");
await rm(root, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
