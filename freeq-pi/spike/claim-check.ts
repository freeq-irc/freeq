#!/usr/bin/env node
/**
 * Acceptance harness — open (claimable) tasks and the claim race.
 *
 * A task posted to a channel with no assignee is a work queue: whoever is
 * capable takes it. The interesting property is that TWO agents claiming at
 * once must not both end up working it, and every party's view must agree on
 * who won.
 *
 *   1. Alice posts an open task with caps.
 *   2. Bob and Carol both claim it, as close to simultaneously as possible.
 *   3. Exactly one wins, and all three views agree on which.
 *
 *   npx tsx spike/claim-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ActEventPayload } from "@freeq/sdk";

import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { HandoffStore, describeHandoff } from "../src/handoff.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: `#pi-queue-${Date.now().toString(36)}` },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-claim-"));
let failed = false;
const fail = (m: string) => {
  console.error(`[claim] FAIL — ${m}`);
  failed = true;
};
const ok = (m: string) => console.error(`[claim] ✓ ${m}`);

const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });
const channel = values.channel!;

function mk(slug: string, nick: string, store: HandoffStore, label: string) {
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
      if (!r.ok && !r.benign) {
        console.error(`[${label}] rejected ${ev.verb} — ${r.reason}`);
      }
    },
  });
}

const aliceStore = new HandoffStore(join(root, "a.json"));
const bobStore = new HandoffStore(join(root, "b.json"));
const carolStore = new HandoffStore(join(root, "c.json"));

const alice = mk("clalice1", "pi-alice", aliceStore, "alice");
const bob = mk("clbob001", "pi-bob", bobStore, "bob");
const carol = mk("clcarol1", "pi-carol", carolStore, "carol");

console.error(`[claim] channel ${channel}`);
await alice.start();
await bob.start();
await carol.start();
for (const [n, c] of [["alice", alice], ["bob", bob], ["carol", carol]] as const) {
  if (c.state !== "online") fail(`${n} did not connect`);
}
console.error(`[claim] alice=${alice.did?.slice(0, 24)}… bob=${bob.did?.slice(0, 24)}… carol=${carol.did?.slice(0, 24)}…`);
await new Promise((r) => setTimeout(r, 3000));

// ── 1. Alice posts an OPEN task (no act-to) ───────────────────────────────
const taskId = await alice.sendAct(channel, "offer", undefined, {
  title: "Summarize today's S2S logs",
  caps: "pi/log-analysis",
});
if (!taskId) {
  fail("alice could not post the open task");
} else {
  ok(`alice posted open task ${taskId.slice(0, 10)} (no assignee)`);
  await new Promise((r) => setTimeout(r, 3000));

  for (const [name, store] of [["bob", bobStore], ["carol", carolStore]] as const) {
    const rec = store.get(taskId);
    if (!rec) fail(`${name} never saw the open task`);
    else if (rec.state !== "open") fail(`${name} sees state '${rec.state}', expected 'open'`);
    else if (rec.offeree) fail(`${name} sees an assignee on an open task`);
  }
  if (!failed) ok("both workers see it as open and unassigned");

  // ── 2. Bob and Carol race ───────────────────────────────────────────────
  console.error("[claim] bob and carol claim simultaneously…");
  await Promise.all([
    bob.sendAct(channel, "claim", taskId, {}),
    carol.sendAct(channel, "claim", taskId, {}),
  ]);
  await new Promise((r) => setTimeout(r, 5000));

  // ── 3. Exactly one winner, and everyone agrees ──────────────────────────
  const views = [
    ["alice", aliceStore.get(taskId)],
    ["bob", bobStore.get(taskId)],
    ["carol", carolStore.get(taskId)],
  ] as const;

  for (const [name, rec] of views) {
    console.error(`[claim] ${name}: ${rec ? describeHandoff(rec, undefined) : "(no record)"}`);
  }

  const assignees = new Set(
    views.map(([, rec]) => rec?.assignee).filter((a): a is string => !!a),
  );
  if (assignees.size === 0) fail("nobody ended up assigned");
  else if (assignees.size > 1) {
    fail(`views disagree on the winner: ${[...assignees].join(" vs ")} — the task would run twice`);
  } else {
    const winner = [...assignees][0];
    const name = winner === bob.did ? "bob" : winner === carol.did ? "carol" : "someone else";
    ok(`exactly one winner: ${name}`);
    if (views.every(([, rec]) => rec?.state === "assigned")) ok("all three views agree: assigned");
    else fail(`states disagree: ${views.map(([n, r]) => `${n}=${r?.state}`).join(" ")}`);

    // The loser must not be able to complete it.
    const loser = winner === bob.did ? carol : bob;
    await loser.sendAct(channel, "complete", taskId, { note: "sneaking in" });
    await new Promise((r) => setTimeout(r, 3000));
    const after = aliceStore.get(taskId);
    if (after?.state === "completed") fail("the LOSER completed the task — authorization is broken");
    else ok("the loser cannot complete it");
  }
}

console.error(failed ? "\n[claim] FAILURES ABOVE" : "\n[claim] ALL CHECKS PASSED — claim race is safe");
await alice.stop("done");
await bob.stop("done");
await carol.stop("done");
await rm(root, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
