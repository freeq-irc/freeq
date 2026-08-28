#!/usr/bin/env node
/**
 * Acceptance harness — inbound act signatures are actually verified.
 *
 * Uses a REAL agent's signature and the REAL server key store, then tampers
 * with the event to prove the check bites:
 *
 *   1. Alice signs and sends a handoff offer.
 *   2. Bob verifies it against the key the signature names → valid.
 *   3. Tamper with a covered tag → invalid.
 *   4. Point the key lookup at a dead origin → unverifiable, NOT invalid.
 *
 *   npx tsx spike/verify-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ActEventPayload } from "@freeq/sdk";

import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";
import { serverKeyFetcher, verifyActEvent } from "../src/verify.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    origin: { type: "string", default: "http://127.0.0.1:18080" },
    channel: { type: "string", default: `#pi-verify-${Date.now().toString(36)}` },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-verify-"));
let failed = false;
const fail = (m: string) => {
  console.error(`[verify] FAIL — ${m}`);
  failed = true;
};
const ok = (m: string) => console.error(`[verify] ✓ ${m}`);

const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });
const channel = values.channel!;
const received: ActEventPayload[] = [];

function mk(slug: string, nick: string, collect = false) {
  return new FreeqConnection({
    ownerDid: values.owner!,
    server: values.server!,
    slug,
    nick,
    channels: [channel],
    meta,
    root: join(root, slug),
    onNotice: (t, l) => console.error(`[${nick}] ${l}: ${t}`),
    onActEvent: collect ? (ev) => received.push(ev) : undefined,
  });
}

const alice = mk("vfalice1", "pi-alice");
const bob = mk("vfbob0001", "pi-bob", true);
await alice.start();
await bob.start();
console.error(`[verify] alice=${alice.did} bob=${bob.did}`);
await new Promise((r) => setTimeout(r, 2500));

const taskId = await alice.sendAct(channel, "offer", undefined, {
  to: bob.did ?? "did:key:zNobody",
  title: "Verify me",
});
if (!taskId) fail("alice could not send the offer");

// Wait for bob to receive it.
const deadline = Date.now() + 30_000;
while (Date.now() < deadline && !received.some((e) => e.taskId === taskId)) {
  await new Promise((r) => setTimeout(r, 1000));
}
const ev = received.find((e) => e.taskId === taskId);

if (!ev) {
  fail("bob never received the offer");
} else {
  console.error(`[verify] bob received ${ev.verb} sig=${ev.sigTag ? "present" : "MISSING"}`);
  const fetchKey = serverKeyFetcher(values.origin!);
  const base = {
    channel: ev.channel,
    did: ev.did,
    eventId: ev.eventId,
    tags: ev.tags,
    sigTag: ev.sigTag,
  };

  // 1. As received → valid.
  const good = await verifyActEvent(base, { fetchKey, selfDid: bob.did ?? "" });
  if (good.outcome === "valid") ok("a real signature verifies against the real key store");
  else fail(`expected valid, got ${good.outcome} (${good.reason})`);

  // 2. Tampered → invalid.
  const tampered = {
    ...base,
    tags: { ...base.tags, "+freeq.at/act-title": "Delete production" },
  };
  const bad = await verifyActEvent(tampered, { fetchKey, selfDid: bob.did ?? "" });
  if (bad.outcome === "invalid") ok("tampering with a covered tag is detected as INVALID");
  else fail(`tampering produced '${bad.outcome}' — it must be invalid`);

  // 3. Key store unreachable → unverifiable, never invalid.
  const deadFetcher = serverKeyFetcher("http://127.0.0.1:9"); // nothing listens
  const deferred = await verifyActEvent(base, { fetchKey: deadFetcher, selfDid: bob.did ?? "" });
  if (deferred.outcome === "unverifiable") {
    ok("an unreachable key store yields UNVERIFIABLE, not invalid");
  } else {
    fail(`a dead key store produced '${deferred.outcome}' — an outage is not a forgery`);
  }

  // 4. An unknown kid → unverifiable (no key on record), not invalid.
  const unknownKid = {
    ...base,
    sigTag: base.sigTag?.replace(/:([^:]+):/, ":AAAAAAAAAAAAAAAAAAAAAA:"),
  };
  const unknown = await verifyActEvent(unknownKid, { fetchKey, selfDid: bob.did ?? "" });
  if (unknown.outcome === "unverifiable") ok("an unknown kid yields UNVERIFIABLE");
  else console.error(`[verify] note: unknown kid gave '${unknown.outcome}' (${unknown.reason})`);
}

console.error(failed ? "\n[verify] FAILURES ABOVE" : "\n[verify] ALL CHECKS PASSED");
await alice.stop("done");
await bob.stop("done");
await rm(root, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
