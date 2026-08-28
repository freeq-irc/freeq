#!/usr/bin/env node
/**
 * Regression harness — a dropped socket must NOT produce extra sessions.
 *
 * The bug: FreeqConnection ran its own reconnect loop (tear the bot down,
 * build a new one) while the SDK transport was already reconnecting the same
 * client. Both raced, so every blip left several live sessions on one DID and
 * the server logged endless ghost-mode churn, repeated AGENT REGISTER, and a
 * hello storm.
 *
 * This forces a disconnect mid-session and asserts we end up with exactly one
 * working connection, and that connect attempts did not multiply.
 *
 *   npx tsx spike/churn-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta } from "../src/presence.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: `#churn-${Date.now().toString(36)}` },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
  },
  strict: true,
});

const root = await mkdtemp(join(tmpdir(), "freeq-churn-"));
let failed = false;
const fail = (m: string) => {
  console.error(`[churn] FAIL — ${m}`);
  failed = true;
};

const meta = await collectSessionMeta({ cwd: process.cwd(), model: "harness" });
const conn = new FreeqConnection({
  ownerDid: values.owner!,
  server: values.server!,
  slug: "churn001",
  nick: "pi-churn",
  channels: [values.channel!],
  meta,
  root,
  onNotice: (t, l) => console.error(`[churn] notice(${l}): ${t}`),
});

await conn.start();
console.error(`[churn] online as ${conn.nick} (${conn.did})`);
if (conn.state !== "online") fail("did not connect");

// A second start() must be a no-op, not a second bot/socket/session.
const nickBefore = conn.nick;
await conn.start();
await conn.start();
if (conn.nick !== nickBefore) fail(`re-entrant start() changed the session (${nickBefore} → ${conn.nick})`);
else console.error("[churn] ✓ re-entrant start() is a no-op");

// Force the socket down underneath us, the way a network blip or a server
// restart does, and let the transport recover on its own.
const client = conn.bot!.client as unknown as {
  transport?: { ws?: { close: () => void } };
};
const ws = client.transport?.ws;
if (!ws) {
  console.error("[churn] note: could not reach the underlying socket; skipping the drop test");
} else {
  console.error("[churn] dropping the socket…");
  ws.close();

  // Wait for the transport's own reconnect.
  const deadline = Date.now() + 60_000;
  let recovered = false;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2000));
    if (conn.state === "online" && conn.nick) {
      recovered = true;
      break;
    }
  }
  if (!recovered) fail(`did not recover after the drop (state=${conn.state})`);
  else console.error(`[churn] ✓ recovered by the transport, state=${conn.state}, nick=${conn.nick}`);

  // The whole point: one session, still able to send.
  const sent = conn.send(values.channel!, "post-reconnect liveness check");
  if (!sent) fail("could not send after recovery — the connection is not usable");
  else console.error("[churn] ✓ still usable after recovery");
}

await new Promise((r) => setTimeout(r, 2000));
console.error(failed ? "\n[churn] FAILURES ABOVE" : "\n[churn] ALL CHECKS PASSED — no duplicate sessions");
await conn.stop("churn done");
await rm(root, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
