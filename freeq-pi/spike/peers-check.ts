#!/usr/bin/env node
/**
 * M1 acceptance harness — two installations must see each other.
 *
 * Spins up two `FreeqConnection`s with distinct installation slugs and
 * separate state roots (i.e. two independent identities, exactly as two
 * laptops would be), joins them to a channel, and asserts each shows the
 * other in `peers()` with usable session metadata.
 *
 *   npx tsx freeq-pi/spike/peers-check.ts --server ws://127.0.0.1:18080/irc
 */

import { parseArgs } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FreeqConnection } from "../src/connection.js";
import { collectSessionMeta, describeMeta } from "../src/presence.js";

const { values } = parseArgs({
  options: {
    server: { type: "string", default: "ws://127.0.0.1:18080/irc" },
    channel: { type: "string", default: "#pi-m1" },
    owner: { type: "string", default: "did:plc:4qsyxmnsblo4luuycm3572bq" },
    timeout: { type: "string", default: "45" },
  },
  strict: true,
});

const deadline = Date.now() + Number(values.timeout) * 1000;
const root = await mkdtemp(join(tmpdir(), "freeq-pi-m1-"));

const meta = await collectSessionMeta({ cwd: process.cwd(), model: "test-model" });

function mk(slug: string, nick: string) {
  return new FreeqConnection({
    ownerDid: values.owner!,
    server: values.server!,
    slug,
    nick,
    channels: [values.channel!],
    meta: { ...meta, session: slug },
    root: join(root, slug),
    onNotice: (t, l) => console.error(`[${nick}] ${l}: ${t}`),
  });
}

const a = mk("aaaa1111", "pi-alice");
const b = mk("bbbb2222", "pi-bob");

console.error(`[m1] server=${values.server} channel=${values.channel} root=${root}`);
await a.start();
await b.start();
console.error(`[m1] alice: ${a.describe()}`);
console.error(`[m1] bob:   ${b.describe()}`);

// Nudge presence so both sides announce into the shared channel.
const settle = async () => {
  a.updateMeta({ ...a.meta, model: "test-model" });
  b.updateMeta({ ...b.meta, model: "test-model" });
};

let ok = false;
while (Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 2000));
  await settle();
  const aSeesB = a.peers().some((p) => p.nick.toLowerCase().startsWith("pi-bob"));
  const bSeesA = b.peers().some((p) => p.nick.toLowerCase().startsWith("pi-alice"));
  console.error(
    `[m1] alice sees ${a.peers().length} peer(s) [${a.peers().map((p) => p.nick).join(",")}] · ` +
      `bob sees ${b.peers().length} [${b.peers().map((p) => p.nick).join(",")}]`,
  );
  if (aSeesB && bSeesA) {
    ok = true;
    break;
  }
}

if (ok) {
  console.error("\n[m1] PEERS VISIBLE — acceptance met");
  for (const [name, c] of [["alice", a], ["bob", b]] as const) {
    for (const p of c.peers()) {
      console.error(`  ${name} → ${p.nick} [${p.did ?? "no did"}] ${p.state} ${describeMeta(p.meta)}`);
    }
  }
} else {
  console.error("\n[m1] FAILED — peers not mutually visible before timeout");
}

await a.stop("m1 done");
await b.stop("m1 done");
await rm(root, { recursive: true, force: true });
process.exit(ok ? 0 : 1);
