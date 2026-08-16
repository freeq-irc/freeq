#!/usr/bin/env -S npx tsx
// The task lifecycle, end to end, against a real server.
//
// Two bots on a local freeq: one posts work, the other declines it, then takes
// the next one and finishes it. Every step is checked twice — once against
// what the server puts on the wire, once against what the REST endpoints say
// it believes. Along the way: a step the task's state does not allow, a step
// that is not the sender's to take, history replayed to a client that arrives
// late, and a task nobody touches swept away with the room told about it.
//
//   cargo build -p freeq-server
//   npx tsx freeq-bot-kit-js/examples/act-acceptance.ts
//
// FREEQ_SERVER_BIN overrides the binary path.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FreeqBot } from '../src/index.js';
import * as act from '../src/act-verbs.js';

const SERVER = process.env.FREEQ_SERVER_BIN ?? 'target/debug/freeq-server';
const CHANNEL = '#acceptance';
/** Short enough that the sweep fires while we are watching. */
const EXPIRY_SECS = 3;

let failures = 0;
const step = (name, what) => console.log(`\n── ${name} ${'─'.repeat(Math.max(1, 56 - name.length))}\n   ${what}`);
const check = (cond, what) => {
  if (cond) console.log(`   ✓ ${what}`);
  else {
    failures += 1;
    console.log(`   ✗ ${what}`);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const dir = mkdtempSync(join(tmpdir(), 'freeq-acceptance-'));
  const ircPort = 7300 + Math.floor(Math.random() * 500);
  const webPort = ircPort + 1000;

  const server = spawn(
    SERVER,
    [
      '--listen-addr', `127.0.0.1:${ircPort}`,
      '--web-addr', `127.0.0.1:${webPort}`,
      '--server-name', 'acceptance',
      '--data-dir', join(dir, 'srv'),
      '--db-path', join(dir, 'server.db'),
      '--act-expiry-secs', String(EXPIRY_SECS),
    ],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  );
  await sleep(2000);

  const api = async (path) => {
    const r = await fetch(`http://127.0.0.1:${webPort}${path}`);
    return r.json().catch(() => null);
  };
  const openWork = async () => (await api('/api/v1/act/tasks')).tasks ?? [];
  // The WebSocket endpoint lives on the web listener, not the IRC one.
  const url = `ws://127.0.0.1:${webPort}/irc`;

  const bots = [];
  const spawnBot = async (name) => {
    const bot = await FreeqBot.create({
      name,
      nick: name,
      ownerDid: 'did:key:zOwnerPlaceholder',
      url,
      root: join(dir, 'bots'),
      channels: [CHANNEL],
      capabilities: ['freeq.at/act'],
    });
    const seen = { raw: [], notices: [], fails: [] };
    bot.client.on('raw', (line) => {
      seen.raw.push(line);
      if (line.includes(' NOTICE ')) seen.notices.push(line);
      if (line.includes(' FAIL ')) seen.fails.push(line);
    });
    await bot.start();
    bots.push(bot);
    return { bot, seen, ctx: { client: bot.client, target: CHANNEL, did: bot.identity.did } };
  };

  try {
    step('connect', 'two bots authenticate, register keys, and join');
    const poster = await spawnBot('acceptance-poster');
    const worker = await spawnBot('acceptance-worker');
    await sleep(1500);
    check(!!poster.ctx.did && !!worker.ctx.did, `poster ${poster.ctx.did}`);
    check(poster.ctx.did !== worker.ctx.did, `worker ${worker.ctx.did}`);

    // ── a task that gets turned down ──
    step('decline', 'a directed offer the worker turns down');
    const declined = await act.offer(poster.ctx, {
      title: 'rewrite the changelog',
      to: worker.ctx.did,
    });
    await sleep(700);
    check(
      (await openWork()).some((t) => t.act_id === declined && t.state === 'offered'),
      `offered — the API shows it as offered (${declined})`,
    );
    await act.decline(worker.ctx, declined);
    await sleep(700);
    check(!(await openWork()).some((t) => t.act_id === declined), 'declined — gone from open work');
    const declinedHistory = await api(`/api/v1/act/tasks/${declined}`);
    check(declinedHistory.events.length === 2, 'its history keeps the offer and the decline');
    check(declinedHistory.task === null, 'and it holds no live row');

    // ── the full run ──
    step('offer', 'a second task, offered to the worker');
    const task = await act.offer(poster.ctx, {
      title: 'ship the release',
      to: worker.ctx.did,
    });
    await sleep(700);
    check((await openWork()).some((t) => t.act_id === task), `offered (${task})`);

    step('wrong sender', 'the poster tries to accept its own directed offer');
    poster.seen.fails.length = 0;
    await act.accept(poster.ctx, task).catch(() => {});
    await sleep(700);
    check(
      poster.seen.fails.some((l) => l.includes('WRONG_SENDER')),
      'refused: WRONG_SENDER',
    );
    check(
      (await openWork()).find((t) => t.act_id === task)?.state === 'offered',
      'and the task did not move',
    );

    step('accept', 'the worker takes it');
    await act.accept(worker.ctx, task);
    await sleep(700);
    let row = (await openWork()).find((t) => t.act_id === task);
    check(row?.state === 'assigned', 'assigned');
    check(row?.assignee === worker.ctx.did, 'and the worker is its assignee');

    step('illegal step', 'the worker accepts a second time');
    worker.seen.fails.length = 0;
    await act.accept(worker.ctx, task).catch(() => {});
    await sleep(700);
    check(
      worker.seen.fails.some((l) => l.includes('ILLEGAL_STEP')),
      'refused: ILLEGAL_STEP',
    );

    step('progress', 'the worker reports in');
    await act.progress(worker.ctx, task, { note: 'tagged the build' });
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === task)?.state === 'assigned',
      'still assigned — progress does not end anything',
    );

    step('complete', 'the worker finishes');
    await act.complete(worker.ctx, task);
    await sleep(700);
    check(!(await openWork()).some((t) => t.act_id === task), 'completed — gone from open work');
    const full = await api(`/api/v1/act/tasks/${task}`);
    check(full.events.length === 4, 'four events on file: offer, accept, progress, complete');
    check(
      full.events.every((e) => typeof e.signature === 'string' && e.signature.startsWith('ed25519:')),
      'each one signed',
    );
    check(
      full.events.every((e) => e.canonical.includes('"act-verb"')),
      'and stored as the exact bytes its signature covers',
    );

    // ── replay ──
    step('replay', 'a third client joins late and is given the history');
    const late = await spawnBot('acceptance-latecomer');
    await sleep(2000);
    const replayed = late.seen.raw.filter((l) => l.includes('+freeq.at/act='));
    check(replayed.length > 0, `task events replayed on join (${replayed.length} lines)`);
    check(
      replayed.some((l) => l.includes('+freeq.at/sig=')),
      'with their signatures, so a late arrival can check them',
    );

    // ── expiry ──
    step('expiry', `a task nobody touches, swept after ${EXPIRY_SECS}s`);
    poster.seen.notices.length = 0;
    const abandoned = await act.offer(poster.ctx, { title: 'nobody wants this' });
    await sleep((EXPIRY_SECS + 5) * 1000);
    check(
      !(await openWork()).some((t) => t.act_id === abandoned),
      'expired out of the live view',
    );
    const swept = await api(`/api/v1/act/tasks/${abandoned}`);
    check(
      swept.events.some((e) => e.canonical.includes('"act-verb":"expire"')),
      "the server's own expire event is on file",
    );
    check(
      swept.events.some((e) => e.canonical.includes('did:web:acceptance')),
      'signed under the server\'s own identity',
    );
    check(
      poster.seen.notices.some((l) =>
        l.endsWith('Task expired without completion: nobody wants this'),
      ),
      'and the room was told, in the approved words',
    );
  } finally {
    for (const b of bots) await b.stop('acceptance').catch(() => {});
    server.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  }

  console.log(
    `\n${failures === 0 ? 'ACCEPTANCE PASSED' : `ACCEPTANCE FAILED — ${failures} check(s)`}\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('\nacceptance run crashed:', e);
  process.exit(1);
});
