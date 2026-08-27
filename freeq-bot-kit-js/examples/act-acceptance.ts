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
import { actTags } from '@freeq/sdk';
import { verifyActTags } from '../src/act.js';

/** Send a task event as `ctx`'s bot, with the line these tags deserve. */
const send = (ctx, kind, verb, task, fields = {}) =>
  ctx.client.sendAct(ctx.target, actTags(kind, verb, task, ctx.did, fields), {
    taskId: task,
  });

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
  const openWork = async () => (await api('/api/v1/actions')).tasks ?? [];
  /** The key this server publishes as its own — what a receipt is checked against. */
  const homeKey = async () =>
    new Uint8Array(Buffer.from((await api('/api/v1/signing-key')).public_key, 'base64url'));
  /**
   * A stored event, back in the shape a verifier wants: the wire tags its
   * canonical rebuilds to, plus the two fields the caller injects.
   */
  const asWire = (event) => {
    const doc = JSON.parse(event.canonical);
    const tags = {};
    for (const [k, v] of Object.entries(doc)) {
      if (k !== 'target' && k !== 'id') tags[`+freeq.at/${k}`] = v;
    }
    return { tags, target: doc.target, id: doc.id, sig: event.signature };
  };
  /** Every receipt in an event list, keyed by the event each one confirms. */
  const receiptsBySubject = (events) => {
    const out = new Map();
    for (const e of events) {
      const doc = JSON.parse(e.canonical);
      if (doc['act-verb'] === 'confirm') out.set(doc['act-subject'], e);
    }
    return out;
  };
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
    const declined = await send(poster.ctx, 'handoff', 'offer', undefined, {
      title: 'rewrite the changelog',
      to: worker.ctx.did,
    });
    await sleep(700);
    check(
      (await openWork()).some((t) => t.act_id === declined && t.state === 'offered'),
      `offered — the API shows it as offered (${declined})`,
    );
    await send(worker.ctx, 'handoff', 'decline', declined);
    await sleep(700);
    check(!(await openWork()).some((t) => t.act_id === declined), 'declined — gone from open work');
    const declinedHistory = await api(`/api/v1/actions/${declined}`);
    check(
      declinedHistory.events.length === 3,
      'its history keeps the offer, the decline, and the home\'s word about the decline',
    );
    check(declinedHistory.task === null, 'and it holds no live row');

    // ── the full run ──
    step('offer', 'a second task, offered to the worker');
    const task = await send(poster.ctx, 'handoff', 'offer', undefined, {
      title: 'ship the release',
      to: worker.ctx.did,
    });
    await sleep(700);
    check((await openWork()).some((t) => t.act_id === task), `offered (${task})`);

    step('wrong sender', 'the poster tries to accept its own directed offer');
    poster.seen.fails.length = 0;
    await send(poster.ctx, 'handoff', 'accept', task).catch(() => {});
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
    const acceptId = await send(worker.ctx, 'handoff', 'accept', task);
    await sleep(700);
    let row = (await openWork()).find((t) => t.act_id === task);
    check(row?.state === 'assigned', 'assigned');
    check(row?.assignee === worker.ctx.did, 'and the worker is its assignee');

    step('illegal step', 'the worker accepts a second time');
    worker.seen.fails.length = 0;
    await send(worker.ctx, 'handoff', 'accept', task).catch(() => {});
    await sleep(700);
    check(
      worker.seen.fails.some((l) => l.includes('ILLEGAL_STEP')),
      'refused: ILLEGAL_STEP',
    );

    step('progress', 'the worker reports in');
    await send(worker.ctx, 'handoff', 'progress', task, { note: 'tagged the build' });
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === task)?.state === 'assigned',
      'still assigned — progress does not end anything',
    );

    step('complete', 'the worker finishes');
    const completeId = await send(worker.ctx, 'handoff', 'complete', task);
    await sleep(700);
    check(!(await openWork()).some((t) => t.act_id === task), 'completed — gone from open work');
    const full = await api(`/api/v1/actions/${task}`);
    check(
      full.events.length === 6,
      'six events on file: offer, accept, progress, complete, and a receipt for each move',
    );
    check(
      full.events.every((e) => typeof e.signature === 'string' && e.signature.startsWith('ed25519:')),
      'each one signed',
    );
    check(
      full.events.every((e) => e.canonical.includes('"act-verb"')),
      'and stored as the exact bytes its signature covers',
    );

    // ── the home's receipts ──
    step('receipts', 'the home confirms every move, and only the moves');
    const receipts = receiptsBySubject(full.events);
    check(receipts.has(acceptId), 'the accept is confirmed');
    check(receipts.has(completeId), 'the complete is confirmed');
    check(receipts.size === 2, 'and nothing else is — an offer opens, a progress moves nothing');
    const key = await homeKey();
    for (const [subject, event] of receipts) {
      const wire = asWire(event);
      check(
        wire.tags['+freeq.at/from'] === 'did:web:acceptance',
        `signed under the server's own identity (${subject.slice(0, 8)}…)`,
      );
      const verdict = await verifyActTags(wire.tags, wire.target, wire.id, wire.sig, key);
      check(verdict.ok === true, 'and its signature verifies against the key the server publishes');
    }

    // ── the revival relation ──
    step('replaces', 'the finished task is re-offered, naming what it revives');
    const revived = await send(poster.ctx, 'handoff', 'offer', undefined, {
      title: 'ship the release, again',
      to: worker.ctx.did,
      replaces: task,
    });
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === revived)?.replaces === task,
      `the new task names the one it revives (${revived} → ${task})`,
    );
    check(
      (await api(`/api/v1/actions/${task}`)).events.length === 6,
      'and the task it replaces is exactly as it ended',
    );

    step('replaces refused', 'a re-offer naming a task that has not finished');
    poster.seen.fails.length = 0;
    await send(poster.ctx, 'handoff', 'offer', undefined, {
      title: 'too soon',
      replaces: revived,
    }).catch(() => {});
    await sleep(700);
    check(
      poster.seen.fails.some((l) => l.includes('REPLACES_NOT_TERMINAL')),
      'refused: REPLACES_NOT_TERMINAL',
    );

    // ── replay ──
    step('replay', 'a third client joins late and is given the history');
    const late = await spawnBot('acceptance-latecomer');
    await sleep(2000);
    const replayed = late.seen.raw.filter((l) => l.includes('+freeq.at/act='));
    // Every stored event reaches a joiner twice: the channel replays history
    // at JOIN, and sdk-js then asks for CHATHISTORY, which answers with the
    // same rows. Counted exactly, so either half changing is visible here
    // rather than passing as "some lines arrived".
    const stored = (
      await Promise.all(
        [declined, task, revived].map(async (id) =>
          (await api(`/api/v1/actions/${id}`)).events.length),
      )
    ).reduce((a, b) => a + b, 0);
    check(
      replayed.length === stored * 2,
      `every stored task event replayed on join, twice over (${replayed.length} lines, ${stored} events)`,
    );
    check(
      replayed.some((l) => l.includes('+freeq.at/sig=')),
      'with their signatures, so a late arrival can check them',
    );

    // ── the second kind ──
    step('bounty', 'a bounty two bots bid on, awarded to one of them');
    const rival = await spawnBot('acceptance-rival');
    await sleep(1500);
    const bounty = await send(poster.ctx, 'bounty', 'offer', undefined, {
      title: 'index the archive',
    });
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === bounty)?.state === 'open',
      `open (${bounty})`,
    );

    const workerBid = await send(worker.ctx, 'bounty', 'bid', bounty, { note: 'two days' });
    await send(rival.ctx, 'bounty', 'bid', bounty, { note: 'one day, no sources' });
    await sleep(900);
    check(
      (await openWork()).find((t) => t.act_id === bounty)?.state === 'open',
      'still open — a bid is additive and moves nothing',
    );
    const bidding = await api(`/api/v1/actions/${bounty}`);
    check(
      bidding.events.filter((e) => e.canonical.includes('"act-verb":"bid"')).length === 2,
      'both bids are on file, neither superseding the other',
    );

    step('award', 'the poster takes one of the bids');
    const awardId = await send(poster.ctx, 'bounty', 'award', bounty, {
      accepts: workerBid,
    });
    await sleep(700);
    const awarded = (await openWork()).find((t) => t.act_id === bounty);
    check(awarded?.state === 'assigned', 'assigned');
    check(
      awarded?.assignee === worker.ctx.did,
      'and the assignee is the author of the bid it took, not the poster',
    );
    check(
      receiptsBySubject((await api(`/api/v1/actions/${bounty}`)).events).has(awardId),
      'the award is confirmed by the home',
    );

    step('the loser', 'the bot whose bid was not taken tries to hand work in');
    rival.seen.fails.length = 0;
    await send(rival.ctx, 'bounty', 'submit', bounty).catch(() => {});
    await sleep(700);
    check(
      rival.seen.fails.some((l) => l.includes('WRONG_SENDER')),
      'refused: WRONG_SENDER',
    );

    step('review', 'the winner hands the work in, and the poster sends it back');
    await send(worker.ctx, 'bounty', 'submit', bounty);
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === bounty)?.state === 'under_review',
      'under review — handed in, not finished',
    );
    poster.seen.fails.length = 0;
    await send(poster.ctx, 'bounty', 'cancel', bounty).catch(() => {});
    await sleep(700);
    check(
      poster.seen.fails.some((l) => l.includes('ILLEGAL_STEP')),
      'and delivered work is not the poster\'s to withdraw: ILLEGAL_STEP',
    );
    await send(poster.ctx, 'bounty', 'revise', bounty);
    await sleep(700);
    check(
      (await openWork()).find((t) => t.act_id === bounty)?.state === 'assigned',
      'sent back — assigned again, and the worker still holds it',
    );

    step('the poster accepts', 'the offerer\'s word is what ends a bounty');
    await send(worker.ctx, 'bounty', 'submit', bounty);
    await sleep(700);
    const bountyDone = await send(poster.ctx, 'bounty', 'accept-work', bounty);
    await sleep(700);
    check(!(await openWork()).some((t) => t.act_id === bounty), 'accepted — gone from open work');
    check(
      receiptsBySubject((await api(`/api/v1/actions/${bounty}`)).events).has(bountyDone),
      'and the acceptance is confirmed too',
    );

    // ── expiry ──
    step('expiry', `a task nobody touches, swept after ${EXPIRY_SECS}s`);
    poster.seen.notices.length = 0;
    const abandoned = await send(poster.ctx, 'handoff', 'offer', undefined, {
      title: 'nobody wants this',
    });
    await sleep((EXPIRY_SECS + 5) * 1000);
    check(
      !(await openWork()).some((t) => t.act_id === abandoned),
      'expired out of the live view',
    );
    const swept = await api(`/api/v1/actions/${abandoned}`);
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
