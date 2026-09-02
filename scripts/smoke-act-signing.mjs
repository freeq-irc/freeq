#!/usr/bin/env node
/**
 * The hand-run live acceptance for message signing and the act family
 * against a deployed server.
 *
 * This is the half no unit test and no local server can answer: it needs a
 * deployed server that both advertises `freeq.at/msgsig` and carries the
 * receive half. Every assertion is made against the server's own answers
 * over REST, never against what the client believes it sent.
 *
 * Usage:
 *   ( cd freeq-sdk-js && npm run build )
 *   ( cd freeq-bot-kit-js && npm run build )
 *   node scripts/smoke-act-signing.mjs --owner did:plc:<your-did>
 *
 * Env:
 *   FREEQ_URL      WebSocket URL  (default wss://irc.zerosum.org/irc)
 *   FREEQ_API      REST base URL  (default https://irc.zerosum.org)
 *   FREEQ_CHANNEL  Test channel   (default #actsmoke-<stamp>, ephemeral)
 *
 * Exit code 0 only if every check passes. Every server response is saved
 * under smoke-evidence/act-signing/live-<stamp>/ (gitignored).
 *
 * NOT covered here, stated rather than left to be assumed:
 *   - The Rust SDK's emitter. This driver is node; the Rust half of the
 *     emitter work is pinned by `coordination_events_rest_api` against a
 *     real server in the Rust suite.
 *   - An unverifiable-but-kept signature. Producing one live means a key
 *     the server cannot resolve, which needs a second server.
 *   - Whether a client renders an attachment. That is a client-side
 *     rendering question; what is checked here is that the wire carries
 *     the prefixed tags and that the signature covers them.
 */

import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';

import { FreeqBot } from '../freeq-bot-kit-js/dist/index.js';

const { values } = parseArgs({ options: { owner: { type: 'string' } }, strict: false });
if (!values.owner) {
  console.error('Usage: node scripts/smoke-act-signing.mjs --owner did:plc:<your-did>');
  process.exit(2);
}

const WS = process.env.FREEQ_URL || 'wss://irc.zerosum.org/irc';
const API = (process.env.FREEQ_API || 'https://irc.zerosum.org').replace(/\/$/, '');
const STAMP = Date.now().toString(36);
const CHANNEL = process.env.FREEQ_CHANNEL || `#actsmoke-${STAMP}`;
const EVIDENCE = join('smoke-evidence', 'act-signing', `live-${STAMP}`);

// ── Harness ────────────────────────────────────────────────────────

const results = [];
let fails = [];

async function check(name, covers, fn) {
  fails = [];
  process.stdout.write(`… ${name}\r`);
  try {
    await fn();
  } catch (e) {
    fails.push(`exception: ${e?.message || e}`);
  }
  const ok = fails.length === 0;
  console.log(`${ok ? '✓' : '✗'} ${name}`);
  if (!ok) for (const f of fails) console.log(`    ${f}`);
  results.push({ name, covers, ok, fails: [...fails] });
  await sleep(800); // server caps event TAGMSGs at 5 per 2s per session
}

const expect = (cond, msg) => { if (!cond) fails.push(msg); };
const expectEq = (a, b, msg) => {
  if (a !== b) fails.push(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
};

// ── Server queries (shapes verified against web.rs) ────────────────

async function getJson(path) {
  const res = await fetch(`${API}${path}`);
  const body = await res.text();
  let json = null;
  try { json = JSON.parse(body); } catch { /* non-JSON stays null */ }
  return { status: res.status, json, body };
}

/** Filing is asynchronous; poll rather than guess a sleep. */
async function verifyEvent(id, { tries = 25, waitMs = 400 } = {}) {
  for (let i = 0; i < tries; i++) {
    const r = await getJson(`/api/v1/verify/${encodeURIComponent(id)}`);
    if (r.status === 200 && r.json && !r.json.error) return r.json;
    await sleep(waitMs);
  }
  return null;
}

/**
 * `until` matters: the action exists from the moment it is opened, so polling
 * for the action alone returns before a later step on it has landed. Callers
 * waiting on a completion must say so.
 */
async function getAction(id, { tries = 25, waitMs = 400, until = null } = {}) {
  let last = null;
  for (let i = 0; i < tries; i++) {
    const r = await getJson(`/api/v1/actions/${encodeURIComponent(id)}`);
    if (r.status === 200 && r.json && !r.json.error) {
      last = r.json;
      if (!until || until(r.json)) return r.json;
    }
    await sleep(waitMs);
  }
  return last;
}

/** The action's history holds a step carrying this verb. A terminal step
 *  also removes the task from the live view (`task` goes null) — the view
 *  holds live actions, the log holds the history — so the events are what a
 *  finished action is read from. */
const hasVerb = (verb) => (action) =>
  (action.events || []).some((e) => String(e.canonical || '').includes(`"act-verb":"${verb}"`));

/** The freeform `+freeq.at/event` rows a channel holds — the older family's
 *  own readback, which the generic events route keeps serving. */
async function channelEvents({ tries = 25, waitMs = 400, until = null } = {}) {
  let last = [];
  for (let i = 0; i < tries; i++) {
    const r = await getJson(
      `/api/v1/channels/${encodeURIComponent(CHANNEL.replace(/^#/, ''))}/events?limit=100`,
    );
    if (r.status === 200 && r.json) {
      last = r.json.events || [];
      if (!until || until(last)) return last;
    }
    await sleep(waitMs);
  }
  return last;
}

const history = (limit = 30) =>
  getJson(`/api/v1/channels/${encodeURIComponent(CHANNEL.replace(/^#/, ''))}/history?limit=${limit}`);

async function evidence(name, value) {
  await mkdir(EVIDENCE, { recursive: true });
  await writeFile(join(EVIDENCE, `${name}.json`), JSON.stringify(value, null, 2) + '\n');
}

/** `verdict` and `verified_by` are nested under `verification`. */
function expectDeviceSigned(v, label) {
  expect(v !== null, `${label}: the server never filed this id`);
  if (!v) return;
  expectEq(v.verification?.verdict, 'valid', `${label}: verdict`);
  expectEq(v.verification?.verified_by, 'client-session-key', `${label}: verified_by`);
}

// ── Bots ───────────────────────────────────────────────────────────

const stateRoot = await mkdtemp(join(tmpdir(), 'actsmoke-'));

async function makeBot(name, nick) {
  const bot = await FreeqBot.create({
    name: `${name}-${STAMP}`,
    ownerDid: values.owner,
    nick,
    url: WS,
    channels: [CHANNEL],
    root: stateRoot,
  });
  await bot.start();
  await sleep(1500); // start() resolves at registration; the join settles after
  return bot;
}

// ── Run ────────────────────────────────────────────────────────────

console.log(`act signing live acceptance`);
console.log(`  wire     ${WS}`);
console.log(`  rest     ${API}`);
console.log(`  channel  ${CHANNEL}`);
console.log(`  evidence ${EVIDENCE}/\n`);

const health = await getJson('/api/v1/health');
if (health.status !== 200) {
  console.error(`server not answering /api/v1/health (HTTP ${health.status}) — aborting`);
  process.exit(2);
}

const tx = await makeBot('actsmoke-tx', `asmk-tx-${STAMP}`);
const rx = await makeBot('actsmoke-rx', `asmk-rx-${STAMP}`);

const actSeen = [];
rx.client.on('actEvent', (e) =>
  actSeen.push({ eventId: e.eventId, verb: e.verb, taskId: e.taskId }));


const msgSeen = [];
rx.client.on('message', (channel, m) =>
  msgSeen.push({ channel, id: m.id, text: m.text, tags: m.tags }));

let taskId = null;
/** The older family's event, filed in checks 7-8. */
let stopgapId = null;

await check('task event is signed by the sender and filed under the signed id',
  'd7b27d54 9107d64c 15952ece 8332482c', async () => {
    taskId = await tx.client.createTask(CHANNEL, 'live: a signed task event');
    expectEq(typeof taskId === 'string' && taskId.length, 26, 'createTask should return a ULID');
    const v = await verifyEvent(taskId);
    await evidence('01-offer', v ?? { error: 'never filed', taskId });
    expectDeviceSigned(v, 'offer');
    if (v) {
      expectEq(v.kind, 'act', 'offer: kind');
      expect(String(v.canonical_form || '').includes('"act":"handoff"'),
        `offer: canonical should be the act document, got ${v.canonical_form}`);
      expect(String(v.canonical_form || '').includes('"act-verb":"offer"'),
        `offer: canonical should carry the verb, got ${v.canonical_form}`);
    }
  });

await check('the completion names the task inside its own signature',
  '15952ece 510d41e0', async () => {
    await tx.client.completeTask(CHANNEL, taskId, 'live: done');
    const action = await getAction(taskId, { until: hasVerb('complete') });
    await evidence('02-action-detail', action ?? { error: 'action not found', taskId });
    expect(action !== null, 'action detail: the server has no such action');
    if (!action) return;
    // A completed action leaves the live view; its signed log stays.
    expectEq(action.task, null, 'a terminal action is off the live view');
    const done = (action.events || []).find((e) =>
      String(e.canonical || '').includes('"act-verb":"complete"'));
    expect(done !== undefined,
      `action detail: no completion in ${JSON.stringify((action.events || []).map(e => e.event_id))}`);
    if (!done) return;
    const v = await verifyEvent(done.event_id);
    await evidence('02-complete', v ?? { error: 'never filed', id: done.event_id });
    expectDeviceSigned(v, 'complete');
    if (v) expect(String(v.canonical_form || '').includes(`"act-id":"${taskId}"`),
      `complete: the signed document names the action, got ${v.canonical_form}`);
  });

await check('the evidence and its hash are inside the signed document, not beside it',
  'e76ee946', async () => {
    // Its own action: `progress` is not a legal move on a completed one, and
    // the action above is finished.
    const evidenceTask = await tx.client.createTask(CHANNEL, 'live: an action carrying evidence');
    await tx.client.attachEvidence(CHANNEL, evidenceTask, 'test_result', 'live: green', {
      reference: 'https://example.org/live-green.txt',
      content: new TextEncoder().encode('live: green'),
    });
    const action = await getAction(evidenceTask, {
      until: (a) => (a.events || []).some((e) => String(e.canonical || '').includes('"act-ctx-h"')),
    });
    const ev = (action?.events || []).find((e) =>
      String(e.canonical || '').includes('"act-ctx-h"'));
    expect(ev !== undefined, 'no step carrying a context hash on the action');
    if (!ev) return;
    const v = await verifyEvent(ev.event_id);
    await evidence('03-evidence', v ?? { error: 'never filed', id: ev.event_id });
    expectDeviceSigned(v, 'evidence');
    if (v) {
      expect(String(v.canonical_form || '').includes('"act-ctx":"https://example.org/live-green.txt"'),
        `the reference should be covered, canonical was ${v.canonical_form}`);
      expect(String(v.canonical_form || '').includes('"act-ctx-h":"sha256:'),
        `the content hash should be covered, canonical was ${v.canonical_form}`);
      expect(String(v.canonical_form || '').includes('test_result'),
        `the evidence type should be covered, canonical was ${v.canonical_form}`);
    }
  });

await check('a receiving client sees ONE event, carrying the real id',
  'e8f015ee c99d084d', async () => {
    actSeen.length = 0;
    const id = await tx.client.createTask(CHANNEL, 'live: one event per event');
    await sleep(3500);
    const mine = actSeen.filter((e) => e.verb === 'offer' && e.eventId === id);
    expectEq(mine.length, 1, `should fire once per event, saw ${JSON.stringify(actSeen)}`);
    await evidence('04-reader', { emitted: id, seen: actSeen });
  });

await check('the companion message names the event inside its signature',
  'c99d084d 510d41e0', async () => {
    msgSeen.length = 0;
    const id = await tx.client.createTask(CHANNEL, 'live: the pair is joined');
    await sleep(3500);
    const companion = msgSeen.find((m) => m.tags && m.tags['+freeq.at/ref'] === id);
    expect(companion !== undefined,
      `no companion carrying ref=${id}; saw ${JSON.stringify(msgSeen.map(m => m.tags))}`);
    if (!companion) return;
    const v = await verifyEvent(companion.id);
    await evidence('05-companion', v ?? { error: 'never filed', id: companion.id });
    expectDeviceSigned(v, 'companion message');
    if (v) expect(String(v.canonical_form || '').includes(`"ref":"${id}"`),
      `the companion should cover the action it names, canonical was ${v.canonical_form}`);
  });

await check('three fresh connections all sign (the emit-after-connect race)',
  '5b7f135e', async () => {
    const runs = [];
    for (let i = 0; i < 3; i++) {
      const b = await makeBot(`actsmoke-race${i}`, `asmk-r${i}-${STAMP}`);
      const id = await b.client.createTask(CHANNEL, `live: race run ${i}`);
      const v = await verifyEvent(id);
      runs.push({ run: i, id, verdict: v?.verification?.verdict ?? null, verified_by: v?.verification?.verified_by ?? null });
      expectDeviceSigned(v, `race run ${i}`);
      await b.stop();
      await sleep(600);
    }
    await evidence('06-connect-race', runs);
  });

await check('another actor cannot take over a stored event id',
  'b5b9e59a', async () => {
    // The older family, driven through the generic emitter it still belongs
    // to, and read back through the route that keeps serving its rows.
    const mine = await tx.client.emitEvent(
      CHANNEL, 'task_request', { description: 'live: a stopgap event' },
      { humanText: '📋 New task: live: a stopgap event' },
    );
    const before = (await channelEvents({ until: (rows) => rows.some((e) => e.event_id === mine) }))
      .find((e) => e.event_id === mine);
    expect(before !== undefined, 'the stopgap event was never filed');
    rx.client.emitEvent(CHANNEL, 'task_request', { description: 'STOLEN' }, { eventId: mine });
    await sleep(3000);
    const after = (await channelEvents()).find((e) => e.event_id === mine);
    await evidence('07-id-takeover', { before, after });
    expect(after !== undefined, 'the event disappeared entirely');
    if (!after) return;
    expectEq(after.actor_did, before?.actor_did, 'the actor on the stored event');
    expect(!JSON.stringify(after.payload || '').includes('STOLEN'),
      `the stolen payload reached the row: ${JSON.stringify(after.payload)}`);
    stopgapId = mine;
  });

await check('re-filing your own id with different content is refused',
  '3658ee9d 9ce71ef8', async () => {
    const before = (await channelEvents()).find((e) => e.event_id === stopgapId);
    tx.client.emitEvent(CHANNEL, 'task_request', { description: 'REWRITTEN' }, { eventId: stopgapId });
    await sleep(3000);
    const after = (await channelEvents()).find((e) => e.event_id === stopgapId);
    await evidence('08-refile', { before, after });
    expect(!JSON.stringify(after?.payload || '').includes('REWRITTEN'),
      `the rewrite reached the row: ${JSON.stringify(after?.payload)}`);
    const v = await verifyEvent(stopgapId);
    expectDeviceSigned(v, 'the event after a refused re-file');
  });

await check('signed sends reach the wire in the order they were called',
  'fece0725', async () => {
    const marks = [1, 2, 3].map((n) => `live-order-${STAMP}-${n}`);
    for (const m of marks) tx.client.sendMessage(CHANNEL, m);
    await sleep(4000);
    const h = await history(50);
    await evidence('09-ordering', h.json ?? { status: h.status, body: h.body });
    const seq = (h.json || []).map((m) => m.text).filter((t) => marks.includes(t));
    expectEq(JSON.stringify(seq), JSON.stringify(marks), 'the three sends in wire order');
  });

await check('a mutation sent through the generic TAGMSG helper is signed',
  '726650af', async () => {
    const mark = `live-mutation-${STAMP}`;
    const target = await tx.client.sendAndAwaitEcho(CHANNEL, mark);
    expect(typeof target === 'string' && target.length > 0, 'no msgid came back for the subject message');
    if (!target) return;
    // The generic door, not the named helper: this is the parity that was missing.
    tx.client.sendTagmsg(CHANNEL, { '+react': '🎯', '+reply': target });
    await sleep(3000);
    const v = await verifyEvent(target);
    await evidence('11-mutation', v ?? { error: 'subject never filed', target });
    expectDeviceSigned(v, 'the message a generic-helper reaction acted on');
  });

await check('media rides prefixed on the wire and is covered by the signature',
  '37602b0e 32d7751b 549cd667', async () => {
    msgSeen.length = 0;
    const url = `https://example.com/live-${STAMP}.png`;
    tx.client.sendMedia(CHANNEL, { url, mime: 'image/png', alt: 'live smoke' });
    await sleep(3000);
    const row = msgSeen.find((m) => m.tags && m.tags['+freeq.at/media-url'] === url);
    expect(row !== undefined,
      `no message carrying +freeq.at/media-url; saw ${JSON.stringify(msgSeen.map(m => m.tags))}`);
    if (!row) return;
    expectEq(row.tags['+freeq.at/media-mime'], 'image/png', 'the mime rides prefixed');
    expect(row.tags['media-url'] === undefined, 'a bare media-url is still on the wire');
    const v = await verifyEvent(row.id);
    await evidence('12-media', v ?? { error: 'never filed', id: row.id });
    expectDeviceSigned(v, 'media message');
    if (v) expect(String(v.canonical_form || '').includes(`"media-url":"${url}"`),
      `the attachment url should be covered, canonical was ${v.canonical_form}`);
  });

await check('a link preview rides prefixed and is covered by the signature',
  '37602b0e dda8b7a5 32d7751b 549cd667', async () => {
    msgSeen.length = 0;
    const url = `https://example.com/live-post-${STAMP}`;
    tx.client.sendLinkPreview(CHANNEL, { url, title: 'Live post', description: 'about things' });
    await sleep(3000);
    const row = msgSeen.find((m) => m.tags && m.tags['+freeq.at/link-url'] === url);
    expect(row !== undefined,
      `no message carrying +freeq.at/link-url; saw ${JSON.stringify(msgSeen.map(m => m.tags))}`);
    if (!row) return;
    expectEq(row.tags['+freeq.at/link-title'], 'Live post', 'the title rides prefixed');
    expect(row.tags['content-type'] === undefined, 'the old content-type discriminator is still on the wire');
    const v = await verifyEvent(row.id);
    await evidence('13-link-preview', v ?? { error: 'never filed', id: row.id });
    expectDeviceSigned(v, 'link preview message');
    if (v) expect(String(v.canonical_form || '').includes(`"link-url":"${url}"`),
      `the link url should be covered, canonical was ${v.canonical_form}`);
  });

// ── Report ─────────────────────────────────────────────────────────

await tx.stop();
await rx.stop();

const failed = results.filter((r) => !r.ok);
await evidence('00-summary', { wire: WS, rest: API, channel: CHANNEL, range: '295b90ae..549cd667', results });

console.log();
console.log(`${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log('\nFailed:');
  for (const f of failed) console.log(`  ✗ ${f.name}  [${f.covers}]`);
}
console.log(`\nEvidence: ${EVIDENCE}/`);
console.log('Not covered here, and why:');
console.log('  - a signed NOTICE: the server never stores one (persistence is gated on');
console.log('    PRIVMSG, messaging.rs), so there is no server record to verify against.');
console.log('    Its signature is pinned cryptographically on the wire by the SDK suite');
console.log('    and its routing by the freeqcc suite.');
console.log('  - the Rust SDK emitter: this driver is node. The Rust half is pinned by');
console.log('    coordination_events_rest_api against a real server in the Rust suite.');
console.log('  - an unverifiable-but-kept signature: needs a key this server cannot');
console.log('    resolve, so it needs a second server.');
console.log('  - whether a client renders an attachment: client-side, checked by hand.');
process.exit(failed.length ? 1 : 0);
