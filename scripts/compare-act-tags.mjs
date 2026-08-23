/**
 * Check that both SDKs spell a task event the same way.
 *
 * A task event's signature covers its act tags exactly as they were written,
 * so two SDKs are interchangeable only if they write the same ones. This runs
 * one list of cases — a kind, a verb, the action it names, the actor and its
 * fields — through `actTags` and `actLine` in `@freeq/sdk` and through
 * `act_tags` and `act_line` in `freeq-sdk`, and compares the two tag maps key
 * by key. The line people read is compared too: it is what a room sees of the
 * event, and it is the one place a verb is spelled out at all.
 *
 * Neither side signs or connects. What is compared is the covered half of the
 * document, before an id or a venue is attached to it.
 *
 * Usage:
 *   freeq-bot-kit-js/node_modules/.bin/tsx scripts/compare-act-tags.mjs
 *
 * It runs under `tsx` because it imports the TypeScript builders from source —
 * what a bot compiles against, rather than whatever `dist` was last built from.
 *
 * Env:
 *   CARGO   path to cargo (default ~/.cargo/bin/cargo)
 *
 * Exit code 0 only if every case agrees.
 */

import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { actLine, actTags } from '../freeq-sdk-js/src/signing.ts';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * One case per arm `actLine` has a sentence for, so a disagreement about any
 * of them fails here rather than in two unit suites that assert the same
 * literal separately. Plus the shapes worth pinning: an opener carrying
 * everything one can, an open one carrying almost nothing, a bounty opener, a
 * re-offer, a step carrying context and its hash, and a kind neither SDK has
 * ever heard of.
 */
const CASES = [
  {
    name: 'directed-offer',
    kind: 'handoff',
    verb: 'offer',
    from: 'did:plc:eliza',
    fields: {
      title: 'Cite 3 sources on X',
      to: 'did:plc:scholar',
      caps: 'freeq.at/web-search',
      deadline: '1788000000',
      ctx: 'https://example.com/brief',
      'ctx-h': 'sha256:9f00',
    },
  },
  {
    name: 'open-offer',
    kind: 'handoff',
    verb: 'offer',
    from: 'did:plc:eliza',
    fields: { title: "Summarize today's S2S logs", caps: 'freeq.at/log-analysis' },
  },
  {
    name: 'bounty-offer',
    kind: 'bounty',
    verb: 'offer',
    from: 'did:plc:eliza',
    fields: {
      title: 'Port the call grid to web',
      price: '250 USD',
      deadline: '1788000000',
      'bid-deadline': '1787000000',
    },
  },
  {
    name: 're-offer',
    kind: 'handoff',
    verb: 'offer',
    from: 'did:plc:eliza',
    fields: { title: 'Cite 3 sources on X', replaces: '01JABCDEF000000000000000EF' },
  },
  {
    name: 'accept',
    kind: 'handoff',
    verb: 'accept',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: { note: 'on it' },
  },
  {
    name: 'accept-bare',
    kind: 'handoff',
    verb: 'accept',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: {},
  },
  {
    name: 'decline',
    kind: 'handoff',
    verb: 'decline',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: { note: 'no capacity today' },
  },
  {
    name: 'claim',
    kind: 'handoff',
    verb: 'claim',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: {},
  },
  {
    name: 'progress',
    kind: 'handoff',
    verb: 'progress',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: { note: 'two of three sources read' },
  },
  {
    name: 'progress-bare',
    kind: 'handoff',
    verb: 'progress',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: {},
  },
  {
    name: 'complete',
    kind: 'handoff',
    verb: 'complete',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: { note: 'filed', ctx: 'https://example.com/result', 'ctx-h': 'sha256:9f86d' },
  },
  {
    name: 'fail',
    kind: 'handoff',
    verb: 'fail',
    task: '01JTASK00000000000000000AA',
    from: 'did:plc:scholar',
    fields: { note: 'the source is paywalled' },
  },
  {
    name: 'cancel-on-a-bounty',
    kind: 'bounty',
    verb: 'cancel',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:eliza',
    fields: { note: 'no longer needed' },
  },
  {
    name: 'bid',
    kind: 'bounty',
    verb: 'bid',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:scholar',
    fields: { note: 'two days, sources included', bid: '250 USD', 'pay-to': 'did:plc:scholar' },
  },
  {
    name: 'bid-bare',
    kind: 'bounty',
    verb: 'bid',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:scholar',
    fields: {},
  },
  {
    name: 'award',
    kind: 'bounty',
    verb: 'award',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:eliza',
    fields: { accepts: '01JBIDEVENTID00000000000B' },
  },
  {
    name: 'submit',
    kind: 'bounty',
    verb: 'submit',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:scholar',
    fields: { note: 'branch pushed' },
  },
  {
    name: 'revise',
    kind: 'bounty',
    verb: 'revise',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:eliza',
    fields: { note: 'tests missing' },
  },
  {
    name: 'forfeit',
    kind: 'bounty',
    verb: 'forfeit',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:scholar',
    fields: { note: 'out of time' },
  },
  {
    name: 'accept-work',
    kind: 'bounty',
    verb: 'accept-work',
    task: '01JBOUNTY000000000000000BB',
    from: 'did:plc:eliza',
    fields: { tx: 'lightning:abc123' },
  },
  {
    name: 'a-kind-neither-has-heard-of',
    kind: 'lease',
    verb: 'renew',
    task: '01JLEASE0000000000000000LL',
    from: 'did:plc:eliza',
    fields: { term: '30d' },
  },
];

function typescriptAnswers() {
  const answers = {};
  for (const c of CASES) {
    const fields = Object.fromEntries(Object.entries(c.fields).sort());
    answers[c.name] = {
      tags: actTags(c.kind, c.verb, c.task, c.from, fields),
      line: actLine(c.kind, c.verb, fields),
    };
  }
  return answers;
}

function rustAnswers() {
  const cargo = process.env.CARGO ?? join(homedir(), '.cargo', 'bin', 'cargo');
  const run = spawnSync(cargo, ['run', '-q', '-p', 'freeq-sdk', '--example', 'act_tags_dump'], {
    cwd: repo,
    input: JSON.stringify(CASES),
    encoding: 'utf8',
    maxBuffer: 1 << 24,
  });
  if (run.status !== 0) {
    console.error(run.stderr || run.error);
    throw new Error(`the Rust builders did not run (exit ${run.status})`);
  }
  return JSON.parse(run.stdout);
}

const ts = typescriptAnswers();
const rs = rustAnswers();

let disagreements = 0;
for (const c of CASES) {
  const a = ts[c.name];
  const b = rs[c.name];
  const names = [...new Set([...Object.keys(a.tags), ...Object.keys(b?.tags ?? {})])].sort();
  const differing = names.filter((n) => a.tags[n] !== b?.tags?.[n]);
  const lineDiffers = a.line !== b?.line;
  if (differing.length === 0 && !lineDiffers) {
    console.log(`✓ ${c.name.padEnd(28)} ${a.line}`);
    continue;
  }
  disagreements += 1;
  console.log(`✗ ${c.name}`);
  for (const n of differing) {
    console.log(`    ${n}: ts=${JSON.stringify(a.tags[n])} rust=${JSON.stringify(b?.tags?.[n])}`);
  }
  if (lineDiffers) {
    console.log(`    line: ts=${JSON.stringify(a.line)} rust=${JSON.stringify(b?.line)}`);
  }
}

console.log();
if (disagreements === 0) {
  console.log(`${CASES.length} cases, both SDKs agree`);
  process.exit(0);
}
console.log(`${disagreements} of ${CASES.length} cases disagree`);
process.exit(1);
