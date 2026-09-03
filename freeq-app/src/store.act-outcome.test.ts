/**
 * What the reader ends up looking at, from the store layers that actually
 * run: the replay batch, act event recording, and pairing. The per-layer
 * tests each pass on their own and still let a wrong transcript through —
 * the offer and accept cards landed on each other's lines — so this is the
 * order's regression net and they are not.
 *
 * The fixture is the live channel's shape. The offer and its accept are
 * minted 195ms apart inside one second; each companion line goes out a few ms
 * into the NEXT second and replays under that second's `.000` stamp. The
 * later event is then nearer to both lines (37ms against 232ms), which is
 * what let the accept take the offer's line.
 *
 * There is no local message cache on web — the Apple clients have one and it
 * is the layer that decides the same two rows there.
 */
import { describe, it, expect, beforeEach } from 'vitest';

const storage = new Map<string, string>();
// @ts-expect-error mock
globalThis.localStorage = {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => storage.set(k, v),
  removeItem: (k: string) => { storage.delete(k); },
  clear: () => storage.clear(),
  get length() { return storage.size; },
  key: (i: number) => [...storage.keys()][i] ?? null,
};
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});
// @ts-expect-error mock
globalThis.window = { localStorage: globalThis.localStorage, location: { hash: '' }, addEventListener: () => {} };

const { useStore } = await import('./store');

const CH = '#actrepoint';
const WORKER = 'did:key:z6MkWorker';
const HOME = 'did:web:irc.zerosum.org';
const SECOND = 1_756_760_000_000;

function ulid(ms: number, tail: string): string {
  const crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let time = '';
  let left = ms;
  for (let i = 0; i < 10; i++) {
    time = crockford[left % 32] + time;
    left = Math.floor(left / 32);
  }
  return time + tail;
}

const OFFER_EVENT = ulid(SECOND + 768, 'ZZZZZZZZZZZZZZZZ');
const ACCEPT_EVENT = ulid(SECOND + 963, 'ZZZZZZZZZZZZZZZZ');
const CONFIRM_EVENT = ulid(SECOND + 3_000, 'ZZZZZZZZZZZZZZZZ');
const OFFER_LINE = ulid(SECOND + 1_002, 'AAAAAAAAAAAAAAAA');
const ACCEPT_LINE = ulid(SECOND + 1_005, 'BBBBBBBBBBBBBBBB');

/** Both companion lines replay under the truncated stamp of the second they
 *  were sent in — the same value for both. */
const REPLAY_STAMP = new Date(SECOND + 1_000);

function companion(id: string, text: string) {
  return {
    id, from: 'worker', text, timestamp: REPLAY_STAMP,
    tags: { '+freeq.at/ref': OFFER_EVENT, account: WORKER },
  };
}

function retired(id: string, eventType: string, text: string) {
  return {
    id, from: 'oldbot', text, timestamp: new Date(SECOND + 2_000),
    tags: { '+freeq.at/event': eventType, '+freeq.at/task-id': 'TASK001' },
  };
}

const OFFER = {
  from: 'worker', did: WORKER, kind: 'handoff', verb: 'offer',
  eventId: OFFER_EVENT, taskId: OFFER_EVENT,
  fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release', 'act-to': WORKER },
};
const ACCEPT = {
  from: 'worker', did: WORKER, kind: 'handoff', verb: 'accept',
  eventId: ACCEPT_EVENT, taskId: OFFER_EVENT,
  fields: { act: 'handoff', 'act-verb': 'accept', 'act-id': OFFER_EVENT },
};
const CONFIRM = {
  from: 'irc.zerosum.org', did: HOME, kind: 'handoff', verb: 'confirm',
  eventId: CONFIRM_EVENT, taskId: OFFER_EVENT,
  fields: { act: 'handoff', 'act-verb': 'confirm', 'act-id': OFFER_EVENT, 'act-subject': ACCEPT_EVENT },
};

beforeEach(() => {
  storage.clear();
  useStore.getState().reset();
  useStore.getState().addChannel(CH);
});

/** The verb of the card each line draws, by that line's id. */
function cardVerbs(): Map<string, string> {
  const ch = useStore.getState().channels.get(CH)!;
  const byLine = new Map<string, string>();
  for (const task of ch.actTasks.values()) {
    for (const ev of task.events) if (ev.msgId) byLine.set(ev.msgId, ev.verb);
  }
  return byLine;
}

/** The transcript as the reader sees it, row by row. */
function transcript(): string[] {
  const ch = useStore.getState().channels.get(CH)!;
  const cards = cardVerbs();
  return ch.messages.map((m) => {
    const verb = cards.get(m.id);
    if (verb) return `card:${verb}`;
    // The same decision the row makes: every event-tagged message cards.
    const eventType = m.tags?.['+freeq.at/event'];
    if (eventType) return `card:${eventType}`;
    if (!m.from) return 'system';
    return 'text';
  });
}

function record() {
  const s = useStore.getState();
  s.addActEvent(CH, OFFER);
  s.addActEvent(CH, ACCEPT);
  // The store writes the confirm's system line itself, dated off the event.
  s.addActEvent(CH, CONFIRM);
}

function deliver() {
  const s = useStore.getState();
  s.startBatch('b1', 'chathistory', CH);
  // Deliberately out of wire order.
  for (const m of [
    retired(ulid(SECOND + 2_000, 'DDDDDDDDDDDDDDDD'), 'task_request', '📋 New task: something the old family sent'),
    companion(ACCEPT_LINE, 'accepted: ship the release'),
    retired(ulid(SECOND + 2_100, 'EEEEEEEEEEEEEEEE'), 'task_complete', '✅ Task complete: something the old family sent'),
    companion(OFFER_LINE, 'offered: ship the release'),
  ]) s.addBatchMessage('b1', m);
  s.endBatch('b1');
}

describe('the transcript the reader ends up with', () => {
  for (const eventsFirst of [true, false]) {
    it(`reads the same with eventsFirst=${eventsFirst}`, () => {
      if (eventsFirst) { record(); deliver(); } else { deliver(); record(); }
      expect(transcript()).toEqual([
        'card:offer', 'card:accept', 'card:task_request', 'card:task_complete', 'system',
      ]);
    });

    it(`puts each card on its own sender's line with eventsFirst=${eventsFirst}`, () => {
      if (eventsFirst) { record(); deliver(); } else { deliver(); record(); }
      const cards = cardVerbs();
      expect(cards.get(OFFER_LINE)).toBe('offer');
      expect(cards.get(ACCEPT_LINE)).toBe('accept');
    });
  }
});
