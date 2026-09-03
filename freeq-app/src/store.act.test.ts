/**
 * The store's task map: what a channel remembers about the work done in it.
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

const CH = '#work';
const OPENER = '01JOPENER00000000000000000';
const POSTER = 'did:plc:poster';
const WORKER = 'did:plc:worker';

beforeEach(() => {
  storage.clear();
  useStore.getState().reset();
  useStore.getState().addChannel(CH);
});

/** One task event as the bridge hands it over. */
function ev(overrides: Record<string, any> = {}) {
  return {
    from: 'poster',
    did: POSTER,
    kind: 'handoff',
    verb: 'offer',
    eventId: OPENER,
    taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release' },
    ...overrides,
  };
}

function move(verb: string, eventId: string, extra: Record<string, string> = {}, who = 'worker', did = WORKER) {
  return ev({
    from: who,
    did,
    verb,
    eventId,
    taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': verb, 'act-id': OPENER, ...extra },
  });
}

function tasks() {
  return useStore.getState().channels.get(CH)!.actTasks;
}

function msg(id: string, from: string, text: string, ref: string) {
  return { id, from, text, timestamp: new Date(), tags: { '+freeq.at/ref': ref } };
}

/** The id an event minted at that moment carries: a ULID, time first. */
function idAt(ms: number): string {
  const crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = crockford[ms % 32] + time;
    ms = Math.floor(ms / 32);
  }
  return time + 'ZZZZZZZZZZZZZZZZ';
}

/** A companion line as replay hands it back: the nick as it was sent, and
 *  the sender's DID under the server's `account` tag. */
function line(id: string, from: string, text: string, ref: string, did?: string, at?: number) {
  return {
    id,
    from,
    text,
    timestamp: new Date(at ?? Date.now()),
    tags: { '+freeq.at/ref': ref, ...(did ? { account: did } : {}) },
  };
}

describe('task map', () => {
  it('opens a task from an offer, keyed by the opener\'s own id', () => {
    useStore.getState().addActEvent(CH, ev());
    const task = tasks().get(OPENER)!;
    expect(task.taskId).toBe(OPENER);
    expect(task.events[0].eventId).toBe(OPENER);
    expect(task.kind).toBe('handoff');
    expect(task.title).toBe('ship the release');
    expect(task.offerer).toBe(POSTER);
    expect(task.verb).toBe('offer');
  });

  it('takes the assignee from a directed offer', () => {
    useStore.getState().addActEvent(CH, ev({
      fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 't', 'act-to': WORKER },
    }));
    expect(tasks().get(OPENER)!.assignee).toBe(WORKER);
  });

  it('carries the latest verb and appends every move to the event list', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addActEvent(CH, move('claim', 'e2'));
    s.addActEvent(CH, move('progress', 'e3', { 'act-note': 'tagged the build' }));
    s.addActEvent(CH, move('complete', 'e4'));

    const task = tasks().get(OPENER)!;
    expect(task.verb).toBe('complete');
    expect(task.assignee).toBe(WORKER);
    expect(task.note).toBe('tagged the build');
    expect(task.events.map((e) => e.verb)).toEqual(['offer', 'claim', 'progress', 'complete']);
  });

  it('collects each context link with the hash its signature covers', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addActEvent(CH, move('progress', 'e2', {
      'act-ctx': 'https://example.com/checks/abc',
      'act-ctx-h': 'sha256:9f00',
    }));
    s.addActEvent(CH, move('complete', 'e3', { 'act-ctx': 'https://example.com/article' }));

    expect(tasks().get(OPENER)!.ctx).toEqual([
      { url: 'https://example.com/checks/abc', hash: 'sha256:9f00' },
      { url: 'https://example.com/article', hash: undefined },
    ]);
  });

  it('resolves an award to the bidder whose bid it names', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev({ kind: 'bounty' }));
    s.addActEvent(CH, move('bid', 'bid-worker', {}, 'worker', WORKER));
    s.addActEvent(CH, move('bid', 'bid-rival', {}, 'rival', 'did:plc:rival'));
    s.addActEvent(CH, move('award', 'e4', { 'act-accepts': 'bid-rival' }, 'poster', POSTER));

    expect(tasks().get(OPENER)!.assignee).toBe('did:plc:rival');
  });

  it('changes nothing when an event is replayed', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addActEvent(CH, move('claim', 'e2'));
    const before = tasks().get(OPENER)!;

    s.addActEvent(CH, ev());
    s.addActEvent(CH, move('claim', 'e2'));

    expect(tasks().get(OPENER)).toBe(before);
    expect(before.events).toHaveLength(2);
  });
});

describe('companion lines', () => {
  it('joins each event to the line its sender wrote beside it', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addMessage(CH, msg('m1', 'poster', 'offered: ship the release', OPENER) as any);
    s.addActEvent(CH, move('claim', 'e2'));
    s.addMessage(CH, msg('m2', 'worker', 'claimed the task', OPENER) as any);

    expect(tasks().get(OPENER)!.events.map((e) => e.msgId)).toEqual(['m1', 'm2']);
  });

  it('joins them when the line arrives before the event', () => {
    const s = useStore.getState();
    s.addMessage(CH, msg('m1', 'poster', 'offered: ship the release', OPENER) as any);
    s.addActEvent(CH, ev());

    expect(tasks().get(OPENER)!.events[0].msgId).toBe('m1');
  });

  it('joins a line that comes back through history to an event already filed', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.mergeHistory(CH, [msg('m1', 'poster', 'offered: ship the release', OPENER) as any]);

    expect(tasks().get(OPENER)!.events[0].msgId).toBe('m1');
  });

  it('joins a line that lands with a batch', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.startBatch('b1', 'chathistory', CH);
    s.addBatchMessage('b1', msg('m1', 'poster', 'offered: ship the release', OPENER) as any);
    s.endBatch('b1');

    expect(tasks().get(OPENER)!.events[0].msgId).toBe('m1');
  });

  it('joins them by DID when the two sides spell the nick differently', () => {
    // Replay hands the event back under the lowercased nick the server holds
    // and the line under the nick as it was sent.
    const s = useStore.getState();
    s.addActEvent(CH, ev({ from: 'taskbot', did: POSTER }));
    s.mergeHistory(CH, [line('m1', 'TaskBot', 'offered: ship the release', OPENER, POSTER) as any]);

    expect(tasks().get(OPENER)!.events[0].msgId).toBe('m1');
  });

  it('joins them by nick, case aside, when neither side carries a DID', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev({ from: 'taskbot', did: undefined }));
    s.mergeHistory(CH, [line('m1', 'TaskBot', 'offered: ship the release', OPENER) as any]);

    expect(tasks().get(OPENER)!.events[0].msgId).toBe('m1');
  });

  it('leaves an event unpaired when its own line fell outside the window', () => {
    // The lines and the task events replay as two windows that truncate
    // independently: here the offer's line fell outside its window.
    const s = useStore.getState();
    const t0 = Date.UTC(2026, 7, 23, 12, 0, 0);
    const at = [t0, t0 + 60_000, t0 + 120_000, t0 + 180_000];
    const ids = at.map(idAt);
    const st = useStore.getState();
    st.addActEvent(CH, ev({ from: 'worker', did: WORKER, eventId: ids[0], taskId: ids[0] }));
    for (const [i, verb] of ['claim', 'progress', 'complete'].entries()) {
      st.addActEvent(CH, ev({
        from: 'worker',
        did: WORKER,
        verb,
        eventId: ids[i + 1],
        taskId: ids[0],
        fields: { act: 'handoff', 'act-verb': verb, 'act-id': ids[0] },
      }));
    }
    s.mergeHistory(CH, ['claim', 'progress', 'complete'].map((verb, i) =>
      line(`m-${verb}`, 'worker', `${verb} line`, ids[0], WORKER, at[i + 1]) as any,
    ));

    expect(tasks().get(ids[0])!.events.map((e) => e.msgId)).toEqual([
      undefined, 'm-claim', 'm-progress', 'm-complete',
    ]);
  });

  it('leaves an event with no companion unpaired', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addMessage(CH, msg('m1', 'poster', 'offered: ship the release', OPENER) as any);
    // The home signs `confirm` itself and writes no line beside it.
    s.addActEvent(CH, move('confirm', 'e2', {}, 'acceptance', undefined as any));

    const events = tasks().get(OPENER)!.events;
    expect(events[0].msgId).toBe('m1');
    expect(events[1].msgId).toBeUndefined();
  });

  it('keeps a pairing when the same line is replayed', () => {
    const s = useStore.getState();
    s.addActEvent(CH, ev());
    s.addMessage(CH, msg('m1', 'poster', 'offered: ship the release', OPENER) as any);
    s.addActEvent(CH, move('progress', 'e2', {}, 'poster', POSTER));
    s.addMessage(CH, msg('m1', 'poster', 'offered: ship the release', OPENER) as any);

    const events = tasks().get(OPENER)!.events;
    expect(events[0].msgId).toBe('m1');
    expect(events[1].msgId).toBeUndefined();
  });
});

describe('the events that write no line of their own', () => {
  it('tells the room what the home confirmed', () => {
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('claim', 'e2'));
    st.addActEvent(CH, move('confirm', 'e3', { 'act-subject': 'e2' }, 'acceptance'));

    const lines = useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem);
    expect(lines.map((m) => m.text)).toEqual([
      '✔️ confirmed: "ship the release" — claim by worker',
    ]);
  });

  it('says nothing about a move it does not hold', () => {
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('confirm', 'e3', { 'act-subject': 'e2' }, 'acceptance'));

    expect(useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem)).toHaveLength(0);
  });

  it('says nothing about a task whose opener it never held', () => {
    // The events replay in a window of their own, so a task's later moves
    // arrive without the opener that carries its title.
    const st = useStore.getState();
    st.addActEvent(CH, move('expire', 'e2', {}, 'acceptance'));

    expect(useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem)).toHaveLength(0);
  });

  it('tells the room when a task expired', () => {
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('expire', 'e2', {}, 'acceptance'));

    const lines = useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem);
    expect(lines.map((m) => m.text)).toEqual(['⌛ ship the release expired']);
  });

  it('says when the home moved, not when the line reached us', () => {
    // A receipt handed back on join is old news: it carries its own time in
    // the id it was minted under.
    const at = Date.UTC(2026, 7, 22, 9, 15, 0);
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('expire', idAt(at), {}, 'acceptance'));

    const line = useStore.getState().channels.get(CH)!.messages.find((m) => m.isSystem)!;
    expect(line.timestamp.getTime()).toBe(at);
  });

  it('puts a replayed move among the lines it belongs between', () => {
    const at = Date.UTC(2026, 7, 22, 9, 15, 0);
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addMessage(CH, { ...msg('m-later', 'poster', 'said later', OPENER), timestamp: new Date(at + 60_000) } as any);
    st.addActEvent(CH, move('expire', idAt(at), {}, 'acceptance'));

    const rows = useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem || m.id === 'm-later');
    expect(rows.map((m) => m.id)).toEqual([idAt(at), 'm-later']);
  });

  it('says it once when the event is replayed', () => {
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('expire', 'e2', {}, 'acceptance'));
    st.addActEvent(CH, move('expire', 'e2', {}, 'acceptance'));

    expect(useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem)).toHaveLength(1);
  });

  it('leaves every other verb to its card', () => {
    const st = useStore.getState();
    st.addActEvent(CH, ev());
    st.addActEvent(CH, move('progress', 'e2', { 'act-note': 'tagged the build' }));

    expect(useStore.getState().channels.get(CH)!.messages.filter((m) => m.isSystem)).toHaveLength(0);
  });
});
