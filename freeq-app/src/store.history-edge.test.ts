/**
 * What the store knows about the top of a channel's loaded history.
 *
 * A reader paging back needs to be told when they have reached the start of
 * the channel rather than just the top of what is loaded. The answer comes
 * from the size of the page the server sent — a short page means there was
 * nothing more to send — and that count has to be the one off the wire: a
 * page overlapping rows already held dedups down to nothing while more
 * history still sits behind it.
 */
import { describe, it, expect, beforeEach } from 'vitest';

// Mock globals before import (store.ts reads persisted prefs at module scope)
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
type Message = Parameters<ReturnType<typeof useStore.getState>['addMessage']>[1];

const s = () => useStore.getState();
const ch = (name: string) => s().channels.get(name.toLowerCase())!;

const PAGE = 50;

beforeEach(() => {
  storage.clear();
  s().reset();
});

/** A page of `n` rows, ids and timestamps ordered from `base`. */
function page(n: number, base: number): Message[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `row-${String(base + i).padStart(5, '0')}`,
    from: 'alice',
    text: `row ${base + i}`,
    timestamp: new Date(1_700_000_000_000 + (base + i) * 1000),
    tags: {},
  }));
}

describe('the history edge', () => {
  it('is unknown until the first answer', () => {
    s().addMessage('#edge', page(1, 500)[0]);
    expect(ch('#edge').historyEdge).toBe('unknown');
    expect(ch('#edge').historyFetching).toBe(false);
  });

  it('is unknown on a channel that has only ever been asked', () => {
    s().historyFetchStarted('#armed');
    expect(ch('#armed').historyEdge).toBe('unknown');
    expect(ch('#armed').historyFetching).toBe(true);
  });

  it('goes unknown → more on a full page', () => {
    s().addMessage('#full', page(1, 500)[0]);
    s().historyFetchStarted('#full');
    s().mergeHistory('#full', page(PAGE, 100));
    s().historyPageReceived('#full', PAGE, PAGE);

    expect(ch('#full').historyEdge).toBe('more');
    expect(ch('#full').historyFetching).toBe(false);
  });

  it('goes more → start on a short page', () => {
    s().addMessage('#short', page(1, 500)[0]);
    s().historyFetchStarted('#short');
    s().historyPageReceived('#short', PAGE, PAGE);
    expect(ch('#short').historyEdge).toBe('more');

    s().historyFetchStarted('#short');
    s().mergeHistory('#short', page(12, 50));
    s().historyPageReceived('#short', 12, PAGE);

    expect(ch('#short').historyEdge).toBe('start');
    expect(ch('#short').historyFetching).toBe(false);
  });

  it('marks the start on an empty page', () => {
    s().addMessage('#empty', page(1, 500)[0]);
    s().historyFetchStarted('#empty');
    s().historyPageReceived('#empty', 0, PAGE);

    expect(ch('#empty').historyEdge).toBe('start');
  });

  it('does not mark the start when a full page dedups to nothing', () => {
    // The overlap case: every row in the answer is already held, so the
    // store gains nothing — but the server sent a full page, which means
    // there is more behind it.
    const overlap = page(PAGE, 200);
    s().mergeHistory('#overlap', overlap);
    const before = ch('#overlap').messages.length;

    s().historyFetchStarted('#overlap');
    s().mergeHistory('#overlap', overlap);
    s().historyPageReceived('#overlap', PAGE, PAGE);

    expect(ch('#overlap').messages.length).toBe(before);
    expect(ch('#overlap').historyEdge).toBe('more');
  });

  it('leaves the edge alone for history that arrives with no fetch in flight', () => {
    // A channel switch asks for LATEST, and its answer is usually shorter
    // than a page. That is not an answer about the start of the channel.
    s().mergeHistory('#latest', page(8, 0));
    s().historyPageReceived('#latest', 8, PAGE);

    expect(ch('#latest').historyEdge).toBe('unknown');
  });

  it('does not re-arm a fetch that is already in flight', () => {
    s().addMessage('#once', page(1, 500)[0]);
    s().historyFetchStarted('#once');
    const armed = ch('#once');
    s().historyFetchStarted('#once');

    expect(ch('#once')).toBe(armed);
  });

  it('clears the in-flight flag when a fetch goes unanswered, leaving the edge', () => {
    s().addMessage('#lost', page(1, 500)[0]);
    s().historyFetchStarted('#lost');
    s().historyPageReceived('#lost', PAGE, PAGE);
    s().historyFetchStarted('#lost');
    s().historyFetchFailed('#lost');

    expect(ch('#lost').historyFetching).toBe(false);
    expect(ch('#lost').historyEdge).toBe('more');
  });

  it('holds the automatic fetch off when a page goes unanswered', () => {
    s().addMessage('#held', page(1, 500)[0]);
    expect(ch('#held').historyAutoPaused).toBe(false);

    s().historyFetchStarted('#held');
    s().historyFetchFailed('#held');

    expect(ch('#held').historyAutoPaused).toBe(true);
  });

  it('starts the automatic fetch again on request', () => {
    s().addMessage('#again', page(1, 500)[0]);
    s().historyFetchStarted('#again');
    s().historyFetchFailed('#again');

    s().historyAutoResumed('#again');

    expect(ch('#again').historyAutoPaused).toBe(false);
  });

  it('leaves a channel alone when nothing was held off', () => {
    s().addMessage('#noop', page(1, 500)[0]);
    const before = ch('#noop');

    s().historyAutoResumed('#noop');

    expect(ch('#noop')).toBe(before);
  });

  it('does not hold off a page that arrived', () => {
    s().addMessage('#fine', page(1, 500)[0]);
    s().historyFetchStarted('#fine');
    s().historyPageReceived('#fine', PAGE, PAGE);

    expect(ch('#fine').historyAutoPaused).toBe(false);
  });

  it('keeps the edge per channel', () => {
    s().historyFetchStarted('#a');
    s().historyPageReceived('#a', 3, PAGE);
    s().historyFetchStarted('#b');
    s().historyPageReceived('#b', PAGE, PAGE);

    expect(ch('#a').historyEdge).toBe('start');
    expect(ch('#b').historyEdge).toBe('more');
  });

  it('keys the channel case-insensitively', () => {
    s().historyFetchStarted('#Mixed');
    s().historyPageReceived('#mIXED', 2, PAGE);

    expect(ch('#mixed').historyEdge).toBe('start');
    expect(ch('#mixed').historyFetching).toBe(false);
  });
});
