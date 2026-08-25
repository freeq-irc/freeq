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

const storeModule = await import('./store');
const { useStore } = storeModule;
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
    s().historyFetchStarted('#armed', true);
    expect(ch('#armed').historyEdge).toBe('unknown');
    expect(ch('#armed').historyFetching).toBe(true);
  });

  it('goes unknown → more on a full page', () => {
    s().addMessage('#full', page(1, 500)[0]);
    s().historyFetchStarted('#full', true);
    s().mergeHistory('#full', page(PAGE, 100));
    s().historyPageReceived('#full', PAGE, PAGE, PAGE);

    expect(ch('#full').historyEdge).toBe('more');
    expect(ch('#full').historyFetching).toBe(false);
  });

  it('goes more → start on a short page', () => {
    s().addMessage('#short', page(1, 500)[0]);
    s().historyFetchStarted('#short', true);
    s().historyPageReceived('#short', PAGE, PAGE, PAGE);
    expect(ch('#short').historyEdge).toBe('more');

    s().historyFetchStarted('#short', true);
    s().mergeHistory('#short', page(12, 50));
    s().historyPageReceived('#short', 12, PAGE, 12);

    expect(ch('#short').historyEdge).toBe('start');
    expect(ch('#short').historyFetching).toBe(false);
  });

  it('marks the start on an empty page', () => {
    s().addMessage('#empty', page(1, 500)[0]);
    s().historyFetchStarted('#empty', true);
    s().historyPageReceived('#empty', 0, PAGE, 0);

    expect(ch('#empty').historyEdge).toBe('start');
  });

  it('does not mark the start when a full page dedups to nothing', () => {
    // The overlap case: every row in the answer is already held, so the
    // store gains nothing — but the server sent a full page, which means
    // there is more behind it.
    const overlap = page(PAGE, 200);
    s().mergeHistory('#overlap', overlap);
    const before = ch('#overlap').messages.length;

    s().historyFetchStarted('#overlap', true);
    s().mergeHistory('#overlap', overlap);
    s().historyPageReceived('#overlap', PAGE, PAGE, 0);

    expect(ch('#overlap').messages.length).toBe(before);
    expect(ch('#overlap').historyEdge).toBe('more');
  });

  it('leaves the edge alone for history that arrives with no fetch in flight', () => {
    // A channel switch asks for LATEST, and its answer is usually shorter
    // than a page. That is not an answer about the start of the channel.
    s().mergeHistory('#latest', page(8, 0));
    s().historyPageReceived('#latest', 8, PAGE, 8);

    expect(ch('#latest').historyEdge).toBe('unknown');
  });

  it('does not re-arm a fetch that is already in flight', () => {
    s().addMessage('#once', page(1, 500)[0]);
    s().historyFetchStarted('#once', true);
    const armed = ch('#once');
    s().historyFetchStarted('#once', true);

    expect(ch('#once')).toBe(armed);
  });

  it('clears the in-flight flag when a fetch goes unanswered, leaving the edge', () => {
    s().addMessage('#lost', page(1, 500)[0]);
    s().historyFetchStarted('#lost', true);
    s().historyPageReceived('#lost', PAGE, PAGE, PAGE);
    s().historyFetchStarted('#lost', true);
    s().historyFetchFailed('#lost');

    expect(ch('#lost').historyFetching).toBe(false);
    expect(ch('#lost').historyEdge).toBe('more');
  });

  it('holds the automatic fetch off when a page goes unanswered', () => {
    s().addMessage('#held', page(1, 500)[0]);
    expect(ch('#held').historyAutoPaused).toBe(false);

    s().historyFetchStarted('#held', true);
    s().historyFetchFailed('#held');

    expect(ch('#held').historyAutoPaused).toBe(true);
  });

  it('starts the automatic fetch again on request', () => {
    s().addMessage('#again', page(1, 500)[0]);
    s().historyFetchStarted('#again', true);
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
    s().historyFetchStarted('#fine', true);
    s().historyPageReceived('#fine', PAGE, PAGE, PAGE);

    expect(ch('#fine').historyAutoPaused).toBe(false);
  });

  /** A channel grown past the resting window the only way it can be: live
   *  rows to the cap, then older pages merged on top by scrolling back. */
  function grownPastTheWindow(name: string) {
    const { MESSAGE_WINDOW } = storeModule;
    for (const m of page(MESSAGE_WINDOW, 5_000)) s().addMessage(name, m);
    s().mergeHistory(name, page(200, 4_000));
    return MESSAGE_WINDOW;
  }

  it('says there is more again after the window is trimmed', () => {
    // The trim discards the oldest rows, so history above the oldest held
    // row exists by construction — whatever the edge said a moment ago.
    const WINDOW = grownPastTheWindow('#trim');
    s().historyFetchStarted('#trim', true);
    s().historyPageReceived('#trim', 2, PAGE, 2);
    expect(ch('#trim').historyEdge).toBe('start');
    expect(ch('#trim').messages.length).toBeGreaterThan(WINDOW);

    s().trimMessageWindow('#trim');

    expect(ch('#trim').messages.length).toBe(WINDOW);
    expect(ch('#trim').historyEdge).toBe('more');
  });

  it('starts the automatic fetch again after the window is trimmed', () => {
    grownPastTheWindow('#trimpause');
    s().historyFetchStarted('#trimpause', true);
    s().historyFetchFailed('#trimpause');
    expect(ch('#trimpause').historyAutoPaused).toBe(true);

    s().trimMessageWindow('#trimpause');

    expect(ch('#trimpause').historyAutoPaused).toBe(false);
  });

  it('leaves the edge alone when there is nothing to trim', () => {
    s().addMessage('#small', page(1, 500)[0]);
    s().historyFetchStarted('#small', true);
    s().historyPageReceived('#small', 2, PAGE, 2);
    const before = ch('#small');

    s().trimMessageWindow('#small');

    expect(ch('#small')).toBe(before);
    expect(ch('#small').historyEdge).toBe('start');
  });

  it('stops the automatic fetching when a fetched page adds no rows', () => {
    // The absolute cap, reached: a channel holding MESSAGE_WINDOW_MAX rows
    // keeps the newest ones, so an older page merges and is discarded whole.
    // Nothing about the answer says "stop" — it is a full page, so the edge
    // reads `more` — and the auto-fetch would ask for the same page forever.
    const { MESSAGE_WINDOW_MAX } = storeModule;
    for (const msg of page(MESSAGE_WINDOW_MAX, 100_000)) s().addMessage('#cap', msg);
    s().mergeHistory('#cap', page(MESSAGE_WINDOW_MAX, 100_000));
    expect(ch('#cap').messages.length).toBe(MESSAGE_WINDOW_MAX);

    const heldBefore = ch('#cap').messages.length;
    const oldestBefore = ch('#cap').messages[0].id;
    s().historyFetchStarted('#cap', true);
    s().mergeHistory('#cap', page(PAGE, 1_000)); // older than everything held
    const added = ch('#cap').messages.length - heldBefore;

    expect(added, 'the cap discarded the whole page').toBe(0);
    expect(ch('#cap').messages[0].id, 'the held list did not move').toBe(oldestBefore);

    s().historyPageReceived('#cap', PAGE, PAGE, added);

    expect(ch('#cap').historyEdge, 'a full page still means more exists').toBe('more');
    expect(ch('#cap').historyAutoPaused, 'but asking again would repeat it forever').toBe(true);
  });

  it('does not stop on an opening page that only repeats what is held', () => {
    // The request a channel opens with is not anchored on anything and its
    // answer is expected to repeat rows already held — that is what makes it
    // safe to send. Reading that as "asking again gets nowhere" would stop
    // the reader before their first scroll.
    for (const msg of page(20, 900)) s().addMessage('#opening', msg);
    const heldBefore = ch('#opening').messages.length;

    s().historyFetchStarted('#opening', false);
    s().mergeHistory('#opening', page(20, 900)); // every row a duplicate
    const added = ch('#opening').messages.length - heldBefore;
    expect(added).toBe(0);

    s().historyPageReceived('#opening', 20, PAGE, added);

    expect(ch('#opening').historyAutoPaused).toBe(false);
    expect(ch('#opening').historyEdge, 'a short page still means the start').toBe('start');
  });

  it('keeps fetching when a page does add rows', () => {
    s().addMessage('#adds', page(1, 500)[0]);
    s().historyFetchStarted('#adds', true);
    s().mergeHistory('#adds', page(PAGE, 100));
    s().historyPageReceived('#adds', PAGE, PAGE, PAGE);

    expect(ch('#adds').historyAutoPaused).toBe(false);
    expect(ch('#adds').historyEdge).toBe('more');
  });

  it('keeps the edge per channel', () => {
    s().historyFetchStarted('#a', true);
    s().historyPageReceived('#a', 3, PAGE, 3);
    s().historyFetchStarted('#b', true);
    s().historyPageReceived('#b', PAGE, PAGE, PAGE);

    expect(ch('#a').historyEdge).toBe('start');
    expect(ch('#b').historyEdge).toBe('more');
  });

  it('keys the channel case-insensitively', () => {
    s().historyFetchStarted('#Mixed', true);
    s().historyPageReceived('#mIXED', 2, PAGE, 2);

    expect(ch('#mixed').historyEdge).toBe('start');
    expect(ch('#mixed').historyFetching).toBe(false);
  });
});
