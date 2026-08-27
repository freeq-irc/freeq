/**
 * Paging forward: the mirror of paging back.
 *
 * A window that has been walked away from the live end has a newer end as
 * well as an older one, and the same three questions have to be answerable
 * about it — whether there is more beyond it, whether a page asked for came
 * back, and whether asking again on the same anchor would get anywhere.
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
type Message = Parameters<ReturnType<typeof useStore.getState>['addMessage']>[1];

const s = () => useStore.getState();
const ch = (name: string) => s().channels.get(name.toLowerCase())!;
const PAGE = 50;
const BASE = 10_000_000;

beforeEach(() => {
  storage.clear();
  s().reset();
});

function msg(id: string, at: number): Message {
  return { id, from: 'alice', text: id, timestamp: new Date(at), tags: {} } as Message;
}

/** A window sitting away from the live end, with `n` rows in it. */
function anchoredWindow(channel: string, n: number) {
  s().openWindow(channel, Array.from({ length: n }, (_, i) => msg(`old-${i}`, BASE + i)), false);
}

describe('a page after the newest held row', () => {
  it('leaves the window saying there is more when it comes back full', () => {
    anchoredWindow('#full', 20);
    s().historyFetchStarted('#full', true, 'after');
    s().historyPageReceived('#full', PAGE, PAGE, PAGE);

    expect(ch('#full').newerEdge).toBe('more');
    expect(ch('#full').historyFetching).toBe(false);
  });

  it('reaches the live end when it comes back short', () => {
    anchoredWindow('#short', 20);
    s().historyFetchStarted('#short', true, 'after');
    s().historyPageReceived('#short', 12, PAGE, 12);

    expect(ch('#short').newerEdge).toBe('tip');
  });

  it('reaches it on an empty answer too', () => {
    anchoredWindow('#empty', 20);
    s().historyFetchStarted('#empty', true, 'after');
    s().historyPageReceived('#empty', 0, PAGE, 0);

    expect(ch('#empty').newerEdge).toBe('tip');
  });

  it('says nothing about the older end', () => {
    // A page forward is not an answer to the question the other end asks.
    anchoredWindow('#older', 20);
    s().historyFetchStarted('#older', true);
    s().historyPageReceived('#older', 2, PAGE, 2);
    expect(ch('#older').historyEdge).toBe('start');

    s().historyFetchStarted('#older', true, 'after');
    s().historyPageReceived('#older', PAGE, PAGE, PAGE);

    expect(ch('#older').historyEdge).toBe('start');
  });

  it('holds the forward fetch off when it adds nothing, and only that one', () => {
    // Asking again on the same anchor would fetch the same page forever.
    anchoredWindow('#dupe', 20);
    s().historyFetchStarted('#dupe', true, 'after');
    s().historyPageReceived('#dupe', PAGE, PAGE, 0);

    expect(ch('#dupe').newerAutoPaused).toBe(true);
    expect(ch('#dupe').historyAutoPaused).toBe(false);
  });

  it('holds it off when the page never comes back', () => {
    anchoredWindow('#lost', 20);
    s().historyFetchStarted('#lost', true, 'after');
    s().historyFetchFailed('#lost');

    expect(ch('#lost').newerAutoPaused).toBe(true);
    expect(ch('#lost').historyAutoPaused).toBe(false);
    expect(ch('#lost').historyFetching).toBe(false);
  });

  it('leaves the older direction to hold itself off', () => {
    anchoredWindow('#back', 20);
    s().historyFetchStarted('#back', true);
    s().historyFetchFailed('#back');

    expect(ch('#back').historyAutoPaused).toBe(true);
    expect(ch('#back').newerAutoPaused).toBe(false);
  });
});

describe('starting the automatic fetching again', () => {
  it('starts both directions', () => {
    // Coming back to a buffer, or asking by hand, is the reader saying to
    // try again — and they cannot say which end they meant.
    anchoredWindow('#resume', 20);
    s().historyFetchStarted('#resume', true, 'after');
    s().historyFetchFailed('#resume');
    s().historyFetchStarted('#resume', true);
    s().historyFetchFailed('#resume');
    expect(ch('#resume').historyAutoPaused).toBe(true);
    expect(ch('#resume').newerAutoPaused).toBe(true);

    s().historyAutoResumed('#resume');

    expect(ch('#resume').historyAutoPaused).toBe(false);
    expect(ch('#resume').newerAutoPaused).toBe(false);
  });
});

describe('a window with a newer end', () => {
  it('starts at the live end, with nothing held off', () => {
    s().addMessage('#fresh', msg('one', BASE));
    expect(ch('#fresh').newerEdge).toBe('tip');
    expect(ch('#fresh').newerAutoPaused).toBe(false);
  });

  it('merges a page forward onto the rows it already holds', () => {
    anchoredWindow('#merge', 20);
    s().mergeHistory('#merge', Array.from({ length: 10 }, (_, i) => msg(`new-${i}`, BASE + 100 + i)));

    const rows = ch('#merge').messages;
    expect(rows.length).toBe(30);
    expect(rows[19].id).toBe('old-19');
    expect(rows[20].id).toBe('new-0');
  });
});
