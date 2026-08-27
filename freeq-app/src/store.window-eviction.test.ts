/**
 * The two-ended window: a second edge for the newest end, eviction from the
 * end the reader has moved away from, and an anchored open that replaces the
 * window rather than merging into it.
 *
 * The one-ended model could only answer "is there anything older than the
 * oldest held row?". A window that can sit away from the live end has to
 * answer the other question too, and has to be able to give rows back at
 * either end without losing the ability to fetch them again.
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

const { useStore, MESSAGE_WINDOW } = await import('./store');
type Message = Parameters<ReturnType<typeof useStore.getState>['addMessage']>[1];

const s = () => useStore.getState();
const ch = (name: string) => s().channels.get(name.toLowerCase())!;
const held = (name: string) => ch(name).messages;
const PAGE = 50;

beforeEach(() => {
  storage.clear();
  s().reset();
});

const LIVE_BASE = 10_000_000;

function msg(id: string, at: number): Message {
  return { id, from: 'alice', text: id, timestamp: new Date(at), tags: {} } as Message;
}

/** `n` live messages through the live path, oldest first. */
function fillLive(channel: string, n: number, prefix = 'live') {
  for (let i = 0; i < n; i++) {
    s().addMessage(channel, msg(`${prefix}-${String(i).padStart(5, '0')}`, LIVE_BASE + i));
  }
}

/** An older page: `n` rows ending just before `endsAt`. */
function olderPage(n: number, endsAt: number, prefix: string): Message[] {
  return Array.from({ length: n }, (_, i) =>
    msg(`${prefix}-${String(i).padStart(5, '0')}`, endsAt - n + i));
}

describe('the newest end of the window', () => {
  it('is the live end of the channel until something says otherwise', () => {
    fillLive('#tip', 10);
    expect(ch('#tip').newerEdge).toBe('tip');
  });

  it('says there is more once an anchored window is opened away from it', () => {
    fillLive('#deep', 10);
    s().openWindow('#deep', olderPage(20, LIVE_BASE - 5_000, 'old'), false);
    expect(ch('#deep').newerEdge).toBe('more');
  });

  it('is the live end again when a window is opened at the tip', () => {
    fillLive('#back', 10);
    s().openWindow('#back', olderPage(20, LIVE_BASE - 5_000, 'old'), false);
    s().openWindow('#back', olderPage(20, LIVE_BASE, 'fresh'), true);
    expect(ch('#back').newerEdge).toBe('tip');
  });
});

describe('an anchored open', () => {
  it('replaces the window rather than merging into it', () => {
    fillLive('#replace', 200);
    const page = olderPage(40, LIVE_BASE - 100_000, 'old');

    s().openWindow('#replace', page, false);

    const rows = held('#replace');
    expect(rows.length).toBe(40);
    expect(rows[0].id).toBe('old-00000');
    expect(rows[39].id).toBe('old-00039');
    expect(rows.some((r) => r.id.startsWith('live-'))).toBe(false);
  });

  it('holds the rows in timestamp order however they arrive', () => {
    const page = olderPage(6, LIVE_BASE, 'old');
    s().openWindow('#order', [page[3], page[0], page[5], page[1], page[4], page[2]], false);
    expect(held('#order').map((r) => r.id)).toEqual(page.map((r) => r.id));
  });

  it('leaves the older edge open, because an anchored page says nothing about the start', () => {
    fillLive('#edgeopen', 10);
    s().historyFetchStarted('#edgeopen', true, 'around');
    s().openWindow('#edgeopen', olderPage(20, LIVE_BASE - 5_000, 'old'), false);
    s().historyPageReceived('#edgeopen', 20, PAGE, 20);
    expect(ch('#edgeopen').historyEdge).toBe('more');
  });

  it('creates the channel if the reader jumped into one they had not opened', () => {
    s().openWindow('#new', olderPage(5, LIVE_BASE, 'old'), false);
    expect(held('#new').length).toBe(5);
  });
});

describe('the short-page heuristic under an around answer', () => {
  // An around page splits across its anchor, so a page smaller than the limit
  // is the ordinary case — half of it sits on each side. Reading that as
  // "this is the whole channel" hides the load-older button over history
  // that is really there.
  it('does not declare the start of the channel', () => {
    fillLive('#split', 10);
    s().historyFetchStarted('#split', true, 'around');
    s().historyPageReceived('#split', 12, PAGE, 12);
    expect(ch('#split').historyEdge).toBe('more');
  });

  it('still declares it for a short page older than a held row', () => {
    fillLive('#older', 10);
    s().historyFetchStarted('#older', true);
    s().historyPageReceived('#older', 12, PAGE, 12);
    expect(ch('#older').historyEdge).toBe('start');
  });

  it('holds the automatic fetch off when an around page adds nothing', () => {
    fillLive('#dupe', 10);
    s().historyFetchStarted('#dupe', true, 'around');
    s().historyPageReceived('#dupe', PAGE, PAGE, 0);
    expect(ch('#dupe').historyAutoPaused).toBe(true);
  });
});

describe('eviction from the end away from the reader', () => {
  it('gives back the newest rows when the reader has paged away from them', () => {
    fillLive('#eold', MESSAGE_WINDOW);
    s().mergeHistory('#eold', olderPage(200, LIVE_BASE, 'page'));
    expect(held('#eold').length).toBe(MESSAGE_WINDOW + 200);
    const oldest = held('#eold')[0].id;

    s().evictNewerRows('#eold');

    const rows = held('#eold');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[0].id).toBe(oldest);
    expect(rows[rows.length - 1].id).toBe(`live-${String(MESSAGE_WINDOW - 201).padStart(5, '0')}`);
  });

  it('gives back the oldest rows when the reader is at the live end', () => {
    fillLive('#enew', MESSAGE_WINDOW);
    s().mergeHistory('#enew', olderPage(200, LIVE_BASE, 'page'));
    const newest = held('#enew')[held('#enew').length - 1].id;

    s().trimMessageWindow('#enew');

    const rows = held('#enew');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[rows.length - 1].id).toBe(newest);
    expect(rows.some((r) => r.id.startsWith('page-'))).toBe(false);
  });

  it('touches only the far end: the reader\'s own end is untouched by either', () => {
    fillLive('#far', MESSAGE_WINDOW);
    s().mergeHistory('#far', olderPage(200, LIVE_BASE, 'page'));
    const oldest = held('#far')[0].id;

    s().evictNewerRows('#far');
    expect(held('#far')[0].id).toBe(oldest);

    s().trimMessageWindow('#far');
    expect(held('#far')[held('#far').length - 1].id)
      .toBe(`live-${String(MESSAGE_WINDOW - 201).padStart(5, '0')}`);
  });

  it('leaves what it took off the new end fetchable again', () => {
    fillLive('#refetchn', MESSAGE_WINDOW);
    s().mergeHistory('#refetchn', olderPage(200, LIVE_BASE, 'page'));
    // Walked to the start, so the older edge says there is nothing above it.
    s().historyFetchStarted('#refetchn', true);
    s().historyPageReceived('#refetchn', 2, PAGE, 2);
    expect(ch('#refetchn').historyEdge).toBe('start');

    s().evictNewerRows('#refetchn');

    expect(ch('#refetchn').newerEdge).toBe('more');
    // ...and says nothing about the other end, which it did not touch.
    expect(ch('#refetchn').historyEdge).toBe('start');
  });

  it('leaves what it took off the old end fetchable again', () => {
    fillLive('#refetcho', MESSAGE_WINDOW);
    s().mergeHistory('#refetcho', olderPage(200, LIVE_BASE, 'page'));
    s().historyFetchStarted('#refetcho', true);
    s().historyPageReceived('#refetcho', 2, PAGE, 2);
    expect(ch('#refetcho').historyEdge).toBe('start');

    s().trimMessageWindow('#refetcho');

    expect(ch('#refetcho').historyEdge).toBe('more');
    expect(ch('#refetcho').newerEdge).toBe('tip');
  });

  it('is a no-op below the ceiling', () => {
    fillLive('#under', 100);
    const before = held('#under');
    s().evictNewerRows('#under');
    expect(held('#under')).toBe(before);
    expect(ch('#under').newerEdge).toBe('tip');
  });

  it('is a no-op on a channel that does not exist', () => {
    expect(() => s().evictNewerRows('#nope')).not.toThrow();
    expect(s().channels.has('#nope')).toBe(false);
  });

  it('leaves other channels alone', () => {
    fillLive('#one', MESSAGE_WINDOW);
    fillLive('#two', MESSAGE_WINDOW);
    s().mergeHistory('#one', olderPage(200, LIVE_BASE, 'pa'));
    s().mergeHistory('#two', olderPage(200, LIVE_BASE, 'pb'));

    s().evictNewerRows('#one');

    expect(held('#one').length).toBe(MESSAGE_WINDOW);
    expect(held('#two').length).toBe(MESSAGE_WINDOW + 200);
    expect(ch('#two').newerEdge).toBe('tip');
  });
});

describe('what eviction may never do', () => {
  it('never lets a merge discard a page it was just handed', () => {
    // Only the explicit eviction gives rows back. A page that arrives while
    // the window is already at its ceiling is kept whole, and the reader is
    // what decides which end to give up.
    fillLive('#whole', MESSAGE_WINDOW);
    for (let p = 0; p < 3; p++) {
      s().mergeHistory('#whole', olderPage(500, LIVE_BASE - p * 500, `p${p}`));
    }
    expect(held('#whole').length).toBe(MESSAGE_WINDOW + 1500);
    expect(held('#whole')[0].id).toBe('p2-00000');
  });

  it('never evicts past the ceiling in one step', () => {
    fillLive('#exact', MESSAGE_WINDOW);
    s().mergeHistory('#exact', olderPage(1, LIVE_BASE, 'page'));
    s().evictNewerRows('#exact');
    expect(held('#exact').length).toBe(MESSAGE_WINDOW);
  });
});
