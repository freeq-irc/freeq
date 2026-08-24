/**
 * The scrollback window: grow while a reader pages back, trim on return.
 *
 * A channel held at most the newest 1000 rows, so once it was full every
 * CHATHISTORY page fetched by scrolling up was merged and immediately
 * discarded — the scrollback above the cap was unreachable. The window now
 * grows past 1000 while older pages arrive (bounded by a per-channel total
 * cap) and is trimmed back to the newest 1000 only when the reader returns
 * to the bottom.
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

const { useStore, MESSAGE_WINDOW, MESSAGE_WINDOW_MAX } = await import('./store');
type Message = Parameters<ReturnType<typeof useStore.getState>['addMessage']>[1];

const s = () => useStore.getState();
const held = (ch: string) => s().channels.get(ch.toLowerCase())!.messages;

beforeEach(() => {
  storage.clear();
  s().reset();
});

// Live rows sit at t = 10_000_000 + i ms; each older page sits below that.
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

/** An older CHATHISTORY page: `n` rows ending just before `endsAt`. */
function olderPage(n: number, endsAt: number, prefix: string): Message[] {
  return Array.from({ length: n }, (_, i) =>
    msg(`${prefix}-${String(i).padStart(5, '0')}`, endsAt - n + i));
}

/** Deliver a page the way the SDK's batch API does. */
function deliverBatch(channel: string, page: Message[], id = 'b1') {
  s().startBatch(id, 'chathistory', channel);
  for (const m of page) s().addBatchMessage(id, m);
  s().endBatch(id);
}

describe('window caps', () => {
  it('holds the newest 1000 at rest and never more than the total cap', () => {
    expect(MESSAGE_WINDOW).toBe(1000);
    expect(MESSAGE_WINDOW_MAX).toBeGreaterThan(MESSAGE_WINDOW);
  });
});

// (a) At the cap, an older page survives the merge in full.

describe('an older page arriving at the cap', () => {
  it('survives the historyBatch merge in full', () => {
    fillLive('#full', MESSAGE_WINDOW);
    expect(held('#full').length).toBe(MESSAGE_WINDOW);
    const oldestBefore = held('#full')[0].id;

    const page = olderPage(50, LIVE_BASE, 'page');
    s().mergeHistory('#full', page);

    const rows = held('#full');
    expect(rows.length).toBe(MESSAGE_WINDOW + 50);
    expect(rows[0].id).toBe('page-00000');
    expect(rows[49].id).toBe('page-00049');
    expect(rows[50].id).toBe(oldestBefore);
    for (const m of page) expect(rows.some((r) => r.id === m.id)).toBe(true);
  });

  it('survives the batch merge in full', () => {
    fillLive('#fullb', MESSAGE_WINDOW);
    const oldestBefore = held('#fullb')[0].id;

    deliverBatch('#fullb', olderPage(50, LIVE_BASE, 'page'));

    const rows = held('#fullb');
    expect(rows.length).toBe(MESSAGE_WINDOW + 50);
    expect(rows[0].id).toBe('page-00000');
    expect(rows[50].id).toBe(oldestBefore);
  });

  it('keeps growing across successive pages', () => {
    fillLive('#pages', MESSAGE_WINDOW);
    s().mergeHistory('#pages', olderPage(50, LIVE_BASE, 'p1'));
    s().mergeHistory('#pages', olderPage(50, LIVE_BASE - 50, 'p2'));

    const rows = held('#pages');
    expect(rows.length).toBe(MESSAGE_WINDOW + 100);
    expect(rows[0].id).toBe('p2-00000');
    expect(rows[50].id).toBe('p1-00000');
  });
});

// (b) A live message arriving while the window is grown evicts nothing.

describe('a live message while the window is grown', () => {
  it('evicts nothing', () => {
    fillLive('#grown', MESSAGE_WINDOW);
    s().mergeHistory('#grown', olderPage(50, LIVE_BASE, 'page'));
    const before = held('#grown');
    const oldest = before[0].id;

    s().addMessage('#grown', msg('fresh-1', LIVE_BASE + MESSAGE_WINDOW));

    const rows = held('#grown');
    expect(rows.length).toBe(before.length + 1);
    expect(rows[0].id).toBe(oldest);
    expect(rows[rows.length - 1].id).toBe('fresh-1');
  });

  it('still evicts nothing after many live messages', () => {
    fillLive('#grown2', MESSAGE_WINDOW);
    s().mergeHistory('#grown2', olderPage(50, LIVE_BASE, 'page'));
    const oldest = held('#grown2')[0].id;

    for (let i = 0; i < 200; i++) {
      s().addMessage('#grown2', msg(`fresh-${i}`, LIVE_BASE + MESSAGE_WINDOW + i));
    }

    const rows = held('#grown2');
    expect(rows.length).toBe(MESSAGE_WINDOW + 250);
    expect(rows[0].id).toBe(oldest);
    expect(rows[rows.length - 1].id).toBe('fresh-199');
  });
});

// (c) The trim action restores newest-1000.

describe('trimMessageWindow', () => {
  it('restores the newest 1000 and keeps the newest row', () => {
    fillLive('#trim', MESSAGE_WINDOW);
    s().mergeHistory('#trim', olderPage(50, LIVE_BASE, 'page'));
    expect(held('#trim').length).toBe(MESSAGE_WINDOW + 50);

    s().trimMessageWindow('#trim');

    const rows = held('#trim');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[rows.length - 1].id).toBe(`live-${String(MESSAGE_WINDOW - 1).padStart(5, '0')}`);
    expect(rows[0].id).toBe('live-00000');
    expect(rows.some((r) => r.id.startsWith('page-'))).toBe(false);
  });

  it('is a no-op below the window', () => {
    fillLive('#small', 100);
    const before = held('#small');
    s().trimMessageWindow('#small');
    expect(held('#small')).toBe(before);
  });

  it('is a no-op on an unknown channel', () => {
    expect(() => s().trimMessageWindow('#nope')).not.toThrow();
    expect(s().channels.has('#nope')).toBe(false);
  });

  it('leaves other channels alone', () => {
    fillLive('#a', MESSAGE_WINDOW);
    fillLive('#b', MESSAGE_WINDOW);
    s().mergeHistory('#a', olderPage(50, LIVE_BASE, 'pa'));
    s().mergeHistory('#b', olderPage(50, LIVE_BASE, 'pb'));

    s().trimMessageWindow('#a');

    expect(held('#a').length).toBe(MESSAGE_WINDOW);
    expect(held('#b').length).toBe(MESSAGE_WINDOW + 50);
  });

  it('the window can grow again after a trim', () => {
    fillLive('#again', MESSAGE_WINDOW);
    s().mergeHistory('#again', olderPage(50, LIVE_BASE, 'p1'));
    s().trimMessageWindow('#again');
    s().mergeHistory('#again', olderPage(50, LIVE_BASE, 'p1'));
    expect(held('#again').length).toBe(MESSAGE_WINDOW + 50);
  });
});

// (d) The total cap drops oldest rows first.

describe('the total cap', () => {
  it('drops the oldest rows first when history merges pass it', () => {
    fillLive('#cap', MESSAGE_WINDOW);
    // Six pages of 1000 older rows, each older than the last.
    for (let p = 0; p < 6; p++) {
      s().mergeHistory('#cap', olderPage(1000, LIVE_BASE - p * 1000, `p${p}`));
    }

    const rows = held('#cap');
    expect(rows.length).toBe(MESSAGE_WINDOW_MAX);
    // Newest is untouched; the oldest pages are what went.
    expect(rows[rows.length - 1].id).toBe(`live-${String(MESSAGE_WINDOW - 1).padStart(5, '0')}`);
    expect(rows.some((r) => r.id.startsWith('p5-'))).toBe(false);
    expect(rows.some((r) => r.id.startsWith('p4-'))).toBe(false);
    expect(rows[0].id).toBe('p3-00000');
  });

  it('drops the oldest rows first when live messages pass it', () => {
    fillLive('#capl', MESSAGE_WINDOW);
    s().mergeHistory('#capl', olderPage(MESSAGE_WINDOW_MAX - MESSAGE_WINDOW, LIVE_BASE, 'page'));
    expect(held('#capl').length).toBe(MESSAGE_WINDOW_MAX);

    s().addMessage('#capl', msg('fresh-1', LIVE_BASE + MESSAGE_WINDOW));

    const rows = held('#capl');
    expect(rows.length).toBe(MESSAGE_WINDOW_MAX);
    expect(rows[rows.length - 1].id).toBe('fresh-1');
    expect(rows[0].id).toBe('page-00001');
  });

  it('caps a single oversized page at the total cap', () => {
    fillLive('#huge', 10);
    s().mergeHistory('#huge', olderPage(MESSAGE_WINDOW_MAX + 500, LIVE_BASE, 'page'));

    const rows = held('#huge');
    expect(rows.length).toBe(MESSAGE_WINDOW_MAX);
    expect(rows[rows.length - 1].id).toBe('live-00009');
  });
});

// (e) A channel that never exceeds 1000 behaves exactly as before.

describe('a channel below the window', () => {
  it('merges a history page without dropping anything', () => {
    fillLive('#under', 100);
    s().mergeHistory('#under', olderPage(50, LIVE_BASE, 'page'));

    const rows = held('#under');
    expect(rows.length).toBe(150);
    expect(rows[0].id).toBe('page-00000');
    expect(rows[rows.length - 1].id).toBe('live-00099');
  });

  it('caps live appends at the window, newest kept', () => {
    fillLive('#live', MESSAGE_WINDOW + 5);
    const rows = held('#live');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[rows.length - 1].id).toBe(`live-${String(MESSAGE_WINDOW + 4).padStart(5, '0')}`);
    expect(rows[0].id).toBe('live-00005');
  });

  it('caps a live append that lands exactly on the window', () => {
    fillLive('#exact', MESSAGE_WINDOW);
    expect(held('#exact').length).toBe(MESSAGE_WINDOW);
    s().addMessage('#exact', msg('fresh-1', LIVE_BASE + MESSAGE_WINDOW));
    expect(held('#exact').length).toBe(MESSAGE_WINDOW);
    expect(held('#exact')[0].id).toBe('live-00001');
  });
});
