/**
 * What happens to a message that arrives while someone is reading.
 *
 * Three positions, three answers. At the bottom, the window keeps its size
 * and the oldest row slides out. Scrolled up with the window still at the
 * live end, nothing is taken from under the reader and the window is allowed
 * to grow until they come back down. Away from the live end, the arrival
 * belongs after a gap the window does not hold, so it is not held either —
 * and the count on the affordance is what tells the reader it happened.
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
const rows = (name: string) => ch(name).messages;
const BASE = 10_000_000;

beforeEach(() => {
  storage.clear();
  s().reset();
});

function msg(id: string, at: number, extra: Partial<Message> = {}): Message {
  return { id, from: 'alice', text: id, timestamp: new Date(at), tags: {}, ...extra } as Message;
}

/** `n` live messages through the live path, oldest first. */
function fillLive(channel: string, n: number, prefix = 'live') {
  for (let i = 0; i < n; i++) {
    s().addMessage(channel, msg(`${prefix}-${String(i).padStart(5, '0')}`, BASE + i));
  }
}

/** A window sitting away from the live end. */
function detachedWindow(channel: string, n: number) {
  s().openWindow(channel, Array.from({ length: n }, (_, i) => msg(`old-${i}`, BASE - 5000 + i)), false);
}

// ── 1. the reader is at the bottom ────────────────────────────────────────

describe('an arrival while the reader is at the bottom', () => {
  it('slides the oldest row out of a full window', () => {
    fillLive('#bottom', MESSAGE_WINDOW);
    expect(rows('#bottom').length).toBe(MESSAGE_WINDOW);

    s().addMessage('#bottom', msg('fresh', BASE + MESSAGE_WINDOW));

    const held = rows('#bottom');
    expect(held.length).toBe(MESSAGE_WINDOW);
    expect(held[held.length - 1].id).toBe('fresh');
    expect(held.some((m) => m.id === 'live-00000')).toBe(false);
  });

  it('leaves a window already grown past the ceiling alone', () => {
    fillLive('#grown', MESSAGE_WINDOW);
    s().mergeHistory('#grown', [msg('older', BASE - 1)]);
    const oldest = rows('#grown')[0].id;

    s().addMessage('#grown', msg('fresh', BASE + MESSAGE_WINDOW));

    expect(rows('#grown')[0].id).toBe(oldest);
  });
});

// ── 2. the reader is scrolled up, the window is still at the live end ─────

describe('an arrival while the reader is scrolled up', () => {
  it('never takes a held row from under them', () => {
    fillLive('#up', MESSAGE_WINDOW);
    s().setReaderAtBottom('#up', false);
    const before = rows('#up').map((m) => m.id);

    for (let i = 0; i < 50; i++) {
      s().addMessage('#up', msg(`fresh-${i}`, BASE + MESSAGE_WINDOW + i));
    }

    const after = rows('#up').map((m) => m.id);
    expect(after.slice(0, before.length)).toEqual(before);
    expect(after.length).toBe(MESSAGE_WINDOW + 50);
  });

  it('is given back by the return to the bottom', () => {
    fillLive('#back', MESSAGE_WINDOW);
    s().setReaderAtBottom('#back', false);
    for (let i = 0; i < 50; i++) {
      s().addMessage('#back', msg(`fresh-${i}`, BASE + MESSAGE_WINDOW + i));
    }

    s().trimMessageWindow('#back');

    expect(rows('#back').length).toBe(MESSAGE_WINDOW);
  });
});

// ── 3. the window is away from the live end ──────────────────────────────

describe('an arrival at a window away from the live end', () => {
  it('is not held at all', () => {
    detachedWindow('#away', 20);
    const before = rows('#away').map((m) => m.id);

    s().addMessage('#away', msg('fresh', BASE + 1_000));

    expect(rows('#away').map((m) => m.id)).toEqual(before);
  });

  it('leaves the held rows the contiguous run they were', () => {
    // The rows the window holds are a run of the channel with nothing
    // missing inside it. A message that belongs after a gap the window does
    // not hold would end that, and it is the reason this is not held.
    detachedWindow('#gap', 20);

    s().addMessage('#gap', msg('fresh-1', BASE + 1_000));
    s().addMessage('#gap', msg('fresh-2', BASE + 1_001));

    const held = rows('#gap');
    expect(held.length).toBe(20);
    expect(held.map((m) => m.id)).toEqual(
      Array.from({ length: 20 }, (_, i) => `old-${i}`),
    );
  });

  it('still marks the buffer unread when the reader is elsewhere', () => {
    detachedWindow('#unread', 20);
    s().setActiveChannel('#other');
    const before = ch('#unread').unreadCount;

    s().addMessage('#unread', msg('fresh', BASE + 1_000));

    expect(ch('#unread').unreadCount).toBe(before + 1);
  });
});

// ── the count on the affordance ───────────────────────────────────────────

describe('what the affordance counts', () => {
  it('goes up by one for an arrival the window does not hold', () => {
    detachedWindow('#count', 20);
    expect(ch('#count').unseenBelow).toBe(0);

    s().addMessage('#count', msg('fresh-1', BASE + 1_000));
    expect(ch('#count').unseenBelow).toBe(1);

    s().addMessage('#count', msg('fresh-2', BASE + 1_001));
    expect(ch('#count').unseenBelow).toBe(2);
  });

  it('goes up by one for an arrival the window does hold', () => {
    // Scrolled up at the live end: the row is held, and it is still below
    // the reader and still unseen.
    fillLive('#counthold', 10);
    s().setReaderAtBottom('#counthold', false);

    s().addMessage('#counthold', msg('fresh', BASE + 1_000));

    expect(ch('#counthold').unseenBelow).toBe(1);
  });

  it('does not move when the reader pages forward into those messages', () => {
    detachedWindow('#forward', 20);
    s().addMessage('#forward', msg('fresh-1', BASE + 1_000));
    s().addMessage('#forward', msg('fresh-2', BASE + 1_001));
    expect(ch('#forward').unseenBelow).toBe(2);

    // The page forward brings those very rows into the window.
    s().mergeHistory('#forward', [
      msg('fresh-1', BASE + 1_000), msg('fresh-2', BASE + 1_001),
    ]);

    expect(ch('#forward').unseenBelow).toBe(2);
    expect(rows('#forward').length).toBe(22);
  });

  it('clears when the reader reaches the present', () => {
    detachedWindow('#present', 20);
    s().addMessage('#present', msg('fresh', BASE + 1_000));
    expect(ch('#present').unseenBelow).toBe(1);

    s().setReaderAtBottom('#present', true);

    expect(ch('#present').unseenBelow).toBe(0);
  });

  it('stays at nothing while the reader is at the bottom', () => {
    fillLive('#at', 10);
    s().addMessage('#at', msg('fresh', BASE + 1_000));
    expect(ch('#at').unseenBelow).toBe(0);
  });

  it('does not count join and part notices', () => {
    fillLive('#notices', 10);
    s().setReaderAtBottom('#notices', false);

    s().addSystemMessage('#notices', 'bob joined');

    expect(ch('#notices').unseenBelow).toBe(0);
  });

  it('does not count a page of history', () => {
    fillLive('#hist', 10);
    s().setReaderAtBottom('#hist', false);

    s().mergeHistory('#hist', [msg('older', BASE - 1)]);

    expect(ch('#hist').unseenBelow).toBe(0);
  });
});

describe('where the reader is', () => {
  it('is the bottom until something says otherwise', () => {
    fillLive('#where', 3);
    expect(ch('#where').readerAtBottom).toBe(true);
  });
});

// ── 4. what one update may do ────────────────────────────────────────────

describe('a single update to the held list', () => {
  /** Every held-list change one action makes, as before/after pairs. */
  function changes(channel: string, run: () => void): Array<[Message[], Message[]]> {
    const key = channel.toLowerCase();
    const seen: Array<[Message[], Message[]]> = [];
    let prev = useStore.getState().channels.get(key)?.messages ?? [];
    const stop = useStore.subscribe((state) => {
      const next = state.channels.get(key)?.messages ?? [];
      if (next !== prev) { seen.push([prev, next]); prev = next; }
    });
    run();
    stop();
    return seen;
  }

  /** Whether one change drops the row that was at the start and puts a new
   *  one at the end — the shape that moves every row's index at once. */
  function straddles([before, after]: [Message[], Message[]]): boolean {
    if (before.length === 0 || after.length === 0) return false;
    const droppedFromStart = !after.some((m) => m.id === before[0].id);
    const addedAtEnd = after[after.length - 1].id !== before[before.length - 1].id;
    return droppedFromStart && addedAtEnd;
  }

  it('never both drops a row at the start and adds one at the end, on a live arrival', () => {
    fillLive('#one', MESSAGE_WINDOW);

    const seen = changes('#one', () => {
      s().addMessage('#one', msg('fresh', BASE + MESSAGE_WINDOW));
    });

    expect(seen.length, 'the add and the drop are separate updates')
      .toBeGreaterThanOrEqual(2);
    expect(seen.filter(straddles)).toEqual([]);
    // ...and between them they did the whole job.
    const last = seen[seen.length - 1][1];
    expect(last.length).toBe(MESSAGE_WINDOW);
    expect(last[last.length - 1].id).toBe('fresh');
  });

  it('never does on a page of history either', () => {
    fillLive('#two', MESSAGE_WINDOW);

    const seen = changes('#two', () => {
      s().mergeHistory('#two', [msg('older', BASE - 1)]);
    });

    expect(seen.filter(straddles)).toEqual([]);
  });

  it('never does on a page that straddles what is held', () => {
    // The newest page over a window that already holds some of it: rows land
    // at the end, and nothing may leave the start in the same breath.
    fillLive('#three', MESSAGE_WINDOW);
    const held = rows('#three');

    const seen = changes('#three', () => {
      s().mergeHistory('#three', [
        held[held.length - 1],
        msg('newer-1', BASE + MESSAGE_WINDOW),
        msg('newer-2', BASE + MESSAGE_WINDOW + 1),
      ]);
    });

    expect(seen.filter(straddles)).toEqual([]);
  });
});
