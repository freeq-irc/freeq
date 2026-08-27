// @vitest-environment jsdom
/**
 * Who gives the scrollback window back.
 *
 * Paging back grows a channel's held rows past the resting window, and the
 * store keeps them until it is told to trim. MessageList owns the scroll
 * position, so it is what tells the store — and only once the reader is
 * back at the bottom, never while they are still reading above it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, fireEvent, act, screen } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

const { MessageList } = await import('./MessageList');
const { useStore, MESSAGE_WINDOW } = await import('../store');
const client = await import('../irc/client');

const s = () => useStore.getState();
const held = (ch: string) => s().channels.get(ch.toLowerCase())!.messages;

const LIVE_BASE = 10_000_000;

beforeEach(() => {
  vi.clearAllMocks();
  s().reset();
});
afterEach(cleanup);

/** A channel holding `live` rows with an older page of `history` merged on
 *  top of them — the state a reader reaches by scrolling up. */
function channelWith(name: string, live: number, history: number) {
  for (let i = 0; i < live; i++) {
    s().addMessage(name, {
      id: `live-${String(i).padStart(5, '0')}`, from: 'alice',
      text: `row ${i}`, timestamp: new Date(LIVE_BASE + i), tags: {},
    });
  }
  if (history > 0) {
    s().mergeHistory(name, Array.from({ length: history }, (_, i) => ({
      id: `page-${String(i).padStart(5, '0')}`, from: 'bob',
      text: `old ${i}`, timestamp: new Date(LIVE_BASE - history + i), tags: {},
    })));
  }
  s().setActiveChannel(name);
}

/** jsdom has no layout, so the scroll geometry is stated outright. */
function scrollTo(el: HTMLElement, pos: 'top' | 'middle' | 'bottom') {
  const scrollHeight = 20_000;
  const clientHeight = 500;
  const scrollTop = pos === 'top' ? 0 : pos === 'middle' ? 8_000 : scrollHeight - clientHeight;
  for (const [prop, value] of [
    ['scrollHeight', scrollHeight], ['clientHeight', clientHeight], ['scrollTop', scrollTop],
  ] as const) {
    Object.defineProperty(el, prop, { value, configurable: true, writable: true });
  }
  fireEvent.scroll(el);
}

function list() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

describe('trimming the grown window', () => {
  it('does not trim while the reader is scrolled back', () => {
    channelWith('#read', MESSAGE_WINDOW, 50);
    const el = list();
    expect(held('#read').length).toBe(MESSAGE_WINDOW + 50);

    scrollTo(el, 'middle');

    expect(held('#read').length).toBe(MESSAGE_WINDOW + 50);
    expect(held('#read')[0].id).toBe('page-00000');
  });

  it('gives back the rows at the live end at the top, and asks for the next page', () => {
    // The walk moves the window rather than growing it. The rows at the end
    // the reader has left are the ones out of reach now, and the edge says
    // they can be fetched again — by paging forward, or by the jump.
    channelWith('#top', MESSAGE_WINDOW, 50);
    const el = list();

    scrollTo(el, 'top');

    const rows = held('#top');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[0].id, 'the end the reader is at is the end that stays').toBe('page-00000');
    expect(s().channels.get('#top')!.newerEdge).toBe('more');
    expect(client.requestHistory).toHaveBeenCalledWith(
      '#top', { timestamp: new Date(LIVE_BASE - 50).toISOString() },
    );
  });

  it('stays at the ceiling across the pages that keep arriving at the top', () => {
    // Parked at the top, the reader is served page after page without
    // touching the scroll again. Each one lands on a window already at its
    // ceiling, so each one has to cost the same at the other end.
    channelWith('#walk', MESSAGE_WINDOW, 0);
    const el = list();
    scrollTo(el, 'top');

    for (let p = 0; p < 4; p++) {
      act(() => {
        s().mergeHistory('#walk', Array.from({ length: 50 }, (_, i) => ({
          id: `p${p}-${String(i).padStart(5, '0')}`, from: 'bob',
          text: `older ${p}.${i}`, timestamp: new Date(LIVE_BASE - (p + 1) * 50 + i), tags: {},
        })));
      });
      expect(held('#walk').length,
        `the window grew past its ceiling on page ${p}`).toBeLessThanOrEqual(MESSAGE_WINDOW);
    }

    expect(held('#walk')[0].id).toBe('p3-00000');
  });

  it('trims to the newest rows once the reader is back at the bottom', () => {
    channelWith('#back', MESSAGE_WINDOW, 50);
    const el = list();
    scrollTo(el, 'middle');
    expect(held('#back').length).toBe(MESSAGE_WINDOW + 50);

    scrollTo(el, 'bottom');

    const rows = held('#back');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows.some((m) => m.id.startsWith('page-'))).toBe(false);
  });

  it('keeps the newest row through the trim', () => {
    channelWith('#newest', MESSAGE_WINDOW, 50);
    const el = list();
    const newest = held('#newest')[MESSAGE_WINDOW + 49].id;

    scrollTo(el, 'bottom');

    const rows = held('#newest');
    expect(rows.length).toBe(MESSAGE_WINDOW);
    expect(rows[rows.length - 1].id).toBe(newest);
    expect(el.querySelector(`#msg-${newest}`)).not.toBeNull();
  });

  it('leaves a channel below the window untouched', () => {
    channelWith('#small', 100, 20);
    const el = list();
    const before = held('#small');

    scrollTo(el, 'bottom');

    expect(held('#small')).toBe(before);
  });
});

describe('the new-message pill while the reader is scrolled back', () => {
  /** Scroll away from the bottom and read the pill/jump button's label. */
  function scrolledBack(name: string, live: number) {
    channelWith(name, live, 0);
    const el = list();
    scrollTo(el, 'middle');
    return el;
  }

  /** The jump/pill button, which only exists while the reader is away from
   *  the bottom; its label is the count. */
  const pillButton = () =>
    screen.queryByRole('button', { name: /new message|Jump to bottom/ });
  const pill = () => pillButton()?.textContent;

  function liveMessage(name: string, id: string, offset: number) {
    act(() => {
      s().addMessage(name, {
        id, from: 'carol', text: id, timestamp: new Date(LIVE_BASE + offset), tags: {},
      });
    });
  }

  function historyPage(name: string, n: number) {
    act(() => {
      s().mergeHistory(name, Array.from({ length: n }, (_, i) => ({
        id: `older-${String(i).padStart(5, '0')}`, from: 'bob',
        text: `older ${i}`, timestamp: new Date(LIVE_BASE - 10_000 + i), tags: {},
      })));
    });
  }

  it('offers the jump button with no count until something arrives', () => {
    scrolledBack('#pill0', 10);
    expect(pill()).toBe('Jump to bottom');
  });

  it('counts a live message', () => {
    scrolledBack('#pill1', 10);
    liveMessage('#pill1', 'new-1', 1_000);
    expect(pill()).toBe('1 new message');
    liveMessage('#pill1', 'new-2', 1_001);
    expect(pill()).toBe('2 new messages');
  });

  it('does not count a merged history page', () => {
    scrolledBack('#pill2', 10);
    historyPage('#pill2', 50);
    expect(pill()).toBe('Jump to bottom');
  });

  it('does not count a history page merged past the window', () => {
    channelWith('#pill3', MESSAGE_WINDOW, 0);
    const el = list();
    scrollTo(el, 'middle');
    historyPage('#pill3', 50);
    expect(held('#pill3').length).toBe(MESSAGE_WINDOW + 50);
    expect(pill()).toBe('Jump to bottom');
  }, 30_000); // renders past the 1000-row window; 15.6s seen under load

  it('keeps counting live messages across a merged history page', () => {
    scrolledBack('#pill4', 10);
    liveMessage('#pill4', 'new-1', 1_000);
    historyPage('#pill4', 50);
    liveMessage('#pill4', 'new-2', 1_001);
    expect(pill()).toBe('2 new messages');
  });

  it('clears the count when the reader returns to the bottom', () => {
    const el = scrolledBack('#pill5', 10);
    liveMessage('#pill5', 'new-1', 1_000);
    expect(pill()).toBe('1 new message');

    act(() => { scrollTo(el, 'bottom'); });

    expect(pillButton()).toBeNull();
  });
});
