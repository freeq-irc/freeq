// @vitest-environment jsdom
/**
 * What a long list mounts, and what a copy across it produces.
 *
 * Only a window of the held rows is mounted, so anything that reads the
 * transcript off the DOM reads a fraction of it. Block-copy has to answer
 * from the store instead: the reader dragged a selection from one row to
 * another, and every row between them is in the copy whether or not it
 * happened to be on screen.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, fireEvent } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

const { MessageList } = await import('./MessageList');
const { useStore } = await import('../store');

const s = () => useStore.getState();
const LIVE_BASE = 10_000_000;
const ROWS = 200;

beforeEach(() => {
  vi.clearAllMocks();
  s().reset();
});
afterEach(cleanup);

function channelWith(name: string, n: number) {
  for (let i = 0; i < n; i++) {
    s().addMessage(name, {
      id: `row-${String(i).padStart(5, '0')}`, from: 'alice',
      text: `line ${i}`, timestamp: new Date(LIVE_BASE + i), tags: {},
    });
  }
  s().setActiveChannel(name);
}

function list() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

const mountedIds = (el: HTMLElement) =>
  Array.from(el.querySelectorAll('[id^="msg-"]')).map((n) => n.id.slice(4));

/** Select from one row to another and copy, returning what reached the
 *  clipboard — or null if the handler left the copy to the browser. */
function copyFrom(el: HTMLElement, fromId: string, toId: string): string | null {
  const a = el.querySelector(`#msg-${fromId}`)!;
  const b = el.querySelector(`#msg-${toId}`)!;
  expect(a, `${fromId} has to be mounted to be an end of the selection`).not.toBeNull();
  expect(b, `${toId} has to be mounted to be an end of the selection`).not.toBeNull();
  const sel = window.getSelection()!;
  sel.removeAllRanges();
  const range = document.createRange();
  range.setStart(a, 0);
  range.setEnd(b, 0);
  sel.addRange(range);

  let copied: string | null = null;
  const clipboardData = {
    setData: (_type: string, value: string) => { copied = value; },
    getData: () => '',
  };
  fireEvent(el, Object.assign(new Event('copy', { bubbles: true }), { clipboardData }));
  return copied;
}

describe('a long channel', () => {
  it('mounts a window of its rows, not all of them', () => {
    channelWith('#long', ROWS);
    const el = list();
    expect(mountedIds(el).length).toBeLessThan(ROWS);
    expect(mountedIds(el).length).toBeGreaterThan(0);
  });

  it('keeps the newest row mounted while the reader is at the bottom', () => {
    channelWith('#newest', ROWS);
    const el = list();
    expect(mountedIds(el)).toContain(`row-${String(ROWS - 1).padStart(5, '0')}`);
  });
});

describe('copying a selection that spans rows', () => {
  it('copies every row between its ends, mounted or not', () => {
    channelWith('#copy', ROWS);
    const el = list();
    const first = mountedIds(el)[0];
    const last = `row-${String(ROWS - 1).padStart(5, '0')}`;
    // The premise: rows between the two ends are not on screen, so a copy
    // that reads the DOM would lose them.
    expect(mountedIds(el)).not.toContain('row-00100');

    const copied = copyFrom(el, first, last);

    expect(copied).not.toBeNull();
    const lines = copied!.split('\n');
    expect(lines[0]).toBe(`alice: line ${Number(first.slice(4))}`);
    expect(lines[lines.length - 1]).toBe(`alice: line ${ROWS - 1}`);
    expect(lines).toContain('alice: line 100');
    expect(lines.length).toBe(ROWS - Number(first.slice(4)));
  });

  it('leaves a selection inside one row to the browser', () => {
    channelWith('#one', ROWS);
    const el = list();
    const only = mountedIds(el)[0];
    expect(copyFrom(el, only, only)).toBeNull();
  });
});
