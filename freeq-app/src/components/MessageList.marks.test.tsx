// @vitest-environment jsdom
/**
 * The signature mark on a message row: the lock alone, dimmed to 30% while
 * only the sender's server vouches for the key; nothing for a signature the
 * server made on the sender's behalf; and a click on a mark opens the proof
 * panel for that row. A row groups under its header only while its mark is
 * the header's, and a grouped row wears no mark.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, screen, fireEvent, act } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

// jsdom lays nothing out, so the real virtualizer mounts only the last row.
// Rendering every row lets a test read each one.
vi.mock('virtua', async () => {
  const React = await import('react');
  return {
    Virtualizer: React.forwardRef<HTMLDivElement, { children?: React.ReactNode }>(({ children }, ref) =>
      React.createElement('div', { ref }, children)),
  };
});

const { MessageList } = await import('./MessageList');
const { useStore } = await import('../store');
const { recordVerdict, __resetVerifyCacheForTests } = await import('../lib/verify-signature');
type Verdict = NonNullable<Parameters<typeof recordVerdict>[1]>;

const s = () => useStore.getState();
const BASE = 10_000_000;
const ulid = (n: number) => `01M0${String(n).padStart(22, '0')}`;

const PUBLISHED: Verdict = { state: 'device', layer: 'published', kid: 'k1' };
const VOUCHED: Verdict = { state: 'device', layer: 'vouched', kid: 'k1' };
const INVALID: Verdict = { state: 'invalid', kid: 'k1' };
const SERVER: Verdict = { state: 'server', kid: 'k1' };
const PENDING: Verdict = { state: 'pending', kid: 'k1' };

beforeEach(() => {
  s().reset();
  __resetVerifyCacheForTests();
});
afterEach(cleanup);

/** Signed lines from one sender, a second apart, so every line after the first would group. */
function channelWith(verdicts: (Verdict | undefined)[]) {
  verdicts.forEach((verdict, i) => {
    s().addMessage('#marks', {
      id: ulid(i),
      from: 'alice',
      text: `line ${i}`,
      timestamp: new Date(BASE + i * 1000),
      tags: { '+freeq.at/sig': 'ed25519:kid:sig', msgid: ulid(i) },
    });
    if (verdict) recordVerdict(ulid(i), verdict);
  });
  s().setActiveChannel('#marks');
  render(<MessageList />);
}

const row = (i: number) => document.getElementById(`msg-${ulid(i)}`)!;
const isHeader = (i: number) => row(i).querySelector('.msg-full') !== null;

/** The mark row `i` shows. */
function shownMark(i: number): 'lock' | 'dim-lock' | 'warning' | 'none' {
  const lock = row(i).querySelector('[data-testid="sig-device-mark"]');
  if (lock) return lock.getAttribute('data-layer') === 'published' ? 'lock' : 'dim-lock';
  return row(i).querySelector('[data-testid="sig-invalid-mark"]') ? 'warning' : 'none';
}

describe('the signature mark on a row', () => {
  it('is the lock alone, at full strength, for a key published in the account', () => {
    channelWith([PUBLISHED]);
    const mark = screen.getByTestId('sig-device-mark');
    expect(mark.textContent).toBe('🔒');
    expect(mark.className).not.toContain('opacity-');
  });

  it('is dimmed to 30% for a key only the server vouches for, with the hover text on the mark itself', () => {
    channelWith([VOUCHED]);
    const mark = screen.getByTestId('sig-device-mark');
    expect(mark.textContent).toBe('🔒');
    expect(mark.className).toContain('opacity-30');
    expect(mark.getAttribute('title')).toBeTruthy();
    expect(mark.querySelector('[title]')).toBeNull();
  });

  it('is absent for a message the server signed on the sender’s behalf', () => {
    channelWith([SERVER]);
    expect(screen.getByText('line 0')).toBeTruthy();
    expect(screen.queryByTestId('sig-server-mark')).toBeNull();
    expect(screen.queryByTestId('sig-device-mark')).toBeNull();
    expect(screen.queryByText('🔒')).toBeNull();
  });

  it('opens the proof panel for its row when clicked', () => {
    channelWith([PUBLISHED]);
    expect(screen.queryByTestId('verify-panel')).toBeNull();
    fireEvent.click(screen.getByTestId('sig-device-mark'), { clientX: 20, clientY: 30 });
    expect(screen.getByTestId('verify-panel').getAttribute('data-msgid')).toBe(ulid(0));
  });

  it('carries no cursor class on either mark, the same as the name button beside them', () => {
    channelWith([PUBLISHED]);
    expect(screen.getByText('alice', { selector: 'button' }).className).not.toMatch(/\bcursor-/);
    expect(screen.getByTestId('sig-device-mark').className).not.toMatch(/\bcursor-/);
    cleanup();
    s().reset();
    __resetVerifyCacheForTests();
    channelWith([INVALID]);
    expect(screen.getByText('alice', { selector: 'button' }).className).not.toMatch(/\bcursor-/);
    expect(screen.getByTestId('sig-invalid-mark').className).not.toMatch(/\bcursor-/);
  });

  it('opens the proof panel from the ⚠ on a second row that starts its own header', () => {
    channelWith([PUBLISHED, INVALID]);
    fireEvent.click(row(1).querySelector('[data-testid="sig-invalid-mark"]')!, { clientX: 20, clientY: 30 });
    expect(screen.getByTestId('verify-panel').getAttribute('data-msgid')).toBe(ulid(1));
  });
});

describe('grouping by the row mark', () => {
  it('groups a second row with the same mark under one header, with no mark on the second', () => {
    channelWith([PUBLISHED, PUBLISHED]);
    expect(isHeader(0)).toBe(true);
    expect(shownMark(0)).toBe('lock');
    expect(isHeader(1)).toBe(false);
    expect(shownMark(1)).toBe('none');
  });

  it.each([
    ['full lock then dim lock', PUBLISHED, VOUCHED, 'lock', 'dim-lock'],
    ['lock then ⚠', PUBLISHED, INVALID, 'lock', 'warning'],
    ['lock then none', PUBLISHED, SERVER, 'lock', 'none'],
  ] as const)('gives %s two headers, each with its own mark', (_, first, second, firstMark, secondMark) => {
    channelWith([first, second]);
    expect(isHeader(0)).toBe(true);
    expect(shownMark(0)).toBe(firstMark);
    expect(isHeader(1)).toBe(true);
    expect(shownMark(1)).toBe(secondMark);
  });

  it('groups a second row whose check is pending', () => {
    channelWith([PUBLISHED, PENDING]);
    expect(isHeader(1)).toBe(false);
    expect(shownMark(1)).toBe('none');
  });

  it('moves the pending row out into its own header, with its mark, when its verdict settles different', () => {
    channelWith([PUBLISHED, PENDING]);
    act(() => recordVerdict(ulid(1), INVALID));
    expect(isHeader(0)).toBe(true);
    expect(shownMark(0)).toBe('lock');
    expect(isHeader(1)).toBe(true);
    expect(shownMark(1)).toBe('warning');
  });

  it('keeps the pending row grouped when its verdict settles the same', () => {
    channelWith([PUBLISHED, PENDING]);
    act(() => recordVerdict(ulid(1), PUBLISHED));
    expect(isHeader(1)).toBe(false);
    expect(shownMark(1)).toBe('none');
  });

  it('groups later rows against the header a settled row started', () => {
    channelWith([PUBLISHED, PENDING, INVALID]);
    expect(isHeader(2)).toBe(true);
    act(() => recordVerdict(ulid(1), INVALID));
    expect(isHeader(1)).toBe(true);
    expect(isHeader(2)).toBe(false);
    expect(shownMark(2)).toBe('none');
  });
});
