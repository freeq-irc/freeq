// @vitest-environment jsdom
/**
 * The "(edited)" marker belongs to each message, not to its group: a follow-on
 * line that was edited shows it the same as a header row does.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';

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

const s = () => useStore.getState();
const BASE = 10_000_000;
const ulid = (n: number) => `01M0${String(n).padStart(22, '0')}`;

beforeEach(() => s().reset());
afterEach(cleanup);

/** Lines from one sender, a second apart, so every line after the first groups. */
function addLines(count: number, tagsOf: (i: number) => Record<string, string> = () => ({})) {
  for (let i = 0; i < count; i++) {
    s().addMessage('#edits', {
      id: ulid(i),
      from: 'alice',
      text: `line ${i}`,
      timestamp: new Date(BASE + i * 1000),
      tags: { msgid: ulid(i), ...tagsOf(i) },
    });
  }
}

function show() {
  s().setActiveChannel('#edits');
  render(<MessageList />);
}

const row = (i: number) => document.getElementById(`msg-${ulid(i)}`)!;
const isHeader = (i: number) => row(i).querySelector('.msg-full') !== null;
const showsEdited = (i: number) => (row(i).textContent ?? '').includes('(edited)');

describe('the (edited) marker', () => {
  it('shows on a follow-on line edited live', () => {
    addLines(2);
    s().editMessage('#edits', ulid(1), 'line 1, fixed');
    show();
    expect(isHeader(1)).toBe(false);
    expect(row(1).textContent).toContain('line 1, fixed');
    expect(showsEdited(1)).toBe(true);
    expect(showsEdited(0)).toBe(false);
  });

  it('shows on a follow-on line replayed with the edited tag', () => {
    addLines(2, (i) => (i === 1 ? { '+freeq.at/edited': '1' } : {}));
    show();
    expect(isHeader(1)).toBe(false);
    expect(showsEdited(1)).toBe(true);
    expect(showsEdited(0)).toBe(false);
  });

  it('still shows on an edited header row', () => {
    addLines(2);
    s().editMessage('#edits', ulid(0), 'line 0, fixed');
    show();
    expect(isHeader(0)).toBe(true);
    expect(showsEdited(0)).toBe(true);
    expect(showsEdited(1)).toBe(false);
  });

  it('is absent on a follow-on line that was not edited', () => {
    addLines(2);
    show();
    expect(isHeader(1)).toBe(false);
    expect(showsEdited(1)).toBe(false);
  });

  it('is absent on a follow-on line still streaming its edit', () => {
    addLines(2);
    s().editMessage('#edits', ulid(1), 'line 1, stream', undefined, true);
    show();
    expect(isHeader(1)).toBe(false);
    expect(showsEdited(1)).toBe(false);
  });
});
