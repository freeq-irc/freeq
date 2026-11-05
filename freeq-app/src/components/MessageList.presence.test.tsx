// @vitest-environment jsdom
/**
 * Join and leave notices: hidden by default, folded into one line per run,
 * or shown one per event — and moderation lines shown whatever the setting.
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

// Render every row: jsdom has no layout for the virtualizer to measure.
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

/** A channel where someone speaks, then a run of comings and goings, a kick,
 *  and someone speaks again. */
function busyChannel() {
  s().addMessage('#room', {
    id: '01M00000000000000000000001', from: 'alice', text: 'hello',
    timestamp: new Date(1_000_000), tags: {},
  });
  s().addSystemMessage('#room', 'bob joined');
  s().addSystemMessage('#room', 'carol joined');
  s().addSystemMessage('#room', 'dave quit (Ping timeout)');
  s().addSystemMessage('#room', 'eve was kicked by alice (spam)');
  s().addMessage('#room', {
    id: '01M00000000000000000000002', from: 'alice', text: 'bye',
    timestamp: new Date(1_001_000), tags: {},
  });
  s().historyFetchStarted('#room', false);
  s().historyPageReceived('#room', 50, 50, 50);
  s().setActiveChannel('#room');
}

function shown() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

beforeEach(() => {
  s().reset();
  busyChannel();
});
afterEach(() => cleanup());

describe('join and leave messages', () => {
  it('are hidden by default, while a kick still shows', () => {
    expect(s().joinPartDisplay).toBe('hidden');
    const el = shown();
    expect(el.textContent).not.toContain('bob joined');
    expect(el.textContent).not.toContain('dave quit');
    expect(el.textContent).not.toContain('carol');
    expect(el.textContent).toContain('eve was kicked by alice');
  });

  it('fold each run into one line when grouped, which opens to the events', () => {
    s().setJoinPartDisplay('grouped');
    const el = shown();
    expect(el.textContent).toContain('bob, carol joined · dave left');
    expect(el.textContent).not.toContain('bob joined');
    expect(el.textContent).toContain('eve was kicked by alice');

    const summary = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes('carol joined'))!;
    fireEvent.click(summary);
    expect(el.textContent).toContain('bob joined');
    expect(el.textContent).toContain('dave quit (Ping timeout)');
  });

  it('show one line per event when set to all', () => {
    s().setJoinPartDisplay('all');
    const el = shown();
    expect(el.textContent).toContain('bob joined');
    expect(el.textContent).toContain('carol joined');
    expect(el.textContent).toContain('dave quit (Ping timeout)');
    expect(el.textContent).not.toContain('bob, carol joined');
  });
});
