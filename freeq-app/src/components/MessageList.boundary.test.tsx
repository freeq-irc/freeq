// @vitest-environment jsdom
/**
 * Where the boundary states are rendered.
 *
 * A row inside the list that appears while a page is on the wire and goes
 * again when it lands moves every row under it, twice, for every page of a
 * walk. The loading state and the retry that follows a page which never came
 * float above the pane instead, out of the layout. What stays in the list is
 * the one that belongs to the conversation rather than to the fetching: the
 * marker saying where the channel begins, which arrives once and stays.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, act, screen } from '@testing-library/react';

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
const client = await import('../irc/client');

const s = () => useStore.getState();
const BASE = 10_000_000;
const ulid = (n: number) => `01M0${String(n).padStart(22, '0')}`;
const requestHistory = client.requestHistory as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  s().reset();
  requestHistory.mockImplementation((channel: string, anchor?: unknown) => {
    s().historyFetchStarted(channel, !!anchor);
  });
});
afterEach(cleanup);

function channelWith(name: string, n: number) {
  for (let i = 0; i < n; i++) {
    s().addMessage(name, {
      id: ulid(i), from: 'alice', text: `row ${i}`,
      timestamp: new Date(BASE + i * 1000), tags: {},
    });
  }
  s().setActiveChannel(name);
}

function list() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

const boundary = () => screen.getByTestId('history-boundary');

describe('the boundary states', () => {
  it('floats the loading state above the pane, not inside the list', () => {
    channelWith('#loading', 5);
    const el = list(); // mounting at the top asks for the first page

    expect(boundary().textContent).toBe('Loading older messages…');
    expect(el.contains(boundary()), 'the loading state is not in the scroller')
      .toBe(false);
  });

  it('floats the retry above the pane too', () => {
    channelWith('#retry', 5);
    const el = list();
    act(() => { s().historyFetchFailed('#retry'); });

    expect(boundary().textContent).toBe('Load older messages');
    expect(el.contains(boundary()), 'the retry is not in the scroller').toBe(false);
  });

  it('keeps the beginning-of-channel marker in the list', () => {
    channelWith('#start', 5);
    const el = list();
    act(() => { s().historyPageReceived('#start', 2, 50, 2); });

    expect(boundary().textContent).toBe('This is the beginning of the channel.');
    expect(el.contains(boundary()), 'the marker belongs to the conversation')
      .toBe(true);
  });

  it('puts nothing in the list while pages are streaming', () => {
    // Nothing may be inserted into or removed from the list as a page lands
    // and the next goes out: every row under it would move, twice a page.
    channelWith('#stream', 5);
    const el = list();
    const inList = () => el.querySelectorAll('[data-testid="history-boundary"]').length;

    expect(inList()).toBe(0);            // a page is on the wire
    act(() => { s().historyFetchFailed('#stream'); });
    expect(inList()).toBe(0);            // the retry stands
    act(() => { s().historyAutoResumed('#stream'); });
    expect(inList()).toBe(0);
  });

  it('is one element at a time, wherever it is', () => {
    channelWith('#one', 5);
    list();
    expect(screen.getAllByTestId('history-boundary').length).toBe(1);
    act(() => { s().historyPageReceived('#one', 2, 50, 2); });
    expect(screen.getAllByTestId('history-boundary').length).toBe(1);
  });
});
