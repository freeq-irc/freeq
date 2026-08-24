// @vitest-environment jsdom
/**
 * Fetching older history: the boundary row, and who asks for the next page.
 *
 * Fetching used to be silent and edge-triggered — a scroll event landing
 * within 50px of the top, with nothing to click and nothing to read. A page
 * prepending left the reader sitting at the top with no further scroll event
 * to fire, so the next page needed a scroll down and back up to re-arm.
 *
 * The row above the oldest held message is now the visible face of it: an
 * affordance, a loading state, and a start-of-channel marker. The auto-fetch
 * is a condition re-read after every change to the list, so one continuous
 * scroll walks the whole channel.
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
const { useStore } = await import('../store');
const client = await import('../irc/client');

const s = () => useStore.getState();
const PAGE = 50;
const BASE = 10_000_000;

/** The mock stands in for the bridge, which arms the in-flight flag as the
 *  request goes out. Without that the guards under test have nothing to
 *  read. */
const requestHistory = client.requestHistory as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  s().reset();
  requestHistory.mockImplementation((channel: string, anchor?: unknown) => {
    if (anchor) s().historyFetchStarted(channel);
  });
});
afterEach(cleanup);

/** A 26-character Crockford id, the shape a server msgid has. */
const ulid = (n: number) => `01M0${String(n).padStart(22, '0')}`;

/** A channel holding `n` rows, ids ordered from `first`. */
function channelWith(name: string, n: number, first = 1000) {
  for (let i = 0; i < n; i++) {
    s().addMessage(name, {
      id: ulid(first + i), from: 'alice',
      text: `row ${first + i}`, timestamp: new Date(BASE + (first + i) * 1000), tags: {},
    });
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
  act(() => { fireEvent.scroll(el); });
}

function list() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

/** Answer the page in flight: `received` rows against a page of `limit`,
 *  merged the way the bridge merges them. */
function answerWith(channel: string, rows: number, first: number, limit = PAGE) {
  act(() => {
    s().historyPageReceived(channel, rows, limit);
    if (rows > 0) {
      s().mergeHistory(channel, Array.from({ length: rows }, (_, i) => ({
        id: ulid(first + i), from: 'bob',
        text: `old ${first + i}`, timestamp: new Date(BASE + (first + i) * 1000), tags: {},
      })));
    }
  });
}

const boundary = () => screen.getByTestId('history-boundary');
const loadButton = () => screen.queryByRole('button', { name: 'Load older messages' });

describe('the boundary row', () => {
  it('shows a loading state while a page is on the wire', () => {
    channelWith('#loading', 5);
    list(); // mounting at the top asks for the first page

    expect(boundary().textContent).toBe('Loading older messages…');
    expect(loadButton()).toBeNull();
  });

  it('offers the affordance once a page has landed and more exists', () => {
    channelWith('#offer', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#offer', PAGE, 100);

    expect(boundary().textContent).toBe('Load older messages');
    expect(loadButton()).not.toBeNull();
  });

  it('offers the affordance while the edge is still unknown', () => {
    // Nothing has answered yet, so the top of the loaded list may or may not
    // be the start of the channel. That is reason to offer the page, not to
    // declare the start.
    channelWith('#fresh', 5);
    const el = list();
    scrollTo(el, 'middle');
    act(() => { s().historyFetchFailed('#fresh'); });

    expect(s().channels.get('#fresh')!.historyEdge).toBe('unknown');
    expect(boundary().textContent).toBe('Load older messages');
  });

  it('marks the start of the channel when a page comes back short', () => {
    channelWith('#start', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#start', 3, 100);

    expect(boundary().textContent).toBe('This is the beginning of the channel.');
    expect(loadButton()).toBeNull();
  });

  it('is not rendered on the server buffer', () => {
    channelWith('#some', 3);
    act(() => { s().setActiveChannel('server'); });
    render(<MessageList />);

    expect(screen.queryByTestId('history-boundary')).toBeNull();
  });

  it('asks for a page when the affordance is clicked', () => {
    channelWith('#click', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#click', PAGE, 100);
    requestHistory.mockClear();

    act(() => { fireEvent.click(loadButton()!); });

    expect(requestHistory).toHaveBeenCalledTimes(1);
    expect(boundary().textContent).toBe('Loading older messages…');
  });
});

describe('the auto-fetch condition', () => {
  it('asks for a page while the reader is at the top', () => {
    channelWith('#auto', 5);
    list();

    expect(requestHistory).toHaveBeenCalledWith('#auto', { msgid: ulid(1000) });
  });

  it('anchors on the oldest row by msgid', () => {
    channelWith('#anchor', 5, 700);
    list();

    expect(requestHistory).toHaveBeenCalledWith('#anchor', { msgid: ulid(700) });
  });

  it('falls back to a timestamp for a row with no server id', () => {
    s().addMessage('#noid', {
      id: 'local-echo-1', from: 'me',
      text: 'mine', timestamp: new Date(BASE + 5_000), tags: {},
    });
    s().setActiveChannel('#noid');
    list();

    expect(requestHistory).toHaveBeenCalledWith(
      '#noid', { timestamp: new Date(BASE + 5_000).toISOString() },
    );
  });

  it('does not ask while the reader is away from the top', () => {
    channelWith('#away', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#away', PAGE, 100);
    requestHistory.mockClear();

    act(() => {
      s().addMessage('#away', {
        id: ulid(2000), from: 'carol', text: 'live', timestamp: new Date(BASE + 2_000_000), tags: {},
      });
    });

    expect(requestHistory).not.toHaveBeenCalled();
  });

  it('asks again after a page prepends, with no re-arm gesture', () => {
    // The reader never moves: the list grows underneath them and the
    // condition is re-read, which is what the old scroll trigger could not do.
    channelWith('#walk', 5, 1000);
    list();
    expect(requestHistory).toHaveBeenCalledTimes(1);
    expect(requestHistory).toHaveBeenLastCalledWith('#walk', { msgid: ulid(1000) });

    answerWith('#walk', PAGE, 900);

    expect(requestHistory).toHaveBeenCalledTimes(2);
    expect(requestHistory).toHaveBeenLastCalledWith('#walk', { msgid: ulid(900) });

    answerWith('#walk', PAGE, 800);

    expect(requestHistory).toHaveBeenCalledTimes(3);
    expect(requestHistory).toHaveBeenLastCalledWith('#walk', { msgid: ulid(800) });
  });

  it('walks a channel to its start and then stops', () => {
    channelWith('#end', 5, 1000);
    list();
    answerWith('#end', PAGE, 900);
    answerWith('#end', 12, 880);

    const calls = requestHistory.mock.calls.length;
    expect(boundary().textContent).toBe('This is the beginning of the channel.');

    // Anything that re-renders the list must not restart the walk.
    act(() => {
      s().addMessage('#end', {
        id: ulid(3000), from: 'carol', text: 'live', timestamp: new Date(BASE + 3_000_000), tags: {},
      });
    });

    expect(requestHistory.mock.calls.length).toBe(calls);
  });

  it('does not ask twice while a page is in flight', () => {
    channelWith('#once', 5);
    const el = list();
    expect(requestHistory).toHaveBeenCalledTimes(1);

    // Scroll events, live messages, re-renders — none of them is an answer,
    // so none of them is a reason to ask again.
    scrollTo(el, 'top');
    scrollTo(el, 'top');
    act(() => {
      s().addMessage('#once', {
        id: ulid(4000), from: 'carol', text: 'live', timestamp: new Date(BASE + 4_000_000), tags: {},
      });
    });

    expect(requestHistory).toHaveBeenCalledTimes(1);
  });

  it('asks again after a fetch goes unanswered', () => {
    channelWith('#retry', 5);
    const el = list();
    expect(requestHistory).toHaveBeenCalledTimes(1);

    act(() => { s().historyFetchFailed('#retry'); });
    scrollTo(el, 'top');

    expect(requestHistory).toHaveBeenCalledTimes(2);
  });

  it('does not ask on a channel holding nothing to anchor on', () => {
    s().addSystemMessage('#quiet', 'alice joined');
    s().setActiveChannel('#quiet');
    list();

    expect(requestHistory).not.toHaveBeenCalled();
  });
});
