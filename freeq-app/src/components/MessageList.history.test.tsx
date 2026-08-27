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
import { render, cleanup, fireEvent, act, screen, waitFor } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

const { MessageList } = await import('./MessageList');
const storeModule = await import('../store');
const { useStore } = storeModule;
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
  // The bridge arms every request it sends, anchored or not, and the guards
  // under test read that flag.
  requestHistory.mockImplementation((channel: string, anchor?: unknown) => {
    s().historyFetchStarted(channel, !!anchor);
  });
});
afterEach(cleanup);

/** A 26-character Crockford id, the shape a server msgid has. */
const ulid = (n: number) => `01M0${String(n).padStart(22, '0')}`;

/** A channel holding `n` rows, ids ordered from `first`.
 *
 *  `taught` answers the channel's opening request up front, the way the
 *  activation fetch does, so a test about paging back starts where a reader
 *  actually starts. Pass false to keep the edge unknown. */
function channelWith(name: string, n: number, first = 1000, taught = true) {
  for (let i = 0; i < n; i++) {
    s().addMessage(name, {
      id: ulid(first + i), from: 'alice',
      text: `row ${first + i}`, timestamp: new Date(BASE + (first + i) * 1000), tags: {},
    });
  }
  if (taught) {
    s().historyFetchStarted(name, false);
    s().historyPageReceived(name, PAGE, PAGE, PAGE);
  }
  s().setActiveChannel(name);
}

/** Answer a channel's opening request up front, so a test about paging back
 *  does not spend it on the activation fetch. */
function taught(name: string) {
  s().historyFetchStarted(name, false);
  s().historyPageReceived(name, PAGE, PAGE, PAGE);
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

/** Like `list()`, but keeping the handle needed to re-render across a
 *  channel switch. */
function renderList() {
  const r = render(<MessageList />);
  return { ...r, rerender: () => r.rerender(<MessageList />) };
}

/** Answer the page in flight: `received` rows against a page of `limit`,
 *  merged the way the bridge merges them. */
function answerWith(channel: string, rows: number, first: number, limit = PAGE) {
  act(() => {
    const held = () => s().channels.get(channel.toLowerCase())?.messages.length ?? 0;
    const before = held();
    if (rows > 0) {
      s().mergeHistory(channel, Array.from({ length: rows }, (_, i) => ({
        id: ulid(first + i), from: 'bob',
        text: `old ${first + i}`, timestamp: new Date(BASE + (first + i) * 1000), tags: {},
      })));
    }
    s().historyPageReceived(channel, rows, limit, held() - before);
  });
}

const boundary = () => screen.getByTestId('history-boundary');
const noBoundary = () => screen.queryByTestId('history-boundary');
const loadButton = () => screen.queryByRole('button', { name: 'Load older messages' });

describe('the boundary row', () => {
  it('shows a loading state while a page is on the wire', () => {
    channelWith('#loading', 5);
    list(); // mounting at the top asks for the first page

    expect(boundary().textContent).toBe('Loading older messages…');
    expect(loadButton()).toBeNull();
  });

  it('shows nothing once a page has landed and the walk can continue on its own', () => {
    channelWith('#offer', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#offer', PAGE, 100);

    expect(noBoundary()).toBeNull();
    expect(loadButton()).toBeNull();
  });

  it('offers the affordance while the edge is still unknown', () => {
    // Nothing has answered yet, so the top of the loaded list may or may not
    // be the start of the channel. That is reason to offer the page, not to
    // declare the start.
    channelWith('#fresh', 5, 1000, false);
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

  it('names the conversation, not the channel, at the start of a DM', () => {
    s().addMessage('alice', {
      id: ulid(1000), from: 'alice',
      text: 'hi', timestamp: new Date(BASE + 1_000_000), tags: {},
    });
    s().setActiveChannel('alice');
    const el = list();
    scrollTo(el, 'middle');
    answerWith('alice', 3, 100);

    expect(boundary().textContent).toBe('This is the beginning of the conversation.');
  });

  it('reaches the start of a guest DM on an empty answer', () => {
    // A session with no DID has no DM history, and the server answers that
    // with an empty page rather than an error. Nothing in the app has to
    // know that: an empty page is a short page.
    s().addMessage('bob', {
      id: ulid(2000), from: 'bob',
      text: 'hello', timestamp: new Date(BASE + 2_000_000), tags: {},
    });
    s().setActiveChannel('bob');
    const el = list();
    scrollTo(el, 'middle');
    answerWith('bob', 0, 0);

    expect(s().channels.get('bob')!.historyEdge).toBe('start');
    expect(boundary().textContent).toBe('This is the beginning of the conversation.');
  });

  it('leaves the beginning line to the empty state in a notices-only channel', async () => {
    // The row is suppressed there because it can do nothing, so something
    // else has to say where the channel begins.
    s().addSystemMessage('#nobody', 'alice joined');
    s().addSystemMessage('#nobody', 'alice left');
    s().setActiveChannel('#nobody');
    const el = list();
    scrollTo(el, 'middle');
    act(() => { s().historyOpeningPage('#nobody', 0, PAGE); });

    // Activation shows a skeleton for the first moments; the empty state is
    // what stands once it clears.
    await waitFor(() => expect(el.textContent).toContain('This is the beginning of'));

    expect(screen.queryByTestId('history-boundary')).toBeNull();
    expect(el.textContent).toContain('#nobody');
    expect(el.textContent, 'the notices are still there').toContain('alice joined');
  });

  it('does not claim the beginning of a channel whose opening page is still out', async () => {
    // The ordinary join: the server sends a notice for your own JOIN, so the
    // buffer holds one row and nothing from a sender while the opening page
    // is in flight. Claiming the beginning there tells the reader a channel
    // about to show fifty messages starts here.
    s().addSystemMessage('#busy', 'me joined');
    s().setActiveChannel('#busy');
    const el = list();
    act(() => { s().historyFetchStarted('#busy', false); });

    expect(boundary().textContent).toBe('Loading older messages…');
    expect(el.textContent).not.toContain('This is the beginning of');

    // Still not once the activation skeleton has cleared — the page decides
    // this, not a timer.
    await new Promise((r) => setTimeout(r, 700));
    expect(boundary().textContent).toBe('Loading older messages…');
    expect(el.textContent).not.toContain('This is the beginning of');

    // The page lands full: fifty messages, and nothing ever said otherwise.
    answerWith('#busy', PAGE, 100);
    expect(el.textContent).not.toContain('This is the beginning of');
    expect(s().channels.get('#busy')!.historyEdge).toBe('more');
  });

  it('does not claim the beginning beside a live button', async () => {
    // A full opening page that holds nothing from a sender settles the edge
    // on `more`. Waiting out the activation skeleton is the point: without
    // it the empty state is hidden anyway and the assertion proves nothing.
    s().addSystemMessage('#quietfull', 'me joined');
    s().setActiveChannel('#quietfull');
    const el = list();
    act(() => { s().historyOpeningPage('#quietfull', PAGE, PAGE); });
    await new Promise((r) => setTimeout(r, 700));

    expect(s().channels.get('#quietfull')!.historyEdge).toBe('more');
    // The row is there and is not the start marker — with no row to anchor
    // on it goes on to ask for the newest page, so it reads as loading.
    expect(boundary().textContent).not.toBe('This is the beginning of the channel.');
    expect(el.textContent).not.toContain('This is the beginning of');
  });

  it('keeps naming the peer in a DM that holds nothing', async () => {
    // A DM's empty state says who the conversation is with and nothing about
    // where it begins, and until a message arrives it is the only thing that
    // does. It holds exactly while there is no boundary row beside it, so it
    // never claims anything a page in flight could contradict.
    s().addDmTarget('bob');
    act(() => { s().setActiveChannel('bob'); });
    const el = list();
    await new Promise((r) => setTimeout(r, 700));

    expect(el.textContent).toContain('Conversation with');
    expect(screen.queryByTestId('history-boundary')).toBeNull();
  });

  it('drops that naming once the DM holds a notice, and the row takes over', async () => {
    s().addDmTarget('carol');
    s().addSystemMessage('carol', 'carol is offline');
    act(() => { s().setActiveChannel('carol'); });
    const el = list();
    await new Promise((r) => setTimeout(r, 700));

    expect(screen.queryByTestId('history-boundary')).not.toBeNull();
    expect(el.textContent).not.toContain('Conversation with');
  });

  it('keeps the empty state away from a channel that holds messages', () => {
    channelWith('#full', 3);
    const el = list();

    expect(el.textContent).not.toContain('This is the beginning of');
  });

  it('leaves the server buffer to its own rows, which are all system rows', () => {
    // Every line on the server tab is a system row, so the sender test would
    // put the welcome over a full log.
    s().addSystemMessage('server', 'MOTD line');
    act(() => { s().setActiveChannel('server'); });
    const { container } = render(<MessageList />);

    expect(container.textContent).toContain('MOTD line');
    expect(container.textContent).not.toContain('Welcome to freeq');
  });

  it('is not rendered once a channel of only notices is known to be empty', () => {
    // Nothing came from a sender and the server holds nothing either, so
    // there is no history boundary to mark — the empty-state welcome is
    // already saying where the channel begins.
    s().addSystemMessage('#notices', 'alice joined');
    s().addSystemMessage('#notices', 'alice left');
    s().setActiveChannel('#notices');
    const el = list();
    scrollTo(el, 'middle');
    // The opening page the SDK asks for on join, answering empty.
    act(() => { s().historyOpeningPage('#notices', 0, PAGE); });

    expect(s().channels.get('#notices')!.historyEdge).toBe('start');
    expect(screen.queryByTestId('history-boundary')).toBeNull();
  });

  it('offers the retry in a channel of only notices after a fetch fails', () => {
    s().addSystemMessage('#asking', 'alice joined');
    s().setActiveChannel('#asking');
    const el = list();
    scrollTo(el, 'middle');
    act(() => {
      s().historyFetchStarted('#asking', false);
      s().historyFetchFailed('#asking');
    });

    expect(boundary().textContent).toBe('Load older messages');
  });

  it('states the beginning itself when a topic has taken the empty state\'s slot', async () => {
    // The empty state renders the topic where it would otherwise say where
    // the channel begins, so the row is what is left to say it.
    s().addSystemMessage('#topical', 'alice joined');
    s().setTopic('#topical', 'Weekly sync notes');
    s().setActiveChannel('#topical');
    const el = list();
    scrollTo(el, 'middle');
    act(() => { s().historyOpeningPage('#topical', 0, PAGE); });
    await new Promise((r) => setTimeout(r, 700));

    expect(boundary().textContent).toBe('This is the beginning of the channel.');
    expect(el.textContent).toContain('Weekly sync notes');
    // Exactly one of the two says it.
    expect(el.textContent).not.toContain('This is the beginning of #topical');
  });

  it('leaves it to the empty state when there is no topic', async () => {
    s().addSystemMessage('#topicless', 'alice joined');
    s().setActiveChannel('#topicless');
    const el = list();
    scrollTo(el, 'middle');
    act(() => { s().historyOpeningPage('#topicless', 0, PAGE); });
    await new Promise((r) => setTimeout(r, 700));

    expect(screen.queryByTestId('history-boundary')).toBeNull();
    expect(el.textContent).toContain('This is the beginning of');
  });

  it('never lets both say it, topic or not', async () => {
    for (const [name, topic] of [['#both1', 'a topic'], ['#both2', '']] as const) {
      s().addSystemMessage(name, 'alice joined');
      if (topic) s().setTopic(name, topic);
      act(() => { s().setActiveChannel(name); });
      const { container, unmount } = render(<MessageList />);
      act(() => { s().historyOpeningPage(name, 0, PAGE); });
      await new Promise((r) => setTimeout(r, 700));

      const said = (container.textContent ?? '').split('This is the beginning of').length - 1;
      expect(said, `${name} should have exactly one beginning line`).toBe(1);
      unmount();
    }
  });

  it('is not rendered on the server buffer', () => {
    channelWith('#some', 3);
    act(() => { s().setActiveChannel('server'); });
    render(<MessageList />);

    expect(screen.queryByTestId('history-boundary')).toBeNull();
  });

  it('asks for a page when the retry is clicked', () => {
    channelWith('#click', 5);
    const el = list();
    scrollTo(el, 'middle');
    answerWith('#click', PAGE, 100);
    act(() => {
      s().historyFetchStarted('#click', true);
      s().historyFetchFailed('#click');
    });
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
    taught('#noid');
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

  it('stops asking on its own after a page goes unanswered', () => {
    // Whatever swallowed the page will swallow the next one, and the reader
    // would otherwise watch a spinner forever.
    channelWith('#lost', 5);
    const el = list();
    expect(requestHistory).toHaveBeenCalledTimes(1);

    act(() => { s().historyFetchFailed('#lost'); });

    expect(boundary().textContent).toBe('Load older messages');

    scrollTo(el, 'top');
    scrollTo(el, 'top');
    act(() => {
      s().addMessage('#lost', {
        id: ulid(5000), from: 'carol', text: 'live', timestamp: new Date(BASE + 5_000_000), tags: {},
      });
    });

    expect(requestHistory).toHaveBeenCalledTimes(1);
  });

  it('asks again, and keeps asking, when the reader clicks', () => {
    channelWith('#byhand', 5, 1000);
    list();
    act(() => { s().historyFetchFailed('#byhand'); });
    expect(requestHistory).toHaveBeenCalledTimes(1);

    act(() => { fireEvent.click(loadButton()!); });
    expect(requestHistory).toHaveBeenCalledTimes(2);

    // And the automatic path is running again: the next page prepending
    // leads into the one after it with no further click.
    answerWith('#byhand', PAGE, 900);
    expect(requestHistory).toHaveBeenCalledTimes(3);
    expect(requestHistory).toHaveBeenLastCalledWith('#byhand', { msgid: ulid(900) });
  });

  it('asks again when the reader comes back to the buffer', () => {
    channelWith('#return', 5);
    list();
    act(() => { s().historyFetchFailed('#return'); });
    expect(requestHistory).toHaveBeenCalledTimes(1);

    // setActiveChannel only moves to a buffer that exists.
    act(() => {
      s().addMessage('#elsewhere', {
        id: ulid(6000), from: 'dave', text: 'over here', timestamp: new Date(BASE + 6_000_000), tags: {},
      });
      s().setActiveChannel('#elsewhere');
    });
    act(() => { s().setActiveChannel('#return'); });

    expect(s().channels.get('#return')!.historyAutoPaused).toBe(false);
    expect(requestHistory.mock.calls.filter((c) => c[0] === '#return').length)
      .toBeGreaterThan(1);
  });

  it('recovers from the start marker after the window is trimmed', () => {
    // The scenario the review named: a channel past the resting window is
    // walked to its true start, the reader returns to the bottom and the
    // trim discards the rows that made it the start, and they scroll up
    // again. The marker must not still be claiming the start over rows that
    // are not it, with the button hidden and the fetch refusing.
    const { MESSAGE_WINDOW } = storeModule;
    for (let i = 0; i < MESSAGE_WINDOW; i++) {
      s().addMessage('#deep', {
        id: ulid(5000 + i), from: 'alice',
        text: `live ${i}`, timestamp: new Date(BASE + (5000 + i) * 1000), tags: {},
      });
    }
    s().setActiveChannel('#deep');
    const el = list();

    // Walked back past the cap, and the last page came up short.
    answerWith('#deep', PAGE, 4000);
    scrollTo(el, 'middle');
    act(() => {
      s().historyFetchStarted('#deep', true);
      s().historyPageReceived('#deep', 4, PAGE, 4);
    });
    expect(boundary().textContent).toBe('This is the beginning of the channel.');
    expect(s().channels.get('#deep')!.messages.length).toBeGreaterThan(MESSAGE_WINDOW);

    // Back to the bottom: MessageList hands the grown rows back.
    scrollTo(el, 'bottom');
    expect(s().channels.get('#deep')!.messages.length).toBe(MESSAGE_WINDOW);

    // Up again. The rows that were the start are gone, so the marker is
    // gone with them and the fetch is no longer refused.
    requestHistory.mockClear();
    scrollTo(el, 'top');

    expect(boundary().textContent).not.toBe('This is the beginning of the channel.');
    expect(requestHistory).toHaveBeenCalledTimes(1);
    expect(boundary().textContent).toBe('Loading older messages…');

    // And once the page lands the walk stands ready again with no chrome:
    // the marker stays gone and nothing floats over the list.
    scrollTo(el, 'middle');
    answerWith('#deep', PAGE, 3000);
    expect(noBoundary()).toBeNull();
  }, 20_000); // renders past the 1000-row window; well clear of the 5s default

  it('asks for the newest page when there is no row to anchor on', () => {
    // A channel holding only join and part notices used to make the click a
    // no-op and the auto-fetch silent. The question it can still ask is
    // whether the server holds anything at all.
    s().addSystemMessage('#quiet', 'alice joined');
    taught('#quiet');
    s().setActiveChannel('#quiet');
    list();

    expect(requestHistory).toHaveBeenCalledWith('#quiet', undefined);
  });

  it('learns the start of a channel of only notices from that answer', () => {
    s().addSystemMessage('#learns', 'alice joined');
    taught('#learns');
    s().setActiveChannel('#learns');
    list();
    expect(requestHistory).toHaveBeenCalledWith('#learns', undefined);

    act(() => { s().historyPageReceived('#learns', 0, PAGE, 0); });

    expect(s().channels.get('#learns')!.historyEdge).toBe('start');
  });

  it('takes the rows when an anchorless ask turns some up', () => {
    s().addSystemMessage('#turnsup', 'alice joined');
    taught('#turnsup');
    s().setActiveChannel('#turnsup');
    list();

    answerWith('#turnsup', 12, 200);

    expect(s().channels.get('#turnsup')!.messages.length).toBeGreaterThan(1);
    expect(s().channels.get('#turnsup')!.historyEdge).toBe('start');
  });

  it('does not leave a fetch behind when the reader switches away', () => {
    // The request is still out when the reader leaves, and nothing on the
    // new channel will answer it. Coming back must not find a spinner that
    // belongs to a request nobody is waiting on any more.
    channelWith('#leave', 5);
    channelWith('#other2', 3, 8000);
    s().setActiveChannel('#leave');
    const { rerender } = renderList();
    expect(s().channels.get('#leave')!.historyFetching).toBe(true);

    act(() => { s().setActiveChannel('#other2'); });
    rerender();
    act(() => { s().historyFetchFailed('#leave'); }); // the bridge's timer
    expect(s().channels.get('#leave')!.historyFetching).toBe(false);
    expect(s().channels.get('#leave')!.historyAutoPaused).toBe(true);

    const before = requestHistory.mock.calls.length;
    act(() => { s().setActiveChannel('#leave'); });
    rerender();

    // Back at the top of a channel that says more exists, so the row is
    // loading again — but on a request that just went out, not the one left
    // behind. Either way it is not stuck.
    expect(s().channels.get('#leave')!.historyAutoPaused, 'coming back re-arms').toBe(false);
    expect(requestHistory.mock.calls.length).toBeGreaterThan(before);
  });
});
