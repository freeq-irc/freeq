// @vitest-environment jsdom
/**
 * A window that sits away from the live end of a channel.
 *
 * A reader who follows a link to an old message is not at the present, and
 * the list has to say so and to be able to get back. The window around the
 * linked message is fetched, the jump-to-bottom affordance stands even at the
 * bottom of that window because the bottom of the window is not the bottom of
 * the channel, and taking it asks for the newest page rather than scrolling
 * to rows that are not there.
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
const OLD_BASE = 1_000_000;
const LIVE_BASE = 10_000_000;

/** Message ids have to be ULIDs to be usable as a server anchor. */
const id = (n: number) => `01M0${String(n).padStart(22, '0')}`;

beforeEach(() => {
  vi.clearAllMocks();
  s().reset();
});
afterEach(cleanup);

function anchoredWindow(name: string, n: number) {
  s().openWindow(name, Array.from({ length: n }, (_, i) => ({
    id: id(i), from: 'alice', text: `old ${i}`,
    timestamp: new Date(OLD_BASE + i), tags: {},
  })), false);
  s().setActiveChannel(name);
}

function list() {
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

/** jsdom lays nothing out, so the scroll geometry is stated outright. */
function scrollTo(el: HTMLElement, pos: 'top' | 'bottom') {
  const scrollHeight = 20_000;
  const clientHeight = 500;
  const scrollTop = pos === 'top' ? 0 : scrollHeight - clientHeight;
  for (const [prop, value] of [
    ['scrollHeight', scrollHeight], ['clientHeight', clientHeight], ['scrollTop', scrollTop],
  ] as const) {
    Object.defineProperty(el, prop, { value, configurable: true, writable: true });
  }
  fireEvent.scroll(el);
}

const jumpButton = () =>
  screen.queryByRole('button', { name: /new message|Jump to bottom/ });

describe('a jump to a message', () => {
  it('asks for the page around one the channel does not hold', () => {
    anchoredWindow('#jump', 20);
    list();
    act(() => { s().setScrollToMsgId(id(9999)); });

    expect(client.requestHistory).toHaveBeenCalledWith(
      '#jump', { msgid: id(9999) }, 'around',
    );
  });

  it('asks for nothing when the row is already held', () => {
    anchoredWindow('#held', 20);
    list();
    act(() => { s().setScrollToMsgId(id(5)); });

    expect(client.requestHistory).not.toHaveBeenCalledWith(
      '#held', expect.anything(), 'around',
    );
  });

  it('asks only once when the page comes back without the row', () => {
    anchoredWindow('#missing', 20);
    list();
    act(() => { s().setScrollToMsgId(id(9999)); });
    act(() => {
      s().openWindow('#missing', [{
        id: id(30), from: 'alice', text: 'elsewhere',
        timestamp: new Date(OLD_BASE + 30), tags: {},
      }], false);
    });

    const asks = (client.requestHistory as ReturnType<typeof vi.fn>).mock.calls
      .filter((c) => c[2] === 'around');
    expect(asks.length).toBe(1);
  });

  it('asks again when the same link is followed a second time', () => {
    // The refusal to ask twice is about one jump that went unanswered, not
    // about the link: a reader who comes back to it later, from a window
    // that no longer holds the row, is asking a fresh question.
    anchoredWindow('#twice', 20);
    list();
    act(() => { s().setScrollToMsgId(id(9999)); });
    // The page lands, with the row in it, and the reader is taken there.
    act(() => {
      s().openWindow('#twice', [{
        id: id(9999), from: 'alice', text: 'linked',
        timestamp: new Date(OLD_BASE + 9999), tags: {},
      }], false);
    });
    // ...and later the window is somewhere else again.
    act(() => {
      s().openWindow('#twice', [{
        id: id(40), from: 'alice', text: 'elsewhere',
        timestamp: new Date(OLD_BASE + 40), tags: {},
      }], true);
    });
    vi.clearAllMocks();

    act(() => { s().setScrollToMsgId(id(9999)); });

    expect(client.requestHistory).toHaveBeenCalledWith(
      '#twice', { msgid: id(9999) }, 'around',
    );
  });
});

describe('the bottom of an anchored window', () => {
  it('is not the present, so the jump affordance stands there', () => {
    anchoredWindow('#bottom', 20);
    const el = list();

    scrollTo(el, 'bottom');

    expect(jumpButton()).not.toBeNull();
  });

  it('asks for the newest page when the reader takes it', () => {
    anchoredWindow('#present', 20);
    const el = list();
    scrollTo(el, 'bottom');

    act(() => { jumpButton()!.click(); });

    expect(client.requestHistory).toHaveBeenCalledWith('#present');
  });

  it('scrolls rather than fetches once the window is at the live end', () => {
    anchoredWindow('#attip', 20);
    // The answer to a jump to the present: a fresh page at the live end.
    act(() => {
      s().openWindow('#attip', [{
        id: id(50), from: 'alice', text: 'now',
        timestamp: new Date(LIVE_BASE), tags: {},
      }], true);
    });
    const el = list();
    scrollTo(el, 'bottom');

    expect(jumpButton()).toBeNull();
    expect(client.requestHistory).not.toHaveBeenCalledWith('#attip');
  });
});

describe('paging back inside an anchored window', () => {
  it('gives back the rows at its new end once it is over the ceiling', async () => {
    const { MESSAGE_WINDOW } = await import('../store');
    anchoredWindow('#ceiling', MESSAGE_WINDOW + 200);
    const el = list();
    expect(s().channels.get('#ceiling')!.messages.length).toBe(MESSAGE_WINDOW + 200);

    act(() => { scrollTo(el, 'top'); });

    const held = s().channels.get('#ceiling')!.messages;
    expect(held.length).toBe(MESSAGE_WINDOW);
    expect(held[0].id, 'the end the reader is at is the end that stays').toBe(id(0));
  });

  it('gives them back in a window that reaches the live end too', async () => {
    // The walk costs the same wherever it started. A window that still
    // reaches the live end is not a reason to keep rows the reader has paged
    // away from — the edge says they are fetchable, forwards or by the jump.
    const { MESSAGE_WINDOW } = await import('../store');
    anchoredWindow('#attipceiling', MESSAGE_WINDOW + 200);
    act(() => { s().openWindow('#attipceiling', s().channels.get('#attipceiling')!.messages, true); });
    const el = list();
    expect(s().channels.get('#attipceiling')!.newerEdge).toBe('tip');

    act(() => { scrollTo(el, 'top'); });

    expect(s().channels.get('#attipceiling')!.messages.length).toBe(MESSAGE_WINDOW);
    expect(s().channels.get('#attipceiling')!.newerEdge).toBe('more');
  });
});

describe('reaching the newer end of a window', () => {
  it('asks for the page after its newest row', () => {
    anchoredWindow('#forward', 20);
    const el = list();

    act(() => { scrollTo(el, 'bottom'); });

    expect(client.requestHistory).toHaveBeenCalledWith(
      '#forward', { msgid: id(19) }, 'after',
    );
  });

  it('asks for nothing at the newer end of a window that reaches the present', () => {
    anchoredWindow('#attip', 20);
    act(() => { s().openWindow('#attip', s().channels.get('#attip')!.messages, true); });
    const el = list();

    act(() => { scrollTo(el, 'bottom'); });

    expect(client.requestHistory).not.toHaveBeenCalledWith(
      '#attip', expect.anything(), 'after',
    );
  });

  it('gives back the rows at the older end once it is over the ceiling', async () => {
    const { MESSAGE_WINDOW } = await import('../store');
    anchoredWindow('#fwdceiling', MESSAGE_WINDOW + 200);

    const el = list();
    act(() => { scrollTo(el, 'bottom'); });

    const held = s().channels.get('#fwdceiling')!.messages;
    expect(held.length).toBe(MESSAGE_WINDOW);
    expect(held[held.length - 1].id, 'the end the reader is at is the end that stays')
      .toBe(id(MESSAGE_WINDOW + 199));
    expect(s().channels.get('#fwdceiling')!.historyEdge).toBe('more');
  });

  it('asks again once for each time the reader arrives there', () => {
    // Not on a loop: a page forward lands below the reader, so the next one
    // is asked for when they scroll down to it.
    anchoredWindow('#once', 20);
    const el = list();

    act(() => { scrollTo(el, 'bottom'); });
    act(() => { scrollTo(el, 'bottom'); });

    const forward = (client.requestHistory as ReturnType<typeof vi.fn>).mock.calls
      .filter((c) => c[2] === 'after');
    expect(forward.length).toBe(1);
  });

  it('leaves it alone while the reader is on their way to the present', () => {
    anchoredWindow('#jumping', 20);
    const el = list();
    act(() => { scrollTo(el, 'bottom'); });
    vi.clearAllMocks();

    act(() => { jumpButton()!.click(); });
    act(() => { scrollTo(el, 'bottom'); });

    expect(client.requestHistory).not.toHaveBeenCalledWith(
      '#jumping', expect.anything(), 'after',
    );
  });
});

describe('a live message arriving while the reader is parked back', () => {
  it('does not stop the reader paging further back', () => {
    anchoredWindow('#parked', 20);
    const el = list();
    act(() => { s().historyOpeningPage('#parked', 50, 50); }); // edge: more above

    act(() => {
      s().addMessage('#parked', {
        id: id(999), from: 'carol', text: 'live one',
        timestamp: new Date(LIVE_BASE), tags: {},
      });
    });

    vi.clearAllMocks();
    act(() => { scrollTo(el, 'top'); });

    // The page asked for is still the one above the oldest held row. Reading
    // the anchor off the newest row instead would ask for history after the
    // live message, and the reader would never move.
    expect(client.requestHistory).toHaveBeenCalledWith('#parked', { msgid: id(0) });
  });

  it('counts on the pill rather than pulling the view to it', () => {
    anchoredWindow('#pillparked', 20);
    const el = list();
    scrollTo(el, 'bottom');

    act(() => {
      s().addMessage('#pillparked', {
        id: id(998), from: 'carol', text: 'live one',
        timestamp: new Date(LIVE_BASE), tags: {},
      });
    });

    expect(jumpButton()?.textContent).toBe('1 new message');
  });
});
