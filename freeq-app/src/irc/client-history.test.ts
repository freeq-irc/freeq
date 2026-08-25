// @vitest-environment jsdom
/**
 * How the bridge resolves a page of history it asked for.
 *
 * A request is armed as it goes out and has to end somewhere: the batch, a
 * refusal from the server, or — only when nothing comes back at all — the
 * timer. What must never happen is that it ends nowhere, because the row
 * above the oldest message reads "Loading older messages…" until it does.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// jsdom supplies window, document and localStorage; only randomUUID is missing.
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});

type Handler = (...args: any[]) => void;

/** Enough of FreeqClient for the bridge to wire itself to, plus a way to
 *  push events back at it and to read what it put on the wire. */
class MockFreeqClient {
  static latest: MockFreeqClient | null = null;
  handlers = new Map<string, Handler[]>();
  history: Array<Record<string, unknown>> = [];
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: any) { MockFreeqClient.latest = this; }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  emit(event: string, ...args: any[]) {
    for (const fn of this.handlers.get(event) ?? []) fn(...args);
  }
  requestHistory(opts: Record<string, unknown>) { this.history.push(opts); }
  requestHistoryTargets() { /* not under test */ }
  setSaslCredentials() { /* not under test */ }
  connect() { /* no-op */ }
  disconnect() { /* no-op */ }
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', () => ({
  FreeqClient: MockFreeqClient,
  format: {},
  prefetchProfiles: () => {},
  claimForMessage: () => undefined,
}));

const bridge = await import('./client');
const { useStore } = await import('../store');

const s = () => useStore.getState();
const ch = (name: string) => s().channels.get(name.toLowerCase());

/** A connected bridge, with the mock client it wired itself to. */
function connected(): MockFreeqClient {
  bridge.connect('wss://test/irc', 'me', []);
  return MockFreeqClient.latest!;
}

/** One row, so the channel exists and has something to anchor on. */
function seed(channel: string) {
  s().addMessage(channel, {
    id: '01M0AAAAAAAAAAAAAAAAAAAA01', from: 'alice',
    text: 'hi', timestamp: new Date(1_700_000_000_000), tags: {},
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  s().reset();
  MockFreeqClient.latest = null;
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('a page of history the bridge asked for', () => {
  it('is armed as the request goes out', () => {
    const client = connected();
    seed('#armed');
    bridge.requestHistory('#armed', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    expect(ch('#armed')!.historyFetching).toBe(true);
    expect(client.history.at(-1)).toMatchObject({
      target: '#armed', mode: 'before', msgid: '01M0AAAAAAAAAAAAAAAAAAAA01',
    });
  });

  it('ends on the batch, and the timer does not fire afterwards', () => {
    const client = connected();
    seed('#batch');
    bridge.requestHistory('#batch', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('historyBatch', '#batch', []);

    expect(ch('#batch')!.historyFetching).toBe(false);
    expect(ch('#batch')!.historyEdge).toBe('start');

    vi.advanceTimersByTime(60_000);
    expect(ch('#batch')!.historyFetching).toBe(false);
    expect(ch('#batch')!.historyEdge).toBe('start');
  });

  it('ends at once on a CHATHISTORY refusal, without waiting for the timer', () => {
    const client = connected();
    seed('#refused');
    bridge.requestHistory('#refused', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit(
      'serverFail',
      'CHATHISTORY ACCOUNT_REQUIRED #refused You must be authenticated to access DM history',
    );

    expect(ch('#refused')!.historyFetching).toBe(false);
    expect(ch('#refused')!.historyAutoPaused).toBe(true);
    expect(ch('#refused')!.historyEdge).toBe('unknown');
  });

  it('ends at once on MESSAGE_ERROR, whose target sits after the subcommand', () => {
    const client = connected();
    seed('#unknownid');
    bridge.requestHistory('#unknownid', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit(
      'serverFail',
      'CHATHISTORY MESSAGE_ERROR BEFORE #unknownid Messages could not be retrieved',
    );

    expect(ch('#unknownid')!.historyFetching).toBe(false);
    expect(ch('#unknownid')!.historyAutoPaused).toBe(true);
  });

  it('leaves a channel alone when the refusal names a different one', () => {
    const client = connected();
    seed('#mine');
    bridge.requestHistory('#mine', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'CHATHISTORY INVALID_TARGET #someone-elses No such channel');

    expect(ch('#mine')!.historyFetching, 'still waiting on our own page').toBe(true);
  });

  it('leaves a channel alone for a FAIL that is not about history', () => {
    const client = connected();
    seed('#other');
    bridge.requestHistory('#other', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'JOIN INVALID_TARGET #other Bad channel');

    expect(ch('#other')!.historyFetching).toBe(true);
  });

  it('ends a DM with a guest peer at the button', () => {
    // A signed-in reader's conversation with a guest has no canonical key —
    // it is built from two DIDs and the guest has none — so the server
    // answers INVALID_TARGET. The row has to end there rather than load on.
    const client = connected();
    seed('gp_guest');
    bridge.requestHistory('gp_guest', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit(
      'serverFail',
      'CHATHISTORY INVALID_TARGET gp_guest Unknown target',
    );

    expect(ch('gp_guest')!.historyFetching).toBe(false);
    expect(ch('gp_guest')!.historyAutoPaused).toBe(true);
    expect(ch('gp_guest')!.historyEdge, 'nothing was learned about the history').toBe('unknown');
  });

  it('does not resolve a DM whose peer is nicked like a subcommand', () => {
    // `before` is a legal nick and sits where the subcommand does. A refusal
    // about another target must not end this one's page.
    const client = connected();
    seed('before');
    bridge.requestHistory('before', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit(
      'serverFail',
      'CHATHISTORY MESSAGE_ERROR BEFORE #elsewhere Messages could not be retrieved',
    );

    expect(ch('before')!.historyFetching, 'still waiting on its own page').toBe(true);
  });

  it('resolves that peer when the refusal is about them', () => {
    const client = connected();
    seed('before');
    bridge.requestHistory('before', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'CHATHISTORY ACCOUNT_REQUIRED before You must be authenticated');

    expect(ch('before')!.historyFetching).toBe(false);
  });

  it('ignores a pending target named inside the description', () => {
    // The description is prose; a channel named in it is not what the
    // refusal is about.
    const client = connected();
    seed('#foo');
    bridge.requestHistory('#foo', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'CHATHISTORY INVALID_TARGET #other No such channel #foo');

    expect(ch('#foo')!.historyFetching).toBe(true);
  });

  it('matches the target however the server cased it', () => {
    const client = connected();
    seed('#Cased');
    bridge.requestHistory('#Cased', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'CHATHISTORY ACCOUNT_REQUIRED #CASED nope');

    expect(ch('#cased')!.historyFetching).toBe(false);
  });
});

describe('what a CHATHISTORY refusal shows the reader', () => {
  /** Rows the buffer holds that are not messages — the app renders a server
   *  rejection as one of these. */
  const noticesIn = (channel: string) =>
    (ch(channel)?.messages ?? []).filter((m) => m.isSystem).map((m) => m.text);

  it('says nothing about a DM with a guest peer', () => {
    // A signed-in reader's DM with a guest has no canonical key, so the
    // server refuses the history request the app sends on every activation.
    // There is nothing the reader can do about it and the row already ends
    // at the button, so the refusal is not worth a line in the conversation.
    const client = connected();
    seed('gp_guest');
    s().setActiveChannel('gp_guest');
    bridge.requestHistory('gp_guest', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('serverFail', 'CHATHISTORY INVALID_TARGET gp_guest Unknown target');

    expect(noticesIn('gp_guest')).toEqual([]);
    expect(ch('gp_guest')!.historyFetching, 'the row still ends').toBe(false);
  });

  it('says nothing when an older server refuses a guest outright', () => {
    // Servers before the empty answer refuse every guest DM history request.
    const client = connected();
    seed('peer');
    s().setActiveChannel('peer');
    bridge.requestHistory('peer', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit(
      'serverFail',
      'CHATHISTORY ACCOUNT_REQUIRED peer You must be authenticated to access DM history',
    );

    expect(noticesIn('peer')).toEqual([]);
    expect(ch('peer')!.historyFetching).toBe(false);
  });

  it('still shows a rejection the reader can act on', () => {
    const client = connected();
    seed('#room');
    s().setActiveChannel('#room');

    client.emit('serverFail', 'JOIN INVITEONLYCHAN #room Cannot join channel');

    expect(noticesIn('#room')).toEqual(['Server error: JOIN INVITEONLYCHAN #room Cannot join channel']);
  });
});

describe('a page that never comes back', () => {
  it('is written off by the timer, and leaves the button', () => {
    connected();
    seed('#silent');
    bridge.requestHistory('#silent', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });
    expect(ch('#silent')!.historyFetching).toBe(true);

    vi.advanceTimersByTime(10_000);

    expect(ch('#silent')!.historyFetching).toBe(false);
    expect(ch('#silent')!.historyAutoPaused).toBe(true);
  });

  it('survives the reader leaving the channel and coming back', () => {
    // Switching away does not cancel the request, and nothing else will
    // answer it — so the buffer has to end somewhere by itself.
    connected();
    seed('#away');
    seed('#elsewhere');
    s().setActiveChannel('#away');
    bridge.requestHistory('#away', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    s().setActiveChannel('#elsewhere');
    vi.advanceTimersByTime(10_000);
    s().setActiveChannel('#away');

    expect(ch('#away')!.historyFetching).toBe(false);
    expect(ch('#away')!.historyAutoPaused).toBe(true);
  });

  it('ends at the button the moment the connection drops', () => {
    const client = connected();
    seed('#dropped');
    bridge.requestHistory('#dropped', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('connectionStateChanged', 'disconnected');

    expect(ch('#dropped')!.historyFetching, 'without waiting out the timer').toBe(false);
    expect(ch('#dropped')!.historyAutoPaused).toBe(true);
  });

  it('ends every buffer waiting on that socket, not just the active one', () => {
    const client = connected();
    seed('#one');
    seed('#two');
    bridge.requestHistory('#one', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });
    bridge.requestHistory('#two', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    client.emit('connectionStateChanged', 'disconnected');

    expect(ch('#one')!.historyFetching).toBe(false);
    expect(ch('#two')!.historyFetching).toBe(false);
  });

  it('arms the automatic fetching again for the buffer in front of the reader', () => {
    const client = connected();
    seed('#back');
    s().setActiveChannel('#back');
    bridge.requestHistory('#back', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });
    client.emit('connectionStateChanged', 'disconnected');
    expect(ch('#back')!.historyAutoPaused).toBe(true);

    client.emit('connectionStateChanged', 'connected');

    expect(ch('#back')!.historyAutoPaused, 'so a scroll to the top asks again').toBe(false);
  });

  it('leaves the timer alone as the answer to silence', () => {
    // A socket that is still up and simply says nothing is the case the
    // timer is for, and it still is.
    connected();
    seed('#quiet');
    bridge.requestHistory('#quiet', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });

    vi.advanceTimersByTime(9_000);
    expect(ch('#quiet')!.historyFetching).toBe(true);
    vi.advanceTimersByTime(1_500);

    expect(ch('#quiet')!.historyFetching).toBe(false);
    expect(ch('#quiet')!.historyAutoPaused).toBe(true);
  });

  it('does not write off a page that already landed', () => {
    const client = connected();
    seed('#landed');
    bridge.requestHistory('#landed', { msgid: '01M0AAAAAAAAAAAAAAAAAAAA01' });
    client.emit('historyBatch', '#landed', Array.from({ length: 50 }, (_, i) => ({
      id: `01M0BBBBBBBBBBBBBBBBBBBB${String(i).padStart(2, '0')}`, from: 'bob',
      text: `old ${i}`, timestamp: new Date(1_600_000_000_000 + i), tags: {},
    })));
    expect(ch('#landed')!.historyEdge).toBe('more');
    expect(ch('#landed')!.historyAutoPaused).toBe(false);

    vi.advanceTimersByTime(60_000);

    expect(ch('#landed')!.historyAutoPaused, 'the timer was cancelled with the batch').toBe(false);
  });
});
