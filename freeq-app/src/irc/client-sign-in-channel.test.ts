// @vitest-environment jsdom
/**
 * Which channel the app opens on connect (irc/client.ts, hotspot gamma 133).
 *
 * A sign-in whose channel field the person edited opens the first channel it
 * names. That has to beat two older rules: the server rejoins the account's
 * saved channels during registration, so their JOINs land before the client's
 * own, and half a second after registration the client reopens the
 * conversation that was last open. An untouched field, a session refresh and
 * a reconnect all name nothing and keep both rules.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  static latest: MockFreeqClient | null = null;
  handlers = new Map<string, Handler[]>();
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  authDid: string | null = null;
  constructor(public opts: unknown) { MockFreeqClient.latest = this; }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  emit(event: string, ...args: unknown[]) {
    for (const fn of this.handlers.get(event) ?? []) fn(...args);
  }
  join() { /* not under test */ }
  requestHistory() { /* not under test */ }
  requestHistoryTargets() { /* not under test */ }
  setSaslCredentials() { /* not under test */ }
  connect() { /* no-op */ }
  disconnect() { /* no-op */ }
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', () => ({
  FreeqClient: MockFreeqClient,
  // The device key, the lookup and the verdict words the bridge now reads.
  IndexedDbDeviceKeyStore: class {},
  KeyLookup: class { originBase() { return null; } async flush() {} },
  makeDidResolver: () => async () => ({ id: 'did:plc:x' }),
  recordKeyOf: async () => ({ publicKeyMultibase: 'z', signer: async () => '' }),
  decodeMultibaseEd25519: () => new Uint8Array(32),
  buildDeviceRecord: async () => ({}),
  buildDeviceRetirement: async () => ({}),
  sentence: () => 'sentence',
  mark: () => 'signed',
  format: {},
  prefetchProfiles: () => {},
  claimForMessage: () => undefined,
}));

const bridge = await import('./client');
const { useStore } = await import('../store');

const s = () => useStore.getState();

/** Connect the way a sign-in with an edited channel field does: the person
 *  asked for these channels. */
function requesting(channels: string[]): MockFreeqClient {
  bridge.connect('wss://test/irc', 'me', channels, false, true);
  return MockFreeqClient.latest!;
}

/** Connect the way an untouched field, a session refresh or a reconnect
 *  does: these channels are joined, but no one asked for them. */
function notRequesting(channels: string[]): MockFreeqClient {
  bridge.connect('wss://test/irc', 'me', channels);
  return MockFreeqClient.latest!;
}

/** Registration, then the server's rejoin of the account's saved channels. */
function registerAndJoin(client: MockFreeqClient, ...channels: string[]) {
  client.emit('registered', 'me');
  for (const ch of channels) client.emit('channelJoined', ch);
}

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  s().reset();
  MockFreeqClient.latest = null;
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the channel a connect opens', () => {
  it('opens the named channel though a saved one joined first', () => {
    // Where this browser last was, and what the account rejoins on its own.
    localStorage.setItem('freeq-active-channel', '#freeq');
    const client = requesting(['#naptest']);

    registerAndJoin(client, '#freeq', '#naptest');
    expect(s().activeChannel).toBe('#naptest');

    // The restore half a second in does not take it back.
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#naptest');
  });

  it('restores the last open channel when the connect named none', () => {
    localStorage.setItem('freeq-active-channel', '#dev');
    const client = notRequesting(['#freeq', '#dev']);

    registerAndJoin(client, '#freeq', '#dev');
    // The first to arrive opens while the restore is still pending.
    expect(s().activeChannel).toBe('#freeq');

    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#dev');
  });

  it('opens the first channel named, not the first to join', () => {
    const client = requesting(['#naptest', '#other']);

    registerAndJoin(client, '#other', '#naptest');
    expect(s().activeChannel).toBe('#naptest');

    // Nothing takes over from the first one named.
    client.emit('channelJoined', '#other2');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#naptest');
  });

  it('matches a named channel by case, and past its channel key', () => {
    localStorage.setItem('freeq-active-channel', '#freeq');
    const client = requesting(['#NapTest secretkey']);

    registerAndJoin(client, '#freeq', '#naptest');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#naptest');
  });

  it('opens #general on a first-ever visit with nothing stored', () => {
    // The field showed the default and nobody edited it, so nothing was
    // asked for — and with no conversation to go back to, the default is
    // both the channel joined and the channel opened.
    const client = notRequesting(['#general']);

    registerAndJoin(client, '#general');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#general');
  });

  it('opens the channel an edited field names, over the account rejoins', () => {
    // The same visit, with the field edited to name a channel instead.
    localStorage.setItem('freeq-active-channel', '#dev');
    const client = requesting(['#naptest']);

    registerAndJoin(client, '#freeq', '#dev', '#naptest');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#naptest');
  });

  it('opens an invited channel, not the saved ones joined with it', () => {
    // An invite link puts its channel first in the field, so arriving by one
    // lands in that channel even though the browser has its own set.
    localStorage.setItem('freeq-active-channel', '#dev');
    const client = requesting(['#party', '#dev']);

    registerAndJoin(client, '#dev', '#party');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#party');
  });

  it('falls back to the restore when no named channel ever joins', () => {
    localStorage.setItem('freeq-active-channel', '#dev');
    const client = requesting(['#naptest']);

    // #naptest is +i and refuses; only the account's own channels join.
    registerAndJoin(client, '#freeq', '#dev');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#dev');
  });

  it('forgets the named channels on the next connect', () => {
    const first = requesting(['#naptest']);
    registerAndJoin(first, '#naptest');
    expect(s().activeChannel).toBe('#naptest');

    // A reconnect of the same page restores what was last open instead.
    localStorage.setItem('freeq-active-channel', '#dev');
    const again = notRequesting(['#naptest', '#dev']);
    registerAndJoin(again, '#naptest', '#dev');
    vi.advanceTimersByTime(600);
    expect(s().activeChannel).toBe('#dev');
  });
});
