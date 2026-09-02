// @vitest-environment jsdom
/**
 * Tests for joinChannel() in irc/client.ts.
 *
 * A channel key is sent as a separate JOIN parameter. The channel name,
 * without the key, is what the store uses to key the channel buffer.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  static latest: MockFreeqClient | null = null;
  handlers = new Map<string, Handler[]>();
  joins: Array<[string, string | undefined]> = [];
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: unknown) { MockFreeqClient.latest = this; }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  join(channel: string, key?: string) { this.joins.push([channel, key]); }
  requestHistory() { /* not under test */ }
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

function connected(): MockFreeqClient {
  bridge.connect('wss://test/irc', 'me', []);
  return MockFreeqClient.latest!;
}

beforeEach(() => {
  localStorage.clear();
  s().reset();
  MockFreeqClient.latest = null;
});

describe('joining a channel that has a key', () => {
  it('sends the key alongside the channel', () => {
    const client = connected();
    bridge.joinChannel('#general', 'hunter2');
    expect(client.joins.at(-1)).toEqual(['#general', 'hunter2']);
  });

  it('opens a buffer named for the channel alone', () => {
    connected();
    bridge.joinChannel('#general', 'hunter2');
    expect([...s().channels.keys()]).toContain('#general');
    expect([...s().channels.keys()]).not.toContain('#general hunter2');
    expect(s().activeChannel).toBe('#general');
  });

  it('splits a key that arrives inside the channel string', () => {
    const client = connected();
    bridge.joinChannel('#general hunter2');
    expect(client.joins.at(-1)).toEqual(['#general', 'hunter2']);
    expect([...s().channels.keys()]).not.toContain('#general hunter2');
  });

  it('joins without a key when none is given', () => {
    const client = connected();
    bridge.joinChannel('#general');
    expect(client.joins.at(-1)).toEqual(['#general', undefined]);
  });

  it('ignores an empty channel', () => {
    const client = connected();
    bridge.joinChannel('   ');
    expect(client.joins).toHaveLength(0);
  });
});
