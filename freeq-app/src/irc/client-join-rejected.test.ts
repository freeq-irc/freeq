// @vitest-environment jsdom
/**
 * A refused JOIN (473/475/477) in the bridge: the reason lands in the buffer
 * `joinChannel` opened, the buffer leaves the sidebar (not joined), a room's
 * 477 does not open the policy gate, and the parked invite survives only
 * when signing in would make it work.
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
  authDid: string | null = null;
  apiBearer: string | null = null;
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: unknown) { MockFreeqClient.latest = this; }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  emit(event: string, ...args: unknown[]) {
    for (const fn of this.handlers.get(event) ?? []) fn(...args);
  }
  join(channel: string, key?: string) { this.joins.push([channel, key]); }
  setChannelCipher() {}
  getChannelCipher() { return null; }
  requestHistory() {}
  requestHistoryTargets() {}
  setSaslCredentials() {}
  connect() {}
  disconnect() {}
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', () => ({
  FreeqClient: MockFreeqClient,
  IndexedDbDeviceKeyStore: class {},
  KeyLookup: class { originBase() { return null; } },
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
const { savePendingRoom, loadPendingRoom } = await import('../lib/room-link');

const s = () => useStore.getState();

function connected(): MockFreeqClient {
  bridge.connect('wss://test/irc', 'me', []);
  return MockFreeqClient.latest!;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  s().reset();
  s().setJoinGateChannel(null);
  MockFreeqClient.latest = null;
});

describe('a refused join', () => {
  it('shows the reason in the buffer the join opened and takes it off the sidebar', () => {
    const client = connected();
    bridge.joinChannel('#secret', 'wrong');
    expect(s().channels.get('#secret')!.isJoined).toBe(true);

    client.emit('joinRejected', '#secret', '475', 'incorrect channel key');

    const ch = s().channels.get('#secret')!;
    expect(ch.isJoined).toBe(false);
    expect(ch.messages.at(-1)).toMatchObject({ isSystem: true, text: 'Cannot join #secret: incorrect channel key (475)' });
    expect(s().activeChannel).toBe('#secret');
  });

  it('explains a room\'s 473 in terms of the invite link', () => {
    const client = connected();
    bridge.joinChannel('#r-a-b-c', 'stale');
    client.emit('joinRejected', '#r-a-b-c', '473', 'invite only (+i)');
    expect(s().channels.get('#r-a-b-c')!.messages.at(-1)!.text).toMatch(/invite link is required/);
  });

  it('explains a room\'s 477 as needing an identity and does not open the policy gate', () => {
    const client = connected();
    s().setAuth('did:plc:me', 'ok');
    bridge.joinChannel('#r-a-b-c', 'tok');
    client.emit('joinGateRequired', '#r-a-b-c');
    client.emit('joinRejected', '#r-a-b-c', '477', 'policy acceptance required');
    expect(s().joinGateChannel).toBeNull();
    expect(s().channels.get('#r-a-b-c')!.messages.at(-1)!.text).toMatch(/sign in with AT Protocol/);
  });

  it('still opens the policy gate for an ordinary channel\'s 477', () => {
    const client = connected();
    s().setAuth('did:plc:me', 'ok');
    bridge.joinChannel('#gated');
    client.emit('joinGateRequired', '#gated');
    expect(s().joinGateChannel).toBe('#gated');
  });

  it('keeps the parked invite on a 477 (sign-in will fix it) and drops it on a 473', () => {
    const client = connected();
    savePendingRoom({ channel: '#r-a-b-c', token: 'T' });
    client.emit('joinRejected', '#r-a-b-c', '477', 'policy acceptance required');
    expect(loadPendingRoom()).toEqual({ channel: '#r-a-b-c', token: 'T' });
    client.emit('joinRejected', '#r-a-b-c', '473', 'invite only (+i)');
    expect(loadPendingRoom()).toBeNull();
  });

  it('clears the parked invite once the room is joined, keeping the token for the copy button', () => {
    const client = connected();
    savePendingRoom({ channel: '#r-a-b-c', token: 'T' });
    client.emit('channelJoined', '#r-a-b-c');
    expect(loadPendingRoom()).toBeNull();
    expect(s().rooms.get('#r-a-b-c')).toMatchObject({ isRoom: true, inviteToken: 'T' });
    expect(s().channels.get('#r-a-b-c')!.isEncrypted).toBe(true);
  });
});
