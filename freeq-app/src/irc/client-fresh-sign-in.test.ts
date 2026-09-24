// @vitest-environment jsdom
/**
 * connect() tells the SDK client whether it follows a new sign-in, which is
 * the one connect allowed to replace a device key the account has retired.
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
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: { freshSignIn?: boolean; deviceKeyStore?: unknown }) {
    MockFreeqClient.latest = this;
  }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
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

beforeEach(() => {
  localStorage.clear();
  useStore.getState().reset();
  MockFreeqClient.latest = null;
  bridge.setSaslCredentials('t', 'did:plc:fresh', '', 'web-token');
});

describe('connecting', () => {
  it('passes freshSignIn when the connect follows a new sign-in', () => {
    bridge.connect('wss://test/irc', 'me', [], true);
    const opts = MockFreeqClient.latest!.opts;
    expect(opts.deviceKeyStore).toBeDefined();
    expect(opts.freshSignIn).toBe(true);
  });

  it('passes false on any other connect', () => {
    bridge.connect('wss://test/irc', 'me', []);
    expect(MockFreeqClient.latest!.opts.freshSignIn).toBe(false);
  });
});
