// @vitest-environment jsdom
/**
 * Reconnect-path tests for irc/client.ts (hotspot, gamma 133).
 *
 * Regression for the "idle → comes back as Guest" bug: an authenticated,
 * broker-backed (web) session uses a single-use web token. On a manual
 * reconnect we must NOT replay that stale token (it would 904 and bounce the
 * user to guest) — instead we force a fresh broker session refresh by clearing
 * the in-memory token and `skipBrokerRefresh`.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// ── Mocks (before store/client import) ──
const storage = new Map<string, string>();
// @ts-expect-error mock
globalThis.localStorage = {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => storage.set(k, v),
  removeItem: (k: string) => { storage.delete(k); },
  clear: () => storage.clear(),
  get length() { return storage.size; },
  key: (i: number) => [...storage.keys()][i] ?? null,
};
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});
// @ts-expect-error mock
globalThis.window = { localStorage: globalThis.localStorage, location: { hash: '', origin: 'http://localhost' }, addEventListener: () => {} };

// Capture every FreeqClient constructed and the SASL creds it was given.
interface Constructed { opts: any; sasl: any | null; }
const constructed: Constructed[] = [];

class MockFreeqClient {
  opts: any;
  sasl: any | null = null;
  joinedChannels = new Set<string>();
  nickToDid: any = null;
  nick = 'chad';
  constructor(opts: any) {
    this.opts = opts;
    constructed.push(this as unknown as Constructed);
  }
  setSaslCredentials(creds: any) { this.sasl = creds; }
  on() { /* record nothing */ }
  connect() { /* no-op */ }
  disconnect() { /* no-op */ }
}

vi.mock('@freeq/sdk', () => ({
  FreeqClient: MockFreeqClient,
  // The device key, the lookup and the verdict words the bridge now reads.
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
}));

const sdk = await import('./client');

beforeEach(() => {
  storage.clear();
  constructed.length = 0;
});

describe('reconnect() with an authenticated broker-backed session', () => {
  it('forces a fresh broker refresh instead of replaying the stale web token', () => {
    storage.set('freeq-broker-token', 'broker-tok');
    storage.set('freeq-broker-base', 'https://broker.example');

    // Initial authenticated connect (web-token path).
    sdk.setSaslCredentials('web-tok-single-use', 'did:plc:chad', '', 'web-token');
    sdk.connect('wss://test/irc', 'chad', ['#freeq']);

    const first = constructed[0];
    expect(first.opts.skipInitialBrokerRefresh, 'first connect skips broker (uses web token)').toBe(true);
    expect(first.sasl.token).toBe('web-tok-single-use');

    sdk.reconnect();

    const second = constructed[1];
    expect(second, 'reconnect creates a new client').toBeDefined();
    // The stale single-use token must NOT be replayed...
    expect(second.opts.skipInitialBrokerRefresh, 'reconnect must NOT skip broker').toBe(false);
    // ...and the broker creds are still passed so the SDK can re-mint.
    expect(second.opts.brokerToken).toBe('broker-tok');
    // setSaslCredentials should not re-arm the dead token.
    expect(second.sasl?.token ?? '').toBe('');
  });

  it('a guest reconnect (no DID) is unaffected', () => {
    sdk.connect('wss://test/irc', 'visitor', ['#freeq']);
    sdk.reconnect();
    const second = constructed[1];
    // No broker creds, no DID → nothing special; no broker creds in opts.
    expect(second.opts.brokerToken).toBeUndefined();
  });
});
