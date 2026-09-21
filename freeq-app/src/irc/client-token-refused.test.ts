// @vitest-environment jsdom
/**
 * A signed-in session whose reconnect is refused its token ends on the sign-in
 * screen with the session-expired line, never as a guest. A guest's own
 * reconnect is unchanged.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true, configurable: true });

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  static built: MockFreeqClient[] = [];
  handlers = new Map<string, Handler[]>();
  nick = 'me';
  joinedChannels = new Set<string>(['#room']);
  nickToDid: unknown = null;
  authDid: string | null = null;
  sasl: { token: string; did: string } | null = null;
  constructor(public opts: { url: string; nick: string; brokerToken?: string }) {
    MockFreeqClient.built.push(this);
  }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  off(event: string, fn: Handler) {
    this.handlers.set(event, (this.handlers.get(event) ?? []).filter((h) => h !== fn));
  }
  emit(event: string, ...args: unknown[]) {
    for (const fn of [...(this.handlers.get(event) ?? [])]) fn(...args);
  }
  join() { /* not under test */ }
  requestHistory() { /* not under test */ }
  requestHistoryTargets() { /* not under test */ }
  setSaslCredentials(creds: { token: string; did: string }) { this.sasl = creds; }
  connect() { /* no-op */ }
  disconnect() { /* no-op */ }
  reconnect() { /* no-op */ }
  quit() { /* no-op */ }
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@freeq/sdk')>()),
  FreeqClient: MockFreeqClient,
  IndexedDbDeviceKeyStore: class {},
}));

const bridge = await import('./client');
const { useStore } = await import('../store');

const DID = 'did:plc:signedin';
const EXPIRED = 'Your session expired. Sign in with AT Protocol again, or connect as guest.';

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  // Drops the previous test's client and account.
  bridge.disconnect();
  localStorage.clear();
  MockFreeqClient.built = [];
  vi.stubGlobal('fetch', vi.fn(async () => new Response('not found', { status: 404 })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Signed in and registered as the account, as the app is after a sign-in. */
function signedIn(): MockFreeqClient {
  localStorage.setItem('freeq-broker-base', 'https://broker.test.example');
  localStorage.setItem('freeq-broker-token', 'BT');
  bridge.setSaslCredentials('web-token', DID, '', 'web-token');
  bridge.connect('wss://test/irc', 'me', ['#room']);
  const c = MockFreeqClient.built.at(-1)!;
  c.authDid = DID;
  c.emit('authenticated', DID, 'ok');
  c.emit('connectionStateChanged', 'connected');
  c.emit('registered', 'me');
  // What App.tsx does once registered.
  useStore.getState().setWasRegistered(true);
  return c;
}

/** Back on the connect screen with the line, signed out, and no guest. */
function expectSignedOutWithLine(): void {
  const s = useStore.getState();
  expect(s.registered).toBe(false);
  expect(s.wasRegistered).toBe(false);
  expect(s.authDid).toBeNull();
  expect(s.authError).toBe(EXPIRED);
  expect(localStorage.getItem('freeq-broker-token')).toBeNull();
}

describe('a reconnect refused its token', () => {
  it('ends on the connect screen with the session-expired line when the SDK reports the refusal', () => {
    const c = signedIn();

    // The SDK's own reconnect offers the spent token and the server answers 904.
    c.authDid = null;
    c.emit('authError', 'Invalid web auth token');
    c.emit('authenticated', '', 'Invalid web auth token');
    c.emit('connectionStateChanged', 'disconnected');

    expectSignedOutWithLine();
    expect(MockFreeqClient.built).toHaveLength(1);
  });

  it('ends on the connect screen when the reconnect registers as a guest', () => {
    signedIn();
    bridge.reconnect();
    const next = MockFreeqClient.built.at(-1)!;
    expect(MockFreeqClient.built).toHaveLength(2);
    // The reconnect still names the account, so the SDK refreshes the session
    // rather than registering without one.
    expect(next.sasl?.did).toBe(DID);

    next.emit('connectionStateChanged', 'connected');
    next.emit('registered', 'Guest12345');

    expectSignedOutWithLine();
    expect(MockFreeqClient.built).toHaveLength(2);
  });

  it('keeps the session when a signed-in connection reports a nick collision', () => {
    const c = signedIn();
    c.emit('authError', "nick 'me' is already taken");
    expect(useStore.getState().registered).toBe(true);
    expect(localStorage.getItem('freeq-broker-token')).toBe('BT');
  });
});

describe("a guest's reconnect", () => {
  it('is unchanged', () => {
    bridge.connect('wss://test/irc', 'web123', ['#room']);
    const c = MockFreeqClient.built.at(-1)!;
    c.emit('connectionStateChanged', 'connected');
    c.emit('registered', 'web123');

    bridge.reconnect();
    const next = MockFreeqClient.built.at(-1)!;
    expect(MockFreeqClient.built).toHaveLength(2);
    expect(next.sasl).toBeNull();
    next.emit('connectionStateChanged', 'connected');
    next.emit('registered', 'web123');

    const s = useStore.getState();
    expect(s.registered).toBe(true);
    expect(s.nick).toBe('web123');
    expect(s.authError).toBeNull();
  });
});
