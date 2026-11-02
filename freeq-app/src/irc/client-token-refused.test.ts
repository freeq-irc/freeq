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
  saslFailed = false;
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

/** Back on the connect screen with `line`, signed out, and no guest. */
function expectSignedOutWith(line: string): void {
  const s = useStore.getState();
  expect(s.registered).toBe(false);
  expect(s.wasRegistered).toBe(false);
  expect(s.authDid).toBeNull();
  expect(s.authError).toBe(line);
  expect(localStorage.getItem('freeq-broker-token')).toBeNull();
}

describe('a reconnect refused its token', () => {
  it('ends on the connect screen with the server\'s words when the SDK reports the refusal', () => {
    const c = signedIn();

    // The SDK's own reconnect offers the spent token and the server answers 904.
    c.authDid = null;
    c.emit('authError', 'Invalid web auth token');
    c.emit('authenticated', '', 'Invalid web auth token');
    c.emit('connectionStateChanged', 'disconnected');

    expectSignedOutWith('Invalid web auth token');
    expect(MockFreeqClient.built).toHaveLength(1);
  });

  it('keeps the session when a signed-in connection reports a nick collision', () => {
    const c = signedIn();
    c.emit('authError', "nick 'me' is already taken");
    expect(useStore.getState().registered).toBe(true);
    expect(localStorage.getItem('freeq-broker-token')).toBe('BT');
  });

  it('keeps the session, and says why, when the server cannot check it just now', () => {
    const c = signedIn();
    const lines: string[] = [];
    const addSystemMessage = useStore.getState().addSystemMessage;
    useStore.setState({
      addSystemMessage: (channel: string, text: string) => {
        lines.push(text);
        addSystemMessage(channel, text);
      },
    });
    const words = 'Your identity could not be checked just now. Try again shortly.';
    // The SDK tries again on its growing wait: the line is said once.
    for (let i = 0; i < 3; i++) {
      c.emit('authErrorRetry', words);
      c.emit('connectionStateChanged', 'disconnected');
      c.emit('connectionStateChanged', 'connected');
    }
    expect(lines).toEqual([words]);
    expect(useStore.getState().authError).toBeNull();
    expect(localStorage.getItem('freeq-broker-token')).toBe('BT');
    // Once the session is in, a later outage is said again.
    c.emit('registered', 'me');
    c.emit('authErrorRetry', words);
    expect(lines).toEqual([words, words]);
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

describe('a refusal for good', () => {
  it("on a first sign-in shows the server's words and drops the saved sign-in", () => {
    localStorage.setItem('freeq-broker-token', 'BT');
    bridge.setSaslCredentials('web-token', DID, '', 'web-token');
    bridge.connect('wss://test/irc', 'me', ['#room']);
    const c = MockFreeqClient.built.at(-1)!;
    c.emit('connectionStateChanged', 'connected');
    // The SDK's final refusal: authError, the empty identity, the drop.
    const words = 'Not authorized to connect to this server';
    c.saslFailed = true;
    c.emit('authError', words);
    c.emit('authenticated', '', words);
    c.emit('connectionStateChanged', 'disconnected');

    const s = useStore.getState();
    expect(s.registered).toBe(false);
    expect(s.authDid).toBeNull();
    expect(s.authError).toBe(words);
    expect(MockFreeqClient.built).toHaveLength(1);
    // A page load finds no broker token, so it does not sign in again.
    expect(localStorage.getItem('freeq-broker-token')).toBeNull();
    // "Connect as guest" connects as a guest, not with the refused token.
    bridge.connect('wss://test/irc', 'web123', ['#room']);
    expect(MockFreeqClient.built).toHaveLength(2);
    expect(MockFreeqClient.built.at(-1)!.sasl).toBeNull();
  });

  it('a try-again at sign-in shows its reason on the connect screen, once', () => {
    bridge.setSaslCredentials('web-token', DID, '', 'web-token');
    bridge.connect('wss://test/irc', 'me', ['#room']);
    const c = MockFreeqClient.built.at(-1)!;
    const lines: string[] = [];
    const addSystemMessage = useStore.getState().addSystemMessage;
    useStore.setState({
      addSystemMessage: (channel: string, text: string) => {
        lines.push(text);
        addSystemMessage(channel, text);
      },
    });
    const words = 'Your identity could not be checked just now. Try again shortly.';
    // The SDK tries again on its growing wait.
    for (let i = 0; i < 3; i++) {
      c.emit('connectionStateChanged', 'connected');
      c.emit('authErrorRetry', words);
      c.emit('connectionStateChanged', 'disconnected');
    }
    const s = useStore.getState();
    expect(s.registered).toBe(false);
    expect(s.authError).toBe(words);
    expect(lines).toEqual([]);
    // The sign-in still holds its credentials: the SDK keeps trying.
    expect(MockFreeqClient.built).toHaveLength(1);
    // Once the account is in, the reason goes.
    c.authDid = DID;
    c.emit('authenticated', DID, 'ok');
    expect(useStore.getState().authError).toBeNull();
  });

  it('"Connect as guest" during a try-again at sign-in connects as a guest', () => {
    localStorage.setItem('freeq-broker-token', 'BT');
    bridge.setSaslCredentials('web-token', DID, '', 'web-token');
    bridge.connect('wss://test/irc', 'me', ['#room']);
    const c = MockFreeqClient.built.at(-1)!;
    c.emit('connectionStateChanged', 'connected');
    c.emit('authErrorRetry', 'Your identity could not be checked just now. Try again shortly.');
    c.emit('connectionStateChanged', 'disconnected');
    // The try-again alone keeps the sign-in: the SDK is still trying it.
    expect(localStorage.getItem('freeq-broker-token')).toBe('BT');

    // The connect screen's guest button: connect(..., asPlainGuest).
    bridge.connect('wss://test/irc', 'web123', ['#room'], false, false, true);
    const guest = MockFreeqClient.built.at(-1)!;
    expect(MockFreeqClient.built).toHaveLength(2);
    expect(guest.sasl).toBeNull();
    expect(guest.opts.brokerToken).toBeUndefined();
    expect(localStorage.getItem('freeq-broker-token')).toBeNull();
  });

  it("of a registered guest ends on the connect screen with the server's words", () => {
    bridge.connect('wss://test/irc', 'web123', ['#room']);
    const c = MockFreeqClient.built.at(-1)!;
    c.emit('connectionStateChanged', 'connected');
    c.emit('registered', 'web123');
    useStore.getState().setWasRegistered(true);

    // An op's revoke: FAIL * AGENT_REVOKED, which the SDK reports as a final
    // refusal, then the drop. Nothing reconnects.
    const words = 'Revoked by opper: bye';
    c.saslFailed = true;
    c.emit('authError', words);
    c.emit('authenticated', '', words);
    c.emit('connectionStateChanged', 'disconnected');

    const s = useStore.getState();
    expect(s.registered).toBe(false);
    expect(s.wasRegistered).toBe(false);
    expect(s.authError).toBe(words);
    expect(MockFreeqClient.built).toHaveLength(1);
  });
});
