/**
 * Regression tests for the silent-guest-fallback bug.
 *
 * Production scenario: user is logged in via SASL ATPROTO-CHALLENGE.
 * Overnight, the WebSocket drops and the Transport auto-reconnects.
 * The stored SASL token is stale; the server returns 904 (SASL failed),
 * then renames the requested nick to "GuestNNNNN" (because the nick is
 * registered to a DID the connection didn't authenticate as) and sends
 * 001 to complete registration as a guest.
 *
 * Before the fix, the SDK silently emitted 'registered' with the Guest
 * nick while leaving the previous _authDid in the store. Subsequent
 * sendMessage calls went out under the Guest identity even though the
 * UI still displayed the user as authenticated.
 *
 * After the fix, the SDK MUST:
 *   1. emit 'authError' on 904
 *   2. clear _authDid (and notify via 'authenticated' so the store
 *      mirrors it) so the UI can show "session expired"
 *   3. NOT silently complete IRC registration as a guest when SASL was
 *      attempted. Either disconnect, or surface a guestFallback event.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// ── WebSocket mock ────────────────────────────────────────────────

type ReadyState = 0 | 1 | 2 | 3;

class MockWebSocket {
  static CONNECTING: ReadyState = 0;
  static OPEN: ReadyState = 1;
  static CLOSING: ReadyState = 2;
  static CLOSED: ReadyState = 3;

  static instances: MockWebSocket[] = [];

  CONNECTING: ReadyState = 0;
  OPEN: ReadyState = 1;
  CLOSING: ReadyState = 2;
  CLOSED: ReadyState = 3;

  url: string;
  readyState: ReadyState = 0;
  bufferedAmount = 0;
  sent: string[] = [];

  onopen: ((ev: any) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: any) => void) | null = null;
  onerror: ((ev: any) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    // Defer onopen — caller wires handlers synchronously after constructor.
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string) {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
    this.onclose?.({});
  }

  /** Test helper: deliver a server line to the client. */
  recv(line: string) {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

// ── Crypto mock (Ed25519 unavailable in Node test env) ────────────

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  if (!globalThis.crypto || !(globalThis.crypto as any).randomUUID) {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2),
        subtle: {
          generateKey: () => Promise.reject(new Error('Ed25519 unavailable in test env')),
        },
      },
      configurable: true,
      writable: true,
    });
  }
  // btoa/atob exist in node 20+
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Helpers ───────────────────────────────────────────────────────

async function flushAsync() {
  // Give microtasks (transport open + sdk handlers) a chance to settle.
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

interface AuthFailScenarioOptions {
  /** Server-assigned nick after Guest rename (e.g., "Guest24609"). */
  guestNick?: string;
  /** Original nick the client requested (same as ctor's nick). */
  originalNick?: string;
}

/**
 * Drive a FreeqClient through the production bug scenario:
 *   connect → CAP LS → CAP ACK sasl → SASL ATPROTO-CHALLENGE
 *   → server 904 (auth failed)
 *   → server NOTICE: "Nick X is registered — renamed to GuestNNN"
 *   → 001 RPL_WELCOME with GuestNNN
 */
async function runStaleSaslScenario(
  ws: MockWebSocket,
  opts: AuthFailScenarioOptions = {},
) {
  const guestNick = opts.guestNick ?? 'Guest24609';
  const originalNick = opts.originalNick ?? 'chad';

  await flushAsync();

  // Step 1: client should have sent CAP LS, NICK, USER
  expect(ws.sent.some(l => l.startsWith('CAP LS'))).toBe(true);

  // Step 2: server advertises caps including sasl
  ws.recv(':srv CAP * LS :message-tags server-time batch sasl echo-message account-notify extended-join away-notify draft/chathistory');
  await flushAsync();

  // Client should have requested caps including sasl
  const capReq = ws.sent.find(l => l.startsWith('CAP REQ'));
  expect(capReq).toBeDefined();
  expect(capReq).toContain('sasl');

  // Step 3: server ACKs caps
  ws.recv(`:srv CAP ${originalNick} ACK :message-tags server-time batch sasl echo-message account-notify extended-join away-notify`);
  await flushAsync();

  // Client should have started AUTHENTICATE
  expect(ws.sent.some(l => l.startsWith('AUTHENTICATE ATPROTO-CHALLENGE'))).toBe(true);

  // Step 4: server issues challenge
  const challenge = btoa(JSON.stringify({
    session_id: 'sess1',
    nonce: 'nonce-deadbeef',
    timestamp: Date.now(),
  }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  ws.recv(`AUTHENTICATE ${challenge}`);
  await flushAsync();

  // Client should have responded with AUTHENTICATE <signed-payload>
  expect(ws.sent.filter(l => l.startsWith('AUTHENTICATE ')).length).toBeGreaterThanOrEqual(2);

  // Step 5: server rejects with 904 (stale token doesn't validate)
  ws.recv(`:srv 904 ${originalNick} :SASL authentication failed`);
  await flushAsync();

  // Step 6: server force-renames to a Guest nick because the requested
  // nick was registered to a DID the connection didn't authenticate as.
  ws.recv(`:srv NOTICE * :Nick ${originalNick} is registered — renamed to ${guestNick}. Authenticate to reclaim.`);
  await flushAsync();

  // Step 7: server completes registration as guest
  ws.recv(`:srv 001 ${guestNick} :Welcome to freeq, ${guestNick} (guest)`);
  await flushAsync();
}

// ── Tests ─────────────────────────────────────────────────────────

describe('silent guest fallback after stale SASL (regression)', () => {
  it('emits authError on 904', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });
    const errors: string[] = [];
    client.on('authError', (e) => errors.push(e));

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/SASL/i);
  });

  it('does NOT report authDid after 904 + Guest 001 (would mislead UI)', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    // After 904 and a Guest 001, the client must NOT report itself as
    // authenticated. authDid must be null.
    expect(client.authDid).toBeNull();
  });

  it('emits authenticated(null/empty) after 904 so the store can clear authDid', async () => {
    // Without this, the app's c.on("authenticated", ...) never fires
    // with null on failure, so the store keeps the stale DID and the
    // UI keeps showing the verified badge next to the Guest nick.
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });

    const authEvents: Array<{ did: string; message: string }> = [];
    client.on('authenticated', (did, message) => authEvents.push({ did, message }));

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    // After SASL failure the SDK should fire an "authenticated" event
    // with an empty/null did so the app store can mirror the wire state.
    expect(authEvents.length).toBeGreaterThan(0);
    expect(authEvents.some(e => !e.did)).toBe(true);
  });

  it('does not silently emit "registered" with the Guest nick when SASL was attempted', async () => {
    // The smoking gun: today the SDK fires 'registered' with "Guest24609"
    // even though SASL was requested and failed. The app's
    // c.on('registered', nick => store.setNick(nick)) then writes the guest
    // nick into the store and the user types as Guest24609. The SDK must
    // either disconnect on 904 or refuse to fire 'registered' as a guest
    // when SASL was requested.
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });

    const registeredAs: string[] = [];
    client.on('registered', (nick) => registeredAs.push(nick));

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    const guestRegistration = registeredAs.find(n => /^Guest\d+$/.test(n));
    expect(
      guestRegistration,
      `expected SDK NOT to emit registered with a Guest nick after SASL failure, got: ${JSON.stringify(registeredAs)}`,
    ).toBeUndefined();
  });

  it('user-visible bug: sendMessage after the failed-reconnect must not silently send as Guest', async () => {
    // End-to-end repro of the production symptom: user goes to bed signed
    // in, comes back the next morning, replies — the message goes out as
    // GuestNNNNN. The SDK must NOT accept a sendMessage on a socket that
    // has degraded to guest after a SASL attempt. Either drop the send,
    // throw, or have already disconnected the socket.
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    // User types a reply.
    const sentBefore = ws.sent.length;
    client.sendMessage('#general', 'good morning');
    await flushAsync();
    const newWireLines = ws.sent.slice(sentBefore);
    const leakedPrivmsg = newWireLines.find(l => /^(@[^ ]* )?PRIVMSG /i.test(l));

    expect(
      leakedPrivmsg,
      `PRIVMSG must not leak onto a guest-degraded socket. Got: ${leakedPrivmsg}`,
    ).toBeUndefined();
  });

  it('does not reconnect after a 904, and a later connect() asks for SASL again, never as a guest', async () => {
    // The refused credentials are not replayed by an automatic reconnect,
    // because there is none; an app that connects again signs in again.
    vi.useFakeTimers();
    try {
      const { FreeqClient } = await import('./client.js');
      const client = new FreeqClient({
        url: 'wss://test/irc',
        nick: 'chad',
        skipInitialBrokerRefresh: true,
      });
      client.setSaslCredentials({
        token: 'stale-token',
        did: 'did:plc:chad',
        pdsUrl: 'https://pds.example',
        method: 'pds-session',
      });

      client.connect();
      const ws = MockWebSocket.instances[0];
      await runStaleSaslScenario(ws);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(MockWebSocket.instances).toHaveLength(1);

      client.connect();
      const again = MockWebSocket.instances[1]!;
      await flushAsync();
      again.recv(':srv CAP * LS :message-tags sasl');
      await flushAsync();
      expect(again.sent.find((l) => l.startsWith('CAP REQ'))).toContain('sasl');
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports the drop once, and writes nothing an authError listener sends', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'stale-token',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });
    const states: string[] = [];
    const drops: string[] = [];
    client.on('connectionStateChanged', (s) => states.push(s));
    client.on('disconnected', (r) => drops.push(r));
    // The socket is still open while the listeners run; the refusal has
    // already been recorded, so nothing they send reaches the server.
    client.on('authError', () => client.raw('PRIVMSG #general :from the listener'));

    client.connect();
    const ws = MockWebSocket.instances[0];
    await runStaleSaslScenario(ws);

    expect(ws.sent).not.toContain('PRIVMSG #general :from the listener');
    expect(states.filter((s) => s === 'disconnected')).toHaveLength(1);
    expect(drops).toHaveLength(1);
  });
});

// ── Silent guest fallback via broker-refresh failure (no 904) ─────
//
// The original regression above covers the path where the server actively
// sends 904. But on an idle reconnect the SDK first tries to refresh the
// broker session, and a SLOW or FAILED broker refresh used to register us as
// a guest *client-side* — without any 904, so `_saslFailed` stayed false,
// `authenticated('')` never fired (store kept the stale DID → verified badge
// next to a Guest nick), and PRIVMSGs leaked under the guest identity.

describe('silent guest fallback via broker-refresh failure (no 904)', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => { globalThis.fetch = realFetch; });

  async function connectAuthedWithBroker() {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      brokerUrl: 'https://broker.example',
      brokerToken: 'broker-tok',
      // No token + skipInitialBrokerRefresh=false → the connected handler takes
      // the broker-refresh branch (this is the idle-reconnect shape).
    });
    client.setSaslCredentials({
      token: '',
      did: 'did:plc:chad',
      pdsUrl: '',
      method: 'web-token',
    });
    return client;
  }

  it('rejecting broker refresh must NOT register as guest; it tears down + clears auth', async () => {
    vi.useFakeTimers();
    globalThis.fetch = vi.fn(() => Promise.reject(new Error('network down'))) as any;

    const client = await connectAuthedWithBroker();
    const authErrors: string[] = [];
    const authEvents: string[] = [];
    const registeredAs: string[] = [];
    client.on('authError', (e) => authErrors.push(e));
    client.on('authenticated', (did) => authEvents.push(did));
    client.on('registered', (n) => registeredAs.push(n));

    client.connect();
    // Drive the rejected fetch + its retry backoffs (500ms, 1000ms) to exhaustion.
    await vi.advanceTimersByTimeAsync(5000);
    // No second socket once every timer has run.
    await vi.advanceTimersByTimeAsync(60_000);
    vi.useRealTimers();

    expect(authErrors.length, 'should surface an auth error').toBeGreaterThan(0);
    expect(authEvents.some((d) => !d), 'must emit authenticated("") so the store clears authDid').toBe(true);
    expect(client.authDid, 'authDid must be cleared').toBeNull();
    expect(registeredAs.find((n) => /^Guest\d+$/.test(n)), 'must not register as a guest').toBeUndefined();
    expect(MockWebSocket.instances).toHaveLength(1);
    // Kept, so an app that connects this client again signs in again.
    expect((client as unknown as { sasl: { did: string } | null }).sasl?.did).toBe('did:plc:chad');
  });

  it('a failed broker refresh reports the drop once', async () => {
    vi.useFakeTimers();
    globalThis.fetch = vi.fn(() => Promise.reject(new Error('network down'))) as any;

    const client = await connectAuthedWithBroker();
    const states: string[] = [];
    client.on('connectionStateChanged', (s) => states.push(s));

    client.connect();
    await vi.advanceTimersByTimeAsync(5000);
    vi.useRealTimers();

    expect(states.filter((s) => s === 'disconnected')).toHaveLength(1);
    expect(client.connectionState).toBe('disconnected');
  });

  it('a guest-degraded socket must not let sendMessage leak a PRIVMSG', async () => {
    vi.useFakeTimers();
    globalThis.fetch = vi.fn(() => Promise.reject(new Error('network down'))) as any;

    const client = await connectAuthedWithBroker();
    client.connect();
    await vi.advanceTimersByTimeAsync(5000);
    vi.useRealTimers();

    const ws = MockWebSocket.instances[0];
    const before = ws.sent.length;
    client.sendMessage('#general', 'good morning');
    await flushAsync();
    const leaked = ws.sent.slice(before).find((l) => /^(@[^ ]* )?PRIVMSG /i.test(l));
    expect(leaked, 'PRIVMSG must not leak under the guest identity').toBeUndefined();
  });

  it('genuine guest reconnect (no DID) is unaffected — still registers normally', async () => {
    // No sasl set at all → the broker branch is skipped and a guest registers.
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });
    const registeredAs: string[] = [];
    client.on('registered', (n) => registeredAs.push(n));

    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[0];
    ws.recv(':srv CAP * LS :message-tags server-time');
    await flushAsync();
    ws.recv(':srv 001 visitor :Welcome');
    await flushAsync();

    expect(registeredAs).toContain('visitor');
  });
});

// ── Verifies the server NOTICE pattern that signals guest rename ──

describe('Guest rename detection', () => {
  it('matches the server-emitted "Nick X is registered — renamed to GuestNNN" pattern', () => {
    const notice = 'Nick chad is registered — renamed to Guest24609. Authenticate to reclaim.';
    // Both em-dash variants exist in the wild.
    const pattern = /is registered.*renamed to (Guest\d+)/i;
    const m = notice.match(pattern);
    expect(m).not.toBeNull();
    expect(m![1]).toBe('Guest24609');
  });

  it('Guest nick pattern is identifiable (Guest followed by digits)', () => {
    expect(/^Guest\d+$/.test('Guest24609')).toBe(true);
    expect(/^Guest\d+$/.test('Guest0')).toBe(true);
    expect(/^Guest\d+$/.test('chad')).toBe(false);
  });
});

// ── A bot signs with a signer and no token ────────────────────────

describe('a refusal on a signer-authenticated connection', () => {
  it('tears the socket down instead of registering as a guest', async () => {
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'helper',
      skipInitialBrokerRefresh: true,
    });
    // How a bot authenticates: its own key signs the challenge, and there
    // is no web token. Before, the 904 handler read only the token, so a
    // bot whose access had been withdrawn carried on into registration.
    client.setSaslCredentials({
      did: 'did:key:zHelper',
      method: 'crypto',
      token: '',
      pdsUrl: '',
      signer: async () => 'c2ln',
    });
    const errors: string[] = [];
    const states: string[] = [];
    client.on('authError', (e) => errors.push(e));
    client.on('connectionStateChanged', (s) => states.push(s));

    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await runSignerRefusal(ws);
    // Past the transport's first reconnect (1 s), so that a socket it
    // opened would be counted below.
    await vi.advanceTimersByTimeAsync(5000);
    vi.useRealTimers();

    expect(errors).toHaveLength(1);
    // It did not go on to register: no CAP END after the 904.
    expect(ws.sent).not.toContain('CAP END');
    // The drop is reported once.
    expect(states.filter((s) => s === 'disconnected')).toHaveLength(1);
    // The welcome that follows a guest registration must not be taken.
    expect(client.registered).toBe(false);
    // And nothing reconnects: the teardown is deliberate.
    expect(MockWebSocket.instances).toHaveLength(1);
  });
});

/** Drive a signer-authenticated connection to a 904, then have the server
 *  carry on with a guest welcome as it really does. */
async function runSignerRefusal(ws: MockWebSocket) {
  ws.recv(':srv CAP * LS :message-tags server-time batch sasl echo-message');
  await flushAsync();
  ws.recv(':srv CAP helper ACK :message-tags server-time batch sasl echo-message');
  await flushAsync();
  const challenge = btoa(JSON.stringify({ session_id: 's', nonce: 'n', timestamp: Date.now() }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  ws.recv(`AUTHENTICATE ${challenge}`);
  await flushAsync();
  ws.recv(':srv 904 helper :SASL authentication failed');
  await flushAsync();
  ws.recv(':srv 001 helper :Welcome to freeq, helper (guest)');
  await flushAsync();
}
