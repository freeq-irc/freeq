/**
 * A guest's nick is their whole identity, so an automatic reconnect has to
 * bring the guest back as the same person in the same rooms.
 *
 * These tests drive the real Transport auto-reconnect (socket close →
 * backoff timer → new WebSocket), not `client.reconnect()`, because the
 * production trigger is an unexpected close.
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

  recv(line: string) {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

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
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ── Helpers ───────────────────────────────────────────────────────

async function flushAsync() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

/** Drive registration to completion as a guest (no SASL). */
async function registerAsGuest(ws: MockWebSocket, nick: string) {
  await flushAsync();
  ws.recv(':srv CAP * LS :message-tags server-time batch echo-message account-notify extended-join away-notify');
  await flushAsync();
  ws.recv(`:srv CAP ${nick} ACK :message-tags server-time batch echo-message account-notify extended-join away-notify`);
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome to freeq, ${nick} (guest)`);
  await flushAsync();
}

/** Close the live socket and let the transport's backoff fire, returning
 *  the WebSocket the reconnect opened. Requires fake timers. */
async function autoReconnect(ws: MockWebSocket): Promise<MockWebSocket> {
  const before = MockWebSocket.instances.length;
  ws.close();
  await flushAsync();
  // Transport backoff for the first attempt is 1000ms.
  await vi.advanceTimersByTimeAsync(1100);
  await flushAsync();
  const next = MockWebSocket.instances[before];
  expect(next, 'transport should have opened a new WebSocket').toBeDefined();
  return next;
}

// ═══════════════════════════════════════════════════════════════════
// Channel rejoin
// ═══════════════════════════════════════════════════════════════════

describe('guest auto-reconnect: channels', () => {
  it('rejoins the channels it was in', async () => {
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });

    client.connect();
    const ws1 = MockWebSocket.instances[0];
    await registerAsGuest(ws1, 'visitor');

    client.join('#lounge');
    ws1.recv(':visitor!u@h JOIN #lounge');
    client.join('#news');
    ws1.recv(':visitor!u@h JOIN #news');
    await flushAsync();

    const ws2 = await autoReconnect(ws1);
    await registerAsGuest(ws2, 'visitor');

    const joins = ws2.sent.filter((l) => l.startsWith('JOIN '));
    expect(joins).toContain('JOIN #lounge');
    expect(joins).toContain('JOIN #news');
  });
});

// ═══════════════════════════════════════════════════════════════════
// Nick resume
// ═══════════════════════════════════════════════════════════════════

/** Registration lines the client sends on a fresh connection. */
function nickLines(ws: MockWebSocket, nick: string): string[] {
  return ws.sent.filter((l) => l === `NICK ${nick}`);
}

describe('guest auto-reconnect: nick', () => {
  it('reclaims the same nick when 433 is the previous session still holding it', async () => {
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });

    client.connect();
    const ws1 = MockWebSocket.instances[0];
    await registerAsGuest(ws1, 'visitor');
    expect(client.nick).toBe('visitor');

    const ws2 = await autoReconnect(ws1);
    expect(nickLines(ws2, 'visitor')).toHaveLength(1);

    // The server hasn't reaped the dead session yet.
    ws2.recv(':srv 433 * visitor :Nickname is already in use');
    await flushAsync();
    expect(
      ws2.sent.find((l) => l.startsWith('NICK visitor_')),
      'must not rename itself while the ghost may still clear',
    ).toBeUndefined();
    expect(nickLines(ws2, 'visitor'), 'the retry is on a backoff, not immediate').toHaveLength(1);

    await vi.advanceTimersByTimeAsync(600);
    expect(nickLines(ws2, 'visitor'), 'the original nick is asked for again').toHaveLength(2);

    // Ghost reaped: registration completes under the original nick.
    ws2.recv(':srv CAP * LS :message-tags server-time');
    await flushAsync();
    ws2.recv(':srv 001 visitor :Welcome to freeq, visitor (guest)');
    await flushAsync();

    expect(client.nick).toBe('visitor');
    expect(ws2.sent.some((l) => l.startsWith('NICK visitor_'))).toBe(false);
  });

  it('falls back to the suffix policy once the retry budget is spent', async () => {
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });

    client.connect();
    const ws1 = MockWebSocket.instances[0];
    await registerAsGuest(ws1, 'visitor');

    const ws2 = await autoReconnect(ws1);

    // Someone else genuinely holds the nick: every retry is refused.
    for (const delay of [600, 1100, 2100]) {
      ws2.recv(':srv 433 * visitor :Nickname is already in use');
      await flushAsync();
      await vi.advanceTimersByTimeAsync(delay);
    }
    expect(nickLines(ws2, 'visitor'), 'registration + three retries').toHaveLength(4);
    expect(ws2.sent.some((l) => l.startsWith('NICK visitor_'))).toBe(false);

    ws2.recv(':srv 433 * visitor :Nickname is already in use');
    await flushAsync();
    expect(
      ws2.sent.find((l) => l === 'NICK visitor_'),
      'budget spent — the existing collision policy takes over',
    ).toBeDefined();

    ws2.recv(':srv 001 visitor_ :Welcome to freeq, visitor_ (guest)');
    await flushAsync();
    expect(client.nick).toBe('visitor_');
  });

  it('a collision on a first connect renames immediately, as before', async () => {
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });

    client.connect();
    const ws = MockWebSocket.instances[0];
    await flushAsync();

    ws.recv(':srv 433 * visitor :Nickname is already in use');
    await flushAsync();

    expect(
      ws.sent.find((l) => l === 'NICK visitor_'),
      'no session to resume: the nick belongs to someone else',
    ).toBeDefined();
  });

  it('an authenticated session does not take the guest resume path', async () => {
    // Its identity is the DID, and its resume path is SASL. The 433 handling
    // it had before this stays exactly as it was.
    vi.useFakeTimers();
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'chad',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 'tok',
      did: 'did:plc:chad',
      pdsUrl: 'https://pds.example',
      method: 'pds-session',
    });

    client.connect();
    const ws1 = MockWebSocket.instances[0];
    await flushAsync();
    // Server offers no sasl cap, so registration completes without a SASL
    // exchange and we get a session to (not) resume.
    ws1.recv(':srv CAP * LS :message-tags server-time');
    await flushAsync();
    ws1.recv(':srv 001 chad :Welcome to freeq, chad');
    await flushAsync();

    const ws2 = await autoReconnect(ws1);
    ws2.recv(':srv 433 * chad :Nickname is already in use');
    await flushAsync();

    expect(ws2.sent.find((l) => l === 'NICK chad_')).toBeDefined();
  });
});
