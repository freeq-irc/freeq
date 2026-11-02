/**
 * The client's verdicts on a refused connection (refusal.ts): a refused key
 * and a final sign-in refusal end it, a try-again keeps reconnecting on the
 * growing wait, and the listeners hear the verdict before the drop.
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
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function flushAsync() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

const WORDS = 'the server says so';

async function signedIn(over: Record<string, unknown> = {}) {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({ url: 'wss://test/irc', nick: 'chad', skipInitialBrokerRefresh: true, ...over });
  client.setSaslCredentials({ token: 'tok', did: 'did:plc:chad', pdsUrl: 'https://pds.example', method: 'pds-session' });
  const events: string[] = [];
  for (const ev of ['authError', 'authErrorRetry', 'signingKeyRefused', 'disconnected', 'registered'] as const) {
    client.on(ev, ((...a: unknown[]) => events.push(`${ev}:${String(a[0] ?? '')}`)) as never);
  }
  client.on('connectionStateChanged', (s) => events.push(`state:${s}`));
  client.connect();
  await flushAsync();
  return { client, events };
}

/** Lines from the server on the newest socket, then the client's queue run. */
async function serverSays(...lines: string[]) {
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  for (const line of lines) ws.recv(line);
  await flushAsync();
}

const afterConnected = (events: string[]) => events.slice(events.indexOf('state:connected') + 1);

describe('a final sign-in refusal', () => {
  it('ends the connection after the verdict, believes no 904 behind it, and opens no second socket', async () => {
    const { client, events } = await signedIn();
    await serverSays(`:srv FAIL AUTHENTICATE NOT_ALLOWED :${WORDS}`, ':srv 904 chad :SASL authentication failed');
    expect(afterConnected(events)).toEqual([
      `authError:${WORDS}`,
      'state:disconnected',
      'disconnected:transport closed',
    ]);
    expect(client.saslFailed).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it('is what a bare 904 means too', async () => {
    const { client, events } = await signedIn();
    await serverSays(':srv 904 chad :SASL authentication failed');
    expect(afterConnected(events)).toEqual([
      'authError:SASL authentication failed',
      'state:disconnected',
      'disconnected:transport closed',
    ]);
    expect(client.saslFailed).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(1);
  });
});

describe('a try-again refusal', () => {
  it('reconnects after 1, 2 and 4 s, saying why each time before the drop, and never as final', async () => {
    const { events } = await signedIn();
    for (const wait of [1000, 2000, 4000]) {
      const before = MockWebSocket.instances.length;
      await serverSays(`:srv FAIL AUTHENTICATE TEMPORARILY_UNAVAILABLE :${WORDS}`, ':srv 904 chad :SASL authentication failed');
      const said = events.lastIndexOf(`authErrorRetry:${WORDS}`);
      expect(said).toBeGreaterThan(-1);
      expect(events.indexOf('state:disconnected', said)).toBeGreaterThan(said);
      await vi.advanceTimersByTimeAsync(wait - 1);
      expect(MockWebSocket.instances).toHaveLength(before);
      await vi.advanceTimersByTimeAsync(1);
      await flushAsync();
      expect(MockWebSocket.instances).toHaveLength(before + 1);
      // The refusal held for the last socket only: this one registers.
      expect(MockWebSocket.instances[before]!.sent.some((l) => l.startsWith('CAP LS'))).toBe(true);
    }
    expect(events.filter((e) => e === `authErrorRetry:${WORDS}`)).toHaveLength(3);
    expect(events.filter((e) => e.startsWith('authError:'))).toEqual([]);
  });
});

describe('a try-again refusal and a welcome still queued behind it', () => {
  it('keeps the wait growing: the 001 of a refused socket is not believed', async () => {
    const { events } = await signedIn();
    for (const wait of [1000, 2000]) {
      const before = MockWebSocket.instances.length;
      await serverSays(
        `:srv FAIL AUTHENTICATE TEMPORARILY_UNAVAILABLE :${WORDS}`,
        ':srv 904 chad :SASL authentication failed',
        ':srv 001 chad :Welcome',
      );
      await vi.advanceTimersByTimeAsync(wait - 1);
      expect(MockWebSocket.instances).toHaveLength(before);
      await vi.advanceTimersByTimeAsync(1);
      await flushAsync();
      expect(MockWebSocket.instances).toHaveLength(before + 1);
    }
    expect(events.filter((e) => e.startsWith('registered:'))).toEqual([]);
  });
});

describe('a refused signing key', () => {
  it('ends the connection after the verdict, and stays at one socket', async () => {
    const { events } = await signedIn();
    await serverSays(':srv 001 chad :Welcome', `:srv FAIL MSGSIG KEY_RETIRED :${WORDS}`);
    await flushAsync();
    const said = events.indexOf(`signingKeyRefused:${WORDS}`);
    expect(said).toBeGreaterThan(-1);
    expect(events.slice(said)).toEqual([
      `signingKeyRefused:${WORDS}`,
      'state:disconnected',
      'disconnected:transport closed',
    ]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(1);
  });
});

describe('a nick taken under the refuse policy', () => {
  it('reports authError without marking a refused sign-in', async () => {
    const { client, events } = await signedIn({ onNickCollision: 'refuse' });
    await serverSays(':srv 433 * chad :Nickname is already in use');
    expect(events.some((e) => e.startsWith('authError:'))).toBe(true);
    expect(client.saslFailed).toBe(false);
  });
});
