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
