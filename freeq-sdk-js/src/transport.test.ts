/**
 * The wait between reconnects. A server that accepts the socket and then
 * refuses the client before welcoming it is retried on a growing wait; once
 * the server has welcomed the client (001), the wait starts again at 1 s.
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

/** Close the newest socket as a server would, and check the next one opens
 *  exactly `ms` later: not a millisecond sooner. */
async function closedThenReopenedAfter(ms: number) {
  const before = MockWebSocket.instances.length;
  MockWebSocket.instances[before - 1]!.close();
  await vi.advanceTimersByTimeAsync(ms - 1);
  expect(MockWebSocket.instances.length, `no new socket before ${ms} ms`).toBe(before);
  await vi.advanceTimersByTimeAsync(1);
  expect(MockWebSocket.instances.length, `a new socket at ${ms} ms`).toBe(before + 1);
  await flushAsync();
}

describe('the wait between reconnects', () => {
  it('grows 1, 2, 4 s while each socket opens and closes before a welcome', async () => {
    const { Transport } = await import('./transport.js');
    const transport = new Transport({
      url: 'wss://test/irc',
      onLine: () => {},
      onStateChange: () => {},
    });
    transport.connect();
    await flushAsync();

    await closedThenReopenedAfter(1000);
    await closedThenReopenedAfter(2000);
    await closedThenReopenedAfter(4000);
    transport.disconnect();
  });

  it('starts again at 1 s once the server has welcomed the client', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'visitor' });
    client.connect();
    await flushAsync();

    // Two sockets the server closes before any welcome.
    await closedThenReopenedAfter(1000);
    await closedThenReopenedAfter(2000);

    // The third is welcomed; when it drops, the wait is 1 s again.
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv CAP * LS :message-tags');
    await flushAsync();
    ws.recv(':srv 001 visitor :Welcome to freeq, visitor (guest)');
    await flushAsync();
    expect(client.registered).toBe(true);
    await closedThenReopenedAfter(1000);
    client.disconnect();
  });

  it('restart() closes the socket, reports the drop and reconnects on the wait', async () => {
    const { Transport } = await import('./transport.js');
    const states: string[] = [];
    const transport = new Transport({
      url: 'wss://test/irc',
      onLine: () => {},
      onStateChange: (s) => states.push(s),
    });
    transport.connect();
    await flushAsync();
    const first = MockWebSocket.instances[0]!;
    states.length = 0;

    transport.restart();
    expect(first.readyState).toBe(3);
    expect(states).toEqual(['disconnected']);
    await vi.advanceTimersByTimeAsync(999);
    expect(MockWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(MockWebSocket.instances).toHaveLength(2);
    // The old socket's own close, had it come, is not reported.
    first.onclose?.({});
    await flushAsync();
    expect(states).toEqual(['disconnected', 'connecting', 'connected']);
    transport.disconnect();
  });
});
