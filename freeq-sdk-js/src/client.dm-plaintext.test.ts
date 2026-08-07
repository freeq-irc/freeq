/**
 * DMs are not auto-encrypted.
 *
 * The per-message-key scheme makes history readable only on the device that
 * held the session; with no multi-device or durable-history model around it,
 * auto-encrypting DMs silently trades away the user's history. Until that
 * model exists, a DM goes signed-plaintext even when E2EE is fully ready —
 * this test is the pin that keeps the trade explicit.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'crypto';
import type { FreeqClient } from './client.js';
import * as e2ee from './e2ee.js';

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

  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string): void {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.({});
  }

  recv(line: string): void {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 12; i++) await new Promise((r) => setTimeout(r, 5));
}

async function makeClient(nick: string): Promise<{ client: FreeqClient; ws: MockWebSocket }> {
  const caps = 'message-tags server-time batch echo-message';
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick,
    skipInitialBrokerRefresh: true,
  });
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(`:srv CAP * LS :${caps}`);
  await flushAsync();
  ws.recv(`:srv CAP * ACK :${caps}`);
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

describe('a DM stays plaintext even with E2EE fully ready', () => {
  it('sends the readable text and never consults the DM encryptor', async () => {
    vi.spyOn(e2ee, 'isE2eeReady').mockReturnValue(true);
    const encryptSpy = vi.spyOn(e2ee, 'encryptMessage');

    const { client, ws } = await makeClient('alice');
    client.sendMessage('did:plc:bob-the-recipient', 'readable on every device');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes('PRIVMSG did:plc:bob-the-recipient'));
    expect(line, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(line).toContain('readable on every device');
    expect(line).not.toContain('+encrypted');
    expect(line).not.toContain('ENC');
    expect(encryptSpy).not.toHaveBeenCalled();
  });

  it('a channel with a shared key still encrypts — the pause is DM-scoped', async () => {
    const channel = '#still-encrypted';
    await e2ee.setChannelKey(channel, 'a shared passphrase');
    const { client, ws } = await makeClient('alice');

    client.sendMessage(channel, 'the quiet part');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${channel}`));
    expect(line, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(line).toContain('+encrypted');
    expect(line).not.toContain('the quiet part');
    e2ee.removeChannelKey(channel);
  });
});
