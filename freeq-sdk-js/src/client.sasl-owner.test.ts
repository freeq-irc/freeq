/**
 * The SASL response names the account an agent acts for, when told one.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { FreeqClient } from './client.js';

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
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

/** Drive a crypto-SASL client to its challenge response; the AUTHENTICATE
 *  lines it sent after naming the mechanism. */
async function responseLines(ownerDid?: string, signature = 'c2ln'): Promise<string[]> {
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'helper',
    skipInitialBrokerRefresh: true,
  });
  client.setSaslCredentials({
    token: '',
    did: 'did:key:z6MkAgent',
    pdsUrl: '',
    method: 'crypto',
    signer: async () => signature,
    ownerDid,
  });
  client.connect();
  const ws = MockWebSocket.instances[0];
  await flushAsync();
  ws.recv(':srv CAP * LS :sasl message-tags');
  await flushAsync();
  ws.recv(':srv CAP helper ACK :sasl message-tags');
  await flushAsync();
  const challenge = btoa(JSON.stringify({ session_id: 's1', nonce: 'n1', timestamp: Date.now() }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  ws.recv(`AUTHENTICATE ${challenge}`);
  await flushAsync();
  return ws.sent.filter(l => l.startsWith('AUTHENTICATE ') && l !== 'AUTHENTICATE ATPROTO-CHALLENGE');
}

/** The decoded response payload a crypto-SASL client sends. */
async function respondToChallenge(ownerDid?: string): Promise<Record<string, unknown>> {
  const [line] = await responseLines(ownerDid);
  expect(line).toBeDefined();
  const encoded = line!.slice('AUTHENTICATE '.length).replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(encoded));
}

describe('SASL response', () => {
  it('names the owner it was given', async () => {
    const payload = await respondToChallenge('did:plc:owner');
    expect(payload.owner_did).toBe('did:plc:owner');
    expect(payload.did).toBe('did:key:z6MkAgent');
  });

  it('carries no owner field when none was given', async () => {
    const payload = await respondToChallenge();
    expect('owner_did' in payload).toBe(false);
  });
});

describe('SASL response on the wire', () => {
  /** A server that predates chunk reassembly reads only the first line. */
  it('goes out as one line with no terminator, however long', async () => {
    const lines = await responseLines('did:plc:tmxbvcho3zysvtadtextctxw', 'x'.repeat(500));
    expect(lines).toHaveLength(1);
    expect(lines[0]!.length).toBeGreaterThan('AUTHENTICATE '.length + 400);
  });
});
