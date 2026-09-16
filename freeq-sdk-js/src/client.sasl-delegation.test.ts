/**
 * Tests for the SASL challenge response in client.ts.
 *
 * The agent's delegation certificate rides the response, which puts a typical
 * one past a single chunk. These cover the wire shape, the chunk boundaries,
 * and the ceiling.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { FreeqClient } from './client.js';

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

  /** Test helper: deliver a server line to the client. */
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

// ── Helpers ───────────────────────────────────────────────────────

async function flushAsync() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

const AGENT_DID = 'did:key:z6MkfakeAgentKeyForTests';

function signedCert() {
  return {
    type: 'FreeqBotDelegation/v1',
    bot_did: AGENT_DID,
    bot_public_key: 'z6MkfakeAgentKeyForTests',
    creator_did: 'did:plc:owner',
    created_at: '2026-09-07T00:00:00Z',
    revocation_authority: 'did:plc:owner',
    signature: 'c2lnbmF0dXJl',
  };
}

/** Drive a client to the point where it has answered the challenge, and
 *  return every AUTHENTICATE line it sent. */
async function runSasl(delegation?: unknown): Promise<string[]> {
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'agent',
    sasl: {
      did: AGENT_DID,
      method: 'crypto',
      signer: async () => 'ZmFrZS1zaWduYXR1cmU',
      token: '',
      pdsUrl: '',
      delegation,
    },
  });
  client.connect();
  await flushAsync();
  // The newest socket: a test may drive several connects.
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];

  ws.recv(':srv CAP * LS :message-tags sasl');
  await flushAsync();
  ws.recv(':srv CAP agent ACK :message-tags sasl');
  await flushAsync();

  const challenge = btoa(
    JSON.stringify({ session_id: 'sess1', nonce: 'nonce-deadbeef', timestamp: Date.now() }),
  )
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  // Only what the client sends in answer to the challenge: everything before
  // this is its own `AUTHENTICATE ATPROTO-CHALLENGE`.
  const before = ws.sent.length;
  ws.recv(`AUTHENTICATE ${challenge}`);
  await flushAsync();

  return ws.sent.slice(before).filter((l) => l.startsWith('AUTHENTICATE '));
}

/** The JSON the client put in its challenge response, reassembled the way
 *  the server does it. */
function decodeResponse(lines: string[]): Record<string, unknown> {
  const joined = lines
    .map((l) => l.slice('AUTHENTICATE '.length))
    .filter((p) => p !== '+')
    .join('');
  const b64 = joined.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(atob(padded));
}

// ── Tests ─────────────────────────────────────────────────────────

describe('SASL delegation', () => {
  it('sends the certificate with the challenge response', async () => {
    const cert = signedCert();
    const response = decodeResponse(await runSasl(cert));
    expect(response.delegation).toEqual(cert);
    expect(response.did).toBe(AGENT_DID);
  });

  it('omits the field entirely when there is no certificate', async () => {
    const response = decodeResponse(await runSasl(undefined));
    expect('delegation' in response).toBe(false);
  });

  // A cert puts a typical response past one chunk.
  it('splits a response that outgrows a single chunk', async () => {
    const cert = { ...signedCert(), padding: 'x'.repeat(600) };
    const lines = await runSasl(cert);

    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) {
      expect(line.slice('AUTHENTICATE '.length).length).toBeLessThanOrEqual(400);
    }
    expect(decodeResponse(lines).delegation).toEqual(cert);
  });

  // The terminator is what ends a response that fills its last chunk.
  it('terminates a response that lands exactly on a chunk boundary', async () => {
    // Pad until the encoded length is a whole number of chunks.
    let lines: string[] = [];
    for (let pad = 0; pad < 400; pad++) {
      lines = await runSasl({ ...signedCert(), padding: 'x'.repeat(600 + pad) });
      const encoded = lines
        .map((l) => l.slice('AUTHENTICATE '.length))
        .filter((p) => p !== '+')
        .join('');
      if (encoded.length % 400 === 0) break;
      lines = [];
    }
    expect(lines.length).toBeGreaterThan(0);
    expect(lines[lines.length - 1]).toBe('AUTHENTICATE +');
  });

  // The exact boundary: one full chunk, with nothing shorter to follow it.
  it('terminates a response of exactly one chunk', async () => {
    let lines: string[] = [];
    for (let pad = 0; pad < 600; pad++) {
      const candidate = await runSasl({ padding: 'x'.repeat(pad) });
      const payload = candidate
        .map((l) => l.slice('AUTHENTICATE '.length))
        .filter((p) => p !== '+')
        .join('');
      if (payload.length === 400) {
        lines = candidate;
        break;
      }
    }

    expect(lines, 'no padding length produced a 400-char payload').not.toEqual([]);
    expect(lines).toHaveLength(2);
    expect(lines[0].slice('AUTHENTICATE '.length)).toHaveLength(400);
    expect(lines[1]).toBe('AUTHENTICATE +');
  });

  it('aborts on a response larger than the server will reassemble', async () => {
    const errors: unknown[] = [];
    vi.spyOn(console, 'error').mockImplementation((...args) => {
      errors.push(args[0]);
    });

    const lines = await runSasl({ ...signedCert(), padding: 'x'.repeat(9000) });

    expect(lines).toEqual(['AUTHENTICATE *']);
    expect(String(errors[0])).toContain('over the 8192');
  });
});
