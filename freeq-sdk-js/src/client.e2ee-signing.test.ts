/**
 * An encrypted message is signed like any other message.
 *
 * The document's body field is a hash of the WIRE body, so under E2EE it
 * covers the ciphertext — exactly the bytes the server and every federated
 * receiver hold. Nothing about the canonical changes; what changes is that
 * the encrypted send path goes through the signing path at all.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'crypto';
import type { FreeqClient } from './client.js';
import * as signing from './signing.js';
import * as e2ee from './e2ee.js';

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
  // Real Web Crypto: Ed25519 for the signature, PBKDF2 + AES-GCM for ENC1.
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

/**
 * A registered client. `caps` is what the server advertises and acks, so a
 * legacy server is expressed by leaving `freeq.at/msgsig` out of it.
 */
async function makeClient(
  nick: string,
  caps = 'message-tags server-time batch echo-message freeq.at/msgsig ' +
    'draft/multiline=max-bytes=40000,max-lines=100',
): Promise<{ client: FreeqClient; ws: MockWebSocket }> {
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
  ws.recv(`:srv CAP * ACK :${caps.replace(/=[^ ]*/g, '')}`);
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

/** Provision a real Ed25519 session key on a client and return the public half. */
async function provisionSigningKey(
  owner: { signing: signing.SessionSigning },
  did: string,
): Promise<CryptoKey> {
  owner.signing.setSigningDid(did);
  await owner.signing.generateSigningKey();
  const pubB64 = owner.signing.getPublicKey();
  if (!pubB64) throw new Error('signing key not provisioned');
  const padded = pubB64 + '='.repeat((4 - (pubB64.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
    c.charCodeAt(0),
  );
  return crypto.subtle.importKey('raw', bytes, 'Ed25519', false, ['verify']);
}

async function verifySig(canonical: string, sigTag: string, key: CryptoKey): Promise<boolean> {
  const sigB64 = sigTag.split(':')[2]!;
  const padded = sigB64 + '='.repeat((4 - (sigB64.length % 4)) % 4);
  const sig = Uint8Array.from(atob(padded.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
    c.charCodeAt(0),
  );
  return crypto.subtle.verify('Ed25519', key, sig, new TextEncoder().encode(canonical));
}

function tagOf(line: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  return line.match(new RegExp(`${escaped}=([^;\\s]+)`))?.[1];
}

/**
 * The body of a PRIVMSG frame. The trailing param only carries a leading
 * colon when it needs one, and ciphertext (no spaces) does not.
 */
function bodyOf(line: string): string {
  const body = line.replace(/^(@\S+ )?PRIVMSG \S+ /, '').trimEnd();
  return body.startsWith(':') ? body.slice(1) : body;
}

const DID = 'did:plc:encrypted-signer';

describe('an encrypted message is signed over its ciphertext', () => {
  it('one PRIVMSG carries the encryption tag, the event id and a signature over the wire body', async () => {
    const channel = '#enc-signed-single';
    await e2ee.setChannelKey(channel, 'a passphrase the room shares');
    const { client, ws } = await makeClient('alice');
    const verifyKey = await provisionSigningKey(client, DID);

    client.sendMessage(channel, 'the quiet part');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${channel}`));
    expect(line, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(line).toContain('+encrypted');
    const ciphertext = bodyOf(line!);
    expect(ciphertext.startsWith('ENC1:'), `body: ${ciphertext}`).toBe(true);
    expect(ciphertext).not.toContain('the quiet part');

    const eventId = tagOf(line!, '+freeq.at/eventid');
    const sigTag = tagOf(line!, '+freeq.at/sig');
    expect(eventId, `line: ${line}`).toBeDefined();
    expect(sigTag).toBeDefined();

    const canonical = await signing.messageCanonical({
      from: DID,
      msgid: eventId!,
      target: signing.channelVenue(channel),
      body: ciphertext,
    });
    expect(
      await verifySig(canonical, sigTag!, verifyKey),
      'the signature covers the bytes on the wire, which under E2EE is the ciphertext',
    ).toBe(true);
  });

  it('a ciphertext-chunked batch signs the assembled ciphertext on its opener', async () => {
    const channel = '#enc-signed-multi';
    await e2ee.setChannelKey(channel, 'a passphrase the room shares');
    const { client, ws } = await makeClient('alice');
    const verifyKey = await provisionSigningKey(client, DID);

    const paragraph = 'Long enough that the ciphertext will not fit one line. '.repeat(30);
    const text = Array.from({ length: 5 }, (_, i) => `line${i}: ${paragraph}`).join('\n');
    client.sendMessage(channel, text);
    await flushAsync();

    const opener = ws.sent.find((l) => l.includes('BATCH +') && l.includes('draft/multiline'));
    const chunks = ws.sent.filter((l) => l.includes('PRIVMSG') && l.includes('batch='));
    expect(opener, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(chunks.length).toBeGreaterThanOrEqual(2);

    // Every chunk stays encrypted, and none of them carries the signature —
    // the document covers the assembled body, which only the opener names.
    for (const c of chunks) {
      expect(c).toContain('+encrypted');
      expect(c).not.toContain('+freeq.at/sig');
    }

    const eventId = tagOf(opener!, '+freeq.at/eventid');
    const sigTag = tagOf(opener!, '+freeq.at/sig');
    expect(eventId, `opener: ${opener}`).toBeDefined();
    expect(sigTag).toBeDefined();

    // Chunks of one ciphertext are all concat, so the assembled body is the
    // chunk bodies joined with no separator.
    const assembled = chunks.map(bodyOf).join('');
    expect(assembled.startsWith('ENC1:')).toBe(true);
    const canonical = await signing.messageCanonical({
      from: DID,
      msgid: eventId!,
      target: signing.channelVenue(channel),
      body: assembled,
    });
    expect(await verifySig(canonical, sigTag!, verifyKey)).toBe(true);
  });

  it('an encrypted reply signs the message it answers', async () => {
    const channel = '#enc-signed-reply';
    await e2ee.setChannelKey(channel, 'a passphrase the room shares');
    const { client, ws } = await makeClient('alice');
    const verifyKey = await provisionSigningKey(client, DID);

    client.sendReply(channel, '01ROOTMSGID', 'answering in the dark');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${channel}`))!;
    const canonical = await signing.messageCanonical({
      from: DID,
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: signing.channelVenue(channel),
      body: bodyOf(line),
      reply: '01ROOTMSGID',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('a server that does not verify documents sees an unsigned encrypted message', async () => {
    const channel = '#enc-legacy';
    await e2ee.setChannelKey(channel, 'a passphrase the room shares');
    const { client, ws } = await makeClient('alice', 'message-tags server-time batch echo-message');
    await provisionSigningKey(client, DID);

    client.sendMessage(channel, 'as far as this server can tell, nothing is new');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${channel}`));
    expect(line, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(line).toContain('+encrypted');
    for (const sent of ws.sent) {
      expect(sent).not.toContain('+freeq.at/sig');
      expect(sent).not.toContain('+freeq.at/eventid');
    }
  });

  it('an encrypted message that cannot be encrypted still goes out signed', async () => {
    // The fallback re-enters the plaintext path; it must not lose the
    // signature on the way.
    const channel = '#enc-fallback';
    await e2ee.setChannelKey(channel, 'a passphrase the room shares');
    vi.spyOn(e2ee, 'encryptChannel').mockResolvedValue(null);
    const { client, ws } = await makeClient('alice');
    const verifyKey = await provisionSigningKey(client, DID);

    client.sendMessage(channel, 'plaintext, because encryption failed');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${channel}`))!;
    expect(line).not.toContain('+encrypted');
    const canonical = await signing.messageCanonical({
      from: DID,
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: signing.channelVenue(channel),
      body: 'plaintext, because encryption failed',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });
});
