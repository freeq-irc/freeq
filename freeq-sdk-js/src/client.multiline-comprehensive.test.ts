/**
 * Comprehensive multiline E2E tests for the JS SDK.
 *
 * Builds on the basic coverage in client.multiline.test.ts with:
 *   - Real Ed25519 signing (Node webcrypto) verifying sig-on-opener
 *     actually validates over the assembled body
 *   - Real ENC1 encryption: ciphertext-chunked outbound round-trips
 *     to a single decrypted Message on the receive side
 *   - Tag passthrough beyond +reply: msgid, +draft/edit,
 *     +freeq.at/event, +freeq.at/streaming, +reply
 *   - Nested multiline inside CHATHISTORY: assembled body lands in
 *     the parent batch's messages rather than emitting top-level
 *   - Edge cases: empty body, single-chunk degenerate, max-lines and
 *     max-bytes overflow → legacy fallback, multi-byte unicode,
 *     concat-mixed assembly, unknown-batch references
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'crypto';
import type { FreeqClient } from './client.js';
import type { Message } from './types.js';
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
  // Real Web Crypto from Node — needed for Ed25519 + AES-GCM in the
  // signing and ENC1 paths. The basic unit tests in
  // client.multiline.test.ts stub these out; here we use the real
  // primitives so we can verify sigs and round-trip ciphertext.
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
  // Reset signing module state between tests so each test starts clean.
  signing.resetSigning();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  // Microtask-only flushing isn't enough here — signing (Ed25519) and
  // ENC1 (PBKDF2 + AES-GCM) go through Web Crypto, which resolves via
  // the macrotask queue. Mix setTimeout in so the event loop actually
  // ticks. ~50ms total upper bound across operations.
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** Build a registered client with `draft/multiline` + `batch` acked. */
async function makeMultilineClient(nick: string): Promise<{
  client: FreeqClient;
  ws: MockWebSocket;
}> {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick,
    skipInitialBrokerRefresh: true,
  });
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(
    ':srv CAP * LS :message-tags server-time batch echo-message freeq.at/msgsig ' +
      'draft/multiline=max-bytes=40000,max-lines=100',
  );
  await flushAsync();
  ws.recv(
    ':srv CAP * ACK :message-tags server-time batch draft/multiline freeq.at/msgsig',
  );
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

/** Provision a real Ed25519 signing key on the signing module. */
async function provisionSigningKey(did: string): Promise<CryptoKey> {
  signing.setSigningDid(did);
  await signing.generateSigningKey();
  // Re-grab the key from a sign() call's effect; we need the pubkey to
  // verify in tests. The module exports getPublicKey() (b64url string),
  // but for verify we need the CryptoKey form — generate it fresh from
  // the b64url and re-import.
  const pubB64 = signing.getPublicKey();
  if (!pubB64) throw new Error('signing key not provisioned');
  // base64url → bytes → import as Ed25519 raw
  const padded = pubB64 + '='.repeat((4 - (pubB64.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', bytes, 'Ed25519', false, ['verify']);
}

/** Pick the BATCH opener line out of an array of sent wire frames. */
function findOpener(sent: string[]): string | undefined {
  return sent.find((l) => l.includes('BATCH +') && l.includes('draft/multiline'));
}

/** Pick the BATCH closer line. */
function findCloser(sent: string[]): string | undefined {
  return sent.find((l) => /BATCH -\S+/.test(l));
}

/** Pick the chunk PRIVMSGs (those carrying a `batch=` tag). */
function findChunks(sent: string[]): string[] {
  return sent.filter((l) => l.includes('PRIVMSG') && l.includes('batch='));
}

// ────────────────────────────────────────────────────────────────────
// 1. Signing: BATCH opener carries +freeq.at/sig over assembled body
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: sig on BATCH opener', () => {
  it('signs assembled body and the sig verifies', async () => {
    const did = 'did:plc:test-signer';
    const verifyKey = await provisionSigningKey(did);
    const { client, ws } = await makeMultilineClient('alice');
    const text = 'first\nsecond\nthird';
    client.sendMessage('#room', text);
    await flushAsync();
    const opener = findOpener(ws.sent);
    expect(opener).toBeDefined();
    // The opener carries the signature AND the event id it covers.
    const sigMatch = opener!.match(/\+freeq\.at\/sig=([^;\s]+)/);
    expect(sigMatch, `opener: ${opener}`).not.toBeNull();
    const sigTag = sigMatch![1]!;
    const idMatch = opener!.match(/\+freeq\.at\/eventid=([^;\s]+)/);
    expect(idMatch, 'a signature covers an id the signer minted').not.toBeNull();
    const eventId = idMatch![1]!;

    // Verification is now deterministic. This test used to try every second in
    // the last five and accept any hit, because the retired canonical folded a
    // wall clock the signer minted and never sent — a receiver had no such
    // luxury, which is precisely why the canonical changed.
    const [alg, kid, sigB64] = sigTag.split(':');
    expect(alg).toBe('ed25519');
    expect(kid).toBe(signing.getKid());
    const padded = sigB64! + '='.repeat((4 - (sigB64!.length % 4)) % 4);
    const sig = Uint8Array.from(atob(padded.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0),
    );
    const canonical = await signing.messageCanonical({
      from: did,
      msgid: eventId,
      target: signing.channelVenue('#room'),
      body: text,
    });
    const verified = await crypto.subtle.verify(
      'Ed25519',
      verifyKey,
      sig,
      new TextEncoder().encode(canonical),
    );
    expect(verified, 'signature verifies over the assembled body, first try').toBe(true);
  });

  it('chunks do NOT carry +freeq.at/sig', async () => {
    await provisionSigningKey('did:plc:test-signer');
    const { client, ws } = await makeMultilineClient('alice');
    client.sendMessage('#room', 'a\nb\nc');
    await flushAsync();
    for (const chunk of findChunks(ws.sent)) {
      expect(chunk).not.toContain('+freeq.at/sig');
    }
  });
});

// ────────────────────────────────────────────────────────────────────
// 2. ENC1 ciphertext-chunking round-trip
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: ENC1 ciphertext-chunked multiline round-trip', () => {
  it('encrypts assembled plaintext, chunks ciphertext, sender wire is BATCH with concat=true', async () => {
    const channel = '#enc-rt-1';
    await e2ee.setChannelKey(channel, 'comprehensive-pass-1');
    const { client, ws } = await makeMultilineClient('alice');
    // ~8 KB plaintext → ciphertext exceeds one chunk; SDK must
    // ciphertext-chunk across a BATCH with every-chunk concat=true.
    const paragraph = 'Wall of comprehensive test text to force chunking. '.repeat(20);
    const text = Array.from({ length: 6 }, (_, i) => `line${i + 1}: ${paragraph}`).join('\n');
    expect(text.length).toBeGreaterThan(6000);
    client.sendMessage(channel, text);
    await flushAsync();
    const opener = findOpener(ws.sent);
    const closer = findCloser(ws.sent);
    const chunks = findChunks(ws.sent);
    expect(opener).toBeDefined();
    expect(closer).toBeDefined();
    expect(chunks.length).toBeGreaterThanOrEqual(2);
    // Every chunk after the first must carry concat tag (ciphertext-chunking)
    const concatChunks = chunks.filter((c) => c.includes('draft/multiline-concat'));
    expect(concatChunks.length).toBe(chunks.length - 1);
    // Every chunk must carry +encrypted
    for (const c of chunks) {
      expect(c).toContain('+encrypted');
    }
  });

  it('receiver assembles ciphertext chunks and decrypts to original plaintext', async () => {
    const channel = '#enc-rt-2';
    const pass = 'comprehensive-pass-2';
    await e2ee.setChannelKey(channel, pass);
    // Build two clients: senderC sends, receiverC receives the BATCH.
    const senderC = await makeMultilineClient('alice');
    const receiverC = await makeMultilineClient('bob');
    const seen: Message[] = [];
    receiverC.client.on('message', (_ch, msg) => seen.push(msg));
    // Body must be large enough that ciphertext exceeds one wire
    // chunk (~6400B per perChunkByteBudget), forcing the
    // BATCH+concat=true path. Matches the first ENC1 test's sizing.
    const paragraph = 'Round-trip wall of text. '.repeat(50);
    const text = Array.from({ length: 6 }, (_, i) => `rt${i}: ${paragraph}`).join('\n');
    expect(text.length).toBeGreaterThan(6000);
    senderC.client.sendMessage(channel, text);
    await flushAsync();
    // Re-broadcast sender's wire frames as if they arrived at receiver
    // from the server (rewrite by prepending a server-stamped prefix).
    const senderFrames = senderC.ws.sent.filter((l) =>
      l.includes('BATCH ') || l.includes(`PRIVMSG ${channel}`),
    );
    expect(senderFrames.length).toBeGreaterThanOrEqual(3); // opener + N chunks + closer
    // Add a server prefix on the lines that don't have one (chunks).
    // The opener already has its msgid stamped; the chunks need a prefix
    // so the receiver's PRIVMSG handler sees a sender.
    for (const raw of senderFrames) {
      const isBatchCommand = raw.startsWith('BATCH') || raw.match(/^@[^ ]+\s+BATCH/);
      const hasPrefix = raw.startsWith(':') || raw.match(/^@[^ ]+ :/);
      let line = raw.trimEnd();
      if (!hasPrefix) {
        // Inject a server prefix to mimic relay
        if (isBatchCommand) {
          // BATCH (raw "BATCH +x ...") or "@tags BATCH +x ..."
          line = line.replace(/^(@[^ ]+ )?BATCH/, '$1:alice!u@host BATCH');
        } else {
          // "@batch=... PRIVMSG #room :..." → inject prefix
          line = line.replace(/^(@[^ ]+) PRIVMSG/, '$1 :alice!u@host PRIVMSG');
        }
      }
      receiverC.ws.recv(line);
    }
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe(text);
    expect(seen[0].encrypted).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// 3. Tag passthrough — opener tags inherit onto assembled Message
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: opener tag passthrough', () => {
  it('msgid + time inherit from BATCH opener into assembled Message', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv(
      '@msgid=01OPENID;time=2026-05-30T12:00:00.000Z ' +
        ':bob!u@h BATCH +tg1 draft/multiline #room',
    );
    ws.recv('@batch=tg1 :bob!u@h PRIVMSG #room :line a');
    ws.recv('@batch=tg1 :bob!u@h PRIVMSG #room :line b');
    ws.recv(':srv BATCH -tg1');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].id).toBe('01OPENID');
    expect(seen[0].timestamp.toISOString()).toBe('2026-05-30T12:00:00.000Z');
    expect(seen[0].text).toBe('line a\nline b');
  });

  it('+reply tag on opener becomes message.replyTo on assembled', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv(
      '@msgid=01REPLY;+reply=01ORIG ' +
        ':bob!u@h BATCH +tg2 draft/multiline #room',
    );
    ws.recv('@batch=tg2 :bob!u@h PRIVMSG #room :reply line 1');
    ws.recv('@batch=tg2 :bob!u@h PRIVMSG #room :reply line 2');
    ws.recv(':srv BATCH -tg2');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].replyTo).toBe('01ORIG');
  });

  it('+freeq.at/streaming=1 on opener becomes message.isStreaming', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv(
      '@msgid=01STREAM;+freeq.at/streaming=1 ' +
        ':bob!u@h BATCH +tg3 draft/multiline #room',
    );
    ws.recv('@batch=tg3 :bob!u@h PRIVMSG #room :partial chunk one');
    ws.recv('@batch=tg3 :bob!u@h PRIVMSG #room :partial chunk two');
    ws.recv(':srv BATCH -tg3');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].isStreaming).toBe(true);
  });

  it('+freeq.at/event=reveal on opener fires coordinationEvent', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const events: unknown[] = [];
    client.on('coordinationEvent', (...args) => events.push(args));
    ws.recv(
      '@msgid=01EV;+freeq.at/event=reveal;+freeq.at/payload=%7B%7D ' +
        ':bob!u@h BATCH +tg4 draft/multiline #room',
    );
    ws.recv('@batch=tg4 :bob!u@h PRIVMSG #room :revealed line 1');
    ws.recv('@batch=tg4 :bob!u@h PRIVMSG #room :revealed line 2');
    ws.recv(':srv BATCH -tg4');
    await flushAsync();
    expect(events.length).toBeGreaterThan(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// 4. Nested multiline inside CHATHISTORY
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: nested multiline inside CHATHISTORY', () => {
  it('assembled multi-line goes into parent chathistory batch, not top-level', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const topLevelMessages: Message[] = [];
    const historyBatches: Array<{ target: string; messages: Message[] }> = [];
    client.on('message', (_ch, m) => topLevelMessages.push(m));
    client.on('historyBatch', (target, messages) =>
      historyBatches.push({ target, messages }),
    );
    // Outer chathistory batch wrapping a multiline batch
    ws.recv(':srv BATCH +ch1 chathistory #room');
    ws.recv(
      '@batch=ch1;msgid=01NEST ' +
        ':bob!u@h BATCH +ml1 draft/multiline #room',
    );
    ws.recv('@batch=ml1 :bob!u@h PRIVMSG #room :nested line 1');
    ws.recv('@batch=ml1 :bob!u@h PRIVMSG #room :nested line 2');
    ws.recv(':srv BATCH -ml1');
    // Also include a plain PRIVMSG in the chathistory batch
    ws.recv(
      '@batch=ch1;msgid=01PLAIN :bob!u@h PRIVMSG #room :a regular history line',
    );
    ws.recv(':srv BATCH -ch1');
    await flushAsync();
    expect(topLevelMessages).toHaveLength(0); // none fired at top level
    expect(historyBatches).toHaveLength(1);
    expect(historyBatches[0].target).toBe('#room');
    const messages = historyBatches[0].messages;
    expect(messages.length).toBe(2);
    const nested = messages.find((m) => m.id === '01NEST');
    const plain = messages.find((m) => m.id === '01PLAIN');
    expect(nested?.text).toBe('nested line 1\nnested line 2');
    expect(plain?.text).toBe('a regular history line');
  });
});

// ────────────────────────────────────────────────────────────────────
// 5. Edge cases
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: edge cases', () => {
  it('single-chunk BATCH (degenerate) reassembles to that one body', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv('@msgid=01SC :bob!u@h BATCH +sc1 draft/multiline #room');
    ws.recv('@batch=sc1 :bob!u@h PRIVMSG #room :only one chunk');
    ws.recv(':srv BATCH -sc1');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('only one chunk');
  });

  it('empty BATCH (no chunks between open and close) emits empty-body message', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv('@msgid=01EM :bob!u@h BATCH +em1 draft/multiline #room');
    ws.recv(':srv BATCH -em1');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('');
  });

  it('BATCH closer for unknown id is silently ignored (no crash)', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv(':srv BATCH -doesnotexist');
    await flushAsync();
    expect(seen).toHaveLength(0); // no spurious message
  });

  it('PRIVMSG with batch=<id> for a non-multiline batch is treated normally', async () => {
    // Inside a chathistory batch, individual PRIVMSGs should still
    // appear as message events on their own — they're not multiline
    // chunks. (Chathistory accumulates them into historyBatch.)
    const { client, ws } = await makeMultilineClient('alice');
    const topLevel: Message[] = [];
    const history: Array<{ target: string; messages: Message[] }> = [];
    client.on('message', (_ch, m) => topLevel.push(m));
    client.on('historyBatch', (target, messages) =>
      history.push({ target, messages }),
    );
    ws.recv(':srv BATCH +chx chathistory #room');
    ws.recv('@batch=chx;msgid=01A :bob!u@h PRIVMSG #room :hello');
    ws.recv('@batch=chx;msgid=01B :bob!u@h PRIVMSG #room :world');
    ws.recv(':srv BATCH -chx');
    await flushAsync();
    expect(topLevel).toHaveLength(0);
    expect(history).toHaveLength(1);
    expect(history[0].messages).toHaveLength(2);
    expect(history[0].messages[0].text).toBe('hello');
    expect(history[0].messages[1].text).toBe('world');
  });

  it('multi-byte unicode (emoji + CJK) round-trips byte-exact', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    const text = '日本語\n🎉🚀✨\n한국어\nthird';
    ws.recv('@msgid=01UC :bob!u@h BATCH +uc1 draft/multiline #room');
    for (const line of text.split('\n')) {
      ws.recv(`@batch=uc1 :bob!u@h PRIVMSG #room :${line}`);
    }
    ws.recv(':srv BATCH -uc1');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe(text);
  });

  it('concat-mixed sequence assembles per spec: concat→no-sep, no-concat→\\n', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv('@msgid=01CM :bob!u@h BATCH +cm1 draft/multiline #room');
    ws.recv('@batch=cm1 :bob!u@h PRIVMSG #room :alpha');
    ws.recv('@batch=cm1;draft/multiline-concat= :bob!u@h PRIVMSG #room :beta');
    ws.recv('@batch=cm1;draft/multiline-concat= :bob!u@h PRIVMSG #room :gamma');
    ws.recv('@batch=cm1 :bob!u@h PRIVMSG #room :delta');
    ws.recv('@batch=cm1;draft/multiline-concat= :bob!u@h PRIVMSG #room :epsilon');
    ws.recv(':srv BATCH -cm1');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('alphabetagamma\ndeltaepsilon');
  });

  it('outbound: text with no \\n sends one PRIVMSG (no BATCH)', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    client.sendMessage('#room', 'just one logical line');
    await flushAsync();
    expect(findOpener(ws.sent)).toBeUndefined();
    expect(ws.sent.find((l) => l.includes('PRIVMSG #room :just one logical line')))
      .toBeDefined();
  });

  it('outbound: exceeding max-lines splits into multiple batches', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    // 101 source lines — server cap is max-lines=100 advertised in CAP LS.
    // Must split into >1 batch, never fall back to a legacy oversized line.
    const text = Array.from({ length: 101 }, (_, i) => `line${i + 1}`).join('\n');
    client.sendMessage('#room', text);
    await flushAsync();
    const openers = ws.sent.filter(
      (l) => l.includes('BATCH +') && l.includes('draft/multiline'),
    );
    expect(openers.length).toBeGreaterThanOrEqual(2);
    const legacy = ws.sent.find((l) =>
      l.includes('+freeq.at/multiline') && l.includes('PRIVMSG #room'),
    );
    expect(legacy).toBeUndefined();
  });

  it('outbound: exceeding max-bytes splits into multiple batches', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    // Exceed max-bytes=40000 while staying under max-lines: 90 × 600 chars.
    const text = Array.from({ length: 90 }, () => 'x'.repeat(600)).join('\n');
    client.sendMessage('#room', text);
    await flushAsync();
    const openers = ws.sent.filter(
      (l) => l.includes('BATCH +') && l.includes('draft/multiline'),
    );
    expect(openers.length).toBeGreaterThanOrEqual(2);
    const legacy = ws.sent.find((l) =>
      l.includes('+freeq.at/multiline') && l.includes('PRIVMSG #room'),
    );
    expect(legacy).toBeUndefined();
  });

  it('inbound: legacy +freeq.at/multiline with multi-byte unicode decodes correctly', async () => {
    const { client, ws } = await makeMultilineClient('alice');
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));
    ws.recv('@+freeq.at/multiline= :bob!u@h PRIVMSG #room :日本語\\n🎉\\n한국어');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('日本語\n🎉\n한국어');
  });
});

// ────────────────────────────────────────────────────────────────────
// Oversize paste: a message past the server's max-lines / max-bytes
// ceiling must be sent as SEVERAL batches (several logical messages),
// never collapsed into one legacy oversized PRIVMSG that the server
// silently truncates. This is the RFC-paste bug: ~130 lines fell back
// to sendLegacyPlaintext → one 14 KB line → cut at 8192.
// ────────────────────────────────────────────────────────────────────

describe('comprehensive: oversize multi-line paste splits into batches', () => {
  it('a >max-lines message becomes multiple BATCHes, not a legacy line', async () => {
    const { client, ws } = await makeMultilineClient('alice');

    // 250 short lines: 2.5× the advertised max-lines=100 ceiling.
    const lines = Array.from({ length: 250 }, (_, i) => `line-${i}`);
    const text = lines.join('\n');
    client.sendMessage('#room', text);
    await flushAsync();

    const openers = ws.sent.filter(
      (l) => l.includes('BATCH +') && l.includes('draft/multiline'),
    );
    const closers = ws.sent.filter((l) => /BATCH -\S+/.test(l));
    const chunks = ws.sent.filter((l) => l.includes('PRIVMSG') && l.includes('batch='));

    // Must NOT have fallen back to a single legacy PRIVMSG carrying the
    // whole doc as one escaped line.
    const legacyWhole = ws.sent.filter(
      (l) =>
        l.includes('PRIVMSG') &&
        !l.includes('batch=') &&
        (l.includes('+freeq.at/multiline') || l.includes('\\n')),
    );
    expect(legacyWhole).toEqual([]);

    // ceil(250 / 100) = 3 batches minimum, balanced open/close.
    expect(openers.length).toBeGreaterThanOrEqual(3);
    expect(closers.length).toBe(openers.length);

    // Every batch respects the max-lines ceiling.
    const perBatch = new Map<string, number>();
    for (const c of chunks) {
      const m = c.match(/batch=([^\s;]+)/);
      if (m) perBatch.set(m[1], (perBatch.get(m[1]) ?? 0) + 1);
    }
    for (const [id, n] of perBatch) {
      expect(n, `batch ${id} exceeded max-lines`).toBeLessThanOrEqual(100);
    }

    // No data loss: every source line survives, in order, across batches.
    // (A space-less trailing param serializes without the leading colon.)
    const bodies = chunks.map((l) => {
      const after = l.slice(l.indexOf('#room ') + '#room '.length);
      return after.startsWith(':') ? after.slice(1) : after;
    });
    expect(bodies).toEqual(lines);
  });
});
