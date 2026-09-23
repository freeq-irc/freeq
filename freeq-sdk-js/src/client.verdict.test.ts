/**
 * A client given a key lookup checks the signature on every received line
 * and puts a verdict on it — the same vectors, negatives and states the Rust
 * SDK's receive path is held to.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { importDidKey } from './did-key.js';
import { type DidDocument, buildDeviceRecord } from './identity-records.js';
import { KeyLookup } from './key-lookup.js';
import { format } from './parser.js';
import * as signing from './signing.js';
import type { Message } from './types.js';
import type { Verdict, VerdictState } from './verdict.js';

// ── WebSocket mock ────────────────────────────────────────────────

type ReadyState = 0 | 1 | 2 | 3;

class MockWebSocket {
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
    if (this.readyState === 1) this.sent.push(data);
  }
  close() {
    this.readyState = 3;
    this.onclose?.({});
  }
  recv(line: string) {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

// ── the origin server and the signers' PDS ─────────────────────────

const ORIGIN = 'https://origin.test';
const PDS = 'https://pds.test';
const SERVER_DID = 'did:web:server.test';
const OWN_DID = 'did:plc:me';

interface Origin {
  keys: Map<string, { key: Uint8Array; removedAt?: number }>;
  serverKeys: Uint8Array[];
  records: unknown[];
  delayMs: number;
  setReads: number;
}

let origin: Origin;

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function rawKey(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64url'));
}

async function hold(did: string, key: Uint8Array, removedAt?: number) {
  origin.keys.set(`${did} ${await signing.deriveKid(key)}`, { key, removedAt });
}

const stubFetch = async (input: string): Promise<Response> => {
  const url = new URL(input);
  if (url.origin === PDS && url.pathname === '/xrpc/com.atproto.repo.listRecords') {
    const device = url.searchParams.get('collection') === 'at.freeq.deviceKey';
    return Response.json({
      records: (device ? origin.records : []).map((value) => ({ uri: 'at://x', cid: 'bafy', value })),
    });
  }
  if (url.origin !== ORIGIN) return new Response('unexpected', { status: 500 });
  // A server without the record routes.
  if (url.pathname.startsWith('/api/v1/records')) return new Response('not found', { status: 404 });
  if (url.pathname === '/api/v1/signing-key') {
    return Response.json({ did: SERVER_DID, public_key: origin.serverKeys[0] && b64url(origin.serverKeys[0]) });
  }
  const prefix = '/api/v1/signing-keys/';
  const [did, kid] = url.pathname.slice(prefix.length).split('/').map(decodeURIComponent);
  if (kid === undefined) {
    origin.setReads++;
    const keys = did === SERVER_DID
      ? await Promise.all(origin.serverKeys.map(async (k) => ({ kid: await signing.deriveKid(k), public_key: b64url(k) })))
      : [];
    return Response.json({ did, keys });
  }
  if (origin.delayMs > 0) await new Promise((r) => setTimeout(r, origin.delayMs));
  const held = origin.keys.get(`${did} ${kid}`);
  if (!held) return new Response('not found', { status: 404 });
  return Response.json({ did, kid, public_key: b64url(held.key), removed_at: held.removedAt ?? null });
};

function lookup(documents: DidDocument[] = []): KeyLookup {
  const resolveDid = async (did: string): Promise<DidDocument> => {
    const doc = documents.find((d) => d.id === did);
    if (!doc) throw new Error(`unknown DID ${did}`);
    return doc;
  };
  return new KeyLookup({ fetch: stubFetch, resolveDid }, ORIGIN, 3_600_000);
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  origin = { keys: new Map(), serverKeys: [], records: [], delayMs: 0, setReads: 0 };
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 404 })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

// ── a session ────────────────────────────────────────────────────────

interface Seen {
  delivered?: Verdict;
  settled?: Verdict;
}

/** An authenticated session as `ownDid`, watching what lines come to. */
async function session(ownDid = OWN_DID, keyLookup: KeyLookup | null = lookup()) {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'me',
    skipInitialBrokerRefresh: true,
    autoMsgSig: false,
    ...(keyLookup ? { keyLookup } : {}),
  });
  client.setSaslCredentials({ token: 't', did: ownDid, pdsUrl: 'https://pds.example', method: 'oauth' });
  // What each line id was delivered with, and the verdict it settled on.
  const seen = new Map<string, Seen>();
  const record = (id: string, v: Verdict | undefined) => {
    const s = seen.get(id) ?? {};
    s.delivered ??= v;
    if (v && v.state !== 'pending') s.settled ??= v;
    seen.set(id, s);
  };
  client.on('message', (_c, m) => record(m.id, m.verdict));
  client.on('coordinationEvent', (p) => record(p.eventId, p.verdict));
  client.on('actEvent', (p) => record(p.eventId, p.verdict));
  client.on('verdict', (id, v) => {
    const s = seen.get(id) ?? {};
    s.settled = v;
    seen.set(id, s);
  });
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(':srv CAP * LS :sasl message-tags');
  await flushAsync();
  ws.recv(':srv CAP * ACK :sasl message-tags');
  await flushAsync();
  ws.recv(':srv 903 me :SASL authentication successful');
  await flushAsync();
  ws.recv(':srv 001 me :Welcome');
  await flushAsync();

  /** Send `lines` and wait for the verdict the line `id` settles on. */
  const lineFor = async (lines: string[], id: string): Promise<Seen> => {
    for (const l of lines) {
      ws.recv(l);
      await flushAsync();
    }
    for (let i = 0; i < 400 && seen.get(id)?.settled === undefined; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    return seen.get(id) ?? {};
  };
  return { client, ws, seen, lineFor };
}

// ── wire lines ───────────────────────────────────────────────────────

function line(tags: Record<string, string>, command: string, target: string, body?: string): string {
  // Tags first, then the prefix: `@tags :nick!u@h COMMAND …`.
  const formatted = format(command, body === undefined ? [target] : [target, body], tags);
  const split = formatted.startsWith('@') ? formatted.indexOf(' ') + 1 : 0;
  return `${formatted.slice(0, split)}:sender!u@h ${formatted.slice(split)}`;
}

/** The wire a chat vector's `input` describes, and the DID this session
 *  must hold for a DM venue to rebuild. */
function chatWire(input: any, sigTag: string): { lines: string[]; own: string } {
  const { from, msgid, target } = input;
  let wireTarget = input.rawTarget ?? target;
  let own = OWN_DID;
  if (target.startsWith('dm:')) {
    own = target.slice(3).split(',').find((d: string) => d !== from);
    wireTarget = 'me';
  }
  const tags: Record<string, string> = {
    account: from,
    msgid,
    [signing.EVENT_ID_TAG]: msgid,
    [signing.SIG_TAG]: sigTag,
  };
  const put = (k: string, v: unknown) => {
    if (typeof v === 'string') tags[k] = v;
  };
  switch (input.kind) {
    case 'message':
      put('+reply', input.reply);
      put('+draft/edit', input.edit);
      for (const [k, v] of Object.entries(input.tags ?? {})) put(k, v);
      break;
    case 'delete':
      put('+draft/delete', input.subject);
      break;
    case 'react':
      put('+react', input.emoji);
      put('+reply', input.subject);
      break;
    case 'unreact':
      put('+freeq.at/unreact', input.emoji);
      put('+reply', input.subject);
      break;
    case 'coordination':
      put('+freeq.at/event', input.eventType);
      put('+freeq.at/payload', input.payload);
      put('+freeq.at/ref', input.ref);
      put('+freeq.at/evidence-type', input.evidence);
      break;
  }
  const body: string | undefined = input.bodyText;
  if (body !== undefined && body.includes('\n')) {
    return {
      own,
      lines: [
        line(tags, 'BATCH', '+b1', `draft/multiline ${wireTarget}`).replace(
          ` :draft/multiline ${wireTarget}`,
          ` draft/multiline ${wireTarget}`,
        ),
        ...body.split('\n').map((chunk) => line({ batch: 'b1' }, 'PRIVMSG', wireTarget, chunk)),
        ':sender!u@h BATCH -b1',
      ],
    };
  }
  return {
    own,
    lines: [body === undefined ? line(tags, 'TAGMSG', wireTarget) : line(tags, 'PRIVMSG', wireTarget, body)],
  };
}

/** The wire an act vector describes, with its own id and signature. */
function actWire(tags: Record<string, string>, target: string, id: string, sigTag: string) {
  const wire = { ...tags, [signing.SIG_TAG]: sigTag, [signing.EVENT_ID_TAG]: id };
  const from = wire['+freeq.at/from'];
  if (target.startsWith('dm:')) {
    return { line: line(wire, 'TAGMSG', 'me'), own: target.slice(3).split(',').find((d) => d !== from)! };
  }
  return { line: line(wire, 'TAGMSG', target), own: OWN_DID };
}

function spec(name: string): any {
  return JSON.parse(readFileSync(join(__dirname, '../../spec', name), 'utf8'));
}

/** The values behind the negatives whose tampered field is hashed in the
 *  canonical (`freeq-sdk/src/chatsig.rs`, where the negatives are built). */
const ALTERED_BODY = 'ship it tomorrow';
const ALTERED_PAYLOAD = '%7B%22summary%22%3A%22not%20done%22%7D';

function tamperedInput(base: any, name: string, tampered: any): any {
  const input = structuredClone(base);
  if (name === 'altered-body') input.bodyText = ALTERED_BODY;
  if (name === 'altered-coordination-payload') input.payload = ALTERED_PAYLOAD;
  for (const field of ['edit', 'subject', 'emoji', 'evidence', 'ref']) {
    if (tampered[field] === undefined) delete input[field];
    else input[field] = tampered[field];
  }
  if (tampered.target !== undefined) {
    input.target = tampered.target;
    delete input.rawTarget;
  }
  if (tampered.kind !== undefined && tampered.kind !== 'coordination') input.kind = tampered.kind;
  if (tampered.coord !== undefined) {
    input.tags = Object.fromEntries(
      Object.entries(tampered.coord).map(([k, v]) => [`+freeq.at/${k}`, v]),
    );
  }
  return input;
}

async function through(lines: string[], own: string, id: string, keys: [string, Uint8Array][]) {
  for (const [did, key] of keys) await hold(did, key);
  const s = await session(own);
  return s.lineFor(lines, id);
}

// ── the vectors ──────────────────────────────────────────────────────

describe('checking received signatures', () => {
  it('reaches device for every chat vector', async () => {
    for (const v of spec('chat-signing-vectors.json').vectors) {
      const { lines, own } = chatWire(v.input, v.sigTag);
      const seen = await through(lines, own, v.input.msgid, [[v.input.from, rawKey(v.publicKey)]]);
      expect(seen.settled, v.name).toEqual({
        state: 'device',
        layer: 'vouched',
        kid: v.kid,
        keySource: 'OriginServer',
      });
    }
  });

  it('reaches the expected verdict for every chat negative', async () => {
    const file = spec('chat-signing-vectors.json');
    for (const n of file.negatives) {
      const base = file.vectors.find((v: any) => v.name === n.vector);
      let input = base.input;
      let sig = base.sigTag;
      if (n.tamperedCanonical !== undefined) {
        input = tamperedInput(base.input, n.name, JSON.parse(n.tamperedCanonical));
      } else {
        sig = n.sigTag;
      }
      const { lines, own } = chatWire(input, sig);
      const seen = await through(lines, own, input.msgid, [[input.from, rawKey(base.publicKey)]]);
      expect(seen.settled?.state, n.name).toBe(n.expected);
    }
  });

  it('reaches device for every act vector', async () => {
    for (const v of spec('act-signing-vectors.json').vectors) {
      const { line: l, own } = actWire(v.tags, v.target, v.id, v.sigTag);
      const seen = await through([l], own, v.id, [[v.tags['+freeq.at/from'], rawKey(v.publicKey)]]);
      expect(seen.settled, v.name).toEqual({
        state: 'device',
        layer: 'vouched',
        kid: v.kid,
        keySource: 'OriginServer',
      });
    }
  });

  it('reaches the expected verdict for every act negative', async () => {
    const file = spec('act-signing-vectors.json');
    for (const n of file.negatives) {
      const base = file.vectors.find((v: any) => v.name === n.vector);
      const tags = { ...base.tags };
      if (n.swappedTag) tags[n.swappedTag.name] = n.swappedTag.value;
      if (n.strippedTag) delete tags[n.strippedTag];
      let sig: string = base.sigTag;
      if (n.sigAlgorithm) sig = `${n.sigAlgorithm}:${sig.split(':').slice(1).join(':')}`;
      const { line: l, own } = actWire(tags, n.target, n.id, sig);
      const seen = await through([l], own, n.id, [[base.tags['+freeq.at/from'], rawKey(base.publicKey)]]);
      expect(seen.settled?.state, n.name).toBe(n.expected as VerdictState);
    }
  });

  // ── the other states ─────────────────────────────────────────────────

  const SIGNER = 'did:plc:signer';

  async function signedMessage(seed: number, body: string) {
    const msgid = signing.newEventId();
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    const canonical = await signing.messageCanonical({ from: SIGNER, msgid, target: '#room', body });
    const sig = await key.signer(new TextEncoder().encode(canonical));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    const kid = await signing.deriveKid(pub);
    const tags = { account: SIGNER, msgid, [signing.SIG_TAG]: `ed25519:${kid}:${sig}` };
    return { wire: line(tags, 'PRIVMSG', '#room', body), msgid, pub, kid, key };
  }

  it('is unverifiable for a key no source holds', async () => {
    const m = await signedMessage(21, 'hello');
    const seen = await through([m.wire], OWN_DID, m.msgid, []);
    expect(seen.delivered?.state).toBe('pending');
    expect(seen.settled?.state).toBe('unverifiable');
  });

  it('delivers a line pending and follows it with its verdict', async () => {
    origin.delayMs = 200;
    const m = await signedMessage(22, 'hello there');
    await hold(SIGNER, m.pub);
    const s = await session();
    const delivered: { text: string; verdict?: Verdict }[] = [];
    s.client.on('message', (_c, msg) => delivered.push({ text: msg.text, verdict: msg.verdict }));
    const verdicts: [string, Verdict][] = [];
    s.client.on('verdict', (id, v) => verdicts.push([id, v]));
    s.ws.recv(m.wire);
    await flushAsync();
    expect(delivered).toEqual([{ text: 'hello there', verdict: { state: 'pending', kid: m.kid } }]);
    expect(verdicts).toEqual([]);
    for (let i = 0; i < 200 && verdicts.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0]![0]).toBe(m.msgid);
    expect(verdicts[0]![1].state).toBe('device');
  });

  it('is the server’s for a kid in the server’s key set', async () => {
    const m = await signedMessage(23, 'on your behalf');
    origin.serverKeys = [m.pub];
    const seen = await through([m.wire], OWN_DID, m.msgid, []);
    expect(seen.settled?.state).toBe('server');
  });

  it('reads the server’s key set once more for an unfamiliar kid, and only once', async () => {
    const s = await session();
    for (const body of ['one', 'two']) {
      const m = await signedMessage(24, body);
      expect((await s.lineFor([m.wire], m.msgid)).settled?.state).toBe('unverifiable');
    }
    expect(origin.setReads).toBe(2);
  });

  it('is unsigned for a line with no signature', async () => {
    const s = await session();
    const got: Verdict[] = [];
    s.client.on('message', (_c, msg) => got.push(msg.verdict!));
    s.ws.recv('@msgid=01KYVT5Z8Q0000000000000000 :sender!u@h PRIVMSG #room :plain');
    await flushAsync();
    expect(got).toEqual([{ state: 'unsigned' }]);
  });

  it('is retired for a key the origin removed before the message', async () => {
    const m = await signedMessage(25, 'too late');
    await hold(SIGNER, m.pub, 1_700_000_000);
    const s = await session();
    expect((await s.lineFor([m.wire], m.msgid)).settled?.state).toBe('retired');
  });

  /**
   * A key lookup for SIGNER whose PDS lists `records` with proofs signed by
   * SIGNER's repository key; every other request goes to the stub origin.
   * Counts requests for one signer's key at the origin.
   */
  async function signerRecordsLookup(records: unknown[]) {
    const { stubRepo } = await import('../test/repo-proofs.js');
    const repo = await stubRepo(SIGNER);
    for (const record of records) await repo.add('at.freeq.deviceKey', record);
    const doc = await repo.document(PDS);
    const counts = { keyReads: 0 };
    const fetch = async (input: string): Promise<Response> => {
      const url = new URL(input);
      if (url.origin === PDS) {
        return (await repo.respond(url)) ?? new Response('unexpected', { status: 500 });
      }
      const parts = url.pathname.split('/');
      if (parts[3] === 'signing-keys' && parts.length === 6) counts.keyReads++;
      return stubFetch(input);
    };
    const resolveDid = async (did: string): Promise<DidDocument> => {
      if (did !== SIGNER) throw new Error(`unknown DID ${did}`);
      return doc;
    };
    return { lookup: new KeyLookup({ fetch, resolveDid }, ORIGIN, 3_600_000), counts };
  }

  it('is published for a key in the signer’s records', async () => {
    const m = await signedMessage(26, 'from my own device');
    const { lookup: records } = await signerRecordsLookup([
      await buildDeviceRecord(m.key, SIGNER, '2026-01-01T00:00:00Z'),
    ]);
    const s = await session(OWN_DID, records);
    expect((await s.lineFor([m.wire], m.msgid)).settled).toEqual({
      state: 'device',
      layer: 'published',
      kid: m.kid,
      keySource: 'IdentityRecord',
    });
  });

  it('is retired for a key the signer’s records retire, without asking the origin', async () => {
    const { buildDeviceRetirement } = await import('./identity-records.js');
    const m = await signedMessage(27, 'sent after I signed it out');
    const { lookup: records, counts } = await signerRecordsLookup([
      await buildDeviceRecord(m.key, SIGNER, '2026-01-01T00:00:00Z'),
      await buildDeviceRetirement(m.key, SIGNER, m.kid, '2026-03-01T00:00:00Z'),
    ]);
    // The origin still serves the same key, with no removal date.
    await hold(SIGNER, m.pub);
    const keyReads = () => counts.keyReads;
    const s = await session(OWN_DID, records);
    expect((await s.lineFor([m.wire], m.msgid)).settled).toEqual({
      state: 'retired',
      kid: m.kid,
      keySource: 'IdentityRecord',
    });
    expect(keyReads()).toBe(0);
  });

  it('puts no verdict on anything without a key lookup', async () => {
    const m = await signedMessage(27, 'hello');
    const s = await session(OWN_DID, null);
    const got: (Verdict | undefined)[] = [];
    s.client.on('message', (_c, msg) => got.push(msg.verdict));
    s.ws.recv(m.wire);
    await flushAsync();
    expect(got).toEqual([undefined]);
  });

  it('reads a ULID msgid’s time', () => {
    const now = Date.now();
    expect(Math.abs(signing.msgidTimestampMs(signing.newEventId())! - now)).toBeLessThan(5_000);
    expect(signing.msgidTimestampMs('0000000001ZZZZZZZZZZZZZZZZ')).toBe(1);
    expect(signing.msgidTimestampMs('00000000100000000000000000')).toBe(32);
    expect(signing.msgidTimestampMs('01kyvt5z8q0000000000000000')).toBeNull();
    expect(signing.msgidTimestampMs('01KYVT5Z8Q000000000000000')).toBeNull();
    expect(signing.msgidTimestampMs('01KYVT5Z8Q000000000000000U')).toBeNull();
  });
});

// ── a replayed batch: one prefetch before its checks ───────────────────

describe('a replayed history batch', () => {
  const A = 'did:plc:replayaaaaaaaaaaaaaaaaaa';
  const B = 'did:plc:replaybbbbbbbbbbbbbbbbbb';
  const C = 'did:plc:replaycccccccccccccccccc';

  async function signed(signer: string, seed: number, body: string, extra: Record<string, string> = {}) {
    const msgid = signing.newEventId();
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    const canonical = await signing.messageCanonical({ from: signer, msgid, target: '#room', body });
    const sig = await key.signer(new TextEncoder().encode(canonical));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    await hold(signer, pub);
    const tags = { ...extra, account: signer, msgid, [signing.SIG_TAG]: `ed25519:${await signing.deriveKid(pub)}:${sig}` };
    return { tags, msgid, wire: line(tags, 'PRIVMSG', '#room', body) };
  }

  /** A lookup whose prefetch waits for `release`, and counts key asks. */
  function gatedLookup() {
    const lk = lookup();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const prefetch = vi.spyOn(lk, 'prefetch').mockImplementation(() => gate);
    const keyForAt = vi.spyOn(lk, 'keyForAt');
    return { lk, prefetch, keyForAt, release };
  }

  /** Wait up to 2 s for `done`; the receive path handles lines one after another, asynchronously. */
  async function until(done: () => boolean) {
    for (let i = 0; i < 400 && !done(); i++) await new Promise((r) => setTimeout(r, 5));
  }

  async function settle(s: { seen: Map<string, Seen> }, ids: string[]) {
    for (let i = 0; i < 400 && ids.some((id) => s.seen.get(id)?.settled === undefined); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  it('prefetches its signers once, then checks its lines', async () => {
    const { lk, prefetch, keyForAt, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const batches: Message[][] = [];
    s.client.on('historyBatch', (_t, msgs) => batches.push(msgs));
    const lines = [
      await signed(A, 41, 'first', { batch: 'h' }),
      await signed(B, 42, 'second', { batch: 'h' }),
      await signed(A, 41, 'third', { batch: 'h' }),
    ];
    s.ws.recv(':srv BATCH +h chathistory #room');
    for (const l of lines) s.ws.recv(l.wire);
    s.ws.recv(line({ batch: 'h', msgid: 'plain1' }, 'PRIVMSG', '#room', 'unsigned'));
    await new Promise((r) => setTimeout(r, 50));
    expect(prefetch).not.toHaveBeenCalled();
    expect(keyForAt, 'no check while the batch is open').not.toHaveBeenCalled();
    s.ws.recv(':srv BATCH -h');
    await until(() => prefetch.mock.calls.length > 0);

    expect(prefetch).toHaveBeenCalledTimes(1);
    expect(prefetch).toHaveBeenCalledWith([A, B]);
    expect(batches[0]!.map((m) => m.verdict?.state)).toEqual(['pending', 'pending', 'pending', 'unsigned']);
    await new Promise((r) => setTimeout(r, 20));
    expect(keyForAt, 'no check before the prefetch settles').not.toHaveBeenCalled();

    release();
    await settle(s, lines.map((l) => l.msgid));
    expect(keyForAt).toHaveBeenCalledTimes(3);
    expect(lines.map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual(['device', 'device', 'device']);
  });

  it('prefetches a multiline message nested in it with the batch', async () => {
    const { lk, prefetch, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const first = await signed(A, 41, 'first', { batch: 'h' });
    const multi = await signed(C, 43, 'one\ntwo', { batch: 'h' });
    s.ws.recv(':srv BATCH +h chathistory #room');
    s.ws.recv(first.wire);
    s.ws.recv(
      line(multi.tags, 'BATCH', '+m', 'draft/multiline #room').replace(' :draft/multiline #room', ' draft/multiline #room'),
    );
    s.ws.recv(line({ batch: 'm' }, 'PRIVMSG', '#room', 'one'));
    s.ws.recv(line({ batch: 'm' }, 'PRIVMSG', '#room', 'two'));
    s.ws.recv(':sender!u@h BATCH -m');
    await new Promise((r) => setTimeout(r, 50));
    expect(prefetch).not.toHaveBeenCalled();
    s.ws.recv(':srv BATCH -h');
    await until(() => prefetch.mock.calls.length > 0);
    expect(prefetch).toHaveBeenCalledTimes(1);
    expect(prefetch).toHaveBeenCalledWith([A, C]);
    release();
    await settle(s, [first.msgid, multi.msgid]);
    expect(s.seen.get(multi.msgid)?.settled?.state).toBe('device');
  });

  it('prefetches nothing for a batch with no signed line', async () => {
    const { lk, prefetch } = gatedLookup();
    const s = await session(OWN_DID, lk);
    s.ws.recv(':srv BATCH +h chathistory #room');
    s.ws.recv(line({ batch: 'h', msgid: 'plain1' }, 'PRIVMSG', '#room', 'unsigned'));
    s.ws.recv(':srv BATCH -h');
    await new Promise((r) => setTimeout(r, 50));
    expect(prefetch).not.toHaveBeenCalled();
  });

  it('starts the checks an open batch holds when the connection ends', async () => {
    const { lk, prefetch, keyForAt, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const lines = [await signed(A, 41, 'first', { batch: 'h' }), await signed(A, 41, 'second', { batch: 'h' })];
    s.ws.recv(':srv BATCH +h chathistory #room');
    for (const l of lines) s.ws.recv(l.wire);
    await new Promise((r) => setTimeout(r, 50));
    expect(keyForAt, 'no check while the batch is open').not.toHaveBeenCalled();

    // No `BATCH -h`: the connection ends with the batch still open.
    s.client.disconnect();
    await until(() => prefetch.mock.calls.length > 0);
    expect(prefetch).toHaveBeenCalledTimes(1);
    expect(prefetch).toHaveBeenCalledWith([A]);

    release();
    await until(() => keyForAt.mock.calls.length >= 2);
    expect(keyForAt).toHaveBeenCalledTimes(2);
  });

  it('settles a DM line an open batch held when the connection ends', async () => {
    const { lk, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    // An incoming DM from A to us: its venue is built from both DIDs, and
    // only `ownDid` tells the checker which end we are.
    const msgid = signing.newEventId();
    const key = await importDidKey(new Uint8Array(32).fill(41));
    const canonical = await signing.messageCanonical({
      from: A,
      msgid,
      target: signing.dmVenue(A, OWN_DID),
      body: 'psst',
    });
    const sig = await key.signer(new TextEncoder().encode(canonical));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    await hold(A, pub);
    const tags = { batch: 'h', account: A, msgid, [signing.SIG_TAG]: `ed25519:${await signing.deriveKid(pub)}:${sig}` };

    s.ws.recv(':srv BATCH +h chathistory me');
    s.ws.recv(line(tags, 'PRIVMSG', 'me', 'psst'));
    await new Promise((r) => setTimeout(r, 50));

    // No `BATCH -h`: the connection ends with the batch still open.
    s.client.disconnect();
    release();
    await settle(s, [msgid]);
    expect(s.seen.get(msgid)?.settled?.state).toBe('device');
  });

  it('starts the checks an open batch holds when the socket drops, once', async () => {
    const { lk, prefetch, keyForAt, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const lines = [await signed(A, 41, 'first', { batch: 'h' }), await signed(A, 41, 'second', { batch: 'h' })];
    s.ws.recv(':srv BATCH +h chathistory #room');
    for (const l of lines) s.ws.recv(l.wire);
    await new Promise((r) => setTimeout(r, 50));

    // No `BATCH -h`, and no `disconnect()`: the socket drops on its own.
    s.ws.close();
    await until(() => prefetch.mock.calls.length > 0);
    expect(prefetch).toHaveBeenCalledTimes(1);
    expect(prefetch).toHaveBeenCalledWith([A]);

    release();
    await settle(s, lines.map((l) => l.msgid));
    expect(keyForAt).toHaveBeenCalledTimes(2);
    expect(lines.map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual(['device', 'device']);
    s.client.disconnect();
  });

  it('delivers the verdict of a held check that finishes after the reconnect', async () => {
    const { lk, prefetch, keyForAt, release } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const lines = [await signed(A, 41, 'first', { batch: 'h' }), await signed(A, 41, 'second', { batch: 'h' })];
    s.ws.recv(':srv BATCH +h chathistory #room');
    for (const l of lines) s.ws.recv(l.wire);
    await new Promise((r) => setTimeout(r, 50));
    // The origin answers at about 1.5 s; the transport reconnects at about 1 s.
    origin.delayMs = 1500;

    s.ws.close();
    release();
    await until(() => MockWebSocket.instances.length === 2);
    expect(MockWebSocket.instances.length).toBe(2);
    for (let i = 0; i < 800 && lines.some((l) => s.seen.get(l.msgid)?.settled === undefined); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(lines.map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual(['device', 'device']);
    expect(prefetch).toHaveBeenCalledTimes(1);
    expect(keyForAt).toHaveBeenCalledTimes(2);
    s.client.disconnect();
  }, 10_000);

  it('checks a line outside a batch, or in a batch never seen opened, at once', async () => {
    const { lk, prefetch } = gatedLookup();
    const s = await session(OWN_DID, lk);
    const live = await signed(A, 41, 'live');
    const orphan = await signed(B, 42, 'orphan', { batch: 'never' });
    s.ws.recv(live.wire);
    s.ws.recv(orphan.wire);
    await settle(s, [live.msgid, orphan.msgid]);
    expect(prefetch).not.toHaveBeenCalled();
    expect([live, orphan].map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual(['device', 'device']);
  });
});
