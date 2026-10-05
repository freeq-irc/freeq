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

/** The connected server, reached at the host it is named for. */
const ORIGIN = 'https://server.test';
const PDS = 'https://pds.test';
const SERVER_DID = 'did:web:server.test';
const OWN_DID = 'did:plc:me';
/** A referee's own site, reached at https://referee.test. */
const SITE = 'https://referee.test';
const REFEREE = 'did:web:referee.test';

/** The referee's own key list: its keys by kid with their removal dates,
 *  answered after `delayMs`, or with `status` while set. */
interface Site {
  keys: Map<string, { key: Uint8Array; removedAt?: number }>;
  delayMs: number;
  status?: number;
  reads: number;
}

let site: Site;

async function siteAnswer(url: URL): Promise<Response> {
  site.reads++;
  if (site.delayMs > 0) await new Promise((r) => setTimeout(r, site.delayMs));
  if (site.status !== undefined) return new Response('no', { status: site.status });
  const did = decodeURIComponent(url.pathname.slice('/api/v1/signing-keys/'.length));
  const keys = [...site.keys].map(([kid, { key, removedAt }]) => ({
    kid,
    public_key: b64url(key),
    removed_at: removedAt ?? null,
  }));
  return Response.json({ did, keys: did === REFEREE ? keys : [] });
}

interface Origin {
  keys: Map<string, { key: Uint8Array; removedAt?: number }>;
  serverKeys: Uint8Array[];
  /** When the server's own keys were removed, if they were. */
  serverRemovedAt?: number;
  /** The name the server claims, when not its own host's (SERVER_DID). */
  claims?: string;
  /** Only this DID's keys are answered after `delayMs`, when set. */
  slowDid?: string;
  /** Answer the server's key set with this status instead, while set. */
  setStatus?: number;
  records: unknown[];
  delayMs: number;
  setReads: number;
  /** Serve `/api/v1/records?dids=`, each account with no device records;
   *  off, the server has no record routes. */
  recordRoutes: boolean;
  /** Requests to `/api/v1/records?dids=`, to the batch key route, and to the per-kid route. */
  recordsReads: number;
  batchReads: number;
  kidReads: number;
  /** The DIDs each records request named, one entry per DID, in the order asked. */
  recordsAsked: string[];
  /** The `did/kid` items each batch key request named, one list per request. */
  keysAsked: string[][];
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
  if (url.origin === SITE) return siteAnswer(url);
  if (url.origin !== ORIGIN) return new Response('unexpected', { status: 500 });
  if (url.pathname.startsWith('/api/v1/records/')) {
    origin.recordsAsked.push(decodeURIComponent(url.pathname.slice('/api/v1/records/'.length).split('/')[0]!));
  }
  if (url.pathname === '/api/v1/records' && origin.recordRoutes) {
    origin.recordsReads++;
    const dids = (url.searchParams.get('dids') ?? '').split(',');
    origin.recordsAsked.push(...dids);
    return Response.json({
      accounts: dids.map((did) => ({
        did,
        collections: {
          'at.freeq.deviceKey': { records: [], proofs: [], fetched_at: Math.floor(Date.now() / 1000) },
        },
      })),
    });
  }
  // A server without the record routes.
  if (url.pathname.startsWith('/api/v1/records')) return new Response('not found', { status: 404 });
  if (url.pathname === '/api/v1/signing-keys') {
    origin.batchReads++;
    origin.keysAsked.push((url.searchParams.get('keys') ?? '').split(','));
    const named = (url.searchParams.get('keys') ?? '').split(',');
    const slow = origin.slowDid === undefined || named.some((item) => item.startsWith(`${origin.slowDid}/`));
    if (origin.delayMs > 0 && slow) await new Promise((r) => setTimeout(r, origin.delayMs));
    const keys = named.flatMap((item) => {
      const at = item.indexOf('/');
      const [did, kid] = [item.slice(0, at), item.slice(at + 1)];
      const held = origin.keys.get(`${did} ${kid}`);
      return held ? [{ did, kid, public_key: b64url(held.key), removed_at: held.removedAt ?? null }] : [];
    });
    return Response.json({ keys });
  }
  if (url.pathname === '/api/v1/signing-key') {
    return Response.json({
      did: origin.claims ?? SERVER_DID,
      public_key: origin.serverKeys[0] && b64url(origin.serverKeys[0]),
    });
  }
  const prefix = '/api/v1/signing-keys/';
  const [did, kid] = url.pathname.slice(prefix.length).split('/').map(decodeURIComponent);
  if (kid === undefined) {
    origin.setReads++;
    if (origin.setStatus !== undefined) return new Response('no', { status: origin.setStatus });
    // The server's own set under the name it claims; for any other DID on
    // this host, that DID's own list: the keys held for it.
    const keys = did === (origin.claims ?? SERVER_DID)
      ? await Promise.all(
          origin.serverKeys.map(async (k) => ({
            kid: await signing.deriveKid(k),
            public_key: b64url(k),
            removed_at: origin.serverRemovedAt ?? null,
          })),
        )
      : [...origin.keys]
          .filter(([held]) => held.startsWith(`${did} `))
          .map(([held, { key, removedAt }]) => ({
            kid: held.slice(did.length + 1),
            public_key: b64url(key),
            removed_at: removedAt ?? null,
          }));
    return Response.json({ did, keys });
  }
  origin.kidReads++;
  if (origin.delayMs > 0 && (origin.slowDid === undefined || did === origin.slowDid)) {
    await new Promise((r) => setTimeout(r, origin.delayMs));
  }
  const held = origin.keys.get(`${did} ${kid}`);
  if (!held) return new Response('not found', { status: 404 });
  return Response.json({ did, kid, public_key: b64url(held.key), removed_at: held.removedAt ?? null });
};

function lookup(documents: DidDocument[] = [], retryAfterMs?: readonly number[]): KeyLookup {
  const resolveDid = async (did: string): Promise<DidDocument> => {
    const doc = documents.find((d) => d.id === did);
    if (!doc) throw new Error(`unknown DID ${did}`);
    return doc;
  };
  return new KeyLookup({ fetch: stubFetch, resolveDid }, ORIGIN, 3_600_000, retryAfterMs);
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  origin = {
    keys: new Map(),
    serverKeys: [],
    records: [],
    delayMs: 0,
    setReads: 0,
    recordRoutes: false,
    recordsReads: 0,
    batchReads: 0,
    kidReads: 0,
    recordsAsked: [],
    keysAsked: [],
  };
  site = { keys: new Map(), delayMs: 0, reads: 0 };
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

/** An authenticated session as `ownDid`, watching what lines come to,
 *  welcomed by a server named `welcome`. */
async function session(ownDid = OWN_DID, keyLookup: KeyLookup | null = lookup(), welcome = 'srv') {
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
  ws.recv(`:${welcome} 001 me :Welcome`);
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
      // A day ago, inside the key's lifetime.
      await buildDeviceRecord(m.key, SIGNER, new Date(Date.now() - 86_400_000).toISOString()),
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

  it('asks for its signers in one records request and their keys in one key request', async () => {
    origin.recordRoutes = true;
    const s = await session(OWN_DID, lookup());
    const lines = [
      await signed(A, 41, 'first', { batch: 'h' }),
      await signed(B, 42, 'second', { batch: 'h' }),
      await signed(A, 44, 'from another device', { batch: 'h' }),
      await signed(C, 43, 'fourth', { batch: 'h' }),
      await signed(A, 41, 'fifth', { batch: 'h' }),
    ];
    s.ws.recv(':srv BATCH +h chathistory #room');
    for (const l of lines) s.ws.recv(l.wire);
    s.ws.recv(':srv BATCH -h');
    await settle(s, lines.map((l) => l.msgid));

    expect(lines.map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual([
      'device',
      'device',
      'device',
      'device',
      'device',
    ]);
    expect(origin.recordsReads, 'records').toBe(1);
    expect(origin.batchReads, 'keys').toBe(1);
    expect(origin.kidReads, 'no key asked on its own').toBe(0);
  });

  it('sends one key request when two batches naming the same key close together', async () => {
    origin.recordRoutes = true;
    const s = await session(OWN_DID, lookup());
    const one = await signed(A, 41, 'first', { batch: 'h1' });
    const two = await signed(A, 41, 'second', { batch: 'h2' });
    s.ws.recv(':srv BATCH +h1 chathistory #room');
    s.ws.recv(one.wire);
    s.ws.recv(':srv BATCH +h2 chathistory #room');
    s.ws.recv(two.wire);
    s.ws.recv(':srv BATCH -h1');
    s.ws.recv(':srv BATCH -h2');
    await settle(s, [one.msgid, two.msgid]);

    expect([one, two].map((l) => s.seen.get(l.msgid)?.settled?.state)).toEqual(['device', 'device']);
    expect(origin.batchReads, 'keys').toBe(1);
    expect(origin.kidReads, 'no key asked on its own').toBe(0);
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

// ── a line a peer server signed ─────────────────────────────────────────

describe('a line a peer server signed', () => {
  const SENDER = 'did:plc:relayedsender';
  const PEER = 'peer.example';
  const PEER_DID = `did:web:${PEER}`;

  /** A line from SENDER signed with `seed`'s key, tagged with `peer` as its origin when given. */
  async function relayed(seed: number, body: string, peer?: string) {
    const msgid = signing.newEventId();
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    const canonical = await signing.messageCanonical({ from: SENDER, msgid, target: '#room', body });
    const sig = await key.signer(new TextEncoder().encode(canonical));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    const kid = await signing.deriveKid(pub);
    const tags: Record<string, string> = { account: SENDER, msgid, [signing.SIG_TAG]: `ed25519:${kid}:${sig}` };
    if (peer !== undefined) tags['+freeq.at/origin'] = peer;
    return { wire: line(tags, 'PRIVMSG', '#room', body), msgid, kid };
  }

  /** The peer server's did:web document, naming `seed`'s key. */
  async function peerDocument(seed: number): Promise<DidDocument> {
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    return {
      id: PEER_DID,
      verificationMethod: [
        { id: `${PEER_DID}#freeq`, type: 'Multikey', controller: PEER_DID, publicKeyMultibase: key.publicKeyMultibase },
      ],
      service: [],
    };
  }

  it("reads as the server's when the peer server's own key signed it", async () => {
    const m = await relayed(51, 'relayed', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51)]));
    expect((await s.lineFor([m.wire], m.msgid)).settled).toEqual({ state: 'server', kid: m.kid });
  });

  it("stays unverifiable when the peer server's key is not the one that signed", async () => {
    const m = await relayed(52, 'relayed', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51)]));
    expect((await s.lineFor([m.wire], m.msgid)).settled).toEqual({ state: 'unverifiable', kid: m.kid });
  });

  it('stays unverifiable when an origin tag names a server whose key did not sign it', async () => {
    // Signed by some key of the sender's own, tagged with a server it never passed through.
    const m = await relayed(53, 'not relayed at all', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51)]));
    expect((await s.lineFor([m.wire], m.msgid)).settled?.state).toBe('unverifiable');
  });

  it("remembers a missing server key like any miss", async () => {
    // The sender resolves to a PDS holding no records, so its miss is a
    // miss too, not a failure asked again.
    const sender: DidDocument = {
      id: SENDER,
      service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
    };
    // Short retries: the first line's sender miss is asked again, as any
    // fresh line's is, before it is remembered.
    const lk = lookup([await peerDocument(51), sender], [10, 20, 30]);
    const first = await relayed(52, 'one', PEER);
    const second = await relayed(52, 'two', PEER);
    const s = await session(OWN_DID, lk);
    await s.lineFor([first.wire], first.msgid);
    const asked = origin.batchReads;
    expect((await s.lineFor([second.wire], second.msgid)).settled?.state).toBe('unverifiable');
    expect(origin.batchReads, 'the second line asks nothing').toBe(asked);
  });

  /** The sender's document: a PDS holding no records, so a miss under the
   *  sender is a miss, not a failure. */
  const senderDocument = (): DidDocument => ({
    id: SENDER,
    service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
  });

  /** Wait up to `ms` for `id` to settle. */
  async function settledWithin(s: Awaited<ReturnType<typeof session>>, id: string, ms: number) {
    for (let waited = 0; waited < ms && s.seen.get(id)?.settled === undefined; waited += 20) {
      await new Promise((r) => setTimeout(r, 20));
    }
    return s.seen.get(id)?.settled;
  }

  it('still retries a federated user\'s key that reaches the server after the line', async () => {
    const m = await relayed(54, 'from a federated user', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51), senderDocument()]));
    // The server copies the key from the peer 2.5 s after the line arrives.
    const key = await importDidKey(new Uint8Array(32).fill(54));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    setTimeout(() => void hold(SENDER, pub), 2_500);
    s.ws.recv(m.wire);
    expect(await settledWithin(s, m.msgid, 12_000)).toEqual({
      state: 'device',
      layer: 'vouched',
      kid: m.kid,
      keySource: 'OriginServer',
    });
  }, 20_000);

  it('gives a server-signed relayed line the server verdict without waiting out the retries', async () => {
    const m = await relayed(51, 'signed by the peer', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51), senderDocument()]));
    s.ws.recv(m.wire);
    expect(await settledWithin(s, m.msgid, 1_500)).toEqual({ state: 'server', kid: m.kid });
  });

  it('prefetches a relayed line in a history batch under the peer server too, in one request', async () => {
    origin.recordRoutes = true;
    const m = await relayed(51, 'signed by the peer', PEER);
    const key = await importDidKey(new Uint8Array(32).fill(51));
    await hold(PEER_DID, (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase));
    const s = await session(OWN_DID, lookup([await peerDocument(51), senderDocument()]));
    const inBatch = m.wire.replace('@', '@batch=h;');
    s.ws.recv(':srv BATCH +h chathistory #room');
    s.ws.recv(inBatch);
    s.ws.recv(':srv BATCH -h');
    expect(await settledWithin(s, m.msgid, 2_000)).toEqual({ state: 'server', kid: m.kid });

    expect(origin.keysAsked).toEqual([[`${SENDER}/${m.kid}`, `${PEER_DID}/${m.kid}`]]);
    expect(origin.kidReads, 'no key asked on its own').toBe(0);
  });

  it('asks for no device records of a peer server', async () => {
    origin.recordRoutes = true;
    const m = await relayed(51, 'signed by the peer', PEER);
    const s = await session(OWN_DID, lookup([await peerDocument(51), senderDocument()]));
    s.ws.recv(m.wire);
    expect(await settledWithin(s, m.msgid, 1_500)).toEqual({ state: 'server', kid: m.kid });
    expect(origin.recordsAsked).not.toContain(PEER_DID);
  });

  it('is not looked up under a server without the tag', async () => {
    const m = await relayed(51, 'no tag');
    const s = await session(OWN_DID, lookup([await peerDocument(51)]));
    expect((await s.lineFor([m.wire], m.msgid)).settled?.state).toBe('unverifiable');
  });
});

// ── task events and rulings ─────────────────────────────────────────────

describe('a task event', () => {
  const ALICE = 'did:plc:alice';
  const ROOM = '#tasks';

  async function keyOf(seed: number) {
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    const pub = (await import('./did-key.js')).decodeMultibaseEd25519(key.publicKeyMultibase);
    return { key, pub, kid: await signing.deriveKid(pub) };
  }

  async function list(seed: number, removedAt?: number) {
    const { pub, kid } = await keyOf(seed);
    site.keys.set(kid, { key: pub, removedAt });
  }

  /** A task event signed with `seed`'s key as `signer`: an opener when
   *  `task` is undefined, else `verb` on that task. */
  async function taskEvent(
    seed: number,
    signer: string,
    verb: string,
    task?: string,
    extra: Record<string, string> = {},
    venue = signing.channelVenue(ROOM),
    target = ROOM,
    id = signing.newEventId(),
  ) {
    const { key, kid } = await keyOf(seed);
    const tags: Record<string, string> = {
      '+freeq.at/act': 'handoff',
      '+freeq.at/act-verb': verb,
      '+freeq.at/from': signer,
      ...(task ? { '+freeq.at/act-id': task } : {}),
      ...extra,
    };
    const canonical = signing.actCanonical(tags, venue, id)!;
    const sig = await key.signer(new TextEncoder().encode(canonical));
    const wire = { ...tags, [signing.EVENT_ID_TAG]: id, [signing.SIG_TAG]: `ed25519:${kid}:${sig}` };
    return { id, tags: wire, wire: line(wire, 'TAGMSG', target) };
  }

  /** Advance fake time by `ms` in steps, letting real work (WebCrypto runs
   *  on the thread pool, off fake time) finish between them. */
  const realTimeout = setTimeout;
  async function advance(ms: number, step = 100) {
    for (let t = 0; t < ms; t += step) {
      await vi.advanceTimersByTimeAsync(Math.min(step, ms - t));
      await new Promise((r) => realTimeout(r, 2));
    }
  }

  const opener = (home?: string) =>
    taskEvent(90, ALICE, 'offer', undefined, home === undefined ? {} : { '+freeq.at/act-home': home });

  /** Every task event and verdict as it goes up, in order. */
  async function watching(keyLookup: KeyLookup = lookup([], []), welcome = 'srv') {
    // ALICE's openers check: an opener names its referee only then.
    await hold(ALICE, (await keyOf(90)).pub);
    const s = await session(OWN_DID, keyLookup, welcome);
    const up: { kind: 'act' | 'verdict'; id: string; verdict?: string; ruling?: string }[] = [];
    s.client.on('actEvent', (p) =>
      up.push({ kind: 'act', id: p.eventId, verdict: p.verdict?.state, ruling: p.ruling }),
    );
    s.client.on('verdict', (id, v) => up.push({ kind: 'verdict', id, verdict: v.state }));
    const send = async (...lines: string[]) => {
      for (const l of lines) {
        s.ws.recv(l);
        await flushAsync();
      }
    };
    const act = (id: string) => up.find((u) => u.kind === 'act' && u.id === id);
    const actFor = async (id: string, ms = 3_000) => {
      for (let i = 0; i < ms / 5 && act(id) === undefined; i++) await new Promise((r) => setTimeout(r, 5));
      return act(id);
    };
    const at = (kind: 'act' | 'verdict', id: string) => up.findIndex((u) => u.kind === kind && u.id === id);
    /** What the ruling `id` on `task` went up as, null when it never went
     *  up: a move on the task sent after it waits behind it, so once the
     *  move is up the ruling has been settled. */
    const wentUpAs = async (id: string, task: string) => {
      const claim = await taskEvent(90, ALICE, 'claim', task);
      await send(claim.wire);
      await actFor(claim.id);
      const a = act(id);
      return a === undefined ? null : a.ruling;
    };
    return { ...s, up, send, act, actFor, at, wentUpAs };
  }

  it('that is no ruling goes up at once, pending, and its verdict follows', async () => {
    await hold(ALICE, (await keyOf(90)).pub);
    origin.delayMs = 100;
    const w = await watching();
    const t = await opener();
    await w.send(t.wire);
    expect(w.up, 'at once, pending').toEqual([{ kind: 'act', id: t.id, verdict: 'pending', ruling: undefined }]);
    for (let i = 0; i < 200 && w.up.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    expect(w.up[1]).toEqual({ kind: 'verdict', id: t.id, verdict: 'device' });
    w.client.disconnect();
  });

  it('that is a ruling goes up once checked when it counts, and never when it fails', async () => {
    const cases: [() => Promise<void>, string, number, string][] = [
      [() => list(91), REFEREE, 91, 'counts'],
      [() => list(91), 'did:web:other.test', 91, 'fails'],
      [() => list(93), REFEREE, 91, 'fails'],
      [() => list(91, 1_600_000_000), REFEREE, 91, 'fails'],
      [async () => { site.status = 503; }, REFEREE, 91, 'cannot-check'],
    ];
    for (const [arrange, signer, seed, expected] of cases) {
      site = { keys: new Map(), delayMs: 100, reads: 0 };
      await arrange();
      const w = await watching();
      const o = await opener(REFEREE);
      const r = await taskEvent(seed, signer, 'expire', o.id);
      await w.send(o.wire, r.wire);
      expect(w.act(r.id), 'waits for its check').toBeUndefined();
      if (expected === 'fails') {
        expect(await w.wentUpAs(r.id, o.id), `${signer} ${seed}: never goes up`).toBeNull();
      } else {
        expect((await w.actFor(r.id))?.ruling, `${signer} ${seed}`).toBe(expected);
      }
      w.client.disconnect();
    }
  });

  it("sends a ruling's verdict after its event, and a failing ruling's with no event, as the Rust SDK does", async () => {
    await list(91);
    for (const [seed, expected] of [[91, 'counts'], [93, 'fails']] as const) {
      const w = await watching();
      const o = await opener(REFEREE);
      const r = await taskEvent(seed, REFEREE, 'expire', o.id);
      await w.send(o.wire, r.wire);
      if (expected === 'fails') expect(await w.wentUpAs(r.id, o.id), 'never goes up').toBeNull();
      else expect((await w.actFor(r.id))?.ruling, String(seed)).toBe(expected);
      for (let i = 0; i < 200 && w.at('verdict', r.id) < 0; i++) await new Promise((res) => setTimeout(res, 5));
      expect(w.at('verdict', r.id), `${expected}: a verdict`).toBeGreaterThanOrEqual(0);
      if (expected === 'counts') {
        expect(w.at('act', r.id), `${expected}: the event first`).toBeLessThan(w.at('verdict', r.id));
      }
      w.client.disconnect();
    }
  });

  it('that is a ruling on a task naming no referee cannot be checked', async () => {
    await list(91);
    const w = await watching();
    const o = await opener();
    const r = await taskEvent(91, REFEREE, 'confirm', o.id);
    await w.send(o.wire, r.wire);
    expect((await w.actFor(r.id))?.ruling).toBe('cannot-check');
    w.client.disconnect();
  });

  it("that is the connected server's own ruling counts only before its key was retired", async () => {
    origin.serverKeys = [(await keyOf(94)).pub];
    // Failing: never goes up.
    for (const [removedAt, expected] of [[undefined, 'counts'], [1_600_000_000, null]] as const) {
      origin.serverRemovedAt = removedAt;
      const w = await watching(lookup([], []), 'server.test');
      const o = await opener(SERVER_DID);
      const r = await taskEvent(94, SERVER_DID, 'confirm', o.id);
      await w.send(o.wire, r.wire);
      expect(await w.wentUpAs(r.id, o.id), String(removedAt)).toBe(expected);
      w.client.disconnect();
    }
    expect(site.reads, 'its own set, not a site').toBe(0);
  });

  it("that names a person and is signed with the connected server's key is invalid; the server's own keeps its verdict", async () => {
    origin.serverKeys = [(await keyOf(94)).pub];
    const w = await watching(lookup([], []), 'server.test');
    const o = await opener(SERVER_DID);
    await w.send(o.wire);
    for (const verb of ['claim', 'progress']) {
      const move = await taskEvent(94, ALICE, verb, o.id);
      await w.send(move.wire);
      for (let i = 0; i < 200 && w.at('verdict', move.id) < 0; i++) await new Promise((r) => setTimeout(r, 5));
      expect(w.up[w.at('verdict', move.id)]?.verdict, verb).toBe('invalid');
    }
    const expire = await taskEvent(94, SERVER_DID, 'expire', o.id);
    await w.send(expire.wire);
    expect(await w.actFor(expire.id), "the server's own ruling").toEqual({
      kind: 'act',
      id: expire.id,
      verdict: 'server',
      ruling: 'counts',
    });
    w.client.disconnect();
  });

  it("that opens a task and is signed with the connected server's key reads invalid and names no referee", async () => {
    await list(91);
    origin.serverKeys = [(await keyOf(94)).pub];
    const w = await watching();
    const o = await taskEvent(94, ALICE, 'offer', undefined, { '+freeq.at/act-home': REFEREE });
    await w.send(o.wire);
    for (let i = 0; i < 200 && w.at('verdict', o.id) < 0; i++) await new Promise((r) => setTimeout(r, 5));
    expect(w.up[w.at('verdict', o.id)]?.verdict).toBe('invalid');
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(r.wire);
    expect(await w.wentUpAs(r.id, o.id)).not.toBe('counts');
    w.client.disconnect();
  });

  it('that is ruled under a name the connected server only claims does not count by its keys', async () => {
    // The server reached at server.test calls itself referee.test, whose own
    // site lists nothing.
    origin.serverKeys = [(await keyOf(94)).pub];
    origin.claims = REFEREE;
    const w = await watching(lookup([], []), 'referee.test');
    const o = await opener(REFEREE);
    const r = await taskEvent(94, REFEREE, 'confirm', o.id);
    await w.send(o.wire, r.wire);
    expect(await w.wentUpAs(r.id, o.id), 'its own keys do not count for the name it claims: never goes up').toBeNull();
    expect(site.reads, "the name's own site was read").toBe(1);
    w.client.disconnect();
  });

  it('behind a waiting ruling goes up after it, and one on another task does not wait', async () => {
    await list(91);
    site.delayMs = 300;
    await hold(ALICE, (await keyOf(90)).pub);
    const w = await watching();
    const a = await opener(REFEREE);
    const ruling = await taskEvent(91, REFEREE, 'expire', a.id);
    const claim = await taskEvent(90, ALICE, 'claim', a.id);
    const b = await opener();
    await w.send(a.wire, ruling.wire, claim.wire, b.wire);
    await w.actFor(claim.id);
    for (let i = 0; i < 200 && w.at('verdict', claim.id) < 0; i++) await new Promise((r) => setTimeout(r, 5));
    const acts = w.up.filter((u) => u.kind === 'act').map((u) => u.id);
    expect(acts).toEqual([a.id, b.id, ruling.id, claim.id]);
    // Its verdict settled while it waited, so it goes up with that one,
    // never with pending after it.
    expect(w.act(claim.id)).toEqual({ kind: 'act', id: claim.id, verdict: 'device', ruling: undefined });
    w.client.disconnect();
  });

  it('that is a ruling goes up when the wait runs out, pending only while no verdict has settled', async () => {
    const { RULING_WAIT_MS } = await import('./client.js');
    await list(91);
    // The ruling's own key lookup is slow; its check, and its opener's, are
    // not.
    await hold(REFEREE, (await keyOf(91)).pub);
    origin.delayMs = 60_000;
    origin.slowDid = REFEREE;
    const w = await watching();
    const o = await opener(REFEREE);
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await w.send(o.wire, r.wire);
      await advance(RULING_WAIT_MS - 100);
      expect(w.act(r.id)).toBeUndefined();
      await advance(100);
      expect(w.act(r.id)).toEqual({ kind: 'act', id: r.id, verdict: 'pending', ruling: 'counts' });
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  it('that is a ruling whose check runs out goes up with its settled verdict', async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    // Its opener seen, its referee's site slower than the check: the
    // referee is known, so it goes up unchecked, as the Rust SDK's does.
    site.delayMs = 12_000;
    const w = await watching();
    const o = await opener(REFEREE);
    await w.send(o.wire);
    await new Promise((res) => setTimeout(res, 50));
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await w.send(r.wire);
      await advance(10_000);
      expect(w.act(r.id)).toEqual({ kind: 'act', id: r.id, verdict: 'device', ruling: 'cannot-check' });
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  /** A task history route answering `home` as the opener's referee for
   *  `task`, after `delayMs`, heeding the abort; `status` while set. */
  function history(task: string, home: string, delayMs = 0) {
    const state: { status?: number } = {};
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toMatch(new RegExp(`/api/v1/actions/${task}$`));
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, delayMs);
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('aborted'));
        });
      });
      if (new Headers(init?.headers).get('authorization') !== 'Bearer sekrit') {
        return new Response('forbidden', { status: 403 });
      }
      if (state.status !== undefined) return new Response('no', { status: state.status });
      return Response.json({ act_id: task, events: [await servedOpener(task, home)] });
    });
    vi.stubGlobal('fetch', fetch);
    return { fetch, state };
  }

  it('that is a ruling still finishes inside the wait after a slow history read and a slow referee read', async () => {
    await list(91);
    // Each read slower than the 4 s and 5 s limits the reads once had; both
    // together inside the check's own 10 s.
    site.delayMs = 5_200;
    const task = signing.newEventId();
    const { fetch } = history(task, REFEREE, 4_400);
    const w = await watching();
    await w.send(':srv NOTICE * :API-BEARER sekrit');
    const r = await taskEvent(91, REFEREE, 'expire', task);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await w.send(r.wire);
      await advance(9_800);
      expect(w.act(r.id)?.ruling).toBe('counts');
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  it('that is a ruling reads a failed task history again, and rulings at once share a read', async () => {
    await list(91);
    const task = signing.newEventId();
    const { fetch, state } = history(task, REFEREE, 50);
    state.status = 500;
    const w = await watching();
    await w.send(':srv NOTICE * :API-BEARER sekrit');
    const first = await taskEvent(91, REFEREE, 'expire', task);
    const second = await taskEvent(91, REFEREE, 'confirm', task);
    // With no opener the referee cannot be known: both are hidden, and the
    // move behind them goes on.
    const claim = await taskEvent(90, ALICE, 'claim', task);
    await w.send(first.wire, second.wire, claim.wire);
    expect(await w.actFor(claim.id)).toBeDefined();
    expect(w.act(first.id), 'hidden').toBeUndefined();
    expect(w.act(second.id), 'hidden').toBeUndefined();
    expect(fetch, 'one read').toHaveBeenCalledTimes(1);
    state.status = undefined;
    const third = await taskEvent(91, REFEREE, 'expire', task);
    await w.send(third.wire);
    expect((await w.actFor(third.id))?.ruling).toBe('counts');
    expect(fetch).toHaveBeenCalledTimes(2);
    w.client.disconnect();
  });

  it('that is a ruling whose history read fails is judged from an opener that checked while the read was under way', async () => {
    await list(91);
    const o = await opener(REFEREE);
    const { fetch, state } = history(o.id, REFEREE, 800);
    state.status = 500;
    const w = await watching();
    await w.send(':srv NOTICE * :API-BEARER sekrit');
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(r.wire);
    await new Promise((resolve) => setTimeout(resolve, 100));
    await w.send(o.wire);
    expect((await w.actFor(r.id))?.ruling, "judged from the opener's naming").toBe('counts');
    const again = await taskEvent(91, REFEREE, 'confirm', o.id);
    await w.send(again.wire);
    expect((await w.actFor(again.id))?.ruling).toBe('counts');
    expect(fetch, 'the second ruling read nothing').toHaveBeenCalledTimes(1);
    w.client.disconnect();
  });

  it('that is a ruling in a history batch waits for the batch to close', async () => {
    await list(91);
    const w = await watching();
    const o = await opener(REFEREE);
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(o.wire, ':srv BATCH +h chathistory #tasks', line({ ...r.tags, batch: 'h' }, 'TAGMSG', ROOM));
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(w.act(r.id), 'held for the batch').toBeUndefined();
    await w.send(':srv BATCH -h');
    expect((await w.actFor(r.id))?.ruling).toBe('counts');
    w.client.disconnect();
  });

  it("sends no verdict for a ruling dropped at disconnect once a reconnect has replaced the checker", async () => {
    await list(91);
    await hold(ALICE, (await keyOf(90)).pub);
    const w = await watching();
    const o = await opener(REFEREE);
    await w.send(o.wire);
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The ruling's own key is read slowly: its verdict settles after the
    // transport has reconnected, at about 1 s.
    origin.delayMs = 1500;
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(r.wire);
    w.ws.close();
    for (let i = 0; i < 400 && MockWebSocket.instances.length < 2; i++) await new Promise((res) => setTimeout(res, 5));
    expect(MockWebSocket.instances.length, 'reconnected').toBe(2);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    expect(w.act(r.id), 'dropped').toBeUndefined();
    expect(w.at('verdict', r.id), 'no verdict from the old connection').toBe(-1);
    w.client.disconnect();
  }, 10_000);

  it('that is a ruling still being checked when the connection drops is dropped, and its replay goes up checked', async () => {
    await list(91);
    await hold(ALICE, (await keyOf(90)).pub);
    site.delayMs = 300;
    const w = await watching();
    const o = await opener(REFEREE);
    const live = await taskEvent(91, REFEREE, 'expire', o.id);
    const behind = await taskEvent(90, ALICE, 'claim', o.id);
    const replayed = await taskEvent(91, REFEREE, 'confirm', o.id);
    await w.send(
      o.wire,
      live.wire,
      behind.wire,
      ':srv BATCH +h chathistory #tasks',
      line({ ...replayed.tags, batch: 'h' }, 'TAGMSG', ROOM),
    );
    // The socket drops while the live ruling is being checked.
    w.ws.close();
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(w.act(live.id), 'dropped, not shown unchecked').toBeUndefined();
    expect(w.act(behind.id), 'and the move behind it').toBeUndefined();
    expect(w.act(replayed.id), "the cut batch's is dropped").toBeUndefined();

    // Reconnected: the replay is not taken for a repeat, and goes up checked.
    for (let i = 0; i < 400 && MockWebSocket.instances.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    const again = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    again.recv(':srv 001 me :Welcome');
    await flushAsync();
    for (const t of [o, live, behind]) {
      again.recv(line({ ...t.tags, time: '2026-10-06T10:00:00.000Z' }, 'TAGMSG', ROOM));
      await flushAsync();
    }
    await w.actFor(behind.id);
    expect(w.act(live.id)?.ruling).toBe('counts');
    expect(w.at('act', live.id), 'the ruling, then the move').toBeLessThan(w.at('act', behind.id));
    w.client.disconnect();
  }, 10_000);

  it("asks the referee's own list when the connected server's key set names another DID", async () => {
    origin.serverKeys = [(await keyOf(94)).pub];
    origin.claims = 'did:web:elsewhere.test';
    // The referee's own list on its host lists the key.
    await hold(SERVER_DID, (await keyOf(94)).pub);
    const w = await watching(lookup([], []), 'server.test');
    const o = await opener(SERVER_DID);
    const r = await taskEvent(94, SERVER_DID, 'confirm', o.id);
    await w.send(o.wire, r.wire);
    expect((await w.actFor(r.id))?.ruling).toBe('counts');
    w.client.disconnect();
  });

  it("that is the connected server's own ruling under a new key cannot be checked while its set cannot be read, and is read again", async () => {
    origin.serverKeys = [(await keyOf(94)).pub];
    const w = await watching(lookup([], []), 'server.test');
    const o = await opener(SERVER_DID);
    await w.send(o.wire);
    const old = await taskEvent(94, SERVER_DID, 'confirm', o.id);
    await w.send(old.wire);
    expect((await w.actFor(old.id))?.ruling, 'the old key').toBe('counts');
    // The server rotates to 95; its key set cannot be read for now.
    origin.serverKeys.push((await keyOf(95)).pub);
    origin.setStatus = 503;
    const next = await taskEvent(95, SERVER_DID, 'expire', o.id);
    await w.send(next.wire);
    expect((await w.actFor(next.id))?.ruling, 'the new key, its re-read failing').toBe('cannot-check');
    origin.setStatus = undefined;
    const again = await taskEvent(95, SERVER_DID, 'confirm', o.id);
    await w.send(again.wire);
    expect((await w.actFor(again.id))?.ruling, 'the new key, the server answering again').toBe('counts');
    w.client.disconnect();
  });

  it('behind a ruling dropped with its cut batch is dropped too, and the replay gives them back in order', async () => {
    await list(91);
    site.delayMs = 50;
    const w = await watching();
    const o = await opener(REFEREE);
    const ruling = await taskEvent(91, REFEREE, 'confirm', o.id);
    const progress = await taskEvent(90, ALICE, 'progress', o.id);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    await w.send(
      o.wire,
      ':srv BATCH +h chathistory #tasks',
      line({ ...ruling.tags, batch: 'h' }, 'TAGMSG', ROOM),
      line({ ...progress.tags, batch: 'h' }, 'TAGMSG', ROOM),
      // Live, while the batch is open.
      claim.wire,
    );
    // The socket drops with the batch still open.
    w.ws.close();
    await new Promise((resolve) => setTimeout(resolve, 100));
    for (const t of [ruling, progress, claim]) expect(w.act(t.id), 'dropped').toBeUndefined();

    // Reconnected: the replay brings them all again.
    for (let i = 0; i < 400 && MockWebSocket.instances.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    const again = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    again.recv(':srv 001 me :Welcome');
    await flushAsync();
    const replay = [o, ruling, progress, claim].map((t) =>
      line({ ...t.tags, batch: 'h2', time: '2026-10-06T10:00:00.000Z' }, 'TAGMSG', ROOM),
    );
    for (const l of [':srv BATCH +h2 chathistory #tasks', ...replay, ':srv BATCH -h2']) {
      again.recv(l);
      await flushAsync();
    }
    await w.actFor(claim.id);
    expect(w.act(ruling.id)?.ruling).toBe('counts');
    expect(w.at('act', ruling.id), 'the ruling, then the moves').toBeLessThan(w.at('act', progress.id));
    expect(w.at('act', progress.id)).toBeLessThan(w.at('act', claim.id));
    w.client.disconnect();
  }, 10_000);

  it("that is a ruling on a DM task is checked under the task's own venue", async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const ours = signing.dmVenue(ALICE, OWN_DID);
    const w = await watching();
    // Seen: ALICE opens the task in a DM to this session.
    const o = await taskEvent(90, ALICE, 'offer', undefined, { '+freeq.at/act-home': REFEREE }, ours, 'me');
    await w.send(o.wire);
    for (const verb of ['expire', 'confirm']) {
      const r = await taskEvent(91, REFEREE, verb, o.id, {}, ours, '*');
      await w.send(r.wire);
      expect(await w.actFor(r.id), verb).toEqual({ kind: 'act', id: r.id, verdict: 'device', ruling: 'counts' });
    }
    // Read from the history: its opener's venue is the pair it names.
    // Failing: never goes up.
    for (const [pair, expected] of [
      [ours, 'counts'],
      [signing.dmVenue(ALICE, 'did:plc:bob'), null],
    ] as const) {
      const task = signing.newEventId();
      vi.stubGlobal(
        'fetch',
        vi.fn(async () =>
          Response.json({
            act_id: task,
            events: [await servedOpener(task, REFEREE, pair)],
          }),
        ),
      );
      const r = await taskEvent(91, REFEREE, 'expire', task, {}, pair, '*');
      await w.send(r.wire);
      expect(await w.wentUpAs(r.id, task), pair).toBe(expected);
    }
    w.client.disconnect();
  });

  it("that is a DM ruling before this session's own DID is known is hidden", async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const pair = signing.dmVenue(ALICE, OWN_DID);
    const task = signing.newEventId();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          act_id: task,
          events: [await servedOpener(task, REFEREE, pair)],
        }),
      ),
    );
    // Signed in with no DID the session knows.
    const s = await session('', lookup([], []));
    const rulings = new Map<string, string | undefined>();
    s.client.on('actEvent', (p) => rulings.set(p.eventId, p.ruling));
    const r = await taskEvent(91, REFEREE, 'expire', task, {}, pair, '*');
    s.ws.recv(r.wire);
    await new Promise((res) => setTimeout(res, 1_000));
    expect(rulings.has(r.id), 'hidden: the pair it was signed for is unknown').toBe(false);
    s.client.disconnect();
  });

  it("gives an unverifiable verdict to a ruling's line whose DM pair needs the session's DID, or that names no signer", async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const pair = signing.dmVenue(ALICE, OWN_DID);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('no', { status: 500 })));
    const verdicts = (client: { on: (e: 'verdict', f: (id: string, v: Verdict) => void) => void }) => {
      const got = new Map<string, Verdict>();
      client.on('verdict', (id, v) => got.set(id, v));
      return got;
    };
    const until = async (got: Map<string, Verdict>, id: string) => {
      for (let i = 0; i < 400 && !got.has(id); i++) await new Promise((res) => setTimeout(res, 5));
      return got.get(id);
    };

    // Signed in with no DID the session knows: the pair cannot be built.
    const s = await session('', lookup([], []));
    const early = verdicts(s.client);
    const dm = await taskEvent(91, REFEREE, 'expire', signing.newEventId(), {}, pair, '*');
    s.ws.recv(dm.wire);
    const kid = (await keyOf(91)).kid;
    expect(await until(early, dm.id), 'no session DID').toEqual({ state: 'unverifiable', kid });
    s.client.disconnect();

    // Signed, but with no `+freeq.at/from` naming its signer.
    const w = await watching();
    const named = verdicts(w.client);
    const real = await taskEvent(91, REFEREE, 'expire', signing.newEventId());
    const { ['+freeq.at/from']: _from, ...tags } = real.tags;
    await w.send(line(tags, 'TAGMSG', ROOM));
    expect(await until(named, real.id), 'no signer named').toEqual({ state: 'unverifiable', kid });
    w.client.disconnect();
  });

  it('that is a ruling on a DM task whose pair is unknown is hidden, and no key is looked up', async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const pair = signing.dmVenue(ALICE, OWN_DID);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('no', { status: 500 })));
    const w = await watching();
    const r = await taskEvent(91, REFEREE, 'expire', signing.newEventId(), {}, pair, '*');
    await w.send(r.wire);
    for (let i = 0; i < 200 && w.at('verdict', r.id) < 0; i++) await new Promise((res) => setTimeout(res, 5));
    expect(w.act(r.id), 'hidden').toBeUndefined();
    expect(w.up[w.at('verdict', r.id)]?.verdict, "its line's verdict").toBe('unverifiable');
    expect(origin.batchReads + origin.kidReads, 'no key looked up').toBe(0);
    expect(site.reads, "nor the referee's list").toBe(0);
    w.client.disconnect();
  });

  it("that fails, a copy of a ruling's id, does not hide the genuine ruling", async () => {
    await list(91);
    const w = await watching();
    const o = await opener(REFEREE);
    await w.send(o.wire);
    const id = signing.newEventId();
    const copy = await taskEvent(93, REFEREE, 'expire', o.id, {}, undefined, undefined, id);
    await w.send(copy.wire);
    expect(await w.wentUpAs(id, o.id), 'the copy never goes up').toBeNull();
    w.up.length = 0;
    const genuine = await taskEvent(91, REFEREE, 'expire', o.id, {}, undefined, undefined, id);
    await w.send(genuine.wire);
    expect((await w.actFor(id))?.ruling, 'the genuine ruling').toBe('counts');
    w.client.disconnect();
  });

  it('names its referee only from an opener whose signature checks', async () => {
    await list(91);
    await hold(ALICE, (await keyOf(90)).pub);
    for (const fakeFirst of [false, true]) {
      const o = await opener(REFEREE);
      const history = vi.fn(async () =>
        Response.json({
          act_id: o.id,
          events: [served(o)],
        }),
      );
      vi.stubGlobal('fetch', history);
      const w = await watching();
      const fake = line(
        {
          '+freeq.at/act': 'handoff',
          '+freeq.at/act-verb': 'offer',
          '+freeq.at/from': ALICE,
          '+freeq.at/act-home': 'did:web:evil.test',
          [signing.EVENT_ID_TAG]: o.id,
        },
        'TAGMSG',
        ROOM,
      );
      await w.send(...(fakeFirst ? [fake, o.wire] : [o.wire, fake]));
      await new Promise((resolve) => setTimeout(resolve, 50));
      const r = await taskEvent(91, REFEREE, 'expire', o.id);
      await w.send(r.wire);
      expect((await w.actFor(r.id))?.ruling, `fake first: ${fakeFirst}`).toBe('counts');
      w.client.disconnect();
    }
  });

  it('that is unsigned or unreadable fails where its task names a referee, at once, and never goes up', async () => {
    await list(91);
    // A well-formed signature over a ruling whose `from` is then left off.
    const real = await taskEvent(91, REFEREE, 'expire', '01TASK');
    const kinds: [string, string | undefined, boolean][] = [
      ['unsigned', undefined, true],
      ['unknown algorithm', 'ed99999:somekid:c2ln', true],
      ['not alg:kid:sig', 'garbled', true],
      ['a signature that is not one', 'ed25519:somekid:c2ln', true],
      ['no from', real.tags[signing.SIG_TAG], false],
    ];
    // Failing: never goes up.
    for (const [named, expected] of [[true, undefined], [false, 'cannot-check']] as const) {
      for (const [kind, sig, withFrom] of kinds) {
        const w = await watching();
        const o = await opener(named ? REFEREE : undefined);
        await w.send(o.wire);
        await new Promise((resolve) => setTimeout(resolve, 50));
        const id = signing.newEventId();
        const tags: Record<string, string> = {
          '+freeq.at/act': 'handoff',
          '+freeq.at/act-verb': 'expire',
          ...(withFrom ? { '+freeq.at/from': REFEREE } : {}),
          '+freeq.at/act-id': o.id,
          [signing.EVENT_ID_TAG]: id,
          ...(sig ? { [signing.SIG_TAG]: sig } : {}),
        };
        const claim = await taskEvent(90, ALICE, 'claim', o.id);
        const sent = Date.now();
        await w.send(line(tags, 'TAGMSG', ROOM), claim.wire);
        await w.actFor(claim.id);
        expect(Date.now() - sent, `${kind}, named ${named}`).toBeLessThan(3_000);
        if (expected === undefined) expect(w.act(id), `${kind}, named ${named}`).toBeUndefined();
        else expect(w.act(id)?.ruling, `${kind}, named ${named}`).toBe(expected);
        w.client.disconnect();
      }
    }
  });

  it('that fails never goes up, and the move behind it does not wait for its verdict', async () => {
    await list(91);
    const w = await watching();
    const o = await opener(REFEREE);
    await w.send(o.wire);
    for (let i = 0; i < 200 && w.at('verdict', o.id) < 0; i++) await new Promise((r) => setTimeout(r, 5));
    // The ruling's own key is read slowly; the referee's list answers at once.
    origin.delayMs = 1_500;
    origin.slowDid = REFEREE;
    const r = await taskEvent(93, REFEREE, 'expire', o.id);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    const sent = Date.now();
    await w.send(r.wire, claim.wire);
    await w.actFor(claim.id);
    expect(Date.now() - sent, "the move did not wait for the ruling's verdict").toBeLessThan(1_000);
    for (let i = 0; i < 600 && w.at('verdict', r.id) < 0; i++) await new Promise((res) => setTimeout(res, 5));
    expect(w.at('verdict', r.id), "its line's verdict still follows").toBeGreaterThanOrEqual(0);
    expect(w.act(r.id), 'never goes up').toBeUndefined();
    w.client.disconnect();
  });

  /** One event as `/api/v1/actions/{id}` serves it, signed for `venue`. */
  function served(t: { id: string; tags: Record<string, string> }, venue = signing.channelVenue(ROOM)) {
    return {
      event_id: t.id,
      canonical: signing.actCanonical(t.tags, venue, t.id),
      signature: t.tags[signing.SIG_TAG],
      actor_did: t.tags['+freeq.at/from'],
      venue,
      confirm_state: null,
      timestamp: 1_700_000_000,
    };
  }

  /** `task`'s opener, ALICE's, naming `home`, as the history route serves
   *  it, signed for `venue`. */
  async function servedOpener(task: string, home: string, venue = signing.channelVenue(ROOM)) {
    const o = await taskEvent(90, ALICE, 'offer', undefined, { '+freeq.at/act-home': home }, venue, ROOM, task);
    return served(o, venue);
  }

  /** `event` as a server that took `name` out of its document serves it,
   *  its signature left as it was. */
  function stripped<T extends { canonical?: string | null }>(event: T, name: string): T {
    const doc = JSON.parse(event.canonical!) as Record<string, unknown>;
    delete doc[name];
    return { ...event, canonical: JSON.stringify(doc) };
  }

  /** The task history route, answering each task's events in order. */
  function histories(held: Map<string, { id: string; tags: Record<string, string> }[]>) {
    const fetch = vi.fn(async (url: string) => {
      const id = decodeURIComponent(url.split('/api/v1/actions/')[1] ?? '');
      const events = held.get(id);
      if (!events) return new Response('not found', { status: 404 });
      return Response.json({
        act_id: id,
        venue: signing.channelVenue(ROOM),
        task: { state: 'open' },
        events: events.map((t) => served(t)),
      });
    });
    vi.stubGlobal('fetch', fetch);
    return fetch;
  }

  it("that is a ruling failing its check is left out of the task's history read through the SDK", async () => {
    await list(91);
    const o = await opener(REFEREE);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    const failing = await taskEvent(93, REFEREE, 'confirm', o.id);
    const counting = await taskEvent(91, REFEREE, 'expire', o.id);
    const plain = await opener();
    const unrefereed = await taskEvent(93, REFEREE, 'expire', plain.id);
    const fetch = histories(
      new Map([
        [o.id, [o, claim, failing, counting]],
        [plain.id, [plain, unrefereed]],
      ]),
    );
    const w = await watching();
    const history = await w.client.taskHistory(o.id);
    expect(history.events.map((e) => e.event_id)).toEqual([o.id, claim.id, counting.id]);
    expect(history.act_id).toBe(o.id);
    expect(history.task).toEqual({ state: 'open' });
    expect(history.events[1]!.actor_did).toBe(ALICE);
    expect(history.events[1]!.timestamp).toBe(1_700_000_000);
    expect(fetch.mock.calls[0]![0]).toBe(`https://test/api/v1/actions/${o.id}`);
    expect((await w.client.taskHistory(plain.id)).events.map((e) => e.event_id), 'no referee named').toEqual([
      plain.id,
      unrefereed.id,
    ]);
    // Under the origin the caller names.
    await w.client.taskHistory(o.id, { origin: 'https://page.test' });
    expect(fetch.mock.calls.at(-1)![0]).toBe(`https://page.test/api/v1/actions/${o.id}`);
    await expect(w.client.taskHistory('01NOSUCHTASK'), 'one that cannot be read').rejects.toThrow();
    w.client.disconnect();
  });

  it("that is a ruling in a task's history is judged with the others, sharing the referee's read", async () => {
    site.status = 503;
    site.delayMs = 800;
    const o = await opener(REFEREE);
    const rulings = [await taskEvent(91, REFEREE, 'expire', o.id), await taskEvent(93, REFEREE, 'expire', o.id),
      await taskEvent(95, REFEREE, 'expire', o.id)];
    histories(new Map([[o.id, [o, ...rulings]]]));
    const w = await watching();
    const asked = Date.now();
    const history = await w.client.taskHistory(o.id);
    expect(Date.now() - asked).toBeLessThan(1_500);
    expect(history.events.length, 'none can be checked: all kept').toBe(4);
    expect(site.reads, 'one shared read').toBe(1);
    w.client.disconnect();
  });

  it("that is a receipt marked ignored is left out of the task's history read through the SDK", async () => {
    await list(91);
    const o = await opener(REFEREE);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    const ignored = await taskEvent(91, REFEREE, 'confirm', o.id);
    const receipt = await taskEvent(91, REFEREE, 'confirm', o.id);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          act_id: o.id,
          events: [o, claim, ignored, receipt].map((t) => ({
            ...served(t),
            confirm_state: t === ignored ? 'ignored' : null,
          })),
        }),
      ),
    );
    const w = await watching();
    const history = await w.client.taskHistory(o.id);
    expect(history.events.map((e) => e.event_id)).toEqual([o.id, claim.id, receipt.id]);
    w.client.disconnect();
  });

  /** A task step as the channel audit route sends it, on `task`. */
  function auditRow(t: { id: string; tags: Record<string, string> }, task: string, details: Record<string, unknown> = {}) {
    const s = served(t);
    return {
      timestamp: s.timestamp,
      category: 'act',
      event: t.tags['+freeq.at/act-verb'],
      actor_did: s.actor_did,
      details: { kind: 'handoff', act_id: task, confirm_state: 'confirmed', ...details },
      signature: s.signature,
      canonical: s.canonical,
      event_id: t.id,
    };
  }

  /** A receipt or an opener as the audit route sends it beside its rows. */
  function signedDoc(t: { id: string; tags: Record<string, string> }) {
    const s = served(t);
    return { event_id: t.id, canonical: s.canonical, signature: s.signature };
  }

  /** The channel audit route answering `answer`, and the task history route
   *  answering from `held`; every request is recorded. */
  function auditRoute(answer: unknown, held = new Map<string, { id: string; tags: Record<string, string> }[]>()) {
    const fetch = vi.fn(async (url: string) => {
      if (url.includes('/audit')) return Response.json(answer);
      const id = decodeURIComponent(url.split('/api/v1/actions/')[1] ?? '');
      const events = held.get(id);
      if (!events) return new Response('not found', { status: 404 });
      return Response.json({ act_id: id, events: events.map((t) => served(t)) });
    });
    vi.stubGlobal('fetch', fetch);
    return fetch;
  }

  it('that is a ruling failing its check is left out of the channel audit read through the SDK', async () => {
    await list(91);
    const o = await opener(REFEREE);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    const failingReceipt = await taskEvent(93, REFEREE, 'confirm', o.id);
    const failing = await taskEvent(93, REFEREE, 'expire', o.id);
    const counting = await taskEvent(91, REFEREE, 'expire', o.id);
    const ignored = await taskEvent(91, REFEREE, 'confirm', o.id);
    const plain = await opener();
    const unrefereed = await taskEvent(93, REFEREE, 'expire', plain.id);
    const coordination = { timestamp: 1, category: 'coordination', event: 'task_request', actor_did: ALICE,
      details: { capability: 'url_fetch' }, signature: 'ed25519:kid:sig', event_id: '01KZCOORD' };
    const answer = {
      channel: ROOM,
      timeline: [
        coordination,
        auditRow(claim, o.id, { receipt: { ...signedDoc(failingReceipt), timestamp: 2 } }),
        auditRow(failing, o.id),
        auditRow(counting, o.id),
        auditRow(ignored, o.id, { confirm_state: 'ignored' }),
        auditRow(unrefereed, plain.id),
      ],
      openers: [signedDoc(o), signedDoc(plain)],
    };
    const fetch = auditRoute(answer);
    const w = await watching();
    const audit = await w.client.channelAudit(ROOM, { limit: 200 });
    expect(audit.timeline.map((r) => r.event_id)).toEqual(['01KZCOORD', claim.id, counting.id, unrefereed.id]);
    expect(audit.timeline[0]).toEqual(coordination);
    expect(audit.timeline[1]!.details).toEqual({ kind: 'handoff', act_id: o.id, confirm_state: 'confirmed' });
    expect(audit.channel).toBe(ROOM);
    expect(audit.openers).toEqual(answer.openers);
    // The openers came with the answer: nothing else was read.
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0]![0]).toBe('https://test/api/v1/channels/tasks/audit?limit=200');

    // With a person picked, under the origin the caller names: the same.
    await w.client.channelAudit(ROOM, { actor: ALICE, limit: 50, origin: 'https://page.test' });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]![0]).toBe(
      `https://page.test/api/v1/channels/tasks/audit?limit=50&actor=${encodeURIComponent(ALICE)}`,
    );
    w.client.disconnect();
  });

  it('that is a ruling on a task whose opener the audit lacks reads its history once per task', async () => {
    await list(91);
    const o = await opener(REFEREE);
    const failing = await taskEvent(93, REFEREE, 'expire', o.id);
    const counting = await taskEvent(91, REFEREE, 'expire', o.id);
    const fetch = auditRoute(
      { channel: ROOM, timeline: [auditRow(failing, o.id), auditRow(counting, o.id)] },
      new Map([[o.id, [o, failing, counting]]]),
    );
    const w = await watching();
    await w.send(':srv NOTICE * :API-BEARER sekrit');
    const audit = await w.client.channelAudit(ROOM);
    expect(audit.timeline.map((r) => r.event_id)).toEqual([counting.id]);
    const reads = fetch.mock.calls.filter(([url]) => String(url).includes('/api/v1/actions/'));
    expect(reads.map(([url]) => url)).toEqual([`https://test/api/v1/actions/${o.id}`]);
    w.client.disconnect();
  });

  it('that is a ruling whose opener lookup outlasts the check is left out of the channel audit', async () => {
    const o = await opener(REFEREE);
    const failing = await taskEvent(93, REFEREE, 'expire', o.id);
    const answer = { channel: ROOM, timeline: [auditRow(failing, o.id)] };
    // The task history never answers, and does not heed the abort.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => (url.includes('/audit') ? Response.json(answer) : new Promise<Response>(() => {}))),
    );
    const w = await watching();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      let audit: { timeline: { event_id?: string }[] } | undefined;
      void w.client.channelAudit(ROOM).then((a) => (audit = a));
      await advance(10_000);
      expect(audit?.timeline.map((r) => r.event_id), 'its referee could not be learned in time').toEqual([]);
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  it('sends the session bearer with the task history and channel audit reads once the notice has come', async () => {
    const o = await opener();
    const answer = { channel: ROOM, timeline: [], openers: [signedDoc(o)] };
    const bearers: (string | null)[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        bearers.push(new Headers(init?.headers).get('authorization'));
        return url.includes('/audit') ? Response.json(answer) : Response.json({ act_id: o.id, events: [served(o)] });
      }),
    );
    const w = await watching();
    await w.client.taskHistory(o.id);
    expect(bearers, 'none before the notice').toEqual([null]);
    await w.send(':srv NOTICE * :API-BEARER sekrit');
    await w.client.taskHistory(o.id);
    await w.client.channelAudit(ROOM);
    expect(bearers.slice(1)).toEqual(['Bearer sekrit', 'Bearer sekrit']);
    w.client.disconnect();
  });

  it('a channel audit that cannot be read rejects with its status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('forbidden', { status: 403 })));
    const w = await watching();
    await expect(w.client.channelAudit(ROOM)).rejects.toMatchObject({ status: 403 });
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ channel: ROOM })));
    await expect(w.client.channelAudit(ROOM), 'no timeline').rejects.toThrow();
    w.client.disconnect();
  });

  it("that is a ruling on a task whose fetched opener no longer matches its signature fails, live, in its history and in the audit", async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const o = await opener(REFEREE);
    const claim = await taskEvent(90, ALICE, 'claim', o.id);
    const counting = await taskEvent(91, REFEREE, 'expire', o.id);
    const altered = stripped(served(o), 'act-home');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.includes('/audit')
          ? Response.json({
              channel: ROOM,
              timeline: [auditRow(claim, o.id), auditRow(counting, o.id)],
              openers: [{ event_id: o.id, canonical: altered.canonical, signature: altered.signature }],
            })
          : Response.json({ act_id: o.id, events: [altered, served(claim), served(counting)] }),
      ),
    );
    const w = await watching();
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(r.wire);
    expect(await w.wentUpAs(r.id, o.id), 'never goes up').toBeNull();
    for (let i = 0; i < 200 && w.at('verdict', r.id) < 0; i++) await new Promise((res) => setTimeout(res, 5));
    expect(w.up[w.at('verdict', r.id)]?.verdict, "its line's verdict, under the channel's venue").toBe('device');
    expect((await w.client.taskHistory(o.id)).events.map((e) => e.event_id)).toEqual([o.id, claim.id]);
    expect((await w.client.channelAudit(ROOM)).timeline.map((row) => row.event_id)).toEqual([claim.id]);
    w.client.disconnect();
  });

  it('that is a DM ruling on a task whose fetched opener was altered fails, its line unverifiable', async () => {
    await list(91);
    await hold(REFEREE, (await keyOf(91)).pub);
    const pair = signing.dmVenue(ALICE, OWN_DID);
    const task = signing.newEventId();
    const altered = stripped(await servedOpener(task, REFEREE, pair), 'act-home');
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ act_id: task, events: [altered] })));
    const w = await watching();
    const r = await taskEvent(91, REFEREE, 'expire', task, {}, pair, '*');
    await w.send(r.wire);
    const after = await taskEvent(90, ALICE, 'claim', task, {}, pair, 'me');
    await w.send(after.wire);
    await w.actFor(after.id);
    expect(w.act(r.id), 'never goes up').toBeUndefined();
    for (let i = 0; i < 200 && w.at('verdict', r.id) < 0; i++) await new Promise((res) => setTimeout(res, 5));
    expect(w.up[w.at('verdict', r.id)]?.verdict).toBe('unverifiable');
    w.client.disconnect();
  });

  it("that is a ruling on a task whose fetched opener's key cannot be found is hidden, and is read again", async () => {
    await list(91);
    const CAROL = 'did:plc:carol';
    const task = signing.newEventId();
    const o = await taskEvent(92, CAROL, 'offer', undefined, { '+freeq.at/act-home': REFEREE }, undefined, ROOM, task);
    const fetch = vi.fn(async () => Response.json({ act_id: task, events: [served(o)] }));
    vi.stubGlobal('fetch', fetch);
    const w = await watching();
    for (const reads of [1, 2]) {
      const r = await taskEvent(91, REFEREE, 'expire', task);
      await w.send(r.wire);
      expect(await w.wentUpAs(r.id, task), 'hidden').toBeNull();
      expect(fetch).toHaveBeenCalledTimes(reads);
    }
    w.client.disconnect();
  });

  it('that is a ruling on a task whose fetched opener checks and names no referee is shown unchecked', async () => {
    await list(91);
    const o = await opener();
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ act_id: o.id, events: [served(o)] })));
    const w = await watching();
    const r = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(r.wire);
    expect((await w.actFor(r.id))?.ruling).toBe('cannot-check');
    w.client.disconnect();
  });

  it('that is a ruling after a live opener checks is judged by it, over a fetched copy found altered', async () => {
    await list(91);
    const o = await opener(REFEREE);
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ act_id: o.id, events: [stripped(served(o), 'act-home')] })));
    const w = await watching();
    const first = await taskEvent(91, REFEREE, 'expire', o.id);
    await w.send(first.wire);
    expect(await w.wentUpAs(first.id, o.id), 'fails').toBeNull();
    await w.send(o.wire);
    await new Promise((res) => setTimeout(res, 100));
    const second = await taskEvent(91, REFEREE, 'confirm', o.id);
    await w.send(second.wire);
    expect((await w.actFor(second.id))?.ruling).toBe('counts');
    w.client.disconnect();
  });

  it("that is a ruling whose opener's read still hangs when its wait runs out drops the read, and the next asks again", async () => {
    await list(91);
    const task = signing.newEventId();
    let aborted = 0;
    const fetch = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            aborted++;
            reject(new Error('aborted'));
          });
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const w = await watching();
    const homes = (w.client as unknown as { taskHomes: Map<string, unknown> }).taskHomes;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const r = await taskEvent(91, REFEREE, 'expire', task);
      await w.send(r.wire);
      await advance(200);
      expect(homes.has(task), 'the read is held while it is waited on').toBe(true);
      await advance(10_000);
      expect(homes.has(task), 'nothing left behind').toBe(false);
      expect(aborted, 'the request is given up').toBe(1);
      // Its referee could not be learned in time: hidden, not shown when
      // its own wait runs out.
      await advance(6_000);
      expect(w.act(r.id), 'hidden').toBeUndefined();
      const next = await taskEvent(91, REFEREE, 'confirm', task);
      await w.send(next.wire);
      await advance(200);
      expect(fetch, 'a fresh request').toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  it("that is two rulings sharing an opener's read that hangs make one request and are both hidden, and a later ruling reads again", async () => {
    await list(91);
    const task = signing.newEventId();
    const fetch = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const w = await watching();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const first = await taskEvent(91, REFEREE, 'expire', task);
      const second = await taskEvent(91, REFEREE, 'confirm', task);
      await w.send(first.wire);
      await advance(200);
      // While the first's read is still under way.
      await w.send(second.wire);
      await advance(200);
      expect(fetch, 'one request').toHaveBeenCalledTimes(1);
      await advance(16_000);
      expect(w.act(first.id), 'hidden').toBeUndefined();
      expect(w.act(second.id), 'hidden').toBeUndefined();
      expect(fetch, 'no second request').toHaveBeenCalledTimes(1);
      const third = await taskEvent(91, REFEREE, 'expire', task);
      await w.send(third.wire);
      await advance(200);
      expect(fetch, 'read again').toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
      w.client.disconnect();
    }
  });

  it("that is a ruling whose referee cannot be known is left out of the task's history and the channel audit", async () => {
    await list(91);
    const CAROL = 'did:plc:carol';
    const task = signing.newEventId();
    const claim = await taskEvent(90, ALICE, 'claim', task);
    const ruling = await taskEvent(91, REFEREE, 'expire', task);
    const unknown = await taskEvent(92, CAROL, 'offer', undefined, { '+freeq.at/act-home': REFEREE });
    const onUnknown = await taskEvent(91, REFEREE, 'expire', unknown.id);
    const fetch = histories(
      new Map([
        [task, [claim, ruling]],
        [unknown.id, [unknown, onUnknown]],
      ]),
    );
    const w = await watching();
    expect((await w.client.taskHistory(task)).events.map((e) => e.event_id), 'no opener').toEqual([claim.id]);
    expect((await w.client.taskHistory(unknown.id)).events.map((e) => e.event_id), 'its key not found').toEqual([
      unknown.id,
    ]);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.includes('/audit')
          ? Response.json({
              channel: ROOM,
              timeline: [auditRow(claim, task), auditRow(ruling, task), auditRow(onUnknown, unknown.id)],
              openers: [signedDoc(unknown)],
            })
          : fetch(url),
      ),
    );
    expect((await w.client.channelAudit(ROOM)).timeline.map((row) => row.event_id)).toEqual([claim.id]);
    w.client.disconnect();
  });

  it('that is a ruling hidden or thrown out is judged again when a replay brings it back, and then shown', async () => {
    await list(91);
    const CAROL = 'did:plc:carol';
    // Thrown out: its task's opener read altered. Hidden: its task's opener
    // under a key nobody can find. Then each task's opener is seen live.
    const altered = await opener(REFEREE);
    const unknownTask = signing.newEventId();
    const unknownCopy = await taskEvent(92, CAROL, 'offer', undefined, { '+freeq.at/act-home': REFEREE }, undefined, ROOM, unknownTask);
    const unknownLive = await taskEvent(90, ALICE, 'offer', undefined, { '+freeq.at/act-home': REFEREE }, undefined, ROOM, unknownTask);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        Response.json(
          url.includes(altered.id)
            ? { act_id: altered.id, events: [stripped(served(altered), 'act-home')] }
            : { act_id: unknownTask, events: [served(unknownCopy)] },
        ),
      ),
    );
    const w = await watching();
    for (const [task, live] of [
      [altered.id, altered],
      [unknownTask, unknownLive],
    ] as const) {
      const r = await taskEvent(91, REFEREE, 'expire', task);
      await w.send(r.wire);
      expect(await w.wentUpAs(r.id, task), 'not shown the first time').toBeNull();
      await w.send(live.wire);
      await new Promise((res) => setTimeout(res, 100));
      // The replay after a reconnect inside ten minutes, on the same client.
      await w.send(r.wire.replace('@', '@batch=replay;'));
      expect((await w.actFor(r.id))?.ruling, task === altered.id ? 'thrown out, then' : 'hidden, then').toBe('counts');
    }
    w.client.disconnect();
  });

  it('names exactly the receipt, the expiry and the review timeout as rulings', async () => {
    const { RULING_VERBS } = await import('./verdict.js');
    const rules = JSON.parse(readFileSync(join(__dirname, '../../spec/act-transitions.json'), 'utf8')) as {
      kinds: Record<string, { transitions: { verb: string; who: string }[] }>;
      confirmation: { verb: string };
    };
    const fromRules = new Set<string>([rules.confirmation.verb]);
    for (const kind of Object.values(rules.kinds)) {
      for (const t of kind.transitions) if (t.who === 'system') fromRules.add(t.verb);
    }
    expect([...RULING_VERBS].sort()).toEqual([...fromRules].sort());
  });
});
