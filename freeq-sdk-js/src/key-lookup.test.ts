/**
 * Key lookup by (DID, kid): the signer's records first, then a did:web
 * signer's own document, then the origin server, with every answer checked
 * against the kid.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import { type DidDocument, buildDeviceRecord } from './identity-records.js';
import { KeyLookup } from './key-lookup.js';
import { deriveKid } from './signing.js';

const ALICE = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const WEB_SIGNER = 'did:web:bot.example.com';
const T0 = '2026-01-01T00:00:00Z';
const PDS = 'https://pds.example';
const ORIGIN = 'https://origin.example';
const HOUR = 3_600_000;

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

async function key(seed: number): Promise<DidKey> {
  return importDidKey(new Uint8Array(32).fill(seed));
}

async function raw(seed: number): Promise<Uint8Array> {
  return decodeMultibaseEd25519((await key(seed)).publicKeyMultibase);
}

async function kidOf(seed: number): Promise<string> {
  return deriveKid(await raw(seed));
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * A stubbed network: a PDS listing `records` as ALICE's device keys, and an
 * origin key store holding `originKeys` by `${did} ${kid}`. Counts requests
 * per host.
 */
function network(records: unknown[], originKeys: Record<string, Uint8Array> = {}) {
  const hits = { pds: 0, origin: 0 };
  const fetch = vi.fn(async (input: string): Promise<Response> => {
    const url = new URL(input);
    if (url.origin === PDS && url.pathname === '/xrpc/com.atproto.repo.listRecords') {
      hits.pds++;
      const device = url.searchParams.get('collection') === 'at.freeq.deviceKey';
      return Response.json({
        records: (device ? records : []).map((value) => ({ uri: 'at://x', cid: 'bafy', value })),
      });
    }
    const prefix = '/api/v1/signing-keys/';
    if (url.origin === ORIGIN && url.pathname.startsWith(prefix)) {
      hits.origin++;
      const [did, kid] = url.pathname.slice(prefix.length).split('/').map(decodeURIComponent);
      const found = originKeys[`${did} ${kid}`];
      if (found === undefined) return new Response('not found', { status: 404 });
      return Response.json({ did, kid, algorithm: 'ed25519', public_key: b64url(found) });
    }
    return new Response('unexpected', { status: 500 });
  });
  return { fetch, hits };
}

function resolver(docs: DidDocument[]) {
  return async (did: string): Promise<DidDocument> => {
    const doc = docs.find((d) => d.id === did);
    if (!doc) throw new Error(`unknown DID ${did}`);
    return doc;
  };
}

const alice: DidDocument = {
  id: ALICE,
  service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
};

describe('KeyLookup', () => {
  it('finds a kid in the records without asking the origin', async () => {
    const { fetch, hits } = network(
      [await buildDeviceRecord(await key(1), ALICE, T0)],
      { [`${ALICE} ${await kidOf(1)}`]: await raw(1) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
    });
    expect(hits.origin).toBe(0);
  });

  it('asks the origin for a kid absent from the records', async () => {
    const { fetch, hits } = network(
      [await buildDeviceRecord(await key(1), ALICE, T0)],
      { [`${ALICE} ${await kidOf(2)}`]: await raw(2) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toEqual({
      publicKey: await raw(2),
      source: 'OriginServer',
    });
    expect(hits.origin).toBe(1);
  });

  it('refuses a key from the origin that does not hash to the kid', async () => {
    const { fetch, hits } = network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(3) });
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(hits.origin).toBe(1);
  });

  it('refuses a key from the records that does not hash to the kid', async () => {
    // The record names kid 2 but carries key 1, signed by key 1.
    const record = { ...(await buildDeviceRecord(await key(1), ALICE, T0)), kid: await kidOf(2) };
    const { fetch } = network([record]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
  });

  it('finds a did:web signer in its own document', async () => {
    const { fetch, hits } = network([]);
    const doc: DidDocument = {
      id: WEB_SIGNER,
      verificationMethod: [
        {
          id: `${WEB_SIGNER}#freeq`,
          type: 'Multikey',
          controller: WEB_SIGNER,
          publicKeyMultibase: (await key(4)).publicKeyMultibase,
        },
      ],
    };
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([doc]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(WEB_SIGNER, await kidOf(4))).toEqual({
      publicKey: await raw(4),
      source: 'DidDocument',
    });
    expect(hits.origin).toBe(0);
  });

  it('still asks the origin when the PDS fails, and fails when nothing else can answer', async () => {
    const { fetch: working } = network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(2) });
    const fetch = vi.fn(async (input: string): Promise<Response> =>
      new URL(input).origin === PDS ? new Response('down', { status: 500 }) : working(input),
    );
    const withOrigin = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect((await withOrigin.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    const alone = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    await expect(alone.keyFor(ALICE, await kidOf(2))).rejects.toThrow();
  });

  it('makes no request for a second lookup inside the ttl, and asks again after it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-11T00:00:00Z'));
    const { fetch, hits } = network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    const first = await lookup.keyFor(ALICE, await kidOf(1));
    expect(hits.pds).toBe(1);
    vi.setSystemTime(new Date('2026-09-11T00:59:00Z'));
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual(first);
    expect(hits.pds).toBe(1);
    vi.setSystemTime(new Date('2026-09-11T01:01:00Z'));
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual(first);
    expect(hits.pds).toBe(2);
  });
});
