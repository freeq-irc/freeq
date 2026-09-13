/**
 * Key lookup by (DID, kid): the signer's records first, then a did:web
 * signer's own document, then the origin server, with every answer checked
 * against the kid.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import { type DidDocument, buildDeviceRecord, buildDeviceRetirement } from './identity-records.js';
import { KeyLookup, makeDidResolver } from './key-lookup.js';
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

type RepoKeypair = Awaited<ReturnType<typeof import('../test/repo-proofs.js')['repoKeypair']>>;

/** ALICE's repository key, and her DID document naming it and the PDS. */
let repoKey: RepoKeypair;
let alice: DidDocument;

beforeAll(async () => {
  const { repoKeypair, stubRepo } = await import('../test/repo-proofs.js');
  repoKey = await repoKeypair();
  alice = await (await stubRepo(ALICE, repoKey)).document(PDS);
});

/**
 * A stubbed network: a PDS listing `records` as ALICE's device keys, each with
 * a proof signed by her repository key, and an origin key store holding
 * `originKeys` by `${did} ${kid}`. Counts listings and origin requests per
 * host, and proof requests on their own.
 */
async function network(records: unknown[], originKeys: Record<string, Uint8Array> = {}) {
  const { stubRepo } = await import('../test/repo-proofs.js');
  const repo = await stubRepo(ALICE, repoKey);
  const entries = [];
  for (const record of records) entries.push(await repo.add('at.freeq.deviceKey', record));
  const hits = { pds: 0, origin: 0, proofs: 0 };
  const fetch = vi.fn(async (input: string): Promise<Response> => {
    const url = new URL(input);
    if (url.origin === PDS) {
      if (url.pathname === '/xrpc/com.atproto.sync.getRecord') hits.proofs++;
      else if (url.pathname === '/xrpc/com.atproto.repo.listRecords') hits.pds++;
      return (await repo.respond(url)) ?? new Response('unexpected', { status: 500 });
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

describe('KeyLookup', () => {
  it('finds a kid in the records without asking the origin', async () => {
    const { fetch, hits } = await network(
      [await buildDeviceRecord(await key(1), ALICE, T0)],
      { [`${ALICE} ${await kidOf(1)}`]: await raw(1) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: null,
    });
    expect(hits.origin).toBe(0);
  });

  it('asks the origin for a kid absent from the records', async () => {
    const { fetch, hits } = await network(
      [await buildDeviceRecord(await key(1), ALICE, T0)],
      { [`${ALICE} ${await kidOf(2)}`]: await raw(2) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toEqual({
      publicKey: await raw(2),
      source: 'OriginServer',
      retiredAt: null,
    });
    expect(hits.origin).toBe(1);
  });

  it('refuses a key from the origin that does not hash to the kid', async () => {
    const { fetch, hits } = await network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(3) });
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(hits.origin).toBe(1);
  });

  it('refuses a key from the records that does not hash to the kid', async () => {
    // The record names kid 2 but carries key 1, signed by key 1.
    const record = { ...(await buildDeviceRecord(await key(1), ALICE, T0)), kid: await kidOf(2) };
    const { fetch } = await network([record]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
  });

  it('finds a did:web signer in its own document', async () => {
    const { fetch, hits } = await network([]);
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
      retiredAt: null,
    });
    expect(hits.origin).toBe(0);
  });

  it('still asks the origin when the PDS fails, and fails when nothing else can answer', async () => {
    const { fetch: working } = await network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(2) });
    const fetch = vi.fn(async (input: string): Promise<Response> =>
      new URL(input).origin === PDS ? new Response('down', { status: 500 }) : working(input),
    );
    const withOrigin = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect((await withOrigin.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    const alone = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    await expect(alone.keyFor(ALICE, await kidOf(2))).rejects.toThrow();
  });

  it('makes one round of requests for two misses inside the ttl', async () => {
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    // The listed record's proof is part of the one round.
    expect(hits).toEqual({ pds: 1, origin: 1, proofs: 1 });
  });

  it('finds a key that appears after a miss once the ttl passes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-11T00:00:00Z'));
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();

    originKeys[`${ALICE} ${await kidOf(2)}`] = await raw(2);
    vi.setSystemTime(new Date('2026-09-11T00:59:00Z'));
    expect(await lookup.keyFor(ALICE, await kidOf(2)), 'inside the ttl the miss stands').toBeNull();
    vi.setSystemTime(new Date('2026-09-11T01:01:00Z'));
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
  });

  it('asks again after a remembered miss is forgotten', async () => {
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();

    originKeys[`${ALICE} ${await kidOf(2)}`] = await raw(2);
    lookup.forget(ALICE, await kidOf(2));
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
  });

  it('keeps a found key cached when asked to forget', async () => {
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(1))).not.toBeNull();
    lookup.forget(ALICE, await kidOf(1));
    expect(await lookup.keyFor(ALICE, await kidOf(1))).not.toBeNull();
    expect(hits.pds).toBe(1);
  });

  it('makes no request for a second lookup inside the ttl, and asks again after it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-11T00:00:00Z'));
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
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

  it('folds the records at the time asked, from one listing', async () => {
    const { fetch, hits } = await network([
      await buildDeviceRecord(await key(1), ALICE, T0),
      await buildDeviceRetirement(await key(1), ALICE, await kidOf(1), '2026-03-01T00:00:00Z'),
    ]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    const kid = await kidOf(1);
    expect((await lookup.keyForAt(ALICE, kid, new Date('2026-02-01T00:00:00Z')))?.source).toBe(
      'IdentityRecord',
    );
    // After its retirement the records still name the key, with the date.
    expect(await lookup.keyForAt(ALICE, kid, new Date('2026-04-01T00:00:00Z'))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: Date.parse('2026-03-01T00:00:00Z') / 1000,
    });
    expect(await lookup.keyForAt(ALICE, kid, new Date('2025-12-01T00:00:00Z'))).toBeNull();
    expect(hits.pds).toBe(1);
  });

  it('reads a key the records retire from the records, with its date, and never asks the origin', async () => {
    const kid = await kidOf(1);
    // The origin still holds the same key and knows nothing of the retirement.
    const { fetch, hits } = await network(
      [
        await buildDeviceRecord(await key(1), ALICE, T0),
        await buildDeviceRetirement(await key(1), ALICE, kid, '2026-03-01T00:00:00Z'),
      ],
      { [`${ALICE} ${kid}`]: await raw(1) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyForAt(ALICE, kid, new Date('2026-04-01T00:00:00Z'))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: Date.parse('2026-03-01T00:00:00Z') / 1000,
    });
    expect(hits.origin).toBe(0);
  });

  it('ignores a listed record its repository does not hold, and checks a record once', async () => {
    const { stubRepo } = await import('../test/repo-proofs.js');
    const repo = await stubRepo(ALICE, repoKey);
    const genuine = await buildDeviceRecord(await key(1), ALICE, T0);
    // Signed by its own key, so it passes every record check but the proof.
    const forged = await buildDeviceRecord(await key(2), ALICE, T0);
    const genuineEntry = await repo.add('at.freeq.deviceKey', genuine);
    await repo.addForged('at.freeq.deviceKey', forged, genuine);
    const fetch = vi.fn(
      async (input: string): Promise<Response> =>
        (await repo.respond(new URL(input))) ?? new Response('not found', { status: 404 }),
    );
    // A ttl of zero lists the records afresh on every lookup.
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, 0);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    for (let i = 0; i < 3; i++) {
      expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    }
    expect(repo.proofReads(genuineEntry)).toBe(1);
  });

  it('carries the date the origin removed a key', async () => {
    const key2 = await raw(2);
    const fetch = vi.fn(async (input: string): Promise<Response> => {
      const url = new URL(input);
      if (url.origin === PDS) return Response.json({ records: [] });
      return Response.json({ public_key: b64url(key2), removed_at: 1_780_000_000 });
    });
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toEqual({
      publicKey: key2,
      source: 'OriginServer',
      retiredAt: 1_780_000_000,
    });
  });

  it('asks a default origin only when none was given', async () => {
    const { fetch } = await network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(2) });
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    expect(lookup.originBase()).toBeNull();
    lookup.setDefaultOriginBase(ORIGIN);
    expect(lookup.originBase()).toBe(ORIGIN);
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');

    const given = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    given.setDefaultOriginBase('https://elsewhere.example');
    expect(given.originBase()).toBe(ORIGIN);
  });
});

describe('makeDidResolver', () => {
  it('resolves a did:plc from the directory and a did:web from its host', async () => {
    const plcDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: ALICE,
      alsoKnownAs: ['at://alice.test'],
      verificationMethod: [
        {
          id: `${ALICE}#atproto`,
          type: 'Multikey',
          controller: ALICE,
          publicKeyMultibase: (await key(1)).publicKeyMultibase,
        },
      ],
      service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
    };
    const webDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
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
    const asked: string[] = [];
    const fetch = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      // The PLC resolver percent-encodes the DID in its path.
      const url = decodeURIComponent(String(input instanceof Request ? input.url : input));
      asked.push(url);
      if (url === `https://plc.directory/${ALICE}`) return Response.json(plcDoc);
      if (url === 'https://bot.example.com/.well-known/did.json') return Response.json(webDoc);
      return new Response('not found', { status: 404 });
    });
    const resolve = makeDidResolver({ fetch: fetch as unknown as typeof globalThis.fetch });
    expect((await resolve(ALICE)).service?.[0]?.serviceEndpoint).toBe(PDS);
    expect((await resolve(WEB_SIGNER)).verificationMethod?.[0]?.id).toBe(`${WEB_SIGNER}#freeq`);
    expect(asked).toEqual([
      `https://plc.directory/${ALICE}`,
      'https://bot.example.com/.well-known/did.json',
    ]);
    await expect(resolve('did:key:z6Mkabc')).rejects.toThrow();
  });
});
