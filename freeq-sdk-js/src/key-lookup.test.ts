/**
 * Key lookup by (DID, kid): the signer's records first, then a did:web
 * signer's own document, then the origin server, with every answer checked
 * against the kid.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import {
  type DidDocument,
  buildDeviceRecord,
  KEY_LIFETIME_MS,
  buildDeviceRetirement,
  clearHostPauses,
} from './identity-records.js';
import { KeyLookup, MemoryKeyLookupStore, makeDidResolver } from './key-lookup.js';
import { deriveKid } from './signing.js';

const ALICE = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const WEB_SIGNER = 'did:web:bot.example.com';
const PDS = 'https://pds.example';
const ORIGIN = 'https://origin.example';
const HOUR = 3_600_000;
/** Real now when the file loads; the fake clocks are set relative to it. */
const NOW = Date.now();
/** Two days before NOW: a key made then is live at every clock set here. */
const T0 = new Date(NOW - 48 * HOUR).toISOString();
/** A fixed date, for the tests that ask at fixed instants. */
const JAN = '2026-01-01T00:00:00Z';

/** When a key made at `createdAt` expires by default, unix seconds. */
function expiryOf(createdAt: string): number {
  return Math.floor((Date.parse(createdAt) + KEY_LIFETIME_MS) / 1000);
}

/** `minutes` after NOW. */
function clock(minutes: number): Date {
  return new Date(NOW + minutes * 60_000);
}
/** Retry delays for tests that are not about retries. */
const NO_RETRIES: number[] = [];

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.useRealTimers();
  clearHostPauses();
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
  return { fetch, hits, repo };
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
      expiresAt: expiryOf(T0),
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
      expiresAt: null,
    });
    expect(hits.origin).toBe(1);
  });

  it('refuses a key from the origin that does not hash to the kid', async () => {
    const { fetch, hits } = await network([], { [`${ALICE} ${await kidOf(2)}`]: await raw(3) });
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
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
      expiresAt: null,
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
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    // The listed record's proof is part of the one round.
    expect(hits).toEqual({ pds: 1, origin: 1, proofs: 1 });
  });

  it('finds a key that appears after a miss once the ttl passes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();

    originKeys[`${ALICE} ${await kidOf(2)}`] = await raw(2);
    vi.setSystemTime(clock(59));
    expect(await lookup.keyFor(ALICE, await kidOf(2)), 'inside the ttl the miss stands').toBeNull();
    vi.setSystemTime(clock(61));
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
  });

  it('lists the account again and finds a record published since, on refreshAccount', async () => {
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(hits.pds).toBe(1);

    // The client publishes its own key while the listing is held.
    await repo.add('at.freeq.deviceKey', await buildDeviceRecord(await key(2), ALICE, T0));
    expect(await lookup.keyFor(ALICE, await kidOf(2)), 'inside the ttl the miss stands').toBeNull();
    expect(hits.pds, 'and nothing is listed again').toBe(1);

    await lookup.refreshAccount(ALICE);
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('IdentityRecord');
    expect(hits.pds, 'one more listing').toBe(2);
  });

  it('finds a key that appears at the origin after the first ask, before the ttl', async () => {
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, [200, 600, 1500]);
    const [kid, key2] = [await kidOf(2), await raw(2)];
    const asked = lookup.keyFor(ALICE, kid);
    while (hits.origin === 0) await new Promise((r) => setTimeout(r, 1));
    // Past the first answer, well before the first retry.
    await new Promise((r) => setTimeout(r, 50));
    originKeys[`${ALICE} ${kid}`] = key2;
    expect((await asked)?.source).toBe('OriginServer');
    expect(hits.origin, 'found on the first retry').toBe(2);

    // The miss was not remembered: the cache holds the key found.
    delete originKeys[`${ALICE} ${kid}`];
    expect((await lookup.keyFor(ALICE, kid))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
  });

  it('asks for a key absent on every ask four times, then again only after the ttl', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits } = await network([]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, [20, 60, 150]);
    const kid = await kidOf(2);
    const started = performance.now();
    expect(await lookup.keyFor(ALICE, kid)).toBeNull();
    expect(performance.now() - started).toBeGreaterThanOrEqual(145);
    expect([hits.pds, hits.origin], 'one listing, the retries at the origin only').toEqual([1, 4]);

    vi.setSystemTime(clock(59));
    expect(await lookup.keyFor(ALICE, kid)).toBeNull();
    expect([hits.pds, hits.origin], 'inside the ttl the miss stands').toEqual([1, 4]);
    vi.setSystemTime(clock(61));
    expect(await lookup.keyFor(ALICE, kid)).toBeNull();
    expect([hits.pds, hits.origin], 'after the ttl, a new lookup: one listing and its retries').toEqual([2, 8]);
  });

  it('lists an account once for two misses, and retries each at the origin only', async () => {
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, [20, 60, 150]);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect([hits.pds, hits.origin], 'one listing, one ask and three retries at the origin').toEqual([1, 4]);
    expect(await lookup.keyFor(ALICE, await kidOf(3))).toBeNull();
    expect([hits.pds, hits.origin], 'the second miss lists nothing').toEqual([1, 8]);
  });

  it('makes one round of requests for ten concurrent asks for one absent kid', async () => {
    const { fetch, hits } = await network([]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, [20, 60, 150]);
    const kid = await kidOf(2);
    const answers = await Promise.all(Array.from({ length: 10 }, () => lookup.keyFor(ALICE, kid)));
    expect(answers).toEqual(Array(10).fill(null));
    expect([hits.pds, hits.origin], 'one lookup and its retries').toEqual([1, 4]);
  });

  it('makes one listing and one proof per record for fifty concurrent asks for fifty kids of one signer', async () => {
    const records = [];
    for (let seed = 1; seed <= 5; seed++) records.push(await buildDeviceRecord(await key(seed), ALICE, T0));
    const { fetch, hits } = await network(records);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    const kids = await Promise.all(Array.from({ length: 51 }, (_, i) => kidOf(101 + i)));
    const answers = await Promise.all(kids.slice(0, 50).map((kid) => lookup.keyFor(ALICE, kid)));
    expect(answers).toEqual(Array(50).fill(null));
    expect([hits.pds, hits.proofs], 'one listing, one proof per record').toEqual([1, 5]);

    expect(await lookup.keyFor(ALICE, kids[50]!)).toBeNull();
    expect([hits.pds, hits.proofs], 'a kid the held listing lacks is answered from it inside the ttl').toEqual([1, 5]);
  });

  it('answers a kid the held listing lacks from it inside the ttl, and finds a key published since after it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect([hits.pds, hits.proofs]).toEqual([1, 1]);

    await repo.add('at.freeq.deviceKey', await buildDeviceRecord(await key(2), ALICE, T0));
    vi.setSystemTime(clock(10));
    expect(await lookup.keyFor(ALICE, await kidOf(2)), 'inside the ttl the held listing stands').toBeNull();
    expect([hits.pds, hits.proofs, hits.origin]).toEqual([1, 1, 1]);

    vi.setSystemTime(clock(71));
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toEqual({
      publicKey: await raw(2),
      source: 'IdentityRecord',
      retiredAt: null,
      expiresAt: expiryOf(T0),
    });
    expect([hits.pds, hits.proofs, hits.origin], 'one more listing, the new record proven').toEqual([2, 2, 1]);
  });

  it('asks again after a remembered miss is forgotten', async () => {
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();

    originKeys[`${ALICE} ${await kidOf(2)}`] = await raw(2);
    lookup.forget(ALICE, await kidOf(2));
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
  });

  it('lists the account again after a remembered miss is forgotten', async () => {
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(hits.pds).toBe(1);

    // Published after the listing the lookup holds.
    await repo.add('at.freeq.deviceKey', await buildDeviceRecord(await key(2), ALICE, T0));
    lookup.forget(ALICE, await kidOf(2));
    expect((await lookup.keyFor(ALICE, await kidOf(2)))?.source).toBe('IdentityRecord');
    expect(hits.pds, 'the forgotten miss listed the account again').toBe(2);
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
    vi.setSystemTime(clock(0));
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    const first = await lookup.keyFor(ALICE, await kidOf(1));
    expect(hits.pds).toBe(1);
    vi.setSystemTime(clock(59));
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual(first);
    expect(hits.pds).toBe(1);
    vi.setSystemTime(clock(61));
    expect(await lookup.keyFor(ALICE, await kidOf(1))).toEqual(first);
    expect(hits.pds).toBe(2);
  });

  it('gives the held listing as proven device records inside the ttl, and lists afresh on a refresh', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR, NO_RETRIES);
    expect(await lookup.provenDeviceRecords(ALICE)).toHaveLength(1);
    expect([hits.pds, hits.proofs]).toEqual([1, 1]);

    await repo.add(
      'at.freeq.deviceKey',
      await buildDeviceRetirement(await key(1), ALICE, await kidOf(1), clock(10).toISOString()),
    );
    vi.setSystemTime(clock(30));
    expect(await lookup.provenDeviceRecords(ALICE), 'inside the ttl the held listing stands').toHaveLength(1);
    expect([hits.pds, hits.proofs]).toEqual([1, 1]);
    expect(await lookup.refreshDeviceRecords(ALICE), 'a refresh lists afresh').toHaveLength(2);
    expect([hits.pds, hits.proofs]).toEqual([2, 2]);

    vi.setSystemTime(clock(91));
    expect(await lookup.provenDeviceRecords(ALICE)).toHaveLength(2);
    expect(hits.pds, 'past the ttl, a listing').toBe(3);
  });

  it('folds the records at the time asked, from one listing', async () => {
    const { fetch, hits } = await network([
      await buildDeviceRecord(await key(1), ALICE, JAN),
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
      expiresAt: expiryOf(JAN),
    });
    expect(await lookup.keyForAt(ALICE, kid, new Date('2025-12-01T00:00:00Z'))).toBeNull();
    expect(hits.pds).toBe(1);
  });

  it('carries the expiry its record names, whether or not it has passed', async () => {
    const { fetch } = await network([await buildDeviceRecord(await key(1), ALICE, JAN)]);
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR);
    const kid = await kidOf(1);
    const expiresAt = Date.parse('2026-04-01T00:00:00Z') / 1000;
    expect(await lookup.keyForAt(ALICE, kid, new Date('2026-02-01T00:00:00Z'))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: null,
      expiresAt,
    });
    expect(await lookup.keyForAt(ALICE, kid, new Date('2026-05-01T00:00:00Z'))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: expiresAt,
      expiresAt,
    });
  });

  it('reads a key the records retire from the records, with its date, and never asks the origin', async () => {
    const kid = await kidOf(1);
    // The origin still holds the same key and knows nothing of the retirement.
    const { fetch, hits } = await network(
      [
        await buildDeviceRecord(await key(1), ALICE, JAN),
        await buildDeviceRetirement(await key(1), ALICE, kid, '2026-03-01T00:00:00Z'),
      ],
      { [`${ALICE} ${kid}`]: await raw(1) },
    );
    const lookup = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR);
    expect(await lookup.keyForAt(ALICE, kid, new Date('2026-04-01T00:00:00Z'))).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: Date.parse('2026-03-01T00:00:00Z') / 1000,
      expiresAt: expiryOf(JAN),
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
      expiresAt: null,
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

describe('KeyLookup with a store', () => {
  it('answers a key another lookup on the same store found, with no request', async () => {
    const { fetch } = await network(
      [await buildDeviceRecord(await key(1), ALICE, T0)],
      { [`${ALICE} ${await kidOf(2)}`]: await raw(2) },
    );
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    const inRecords = await first.keyFor(ALICE, await kidOf(1));
    const atOrigin = await first.keyFor(ALICE, await kidOf(2));
    expect([inRecords?.source, atOrigin?.source]).toEqual(['IdentityRecord', 'OriginServer']);
    const requests = fetch.mock.calls.length;

    const second = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    expect(await second.keyFor(ALICE, await kidOf(1))).toEqual(inRecords);
    expect(await second.keyFor(ALICE, await kidOf(2))).toEqual(atOrigin);
    expect(fetch.mock.calls.length).toBe(requests);
  });

  it('does not fetch a proof another lookup on the same store checked', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR, NO_RETRIES, store);
    expect((await first.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect([hits.pds, hits.proofs]).toEqual([1, 1]);

    await repo.add('at.freeq.deviceKey', await buildDeviceRecord(await key(2), ALICE, T0));
    const second = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR, NO_RETRIES, store);
    vi.setSystemTime(clock(61));
    expect((await second.keyFor(ALICE, await kidOf(2)))?.source).toBe('IdentityRecord');
    expect([hits.pds, hits.proofs], 'one more listing past the ttl, only the new record proven').toEqual([2, 2]);
  });

  it('answers an unknown key from the stored listing inside the ttl, and lists once past it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    expect(await first.keyFor(ALICE, await kidOf(2))).toBeNull();
    expect(hits.pds).toBe(1);

    // A reload: a new lookup on the same store.
    const second = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    vi.setSystemTime(clock(30));
    expect(await second.keyFor(ALICE, await kidOf(3))).toBeNull();
    expect(hits.pds, 'inside the ttl, no listing').toBe(1);

    vi.setSystemTime(clock(61));
    expect(await second.keyFor(ALICE, await kidOf(4))).toBeNull();
    expect(await second.keyFor(ALICE, await kidOf(5))).toBeNull();
    expect(hits.pds, 'past the ttl, one listing').toBe(2);
  });

  it('lists again after the ttl and carries a retirement onto a stored key', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const kid = await kidOf(1);
    const { fetch, hits, repo } = await network([await buildDeviceRecord(await key(1), ALICE, T0)]);
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR, NO_RETRIES, store);
    expect((await first.keyFor(ALICE, kid))?.retiredAt).toBeNull();

    await repo.add(
      'at.freeq.deviceKey',
      await buildDeviceRetirement(await key(1), ALICE, kid, clock(30).toISOString()),
    );
    const second = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, null, HOUR, NO_RETRIES, store);
    vi.setSystemTime(clock(59));
    expect((await second.keyFor(ALICE, kid))?.retiredAt, 'inside the ttl the stored listing stands').toBeNull();
    expect(hits.pds).toBe(1);
    vi.setSystemTime(clock(61));
    expect(await second.keyFor(ALICE, kid)).toEqual({
      publicKey: await raw(1),
      source: 'IdentityRecord',
      retiredAt: Math.floor(clock(30).getTime() / 1000),
      expiresAt: expiryOf(T0),
    });
    expect(hits.pds).toBe(2);
  });

  it('keeps no miss in the store', async () => {
    const originKeys: Record<string, Uint8Array> = {};
    const { fetch, hits } = await network([], originKeys);
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    expect(await first.keyFor(ALICE, await kidOf(2))).toBeNull();

    originKeys[`${ALICE} ${await kidOf(2)}`] = await raw(2);
    const second = new KeyLookup({ fetch, resolveDid: resolver([alice]) }, ORIGIN, HOUR, NO_RETRIES, store);
    expect((await second.keyFor(ALICE, await kidOf(2)))?.source).toBe('OriginServer');
    expect(hits.origin).toBe(2);
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

  /** A `fetch` answering the PLC directory for ALICE, counting the calls. */
  async function plcNetwork(): Promise<{ fetch: typeof globalThis.fetch; hits: { plc: number } }> {
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: ALICE,
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
    const hits = { plc: 0 };
    const fetch = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = decodeURIComponent(String(input instanceof Request ? input.url : input));
      if (url === `https://plc.directory/${ALICE}`) {
        hits.plc += 1;
        return Response.json(doc);
      }
      return new Response('not found', { status: 404 });
    });
    return { fetch: fetch as unknown as typeof globalThis.fetch, hits };
  }

  it('resolves a did once inside the ttl and again past it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { fetch, hits } = await plcNetwork();
    const resolve = makeDidResolver({ fetch });
    expect((await resolve(ALICE)).id).toBe(ALICE);
    vi.setSystemTime(clock(59));
    expect((await resolve(ALICE)).id).toBe(ALICE);
    expect(hits.plc, 'inside the ttl the copy is used').toBe(1);
    vi.setSystemTime(clock(61));
    expect((await resolve(ALICE)).id).toBe(ALICE);
    expect(hits.plc).toBe(2);
  });

  it('shares one fetch between concurrent resolves of one did', async () => {
    const { fetch, hits } = await plcNetwork();
    const resolve = makeDidResolver({ fetch });
    const [a, b] = await Promise.all([resolve(ALICE), resolve(ALICE)]);
    expect(a.id).toBe(ALICE);
    expect(b.id).toBe(ALICE);
    expect(hits.plc).toBe(1);
  });

  it('does not keep a failed resolve', async () => {
    let down = true;
    let hits = 0;
    const doc = { '@context': ['https://www.w3.org/ns/did/v1'], id: ALICE };
    const fetch = vi.fn(async (): Promise<Response> => {
      hits += 1;
      if (down) return new Response('nope', { status: 500 });
      return Response.json(doc);
    }) as unknown as typeof globalThis.fetch;
    const resolve = makeDidResolver({ fetch });
    await expect(resolve(ALICE)).rejects.toThrow();
    down = false;
    expect((await resolve(ALICE)).id).toBe(ALICE);
    expect(hits).toBe(2);
  });

  it('fetches every time when the ttl is zero', async () => {
    const { fetch, hits } = await plcNetwork();
    const resolve = makeDidResolver({ fetch, ttlMs: 0 });
    await resolve(ALICE);
    await resolve(ALICE);
    expect(hits.plc).toBe(2);
  });
});

// ─── through the home server ────────────────────────────────────────────

const BOB = 'did:plc:bobbobbobbobbobbobbobbob';
const CAROL = 'did:plc:carolcarolcarolcarolcaro';

/**
 * ALICE, BOB and CAROL with device keys 1, 2 and 3, their PDS, and the origin
 * as their home server answering the record routes from the same
 * repositories. Counts PDS listings and proofs, and origin key requests.
 */
async function homeNetwork(originKeys: Record<string, Uint8Array> = {}) {
  const { stubRepo, stubHome } = await import('../test/repo-proofs.js');
  const repos = [await stubRepo(ALICE, repoKey), await stubRepo(BOB), await stubRepo(CAROL)];
  for (const [i, repo] of repos.entries()) {
    await repo.add('at.freeq.deviceKey', await buildDeviceRecord(await key(i + 1), repo.did, T0));
  }
  const home = stubHome(repos);
  const docs = await Promise.all(repos.map((r) => r.document(PDS)));
  const pds = { listings: 0, proofs: 0 };
  const hits = { origin: 0 };
  const fetch = vi.fn(async (input: string): Promise<Response> => {
    const url = new URL(input);
    if (url.origin === PDS) {
      if (url.pathname.endsWith('listRecords')) pds.listings++;
      if (url.pathname.endsWith('getRecord')) pds.proofs++;
      for (const repo of repos) {
        const answer = await repo.respond(url);
        if (answer !== undefined) return answer;
      }
      return new Response('unexpected', { status: 500 });
    }
    if (url.origin === ORIGIN) {
      const answer = await home.respond(url);
      if (answer !== undefined) return answer;
      hits.origin++;
      // The origin's key route: one server answers both in production.
      const prefix = '/api/v1/signing-keys/';
      if (url.pathname.startsWith(prefix)) {
        const [did, kid] = url.pathname.slice(prefix.length).split('/').map(decodeURIComponent);
        const found = originKeys[`${did} ${kid}`];
        if (found !== undefined) {
          return Response.json({ did, kid, algorithm: 'ed25519', public_key: b64url(found) });
        }
      }
      return new Response('not found', { status: 404 });
    }
    return new Response('unexpected', { status: 500 });
  });
  const [alice, bob, carol] = repos as [typeof repos[0], typeof repos[0], typeof repos[0]];
  return { alice, bob, carol, home, pds, hits, fetch, resolveDid: resolver(docs) };
}

const noHome = { batch: 0, account: 0, listing: 0, proof: 0 };

describe('KeyLookup through the home server', () => {
  it('prefetches a channel of three signers in one batch request, and finds every key in the records with no PDS request', async () => {
    const { home, pds, hits, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE, BOB, CAROL, ALICE]);
    for (const [did, seed] of [[ALICE, 1], [BOB, 2], [CAROL, 3]] as const) {
      expect((await lookup.keyFor(did, await kidOf(seed)))?.source, did).toBe('IdentityRecord');
    }
    expect(home.hits).toEqual({ ...noHome, batch: 1 });
    expect(home.batches).toEqual([[ALICE, BOB, CAROL]]);
    expect(pds).toEqual({ listings: 0, proofs: 0 });
    expect(hits.origin).toBe(0);
  });

  it('shares one batch request between two prefetches for the same signers', async () => {
    const { home, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await Promise.all([lookup.prefetch([ALICE, BOB]), lookup.prefetch([BOB, ALICE])]);
    await lookup.prefetch([ALICE]);
    expect(home.hits.batch).toBe(1);
  });

  it('leaves a did:key signer out of the batch, and asks for a did:web one', async () => {
    const { home, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE, 'did:key:z6MkExample', 'did:web:irc.example.com']);
    expect(home.batches).toEqual([[ALICE, 'did:web:irc.example.com']]);
  });

  it('reads no records anywhere for a did:key signer, and takes its key from the origin', async () => {
    const BOT = 'did:key:z6MkExampleBotSigner';
    const botKey = await raw(7);
    const { home, pds, hits, fetch, resolveDid } = await homeNetwork({ [`${BOT} ${await kidOf(7)}`]: botKey });
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    expect((await lookup.keyFor(BOT, await kidOf(7)))?.source).toBe('OriginServer');
    expect(home.hits, 'no record request').toEqual(noHome);
    expect(pds, 'the PDS was not asked').toEqual({ listings: 0, proofs: 0 });
    expect(hits.origin).toBe(1);
  });

  it('asks nothing for a batch of did:key signers alone', async () => {
    const { home, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch(['did:key:z6MkExample']);
    expect(home.hits.batch).toBe(0);
  });

  it('lists a signer the home server left out at the PDS', async () => {
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    home.left.add(CAROL);
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE, BOB, CAROL]);
    expect(pds, 'the prefetch reads no PDS').toEqual({ listings: 0, proofs: 0 });
    expect((await lookup.keyFor(CAROL, await kidOf(3)))?.source).toBe('IdentityRecord');
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(pds, 'only the signer left out').toEqual({ listings: 1, proofs: 1 });
  });

  it('proves a record whose proof the batch left out at the PDS', async () => {
    const { alice, home, pds, fetch, resolveDid } = await homeNetwork();
    const rkey = alice.entries('at.freeq.deviceKey')[0]!.uri.split('/').pop()!;
    home.withheld.add(`at.freeq.deviceKey/${rkey}`);
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE]);
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(pds).toEqual({ listings: 0, proofs: 1 });
  });

  it('reads the PDS on a 429 from the home server, and asks the home server nothing inside the cooldown', async () => {
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    home.status = 429;
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(home.hits).toEqual({ ...noHome, batch: 1 });
    expect(pds).toEqual({ listings: 1, proofs: 1 });

    home.status = null;
    await lookup.prefetch([BOB]);
    expect((await lookup.keyFor(BOB, await kidOf(2)))?.source).toBe('IdentityRecord');
    expect(home.hits, 'inside the cooldown').toEqual({ ...noHome, batch: 1 });
    expect(pds).toEqual({ listings: 2, proofs: 2 });
  });

  it('re-lists a held account past the hour with one home listing request and no proof request', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(0));
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE]);
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(home.hits).toEqual({ ...noHome, batch: 1 });

    vi.setSystemTime(clock(61));
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(home.hits).toEqual({ ...noHome, batch: 1, listing: 1 });
    expect(pds).toEqual({ listings: 0, proofs: 0 });
  });

  it('keeps the server listing time, so a copy an hour old is listed again at once', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(clock(60));
    const { home, fetch, resolveDid } = await homeNetwork();
    home.fetchedAt = clock(-1).getTime() / 1000;
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE]);
    await lookup.prefetch([ALICE]);
    expect(home.hits.batch, 'a listing older than the hour is not held').toBe(2);
  });

  it('proves the retirement closure through one home listing and the single-proof route', async () => {
    const { alice, home, pds, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    // Nothing retires the key, but its own record carries its expiry.
    expect(await lookup.provenRetirementClosure(ALICE, await kidOf(1))).toHaveLength(1);
    expect(home.hits).toEqual({ ...noHome, listing: 1, proof: 1 });

    await alice.add(
      'at.freeq.deviceKey',
      await buildDeviceRetirement(await key(1), ALICE, await kidOf(1), clock(0).toISOString()),
    );
    expect(await lookup.provenRetirementClosure(ALICE, await kidOf(1))).toHaveLength(2);
    expect(home.hits).toEqual({ ...noHome, listing: 2, proof: 2 });
    expect(pds).toEqual({ listings: 0, proofs: 0 });
  });

  it('lists the Devices of a cold account with one home request and no PDS request', async () => {
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    expect(await lookup.provenDeviceRecords(ALICE)).toHaveLength(1);
    expect(home.hits).toEqual({ ...noHome, batch: 1 });
    expect(pds).toEqual({ listings: 0, proofs: 0 });
  });

  it('makes no request for a lookup built on the same store', async () => {
    const { fetch, resolveDid } = await homeNetwork();
    const store = new MemoryKeyLookupStore();
    const first = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES, store);
    await first.prefetch([ALICE, BOB, CAROL]);
    for (const [did, seed] of [[ALICE, 1], [BOB, 2], [CAROL, 3]] as const) await first.keyFor(did, await kidOf(seed));
    const requests = fetch.mock.calls.length;

    const second = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES, store);
    await second.prefetch([ALICE, BOB, CAROL]);
    for (const [did, seed] of [[ALICE, 1], [BOB, 2], [CAROL, 3]] as const) {
      expect((await second.keyFor(did, await kidOf(seed)))?.source).toBe('IdentityRecord');
    }
    expect(fetch.mock.calls.length).toBe(requests);
  });

  it('lists the PDS on refreshAccount while the home server serves an older copy', async () => {
    const { alice, home, pds, hits, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    home.frozen = true;
    await lookup.prefetch([ALICE]);

    // The client publishes its own key; the home server's copy predates it.
    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    await lookup.refreshAccount(ALICE);
    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');
    expect(pds).toEqual({ listings: 1, proofs: 1 });
    expect(hits.origin).toBe(0);
    expect(home.hits.batch).toBe(1);
  });

  it('replaces an origin answer for a key published since, in memory and in the store', async () => {
    const { alice, home, hits, fetch, resolveDid } = await homeNetwork({ [`${ALICE} ${await kidOf(4)}`]: await raw(4) });
    const store = new MemoryKeyLookupStore();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES, store);
    home.frozen = true;
    await lookup.prefetch([ALICE]);
    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('OriginServer');

    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    await lookup.refreshAccount(ALICE);
    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');

    const second = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES, store);
    expect((await second.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');
    expect(hits.origin).toBe(1);
  });

  it('keeps the fresh listing when an older listing through the home server lands after it', async () => {
    const { alice, home, pds, fetch, resolveDid } = await homeNetwork();
    home.frozen = true;
    home.fetchedAt = Math.floor(Date.now() / 1000) - 60;
    // The server's copy is taken before the publish.
    await new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES).prefetch([ALICE]);
    const listed = pds.listings;

    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const gated = async (input: string): Promise<Response> => {
      if (input.includes('/api/v1/records?')) await gate;
      return fetch(input);
    };
    const lookup = new KeyLookup({ fetch: gated, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    const prefetched = lookup.prefetch([ALICE]);
    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    await lookup.refreshAccount(ALICE);
    release();
    await prefetched;

    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');
    expect(pds.listings - listed).toBe(1);
  });

  it('does not keep an origin answer from a lookup that began before refreshAccount', async () => {
    const { alice, home, fetch, resolveDid } = await homeNetwork({ [`${ALICE} ${await kidOf(4)}`]: await raw(4) });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const gated = async (input: string): Promise<Response> => {
      if (input.includes('/api/v1/signing-keys/')) await gate;
      return fetch(input);
    };
    const lookup = new KeyLookup({ fetch: gated, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    home.frozen = true;
    await lookup.prefetch([ALICE]);

    const first = lookup.keyFor(ALICE, await kidOf(4));
    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    await lookup.refreshAccount(ALICE);
    release();
    await first;

    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');
  });

  it('refreshDeviceRecords reads the PDS while the home server serves an older copy', async () => {
    const { alice, home, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    home.frozen = true;
    expect(await lookup.provenDeviceRecords(ALICE)).toHaveLength(1);

    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    expect(await lookup.refreshDeviceRecords(ALICE)).toHaveLength(2);
  });

  it("dates a listing from the home server's per-DID route with its fetched_at, so it loses to a newer PDS listing", async () => {
    const { alice, home, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, ORIGIN, HOUR, NO_RETRIES);
    home.frozen = true;
    home.fetchedAt = Math.floor(Date.now() / 1000) - 60;
    await lookup.prefetch([ALICE]);
    await alice.add('at.freeq.deviceKey', await buildDeviceRecord(await key(4), ALICE, T0));
    await lookup.refreshAccount(ALICE);

    // A kid no record names; forgetting its miss lists the account again,
    // through the per-DID route since a listing is held.
    const absent = await kidOf(9);
    expect(await lookup.keyFor(ALICE, absent)).toBeNull();
    lookup.forget(ALICE, absent);
    const listings = home.hits.listing;
    expect(await lookup.keyFor(ALICE, absent)).toBeNull();
    expect(home.hits.listing, 'the per-DID route').toBe(listings + 1);

    expect((await lookup.keyFor(ALICE, await kidOf(4)))?.source).toBe('IdentityRecord');
  });

  it('asks no home server with no origin', async () => {
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    const lookup = new KeyLookup({ fetch, resolveDid }, null, HOUR, NO_RETRIES);
    await lookup.prefetch([ALICE]);
    expect((await lookup.keyFor(ALICE, await kidOf(1)))?.source).toBe('IdentityRecord');
    expect(home.hits).toEqual(noHome);
    expect(pds).toEqual({ listings: 1, proofs: 1 });
  });
});
