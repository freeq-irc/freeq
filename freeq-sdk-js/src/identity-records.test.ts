/**
 * The fold, against records built here rather than read from the spec file.
 *
 * The vector file carries the same seven cases, but a package installed
 * without `spec/` still has to fold the same way, so these build their own
 * inputs.
 */
import { webcrypto } from 'node:crypto';
import { writeCarStream } from '@atcute/car';
import { BytesWrapper, encode, toCidLink } from '@atcute/cbor';
import { CODEC_DCBOR, CODEC_RAW, type Cid, create } from '@atcute/cid';
import { Secp256k1PrivateKeyExportable } from '@atcute/crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import {
  DEVICE_KEY_TYPE,
  KEY_LIFETIME_MS,
  type DidDocument,
  buildAgentRecord,
  buildAgentRetirement,
  buildDeviceRecord,
  buildDeviceRetirement,
  clearHostPauses,
  deviceKeyHistory,
  fetchAccounts,
  foldAgentRecords,
  foldDeviceRecords,
  listRecords,
  liveAgentLinks,
  listRecordEntries,
  liveDeviceKeys,
  provenRecords,
  recordCid,
  retirementClosure,
  setPauseClock,
  verifyProof,
  verifyRecord,
} from './identity-records.js';
import { deriveKid } from './signing.js';

const ALICE = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const T0 = '2026-01-01T00:00:00Z';
const T1 = '2026-02-01T00:00:00Z';
const T2 = '2026-03-01T00:00:00Z';
const T3 = '2026-04-01T00:00:00Z';
/** Past the default expiry of a key created at T0, before `LATER`. */
const T4 = '2026-12-01T00:00:00Z';
/** An `expiresAt` later than the default: honoured, with no cap. */
const LATER = '2027-01-01T00:00:00Z';

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
});

async function key(seed: number): Promise<DidKey> {
  return importDidKey(new Uint8Array(32).fill(seed));
}

async function kidOf(k: DidKey): Promise<string> {
  return deriveKid(decodeMultibaseEd25519(k.publicKeyMultibase));
}

async function agentDid(): Promise<string> {
  return (await key(9)).did;
}

async function liveKids(records: unknown[], at: string): Promise<string[]> {
  return (await foldDeviceRecords(ALICE, records, new Date(at))).map((k) => k.kid);
}

async function liveAgents(
  deviceRecords: unknown[],
  agentRecords: unknown[],
  at: string,
): Promise<string[]> {
  return (await foldAgentRecords(ALICE, deviceRecords, agentRecords, new Date(at))).map(
    (l) => l.agentDid,
  );
}

describe('device key fold', () => {
  it('a key that retires itself stops being live', async () => {
    const k1 = await key(1);
    const record = await buildDeviceRecord(k1, ALICE, T0, 'laptop');
    const retirement = await buildDeviceRetirement(k1, ALICE, await kidOf(k1), T1);
    expect(await liveKids([record, retirement], '2026-01-15T00:00:00Z')).toEqual([await kidOf(k1)]);
    expect(await liveKids([record, retirement], T2)).toEqual([]);
  });

  it('a second live key can retire the first', async () => {
    const [k1, k2] = [await key(1), await key(2)];
    const records = [
      await buildDeviceRecord(k1, ALICE, T0, 'laptop'),
      await buildDeviceRecord(k2, ALICE, T0, 'phone'),
      await buildDeviceRetirement(k2, ALICE, await kidOf(k1), T1),
    ];
    expect(await liveKids(records, T2)).toEqual([await kidOf(k2)]);
  });

  it('a retirement from a key with no record is ignored', async () => {
    const [k1, k3] = [await key(1), await key(3)];
    const records = [
      await buildDeviceRecord(k1, ALICE, T0, 'laptop'),
      await buildDeviceRetirement(k3, ALICE, await kidOf(k1), T1),
    ];
    expect(await liveKids(records, T2)).toEqual([await kidOf(k1)]);
  });

  it('a key record whose kid does not match is ignored', async () => {
    const [k1, k2, k3] = [await key(1), await key(2), await key(3)];
    const mismatched = { ...(await buildDeviceRecord(k1, ALICE, T0)), kid: await kidOf(k3) };
    const records = [mismatched, await buildDeviceRecord(k2, ALICE, T0, 'phone')];
    expect(await liveKids(records, T2)).toEqual([await kidOf(k2)]);
  });

  it('leaves absent fields out of a record rather than setting them null', async () => {
    const record = await buildDeviceRecord(await key(1), ALICE, T0);
    expect(Object.keys(record).sort()).toEqual([
      '$type',
      'bindingSig',
      'createdAt',
      'did',
      'expiresAt',
      'kid',
      'publicKeyMultibase',
    ]);
  });

  it('drops a record dated in a way the Rust side would not parse', async () => {
    // Each record is built around its own date, so its signature is good and
    // the date check is the only thing that can reject it. Date.parse alone
    // rolls Feb 30 into March and accepts hour 24; chrono refuses both.
    const k1 = await key(1);
    for (const createdAt of [
      '2026-02-30T00:00:00Z',
      '2026-02-29T00:00:00Z',
      '2026-01-01T24:00:00Z',
      '2026-01-01',
      'Jan 1 2026',
    ]) {
      // An expiry given outright, since the builder cannot count one from
      // a date it cannot read.
      const record = await buildDeviceRecord(k1, ALICE, createdAt, undefined, LATER);
      expect(await liveKids([record], T2)).toEqual([]);
    }
    const leapDay = await buildDeviceRecord(k1, ALICE, '2024-02-29T00:00:00Z', undefined, LATER);
    expect(await liveKids([leapDay], T2)).toHaveLength(1);
  });

  it('drops a record with any field altered after signing', async () => {
    const record = await buildDeviceRecord(await key(1), ALICE, T0, 'laptop');
    for (const field of ['createdAt', 'label', 'kid', 'did', '$type']) {
      const altered = { ...record, [field]: '2026-06-01T00:00:00Z' };
      expect(await liveKids([altered], T1), `${field} was changed`).toEqual([]);
    }
  });

  it('drops a record whose binding signature was tampered with', async () => {
    const record = await buildDeviceRecord(await key(1), ALICE, T0);
    const tampered = { ...record, bindingSig: `A${record.bindingSig.slice(1)}` };
    expect(await liveKids([tampered], T1)).toEqual([]);
  });
});

describe('agent link fold', () => {
  it('a link signed by a live key is live', async () => {
    const k1 = await key(1);
    const agent = await agentDid();
    const devices = [await buildDeviceRecord(k1, ALICE, T0, 'laptop')];
    const links = [await buildAgentRecord(k1, ALICE, agent, T1, 'helper')];
    expect(await liveAgents(devices, links, T2)).toEqual([agent]);
  });

  it('a link signed by a key retired before it is not live', async () => {
    const k1 = await key(1);
    const agent = await agentDid();
    const devices = [
      await buildDeviceRecord(k1, ALICE, T0, 'laptop'),
      await buildDeviceRetirement(k1, ALICE, await kidOf(k1), T1),
    ];
    const links = [await buildAgentRecord(k1, ALICE, agent, T2)];
    expect(await liveAgents(devices, links, T3)).toEqual([]);
  });

  it('a link signature is not a retirement signature', async () => {
    const k1 = await key(1);
    const agent = await agentDid();
    const devices = [await buildDeviceRecord(k1, ALICE, T0, 'laptop')];
    const link = await buildAgentRecord(k1, ALICE, agent, T1);
    // The same fields with the agent DID moved into `revokes`: a forged
    // retirement wearing the link's own signature.
    const forged = {
      $type: link.$type,
      did: link.did,
      revokes: agent,
      kid: link.kid,
      createdAt: link.createdAt,
      bindingSig: link.bindingSig,
    };
    expect(await liveAgents(devices, [link, forged], T2)).toEqual([agent]);
  });

  it('a link retirement ends the link', async () => {
    const k1 = await key(1);
    const agent = await agentDid();
    const devices = [await buildDeviceRecord(k1, ALICE, T0, 'laptop')];
    const links = [
      await buildAgentRecord(k1, ALICE, agent, T1, 'helper'),
      await buildAgentRetirement(k1, ALICE, agent, T2),
    ];
    expect(await liveAgents(devices, links, '2026-02-15T00:00:00Z')).toEqual([agent]);
    expect(await liveAgents(devices, links, T3)).toEqual([]);
  });
});

describe('device key expiry', () => {
  it('lasts 90 days by default', () => {
    expect(KEY_LIFETIME_MS).toBe(90 * 24 * 60 * 60 * 1000);
  });

  it('is written by the builder as the Rust builder writes it, and never on a retirement', async () => {
    const k1 = await key(1);
    const record = (await buildDeviceRecord(k1, ALICE, T0)) as unknown as Record<string, unknown>;
    expect(record.expiresAt).toBe('2026-04-01T00:00:00.000Z');
    const retirement = await buildDeviceRetirement(k1, ALICE, await kidOf(k1), T1);
    expect('expiresAt' in retirement).toBe(false);
  });

  it('ends a key at its default expiry', async () => {
    const records = [await buildDeviceRecord(await key(1), ALICE, T0)];
    expect(await liveKids(records, '2026-03-31T23:59:59Z')).toHaveLength(1);
    expect(await liveKids(records, T3)).toEqual([]);
  });

  it('ends a key at an earlier expiry its record names', async () => {
    const records = [await buildDeviceRecord(await key(1), ALICE, T0, undefined, T1)];
    expect(await liveKids(records, T2)).toEqual([]);
  });

  it('honours a later expiry without a cap', async () => {
    const k1 = await key(1);
    const records = [await buildDeviceRecord(k1, ALICE, T0, 'laptop', LATER)];
    expect(await liveKids(records, T4)).toEqual([await kidOf(k1)]);
  });

  it('does not count a retirement signed by an expired key', async () => {
    const [k1, k2] = [await key(1), await key(2)];
    const records = [
      await buildDeviceRecord(k1, ALICE, T0, undefined, T1),
      await buildDeviceRecord(k2, ALICE, T0),
      await buildDeviceRetirement(k1, ALICE, await kidOf(k2), T2),
    ];
    expect(await liveKids(records, T2)).toEqual([await kidOf(k2)]);
  });

  it('names the expiry in the history and retires the key at it', async () => {
    const [k1, k2, k3] = [await key(1), await key(2), await key(3)];
    const history = await deviceKeyHistory(ALICE, [
      await buildDeviceRecord(k1, ALICE, T0),
      await buildDeviceRecord(k2, ALICE, T0, undefined, LATER),
      await buildDeviceRecord(k3, ALICE, T0),
      await buildDeviceRetirement(k3, ALICE, await kidOf(k3), T1),
    ]);
    const of = async (k: DidKey) => {
      const kid = await kidOf(k);
      return history.find((h) => h.kid === kid)!;
    };
    expect((await of(k1)).expiresAt).toEqual(new Date(T3));
    expect((await of(k1)).retiredAt).toEqual(new Date(T3));
    expect((await of(k2)).expiresAt).toEqual(new Date(LATER));
    expect((await of(k2)).retiredAt).toEqual(new Date(LATER));
    // A retirement before the expiry is the date that counts.
    expect((await of(k3)).expiresAt).toEqual(new Date(T3));
    expect((await of(k3)).retiredAt).toEqual(new Date(T1));
  });

  it('drops a record whose expiry is not an RFC 3339 string', async () => {
    const k1 = await key(1);
    for (const expiresAt of ['next spring', '2026-13-01T00:00:00Z', '']) {
      const record = await buildDeviceRecord(k1, ALICE, T0, undefined, expiresAt);
      expect(await deviceKeyHistory(ALICE, [record]), expiresAt).toEqual([]);
    }
    const numeric = { ...(await buildDeviceRecord(k1, ALICE, T0)), expiresAt: 1_775_001_600 };
    expect(await deviceKeyHistory(ALICE, [numeric])).toEqual([]);
  });

  it("keeps a key's own record in its retirement closure when nothing retires it", async () => {
    const [k1, k2] = [await key(1), await key(2)];
    const own = await buildDeviceRecord(k1, ALICE, T0);
    const other = await buildDeviceRecord(k2, ALICE, T0);
    const closure = retirementClosure(ALICE, await kidOf(k1), [own, other], (r) => r);
    expect(closure).toEqual([own]);
    const [decided] = await deviceKeyHistory(ALICE, closure);
    expect(decided!.retiredAt).toEqual(new Date(T3));
  });
});

// ─── reading from a PDS ─────────────────────────────────────────────────

const PDS = 'https://pds.example';

function resolverFor(did: string, pds: string | undefined) {
  const doc: DidDocument = {
    id: did,
    service:
      pds === undefined
        ? []
        : [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds }],
  };
  return async (): Promise<DidDocument> => doc;
}

describe('device key history', () => {
  it('carries the retirement the fold accepted', async () => {
    // An earlier retirement signed by a key the account never published is
    // ignored; the later one, signed by the key itself, counts.
    const { deviceKeyHistory } = await import('./identity-records.js');
    const [k1, k2] = [await key(1), await key(2)];
    const records = [
      await buildDeviceRecord(k1, ALICE, T0),
      await buildDeviceRetirement(k2, ALICE, await kidOf(k1), T1),
      await buildDeviceRetirement(k1, ALICE, await kidOf(k1), T2),
    ];
    const history = await deviceKeyHistory(ALICE, records);
    expect(history.map((k) => k.kid)).toEqual([await kidOf(k1)]);
    expect(history[0]!.createdAt).toEqual(new Date(T0));
    expect(history[0]!.retiredAt).toEqual(new Date(T2));
  });
});

describe('checking listed records against the repository', () => {
  it('keeps a genuine record, ignores a forged one, and fetches a passed proof once', async () => {
    const { listRecordEntries, provenRecords } = await import('./identity-records.js');
    const { stubRepo } = await import('../test/repo-proofs.js');
    const repo = await stubRepo(ALICE);
    const genuine = await buildDeviceRecord(await key(1), ALICE, T0, 'laptop');
    // Signed by its own key, so it passes every record check but the proof.
    const forged = await buildDeviceRecord(await key(2), ALICE, T0, 'forged');
    const genuineEntry = await repo.add(DEVICE_KEY_TYPE, genuine);
    const forgedEntry = await repo.addForged(DEVICE_KEY_TYPE, forged, genuine);
    const doc = await repo.document(PDS);
    const fetch = async (input: string): Promise<Response> =>
      (await repo.respond(new URL(input))) ?? new Response('unexpected', { status: 500 });
    const resolveDid = async (): Promise<DidDocument> => doc;

    const proven = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const entries = await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE);
      expect(entries).toHaveLength(2);
      expect(await provenRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, entries, proven)).toEqual([
        genuine,
      ]);
    }
    expect(repo.proofReads(genuineEntry)).toBe(1);
    expect(repo.proofReads(forgedEntry)).toBe(3);
  });

  it('shares one proof between two listings racing on a record, and fetches a failed one again', async () => {
    const { listRecordEntries, provenRecords } = await import('./identity-records.js');
    const { stubRepo } = await import('../test/repo-proofs.js');
    const repo = await stubRepo(ALICE);
    const genuine = await buildDeviceRecord(await key(1), ALICE, T0, 'laptop');
    // Signed by its own key, so it passes every record check but the proof.
    const forged = await buildDeviceRecord(await key(2), ALICE, T0, 'forged');
    const genuineEntry = await repo.add(DEVICE_KEY_TYPE, genuine);
    const forgedEntry = await repo.addForged(DEVICE_KEY_TYPE, forged, genuine);
    const doc = await repo.document(PDS);
    const fetch = async (input: string): Promise<Response> =>
      (await repo.respond(new URL(input))) ?? new Response('unexpected', { status: 500 });
    const resolveDid = async (): Promise<DidDocument> => doc;
    const reads = () => [repo.proofReads(genuineEntry), repo.proofReads(forgedEntry)];

    const proven = new Set<string>();
    const proving = new Map<string, Promise<boolean>>();
    const entries = await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE);
    const prove = () => provenRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, entries, proven, proving);
    expect(await Promise.all([prove(), prove()])).toEqual([[genuine], [genuine]]);
    expect(reads(), 'racing listings share each proof').toEqual([1, 1]);

    expect(await prove()).toEqual([genuine]);
    expect(reads(), 'a failed proof is not kept').toEqual([1, 2]);
  });
});

describe('reading records from a PDS', () => {
  it('reads every page until the PDS stops sending a cursor', async () => {
    const [k1, k2] = [await key(1), await key(2)];
    const records = [
      await buildDeviceRecord(k1, ALICE, T0, 'laptop'),
      await buildDeviceRecord(k2, ALICE, T0, 'phone'),
      await buildDeviceRetirement(k2, ALICE, await kidOf(k1), T1),
    ];
    const fetch = vi.fn(async (input: string): Promise<Response> => {
      const cursor = new URL(input).searchParams.get('cursor');
      const page = cursor === null ? records.slice(0, 2) : records.slice(2);
      return Response.json({
        records: page.map((value) => ({ uri: 'at://x', cid: 'bafyreistub', value })),
        ...(cursor === null ? { cursor: 'page-2' } : {}),
      });
    });
    const resolveDid = resolverFor(ALICE, PDS);
    expect(await listRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE)).toEqual(records);
    expect(fetch).toHaveBeenCalledTimes(2);
    const kids = (await liveDeviceKeys(fetch, resolveDid, ALICE, new Date(T2))).map((k) => k.kid);
    expect(kids).toEqual([await kidOf(k2)]);
  });

  it('finds no records for a DID with no PDS', async () => {
    const fetch = vi.fn(async (): Promise<Response> => new Response('unreachable'));
    const resolveDid = resolverFor(ALICE, undefined);
    expect(await listRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE)).toEqual([]);
    expect(await liveDeviceKeys(fetch, resolveDid, ALICE, new Date(T1))).toEqual([]);
    expect(await liveAgentLinks(fetch, resolveDid, ALICE, new Date(T1))).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('fails when the PDS answers 500', async () => {
    const fetch = vi.fn(async (): Promise<Response> => new Response('down', { status: 500 }));
    const resolveDid = resolverFor(ALICE, PDS);
    await expect(listRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow();
    await expect(liveDeviceKeys(fetch, resolveDid, ALICE, new Date(T1))).rejects.toThrow();
    await expect(liveAgentLinks(fetch, resolveDid, ALICE, new Date(T1))).rejects.toThrow();
  });
});

// ─── hostile proofs ─────────────────────────────────────────────────────

const RKEY = '3mv2l5ebug2ql';

/**
 * A one-record repository proof built here: a commit for ALICE signed by a
 * fresh secp256k1 key, one tree node whose single leaf is `leaf`, and the
 * blocks given. Returns the CAR and the repository key as a multikey.
 */
async function buildProof(
  leaf: Cid,
  blocks: { cid: Cid; bytes: Uint8Array }[],
  forgedLeaf?: Cid,
): Promise<{ car: Uint8Array; repoKey: string }> {
  const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
  const key = new TextEncoder().encode(`${DEVICE_KEY_TYPE}/${RKEY}`);
  const node = (value: Cid) =>
    encode({ e: [{ k: new BytesWrapper(key), p: 0, t: null, v: toCidLink(value) }], l: null });
  const nodeCid = await create(CODEC_DCBOR, node(leaf));
  // With `forgedLeaf`, the CAR files a different node under the real node's CID.
  const nodeBytes = node(forgedLeaf ?? leaf);
  const unsigned = { did: ALICE, version: 3, data: toCidLink(nodeCid), rev: RKEY, prev: null };
  const sig = await keypair.sign(encode(unsigned));
  const commitBytes = encode({ ...unsigned, sig: new BytesWrapper(sig) });
  const commitCid = await create(CODEC_DCBOR, commitBytes);
  const entries = [
    { cid: commitCid.bytes, data: commitBytes },
    { cid: nodeCid.bytes, data: nodeBytes },
    ...blocks.map((b) => ({ cid: b.cid.bytes, data: b.bytes })),
  ];
  const chunks: Uint8Array[] = [];
  for await (const chunk of writeCarStream([toCidLink(commitCid)], entries)) chunks.push(chunk);
  const car = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    car.set(chunk, offset);
    offset += chunk.length;
  }
  return { car, repoKey: await keypair.exportPublicKey('multikey') };
}

describe('a proof built here', () => {
  it('verifies a record it holds', async () => {
    const record = await buildDeviceRecord(await key(1), ALICE, T0, 'laptop');
    const bytes = encode(record);
    const cid = await create(CODEC_DCBOR, bytes);
    const { car, repoKey } = await buildProof(cid, [{ cid, bytes }]);
    const expected = await recordCid(record);
    expect(await verifyProof(car, ALICE, DEVICE_KEY_TYPE, RKEY, expected, repoKey)).toEqual({
      commitDidMatches: true,
      signatureValid: true,
      recordPresent: true,
    });
  });

  it('reports no record when a tree node does not hash to its CID', async () => {
    // A real signed commit, with a forged tree node filed under the real
    // node's CID; the forged node's leaf is the record asked about.
    const genuine = encode({ $type: DEVICE_KEY_TYPE, label: 'genuine' });
    const genuineCid = await create(CODEC_DCBOR, genuine);
    const forged = await buildDeviceRecord(await key(2), ALICE, T0, 'forged');
    const forgedBytes = encode(forged);
    const forgedCid = await create(CODEC_DCBOR, forgedBytes);
    const { car, repoKey } = await buildProof(
      genuineCid,
      [{ cid: forgedCid, bytes: forgedBytes }],
      forgedCid,
    );
    const expected = await recordCid(forged);
    expect(await verifyProof(car, ALICE, DEVICE_KEY_TYPE, RKEY, expected, repoKey)).toEqual({
      commitDidMatches: true,
      signatureValid: true,
      recordPresent: false,
    });
  });

  it('reports no record when the leaf links to a block that is not DAG-CBOR', async () => {
    // A validly signed commit whose tree leaf for the record is a raw block:
    // the tree walk runs and finds a leaf that is not the record asked for.
    const bytes = new TextEncoder().encode('not a record');
    const cid = await create(CODEC_RAW, bytes);
    const { car, repoKey } = await buildProof(cid, [{ cid, bytes }]);
    const expected = await recordCid({ $type: DEVICE_KEY_TYPE });
    expect(await verifyProof(car, ALICE, DEVICE_KEY_TYPE, RKEY, expected, repoKey)).toEqual({
      commitDidMatches: true,
      signatureValid: true,
      recordPresent: false,
    });
  });
});

// ─── through the home server ────────────────────────────────────────────

const HOME = 'https://home.example';
const BOB = 'did:plc:bobbobbobbobbobbobbobbob';

afterEach(() => {
  clearHostPauses();
  setPauseClock();
});

/**
 * ALICE and BOB, each with one device record, served by a PDS and a home
 * server that answer from the same repositories. Counts PDS requests.
 */
async function homeNetwork() {
  const { stubRepo, stubHome } = await import('../test/repo-proofs.js');
  const alice = await stubRepo(ALICE);
  const bob = await stubRepo(BOB);
  const aliceRecord = await buildDeviceRecord(await key(1), ALICE, T0, 'laptop');
  const bobRecord = await buildDeviceRecord(await key(2), BOB, T0, 'phone');
  const aliceEntry = await alice.add(DEVICE_KEY_TYPE, aliceRecord);
  const bobEntry = await bob.add(DEVICE_KEY_TYPE, bobRecord);
  const home = stubHome([alice, bob]);
  const docs = [await alice.document(PDS), await bob.document(PDS)];
  const pds = { listings: 0, proofs: 0 };
  const fetch = vi.fn(async (input: string): Promise<Response> => {
    const url = new URL(input);
    if (url.origin === HOME) return (await home.respond(url)) ?? new Response('unexpected', { status: 500 });
    if (url.origin === PDS) {
      if (url.pathname.endsWith('listRecords')) pds.listings++;
      if (url.pathname.endsWith('getRecord')) pds.proofs++;
      for (const repo of [alice, bob]) {
        const answer = await repo.respond(url);
        if (answer !== undefined) return answer;
      }
    }
    return new Response('unexpected', { status: 500 });
  });
  const resolveDid = async (did: string): Promise<DidDocument> => {
    const doc = docs.find((d) => d.id === did);
    if (doc === undefined) throw new Error(`unknown DID ${did}`);
    return doc;
  };
  return { alice, bob, aliceRecord, bobRecord, aliceEntry, bobEntry, home, pds, fetch, resolveDid };
}

const rkeyOf = (entry: { uri: string }) => entry.uri.split('/').pop()!;

describe('fetchAccounts', () => {
  it('decodes a two-account answer and leaves an absent DID out', async () => {
    const { alice, aliceEntry, bobEntry, home, fetch } = await homeNetwork();
    const carol = 'did:plc:carolcarolcarolcarolcaro';
    home.fetchedAt = 1_790_000_000;
    const got = await fetchAccounts(fetch, HOME, [ALICE, BOB, carol], DEVICE_KEY_TYPE);
    expect([...got.keys()]).toEqual([ALICE, BOB]);
    expect(got.get(ALICE)!.entries).toEqual([aliceEntry]);
    expect(got.get(BOB)!.entries).toEqual([bobEntry]);
    expect(got.get(ALICE)!.proofs.get(rkeyOf(aliceEntry))).toEqual(alice.car(DEVICE_KEY_TYPE, rkeyOf(aliceEntry)));
    expect(got.get(ALICE)!.stale).toBe(false);
    expect(got.get(ALICE)!.fetchedAt).toBe(1_790_000_000);
    expect(home.hits.batch).toBe(1);
    expect(home.batches).toEqual([[ALICE, BOB, carol]]);
  });

  it('asks for 51 DIDs in two requests of at most 50', async () => {
    const { home, fetch } = await homeNetwork();
    const dids = [ALICE, ...Array.from({ length: 50 }, (_, i) => `did:plc:unseen${i}`)];
    const got = await fetchAccounts(fetch, HOME, dids, DEVICE_KEY_TYPE);
    expect([...got.keys()]).toEqual([ALICE]);
    expect(home.batches.map((b) => b.length)).toEqual([50, 1]);
  });

  it('gives nothing on a 404, 502, 400 or 500, and asks again next time', async () => {
    const { home, fetch } = await homeNetwork();
    for (const status of [404, 502, 400, 500]) {
      home.status = status;
      expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size, `${status}`).toBe(0);
    }
    home.status = null;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(1);
    expect(home.hits.batch).toBe(5);
  });

  it('gives nothing on a network error', async () => {
    const fetch = vi.fn(async (): Promise<Response> => {
      throw new TypeError('network down');
    });
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(0);
  });

  it('gives nothing on a 429 and asks the home server nothing for the 60 s that follow', async () => {
    let now = 1_000_000;
    setPauseClock(() => now);
    const { home, fetch, resolveDid } = await homeNetwork();
    home.status = 429;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(0);
    home.status = null;
    now += 59_000;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(0);
    expect(await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, HOME)).toHaveLength(1);
    expect(home.hits, 'no home route asked inside the cooldown').toEqual({ batch: 1, account: 0, listing: 0, proof: 0 });
    now += 2_000;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(1);
    expect(home.hits.batch).toBe(2);
  });

  it('holds the home server off for the Retry-After a 429 names', async () => {
    let now = 1_000_000;
    setPauseClock(() => now);
    const { home, fetch } = await homeNetwork();
    home.status = 429;
    home.headers = { 'retry-after': '5' };
    await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE);
    home.status = null;
    now += 4_000;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(0);
    now += 2_000;
    expect((await fetchAccounts(fetch, HOME, [ALICE], DEVICE_KEY_TYPE)).size).toBe(1);
    expect(home.hits.batch).toBe(2);
  });
});

describe('listRecordEntries through the home server', () => {
  it('takes the home listing and never asks the PDS', async () => {
    const { aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    expect(await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, HOME)).toEqual([aliceEntry]);
    expect(home.hits.listing).toBe(1);
    expect(pds.listings).toBe(0);
  });

  it('lists at the PDS when the home server answers 404', async () => {
    const { aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    home.left.add(ALICE);
    expect(await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, HOME)).toEqual([aliceEntry]);
    expect([home.hits.listing, pds.listings]).toEqual([1, 1]);
  });

  it('lists at the PDS alone with no home server', async () => {
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    expect(await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE)).toHaveLength(1);
    expect([home.hits.listing, pds.listings]).toEqual([0, 1]);
  });
});

describe('verifyRecord through the home server', () => {
  const holds = { commitDidMatches: true, signatureValid: true, recordPresent: true };

  it('checks a CAR it is given without fetching one', async () => {
    const { alice, aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    const car = alice.car(DEVICE_KEY_TYPE, rkeyOf(aliceEntry))!;
    expect(
      await verifyRecord(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, rkeyOf(aliceEntry), aliceEntry.cid, HOME, car),
    ).toEqual(holds);
    expect([home.hits.proof, pds.proofs]).toEqual([0, 0]);
  });

  it('takes the home proof and never asks the PDS', async () => {
    const { aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    expect(
      await verifyRecord(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, rkeyOf(aliceEntry), aliceEntry.cid, HOME),
    ).toEqual(holds);
    expect([home.hits.proof, pds.proofs]).toEqual([1, 0]);
  });

  it('fetches from the PDS when the home proof does not check, and the PDS proof decides', async () => {
    const { stubRepo } = await import('../test/repo-proofs.js');
    const { aliceRecord, aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    // The same record at the same rkey, committed under a key that is not ALICE's.
    const impostor = await stubRepo(ALICE);
    const forged = await impostor.add(DEVICE_KEY_TYPE, aliceRecord);
    expect(forged.uri).toBe(aliceEntry.uri);
    const forgedCar = impostor.car(DEVICE_KEY_TYPE, rkeyOf(forged))!;
    home.served.set(`${DEVICE_KEY_TYPE}/${rkeyOf(aliceEntry)}`, forgedCar);
    const rkey = rkeyOf(aliceEntry);
    const repoKey = (await resolveDid(ALICE)).verificationMethod![0]!.publicKeyMultibase!;
    expect((await verifyProof(forgedCar, ALICE, DEVICE_KEY_TYPE, rkey, aliceEntry.cid, repoKey)).signatureValid).toBe(false);
    expect(await verifyRecord(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, rkey, aliceEntry.cid, HOME)).toEqual(holds);
    expect([home.hits.proof, pds.proofs]).toEqual([1, 1]);
  });

  it('fetches from the PDS when a CAR it is given does not check', async () => {
    const { stubRepo } = await import('../test/repo-proofs.js');
    const { aliceRecord, aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    const impostor = await stubRepo(ALICE);
    const forgedCar = impostor.car(DEVICE_KEY_TYPE, rkeyOf(await impostor.add(DEVICE_KEY_TYPE, aliceRecord)))!;
    expect(
      await verifyRecord(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, rkeyOf(aliceEntry), aliceEntry.cid, HOME, forgedCar),
    ).toEqual(holds);
    expect([home.hits.proof, pds.proofs], 'the home server gave its proof already').toEqual([0, 1]);
  });

  it('fetches from the PDS when the home server has no proof', async () => {
    const { aliceEntry, home, pds, fetch, resolveDid } = await homeNetwork();
    home.withheld.add(`${DEVICE_KEY_TYPE}/${rkeyOf(aliceEntry)}`);
    expect(
      await verifyRecord(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, rkeyOf(aliceEntry), aliceEntry.cid, HOME),
    ).toEqual(holds);
    expect([home.hits.proof, pds.proofs]).toEqual([1, 1]);
  });

  it('proves listed records from given proofs, and fetches a proof absent from them at the PDS', async () => {
    const { alice, aliceRecord, aliceEntry, pds, fetch, resolveDid } = await homeNetwork();
    const second = await buildDeviceRecord(await key(3), ALICE, T0, 'tablet');
    const secondEntry = await alice.add(DEVICE_KEY_TYPE, second);
    const proofs = new Map([[rkeyOf(aliceEntry), alice.car(DEVICE_KEY_TYPE, rkeyOf(aliceEntry))!]]);
    const proven = new Set<string>();
    expect(
      await provenRecords(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, [aliceEntry, secondEntry], proven, new Map(), proofs),
    ).toEqual([aliceRecord, second]);
    expect(pds.proofs, 'only the record with no proof given').toBe(1);
    expect(alice.proofReads(secondEntry)).toBe(1);
  });
});

describe('a host that answered 429', () => {
  it('is not sent to while paused, for Retry-After seconds, then is asked again', async () => {
    let now = 1_000_000;
    setPauseClock(() => now);
    let limited = true;
    const inner = await homeNetwork();
    const fetch = vi.fn(async (input: string): Promise<Response> =>
      limited && new URL(input).origin === PDS
        ? new Response('slow down', { status: 429, headers: { 'retry-after': '30' } })
        : inner.fetch(input),
    );
    await expect(listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow();
    limited = false;
    const sent = fetch.mock.calls.length;
    now += 29_000;
    await expect(listRecords(fetch, inner.resolveDid, BOB, DEVICE_KEY_TYPE)).rejects.toThrow(/paused/);
    expect(fetch.mock.calls.length, 'a paused host is not sent to').toBe(sent);
    now += 2_000;
    expect(await listRecords(fetch, inner.resolveDid, BOB, DEVICE_KEY_TYPE)).toHaveLength(1);
  });

  it('pauses a PDS until RateLimit-Reset when no Retry-After is given, else five minutes', async () => {
    let now = 1_000_000_000;
    setPauseClock(() => now);
    const inner = await homeNetwork();
    let headers: Record<string, string> | null = { 'ratelimit-reset': String(1_000_000 + 100) };
    const fetch = vi.fn(async (input: string): Promise<Response> =>
      headers !== null && new URL(input).origin === PDS
        ? new Response('slow down', { status: 429, headers })
        : inner.fetch(input),
    );
    await expect(listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow();
    now += 99_000;
    await expect(listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow(/paused/);
    now += 2_000;
    headers = {};
    const sent = fetch.mock.calls.length;
    await expect(listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow();
    expect(fetch.mock.calls.length, 'the pause ended: sent, and answered 429 again').toBe(sent + 1);
    headers = null;
    now += 299_000;
    await expect(listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).rejects.toThrow(/paused/);
    now += 2_000;
    expect(await listRecords(fetch, inner.resolveDid, ALICE, DEVICE_KEY_TYPE)).toHaveLength(1);
  });

  it('pauses the home server without pausing the PDS', async () => {
    let now = 1_000_000;
    setPauseClock(() => now);
    const { home, pds, fetch, resolveDid } = await homeNetwork();
    home.status = 429;
    expect(await listRecordEntries(fetch, resolveDid, ALICE, DEVICE_KEY_TYPE, HOME)).toHaveLength(1);
    expect(await listRecordEntries(fetch, resolveDid, BOB, DEVICE_KEY_TYPE, HOME)).toHaveLength(1);
    expect([home.hits.listing, pds.listings]).toEqual([1, 2]);
  });
});
