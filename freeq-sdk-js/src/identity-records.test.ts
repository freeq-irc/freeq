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
import { beforeAll, describe, expect, it, vi } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import {
  DEVICE_KEY_TYPE,
  type DidDocument,
  buildAgentRecord,
  buildAgentRetirement,
  buildDeviceRecord,
  buildDeviceRetirement,
  foldAgentRecords,
  foldDeviceRecords,
  listRecords,
  liveAgentLinks,
  liveDeviceKeys,
  recordCid,
  verifyProof,
} from './identity-records.js';
import { deriveKid } from './signing.js';

const ALICE = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const T0 = '2026-01-01T00:00:00Z';
const T1 = '2026-02-01T00:00:00Z';
const T2 = '2026-03-01T00:00:00Z';
const T3 = '2026-04-01T00:00:00Z';

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
      const record = await buildDeviceRecord(k1, ALICE, createdAt);
      expect(await liveKids([record], T2)).toEqual([]);
    }
    const leapDay = await buildDeviceRecord(k1, ALICE, '2024-02-29T00:00:00Z');
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
