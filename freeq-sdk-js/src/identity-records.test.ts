/**
 * The fold, against records built here rather than read from the spec file.
 *
 * The vector file carries the same seven cases, but a package installed
 * without `spec/` still has to fold the same way, so these build their own
 * inputs.
 */
import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';

import { type DidKey, decodeMultibaseEd25519, importDidKey } from './did-key.js';
import {
  buildAgentRecord,
  buildAgentRetirement,
  buildDeviceRecord,
  buildDeviceRetirement,
  foldAgentRecords,
  foldDeviceRecords,
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
