/**
 * The key lookup's IndexedDB snapshot: found keys, proven records and proven
 * CIDs come back as saved, per signed-in account.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { beforeEach, describe, expect, it } from 'vitest';
import type { KeyLookupSnapshot } from '@freeq/sdk';
import { IndexedDbKeyLookupStore } from './key-lookup-store';

beforeEach(() => {
  // A fresh database per test.
  globalThis.indexedDB = new IDBFactory();
});

const RECORD = { $type: 'at.freeq.deviceKey', kid: 'kid1', publicKeyMultibase: 'z6Mk' };

const snapshot: KeyLookupSnapshot = {
  keys: [
    [JSON.stringify(['did:plc:alice', 'kid1']), { records: [RECORD], other: undefined, at: 1_000 }],
    [
      JSON.stringify(['did:plc:bob', 'kid2']),
      {
        records: [],
        other: { publicKey: new Uint8Array([1, 2, 3]), source: 'OriginServer', retiredAt: 1_780_000_000 },
        at: 2_000,
      },
    ],
  ],
  records: [['did:plc:alice', { records: [RECORD], at: 1_000 }]],
  proven: ['bafyreiproven'],
};

describe('IndexedDbKeyLookupStore', () => {
  it('holds nothing for an account with no snapshot', async () => {
    expect(await new IndexedDbKeyLookupStore('did:plc:me').load()).toBeNull();
  });

  it('gives back the found keys, proven records and proven CIDs it saved', async () => {
    await new IndexedDbKeyLookupStore('did:plc:me').save(snapshot);
    const loaded = await new IndexedDbKeyLookupStore('did:plc:me').load();
    expect(loaded).toEqual(snapshot);
    expect(loaded!.keys[1]![1].other!.publicKey).toBeInstanceOf(Uint8Array);
  });

  it('never gives one account the snapshot another saved', async () => {
    await new IndexedDbKeyLookupStore('did:plc:me').save(snapshot);
    expect(await new IndexedDbKeyLookupStore('did:plc:other').load()).toBeNull();
  });
});
