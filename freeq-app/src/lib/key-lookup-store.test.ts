/**
 * The key lookup's IndexedDB snapshot: each account's records once, the key
 * answers (found and missed), and proven CIDs come back as saved, one
 * snapshot for the whole browser.
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
  version: 2,
  accounts: [
    ['did:plc:alice', [RECORD]],
    ['did:plc:bob', []],
  ],
  keys: [
    [JSON.stringify(['did:plc:alice', 'kid1']), { other: undefined, at: 1_000 }],
    [
      JSON.stringify(['did:plc:bob', 'kid2']),
      {
        other: {
          publicKey: new Uint8Array([1, 2, 3]),
          source: 'OriginServer',
          retiredAt: 1_780_000_000,
          expiresAt: null,
        },
        at: 2_000,
      },
    ],
    [JSON.stringify(['did:plc:bob', 'kid3']), { other: null, at: 3_000 }],
  ],
  records: [['did:plc:alice', 1_000]],
  refreshed: [['did:plc:alice', 1_000]],
  proven: ['bafyreiproven'],
};

describe('IndexedDbKeyLookupStore', () => {
  it('holds nothing before a snapshot is saved', async () => {
    expect(await new IndexedDbKeyLookupStore().load()).toBeNull();
  });

  it('gives back the accounts, answers, listing times and proven CIDs it saved', async () => {
    await new IndexedDbKeyLookupStore().save(snapshot);
    const loaded = await new IndexedDbKeyLookupStore().load();
    expect(loaded).toEqual(snapshot);
    expect(loaded!.keys[1]![1].other!.publicKey).toBeInstanceOf(Uint8Array);
  });

  it('is one snapshot however many stores are built on it', async () => {
    const first = { ...snapshot, proven: ['bafyreifirst'] };
    await new IndexedDbKeyLookupStore().save(first);
    expect(await new IndexedDbKeyLookupStore().load()).toEqual(first);
    const second = { ...snapshot, proven: ['bafyreisecond'] };
    await new IndexedDbKeyLookupStore().save(second);
    expect(await new IndexedDbKeyLookupStore().load()).toEqual(second);
  });

  it('reads only once a given wait has settled', async () => {
    await new IndexedDbKeyLookupStore().save(snapshot);
    let release!: () => void;
    const after = new Promise<void>((r) => (release = r));
    let read = false;
    const loading = new IndexedDbKeyLookupStore(after).load().then((s) => {
      read = true;
      return s;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(read).toBe(false);
    const later = { ...snapshot, proven: ['bafyreilater'] };
    await new IndexedDbKeyLookupStore().save(later);
    release();
    expect(await loading).toEqual(later);
  });
});
