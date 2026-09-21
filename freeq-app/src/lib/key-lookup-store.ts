/**
 * The key lookup's snapshot, kept in this browser's IndexedDB so a page load
 * starts with the keys, proven records and proven CIDs the last one found.
 * One entry per signed-in account, so another account's snapshot is never
 * read. Built like the SDK's IndexedDB device key store.
 */
import { openDB, type IDBPDatabase } from 'idb';
import type { KeyLookupSnapshot, KeyLookupStore } from '@freeq/sdk';

const DB_NAME = 'freeq-key-lookup';
const STORE = 'snapshots';

function openSnapshots(): Promise<IDBPDatabase> {
  return openDB(DB_NAME, 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    },
  });
}

/** `did` is the signed-in account the snapshot belongs to. */
export class IndexedDbKeyLookupStore implements KeyLookupStore {
  private readonly did: string;

  constructor(did: string) {
    this.did = did;
  }

  async load(): Promise<KeyLookupSnapshot | null> {
    const db = await openSnapshots();
    try {
      return ((await db.get(STORE, this.did)) as KeyLookupSnapshot | undefined) ?? null;
    } finally {
      db.close();
    }
  }

  async save(snapshot: KeyLookupSnapshot): Promise<void> {
    const db = await openSnapshots();
    try {
      await db.put(STORE, snapshot, this.did);
    } finally {
      db.close();
    }
  }
}
