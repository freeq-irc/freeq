/**
 * The key lookup's snapshot, kept in this browser's IndexedDB so a page load
 * starts with the keys, proven records and proven CIDs the last one found.
 * All of it is public data about other accounts, so the browser keeps one
 * snapshot shared by everyone who uses it, guest or signed in; nothing is
 * cleared on sign-out. Built like the SDK's IndexedDB device key store.
 */
import { openDB, type IDBPDatabase } from 'idb';
import type { KeyLookupSnapshot, KeyLookupStore } from '@freeq/sdk';

const DB_NAME = 'freeq-key-lookup';
const STORE = 'snapshots';
/** The one entry the shared snapshot is kept under. */
const KEY = 'shared';

function openSnapshots(): Promise<IDBPDatabase> {
  return openDB(DB_NAME, 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    },
  });
}

export class IndexedDbKeyLookupStore implements KeyLookupStore {
  async load(): Promise<KeyLookupSnapshot | null> {
    const db = await openSnapshots();
    try {
      return ((await db.get(STORE, KEY)) as KeyLookupSnapshot | undefined) ?? null;
    } finally {
      db.close();
    }
  }

  async save(snapshot: KeyLookupSnapshot): Promise<void> {
    const db = await openSnapshots();
    try {
      await db.put(STORE, snapshot, KEY);
    } finally {
      db.close();
    }
  }
}
