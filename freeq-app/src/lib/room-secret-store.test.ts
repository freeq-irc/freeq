/**
 * Opened room secrets at rest: IndexedDB, sealed under a non-extractable
 * AES-GCM key, with the old plaintext localStorage entries imported once and
 * removed, and memory only when IndexedDB is not there.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { openDB } from 'idb';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  IndexedDbRoomSecretStore,
  MemoryRoomSecretStore,
  carryRoomSecrets,
  LEGACY_ROOM_KEYS_PREFIX,
  ROOM_SECRETS_DB,
  type LegacyStorage,
} from './room-secret-store';

const ME = 'did:plc:alice';
const GUEST = 'did:key:z6MkguestKey';
const CH = '#r-quiet-copper-fox';

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
});

function legacyStorage(entries: Record<string, string> = {}): LegacyStorage & { data: Map<string, string> } {
  const data = new Map(Object.entries(entries));
  return {
    data,
    get length() { return data.size; },
    key: (i: number) => [...data.keys()][i] ?? null,
    getItem: (k: string) => data.get(k) ?? null,
    removeItem: (k: string) => void data.delete(k),
  };
}

const secret = () => crypto.getRandomValues(new Uint8Array(32));

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function contains(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

/** Everything the store wrote, read straight from IndexedDB. */
async function rawRecords(): Promise<unknown[]> {
  const db = await openDB(ROOM_SECRETS_DB);
  try {
    return await db.getAll('secrets');
  } finally {
    db.close();
  }
}

describe('IndexedDbRoomSecretStore', () => {
  it('round-trips epochs per DID and channel, across instances', async () => {
    const s1 = secret();
    const s2 = secret();
    const a = new IndexedDbRoomSecretStore({ legacy: null });
    await a.save(ME, CH, new Map([[1, s1], [2, s2]]));
    expect(await a.backend()).toBe('indexeddb');

    // A fresh instance is a page reload: it reads from IndexedDB, not memory.
    const b = new IndexedDbRoomSecretStore({ legacy: null });
    const got = await b.load(ME, CH);
    expect([...got.keys()].sort()).toEqual([1, 2]);
    expect(got.get(1)).toEqual(s1);
    expect(got.get(2)).toEqual(s2);
    expect((await b.load(GUEST, CH)).size).toBe(0);
    expect((await b.load(ME, '#r-other')).size).toBe(0);
  });

  it('keeps nothing in plaintext: records are AES-GCM ciphertext under a key that cannot be read out', async () => {
    const s1 = secret();
    const store = new IndexedDbRoomSecretStore({ legacy: null });
    await store.save(ME, CH, new Map([[1, s1]]));

    const records = await rawRecords();
    expect(records).toHaveLength(1);
    const rec = records[0] as { iv: Uint8Array; ct: ArrayBuffer | Uint8Array };
    const ct = new Uint8Array(rec.ct as ArrayBuffer);
    expect(contains(ct, s1)).toBe(false);
    const text = new TextDecoder('latin1').decode(ct);
    expect(text.includes(b64(s1))).toBe(false);
    expect(JSON.stringify(rec)).not.toContain(b64(s1));

    const db = await openDB(ROOM_SECRETS_DB);
    const key = (await db.get('meta', 'key')) as CryptoKey;
    db.close();
    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe('AES-GCM');
  });

  it('binds each record to its DID and channel (a swapped record does not open)', async () => {
    const store = new IndexedDbRoomSecretStore({ legacy: null });
    await store.save(ME, CH, new Map([[1, secret()]]));
    const db = await openDB(ROOM_SECRETS_DB);
    const rec = await db.get('secrets', [ME, CH]);
    await db.put('secrets', rec, [GUEST, CH]);
    db.close();
    const fresh = new IndexedDbRoomSecretStore({ legacy: null });
    expect((await fresh.load(GUEST, CH)).size).toBe(0);
    expect((await fresh.load(ME, CH)).size).toBe(1);
  });

  it('imports the old localStorage entries once and deletes them', async () => {
    const s1 = secret();
    const g1 = secret();
    const legacy = legacyStorage({
      [`${LEGACY_ROOM_KEYS_PREFIX}${ME}:${CH}`]: JSON.stringify({ '1': b64(s1) }),
      [`${LEGACY_ROOM_KEYS_PREFIX}${GUEST}:${CH}`]: JSON.stringify({ '3': b64(g1) }),
      [`${LEGACY_ROOM_KEYS_PREFIX}garbage`]: 'not json',
      'freeq-something-else': 'kept',
    });
    const store = new IndexedDbRoomSecretStore({ legacy });
    expect((await store.load(ME, CH)).get(1)).toEqual(s1);

    expect([...legacy.data.keys()]).toEqual(['freeq-something-else']);
    // Imported into IndexedDB, so a reload without the old entries still reads.
    const reload = new IndexedDbRoomSecretStore({ legacy: legacyStorage() });
    expect((await reload.load(ME, CH)).get(1)).toEqual(s1);
    expect((await reload.load(GUEST, CH)).get(3)).toEqual(g1);
  });

  it('does not let an old entry overwrite epochs already in IndexedDB', async () => {
    const newer = secret();
    const first = new IndexedDbRoomSecretStore({ legacy: null });
    await first.save(ME, CH, new Map([[2, newer]]));
    const old = secret();
    const legacy = legacyStorage({ [`${LEGACY_ROOM_KEYS_PREFIX}${ME}:${CH}`]: JSON.stringify({ '1': b64(old) }) });
    const store = new IndexedDbRoomSecretStore({ legacy });
    const got = await store.load(ME, CH);
    expect(got.get(1)).toEqual(old);
    expect(got.get(2)).toEqual(newer);
    expect(legacy.data.size).toBe(0);
  });

  it('falls back to memory when IndexedDB throws, and never writes localStorage', async () => {
    globalThis.indexedDB = {
      open() { throw new DOMException('denied', 'SecurityError'); },
    } as unknown as IDBFactory;
    const s1 = secret();
    const legacy = legacyStorage({ [`${LEGACY_ROOM_KEYS_PREFIX}${ME}:${CH}`]: JSON.stringify({ '1': b64(s1) }) });
    const store = new IndexedDbRoomSecretStore({ legacy });
    expect(await store.backend()).toBe('memory');
    // The old entry is read into memory and still removed from disk.
    expect((await store.load(ME, CH)).get(1)).toEqual(s1);
    expect(legacy.data.size).toBe(0);

    const s2 = secret();
    await store.save(ME, CH, new Map([[1, s1], [2, s2]]));
    expect((await store.load(ME, CH)).get(2)).toEqual(s2);
    expect(legacy.data.size).toBe(0);
  });

  it('falls back to memory when there is no IndexedDB at all', async () => {
    const saved = globalThis.indexedDB;
    // @ts-expect-error simulate an environment without IndexedDB
    delete globalThis.indexedDB;
    try {
      const store = new IndexedDbRoomSecretStore({ legacy: null });
      expect(await store.backend()).toBe('memory');
      await store.save(ME, CH, new Map([[1, secret()]]));
      expect((await store.load(ME, CH)).size).toBe(1);
    } finally {
      globalThis.indexedDB = saved;
    }
  });

  it('removes a DID+channel slot from IndexedDB and memory', async () => {
    const store = new IndexedDbRoomSecretStore({ legacy: null });
    await store.save(ME, CH, new Map([[1, secret()]]));
    await store.save(ME, '#r-other', new Map([[1, secret()]]));
    await store.remove(ME, CH);
    expect((await store.load(ME, CH)).size).toBe(0);
    const reload = new IndexedDbRoomSecretStore({ legacy: null });
    expect((await reload.load(ME, CH)).size).toBe(0);
    expect((await reload.load(ME, '#r-other')).size).toBe(1);
    expect(await rawRecords()).toHaveLength(1);
  });

  it('applies writes in order (a later, larger save is never lost to an earlier one)', async () => {
    const store = new IndexedDbRoomSecretStore({ legacy: null });
    const s1 = secret();
    const s2 = secret();
    const p1 = store.save(ME, CH, new Map([[1, s1]]));
    const p2 = store.save(ME, CH, new Map([[1, s1], [2, s2]]));
    await Promise.all([p1, p2]);
    const reload = new IndexedDbRoomSecretStore({ legacy: null });
    expect([...(await reload.load(ME, CH)).keys()].sort()).toEqual([1, 2]);
  });
});

describe('carryRoomSecrets', () => {
  it('copies the guest slot to the new identity', async () => {
    const store = new MemoryRoomSecretStore();
    const s1 = secret();
    await store.save(GUEST, CH, new Map([[1, s1]]));
    expect(await carryRoomSecrets(store, GUEST, ME, CH)).toBe(true);
    expect((await store.load(ME, CH)).get(1)).toEqual(s1);
  });

  it('never overwrites what the new identity already holds', async () => {
    const store = new MemoryRoomSecretStore();
    const mine = secret();
    await store.save(GUEST, CH, new Map([[1, secret()]]));
    await store.save(ME, CH, new Map([[1, mine], [2, secret()]]));
    expect(await carryRoomSecrets(store, GUEST, ME, CH)).toBe(false);
    expect((await store.load(ME, CH)).get(1)).toEqual(mine);
  });

  it('is a no-op for the same DID or an empty guest slot', async () => {
    const store = new MemoryRoomSecretStore();
    expect(await carryRoomSecrets(store, GUEST, ME, CH)).toBe(false);
    await store.save(ME, CH, new Map([[1, secret()]]));
    expect(await carryRoomSecrets(store, ME, ME, CH)).toBe(false);
  });
});
