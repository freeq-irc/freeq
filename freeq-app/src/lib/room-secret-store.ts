/**
 * Where the web client keeps the instant-room epoch secrets it has opened, so
 * a reload reads a room without waiting for a steward to seal the key again.
 * See docs/INSTANT-ROOMS.md ("Web").
 *
 * The secrets live in IndexedDB, each slot (DID + channel) AES-GCM encrypted
 * under one 256-bit key that WebCrypto generates in this browser as
 * non-extractable: the page can use it but never read it out, and IndexedDB
 * holds it as an opaque `CryptoKey`. Each record's additional data is its own
 * slot, so a record moved to another DID or channel does not open. Built like
 * the SDK's IndexedDB device key store and `key-lookup-store.ts`.
 *
 * Earlier builds kept these in localStorage as plaintext base64
 * (`freeq-room-keys:<did>:<channel>`). The first use imports any such entries
 * and deletes them from localStorage.
 *
 * Without IndexedDB (some private modes, locked-down embeds) the secrets stay
 * in memory for this page only. They never go back to localStorage.
 *
 * Nothing here logs a secret.
 */
import { openDB, type IDBPDatabase } from 'idb';

export const ROOM_SECRETS_DB = 'freeq-room-secrets';
const SECRETS = 'secrets';
const META = 'meta';
const KEY_ID = 'key';

/** The old plaintext localStorage entries: `freeq-room-keys:<did>:<channel>`. */
export const LEGACY_ROOM_KEYS_PREFIX = 'freeq-room-keys:';

/** The parts of `Storage` the one-time migration needs. */
export type LegacyStorage = Pick<Storage, 'length' | 'key' | 'getItem' | 'removeItem'>;

/** Epoch → 32-byte group secret. */
export type RoomEpochSecrets = Map<number, Uint8Array>;

export interface RoomSecretStore {
  /** The epochs held for this DID in this channel; empty when none. */
  load(did: string, channel: string): Promise<RoomEpochSecrets>;
  /** Replace the slot with these epochs. */
  save(did: string, channel: string, epochs: RoomEpochSecrets): Promise<void>;
  /** Forget the slot. */
  remove(did: string, channel: string): Promise<void>;
}

const slot = (did: string, channel: string) => `${did}\n${channel.toLowerCase()}`;

const copyEpochs = (m: RoomEpochSecrets): RoomEpochSecrets =>
  new Map([...m.entries()].map(([e, s]) => [e, new Uint8Array(s)]));

/** Keeps secrets for this page only. For tests, and the fallback. */
export class MemoryRoomSecretStore implements RoomSecretStore {
  private readonly slots = new Map<string, RoomEpochSecrets>();

  async load(did: string, channel: string): Promise<RoomEpochSecrets> {
    const got = this.slots.get(slot(did, channel));
    return got ? copyEpochs(got) : new Map();
  }

  async save(did: string, channel: string, epochs: RoomEpochSecrets): Promise<void> {
    if (epochs.size === 0) this.slots.delete(slot(did, channel));
    else this.slots.set(slot(did, channel), copyEpochs(epochs));
  }

  async remove(did: string, channel: string): Promise<void> {
    this.slots.delete(slot(did, channel));
  }
}

interface SealedRecord {
  iv: Uint8Array;
  ct: ArrayBuffer;
}

interface Backend {
  kind: 'indexeddb' | 'memory';
  db: IDBPDatabase | null;
  key: CryptoKey | null;
}

/**
 * IndexedDB, encrypted at rest, with a memory mirror in front of it. Every
 * operation runs in order behind the one before, so an earlier write can
 * never land over a later one.
 */
export class IndexedDbRoomSecretStore implements RoomSecretStore {
  private readonly legacy: LegacyStorage | null;
  private readonly mem = new MemoryRoomSecretStore();
  /** Slots known to be in `mem` (loaded or written this page). */
  private readonly mirrored = new Set<string>();
  private queue: Promise<unknown>;
  private readonly ready: Promise<Backend>;

  constructor(opts: { legacy?: LegacyStorage | null } = {}) {
    this.legacy = opts.legacy === undefined ? defaultLegacyStorage() : opts.legacy;
    this.ready = this.init();
    this.queue = this.ready.catch(() => undefined);
  }

  /** Which backend ended up in use. */
  async backend(): Promise<'indexeddb' | 'memory'> {
    return (await this.ready).kind;
  }

  load(did: string, channel: string): Promise<RoomEpochSecrets> {
    return this.run(async (b) => {
      const id = slot(did, channel);
      if (this.mirrored.has(id) || b.kind === 'memory') return this.mem.load(did, channel);
      const got = await this.readSealed(b, did, channel);
      await this.mem.save(did, channel, got);
      this.mirrored.add(id);
      return copyEpochs(got);
    });
  }

  save(did: string, channel: string, epochs: RoomEpochSecrets): Promise<void> {
    const snapshot = copyEpochs(epochs);
    return this.run(async (b) => {
      await this.mem.save(did, channel, snapshot);
      this.mirrored.add(slot(did, channel));
      if (b.kind === 'indexeddb') {
        try {
          await this.writeSealed(b, did, channel, snapshot);
        } catch { /* quota or a closed database: memory still has it for this page */ }
      }
    });
  }

  remove(did: string, channel: string): Promise<void> {
    return this.run(async (b) => {
      await this.mem.remove(did, channel);
      this.mirrored.add(slot(did, channel));
      if (b.kind === 'indexeddb') {
        try { await b.db!.delete(SECRETS, [did, channel.toLowerCase()]); } catch { /* gone already */ }
      }
    });
  }

  private run<T>(op: (b: Backend) => Promise<T>): Promise<T> {
    const p = this.queue.then(async () => op(await this.ready));
    this.queue = p.catch(() => undefined);
    return p;
  }

  // ── Setup ──

  private async init(): Promise<Backend> {
    let backend: Backend;
    try {
      backend = await openBackend();
    } catch {
      backend = { kind: 'memory', db: null, key: null };
    }
    await this.migrate(backend);
    return backend;
  }

  /** Move the old plaintext localStorage entries in, then delete them. */
  private async migrate(b: Backend): Promise<void> {
    const ls = this.legacy;
    if (!ls) return;
    let keys: string[];
    try {
      keys = [];
      for (let i = 0; i < ls.length; i++) {
        const k = ls.key(i);
        if (k && k.startsWith(LEGACY_ROOM_KEYS_PREFIX)) keys.push(k);
      }
    } catch {
      return;
    }
    for (const k of keys) {
      try {
        const parsed = parseLegacy(k, ls.getItem(k));
        if (parsed) {
          const { did, channel, epochs } = parsed;
          const merged = b.kind === 'indexeddb' ? await this.readSealed(b, did, channel) : await this.mem.load(did, channel);
          for (const [e, s] of epochs) if (!merged.has(e)) merged.set(e, s);
          await this.mem.save(did, channel, merged);
          this.mirrored.add(slot(did, channel));
          if (b.kind === 'indexeddb') await this.writeSealed(b, did, channel, merged);
        }
      } catch { /* unreadable or unwritable: drop it rather than keep plaintext */ }
      try { ls.removeItem(k); } catch { /* ignore */ }
    }
  }

  // ── Records ──

  private async readSealed(b: Backend, did: string, channel: string): Promise<RoomEpochSecrets> {
    const ch = channel.toLowerCase();
    const rec = (await b.db!.get(SECRETS, [did, ch])) as SealedRecord | undefined;
    if (!rec) return new Map();
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: rec.iv as BufferSource, additionalData: aad(did, ch) as BufferSource },
        b.key!,
        rec.ct,
      );
      return decodeEpochs(JSON.parse(new TextDecoder().decode(plain)));
    } catch {
      return new Map(); // not ours, or the key is gone: as if never held
    }
  }

  private async writeSealed(b: Backend, did: string, channel: string, epochs: RoomEpochSecrets): Promise<void> {
    const ch = channel.toLowerCase();
    if (epochs.size === 0) {
      await b.db!.delete(SECRETS, [did, ch]);
      return;
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(encodeEpochs(epochs)));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad(did, ch) as BufferSource },
      b.key!,
      plain as BufferSource,
    );
    const rec: SealedRecord = { iv, ct };
    await b.db!.put(SECRETS, rec, [did, ch]);
  }
}

async function openBackend(): Promise<Backend> {
  if (typeof indexedDB === 'undefined' || !indexedDB) throw new Error('no IndexedDB');
  const db = await openDB(ROOM_SECRETS_DB, 1, {
    upgrade(d) {
      if (!d.objectStoreNames.contains(SECRETS)) d.createObjectStore(SECRETS);
      if (!d.objectStoreNames.contains(META)) d.createObjectStore(META);
    },
  });
  try {
    let key = (await db.get(META, KEY_ID)) as CryptoKey | undefined;
    if (!key) {
      key = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])) as CryptoKey;
      // `add`, not `put`: if another tab got there first, use its key.
      try {
        await db.add(META, key, KEY_ID);
      } catch {
        key = (await db.get(META, KEY_ID)) as CryptoKey | undefined;
        if (!key) throw new Error('no room secret key');
      }
    }
    return { kind: 'indexeddb', db, key };
  } catch (err) {
    db.close();
    throw err;
  }
}

function aad(did: string, channel: string): Uint8Array {
  return new TextEncoder().encode(`freeq-room-secrets:v1\n${did}\n${channel}`);
}

function encodeEpochs(epochs: RoomEpochSecrets): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [e, s] of [...epochs.entries()].sort((a, b) => a[0] - b[0])) out[String(e)] = b64(s);
  return out;
}

function decodeEpochs(raw: unknown): RoomEpochSecrets {
  const out: RoomEpochSecrets = new Map();
  if (!raw || typeof raw !== 'object') return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const epoch = Number(k);
    if (!Number.isInteger(epoch) || epoch < 1 || typeof v !== 'string') continue;
    try {
      const secret = unb64(v);
      if (secret.length === 32) out.set(epoch, secret);
    } catch { /* skip */ }
  }
  return out;
}

/** `freeq-room-keys:<did>:<channel>` → its slot and epochs. DIDs hold colons,
 *  so the channel is what follows the last `:#`. */
function parseLegacy(key: string, value: string | null): { did: string; channel: string; epochs: RoomEpochSecrets } | null {
  if (!value) return null;
  const rest = key.slice(LEGACY_ROOM_KEYS_PREFIX.length);
  const cut = rest.lastIndexOf(':#');
  if (cut <= 0) return null;
  const did = rest.slice(0, cut);
  const channel = rest.slice(cut + 1).toLowerCase();
  if (!did.startsWith('did:')) return null;
  const epochs = decodeEpochs(JSON.parse(value));
  return epochs.size > 0 ? { did, channel, epochs } : null;
}

function defaultLegacyStorage(): LegacyStorage | null {
  try {
    if (typeof localStorage !== 'undefined' && typeof localStorage.key === 'function') return localStorage;
  } catch { /* locked-down embeds */ }
  return null;
}

/**
 * Copy one DID's slot to another (a room guest who signed in keeps reading).
 * Never overwrites what the new identity already holds. True when something
 * was carried.
 */
export async function carryRoomSecrets(
  store: RoomSecretStore,
  fromDid: string,
  toDid: string,
  channel: string,
): Promise<boolean> {
  if (fromDid === toDid) return false;
  const from = await store.load(fromDid, channel);
  if (from.size === 0) return false;
  const to = await store.load(toDid, channel);
  if (to.size > 0) return false;
  await store.save(toDid, channel, from);
  return true;
}

let singleton: RoomSecretStore | null = null;

/** The app's store: IndexedDB, or memory when that is unavailable. */
export function getRoomSecretStore(): RoomSecretStore {
  if (!singleton) singleton = new IndexedDbRoomSecretStore();
  return singleton;
}

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) throw new Error('not base64');
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
