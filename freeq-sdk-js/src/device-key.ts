/**
 * A device's own signing key, kept across connects.
 *
 * Without a store the client mints a fresh session key on every connect.
 * With one, the device presents the same key every time, so it can be
 * published once as an `at.freeq.deviceKey` record through the broker.
 *
 * `MemoryDeviceKeyStore` is for tests. `IndexedDbDeviceKeyStore` keeps a key
 * the page cannot read out.
 */

import { openDB, type IDBPDatabase } from 'idb';
import type { DidKey } from './did-key.js';

export interface StoredDeviceKey {
  keyPair: CryptoKeyPair;
  /** When the key was made, ISO 8601; the published record carries it. */
  createdAt: string;
  /** The `at://` URI of the record that publishes the key, once written. */
  recordUri?: string;
}

/** Where a device keeps its signing key between connects. */
export interface DeviceKeyStore {
  load(): Promise<StoredDeviceKey | null>;
  save(key: StoredDeviceKey): Promise<void>;
}

/** A store that forgets on reload. For tests. */
export class MemoryDeviceKeyStore implements DeviceKeyStore {
  constructor(private key: StoredDeviceKey | null = null) {}

  async load(): Promise<StoredDeviceKey | null> {
    return this.key;
  }

  async save(key: StoredDeviceKey): Promise<void> {
    this.key = key;
  }
}

// ─── IndexedDB ──────────────────────────────────────────────────────────

const DB_NAME = 'freeq-device-key';
const STORE = 'keys';

/** The key pair itself, where the browser can store a non-extractable key. */
interface PairEntry {
  kind: 'pair';
  keyPair: CryptoKeyPair;
  createdAt: string;
  recordUri?: string;
}

/** The private key wrapped under an AES-KW key that cannot be read out. */
interface WrappedEntry {
  kind: 'wrapped';
  wrappedKey: ArrayBuffer;
  publicKey: Uint8Array;
  wrappingKey: CryptoKey;
  createdAt: string;
  recordUri?: string;
}

function openKeys(): Promise<IDBPDatabase> {
  return openDB(DB_NAME, 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    },
  });
}

/**
 * A key kept in this browser's IndexedDB, made on first load. It is
 * generated non-extractable and the pair is stored as it is; a browser that
 * refuses a non-extractable Ed25519 key, or cannot store one, gets an
 * extractable key wrapped under a non-extractable AES-KW key instead.
 * `name` keeps one key per account.
 */
export class IndexedDbDeviceKeyStore implements DeviceKeyStore {
  /** How the key is kept, once loaded. */
  storage: 'pair' | 'wrapped' | null = null;

  constructor(private readonly name = 'device') {}

  async load(): Promise<StoredDeviceKey | null> {
    const db = await openKeys();
    try {
      const entry = (await db.get(STORE, this.name)) as PairEntry | WrappedEntry | undefined;
      if (entry?.kind === 'pair') {
        this.storage = 'pair';
        return { keyPair: entry.keyPair, createdAt: entry.createdAt, recordUri: entry.recordUri };
      }
      if (entry?.kind === 'wrapped') {
        this.storage = 'wrapped';
        return { keyPair: await unwrap(entry), createdAt: entry.createdAt, recordUri: entry.recordUri };
      }
      return await this.create(db);
    } finally {
      db.close();
    }
  }

  async save(key: StoredDeviceKey): Promise<void> {
    const db = await openKeys();
    try {
      const entry = (await db.get(STORE, this.name)) as PairEntry | WrappedEntry | undefined;
      // A wrapped key cannot be stored as a pair here, so it keeps its
      // wrapping; only the date and the URI change.
      if (entry?.kind === 'wrapped' && (await samePublicKey(entry.publicKey, key.keyPair))) {
        await db.put(STORE, { ...entry, createdAt: key.createdAt, recordUri: key.recordUri }, this.name);
        return;
      }
      const pair: PairEntry = {
        kind: 'pair',
        keyPair: key.keyPair,
        createdAt: key.createdAt,
        recordUri: key.recordUri,
      };
      await db.put(STORE, pair, this.name);
      this.storage = 'pair';
    } finally {
      db.close();
    }
  }

  private async create(db: IDBPDatabase): Promise<StoredDeviceKey> {
    const createdAt = new Date().toISOString();
    try {
      const keyPair = (await crypto.subtle.generateKey('Ed25519', false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair;
      const entry: PairEntry = { kind: 'pair', keyPair, createdAt };
      await db.put(STORE, entry, this.name);
      this.storage = 'pair';
      return { keyPair, createdAt };
    } catch {
      // Refused, or not storable: the wrapped form below.
    }
    const extractable = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const wrappingKey = (await crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, false, [
      'wrapKey',
      'unwrapKey',
    ])) as CryptoKey;
    const entry: WrappedEntry = {
      kind: 'wrapped',
      wrappedKey: await crypto.subtle.wrapKey('pkcs8', extractable.privateKey, wrappingKey, 'AES-KW'),
      publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', extractable.publicKey)),
      wrappingKey,
      createdAt,
    };
    await db.put(STORE, entry, this.name);
    this.storage = 'wrapped';
    return { keyPair: await unwrap(entry), createdAt };
  }
}

async function unwrap(entry: WrappedEntry): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    entry.wrappedKey,
    entry.wrappingKey,
    'AES-KW',
    'Ed25519',
    false,
    ['sign'],
  );
  const publicKey = await crypto.subtle.importKey(
    'raw',
    entry.publicKey as BufferSource,
    'Ed25519',
    true,
    ['verify'],
  );
  return { privateKey, publicKey };
}

async function samePublicKey(raw: Uint8Array, keyPair: CryptoKeyPair): Promise<boolean> {
  const other = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  return other.length === raw.length && other.every((b, i) => b === raw[i]);
}

// ─── the record key ─────────────────────────────────────────────────────

/**
 * What `buildDeviceRecord` needs from a key pair: its multibase public key
 * and a signer that signs through Web Crypto, so a non-extractable private
 * key signs its own record.
 */
export async function recordKeyOf(
  keyPair: CryptoKeyPair,
): Promise<Pick<DidKey, 'publicKeyMultibase' | 'signer'>> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  return {
    publicKeyMultibase: `z${base58btcEncode(new Uint8Array([0xed, 0x01, ...raw]))}`,
    signer: async (bytes: Uint8Array) =>
      base64UrlEncode(
        new Uint8Array(await crypto.subtle.sign('Ed25519', keyPair.privateKey, bytes as BufferSource)),
      ),
  };
}

// did-key.ts has the same encoders, private to it.

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]!];
  return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
