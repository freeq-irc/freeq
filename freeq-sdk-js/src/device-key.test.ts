import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  IndexedDbDeviceKeyStore,
  MemoryDeviceKeyStore,
  recordKeyOf,
} from './device-key.js';
import { decodeMultibaseEd25519, importDidKey } from './did-key.js';
import { buildDeviceRecord, foldDeviceRecords } from './identity-records.js';
import { deriveKid } from './signing.js';

const DID = 'did:plc:k2n3e2vsihf3farequ44t5j7';

async function kidOf(keyPair: CryptoKeyPair): Promise<string> {
  return deriveKid(new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)));
}

/** Sign with the loaded private key and check under the loaded public key. */
async function signsAndVerifies(keyPair: CryptoKeyPair): Promise<boolean> {
  const message = new TextEncoder().encode('freeq');
  const sig = await crypto.subtle.sign('Ed25519', keyPair.privateKey, message);
  return crypto.subtle.verify('Ed25519', keyPair.publicKey, sig, message);
}

beforeEach(() => {
  // A fresh database per test.
  globalThis.indexedDB = new IDBFactory();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('recordKeyOf', () => {
  it('names the key as its did:key does and signs records that fold live', async () => {
    const seed = new Uint8Array(32).fill(3);
    const didKey = await importDidKey(seed);
    const pkcs8 = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
      0x20, ...seed,
    ]);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
    const publicKey = await crypto.subtle.importKey(
      'raw',
      decodeMultibaseEd25519(didKey.publicKeyMultibase) as BufferSource,
      'Ed25519',
      true,
      ['verify'],
    );
    const key = await recordKeyOf({ privateKey, publicKey });
    expect(key.publicKeyMultibase).toBe(didKey.publicKeyMultibase);

    const record = await buildDeviceRecord(key, DID, '2026-09-11T10:00:00.000Z', 'Chrome');
    const live = await foldDeviceRecords(DID, [record], new Date('2026-09-12T00:00:00Z'));
    expect(live.map((k) => k.kid)).toEqual([record.kid]);
  });
});

describe('MemoryDeviceKeyStore', () => {
  it('holds what it was given', async () => {
    const store = new MemoryDeviceKeyStore();
    expect(await store.load()).toBeNull();
    const keyPair = (await crypto.subtle.generateKey('Ed25519', false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    await store.save({ keyPair, createdAt: '2026-09-11T10:00:00.000Z' });
    expect((await store.load())?.keyPair).toBe(keyPair);
  });
});

describe('IndexedDbDeviceKeyStore', () => {
  it('makes a key the page cannot read out, and keeps it', async () => {
    const first = new IndexedDbDeviceKeyStore();
    const made = await first.load();
    expect(made).not.toBeNull();
    expect(first.storage).toBe('pair');
    expect(made!.keyPair.privateKey.extractable).toBe(false);
    expect(made!.recordUri).toBeUndefined();

    const uri = 'at://did:plc:k2n3e2vsihf3farequ44t5j7/at.freeq.deviceKey/3k';
    await first.save({ ...made!, recordUri: uri });

    const again = await new IndexedDbDeviceKeyStore().load();
    expect(await kidOf(again!.keyPair)).toBe(await kidOf(made!.keyPair));
    expect(again!.createdAt).toBe(made!.createdAt);
    expect(again!.recordUri).toBe(uri);
    expect(await signsAndVerifies(again!.keyPair)).toBe(true);
  });

  it("keeps a refused key's flag through a save and a load", async () => {
    const store = new IndexedDbDeviceKeyStore('did:plc:refused');
    const made = await store.load();
    expect(made!.refused).toBeUndefined();
    await store.save({ ...made!, refused: true });
    const again = await new IndexedDbDeviceKeyStore('did:plc:refused').load();
    expect(again!.refused).toBe(true);
    expect(await kidOf(again!.keyPair)).toBe(await kidOf(made!.keyPair));
  });

  it('keeps one key per name', async () => {
    const a = await new IndexedDbDeviceKeyStore('did:plc:a').load();
    const b = await new IndexedDbDeviceKeyStore('did:plc:b').load();
    expect(await kidOf(a!.keyPair)).not.toBe(await kidOf(b!.keyPair));
    const a2 = await new IndexedDbDeviceKeyStore('did:plc:a').load();
    expect(await kidOf(a2!.keyPair)).toBe(await kidOf(a!.keyPair));
  });

  it('wraps the key under an AES-KW key where the browser refuses a non-extractable Ed25519 key', async () => {
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(((
      algorithm: AlgorithmIdentifier,
      extractable: boolean,
      usages: KeyUsage[],
    ) => {
      if (algorithm === 'Ed25519' && !extractable) {
        return Promise.reject(new DOMException('refused', 'NotSupportedError'));
      }
      return generate(algorithm as any, extractable, usages);
    }) as any);

    const first = new IndexedDbDeviceKeyStore();
    const made = await first.load();
    expect(first.storage).toBe('wrapped');
    expect(made!.keyPair.privateKey.extractable).toBe(false);

    const uri = 'at://did:plc:k2n3e2vsihf3farequ44t5j7/at.freeq.deviceKey/3w';
    await first.save({ ...made!, recordUri: uri });

    const second = new IndexedDbDeviceKeyStore();
    const again = await second.load();
    expect(second.storage).toBe('wrapped');
    expect(await kidOf(again!.keyPair)).toBe(await kidOf(made!.keyPair));
    expect(again!.recordUri).toBe(uri);
    expect(await signsAndVerifies(again!.keyPair)).toBe(true);

    // A refused wrapped key keeps its wrapping and its flag.
    await second.save({ ...again!, refused: true });
    const third = new IndexedDbDeviceKeyStore();
    const refused = await third.load();
    expect(third.storage).toBe('wrapped');
    expect(refused!.refused).toBe(true);
    expect(refused!.recordUri).toBe(uri);
  });
});
