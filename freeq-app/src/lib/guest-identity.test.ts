import { describe, it, expect } from 'vitest';
import { loadOrCreateGuestIdentity, storedGuestDid } from './guest-identity';

function memStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
  };
}

describe('a browser guest identity', () => {
  it('is a did:key, minted once and the same on every later visit', async () => {
    const storage = memStorage();
    const first = await loadOrCreateGuestIdentity(storage);
    expect(first.did).toMatch(/^did:key:z6Mk/);
    expect(storedGuestDid(storage)).toBe(first.did);
    const again = await loadOrCreateGuestIdentity(storage);
    expect(again.did).toBe(first.did);
  });

  it('signs with the key its DID names', async () => {
    const storage = memStorage();
    const g = await loadOrCreateGuestIdentity(storage);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', g.pair.publicKey));
    const { decodeMultibaseEd25519 } = await import('@freeq/sdk');
    expect([...pub]).toEqual([...decodeMultibaseEd25519(g.did.slice('did:key:'.length))]);
  });

  it('mints a fresh one when what is stored is unreadable', async () => {
    const storage = memStorage();
    storage.setItem('freeq-guest-key', 'not json');
    const g = await loadOrCreateGuestIdentity(storage);
    expect(g.did).toMatch(/^did:key:/);
  });
});
