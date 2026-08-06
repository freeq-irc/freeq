import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

import {
  initialize, shutdown, isE2eeReady, getIdentityPublicKey, encryptMessage, decryptMessage,
  isEncrypted, setAuthToken, publishPreKeyBundle,
} from './e2ee';

const DID = 'did:plc:testuser000000000000000';
const ORIGIN = 'https://irc.example.test';

describe('e2ee identity keys (first login, empty IndexedDB)', () => {
  let bundles: Array<Record<string, any>>;

  beforeEach(() => {
    // A brand-new browser profile: no stored identity to fall back on, so the
    // generate path runs.
    globalThis.indexedDB = new IDBFactory();
    bundles = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/api/v1/keys') && init?.method === 'POST') {
        bundles.push(JSON.parse(String(init.body)));
        return new Response('{}', { status: 200 });
      }
      return new Response('{}', { status: 404 });
    }));
  });

  afterEach(() => {
    shutdown();
    vi.unstubAllGlobals();
  });

  it('initializes and publishes a pre-key bundle', async () => {
    await initialize(DID, ORIGIN);

    expect(isE2eeReady()).toBe(true);
    expect(getIdentityPublicKey()).toHaveLength(32);
    expect(bundles).toHaveLength(1);
    expect(bundles[0].bundle.identity_key).toBeTruthy();
    expect(bundles[0].bundle.signed_pre_key).toBeTruthy();
  });

  it('proves DID ownership when publishing, and can publish again later', async () => {
    // The server takes a bundle only from the session that authenticated as
    // that DID (the token arrives after login, so it can be set late).
    const auth: Array<string | null> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/api/v1/keys') && init?.method === 'POST') {
        const header = (init.headers as Record<string, string>)?.Authorization ?? null;
        auth.push(header);
        return new Response('{}', { status: header ? 200 : 403 });
      }
      return new Response('{}', { status: 404 });
    }));

    // The token lands after login, so the first attempt is refused...
    await initialize(DID, ORIGIN);
    expect(auth).toEqual([null]);

    // ...and learning it re-publishes on its own.
    setAuthToken('session-abc');
    await vi.waitFor(() => expect(auth[1]).toBe('Bearer session-abc'));

    expect(await publishPreKeyBundle(ORIGIN)).toBe(true);
  });

  it('publishes with the token when it is known before the keys are', async () => {
    const auth: Array<string | null> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/api/v1/keys') && init?.method === 'POST') {
        const header = (init.headers as Record<string, string>)?.Authorization ?? null;
        auth.push(header);
        return new Response('{}', { status: header ? 200 : 403 });
      }
      return new Response('{}', { status: 404 });
    }));

    setAuthToken('session-early');
    await initialize(DID, ORIGIN);
    expect(auth).toEqual(['Bearer session-early']);
  });

  it('persists the identity, so a second login reuses the same keys', async () => {
    await initialize(DID, ORIGIN);
    const first = getIdentityPublicKey();
    shutdown();

    await initialize(DID, ORIGIN);
    expect(getIdentityPublicKey()).toEqual(first);
  });

  it('encrypts a DM against a freshly generated identity', async () => {
    await initialize(DID, ORIGIN);

    // The peer's bundle is served from a second, independent identity.
    const peerIk = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as CryptoKeyPair;
    const peerSpk = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as CryptoKeyPair;
    const rawPub = async (k: CryptoKey) =>
      btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', k))));

    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/api/v1/keys/')) {
        return new Response(JSON.stringify({
          bundle: {
            identity_key: await rawPub(peerIk.publicKey),
            signed_pre_key: await rawPub(peerSpk.publicKey),
            spk_id: 1,
          },
        }), { status: 200 });
      }
      return new Response('{}', { status: 200 });
    }));

    const ct = await encryptMessage('did:plc:peer00000000000000000000', 'hello', ORIGIN);
    expect(ct).not.toBeNull();
    expect(isEncrypted(ct!)).toBe(true);
  });

  describe('two identities', () => {
    // Both sides live in the same module, so each takes a turn at the wheel:
    // its own IndexedDB persists its identity and sessions while the other
    // side is the initialized one.
    type Side = { did: string; idb: IDBFactory; bundle: any };
    const alice: Side = { did: 'did:plc:alice0000000000000000000', idb: null as any, bundle: null };
    const bob: Side = { did: 'did:plc:bob000000000000000000000', idb: null as any, bundle: null };

    /** Make `side` the live identity, with `peer`'s bundle served by the API. */
    async function takeTurn(side: Side, peer: Side): Promise<void> {
      shutdown();
      globalThis.indexedDB = side.idb;
      vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
        if (String(url).endsWith('/api/v1/keys') && init?.method === 'POST') {
          side.bundle = JSON.parse(String(init.body)).bundle;
          return new Response('{}', { status: 200 });
        }
        if (String(url).includes('/api/v1/keys/')) {
          return new Response(JSON.stringify({ bundle: peer.bundle }), { status: 200 });
        }
        return new Response('{}', { status: 404 });
      }));
      await initialize(side.did, ORIGIN);
    }

    beforeEach(async () => {
      alice.idb = new IDBFactory();
      bob.idb = new IDBFactory();
      // Publish both pre-key bundles before either side sends anything.
      await takeTurn(alice, bob);
      await takeTurn(bob, alice);
      expect(alice.bundle?.identity_key).toBeTruthy();
      expect(bob.bundle?.identity_key).toBeTruthy();
    });

    it('round-trips a DM', async () => {
      await takeTurn(alice, bob);
      const wire = await encryptMessage(bob.did, 'meet me at the usual place', ORIGIN);
      expect(wire).not.toBeNull();
      expect(isEncrypted(wire!)).toBe(true);
      expect(wire).not.toContain('usual place');

      await takeTurn(bob, alice);
      expect(await decryptMessage(alice.did, wire!, ORIGIN)).toBe('meet me at the usual place');
    });

    it('keeps decrypting across a DH ratchet step', async () => {
      // The sender re-keys every tenth message; the receiver has to follow.
      for (let i = 0; i < 13; i++) {
        await takeTurn(alice, bob);
        const wire = await encryptMessage(bob.did, `message ${i}`, ORIGIN);
        expect(wire).not.toBeNull();

        await takeTurn(bob, alice);
        expect(await decryptMessage(alice.did, wire!, ORIGIN)).toBe(`message ${i}`);
      }
    });

    it('a third party with its own keys cannot read the DM', async () => {
      await takeTurn(alice, bob);
      const wire = await encryptMessage(bob.did, 'for bob only', ORIGIN);

      const mallory: Side = { did: 'did:plc:mallory00000000000000000', idb: new IDBFactory(), bundle: null };
      await takeTurn(mallory, alice);
      expect(await decryptMessage(alice.did, wire!, ORIGIN)).toBeNull();
    });
  });
});
