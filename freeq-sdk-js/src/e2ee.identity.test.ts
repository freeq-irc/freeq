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

describe('e2ee identity for a browser did:key', () => {
  // A did:key is checkable: a room member seals the room key only to a bundle
  // signed by the DID's own key. A browser guest that minted a did:key must
  // therefore publish a bundle signed with that key, not with the random
  // signing key the e2ee module would otherwise generate.
  let bundles: Array<Record<string, any>>;

  beforeEach(() => {
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

  async function boundTo(did: string, bundle: Record<string, any>): Promise<boolean> {
    const { decodeMultibaseEd25519, verifyEd25519 } = await import('./index');
    const didPub = decodeMultibaseEd25519(did.slice('did:key:'.length));
    // Bundle fields are base64url, unpadded.
    const unb64 = (s: string) => {
      const std = s.replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(std + '='.repeat((4 - (std.length % 4)) % 4)), (c) => c.charCodeAt(0));
    };
    const signing = unb64(bundle.signing_key);
    if (signing.length !== didPub.length || signing.some((b, i) => b !== didPub[i])) return false;
    return verifyEd25519(didPub, unb64(bundle.signed_pre_key), bundle.spk_signature);
  }

  it('signs its pre-key bundle with the did:key itself', async () => {
    const { generateDidKey, importDidKeyPair } = await import('./index');
    const key = await generateDidKey();
    const pair = await importDidKeyPair(await key.exportSeed());
    await initialize(key.did, ORIGIN, { signingKey: pair });
    expect(bundles).toHaveLength(1);
    expect(await boundTo(key.did, bundles[0].bundle)).toBe(true);
  });

  it('stays bound on a later visit, when the identity is already stored', async () => {
    const { generateDidKey, importDidKeyPair } = await import('./index');
    const key = await generateDidKey();
    const pair = await importDidKeyPair(await key.exportSeed());
    await initialize(key.did, ORIGIN, { signingKey: pair });
    shutdown();
    await initialize(key.did, ORIGIN, { signingKey: pair });
    expect(bundles).toHaveLength(2);
    expect(await boundTo(key.did, bundles[1].bundle)).toBe(true);
    expect(bundles[1].bundle.signed_pre_key).toBe(bundles[0].bundle.signed_pre_key);
  });
});

describe('e2ee bundle signed by a signed-in account’s device key', () => {
  // A did:plc account's bundle can be bound to the DID only through a device
  // key the account published in its own PDS. The client learns that key
  // after e2ee has started (the device key is loaded once SASL succeeds), so
  // the bundle is signed again with it and published again.
  let bundles: Array<Record<string, any>>;

  beforeEach(() => {
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

  async function signedBy(bundle: Record<string, any>, device: CryptoKeyPair): Promise<boolean> {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', device.publicKey));
    const unb64 = (s: string) => {
      const std = s.replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(std + '='.repeat((4 - (std.length % 4)) % 4)), (c) => c.charCodeAt(0));
    };
    const signing = unb64(bundle.signing_key);
    if (signing.length !== raw.length || signing.some((b, i) => b !== raw[i])) return false;
    return crypto.subtle.verify('Ed25519', device.publicKey, unb64(bundle.spk_signature), unb64(bundle.signed_pre_key));
  }

  it('re-signs and republishes the bundle when the device key arrives after initialize', async () => {
    const { useBundleSigningKey } = await import('./e2ee');
    const device = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
    await initialize(DID, ORIGIN);
    expect(await signedBy(bundles[0].bundle, device)).toBe(false);
    await useBundleSigningKey(DID, device);
    expect(bundles).toHaveLength(2);
    expect(await signedBy(bundles[1].bundle, device)).toBe(true);
    expect(bundles[1].bundle.signed_pre_key).toBe(bundles[0].bundle.signed_pre_key);
  });

  it('signs the first bundle with a device key supplied before initialize', async () => {
    const { useBundleSigningKey } = await import('./e2ee');
    const device = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
    await useBundleSigningKey(DID, device);
    expect(bundles).toHaveLength(0);
    await initialize(DID, ORIGIN);
    expect(bundles).toHaveLength(1);
    expect(await signedBy(bundles[0].bundle, device)).toBe(true);
  });

  it('ignores a device key for another DID', async () => {
    const { useBundleSigningKey } = await import('./e2ee');
    const device = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
    await useBundleSigningKey('did:plc:someoneelse0000000000000', device);
    await initialize(DID, ORIGIN);
    expect(await signedBy(bundles[0].bundle, device)).toBe(false);
  });

  it('prefers the identity’s own key (a did:key guest) over a device key', async () => {
    const { generateDidKey, importDidKeyPair, useBundleSigningKey } = { ...(await import('./index')), ...(await import('./e2ee')) };
    const key = await generateDidKey();
    const own = await importDidKeyPair(await key.exportSeed());
    const device = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
    await useBundleSigningKey(key.did, device);
    await initialize(key.did, ORIGIN, { signingKey: own });
    expect(await signedBy(bundles[0].bundle, own)).toBe(true);
  });
});
