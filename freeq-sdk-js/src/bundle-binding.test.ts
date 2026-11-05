/**
 * Binding a pre-key bundle to its DID. A did:key bundle must be signed by the
 * DID's own key. Any other DID's bundle must be signed by a device key the
 * account published as an `at.freeq.deviceKey` record in its own repository,
 * read from its PDS with a repository proof, so the freeq host that serves the
 * bundle has no say in whether it is accepted.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { PdsDeviceKeys, verifyBundleBinding, type DeviceKeySource } from './bundle-binding.js';
import { generateDidKey, importDidKeyPair, type DidKey } from './did-key.js';
import { buildDeviceRecord, buildDeviceRetirement, type DidDocument } from './identity-records.js';
import { recordKeyOf } from './device-key.js';
import { deriveKid } from './signing.js';

const ALICE = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const PDS = 'https://pds.example';
const HOST = 'https://freeq.example';
const HOUR = 3_600_000;
const T0 = new Date(Date.now() - 48 * HOUR).toISOString();

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64url(bytes: Uint8Array): string {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** An Ed25519 pair, like a browser device key. */
async function pair(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
}

async function rawOf(p: CryptoKeyPair): Promise<Uint8Array> {
  return new Uint8Array(await webcrypto.subtle.exportKey('raw', p.publicKey));
}

/** A pre-key bundle whose signed pre-key `signer` signs. */
async function bundleSignedBy(signer: CryptoKeyPair) {
  const spk = webcrypto.getRandomValues(new Uint8Array(32));
  const sig = new Uint8Array(await webcrypto.subtle.sign('Ed25519', signer.privateKey, spk));
  return {
    identity_key: b64(webcrypto.getRandomValues(new Uint8Array(32))),
    signed_pre_key: b64(spk),
    spk_signature: b64(sig),
    signing_key: b64(await rawOf(signer)),
  };
}

let alice: DidDocument;

beforeAll(async () => {
  const { stubRepo } = await import('../test/repo-proofs.js');
  alice = await (await stubRepo(ALICE)).document(PDS);
});

/**
 * A network: ALICE's PDS (her repository, with proofs) and a freeq host that
 * vouches for every key it is asked about and serves its own copy of her
 * records holding `hostRecords`. Counts what each was asked.
 */
async function network(records: unknown[], hostRecords: unknown[] = []) {
  const { stubRepo } = await import('../test/repo-proofs.js');
  const own = await stubRepo(ALICE);
  const doc = await own.document(PDS);
  for (const r of records) await own.add('at.freeq.deviceKey', r);
  const hits = { pds: 0, host: 0 };
  const fetch = vi.fn(async (input: string): Promise<Response> => {
    const url = new URL(input);
    if (url.origin === PDS) {
      hits.pds++;
      return (await own.respond(url)) ?? new Response('unexpected', { status: 500 });
    }
    if (url.origin === HOST) {
      hits.host++;
      return Response.json({ records: hostRecords, keys: [] });
    }
    return new Response('unexpected', { status: 500 });
  });
  const resolveDid = async (did: string) => {
    if (did !== ALICE) throw new Error(`unknown DID ${did}`);
    return doc;
  };
  return { fetch, hits, repo: own, reader: { fetch, resolveDid } };
}

/** A device record for `p`, made `createdAt`. */
async function deviceRecordFor(p: CryptoKeyPair, createdAt = T0, expiresAt?: string) {
  return buildDeviceRecord(await recordKeyOf(p), ALICE, createdAt, 'Chrome', expiresAt);
}

describe('verifyBundleBinding, did:plc', () => {
  it('accepts a bundle signed by a device key published in the DID’s PDS', async () => {
    const device = await pair();
    const net = await network([await deviceRecordFor(device)]);
    const keys = new PdsDeviceKeys(net.reader);
    expect(await verifyBundleBinding(ALICE, await bundleSignedBy(device), { deviceKeys: keys })).toEqual({ ok: true });
    expect(net.hits.host, 'the freeq host is never asked').toBe(0);
  });

  it('refuses a bundle the host substituted, signed by a key of its own', async () => {
    const device = await pair();
    const net = await network([await deviceRecordFor(device)]);
    const keys = new PdsDeviceKeys(net.reader);
    const forged = await bundleSignedBy(await pair());
    const r = await verifyBundleBinding(ALICE, forged, { deviceKeys: keys });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/not a device key published in/);
  });

  it('refuses a substituted signed pre-key under the real device key', async () => {
    const device = await pair();
    const net = await network([await deviceRecordFor(device)]);
    const keys = new PdsDeviceKeys(net.reader);
    const genuine = await bundleSignedBy(device);
    const swapped = { ...genuine, signed_pre_key: b64(webcrypto.getRandomValues(new Uint8Array(32))) };
    const r = await verifyBundleBinding(ALICE, swapped, { deviceKeys: keys });
    expect(r).toEqual({ ok: false, reason: 'spk_signature does not verify under the bundle’s signing_key' });
  });

  it('refuses a key only the freeq host vouches for, and never asks it', async () => {
    const device = await pair();
    // The host's copy of her records holds the key; her PDS does not.
    const net = await network([], [await deviceRecordFor(device)]);
    const keys = new PdsDeviceKeys(net.reader);
    const r = await verifyBundleBinding(ALICE, await bundleSignedBy(device), { deviceKeys: keys });
    expect(r.ok).toBe(false);
    expect(net.hits.host).toBe(0);
  });

  it('refuses a key a lookup found only at the origin server', async () => {
    const device = await pair();
    const raw = await rawOf(device);
    const vouched: DeviceKeySource = {
      keyFor: async () => ({ publicKey: raw, source: 'OriginServer', retiredAt: null, expiresAt: null }),
    };
    const r = await verifyBundleBinding(ALICE, await bundleSignedBy(device), { deviceKeys: vouched });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/OriginServer/);
  });

  it('refuses a device key the account retired', async () => {
    const device = await pair();
    const record = await deviceRecordFor(device);
    const retirement = await buildDeviceRetirement(
      await recordKeyOf(device),
      ALICE,
      await deriveKid(await rawOf(device)),
      new Date(Date.now() - HOUR).toISOString(),
    );
    const net = await network([record, retirement]);
    const r = await verifyBundleBinding(ALICE, await bundleSignedBy(device), { deviceKeys: new PdsDeviceKeys(net.reader) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/retired/);
  });

  it('refuses a device key past its expiry', async () => {
    const device = await pair();
    const expired = await deviceRecordFor(device, T0, new Date(Date.now() - HOUR).toISOString());
    const net = await network([expired]);
    const r = await verifyBundleBinding(ALICE, await bundleSignedBy(device), { deviceKeys: new PdsDeviceKeys(net.reader) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/retired or let expire/);
  });

  it('refuses a bundle with no signing_key, and one with no reader to check it', async () => {
    const device = await pair();
    const { signing_key: _s, ...bare } = await bundleSignedBy(device);
    void _s;
    const net = await network([await deviceRecordFor(device)]);
    const r1 = await verifyBundleBinding(ALICE, bare, { deviceKeys: new PdsDeviceKeys(net.reader) });
    expect(r1.ok).toBe(false);
    const r2 = await verifyBundleBinding(ALICE, await bundleSignedBy(device));
    expect(r2.ok).toBe(false);
  });

  it('marks a key not yet published as worth another try, and accepts it once it is', async () => {
    const device = await pair();
    const net = await network([]);
    let now = Date.now();
    const keys = new PdsDeviceKeys(net.reader, { relistAfterMs: 10_000, now: () => now });
    const bundle = await bundleSignedBy(device);
    const first = await verifyBundleBinding(ALICE, bundle, { deviceKeys: keys });
    expect(first).toMatchObject({ ok: false, retry: true });

    await net.repo.add('at.freeq.deviceKey', await deviceRecordFor(device));
    // Inside the relist window the held listing answers.
    const listed = net.hits.pds;
    expect((await verifyBundleBinding(ALICE, bundle, { deviceKeys: keys })).ok).toBe(false);
    expect(net.hits.pds).toBe(listed);
    now += 10_001;
    expect(await verifyBundleBinding(ALICE, bundle, { deviceKeys: keys })).toEqual({ ok: true });
  });

  it('marks a PDS that cannot be read as worth another try', async () => {
    const keys = new PdsDeviceKeys({
      fetch: async () => new Response('down', { status: 503 }),
      resolveDid: async () => alice,
    });
    const r = await verifyBundleBinding(ALICE, await bundleSignedBy(await pair()), { deviceKeys: keys });
    expect(r).toMatchObject({ ok: false, retry: true });
  });

  it('lists an account once for many bundles inside the ttl', async () => {
    const device = await pair();
    const net = await network([await deviceRecordFor(device)]);
    const keys = new PdsDeviceKeys(net.reader);
    const bundle = await bundleSignedBy(device);
    await Promise.all([1, 2, 3].map(() => verifyBundleBinding(ALICE, bundle, { deviceKeys: keys })));
    const listings = net.fetch.mock.calls.filter(([u]) => String(u).includes('listRecords')).length;
    expect(listings).toBe(1);
  });
});

describe('verifyBundleBinding, did:key (unchanged)', () => {
  let key: DidKey;
  let keyPair: CryptoKeyPair;

  beforeAll(async () => {
    key = await generateDidKey();
    keyPair = await importDidKeyPair(await key.exportSeed());
  });

  it('accepts a bundle signed by the did:key, with no device key reader', async () => {
    expect(await verifyBundleBinding(key.did, await bundleSignedBy(keyPair))).toEqual({ ok: true });
  });

  it('refuses a bundle signed by another key', async () => {
    const r = await verifyBundleBinding(key.did, await bundleSignedBy(await pair()));
    expect(r).toEqual({ ok: false, reason: 'bundle signing_key is not the did:key\'s key' });
  });

  it('never consults the device key reader', async () => {
    const keyFor = vi.fn();
    await verifyBundleBinding(key.did, await bundleSignedBy(keyPair), { deviceKeys: { keyFor } });
    expect(keyFor).not.toHaveBeenCalled();
  });

  it('accepts base64url fields too', async () => {
    const b = await bundleSignedBy(keyPair);
    const toUrl = (s: string) => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(
      await verifyBundleBinding(key.did, { ...b, spk_signature: toUrl(b.spk_signature), signing_key: toUrl(b.signing_key) }),
    ).toEqual({ ok: true });
    void b64url;
  });
});
