/**
 * X3DH key agreement for encrypted DMs, in TypeScript.
 *
 * This is the JS half of `freeq_sdk::x3dh` (Rust), pinned to the shared
 * vectors in `spec/e2ee-dm-vectors.json`. Both sides must reach the same
 * secret from the same keys or nothing above them can work.
 *
 *   SK = HKDF-SHA256(
 *          salt = 0xFF * 32,
 *          ikm  = DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B),
 *          info = "freeq-x3dh-v1")
 *
 * `EK_A` is a per-session ephemeral the initiator mints. It is what gives a
 * conversation forward secrecy from its first message, and it is also why the
 * responder cannot get there alone: it needs `IK_A`, `EK_A` and the pre-key id
 * — the initial message — before it can derive anything.
 */

import { fromB64Url, generateSecret, toB64Url, x25519PublicKey } from './ratchet.js';

/** Our own long-term encryption identity. */
export interface OwnIdentity {
  /** X25519 identity secret. */
  identitySecret: Uint8Array;
  /** Our DID, so the peer can resolve who opened the conversation. */
  did: string;
}

/** Our identity plus the pre-key a peer will have fetched. */
export interface ResponderKeys {
  identitySecret: Uint8Array;
  signedPreKeySecret: Uint8Array;
  spkId: number;
}

/** The public half a peer publishes for others to open a session with. */
export interface PreKeyBundle {
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
  spkId: number;
}

/**
 * What the initiator must send the responder for it to reach the same secret.
 * Public values only — it names the ephemeral, it does not carry it.
 */
export interface InitialMessage {
  identityKey: string;
  ephemeralKey: string;
  spkId: number;
  did: string;
}

export interface InitiatorResult {
  sharedSecret: Uint8Array;
  /** The peer's signed pre-key: the initiator's first ratchet target. */
  theirRatchetKey: Uint8Array;
  initialMessage: InitialMessage;
}

/** A DH output of all zeroes means the peer's key was not a real point. */
function rejectSmallSubgroup(dh: Uint8Array): Uint8Array {
  if (dh.every((b) => b === 0)) {
    throw new Error('DH produced a zero shared secret (possible small subgroup attack)');
  }
  return dh;
}

async function dh(secret: Uint8Array, theirPublic: Uint8Array): Promise<Uint8Array> {
  const mine = await importSecret(secret);
  const theirs = await crypto.subtle.importKey(
    'raw',
    theirPublic as BufferSource,
    { name: 'X25519' },
    false,
    [],
  );
  return rejectSmallSubgroup(
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'X25519', public: theirs } as AlgorithmIdentifier,
        mine,
        256,
      ),
    ),
  );
}

const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

async function importSecret(secret: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + secret.length);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(secret, X25519_PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'X25519' }, false, [
    'deriveBits',
  ]);
}

/** HKDF over the three DH outputs, exactly as the Rust side derives it. */
async function kdf(ikm: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32).fill(0xff),
        info: new TextEncoder().encode('freeq-x3dh-v1'),
      },
      key,
      256,
    ),
  );
}

/**
 * Open a session with a peer's published bundle.
 *
 * `ephemeralSecret` is for reproducing published vectors only. A real session
 * mints a fresh one — an ephemeral reused across sessions is not ephemeral,
 * and reusing one costs exactly the forward secrecy it exists to buy.
 */
export async function initiate(
  ours: OwnIdentity,
  theirBundle: PreKeyBundle,
  ephemeralSecret?: Uint8Array,
): Promise<InitiatorResult> {
  const ek = ephemeralSecret ?? (await generateSecret());

  const dh1 = await dh(ours.identitySecret, theirBundle.signedPreKey);
  const dh2 = await dh(ek, theirBundle.identityKey);
  const dh3 = await dh(ek, theirBundle.signedPreKey);

  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);

  return {
    sharedSecret: await kdf(ikm),
    theirRatchetKey: theirBundle.signedPreKey,
    initialMessage: {
      identityKey: toB64Url(await x25519PublicKey(ours.identitySecret)),
      ephemeralKey: toB64Url(await x25519PublicKey(ek)),
      spkId: theirBundle.spkId,
      did: ours.did,
    },
  };
}

/**
 * Complete the agreement from the initiator's initial message. Returns the
 * shared secret; the responder's ratchet key is its own pre-key secret.
 */
export async function respond(
  ours: ResponderKeys,
  initial: InitialMessage,
): Promise<Uint8Array> {
  const theirIdentity = fromB64Url(initial.identityKey);
  const theirEphemeral = fromB64Url(initial.ephemeralKey);
  if (theirIdentity.length !== 32 || theirEphemeral.length !== 32) {
    throw new Error('invalid initial message');
  }
  if (initial.spkId !== ours.spkId) {
    throw new Error('pre-key id mismatch: the initial message names a pre-key we do not hold');
  }

  // The same three agreements, from the other side.
  const dh1 = await dh(ours.signedPreKeySecret, theirIdentity);
  const dh2 = await dh(ours.identitySecret, theirEphemeral);
  const dh3 = await dh(ours.signedPreKeySecret, theirEphemeral);

  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);

  return kdf(ikm);
}
