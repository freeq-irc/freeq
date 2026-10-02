/**
 * VC-bootstrapped end-to-end group encryption for channels (EG1 / EGK1).
 *
 * The web/TS counterpart of `freeq-sdk::e2ee_group` (Rust). Wire formats and
 * key derivation are byte-identical, so a Rust steward bot can seal a group key
 * that a browser member opens, and vice versa (both use RFC 7748 X25519,
 * HKDF-SHA256, and AES-256-GCM).
 *
 * Model (see docs/VC-BOOTSTRAPPED-CHANNEL-E2EE.md):
 *  - A channel has a RANDOM 32-byte group secret at a given epoch — NOT derived
 *    from any public value (that was the broken ENC2 mistake).
 *  - A steward seals the secret to each member's X25519 public key. The server
 *    stores/relays the sealed `EGK1:` blob but can never open it.
 *  - Channel traffic is `EG1:<epoch>:<nonce>:<ct>` AES-256-GCM ciphertext.
 *  - On membership change the steward rotates the epoch and re-seals to the
 *    remaining members only — the departed member cannot read new epochs.
 */

import type { ChannelCipher } from './channel-cipher.js';

const EG1_PREFIX = 'EG1:';
const EGK1_PREFIX = 'EGK1:';

// WebCrypto's lib.dom types reject `Uint8Array<ArrayBufferLike>` where a strict
// `BufferSource` is expected (SharedArrayBuffer strictness). The rest of this
// SDK works around it with an `any` view of SubtleCrypto; mirror that here.
const subtle: any = crypto.subtle;

// ── Types ──

export interface GroupState {
  channel: string;
  epoch: number;
  /** Random 32-byte group secret. Never leaves a member's device unsealed. */
  secret: Uint8Array;
}

export interface SealedGroupKey {
  channel: string;
  epoch: number;
  ephemeralPub: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * A member's X25519 secret for opening sealed keys. WebCrypto cannot import an
 * X25519 private key from raw bytes, so pass EITHER the private `CryptoKey`
 * (the natural browser path — generate the keypair and keep it) OR the raw
 * `{ secret, publicKey }` scalar pair (for interop with keys minted elsewhere,
 * e.g. a Rust member — imported via JWK, which needs both halves).
 */
export type X25519Secret = CryptoKey | { secret: Uint8Array; publicKey: Uint8Array };

// ── Steward: group lifecycle ──

/** Create a fresh group at epoch 1 with a random secret. */
export function createGroup(channel: string): GroupState {
  return {
    channel: channel.toLowerCase(),
    epoch: 1,
    secret: crypto.getRandomValues(new Uint8Array(32)),
  };
}

/** Mint the next epoch with a new random secret (call on membership change). */
export function rotate(state: GroupState): GroupState {
  return {
    channel: state.channel,
    epoch: state.epoch + 1,
    secret: crypto.getRandomValues(new Uint8Array(32)),
  };
}

// ── Channel message encrypt / decrypt (EG1) ──

/** Encrypt a channel message → `EG1:<epoch>:<nonce>:<ct>`. */
export async function encryptGroup(state: GroupState, plaintext: string): Promise<string> {
  const key = await messageKey(state);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, new TextEncoder().encode(plaintext)));
  return `${EG1_PREFIX}${state.epoch}:${b64(iv)}:${b64(ct)}`;
}

/** Decrypt an `EG1:` message. Returns null on wrong epoch/key/tamper. */
export async function decryptGroup(state: GroupState, wire: string): Promise<string | null> {
  if (!wire.startsWith(EG1_PREFIX)) return null;
  const parts = wire.slice(EG1_PREFIX.length).split(':');
  if (parts.length !== 3) return null;
  const epoch = Number(parts[0]);
  if (!Number.isInteger(epoch) || epoch !== state.epoch) return null;
  try {
    const iv = unb64(parts[1]);
    const ct = unb64(parts[2]);
    if (iv.length !== 12) return null;
    const key = await messageKey(state);
    const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

/** True if `text` is an EG1 channel message. */
export function isGroupEncrypted(text: string): boolean {
  return text.startsWith(EG1_PREFIX);
}

/** Read the epoch off an EG1 message without decrypting. */
export function parseEpoch(wire: string): number | null {
  if (!wire.startsWith(EG1_PREFIX)) return null;
  const n = Number(wire.slice(EG1_PREFIX.length).split(':')[0]);
  return Number.isInteger(n) ? n : null;
}

// ── Key wrap: seal to a member, open with your secret (EGK1) ──

/**
 * Steward: seal this epoch's secret to a member's raw 32-byte X25519 public key.
 * Ephemeral-static ECIES — a fresh ephemeral key per seal.
 */
export async function sealFor(state: GroupState, memberPub: Uint8Array): Promise<SealedGroupKey> {
  const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as CryptoKeyPair;
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const shared = await x25519(eph.privateKey, memberPub);
  const wrapKey = await deriveWrapKey(shared, state.channel, state.epoch);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await subtle.importKey('raw', wrapKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, state.secret));
  return { channel: state.channel, epoch: state.epoch, ephemeralPub: ephPub, nonce: iv, ciphertext: ct };
}

/**
 * Member: recover the group state from a sealed key using your raw 32-byte
 * X25519 secret. This is the only way to obtain the secret; the server cannot.
 */
export async function openSealed(sealed: SealedGroupKey, mySecret: X25519Secret): Promise<GroupState | null> {
  try {
    const myKey = await toPrivateKey(mySecret);
    const shared = await x25519(myKey, sealed.ephemeralPub);
    const wrapKey = await deriveWrapKey(shared, sealed.channel, sealed.epoch);
    const cryptoKey = await subtle.importKey('raw', wrapKey, { name: 'AES-GCM' }, false, ['decrypt']);
    const secret = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: sealed.nonce }, cryptoKey, sealed.ciphertext));
    if (secret.length !== 32) return null;
    return { channel: sealed.channel, epoch: sealed.epoch, secret };
  } catch {
    return null;
  }
}

/** Serialize to `EGK1:<channel>:<epoch>:<eph-pub>:<nonce>:<ct>`. */
export function sealedToWire(s: SealedGroupKey): string {
  return `${EGK1_PREFIX}${s.channel}:${s.epoch}:${b64(s.ephemeralPub)}:${b64(s.nonce)}:${b64(s.ciphertext)}`;
}

/** Parse an `EGK1:` control message. */
export function sealedFromWire(wire: string): SealedGroupKey | null {
  if (!wire.startsWith(EGK1_PREFIX)) return null;
  const body = wire.slice(EGK1_PREFIX.length);
  // channel : epoch : ephPub : nonce : ct  — channel has no ':' for IRC names.
  const idx: number[] = [];
  for (let i = 0, found = 0; i < body.length && found < 4; i++) {
    if (body[i] === ':') { idx.push(i); found++; }
  }
  if (idx.length !== 4) return null;
  const channel = body.slice(0, idx[0]);
  const epoch = Number(body.slice(idx[0] + 1, idx[1]));
  if (!Number.isInteger(epoch)) return null;
  try {
    return {
      channel,
      epoch,
      ephemeralPub: unb64(body.slice(idx[1] + 1, idx[2])),
      nonce: unb64(body.slice(idx[2] + 1, idx[3])),
      ciphertext: unb64(body.slice(idx[3] + 1)),
    };
  } catch {
    return null;
  }
}

// ── Convenience ──

/** Steward: seal to many members → `[member_did, EGK1-wire]` for the POST body. */
export async function sealBatch(state: GroupState, members: Array<[string, Uint8Array]>): Promise<Array<[string, string]>> {
  const out: Array<[string, string]> = [];
  for (const [did, pub] of members) out.push([did, sealedToWire(await sealFor(state, pub))]);
  return out;
}

/**
 * Member: from the sealed keys the server returned (each `[epoch, EGK1-wire]`),
 * recover the newest epoch we can open. Older epochs stay openable for history.
 */
export async function openBest(candidates: Array<[number, string]>, mySecret: X25519Secret): Promise<GroupState | null> {
  const sorted = [...candidates].sort((a, b) => b[0] - a[0]);
  for (const [, wire] of sorted) {
    const sealed = sealedFromWire(wire);
    if (!sealed) continue;
    const state = await openSealed(sealed, mySecret);
    if (state) return state;
  }
  return null;
}

// ── ChannelCipher adapter ──

/**
 * Wrap a set of group states (one per epoch we hold) as a `ChannelCipher` for
 * `FreeqClient.setChannelCipher`. `states` is a getter so the cipher always
 * sees the latest keys — install once, keep loading epochs.
 *
 * - encrypt: with the highest epoch held; `null` when none.
 * - decrypt: by the epoch named in the wire (`parseEpoch`); `null` when we
 *   do not hold it or the ciphertext does not open.
 * - isCiphertext: `isGroupEncrypted` (an `EG1:` body).
 */
export function makeGroupCipher(states: () => GroupState[]): ChannelCipher {
  const byEpoch = (): Map<number, GroupState> => {
    const m = new Map<number, GroupState>();
    for (const s of states()) m.set(s.epoch, s);
    return m;
  };
  return {
    async encrypt(plaintext: string): Promise<string | null> {
      let best: GroupState | null = null;
      for (const s of states()) if (!best || s.epoch > best.epoch) best = s;
      if (!best) return null;
      return encryptGroup(best, plaintext);
    },
    async decrypt(wire: string): Promise<string | null> {
      const epoch = parseEpoch(wire);
      if (epoch === null) return null;
      const state = byEpoch().get(epoch);
      if (!state) return null;
      return decryptGroup(state, wire);
    },
    isCiphertext(wire: string): boolean {
      return isGroupEncrypted(wire);
    },
  };
}

// ── Crypto helpers (mirror freeq-sdk-js/src/e2ee.ts) ──

async function messageKey(state: GroupState): Promise<Uint8Array> {
  const salt = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(state.channel)));
  return hkdf(state.secret, salt, `freeq-group-msg-v1-${state.epoch}`);
}

async function deriveWrapKey(shared: Uint8Array, channel: string, epoch: number): Promise<Uint8Array> {
  const salt = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(channel.toLowerCase())));
  return hkdf(shared, salt, `freeq-group-keywrap-v1-${epoch}`);
}

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
    base, 256,
  );
  return new Uint8Array(bits);
}

/** Coerce a member secret into an importable X25519 private CryptoKey. */
async function toPrivateKey(sk: X25519Secret): Promise<CryptoKey> {
  if (sk instanceof CryptoKey) return sk;
  // Raw scalar pair → JWK (WebCrypto requires both d and x for OKP private keys).
  return subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'X25519', d: b64(sk.secret), x: b64(sk.publicKey) },
    { name: 'X25519' },
    false,
    ['deriveBits'],
  );
}

async function x25519(mySecret: CryptoKey, theirPublic: Uint8Array): Promise<Uint8Array> {
  const theirKey = await subtle.importKey('raw', theirPublic, { name: 'X25519' }, false, []);
  const bits = await subtle.deriveBits({ name: 'X25519', public: theirKey }, mySecret, 256);
  return new Uint8Array(bits);
}

function b64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
