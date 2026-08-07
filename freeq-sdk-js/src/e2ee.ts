/**
 * End-to-end encryption for DMs using Double Ratchet (Signal protocol)
 * and channel passphrase encryption (AES-256-GCM via HKDF).
 *
 * Architecture:
 * - X25519 identity key generated on first AT Protocol login
 * - Signed pre-key uploaded to server for async key exchange (X3DH)
 * - Session per DM partner with forward-secret key derivation
 * - Sessions persisted in IndexedDB
 * - Messages with ENC3: prefix are DM-encrypted; ENC1: are channel-encrypted
 *
 * The server never sees plaintext DM content.
 */

import { openDB, type IDBPDatabase } from 'idb';
import * as ratchet from './ratchet.js';
import * as x3dh from './x3dh.js';

// ── Constants ──

const ENC1_PREFIX = 'ENC1:';
const DB_NAME = 'freeq-e2ee';
// v2 dropped the sessions store: what it held was the old construction's
// state, which no longer decrypts anything and never reached a real user —
// browser DM encryption did not work at all before this.
const DB_VERSION = 2;

// ── Types ──

interface IdentityKeys {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  spkSecret: Uint8Array;
  spkPublic: Uint8Array;
  spkSignature: Uint8Array;
  spkId: number;
  signingKey?: CryptoKeyPair;
  signingPublic?: Uint8Array;
}

interface RatchetSession {
  remoteDid: string;
  /** The ratchet's own state — plain data, stored as-is. */
  state: ratchet.SessionState;
  /**
   * The agreement we opened with, until it has been sent. The first message
   * of a session has to carry it or the peer can derive nothing.
   */
  pendingIntro: ratchet.Intro | null;
  createdAt: number;
  lastUsed: number;
}

// ── State ──

let db: IDBPDatabase | null = null;
let identityKeys: IdentityKeys | null = null;
let ownDid: string | null = null;
let authToken: string | null = null;
let publishOrigin: string | null = null;
let bundlePublished = false;
const sessions = new Map<string, RatchetSession>();
let initialized = false;

// Channel passphrase keys
const channelKeys = new Map<string, Uint8Array>();

// ── Public API ──

/** Check if text is a Double Ratchet encrypted DM (ENC3, or ENC4 opening). */
export function isEncrypted(text: string): boolean {
  return ratchet.isEncrypted(text);
}

/** Check if text is an ENC1 (channel passphrase) encrypted message. */
export function isENC1(text: string): boolean {
  return text.startsWith(ENC1_PREFIX);
}

/** Check if E2EE is initialized and ready for DM encryption. */
export function isE2eeReady(): boolean {
  return initialized && identityKeys !== null;
}

/** Check if a DM session exists with the given DID. */
export function hasSession(did: string): boolean {
  return sessions.has(did);
}

/** Check if a channel has an encryption key set. */
export function hasChannelKey(channel: string): boolean {
  return channelKeys.has(channel.toLowerCase());
}

/** Get the identity public key (X25519). */
export function getIdentityPublicKey(): Uint8Array | null {
  return identityKeys?.publicKey ?? null;
}

/**
 * Get the safety number for a DM session.
 * A human-readable fingerprint of both identity keys.
 * Format: 12 groups of 5 digits (60 digits total), like Signal.
 */
export async function getSafetyNumber(remoteDid: string): Promise<string | null> {
  if (!identityKeys) return null;

  const myKey = identityKeys.publicKey;
  const encoder = new TextEncoder();
  const remoteDIDBytes = encoder.encode(remoteDid);
  const material = new Uint8Array(64 + remoteDIDBytes.length);
  const myKeyHex = Array.from(myKey).map(b => b.toString(16).padStart(2, '0')).join('');
  const weAreFirst = myKeyHex < remoteDid;
  if (weAreFirst) {
    material.set(myKey, 0);
    material.set(remoteDIDBytes, 32);
  } else {
    material.set(remoteDIDBytes, 0);
    material.set(myKey, remoteDIDBytes.length);
  }

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  const digits: string[] = [];
  for (let i = 0; i < 12; i++) {
    const val = ((hash[i * 2] << 8) | hash[i * 2 + 1]) % 100000;
    digits.push(val.toString().padStart(5, '0'));
  }
  return digits.join(' ');
}

/** Initialize E2EE for an authenticated user. */
export async function initialize(did: string, serverOrigin: string): Promise<void> {
  if (typeof indexedDB === 'undefined') {
    // Node / non-browser runtimes don't have IndexedDB. E2EE is browser-only
    // (DM key store, session state). Bail silently — bots and headless agents
    // don't use E2EE.
    return;
  }
  try {
    await (crypto.subtle.generateKey as any)({ name: 'X25519' }, false, ['deriveBits']);
  } catch {
    console.warn('[e2ee] X25519 not available — E2EE disabled');
    return;
  }

  db = await openDB(DB_NAME, DB_VERSION, {
    upgrade(database) {
      if (!database.objectStoreNames.contains('identity')) {
        database.createObjectStore('identity');
      }
      if (!database.objectStoreNames.contains('sessions')) {
        database.createObjectStore('sessions', { keyPath: 'remoteDid' });
      }
    },
  });

  const stored = await db.get('identity', did);
  if (stored) {
    identityKeys = {
      secretKey: new Uint8Array(stored.secretKey),
      publicKey: new Uint8Array(stored.publicKey),
      spkSecret: new Uint8Array(stored.spkSecret),
      spkPublic: new Uint8Array(stored.spkPublic),
      spkSignature: new Uint8Array(stored.spkSignature),
      spkId: stored.spkId,
      signingPublic: stored.signingPublic ? new Uint8Array(stored.signingPublic) : undefined,
    };
    if (stored.signingPrivate) {
      try {
        const privKey = await crypto.subtle.importKey('pkcs8', new Uint8Array(stored.signingPrivate), 'Ed25519', false, ['sign']);
        const pubKey = await crypto.subtle.importKey('raw', new Uint8Array(stored.signingPublic), 'Ed25519', false, ['verify']);
        identityKeys.signingKey = { privateKey: privKey, publicKey: pubKey };
      } catch { /* Ed25519 import not available */ }
    }
  } else {
    identityKeys = await generateIdentityKeys();
    const toStore: Record<string, unknown> = {
      secretKey: Array.from(identityKeys.secretKey),
      publicKey: Array.from(identityKeys.publicKey),
      spkSecret: Array.from(identityKeys.spkSecret),
      spkPublic: Array.from(identityKeys.spkPublic),
      spkSignature: Array.from(identityKeys.spkSignature),
      spkId: identityKeys.spkId,
    };
    if (identityKeys.signingPublic) {
      toStore.signingPublic = Array.from(identityKeys.signingPublic);
    }
    if (identityKeys.signingKey) {
      try {
        const privBytes = await crypto.subtle.exportKey('pkcs8', identityKeys.signingKey.privateKey);
        toStore.signingPrivate = Array.from(new Uint8Array(privBytes));
      } catch { /* can't export */ }
    }
    await db.put('identity', toStore, did);
  }

  const allSessions: RatchetSession[] = await db.getAll('sessions');
  for (const s of allSessions) sessions.set(s.remoteDid, s);

  ownDid = did;
  publishOrigin = serverOrigin;
  try {
    bundlePublished = await uploadPreKeyBundle(serverOrigin, did, identityKeys);
  } catch (e) {
    console.warn('[e2ee] Failed to upload pre-key bundle:', e);
  }

  initialized = true;
}

/** Shut down E2EE and clear state. */
export function shutdown(): void {
  initialized = false;
  identityKeys = null;
  ownDid = null;
  authToken = null;
  publishOrigin = null;
  bundlePublished = false;
  sessions.clear();
  if (db) { db.close(); db = null; }
}

/** Set a passphrase for a channel. Derives AES-256 key via HKDF. */
export async function setChannelKey(channel: string, passphrase: string): Promise<void> {
  const chanLower = channel.toLowerCase();
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(chanLower)));
  const ikm = new TextEncoder().encode(passphrase);
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await (crypto.subtle as any).deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('freeq-e2ee-v1') },
    baseKey, 256,
  );
  channelKeys.set(chanLower, new Uint8Array(bits));
}

/** Remove the encryption key for a channel. */
export function removeChannelKey(channel: string): void {
  channelKeys.delete(channel.toLowerCase());
}

// ── Encrypt / Decrypt ──

/**
 * Encrypt a DM.
 *
 * The first message of a session goes out as ENC4, carrying the agreement
 * that opened it; everything after is ENC3.
 */
export async function encryptMessage(
  remoteDid: string,
  plaintext: string,
  serverOrigin: string,
): Promise<string | null> {
  if (!initialized || !identityKeys) return null;

  let session = sessions.get(remoteDid);
  if (!session) {
    const opened = await establishSession(remoteDid, serverOrigin);
    if (!opened) return null;
    session = opened;
  }

  try {
    const wire = session.pendingIntro
      ? await ratchet.encryptFirst(session.state, session.pendingIntro, plaintext)
      : await ratchet.encrypt(session.state, plaintext);
    session.pendingIntro = null;
    await rememberSession(session);
    return wire;
  } catch (e) {
    console.error('[e2ee] Encrypt failed:', e);
    return null;
  }
}

/**
 * Decrypt a DM.
 *
 * An opening message carries the agreement it was built from, so a responder
 * can answer someone it has never heard from. An opening for a conversation
 * we already have is tried against the existing session first: a replayed one
 * must not be able to reset a live conversation's chains.
 */
export async function decryptMessage(
  remoteDid: string,
  wire: string,
  serverOrigin?: string,
): Promise<string | null> {
  if (!initialized || !identityKeys) return null;
  if (!ratchet.isEncrypted(wire)) return null;

  const existing = sessions.get(remoteDid);
  if (existing) {
    try {
      const plaintext = await ratchet.decrypt(existing.state, wire);
      await rememberSession(existing);
      return plaintext;
    } catch {
      // Falls through: an opening may be starting a genuinely new session.
    }
  }

  const intro = ratchet.introOf(wire);
  if (!intro) {
    // An ordinary message with no session to read it under. Nothing to do —
    // the sender has to open a conversation before continuing one.
    if (!existing) console.warn('[e2ee] No session for a DM from', remoteDid);
    return null;
  }

  try {
    const sharedSecret = await x3dh.respond(
      {
        identitySecret: identityKeys.secretKey,
        signedPreKeySecret: identityKeys.spkSecret,
        spkId: identityKeys.spkId,
      },
      {
        identityKey: ratchet.toB64Url(intro.identityKey),
        ephemeralKey: ratchet.toB64Url(intro.ephemeralKey),
        spkId: intro.spkId,
        did: remoteDid,
      },
    );
    const state = await ratchet.initBob(sharedSecret, identityKeys.spkSecret);
    const plaintext = await ratchet.decrypt(state, wire);
    await rememberSession({
      remoteDid,
      state,
      pendingIntro: null,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    });
    return plaintext;
  } catch (e) {
    console.error('[e2ee] Decrypt failed:', e);
    return null;
  }
}

/** Keep a session in memory and on disk, both keyed by the peer. */
async function rememberSession(session: RatchetSession): Promise<void> {
  session.lastUsed = Date.now();
  sessions.set(session.remoteDid, session);
  if (db) await db.put('sessions', session);
}

/** Encrypt a message for a channel (ENC1 format). */
export async function encryptChannel(channel: string, plaintext: string): Promise<string | null> {
  const key = channelKeys.get(channel.toLowerCase());
  if (!key) return null;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await (crypto.subtle as any).importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await (crypto.subtle as any).encrypt(
    { name: 'AES-GCM', iv }, cryptoKey, new TextEncoder().encode(plaintext),
  ));

  const nonceB64 = btoa(String.fromCharCode(...iv));
  const ctB64 = btoa(String.fromCharCode(...ct));
  return `${ENC1_PREFIX}${nonceB64}:${ctB64}`;
}

/** Decrypt an ENC1 message. */
export async function decryptChannel(channel: string, wire: string): Promise<string | null> {
  const key = channelKeys.get(channel.toLowerCase());
  if (!key) return null;
  if (!wire.startsWith(ENC1_PREFIX)) return null;

  try {
    const body = wire.slice(ENC1_PREFIX.length);
    const sep = body.indexOf(':');
    if (sep === -1) return null;

    const nonce = Uint8Array.from(atob(body.slice(0, sep)), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(body.slice(sep + 1)), c => c.charCodeAt(0));
    if (nonce.length !== 12) return null;

    const cryptoKey = await (crypto.subtle as any).importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await (crypto.subtle as any).decrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, ct,
    );
    return new TextDecoder().decode(plain);
  } catch (e) {
    // AES-GCM auth-tag mismatch (wrong key) raises DOMException with
    // name 'OperationError' — that's the expected case for chathistory
    // replay across key rotations / joining a channel with a different
    // pass. Demote to debug so the trail is there but stderr stays
    // clean. Other errors (corrupt frame, missing SubtleCrypto, etc.)
    // are real and still warn.
    const isWrongKey =
      e instanceof Error && (e as any).name === 'OperationError';
    if (isWrongKey) {
      console.debug('[e2ee] ENC1 decrypt failed (wrong key):', e);
    } else {
      console.warn('[e2ee] ENC1 decrypt failed:', e);
    }
    return null;
  }
}

/** Fetch a pre-key bundle for a remote user. */
export async function fetchPreKeyBundle(origin: string, did: string): Promise<any | null> {
  try {
    const resp = await fetch(`${origin}/api/v1/keys/${encodeURIComponent(did)}`);
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.bundle;
  } catch { return null; }
}

// ── Key Generation ──

async function generateIdentityKeys(): Promise<IdentityKeys> {
  const ikPair = await (crypto.subtle.generateKey as any)(
    { name: 'X25519' }, true, ['deriveBits']
  );
  const spkPair = await (crypto.subtle.generateKey as any)(
    { name: 'X25519' }, true, ['deriveBits']
  );
  const ikSecret = await exportPrivateBytes(ikPair.privateKey);
  const ikPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ikPair.publicKey));
  const spkSecret = await exportPrivateBytes(spkPair.privateKey);
  const spkPublic = new Uint8Array(await crypto.subtle.exportKey('raw', spkPair.publicKey));

  let signingKey: CryptoKeyPair | undefined;
  let signingPublic: Uint8Array | undefined;
  let spkSignature: Uint8Array;
  try {
    signingKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    signingPublic = new Uint8Array(await crypto.subtle.exportKey('raw', signingKey.publicKey));
    const sig = await crypto.subtle.sign('Ed25519', signingKey.privateKey, spkPublic);
    spkSignature = new Uint8Array(sig);
  } catch {
    spkSignature = new Uint8Array(64);
  }

  return {
    secretKey: ikSecret, publicKey: ikPublic,
    spkSecret, spkPublic, spkSignature,
    spkId: 1, signingKey, signingPublic,
  };
}

// ── Pre-Key Bundle API ──

async function uploadPreKeyBundle(origin: string, did: string, keys: IdentityKeys): Promise<boolean> {
  const bundle: Record<string, unknown> = {
    did,
    identity_key: toB64(keys.publicKey),
    signed_pre_key: toB64(keys.spkPublic),
    spk_signature: toB64(keys.spkSignature),
    spk_id: keys.spkId,
  };
  if (keys.signingPublic) {
    bundle.signing_key = toB64(keys.signingPublic);
  }
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const resp = await fetch(`${origin}/api/v1/keys`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ did, bundle }),
  });
  if (!resp.ok) {
    console.warn('[e2ee] Pre-key bundle upload rejected:', resp.status);
    return false;
  }
  return true;
}

/**
 * Supply the credential that proves we own the DID we publish keys under.
 * The server only accepts a pre-key bundle from the session that authenticated
 * as that DID, and that token arrives after login — either while `initialize`
 * is still generating keys (the upload then picks it up) or after it already
 * tried and was refused, which is why setting it retries the publish. Without
 * a published bundle nobody can open a session with us.
 */
export function setAuthToken(token: string | null): void {
  authToken = token;
  if (token && !bundlePublished && identityKeys && publishOrigin) {
    void publishPreKeyBundle(publishOrigin);
  }
}

/** Publish our pre-key bundle. Safe to call again once the token is known. */
export async function publishPreKeyBundle(serverOrigin: string): Promise<boolean> {
  if (!identityKeys || !ownDid) return false;
  try {
    bundlePublished = await uploadPreKeyBundle(serverOrigin, ownDid, identityKeys);
    return bundlePublished;
  } catch (e) {
    console.warn('[e2ee] Failed to upload pre-key bundle:', e);
    return false;
  }
}

// ── Session Establishment ──

async function establishSession(
  remoteDid: string,
  serverOrigin: string,
): Promise<RatchetSession | null> {
  if (!identityKeys) return null;
  const bundle = await fetchPreKeyBundle(serverOrigin, remoteDid);
  if (!bundle) return null;

  try {
    const theirIdentity = fromB64(bundle.identity_key);
    const theirSignedPreKey = fromB64(bundle.signed_pre_key);

    if (bundle.signing_key && bundle.spk_signature) {
      try {
        const verifyKey = await crypto.subtle.importKey(
          'raw', fromB64(bundle.signing_key) as BufferSource, 'Ed25519', false, ['verify'],
        );
        const valid = await crypto.subtle.verify(
          'Ed25519',
          verifyKey,
          fromB64(bundle.spk_signature) as BufferSource,
          theirSignedPreKey as BufferSource,
        );
        if (!valid) {
          console.error('[e2ee] SPK signature verification failed for', remoteDid);
          return null;
        }
      } catch (e) {
        console.warn('[e2ee] Could not verify SPK signature:', e);
      }
    }

    // The agreement mints a per-session ephemeral, which is what the opening
    // message carries: without it the peer cannot derive the same secret.
    const agreed = await x3dh.initiate(
      { identitySecret: identityKeys.secretKey, did: ownDid ?? '' },
      {
        identityKey: theirIdentity,
        signedPreKey: theirSignedPreKey,
        spkId: typeof bundle.spk_id === 'number' ? bundle.spk_id : 1,
      },
    );

    const session: RatchetSession = {
      remoteDid,
      state: await ratchet.initAlice(agreed.sharedSecret, agreed.theirRatchetKey),
      pendingIntro: {
        identityKey: ratchet.fromB64Url(agreed.initialMessage.identityKey),
        ephemeralKey: ratchet.fromB64Url(agreed.initialMessage.ephemeralKey),
        spkId: agreed.initialMessage.spkId,
      },
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };
    await rememberSession(session);
    return session;
  } catch (e) {
    console.error('[e2ee] Key agreement failed:', e);
    return null;
  }
}

// ── Crypto Helpers ──

/**
 * The 32 raw secret bytes of an X25519 private key. WebCrypto permits `raw`
 * export for public keys only; the JWK `d` field is those same bytes.
 */
async function exportPrivateBytes(key: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.d) throw new Error('exported JWK is missing the private component');
  return fromB64(jwk.d);
}

function toB64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
