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

// ── Constants ──

const ENC3_PREFIX = 'ENC3:';
const ENC1_PREFIX = 'ENC1:';
const DB_NAME = 'freeq-e2ee';
const DB_VERSION = 1;

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

interface SessionState {
  sharedSecret: number[];
  sendChainKey: number[];
  recvChainKey: number[];
  sendMsgNum: number;
  recvMsgNum: number;
  prevChainLen: number;
  dhSendSecret?: number[];
  dhSendPublic?: number[];
  dhRecvPublic?: number[];
  rootKey?: number[];
  dhRatchetInitialized?: boolean;
}

interface RatchetSession {
  remoteDid: string;
  state: string;
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

/** Check if text is an ENC3 (DM Double Ratchet) encrypted message. */
export function isEncrypted(text: string): boolean {
  return text.startsWith(ENC3_PREFIX);
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

/** Encrypt a DM using the Double Ratchet. */
export async function encryptMessage(
  remoteDid: string,
  plaintext: string,
  serverOrigin: string,
): Promise<string | null> {
  if (!initialized || !identityKeys) return null;

  let session = sessions.get(remoteDid);
  if (!session) {
    const newSession = await establishSession(remoteDid, serverOrigin);
    if (!newSession) return null;
    session = newSession;
  }

  try {
    const st: SessionState = JSON.parse(session.state);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    if (st.dhRatchetInitialized && st.dhRecvPublic && st.sendMsgNum > 0 && st.sendMsgNum % 10 === 0) {
      try {
        const dhPair = await (crypto.subtle.generateKey as any)({ name: 'X25519' }, true, ['deriveBits']);
        const newSecret = await exportPrivateBytes(dhPair.privateKey);
        const newPublic = new Uint8Array(await crypto.subtle.exportKey('raw', dhPair.publicKey));
        const dhOutput = await x25519DH(newSecret, new Uint8Array(st.dhRecvPublic));
        const newRoot = await hkdfDerive(dhOutput, 'freeq-ratchet-root');
        const newChain = await hkdfDerive(newRoot, 'freeq-ratchet-chain');
        st.prevChainLen = st.sendMsgNum;
        st.sendMsgNum = 0;
        st.dhSendSecret = Array.from(newSecret);
        st.dhSendPublic = Array.from(newPublic);
        st.rootKey = Array.from(newRoot);
        st.sendChainKey = Array.from(newChain);
      } catch (e) {
        console.warn('[e2ee] DH ratchet step failed, continuing with chain key:', e);
      }
    }

    // Derived after any ratchet step, so it matches the chain the header
    // announces — the receiver re-keys off that header before decrypting.
    const msgKey = await deriveMessageKey(st.sendChainKey, st.sendMsgNum);

    const dhPub = st.dhSendPublic ? new Uint8Array(st.dhSendPublic) : identityKeys.publicKey;
    const header = new Uint8Array(40);
    header.set(dhPub, 0);
    new DataView(header.buffer).setUint32(32, st.prevChainLen, false);
    new DataView(header.buffer).setUint32(36, st.sendMsgNum, false);

    const key = await ((crypto.subtle as any).importKey)('raw', msgKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = new Uint8Array(await ((crypto.subtle as any).encrypt)(
      { name: 'AES-GCM', iv, additionalData: header } as any, key,
      new TextEncoder().encode(plaintext),
    ));

    st.sendChainKey = Array.from(await advanceChainKey(st.sendChainKey));
    st.sendMsgNum++;
    session.state = JSON.stringify(st);
    session.lastUsed = Date.now();
    sessions.set(remoteDid, session);
    if (db) await db.put('sessions', session);

    return `${ENC3_PREFIX}${toB64(header)}:${toB64(iv)}:${toB64(ct)}`;
  } catch (e) {
    console.error('[e2ee] Encrypt failed:', e);
    return null;
  }
}

/** Decrypt a DM using the Double Ratchet. */
export async function decryptMessage(
  remoteDid: string,
  wire: string,
  serverOrigin?: string,
): Promise<string | null> {
  if (!initialized) return null;
  if (!wire.startsWith(ENC3_PREFIX)) return null;

  let session = sessions.get(remoteDid);
  if (!session && serverOrigin) {
    const newSession = await establishSession(remoteDid, serverOrigin);
    if (!newSession) return null;
    session = newSession;
  }
  if (!session) return null;

  try {
    const body = wire.slice(ENC3_PREFIX.length);
    const parts = body.split(':');
    if (parts.length !== 3) return null;

    const header = fromB64(parts[0]);
    const iv = fromB64(parts[1]);
    const ct = fromB64(parts[2]);
    if (header.length !== 40 || iv.length !== 12) return null;

    const senderDHPub = header.slice(0, 32);
    const msgNum = new DataView(header.buffer, header.byteOffset + 36, 4).getUint32(0, false);
    const st: SessionState = JSON.parse(session.state);

    if (st.dhRatchetInitialized && st.dhRecvPublic && st.dhSendSecret) {
      const currentRecvPub = new Uint8Array(st.dhRecvPublic);
      if (!arraysEqual(senderDHPub, currentRecvPub)) {
        try {
          const dhOutput = await x25519DH(new Uint8Array(st.dhSendSecret), senderDHPub);
          const newRoot = await hkdfDerive(dhOutput, 'freeq-ratchet-root');
          const newChain = await hkdfDerive(newRoot, 'freeq-ratchet-chain');
          st.dhRecvPublic = Array.from(senderDHPub);
          st.rootKey = Array.from(newRoot);
          st.recvChainKey = Array.from(newChain);
          st.recvMsgNum = 0;
        } catch (e) {
          console.warn('[e2ee] Receiving DH ratchet failed:', e);
        }
      }
    }

    let chainKey = st.recvChainKey;
    for (let i = st.recvMsgNum; i < msgNum; i++) {
      chainKey = Array.from(await advanceChainKey(chainKey));
    }

    const msgKey = await deriveMessageKey(chainKey, msgNum);
    const key = await ((crypto.subtle as any).importKey)('raw', msgKey, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await ((crypto.subtle as any).decrypt)(
      { name: 'AES-GCM', iv, additionalData: header } as any, key, ct,
    );

    st.recvChainKey = Array.from(await advanceChainKey(chainKey));
    st.recvMsgNum = msgNum + 1;
    session.state = JSON.stringify(st);
    session.lastUsed = Date.now();
    sessions.set(remoteDid, session);
    if (db) await db.put('sessions', session);

    return new TextDecoder().decode(plain);
  } catch (e) {
    console.error('[e2ee] Decrypt failed:', e);
    return null;
  }
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

async function establishSession(remoteDid: string, serverOrigin: string): Promise<RatchetSession | null> {
  if (!identityKeys) return null;
  const bundle = await fetchPreKeyBundle(serverOrigin, remoteDid);
  if (!bundle) return null;

  try {
    const theirIK = fromB64(bundle.identity_key);
    const theirSPK = fromB64(bundle.signed_pre_key);

    if (bundle.signing_key && bundle.spk_signature) {
      try {
        const signingPub = fromB64(bundle.signing_key);
        const spkSig = fromB64(bundle.spk_signature);
        const verifyKey = await (crypto.subtle as any).importKey('raw', signingPub, 'Ed25519', false, ['verify']);
        const valid = await (crypto.subtle as any).verify('Ed25519', verifyKey, spkSig, theirSPK);
        if (!valid) {
          console.error('[e2ee] SPK signature verification failed for', remoteDid);
          return null;
        }
      } catch (e) {
        console.warn('[e2ee] Could not verify SPK signature:', e);
      }
    }

    const dh_ik_spk = await x25519DH(identityKeys.secretKey, theirSPK);
    const dh_spk_ik = await x25519DH(identityKeys.spkSecret, theirIK);
    const dh_spk_spk = await x25519DH(identityKeys.spkSecret, theirSPK);

    const myIK = identityKeys.publicKey;
    const weAreFirst = compareBytes(myIK, theirIK) < 0;
    const dh1 = weAreFirst ? dh_ik_spk : dh_spk_ik;
    const dh2 = weAreFirst ? dh_spk_ik : dh_ik_spk;

    const ikm = new Uint8Array(96);
    ikm.set(dh1, 0); ikm.set(dh2, 32); ikm.set(dh_spk_spk, 64);

    const sharedSecret = await hkdfDerive(ikm, 'freeq-x3dh-v1');
    const chain_a = await hkdfDerive(sharedSecret, 'freeq-chain-a');
    const chain_b = await hkdfDerive(sharedSecret, 'freeq-chain-b');

    // The signed pre-key is the initial ratchet key on both sides: the peer
    // knows it from our bundle, so the first message needs no ratchet step and
    // later steps line up (a per-side ephemeral here can never agree).
    const dhSecret = identityKeys.spkSecret;
    const dhPublic = identityKeys.spkPublic;

    const st: SessionState = {
      sharedSecret: Array.from(sharedSecret),
      sendChainKey: Array.from(weAreFirst ? chain_a : chain_b),
      recvChainKey: Array.from(weAreFirst ? chain_b : chain_a),
      sendMsgNum: 0, recvMsgNum: 0, prevChainLen: 0,
      dhSendSecret: Array.from(dhSecret),
      dhSendPublic: Array.from(dhPublic),
      dhRecvPublic: Array.from(theirSPK),
      rootKey: Array.from(sharedSecret),
      dhRatchetInitialized: true,
    };

    const session: RatchetSession = {
      remoteDid, state: JSON.stringify(st),
      createdAt: Date.now(), lastUsed: Date.now(),
    };
    sessions.set(remoteDid, session);
    if (db) await db.put('sessions', session);
    return session;
  } catch (e) {
    console.error('[e2ee] X3DH failed:', e);
    return null;
  }
}

// ── Crypto Helpers ──

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return false; }
  return true;
}

/**
 * The 32 raw secret bytes of an X25519 private key. WebCrypto permits `raw`
 * export for public keys only; the JWK `d` field is those same bytes.
 */
async function exportPrivateBytes(key: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.d) throw new Error('exported JWK is missing the private component');
  return fromB64(jwk.d);
}

/**
 * RFC 8410 PKCS#8 wrapper for a bare 32-byte X25519 scalar. WebCrypto's `raw`
 * format carries public keys only, so a stored secret has to be wrapped to be
 * imported back.
 */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

async function importPrivateKey(secret: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + secret.length);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(secret, X25519_PKCS8_PREFIX.length);
  return (crypto.subtle as any).importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
}

async function x25519DH(mySecret: Uint8Array, theirPublic: Uint8Array): Promise<Uint8Array> {
  const myKey = await importPrivateKey(mySecret);
  const theirKey = await (crypto.subtle as any).importKey('raw', theirPublic, { name: 'X25519' }, false, []);
  const bits = await (crypto.subtle as any).deriveBits({ name: 'X25519', public: theirKey }, myKey, 256);
  return new Uint8Array(bits);
}

async function hkdfDerive(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const key = await ((crypto.subtle as any).importKey)('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await ((crypto.subtle as any).deriveBits)(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32).fill(0xFF), info: new TextEncoder().encode(info) } as any,
    key, 256,
  );
  return new Uint8Array(bits);
}

async function deriveMessageKey(chainKey: number[], _msgNum: number): Promise<Uint8Array> {
  const ck = new Uint8Array(chainKey);
  const key = await ((crypto.subtle as any).importKey)('raw', ck, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await ((crypto.subtle as any).sign)('HMAC', key, new Uint8Array([0x01]));
  return new Uint8Array(sig);
}

async function advanceChainKey(chainKey: number[]): Promise<Uint8Array> {
  const ck = new Uint8Array(chainKey);
  const key = await ((crypto.subtle as any).importKey)('raw', ck, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await ((crypto.subtle as any).sign)('HMAC', key, new Uint8Array([0x02]));
  return new Uint8Array(sig);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function toB64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
