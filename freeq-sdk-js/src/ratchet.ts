/**
 * The Double Ratchet for encrypted DMs, in TypeScript.
 *
 * This is the JS half of `freeq_sdk::ratchet` (Rust). The two MUST agree
 * byte-for-byte — a DM is cross-client by definition, and a one-byte
 * disagreement about a KDF label or a header field means a web user and a
 * phone user simply cannot read each other — so both are pinned to the shared
 * vectors in `spec/e2ee-dm-vectors.json`, which `ratchet.vectors.test.ts`
 * replays.
 *
 * Session state is plain data: this module holds nothing and stores nothing.
 * Whoever owns the conversation owns the state, which is what lets the whole
 * construction be tested without a browser.
 */

/** Wire prefix for Double Ratchet encrypted messages. */
export const ENC3_PREFIX = 'ENC3:';

/**
 * Wire prefix for the first message of a session, which carries the key
 * agreement's opening alongside the ciphertext.
 *
 * The responder cannot derive anything without it, and it has to survive
 * everywhere the ciphertext survives — stored, replayed to someone who was
 * offline, relayed between servers — so it travels in the body rather than
 * beside it.
 */
export const ENC4_PREFIX = 'ENC4:';

/** Length of an encoded {@link Intro}. */
const INTRO_LEN = 68;

/** Most skipped message keys kept per session, as the Rust side caps it. */
const MAX_SKIP = 1000;

const HEADER_LEN = 40;
const NONCE_LEN = 12;

/** A message key held for a message that arrived out of order. */
export interface SkippedKey {
  ratchetKey: Uint8Array;
  msgNum: number;
  messageKey: Uint8Array;
}

/** A Double Ratchet session. Structured-cloneable, so it persists as-is. */
export interface SessionState {
  dhSelfSecret: Uint8Array;
  dhSelfPublic: Uint8Array;
  dhRemote: Uint8Array | null;
  rootKey: Uint8Array;
  sendChainKey: Uint8Array | null;
  sendMsgNum: number;
  recvChainKey: Uint8Array | null;
  recvMsgNum: number;
  prevSendChainLen: number;
  skipped: SkippedKey[];
  isInitiator: boolean;
}

/**
 * The opening of a key agreement, carried on the first message.
 *
 * Wire layout, 68 bytes: identity key (32) ‖ ephemeral key (32) ‖ pre-key id
 * (u32 big-endian). The sender's DID is not in it — the responder has that
 * from the message it arrived on, and the agreement never reads it.
 */
export interface Intro {
  identityKey: Uint8Array;
  ephemeralKey: Uint8Array;
  spkId: number;
}

export interface MessageHeader {
  ratchetKey: Uint8Array;
  prevChainLen: number;
  msgNum: number;
}

// ── Primitives ──

/**
 * The root KDF: one HKDF-SHA256 keyed by the current root, over the DH
 * output, yielding the next root and a chain key in one 64-byte read.
 */
export async function kdfRoot(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): Promise<{ rootKey: Uint8Array; chainKey: Uint8Array }> {
  const key = await crypto.subtle.importKey('raw', dhOutput as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: rootKey as BufferSource,
        info: new TextEncoder().encode('freeq-ratchet-v1'),
      },
      key,
      512,
    ),
  );
  return { rootKey: bits.slice(0, 32), chainKey: bits.slice(32) };
}

/** The symmetric chain KDF: a message key and the chain key that follows it. */
export async function kdfChain(
  chainKey: Uint8Array,
): Promise<{ messageKey: Uint8Array; nextChainKey: Uint8Array }> {
  const key = await crypto.subtle.importKey(
    'raw',
    chainKey as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = async (byte: number) =>
    new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array([byte])));
  return { messageKey: await mac(0x01), nextChainKey: await mac(0x02) };
}

async function dh(secret: Uint8Array, theirPublic: Uint8Array): Promise<Uint8Array> {
  const mine = await importX25519Secret(secret);
  const theirs = await crypto.subtle.importKey(
    'raw',
    theirPublic as BufferSource,
    { name: 'X25519' },
    false,
    [],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'X25519', public: theirs } as AlgorithmIdentifier, mine, 256),
  );
}

/**
 * RFC 8410 PKCS#8 wrapper for a bare 32-byte X25519 scalar. WebCrypto's `raw`
 * format carries public keys only, so a stored secret has to be wrapped.
 */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

async function importX25519Secret(secret: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + secret.length);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(secret, X25519_PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'X25519' }, false, [
    'deriveBits',
  ]);
}

/** The public key for a 32-byte X25519 secret. */
export async function x25519PublicKey(secret: Uint8Array): Promise<Uint8Array> {
  // WebCrypto won't hand back the public half of an imported private key, so
  // the JWK export — which carries both — is the way across.
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + secret.length);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(secret, X25519_PKCS8_PREFIX.length);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'X25519' }, true, [
    'deriveBits',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.x) throw new Error('exported JWK is missing the public component');
  return fromB64Url(jwk.x);
}

/** Generate a fresh X25519 secret. */
export async function generateSecret(): Promise<Uint8Array> {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  if (!jwk.d) throw new Error('exported JWK is missing the private component');
  return fromB64Url(jwk.d);
}

// ── Header ──

export function encodeHeader(header: MessageHeader): Uint8Array {
  const out = new Uint8Array(HEADER_LEN);
  out.set(header.ratchetKey, 0);
  const view = new DataView(out.buffer);
  view.setUint32(32, header.prevChainLen, false);
  view.setUint32(36, header.msgNum, false);
  return out;
}

export function encodeIntro(intro: Intro): Uint8Array {
  const out = new Uint8Array(INTRO_LEN);
  out.set(intro.identityKey, 0);
  out.set(intro.ephemeralKey, 32);
  new DataView(out.buffer).setUint32(64, intro.spkId, false);
  return out;
}

export function decodeIntro(bytes: Uint8Array): Intro | null {
  if (bytes.length !== INTRO_LEN) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    identityKey: bytes.slice(0, 32),
    ephemeralKey: bytes.slice(32, 64),
    spkId: view.getUint32(64, false),
  };
}

/**
 * Read the opening off a first message, or `null` for an ordinary one. A
 * responder calls this before it has a session — the intro is what lets it
 * build one.
 */
export function introOf(wire: string): Intro | null {
  if (!wire.startsWith(ENC4_PREFIX)) return null;
  const field = wire.slice(ENC4_PREFIX.length).split(':')[0];
  try {
    return decodeIntro(fromB64Url(field));
  } catch {
    return null;
  }
}

export function decodeHeader(bytes: Uint8Array): MessageHeader | null {
  if (bytes.length !== HEADER_LEN) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    ratchetKey: bytes.slice(0, 32),
    prevChainLen: view.getUint32(32, false),
    msgNum: view.getUint32(36, false),
  };
}

// ── Session setup ──

/**
 * Open a session as the initiator: mint a ratchet keypair and step the root
 * KDF once against the peer's signed pre-key, so the first message already
 * rides a chain the peer can rebuild from its header.
 */
export async function initAlice(
  sharedSecret: Uint8Array,
  theirRatchetKey: Uint8Array,
  ourSecret?: Uint8Array,
): Promise<SessionState> {
  const secret = ourSecret ?? (await generateSecret());
  const dhOut = await dh(secret, theirRatchetKey);
  const { rootKey, chainKey } = await kdfRoot(sharedSecret, dhOut);
  return {
    dhSelfSecret: secret,
    dhSelfPublic: await x25519PublicKey(secret),
    dhRemote: theirRatchetKey,
    rootKey,
    sendChainKey: chainKey,
    sendMsgNum: 0,
    recvChainKey: null,
    recvMsgNum: 0,
    prevSendChainLen: 0,
    skipped: [],
    isInitiator: true,
  };
}

/**
 * Open a session as the responder: the root is the shared secret and there
 * are no chains yet. The receiving chain comes from the ratchet key in the
 * first header that arrives, and the sending chain from the step taken then.
 */
export async function initBob(
  sharedSecret: Uint8Array,
  ourRatchetSecret: Uint8Array,
): Promise<SessionState> {
  return {
    dhSelfSecret: ourRatchetSecret,
    dhSelfPublic: await x25519PublicKey(ourRatchetSecret),
    dhRemote: null,
    rootKey: sharedSecret,
    sendChainKey: null,
    sendMsgNum: 0,
    recvChainKey: null,
    recvMsgNum: 0,
    prevSendChainLen: 0,
    skipped: [],
    isInitiator: false,
  };
}

// ── Encrypt / decrypt ──

/**
 * Encrypt one message, advancing the sending chain.
 *
 * `nonce` is for reproducing published vectors only — a repeated nonce under
 * one key breaks AES-GCM outright, so real sends leave it out.
 */
export async function encryptFirst(
  state: SessionState,
  intro: Intro,
  plaintext: string,
  nonce?: Uint8Array,
): Promise<string> {
  return encryptInner(state, plaintext, nonce, intro);
}

export async function encrypt(
  state: SessionState,
  plaintext: string,
  nonce?: Uint8Array,
): Promise<string> {
  return encryptInner(state, plaintext, nonce, null);
}

async function encryptInner(
  state: SessionState,
  plaintext: string,
  nonce: Uint8Array | undefined,
  intro: Intro | null,
): Promise<string> {
  if (!state.sendChainKey) throw new Error('no sending chain (session not fully initialized)');

  const { messageKey, nextChainKey } = await kdfChain(state.sendChainKey);
  state.sendChainKey = nextChainKey;

  const header: MessageHeader = {
    ratchetKey: state.dhSelfPublic,
    prevChainLen: state.prevSendChainLen,
    msgNum: state.sendMsgNum,
  };
  state.sendMsgNum += 1;

  const headerBytes = encodeHeader(header);
  const iv = nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const key = await crypto.subtle.importKey('raw', messageKey as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: headerBytes as BufferSource },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );

  const tail = `${toB64Url(headerBytes)}:${toB64Url(iv)}:${toB64Url(ciphertext)}`;
  // The intro is not in the AAD: tampering with it lands the responder on a
  // different secret, so the message does not open either way.
  return intro ? `${ENC4_PREFIX}${toB64Url(encodeIntro(intro))}:${tail}` : `${ENC3_PREFIX}${tail}`;
}

/** Decrypt one message, stepping the ratchet when the peer's key has moved. */
export async function decrypt(state: SessionState, wire: string): Promise<string> {
  // A first message carries the agreement's opening ahead of the header. By
  // the time there is a session to decrypt with, that opening has done its
  // work, so the rest is read exactly alike.
  let parts: [string, string, string] | null;
  if (wire.startsWith(ENC4_PREFIX)) {
    const body = wire.slice(ENC4_PREFIX.length);
    const cut = body.indexOf(':');
    parts = cut < 0 ? null : splitWire(body.slice(cut + 1));
  } else if (wire.startsWith(ENC3_PREFIX)) {
    parts = splitWire(wire.slice(ENC3_PREFIX.length));
  } else {
    throw new Error('not an encrypted message');
  }
  if (!parts) throw new Error('malformed encrypted message');
  const [headerB64, nonceB64, ctB64] = parts;

  const headerBytes = fromB64Url(headerB64);
  const nonce = fromB64Url(nonceB64);
  const ciphertext = fromB64Url(ctB64);
  if (nonce.length !== NONCE_LEN) throw new Error('malformed encrypted message');
  const header = decodeHeader(headerBytes);
  if (!header) throw new Error('malformed header');

  // A key held for a message that overtook this one.
  const skippedAt = state.skipped.findIndex(
    (s) => s.msgNum === header.msgNum && bytesEqual(s.ratchetKey, header.ratchetKey),
  );
  if (skippedAt >= 0) {
    const [held] = state.skipped.splice(skippedAt, 1);
    return openMessage(held.messageKey, headerBytes, nonce, ciphertext);
  }

  const theirKeyChanged = !state.dhRemote || !bytesEqual(state.dhRemote, header.ratchetKey);
  if (theirKeyChanged) {
    // Hold keys for whatever is still in flight on the chain we're leaving.
    if (state.recvChainKey) {
      await skipMessages(
        state,
        state.dhRemote ?? new Uint8Array(32),
        state.recvChainKey,
        state.recvMsgNum,
        header.prevChainLen,
      );
    }

    state.dhRemote = header.ratchetKey;
    const recvStep = await kdfRoot(state.rootKey, await dh(state.dhSelfSecret, header.ratchetKey));
    state.rootKey = recvStep.rootKey;
    state.recvChainKey = recvStep.chainKey;
    state.recvMsgNum = 0;

    // Our own next sending chain rides a fresh keypair: this is the ratchet.
    state.prevSendChainLen = state.sendMsgNum;
    state.sendMsgNum = 0;
    state.dhSelfSecret = await generateSecret();
    state.dhSelfPublic = await x25519PublicKey(state.dhSelfSecret);
    const sendStep = await kdfRoot(state.rootKey, await dh(state.dhSelfSecret, header.ratchetKey));
    state.rootKey = sendStep.rootKey;
    state.sendChainKey = sendStep.chainKey;
  }

  if (!state.recvChainKey) throw new Error('no receiving chain');
  await skipMessages(
    state,
    header.ratchetKey,
    state.recvChainKey,
    state.recvMsgNum,
    header.msgNum,
  );

  const { messageKey, nextChainKey } = await kdfChain(state.recvChainKey!);
  state.recvChainKey = nextChainKey;
  state.recvMsgNum = header.msgNum + 1;
  return openMessage(messageKey, headerBytes, nonce, ciphertext);
}

/** Hold the keys for messages `from`..`until` so they still open if they land. */
async function skipMessages(
  state: SessionState,
  ratchetKey: Uint8Array,
  chainKey: Uint8Array,
  from: number,
  until: number,
): Promise<void> {
  if (until < from) return;
  if (until - from > MAX_SKIP) throw new Error('too many skipped messages');
  let current = chainKey;
  for (let n = from; n < until; n++) {
    const { messageKey, nextChainKey } = await kdfChain(current);
    state.skipped.push({ ratchetKey, msgNum: n, messageKey });
    current = nextChainKey;
  }
  state.recvChainKey = current;
}

async function openMessage(
  messageKey: Uint8Array,
  headerBytes: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<string> {
  const key = await crypto.subtle.importKey('raw', messageKey as BufferSource, 'AES-GCM', false, [
    'decrypt',
  ]);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: headerBytes as BufferSource },
    key,
    ciphertext as BufferSource,
  );
  return new TextDecoder().decode(plaintext);
}

/** Is this an ENC3 message? */
export function isEncrypted(text: string): boolean {
  return text.startsWith(ENC3_PREFIX) || text.startsWith(ENC4_PREFIX);
}

// ── Wire helpers ──

/** Split into exactly three fields, as the Rust side's `splitn(3, ':')` does. */
function splitWire(body: string): [string, string, string] | null {
  const first = body.indexOf(':');
  if (first < 0) return null;
  const second = body.indexOf(':', first + 1);
  if (second < 0) return null;
  return [body.slice(0, first), body.slice(first + 1, second), body.slice(second + 1)];
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function toB64Url(data: Uint8Array): string {
  let s = '';
  for (const b of data) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64Url(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
