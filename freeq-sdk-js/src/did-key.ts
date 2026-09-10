/**
 * did:key generation + signing for SASL ATPROTO-CHALLENGE crypto auth.
 *
 * Lets a JS bot authenticate to freeq with no PDS, no OAuth, no
 * external service — just a freshly-generated ed25519 keypair.
 *
 * The public key is encoded as `did:key:z<base58btc(0xed01 || pubkey)>`
 * which the server resolves locally (no network fetch). The signer
 * produces a base64url-encoded ed25519 signature over the raw
 * challenge bytes the server emitted in the AUTHENTICATE line.
 *
 * Wire-compatible with `freeq-sdk` (Rust)'s `KeySigner` and
 * `verify_crypto` — round-trip verified by
 * `freeq-server/tests/agent_assist_authenticated.rs`.
 */

// ─── base58btc + multicodec ─────────────────────────────────────────────

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base58btc encode a byte slice. Inline implementation (~25 lines) so
 * the SDK gains zero dependencies for this. Performance-irrelevant —
 * called once at key-generation time and never on a hot path.
 */
function base58btcEncode(bytes: Uint8Array): string {
  // Count leading zero bytes — base58 doesn't represent them
  // implicitly, so we prepend a '1' for each.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert bytes to base58 by repeated division.
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '';
  for (let i = 0; i < zeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}

/** ed25519 multicodec public-key prefix (varint). */
const MULTICODEC_ED25519_PUB = new Uint8Array([0xed, 0x01]);

/**
 * Base58btc decode, the inverse of [`base58btcEncode`]. Throws on any
 * character outside the alphabet.
 */
function base58btcDecode(text: string): Uint8Array {
  // Leading '1's are the leading zero bytes the encoder dropped.
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros++;

  const bytes: number[] = [];
  for (let i = zeros; i < text.length; i++) {
    const digit = BASE58_ALPHABET.indexOf(text[i]!);
    if (digit < 0) throw new Error(`invalid base58 character ${text[i]}`);
    let carry = digit;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + bytes.length - 1 - i] = bytes[i]!;
  return out;
}

/**
 * Decode a `z…` multibase public key to its raw 32 ed25519 bytes.
 *
 * Throws if the string is not base58btc, not an ed25519 multicodec key, or
 * not 32 bytes long — callers reading keys off the wire catch and discard.
 */
export function decodeMultibaseEd25519(multibase: string): Uint8Array {
  if (!multibase.startsWith('z')) {
    throw new Error("multibase key must start with 'z' (base58btc)");
  }
  const bytes = base58btcDecode(multibase.slice(1));
  if (bytes.length !== 34 || bytes[0] !== MULTICODEC_ED25519_PUB[0] || bytes[1] !== MULTICODEC_ED25519_PUB[1]) {
    throw new Error('not an ed25519 multicodec public key');
  }
  return bytes.slice(2);
}

/**
 * Verify a base64url (unpadded) ed25519 signature over `message`.
 *
 * Returns false rather than throwing for anything malformed — a bad
 * signature and an unreadable one are both "does not verify" to a caller
 * reading records it did not write.
 */
export async function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signatureBase64url: string,
): Promise<boolean> {
  // base64url without padding, as everywhere else in freeq: anything else
  // is refused here rather than silently re-interpreted by atob.
  if (!/^[A-Za-z0-9_-]+$/.test(signatureBase64url)) return false;
  try {
    const signature = base64UrlDecode(signatureBase64url);
    if (signature.length !== 64) return false;
    const key = await crypto.subtle.importKey(
      'raw',
      publicKey as BufferSource,
      'Ed25519',
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      signature as BufferSource,
      message as BufferSource,
    );
  } catch {
    return false;
  }
}


function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ─── Key generation + signing ───────────────────────────────────────────

/** Result of [`generateDidKey`]: a fresh did:key + a sign callback. */
export interface DidKey {
  /** `did:key:z…` — give this to the freeq server as your identity. */
  did: string;

  /** Multibase-encoded public key (`z…`). The DID without the `did:key:` prefix. */
  publicKeyMultibase: string;

  /**
   * Sign the raw challenge bytes the server emitted in AUTHENTICATE.
   * Returns a base64url-encoded ed25519 signature suitable for the
   * `signature` field of a SASL ATPROTO-CHALLENGE response.
   */
  signer: (challengeBytes: Uint8Array) => Promise<string>;

  /**
   * Raw private key bytes (32). Use [`exportSeed`]/[`importDidKey`] to
   * persist between bot runs. Treat as secret.
   */
  exportSeed: () => Promise<Uint8Array>;
}

/**
 * Generate a fresh ed25519 did:key.
 *
 * Uses Web Crypto Subtle (`Ed25519`), available in Node 22+ and modern
 * browsers. Throws if Ed25519 isn't available — there's no fallback;
 * the bot author should bail and surface the missing-runtime error.
 */
export async function generateDidKey(): Promise<DidKey> {
  // The `extractable: true` on the private key is required so that
  // exportSeed can return the seed for persistence. Web Crypto allows
  // sign() to use an extractable key normally.
  const kp = (await crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  return wrapKeypair(kp);
}

/**
 * Re-import a previously generated did:key from its raw 32-byte seed
 * (returned by [`DidKey.exportSeed`]).
 *
 * Lets a bot persist its identity between runs without the operator
 * managing a PEM file or PDS account. Just store the seed somewhere
 * safe (env var, secrets file).
 */
export async function importDidKey(seed: Uint8Array): Promise<DidKey> {
  if (seed.length !== 32) {
    throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  // Web Crypto's import format for a raw ed25519 private key is PKCS8.
  // We construct a minimal PKCS8 wrapper around the 32-byte seed.
  const pkcs8 = ed25519SeedToPkcs8(seed);
  // Cast: Web Crypto's `BufferSource` doesn't accept the
  // `Uint8Array<ArrayBufferLike>` shape Node's TS types produce, but the
  // runtime accepts plain Uint8Array fine.
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8 as BufferSource,
    'Ed25519',
    true,
    ['sign'],
  );
  // Derive the public key from the private one — Web Crypto doesn't
  // give us a CryptoKeyPair, so we have to construct one. The public
  // half can be exported by re-deriving via JWK: export as JWK, take
  // the `x` field, import as raw public.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk.x) throw new Error('exported JWK missing public component');
  const pubBytes = base64UrlDecode(jwk.x);
  const publicKey = await crypto.subtle.importKey(
    'raw',
    pubBytes as BufferSource,
    'Ed25519',
    true,
    ['verify'],
  );
  return wrapKeypair({ privateKey, publicKey } as CryptoKeyPair);
}

async function wrapKeypair(kp: CryptoKeyPair): Promise<DidKey> {
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const multibase = `z${base58btcEncode(concat(MULTICODEC_ED25519_PUB, rawPub))}`;
  const did = `did:key:${multibase}`;

  const signer = async (challengeBytes: Uint8Array): Promise<string> => {
    const sigBuf = await crypto.subtle.sign(
      'Ed25519',
      kp.privateKey,
      challengeBytes as BufferSource,
    );
    return bytesToBase64Url(new Uint8Array(sigBuf));
  };

  const exportSeed = async (): Promise<Uint8Array> => {
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    if (!jwk.d) throw new Error('exported JWK missing seed (key was not extractable)');
    return base64UrlDecode(jwk.d);
  };

  return { did, publicKeyMultibase: multibase, signer, exportSeed };
}

// ─── PKCS8 wrapper for ed25519 seed import ──────────────────────────────

/**
 * Wrap a 32-byte ed25519 seed in the minimum PKCS8 envelope that
 * Web Crypto's importKey('pkcs8', …, 'Ed25519') accepts.
 *
 * Hand-coded DER because the structure is fixed: PKCS8 PrivateKeyInfo
 * for an Ed25519 key is always exactly these bytes followed by the
 * 32-byte seed inside an OCTET STRING inside an OCTET STRING.
 */
function ed25519SeedToPkcs8(seed: Uint8Array): Uint8Array {
  // SEQUENCE {
  //   INTEGER 0                -- version
  //   SEQUENCE {               -- algorithm
  //     OID 1.3.101.112        -- ed25519
  //   }
  //   OCTET STRING {           -- privateKey
  //     OCTET STRING { seed }  -- inner
  //   }
  // }
  const prefix = new Uint8Array([
    0x30, 0x2e, // SEQUENCE 46
    0x02, 0x01, 0x00, // INTEGER 0
    0x30, 0x05, // SEQUENCE 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
    0x04, 0x22, // OCTET STRING 34
    0x04, 0x20, // inner OCTET STRING 32
  ]);
  return concat(prefix, seed);
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + '='.repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
