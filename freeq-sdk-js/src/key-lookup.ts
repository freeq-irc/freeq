/**
 * Finding a signer's public key from the key id a signature names.
 *
 * The key is looked for where the signer published it, most direct first:
 * the signer's own identity records, then, for a did:web signer, its DID
 * document, and last the origin server's key store. Whichever source
 * answers, the key must hash to the kid, or it is refused.
 *
 * Twin of the Rust `freeq_sdk::key_lookup`.
 */
import { decodeMultibaseEd25519 } from './did-key.js';
import { type Fetch, type ResolveDid, liveDeviceKeys } from './identity-records.js';
import { deriveKid } from './signing.js';

/** Where a key was found. */
export type KeySource = 'IdentityRecord' | 'DidDocument' | 'OriginServer';

/** An ed25519 public key (32 bytes) that hashes to the kid asked for, and its source. */
export interface FoundKey {
  publicKey: Uint8Array;
  source: KeySource;
}

/** What the identity-record reader needs: an HTTP GET and a DID resolver. */
export interface RecordReader {
  fetch: Fetch;
  resolveDid: ResolveDid;
}

/**
 * Looks keys up by (DID, kid), caching each answer for `ttlMs`: a key found,
 * or a miss, when every source answered without the key.
 */
export class KeyLookup {
  private readonly cache = new Map<string, { found: FoundKey | null; at: number }>();

  /** `originBase` is the origin server's base URL; the reader's `fetch` serves its requests. */
  constructor(
    private readonly reader: RecordReader,
    private readonly originBase: string | null,
    private readonly ttlMs: number,
  ) {}

  /**
   * The key `did` signs with under `kid`, or null when no source has it.
   *
   * A source that fails is skipped and the next one asked; the first failure
   * is thrown only if no later source finds the key. A miss is remembered only
   * when no source failed, since a failed source did not say it lacks the key.
   */
  async keyFor(did: string, kid: string): Promise<FoundKey | null> {
    const slot = JSON.stringify([did, kid]);
    const cached = this.cache.get(slot);
    if (cached !== undefined && Date.now() - cached.at < this.ttlMs) return cached.found;

    let failure: unknown;
    let failed = false;
    const sources: [KeySource, () => Promise<Uint8Array | null>][] = [
      ['IdentityRecord', () => this.fromRecords(did, kid)],
    ];
    if (did.startsWith('did:web:')) sources.push(['DidDocument', () => this.fromDocument(did, kid)]);
    const origin = this.originBase;
    if (origin !== null) sources.push(['OriginServer', () => this.fromOrigin(origin, did, kid)]);

    for (const [source, ask] of sources) {
      let key: Uint8Array | null;
      try {
        key = await ask();
      } catch (e) {
        if (!failed) [failed, failure] = [true, e];
        continue;
      }
      if (key === null || key.length !== 32 || (await deriveKid(key)) !== kid) continue;
      const found: FoundKey = { publicKey: key, source };
      this.cache.set(slot, { found, at: Date.now() });
      return found;
    }
    if (failed) throw failure;
    this.cache.set(slot, { found: null, at: Date.now() });
    return null;
  }

  /** Clear a remembered miss for `(did, kid)`, so the next lookup asks again. A key found stays cached. */
  forget(did: string, kid: string): void {
    const slot = JSON.stringify([did, kid]);
    if (this.cache.get(slot)?.found === null) this.cache.delete(slot);
  }

  private async fromRecords(did: string, kid: string): Promise<Uint8Array | null> {
    const live = await liveDeviceKeys(this.reader.fetch, this.reader.resolveDid, did, new Date());
    const match = live.find((k) => k.kid === kid);
    return match === undefined ? null : ed25519Raw(match.publicKeyMultibase);
  }

  private async fromDocument(did: string, kid: string): Promise<Uint8Array | null> {
    const doc = await this.reader.resolveDid(did);
    for (const method of doc.verificationMethod ?? []) {
      const key = method.publicKeyMultibase === undefined ? null : ed25519Raw(method.publicKeyMultibase);
      if (key !== null && (await deriveKid(key)) === kid) return key;
    }
    return null;
  }

  private async fromOrigin(base: string, did: string, kid: string): Promise<Uint8Array | null> {
    const path = `/api/v1/signing-keys/${encodeURIComponent(did)}/${encodeURIComponent(kid)}`;
    const res = await this.reader.fetch(`${base.replace(/\/+$/, '')}${path}`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`the origin key store answered ${res.status}`);
    const answer = (await res.json()) as { public_key?: unknown };
    if (typeof answer.public_key !== 'string') throw new Error('the origin answer is not a key');
    // A key that does not decode is refused like a wrong one.
    return base64UrlDecode(answer.public_key);
  }
}

/** The raw bytes of a `z6Mk…` ed25519 key; anything else is not a signing key here. */
function ed25519Raw(multibase: string): Uint8Array | null {
  try {
    return decodeMultibaseEd25519(multibase);
  } catch {
    return null;
  }
}

/** Unpadded base64url, the encoding the origin uses; anything else is null. */
function base64UrlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  try {
    const bin = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
