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
import {
  CompositeDidDocumentResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
} from '@atcute/identity-resolver';
import { decodeMultibaseEd25519 } from './did-key.js';
import {
  DEVICE_KEY_TYPE,
  type DidDocument,
  type Fetch,
  type ResolveDid,
  deviceKeyHistory,
  listRecordEntries,
  provenRecords,
} from './identity-records.js';
import { deriveKid } from './signing.js';

/** Where a key was found. */
export type KeySource = 'IdentityRecord' | 'DidDocument' | 'OriginServer';

/** An ed25519 public key (32 bytes) that hashes to the kid asked for, and its source. */
export interface FoundKey {
  publicKey: Uint8Array;
  source: KeySource;
  /** When the key was retired, unix seconds: by a retirement in the signer's
   *  records, or the date the origin server says it was removed. */
  retiredAt: number | null;
}

/** What the identity-record reader needs: an HTTP GET and a DID resolver. */
export interface RecordReader {
  fetch: Fetch;
  resolveDid: ResolveDid;
}

/**
 * One (DID, kid)'s cached answer: the signer's device records as listed,
 * folded again at whatever time is asked, and what the other sources said
 * once they have been asked (`undefined` until then).
 */
interface Cached {
  records: unknown[];
  other: FoundKey | null | undefined;
  at: number;
}

/**
 * Looks keys up by (DID, kid), caching each answer for `ttlMs`: a key found,
 * or a miss, when every source answered without the key.
 */
export class KeyLookup {
  private readonly cache = new Map<string, Cached>();
  /** CIDs of records whose repository proof has checked, so each is fetched once. */
  private readonly proven = new Set<string>();
  private defaultOrigin: string | null = null;

  /** `originBase` is the origin server's base URL; the reader's `fetch` serves its requests. */
  constructor(
    readonly reader: RecordReader,
    private readonly givenOrigin: string | null,
    private readonly ttlMs: number,
  ) {}

  /** The origin to ask when none was given at construction. Set once; a
   *  client sets it to the server it connected to. */
  setDefaultOriginBase(base: string): void {
    if (this.defaultOrigin === null) this.defaultOrigin = base;
  }

  /** The origin server this lookup asks: the one given, else the default. */
  originBase(): string | null {
    return this.givenOrigin ?? this.defaultOrigin;
  }

  /** The key `did` signs with under `kid` now; see `keyForAt`. */
  keyFor(did: string, kid: string): Promise<FoundKey | null> {
    return this.keyForAt(did, kid, new Date());
  }

  /**
   * The key `did` signed with under `kid` at `at`, or null when no source has
   * it. The signer's records are folded at `at`, so a record key counts only
   * if it was live then; the other sources are not dated.
   *
   * A source that fails is skipped and the next one asked; the first failure
   * is thrown only if no later source finds the key. A miss is remembered only
   * when no source failed, since a failed source did not say it lacks the key.
   */
  async keyForAt(did: string, kid: string, at: Date): Promise<FoundKey | null> {
    const slot = JSON.stringify([did, kid]);
    const hit = this.cache.get(slot);
    const cached = hit !== undefined && Date.now() - hit.at < this.ttlMs ? hit : undefined;

    let failure: unknown;
    let failed = false;
    let records: unknown[] = [];
    if (cached !== undefined) {
      records = cached.records;
    } else {
      try {
        // A listed record counts only once its repository proof checks.
        records = await this.provenDeviceRecords(did);
      } catch (e) {
        [failed, failure] = [true, e];
      }
    }
    const inRecords = await fromRecords(did, kid, records, at);
    if (inRecords !== null) {
      if (!failed && cached === undefined) this.remember(slot, records, undefined);
      return inRecords;
    }
    if (cached !== undefined && cached.other !== undefined) return cached.other;

    const sources: [KeySource, () => Promise<[Uint8Array | null, number | null]>][] = [];
    if (did.startsWith('did:web:')) {
      sources.push(['DidDocument', async () => [await this.fromDocument(did, kid), null]]);
    }
    const origin = this.originBase();
    if (origin !== null) sources.push(['OriginServer', () => this.fromOrigin(origin, did, kid)]);

    for (const [source, ask] of sources) {
      let key: Uint8Array | null;
      let retiredAt: number | null;
      try {
        [key, retiredAt] = await ask();
      } catch (e) {
        if (!failed) [failed, failure] = [true, e];
        continue;
      }
      if (key === null || key.length !== 32 || (await deriveKid(key)) !== kid) continue;
      const found: FoundKey = { publicKey: key, source, retiredAt };
      this.remember(slot, records, found);
      return found;
    }
    if (failed) throw failure;
    this.remember(slot, records, null);
    return null;
  }

  /**
   * `did`'s device key records whose repository proof checks, through this
   * lookup's cache of proven records, so each record's proof is fetched once.
   */
  async provenDeviceRecords(did: string): Promise<unknown[]> {
    const listed = await listRecordEntries(this.reader.fetch, this.reader.resolveDid, did, DEVICE_KEY_TYPE);
    return provenRecords(this.reader.fetch, this.reader.resolveDid, did, DEVICE_KEY_TYPE, listed, this.proven);
  }

  /** Clear a remembered miss for `(did, kid)`, so the next lookup asks again. A key found stays cached. */
  forget(did: string, kid: string): void {
    const slot = JSON.stringify([did, kid]);
    if (this.cache.get(slot)?.other === null) this.cache.delete(slot);
  }

  private remember(slot: string, records: unknown[], other: FoundKey | null | undefined): void {
    this.cache.set(slot, { records, other, at: Date.now() });
  }

  private async fromDocument(did: string, kid: string): Promise<Uint8Array | null> {
    const doc = await this.reader.resolveDid(did);
    for (const method of doc.verificationMethod ?? []) {
      const key = method.publicKeyMultibase === undefined ? null : ed25519Raw(method.publicKeyMultibase);
      if (key !== null && (await deriveKid(key)) === kid) return key;
    }
    return null;
  }

  /** The key the origin holds for `(did, kid)`, and when it was removed. */
  private async fromOrigin(
    base: string,
    did: string,
    kid: string,
  ): Promise<[Uint8Array | null, number | null]> {
    const path = `/api/v1/signing-keys/${encodeURIComponent(did)}/${encodeURIComponent(kid)}`;
    const res = await this.reader.fetch(`${base.replace(/\/+$/, '')}${path}`);
    if (res.status === 404) return [null, null];
    if (!res.ok) throw new Error(`the origin key store answered ${res.status}`);
    const answer = (await res.json()) as { public_key?: unknown; removed_at?: unknown };
    if (typeof answer.public_key !== 'string') throw new Error('the origin answer is not a key');
    const removedAt = typeof answer.removed_at === 'number' ? answer.removed_at : null;
    // A key that does not decode is refused like a wrong one.
    return [base64UrlDecode(answer.public_key), removedAt];
  }
}

/**
 * The key `kid` names among `did`'s device records at `at`: live then, or
 * retired at or before then, carrying the retirement the fold accepted. A key
 * the records retire is answered here, so no other source is asked for it.
 */
async function fromRecords(
  did: string,
  kid: string,
  records: unknown[],
  at: Date,
): Promise<FoundKey | null> {
  const when = at.getTime();
  const match = (await deviceKeyHistory(did, records)).find((k) => k.kid === kid);
  if (match === undefined || match.createdAt.getTime() > when) return null;
  const key = ed25519Raw(match.publicKeyMultibase);
  if (key === null || (await deriveKid(key)) !== kid) return null;
  const retired = match.retiredAt !== null && match.retiredAt.getTime() <= when;
  return {
    publicKey: key,
    source: 'IdentityRecord',
    // Unix seconds, like the origin's removal date.
    retiredAt: retired ? Math.floor(match.retiredAt!.getTime() / 1000) : null,
  };
}

/**
 * A `ResolveDid` for did:plc (the PLC directory) and did:web, built on
 * `@atcute/identity-resolver`. Anything else is refused.
 */
export function makeDidResolver(
  options: { fetch?: typeof globalThis.fetch; plcUrl?: string } = {},
): ResolveDid {
  const resolver = new CompositeDidDocumentResolver({
    methods: {
      plc: new PlcDidDocumentResolver({ fetch: options.fetch, apiUrl: options.plcUrl }),
      web: new WebDidDocumentResolver({ fetch: options.fetch }),
    },
  });
  return async (did: string): Promise<DidDocument> => {
    if (!did.startsWith('did:plc:') && !did.startsWith('did:web:')) {
      throw new Error(`no resolver for ${did}`);
    }
    const doc = await resolver.resolve(did as `did:plc:${string}` | `did:web:${string}`);
    return doc as unknown as DidDocument;
  };
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
