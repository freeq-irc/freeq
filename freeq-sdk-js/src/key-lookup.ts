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
export interface Cached {
  records: unknown[];
  other: FoundKey | null | undefined;
  at: number;
}

/**
 * What a lookup keeps between page loads: each (DID, kid) answer that found a
 * key, each DID's proven device records with their listing time, and the CIDs
 * of records whose proof checked. Misses, failures and lookups in flight are
 * not kept.
 */
export interface KeyLookupSnapshot {
  keys: [string, Cached][];
  records: [string, { records: unknown[]; at: number }][];
  proven: string[];
}

/** Where a key lookup keeps its snapshot. */
export interface KeyLookupStore {
  load(): Promise<KeyLookupSnapshot | null>;
  save(snapshot: KeyLookupSnapshot): Promise<void>;
}

/** A store that forgets on reload; the default. */
export class MemoryKeyLookupStore implements KeyLookupStore {
  private snapshot: KeyLookupSnapshot | null = null;

  async load(): Promise<KeyLookupSnapshot | null> {
    return this.snapshot;
  }

  async save(snapshot: KeyLookupSnapshot): Promise<void> {
    this.snapshot = snapshot;
  }
}

/** What one lookup settled on, shared by every ask that awaited it. */
interface Settled {
  records: unknown[];
  /** What the other sources said; `undefined` when they were not asked. */
  other: FoundKey | null | undefined;
  failed: boolean;
  failure: unknown;
}

/**
 * When a miss the origin answered is asked again, in ms after the first ask:
 * the origin may still be fetching the key from the signer's home server.
 */
export const MISS_RETRY_AFTER_MS: readonly number[] = [2_000, 6_000, 15_000];

/**
 * Looks keys up by (DID, kid). A miss, when every source answered without the
 * key, is cached for `ttlMs`; a key found is cached without expiry, and one
 * found in the records takes the DID's listing again once that is older than
 * `ttlMs`, so a retirement since lands on it. A miss the origin answered is
 * asked again at each of `retryAfterMs` before it is remembered. A signer's
 * device records are listed and proven per DID, shared by the lookups for
 * every kid of that DID. Found keys, proven records and proven CIDs are
 * kept in `store`, so a lookup built on the same store starts with them.
 */
export class KeyLookup {
  private readonly cache = new Map<string, Cached>();
  /** One lookup in flight per (DID, kid). */
  private readonly inFlight = new Map<string, Promise<Settled>>();
  /** Each DID's proven device records as last listed, kept for `ttlMs`. */
  private readonly records = new Map<string, { records: unknown[]; at: number }>();
  /** One listing, with its proofs, in flight per DID. */
  private readonly listing = new Map<string, Promise<unknown[]>>();
  /** CIDs of records whose repository proof has checked, so each is fetched once. */
  private readonly proven = new Set<string>();
  /** Proofs in flight by record CID, so listings racing on a record share one fetch. */
  private readonly proving = new Map<string, Promise<boolean>>();
  private defaultOrigin: string | null = null;
  /** The store's snapshot, taken in once before the first lookup. */
  private loaded: Promise<void> | null = null;
  /** Writes to the store, one after another. */
  private saving: Promise<void> = Promise.resolve();

  /** `originBase` is the origin server's base URL; the reader's `fetch` serves its requests. */
  constructor(
    readonly reader: RecordReader,
    private readonly givenOrigin: string | null,
    private readonly ttlMs: number,
    private readonly retryAfterMs: readonly number[] = MISS_RETRY_AFTER_MS,
    private readonly store: KeyLookupStore = new MemoryKeyLookupStore(),
  ) {}

  /** Take in what the store holds, once; a store that cannot be read leaves the cache as it is. */
  private load(): Promise<void> {
    if (this.loaded === null) {
      this.loaded = this.store.load().then(
        (snapshot) => {
          if (snapshot === null) return;
          for (const [slot, cached] of snapshot.keys) {
            if (!this.cache.has(slot)) this.cache.set(slot, cached);
          }
          for (const [did, listed] of snapshot.records) {
            if (!this.records.has(did)) this.records.set(did, listed);
          }
          for (const cid of snapshot.proven) this.proven.add(cid);
        },
        () => undefined,
      );
    }
    return this.loaded;
  }

  /** Write the found keys, proven records and proven CIDs to the store; a write that fails is dropped. */
  private save(): Promise<void> {
    const snapshot: KeyLookupSnapshot = {
      keys: [...this.cache].filter(([, cached]) => cached.other !== null),
      records: [...this.records],
      proven: [...this.proven],
    };
    this.saving = this.saving.then(() => this.store.save(snapshot)).catch(() => undefined);
    return this.saving;
  }

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
   * Asks for one (did, kid) while a lookup for it runs await that lookup.
   */
  async keyForAt(did: string, kid: string, at: Date): Promise<FoundKey | null> {
    await this.load();
    const slot = JSON.stringify([did, kid]);
    for (;;) {
      const hit = this.cache.get(slot);
      let cached = hit !== undefined && Date.now() - hit.at < this.ttlMs ? hit : undefined;
      // A found key does not expire; one found in the records takes the DID's
      // listing again past the ttl, so a retirement since lands on it.
      if (cached === undefined && hit !== undefined && hit.other !== null) {
        cached = hit.other === undefined ? await this.relisted(slot, did, kid, hit) : hit;
      }
      if (cached !== undefined) {
        const inRecords = await fromRecords(did, kid, cached.records, at);
        if (inRecords !== null) return inRecords;
        if (cached.other !== undefined) return cached.other;
      }

      let pending = this.inFlight.get(slot);
      if (pending === undefined) {
        const started: Promise<Settled> = this.settle(slot, did, kid, at, cached).finally(() => {
          if (this.inFlight.get(slot) === started) this.inFlight.delete(slot);
        });
        this.inFlight.set(slot, started);
        pending = started;
      }
      const settled = await pending;
      // Each ask folds the records at its own time.
      const inRecords = await fromRecords(did, kid, settled.records, at);
      if (inRecords !== null) return inRecords;
      if (settled.other) return settled.other;
      if (settled.failed) throw settled.failure;
      if (settled.other === null) return null;
      // The other sources were not asked, since the lookup found the key in
      // the records at its own time: ask them now.
    }
  }

  /**
   * Ask every source, and again at each retry delay while the origin answers
   * with a miss; then remember what was settled.
   */
  private async settle(
    slot: string,
    did: string,
    kid: string,
    at: Date,
    cached: Cached | undefined,
  ): Promise<Settled> {
    const started = performance.now();
    let listed = cached === undefined;
    let settled = await this.ask(did, kid, at, cached);
    for (const after of this.retryAfterMs) {
      const missed = settled.other === null && !settled.failed && this.originBase() !== null;
      if (!missed) break;
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, started + after - performance.now())));
      settled = await this.ask(did, kid, at, undefined);
      listed = true;
    }
    if (settled.other === undefined) {
      if (listed && !settled.failed) this.remember(slot, settled.records, undefined);
    } else if (settled.other !== null || !settled.failed) {
      this.remember(slot, settled.records, settled.other);
    }
    await this.save();
    return settled;
  }

  /**
   * A found key's cached answer with the DID's current proven records: the
   * last listing while inside the ttl, else a new one. A listing that fails
   * leaves `hit` as it was.
   */
  private async relisted(slot: string, did: string, kid: string, hit: Cached): Promise<Cached> {
    let records: unknown[];
    try {
      records = await this.deviceRecords(did, kid);
    } catch {
      return hit;
    }
    this.remember(slot, records, undefined);
    await this.save();
    return this.cache.get(slot)!;
  }

  /** One round: the records (from `cached` when given, else the DID's records), then the other sources. */
  private async ask(did: string, kid: string, at: Date, cached: Cached | undefined): Promise<Settled> {
    let failure: unknown;
    let failed = false;
    let records: unknown[] = [];
    if (cached !== undefined) {
      records = cached.records;
    } else {
      try {
        // A listed record counts only once its repository proof checks.
        records = await this.deviceRecords(did, kid);
      } catch (e) {
        [failed, failure] = [true, e];
      }
    }
    if ((await fromRecords(did, kid, records, at)) !== null) {
      return { records, other: undefined, failed, failure };
    }

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
      return { records, other: { publicKey: key, source, retiredAt }, failed, failure };
    }
    return { records, other: null, failed, failure };
  }

  /**
   * `did`'s device key records whose repository proof checks, listed afresh
   * or by a listing already in flight, through this lookup's cache of proven
   * records, so each record's proof is fetched once.
   */
  async provenDeviceRecords(did: string): Promise<unknown[]> {
    await this.load();
    return this.listDeviceRecords(did);
  }

  /**
   * `did`'s proven device records: the last listing while inside the ttl, if
   * it names `kid`; else a listing, so a key published since the last one is
   * found in the records.
   */
  private async deviceRecords(did: string, kid: string): Promise<unknown[]> {
    const last = this.records.get(did);
    if (last !== undefined && Date.now() - last.at < this.ttlMs) {
      if ((await deviceKeyHistory(did, last.records)).some((k) => k.kid === kid)) return last.records;
    }
    return this.listDeviceRecords(did);
  }

  /** `did`'s proven device records from the listing in flight, else a new one. A listing that fails is not kept. */
  private listDeviceRecords(did: string): Promise<unknown[]> {
    let pending = this.listing.get(did);
    if (pending === undefined) {
      const started: Promise<unknown[]> = (async () => {
        const { fetch, resolveDid } = this.reader;
        const listed = await listRecordEntries(fetch, resolveDid, did, DEVICE_KEY_TYPE);
        const records = await provenRecords(
          fetch,
          resolveDid,
          did,
          DEVICE_KEY_TYPE,
          listed,
          this.proven,
          this.proving,
        );
        this.records.set(did, { records, at: Date.now() });
        await this.save();
        return records;
      })().finally(() => {
        if (this.listing.get(did) === started) this.listing.delete(did);
      });
      this.listing.set(did, started);
      pending = started;
    }
    return pending;
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
