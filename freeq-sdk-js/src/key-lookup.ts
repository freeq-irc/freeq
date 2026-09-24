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
  fetchAccounts,
  listRecordEntries,
  listRecordEntriesDated,
  provenRecords,
  retirementClosure,
} from './identity-records.js';
import { deriveKid } from './signing.js';

/** Where a key was found. */
export type KeySource = 'IdentityRecord' | 'DidDocument' | 'OriginServer';

/** An ed25519 public key (32 bytes) that hashes to the kid asked for, and its source. */
export interface FoundKey {
  publicKey: Uint8Array;
  source: KeySource;
  /** When the key stopped counting, unix seconds. From the signer's records:
   *  its retirement or expiry, only when at or before the instant asked
   *  about. From the origin server: the earlier of its removal and its
   *  expiry, which may be later than that instant. */
  retiredAt: number | null;
  /** When the key stops counting, unix seconds: its record's expiry, told
   *  whether or not it has passed. Only the records give one. */
  expiresAt: number | null;
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
 * What a lookup keeps between page loads: each account's proven device
 * records once (`accounts`); each (DID, kid) answer, a key found or a miss
 * with the time it was settled (a miss answers for the ttl), reading its
 * DID's records from `accounts`; when each DID's held listing was taken and
 * when it was last listed for a key lookup; and the CIDs of records whose
 * proof checked. Failures and lookups in flight are not kept. A snapshot of
 * another `version` is not read.
 */
export interface KeyLookupSnapshot {
  version: typeof SNAPSHOT_VERSION;
  accounts: [string, unknown[]][];
  keys: [string, { other: FoundKey | null | undefined; at: number }][];
  records: [string, number][];
  refreshed: [string, number][];
  proven: string[];
}

/** The snapshot shape this code reads and writes. */
export const SNAPSHOT_VERSION = 2;

/** The least time between two writes of a lookup's snapshot. */
export const SAVE_EVERY_MS = 2_000;

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
 * Only the origin is asked again; the first ask listed the records.
 */
export const MISS_RETRY_AFTER_MS: readonly number[] = [2_000, 6_000, 15_000];

/**
 * How recently a line must have been signed for its missing key to be asked
 * again at the retry delays: a line that just arrived may name a key its
 * server is still fetching; a replayed one settles on its first miss.
 */
export const FRESH_LINE_MS = 120_000;

/** A key to prefetch: its DID and kid, and whether the DID is a server's,
 *  which has no device records. */
export type KeyPair = [did: string, kid: string, server?: boolean];

/** Most keys one request to the origin's batch key route names. */
export const MAX_KEYS_PER_REQUEST = 50;

/**
 * Looks keys up by (DID, kid). A miss, when every source answered without the
 * key, is cached for `ttlMs`; a key found is cached without expiry, and one
 * found in the records takes the DID's listing again once that is older than
 * `ttlMs`, so a retirement since lands on it. A miss the origin answered is
 * asked again at the origin at each of `retryAfterMs` before it is
 * remembered. A signer's device records are listed and proven per DID, shared
 * by the lookups for every kid of that DID; a kid the held listing lacks lists
 * the DID again at most once per `ttlMs`. Found keys, proven records, listing
 * times and proven CIDs are kept in `store`, so a lookup built on the same
 * store starts with them.
 */
export class KeyLookup {
  private readonly cache = new Map<string, Cached>();
  /** One lookup in flight per (DID, kid). */
  private readonly inFlight = new Map<string, Promise<Settled>>();
  /** Each DID's proven device records as last listed, kept for `ttlMs`. */
  private readonly records = new Map<string, { records: unknown[]; at: number }>();
  /** When each DID was last listed for a key lookup, so a kid the held
   *  listing lacks lists it again at most once per `ttlMs`. */
  private readonly refreshed = new Map<string, number>();
  /** One listing, with its proofs, in flight per DID. */
  private readonly listing = new Map<string, Promise<unknown[]>>();
  /** CIDs of records whose repository proof has checked, so each is fetched once. */
  private readonly proven = new Set<string>();
  /** Proofs in flight by record CID, so listings racing on a record share one fetch. */
  private readonly proving = new Map<string, Promise<boolean>>();
  /** One prefetch in flight per DID, so prefetches racing on an account share one request. */
  private readonly prefetching = new Map<string, Promise<void>>();
  /** One batch key request in flight per (DID, kid), so prefetches racing on
   *  a key share one request. */
  private readonly prefetchingKeys = new Map<string, Promise<void>>();
  /** Per DID, how many times `refreshAccount` has dropped its answers. */
  private readonly refreshes = new Map<string, number>();
  private defaultOrigin: string | null = null;
  /** The store's snapshot, taken in once before the first lookup. */
  private loaded: Promise<void> | null = null;
  /** Writes to the store, one after another. */
  private saving: Promise<void> = Promise.resolve();
  /** When the store was last written, and the write held back until two
   *  seconds after it. */
  private lastWrite = -Infinity;
  private heldWrite: ReturnType<typeof setTimeout> | null = null;
  /** Set by `flush`: nothing is written after it. */
  private flushed = false;
  /** The origin answered its batch key route with a 404: a server from
   *  before it, asked key by key for the rest of this lookup's life. */
  private batchRouteMissing = false;

  /** `originBase` is the origin server's base URL; the reader's `fetch` serves its requests. */
  constructor(
    readonly reader: RecordReader,
    private readonly givenOrigin: string | null,
    private readonly ttlMs: number,
    private readonly retryAfterMs: readonly number[] = MISS_RETRY_AFTER_MS,
    private readonly store: KeyLookupStore = new MemoryKeyLookupStore(),
  ) {}

  /** Take in what the store holds, once; a store that cannot be read, or a
   *  snapshot of another shape, leaves the cache as it is. */
  private load(): Promise<void> {
    if (this.loaded === null) {
      this.loaded = this.store.load().then(
        (snapshot) => {
          if (snapshot === null || snapshot.version !== SNAPSHOT_VERSION) return;
          const accounts = new Map(snapshot.accounts);
          const recordsOf = (did: string) => accounts.get(did) ?? [];
          for (const [slot, answer] of snapshot.keys) {
            const did = (JSON.parse(slot) as [string, string])[0];
            if (!this.cache.has(slot)) this.cache.set(slot, { ...answer, records: recordsOf(did) });
          }
          for (const [did, at] of snapshot.records) {
            if (!this.records.has(did)) this.records.set(did, { records: recordsOf(did), at });
          }
          for (const [did, at] of snapshot.refreshed) {
            if (!this.refreshed.has(did)) this.refreshed.set(did, at);
          }
          for (const cid of snapshot.proven) this.proven.add(cid);
        },
        () => undefined,
      );
    }
    return this.loaded;
  }

  /** What the store is given: each account's records once, the DID's held
   *  listing where there is one, else the records its first answer holds. */
  private snapshot(): KeyLookupSnapshot {
    const accounts = new Map<string, unknown[]>();
    for (const [did, listed] of this.records) accounts.set(did, listed.records);
    const keys: KeyLookupSnapshot['keys'] = [];
    for (const [slot, cached] of this.cache) {
      const did = (JSON.parse(slot) as [string, string])[0];
      if (!accounts.has(did)) accounts.set(did, cached.records);
      keys.push([slot, { other: cached.other, at: cached.at }]);
    }
    return {
      version: SNAPSHOT_VERSION,
      accounts: [...accounts],
      keys,
      records: [...this.records].map(([did, listed]) => [did, listed.at]),
      refreshed: [...this.refreshed],
      proven: [...this.proven],
    };
  }

  /**
   * Write the snapshot to the store, at most once every `SAVE_EVERY_MS`: a
   * save inside that time is held and written when it ends, with whatever is
   * held then. Nothing is written after `flush`. A write that fails is dropped.
   */
  private save(): Promise<void> {
    if (this.flushed || this.heldWrite !== null) return Promise.resolve();
    const wait = this.lastWrite + SAVE_EVERY_MS - Date.now();
    if (wait <= 0) return this.write();
    this.heldWrite = setTimeout(() => {
      this.heldWrite = null;
      if (!this.flushed) void this.write();
    }, wait);
    return Promise.resolve();
  }

  private write(): Promise<void> {
    this.lastWrite = Date.now();
    const snapshot = this.snapshot();
    this.saving = this.saving.then(() => this.store.save(snapshot)).catch(() => undefined);
    return this.saving;
  }

  /**
   * Write a held save now, wait for every write to land, and write nothing
   * after. Called before another lookup on the same store loads it, so that
   * load sees this lookup's last answers and no later write of this one
   * replaces what the other writes.
   */
  async flush(): Promise<void> {
    if (!this.flushed) {
      this.flushed = true;
      if (this.heldWrite !== null) {
        clearTimeout(this.heldWrite);
        this.heldWrite = null;
        void this.write();
      }
    }
    await this.saving;
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
   * `retry: false` settles a fresh line's miss without the retry delays.
   * `server: true` names a server's DID, which has no device records: none
   * are listed.
   */
  async keyForAt(
    did: string,
    kid: string,
    at: Date,
    options: { retry?: boolean; server?: boolean } = {},
  ): Promise<FoundKey | null> {
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
        const started: Promise<Settled> = this.settle(
          slot,
          did,
          kid,
          at,
          cached,
          options.retry !== false,
          options.server === true,
        ).finally(() => {
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
    retry: boolean,
    server: boolean,
  ): Promise<Settled> {
    const started = performance.now();
    const refreshes = this.refreshes.get(did);
    const listed = cached === undefined;
    let settled = await this.ask(did, kid, at, cached?.records ?? (server ? [] : undefined));
    // Only a line signed just now is asked about again.
    const retries = retry && Date.now() - at.getTime() <= FRESH_LINE_MS ? this.retryAfterMs : [];
    for (const after of retries) {
      const missed = settled.other === null && !settled.failed && this.originBase() !== null;
      if (!missed) break;
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, started + after - performance.now())));
      settled = await this.ask(did, kid, at, settled.records, true);
    }
    if (settled.other === undefined) {
      if (listed && !settled.failed) this.remember(slot, settled.records, undefined);
    } else if ((settled.other !== null || !settled.failed) && this.refreshes.get(did) === refreshes) {
      // An account refreshed since this lookup began has dropped the answers
      // its new records can change; one from before stays dropped.
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

  /**
   * One round: the records (`held` when given, else the DID's records), then
   * the other sources, or the origin alone when `originOnly`.
   */
  private async ask(
    did: string,
    kid: string,
    at: Date,
    held: unknown[] | undefined,
    originOnly = false,
  ): Promise<Settled> {
    let failure: unknown;
    let failed = false;
    let records: unknown[] = [];
    if (held !== undefined) {
      records = held;
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
    if (!originOnly && did.startsWith('did:web:')) {
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
      return {
        records,
        other: { publicKey: key, source, retiredAt, expiresAt: null },
        failed,
        failure,
      };
    }
    return { records, other: null, failed, failure };
  }

  /**
   * Ask the origin's batch key route for the keys of `pairs`, in one request
   * per 50, for the pairs no answer is held for: not a key found, not a miss
   * inside the ttl, not a key the DID's held records name. A pair another
   * prefetch is asking for is not asked again; its answer is waited for. A
   * key the origin answers is kept as its answer; a pair it leaves out is
   * kept as a miss only when the DID's records are held (or it is a did:key
   * or a server's DID, which have none). A request that fails, or is
   * answered 429 or 5xx, keeps nothing, since it said nothing about the keys.
   * Against a server without the route (a 404) nothing is asked. Never fails.
   */
  async prefetchKeys(pairs: KeyPair[]): Promise<void> {
    await this.load();
    const base = this.originBase();
    if (base === null || this.batchRouteMissing) return;
    const now = Date.now();
    const asked: KeyPair[] = [];
    const seen = new Set<string>();
    const waits = new Set<Promise<void>>();
    let done!: () => void;
    const mine = new Promise<void>((resolve) => (done = resolve));
    for (const [did, kid, server] of pairs) {
      const slot = JSON.stringify([did, kid]);
      if (seen.has(slot) || this.inFlight.has(slot)) continue;
      seen.add(slot);
      const hit = this.cache.get(slot);
      if (hit !== undefined && hit.other !== undefined && (hit.other !== null || now - hit.at < this.ttlMs)) {
        continue;
      }
      const held = server ? undefined : (this.records.get(did)?.records ?? hit?.records);
      if (held !== undefined && (await fromRecords(did, kid, held, new Date(now))) !== null) continue;
      // Read after the await above, so a prefetch that began meanwhile is seen.
      const other = this.prefetchingKeys.get(slot);
      if (other !== undefined) {
        waits.add(other);
        continue;
      }
      this.prefetchingKeys.set(slot, mine);
      asked.push([did, kid, server]);
    }
    try {
      await this.askBatchRoute(base, asked);
    } finally {
      for (const [did, kid] of asked) {
        const slot = JSON.stringify([did, kid]);
        if (this.prefetchingKeys.get(slot) === mine) this.prefetchingKeys.delete(slot);
      }
      done();
    }
    await Promise.all(waits);
  }

  /** `prefetchKeys`' requests for the pairs it asks. */
  private async askBatchRoute(base: string, asked: KeyPair[]): Promise<void> {
    let kept = false;
    for (let i = 0; i < asked.length; i += MAX_KEYS_PER_REQUEST) {
      const chunk = asked.slice(i, i + MAX_KEYS_PER_REQUEST);
      let answered: Map<string, OriginAnswer>;
      try {
        const found = await this.fromBatchRoute(base, chunk);
        if (found === null) return;
        answered = found;
      } catch {
        continue;
      }
      for (const [did, kid, server] of chunk) {
        const slot = JSON.stringify([did, kid]);
        const answer = answered.get(slot);
        const records = server ? [] : (this.records.get(did)?.records ?? []);
        let other: FoundKey | null = null;
        if (answer?.key && answer.key.length === 32 && (await deriveKid(answer.key)) === kid) {
          other = { publicKey: answer.key, source: 'OriginServer', retiredAt: answer.retiredAt, expiresAt: null };
        }
        // A miss counts only when the account's records were read: without
        // them, the line's own lookup lists the account.
        if (other === null && !server && !this.records.has(did) && !did.startsWith('did:key:')) continue;
        this.remember(slot, records, other);
        kept = true;
      }
    }
    if (kept) await this.save();
  }

  /**
   * The origin's batch key route's answer for `pairs`, by slot; null when the
   * origin has no such route (a 404), which it remembers. Throws on anything
   * else that is not a 200.
   */
  private async fromBatchRoute(
    base: string,
    pairs: KeyPair[],
  ): Promise<Map<string, OriginAnswer> | null> {
    const keys = pairs.map(([did, kid]) => `${encodeURIComponent(did)}/${encodeURIComponent(kid)}`).join(',');
    const res = await this.reader.fetch(`${base.replace(/\/+$/, '')}/api/v1/signing-keys?keys=${keys}`);
    if (res.status === 404) {
      this.batchRouteMissing = true;
      return null;
    }
    if (!res.ok) throw new Error(`the origin key store answered ${res.status}`);
    const body = (await res.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) throw new Error('the origin answer is not a key list');
    const out = new Map<string, OriginAnswer>();
    for (const entry of body.keys as Record<string, unknown>[]) {
      if (typeof entry !== 'object' || entry === null) continue;
      if (typeof entry.did !== 'string' || typeof entry.kid !== 'string') continue;
      const answer = originAnswer(entry);
      if (answer !== null) out.set(JSON.stringify([entry.did, entry.kid]), answer);
    }
    return out;
  }

  /**
   * Take the device records of `dids` from the origin, the home server, in
   * one request per 50 accounts, for the DIDs whose listing is not held
   * inside the ttl, and that can have one at all (a did:key is the key, so
   * it is never asked for): each account the server returns is proven from the
   * proofs it carries (a record whose proof is missing or fails is proven at
   * the PDS) and kept with the server's listing time. An account the server
   * leaves out is not read here; its first lookup lists it. Nothing is asked
   * without an origin. Never fails.
   */
  async prefetch(dids: string[]): Promise<void> {
    await this.load();
    const home = this.originBase();
    if (home === null) return;
    const now = Date.now();
    const waits: Promise<void>[] = [];
    const asked: string[] = [];
    for (const did of new Set(dids)) {
      // A did:key has no repository to list: the DID is the key.
      if (did.startsWith('did:key:')) continue;
      const inFlight = this.prefetching.get(did);
      if (inFlight !== undefined) {
        waits.push(inFlight);
        continue;
      }
      const last = this.records.get(did);
      if (this.listing.has(did) || (last !== undefined && now - last.at < this.ttlMs)) continue;
      asked.push(did);
    }
    if (asked.length > 0) {
      const started: Promise<void> = this.prefetchAccounts(home, asked).finally(() => {
        for (const did of asked) if (this.prefetching.get(did) === started) this.prefetching.delete(did);
      });
      for (const did of asked) this.prefetching.set(did, started);
      waits.push(started);
    }
    await Promise.all(waits);
  }

  private async prefetchAccounts(home: string, dids: string[]): Promise<void> {
    const { fetch, resolveDid } = this.reader;
    const accounts = await fetchAccounts(fetch, home, dids, DEVICE_KEY_TYPE);
    await Promise.all(
      [...accounts].map(async ([did, account]) => {
        const records = await provenRecords(
          fetch,
          resolveDid,
          did,
          DEVICE_KEY_TYPE,
          account.entries,
          this.proven,
          this.proving,
          account.proofs,
        );
        const at = Math.min(account.fetchedAt * 1000, Date.now());
        // A listing for key lookups, like the one `deviceRecords` makes,
        // unless a newer one is held.
        if (this.keepListing(did, records, at) === records) this.refreshed.set(did, at);
      }),
    ).catch(() => undefined);
    if (accounts.size > 0) await this.save();
  }

  /**
   * `did`'s device key records whose repository proof checks: the held
   * listing while inside the ttl, else a listing, through this lookup's cache
   * of proven records, so each record's proof is fetched once.
   */
  async provenDeviceRecords(did: string): Promise<unknown[]> {
    await this.load();
    const last = this.records.get(did);
    if (last !== undefined && Date.now() - last.at < this.ttlMs) return last.records;
    this.refreshed.set(did, Date.now());
    return this.listDeviceRecords(did);
  }

  /**
   * `did`'s proven device records listed afresh at the PDS, for a caller that
   * must see a record written since the last listing: the home server's copy
   * may predate it.
   */
  async refreshDeviceRecords(did: string): Promise<unknown[]> {
    await this.load();
    this.refreshed.set(did, Date.now());
    return this.listDeviceRecords(did, true);
  }

  /**
   * The proven records that decide whether `did`'s device key `kid` is
   * retired (`retirementClosure`), from a new listing. Only those records are
   * proven, through this lookup's proven set; the listing is not kept as the
   * account's records, since it holds only part of them.
   */
  async provenRetirementClosure(did: string, kid: string): Promise<unknown[]> {
    await this.load();
    const { fetch, resolveDid } = this.reader;
    const home = this.originBase();
    const listed = await listRecordEntries(fetch, resolveDid, did, DEVICE_KEY_TYPE, home);
    const closure = retirementClosure(did, kid, listed, (entry) => entry.value);
    if (closure.length === 0) return [];
    const records = await provenRecords(
      fetch,
      resolveDid,
      did,
      DEVICE_KEY_TYPE,
      closure,
      this.proven,
      this.proving,
      undefined,
      home,
    );
    await this.save();
    return records;
  }

  /**
   * `did`'s proven device records: the last listing while inside the ttl, if
   * it names `kid` or the DID was already listed for a lookup inside the ttl;
   * else a listing, so a key published since is found within the ttl. A
   * `did:key` has none, and is answered without a request.
   */
  private async deviceRecords(did: string, kid: string): Promise<unknown[]> {
    // A did:key has no repository to list: the DID is the key. Answering
    // before anything is looked up or asked for keeps the records step from
    // making a request the server can only answer empty.
    if (did.startsWith('did:key:')) return [];
    const last = this.records.get(did);
    const now = Date.now();
    if (last !== undefined && now - last.at < this.ttlMs) {
      if ((await deviceKeyHistory(did, last.records)).some((k) => k.kid === kid)) return last.records;
      const refreshed = this.refreshed.get(did);
      if (refreshed !== undefined && now - refreshed < this.ttlMs) return last.records;
    }
    this.refreshed.set(did, now);
    return this.listDeviceRecords(did);
  }

  /**
   * `did`'s proven device records from the listing in flight, else a new one.
   * With an origin, the home server is asked first: for an account with no
   * listing held, its records and proofs together; for one held, the listing
   * alone, since its proofs are mostly proven already, then each new
   * record's proof. Whatever it does not serve is read from the PDS. A
   * listing that fails is not kept.
   *
   * A prefetch in flight for the account is waited for first, and its
   * listing used when it brought one.
   *
   * `direct` lists at the PDS, the home server skipped, and always starts a
   * new listing, which lookups starting meanwhile join. Either way a listing
   * is kept only if none newer is held (`keepListing`), and is dated from
   * before its request.
   */
  private listDeviceRecords(did: string, direct = false): Promise<unknown[]> {
    // A prefetch in flight for the account brings its listing: wait for it,
    // and use that listing rather than asking again.
    const prefetching = direct ? undefined : this.prefetching.get(did);
    if (prefetching !== undefined) {
      return prefetching.then(() => {
        const held = this.records.get(did);
        if (held !== undefined && Date.now() - held.at < this.ttlMs) return held.records;
        return this.listDeviceRecords(did);
      });
    }
    let pending = direct ? undefined : this.listing.get(did);
    if (pending === undefined) {
      const started: Promise<unknown[]> = (async () => {
        const { fetch, resolveDid } = this.reader;
        const home = direct ? null : this.originBase();
        if (home !== null && !this.records.has(did)) {
          const account = (await fetchAccounts(fetch, home, [did], DEVICE_KEY_TYPE)).get(did);
          if (account !== undefined) {
            const records = await provenRecords(
              fetch,
              resolveDid,
              did,
              DEVICE_KEY_TYPE,
              account.entries,
              this.proven,
              this.proving,
              account.proofs,
            );
            const kept = this.keepListing(did, records, Math.min(account.fetchedAt * 1000, Date.now()));
            await this.save();
            return kept;
          }
        }
        const asked = Date.now();
        const listed = await listRecordEntriesDated(fetch, resolveDid, did, DEVICE_KEY_TYPE, home);
        // What the home server hands over is dated with its own listing time,
        // never later than now, as the batch route's is; a PDS listing with
        // this client's time from before the request.
        const at = listed.fetchedAt === null ? asked : Math.min(listed.fetchedAt * 1000, Date.now());
        const records = await provenRecords(
          fetch,
          resolveDid,
          did,
          DEVICE_KEY_TYPE,
          listed.entries,
          this.proven,
          this.proving,
          undefined,
          home,
        );
        const kept = this.keepListing(did, records, at);
        await this.save();
        return kept;
      })().finally(() => {
        if (this.listing.get(did) === started) this.listing.delete(did);
      });
      this.listing.set(did, started);
      pending = started;
    }
    return pending;
  }

  /**
   * Clear a remembered miss for `(did, kid)`, so the next lookup asks again.
   * A key found stays cached.
   *
   * The DID's refresh time goes too, or the next lookup would answer a kid
   * the held listing lacks from that listing and never see a record
   * published since — which is what a caller forgetting a miss is after.
   * `relist: false` keeps it, for a caller whose miss was listed just now.
   */
  forget(did: string, kid: string, options: { relist?: boolean } = {}): void {
    const slot = JSON.stringify([did, kid]);
    if (this.cache.get(slot)?.other !== null) return;
    this.cache.delete(slot);
    if (options.relist !== false) this.refreshed.delete(did);
  }

  /** Whether a miss for `(did, kid)` is remembered inside the ttl. Reads the
   *  stored snapshot first. */
  async holdsMiss(did: string, kid: string): Promise<boolean> {
    await this.load();
    const hit = this.cache.get(JSON.stringify([did, kid]));
    return hit !== undefined && hit.other === null && Date.now() - hit.at < this.ttlMs;
  }

  /**
   * Whether the answer held for `(did, kid)` came from the origin server: a
   * key the server vouched for, which a listing of the account's records
   * could turn into a published one. Reads the stored snapshot first.
   */
  async holdsOriginAnswer(did: string, kid: string): Promise<boolean> {
    await this.load();
    return this.cache.get(JSON.stringify([did, kid]))?.other?.source === 'OriginServer';
  }

  /**
   * List `did`'s account at the PDS now, however recently it was listed:
   * this client has just published a device key record of its own, and the
   * home server's copy may predate it. Then drops the cached answers a new
   * record can change — a remembered miss, and one the origin server
   * answered — including any a lookup already running would keep. An answer
   * found in the records stands. A listing that fails changes nothing.
   * Never rejects.
   */
  async refreshAccount(did: string): Promise<void> {
    await this.load();
    if (did.startsWith('did:key:')) return;
    try {
      await this.listDeviceRecords(did, true);
    } catch {
      return;
    }
    this.refreshed.set(did, Date.now());
    this.refreshes.set(did, (this.refreshes.get(did) ?? 0) + 1);
    for (const [slot, cached] of this.cache) {
      if ((JSON.parse(slot) as [string, string])[0] !== did) continue;
      if (cached.other === null || cached.other?.source === 'OriginServer') this.cache.delete(slot);
    }
    await this.save();
  }

  /**
   * Hold `records`, listed at `at`, as `did`'s listing unless a newer one is
   * held; the listing held after, for a lookup to use.
   */
  private keepListing(did: string, records: unknown[], at: number): unknown[] {
    const held = this.records.get(did);
    if (held !== undefined && held.at > at) return held.records;
    this.records.set(did, { records, at });
    return records;
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

  /**
   * The key the origin holds for `(did, kid)`, and when it stopped counting:
   * through the batch key route, or the per-kid route on a server without it.
   */
  private async fromOrigin(
    base: string,
    did: string,
    kid: string,
  ): Promise<[Uint8Array | null, number | null]> {
    if (!this.batchRouteMissing) {
      const answered = await this.fromBatchRoute(base, [[did, kid]]);
      if (answered !== null) {
        const answer = answered.get(JSON.stringify([did, kid]));
        return answer === undefined ? [null, null] : [answer.key, answer.retiredAt];
      }
    }
    const path = `/api/v1/signing-keys/${encodeURIComponent(did)}/${encodeURIComponent(kid)}`;
    const res = await this.reader.fetch(`${base.replace(/\/+$/, '')}${path}`);
    if (res.status === 404) return [null, null];
    if (!res.ok) throw new Error(`the origin key store answered ${res.status}`);
    const answer = originAnswer((await res.json()) as Record<string, unknown>);
    if (answer === null) throw new Error('the origin answer is not a key');
    return [answer.key, answer.retiredAt];
  }
}

/** A key the origin answered, and when it stopped counting (unix seconds). */
interface OriginAnswer {
  /** Null when it does not decode: refused like a wrong key. */
  key: Uint8Array | null;
  retiredAt: number | null;
}

/**
 * One key of an origin's answer: its bytes, and the earlier of its
 * `removed_at` and `expires_at`. A server from before expiries sends no
 * `expires_at`, and its keys are taken as not expiring. Null when the answer
 * carries no key.
 */
function originAnswer(entry: Record<string, unknown>): OriginAnswer | null {
  if (typeof entry.public_key !== 'string') return null;
  const dates = [entry.removed_at, entry.expires_at].filter((d): d is number => typeof d === 'number');
  // A key that does not decode is refused like a wrong one.
  return {
    key: base64UrlDecode(entry.public_key),
    retiredAt: dates.length === 0 ? null : Math.min(...dates),
  };
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
    // Not filtered by `at`: the date the key will expire, too.
    expiresAt: Math.floor(match.expiresAt.getTime() / 1000),
  };
}

/**
 * A `ResolveDid` for did:plc (the PLC directory) and did:web, built on
 * `@atcute/identity-resolver`. Anything else is refused.
 *
 * The document is kept for `ttlMs` (an hour by default) per DID, so the
 * readers and lookups built on one resolver resolve an account once an hour
 * rather than once per proof. The library keeps no cache of its own. A
 * rotation is learned at most a ttl late; a proof that then fails its check
 * already falls through to a fresh one, the same bound the records take.
 */
export function makeDidResolver(
  options: { fetch?: typeof globalThis.fetch; plcUrl?: string; ttlMs?: number } = {},
): ResolveDid {
  const resolver = new CompositeDidDocumentResolver({
    methods: {
      plc: new PlcDidDocumentResolver({ fetch: options.fetch, apiUrl: options.plcUrl }),
      web: new WebDidDocumentResolver({ fetch: options.fetch }),
    },
  });
  const ttlMs = options.ttlMs ?? 3_600_000;
  const held = new Map<string, { doc: DidDocument; at: number }>();
  const resolving = new Map<string, Promise<DidDocument>>();
  return async (did: string): Promise<DidDocument> => {
    if (!did.startsWith('did:plc:') && !did.startsWith('did:web:')) {
      throw new Error(`no resolver for ${did}`);
    }
    const last = held.get(did);
    if (last !== undefined && Date.now() - last.at < ttlMs) return last.doc;
    const inFlight = resolving.get(did);
    if (inFlight !== undefined) return inFlight;
    const started: Promise<DidDocument> = resolver
      .resolve(did as `did:plc:${string}` | `did:web:${string}`)
      .then((doc) => {
        const document = doc as unknown as DidDocument;
        // A failed resolve throws instead, and nothing is kept.
        if (ttlMs > 0) held.set(did, { doc: document, at: Date.now() });
        return document;
      })
      .finally(() => {
        if (resolving.get(did) === started) resolving.delete(did);
      });
    resolving.set(did, started);
    return started;
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
