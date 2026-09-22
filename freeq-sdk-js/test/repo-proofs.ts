/**
 * A test account repository: a secp256k1 repository key, `listRecords`
 * entries carrying their uri and CID, and a `getRecord` proof for each entry
 * that commits to exactly that record, signed by the repository key.
 *
 * Each proof is its own one-leaf tree. Rkeys are chosen at MST layer 0, so a
 * one-leaf tree is a valid tree for the key it holds.
 */
import { writeCarStream } from '@atcute/car';
import { BytesWrapper, encode, toCidLink } from '@atcute/cbor';
import { CODEC_DCBOR, create } from '@atcute/cid';
import { Secp256k1PrivateKeyExportable } from '@atcute/crypto';

import { type DidDocument, recordCid } from '../src/identity-records.js';

export type RepoKeypair = Awaited<ReturnType<typeof Secp256k1PrivateKeyExportable.createKeypair>>;

export interface ListedEntry {
  uri: string;
  cid: string;
  value: unknown;
}

export interface StubRepo {
  /** The account this repository is for. */
  did: string;
  /** A DID document naming the repository key and the PDS at `pds`. */
  document(pds: string): Promise<DidDocument>;
  /** List `record` at a fresh rkey, with a proof that holds it. */
  add(collection: string, record: unknown): Promise<ListedEntry>;
  /** List `record` at a fresh rkey, served with a proof that holds `held` there instead. */
  addForged(collection: string, record: unknown, held: unknown): Promise<ListedEntry>;
  /** What `listRecords` lists for `collection`. */
  entries(collection: string): ListedEntry[];
  /** The proof served for `collection/rkey`, without counting a read. */
  car(collection: string, rkey: string): Uint8Array | undefined;
  /** How many times the proof at `collection/rkey` of `entry` was asked for. */
  proofReads(entry: ListedEntry): number;
  /** Answer a `listRecords` or `getRecord` request for this account; undefined for anything else. */
  respond(url: URL): Promise<Response | undefined>;
}

export function repoKeypair(): Promise<RepoKeypair> {
  return Secp256k1PrivateKeyExportable.createKeypair();
}

export async function stubRepo(did: string, keypair?: RepoKeypair): Promise<StubRepo> {
  const key = keypair ?? (await repoKeypair());
  const listed = new Map<string, ListedEntry[]>();
  const proofs = new Map<string, Uint8Array>();
  const reads = new Map<string, number>();
  let next = 0;

  const rkeyFor = async (collection: string): Promise<string> => {
    for (;;) {
      const rkey = `3kstub${(next++).toString(36)}`;
      const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${collection}/${rkey}`)),
      );
      // Layer 0: fewer than two leading zero bits.
      if (digest[0]! >= 0x40) return rkey;
    }
  };

  const proofHolding = async (collection: string, rkey: string, record: unknown): Promise<Uint8Array> => {
    const bytes = encode(record);
    const recordCidValue = await create(CODEC_DCBOR, bytes);
    const node = encode({
      e: [
        {
          k: new BytesWrapper(new TextEncoder().encode(`${collection}/${rkey}`)),
          p: 0,
          t: null,
          v: toCidLink(recordCidValue),
        },
      ],
      l: null,
    });
    const nodeCid = await create(CODEC_DCBOR, node);
    const unsigned = { did, version: 3, data: toCidLink(nodeCid), rev: rkey, prev: null };
    const sig = await key.sign(encode(unsigned));
    const commit = encode({ ...unsigned, sig: new BytesWrapper(sig) });
    const commitCid = await create(CODEC_DCBOR, commit);
    const entries = [
      { cid: commitCid.bytes, data: commit },
      { cid: nodeCid.bytes, data: node },
      { cid: recordCidValue.bytes, data: bytes },
    ];
    const chunks: Uint8Array[] = [];
    for await (const chunk of writeCarStream([toCidLink(commitCid)], entries)) chunks.push(chunk);
    const car = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
      car.set(chunk, offset);
      offset += chunk.length;
    }
    return car;
  };

  const list = async (collection: string, record: unknown, held: unknown): Promise<ListedEntry> => {
    const rkey = await rkeyFor(collection);
    const entry = { uri: `at://${did}/${collection}/${rkey}`, cid: await recordCid(record), value: record };
    listed.set(collection, [...(listed.get(collection) ?? []), entry]);
    proofs.set(`${collection}/${rkey}`, await proofHolding(collection, rkey, held));
    return entry;
  };

  return {
    did,
    async document(pds: string): Promise<DidDocument> {
      return {
        id: did,
        verificationMethod: [
          {
            id: `${did}#atproto`,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase: await key.exportPublicKey('multikey'),
          },
        ],
        service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds }],
      };
    },
    add: (collection, record) => list(collection, record, record),
    addForged: (collection, record, held) => list(collection, record, held),
    entries: (collection) => listed.get(collection) ?? [],
    car: (collection, rkey) => proofs.get(`${collection}/${rkey}`),
    proofReads(entry: ListedEntry): number {
      return reads.get(entry.uri.split('/').slice(3).join('/')) ?? 0;
    },
    async respond(url: URL): Promise<Response | undefined> {
      if (url.pathname === '/xrpc/com.atproto.repo.listRecords') {
        if (url.searchParams.get('repo') !== did) return undefined;
        const collection = url.searchParams.get('collection') ?? '';
        return Response.json({ records: listed.get(collection) ?? [] });
      }
      if (url.pathname === '/xrpc/com.atproto.sync.getRecord') {
        if (url.searchParams.get('did') !== did) return undefined;
        const path = `${url.searchParams.get('collection')}/${url.searchParams.get('rkey')}`;
        reads.set(path, (reads.get(path) ?? 0) + 1);
        const car = proofs.get(path);
        return car === undefined
          ? new Response('RecordNotFound', { status: 400 })
          : new Response(car, { headers: { 'content-type': 'application/vnd.ipld.car' } });
      }
      return undefined;
    },
  };
}

/**
 * A home server's record routes (`/api/v1/records…`), answered from `repos`'
 * listings and proofs. Counts requests per route. `status` answers every
 * route with that status and `headers`; `left` names accounts the server has
 * not seen (left out of a batch, 404 alone); `withheld` names `collection/rkey`
 * proofs the server cannot serve (left out of `proofs`, 502 alone); `served`
 * replaces the CAR served for a `collection/rkey`. `fetchedAt` is the listing
 * time served, unix seconds; null serves the time of the answer.
 */
export interface StubHome {
  hits: { batch: number; account: number; listing: number; proof: number };
  /** The `dids` of each batch request, in order. */
  batches: string[][];
  status: number | null;
  headers: Record<string, string>;
  left: Set<string>;
  withheld: Set<string>;
  served: Map<string, Uint8Array>;
  fetchedAt: number | null;
  /** Answer a record route; undefined for any other path. */
  respond(url: URL): Promise<Response | undefined>;
}

export function stubHome(repos: StubRepo[]): StubHome {
  const prefix = '/api/v1/records';
  const home: StubHome = {
    hits: { batch: 0, account: 0, listing: 0, proof: 0 },
    batches: [],
    status: null,
    headers: {},
    left: new Set(),
    withheld: new Set(),
    served: new Map(),
    fetchedAt: null,
    async respond(url: URL): Promise<Response | undefined> {
      if (url.pathname !== prefix && !url.pathname.startsWith(`${prefix}/`)) return undefined;
      const parts = url.pathname.slice(prefix.length).split('/').filter(Boolean).map(decodeURIComponent);
      const route = parts.length === 0 ? 'batch' : parts.length === 1 ? 'account' : parts.length === 2 ? 'listing' : 'proof';
      home.hits[route]++;
      if (route === 'batch') home.batches.push((url.searchParams.get('dids') ?? '').split(','));
      if (home.status !== null) return new Response('refused', { status: home.status, headers: home.headers });
      const seen = (did: string) => (home.left.has(did) ? undefined : repos.find((r) => r.did === did));
      const carFor = (repo: StubRepo, collection: string, rkey: string) =>
        home.withheld.has(`${collection}/${rkey}`)
          ? undefined
          : (home.served.get(`${collection}/${rkey}`) ?? repo.car(collection, rkey));
      const rkeyOf = (entry: ListedEntry) => entry.uri.split('/').pop()!;
      const fetchedAt = home.fetchedAt ?? Math.floor(Date.now() / 1000);
      const account = (repo: StubRepo, collection: string) => ({
        did: repo.did,
        collections: {
          [collection]: {
            fetched_at: fetchedAt,
            stale: false,
            records: repo.entries(collection),
            proofs: repo.entries(collection).flatMap((entry) => {
              const car = carFor(repo, collection, rkeyOf(entry));
              return car === undefined
                ? []
                : [{ rkey: rkeyOf(entry), cid: entry.cid, fetched_at: fetchedAt, car: Buffer.from(car).toString('base64') }];
            }),
          },
        },
      });
      const collection = url.searchParams.get('collection') ?? 'at.freeq.deviceKey';
      if (route === 'batch') {
        const dids = (url.searchParams.get('dids') ?? '').split(',').filter(Boolean);
        if (dids.length === 0 || dids.length > 50) return new Response('bad', { status: 400 });
        const accounts = dids.flatMap((did) => {
          const repo = seen(did);
          return repo === undefined ? [] : [account(repo, collection)];
        });
        return Response.json({ accounts });
      }
      const repo = seen(parts[0]!);
      if (repo === undefined) return new Response('not found', { status: 404 });
      if (route === 'account') return Response.json(account(repo, collection));
      if (route === 'listing') {
        return Response.json({
          did: repo.did,
          collection: parts[1],
          fetched_at: fetchedAt,
          stale: false,
          records: repo.entries(parts[1]!),
        });
      }
      if (!repo.entries(parts[1]!).some((e) => rkeyOf(e) === parts[2])) {
        return new Response('not found', { status: 404 });
      }
      const car = carFor(repo, parts[1]!, parts[2]!);
      if (car === undefined) return new Response('no proof', { status: 502 });
      return new Response(car, {
        headers: { 'content-type': 'application/vnd.ipld.car', 'x-freeq-fetched-at': String(fetchedAt) },
      });
    },
  };
  return home;
}
