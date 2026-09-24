/**
 * A client given a device key store signs with the same key on every
 * connect, and publishes that key to the account through the broker's
 * `/enroll` once, off the connect path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryDeviceKeyStore, type StoredDeviceKey } from './device-key.js';
import { decodeMultibaseEd25519, verifyEd25519 } from './did-key.js';
import { recordSignedBytes } from './identity-records.js';
import { deriveKid } from './signing.js';
import type { ListedEntry } from '../test/repo-proofs.js';

// ── WebSocket mock ────────────────────────────────────────────────

type ReadyState = 0 | 1 | 2 | 3;

class MockWebSocket {
  static CONNECTING: ReadyState = 0;
  static OPEN: ReadyState = 1;
  static CLOSING: ReadyState = 2;
  static CLOSED: ReadyState = 3;
  static instances: MockWebSocket[] = [];

  CONNECTING: ReadyState = 0;
  OPEN: ReadyState = 1;
  CLOSING: ReadyState = 2;
  CLOSED: ReadyState = 3;

  url: string;
  readyState: ReadyState = 0;
  bufferedAmount = 0;
  sent: string[] = [];

  onopen: ((ev: any) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: any) => void) | null = null;
  onerror: ((ev: any) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string) {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
    this.onclose?.({});
  }

  recv(line: string) {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

// ── the broker ────────────────────────────────────────────────────

const BROKER = 'https://auth.test.example';
const DID = 'did:plc:alice';
const CAPS = 'message-tags server-time freeq.at/msgsig';

interface EnrollCall {
  broker_token: string;
  record: Record<string, unknown>;
  signer_public_key: string;
}

let enrollCalls: EnrollCall[];
let enrollAnswer: { status: number; body: unknown };

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  enrollCalls = [];
  enrollAnswer = { status: 200, body: {} };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === `${BROKER}/enroll`) {
        enrollCalls.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify(enrollAnswer.body), { status: enrollAnswer.status });
      }
      return new Response('{}', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

/** Let anything still in flight land. */
async function pause(): Promise<void> {
  await new Promise((r) => setTimeout(r, 100));
}

/** Wait for `done`, or give up and let the assertions say what happened. */
async function until(done: () => boolean): Promise<void> {
  for (let i = 0; i < 200 && !done(); i++) await new Promise((r) => setTimeout(r, 5));
}

async function makeClient(
  store: MemoryDeviceKeyStore | null,
  broker = true,
  keyLookup?: import('./key-lookup.js').KeyLookup,
) {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'alice',
    skipInitialBrokerRefresh: true,
    ...(broker ? { brokerUrl: BROKER, brokerToken: 'BT1' } : {}),
    ...(store ? { deviceKeyStore: store } : {}),
    ...(keyLookup ? { keyLookup } : {}),
    deviceLabel: 'Chrome',
  });
  client.setSaslCredentials({ token: 't', did: DID, pdsUrl: 'https://pds.example', method: 'oauth' });
  let unpublished = 0;
  client.on('signingKeyUnpublished', () => unpublished++);
  return { client, unpublished: () => unpublished };
}

/** One authenticated registration on a fresh socket; the socket. */
async function login(client: import('./client.js').FreeqClient): Promise<MockWebSocket> {
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(`:srv CAP * LS :${CAPS}`);
  await flushAsync();
  ws.recv(`:srv CAP * ACK :${CAPS}`);
  await flushAsync();
  ws.recv(':srv 903 alice :SASL authentication successful');
  await flushAsync();
  ws.recv(':srv 001 alice :Welcome');
  await until(() => ws.sent.some((l) => l.startsWith('MSGSIG ')));
  return ws;
}

function msgsigOf(ws: MockWebSocket): string {
  return ws.sent.find((l) => l.startsWith('MSGSIG '))!.slice('MSGSIG '.length);
}

async function rawPublicB64(keyPair: CryptoKeyPair): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Real now when the file loads; the test dates count back from it. */
const NOW = Date.now();

/** `hours` before NOW, as a record writes it. */
function hoursAgo(hours: number): string {
  return new Date(NOW - hours * 3_600_000).toISOString();
}

/** A key made two days ago, inside its lifetime. */
async function storedKey(recordUri?: string): Promise<StoredDeviceKey> {
  const keyPair = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
  return { keyPair, createdAt: hoursAgo(48), ...(recordUri ? { recordUri } : {}) };
}

describe('a device key store', () => {
  it('presents the stored key, and signs with it', async () => {
    const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const { client } = await makeClient(new MemoryDeviceKeyStore(stored));
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));

    client.sendMessage('#room', 'hello');
    await until(() => ws.sent.some((l) => l.includes('PRIVMSG')));
    const line = ws.sent.find((l) => l.includes('PRIVMSG'))!;
    const kid = await deriveKid(new Uint8Array(await crypto.subtle.exportKey('raw', stored.keyPair.publicKey)));
    expect(line).toContain(`+freeq.at/sig=ed25519:${kid}:`);
    expect(enrollCalls, 'a published key is not sent again').toEqual([]);
  });

  it('gets a key when it is empty, keeps it, and presents it again', async () => {
    const store = new MemoryDeviceKeyStore();
    const save = vi.spyOn(store, 'save');
    const { client } = await makeClient(store, false);
    const ws = await login(client);
    expect(save).toHaveBeenCalledTimes(1);
    const saved = (await store.load())!;
    expect(saved.recordUri).toBeUndefined();
    expect(Number.isNaN(Date.parse(saved.createdAt))).toBe(false);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(saved.keyPair));

    ws.close();
    await flushAsync();
    const ws2 = await login(client);
    expect(msgsigOf(ws2)).toBe(msgsigOf(ws));
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('is not used at all when the client registers no key', async () => {
    const store = new MemoryDeviceKeyStore();
    const load = vi.spyOn(store, 'load');
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
      autoMsgSig: false,
      deviceKeyStore: store,
    });
    client.setSaslCredentials({ token: 't', did: DID, pdsUrl: 'https://pds.example', method: 'oauth' });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(`:srv CAP * LS :${CAPS}`);
    await flushAsync();
    ws.recv(`:srv CAP * ACK :${CAPS}`);
    await flushAsync();
    ws.recv(':srv 903 alice :SASL authentication successful');
    await flushAsync();
    ws.recv(':srv 001 alice :Welcome');
    await pause();
    expect(load).not.toHaveBeenCalled();
    expect(ws.sent.some((l) => l.startsWith('MSGSIG'))).toBe(false);
  });
});

describe('publishing the device key through the broker', () => {
  it('saves the record URI the broker answers with', async () => {
    const uri = 'at://did:plc:alice/at.freeq.deviceKey/3kdevice';
    enrollAnswer = { status: 200, body: { ok: true, uri, cid: 'bafy' } };
    const stored = await storedKey();
    const store = new MemoryDeviceKeyStore(stored);
    const { client, unpublished } = await makeClient(store);
    await login(client);
    await until(() => enrollCalls.length > 0);
    await pause();

    expect(enrollCalls).toHaveLength(1);
    const { broker_token, record, signer_public_key } = enrollCalls[0]!;
    expect(broker_token).toBe('BT1');
    expect(record.$type).toBe('at.freeq.deviceKey');
    expect(record.did).toBe(DID);
    expect(record.createdAt).toBe(stored.createdAt);
    expect(record.label).toBe('Chrome');
    expect(record.publicKeyMultibase).toBe(signer_public_key);
    const raw = decodeMultibaseEd25519(signer_public_key);
    expect(await rawPublicB64(stored.keyPair)).toBe(
      btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    );
    expect(record.kid).toBe(await deriveKid(raw));
    const { bindingSig, ...unsigned } = record;
    expect(await verifyEd25519(raw, recordSignedBytes(unsigned), bindingSig as string)).toBe(true);

    expect((await store.load())!.recordUri).toBe(uri);
    expect(unpublished()).toBe(0);
  });

  it("re-checks the client's own account once the key is published", async () => {
    const uri = 'at://did:plc:alice/at.freeq.deviceKey/3kdevice';
    enrollAnswer = { status: 200, body: { ok: true, uri, cid: 'bafy' } };
    const { KeyLookup } = await import('./key-lookup.js');
    const lookup = new KeyLookup(
      { fetch: globalThis.fetch as never, resolveDid: async () => ({ id: DID }) as never },
      null,
      3_600_000,
    );
    const refresh = vi.spyOn(lookup, 'refreshAccount');
    const store = new MemoryDeviceKeyStore(await storedKey());
    const { client } = await makeClient(store, true, lookup);
    await login(client);
    await until(() => enrollCalls.length > 0);
    await pause();

    expect((await store.load())!.recordUri, 'the key was published').toBe(uri);
    expect(refresh, 'the account it published to').toHaveBeenCalledWith(DID);
  });

  /** A key lookup on a store holding, for DID and `stored`'s kid, an answer
   *  from the origin server when `vouched`. */
  async function lookupHolding(stored: StoredDeviceKey, vouched: boolean) {
    const { KeyLookup, MemoryKeyLookupStore, SNAPSHOT_VERSION } = await import('./key-lookup.js');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', stored.keyPair.publicKey));
    const slot = JSON.stringify([DID, await deriveKid(raw)]);
    const cache = new MemoryKeyLookupStore();
    await cache.save({
      version: SNAPSHOT_VERSION,
      accounts: [],
      keys: vouched
        ? [[slot, { other: { publicKey: raw, source: 'OriginServer', retiredAt: null, expiresAt: null }, at: Date.now() }]]
        : [],
      records: [],
      refreshed: [],
      proven: [],
    });
    const lookup = new KeyLookup(
      { fetch: globalThis.fetch as never, resolveDid: async () => ({ id: DID }) as never },
      null,
      3_600_000,
      undefined,
      cache,
    );
    return { lookup, refresh: vi.spyOn(lookup, 'refreshAccount') };
  }

  it('re-lists its own account on connect when its published key reads as vouched', async () => {
    const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const { lookup, refresh } = await lookupHolding(stored, true);
    const { client } = await makeClient(new MemoryDeviceKeyStore(stored), true, lookup);
    await login(client);
    await until(() => refresh.mock.calls.length > 0);
    await pause();
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith(DID);
  });

  it('does not re-list when its published key reads as published, or its key is not published', async () => {
    enrollAnswer = { status: 403, body: { error: 'insufficient_scope' } };
    const published = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const first = await lookupHolding(published, false);
    await login((await makeClient(new MemoryDeviceKeyStore(published), true, first.lookup)).client);
    const unpublished = await storedKey();
    const second = await lookupHolding(unpublished, true);
    await login((await makeClient(new MemoryDeviceKeyStore(unpublished), true, second.lookup)).client);
    await pause();
    expect(first.refresh).not.toHaveBeenCalled();
    expect(second.refresh).not.toHaveBeenCalled();
  });

  it('reports a session that cannot publish once per connection, and tries again next connect', async () => {
    enrollAnswer = { status: 403, body: { error: 'insufficient_scope' } };
    const store = new MemoryDeviceKeyStore(await storedKey());
    const { client, unpublished } = await makeClient(store);
    const ws = await login(client);
    await until(() => unpublished() > 0);
    await pause();
    expect(unpublished()).toBe(1);
    expect(enrollCalls).toHaveLength(1);
    expect(ws.readyState, 'the session stays connected').toBe(1);

    ws.close();
    await flushAsync();
    await login(client);
    await until(() => unpublished() > 1);
    expect(unpublished()).toBe(2);
    expect(enrollCalls).toHaveLength(2);
    expect((await store.load())!.recordUri).toBeUndefined();
  });

  it('treats a 401 the same as a 403', async () => {
    enrollAnswer = { status: 401, body: 'Session expired' };
    const { client, unpublished } = await makeClient(new MemoryDeviceKeyStore(await storedKey()));
    await login(client);
    await until(() => unpublished() > 0);
    expect(unpublished()).toBe(1);
  });

  it('says nothing about any other failure, and tries again next connect', async () => {
    enrollAnswer = { status: 502, body: 'PDS rejected record' };
    const store = new MemoryDeviceKeyStore(await storedKey());
    const { client, unpublished } = await makeClient(store);
    const ws = await login(client);
    await until(() => enrollCalls.length > 0);
    await pause();
    ws.close();
    await flushAsync();
    await login(client);
    await until(() => enrollCalls.length > 1);
    await pause();
    expect(enrollCalls).toHaveLength(2);
    expect(unpublished()).toBe(0);
    expect((await store.load())!.recordUri).toBeUndefined();
  });

  it('publishes nothing without a broker session', async () => {
    const { client } = await makeClient(new MemoryDeviceKeyStore(await storedKey()), false);
    await login(client);
    await pause();
    expect(enrollCalls).toEqual([]);
  });
});

describe('a stored key the account has retired', () => {
  const RETIRED = hoursAgo(24);

  const KEY_TYPE = 'at.freeq.deviceKey';
  type StubRepo = Awaited<ReturnType<typeof import('../test/repo-proofs.js')['stubRepo']>>;

  /** `stored`'s own record, and a retirement of it signed by the key itself. */
  async function recordsOf(stored: StoredDeviceKey): Promise<{ record: unknown; retirement: unknown }> {
    const { buildDeviceRecord, buildDeviceRetirement } = await import('./identity-records.js');
    const { recordKeyOf } = await import('./device-key.js');
    const key = await recordKeyOf(stored.keyPair);
    const record = await buildDeviceRecord(key, DID, stored.createdAt);
    const kid = await deriveKid(decodeMultibaseEd25519(key.publicKeyMultibase));
    return { record, retirement: await buildDeviceRetirement(key, DID, kid, RETIRED) };
  }

  /** The account's repository holding `records`, each with its proof. */
  async function repoHolding(...records: unknown[]): Promise<StubRepo> {
    const { stubRepo } = await import('../test/repo-proofs.js');
    const repo = await stubRepo(DID);
    for (const record of records) await repo.add(KEY_TYPE, record);
    return repo;
  }

  /** A client whose key lookup reads the account from `repo`, with an empty
   *  proven set; how many listings and proofs it served. */
  async function clientReading(store: MemoryDeviceKeyStore, repo: StubRepo, freshSignIn?: boolean) {
    const { FreeqClient } = await import('./client.js');
    const { KeyLookup } = await import('./key-lookup.js');
    let listings = 0;
    let proofs = 0;
    const doc = await repo.document('https://pds.test.example');
    const reader = {
      fetch: async (url: string): Promise<Response> => {
        const parsed = new URL(url);
        if (parsed.pathname === '/xrpc/com.atproto.repo.listRecords') listings++;
        if (parsed.pathname === '/xrpc/com.atproto.sync.getRecord') proofs++;
        return (await repo.respond(parsed)) ?? new Response('{}', { status: 404 });
      },
      resolveDid: async () => doc,
    };
    const lookup = new KeyLookup(reader, null, 60_000);
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
      brokerUrl: BROKER,
      brokerToken: 'BT1',
      deviceKeyStore: store,
      deviceLabel: 'Chrome',
      keyLookup: lookup,
      ...(freshSignIn === undefined ? {} : { freshSignIn }),
    });
    client.setSaslCredentials({ token: 't', did: DID, pdsUrl: 'https://pds.example', method: 'oauth' });
    return { client, lookup, listings: () => listings, proofs: () => proofs };
  }

  it('is replaced right after a new sign-in when the key lookup holds a listing from before the retirement', async () => {
    const old = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3old');
    const { record, retirement } = await recordsOf(old);
    const repo = await repoHolding(record);
    const store = new MemoryDeviceKeyStore(old);
    const { client, lookup } = await clientReading(store, repo, true);
    // Listed before the retirement, and still inside the lookup's ttl.
    expect(await lookup.provenDeviceRecords(DID)).toHaveLength(1);
    await repo.add(KEY_TYPE, retirement);

    const ws = await login(client);
    expect(msgsigOf(ws)).not.toBe(await rawPublicB64(old.keyPair));
    expect((await store.load())!.keyPair).not.toBe(old.keyPair);
  });

  it('is replaced right after a new sign-in, and the new key is published', async () => {
    const old = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3old');
    const { record, retirement } = await recordsOf(old);
    const store = new MemoryDeviceKeyStore(old);
    const { client } = await clientReading(store, await repoHolding(record, retirement), true);
    const ws = await login(client);

    expect(msgsigOf(ws)).not.toBe(await rawPublicB64(old.keyPair));
    const now = (await store.load())!;
    expect(now.keyPair).not.toBe(old.keyPair);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(now.keyPair));
    await until(() => enrollCalls.length > 0);
    expect(enrollCalls).toHaveLength(1);
    expect(enrollCalls[0]!.record.publicKeyMultibase).toBeDefined();
  });

  it('is not replaced when it is still live', async () => {
    const live = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3live');
    const { record } = await recordsOf(live);
    const store = new MemoryDeviceKeyStore(live);
    const { client } = await clientReading(store, await repoHolding(record), true);
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(live.keyPair));
    expect((await store.load())!.keyPair).toBe(live.keyPair);
  });

  it('is not replaced by a retirement the repository does not hold, and is by one it does', async () => {
    const forgedKey = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const forged = await recordsOf(forgedKey);
    const forgedRepo = await repoHolding(forged.record);
    // Signed by the key itself, so it passes every record check but the
    // proof, which commits to a different record at its path.
    await forgedRepo.addForged(KEY_TYPE, forged.retirement, forged.record);
    const kept = new MemoryDeviceKeyStore(forgedKey);
    const first = await clientReading(kept, forgedRepo, true);
    const ws = await login(first.client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(forgedKey.keyPair));
    expect((await kept.load())!.keyPair).toBe(forgedKey.keyPair);

    MockWebSocket.instances = [];
    const genuineKey = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const genuine = await recordsOf(genuineKey);
    const replaced = new MemoryDeviceKeyStore(genuineKey);
    const second = await clientReading(
      replaced,
      await repoHolding(genuine.record, genuine.retirement),
      true,
    );
    const ws2 = await login(second.client);
    expect(msgsigOf(ws2)).not.toBe(await rawPublicB64(genuineKey.keyPair));
    expect((await replaced.load())!.keyPair).not.toBe(genuineKey.keyPair);
  });

  it('is kept on a connect that does not follow a new sign-in', async () => {
    const old = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3old');
    const { record, retirement } = await recordsOf(old);
    const store = new MemoryDeviceKeyStore(old);
    const { client, listings } = await clientReading(store, await repoHolding(record, retirement));
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(old.keyPair));
    expect(listings()).toBe(0);
  });

  it('is kept on a reconnect after the sign-in connect', async () => {
    const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    const { record, retirement } = await recordsOf(stored);
    const repo = await repoHolding(record);
    const store = new MemoryDeviceKeyStore(stored);
    const { client } = await clientReading(store, repo, true);
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));

    await repo.add(KEY_TYPE, retirement);
    ws.close();
    await flushAsync();
    const ws2 = await login(client);
    expect(msgsigOf(ws2)).toBe(await rawPublicB64(stored.keyPair));
  });

  describe('checked cold against an account of fifty device keys', () => {
    /** `stored`'s own record and 49 other keys' records, in one repository. */
    async function account(stored: StoredDeviceKey) {
      const { buildDeviceRecord } = await import('./identity-records.js');
      const { recordKeyOf } = await import('./device-key.js');
      const repo = await repoHolding();
      const values: unknown[] = [];
      const own = (await recordsOf(stored)).record;
      const ownEntry = await repo.add(KEY_TYPE, own);
      values.push(own);
      const others: { key: Awaited<ReturnType<typeof recordKeyOf>>; kid: string; entry: ListedEntry }[] = [];
      for (let i = 0; i < 49; i++) {
        const key = await recordKeyOf((await storedKey()).keyPair);
        const record = await buildDeviceRecord(key, DID, stored.createdAt);
        values.push(record);
        const entry = await repo.add(KEY_TYPE, record);
        others.push({ key, kid: await deriveKid(decodeMultibaseEd25519(key.publicKeyMultibase)), entry });
      }
      const storedKid = await deriveKid(new Uint8Array(await crypto.subtle.exportKey('raw', stored.keyPair.publicKey)));
      return { repo, values, ownEntry, others, storedKid };
    }

    it('presents the stored key and proves only its own record when nothing retires it', async () => {
      const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
      const { repo } = await account(stored);
      const store = new MemoryDeviceKeyStore(stored);
      const { client, lookup, proofs } = await clientReading(store, repo, true);
      const ws = await login(client);
      expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));
      expect(proofs(), 'no retirement names the key; its own record carries its expiry').toBe(1);

      // The check stored nothing as the account's listing.
      expect(await lookup.provenDeviceRecords(DID)).toHaveLength(50);
    });

    it('replaces a key another live key retired, proving only the records that decide it', async () => {
      const { buildDeviceRetirement } = await import('./identity-records.js');
      const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
      const { repo, ownEntry, others, storedKid } = await account(stored);
      const signer = others[7]!;
      const retirementEntry = await repo.add(
        KEY_TYPE,
        await buildDeviceRetirement(signer.key, DID, storedKid, RETIRED),
      );
      const store = new MemoryDeviceKeyStore(stored);
      const { client, lookup, proofs } = await clientReading(store, repo, true);
      const ws = await login(client);

      expect(msgsigOf(ws)).not.toBe(await rawPublicB64(stored.keyPair));
      expect((await store.load())!.keyPair).not.toBe(stored.keyPair);
      expect(proofs()).toBe(3);
      for (const entry of [ownEntry, signer.entry, retirementEntry]) {
        expect(repo.proofReads(entry)).toBe(1);
      }
      expect(await lookup.provenDeviceRecords(DID)).toHaveLength(51);
    });

    it('keeps the key when the retirement proof fails', async () => {
      const { buildDeviceRetirement } = await import('./identity-records.js');
      const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
      const { repo, others, storedKid } = await account(stored);
      const signer = others[3]!;
      const retirement = await buildDeviceRetirement(signer.key, DID, storedKid, RETIRED);
      await repo.addForged(KEY_TYPE, retirement, (await recordsOf(stored)).record);
      const store = new MemoryDeviceKeyStore(stored);
      const { client, proofs } = await clientReading(store, repo, true);
      const ws = await login(client);

      expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));
      expect((await store.load())!.keyPair).toBe(stored.keyPair);
      expect(proofs()).toBe(3);
    });

    it('keeps the key when its retirement was signed by a key already retired, as the full fold does', async () => {
      const { buildDeviceRetirement, deviceKeyHistory } = await import('./identity-records.js');
      const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
      const { repo, values, others, storedKid } = await account(stored);
      const signer = others[11]!;
      const signerGone = await buildDeviceRetirement(signer.key, DID, signer.kid, hoursAgo(46));
      const late = await buildDeviceRetirement(signer.key, DID, storedKid, RETIRED);
      await repo.add(KEY_TYPE, signerGone);
      await repo.add(KEY_TYPE, late);
      const store = new MemoryDeviceKeyStore(stored);
      const { client, proofs } = await clientReading(store, repo, true);
      const ws = await login(client);

      const full = (await deviceKeyHistory(DID, [...values, signerGone, late])).find((k) => k.kid === storedKid);
      // Only its expiry, which is still ahead.
      expect(full?.retiredAt).toEqual(full?.expiresAt);
      expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));
      expect((await store.load())!.keyPair).toBe(stored.keyPair);
      expect(proofs()).toBe(4);
    });
  });
});
