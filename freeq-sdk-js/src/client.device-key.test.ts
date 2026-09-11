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

async function makeClient(store: MemoryDeviceKeyStore | null, broker = true) {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'alice',
    skipInitialBrokerRefresh: true,
    ...(broker ? { brokerUrl: BROKER, brokerToken: 'BT1' } : {}),
    ...(store ? { deviceKeyStore: store } : {}),
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

async function storedKey(recordUri?: string): Promise<StoredDeviceKey> {
  const keyPair = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
  return { keyPair, createdAt: '2026-09-11T10:00:00.000Z', ...(recordUri ? { recordUri } : {}) };
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
  const RETIRED = '2026-09-12T10:00:00.000Z';

  /** The account's device records for `stored`: its record, and a
   *  retirement signed by the key itself when `retired`. */
  async function accountRecords(stored: StoredDeviceKey, retired: boolean): Promise<unknown[]> {
    const { buildDeviceRecord, buildDeviceRetirement } = await import('./identity-records.js');
    const { recordKeyOf } = await import('./device-key.js');
    const key = await recordKeyOf(stored.keyPair);
    const record = await buildDeviceRecord(key, DID, stored.createdAt);
    if (!retired) return [record];
    const kid = await deriveKid(decodeMultibaseEd25519(key.publicKeyMultibase));
    return [record, await buildDeviceRetirement(key, DID, kid, RETIRED)];
  }

  /** A client whose record reader lists `records` for the account; how many
   *  listings it served. */
  async function clientReading(
    store: MemoryDeviceKeyStore,
    records: () => unknown[],
    freshSignIn?: boolean,
  ) {
    const { FreeqClient } = await import('./client.js');
    const { KeyLookup } = await import('./key-lookup.js');
    let listings = 0;
    const reader = {
      fetch: async (url: string): Promise<Response> => {
        if (!url.includes('com.atproto.repo.listRecords')) return new Response('{}', { status: 404 });
        listings++;
        return Response.json({
          records: records().map((value) => ({ uri: 'at://x', cid: 'bafy', value })),
        });
      },
      resolveDid: async (did: string) => ({
        id: did,
        service: [{ type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://pds.test.example' }],
      }),
    };
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
      brokerUrl: BROKER,
      brokerToken: 'BT1',
      deviceKeyStore: store,
      deviceLabel: 'Chrome',
      keyLookup: new KeyLookup(reader, null, 60_000),
      ...(freshSignIn === undefined ? {} : { freshSignIn }),
    });
    client.setSaslCredentials({ token: 't', did: DID, pdsUrl: 'https://pds.example', method: 'oauth' });
    return { client, listings: () => listings };
  }

  it('is replaced right after a new sign-in, and the new key is published', async () => {
    const old = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3old');
    const records = await accountRecords(old, true);
    const store = new MemoryDeviceKeyStore(old);
    const { client } = await clientReading(store, () => records, true);
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
    const records = await accountRecords(live, false);
    const store = new MemoryDeviceKeyStore(live);
    const { client } = await clientReading(store, () => records, true);
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(live.keyPair));
    expect((await store.load())!.keyPair).toBe(live.keyPair);
  });

  it('is kept on a connect that does not follow a new sign-in', async () => {
    const old = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3old');
    const records = await accountRecords(old, true);
    const store = new MemoryDeviceKeyStore(old);
    const { client, listings } = await clientReading(store, () => records);
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(old.keyPair));
    expect(listings()).toBe(0);
  });

  it('is kept on a reconnect after the sign-in connect', async () => {
    const stored = await storedKey('at://did:plc:alice/at.freeq.deviceKey/3k');
    let records = await accountRecords(stored, false);
    const store = new MemoryDeviceKeyStore(stored);
    const { client } = await clientReading(store, () => records, true);
    const ws = await login(client);
    expect(msgsigOf(ws)).toBe(await rawPublicB64(stored.keyPair));

    records = await accountRecords(stored, true);
    ws.close();
    await flushAsync();
    const ws2 = await login(client);
    expect(msgsigOf(ws2)).toBe(await rawPublicB64(stored.keyPair));
  });
});
