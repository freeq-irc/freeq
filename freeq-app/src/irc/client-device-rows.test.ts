// @vitest-environment jsdom
/**
 * The Devices list reads the account's device records through the key lookup
 * built at connect, so records it already holds cost no request; a refresh
 * lists the account again.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true, configurable: true });

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  handlers = new Map<string, Handler[]>();
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: unknown) {}
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  join() { /* not under test */ }
  requestHistory() { /* not under test */ }
  requestHistoryTargets() { /* not under test */ }
  setSaslCredentials() { /* not under test */ }
  connect() { /* no-op */ }
  disconnect() { /* no-op */ }
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@freeq/sdk')>()),
  FreeqClient: MockFreeqClient,
  IndexedDbDeviceKeyStore: class {},
}));

const bridge = await import('./client');
const { useStore } = await import('../store');
const { IndexedDbKeyLookupStore } = await import('../lib/key-lookup-store');
const { buildDeviceRecord, buildDeviceRetirement, recordKeyOf } = await import('@freeq/sdk');

const DID = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const PDS = 'https://pds.example';

const plcDoc = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  alsoKnownAs: ['at://devices.test'],
  verificationMethod: [
    {
      id: `${DID}#atproto`,
      type: 'Multikey',
      controller: DID,
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    },
  ],
  service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
};

let requests: string[] = [];

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  localStorage.clear();
  useStore.getState().reset();
  requests = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = decodeURIComponent(String(input instanceof Request ? input.url : input));
      requests.push(url);
      if (url === `https://plc.directory/${DID}`) return Response.json(plcDoc);
      if (url.startsWith(`${PDS}/xrpc/com.atproto.repo.listRecords`)) return Response.json({ records: [] });
      return new Response('not found', { status: 404 });
    }),
  );
  bridge.setSaslCredentials('t', DID, '', 'web-token');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const readsRecords = (url: string) =>
  url.includes('com.atproto.repo.listRecords') || url.includes('com.atproto.sync.getRecord');

describe('the Devices rows', () => {
  it('come from the records the key lookup holds, with no listing and no proof', async () => {
    const pair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    // Ten days ago, inside the key's lifetime.
    const createdAt = new Date(Date.now() - 10 * 24 * 3_600_000).toISOString();
    const record = await buildDeviceRecord(await recordKeyOf(pair), DID, createdAt, 'Work laptop');
    // What an earlier page load's lookup kept for this account, a minute ago.
    await new IndexedDbKeyLookupStore().save({
      keys: [],
      records: [[DID, { records: [record], at: Date.now() - 60_000 }]],
      proven: [],
    });
    bridge.connect('wss://test/irc', 'me', []);

    const rows = await bridge.listDeviceRows();
    expect(rows.map((row) => row.name)).toEqual(['Work laptop']);
    expect(requests.filter(readsRecords)).toEqual([]);

    await bridge.listDeviceRows({ refresh: true });
    expect(requests.some((url) => url.includes('com.atproto.repo.listRecords'))).toBe(true);
  });

  it('list the five most recently signed-out keys and every active one', async () => {
    const HOUR_MS = 60 * 60 * 1000;
    const device = async (label: string, createdAt: string) => {
      const pair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
      const key = await recordKeyOf(pair);
      return { key, record: await buildDeviceRecord(key, DID, createdAt, label) };
    };
    // The active key is the oldest, so a cap on the whole list would drop it.
    const daysAgo = (days: number) => new Date(Date.now() - days * 24 * HOUR_MS).toISOString();
    const active = await device('Desktop', daysAgo(10));
    const records: unknown[] = [active.record];
    for (let i = 1; i <= 6; i++) {
      const gone = await device(`Phone ${i}`, daysAgo(10 - i));
      // Phone 6 is the newest key and the most recently signed out.
      const retiredAt = new Date(Date.now() - (7 - i) * HOUR_MS).toISOString();
      records.push(gone.record, await buildDeviceRetirement(gone.key, DID, gone.record.kid, retiredAt));
    }

    const rows = await bridge.deviceRowsFrom(DID, records, { published: true });
    expect(rows.map((row) => row.name)).toEqual([
      'Phone 6',
      'Phone 5',
      'Phone 4',
      'Phone 3',
      'Phone 2',
      'Desktop',
    ]);
    expect(rows.find((row) => row.name === 'Desktop')?.state).toBe('active');
  });
});
