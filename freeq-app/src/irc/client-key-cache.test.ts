// @vitest-environment jsdom
/**
 * Each connect() builds a new key lookup on the browser's one IndexedDB
 * snapshot, guest or signed in, so a key an earlier connect's lookup found is
 * answered with no request.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { KeyLookup } from '@freeq/sdk';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true, configurable: true });

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  static latest: MockFreeqClient | null = null;
  handlers = new Map<string, Handler[]>();
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: { keyLookup?: KeyLookup }) {
    MockFreeqClient.latest = this;
  }
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

const SIGNER = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const PDS = 'https://pds.example';
/** The signer's key, which only the origin server holds. */
const KEY = new Uint8Array(32).fill(7);

/** The kid the SDK derives: the first 16 bytes of the key's SHA-256, base64url. */
async function kidOf(raw: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', raw);
  return Buffer.from(new Uint8Array(digest).slice(0, 16)).toString('base64url');
}

const plcDoc = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: SIGNER,
  alsoKnownAs: ['at://signer.test'],
  verificationMethod: [
    {
      id: `${SIGNER}#atproto`,
      type: 'Multikey',
      controller: SIGNER,
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
  MockFreeqClient.latest = null;
  requests = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = decodeURIComponent(String(input instanceof Request ? input.url : input));
      requests.push(url);
      if (url === `https://plc.directory/${SIGNER}`) return Response.json(plcDoc);
      if (url.startsWith(`${PDS}/xrpc/com.atproto.repo.listRecords`)) return Response.json({ records: [] });
      if (url.includes('/api/v1/signing-keys/')) {
        return Response.json({ public_key: Buffer.from(KEY).toString('base64url') });
      }
      return new Response('not found', { status: 404 });
    }),
  );
  bridge.setSaslCredentials('t', 'did:plc:me', '', 'web-token');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the key lookup across connects', () => {
  it('answers a key an earlier connect found with no request', async () => {
    const kid = await kidOf(KEY);
    bridge.connect('wss://test/irc', 'me', []);
    const first = MockFreeqClient.latest!.opts.keyLookup!;
    const found = await first.keyFor(SIGNER, kid);
    expect(found?.source).toBe('OriginServer');
    expect(requests.some((url) => url.includes('/api/v1/signing-keys/'))).toBe(true);

    requests = [];
    bridge.connect('wss://test/irc', 'me', []);
    const second = MockFreeqClient.latest!.opts.keyLookup!;
    expect(second).not.toBe(first);
    const again = await second.keyFor(SIGNER, kid);
    // Compared field by field: the key bytes come back from IndexedDB as a
    // Uint8Array of another realm under jsdom.
    expect([again?.source, again?.retiredAt]).toEqual([found!.source, found!.retiredAt]);
    expect(Array.from(again!.publicKey)).toEqual(Array.from(found!.publicKey));
    expect(requests).toEqual([]);
  });

  it('keeps what a guest found, for the guest and for an account', async () => {
    const kid = await kidOf(KEY);
    bridge.setSaslCredentials('', '', '', '');
    bridge.connect('wss://test/irc', 'guest', []);
    const guest = MockFreeqClient.latest!.opts.keyLookup!;
    const found = await guest.keyFor(SIGNER, kid);
    expect(found?.source).toBe('OriginServer');

    requests = [];
    bridge.connect('wss://test/irc', 'guest', []);
    expect(await MockFreeqClient.latest!.opts.keyLookup!.keyFor(SIGNER, kid)).toBeTruthy();
    expect(requests).toEqual([]);

    bridge.setSaslCredentials('t', 'did:plc:me', '', 'web-token');
    bridge.connect('wss://test/irc', 'me', []);
    expect(await MockFreeqClient.latest!.opts.keyLookup!.keyFor(SIGNER, kid)).toBeTruthy();
    expect(requests).toEqual([]);
  });

  it('gives a guest what an account found', async () => {
    const kid = await kidOf(KEY);
    bridge.connect('wss://test/irc', 'me', []);
    expect(await MockFreeqClient.latest!.opts.keyLookup!.keyFor(SIGNER, kid)).toBeTruthy();

    requests = [];
    bridge.setSaslCredentials('', '', '', '');
    bridge.connect('wss://test/irc', 'guest', []);
    expect(await MockFreeqClient.latest!.opts.keyLookup!.keyFor(SIGNER, kid)).toBeTruthy();
    expect(requests).toEqual([]);
  });
});
