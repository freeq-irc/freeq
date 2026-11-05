// @vitest-environment jsdom
/**
 * A replacement made through the browser's key store shows on the Settings
 * row as a save does: the new key, not yet published.
 */
import { describe, it, expect, vi } from 'vitest';
import type { DeviceKeyStore } from '@freeq/sdk';

const seam = vi.hoisted(() => ({
  old: null as CryptoKeyPair | null,
  made: null as CryptoKeyPair | null,
  latest: null as MockFreeqClient | null,
}));

const OLD_CREATED = '2026-07-01T00:00:00.000Z';
const NEW_CREATED = '2026-10-17T00:00:00.000Z';

class MockFreeqClient {
  handlers = new Map<string, unknown[]>();
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  constructor(public opts: { deviceKeyStore?: Required<DeviceKeyStore> }) {
    seam.latest = this;
  }
  on() { /* not under test */ }
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
  // This browser's key store, without IndexedDB (jsdom has none): it holds a
  // published key, and replaces it with a new one.
  IndexedDbDeviceKeyStore: class {
    async load() {
      seam.old ??= (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
      return { keyPair: seam.old, createdAt: OLD_CREATED, recordUri: 'at://old' };
    }
    async save() {}
    async replace() {
      seam.made = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
      return { keyPair: seam.made, createdAt: NEW_CREATED };
    }
  },
}));

const bridge = await import('./client');
const { buildDeviceRecord, recordKeyOf } = await import('@freeq/sdk');

const DID = 'did:plc:fresh';

async function kidOf(pair: CryptoKeyPair): Promise<string> {
  return (await buildDeviceRecord(await recordKeyOf(pair), DID, NEW_CREATED)).kid;
}

describe("the browser's device key store", () => {
  it('names the replacement on the Settings row, not yet published', async () => {
    bridge.setSaslCredentials('t', DID, '', 'web-token');
    bridge.connect('wss://test/irc', 'me', [], true);
    const store = seam.latest!.opts.deviceKeyStore!;
    await store.load();
    expect(bridge.getDeviceKeyState().kid).toBe(await kidOf(seam.old!));
    expect(bridge.getDeviceKeyState().published).toBe(true);

    const key = await store.replace();
    expect(key.keyPair).toBe(seam.made);
    const state = bridge.getDeviceKeyState();
    expect(state.kid).toBe(await kidOf(seam.made!));
    expect(state.published).toBe(false);
    expect(state.createdAt).toBe(NEW_CREATED);
  });
});
