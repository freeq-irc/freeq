// @vitest-environment jsdom
/**
 * A server refusing this device's key (FAIL MSGSIG KEY_RETIRED, which the
 * SDK hands on as `MSGSIG KEY_RETIRED <reason>`) signs the app out: the saved
 * login is cleared and the sign-in screen says why.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, screen } from '@testing-library/react';

Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});

type Handler = (...args: unknown[]) => void;

class MockFreeqClient {
  static latest: MockFreeqClient | null = null;
  handlers = new Map<string, Handler[]>();
  nick = 'me';
  joinedChannels = new Set<string>();
  nickToDid: unknown = null;
  disconnects = 0;
  constructor(public opts: { url: string }) {
    MockFreeqClient.latest = this;
  }
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
  }
  emit(event: string, ...args: unknown[]) {
    for (const fn of this.handlers.get(event) ?? []) fn(...args);
  }
  join() { /* not under test */ }
  requestHistory() { /* not under test */ }
  requestHistoryTargets() { /* not under test */ }
  setSaslCredentials() { /* not under test */ }
  connect() { /* no-op */ }
  disconnect() { this.disconnects++; }
  getNickForDid() { return undefined; }
}

vi.mock('@freeq/sdk', () => ({
  FreeqClient: MockFreeqClient,
  IndexedDbDeviceKeyStore: class {},
  KeyLookup: class { originBase() { return null; } async flush() {} },
  makeDidResolver: () => async () => ({ id: 'did:plc:x' }),
  recordKeyOf: async () => ({ publicKeyMultibase: 'z', signer: async () => '' }),
  decodeMultibaseEd25519: () => new Uint8Array(32),
  buildDeviceRecord: async () => ({}),
  buildDeviceRetirement: async () => ({}),
  sentence: () => 'sentence',
  mark: () => 'signed',
  format: {},
  prefetchProfiles: () => {},
  claimForMessage: () => undefined,
}));

const SIGNED_OUT = 'This device was signed out from another device. Sign in again to continue.';

const bridge = await import('./client');
const { useStore } = await import('../store');
const { ConnectScreen } = await import('../components/ConnectScreen');

beforeEach(() => {
  localStorage.clear();
  useStore.getState().fullReset();
  MockFreeqClient.latest = null;
});

afterEach(() => {
  cleanup();
});

describe('a signing key the server refuses', () => {
  it('clears the saved login and shows the sign-in screen with the reason', () => {
    localStorage.setItem('freeq-broker-token', 'BT');
    localStorage.setItem('freeq-broker-base', 'https://auth.example');
    bridge.setSaslCredentials('WT', 'did:plc:me', '', 'web-token');
    bridge.connect('wss://test/irc', 'me', []);
    const c = MockFreeqClient.latest!;
    // Every system line written, since the reset below empties the buffers.
    const lines: string[] = [];
    const addSystemMessage = useStore.getState().addSystemMessage;
    useStore.setState({
      addSystemMessage: (channel: string, text: string) => {
        lines.push(text);
        addSystemMessage(channel, text);
      },
    });

    c.emit('connectionStateChanged', 'connected');
    c.emit('registered', 'me');
    expect(useStore.getState().registered).toBe(true);

    c.emit('serverFail', `MSGSIG KEY_RETIRED ${SIGNED_OUT}`);
    c.emit('connectionStateChanged', 'disconnected');

    const state = useStore.getState();
    expect(c.disconnects).toBe(1);
    expect(localStorage.getItem('freeq-broker-token')).toBeNull();
    expect(state.registered).toBe(false);
    expect(state.authError).toBe(SIGNED_OUT);
    expect(lines.some((text) => text.includes('KEY_RETIRED'))).toBe(false);

    render(<ConnectScreen />);
    expect(screen.getByText(SIGNED_OUT)).toBeTruthy();
  });
});
