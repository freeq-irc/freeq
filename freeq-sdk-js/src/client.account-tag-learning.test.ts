/**
 * The server stamps every message with the sender's DID in an `account` tag.
 * That tag is the only thing that names a did:key peer — it has no profile to
 * fall back on — so any inbound message carrying one should leave the SDK
 * knowing the binding, whatever venue it arrived through.
 *
 * A DM thread is keyed by the peer's DID. When the binding is missing, the
 * thread wears the raw DID as its title, which is what a user sees.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

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

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  if (!globalThis.crypto || !(globalThis.crypto as any).randomUUID) {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2),
        subtle: {
          generateKey: () => Promise.reject(new Error('Ed25519 unavailable in test env')),
        },
      },
      configurable: true,
      writable: true,
    });
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

const CAPS = 'message-tags server-time batch echo-message account-notify account-tag extended-join away-notify';

async function registerAsGuest(ws: MockWebSocket, nick: string) {
  await flushAsync();
  ws.recv(`:srv CAP * LS :${CAPS}`);
  await flushAsync();
  ws.recv(`:srv CAP ${nick} ACK :${CAPS}`);
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome to freeq, ${nick} (guest)`);
  await flushAsync();
}

/** A did:key peer — the case with no profile to fall back on. */
const BOT_DID = 'did:key:z6MkfPfooBarBazQuuxWibbleWobbleFlimFlam7JuZ';
const BOT_NICK = 'claimtestbot';

async function connectedClient(nick = 'me') {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({ url: 'wss://test/irc', nick });
  client.connect();
  const ws = MockWebSocket.instances[0];
  await registerAsGuest(ws, nick);
  return { client, ws };
}

describe('learning a nick↔DID binding from an inbound account tag', () => {
  it('learns from a live DM sent by a peer we never saw join', async () => {
    const { client, ws } = await connectedClient();

    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG me :echo: hey`);
    await flushAsync();

    expect(
      client.getNickForDid(BOT_DID),
      'a DM from an unseen peer must leave the SDK able to name that DID',
    ).toBe(BOT_NICK);
    expect(client.getDidForNick(BOT_NICK)).toBe(BOT_DID);
  });

  it('learns from a live channel message sent by a peer we never saw join', async () => {
    const { client, ws } = await connectedClient();

    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG #room :hello room`);
    await flushAsync();

    expect(
      client.getNickForDid(BOT_DID),
      'a channel message carries the same server-stamped binding as a DM and must teach the map too',
    ).toBe(BOT_NICK);
    expect(client.getDidForNick(BOT_NICK)).toBe(BOT_DID);
  });

  it('learns from a channel history replay row', async () => {
    const { client, ws } = await connectedClient();

    ws.recv('@batch=h1 :srv BATCH +h1 chathistory #room');
    ws.recv(`@batch=h1;account=${BOT_DID};time=2026-08-10T00:00:00.000Z :${BOT_NICK}!u@h PRIVMSG #room :said earlier`);
    ws.recv(':srv BATCH -h1');
    await flushAsync();

    expect(
      client.getNickForDid(BOT_DID),
      'replayed history names its senders the same way live traffic does',
    ).toBe(BOT_NICK);
  });

  it('does not bind a channel name to a DID', async () => {
    const { client, ws } = await connectedClient();

    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG #room :hello room`);
    await flushAsync();

    expect(client.getDidForNick('#room')).toBeUndefined();
    expect(client.getNickForDid(BOT_DID)).not.toBe('#room');
  });

  it('does not bind our own nick from the echo of our own message', async () => {
    const { client, ws } = await connectedClient('me');
    const myDid = 'did:plc:mineminemine';

    ws.recv(`@account=${myDid} :me!u@h PRIVMSG #room :my own words`);
    await flushAsync();

    expect(
      client.getNickForDid(BOT_DID),
      'our own echo says nothing about the peer',
    ).toBeUndefined();
  });
});

describe('announcing a learned binding', () => {
  it('emits memberDid when an inbound message teaches a new binding', async () => {
    const { client, ws } = await connectedClient();
    const learned: Array<[string, string]> = [];
    client.on('memberDid', (nick: string, did: string) => learned.push([nick, did]));

    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG me :echo: hey`);
    await flushAsync();

    expect(
      learned,
      'nothing re-renders a thread title unless the SDK says the binding changed',
    ).toContainEqual([BOT_NICK, BOT_DID]);
  });

  it('does not re-announce a binding it already knew', async () => {
    const { client, ws } = await connectedClient();

    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG me :first`);
    await flushAsync();

    const later: Array<[string, string]> = [];
    client.on('memberDid', (nick: string, did: string) => later.push([nick, did]));
    ws.recv(`@account=${BOT_DID} :${BOT_NICK}!u@h PRIVMSG me :second`);
    await flushAsync();

    expect(later, 'a repeat of a known binding is not news').toEqual([]);
  });
});
