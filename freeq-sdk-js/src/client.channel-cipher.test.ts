/**
 * App-owned channel ciphers (instant rooms).
 *
 * `setChannelCipher` plugs a cipher into the same seams the ENC1 passphrase
 * path uses: `say()` encrypts + tags `+encrypted`, the `+E` refusal is
 * satisfied, and inbound ciphertext is opened on every path a PRIVMSG can
 * arrive by — single line, multiline batch, and CHATHISTORY replay — with
 * `[encrypted message]` + `encrypted: true` when it cannot be opened.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'crypto';
import type { FreeqClient } from './client.js';
import type { ChannelCipher } from './channel-cipher.js';
import type { Message } from './types.js';
import {
  createGroup, rotate, encryptGroup, makeGroupCipher, type GroupState,
} from './e2ee_group.js';

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

  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string): void {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.({});
  }

  recv(line: string): void {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 12; i++) await new Promise((r) => setTimeout(r, 5));
}

async function makeClient(nick: string): Promise<{ client: FreeqClient; ws: MockWebSocket }> {
  const caps = 'message-tags server-time batch echo-message draft/multiline=max-bytes=40000,max-lines=100';
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick,
    skipInitialBrokerRefresh: true,
  });
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(`:srv CAP * LS :${caps}`);
  await flushAsync();
  ws.recv(`:srv CAP * ACK :${caps.replace(/=max-bytes=\S+/, '')}`);
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

/** Body of the PRIVMSG/BATCH line(s) sent to `target`, joined. */
function sentBody(ws: MockWebSocket, target: string): string {
  // `format()` omits the trailing `:` when the body has no spaces.
  return ws.sent
    .map((l) => l.match(new RegExp(`PRIVMSG ${target} :?(.*)$`)))
    .filter((m): m is RegExpMatchArray => !!m)
    .map((m) => m[1].replace(/\r\n$/, ''))
    .join('');
}

/** A cipher that is obviously not encryption but is easy to assert on. */
function toyCipher(): ChannelCipher {
  return {
    async encrypt(p) { return `TOY:${Buffer.from(p).toString('base64')}`; },
    async decrypt(w) {
      if (!w.startsWith('TOY:')) return null;
      const body = w.slice(4);
      if (body === 'bad') return null;
      return Buffer.from(body, 'base64').toString();
    },
    isCiphertext(w) { return w.startsWith('TOY:'); },
  };
}

const ROOM = '#r-quiet-copper-fox';

describe('setChannelCipher / getChannelCipher', () => {
  it('installs case-insensitively and removes with null', async () => {
    const { client } = await makeClient('alice');
    const c = toyCipher();
    expect(client.getChannelCipher(ROOM)).toBeNull();
    client.setChannelCipher(ROOM.toUpperCase(), c);
    expect(client.getChannelCipher(ROOM)).toBe(c);
    client.setChannelCipher(ROOM, null);
    expect(client.getChannelCipher(ROOM)).toBeNull();
  });
});

describe('say() through a channel cipher', () => {
  it('sends ciphertext tagged +encrypted, never the plaintext', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());

    client.sendMessage(ROOM, 'the quiet part');
    await flushAsync();

    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${ROOM}`));
    expect(line, `sent: ${ws.sent.join(' | ')}`).toBeDefined();
    expect(line).toContain('+encrypted');
    expect(line).not.toContain('the quiet part');
    expect(sentBody(ws, ROOM)).toBe(`TOY:${Buffer.from('the quiet part').toString('base64')}`);
  });

  it('the server echo of our own ciphertext comes back as the plaintext we typed', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    client.sendMessage(ROOM, 'echo me');
    await flushAsync();
    const wire = sentBody(ws, ROOM);
    ws.recv(`@msgid=e1;+encrypted :alice!a@h PRIVMSG ${ROOM} :${wire}`);
    await flushAsync();

    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('echo me');
    expect(seen[0].isSelf).toBe(true);
    expect(seen[0].encrypted).toBe(true);
  });

  it('a multiline message is chunked as ciphertext and reassembles on the far side', async () => {
    const { client, ws } = await makeClient('alice');
    const g = createGroup(ROOM);
    client.setChannelCipher(ROOM, makeGroupCipher(() => [g]));
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    // Big enough that the ciphertext crosses the per-chunk budget.
    const big = 'x'.repeat(9000);
    client.sendMessage(ROOM, big);
    await flushAsync();

    const opener = ws.sent.find((l) => l.includes('BATCH +') && l.includes('draft/multiline'));
    expect(opener, `sent: ${ws.sent.map((l) => l.slice(0, 60)).join(' | ')}`).toBeDefined();
    const chunks = ws.sent.filter((l) => l.includes(`PRIVMSG ${ROOM} `));
    expect(chunks.length).toBeGreaterThan(1);
    // As on the ENC1 path, `+encrypted` rides every chunk (the server checks
    // the tag per PRIVMSG); the opener carries msgid/sig.
    for (const c of chunks) {
      expect(c).toContain('+encrypted');
      expect(c).not.toContain('xxxxxxxxxx');
    }
    const wire = sentBody(ws, ROOM);
    expect(wire.startsWith('EG1:1:')).toBe(true);

    // Replay the batch inbound as the server would to another member.
    ws.recv(`@msgid=m9 :bob!b@h BATCH +in1 draft/multiline ${ROOM}`);
    let first = true;
    for (const c of chunks) {
      const body = c.match(new RegExp(`PRIVMSG ${ROOM} :?(.*)$`))![1].replace(/\r\n$/, '');
      ws.recv(`@batch=in1${first ? '' : ';draft/multiline-concat='} :bob!b@h PRIVMSG ${ROOM} :${body}`);
      first = false;
    }
    ws.recv(':srv BATCH -in1');
    await flushAsync();

    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe(big);
    expect(seen[0].encrypted).toBe(true);
  });

  it('a cipher that cannot encrypt drops the send instead of leaking plaintext', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, makeGroupCipher(() => [])); // no epochs held
    const sys: string[] = [];
    client.on('systemMessage', (_t, text) => sys.push(text));

    client.sendMessage(ROOM, 'must not leak');
    await flushAsync();

    expect(ws.sent.some((l) => l.includes('PRIVMSG'))).toBe(false);
    expect(sys.some((s) => /could not encrypt/.test(s))).toBe(true);
  });
});

describe('+E refusal', () => {
  it('refuses without a cipher and sends with one', async () => {
    const { client, ws } = await makeClient('alice');
    ws.recv(`:srv MODE ${ROOM} +E`);
    await flushAsync();
    const sys: string[] = [];
    client.on('systemMessage', (_t, text) => sys.push(text));

    client.sendMessage(ROOM, 'plain');
    await flushAsync();
    expect(ws.sent.some((l) => l.includes('PRIVMSG'))).toBe(false);
    expect(sys.some((s) => /encrypted \(\+E\)/.test(s))).toBe(true);

    client.setChannelCipher(ROOM, toyCipher());
    client.sendMessage(ROOM, 'now allowed');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes(`PRIVMSG ${ROOM}`));
    expect(line).toBeDefined();
    expect(line).toContain('+encrypted');
    expect(line).not.toContain('now allowed');
  });
});

describe('inbound decryption', () => {
  it('decrypts a single PRIVMSG that the cipher claims', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    const wire = `TOY:${Buffer.from('hello room').toString('base64')}`;
    ws.recv(`@msgid=i1;+encrypted :bob!b@h PRIVMSG ${ROOM} :${wire}`);
    await flushAsync();

    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('hello room');
    expect(seen[0].encrypted).toBe(true);
  });

  it('shows [encrypted message] with encrypted:true when the cipher cannot open it', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    ws.recv(`@msgid=i2 :bob!b@h PRIVMSG ${ROOM} :TOY:bad`);
    await flushAsync();

    expect(seen).toHaveLength(1);
    expect(seen[0].text).toBe('[encrypted message]');
    expect(seen[0].encrypted).toBe(true);
  });

  it('a throwing cipher is "could not open", not a broken dispatch', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, {
      async encrypt() { return null; },
      async decrypt() { throw new Error('boom'); },
      isCiphertext(w) { return w.startsWith('TOY:'); },
    });
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    ws.recv(`@msgid=i3 :bob!b@h PRIVMSG ${ROOM} :TOY:anything`);
    ws.recv(`@msgid=i4 :bob!b@h PRIVMSG ${ROOM} :plain follows`);
    await flushAsync();

    expect(seen.map((m) => m.text)).toEqual(['[encrypted message]', 'plain follows']);
    expect(seen[0].encrypted).toBe(true);
    expect(seen[1].encrypted).toBe(false);
  });

  it('leaves bodies the cipher does not claim alone', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    ws.recv(`@msgid=i5 :bob!b@h PRIVMSG ${ROOM} :just words`);
    await flushAsync();

    expect(seen[0].text).toBe('just words');
    expect(seen[0].encrypted).toBe(false);
  });

  it('does not apply a channel cipher to DMs', async () => {
    const { client, ws } = await makeClient('alice');
    client.setChannelCipher(ROOM, toyCipher());
    const seen: Message[] = [];
    client.on('message', (_ch, m) => seen.push(m));

    ws.recv(`@msgid=i6 :bob!b@h PRIVMSG alice :TOY:bad`);
    await flushAsync();

    expect(seen[0].text).toBe('TOY:bad');
  });

  it('decrypts every row of a CHATHISTORY replay, including a nested multiline', async () => {
    const { client, ws } = await makeClient('alice');
    const g = createGroup(ROOM);
    client.setChannelCipher(ROOM, makeGroupCipher(() => [g]));
    const history: Message[][] = [];
    client.on('historyBatch', (_ch, msgs) => history.push(msgs));

    const one = await encryptGroup(g, 'first');
    const two = await encryptGroup(g, 'second\nline');
    const stranger = await encryptGroup(rotate(g), 'from an epoch we lack');
    // Split `two` in half as concat chunks inside a nested multiline batch.
    const cut = Math.floor(two.length / 2);

    ws.recv(`:srv BATCH +h1 chathistory ${ROOM}`);
    ws.recv(`@batch=h1;msgid=m1;+encrypted :bob!b@h PRIVMSG ${ROOM} :${one}`);
    ws.recv(`@batch=h1;msgid=m2;+encrypted :bob!b@h BATCH +ml1 draft/multiline ${ROOM}`);
    ws.recv(`@batch=ml1 :bob!b@h PRIVMSG ${ROOM} :${two.slice(0, cut)}`);
    ws.recv(`@batch=ml1;draft/multiline-concat= :bob!b@h PRIVMSG ${ROOM} :${two.slice(cut)}`);
    ws.recv(':srv BATCH -ml1');
    ws.recv(`@batch=h1;msgid=m3;+encrypted :bob!b@h PRIVMSG ${ROOM} :${stranger}`);
    ws.recv(`@batch=h1;msgid=m4 :bob!b@h PRIVMSG ${ROOM} :plain row`);
    ws.recv(':srv BATCH -h1');
    await vi.waitFor(() => expect(history).toHaveLength(1));

    const texts = history[0].map((m) => [m.text, m.encrypted]);
    expect(texts).toEqual([
      ['first', true],
      ['second\nline', true],
      ['[encrypted message]', true],
      ['plain row', false],
    ]);
  });
});

describe('makeGroupCipher', () => {
  it('encrypts with the highest epoch and decrypts any held epoch', async () => {
    const e1 = createGroup(ROOM);
    const e2 = rotate(e1);
    const held: GroupState[] = [e1];
    const cipher = makeGroupCipher(() => held);

    expect(cipher.isCiphertext('EG1:1:x:y')).toBe(true);
    expect(cipher.isCiphertext('ENC1:x')).toBe(false);

    const w1 = await cipher.encrypt('at one');
    expect(w1?.startsWith('EG1:1:')).toBe(true);
    held.push(e2); // the getter sees the new epoch without reinstalling
    const w2 = await cipher.encrypt('at two');
    expect(w2?.startsWith('EG1:2:')).toBe(true);

    expect(await cipher.decrypt(w1!)).toBe('at one');
    expect(await cipher.decrypt(w2!)).toBe('at two');
    // An epoch we do not hold, a tampered body, a non-EG1 body: null.
    expect(await cipher.decrypt(await encryptGroup(rotate(e2), 'three'))).toBeNull();
    expect(await cipher.decrypt(w2!.slice(0, -2) + 'AA')).toBeNull();
    expect(await cipher.decrypt('nope')).toBeNull();
  });

  it('cannot encrypt with no epochs', async () => {
    const cipher = makeGroupCipher(() => []);
    expect(await cipher.encrypt('x')).toBeNull();
  });
});
