/** Unit tests for FreeqClient. */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { ActEventPayload } from './types';
import { actTags } from './signing';

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
  if (!globalThis.crypto || !(globalThis.crypto as { randomUUID?: () => string }).randomUUID) {
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

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

/** Build a connected, registered FreeqClient as a guest. Returns the
 *  client and the underlying mock WebSocket. */
async function makeRegistered(nick = 'alice'): Promise<{
  client: import('./client.js').FreeqClient;
  ws: MockWebSocket;
}> {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick,
    skipInitialBrokerRefresh: true,
  });
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(':srv CAP * LS :');
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

// ────────────────────────────────────────────────────────────────────
// Outbound methods
// ────────────────────────────────────────────────────────────────────

describe('channel methods', () => {
  it('join() sends JOIN', async () => {
    const { client, ws } = await makeRegistered();
    client.join('#foo');
    expect(ws.sent).toContain('JOIN #foo');
  });

  it('joinMany() sends comma-separated JOIN', async () => {
    const { client, ws } = await makeRegistered();
    client.joinMany(['#a', '#b', '#c']);
    expect(ws.sent).toContain('JOIN #a,#b,#c');
  });

  it('joinMany([]) is a no-op', async () => {
    const { client, ws } = await makeRegistered();
    client.joinMany([]);
    expect(ws.sent).toHaveLength(0);
  });

  it('part() sends PART and updates joinedChannels', async () => {
    const { client, ws } = await makeRegistered();
    ws.recv(':alice!u@h JOIN #foo');
    await flushAsync();
    expect(client.joinedChannels.has('#foo')).toBe(true);
    client.part('#foo');
    expect(ws.sent).toContain('PART #foo');
    expect(client.joinedChannels.has('#foo')).toBe(false);
  });

  it('quit() sends QUIT with reason', async () => {
    const { client, ws } = await makeRegistered();
    client.quit('bye');
    expect(ws.sent).toContain('QUIT :bye');
  });

  it('quit() with no reason sends bare QUIT', async () => {
    const { client, ws } = await makeRegistered();
    client.quit();
    expect(ws.sent).toContain('QUIT');
  });

  it('setMode() with arg sends MODE channel flags arg', async () => {
    const { client, ws } = await makeRegistered();
    client.setMode('#foo', '+o', 'bob');
    expect(ws.sent).toContain('MODE #foo +o bob');
  });

  it('setMode() without arg sends MODE channel flags', async () => {
    const { client, ws } = await makeRegistered();
    client.setMode('#foo', '+m');
    expect(ws.sent).toContain('MODE #foo +m');
  });

  it('setTopic() sends TOPIC channel :topic', async () => {
    const { client, ws } = await makeRegistered();
    client.setTopic('#foo', 'new topic');
    expect(ws.sent).toContain('TOPIC #foo :new topic');
  });

  it('kick() sends KICK channel nick :reason', async () => {
    const { client, ws } = await makeRegistered();
    client.kick('#foo', 'bob', 'spam');
    expect(ws.sent).toContain('KICK #foo bob :spam');
  });

  it('kick() with no reason uses default', async () => {
    const { client, ws } = await makeRegistered();
    client.kick('#foo', 'bob');
    expect(ws.sent).toContain('KICK #foo bob :kicked');
  });

  it('invite() sends INVITE nick channel', async () => {
    const { client, ws } = await makeRegistered();
    client.invite('#foo', 'bob');
    expect(ws.sent).toContain('INVITE bob #foo');
  });

  it('setAway() with reason sends AWAY :reason', async () => {
    const { client, ws } = await makeRegistered();
    client.setAway('lunch');
    expect(ws.sent).toContain('AWAY :lunch');
  });

  it('setAway() with no arg sends bare AWAY (clears)', async () => {
    const { client, ws } = await makeRegistered();
    client.setAway();
    expect(ws.sent).toContain('AWAY');
  });

  it('pin() sends PIN channel msgid', async () => {
    const { client, ws } = await makeRegistered();
    client.pin('#foo', 'msg123');
    expect(ws.sent).toContain('PIN #foo msg123');
  });

  it('unpin() sends UNPIN channel msgid', async () => {
    const { client, ws } = await makeRegistered();
    client.unpin('#foo', 'msg123');
    expect(ws.sent).toContain('UNPIN #foo msg123');
  });

  it('raw() sends arbitrary IRC line', async () => {
    const { client, ws } = await makeRegistered();
    client.raw('PING :test');
    expect(ws.sent).toContain('PING :test');
  });
});

describe('messaging methods', () => {
  it('sendMessage() sends PRIVMSG with trailing param', async () => {
    const { client, ws } = await makeRegistered();
    client.sendMessage('#foo', 'hello world');
    await flushAsync(); // routes through async signedPrivmsg
    const line = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(line).toMatch(/PRIVMSG #foo :hello world/);
  });

  it('sendMessage() emits local echo when echo-message cap not negotiated', async () => {
    const { client } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('message', (channel, msg) => seen.push({ channel, msg }));
    client.sendMessage('#foo', 'echo test');
    expect(seen.length).toBe(1);
  });

  // ── DID-addressed DMs ──────────────────────────────────────────────
  // A DM to a peer whose DID we know goes out addressed to the DID, and the
  // local thread is keyed by that DID — so the same conversation reaches the
  // right identity on any server and never splits between nick and DID.

  it('sendMessage() to a known-DID nick addresses the DID on the wire', async () => {
    const { client, ws } = await makeRegistered();
    client.nickToDid = (n) => (n.toLowerCase() === 'bob' ? 'did:plc:bob' : undefined);
    client.sendMessage('bob', 'hi bob');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG'));
    expect(line).toMatch(/PRIVMSG did:plc:bob :hi bob/);
  });

  it('sendMessage() to an unknown nick addresses the nick unchanged', async () => {
    const { client, ws } = await makeRegistered();
    client.nickToDid = () => undefined; // guest / unresolved peer
    client.sendMessage('carol', 'hi carol');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG'));
    expect(line).toMatch(/PRIVMSG carol :hi carol/);
  });

  it('sendMessage() addressed directly to a DID passes it through', async () => {
    const { client, ws } = await makeRegistered();
    client.sendMessage('did:plc:bob', 'hi by did');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG'));
    expect(line).toMatch(/PRIVMSG did:plc:bob :hi by did/);
  });

  it('local echo of a known-DID DM is keyed under the DID (one thread)', async () => {
    const { client } = await makeRegistered();
    client.nickToDid = (n) => (n.toLowerCase() === 'bob' ? 'did:plc:bob' : undefined);
    const seen: string[] = [];
    client.on('message', (channel) => seen.push(channel));
    client.sendMessage('bob', 'hi');
    expect(seen).toEqual(['did:plc:bob']);
  });

  it('an incoming DM keys under the sender DID learned from its account tag', async () => {
    // We share no channel with bob, so no JOIN/WHOIS taught us his DID. His
    // message's account tag must still key the thread under his DID — the
    // same key our own sends to him use — so the conversation is one thread.
    const { client, ws } = await makeRegistered();
    const seen: string[] = [];
    client.on('message', (channel) => seen.push(channel));
    ws.recv('@account=did:plc:bob :bob!b@freeq/plc/xx PRIVMSG alice :hey there');
    await flushAsync();
    expect(seen).toEqual(['did:plc:bob']);
    // And a later reply from us now resolves bob → same DID key.
    expect(client.getDidForNick('bob')).toBe('did:plc:bob');
  });

  it('TARGETS with freeq.at/partner-did keys the conversation by the DID', async () => {
    // The server's conversation list carries each DM partner's DID as a tag.
    // The client must key the conversation by that DID — emit it as the
    // target, fetch history by it (the reply batch then arrives DID-keyed),
    // and learn the display binding so the DID renders as a name at once.
    const { client, ws } = await makeRegistered();
    // TARGETS only ever arrive on an authenticated session.
    (client as any)._authDid = 'did:plc:alice';
    const targets: string[] = [];
    client.on('historyTarget', (t) => targets.push(t));
    ws.recv(
      '@time=2026-07-16T21:12:22.000Z;freeq.at/partner-did=did:key:z6MkBot :srv CHATHISTORY TARGETS didtestbot',
    );
    await flushAsync();
    expect(targets).toEqual(['did:key:z6MkBot']);
    const fetch = ws.sent.find((l) => l.startsWith('CHATHISTORY LATEST'));
    expect(fetch).toContain('did:key:z6MkBot');
    expect(client.getNickForDid('did:key:z6MkBot')).toBe('didtestbot');
  });

  it('a DM sent by nick to an OFFLINE peer still keys under their DID thread', async () => {
    // The offline-peer split: the peer is offline, so nothing this session
    // teaches nick→DID (QUIT clears it; no shared channel; no incoming
    // messages). Only the conversation list's DID→nick display binding
    // exists. Sending by nick then echoed into a nick-keyed thread while the
    // server persisted the same message under the DID conversation — one
    // person, two buffers. Buffer keying must reverse the display binding;
    // the wire target stays the nick (addressing is strict).
    const { client, ws } = await makeRegistered();
    ws.recv('@freeq.at/partner-did=did:key:z6MkLobot :srv CHATHISTORY TARGETS lobot');
    await flushAsync();
    expect(client.getDidForNick('lobot')).toBeUndefined(); // addressing NOT taught

    const seen: string[] = [];
    client.on('message', (channel) => seen.push(channel));
    client.sendMessage('lobot', 'llll');
    await flushAsync();

    // Wire: addressed by nick (strict — no display-grade routing).
    const line = ws.sent.find((l) => l.includes('PRIVMSG') && l.includes('llll'));
    expect(line).toMatch(/PRIVMSG lobot :llll/);
    // Local echo: filed under the DID thread, not a new nick thread.
    expect(seen).toEqual(['did:key:z6MkLobot']);

    // Server echo (echo-message) with the nick target keys the same way.
    ws.recv(`:alice!u@h PRIVMSG lobot :llll`);
    await flushAsync();
    expect([...new Set(seen)]).toEqual(['did:key:z6MkLobot']);
  });

  it('the offline notice (401) files under the DID thread, not a nick shell', async () => {
    // The 401 notice used to buffer under the raw fail target, creating a
    // nick-keyed ghost thread containing nothing but system notices.
    const { client, ws } = await makeRegistered();
    ws.recv('@freeq.at/partner-did=did:key:z6MkFed :srv CHATHISTORY TARGETS fedtestbot');
    await flushAsync();
    const seen: string[] = [];
    client.on('systemMessage', (channel) => seen.push(channel));
    ws.recv(':srv 401 alice fedtestbot :No such nick/channel');
    await flushAsync();
    expect(seen).toEqual(['did:key:z6MkFed']);
  });

  it('a history batch with no learned binding recovers the partner DID from its rows', async () => {
    // If the conversation-list entry never arrived (login burst), no binding
    // exists when history is fetched by nick — the batch must not create a
    // nick-keyed thread when its own rows name the partner's DID.
    const { client, ws } = await makeRegistered();
    const batches: string[] = [];
    client.on('historyBatch', (channel) => batches.push(channel));
    ws.recv(':srv BATCH +h1 chathistory bob');
    ws.recv('@batch=h1;account=did:plc:bob;msgid=m1 :bob!b@h PRIVMSG alice :old message');
    ws.recv(':srv BATCH -h1');
    // The batched-message path suspends across more microtasks than a plain
    // PRIVMSG; one flushAsync races the batch close.
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(batches).toEqual(['did:plc:bob']);
    expect(client.getNickForDid('did:plc:bob')).toBe('bob'); // binding learned
  });

  it('a replayed line whose batch was never opened arrives as history', async () => {
    // The envelope can be missed — a reconnect mid-replay, an open lost to
    // the login burst — and the line inside it still says it is a replay.
    // Handing it over as live filed day-old rows under the newest thing said.
    const { client, ws } = await makeRegistered();
    const live: string[] = [];
    const history: Array<[string, number]> = [];
    client.on('message', (channel) => live.push(channel));
    client.on('historyBatch', (channel, msgs) => history.push([channel, msgs.length]));

    ws.recv('@batch=gone;time=2026-08-22T10:00:00.000Z;msgid=m1 :bob!b@h PRIVMSG #room :old news');
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(live).toEqual([]);
    expect(history).toEqual([['#room', 1]]);
  });

  it('sendMarkdown() resolves the DM target like sendMessage', async () => {
    const { client, ws } = await makeRegistered();
    client.nickToDid = (n) => (n.toLowerCase() === 'bob' ? 'did:plc:bob' : undefined);
    const seen: string[] = [];
    client.on('message', (channel) => seen.push(channel));
    client.sendMarkdown('bob', '**hi**');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG') && l.includes('**hi**'));
    expect(line).toContain('PRIVMSG did:plc:bob');
    expect(seen).toEqual(['did:plc:bob']);
  });

  it('the TARGETS envelope batch does not emit an empty historyBatch', async () => {
    const { client, ws } = await makeRegistered();
    const batches: string[] = [];
    client.on('historyBatch', (channel) => batches.push(channel));
    ws.recv(':srv BATCH +cht1 draft/chathistory-targets');
    ws.recv('@batch=cht1;freeq.at/partner-did=did:plc:bob :srv CHATHISTORY TARGETS bob');
    ws.recv(':srv BATCH -cht1');
    await flushAsync();
    expect(batches).toEqual([]); // no ('', []) noise for the envelope
  });

  it('TARGETS without the tag (old server) keeps nick behavior unchanged', async () => {
    const { client, ws } = await makeRegistered();
    // TARGETS only ever arrive on an authenticated session (see above).
    (client as any)._authDid = 'did:plc:alice';
    const targets: string[] = [];
    client.on('historyTarget', (t) => targets.push(t));
    ws.recv(':srv CHATHISTORY TARGETS bob');
    await flushAsync();
    expect(targets).toEqual(['bob']);
    expect(ws.sent.find((l) => l.startsWith('CHATHISTORY LATEST'))).toContain('bob');
  });

  it('does not split a DM thread when the peer DID is learned mid-conversation', async () => {
    // Regression for the bug live-testing caught: a DM keyed under the peer's
    // bare nick, then re-keyed to their DID once a WHOIS resolved it — two
    // threads for one person. With the account tag on the message, the DID is
    // known from message one, and an interleaved WHOIS must not fork a second
    // thread. All messages from the peer stay under a single DID key.
    const { client, ws } = await makeRegistered();
    const threads: string[] = [];
    client.on('message', (channel) => threads.push(channel));

    ws.recv('@account=did:plc:bob :bob!b@freeq/plc/xx PRIVMSG alice :one');
    await flushAsync();
    // A redundant WHOIS DID numeric arrives later (same binding) …
    ws.recv(':srv 330 alice bob did:plc:bob :is logged in as');
    // … and a second DM follows.
    ws.recv('@account=did:plc:bob :bob!b@freeq/plc/xx PRIVMSG alice :two');
    await flushAsync();

    expect([...new Set(threads)]).toEqual(['did:plc:bob']);
  });

  it('sendReply() sets +reply tag', async () => {
    const { client, ws } = await makeRegistered();
    client.sendReply('#foo', 'msg123', 'replying');
    await flushAsync(); // routes through async signedPrivmsg
    const line = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(line).toContain('+reply=msg123');
  });

  it('sendReplyInThread() sets +reply tag', async () => {
    const { client, ws } = await makeRegistered();
    client.sendReplyInThread('#foo', 'msg123', 'replying');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(line).toContain('+reply=msg123');
    expect(line).toContain('PRIVMSG #foo');
  });

  it('sendEdit() sets +draft/edit tag', async () => {
    const { client, ws } = await makeRegistered();
    client.sendEdit('#foo', 'msg123', 'corrected');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(line).toContain('+draft/edit=msg123');
  });

  it('sendDelete() sends TAGMSG with +draft/delete', async () => {
    const { client, ws } = await makeRegistered();
    client.sendDelete('#foo', 'msg123');
    // Signed sends are serialized, so every send leaves on the queue.
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+draft/delete=msg123');
  });

  it('sendDelete() emits messageDeleted locally', async () => {
    const { client } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('messageDeleted', (ch, msgid) => seen.push({ ch, msgid }));
    client.sendDelete('#foo', 'msg123');
    expect(seen).toContainEqual({ ch: '#foo', msgid: 'msg123' });
  });

  it('sendReaction() sends TAGMSG with +react + +reply', async () => {
    const { client, ws } = await makeRegistered();
    client.sendReaction('#foo', '🎉', 'msg123');
    // Signed sends are serialized, so every send leaves on the queue.
    await flushAsync();
    const line = ws.sent[0];
    expect(line).toContain('+react=🎉');
    expect(line).toContain('+reply=msg123');
  });

  it('sendReaction() emits reactionAdded locally when msgId given', async () => {
    const { client } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('reactionAdded', (ch, msgid, emoji, from) => seen.push({ ch, msgid, emoji, from }));
    client.sendReaction('#foo', '🔥', 'msg-abc');
    expect(seen).toHaveLength(1);
  });

  it('sendUnreact() sends TAGMSG with +freeq.at/unreact', async () => {
    const { client, ws } = await makeRegistered();
    client.sendUnreact('#foo', '🎉', 'msg123');
    // Signed sends are serialized, so every send leaves on the queue.
    await flushAsync();
    expect(ws.sent[0]).toContain('+freeq.at/unreact=🎉');
  });

  it('sendMarkdown() sets +freeq.at/mime=text/markdown', async () => {
    const { client, ws } = await makeRegistered();
    client.sendMarkdown('#foo', '**bold**');
    await flushAsync();
    expect(ws.sent[0]).toContain('+freeq.at/mime=text/markdown');
  });

  it('sendTagged() emits PRIVMSG with custom tags', async () => {
    const { client, ws } = await makeRegistered();
    client.sendTagged('#foo', 'hello world', { '+freeq.at/streaming': '1' });
    await flushAsync();
    expect(ws.sent[0]).toMatch(/^@\+freeq.at\/streaming=1 PRIVMSG #foo :hello world/);
  });

  it('sendTagmsg() emits tags-only TAGMSG (no body)', async () => {
    const { client, ws } = await makeRegistered();
    client.sendTagmsg('#foo', { '+react': '🎉', '+reply': 'abc' });
    // Signed sends are serialized, so every send leaves on the queue.
    await flushAsync();
    expect(ws.sent[0]).toContain('TAGMSG #foo');
    expect(ws.sent[0]).toContain('+react=🎉');
    expect(ws.sent[0]).toContain('+reply=abc');
  });

  it('sendMedia() emits PRIVMSG with media tags', async () => {
    const { client, ws } = await makeRegistered();
    client.sendMedia('#foo', {
      url: 'https://x.com/img.png',
      mime: 'image/png',
      alt: 'a cat',
    });
    // The send goes through the signing path, which resolves off the
    // microtask queue even when nothing is signed.
    await flushAsync();
    const line = ws.sent[0];
    expect(line).toContain('PRIVMSG #foo');
    expect(line).toContain('+freeq.at/media-url=https://x.com/img.png');
    expect(line).toContain('+freeq.at/media-mime=image/png');
  });

  it('sendLinkPreview() emits PRIVMSG with link tags + fallback text', async () => {
    const { client, ws } = await makeRegistered();
    client.sendLinkPreview('#foo', {
      url: 'https://x.com',
      title: 'Title',
      description: 'Desc',
    });
    await flushAsync();
    const line = ws.sent[0];
    expect(line).toContain('+freeq.at/link-url=https://x.com');
    expect(line).toContain('+freeq.at/link-title=Title');
    expect(line).toContain('🔗');
  });

  it('sendAndAwaitEcho() resolves with server-assigned msgid', async () => {
    const { client, ws } = await makeRegistered();
    const promise = client.sendAndAwaitEcho('#foo', 'hi', {});
    await flushAsync();
    const sentLine = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(sentLine).toBeDefined();
    const nonceMatch = sentLine!.match(/\+freeq\.at\/echo-nonce=([^;\s]+)/);
    expect(nonceMatch).toBeTruthy();
    const nonce = nonceMatch![1];
    ws.recv(`@+freeq.at/echo-nonce=${nonce};msgid=server-msg-001 :alice PRIVMSG #foo :hi`);
    await flushAsync();
    const msgid = await promise;
    expect(msgid).toBe('server-msg-001');
  });
});

describe('typing methods', () => {
  it('startTyping() sends TAGMSG with +typing=active', async () => {
    const { client, ws } = await makeRegistered();
    client.startTyping('#foo');
    expect(ws.sent[0]).toMatch(/^@\+typing=active TAGMSG #foo/);
  });

  it('stopTyping() sends TAGMSG with +typing=done', async () => {
    const { client, ws } = await makeRegistered();
    client.stopTyping('#foo');
    expect(ws.sent[0]).toMatch(/^@\+typing=done TAGMSG #foo/);
  });
});

describe('identity resolution', () => {
  it('getDidForNick() returns undefined for unknown nicks', async () => {
    const { client } = await makeRegistered();
    expect(client.getDidForNick('unknown')).toBeUndefined();
  });

  it('populates cache from WHOIS 330', async () => {
    const { client, ws } = await makeRegistered();
    ws.recv(':srv 330 alice bob did:plc:bob123 :is authenticated as');
    await flushAsync();
    expect(client.getDidForNick('bob')).toBe('did:plc:bob123');
    expect(client.getDidForNick('BOB')).toBe('did:plc:bob123'); // case-insensitive
    expect(client.getNickForDid('did:plc:bob123')).toBe('bob');
  });

  it('populates cache from JOIN account tag', async () => {
    const { client, ws } = await makeRegistered();
    ws.recv(':carol!user@host JOIN #foo did:plc:carol :real');
    await flushAsync();
    expect(client.getDidForNick('carol')).toBe('did:plc:carol');
    expect(client.getNickForDid('did:plc:carol')).toBe('carol');
  });

  it('QUIT forgets nick→DID (addressing) but keeps DID→nick (display)', async () => {
    // The two directions carry different risk. A released nick can be
    // recycled by someone else, so addressing must forget it. A DID is
    // permanent and the reverse map is display-only, so keeping it lets an
    // offline peer still render as a name rather than a raw did:… string —
    // which is exactly when we need it (the "is offline" notice, a DM title
    // for a peer who logged off). A rename overwrites it on the next
    // JOIN/WHOIS, so it cannot drift silently.
    const { client, ws } = await makeRegistered();
    ws.recv(':srv 330 alice dave did:plc:dave :is authenticated as');
    await flushAsync();
    expect(client.getDidForNick('dave')).toBeDefined();
    ws.recv(':dave!user@host QUIT :goodbye');
    await flushAsync();
    expect(client.getDidForNick('dave')).toBeUndefined();
    expect(client.getNickForDid('did:plc:dave')).toBe('dave');
  });
});

describe('requestWhois', () => {
  it('resolves with WhoisInfo when 318 fires', async () => {
    const { client, ws } = await makeRegistered();
    const promise = client.requestWhois('bob');
    await flushAsync();
    expect(ws.sent).toContain('WHOIS bob');
    ws.recv(':srv 311 alice bob ~user host.example * :Bob');
    ws.recv(':srv 330 alice bob did:plc:bob123 :is authenticated as');
    ws.recv(':srv 671 alice bob bob.bsky.social :is using a registered handle');
    ws.recv(':srv 318 alice bob :End of WHOIS list');
    await flushAsync();
    const info = await promise;
    expect(info.nick).toBe('bob');
    expect(info.user).toBe('~user');
    expect(info.host).toBe('host.example');
    expect(info.did).toBe('did:plc:bob123');
    expect(info.handle).toBe('bob.bsky.social');
    expect(typeof info.fetchedAt).toBe('number');
  });

  it('rejects on timeout', async () => {
    vi.useFakeTimers();
    const { client } = await makeRegistered();
    const promise = client.requestWhois('ghost', { timeoutMs: 100 });
    promise.catch(() => { /* swallow */ });
    vi.advanceTimersByTime(150);
    await expect(promise).rejects.toThrow(/timed out/);
    vi.useRealTimers();
  });

  it('multiple concurrent waiters share one WHOIS request', async () => {
    const { client, ws } = await makeRegistered();
    const p1 = client.requestWhois('alice2');
    const p2 = client.requestWhois('alice2');
    await flushAsync();
    const whoisCount = ws.sent.filter((l) => l === 'WHOIS alice2').length;
    expect(whoisCount).toBe(1);
    ws.recv(':srv 311 me alice2 ~u host * :real');
    ws.recv(':srv 318 me alice2 :End');
    await flushAsync();
    const [a, b] = await Promise.all([p1, p2]);
    expect(a.nick).toBe('alice2');
    expect(b.nick).toBe('alice2');
  });

  it('deprecated whois() method still fires WHOIS', async () => {
    const { client, ws } = await makeRegistered();
    client.whois('bob');
    expect(ws.sent).toContain('WHOIS bob');
  });
});

// A caller that only sees `whois` cannot tell "the server finished and named
// no account" from "no answer yet" — the two need different words on screen,
// and a timer that guesses which is exactly the defect this replaces.
describe('whoisEnd', () => {
  it('318 ends the WHOIS, naming the nick', async () => {
    const { client, ws } = await makeRegistered();
    const ended: string[] = [];
    client.on('whoisEnd', (nick) => ended.push(nick));
    client.whois('bob');
    ws.recv(':srv 311 alice bob ~user host.example * :Bob');
    await flushAsync();
    expect(ended).toEqual([]);
    ws.recv(':srv 318 alice bob :End of WHOIS list');
    await flushAsync();
    expect(ended).toEqual(['bob']);
  });

  it('a guest answer ends with no account named', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<{ did?: string }> = [];
    let ended = false;
    client.on('whois', (_nick, info) => seen.push(info));
    client.on('whoisEnd', () => { ended = true; });
    client.whois('guest1');
    ws.recv(':srv 311 alice guest1 ~u freeq/guest * :IRC User');
    await flushAsync();
    ws.recv(':srv 312 alice guest1 srv :freeq');
    await flushAsync();
    ws.recv(':srv 318 alice guest1 :End of WHOIS list');
    await flushAsync();
    expect(ended).toBe(true);
    expect(seen.some((i) => i.did)).toBe(false);
    expect(client.getDidForNick('guest1')).toBeUndefined();
  });

  it('401 for a name nobody holds also ends the WHOIS', async () => {
    const { client, ws } = await makeRegistered();
    const ended: string[] = [];
    client.on('whoisEnd', (nick) => ended.push(nick));
    ws.recv(':srv 401 alice ghost :No such nick');
    await flushAsync();
    expect(ended).toEqual(['ghost']);
  });

  it('ends the WHOIS for a background lookup too', async () => {
    // The SDK fires its own WHOIS for DM partners; those answers end the
    // same way, so a surface watching the event is never left pending.
    const { client, ws } = await makeRegistered();
    const ended: string[] = [];
    client.on('whoisEnd', (nick) => ended.push(nick));
    ws.recv(':carol!u@h PRIVMSG alice :hi');
    await flushAsync();
    expect(ws.sent).toContain('WHOIS carol');
    ws.recv(':srv 318 alice carol :End of WHOIS list');
    await flushAsync();
    expect(ended).toEqual(['carol']);
  });
});

describe('agent lifecycle methods', () => {
  it('registerAgent() sends AGENT REGISTER', async () => {
    const { client, ws } = await makeRegistered();
    client.registerAgent('agent');
    expect(ws.sent).toContain('AGENT REGISTER :class=agent');
  });

  it('submitProvenance() sends base64url-encoded PROVENANCE', async () => {
    const { client, ws } = await makeRegistered();
    client.submitProvenance({ type: 'FreeqBotDelegation/v1', bot_did: 'did:key:z6Mk' });
    const line = ws.sent.find((l) => l.startsWith('PROVENANCE'));
    expect(line).toBeDefined();
    const encoded = line!.slice('PROVENANCE :'.length);
    const padded = encoded + '='.repeat((4 - (encoded.length % 4)) % 4);
    const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(b64);
    expect(decoded).toContain('FreeqBotDelegation/v1');
  });

  it('setPresence() sends PRESENCE with state', async () => {
    const { client, ws } = await makeRegistered();
    client.setPresence('executing', 'working on task', 'task-1');
    expect(ws.sent).toContain('PRESENCE :state=executing;status=working on task;task=task-1');
  });

  it('setPresence() omits optional fields when undefined', async () => {
    const { client, ws } = await makeRegistered();
    client.setPresence('online');
    expect(ws.sent).toContain('PRESENCE :state=online');
  });

  it('sendHeartbeat() sends HEARTBEAT', async () => {
    const { client, ws } = await makeRegistered();
    client.sendHeartbeat('active', 60);
    expect(ws.sent).toContain('HEARTBEAT :state=active;ttl=60');
  });

  it('startHeartbeat() sends one immediately and returns a handle', async () => {
    vi.useFakeTimers();
    const { client, ws } = await makeRegistered();
    const handle = client.startHeartbeat(30_000);
    expect(ws.sent.filter((l) => l.startsWith('HEARTBEAT')).length).toBe(1);
    vi.advanceTimersByTime(30_001);
    expect(ws.sent.filter((l) => l.startsWith('HEARTBEAT')).length).toBe(2);
    handle.stop();
    vi.advanceTimersByTime(60_000);
    expect(ws.sent.filter((l) => l.startsWith('HEARTBEAT')).length).toBe(2);
    vi.useRealTimers();
  });
});

describe('governance methods', () => {
  it('requestApproval() sends APPROVAL_REQUEST', async () => {
    const { client, ws } = await makeRegistered();
    client.requestApproval('#foo', 'deploy', 'prod-server');
    expect(ws.sent).toContain('APPROVAL_REQUEST #foo :deploy;resource=prod-server');
  });

  it('pauseAgent() sends AGENT PAUSE with reason', async () => {
    const { client, ws } = await makeRegistered();
    client.pauseAgent('worker1', 'too loud');
    expect(ws.sent).toContain('AGENT PAUSE worker1 :too loud');
  });

  it('resumeAgent() sends AGENT RESUME', async () => {
    const { client, ws } = await makeRegistered();
    client.resumeAgent('worker1');
    expect(ws.sent).toContain('AGENT RESUME worker1');
  });

  it('revokeAgent() sends AGENT REVOKE', async () => {
    const { client, ws } = await makeRegistered();
    client.revokeAgent('worker1', 'policy violation');
    expect(ws.sent).toContain('AGENT REVOKE worker1 :policy violation');
  });

  it('approveAgent() sends AGENT APPROVE', async () => {
    const { client, ws } = await makeRegistered();
    client.approveAgent('worker1', 'deploy');
    expect(ws.sent).toContain('AGENT APPROVE worker1 deploy');
  });

  it('denyAgent() sends AGENT DENY', async () => {
    const { client, ws } = await makeRegistered();
    client.denyAgent('worker1', 'deploy', 'not during freeze');
    expect(ws.sent).toContain('AGENT DENY worker1 deploy :not during freeze');
  });
});

describe('coordination event methods', () => {
  it('emitEvent() sends paired TAGMSG + PRIVMSG with same tags', async () => {
    const { client, ws } = await makeRegistered();
    const eventId = client.emitEvent('#foo', 'task_request', { description: 'review PR' }, {
      humanText: 'New task',
    });
    await flushAsync();
    expect(eventId).toBeDefined();
    const tagmsg = ws.sent.find((l) => l.includes(`TAGMSG #foo`));
    const privmsg = ws.sent.find((l) => l.includes('PRIVMSG #foo'));
    expect(tagmsg).toBeDefined();
    expect(privmsg).toBeDefined();
    expect(tagmsg).toContain('+freeq.at/event=task_request');
    expect(tagmsg).toContain(`msgid=${eventId}`);
    expect(privmsg).toContain('+freeq.at/event=task_request');
    expect(privmsg).toContain(`msgid=${eventId}`);
  });

  it('emitEvent() percent-encodes payload', async () => {
    const { client, ws } = await makeRegistered();
    client.emitEvent('#foo', 'test', { msg: 'has spaces; and semicolons' });
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('%20');
    expect(line).toContain('%3B');
  });

  it('createTask() returns an event ID', async () => {
    const { client } = await makeRegistered();
    const taskId = client.createTask('#foo', 'do thing');
    expect(taskId).toMatch(/^[0-9a-f]+$/);
  });

  it('updateTask() includes ref tag', async () => {
    const { client, ws } = await makeRegistered();
    client.updateTask('#foo', 'task-abc', 'reviewing', 'looking');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/ref=task-abc');
  });

  it('completeTask() emits task_complete', async () => {
    const { client, ws } = await makeRegistered();
    client.completeTask('#foo', 'task-abc', 'done', 'https://result');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/event=task_complete');
  });

  it('failTask() emits task_failed', async () => {
    const { client, ws } = await makeRegistered();
    client.failTask('#foo', 'task-abc', 'something broke');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/event=task_failed');
  });

  it('attachEvidence() emits evidence_attach with evidence-type tag', async () => {
    const { client, ws } = await makeRegistered();
    client.attachEvidence('#foo', 'task-abc', 'code_review', 'looks ok');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/event=evidence_attach');
    expect(line).toContain('+freeq.at/evidence-type=code_review');
  });
});

describe('spawning methods', () => {
  it('submitManifest() sends AGENT MANIFEST with base64 TOML', async () => {
    const { client, ws } = await makeRegistered();
    client.submitManifest('[manifest]\nname = "test"');
    const line = ws.sent.find((l) => l.startsWith('AGENT MANIFEST'));
    expect(line).toBeDefined();
    const b64 = line!.slice('AGENT MANIFEST '.length);
    expect(atob(b64)).toContain('[manifest]');
  });

  it('spawnAgent() sends AGENT SPAWN with semicolon-delimited params', async () => {
    const { client, ws } = await makeRegistered();
    client.spawnAgent('#foo', 'worker-1', ['post_message', 'read'], 300, 'task-abc');
    const line = ws.sent.find((l) => l.startsWith('AGENT SPAWN'));
    expect(line).toBe('AGENT SPAWN #foo :nick=worker-1;capabilities=post_message,read;ttl=300;task=task-abc');
  });

  it('despawnAgent() sends AGENT DESPAWN', async () => {
    const { client, ws } = await makeRegistered();
    client.despawnAgent('worker-1');
    expect(ws.sent).toContain('AGENT DESPAWN worker-1');
  });

  it('sendAsChild() sends AGENT MSG', async () => {
    const { client, ws } = await makeRegistered();
    client.sendAsChild('worker-1', '#foo', 'hello from child');
    expect(ws.sent).toContain('AGENT MSG worker-1 #foo :hello from child');
  });
});

describe('economics methods', () => {
  it('submitSpend() sends SPEND with amount/unit/desc', async () => {
    const { client, ws } = await makeRegistered();
    client.submitSpend('#foo', 0.5, 'usd', 'llm call', 'task-1');
    const line = ws.sent.find((l) => l.startsWith('SPEND'));
    expect(line).toBe('SPEND #foo :amount=0.500000;unit=usd;desc=llm call;task=task-1');
  });

  it('setBudget() sends BUDGET with policy params', async () => {
    const { client, ws } = await makeRegistered();
    client.setBudget('#foo', 10, 'usd', 'per_day', 'did:plc:sponsor');
    expect(ws.sent).toContain('BUDGET #foo :max=10;unit=usd;period=per_day;sponsor=did:plc:sponsor');
  });

  it('requestBudget() sends bare BUDGET to query', async () => {
    const { client, ws } = await makeRegistered();
    client.requestBudget('#foo');
    expect(ws.sent).toContain('BUDGET #foo');
  });
});

describe('requestHistory', () => {
  it('opts.mode=latest sends CHATHISTORY LATEST', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({ target: '#foo', mode: 'latest', count: 20 });
    expect(ws.sent).toContain('CHATHISTORY LATEST #foo * 20');
  });

  it("opts.mode=before sends CHATHISTORY BEFORE with msgid", async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({ target: '#foo', mode: 'before', msgid: 'abc', count: 30 });
    expect(ws.sent).toContain('CHATHISTORY BEFORE #foo msgid=abc 30');
  });

  it('opts.mode=after sends CHATHISTORY AFTER', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({ target: '#foo', mode: 'after', msgid: 'xyz' });
    expect(ws.sent).toContain('CHATHISTORY AFTER #foo msgid=xyz 50');
  });

  it('opts.mode=before falls back to the timestamp anchor', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({
      target: '#foo', mode: 'before', timestamp: '2026-08-24T12:00:00.000Z', count: 30,
    });
    expect(ws.sent).toContain('CHATHISTORY BEFORE #foo timestamp=2026-08-24T12:00:00.000Z 30');
  });

  it('opts.mode=after falls back to the timestamp anchor', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({
      target: '#foo', mode: 'after', timestamp: '2026-08-24T12:00:00.000Z',
    });
    expect(ws.sent).toContain('CHATHISTORY AFTER #foo timestamp=2026-08-24T12:00:00.000Z 50');
  });

  it('prefers the msgid anchor when both are given', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({
      target: '#foo', mode: 'before', msgid: 'abc',
      timestamp: '2026-08-24T12:00:00.000Z', count: 10,
    });
    expect(ws.sent).toContain('CHATHISTORY BEFORE #foo msgid=abc 10');
    expect(ws.sent.some((l: string) => l.includes('timestamp='))).toBe(false);
  });

  it('opts.mode=around sends CHATHISTORY AROUND with msgid', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({ target: '#foo', mode: 'around', msgid: 'abc', count: 40 });
    expect(ws.sent).toContain('CHATHISTORY AROUND #foo msgid=abc 40');
  });

  it('opts.mode=around falls back to the timestamp anchor', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory({
      target: '#foo', mode: 'around', timestamp: '2026-08-24T12:00:00.000Z',
    });
    expect(ws.sent).toContain('CHATHISTORY AROUND #foo timestamp=2026-08-24T12:00:00.000Z 50');
  });

  it('opts.mode=around throws if no anchor is given', async () => {
    const { client } = await makeRegistered();
    expect(() => client.requestHistory({ target: '#foo', mode: 'around' })).toThrow(/msgid/);
  });

  it('opts.mode=before throws if msgid missing', async () => {
    const { client } = await makeRegistered();
    expect(() => client.requestHistory({ target: '#foo', mode: 'before' })).toThrow(/msgid/);
  });

  it('a guest asking for DM history reaches the wire', async () => {
    // The client used to drop this request: the server always answered
    // ACCOUNT_REQUIRED, so asking was noise. A current server answers an
    // empty result instead, which is what lets a guest's DM buffer reach
    // the start of the conversation.
    const { client, ws } = await makeRegistered();
    client.requestHistory({ target: 'somebody', mode: 'latest' });
    client.requestHistory({ target: 'somebody', mode: 'before', msgid: 'abc', count: 50 });
    expect(ws.sent).toContain('CHATHISTORY LATEST somebody * 50');
    expect(ws.sent).toContain('CHATHISTORY BEFORE somebody msgid=abc 50');
  });

  it('legacy two-arg form still works', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory('#foo');
    expect(ws.sent).toContain('CHATHISTORY LATEST #foo * 50');
  });
});

describe('what a history batch answers', () => {
  /** Open and close a chathistory batch for `target`, with `n` rows. */
  function batch(ws: any, id: string, target: string, n: number) {
    ws.recv(`:srv BATCH +${id} chathistory ${target}`);
    for (let i = 0; i < n; i++) {
      ws.recv(`@batch=${id};msgid=m${id}${i} :bob!b@h PRIVMSG ${target} :row ${i}`);
    }
    ws.recv(`:srv BATCH -${id}`);
  }

  it('reports the mode and size the request asked for', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: '#foo', mode: 'latest', count: 30 });
    batch(ws, 'b1', '#foo', 2);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'latest', count: 30 }]);
  });

  it('answers a target\'s requests in the order they were asked', async () => {
    // Two requests can be out for one target at once — the opening page and
    // a page the reader asked for. Labelling the first answer with the
    // second request tells the caller its paging request came back when it
    // has not.
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: '#foo', mode: 'latest', count: 50 });
    client.requestHistory({ target: '#foo', mode: 'before', msgid: 'abc', count: 50 });
    batch(ws, 'b1', '#foo', 0);
    for (let i = 0; i < 4; i++) await flushAsync();
    batch(ws, 'b2', '#foo', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([
      { mode: 'latest', count: 50 },
      { mode: 'before', count: 50 },
    ]);
  });

  it('labels an around answer as one', async () => {
    // A caller that cannot tell an around answer from the opening page
    // leaves the channel waiting on a page that already arrived.
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: '#foo', mode: 'around', msgid: 'abc', count: 60 });
    batch(ws, 'b1', '#foo', 3);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'around', count: 60 }]);
  });

  it('keeps the queue straight when a request is refused instead of answered', async () => {
    // A refused CHATHISTORY is answered by the FAIL and by no batch. If the
    // request it refuses stays queued, the next batch is labelled with it and
    // the caller does not recognise the answer to the request it is waiting
    // on — which sends that page to a timeout rather than to the reader.
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: '#foo', mode: 'before', msgid: 'gone', count: 50 });
    ws.recv(':srv FAIL CHATHISTORY MESSAGE_ERROR BEFORE #foo :Messages could not be retrieved');
    await flushAsync();

    client.requestHistory({ target: '#foo', mode: 'latest', count: 20 });
    batch(ws, 'b1', '#foo', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'latest', count: 20 }]);
  });

  it('does not drain a DM whose peer is nicked like a subcommand', async () => {
    // The subcommand sits where a target could, and `before` is a legal nick.
    // A refusal about one target must not drain another's request.
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: 'before', mode: 'latest', count: 44 });
    ws.recv(':srv FAIL CHATHISTORY MESSAGE_ERROR BEFORE #elsewhere :Messages could not be retrieved');
    await flushAsync();
    batch(ws, 'b1', 'before', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'latest', count: 44 }]);
  });

  it('still finds that peer when the refusal is about them', async () => {
    // The subcommand is only skipped when something follows it, so a refusal
    // whose one remaining parameter is that peer resolves to them.
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: 'before', mode: 'before', msgid: 'x', count: 44 });
    ws.recv(':srv FAIL CHATHISTORY ACCOUNT_REQUIRED before :You must be authenticated');
    await flushAsync();

    client.requestHistory({ target: 'before', mode: 'latest', count: 12 });
    batch(ws, 'b1', 'before', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'latest', count: 12 }]);
  });

  it('leaves the queue alone for a refusal naming no pending target', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    client.requestHistory({ target: '#foo', mode: 'before', msgid: 'abc', count: 50 });
    ws.recv(':srv FAIL CHATHISTORY INVALID_TARGET #somewhere-else :No such channel');
    await flushAsync();
    batch(ws, 'b1', '#foo', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([{ mode: 'before', count: 50 }]);
  });

  it('reports nothing for a batch no request is on record for', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<unknown> = [];
    client.on('historyBatch', (_c, _m, info) => seen.push(info));

    batch(ws, 'b1', '#unasked', 3);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([undefined]);
  });

  it('keeps each target\'s requests apart', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<[string, unknown]> = [];
    client.on('historyBatch', (c, _m, info) => seen.push([c, info]));

    client.requestHistory({ target: '#a', mode: 'latest', count: 50 });
    client.requestHistory({ target: '#b', mode: 'before', msgid: 'x', count: 20 });
    batch(ws, 'b2', '#b', 0);
    for (let i = 0; i < 4; i++) await flushAsync();
    batch(ws, 'b1', '#a', 0);
    for (let i = 0; i < 4; i++) await flushAsync();

    expect(seen).toEqual([
      ['#b', { mode: 'before', count: 20 }],
      ['#a', { mode: 'latest', count: 50 }],
    ]);
  });
});

describe('history targets', () => {
  it('requestHistoryTargets() sends CHATHISTORY TARGETS', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistoryTargets(25);
    expect(ws.sent).toContain('CHATHISTORY TARGETS * * 25');
  });

  it('deprecated requestDmTargets() still works', async () => {
    const { client, ws } = await makeRegistered();
    client.requestDmTargets(25);
    expect(ws.sent).toContain('CHATHISTORY TARGETS * * 25');
  });

  it("'historyTarget' event fires on CHATHISTORY TARGETS response", async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<[string, string | undefined]> = [];
    client.on('historyTarget', (target, ts) => seen.push([target, ts]));
    ws.recv(':srv CHATHISTORY TARGETS bob 2026-05-12T10:00:00Z');
    await flushAsync();
    expect(seen).toContainEqual(['bob', '2026-05-12T10:00:00Z']);
  });

  it("deprecated 'dmTarget' event still fires alongside 'historyTarget'", async () => {
    const { client, ws } = await makeRegistered();
    const seen: string[] = [];
    client.on('dmTarget', (target) => seen.push(target));
    ws.recv(':srv CHATHISTORY TARGETS bob 2026-05-12T10:00:00Z');
    await flushAsync();
    expect(seen).toContain('bob');
  });
});

describe('fetchPins', () => {
  it('returns parsed pins array on success', async () => {
    const { client } = await makeRegistered();
    const mockPins = [
      { msgid: 'm1', pinned_by: 'alice', pinned_at: 1700000000 },
      { msgid: 'm2', pinned_by: 'bob', pinned_at: 1700000100 },
    ];
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ pins: mockPins }),
    });
    globalThis.fetch = fetchMock as typeof fetch;
    const result = await client.fetchPins('#foo');
    expect(result).toEqual(mockPins);
  });

  it("returns [] on fetch failure", async () => {
    const { client } = await makeRegistered();
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('network')) as typeof fetch;
    const result = await client.fetchPins('#foo');
    expect(result).toEqual([]);
  });

  it("'pins' event still fires alongside Promise return", async () => {
    const { client } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('pins', (channel, pins) => seen.push({ channel, pins }));
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ pins: [{ msgid: 'm1', pinned_by: 'a', pinned_at: 1 }] }),
    }) as typeof fetch;
    await client.fetchPins('#foo');
    expect(seen.length).toBe(1);
  });
});

// ────────────────────────────────────────────────────────────────────
// Inbound events
// ────────────────────────────────────────────────────────────────────

describe('inbound: messages and reactions', () => {
  it('PRIVMSG emits message event', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('message', (channel, msg) => seen.push({ channel, text: msg.text, from: msg.from }));
    ws.recv(':bob!u@h PRIVMSG #foo :hello');
    await flushAsync();
    expect(seen).toContainEqual({ channel: '#foo', text: 'hello', from: 'bob' });
  });

  it('TAGMSG with +typing emits typing event', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('typing', (ch, nick, active) => seen.push({ ch, nick, active }));
    ws.recv('@+typing=active :bob TAGMSG #foo');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', nick: 'bob', active: true });
  });

  it('TAGMSG with +react emits reactionAdded', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('reactionAdded', (ch, msgid, emoji, by) => seen.push({ ch, msgid, emoji, by }));
    ws.recv('@+react=🔥;+reply=msg-abc :bob TAGMSG #foo');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', msgid: 'msg-abc', emoji: '🔥', by: 'bob' });
  });
});

describe('inbound: channel membership', () => {
  it('JOIN emits memberJoined for others', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('memberJoined', (ch, m) => seen.push({ ch, nick: m.nick }));
    ws.recv(':bob!u@h JOIN #foo');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', nick: 'bob' });
  });

  it('JOIN emits channelJoined for self', async () => {
    const { client, ws } = await makeRegistered();
    const seen: string[] = [];
    client.on('channelJoined', (ch) => seen.push(ch));
    ws.recv(':alice!u@h JOIN #foo');
    await flushAsync();
    expect(seen).toContain('#foo');
  });

  it('PART emits memberLeft for others', async () => {
    const { client, ws } = await makeRegistered();
    ws.recv(':bob!u@h JOIN #foo');
    await flushAsync();
    const seen: unknown[] = [];
    client.on('memberLeft', (ch, nick) => seen.push({ ch, nick }));
    ws.recv(':bob!u@h PART #foo');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', nick: 'bob' });
  });

  it('KICK emits userKicked', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('userKicked', (ch, kicked, by, reason) => seen.push({ ch, kicked, by, reason }));
    ws.recv(':op!u@h KICK #foo bob :spam');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', kicked: 'bob', by: 'op', reason: 'spam' });
  });

  it('NICK emits userRenamed', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('userRenamed', (oldNick, newNick) => seen.push({ oldNick, newNick }));
    ws.recv(':bob!u@h NICK bobby');
    await flushAsync();
    expect(seen).toContainEqual({ oldNick: 'bob', newNick: 'bobby' });
  });

  it('QUIT emits userQuit', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('userQuit', (nick, reason) => seen.push({ nick, reason }));
    ws.recv(':bob!u@h QUIT :goodbye');
    await flushAsync();
    expect(seen).toContainEqual({ nick: 'bob', reason: 'goodbye' });
  });

  it('TOPIC emits topicChanged', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('topicChanged', (ch, topic, by) => seen.push({ ch, topic, by }));
    ws.recv(':op TOPIC #foo :the new topic');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', topic: 'the new topic', by: 'op' });
  });

  it('INVITE emits invited', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('invited', (ch, by) => seen.push({ ch, by }));
    ws.recv(':bob INVITE alice #foo');
    await flushAsync();
    expect(seen).toContainEqual({ ch: '#foo', by: 'bob' });
  });
});

describe('read markers (draft/read-marker)', () => {
  it('markRead() sends MARKREAD with timestamp=', async () => {
    const { client, ws } = await makeRegistered();
    client.markRead('#room', '2026-07-02T10:00:00.000Z');
    expect(ws.sent).toContain('MARKREAD #room timestamp=2026-07-02T10:00:00.000Z');
  });

  it('getReadMarker() sends bare MARKREAD', async () => {
    const { client, ws } = await makeRegistered();
    client.getReadMarker('#room');
    expect(ws.sent).toContain('MARKREAD #room');
  });

  it('MARKREAD <target> timestamp=<iso> emits readMarker with the timestamp', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('readMarker', (target, ts) => seen.push({ target, ts }));
    ws.recv('MARKREAD #room timestamp=2026-07-02T10:00:00.000Z');
    await flushAsync();
    expect(seen).toContainEqual({ target: '#room', ts: '2026-07-02T10:00:00.000Z' });
  });

  it('MARKREAD <target> * emits readMarker with null timestamp', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('readMarker', (target, ts) => seen.push({ target, ts }));
    ws.recv('MARKREAD #room *');
    await flushAsync();
    expect(seen).toContainEqual({ target: '#room', ts: null });
  });

  it('requests draft/read-marker during CAP negotiation', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'caps',
      skipInitialBrokerRefresh: true,
    });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv CAP * LS :message-tags server-time draft/read-marker');
    await flushAsync();
    const reqLine = ws.sent.find((l) => l.startsWith('CAP REQ'));
    expect(reqLine).toBeDefined();
    expect(reqLine).toContain('draft/read-marker');
  });

  it('requests account-tag so incoming DMs carry the sender DID', async () => {
    // Without account-tag the server never stamps the sender's DID onto a DM,
    // so a first DM from a peer we share no channel with keys under the bare
    // nick and later splits when the DID is learned. account-tag closes that.
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'caps', skipInitialBrokerRefresh: true });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv CAP * LS :message-tags server-time account-notify account-tag');
    await flushAsync();
    const reqLine = ws.sent.find((l) => l.startsWith('CAP REQ'));
    expect(reqLine).toContain('account-tag');
  });
});

describe('inbound: identity and MOTD', () => {
  it('330 (WHOIS DID numeric) emits memberDid', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('memberDid', (nick, did) => seen.push({ nick, did }));
    ws.recv(':srv 330 alice bob did:plc:bob :is authenticated as');
    await flushAsync();
    expect(seen).toContainEqual({ nick: 'bob', did: 'did:plc:bob' });
  });

  it('MOTD numerics emit motd / motdStart', async () => {
    const { client, ws } = await makeRegistered();
    const events: string[] = [];
    client.on('motdStart', () => events.push('start'));
    client.on('motd', (line) => events.push(`line:${line}`));
    ws.recv(':srv 375 alice :- begin MOTD');
    ws.recv(':srv 372 alice :- welcome to freeq');
    await flushAsync();
    expect(events[0]).toBe('start');
    expect(events[1]).toBe('line:welcome to freeq');
  });
});

describe('inbound: governance', () => {
  it("emits 'governance' for valid signal TAGMSG", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('governance', (payload) => seen.push(payload));
    ws.recv('@+freeq.at/governance=pause;+freeq.at/reason=too\\snoisy :op!u@h TAGMSG alice');
    await flushAsync();
    expect(seen).toEqual([{
      signal: 'pause',
      target: 'alice',
      by: 'op',
      reason: 'too noisy',
    }]);
  });

  it("ignores unknown governance signal", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('governance', (payload) => seen.push(payload));
    ws.recv('@+freeq.at/governance=bogus :op TAGMSG alice');
    await flushAsync();
    expect(seen).toHaveLength(0);
  });

  it.each([
    'pause',
    'resume',
    'revoke',
    'approval_granted',
    'approval_denied',
    'budget_exceeded',
  ])("accepts signal '%s'", async (sig) => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('governance', (payload) => seen.push(payload));
    ws.recv(`@+freeq.at/governance=${sig} :op TAGMSG alice`);
    await flushAsync();
    expect(seen).toHaveLength(1);
  });
});

describe('inbound: coordinationEvent', () => {
  it("emits parsed event from TAGMSG", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('coordinationEvent', (e) => seen.push(e));
    const payload = JSON.stringify({ description: 'review' });
    const encoded = encodeURIComponent(payload);
    ws.recv(
      `@msgid=evt1;+freeq.at/event=task_request;+freeq.at/payload=${encoded} :alice TAGMSG #foo`,
    );
    await flushAsync();
    expect(seen).toHaveLength(1);
    const e = seen[0] as { eventType: string; eventId: string; payload: unknown };
    expect(e.eventType).toBe('task_request');
    expect(e.eventId).toBe('evt1');
    expect(e.payload).toEqual({ description: 'review' });
  });

  it("de-dupes paired TAGMSG + PRIVMSG by eventId", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('coordinationEvent', (e) => seen.push(e));
    ws.recv('@msgid=evt2;+freeq.at/event=task_complete :alice TAGMSG #foo');
    ws.recv('@msgid=evt2;+freeq.at/event=task_complete :alice PRIVMSG #foo :done');
    await flushAsync();
    expect(seen).toHaveLength(1);
  });

  it("ignores TAGMSG without +freeq.at/event tag", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('coordinationEvent', (e) => seen.push(e));
    ws.recv('@+react=🎉 :alice TAGMSG #foo');
    await flushAsync();
    expect(seen).toHaveLength(0);
  });
});

describe('outbound: sendAct', () => {
  /** A registered client with a real session key, so a task event can be
   *  signed and put on the wire. */
  async function signingClient(caps = 'message-tags freeq.at/msgsig'): Promise<{
    client: import('./client.js').FreeqClient;
    ws: MockWebSocket;
  }> {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'eliza',
      skipInitialBrokerRefresh: true,
    });
    client.signing.setSigningDid('did:plc:eliza');
    await client.signing.generateSigningKey();
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(`:srv CAP * LS :${caps}`);
    await flushAsync();
    ws.recv(`:srv CAP * ACK :${caps}`);
    await flushAsync();
    ws.recv(':srv 001 eliza :Welcome');
    await flushAsync();
    ws.sent.length = 0;
    return { client, ws };
  }

  async function settled(ws: MockWebSocket, match: string): Promise<void> {
    for (let i = 0; i < 100; i++) {
      if (ws.sent.some((l) => l.includes(match))) return;
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  const TASK = '01JABCDEF000000000000000EF';
  const lines = (ws: MockWebSocket) => ws.sent.filter((l) => l.includes('PRIVMSG'));

  it('asked for no line, sends the one the tags deserve', async () => {
    const { client, ws } = await signingClient();
    const id = await client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'halfway' }),
    );
    await settled(ws, 'PRIVMSG');
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    const companion = lines(ws)[0]!;
    expect(companion).toContain(':progress: halfway');
    // A follow-up's companion names the action, not this event.
    expect(companion).toContain(`+freeq.at/ref=${TASK}`);
  });

  it("an opener's companion names the event it opened", async () => {
    const { client, ws } = await signingClient();
    const id = await client.sendAct(
      '#ops',
      actTags('handoff', 'offer', undefined, 'did:plc:eliza', { title: 'Cite 3 sources' }),
    );
    await settled(ws, 'PRIVMSG');
    const companion = lines(ws)[0]!;
    expect(companion).toContain(':offered: Cite 3 sources');
    expect(companion).toContain(`+freeq.at/ref=${id}`);
  });

  it('an empty line sends the event and nothing else', async () => {
    const { client, ws } = await signingClient();
    await client.sendAct(
      '#ops',
      actTags('handoff', 'accept', TASK, 'did:plc:eliza', {}),
      { humanText: '' },
    );
    await settled(ws, 'TAGMSG');
    expect(ws.sent.some((l) => l.includes('TAGMSG'))).toBe(true);
    expect(lines(ws)).toHaveLength(0);
  });

  it("a caller's own words are what the room reads", async () => {
    const { client, ws } = await signingClient();
    await client.sendAct(
      '#ops',
      actTags('handoff', 'accept', TASK, 'did:plc:eliza', {}),
      { humanText: 'on it' },
    );
    await settled(ws, 'PRIVMSG');
    expect(lines(ws)[0]!).toContain(':on it');
  });

  it('sends a kind and verb it has never heard of, signed', async () => {
    // Which verbs a kind allows is the rules file's business; nothing in the
    // send path reads either one.
    const { client, ws } = await signingClient();
    await client.sendAct(
      '#ops',
      actTags('lease', 'renew', TASK, 'did:plc:eliza', { term: '30d' }),
    );
    await settled(ws, 'PRIVMSG');
    const event = ws.sent.find((l) => l.includes('TAGMSG'))!;
    expect(event).toContain('+freeq.at/act=lease');
    expect(event).toContain('+freeq.at/act-verb=renew');
    expect(event).toContain('+freeq.at/sig=ed25519:');
    // A verb with no sentence written for it is named, not described. A
    // one-word body carries no leading colon on the wire.
    expect(lines(ws)[0]!).toMatch(/PRIVMSG #ops renew$/);
  });

  it('refuses to send a task event it cannot sign', async () => {
    const { client } = await makeRegistered();
    await expect(
      client.sendAct('#ops', actTags('handoff', 'claim', TASK, 'did:plc:eliza', {})),
    ).rejects.toThrow('a task event must be signed');
  });

  // ── The line waits for the server to take the event ──
  //
  // The server gates only the TAGMSG, so a line sent beside it unconditionally
  // is prose about a step that may never have happened.

  const ECHOING = 'message-tags freeq.at/msgsig echo-message';
  const events = (ws: MockWebSocket) => ws.sent.filter((l) => l.includes('TAGMSG'));
  const eventIdOf = (line: string) => /\+freeq\.at\/eventid=([^;\s]+)/.exec(line)![1];

  /** The server's echo of a task event we sent, which is what says it took it. */
  function echoOf(line: string): string {
    return (
      `@+freeq.at/eventid=${eventIdOf(line)};+freeq.at/act=handoff;` +
      '+freeq.at/act-verb=progress;+freeq.at/from=did:plc:eliza :eliza TAGMSG #ops'
    );
  }

  const REFUSAL =
    ":srv FAIL TAGMSG ILLEGAL_STEP :That step cannot be taken from the task's current state";

  it('holds the line until our own echo of the event comes back', async () => {
    const { client, ws } = await signingClient(ECHOING);
    const sent = client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'halfway' }),
    );
    await settled(ws, 'TAGMSG');
    // The event alone so far — the line is what the server has not spoken for.
    expect(events(ws)).toHaveLength(1);
    expect(lines(ws)).toHaveLength(0);

    ws.recv(echoOf(events(ws)[0]!));
    expect(await sent).toBe(eventIdOf(events(ws)[0]!));
    await settled(ws, 'PRIVMSG');
    expect(lines(ws)[0]!).toContain(':progress: halfway');
  });

  it('never writes the line for an event the server refused', async () => {
    const { client, ws } = await signingClient(ECHOING);
    const sent = client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'halfway' }),
    );
    await settled(ws, 'TAGMSG');
    ws.recv(REFUSAL);
    // The caller hears the server's own words, code first.
    await expect(sent).rejects.toThrow(
      "ILLEGAL_STEP That step cannot be taken from the task's current state",
    );
    await settled(ws, 'PRIVMSG');
    expect(lines(ws)).toHaveLength(0);
  });

  it('writes the line anyway when nobody answers inside the window', async () => {
    const { client, ws } = await signingClient(ECHOING);
    // Only the window's own timer is faked: signing resolves off the
    // platform's work queue, and a fake clock over all of it never lets go.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const sent = client.sendAct(
        '#ops',
        actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'halfway' }),
      );
      // `setImmediate` is not faked, so this pumps the real work queue the
      // signature resolves on without moving the window's clock.
      const tick = (): Promise<void> => new Promise((r) => setImmediate(r));
      for (let i = 0; i < 200 && events(ws).length === 0; i++) await tick();
      await vi.advanceTimersByTimeAsync(4_999);
      expect(lines(ws)).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(1);
      await sent;
      expect(lines(ws)[0]!).toContain(':progress: halfway');
    } finally {
      vi.useRealTimers();
    }
  });

  it('sends both halves at once on a session with no echo to wait for', async () => {
    const { client, ws } = await signingClient();
    const sent = client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'halfway' }),
    );
    await settled(ws, 'PRIVMSG');
    await sent;
    // Nothing was ever echoed, and the line went out regardless.
    expect(lines(ws)).toHaveLength(1);
  });

  it('waits for nothing when the caller asked for no line', async () => {
    const { client, ws } = await signingClient(ECHOING);
    await client.sendAct(
      '#ops',
      actTags('handoff', 'accept', TASK, 'did:plc:eliza', {}),
      { humanText: '' },
    );
    await settled(ws, 'TAGMSG');
    expect(events(ws)).toHaveLength(1);
    expect(lines(ws)).toHaveLength(0);
  });

  it('keeps the next event off the wire until the one before it is answered', async () => {
    const { client, ws } = await signingClient(ECHOING);
    const first = client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'first' }),
    );
    const second = client.sendAct(
      '#ops',
      actTags('handoff', 'progress', TASK, 'did:plc:eliza', { note: 'second' }),
    );
    await settled(ws, 'TAGMSG');
    // A refusal names no event id, so a second event in flight would make the
    // next `FAIL` unattributable.
    expect(events(ws)).toHaveLength(1);

    ws.recv(echoOf(events(ws)[0]!));
    await first;
    await settled(ws, 'PRIVMSG');
    expect(lines(ws).map((l) => l.includes('first'))).toEqual([true]);

    // The second event only now goes out, and its line follows its own answer.
    for (let i = 0; i < 50 && events(ws).length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    expect(events(ws)).toHaveLength(2);
    expect(lines(ws)).toHaveLength(1);
    ws.recv(echoOf(events(ws)[1]!));
    await second;
    for (let i = 0; i < 50 && lines(ws).length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    expect(lines(ws)[1]!).toContain('second');
  });
});

describe('inbound: actEvent', () => {
  const OFFER =
    '@+freeq.at/eventid=01OFFER;+freeq.at/act=handoff;+freeq.at/act-verb=offer;' +
    '+freeq.at/act-title=Cite\\s3\\ssources;+freeq.at/from=did:plc:eliza;' +
    '+freeq.at/sig=ed25519:kid:sig :eliza TAGMSG #foo';

  it('emits the parsed task event from a TAGMSG', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(OFFER);
    await flushAsync();
    expect(seen).toHaveLength(1);
    const e = seen[0];
    expect(e.channel).toBe('#foo');
    expect(e.from).toBe('eliza');
    expect(e.did).toBe('did:plc:eliza');
    expect(e.kind).toBe('handoff');
    expect(e.verb).toBe('offer');
    expect(e.eventId).toBe('01OFFER');
    // Every act tag, keyed by its stripped name — and nothing else.
    expect(e.fields).toEqual({
      act: 'handoff',
      'act-verb': 'offer',
      'act-title': 'Cite 3 sources',
    });
    expect(e.sigTag).toBe('ed25519:kid:sig');
    expect(e.replayed).toBe(false);
  });

  it('falls back to the account tag when the sender wrote no from tag', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(
      '@msgid=01NOFROM;account=did:plc:scholar;+freeq.at/act=handoff;' +
        '+freeq.at/act-verb=claim;+freeq.at/act-id=01OFFER :scholar TAGMSG #foo',
    );
    await flushAsync();
    expect(seen[0].did).toBe('did:plc:scholar');
  });

  it("an opener's task is itself; a follow-up names the task it is about", async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(OFFER);
    ws.recv(
      '@+freeq.at/eventid=01CLAIM;+freeq.at/act=handoff;+freeq.at/act-verb=claim;' +
        '+freeq.at/act-id=01OFFER;+freeq.at/from=did:plc:scholar :scholar TAGMSG #foo',
    );
    await flushAsync();
    expect(seen.map((e) => [e.eventId, e.taskId])).toEqual([
      ['01OFFER', '01OFFER'],
      ['01CLAIM', '01OFFER'],
    ]);
  });

  it('de-dupes our own echo by event id', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(OFFER);
    ws.recv(OFFER);
    await flushAsync();
    expect(seen).toHaveLength(1);
  });

  it('de-dupes an event a joiner gets from JOIN replay and again from CHATHISTORY', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    // JOIN replay: the server stamps the original time on the line.
    ws.recv(
      '@time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01REPLAY;+freeq.at/act=handoff;' +
        '+freeq.at/act-verb=offer;+freeq.at/act-title=x;+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    // The same event again, inside the CHATHISTORY batch the joiner asks for.
    ws.recv(':server BATCH +h chathistory #foo');
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01REPLAY;+freeq.at/act=handoff;' +
        '+freeq.at/act-verb=offer;+freeq.at/act-title=x;+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    ws.recv(':server BATCH -h');
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].replayed).toBe(true);
  });

  it('ignores a TAGMSG carrying no act tag', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv('@+react=🎉;+reply=01ABC :alice TAGMSG #foo');
    // `actor-class` is not an act tag, and the coverage rule says so.
    ws.recv('@msgid=01X;+freeq.at/actor-class=agent :alice TAGMSG #foo');
    await flushAsync();
    expect(seen).toHaveLength(0);
  });

  it('holds a batched event until the batch that carries its companion lands', async () => {
    const { client, ws } = await makeRegistered();
    const order: string[] = [];
    client.on('actEvent', (e) => order.push(`act:${e.eventId}`));
    client.on('historyBatch', (buf, msgs) =>
      order.push(`batch:${buf}:${msgs.map((m) => m.id).join(',')}`),
    );
    ws.recv(':server BATCH +h chathistory #foo');
    // The event line precedes its companion on the wire — the case that
    // used to hand the app the event with nothing to hang it on.
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01OFFER;' +
        '+freeq.at/act=handoff;+freeq.at/act-verb=offer;+freeq.at/act-title=x;' +
        '+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:01.000Z;msgid=01LINE;+freeq.at/ref=01OFFER ' +
        ':eliza PRIVMSG #foo :offered: x',
    );
    ws.recv(':server BATCH -h');
    // The batched-message path suspends across more microtasks than a plain
    // PRIVMSG; one flushAsync races the batch close.
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(order).toEqual(['batch:#foo:01LINE', 'act:01OFFER']);
  });

  it('keeps two batched events in wire order behind their batch', async () => {
    const { client, ws } = await makeRegistered();
    const order: string[] = [];
    client.on('actEvent', (e) => order.push(`act:${e.eventId}`));
    client.on('historyBatch', (buf, msgs) =>
      order.push(`batch:${msgs.map((m) => m.id).join(',')}`),
    );
    ws.recv(':server BATCH +h chathistory #foo');
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01OFFER;' +
        '+freeq.at/act=handoff;+freeq.at/act-verb=offer;+freeq.at/act-title=x;' +
        '+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:01.000Z;msgid=01LINE1;+freeq.at/ref=01OFFER ' +
        ':eliza PRIVMSG #foo :offered: x',
    );
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:02.000Z;+freeq.at/eventid=01CLAIM;' +
        '+freeq.at/act=handoff;+freeq.at/act-verb=claim;+freeq.at/act-id=01OFFER;' +
        '+freeq.at/from=did:plc:scholar :scholar TAGMSG #foo',
    );
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:03.000Z;msgid=01LINE2;+freeq.at/ref=01CLAIM ' +
        ':scholar PRIVMSG #foo :claimed: x',
    );
    ws.recv(':server BATCH -h');
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(order).toEqual(['batch:01LINE1,01LINE2', 'act:01OFFER', 'act:01CLAIM']);
  });

  it('fires an unbatched event straight away', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    // A batch is open, but this line is not in it.
    ws.recv(':server BATCH +h chathistory #foo');
    ws.recv(OFFER);
    await flushAsync();
    expect(seen.map((e) => e.eventId)).toEqual(['01OFFER']);
  });

  it('fires a JOIN-replay event straight away, marked replayed', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(
      '@time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01JOINED;+freeq.at/act=handoff;' +
        '+freeq.at/act-verb=offer;+freeq.at/act-title=x;+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    await flushAsync();
    expect(seen).toHaveLength(1);
    expect(seen[0].eventId).toBe('01JOINED');
    expect(seen[0].replayed).toBe(true);
  });

  it('leaves the companion prose line to fire message', async () => {
    const { client, ws } = await makeRegistered();
    const acts: ActEventPayload[] = [];
    const msgs: unknown[] = [];
    client.on('actEvent', (e) => acts.push(e));
    client.on('message', (m) => msgs.push(m));
    ws.recv(OFFER);
    ws.recv('@msgid=01LINE;+freeq.at/ref=01OFFER :eliza PRIVMSG #foo :offered: Cite 3 sources');
    await flushAsync();
    expect(acts).toHaveLength(1);
    expect(msgs).toHaveLength(1);
  });
});

describe('inbound: actEvent in a DM', () => {
  // A DM task event as the server relays it: addressed to the recipient's
  // nick, sender named by the account tag the recipient learns them by.
  const INCOMING =
    '@account=did:plc:eliza;+freeq.at/eventid=01DMOFFER;+freeq.at/act=handoff;' +
    '+freeq.at/act-verb=offer;+freeq.at/act-title=Cite\\s3\\ssources;' +
    '+freeq.at/from=did:plc:eliza;+freeq.at/sig=ed25519:kid:sig :eliza TAGMSG alice';

  it('files an incoming DM event under the thread key, not the wire target', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    const bufs: string[] = [];
    client.on('actEvent', (e) => seen.push(e));
    client.on('message', (buf) => bufs.push(buf));
    ws.recv(INCOMING);
    ws.recv(
      '@account=did:plc:eliza;msgid=01DMLINE;+freeq.at/ref=01DMOFFER ' +
        ':eliza PRIVMSG alice :offered: Cite 3 sources',
    );
    await flushAsync();
    // The event and the line it pairs with have to name one buffer, or the
    // card has nothing to render against.
    expect(seen.map((e) => e.channel)).toEqual(['did:plc:eliza']);
    expect(bufs).toEqual(['did:plc:eliza']);
  });

  it("files our own echo under the same key as the peer's events", async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(INCOMING);
    // Our own echo, addressed by the peer's DID the way the SDK sends it.
    ws.recv(
      '@+freeq.at/eventid=01DMCLAIM;+freeq.at/act=handoff;+freeq.at/act-verb=claim;' +
        '+freeq.at/act-id=01DMOFFER;+freeq.at/from=did:plc:alice ' +
        ':alice TAGMSG did:plc:eliza',
    );
    await flushAsync();
    expect(seen.map((e) => e.channel)).toEqual(['did:plc:eliza', 'did:plc:eliza']);
  });

  it('flushes a DM event held in a history batch under the thread key', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    const batches: string[] = [];
    client.on('actEvent', (e) => seen.push(e));
    client.on('historyBatch', (buf) => batches.push(buf));
    ws.recv(':server BATCH +h chathistory did:plc:eliza');
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:00.000Z;account=did:plc:eliza;' +
        '+freeq.at/eventid=01DMREPLAY;+freeq.at/act=handoff;+freeq.at/act-verb=offer;' +
        '+freeq.at/act-title=x;+freeq.at/from=did:plc:eliza :eliza TAGMSG alice',
    );
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:01.000Z;account=did:plc:eliza;msgid=01DMLINE;' +
        '+freeq.at/ref=01DMREPLAY :eliza PRIVMSG alice :offered: x',
    );
    ws.recv(':server BATCH -h');
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(batches).toEqual(['did:plc:eliza']);
    expect(seen.map((e) => e.channel)).toEqual(['did:plc:eliza']);
  });

  it('leaves a channel event under the channel name, live and batched', async () => {
    const { client, ws } = await makeRegistered();
    const seen: ActEventPayload[] = [];
    client.on('actEvent', (e) => seen.push(e));
    ws.recv(
      '@+freeq.at/eventid=01LIVE;+freeq.at/act=handoff;+freeq.at/act-verb=offer;' +
        '+freeq.at/act-title=x;+freeq.at/from=did:plc:eliza :eliza TAGMSG #foo',
    );
    ws.recv(':server BATCH +h chathistory #foo');
    ws.recv(
      '@batch=h;time=2026-08-22T10:00:00.000Z;+freeq.at/eventid=01HELD;' +
        '+freeq.at/act=handoff;+freeq.at/act-verb=claim;+freeq.at/act-id=01LIVE;' +
        '+freeq.at/from=did:plc:scholar :scholar TAGMSG #foo',
    );
    ws.recv(':server BATCH -h');
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(seen.map((e) => e.channel)).toEqual(['#foo', '#foo']);
  });
});

describe('inbound: presence', () => {
  it("parses '<state>: <status>' AWAY text", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('presence', (p) => seen.push(p));
    ws.recv(':bob!u@h AWAY :executing: writing article');
    await flushAsync();
    expect(seen).toContainEqual({
      nick: 'bob',
      did: undefined,
      state: 'executing',
      status: 'writing article',
      task: undefined,
    });
  });

  it("parses bare state AWAY text", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('presence', (p) => seen.push(p));
    ws.recv(':bob!u@h AWAY :idle');
    await flushAsync();
    expect(seen).toContainEqual({
      nick: 'bob',
      did: undefined,
      state: 'idle',
      status: undefined,
      task: undefined,
    });
  });

  it("emits state=online when AWAY is cleared", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('presence', (p) => seen.push(p));
    ws.recv(':bob!u@h AWAY');
    await flushAsync();
    expect(seen).toContainEqual({
      nick: 'bob',
      did: undefined,
      state: 'online',
    });
  });
});

describe('inbound: spawned agents', () => {
  it("emits agentSpawned on JOIN with +freeq.at/parent tag", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('agentSpawned', (p) => seen.push(p));
    ws.recv('@+freeq.at/actor-class=agent;+freeq.at/parent=alice :worker-1!spawn@freeq/spawn/abc JOIN #foo');
    await flushAsync();
    expect(seen).toContainEqual({
      parentNick: 'alice',
      childNick: 'worker-1',
      channel: '#foo',
      capabilities: [],
      ttlSeconds: undefined,
      taskRef: undefined,
    });
  });

  it("emits agentDespawned on QUIT from spawn hostmask", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('agentDespawned', (p) => seen.push(p));
    ws.recv(':worker-1!spawn@freeq/spawn QUIT :TTL expired');
    await flushAsync();
    expect(seen).toContainEqual({ nick: 'worker-1', reason: 'TTL expired' });
  });

  it("does NOT emit agentDespawned for regular QUITs", async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('agentDespawned', (p) => seen.push(p));
    ws.recv(':bob!user@host QUIT :goodbye');
    await flushAsync();
    expect(seen).toHaveLength(0);
  });
});

describe('inbound: AV error signal', () => {
  // `+freeq.at/av-error` is the server's machine-readable AV failure. Before
  // it existed a rejected av-join was only a human NOTICE — client call state
  // was set up optimistically and never torn down, leaving a ghost publisher
  // in a session the server never admitted us to (in-call UI, silent to all).
  it('emits avError with code, session id, and reason', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('avError', (code, sessionId, reason) => seen.push({ code, sessionId, reason }));
    ws.recv('@+freeq.at/av-error=join-failed;+freeq.at/av-id=S1;+freeq.at/av-reason=Session\\shas\\sended :srv TAGMSG alice');
    await flushAsync();
    expect(seen).toContainEqual({ code: 'join-failed', sessionId: 'S1', reason: 'Session has ended' });
  });

  it('emits avError for a start-collision naming the winning session', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('avError', (code, sessionId) => seen.push({ code, sessionId }));
    ws.recv('@+freeq.at/av-error=start-collision;+freeq.at/av-id=WINNER;+freeq.at/av-reason=busy :srv TAGMSG alice');
    await flushAsync();
    expect(seen).toContainEqual({ code: 'start-collision', sessionId: 'WINNER' });
  });

  it('emits avError with empty session id when the tag is absent', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('avError', (code, sessionId) => seen.push({ code, sessionId }));
    ws.recv('@+freeq.at/av-error=join-failed :srv TAGMSG alice');
    await flushAsync();
    expect(seen).toContainEqual({ code: 'join-failed', sessionId: '' });
  });
});

describe('inbound: connection lifecycle', () => {
  it("emits 'connected' on transport open", async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'alice', skipInitialBrokerRefresh: true });
    const events: string[] = [];
    client.on('connected', () => events.push('connected'));
    client.connect();
    await flushAsync();
    expect(events).toContain('connected');
  });

  it("emits 'disconnected' on transport close", async () => {
    const { client, ws } = await makeRegistered();
    const events: string[] = [];
    client.on('disconnected', (reason) => events.push(reason));
    ws.close();
    await flushAsync();
    expect(events.length).toBeGreaterThan(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Nick collision policy
// ────────────────────────────────────────────────────────────────────

describe('onNickCollision policy', () => {
  it("default ('auto-suffix') appends underscore on 433", async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({ url: 'wss://test/irc', nick: 'alice', skipInitialBrokerRefresh: true });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv 433 * alice :Nickname is already in use');
    await flushAsync();
    expect(ws.sent).toContain('NICK alice_');
  });

  it("'refuse' emits authError and disconnects", async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
      onNickCollision: 'refuse',
    });
    const errors: string[] = [];
    client.on('authError', (e) => errors.push(e));
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv 433 * alice :Nickname is already in use');
    await flushAsync();
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/taken/);
  });

  it("'random-suffix' appends a random 4-digit suffix", async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
      onNickCollision: 'random-suffix',
    });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv 433 * alice :Nickname is already in use');
    await flushAsync();
    const retryLines = ws.sent.filter((l) => l.startsWith('NICK alice-'));
    expect(retryLines.length).toBeGreaterThan(0);
    expect(retryLines[0]).toMatch(/^NICK alice-\d{4}$/);
  });
});

  it('a replayed edit row carries its reactions into the collapsed message', async () => {
    // Reactions attach to the msgid the user reacted to — the latest edit
    // id — so they arrive on the EDIT row in replay. The collapse must
    // carry them onto the collapsed message; dropping them made reactions
    // on edited messages vanish on every reload.
    const { client, ws } = await makeRegistered();
    const batches: Array<[string, any[]]> = [];
    client.on('historyBatch', (buf, msgs) => batches.push([buf, msgs]));
    ws.recv(':srv BATCH +h1 chathistory did:plc:peer');
    ws.recv('@batch=h1;msgid=M0;time=2026-07-21T00:00:00.000Z :zapnap!u@h PRIVMSG did:plc:peer :original');
    ws.recv('@batch=h1;msgid=E1;+draft/edit=M0;+freeq.at/reactions=🔥:alice,bob;time=2026-07-21T00:01:00.000Z :zapnap!u@h PRIVMSG did:plc:peer :original - edited');
    ws.recv(':srv BATCH -h1');
    // Batched messages suspend across more microtasks than plain PRIVMSGs.
    for (let i = 0; i < 4; i++) await flushAsync();
    expect(batches).toHaveLength(1);
    const msgs = batches[0][1];
    expect(msgs).toHaveLength(1);
    // The collapsed row keeps the ORIGINAL id. An edit changes the text, not
    // which message this is — and the id it keeps is the one the server files
    // reactions, pins and deletes under.
    expect(msgs[0].id).toBe('M0');
    expect(msgs[0].text).toBe('original - edited');
    const nicks = msgs[0].reactions?.get('🔥');
    expect(nicks && [...nicks].sort()).toEqual(['alice', 'bob']);
  });

// ────────────────────────────────────────────────────────────────────
// Signed mutations, and the cap that gates them
// ────────────────────────────────────────────────────────────────────

describe('signed mutations', () => {
  /** A registered client whose server advertises and ACKs the signing cap,
   *  with a real Ed25519 session key provisioned. */
  async function makeSigningClient(did = 'did:plc:mutator'): Promise<{
    client: import('./client.js').FreeqClient;
    ws: MockWebSocket;
    verifyKey: CryptoKey;
  }> {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
    });
    // Signing state lives on the instance, so provision this client's own.
    client.signing.setSigningDid(did);
    await client.signing.generateSigningKey();
    const pubB64 = client.signing.getPublicKey();
    if (!pubB64) throw new Error('signing key not provisioned');
    const padded = pubB64 + '='.repeat((4 - (pubB64.length % 4)) % 4);
    const bytes = Uint8Array.from(
      atob(padded.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    );
    const verifyKey = await crypto.subtle.importKey('raw', bytes, 'Ed25519', false, [
      'verify',
    ]);
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv CAP * LS :message-tags freeq.at/msgsig');
    await flushAsync();
    ws.recv(':srv CAP * ACK :message-tags freeq.at/msgsig');
    await flushAsync();
    ws.recv(':srv 001 alice :Welcome');
    await flushAsync();
    ws.sent.length = 0;
    return { client, ws, verifyKey };
  }

  /** Wait for the client's async signing to land a line on the wire.
   *  `crypto.subtle.sign` resolves off the microtask queue, so draining
   *  microtasks alone is not enough. */
  async function waitForSent(ws: MockWebSocket, match: string): Promise<string> {
    for (let i = 0; i < 100; i++) {
      const line = ws.sent.find((l) => l.includes(match));
      if (line) return line;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error(`no ${match} on the wire; sent: ${ws.sent.join(' | ')}`);
  }

  function tagOf(line: string, name: string): string | null {
    const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    const m = line.match(new RegExp(`${escaped}=([^;\\s]+)`));
    return m ? m[1]! : null;
  }

  async function verifySig(
    canonical: string,
    sigTag: string,
    key: CryptoKey,
  ): Promise<boolean> {
    const sigB64 = sigTag.split(':')[2]!;
    const padded = sigB64 + '='.repeat((4 - (sigB64.length % 4)) % 4);
    const sig = Uint8Array.from(
      atob(padded.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    );
    return crypto.subtle.verify(
      'Ed25519',
      key,
      sig as unknown as ArrayBuffer,
      new TextEncoder().encode(canonical) as unknown as ArrayBuffer,
    );
  }

  it('a delete carries its own event id and a signature over the delete document', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendDelete('#room', 'M0');
    const line = await waitForSent(ws, 'TAGMSG');
    const eventId = tagOf(line, '+freeq.at/eventid');
    const sigTag = tagOf(line, '+freeq.at/sig');
    expect(eventId, `line: ${line}`).not.toBeNull();
    expect(sigTag).not.toBeNull();

    const canonical = signing.mutationCanonical({
      kind: 'delete',
      from: 'did:plc:mutator',
      msgid: eventId!,
      target: '#room',
      subject: 'M0',
    });
    expect(await verifySig(canonical, sigTag!, verifyKey)).toBe(true);
  });

  it('a reaction and its removal sign different documents', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();

    for (const [kind, send] of [
      ['react', () => client.sendReaction('#room', '👍', 'M0')],
      ['unreact', () => client.sendUnreact('#room', '👍', 'M0')],
    ] as const) {
      ws.sent.length = 0;
      send();
      const line = await waitForSent(ws, 'TAGMSG');
      const eventId = tagOf(line, '+freeq.at/eventid')!;
      const sigTag = tagOf(line, '+freeq.at/sig')!;
      expect(sigTag, `line: ${line}`).not.toBeNull();

      const canonical = signing.mutationCanonical({
        kind,
        from: 'did:plc:mutator',
        msgid: eventId,
        target: '#room',
        subject: 'M0',
        emoji: '👍',
      });
      expect(await verifySig(canonical, sigTag, verifyKey)).toBe(true);

      // The verb is inside the document: the other kind's canonical must not
      // verify against the same signature.
      const other = signing.mutationCanonical({
        kind: kind === 'react' ? 'unreact' : 'react',
        from: 'did:plc:mutator',
        msgid: eventId,
        target: '#room',
        subject: 'M0',
        emoji: '👍',
      });
      expect(await verifySig(other, sigTag, verifyKey)).toBe(false);
    }
  });

  it('sends nothing new against a server that does not verify documents', async () => {
    // makeRegistered's server advertises no caps at all — a legacy server.
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    client.sendDelete('#room', 'M0');
    client.sendReaction('#room', '👍', 'M0');
    await flushAsync();

    for (const line of ws.sent) {
      expect(line, 'a legacy server must see a legacy client').not.toContain(
        '+freeq.at/sig',
      );
      expect(line).not.toContain('+freeq.at/eventid');
    }
    expect(ws.sent).toContain('@+draft/delete=M0 TAGMSG #room');
  });

  it('leaves ephemera unsigned', async () => {
    const { client, ws } = await makeSigningClient();
    client.startTyping('#room');
    await flushAsync();
    for (const line of ws.sent) {
      expect(line).not.toContain('+freeq.at/sig');
    }
  });

  it('sendAndAwaitEcho signs the message like sendMessage does', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    const promise = client.sendAndAwaitEcho('#room', 'echoed and signed');
    const line = await waitForSent(ws, 'PRIVMSG');
    const eventId = tagOf(line, '+freeq.at/eventid');
    const sigTag = tagOf(line, '+freeq.at/sig');
    const nonce = tagOf(line, '+freeq.at/echo-nonce');
    expect(eventId, `line: ${line}`).not.toBeNull();
    expect(sigTag).not.toBeNull();
    expect(nonce).not.toBeNull();

    // The echo nonce is not a covered tag: the signature is over the plain
    // message document, and the signed id is the one the server adopts.
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: eventId!,
      target: '#room',
      body: 'echoed and signed',
    });
    expect(await verifySig(canonical, sigTag!, verifyKey)).toBe(true);

    // The round-trip contract is unchanged: the promise resolves with the
    // msgid the server stamps on the echo.
    ws.recv(
      `@+freeq.at/echo-nonce=${nonce};msgid=${eventId} :alice PRIVMSG #room :echoed and signed`,
    );
    expect(await promise).toBe(eventId);
  });

  it('an action is signed, and its body keeps the framing a receiver reads', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendAction('#room', 'waves at the room');
    const line = await waitForSent(ws, 'PRIVMSG');
    expect(line).toContain('\x01ACTION waves at the room\x01');

    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      // The framing is part of the body: strip it and the document no longer
      // describes what was sent.
      body: '\x01ACTION waves at the room\x01',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('an action in a DM addresses the peer it knows, and signs that venue', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    ws.recv(':srv 330 alice bob did:plc:bob :is authenticated as');
    await flushAsync();

    client.sendAction('bob', 'nods');
    const line = await waitForSent(ws, 'PRIVMSG');
    expect(line, 'a DM whose peer is known is addressed by DID').toContain(
      'PRIVMSG did:plc:bob',
    );

    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: signing.dmVenue('did:plc:mutator', 'did:plc:bob'),
      body: '\x01ACTION nods\x01',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('a mutation in a DM addresses the peer it knows, and signs that venue', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    ws.recv(':srv 330 alice bob did:plc:bob :is authenticated as');
    await flushAsync();

    for (const [kind, send] of [
      ['delete', () => client.sendDelete('bob', 'M0')],
      ['react', () => client.sendReaction('bob', '👍', 'M0')],
      ['unreact', () => client.sendUnreact('bob', '👍', 'M0')],
    ] as const) {
      ws.sent.length = 0;
      send();
      const line = await waitForSent(ws, 'TAGMSG');
      expect(line, `a ${kind} in a known DM is addressed by DID`).toContain(
        'TAGMSG did:plc:bob',
      );
      const canonical = signing.mutationCanonical({
        kind,
        from: 'did:plc:mutator',
        msgid: tagOf(line, '+freeq.at/eventid')!,
        target: signing.dmVenue('did:plc:mutator', 'did:plc:bob'),
        subject: 'M0',
        emoji: kind === 'delete' ? undefined : '👍',
      });
      expect(
        await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey),
        `a ${kind} must sign the DM venue it was addressed to`,
      ).toBe(true);
    }
  });

  // A session key is registered only with a server that asked for the signing
  // capability. A server that never advertised it cannot verify a client
  // document, so it would file a public key it will never read — and the
  // registration is a command an older server has no reason to know at all.
  it('registers the session key only with a server that can use it', async () => {
    async function wireAfterLogin(caps: string): Promise<string[]> {
      const { FreeqClient } = await import('./client.js');
      const client = new FreeqClient({
        url: 'wss://test/irc',
        nick: 'alice',
        skipInitialBrokerRefresh: true,
      });
      client.setSaslCredentials({
        token: 't',
        did: 'did:plc:alice',
        pdsUrl: 'https://pds.example',
        method: 'oauth',
      });
      client.connect();
      await flushAsync();
      const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
      ws.recv(`:srv CAP * LS :${caps}`);
      await flushAsync();
      ws.recv(`:srv CAP * ACK :${caps}`);
      await flushAsync();
      ws.recv(':srv 903 alice :SASL authentication successful');
      await flushAsync();
      ws.recv(':srv 001 alice :Welcome');
      for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 5));
      return ws.sent;
    }

    const legacy = await wireAfterLogin('message-tags server-time');
    expect(
      legacy.filter((l) => l.startsWith('MSGSIG')),
      'a server that never advertised the capability stays unaware of the key',
    ).toEqual([]);

    const current = await wireAfterLogin('message-tags server-time freeq.at/msgsig');
    expect(
      current.filter((l) => l.startsWith('MSGSIG')).length,
      'where the capability was negotiated, nothing changes',
    ).toBe(1);
  });

  // Nothing that signs may reach the wire before the key registration does.
  // The session key is generated asynchronously and MSGSIG goes out when that
  // resolves, after 001 — so a client that emits the moment it is registered
  // used to race its own registration and send either unsigned or with a
  // signature naming a key the server had not been told about. The Rust SDK
  // has always ordered these; this is the same ordering.
  //
  // Registration here is driven through the real sequence rather than the
  // helper, because the helper provisions the key before connecting and so
  // cannot reproduce the race.
  async function loggedIn(caps: string): Promise<{
    client: import('./client.js').FreeqClient;
    ws: MockWebSocket;
  }> {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'alice',
      skipInitialBrokerRefresh: true,
    });
    client.setSaslCredentials({
      token: 't',
      did: 'did:plc:alice',
      pdsUrl: 'https://pds.example',
      method: 'oauth',
    });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(`:srv CAP * LS :${caps}`);
    await flushAsync();
    ws.recv(`:srv CAP * ACK :${caps}`);
    await flushAsync();
    ws.recv(':srv 903 alice :SASL authentication successful');
    await flushAsync();
    ws.recv(':srv 001 alice :Welcome');
    await flushAsync();
    return { client, ws };
  }

  /** Wait for the wire to hold every line named, or give up and let the
   *  assertions report what actually arrived. */
  async function settle(ws: MockWebSocket, ...needles: string[]): Promise<void> {
    for (let i = 0; i < 200; i++) {
      if (needles.every((n) => ws.sent.some((l) => l.includes(n)))) return;
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  it('registers the key before the first event a client emits on connect', async () => {
    const { client, ws } = await loggedIn('message-tags server-time freeq.at/msgsig');
    // The moment registration lands — exactly what the reference example does.
    const eventId = client.createTask('#room', 'ship it');
    await settle(ws, 'MSGSIG ', 'TAGMSG');

    const msgsig = ws.sent.findIndex((l) => l.startsWith('MSGSIG '));
    const tagmsg = ws.sent.findIndex((l) => l.includes('TAGMSG'));
    expect(msgsig, `no key registration on the wire: ${ws.sent.join(' | ')}`).toBeGreaterThan(-1);
    expect(tagmsg).toBeGreaterThan(-1);
    expect(
      msgsig,
      `the key must reach the server before the event it signs: ${ws.sent.join(' | ')}`,
    ).toBeLessThan(tagmsg);

    expect(eventId, 'a signed event is filed under a ULID').toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    const line = ws.sent[tagmsg]!;
    expect(tagOf(line, '+freeq.at/eventid')).toBe(eventId);
    expect(line).toContain('+freeq.at/sig=');
  });

  it('does not hold sends for a registration that will never come', async () => {
    // A server without the capability, and a guest with no identity at all:
    // neither will ever register a key, so neither may wait for one.
    const { client, ws } = await loggedIn('message-tags server-time');
    client.sendMessage('#room', 'hello');
    await settle(ws, 'PRIVMSG');
    expect(ws.sent.filter((l) => l.includes('PRIVMSG'))).toEqual(['PRIVMSG #room :hello']);

    const guest = await makeRegistered();
    guest.client.sendMessage('#room', 'hello');
    await settle(guest.ws, 'PRIVMSG');
    expect(guest.ws.sent.filter((l) => l.includes('PRIVMSG'))).toEqual([
      'PRIVMSG #room :hello',
    ]);
  });

  it('closes the same window again on a reconnect', async () => {
    const { client, ws } = await loggedIn('message-tags server-time freeq.at/msgsig');
    await settle(ws, 'MSGSIG ');
    ws.close();
    await flushAsync();

    // Same sequence on the new connection; the guarantee has to be re-armed,
    // not spent.
    client.connect();
    await flushAsync();
    const ws2 = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws2.recv(':srv CAP * LS :message-tags server-time freeq.at/msgsig');
    await flushAsync();
    ws2.recv(':srv CAP * ACK :message-tags server-time freeq.at/msgsig');
    await flushAsync();
    ws2.recv(':srv 903 alice :SASL authentication successful');
    await flushAsync();
    ws2.recv(':srv 001 alice :Welcome');
    await flushAsync();

    client.createTask('#room', 'again');
    await settle(ws2, 'MSGSIG ', 'TAGMSG');
    const msgsig = ws2.sent.findIndex((l) => l.startsWith('MSGSIG '));
    const tagmsg = ws2.sent.findIndex((l) => l.includes('TAGMSG'));
    expect(msgsig, `wire: ${ws2.sent.join(' | ')}`).toBeGreaterThan(-1);
    expect(msgsig, `wire: ${ws2.sent.join(' | ')}`).toBeLessThan(tagmsg);
    expect(ws2.sent[tagmsg]!).toContain('+freeq.at/sig=');
  });

  it('a mutation to a peer we cannot name still sends, unsigned', async () => {
    const { client, ws } = await makeSigningClient();
    client.sendReaction('carol', '👍', 'M0');
    const line = await waitForSent(ws, 'TAGMSG');
    expect(line, 'a nick we have no DID for stays a nick').toContain('TAGMSG carol');
    expect(line, 'a bare nick is no venue a verifier could rebuild').not.toContain(
      '+freeq.at/sig',
    );
  });

  it('an action against a legacy server is an ordinary unsigned PRIVMSG', async () => {
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    client.sendAction('#room', 'waves');
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG'));
    expect(line).toBe('PRIVMSG #room :\x01ACTION waves\x01');
  });

  // A tagged send is a durable statement whose coordination tags are exactly
  // what the document's covered-coord set exists to protect. It signs like
  // any other message, with those tags inside the document.
  it('sendTagged signs the document, coordination tags included', async () => {
    const { client, ws, verifyKey } = await makeSigningClient();
    const coord = {
      '+freeq.at/event': 'society-question',
      '+freeq.at/ref': 'r1',
      '+freeq.at/payload': '{"q":1}',
    };
    client.sendTagged('#room', 'question', coord);
    const line = await waitForSent(ws, '+freeq.at/sig');
    for (const name of Object.keys(coord)) {
      expect(tagOf(line, name), `line: ${line}`).not.toBeNull();
    }
    const eventId = tagOf(line, '+freeq.at/eventid')!;
    const sigTag = tagOf(line, '+freeq.at/sig')!;

    const signing = await import('./signing.js');
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: eventId,
      target: '#room',
      body: 'question',
      tags: coord,
    });
    expect(await verifySig(canonical, sigTag, verifyKey)).toBe(true);

    // The tags are in the document: the same signature must not verify a
    // document whose payload was swapped.
    const tampered = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: eventId,
      target: '#room',
      body: 'question',
      tags: { ...coord, '+freeq.at/payload': '{"q":2}' },
    });
    expect(await verifySig(tampered, sigTag, verifyKey)).toBe(false);
  });

  it('sendTagged against a legacy server stays a bare tagged PRIVMSG', async () => {
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    client.sendTagged('#room', 'question', { '+freeq.at/event': 'e' });
    await flushAsync();
    const line = ws.sent.find((l) => l.includes('PRIVMSG'));
    expect(line).toBe('@+freeq.at/event=e PRIVMSG #room question');
  });

  // Media and link previews are messages with metadata attached, and the
  // metadata is the part a reader acts on — so they sign like every other
  // message. The media tags themselves are not covered fields; they ride
  // outside the document, as the echo nonce does.
  it('a media send is signed, and its media tags survive intact', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendMedia('#room', {
      url: 'https://cdn.example/cat.png',
      mime: 'image/png',
      alt: 'a cat',
      width: 640,
    });
    const line = await waitForSent(ws, '+freeq.at/sig');
    expect(tagOf(line, '+freeq.at/media-url')).toBe('https://cdn.example/cat.png');
    expect(tagOf(line, '+freeq.at/media-mime')).toBe('image/png');
    expect(tagOf(line, '+freeq.at/media-alt')).toBe('a\\scat');
    expect(tagOf(line, '+freeq.at/media-w')).toBe('640');

    // The media tags are inside the document now: they are rendered, so a
    // signature that skipped them left a relay free to change what the
    // reader sees.
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body: '📎 https://cdn.example/cat.png',
      tags: {
        '+freeq.at/media-url': 'https://cdn.example/cat.png',
        '+freeq.at/media-mime': 'image/png',
        '+freeq.at/media-alt': 'a cat',
        '+freeq.at/media-w': '640',
      },
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('a link preview is signed over the fallback body a reader sees', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendLinkPreview('#room', {
      url: 'https://example.com/post',
      title: 'A post',
    });
    const line = await waitForSent(ws, '+freeq.at/sig');
    expect(tagOf(line, '+freeq.at/link-url')).toBe('https://example.com/post');

    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body: '🔗 A post (https://example.com/post)',
      tags: {
        '+freeq.at/link-url': 'https://example.com/post',
        '+freeq.at/link-title': 'A post',
      },
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  // A coordination event is the artifact the server stores and serves back as
  // a task card and an audit row, so it signs standalone rather than leaning
  // on the message that renders it.
  it('a coordination event is a TAGMSG signed over its own event id', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    const eventId = client.createTask('#room', 'ship it');
    const line = await waitForSent(ws, 'TAGMSG');

    expect(eventId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(tagOf(line, '+freeq.at/eventid')).toBe(eventId);
    expect(line, 'the legacy self-minted id is gone under the cap').not.toContain('msgid=');

    const canonical = await signing.coordinationCanonical({
      from: 'did:plc:mutator',
      msgid: eventId,
      target: '#room',
      eventType: 'task_request',
      payload: '{"description":"ship%20it"}',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('an event that references a task covers the reference it names', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.completeTask('#room', '01KYVT1W2P0000000000000000', 'done');
    const line = await waitForSent(ws, 'TAGMSG');
    const sigTag = tagOf(line, '+freeq.at/sig')!;

    const canonical = await signing.coordinationCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      eventType: 'task_complete',
      payload: '{"summary":"done"}',
      ref: '01KYVT1W2P0000000000000000',
    });
    expect(await verifySig(canonical, sigTag, verifyKey)).toBe(true);

    // Re-pointing the completion at another task is tampering, and reads as it.
    const repointed = await signing.coordinationCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      eventType: 'task_complete',
      payload: '{"summary":"done"}',
      ref: '01KYVT9ZZZ0000000000000000',
    });
    expect(await verifySig(repointed, sigTag, verifyKey)).toBe(false);
  });

  // The TAGMSG is the event: it carries the event's id under its own
  // signature. The companion is a rendering of it — an ordinary signed
  // message whose covered event tags are what a reader draws a card from —
  // and it makes no claim to the event's id.
  it('the companion is a rendering: signed event tags, no claim to the event id', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    const eventId = client.emitEvent('#room', 'task_request', { description: 'ship it' }, {
      humanText: 'New task: ship it',
    });
    const privmsg = await waitForSent(ws, 'PRIVMSG');
    const tagmsg = ws.sent.find((l) => l.includes('TAGMSG'))!;

    expect(tagOf(tagmsg, '+freeq.at/eventid')).toBe(eventId);
    expect(
      tagOf(privmsg, '+freeq.at/coordid'),
      'a message never carries another event’s id',
    ).toBeNull();
    const messageId = tagOf(privmsg, '+freeq.at/eventid')!;
    expect(messageId, 'each document signs its own id').not.toBe(eventId);

    const coord = {
      '+freeq.at/event': 'task_request',
      '+freeq.at/payload': '{"description":"ship%20it"}',
    };
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: messageId,
      target: '#room',
      body: 'New task: ship it',
      tags: coord,
    });
    expect(await verifySig(canonical, tagOf(privmsg, '+freeq.at/sig')!, verifyKey)).toBe(true);

    // Sanitizing a covered event tag off the rendering is tampering.
    const sanitized = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: messageId,
      target: '#room',
      body: 'New task: ship it',
      tags: { '+freeq.at/event': 'task_request' },
    });
    expect(await verifySig(sanitized, tagOf(privmsg, '+freeq.at/sig')!, verifyKey)).toBe(false);
  });

  // Signing moved these sends off the synchronous socket write, and each one
  // awaits its own signature. If completion order could differ from call
  // order, a streaming reply would edit itself out of sequence and land on
  // the wrong text — freeqcc sends a chunk and then edits it, twice.
  it('keeps call order on the wire when every send is signed', async () => {
    const { client, ws } = await makeSigningClient();
    client.sendTagged('#room', 'chunk one', { '+freeq.at/streaming': '1' });
    client.sendTagged('#room', 'chunk one and two', { '+draft/edit': 'M0', '+freeq.at/streaming': '1' });
    client.sendTagged('#room', 'chunk one and two and three', { '+draft/edit': 'M0' });
    for (let i = 0; i < 100 && ws.sent.length < 3; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(ws.sent).toHaveLength(3);
    const bodies = ws.sent.map((l) => l.slice(l.lastIndexOf(' :') + 2));
    expect(bodies, `wire: ${ws.sent.join(' | ')}`).toEqual([
      'chunk one',
      'chunk one and two',
      'chunk one and two and three',
    ]);
  });

  // The TAGMSG is the event; the companion is a message. A receiver holding
  // both halves reports exactly one event, under the event's own id — not by
  // de-duping the pair, but because the companion never fires
  // `coordinationEvent` at all. Replaying the lines the emitter actually
  // produced is what pins this — a hand-written legacy fixture cannot.
  it('a signed pair read back is one event, carrying the event id', async () => {
    const { client: sender, ws: senderWs } = await makeSigningClient();
    const eventId = sender.createTask('#room', 'ship it');
    const tagmsgOut = await waitForSent(senderWs, 'TAGMSG');
    const privmsgOut = await waitForSent(senderWs, 'PRIVMSG');

    const { client, ws } = await makeRegistered();
    const seen: Array<{ eventId: string; eventType: string }> = [];
    const messages: string[] = [];
    client.on('coordinationEvent', (e) =>
      seen.push({ eventId: e.eventId, eventType: e.eventType }),
    );
    client.on('message', (_ch, m) => messages.push(m.text));
    // What the server puts on a receiver's socket, built from those exact
    // lines: the sender's prefix after the tags, a TAGMSG relayed verbatim,
    // and a companion whose signer-minted event id has been adopted as the
    // message's own `msgid` (`strip_event_id_tag` then `msgid`, server-side).
    const relayed = (sent: string): string => {
      const [tags, ...rest] = sent.split(' ');
      return `${tags} :bot!u@h ${rest.join(' ')}`;
    };
    ws.recv(relayed(tagmsgOut));
    ws.recv(
      relayed(privmsgOut.replace(/\+freeq\.at\/eventid=([0-9A-HJKMNP-TV-Z]{26})/, 'msgid=$1')),
    );
    await flushAsync();

    expect(seen, 'one event, not one per half').toHaveLength(1);
    expect(seen[0]!.eventId, "the event's own id, not the companion's").toBe(eventId);
    expect(seen[0]!.eventType).toBe('task_request');
    expect(messages, 'the companion still renders as a message').toContain(
      '📋 New task: ship it',
    );
  });

  // The id is handed to the caller before the signature exists, so the send
  // has to file under it whatever happens next. Two ways it could not:
  // signing failing after the emitter committed to signing, and a caller
  // naming an id the server will refuse to adopt.
  it('files under the id it returned even when signing fails after the fact', async () => {
    const { client, ws } = await makeSigningClient();
    vi.spyOn(client.signing, 'signCoordination').mockResolvedValue(null);
    const eventId = client.createTask('#room', 'ship it');
    const line = await waitForSent(ws, 'TAGMSG');
    expect(line).not.toContain('+freeq.at/sig');
    expect(
      tagOf(line, 'msgid'),
      'unsigned, but still filed under the id the caller holds',
    ).toBe(eventId);
  });

  it('lets a caller-named id the server would refuse take the unsigned path', async () => {
    const { client, ws } = await makeSigningClient();
    // Not ULID-shaped: the server will not adopt it, and signing over it
    // would produce a document filed under a different id than it names.
    const eventId = client.emitEvent('#room', 'task_request', { description: 'x' }, {
      eventId: 'task-abc',
      humanText: 'New task: x',
    });
    await flushAsync();
    expect(eventId).toBe('task-abc');
    const line = ws.sent.find((l) => l.includes('TAGMSG'))!;
    expect(tagOf(line, 'msgid')).toBe('task-abc');
    expect(line).not.toContain('+freeq.at/sig');
    expect(line).not.toContain('+freeq.at/eventid');
  });

  // What kind of evidence an event carries is rendered — the card's icon and
  // label — and handed to bots. It rode on a signed event covered by nothing,
  // so a relay could relabel it with both signatures still verifying.
  it('covers the kind of evidence an event carries, on both halves', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.attachEvidence('#room', '01KYVT1W2P0000000000000000', 'code_review', 'looks ok');
    const tagmsg = await waitForSent(ws, 'TAGMSG');
    const privmsg = await waitForSent(ws, 'PRIVMSG');
    expect(tagOf(tagmsg, '+freeq.at/evidence-type')).toBe('code_review');

    const eventId = tagOf(tagmsg, '+freeq.at/eventid')!;
    const payload = tagOf(tagmsg, '+freeq.at/payload')!;
    const canonical = await signing.coordinationCanonical({
      from: 'did:plc:mutator',
      msgid: eventId,
      target: '#room',
      eventType: 'evidence_attach',
      payload,
      ref: '01KYVT1W2P0000000000000000',
      evidence: 'code_review',
    });
    expect(await verifySig(canonical, tagOf(tagmsg, '+freeq.at/sig')!, verifyKey)).toBe(true);

    // Relabelled is a different claim, and reads as one.
    const relabelled = await signing.coordinationCanonical({
      from: 'did:plc:mutator',
      msgid: eventId,
      target: '#room',
      eventType: 'evidence_attach',
      payload,
      ref: '01KYVT1W2P0000000000000000',
      evidence: 'test_run',
    });
    expect(await verifySig(relabelled, tagOf(tagmsg, '+freeq.at/sig')!, verifyKey)).toBe(false);

    // And the companion covers it through its coordination tags.
    const companionDoc = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(privmsg, '+freeq.at/eventid')!,
      target: '#room',
      body: '📎 Evidence (code_review): looks ok',
      tags: {
        '+freeq.at/event': 'evidence_attach',
        '+freeq.at/payload': payload,
        '+freeq.at/ref': '01KYVT1W2P0000000000000000',
        '+freeq.at/evidence-type': 'code_review',
      },
    });
    expect(await verifySig(companionDoc, tagOf(privmsg, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  // An attachment is rendered — an image inline, a link's title and
  // description on screen — so a value no signature covers is one a relay can
  // change with the message still verifying.
  it('covers what an attachment says about itself', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendMedia('#room', {
      url: 'https://cdn.example/cat.png',
      mime: 'image/png',
      alt: 'a cat',
    });
    const line = await waitForSent(ws, '+freeq.at/sig');
    const tags = {
      '+freeq.at/media-url': 'https://cdn.example/cat.png',
      '+freeq.at/media-mime': 'image/png',
      '+freeq.at/media-alt': 'a cat',
    };
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body: '📎 https://cdn.example/cat.png',
      tags,
    });
    const sig = tagOf(line, '+freeq.at/sig')!;
    expect(await verifySig(canonical, sig, verifyKey)).toBe(true);

    // Repointed at another file, relabelled, or retyped: each is a different
    // claim about what was attached.
    for (const swap of [
      { '+freeq.at/media-url': 'https://cdn.example/dog.png' },
      { '+freeq.at/media-alt': 'a dog' },
      { '+freeq.at/media-mime': 'text/plain' },
    ]) {
      const tampered = await signing.messageCanonical({
        from: 'did:plc:mutator',
        msgid: tagOf(line, '+freeq.at/eventid')!,
        target: '#room',
        body: '📎 https://cdn.example/cat.png',
        tags: { ...tags, ...swap },
      });
      expect(await verifySig(tampered, sig, verifyKey), JSON.stringify(swap)).toBe(false);
    }
  });

  it('covers a link preview title, and signs no field the sender left out', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendLinkPreview('#room', { url: 'https://example.com/post', title: 'A post' });
    const line = await waitForSent(ws, '+freeq.at/sig');
    const body = '🔗 A post (https://example.com/post)';
    const tags = {
      '+freeq.at/link-url': 'https://example.com/post',
      '+freeq.at/link-title': 'A post',
    };
    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body,
      tags,
    });
    const sig = tagOf(line, '+freeq.at/sig')!;
    expect(await verifySig(canonical, sig, verifyKey)).toBe(true);

    const retitled = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body,
      tags: { ...tags, '+freeq.at/link-title': 'Something else entirely' },
    });
    expect(await verifySig(retitled, sig, verifyKey)).toBe(false);

    // A field the sender never sent is not in the document. A reader's
    // default for an absent type is a rendering decision; putting it in the
    // signed bytes would have every other implementation rebuild a document
    // the sender never signed.
    const noMime = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: 'M0',
      target: '#room',
      body: 'x',
      tags: { '+freeq.at/media-url': 'https://cdn.example/thing.bin' },
    });
    expect(noMime).not.toContain('media-mime');
    expect(noMime).toContain('"media-url"');
  });

  // A server that never offered the signing cap gets exactly the shape it
  // always got — legacy id in `msgid`, the pair of frames, no signature. The
  // one field that moved is the reference, which both spellings have always
  // meant and which readers still accept under either.
  it('an emitted event against a legacy server keeps its unsigned shape', async () => {
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    const eventId = client.emitEvent('#room', 'task_request', { description: 'ship it' }, {
      refId: 'task-abc',
      humanText: '📋 New task: ship it',
    });
    await flushAsync();
    expect(eventId, 'the legacy id format is what a legacy server files').toMatch(/^[0-9a-f]+$/);
    const tags =
      `msgid=${eventId};+freeq.at/event=task_request;` +
      '+freeq.at/payload={"description":"ship%20it"};+freeq.at/ref=task-abc';
    expect(ws.sent).toEqual([
      `@${tags} TAGMSG #room`,
      `@${tags} PRIVMSG #room :📋 New task: ship it`,
    ]);
  });

  // The generic TAGMSG door and the named helpers lead to the same place:
  // which method a caller reached for is not a reason for one delete to be
  // provable and another not.
  it('a mutation handed to the generic TAGMSG helper is signed like any other', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendTagmsg('#room', { '+draft/delete': 'M0' });
    const line = await waitForSent(ws, 'TAGMSG');

    const canonical = signing.mutationCanonical({
      kind: 'delete',
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      subject: 'M0',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('an ephemeral TAGMSG handed to the same helper stays unsigned', async () => {
    const { client, ws } = await makeSigningClient();
    client.sendTagmsg('#room', { '+typing': 'active' });
    await flushAsync();
    expect(ws.sent).toEqual(['@+typing=active TAGMSG #room']);
  });

  // A notice is a statement under the sender's name like any other, and the
  // server checks it against the same document — so an agent that answers by
  // NOTICE carries the same proof as one that answers by PRIVMSG.
  it('a notice is signed over the same document a message would be', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.sendNotice('#room', 'back in five');
    const line = await waitForSent(ws, 'NOTICE');

    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body: 'back in five',
    });
    expect(await verifySig(canonical, tagOf(line, '+freeq.at/sig')!, verifyKey)).toBe(true);
  });

  it('a notice against a legacy server is a plain NOTICE line', async () => {
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    client.sendNotice('#room', 'back in five');
    await flushAsync();
    expect(ws.sent).toEqual(['NOTICE #room :back in five']);
  });

  it('media and link previews against a legacy server are byte-identical to before', async () => {
    const { client, ws } = await makeRegistered();
    client.signing.setSigningDid('did:plc:mutator');
    await client.signing.generateSigningKey();
    client.sendMedia('#room', { url: 'https://cdn.example/cat.png', mime: 'image/png' });
    client.sendLinkPreview('#room', { url: 'https://example.com/post' });
    // Two separate sends, each taking its turn on the queue.
    for (let i = 0; i < 50 && ws.sent.length < 2; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(ws.sent).toEqual([
      '@+freeq.at/media-url=https://cdn.example/cat.png;+freeq.at/media-mime=image/png ' +
        'PRIVMSG #room :📎 https://cdn.example/cat.png',
      '@+freeq.at/link-url=https://example.com/post PRIVMSG #room :🔗 https://example.com/post',
    ]);
  });
});

describe('roster-time actor class (numeric 674)', () => {
  it('reports the class of members who were already in the channel', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<{ channel: string; nick: string; actorClass?: string }> = [];
    client.on('memberJoined', (channel, m) =>
      seen.push({ channel, nick: m.nick, actorClass: m.actorClass }),
    );

    ws.recv(':srv 674 alice #ops :worker=agent bridge=external_agent');
    await flushAsync();

    expect(seen).toEqual([
      { channel: '#ops', nick: 'worker', actorClass: 'agent' },
      { channel: '#ops', nick: 'bridge', actorClass: 'external_agent' },
    ]);
  });

  it('ignores malformed entries and unknown classes rather than inventing members', async () => {
    const { client, ws } = await makeRegistered();
    const seen: string[] = [];
    client.on('memberJoined', (_c, m) => seen.push(m.nick));
    ws.recv(':srv 674 alice #ops :garbage nick= =agent bot=wizard');
    await flushAsync();
    expect(seen).toEqual([]);
  });

  it('handles an empty list', async () => {
    const { client, ws } = await makeRegistered();
    const seen: string[] = [];
    client.on('memberJoined', (_c, m) => seen.push(m.nick));
    ws.recv(':srv 674 alice #ops :');
    await flushAsync();
    expect(seen).toEqual([]);
  });
});

describe('structured presence relay', () => {
  it('carries the status of an ACTIVE agent (the AWAY path cannot)', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<{ nick: string; state: string; status?: string; task?: string }> = [];
    client.on('presence', (p) => seen.push(p as never));

    ws.recv(':busybot!u@h PRESENCE :state=active;status=project=freeq branch=main');
    await flushAsync();

    expect(seen).toHaveLength(1);
    expect(seen[0].nick).toBe('busybot');
    expect(seen[0].state).toBe('active');
    expect(seen[0].status).toBe('project=freeq branch=main');
  });

  it('carries state, status and task together', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<{ state: string; status?: string; task?: string }> = [];
    client.on('presence', (p) => seen.push(p as never));

    ws.recv(':bot!u@h PRESENCE :state=executing;status=fixing the parser;task=01ABCDEF');
    await flushAsync();

    expect(seen[0]).toMatchObject({
      state: 'executing',
      status: 'fixing the parser',
      task: '01ABCDEF',
    });
  });

  it('tolerates a bare state with no status', async () => {
    const { client, ws } = await makeRegistered();
    const seen: Array<{ state: string; status?: string }> = [];
    client.on('presence', (p) => seen.push(p as never));
    ws.recv(':bot!u@h PRESENCE :state=idle');
    await flushAsync();
    expect(seen[0]).toMatchObject({ state: 'idle' });
    expect(seen[0].status).toBeUndefined();
  });

  it('ignores a relay with no state', async () => {
    const { client, ws } = await makeRegistered();
    const seen: unknown[] = [];
    client.on('presence', (p) => seen.push(p));
    ws.recv(':bot!u@h PRESENCE :status=orphaned');
    await flushAsync();
    expect(seen).toEqual([]);
  });
});
