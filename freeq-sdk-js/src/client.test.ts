/** Unit tests for FreeqClient. */

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
    // TARGETS only ever arrive on an authenticated session; the client now
    // skips DM-history fetches as a guest, so simulate the authed state.
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
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/task-id=task-abc');
  });

  it('completeTask() emits task_complete', async () => {
    const { client, ws } = await makeRegistered();
    client.completeTask('#foo', 'task-abc', 'done', 'https://result');
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/event=task_complete');
  });

  it('failTask() emits task_failed', async () => {
    const { client, ws } = await makeRegistered();
    client.failTask('#foo', 'task-abc', 'something broke');
    const line = ws.sent.find((l) => l.includes('TAGMSG'));
    expect(line).toContain('+freeq.at/event=task_failed');
  });

  it('attachEvidence() emits evidence_attach with evidence-type tag', async () => {
    const { client, ws } = await makeRegistered();
    client.attachEvidence('#foo', 'task-abc', 'code_review', 'looks ok');
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

  it('opts.mode=before throws if msgid missing', async () => {
    const { client } = await makeRegistered();
    expect(() => client.requestHistory({ target: '#foo', mode: 'before' })).toThrow(/msgid/);
  });

  it('legacy two-arg form still works', async () => {
    const { client, ws } = await makeRegistered();
    client.requestHistory('#foo');
    expect(ws.sent).toContain('CHATHISTORY LATEST #foo * 50');
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

    const canonical = await signing.messageCanonical({
      from: 'did:plc:mutator',
      msgid: tagOf(line, '+freeq.at/eventid')!,
      target: '#room',
      body: '📎 https://cdn.example/cat.png',
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

  it('the companion message is signed on its own, and carries the event tags', async () => {
    const signing = await import('./signing.js');
    const { client, ws, verifyKey } = await makeSigningClient();
    client.emitEvent('#room', 'task_request', { description: 'ship it' }, {
      humanText: 'New task: ship it',
    });
    const privmsg = await waitForSent(ws, 'PRIVMSG');
    const tagmsg = ws.sent.find((l) => l.includes('TAGMSG'))!;

    const messageId = tagOf(privmsg, '+freeq.at/eventid')!;
    expect(messageId, 'each document signs its own id').not.toBe(
      tagOf(tagmsg, '+freeq.at/eventid'),
    );
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
  });

  it('an emitted event against a legacy server is byte-identical to before', async () => {
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
      '+freeq.at/payload={"description":"ship%20it"};+freeq.at/task-id=task-abc';
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
    await flushAsync();
    expect(ws.sent).toEqual([
      '@+freeq.at/media-url=https://cdn.example/cat.png;+freeq.at/media-mime=image/png ' +
        'PRIVMSG #room :📎 https://cdn.example/cat.png',
      '@+freeq.at/link-url=https://example.com/post PRIVMSG #room :🔗 https://example.com/post',
    ]);
  });
});
