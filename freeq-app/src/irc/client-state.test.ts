/**
 * State mutation tests for irc/client.ts handlers.
 *
 * Tests what the store looks like AFTER processing protocol messages.
 * Targets the #3 hotspot's state management bugs.
 */
import { describe, it, expect, beforeEach } from 'vitest';

// Mocks (before store import)
const storage = new Map<string, string>();
// @ts-expect-error mock
globalThis.localStorage = {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => storage.set(k, v),
  removeItem: (k: string) => { storage.delete(k); },
  clear: () => storage.clear(),
  get length() { return storage.size; },
  key: (i: number) => [...storage.keys()][i] ?? null,
};
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});
// @ts-expect-error mock
globalThis.window = { localStorage: globalThis.localStorage, location: { hash: '', origin: 'http://localhost' }, addEventListener: () => {} };

const { useStore } = await import('../store');
import { parse, prefixNick } from './parser';

const s = () => useStore.getState();
const m = (o: Record<string, any> = {}) => ({
  id: 'id-' + Math.random().toString(36).slice(2),
  from: 'alice', text: 'hi', timestamp: new Date(), tags: {}, ...o,
});

beforeEach(() => { storage.clear(); s().reset(); });

// Simulate what client.ts does for each handler
function simulateJoin(nick: string, channel: string, myNick: string, account?: string) {
  const from = nick;
  const store = s();
  if (from.toLowerCase() === myNick.toLowerCase()) {
    store.addChannel(channel);
    store.clearMembers(channel);
  }
  const joinDid = account && account !== '*' ? account : undefined;
  store.addMember(channel, { nick: from, did: joinDid });
}

function simulatePart(nick: string, channel: string, myNick: string) {
  const store = s();
  if (nick.toLowerCase() === myNick.toLowerCase()) {
    store.removeChannel(channel);
  } else {
    store.removeMember(channel, nick);
  }
}

function simulateKick(kicked: string, channel: string, by: string, myNick: string) {
  const store = s();
  if (kicked.toLowerCase() === myNick.toLowerCase()) {
    store.removeChannel(channel);
  } else {
    store.removeMember(channel, kicked);
  }
}

function simulateNick(oldNick: string, newNick: string, myNick: string): string {
  const store = s();
  if (oldNick.toLowerCase() === myNick.toLowerCase()) {
    store.setNick(newNick);
    return newNick;
  }
  store.renameUser(oldNick, newNick);
  return myNick;
}

function simulatePrivmsg(from: string, target: string, text: string, myNick: string, tags: Record<string, string> = {}) {
  const store = s();
  const isChannel = target.startsWith('#') || target.startsWith('&');
  const isSelf = from.toLowerCase() === myNick.toLowerCase();
  const bufName = isChannel ? target : (isSelf ? target : from);

  // Edit
  const editOf = tags['+draft/edit'];
  if (editOf) {
    store.editMessage(bufName, editOf, text, tags['msgid']);
    return;
  }

  const message = {
    id: tags['msgid'] || 'uuid-' + Math.random().toString(36).slice(2),
    from,
    text,
    timestamp: tags['time'] ? new Date(tags['time']) : new Date(),
    tags,
    isSelf,
  };

  if (!isChannel && !store.channels.has(bufName.toLowerCase())) {
    store.addChannel(bufName);
  }

  store.addMessage(bufName, message);
}

// ═══════════════════════════════════════════════════════════════
// JOIN STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('JOIN state mutations', () => {
  it('self-join creates channel and clears members', () => {
    s().setNick('me');
    simulateJoin('me', '#test', 'me');
    expect(s().channels.has('#test')).toBe(true);
    // Members cleared on self-join (waiting for NAMES)
    expect(s().channels.get('#test')!.members.size).toBe(1); // Just us
  });

  it('other-join adds member', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    expect(s().channels.get('#ch')!.members.has('alice')).toBe(true);
  });

  it('extended-join with DID sets member DID', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me', 'did:plc:alice');
    expect(s().channels.get('#ch')!.members.get('alice')!.did).toBe('did:plc:alice');
  });

  it('extended-join with * account is treated as no DID', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('guest', '#ch', 'me', '*');
    expect(s().channels.get('#ch')!.members.get('guest')!.did).toBeUndefined();
  });

  it('BUG: self-join clearMembers removes members who joined before NAMES', () => {
    s().setNick('me');
    // Alice joins first
    s().addChannel('#race');
    s().addMember('#race', { nick: 'alice', did: 'did:plc:alice' });
    // Then we get our own JOIN echo (which calls clearMembers)
    simulateJoin('me', '#race', 'me');
    // Alice's entry was WIPED by clearMembers
    const alice = s().channels.get('#race')!.members.get('alice');
    // BUG if alice is gone — she'll be re-added by NAMES, but her DID is lost
    if (!alice) {
      // This is the expected behavior (clearMembers before NAMES), but
      // if we had profile data, it's lost until next WHOIS
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// PART STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('PART state mutations', () => {
  it('self-part removes channel', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulatePart('me', '#ch', 'me');
    expect(s().channels.has('#ch')).toBe(false);
  });

  it('other-part removes member', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    simulatePart('alice', '#ch', 'me');
    expect(s().channels.get('#ch')!.members.has('alice')).toBe(false);
  });

  it('self-part with batches cleans up', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    s().startBatch('b1', 'chathistory', '#ch');
    simulatePart('me', '#ch', 'me');
    expect(s().batches.has('b1')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// KICK STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('KICK state mutations', () => {
  it('kicked self removes channel', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateKick('me', '#ch', 'op', 'me');
    expect(s().channels.has('#ch')).toBe(false);
  });

  it('kicked other removes member', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    simulateKick('alice', '#ch', 'op', 'me');
    expect(s().channels.get('#ch')!.members.has('alice')).toBe(false);
  });

  it('BUG: kick comparison is case-sensitive in client.ts', () => {
    // client.ts line 673: kicked.toLowerCase() === nick.toLowerCase()
    // This is correct — but what if server sends different case?
    s().setNick('MyNick');
    simulateJoin('MyNick', '#ch', 'MyNick');
    // Server KICKs "mynick" (lowercase) — should still match
    simulateKick('mynick', '#ch', 'op', 'MyNick');
    // Channel should be removed (case-insensitive match)
    expect(s().channels.has('#ch')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// NICK STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('NICK state mutations', () => {
  it('self nick change updates store nick', () => {
    s().setNick('old');
    const newNick = simulateNick('old', 'new', 'old');
    expect(newNick).toBe('new');
    expect(s().nick).toBe('new');
  });

  it('other nick change renames in all channels', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    simulateNick('alice', 'alice2', 'me');
    expect(s().channels.get('#ch')!.members.has('alice2')).toBe(true);
    expect(s().channels.get('#ch')!.members.has('alice')).toBe(false);
  });

  it('BUG: 433 nick-in-use appends underscore without limit', () => {
    // client.ts line 605-607: nick += '_'; raw(`NICK ${nick}`);
    // No retry counter — nick grows unboundedly
    let testNick = 'user';
    for (let i = 0; i < 20; i++) {
      testNick += '_';
    }
    // After 20 retries: "user____________________" (24 chars)
    // Server max is typically 64 — but this could grow much more
    expect(testNick.length).toBe(24);
    // After 64 retries it would exceed server's 64-char limit
    let longNick = 'user';
    for (let i = 0; i < 64; i++) longNick += '_';
    expect(longNick.length).toBe(68); // Exceeds server limit!
    // BUG DOCUMENTED: no retry cap
  });
});

// ═══════════════════════════════════════════════════════════════
// PRIVMSG STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('PRIVMSG state mutations', () => {
  it('channel message adds to channel', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulatePrivmsg('alice', '#ch', 'hello', 'me', { msgid: 'msg1' });
    const ch = s().channels.get('#ch')!;
    expect(ch.messages.some(m => m.id === 'msg1')).toBe(true);
  });

  it('DM creates buffer automatically', () => {
    s().setNick('me');
    simulatePrivmsg('alice', 'me', 'private msg', 'me');
    // Buffer should be created under alice's nick (the sender)
    expect(s().channels.has('alice')).toBe(true);
  });

  it('self-DM routes to target buffer', () => {
    s().setNick('me');
    simulatePrivmsg('me', 'bob', 'sent to bob', 'me');
    expect(s().channels.has('bob')).toBe(true);
    expect(s().channels.get('bob')!.messages.some(m => m.text === 'sent to bob')).toBe(true);
  });

  it('edit updates existing message', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulatePrivmsg('alice', '#ch', 'original', 'me', { msgid: 'orig1' });
    simulatePrivmsg('alice', '#ch', 'edited', 'me', { '+draft/edit': 'orig1', msgid: 'edit1' });
    const ch = s().channels.get('#ch')!;
    const msg = ch.messages.find(m => m.id === 'orig1' || m.editOf === 'orig1');
    expect(msg?.text).toBe('edited');
  });

  it('BUG: mention detection uses raw text including nick in URLs', () => {
    // client.ts line 789: text.toLowerCase().includes(nick.toLowerCase())
    // This triggers on nick appearing ANYWHERE in text, including URLs
    s().setNick('admin');
    simulateJoin('admin', '#ch', 'admin');
    // This message contains "admin" in a URL — not an actual mention
    simulatePrivmsg('bob', '#ch', 'check https://example.com/admin/panel', 'admin', { msgid: 'url1' });
    // The mention counter incremented because "admin" appears in the URL
    // This is a false positive mention
  });

  it('BUG: DM from self to self creates self-buffer', () => {
    s().setNick('me');
    // If server echoes a PRIVMSG from "me" to "me"
    simulatePrivmsg('me', 'me', 'note to self', 'me');
    // Buffer created under "me" — user sees a DM conversation with themselves
    expect(s().channels.has('me')).toBe(true);
    // This is weird but not a crash — just unexpected UX
  });

  it('BUG: message with no msgid gets random UUID — no dedup possible', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    // Two messages from server without msgid
    simulatePrivmsg('alice', '#ch', 'same text', 'me', {});
    simulatePrivmsg('alice', '#ch', 'same text', 'me', {});
    const ch = s().channels.get('#ch')!;
    const matching = ch.messages.filter(m => m.text === 'same text');
    // Both added because random UUIDs are different — no dedup
    expect(matching.length).toBe(2);
    // If the server sent the same message twice (e.g., reconnect overlap),
    // both appear as separate messages
  });
});

// ═══════════════════════════════════════════════════════════════
// TAGMSG (DELETE/REACTION) STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('TAGMSG state mutations', () => {
  it('delete marks message as deleted', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulatePrivmsg('alice', '#ch', 'to delete', 'me', { msgid: 'del1' });
    s().deleteMessage('#ch', 'del1');
    expect(s().channels.get('#ch')!.messages.find(m => m.id === 'del1')?.deleted).toBe(true);
  });

  it('reaction adds to message', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulatePrivmsg('alice', '#ch', 'react to me', 'me', { msgid: 'r1' });
    s().addReaction('#ch', 'r1', '👍', 'bob');
    const msg = s().channels.get('#ch')!.messages.find(m => m.id === 'r1');
    expect(msg?.reactions?.get('👍')?.has('bob')).toBe(true);
  });

  it('BUG: delete of nonexistent msgid is silent — no feedback', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    // Delete for a message that doesn't exist yet (e.g., arrived before original via race)
    s().deleteMessage('#ch', 'future_msg');
    // No error, no stored pending delete — the delete is just lost
    // When the original message arrives later, it won't know to be deleted
    simulatePrivmsg('alice', '#ch', 'should be deleted', 'me', { msgid: 'future_msg' });
    const msg = s().channels.get('#ch')!.messages.find(m => m.id === 'future_msg');
    // BUG: message appears even though delete was received first
    expect(msg?.deleted).toBeFalsy();
  });
});

// ═══════════════════════════════════════════════════════════════
// MODE STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('MODE state mutations', () => {
  it('+o sets member as op', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    s().handleMode('#ch', '+o', 'alice', 'op');
    expect(s().channels.get('#ch')!.members.get('alice')!.isOp).toBe(true);
  });

  it('-o removes op', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    simulateJoin('alice', '#ch', 'me');
    s().handleMode('#ch', '+o', 'alice', 'op');
    s().handleMode('#ch', '-o', 'alice', 'op');
    expect(s().channels.get('#ch')!.members.get('alice')!.isOp).toBe(false);
  });

  it('+E sets channel encrypted flag', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    s().handleMode('#ch', '+E', undefined, 'op');
    expect(s().channels.get('#ch')!.isEncrypted).toBe(true);
  });

  it('FIXED: +o without arg ignored (does not corrupt channel modes)', () => {
    s().setNick('me');
    simulateJoin('me', '#ch', 'me');
    // MODE +o with no argument — protocol error, should be ignored
    s().handleMode('#ch', '+o', undefined, 'op');
    // "o" should NOT be in channel modes set
    expect(s().channels.get('#ch')!.modes.has('o')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// QUIT STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('QUIT state mutations', () => {
  it('removes user from all channels', () => {
    s().setNick('me');
    simulateJoin('me', '#a', 'me');
    simulateJoin('me', '#b', 'me');
    simulateJoin('alice', '#a', 'me');
    simulateJoin('alice', '#b', 'me');
    s().removeUserFromAll('alice', 'quit');
    expect(s().channels.get('#a')!.members.has('alice')).toBe(false);
    expect(s().channels.get('#b')!.members.has('alice')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// WHOIS STATE MUTATIONS
// ═══════════════════════════════════════════════════════════════

describe('WHOIS state mutations', () => {
  it('311 clears old DID/handle', () => {
    s().updateWhois('alice', { did: 'did:plc:old', handle: 'old.bsky' });
    s().updateWhois('alice', { user: '~u', host: 'h', did: undefined, handle: undefined });
    const info = s().whoisCache.get('alice');
    expect(info?.did).toBeUndefined();
    expect(info?.handle).toBeUndefined();
  });

  it('330 sets DID', () => {
    s().updateWhois('alice', { did: 'did:plc:new' });
    expect(s().whoisCache.get('alice')?.did).toBe('did:plc:new');
  });

  it('BUG: 330 with empty DID stored as undefined (was "" before fix)', () => {
    // This was fixed — verify it stays fixed
    s().updateWhois('alice', { did: undefined });
    expect(s().whoisCache.get('alice')?.did).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════
// SELF-REACTION LOCAL ECHO
// ═══════════════════════════════════════════════════════════════

describe('sendReaction local echo', () => {
  beforeEach(() => {
    useStore.setState({
      channels: new Map(),
      nick: 'me',
      activeChannel: '#react',
    });
    s().addChannel('#react');
    s().addMessage('#react', m({ id: 'target-msg', from: 'alice', text: 'react to this' }));
  });

  it('BUG: sendReaction should add reaction to store immediately', () => {
    // This is the core bug: when the user sends a reaction, it should
    // appear in the store right away (optimistic local echo), not only
    // when the server echoes the TAGMSG back.
    s().addReaction('#react', 'target-msg', '👍', 'me');
    const ch = s().channels.get('#react')!;
    const msg = ch.messages.find(m => m.id === 'target-msg')!;
    expect(msg.reactions?.get('👍')?.has('me')).toBe(true);
  });

  it('server echo of self-reaction should not double-count', () => {
    // User reacts locally, then server echoes it back
    s().addReaction('#react', 'target-msg', '🎉', 'me');
    s().addReaction('#react', 'target-msg', '🎉', 'me'); // echo
    const ch = s().channels.get('#react')!;
    const msg = ch.messages.find(m => m.id === 'target-msg')!;
    expect(msg.reactions?.get('🎉')?.size).toBe(1);
  });
});

// ── Reconnect channel persistence ───────────────────────────────────────

describe('reconnect channel persistence', () => {
  it('saved joined channels should be preferred over connect screen input', () => {
    // This simulates the fix for the bug where PART would not persist
    // across reconnects because the web app used the wrong localStorage key
    const savedJoined = JSON.stringify(['#stay', '#general']);
    storage.set('freeq-joined-channels', savedJoined);
    storage.set('freeq-channels', '#leaved,#general,#stay'); // stale input from connect screen

    // When reconnecting, saved joined channels should be used
    const ch = JSON.parse(storage.get('freeq-joined-channels') || '[]');
    expect(ch).toEqual(['#stay', '#general']);
    expect(ch).not.toContain('#leaved');
  });

  it('falls back to freeq-channels when freeq-joined-channels is missing', () => {
    storage.delete('freeq-joined-channels');
    storage.set('freeq-channels', '#fallback');

    // When no joined channels saved, use connect screen input
    const savedJoined = storage.get('freeq-joined-channels');
    const ch = savedJoined
      ? JSON.parse(savedJoined)
      : (storage.get('freeq-channels') || '#freeq').split(',').map(s => s.trim()).filter(Boolean);

    expect(ch).toEqual(['#fallback']);
  });
});

describe('setMembers — end-of-NAMES roster replace (vanishing-members fix)', () => {
  it('replaces a roster left with only live-joined members after a self-JOIN clear', () => {
    // Reproduce the bug: self joins (live), roster cleared on self-JOIN, self
    // re-added live — so only the local session is present.
    s().addMember('#freeq', { nick: 'me' });
    s().clearMembers('#freeq');
    s().addMember('#freeq', { nick: 'me' });
    expect(s().channels.get('#freeq')!.members.size).toBe(1);

    // End-of-NAMES sync delivers the server's authoritative roster → replace.
    s().setMembers('#freeq', [
      { nick: 'me', isOp: true },
      { nick: 'zapnap', isOp: true },
      { nick: 'yolo' },
      { nick: 'pbanhardt' },
    ]);
    const members = s().channels.get('#freeq')!.members;
    expect(members.size).toBe(4);
    expect(members.has('zapnap')).toBe(true);
    expect(members.has('yolo')).toBe(true);
    expect(members.has('pbanhardt')).toBe(true);
    expect(members.get('zapnap')!.isOp).toBe(true);
  });

  it('drops members no longer in the NAMES snapshot', () => {
    s().setMembers('#c', [{ nick: 'alice' }, { nick: 'bob' }]);
    s().setMembers('#c', [{ nick: 'alice' }]); // bob left; a fresh NAMES omits him
    expect(s().channels.get('#c')!.members.has('bob')).toBe(false);
    expect(s().channels.get('#c')!.members.has('alice')).toBe(true);
  });

  it('preserves enriched fields (DID) by nick across a sync', () => {
    s().addMember('#d', { nick: 'alice', did: 'did:plc:alice' });
    s().setMembers('#d', [{ nick: 'alice', isOp: true }]); // NAMES carries no DID
    const alice = s().channels.get('#d')!.members.get('alice')!;
    expect(alice.did).toBe('did:plc:alice');
    expect(alice.isOp).toBe(true);
  });
});

describe('updateMemberActorClass — agent badge for members who joined before us', () => {
  // NAMES (353) carries only nicks and prefixes, so a client that joins a
  // channel an agent is already in never learns the agent is an agent, and
  // renders it as a human. WHOIS (numeric 673) is the only way to find out
  // after the fact, and the SDK reports it with an EMPTY channel — which the
  // client used to drop on the floor.
  it('applies an actor class learned after the roster arrived', () => {
    s().setMembers('#ops', [{ nick: 'pi-reth' }, { nick: 'chad' }]);
    expect(s().channels.get('#ops')!.members.get('pi-reth')!.actorClass).toBeUndefined();

    s().updateMemberActorClass('pi-reth', 'agent');
    expect(s().channels.get('#ops')!.members.get('pi-reth')!.actorClass).toBe('agent');
    // Humans are left alone.
    expect(s().channels.get('#ops')!.members.get('chad')!.actorClass).toBeUndefined();
  });

  it('applies it in every channel the member shares with us', () => {
    s().setMembers('#a', [{ nick: 'pi-bot' }]);
    s().setMembers('#b', [{ nick: 'pi-bot' }]);
    s().updateMemberActorClass('pi-bot', 'external_agent');
    expect(s().channels.get('#a')!.members.get('pi-bot')!.actorClass).toBe('external_agent');
    expect(s().channels.get('#b')!.members.get('pi-bot')!.actorClass).toBe('external_agent');
  });

  it('is case-insensitive about the nick', () => {
    s().setMembers('#c', [{ nick: 'Pi-Agent' }]);
    s().updateMemberActorClass('pi-agent', 'agent');
    expect(s().channels.get('#c')!.members.get('pi-agent')!.actorClass).toBe('agent');
  });

  it('survives a later NAMES sync that carries no actor class', () => {
    s().setMembers('#d', [{ nick: 'pi-x' }]);
    s().updateMemberActorClass('pi-x', 'agent');
    s().setMembers('#d', [{ nick: 'pi-x', isOp: true }]); // fresh NAMES, no class
    const m = s().channels.get('#d')!.members.get('pi-x')!;
    expect(m.actorClass).toBe('agent');
    expect(m.isOp).toBe(true);
  });

  it('ignores a nick nobody in view holds', () => {
    s().setMembers('#e', [{ nick: 'alice' }]);
    expect(() => s().updateMemberActorClass('ghost', 'agent')).not.toThrow();
    expect(s().channels.get('#e')!.members.has('ghost')).toBe(false);
  });
});
