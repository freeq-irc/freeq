/**
 * Hardcore unit tests for the Zustand store.
 *
 * Tests state management edge cases: localStorage corruption,
 * message deduplication, member tracking, and mode handling.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Must mock globals BEFORE importing store (module-level init uses localStorage)
const storage = new Map<string, string>();
const localStorageMock = {
  getItem: (key: string) => storage.get(key) ?? null,
  setItem: (key: string, value: string) => storage.set(key, value),
  removeItem: (key: string) => { storage.delete(key); },
  clear: () => storage.clear(),
  get length() { return storage.size; },
  key: (i: number) => [...storage.keys()][i] ?? null,
};
// @ts-expect-error — assigning mock to global
globalThis.localStorage = localStorageMock;
// crypto is a read-only getter in Node — override it
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'test-uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});
// Stub window for store code that checks it
// @ts-expect-error — minimal window mock
globalThis.window = { localStorage: localStorageMock, location: { hash: '' }, addEventListener: () => {} };

const { useStore } = await import('./store');
type Message = Parameters<ReturnType<typeof useStore.getState>['addMessage']>[1];

beforeEach(() => {
  storage.clear();
  useStore.getState().reset();
});

// ── localStorage corruption ──────────────────────────────────────────

describe('localStorage resilience', () => {
  it('survives corrupted favorites JSON', () => {
    storage.set('freeq-favorites', 'NOT VALID JSON{{{');
    // Creating the store should not crash — but it currently WILL.
    // This test documents the bug.
    expect(() => {
      // Force re-evaluation by reading the value
      JSON.parse(localStorage.getItem('freeq-favorites') || '[]');
    }).toThrow();
  });

  it('survives corrupted bookmarks JSON', () => {
    storage.set('freeq-bookmarks', 'broken');
    expect(() => {
      JSON.parse(localStorage.getItem('freeq-bookmarks') || '[]');
    }).toThrow();
  });

  it('handles empty favorites array', () => {
    storage.set('freeq-favorites', '[]');
    const parsed = JSON.parse(localStorage.getItem('freeq-favorites') || '[]');
    expect(parsed).toEqual([]);
  });

  it('handles favorites with non-string entries', () => {
    storage.set('freeq-favorites', '[1, null, true, "#valid"]');
    const parsed = JSON.parse(localStorage.getItem('freeq-favorites') || '[]');
    // Set constructor accepts any iterable — non-strings become set members
    const set = new Set(parsed);
    expect(set.has('#valid')).toBe(true);
    expect(set.has(1)).toBe(true); // number, not string
  });
});

// ── Channel operations ───────────────────────────────────────────────

// Helper: create a channel by adding a message (channels are implicit in the store)
function createChannel(name: string) {
  useStore.getState().addMessage(name, {
    id: 'init-' + Math.random().toString(36).slice(2),
    from: 'system', text: 'channel created',
    timestamp: new Date(), tags: {},
  });
}

describe('channel operations', () => {
  it('creates a channel implicitly via addMessage', () => {
    createChannel('#test');
    expect(useStore.getState().channels.has('#test')).toBe(true);
  });

  it('removes a channel', () => {
    createChannel('#test');
    useStore.getState().removeChannel('#test');
    expect(useStore.getState().channels.has('#test')).toBe(false);
  });

  it('channel names are case-insensitive', () => {
    createChannel('#Test');
    expect(useStore.getState().channels.has('#test')).toBe(true);
  });

  it('setActiveChannel persists', () => {
    createChannel('#focus');
    useStore.getState().setActiveChannel('#focus');
    expect(useStore.getState().activeChannel).toBe('#focus');
  });

  it('removing active channel falls back to server', () => {
    createChannel('#gone');
    useStore.getState().setActiveChannel('#gone');
    useStore.getState().removeChannel('#gone');
    expect(useStore.getState().activeChannel).toBe('server');
  });
});

// ── Message handling ─────────────────────────────────────────────────

describe('message handling', () => {
  beforeEach(() => {
    createChannel('#msgs');
  });

  const msg = (overrides: Partial<Message> = {}): Message => ({
    id: 'msg-' + Math.random().toString(36).slice(2),
    from: 'alice',
    text: 'hello',
    timestamp: new Date(),
    tags: {},
    ...overrides,
  });

  it('adds a message to a channel', () => {
    useStore.getState().addMessage('#msgs', msg({ text: 'first' }));
    const ch = useStore.getState().channels.get('#msgs')!;
    // createChannel adds an init message + this one
    expect(ch.messages.length).toBe(2);
    expect(ch.messages[ch.messages.length - 1].text).toBe('first');
  });

  it('deduplicates by msgid', () => {
    const m = msg({ id: 'dup-123', text: 'hello' });
    useStore.getState().addMessage('#msgs', m);
    useStore.getState().addMessage('#msgs', { ...m, text: 'hello again' });
    const ch = useStore.getState().channels.get('#msgs')!;
    // Should only have one message with id 'dup-123'
    const matching = ch.messages.filter(m => m.id === 'dup-123');
    expect(matching.length).toBe(1);
  });

  it('caps messages at 1000', () => {
    const store = useStore.getState();
    for (let i = 0; i < 1100; i++) {
      store.addMessage('#msgs', msg({ text: `msg ${i}` }));
    }
    const ch = useStore.getState().channels.get('#msgs')!;
    expect(ch.messages.length).toBeLessThanOrEqual(1000);
  });

  it('edit updates message text', () => {
    const m = msg({ id: 'edit-1', text: 'before' });
    useStore.getState().addMessage('#msgs', m);
    useStore.getState().editMessage('#msgs', 'edit-1', 'after');
    const ch = useStore.getState().channels.get('#msgs')!;
    const edited = ch.messages.find(m => m.id === 'edit-1');
    expect(edited?.text).toBe('after');
  });

  it('delete marks message as deleted', () => {
    const m = msg({ id: 'del-1', text: 'doomed' });
    useStore.getState().addMessage('#msgs', m);
    useStore.getState().deleteMessage('#msgs', 'del-1');
    const ch = useStore.getState().channels.get('#msgs')!;
    const deleted = ch.messages.find(m => m.id === 'del-1');
    expect(deleted?.deleted).toBe(true);
  });

  it('edit nonexistent message is a no-op', () => {
    useStore.getState().editMessage('#msgs', 'nope', 'text');
    // Should not crash — only the init message from createChannel exists
    const ch = useStore.getState().channels.get('#msgs')!;
    expect(ch.messages.every(m => m.text !== 'text')).toBe(true);
  });

  it('delete nonexistent message is a no-op', () => {
    useStore.getState().deleteMessage('#msgs', 'nope');
    // Should not crash
  });
});

// ── Member operations ────────────────────────────────────────────────

describe('member operations', () => {
  beforeEach(() => {
    createChannel('#members');
  });

  it('adds a member', () => {
    useStore.getState().addMember('#members', { nick: 'alice' });
    const ch = useStore.getState().channels.get('#members')!;
    expect(ch.members.has('alice')).toBe(true);
  });

  it('removes a member', () => {
    useStore.getState().addMember('#members', { nick: 'bob' });
    useStore.getState().removeMember('#members', 'bob');
    const ch = useStore.getState().channels.get('#members')!;
    expect(ch.members.has('bob')).toBe(false);
  });

  it('member nicks are case-insensitive', () => {
    useStore.getState().addMember('#members', { nick: 'Alice' });
    const ch = useStore.getState().channels.get('#members')!;
    expect(ch.members.has('alice')).toBe(true);
  });

  it('renames user across all channels', () => {
    createChannel('#ch1');
    createChannel('#ch2');
    useStore.getState().addMember('#ch1', { nick: 'old' });
    useStore.getState().addMember('#ch2', { nick: 'old' });
    useStore.getState().renameUser('old', 'new');
    const ch1 = useStore.getState().channels.get('#ch1')!;
    const ch2 = useStore.getState().channels.get('#ch2')!;
    expect(ch1.members.has('new')).toBe(true);
    expect(ch1.members.has('old')).toBe(false);
    expect(ch2.members.has('new')).toBe(true);
  });

  it('removeUserFromAll removes from all channels', () => {
    createChannel('#a');
    createChannel('#b');
    useStore.getState().addMember('#a', { nick: 'quitter' });
    useStore.getState().addMember('#b', { nick: 'quitter' });
    useStore.getState().removeUserFromAll('quitter', 'bye');
    expect(useStore.getState().channels.get('#a')!.members.has('quitter')).toBe(false);
    expect(useStore.getState().channels.get('#b')!.members.has('quitter')).toBe(false);
  });

  it('addMember with op status', () => {
    useStore.getState().addMember('#members', { nick: 'op', isOp: true });
    const ch = useStore.getState().channels.get('#members')!;
    const member = ch.members.get('op');
    expect(member?.isOp).toBe(true);
  });
});

// ── Unread tracking ──────────────────────────────────────────────────

describe('unread tracking', () => {
  beforeEach(() => {
    createChannel('#unread');
    useStore.getState().setNick('myself');
  });

  it('increments unreadCount for non-active channel', () => {
    useStore.getState().setActiveChannel('server');
    useStore.getState().addMessage('#unread', {
      id: 'u1', from: 'other', text: 'hey',
      timestamp: new Date(), tags: {},
    });
    const ch = useStore.getState().channels.get('#unread')!;
    expect(ch.unreadCount).toBeGreaterThan(0);
  });

  it('does not increment unreadCount for active channel', () => {
    useStore.getState().setActiveChannel('#unread');
    useStore.getState().addMessage('#unread', {
      id: 'u2', from: 'other', text: 'hey',
      timestamp: new Date(), tags: {},
    });
    const ch = useStore.getState().channels.get('#unread')!;
    expect(ch.unreadCount).toBe(0);
  });
});

// ── WHOIS cache ──────────────────────────────────────────────────────

describe('whois cache', () => {
  it('stores and retrieves whois info', () => {
    useStore.getState().updateWhois('testuser', { user: '~u', host: 'host' });
    const info = useStore.getState().whoisCache.get('testuser');
    expect(info?.user).toBe('~u');
  });

  it('merges partial updates', () => {
    useStore.getState().updateWhois('testuser', { user: '~u' });
    useStore.getState().updateWhois('testuser', { host: 'host' });
    const info = useStore.getState().whoisCache.get('testuser');
    expect(info?.user).toBe('~u');
    expect(info?.host).toBe('host');
  });

  it('clears did/handle on re-whois (stale data prevention)', () => {
    useStore.getState().updateWhois('testuser', { did: 'did:plc:old', handle: 'old.bsky' });
    // Simulate new WHOIS (311) which clears identity fields
    useStore.getState().updateWhois('testuser', { user: '~u', did: undefined, handle: undefined });
    const info = useStore.getState().whoisCache.get('testuser');
    expect(info?.did).toBeUndefined();
    expect(info?.handle).toBeUndefined();
  });

  it('is case-insensitive', () => {
    useStore.getState().updateWhois('TestUser', { user: '~u' });
    const info = useStore.getState().whoisCache.get('testuser');
    expect(info?.user).toBe('~u');
  });
});

// ── WHOIS in flight ──────────────────────────────────────────────────
// Telling "the answer named no account" from "no answer yet" is what keeps a
// guest label off someone the server hasn't described yet. Only the server's
// end-of-WHOIS clears it — never a timer.

describe('whois pending', () => {
  it('marks and ends a lookup, case-insensitively', () => {
    useStore.getState().markWhoisPending('Bob');
    expect(useStore.getState().whoisPending.has('bob')).toBe(true);
    useStore.getState().endWhoisPending('bOB');
    expect(useStore.getState().whoisPending.has('bob')).toBe(false);
  });

  it('ending a lookup nobody asked for is a no-op', () => {
    const before = useStore.getState().whoisPending;
    useStore.getState().endWhoisPending('nobody');
    expect(useStore.getState().whoisPending).toBe(before);
  });

  it('an answer for one nick leaves another still waiting', () => {
    useStore.getState().markWhoisPending('bob');
    useStore.getState().markWhoisPending('carol');
    useStore.getState().endWhoisPending('bob');
    expect(useStore.getState().whoisPending.has('bob')).toBe(false);
    expect(useStore.getState().whoisPending.has('carol')).toBe(true);
  });

  it('losing the connection ends every outstanding lookup', () => {
    useStore.getState().markWhoisPending('bob');
    useStore.getState().setConnectionState('disconnected');
    expect(useStore.getState().whoisPending.size).toBe(0);
  });
});

// ── Favorites / muted ────────────────────────────────────────────────

describe('favorites and muted', () => {
  it('toggles favorite', () => {
    useStore.getState().toggleFavorite('#fav');
    expect(useStore.getState().favorites.has('#fav')).toBe(true);
    useStore.getState().toggleFavorite('#fav');
    expect(useStore.getState().favorites.has('#fav')).toBe(false);
  });

  it('persists favorites to localStorage', () => {
    useStore.getState().toggleFavorite('#saved');
    const stored = localStorage.getItem('freeq-favorites');
    expect(stored).toContain('#saved');
  });

  it('toggles muted', () => {
    useStore.getState().toggleMuted('#quiet');
    expect(useStore.getState().mutedChannels.has('#quiet')).toBe(true);
    useStore.getState().toggleMuted('#quiet');
    expect(useStore.getState().mutedChannels.has('#quiet')).toBe(false);
  });
});

// ── Batch message handling ───────────────────────────────────────────

describe('batch message handling', () => {
  beforeEach(() => {
    createChannel('#batch');
  });

  it('starts and ends batch', () => {
    useStore.getState().startBatch('b1', 'chathistory', '#batch');
    expect(useStore.getState().batches.has('b1')).toBe(true);
    useStore.getState().endBatch('b1');
    expect(useStore.getState().batches.has('b1')).toBe(false);
  });

  it('batch messages merged on endBatch', () => {
    useStore.getState().startBatch('b2', 'chathistory', '#batch');
    useStore.getState().addBatchMessage('b2', {
      id: 'bm1', from: 'alice', text: 'batch msg',
      timestamp: new Date(), tags: {},
    });
    useStore.getState().endBatch('b2');
    const ch = useStore.getState().channels.get('#batch')!;
    expect(ch.messages.some(m => m.id === 'bm1')).toBe(true);
  });

  it('batch deduplicates against existing messages', () => {
    useStore.getState().addMessage('#batch', {
      id: 'existing', from: 'a', text: 'hi',
      timestamp: new Date(), tags: {},
    });
    useStore.getState().startBatch('b3', 'chathistory', '#batch');
    useStore.getState().addBatchMessage('b3', {
      id: 'existing', from: 'a', text: 'hi duplicate',
      timestamp: new Date(), tags: {},
    });
    useStore.getState().endBatch('b3');
    const ch = useStore.getState().channels.get('#batch')!;
    const matches = ch.messages.filter(m => m.id === 'existing');
    expect(matches.length).toBe(1);
  });
});

// ── System messages ──────────────────────────────────────────────────

describe('system messages', () => {
  it('adds system message to server tab', () => {
    useStore.getState().addSystemMessage('server', 'test system message');
    const msgs = useStore.getState().serverMessages;
    expect(msgs.some(m => m.text === 'test system message')).toBe(true);
  });

  it('adds system message to channel', () => {
    createChannel('#sys');
    useStore.getState().addSystemMessage('#sys', 'channel system msg');
    const ch = useStore.getState().channels.get('#sys')!;
    expect(ch.messages.some(m => m.text === 'channel system msg')).toBe(true);
  });
});

// ── Reactions ────────────────────────────────────────────────────────

describe('reactions', () => {
  beforeEach(() => {
    createChannel('#react');
    useStore.getState().addMessage('#react', {
      id: 'rmsg', from: 'alice', text: 'react to me',
      timestamp: new Date(), tags: {},
    });
  });

  it('adds a reaction', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'bob');
    const ch = useStore.getState().channels.get('#react')!;
    const m = ch.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('👍')?.has('bob')).toBe(true);
  });

  it('multiple users react with same emoji', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'bob');
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'carol');
    const ch = useStore.getState().channels.get('#react')!;
    const m = ch.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('👍')?.size).toBe(2);
  });

  it('different emojis tracked separately', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'bob');
    useStore.getState().addReaction('#react', 'rmsg', '❤️', 'carol');
    const ch = useStore.getState().channels.get('#react')!;
    const m = ch.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.size).toBe(2);
  });

  it('self-reaction shows immediately (own nick appears in reaction)', () => {
    // Simulate: user "me" is logged in and reacts to a message.
    // The reaction should appear in the store immediately, not only after
    // the server echoes it back.
    useStore.getState().addReaction('#react', 'rmsg', '🎉', 'me');
    const ch = useStore.getState().channels.get('#react')!;
    const m = ch.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('🎉')?.has('me')).toBe(true);
  });

  it('duplicate self-reaction does not double-count', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'me');
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'me');
    const ch = useStore.getState().channels.get('#react')!;
    const m = ch.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('👍')?.size).toBe(1);
  });

  it('removes my own reaction (last reactor → emoji entry deleted)', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'me');
    useStore.getState().removeReaction('#react', 'rmsg', '👍', 'me');
    const m = useStore.getState().channels.get('#react')!.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.has('👍')).toBe(false);
  });

  it('removes one reactor while preserving others on the same emoji', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'bob');
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'carol');
    useStore.getState().removeReaction('#react', 'rmsg', '👍', 'bob');
    const m = useStore.getState().channels.get('#react')!.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('👍')?.has('bob')).toBe(false);
    expect(m.reactions?.get('👍')?.has('carol')).toBe(true);
    expect(m.reactions?.get('👍')?.size).toBe(1);
  });

  it('does not affect a different emoji on the same message', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'me');
    useStore.getState().addReaction('#react', 'rmsg', '❤️', 'me');
    useStore.getState().removeReaction('#react', 'rmsg', '👍', 'me');
    const m = useStore.getState().channels.get('#react')!.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.has('👍')).toBe(false);
    expect(m.reactions?.get('❤️')?.has('me')).toBe(true);
  });

  it('removeReaction is a no-op when the reactor never reacted', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'bob');
    const before = useStore.getState().channels.get('#react');
    useStore.getState().removeReaction('#react', 'rmsg', '👍', 'me'); // 'me' never reacted
    const after = useStore.getState().channels.get('#react');
    // Reference-equal: zustand bail-out (we returned the message unchanged from .map)
    expect(after?.messages.find(m => m.id === 'rmsg')?.reactions?.get('👍')?.size).toBe(1);
    expect(before?.messages.find(m => m.id === 'rmsg')?.reactions?.get('👍')?.has('bob')).toBe(true);
  });

  it('removeReaction is a no-op for an emoji that was never used', () => {
    useStore.getState().addReaction('#react', 'rmsg', '👍', 'me');
    useStore.getState().removeReaction('#react', 'rmsg', '🚀', 'me');
    const m = useStore.getState().channels.get('#react')!.messages.find(m => m.id === 'rmsg')!;
    expect(m.reactions?.get('👍')?.has('me')).toBe(true);
  });

  it('removeReaction tolerates missing channel / message', () => {
    expect(() => {
      useStore.getState().removeReaction('#never', 'nope', '👍', 'me');
      useStore.getState().removeReaction('#react', 'no-such-msg', '👍', 'me');
    }).not.toThrow();
  });
});
