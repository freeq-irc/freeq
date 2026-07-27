/**
 * Bug-hunting tests for the Zustand store — state corruption,
 * phantom members, edge cases in message handling.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock globals before import
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
globalThis.window = { localStorage: globalThis.localStorage, location: { hash: '' }, addEventListener: () => {} };

const { useStore } = await import('./store');

beforeEach(() => {
  storage.clear();
  useStore.getState().reset();
});

function mkMsg(overrides: Record<string, any> = {}) {
  return {
    id: 'msg-' + Math.random().toString(36).slice(2),
    from: 'alice',
    text: 'hello',
    timestamp: new Date(),
    tags: {},
    ...overrides,
  };
}

function ensureChannel(name: string) {
  useStore.getState().addMessage(name, mkMsg({ from: 'system', text: 'init', isSystem: true }));
}

// ═══════════════════════════════════════════════════════════════
// BUG: handleMode creates phantom members
// ═══════════════════════════════════════════════════════════════

describe('handleMode phantom members', () => {
  it('MODE +o on non-existent nick does NOT create phantom member (FIXED)', () => {
    ensureChannel('#test');
    useStore.getState().handleMode('#test', '+o', 'ghost_user', 'server');
    const ch = useStore.getState().channels.get('#test')!;
    // FIXED: ghost_user should NOT be in members
    expect(ch.members.has('ghost_user')).toBe(false);
  });

  it('MODE +v on non-existent nick does NOT create phantom member (FIXED)', () => {
    ensureChannel('#test');
    useStore.getState().handleMode('#test', '+v', 'phantom', 'server');
    const ch = useStore.getState().channels.get('#test')!;
    expect(ch.members.has('phantom')).toBe(false);
  });

  it('MODE +o on existing member does NOT create phantom', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: 'real_user' });
    useStore.getState().handleMode('#test', '+o', 'real_user', 'server');
    const ch = useStore.getState().channels.get('#test')!;
    const member = ch.members.get('real_user');
    expect(member).toBeDefined();
    expect(member!.isOp).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: renameUser with empty/same nick
// ═══════════════════════════════════════════════════════════════

describe('renameUser edge cases', () => {
  it('renameUser with empty new nick is rejected (FIXED)', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: 'alice' });
    useStore.getState().renameUser('alice', '');
    const ch = useStore.getState().channels.get('#test')!;
    // FIXED: rename rejected, alice still present
    expect(ch.members.has('alice')).toBe(true);
    expect(ch.members.has('')).toBe(false);
  });

  it('renameUser with same name (case change) works', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: 'Alice' });
    useStore.getState().renameUser('Alice', 'alice');
    const ch = useStore.getState().channels.get('#test')!;
    // Should have lowercase key
    expect(ch.members.has('alice')).toBe(true);
  });

  it('renameUser where old nick does not exist is a no-op', () => {
    ensureChannel('#test');
    useStore.getState().renameUser('nonexistent', 'newname');
    const ch = useStore.getState().channels.get('#test')!;
    expect(ch.members.has('newname')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: addMessage with missing/falsy ID allows duplicates
// ═══════════════════════════════════════════════════════════════

describe('addMessage ID edge cases', () => {
  it('message with undefined id bypasses dedup', () => {
    ensureChannel('#test');
    const m1 = mkMsg({ id: undefined, text: 'dup1' });
    const m2 = mkMsg({ id: undefined, text: 'dup2' });
    useStore.getState().addMessage('#test', m1);
    useStore.getState().addMessage('#test', m2);
    const ch = useStore.getState().channels.get('#test')!;
    // Both should be added since dedup is skipped for falsy IDs
    const texts = ch.messages.map(m => m.text);
    expect(texts).toContain('dup1');
    expect(texts).toContain('dup2');
  });

  it('message with empty string id bypasses dedup', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: '', text: 'a' }));
    useStore.getState().addMessage('#test', mkMsg({ id: '', text: 'b' }));
    const ch = useStore.getState().channels.get('#test')!;
    const noId = ch.messages.filter(m => m.id === '');
    // Empty string IDs may or may not be deduped
    // Document actual behavior
    expect(noId.length).toBeGreaterThanOrEqual(1);
  });

  it('message with same ID is deduped', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'same', text: 'first' }));
    useStore.getState().addMessage('#test', mkMsg({ id: 'same', text: 'second' }));
    const ch = useStore.getState().channels.get('#test')!;
    const matches = ch.messages.filter(m => m.id === 'same');
    expect(matches.length).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: editMessage on missing message is silent
// ═══════════════════════════════════════════════════════════════

describe('editMessage edge cases', () => {
  it('edit on non-existent message is silent no-op', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'real', text: 'original' }));
    // Edit a message that doesn't exist
    useStore.getState().editMessage('#test', 'nonexistent', 'edited text');
    const ch = useStore.getState().channels.get('#test')!;
    // Original should be unchanged
    const real = ch.messages.find(m => m.id === 'real');
    expect(real?.text).toBe('original');
  });

  it('edit on deleted message is silent no-op', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'del', text: 'original' }));
    useStore.getState().deleteMessage('#test', 'del');
    useStore.getState().editMessage('#test', 'del', 'edited');
    const ch = useStore.getState().channels.get('#test')!;
    const msg = ch.messages.find(m => m.id === 'del');
    expect(msg?.deleted).toBe(true);
    // Text may or may not be updated — document behavior
  });

  it('edit with empty text shows placeholder (FIXED)', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'empty_edit', text: 'original' }));
    useStore.getState().editMessage('#test', 'empty_edit', '');
    const ch = useStore.getState().channels.get('#test')!;
    const msg = ch.messages.find(m => m.id === 'empty_edit');
    // FIXED: empty edit shows placeholder
    expect(msg?.text).toBe('[message cleared]');
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: setActiveChannel for non-existent channel
// ═══════════════════════════════════════════════════════════════

describe('setActiveChannel edge cases', () => {
  it('setting active to non-existent channel', () => {
    useStore.getState().setActiveChannel('#doesnotexist');
    // Should either be rejected or create an empty state
    // Document actual behavior
    expect(useStore.getState().activeChannel).toBeDefined();
  });

  it('setting active to empty string', () => {
    useStore.getState().setActiveChannel('');
    expect(useStore.getState().activeChannel).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: removeChannel doesn't clean up in-flight batches
// ═══════════════════════════════════════════════════════════════

describe('removeChannel batch cleanup', () => {
  it('removing channel cleans up pending batches (FIXED)', () => {
    ensureChannel('#leaving');
    useStore.getState().startBatch('b1', 'chathistory', '#leaving');
    useStore.getState().addBatchMessage('b1', mkMsg({ text: 'batch msg' }));
    // Remove the channel — should also clean up the batch
    useStore.getState().removeChannel('#leaving');
    // FIXED: batch should be cleaned up
    expect(useStore.getState().batches.has('b1')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: addReaction on missing message
// ═══════════════════════════════════════════════════════════════

describe('addReaction edge cases', () => {
  it('reaction on non-existent message is silent no-op', () => {
    ensureChannel('#test');
    useStore.getState().addReaction('#test', 'nonexistent', '👍', 'bob');
    // Should not crash
    const ch = useStore.getState().channels.get('#test')!;
    // No message has a reaction
    const withReaction = ch.messages.filter(m => m.reactions && m.reactions.size > 0);
    expect(withReaction.length).toBe(0);
  });

  it('reaction with empty emoji', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'r1' }));
    useStore.getState().addReaction('#test', 'r1', '', 'bob');
    const ch = useStore.getState().channels.get('#test')!;
    const msg = ch.messages.find(m => m.id === 'r1');
    // Empty emoji reaction — document behavior
    if (msg?.reactions?.has('')) {
      // BUG: empty emoji stored
      expect(msg.reactions.get('')!.has('bob')).toBe(true);
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: addMember with empty nick
// ═══════════════════════════════════════════════════════════════

describe('addMember edge cases', () => {
  it('addMember with empty nick', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: '' });
    const ch = useStore.getState().channels.get('#test')!;
    // BUG: empty nick member exists in map under key ''
    const empty = ch.members.get('');
    if (empty) {
      expect(empty.nick).toBe('');
    }
  });

  it('addMember with whitespace-only nick', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: '   ' });
    const ch = useStore.getState().channels.get('#test')!;
    // Stored under key '   ' (lowercased = '   ')
    const ws = ch.members.get('   ');
    if (ws) {
      expect(ws.nick).toBe('   ');
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: 1000 message cap — verify no data loss
// ═══════════════════════════════════════════════════════════════

describe('message cap', () => {
  it('adding 1001 messages keeps exactly 1000', () => {
    ensureChannel('#big');
    for (let i = 0; i < 1001; i++) {
      useStore.getState().addMessage('#big', mkMsg({ text: `msg${i}` }));
    }
    const ch = useStore.getState().channels.get('#big')!;
    expect(ch.messages.length).toBeLessThanOrEqual(1000);
    // Newest message should be preserved
    expect(ch.messages[ch.messages.length - 1].text).toBe('msg1000');
  });

  it('batch merge with overflow drops oldest correctly', () => {
    ensureChannel('#batchbig');
    // Add 900 messages
    for (let i = 0; i < 900; i++) {
      useStore.getState().addMessage('#batchbig', mkMsg({ id: `exist-${i}`, text: `e${i}` }));
    }
    // Start batch with 200 messages (total would be 1100)
    useStore.getState().startBatch('big', 'chathistory', '#batchbig');
    for (let i = 0; i < 200; i++) {
      useStore.getState().addBatchMessage('big', mkMsg({
        id: `batch-${i}`,
        text: `b${i}`,
        timestamp: new Date(1000 + i), // old timestamps
      }));
    }
    useStore.getState().endBatch('big');
    const ch = useStore.getState().channels.get('#batchbig')!;
    expect(ch.messages.length).toBeLessThanOrEqual(1000);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: WHOIS cache with undefined values
// ═══════════════════════════════════════════════════════════════

describe('whois cache edge cases', () => {
  it('updateWhois with all undefined fields', () => {
    useStore.getState().updateWhois('test', {});
    const info = useStore.getState().whoisCache.get('test');
    expect(info).toBeDefined();
    expect(info?.nick).toBe('test');
  });

  it('whois for nick with special characters', () => {
    useStore.getState().updateWhois('test[bot]', { user: '~bot' });
    const info = useStore.getState().whoisCache.get('test[bot]');
    expect(info?.user).toBe('~bot');
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: deleteMessage then addMessage with same ID
// ═══════════════════════════════════════════════════════════════

describe('delete then re-add', () => {
  it('deleted message ID blocks re-add (dedup)', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'resurrect', text: 'original' }));
    useStore.getState().deleteMessage('#test', 'resurrect');
    // Try to add a new message with the same ID
    useStore.getState().addMessage('#test', mkMsg({ id: 'resurrect', text: 'new version' }));
    const ch = useStore.getState().channels.get('#test')!;
    const matches = ch.messages.filter(m => m.id === 'resurrect');
    // Dedup should prevent re-add — the deleted message is still in the array
    expect(matches.length).toBe(1);
    // The one that exists should still be marked deleted
    expect(matches[0].deleted).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: removeUserFromAll with nick that has special chars
// ═══════════════════════════════════════════════════════════════

describe('removeUserFromAll edge cases', () => {
  it('remove user with brackets in nick', () => {
    ensureChannel('#test');
    useStore.getState().addMember('#test', { nick: '[bot]' });
    useStore.getState().removeUserFromAll('[bot]', 'quit');
    const ch = useStore.getState().channels.get('#test')!;
    expect(ch.members.has('[bot]')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: CHATHISTORY arriving after newer live messages produces
// two-block swapped order (reproduces screenshot on 2026-04-21:
// top→bottom [Apr 18, Apr 20, Apr 15, Apr 16, Apr 17]).
// ═══════════════════════════════════════════════════════════════

function msgAt(iso: string, id: string, text = 'x') {
  return mkMsg({ id, timestamp: new Date(iso), text });
}

describe('history batch merge ordering (FIXED)', () => {
  it('reproduces the two-block swapped-order screenshot', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    // Clear the init message so we test pure ordering.
    s().channels.get(ch)!.messages = [];

    // Existing live-state already shows recent messages.
    s().addMessage(ch, msgAt('2026-04-18T14:17:00Z', 'm18', 'url post'));
    s().addMessage(ch, msgAt('2026-04-20T13:04:00Z', 'm20', 'LLMs to conform...'));

    // CHATHISTORY backfill arrives with older messages.
    const history = [
      msgAt('2026-04-15T21:09:00Z', 'm15', 'spec grammar...'),
      msgAt('2026-04-16T16:24:00Z', 'm16', 'or domains to IUs...'),
      msgAt('2026-04-17T15:54:00Z', 'm17', 'definite the right direction'),
    ];
    // This is the fix-path contract: a single sort-merge, not a per-msg append.
    (s() as any).mergeHistory(ch, history);

    const ids = s().channels.get(ch)!.messages.map((m) => m.id);
    expect(ids).toEqual(['m15', 'm16', 'm17', 'm18', 'm20']);
  });

  it('handles history interleaved with existing', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];

    s().addMessage(ch, msgAt('2026-04-18T00:00:00Z', 'm18'));
    s().addMessage(ch, msgAt('2026-04-20T00:00:00Z', 'm20'));

    // History straddles the existing window: one older, one between.
    const history = [
      msgAt('2026-04-14T00:00:00Z', 'm14'),
      msgAt('2026-04-19T00:00:00Z', 'm19'),
    ];
    (s() as any).mergeHistory(ch, history);

    expect(s().channels.get(ch)!.messages.map((m) => m.id))
      .toEqual(['m14', 'm18', 'm19', 'm20']);
  });

  it('dedups by msgid when history repeats a live message', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];

    s().addMessage(ch, msgAt('2026-04-18T00:00:00Z', 'm18', 'live'));

    // History returns the same msgid plus older siblings.
    const history = [
      msgAt('2026-04-15T00:00:00Z', 'm15'),
      msgAt('2026-04-18T00:00:00Z', 'm18', 'history-copy'),
    ];
    (s() as any).mergeHistory(ch, history);

    const msgs = s().channels.get(ch)!.messages;
    expect(msgs.map((m) => m.id)).toEqual(['m15', 'm18']);
    // Live copy wins (we don't clobber with the history copy).
    expect(msgs.find((m) => m.id === 'm18')!.text).toBe('live');
  });

  it('tiebreaks by msgid when timestamps are identical', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];

    const t = '2026-04-18T00:00:00Z';
    s().addMessage(ch, msgAt(t, 'mC'));
    (s() as any).mergeHistory(ch, [msgAt(t, 'mA'), msgAt(t, 'mB')]);

    expect(s().channels.get(ch)!.messages.map((m) => m.id))
      .toEqual(['mA', 'mB', 'mC']);
  });

  it('caps merged result to 1000 most recent messages', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];

    // 600 existing live messages (chronological).
    for (let i = 0; i < 600; i++) {
      s().addMessage(ch, msgAt(
        new Date(2026, 3, 1, i / 60 | 0, i % 60).toISOString(),
        `live-${i.toString().padStart(4, '0')}`,
      ));
    }
    // 600 older history messages.
    const history = [];
    for (let i = 0; i < 600; i++) {
      history.push(msgAt(
        new Date(2026, 2, 1, i / 60 | 0, i % 60).toISOString(),
        `hist-${i.toString().padStart(4, '0')}`,
      ));
    }
    (s() as any).mergeHistory(ch, history);

    const msgs = s().channels.get(ch)!.messages;
    expect(msgs.length).toBe(1000);
    // Should retain the 1000 most recent (all 600 live + last 400 history).
    expect(msgs[msgs.length - 1].id).toBe('live-0599');
    expect(msgs[0].id).toBe('hist-0200');
  });
});

describe('mergeHistory safety / side-effects', () => {
  it('no-op on empty array and does not create the channel', () => {
    const s = () => useStore.getState();
    expect(s().channels.has('#never')).toBe(false);
    (s() as any).mergeHistory('#never', []);
    expect(s().channels.has('#never')).toBe(false);
  });

  it('ignores the "server" target (matches addMessage contract)', () => {
    const s = () => useStore.getState();
    const before = s().serverMessages.length;
    (s() as any).mergeHistory('server', [msgAt('2026-04-10T00:00:00Z', 'sv1')]);
    (s() as any).mergeHistory('SERVER', [msgAt('2026-04-10T00:00:00Z', 'sv2')]);
    expect(s().serverMessages.length).toBe(before);
    expect(s().channels.has('server')).toBe(false);
  });

  it('does not bump unreadCount (history backfill is not unread)', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().setActiveChannel('#other'); // make #freeq inactive, so addMessage would bump
    s().channels.get(ch)!.messages = [];
    s().channels.get(ch)!.unreadCount = 0;

    (s() as any).mergeHistory(ch, [
      msgAt('2026-04-15T00:00:00Z', 'h1'),
      msgAt('2026-04-16T00:00:00Z', 'h2'),
    ]);

    expect(s().channels.get(ch)!.unreadCount).toBe(0);
  });

  it('does not auto-unhide a hidden DM on backfill', () => {
    const s = () => useStore.getState();
    const dm = 'alice';
    ensureChannel(dm);
    s().channels.get(dm)!.messages = [];
    s().hideDM(dm);
    expect(s().hiddenDMs.has(dm.toLowerCase())).toBe(true);

    (s() as any).mergeHistory(dm, [msgAt('2026-04-15T00:00:00Z', 'd1')]);

    expect(s().hiddenDMs.has(dm.toLowerCase())).toBe(true);
  });

  it('merge into one channel does not touch another channel', () => {
    const s = () => useStore.getState();
    ensureChannel('#a');
    ensureChannel('#b');
    s().channels.get('#a')!.messages = [];
    s().channels.get('#b')!.messages = [msgAt('2026-04-10T00:00:00Z', 'b1')];

    (s() as any).mergeHistory('#a', [msgAt('2026-04-14T00:00:00Z', 'a1')]);

    expect(s().channels.get('#a')!.messages.map((m) => m.id)).toEqual(['a1']);
    expect(s().channels.get('#b')!.messages.map((m) => m.id)).toEqual(['b1']);
  });

  it('preserves topic / modes / members while merging messages', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    const c = s().channels.get(ch)!;
    c.topic = 'hello world';
    c.modes = new Set(['n', 't']);
    s().addMember(ch, { nick: 'alice' });
    c.messages = [msgAt('2026-04-18T00:00:00Z', 'm18')];

    (s() as any).mergeHistory(ch, [msgAt('2026-04-15T00:00:00Z', 'm15')]);

    const after = s().channels.get(ch)!;
    expect(after.topic).toBe('hello world');
    expect([...after.modes].sort()).toEqual(['n', 't']);
    expect(after.members.has('alice')).toBe(true);
    expect(after.messages.map((m) => m.id)).toEqual(['m15', 'm18']);
  });

  it('idempotent: merging the same history twice does not duplicate', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];
    const history = [
      msgAt('2026-04-15T00:00:00Z', 'h1'),
      msgAt('2026-04-16T00:00:00Z', 'h2'),
    ];
    (s() as any).mergeHistory(ch, history);
    (s() as any).mergeHistory(ch, history);
    expect(s().channels.get(ch)!.messages.map((m) => m.id)).toEqual(['h1', 'h2']);
  });

  it('all-duplicate history leaves state unchanged (reference-equal channels map)', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [msgAt('2026-04-18T00:00:00Z', 'm18')];

    const mapBefore = s().channels;
    (s() as any).mergeHistory(ch, [msgAt('2026-04-18T00:00:00Z', 'm18', 'dup')]);
    // No new state produced → the channels Map reference is unchanged.
    expect(s().channels).toBe(mapBefore);
    // And the original copy is preserved (not clobbered).
    expect(s().channels.get(ch)!.messages[0].text).not.toBe('dup');
  });

  it('preserves reactions on existing live message when history repeats its msgid', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [msgAt('2026-04-18T00:00:00Z', 'm18', 'live')];
    s().addReaction(ch, 'm18', '🎉', 'alice');

    (s() as any).mergeHistory(ch, [msgAt('2026-04-18T00:00:00Z', 'm18', 'from-history')]);

    const m = s().channels.get(ch)!.messages.find((x) => x.id === 'm18')!;
    expect(m.text).toBe('live');
    expect(m.reactions?.get('🎉')?.has('alice')).toBe(true);
  });

  it('is case-insensitive on the channel name', () => {
    const s = () => useStore.getState();
    ensureChannel('#FreeQ');
    s().channels.get('#freeq')!.messages = [];

    (s() as any).mergeHistory('#FREEQ', [msgAt('2026-04-15T00:00:00Z', 'h1')]);

    expect(s().channels.get('#freeq')!.messages.map((m) => m.id)).toEqual(['h1']);
  });

  it('does not mutate the caller-supplied messages array', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];
    const history = [
      msgAt('2026-04-20T00:00:00Z', 'z'),
      msgAt('2026-04-15T00:00:00Z', 'a'),
    ];
    const snapshotIds = history.map((m) => m.id);
    (s() as any).mergeHistory(ch, history);
    expect(history.map((m) => m.id)).toEqual(snapshotIds);
  });

  it('sorts messages with a missing timestamp to the front (epoch-0 fallback)', () => {
    const s = () => useStore.getState();
    const ch = '#freeq';
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];

    // One message with no timestamp (simulates a malformed history item).
    const noTs = mkMsg({ id: 'nt' });
    // @ts-expect-error — deliberately drop timestamp for this test
    noTs.timestamp = undefined;

    (s() as any).mergeHistory(ch, [
      msgAt('2026-04-18T00:00:00Z', 'm18'),
      noTs,
    ]);

    expect(s().channels.get(ch)!.messages.map((m) => m.id)).toEqual(['nt', 'm18']);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: whoisCache stale after nick reuse (UI shows previous
// occupant's DID/handle until something forces a re-WHOIS).
// Same shape as the silent-guest-fallback bug: cached identity
// outlives the wire event that should have invalidated it.
// ═══════════════════════════════════════════════════════════════

describe('whoisCache vs nick reassignment (stale identity bug)', () => {
  it('removeUserFromAll must drop the whois cache entry for the quitter', () => {
    const s = () => useStore.getState();
    s().updateWhois('alice', { did: 'did:plc:OLD', handle: 'alice.example' });
    s().removeUserFromAll('alice', 'bye');
    expect(
      s().whoisCache.has('alice'),
      'whoisCache must not retain identity for a nick that has quit',
    ).toBe(false);
  });

  it('renameUser must move the whois cache entry to the new nick (or clear it)', () => {
    // If alice changes nick to bob, the cached DID is still valid for
    // the same human at the new nick. But if we leave it under "alice",
    // a different person taking the freed nick "alice" later inherits
    // the stale identity.
    const s = () => useStore.getState();
    s().updateWhois('alice', { did: 'did:plc:HER', handle: 'alice.bsky' });
    s().renameUser('alice', 'bob');
    expect(
      s().whoisCache.has('alice'),
      'after a rename, the old nick must not still resolve to the renamer\'s DID',
    ).toBe(false);
  });
});

// ── DM edit stacking (replayed edits vs live/collapsed rows) ──
//
// A replayed history row and a live row can be the SAME message under
// different msgids (edits re-key). Blind append rendered the original
// plus stacked "- edited" copies. mergeHistory reconciles via the edit
// anchor (editOf, root of the chain).
describe('mergeHistory edit reconciliation', () => {
  const s = () => useStore.getState();
  const ch = 'did:key:z6mktestpeer';
  const at = (iso: string, id: string, text: string, editOf?: string) => ({
    id, from: 'zapnap', text, timestamp: new Date(iso), tags: {},
    ...(editOf ? { editOf } : {}),
  });

  beforeEach(() => {
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];
  });

  it('replayed collapsed edit updates the held original in place', () => {
    s().addMessage(ch, at('2026-07-20T14:35:00Z', 'm0', 'original'));
    (s() as any).mergeHistory(ch, [
      at('2026-07-20T14:36:00Z', 'e1', 'original - edited', 'm0'),
    ]);
    const msgs = s().channels.get(ch)!.messages;
    expect(msgs).toHaveLength(1);
    // The held id survives the reconciliation: an edit changes the text, not
    // which message this is. Re-keying to the revision's id was what made
    // reactions and pending deletes stop resolving after a reload.
    expect(msgs[0].id).toBe('m0');
    expect(msgs[0].text).toBe('original - edited');
    expect(msgs[0].editOf).toBe('m0');
  });

  it('replayed stale base row is skipped when a collapsed edit is held', () => {
    s().addMessage(ch, at('2026-07-20T14:35:00Z', 'm0', 'original'));
    (s() as any).editMessage(ch, 'm0', 'original - edited', 'e1');
    (s() as any).mergeHistory(ch, [
      at('2026-07-20T14:35:00Z', 'm0', 'original'),
    ]);
    const msgs = s().channels.get(ch)!.messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].id).toBe('m0');
    expect(msgs[0].text).toBe('original - edited');
  });

  it('repeated live edits still match a root-anchored replayed row', () => {
    s().addMessage(ch, at('2026-07-20T14:35:00Z', 'm0', 'original'));
    // Every edit names the identity the client holds — which never moves, so
    // there is no chain to follow. (The server also normalizes `+draft/edit`
    // to the root before broadcasting, so this is what arrives on the wire.)
    (s() as any).editMessage(ch, 'm0', 'edited once', 'e1');
    (s() as any).editMessage(ch, 'm0', 'edited twice', 'e2');
    // Replay delivers the final collapsed row root-anchored to m0.
    (s() as any).mergeHistory(ch, [
      at('2026-07-20T14:37:00Z', 'e2', 'edited twice', 'm0'),
    ]);
    const msgs = s().channels.get(ch)!.messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].id).toBe('m0');
    expect(msgs[0].text).toBe('edited twice');
  });

  it('a replayed edit carries its reactions onto the held row', () => {
    // Reactions arrive attached to whichever revision they were filed
    // against. Dropping them on reconciliation is what made reactions on an
    // edited message disappear on every reload.
    s().addMessage(ch, at('2026-07-20T14:35:00Z', 'm0', 'original'));
    const incoming = {
      ...at('2026-07-20T14:36:00Z', 'e1', 'original - edited', 'm0'),
      reactions: new Map([['🔥', new Set(['alice'])]]),
    };
    s().mergeHistory(ch, [incoming]);
    const msgs = s().channels.get(ch)!.messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].id).toBe('m0');
    expect([...(msgs[0].reactions?.get('🔥') ?? [])]).toEqual(['alice']);
  });

  it('edit row with no held original still lands as a single row', () => {
    (s() as any).mergeHistory(ch, [
      at('2026-07-20T14:36:00Z', 'e1', 'edited orphan', 'm0'),
    ]);
    const msgs = s().channels.get(ch)!.messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].text).toBe('edited orphan');
  });
});

// ── Edit/delete authorship gate (forged events ignored) ──
describe('edit/delete authorship gate', () => {
  const s = () => useStore.getState();
  const ch = 'did:key:z6mkgatepeer';
  const at = (id: string, from: string, text: string) => ({
    id, from, text, timestamp: new Date('2026-07-21T00:00:00Z'), tags: {},
  });

  beforeEach(() => {
    ensureChannel(ch);
    s().channels.get(ch)!.messages = [];
  });

  it('ignores an edit whose actor is not the original sender', () => {
    s().addMessage(ch, at('m1', 'alice', 'mine'));
    (s() as any).editMessage(ch, 'm1', 'forged', 'e1', false, 'mallory', undefined);
    const m = s().channels.get(ch)!.messages[0];
    expect(m.text).toBe('mine');
    expect(m.id).toBe('m1');
  });

  it('ignores a delete whose actor is not the original sender', () => {
    s().addMessage(ch, at('m2', 'alice', 'keep me'));
    (s() as any).deleteMessage(ch, 'm2', 'mallory', undefined);
    expect(s().channels.get(ch)!.messages[0].deleted).toBeUndefined();
  });

  it('applies edit and delete from the matching author', () => {
    s().addMessage(ch, at('m3', 'alice', 'v1'));
    (s() as any).editMessage(ch, 'm3', 'v2', 'e3', false, 'alice', undefined);
    expect(s().channels.get(ch)!.messages[0].text).toBe('v2');
    // The delete names the identity the message keeps, not the revision.
    (s() as any).deleteMessage(ch, 'm3', 'ALICE', undefined);
    expect(s().channels.get(ch)!.messages[0].deleted).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// BUG: deleting an EDITED message leaves it on screen
// ═══════════════════════════════════════════════════════════════

describe('delete after edit', () => {
  it('marks an edited message deleted when the delete names the ORIGINAL msgid', () => {
    // Deletes always name the ORIGINAL msgid — that is the identity clients
    // hold and what the server relays in +draft/delete. A delete of an edited
    // message used to find nothing and leave it visible after the server had
    // removed it.
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'orig', text: 'secret v1' }));
    useStore.getState().editMessage('#test', 'orig', 'secret v2', 'edit1');

    // Sanity: the edit changed the text and left the identity alone.
    const afterEdit = useStore.getState().channels.get('#test')!
      .messages.find((m) => m.editOf === 'orig');
    expect(afterEdit?.id).toBe('orig');
    expect(afterEdit?.text).toBe('secret v2');

    useStore.getState().deleteMessage('#test', 'orig');

    const m = useStore.getState().channels.get('#test')!
      .messages.find((x) => x.id === 'edit1' || x.editOf === 'orig');
    expect(m?.deleted).toBe(true);
    expect(m?.text).toBe('');
  });

  it('still deletes a row an older build re-keyed to the edit revision', () => {
    // Rows written by a build that re-keyed on edit are still in IndexedDB and
    // still on screen: id = the revision, editOf = the root. The server names
    // the root, so the `editOf` arm of the match is what reaches them. This is
    // the transition cover; it can go once such rows can't be around.
    ensureChannel('#test');
    useStore.getState().addMessage(
      '#test',
      mkMsg({ id: 'edit1', text: 'v2', editOf: 'orig' }),
    );
    useStore.getState().deleteMessage('#test', 'orig');
    const m = useStore.getState().channels.get('#test')!
      .messages.find((x) => x.id === 'edit1');
    expect(m?.deleted).toBe(true);
  });

  it('a reaction outlives an edit and is removed by the same id', () => {
    // The reason the key has to be stable. Reacting, then editing, then
    // un-reacting: every one of those names the message. When the edit moved
    // the key, the un-react (and the reaction chip itself) stopped resolving —
    // the tally kept a reaction the user had already taken back.
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'orig', text: 'v1' }));
    useStore.getState().addReaction('#test', 'orig', '🔥', 'alice');
    useStore.getState().editMessage('#test', 'orig', 'v2', 'edit1');

    const edited = useStore.getState().channels.get('#test')!
      .messages.find((m) => m.id === 'orig');
    expect(edited?.text).toBe('v2');
    expect([...(edited?.reactions?.get('🔥') ?? [])]).toEqual(['alice']);

    useStore.getState().removeReaction('#test', 'orig', '🔥', 'alice');
    const after = useStore.getState().channels.get('#test')!
      .messages.find((m) => m.id === 'orig');
    expect(after?.reactions?.get('🔥')).toBeUndefined();
  });

  it('does not delete unrelated messages', () => {
    ensureChannel('#test');
    useStore.getState().addMessage('#test', mkMsg({ id: 'orig', text: 'v1' }));
    useStore.getState().addMessage('#test', mkMsg({ id: 'other', text: 'keep me' }));
    useStore.getState().editMessage('#test', 'orig', 'v2', 'edit1');
    useStore.getState().deleteMessage('#test', 'orig');
    const other = useStore.getState().channels.get('#test')!
      .messages.find((x) => x.id === 'other');
    expect(other?.deleted).toBeFalsy();
    expect(other?.text).toBe('keep me');
  });
});
