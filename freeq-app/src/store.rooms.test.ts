/**
 * Store behaviour for instant rooms: a refused JOIN keeps its buffer (with
 * the reason) but is not a joined channel, and room state marks the channel
 * encrypted for the lock badge and the composer.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { useStore } from './store';

const s = () => useStore.getState();

beforeEach(() => {
  s().reset();
});

describe('markJoinRejected', () => {
  it('keeps the buffer the join opened, unjoined, with the reason as a system line', () => {
    s().addChannel('#r-a-b-c');
    s().setActiveChannel('#r-a-b-c');
    s().markJoinRejected('#r-a-b-c', 'Cannot join #r-a-b-c: an invite link is required.');
    const ch = s().channels.get('#r-a-b-c')!;
    expect(ch.isJoined).toBe(false);
    expect(ch.messages).toHaveLength(1);
    expect(ch.messages[0]).toMatchObject({ isSystem: true, text: 'Cannot join #r-a-b-c: an invite link is required.' });
    // The user is still looking at it, so they can read why.
    expect(s().activeChannel).toBe('#r-a-b-c');
  });

  it('creates the buffer when nothing opened one', () => {
    s().markJoinRejected('#secret', 'Cannot join #secret: you are banned (474)');
    const ch = s().channels.get('#secret')!;
    expect(ch).toBeTruthy();
    expect(ch.isJoined).toBe(false);
    expect(ch.messages[0].text).toMatch(/banned/);
  });

  it('replaces the SDK\'s generic "Cannot join" line rather than adding a second', () => {
    s().addChannel('#r-a-b-c');
    s().addSystemMessage('#r-a-b-c', 'Cannot join #r-a-b-c — invite only (+i)');
    s().markJoinRejected('#r-a-b-c', 'Cannot join #r-a-b-c: an invite link is required.');
    const ch = s().channels.get('#r-a-b-c')!;
    expect(ch.messages.map((m) => m.text)).toEqual(['Cannot join #r-a-b-c: an invite link is required.']);
  });

  it('leaves other messages alone', () => {
    s().addChannel('#x');
    s().addSystemMessage('#x', 'joined');
    s().markJoinRejected('#x', 'Cannot join #x: incorrect channel key (475)');
    expect(s().channels.get('#x')!.messages.map((m) => m.text)).toEqual(['joined', 'Cannot join #x: incorrect channel key (475)']);
  });

  it('a later successful join makes it a joined channel again', () => {
    s().markJoinRejected('#r-a-b-c', 'nope');
    s().addChannel('#r-a-b-c');
    expect(s().channels.get('#r-a-b-c')!.isJoined).toBe(true);
  });
});

describe('room state', () => {
  it('starts from defaults, merges patches and keys by lowercase channel', () => {
    s().setRoomState('#R-A-B-C', { isRoom: true });
    s().setRoomState('#r-a-b-c', { hasKey: true, heldEpoch: 2 });
    expect(s().rooms.get('#r-a-b-c')).toEqual({
      channel: '#r-a-b-c',
      isRoom: true,
      hasKey: true,
      heldEpoch: 2,
      latestEpoch: null,
      founderDid: null,
      inviteToken: null,
      expiresAt: null,
      waiting: false,
    });
  });

  it('marks a joined room channel encrypted so the badge and composer do not wait for +E', () => {
    s().addChannel('#r-a-b-c');
    expect(s().channels.get('#r-a-b-c')!.isEncrypted).toBe(false);
    s().setRoomState('#r-a-b-c', { isRoom: true });
    const ch = s().channels.get('#r-a-b-c')!;
    expect(ch.isEncrypted).toBe(true);
    expect(ch.modes.has('E')).toBe(true);
  });

  it('clears', () => {
    s().setRoomState('#r-a-b-c', { isRoom: true });
    s().clearRoomState('#r-a-b-c');
    expect(s().rooms.has('#r-a-b-c')).toBe(false);
  });

  it('is dropped by reset (a new connection)', () => {
    s().setRoomState('#r-a-b-c', { isRoom: true, inviteToken: 'T' });
    s().reset();
    expect(s().rooms.size).toBe(0);
  });
});
