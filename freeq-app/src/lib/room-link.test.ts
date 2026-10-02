/**
 * Room share links: what the app recognises on load, and how the pending
 * room is parked so it survives the OAuth redirect.
 */
import { describe, it, expect } from 'vitest';
import {
  parseRoomLocation,
  roomInviteUrl,
  isRoomChannel,
  loadPendingRoom,
  savePendingRoom,
  clearPendingRoom,
  consumeRoomLink,
  PENDING_ROOM_KEY,
  type StorageLike,
} from './room-link';

function memStorage(): StorageLike & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

describe('parseRoomLocation', () => {
  it('reads /r/<name>#<token>', () => {
    expect(parseRoomLocation({ pathname: '/r/r-quiet-copper-fox', search: '', hash: '#Xk3abc' }))
      .toEqual({ channel: '#r-quiet-copper-fox', token: 'Xk3abc' });
  });

  it('reads /?room=<name>#<token> (the landing page forward)', () => {
    expect(parseRoomLocation({ pathname: '/', search: '?room=r-quiet-copper-fox', hash: '#Xk3abc' }))
      .toEqual({ channel: '#r-quiet-copper-fox', token: 'Xk3abc' });
  });

  it('accepts a leading # and lowercases the name', () => {
    expect(parseRoomLocation({ pathname: '/', search: '?room=%23R-Quiet-Copper-Fox', hash: '' }))
      .toEqual({ channel: '#r-quiet-copper-fox', token: null });
  });

  it('has a null token when the fragment is empty', () => {
    expect(parseRoomLocation({ pathname: '/r/r-a-b-c', search: '', hash: '' })?.token).toBeNull();
    expect(parseRoomLocation({ pathname: '/r/r-a-b-c', search: '', hash: '#' })?.token).toBeNull();
  });

  it('is null for anything else', () => {
    expect(parseRoomLocation({ pathname: '/', search: '', hash: '' })).toBeNull();
    expect(parseRoomLocation({ pathname: '/', search: '', hash: '#auto-join=%23freeq' })).toBeNull();
    expect(parseRoomLocation({ pathname: '/rooms/x', search: '', hash: '' })).toBeNull();
    expect(parseRoomLocation({ pathname: '/r/', search: '', hash: '' })).toBeNull();
  });

  it('refuses a name outside the room alphabet (nothing smuggled into a JOIN)', () => {
    expect(parseRoomLocation({ pathname: '/', search: '?room=r-a%20b', hash: '' })).toBeNull();
    expect(parseRoomLocation({ pathname: '/', search: '?room=r-a,%23other', hash: '' })).toBeNull();
  });
});

describe('roomInviteUrl', () => {
  it('puts the token in the fragment', () => {
    expect(roomInviteUrl('https://irc.freeq.at/', '#r-a-b-c', 'tok')).toBe('https://irc.freeq.at/r/r-a-b-c#tok');
  });
});

describe('isRoomChannel', () => {
  it('recognises the #r- prefix only', () => {
    expect(isRoomChannel('#r-a-b-c')).toBe(true);
    expect(isRoomChannel('#R-A-B-C')).toBe(true);
    expect(isRoomChannel('#freeq')).toBe(false);
    expect(isRoomChannel('#rooms')).toBe(false);
  });
});

describe('pending room persistence', () => {
  it('round-trips through storage and clears', () => {
    const st = memStorage();
    expect(loadPendingRoom(st)).toBeNull();
    savePendingRoom({ channel: '#r-a-b-c', token: 'T' }, st);
    expect(loadPendingRoom(st)).toEqual({ channel: '#r-a-b-c', token: 'T' });
    clearPendingRoom(st);
    expect(loadPendingRoom(st)).toBeNull();
  });

  it('ignores garbage in storage', () => {
    const st = memStorage();
    st.setItem(PENDING_ROOM_KEY, '{not json');
    expect(loadPendingRoom(st)).toBeNull();
    st.setItem(PENDING_ROOM_KEY, JSON.stringify({ channel: 'nope', token: 'T' }));
    expect(loadPendingRoom(st)).toBeNull();
  });

  it('is a no-op without storage', () => {
    expect(loadPendingRoom(null)).toBeNull();
    savePendingRoom({ channel: '#r-a-b-c', token: 'T' }, null);
    clearPendingRoom(null);
  });
});

describe('consumeRoomLink', () => {
  function fakeWindow(pathname: string, search: string, hash: string) {
    const calls: string[] = [];
    return {
      calls,
      win: {
        location: { pathname, search, hash },
        history: { replaceState: (_a: unknown, _b: string, url: string) => { calls.push(url); } },
      },
    };
  }

  it('parks a room link and scrubs the URL to /', () => {
    const st = memStorage();
    const { win, calls } = fakeWindow('/r/r-a-b-c', '', '#T');
    expect(consumeRoomLink(win, st)).toEqual({ channel: '#r-a-b-c', token: 'T' });
    expect(loadPendingRoom(st)).toEqual({ channel: '#r-a-b-c', token: 'T' });
    expect(calls).toEqual(['/']);
  });

  it('returns the room already pending when the URL is plain (after the OAuth redirect)', () => {
    const st = memStorage();
    savePendingRoom({ channel: '#r-a-b-c', token: 'T' }, st);
    const { win, calls } = fakeWindow('/', '', '');
    expect(consumeRoomLink(win, st)).toEqual({ channel: '#r-a-b-c', token: 'T' });
    expect(calls).toEqual([]);
  });

  it('is null with nothing pending and no link', () => {
    const st = memStorage();
    const { win } = fakeWindow('/', '', '#auto-join=%23freeq');
    expect(consumeRoomLink(win, st)).toBeNull();
    expect(st.data.size).toBe(0);
  });
});
