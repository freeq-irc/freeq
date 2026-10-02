/**
 * Instant-room share links (see docs/INSTANT-ROOMS.md, "Web").
 *
 * A room link is `https://host/r/<name>#<token>`; the server's landing page
 * forwards a browser to `/?room=<name>#<token>` with the fragment intact. The
 * token rides the URL fragment so it never reaches a server log, and it is
 * the only thing that admits a newcomer, so it must survive the OAuth
 * round-trip: it is parked in sessionStorage (per tab, gone when the tab
 * closes) and the URL is scrubbed back to `/` right away.
 */

export interface PendingRoom {
  /** `#r-word-word-word` — the channel, lowercased, with its `#`. */
  channel: string;
  /** The invite token from the fragment, or null when the link had none. */
  token: string | null;
}

export const PENDING_ROOM_KEY = 'freeq-pending-room';

/** Minimal storage surface so tests can hand in a plain object. */
export type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/** Is this channel an instant room by name? Rooms are minted as `#r-…`. */
export function isRoomChannel(name: string): boolean {
  return /^#r-/i.test(name);
}

/**
 * Recognise `/r/<name>#<token>` and `/?room=<name>#<token>`. Anything else
 * is null. The name is validated against the room name alphabet so a
 * hostile link cannot smuggle a channel with spaces or commas into a JOIN.
 */
export function parseRoomLocation(loc: { pathname: string; search: string; hash: string }): PendingRoom | null {
  let name: string | null = null;
  const m = loc.pathname.match(/^\/r\/([^/]+)\/?$/);
  if (m) {
    try { name = decodeURIComponent(m[1]); } catch { return null; }
  } else {
    const params = new URLSearchParams(loc.search);
    if (params.has('room')) name = params.get('room');
  }
  if (!name) return null;
  name = name.replace(/^#/, '');
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return null;
  const frag = loc.hash.replace(/^#/, '');
  return {
    channel: `#${name.toLowerCase()}`,
    token: frag.length > 0 ? frag : null,
  };
}

/** Build a share URL. The token rides the fragment so it never reaches a server log. */
export function roomInviteUrl(origin: string, channel: string, token: string): string {
  const name = channel.replace(/^#/, '');
  return `${origin.replace(/\/+$/, '')}/r/${encodeURIComponent(name)}#${token}`;
}

function defaultStorage(): StorageLike | null {
  try {
    if (typeof sessionStorage !== 'undefined' && typeof sessionStorage.getItem === 'function') return sessionStorage;
  } catch { /* access can throw in locked-down embeds */ }
  return null;
}

export function loadPendingRoom(storage: StorageLike | null = defaultStorage()): PendingRoom | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(PENDING_ROOM_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<PendingRoom>;
    if (typeof parsed.channel !== 'string' || !parsed.channel.startsWith('#')) return null;
    return { channel: parsed.channel.toLowerCase(), token: typeof parsed.token === 'string' ? parsed.token : null };
  } catch {
    return null;
  }
}

export function savePendingRoom(room: PendingRoom, storage: StorageLike | null = defaultStorage()): void {
  if (!storage) return;
  try { storage.setItem(PENDING_ROOM_KEY, JSON.stringify(room)); } catch { /* quota / private mode */ }
}

export function clearPendingRoom(storage: StorageLike | null = defaultStorage()): void {
  if (!storage) return;
  try { storage.removeItem(PENDING_ROOM_KEY); } catch { /* ignore */ }
}

/**
 * On page load: if the URL is a room link, park it as the pending room and
 * scrub the URL to `/` (replaceState — no reload, nothing in history holding
 * the token). Returns what was parked, or the room already pending from an
 * earlier load in this tab (the OAuth redirect lands back on `/`).
 */
export function consumeRoomLink(
  win: { location: { pathname: string; search: string; hash: string }; history: { replaceState: (a: unknown, b: string, c: string) => void } } | null =
    typeof window !== 'undefined' ? window : null,
  storage: StorageLike | null = defaultStorage(),
): PendingRoom | null {
  if (!win) return loadPendingRoom(storage);
  const room = parseRoomLocation(win.location);
  if (!room) return loadPendingRoom(storage);
  savePendingRoom(room, storage);
  try { win.history.replaceState(null, '', '/'); } catch { /* ignore */ }
  return room;
}
