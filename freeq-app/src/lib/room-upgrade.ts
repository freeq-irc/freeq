/**
 * Upgrading a room guest to a signed-in identity.
 *
 * Someone who opened a room link without an account joined as a browser
 * `did:key` (lib/guest-identity.ts). When they later sign in, they rejoin the
 * same room as their account. Two things make that seamless and honest:
 *
 *  - the room key they already held as the guest is carried over to the new
 *    identity's slot, so the room reads at once instead of waiting for a
 *    member to seal the key again;
 *  - they post one link message, sent (and MSGSIG-signed) by the account and
 *    carrying a signature by the guest key over
 *    `room, guest DID, account DID`. Anyone can check that the guest key — a
 *    did:key, so no server's word is needed — vouched for that account, in
 *    that room. That makes everything the guest said attributable to the
 *    account after the fact, without rewriting history.
 *
 * The upgrade record bridges the sign-in redirect (localStorage: the OAuth
 * round trip leaves the page).
 */

import { decodeMultibaseEd25519, verifyEd25519 } from '@freeq/sdk';
import type { StorageLike } from './room-link';

export interface RoomUpgrade {
  guestDid: string;
  guestNick: string;
  /** `#r-…`, lowercased. */
  channel: string;
  /** The invite token, so the account can be admitted to the room. */
  token: string | null;
}

export const ROOM_UPGRADE_KEY = 'freeq-room-upgrade';
/** The sign-in round trip should take minutes, not an afternoon. */
export const ROOM_UPGRADE_TTL_MS = 30 * 60 * 1000;

function defaultStorage(): StorageLike | null {
  try {
    if (typeof localStorage !== 'undefined' && typeof localStorage.getItem === 'function') return localStorage;
  } catch { /* locked-down embeds */ }
  return null;
}

export function saveRoomUpgrade(up: RoomUpgrade, storage: StorageLike | null = defaultStorage(), now = Date.now()): void {
  if (!storage) return;
  try { storage.setItem(ROOM_UPGRADE_KEY, JSON.stringify({ ...up, at: now })); } catch { /* quota */ }
}

export function loadRoomUpgrade(storage: StorageLike | null = defaultStorage(), now = Date.now()): RoomUpgrade | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(ROOM_UPGRADE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as Partial<RoomUpgrade> & { at?: number };
    if (typeof p.at !== 'number' || now - p.at > ROOM_UPGRADE_TTL_MS) return null;
    if (typeof p.guestDid !== 'string' || !p.guestDid.startsWith('did:key:')) return null;
    if (typeof p.channel !== 'string' || !p.channel.startsWith('#')) return null;
    return {
      guestDid: p.guestDid,
      guestNick: typeof p.guestNick === 'string' ? p.guestNick : 'guest',
      channel: p.channel.toLowerCase(),
      token: typeof p.token === 'string' ? p.token : null,
    };
  } catch {
    return null;
  }
}

export function clearRoomUpgrade(storage: StorageLike | null = defaultStorage()): void {
  if (!storage) return;
  try { storage.removeItem(ROOM_UPGRADE_KEY); } catch { /* ignore */ }
}

/** Copy the guest's opened room secrets to the new identity's slot (the
 *  key lib/rooms.ts persists under). Never overwrites what the new identity
 *  already holds. True when something was carried. */
export function carryRoomKeys(
  guestDid: string,
  newDid: string,
  channel: string,
  storage: StorageLike | null = defaultStorage(),
): boolean {
  if (!storage || guestDid === newDid) return false;
  try {
    const from = storage.getItem(`freeq-room-keys:${guestDid}:${channel}`);
    if (!from) return false;
    const to = `freeq-room-keys:${newDid}:${channel}`;
    if (storage.getItem(to)) return false;
    storage.setItem(to, from);
    return true;
  } catch {
    return false;
  }
}

/** The exact bytes the guest key signs. */
export function roomLinkStatement(guestDid: string, newDid: string, channel: string): Uint8Array {
  return new TextEncoder().encode(`freeq-room-link:v1\n${channel.toLowerCase()}\n${guestDid}\n${newDid}`);
}

/** `signer` is a did:key signer (base64url ed25519 signature). */
export function signRoomLink(
  signer: (bytes: Uint8Array) => Promise<string>,
  guestDid: string,
  newDid: string,
  channel: string,
): Promise<string> {
  return signer(roomLinkStatement(guestDid, newDid, channel));
}

const MARKER = /\[freeq-link:v1 (did:key:z[1-9A-HJ-NP-Za-km-z]+) ([A-Za-z0-9_-]{40,})\]/;

export function formatLinkMessage(guestNick: string, guestDid: string, sig: string): string {
  return `Signed in — I was here as guest ${guestNick}. [freeq-link:v1 ${guestDid} ${sig}]`;
}

export function parseLinkMessage(text: string): { guestDid: string; sig: string } | null {
  const m = text.match(MARKER);
  return m ? { guestDid: m[1], sig: m[2] } : null;
}

/** The guest DID this message links to its sender, if its signature checks
 *  out for exactly this sender and room; null otherwise. */
export async function verifyRoomLink(
  text: string,
  senderDid: string,
  channel: string,
): Promise<{ guestDid: string } | null> {
  const parsed = parseLinkMessage(text);
  if (!parsed || !senderDid || parsed.guestDid === senderDid) return null;
  try {
    const pub = decodeMultibaseEd25519(parsed.guestDid.slice('did:key:'.length));
    const ok = await verifyEd25519(pub, roomLinkStatement(parsed.guestDid, senderDid, channel), parsed.sig);
    return ok ? { guestDid: parsed.guestDid } : null;
  } catch {
    return null;
  }
}
