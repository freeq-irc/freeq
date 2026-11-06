/**
 * A browser's own `did:key`, for joining a room without an account.
 *
 * Rooms are end-to-end encrypted, so a member needs an identity to have the
 * room key sealed to. This is the smallest one there is: an Ed25519 key the
 * browser mints for itself and keeps in localStorage. It authenticates with
 * the same did:key SASL flow agents use (no new auth path, nothing on the
 * server), signs its messages with that key, and signs its e2ee pre-key
 * bundle with it too, which is what lets other members bind the bundle to the
 * DID and seal the room key to it.
 *
 * The same browser coming back is the same guest: it is still on the room's
 * roster and rejoins without the invite. Clearing site data forgets it.
 */

import { generateDidKey, importDidKey, importDidKeyPair, type DidKey } from '@freeq/sdk';
import type { StorageLike } from './room-link';

export const GUEST_KEY = 'freeq-guest-key';

export interface GuestIdentity {
  did: string;
  /** SASL challenge signer, and the signer for room-link statements. */
  key: DidKey;
  /** The same key as a WebCrypto pair, for MSGSIG and the e2ee bundle. */
  pair: CryptoKeyPair;
}

function defaultStorage(): StorageLike | null {
  try {
    if (typeof localStorage !== 'undefined' && typeof localStorage.getItem === 'function') return localStorage;
  } catch { /* locked-down embeds */ }
  return null;
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(std + '='.repeat((4 - (std.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

async function fromSeed(seed: Uint8Array): Promise<GuestIdentity> {
  const key = await importDidKey(seed);
  return { did: key.did, key, pair: await importDidKeyPair(seed) };
}

/** This browser's guest identity, minting and storing one on first use. */
export async function loadOrCreateGuestIdentity(storage: StorageLike | null = defaultStorage()): Promise<GuestIdentity> {
  const stored = storage?.getItem(GUEST_KEY);
  if (stored) {
    try {
      const { seed } = JSON.parse(stored) as { seed?: string };
      if (seed) {
        const bytes = unb64url(seed);
        if (bytes.length === 32) return await fromSeed(bytes);
      }
    } catch { /* unreadable: mint a new one */ }
  }
  const fresh = await generateDidKey();
  const seed = await fresh.exportSeed();
  const identity = await fromSeed(seed);
  try { storage?.setItem(GUEST_KEY, JSON.stringify({ seed: b64url(seed), did: identity.did })); } catch { /* quota */ }
  return identity;
}

/** The stored guest DID without touching the key, or null. */
export function storedGuestDid(storage: StorageLike | null = defaultStorage()): string | null {
  try {
    const raw = storage?.getItem(GUEST_KEY);
    if (!raw) return null;
    const { did } = JSON.parse(raw) as { did?: string };
    return typeof did === 'string' && did.startsWith('did:key:') ? did : null;
  } catch {
    return null;
  }
}
