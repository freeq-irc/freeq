/** Identity display for DM thread keys and message authors.
 *
 * With DIDs as the load-bearing identity, a DM thread is keyed by the peer's
 * DID (see the SDK's `address.ts`), so the buffer name reaching the UI can be
 * a raw `did:plc:…` / `did:key:…` string. These helpers turn that into a human
 * name, resolving against data the client already holds and falling back to a
 * compact form only when nothing resolves. Display-only — the raw DID stays
 * the identity the app operates on (DMs, blocks, reports).
 */

/** A syntactic DID: `did:<method>:<id>`. No network, no `id` validation. */
export function isDid(s: string): boolean {
  return /^did:[a-z0-9]+:.+/i.test(s);
}

/** Compact a DID for display: `did:plc:k2n3…t5j7`. Non-DIDs pass through. */
export function shortenDid(s: string): string {
  if (!isDid(s)) return s;
  const [, method, ...idParts] = s.split(':');
  const id = idParts.join(':');
  if (id.length <= 12) return `${method}:${id}`;
  return `${method}:${id.slice(0, 4)}…${id.slice(-4)}`;
}

/**
 * Human name for a DM thread key or author identifier that may be a raw DID.
 * A non-DID (an ordinary nick) is returned unchanged. A DID is resolved
 * through the provided sources in order — the SDK's learned nick↔DID map, then
 * a cached AT profile handle/display name — and only compacted with
 * `shortenDid` when every source misses. Sources that themselves return a DID
 * (or nothing) are skipped, so we never present one DID in place of another.
 */
export function resolveIdentityName(
  id: string,
  sources: {
    nickForDid?: (did: string) => string | undefined | null;
    nameForDid?: (did: string) => string | undefined | null;
  } = {},
): string {
  if (!isDid(id)) return id;
  for (const src of [sources.nickForDid, sources.nameForDid]) {
    const v = src?.(id);
    if (v && !isDid(v)) return v;
  }
  return shortenDid(id);
}

interface MemberLike {
  did?: string;
  away?: string | null;
}
interface ChannelLike {
  members: Map<string, MemberLike>;
}

/**
 * Locate a DM peer's member record across channels, given a thread key that
 * may be a **nick or a DID**. Members carry both, so match on whichever form
 * the key takes — a DID-keyed DM would otherwise find nothing in the
 * nick-keyed member maps, reporting a peer who is plainly online as offline.
 *
 * `channelsOnly` restricts the search to real channels (`#…`), which presence
 * needs so a DM buffer's own member map can't answer for itself.
 */
/**
 * Whether the peer of a DM thread key is blocked, under every form a block
 * can be recorded in: the key itself (DID or nick), the peer's member record
 * (found by either key form), or — for a DID key — the peer's known display
 * nick (a block recorded while they were offline stores only the nick).
 * `nickForDid` supplies the retained DID→nick display binding.
 *
 * The single source of truth for "is this conversation with a blocked user";
 * used by the sidebar filter and the in-thread blocked banner so the two
 * can't disagree.
 */
export function isPeerBlocked(
  channels: Map<string, ChannelLike>,
  key: string,
  blockedNicks: string[],
  blockedDids: string[],
  nickForDid?: (did: string) => string | undefined | null,
): boolean {
  if (isDid(key) && blockedDids.includes(key)) return true;
  if (blockedNicks.includes(key.toLowerCase())) return true;
  if (isDid(key)) {
    const peerNick = nickForDid?.(key)?.toLowerCase();
    if (peerNick && blockedNicks.includes(peerNick)) return true;
  }
  if (blockedDids.length > 0) {
    const m = findMemberByKey(channels, key)?.member;
    if (m?.did && blockedDids.includes(m.did)) return true;
  }
  return false;
}

export function findMemberByKey<M extends MemberLike>(
  channels: Map<string, { members: Map<string, M> }>,
  key: string,
  channelsOnly = false,
): { nick: string; member: M } | null {
  const byDid = isDid(key);
  const lower = key.toLowerCase();
  for (const [name, ch] of channels) {
    if (channelsOnly && !name.startsWith('#')) continue;
    if (byDid) {
      for (const [nick, member] of ch.members) {
        if (member.did === key) return { nick, member };
      }
    } else {
      const member = ch.members.get(lower);
      if (member) return { nick: lower, member };
    }
  }
  return null;
}
