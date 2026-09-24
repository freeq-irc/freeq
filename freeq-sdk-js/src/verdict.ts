/**
 * What a client shows for a message's signature, and the words for it.
 *
 * The words come from `spec/verdict-model.json`, which both SDKs read. The
 * copy imported here (`./verdict-model.json`) exists only because this
 * package's build root cannot reach outside `src/`; a test pins it
 * byte-identical to the spec file. Twin of the Rust `freeq_sdk::verdict`.
 */

// Node's ESM loader needs the type attribute on a JSON import (see
// identity-claim.ts).
import model from './verdict-model.json' with { type: 'json' };
import { verifyEd25519 } from './did-key.js';
import type { KeyLookup, KeySource } from './key-lookup.js';
import * as signing from './signing.js';

/** What checking a message's signature came to. */
export type VerdictState =
  | 'device'
  | 'server'
  | 'unsigned'
  | 'unverifiable'
  | 'invalid'
  | 'retired'
  | 'pending';

/** Where a device key's standing comes from. */
export type KeyLayer = 'vouched' | 'published';

export const VERDICT_STATES: readonly VerdictState[] = [
  'device',
  'server',
  'unsigned',
  'unverifiable',
  'invalid',
  'retired',
  'pending',
];

export const KEY_LAYERS: readonly KeyLayer[] = ['vouched', 'published'];

/** A message's verdict: the state, the layer for a device signature, and
 *  the key the check used. */
export interface Verdict {
  state: VerdictState;
  layer?: KeyLayer;
  kid?: string;
  keySource?: KeySource;
}

/** The word on the mark. */
export function mark(): string {
  return model.mark;
}

/** The sentence for a verdict. A layer counts only for `device`. */
export function sentence(state: VerdictState, layer?: KeyLayer): string {
  if (state === 'device' && layer) return model.layers[layer];
  return model.states[state].sentence;
}

// ─── checking a received line ───────────────────────────────────────────

/** What a received line's signature covers, rebuilt from the wire. */
export interface Signed {
  /** Who the document says signed it; the key is looked up under this DID. */
  did: string;
  kid: string;
  sigTag: string;
  /** The id the signature covers: what a late verdict is filed under, and
   *  whose ULID time dates the signature. */
  msgid: string;
  /** A chat line's `+freeq.at/origin`: the peer server it was relayed from,
   *  whose own key may have signed it on the sender's behalf. */
  origin?: string;
  doc:
    | { kind: 'chat'; canonical: string }
    | { kind: 'act'; tags: Record<string, string>; venue: string; id: string };
}

/** What can be said about a received line before any key is fetched. */
export type FirstLook =
  | { kind: 'unsigned' }
  | { kind: 'unverifiable'; kid?: string }
  | { kind: 'check'; signed: Signed };

/** The line a first look is taken of. */
export interface Line {
  tags: Record<string, string>;
  /** The wire target: a channel, our nick, or (our echo) the peer's. */
  target: string;
  /** The wire body of a PRIVMSG; undefined for a TAGMSG. */
  body?: string;
  /** This session's DID. */
  ownDid?: string;
  /** The DID a DM's wire target stands for, when the target is a nick. */
  targetDid?: string;
}

/** The kid of an `ed25519:<kid>:<sig>` tag with a 64-byte signature, else null. */
export function sigTagKid(sigTag: string): string | null {
  const [alg, kid, sig, ...rest] = sigTag.split(':');
  if (rest.length > 0 || alg !== 'ed25519' || !kid || !sig) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(sig) || base64UrlLength(sig) !== 64) return null;
  return kid;
}

function base64UrlLength(text: string): number {
  return Math.floor((text.length * 3) / 4);
}

/**
 * Rebuild what a received line's signature covers, the way the server
 * rebuilds it. Twin of the Rust `verdict::first_look`.
 */
export async function firstLook(line: Line): Promise<FirstLook> {
  const tags = line.tags;
  const sigTag = tags[signing.SIG_TAG] ?? tags['freeq.at/sig'];
  if (sigTag === undefined) return { kind: 'unsigned' };
  const kid = sigTagKid(sigTag);
  if (kid === null) return { kind: 'unverifiable' };
  const unverifiable: FirstLook = { kind: 'unverifiable', kid };
  const eventId = tags[signing.EVENT_ID_TAG] ?? tags['freeq.at/eventid'];

  // An act event: the signer is the `from` tag, the id its own.
  const isAct = line.body === undefined && Object.keys(tags).some((n) => signing.isActTag(n));
  if (isAct) {
    const id = eventId || tags['msgid'];
    const did = tags['+freeq.at/from'] ?? tags['freeq.at/from'];
    if (!id || !did) return unverifiable;
    const venue = venueOf(line.target, did, line);
    if (venue === null) return unverifiable;
    return { kind: 'check', signed: { did, kid, sigTag, msgid: id, doc: { kind: 'act', tags, venue, id } } };
  }

  // Everything else names its signer in the server's `account` tag.
  const did = tags['account'];
  if (!did || !did.startsWith('did:')) return unverifiable;
  const venue = venueOf(line.target, did, line);
  if (venue === null) return unverifiable;
  let msgid: string | undefined;
  let canonical: string;
  if (line.body !== undefined) {
    msgid = tags['msgid'] || eventId;
    if (!msgid) return unverifiable;
    canonical = await signing.messageCanonical({
      from: did,
      msgid,
      target: venue,
      body: line.body,
      reply: tags['+reply'] ?? tags['+draft/reply'],
      edit: tags['+draft/edit'],
      tags,
    });
  } else {
    msgid = eventId || tags['msgid'];
    if (!msgid) return unverifiable;
    const mutation = mutationIn(tags);
    if (mutation !== null) {
      canonical = signing.mutationCanonical({ ...mutation, from: did, msgid, target: venue });
    } else if (tags['+freeq.at/event']) {
      canonical = await signing.coordinationCanonical({
        from: did,
        msgid,
        target: venue,
        eventType: tags['+freeq.at/event'],
        payload: tags['+freeq.at/payload'],
        ref: tags['+freeq.at/ref'] ?? tags['+freeq.at/task-id'],
        evidence: tags['+freeq.at/evidence-type'],
      });
    } else {
      // A signed TAGMSG of no kind a document is defined for.
      return unverifiable;
    }
  }
  const origin = tags['+freeq.at/origin'];
  return {
    kind: 'check',
    signed: {
      did,
      kid,
      sigTag,
      msgid,
      ...(origin ? { origin } : {}),
      doc: { kind: 'chat', canonical },
    },
  };
}

/** The mutation a TAGMSG's tags describe, read as the server reads them. */
function mutationIn(
  tags: Record<string, string>,
): { kind: 'delete' | 'react' | 'unreact'; subject: string; emoji?: string } | null {
  const subject = tags['+reply'] ?? tags['+draft/reply'];
  const deleted = tags['+draft/delete'] ?? tags['+delete'];
  if (deleted !== undefined) return { kind: 'delete', subject: deleted };
  const react = tags['+react'] ?? tags['+draft/react'];
  if (react !== undefined) return subject === undefined ? null : { kind: 'react', subject, emoji: react };
  const unreact = tags['+freeq.at/unreact'];
  if (unreact !== undefined) return subject === undefined ? null : { kind: 'unreact', subject, emoji: unreact };
  return null;
}

/** The venue a line was signed for: a channel folded, or a DM's DID pair. */
function venueOf(target: string, signer: string, line: Line): string | null {
  if (target.startsWith('#') || target.startsWith('&')) return signing.channelVenue(target);
  let other: string | undefined;
  if (line.ownDid === signer) {
    other = target.startsWith('did:') ? target : line.targetDid;
  } else {
    other = line.ownDid;
  }
  return other ? signing.dmVenue(signer, other) : null;
}

/**
 * Whether `signed` checks under `key` (32 raw bytes): true when it does,
 * false when the key it names fails the bytes, null when this key cannot
 * check it at all.
 */
export async function checkSigned(signed: Signed, key: Uint8Array): Promise<boolean | null> {
  if (key.length !== 32 || (await signing.deriveKid(key)) !== signed.kid) return null;
  let canonical: string | null;
  if (signed.doc.kind === 'chat') {
    canonical = signed.doc.canonical;
  } else {
    canonical = signing.actCanonical(signed.doc.tags, signed.doc.venue, signed.doc.id);
    if (canonical === null) return null;
  }
  const sig = signed.sigTag.split(':')[2]!;
  return verifyEd25519(key, new TextEncoder().encode(canonical), sig);
}

/**
 * Checks received signatures for one connection. Holds the connected server's
 * own key set, so a signature the server made on a sender's behalf reads as
 * the server's. Twin of the Rust client's `SignatureChecker`.
 */
export class SignatureChecker {
  private serverKeys = new Map<string, Uint8Array>();
  private fetched: Promise<void> | null = null;
  private readonly refetched = new Set<string>();

  constructor(private readonly lookup: KeyLookup) {}

  /** The verdict once the key is found, or found nowhere. */
  async resolve(signed: Signed): Promise<Verdict> {
    await (this.fetched ??= this.fetchServerKeys());
    const serverKey = this.serverKeys.get(signed.kid);
    if (serverKey !== undefined) return serverVerdict(signed, serverKey);

    const atMs = signing.msgidTimestampMs(signed.msgid) ?? Date.now();
    const server = originServerDid(signed.origin);
    const at = new Date(atMs);
    const lookup = async (did: string, retry: boolean, isServer = false) => {
      try {
        return await this.lookup.keyForAt(did, signed.kid, at, { retry, server: isServer });
      } catch {
        return null;
      }
    };
    let found = null;
    if (server === null) {
      found = await lookup(signed.did, true);
    } else {
      // Every relayed line carries its origin, whether the sender or the peer
      // server signed it. The sender is asked first without the retry delays,
      // so a line the server signed is not held up by them.
      const missedBefore = await this.lookup.holdsMiss(signed.did, signed.kid);
      found = await lookup(signed.did, false);
      if (found === null) {
        // The peer server's own key, which signs on a sender's behalf. The kid
        // is a hash of the key, so neither a wrong key nor a forged tag can
        // make a line verify here. No retries: the origin reads a server's
        // document itself before it answers.
        const byServer = await lookup(server, false, true);
        if (byServer !== null) return serverVerdict(signed, byServer.publicKey);
        // Not the server's: the sender's key, which the origin may still be
        // fetching from the peer. Its miss from just now is dropped and it is
        // asked again with the retries a line that just arrived gets; a miss
        // remembered from an earlier line stands.
        if (!missedBefore) {
          this.lookup.forget(signed.did, signed.kid, { relist: false });
          found = await lookup(signed.did, true);
        }
      }
    }
    if (found !== null) {
      const ok = await checkSigned(signed, found.publicKey);
      const keySource = found.source;
      if (ok === false) return { state: 'invalid', kid: signed.kid, keySource };
      if (ok === null) return { state: 'unverifiable', kid: signed.kid, keySource };
      if (found.retiredAt !== null && found.retiredAt * 1000 <= atMs) {
        return { state: 'retired', kid: signed.kid, keySource };
      }
      const layer: KeyLayer = found.source === 'IdentityRecord' ? 'published' : 'vouched';
      return { state: 'device', layer, kid: signed.kid, keySource };
    }

    // A kid no source holds may be a key the server rotated to since its set
    // was read: read it again, once per kid.
    if (!this.refetched.has(signed.kid)) {
      this.refetched.add(signed.kid);
      await (this.fetched = this.fetchServerKeys());
      const again = this.serverKeys.get(signed.kid);
      if (again !== undefined) return serverVerdict(signed, again);
    }
    return { state: 'unverifiable', kid: signed.kid };
  }

  /** Read the server's key set: `/api/v1/signing-key` names the DID it is
   *  published under, `/api/v1/signing-keys/{did}` lists every key. */
  private async fetchServerKeys(): Promise<void> {
    const origin = this.lookup.originBase()?.replace(/\/+$/, '');
    if (!origin) return;
    const get = async (url: string): Promise<Record<string, unknown> | null> => {
      try {
        const res = await this.lookup.reader.fetch(url);
        return res.ok ? ((await res.json()) as Record<string, unknown>) : null;
      } catch {
        return null;
      }
    };
    const did = (await get(`${origin}/api/v1/signing-key`))?.['did'];
    if (typeof did !== 'string' || !/^did:web:[A-Za-z0-9.\-_:%]+$/.test(did)) return;
    const set = await get(`${origin}/api/v1/signing-keys/${did}`);
    if (set === null) return;
    const publicKeys: unknown[] = [];
    if (Array.isArray(set['keys'])) {
      for (const k of set['keys'] as { public_key?: unknown }[]) publicKeys.push(k.public_key);
    }
    publicKeys.push(set['public_key']);
    for (const b64 of publicKeys) {
      if (typeof b64 !== 'string') continue;
      const key = base64UrlDecode(b64);
      if (key?.length === 32) this.serverKeys.set(await signing.deriveKid(key), key);
    }
  }
}

/**
 * The did:web of the peer server a relayed line's `+freeq.at/origin` names,
 * whose own key may have signed it; null without one, or for a value that is
 * not a host name.
 */
export function originServerDid(origin: string | undefined): string | null {
  return origin !== undefined && /^[A-Za-z0-9.-]+$/.test(origin) ? `did:web:${origin}` : null;
}

async function serverVerdict(signed: Signed, key: Uint8Array): Promise<Verdict> {
  const ok = await checkSigned(signed, key);
  const state: VerdictState = ok === true ? 'server' : ok === false ? 'invalid' : 'unverifiable';
  return { state, kid: signed.kid };
}

function base64UrlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  try {
    return Uint8Array.from(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)), (c) =>
      c.charCodeAt(0),
    );
  } catch {
    return null;
  }
}
