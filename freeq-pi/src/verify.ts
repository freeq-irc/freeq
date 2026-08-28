/**
 * Signature verification for inbound task events.
 *
 * The RFC is explicit that the outcome is THREE-way, not two, and getting
 * this wrong in either direction is harmful:
 *
 *   valid        → apply it
 *   invalid      → REJECT. The canonical rebuilt but the signature does not
 *                  verify, or a covered tag was added/stripped in transit.
 *                  That is evidence of tampering or forgery.
 *   unverifiable → DEFER, never reject. The canonical rebuilt fine but the
 *                  key cannot currently be fetched (the signer's key-origin
 *                  is unreachable, or the key predates the store). A blip at
 *                  a third party must not permanently destroy a valid accept.
 *
 * Conflating the last two is the trap: treating "I couldn't check" as "it's a
 * forgery" turns someone else's outage into silent, permanent work loss.
 *
 * KNOWN GAP (the RFC's, not ours): the DID↔key binding is published by the
 * server, so this holds against an honest origin, not a malicious one. The
 * hash-derived `kid` means a key server cannot swap keys under an existing
 * signature undetected, but it cannot attest the original binding. Real E2E
 * non-repudiation needs the key anchored in the DID document.
 */

import { verifyActTags } from "@freeq/bot-kit";

export type VerifyOutcome = "valid" | "invalid" | "unverifiable";

export interface VerifyResult {
  outcome: VerifyOutcome;
  /** Machine-readable detail, for logs and tests. */
  reason: string;
}

/** Fetches the raw 32-byte public key a signature names, or undefined. */
export type KeyFetcher = (did: string, kid: string) => Promise<Uint8Array | undefined>;

export interface VerifiableEvent {
  channel: string;
  did?: string;
  eventId: string;
  tags: Record<string, string>;
  sigTag?: string;
}

const SIG_TAGS = ["+freeq.at/sig", "freeq.at/sig"];

export function sigTagOf(ev: VerifiableEvent): string | undefined {
  if (ev.sigTag) return ev.sigTag;
  for (const name of SIG_TAGS) if (ev.tags[name]) return ev.tags[name];
  return undefined;
}

/** The `kid` a signature names: `ed25519:<kid>:<sig>`. */
export function kidOf(sigTag: string): string | undefined {
  const parts = sigTag.split(":");
  return parts.length === 3 && parts[1] ? parts[1] : undefined;
}

/**
 * The venue a signature covers.
 *
 * Must match what the signer used, or every signature reads as tampered. A
 * channel is lowercased; a DM is `dm:<did_a>,<did_b>` with the DIDs sorted,
 * so both ends derive the same string. This mirrors the SDK's own rule.
 */
export function venueFor(channel: string, selfDid: string, senderDid?: string): string | undefined {
  if (channel.startsWith("#")) return channel.toLowerCase();
  // A DM target is the other party — either a DID, or a nick we cannot map.
  const other = channel.startsWith("did:") ? channel : senderDid;
  if (!other || !selfDid) return undefined;
  return `dm:${[selfDid, other].sort().join(",")}`;
}

export interface VerifyOptions {
  fetchKey: KeyFetcher;
  selfDid: string;
}

/**
 * Verify one act event.
 *
 * Deliberately returns `unverifiable` (not `invalid`) whenever we cannot
 * obtain the material to judge: no signature, no DID, no resolvable venue, or
 * no key. Only a real cryptographic failure is `invalid`.
 */
export async function verifyActEvent(
  ev: VerifiableEvent,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const sigTag = sigTagOf(ev);
  if (!sigTag) return { outcome: "unverifiable", reason: "no signature on the event" };
  if (!ev.did) return { outcome: "unverifiable", reason: "no sender DID to look a key up by" };

  const kid = kidOf(sigTag);
  if (!kid) return { outcome: "invalid", reason: "malformed signature tag" };

  const venue = venueFor(ev.channel, opts.selfDid, ev.did);
  if (!venue) {
    return { outcome: "unverifiable", reason: `cannot derive the signed venue for ${ev.channel}` };
  }

  let key: Uint8Array | undefined;
  try {
    key = await opts.fetchKey(ev.did, kid);
  } catch (err) {
    // A lookup failure is an outage, not a forgery.
    return { outcome: "unverifiable", reason: `key lookup failed: ${(err as Error).message}` };
  }
  if (!key) return { outcome: "unverifiable", reason: `no key on record for kid ${kid}` };

  const result = await verifyActTags(ev.tags, venue, ev.eventId, sigTag, key);
  if (result.ok) return { outcome: "valid", reason: "signature verified" };

  switch (result.reason) {
    // The signer's identity or the document itself is missing — we cannot
    // judge, so we must not condemn.
    case "no-act-tags":
    case "missing-from":
      return { outcome: "unverifiable", reason: result.reason };
    // These are real failures: the bytes do not match what was signed.
    case "sig-invalid":
    case "kid-mismatch":
    case "bad-sig-format":
    case "unsupported-algorithm":
    default:
      return { outcome: "invalid", reason: result.reason };
  }
}

/**
 * A key fetcher backed by the server's key store, with a small cache.
 *
 * `(did, kid)` is immutable — the kid is a hash of the key — so a hit can be
 * cached forever. A miss is NOT cached: the key may simply not have been
 * registered yet, and caching that would turn a transient gap into a
 * permanent "unverifiable".
 */
export function serverKeyFetcher(origin: string): KeyFetcher {
  const cache = new Map<string, Uint8Array>();
  return async (did, kid) => {
    const cacheKey = `${did}\u0000${kid}`;
    const hit = cache.get(cacheKey);
    if (hit) return hit;

    const url = `${origin.replace(/\/$/, "")}/api/v1/signing-keys/${encodeURIComponent(
      did,
    )}/${encodeURIComponent(kid)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.status === 404) return undefined;
    if (!res.ok) throw new Error(`key store returned ${res.status}`);

    const body = (await res.json()) as { public_key?: string; algorithm?: string };
    if (body.algorithm && body.algorithm !== "ed25519") {
      throw new Error(`unsupported key algorithm ${body.algorithm}`);
    }
    if (!body.public_key) return undefined;
    const raw = base64urlToBytes(body.public_key);
    if (raw.length !== 32) throw new Error(`expected a 32-byte key, got ${raw.length}`);
    cache.set(cacheKey, raw);
    return raw;
  };
}

export function base64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
