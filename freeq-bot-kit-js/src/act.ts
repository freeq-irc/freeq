// Signing and verification for `freeq.at/act` action messages.
//
// Implements the act canonical from the act RFC (docs/HANDOFF-RFC.md, v0.4):
// the signature covers every `act-*` tag present on the message — not a
// fixed field list — JCS-canonicalized with sorted keys. Must stay
// byte-compatible with `freeq_sdk::act` on the Rust side; the shared
// contract is `spec/act-signing-vectors.json`, which both test suites
// reproduce exactly.
//
//
// Only the sender ever writes `act-` tags. The open coverage rule is what
// lets a new task kind add fields without anyone updating a canonical, and it
// only works under that discipline: a server that stamped a tag of its own
// under this prefix would land it inside the signature's coverage and break
// every act signature it relayed. Server attestations go in their own
// namespaces (`account`, `time`, `msgid`, `+freeq.at/origin`).
//
// Canonical mapping rules (see the Rust module for the full rationale):
// - covered iff the tag name, after stripping `+freeq.at/`, is `act` or
//   starts with `act-` (`actor-class` and `sig` are NOT covered)
// - canonical keys are the stripped names; values verbatim, always strings
// - two more keys are injected by the caller, never read from a tag — the
//   same two chat's documents carry: `target`, the normalized venue (a
//   channel lowercased, or `dm:<did_a>,<did_b>` with the DIDs sorted), and
//   `msgid`, the event id the signer minted (`+freeq.at/eventid` on the
//   wire). Neither can collide with a covered key, which always starts with
//   `act`. Without the venue an offer signed in one room replays into
//   another intact; without the id a task's identity is the one unsigned
//   thing about it.
// - an offer carries no `act-id`: its own event id is the task's id. Later
//   events name that id in `act-id` and mint their own id for themselves.
// - sig tag value: `ed25519:<kid>:<base64url sig>`, kid =
//   base64url-nopad(sha256(raw 32-byte public key)[0..16])

import type { DidKey } from "@freeq/sdk";
import { canonicalizeForSigning } from "./delegation.js";

/** Wire name of the signature tag (also accepted without the `+`). */
export const ACT_SIG_TAG = "+freeq.at/sig";

const CLIENT_TAG_PREFIX = "+freeq.at/";
const TAG_PREFIX = "freeq.at/";

export type ActVerifyResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | "no-act-tags"
        | "bad-sig-format"
        | "unsupported-algorithm"
        | "kid-mismatch"
        | "sig-invalid";
    };

function strippedName(tagName: string): string {
  if (tagName.startsWith(CLIENT_TAG_PREFIX)) return tagName.slice(CLIENT_TAG_PREFIX.length);
  if (tagName.startsWith(TAG_PREFIX)) return tagName.slice(TAG_PREFIX.length);
  return tagName;
}

function isActTag(tagName: string): boolean {
  const name = strippedName(tagName);
  return name === "act" || name.startsWith("act-");
}

/**
 * Build the canonical string over the act tags in `tags` (wire names,
 * unescaped values), the venue, and the event id.
 *
 * `target` and `msgid` are supplied by the caller — a verifier rebuilds them
 * from delivery context rather than reading either off a tag. Returns null if
 * no act tags are present: delivery context alone is not a document.
 */
export function actCanonical(
  tags: Record<string, string>,
  target: string,
  msgid: string,
): string | null {
  const covered: Record<string, string> = {};
  for (const [name, value] of Object.entries(tags)) {
    if (isActTag(name)) covered[strippedName(name)] = value;
  }
  if (Object.keys(covered).length === 0) return null;
  covered.target = target;
  covered.msgid = msgid;
  return canonicalizeForSigning(covered);
}

/** base64url (unpadded) of the first 16 bytes of SHA-256 over the raw key. */
export async function deriveKid(rawPublicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawPublicKey));
  return b64url(digest.slice(0, 16));
}

/**
 * Sign the act tags, posted to `target` under `msgid`, with a DidKey. Returns
 * the sig tag value (`ed25519:<kid>:<base64url sig>`), or null if no act tags
 * are present.
 */
export async function signActTags(
  tags: Record<string, string>,
  target: string,
  msgid: string,
  key: DidKey,
): Promise<string | null> {
  const canonical = actCanonical(tags, target, msgid);
  if (canonical === null) return null;
  const sig = await key.signer(new TextEncoder().encode(canonical));
  const kid = await deriveKid(publicKeyFromMultibase(key.publicKeyMultibase));
  return `ed25519:${kid}:${sig}`;
}

/**
 * Verify an act sig tag over `tags` against a raw 32-byte public key.
 *
 * `target` and `msgid` come from the receiver's own view of the delivery — the
 * venue the message arrived in and the id it is being filed under — so a
 * message replayed elsewhere, or filed under another id, reads as tampering.
 */
export async function verifyActTags(
  tags: Record<string, string>,
  target: string,
  msgid: string,
  sigTag: string,
  rawPublicKey: Uint8Array,
): Promise<ActVerifyResult> {
  const parts = sigTag.split(":");
  if (parts.length !== 3) return { ok: false, reason: "bad-sig-format" };
  const [alg, kid, sigB64] = parts;
  if (alg !== "ed25519") return { ok: false, reason: "unsupported-algorithm" };
  if ((await deriveKid(rawPublicKey)) !== kid) return { ok: false, reason: "kid-mismatch" };
  const canonical = actCanonical(tags, target, msgid);
  if (canonical === null) return { ok: false, reason: "no-act-tags" };
  let sig: Uint8Array;
  try {
    sig = b64urlDecode(sigB64);
  } catch {
    return { ok: false, reason: "bad-sig-format" };
  }
  // base64url decoding silently tolerates junk/short input, so an ed25519 sig
  // that isn't exactly 64 bytes reaches here — reject it as a format error to
  // match Rust's BadSigFormat (reason parity feeds the Phase 2 validator's
  // valid / invalid / unverifiable branch).
  if (sig.length !== 64) {
    return { ok: false, reason: "bad-sig-format" };
  }
  const cryptoKey = await crypto.subtle.importKey("raw", rawPublicKey, "Ed25519", false, [
    "verify",
  ]);
  const valid = await crypto.subtle.verify(
    "Ed25519",
    cryptoKey,
    sig,
    new TextEncoder().encode(canonical),
  );
  return valid ? { ok: true } : { ok: false, reason: "sig-invalid" };
}

/**
 * Decode a `z…` ed25519 multibase public key (the part of a did:key after
 * `did:key:`) to its raw 32 bytes.
 */
export function publicKeyFromMultibase(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new Error(`expected base58btc multibase (z…), got ${multibase.slice(0, 4)}…`);
  }
  const bytes = base58btcDecode(multibase.slice(1));
  // Strip the 0xed01 ed25519 multicodec prefix.
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("not an ed25519 multicodec key");
  }
  return bytes.slice(2);
}

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(s: string): Uint8Array {
  const bytes: number[] = [0];
  for (const c of s) {
    const digit = B58_ALPHABET.indexOf(c);
    if (digit < 0) throw new Error(`invalid base58 character ${c}`);
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i] * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's are leading zero bytes.
  for (const c of s) {
    if (c !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
