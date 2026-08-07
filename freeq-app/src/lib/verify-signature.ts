/**
 * Asking the server whether a message's signature holds up.
 *
 * Verification is an explicit request — the UI asks only when the user does.
 * The answer says only what it can support: what the server actually
 * answered, that the answer was bad, that nobody could tell — or that the
 * question never got through at all, which is a fact about the network, not
 * about the message.
 */
import { useSyncExternalStore } from 'react';

/** Result of checking a signature against `GET /api/v1/verify/{msgid}`.
 *
 *  "We couldn't check this" and "this doesn't check out" are different facts
 *  and only one of them is an accusation: `unverifiable` covers a signature
 *  from before the current canonical, or one made with a key the server does
 *  not hold; `invalid` means the key the signature names was found and the
 *  signature does not match. `unreachable` means the check itself failed —
 *  network down, proxy fault, server error. It is not a verdict about the
 *  message and must never be dressed up as one. */
export type VerifyOutcome = 'device' | 'server' | 'unverifiable' | 'invalid' | 'unreachable';

/** A checked answer, with the one distinction inside `unverifiable` that
 *  changes what happens next: a signature naming a key this server simply
 *  hasn't fetched yet is `transient` — the server starts fetching the key the
 *  moment it answers, so asking again shortly usually resolves. Every other
 *  flavour (a retired format, an unknown algorithm, no record) is final. */
export interface VerifyAnswer {
  outcome: VerifyOutcome;
  transient: boolean;
}

/**
 * Checked verdicts by msgid. Definitive server answers are cached — the same
 * message is answered the same way every time. Transient can't-check answers
 * and failed checks are NOT cached, so asking again can land a real verdict.
 */
const verifyCache = new Map<string, VerifyAnswer>();

/** Rows subscribe so a cached verdict (the ⚠ after an `invalid` answer) can
 *  appear without anything else forcing a re-render. */
const listeners = new Set<() => void>();

function notifyVerdictListeners(): void {
  for (const fn of listeners) fn();
}

export function subscribeVerdicts(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** The verdict already on file for a message, if it has been checked. */
export function cachedVerdict(msgid: string): VerifyAnswer | undefined {
  return verifyCache.get(msgid);
}

/** Reactive form of `cachedVerdict` for message rows. */
export function useCachedVerdict(msgid: string): VerifyAnswer | undefined {
  return useSyncExternalStore(subscribeVerdicts, () => verifyCache.get(msgid));
}

/** Test-only: forget every checked verdict. */
export function __resetVerifyCacheForTests(): void {
  verifyCache.clear();
}

export async function verifySignature(msgid: string): Promise<VerifyAnswer> {
  const cached = verifyCache.get(msgid);
  if (cached) return cached;
  try {
    const r = await fetch(`/api/v1/verify/${encodeURIComponent(msgid)}`);
    if (!r.ok) {
      // A 4xx is the server answering "no record of that id" — a can't-check.
      // A 5xx (from the server or anything between) means the check never
      // happened; saying "could not be checked here" would claim the server
      // considered it. Neither is cached: a later ask deserves a fresh try.
      return { outcome: r.status < 500 ? 'unverifiable' : 'unreachable', transient: false };
    }
    const j = await r.json();
    const v = j?.verification;
    // `verdict` is the server's three-way answer; fall back to the older
    // boolean for a server that predates it. An old server's `false` means
    // "could not confirm", which is not the same as "forged" — reading it as
    // an accusation would put a warning on messages nobody impugned.
    const verdict: string = v?.verdict ?? (v?.valid ? 'valid' : 'unverifiable');
    let answer: VerifyAnswer;
    if (verdict === 'valid') {
      answer = {
        outcome: v.verified_by === 'client-session-key' ? 'device' : 'server',
        transient: false,
      };
    } else if (verdict === 'invalid') {
      answer = { outcome: 'invalid', transient: false };
    } else {
      // The server names its reason; a key it hasn't fetched yet is the one
      // reason a retry can outrun, because answering the request is what
      // starts the fetch.
      answer = {
        outcome: 'unverifiable',
        transient: v?.verified_by === 'unverifiable-unknown-key',
      };
    }
    if (!answer.transient) {
      verifyCache.set(msgid, answer);
      notifyVerdictListeners();
    }
    return answer;
  } catch {
    // A network failure says nothing about the signature.
    return { outcome: 'unreachable', transient: false };
  }
}

/** How a checked message describes itself, and the colour it wears.
 *  Green means the SENDER proved it — a server signature is the server
 *  vouching for what it received, which is a fact worth stating and not a
 *  verification of the sender, so it stays quiet (ruled 2026-08-07: valid
 *  is not verified). Red only after a mismatch; every can't-know is quiet —
 *  a fact, never a warning. */
export const VERIFY_LABELS: Record<VerifyOutcome, { text: string; tone: string }> = {
  device: { text: 'Verified — signed on the sender’s device', tone: 'text-success' },
  server: { text: 'Valid server signature — the server vouches for what it received; the sender’s own key did not sign it', tone: 'text-fg-muted' },
  unverifiable: { text: 'Could not be checked — the server doesn’t have what it needs to verify this one', tone: 'text-fg-muted' },
  invalid: { text: 'Does not match its signing key — treat with suspicion', tone: 'text-danger' },
  unreachable: { text: 'The check didn’t go through — nothing was determined. Close and try again.', tone: 'text-fg-muted' },
};
