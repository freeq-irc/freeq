/**
 * Asking the server whether a message's signature holds up.
 *
 * The badge on a message says only what it can support. Before a check it
 * claims nothing beyond "this carries a signature"; afterwards it says what
 * the server actually answered — including that the answer was bad, or that
 * nobody could tell.
 */

/** Result of checking a signature against `GET /api/v1/verify/{msgid}`.
 *
 *  Four outcomes, because "we couldn't check this" and "this doesn't check
 *  out" are different facts and only one of them is an accusation:
 *  `unverifiable` covers a signature from before the current canonical, or one
 *  made with a key the server no longer holds; `invalid` means the key the
 *  signature names was found and the signature does not match. */
export type VerifyOutcome = 'device' | 'server' | 'unverifiable' | 'invalid';

/**
 * Checked verdicts by msgid. Definitive server answers are cached — the same
 * message is answered the same way every time, and rows re-render constantly.
 * Network errors are not cached, so a transient failure can be retried.
 */
const verifyCache = new Map<string, VerifyOutcome>();

/** The verdict already on file for a message, if it has been checked. */
export function cachedVerdict(msgid: string): VerifyOutcome | undefined {
  return verifyCache.get(msgid);
}

/** Test-only: forget every checked verdict. */
export function __resetVerifyCacheForTests(): void {
  verifyCache.clear();
}

export async function verifySignature(msgid: string): Promise<VerifyOutcome> {
  const cached = verifyCache.get(msgid);
  if (cached) return cached;
  try {
    const r = await fetch(`/api/v1/verify/${encodeURIComponent(msgid)}`);
    if (!r.ok) return 'unverifiable';
    const j = await r.json();
    const v = j?.verification;
    // `verdict` is the server's three-way answer; fall back to the older
    // boolean for a server that predates it. An old server's `false` means
    // "could not confirm", which is not the same as "forged" — reading it as
    // an accusation would put a warning on messages nobody impugned.
    const verdict: string = v?.verdict ?? (v?.valid ? 'valid' : 'unverifiable');
    let outcome: VerifyOutcome;
    if (verdict === 'valid') {
      outcome = v.verified_by === 'client-session-key' ? 'device' : 'server';
    } else if (verdict === 'invalid') {
      outcome = 'invalid';
    } else {
      outcome = 'unverifiable';
    }
    verifyCache.set(msgid, outcome);
    return outcome;
  } catch {
    // A network failure says nothing about the signature.
    return 'unverifiable';
  }
}

/** How a checked message describes itself, and the colour it wears. */
export const VERIFY_LABELS: Record<VerifyOutcome, { text: string; tone: string }> = {
  device: { text: 'Verified — signed on the sender’s device', tone: 'text-success' },
  server: { text: 'Verified — signed by the server on the sender’s behalf', tone: 'text-success' },
  unverifiable: { text: 'Could not be checked here — not a claim either way', tone: 'text-warning' },
  invalid: { text: 'Does not match its signing key — treat with suspicion', tone: 'text-danger' },
};

/**
 * The colour of the resting badge. Unchecked is deliberately not green: the
 * only thing known before a check is that a signature is present, and a badge
 * that looks verified before anyone verified anything is the claim this whole
 * feature exists to stop making. Once checked, the marker carries the verdict
 * — a message whose signature came back bad must never sit under a green
 * padlock.
 */
export function badgeTone(outcome: VerifyOutcome | null): string {
  return outcome ? VERIFY_LABELS[outcome].tone : 'text-fg-dim';
}

/** The tooltip of the resting badge, before and after a check. */
export function badgeTitle(outcome: VerifyOutcome | null): string {
  return outcome ? VERIFY_LABELS[outcome].text : 'Signed message — click to check';
}
