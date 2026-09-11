/**
 * What this client can say about a message's signature.
 *
 * The check is the SDK's own, made here on the device: it rebuilds the signed
 * document from the line and looks the signer's key up in their identity
 * records, their DID document, or the server's key store. The verdict arrives
 * on the message, or shortly after it as a `verdict` event, and this module
 * holds it so a row and the proof panel read the same answer.
 *
 * The sentences come from `spec/verdict-model.json` through the SDK, so every
 * freeq client says the same words for the same state.
 */
import { useSyncExternalStore } from 'react';
import { sentence, type KeyLayer, type Verdict, type VerdictState } from '@freeq/sdk';

export type { KeyLayer, Verdict };

/** What checking a signature came to.
 *
 *  "We couldn't check this" and "this doesn't check out" are different facts
 *  and only one of them is an accusation: `unverifiable` covers a signature
 *  whose key no source holds, or a format this build cannot read; `invalid`
 *  means the key the signature names was found and the signature does not
 *  match; `retired` means it was made with a key its owner had already
 *  retired. `unsigned` is a third thing again — there was never a signature,
 *  so nothing was checked and nothing failed. `pending` means the key is
 *  still being fetched. */
export type VerifyOutcome = VerdictState;

/** Verdicts by msgid, as the SDK settles them. A row and the panel read the
 *  same entry, and a late verdict replaces the `pending` one in place. */
const verdicts = new Map<string, Verdict>();

/** Rows subscribe so a verdict that settles after the line was drawn can
 *  appear without anything else forcing a re-render. */
const listeners = new Set<() => void>();

export function subscribeVerdicts(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** File what the SDK said about one line. */
export function recordVerdict(msgid: string, verdict: Verdict | undefined): void {
  if (!msgid || !verdict) return;
  const known = verdicts.get(msgid);
  if (known && known.state === verdict.state && known.layer === verdict.layer) return;
  verdicts.set(msgid, verdict);
  for (const fn of listeners) fn();
}

/** The verdict on file for a message, if the SDK has given one. */
export function cachedVerdict(msgid: string): Verdict | undefined {
  return verdicts.get(msgid);
}

/** Reactive form of `cachedVerdict` for message rows. */
export function useCachedVerdict(msgid: string): Verdict | undefined {
  return useSyncExternalStore(subscribeVerdicts, () => verdicts.get(msgid));
}

/** Test-only: forget every verdict. */
export function __resetVerifyCacheForTests(): void {
  verdicts.clear();
}

/** One answer: what it is, what it means for the reader, and the colour it
 *  wears. The reader is asking a single question — who vouches for this
 *  message — so the heading answers it and the line says what that means for
 *  them. The line is the SDK's sentence for the state, which every client
 *  shows; the heading and the tone are this client's. Green means the SENDER
 *  proved it: a server signature is the server vouching for what it received,
 *  a fact worth stating and not a verification of the sender, so it stays
 *  quiet (ruled 2026-08-07: valid is not verified). Red only after a mismatch
 *  or a retired key; every can't-know is quiet — a fact, never a warning. */
export interface VerdictCopy {
  heading: string;
  line: string;
  tone: string;
}

/** The heading and tone each state wears. A signature made after its key was
 *  retired reads as an invalid one, which is what the verdict is (`PHASE6-PLAN`,
 *  "Ruled", item 2). */
const HEADINGS: Record<VerdictState, { heading: string; tone: string }> = {
  device: { heading: 'Signed', tone: 'text-success' },
  server: { heading: 'Server Signed', tone: 'text-fg-muted' },
  unsigned: { heading: 'Unsigned', tone: 'text-fg-muted' },
  unverifiable: { heading: 'Signature Not Supported', tone: 'text-fg-muted' },
  invalid: { heading: 'Signature Invalid', tone: 'text-danger' },
  retired: { heading: 'Signature Invalid', tone: 'text-danger' },
  pending: { heading: 'Verification in Progress', tone: 'text-fg-muted' },
};

/** Four of the states never name what was signed, so they read the same over
 *  a message and over a coordination event. These three do. Kept as whole
 *  sentences rather than an interpolated noun: copy that is assembled is copy
 *  nobody reads before it ships. */
const EVENT_LINES: Partial<Record<VerdictState, string>> = {
  unsigned: 'Nothing was signed — there is no signature to check. Typical for events emitted before event signing.',
  unverifiable: 'This device can’t check this signature — usually an older event, sometimes a newer app.',
  invalid: 'This event is signed, but the signature doesn’t check out. Treat it with suspicion.',
};

/** The answer for one verdict, worded for what the id actually names. */
export function verdictCopy(
  outcome: VerifyOutcome,
  noun: 'message' | 'event' = 'message',
  layer?: KeyLayer,
): VerdictCopy {
  const { heading, tone } = HEADINGS[outcome];
  const line = (noun === 'event' ? EVENT_LINES[outcome] : undefined) ?? sentence(outcome, layer);
  return { heading, line, tone };
}

/** The copy for a verdict the SDK gave, layer and all. */
export function copyForVerdict(
  verdict: Verdict,
  noun: 'message' | 'event' = 'message',
): VerdictCopy {
  return verdictCopy(verdict.state, noun, verdict.layer);
}

/** Nothing was signed, so there was nothing to check. Not a failed check —
 *  treating it as one would put a fault on a message that has none. */
export function unsignedCopy(noun: 'message' | 'event' = 'message'): VerdictCopy {
  return verdictCopy('unsigned', noun);
}

/** The key is still being looked up. The row shows nothing yet and the panel
 *  says so, rather than claiming an answer it does not have. */
export const CHECKING_COPY: VerdictCopy = verdictCopy('pending');
