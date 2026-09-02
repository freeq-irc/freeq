/**
 * The word each task verb shows a reader.
 *
 * The headline of a card is the word for the verb its event carried — the
 * verb is on the wire and the client computes nothing from it, so a progress
 * report never reads as a claim. A verb with no row here shows itself, which
 * is how a kind may add one without this having to be taught it.
 */
const HEADLINE: Record<string, string> = {
  offer: 'offered',
  accept: 'accepted',
  decline: 'declined',
  claim: 'claimed',
  progress: 'in progress',
  complete: 'completed',
  fail: 'failed',
  cancel: 'cancelled',
  bid: 'bid',
  award: 'awarded',
  submit: 'submitted',
  revise: 'revisions requested',
  'accept-work': 'accepted',
  forfeit: 'forfeited',
  // The two the home signs for itself. They write no companion line, so these
  // words are read in the timeline rather than on a card.
  confirm: 'confirmed',
  expire: 'expired',
};

export function actHeadline(verb: string): string {
  return HEADLINE[verb] ?? verb;
}

/**
 * The glyph each task verb shows a reader, beside its word.
 *
 * One row per verb, read the same way the word above it is: off the verb the
 * event carried, never off where the task got to. A verb with no row here
 * gets the generic pin, so a kind may add a move without this being taught it.
 */
const EMOJI: Record<string, string> = {
  offer: '📋',
  accept: '👍',
  decline: '👎',
  claim: '✋',
  progress: '📌',
  complete: '🎉',
  fail: '❌',
  cancel: '🚫',
  bid: '💰',
  award: '🏆',
  submit: '📤',
  revise: '🔁',
  'accept-work': '✅',
  forfeit: '🏳️',
  // The two the home signs for itself. They write no companion line, so they
  // carry their glyph on a system line rather than on a card.
  confirm: '✔️',
  expire: '⌛',
};

export function actEmoji(verb: string): string {
  return EMOJI[verb] ?? '📌';
}

/**
 * The accent a card's left edge carries, as a role rather than a colour —
 * each client paints the role in its own theme.
 *
 * Purple where the work lands on someone's plate, green on a good end, red on
 * a failure. Every other verb goes without: an edge on everything is an edge
 * that says nothing.
 */
export type ActAccent = 'none' | 'handoff' | 'success' | 'failure';

export function actAccent(verb: string): ActAccent {
  switch (verb) {
    case 'offer':
    case 'award':
      return 'handoff';
    case 'complete':
    case 'accept-work':
      return 'success';
    case 'fail':
      return 'failure';
    default:
      return 'none';
  }
}
