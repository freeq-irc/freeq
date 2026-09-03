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
  // The three the home signs for itself. They write no companion line, so
  // these words are read on a system line rather than on a card.
  confirm: 'confirmed',
  expire: 'expired',
  'auto-accept': 'accepted (review window closed)',
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
  // The three the home signs for itself. They write no companion line, so
  // they carry their glyph on a system line rather than on a card.
  confirm: '✔️',
  expire: '⌛',
  'auto-accept': '⏱️',
};

export function actEmoji(verb: string): string {
  return EMOJI[verb] ?? '📌';
}

/**
 * The register a card wears: the state the step it carries lands the action
 * in, as a role rather than a colour — each client paints the role in its own
 * theme.
 *
 * Read off `spec/act-transitions.json`: the `to` of the row the verb matched,
 * except that a step landing where it started is in-progress whatever state
 * that is. A row whose `who` is `system` writes no card and so has no
 * register; a verb with no row at all falls to the neutral end.
 */
export type ActRegister = 'new' | 'inProgress' | 'endedWell' | 'didNotEndWell' | 'neutralEnd';

const REGISTER: Record<string, ActRegister | null> = {
  // lands open / offered
  offer: 'new',
  // lands assigned / under_review, and the two additive steps
  accept: 'inProgress',
  claim: 'inProgress',
  award: 'inProgress',
  submit: 'inProgress',
  revise: 'inProgress',
  progress: 'inProgress',
  bid: 'inProgress',
  // lands completed / accepted
  complete: 'endedWell',
  'accept-work': 'endedWell',
  // lands failed / forfeited / cancelled / declined
  fail: 'didNotEndWell',
  forfeit: 'didNotEndWell',
  cancel: 'didNotEndWell',
  decline: 'didNotEndWell',
  // The rows a home signs for itself. No card, so no register.
  confirm: null,
  expire: null,
  'auto-accept': null,
};

export function actRegister(verb: string): ActRegister | null {
  const r = REGISTER[verb];
  return r === undefined ? 'neutralEnd' : r;
}

/**
 * Who the rules file lets take this step — the `who` of the row the verb
 * matched, and the key the seal panel picks its sentence by.
 *
 * An opening verb has no transition row of its own and reports `opener`. A
 * system row and an unteached verb report nothing, because neither has a rule
 * about a person to state.
 */
export type ActWhoRole = 'opener' | 'offeree' | 'assignee' | 'offerer' | 'anyone';

const WHO: Record<string, ActWhoRole | null> = {
  offer: 'opener',
  accept: 'offeree',
  decline: 'offeree',
  claim: 'anyone',
  bid: 'anyone',
  progress: 'assignee',
  complete: 'assignee',
  fail: 'assignee',
  submit: 'assignee',
  forfeit: 'assignee',
  cancel: 'offerer',
  award: 'offerer',
  revise: 'offerer',
  'accept-work': 'offerer',
  confirm: null,
  expire: null,
  'auto-accept': null,
};

export function actWhoRole(verb: string): ActWhoRole | null {
  return WHO[verb] ?? null;
}
