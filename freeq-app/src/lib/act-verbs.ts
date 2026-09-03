/**
 * The word and glyph each task verb shows a reader.
 *
 * The headline of a card is the word for the verb its event carried — the
 * verb is on the wire and the client computes nothing from it, so a progress
 * report never reads as a claim. The rows live in `spec/act-card-copy.json`
 * (this file bundles a byte-pinned copy) so the four clients cannot drift; a
 * verb with no row shows itself, with the fallback glyph, which is how a kind
 * may add a move without any client being taught it.
 */
import copySpec from './act-card-copy.json';

const VERBS: Record<string, { word: string; glyph: string }> = copySpec.verbs;
const FALLBACK_GLYPH: string = copySpec.fallback_glyph;

export function actHeadline(verb: string): string {
  return VERBS[verb]?.word ?? verb;
}

export function actEmoji(verb: string): string {
  return VERBS[verb]?.glyph ?? FALLBACK_GLYPH;
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
