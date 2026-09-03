/**
 * The seal panel's words, read from the bundled copy of `spec/act-card-copy.json`.
 *
 * The prose is not written here and is not written in the other three clients
 * either: all four read the same file so a sentence cannot drift between them.
 * The copy in this directory exists only because the build root cannot reach
 * outside `src/`, and a test pins it byte-identical to the canonical file.
 */
import copy from './act-card-copy.json';
import { actWhoRole } from './act-verbs';

const panel = copy.seal_panel as {
  header_format: string;
  link_text: string;
  sentences: Record<string, string>;
};

/** `HANDOFF: Rules Enforced` — the kind comes off the event's own act tag. */
export function sealPanelHeader(kind: string): string {
  return panel.header_format.replace('<KIND>', kind.toUpperCase());
}

export function sealPanelLinkText(): string {
  return panel.link_text;
}

/**
 * What the server enforced on this step, in one sentence.
 *
 * Chosen off the `who` of the transition row the verb matched — never off the
 * verb's name and never off the kind. A system row and a verb with no row at
 * all claim nothing, so neither gets a sentence.
 */
export function sealPanelSentence(verb: string): string | undefined {
  const role = actWhoRole(verb);
  return role ? panel.sentences[role] : undefined;
}
