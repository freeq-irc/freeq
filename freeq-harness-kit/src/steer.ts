/**
 * Steering the agent's chattiness from the room, in plain words.
 *
 * "be more verbose" typed into freeq should do what `/freeq verbosity` does
 * in the terminal. The parser is deliberately narrow: it must be *about*
 * verbosity, not merely contain "more" or "less" - "tell me more about the
 * parser" is a question, and turning it into a settings change would be the
 * kind of bug that makes people stop trusting the agent with anything.
 *
 * Two kinds of phrase: ones that name the topic (verbose, quiet, chatty…)
 * and need a direction; and a short list of idioms that are unambiguous on
 * their own ("tone it down", "stop posting here").
 *
 * The caller gates on the owner's server-resolved DID before calling this.
 */

import type { ProvenanceTier } from "./provenance.js";

export function parseVerbositySteer(text: string): ProvenanceTier | undefined {
  const t = text.toLowerCase().trim();

  // Idioms that are instructions on their own.
  if (/\b(tone it down|dial it (back|down)|keep it down)\b/.test(t)) return "decisions";
  if (/\b(stop (mirroring|narrating|posting)( your work| here| in here)?|say nothing (here|in here)|go silent|be silent)\b/.test(t)) {
    return "silent";
  }
  if (/\b(narrate (everything|what you'?re doing|as you go)|show your work|think out loud)\b/.test(t)) {
    return "firehose";
  }

  // Otherwise the sentence must be about the topic, and carry a direction.
  const onTopic = /\b(verbos\w*|quiet\w*|chatt\w*|nois\w*|talkative|terse|firehose|loud\w*)\b/.test(t);
  if (!onTopic) return undefined;
  // A question about the setting is not a change to it.
  if (/^(what|how|why|does|is|are|do)\b/.test(t) && t.endsWith("?")) return undefined;

  if (/\b(firehose|max(imum)? verbos\w*|as verbose as)\b/.test(t)) return "firehose";
  if (/\b(more verbose|be verbose|verbose please|chattier|noisier|more chatty|more talkative|louder)\b/.test(t)) return "firehose";
  if (/\b(less verbose|quieter|quiet(er)? down|be quiet|terse|less chatty|less noisy|less talkative)\b/.test(t)) return "decisions";
  if (/\b(normal|default|usual|regular) verbos\w*\b/.test(t)) return "evidence";
  return undefined;
}
