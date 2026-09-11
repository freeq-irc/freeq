/**
 * What a client shows for a message's signature, and the words for it.
 *
 * The words come from `spec/verdict-model.json`, which both SDKs read. The
 * copy imported here (`./verdict-model.json`) exists only because this
 * package's build root cannot reach outside `src/`; a test pins it
 * byte-identical to the spec file. Twin of the Rust `freeq_sdk::verdict`.
 */

// Node's ESM loader needs the type attribute on a JSON import (see
// identity-claim.ts).
import model from './verdict-model.json' with { type: 'json' };
import type { KeySource } from './key-lookup.js';

/** What checking a message's signature came to. */
export type VerdictState =
  | 'device'
  | 'server'
  | 'unsigned'
  | 'unverifiable'
  | 'invalid'
  | 'retired'
  | 'pending';

/** Where a device key's standing comes from. */
export type KeyLayer = 'vouched' | 'published';

export const VERDICT_STATES: readonly VerdictState[] = [
  'device',
  'server',
  'unsigned',
  'unverifiable',
  'invalid',
  'retired',
  'pending',
];

export const KEY_LAYERS: readonly KeyLayer[] = ['vouched', 'published'];

/** A message's verdict: the state, the layer for a device signature, and
 *  the key the check used. */
export interface Verdict {
  state: VerdictState;
  layer?: KeyLayer;
  kid?: string;
  keySource?: KeySource;
}

/** The word on the mark. */
export function mark(): string {
  return model.mark;
}

/** The sentence for a verdict. A layer counts only for `device`. */
export function sentence(state: VerdictState, layer?: KeyLayer): string {
  if (state === 'device' && layer) return model.layers[layer];
  return model.states[state].sentence;
}
