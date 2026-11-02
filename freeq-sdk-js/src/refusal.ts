/**
 * What a `FAIL` line says about this client being let in, by the table the
 * Rust SDK's `freeq_sdk::refusal::classify` uses and `spec/sasl-refusals.json`
 * lists:
 *
 * - `FAIL MSGSIG KEY_EXPIRED` or `KEY_RETIRED`: the server refused this
 *   device's signing key;
 * - `FAIL AUTHENTICATE` or `FAIL *` with `TEMPORARILY_UNAVAILABLE`: the server
 *   could not check the client just now, so the same credentials may get in
 *   later;
 * - `FAIL AUTHENTICATE` or `FAIL *` with any other code: final, the same
 *   credentials will never get in;
 * - any other `FAIL`: not a refusal.
 *
 * `reason` is the line's last parameter, the server's sentence.
 */
export type Refusal =
  | { kind: 'signingKey'; reason: string }
  | { kind: 'tryAgain'; reason: string }
  | { kind: 'final'; reason: string };

export const TEMPORARILY_UNAVAILABLE = 'TEMPORARILY_UNAVAILABLE';
export const KEY_EXPIRED = 'KEY_EXPIRED';
export const KEY_RETIRED = 'KEY_RETIRED';

export function refusalOf(params: readonly string[]): Refusal | null {
  const [command, code] = params;
  if (command === undefined || code === undefined) return null;
  const reason = params.length > 2 ? params[params.length - 1] : '';
  if (command === 'MSGSIG') {
    return code === KEY_EXPIRED || code === KEY_RETIRED ? { kind: 'signingKey', reason } : null;
  }
  if (command !== 'AUTHENTICATE' && command !== '*') return null;
  return code === TEMPORARILY_UNAVAILABLE ? { kind: 'tryAgain', reason } : { kind: 'final', reason };
}
