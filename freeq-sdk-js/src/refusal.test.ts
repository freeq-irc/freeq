import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { refusalOf } from './refusal.js';

const vector = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../spec/sasl-refusals.json'), 'utf8'),
) as { codes: Array<{ command: string; code: string; kind: string }> };

describe('refusalOf', () => {
  it('classifies every code in the shared vector as its kind', () => {
    expect(vector.codes.length).toBeGreaterThan(0);
    const kinds: Record<string, string> = { try_again: 'tryAgain', final: 'final', signing_key: 'signingKey' };
    for (const { command, code, kind } of vector.codes) {
      expect(refusalOf([command, code, 'the words']), `FAIL ${command} ${code}`).toEqual({
        kind: kinds[kind],
        reason: 'the words',
      });
    }
  });

  it('is not a refusal for any other FAIL', () => {
    expect(refusalOf(['CHATHISTORY', 'INVALID_TARGET', '#x', 'no such channel'])).toBeNull();
    expect(refusalOf(['MSGSIG', 'SIGNATURE_INVALID', 'bad'])).toBeNull();
    expect(refusalOf(['AUTHENTICATE'])).toBeNull();
  });

  it('takes the last parameter as the sentence', () => {
    expect(refusalOf(['*', 'AGENT_REVOKED', 'ctx', 'Revoked by an operator.'])).toEqual({
      kind: 'final',
      reason: 'Revoked by an operator.',
    });
    expect(refusalOf(['AUTHENTICATE', 'NOT_ALLOWED'])).toEqual({ kind: 'final', reason: '' });
  });
});
