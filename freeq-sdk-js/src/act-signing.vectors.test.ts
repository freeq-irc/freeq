/**
 * The act canonical, checked against the same fixtures the Rust SDK and
 * bot-kit replay. This is a third implementation of those bytes; without this
 * it could drift and start producing signatures the server calls forgeries.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { actCanonical } from './signing';

interface Vector {
  name: string;
  tags: Record<string, string>;
  target: string;
  msgid: string;
  canonical: string;
}

const spec = JSON.parse(
  readFileSync(join(__dirname, '../../spec/act-signing-vectors.json'), 'utf8'),
) as { vectors: Vector[]; negatives: { vector: string; target: string; msgid: string; tamperedCanonical: string }[] };

describe('act canonical', () => {
  for (const v of spec.vectors) {
    it(`reproduces the canonical bytes of ${v.name}`, () => {
      expect(actCanonical(v.tags, v.target, v.msgid)).toBe(v.canonical);
    });
  }

  for (const n of spec.negatives) {
    it(`rebuilds ${n.vector} under other delivery context: ${n.tamperedCanonical.length} bytes`, () => {
      const v = spec.vectors.find((x) => x.name === n.vector)!;
      expect(actCanonical(v.tags, n.target, n.msgid)).toBe(n.tamperedCanonical);
    });
  }

  it('is null when nothing on the message is a task tag', () => {
    expect(actCanonical({ msgid: '01J', account: 'did:plc:x' }, '#c', '01J')).toBeNull();
  });
});
