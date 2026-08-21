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
  id: string;
  canonical: string;
}

interface Negative {
  vector: string;
  target: string;
  id: string;
  tamperedCanonical?: string;
  strippedTag?: string;
  swappedTag?: { name: string; value: string };
}

const spec = JSON.parse(
  readFileSync(join(__dirname, '../../spec/act-signing-vectors.json'), 'utf8'),
) as { vectors: Vector[]; negatives: Negative[] };

/** The vector's tags as a negative presents them to a verifier. */
function tagsFor(n: Negative, v: Vector): Record<string, string> {
  const tags = { ...v.tags };
  if (n.strippedTag !== undefined) delete tags[n.strippedTag];
  if (n.swappedTag !== undefined) tags[n.swappedTag.name] = n.swappedTag.value;
  return tags;
}

describe('act canonical', () => {
  for (const v of spec.vectors) {
    it(`reproduces the canonical bytes of ${v.name}`, () => {
      expect(actCanonical(v.tags, v.target, v.id)).toBe(v.canonical);
    });
  }

  // Unverifiable-class negatives (a stripped mandatory tag, an unknown
  // algorithm) have no canonical to rebuild; this suite has no verifier, so
  // only the tamper-class negatives are byte-checked here.
  for (const n of spec.negatives.filter((x) => x.tamperedCanonical !== undefined)) {
    it(`rebuilds tampered ${n.vector}: ${n.tamperedCanonical!.length} bytes`, () => {
      const v = spec.vectors.find((x) => x.name === n.vector)!;
      expect(actCanonical(tagsFor(n, v), n.target, n.id)).toBe(n.tamperedCanonical);
    });
  }

  it('an empty id or venue builds no document (mandatory fields)', () => {
    const v = spec.vectors[0];
    expect(actCanonical(v.tags, v.target, '')).toBeNull();
    expect(actCanonical(v.tags, '', v.id)).toBeNull();
  });

  it('act tags without a from tag build no document (missing mandatory field)', () => {
    const v = spec.vectors[0];
    const tags = { ...v.tags };
    delete tags['+freeq.at/from'];
    expect(actCanonical(tags, v.target, v.id)).toBeNull();
  });

  it('is null when nothing on the message is a task tag', () => {
    expect(actCanonical({ msgid: '01J', account: 'did:plc:x' }, '#c', '01J')).toBeNull();
  });
});
