/**
 * What a verdict is allowed to claim, and the words each one wears.
 *
 * The check itself is the SDK's and is covered by its own vectors; what this
 * pins is the app's side: the verdict a row and the panel read, and the copy
 * shown for it.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { sentence } from '@freeq/sdk';
import {
  cachedVerdict,
  copyForVerdict,
  recordVerdict,
  subscribeVerdicts,
  unsignedCopy,
  verdictCopy,
  CHECKING_COPY,
  __resetVerifyCacheForTests,
  type VerifyOutcome,
} from './verify-signature';

const STATES: VerifyOutcome[] = [
  'device',
  'server',
  'unsigned',
  'unverifiable',
  'invalid',
  'retired',
  'pending',
];

beforeEach(() => {
  __resetVerifyCacheForTests();
});

describe('the verdict a row and the panel read', () => {
  it('is the one the SDK gave for that message', () => {
    expect(cachedVerdict('01MSG')).toBeUndefined();
    recordVerdict('01MSG', { state: 'device', layer: 'published', kid: 'k1' });
    expect(cachedVerdict('01MSG')).toEqual({ state: 'device', layer: 'published', kid: 'k1' });
  });

  it('is replaced when a pending one settles, and tells subscribers', () => {
    let told = 0;
    const stop = subscribeVerdicts(() => told++);
    recordVerdict('01MSG', { state: 'pending', kid: 'k1' });
    expect(told).toBe(1);
    recordVerdict('01MSG', { state: 'device', layer: 'vouched', kid: 'k1' });
    expect(told).toBe(2);
    expect(cachedVerdict('01MSG')?.state).toBe('device');
    // The same answer again is not news.
    recordVerdict('01MSG', { state: 'device', layer: 'vouched', kid: 'k1' });
    expect(told).toBe(2);
    stop();
  });

  it('ignores a line with no id and a message with no verdict', () => {
    recordVerdict('', { state: 'device' });
    recordVerdict('01MSG', undefined);
    expect(cachedVerdict('01MSG')).toBeUndefined();
  });
});

describe('the words for a verdict', () => {
  it('are the SDK sentences, for every state', () => {
    for (const state of STATES) {
      expect(verdictCopy(state).line).toBe(sentence(state));
    }
    expect(copyForVerdict({ state: 'device', layer: 'published' }).line).toBe(
      sentence('device', 'published'),
    );
    expect(copyForVerdict({ state: 'device', layer: 'vouched' }).line).toBe(
      sentence('device', 'vouched'),
    );
  });

  it('say what the answer is and what it means, in two parts', () => {
    for (const state of STATES) {
      const copy = verdictCopy(state);
      expect(copy.heading.length, state).toBeGreaterThan(0);
      expect(copy.line.length, state).toBeGreaterThan(0);
      expect(copy.heading, state).not.toBe(copy.line);
    }
  });

  it('wear green only for sender proof, and red only where the check failed', () => {
    // Ruled 2026-08-07: valid is not verified. A server signature is the
    // server vouching for what it received, so it stays quiet.
    expect(verdictCopy('device').tone).toBe('text-success');
    expect(verdictCopy('device').heading).toBe('Signed');
    expect(verdictCopy('server').tone).toBe('text-fg-muted');
    expect(verdictCopy('server').heading).not.toBe('Signed');
    for (const state of ['invalid', 'retired'] as VerifyOutcome[]) {
      expect(verdictCopy(state).tone, state).toBe('text-danger');
    }
    for (const state of ['unsigned', 'unverifiable', 'pending'] as VerifyOutcome[]) {
      expect(verdictCopy(state).tone, state).toBe('text-fg-muted');
    }
  });

  it('word the three answers that name what was signed for an event', () => {
    for (const state of ['unsigned', 'unverifiable', 'invalid'] as VerifyOutcome[]) {
      expect(verdictCopy(state, 'event').line, state).not.toBe(verdictCopy(state).line);
      expect(verdictCopy(state, 'event').line, state).toContain('event');
    }
    // The rest read the same either way.
    for (const state of ['device', 'server', 'retired', 'pending'] as VerifyOutcome[]) {
      expect(verdictCopy(state, 'event'), state).toEqual(verdictCopy(state));
    }
  });

  it('say nothing was signed, rather than that a check failed', () => {
    expect(unsignedCopy()).toEqual(verdictCopy('unsigned'));
    expect(unsignedCopy('event')).toEqual(verdictCopy('unsigned', 'event'));
  });

  it('say the key is still being looked up while it is', () => {
    expect(CHECKING_COPY).toEqual(verdictCopy('pending'));
    expect(CHECKING_COPY.line).toBe(sentence('pending'));
  });
});
