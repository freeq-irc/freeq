/**
 * What a verification answer is allowed to claim, given what actually happened.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  verifySignature,
  cachedVerdict,
  subscribeVerdicts,
  __resetVerifyCacheForTests,
  VERIFY_LABELS,
  CHECKING_COPY,
  unsignedCopy,
  verdictCopy,
  type VerifyOutcome,
} from './verify-signature';

/** Answer the verify endpoint with `body`, or fail the request. */
function serverSays(body: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
  });
}

beforeEach(() => {
  __resetVerifyCacheForTests();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('reading the server verdict', () => {
  const cases: Array<[string, unknown, VerifyOutcome]> = [
    [
      'a signature the sender made on their own device',
      { verification: { verdict: 'valid', verified_by: 'client-session-key' } },
      'device',
    ],
    [
      'a signature the server made on the sender’s behalf',
      { verification: { verdict: 'valid', verified_by: 'server-key' } },
      'server',
    ],
    [
      'a signature that does not match the key it names',
      { verification: { verdict: 'invalid', verified_by: 'client-session-key' } },
      'invalid',
    ],
    [
      'a signature nobody here can check',
      { verification: { verdict: 'unverifiable' } },
      'unverifiable',
    ],
    ['a verdict this client has never heard of', { verification: { verdict: 'shrug' } }, 'unverifiable'],
    ['an answer with no verification at all', {}, 'unverifiable'],
  ];

  for (const [name, body, expected] of cases) {
    it(`${name} reads as ${expected}`, async () => {
      vi.stubGlobal('fetch', serverSays(body));
      expect((await verifySignature('01MSG')).outcome).toBe(expected);
    });
  }

  it('reads the older boolean from a server that predates the three-way verdict', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { valid: true, verified_by: 'client-session-key' } }));
    expect((await verifySignature('01MSG')).outcome).toBe('device');

    __resetVerifyCacheForTests();
    vi.stubGlobal('fetch', serverSays({ verification: { valid: false } }));
    expect(
      (await verifySignature('01MSG')).outcome,
      'an old server saying "not valid" is not the same as saying "forged"',
    ).toBe('unverifiable');
  });

  it('treats no record on file as unverifiable, not as an accusation', async () => {
    vi.stubGlobal('fetch', serverSays({ error: 'not found' }, false, 404));
    expect((await verifySignature('01MSG')).outcome).toBe('unverifiable');
  });
});

describe('a check that never happened is not a verdict', () => {
  it('a network failure reads as unreachable, and is not remembered', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    expect((await verifySignature('01MSG')).outcome).toBe('unreachable');
    expect(
      cachedVerdict('01MSG'),
      'a failed check must be retryable, so it is not remembered',
    ).toBeUndefined();
  });

  it('a server (or proxy) error reads as unreachable, not as "could not be checked"', async () => {
    // The observed failure this pins: a broken dev proxy answered every
    // verify with an empty 500, and provably-valid messages were shown as
    // "could not be checked here" — a transport fault dressed as a verdict.
    vi.stubGlobal('fetch', serverSays(undefined, false, 500));
    expect((await verifySignature('01MSG')).outcome).toBe('unreachable');
    expect(cachedVerdict('01MSG')).toBeUndefined();
  });
});

describe('what is already on file', () => {
  it('remembers a definitive answer instead of asking again', async () => {
    const fetchMock = serverSays({ verification: { verdict: 'valid', verified_by: 'client-session-key' } });
    vi.stubGlobal('fetch', fetchMock);
    expect((await verifySignature('01MSG')).outcome).toBe('device');
    expect((await verifySignature('01MSG')).outcome).toBe('device');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(cachedVerdict('01MSG')?.outcome).toBe('device');
  });

  it('knows nothing about a message it has not checked', () => {
    expect(cachedVerdict('01NEVER-CHECKED')).toBeUndefined();
  });

  it('remembers a bad verdict too, so no other row can show it as good', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { verdict: 'invalid' } }));
    expect((await verifySignature('01BAD')).outcome).toBe('invalid');
    expect(cachedVerdict('01BAD')?.outcome).toBe('invalid');
  });

  it('tells subscribers when a verdict lands, so a row can wear the ⚠', async () => {
    const seen = vi.fn();
    const unsubscribe = subscribeVerdicts(seen);
    vi.stubGlobal('fetch', serverSays({ verification: { verdict: 'invalid' } }));
    await verifySignature('01BAD');
    expect(seen).toHaveBeenCalled();
    unsubscribe();
  });
});

describe('the one retryable flavour of can’t-check', () => {
  it('a key the server hasn’t fetched yet is transient and not cached', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { verdict: 'unverifiable', verified_by: 'unverifiable-unknown-key' } }));
    const a = await verifySignature('01FED');
    expect(a.outcome).toBe('unverifiable');
    expect(a.transient, 'answering is what starts the key fetch — worth re-asking').toBe(true);
    expect(cachedVerdict('01FED'), 'a transient answer must stay retryable').toBeUndefined();
  });

  it('every other flavour of can’t-check is final and cached', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { verdict: 'unverifiable', verified_by: 'unverifiable-legacy-format' } }));
    const a = await verifySignature('01OLD');
    expect(a.transient).toBe(false);
    expect(cachedVerdict('01OLD')?.outcome).toBe('unverifiable');
  });
});

describe('valid is not verified (ruled 2026-08-07)', () => {
  it('sender proof wears green; a server vouch stays quiet and never claims "Verified"', () => {
    expect(VERIFY_LABELS.device.tone).toBe('text-success');
    expect(VERIFY_LABELS.device.heading).toBe('Verified');
    expect(VERIFY_LABELS.server.tone).toBe('text-fg-muted');
    expect(VERIFY_LABELS.server.heading).not.toMatch(/Verified/);
    // The distinction the reader has to come away with: the server stands
    // behind it, the sender did not sign it.
    expect(VERIFY_LABELS.server.line).toMatch(/didn’t sign it themselves/);
  });

  it('only the sender-proof answer wears green, and only a mismatch wears red', () => {
    const tones = Object.fromEntries(
      Object.entries(VERIFY_LABELS).map(([k, v]) => [k, v.tone]),
    );
    expect(tones).toEqual({
      device: 'text-success',
      server: 'text-fg-muted',
      unverifiable: 'text-fg-muted',
      invalid: 'text-danger',
      unreachable: 'text-fg-muted',
    });
    expect(unsignedCopy().tone).toBe('text-fg-muted');
    expect(CHECKING_COPY.tone).toBe('text-fg-muted');
  });

  it('every answer says what it is and what it means, in two parts', () => {
    const all = [...Object.values(VERIFY_LABELS), unsignedCopy(), unsignedCopy('event'), CHECKING_COPY];
    for (const c of all) {
      expect(c.heading.length).toBeGreaterThan(0);
      expect(c.line.length).toBeGreaterThan(0);
      // The heading is the answer, not a restatement of the line.
      expect(c.line).not.toBe(c.heading);
    }
  });
});

describe('an answer names what the id actually points at', () => {
  it('the two lines that say "message" say "event" over a coordination event', () => {
    expect(verdictCopy('unverifiable', 'event').line).toContain('older event');
    expect(verdictCopy('invalid', 'event').line).toMatch(/^This event is signed/);
    expect(unsignedCopy('event').line).toContain('before event signing');
  });

  it('the noun-neutral answers are the same object either way', () => {
    for (const o of ['device', 'server', 'unreachable'] as VerifyOutcome[]) {
      expect(verdictCopy(o, 'event')).toBe(verdictCopy(o, 'message'));
    }
  });

  it('a message reads as a message', () => {
    expect(verdictCopy('unverifiable').line).toContain('older message');
    expect(verdictCopy('invalid').line).toMatch(/^This message is signed/);
  });
});
