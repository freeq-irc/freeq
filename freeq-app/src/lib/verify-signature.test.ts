/**
 * What the badge is allowed to claim, given what the server answered.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  verifySignature,
  cachedVerdict,
  __resetVerifyCacheForTests,
  type VerifyOutcome,
} from './verify-signature';

/** Answer the verify endpoint with `body`, or fail the request. */
function serverSays(body: unknown, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
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
      expect(await verifySignature('01MSG')).toBe(expected);
    });
  }

  it('reads the older boolean from a server that predates the three-way verdict', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { valid: true, verified_by: 'client-session-key' } }));
    expect(await verifySignature('01MSG')).toBe('device');

    __resetVerifyCacheForTests();
    vi.stubGlobal('fetch', serverSays({ verification: { valid: false } }));
    expect(
      await verifySignature('01MSG'),
      'an old server saying "not valid" is not the same as saying "forged"',
    ).toBe('unverifiable');
  });

  it('treats no record on file as unverifiable, not as an accusation', async () => {
    vi.stubGlobal('fetch', serverSays({ error: 'not found' }, false));
    expect(await verifySignature('01MSG')).toBe('unverifiable');
  });

  it('says nothing about the signature when the network fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    expect(await verifySignature('01MSG')).toBe('unverifiable');
    expect(
      cachedVerdict('01MSG'),
      'a transient failure must be retryable, so it is not remembered',
    ).toBeUndefined();
  });
});

describe('what a badge already knows', () => {
  it('remembers a definitive answer instead of asking again', async () => {
    const fetchMock = serverSays({ verification: { verdict: 'valid', verified_by: 'client-session-key' } });
    vi.stubGlobal('fetch', fetchMock);
    expect(await verifySignature('01MSG')).toBe('device');
    expect(await verifySignature('01MSG')).toBe('device');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(cachedVerdict('01MSG')).toBe('device');
  });

  it('knows nothing about a message it has not checked', () => {
    expect(cachedVerdict('01NEVER-CHECKED')).toBeUndefined();
  });

  it('remembers a bad verdict too, so no other row can show it as good', async () => {
    vi.stubGlobal('fetch', serverSays({ verification: { verdict: 'invalid' } }));
    expect(await verifySignature('01BAD')).toBe('invalid');
    expect(cachedVerdict('01BAD')).toBe('invalid');
  });
});
