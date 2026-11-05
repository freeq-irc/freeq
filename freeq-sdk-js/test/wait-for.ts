/**
 * Wait for something the test can observe, instead of for a fixed number of
 * milliseconds.
 *
 * The client's send path goes through Web Crypto, which resolves off the
 * macrotask queue: a signature or an AES-GCM pass takes as long as the
 * machine takes. A test that spends a fixed flush budget and then reads the
 * wire passes on a quiet box and fails on a loaded CI runner, where the
 * timers tick on the wall clock while the work waits for a thread. So a test
 * that asserts on what the client produced waits for that value to appear,
 * returns the moment it is there, and says what never arrived when it is not.
 *
 * Built on `vi.waitFor`, which is already how this package waits for a
 * condition (`src/client.test.ts`, `src/e2ee.identity.test.ts`): it checks
 * once synchronously, then polls until the deadline. The predicate throws to
 * say "not yet", because `vi.waitFor` accepts any returned value — including
 * `undefined` — as success.
 */
import { vi } from 'vitest';

/**
 * The ceiling, matching the longest wait this package already allows
 * (`src/client.verdict.test.ts`'s `until`: 400 turns of 5 ms). It is a
 * backstop for a slow runner, not a budget: a condition already met returns
 * at once, and it stays under vitest's 5 s test timeout so the failure is
 * this helper's message rather than a timed-out test.
 */
const CEILING_MS = 2_000;

/**
 * Resolve with the first truthy value `ready()` returns, or fail naming
 * `what` never arrived.
 *
 * `what` completes the sentence "waited for …", e.g.
 * `'the BATCH opener on the wire'`.
 *
 * `ready` must be synchronous: a promise is truthy, so an `async` predicate
 * would satisfy the wait on its first call.
 */
export async function waitFor<T>(
  what: string,
  ready: () => T | undefined | null | false,
): Promise<T> {
  return vi.waitFor(
    () => {
      const value = ready();
      if (value === undefined || value === null || value === false) {
        throw new Error(`waited ${CEILING_MS}ms for ${what}, which never arrived`);
      }
      return value;
    },
    { timeout: CEILING_MS, interval: 5 },
  );
}
