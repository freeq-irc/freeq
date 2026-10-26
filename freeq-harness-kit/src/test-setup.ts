/**
 * The test floor for every package whose tests build a runtime from this kit:
 * `HOME` points at a scratch directory and `globalThis.fetch` is a fake, both
 * before a test file's imports run.
 *
 * Loaded through `setupFiles`, which is the only place that beats those
 * imports and that a new test file cannot forget. Without it the default is
 * the developer's real `~/.freeq` and the real network, so a file that forgets
 * to stub reaches both: `freeq-cc/test/channel.test.ts` and
 * `permission.test.ts` forgot `fetch` and `runtime.test.ts` forgot `HOME`.
 *
 * Both globals stay overridable — the same rule as `freeq-app/src/test-setup.ts`
 * — so a suite that installs its own `vi.stubGlobal("fetch", …)` over the floor
 * still does, and lands back on the floor when it unstubs.
 *
 * Requests to loopback are passed through to the real `fetch`, because a test
 * about HTTP itself binds a real server on `127.0.0.1` and reaches it for real
 * (`verify.test.ts:209-221`, `freeq-fabro/src/relay.test.ts:26-29`). A floor
 * that swallowed loopback would break exactly those tests.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A stand-in for the server's HTTP API: `/api/v1/actions`, key lookups. */
export type FetchHandler = (url: string) => { status: number; body?: unknown } | Error;

/** Default: nothing assigned to us, and no key on record for anyone. */
export const defaultFetch: FetchHandler = (url) =>
  url.includes("/api/v1/actions") ? { status: 200, body: { tasks: [] } } : { status: 404 };

/**
 * The scratch `HOME`. Tests that name a path under it — the state directory a
 * delegation or an identity lands in — read it from here.
 */
export const TEST_HOME = mkdtempSync(join(tmpdir(), "freeq-test-home-"));
process.env.HOME = TEST_HOME;

/** The floor's answers, and what it was asked, for a test to read or replace. */
export const state: { fetch: FetchHandler; fetched: string[] } = {
  fetch: defaultFetch,
  fetched: [],
};

/** Whether a URL names this machine, and so is a real server under test. */
function isLoopback(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return host === "localhost" || host === "::1" || host === "[::1]" || /^127\./.test(host);
  } catch {
    return false;
  }
}

const realFetch = globalThis.fetch;

globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
  const url = String(input);
  state.fetched.push(url);
  if (isLoopback(url)) return realFetch(input, init);
  const r = state.fetch(url);
  if (r instanceof Error) throw r;
  return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status });
}) as typeof fetch;
