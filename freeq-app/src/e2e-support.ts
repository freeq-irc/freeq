/**
 * Test-only re-exports, so an end-to-end spec can drive a second, fully
 * authenticated client from inside the browser, and read what the app's own
 * store holds.
 *
 * A spec's `page.evaluate` body is never seen by the bundler, so it cannot
 * resolve a bare specifier like `@freeq/sdk` for itself — it can only import
 * paths the dev server already serves. This module is such a path. Nothing in
 * the app imports it, so it never reaches a production bundle.
 */
import { useStore } from './store';

export { FreeqClient, generateDidKey } from '@freeq/sdk';

/**
 * How many message rows the store holds for `channel` right now.
 *
 * A spec that counts mounted DOM rows counts what is on screen, which under a
 * virtualized list is a window rather than the held list. This reads the held
 * list itself. It answers correctly only if this module and the app share one
 * `store` instance — which is what `e2e/store-count.spec.ts` proves.
 */
export function heldRowCount(channel: string): number {
  const s = useStore.getState();
  if (channel.toLowerCase() === 'server') return s.serverMessages.length;
  return s.channels.get(channel.toLowerCase())?.messages.length ?? 0;
}
