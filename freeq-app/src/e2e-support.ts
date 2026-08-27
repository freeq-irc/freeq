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

/** The msgid of the newest row the store holds for `channel`, or null.
 *
 *  The newest row is not always mounted — a reader scrolled back is looking
 *  at rows a long way from it — so a spec cannot read it off the last
 *  `msg-` node in the document. */
export function newestHeldMsgId(channel: string): string | null {
  const s = useStore.getState();
  const rows = channel.toLowerCase() === 'server'
    ? s.serverMessages
    : (s.channels.get(channel.toLowerCase())?.messages ?? []);
  return rows.length > 0 ? rows[rows.length - 1].id : null;
}

/** The msgid of the oldest row the store holds for `channel`, or null. */
export function oldestHeldMsgId(channel: string): string | null {
  const s = useStore.getState();
  const rows = channel.toLowerCase() === 'server'
    ? s.serverMessages
    : (s.channels.get(channel.toLowerCase())?.messages ?? []);
  return rows.length > 0 ? rows[0].id : null;
}

/** Ask the message list to go to `msgid`, the way a search result or a reply
 *  reference does. */
export function jumpToMessage(msgid: string): void {
  useStore.getState().setScrollToMsgId(msgid);
}
