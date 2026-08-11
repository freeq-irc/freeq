/**
 * Test-only re-exports, so an end-to-end spec can drive a second, fully
 * authenticated client from inside the browser.
 *
 * A spec's `page.evaluate` body is never seen by the bundler, so it cannot
 * resolve a bare specifier like `@freeq/sdk` for itself — it can only import
 * paths the dev server already serves. This module is such a path. Nothing in
 * the app imports it, so it never reaches a production bundle.
 */
export { FreeqClient, generateDidKey } from '@freeq/sdk';
