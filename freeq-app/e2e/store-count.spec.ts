/**
 * The precondition for every spec that counts held rows rather than mounted
 * ones: `heldRowCount` has to read the store the app is actually using.
 *
 * A spec's dynamic `import('/src/e2e-support.ts')` is resolved by the dev
 * server, not by the bundle the page loaded. If that yielded a second copy of
 * the store module, the count would come back as a permanent zero while the
 * app's own list grew — a mechanism that silently agrees with any assertion
 * about a shrinking window. So: send a known number of messages, then require
 * the store to have them.
 */
import { test, expect } from '@playwright/test';
import { connectGuest, sendMessage, uniqueNick, uniqueChannel } from './helpers';

function heldRows(page: import('@playwright/test').Page, channel: string): Promise<number> {
  return page.evaluate(async (ch) => {
    const mod = await import('/src/e2e-support.ts');
    return mod.heldRowCount(ch);
  }, channel);
}

test.describe('the store-count surface', () => {
  test('counts the rows the app itself is holding', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick('cnt'), channel);

    const before = await heldRows(page, channel);

    await sendMessage(page, 'one');
    await sendMessage(page, 'two');
    await sendMessage(page, 'three');

    await expect.poll(() => heldRows(page, channel), { timeout: 10_000 })
      .toBeGreaterThanOrEqual(before + 3);

    // A second module instance would answer zero however much was sent, and
    // would also disagree with the rows on screen. Both have to hold.
    const held = await heldRows(page, channel);
    expect(held).toBeGreaterThan(0);
    const mounted = await page.getByTestId('message-list')
      .evaluate((el) => el.querySelectorAll('[id^="msg-"]').length);
    expect(mounted).toBeGreaterThan(0);
    expect(held).toBeGreaterThanOrEqual(mounted);

    // An unknown channel is zero, so a nonzero answer above cannot be a
    // constant the surface returns whatever it is asked.
    expect(await heldRows(page, '#no-such-channel-here')).toBe(0);
  });
});
