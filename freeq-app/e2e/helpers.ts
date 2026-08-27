/**
 * Shared helpers for freeq E2E tests.
 */
import { Page, expect, BrowserContext, Browser } from '@playwright/test';

const TS = Date.now().toString(36);
let counter = 0;

/** Generate a unique nick for each test user */
export function uniqueNick(prefix = 'pw'): string {
  return `${prefix}${TS}${counter++}`;
}

/** Generate a unique channel name */
export function uniqueChannel(): string {
  return `#pw-${TS}-${counter++}`;
}

/** Start a call with a bare av-start TAGMSG.
 *
 * `+freeq.at/av-instance` is deliberately not sent. The server documents a
 * one-slot-per-DID fallback for clients that omit it, and that fallback does
 * not hold — the live set the reaper checks holds only (did, Some(instance))
 * pairs, so an instance-less creator is swept by the next participant's
 * av-join. Sending the tag from here would turn the specs that catch that
 * green without the server changing.
 */
export async function startAvSessionRaw(page: Page, channel: string) {
  await page.evaluate(async ([ch]) => {
    const mod = await import('/src/irc/client.ts');
    mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
  }, [channel]);
}

/** How many message rows the app's store holds for `channel`.
 *
 *  Not the rows on screen. The message list mounts a window of what it holds,
 *  so counting `msg-` nodes in the document counts the window and not the
 *  list — a count that shrinks when the reader scrolls, and that says nothing
 *  about what a page of history added. `src/e2e-support.ts` reads the held
 *  list itself; `e2e/store-count.spec.ts` is what proves it reads the store
 *  the running app is using. */
export function heldRowCount(page: Page, channel: string): Promise<number> {
  return page.evaluate(async (ch) => {
    const mod = await import('/src/e2e-support.ts');
    return mod.heldRowCount(ch);
  }, channel);
}

/** The msgid of the newest row the store holds for `channel`. */
export function newestHeldMsgId(page: Page, channel: string): Promise<string | null> {
  return page.evaluate(async (ch) => {
    const mod = await import('/src/e2e-support.ts');
    return mod.newestHeldMsgId(ch);
  }, channel);
}

/** The msgid of the oldest row the store holds for `channel`. */
export function oldestHeldMsgId(page: Page, channel: string): Promise<string | null> {
  return page.evaluate(async (ch) => {
    const mod = await import('/src/e2e-support.ts');
    return mod.oldestHeldMsgId(ch);
  }, channel);
}

/** Go to a message the way a search result or a reply reference does. */
export function jumpToMessage(page: Page, msgid: string): Promise<void> {
  return page.evaluate(async (id) => {
    const mod = await import('/src/e2e-support.ts');
    mod.jumpToMessage(id);
  }, msgid);
}

/** Set up localStorage before page load to skip onboarding */
export async function prepPage(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('freeq-onboarding-done', '1');
    localStorage.setItem('freeq-install-dismissed', '1');
  });
}

/** Connect as guest and wait for registration */
export async function connectGuest(page: Page, nick: string, channel: string) {
  await prepPage(page);
  await page.goto('/');

  // Switch to Guest tab
  const guestTab = page.getByRole('button', { name: 'Guest' });
  await guestTab.click();

  // Fill nickname
  const nickInput = page.getByPlaceholder('your_nick');
  await nickInput.fill(nick);

  // Fill channel
  const channelInput = page.getByPlaceholder('#freeq');
  await channelInput.fill(channel);

  // Click connect
  await page.getByRole('button', { name: 'Connect as Guest' }).click();

  // Wait for the chat UI to appear (sidebar with channel name)
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 15_000 });

  // Wait for first channel to appear in sidebar
  const firstChannel = channel.split(',')[0].trim();
  await expect(page.getByTestId('sidebar').getByText(firstChannel)).toBeVisible({ timeout: 10_000 });
}

/** Send a message in the compose box */
export async function sendMessage(page: Page, text: string) {
  const compose = page.getByTestId('compose-input');
  await compose.click();
  await compose.fill(text);
  // Dismiss any autocomplete popup that may have appeared
  await compose.press('Escape');
  await page.waitForTimeout(50);
  await compose.press('Enter');
  // Wait for compose to clear (message was sent)
  await expect(compose).toHaveValue('', { timeout: 3_000 });
}

/** Wait for a message to appear in the message list */
export async function expectMessage(page: Page, text: string, timeout = 10_000) {
  await expect(page.getByTestId('message-list').getByText(text, { exact: false })).toBeVisible({ timeout });
}

/** Wait for a system/status message */
export async function expectSystemMessage(page: Page, text: string, timeout = 10_000) {
  await expect(page.getByText(text, { exact: false })).toBeVisible({ timeout });
}

/** Open the sidebar on mobile (no-op on desktop if already visible) */
export async function openSidebar(page: Page) {
  const sidebar = page.getByTestId('sidebar');
  const isInViewport = await sidebar.evaluate((el) => {
    const rect = el.getBoundingClientRect();
    return rect.right > 0 && rect.left < window.innerWidth;
  }).catch(() => false);

  if (!isInViewport) {
    const hamburger = page.locator('header button').first();
    await hamburger.click();
    await page.waitForTimeout(300);
  }
  return sidebar;
}

/** Create a second browser context + page, connected as guest */
export async function connectSecondUser(browser: Browser, nick: string, channel: string) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await connectGuest(page, nick, channel);
  return { ctx, page };
}

/** Switch to a channel via sidebar click. Closes sidebar on mobile after click. */
export async function switchChannel(page: Page, channel: string) {
  const sidebar = await openSidebar(page);
  await sidebar.getByText(channel).click();
  await page.waitForTimeout(300);

  // On mobile, sidebar may stay open — close it by clicking the backdrop or pressing Escape
  const isMobile = (page.viewportSize()?.width || 1280) < 768;
  if (isMobile) {
    // Click on the backdrop/overlay if it exists, or press Escape
    const backdrop = page.locator('[class*="backdrop"], [class*="overlay"]');
    if (await backdrop.count() > 0 && await backdrop.first().isVisible()) {
      await backdrop.first().click();
    }
    await page.waitForTimeout(200);
    // If sidebar is still covering compose, try pressing Escape
    const compose = page.getByTestId('compose-input');
    const isClickable = await compose.evaluate((el) => {
      const rect = el.getBoundingClientRect();
      const topEl = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return el.contains(topEl) || el === topEl;
    }).catch(() => false);
    if (!isClickable) {
      // Click somewhere in the main content area to dismiss sidebar
      await page.mouse.click(page.viewportSize()!.width - 10, page.viewportSize()!.height / 2);
      await page.waitForTimeout(200);
    }
  }
}
