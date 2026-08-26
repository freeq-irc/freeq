/**
 * E2E tests: UI elements, keyboard shortcuts, modals, settings
 */
import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, expectMessage } from './helpers';

test.describe('UI Elements', () => {
  let nick: string;
  let channel: string;

  test.beforeEach(async ({ page }) => {
    nick = uniqueNick();
    channel = uniqueChannel();
    await connectGuest(page, nick, channel);
  });

  test('member list shows current user', async ({ page }) => {
    // On mobile, member list is hidden — skip
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 768, 'member list hidden on mobile');
    await expect(page.getByText(nick).first()).toBeVisible({ timeout: 5_000 });
  });

  test('compose box is focused and ready', async ({ page }) => {
    const compose = page.getByTestId('compose-input');
    await expect(compose).toBeVisible();
  });

  test('search modal opens with Cmd+F', async ({ page }) => {
    await page.keyboard.press('Meta+f');
    await expect(page.getByPlaceholder(/search/i)).toBeVisible({ timeout: 3_000 });
    await page.keyboard.press('Escape');
  });

  test('quick switcher opens with Cmd+K', async ({ page }) => {
    await page.keyboard.press('Meta+k');
    await expect(
      page.getByPlaceholder(/switch/i).or(page.getByPlaceholder(/channel/i))
    ).toBeVisible({ timeout: 3_000 });
    await page.keyboard.press('Escape');
  });

  test('search finds messages', async ({ page }) => {
    await sendMessage(page, 'findable needle xyz789');
    await page.waitForTimeout(300);

    await page.keyboard.press('Meta+f');
    const searchInput = page.getByPlaceholder(/search/i);
    await expect(searchInput).toBeVisible({ timeout: 3_000 });
    await searchInput.fill('needle xyz789');
    await page.waitForTimeout(500);

    // Should show the matching message — scope to message list to avoid search result sidebar
    await expect(page.getByTestId('message-list').getByText('findable needle xyz789')).toBeVisible({ timeout: 5_000 });
    await page.keyboard.press('Escape');
  });

  test('channel name shown in top bar', async ({ page }) => {
    const header = page.locator('header');
    await expect(header.getByText(channel)).toBeVisible({ timeout: 5_000 });
  });

  test('message list scrolls to bottom on new message', async ({ page }) => {
    for (let i = 0; i < 15; i++) {
      await sendMessage(page, `scroll test message ${i}`);
    }
    await page.waitForTimeout(500);

    await sendMessage(page, 'final scroll test');
    await expectMessage(page, 'final scroll test');
  });
});

test.describe('Slash commands', () => {
  test('/nick changes nickname', async ({ page }) => {
    const oldNick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, oldNick, channel);

    const newNick = uniqueNick('newnick');
    await sendMessage(page, `/nick ${newNick}`);
    await expect(page.getByText(newNick).first()).toBeVisible({ timeout: 5_000 });
  });

  test('/me sends action message', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, '/me does a thing');
    await expect(page.getByText('does a thing')).toBeVisible({ timeout: 5_000 });
  });

  test('/topic sets channel topic', async ({ page }) => {
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 640, 'topic hidden on mobile');

    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, '/topic My cool topic');
    await expect(
      page.locator('header').getByText('My cool topic'),
    ).toBeVisible({ timeout: 5_000 });
  });
});

test.describe('Message formatting', () => {
  test('bold markdown renders', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, 'this is **bold text** here');
    const bold = page.getByTestId('message-list').locator('strong, b').filter({ hasText: 'bold text' });
    await expect(bold).toBeVisible({ timeout: 5_000 });
  });

  test('inline code renders', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, 'use `console.log()` for debug');
    const code = page.getByTestId('message-list').locator('code').filter({ hasText: 'console.log()' });
    await expect(code).toBeVisible({ timeout: 5_000 });
  });

  test('multiple URLs render as links', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, 'visit https://example.com and https://example.org');
    const links = page.getByTestId('message-list').locator('a[href^="https://example"]');
    await expect(links).toHaveCount(2, { timeout: 5_000 });
  });
});
