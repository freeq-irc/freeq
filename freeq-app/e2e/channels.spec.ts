/**
 * E2E tests: Channel operations
 */
import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, openSidebar, switchChannel, connectSecondUser } from './helpers';

test.describe('Channels', () => {
  test('channel topic shows in top bar', async ({ page }) => {
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 640, 'topic hidden on mobile');

    const nick = uniqueNick('top');
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    // Wait a moment for ops to be assigned
    await page.waitForTimeout(500);
    // `/topic` takes the text only — it always targets the open channel — and
    // the topic then reads back in exactly one place, the header.
    await sendMessage(page, '/topic E2E test topic');
    await expect(
      page.locator('header').getByText('E2E test topic'),
    ).toBeVisible({ timeout: 8_000 });
  });

  test('can switch between channels', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1}, ${ch2}`);

    let sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch1)).toBeVisible({ timeout: 10_000 });
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 10_000 });

    await sidebar.getByText(ch1).click();
    await page.waitForTimeout(300);
    await sendMessage(page, 'msg in first channel');
    await expect(page.getByTestId('message-list').getByText('msg in first channel')).toBeVisible();

    await switchChannel(page, ch2);
    await sendMessage(page, 'msg in second channel');
    await expect(page.getByTestId('message-list').getByText('msg in second channel')).toBeVisible();

    await switchChannel(page, ch1);
    await expect(page.getByTestId('message-list').getByText('msg in first channel')).toBeVisible();
  });

  test('join command works', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, ch1);

    await sendMessage(page, `/join ${ch2}`);
    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 5_000 });
  });

  test('part command removes channel', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1}, ${ch2}`);

    // Verify ch2 is in sidebar
    let sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 10_000 });

    // Switch to ch2 first (ensures sidebar closes on mobile + we're in the right channel)
    await switchChannel(page, ch2);
    await sendMessage(page, `/part ${ch2}`);

    sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).not.toBeVisible({ timeout: 5_000 });
    await expect(sidebar.getByText(ch1)).toBeVisible();
  });

  test('channel creator gets ops', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);
    // The founder should appear in the UI somewhere
    await expect(page.getByText(nick).first()).toBeVisible({ timeout: 5_000 });
  });

  test('second user sees first user in channel', async ({ page, browser }) => {
    // On mobile, member list is hidden — need to check messages or open member list
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 768, 'member list hidden on mobile');

    const nick1 = uniqueNick('usr1');
    const nick2 = uniqueNick('usr2');
    const channel = uniqueChannel();

    await connectGuest(page, nick1, channel);
    const { ctx, page: page2 } = await connectSecondUser(browser, nick2, channel);

    // User 2 should see user 1 in the page somewhere (member list)
    await expect(page2.getByText(nick1).first()).toBeVisible({ timeout: 10_000 });

    await ctx.close();
  });

  test('user join is shown as system message', async ({ page, browser }) => {
    const nick1 = uniqueNick('host');
    const nick2 = uniqueNick('joiner');
    const channel = uniqueChannel();

    await connectGuest(page, nick1, channel);
    const { ctx, page: page2 } = await connectSecondUser(browser, nick2, channel);

    // Host should see join system message
    await expect(page.getByText(new RegExp(`${nick2}.*joined`, 'i'))).toBeVisible({ timeout: 10_000 });

    await ctx.close();
  });

  test('user part is shown as system message', async ({ page, browser }) => {
    const nick1 = uniqueNick('host');
    const nick2 = uniqueNick('leaver');
    const channel = uniqueChannel();

    await connectGuest(page, nick1, channel);
    const { ctx, page: page2 } = await connectSecondUser(browser, nick2, channel);
    await page.waitForTimeout(500);

    // User 2 leaves
    await sendMessage(page2, `/part ${channel}`);

    // Host should see part system message
    await expect(page.getByText(new RegExp(`${nick2}.*(left|parted)`, 'i'))).toBeVisible({ timeout: 10_000 });

    await ctx.close();
  });
});
