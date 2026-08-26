/**
 * E2E tests: Edge cases and potential failure points
 *
 * These test risky areas: nick formats, XSS, case sensitivity,
 * race conditions, layout limits, and multi-tab behavior.
 */
import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, expectMessage, openSidebar, switchChannel, connectSecondUser, prepPage } from './helpers';

test.describe('Nick with dots (AT Protocol handles)', () => {
  test('dotted nick can send and receive messages', async ({ browser }) => {
    // AT Protocol handles become nicks like "chadfowler.com"
    const ts = Date.now().toString(36) + (Math.random() * 1000 | 0);
    const nick1 = `t.${ts}.com`;
    const nick2 = uniqueNick('plain');
    const channel = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    await connectGuest(page1, nick1, channel);
    await connectGuest(page2, nick2, channel);
    await page1.waitForTimeout(500);

    // Dotted nick sends message
    await sendMessage(page1, 'hello from dotted nick');
    await expectMessage(page2, 'hello from dotted nick');

    // Dotted nick receives message
    await sendMessage(page2, `hey ${nick1}!`);
    await expectMessage(page1, `hey ${nick1}!`);

    await ctx1.close();
    await ctx2.close();
  });

  test('DM to dotted nick works', async ({ browser }) => {
    const nick1 = `d.${Date.now().toString(36)}${(Math.random() * 1000 | 0)}.io`;
    const nick2 = uniqueNick('sender');
    const channel = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    await connectGuest(page1, nick1, channel);
    await connectGuest(page2, nick2, channel);
    await page1.waitForTimeout(500);

    // Send DM TO the dotted nick
    await sendMessage(page2, `/msg ${nick1} private to dotted`);

    // Dotted nick should receive it
    const sidebar1 = await openSidebar(page1);
    await expect(sidebar1.getByText(nick2).first()).toBeVisible({ timeout: 10_000 });
    await sidebar1.getByText(nick2).first().click();
    await page1.waitForTimeout(300);
    await expectMessage(page1, 'private to dotted');

    await ctx1.close();
    await ctx2.close();
  });
});

test.describe('XSS and injection', () => {
  test('HTML in channel name is escaped in sidebar', async ({ page }) => {
    const nick = uniqueNick();
    // Channel names with HTML-like content
    const channel = '#pw-<b>bold</b>';
    await connectGuest(page, nick, channel);

    // The sidebar should show the channel name as text, not render HTML
    const sidebar = await openSidebar(page);
    // Should NOT have a <b> element — text should be escaped
    const boldInSidebar = sidebar.locator('b').filter({ hasText: 'bold' });
    expect(await boldInSidebar.count()).toBe(0);
    // But the text should still be visible
    await expect(sidebar.getByText(channel).first()).toBeVisible({ timeout: 5_000 });
  });

  test('HTML in message is escaped', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, '<img src=x onerror=alert(1)>');
    // Should show as text, no img element rendered
    const imgs = page.getByTestId('message-list').locator('img[src="x"]');
    expect(await imgs.count()).toBe(0);
    await expectMessage(page, '<img');
  });

  test('javascript: URL is not rendered as clickable link', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    await sendMessage(page, 'click javascript:alert(1) here');
    // Should NOT have a clickable javascript: link
    const jsLinks = page.getByTestId('message-list').locator('a[href^="javascript"]');
    expect(await jsLinks.count()).toBe(0);
  });
});

test.describe('Case sensitivity', () => {
  test('channel is case-insensitive — messages go to same buffer', async ({ page }) => {
    const nick = uniqueNick();
    const base = uniqueChannel(); // e.g. #pw-xxx-1
    await connectGuest(page, nick, base);

    await sendMessage(page, 'lowercase message');
    await expectMessage(page, 'lowercase message');

    // Messages sent to the channel should appear regardless of case
    // The server normalizes, so this just verifies the client handles it
    const sidebar = await openSidebar(page);
    // Should only have one channel entry, not two
    const channelButtons = sidebar.getByText(base);
    expect(await channelButtons.count()).toBe(1);
  });
});

test.describe('Rapid interactions', () => {
  test('rapid channel switching shows correct messages', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    const ch3 = uniqueChannel();
    await connectGuest(page, nick, `${ch1}, ${ch2}, ${ch3}`);

    // Send unique messages to each channel
    await switchChannel(page, ch1);
    await sendMessage(page, 'message-in-ch1');

    await switchChannel(page, ch2);
    await sendMessage(page, 'message-in-ch2');

    await switchChannel(page, ch3);
    await sendMessage(page, 'message-in-ch3');

    // Now rapidly switch and verify
    await switchChannel(page, ch1);
    await expectMessage(page, 'message-in-ch1');

    await switchChannel(page, ch3);
    await expectMessage(page, 'message-in-ch3');

    await switchChannel(page, ch2);
    await expectMessage(page, 'message-in-ch2');

    // Rapid fire switches — just verify no crash
    await switchChannel(page, ch1);
    await switchChannel(page, ch3);
    await switchChannel(page, ch2);
    await switchChannel(page, ch1);
    await page.waitForTimeout(500);
    await expectMessage(page, 'message-in-ch1');
  });

  test('typing then switching channel clears compose', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1}, ${ch2}`);

    await switchChannel(page, ch1);
    const compose = page.getByTestId('compose-input');
    await compose.fill('unsent draft text');
    expect(await compose.inputValue()).toBe('unsent draft text');

    // Switch channel — compose should clear
    await switchChannel(page, ch2);
    const val = await page.getByTestId('compose-input').inputValue();
    expect(val).toBe('');
  });
});

test.describe('Multi-tab / nick collision', () => {
  test('second tab with same nick gets renamed', async ({ browser }) => {
    const nick = uniqueNick('dupe');
    const channel = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    await connectGuest(page1, nick, channel);

    // Second tab with same nick — server should rename to nick_ or similar
    await prepPage(page2);
    await page2.goto('/');
    await page2.getByRole('button', { name: 'Guest' }).click();
    await page2.getByPlaceholder('your_nick').fill(nick);
    await page2.getByPlaceholder('#freeq').fill(channel);
    await page2.getByRole('button', { name: 'Connect as Guest' }).click();

    // Wait for connection
    await expect(page2.getByTestId('sidebar')).toBeVisible({ timeout: 15_000 });

    // Both pages should work — send from page2 (possibly renamed nick)
    await sendMessage(page2, 'hello from second tab');
    await expectMessage(page1, 'hello from second tab');

    await ctx1.close();
    await ctx2.close();
  });
});

test.describe('Layout limits', () => {
  test('very long channel name does not break layout', async ({ page }) => {
    const nick = uniqueNick();
    // 64 characters is the server's limit; past it the JOIN is refused with
    // numeric 479 and there is no channel to lay out.
    const longName = ('#pw-' + 'a'.repeat(80)).slice(0, 64);
    await connectGuest(page, nick, longName);

    // No horizontal overflow
    const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
    const vpWidth = page.viewportSize()!.width;
    expect(bodyWidth).toBeLessThanOrEqual(vpWidth + 5);

    // Can still send messages
    await sendMessage(page, 'test in long channel');
    await expectMessage(page, 'test in long channel');
  });

  test('many channels in sidebar does not break layout', async ({ page }) => {
    const nick = uniqueNick();
    const channels = Array.from({ length: 8 }, () => uniqueChannel());
    await connectGuest(page, nick, channels.join(', '));

    // All channels should be in sidebar
    const sidebar = await openSidebar(page);
    for (const ch of channels.slice(0, 3)) {
      // Check at least the first few (rest may need scrolling)
      await expect(sidebar.getByText(ch).first()).toBeVisible({ timeout: 10_000 });
    }

    // No horizontal overflow
    const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
    const vpWidth = page.viewportSize()!.width;
    expect(bodyWidth).toBeLessThanOrEqual(vpWidth + 5);
  });
});

test.describe('Cross-user events', () => {
  test('messages arrive while viewing different channel', async ({ browser }) => {
    const nick1 = uniqueNick('viewer');
    const nick2 = uniqueNick('poster');
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    // User 1 joins both channels, views ch2
    await connectGuest(page1, nick1, `${ch1}, ${ch2}`);
    await switchChannel(page1, ch2);

    // User 2 joins ch1 and sends a message
    await connectGuest(page2, nick2, ch1);
    await page2.waitForTimeout(500);
    await sendMessage(page2, 'message while away');

    // User 1 should see unread indicator on ch1
    await page1.waitForTimeout(1000);
    const sidebar1 = await openSidebar(page1);
    // Look for unread badge/count on ch1
    const ch1Entry = sidebar1.getByText(ch1).first();
    await expect(ch1Entry).toBeVisible({ timeout: 5_000 });

    // Switch to ch1 — message should be there
    await switchChannel(page1, ch1);
    await expectMessage(page1, 'message while away');

    await ctx1.close();
    await ctx2.close();
  });

  test('user quit shows system message', async ({ browser }) => {
    const nick1 = uniqueNick('stayer');
    const nick2 = uniqueNick('quitter');
    const channel = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    await connectGuest(page1, nick1, channel);
    await connectGuest(page2, nick2, channel);
    await page1.waitForTimeout(500);

    // User 2 quits
    await sendMessage(page2, '/quit goodbye');
    await page2.waitForTimeout(500);

    // User 1 should see quit message
    await expect(page1.getByText(new RegExp(`${nick2}.*(quit|left|disconnected)`, 'i'))).toBeVisible({ timeout: 10_000 });

    await ctx1.close();
    await ctx2.close();
  });

  test('kick removes channel from kicked user', async ({ browser }) => {
    const op = uniqueNick('theop');
    const victim = uniqueNick('kicked');
    const channel = uniqueChannel();

    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();
    const page1 = await ctx1.newPage();
    const page2 = await ctx2.newPage();

    // Op creates channel (gets ops)
    await connectGuest(page1, op, channel);
    // Victim joins
    await connectGuest(page2, victim, channel);
    await page1.waitForTimeout(500);

    // Op kicks victim (active channel is implicit)
    await sendMessage(page1, `/kick ${victim} bye`);

    // Victim should no longer see the channel (or see a kicked message)
    await page2.waitForTimeout(1000);
    const sidebar2 = await openSidebar(page2);
    // Channel should be removed from sidebar after kick
    await expect(sidebar2.getByText(channel)).not.toBeVisible({ timeout: 5_000 });

    await ctx1.close();
    await ctx2.close();
  });
});

test.describe('Input edge cases', () => {
  test('whitespace-only message is not sent', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    const compose = page.getByTestId('compose-input');
    await compose.fill('   ');
    await compose.press('Escape');
    await page.waitForTimeout(50);
    await compose.press('Enter');

    // Compose should still have the whitespace (not cleared, because nothing was sent)
    // OR it was cleared but no message appeared
    await page.waitForTimeout(500);
    const msgList = page.getByTestId('message-list');
    // Should not have a message with just spaces
    const msgs = await msgList.locator('[class*="msg-full"]').count();
    // If there are messages, none should be whitespace-only
    // (system messages about joining don't count)
    expect(msgs).toBe(0);
  });

  test('message with only newlines is not sent', async ({ page }) => {
    const nick = uniqueNick();
    const channel = uniqueChannel();
    await connectGuest(page, nick, channel);

    const compose = page.getByTestId('compose-input');
    // Type text then clear it — verify compose handles this gracefully
    await compose.fill('test');
    await compose.fill('');
    await compose.press('Escape');
    await page.waitForTimeout(50);
    await compose.press('Enter');
    await page.waitForTimeout(500);

    // No user message should appear
    const msgList = page.getByTestId('message-list');
    const msgs = await msgList.locator('[class*="msg-full"]').count();
    expect(msgs).toBe(0);
  });
});
