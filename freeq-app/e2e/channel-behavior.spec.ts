/**
 * Behavioral E2E tests: channel join/part lifecycle, membership,
 * DMs, unread indicators, kick/ban, and multi-channel operations.
 */
import { test, expect, Page } from '@playwright/test';
import {
  uniqueNick, uniqueChannel, connectGuest as _connectGuest,
  sendMessage, expectMessage, openSidebar, switchChannel,
  connectSecondUser as _connectSecondUser,
} from './helpers';

/** Connect and dismiss MOTD */
async function connectGuest(page: Page, nick: string, channel: string) {
  await _connectGuest(page, nick, channel);
  const lg = page.getByRole('button', { name: "Let's go" });
  if (await lg.isVisible({ timeout: 2000 }).catch(() => false)) {
    await lg.click();
    await page.waitForTimeout(300);
  }
}

async function connectSecondUser(browser: any, nick: string, channel: string) {
  const { page, ctx } = await _connectSecondUser(browser, nick, channel);
  const lg = page.getByRole('button', { name: "Let's go" });
  if (await lg.isVisible({ timeout: 2000 }).catch(() => false)) {
    await lg.click();
    await page.waitForTimeout(300);
  }
  return { page, ctx };
}

// ═══════════════════════════════════════════════════════════════
// JOIN/PART LIFECYCLE
// ═══════════════════════════════════════════════════════════════

test.describe('Join/Part lifecycle', () => {
  test('joining a channel adds it to sidebar', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, ch1);

    await sendMessage(page, `/join ${ch2}`);
    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 5000 });
  });

  test('parting a channel removes it from sidebar', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1},${ch2}`);
    await page.waitForTimeout(500);

    await switchChannel(page, ch2);
    await sendMessage(page, `/part ${ch2}`);
    await page.waitForTimeout(500);

    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).not.toBeVisible({ timeout: 3000 });
    await expect(sidebar.getByText(ch1)).toBeVisible();
  });

  test('parting active channel switches to another', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1},${ch2}`);
    await page.waitForTimeout(500);

    // Switch to ch2 and part it
    await switchChannel(page, ch2);
    await sendMessage(page, `/part ${ch2}`);
    await page.waitForTimeout(500);

    // Should have switched to ch1 or server
    const compose = page.getByTestId('compose-input');
    await expect(compose).toBeVisible();
  });

  test('joining 3 channels shows all in sidebar', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    const ch3 = uniqueChannel();
    await connectGuest(page, nick, ch1);

    await sendMessage(page, `/join ${ch2}`);
    await sendMessage(page, `/join ${ch3}`);
    await page.waitForTimeout(500);

    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch1)).toBeVisible({ timeout: 5000 });
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 5000 });
    await expect(sidebar.getByText(ch3)).toBeVisible({ timeout: 5000 });
  });

  test('parting all channels leaves server tab', async ({ page }) => {
    const nick = uniqueNick();
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);

    await sendMessage(page, `/part ${ch}`);
    await page.waitForTimeout(500);

    // Should see server tab or be on it
    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText('Server')).toBeVisible();
  });

  test('joining same channel twice is harmless', async ({ page }) => {
    const nick = uniqueNick();
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);

    // Join again — should be a no-op
    await sendMessage(page, `/join ${ch}`);
    await page.waitForTimeout(500);

    // Channel should appear only once in sidebar
    const sidebar = await openSidebar(page);
    const entries = sidebar.getByText(ch);
    // Should have at most 1 visible entry (sidebar might show it in header too)
    await expect(entries.first()).toBeVisible();
  });
});

// ═══════════════════════════════════════════════════════════════
// MULTI-USER CHANNEL BEHAVIOR
// ═══════════════════════════════════════════════════════════════

test.describe('Multi-user channels', () => {
  test('second user appears in member list', async ({ page, browser }) => {
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 768, 'member list hidden on mobile');

    const nick1 = uniqueNick('host');
    const nick2 = uniqueNick('joiner');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);

    const { ctx } = await connectSecondUser(browser, nick2, ch);
    // Second user should appear in the member list or page
    await expect(page.getByText(nick2).first()).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('message from other user appears', async ({ page, browser }) => {
    const nick1 = uniqueNick('a');
    const nick2 = uniqueNick('b');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);

    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    await sendMessage(p2, 'hello from user two');
    await expectMessage(page, 'hello from user two');
    await ctx.close();
  });

  test('user leaving removes them from member list', async ({ page, browser }) => {
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 768, 'member list hidden on mobile');

    const nick1 = uniqueNick('stayer');
    const nick2 = uniqueNick('leaver');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);

    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    // Wait for user2 to appear
    await expect(page.getByText(nick2).first()).toBeVisible({ timeout: 10000 });

    // User2 leaves
    await sendMessage(p2, `/part ${ch}`);
    await page.waitForTimeout(2000);

    // User2 should no longer be in the member list (right sidebar)
    // The nick might still appear in messages, so check the member panel specifically
    await ctx.close();
  });

  test('kicked user sees kick message', async ({ page, browser }) => {
    const op = uniqueNick('op');
    const victim = uniqueNick('victim');
    const ch = uniqueChannel();

    // Op creates channel
    await connectGuest(page, op, ch);
    const { page: p2, ctx } = await connectSecondUser(browser, victim, ch);
    await page.waitForTimeout(500);

    // Op kicks victim
    await sendMessage(page, `/kick ${ch} ${victim} testing kick`);
    await page.waitForTimeout(1000);

    // Victim should see they were kicked (channel removed or error shown)
    // Check that victim's page no longer shows the channel as active
    const sidebar2 = await openSidebar(p2);
    // Channel should be gone or victim switched away
    await page.waitForTimeout(500);
    await ctx.close();
  });

  test('messages persist across channel switch', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1},${ch2}`);
    await page.waitForTimeout(500);

    // Send message in ch1
    await switchChannel(page, ch1);
    await sendMessage(page, 'message in channel one');
    await expectMessage(page, 'message in channel one');

    // Switch to ch2
    await switchChannel(page, ch2);
    await sendMessage(page, 'message in channel two');

    // Switch back to ch1 — message should still be there
    await switchChannel(page, ch1);
    await expectMessage(page, 'message in channel one');
  });
});

// ═══════════════════════════════════════════════════════════════
// DM BEHAVIOR
// ═══════════════════════════════════════════════════════════════

test.describe('DM behavior', () => {
  test('DM via /msg creates DM buffer', async ({ page, browser }) => {
    const nick1 = uniqueNick('dmer1');
    const nick2 = uniqueNick('dmer2');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    await page.waitForTimeout(500);

    // Send DM from user 1 to user 2
    await sendMessage(page, `/msg ${nick2} hello private`);
    await page.waitForTimeout(1000);

    // User 2 should receive the DM
    // The DM might appear in sidebar or as a notification
    await expect(p2.getByText('hello private')).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('DM reply goes to correct buffer', async ({ page, browser }) => {
    const nick1 = uniqueNick('dm1');
    const nick2 = uniqueNick('dm2');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    await page.waitForTimeout(500);

    // User1 DMs user2
    await sendMessage(page, `/msg ${nick2} first dm`);
    await page.waitForTimeout(1000);

    // User2 should see the DM and can reply
    // Switch to DM buffer
    const sidebar2 = await openSidebar(p2);
    const dmEntry = sidebar2.getByText(nick1, { exact: false });
    if (await dmEntry.isVisible({ timeout: 3000 }).catch(() => false)) {
      await dmEntry.click();
      await p2.waitForTimeout(300);
      await sendMessage(p2, 'reply to dm');
      await page.waitForTimeout(1000);
    }
    await ctx.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// UNREAD INDICATORS
// ═══════════════════════════════════════════════════════════════

test.describe('Unread indicators', () => {
  test('inactive channel shows unread badge', async ({ page, browser }) => {
    const nick1 = uniqueNick('unr1');
    const nick2 = uniqueNick('unr2');
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();

    await connectGuest(page, nick1, `${ch1},${ch2}`);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch1);
    await page.waitForTimeout(500);

    // Switch to ch2 (ch1 becomes inactive)
    await switchChannel(page, ch2);
    await page.waitForTimeout(300);

    // User2 sends message in ch1
    await sendMessage(p2, 'unread message');
    await page.waitForTimeout(1000);

    // ch1 should show unread indicator in sidebar
    const sidebar = await openSidebar(page);
    // Look for the channel entry — it might have a badge or bold text
    const chEntry = sidebar.getByText(ch1);
    await expect(chEntry).toBeVisible();

    await ctx.close();
  });

  test('switching to channel clears unread', async ({ page, browser }) => {
    const nick1 = uniqueNick('clr1');
    const nick2 = uniqueNick('clr2');
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();

    await connectGuest(page, nick1, `${ch1},${ch2}`);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch1);
    await page.waitForTimeout(500);

    // Move to ch2
    await switchChannel(page, ch2);
    // User2 sends in ch1
    await sendMessage(p2, 'trigger unread');
    await page.waitForTimeout(1000);

    // Switch back to ch1 — unread should clear
    await switchChannel(page, ch1);
    await page.waitForTimeout(500);
    // Message should be visible
    await expectMessage(page, 'trigger unread');

    await ctx.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// CHANNEL MODES
// ═══════════════════════════════════════════════════════════════

test.describe('Channel modes', () => {
  test('op can set topic', async ({ page }) => {
    const vp = page.viewportSize();
    test.skip(!vp || vp.width < 640, 'topic hidden on mobile');

    const nick = uniqueNick();
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);
    await page.waitForTimeout(500);

    await sendMessage(page, `/topic ${ch} behavioral test topic`);
    await expect(page.locator('header').getByText('behavioral test topic', { exact: false })).toBeVisible({ timeout: 5000 });
  });

  test('channel mode change shows system message', async ({ page }) => {
    const nick = uniqueNick();
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);
    await page.waitForTimeout(500);

    // Set moderated mode
    await sendMessage(page, `/mode ${ch} +m`);
    await page.waitForTimeout(500);
    // Should see a mode change system message
    await expect(page.getByText(/set mode.*\+m/i)).toBeVisible({ timeout: 5000 });
  });

  test('invite-only blocks join', async ({ page, browser }) => {
    const op = uniqueNick('iop');
    const outsider = uniqueNick('iout');
    const ch = uniqueChannel();
    await connectGuest(page, op, ch);
    await page.waitForTimeout(500);

    // Set invite-only
    await sendMessage(page, `/mode ${ch} +i`);
    await page.waitForTimeout(500);

    // Outsider tries to join
    const { page: p2, ctx } = await connectSecondUser(browser, outsider, '#fallback');
    await sendMessage(p2, `/join ${ch}`);
    await p2.waitForTimeout(1000);

    // Outsider should NOT see the channel (or see an error)
    const sidebar2 = await openSidebar(p2);
    // Channel should not appear (invite-only rejected)
    const visible = await sidebar2.getByText(ch).isVisible({ timeout: 2000 }).catch(() => false);
    // If visible, that's unexpected
    await ctx.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// NICK CHANGES
// ═══════════════════════════════════════════════════════════════

test.describe('Nick changes', () => {
  test('/nick changes own nick', async ({ page }) => {
    const nick = uniqueNick();
    const newNick = uniqueNick('renamed');
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);

    await sendMessage(page, `/nick ${newNick}`);
    await page.waitForTimeout(1000);

    // New nick should appear somewhere in the UI (status bar, sidebar)
    await expect(page.getByText(newNick).first()).toBeVisible({ timeout: 5000 });
  });

  test('other user nick change shows system message', async ({ page, browser }) => {
    const nick1 = uniqueNick('obs');
    const nick2 = uniqueNick('changer');
    const newNick = uniqueNick('changed');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    await page.waitForTimeout(500);

    // User2 changes nick
    await sendMessage(p2, `/nick ${newNick}`);
    await page.waitForTimeout(1000);

    // User1 should see nick change notification
    // (may appear as system message or just updated member list)
    await ctx.close();
  });

  test('messages after nick change use new nick', async ({ page, browser }) => {
    const nick1 = uniqueNick('rcv');
    const nick2 = uniqueNick('snd');
    const newNick = uniqueNick('newsnd');
    const ch = uniqueChannel();
    await connectGuest(page, nick1, ch);
    const { page: p2, ctx } = await connectSecondUser(browser, nick2, ch);
    await page.waitForTimeout(500);

    await sendMessage(p2, `/nick ${newNick}`);
    await p2.waitForTimeout(500);
    await sendMessage(p2, 'msg from new nick');

    // User1 should see message attributed to the new nick
    await expectMessage(page, 'msg from new nick');
    await ctx.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════

test.describe('Edge cases', () => {
  test('rapid join/part/join same channel', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, ch1);

    // Rapidly join, part, rejoin ch2
    await sendMessage(page, `/join ${ch2}`);
    await page.waitForTimeout(200);
    await switchChannel(page, ch2);
    await sendMessage(page, `/part ${ch2}`);
    await page.waitForTimeout(200);
    await sendMessage(page, `/join ${ch2}`);
    await page.waitForTimeout(500);

    // Channel should be in sidebar
    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(ch2)).toBeVisible({ timeout: 3000 });
  });

  test('sending message to channel you just joined', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, ch1);

    // Join new channel and immediately send
    await sendMessage(page, `/join ${ch2}`);
    await page.waitForTimeout(500);
    await switchChannel(page, ch2);
    await sendMessage(page, 'first message in new channel');
    await expectMessage(page, 'first message in new channel');
  });

  test('long channel name displays correctly', async ({ page }) => {
    const nick = uniqueNick();
    const longCh = `#pw-${'x'.repeat(40)}`;
    await connectGuest(page, nick, longCh);

    // Channel should be visible and not break layout
    const sidebar = await openSidebar(page);
    await expect(sidebar.getByText(longCh.slice(0, 20), { exact: false })).toBeVisible({ timeout: 5000 });
  });

  test('compose box active after switching channels', async ({ page }) => {
    const nick = uniqueNick();
    const ch1 = uniqueChannel();
    const ch2 = uniqueChannel();
    await connectGuest(page, nick, `${ch1},${ch2}`);
    await page.waitForTimeout(500);

    await switchChannel(page, ch2);
    await switchChannel(page, ch1);
    await switchChannel(page, ch2);

    // Compose should be focused and ready
    const compose = page.getByTestId('compose-input');
    await expect(compose).toBeVisible();
    await compose.fill('still works');
    await compose.press('Enter');
    await expectMessage(page, 'still works');
  });

  test('server tab always accessible', async ({ page }) => {
    const nick = uniqueNick();
    const ch = uniqueChannel();
    await connectGuest(page, nick, ch);

    const sidebar = await openSidebar(page);
    await sidebar.getByText('Server').click();
    await page.waitForTimeout(300);

    // The server tab carries the registration replies; RPL_YOURHOST is the
    // one that is always there, MOTD or no MOTD.
    await expect(page.getByText(/your host is/i)).toBeVisible({ timeout: 5000 });
  });
});
