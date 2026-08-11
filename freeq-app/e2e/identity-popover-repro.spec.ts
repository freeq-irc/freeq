import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, connectSecondUser, sendMessage, expectMessage } from './helpers';

// Reproduction: a connected guest's popover must settle to Guest, not Unknown.
// Live observation 2026-08-10: popovers for nicks the server answers about
// (including an authenticated one) showed Unknown, meaning the WHOIS answer
// never reached the popover's view of the store.
test('the popover for a connected guest settles to Guest', async ({ page, browser }) => {
  const channel = uniqueChannel();
  const alice = uniqueNick('alice');
  const bob = uniqueNick('bob');

  await connectGuest(page, alice, channel);
  const second = await connectSecondUser(browser, bob, channel);
  await sendMessage(second.page, 'hello from bob');
  await expectMessage(page, 'hello from bob');

  // Open bob's popover from the message header.
  await page.getByRole('button', { name: bob }).first().click();

  // The claim block inside the popover: Guest, with the settled sentence.
  const pop = page.getByTestId('user-popover');
  await expect(pop.getByText('Guest', { exact: true })).toBeVisible({ timeout: 10_000 });
  await expect(pop.getByText('No account — just a nickname on this server.', { exact: false })).toBeVisible();
  await expect(pop.getByText('Unknown', { exact: true })).toHaveCount(0);

  await second.ctx.close();
});

// A relayed guest: the message came through a peer with no account attached.
// The popover's top strip must read Guest with the origin-naming sentence —
// live observation said it rendered nothing.
test('the popover for a relayed guest reads Guest at the origin', async ({ page }) => {
  const channel = uniqueChannel();
  await connectGuest(page, uniqueNick('carol'), channel);

  await page.evaluate(
    async ({ channel }) => {
      const { useStore } = await import('/src/store.ts');
      useStore.getState().addMessage(channel, {
        id: '01JRELAYEDGUEST00000000001',
        from: 'farguest',
        text: 'hello from far away',
        timestamp: new Date(),
        tags: { '+freeq.at/origin': 'irc.peer.example', msgid: '01JRELAYEDGUEST00000000001' },
      });
    },
    { channel },
  );
  await expectMessage(page, 'hello from far away');

  await page.getByRole('button', { name: 'farguest' }).first().click();
  const pop = page.getByTestId('user-popover');
  await expect(pop.getByText('Guest', { exact: true })).toBeVisible({ timeout: 10_000 });
  await expect(pop.getByText('No account — just a nickname on irc.peer.example.', { exact: false })).toBeVisible();
});
