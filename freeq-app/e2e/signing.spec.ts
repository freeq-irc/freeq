/**
 * E2E: what a message says about who wrote it.
 *
 * Runs against a local freeq-server (see playwright.config.ts). Point
 * FREEQ_WEB at a real deployment to run the same flows there.
 *
 * A guest has no identity, so nothing a guest sends is signed — which is the
 * first property worth pinning: no signature, no marker, no claim. The marker
 * states themselves are exercised on messages that do carry a signature, with
 * the verdict coming from the server's real verify endpoint.
 */
import { test, expect, type Page } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, expectMessage } from './helpers';

/** The verdicts a checked marker is allowed to show. */
const VERDICTS = ['device', 'server', 'unverifiable', 'invalid'];

/**
 * Put a signed message into the open conversation, as if it had arrived.
 *
 * A signature needs an identity, and a browser in CI has none — so the
 * message is injected while everything downstream of it stays real: the row
 * renders through the app, and clicking its marker asks the running server
 * about that id.
 */
async function receiveSignedMessage(
  page: Page,
  channel: string,
  msg: { id: string; from: string; text: string; encrypted?: boolean },
) {
  await page.evaluate(
    async ({ channel, msg }) => {
      const { useStore } = await import('/src/store.ts');
      useStore.getState().addMessage(channel, {
        ...msg,
        timestamp: new Date(),
        tags: { '+freeq.at/sig': 'ed25519:kid:signature', msgid: msg.id },
      });
    },
    { channel, msg },
  );
}

test.describe('signature markers', () => {
  test('a guest message claims nothing, because nothing signed it', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);

    await sendMessage(page, 'sent without an identity');
    await expectMessage(page, 'sent without an identity');

    await expect(
      page.getByTestId('signed-badge'),
      'a guest has no key, so there is nothing to claim',
    ).toHaveCount(0);
  });

  test('a signed message rests unchecked, then shows what the server answered', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEUNCHECKED0000000001',
      from: 'someone',
      text: 'a message with a signature on it',
    });
    await expectMessage(page, 'a message with a signature on it');

    const badge = page.getByTestId('signed-badge').first();
    await expect(badge).toBeVisible({ timeout: 10_000 });
    await expect(
      badge,
      'the resting marker knows only that a signature is present',
    ).toHaveAttribute('data-verdict', 'unchecked');

    await badge.click();
    await expect(badge).not.toHaveAttribute('data-verdict', 'unchecked', { timeout: 10_000 });
    const verdict = await badge.getAttribute('data-verdict');
    expect(VERDICTS).toContain(verdict);
    // Nothing on this server ever signed that id, so the honest answer is
    // that it cannot be checked — and the marker must not read as verified.
    expect(verdict, 'an unknown id is not evidence of anything').toBe('unverifiable');
    await expect(page.getByText('Could not be checked here')).toBeVisible();
  });

  test('a follow-up row carries its own marker', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEGROUPED000000000001',
      from: 'someone',
      text: 'first thing said',
    });
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEGROUPED000000000002',
      from: 'someone',
      text: 'second thing said',
    });
    await expectMessage(page, 'second thing said');

    await expect(
      page.getByTestId('signed-badge'),
      'being the second thing someone said is not a reason to drop the evidence',
    ).toHaveCount(2, { timeout: 10_000 });
  });

  test('an encrypted message shows both what it is and who wrote it', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEENCRYPTED00000000001',
      from: 'someone',
      text: 'unreadable to the server',
      encrypted: true,
    });
    await expectMessage(page, 'unreadable to the server');

    await expect(page.getByTestId('signed-badge')).toHaveCount(1, { timeout: 10_000 });
    await expect(page.getByTitle('End-to-end encrypted')).toBeVisible();
  });

  test('reacting and deleting leave the conversation intact', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);

    await sendMessage(page, 'react then delete me');
    await expectMessage(page, 'react then delete me');

    const msg = page.getByTestId('message-list').getByText('react then delete me');
    await msg.hover();
    const reactBtn = page.locator('[title="Add reaction"]').first();
    if (await reactBtn.isVisible().catch(() => false)) {
      await reactBtn.click();
      const emoji = page.getByText('👍').first();
      if (await emoji.isVisible().catch(() => false)) {
        await emoji.click();
        await expect(page.getByTestId('message-list').getByText('👍')).toBeVisible({
          timeout: 5_000,
        });
      }
    }

    // Dismiss the emoji picker before reaching for the context menu.
    await page.keyboard.press('Escape');
    await expect(page.locator('em-emoji-picker')).toHaveCount(0);

    // Deleting asks first, through the browser's own confirm dialog.
    page.once('dialog', (d) => d.accept());
    await msg.click({ button: 'right' });
    await page.getByRole('button', { name: 'Delete' }).click();
    await expect(
      page.getByTestId('message-list').getByText('react then delete me'),
    ).toHaveCount(0, { timeout: 10_000 });
  });

  test('an action goes out as a message, and is rendered as one', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);

    await sendMessage(page, '/me tries the action path');
    await expectMessage(page, 'tries the action path');
  });
});
