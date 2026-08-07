/**
 * E2E: what a message says about who wrote it.
 *
 * Runs against a local freeq-server (see playwright.config.ts). Point
 * FREEQ_WEB at a real deployment to run the same flows there.
 *
 * Signing is the default state of a message, so it earns no resting ink —
 * there is no marker to click. Verification is an explicit request: the
 * message context menu offers "Verify Signature…", and the panel it opens
 * says only what the check actually established. The one mark a row can ever
 * wear is the ⚠ after a check answered "invalid".
 */
import { test, expect, type Page } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, expectMessage } from './helpers';

/**
 * Put a signed message into the open conversation, as if it had arrived.
 *
 * A signature needs an identity, and a browser in CI has none — so the
 * message is injected while everything downstream of it stays real: the row
 * renders through the app, and verifying it asks the running server about
 * that id.
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

/** Right-click a message and choose "Verify Signature…". */
async function requestVerify(page: Page, text: string) {
  await page.getByTestId('message-list').getByText(text).click({ button: 'right' });
  await page.getByRole('button', { name: /Verify Signature/ }).click();
}

test.describe('signature verification', () => {
  test('nothing signature-related rests on a message', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGERESTINGSILENT000001',
      from: 'someone',
      text: 'a signed message wearing nothing',
    });
    await expectMessage(page, 'a signed message wearing nothing');

    await expect(page.getByTestId('verify-panel')).toHaveCount(0);
    await expect(
      page.getByTestId('sig-invalid-mark'),
      'the ⚠ exists only after a check answered invalid',
    ).toHaveCount(0);
  });

  test('an unsigned message answers with a fact, not a warning', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);

    await sendMessage(page, 'sent without an identity');
    await expectMessage(page, 'sent without an identity');

    await requestVerify(page, 'sent without an identity');
    const panel = page.getByTestId('verify-panel');
    await expect(panel).toHaveAttribute('data-verdict', 'unsigned');
    await expect(page.getByText('there is no signature to check')).toBeVisible();
    // Clicking inside the panel is the guard visibility checks can't give:
    // an element clipped away by an overflow ancestor still reads as
    // "visible", but its hit-target is gone and this click fails.
    await panel.getByRole('button', { name: 'Dismiss' }).click();
    await expect(page.getByTestId('verify-panel')).toHaveCount(0);
  });

  test('a signed message shows what the server actually answered', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEUNCHECKED0000000001',
      from: 'someone',
      text: 'a message with a signature on it',
    });
    await expectMessage(page, 'a message with a signature on it');

    await requestVerify(page, 'a message with a signature on it');
    const panel = page.getByTestId('verify-panel');
    await expect(panel).not.toHaveAttribute('data-verdict', 'checking', { timeout: 10_000 });
    // Nothing on this server ever signed that id, so the honest answer is
    // that it cannot be checked — and it must not read as verified.
    await expect(panel).toHaveAttribute('data-verdict', 'unverifiable');
    await expect(page.getByText('Could not be checked here')).toBeVisible();
    await panel.getByRole('button', { name: 'Dismiss' }).click();
    await expect(page.getByTestId('verify-panel')).toHaveCount(0);
  });

  test('the panel stays inside the viewport wherever the request came from', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEVIEWPORTEDGE0000001',
      from: 'someone',
      text: 'verify me from the far edge',
    });
    await expectMessage(page, 'verify me from the far edge');

    // Ask from the bottom-right corner of the row — the spot that pushed the
    // old panel off the right edge of the screen.
    const row = page.locator('.msg-full', { hasText: 'verify me from the far edge' }).first();
    const box = await row.boundingBox();
    if (!box) throw new Error('row has no box');
    await row.click({ button: 'right', position: { x: box.width - 4, y: box.height - 4 } });
    await page.getByRole('button', { name: /Verify Signature/ }).click();

    const panel = page.getByTestId('verify-panel');
    await expect(panel).toBeVisible();
    const pbox = await panel.boundingBox();
    const viewport = page.viewportSize();
    if (!pbox || !viewport) throw new Error('panel or viewport has no box');
    expect(pbox.x, 'panel must not start left of the viewport').toBeGreaterThanOrEqual(0);
    expect(pbox.y, 'panel must not start above the viewport').toBeGreaterThanOrEqual(0);
    expect(pbox.x + pbox.width, 'panel must not run off the right edge').toBeLessThanOrEqual(viewport.width);
    expect(pbox.y + pbox.height, 'panel must not run off the bottom edge').toBeLessThanOrEqual(viewport.height);
    await panel.getByRole('button', { name: 'Dismiss' }).click();
  });

  test('only one panel is ever open, and clicking away dismisses it', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEONLYONEA0000000001',
      from: 'someone',
      text: 'first candidate for a verdict',
    });
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEONLYONEB0000000002',
      from: 'someoneelse',
      text: 'second candidate for a verdict',
    });
    await expectMessage(page, 'second candidate for a verdict');

    await requestVerify(page, 'first candidate for a verdict');
    await expect(page.getByTestId('verify-panel')).toHaveCount(1);

    // The open panel covers the neighbouring row's text, so the second
    // request comes from the row's right edge — as a real hand would. The
    // mousedown of that right-click is itself the click-away that closes the
    // first panel.
    const second = page.locator('.msg-full', { hasText: 'second candidate for a verdict' }).first();
    const box = await second.boundingBox();
    if (!box) throw new Error('row has no box');
    await second.click({ button: 'right', position: { x: box.width - 8, y: box.height / 2 } });
    await page.getByRole('button', { name: /Verify Signature/ }).click();
    await expect(
      page.getByTestId('verify-panel'),
      'a second request replaces the first panel instead of stacking on it',
    ).toHaveCount(1);

    await page.getByTestId('message-list').click({ position: { x: 10, y: 10 } });
    await expect(page.getByTestId('verify-panel')).toHaveCount(0);
  });

  test('a check that answers invalid marks the row — and only that answer does', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEINVALIDMARK0000001',
      from: 'someone',
      text: 'a signature that will not hold up',
    });
    await expectMessage(page, 'a signature that will not hold up');

    // The server-side "invalid" answer essentially never occurs in the wild,
    // so it is staged: the endpoint is mocked, everything downstream is real.
    await page.route('**/api/v1/verify/**', (route) =>
      route.fulfill({ json: { verification: { verdict: 'invalid', verified_by: 'client-session-key' } } }),
    );

    await requestVerify(page, 'a signature that will not hold up');
    const panel = page.getByTestId('verify-panel');
    await expect(panel).toHaveAttribute('data-verdict', 'invalid', { timeout: 10_000 });
    await expect(page.getByText('Does not match its signing key')).toBeVisible();
    await panel.getByRole('button', { name: 'Dismiss' }).click();

    await expect(
      page.getByTestId('sig-invalid-mark'),
      'the row wears the verdict after the panel is gone',
    ).toHaveCount(1);
  });

  test('a follow-up row offers the same request', async ({ page }) => {
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

    await requestVerify(page, 'second thing said');
    await expect(page.getByTestId('verify-panel')).toHaveCount(1);
    await page.getByTestId('verify-panel').getByRole('button', { name: 'Dismiss' }).click();
  });

  test('an encrypted message still shows what it is', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(page, channel, {
      id: '01JBADGEENCRYPTED00000000001',
      from: 'someone',
      text: 'unreadable to the server',
      encrypted: true,
    });
    await expectMessage(page, 'unreadable to the server');

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
