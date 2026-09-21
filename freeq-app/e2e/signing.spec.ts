/**
 * E2E: what a message says about who wrote it.
 *
 * Runs against a local freeq-server (see playwright.config.ts). Point
 * FREEQ_WEB at a real deployment to run the same flows there.
 *
 * The check runs on this device as the line arrives: the SDK rebuilds what
 * was signed and looks the signer's key up. A row wears the mark its verdict
 * earns — the lock when the sender's own device signed, or the ⚠ after a
 * check that did not hold — and the panel behind "Verify Signature…" says
 * what the check established, asking the server nothing.
 */
import { test, expect, type Page } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, sendMessage, expectMessage } from './helpers';
// The verdict wording lives in one model every client shares (the SDK reads
// spec/verdict-model.json). Assert from it, not from a copy: rewording a
// verdict is not a regression.
import { verdictCopy } from '../src/lib/verify-signature';

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
  verdict?: { state: string; layer?: string; kid?: string; keySource?: string },
) {
  await page.evaluate(
    async ({ channel, msg, verdict }) => {
      const { useStore } = await import('/src/store.ts');
      const { recordVerdict } = await import('/src/lib/verify-signature.ts');
      useStore.getState().addMessage(channel, {
        ...msg,
        timestamp: new Date(),
        tags: { '+freeq.at/sig': 'ed25519:kid:signature', msgid: msg.id },
      });
      // The SDK settles a verdict for a line that came off the wire; this one
      // was put straight into the store, so its verdict is put there too.
      if (verdict) recordVerdict(msg.id, verdict);
    },
    { channel, msg, verdict },
  );
}

/** Right-click a message and choose "Verify Signature…". */
async function requestVerify(page: Page, text: string) {
  await page.getByTestId('message-list').getByText(text).click({ button: 'right' });
  await page.getByRole('button', { name: /Verify Signature/ }).click();
}

test.describe('signature verification', () => {
  test('a line whose key is still being looked up wears nothing', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(
      page,
      channel,
      {
        id: '01JBADGERESTINGSILENT000001',
        from: 'someone',
        text: 'a signed message wearing nothing',
      },
      { state: 'pending', kid: 'kid' },
    );
    await expectMessage(page, 'a signed message wearing nothing');

    await expect(page.getByTestId('verify-panel')).toHaveCount(0);
    await expect(page.getByTestId('sig-device-mark')).toHaveCount(0);
    await expect(
      page.getByTestId('sig-invalid-mark'),
      'the ⚠ exists only after a check that did not hold',
    ).toHaveCount(0);
  });

  test('the mark a row wears is the verdict the check reached', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(
      page,
      channel,
      { id: '01JBADGEPUBLISHEDKEY000001', from: 'someone', text: 'signed on their own device' },
      { state: 'device', layer: 'published', kid: 'kid1', keySource: 'IdentityRecord' },
    );
    await receiveSignedMessage(
      page,
      channel,
      { id: '01JBADGEVOUCHEDKEY00000001', from: 'someone', text: 'signed under a vouched key' },
      { state: 'device', layer: 'vouched', kid: 'kid2', keySource: 'OriginServer' },
    );
    await receiveSignedMessage(
      page,
      channel,
      { id: '01JBADGESERVERSIGNED000001', from: 'someone', text: 'signed by the server' },
      { state: 'server', kid: 'kid3' },
    );
    await expectMessage(page, 'signed by the server');

    const marks = page.getByTestId('sig-device-mark');
    await expect(marks).toHaveCount(2);
    await expect(marks.first()).toHaveAttribute('data-layer', 'published');
    await expect(marks.nth(1)).toHaveAttribute('data-layer', 'vouched');
    await expect(marks.first()).toHaveAttribute(
      'title',
      verdictCopy('device', 'message', 'published').line,
    );
    // The lock alone, with no word beside it.
    await expect(marks.first()).toHaveText('🔒');
    // A signature the server made on the sender's behalf wears nothing.
    await expect(page.getByTestId('sig-server-mark')).toHaveCount(0);
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

  test('a signed message shows what the check found', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    await receiveSignedMessage(
      page,
      channel,
      {
        id: '01JBADGEUNCHECKED0000000001',
        from: 'someone',
        text: 'a message with a signature on it',
      },
      { state: 'unverifiable', kid: 'kid' },
    );
    await expectMessage(page, 'a message with a signature on it');

    await requestVerify(page, 'a message with a signature on it');
    const panel = page.getByTestId('verify-panel');
    // No source held the key, so the honest answer is that it cannot be
    // checked — and it must not read as verified.
    await expect(panel).toHaveAttribute('data-verdict', 'unverifiable');
    await expect(panel.getByText(verdictCopy('unverifiable').heading)).toBeVisible();
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
    // A signature that does not hold essentially never occurs in the wild, so
    // the verdict is staged; everything downstream of it is real.
    await receiveSignedMessage(
      page,
      channel,
      {
        id: '01JBADGEINVALIDMARK0000001',
        from: 'someone',
        text: 'a signature that will not hold up',
      },
      { state: 'invalid', kid: 'kid' },
    );
    await expectMessage(page, 'a signature that will not hold up');

    await requestVerify(page, 'a signature that will not hold up');
    const panel = page.getByTestId('verify-panel');
    await expect(panel).toHaveAttribute('data-verdict', 'invalid');
    await expect(panel.getByText(verdictCopy('invalid').heading)).toBeVisible();
    await panel.getByRole('button', { name: 'Dismiss' }).click();

    await expect(
      page.getByTestId('sig-invalid-mark'),
      'the row wears the verdict after the panel is gone',
    ).toHaveCount(1);
  });

  test('a key the account has not got leaves the room working and says so', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    // What a broker that refuses to publish the key leaves behind. The
    // refusal itself is the SDK's (client.device-key.test.ts): this rig has
    // no broker and no identity to publish for.
    await page.evaluate(async () => {
      const client = await import('/src/irc/client.ts');
      client.__setKeyUnpublishedForTests();
    });

    // The bar holding the sentence and its buttons: the innermost div with
    // that text.
    const banner = page.locator('div', { hasText: 'Security upgrade available:' }).last();
    await expect(banner).toBeVisible();
    await expect(page.getByText('so others can verify messages from this device')).toBeVisible();

    // The session keeps working, which is the whole point of not blocking on
    // enrollment.
    await sendMessage(page, 'still talking with an unpublished key');
    await expectMessage(page, 'still talking with an unpublished key');

    // Dismissable, and dismissed for this session only.
    await banner.getByRole('button', { name: '✕' }).click();
    await expect(banner).toHaveCount(0);
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

  test('a run from one nick breaks wherever the row mark changes', async ({ page }, testInfo) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    const published = { state: 'device', layer: 'published', kid: 'kidpub', keySource: 'IdentityRecord' };
    const lines = [
      { id: '01JBADGEMARKRUN00000000001', text: 'run line one, published key', verdict: published },
      { id: '01JBADGEMARKRUN00000000002', text: 'run line two, published key', verdict: published },
      {
        id: '01JBADGEMARKRUN00000000003',
        text: 'run line three, vouched key',
        verdict: { state: 'device', layer: 'vouched', kid: 'kidvouch', keySource: 'OriginServer' },
      },
      {
        id: '01JBADGEMARKRUN00000000004',
        text: 'run line four, retired key',
        verdict: { state: 'retired', kid: 'kidpub', keySource: 'IdentityRecord' },
      },
      { id: '01JBADGEMARKRUN00000000005', text: 'run line five, published key again', verdict: published },
    ];
    for (const l of lines) {
      await receiveSignedMessage(page, channel, { id: l.id, from: 'someone', text: l.text }, l.verdict);
    }
    await expectMessage(page, lines[4].text);

    const list = page.getByTestId('message-list');
    const header = (text: string) => list.locator('.msg-full', { hasText: text });
    const followUp = (text: string) => list.locator('div.group:not(.msg-full)', { hasText: text });

    // Lines one and two share a header, which wears the full lock once.
    const first = header(lines[0].text);
    await expect(first).toHaveCount(1);
    await expect(first).not.toContainText(lines[1].text);
    await expect(first.getByTestId('sig-device-mark')).toHaveAttribute('data-layer', 'published');
    await expect(header(lines[1].text)).toHaveCount(0);
    const second = followUp(lines[1].text);
    await expect(second).toHaveCount(1);
    await expect(second.getByTestId('sig-device-mark')).toHaveCount(0);
    await expect(second.getByTestId('sig-invalid-mark')).toHaveCount(0);

    // Each change of mark starts its own header, carrying the new mark.
    const third = header(lines[2].text);
    await expect(third).toHaveCount(1);
    await expect(third.getByTestId('sig-device-mark')).toHaveAttribute('data-layer', 'vouched');
    await expect(third.getByTestId('sig-device-mark')).toHaveClass(/opacity-30/);

    const fourth = header(lines[3].text);
    await expect(fourth).toHaveCount(1);
    await expect(fourth.getByTestId('sig-invalid-mark')).toHaveCount(1);
    await expect(fourth.getByTestId('sig-device-mark')).toHaveCount(0);

    const fifth = header(lines[4].text);
    await expect(fifth).toHaveCount(1);
    await expect(fifth.getByTestId('sig-device-mark')).toHaveAttribute('data-layer', 'published');
    await expect(fifth.getByTestId('sig-device-mark')).not.toHaveClass(/opacity-30/);

    const shot = testInfo.outputPath('grouping-by-mark.png');
    await list.screenshot({ path: shot });
    await testInfo.attach('grouping-by-mark', { path: shot, contentType: 'image/png' });
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
