/**
 * E2E: screen sharing between two real browsers over the real MoQ relay.
 *
 * Browser A joins a call and shares its screen (Chromium auto-picks the
 * virtual display via --auto-select-desktop-capture-source). Browser B,
 * in the same call, must reveal A's spotlight screen tile when the
 * `…/screen` broadcast goes live — and hide it again when A stops.
 *
 * This exercises the full path the unit tests stub out: real
 * getDisplayMedia, real moq-publish encode, the server's /av/moq relay,
 * and moq-watch's status signal on the viewer.
 */
import { test, expect, chromium } from '@playwright/test';
import { uniqueNick, uniqueChannel, prepPage } from './helpers';

const BASE_URL = 'http://127.0.0.1:5173';

test.describe('Screen sharing', () => {
  let browser: Awaited<ReturnType<typeof chromium.launch>>;

  test.beforeAll(async () => {
    browser = await chromium.launch({
      // Full Chromium (new headless): the headless shell has no screen
      // surface, so getDisplayMedia would fail there.
      channel: 'chromium',
      args: [
        '--use-fake-ui-for-media-stream',
        '--use-fake-device-for-media-stream',
        '--auto-select-desktop-capture-source=Entire screen',
        '--autoplay-policy=no-user-gesture-required',
      ],
    });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('viewer sees the spotlight tile while the sharer shares, and it clears on stop', async () => {
    test.setTimeout(120_000);
    const channel = uniqueChannel();
    const sharerNick = uniqueNick('shr');
    const viewerNick = uniqueNick('vwr');

    // ── Sharer joins and starts the call ─────────────────────────
    const ctxA = await browser.newContext({ permissions: ['microphone'] });
    const sharer = await ctxA.newPage();
    await connectGuest(sharer, sharerNick, channel);

    await sharer.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await sharer.waitForTimeout(1500);
    await activateCall(sharer, channel);

    // ── Viewer joins the same call ───────────────────────────────
    const ctxB = await browser.newContext({ permissions: ['microphone'] });
    const viewer = await ctxB.newPage();
    await connectGuest(viewer, viewerNick, channel);
    await viewer.waitForTimeout(1500);
    await activateCall(viewer, channel);

    // Both call panels up; viewer discovers the sharer via the roster poll.
    await expect(sharer.locator('button[title="Share screen"]')).toBeVisible({ timeout: 15_000 });
    await expect(viewer.locator(`moq-watch[name*="${sharerNick}"]`).first()).toBeAttached({
      timeout: 20_000,
    });

    // Viewer's screen watch exists but its tile is hidden (no share yet).
    const viewerScreenWatch = viewer.locator(
      `moq-watch[name*="${sharerNick}"][name$="/screen"]`,
    );
    await expect(viewerScreenWatch).toBeAttached({ timeout: 20_000 });
    await expect(viewer.getByText(`${sharerNick} — screen`)).toBeHidden();

    // ── Share ────────────────────────────────────────────────────
    await sharer.locator('button[title="Share screen"]').click();

    // Sharer: second publish element with source=screen + local preview.
    const screenPub = sharer.locator('moq-publish[name$="/screen"]');
    await expect(screenPub).toBeAttached({ timeout: 10_000 });
    await expect(screenPub).toHaveAttribute('source', 'screen');
    await expect(screenPub).toHaveAttribute('muted', '');
    await expect(sharer.getByText('You — screen')).toBeVisible({ timeout: 10_000 });

    // Viewer: spotlight tile must reveal once the broadcast announces live.
    await expect(viewer.getByText(`${sharerNick} — screen`)).toBeVisible({ timeout: 30_000 });

    // Sharer's camera/mic publisher is untouched. ([name] excludes the
    // moq-loader placeholder element, which has no broadcast name.)
    await expect(sharer.locator('moq-publish[name]:not([name$="/screen"])')).toBeAttached();

    // ── Stop ─────────────────────────────────────────────────────
    await sharer.locator('button[title="Stop sharing screen"]').click();
    await expect(sharer.locator('moq-publish[name$="/screen"]')).not.toBeAttached({
      timeout: 10_000,
    });
    // Viewer's tile hides again when the broadcast goes offline.
    await expect(viewer.getByText(`${sharerNick} — screen`)).toBeHidden({ timeout: 30_000 });

    await ctxA.close();
    await ctxB.close();
  });
});

async function connectGuest(
  page: import('@playwright/test').Page,
  nick: string,
  channel: string,
) {
  await prepPage(page);
  await page.goto(BASE_URL);
  await page.getByRole('button', { name: 'Guest' }).click();
  await page.getByPlaceholder('your_nick').fill(nick);
  await page.getByPlaceholder('#general').fill(channel);
  await page.getByRole('button', { name: 'Connect as Guest' }).click();
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('sidebar').getByText(channel)).toBeVisible({ timeout: 10_000 });
}

/** Activate the channel's live AV session (renders CallPanel + publisher). */
async function activateCall(page: import('@playwright/test').Page, channel: string) {
  await page.evaluate(
    async ([ch]) => {
      const store = await import('/src/store.ts');
      for (const s of store.useStore.getState().avSessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          break;
        }
      }
    },
    [channel],
  );
}
