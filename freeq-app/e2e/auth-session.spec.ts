/**
 * The first five minutes: signing in, staying signed in, and being told when
 * that fails.
 *
 * This path had no end-to-end coverage at all — 30 spec files, five of them on
 * scrollback, none on authentication — and it is where the product actually
 * broke. A refresh-token race bricked persistent sessions for six weeks in
 * 2026 (#33, fixed 2026-07-03 after it reached production), and a rejected
 * user was returned to the sign-in form with no message, so nobody could
 * report what happened.
 *
 * The broker's own concurrency is pinned in Rust
 * (`session_concurrent_calls_serialize_on_refresh_lock`). What is checked here
 * is the half a browser owns: how many times the app asks, what it does with
 * the answer, and what the user is told when the answer is "no".
 */
import { test, expect, type Page } from '@playwright/test';
import { prepPage, connectGuest, sendMessage, expectMessage } from './helpers';

const LS_BROKER_TOKEN = 'freeq-broker-token';
const LS_HANDLE = 'freeq-handle';

/** Arrive as a returning user: a stored broker token, as if signed in before. */
async function withStoredSession(page: Page) {
  await prepPage(page);
  await page.addInitScript(
    ([tokenKey, handleKey]) => {
      localStorage.setItem(tokenKey, 'e2e-stored-broker-token');
      localStorage.setItem(handleKey, 'someone.bsky.social');
    },
    [LS_BROKER_TOKEN, LS_HANDLE],
  );
}

test.describe('session restore', () => {
  test('a returning user asks the broker to restore the session exactly once', async ({ page }) => {
    // React StrictMode double-invokes effects, and each call rotates a
    // single-use refresh token upstream. Two calls per load is how the
    // original race got started.
    let calls = 0;
    await page.route('**/session', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      calls++;
      await route.fulfill({ status: 401, body: 'Session expired — re-authentication required' });
    });

    await withStoredSession(page);
    await page.goto('/');
    await expect(page.getByText(/session expired/i)).toBeVisible({ timeout: 15_000 });
    await page.waitForTimeout(2_000); // let any duplicate effect fire

    expect(calls, `POST /session was called ${calls} times for one page load`).toBe(1);
  });

  test('an expired session says so instead of silently showing the sign-in form', async ({ page }) => {
    await page.route('**/session', (route) =>
      route.request().method() === 'POST'
        ? route.fulfill({ status: 401, body: 'Session expired — re-authentication required' })
        : route.continue(),
    );

    await withStoredSession(page);
    await page.goto('/');

    // The message a user can act on, and repeat back to us.
    await expect(page.getByText(/session expired/i)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/sign in|guest/i).first()).toBeVisible();

    // A dead token must not be kept: retrying it can only fail again.
    expect(await page.evaluate((k) => localStorage.getItem(k), LS_BROKER_TOKEN)).toBeNull();
  });

  test('a broker that is down is reported, and does not discard the session', async ({ page }) => {
    await page.route('**/session', (route) =>
      route.request().method() === 'POST' ? route.abort('connectionrefused') : route.continue(),
    );

    await withStoredSession(page);
    await page.goto('/');

    // Some explanation, eventually — never an unexplained form.
    await expect(page.getByText(/unavailable|could not restore|try again/i)).toBeVisible({
      timeout: 25_000,
    });

    // A transient failure is not a reason to sign someone out.
    expect(await page.evaluate((k) => localStorage.getItem(k), LS_BROKER_TOKEN)).toBe(
      'e2e-stored-broker-token',
    );
  });
});

test.describe('staying connected', () => {
  test('a guest reload returns to sign-in, and the words they said survive', async ({ page }) => {
    // Guests deliberately do not persist: there is no credential to
    // re-present, and silently reclaiming a nick nobody proved they own is
    // worse than asking again. `adversarial.spec.ts` pins the same contract.
    // What must not happen is losing what they said — the session is
    // disposable, the conversation is not.
    const nick = `stay${Date.now().toString().slice(-6)}`;
    const channel = `#reload${Date.now().toString().slice(-6)}`;
    await connectGuest(page, nick, channel);
    await sendMessage(page, 'before the reload');
    await expectMessage(page, 'before the reload');

    await page.reload();
    await expect(page.getByRole('button', { name: 'Guest' })).toBeVisible({ timeout: 15_000 });

    // Rejoin the same room: the history is still there, and it still works.
    await connectGuest(page, nick, channel);
    await expectMessage(page, 'before the reload', 20_000);
    await sendMessage(page, 'after the reload');
    await expectMessage(page, 'after the reload');
  });

  test('a dropped connection reconnects and the room still works', async ({ page }) => {
    const nick = `drop${Date.now().toString().slice(-6)}`;
    const channel = `#drop${Date.now().toString().slice(-6)}`;
    await connectGuest(page, nick, channel);
    await sendMessage(page, 'before the drop');
    await expectMessage(page, 'before the drop');

    // Kill the transport under the app, the way a laptop lid or a tunnel does.
    await page.evaluate(() => {
      const ws = (window as unknown as { __freeqSocket?: WebSocket }).__freeqSocket;
      ws?.close();
    });
    await page.context().setOffline(true);
    await page.waitForTimeout(1_000);
    await page.context().setOffline(false);

    // It comes back on its own and the room is usable again.
    await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 30_000 });
    await sendMessage(page, 'after the drop');
    await expectMessage(page, 'after the drop', 30_000);
  });
});
