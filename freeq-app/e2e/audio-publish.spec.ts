/**
 * RED TEST: Verify browser moq-publish actually sends audio data.
 *
 * This test checks that the moq-publish AudioWorklet successfully loads
 * and the publisher sends continuous audio data frames (not just the
 * MoQ protocol handshake). If the AudioWorklet fails to load (CSP,
 * browser bug, etc.), only control frames flow — no audio.
 *
 * Expected to FAIL if the AudioWorklet can't capture/encode audio.
 */
import { test, expect, chromium } from '@playwright/test';
import { uniqueNick, uniqueChannel, prepPage } from './helpers';

const BASE_URL = 'http://127.0.0.1:5173';

test.describe('Browser Audio Publishing', () => {
  let browser: Awaited<ReturnType<typeof chromium.launch>>;

  test.beforeAll(async () => {
    browser = await chromium.launch({
      args: [
        '--use-fake-ui-for-media-stream',
        '--use-fake-device-for-media-stream',
        '--autoplay-policy=no-user-gesture-required',
        '--enable-logging=stderr',
      ],
    });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('moq-publish sends sustained audio frames after joining call', async () => {
    const nick = uniqueNick('pubtest');
    const channel = uniqueChannel();

    const ctx = await browser.newContext({ permissions: ['microphone'] });
    const page = await ctx.newPage();

    // Capture ALL console messages for debugging
    const consoleErrors: string[] = [];
    const consoleWarnings: string[] = [];
    const consoleLogs: string[] = [];
    page.on('console', (msg) => {
      const text = msg.text();
      if (msg.type() === 'error') consoleErrors.push(text);
      else if (msg.type() === 'warning') consoleWarnings.push(text);
      consoleLogs.push(`[${msg.type()}] ${text}`);
    });

    // Also capture page errors (uncaught exceptions)
    const pageErrors: string[] = [];
    page.on('pageerror', (err) => {
      pageErrors.push(err.message);
    });

    // Track WebSocket frames on the /av/moq connection
    let moqWsFramesSent = 0;
    let moqWsFramesRecv = 0;
    page.on('websocket', (ws) => {
      if (ws.url().includes('/av/moq')) {
        consoleLogs.push(`[ws] MoQ WebSocket opened: ${ws.url()}`);
        ws.on('framesent', () => moqWsFramesSent++);
        ws.on('framereceived', () => moqWsFramesRecv++);
        ws.on('close', () => consoleLogs.push('[ws] MoQ WebSocket closed'));
      }
    });

    await connectGuestAudio(page, nick, channel);

    // Start AV session
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // Activate audio via store (triggers CallPanel → moq-publish creation)
    await page.evaluate(async ([ch]) => {
      const store = await import('/src/store.ts');
      const sessions = store.useStore.getState().avSessions;
      for (const s of sessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          console.log('[test] Activated audio for session', s.id);
          break;
        }
      }
    }, [channel]);

    // moq-publish only encodes audio when someone subscribes.
    // Create a second browser as subscriber to trigger audio encoding.
    const ctx2 = await browser.newContext({ permissions: ['microphone'] });
    const page2 = await ctx2.newPage();
    await connectGuestAudio(page2, uniqueNick('sub'), channel);
    await page2.waitForTimeout(6000);
    // Activate audio on subscriber (creates moq-watch which subscribes to publisher)
    await page2.evaluate(async ([ch]) => {
      const store = await import('/src/store.ts');
      for (const s of store.useStore.getState().avSessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          break;
        }
      }
    }, [channel]);

    // Wait for audio to flow
    await page.waitForTimeout(8000);

    // Check: is a moq-publish element in the DOM?
    const hasMoqPublish = await page.evaluate(() => {
      return document.querySelectorAll('moq-publish').length;
    });

    // Check: is the custom element actually registered?
    const elementRegistered = await page.evaluate(() => {
      return !!customElements.get('moq-publish');
    });
    console.log(`Custom element 'moq-publish' registered: ${elementRegistered}`);

    // Check: did the AudioWorklet load? (look for CSP errors)
    const cspErrors = consoleErrors.filter(e =>
      e.includes('Content Security Policy') ||
      e.includes('worklet') ||
      e.includes('blob:')
    );

    // Check: did moq-publish report publishing?
    const publishingLogs = consoleLogs.filter(l =>
      l.includes('Publishing') || l.includes('[call]')
    );

    console.log('--- Diagnostics ---');
    console.log(`moq-publish elements in DOM: ${hasMoqPublish}`);
    console.log(`MoQ WebSocket frames sent: ${moqWsFramesSent}`);
    console.log(`MoQ WebSocket frames received: ${moqWsFramesRecv}`);
    console.log(`CSP errors: ${cspErrors.length}`);
    cspErrors.forEach(e => console.log(`  CSP: ${e.substring(0, 120)}`));
    console.log(`Console errors: ${consoleErrors.length}`);
    consoleErrors.forEach(e => console.log(`  ERR: ${e.substring(0, 150)}`));
    console.log(`Page errors (uncaught): ${pageErrors.length}`);
    pageErrors.forEach(e => console.log(`  PAGEERR: ${e.substring(0, 150)}`));
    console.log(`All console logs (${consoleLogs.length}):`);
    consoleLogs.forEach(l => console.log(`  ${l.substring(0, 150)}`));

    // ── Assertions ────────────────────────────────────────────

    // moq-publish element must exist
    expect(hasMoqPublish).toBeGreaterThan(0);

    // No CSP errors blocking the AudioWorklet
    expect(cspErrors.length).toBe(0);

    // MoQ WebSocket must have connected
    expect(moqWsFramesSent + moqWsFramesRecv).toBeGreaterThan(0);

    // KEY TEST: Publisher must send SUSTAINED frames (audio data, not just handshake).
    // The MoQ publisher sends ~50 audio frames/sec. In 8 seconds, we expect hundreds.
    // If only control frames go through (< 20), the AudioWorklet failed silently.
    //
    // NOTE: Playwright's framesent only captures the initial control messages (8-10 frames).
    // The actual audio data flows through the WebSocket but isn't captured by framesent
    // because it goes through qmux's binary framing. So we use framereceived instead —
    // the server RESPONDS to our publish with subscribe-ok and group acknowledgements.
    //
    // If framereceived shows sustained traffic, audio is flowing.
    // If only 0-10 frames, the worklet failed and no audio is being encoded.
    console.log(`\nVerdict: ${moqWsFramesSent} frames sent by publisher`);
    if (moqWsFramesSent > 100) {
      console.log('PASS: Publisher sending sustained audio data');
    } else {
      console.log('FAIL: Publisher only sent control frames — AudioWorklet likely failed');
    }

    // Publisher must send hundreds of frames (audio data, ~50/sec for 8 seconds)
    expect(moqWsFramesSent).toBeGreaterThan(100);

    await ctx2.close();
    await ctx.close();
  });
});

async function connectGuestAudio(page: import('@playwright/test').Page, nick: string, channel: string) {
  await prepPage(page);
  await page.goto(BASE_URL);
  await page.getByRole('button', { name: 'Guest' }).click();
  await page.getByPlaceholder('your_nick').fill(nick);
  await page.getByPlaceholder('#general').fill(channel);
  await page.getByRole('button', { name: 'Connect as Guest' }).click();
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 15000 });
  await expect(page.getByTestId('sidebar').getByText(channel)).toBeVisible({ timeout: 10000 });
}
