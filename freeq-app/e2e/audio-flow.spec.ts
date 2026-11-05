/**
 * Full E2E audio flow test.
 *
 * Verifies actual audio data (WebSocket frames) flows between browser clients
 * through the MoQ SFU. Uses Chromium's fake audio device which generates a
 * 440Hz sine wave.
 *
 * Requires freeq-server running on 127.0.0.1:8080 with av-native.
 */
import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test';
import { uniqueNick, uniqueChannel, prepPage } from './helpers';

const API_BASE = 'http://127.0.0.1:8080';
const BASE_URL = 'http://127.0.0.1:5173';

async function connectGuestAudio(page: Page, nick: string, channel: string) {
  await prepPage(page);
  await page.goto(BASE_URL);
  await page.getByRole('button', { name: 'Guest' }).click();
  await page.getByPlaceholder('your_nick').fill(nick);
  await page.getByPlaceholder('#general').fill(channel);
  await page.getByRole('button', { name: 'Connect as Guest' }).click();
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 15000 });
  await expect(page.getByTestId('sidebar').getByText(channel)).toBeVisible({ timeout: 10000 });
}

test.describe('Audio Flow E2E', () => {
  let browser: Awaited<ReturnType<typeof chromium.launch>>;

  test.beforeAll(async () => {
    browser = await chromium.launch({
      args: [
        '--use-fake-ui-for-media-stream',
        '--use-fake-device-for-media-stream',
        '--autoplay-policy=no-user-gesture-required',
      ],
    });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('two browsers exchange audio via MoQ SFU — WebSocket frames flow both directions', async () => {
    const channel = uniqueChannel();
    const nick1 = uniqueNick('pub');
    const nick2 = uniqueNick('sub');

    // ── Publisher ──────────────────────────────────────────────
    const ctx1 = await browser.newContext({ permissions: ['microphone'] });
    const page1 = await ctx1.newPage();

    // Track MoQ WebSocket frames
    const wsSent1: number[] = [];
    const wsRecv1: number[] = [];
    page1.on('websocket', (ws) => {
      if (ws.url().includes('/av/moq')) {
        ws.on('framesent', () => wsSent1.push(Date.now()));
        ws.on('framereceived', () => wsRecv1.push(Date.now()));
      }
    });

    await connectGuestAudio(page1, nick1, channel);

    // Start AV session
    await page1.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page1.waitForTimeout(2000);

    // Activate audio
    await page1.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      const store = await import('/src/store.ts');
      // Set active session from store
      const sessions = store.useStore.getState().avSessions;
      for (const s of sessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          break;
        }
      }
    }, [channel]);
    await page1.waitForTimeout(5000);

    // ── Subscriber ────────────────────────────────────────────
    const ctx2 = await browser.newContext({ permissions: ['microphone'] });
    const page2 = await ctx2.newPage();

    const wsRecv2: number[] = [];
    page2.on('websocket', (ws) => {
      if (ws.url().includes('/av/moq')) {
        ws.on('framereceived', () => wsRecv2.push(Date.now()));
      }
    });

    await connectGuestAudio(page2, nick2, channel);

    // Wait for session discovery via REST API polling
    await page2.waitForTimeout(6000);

    // Activate audio on subscriber too
    await page2.evaluate(async ([ch]) => {
      const store = await import('/src/store.ts');
      const sessions = store.useStore.getState().avSessions;
      for (const s of sessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          break;
        }
      }
    }, [channel]);

    // Wait for MoQ connections and audio frames to flow
    await page2.waitForTimeout(8000);

    // ── Verify ────────────────────────────────────────────────
    console.log(`Publisher: sent=${wsSent1.length} recv=${wsRecv1.length}`);
    console.log(`Subscriber: recv=${wsRecv2.length}`);

    // Publisher should have sent frames (moq-publish publishing audio)
    expect(wsSent1.length).toBeGreaterThan(0);

    // Subscriber should have received frames (moq-watch receiving audio)
    expect(wsRecv2.length).toBeGreaterThan(0);

    console.log(`PASS: Publisher sent ${wsSent1.length} MoQ frames, subscriber received ${wsRecv2.length} frames`);

    await ctx1.close();
    await ctx2.close();
  });

  test('subscriber receives sustained audio over time (not just initial burst)', async () => {
    const channel = uniqueChannel();
    const nick1 = uniqueNick('sender');
    const nick2 = uniqueNick('listener');

    // Publisher
    const ctx1 = await browser.newContext({ permissions: ['microphone'] });
    const page1 = await ctx1.newPage();
    await connectGuestAudio(page1, nick1, channel);

    await page1.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page1.waitForTimeout(2000);

    await page1.evaluate(async ([ch]) => {
      const store = await import('/src/store.ts');
      for (const s of store.useStore.getState().avSessions.values()) {
        if (s.channel?.toLowerCase() === ch.toLowerCase() && s.state === 'active') {
          store.useStore.getState().setActiveAvSession(s.id);
          store.useStore.getState().setAvAudioActive(true);
          break;
        }
      }
    }, [channel]);
    await page1.waitForTimeout(3000);

    // Subscriber — track frames received over time
    const ctx2 = await browser.newContext({ permissions: ['microphone'] });
    const page2 = await ctx2.newPage();
    const frameTimes: number[] = [];
    page2.on('websocket', (ws) => {
      if (ws.url().includes('/av/moq')) {
        ws.on('framereceived', () => frameTimes.push(Date.now()));
      }
    });

    await connectGuestAudio(page2, nick2, channel);
    await page2.waitForTimeout(6000);

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

    // Wait for initial connection + audio flow
    await page2.waitForTimeout(5000);
    const earlyCount = frameTimes.length;
    console.log(`Frames received after 5s: ${earlyCount}`);

    // Wait 3 more seconds — frames should keep coming
    await page2.waitForTimeout(3000);
    const totalCount = frameTimes.length;
    const lateFrames = totalCount - earlyCount;
    console.log(`Frames received after 8s: ${totalCount} (${lateFrames} new in last 3s)`);

    // Should receive hundreds of frames total, with sustained flow
    expect(totalCount).toBeGreaterThan(100);
    expect(lateFrames).toBeGreaterThan(50);

    console.log(`PASS: ${totalCount} total frames received, ${lateFrames} in last 3s (sustained audio flow)`);

    await ctx1.close();
    await ctx2.close();
  });
});
