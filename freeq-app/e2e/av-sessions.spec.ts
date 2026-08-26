/**
 * E2E tests for AV session lifecycle.
 *
 * Tests the AV session control plane:
 * - Starting a session (via client.ts rawCommand)
 * - Session visibility in REST API
 * - Participant tracking
 * - Session cleanup
 *
 * These don't test actual audio (no mic in CI) — they verify the session
 * state management that the call UI depends on.
 */
import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, connectSecondUser, expectSystemMessage, startAvSessionRaw } from './helpers';

const API_BASE = 'http://127.0.0.1:8080';

/** Send a raw IRC command via the client's rawCommand function */
async function sendRawCommand(page: import('@playwright/test').Page, command: string) {
  await page.evaluate((cmd) => {
    // Access the IRC client module — it's imported in the global scope
    // @ts-ignore
    const { rawCommand } = window.__freeqIrcClient || {};
    if (rawCommand) rawCommand(cmd);
  }, command);
}

/** Send a TAGMSG via the compose box using the /quote or direct approach */
async function sendTagmsg(page: import('@playwright/test').Page, channel: string, tag: string) {
  // Use page.evaluate to call rawCommand directly from the client module
  await page.evaluate(([ch, t]) => {
    // The IRC client exports rawCommand — we can access it via the store's internal reference
    const ws = (window as unknown as { __freeqWs?: WebSocket }).__freeqWs;
    if (ws && ws.readyState === 1) {
      ws.send(`@${t} TAGMSG ${ch}\r\n`);
    }
  }, [channel, tag]);
}

test.describe('AV Session REST API', () => {

  test('sessions list is initially empty for a new channel', async ({ page, request }) => {
    const channel = uniqueChannel();
    // The endpoint fails closed on a channel it has never heard of, so the
    // channel has to exist before "no call in it yet" is answerable.
    await connectGuest(page, uniqueNick('av'), channel);
    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.active).toBeNull();
  });

  test('sessions list endpoint returns valid structure', async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/sessions`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.sessions)).toBe(true);
  });

  test('session API returns 404 for nonexistent session', async ({ request }) => {
    const resp = await request.get(`${API_BASE}/api/v1/sessions/nonexistent-id`);
    expect(resp.status()).toBe(404);
  });
});

test.describe('AV Session Lifecycle via IRC', () => {

  test('av-start creates session visible in API', async ({ page, request }) => {
    const nick = uniqueNick('av');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);

    await startAvSessionRaw(page, channel);

    // Wait for session to be created
    await page.waitForTimeout(2000);

    // Verify via API
    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.active).toBeTruthy();
    expect(data.active.channel).toBe(channel);
    expect(data.active.state).toBe('Active');
  });

  test('av-start creates session with iroh ticket', async ({ page, request }) => {
    const nick = uniqueNick('av');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);

    await startAvSessionRaw(page, channel);

    await page.waitForTimeout(2000);

    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const data = await resp.json();
    expect(data.active).toBeTruthy();
    expect(data.active.iroh_ticket).toBeTruthy();
    expect(typeof data.active.iroh_ticket).toBe('string');
    expect(data.active.iroh_ticket.length).toBeGreaterThan(20);
  });

  test('second user joins and appears in participants', async ({ page, browser, request }) => {
    const nick1 = uniqueNick('av1');
    const nick2 = uniqueNick('av2');
    const channel = uniqueChannel();

    // User 1 starts session
    await connectGuest(page, nick1, channel);
    await startAvSessionRaw(page, channel);
    await page.waitForTimeout(2000);

    // User 2 connects and joins
    // av-join has to name the session it joins; a bare TAGMSG routes nowhere,
    // which is why the client refuses to send one.
    const started = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const sessionId = (await started.json()).active.id;
    const { page: page2, ctx } = await connectSecondUser(browser, nick2, channel);
    await page2.evaluate(async ([ch, id]) => {
      const mod = await import('/src/irc/client.ts');
      mod.joinAvSession(ch, id as string);
    }, [channel, sessionId]);
    await page2.waitForTimeout(2000);

    // Check API
    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const data = await resp.json();
    expect(data.active.participant_count).toBeGreaterThanOrEqual(2);
    const nicks = data.active.participants.map((p: { nick: string }) => p.nick);
    expect(nicks).toContain(nick1);
    expect(nicks).toContain(nick2);

    await ctx.close();
  });

  test('disconnecting user reduces participant count', async ({ page, browser, request }) => {
    const nick1 = uniqueNick('av1');
    const nick2 = uniqueNick('av2');
    const channel = uniqueChannel();

    await connectGuest(page, nick1, channel);
    await startAvSessionRaw(page, channel);
    await page.waitForTimeout(2000);

    // av-join has to name the session it joins; a bare TAGMSG routes nowhere,
    // which is why the client refuses to send one.
    const started = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const sessionId = (await started.json()).active.id;
    const { page: page2, ctx } = await connectSecondUser(browser, nick2, channel);
    await page2.evaluate(async ([ch, id]) => {
      const mod = await import('/src/irc/client.ts');
      mod.joinAvSession(ch, id as string);
    }, [channel, sessionId]);
    await page2.waitForTimeout(2000);

    // Verify 2 participants
    let resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    let data = await resp.json();
    expect(data.active.participant_count).toBeGreaterThanOrEqual(2);

    // Disconnect user 2
    await ctx.close();
    await page.waitForTimeout(3000);

    // Verify participant count decreased
    resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    data = await resp.json();
    if (data.active) {
      expect(data.active.participant_count).toBeLessThan(2);
    }
    // Active could be null if session auto-ended
  });

  test('session auto-ends when all participants leave', async ({ page, request }) => {
    const nick = uniqueNick('av');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);
    await startAvSessionRaw(page, channel);
    await page.waitForTimeout(2000);

    // Get session ID
    let resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    let data = await resp.json();
    const sessionId = data.active?.id;
    expect(sessionId).toBeTruthy();

    // Disconnect (closes WebSocket)
    await page.close();
    await new Promise(r => setTimeout(r, 5000));

    // Session should be ended
    resp = await request.get(`${API_BASE}/api/v1/sessions/${sessionId}`);
    if (resp.ok()) {
      data = await resp.json();
      // Ended or no participants
      const isEnded = data.state === 'Ended' || data.state === 'ended' || data.participant_count === 0;
      expect(isEnded).toBe(true);
    }
    // 404 is also fine (fully cleaned up)
  });
});
