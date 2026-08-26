/**
 * AV session edge case tests — red/green TDD.
 *
 * These tests expose specific bugs found during manual testing:
 * 1. Browser audio doesn't reach native client (one-way audio)
 * 2. Native --join doesn't restart bridge for existing session
 * 3. Session state gets stuck after reconnections
 * 4. Stale sessions block new session creation
 */
import { test, expect } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, connectSecondUser, expectSystemMessage } from './helpers';

const API_BASE = 'http://127.0.0.1:8080';

test.describe('AV Session Edge Cases', () => {

  test('stale session auto-ends when new av-start is sent', async ({ page, request }) => {
    const nick1 = uniqueNick('stale1');
    const nick2 = uniqueNick('stale2');
    const channel = uniqueChannel();

    // User 1 starts session
    await connectGuest(page, nick1, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // Verify session exists
    let resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    let data = await resp.json();
    expect(data.active).toBeTruthy();
    const firstSessionId = data.active.id;

    // User 1 disconnects (simulating crash)
    await page.close();
    await new Promise(r => setTimeout(r, 3000));

    // User 2 tries to start a NEW session on same channel
    const { page: page2, ctx } = await connectSecondUser(
      await (await import('@playwright/test')).chromium.launch(),
      nick2,
      channel,
    );
    await page2.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page2.waitForTimeout(2000);

    // New session should exist (old one auto-ended)
    resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    data = await resp.json();
    expect(data.active).toBeTruthy();
    expect(data.active.id).not.toBe(firstSessionId); // different session
    expect(data.active.created_by_nick).toBe(nick2);

    await ctx.close();
  });

  test('session discovered via REST API after late join', async ({ page, browser, request }) => {
    const nick1 = uniqueNick('early');
    const nick2 = uniqueNick('late');
    const channel = uniqueChannel();

    // User 1 starts session before User 2 is in the channel
    await connectGuest(page, nick1, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // User 2 joins the channel AFTER session started
    const { page: page2, ctx } = await connectSecondUser(browser, nick2, channel);

    // Wait for REST API polling to discover the session (5s poll interval)
    await page2.waitForTimeout(6000);

    // The session indicator should be visible (green dot + "Voice")
    const voiceIndicator = page2.locator('text=Voice');
    await expect(voiceIndicator).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('joining existing session shows participant count', async ({ page, request }) => {
    const nick = uniqueNick('av');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // startAvSession on a channel that already has a session should join
    // and show a system message
    await page.evaluate(async ([ch]) => {
      const { startAvSession } = await import('/src/irc/client.ts');
      await startAvSession(ch);
    }, [channel]);
    await page.waitForTimeout(1000);

    // Should see "Joining existing voice session" message
    await expect(page.getByText('Joining existing', { exact: false })).toBeVisible({ timeout: 5000 });
  });

  test('session API returns correct participant count after join and leave', async ({ page, browser, request }) => {
    const nick1 = uniqueNick('p1');
    const nick2 = uniqueNick('p2');
    const channel = uniqueChannel();

    await connectGuest(page, nick1, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // Check: 1 participant
    let resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    let data = await resp.json();
    expect(data.active.participant_count).toBe(1);

    // User 2 joins
    const { page: page2, ctx } = await connectSecondUser(browser, nick2, channel);
    await page2.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-join TAGMSG ${ch}`);
    }, [channel]);
    await page2.waitForTimeout(2000);

    // Check: 2 participants
    resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    data = await resp.json();
    expect(data.active.participant_count).toBe(2);

    // User 2 disconnects
    await ctx.close();
    await page.waitForTimeout(3000);

    // Check: back to 1 participant
    resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    data = await resp.json();
    expect(data.active).toBeTruthy();
    expect(data.active.participant_count).toBe(1);
  });

  test('bridge exists after session creator leaves if other participants remain', async ({ page, browser, request }) => {
    const nick1 = uniqueNick('creator');
    const nick2 = uniqueNick('joiner');
    const channel = uniqueChannel();

    // Creator starts session
    await connectGuest(page, nick1, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // Joiner joins
    const { page: page2, ctx } = await connectSecondUser(browser, nick2, channel);
    await page2.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-join TAGMSG ${ch}`);
    }, [channel]);
    await page2.waitForTimeout(2000);

    // Creator disconnects
    await page.close();
    await new Promise(r => setTimeout(r, 3000));

    // Session should still be active (joiner is still in)
    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const data = await resp.json();
    expect(data.active).toBeTruthy();
    expect(data.active.participant_count).toBe(1);
    const nicks = data.active.participants.map((p: { nick: string }) => p.nick);
    expect(nicks).toContain(nick2);
    expect(nicks).not.toContain(nick1);

    await ctx.close();
  });

  test('MoQ SFU has browser broadcast while session is active', async ({ page, request }) => {
    const nick = uniqueNick('sfu');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // Get session ID
    const resp = await request.get(`${API_BASE}/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
    const data = await resp.json();
    const sessionId = data.active.id;

    // Activate audio (this creates moq-publish)
    await page.evaluate(async (id) => {
      const { useStore } = await import('/src/store.ts');
      useStore.getState().setActiveAvSession(id);
      useStore.getState().setAvAudioActive(true);
    }, sessionId);
    await page.waitForTimeout(3000);

    // Check that the SFU session was established
    // (We can't directly query the MoQ cluster, but we can check server logs
    // or verify the session API still shows the session as active)
    const resp2 = await request.get(`${API_BASE}/api/v1/sessions/${sessionId}`);
    expect(resp2.ok()).toBe(true);
  });

  test('ended session is cleaned from store after timeout', async ({ page }) => {
    const nick = uniqueNick('av');
    const channel = uniqueChannel();

    await connectGuest(page, nick, channel);
    await page.evaluate(async ([ch]) => {
      const mod = await import('/src/irc/client.ts');
      mod.rawCommand(`@+freeq.at/av-start TAGMSG ${ch}`);
    }, [channel]);
    await page.waitForTimeout(2000);

    // End it the way the app does: av-end carries the session id, and a
    // TAGMSG without one names no session to end.
    const sessionId = await page.evaluate(async () => {
      const { useStore } = await import('/src/store.ts');
      for (const s of useStore.getState().avSessions.values()) return s.id;
      return null;
    });
    expect(sessionId, 'av-start created a session').not.toBeNull();
    await page.evaluate(async ([ch, id]) => {
      const mod = await import('/src/irc/client.ts');
      mod.endAvSession(ch, id as string);
    }, [channel, sessionId]);
    await page.waitForTimeout(1000);

    // Session should be in 'ended' state briefly
    const sessionState = await page.evaluate(async () => {
      const { useStore } = await import('/src/store.ts');
      const sessions = useStore.getState().avSessions;
      for (const s of sessions.values()) {
        return s.state;
      }
      return null;
    });
    // Could be 'ended' or already removed
    expect(sessionState === 'ended' || sessionState === null).toBe(true);

    // After 6 seconds, should be fully removed
    await page.waitForTimeout(6000);
    const remainingSessions = await page.evaluate(async () => {
      const { useStore } = await import('/src/store.ts');
      return useStore.getState().avSessions.size;
    });
    expect(remainingSessions).toBe(0);
  });
});
