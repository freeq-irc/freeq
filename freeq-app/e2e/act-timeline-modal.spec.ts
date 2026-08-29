/**
 * E2E: the card's timeline modal sits above the whole list.
 *
 * Rendered inline, the modal lived inside a virtualized list row, and rows
 * after the card hit-tested above it — a click on the modal fell through to
 * the row behind it (the verify link took focus and nothing happened; a
 * right-click opened the hidden row's context menu). The modal is portaled to
 * the body now, and this spec keeps it there: the card is followed by a
 * screenful of later rows, and the verify click must land.
 */
import { test, expect, type Browser } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest } from './helpers';

async function startPeer(browser: Browser, nick: string, channel: string) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  const did = await page.evaluate(async ({ nick, channel }) => {
    const { FreeqClient, generateDidKey } = await import('/src/e2e-support.ts');
    const didKey = await generateDidKey();
    const client = new FreeqClient({
      url: `ws://${location.hostname}:8080/irc`,
      nick, channels: [channel],
      sasl: { did: didKey.did, method: 'crypto', signer: didKey.signer, token: '', pdsUrl: '' },
    });
    (window as any).__peer = client;
    const joined = new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('peer never joined')), 20_000);
      client.on('channelJoined', (chan: string) => {
        if (chan.toLowerCase() === channel.toLowerCase()) { clearTimeout(t); resolve(); }
      });
    });
    client.connect();
    await joined;
    return didKey.did;
  }, { nick, channel });
  return { page, ctx, did };
}

test('verify inside the timeline modal is clickable with rows after the card', async ({ page, browser }) => {
  const nick = uniqueNick('vm');
  const channel = uniqueChannel('vm');
  const peer = await startPeer(browser, uniqueNick('ModalBot'), channel);
  try {
    await connectGuest(page, nick, channel);
    await peer.page.evaluate(async ({ channel, did }) => {
      const { actTags } = await import('/src/e2e-support.ts');
      const client = (window as any).__peer;
      await client.sendAct(channel, actTags('handoff', 'offer', undefined, did, { title: 'stack the modal' }));
      // A screenful of rows after the card, so later rows exist to hit-test
      // above an inline modal. Paced under the flood limit, which drops
      // over-rate messages without error.
      for (let i = 0; i < 15; i++) {
        client.sendMessage(channel, `filler line ${i}`);
        await new Promise(r => setTimeout(r, 200));
      }
    }, { channel, did: peer.did });

    await expect(page.getByText('filler line 14')).toBeVisible({ timeout: 15000 });
    const card = page.getByTestId('act-card').first();
    await card.scrollIntoViewIfNeeded();
    await card.click();

    const verify = page.getByTitle("Check this event's signature").first();
    await expect(verify).toBeVisible({ timeout: 8000 });
    await verify.click({ timeout: 5000 });
    await expect(page.getByTestId('verify-panel')).toBeVisible({ timeout: 4000 });
  } finally {
    await peer.ctx.close();
  }
});
