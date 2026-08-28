/**
 * E2E: a task's lifecycle over the wire.
 *
 * The other act spec puts each move straight into the store. This one puts
 * them on a real connection: a signed peer runs the task, the server files
 * every event and replays them to whoever joins next, and the app's own
 * bridge is what turns them into cards. The peer's nick carries capitals on
 * purpose — a replayed event names its sender by the nick the server holds
 * for the DID, and its companion line by the nick as it was sent.
 */
import { test, expect, type Page, type Browser } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, prepPage } from './helpers';

type Peer = { page: Page; did: string };

/**
 * A signed peer in the channel, driven from a second browser page: a spec
 * body is not bundled, so the SDK is reachable only through the dev server
 * (see `src/e2e-support.ts`).
 */
async function startPeer(browser: Browser, nick: string, channel: string): Promise<Peer> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await prepPage(page);
  await page.goto('/');

  const did = await page.evaluate(async ({ nick, channel }) => {
    const { FreeqClient, generateDidKey } = await import('/src/e2e-support.ts');
    const didKey = await generateDidKey();
    const client = new FreeqClient({
      url: `ws://${location.hostname}:8080/irc`,
      nick,
      channels: [channel],
      sasl: { did: didKey.did, method: 'crypto', signer: didKey.signer, token: '', pdsUrl: '' },
    });
    (window as any).__peer = client;
    const joined = new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('peer never joined')), 20_000);
      client.on('channelJoined', (chan: string) => {
        if (chan.toLowerCase() === channel.toLowerCase()) {
          clearTimeout(t);
          resolve();
        }
      });
    });
    client.connect();
    await joined;
    return didKey.did;
  }, { nick, channel });

  return { page, did };
}

/** One move by the peer: the signed event, and the line it writes beside it. */
async function sendMove(
  peer: Peer,
  channel: string,
  verb: string,
  task: string | undefined,
  fields: Record<string, string> = {},
): Promise<string> {
  return peer.page.evaluate(async ({ channel, verb, task, fields, did }) => {
    const { actTags } = await import('/src/e2e-support.ts');
    const client = (window as any).__peer;
    return client.sendAct(channel, actTags('handoff', verb, task, did, fields), { taskId: task });
  }, { channel, verb, task, fields, did: peer.did });
}

test('a task run on the wire reads as cards, live and again after a reload', async ({ page, browser }) => {
  const channel = uniqueChannel();
  const peer = await startPeer(browser, uniqueNick('TaskBot'), channel);

  try {
    await connectGuest(page, uniqueNick(), channel);
    const cards = page.getByTestId('act-card');

    const task = await sendMove(peer, channel, 'offer', undefined, { title: 'ship the release' });
    await expect(cards).toHaveCount(1, { timeout: 15_000 });
    await expect(cards.nth(0)).toContainText('offered');

    await sendMove(peer, channel, 'claim', task);
    await expect(cards).toHaveCount(2, { timeout: 15_000 });
    await expect(cards.nth(1)).toContainText('claimed');

    await sendMove(peer, channel, 'progress', task, { note: 'tagged the build' });
    await expect(cards).toHaveCount(3, { timeout: 15_000 });
    await expect(cards.nth(2)).toContainText('in progress');
    await expect(cards.nth(2)).toContainText('tagged the build');

    await sendMove(peer, channel, 'complete', task);
    await expect(cards).toHaveCount(4, { timeout: 15_000 });
    await expect(cards.nth(3)).toContainText('completed');

    // What the server replays to a reader who arrives after all of it: the
    // same four cards, from the events and lines it hands back on the join.
    await page.reload();
    await connectGuest(page, uniqueNick(), channel);
    await expect(cards).toHaveCount(4, { timeout: 15_000 });
    for (const [i, word] of ['offered', 'claimed', 'in progress', 'completed'].entries()) {
      await expect(cards.nth(i)).toContainText(word);
    }
  } finally {
    await peer.page.context().close();
  }
});
