import { test, expect, type Page, type Browser } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest, openSidebar, prepPage } from './helpers';

/**
 * A DM thread is keyed by the peer's DID, so its title depends on the client
 * being able to turn that DID back into a name. For a did:key peer — a bot
 * with no PDS and no profile behind it — the server's `account` tag is the
 * only thing that ever can, which makes this the case where a raw
 * `key:z6Mk…7JuZ` reaches the screen if anything in the chain is missing.
 *
 * Drives the real thing: a real server, a real did:key SASL handshake, a real
 * account tag, and the real sidebar. The peer runs in a second browser page
 * rather than in the test process, because the spec body is not bundled and
 * so cannot resolve the SDK for itself (see `src/e2e-support.ts`).
 */

/** A did:key peer, connected and registered. Returns its DID. */
async function startDidKeyPeer(browser: Browser, nick: string): Promise<{ page: Page; did: string }> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await prepPage(page);
  await page.goto('/');

  const did = await page.evaluate(async (nick) => {
    const { FreeqClient, generateDidKey } = await import('/src/e2e-support.ts');
    const didKey = await generateDidKey();
    const client = new FreeqClient({
      url: `ws://${location.hostname}:8080/irc`,
      nick,
      sasl: { did: didKey.did, method: 'crypto', signer: didKey.signer, token: '', pdsUrl: '' },
    });
    (window as any).__peer = client;
    const registered = new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('peer never registered')), 20_000);
      client.on('registered', () => { clearTimeout(t); resolve(); });
    });
    client.connect();
    await registered;
    return didKey.did;
  }, nick);

  return { page, did };
}

function compactDid(did: string): string {
  const id = did.slice('did:key:'.length);
  return `key:${id.slice(0, 4)}…${id.slice(-4)}`;
}

test('a DM from a did:key peer is titled with its nick, not its DID', async ({ page, browser }) => {
  const channel = uniqueChannel();
  const human = uniqueNick('human');
  const botNick = uniqueNick('keybot');

  await connectGuest(page, human, channel);
  const peer = await startDidKeyPeer(browser, botNick);

  try {
    // The peer speaks first, to a session that never saw it join anything.
    await peer.page.evaluate((to) => (window as any).__peer.sendMessage(to, 'hello from a key'), human);

    await openSidebar(page);
    const sidebar = page.getByTestId('sidebar');

    await expect(sidebar.getByText(botNick, { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(sidebar.getByText(compactDid(peer.did))).toHaveCount(0);
    await expect(sidebar.getByText(peer.did)).toHaveCount(0);
  } finally {
    await peer.page.context().close();
  }
});

/**
 * The gap this batch closed: a peer whose only appearance is a channel
 * message. The account tag on it is the same server-stamped binding a DM
 * carries, and the client learned nothing from it — so the peer stayed
 * nameless until they DMed or someone ran a WHOIS.
 */
test('a peer seen only in a channel becomes nameable by DID', async ({ page, browser }) => {
  const channel = uniqueChannel();
  const human = uniqueNick('human');
  const botNick = uniqueNick('chanbot');

  // The peer is already in the channel before the session exists, so the
  // session never witnesses the JOIN that would have named it. What it gets
  // instead is a NAMES roster, which carries nicks and no DIDs at all.
  const peer = await startDidKeyPeer(browser, botNick);

  try {
    await peer.page.evaluate((ch) => (window as any).__peer.join(ch), channel);
    await connectGuest(page, human, channel);

    await peer.page.evaluate(
      (ch) => (window as any).__peer.sendMessage(ch, 'only ever spoke here'),
      channel,
    );
    await expect(page.getByText('only ever spoke here')).toBeVisible({ timeout: 15_000 });

    // The session should now be able to name that DID from the tag alone —
    // no JOIN it witnessed, no WHOIS, no DM, no profile.
    const named = await page.evaluate(async (did) => {
      const { getClient } = await import('/src/irc/client.ts');
      return getClient()?.getNickForDid(did) ?? null;
    }, peer.did);

    expect(named, 'a channel message names its sender as well as a DM does').toBe(
      botNick.toLowerCase(),
    );
  } finally {
    await peer.page.context().close();
  }
});
