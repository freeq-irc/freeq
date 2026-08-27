/**
 * E2E: walking back, coming to the present, and following a link to where
 * you were.
 *
 * Three positions a reader takes in one channel. Walking back moves the
 * window away from the live end a page at a time. The jump affordance brings
 * it back to the present. And a link to a message the window has never
 * reached — a search result, a reply reference, a shared link opened fresh —
 * opens the window around that message, which is a fetch and not a scroll:
 * the rows around it were never in this session's list.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import {
  uniqueNick, uniqueChannel, connectGuest,
  heldRowCount, newestHeldMsgId, oldestHeldMsgId, jumpToMessage,
} from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** The server's flood window: five messages per two seconds per connection. */
const BURST = 5;
const BURST_WINDOW_MS = 2_250;
/** Sessions held open for the whole seeding, kept low so the per-IP cap
 *  leaves room for the readers and for whatever else is running. */
const SESSIONS = 6;
/** Seeding connects from a second loopback address, as the deep walk does.
 *  The server counts connections per IP and refuses the 21st, and these are
 *  held open for the length of the seeding while the rest of the suite is
 *  using the same address — enough, on the run this spec first joined, to
 *  cost two neighbouring specs their connection. Where the address is not
 *  usable the sessions fall back to the default source. */
const SEED_SRC = '127.0.0.2';
const PER_SESSION = 50;
const SEEDED = SESSIONS * PER_SESSION;
/** The opening page the SDK asks for on join. */
const PAGE = 50;

/** One session that stays connected and sends its whole share, pausing
 *  between bursts to stay inside the flood window. */
function seedSession(
  channel: string, nick: string, first: number, count: number, src: string | undefined,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ port: IRC_PORT, host: IRC_HOST, localAddress: src });
    sock.setNoDelay(true);
    let buf = '';
    let joined = false;
    let sent = 0;
    const timer = setTimeout(
      () => { sock.destroy(); reject(new Error(`seed session ${nick} timed out`)); },
      30_000 + (count / BURST) * BURST_WINDOW_MS,
    );
    const done = () => {
      clearTimeout(timer);
      sock.write('QUIT :seeded\r\n');
      sock.on('close', () => resolve());
      setTimeout(() => sock.end(), 100);
      setTimeout(() => resolve(), 2_000);
    };
    const sendBurst = () => {
      let out = '';
      for (let i = 0; i < BURST && sent < count; i++, sent++) {
        out += `PRIVMSG ${channel} :seed ${String(first + sent).padStart(5, '0')}\r\n`;
      }
      sock.write(out);
      if (sent >= count) done();
      else setTimeout(sendBurst, BURST_WINDOW_MS);
    };
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
    sock.on('data', (chunk) => {
      buf += chunk.toString();
      const lines = buf.split('\r\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (line.startsWith('PING')) sock.write(`PONG${line.slice(4)}\r\n`);
        if (/ 001 /.test(line)) sock.write(`JOIN ${channel}\r\n`);
        if (!joined && / 366 /.test(line)) { joined = true; sendBurst(); }
      }
    });
    sock.write(`NICK ${nick}\r\nUSER ${nick} 0 * :${nick}\r\n`);
  });
}

/** Whether the server accepts a connection from `SEED_SRC`. */
function seedSourceUsable(): Promise<string | undefined> {
  return new Promise((resolve) => {
    const probe = net.connect({ port: IRC_PORT, host: IRC_HOST, localAddress: SEED_SRC });
    probe.on('connect', () => { probe.destroy(); resolve(SEED_SRC); });
    probe.on('error', () => resolve(undefined));
  });
}

async function seedChannel(channel: string): Promise<void> {
  const src = await seedSourceUsable();
  await Promise.all(Array.from({ length: SESSIONS }, (_, k) =>
    seedSession(channel, `rt${k}`, k * PER_SESSION, PER_SESSION, src)));
}

/** Where the reader is: distance from the bottom, in pixels. */
function distanceFromBottom(list: Locator): Promise<number> {
  return list.evaluate((el) => el.scrollHeight - el.scrollTop - el.clientHeight);
}

const jumpButton = (page: Page): Locator =>
  page.getByRole('button', { name: /Jump to bottom|new message/ });

/** Settle a freshly activated channel: the view is re-pinned to the bottom on
 *  a timer for the first 1.2s, and a scroll inside that window is undone. */
async function settled(page: Page, channel: string): Promise<void> {
  await expect.poll(() => heldRowCount(page, channel), { timeout: 20_000 })
    .toBeGreaterThan(10);
  await page.waitForTimeout(1_500);
}

test.describe('a reader moving through a channel', () => {
  // Seeding paces against the flood window, and a walk of several pages
  // follows it.
  test.setTimeout(300_000);

  test('walks back, comes to the present, and follows a link to where it was',
    async ({ page, context }) => {
      const channel = uniqueChannel();
      await seedChannel(channel);

      // ── walking back ──
      await connectGuest(page, uniqueNick('rt'), channel);
      const list = page.getByTestId('message-list');
      await settled(page, channel);
      expect(await heldRowCount(page, channel)).toBeLessThan(SEEDED);

      const marker = page.getByText('This is the beginning of the channel.');
      const deadline = Date.now() + 180_000;
      while (Date.now() < deadline && await marker.count() === 0) {
        await list.evaluate((el) => { el.scrollTop = 0; });
        await page.waitForTimeout(150);
      }
      await expect(marker).toBeVisible();
      expect(await heldRowCount(page, channel)).toBeGreaterThanOrEqual(SEEDED);

      const oldest = await oldestHeldMsgId(page, channel);
      const newest = await newestHeldMsgId(page, channel);
      expect(oldest).toBeTruthy();
      expect(newest).toBeTruthy();

      // ── coming to the present ──
      await jumpButton(page).click();
      await expect(list.locator(`[id="msg-${newest}"]`)).toBeInViewport({ timeout: 10_000 });
      expect(await distanceFromBottom(list)).toBeLessThan(80);

      // ── following a link back ──
      //
      // A second reader, whose list has never held anything but the opening
      // page. The linked message is not in it, so going there is a fetch.
      const linked = await context.newPage();
      await connectGuest(linked, uniqueNick('rl'), channel);
      const linkedList = linked.getByTestId('message-list');
      await settled(linked, channel);
      expect(await heldRowCount(linked, channel)).toBeLessThanOrEqual(PAGE * 2);
      expect(await oldestHeldMsgId(linked, channel)).not.toBe(oldest);

      await jumpToMessage(linked, oldest!);

      await expect(linkedList.locator(`[id="msg-${oldest}"]`))
        .toBeInViewport({ timeout: 15_000 });
      // The window moved: it is the page around the linked message — which
      // is the start of this channel, so that message is the oldest row in
      // it — and not the live end, which is what the affordance back to the
      // present says.
      expect(await oldestHeldMsgId(linked, channel)).toBe(oldest);
      await expect(jumpButton(linked)).toBeVisible();

      // ── and to the present from there ──
      //
      // Nothing below an anchored window has been fetched, so this is a
      // request for the newest page and not a scroll. The affordance going
      // away is the window arriving at the live end.
      await jumpButton(linked).click();
      await expect(jumpButton(linked)).toHaveCount(0, { timeout: 15_000 });
      expect(await heldRowCount(linked, channel)).toBeLessThanOrEqual(PAGE * 2);
      expect(await oldestHeldMsgId(linked, channel)).not.toBe(oldest);

      await linked.close();
    });
});
