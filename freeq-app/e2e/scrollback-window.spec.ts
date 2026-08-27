/**
 * E2E: the scrollback window — moves while paging back, and the way back to
 * the present is a fetch.
 *
 * The store keeps a channel's newest 1000 rows at rest. Paging back fills
 * that window and then moves it: each page arriving at the older end costs a
 * page at the newer one, so the reader walks the channel without the list
 * growing under them. Nothing below the window is held once they have walked
 * off it, so returning to the bottom asks the server for the newest page
 * rather than scrolling to rows that are no longer there. Everything about
 * that behaviour is scroll geometry, which jsdom does not have: this is the
 * only place it can be seen for real.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import {
  uniqueNick, uniqueChannel, connectGuest,
  heldRowCount, newestHeldMsgId, oldestHeldMsgId,
} from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** Rows the app holds at rest (`MESSAGE_WINDOW` in the store). */
const WINDOW = 1000;
/** Rows per CHATHISTORY page the app asks for. */
const PAGE = 50;
/** The server's flood window: five messages per two seconds per connection. */
const BURST = 5;
const BURST_WINDOW_MS = 2_100;
/** Sessions held open for the whole seeding. With the talker and the reader
 *  this stays well under the 20-per-IP cap, and a held-open connection
 *  overlaps whatever the rest of the suite is doing on the same address. */
const SESSIONS = 10;
/** Messages each of them sends, in bursts of `BURST`.
 *
 *  The total is the one this channel always held. It is not slack: paging is
 *  continuous now, so holding at the top drains the channel rather than
 *  taking one page, and the assertions after the growth loop need history
 *  still to be arriving. A channel that can be drained inside the loop has
 *  none left for them. */
const PER_SESSION = 264;

/**
 * One session that stays connected and sends its whole share, pausing
 * between bursts to stay inside the flood window.
 *
 * This used to be one short-lived session per five messages — over five
 * hundred connects, joins and quits for a channel this size, against a
 * server the rest of the suite is also using. Any one of them failing to
 * connect fails the test for a reason that has nothing to do with the
 * window.
 */
function seedSession(channel: string, nick: string, first: number, count: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(IRC_PORT, IRC_HOST);
    sock.setNoDelay(true);
    let buf = '';
    let joined = false;
    let sent = 0;
    // Twice the time the bursts need, plus a minute. Seeding shares an event
    // loop with the browser driver, and a budget that merely covers the
    // bursts back to back is one this fails under suite load rather than for
    // anything about the window.
    const timer = setTimeout(
      () => { sock.destroy(); reject(new Error(`seed session ${nick} timed out`)); },
      60_000 + (count / BURST) * BURST_WINDOW_MS * 2,
    );
    const done = () => {
      clearTimeout(timer);
      sock.write('QUIT :seeded\r\n');
      // Resolve once the server has let go, so the connection is off its
      // per-IP count before whatever runs next starts connecting.
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
        if (!joined && / 366 /.test(line)) {
          joined = true;
          sendBurst();
        }
      }
    });
    sock.write(`NICK ${nick}\r\nUSER ${nick} 0 * :${nick}\r\n`);
  });
}

/**
 * Seed `SESSIONS * PER_SESSION` messages through connections held open.
 *
 * The old seeding paced one bucket of messages per wall-clock second, and
 * the reason was that CHATHISTORY paged with `timestamp < marker`: rows
 * sharing a page boundary's second were stepped over, so a channel seeded
 * all at once was one page deep however many rows it held. Pages are cut on
 * `(timestamp, msgid)` now and step through a shared second one row at a
 * time, so the channel is walkable however its rows fall across seconds and
 * the bucketing has nothing left to do.
 */
async function seedChannel(channel: string): Promise<number> {
  // One retry each. The server caps connections per IP and this spec's
  // senders go up while a neighbouring spec's may still be coming down, so a
  // refused connect is a transient the fixture should ride out rather than
  // report as a failure of the window.
  await Promise.all(Array.from({ length: SESSIONS }, (_, k) =>
    seedSession(channel, `sd${k}`, k * PER_SESSION, PER_SESSION)
      .catch(() => new Promise((r) => setTimeout(r, 2_000))
        .then(() => seedSession(channel, `sdr${k}`, k * PER_SESSION, PER_SESSION)))));
  return SESSIONS * PER_SESSION;
}

/**
 * Someone already in the channel, who can say something later.
 *
 * They join before the reader arrives on purpose: a sender joining while the
 * reader is scrolled back lands a join notice below them too, and the point
 * here is to count one live message exactly.
 */
async function talker(channel: string, nick: string) {
  const sock = net.connect(IRC_PORT, IRC_HOST);
  sock.setNoDelay(true);
  await new Promise<void>((resolve, reject) => {
    let buf = '';
    let joined = false;
    const timer = setTimeout(() => { sock.destroy(); reject(new Error(`talker ${nick} timed out`)); }, 15_000);
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
    sock.on('data', (chunk) => {
      buf += chunk.toString();
      const lines = buf.split('\r\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (line.startsWith('PING')) sock.write(`PONG${line.slice(4)}\r\n`);
        if (/ 001 /.test(line)) sock.write(`JOIN ${channel}\r\n`);
        if (!joined && / 366 /.test(line)) { joined = true; clearTimeout(timer); resolve(); }
      }
    });
    sock.write(`NICK ${nick}\r\nUSER ${nick} 0 * :${nick}\r\n`);
  });
  return {
    say: (text: string) => { sock.write(`PRIVMSG ${channel} :${text}\r\n`); },
    close: () => { sock.write('QUIT :done\r\n'); sock.end(); },
  };
}

/** Where the reader is: distance from the bottom, in pixels. */
function distanceFromBottom(list: Locator): Promise<number> {
  return list.evaluate((el) => el.scrollHeight - el.scrollTop - el.clientHeight);
}

/** Ask for the next older page the way a reader does — by hitting the top.
 *  The handler reads the live `scrollTop`, so the two positions need a frame
 *  between them or the second assignment is all that is ever seen. */
async function pageBack(list: Locator): Promise<void> {
  await list.evaluate((el) => { el.scrollTop = 400; });
  await list.page().waitForTimeout(120);
  await list.evaluate((el) => { el.scrollTop = 0; });
}

/** Wait for a scroll-up fetch to land, without failing if this one did not.
 *
 *  What says a page arrived is the oldest row in the window changing. The
 *  count does not: at its ceiling the window moves rather than grows. */
async function movedWithin(
  list: Locator, channel: string, before: string | null, ms: number,
): Promise<string | null> {
  const deadline = Date.now() + ms;
  let oldest = before;
  while (Date.now() < deadline) {
    oldest = await oldestHeldMsgId(list.page(), channel);
    if (oldest !== before) return oldest;
    await list.page().waitForTimeout(100);
  }
  return oldest;
}

/** The jump/pill button, whose label carries the unread count. */
function jumpButton(page: Page): Locator {
  return page.getByRole('button', { name: /Jump to bottom|new message/ });
}

test.describe('scrollback window', () => {
  // The flood window is per connection, so seeding this much through
  // connections that stay open takes minutes rather than the seconds a crowd
  // of disposable ones took, and ~19 pages of scroll-back follow it.
  test.setTimeout(600_000);

  test('paging back holds the ceiling; returning to the bottom lands at the live tip', async ({ page }) => {
    const channel = uniqueChannel();
    // Ten senders, 264 each: one page is spent on the rows the JOIN already
    // replayed, ~19 fill the window to its ceiling, and the rest is what the
    // window moves over once it is there.
    const seeded = await seedChannel(channel);
    expect(seeded).toBeGreaterThan(WINDOW);
    const live = await talker(channel, uniqueNick('live'));

    await connectGuest(page, uniqueNick('rdr'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRowCount(page, channel), { timeout: 20_000 }).toBeGreaterThan(PAGE);
    // Activating a channel re-pins the view to the bottom on a timer for the
    // next 1.2s; scrolling up inside that window is undone before the handler
    // reads it.
    await page.waitForTimeout(1_500);

    // ── page back until the window is full ──
    let oldest = await oldestHeldMsgId(page, channel);
    let held = await heldRowCount(page, channel);
    let stalled = 0;
    for (let attempt = 0; attempt < 60 && held < WINDOW; attempt++) {
      const before = oldest;
      await pageBack(list);
      oldest = await movedWithin(list, channel, before, 8_000);
      stalled = oldest !== before ? 0 : stalled + 1;
      expect(stalled, 'four scroll-up fetches in a row moved the window nowhere').toBeLessThan(4);
      held = await heldRowCount(page, channel);
    }
    expect(held, 'paging back should fill the window to its ceiling').toBeGreaterThanOrEqual(WINDOW);

    // ── and then keep paging: the window moves, it does not grow ──
    for (let more = 0; more < 5; more++) {
      const before = oldest;
      await pageBack(list);
      oldest = await movedWithin(list, channel, before, 8_000);
      expect(oldest, 'the window should keep moving over the channel').not.toBe(before);
      const now = await heldRowCount(page, channel);
      expect(now, `the window grew past its ceiling, to ${now} rows`)
        .toBeLessThanOrEqual(WINDOW + PAGE);
    }
    expect(await distanceFromBottom(list)).toBeGreaterThan(0);

    // ── the pill counts live messages, and a history page does not move it ──
    await expect(jumpButton(page)).toHaveText('Jump to bottom');

    live.say('a live line while the reader is up the page');
    await expect(jumpButton(page)).toHaveText('1 new message');

    const beforePage = oldest;
    await pageBack(list);
    expect(await movedWithin(list, channel, beforePage, 8_000)).not.toBe(beforePage);
    await expect(jumpButton(page), 'a fetched history page is not new to the reader')
      .toHaveText('1 new message');

    // ── returning to the bottom lands at the live tip ──
    //
    // The rows between here and the present were given back on the way, so
    // there is nothing below this window to scroll to: taking the affordance
    // asks the server for the newest page, and what arrives is a page rather
    // than the ceiling.
    await jumpButton(page).click();
    await expect(jumpButton(page), 'the affordance has nothing left to offer at the tip')
      .toHaveCount(0, { timeout: 15_000 });
    expect(await heldRowCount(page, channel)).toBeLessThanOrEqual(PAGE * 2);

    // It is the live end: the line sent while the reader was up the page is
    // in it, and the newest row is the one they are looking at.
    await expect(list.getByText('a live line while the reader is up the page')).toBeVisible();
    const newestId = await newestHeldMsgId(page, channel);
    const newest = list.locator(`[id="msg-${newestId}"]`);
    await expect(newest).toBeInViewport();
    // Polled, not read once: the page that just arrived is a window of rows
    // nothing has measured yet, so the height the view is put against is an
    // estimate for a frame or two after it lands.
    await expect.poll(() => distanceFromBottom(list), { timeout: 5_000 })
      .toBeLessThan(4);

    // ...and stays there: the page arriving must not yank the view a frame later.
    await page.waitForTimeout(500);
    await expect(newest).toBeInViewport();
    expect(await distanceFromBottom(list)).toBeLessThan(4);
    await expect(jumpButton(page)).toHaveCount(0);

    live.close();
  });
});
