/**
 * E2E: the scrollback window — grow while paging back, trim on return.
 *
 * The store keeps a channel's newest 1000 rows at rest, grows past that
 * while the reader pages back, and gives the rows up when they return to
 * the bottom. Everything about that behaviour is scroll geometry, which
 * jsdom does not have: this is the only place it can be seen for real.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import { uniqueNick, uniqueChannel, connectGuest } from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** Rows the app holds at rest (`MESSAGE_WINDOW` in the store). */
const WINDOW = 1000;
/** Rows per CHATHISTORY page the app asks for. */
const PAGE = 50;
/** Messages one session may send before the server's flood limit bites. */
const PER_SESSION = 5;
/** Sockets open at once — the server caps connections per IP at 20. */
const MAX_PARALLEL = 10;

/**
 * Fill one session's flood budget into `channel` and leave.
 *
 * A fresh session gets a fresh budget, so seeding at any volume means many
 * short-lived ones rather than one chatty connection.
 */
function seedSession(channel: string, nick: string, first: number, count: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(IRC_PORT, IRC_HOST);
    sock.setNoDelay(true);
    let buf = '';
    let joined = false;
    const timer = setTimeout(() => { sock.destroy(); reject(new Error(`seed session ${nick} timed out`)); }, 15_000);
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
          let out = '';
          for (let i = 0; i < count; i++) {
            out += `PRIVMSG ${channel} :seed ${String(first + i).padStart(5, '0')}\r\n`;
          }
          sock.write(`${out}QUIT :seeded\r\n`);
          setTimeout(() => { clearTimeout(timer); sock.end(); resolve(); }, 50);
        }
      }
    });
    sock.write(`NICK ${nick}\r\nUSER ${nick} 0 * :${nick}\r\n`);
  });
}

/**
 * Seed `buckets` wall-clock seconds' worth of messages, `perBucket` each.
 *
 * The bucketing is not decoration. Stored timestamps are second-resolution
 * and CHATHISTORY pages with `timestamp < marker`, so rows sharing the page
 * boundary's second are stepped over — a channel seeded all at once is one
 * page deep however many rows it holds. One bucket per second is what makes
 * the channel walkable a page at a time.
 */
async function seedChannel(channel: string, buckets: number, perBucket: number): Promise<number> {
  const sessions = Math.ceil(perBucket / PER_SESSION);
  let sent = 0;
  for (let bucket = 0; bucket < buckets; bucket++) {
    const startedAt = Date.now();
    for (let wave = 0; wave < sessions; wave += MAX_PARALLEL) {
      const size = Math.min(MAX_PARALLEL, sessions - wave);
      await Promise.all(Array.from({ length: size }, (_, k) =>
        seedSession(channel, `sd${bucket}w${wave}k${k}`, sent + (wave + k) * PER_SESSION, PER_SESSION)));
    }
    sent += sessions * PER_SESSION;
    const spent = Date.now() - startedAt;
    if (spent < 1000) await new Promise((r) => setTimeout(r, 1000 - spent));
  }
  return sent;
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

/** How many message rows the transcript is holding. */
function heldRows(list: Locator): Promise<number> {
  return list.evaluate((el) => el.querySelectorAll('[id^="msg-"]').length);
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

/** Wait for a scroll-up fetch to land, without failing if this one did not. */
async function grewWithin(list: Locator, before: number, ms: number): Promise<number> {
  const deadline = Date.now() + ms;
  let rows = before;
  while (Date.now() < deadline) {
    rows = await heldRows(list);
    if (rows > before) return rows;
    await list.page().waitForTimeout(100);
  }
  return rows;
}

/** The jump/pill button, whose label carries the unread count. */
function jumpButton(page: Page): Locator {
  return page.getByRole('button', { name: /Jump to bottom|new message/ });
}

test.describe('scrollback window', () => {
  // Seeding is paced against wall-clock seconds, and ~19 pages of scroll-back
  // follow it, so this one runs long by construction.
  test.setTimeout(300_000);

  test('paging back grows the window; returning to the bottom trims it without moving the view', async ({ page }) => {
    const channel = uniqueChannel();
    // 24 buckets ≈ 24 walkable pages: one is spent on the rows the JOIN
    // already replayed, ~19 carry the held list past 1000, the rest is slack.
    const seeded = await seedChannel(channel, 24, 110);
    expect(seeded).toBeGreaterThan(WINDOW);
    const live = await talker(channel, uniqueNick('live'));

    await connectGuest(page, uniqueNick('rdr'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRows(list), { timeout: 20_000 }).toBeGreaterThan(PAGE);
    // Activating a channel re-pins the view to the bottom on a timer for the
    // next 1.2s; scrolling up inside that window is undone before the handler
    // reads it.
    await page.waitForTimeout(1_500);

    // ── page back until the held list is past the resting window ──
    let held = await heldRows(list);
    let stalled = 0;
    for (let attempt = 0; attempt < 60 && held <= WINDOW; attempt++) {
      const before = held;
      await pageBack(list);
      held = await grewWithin(list, before, 8_000);
      stalled = held > before ? 0 : stalled + 1;
      expect(stalled, 'four scroll-up fetches in a row added no rows').toBeLessThan(4);
    }
    expect(held, 'paging back should grow the held list past the resting window').toBeGreaterThan(WINDOW);
    expect(await distanceFromBottom(list)).toBeGreaterThan(0);

    // ── the pill counts live messages, and a history page does not move it ──
    await expect(jumpButton(page)).toHaveText('Jump to bottom');

    live.say('a live line while the reader is up the page');
    await expect(jumpButton(page)).toHaveText('1 new message');

    const heldBeforePage = await heldRows(list);
    await pageBack(list);
    expect(await grewWithin(list, heldBeforePage, 8_000)).toBeGreaterThan(heldBeforePage);
    await expect(jumpButton(page), 'a fetched history page is not new to the reader')
      .toHaveText('1 new message');

    // ── returning to the bottom trims, and the view stays put ──
    const newestRow = list.locator('[id^="msg-"]').last();
    const newestId = await newestRow.getAttribute('id');
    await jumpButton(page).click();

    await expect.poll(() => heldRows(list), { timeout: 15_000 }).toBeLessThanOrEqual(WINDOW);
    expect(await heldRows(list)).toBe(WINDOW);

    // The newest row survived the trim and is the one the reader is looking at.
    const newest = list.locator(`[id="${newestId}"]`);
    await expect(newest).toBeInViewport();
    expect(await distanceFromBottom(list)).toBeLessThan(4);

    // ...and stays there: the trim must not yank the view a frame later.
    await page.waitForTimeout(500);
    await expect(newest).toBeInViewport();
    expect(await distanceFromBottom(list)).toBeLessThan(4);
    await expect(jumpButton(page)).toHaveCount(0);

    live.close();
  });
});
