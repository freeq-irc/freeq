/**
 * E2E: one continuous scroll walks a channel to its start.
 *
 * Fetching older history used to be an edge-triggered scroll handler with no
 * visible face. This walks a densely seeded channel from the bottom to the
 * start-of-channel marker, scrolling in one direction the whole way — every
 * gesture is toward the top, and the marker has to appear without a single
 * scroll back down to re-arm anything.
 *
 * The seeding is deliberately dense — as fast as the wire carries it, with
 * no pacing against wall-clock seconds. Pages anchored on a `msgid` step
 * through rows sharing a stored second one at a time, which a
 * second-resolution `timestamp` anchor cannot do; a channel seeded this way
 * is only walkable at all because of that.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import { uniqueNick, uniqueChannel, connectGuest } from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** Messages one session may send before the server's flood limit bites. */
const PER_SESSION = 5;
/** Sockets open at once — the server caps connections per IP at 20. */
const MAX_PARALLEL = 10;
/** Sessions to seed with, so `SESSIONS * PER_SESSION` messages in all. */
const SESSIONS = 60;
const SEEDED = SESSIONS * PER_SESSION;

/** Fill one session's flood budget into `channel` and leave. */
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

/** Seed `SEEDED` messages as fast as the connection cap allows. */
async function seedDensely(channel: string): Promise<void> {
  for (let wave = 0; wave < SESSIONS; wave += MAX_PARALLEL) {
    const size = Math.min(MAX_PARALLEL, SESSIONS - wave);
    await Promise.all(Array.from({ length: size }, (_, k) =>
      seedSession(channel, `df${wave}k${k}`, (wave + k) * PER_SESSION, PER_SESSION)));
  }
}

/** How many message rows the transcript is holding. */
function heldRows(list: Locator): Promise<number> {
  return list.evaluate((el) => el.querySelectorAll('[id^="msg-"]').length);
}

/** Where the reader is: distance from the bottom, in pixels. */
function distanceFromBottom(list: Locator): Promise<number> {
  return list.evaluate((el) => el.scrollHeight - el.scrollTop - el.clientHeight);
}

function boundary(page: Page): Locator {
  return page.getByTestId('history-boundary');
}

test.describe('walking a channel to its start', () => {
  // Seeding 300 messages over 60 short-lived sessions, then a walk of
  // several pages, runs long by construction.
  test.setTimeout(300_000);

  test('one continuous scroll up reaches the start-of-channel marker', async ({ page }) => {
    const channel = uniqueChannel();
    await seedDensely(channel);

    await connectGuest(page, uniqueNick('rdr'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRows(list), { timeout: 20_000 }).toBeGreaterThan(10);
    // Activating a channel re-pins the view to the bottom on a timer for the
    // next 1.2s; scrolling up inside that window is undone.
    await page.waitForTimeout(1_500);
    expect(await distanceFromBottom(list)).toBeLessThan(80);

    // The row is there from the start, and it is not claiming the channel
    // begins where the loaded list happens to.
    await expect(boundary(page)).toBeVisible();
    await expect(boundary(page)).not.toHaveText('This is the beginning of the channel.');

    // ── the walk ──
    //
    // Every gesture sets scrollTop to 0. Nothing here ever scrolls down, so
    // reaching the start proves no re-arm gesture is needed: a page landing
    // above the reader leads into the next request on its own.
    const marker = page.getByText('This is the beginning of the channel.');
    const deadline = Date.now() + 180_000;
    let reached = false;
    while (Date.now() < deadline) {
      if (await marker.count() > 0) { reached = true; break; }
      await list.evaluate((el) => { el.scrollTop = 0; });
      await page.waitForTimeout(150);
    }

    expect(reached, 'scrolling up should reach the start of the channel').toBe(true);
    await expect(boundary(page)).toHaveText('This is the beginning of the channel.');
    await expect(page.getByRole('button', { name: 'Load older messages' })).toHaveCount(0);

    // The whole channel came back on the way there. A page anchored by
    // timestamp would have stepped over the rows sharing each page
    // boundary's second and arrived short.
    expect(await heldRows(list)).toBeGreaterThanOrEqual(SEEDED);
  });
});
