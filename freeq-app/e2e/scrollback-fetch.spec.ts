/**
 * E2E: one continuous scroll walks a channel to its start.
 *
 * Fetching older history used to be an edge-triggered scroll handler with no
 * visible face. This walks a densely seeded channel from the bottom to the
 * start-of-channel marker, scrolling in one direction the whole way — every
 * gesture is toward the top, and the marker has to appear without a single
 * scroll back down to re-arm anything.
 *
 * The seeding is deliberately dense. Every sender fires a burst at once, so
 * each burst lands inside one stored second with their msgids interleaved;
 * the only pacing is the server's flood window between bursts. Pages
 * anchored on a `msgid` step through rows sharing a second one at a time,
 * which a second-resolution `timestamp` anchor cannot do; a channel seeded
 * this way is only walkable at all because of that.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import { uniqueNick, uniqueChannel, connectGuest, heldRowCount } from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** The server's flood window: five messages per two seconds per connection. */
const BURST = 5;
const BURST_WINDOW_MS = 2_250;
/** Sessions that stay up for the whole seeding.
 *
 *  Kept low on purpose. These are held open for the length of the seeding,
 *  so they overlap whatever the rest of the suite is doing on the same
 *  address, and the server caps connections per IP at 20 — ten of them was
 *  enough to push the spec that runs next over that cap and reject its
 *  first wave. Six leaves room for a neighbour's ten and the readers. */
const SESSIONS = 6;
/** Messages each of them sends, in bursts of `BURST`. */
const PER_SESSION = 50;
const SEEDED = SESSIONS * PER_SESSION;

/**
 * One session that stays connected and sends its whole share, pausing
 * between bursts to stay inside the flood window.
 *
 * Sixty short-lived sessions seeding this channel is what made the walk
 * unreliable under suite load: sixty connects, joins and quits against a
 * server the rest of the suite is also using, any one of which timing out
 * fails the test for a reason that has nothing to do with paging. A
 * handful of connections held open cost the same messages and almost none of
 * that.
 */
function seedSession(channel: string, nick: string, first: number, count: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(IRC_PORT, IRC_HOST);
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
      // Resolve once the server has actually let go, so the connection is off
      // its per-IP count before whatever runs next starts connecting. The
      // socket is not ended until the last burst has had a moment to flush.
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

/** Seed `SEEDED` messages through `SESSIONS` connections held open. */
async function seedDensely(channel: string): Promise<void> {
  await Promise.all(Array.from({ length: SESSIONS }, (_, k) =>
    seedSession(channel, `df${k}`, k * PER_SESSION, PER_SESSION)));
}

/** Where the reader is: distance from the bottom, in pixels. */
function distanceFromBottom(list: Locator): Promise<number> {
  return list.evaluate((el) => el.scrollHeight - el.scrollTop - el.clientHeight);
}

function boundary(page: Page): Locator {
  return page.getByTestId('history-boundary');
}

test.describe('walking a channel to its start', () => {
  // Seeding paces against the flood window, and a walk of several pages
  // follows it, so this one runs long by construction.
  test.setTimeout(300_000);

  test('one continuous scroll up reaches the start-of-channel marker', async ({ page }) => {
    const channel = uniqueChannel();
    await seedDensely(channel);

    await connectGuest(page, uniqueNick('rdr'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRowCount(page, channel), { timeout: 20_000 }).toBeGreaterThan(10);
    // Activating a channel re-pins the view to the bottom on a timer for the
    // next 1.2s; scrolling up inside that window is undone.
    await page.waitForTimeout(1_500);
    expect(await distanceFromBottom(list)).toBeLessThan(80);

    // The row is there from the start, and it is not claiming the channel
    // begins where the loaded list happens to.
    // At rest nothing floats over the list and the start marker does not
    // exist yet: the fetching states render only while a page is on the wire
    // or after one failed.
    await expect(boundary(page)).toHaveCount(0);

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
    expect(await heldRowCount(page, channel)).toBeGreaterThanOrEqual(SEEDED);
  });
});
