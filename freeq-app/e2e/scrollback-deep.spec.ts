/**
 * E2E: a channel far deeper than the window walks to its start, and the
 * window stays the size it is meant to be the whole way.
 *
 * The two halves are one statement. A walk that reaches the start by holding
 * every page it was ever handed proves nothing about a reader who keeps
 * reading: it is the same unbounded list under another name. A window that
 * holds its ceiling but stops moving is a reader stuck at a button. This
 * seeds past five thousand rows, walks the whole channel to its start marker,
 * and requires the held list never to pass its ceiling on the way.
 *
 * Nothing below a few thousand rows can see either half, which is why this
 * spec seeds so much and runs so long.
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import net from 'node:net';
import { uniqueNick, uniqueChannel, connectGuest, heldRowCount, oldestHeldMsgId } from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** A depth far past anything the window holds, so the walk is hundreds of
 *  pages rather than a handful. */
const WALL = 5000;
/** Rows the app holds at rest (`MESSAGE_WINDOW` in the store). */
const WINDOW = 1000;
/** Rows per CHATHISTORY page the app asks for. */
const PAGE = 50;
/** The server's flood window: five messages per two seconds per connection. */
const BURST = 5;
const BURST_WINDOW_MS = 2_250;
/** Sessions held open for the whole seeding. */
const SESSIONS = 8;
/** Seeding connects from a second loopback address.
 *
 *  The server counts connections per IP and refuses the 21st. Eight sessions
 *  held open for five minutes on the address the whole suite shares is enough
 *  to push it over on its own: the first run of this spec cost the two
 *  neighbouring scrollback specs their seeding (`ECONNRESET`, a session that
 *  never registered) and rejected browser sockets besides. Seeding from
 *  127.0.0.2 spends a budget nothing else is using. Where that address is not
 *  usable the sessions fall back to the default source and the pressure comes
 *  back with them. */
const SEED_SRC = '127.0.0.2';
/** Messages each of them sends, in bursts of `BURST`. */
const PER_SESSION = 640;
const SEEDED = SESSIONS * PER_SESSION; // 5120 — five times the window

/**
 * One session that stays connected and sends its whole share, pausing
 * between bursts to stay inside the flood window.
 */
function seedSession(
  channel: string, nick: string, first: number, count: number, src: string | undefined,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ port: IRC_PORT, host: IRC_HOST, localAddress: src });
    sock.setNoDelay(true);
    let buf = '';
    let joined = false;
    let sent = 0;
    // Twice the time the bursts need, plus a minute: seeding shares an event
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

/** Whether the server accepts a connection from `SEED_SRC`. */
function seedSourceUsable(): Promise<string | undefined> {
  return new Promise((resolve) => {
    const probe = net.connect({ port: IRC_PORT, host: IRC_HOST, localAddress: SEED_SRC });
    probe.on('connect', () => { probe.destroy(); resolve(SEED_SRC); });
    probe.on('error', () => resolve(undefined));
  });
}

/** Seed `SEEDED` messages through `SESSIONS` connections held open. */
async function seedChannel(channel: string): Promise<number> {
  const src = await seedSourceUsable();
  // One retry each. A neighbouring spec's senders may still be coming down
  // while these go up, so a refused connect is a transient to ride out rather
  // than a failure of the window.
  await Promise.all(Array.from({ length: SESSIONS }, (_, k) =>
    seedSession(channel, `dp${k}`, k * PER_SESSION, PER_SESSION, src)
      .catch(() => new Promise((r) => setTimeout(r, 2_000))
        .then(() => seedSession(channel, `dpr${k}`, k * PER_SESSION, PER_SESSION, src)))));
  return SEEDED;
}

function boundary(page: Page): Locator {
  return page.getByTestId('history-boundary');
}

test.describe('walking a channel far deeper than the window', () => {
  // Seeding paces against the flood window and the walk is a hundred pages,
  // so this one runs long by construction.
  test.setTimeout(1_800_000);

  test('a channel of more than 5000 messages walks all the way to its start', async ({ page }) => {
    const channel = uniqueChannel();
    const seeded = await seedChannel(channel);
    expect(seeded).toBeGreaterThan(WALL);

    await connectGuest(page, uniqueNick('rdr'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRowCount(page, channel), { timeout: 20_000 }).toBeGreaterThan(10);
    // Activating a channel re-pins the view to the bottom on a timer for the
    // next 1.2s; scrolling up inside that window is undone.
    await page.waitForTimeout(1_500);

    // At rest nothing floats over the list and the start marker does not
    // exist yet: the fetching states render only while a page is on the wire
    // or after one failed.
    await expect(boundary(page)).toHaveCount(0);

    // ── the walk ──
    //
    // Every gesture sets scrollTop to 0, all the way from the newest row to
    // the oldest.
    const marker = page.getByText('This is the beginning of the channel.');
    const deadline = Date.now() + 1_200_000;
    let reached = false;
    let oldest = await oldestHeldMsgId(page, channel);
    let stalled = 0;
    let deepest = 0;
    while (Date.now() < deadline) {
      if (await marker.count() > 0) { reached = true; break; }
      await list.evaluate((el) => { el.scrollTop = 0; });
      await page.waitForTimeout(250);
      // What says a page landed is the oldest row in the window changing, not
      // the count: at its ceiling the window moves rather than grows. Pages
      // land as fast as the server answers and a list this long takes a while
      // to render each one, so the movement is uneven — only a long run of
      // none at all, a minute of gestures, says the walk stopped.
      const now = await oldestHeldMsgId(page, channel);
      stalled = now !== oldest ? 0 : stalled + 1;
      oldest = now;
      expect(stalled, `the walk stopped moving, ${oldest} at the top`).toBeLessThan(240);

      const held = await heldRowCount(page, channel);
      deepest = Math.max(deepest, held);
      expect(held, `the window grew past its ceiling, to ${held} rows`)
        .toBeLessThanOrEqual(WINDOW + PAGE);
    }

    expect(reached, `scrolling up should reach the start; ${oldest} at the top`).toBe(true);
    await expect(boundary(page)).toHaveText('This is the beginning of the channel.');
    await expect(page.getByRole('button', { name: 'Load older messages' })).toHaveCount(0);

    // Thousands of rows went past the reader and the window carried its
    // ceiling and no more — which is the whole of it: the pages it gave up at
    // the far end are what let it keep taking new ones at this one.
    expect(deepest, 'the window should have filled to its ceiling on the way')
      .toBeGreaterThanOrEqual(WINDOW);
    const finalRows = await heldRowCount(page, channel);
    expect(finalRows).toBeLessThanOrEqual(WINDOW + PAGE);
  });
});
