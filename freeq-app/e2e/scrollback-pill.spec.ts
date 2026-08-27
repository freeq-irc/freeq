/**
 * E2E: the jump-to-bottom pill sits on the pane, wherever the reader is.
 *
 * It used to be positioned against the scroll container, and inside a scroll
 * container an absolutely positioned box is placed against the whole
 * scrollable content rather than the part of it on screen — so the pill sat
 * at the end of the content and was only in view once the reader had already
 * scrolled to the bottom, which is the one place it is not offered. Shallow
 * histories hid that: scrolled-up used to mean near the top of a short
 * channel. Continuous paging made every deep position reachable.
 *
 * Geometry is the whole point here, so this is the only place it can be
 * checked: jsdom reports zeroes for every rect.
 */
import { test, expect, type Locator } from '@playwright/test';
import net from 'node:net';
import { uniqueNick, uniqueChannel, connectGuest, heldRowCount } from './helpers';

const IRC_HOST = process.env.FREEQ_IRC_HOST || '127.0.0.1';
const IRC_PORT = Number(process.env.FREEQ_IRC_PORT || 16799);

/** The server's flood window: five messages per two seconds per connection. */
const BURST = 5;
const BURST_WINDOW_MS = 2_100;
/** Enough to fill several panes, and no more than that.
 *
 *  These connections stay open, and so do the ones belonging to the specs
 *  either side of this one; the server caps connections per IP at 20 and
 *  three specs' worth of held-open senders overlapping is what reaches it.
 *  This test only needs the pane to be scrollable. */
const SESSIONS = 2;
const PER_SESSION = 40;

/** The inset the pill is given from the bottom of the pane (`bottom-4`). */
const INSET_PX = 16;

/** One session that stays connected and sends its share inside the flood
 *  window. */
function seedSession(channel: string, nick: string, first: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(IRC_PORT, IRC_HOST);
    sock.setNoDelay(true);
    let buf = '';
    let joined = false;
    let sent = 0;
    const timer = setTimeout(
      () => { sock.destroy(); reject(new Error(`seed session ${nick} timed out`)); },
      60_000 + (PER_SESSION / BURST) * BURST_WINDOW_MS * 2,
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
      for (let i = 0; i < BURST && sent < PER_SESSION; i++, sent++) {
        out += `PRIVMSG ${channel} :pill ${String(first + sent).padStart(5, '0')}\r\n`;
      }
      sock.write(out);
      if (sent >= PER_SESSION) done();
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

async function seedChannel(channel: string): Promise<void> {
  await Promise.all(Array.from({ length: SESSIONS }, (_, k) =>
    seedSession(channel, `pl${k}`, k * PER_SESSION)
      .catch(() => new Promise((r) => setTimeout(r, 2_000))
        .then(() => seedSession(channel, `plr${k}`, k * PER_SESSION)))));
}

/** How far the pill's bottom edge sits above the bottom edge of the pane the
 *  reader is looking at. Both rects are viewport-relative, so this is what
 *  the reader actually sees. */
async function pillGapFromPaneBottom(pill: Locator, list: Locator): Promise<number> {
  const pillBox = await pill.boundingBox();
  const listBox = await list.boundingBox();
  if (!pillBox || !listBox) throw new Error('pill or pane has no box');
  return (listBox.y + listBox.height) - (pillBox.y + pillBox.height);
}

test.describe('the jump-to-bottom pill', () => {
  test.setTimeout(180_000);

  test('sits at the bottom of the pane at every scroll position', async ({ page }) => {
    const channel = uniqueChannel();
    await seedChannel(channel);

    await connectGuest(page, uniqueNick('pil'), channel);
    const list = page.getByTestId('message-list');
    await expect.poll(() => heldRowCount(page, channel),
      { timeout: 20_000 }).toBeGreaterThan(20);
    // Activating a channel re-pins the view to the bottom on a timer.
    await page.waitForTimeout(1_500);

    const geometry = await list.evaluate((el) => ({
      scrollHeight: el.scrollHeight, clientHeight: el.clientHeight,
    }));
    expect(geometry.scrollHeight, 'the channel has to be deeper than the pane')
      .toBeGreaterThan(geometry.clientHeight * 2);

    const pill = page.getByRole('button', { name: /Jump to bottom|new message/ });

    // Three positions, one of which is the only one the old test took: the
    // top. The other two are where the pill used to be out of sight.
    const positions: Array<[string, number]> = [
      ['the top', 0],
      ['deep in the middle', Math.floor((geometry.scrollHeight - geometry.clientHeight) / 2)],
      ['near the bottom', geometry.scrollHeight - geometry.clientHeight - 200],
    ];

    for (const [where, scrollTop] of positions) {
      await list.evaluate((el, top) => { el.scrollTop = top; }, scrollTop);
      await page.waitForTimeout(400);

      await expect(pill, `the pill is offered at ${where}`).toBeVisible();
      await expect(pill, `the pill is on screen at ${where}`).toBeInViewport();

      const gap = await pillGapFromPaneBottom(pill, list);
      expect(gap, `the pill sits at the bottom of the pane at ${where}`)
        .toBeGreaterThan(INSET_PX - 4);
      expect(gap, `the pill sits at the bottom of the pane at ${where}`)
        .toBeLessThan(INSET_PX + 4);
    }
  });
});
