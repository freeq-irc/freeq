/**
 * E2E: a task's lifecycle, as the room sees it.
 *
 * Runs against a local freeq-server (see playwright.config.ts). Each move is
 * put into the open conversation the way it arrives on the wire — the event,
 * then the line its sender wrote beside it — and everything downstream of
 * that stays real: the store pairs them and the row renders through the app.
 */
import { test, expect, type Page } from '@playwright/test';
import { uniqueNick, uniqueChannel, connectGuest } from './helpers';

const TASK = '01JPWLIFECYCLE00000000000A';

type Move = { verb: string; eventId: string; text: string; fields?: Record<string, string> };

const LIFECYCLE: Move[] = [
  { verb: 'offer', eventId: TASK, text: 'offered: ship the release', fields: { 'act-title': 'ship the release' } },
  { verb: 'claim', eventId: '01JPWLIFECYCLE00000000000B', text: 'claimed the task' },
  {
    verb: 'progress',
    eventId: '01JPWLIFECYCLE00000000000C',
    text: 'progress: tagged the build',
    fields: { 'act-note': 'tagged the build', 'act-ctx': 'https://example.com/checks/abc', 'act-ctx-h': 'sha256:9f00' },
  },
  { verb: 'complete', eventId: '01JPWLIFECYCLE00000000000D', text: 'completed the task' },
];

/** Put one move into the conversation: the event, then its companion line. */
async function receiveMove(page: Page, channel: string, move: Move) {
  await page.evaluate(
    async ({ channel, move, task }) => {
      const { useStore } = await import('/src/store.ts');
      const s = useStore.getState();
      s.addActEvent(channel, {
        from: 'worker',
        did: 'did:plc:worker',
        kind: 'handoff',
        verb: move.verb,
        eventId: move.eventId,
        taskId: task,
        fields: { act: 'handoff', 'act-verb': move.verb, ...(move.fields ?? {}) },
      });
      s.addMessage(channel, {
        id: `m-${move.eventId}`,
        from: 'worker',
        text: move.text,
        timestamp: new Date(),
        tags: { '+freeq.at/ref': task, msgid: `m-${move.eventId}` },
      });
    },
    { channel, move, task: TASK },
  );
}

test.describe('task cards', () => {
  test('every move of a lifecycle keeps its own card, and its own word', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);

    const cards = page.getByTestId('act-card');
    const words = ['offered', 'claimed', 'in progress', 'completed'];

    // The first half of the task, live.
    for (const [i, move] of LIFECYCLE.slice(0, 2).entries()) {
      await receiveMove(page, channel, move);
      await expect(cards).toHaveCount(i + 1);
      await expect(cards.nth(i)).toContainText(words[i]);
    }

    // A reader who reloads mid-task is handed what already happened as replay
    // and the rest of it live, and both halves read the same.
    await page.reload();
    await connectGuest(page, uniqueNick(), channel);
    for (const move of LIFECYCLE.slice(0, 2)) await receiveMove(page, channel, move);
    await expect(cards).toHaveCount(2, { timeout: 10_000 });
    await expect(cards.nth(0)).toContainText(words[0]);
    await expect(cards.nth(1)).toContainText(words[1]);

    for (const [i, move] of LIFECYCLE.slice(2).entries()) {
      await receiveMove(page, channel, move);
      await expect(cards).toHaveCount(i + 3);
      await expect(cards.nth(i + 2)).toContainText(words[i + 2]);
    }

    // The finished lifecycle: four cards, four words, and the sender's prose
    // nowhere — every event is a card and stays one.
    await expect(cards.nth(2)).toContainText('tagged the build');
    await expect(page.getByTestId('message-list')).not.toContainText('offered: ship the release');

    // And the whole thing over again — the JOIN replay, then the CHATHISTORY
    // the client asks for next — is still those same four cards.
    for (const move of LIFECYCLE) await receiveMove(page, channel, move);
    await expect(cards).toHaveCount(4, { timeout: 10_000 });
    for (const [i, word] of words.entries()) {
      await expect(cards.nth(i)).toContainText(word);
    }
  });

  test('next from the offer card lands on the claim card', async ({ page }) => {
    const channel = uniqueChannel();
    await connectGuest(page, uniqueNick(), channel);
    for (const move of LIFECYCLE) await receiveMove(page, channel, move);

    const cards = page.getByTestId('act-card');
    await expect(cards).toHaveCount(4);
    await cards.nth(0).getByText('next →').click();

    // The jump highlights the row it lands on, which is the claim's line.
    const claim = page.locator(`#msg-m-${LIFECYCLE[1].eventId}`);
    await expect(claim).toHaveClass(/bg-accent/);
    await expect(claim.getByTestId('act-card')).toContainText('claimed');
  });
});
