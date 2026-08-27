// @vitest-environment jsdom
/**
 * The action timeline's headline: the title the opener signed, and nothing at
 * all where no opener the reader holds signed one — an id is not a name.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';
import { TaskTimeline } from './TaskTimeline';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const ACT_ID = '01KZACTION0000000000000ACT';

/** One event as `/api/v1/actions/{id}` serves it: the bytes it signed, and
 *  the row the view lists it under. */
function event(eventId: string, doc: Record<string, string>) {
  return {
    event_id: eventId,
    canonical: JSON.stringify(doc),
    signature: 'ed25519:kid:sigsigsig',
    actor_did: 'did:plc:worker',
    timestamp: 0,
  };
}

function serve(events: ReturnType<typeof event>[]) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ task: null, events }),
  }));
}

describe('the action timeline headline', () => {
  it('shows the title the opener signed', async () => {
    serve([
      event(ACT_ID, { 'act-verb': 'offer', 'act-title': 'ship the release' }),
      event('01KZCLAIM00000000000000CLM', { 'act-verb': 'claim' }),
    ]);

    const { container } = render(<TaskTimeline actId={ACT_ID} onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('ship the release'));
    expect(container.textContent).toContain('claimed');
  });

  it("reads the home's own moves under their own words", async () => {
    serve([
      event(ACT_ID, { 'act-verb': 'offer', 'act-title': 'ship the release' }),
      event('01KZCONFIRM000000000000CNF', { 'act-verb': 'confirm', 'act-subject': ACT_ID }),
      event('01KZEXPIRE0000000000000EXP', { 'act-verb': 'expire' }),
    ]);

    const { container } = render(<TaskTimeline actId={ACT_ID} onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('confirmed'));
    expect(container.textContent).toContain('expired');
  });

  it('shows no id in place of a title the reader never got', async () => {
    serve([event('01KZCLAIM00000000000000CLM', { 'act-verb': 'claim' })]);

    const { container } = render(<TaskTimeline actId={ACT_ID} onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('claimed'));
    expect(container.textContent).not.toContain(ACT_ID);
    // The id fragment beside the headline is the badge every card carries.
    expect(container.textContent).toContain(ACT_ID.slice(0, 12));
  });
});
