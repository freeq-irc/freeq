// @vitest-environment jsdom
/**
 * The task history panel: a row is the step's message, and clicking it goes
 * there.
 *
 * The endpoint knows the events; only the store knows which line each one was
 * paired with, so a row that has no companion — a receipt, an expiry — has
 * nowhere to go and stays inert.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, cleanup, waitFor, fireEvent } from '@testing-library/react';
import { TaskTimeline } from './TaskTimeline';
import { useStore } from '../store';
import type { Message } from '../store';
import * as api from '../lib/api';

/** The id an event minted at that moment carries: a ULID, time first. A
 *  companion is paired with the event of its own second, so the ids and the
 *  line have to agree about when this happened. */
function idAt(ms: number, tail: string): string {
  const crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = crockford[ms % 32] + time;
    ms = Math.floor(ms / 32);
  }
  return time + tail;
}

const CH = '#work';
const NOW = Date.now();
const OPENER = idAt(NOW, 'OPENER0000000000');
const ACCEPT = idAt(NOW, 'ACCEPT0000000000');
const RECEIPT = idAt(NOW, 'RECEIPT000000000');
const POSTER = 'did:plc:poster';
const WORKER = 'did:plc:worker';
const HOME = 'did:web:irc.example';

beforeEach(() => {
  useStore.getState().reset();
  // `reset` leaves the pending jump where it is, so each test starts by
  // clearing it: that field is what these assertions read.
  useStore.getState().setScrollToMsgId(null);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/** The three events as `/api/v1/actions/{id}` serves them. */
function served() {
  return [
    {
      event_id: OPENER,
      canonical: JSON.stringify({ act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release' }),
      actor_did: POSTER,
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 1756900000,
    },
    {
      event_id: ACCEPT,
      canonical: JSON.stringify({ act: 'handoff', 'act-verb': 'accept', 'act-id': OPENER }),
      actor_did: WORKER,
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 1756900001,
    },
    {
      event_id: RECEIPT,
      canonical: JSON.stringify({ act: 'handoff', 'act-verb': 'confirm', 'act-id': OPENER }),
      actor_did: HOME,
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 1756900002,
    },
  ];
}

function companion(id: string, from: string, did: string): Message {
  return {
    id,
    from,
    text: 'accepted: ship the release',
    timestamp: new Date(NOW),
    tags: { '+freeq.at/ref': OPENER, account: did },
  };
}

/** The store as the room left it: two steps, one of them with a line. */
function seed() {
  const s = useStore.getState();
  s.addChannel(CH);
  s.addActEvent(CH, {
    from: 'poster', did: POSTER, kind: 'handoff', verb: 'offer',
    eventId: OPENER, taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release' },
  });
  s.addActEvent(CH, {
    from: 'worker', did: WORKER, kind: 'handoff', verb: 'accept',
    eventId: ACCEPT, taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': 'accept', 'act-id': OPENER },
  });
  s.addMessage(CH, companion('m2', 'worker', WORKER) as never);
}

function open(onClose: () => void) {
  vi.spyOn(api, 'apiFetch').mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ task: null, events: served() }),
  } as unknown as Response);
  return render(<TaskTimeline actId={OPENER} onClose={onClose} />);
}

describe('a row of a task s history', () => {
  it('jumps to the step s message and closes the panel', async () => {
    seed();
    expect(useStore.getState().channels.get(CH)!.actTasks.get(OPENER)!
      .events.find(e => e.eventId === ACCEPT)!.msgId).toBe('m2');

    const onClose = vi.fn();
    const { container, getByText } = open(onClose);
    await waitFor(() => expect(container.textContent).toContain('accepted'));

    fireEvent.click(getByText('accepted').parentElement!);
    expect(useStore.getState().scrollToMsgId).toBe('m2');
    expect(onClose).toHaveBeenCalled();
  });

  it('does not react when the step wrote no line', async () => {
    seed();
    const onClose = vi.fn();
    const { container, getByText } = open(onClose);
    await waitFor(() => expect(container.textContent).toContain('accepted'));

    // The receipt is served but never entered the store's task, so it has no
    // companion and no jump.
    fireEvent.click(getByText('confirmed').parentElement!);
    expect(useStore.getState().scrollToMsgId).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('checks a signature without jumping', async () => {
    seed();
    const onClose = vi.fn();
    const { container, getAllByText } = open(onClose);
    await waitFor(() => expect(container.textContent).toContain('accepted'));

    fireEvent.click(getAllByText('verify')[1]);
    expect(useStore.getState().scrollToMsgId).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('public receipt permalink', () => {
  it('offers a link a stranger can open, pointing at the task id', async () => {
    // The in-app panel proves a signature to whoever is already logged in.
    // This is the version you paste to someone who is not, and who has no
    // reason to take our word for anything.
    vi.spyOn(api, 'apiFetch').mockResolvedValue(
      new Response(JSON.stringify({ task: null, events: served() }), { status: 200 }),
    );
    const { container } = render(<TaskTimeline actId={OPENER} onClose={() => {}} />);
    await waitFor(() => expect(container.querySelector('a[href^="/act/"]')).toBeTruthy());

    const link = container.querySelector('a[href^="/act/"]') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe(`/act/${OPENER}`);
    // Opening evidence must not navigate away from the conversation, and an
    // external tab gets no handle back on this one.
    expect(link.target).toBe('_blank');
    expect(link.rel).toContain('noopener');
  });
});
