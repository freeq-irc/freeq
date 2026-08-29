// @vitest-environment jsdom
/**
 * A task card in a direct message.
 *
 * Nothing here is DM-specific by design: the store files a task under
 * whatever key it is handed, and a DM's key is the peer's canonical id
 * rather than a channel name. These tests pin that the same event and the
 * same companion line reach a card either way.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { render, renderHook, cleanup } from '@testing-library/react';
import { ActEventCard, useActCompanion } from './ActCards';
import { useStore } from '../store';
import type { Message } from '../store';

afterEach(cleanup);

const DM = 'did:plc:worker';
const CH = '#work';
const OPENER = '01JOPENER00000000000000000';
const POSTER = 'did:plc:poster';

beforeEach(() => {
  useStore.getState().reset();
});

/** The opener as the bridge hands it over, filed under `where`. */
function offer() {
  return {
    from: 'poster',
    did: POSTER,
    kind: 'handoff',
    verb: 'offer',
    eventId: OPENER,
    taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release' },
  };
}

/** The companion line the sender wrote beside it. */
function companion(): Message {
  return {
    id: 'm1',
    from: 'poster',
    text: 'offered: ship the release',
    timestamp: new Date(),
    tags: { '+freeq.at/ref': OPENER, account: POSTER },
  };
}

function fileBoth(where: string): void {
  const s = useStore.getState();
  s.addChannel(where);
  s.addActEvent(where, offer());
  s.addMessage(where, companion() as never);
}

describe('a task card in a DM', () => {
  it('pairs the event with its companion line, the way a channel does', () => {
    fileBoth(DM);
    fileBoth(CH);
    const inDm = useStore.getState().channels.get(DM)!.actTasks.get(OPENER)!;
    const inChannel = useStore.getState().channels.get(CH)!.actTasks.get(OPENER)!;
    expect(inDm.events.map((e) => e.msgId)).toEqual(['m1']);
    expect(inDm.events).toEqual(inChannel.events);
  });

  it('resolves the line to card data through the path a channel line takes', () => {
    fileBoth(DM);
    const { result } = renderHook(() => useActCompanion(companion(), DM));
    expect(result.current).not.toBeNull();
    expect(result.current!.task.title).toBe('ship the release');
    expect(result.current!.event.verb).toBe('offer');
  });

  it('renders the card the resolved data names', () => {
    fileBoth(DM);
    const { result } = renderHook(() => useActCompanion(companion(), DM));
    const { task, event } = result.current!;
    const { container } = render(<ActEventCard msg={companion()} task={task} event={event} />);
    // The headline word for this event's own verb, and the task it is about.
    expect(container.textContent).toContain('offered');
    expect(container.textContent).toContain('ship the release');
    // Never the sender's prose in place of the card.
    expect(container.textContent).not.toContain('offered: ship the release');
  });

  it('answers for the buffer the task was filed under and no other', () => {
    fileBoth(DM);
    const { result } = renderHook(() => useActCompanion(companion(), CH));
    expect(result.current).toBeNull();
  });
});
