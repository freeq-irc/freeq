// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';
import { CoordinationEventCard } from './CoordinationCards';
import { TaskTimeline } from './TaskTimeline';
import type { Message } from '../store';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function signedEventMsg(): Message {
  return {
    id: '01KZTEST00000000000000TEST',
    from: 'workerbot',
    text: '📋 New task: fetch this URL',
    timestamp: new Date(0),
    tags: {
      '+freeq.at/event': 'task_request',
      '+freeq.at/payload': '%7B%7D',
      '+freeq.at/sig': 'ed25519:kid:sigsigsig',
    },
  };
}

// A signed event earns no resting ink anywhere — signing is the default
// state; verification is an explicit action (the message row's context
// menu covers cards; the timelines carry their own verify buttons).
describe('act surfaces carry no resting signature ink', () => {
  it('coordination card renders without a lock or signed-claim for a signed event', () => {
    const { container } = render(<CoordinationEventCard msg={signedEventMsg()} />);
    expect(container.textContent).toContain('New Task');
    expect(container.textContent).not.toContain('🔒');
    expect(container.querySelector('[title="Cryptographically signed"]')).toBeNull();
  });

  it('task timeline shows verify actions instead of resting locks', async () => {
    const task = {
      event_id: '01KZTASK00000000000000TASK',
      event_type: 'task_request',
      actor_did: 'did:plc:worker',
      channel: '#tasks',
      payload_json: '{"description":"fetch this URL"}',
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 0,
    };
    const evidence = {
      ...task,
      event_id: '01KZEVID00000000000000EVID',
      event_type: 'evidence_attach',
      payload_json: '{"type":"commit","summary":"done"}',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ task, events: [evidence] }),
    }));

    const { container, getAllByText } = render(
      <TaskTimeline taskId={task.event_id} onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('fetch this URL'));
    expect(container.textContent).not.toContain('🔒');
    // Header + evidence row each offer an explicit check.
    expect(getAllByText('verify').length).toBe(2);
  });
});
