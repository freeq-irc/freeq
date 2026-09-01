// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';
import { CoordinationEventCard } from './CoordinationCards';
import { TaskTimeline } from './TaskTimeline';
import { AuditTimeline } from './AuditTimeline';
import type { Message } from '../store';
import * as api from '../lib/api';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// A coordination type that still cards: the six task names lost theirs and
// render as ordinary text, so they carry no card ink to check.
function signedEventMsg(): Message {
  return {
    id: '01KZTEST00000000000000TEST',
    from: 'workerbot',
    text: 'handed the fetch to bob',
    timestamp: new Date(0),
    tags: {
      '+freeq.at/event': 'delegation_notice',
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
    expect(container.textContent).toContain('delegation_notice');
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

// A DID is the identity the app operates on, never the name it shows a
// person. The audit timeline was chopping one to 20 characters, which put a
// mid-string `did:key:z6MkiM7w5ZcW` in front of the reader.
describe('the audit timeline never renders a raw DID', () => {
  it('resolves the actor, and compacts it when nothing resolves', async () => {
    const event = {
      id: 1,
      event_id: '01KZAUDIT0000000000000AUD',
      category: 'coordination',
      event_type: 'task_request',
      actor_did: 'did:key:z6MkiM7w5ZcWlongtailthatgetschopped',
      channel: '#naptest',
      payload_json: '{"capability":"url_fetch"}',
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 0,
    };
    vi.spyOn(api, 'apiFetch').mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ events: [event] }),
    } as unknown as Response);

    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    // Nothing resolves this bot, so it wears the compact form — not a DID
    // truncated mid-identifier, and not the full string either.
    await waitFor(() => expect(container.textContent).toContain('key:z6Mk…'));
    expect(container.textContent).not.toContain('did:key:z6MkiM7w5ZcW');
  });
});
