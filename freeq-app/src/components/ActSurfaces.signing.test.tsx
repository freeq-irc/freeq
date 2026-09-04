// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor, fireEvent } from '@testing-library/react';

// Display resolution reads the SDK's learned nick↔DID map; give it one name to
// find so a row carrying a DID can be asserted as the name it resolves to.
const NAMED_DID = 'did:plc:namedone';
vi.mock('../irc/client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../irc/client')>()),
  getClient: () => ({
    apiBearer: null,
    getNickForDid: (did: string) => (did === NAMED_DID ? 'carol' : undefined),
  }),
}));

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
    const ACT_ID = '01KZTASK00000000000000TASK';
    const offer = {
      event_id: ACT_ID,
      canonical: JSON.stringify({ 'act-verb': 'offer', 'act-title': 'fetch this URL' }),
      actor_did: 'did:plc:worker',
      signature: 'ed25519:kid:sigsigsig',
      timestamp: 0,
    };
    const accept = {
      ...offer,
      event_id: '01KZACPT00000000000000ACPT',
      canonical: JSON.stringify({ 'act-verb': 'accept', 'act-id': ACT_ID }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ task: null, events: [offer, accept] }),
    }));

    const { container, getAllByText } = render(
      <TaskTimeline actId={ACT_ID} onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('fetch this URL'));
    expect(container.textContent).not.toContain('🔒');
    // Each event row offers an explicit check.
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

// The audit timeline is one time order over three kinds of row, and a task
// event is one of them: the verb word the cards use, the title the step
// named, the cards' seal, and the same verify link every signed row carries.
describe('the audit timeline says why it is empty', () => {
  it('tells a refused reader the audit is for signed-in members', async () => {
    vi.spyOn(api, 'apiFetch').mockResolvedValue({
      ok: false,
      status: 403,
      json: () => Promise.resolve({ error: 'Forbidden' }),
    } as unknown as Response);
    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain("This channel's audit is shown only to signed-in members."));
    expect(container.textContent).not.toContain('No audit events found.');
  });

  it('says when the audit could not be loaded', async () => {
    vi.spyOn(api, 'apiFetch').mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({}),
    } as unknown as Response);
    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('The audit could not be loaded.'));
  });

  it('still says no events for an empty answer', async () => {
    vi.spyOn(api, 'apiFetch').mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ timeline: [] }),
    } as unknown as Response);
    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('No audit events found.'));
  });
});

describe('the audit timeline reads task events', () => {
  function mockRows(rows: unknown[]) {
    vi.spyOn(api, 'apiFetch').mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ timeline: rows }),
    } as unknown as Response);
  }

  const RECEIPT_ID = '01KZRCPT00000000000000RCPT';

  const actRow = {
    category: 'act',
    event: 'accept',
    actor_did: 'did:plc:bob',
    actor_name: 'bob',
    event_id: '01KZACPT00000000000000ACPT',
    signature: 'ed25519:kid:sigsigsig',
    timestamp: 1756900000,
    details: {
      kind: 'handoff',
      title: 'Cite 3 sources',
      act_id: '01KZTASK00000000000000TASK',
      confirm_state: 'confirmed',
      receipt: { event_id: RECEIPT_ID, timestamp: 1756900009, signature: 'ed25519:kid:sig' },
    },
  };

  it('shows the verb word, the title, the seal and verify', async () => {
    mockRows([actRow]);
    const { container, getByText, getByTestId } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    expect(container.textContent).toContain('accepted');
    const seal = getByTestId('act-seal');
    expect(seal.getAttribute('title')).toBe('HANDOFF: Rules Enforced');
    expect(getByText('verify')).toBeTruthy();
  });

  it('opens and closes the row s details', async () => {
    mockRows([actRow]);
    const { container, getByLabelText, getByTestId, queryByTestId } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    expect(queryByTestId('audit-details')).toBeNull();

    const details = getByLabelText('Details');
    expect(details.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(details);
    expect(getByTestId('audit-details').textContent).toContain('01KZRCPT');
    expect(getByLabelText('Details').getAttribute('aria-expanded')).toBe('true');

    fireEvent.click(getByLabelText('Details'));
    expect(queryByTestId('audit-details')).toBeNull();
  });

  it('opens the cards seal panel from the seal, without a history link', async () => {
    mockRows([actRow]);
    const { container, getByTestId, getByLabelText, queryByTestId } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    expect(queryByTestId('act-seal-panel')).toBeNull();

    fireEvent.click(getByTestId('act-seal'));
    const panel = getByTestId('act-seal-panel');
    expect(panel.textContent).toContain('HANDOFF: Rules Enforced');
    // No task timeline on this surface, so no link to one.
    expect(queryByTestId('act-seal-history')).toBeNull();

    // The two disclosures take turns.
    fireEvent.click(getByLabelText('Details'));
    expect(queryByTestId('act-seal-panel')).toBeNull();
    expect(queryByTestId('audit-details')).not.toBeNull();
    fireEvent.click(getByTestId('act-seal'));
    expect(queryByTestId('audit-details')).toBeNull();
    expect(queryByTestId('act-seal-panel')).not.toBeNull();

    // And each closes on a second click of its own control.
    fireEvent.click(getByTestId('act-seal'));
    expect(queryByTestId('act-seal-panel')).toBeNull();
  });

  it('leaves the row itself untouched when a disclosure opens', async () => {
    mockRows([actRow]);
    const { container, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    const before = getByTestId('audit-row').className;
    fireEvent.click(getByLabelText('Details'));
    expect(getByTestId('audit-row').className).toBe(before);
    // The block is a sibling of the row, not a cell inside its grid.
    expect(getByTestId('audit-row').contains(getByTestId('audit-details'))).toBe(false);
  });

  it('opens on the chevron and on nothing else', async () => {
    mockRows([actRow]);
    const { container, getByLabelText, getByTestId, queryByTestId } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    // The row is not a control: reading it, or clicking the words in it,
    // opens nothing.
    fireEvent.click(getByTestId('audit-summary'));
    expect(queryByTestId('audit-details')).toBeNull();
    fireEvent.click(getByTestId('audit-time'));
    expect(queryByTestId('audit-details')).toBeNull();

    fireEvent.click(getByLabelText('Details'));
    expect(queryByTestId('audit-details')).not.toBeNull();
  });

  it('lays every row out on the same six columns', async () => {
    mockRows([actRow]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    const row = getByTestId('audit-row');
    expect(row.className).toContain('grid-cols-[64px_24px_128px_minmax(0,1fr)_96px_88px]');
    // Under 640px the row is two lines: time, icon and the words, then the
    // state and the controls beneath them.
    expect(row.className).toContain('@max-[640px]:grid-cols-[44px_20px_minmax(0,1fr)]');
  });

  it('carries the whole summary as the line s hover text', async () => {
    mockRows([{ ...actRow, details: { ...actRow.details, note: 'two found so far' } }]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    const line = getByTestId('audit-summary');
    expect(line.textContent).toBe('accepted · Cite 3 sources · two found so far');
    expect(line.getAttribute('title')).toBe('accepted · Cite 3 sources · two found so far');
  });

  it('reads the clock in 24-hour form, seconds and all', async () => {
    mockRows([actRow]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    const expected = new Date(1756900000 * 1000).toLocaleTimeString([], {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    expect(getByTestId('audit-time').textContent).toBe(expected);
    expect(expected).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });

  it('says nothing in the column when the home confirmed the step', async () => {
    mockRows([actRow]);
    const { container, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    // A confirmed step is the ordinary case and the column stays empty.
    expect(getByTestId('audit-ruling').textContent).toBe('');

    // The ruling is in the details: the receipt's own id, whole so it can be
    // copied, with its own check and nothing else.
    fireEvent.click(getByLabelText('Details'));
    const details = getByTestId('audit-details').textContent!;
    expect(details).toContain(RECEIPT_ID);
    expect(details).toContain('verify');
    // Not its signature, which no eye can check, and not its time, which is
    // the step's own time on the row.
    expect(details).not.toContain('ed25519');
    const at = new Date(1756900009 * 1000).toLocaleTimeString([], {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    expect(details).not.toContain(at);
  });

  it('names the exception, and says what the word means', async () => {
    for (const [word, hover] of [
      ['unconfirmed', "The task's home server has not confirmed this step yet"],
      ['superseded', 'An earlier step won this move; this one did not count'],
    ]) {
      mockRows([{
        ...actRow,
        details: { kind: 'handoff', title: 'Cite 3 sources', confirm_state: word },
      }]);
      const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
      await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
      const column = getByTestId('audit-ruling');
      expect(column.textContent).toBe(word);
      expect(column.getAttribute('title')).toBe(hover);
      expect(column.className).toContain('text-warning');
      cleanup();
    }
  });

  it('checks the receipt s own signature, not the step s', async () => {
    mockRows([actRow]);
    // The panel does not print the id it was handed; what it does with it is
    // ask the verify endpoint, so the request is the assertion.
    const asked = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ verification: { verdict: 'valid' } }),
    });
    vi.stubGlobal('fetch', asked);

    const { container, getByTitle, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    fireEvent.click(getByLabelText('Details'));
    fireEvent.click(getByTitle("Check the receipt's signature"));

    expect(getByTestId('verify-panel')).toBeTruthy();
    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(asked.mock.calls[0][0]).toContain(RECEIPT_ID);
    expect(asked.mock.calls[0][0]).not.toContain('01KZACPT');
  });

  it('says nothing in the column when the home ruled the step confirmed, receipt or not', async () => {
    mockRows([{
      ...actRow,
      event: 'complete',
      event_id: '01KZCMPL00000000000000CMPL',
      details: { kind: 'handoff', title: 'Cite 3 sources', confirm_state: 'confirmed' },
    }]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    expect(getByTestId('audit-ruling').textContent).toBe('');
  });

  it('labels a task row s details the way a card does, with names not identifiers', async () => {
    mockRows([{
      ...actRow,
      event: 'offer',
      event_id: '01KZTASK00000000000000TASK',
      details: {
        kind: 'handoff',
        act_id: '01KZTASK00000000000000TASK',
        title: 'Cite 3 sources',
        to: NAMED_DID,
        note: 'two found so far',
        confirm_state: 'confirmed',
      },
    }]);
    const { container, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    fireEvent.click(getByLabelText('Details'));
    const details = getByTestId('audit-details');
    // The cards' own labels, not the wire's key names.
    expect(details.textContent).toContain('offered to');
    expect(details.textContent).toContain('carol');
    expect(details.textContent).not.toContain(NAMED_DID);
    expect(details.textContent).toContain('note');
    // The task this step belongs to, whole: the details are the one place a
    // reader can copy an id from.
    expect(details.textContent).toContain('01KZTASK00000000000000TASK');
  });

  it('resolves a DID in a governance row s details', async () => {
    mockRows([{
      category: 'governance',
      event: 'pause',
      actor_did: 'did:plc:target',
      timestamp: 1756900000,
      details: { issued_by: NAMED_DID, reason: 'spam' },
    }]);
    const { container, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('paused by'));
    fireEvent.click(getByLabelText('Details'));
    const details = getByTestId('audit-details');
    expect(details.textContent).toContain('carol');
    expect(details.textContent).not.toContain(NAMED_DID);
  });

  it('breaks a long details value instead of overflowing the panel', async () => {
    const long = 'x'.repeat(120);
    mockRows([{
      category: 'coordination',
      event: 'status_update',
      actor_did: 'did:plc:worker',
      actor_name: 'worker',
      timestamp: 1756900000,
      details: { blob: long },
    }]);
    const { container, getByTestId, getByLabelText } = render(
      <AuditTimeline channel="#naptest" onClose={() => {}} />,
    );
    await waitFor(() => expect(container.textContent).toContain('status_update'));
    fireEvent.click(getByLabelText('Details'));
    const block = getByTestId('audit-details');
    expect(block.className).toContain('min-w-0');
    expect(block.className).toContain('w-full');
    const value = getByTestId('audit-detail-value');
    expect(value.textContent).toBe(long);
    expect(value.className).toContain('break-all');
  });

  it('leaves a retired coordination name as its own word', async () => {
    mockRows([{
      category: 'coordination',
      event: 'task_request',
      actor_did: 'did:plc:worker',
      actor_name: 'worker',
      timestamp: 1756900000,
      details: { description: 'fetch this URL' },
    }]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('task_request'));
    expect(container.textContent).not.toContain('created task');
    // A ruling is a thing said about a task step; no other row says one.
    expect(getByTestId('audit-ruling').textContent).toBe('');
  });

  it('filters the list by the type dropdown', async () => {
    mockRows([
      actRow,
      {
        category: 'coordination',
        event: 'status_update',
        actor_did: 'did:plc:worker',
        actor_name: 'worker',
        timestamp: 1756900000,
        details: { state: 'working' },
      },
    ]);
    const { container, getByTestId } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('status_update'));
    expect(container.textContent).toContain('2 events');

    const types = container.querySelectorAll('select')[1];
    fireEvent.change(types, { target: { value: 'act' } });
    await waitFor(() => expect(container.textContent).not.toContain('status_update'));
    expect(getByTestId('audit-summary').textContent).toBe('accepted · Cite 3 sources');
    expect(container.textContent).toContain('1 events');

    fireEvent.change(types, { target: { value: 'governance' } });
    await waitFor(() => expect(container.textContent).toContain('No audit events found.'));
  });

  it('filters by an actor without emptying the actor menu', async () => {
    const bob = { ...actRow, actor_did: 'did:plc:bob', actor_name: 'bob' };
    const worker = {
      category: 'coordination',
      event: 'status_update',
      actor_did: 'did:plc:worker',
      actor_name: 'worker',
      timestamp: 1756900000,
      details: { state: 'working' },
    };
    const home = {
      category: 'act',
      event: 'expire',
      actor_did: 'did:web:eyeball.local',
      actor_name: 'server: eyeball.local',
      event_id: '01KZEXPR00000000000000EXPR',
      timestamp: 1756900002,
      details: { kind: 'handoff', confirm_state: 'confirmed' },
    };
    // The route's own filter, so a value the route cannot match shows up as
    // an empty list here the way it does against a real server.
    vi.spyOn(api, 'apiFetch').mockImplementation(async (path: string) => {
      const asked = new URL(path, 'http://x').searchParams.get('actor');
      const rows = [bob, worker, home].filter(r => !asked || r.actor_did === asked);
      return { ok: true, json: () => Promise.resolve({ timeline: rows }) } as unknown as Response;
    });

    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('status_update'));
    const menu = container.querySelectorAll('select')[0] as HTMLSelectElement;
    // People first, then a break, then the homes — a server is not a person.
    expect([...menu.querySelectorAll('option')].map(o => o.textContent))
      .toEqual(['All actors', 'bob', 'worker', '──────────', 'server: eyeball.local']);
    expect([...menu.querySelectorAll('option')].map(o => o.getAttribute('value')))
      .toEqual(['', 'did:plc:bob', 'did:plc:worker', null, 'did:web:eyeball.local']);
    expect(menu.querySelector('option[disabled]')).not.toBeNull();

    fireEvent.change(menu, { target: { value: 'did:plc:bob' } });
    await waitFor(() => expect(container.textContent).not.toContain('status_update'));
    expect(container.textContent).toContain('Cite 3 sources');
    // The menu still holds both, and still holds the selection.
    expect(menu.querySelectorAll('option').length).toBe(5);
    expect(menu.value).toBe('did:plc:bob');
  });

  it('offers exactly the four type filters', async () => {
    mockRows([]);
    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('No audit events found.'));
    const types = container.querySelectorAll('select')[1];
    expect([...types.querySelectorAll('option')].map(o => [o.getAttribute('value'), o.textContent]))
      .toEqual([['', 'All types'], ['coordination', 'Events'], ['act', 'Tasks'], ['governance', 'Governance']]);
  });

  it('dates a row from unix seconds, not from milliseconds', async () => {
    mockRows([actRow]);
    const { container } = render(<AuditTimeline channel="#naptest" onClose={() => {}} />);
    await waitFor(() => expect(container.textContent).toContain('Cite 3 sources'));
    const expected = new Date(1756900000 * 1000).toLocaleTimeString([], {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    expect(container.textContent).toContain(expected);
    expect(container.textContent).not.toContain('1970');
  });
});
