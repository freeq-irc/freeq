// @vitest-environment jsdom
/**
 * A "confirmed" line drawn under the card it confirms, and the "New" divider
 * around the two, through the list itself.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

// Render every row: jsdom has no layout for the virtualizer to measure.
vi.mock('virtua', async () => {
  const React = await import('react');
  return {
    Virtualizer: React.forwardRef<HTMLDivElement, { children?: React.ReactNode }>(({ children }, ref) =>
      React.createElement('div', { ref }, children)),
  };
});

const { MessageList } = await import('./MessageList');
const { useStore } = await import('../store');

const s = () => useStore.getState();
const CH = '#room';
const OPENER = '01JOPENER00000000000000000';
const SECOND = Date.UTC(2026, 9, 9, 12, 0, 0);

/** The id an event minted at that moment carries: a ULID, time first. */
function idAt(ms: number): string {
  const crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = crockford[ms % 32] + time;
    ms = Math.floor(ms / 32);
  }
  return time + 'ZZZZZZZZZZZZZZZZ';
}

const CLAIM = idAt(SECOND + 400);
const RECEIPT = idAt(SECOND + 450);
const CARD = '01M00000000000000000000CRD';

function act(verb: string, eventId: string, from: string, fields: Record<string, string> = {}) {
  return {
    from, did: `did:plc:${from}`, kind: 'handoff', verb, eventId, taskId: OPENER,
    fields: eventId === OPENER
      ? { act: 'handoff', 'act-verb': verb, 'act-title': 'ship the release' }
      : { act: 'handoff', 'act-verb': verb, 'act-id': OPENER, ...fields },
  };
}

/** Live order: the step, the home's confirmation, and later the card's line. */
function stepAndConfirmation() {
  s().addActEvent(CH, act('offer', OPENER, 'poster'));
  s().addActEvent(CH, act('claim', CLAIM, 'worker'));
  s().addActEvent(CH, act('confirm', RECEIPT, 'acceptance', { 'act-subject': CLAIM }));
}

function card() {
  s().addMessage(CH, {
    id: CARD, from: 'worker', text: 'on it', timestamp: new Date(SECOND + 1000),
    tags: { '+freeq.at/ref': OPENER, account: 'did:plc:worker' },
  });
}

function said(id: string, text: string, at: number) {
  s().addMessage(CH, { id, from: 'alice', text, timestamp: new Date(at), tags: {} });
}

/** Leave the room, so what it last held is what was read, and come back. */
function leave() {
  s().setActiveChannel('server');
}

function shown() {
  s().setActiveChannel(CH);
  const { getByTestId } = render(<MessageList />);
  return getByTestId('message-list');
}

/** Row ids in the order they are drawn. */
function drawn(list: HTMLElement): string[] {
  return Array.from(list.querySelectorAll('[id^="msg-"]')).map((el) => el.id.slice(4));
}

/** The row the "New" divider sits in, before that row's own content. */
function dividerRow(list: HTMLElement): string | undefined {
  return list.querySelector('#unread-marker')?.closest('[id^="msg-"]')?.id.slice(4);
}

beforeEach(() => {
  s().reset();
  s().addChannel(CH);
  s().historyFetchStarted(CH, false);
  s().historyPageReceived(CH, 50, 50, 50);
  s().setActiveChannel(CH);
});
afterEach(() => cleanup());

describe('a confirmation line', () => {
  it('is drawn under its card though it is stored above it', () => {
    stepAndConfirmation();
    card();
    expect(s().channels.get(CH)!.messages.map((m) => m.id)).toEqual([RECEIPT, CARD]);
    expect(drawn(shown())).toEqual([CARD, RECEIPT]);
  });

  it('gets no "New" divider between it and its card when both were read', () => {
    stepAndConfirmation();
    card();
    leave();
    said('01M00000000000000000000LTR', 'later', SECOND + 60_000);
    const list = shown();
    expect(drawn(list)).toEqual([CARD, RECEIPT, '01M00000000000000000000LTR']);
    expect(dividerRow(list)).toBe('01M00000000000000000000LTR');
  });

  it('puts the "New" divider above a card that arrived after its line was read', () => {
    stepAndConfirmation();
    leave();
    card();
    const list = shown();
    expect(drawn(list)).toEqual([CARD, RECEIPT]);
    expect(dividerRow(list)).toBe(CARD);
  });
});
