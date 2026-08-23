// @vitest-environment jsdom
/**
 * The card a task event's companion line becomes: its headline is the word
 * for the verb that event carried, and every event keeps its own card.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { ActEventCard } from './ActCards';
import { actHeadline } from '../lib/act-verbs';
import type { Message, ActTask, ActEvent } from '../store';

afterEach(cleanup);

const TASK_ID = '01JOPENER00000000000000000';

function task(events: ActEvent[]): ActTask {
  return {
    taskId: TASK_ID,
    kind: 'handoff',
    title: 'ship the release',
    offerer: 'did:plc:poster',
    verb: events[events.length - 1].verb,
    ctx: [],
    events,
  };
}

function event(verb: string, fields: Record<string, string> = {}): ActEvent {
  return { eventId: `e-${verb}`, verb, from: 'worker', did: 'did:plc:worker', fields, msgId: `m-${verb}` };
}

function msg(id: string): Message {
  return { id, from: 'worker', text: 'whatever the sender wrote', timestamp: new Date(0), tags: { '+freeq.at/ref': TASK_ID } };
}

const WORDS: Array<[string, string]> = [
  ['offer', 'offered'],
  ['accept', 'accepted'],
  ['decline', 'declined'],
  ['claim', 'claimed'],
  ['progress', 'in progress'],
  ['complete', 'completed'],
  ['fail', 'failed'],
  ['cancel', 'cancelled'],
  ['bid', 'bid'],
  ['award', 'awarded'],
  ['submit', 'submitted'],
  ['revise', 'revisions requested'],
  ['accept-work', 'accepted'],
  ['forfeit', 'forfeited'],
];

describe('the headline word', () => {
  it.each(WORDS)('a %s shows "%s"', (verb, word) => {
    const ev = event(verb);
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.textContent).toContain(word);
  });

  it('shows a verb it has not been taught by its own name', () => {
    expect(actHeadline('withdraw-bid')).toBe('withdraw-bid');
  });

  // The home's own two verbs write no companion, so they have no card — their
  // words are read in the timeline, off the same table.
  it('has a word for each verb the home signs itself', () => {
    expect(actHeadline('confirm')).toBe('confirmed');
    expect(actHeadline('expire')).toBe('expired');
  });

  it('reads a progress off the event, not off where the task got to', () => {
    const moves = [event('claim'), event('progress', { 'act-note': 'tagged the build' })];
    const { container } = render(
      <ActEventCard msg={msg('m-progress')} task={task(moves)} event={moves[1]} />,
    );
    expect(container.textContent).toContain('in progress');
    expect(container.textContent).not.toContain('claimed');
  });
});

describe('what the card carries', () => {
  it('shows the task title and the event\'s own note', () => {
    const ev = event('progress', { 'act-note': 'tagged the build' });
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.textContent).toContain('ship the release');
    expect(container.textContent).toContain('tagged the build');
  });

  it('links the context the event carried, under the hash its signature covers', () => {
    const ev = event('progress', {
      'act-ctx': 'https://example.com/checks/abc',
      'act-ctx-h': 'sha256:9f00',
    });
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    const link = container.querySelector('a')!;
    expect(link.getAttribute('href')).toBe('https://example.com/checks/abc');
    expect(link.getAttribute('title')).toBe('sha256:9f00');
  });

  it('never shows the sender\'s prose in place of the card', () => {
    const ev = event('claim');
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.textContent).not.toContain('whatever the sender wrote');
  });
});
