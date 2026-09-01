// @vitest-environment jsdom
/**
 * The row cards every event-tagged message.
 *
 * Tested at the row rather than at the card: the row is where the decision is
 * made, and it is the branch that has to stop asking what the event type is.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { MessageContent } from './MessageList';
import type { Message } from '../store';

afterEach(cleanup);

const TYPES = [
  'task_request',
  'task_accept',
  'task_update',
  'task_complete',
  'task_failed',
  'evidence_attach',
  'delegation_notice',
  'status_update',
  'society-question',
  'nobody_taught_this',
];

function eventMsg(eventType: string, text: string): Message {
  return {
    id: `m-${eventType}`,
    from: 'agent',
    text,
    timestamp: new Date(0),
    tags: { '+freeq.at/event': eventType },
  };
}

describe('an event-tagged row is a card', () => {
  it.each(TYPES)('%s draws the generic card', (eventType) => {
    const { container } = render(<MessageContent msg={eventMsg(eventType, 'a line')} />);
    expect(container.querySelector('[data-testid="event-card"]')).not.toBeNull();
  });

  it.each(TYPES)('%s names its type in the header', (eventType) => {
    const { container } = render(<MessageContent msg={eventMsg(eventType, 'a line')} />);
    expect(
      container.querySelector('[data-testid="event-card-type"]')?.textContent,
    ).toBe(eventType);
  });

  it.each(TYPES)('%s keeps the line its sender wrote', (eventType) => {
    const text = `the sender's own words about ${eventType}`;
    const { container } = render(<MessageContent msg={eventMsg(eventType, text)} />);
    expect(container.textContent).toContain(text);
  });
});

describe('a row with no event tag', () => {
  it('draws no card', () => {
    const plain: Message = {
      id: 'plain', from: 'agent', text: 'just a line', timestamp: new Date(0), tags: {},
    };
    const { container } = render(<MessageContent msg={plain} />);
    expect(container.querySelector('[data-testid="event-card"]')).toBeNull();
    expect(container.textContent).toContain('just a line');
  });
});
