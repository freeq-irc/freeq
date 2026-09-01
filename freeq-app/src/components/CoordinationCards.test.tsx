// @vitest-environment jsdom
/** Every event type gets the same card.
 *
 *  There is no list of types that card and no per-type face: the six names the
 *  act events replaced, the two that used to have faces of their own, and a
 *  type nobody has taught this client all render identically. The payload is
 *  always visible, in the rows the payload rule builds.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { CoordinationEventCard } from './CoordinationCards';
import type { Message } from '../store';

afterEach(cleanup);

const RETIRED = [
  'task_request',
  'task_accept',
  'task_update',
  'task_complete',
  'task_failed',
  'evidence_attach',
] as const;

function eventMsg(eventType: string, text = 'a line about the work', payload?: string): Message {
  return {
    id: '01KYVT1W2P0000000000000000',
    from: 'agent',
    text,
    timestamp: new Date(0),
    tags: {
      '+freeq.at/event': eventType,
      ...(payload === undefined ? {} : { '+freeq.at/payload': encodeURIComponent(payload) }),
    },
  } as unknown as Message;
}

/** The card's shape, as the assertions below compare it. */
function shapeOf(container: HTMLElement) {
  const card = container.querySelector('[data-testid="event-card"]');
  return {
    type: card?.querySelector('[data-testid="event-card-type"]')?.textContent,
    className: (card as HTMLElement | null)?.className,
    hasPayload: !!card?.querySelector('[data-testid="event-payload"]'),
  };
}

describe('the six names the act events replaced', () => {
  for (const name of RETIRED) {
    it(`${name} renders the generic card`, () => {
      const { container } = render(<CoordinationEventCard msg={eventMsg(name)} />);
      expect(container.querySelector('[data-testid="event-card"]')).not.toBeNull();
      expect(shapeOf(container).type).toBe(name);
    });
  }
});

describe('no type gets a face of its own', () => {
  const types = [...RETIRED, 'delegation_notice', 'status_update', 'society-question', 'nobody_taught_this'];

  it('every type renders the same card shape', () => {
    const shapes = types.map((t) => {
      const { container } = render(<CoordinationEventCard msg={eventMsg(t)} />);
      const s = shapeOf(container);
      cleanup();
      return { ...s, type: undefined };
    });
    for (const s of shapes) expect(s).toEqual(shapes[0]);
  });

  it('the header shows the type lowercased in monospace behind a ◇', () => {
    const { container, getByText } = render(<CoordinationEventCard msg={eventMsg('Delegation_Notice')} />);
    const label = container.querySelector('[data-testid="event-card-type"]')!;
    expect(label.textContent).toBe('delegation_notice');
    expect(label.className).toContain('font-mono');
    expect(getByText('◇')).toBeTruthy();
  });

  it('a generic card wears no colour and no edge', () => {
    const { container } = render(<CoordinationEventCard msg={eventMsg('status_update')} />);
    const cls = (container.querySelector('[data-testid="event-card"]') as HTMLElement).className;
    expect(cls).not.toMatch(/border-l|text-purple|text-blue|text-success|text-danger|text-warning/);
  });

  it('a message carrying no event tag is not a coordination event', () => {
    const plain = { ...eventMsg('task_request'), tags: {} } as Message;
    const { container } = render(<CoordinationEventCard msg={plain} />);
    expect(container.firstChild).toBeNull();
  });
});

describe('the body carries the sender line as sent', () => {
  it('shows the text unaltered, spacing included', () => {
    const text = '📋 New task: ship it   — with  spacing kept';
    const { container } = render(<CoordinationEventCard msg={eventMsg('task_request', text)} />);
    // textContent, not getByText: the matcher collapses runs of whitespace and
    // the card is asserting it did not.
    expect(container.textContent).toContain(text);
  });

  it('renders with no body text at all', () => {
    const { container } = render(<CoordinationEventCard msg={eventMsg('status_update', '')} />);
    expect(container.querySelector('[data-testid="event-card"]')).not.toBeNull();
  });
});

describe('the payload rows, always visible', () => {
  /** key/value pairs the card is showing, in order. */
  function rows(container: HTMLElement): [string, string][] {
    const dl = container.querySelector('[data-testid="event-payload"]');
    if (!dl) return [];
    const keys = [...dl.querySelectorAll('dt')].map((n) => n.textContent!);
    const vals = [...dl.querySelectorAll('dd')].map((n) => n.textContent!);
    return keys.map((k, i) => [k, vals[i]]);
  }

  it('an object spreads into one row per top-level key', () => {
    const { container } = render(
      <CoordinationEventCard msg={eventMsg('status_update', 'x', '{"to":"bob","n":2}')} />,
    );
    expect(rows(container)).toEqual([['to', 'bob'], ['n', '2']]);
  });

  it('an array is one row keyed payload', () => {
    const { container } = render(
      <CoordinationEventCard msg={eventMsg('status_update', 'x', '[1,2]')} />,
    );
    expect(rows(container)).toEqual([['payload', '[1,2]']]);
  });

  it('a scalar is one row keyed payload', () => {
    const { container } = render(
      <CoordinationEventCard msg={eventMsg('status_update', 'x', '42')} />,
    );
    expect(rows(container)).toEqual([['payload', '42']]);
  });

  it('text that is not JSON is one row keyed payload carrying it raw', () => {
    const { container } = render(
      <CoordinationEventCard msg={eventMsg('status_update', 'x', 'not json at all')} />,
    );
    expect(rows(container)).toEqual([['payload', 'not json at all']]);
  });

  it('no payload tag means no payload rows', () => {
    const { container } = render(<CoordinationEventCard msg={eventMsg('status_update')} />);
    expect(rows(container)).toEqual([]);
  });

  it('a long value scrolls inside its row rather than growing the card', () => {
    const { container } = render(
      <CoordinationEventCard
        msg={eventMsg('status_update', 'x', JSON.stringify({ log: 'y'.repeat(4000) }))}
      />,
    );
    const dd = container.querySelector('[data-testid="event-payload"] dd') as HTMLElement;
    expect(dd.className).toMatch(/max-h-/);
    expect(dd.className).toMatch(/overflow-auto/);
  });
});
