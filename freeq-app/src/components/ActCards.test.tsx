// @vitest-environment jsdom
/**
 * The card a task event's companion line becomes: its headline is the word
 * for the verb that event carried, and every event keeps its own card.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { ActEventCard, cardNeighbours } from './ActCards';
import { actHeadline, actEmoji, actAccent } from '../lib/act-verbs';
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

const GLYPHS: Array<[string, string]> = [
  ['offer', '📋'],
  ['accept', '👍'],
  ['decline', '👎'],
  ['claim', '✋'],
  ['progress', '📌'],
  ['complete', '🎉'],
  ['fail', '❌'],
  ['cancel', '🚫'],
  ['bid', '💰'],
  ['award', '🏆'],
  ['submit', '📤'],
  ['revise', '🔁'],
  ['accept-work', '✅'],
  ['forfeit', '🏳️'],
];

describe('the headline glyph', () => {
  it.each(GLYPHS)('a %s shows %s', (verb, glyph) => {
    expect(actEmoji(verb)).toBe(glyph);
  });

  // Same discipline as the word table: a kind may add a move without this
  // having to be taught it.
  it('pins a verb it has not been taught', () => {
    expect(actEmoji('withdraw-bid')).toBe('📌');
    expect(actEmoji('')).toBe('📌');
  });

  it('puts the event\'s own glyph on the card, not a fixed one', () => {
    const ev = event('complete');
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.textContent).toContain('🎉');
    expect(container.textContent).not.toContain('📋');
  });
});

describe('the accent edge', () => {
  it('marks the moves that put work on a plate', () => {
    expect(actAccent('offer')).toBe('handoff');
    expect(actAccent('award')).toBe('handoff');
  });

  it('marks a good end and a bad one', () => {
    expect(actAccent('complete')).toBe('success');
    expect(actAccent('accept-work')).toBe('success');
    expect(actAccent('fail')).toBe('failure');
  });

  it('leaves every other verb unaccented', () => {
    const plain = ['accept', 'decline', 'claim', 'progress', 'cancel', 'bid',
                   'submit', 'revise', 'forfeit', 'escalate'];
    for (const verb of plain) expect(actAccent(verb)).toBe('none');
  });

  it('paints the edge in the colour the accent names', () => {
    const cases: Array<[string, string]> = [
      ['offer', 'border-l-purple'],
      ['complete', 'border-l-success'],
      ['fail', 'border-l-danger'],
    ];
    for (const [verb, edge] of cases) {
      const ev = event(verb);
      const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
      expect(container.querySelector('[data-testid="act-card"] > div')!.className).toContain(edge);
      cleanup();
    }
  });

  it('draws no edge on a verb with no accent', () => {
    const ev = event('progress');
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.querySelector('[data-testid="act-card"] > div')!.className).not.toContain('border-l-');
  });
});

describe('the headline casing', () => {
  it('is uppercased by the style, so the word itself is untouched', () => {
    const ev = event('progress');
    const { getByText } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(getByText('in progress').className).toContain('uppercase');
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

describe('skipping between a task\'s cards', () => {
  const lifecycle = [event('offer'), event('claim'), event('progress'), event('complete')];

  it('names the card before and the card after', () => {
    expect(cardNeighbours(task(lifecycle), lifecycle[1])).toEqual({ prev: 'm-offer', next: 'm-progress' });
  });

  it('offers nothing before the first card, or after the last', () => {
    expect(cardNeighbours(task(lifecycle), lifecycle[0])).toEqual({ prev: undefined, next: 'm-claim' });
    expect(cardNeighbours(task(lifecycle), lifecycle[3])).toEqual({ prev: 'm-progress', next: undefined });
  });

  it('skips the events the home signs, which are lines and not cards', () => {
    const confirmed = [
      lifecycle[0],
      { eventId: 'e-confirm', verb: 'confirm', from: 'e2e', fields: {} },
      lifecycle[1],
    ];
    expect(cardNeighbours(task(confirmed), lifecycle[0])).toEqual({ prev: undefined, next: 'm-claim' });
  });

  it('puts the links in a footer of the card, under a divider', () => {
    const { container } = render(<ActEventCard msg={msg('m-claim')} task={task(lifecycle)} event={lifecycle[1]} />);
    const footer = container.querySelector('[data-testid="card-footer"]')!;
    expect(footer.className).toContain('border-t');
    // The header is the card's only filled strip, so the footer takes no tint.
    expect(footer.className).not.toContain('bg-');
    expect(footer.textContent).toContain('← prev');
    expect(footer.textContent).toContain('next →');
  });

  it('renders no footer on a card with no neighbours', () => {
    const only = [event('offer')];
    const { container } = render(<ActEventCard msg={msg('m-offer')} task={task(only)} event={only[0]} />);
    expect(container.querySelector('[data-testid="card-footer"]')).toBeNull();
  });

  it('shows a link for each neighbour a card has', () => {
    const first = render(<ActEventCard msg={msg('m-offer')} task={task(lifecycle)} event={lifecycle[0]} />);
    expect(first.container.textContent).toContain('next →');
    expect(first.container.textContent).not.toContain('← prev');
    cleanup();

    const middle = render(<ActEventCard msg={msg('m-claim')} task={task(lifecycle)} event={lifecycle[1]} />);
    expect(middle.container.textContent).toContain('← prev');
    expect(middle.container.textContent).toContain('next →');
  });

  it('asks the list to jump to the neighbour it names', async () => {
    const { useStore } = await import('../store');
    const { getByText } = render(
      <ActEventCard msg={msg('m-claim')} task={task(lifecycle)} event={lifecycle[1]} />,
    );
    getByText('next →').click();
    expect(useStore.getState().scrollToMsgId).toBe('m-progress');
    getByText('← prev').click();
    expect(useStore.getState().scrollToMsgId).toBe('m-offer');
  });
});
