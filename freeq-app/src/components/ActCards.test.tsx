// @vitest-environment jsdom
/**
 * The card a task event's companion line becomes: its headline is the word
 * for the verb that event carried, and every event keeps its own card.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { render, cleanup, fireEvent } from '@testing-library/react';
import { ActEventCard, cardNeighbours } from './ActCards';
import { actHeadline, actEmoji, actRegister } from '../lib/act-verbs';
import type { Message, ActTask, ActEvent } from '../store';
import { useStore } from '../store';

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

beforeEach(() => {
  // The seal panel's open state lives in the store now; a test must not
  // inherit the previous test's open card.
  useStore.setState({ sealPanelFor: null });
});

describe('the headline word', () => {
  it.each(WORDS)('a %s shows "%s"', (verb, word) => {
    const ev = event(verb);
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    expect(container.textContent).toContain(word);
  });

  it('shows a verb it has not been taught by its own name', () => {
    expect(actHeadline('withdraw-bid')).toBe('withdraw-bid');
  });

  // The home's own three verbs write no companion, so they have no card —
  // their words are read on a system line, off the same table.
  it('has a word for each verb the home signs itself', () => {
    expect(actHeadline('confirm')).toBe('confirmed');
    expect(actHeadline('expire')).toBe('expired');
    expect(actHeadline('auto-accept')).toBe('accepted (review window closed)');
  });

  it('has a glyph for each verb the home signs itself', () => {
    expect(actEmoji('confirm')).toBe('✔️');
    expect(actEmoji('expire')).toBe('⌛');
    expect(actEmoji('auto-accept')).toBe('⏱️');
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

describe('the colour law', () => {
  /** register → the token this client paints it in. */
  const PAINT: Array<[string, string, string]> = [
    // verb, the class on the headline word, the class on the card's edge
    ['offer', 'text-purple', 'border-l-purple'],
    ['claim', 'text-blue', 'border-l-blue'],
    ['progress', 'text-blue', 'border-l-blue'],
    ['bid', 'text-blue', 'border-l-blue'],
    ['complete', 'text-success', 'border-l-success'],
    ['accept-work', 'text-success', 'border-l-success'],
    ['fail', 'text-danger', 'border-l-danger'],
    ['forfeit', 'text-danger', 'border-l-danger'],
    ['cancel', 'text-danger', 'border-l-danger'],
    ['decline', 'text-danger', 'border-l-danger'],
    ['escalate', 'text-warning', 'border-l-warning'],
  ];

  function frame(verb: string): HTMLElement {
    const ev = event(verb);
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    return container.querySelector('[data-testid="act-card"] > div') as HTMLElement;
  }

  it.each(PAINT)('a %s paints its word %s and its edge %s', (verb, word, edge) => {
    const el = frame(verb);
    expect(el.className).toContain(edge);
    expect(el.querySelector('[data-testid="act-headline"]')!.className).toContain(word);
  });

  it.each(PAINT)('a %s washes the border in the same hue', (verb, word) => {
    const hue = word.replace('text-', '');
    expect(frame(verb).className).toContain(`border-${hue}/`);
  });

  it('every act card carries an edge — it is the act-vs-generic tell', () => {
    for (const [verb] of PAINT) {
      expect(frame(verb).className, verb).toContain('border-l-[3px]');
      cleanup();
    }
  });

  it('the register is what picks the hue, not the verb', () => {
    for (const [verb, word] of PAINT) {
      const byRegister: Record<string, string> = {
        new: 'text-purple', inProgress: 'text-blue', endedWell: 'text-success',
        didNotEndWell: 'text-danger', neutralEnd: 'text-warning',
      };
      expect(byRegister[actRegister(verb)!], verb).toBe(word);
    }
  });
});

describe('the seal', () => {
  function card(verb: string, fields: Record<string, string> = {}) {
    const ev = event(verb, fields);
    return render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
  }

  const CARDING = ['offer', 'accept', 'decline', 'claim', 'progress', 'complete', 'fail',
                   'cancel', 'bid', 'award', 'submit', 'revise', 'accept-work', 'forfeit',
                   'escalate'];

  it.each(CARDING)('a %s card carries the seal', (verb) => {
    const { container } = card(verb);
    expect(container.querySelector('[data-testid="act-seal"]')).not.toBeNull();
  });

  it.each(CARDING)('the seal on a %s card is monochrome, never the card hue', (verb) => {
    const { container } = card(verb);
    const seal = container.querySelector('[data-testid="act-seal"]') as HTMLElement;
    expect(seal.className).toContain('text-fg-dim');
    expect(seal.className).not.toMatch(/text-(purple|blue|success|danger|warning)/);
    // `currentColor` and nothing else: no fill or stroke of its own.
    expect(seal.querySelector('svg')!.outerHTML).not.toMatch(/#[0-9a-fA-F]{3,6}/);
  });

  it('is shut until it is asked for', () => {
    const { container } = card('claim');
    expect(container.querySelector('[data-testid="act-seal-panel"]')).toBeNull();
  });

  it('opens the panel without opening the timeline modal', () => {
    const { container } = card('claim');
    fireEvent.click(container.querySelector('[data-testid="act-seal"]')!);
    expect(container.querySelector('[data-testid="act-seal-panel"]')).not.toBeNull();
    expect(document.body.querySelector('[data-testid="act-timeline-modal"]')).toBeNull();
  });

  it('shuts again on a second click', () => {
    const { container } = card('claim');
    const seal = container.querySelector('[data-testid="act-seal"]')!;
    fireEvent.click(seal);
    fireEvent.click(seal);
    expect(container.querySelector('[data-testid="act-seal-panel"]')).toBeNull();
  });
});

describe("the seal panel's words", () => {
  function panelOf(verb: string, kind = 'handoff'): HTMLElement {
    const ev = event(verb, { act: kind });
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    fireEvent.click(container.querySelector('[data-testid="act-seal"]')!);
    return container.querySelector('[data-testid="act-seal-panel"]') as HTMLElement;
  }

  it('heads the panel with the kind off the event tag, uppercased', () => {
    expect(panelOf('claim', 'handoff').textContent).toContain('HANDOFF: Rules Enforced');
    cleanup();
    expect(panelOf('bid', 'bounty').textContent).toContain('BOUNTY: Rules Enforced');
  });

  it('takes a kind nobody has taught it', () => {
    expect(panelOf('claim', 'society-question').textContent)
      .toContain('SOCIETY-QUESTION: Rules Enforced');
  });

  const SENTENCES: Array<[string, string]> = [
    ['offer', 'This opened a task with known rules: who may take it, who may work it, who may finish it. Every later step is checked against those rules before the server accepts it — an illegal step is refused and never appears here.'],
    ['accept', 'Only the person this task was offered to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.'],
    ['progress', 'Only the worker this task is assigned to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.'],
    ['cancel', 'Only the person who posted this task could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.'],
    ['claim', "Any signed-in account could take this step, and the server checked it was legal from the task's current state before accepting it — an illegal step is refused and never appears here."],
  ];

  it.each(SENTENCES)('a %s says what the server enforced', (verb, sentence) => {
    expect(panelOf(verb).textContent).toContain(sentence);
  });

  it('offers the link to the full history', () => {
    const panel = panelOf('claim');
    expect(panel.textContent).toContain('View full history');
  });

  it('opens the timeline from that link', () => {
    const ev = event('claim', { act: 'handoff' });
    const { container } = render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
    fireEvent.click(container.querySelector('[data-testid="act-seal"]')!);
    fireEvent.click(container.querySelector('[data-testid="act-seal-history"]')!);
    expect(document.body.querySelector('[data-testid="act-timeline-modal"]')).not.toBeNull();
  });

  it('claims nothing for a verb it has no rule for', () => {
    const panel = panelOf('escalate');
    expect(panel.textContent).toContain('ESCALATE'.length ? 'Rules Enforced' : '');
    expect(panel.textContent).not.toContain('could take this step');
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

describe('the way into the history', () => {
  function card(fields: Record<string, string> = {}) {
    const ev = event('progress', fields);
    return render(<ActEventCard msg={msg(ev.msgId!)} task={task([ev])} event={ev} />);
  }

  const modal = () => document.body.querySelector('[data-testid="act-timeline-modal"]');

  it('opens the timeline from the title', () => {
    const { getByText } = card();
    fireEvent.click(getByText('ship the release'));
    expect(modal()).not.toBeNull();
  });

  it('opens the timeline from the task id', () => {
    const { getByText } = card();
    fireEvent.click(getByText('01JOPENER0…'));
    expect(modal()).not.toBeNull();
  });

  it('leaves the rest of the body alone — a click on the note opens nothing', () => {
    const { getByText } = card({ 'act-note': 'tagged the build' });
    fireEvent.click(getByText('tagged the build'));
    expect(modal()).toBeNull();
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
