// @vitest-environment jsdom
/**
 * Where a "confirmed" line is drawn: directly under the card of the step it
 * confirms, whatever order time put the two in.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { confirmLinesUnderCards } from './ActCards';
import { useStore } from '../store';
import type { ActTask, ActEvent, Message } from '../store';

const SECOND = Date.UTC(2026, 9, 9, 12, 0, 0);

function row(id: string, at: number, extra: Partial<Message> = {}): Message {
  return { id, from: 'worker', text: id, timestamp: new Date(at), tags: {}, ...extra };
}

/** The line the home's confirmation draws, stamped by the home's clock. */
function systemRow(id: string, at: number): Message {
  return row(id, at, { from: '', isSystem: true });
}

function event(eventId: string, verb: string, extra: Partial<ActEvent> = {}): ActEvent {
  return { eventId, verb, from: 'worker', fields: {}, ...extra };
}

function confirm(eventId: string, subject: string): ActEvent {
  return event(eventId, 'confirm', { from: 'home', fields: { 'act-subject': subject } });
}

function task(taskId: string, events: ActEvent[]): ActTask {
  return { taskId, kind: 'handoff', title: 'ship it', verb: 'claim', ctx: [], events };
}

/** One task: a claim drawn as the card `card`, and the home's confirmation of it. */
function claimed(card = 'card', line = 'line'): Map<string, ActTask> {
  return new Map([['t1', task('t1', [event('claim', 'claim', { msgId: card }), confirm(line, 'claim')])]]);
}

const ids = (rows: Message[]) => rows.map((m) => m.id);

describe('confirmLinesUnderCards', () => {
  it('draws a line stored above its card under it, the card stamped in the step s second or the next', () => {
    for (const cardAt of [SECOND, SECOND + 1000]) {
      const stored = [row('before', SECOND - 5000), systemRow('line', SECOND + 400), row('card', cardAt), row('after', SECOND + 9000)];
      expect(ids(confirmLinesUnderCards(stored, claimed()))).toEqual(['before', 'card', 'line', 'after']);
    }
  });

  it('leaves a line already under its card where it is', () => {
    for (const cardAt of [SECOND, SECOND + 1000]) {
      const stored = [row('card', cardAt), systemRow('line', cardAt + 400), row('after', SECOND + 9000)];
      expect(ids(confirmLinesUnderCards(stored, claimed()))).toEqual(['card', 'line', 'after']);
    }
  });

  it('leaves a line where its time put it when its card is not drawn or was deleted', () => {
    const missing = [systemRow('line', SECOND + 400), row('after', SECOND + 9000)];
    expect(ids(confirmLinesUnderCards(missing, claimed()))).toEqual(['line', 'after']);

    const deleted = [systemRow('line', SECOND + 400), row('card', SECOND, { deleted: true })];
    expect(ids(confirmLinesUnderCards(deleted, claimed()))).toEqual(['line', 'card']);
  });

  it('leaves an expiry line by its time', () => {
    const tasks = new Map([['t1', task('t1', [event('claim', 'claim', { msgId: 'card' }), event('gone', 'expire', { from: 'home' })])]]);
    const stored = [systemRow('gone', SECOND + 400), row('card', SECOND)];
    expect(ids(confirmLinesUnderCards(stored, tasks))).toEqual(['gone', 'card']);
  });

  it('puts each of two tasks lines under its own card', () => {
    const tasks = new Map([
      ['t1', task('t1', [event('a', 'claim', { msgId: 'cardA' }), confirm('lineA', 'a')])],
      ['t2', task('t2', [event('b', 'claim', { msgId: 'cardB' }), confirm('lineB', 'b')])],
    ]);
    const stored = [
      systemRow('lineA', SECOND + 100), systemRow('lineB', SECOND + 200),
      row('cardA', SECOND), row('between', SECOND), row('cardB', SECOND + 1000),
    ];
    expect(ids(confirmLinesUnderCards(stored, tasks))).toEqual(['cardA', 'lineA', 'between', 'cardB', 'lineB']);
  });

  it('keeps two lines under one card in their order', () => {
    const tasks = new Map([['t1', task('t1', [
      event('claim', 'claim', { msgId: 'card' }), confirm('first', 'claim'), confirm('second', 'claim'),
    ])]]);
    const stored = [systemRow('first', SECOND + 100), systemRow('second', SECOND + 200), row('card', SECOND + 1000)];
    expect(ids(confirmLinesUnderCards(stored, tasks))).toEqual(['card', 'first', 'second']);
  });
});

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

describe('a confirmation line arriving live', () => {
  const CH = '#work';
  const OPENER = '01JOPENER00000000000000000';
  const s = () => useStore.getState();

  beforeEach(() => {
    s().reset();
    s().addChannel(CH);
  });

  /** A move on the task, as the bridge hands it over. */
  function act(verb: string, eventId: string, from: string, fields: Record<string, string> = {}) {
    const opener = eventId === OPENER;
    return {
      from, did: `did:plc:${from}`, kind: 'handoff', verb, eventId, taskId: OPENER,
      fields: opener
        ? { act: 'handoff', 'act-verb': verb, 'act-title': 'ship the release' }
        : { act: 'handoff', 'act-verb': verb, 'act-id': OPENER, ...fields },
    };
  }

  // Live, every reader gets the step, then the home's confirmation, then the
  // card's line: the sender holds its line until the server echoes the step.
  // The confirmation is stamped by its id's millisecond and the line by the
  // server's whole second, in the step's second or the next.
  for (const [stamping, offset] of [['the step s second', 0], ['the next second', 1000]] as const) {
    it(`is stored above its card and drawn under it, the card stamped in ${stamping}`, () => {
      const at = SECOND + 400;
      const claim = idAt(at);
      const receipt = idAt(at + 50);
      s().addActEvent(CH, act('offer', OPENER, 'poster'));
      s().addActEvent(CH, act('claim', claim, 'worker'));
      s().addActEvent(CH, act('confirm', receipt, 'acceptance', { 'act-subject': claim }));
      s().addMessage(CH, {
        id: 'm-card', from: 'worker', text: 'on it', timestamp: new Date(SECOND + offset),
        tags: { '+freeq.at/ref': OPENER, account: 'did:plc:worker' },
      });

      const ch = s().channels.get(CH)!;
      expect(ids(ch.messages)).toEqual([receipt, 'm-card']);
      expect(ch.actTasks.get(OPENER)!.events.find((e) => e.eventId === claim)!.msgId).toBe('m-card');
      expect(ids(confirmLinesUnderCards(ch.messages, ch.actTasks))).toEqual(['m-card', receipt]);
    });
  }
});
