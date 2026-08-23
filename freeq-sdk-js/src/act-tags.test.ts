/**
 * What a task event's tags say, and the line a room reads beside it.
 *
 * Both are byte-identical to the Rust SDK's `act_tags` and `act_line`, which
 * `scripts/compare-act-tags.mjs` holds them to across eighteen shapes. These
 * pin the rules each one follows on its own.
 */
import { describe, expect, it } from 'vitest';
import { actLine, actTags } from './signing';

const TASK = '01JABCDEF000000000000000EF';

describe('actTags', () => {
  it('leaves an opener naming no action', () => {
    // An opener's own event id becomes the action's, so `act-id` is the one
    // tag it must not carry.
    expect(
      actTags('handoff', 'offer', undefined, 'did:plc:eliza', {
        title: 'Cite 3 sources on X',
        caps: 'freeq.at/web-search',
      }),
    ).toEqual({
      '+freeq.at/act': 'handoff',
      '+freeq.at/act-verb': 'offer',
      '+freeq.at/from': 'did:plc:eliza',
      '+freeq.at/act-title': 'Cite 3 sources on X',
      '+freeq.at/act-caps': 'freeq.at/web-search',
    });
  });

  it('makes a follow-up name its action, and nothing else changes', () => {
    expect(actTags('handoff', 'claim', TASK, 'did:plc:scholar', {})).toEqual({
      '+freeq.at/act': 'handoff',
      '+freeq.at/act-verb': 'claim',
      '+freeq.at/from': 'did:plc:scholar',
      '+freeq.at/act-id': TASK,
    });
  });

  it('prefixes a hyphenated field whole', () => {
    const tags = actTags('handoff', 'progress', TASK, 'did:plc:scholar', {
      ctx: 'https://example.com/x',
      'ctx-h': 'sha256:9f00',
    });
    expect(tags['+freeq.at/act-ctx-h']).toBe('sha256:9f00');
    expect(tags['+freeq.at/act-ctx']).toBe('https://example.com/x');
  });

  it('builds a kind and verb it has never heard of', () => {
    // Which verbs a kind allows is the rules file's business, not this
    // function's: it writes what it is told.
    const tags = actTags('lease', 'renew', TASK, 'did:plc:eliza', { term: '30d' });
    expect(tags['+freeq.at/act']).toBe('lease');
    expect(tags['+freeq.at/act-verb']).toBe('renew');
    expect(tags['+freeq.at/act-term']).toBe('30d');
  });
});

describe('actLine', () => {
  it('says what each verb did', () => {
    // A handoff is a task in prose; every other kind is called by its name.
    expect(actLine('handoff', 'offer', { title: 'Cite 3 sources on X' })).toBe(
      'offered: Cite 3 sources on X',
    );
    expect(actLine('handoff', 'accept', {})).toBe('accepted the task');
    expect(actLine('handoff', 'decline', {})).toBe('declined the task');
    expect(actLine('handoff', 'claim', {})).toBe('claimed the task');
    expect(actLine('handoff', 'complete', {})).toBe('completed the task');
    expect(actLine('handoff', 'fail', {})).toBe('failed the task');
    expect(actLine('handoff', 'cancel', {})).toBe('cancelled the task');
    expect(actLine('bounty', 'cancel', {})).toBe('cancelled the bounty');
    expect(actLine('bounty', 'award', {})).toBe('awarded the bounty');
    expect(actLine('bounty', 'submit', {})).toBe('submitted the work');
    expect(actLine('bounty', 'revise', {})).toBe('asked for revisions');
    expect(actLine('bounty', 'accept-work', {})).toBe('accepted the work');
    expect(actLine('bounty', 'forfeit', {})).toBe('forfeited the bounty');
  });

  it('uses a note only when one was written', () => {
    expect(actLine('handoff', 'progress', {})).toBe('made progress');
    expect(actLine('handoff', 'progress', { note: 'halfway' })).toBe('progress: halfway');
    expect(actLine('bounty', 'bid', {})).toBe('bid on the bounty');
    expect(actLine('bounty', 'bid', { note: 'two days' })).toBe('bid: two days');
  });

  it('names a verb it has no sentence for', () => {
    // A kind may add a verb without editing prose; the room still sees what
    // it was.
    expect(actLine('lease', 'renew', {})).toBe('renew');
  });
});
