import { describe, it, expect } from 'vitest';
import { actFacts, unknownFields } from './act-facts';

const R = (k: string) => (k === 'did:key:zWORKER' ? 'cardworker2' : k);

describe('the card facts', () => {
  it('a directed offer names its recipient, resolved, never raw', () => {
    expect(actFacts({ 'act-to': 'did:key:zWORKER' }, true, R)).toEqual([['offered to', 'cardworker2']]);
  });
  it('an opener with no recipient is offered to anyone', () => {
    expect(actFacts({}, true, R)).toEqual([['offered to', 'anyone']]);
  });
  it('a follow-up with no act-to claims nothing about audience', () => {
    expect(actFacts({}, false, R)).toEqual([]);
  });
  it('money is labelled: price on offers, bid on bids', () => {
    expect(actFacts({ 'act-price': '250 USD' }, true, R))
      .toEqual([['offered to', 'anyone'], ['price', '250 USD']]);
    expect(actFacts({ 'act-bid': '200 USD' }, false, R)).toEqual([['bid', '200 USD']]);
  });
  it('deadlines carry a local time as their value', () => {
    const facts = actFacts({ 'act-deadline': '1788000000' }, true, R);
    expect(facts[0]).toEqual(['offered to', 'anyone']);
    expect(facts[1][0]).toBe('deadline');
    expect(facts[1][1]).toBeTruthy();
  });
  it('a bid deadline gets its own label', () => {
    const facts = actFacts({ 'act-bid-deadline': '1788000000' }, true, R);
    expect(facts[1][0]).toBe('bids close');
  });
  it('capabilities are labelled as required skills', () => {
    expect(actFacts({ 'act-caps': 'url_fetch' }, true, R))
      .toEqual([['offered to', 'anyone'], ['skills required', 'url_fetch']]);
  });
  it("the award's winner gets an awarded-to line of its own", () => {
    expect(actFacts({}, false, R, 'did:key:zWORKER')).toEqual([['awarded to', 'cardworker2']]);
  });
  it('an unreadable deadline is skipped, not rendered as garbage', () => {
    expect(actFacts({ 'act-deadline': 'soon' }, false, R)).toEqual([]);
  });
  it('the note is a row of the grid, not a line under it', () => {
    expect(actFacts({ 'act-note': 'two days' }, false, R)).toEqual([['note', 'two days']]);
  });
  it('the context link is a row', () => {
    expect(actFacts({ 'act-ctx': 'https://example.org/a' }, false, R))
      .toEqual([['context', 'https://example.org/a']]);
  });
  it('the context hash is a row', () => {
    expect(actFacts({ 'act-ctx-h': 'sha256:9f00' }, false, R))
      .toEqual([['hash', 'sha256:9f00']]);
  });
  it('the payee is a row: a DID resolves, anything else is shown as sent', () => {
    expect(actFacts({ 'act-pay-to': 'did:key:zWORKER' }, false, R))
      .toEqual([['pay to', 'cardworker2']]);
    expect(actFacts({ 'act-pay-to': '0xdeadbeef' }, false, R))
      .toEqual([['pay to', '0xdeadbeef']]);
  });
  it('the payment is a row', () => {
    expect(actFacts({ 'act-tx': 'eth:0xdemo' }, false, R)).toEqual([['payment', 'eth:0xdemo']]);
  });
  it('the action a revision replaces is a row, under its raw id for now', () => {
    expect(actFacts({ 'act-replaces': '01JOLD' }, false, R)).toEqual([['replaces', '01JOLD']]);
  });
  it('the scope is a row', () => {
    expect(actFacts({ 'act-scope': 'room' }, false, R)).toEqual([['scope', 'room']]);
  });
  it('the seven follow the labelled facts, in their own fixed order', () => {
    expect(actFacts({
      'act-price': '250 USD', 'act-caps': 'url_fetch', 'act-note': 'two days',
      'act-ctx': 'https://example.org/a', 'act-ctx-h': 'sha256:9f00',
      'act-pay-to': 'did:key:zW', 'act-tx': 'eth:0xdemo', 'act-replaces': '01JOLD',
      'act-scope': 'room',
    }, true, R)).toEqual([
      ['offered to', 'anyone'],
      ['price', '250 USD'],
      ['skills required', 'url_fetch'],
      ['note', 'two days'],
      ['context', 'https://example.org/a'],
      ['hash', 'sha256:9f00'],
      ['pay to', 'did:key:zW'],
      ['payment', 'eth:0xdemo'],
      ['replaces', '01JOLD'],
      ['scope', 'room'],
    ]);
  });
});

describe('the unlabelled fields', () => {
  it('a field the card has no label for keeps its own key', () => {
    expect(unknownFields({ 'act-mystery': 'y', 'act-oracle': 'z' }))
      .toEqual([['mystery', 'y'], ['oracle', 'z']]);
  });
  it('the four newly labelled fields no longer fall through', () => {
    expect(unknownFields({
      'act-pay-to': 'did:key:zW', 'act-tx': 'eth:0xabc',
      'act-replaces': '01JOLD', 'act-scope': 'room',
    })).toEqual([]);
  });
  it('labelled and structural fields never fall through', () => {
    expect(unknownFields({
      act: 'handoff', 'act-verb': 'offer', 'act-id': 'X', 'act-to': 'd',
      'act-title': 't', 'act-note': 'n', 'act-ctx': 'u', 'act-ctx-h': 'h', 'act-deadline': '1',
      'act-bid-deadline': '1', 'act-caps': 'c', 'act-price': 'p',
      'act-bid': 'b', 'act-accepts': 'e', 'act-subject': 's',
      'act-pay-to': 'p2', 'act-tx': 'tx', 'act-replaces': 'r', 'act-scope': 'sc',
    })).toEqual([]);
  });
  it('non-act tags are not its business', () => {
    expect(unknownFields({ msgid: 'X', 'act-mystery': 'y' })).toEqual([['mystery', 'y']]);
  });
});
