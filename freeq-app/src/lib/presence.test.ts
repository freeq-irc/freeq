import { describe, it, expect } from 'vitest';
import { initialJoinPartDisplay, isPresenceLine, summarizePresence } from './presence';

const sys = (text: string) => ({ text, isSystem: true });

describe('isPresenceLine', () => {
  it('matches join, part and quit notices', () => {
    expect(isPresenceLine(sys('alice joined'))).toBe(true);
    expect(isPresenceLine(sys('bob left'))).toBe(true);
    expect(isPresenceLine(sys('carol quit'))).toBe(true);
    expect(isPresenceLine(sys('carol quit (Ping timeout: 120 seconds)'))).toBe(true);
  });

  it('leaves moderation and other system lines alone', () => {
    expect(isPresenceLine(sys('bob was kicked by alice (spam)'))).toBe(false);
    expect(isPresenceLine(sys("Couldn't join the call: full"))).toBe(false);
    expect(isPresenceLine(sys('Joining existing voice session (3 participants)'))).toBe(false);
  });

  it('never matches what someone said', () => {
    expect(isPresenceLine({ text: 'alice joined' })).toBe(false);
    expect(isPresenceLine({ text: 'alice joined', isSystem: false })).toBe(false);
  });
});

describe('summarizePresence', () => {
  it("names one person's churn as a reconnect", () => {
    expect(summarizePresence([sys('nap left'), sys('nap joined'), sys('nap quit (bye)'), sys('nap joined')]))
      .toBe('nap reconnected 2×');
    expect(summarizePresence([sys('nap joined'), sys('nap joined')])).toBe('nap joined 2×');
    expect(summarizePresence([sys('nap left'), sys('nap quit')])).toBe('nap left 2×');
  });

  it('lists distinct people, quits counted as leaving', () => {
    expect(summarizePresence([sys('alice joined'), sys('bob joined'), sys('carol quit (x)'), sys('alice joined')]))
      .toBe('alice, bob joined · carol left');
  });

  it('caps the names it lists', () => {
    const run = ['a', 'b', 'c', 'd', 'e'].map((n) => sys(`${n} joined`));
    expect(summarizePresence(run)).toBe('a, b, c and 2 more joined');
  });
});

describe('initialJoinPartDisplay', () => {
  it('is hidden for someone who never chose', () => {
    expect(initialJoinPartDisplay(null, null)).toBe('hidden');
  });

  it('honours a stored choice', () => {
    expect(initialJoinPartDisplay('all', null)).toBe('all');
    expect(initialJoinPartDisplay('grouped', 'false')).toBe('grouped');
  });

  it('carries an explicit old "on" over as grouped, and ignores junk', () => {
    expect(initialJoinPartDisplay(null, 'true')).toBe('grouped');
    expect(initialJoinPartDisplay(null, 'false')).toBe('hidden');
    expect(initialJoinPartDisplay('bogus', null)).toBe('hidden');
  });
});
