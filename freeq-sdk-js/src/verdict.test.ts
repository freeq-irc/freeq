import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { KEY_LAYERS, RULING_VERBS, VERDICT_STATES, mark, sentence } from './verdict.js';

const specPath = join(__dirname, '../../spec/verdict-model.json');
const spec = JSON.parse(readFileSync(specPath, 'utf8'));

describe('the verdict model', () => {
  it('the copy this package imports is byte-identical to the spec file', () => {
    const copy = readFileSync(join(__dirname, 'verdict-model.json'), 'utf8');
    expect(copy, 'refresh with: cp spec/verdict-model.json freeq-sdk-js/src/verdict-model.json').toBe(
      readFileSync(specPath, 'utf8'),
    );
  });

  it('every state reads its sentence from the file', () => {
    expect(Object.keys(spec.states).sort()).toEqual([...VERDICT_STATES].sort());
    for (const state of VERDICT_STATES) {
      expect(sentence(state), state).toBe(spec.states[state].sentence);
    }
    for (const layer of KEY_LAYERS) {
      expect(sentence('device', layer)).toBe(spec.layers[layer]);
    }
    expect(spec.states.device.layers).toEqual(['vouched', 'published']);
    expect(mark()).toBe(spec.mark);
  });

  it('a layer counts only for a device signature', () => {
    expect(sentence('server', 'published')).toBe(sentence('server'));
  });

  it('the words are the ruled ones', () => {
    expect(mark()).toBe('signed');
    expect(sentence('device', 'vouched')).toBe(
      "Signed on the sender’s device. Key vouched for by their server.",
    );
    expect(sentence('device', 'published')).toBe(
      "Signed on the sender’s device. Key published in their identity record.",
    );
    expect(sentence('retired')).toBe('Signed after this key was retired.');
    expect(sentence('pending')).toBe('This signature hasn’t been checked yet.');
  });
});

describe('the ruling verbs', () => {
  const rulesPath = join(__dirname, '../../spec/act-transitions.json');

  it('the copy this package imports is byte-identical to the spec file', () => {
    const copy = readFileSync(join(__dirname, 'act-transitions.json'), 'utf8');
    expect(copy, 'refresh with: cp spec/act-transitions.json freeq-sdk-js/src/act-transitions.json').toBe(
      readFileSync(rulesPath, 'utf8'),
    );
  });

  it('today they are the receipt, the expiry and the review timeout', () => {
    expect([...RULING_VERBS].sort()).toEqual(['auto-accept', 'confirm', 'expire']);
  });

  it('a system transition added to the rules is a ruling', async () => {
    const rules = JSON.parse(readFileSync(rulesPath, 'utf8'));
    rules.kinds.handoff.transitions.push({ verb: 'lapse', from: 'assigned', to: 'expired', who: 'system' });
    rules.kinds.handoff.transitions.push({ verb: 'nudge', from: 'assigned', to: 'assigned', who: 'offerer' });
    vi.resetModules();
    vi.doMock('./act-transitions.json', () => ({ default: rules }));
    try {
      const fresh = await import('./verdict.js');
      expect([...fresh.RULING_VERBS].sort()).toEqual(['auto-accept', 'confirm', 'expire', 'lapse']);
    } finally {
      vi.doUnmock('./act-transitions.json');
      vi.resetModules();
    }
  });
});
