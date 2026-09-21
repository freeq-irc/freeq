import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KEY_LAYERS, VERDICT_STATES, mark, sentence } from './verdict.js';

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
