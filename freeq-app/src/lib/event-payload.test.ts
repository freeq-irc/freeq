/**
 * The payload rule every event card renders through.
 *
 * A payload tag is JSON by convention only, so the rule has to answer for
 * what actually arrives: an object, an array, a scalar, and text that never
 * was JSON. The same rows the other three clients build.
 */
import { describe, it, expect } from 'vitest';
import { payloadRows } from './event-payload';

/** The wire form: percent-encoded in the tag. */
const enc = (s: string) => encodeURIComponent(s);

describe('an object payload', () => {
  it('gives one row per top-level key, in the order written', () => {
    expect(payloadRows(enc('{"to":"bob","why":"capacity"}'))).toEqual([
      { key: 'to', value: 'bob' },
      { key: 'why', value: 'capacity' },
    ]);
  });

  it('shows a string value as itself, not as quoted JSON', () => {
    expect(payloadRows(enc('{"note":"half done"}'))).toEqual([
      { key: 'note', value: 'half done' },
    ]);
  });

  it('shows a non-string value as compact JSON', () => {
    expect(payloadRows(enc('{"n":3,"ok":true,"tags":["a","b"],"deep":{"x":1},"nil":null}'))).toEqual([
      { key: 'n', value: '3' },
      { key: 'ok', value: 'true' },
      { key: 'tags', value: '["a","b"]' },
      { key: 'deep', value: '{"x":1}' },
      { key: 'nil', value: 'null' },
    ]);
  });

  it('gives no rows for an empty object', () => {
    expect(payloadRows(enc('{}'))).toEqual([]);
  });
});

describe('a value as the document wrote it', () => {
  it('keeps a number as it was written, never re-serialized', () => {
    expect(payloadRows(enc('{"load":0.3}'))).toEqual([{ key: 'load', value: '0.3' }]);
    expect(payloadRows(enc('{"n":1.0}'))).toEqual([{ key: 'n', value: '1.0' }]);
    expect(payloadRows(enc('{"big":1e2}'))).toEqual([{ key: 'big', value: '1e2' }]);
  });

  it('keeps a nested object as written, in its own key order', () => {
    expect(payloadRows(enc('{"deep":{"b":1,"a":2}}'))).toEqual([
      { key: 'deep', value: '{"b":1,"a":2}' },
    ]);
  });

  it('drops the whitespace between tokens but not inside a string', () => {
    expect(payloadRows(enc('{ "deep" : { "b" : "x y" } }'))).toEqual([
      { key: 'deep', value: '{"b":"x y"}' },
    ]);
  });

  it('still shows a string value unquoted', () => {
    expect(payloadRows(enc('{"note":"half done"}'))).toEqual([
      { key: 'note', value: 'half done' },
    ]);
  });

  it('keeps an array or a scalar payload as written', () => {
    expect(payloadRows(enc('[1.0, 2]'))).toEqual([{ key: 'payload', value: '[1.0,2]' }]);
    expect(payloadRows(enc('1e2'))).toEqual([{ key: 'payload', value: '1e2' }]);
  });
});

describe('an array or a scalar payload', () => {
  it('an array is one row keyed payload, compact', () => {
    expect(payloadRows(enc('[1,"two",{"three":3}]'))).toEqual([
      { key: 'payload', value: '[1,"two",{"three":3}]' },
    ]);
  });

  it('a number is one row keyed payload', () => {
    expect(payloadRows(enc('42'))).toEqual([{ key: 'payload', value: '42' }]);
  });

  it('a JSON string is one row keyed payload, unquoted', () => {
    expect(payloadRows(enc('"just words"'))).toEqual([
      { key: 'payload', value: 'just words' },
    ]);
  });

  it('a null payload is one row keyed payload', () => {
    expect(payloadRows(enc('null'))).toEqual([{ key: 'payload', value: 'null' }]);
  });
});

describe('a payload that is not JSON', () => {
  it('is one row keyed payload carrying the decoded string', () => {
    expect(payloadRows(enc('half the build is red'))).toEqual([
      { key: 'payload', value: 'half the build is red' },
    ]);
  });

  it('keeps the tag value when the percent-escaping is malformed', () => {
    expect(payloadRows('100%-sure')).toEqual([
      { key: 'payload', value: '100%-sure' },
    ]);
  });
});

describe('no payload at all', () => {
  it('gives no rows for an absent tag', () => {
    expect(payloadRows(undefined)).toEqual([]);
  });

  it('gives no rows for an empty tag', () => {
    expect(payloadRows('')).toEqual([]);
  });
});
