import { describe, it, expect } from 'vitest';
import { jumbomojiSize, isJumbomoji } from './jumbomoji';

describe('jumbomoji', () => {
  it('sizes 1–3 emoji, largest first', () => {
    expect(jumbomojiSize('🎉')).toBe(48);
    expect(jumbomojiSize('🎉🚀')).toBe(40);
    expect(jumbomojiSize('🎉🚀🔥')).toBe(34);
  });

  it('ignores whitespace between emoji', () => {
    expect(jumbomojiSize('🎉 🚀')).toBe(40);
    expect(jumbomojiSize('  🔥  ')).toBe(48);
  });

  it('keeps ZWJ sequences as one grapheme', () => {
    expect(isJumbomoji('👩‍💻')).toBe(true);        // 1 grapheme
    expect(isJumbomoji('👍🏽')).toBe(true);          // emoji + skin tone
    expect(jumbomojiSize('👩‍💻👨‍👩‍👧')).toBe(40);   // 2 graphemes
  });

  it('rejects >3 emoji', () => {
    expect(jumbomojiSize('🎉🚀🔥💯')).toBeNull();
    expect(isJumbomoji('😀😀😀😀😀')).toBe(false);
  });

  it('rejects any text with letters/numbers/punctuation', () => {
    expect(jumbomojiSize('nice 🎉')).toBeNull();
    expect(jumbomojiSize('🎉!')).toBeNull();
    expect(jumbomojiSize('lol')).toBeNull();
    expect(jumbomojiSize('123')).toBeNull();
  });

  it('rejects empty / whitespace-only', () => {
    expect(jumbomojiSize('')).toBeNull();
    expect(jumbomojiSize('   ')).toBeNull();
  });

  // Cross-client parity vectors — these shapes diverged between web and
  // the native clients until the rule was unified; the same cases are
  // pinned in the iOS, macOS, and Android suites.

  it('flags are one emoji', () => {
    expect(jumbomojiSize('🇺🇸')).toBe(48);
    expect(jumbomojiSize('🇺🇸🇯🇵')).toBe(40);
  });

  it('tag-sequence flags are one emoji', () => {
    expect(jumbomojiSize('🏴󠁧󠁢󠁥󠁮󠁧󠁿')).toBe(48);
  });

  it('keycaps are one emoji', () => {
    expect(jumbomojiSize('#️⃣')).toBe(48);
    expect(jumbomojiSize('1️⃣2️⃣')).toBe(40);
  });

  it('variation-selector sequences are emoji; bare symbols are not', () => {
    expect(jumbomojiSize('❤️')).toBe(48);
    expect(jumbomojiSize('❤')).toBeNull();
    expect(jumbomojiSize('#')).toBeNull();
  });

  it('zwj family with skin tones is one emoji', () => {
    expect(jumbomojiSize('👩🏽‍❤️‍💋‍👨🏻')).toBe(48);
  });
});
