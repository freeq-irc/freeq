/**
 * Jumbomoji: when a message is nothing but a few emoji, render them large.
 * A small, universal delight — mirror this policy on macOS/iOS so all clients
 * agree on what counts as "jumbo".
 *
 * Rule (matches the DESIGN doc): a message whose entire content is 1–3 emoji
 * graphemes (ignoring whitespace) renders big; 1 emoji biggest, tapering to 3.
 * Anything with letters/numbers/punctuation is a normal message.
 */

// Emoji presentation by default (this is what makes flags jumbo — regional
// indicators carry it, but ❤ and ☺ don't), or an explicit emoji variation
// selector (❤️, #️⃣). Matches the iOS/macOS/Android rule so all four clients
// agree; the previous \p{Extended_Pictographic} test missed flags and
// keycaps and let bare text-presentation symbols through.
const EMOJI_PRESENTATION_RE = /\p{Emoji_Presentation}/u;
const isEmojiGrapheme = (g: string): boolean =>
  EMOJI_PRESENTATION_RE.test(g) || g.includes('\uFE0F');

/** Count emoji graphemes if the text is emoji-only; else null. */
function emojiOnlyCount(text: string): number | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  // Grapheme segmentation keeps ZWJ sequences (👩‍💻) and flags as one unit.
  const seg = typeof Intl !== 'undefined' && 'Segmenter' in Intl
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;
  const graphemes = seg
    ? [...seg.segment(trimmed)].map((s) => s.segment)
    : [...trimmed]; // fallback: code points (good enough for the common case)

  let count = 0;
  for (const g of graphemes) {
    if (/^\s+$/.test(g)) continue;            // spaces between emoji are fine
    if (!isEmojiGrapheme(g)) return null;     // any non-emoji grapheme → not jumbo
    count += 1;
  }
  return count > 0 ? count : null;
}

/**
 * Font-size (in px) for a jumbo message, or null if it isn't one.
 * 1 emoji → 48, 2 → 40, 3 → 34. Capped at 3 emoji.
 */
export function jumbomojiSize(text: string): number | null {
  const count = emojiOnlyCount(text);
  if (count === null || count > 3) return null;
  return { 1: 48, 2: 40, 3: 34 }[count] ?? null;
}

/** Convenience predicate. */
export function isJumbomoji(text: string): boolean {
  return jumbomojiSize(text) !== null;
}
