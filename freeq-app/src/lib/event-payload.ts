/**
 * The rows an event card shows for its `+freeq.at/payload` tag.
 *
 * The tag is JSON by convention and nothing enforces it, so the rule answers
 * for everything that can arrive rather than for the happy case: an object
 * spreads into its top-level keys, anything else that parses becomes one
 * `payload` row, and text that never was JSON becomes that same row carrying
 * what was sent. A tag that arrived is never dropped.
 *
 * A value is shown as the document wrote it, never re-serialized: a string
 * decoded, everything else sliced out of the source text with the whitespace
 * between its tokens dropped. `JSON.stringify` of a parsed value would not do
 * — it writes `1.0` back as `1` and `1e2` as `100`.
 *
 * The same rule the Android and Apple clients apply, so one payload reads the
 * same on all four.
 */
export interface PayloadRow {
  key: string;
  value: string;
}

/** One top-level key with the source text of its value. */
interface Entry {
  key: string;
  raw: string;
}

const WHITESPACE = ' \t\n\r';

/** The index of the quote that closes the string opened at `start`, or -1. */
function endOfString(text: string, start: number): number {
  let i = start + 1;
  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2;
      continue;
    }
    if (text[i] === '"') return i;
    i++;
  }
  return -1;
}

/** The index just past the value that starts at `start`, or -1. */
function endOfValue(text: string, start: number): number {
  if (start >= text.length) return -1;
  const c = text[start];
  if (c === '"') {
    const end = endOfString(text, start);
    return end < 0 ? -1 : end + 1;
  }
  if (c === '{' || c === '[') {
    let depth = 0;
    let i = start;
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"') {
        const end = endOfString(text, i);
        if (end < 0) return -1;
        i = end + 1;
        continue;
      }
      if (ch === '{' || ch === '[') depth++;
      else if (ch === '}' || ch === ']') {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return -1;
  }
  let i = start;
  while (
    i < text.length &&
    !WHITESPACE.includes(text[i]) &&
    text[i] !== ',' &&
    text[i] !== '}' &&
    text[i] !== ']'
  ) {
    i++;
  }
  return i === start ? -1 : i;
}

/** The same text with the whitespace between its tokens dropped. */
function compact(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    if (text[i] === '"') {
      const end = endOfString(text, i);
      if (end < 0) return out + text.slice(i);
      out += text.slice(i, end + 1);
      i = end + 1;
      continue;
    }
    if (!WHITESPACE.includes(text[i])) out += text[i];
    i++;
  }
  return out;
}

/**
 * The top-level entries of a JSON object, each with the source text of its
 * value, in the order the document wrote them.
 *
 * Null when the text is not one complete JSON object, which leaves the caller
 * its own fallback.
 */
function scanObject(text: string): Entry[] | null {
  let i = 0;
  const skip = () => {
    while (i < text.length && WHITESPACE.includes(text[i])) i++;
  };
  const closes = (entries: Entry[]): Entry[] | null => {
    i++;
    skip();
    return i === text.length ? entries : null;
  };

  skip();
  if (text[i] !== '{') return null;
  i++;
  const entries: Entry[] = [];
  skip();
  if (text[i] === '}') return closes(entries);
  for (;;) {
    skip();
    if (text[i] !== '"') return null;
    const keyEnd = endOfString(text, i);
    if (keyEnd < 0) return null;
    let key: unknown;
    try {
      key = JSON.parse(text.slice(i, keyEnd + 1));
    } catch {
      return null;
    }
    if (typeof key !== 'string') return null;
    i = keyEnd + 1;
    skip();
    if (text[i] !== ':') return null;
    i++;
    skip();
    const valueEnd = endOfValue(text, i);
    if (valueEnd < 0) return null;
    entries.push({ key, raw: text.slice(i, valueEnd) });
    i = valueEnd;
    skip();
    if (text[i] === ',') {
      i++;
      continue;
    }
    if (text[i] === '}') return closes(entries);
    return null;
  }
}

/** A value as a row shows it: a string decoded, everything else as written. */
function showSource(raw: string): string {
  if (raw.startsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === 'string') return parsed;
    } catch {
      // Not a string after all: fall through and show what was written.
    }
  }
  return compact(raw);
}

/** A parsed value, for the fallback where the source text could not be read. */
function showParsed(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

export function payloadRows(rawTagValue: string | undefined): PayloadRow[] {
  if (!rawTagValue) return [];

  let decoded: string;
  try {
    decoded = decodeURIComponent(rawTagValue);
  } catch {
    // Malformed escaping: the bytes that arrived beat nothing at all.
    decoded = rawTagValue;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    return [{ key: 'payload', value: decoded }];
  }
  const trimmed = decoded.trim();

  if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const scanned = scanObject(trimmed);
    if (scanned) {
      // A key written twice is one row: the rows are keyed by their key.
      const seen = new Set<string>();
      return scanned
        .filter((entry) => !seen.has(entry.key) && (seen.add(entry.key), true))
        .map((entry) => ({ key: entry.key, value: showSource(entry.raw) }));
    }
    return Object.entries(parsed as Record<string, unknown>).map(([key, value]) => ({
      key,
      value: showParsed(value),
    }));
  }
  return [{ key: 'payload', value: typeof parsed === 'string' ? parsed : compact(trimmed) }];
}
