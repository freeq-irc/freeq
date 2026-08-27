import type { Message } from '../store';

/** The msgid of the row `node` sits in, or null if it is in none. */
function rowIdAt(node: Node | null): string | null {
  const el = node instanceof Element ? node : (node?.parentElement ?? null);
  const row = el?.closest<HTMLElement>('[id^="msg-"]');
  return row ? row.id.slice(4) : null;
}

/**
 * The held rows a selection runs across: the row it starts in, the row it
 * ends in, and every row between them.
 *
 * Read from the held rows rather than from the mounted ones. A list that
 * mounts a window of what it holds has no element for most of a long
 * selection, so collecting the rows the selection touches in the document
 * collects the part of it that happened to be on screen and silently drops
 * the rest.
 *
 * `null` where there is nothing to rewrite: a selection inside a single row,
 * or one whose ends are not rows.
 */
export function rowsInSelection(messages: Message[], sel: Selection): Message[] | null {
  const first = rowIdAt(sel.anchorNode);
  const last = rowIdAt(sel.focusNode);
  if (!first || !last || first === last) return null;
  const a = messages.findIndex((m) => m.id === first);
  const b = messages.findIndex((m) => m.id === last);
  if (a < 0 || b < 0) return null;
  return messages.slice(Math.min(a, b), Math.max(a, b) + 1);
}

/**
 * Clean, paste-friendly plain-text transcript of a run of messages — the web
 * analogue of the macOS `MessageTranscript`. The point is the opposite of what
 * a raw DOM copy gives you: no timestamps, no "(edited)", no reaction tallies,
 * no avatars-as-blank-lines. Just `Name: message`, one per entry.
 *
 * - system lines (empty `from` / isSystem) are skipped (presence noise)
 * - deleted tombstones are skipped
 * - actions render as `* Name text`
 * - `displayName` resolves a wire nick to the shown name (defaults to nick)
 */
export function buildTranscript(
  messages: Message[],
  displayName: (nick: string) => string = (n) => n,
): string {
  const lines: string[] = [];
  for (const m of messages) {
    if (m.deleted) continue;
    if (!m.from || m.isSystem) continue;
    const name = displayName(m.from) || m.from;
    if (m.isAction) {
      lines.push(`* ${name} ${m.text}`);
    } else {
      lines.push(`${name}: ${m.text}`);
    }
  }
  return lines.join('\n');
}
