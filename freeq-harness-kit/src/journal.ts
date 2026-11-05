/**
 * Task journal: what this session was *doing* on a handoff, persisted in the
 * pi session log.
 *
 * The server is the authority for what is assigned (`/api/v1/actions`), and
 * a restart re-enters that work correctly. But the how — what the model had
 * tried, decided, and was about to do — lived only in model context, which a
 * crash or restart throws away. The result was a resumed task that arrived as
 * a bare title, and an agent that started over, sometimes redoing work it had
 * already reported as done.
 *
 * pi's `appendEntry` persists extension data in the session file without
 * feeding it to the model. So: each turn taken while a task is in flight
 * leaves a short note keyed by task id; on resume, the notes are read back and
 * put in front of the model as "here is where you were". Nothing is sent to
 * the model unless it is resuming that exact task, so the journal costs no
 * context in the common case.
 *
 * Entries are pure data. The type lives here so the extension and the tests
 * agree on it.
 */

/** The custom entry type under which notes are appended. */
export const JOURNAL_ENTRY = "freeq-task-note";

export interface TaskNote {
  taskId: string;
  /** Epoch ms. */
  at: number;
  /** `start` | `turn` | `progress` | `resume` — what produced this note. */
  kind: "start" | "turn" | "progress" | "resume";
  /** Short prose: the model's own summary of the turn, or the progress note. */
  text: string;
}

/** Per-note length cap. A journal is a trail of breadcrumbs, not a transcript. */
export const NOTE_MAX_CHARS = 600;
/** How many notes are replayed on resume. Recent ones matter most. */
export const RESUME_NOTE_LIMIT = 12;

/** Trim a model turn down to a breadcrumb: first paragraph, bounded. */
export function summarizeTurn(text: string): string {
  const firstPara = text.trim().split(/\n\s*\n/)[0] ?? "";
  const oneLine = firstPara.replace(/\s+/g, " ").trim();
  return oneLine.length > NOTE_MAX_CHARS ? `${oneLine.slice(0, NOTE_MAX_CHARS - 1)}…` : oneLine;
}

/** The subset of a pi session entry this module reads. */
export interface EntryLike {
  type: string;
  customType?: string;
  data?: unknown;
}

/** Notes for one task, oldest first. */
export function notesFor(entries: Iterable<EntryLike>, taskId: string): TaskNote[] {
  const out: TaskNote[] = [];
  for (const e of entries) {
    if (e.type !== "custom" || e.customType !== JOURNAL_ENTRY) continue;
    const d = e.data as Partial<TaskNote> | undefined;
    if (!d || d.taskId !== taskId || typeof d.text !== "string") continue;
    out.push({
      taskId,
      at: typeof d.at === "number" ? d.at : 0,
      kind: (d.kind as TaskNote["kind"]) ?? "turn",
      text: d.text,
    });
  }
  out.sort((a, b) => a.at - b.at);
  return out;
}

/**
 * Render a resume preamble from the journal, or an empty string if there is
 * nothing to say. Recent notes are kept in full; if there are more than the
 * limit, the older ones are dropped with a count so the model knows the
 * trail is longer than what it sees.
 */
export function resumePreamble(notes: TaskNote[]): string {
  if (notes.length === 0) return "";
  const shown = notes.slice(-RESUME_NOTE_LIMIT);
  const dropped = notes.length - shown.length;
  const lines = shown.map((n) => {
    const when = new Date(n.at).toISOString().slice(11, 16);
    const tag = n.kind === "turn" ? "" : `[${n.kind}] `;
    return `- ${when} ${tag}${n.text}`;
  });
  return (
    `Where you were on this task before the session restarted` +
    (dropped > 0 ? ` (${dropped} earlier note${dropped === 1 ? "" : "s"} omitted)` : "") +
    `:\n${lines.join("\n")}\n\n` +
    `Continue from there. Do not redo work these notes say is done.`
  );
}
