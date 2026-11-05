/**
 * The task journal, in a file. pi keeps its journal in the pi session log;
 * a Claude Code channel has no such log it can write to, so the notes go to
 * one JSON-lines file per identity (identities are per project), in the
 * shape pi's entries have, and are read back with the kit's `notesFor`.
 * Unlike pi's, it outlives the session, which is what resume after a
 * restart needs.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

import { JOURNAL_ENTRY, notesFor, type EntryLike, type TaskNote } from "@freeq/harness-kit/journal";

export class FileJournal {
  constructor(private readonly path: () => string) {}

  append(note: TaskNote): void {
    const file = this.path();
    mkdirSync(dirname(file), { recursive: true });
    const entry: EntryLike = { type: "custom", customType: JOURNAL_ENTRY, data: note };
    appendFileSync(file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  }

  read(taskId: string): TaskNote[] {
    const file = this.path();
    if (!existsSync(file)) return [];
    const entries: EntryLike[] = [];
    for (const line of readFileSync(file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line) as EntryLike);
      } catch {
        /* a torn last line from a crash; the rest still counts */
      }
    }
    return notesFor(entries, taskId);
  }
}
