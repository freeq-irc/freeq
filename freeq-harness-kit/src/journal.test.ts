import { describe, it, expect } from "vitest";
import {
  JOURNAL_ENTRY,
  NOTE_MAX_CHARS,
  RESUME_NOTE_LIMIT,
  notesFor,
  resumePreamble,
  summarizeTurn,
  type EntryLike,
} from "./journal.js";

function entry(taskId: string, at: number, text: string, kind = "turn"): EntryLike {
  return { type: "custom", customType: JOURNAL_ENTRY, data: { taskId, at, kind, text } };
}

describe("task journal", () => {
  it("reads back only this task's notes, oldest first", () => {
    const entries: EntryLike[] = [
      entry("T1", 300, "third"),
      entry("T2", 100, "other task"),
      entry("T1", 100, "first"),
      { type: "message", data: { taskId: "T1", text: "not a journal entry" } },
      { type: "custom", customType: "something-else", data: { taskId: "T1", text: "wrong type" } },
      entry("T1", 200, "second"),
    ];
    expect(notesFor(entries, "T1").map((n) => n.text)).toEqual(["first", "second", "third"]);
  });

  it("turns a model turn into a breadcrumb, not a transcript", () => {
    const long = "Decided to rewrite the parser.\n\nHere is a 5000-word essay " + "x".repeat(5000);
    const s = summarizeTurn(long);
    expect(s).toBe("Decided to rewrite the parser.");
    const oneHuge = "y".repeat(NOTE_MAX_CHARS * 3);
    expect(summarizeTurn(oneHuge).length).toBe(NOTE_MAX_CHARS);
  });

  it("says nothing when there is nothing to say", () => {
    expect(resumePreamble([])).toBe("");
  });

  it("puts the trail in front of the model, and tells it not to redo done work", () => {
    const notes = notesFor(
      [
        entry("T1", Date.UTC(2026, 0, 1, 9, 0), "took on: fix the parser", "start"),
        entry("T1", Date.UTC(2026, 0, 1, 9, 5), "Rewrote tokenizer; tests green."),
        entry("T1", Date.UTC(2026, 0, 1, 9, 9), "halfway through", "progress"),
      ],
      "T1",
    );
    const p = resumePreamble(notes);
    expect(p).toContain("Where you were on this task");
    expect(p).toContain("[start] took on: fix the parser");
    expect(p).toContain("Rewrote tokenizer; tests green.");
    expect(p).toContain("[progress] halfway through");
    expect(p).toContain("Do not redo work these notes say is done.");
  });

  it("keeps the recent notes and says how many older ones were dropped", () => {
    const many = Array.from({ length: RESUME_NOTE_LIMIT + 5 }, (_, i) =>
      entry("T1", 1000 + i, `note ${i}`),
    );
    const p = resumePreamble(notesFor(many, "T1"));
    expect(p).toContain("5 earlier notes omitted");
    expect(p).toContain(`note ${RESUME_NOTE_LIMIT + 4}`); // the newest
    expect(p).not.toContain("- note 0\n"); // the oldest is gone
  });
});
