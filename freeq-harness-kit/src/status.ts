/**
 * Richer working status — what a watcher actually wanted to know.
 *
 * Presence used to carry a tool NAME ("executing: bash"), which says nothing:
 * bash could be the test suite or `rm -rf`. A step status is a short human
 * phrase ("answering chad in #freeq-dev", "looking at why reconnect drops
 * channels"), the current tool as a suffix, and elapsed time on the phrase —
 * the three things that let a watcher tell "thinking" from "stuck" without
 * opening the terminal.
 *
 * The wire budget is real: presence `doing` is capped at 60 chars by
 * formatStatus (src/presence.ts), and peers on small clients truncate too.
 * Everything here renders inside that budget, phrase first.
 *
 * Pure module: no I/O, no pi API. The extension owns when steps begin and
 * end; this owns what the words look like.
 */

import { formatAge } from "./ui.js";

/** The on-the-wire cap for presence `doing` (formatStatus slices at 60). */
export const STATUS_BUDGET = 60;

/** How long a phrase may be before the renderer starts dropping tail pieces. */
export const PHRASE_MAX = 36;

export interface StepStatus {
  /** Human phrase for the current step. Never a raw tool name. */
  phrase: string;
  /** Epoch ms the phrase began — elapsed is measured on the phrase, not the run. */
  since: number;
  /** Current tool detail ("bash: npm test"), refreshed per tool call. */
  tool?: string;
}

/**
 * Collapse arbitrary text to a short, single-line human phrase. Truncates at
 * a word boundary where one is available, so the ellipsis doesn't saw a word
 * in half.
 */
export function gistOf(text: string, max = PHRASE_MAX): string {
  const flat = text.replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  const cut = flat.slice(0, Math.max(1, max - 1));
  const sp = cut.lastIndexOf(" ");
  const base = sp > max * 0.5 ? cut.slice(0, sp) : cut;
  return `${base}…`;
}

/**
 * A tool call as a short human detail. The tool name alone is the failure
 * mode this module exists to fix, so bash shows its command and file tools
 * show the basename: "bash: npm test", "edit: ui.ts".
 */
export function toolDetail(name: string, input: Record<string, unknown> | undefined, max = 18): string {
  const raw =
    typeof input?.command === "string"
      ? `bash: ${input.command.split("\n")[0]!.trim()}`
      : typeof input?.path === "string"
        ? `${name}: ${String(input.path).split(/[\\/]/).pop()}`
        : name;
  return raw.length <= max ? raw : `${raw.slice(0, max - 1)}…`;
}

/**
 * Render the presence label within budget: `phrase · tool · elapsed`.
 *
 * When the budget is tight the tail pieces are dropped in order of how much
 * they matter: the tool detail first, then the phrase is shortened — the
 * elapsed time never goes, because "12m" is the difference between watching
 * a thinking agent and watching a stuck one.
 */
export function renderStatus(s: StepStatus, now: number, budget = STATUS_BUDGET): string {
  const elapsed = formatAge(Math.max(0, now - s.since));
  const tool = s.tool ? ` · ${s.tool}` : "";
  const full = `${s.phrase}${tool} · ${elapsed}`;
  if (full.length <= budget) return full;
  const shortTail = ` · ${elapsed}`;
  const noTool = `${s.phrase}${shortTail}`;
  if (noTool.length <= budget) return noTool;
  return `${gistOf(s.phrase, Math.max(8, budget - shortTail.length))}${shortTail}`;
}
