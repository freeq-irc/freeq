/**
 * Progress updates for the room that asked.
 *
 * A watcher in the terminal sees pi narrate as it works: a phrase, the tool
 * it is in, how long it has been there. A watcher in freeq saw one line, at
 * the end, however long the turn ran — because the only channel output was
 * the per-turn provenance mirror, and a turn with forty tool calls is still
 * one turn. Someone who asked a question over freeq and got ten minutes of
 * nothing cannot tell a working agent from a dead one, which is the exact
 * distinction presence exists to carry and chat did not.
 *
 * So: while a turn that came from freeq is running, post a short line into
 * the channel that asked, on an interval.
 *
 * The hard part is not the timer, it is not being noise. Two rules, both
 * here and both tested:
 *
 * 1. **Say something new, or say nothing.** If the phrase and the tool are
 *    unchanged, the only thing that moved is the clock, and a clock is not
 *    news.
 * 2. **Except when silence would be the story.** Past the keepalive window a
 *    repeat goes out anyway, because "still on the same thing after twelve
 *    minutes" is precisely what a watcher wants and is also what a stuck
 *    agent looks like. That is the one case where repeating yourself is the
 *    informative move.
 *
 * Pure module: no timers, no I/O, no pi API. The extension owns when to ask;
 * this owns whether there is anything worth saying and what it says.
 */

import { renderStatus, type StepStatus } from "./status.js";

/** How often the extension asks this module whether to speak. */
export const DEFAULT_UPDATE_SECS = 60;

/**
 * How many intervals of nothing-new before a repeat goes out anyway.
 *
 * Three: at the default interval that is a line every three minutes for an
 * agent grinding on one thing, which reads as reassurance rather than
 * chatter.
 */
export const KEEPALIVE_INTERVALS = 3;

export interface ProgressState {
  /** The line last posted, so an unchanged step can stay quiet. */
  lastKey?: string;
  /** When that line went out. */
  lastAt?: number;
}

/**
 * The identity of a step for "is this news?" purposes: the phrase and the
 * tool, deliberately NOT the elapsed time.
 */
function keyOf(step: StepStatus): string {
  return `${step.phrase}\u0000${step.tool ?? ""}`;
}

/**
 * The line a room sees. Wider than the presence budget — chat is not a
 * 60-character status field — but still one line, and still phrase-first.
 */
export function progressLine(step: StepStatus, now: number): string {
  return `⋯ ${renderStatus(step, now, 120)}`;
}

/**
 * Decide whether to post, and what.
 *
 * Returns the text to send and the state to carry forward, or `undefined`
 * when the right move is silence. The caller does not need to know the
 * rules, only to pass the state back in.
 */
export function nextUpdate(
  state: ProgressState,
  step: StepStatus | undefined,
  now: number,
  opts: { intervalMs: number },
): { text: string; state: ProgressState } | undefined {
  // No step means the turn is not running, or is running without anything a
  // person could be told. Either way there is nothing honest to say.
  if (!step) return undefined;

  const key = keyOf(step);
  const keepaliveMs = opts.intervalMs * KEEPALIVE_INTERVALS;
  const unchanged = state.lastKey === key;
  const quietFor = state.lastAt === undefined ? Infinity : now - state.lastAt;

  if (unchanged && quietFor < keepaliveMs) return undefined;

  return { text: progressLine(step, now), state: { lastKey: key, lastAt: now } };
}
