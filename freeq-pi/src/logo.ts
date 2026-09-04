/**
 * The freeq mark, as ANSI.
 *
 * A 60×27 half-block truecolor render. Shown once, on the first successful
 * connect of a session, and on `/freeq status` — the moments you actually
 * look. Never on reconnect: a mark that repaints every time the socket blips
 * stops being a mark and starts being noise.
 *
 * It is truecolor (`38;2;r;g;b`). On a terminal that cannot show that it
 * degrades to blotches, which is worse than nothing, so the caller checks
 * `supportsTruecolor()` first and falls back to a one-line wordmark.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const cache = new Map<string, string>();

function readAsset(name: string): string {
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  let out = "";
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/logo.js → ../assets/… ; src/logo.ts → ../assets/…
    out = readFileSync(join(here, "..", "assets", name), "utf8").replace(/\n+$/, "");
  } catch {
    out = "";
  }
  cache.set(name, out);
  return out;
}

/** The raw ANSI, trailing newline stripped. Empty string if the asset is missing. */
export function logoAnsi(): string {
  return readAsset("logo.ans");
}

/** Half-scale (30×14), for terminals without room for the full mark. */
export function logoCompactAnsi(): string {
  return readAsset("logo-compact.ans");
}

/** Lines of the full mark. */
export function logoLines(): string[] {
  const s = logoAnsi();
  return s ? s.split("\n") : [];
}

/** Lines of the half-scale mark. */
export function logoCompactLines(): string[] {
  const s = logoCompactAnsi();
  return s ? s.split("\n") : [];
}

/**
 * The biggest mark this terminal has room for, or none.
 *
 * Height is the constraint, not width: pi caps a string-array widget at 10
 * lines (the caller uses a component factory to avoid that), and a mark taller
 * than the window is worse than no mark. Leave room for the editor and a few
 * lines of transcript.
 */
export function markForTerminal(rows = process.stdout.rows ?? 24): string[] {
  const full = logoLines();
  const compact = logoCompactLines();
  if (full.length && rows >= full.length + 10) return full;
  if (compact.length && rows >= compact.length + 8) return compact;
  return [];
}

/**
 * Does this terminal render 24-bit colour? The usual signals, in order of
 * how much to trust them. `NO_COLOR` wins outright.
 */
export function supportsTruecolor(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.NO_COLOR) return false;
  const ct = (env.COLORTERM ?? "").toLowerCase();
  if (ct === "truecolor" || ct === "24bit") return true;
  const tp = (env.TERM_PROGRAM ?? "").toLowerCase();
  if (["iterm.app", "ghostty", "wezterm", "vscode", "hyper", "alacritty", "kitty"].some((t) => tp.includes(t))) {
    return true;
  }
  const term = (env.TERM ?? "").toLowerCase();
  return term.includes("truecolor") || term.includes("24bit") || term.includes("kitty") || term.includes("ghostty");
}

/** One line for terminals that cannot show the mark. */
export const WORDMARK = "⬡ freeq";
