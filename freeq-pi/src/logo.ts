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

let cached: string | undefined;

/** The raw ANSI, trailing newline stripped. Empty string if the asset is missing. */
export function logoAnsi(): string {
  if (cached !== undefined) return cached;
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/logo.js → ../assets/logo.ans ; src/logo.ts → ../assets/logo.ans
    cached = readFileSync(join(here, "..", "assets", "logo.ans"), "utf8").replace(/\n+$/, "");
  } catch {
    cached = "";
  }
  return cached;
}

/** Lines, for a widget that takes an array. */
export function logoLines(): string[] {
  const s = logoAnsi();
  return s ? s.split("\n") : [];
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
