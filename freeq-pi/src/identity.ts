/**
 * Installation identity (design doc §7).
 *
 * One owner-bound `did:key` per *pi installation* — not per machine, not per
 * session. Sessions are metadata underneath it (see presence.ts). We reuse
 * bot-kit's persistence (`~/.freeq/bots/<name>/`, 0600 seed + delegation
 * cert) rather than inventing a parallel key store; the installation slug
 * names the bot.
 *
 * Deviation from build spec §3 M1 (flagged in PLAN.md): spec suggested
 * `~/.freeq/pi/identity/`. Behaviour is identical; this reuses
 * `loadOrCreateIdentity` + delegation minting untouched.
 */

import { hostname, userInfo } from "node:os";
import { createHash } from "node:crypto";

/** Prefix for bot-kit state dirs and default nicks. */
export const INSTALL_PREFIX = "pi";

/**
 * Derive a stable, non-identifying installation slug.
 *
 * Hostname and username are hashed rather than embedded: the slug ends up in
 * a public nick, and "chads-macbook" tells a channel more about you than it
 * needs to. Stable across restarts, distinct across machines/accounts.
 */
export function deriveInstallSlug(seed?: string): string {
  const material = seed ?? `${hostname()}\0${userInfo().username}`;
  return createHash("sha256").update(material).digest("hex").slice(0, 8);
}

/** bot-kit state name for an installation slug. */
export function botName(slug: string): string {
  return `${INSTALL_PREFIX}-${slug}`;
}

// ── Per-project identities ──────────────────────────────────────────────
//
// One identity per installation was the v0.1 rule, and it made every pi
// window on a machine the same agent. That is wrong for how people actually
// work: a long-running session in a music repo and another in a work repo are
// different participants doing unrelated things, and collapsing them into one
// nick made presence last-writer-wins and every mention answered twice.
//
// The unit is the *project* — the git root, or the directory when there is
// none — not the pi session id. A session id changes on every launch, so a
// per-session identity would mint a fresh did:key each morning and nobody
// could trust or address it. A project identity is stable across restarts,
// which is what makes it worth trusting. Two windows in one project still
// share it, which is correct: they are the same agent working on the same
// thing, and the lock keeps them from both speaking.
//
// Every project identity is still delegated by the same owner, so trust that
// was granted to the person carries to all of them; what differs is the nick
// and the key.

/**
 * A short, URL-and-nick-safe slug for a project name. Hashed rather than
 * used raw when it does not survive sanitising, so two projects with
 * awkward names cannot collide.
 */
export function projectSlug(project: string | undefined): string | undefined {
  if (!project) return undefined;
  const clean = project.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (clean && clean.length <= 12) return clean;
  return createHash("sha256").update(project).digest("hex").slice(0, 8);
}

/** bot-kit state name for a project identity under an installation. */
export function projectBotName(installSlug: string, project: string | undefined): string {
  const ps = projectSlug(project);
  return ps ? `${INSTALL_PREFIX}-${installSlug}-${ps}` : botName(installSlug);
}

/**
 * The nick for a project identity: `<base>-<project>`. Base is whatever the
 * installation was called (`chad-bot`), so `chad-bot-freeq` and
 * `chad-bot-music` are recognisably the same person's agents in different
 * rooms.
 */
export function projectNick(base: string, project: string | undefined): string {
  const ps = projectSlug(project);
  if (!ps) return sanitizeNick(base);
  // IRC nicks are length-limited; the project is the distinguishing part,
  // so it gets priority over the base when they do not both fit.
  const budget = 30 - 1 - ps.length;
  const head = sanitizeNick(base).slice(0, Math.max(budget, 4));
  return sanitizeNick(`${head}-${ps}`, 30);
}

/**
 * Default nick. IRC nicks are length-limited and charset-limited, so keep it
 * short and conservative: `pi-<8 hex>`.
 */
export function defaultNick(slug: string): string {
  return sanitizeNick(`${INSTALL_PREFIX}-${slug}`);
}

/** Coerce a string into something valid as an IRC nick. */
export function sanitizeNick(raw: string, max = 16): string {
  let s = raw.replace(/[^A-Za-z0-9_\-[\]{}\\^`|]/g, "-").replace(/^[^A-Za-z[\]{}\\^`|]+/, "");
  if (!s) s = INSTALL_PREFIX;
  return s.slice(0, max);
}

export function isDid(s: string | undefined): s is string {
  return !!s && /^did:[a-z0-9]+:.+/.test(s);
}
