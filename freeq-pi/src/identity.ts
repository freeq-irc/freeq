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

/**
 * Default nick. IRC nicks are length-limited and charset-limited, so keep it
 * short and conservative: `pi-<8 hex>`.
 */
export function defaultNick(slug: string): string {
  return sanitizeNick(`${INSTALL_PREFIX}-${slug}`);
}

/** Coerce a string into something valid as an IRC nick. */
export function sanitizeNick(raw: string): string {
  let s = raw.replace(/[^A-Za-z0-9_\-[\]{}\\^`|]/g, "-").replace(/^[^A-Za-z[\]{}\\^`|]+/, "");
  if (!s) s = INSTALL_PREFIX;
  return s.slice(0, 16);
}

export function isDid(s: string | undefined): s is string {
  return !!s && /^did:[a-z0-9]+:.+/.test(s);
}
