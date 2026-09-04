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
/**
 * How much of a nick the project may occupy.
 *
 * A nick is capped at 30, and it has to carry both who you are and which of
 * your projects this is. 16 leaves 13 for the base, which is enough for
 * `chad-bot` and most names people actually use.
 */
export const SLUG_MAX = 16;

/**
 * A short, stable, readable name for a project.
 *
 * This used to hash anything over 12 characters, which meant `my-new-project`
 * became `278cc566` — stable and unique and completely unreadable, and the
 * first thing a stranger sees of their own agent. Most repository names are
 * longer than 12, so the opaque case was the common one.
 *
 * Now a name that fits is used verbatim, and one that does not is truncated
 * to a readable stem with four hex of the FULL name appended. `some-very-long
 * -project` reads as `some-very--a1b2`: you can tell which project it is, and
 * two projects sharing a prefix still differ, because the hash is taken over
 * the whole name rather than the part that survived truncation.
 */
export function projectSlug(project: string | undefined): string | undefined {
  if (!project) return undefined;
  const clean = project.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  // Nothing usable survived (a name of only punctuation, say): fall back to
  // the hash, since an unreadable name beats no name.
  if (!clean) return createHash("sha256").update(project).digest("hex").slice(0, 8);
  if (clean.length <= SLUG_MAX) return clean;
  const tag = createHash("sha256").update(project).digest("hex").slice(0, 4);
  const stem = clean.slice(0, SLUG_MAX - tag.length - 1).replace(/-+$/, "");
  return `${stem}-${tag}`;
}

/**
 * What `projectSlug` used to return, for finding an identity minted before
 * the change.
 *
 * A slug names a keypair and a registered nick, so changing the function
 * silently orphans an existing agent and mints a new one under a new DID.
 * Callers check here first and keep using the old name if that state exists.
 */
export function legacyProjectSlug(project: string | undefined): string | undefined {
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
 * The state name to actually use, preferring an identity that already exists.
 *
 * `projectSlug` changed, and a slug names a keypair and a registered nick. An
 * agent whose name moved would come back as a stranger: new DID, new nick,
 * every trust entry pointing at the old one. So if state exists under the old
 * name and not the new one, keep the old name. Nobody's agent is renamed by
 * an upgrade; only new projects get the readable form.
 */
export function resolveBotName(
  installSlug: string,
  project: string | undefined,
  exists: (name: string) => boolean,
): string {
  const current = projectBotName(installSlug, project);
  if (exists(current)) return current;
  const legacy = legacyProjectSlug(project);
  if (legacy) {
    const legacyName = `${INSTALL_PREFIX}-${installSlug}-${legacy}`;
    if (legacyName !== current && exists(legacyName)) return legacyName;
  }
  return current;
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
