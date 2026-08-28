/**
 * Session metadata advertised as freeq presence.
 *
 * HARD RULE (build spec §4.3, design §7): never advertise `cwd` or any
 * absolute filesystem path. Advertise what is useful *on the network* —
 * project, repo, branch, model — and nothing that describes local disk
 * layout. `repoRoot` is resolved internally to derive the project name and
 * is deliberately not part of `SessionMeta`.
 *
 * M0 field note: an agent answer leaked an absolute path into public channel
 * history. Presence is locked down here; the answer path gets the same
 * treatment via the redactor in M3.
 */

import { execFile } from "node:child_process";
import { basename } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);

/** Advertised session metadata. Note the absence of any path field. */
export interface SessionMeta {
  /** pi session id (ephemeral — identity lives at the installation level). */
  session?: string;
  /** Project name (repo basename, or cwd basename when not a repo). */
  project?: string;
  /** Normalized repo slug, e.g. `github.com/freeq-irc/freeq`. */
  repo?: string;
  /** Current branch. */
  branch?: string;
  /** Active model id. */
  model?: string;
}

async function git(cwd: string, args: string[]): Promise<string | undefined> {
  try {
    const { stdout } = await exec("git", args, { cwd, timeout: 2000 });
    const out = stdout.trim();
    return out || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Normalize a git remote URL to `host/owner/repo`, dropping credentials,
 * scheme, port and `.git`. Returns undefined if it can't be parsed — better
 * to advertise nothing than something malformed.
 */
export function normalizeRemote(url: string | undefined): string | undefined {
  if (!url) return undefined;
  let s = url.trim();
  if (!s) return undefined;

  // scp-style: git@host:owner/repo.git
  const scp = /^[^@/]+@([^:]+):(.+)$/.exec(s);
  if (scp) {
    s = `${scp[1]}/${scp[2]}`;
  } else {
    s = s.replace(/^[a-z+]+:\/\//i, "");
    const at = s.indexOf("@");
    const slash = s.indexOf("/");
    if (at !== -1 && (slash === -1 || at < slash)) s = s.slice(at + 1); // strip creds
    s = s.replace(/:(\d+)\//, "/"); // strip port
  }
  s = s.replace(/\.git$/i, "").replace(/\/+$/, "");
  return s || undefined;
}

export interface CollectOptions {
  cwd: string;
  sessionId?: string;
  model?: string;
}

/** Collect advertisable metadata for the current session. */
export async function collectSessionMeta(opts: CollectOptions): Promise<SessionMeta> {
  const { cwd } = opts;
  const repoRoot = await git(cwd, ["rev-parse", "--show-toplevel"]);
  const branch = await git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const repo = normalizeRemote(await git(cwd, ["remote", "get-url", "origin"]));

  // basename only — never the full path
  const project = repoRoot ? basename(repoRoot) : basename(cwd) || undefined;

  return {
    session: opts.sessionId,
    project,
    repo,
    branch: branch === "HEAD" ? undefined : branch, // detached HEAD says nothing useful
    model: opts.model,
  };
}

/**
 * Render metadata as a freeq PRESENCE status string.
 *
 * `k=v` pairs joined by spaces; values with spaces are dropped rather than
 * quoted (nothing here legitimately contains one, and the presence line is
 * semicolon-delimited upstream — no reason to risk mangling it).
 */
export function formatStatus(meta: SessionMeta): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(meta)) {
    if (!v || typeof v !== "string") continue;
    if (/[\s;]/.test(v)) continue;
    if (looksLikePath(v)) continue; // paranoia: never leak local disk layout
    parts.push(`${k}=${v}`);
  }
  return parts.join(" ");
}

/**
 * True for anything resembling an absolute local path.
 *
 * Covers POSIX (`/Users/…`), Windows drive (`C:\…`), UNC (`\\host\share`)
 * and `~` expansions. Checked independently of separator style — an early
 * version gated the Windows branch behind a `/` test and let `C:\Users\…`
 * through, which the unit test caught.
 */
export function looksLikePath(v: string): boolean {
  if (v.startsWith("/") || v.startsWith("~")) return true;
  if (/^[A-Za-z]:[\\/]/.test(v)) return true;
  if (v.startsWith("\\\\")) return true;
  return false;
}

/** Parse a status string produced by `formatStatus` back into metadata. */
export function parseStatus(status: string | undefined): SessionMeta {
  const meta: SessionMeta = {};
  if (!status) return meta;
  for (const tok of status.split(/\s+/)) {
    const eq = tok.indexOf("=");
    if (eq <= 0) continue;
    const k = tok.slice(0, eq);
    const v = tok.slice(eq + 1);
    if (!v) continue;
    if (k === "session" || k === "project" || k === "repo" || k === "branch" || k === "model") {
      meta[k] = v;
    }
  }
  return meta;
}

/** One-line human summary for `/freeq status` and `/freeq peers`. */
export function describeMeta(meta: SessionMeta): string {
  const bits: string[] = [];
  if (meta.project) bits.push(meta.project);
  if (meta.branch) bits.push(`@${meta.branch}`);
  if (meta.repo) bits.push(`(${meta.repo})`);
  if (meta.model) bits.push(`· ${meta.model}`);
  return bits.join(" ") || "no metadata";
}
