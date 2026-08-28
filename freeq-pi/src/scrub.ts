/**
 * Outbound redaction.
 *
 * Everything this agent sends to freeq passes through here. freeq channel
 * history is durable and often public, so a single careless line is a
 * permanent disclosure — this is a real incident class, not a hypothetical:
 * during M0 an agent asked "which repo are you in?" answered with an absolute
 * home-directory path, and that message is still in public channel history.
 *
 * Two categories:
 *   1. secrets  — tokens, keys, passwords, connection strings
 *   2. paths    — absolute filesystem paths, which identify the user and the
 *                 machine layout even when they contain nothing secret
 *
 * This is a safety net, not a permission slip. The skill also instructs the
 * model not to send these in the first place; defence in depth.
 */

import { homedir } from "node:os";

export interface ScrubResult {
  text: string;
  /** Kinds of redaction applied, for logging/notifying the user. */
  hits: string[];
}

/** Redaction placeholder. Deliberately conspicuous. */
const R = (kind: string) => `[redacted:${kind}]`;

interface Rule {
  kind: string;
  re: RegExp;
  /** Replacement; may reference capture groups. */
  to: string | ((m: string, ...groups: string[]) => string);
}

const SECRET_RULES: Rule[] = [
  // PEM private keys — collapse the whole block.
  {
    kind: "private-key",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    to: R("private-key"),
  },
  // Well-known token shapes.
  { kind: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g, to: R("github-token") },
  { kind: "slack-token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, to: R("slack-token") },
  { kind: "aws-key-id", re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, to: R("aws-key-id") },
  { kind: "openai-key", re: /\bsk-[A-Za-z0-9_-]{20,}\b/g, to: R("api-key") },
  { kind: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, to: R("api-key") },
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, to: R("jwt") },
  // Bearer headers.
  { kind: "bearer", re: /\b(Bearer|Authorization:\s*Bearer)\s+[A-Za-z0-9._~+/-]{12,}=*/gi, to: R("bearer-token") },
  // Credentials embedded in URLs.
  {
    kind: "url-credentials",
    re: /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi,
    to: (_m, scheme) => `${scheme}${R("credentials")}@`,
  },
  // KEY=value / KEY: value for secret-ish names.
  {
    kind: "env-secret",
    re: /\b([A-Z][A-Z0-9_]{2,}(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)[A-Z0-9_]*)\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[^\s,;]+)/g,
    to: (_m, key) => `${key}=${R("secret")}`,
  },
];

/**
 * Absolute paths.
 *
 * The home directory is handled first and specifically (it names the user).
 * Other absolute paths are redacted to their last segment so the message
 * stays intelligible: "/Users/x/src/freeq/deploy.sh" → "[path]/deploy.sh".
 */
function scrubPaths(text: string, hits: Set<string>): string {
  let out = text;
  const home = homedir();

  if (home && home.length > 4) {
    const homeRe = new RegExp(escapeRe(home), "g");
    if (homeRe.test(out)) {
      hits.add("home-path");
      out = out.replace(homeRe, "~");
    }
  }

  // POSIX absolute paths with at least two segments.
  //
  // The lookbehind must exclude `:`, `/`, `.` and `\` as well as word chars,
  // otherwise this eats the `//host/path` of a URL and the tail of a
  // relative path like `./deploy/deploy.sh` — both caught by unit tests.
  out = out.replace(/(?<![\w~:./\\])\/(?:[\w.-]+\/){1,}[\w.-]+\/?/g, (m) => {
    if (isBenignPath(m)) return m;
    hits.add("abs-path");
    const seg = m.replace(/\/$/, "").split("/").filter(Boolean);
    return seg.length ? `[path]/${seg[seg.length - 1]}` : R("path");
  });

  // Windows drive paths and UNC shares.
  out = out.replace(/\b[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]*/g, (m) => {
    hits.add("abs-path");
    const seg = m.split("\\").filter(Boolean);
    return `[path]\\${seg[seg.length - 1] ?? ""}`;
  });
  out = out.replace(/\\\\[^\\\s]+\\[^\\\s]+/g, () => {
    hits.add("abs-path");
    return R("unc-path");
  });

  return out;
}

/**
 * Paths that are safe (and useful) to keep: system locations that describe
 * software rather than a person, and URL paths.
 */
function isBenignPath(p: string): boolean {
  return /^\/(usr|bin|sbin|etc|opt|var\/log|tmp|dev|proc|lib)\//.test(p);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Redact secrets and absolute paths from outbound text. */
export function scrubOutbound(text: string): ScrubResult {
  const hits = new Set<string>();
  let out = text;

  for (const rule of SECRET_RULES) {
    out = out.replace(rule.re, (...args: unknown[]) => {
      hits.add(rule.kind);
      return typeof rule.to === "function"
        ? (rule.to as (m: string, ...g: string[]) => string)(
            args[0] as string,
            ...(args.slice(1, -2) as string[]),
          )
        : rule.to;
    });
  }

  out = scrubPaths(out, hits);
  return { text: out, hits: [...hits] };
}
