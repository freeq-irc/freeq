/**
 * `/freeq doctor`: is this installation set up, and is it working?
 *
 * The checks bot-kit's daemon doctor runs (identity, delegation, the
 * server's actor record, `freeq-bot-kit-js/src/daemon-cli.ts`), plus what a
 * harness session adds: owner, config, server health, connection and joined
 * channels. Each is one line, ok / warn / fail; the harness appends its own
 * (`Harness.doctorLines`). A check reads and reports; it never connects,
 * mints or writes anything.
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { loadDelegation, loadOrCreateIdentity } from "@freeq/bot-kit";

import { normalizeConfig, userConfigPath, channelsForProject, type FreeqConfig } from "./config.js";
import { deriveInstallSlug, isDid, resolveBotName } from "./identity.js";
import type { HarnessNames } from "./names.js";

export type DoctorStatus = "ok" | "warn" | "fail";

/** One line of the doctor's answer. */
export interface DoctorLine {
  name: string;
  status: DoctorStatus;
  detail: string;
}

const MARK: Record<DoctorStatus, string> = { ok: "✓", warn: "⚠", fail: "✗" };

/** The answer as the person reads it, and the notice level it deserves. */
export function formatDoctor(lines: DoctorLine[]): { text: string; level: "info" | "warning" | "error" } {
  const fails = lines.filter((l) => l.status === "fail").length;
  const warns = lines.filter((l) => l.status === "warn").length;
  const summary =
    fails > 0
      ? `${fails} problem${fails === 1 ? "" : "s"}${warns ? `, ${warns} warning${warns === 1 ? "" : "s"}` : ""}.`
      : warns > 0
        ? `No problems, ${warns} warning${warns === 1 ? "" : "s"}.`
        : "All checks passed.";
  return {
    text: ["freeq doctor", ...lines.map((l) => `  ${MARK[l.status]} ${l.name}: ${l.detail}`), "", summary].join("\n"),
    level: fails > 0 ? "error" : warns > 0 ? "warning" : "info",
  };
}

/** What the doctor needs to know about the session it checks. */
export interface DoctorInput {
  agentDir: string;
  /** Where bot-kit keeps identities (`~/.freeq/bots`). */
  botsRoot: string;
  /** This session's project, which names its identity. */
  project: string | undefined;
  names: HarnessNames;
  /** The live connection, if there is one. */
  conn?: {
    state: string;
    did?: string;
    lastError?: string;
    describe(): string;
    joinedChannels(): string[];
    refusedChannels(): Array<{ channel: string; reason: string }>;
  };
  passive: boolean;
  dormant: boolean;
  /** `https://host` for the server in the config. */
  httpOrigin(server: string): string;
}

/** Read the config file as it is on disk, without the runtime's cache. */
async function readConfig(agentDir: string): Promise<{ line: DoctorLine; config: FreeqConfig }> {
  const path = userConfigPath(agentDir);
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        line: { name: "config", status: "warn", detail: `none at ${path} (defaults in use)` },
        config: normalizeConfig(undefined),
      };
    }
    return {
      line: { name: "config", status: "fail", detail: `cannot read ${path}: ${(err as Error).message}` },
      config: normalizeConfig(undefined),
    };
  }
  try {
    return { line: { name: "config", status: "ok", detail: path }, config: normalizeConfig(JSON.parse(raw)) };
  } catch (err) {
    return {
      line: { name: "config", status: "fail", detail: `${path} is not valid JSON: ${(err as Error).message}` },
      config: normalizeConfig(undefined),
    };
  }
}

/** GET a JSON document with a short timeout. */
async function getJson(url: string): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; reason: string }> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    if (!resp.ok) return { ok: false, reason: `${resp.status} ${resp.statusText}`.trim() };
    return { ok: true, body: ((await resp.json()) ?? {}) as Record<string, unknown> };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** The common checks, in order. */
export async function runDoctor(input: DoctorInput): Promise<DoctorLine[]> {
  const { names, conn } = input;
  const lines: DoctorLine[] = [];

  const { line: configLine, config: cfg } = await readConfig(input.agentDir);

  // The identity this session would connect as. It is made on the first
  // connect in a project, so its absence is news, not a fault.
  const slug = cfg.install ?? deriveInstallSlug();
  const botName = resolveBotName(slug, input.project, (n) => existsSync(join(input.botsRoot, n)), names.name);
  const stateDir = join(input.botsRoot, botName);
  const keyPath = join(stateDir, "agent.key");
  let did: string | undefined;
  if (existsSync(keyPath)) {
    did = (await loadOrCreateIdentity({ seedPath: keyPath }).catch(() => null))?.did;
  }
  if (!did) {
    lines.push({
      name: "identity",
      status: "warn",
      detail: `none yet at ${keyPath} — made on the first connect in this project`,
    });
  } else if (conn?.did && conn.did !== did) {
    lines.push({ name: "identity", status: "fail", detail: `connected as ${conn.did}, but ${keyPath} holds ${did}` });
  } else {
    lines.push({ name: "identity", status: "ok", detail: `${did} (${botName})` });
  }

  if (did) {
    const certPath = join(stateDir, "delegation.json");
    const cert = await loadDelegation({ certPath }).catch((e: Error) => ({ error: e.message }));
    if (cert && "error" in cert) {
      lines.push({ name: "delegation", status: "fail", detail: `${certPath} is malformed: ${cert.error}` });
    } else if (!cert) {
      lines.push({ name: "delegation", status: "warn", detail: `none at ${certPath} — made on the next connect` });
    } else if (cert.bot_did !== did) {
      lines.push({ name: "delegation", status: "fail", detail: `names ${cert.bot_did}, not this identity` });
    } else if (isDid(cfg.ownerDid) && cert.creator_did !== cfg.ownerDid) {
      lines.push({
        name: "delegation",
        status: "fail",
        detail: `names ${cert.creator_did} as owner, but the config says ${cfg.ownerDid}`,
      });
    } else {
      lines.push({ name: "delegation", status: "ok", detail: `${cert.signature ? "signed" : "unsigned"}, owner ${cert.creator_did}` });
    }
  }

  // The ownership verdict is the server's: its record of this actor says
  // whether it proved the certificate against the owner's agent record.
  const origin = input.httpOrigin(cfg.server);
  if (!did) {
    lines.push({ name: "ownership", status: "warn", detail: "no identity to ask the server about" });
  } else {
    const r = await getJson(`${origin}/api/v1/actors/${encodeURIComponent(did)}`);
    if (!r.ok) {
      lines.push({ name: "ownership", status: "warn", detail: `could not ask the server: ${r.reason}` });
    } else {
      const prov = r.body.provenance as { _verified?: boolean; _verification_reason?: string } | undefined;
      lines.push(
        prov?._verified === true
          ? { name: "ownership", status: "ok", detail: "verified by the server" }
          : {
              name: "ownership",
              status: "warn",
              detail:
                `not verified${prov?._verification_reason ? `: ${prov._verification_reason}` : prov ? "" : " (the server has no provenance for it)"}` +
                ` — ${names.hint("authorize")}`,
            },
      );
    }
  }

  lines.push(
    isDid(cfg.ownerDid)
      ? { name: "owner", status: "ok", detail: cfg.ownerDid }
      : { name: "owner", status: "fail", detail: `not logged in — ${names.hint("login")} <your did>` },
  );

  lines.push(configLine);

  // A config that could not be read names no server; checking the default
  // one would report on a server this installation may never use.
  const health =
    configLine.status === "fail"
      ? ({ ok: false, reason: "not checked: the config could not be read" } as const)
      : await getJson(`${origin}/api/v1/health`);
  lines.push(
    health.ok
      ? {
          name: "server",
          status: "ok",
          detail:
            `${cfg.server} (${[health.body.server_name, health.body.version].filter((x) => typeof x === "string").join(" ") || "healthy"})`,
        }
      : configLine.status === "fail"
        ? { name: "server", status: "warn", detail: health.reason }
        : { name: "server", status: "fail", detail: `${origin}/api/v1/health: ${health.reason}` },
  );

  if (input.passive) {
    lines.push({
      name: "connection",
      status: "warn",
      detail: `passive — another ${names.name} session in this project holds it (${names.hint("takeover")})`,
    });
  } else if (conn?.state === "online") {
    lines.push({ name: "connection", status: "ok", detail: conn.describe() });
  } else if (input.dormant) {
    lines.push({
      name: "connection",
      status: "warn",
      detail: `not connected — this project has no freeq identity yet; ${names.hint("status")} connects it`,
    });
  } else if (!cfg.enabled) {
    lines.push({ name: "connection", status: "warn", detail: `disabled (${names.hint("on")})` });
  } else if (conn) {
    lines.push({
      name: "connection",
      status: "fail",
      detail: `${conn.state}${conn.lastError ? ` — last error: ${conn.lastError}` : ""}`,
    });
  } else {
    lines.push({ name: "connection", status: "fail", detail: "not connected" });
  }

  const wanted = channelsForProject(cfg, input.project);
  if (conn?.state !== "online") {
    lines.push({
      name: "channels",
      status: wanted.length ? "warn" : "ok",
      detail: wanted.length ? `configured ${wanted.join(", ")}; none joined (offline)` : "none configured",
    });
  } else {
    const joined = conn.joinedChannels();
    const refused = conn.refusedChannels();
    const missing = wanted.filter(
      (c) => !joined.some((j) => j.toLowerCase() === c.toLowerCase()) && !refused.some((r) => r.channel.toLowerCase() === c.toLowerCase()),
    );
    const parts = [
      joined.length ? `joined ${joined.join(", ")}` : wanted.length ? "none joined" : "none configured",
      ...refused.map((r) => `refused ${r.channel} (${r.reason})`),
      ...(missing.length ? [`not yet joined ${missing.join(", ")}`] : []),
    ];
    lines.push({ name: "channels", status: refused.length || missing.length ? "warn" : "ok", detail: parts.join("; ") });
  }

  return lines;
}
