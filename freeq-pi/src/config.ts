/**
 * Configuration for @freeq/pi.
 *
 * Two layers:
 *   1. user   — `<agentDir>/freeq.json`      (identity, server, trust)
 *   2. project — `<cwd>/<CONFIG_DIR_NAME>/freeq.json` (channels, modes only)
 *
 * The project layer is deliberately *narrow*: a repo you cloned must never be
 * able to hand you an owner DID, a server, or a trust table. Those are user
 * decisions. Project config may only add channels and set presentation modes,
 * and is honoured only when the project is trusted (see `loadConfig`).
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

/** Presentation mode for a channel (design doc §3). */
export type Mode = "silent" | "addressed" | "participant";
export const MODES: readonly Mode[] = ["silent", "addressed", "participant"] as const;
export const DEFAULT_MODE: Mode = "addressed";

/**
 * Authority tiers (design doc §6). Ordered — comparisons use `TIER_RANK`.
 * Landing in M2; the type and storage live here from M1 so the config file
 * format doesn't change under users between milestones.
 */
export type ProvenanceTier = "silent" | "decisions" | "evidence" | "firehose";

export type Tier = "observe" | "message" | "request" | "handoff" | "control";
export const TIER_RANK: Record<Tier, number> = {
  observe: 0,
  message: 1,
  request: 2,
  handoff: 3,
  control: 4,
};
export const DEFAULT_TIER: Tier = "observe";

export interface FreeqConfig {
  /** Owner DID (`did:plc:…`) — set by `/freeq login`. Undefined = not set up. */
  ownerDid?: string;
  /** WebSocket URL of the freeq server. */
  server: string;
  /** Nick to register with. Defaults to `pi-<install>`. */
  nick?: string;
  /** Stable installation slug — names the identity and its state dir. */
  install?: string;
  /** Channels to join on connect. */
  channels: string[];
  /** Per-channel presentation mode. Keys are lowercased channel names. */
  modes: Record<string, Mode>;
  /** DID → authority tier. Owner is always `control`, regardless of this map. */
  trust: Record<string, Tier>;
  /** Master switch — `/freeq off` sets false without discarding config. */
  enabled: boolean;
  /**
   * `/freeq mute` — stay connected but behave as `silent` everywhere.
   * Distinct from `enabled: false`, which disconnects entirely.
   */
  muted: boolean;
  /**
   * DIDs whose handoff offers are accepted without a confirmation prompt.
   * Opt-in only, and only meaningful at `handoff` tier or above.
   */
  autoAccept?: string[];
  /**
   * How much of this agent's work is mirrored to freeq as a signed log.
   * Default `decisions`: changes and outbound actions, not every read.
   */
  provenance?: ProvenanceTier;
  /** Where provenance goes. Defaults to the first joined channel. */
  provenanceChannel?: string;
}

export const DEFAULT_SERVER = "wss://irc.freeq.at/irc";

export function defaultConfig(): FreeqConfig {
  return {
    server: DEFAULT_SERVER,
    channels: [],
    modes: {},
    trust: {},
    enabled: true,
    muted: false,
    autoAccept: [],
    provenance: "decisions",
  };
}

/** Fields a project-local config may contribute. Everything else is ignored. */
type ProjectOverrides = Partial<Pick<FreeqConfig, "channels" | "modes">>;

export function userConfigPath(agentDir: string): string {
  return join(agentDir, "freeq.json");
}

export function projectConfigPath(cwd: string, configDirName: string): string {
  return join(cwd, configDirName, "freeq.json");
}

async function readJson(path: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return undefined;
    throw new Error(`freeq: cannot read config at ${path}: ${(err as Error).message}`);
  }
}

/** Coerce unknown JSON into a config, dropping anything malformed. */
export function normalizeConfig(raw: unknown): FreeqConfig {
  const base = defaultConfig();
  if (!raw || typeof raw !== "object") return base;
  const o = raw as Record<string, unknown>;

  if (typeof o.ownerDid === "string" && o.ownerDid.startsWith("did:")) base.ownerDid = o.ownerDid;
  if (typeof o.server === "string" && o.server) base.server = o.server;
  if (typeof o.nick === "string" && o.nick) base.nick = o.nick;
  if (typeof o.install === "string" && o.install) base.install = o.install;
  if (typeof o.enabled === "boolean") base.enabled = o.enabled;
  if (typeof o.muted === "boolean") base.muted = o.muted;
  if (
    typeof o.provenance === "string" &&
    ["silent", "decisions", "evidence", "firehose"].includes(o.provenance)
  ) {
    base.provenance = o.provenance as ProvenanceTier;
  }
  if (typeof o.provenanceChannel === "string" && o.provenanceChannel.startsWith("#")) {
    base.provenanceChannel = o.provenanceChannel;
  }
  if (Array.isArray(o.autoAccept)) {
    base.autoAccept = o.autoAccept.filter(
      (d): d is string => typeof d === "string" && d.startsWith("did:"),
    );
  }
  base.channels = normalizeChannels(o.channels);

  if (o.modes && typeof o.modes === "object") {
    for (const [k, v] of Object.entries(o.modes as Record<string, unknown>)) {
      if (typeof v === "string" && (MODES as readonly string[]).includes(v)) {
        base.modes[k.toLowerCase()] = v as Mode;
      }
    }
  }
  if (o.trust && typeof o.trust === "object") {
    for (const [k, v] of Object.entries(o.trust as Record<string, unknown>)) {
      if (typeof v === "string" && v in TIER_RANK && k.startsWith("did:")) {
        base.trust[k] = v as Tier;
      }
    }
  }
  return base;
}

function normalizeChannels(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const c of raw) {
    if (typeof c !== "string") continue;
    const name = c.trim();
    if (!name.startsWith("#") || name.length < 2) continue;
    if (!out.some((e) => e.toLowerCase() === name.toLowerCase())) out.push(name);
  }
  return out;
}

/** Extract only the fields a project config is allowed to contribute. */
export function projectOverrides(raw: unknown): ProjectOverrides {
  if (!raw || typeof raw !== "object") return {};
  const norm = normalizeConfig({
    channels: (raw as Record<string, unknown>).channels,
    modes: (raw as Record<string, unknown>).modes,
  });
  return { channels: norm.channels, modes: norm.modes };
}

export function mergeProject(user: FreeqConfig, overrides: ProjectOverrides): FreeqConfig {
  const merged: FreeqConfig = { ...user, channels: [...user.channels], modes: { ...user.modes } };
  for (const c of overrides.channels ?? []) {
    if (!merged.channels.some((e) => e.toLowerCase() === c.toLowerCase())) merged.channels.push(c);
  }
  Object.assign(merged.modes, overrides.modes ?? {});
  return merged;
}

export interface LoadOptions {
  agentDir: string;
  cwd: string;
  configDirName: string;
  /** Project config is ignored entirely when false. */
  projectTrusted: boolean;
}

export interface LoadedConfig {
  config: FreeqConfig;
  /** Paths actually read, for `/freeq status`. */
  sources: string[];
}

export async function loadConfig(opts: LoadOptions): Promise<LoadedConfig> {
  const sources: string[] = [];
  const userPath = userConfigPath(opts.agentDir);
  const rawUser = await readJson(userPath);
  if (rawUser !== undefined) sources.push(userPath);
  let config = normalizeConfig(rawUser);

  if (opts.projectTrusted) {
    const projPath = projectConfigPath(opts.cwd, opts.configDirName);
    const rawProj = await readJson(projPath);
    if (rawProj !== undefined) {
      sources.push(projPath);
      config = mergeProject(config, projectOverrides(rawProj));
    }
  }
  return { config, sources };
}

/** Persist the user-level config (never writes project config). */
export async function saveConfig(agentDir: string, config: FreeqConfig): Promise<void> {
  const path = userConfigPath(agentDir);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

/** Effective mode for a channel. Mute forces `silent` everywhere. */
export function modeFor(config: FreeqConfig, channel: string): Mode {
  if (config.muted) return "silent";
  return config.modes[channel.toLowerCase()] ?? DEFAULT_MODE;
}

/**
 * Effective authority tier for a DID.
 *
 * Owner is pinned to `control` and unknown/guest (null) DIDs floor at
 * `observe` — the two invariants M2's inbound pipeline depends on.
 */
export function tierFor(config: FreeqConfig, did: string | null | undefined): Tier {
  if (!did) return DEFAULT_TIER;
  if (config.ownerDid && did === config.ownerDid) return "control";
  return config.trust[did] ?? DEFAULT_TIER;
}

export function tierAtLeast(a: Tier, b: Tier): boolean {
  return TIER_RANK[a] >= TIER_RANK[b];
}
