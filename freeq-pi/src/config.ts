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

/**
 * Per-project overrides, keyed by project slug (the git root's directory
 * name). Identity is already per-project; channels had stayed global, so two
 * windows in different repos joined the same rooms and a music project sat in
 * a work channel. A project's entry REPLACES the global channel list rather
 * than adding to it - "also join" is what the global list already means.
 */
export interface ProjectSettings {
  channels?: string[];
}

export interface FreeqConfig {
  /** Owner DID (`did:plc:…`) — set by `/freeq login`. Undefined = not set up. */
  ownerDid?: string;
  /** Per-project channel overrides, keyed by project slug. */
  projects?: Record<string, ProjectSettings>;
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

  /**
   * Accept an offer straight away when this session is idle and the offerer
   * is trusted at `handoff` or above. The alternative is a queue, and a queue
   * only pays off when somebody eventually looks at it — an idle session that
   * declines to start trusted work is just a slower way of dropping it.
   * `autoAccept` above is the stronger, per-DID form: it accepts even mid-turn.
   */
  autoAcceptWhenIdle: boolean;
  /**
   * How long a queued offer may wait before it is declined with a reason.
   * Silence teaches an offerer nothing; a decline lets them re-offer
   * somewhere else while the work still matters.
   */
  offerTtlSecs: number;
  /** How often an in-flight task emits a `progress` heartbeat. */
  progressIntervalSecs: number;
  /** How long an in-flight task may go without model activity before it fails. */
  stallSecs: number;
  /** How many assigned tasks a restart re-enters at once. */
  maxResume: number;
}

export const DEFAULT_SERVER = "wss://irc.freeq.at/irc";

/** Resilience defaults, named so tests and help text quote one source. */
export const DEFAULT_OFFER_TTL_SECS = 1800;
export const DEFAULT_PROGRESS_INTERVAL_SECS = 120;
export const DEFAULT_STALL_SECS = 900;
export const DEFAULT_MAX_RESUME = 3;

export function defaultConfig(): FreeqConfig {
  return {
    server: DEFAULT_SERVER,
    channels: [],
    modes: {},
    trust: {},
    enabled: true,
    muted: false,
    autoAccept: [],
    provenance: "evidence",
    autoAcceptWhenIdle: true,
    offerTtlSecs: DEFAULT_OFFER_TTL_SECS,
    progressIntervalSecs: DEFAULT_PROGRESS_INTERVAL_SECS,
    stallSecs: DEFAULT_STALL_SECS,
    maxResume: DEFAULT_MAX_RESUME,
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
  if (typeof o.autoAcceptWhenIdle === "boolean") base.autoAcceptWhenIdle = o.autoAcceptWhenIdle;
  // A config written before these keys existed simply keeps the defaults, and
  // a nonsensical value (zero, negative, a string) does too — a stall timeout
  // of 0 would fail every task the instant it started.
  base.offerTtlSecs = duration(o.offerTtlSecs, base.offerTtlSecs);
  base.progressIntervalSecs = duration(o.progressIntervalSecs, base.progressIntervalSecs);
  base.stallSecs = duration(o.stallSecs, base.stallSecs);
  base.maxResume = count(o.maxResume, base.maxResume);
  base.channels = normalizeChannels(o.channels);

  if (o.projects && typeof o.projects === "object") {
    const out: Record<string, ProjectSettings> = {};
    for (const [slug, v] of Object.entries(o.projects as Record<string, unknown>)) {
      if (!slug || !v || typeof v !== "object") continue;
      const chans = normalizeChannels((v as Record<string, unknown>).channels);
      // An entry with an empty list is meaningful: "this project joins
      // nothing". Keep it; only drop entries that say nothing at all.
      if (Array.isArray((v as Record<string, unknown>).channels)) out[slug] = { channels: chans };
    }
    if (Object.keys(out).length) base.projects = out;
  }

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

/** A positive number of seconds, or the default. */
function duration(raw: unknown, fallback: number): number {
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.round(raw);
}

/** A non-negative count — zero is meaningful here (resume nothing). */
function count(raw: unknown, fallback: number): number {
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0) return fallback;
  return Math.floor(raw);
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

/**
 * The channels this project should be in.
 *
 * A project entry wins outright when present; otherwise the global list. The
 * caller passes the project slug because config does not know the cwd.
 */
export function channelsForProject(config: FreeqConfig, project?: string): string[] {
  const entry = project ? config.projects?.[project] : undefined;
  return entry?.channels ? [...entry.channels] : [...config.channels];
}

/**
 * Return a config in which `project` joins exactly `channels`.
 *
 * Writing pins the project: once a window has said "join here" or "leave
 * there", it stops inheriting later edits to the global list, which is the
 * only reading under which /freeq leave means what it says.
 */
export function withProjectChannels(
  config: FreeqConfig,
  project: string,
  channels: string[],
): FreeqConfig {
  const projects = { ...(config.projects ?? {}) };
  projects[project] = { channels: [...new Set(channels.map((c) => c.trim()).filter(Boolean))] };
  return { ...config, projects };
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
