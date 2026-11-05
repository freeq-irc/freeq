// Who may drive Fabro from freeq, and how far.
//
// Same tier vocabulary and order as @freeq/pi (freeq-pi/src/config.ts), so a
// DID's standing reads the same in both places:
//
//   observe  — help, status (no gate questions or failure details)
//   message  — (reserved; nothing extra here)
//   request  — run an upkeep automation from main
//   handoff  — run any workflow with a goal
//   control  — approve / deny / answer gates, cancel runs
//
// One deliberate difference from freeq-pi: a DID that isn't in the table has
// NO standing at all (pi defaults strangers to `observe`). Even `status`
// reveals what is running, so it is opt-in per person.
//
// The owner is always `control`. Everyone else comes from a JSON file,
// `{ "did:plc:…": "observe" }`, re-read on every command so edits apply
// without a restart. Sender DIDs are only ever taken from the server's
// account tag (see cli.ts), never from anything the sender typed.
import { readFile } from "node:fs/promises";
import type { Command } from "./commands.js";

export type Tier = "observe" | "message" | "request" | "handoff" | "control";

export const TIER_RANK: Record<Tier, number> = {
  observe: 0,
  message: 1,
  request: 2,
  handoff: 3,
  control: 4,
};

export function isTier(v: unknown): v is Tier {
  return typeof v === "string" && v in TIER_RANK;
}

export type TrustTable = Record<string, Tier>;

/** Parse a trust file's JSON. Unknown tiers and non-DID keys are dropped. */
export function parseTrust(json: string): TrustTable {
  const raw = JSON.parse(json) as unknown;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("trust file must be a JSON object");
  const out: TrustTable = {};
  for (const [did, tier] of Object.entries(raw as Record<string, unknown>)) {
    if (did.startsWith("did:") && isTier(tier)) out[did] = tier;
  }
  return out;
}

/** Load the trust file; a missing file means "owner only". A malformed file
 *  throws — failing closed beats silently granting nothing or everything. */
export async function loadTrust(path: string): Promise<TrustTable> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  return parseTrust(text);
}

/** The sender's tier, or null for no standing. */
export function tierFor(did: string | null, ownerDid: string, table: TrustTable): Tier | null {
  if (!did) return null;
  if (did === ownerDid) return "control";
  return table[did] ?? null;
}

/** The minimum tier a command needs. */
export function requiredTier(cmd: Command): Tier {
  switch (cmd.kind) {
    case "help":
    case "status":
    case "unknown":
      return "observe";
    case "run":
      return cmd.goal ? "handoff" : "request";
    case "approve":
    case "deny":
    case "answer":
    case "cancel":
      return "control";
  }
}

export function allows(tier: Tier | null, needed: Tier): boolean {
  return tier !== null && TIER_RANK[tier] >= TIER_RANK[needed];
}
