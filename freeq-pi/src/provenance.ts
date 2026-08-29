/**
 * Provenance — the decision log that writes itself.
 *
 * Everything an agent does over freeq is already signed and durable, so the
 * work here is not cryptography: it is deciding WHAT is worth recording, and
 * keeping it small enough that a human will actually read it.
 *
 * The failure mode to avoid is a firehose. A log of every tool call is
 * technically complete and practically useless — nobody scrolls it, so
 * nobody notices when it is wrong. So the default tier records **decisions
 * and consequences**: what the agent set out to do, what it changed, and what
 * it concluded. Individual reads and greps are noise.
 *
 * Tiers:
 *   silent    nothing is mirrored
 *   decisions (default) turn summaries, files changed, commands with side
 *             effects, and explicit decision records
 *   evidence  the above plus command output excerpts
 *   firehose  every tool call — debugging the mirror itself, not for daily use
 */

export type ProvenanceTier = "silent" | "decisions" | "evidence" | "firehose";
export const PROVENANCE_TIERS: readonly ProvenanceTier[] = [
  "silent",
  "decisions",
  "evidence",
  "firehose",
] as const;
export const DEFAULT_PROVENANCE_TIER: ProvenanceTier = "decisions";

const TIER_RANK: Record<ProvenanceTier, number> = {
  silent: 0,
  decisions: 1,
  evidence: 2,
  firehose: 3,
};

/** A tool call, as the mirror sees it. */
export interface ToolEvent {
  name: string;
  input?: Record<string, unknown>;
}

/**
 * Tools whose use is a *consequence* — they changed something, or reached
 * outside this machine. These are what a reader cares about.
 */
const MUTATING_TOOLS = new Set(["edit", "write", "bash", "freeq"]);

/**
 * Shell commands that only read. A `bash` call is not automatically a
 * consequence: `git status` and `ls` are how an agent looks around, and
 * logging them buries the `git push` that matters.
 */
const READ_ONLY_COMMANDS =
  /^\s*(ls|cat|head|tail|grep|rg|find|wc|stat|file|pwd|echo|which|type|env|date|ps|df|du|tree|diff|git\s+(status|log|diff|show|branch|remote|rev-parse|describe|blame)|npm\s+(ls|view|outdated)|cargo\s+(tree|metadata))\b/;

/** Does this tool call deserve a line in the log at this tier? */
export function shouldRecord(ev: ToolEvent, tier: ProvenanceTier): boolean {
  if (tier === "silent") return false;
  if (TIER_RANK[tier] >= TIER_RANK.firehose) return true;
  if (!MUTATING_TOOLS.has(ev.name)) return false;

  if (ev.name === "bash") {
    const cmd = typeof ev.input?.command === "string" ? ev.input.command : "";
    // A read-only command is how the agent looks around, not something it did.
    if (READ_ONLY_COMMANDS.test(cmd)) return false;
  }
  return true;
}

/** A one-line, human-first description of what happened. */
export function describeToolEvent(ev: ToolEvent): string {
  const input = ev.input ?? {};
  switch (ev.name) {
    case "edit":
    case "write": {
      const path = typeof input.path === "string" ? input.path : "(unknown file)";
      return `${ev.name === "write" ? "wrote" : "edited"} ${basename(path)}`;
    }
    case "bash": {
      const cmd = typeof input.command === "string" ? input.command : "";
      return `ran: ${truncate(firstLine(cmd), 120)}`;
    }
    case "freeq": {
      const action = typeof input.action === "string" ? input.action : "?";
      const to = typeof input.to === "string" ? ` → ${input.to}` : "";
      return `freeq ${action}${to}`;
    }
    default:
      return ev.name;
  }
}

/**
 * A decision record: the thing a reader actually wants six months later.
 *
 * Deliberately not auto-derived. An agent that guesses at "why" produces
 * plausible-sounding fiction; this is emitted only when the reasoning is
 * stated explicitly.
 */
export interface DecisionRecord {
  /** What was decided, in one line. */
  choice: string;
  /** Why — the part that is worth keeping. */
  rationale?: string;
  /** What was rejected, if anything. */
  alternatives?: string;
  /** Task id, commit, file, URL — what backs the claim. */
  evidence?: string;
}

export function formatDecision(d: DecisionRecord): string {
  const parts = [`decision: ${d.choice}`];
  if (d.rationale) parts.push(`because: ${d.rationale}`);
  if (d.alternatives) parts.push(`instead of: ${d.alternatives}`);
  if (d.evidence) parts.push(`evidence: ${d.evidence}`);
  return parts.join("\n");
}

/** Coordination-event tags for a mirrored provenance entry. */
export const PROVENANCE_EVENT = "pi_provenance";
export const DECISION_EVENT = "pi_decision";

export interface ProvenancePayload {
  v: number;
  /** `turn`, `tool`, or `decision`. */
  kind: "turn" | "tool" | "decision";
  /** Human-readable summary. */
  text: string;
  /** Files touched this turn, if any. */
  files?: string[];
  /** Set for decision records. */
  decision?: DecisionRecord;
}

export function buildProvenance(payload: ProvenancePayload): ProvenancePayload {
  return { ...payload, v: 1 };
}

export function parseProvenance(raw: unknown): ProvenancePayload | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.v !== "number" || o.v < 1) return undefined;
  if (o.kind !== "turn" && o.kind !== "tool" && o.kind !== "decision") return undefined;
  if (typeof o.text !== "string" || !o.text.trim()) return undefined;
  return {
    v: o.v,
    kind: o.kind,
    text: o.text.slice(0, 2000),
    files: Array.isArray(o.files)
      ? o.files.filter((f): f is string => typeof f === "string").slice(0, 50)
      : undefined,
    decision:
      o.decision && typeof o.decision === "object"
        ? (o.decision as DecisionRecord)
        : undefined,
  };
}

/**
 * Accumulates what happened during one turn, so the log gets a single
 * readable line rather than a running commentary.
 */
export class TurnRecorder {
  #actions: string[] = [];
  #files = new Set<string>();

  record(ev: ToolEvent, tier: ProvenanceTier): void {
    if (!shouldRecord(ev, tier)) return;
    this.#actions.push(describeToolEvent(ev));
    const path = ev.input?.path;
    if (typeof path === "string") this.#files.add(basename(path));
  }

  get isEmpty(): boolean {
    return this.#actions.length === 0;
  }

  get files(): string[] {
    return [...this.#files];
  }

  /** One line for the room. Returns undefined when nothing worth saying. */
  summary(maxActions = 6): string | undefined {
    if (!this.#actions.length) return undefined;
    const head = this.#actions.slice(0, maxActions);
    const more = this.#actions.length - head.length;
    return head.join("; ") + (more > 0 ? `; +${more} more` : "");
  }

  reset(): void {
    this.#actions = [];
    this.#files.clear();
  }
}

function basename(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : p;
}

function firstLine(s: string): string {
  const i = s.indexOf("\n");
  return i === -1 ? s : `${s.slice(0, i)}…`;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}
