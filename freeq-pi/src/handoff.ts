/**
 * Handoffs — durable, signed delegation between independently owned agents.
 *
 * This is the capability local (same-filesystem) multiplayer extensions
 * cannot provide: work that is addressed to an identity, survives the
 * recipient being offline, and carries a signed lifecycle anyone can audit.
 *
 * WHAT IS REUSED (deliberately — see the RFC's build discipline):
 *   - `@freeq/sdk` `sendAct()` signs and emits the TAGMSG plus a
 *     human-readable companion PRIVMSG.
 *   - `@freeq/sdk` `actTags()` builds the `+freeq.at/act-*` tag set.
 *   - `@freeq/bot-kit` `checkTransition()` / `initialState()` own the
 *     lifecycle rules, loaded from `act-transitions.json`. We do NOT restate
 *     which verb is legal from which state; that table is the authority.
 *
 * WHAT IS NEW HERE: a local materialized view (per the RFC: the signed log is
 * the source of truth, the view is rebuildable and never authoritative), plus
 * the policy for what a pi session does about an inbound offer.
 *
 * DELIVERY: handoffs are posted **in a channel** with `act-to` naming the
 * assignee DID. That is the RFC's recommended default for multi-agent work —
 * the room gets observability and, critically, channel history gives us
 * offline replay for free. An offer made while the recipient is asleep is
 * replayed by the server when their pi reconnects; we dedupe by task id.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import {
  checkTransition,
  initialState,
  isTerminal,
  refusalDescription,
  type Task,
} from "@freeq/bot-kit";

/**
 * The verb a home server uses to acknowledge an event it filed. bot-kit does
 * not re-export its `isConfirmation` helper, but `checkTransition` reports
 * confirmations with a dedicated refusal reason — so we key off that public
 * contract rather than deep-importing or hardcoding a verb list.
 */
const CONFIRM_REFUSAL = "client-confirm";

export const HANDOFF_KIND = "handoff";

/** A handoff as this session currently understands it. */
export interface HandoffRecord {
  id: string;
  kind: string;
  state: string;
  /** DID of the offerer. */
  offerer: string;
  /** DID of the intended assignee; undefined for an open (claimable) offer. */
  offeree?: string;
  /** DID currently doing the work. */
  assignee?: string;
  title: string;
  /** Free-text brief. Held locally; the wire carries its hash. */
  note?: string;
  /** sha256 of the brief, as signed (`act-ctx-h`). */
  ctxHash?: string;
  /** Self-declared capability hints. */
  caps?: string;
  /** Unix seconds. */
  deadline?: number;
  /** Venue the task lives in. */
  channel: string;
  /** Nick of whoever last moved it, for display. */
  lastActor?: string;
  /** True when we have never seen this task live — i.e. it arrived by replay. */
  fromReplay: boolean;
  /** True when every event we applied carried a signature. */
  signed: boolean;
  /**
   * Worst verification outcome across the events we applied.
   *
   * `valid` means every event's signature was checked against the key it
   * named. `unverifiable` means at least one could not be checked (no key on
   * record, or the key origin was unreachable) — the work is NOT discarded,
   * per the RFC, but the chain is not proven either. Events that verify as
   * INVALID are never applied, so they never appear here.
   */
  verification?: "valid" | "unverifiable";
  createdAt: number;
  updatedAt: number;
  /** Append-only local log of applied events, for `/freeq handoffs <id>`. */
  log: Array<{ verb: string; by: string; at: number; note?: string }>;
}

export type ApplyResult =
  | { ok: true; record: HandoffRecord; created: boolean }
  | { ok: false; reason: string; taskId?: string; /** Routine, not a problem. */ benign?: boolean };

/** The subset of an act event this module needs. Mirrors ActEventPayload. */
export interface ActEventLike {
  channel: string;
  from: string;
  did?: string;
  kind: string;
  verb: string;
  eventId: string;
  taskId: string;
  fields: Record<string, string>;
  sigTag?: string;
  replayed: boolean;
}

export function hashBrief(text: string): string {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

/**
 * In-memory view of every handoff this installation knows about, persisted so
 * it survives a pi restart (the RFC's view is rebuildable from the log; this
 * is a cache that also lets us dedupe replayed events).
 */
export class HandoffStore {
  #records = new Map<string, HandoffRecord>();
  #path: string;
  #dirty = false;

  constructor(path: string) {
    this.#path = path;
  }

  static pathFor(agentDir: string): string {
    return join(agentDir, "freeq-handoffs.json");
  }

  async load(): Promise<void> {
    try {
      const raw = JSON.parse(await readFile(this.#path, "utf8")) as unknown;
      if (Array.isArray(raw)) {
        for (const r of raw) {
          const rec = normalizeRecord(r);
          if (rec) this.#records.set(rec.id, rec);
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        // A corrupt view must not stop the session; it is rebuildable.
        this.#records.clear();
      }
    }
  }

  async save(): Promise<void> {
    if (!this.#dirty) return;
    this.#dirty = false;
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(this.#path, `${JSON.stringify([...this.#records.values()], null, 2)}\n`, {
      mode: 0o600,
    });
  }

  get(id: string): HandoffRecord | undefined {
    return this.#records.get(id);
  }

  all(): HandoffRecord[] {
    return [...this.#records.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** Non-terminal tasks assigned to, or offered to, the given DID. */
  inboxFor(did: string | undefined): HandoffRecord[] {
    if (!did) return [];
    return this.all().filter(
      (r) =>
        !isTerminal(r.kind, r.state) &&
        (r.offeree === did || r.assignee === did || (!r.offeree && r.state === "open")),
    );
  }

  /** Non-terminal tasks this DID offered. */
  outboxFor(did: string | undefined): HandoffRecord[] {
    if (!did) return [];
    return this.all().filter((r) => !isTerminal(r.kind, r.state) && r.offerer === did);
  }

  /** Record a task we are creating locally (before the wire echo arrives). */
  put(record: HandoffRecord): void {
    this.#records.set(record.id, record);
    this.#dirty = true;
  }

  /**
   * Apply an inbound act event.
   *
   * Legality is delegated to bot-kit's transition table — this function never
   * decides which verb is allowed, only how to fold a legal one into the view.
   */
  apply(ev: ActEventLike): ApplyResult {
    if (ev.kind !== HANDOFF_KIND) {
      return { ok: false, reason: `unsupported kind '${ev.kind}'` };
    }
    const actor = ev.did;
    if (!actor) {
      // Every participant in an action is a DID by construction (RFC); an
      // event we cannot attribute is not one we can authorize.
      return { ok: false, reason: "event has no attributable DID" };
    }

    const opener = !ev.fields["act-id"];
    const existing = this.#records.get(ev.taskId);

    if (opener) {
      // Re-seeing our own offer (echo, or history replay into a rebuilt view)
      // is expected, not a fault.
      if (existing) {
        return { ok: false, reason: "duplicate offer", taskId: ev.taskId, benign: true };
      }
      const directed = !!ev.fields["act-to"];
      const state = initialState(HANDOFF_KIND, directed);
      if (!state) return { ok: false, reason: "kind cannot be opened" };

      const now = Date.now();
      const rec: HandoffRecord = {
        id: ev.taskId,
        kind: HANDOFF_KIND,
        state,
        offerer: actor,
        offeree: ev.fields["act-to"] || undefined,
        title: ev.fields["act-title"] || "(untitled)",
        ctxHash: ev.fields["act-ctx-h"] || undefined,
        caps: ev.fields["act-caps"] || undefined,
        deadline: numeric(ev.fields["act-deadline"]),
        channel: ev.channel,
        lastActor: ev.from,
        fromReplay: ev.replayed,
        signed: !!ev.sigTag,
        createdAt: now,
        updatedAt: now,
        log: [{ verb: ev.verb, by: actor, at: now, note: ev.fields["act-note"] }],
      };
      this.#records.set(rec.id, rec);
      this.#dirty = true;
      return { ok: true, record: rec, created: true };
    }

    if (!existing) {
      // A move for a task we never saw the opener of. Common and benign
      // during replay; we cannot validate it, so we refuse rather than invent
      // a task from a transition.
      return { ok: false, reason: "move for an unknown task", taskId: ev.taskId };
    }

    const task: Task = {
      kind: existing.kind,
      state: existing.state,
      offerer: existing.offerer,
      offeree: existing.offeree ?? null,
      assignee: existing.assignee ?? null,
      deadline: existing.deadline ?? null,
    };

    const verdict = checkTransition(
      task,
      { verb: ev.verb, msgid: ev.eventId, fields: Object.keys(ev.fields) },
      { did: actor },
    );
    if (!verdict.ok) {
      // A confirmation is the home server's receipt for an event it filed,
      // not a move anybody makes. Expected on the wire; not a fault.
      return {
        ok: false,
        reason:
          verdict.reason === CONFIRM_REFUSAL
            ? "server receipt"
            : refusalDescription(verdict.reason),
        taskId: ev.taskId,
        benign: verdict.reason === CONFIRM_REFUSAL,
      };
    }

    existing.state = verdict.to;
    if (ev.verb === "accept" || ev.verb === "claim") existing.assignee = actor;
    existing.lastActor = ev.from;
    existing.updatedAt = Date.now();
    existing.signed = existing.signed && !!ev.sigTag;
    existing.log.push({
      verb: ev.verb,
      by: actor,
      at: Date.now(),
      note: ev.fields["act-note"],
    });
    this.#dirty = true;
    return { ok: true, record: existing, created: false };
  }
}

function numeric(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function normalizeRecord(raw: unknown): HandoffRecord | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.id !== "string" || typeof o.state !== "string") return undefined;
  if (typeof o.offerer !== "string" || typeof o.channel !== "string") return undefined;
  return {
    id: o.id,
    kind: typeof o.kind === "string" ? o.kind : HANDOFF_KIND,
    state: o.state,
    offerer: o.offerer,
    offeree: typeof o.offeree === "string" ? o.offeree : undefined,
    assignee: typeof o.assignee === "string" ? o.assignee : undefined,
    title: typeof o.title === "string" ? o.title : "(untitled)",
    note: typeof o.note === "string" ? o.note : undefined,
    ctxHash: typeof o.ctxHash === "string" ? o.ctxHash : undefined,
    caps: typeof o.caps === "string" ? o.caps : undefined,
    deadline: typeof o.deadline === "number" ? o.deadline : undefined,
    channel: o.channel,
    lastActor: typeof o.lastActor === "string" ? o.lastActor : undefined,
    fromReplay: o.fromReplay === true,
    signed: o.signed !== false,
    verification:
      o.verification === "valid" || o.verification === "unverifiable" ? o.verification : undefined,
    createdAt: typeof o.createdAt === "number" ? o.createdAt : Date.now(),
    updatedAt: typeof o.updatedAt === "number" ? o.updatedAt : Date.now(),
    log: Array.isArray(o.log)
      ? o.log.flatMap((e) => {
          if (!e || typeof e !== "object") return [];
          const le = e as Record<string, unknown>;
          if (typeof le.verb !== "string" || typeof le.by !== "string") return [];
          return [
            {
              verb: le.verb,
              by: le.by,
              at: typeof le.at === "number" ? le.at : 0,
              note: typeof le.note === "string" ? le.note : undefined,
            },
          ];
        })
      : [],
  };
}

/** Fold a new verification outcome into a record, keeping the worst. */
export function noteVerification(
  rec: HandoffRecord,
  outcome: "valid" | "unverifiable",
): void {
  if (outcome === "unverifiable" || rec.verification === "unverifiable") {
    rec.verification = "unverifiable";
    return;
  }
  rec.verification = "valid";
}

/** One-line human summary of a handoff. */
export function describeHandoff(r: HandoffRecord, selfDid?: string): string {
  const who =
    r.offerer === selfDid
      ? `→ ${short(r.offeree) ?? "open"}`
      : `← ${short(r.offerer)}`;
  const flags = [
    r.signed ? "" : " unsigned",
    r.verification === "valid" ? " ✓verified" : "",
    r.verification === "unverifiable" ? " ⚠unverified" : "",
    r.fromReplay ? " (replayed)" : "",
  ].join("");
  return `${r.id.slice(0, 10)}  ${r.state.padEnd(9)} ${who}  ${r.title}${flags}`;
}

function short(did: string | undefined): string | undefined {
  if (!did) return undefined;
  return did.length > 22 ? `${did.slice(0, 18)}…` : did;
}
