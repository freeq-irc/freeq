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
import { tierAtLeast, type Tier } from "./config.js";

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

// ── intake: what a session does about an offer addressed to it ─────────────
//
// The old answer was a blocking modal, and a modal is exactly what loses
// work: nobody at the terminal, or a restart while it is open, and the offer
// is gone — the task sits `offered` forever and nothing ever revisits it.
// Replay does not help, because the event did arrive; we dropped it.
//
// So an offer either starts now or goes in a queue that outlives the session.

export type OfferAction =
  /** Not even worth telling the user about — an untrusted DID. */
  | "ignore"
  /** Accept it now. */
  | "accept"
  /** Hold it until this session is free, or until it expires. */
  | "queue";

export interface OfferDecision {
  action: OfferAction;
  /** One sentence naming why, for the notification and the tests. */
  reason: string;
}

export interface OfferPolicy {
  /** The offerer's authority tier. */
  tier: Tier;
  /** Is this session free right now? */
  idle: boolean;
  /** The offerer is on `cfg.autoAccept` — an explicit per-DID override. */
  autoAcceptDid: boolean;
  /** `cfg.autoAcceptWhenIdle`. */
  autoAcceptWhenIdle: boolean;
}

/**
 * Decide what to do with an offer addressed to us.
 *
 * The trust gate comes first and is absolute: an unknown DID must not be able
 * to raise a dialog in your terminal, put anything in your queue, or cost you
 * a notification. Everything after it is about timing, not authority.
 */
export function decideOffer(p: OfferPolicy): OfferDecision {
  if (!tierAtLeast(p.tier, "handoff")) {
    return {
      action: "ignore",
      reason: `offerer is tier '${p.tier}', below 'handoff' — ignored entirely`,
    };
  }
  if (p.autoAcceptDid) {
    return { action: "accept", reason: "the offerer is on your auto-accept list" };
  }
  if (p.autoAcceptWhenIdle && p.idle) {
    return { action: "accept", reason: "this session is idle and the offerer is trusted" };
  }
  return {
    action: "queue",
    reason: p.idle
      ? "auto-accept when idle is off — queued for you to decide"
      : "this session is busy — queued rather than interrupting the turn",
  };
}

/** An offer waiting for this session to be free. */
export interface QueuedOffer {
  taskId: string;
  /** epoch ms this offer was queued. */
  queuedAt: number;
}

/**
 * The queue of offers we have not answered yet.
 *
 * Persisted beside the handoff view rather than inside it: the view's on-disk
 * shape is a plain array that older builds already read, and a queue entry is
 * a decision we owe, not a fact about a task. The records themselves stay in
 * `HandoffStore` — an entry here is only an id and a clock.
 */
export class OfferQueue {
  #entries: QueuedOffer[] = [];
  #path: string;
  #dirty = false;

  constructor(path: string) {
    this.#path = path;
  }

  static pathFor(agentDir: string): string {
    return join(agentDir, "freeq-offer-queue.json");
  }

  async load(): Promise<void> {
    try {
      const raw = JSON.parse(await readFile(this.#path, "utf8")) as unknown;
      if (Array.isArray(raw)) {
        for (const e of raw) {
          if (!e || typeof e !== "object") continue;
          const o = e as Record<string, unknown>;
          if (typeof o.taskId !== "string") continue;
          this.#entries.push({
            taskId: o.taskId,
            queuedAt: typeof o.queuedAt === "number" ? o.queuedAt : Date.now(),
          });
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        // Losing the queue costs us pending offers, which is bad — but not as
        // bad as refusing to start the session over a corrupt cache file.
        this.#entries = [];
      }
    }
  }

  async save(): Promise<void> {
    if (!this.#dirty) return;
    this.#dirty = false;
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(this.#path, `${JSON.stringify(this.#entries, null, 2)}\n`, { mode: 0o600 });
  }

  /** Oldest first — the order the queue is drained in. */
  all(): QueuedOffer[] {
    return [...this.#entries].sort((a, b) => a.queuedAt - b.queuedAt);
  }

  has(taskId: string): boolean {
    return this.#entries.some((e) => e.taskId === taskId);
  }

  /** Queue an offer. Queuing one twice is a no-op, not a second entry. */
  add(taskId: string, at = Date.now()): void {
    if (this.has(taskId)) return;
    this.#entries.push({ taskId, queuedAt: at });
    this.#dirty = true;
  }

  remove(taskId: string): void {
    const before = this.#entries.length;
    this.#entries = this.#entries.filter((e) => e.taskId !== taskId);
    if (this.#entries.length !== before) this.#dirty = true;
  }
}

/** What a pass over the queue found to do. */
export interface QueueSweep {
  /** The one offer to accept now. At most one: accepting makes us busy. */
  accept?: { entry: QueuedOffer; record: HandoffRecord };
  /** Offers to decline, each with the reason to send with the decline. */
  expire: Array<{ entry: QueuedOffer; record: HandoffRecord; reason: string }>;
  /** Entries to forget silently — the task moved on without us. */
  drop: QueuedOffer[];
}

export interface SweepOptions {
  entries: QueuedOffer[];
  /** The current record for a queued id, if the view still has one. */
  lookup: (taskId: string) => HandoffRecord | undefined;
  /** Is the offerer still trusted at `handoff` or above? */
  trusted: (offererDid: string) => boolean;
  /** Is this session free right now? */
  idle: boolean;
  now: number;
  ttlSecs: number;
}

/**
 * One pass over the queue: expire what has waited too long, then take the
 * oldest thing left if we are free.
 *
 * Expiry runs first on purpose. An offer whose deadline has already passed is
 * not work we can honestly start, so it must not be picked up by the same
 * sweep that would have retired it.
 */
export function sweepOfferQueue(opts: SweepOptions): QueueSweep {
  const sweep: QueueSweep = { expire: [], drop: [] };
  const live: Array<{ entry: QueuedOffer; record: HandoffRecord }> = [];

  for (const entry of [...opts.entries].sort((a, b) => a.queuedAt - b.queuedAt)) {
    const record = opts.lookup(entry.taskId);
    // A record we no longer hold, or one that has moved on (cancelled by the
    // offerer, expired by the server, accepted from another window) is not an
    // open question any more. Forget it without saying anything.
    if (!record || record.state !== "offered" || isTerminal(record.kind, record.state)) {
      sweep.drop.push(entry);
      continue;
    }
    const expiry = offerExpiry(record, entry.queuedAt, opts.ttlSecs);
    if (opts.now >= expiry.at) {
      sweep.expire.push({ entry, record, reason: expiry.reason });
      continue;
    }
    // Trust can be revoked while an offer sits in the queue. Do not act on it,
    // but do not decline it either — the offer was legitimate when it arrived
    // and its TTL will retire it soon enough.
    if (opts.trusted(record.offerer)) live.push({ entry, record });
  }

  if (opts.idle && live.length) sweep.accept = live[0];
  return sweep;
}

/**
 * When a queued offer stops being answerable, and what to say about it.
 *
 * The task's own deadline wins when it is sooner: accepting work whose
 * deadline has passed helps nobody, and our TTL is only a floor on how long
 * we are willing to sit on a decision.
 */
export function offerExpiry(
  rec: HandoffRecord,
  queuedAt: number,
  ttlSecs: number,
): { at: number; reason: string } {
  const ttlAt = queuedAt + ttlSecs * 1000;
  const deadlineAt = rec.deadline ? rec.deadline * 1000 : undefined;
  if (deadlineAt !== undefined && deadlineAt < ttlAt) {
    return { at: deadlineAt, reason: "the offer's own deadline passed before this session was free" };
  }
  return {
    at: ttlAt,
    reason: `no decision for ${formatDuration(ttlSecs)} — this session was never free to take it`,
  };
}

/** Durations as a human says them: 45s, 15m, 2h, 1d. */
export function formatDuration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86_400) return `${Math.round(s / 360) / 10}h`.replace(".0h", "h");
  return `${Math.round(s / 8640) / 10}d`.replace(".0d", "d");
}

/** How long ago, for listings. */
export function formatAge(ms: number): string {
  return `${formatDuration(ms / 1000)} ago`;
}

// ── a watchdog on work we accepted ────────────────────────────────────────
//
// Accepting used to be the last thing that happened: a presence label, a
// prompt, and then nothing tracked the work at all. A model that wanders off
// leaves the task `assigned` until the server's expiry sweep notices, days
// later, and the offerer has no way to tell a busy agent from a dead one.
//
// Two clocks fix that. A heartbeat says the work is alive; a stall timeout
// says honestly that it is not. `progress` is additive in the transition
// table, so the heartbeat costs the task nothing.

/** A task this session is working on right now. */
export interface WatchedTask {
  taskId: string;
  channel: string;
  title: string;
  startedAt: number;
  /** Last sign of life from the model — a turn starting, a tool running. */
  lastProgressAt: number;
  /** Last heartbeat we emitted, so beats are spaced rather than repeated. */
  lastBeatAt: number;
}

/** Something the watchdog wants said on the wire. The caller emits it. */
export type WatchdogAction =
  | { kind: "progress"; task: WatchedTask; note: string }
  | { kind: "fail"; task: WatchedTask; reason: string };

/**
 * The clocks on in-flight work.
 *
 * Deliberately has no timer of its own: the caller ticks it. That keeps the
 * decision — beat, fail, or nothing — testable at any point in time without
 * waiting fifteen real minutes for a stall, and it means teardown is a single
 * `clearInterval` in one place rather than two timers per task to chase.
 */
export class WorkWatchdog {
  #tasks = new Map<string, WatchedTask>();
  #progressIntervalMs: number;
  #stallMs: number;

  constructor(opts: { progressIntervalSecs: number; stallSecs: number }) {
    this.#progressIntervalMs = opts.progressIntervalSecs * 1000;
    this.#stallMs = opts.stallSecs * 1000;
  }

  /** Begin watching. Starting a task we already watch only marks it alive. */
  start(task: { taskId: string; channel: string; title: string }, now = Date.now()): void {
    const existing = this.#tasks.get(task.taskId);
    if (existing) {
      existing.lastProgressAt = now;
      return;
    }
    this.#tasks.set(task.taskId, {
      taskId: task.taskId,
      channel: task.channel,
      title: task.title,
      startedAt: now,
      lastProgressAt: now,
      lastBeatAt: now,
    });
  }

  /** The model did something. Named `touch` because it only moves a clock. */
  touch(now = Date.now(), taskId?: string): void {
    for (const t of this.#tasks.values()) {
      if (taskId && t.taskId !== taskId) continue;
      t.lastProgressAt = now;
    }
  }

  /** Stop watching — the task completed, failed, or is no longer ours. */
  finish(taskId: string): boolean {
    return this.#tasks.delete(taskId);
  }

  has(taskId: string): boolean {
    return this.#tasks.has(taskId);
  }

  inFlight(): WatchedTask[] {
    return [...this.#tasks.values()];
  }

  /**
   * Advance the clocks.
   *
   * A stalled task is dropped as it fails, so the failure can only ever be
   * emitted once however often this is called afterwards.
   */
  tick(now = Date.now()): WatchdogAction[] {
    const out: WatchdogAction[] = [];
    for (const task of [...this.#tasks.values()]) {
      if (now - task.lastProgressAt >= this.#stallMs) {
        this.#tasks.delete(task.taskId);
        out.push({
          kind: "fail",
          task,
          reason:
            `no progress for ${formatDuration(this.#stallMs / 1000)} — ` +
            `the session stopped working on it`,
        });
        continue;
      }
      if (now - task.lastBeatAt >= this.#progressIntervalMs) {
        task.lastBeatAt = now;
        out.push({
          kind: "progress",
          task,
          note: `still on it — ${formatDuration((now - task.startedAt) / 1000)} so far`,
        });
      }
    }
    return out;
  }

  /**
   * The session is going down.
   *
   * Every in-flight task gets a note saying so, and none of them fails: a
   * restart may pick the work straight back up, and a false failure in a
   * signed, permanent log is worse than a gap in it.
   */
  shutdown(now = Date.now()): WatchdogAction[] {
    const out: WatchdogAction[] = this.inFlight().map((task) => ({
      kind: "progress" as const,
      task,
      note:
        `the pi session working on this is shutting down after ` +
        `${formatDuration((now - task.startedAt) / 1000)} — not finished`,
    }));
    this.#tasks.clear();
    return out;
  }
}

// ── resume: picking up where a restarted session left off ─────────────────
//
// A restart used to load the view and ask nobody anything, so work this
// session had accepted simply stopped. The view alone cannot answer the
// question either: it is a cache, and a cache that says "still mine" about
// work somebody else has since taken is worse than no answer. So we ask the
// server, which is the authority on who holds what.

/** One row of `GET /api/v1/actions`, reduced to what a resume needs. */
export interface ServerTask {
  id: string;
  kind: string;
  state: string;
  /** Where the task lives — a channel for everything we post. */
  venue: string;
  offerer?: string;
  offeree?: string;
  assignee?: string;
  caps?: string;
  /** Unix seconds. */
  deadline?: number;
  /** epoch ms the server last saw it move. */
  updated?: number;
}

/**
 * Read the listing.
 *
 * `stored_state` is preferred over `state` where the server sends both:
 * `state` can read `orphaned`, which is this server's opinion about a task
 * whose home it has lost contact with, not the task's own record. Our task is
 * still assigned to us; a federation link being down does not un-assign it.
 */
export function parseServerTasks(body: unknown): ServerTask[] {
  const rows = (body as { tasks?: unknown })?.tasks;
  if (!Array.isArray(rows)) return [];
  const out: ServerTask[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const o = row as Record<string, unknown>;
    const id = typeof o.act_id === "string" ? o.act_id : undefined;
    const state = str(o.stored_state) ?? str(o.state);
    if (!id || !state) continue;
    out.push({
      id,
      kind: str(o.kind) ?? HANDOFF_KIND,
      state,
      venue: str(o.venue) ?? "",
      offerer: str(o.offerer),
      offeree: str(o.offeree),
      assignee: str(o.assignee),
      caps: str(o.caps),
      deadline: typeof o.deadline === "number" ? o.deadline : undefined,
      updated: epochMs(o.updated),
    });
  }
  return out;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

/** Timestamps arrive in seconds; everything in this package is in ms. */
function epochMs(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
  return v < 1e12 ? v * 1000 : v;
}

/**
 * Ask the server what it still holds for us.
 *
 * A failure here is an outage, not an answer: it returns nothing and says
 * why, so the caller reports a resume it could not do rather than concluding
 * there was nothing to resume.
 */
export async function fetchAssignedTasks(opts: {
  origin: string;
  did: string;
  state?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}): Promise<{ ok: true; tasks: ServerTask[] } | { ok: false; reason: string }> {
  const url =
    `${opts.origin.replace(/\/$/, "")}/api/v1/actions` +
    `?assignee=${encodeURIComponent(opts.did)}&state=${encodeURIComponent(opts.state ?? "assigned")}`;
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, {
      signal: AbortSignal.timeout(opts.timeoutMs ?? 8000),
    });
    if (!res.ok) return { ok: false, reason: `the task listing returned ${res.status}` };
    return { ok: true, tasks: parseServerTasks(await res.json()) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

export interface ResumePlan {
  /** Tasks to re-enter, oldest first. */
  resume: HandoffRecord[];
  /** Still assigned to us, but not started by this pass. */
  skipped: number;
  /** Local records claiming to be ours that the server does not list. */
  stale: HandoffRecord[];
}

export interface ResumeOptions {
  /** The server's answer, already filtered to `assignee=us&state=assigned`. */
  serverTasks: ServerTask[];
  /** What the local view holds. */
  known: HandoffRecord[];
  me: string;
  max: number;
  /** Tasks this session has already re-entered — resume must be idempotent. */
  already: ReadonlySet<string>;
}

/**
 * Decide what a resume re-enters.
 *
 * The server's list is the input, not the view's: a local record it does not
 * name is stale by definition. Stale records are reported rather than
 * rewritten — a task in a venue this reader cannot see is absent from the
 * listing for a reason that has nothing to do with who holds it, and
 * silently retiring somebody's work over an authorization gap is exactly the
 * kind of confident wrongness the whole three-way verification rule exists to
 * avoid.
 */
export function planResume(opts: ResumeOptions): ResumePlan {
  const byId = new Map(opts.known.map((r) => [r.id, r]));
  const mine = opts.serverTasks.filter(
    (t) => t.kind === HANDOFF_KIND && t.state === "assigned" && t.assignee === opts.me,
  );

  const candidates: HandoffRecord[] = [];
  let unusable = 0;
  for (const t of mine) {
    if (opts.already.has(t.id)) continue;
    const known = byId.get(t.id);
    if (known) {
      candidates.push(known);
      continue;
    }
    // Nothing local — a lost view, or work accepted from another machine. The
    // row is enough to re-enter the work, as long as it names a venue we can
    // post the lifecycle back into.
    if (!t.venue.startsWith("#")) {
      unusable++;
      continue;
    }
    candidates.push(recordFromServer(t, opts.me));
  }

  candidates.sort((a, b) => a.createdAt - b.createdAt);
  const resume = candidates.slice(0, Math.max(0, opts.max));

  const listed = new Set(mine.map((t) => t.id));
  const stale = opts.known.filter(
    (r) => r.state === "assigned" && r.assignee === opts.me && !listed.has(r.id),
  );

  return { resume, skipped: candidates.length - resume.length + unusable, stale };
}

/** A view record built from a server row, for work we have no local memory of. */
function recordFromServer(t: ServerTask, me: string): HandoffRecord {
  const at = t.updated ?? Date.now();
  return {
    id: t.id,
    kind: t.kind,
    state: t.state,
    offerer: t.offerer ?? "",
    offeree: t.offeree,
    assignee: t.assignee ?? me,
    // The listing carries no title — it was never a signed field the server
    // keeps for us — so say that plainly rather than inventing one.
    title: "(title not in the server's listing)",
    caps: t.caps,
    deadline: t.deadline,
    channel: t.venue,
    fromReplay: false,
    signed: true,
    createdAt: at,
    updatedAt: at,
    log: [],
  };
}

// ── referring to a task by the short id the notifications print ────────────

export type TaskRef =
  | { ok: true; record: HandoffRecord }
  | { ok: false; reason: string };

/**
 * Resolve the 10-character prefix our notifications print back to one task.
 *
 * An ambiguous prefix is refused by name rather than guessed: picking the
 * newest match would eventually drop, fail, or accept the wrong piece of
 * somebody's work, and the user is one keystroke from disambiguating it.
 */
export function resolveTaskRef(records: HandoffRecord[], ref: string): TaskRef {
  const needle = ref.trim();
  if (!needle) return { ok: false, reason: "no task id given" };

  const exact = records.find((r) => r.id === needle);
  if (exact) return { ok: true, record: exact };

  const lower = needle.toLowerCase();
  const hits = records.filter((r) => r.id.toLowerCase().startsWith(lower));
  if (!hits.length) return { ok: false, reason: `no task on record starts with '${needle}'` };
  if (hits.length === 1) return { ok: true, record: hits[0] };
  return {
    ok: false,
    reason:
      `'${needle}' matches ${hits.length} tasks (` +
      hits.map((r) => r.id.slice(0, 14)).join(", ") +
      `) — give more of the id`,
  };
}
