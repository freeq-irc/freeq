/**
 * `ask` — RPC-shaped request/reply between agents.
 *
 * Decided in the design doc: `ask` gets an application-level contract from
 * day one — an explicit caller-minted request id, a timeout, and an
 * exactly-one-response rule. It must NOT hang its semantics on IRC reply
 * tags; those may represent the relationship for human clients, but
 * correctness never depends on them.
 *
 * Wire: rides the `+freeq.at/event=*` coordination-event channel (same
 * substrate as discovery), so no SDK or server change is needed.
 *
 *   pi_ask        payload { req, q }
 *   pi_ask_reply  payload { req, a, err? }
 */

import { randomUUID } from "node:crypto";

export const PI_ASK = "pi_ask";
export const PI_ASK_REPLY = "pi_ask_reply";

/** Server line limit is 8192 incl. tags; leave generous headroom. */
export const MAX_ENCODED_PAYLOAD = 6000;
export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_TIMEOUT_MS = 600_000;

export interface AskRequest {
  req: string;
  q: string;
}
export interface AskReply {
  req: string;
  a?: string;
  err?: string;
}

export function newRequestId(): string {
  return randomUUID();
}

/**
 * Encode a payload, truncating `text` until the percent-encoded form fits.
 *
 * Percent-encoding can triple the size of non-ASCII text, so budgeting on
 * raw length alone is wrong — we measure the encoded form and shrink.
 */
export function encodePayload(
  obj: Record<string, unknown>,
  textKey: string,
  limit = MAX_ENCODED_PAYLOAD,
): { encoded: string; truncated: boolean } {
  let text = typeof obj[textKey] === "string" ? (obj[textKey] as string) : "";
  let truncated = false;
  const enc = (o: unknown) => encodeURIComponent(JSON.stringify(o));

  let encoded = enc(obj);
  while (encoded.length > limit && text.length > 0) {
    truncated = true;
    // Shrink proportionally to the overshoot, with a floor so we converge.
    const overshoot = encoded.length / limit;
    const next = Math.max(0, Math.floor(text.length / Math.max(overshoot, 1.1)) - 16);
    text = text.slice(0, next);
    encoded = enc({ ...obj, [textKey]: text ? `${text}\n…[truncated]` : "…[truncated]" });
  }
  return { encoded, truncated };
}

export function parseAskRequest(raw: unknown): AskRequest | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.req !== "string" || !o.req) return undefined;
  if (typeof o.q !== "string" || !o.q.trim()) return undefined;
  return { req: o.req.slice(0, 128), q: o.q.slice(0, 8000) };
}

export function parseAskReply(raw: unknown): AskReply | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.req !== "string" || !o.req) return undefined;
  return {
    req: o.req.slice(0, 128),
    a: typeof o.a === "string" ? o.a.slice(0, 8000) : undefined,
    err: typeof o.err === "string" ? o.err.slice(0, 500) : undefined,
  };
}

interface Pending {
  req: string;
  /** Nick we sent to — a reply from anyone else is rejected. */
  to: string;
  settled: boolean;
  timer: NodeJS.Timeout;
  resolve: (value: AskResult) => void;
}

export interface AskResult {
  ok: boolean;
  answer?: string;
  error?: string;
  /** Nick that actually answered. */
  from?: string;
}

/**
 * Tracks outstanding asks and enforces the exactly-one-response contract.
 *
 * Late duplicates, replies from the wrong peer, and replies for unknown ids
 * are all dropped and reported via `onDrop` rather than silently ignored —
 * silent drops here would be indistinguishable from bugs.
 */
export class AskRegistry {
  #pending = new Map<string, Pending>();
  #onDrop?: (reason: string) => void;

  constructor(onDrop?: (reason: string) => void) {
    this.#onDrop = onDrop;
  }

  get size(): number {
    return this.#pending.size;
  }

  /** Register an outstanding ask. Resolves on reply, timeout, or cancel. */
  create(req: string, to: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<AskResult> {
    const ms = Math.min(Math.max(1_000, timeoutMs), MAX_TIMEOUT_MS);
    return new Promise<AskResult>((resolve) => {
      const timer = setTimeout(() => {
        const p = this.#pending.get(req);
        if (!p || p.settled) return;
        p.settled = true;
        this.#pending.delete(req);
        resolve({
          ok: false,
          error: `no reply from ${to} within ${Math.round(ms / 1000)}s`,
        });
      }, ms);
      timer.unref?.();
      this.#pending.set(req, { req, to, settled: false, timer, resolve });
    });
  }

  /**
   * Deliver a reply. Returns true if it settled a pending ask.
   *
   * Enforces: known id, not already settled, and the responder is the peer we
   * asked (nick-insensitive). A third party must not be able to answer
   * someone else's question.
   */
  deliver(reply: AskReply, from: string): boolean {
    const p = this.#pending.get(reply.req);
    if (!p) {
      this.#onDrop?.(`reply for unknown/expired request ${reply.req} from ${from}`);
      return false;
    }
    if (p.settled) {
      this.#onDrop?.(`duplicate reply for ${reply.req} from ${from} (already answered)`);
      return false;
    }
    if (p.to.toLowerCase() !== from.toLowerCase()) {
      this.#onDrop?.(`reply for ${reply.req} came from ${from}, expected ${p.to} — dropped`);
      return false;
    }
    p.settled = true;
    clearTimeout(p.timer);
    this.#pending.delete(reply.req);
    p.resolve(
      reply.err
        ? { ok: false, error: reply.err, from }
        : { ok: true, answer: reply.a ?? "", from },
    );
    return true;
  }

  /** Fail everything outstanding (disconnect / shutdown). */
  cancelAll(reason: string): void {
    for (const p of [...this.#pending.values()]) {
      if (p.settled) continue;
      p.settled = true;
      clearTimeout(p.timer);
      p.resolve({ ok: false, error: reason });
    }
    this.#pending.clear();
  }
}
