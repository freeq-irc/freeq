/**
 * Messages that were addressed to this agent and did not reach it.
 *
 * The tier gate is right to drop them: an untrusted sender must not put words
 * into a model's context. But dropping them *silently* makes two very
 * different situations look identical from the inside —
 *
 *   - nobody spoke to us, and
 *   - somebody spoke to us and we were not allowed to hear it
 *
 * — and identical from the outside too, because an ignored message and an
 * undelivered one both look like being ignored. That ambiguity cost four
 * rounds of a live debugging session: a peer's human asked repeatedly for a
 * review, the agent sat mute, and the owner had to ask why. The gate was
 * working exactly as designed and nobody could tell.
 *
 * So: hold what we refused, bounded, and be able to say who is waiting. When
 * the owner promotes a sender, the held messages can be delivered rather than
 * asking the sender to repeat themselves — a repeat is a second chance to be
 * misunderstood, and the sender has already done their part.
 *
 * This is a buffer, not a queue with delivery semantics: it is in-memory,
 * capped, and lossy by design. Losing a withheld message is fine. Losing the
 * *fact* that messages were withheld is not, which is why the counts are what
 * the UI reads.
 */

export interface WithheldMessage {
  /** Sender's server-resolved DID, when they had one. Undefined for guests. */
  did?: string;
  /** Display nick at the time. Never used for authorisation — only display. */
  from: string;
  channel: string;
  text: string;
  /** Why it was held, in the words the UI will show. */
  reason: string;
  at: number;
}

/** Per-sender cap. A sender who floods should not evict everyone else. */
export const MAX_PER_SENDER = 20;
/** Total cap across all senders. */
export const MAX_TOTAL = 200;
/** Nothing older than this is worth delivering unasked. */
export const MAX_AGE_MS = 24 * 60 * 60 * 1000;

/** Key a sender by DID when they have one, else by nick with a marker. */
export function senderKey(m: Pick<WithheldMessage, "did" | "from">): string {
  return m.did ?? `nick:${m.from.toLowerCase()}`;
}

export class WithheldBuffer {
  #items: WithheldMessage[] = [];

  constructor(private readonly now: () => number = Date.now) {}

  add(m: WithheldMessage): void {
    this.#items.push(m);
    this.#prune();
  }

  /** Everything still held, newest last. */
  all(): WithheldMessage[] {
    this.#prune();
    return [...this.#items];
  }

  /** How many are held, total. */
  get size(): number {
    this.#prune();
    return this.#items.length;
  }

  /**
   * One line per distinct sender: who, how many, and how recently.
   *
   * Grouped by sender because the actionable unit is a *person* — the owner
   * promotes a sender, not a message.
   */
  senders(): Array<{ key: string; from: string; did?: string; count: number; latest: number }> {
    const by = new Map<string, { key: string; from: string; did?: string; count: number; latest: number }>();
    for (const m of this.all()) {
      const key = senderKey(m);
      const cur = by.get(key);
      if (cur) {
        cur.count += 1;
        cur.latest = Math.max(cur.latest, m.at);
        // Prefer the most recent display nick; nicks change, DIDs do not.
        if (m.at >= cur.latest) cur.from = m.from;
      } else {
        by.set(key, { key, from: m.from, did: m.did, count: 1, latest: m.at });
      }
    }
    return [...by.values()].sort((a, b) => b.latest - a.latest);
  }

  /**
   * Remove and return everything held for a sender.
   *
   * Draining is the point: once delivered they must not be delivered again,
   * and once declined they should not linger as a reproach.
   */
  drain(key: string): WithheldMessage[] {
    this.#prune();
    const out = this.#items.filter((m) => senderKey(m) === key);
    this.#items = this.#items.filter((m) => senderKey(m) !== key);
    return out;
  }

  /** Drop everything for a sender without returning it. */
  discard(key: string): number {
    const before = this.#items.length;
    this.#items = this.#items.filter((m) => senderKey(m) !== key);
    return before - this.#items.length;
  }

  #prune(): void {
    const cutoff = this.now() - MAX_AGE_MS;
    this.#items = this.#items.filter((m) => m.at >= cutoff);

    // Per-sender cap: keep the newest, since an old withheld message is the
    // least likely to still be worth answering.
    const counts = new Map<string, number>();
    const kept: WithheldMessage[] = [];
    for (let i = this.#items.length - 1; i >= 0; i--) {
      const m = this.#items[i]!;
      const k = senderKey(m);
      const n = (counts.get(k) ?? 0) + 1;
      if (n <= MAX_PER_SENDER) {
        counts.set(k, n);
        kept.push(m);
      }
    }
    kept.reverse();
    this.#items = kept.length > MAX_TOTAL ? kept.slice(kept.length - MAX_TOTAL) : kept;
  }
}

/**
 * The line the UI shows when somebody is waiting.
 *
 * Deliberately names the remedy. A notice that reports a problem without the
 * command that fixes it is a notice that gets ignored twice.
 */
export function withheldSummary(
  senders: ReturnType<WithheldBuffer["senders"]>,
): string | undefined {
  if (!senders.length) return undefined;
  const head = senders[0]!;
  const total = senders.reduce((n, s) => n + s.count, 0);
  const who =
    senders.length === 1
      ? `${head.from}`
      : `${head.from} and ${senders.length - 1} other${senders.length === 2 ? "" : "s"}`;
  return (
    `${total} message${total === 1 ? "" : "s"} addressed to you from ${who} ` +
    `were not delivered (sender not trusted). ` +
    `/freeq trust ${head.did ?? head.from} message — then /freeq withheld deliver`
  );
}
