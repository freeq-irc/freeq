/**
 * The owner relay: what this session asks its owner over freeq, and how the
 * owner's answers are checked before they count.
 *
 * Two kinds of question go out by DM to the owner's DID:
 *
 *   - tool approvals Claude Code relays to the channel (`yes <id>` / `no <id>`)
 *   - AskUserQuestion dialogs the mod holds (`q<id> <answer>`)
 *
 * An answer counts only from the owner's DID as the server resolved it, in a
 * DM, and, under the default `device` policy, only when the message carries a
 * signature made with one of the owner's own device keys. A server-relayed or
 * unsigned message is refused, and the owner is told why: an approval is a
 * signed, attributable record, not a line anyone holding the session's nick
 * could type. Every answer, applied or refused, is kept in the audit log.
 */

import { KeyLookup, makeDidResolver, verifyLine, type Verdict } from "@freeq/sdk";

import type { ApprovalRecord, UiState } from "./ui-state.js";

/** `device`: only a device-key signature counts. `any`: the server's word on the DID is enough. */
export type SignaturePolicy = "device" | "any";

/** When an AskUserQuestion goes to the owner. */
export type QuestionRelay = "off" | "freeq-turns" | "always";

/**
 * A reply to a relayed tool-approval prompt: `yes <id>` or `no <id>`. The id
 * is five lowercase letters without `l`, as Claude Code makes them; case is
 * ignored because phones capitalise.
 */
export const VERDICT = /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i;

/** A reply to a relayed question: `q<id> <answer>`. */
export const QUESTION_REPLY = /^\s*q([a-km-z]{5})\s+([\s\S]+?)\s*$/i;

/** One question of an AskUserQuestion call, as much of it as the relay reads. */
export interface RelayQuestion {
  question: string;
  header?: string;
  multiSelect?: boolean;
  options?: Array<{ label: string; description?: string }>;
}

export type QuestionOutcome =
  | { state: "answered"; answers: Record<string, string>; record: ApprovalRecord }
  | { state: "cancelled" }
  | { state: "pending" };

export interface InboundReply {
  channel: string;
  from: string;
  did: string | null;
  text: string;
  msgid?: string;
  tags?: Record<string, string>;
}

export interface RelayOptions {
  ownerDid: string;
  policy: SignaturePolicy;
  ui: UiState;
  /** DM the owner. False when not connected. */
  send(text: string): boolean;
  /** This session's DID, for rebuilding a DM's signed venue. */
  ownDid(): string | undefined;
  /** The freeq server's websocket URL, for its key set. */
  server(): string | undefined;
  /** Apply a tool-approval verdict in Claude Code. */
  applyPermission(requestId: string, behavior: "allow" | "deny"): void;
  log(line: string): void;
}

const ID_ALPHABET = "abcdefghijkmnopqrstuvwxyz";

function newId(): string {
  let id = "";
  for (let i = 0; i < 5; i++) id += ID_ALPHABET[Math.floor(Math.random() * ID_ALPHABET.length)];
  return id;
}

/** `wss://host/irc` → `https://host`, the origin the key set is served from. */
export function httpOrigin(server: string | undefined): string | null {
  if (!server) return null;
  try {
    const u = new URL(server);
    const scheme = u.protocol === "ws:" ? "http:" : "https:";
    return `${scheme}//${u.host}`;
  } catch {
    return null;
  }
}

/** Read an owner's answer against the question's options: `2` picks the second, a label picks itself. */
export function readAnswer(q: RelayQuestion, raw: string): string {
  const opts = q.options ?? [];
  const parts = q.multiSelect ? raw.split(/\s*,\s*/) : [raw];
  const picked = parts.map((p) => {
    const n = /^\d+$/.test(p) ? Number(p) : NaN;
    if (n >= 1 && n <= opts.length) return opts[n - 1]!.label;
    const byLabel = opts.find((o) => o.label.toLowerCase() === p.toLowerCase());
    return byLabel ? byLabel.label : p;
  });
  return picked.join(", ");
}

/** The DM a relayed question goes out as. */
export function questionText(id: string, questions: RelayQuestion[]): string {
  const lines = ["Claude needs an answer from you:"];
  questions.forEach((q, i) => {
    lines.push(`${questions.length > 1 ? `${i + 1}. ` : ""}${q.question}${q.multiSelect ? " (pick any, comma-separated)" : ""}`);
    (q.options ?? []).forEach((o, j) => lines.push(`   ${j + 1}) ${o.label}${o.description ? ` — ${o.description}` : ""}`));
  });
  lines.push(
    questions.length > 1
      ? `Reply "q${id} <answer 1> | <answer 2> …" — a number picks an option, or write your own.`
      : `Reply "q${id} <answer>" — a number picks an option, or write your own.`,
  );
  return lines.join("\n");
}

interface OpenQuestion {
  id: string;
  questions: RelayQuestion[];
  outcome: QuestionOutcome;
  waiters: Array<() => void>;
}

export class OwnerRelay {
  readonly #o: RelayOptions;
  #lookup: KeyLookup | undefined;
  #lookupOrigin: string | null = null;
  readonly #open = new Map<string, OpenQuestion>();
  /** Tool approvals Claude Code relayed and has not seen answered, by id. */
  readonly #permissions = new Map<string, { tool: string }>();

  constructor(opts: RelayOptions) {
    this.#o = opts;
  }

  get ownerDid(): string {
    return this.#o.ownerDid;
  }

  #keys(): KeyLookup {
    const origin = httpOrigin(this.#o.server());
    if (!this.#lookup || origin !== this.#lookupOrigin) {
      this.#lookupOrigin = origin;
      this.#lookup = new KeyLookup(
        { fetch: (target, init) => fetch(target, init), resolveDid: makeDidResolver() },
        origin,
        60 * 60 * 1000,
      );
    }
    return this.#lookup;
  }

  /** The signature verdict on an inbound DM. */
  async verdictOf(m: InboundReply): Promise<Verdict> {
    if (!m.tags) return { state: "unsigned" };
    try {
      return await verifyLine({ tags: m.tags, target: m.channel, body: m.text, ownDid: this.#o.ownDid() }, this.#keys());
    } catch {
      return { state: "unverifiable" };
    }
  }

  /** Does this verdict let an answer count, and if not, why not. */
  #counts(v: Verdict): { ok: boolean; reason?: string } {
    if (this.#o.policy === "any") return { ok: true };
    if (v.state === "device") return { ok: true };
    const why: Record<string, string> = {
      server: "it was signed by the server, not by one of your devices",
      unsigned: "it carried no signature",
      unverifiable: "its signature could not be checked right now",
      invalid: "its signature did not verify",
      retired: "it was signed with a retired key",
      pending: "its signature check did not finish",
    };
    return { ok: false, reason: why[v.state] ?? `its signature verdict was ${v.state}` };
  }

  // ── tool approvals ──────────────────────────────────────────────────────

  /** Claude Code relayed a tool-approval prompt; send it to the owner. */
  relayPermission(p: { request_id: string; tool_name: string; description: string; input_preview: string }): boolean {
    const preview = p.input_preview.length > 600 ? `${p.input_preview.slice(0, 600)}…` : p.input_preview;
    this.#permissions.set(p.request_id, { tool: p.tool_name });
    this.#o.ui.approvals.set(p.request_id, {
      requestId: p.request_id,
      tool: p.tool_name,
      description: p.description,
      at: Date.now(),
    });
    this.#o.ui.bump();
    const sign = this.#o.policy === "device" ? " (from a client that signs your messages)" : "";
    return this.#o.send(
      `Claude wants to use ${p.tool_name}: ${p.description}\n${preview}\n` +
        `Reply "yes ${p.request_id}" or "no ${p.request_id}"${sign}`,
    );
  }

  /** A verdict decided locally (or elsewhere) closes the pending entry. */
  forgetPermission(requestId: string): void {
    this.#permissions.delete(requestId);
    if (this.#o.ui.approvals.delete(requestId)) this.#o.ui.bump();
  }

  /**
   * The tool call went ahead or the response ended: whatever was pending was
   * answered at the terminal. A late answer from the owner then matches no
   * open request, and Claude Code drops it.
   */
  clearPermissions(): void {
    if (!this.#permissions.size && !this.#o.ui.approvals.size) return;
    this.#permissions.clear();
    this.#o.ui.approvals.clear();
    this.#o.ui.bump();
  }

  // ── questions ───────────────────────────────────────────────────────────

  /** Send a question to the owner; its id, or undefined when it could not go. */
  ask(questions: RelayQuestion[]): string | undefined {
    let id = newId();
    while (this.#open.has(id)) id = newId();
    if (!this.#o.send(questionText(id, questions))) return undefined;
    this.#open.set(id, { id, questions, outcome: { state: "pending" }, waiters: [] });
    this.#o.ui.questions.set(id, {
      id,
      question: questions.map((q) => q.question).join(" · "),
      options: questions.flatMap((q) => (q.options ?? []).map((o) => o.label)),
      at: Date.now(),
    });
    this.#o.ui.bump();
    return id;
  }

  /** Wait up to `ms` for a question's outcome. */
  async wait(id: string, ms: number): Promise<QuestionOutcome> {
    const q = this.#open.get(id);
    if (!q) return { state: "cancelled" };
    if (q.outcome.state !== "pending") return this.#settle(q);
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, ms);
      q.waiters.push(() => {
        clearTimeout(t);
        resolve();
      });
    });
    return q.outcome.state === "pending" ? q.outcome : this.#settle(q);
  }

  #settle(q: OpenQuestion): QuestionOutcome {
    this.#open.delete(q.id);
    if (this.#o.ui.questions.delete(q.id)) this.#o.ui.bump();
    return q.outcome;
  }

  #finish(q: OpenQuestion, outcome: QuestionOutcome): void {
    q.outcome = outcome;
    for (const w of q.waiters.splice(0)) w();
  }

  /** The person answers at the terminal instead: stop waiting on the owner. */
  cancel(id: string): boolean {
    const q = this.#open.get(id);
    if (!q) return false;
    this.#finish(q, { state: "cancelled" });
    if (q.waiters.length === 0) this.#settle(q);
    this.#o.send(`(q${id} was answered at the terminal; no need to reply.)`);
    return true;
  }

  // ── inbound ─────────────────────────────────────────────────────────────

  /**
   * An inbound message, before the gate: true when it is an answer the relay
   * takes (it is then never delivered to the model). Checking the signature
   * is asynchronous, so the answer is applied, or refused, shortly after.
   */
  intercept(m: InboundReply): boolean {
    if (m.did !== this.#o.ownerDid) return false;
    if (m.channel.startsWith("#") || m.channel.startsWith("&")) return false;
    const verdict = VERDICT.exec(m.text);
    if (verdict) {
      const requestId = verdict[2]!.toLowerCase();
      const behavior = verdict[1]!.toLowerCase().startsWith("y") ? "allow" : "deny";
      void this.#onPermission(m, requestId, behavior);
      return true;
    }
    const reply = QUESTION_REPLY.exec(m.text);
    if (reply) {
      const q = this.#open.get(reply[1]!.toLowerCase());
      if (!q) return false;
      void this.#onAnswer(m, q, reply[2]!);
      return true;
    }
    return false;
  }

  async #onPermission(m: InboundReply, requestId: string, behavior: "allow" | "deny"): Promise<void> {
    const v = await this.verdictOf(m);
    const { ok, reason } = this.#counts(v);
    const tool = this.#permissions.get(requestId)?.tool ?? "a tool";
    // Applied before the audit line is written: the session waits on it.
    if (ok) this.#o.applyPermission(requestId, behavior);
    await this.#o.ui.record({
      at: new Date().toISOString(),
      kind: "permission",
      request: requestId,
      subject: tool,
      answer: behavior,
      did: m.did!,
      msgid: m.msgid,
      verdict: v.state,
      kid: v.kid,
      applied: ok,
      reason,
    });
    if (!ok) {
      this.#o.send(`Not applied: "${behavior === "allow" ? "yes" : "no"} ${requestId}" did not count because ${reason}. Answer at the terminal, or from a client that signs your messages.`);
      return;
    }
    this.forgetPermission(requestId);
    this.#o.send(`${behavior === "allow" ? "✓ allowed" : "✗ denied"} ${tool} (${v.state === "device" ? `signed by your device key ${v.kid ?? ""}`.trim() : `verdict: ${v.state}`}${m.msgid ? `, msgid ${m.msgid}` : ""})`);
  }

  async #onAnswer(m: InboundReply, q: OpenQuestion, raw: string): Promise<void> {
    const v = await this.verdictOf(m);
    const { ok, reason } = this.#counts(v);
    const parts = q.questions.length > 1 ? raw.split(/\s*\|\s*/) : [raw];
    const answers: Record<string, string> = {};
    q.questions.forEach((qq, i) => {
      const a = parts[i];
      if (a && a.trim()) answers[qq.question] = readAnswer(qq, a.trim());
    });
    const record: ApprovalRecord = {
      at: new Date().toISOString(),
      kind: "question",
      request: q.id,
      subject: q.questions.map((x) => x.question).join(" · "),
      answer: Object.values(answers).join(" | "),
      did: m.did!,
      msgid: m.msgid,
      verdict: v.state,
      kid: v.kid,
      applied: ok,
      reason,
    };
    if (ok) this.#finish(q, { state: "answered", answers, record });
    await this.#o.ui.record(record);
    if (!ok) {
      this.#o.send(`Not applied: your answer to q${q.id} did not count because ${reason}. Answer at the terminal, or from a client that signs your messages.`);
      return;
    }
    this.#o.send(`✓ answer to q${q.id} passed to Claude`);
  }
}
