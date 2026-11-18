/**
 * What freeq-cc's mod draws, kept by the channel server and read by the mod
 * through the `freeq_ui` tool (`$.mcp.call`): the room feed, the peers, the
 * work offered and held, what waits on the owner, and the approval audit.
 *
 * The mod runs inside Claude Code with no Node and no freeq connection of its
 * own; the connection lives here. A snapshot is plain JSON, and `version`
 * moves whenever anything in it changes, so the mod redraws only on change.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { tierFor } from "@freeq/harness-kit/config";
import type { AgentRuntime } from "@freeq/harness-kit/runtime";

/** One line of room traffic: delivered to the model, shown, or sent. */
export interface FeedLine {
  /** Epoch ms. */
  at: number;
  direction: "in" | "out";
  channel: string;
  from: string;
  did?: string;
  text: string;
  /** Short dim suffix: "withheld · tier observe", "delivered". */
  note?: string;
  /** The sender's trust tier, for an inbound line. */
  tier?: string;
  /** True when the line reached the model. */
  delivered?: boolean;
}

/** A tool approval Claude Code relayed and is waiting on. */
export interface PendingApproval {
  requestId: string;
  tool: string;
  description: string;
  at: number;
}

/** An AskUserQuestion relayed to the owner and not yet answered. */
export interface PendingQuestion {
  id: string;
  question: string;
  options: string[];
  at: number;
}

/** One answer the owner gave over freeq, as recorded for audit. */
export interface ApprovalRecord {
  at: string;
  kind: "permission" | "question";
  /** The relayed request: a permission request id or a question id. */
  request: string;
  /** What was asked: the tool name, or the question. */
  subject: string;
  /** allow / deny, or the answer text. */
  answer: string;
  /** The answering message's DID as the server resolved it. */
  did: string;
  /** The answering message's id, so the signed line can be fetched again. */
  msgid?: string;
  /** The signature check on the answering message (`device`, `server`, `unsigned`, …). */
  verdict: string;
  /** The key that signed it, when it was signed. */
  kid?: string;
  /** Applied, or refused (and why). */
  applied: boolean;
  reason?: string;
}

export interface Snapshot {
  version: number;
  connection: {
    state: string;
    nick?: string;
    did?: string;
    ownerDid?: string;
    server?: string;
    lastError?: string;
    enabled: boolean;
    muted: boolean;
  };
  step?: string;
  channels: string[];
  peers: Array<{ nick: string; did?: string; state: string; doing?: string; project?: string; tier: string; isAgent: boolean }>;
  tasks: Array<{
    id: string;
    title: string;
    state: string;
    channel: string;
    from?: string;
    assignee?: string;
    /** `in`: offered to or held by this agent; `out`: offered by it. */
    side: "in" | "out";
    queued: boolean;
  }>;
  feed: FeedLine[];
  unread: number;
  approvals: PendingApproval[];
  questions: PendingQuestion[];
  audit: ApprovalRecord[];
  /** Senders whose messages to this agent the trust policy held back. */
  withheld: Array<{ key: string; from: string; did?: string; count: number; latest: number }>;
}

const FEED_MAX = 300;
const AUDIT_MAX = 50;

/** The mutable side of the snapshot: what the runtime does not keep itself. */
export class UiState {
  #version = 1;
  #feed: FeedLine[] = [];
  #readUpTo = 0;
  readonly approvals = new Map<string, PendingApproval>();
  readonly questions = new Map<string, PendingQuestion>();
  #audit: ApprovalRecord[] = [];

  constructor(private readonly auditPath: () => string) {}

  get version(): number {
    return this.#version;
  }

  /** Something the snapshot shows changed. */
  bump(): void {
    this.#version += 1;
  }

  #lastKey = "";
  /** Bump when the runtime-owned part of the picture (peers, tasks, the
   *  connection) differs from the last snapshot's: the runtime does not say. */
  noteKey(key: string): void {
    if (key === this.#lastKey) return;
    this.#lastKey = key;
    this.bump();
  }

  push(line: Omit<FeedLine, "at"> & { at?: number }): void {
    this.#feed.push({ at: Date.now(), ...line });
    if (this.#feed.length > FEED_MAX) this.#feed.splice(0, this.#feed.length - FEED_MAX);
    this.bump();
  }

  /** The person has seen the feed. */
  markRead(): void {
    this.#readUpTo = Date.now();
    this.bump();
  }

  unread(): number {
    return this.#feed.filter((l) => l.direction === "in" && l.at > this.#readUpTo).length;
  }

  feed(limit: number): FeedLine[] {
    return this.#feed.slice(-limit);
  }

  /**
   * Keep an answer the owner gave: in the snapshot, and appended as one JSON
   * line to the audit file, which outlives the session.
   */
  async record(rec: ApprovalRecord): Promise<void> {
    this.#audit.push(rec);
    if (this.#audit.length > AUDIT_MAX) this.#audit.splice(0, this.#audit.length - AUDIT_MAX);
    this.bump();
    const path = this.auditPath();
    try {
      await mkdir(dirname(path), { recursive: true });
      await appendFile(path, `${JSON.stringify(rec)}\n`, { mode: 0o600 });
    } catch {
      /* the snapshot still has it */
    }
  }

  audit(): ApprovalRecord[] {
    return [...this.#audit];
  }
}

/** The whole picture, for one `freeq_ui snapshot` call. */
export function buildSnapshot(runtime: AgentRuntime, ui: UiState, feedLimit = 80): Snapshot {
  const cfg = runtime.config;
  const conn = runtime.conn;
  const self = conn?.did;
  const queued = new Set((runtime.offers?.all() ?? []).map((o) => o.taskId));
  const store = runtime.handoffs;
  const seen = new Set<string>();
  const tasks: Snapshot["tasks"] = [];
  const add = (side: "in" | "out", recs: ReturnType<NonNullable<typeof store>["all"]>): void => {
    for (const r of recs) {
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      tasks.push({
        id: r.id,
        title: r.title,
        state: r.state,
        channel: r.channel,
        from: r.offererNick ?? r.offerer,
        assignee: r.assignee,
        side,
        queued: queued.has(r.id),
      });
    }
  };
  if (store) {
    add("in", store.inboxFor(self));
    add("out", store.outboxFor(self));
  }
  const peers = (conn?.peers() ?? []).map((p) => ({
    nick: p.nick,
    did: p.did,
    state: p.state,
    doing: p.meta.doing,
    project: p.meta.project,
    tier: cfg ? tierFor(cfg, p.did) : "observe",
    isAgent: p.isPi,
  }));
  const connection = {
      state: conn?.state ?? "offline",
      nick: conn?.nick,
      did: self,
      ownerDid: cfg?.ownerDid,
      server: cfg?.server,
      lastError: conn?.lastError,
      enabled: cfg?.enabled ?? false,
      muted: cfg?.muted ?? false,
  };
  const step = runtime.step?.phrase;
  const channels = conn?.joinedChannels() ?? [];
  const withheld = runtime.withheld.senders();
  ui.noteKey(
    JSON.stringify({ connection, step, channels, peers: peers.map((p) => [p.nick, p.state, p.doing, p.tier]), tasks, withheld: withheld.map((w) => [w.key, w.count]) }),
  );
  return {
    version: ui.version,
    connection,
    step,
    channels,
    peers,
    tasks,
    feed: ui.feed(feedLimit),
    unread: ui.unread(),
    approvals: [...ui.approvals.values()],
    questions: [...ui.questions.values()],
    audit: ui.audit(),
    withheld,
  };
}
