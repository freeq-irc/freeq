/**
 * What the kit needs from an agent harness (pi, Claude Code, …).
 *
 * The runtime (`runtime.ts`) holds freeq's behaviour: which inbound messages
 * reach the model and how they are framed, replies, presence, handoffs,
 * resume. A harness supplies only the handful of things that differ between
 * hosts: how a message is put in front of the model, how the person is told
 * or asked something, where state lives, and what the model and session are
 * doing right now. Everything optional is presentation.
 */

import type { Tier } from "./config.js";
import type { DoctorLine } from "./doctor.js";
import type { TaskNote } from "./journal.js";
import type { RoomLineInput } from "./ui.js";

/** What a delivered message says about itself, for a transcript card. */
export interface InboundCard {
  kind: "chat" | "ask";
  channel: string;
  from: string;
  did: string | null;
  tier: Tier;
  text: string;
  /** The gate's reason for delivering it. */
  reason: string;
  /** True when a reply over freeq is owed for it. */
  expectsReply: boolean;
}

/** One gated, framed message for the model. */
export interface Delivery {
  /** The framed text the model reads (`frameInbound`'s output). */
  content: string;
  /**
   * True for addressed input at `request` tier and up: deliver it at the next
   * break in the current run (pi's `steer`) rather than after the run ends
   * (`followUp`). A harness with one queue may ignore it.
   */
  interrupt: boolean;
  card: InboundCard;
}

export type NoticeLevel = "info" | "warning" | "error";

export interface Harness {
  /**
   * The harness's short name: identity and nick prefix, the discovery
   * hello's `agent`, and the word for a session in text. Default "pi".
   */
  readonly name?: string;
  /** How the person runs a subcommand, for text the kit prints. Default `/freeq <sub>`. */
  commandHint?(sub: string): string;
  /** Directory for freeq.json, the handoff store, the offer queue and the lock. */
  readonly agentDir: string;
  /** The harness's per-project config directory name (pi: `.pi`). */
  readonly configDirName: string;
  /** May the project-level config be read? */
  projectTrusted(): boolean;
  /** The session's working directory. */
  cwd(): string;
  /** The model in use, if the harness knows it. */
  modelId(): string | undefined;

  /** Put one message in front of the model. Throws if it cannot. */
  deliver(msg: Delivery): void;
  /** Tell the person something. */
  notify(text: string, level: NoticeLevel): void;
  /** Ask the person yes or no. Resolves false if it cannot ask. */
  confirm(title: string, body: string): Promise<boolean>;
  /** Is the model idle right now? */
  isIdle(): boolean;

  /** The task journal: breadcrumbs that let a restarted session resume. */
  journal: {
    append(note: TaskNote): void;
    read(taskId: string): TaskNote[];
  };

  /**
   * A room message worth showing but not delivering (`direction: "in"`), or
   * something this agent posted (`direction: "out"`).
   */
  roomLine?(input: RoomLineInput): void;
  /** Something the footer, title or offer card shows has changed. */
  stateChanged?(): void;
  /** The connection came online (the first connect or a reconnect). */
  connected?(): void;
  /** A new presence step began, with this phrase. */
  stepBegan?(phrase: string): void;
  /**
   * Show the peer roster: one line per peer, with each peer's DID for
   * colouring. Without it, the roster is sent as a notice.
   */
  roster?(title: string, lines: string[], dids: Array<string | undefined>): void;
  /**
   * A message the harness takes for itself instead of the model, such as a
   * tool-approval verdict. Called for every inbound chat message, with the
   * sender's server-resolved DID, before the gate; `true` means taken: it
   * is not delivered and no reply is owed for it.
   */
  intercept?(msg: { channel: string; from: string; did: string | null; text: string }): boolean;
  /**
   * The harness's own lines for `/freeq doctor`, after the kit's common
   * checks: what only the harness knows about its setup.
   */
  doctorLines?(): Promise<DoctorLine[]>;
}
