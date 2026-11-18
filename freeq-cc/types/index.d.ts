/**
 * The freeq mod's state contract: what `hooks/register.tsx` keeps in
 * `$.state`, and the shape of the snapshot it reads from the channel server's
 * `freeq_ui` tool (`src/ui-state.ts`, `Snapshot`, is the authority; this is
 * the part the mod draws).
 */

export type FeedLine = {
  at: number;
  direction: "in" | "out";
  channel: string;
  from: string;
  did?: string;
  text: string;
  note?: string;
  tier?: string;
  delivered?: boolean;
};

export type Task = {
  id: string;
  title: string;
  state: string;
  channel: string;
  from?: string;
  assignee?: string;
  side: "in" | "out";
  queued: boolean;
};

export type AuditRecord = {
  at: string;
  kind: "permission" | "question";
  request: string;
  subject: string;
  answer: string;
  did: string;
  msgid?: string;
  verdict: string;
  kid?: string;
  applied: boolean;
  reason?: string;
};

export type Snap = {
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
  tasks: Task[];
  feed: FeedLine[];
  unread: number;
  approvals: Array<{ requestId: string; tool: string; description: string; at: number }>;
  questions: Array<{ id: string; question: string; options: string[]; at: number }>;
  audit: AuditRecord[];
  /** Senders whose messages to this agent were held back by the trust policy. */
  withheld?: Array<{ key: string; from: string; did?: string; count: number; latest: number }>;
};

/** Which tab the pane shows. */
export type View = "feed" | "peers" | "work" | "audit";

/** An AskUserQuestion the mod is holding while the owner is asked on freeq. */
export type Held = { id: string; question: string };

declare module "claude-code" {
  interface PluginState {
    freeq: {
      snap: Shaped<Snap | null>;
      view: View;
      held: Held | null;
    };
  }
}
