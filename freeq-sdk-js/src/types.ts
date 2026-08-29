/** Core types for the freeq SDK. */

/** Parsed IRC message with optional IRCv3 tags. */
export interface IRCMessage {
  tags: Record<string, string>;
  prefix: string;
  command: string;
  params: string[];
}

/** A chat message. */
export interface Message {
  id: string;
  from: string;
  text: string;
  timestamp: Date;
  tags: Record<string, string>;
  isAction?: boolean;
  isSelf?: boolean;
  isSystem?: boolean;
  replyTo?: string;
  editOf?: string;
  isStreaming?: boolean;
  deleted?: boolean;
  reactions?: Map<string, Set<string>>;
  encrypted?: boolean;
}

/** A channel or DM member. */
export interface Member {
  nick: string;
  did?: string;
  handle?: string;
  displayName?: string;
  avatarUrl?: string;
  isOp: boolean;
  isHalfop: boolean;
  isVoiced: boolean;
  away?: string | null;
  typing?: boolean;
  actorClass?: 'human' | 'agent' | 'external_agent';
}

/** A pinned message reference. */
export interface PinnedMessage {
  msgid: string;
  pinned_by: string;
  pinned_at: number;
}

/** A channel with members and messages. */
export interface Channel {
  name: string;
  topic: string;
  topicSetBy?: string;
  members: Map<string, Member>;
  messages: Message[];
  modes: Set<string>;
  isEncrypted: boolean;
  unreadCount: number;
  mentionCount: number;
  lastReadMsgId?: string;
  isJoined: boolean;
  pins: PinnedMessage[];
}

/** WHOIS information for a user. */
export interface WhoisInfo {
  nick: string;
  user?: string;
  host?: string;
  realname?: string;
  server?: string;
  did?: string;
  handle?: string;
  channels?: string;
  fetchedAt: number;
}

/** An entry in the server's channel list. */
export interface ChannelListEntry {
  name: string;
  topic: string;
  count: number;
}

/** AV session participant. */
export interface AvParticipant {
  did: string;
  nick: string;
  role: 'host' | 'speaker' | 'listener';
  joinedAt: Date;
}

/** AV (audio/video) session. */
export interface AvSession {
  id: string;
  channel: string | null;
  createdBy: string;
  createdByNick: string;
  title?: string;
  participants: Map<string, AvParticipant>;
  state: 'active' | 'ended';
  startedAt: Date;
  irohTicket?: string;
}

/** WebSocket transport state. */
export type TransportState = 'disconnected' | 'connecting' | 'connected';

/** SASL credentials for AT Protocol authentication.
 *
 * Two flavours:
 *   - Token-based (`method: "pds-session"` or `"pds-oauth"`): a PDS-
 *     issued bearer goes in `token`; the server checks it with the PDS.
 *   - Crypto / did:key (`method: "crypto"`): no token — instead, the
 *     SDK signs the challenge bytes via the `signer` callback. The
 *     server resolves `did` and verifies the signature against the
 *     advertised public key. No PDS, no OAuth, no external service.
 *     See `generateDidKey()` in `./did-key.ts`.
 */
export interface SaslCredentials {
  /** Bearer token for token-based methods. Empty when method=crypto. */
  token: string;
  did: string;
  pdsUrl: string;
  method: string;
  /** Required when `method === "crypto"`. Called on the raw challenge
   *  bytes the server emits in AUTHENTICATE. Returns base64url(sig). */
  signer?: (challengeBytes: Uint8Array) => Promise<string>;
}

/** Options for creating a FreeqClient. */
export interface FreeqClientOptions {
  /** WebSocket URL (e.g. "wss://irc.freeq.at/irc"). */
  url: string;

  /** Desired IRC nickname. */
  nick: string;

  /** Channels to auto-join on connect. */
  channels?: string[];

  /** SASL credentials for AT Protocol authentication. */
  sasl?: SaslCredentials;

  /**
   * Base URL for the auth broker (for session refresh).
   * If set along with `brokerToken`, the client refreshes
   * the web-token on each reconnect.
   */
  brokerUrl?: string;

  /** Long-lived broker token for session refresh. */
  brokerToken?: string;

  /** Server origin for API calls (e.g. E2EE key upload). Defaults to url origin. */
  serverOrigin?: string;

  /** Skip the first broker token refresh (use when token is already fresh). */
  skipInitialBrokerRefresh?: boolean;

  /** When `false`, the SDK does NOT auto-mint a session ed25519 key and
   *  send MSGSIG after SASL success. Defaults to true for backward
   *  compatibility. Useful for agents that hold their own signing key
   *  (e.g. freeqcc using its did:key seed) or for headless tests. */
  autoMsgSig?: boolean;

  /** Policy on 433 ERR_NICKNAMEINUSE during registration:
   *   - `'refuse'` (default for new code): emit `authError` and disconnect.
   *   - `'auto-suffix'`: append `_` until accepted (legacy SDK behavior).
   *   - `'random-suffix'`: append a 4-digit random suffix, up to 3 attempts.
   *  Omitted defaults to `'auto-suffix'` for backward compatibility. */
  onNickCollision?: NickCollisionPolicy;
}

/** A batch of messages (e.g. CHATHISTORY response). */
export interface Batch {
  type: string;
  target: string;
  messages: Message[];
  /**
   * `draft/multiline`-only: opener metadata (msgid, time, account,
   * client-only tags from the BATCH opener) captured so the assembled
   * message inherits the right identity. Unused for chathistory batches.
   */
  openerTags?: Record<string, string>;
  /** `draft/multiline`-only: the BATCH opener's sender (the message author). */
  openerFrom?: string;
  /**
   * `draft/multiline`-only: accumulated chunks. Each entry is one
   * PRIVMSG body plus whether the chunk carried `draft/multiline-concat`
   * (join to predecessor without separator) or not (join with `\n`).
   */
  multilineLines?: Array<{ body: string; concat: boolean }>;
  /**
   * If this batch's opener carried `batch=<parent>` (a nested batch),
   * the parent id — assembled message gets pushed into the parent's
   * `messages` instead of emitted as a top-level `message` event.
   */
  parentBatchId?: string;
  /**
   * Act TAGMSGs read inside this batch, in wire order, held so `actEvent`
   * fires after the batch's companion lines are delivered. `buffer` is the
   * thread key the handler resolved when it read the line — a channel name,
   * or a DM's canonical peer key — because at flush time the line's own
   * sender and target are no longer in hand.
   */
  actEvents?: Array<{ buffer: string; from: string; tags: Record<string, string> }>;
}

// ── Agent-native types ─────────────────────────────────────────────────────

/** Structured presence states an agent (or human) can broadcast. */
export type PresenceState =
  | 'online'
  | 'idle'
  | 'active'
  | 'executing'
  | 'waiting_for_input'
  | 'blocked_on_permission'
  | 'blocked_on_budget'
  | 'degraded'
  | 'paused'
  | 'sandboxed'
  | 'revoked'
  | 'offline';

/** Governance signal types delivered via `+freeq.at/governance=*` TAGMSG. */
export type GovernanceSignal =
  | 'pause'
  | 'resume'
  | 'revoke'
  | 'approval_granted'
  | 'approval_denied'
  | 'budget_exceeded';

/** Payload of the `governance` event. */
export interface GovernancePayload {
  signal: GovernanceSignal;
  /** Nick the signal addresses (typically us). */
  target: string;
  /** Issuer of the signal (op nick), if available. */
  by?: string;
  /** Optional human-readable detail. */
  reason?: string;
}

/** Payload of the `presence` event — someone else's PRESENCE update. */
export interface PresencePayload {
  nick: string;
  did?: string;
  state: PresenceState | string;
  status?: string;
  task?: string;
}

/** Payload of the `coordinationEvent` event — parsed `+freeq.at/event=*` TAGMSG. */
export interface CoordinationEventPayload {
  /** Channel (or DM target) the event was emitted in. */
  channel: string;
  /** Sender's nick. */
  from: string;
  /** Sender's DID, if known. */
  did?: string;
  /** Event type — e.g. `task_request`, `task_update`, `task_complete`, etc. */
  eventType: string;
  /** Stable event ID (ULID). */
  eventId: string;
  /** Threading reference — the task this event belongs to. */
  taskId?: string;
  /** Evidence subtype for `evidence_attach` events. */
  evidenceType?: string;
  /** Decoded payload JSON. `null` if no payload tag. */
  payload: unknown;
  /** Raw IRCv3 tags from the wire (for advanced consumers). */
  tags: Record<string, string>;
}

/** Payload of the `actEvent` event — parsed `act-` tagged TAGMSG. */
export interface ActEventPayload {
  /** The thread the event belongs to: a channel name, or — for a DM — the
   *  canonical peer key every other TAGMSG feature files under, never the
   *  wire target (which for an incoming DM names the recipient). */
  channel: string;
  /** Sender's nick. */
  from: string;
  /** The acting identity: the `+freeq.at/from` tag, else the account tag. */
  did?: string;
  /** The task kind — the `+freeq.at/act` value, e.g. `handoff`, `bounty`. */
  kind: string;
  /** The move — `offer`, `claim`, `progress`, `confirm`, … */
  verb: string;
  /** The signer-minted id of this event. */
  eventId: string;
  /** The task this event is about. An opener names no other, so its own id
   *  is the task's — which is why this is never empty. */
  taskId: string;
  /** Every `act-` tag on the line, keyed by its name with the vendor prefix
   *  stripped — so `+freeq.at/act-note` reads as `act-note`, and the kind
   *  itself as `act`. The signature covers exactly these, so a reader that
   *  draws a card from them draws from what was signed. */
  fields: Record<string, string>;
  /** Raw IRCv3 tags from the wire (for advanced consumers). */
  tags: Record<string, string>;
  /** The signature over the act document, if the line carried one. */
  sigTag?: string;
  /** True when this arrived from history rather than live — a replayed line
   *  carries the server's `time` tag. */
  replayed: boolean;
}

/** Payload of the `spend` event — SPEND wire command relayed by the server. */
export interface SpendPayload {
  channel: string;
  did: string;
  amount: number;
  unit: string;
  description?: string;
  taskRef?: string;
}

/** Per-period budget snapshot. */
export interface BudgetSnapshot {
  channel: string;
  policy?: {
    maxAmount: number;
    unit: string;
    period: string;
    sponsorDid: string;
  };
  currentPeriod?: {
    totalSpent: number;
    remaining: number;
    percentUsed: number;
    byAgent: Array<{ agentDid: string; spent: number; items: number }>;
  };
}

/** Payload of the `agentSpawned` event. */
export interface AgentSpawnedPayload {
  parentNick: string;
  childNick: string;
  channel: string;
  capabilities: string[];
  ttlSeconds?: number;
  taskRef?: string;
}

/** Payload of the `agentDespawned` event. */
export interface AgentDespawnedPayload {
  nick: string;
  reason?: string;
}

/** What a `historyBatch` answers: the request the client sent for that
 *  target. A batch with no matching request reports none. */
export interface HistoryBatchInfo {
  mode: 'latest' | 'before' | 'after' | 'around';
  /** The page size that was asked for. */
  count: number;
}

/** Options for `requestHistory`. */
export interface HistoryOptions {
  target: string;
  mode: 'latest' | 'before' | 'after' | 'around';
  /** Required for mode='before', 'after' or 'around' unless `timestamp` is
   *  given. Preferred over `timestamp` when both are supplied. */
  msgid?: string;
  /** ISO 8601 timestamp. The anchor used for 'before'/'after'/'around' when
   *  no `msgid` is given. Second-resolution on the server, so it cannot
   *  separate messages sent in the same second. */
  timestamp?: string;
  /** Default: 50. */
  count?: number;
}

/** Options for `emitEvent`. */
export interface EmitEventOptions {
  /** Threading reference — the task this event belongs to. */
  refId?: string;
  /** Human-readable companion text for the PRIVMSG. */
  humanText?: string;
  /** Additional IRCv3 tags to set on both the TAGMSG and PRIVMSG. */
  extraTags?: Record<string, string>;
  /** Pre-supplied event ID (ULID). If omitted, a fresh one is minted. */
  eventId?: string;
}

/** Handle returned by `startHeartbeat()`. */
export interface HeartbeatHandle {
  /** Stop the heartbeat loop. */
  stop(): void;
}

/** Policy for handling a 433 ERR_NICKNAMEINUSE during registration. */
export type NickCollisionPolicy = 'refuse' | 'auto-suffix' | 'random-suffix';

/** Configuration for the auto-reconnect loop. */
export interface ReconnectConfig {
  /** Channels to rejoin after each reconnect. */
  channels?: string[];
  /** Initial delay before first reconnect attempt (ms). Default: 2000. */
  initialDelayMs?: number;
  /** Maximum delay between attempts (ms). Default: 30000. */
  maxDelayMs?: number;
  /** Exponential backoff factor. Default: 2. */
  backoffFactor?: number;
}
