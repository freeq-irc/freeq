/**
 * Typed event emitter for the freeq SDK.
 *
 * Usage:
 *   client.on('message', (channel, message) => { ... });
 *   client.off('message', handler);
 *   client.once('connected', () => { ... });
 */

import type {
  Message, Member, Channel, WhoisInfo, ChannelListEntry,
  AvSession, TransportState, PinnedMessage,
  GovernancePayload, PresencePayload, CoordinationEventPayload,
  SpendPayload, BudgetSnapshot, AgentSpawnedPayload, AgentDespawnedPayload,
} from './types.js';

/** Map of event names to their handler signatures. */
export interface FreeqEvents {
  /** Fired when connection state changes. */
  connectionStateChanged: (state: TransportState) => void;

  /** Fired after successful IRC registration (001). */
  registered: (nick: string) => void;

  /** Fired when our nick changes (server-assigned or NICK command). */
  nickChanged: (nick: string) => void;

  /** Fired on successful SASL authentication. */
  authenticated: (did: string, message: string) => void;

  /** Fired on SASL authentication failure. */
  authError: (error: string) => void;

  /** Fired when a new message arrives in a channel or DM. */
  message: (channel: string, message: Message) => void;

  /** Fired when a message is edited. */
  messageEdited: (channel: string, originalMsgId: string, newText: string, newMsgId?: string, isStreaming?: boolean, editorNick?: string, editorAccount?: string) => void;

  /** Fired when a message is deleted. Deleter identity lets receivers
   *  enforce authorship in unpersisted (guest) threads, where the server
   *  relays without a row to check. */
  messageDeleted: (channel: string, msgId: string, deleterNick?: string, deleterAccount?: string) => void;

  /** IRCv3 FAIL from the server ("COMMAND ERROR_CODE description") — render
   *  it; silent rejections are indistinguishable from client bugs. */
  serverFail: (text: string) => void;

  /** Fired when a reaction is added. */
  reactionAdded: (channel: string, msgId: string, emoji: string, fromNick: string) => void;

  /** Fired when a reaction is removed. */
  reactionRemoved: (channel: string, msgId: string, emoji: string, fromNick: string) => void;

  /** Fired when we join a channel. */
  channelJoined: (channel: string) => void;

  /** Fired when we leave a channel. */
  channelLeft: (channel: string) => void;

  /** Fired when a member joins a channel. */
  memberJoined: (channel: string, member: Partial<Member> & { nick: string }) => void;

  /** Fired when a member leaves a channel. */
  memberLeft: (channel: string, nick: string) => void;

  /** Fired when a user quits (leaves all channels). */
  userQuit: (nick: string, reason: string) => void;

  /** Fired when a user changes nick. */
  userRenamed: (oldNick: string, newNick: string) => void;

  /** Fired when a user's away status changes. */
  userAway: (nick: string, reason: string | null) => void;

  /**
   * Fired when a read marker is set or reported for a target (IRCv3
   * `draft/read-marker`). Delivered both as the reply to our own
   * `markRead`/`getReadMarker` and when another of our devices advances the
   * marker. `timestamp` is an ISO 8601 string (as in server-time), or `null`
   * when the server reports no marker (`MARKREAD <target> *`).
   */
  readMarker: (target: string, timestamp: string | null) => void;

  /** Fired when a user starts/stops typing. */
  typing: (channel: string, nick: string, isTyping: boolean) => void;

  /** Fired when a channel topic changes. */
  topicChanged: (channel: string, topic: string, setBy?: string) => void;

  /** Fired when a channel mode changes. */
  modeChanged: (channel: string, mode: string, arg: string | undefined, setBy: string) => void;

  /** Fired for each NAMES (353) line — incremental, additive. */
  membersList: (channel: string, members: Array<Partial<Member> & { nick: string }>) => void;

  /** Fired once at end-of-NAMES (366) with the FULL accumulated roster for a
   *  channel. Consumers should REPLACE the channel's member set with this — it
   *  is the server's authoritative roster, so a self-JOIN clear, nick
   *  collision, or reconnect can never leave the list half-populated. */
  membersSync: (channel: string, members: Array<Partial<Member> & { nick: string }>) => void;

  /** Fired when a member's DID is discovered (via WHOIS). */
  memberDid: (nick: string, did: string) => void;

  /** Fired when WHOIS info is updated. */
  whois: (nick: string, info: Partial<WhoisInfo>) => void;

  /** Fired when the server has finished answering a WHOIS — 318
   *  (RPL_ENDOFWHOIS), or 401 (ERR_NOSUCHNICK) for a name nobody holds.
   *  Without it a caller cannot tell "the answer named no account" from
   *  "no answer yet", and the only alternative is a timer that guesses. */
  whoisEnd: (nick: string) => void;

  /** Fired when a MOTD line is received. */
  motd: (line: string) => void;

  /** Fired when a system/server message should be displayed. */
  systemMessage: (target: string, text: string) => void;

  /** Fired when a CHATHISTORY batch completes. */
  historyBatch: (channel: string, messages: Message[]) => void;

  /** Fired when a DM target is discovered (CHATHISTORY TARGETS). */
  dmTarget: (nick: string) => void;

  /** Fired when the channel list response arrives. */
  channelListEntry: (entry: ChannelListEntry) => void;

  /** Fired when channel list is complete. */
  channelListEnd: () => void;

  /** Fired when pins are fetched for a channel. */
  pins: (channel: string, pins: PinnedMessage[]) => void;

  /** Fired when a single pin is added. */
  pinAdded: (channel: string, msgid: string, pinnedBy: string) => void;

  /** Fired when a pin is removed. */
  pinRemoved: (channel: string, msgid: string) => void;

  /** Fired when an AV session state changes. */
  avSessionUpdate: (session: AvSession) => void;

  /** Fired when an AV session is removed. */
  avSessionRemoved: (sessionId: string) => void;

  /** Fired when an AV ticket is received. */
  avTicket: (sessionId: string, ticket: string) => void;

  /** Fired when a MoQ access token for an AV session is received
   *  (`+freeq.at/av-token`). Append to the SFU dial URL as `?jwt=…`. */
  avToken: (sessionId: string, token: string) => void;

  /** Fired when the server rejects an AV request (`+freeq.at/av-error`).
   *  `code` is machine-readable: `join-failed` (tear down local call state —
   *  we were NOT admitted), `start-collision` (our av-start lost a race;
   *  `sessionId` names the winning session to join instead). */
  avError: (code: string, sessionId: string, reason: string) => void;

  /** Fired when the join gate (policy acceptance) is required. */
  joinGateRequired: (channel: string) => void;

  /** Fired when a user is kicked from a channel. */
  userKicked: (channel: string, kicked: string, by: string, reason: string) => void;

  /** Fired when we are invited to a channel. */
  invited: (channel: string, by: string) => void;

  /** Fired on raw IRC lines (for debugging/extensions). */
  raw: (line: string, parsed: import('./types.js').IRCMessage) => void;

  /** Fired when MOTD is starting (for clearing previous). */
  motdStart: () => void;

  /** Fired when members list is cleared (before new NAMES). */
  membersCleared: (channel: string) => void;

  /** Fired when the server connection is fully ready (001 + channels joined). */
  ready: () => void;

  /** Fired when an ERROR message is received from the server. */
  error: (message: string) => void;

  // ── Agent-native events (new in TS SDK; server-supported today) ────

  /** Fired when the underlying transport opens (TCP/WS established).
   *  Distinct from `'connectionStateChanged'`: this is a discrete
   *  transition event, useful for telemetry. */
  connected: () => void;

  /** Fired when the transport closes. `reason` is best-effort. */
  disconnected: (reason: string) => void;

  /** Fired when another participant broadcasts a PRESENCE update.
   *  See `setPresence()` for the outbound side. */
  presence: (payload: PresencePayload) => void;

  /** Fired when this client receives a governance signal targeted at us.
   *  A well-behaved agent must respond promptly (e.g. transition
   *  `setPresence('paused', …)` within 10s on `'pause'`). */
  governance: (payload: GovernancePayload) => void;

  /** Fired when a `+freeq.at/event=*` coordination event arrives in a
   *  channel we're in (TAGMSG or its companion PRIVMSG). Handlers
   *  dispatch on `payload.eventType`. */
  coordinationEvent: (payload: CoordinationEventPayload) => void;

  /** Fired when a SPEND wire command is broadcast to a channel we're in. */
  spend: (payload: SpendPayload) => void;

  /** Fired when BUDGET state changes in a channel we're in (set, updated,
   *  or exceeded). Note: `budget_exceeded` also fires `governance`. */
  budget: (payload: BudgetSnapshot) => void;

  /** Fired when a parent agent broadcasts AGENT SPAWN in a channel we're in. */
  agentSpawned: (payload: AgentSpawnedPayload) => void;

  /** Fired when a child agent broadcasts AGENT DESPAWN (or its TTL expires). */
  agentDespawned: (payload: AgentDespawnedPayload) => void;

  // ── Renamed events (canonical names with deprecated aliases) ──────

  /** Fired per result of `requestHistoryTargets()` — once per recent
   *  conversation target (channel or DM partner) with the most-recent
   *  message timestamp. */
  historyTarget: (target: string, timestamp?: string) => void;
}

type EventHandler<K extends keyof FreeqEvents> = FreeqEvents[K];

/**
 * Minimal typed event emitter.
 * Consumers subscribe to strongly-typed events.
 */
export class EventEmitter {
  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();

  /** Subscribe to an event. */
  on<K extends keyof FreeqEvents>(event: K, handler: EventHandler<K>): this {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(handler as (...args: unknown[]) => void);
    return this;
  }

  /** Unsubscribe from an event. */
  off<K extends keyof FreeqEvents>(event: K, handler: EventHandler<K>): this {
    this.listeners.get(event)?.delete(handler as (...args: unknown[]) => void);
    return this;
  }

  /** Subscribe to an event, but only fire once. */
  once<K extends keyof FreeqEvents>(event: K, handler: EventHandler<K>): this {
    const wrapper = ((...args: unknown[]) => {
      this.off(event, wrapper as EventHandler<K>);
      (handler as (...a: unknown[]) => void)(...args);
    }) as EventHandler<K>;
    return this.on(event, wrapper);
  }

  /** Emit an event to all subscribers. */
  protected emit<K extends keyof FreeqEvents>(
    event: K,
    ...args: Parameters<FreeqEvents[K]>
  ): void {
    const set = this.listeners.get(event);
    if (!set) return;
    for (const fn of set) {
      try {
        fn(...args);
      } catch (e) {
        console.error(`[freeq-sdk] Error in ${event} handler:`, e);
      }
    }
  }

  /** Remove all listeners (useful on disconnect). */
  removeAllListeners(): void {
    this.listeners.clear();
  }
}
