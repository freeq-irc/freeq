/**
 * FreeqClient — event-driven IRC client with AT Protocol identity and E2EE.
 *
 * Usage:
 *   const client = new FreeqClient({ url: 'wss://irc.freeq.at/irc', nick: 'mybot' });
 *   client.on('message', (channel, msg) => console.log(`${msg.from}: ${msg.text}`));
 *   client.connect();
 */

import { EventEmitter } from './events.js';
import { parse, prefixNick, format } from './parser.js';
import { Transport } from './transport.js';
import * as signing from './signing.js';
import * as e2ee from './e2ee.js';
import { dmPeerKey, isDid } from './address.js';
import { prefetchProfiles } from './profiles.js';
import type {
  IRCMessage, Message, Member, AvSession, AvParticipant,
  FreeqClientOptions, SaslCredentials, Batch, TransportState,
  PinnedMessage, WhoisInfo, HistoryOptions, HistoryBatchInfo, EmitEventOptions,
  HeartbeatHandle, GovernanceSignal, CoordinationEventPayload, ActEventPayload,
} from './types.js';

/**
 * The capability a server advertises to say it verifies the chat signing
 * document (see `signing.ts` for what that document is).
 *
 * A signature is only worth sending to a server that checks it. Against one
 * that doesn't, the signature is stripped and replaced by the server's own
 * — turning a non-repudiable claim into that server's attestation — and the
 * event id we minted is ignored while its tag leaks onward over federation.
 * Gating on the cap makes the client rollout self-coordinating per server: no
 * deploy lockstep, no flag day.
 */
export const SIGNING_CAP = 'freeq.at/msgsig';

/**
 * How long a task event's id is remembered so the same event is not emitted
 * twice.
 *
 * Generous on purpose: the duplicate this exists to swallow is a joiner's
 * JOIN replay followed by the CHATHISTORY it asks for, and a catch-up over a
 * slow link can put minutes between the two sightings of one event.
 */
const ACT_EVENT_DEDUPE_MS = 10 * 60_000;

/**
 * How long a task event waits for the server's word before its companion
 * line is sent anyway.
 *
 * Fail-open on purpose: the line is what clients render as the card, so an
 * accepted step whose line never went out is invisible to everyone — a worse
 * failure than the rare late line beside a step that was refused.
 */
const ACT_ANSWER_WINDOW_MS = 5_000;

/**
 * Backoff for re-sending a guest's own nick after 433 on an automatic
 * reconnect. A guest's nick is their whole identity, and the reconnect can
 * arrive before the server has reaped the previous session holding it —
 * a few seconds of retries outlast that race without stalling the reconnect.
 */
const GUEST_NICK_RESUME_DELAYS_MS = [500, 1000, 2000];

/** CHATHISTORY subcommands, which sit where a target could and are all legal
 *  nicks. */
const HISTORY_SUBCOMMANDS = new Set([
  'latest', 'before', 'after', 'around', 'between', 'targets',
]);

/** Which parameter of `FAIL CHATHISTORY <code> …` names the target, by code.
 *  Counted from the start of the FAIL parameters, so `CHATHISTORY` is 0 and
 *  the code is 1. Codes not listed have no fixed position and are scanned. */
const HISTORY_FAIL_TARGET_AT: Record<string, number> = {
  message_error: 3,      // <subcommand> <target>
  invalid_target: 2,
  account_required: 2,
};

export class FreeqClient extends EventEmitter {
  private transport: Transport | null = null;
  private _nick = '';
  private _authDid: string | null = null;
  /** Bearer token usable for `/agent/tools/*` HTTP calls. Populated
   *  from the server-emitted `NOTICE * :API-BEARER <session_id>` that
   *  fires immediately after SASL success. Bots use this to call
   *  diagnostic tools as themselves instead of as anonymous. */
  private _apiBearer: string | null = null;
  private _connectionState: TransportState = 'disconnected';
  private _registered = false;
  private opts: FreeqClientOptions;

  private ackedCaps = new Set<string>();
  private sasl: SaslCredentials | null = null;
  private skipBrokerRefresh: boolean;
  private guestFallbackCount = 0;
  /** This connection's signing state (session key, kid, DID). Per-instance
   *  on purpose: as a module global, every client in a Node process shared
   *  one key and each connect overwrote the last — all but the last client's
   *  messages then verified as server-signed instead of their own. */
  readonly signing = new signing.SessionSigning();
  /** Session signing key waiting on registration before MSGSIG is sent. */
  private pendingMsgSig: Promise<string | null> | null = null;
  /** Set when SASL was attempted and 904 was received. Suppresses any
   *  subsequent registration completion as a guest, and blocks outgoing
   *  PRIVMSGs that would silently leak under the guest identity. */
  private _saslFailed = false;
  /** Channels the server has flagged +E. Used to block plaintext sends
   *  when we don't (yet) have the passphrase, so messages don't leak
   *  unencrypted into a channel the rest of the room expects encrypted. */
  private _encryptedChannels = new Set<string>();
  /** Current AWAY reason, or null if not away. Re-asserted on
   *  reconnect so the wire and UI states don't diverge after the
   *  server forgets us during the disconnect. */
  private _currentAway: string | null = null;

  private autoJoinChannels: string[] = [];
  private _joinedChannels = new Set<string>();
  /** Accumulates NAMES (353) lines per channel between the start of a NAMES
   *  reply and its 366 terminator, so the full roster can be emitted atomically
   *  as `membersSync`. A key present = a NAMES sequence is in progress; 366
   *  deletes it, so the next reply starts fresh. */
  private _namesAccum = new Map<string, Array<Partial<Member> & { nick: string }>>();

  private backgroundWhois = new Set<string>();
  private echoPlaintextCache = new Map<string, { plaintext: string; ts: number }>();
  private batches = new Map<string, Batch>();
  /** History requests sent per lowercased target, oldest first. The server
   *  answers a target's requests in the order they were asked, so the batch
   *  that closes takes the front of the queue — a single slot would label an
   *  earlier answer with a later request. */
  private historyRequests = new Map<string, Array<HistoryBatchInfo>>();
  /** Server-advertised `draft/multiline` policy (parsed from CAP LS). */
  private multilineMaxBytes = 40000;
  private multilineMaxLines = 100;
  /** Monotonic counter for client-generated BATCH ids. */
  private nextBatchSeq = 0;
  private pendingAwayReason: string | null = null;

  private _avSessions = new Map<string, AvSession>();
  private _activeAvSession: string | null = null;
  /** Session id → MoQ access token (`+freeq.at/av-token` TAGMSG, sent by
   *  the server right after av-start/av-join). Appended to the SFU dial
   *  URL as `?jwt=…`; without it the SFU rejects the connection once the
   *  server enforces tokens (FREEQ_AV_REQUIRE_TOKEN). */
  private _avTokens = new Map<string, string>();

  // ── Internal caches and timer state ───────────────────────────────
  /** Lowercase nick → DID. Populated from numeric 330 (WHOIS) and from
   *  inbound `+freeq.at/account` tags. */
  private _nickToDid = new Map<string, string>();
  /** DID → lowercase nick. Reverse cache for AGENT PAUSE/REVOKE which
   *  take nicks, not DIDs. */
  private _didToNick = new Map<string, string>();
  /** Accumulating WHOIS info per nick. Multiple WHOIS numerics fire
   *  incrementally (311/312/319/330/671/673); we collect until 318
   *  (RPL_ENDOFWHOIS) and resolve the requestWhois() Promise. */
  private _whoisBuffer = new Map<string, Partial<WhoisInfo>>();
  /** Pending requestWhois() Promise resolvers, keyed by lowercase nick. */
  private _pendingWhois = new Map<string, Array<{
    resolve: (info: WhoisInfo) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>>();
  /** Random-suffix nick collision retry counter. */
  private _nickCollisionRetries = 0;
  /** Set on the first completed registration: a later connection on this
   *  client is a reconnect, not a first connect. */
  private _hadSession = false;
  /** True between sending registration and 001 on the current connection. */
  private _awaitingWelcome = false;
  /** How many times the current connection has re-sent its own nick after
   *  433, and the pending retry's timer. */
  private _nickResumeAttempts = 0;
  private _nickResumeTimer: ReturnType<typeof setTimeout> | null = null;
  /** Background heartbeat loop handle (set by startHeartbeat()). */
  private _agentHeartbeatTimer: ReturnType<typeof setInterval> | null = null;
  /** Recently-seen coordination event IDs (TAGMSG + companion PRIVMSG carry
   *  the same eventId; we fire `coordinationEvent` only once per pair). */
  private _seenCoordinationEvents = new Map<string, number>();
  /** Task event ids already emitted, and when. Longer-lived than the
   *  coordination map because the duplicates it exists to swallow are further
   *  apart: an echo arrives in the same breath, but a joiner gets every event
   *  twice — once in JOIN replay and once in the CHATHISTORY it asks for
   *  next. */
  private _seenActEvents = new Map<string, number>();

  constructor(opts: FreeqClientOptions) {
    super();
    this.opts = opts;
    this._nick = opts.nick;
    this.sasl = opts.sasl ?? null;
    this.autoJoinChannels = opts.channels ? [...opts.channels] : [];
    this.skipBrokerRefresh = opts.skipInitialBrokerRefresh ?? false;
  }

  // ── Accessors ──

  /** Current IRC nickname. */
  get nick(): string { return this._nick; }

  /** Authenticated AT Protocol DID, or null if guest. */
  get authDid(): string | null { return this._authDid; }

  /** Bearer token for `/agent/tools/*` HTTP calls. Set automatically
   *  on SASL success; null while unauthenticated. Use as
   *  `Authorization: Bearer <client.apiBearer>` to make diagnostic
   *  calls as the same identity the IRC session is bound to. */
  get apiBearer(): string | null { return this._apiBearer; }

  /** Current connection state. */
  get connectionState(): TransportState { return this._connectionState; }

  /** Whether IRC registration is complete (001 received). */
  get registered(): boolean { return this._registered; }

  /** Set of channels we're currently in (lowercase). */
  get joinedChannels(): ReadonlySet<string> { return this._joinedChannels; }

  /** Active AV sessions. */
  get avSessions(): ReadonlyMap<string, AvSession> { return this._avSessions; }

  /** Active AV session ID we're participating in. */
  get activeAvSession(): string | null { return this._activeAvSession; }

  /** MoQ access token for an AV session (from `+freeq.at/av-token`), or
   *  null if none received yet. Append to the SFU URL as `?jwt=…`. */
  avTokenFor(sessionId: string): string | null {
    return this._avTokens.get(sessionId) ?? null;
  }

  /** Server origin for API calls. */
  get serverOrigin(): string {
    if (this.opts.serverOrigin) return this.opts.serverOrigin;
    try {
      const u = new URL(this.opts.url);
      return `${u.protocol === 'wss:' ? 'https:' : 'http:'}//${u.host}`;
    } catch {
      return '';
    }
  }

  // ── Connection ──

  /** Connect to the IRC server. */
  connect(): void {
    if (this.transport) {
      try { this.transport.disconnect(); } catch { /* ignore */ }
      this.transport = null;
    }
    this._saslFailed = false;
    this.clearNickResume();

    let lineQueue: Promise<void> = Promise.resolve();
    const serializedHandleLine = (line: string) => {
      lineQueue = lineQueue.then(() => this.handleLine(line)).catch((e) =>
        console.error('[freeq-sdk] line handler error:', e)
      );
    };

    this.transport = new Transport({
      url: this.opts.url,
      onLine: serializedHandleLine,
      onStateChange: (s) => this.onTransportStateChange(s),
    });
    this.transport.connect();
  }

  /** Wait for the WebSocket send buffer to drain. Returns when
   *  `bufferedAmount` reaches 0 (or the WS is no longer open), or after
   *  `maxMs` (default 2000ms). Call before `disconnect()` if you need
   *  outbound messages (PRESENCE=offline, QUIT, etc.) to actually reach
   *  the server before the socket closes. */
  async flush(maxMs?: number): Promise<void> {
    await this.transport?.flush(maxMs);
  }

  /** Disconnect from the server. */
  disconnect(): void {
    this.transport?.disconnect();
    this.transport = null;
    this._nick = '';
    this._authDid = null;
    this._apiBearer = null;
    this._registered = false;
    this._saslFailed = false;
    this.ackedCaps.clear();
    this.sasl = null;
    this._joinedChannels.clear();
    this.backgroundWhois.clear();
    this.echoPlaintextCache.clear();
    this.batches.clear();
    this.historyRequests.clear();
    this._avSessions.clear();
    this._activeAvSession = null;
    this._avTokens.clear();
    this._encryptedChannels.clear();
    this._currentAway = null;
    // Clear internal caches and timer state.
    this._nickToDid.clear();
    this._didToNick.clear();
    this._whoisBuffer.clear();
    // Reject any pending whois Promises so callers don't hang forever.
    for (const [, waiters] of this._pendingWhois) {
      for (const w of waiters) {
        clearTimeout(w.timer);
        w.reject(new Error('disconnect()'));
      }
    }
    this._pendingWhois.clear();
    this._seenCoordinationEvents.clear();
    this._seenActEvents.clear();
    this._nickCollisionRetries = 0;
    this.clearNickResume();
    this._hadSession = false;
    this._awaitingWelcome = false;
    if (this._agentHeartbeatTimer) {
      clearInterval(this._agentHeartbeatTimer);
      this._agentHeartbeatTimer = null;
    }
    this.signing.resetSigning();
    // Whatever was waiting for a registration on this connection is not
    // getting one. The next session arms the gate again.
    this.msgSigRegistered();
    this._connectionState = 'disconnected';
  }

  /** Force an immediate reconnect. */
  reconnect(): void {
    if (!this.opts.url || !this.opts.nick) return;
    this.transport?.disconnect();
    this.transport = null;
    const channels = [...this._joinedChannels];
    this.autoJoinChannels = channels;
    this._nick = this.opts.nick;
    this.connect();
  }

  /** Set SASL credentials (call before connect, or before reconnect). */
  setSaslCredentials(creds: SaslCredentials): void {
    this.sasl = creds;
    if (creds.token) this.skipBrokerRefresh = true;
  }

  // ── Sending ──

  /**
   * Send a message to a channel or user. Multi-line text routes by
   * negotiated cap:
   * - `draft/multiline` acked AND text contains `\n` → BATCH (one
   *   chunk per logical line).
   * - Otherwise → single PRIVMSG with `\n` escaped as `\\n` and a
   *   `+freeq.at/multiline` tag. The SDK normalizes both forms on
   *   receive so consumers always see real `\n`.
   *
   * The `multiline` param is accepted but unused; routing keys on `\n`
   * in the text and the negotiated cap.
   */
  sendMessage(target: string, text: string, multiline = false): void {
    void multiline;
    this.sendMessageInternal(target, text, {});
  }

  /**
   * Multi-line send with two affordances `sendMessage` doesn't have:
   *
   * - **Array input** — pass `['line1', 'line2', ...]` directly.
   *   Equivalent to `sendMessage(target, body.join('\n'))`.
   * - **Opener tags** — pass arbitrary tags via `options.tags` to ride
   *   on the BATCH opener (e.g. commit-reveal payloads). For common
   *   tags use the dedicated methods: `sendReply` (+reply), `sendEdit`
   *   (+draft/edit), `sendTagged` (arbitrary single-PRIVMSG tags).
   *
   * For plain multi-line text without custom opener tags, `sendMessage`
   * is equivalent and simpler — it auto-detects `\n` and routes to a
   * `draft/multiline` BATCH (when the cap is acked) or the legacy
   * single-PRIVMSG path otherwise.
   *
   * Returns `null` — the BATCH frames are emitted asynchronously
   * after the assembled body is signed, so the id isn't synchronously
   * available.
   */
  sendMultiline(
    target: string,
    body: string | string[],
    options: { tags?: Record<string, string> } = {},
  ): string | null {
    const text = Array.isArray(body) ? body.join('\n') : body;
    return this.sendMessageInternal(target, text, options.tags ?? {});
  }

  /**
   * Shared implementation behind `sendMessage` / `sendMultiline` /
   * `sendReply` / `sendEdit`. Picks the wire shape based on whether
   * the text has line breaks, whether the channel is E2EE, and
   * whether the server acked `draft/multiline`.
   *
   * Returns the BATCH id if a multiline BATCH was used, or `null` if
   * a single PRIVMSG (with or without `+freeq.at/multiline`) was used.
   */
  private sendMessageInternal(
    target: string,
    text: string,
    extraOpenerTags: Record<string, string>,
  ): string | null {
    const isChannel = target.startsWith('#') || target.startsWith('&');

    // Wire target for a DM: the peer's DID when addressing-grade known, else
    // the nick unchanged (strict — routing must not ride a display binding).
    // `target` stays the caller's input for E2EE peer resolution; `bufKey`
    // is where the local echo files — resolved loosely (dmKey) so a send to
    // an offline peer's nick still lands in the DID-keyed thread.
    const wireTarget = this.wireTargetFor(target);
    const bufKey = isChannel ? target : this.dmKey(target);

    // +E channels require the `+encrypted` tag on every PRIVMSG —
    // refuse rather than leak plaintext into a room the rest of the
    // members expect encrypted.
    if (
      isChannel &&
      this._encryptedChannels.has(target.toLowerCase()) &&
      !e2ee.hasChannelKey(target)
    ) {
      this.emit(
        'systemMessage',
        target,
        `Cannot send to ${target}: channel is encrypted (+E) and you have no key set. Use the channel passphrase to enable encryption first.`,
      );
      return null;
    }

    const hasNewline = text.includes('\n');
    const multilineCap =
      this.ackedCaps.has('draft/multiline') && this.ackedCaps.has('batch');
    const perChunkBudget = this.perChunkByteBudget();

    // DMs are deliberately NOT auto-encrypted. The per-message-key scheme
    // makes history readable only on the one device that held the session,
    // and no multi-device or durable-history model exists around it yet —
    // so DMs go signed-plaintext until one does. Inbound decryption stays
    // wired so anything already encrypted still reads where it can.
    const willEncrypt = e2ee.hasChannelKey(target);

    // ── E2EE path ──
    if (willEncrypt) {
      const remoteDid = !isChannel ? this.remoteDidFor(target) : null;
      const encryptFn = isChannel
        ? () => e2ee.encryptChannel(target, text)
        : () => e2ee.encryptMessage(remoteDid!, text, this.serverOrigin);

      encryptFn().then(async (encrypted) => {
        if (!encrypted) {
          // Encryption failed — fall back to signed plaintext
          this.sendLegacyPlaintext(wireTarget, text, extraOpenerTags);
          return;
        }
        this.cacheEchoPlaintext(encrypted, text);
        if (encrypted.length + 200 <= perChunkBudget || !multilineCap) {
          // Fits in one line, or we can't multiline anyway → one PRIVMSG.
          // Signed like any other message: the document hashes the WIRE body,
          // so under encryption it covers the ciphertext — the same bytes the
          // server stores and every federated receiver holds. Nothing about
          // the canonical changes, and nobody has to see the plaintext to
          // check who sent it.
          const tags: Record<string, string> = {
            '+encrypted': '',
            ...extraOpenerTags,
          };
          await this.signedPrivmsg(wireTarget, encrypted, tags);
        } else {
          // Ciphertext too big → chunk across a multiline BATCH with
          // concat=true. Receiver concatenates fragments and decrypts once.
          const chunks = this.chunkMultilineBody(encrypted, perChunkBudget, true);
          if (chunks.length > this.multilineMaxLines) {
            this.emit(
              'systemMessage',
              wireTarget,
              `Message too large to send: ciphertext exceeds server multiline limit (${this.multilineMaxLines} lines).`,
            );
            return;
          }
          // The signature rides the opener and covers the ASSEMBLED
          // ciphertext, which is what the server reassembles and verifies —
          // per-chunk signatures would cover bytes no receiver ever holds.
          await this.enqueueSend(async () => {
            const sigTags = await this.signatureTags(
              wireTarget,
              this.assembleMultiline(chunks),
              extraOpenerTags,
            );
            this.emitMultilineBatch(
              wireTarget,
              chunks,
              { ...extraOpenerTags, ...sigTags },
              { '+encrypted': '' },
            );
          });
        }
      });
      this.maybeLocalEcho(bufKey, text, willEncrypt);
      return null; // Async; can't return batch id meaningfully here
    }

    // ── Non-E2EE path ──
    // Route to a multiline BATCH when the text has newlines OR is simply too
    // big for one PRIVMSG. Length alone must trigger it — a long single-line
    // message (no `\n`) would otherwise hit the legacy path and truncate at the
    // wire cap. chunkMultilineBody length-splits a long line into concat chunks
    // regardless, so this just widens the entry condition.
    const overBudget = new TextEncoder().encode(text).length > perChunkBudget;
    if (multilineCap && (hasNewline || overBudget)) {
      const chunks = this.chunkMultilineBody(text, perChunkBudget, false);
      // A paste larger than one batch (server-advertised max-lines /
      // max-bytes) is sent as SEVERAL batches — several logical messages
      // — rather than collapsed into one oversized legacy line. That
      // legacy fallback was the RFC-paste bug: a ~130-line doc exceeded
      // max-lines=100, fell back to a single escaped line, and got
      // silently truncated at the server's 8 KB wire cap. Splitting is
      // the intended completion of the multiline feature, not a fallback.
      for (const group of this.groupChunksIntoBatches(chunks)) {
        // Sign each group's ASSEMBLED body and ride the sig on that
        // batch's opener. The server verifies sigs over the assembled
        // body (multiline dispatch calls handle_privmsg with the joined
        // text) and reads `+freeq.at/sig` from the opener tags. Per-batch
        // signing keeps each emitted message independently verifiable.
        const body = this.assembleMultiline(group);
        void this.enqueueSend(async () => {
          const sigTags = await this.signatureTags(wireTarget, body, extraOpenerTags);
          this.emitMultilineBatch(wireTarget, group, { ...extraOpenerTags, ...sigTags });
        });
        this.maybeLocalEcho(bufKey, body, willEncrypt);
      }
      // Async signing — batch id isn't synchronously available.
      return null;
    }

    // Fits in one PRIVMSG (or no multiline cap) → single PRIVMSG. Legacy path
    // preserves \n escaping + +freeq.at/multiline for receivers that decode it.
    this.sendLegacyPlaintext(wireTarget, text, extraOpenerTags);
    this.maybeLocalEcho(bufKey, text, willEncrypt);
    return null;
  }

  /**
   * Single-PRIVMSG fallback: escapes `\n` as `\\n` and sets
   * `+freeq.at/multiline` when the text has line breaks, so older
   * receivers that decode that tag still render correctly. Used when
   * the multiline cap isn't acked.
   */
  private sendLegacyPlaintext(
    target: string,
    text: string,
    extraTags: Record<string, string>,
  ): void {
    const hasNewline = text.includes('\n');
    const wireText = hasNewline ? text.replace(/\n/g, '\\n') : text;
    const tags: Record<string, string> = { ...extraTags };
    if (hasNewline) tags['+freeq.at/multiline'] = '';
    this.signedPrivmsg(target, wireText, tags);
  }

  /**
   * Emit local echo if `echo-message` wasn't acked, so the sender's UI
   * still sees its own outbound message immediately.
   */
  private maybeLocalEcho(target: string, text: string, willEncrypt: boolean): void {
    if (this.ackedCaps.has('echo-message')) return;
    const msg: Message = {
      id: crypto.randomUUID(),
      from: this._nick,
      text,
      timestamp: new Date(),
      tags: {},
      isSelf: true,
      encrypted: willEncrypt,
    };
    this.emit('message', target, msg);
  }

  /**
   * Per-PRIVMSG-chunk byte budget. Caps below the SDK's own
   * `LINE_SIZE_WARN_THRESHOLD` (7000) so chunked sends don't trigger
   * an oversize warning. Reserve ~600 bytes for worst-case opener
   * metadata; the rest is body content. The server-advertised
   * `max-bytes` is the TOTAL across all chunks, not per-chunk, so it
   * doesn't override this budget directly.
   */
  private perChunkByteBudget(): number {
    return 6400;
  }

  /** Send a reply to a specific message. Multi-line replies use the
   *  same wire shape as `sendMessage`. */
  sendReply(target: string, replyToMsgId: string, text: string, multiline = false): void {
    void multiline;
    this.sendMessageInternal(target, text, { '+reply': replyToMsgId });
  }

  /** Edit a message. Multi-line edits use the same wire shape as
   *  `sendMessage`. */
  sendEdit(target: string, originalMsgId: string, newText: string, multiline = false): void {
    void multiline;
    this.sendMessageInternal(target, newText, { '+draft/edit': originalMsgId });
  }

  /** Send a message with Markdown formatting. */
  sendMarkdown(target: string, text: string): void {
    const isMultiline = text.includes('\n');
    const wireText = isMultiline ? text.replace(/\n/g, '\\n') : text;
    const tags: Record<string, string> = { '+freeq.at/mime': 'text/markdown' };
    if (isMultiline) tags['+freeq.at/multiline'] = '';
    // Same target discipline as sendMessageInternal: strict DID resolution
    // for the wire, canonical (loose) key for the local echo.
    const isChannel = target.startsWith('#') || target.startsWith('&');
    const bufKey = isChannel ? target : this.dmKey(target);
    this.signedPrivmsg(this.wireTargetFor(target), wireText, tags);

    if (!this.ackedCaps.has('echo-message')) {
      this.emit('message', bufKey, {
        id: crypto.randomUUID(),
        from: this._nick,
        text: wireText,
        timestamp: new Date(),
        tags,
        isSelf: true,
      });
    }
  }

  /**
   * Send an action — what `/me` writes. The body carries the CTCP ACTION
   * framing every receiver reads it by, and the framing is inside what the
   * signature covers: an action asserts something under a user's name just as
   * a sentence does, and stripping the framing in flight would change what
   * was said.
   */
  sendAction(target: string, text: string): void {
    const isChannel = target.startsWith('#') || target.startsWith('&');
    this.signedPrivmsg(this.wireTargetFor(target), `\x01ACTION ${text}\x01`);

    if (!this.ackedCaps.has('echo-message')) {
      this.emit('message', isChannel ? target : this.dmKey(target), {
        id: crypto.randomUUID(),
        from: this._nick,
        text,
        timestamp: new Date(),
        tags: {},
        isSelf: true,
        isAction: true,
      });
    }
  }

  /**
   * Delete a message.
   *
   * The mutation is addressed like a message is: in a DM, the peer's DID when
   * we know it. The signer derives the venue from the target it is handed, so
   * a mutation left on a bare nick could not be signed at all — while the DID
   * needed to sign it sat in the map the whole time.
   */
  sendDelete(target: string, msgId: string): void {
    this.emit('messageDeleted', target, msgId);
    this.signedMutation('delete', this.wireTargetFor(target), { '+draft/delete': msgId }, msgId);
  }

  /** React to a message with an emoji. */
  sendReaction(target: string, emoji: string, msgId?: string): void {
    const tags: Record<string, string> = { '+react': emoji };
    if (msgId) tags['+reply'] = msgId;
    this.signedMutation('react', this.wireTargetFor(target), tags, msgId, emoji);

    if (msgId) {
      this.emit('reactionAdded', target, msgId, emoji, this._nick);
    }
  }

  /** Remove our previous reaction to a message. */
  sendUnreact(target: string, emoji: string, msgId: string): void {
    const tags: Record<string, string> = {
      '+freeq.at/unreact': emoji,
      '+reply': msgId,
    };
    this.signedMutation('unreact', this.wireTargetFor(target), tags, msgId, emoji);
    this.emit('reactionRemoved', target, msgId, emoji, this._nick);
  }

  // ── Channel management ──

  /** Join a channel. */
  join(channel: string, key?: string): void {
    this.raw(key ? `JOIN ${channel} ${key}` : `JOIN ${channel}`);
  }

  /** Leave a channel. */
  part(channel: string): void {
    this.raw(`PART ${channel}`);
    this._joinedChannels.delete(channel.toLowerCase());
  }

  /** Set a channel's topic. */
  setTopic(channel: string, topic: string): void {
    this.raw(`TOPIC ${channel} :${topic}`);
  }

  /** Set a channel or user mode. */
  setMode(channel: string, mode: string, arg?: string): void {
    this.raw(arg ? `MODE ${channel} ${mode} ${arg}` : `MODE ${channel} ${mode}`);
  }

  /** Kick a user from a channel. */
  kick(channel: string, nick: string, reason?: string): void {
    this.raw(`KICK ${channel} ${nick} :${reason || 'kicked'}`);
  }

  /** Invite a user to a channel. */
  invite(channel: string, nick: string): void {
    this.raw(`INVITE ${nick} ${channel}`);
  }

  /** Set or clear away status. */
  setAway(reason?: string): void {
    this.pendingAwayReason = reason || null;
    this._currentAway = reason || null;
    this.raw(reason ? `AWAY :${reason}` : 'AWAY');
  }

  /**
   * Set the cross-device read marker for `target` (IRCv3 `draft/read-marker`).
   *
   * `timestamp` must be ISO 8601 with millisecond precision and a `Z` suffix,
   * exactly as in the `server-time` extension (`YYYY-MM-DDThh:mm:ss.sssZ`).
   * The server only ever moves the marker forward: a stale timestamp is
   * ignored and the server replies with the current (newer) value. Either way
   * the reply arrives via the `readMarker` event, and — for DID-authenticated
   * sessions — the update is pushed to your other connected devices.
   */
  markRead(target: string, timestamp: string): void {
    this.raw(`MARKREAD ${target} timestamp=${timestamp}`);
  }

  /**
   * Query the current read marker for `target`. The answer arrives via the
   * `readMarker` event with `timestamp = null` when no marker has been set.
   */
  getReadMarker(target: string): void {
    this.raw(`MARKREAD ${target}`);
  }

  /** Fire a WHOIS and resolve with parsed info when 318 (RPL_ENDOFWHOIS)
   *  arrives. Renamed from `whois()` — that name remains as a deprecated
   *  alias for one release. */
  requestWhois(nick: string, opts: { timeoutMs?: number } = {}): Promise<WhoisInfo> {
    const lc = nick.toLowerCase();
    const timeoutMs = opts.timeoutMs ?? 5000;
    return new Promise<WhoisInfo>((resolve, reject) => {
      const timer = setTimeout(() => {
        // Remove this waiter from the queue.
        const queue = this._pendingWhois.get(lc) ?? [];
        const idx = queue.findIndex((w) => w.timer === timer);
        if (idx >= 0) queue.splice(idx, 1);
        if (queue.length === 0) this._pendingWhois.delete(lc);
        else this._pendingWhois.set(lc, queue);
        reject(new Error(`requestWhois('${nick}') timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const queue = this._pendingWhois.get(lc) ?? [];
      queue.push({ resolve, reject, timer });
      this._pendingWhois.set(lc, queue);
      // Fire WHOIS lazily — multiple concurrent waiters share one request.
      if (queue.length === 1) {
        this.raw(`WHOIS ${nick}`);
      }
    });
  }

  /** @deprecated Use `requestWhois(nick)` (returns `Promise<WhoisInfo>`).
   *  Kept for one release; calling this still fires the `whois` event
   *  on each numeric, same as before. */
  whois(nick: string): void {
    this.raw(`WHOIS ${nick}`);
  }

  /** Request chat history for a target (channel or DM partner).
   *
   *  `opts.mode` selects:
   *    - 'latest' — most recent N messages
   *    - 'before' — N messages before the anchor
   *    - 'after'  — N messages after the anchor
   *    - 'around' — N messages surrounding the anchor, split across it
   *
   *  'before', 'after' and 'around' need an anchor: `opts.msgid` or
   *  `opts.timestamp`.
   *  A msgid is preferred when both are given — it names one stored row,
   *  where a timestamp is second-resolution and cannot separate messages
   *  sent in the same second.
   */
  requestHistory(opts: HistoryOptions): void;
  /** @deprecated Use the `HistoryOptions` form. The two-arg form is kept
   *  for backwards compatibility with freeq-app. */
  requestHistory(channel: string, before?: string): void;
  requestHistory(channelOrOpts: string | HistoryOptions, before?: string): void {
    const count = 50;
    let opts: HistoryOptions;
    if (typeof channelOrOpts === 'string') {
      // Legacy positional form: (channel, before?). `before` is treated
      // as a timestamp marker for CHATHISTORY BEFORE (existing behavior).
      if (before) {
        this.noteHistoryRequest(channelOrOpts, 'before', count);
        this.raw(`CHATHISTORY BEFORE ${channelOrOpts} timestamp=${before} ${count}`);
      } else {
        this.noteHistoryRequest(channelOrOpts, 'latest', count);
        this.raw(`CHATHISTORY LATEST ${channelOrOpts} * ${count}`);
      }
      return;
    }
    opts = channelOrOpts;
    const c = opts.count ?? count;
    const marker = opts.msgid
      ? `msgid=${opts.msgid}`
      : opts.timestamp
        ? `timestamp=${opts.timestamp}`
        : null;
    switch (opts.mode) {
      case 'latest':
        this.noteHistoryRequest(opts.target, 'latest', c);
        this.raw(`CHATHISTORY LATEST ${opts.target} * ${c}`);
        break;
      case 'before':
        if (!marker) throw new Error("requestHistory mode='before' requires opts.msgid or opts.timestamp");
        this.noteHistoryRequest(opts.target, 'before', c);
        this.raw(`CHATHISTORY BEFORE ${opts.target} ${marker} ${c}`);
        break;
      case 'after':
        if (!marker) throw new Error("requestHistory mode='after' requires opts.msgid or opts.timestamp");
        this.noteHistoryRequest(opts.target, 'after', c);
        this.raw(`CHATHISTORY AFTER ${opts.target} ${marker} ${c}`);
        break;
      case 'around':
        if (!marker) throw new Error("requestHistory mode='around' requires opts.msgid or opts.timestamp");
        this.noteHistoryRequest(opts.target, 'around', c);
        this.raw(`CHATHISTORY AROUND ${opts.target} ${marker} ${c}`);
        break;
    }
  }

  /** Remember what was asked for, keyed by the target as it goes on the
   *  wire — which is the target the server echoes on the answering batch. */
  private noteHistoryRequest(target: string, mode: HistoryBatchInfo['mode'], count: number): void {
    const key = target.toLowerCase();
    const queue = this.historyRequests.get(key) ?? [];
    queue.push({ mode, count });
    this.historyRequests.set(key, queue);
  }

  /** Drop the oldest pending request for whichever target a refused
   *  CHATHISTORY names.
   *
   *  The parameter holding the target sits in a different position per error
   *  code, so rather than parse by code this matches the remaining
   *  parameters against the targets that have a request outstanding. A FAIL
   *  naming none of them is not about a request this client is waiting on.
   *
   *  For the codes whose shape is known the target is read from its own
   *  position and nowhere else, so a refusal about one target cannot drain a
   *  DM whose peer happens to be nicked `before` — the subcommand sits where
   *  a target could and every subcommand is a legal nick. Codes with no known
   *  shape fall back to scanning, skipping the words that can only be
   *  subcommands. */
  private dropRefusedHistoryRequest(params: string[]): void {
    const at = HISTORY_FAIL_TARGET_AT[(params[1] ?? '').toLowerCase()];
    const candidates = at !== undefined
      ? [params[at]]
      : params.slice(2).filter((p) => !HISTORY_SUBCOMMANDS.has(p.toLowerCase()));
    for (const candidate of candidates) {
      const key = (candidate ?? '').toLowerCase();
      if (this.historyRequests.has(key)) {
        this.takeHistoryRequest(key);
        return;
      }
    }
  }

  /** What the closing batch for `target` answers, consuming it. */
  private takeHistoryRequest(target: string): HistoryBatchInfo | undefined {
    const key = target.toLowerCase();
    const queue = this.historyRequests.get(key);
    const info = queue?.shift();
    if (queue && queue.length === 0) this.historyRequests.delete(key);
    return info;
  }

  /** Request CHATHISTORY TARGETS — list of recent conversation targets
   *  (channels + DM partners with recent activity).
   *  Each result fires `historyTarget(target, timestamp?)`. */
  requestHistoryTargets(limit = 50): void {
    this.raw(`CHATHISTORY TARGETS * * ${limit}`);
  }

  /** @deprecated Use `requestHistoryTargets(limit)`. CHATHISTORY TARGETS
   *  returns channels too, not just DMs; the original name was misleading.
   *  Kept for one release. */
  requestDmTargets(limit = 50): void {
    this.raw(`CHATHISTORY TARGETS * * ${limit}`);
  }

  /** Pin a message. */
  pin(channel: string, msgid: string): void {
    this.raw(`PIN ${channel} ${msgid}`);
  }

  /** Unpin a message. */
  unpin(channel: string, msgid: string): void {
    this.raw(`UNPIN ${channel} ${msgid}`);
  }

  /** Send a raw IRC command. */
  raw(line: string): void {
    // Defense in depth against the silent-guest-fallback bug: if SASL
    // was attempted and failed on this socket, refuse to write anything
    // that could leak under the guest identity the server would have
    // assigned. The transport is normally already torn down by the 904
    // handler, but a queued send during the close window is still
    // possible.
    if (this._saslFailed) return;
    this.transport?.send(line);
  }

  /** Set a channel encryption passphrase (ENC1). */
  async setChannelEncryption(channel: string, passphrase: string): Promise<void> {
    await e2ee.setChannelKey(channel, passphrase);
  }

  /** Remove channel encryption. */
  removeChannelEncryption(channel: string): void {
    e2ee.removeChannelKey(channel);
  }

  /** Initialize E2EE for DMs (called automatically after SASL success). */
  async initializeE2EE(did: string): Promise<void> {
    await e2ee.initialize(did, this.serverOrigin);
  }

  /** Get the E2EE safety number for a DM partner. */
  async getSafetyNumber(remoteDid: string): Promise<string | null> {
    return e2ee.getSafetyNumber(remoteDid);
  }

  /** Fetch pinned messages for a channel via REST API.
   *  Returns the fetched pins; also fires the `pins` event for any
   *  subscribers. Returns an empty array on failure. */
  async fetchPins(channel: string): Promise<PinnedMessage[]> {
    try {
      const name = channel.startsWith('#') ? channel.slice(1) : channel;
      const resp = await fetch(`${this.serverOrigin}/api/v1/channels/${encodeURIComponent(name)}/pins`);
      if (resp.ok) {
        const data = await resp.json();
        const pins: PinnedMessage[] = data.pins || [];
        this.emit('pins', channel, pins);
        return pins;
      }
    } catch { /* ignore */ }
    return [];
  }

  // ── Internals ──

  /** Whether a 433 should be answered by asking for the same nick again:
   *  a guest registering on a reconnect, with retries left and none in
   *  flight. A collision on a first connect is someone else's nick. */
  private shouldResumeNick(): boolean {
    return this._hadSession
      && this._awaitingWelcome
      && !this.sasl?.did
      && this._nickResumeTimer === null
      && this._nickResumeAttempts < GUEST_NICK_RESUME_DELAYS_MS.length;
  }

  private clearNickResume(): void {
    if (this._nickResumeTimer) {
      clearTimeout(this._nickResumeTimer);
      this._nickResumeTimer = null;
    }
    this._nickResumeAttempts = 0;
  }

  /**
   * A reconnect could not re-establish the authenticated identity *before any
   * SASL attempt* — the broker session refresh timed out or failed and we have
   * no usable token to fall back on. The user intended to be logged in
   * (`sasl.did` is set), so we MUST NOT silently complete registration as a
   * guest: that would rename us to GuestNNNNN, leave the app's stale `authDid`
   * in place (verified badge next to a Guest nick), and let PRIVMSGs leak under
   * the guest identity.
   *
   * Mirror the 904 teardown: drop the dead credentials, mark `_saslFailed` so
   * any in-flight 001 is suppressed and outgoing PRIVMSGs are blocked, notify
   * the app (so its store clears `authDid` and surfaces "session expired"), and
   * tear the socket down so the next user action is an explicit re-auth.
   */
  private failReconnectAuth(reason: string): void {
    this.sasl = null;
    this._authDid = null;
    this._apiBearer = null;
    this._saslFailed = true;
    this.emit('authError', reason);
    this.emit('authenticated', '', reason);
    this.transport?.disconnect();
    this.transport = null;
    this._connectionState = 'disconnected';
    this.emit('connectionStateChanged', 'disconnected');
  }

  private onTransportStateChange(state: TransportState): void {
    const prev = this._connectionState;
    this._connectionState = state;
    this.emit('connectionStateChanged', state);

    // Discrete transition events (complement `connectionStateChanged`).
    if (state === 'connected' && prev !== 'connected') {
      this.emit('connected');
    } else if (state === 'disconnected' && prev !== 'disconnected') {
      this.emit('disconnected', 'transport closed');
    }

    if (state === 'connected') {
      this.ackedCaps.clear();
      this.clearNickResume();
      let registrationSent = false;

      const sendRegistration = (token?: string) => {
        // A late broker resolution can fire after we've already torn the
        // socket down (failReconnectAuth nulls `transport`). Don't register
        // onto a dead/replaced transport.
        if (registrationSent || !this.transport) return;
        registrationSent = true;
        this._awaitingWelcome = true;
        if (token && this.sasl) this.sasl.token = token;
        this.raw('CAP LS 302');
        this.raw(`NICK ${this._nick}`);
        this.raw(`USER ${this._nick} 0 * :freeq sdk`);
      };

      // Safety net so we never hang forever waiting on the broker. Must out-wait
      // the broker fetch (its own AbortController fires at 8s) so the broker
      // path's .then/.catch wins the race and we get a clean SASL attempt or a
      // clean failure — never a guest registration racing in underneath.
      const safetyTimer = setTimeout(() => {
        if (registrationSent) return;
        // The user authenticated: refuse to silently downgrade to a guest.
        if (this.sasl?.did) {
          this.failReconnectAuth('Could not re-establish your session (timed out). Please sign in again.');
          return;
        }
        console.warn('[freeq-sdk] Registration safety timeout — sending as guest');
        this.sasl = null;
        sendRegistration();
      }, 15000);

      const brokerToken = this.opts.brokerToken;
      const brokerBase = this.opts.brokerUrl;

      // Skip broker refresh when we have token-based credentials (the
      // broker would re-mint them anyway) OR when we have a signer
      // (did:key auth: no broker needed, no token to refresh).
      if (this.skipBrokerRefresh && (this.sasl?.token || this.sasl?.signer)) {
        this.skipBrokerRefresh = false;
        clearTimeout(safetyTimer);
        sendRegistration();
      } else if (this.sasl?.signer) {
        // did:key flow — bypass broker entirely.
        clearTimeout(safetyTimer);
        sendRegistration();
      } else if (brokerToken && brokerBase && this.sasl?.did) {
        const ctrl = new AbortController();
        const tm = setTimeout(() => ctrl.abort(), 8000);
        const brokerBody = JSON.stringify({ broker_token: brokerToken });
        const doFetch = () => fetch(`${brokerBase}/session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: brokerBody,
          signal: ctrl.signal,
        });
        const fetchWithRetry = async (): Promise<any> => {
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              const r = await doFetch();
              if (r.status === 502 && attempt < 2) {
                await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
                continue;
              }
              if (r.status === 401) throw new Error('broker token invalid');
              if (!r.ok) throw new Error('broker refresh failed');
              return r.json();
            } catch (e: any) {
              if (e?.name === 'AbortError' || attempt >= 2) throw e;
              await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
            }
          }
          throw new Error('broker fetch exhausted retries');
        };
        fetchWithRetry()
          .then((session: { token: string; nick: string; did: string; handle: string }) => {
            clearTimeout(tm);
            clearTimeout(safetyTimer);
            sendRegistration(session.token);
          })
          .catch(() => {
            clearTimeout(tm);
            clearTimeout(safetyTimer);
            if (this.sasl?.token) {
              // We still hold a (possibly stale) token — let the server be the
              // judge. If it's dead the 904 path tears down cleanly. Better to
              // try than to assume failure.
              sendRegistration();
            } else if (this.sasl?.did) {
              // Authenticated user, broker refresh failed, no token to fall
              // back on: refuse to register as a guest. Surface + teardown so
              // the app re-auths instead of silently posting as GuestNNNNN.
              this.failReconnectAuth('Could not refresh your session. Please sign in again.');
            } else {
              this.sasl = null;
              sendRegistration();
            }
          });
      } else {
        clearTimeout(safetyTimer);
        sendRegistration();
      }
    }
  }

  /** Whether a message/tag came from us. Prefers the account DID — robust to
   *  nick case and to force-renames across our own sessions, unlike a raw nick
   *  compare (a stale `_nick` made our own DM echoes look like incoming DMs,
   *  spawning a phantom self-DM buffer + notification). Falls back to nick. */
  private isSelfSender(from: string, tags?: Record<string, string>): boolean {
    const acct = tags?.['+freeq.at/account'] ?? tags?.['account'];
    if (acct && this._authDid && acct === this._authDid) return true;
    return from.toLowerCase() === this._nick.toLowerCase();
  }

  private didForNick(targetNick: string): string | undefined {
    // Internal cache first (populated from WHOIS 330 + JOIN account tags).
    // Falls back to the legacy external `nickToDid` resolver an app layer
    // may have set. New code should use the public `getDidForNick()`.
    return this._nickToDid.get(targetNick.toLowerCase()) ?? this.nickToDid?.(targetNick);
  }

  /**
   * Canonical DM identity for a peer — its DID when known, else the peer
   * unchanged (see `address.ts`). Used as BOTH the wire target we address and
   * the local buffer key we file under, so "bob" and "did:plc:bob" are one
   * conversation and a DID-addressed DM reaches the right identity on any
   * server. A guest / unresolved nick passes through, so nick DMs are intact.
   *
   * Buffer keying additionally consults the REVERSE of the display binding
   * (DID→nick, learned from the server's conversation list): for an OFFLINE
   * peer nothing this session teaches nick→DID, so without the reverse an
   * echo or incoming line addressed by nick files under a nick thread while
   * the server persists the same conversation under the DID — one person,
   * two buffers. The reverse binding is server-asserted conversation
   * identity, safe for grouping; wire ADDRESSING stays strict (didForNick
   * only) so routing semantics never ride a possibly-stale display nick.
   */
  private dmKey(peer: string): string {
    return dmPeerKey(peer, (n) => this.didForNick(n) ?? this.reverseDidForNick(n));
  }

  /** Strict resolver for wire targets: DID only when addressing-grade known. */
  private wireDmTarget(peer: string): string {
    return dmPeerKey(peer, (n) => this.didForNick(n));
  }

  /**
   * What a send addresses on the wire: a channel unchanged, a DM peer by DID
   * when we know it. Every send path resolves through here, so a target's
   * wire form cannot depend on which kind of event is being sent.
   */
  private wireTargetFor(target: string): string {
    const isChannel = target.startsWith('#') || target.startsWith('&');
    return isChannel ? target : this.wireDmTarget(target);
  }

  /** The DID whose known display nick is `nick`, if exactly that binding exists. */
  private reverseDidForNick(nick: string): string | undefined {
    const lc = nick.toLowerCase();
    for (const [did, n] of this._didToNick) {
      if (n === lc) return did;
    }
    return undefined;
  }

  /** The recipient DID for a DM target that may be a nick or already a DID. */
  private remoteDidFor(target: string): string | undefined {
    return isDid(target) ? target : this.didForNick(target);
  }

  /**
   * Learn a sender's nick↔DID binding from an inbound message's `account`
   * tag. Without this, the first DM from a peer we share no channel with (so
   * no JOIN/WHOIS taught us their DID) would key under the bare nick while
   * our own sends key under the DID — splitting one conversation in two.
   *
   * The server stamps the tag for any sender holding an account, so it is the
   * same authority as an extended JOIN and is worth learning from whatever
   * venue it arrives through — a DM, a channel, or a history replay. A peer
   * whose only appearance is one line in a channel is still a peer we can
   * name, and for a did:key, which has no profile behind it, this tag is the
   * only thing that ever will.
   *
   * `from` is always a sender, never a target; the channel guard below is
   * belt and braces against a caller that confuses the two.
   */
  private rememberSenderDid(from: string, tags?: Record<string, string>): void {
    const did = tags?.['+freeq.at/account'] ?? tags?.['account'];
    if (!did || !isDid(did) || !from || from.startsWith('#') || from.startsWith('&')) return;
    const lc = from.toLowerCase();
    const isNews = this._nickToDid.get(lc) !== did || this._didToNick.get(did) !== lc;
    this._nickToDid.set(lc, did);
    this._didToNick.set(did, lc);
    // Whatever is already on screen resolved this peer's name before we knew
    // it. Say so, or a thread keyed by the DID wears the raw DID until
    // something unrelated happens to re-render it.
    if (isNews) this.emit('memberDid', from, did);
  }

  /** Resolve nick to DID — set by the app layer for E2EE support. */
  nickToDid: ((nick: string) => string | undefined) | null = null;

  /** Parse a `+freeq.at/event=*` TAGMSG and emit `coordinationEvent`.
   *  The TAGMSG is the event — the server stores the event from it, and it
   *  carries the event's id under its own signature. A PRIVMSG carrying
   *  event tags is a rendering of the event (the human-readable companion),
   *  so it fires `message`, never `coordinationEvent`. De-dupes by eventId
   *  against echo and multi-path delivery. */
  private emitCoordinationEvent(channel: string, from: string, tags: Record<string, string>): void {
    const eventType = tags['+freeq.at/event'];
    if (!eventType) return;
    // A signed event through an adopting server arrives with the id in
    // `msgid` (the server adopts the signed id and strips the eventid tag);
    // through a server that predates adoption, in `+freeq.at/eventid`
    // verbatim; a legacy emitter's event, in its self-minted `msgid`.
    const eventId =
      tags[signing.EVENT_ID_TAG] ||
      tags['msgid'] ||
      '';
    if (eventId) {
      const now = Date.now();
      const seen = this._seenCoordinationEvents.get(eventId);
      if (seen !== undefined && now - seen < 30_000) return; // dup
      this._seenCoordinationEvents.set(eventId, now);
      // Trim periodically.
      if (this._seenCoordinationEvents.size > 1000) {
        const cutoff = now - 30_000;
        for (const [k, t] of this._seenCoordinationEvents) {
          if (t < cutoff) this._seenCoordinationEvents.delete(k);
        }
      }
    }
    // Payload is percent-encoded JSON per the wire format.
    let payload: unknown = null;
    const rawPayload = tags['+freeq.at/payload'];
    if (rawPayload) {
      try {
        payload = JSON.parse(decodeURIComponent(rawPayload));
      } catch {
        payload = null;
      }
    }
    const did = this.getDidForNick(from);
    const taskId = tags['+freeq.at/ref'] || tags['+freeq.at/task-id'];
    const evidenceType = tags['+freeq.at/evidence-type'];
    const eventPayload: CoordinationEventPayload = {
      channel,
      from,
      did,
      eventType,
      eventId,
      taskId: taskId || undefined,
      evidenceType: evidenceType || undefined,
      payload,
      tags,
    };
    this.emit('coordinationEvent', eventPayload);
  }

  /**
   * Emit `actEvent` for a TAGMSG carrying act tags.
   *
   * The TAGMSG *is* the event — the server files it from this line — and this
   * is the one place `actEvent` fires. The companion prose line is an
   * ordinary message and keeps arriving as `message` — for a history batch,
   * inside `historyBatch`, which is why the TAGMSG handler holds a batched
   * event and calls this at batch end instead.
   *
   * Deduped by event id. Three things produce the same id twice: our own echo,
   * the JOIN replay a channel hands a joiner, and the CHATHISTORY that joiner
   * asks for next. The last two are the ledger item
   * `act-events-replay-twice-to-a-joiner`, and dropping the second sighting
   * here is where it closes.
   */
  private emitActEvent(buffer: string, from: string, tags: Record<string, string>): void {
    const fields: Record<string, string> = {};
    for (const [name, value] of Object.entries(tags)) {
      if (signing.isActTag(name)) fields[signing.strippedTagName(name)] = value;
    }
    if (Object.keys(fields).length === 0) return;

    // A signed event through an adopting server arrives with the id in
    // `msgid` (the server adopts the signed id and strips the eventid tag);
    // through one that predates adoption, in `+freeq.at/eventid` verbatim.
    const eventId = tags[signing.EVENT_ID_TAG] || tags['msgid'] || '';
    if (!eventId) return;
    const now = Date.now();
    const seen = this._seenActEvents.get(eventId);
    if (seen !== undefined && now - seen < ACT_EVENT_DEDUPE_MS) return;
    this._seenActEvents.set(eventId, now);
    if (this._seenActEvents.size > 4096) {
      const cutoff = now - ACT_EVENT_DEDUPE_MS;
      for (const [k, t] of this._seenActEvents) {
        if (t < cutoff) this._seenActEvents.delete(k);
      }
    }

    // An opener carries no `act-id`: its own event id is the task's, for the
    // rest of the task's life. Every later move names that id.
    this.emit('actEvent', {
      channel: buffer,
      from,
      did: tags['+freeq.at/from'] || tags['account'] || undefined,
      kind: fields['act'] || '',
      verb: fields['act-verb'] || '',
      eventId,
      taskId: fields['act-id'] || eventId,
      fields,
      tags,
      sigTag: tags[signing.SIG_TAG] || undefined,
      replayed: tags['time'] !== undefined,
    } satisfies ActEventPayload);
  }

  /**
   * Sign an outgoing mutation — a delete, a reaction added or removed — and
   * put it on the wire with the event id the signature covers.
   *
   * A mutation is durable state asserted under a user's name, so the server
   * can act on a *proven* actor instead of a nick, and a receiving server can
   * check the claim itself rather than trusting the peer that relayed it.
   * Unsigned when there is no subject to name, no reproducible venue (a
   * bare-nick DM), or no key — and never signed at all against a server that
   * doesn't verify documents (see `SIGNING_CAP`).
   */
  private signedMutation(
    kind: 'delete' | 'react' | 'unreact',
    target: string,
    tags: Record<string, string>,
    subject?: string,
    emoji?: string,
  ): Promise<void> {
    return this.enqueueSend(() =>
      this.writeSignedMutation(kind, target, tags, subject, emoji),
    );
  }

  private async writeSignedMutation(
    kind: 'delete' | 'react' | 'unreact',
    target: string,
    tags: Record<string, string>,
    subject?: string,
    emoji?: string,
  ): Promise<void> {
    const signed =
      subject && this.ackedCaps.has(SIGNING_CAP)
        ? await this.signing.signMutation(kind, target, subject, emoji)
        : null;
    const wireTags = { ...tags };
    if (signed) {
      wireTags[signing.EVENT_ID_TAG] = signed.eventId;
      wireTags[signing.SIG_TAG] = signed.sigTag;
    }
    this.raw(format('TAGMSG', [target], wireTags));
  }

  /**
   * The signature tags for a message document, or an empty set when this send
   * goes unsigned.
   *
   * The signature covers the tags it rides with — the reply or edit reference
   * and the coordination tags — so they're read from the wire tags here, in
   * one place: a receiver rebuilds the document from those same tags, and a
   * reference the sender left out of the document reads as tampering.
   *
   * Nothing is signed against a server that never negotiated `SIGNING_CAP`:
   * it would strip our signature and re-sign the message itself, turning a
   * non-repudiable claim into its own attestation, and ignore the id we
   * minted while its tag rides on over federation.
   */
  private async signatureTags(
    target: string,
    body: string,
    tags: Record<string, string>,
  ): Promise<Record<string, string>> {
    if (!this.ackedCaps.has(SIGNING_CAP)) return {};
    const signed = await this.signing.signMessage(target, body, {
      reply: tags['+reply'] ?? tags['+draft/reply'],
      edit: tags['+draft/edit'],
      tags,
    });
    // Both tags, always together: the id is what the signature covers, and
    // the server adopts it as the message's msgid.
    return signed
      ? { [signing.EVENT_ID_TAG]: signed.eventId, [signing.SIG_TAG]: signed.sigTag }
      : {};
  }

  /**
   * Outbound sends that sign go out in the order they were called.
   *
   * Each send awaits its own signature, and signatures do not complete in the
   * order they were started — three sends fired back to back reach the wire
   * shuffled. That is invisible for independent messages and wrong for
   * dependent ones: a streaming reply edits the message it just sent, so an
   * edit overtaking a later edit leaves the reader looking at stale text for
   * good. Serializing the whole signed path costs a message's own signing
   * latency and nothing else — sends were already asynchronous.
   *
   * A task on this chain must never wait on another: `enqueue` is called by
   * the outermost signed operation only, and the helpers it calls write
   * directly.
   */
  private sendChain: Promise<unknown> = Promise.resolve();

  /**
   * Task events whose companion line is waiting on the server's word, one at
   * a time.
   *
   * Its own chain, not `sendChain`: a send waiting here holds the wire for as
   * long as the server takes to answer, and ordinary messages must not queue
   * behind that. One at a time because a `FAIL TAGMSG` names no event id —
   * the only thing that makes a refusal attributable is there being exactly
   * one send it could belong to.
   */
  private actAnswerChain: Promise<unknown> = Promise.resolve();

  /**
   * Resolves once this session's key registration has reached the wire.
   *
   * `null` whenever no registration is coming — a guest, a server that never
   * acked the capability, `autoMsgSig: false`. A send must never wait on a
   * registration that will never happen, so the absence is the release.
   *
   * The window this closes: the session key is generated asynchronously and
   * `MSGSIG` goes out when that resolves, which is after `001`. A client that
   * emitted the moment it was registered therefore raced its own key — going
   * out unsigned, or signed with a key the server had not been told about and
   * so could not resolve. The Rust SDK writes `MSGSIG` before draining the
   * commands it queued; this is the same ordering, expressed through the
   * chain every signed send already takes its turn on.
   */
  private msgSigReady: Promise<void> | null = null;
  private releaseMsgSigReady: (() => void) | null = null;

  /** Arm the gate: sends now wait for the key registration. */
  private awaitMsgSigRegistration(): void {
    this.releaseMsgSigReady?.();
    this.msgSigReady = new Promise<void>((resolve) => {
      this.releaseMsgSigReady = resolve;
    });
  }

  /** Open the gate, whether or not a key actually materialized. */
  private msgSigRegistered(): void {
    this.releaseMsgSigReady?.();
    this.releaseMsgSigReady = null;
    this.msgSigReady = null;
  }

  private enqueueSend(run: () => Promise<void>): Promise<void> {
    // Read the gate when the turn comes up, not when it is taken: a send
    // queued before registration must honour the gate armed after it.
    const gated = async (): Promise<void> => {
      if (this.msgSigReady) await this.msgSigReady;
      return run();
    };
    const next = this.sendChain.then(gated, gated);
    // A failed send must not wedge every send after it.
    this.sendChain = next.catch(() => undefined);
    return next;
  }

  private signedPrivmsg(target: string, text: string, extraTags?: Record<string, string>): Promise<void> {
    return this.enqueueSend(() => this.writeSignedMessage('PRIVMSG', target, text, extraTags));
  }

  /**
   * A message on the wire, signed. `NOTICE` and `PRIVMSG` sign the same
   * document — the canonical binds who said what, where, and under which id,
   * and says nothing about which verb carried it.
   *
   * Writes immediately; ordering is the caller's, through `enqueueSend`.
   */
  private async writeSignedMessage(
    command: 'PRIVMSG' | 'NOTICE',
    target: string,
    text: string,
    extraTags?: Record<string, string>,
  ): Promise<void> {
    const tags: Record<string, string> = { ...extraTags };
    Object.assign(tags, await this.signatureTags(target, text, tags));
    if (Object.keys(tags).length > 0) {
      this.raw(format(command, [target, text], tags));
    } else {
      this.raw(`${command} ${target} :${text}`);
    }
  }

  private cacheEchoPlaintext(ciphertext: string, plaintext: string): void {
    this.echoPlaintextCache.set(ciphertext, { plaintext, ts: Date.now() });
    if (this.echoPlaintextCache.size > 100) {
      const now = Date.now();
      for (const [k, v] of this.echoPlaintextCache) {
        if (now - v.ts > 60_000) this.echoPlaintextCache.delete(k);
      }
    }
  }

  // ── draft/multiline helpers ──

  /**
   * Parse the cap params advertised as `draft/multiline=max-bytes=N,max-lines=M`.
   * Captures server policy so the chunker doesn't exceed it.
   */
  private parseMultilineCapParams(params: string): void {
    for (const part of params.split(',')) {
      const [k, v] = part.split('=');
      const n = Number(v);
      if (!Number.isFinite(n) || n <= 0) continue;
      if (k === 'max-bytes') this.multilineMaxBytes = n;
      else if (k === 'max-lines') this.multilineMaxLines = n;
    }
  }

  /** Mint a unique BATCH id for an outbound multiline send. */
  private mintBatchId(): string {
    this.nextBatchSeq = (this.nextBatchSeq + 1) & 0x7fffffff;
    return `ml${this.nextBatchSeq.toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
  }

  /**
   * Assemble the chunks of a closed `draft/multiline` batch per spec
   * concat rules: a chunk with `draft/multiline-concat` is joined to
   * the predecessor with no separator; otherwise joined with `\n`.
   */
  private assembleMultiline(lines: Array<{ body: string; concat: boolean }>): string {
    let result = '';
    for (let i = 0; i < lines.length; i++) {
      const { body, concat } = lines[i];
      if (i > 0 && !concat) result += '\n';
      result += body;
    }
    return result;
  }

  /**
   * Emit a `draft/multiline` BATCH on the wire. `chunks` are already
   * sized to fit in a PRIVMSG line. `openerTags` go on the BATCH opener
   * (e.g. commit-reveal client-tags); `+encrypted` rides on each chunk.
   * Returns the BATCH id used.
   */
  private emitMultilineBatch(
    target: string,
    chunks: Array<{ body: string; concat: boolean }>,
    openerTags: Record<string, string> = {},
    perChunkTags: Record<string, string> = {},
  ): string {
    const batchId = this.mintBatchId();
    this.raw(format('BATCH', [`+${batchId}`, 'draft/multiline', target], openerTags));
    for (const c of chunks) {
      const tags: Record<string, string> = { ...perChunkTags, batch: batchId };
      if (c.concat) tags['draft/multiline-concat'] = '';
      this.raw(format('PRIVMSG', [target, c.body], tags));
    }
    this.raw(format('BATCH', [`-${batchId}`]));
    return batchId;
  }

  /**
   * Close-time handler for an assembled `draft/multiline` batch.
   * Concatenates the chunks per spec rules, decrypts if the assembled
   * body is ENC1/ENC3, builds a synthetic `Message` carrying the
   * opener's identity (msgid, time, sender, etc.), and either emits it
   * as a top-level `message` event or pushes it into the parent batch
   * if the multiline was nested (e.g. inside a CHATHISTORY batch).
   */
  private async dispatchAssembledMultiline(batch: Batch): Promise<void> {
    const lines = batch.multilineLines ?? [];
    const openerTags = batch.openerTags ?? {};
    const from = batch.openerFrom ?? '';
    const target = batch.target;
    const isChannel = target.startsWith('#') || target.startsWith('&');
    const isSelf = this.isSelfSender(from, openerTags);
    if (!isSelf) this.rememberSenderDid(from, openerTags);
    // DM thread key = the peer's canonical DID when known (else the nick):
    // our own echo is keyed by the wire target, an incoming DM by the sender,
    // and both collapse to the same DID so a conversation is never split.
    const bufName = isChannel ? target : this.dmKey(isSelf ? target : from);

    const wireText = this.assembleMultiline(lines);

    // Decryption — match the single-PRIVMSG path's logic exactly,
    // but applied to the assembled body so ciphertext-chunked E2EE
    // messages decrypt in one shot.
    let displayText = wireText;
    let isEncryptedMsg = false;

    const cachedPlain = this.echoPlaintextCache.get(wireText);
    if (cachedPlain && isSelf) {
      displayText = cachedPlain.plaintext;
      isEncryptedMsg = true;
      this.echoPlaintextCache.delete(wireText);
    } else if (e2ee.isENC1(wireText) && isChannel) {
      const plain = await e2ee.decryptChannel(target, wireText);
      if (plain !== null) { displayText = plain; isEncryptedMsg = true; }
      else { displayText = '[encrypted message]'; isEncryptedMsg = true; }
    } else if (e2ee.isEncrypted(wireText) && !isChannel && !isSelf) {
      const remoteDid = this.didForNick(from);
      if (remoteDid) {
        const plain = await e2ee.decryptMessage(remoteDid, wireText, this.serverOrigin);
        if (plain !== null) { displayText = plain; isEncryptedMsg = true; }
        else { displayText = '[encrypted DM — could not decrypt]'; isEncryptedMsg = true; }
      } else {
        displayText = '[encrypted DM — unknown sender identity]'; isEncryptedMsg = true;
      }
    } else if (e2ee.isEncrypted(wireText) && !isChannel && isSelf) {
      displayText = '[encrypted message]'; isEncryptedMsg = true;
    }
    if (openerTags['+encrypted']) isEncryptedMsg = true;

    const isAction = displayText.startsWith('\x01ACTION ') && displayText.endsWith('\x01');
    if (isAction) displayText = displayText.slice(8, -1);

    const message: Message = {
      id: openerTags['msgid'] || crypto.randomUUID(),
      from,
      text: displayText,
      timestamp: openerTags['time'] ? new Date(openerTags['time']) : new Date(),
      tags: openerTags,
      isAction,
      isSelf,
      replyTo: openerTags['+reply'],
      encrypted: isEncryptedMsg,
      isStreaming: openerTags['+freeq.at/streaming'] === '1',
    };

    // Persisted reactions from CHATHISTORY replay (multiline-nested case)
    const reactionsTag = openerTags['+freeq.at/reactions'];
    if (reactionsTag && message.id) {
      for (const part of reactionsTag.split(';')) {
        const [emoji, nicks] = part.split(':');
        if (emoji && nicks) {
          for (const n of nicks.split(',')) {
            if (n) {
              message.reactions = message.reactions || new Map();
              const set = message.reactions.get(emoji) || new Set();
              set.add(n);
              message.reactions.set(emoji, set);
            }
          }
        }
      }
    }

    // Edits ride through `messageEdited` regardless of how they arrived
    if (openerTags['+draft/edit']) {
      const isStreaming = openerTags['+freeq.at/streaming'] === '1';
      this.emit(
        'messageEdited',
        bufName,
        openerTags['+draft/edit'],
        displayText,
        openerTags['msgid'],
        isStreaming,
        from,
        openerTags['account'],
      );
      return;
    }

    // A multiline companion carrying event tags is a rendering of its event,
    // not the event: the TAGMSG already fired `coordinationEvent`.

    // If this batch was nested inside a parent (CHATHISTORY most likely),
    // push the assembled message into the parent's message list instead
    // of emitting it as a top-level event.
    if (batch.parentBatchId) {
      const parent = this.batches.get(batch.parentBatchId);
      if (parent) {
        parent.messages.push(message);
        return;
      }
    }

    this.emit('message', bufName, message);

    const isMention = !message.isSelf && displayText.toLowerCase().includes(this._nick.toLowerCase());
    const isDM = !isChannel && !message.isSelf;
    if (isMention || isDM) {
      this.emit('systemMessage', '__mention__', JSON.stringify({
        channel: bufName, from, text: displayText, isDM, isMention,
      }));
    }
  }

  /**
   * Chunk a body into lines respecting `max-bytes` per chunk and the
   * `max-lines` per batch ceiling. Two strategies:
   *
   *   - `concatChunks=false`: chunk on `\n` boundaries; each source line
   *     becomes one chunk (no `draft/multiline-concat`). If a single
   *     source line exceeds the byte budget it is hard-split with concat
   *     so the assembled body is byte-identical.
   *   - `concatChunks=true`: chunk on byte boundaries only (used for
   *     ciphertext-chunking E2EE messages — there are no logical line
   *     breaks to honor).
   */
  private chunkMultilineBody(
    body: string,
    perChunkBudget: number,
    concatChunks: boolean,
  ): Array<{ body: string; concat: boolean }> {
    const out: Array<{ body: string; concat: boolean }> = [];
    // Split one logical piece (a source line, or the whole body in
    // concat mode) into byte-sized chunks. The first piece inherits the
    // caller's `firstConcat`; later pieces of the SAME source line are
    // concat=true so reassembly re-fuses them with no separator.
    const pushSplit = (s: string, firstConcat: boolean) => {
      let pos = 0;
      while (pos < s.length) {
        const take = Math.min(perChunkBudget, s.length - pos);
        out.push({ body: s.slice(pos, pos + take), concat: pos === 0 ? firstConcat : true });
        pos += take;
      }
    };
    if (concatChunks) {
      // Ciphertext-style: one logical blob; every wire chunk fuses with
      // no separator on reassembly. First piece's concat is irrelevant
      // (no predecessor); leave it `false`.
      pushSplit(body, false);
      return out;
    }
    // Plaintext multiline: split on `\n`. Each source line opens a new
    // chunk with concat=false so reassembly inserts the `\n` back.
    for (const sourceLine of body.split('\n')) {
      // An empty source line (a blank line / paragraph break) must still
      // emit a chunk. `pushSplit('')` produces nothing, which would drop
      // the blank line on reassembly — breaking byte-exact round-trip:
      // rendering loses paragraph spacing, and commit-reveal hashes over
      // the original (blank lines intact) no longer match the reassembled
      // reveal body. Emit an explicit empty, non-concat chunk so assembly
      // re-inserts the `\n`.
      if (sourceLine.length === 0) {
        out.push({ body: '', concat: false });
      } else {
        pushSplit(sourceLine, false);
      }
    }
    return out;
  }

  /**
   * Partition already-sized chunk lines into batches that each respect
   * the server's `max-lines` and `max-bytes` ceilings. A message that
   * doesn't fit one batch becomes several — each emitted as its own
   * BATCH (its own logical message), rather than collapsed into a single
   * oversized line the server would truncate.
   *
   * Group boundaries fall only on a real line start (`concat === false`)
   * so a hard-split source line (its continuations carry `concat`) is
   * never severed across two messages. Byte accounting uses string
   * `.length`, matching the rest of the multiline sizing (`perChunkBudget`,
   * the `max-bytes` guard) — exact for the ASCII-heavy pastes this fixes.
   */
  private groupChunksIntoBatches(
    chunks: Array<{ body: string; concat: boolean }>,
  ): Array<Array<{ body: string; concat: boolean }>> {
    const groups: Array<Array<{ body: string; concat: boolean }>> = [];
    let cur: Array<{ body: string; concat: boolean }> = [];
    let curLen = 0;
    for (const c of chunks) {
      const sep = cur.length > 0 && !c.concat ? 1 : 0; // '\n' re-added on assembly
      const startsNewBatch =
        cur.length > 0 &&
        !c.concat &&
        (cur.length + 1 > this.multilineMaxLines ||
          curLen + sep + c.body.length > this.multilineMaxBytes);
      if (startsNewBatch) {
        groups.push(cur);
        cur = [];
        curLen = 0;
      }
      curLen += (cur.length > 0 && !c.concat ? 1 : 0) + c.body.length;
      cur.push(c);
    }
    if (cur.length) groups.push(cur);
    return groups;
  }

  private async handleLine(rawLine: string): Promise<void> {
    const msg = parse(rawLine);
    const from = prefixNick(msg.prefix);

    this.emit('raw', rawLine, msg);

    switch (msg.command) {
      case 'CAP':
        this.handleCap(msg);
        break;

      case 'AUTHENTICATE':
        await this.handleAuthenticate(msg);
        break;

      case '900':
        this._authDid = this.sasl?.did ?? null;
        this.emit('authenticated', this._authDid || '', msg.params[msg.params.length - 1]);
        if (this._authDid) {
          prefetchProfiles([this._authDid]);
          e2ee.initialize(this._authDid, this.serverOrigin).catch((e) =>
            console.warn('[e2ee] Init failed:', e)
          );
        }
        break;

      case '903':
        // Auto-mint a per-session ed25519 signing key and register it via
        // MSGSIG. Some consumers (Node-side bots, agents that already hold
        // their own signing key) want to skip this; opt out via
        // FreeqClientOptions.autoMsgSig=false.
        //
        // Only where the key can be used: a server that never negotiated the
        // signing cap cannot verify a client document, so registering with it
        // files a public key it will never read — and the command itself is
        // one an older server has no reason to know, which is exactly what
        // capability gating exists to avoid saying. Cap negotiation is settled
        // by the time authentication succeeds, so the answer is known here.
        if (this.sasl?.did && this.opts.autoMsgSig !== false && this.ackedCaps.has(SIGNING_CAP)) {
          this.signing.setSigningDid(this.sasl.did);
          // Minted here, REGISTERED on 001. MSGSIG sent before registration
          // completes is discarded by the server (`if !conn.registered`),
          // which left the key unregistered and every "client-signed"
          // message silently server-signed instead.
          this.pendingMsgSig = this.signing.generateSigningKey();
          // From here until MSGSIG is on the wire, a signing send waits.
          this.awaitMsgSigRegistration();
        }
        this.raw('CAP END');
        break;

      case '904': {
        // SASL failed. The user expected to be authenticated, but our
        // credentials (often a token that went stale during an idle
        // reconnect) didn't validate. The server will now finish IRC
        // registration and force-rename us to GuestNNNNN since the nick
        // is registered to a DID we can't prove ownership of.
        //
        // We MUST NOT silently let registration complete as a guest:
        // the user would post messages under the guest identity while
        // the UI still shows them as authenticated. Drop the dead
        // credentials and intentionally tear the socket down so the
        // app can re-auth (or explicitly choose guest mode) instead of
        // racing the next reconnect with the same dead token.
        const reason = msg.params[msg.params.length - 1] || 'SASL failed';
        const hadSaslAttempt = !!this.sasl?.token;
        this.sasl = null;
        this._authDid = null;
        this._apiBearer = null;
        this.emit('authError', reason);
        // Mirror the wire identity to the app: did is now empty.
        this.emit('authenticated', '', reason);
        if (hadSaslAttempt) {
          // Refuse to register as a guest on a connection where SASL
          // was requested. Mark _saslFailed so any in-flight 001 from
          // the server is suppressed (the WS may still deliver buffered
          // lines for a moment after close), and tear down the socket
          // so the next user action is an explicit re-auth.
          this._saslFailed = true;
          this.transport?.disconnect();
          this.transport = null;
          this._connectionState = 'disconnected';
          this.emit('connectionStateChanged', 'disconnected');
        } else {
          this.raw('CAP END');
        }
        break;
      }

      case 'PING':
        this.raw(`PONG :${msg.params[0] || ''}`);
        break;

      case 'ERROR': {
        const reason = msg.params[0] || '';
        this.emit('error', reason);
        if (reason.includes('same identity reconnected')) {
          this.transport?.disconnect();
        }
        break;
      }

      case '001': {
        const serverNick = msg.params[0] || this._nick;
        // If SASL failed on this socket, suppress any in-flight 001
        // from the server. We've already torn the socket down; do not
        // let the app think we registered as the assigned Guest nick.
        if (this._saslFailed) break;
        this.guestFallbackCount = 0;
        this._nick = serverNick;
        this._registered = true;
        this._hadSession = true;
        this._awaitingWelcome = false;
        this.clearNickResume();
        this.emit('registered', this._nick);
        this.emit('nickChanged', this._nick);

        // Register the session signing key now that the server will accept it.
        if (this.pendingMsgSig) {
          const pending = this.pendingMsgSig;
          this.pendingMsgSig = null;
          pending.then(
            (pubkey) => {
              if (pubkey) this.raw(`MSGSIG ${pubkey}`);
              // Released either way: a key this platform could not generate
              // is a reason to send unsigned, never a reason to stop sending.
              this.msgSigRegistered();
            },
            () => this.msgSigRegistered(),
          );
        }

        const toJoin = this.autoJoinChannels.length > 0
          ? this.autoJoinChannels
          : (this.sasl?.did ? [] : (this._joinedChannels.size > 0 ? [...this._joinedChannels] : ['#freeq']));
        if (!this.sasl?.did && toJoin.length === 0) toJoin.push('#freeq');
        for (const ch of toJoin) {
          if (ch.trim()) this.raw(`JOIN ${ch.trim()}`);
        }
        this.autoJoinChannels = [];
        if (this.sasl?.did) this.requestHistoryTargets();
        // Re-assert AWAY across reconnects so the server stops thinking
        // we're present. We deliberately re-send even on the first 001
        // if _currentAway was set earlier; it's a no-op if we weren't
        // away.
        if (this._currentAway !== null) {
          this.raw(`AWAY :${this._currentAway}`);
        }
        this.emit('ready');
        break;
      }

      case '433': {
        // 433 ERR_NICKNAMEINUSE.
        // On an automatic reconnect the nick in use is usually our own,
        // still held by the previous session the server hasn't reaped yet.
        // Ask for it again on a short backoff before renaming ourselves —
        // for a guest, a rename is a change of identity.
        if (this.shouldResumeNick()) {
          const delay = GUEST_NICK_RESUME_DELAYS_MS[this._nickResumeAttempts];
          this._nickResumeAttempts++;
          this._nickResumeTimer = setTimeout(() => {
            this._nickResumeTimer = null;
            this.raw(`NICK ${this._nick}`);
          }, delay);
          break;
        }
        // Retries exhausted (or not a reconnect): apply onNickCollision policy.
        const policy = this.opts.onNickCollision ?? 'auto-suffix';
        if (policy === 'refuse') {
          this.emit('authError', `nick '${this._nick}' is already taken`);
          this.transport?.disconnect();
          this.transport = null;
          this._connectionState = 'disconnected';
          this.emit('connectionStateChanged', 'disconnected');
        } else if (policy === 'random-suffix') {
          const MAX_RETRIES = 3;
          if (this._nickCollisionRetries >= MAX_RETRIES) {
            this.emit('authError', `exhausted ${MAX_RETRIES} nick collision retries for '${this.opts.nick}'`);
            this.transport?.disconnect();
            this.transport = null;
            this._connectionState = 'disconnected';
            this.emit('connectionStateChanged', 'disconnected');
            break;
          }
          this._nickCollisionRetries++;
          const suffix = Math.floor(1000 + Math.random() * 9000).toString();
          this._nick = `${this.opts.nick}-${suffix}`;
          this.raw(`NICK ${this._nick}`);
        } else {
          // auto-suffix (legacy default): append `_` and retry.
          this._nick += '_';
          this.raw(`NICK ${this._nick}`);
        }
        break;
      }

      case 'NICK': {
        const newNick = msg.params[0];
        if (from.toLowerCase() === this._nick.toLowerCase()) {
          this._nick = newNick;
          this.emit('nickChanged', this._nick);
        }
        this.emit('userRenamed', from, newNick);
        break;
      }

      case 'JOIN': {
        const channel = msg.params[0];
        const account = msg.params[1];
        const isSelf = from.toLowerCase() === this._nick.toLowerCase();
        if (isSelf) {
          this._joinedChannels.add(channel.toLowerCase());
          this.emit('channelJoined', channel);
          this.emit('membersCleared', channel);
          this.fetchPins(channel);
        }
        const joinDid = account && account !== '*' ? account : undefined;
        const actorClass = (msg.tags?.['freeq.at/actor-class'] || msg.tags?.['+freeq.at/actor-class']) as Member['actorClass'] | undefined;
        this.emit('memberJoined', channel, { nick: from, did: joinDid, actorClass });
        if (joinDid) {
          prefetchProfiles([joinDid]);
          // Populate internal nick↔DID cache (account-notify tag carries DID).
          const lc = from.toLowerCase();
          this._nickToDid.set(lc, joinDid);
          this._didToNick.set(joinDid, lc);
        }
        // Spawned-agent broadcast (`+freeq.at/parent=<nick>` indicates
        // a child agent joining the channel; see server connection/mod.rs
        // SPAWN handler).
        const parent = msg.tags['+freeq.at/parent'];
        if (parent) {
          this.emit('agentSpawned', {
            parentNick: parent,
            childNick: from,
            channel,
            capabilities: [],
            ttlSeconds: undefined,
            taskRef: undefined,
          });
        }
        this.emit('systemMessage', channel, `${from} joined`);
        break;
      }

      case 'PART': {
        const channel = msg.params[0];
        if (from.toLowerCase() === this._nick.toLowerCase()) {
          this._joinedChannels.delete(channel.toLowerCase());
          this.emit('channelLeft', channel);
        } else {
          this.emit('memberLeft', channel, from);
          this.emit('systemMessage', channel, `${from} left`);
        }
        break;
      }

      case 'QUIT': {
        const reason = msg.params[0] || '';
        this.emit('userQuit', from, reason);
        // Spawned-child despawn pattern: hostmask is `*!spawn@freeq/spawn*`
        // when the server tears down a TTL'd or explicitly despawned
        // child agent. Mirror to `agentDespawned`.
        if (msg.prefix.includes('!spawn@freeq/spawn')) {
          this.emit('agentDespawned', { nick: from, reason: reason || undefined });
        }
        // Forget the nick→DID binding: a released nick can be recycled by
        // someone else, and addressing must never follow a stale one. Keep
        // did→nick — a DID is permanent and that direction is display-only,
        // so an offline peer still shows a name instead of a raw did:… string
        // (a rename overwrites it on the next JOIN/WHOIS).
        this._nickToDid.delete(from.toLowerCase());
        break;
      }

      case 'KICK': {
        const channel = msg.params[0];
        const kicked = msg.params[1];
        const reason = msg.params[2] || '';
        if (kicked.toLowerCase() === this._nick.toLowerCase()) {
          this._joinedChannels.delete(channel.toLowerCase());
          this.emit('channelLeft', channel);
          this.emit('systemMessage', 'server', `Kicked from ${channel} by ${from}: ${reason}`);
        } else {
          this.emit('userKicked', channel, kicked, from, reason);
          this.emit('systemMessage', channel, `${kicked} kicked by ${from}${reason ? `: ${reason}` : ''}`);
        }
        break;
      }

      case 'PRIVMSG': {
        const target = msg.params[0];
        const text = msg.params[1] || '';
        const isAction = text.startsWith('\x01ACTION ') && text.endsWith('\x01');
        const isChannel = target.startsWith('#') || target.startsWith('&');
        const isSelf = this.isSelfSender(from, msg.tags);
        if (!isSelf) this.rememberSenderDid(from, msg.tags);
        // DM thread key = the peer's canonical DID when known (else the nick):
        // our own echo is keyed by the wire target, an incoming DM by the
        // sender, and both collapse to the same DID so a conversation is
        // never split.
        const bufName = isChannel ? target : this.dmKey(isSelf ? target : from);

        // If this PRIVMSG is a chunk of an open `draft/multiline` batch,
        // accumulate it raw and defer ALL processing (decryption,
        // coordination events, reactions, message emission) until the
        // BATCH closer fires. Decrypting per-chunk would fail for
        // ciphertext-chunked E2EE messages — each fragment is a slice
        // of one AES-GCM ciphertext and only the assembled blob decrypts.
        const inboundBatchId = msg.tags['batch'];
        if (inboundBatchId) {
          const batch = this.batches.get(inboundBatchId);
          if (batch && batch.type === 'draft/multiline') {
            batch.multilineLines = batch.multilineLines || [];
            batch.multilineLines.push({
              body: text,
              // Per IRCv3 multiline + the freeq server, the concat tag is
              // `draft/multiline-concat` (no `+` client-tag prefix — the server
              // processes it). Reading `+draft/...` here silently lost concat
              // on any line >6400B, injecting a raw \n at the split boundary.
              concat: 'draft/multiline-concat' in msg.tags,
            });
            break;
          }
        }

        // A PRIVMSG carrying event tags is the event's human-readable
        // companion — a rendering, not the event. The TAGMSG is the event
        // and the only thing that fires `coordinationEvent`; this fires the
        // regular `message` event below so the text renders normally.

        let displayText = isAction ? text.slice(8, -1) : text;
        let isEncryptedMsg = false;

        const cachedPlain = this.echoPlaintextCache.get(text);
        if (cachedPlain && isSelf) {
          displayText = cachedPlain.plaintext;
          isEncryptedMsg = true;
          this.echoPlaintextCache.delete(text);
        } else if (e2ee.isENC1(text) && isChannel) {
          const plain = await e2ee.decryptChannel(target, text);
          if (plain !== null) { displayText = plain; isEncryptedMsg = true; }
          else { displayText = '[encrypted message]'; isEncryptedMsg = true; }
        } else if (e2ee.isEncrypted(text) && !isChannel && !isSelf) {
          const remoteDid = this.didForNick(from);
          if (remoteDid) {
            const plain = await e2ee.decryptMessage(remoteDid, text, this.serverOrigin);
            if (plain !== null) { displayText = plain; isEncryptedMsg = true; }
            else { displayText = '[encrypted DM — could not decrypt]'; isEncryptedMsg = true; }
          } else {
            displayText = '[encrypted DM — unknown sender identity]'; isEncryptedMsg = true;
          }
        } else if (e2ee.isEncrypted(text) && !isChannel && isSelf) {
          displayText = '[encrypted message]'; isEncryptedMsg = true;
        }
        if (msg.tags['+encrypted']) isEncryptedMsg = true;

        // `+freeq.at/multiline` is a freeq-specific tag that encodes
        // `\n` as the literal two chars `\\n` in a single PRIVMSG.
        // Normalize so consumers always see real `\n`.
        if ('+freeq.at/multiline' in msg.tags) {
          displayText = displayText.replace(/\\n/g, '\n');
        }

        // Edits dispatch as a dedicated event AFTER decrypt so that
        // E2EE edits arrive with plaintext, not raw ciphertext. (Prior
        // bug: edit branched before the decrypt block, so receivers
        // saw `ENC1:…` in place of the edited body.)
        const editOf = msg.tags['+draft/edit'];
        if (editOf) {
          // A replayed edit inside a CHATHISTORY batch collapses into the
          // batch itself, so `historyBatch` hands the app a final
          // transcript. Emitting mid-batch raced the batch delivery: the
          // app's store had nothing to apply the edit to yet (fresh
          // session) and dropped it — or, in older builds, rendered the
          // edit as a stacked duplicate row. `editOf` is anchored to the
          // ROOT of an edit chain so chained edits keep matching.
          const editBatchId = msg.tags['batch'];
          const editBatch = editBatchId ? this.batches.get(editBatchId) : undefined;
          if (editBatch && editBatch.type !== 'draft/multiline') {
            // Reactions attach to the msgid the user reacted to — usually
            // the latest edit id — so replay delivers them ON the edit row.
            // The collapse must carry them, or reactions on edited messages
            // vanish every reload.
            let editReactions: Map<string, Set<string>> | undefined;
            const reactionsTag = msg.tags['+freeq.at/reactions'];
            if (reactionsTag) {
              editReactions = new Map();
              for (const part of reactionsTag.split(';')) {
                const [emoji, nicks] = part.split(':');
                if (emoji && nicks) {
                  const set = editReactions.get(emoji) ?? new Set<string>();
                  for (const n of nicks.split(',')) if (n) set.add(n);
                  editReactions.set(emoji, set);
                }
              }
            }
            const idx = editBatch.messages.findIndex(
              (m) => m.id === editOf || m.editOf === editOf,
            );
            if (idx >= 0) {
              const prev = editBatch.messages[idx];
              const mergedReactions = editReactions
                ? new Map([...(prev.reactions ?? new Map()), ...editReactions])
                : prev.reactions;
              editBatch.messages[idx] = {
                ...prev,
                text: displayText,
                // The id does NOT move to the edit's. A message keeps the id
                // it was born with, so anything holding a reference to it —
                // a reaction, a pending delete, a reply — still resolves.
                editOf: prev.editOf ?? editOf,
                ...(mergedReactions ? { reactions: mergedReactions } : {}),
              };
              break;
            }
            // Original row absent from this batch window — deliver the
            // edit as its own row rather than losing the content, keyed by
            // the message's identity rather than this revision's wire id.
            editBatch.messages.push({
              id: editOf,
              from,
              text: displayText,
              timestamp: msg.tags['time'] ? new Date(msg.tags['time']) : new Date(),
              tags: msg.tags,
              isSelf,
              editOf,
              ...(editReactions ? { reactions: editReactions } : {}),
            });
            break;
          }
          const isStreaming = msg.tags['+freeq.at/streaming'] === '1';
          this.emit('messageEdited', bufName, editOf, displayText, msg.tags['msgid'], isStreaming, from, msg.tags['account']);
          break;
        }

        const message: Message = {
          id: msg.tags['msgid'] || crypto.randomUUID(),
          from,
          text: displayText,
          timestamp: msg.tags['time'] ? new Date(msg.tags['time']) : new Date(),
          tags: msg.tags,
          isAction,
          isSelf,
          replyTo: msg.tags['+reply'],
          encrypted: isEncryptedMsg,
          isStreaming: msg.tags['+freeq.at/streaming'] === '1',
        };

        // Parse persisted reactions from CHATHISTORY
        const reactionsTag = msg.tags['+freeq.at/reactions'];
        if (reactionsTag && message.id) {
          for (const part of reactionsTag.split(';')) {
            const [emoji, nicks] = part.split(':');
            if (emoji && nicks) {
              for (const n of nicks.split(',')) {
                if (n) {
                  message.reactions = message.reactions || new Map();
                  const set = message.reactions.get(emoji) || new Set();
                  set.add(n);
                  message.reactions.set(emoji, set);
                }
              }
            }
          }
        }

        // Background WHOIS for DM partners
        if (!isChannel && !isSelf && !this.didForNick(from) && !this.backgroundWhois.has(from.toLowerCase()) && this.backgroundWhois.size < 500) {
          this.backgroundWhois.add(from.toLowerCase());
          this.raw(`WHOIS ${from}`);
        }

        // Check if this message belongs to a batch
        const batchId = msg.tags['batch'];
        if (batchId) {
          const batch = this.batches.get(batchId);
          if (batch) {
            batch.messages.push(message);
            break;
          }
          // A line naming a batch we never saw opened is still a replay: the
          // envelope was missed, not the line. It goes over as history, which
          // the app files by time, rather than as something just said.
          this.emit('historyBatch', bufName, [message]);
          break;
        }

        this.emit('message', bufName, message);

        // Mention detection
        const isMention = !message.isSelf && text.toLowerCase().includes(this._nick.toLowerCase());
        const isDM = !isChannel && !message.isSelf;
        if (isMention || isDM) {
          // Emitted so the app can show notifications / increment badges
          this.emit('systemMessage', '__mention__', JSON.stringify({ channel: bufName, from, text, isDM, isMention }));
        }
        break;
      }

      case 'FAIL': {
        // A refused CHATHISTORY is answered by this line and by no batch, so
        // the request it refuses has to leave the queue here or the queue for
        // that target stays one behind for the rest of the connection and
        // every later batch is labelled with the request before it.
        if (msg.params[0] === 'CHATHISTORY') this.dropRefusedHistoryRequest(msg.params);
        // IRCv3 FAIL — surface to the app. A silent server rejection is
        // indistinguishable from a client bug at the UI (and has cost
        // real debugging time); the app renders these as system messages.
        this.emit('serverFail', msg.params.join(' '));
        break;
      }

      case 'NOTICE': {
        const target = msg.params[0];
        const text = msg.params[1] || '';
        const buf = target === '*' || target === this._nick ? 'server' : target;

        const noticeActorClass = (msg.tags?.['freeq.at/actor-class'] || msg.tags?.['+freeq.at/actor-class']) as Member['actorClass'] | undefined;
        if (noticeActorClass && from && (target.startsWith('#') || target.startsWith('&'))) {
          this.emit('memberJoined', target, { nick: from, actorClass: noticeActorClass });
        }

        // API bearer (sent by the server immediately after SASL success).
        // Capture so the bot can use the same identity it just authenticated
        // to IRC with when calling the /agent/tools/* HTTP surface. The
        // bearer is the bot's IRC session_id, which only the server knows;
        // without this NOTICE there's no production path for a bot to
        // discover its own bearer.
        const bearerMatch = text.match(/^API-BEARER (\S+)$/);
        if (bearerMatch) {
          this._apiBearer = bearerMatch[1];
          // Publishing a pre-key bundle means proving we own the DID we
          // publish under, and this bearer is that proof. It lands either
          // side of e2ee.initialize (started on 900) finishing, so hand it
          // over and let e2ee publish whenever it can.
          e2ee.setAuthToken(this._apiBearer);
          break; // suppress; do not surface to systemMessage
        }

        // AV ticket
        const ticketMatch = text.match(/^AV ticket: (.+)$/);
        if (ticketMatch) {
          const activeId = this._activeAvSession;
          if (activeId) this.emit('avTicket', activeId, ticketMatch[1]);
          break;
        }

        // Pin/unpin sync
        const pinMsgid = msg.tags?.['+freeq.at/pin'];
        const unpinMsgid = msg.tags?.['+freeq.at/unpin'];
        if (pinMsgid && (target.startsWith('#') || target.startsWith('&'))) {
          this.emit('pinAdded', target, pinMsgid, from);
        }
        if (unpinMsgid && (target.startsWith('#') || target.startsWith('&'))) {
          this.emit('pinRemoved', target, unpinMsgid);
        }

        const isAction = text.startsWith('\x01ACTION ') && text.endsWith('\x01');
        if (isAction) {
          this.emit('systemMessage', buf, `${from} ${text.slice(8, -1)}`);
        } else {
          this.emit('systemMessage', buf, `[${from || 'server'}] ${text}`);
        }
        break;
      }

      case 'TAGMSG': {
        const target = msg.params[0];
        const isChannel = target.startsWith('#') || target.startsWith('&');
        const isSelf = this.isSelfSender(from, msg.tags);
        if (!isSelf) this.rememberSenderDid(from, msg.tags);
        // DM thread key = the peer's canonical DID when known (else the nick):
        // our own echo is keyed by the wire target, an incoming DM by the
        // sender, and both collapse to the same DID so a conversation is
        // never split.
        const bufName = isChannel ? target : this.dmKey(isSelf ? target : from);

        const deleteOf = msg.tags['+draft/delete'];
        if (deleteOf) { this.emit('messageDeleted', bufName, deleteOf, from, msg.tags['account']); break; }

        const reaction = msg.tags['+react'];
        if (reaction) {
          const reactTarget = msg.tags['+reply'];
          if (reactTarget) {
            this.emit('reactionAdded', bufName, reactTarget, reaction, from);
          }
        }

        const unreact = msg.tags['+freeq.at/unreact'];
        if (unreact) {
          const unreactTarget = msg.tags['+reply'];
          if (unreactTarget) {
            this.emit('reactionRemoved', bufName, unreactTarget, unreact, from);
          }
        }

        const typing = msg.tags['+typing'];
        if (typing) {
          this.emit('typing', bufName, from, typing === 'active');
        }

        // Governance signal (TAGMSG to a specific nick, usually us).
        const govSignal = msg.tags['+freeq.at/governance'];
        if (govSignal) {
          const validSignals: GovernanceSignal[] = ['pause', 'resume', 'revoke', 'approval_granted', 'approval_denied', 'budget_exceeded'];
          if ((validSignals as readonly string[]).includes(govSignal)) {
            this.emit('governance', {
              signal: govSignal as GovernanceSignal,
              target,
              by: from || undefined,
              reason: msg.tags['+freeq.at/reason'] || undefined,
            });
          }
        }

        // Coordination event (+freeq.at/event=*). The TAGMSG is the event:
        // the server stores it from this line, and this is the one place
        // `coordinationEvent` fires. De-dupe by eventId against echo.
        const eventType = msg.tags['+freeq.at/event'];
        if (eventType) {
          this.emitCoordinationEvent(target, from, msg.tags);
        }

        // Task event (`act-` tags). Same rule as the coordination branch: the
        // TAGMSG is the event, so this is the one place `actEvent` fires.
        // Inside a history batch the event is held and fired at batch end,
        // the way a replayed edit collapses into its batch above.
        const actBatchId = msg.tags['batch'];
        const actBatch = actBatchId ? this.batches.get(actBatchId) : undefined;
        if (
          actBatch &&
          actBatch.type !== 'draft/multiline' &&
          Object.keys(msg.tags).some((n) => signing.isActTag(n))
        ) {
          // The thread key, not the wire target: a DM's act event is
          // addressed to whoever receives it, and only the key every other
          // TAGMSG feature files under puts the event in the same thread as
          // the line that renders it. Resolved here because the flush below
          // no longer has the sender in hand.
          (actBatch.actEvents ??= []).push({ buffer: bufName, from, tags: msg.tags });
        } else {
          this.emitActEvent(bufName, from, msg.tags);
        }

        const avState = msg.tags['+freeq.at/av-state'];
        const avId = msg.tags['+freeq.at/av-id'];
        if (avState && avId) {
          this.handleAvSessionState(avId, avState, target,
            msg.tags['+freeq.at/av-actor'] || '',
            parseInt(msg.tags['+freeq.at/av-participants'] || '0', 10),
            msg.tags['+freeq.at/av-title']);
        }

        // Per-session MoQ access token, sent as a directed TAGMSG after
        // our av-start/av-join. Stored for avTokenFor(); apps append it
        // to the SFU dial URL as `?jwt=…`.
        const avToken = msg.tags['+freeq.at/av-token'];
        if (avToken && avId) {
          this._avTokens.set(avId, avToken);
          this.emit('avToken', avId, avToken);
        }

        // Machine-readable AV failure (join rejected / start lost a race).
        // Without this, a failed av-join was only a human NOTICE — client
        // call state got set up optimistically and never torn down, leaving
        // a ghost publisher in a session the server never admitted us to.
        const avError = msg.tags['+freeq.at/av-error'];
        if (avError) {
          this.emit('avError', avError, avId || '',
            msg.tags['+freeq.at/av-reason'] || '');
        }
        break;
      }

      case 'TOPIC': {
        const channel = msg.params[0];
        this.emit('topicChanged', channel, msg.params[1] || '', from);
        break;
      }
      case '332': {
        const channel = msg.params[1];
        this.emit('topicChanged', channel, msg.params[2] || '');
        break;
      }

      case '353': {
        const channel = msg.params[2];
        const nicks = (msg.params[3] || '').split(' ').filter(Boolean);
        const members: Array<Partial<Member> & { nick: string }> = [];
        for (const n of nicks) {
          const prefixMatch = n.match(/^([@%+]+)/);
          const prefixes = prefixMatch ? prefixMatch[1] : '';
          const bare = n.slice(prefixes.length);
          members.push({
            nick: bare,
            isOp: prefixes.includes('@'),
            isHalfop: prefixes.includes('%'),
            isVoiced: prefixes.includes('+'),
          });
        }
        this.emit('membersList', channel, members);
        // Accumulate for the atomic end-of-NAMES `membersSync` (366). A fresh
        // sequence (no key yet, because 366 deleted it) starts a new array.
        const key = (channel || '').toLowerCase();
        const acc = this._namesAccum.get(key) ?? [];
        acc.push(...members);
        this._namesAccum.set(key, acc);
        break;
      }

      // Actor classes for members already in the channel (vendor numeric).
      //
      // Sent right after 366. NAMES carries only nicks and prefixes, and the
      // extended-join tag only reaches clients that were already watching, so
      // without this a client that joins a room an agent is already in renders
      // that agent as a person. Format:
      //   :server 674 <me> <channel> :<nick>=<class> <nick>=<class> …
      case '674': {
        const classChannel = msg.params[1];
        const entries = (msg.params[2] || '').split(' ').filter(Boolean);
        for (const entry of entries) {
          const eq = entry.lastIndexOf('=');
          if (eq <= 0) continue;
          const nick = entry.slice(0, eq);
          const actorClass = entry.slice(eq + 1) as Member['actorClass'];
          if (actorClass !== 'agent' && actorClass !== 'external_agent' && actorClass !== 'human') {
            continue;
          }
          this.emit('memberJoined', classChannel, { nick, actorClass });
        }
        break;
      }

      // Structured presence relay. Unlike the AWAY back-compat line, this
      // carries the status for EVERY state — including active/online/idle,
      // where "back from away" is parameterless and the status used to be
      // dropped on the floor.
      case 'PRESENCE': {
        const raw = msg.params[msg.params.length - 1] || '';
        let state: string | undefined;
        let status: string | undefined;
        let task: string | undefined;
        for (const part of raw.split(';')) {
          const eq = part.indexOf('=');
          if (eq <= 0) continue;
          const k = part.slice(0, eq).trim();
          const v = part.slice(eq + 1);
          if (k === 'state') state = v;
          else if (k === 'status') status = v || undefined;
          else if (k === 'task') task = v || undefined;
        }
        if (from && state) {
          this.emit('presence', {
            nick: from,
            did: this.getDidForNick(from),
            state,
            status,
            task,
          });
        }
        break;
      }

      case '366': {
        const namesChannel = msg.params[1];
        // Emit the FULL accumulated roster so consumers can replace the member
        // set atomically — immune to a self-JOIN clear / collision / reconnect
        // leaving it half-populated. Then end the sequence so the next NAMES
        // reply starts fresh.
        const key = (namesChannel || '').toLowerCase();
        this.emit('membersSync', namesChannel, this._namesAccum.get(key) ?? []);
        this._namesAccum.delete(key);
        this.requestHistory({ target: namesChannel, mode: 'latest' });
        break;
      }

      case 'MODE': {
        const target = msg.params[0];
        if (target.startsWith('#') || target.startsWith('&')) {
          const modeStr = msg.params[1] || '';
          const argsWithParam = new Set(['o', 'h', 'v', 'k', 'b']);
          const targetLower = target.toLowerCase();
          let adding = true;
          let argIdx = 2;
          for (const ch of modeStr) {
            if (ch === '+') { adding = true; continue; }
            if (ch === '-') { adding = false; continue; }
            const modeArg = argsWithParam.has(ch) ? msg.params[argIdx++] : undefined;
            // Track +E so we can block plaintext sends; drop the cached
            // e2ee key on -E so we don't keep encrypting with a key the
            // rest of the channel no longer expects.
            if (ch === 'E') {
              if (adding) {
                this._encryptedChannels.add(targetLower);
              } else {
                this._encryptedChannels.delete(targetLower);
                e2ee.removeChannelKey(target);
              }
            }
            this.emit('modeChanged', target, `${adding ? '+' : '-'}${ch}`, modeArg, from);
          }
          const allArgs = msg.params.slice(2).join(' ');
          this.emit('systemMessage', target, `${from} set mode ${modeStr}${allArgs ? ' ' + allArgs : ''}`);
        }
        break;
      }

      case 'AWAY': {
        const awayText = msg.params[0] || null;
        this.emit('userAway', from, awayText);
        // Server broadcasts structured PRESENCE updates via the AWAY
        // mechanism (see freeq-server connection/mod.rs PRESENCE handler).
        // Format: either "<state>" alone, or "<state>: <status text>".
        // Parse back into the structured `presence` event.
        if (awayText) {
          const colonIdx = awayText.indexOf(':');
          let state: string = awayText;
          let status: string | undefined;
          if (colonIdx > 0) {
            state = awayText.slice(0, colonIdx).trim();
            status = awayText.slice(colonIdx + 1).trim() || undefined;
          }
          this.emit('presence', {
            nick: from,
            did: this.getDidForNick(from),
            state,
            status,
            task: undefined,
          });
        } else {
          // AWAY cleared = back to online.
          this.emit('presence', {
            nick: from,
            did: this.getDidForNick(from),
            state: 'online',
          });
        }
        break;
      }

      case 'MARKREAD': {
        // draft/read-marker: reply to our own get/set, or a push from
        // another of our devices. `MARKREAD <target> timestamp=<iso>` or
        // `MARKREAD <target> *`.
        const target = msg.params[0];
        if (target) {
          const raw = msg.params[1];
          const timestamp =
            raw && raw !== '*' && raw.startsWith('timestamp=')
              ? raw.slice('timestamp='.length)
              : null;
          this.emit('readMarker', target, timestamp);
        }
        break;
      }

      case '306':
        this.emit('userAway', this._nick, this.pendingAwayReason || 'away');
        this.pendingAwayReason = null;
        this.emit('systemMessage', 'server', `You are now away: ${this.pendingAwayReason || 'away'}`);
        break;

      case '305':
        this.pendingAwayReason = null;
        this._currentAway = null;
        this.emit('userAway', this._nick, null);
        this.emit('systemMessage', 'server', 'You are no longer away');
        break;

      case 'BATCH': {
        const ref = msg.params[0];
        if (ref.startsWith('+')) {
          const id = ref.slice(1);
          const type = msg.params[1] || '';
          const target = msg.params[2] || '';
          if (type === 'draft/multiline') {
            // Per spec, the BATCH opener carries the assembled message's
            // metadata (msgid, time, account, client-only tags). Capture
            // those plus the sender from the prefix; the per-chunk
            // PRIVMSGs only carry `batch=<id>`.
            const openerTags: Record<string, string> = {};
            for (const [k, v] of Object.entries(msg.tags)) {
              if (k !== 'batch') openerTags[k] = v;
            }
            const parentBatchId = msg.tags['batch']; // nesting (e.g. inside chathistory)
            this.batches.set(id, {
              type,
              target,
              messages: [],
              openerTags,
              openerFrom: from,
              multilineLines: [],
              parentBatchId,
            });
          } else {
            this.batches.set(id, { type, target, messages: [] });
          }
        } else if (ref.startsWith('-')) {
          const id = ref.slice(1);
          const batch = this.batches.get(id);
          if (batch) {
            this.batches.delete(id);
            if (batch.type === 'draft/multiline') {
              // Assemble per concat rules, decrypt if encrypted, and
              // emit a single `message` event (or push into a parent
              // batch if this was nested).
              await this.dispatchAssembledMultiline(batch);
            } else if (batch.type === 'draft/chathistory-targets') {
              // The TARGETS list envelope: its lines are CHATHISTORY
              // TARGETS commands, each already handled individually, and it
              // has no target of its own — emitting it as a historyBatch
              // handed the app a meaningless ('', []) every login.
            } else {
              let key = batch.target;
              if (key && !key.startsWith('#') && !key.startsWith('&')) {
                key = this.dmKey(key);
                if (!isDid(key)) {
                  // No binding was ever learned for this conversation (its
                  // TARGETS entry may have been lost to the login burst).
                  // The replayed rows themselves name the partner: recover
                  // the DID from a non-self account tag and learn the
                  // display binding, so the batch cannot mint a nick-keyed
                  // twin of a DID-keyed thread.
                  const own = this._authDid;
                  const partner = batch.messages
                    .map((m) => m.tags?.['account'])
                    .find((a) => a && isDid(a) && a !== own);
                  if (partner) {
                    this._didToNick.set(partner, batch.target.toLowerCase());
                    key = partner;
                  }
                }
              }
              this.emit(
                'historyBatch', key, batch.messages,
                this.takeHistoryRequest(batch.target),
              );
            }
            // Held task events ride out with the batch, in wire order,
            // after the lines they refer to.
            for (const held of batch.actEvents ?? []) {
              this.emitActEvent(held.buffer, held.from, held.tags);
            }
          }
        }
        break;
      }

      case 'CHATHISTORY': {
        const sub = msg.params[0];
        if (sub === 'TARGETS' && msg.params[1]) {
          const displayNick = msg.params[1];
          const timestamp = msg.params[2] || undefined;
          // The server names the conversation partner's identity in the
          // `freeq.at/partner-did` tag; the param is only a display nick
          // (possibly historical — offline peers, renames). Key the
          // conversation by the DID when present: emit it as the target and
          // fetch history by it, so the reply batch (whose target echoes the
          // request) is DID-keyed too — live messages and replay then agree
          // on what a conversation is. Absent tag (older server) → nick
          // behavior, unchanged.
          const partnerDid = msg.tags['freeq.at/partner-did'];
          const key = partnerDid && isDid(partnerDid) ? partnerDid : displayNick;
          if (key !== displayNick) {
            // Learn the display direction only (DID→nick): the nick may be
            // historical, so binding it for addressing (nick→DID) could
            // route a fresh nick owner's messages to the old identity.
            this._didToNick.set(key, displayNick.toLowerCase());
          }
          // Canonical event name (renamed from `dmTarget` — CHATHISTORY
          // TARGETS returns channels too, not just DMs).
          this.emit('historyTarget', key, timestamp);
          // Deprecated alias — kept for one release for backwards compat.
          this.emit('dmTarget', key);
          this.requestHistory({ target: key, mode: 'latest' });
        }
        break;
      }

      case 'INVITE':
        if (msg.params.length >= 2) {
          this.emit('invited', msg.params[1], from);
          this.emit('systemMessage', 'server', `${from} invited you to ${msg.params[1]}`);
        }
        break;

      // Error numerics
      case '401': {
        const failTarget = msg.params[1];
        // A name nobody holds ends any WHOIS out for it, so listeners waiting
        // on an answer are released rather than left pending forever.
        this.emit('whoisEnd', failTarget || '');
        // Show a name rather than a raw did:… string, and file the notice
        // under the CANONICAL conversation key (dmKey) — keying by the raw
        // fail target created a nick-keyed ghost thread holding nothing but
        // offline notices whenever the wire target was a nick.
        const shown = failTarget && isDid(failTarget)
          ? (this.getNickForDid(failTarget) ?? failTarget)
          : failTarget;
        this.emit('systemMessage', failTarget ? this.dmKey(failTarget) : 'server',
          `${shown} is offline — message saved, they'll see it next time they connect`);
        break;
      }
      case '404':
        this.emit('systemMessage', msg.params[1] || 'server', msg.params[2] || 'Cannot send to channel');
        break;
      case '473':
        this.emit('systemMessage', msg.params[1] || 'server', `Cannot join ${msg.params[1]} — invite only (+i)`);
        break;
      case '474':
        this.emit('systemMessage', msg.params[1] || 'server', `Cannot join ${msg.params[1]} — you are banned`);
        break;
      case '475':
        this.emit('systemMessage', msg.params[1] || 'server', `Cannot join ${msg.params[1]} — incorrect channel key`);
        break;
      case '477': {
        const ch = msg.params[1] || '';
        this.emit('systemMessage', 'server', `Cannot join ${ch}: ${msg.params[2] || 'Policy acceptance required'}`);
        this.emit('joinGateRequired', ch);
        break;
      }
      case '482':
        this.emit('systemMessage', msg.params[1] || 'server', msg.params[2] || 'Not operator');
        break;

      // WHOIS
      case '311': {
        const whoisNick = msg.params[1] || '';
        const info = {
          user: msg.params[2],
          host: msg.params[3],
          realname: msg.params[5] || msg.params[4],
          did: undefined,
          handle: undefined,
        };
        this.emit('whois', whoisNick, info);
        // Accumulate for requestWhois() Promise.
        const lc = whoisNick.toLowerCase();
        const buf = this._whoisBuffer.get(lc) ?? { nick: whoisNick, fetchedAt: 0 };
        buf.user = info.user;
        buf.host = info.host;
        buf.realname = info.realname;
        this._whoisBuffer.set(lc, buf);
        if (!this.backgroundWhois.has(lc)) {
          this.emit('systemMessage', 'server', `WHOIS ${whoisNick}: ${msg.params[2]}@${msg.params[3]} (${msg.params[5] || msg.params[4]})`);
        }
        break;
      }
      case '312': {
        const whoisNick = msg.params[1] || '';
        this.emit('whois', whoisNick, { server: msg.params[2] });
        const lc = whoisNick.toLowerCase();
        const buf = this._whoisBuffer.get(lc) ?? { nick: whoisNick, fetchedAt: 0 };
        buf.server = msg.params[2];
        this._whoisBuffer.set(lc, buf);
        if (!this.backgroundWhois.has(lc)) {
          this.emit('systemMessage', 'server', `  Server: ${msg.params[2]}`);
        }
        break;
      }
      case '318': {
        // End of WHOIS. Resolve any pending requestWhois() Promise(s)
        // for this nick with the accumulated info.
        const lc = (msg.params[1] || '').toLowerCase();
        this.emit('whoisEnd', msg.params[1] || '');
        this.backgroundWhois.delete(lc);
        const buf = this._whoisBuffer.get(lc);
        this._whoisBuffer.delete(lc);
        const waiters = this._pendingWhois.get(lc);
        if (waiters) {
          this._pendingWhois.delete(lc);
          const info: WhoisInfo = {
            nick: buf?.nick ?? msg.params[1] ?? '',
            user: buf?.user,
            host: buf?.host,
            realname: buf?.realname,
            server: buf?.server,
            did: buf?.did,
            handle: buf?.handle,
            channels: buf?.channels,
            fetchedAt: Date.now(),
          };
          for (const w of waiters) {
            clearTimeout(w.timer);
            w.resolve(info);
          }
        }
        break;
      }
      case '319': {
        const whoisNick = msg.params[1] || '';
        this.emit('whois', whoisNick, { channels: msg.params[2] });
        const lc = whoisNick.toLowerCase();
        const buf = this._whoisBuffer.get(lc) ?? { nick: whoisNick, fetchedAt: 0 };
        buf.channels = msg.params[2];
        this._whoisBuffer.set(lc, buf);
        if (!this.backgroundWhois.has(lc)) {
          this.emit('systemMessage', 'server', `  Channels: ${msg.params[2]}`);
        }
        break;
      }
      case '330': {
        const whoisNick = msg.params[1] || '';
        const did = msg.params[2]?.trim() || undefined;
        this.emit('whois', whoisNick, { did });
        if (whoisNick && did) {
          this.emit('memberDid', whoisNick, did);
          // Populate internal bidirectional cache (used by getDidForNick /
          // getNickForDid / requestWhois). Lowercase nick key for
          // case-insensitive lookup. Forget any previous nick that was
          // bound to this DID (e.g. after NICK change).
          const lc = whoisNick.toLowerCase();
          const prevDid = this._nickToDid.get(lc);
          if (prevDid && prevDid !== did) this._didToNick.delete(prevDid);
          const prevNick = this._didToNick.get(did);
          if (prevNick && prevNick !== lc) this._nickToDid.delete(prevNick);
          this._nickToDid.set(lc, did);
          this._didToNick.set(did, lc);
          // Accumulate for the requestWhois() Promise.
          const buf = this._whoisBuffer.get(lc) ?? { nick: whoisNick, fetchedAt: 0 };
          buf.did = did;
          this._whoisBuffer.set(lc, buf);
          prefetchProfiles([did]);
        }
        if (!this.backgroundWhois.has(whoisNick.toLowerCase())) {
          this.emit('systemMessage', 'server', `  DID: ${did}`);
        }
        break;
      }
      case '673': {
        const whoisNick = msg.params[1] || '';
        const classStr = msg.params[2] || '';
        const match = classStr.match(/actor_class=(\w+)/);
        if (match && whoisNick) {
          this.emit('memberJoined', '', { nick: whoisNick, actorClass: match[1] as Member['actorClass'] });
        }
        if (!this.backgroundWhois.has(whoisNick.toLowerCase())) {
          this.emit('systemMessage', 'server', `  Actor class: ${classStr}`);
        }
        break;
      }
      case '671': {
        const whoisNick = msg.params[1] || '';
        const info = msg.params[2]?.trim() ?? '';
        const lc = whoisNick.toLowerCase();
        const handle = info.match(/^AT Protocol handle:\s*(\S+)$/)?.[1];
        if (handle) {
          this.emit('whois', whoisNick, { handle });
          const buf = this._whoisBuffer.get(lc) ?? { nick: whoisNick, fetchedAt: 0 };
          buf.handle = handle;
          this._whoisBuffer.set(lc, buf);
        }
        if (!this.backgroundWhois.has(lc)) {
          this.emit('systemMessage', 'server', `  ${info}`);
        }
        break;
      }

      // Channel list
      case '321':
        break;
      case '322': {
        const chName = msg.params[1] || '';
        const chCount = parseInt(msg.params[2] || '0', 10);
        const chTopic = msg.params[3] || '';
        this.emit('channelListEntry', { name: chName, topic: chTopic, count: chCount });
        this.emit('systemMessage', 'server', `  ${chName} (${chCount}) ${chTopic}`);
        break;
      }
      case '323':
        this.emit('channelListEnd');
        break;

      // MOTD
      case '375':
        this.emit('motdStart');
        this.emit('systemMessage', 'server', msg.params[msg.params.length - 1]);
        break;
      case '372': {
        const motdLine = msg.params[msg.params.length - 1];
        this.emit('systemMessage', 'server', motdLine);
        this.emit('motd', motdLine.replace(/^- ?/, ''));
        break;
      }

      default:
        if (/^\d{3}$/.test(msg.command)) {
          this.emit('systemMessage', 'server', msg.params.slice(1).join(' '));
        }
        break;
    }
  }

  private handleCap(msg: IRCMessage): void {
    const sub = (msg.params[1] || '').toUpperCase();
    if (sub === 'LS') {
      const available = msg.params.slice(2).join(' ');
      const wantedCaps: string[] = [];
      const caps = [
        'message-tags', 'server-time', 'batch', 'multi-prefix',
        'echo-message', 'account-notify', 'account-tag', 'extended-join', 'away-notify',
        'draft/chathistory', 'draft/multiline', 'draft/read-marker',
        // Requested rather than merely read off the LS line: the ACK is the
        // server's own confirmation that it verifies chat documents, and
        // signing is gated on it (see `SIGNING_CAP`).
        SIGNING_CAP,
        // Task events reach only the connections that ask for them. This
        // SDK's callers are agents, which are the audience — a bot that can
        // send a task step and never see another one has half a conversation.
        'freeq.at/act',
      ];
      for (const c of caps) {
        // `draft/multiline` advertises with params (`=max-bytes=…,max-lines=…`)
        // — capture them for the chunker. The base `includes()` match still
        // works because the cap name is a prefix of the full token.
        if (c === 'draft/multiline') {
          const m = available.match(/draft\/multiline(?:=([^\s]+))?/);
          if (m) {
            wantedCaps.push(c);
            if (m[1]) this.parseMultilineCapParams(m[1]);
          }
        } else if (available.includes(c)) {
          wantedCaps.push(c);
        }
      }
      // Negotiate `sasl` whenever the bot has SOME way to authenticate:
      // either a pre-issued token (pds-session/pds-oauth) OR a signer
      // callback (crypto / did:key). Previously only the token branch
      // qualified, so JS bots using did:key never reached SASL.
      const wantsSasl = (this.sasl?.token || this.sasl?.signer) && available.includes('sasl');
      if (wantsSasl) {
        wantedCaps.push('sasl');
      }
      if (wantedCaps.length) {
        this.raw(`CAP REQ :${wantedCaps.join(' ')}`);
      } else {
        this.raw('CAP END');
      }
    } else if (sub === 'ACK') {
      const caps = msg.params.slice(2).join(' ');
      for (const c of caps.split(' ')) this.ackedCaps.add(c);
      const canSasl = this.ackedCaps.has('sasl') && (this.sasl?.token || this.sasl?.signer);
      if (canSasl) {
        this.raw('AUTHENTICATE ATPROTO-CHALLENGE');
      } else {
        this.raw('CAP END');
      }
    } else if (sub === 'NAK') {
      this.raw('CAP END');
    }
  }

  private async handleAuthenticate(msg: IRCMessage): Promise<void> {
    const param = msg.params[0] || '';
    if (param === '+' || !param) return;

    // Decode the raw challenge bytes the server sent. Two parallel
    // uses:
    //   - PDS methods need only the nonce (echoed back so the server
    //     can bind the PDS verification to this specific challenge).
    //   - Crypto / did:key signs the raw challenge bytes themselves
    //     and puts the signature in the response.
    const padded = param.replace(/-/g, '+').replace(/_/g, '/');
    let rawChallengeBytes = new Uint8Array(0);
    let challengeNonce: string | undefined;
    try {
      const bin = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
      rawChallengeBytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) rawChallengeBytes[i] = bin.charCodeAt(i);
      const challenge = JSON.parse(new TextDecoder().decode(rawChallengeBytes));
      challengeNonce = challenge.nonce;
    } catch { /* proceed without nonce — pds-* path will still work for legacy servers */ }

    const method = this.sasl?.method || 'pds-session';

    // ── Crypto / did:key auth — sign the raw challenge bytes ──
    let signature = this.sasl?.token ?? '';
    if (method === 'crypto') {
      if (!this.sasl?.signer) {
        console.warn('[freeq-sdk] SASL method=crypto requires a signer callback in setSaslCredentials; aborting');
        this.raw('AUTHENTICATE *');
        return;
      }
      try {
        signature = await this.sasl.signer(rawChallengeBytes);
      } catch (e) {
        console.error('[freeq-sdk] Crypto SASL signer threw:', e);
        this.raw('AUTHENTICATE *');
        return;
      }
    }

    const response = JSON.stringify({
      did: this.sasl?.did,
      method,
      signature,
      pds_url: this.sasl?.pdsUrl,
      challenge_nonce: challengeNonce,
    });
    const encoded = btoa(response)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    if (encoded.length <= 400) {
      this.raw(`AUTHENTICATE ${encoded}`);
    } else {
      for (let i = 0; i < encoded.length; i += 400) {
        this.raw(`AUTHENTICATE ${encoded.slice(i, i + 400)}`);
      }
      this.raw('AUTHENTICATE +');
    }
  }

  private handleAvSessionState(
    sessionId: string,
    action: string,
    channel: string,
    actorNick: string,
    _participantCount: number,
    title?: string,
  ): void {
    const existing = this._avSessions.get(sessionId);

    switch (action) {
      case 'started': {
        const session: AvSession = {
          id: sessionId,
          channel,
          createdBy: '',
          createdByNick: actorNick,
          title: title || undefined,
          participants: new Map([[actorNick, {
            did: '',
            nick: actorNick,
            role: 'host' as const,
            joinedAt: new Date(),
          }]]),
          state: 'active',
          startedAt: new Date(),
        };
        this._avSessions.set(sessionId, session);
        this.emit('avSessionUpdate', session);
        if (actorNick.toLowerCase() === this._nick.toLowerCase()) {
          this._activeAvSession = sessionId;
        }
        break;
      }
      case 'joined': {
        if (existing && existing.state === 'active') {
          const updated = { ...existing, participants: new Map(existing.participants) };
          updated.participants.set(actorNick, {
            did: '',
            nick: actorNick,
            role: 'speaker' as const,
            joinedAt: new Date(),
          });
          this._avSessions.set(sessionId, updated);
          this.emit('avSessionUpdate', updated);
          if (actorNick.toLowerCase() === this._nick.toLowerCase()) {
            this._activeAvSession = sessionId;
          }
        }
        break;
      }
      case 'left': {
        if (existing && existing.state === 'active') {
          const updated = { ...existing, participants: new Map(existing.participants) };
          updated.participants.delete(actorNick);
          this._avSessions.set(sessionId, updated);
          this.emit('avSessionUpdate', updated);
        }
        break;
      }
      case 'ended': {
        if (existing) {
          const ended = { ...existing, state: 'ended' as const, participants: new Map<string, AvParticipant>() };
          this._avSessions.set(sessionId, ended);
          this.emit('avSessionUpdate', ended);
          setTimeout(() => {
            this._avSessions.delete(sessionId);
            this.emit('avSessionRemoved', sessionId);
          }, 5000);
        }
        if (this._activeAvSession === sessionId) {
          this._activeAvSession = null;
        }
        break;
      }
    }
  }

  // ── Channels ──

  /** Send IRC QUIT. Closes the session cleanly on the server side. */
  quit(reason?: string): void {
    this.raw(reason ? `QUIT :${reason}` : 'QUIT');
  }

  /** JOIN multiple channels at once (comma-separated wire form). */
  joinMany(channels: string[]): void {
    if (channels.length === 0) return;
    this.raw(`JOIN ${channels.join(',')}`);
  }

  // ── Messaging extensions ──

  /** PRIVMSG with arbitrary IRCv3 tags. Caller-managed escaping is handled
   *  by the SDK's format() helper. Signs like any other message — the
   *  covered coordination tags ride inside the document. */
  sendTagged(target: string, text: string, tags: Record<string, string>): void {
    void this.signedPrivmsg(target, text, tags);
  }

  /** Send a NOTICE. Signed like a PRIVMSG — the server verifies both against
   *  the same document. A DM peer resolves to their DID where it's known,
   *  which is what gives the signature a venue a verifier can rebuild.
   *
   *  **A notice leaves no record, so its signature cannot be checked later.**
   *  The server stores and logs messages only (persistence is gated on
   *  PRIVMSG), so a notice is verifiable in flight and by nothing afterwards:
   *  it is absent from channel history, from CHATHISTORY replay, and from
   *  `/api/v1/verify`. That is deliberate for the server's own notices —
   *  command results, errors, the API bearer — which are control chatter
   *  nobody wants in history.
   *
   *  Choose on that basis. Something the sender should be able to *prove*
   *  later — an answer, a result, a decision — wants `sendMessage`. Chatter
   *  that should not be on the record — "restarting", "backing off", a reply
   *  to another bot that must not start a loop — is what a notice is for, and
   *  there the missing record costs nothing. The convention that nothing
   *  auto-replies to a notice is a real reason to use one when talking to
   *  other automation; it is not a reason to use one for output a person
   *  reads and may rely on. */
  sendNotice(target: string, text: string, tags: Record<string, string> = {}): void {
    void this.enqueueSend(() =>
      this.writeSignedMessage('NOTICE', this.wireTargetFor(target), text, tags),
    );
  }

  /** TAGMSG (tags-only, no body) to a target.
   *
   *  A TAGMSG carrying a mutation — a delete, a reaction, its removal — is
   *  signed like one sent through the named helpers. The generic door and the
   *  named ones lead to the same place: which method a caller reached for is
   *  not a reason for one event to be provable and another not. Ephemera
   *  (typing, AV signalling) go out as they always have. */
  sendTagmsg(target: string, tags: Record<string, string>): void {
    const mutation = mutationIn(tags);
    if (!mutation) {
      this.raw(format('TAGMSG', [target], tags));
      return;
    }
    const { kind, subject, emoji } = mutation;
    this.signedMutation(kind, target, tags, subject, emoji);
  }

  /** Send a media attachment (image/audio/video URL with metadata).
   *  Server side stores the media tags; rich clients render the embed.
   *  Signs like any other message, and the media tags are inside the
   *  document: a reader renders them, so a signature that skipped them would
   *  leave a relay free to change what the reader sees. */
  sendMedia(
    target: string,
    media: { url: string; mime?: string; alt?: string; width?: number; height?: number; durationMs?: number; sizeBytes?: number; fallback?: string },
  ): void {
    const tags: Record<string, string> = { '+freeq.at/media-url': media.url };
    if (media.mime) tags['+freeq.at/media-mime'] = media.mime;
    if (media.alt) tags['+freeq.at/media-alt'] = media.alt;
    if (media.width !== undefined) tags['+freeq.at/media-w'] = String(media.width);
    if (media.height !== undefined) tags['+freeq.at/media-h'] = String(media.height);
    if (media.durationMs !== undefined) tags['+freeq.at/media-duration'] = String(media.durationMs);
    if (media.sizeBytes !== undefined) tags['+freeq.at/media-size'] = String(media.sizeBytes);
    const body = media.fallback ?? `📎 ${media.url}`;
    void this.signedPrivmsg(target, body, tags);
  }

  /** Attach link-preview metadata to a message. Signed, same as media, with
   *  the preview's fields covered for the same reason. */
  sendLinkPreview(
    target: string,
    preview: { url: string; title?: string; description?: string; imageUrl?: string },
  ): void {
    const tags: Record<string, string> = { '+freeq.at/link-url': preview.url };
    if (preview.title) tags['+freeq.at/link-title'] = preview.title;
    if (preview.description) tags['+freeq.at/link-desc'] = preview.description;
    if (preview.imageUrl) tags['+freeq.at/link-image'] = preview.imageUrl;
    const fallback = preview.title && preview.description
      ? `🔗 ${preview.title} — ${preview.description} (${preview.url})`
      : preview.title
        ? `🔗 ${preview.title} (${preview.url})`
        : `🔗 ${preview.url}`;
    void this.signedPrivmsg(target, fallback, tags);
  }

  /** Send a message and await the server-assigned msgid via echo-message.
   *  Resolves with the msgid the server stamps on the echo. Requires
   *  `echo-message` cap (negotiated by default). Timeouts after 5s. */
  sendAndAwaitEcho(target: string, text: string, tags: Record<string, string> = {}): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const nonce = `echo-${Date.now().toString(16)}${Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0')}`;
      const fullTags = { ...tags, '+freeq.at/echo-nonce': nonce };
      const timer = setTimeout(() => {
        this.off('raw', onRaw);
        reject(new Error('sendAndAwaitEcho timed out waiting for echo-message'));
      }, 5000);
      const onRaw = (_line: string, parsed: IRCMessage): void => {
        if (parsed.command !== 'PRIVMSG' && parsed.command !== 'TAGMSG') return;
        if (parsed.tags?.['+freeq.at/echo-nonce'] !== nonce) return;
        const msgid = parsed.tags?.['msgid'];
        if (!msgid) return;
        clearTimeout(timer);
        this.off('raw', onRaw);
        resolve(msgid);
      };
      this.on('raw', onRaw);
      // Through the signing path, not a hand-built line: a helper that
      // bypasses signedPrivmsg sends unsigned even when signing is armed.
      // The nonce tag is not a covered field, so it rides outside the
      // signed document.
      void this.signedPrivmsg(target, text, fullTags);
    });
  }

  /** Send a threaded reply (alias for sendReply, named to match Rust SDK
   *  `reply_in_thread`). */
  sendReplyInThread(target: string, parentMsgId: string, text: string): void {
    this.sendReply(target, parentMsgId, text);
  }

  // ── Typing indicators ──

  /** Start a typing indicator in a target (channel or DM). */
  startTyping(target: string): void {
    this.raw(format('TAGMSG', [target], { '+typing': 'active' }));
  }

  /** Stop a typing indicator. */
  stopTyping(target: string): void {
    this.raw(format('TAGMSG', [target], { '+typing': 'done' }));
  }

  // ── Identity resolution (sync getters; cache is auto-populated) ──

  /** Sync lookup: nick → DID. Returns undefined if unknown.
   *  Auto-populated from WHOIS 330, JOIN account tags, and ACCOUNT notify. */
  getDidForNick(nick: string): string | undefined {
    return this._nickToDid.get(nick.toLowerCase()) ?? this.nickToDid?.(nick);
  }

  /** Sync lookup: DID → current nick. Returns undefined if unknown.
   *  Needed for AGENT PAUSE/REVOKE which take nicks, not DIDs. */
  getNickForDid(did: string): string | undefined {
    return this._didToNick.get(did);
  }

  // ── Agent lifecycle ──

  /** Declare actor_class for this session. Class is one of:
   *  'agent' | 'external_agent' | 'human'. Broadcast to shared channels. */
  registerAgent(actorClass: 'agent' | 'external_agent' | 'human'): void {
    this.raw(`AGENT REGISTER :class=${actorClass}`);
  }

  /** Submit a provenance declaration (JSON value, base64url-encoded on
   *  the wire). For agents, typically a FreeqBotDelegation/v1 cert. */
  submitProvenance(provenance: unknown): void {
    const json = JSON.stringify(provenance);
    const bytes = new TextEncoder().encode(json);
    // base64url, no padding.
    let b64 = btoa(String.fromCharCode(...bytes));
    b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    this.raw(`PROVENANCE :${b64}`);
  }

  /** Update structured agent presence (state, status, task). */
  setPresence(state: string, status?: string, task?: string): void {
    const parts = [`state=${state}`];
    if (status) parts.push(`status=${status}`);
    if (task) parts.push(`task=${task}`);
    this.raw(`PRESENCE :${parts.join(';')}`);
  }

  /** Send a single heartbeat. */
  sendHeartbeat(state: string, ttlSeconds: number): void {
    this.raw(`HEARTBEAT :state=${state};ttl=${ttlSeconds}`);
  }

  /** Start a background heartbeat loop at the given interval (ms).
   *  TTL is set to 2× interval per Rust SDK convention. */
  startHeartbeat(intervalMs: number): HeartbeatHandle {
    if (this._agentHeartbeatTimer) clearInterval(this._agentHeartbeatTimer);
    const ttl = Math.max(1, Math.floor(intervalMs / 1000) * 2);
    // First beat immediately so server marks us alive without waiting.
    this.sendHeartbeat('active', ttl);
    this._agentHeartbeatTimer = setInterval(() => {
      try { this.sendHeartbeat('active', ttl); }
      catch { /* socket gone; next reconnect re-arms */ }
    }, intervalMs);
    return {
      stop: () => {
        if (this._agentHeartbeatTimer) {
          clearInterval(this._agentHeartbeatTimer);
          this._agentHeartbeatTimer = null;
        }
      },
    };
  }

  // ── Governance ──

  /** Request approval from channel ops for a capability use. */
  requestApproval(channel: string, capability: string, resource?: string): void {
    const tail = resource ? `${capability};resource=${resource}` : capability;
    this.raw(`APPROVAL_REQUEST ${channel} :${tail}`);
  }

  /** Op-only. Pause target agent — expects PRESENCE=paused within 10s. */
  pauseAgent(nick: string, reason?: string): void {
    this.raw(reason ? `AGENT PAUSE ${nick} :${reason}` : `AGENT PAUSE ${nick}`);
  }

  /** Op-only. Resume a paused agent. */
  resumeAgent(nick: string): void {
    this.raw(`AGENT RESUME ${nick}`);
  }

  /** Op-only. Revoke capabilities + force disconnect. */
  revokeAgent(nick: string, reason?: string): void {
    this.raw(reason ? `AGENT REVOKE ${nick} :${reason}` : `AGENT REVOKE ${nick}`);
  }

  /** Op approval response. */
  approveAgent(nick: string, capability: string): void {
    this.raw(`AGENT APPROVE ${nick} ${capability}`);
  }

  /** Op denial response. */
  denyAgent(nick: string, capability: string, reason?: string): void {
    this.raw(reason
      ? `AGENT DENY ${nick} ${capability} :${reason}`
      : `AGENT DENY ${nick} ${capability}`);
  }

  // ── Coordination events ──

  /** Emit a coordination event as paired TAGMSG (for storage) +
   *  companion PRIVMSG (for rich-client rendering). Returns the
   *  server-stored event ID.
   *
   *  Against a server that verifies documents the TAGMSG is signed over its
   *  own document and carries a signer-minted ULID; against one that doesn't,
   *  the pair is exactly what a pre-signing client sent, legacy id and all.
   *  Either way the returned id is the id the server files, because callers
   *  reference it. */
  emitEvent(
    channel: string,
    eventType: string,
    payload: unknown,
    opts: EmitEventOptions = {},
  ): string {
    const payloadJson = JSON.stringify(payload);
    // Percent-encode `;` and ` ` so the value survives both IRCv3 tag
    // escape and the server's url-decode pass (see proposal §5.0).
    const encoded = payloadJson.replace(/;/g, '%3B').replace(/ /g, '%20');
    // Decided before the signature exists, because the id is returned now:
    // a signed event is filed under the ULID its signature covers, an
    // unsigned one under the legacy id the server reads from `msgid`.
    //
    // A caller-supplied id that is not ULID-shaped takes the unsigned path
    // whole: a server will not adopt it, so signing over it would file the
    // event under an id its own document does not name — and the caller,
    // holding the id it chose, would be pointing at nothing.
    const signable =
      this.ackedCaps.has(SIGNING_CAP) &&
      // A key still being generated counts: the send waits for the
      // registration, so by the time this event reaches the wire it can be
      // signed — and deciding otherwise would emit unsigned events for the
      // first moments of every session.
      this.signing.canSign(channel, { keyPending: this.msgSigReady !== null }) &&
      (opts.eventId === undefined || isUlid(opts.eventId));
    const eventId = opts.eventId ?? (signable ? signing.newEventId() : mintEventId());
    const tags: Record<string, string> = {
      '+freeq.at/event': eventType,
      '+freeq.at/payload': encoded,
    };
    if (opts.refId) tags['+freeq.at/ref'] = opts.refId;
    if (opts.extraTags) Object.assign(tags, opts.extraTags);
    const humanText = opts.humanText ?? `${eventType}`;
    if (!signable) {
      // Byte-for-byte what a pre-signing client sends, `msgid` first — but
      // still through the queue, so an unsigned event cannot overtake a
      // signed send that is still waiting on its signature.
      const legacy = { msgid: eventId, ...tags };
      void this.enqueueSend(async () => {
        this.raw(format('TAGMSG', [channel], legacy));
        this.raw(format('PRIVMSG', [channel, humanText], legacy));
      });
      return eventId;
    }
    void this.enqueueSend(() =>
      this.signedCoordinationEvent(channel, eventType, eventId, encoded, tags, humanText, opts.refId),
    );
    return eventId;
  }

  /**
   * Put a signed coordination event on the wire: the TAGMSG that is the
   * stored artifact, then the companion message that renders it.
   *
   * Two documents, each signing its own id. The message is an ordinary
   * message whose covered coordination tags name the event — which is what
   * joins the pair without either one signing the other's bytes.
   */
  private async signedCoordinationEvent(
    channel: string,
    eventType: string,
    eventId: string,
    encodedPayload: string,
    tags: Record<string, string>,
    humanText: string,
    refId?: string,
  ): Promise<void> {
    const signed = await this.signing.signCoordination(channel, eventType, {
      eventId,
      payload: encodedPayload,
      ref: refId,
      // Rendered, so covered: a reader shows it as the evidence's icon and
      // label, and a bot reads it off the event.
      evidence: tags['+freeq.at/evidence-type'],
    });
    const wireTags = { ...tags };
    if (signed) {
      wireTags[signing.EVENT_ID_TAG] = signed.eventId;
      wireTags[signing.SIG_TAG] = signed.sigTag;
    } else {
      // Signing was expected and did not happen. The caller already holds
      // this id, so it still has to be the id the server files: the legacy
      // tag is the only one an unsigned event is filed under.
      wireTags['msgid'] = eventId;
    }
    this.raw(format('TAGMSG', [channel], wireTags));
    // The companion is an ordinary message signing its own id. The TAGMSG
    // is the event — it carries the event id under its own signature — and
    // the companion is a rendering of it: it carries the event tags a
    // reader draws a card from, and no claim to the event's id.
    await this.writeSignedMessage('PRIVMSG', channel, humanText, { ...tags });
  }

  /**
   * Put a task event on the wire: the signed TAGMSG that *is* the event, then
   * the plain-text companion that renders it for people.
   *
   * The same paired send the coordination emitter does, and for the same
   * reason — two documents, each signing its own id. The companion links back
   * with `+freeq.at/ref`, which is on chat's covered list; an `act-` name there
   * would sit outside every signature, because those belong to task messages
   * alone.
   *
   * Returns the event's id — which, for an opener, is the task's id.
   */
  async sendAct(
    target: string,
    actTags: Record<string, string>,
    opts: { humanText?: string; taskId?: string } = {},
  ): Promise<string> {
    const eventId = signing.newEventId();
    const signed = await this.signing.signAct(target, actTags, eventId);
    if (!signed) {
      throw new Error(
        'a task event must be signed: authenticate, register a signing key, ' +
          'and address a channel or a DID',
      );
    }
    const wireTags = {
      ...actTags,
      [signing.EVENT_ID_TAG]: eventId,
      [signing.SIG_TAG]: signed.sigTag,
    };
    // Three answers, not two: no `humanText` asks for the line these tags
    // deserve, `''` asks for no companion at all, and anything else is the
    // caller's own words.
    const humanText =
      opts.humanText ??
      signing.actLine(
        actTags['+freeq.at/act'] ?? '',
        actTags['+freeq.at/act-verb'] ?? '',
        Object.fromEntries(
          Object.entries(actTags).flatMap(([name, value]) => {
            const field = name.startsWith('+freeq.at/act-')
              ? name.slice('+freeq.at/act-'.length)
              : null;
            return field === null ? [] : [[field, value] as [string, string]];
          }),
        ),
      );
    // The companion is an ordinary message signing its own id, carrying only
    // the reference that joins it to the action — the one it names, or itself
    // when it names none.
    const ref = opts.taskId ?? actTags['+freeq.at/act-id'] ?? eventId;

    // Nothing to wait for: a session without `echo-message` is never told its
    // own event was taken, and a caller who asked for no line has none to
    // hold back. Both halves go out as they always did.
    if (!humanText || !this.ackedCaps.has('echo-message')) {
      this.raw(format('TAGMSG', [target], wireTags));
      if (humanText) await this.writeActCompanion(target, humanText, ref);
      return eventId;
    }

    const settled = this.actAnswerChain.then(
      () => this.writeActAwaitingAnswer(target, wireTags, humanText, ref, eventId),
      () => this.writeActAwaitingAnswer(target, wireTags, humanText, ref, eventId),
    );
    // A refused send must not wedge every act send after it.
    this.actAnswerChain = settled.catch(() => undefined);
    await settled;
    return eventId;
  }

  /** The line beside a task event, signed as the ordinary message it is. */
  private writeActCompanion(target: string, humanText: string, ref: string): Promise<void> {
    return this.writeSignedMessage('PRIVMSG', target, humanText, { '+freeq.at/ref': ref });
  }

  /**
   * Put a task event on the wire and hold its line until the server has
   * answered for the event.
   *
   * The server gates the event and not the line, so a line sent beside a
   * refused step is prose about something that never happened — and no card
   * can ever attach to it. Throws the refusal, so the caller of `sendAct`
   * hears what the server said.
   */
  private async writeActAwaitingAnswer(
    target: string,
    wireTags: Record<string, string>,
    humanText: string,
    ref: string,
    eventId: string,
  ): Promise<void> {
    // Armed before the event goes out: the answer is a line off the same
    // socket, and the listener has to be there when it lands.
    const answer = this.actAnswer(eventId);
    this.raw(format('TAGMSG', [target], wireTags));
    const refusal = await answer;
    if (refusal) throw new Error(refusal);
    await this.writeActCompanion(target, humanText, ref);
  }

  /**
   * The server's word on a task event just sent: the refusal's words when it
   * was refused, and nothing when it was taken.
   *
   * Acceptance is our own echo of the event — matched by the id we minted,
   * either as the sender's tag or, through a server that adopts it, as the
   * msgid it was filed under. A `FAIL TAGMSG` is the refusal; it names no
   * event id, which is why only one send waits here at a time. Silence for
   * the whole window reads as taken, deliberately (see `ACT_ANSWER_WINDOW_MS`).
   */
  private actAnswer(eventId: string): Promise<string | undefined> {
    return new Promise<string | undefined>((resolve) => {
      const settle = (refusal?: string): void => {
        clearTimeout(timer);
        this.off('raw', onRaw);
        resolve(refusal);
      };
      const timer = setTimeout(() => settle(), ACT_ANSWER_WINDOW_MS);
      const onRaw = (_line: string, parsed: IRCMessage): void => {
        if (parsed.command === 'TAGMSG') {
          const id = parsed.tags?.[signing.EVENT_ID_TAG] ?? parsed.tags?.['msgid'];
          if (id === eventId) settle();
        } else if (parsed.command === 'FAIL' && parsed.params[0] === 'TAGMSG') {
          settle(parsed.params.slice(1).join(' ') || 'the server refused the task event');
        }
      };
      this.on('raw', onRaw);
    });
  }

  /**
   * Sugar over `emitEvent` for `task_request`. Returns the task ID.
   *
   * Superseded by `sendAct` carrying an `offer` built by `actTags` — the same
   * work opened as a signed task event the sender then holds by accepting it.
   * This one keeps sending the older task family until every caller has moved.
   */
  createTask(channel: string, description: string): string {
    return this.emitEvent(channel, 'task_request', { description }, {
      humanText: `📋 New task: ${description}`,
    });
  }

  /**
   * Sugar for `task_update` — progress update on a task.
   *
   * Superseded by `sendAct` carrying a `progress` built by `actTags`, which
   * says the same thing on the task's own record. This one keeps sending the
   * older task family until every caller has moved.
   */
  updateTask(channel: string, taskId: string, phase: string, summary: string): void {
    this.emitEvent(channel, 'task_update', { phase, summary }, {
      refId: taskId,
      humanText: `🔄 [${phase}] ${summary}`,
    });
  }

  /**
   * Sugar for `task_complete`.
   *
   * Superseded by `sendAct` carrying a `complete` built by `actTags`. This one
   * keeps sending the older task family until every caller has moved.
   */
  completeTask(channel: string, taskId: string, summary: string, url?: string): void {
    const payload: Record<string, unknown> = { summary };
    if (url) payload.url = url;
    const urlStr = url ? ` — ${url}` : '';
    this.emitEvent(channel, 'task_complete', payload, {
      refId: taskId,
      humanText: `🎉 Task complete: ${summary}${urlStr}`,
    });
  }

  /**
   * Sugar for `task_failed`.
   *
   * Superseded by `sendAct` carrying a `fail` built by `actTags`. This one
   * keeps sending the older task family until every caller has moved.
   */
  failTask(channel: string, taskId: string, error: string): void {
    this.emitEvent(channel, 'task_failed', { error }, {
      refId: taskId,
      humanText: `❌ Task failed: ${error}`,
    });
  }

  /**
   * Sugar for `evidence_attach` — attach evidence to a task.
   *
   * Superseded by `sendAct` carrying a `progress` built by `actTags` with
   * `ctx` and `ctx-h` fields — the materials and a hash of them, so what is
   * fetched later is checkable against what was signed. This one keeps sending
   * the older task family until every caller has moved.
   */
  attachEvidence(
    channel: string,
    taskId: string,
    evidenceType: string,
    summary: string,
    url?: string,
  ): void {
    const payload: Record<string, unknown> = { type: evidenceType, summary };
    if (url) payload.url = url;
    const urlStr = url ? ` — ${url}` : '';
    this.emitEvent(channel, 'evidence_attach', payload, {
      refId: taskId,
      extraTags: { '+freeq.at/evidence-type': evidenceType },
      humanText: `📎 Evidence (${evidenceType}): ${summary}${urlStr}`,
    });
  }

  // ── Spawning (Phase 4) ──

  /** Submit an agent manifest (base64-encoded TOML). */
  submitManifest(tomlContent: string): void {
    const bytes = new TextEncoder().encode(tomlContent);
    const b64 = btoa(String.fromCharCode(...bytes));
    this.raw(`AGENT MANIFEST ${b64}`);
  }

  /** Spawn a child agent in a channel. */
  spawnAgent(
    channel: string,
    nick: string,
    capabilities: string[],
    ttlSeconds?: number,
    taskRef?: string,
  ): void {
    let params = `nick=${nick}`;
    if (capabilities.length > 0) params += `;capabilities=${capabilities.join(',')}`;
    if (ttlSeconds !== undefined) params += `;ttl=${ttlSeconds}`;
    if (taskRef) params += `;task=${taskRef}`;
    this.raw(`AGENT SPAWN ${channel} :${params}`);
  }

  /** Despawn a child agent (parent only). */
  despawnAgent(nick: string): void {
    this.raw(`AGENT DESPAWN ${nick}`);
  }

  /** Send a message attributed to a spawned child agent. */
  sendAsChild(childNick: string, channel: string, text: string): void {
    this.raw(`AGENT MSG ${childNick} ${channel} :${text}`);
  }

  // ── Economics (Phase 5) ──

  /** Submit a spend record for the current action.
   *  (Server emits a `budget_exceeded` governance TAGMSG to us if this
   *  spend pushes us past the per-agent budget cap.) */
  submitSpend(
    channel: string,
    amount: number,
    unit: string,
    description: string,
    taskRef?: string,
  ): void {
    let params = `amount=${amount.toFixed(6)};unit=${unit};desc=${description}`;
    if (taskRef) params += `;task=${taskRef}`;
    this.raw(`SPEND ${channel} :${params}`);
  }

  /** Set a per-agent budget on a channel (op only). */
  setBudget(
    channel: string,
    maxAmount: number,
    unit: string,
    period: string,
    sponsorDid: string,
  ): void {
    this.raw(`BUDGET ${channel} :max=${maxAmount};unit=${unit};period=${period};sponsor=${sponsorDid}`);
  }

  /** Query channel budget state (server replies with snapshot). */
  requestBudget(channel: string): void {
    this.raw(`BUDGET ${channel}`);
  }
}

/**
 * The mutation a TAGMSG's tags describe: the kind, the root msgid it acts on,
 * and — for reactions — the emoji.
 *
 * Both spellings of every tag, and the same three shapes the Rust SDK and the
 * server read, so what one signs is what the others rebuild. `null` for every
 * other TAGMSG: typing, AV signalling and presence assert nothing durable
 * under a user's name, so there is nothing for a signature to be evidence of.
 */
function mutationIn(
  tags: Record<string, string>,
): { kind: 'delete' | 'react' | 'unreact'; subject?: string; emoji?: string } | null {
  const subject = tags['+reply'] ?? tags['+draft/reply'];
  const deleted = tags['+draft/delete'] ?? tags['+delete'];
  if (deleted) return { kind: 'delete', subject: deleted };
  const react = tags['+react'] ?? tags['+draft/react'];
  if (react) return { kind: 'react', subject, emoji: react };
  const unreact = tags['+freeq.at/unreact'];
  if (unreact) return { kind: 'unreact', subject, emoji: unreact };
  return null;
}

/** ULID shape: 26 characters of uppercase Crockford base32. What a server
 *  checks before it will adopt a client-minted id as an event's own. */
function isUlid(id: string): boolean {
  return /^[0-9A-HJKMNP-TV-Z]{26}$/.test(id);
}

/** Generate a coordination event ID. Format mirrors Rust SDK
 *  (millis-hex + 16 random hex chars). Not a ULID. */
function mintEventId(): string {
  const millis = Date.now().toString(16).padStart(13, '0');
  const r1 = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0');
  const r2 = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0');
  return millis + r1 + r2;
}
