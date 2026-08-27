/**
 * IRC client bridge — thin wrapper that connects @freeq/sdk to the Zustand store.
 *
 * Components import from here and get the same API as before.
 * Internally, all protocol handling is delegated to the SDK's FreeqClient.
 */

import { FreeqClient, format } from '@freeq/sdk';
import { useStore } from '../store';
import { notify } from '../lib/notifications';
import { prefetchProfiles } from '@freeq/sdk';
import { shouldRejoinCall, AV_REJOIN_WINDOW_MS, type PendingCallRejoin } from '../lib/av-mesh';
import { fetchFavorites, pushFavorites, mergeFavorites, favoritesEqual } from '../lib/favorites-sync';
import { createDmSendGate, dmThreadKey } from './dm-resolve';

// Roaming-favorites state (module scope so it survives reconnects).
let favoritesSynced = false;
let favoritesPushWired = false;

/** Pull the DID's server favorites, union with local, write back if changed,
 *  and wire a debounced push for future toggles. No-op without a bearer. */
async function syncFavorites(c: FreeqClient): Promise<void> {
  // The API-BEARER notice can land just after 'registered'; poll briefly.
  let bearer = c.apiBearer;
  for (let i = 0; !bearer && i < 20; i++) {
    await new Promise((r) => setTimeout(r, 200));
    bearer = c.apiBearer;
  }
  if (!bearer) return; // guest / no authenticated session
  try {
    const server = await fetchFavorites(bearer);
    const local = [...useStore.getState().favorites];
    const merged = mergeFavorites(server, local);
    if (!favoritesEqual(merged, local)) useStore.getState().setFavorites(merged);
    if (!favoritesEqual(merged, server)) await pushFavorites(bearer, merged);
    favoritesSynced = true;
  } catch { /* transient; try again next connect */ }

  // Push future changes (debounced). Wire once; guarded by favoritesSynced
  // so the initial merge above doesn't echo a redundant push.
  if (favoritesPushWired) return;
  favoritesPushWired = true;
  let last = [...useStore.getState().favorites].join(',');
  let timer: ReturnType<typeof setTimeout> | null = null;
  useStore.subscribe((st) => {
    const b = c.apiBearer;
    if (!favoritesSynced || !b) return;
    const now = [...st.favorites].join(',');
    if (now === last) return;
    last = now;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { pushFavorites(b, [...st.favorites]).catch(() => {}); }, 400);
  });
}

// ── Singleton SDK client ──

let client: FreeqClient | null = null;

/**
 * How long a first DM waits to learn its peer. Long enough for a WHOIS
 * round-trip, short enough that a typed message never feels stuck.
 */
const DM_PEER_WHOIS_TIMEOUT_MS = 2000;

/** Rebuilt per connection: what a peer resolved to dies with the session. */
let dmSendGate: ((target: string, send: () => void) => void) | null = null;

/** Send to a DM peer, waiting once for a stranger's identity. */
function sendToPeer(target: string, send: () => void): void {
  if (dmSendGate) dmSendGate(target, send);
  else send();
}

/**
 * Make sure the conversation is filed where the SDK will address and echo it.
 * Learning a peer's DID moves the thread, so a buffer opened under the bare
 * nick has to follow, or the message the user just sent lands in a thread
 * they aren't looking at.
 */
function ensureDmThread(target: string): void {
  if (target.startsWith('#') || target.startsWith('&')) return;
  const store = useStore.getState();
  const key = dmThreadKey(target, (nick) => client?.getDidForNick(nick));
  if (!store.channels.has(key.toLowerCase())) store.addChannel(key);
  if (key === target) return;
  if (store.activeChannel.toLowerCase() !== target.toLowerCase()) return;
  store.setActiveChannel(key);
  // Don't leave an empty twin of the same conversation behind.
  if (!store.channels.get(target.toLowerCase())?.messages.length) {
    store.removeChannel(target);
  }
}

const SAVED_CHANNELS_KEY = 'freeq-joined-channels';

function saveJoinedChannels() {
  try {
    if (client) {
      localStorage.setItem(SAVED_CHANNELS_KEY, JSON.stringify([...client.joinedChannels]));
    }
  } catch { /* quota exceeded, etc */ }
}

/** Get the underlying SDK client (for advanced usage). */
/** Local authed fetch. This module owns the singleton client, so it must not
 *  import ../lib/api (that would be a cycle); components use apiFetch there. */
function authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const bearer = client?.apiBearer;
  if (!bearer) return fetch(path, init);
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${bearer}`);
  return fetch(path, { ...init, headers });
}

export function getClient(): FreeqClient | null {
  return client;
}

/**
 * Test-only seam. Lets unit tests inject a stub FreeqClient (typically
 * something that only implements `raw`/`nick`) so they can assert on the
 * raw IRC lines our AV functions send without bringing up a real SDK.
 *
 * Never call this from production code.
 */
export function __setClientForTests(c: FreeqClient | null): void {
  client = c;
}

/** Test-only: reset the per-call instance suffix so tests can start fresh. */
export function __resetAvInstanceForTests(): void {
  currentAvInstance = null;
  pendingAvStart = null;
  pendingCallRejoin = null;
}

/** Test-only: inspect the captured pending rejoin (null when none). */
export function __getPendingCallRejoinForTests(): PendingCallRejoin | null {
  return pendingCallRejoin;
}

// ── Public API (same signatures as before) ──

export function connect(url: string, desiredNick: string, channels?: string[]) {
  if (client) {
    try { client.disconnect(); } catch { /* ignore */ }
    client = null;
  }

  const store = useStore.getState();
  store.reset();

  client = new FreeqClient({
    url,
    nick: desiredNick,
    channels,
    brokerUrl: localStorage.getItem('freeq-broker-base') || undefined,
    brokerToken: localStorage.getItem('freeq-broker-token') || undefined,
    skipInitialBrokerRefresh: !!saslState.skipBrokerRefresh,
  });

  // Set SASL credentials if we have them
  if (saslState.token) {
    client.setSaslCredentials({
      token: saslState.token,
      did: saslState.did,
      pdsUrl: saslState.pdsUrl,
      method: saslState.method,
    });
  }

  // Provide nick→DID resolver for E2EE
  client.nickToDid = (targetNick: string) => {
    const s = useStore.getState();
    const lower = targetNick.toLowerCase();
    for (const ch of s.channels.values()) {
      const m = ch.members.get(lower);
      if (m?.did) return m.did;
    }
    return undefined;
  };

  // A DM to someone we share no channel with reaches the SDK as a bare nick,
  // which it will not sign — no venue a verifier could rebuild. One WHOIS
  // before the first message turns that into an addressed, signed DM.
  const sdk = client;
  dmSendGate = createDmSendGate({
    didForNick: (nick) => sdk.getDidForNick(nick),
    requestWhois: (nick) => sdk.requestWhois(nick, { timeoutMs: DM_PEER_WHOIS_TIMEOUT_MS }),
  });

  wireEvents(client);
  client.connect();

  // Send QUIT when tab/window is closing
  window.addEventListener('beforeunload', () => {
    if (client) {
      try { client.quit('Leaving'); } catch { /* ignore */ }
    }
  });
}

export function disconnect() {
  client?.disconnect();
  client = null;
  dmSendGate = null;
  saslState = { token: '', did: '', pdsUrl: '', method: '', skipBrokerRefresh: false };
  // Clear persistent-login material so ConnectScreen doesn't immediately
  // re-auth the user via broker session refresh after a deliberate logout.
  try {
    localStorage.removeItem('freeq-broker-token');
    localStorage.removeItem('freeq-oauth-result');
    localStorage.removeItem('freeq-oauth-pending');
  } catch { /* ignore */ }
  useStore.getState().fullReset();
}

export function reconnect() {
  if (!client) return;
  const channels = [...(client.joinedChannels)];
  const opts = client['opts']; // access private opts for url/nick
  client.disconnect();
  client = null;
  // For an authenticated, broker-backed (web) session, force a fresh broker
  // session refresh instead of replaying the in-memory token: web tokens are
  // single-use, so a manual reconnect with the stale token would just fail
  // SASL and bounce us back to guest. Clearing the token + skipBrokerRefresh
  // makes the SDK re-mint via /session on (re)connect.
  const hasBroker =
    !!localStorage.getItem('freeq-broker-token') &&
    !!localStorage.getItem('freeq-broker-base');
  if (saslState.did && hasBroker) {
    saslState = { ...saslState, token: '', skipBrokerRefresh: false };
  }
  const store = useStore.getState();
  store.reset();
  connect(opts.url, opts.nick, channels);
}

// SASL state (set before connect)
let saslState = { token: '', did: '', pdsUrl: '', method: '', skipBrokerRefresh: false };

export function setSaslCredentials(token: string, did: string, pdsUrl: string, method: string) {
  saslState = { token, did, pdsUrl, method, skipBrokerRefresh: !!token };
  if (client) {
    client.setSaslCredentials({ token, did, pdsUrl, method });
  }
}

export function sendMessage(target: string, text: string, multiline = false) {
  sendToPeer(target, () => {
    client?.sendMessage(target, text, multiline);
    ensureDmThread(target);
  });
}

export function sendReply(target: string, replyToMsgId: string, text: string, multiline = false) {
  sendToPeer(target, () => {
    client?.sendReply(target, replyToMsgId, text, multiline);
    ensureDmThread(target);
  });
}

export function sendEdit(target: string, originalMsgId: string, newText: string, multiline = false) {
  sendToPeer(target, () => client?.sendEdit(target, originalMsgId, newText, multiline));
}

export function sendMarkdown(target: string, text: string) {
  sendToPeer(target, () => client?.sendMarkdown(target, text));
}

export function sendAction(target: string, text: string) {
  sendToPeer(target, () => client?.sendAction(target, text));
}

export function sendDelete(target: string, msgId: string) {
  sendToPeer(target, () => client?.sendDelete(target, msgId));
}

export function sendReaction(target: string, emoji: string, msgId?: string) {
  sendToPeer(target, () => client?.sendReaction(target, emoji, msgId));
}

export function sendUnreact(target: string, emoji: string, msgId: string) {
  sendToPeer(target, () => client?.sendUnreact(target, emoji, msgId));
}

/**
 * Typing is a hint about a message that may never be sent, so it goes straight
 * out rather than through the DM identity gate: an ephemeral tag is not worth
 * holding a keystroke for a WHOIS round trip, and the server routes a TAGMSG
 * to a bare nick as readily as to a DID.
 */
export function startTyping(target: string) {
  client?.startTyping(target);
}

export function stopTyping(target: string) {
  client?.stopTyping(target);
}

export function joinChannel(channel: string) {
  client?.join(channel);
  useStore.getState().addChannel(channel);
  useStore.getState().setActiveChannel(channel);
}

export function partChannel(channel: string) {
  client?.part(channel);
  useStore.getState().removeChannel(channel);
  saveJoinedChannels();
}

export function setTopic(channel: string, topic: string) {
  client?.setTopic(channel, topic);
}

export function setMode(channel: string, mode: string, arg?: string) {
  client?.setMode(channel, mode, arg);
}

export function kickUser(channel: string, userNick: string, reason?: string) {
  client?.kick(channel, userNick, reason);
}

export function inviteUser(channel: string, userNick: string) {
  client?.invite(channel, userNick);
}

export function setAway(reason?: string) {
  client?.setAway(reason);
}

export function sendWhois(userNick: string) {
  if (!client) return;
  client.whois(userNick);
  // Marked only once the ask is actually on the wire — a surface waiting on
  // the answer must never wait on a question nobody asked.
  useStore.getState().markWhoisPending(userNick);
}

/** Rows one page of history asks for. */
export const HISTORY_PAGE = 50;

/** How long a page has to arrive before the request is written off. A FAIL
 *  (an anchor naming no stored row) or a dropped connection would otherwise
 *  leave the channel loading forever. */
const HISTORY_TIMEOUT_MS = 10_000;

const historyTimers = new Map<string, ReturnType<typeof setTimeout>>();

function clearHistoryTimer(key: string) {
  const t = historyTimers.get(key);
  if (t !== undefined) {
    clearTimeout(t);
    historyTimers.delete(key);
  }
}

/** CHATHISTORY subcommands, which sit where a target could and are all legal
 *  nicks. */
const HISTORY_SUBCOMMANDS = new Set([
  'latest', 'before', 'after', 'around', 'between', 'targets',
]);

/** Which word of `CHATHISTORY <code> …` names the target, by code, counting
 *  the command word as 0. Codes not listed have no fixed position. */
const HISTORY_FAIL_TARGET_AT: Record<string, number> = {
  message_error: 3,      // <subcommand> <target>
  invalid_target: 2,
  account_required: 2,
};

/** The channel a `FAIL CHATHISTORY …` answers, if we are waiting on a page
 *  for it.
 *
 *  The parameter that names the target sits in a different position per error
 *  code, so rather than parse by code this matches the ones that could hold a
 *  target against the targets we actually have a page out for. A FAIL for
 *  anything else is not ours to act on.
 *
 *  For the codes whose shape is known the target is read from its own
 *  position and nowhere else: the subcommand sits where a target could and
 *  every subcommand is a legal nick, and the description that follows is
 *  prose in which a channel name means nothing. Codes with no known shape
 *  fall back to scanning what is left, skipping the words that can only be
 *  subcommands. */
function pendingHistoryTargetIn(text: string): string | null {
  if (!text.startsWith('CHATHISTORY ')) return null;
  const words = text.toLowerCase().split(/\s+/);
  const at = HISTORY_FAIL_TARGET_AT[words[1] ?? ''];
  const candidates = at !== undefined
    ? [words[at]]
    : words.slice(2).filter((w) => !HISTORY_SUBCOMMANDS.has(w));
  for (const candidate of candidates) {
    if (candidate && historyTimers.has(candidate)) return candidate;
  }
  return null;
}

/** An anchor for the page of history older than what is already held. */
export interface HistoryAnchor {
  msgid?: string;
  timestamp?: string;
}

/** Ask for history in `channel`: with an anchor, the page around, older or
 *  newer than it; without one, the most recent page.
 *
 *  Either way the request is tracked, so its answer teaches the channel
 *  what is above the oldest row it holds. An untracked request tells the
 *  app nothing — which is how a channel with no row to anchor on, and a
 *  channel shorter than one page, both ended up showing a button over
 *  history that was already complete. */
export function requestHistory(
  channel: string,
  anchor?: HistoryAnchor,
  mode: 'before' | 'around' | 'after' = 'before',
) {
  if (!client) return;
  const anchored = !!anchor && (!!anchor.msgid || !!anchor.timestamp);
  const key = channel.toLowerCase();
  useStore.getState().historyFetchStarted(channel, anchored, mode);
  clearHistoryTimer(key);
  historyTimers.set(key, setTimeout(() => {
    historyTimers.delete(key);
    useStore.getState().historyFetchFailed(channel);
  }, HISTORY_TIMEOUT_MS));
  client.requestHistory(
    anchored
      ? { target: channel, mode, count: HISTORY_PAGE, ...anchor }
      : { target: channel, mode: 'latest', count: HISTORY_PAGE },
  );
}

export function requestDmTargets(limit = 50) {
  client?.requestHistoryTargets(limit);
}

export function rawCommand(line: string) {
  client?.raw(line);
}

export function getNick(): string {
  return client?.nick ?? '';
}

export function pinMessage(channel: string, msgid: string) {
  client?.pin(channel, msgid);
}

export function unpinMessage(channel: string, msgid: string) {
  client?.unpin(channel, msgid);
}

// ── AV Session ──

let pendingAvStart: { channel: string; did: string } | null = null;

/// Per-call random suffix. Sent on every av-start/av-join/av-leave as the
/// `+freeq.at/av-instance` tag and used to build the MoQ broadcast path
/// (`{sessionId}/{nick}~{instance}`), so two devices signed in as the same
/// DID get distinct participant slots and broadcasts.
let currentAvInstance: string | null = null;

/// A call dropped by a connection blip, kept so a reconnect can rejoin the
/// same session+instance within the server's AV grace window. Set only on a
/// disconnect-driven teardown (see `connectionStateChanged`); cleared on
/// explicit leave, once consumed by a rejoin, or once it passes the window.
let pendingCallRejoin: PendingCallRejoin | null = null;

function generateAvInstanceId(): string {
  // 4 random bytes → 8 lowercase hex chars. Plenty of entropy for
  // collision avoidance within a session; short enough that broadcast
  // paths stay readable in logs.
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function getAvInstanceId(): string | null {
  return currentAvInstance;
}

// Per-channel in-flight guard. We only want to suppress *concurrent*
// startAvSession invocations for the same channel (rapid double-clicks
// while the discovery fetch is in flight); the previous guard checked
// store.avAudioActive which would stick true after any teardown blip
// and silently no-op every future button click on that user's session.
const _startInFlight = new Set<string>();

/// Convergence-poll pacing for startAvSession. Injectable so tests don't sit
/// through the production 16×500 ms schedule — a timed-out test used to leave
/// the poll running, and the in-flight guard then silently suppressed every
/// later startAvSession in the file (order-dependent failures).
let avStartPoll = { intervalMs: 500, attempts: 16 };
export function __setAvStartPollForTests(intervalMs: number, attempts: number): void {
  avStartPoll = { intervalMs, attempts };
}

/** Seed an AV session into the store from the REST `/sessions` shape, so
 *  CallPanel (which renders `avSessions.get(activeAvSession)`) can mount
 *  immediately rather than waiting for the 5s discovery poll. */
function seedAvSessionFromRest(active: {
  id: string; channel: string; created_by?: string; created_by_nick?: string;
  title?: string; created_at?: number; iroh_ticket?: string;
  participants?: Array<{ nick: string; did?: string; role?: string; joined_at?: number }>;
}) {
  const participants = new Map<string, import('../store').AvParticipant>();
  for (const p of active.participants || []) {
    participants.set(p.nick, {
      did: p.did || '', nick: p.nick,
      role: (p.role as import('../store').AvParticipant['role']) || 'speaker',
      joinedAt: new Date((p.joined_at || 0) * 1000),
    });
  }
  useStore.getState().updateAvSession({
    id: active.id, channel: active.channel, createdBy: active.created_by || '',
    createdByNick: active.created_by_nick || '', title: active.title || undefined,
    participants, state: 'active', startedAt: new Date((active.created_at || 0) * 1000),
    irohTicket: active.iroh_ticket || undefined,
  });
}

export async function startAvSession(channel: string, title?: string) {
  const store = useStore.getState();
  if (!store.authDid) {
    store.addSystemMessage(channel, 'You must be signed in with AT Protocol to start a voice session.');
    return;
  }
  if (store.connectionState !== 'connected') {
    store.addSystemMessage(channel, 'Cannot start voice session: not connected to server.');
    return;
  }
  const key = channel.toLowerCase();
  if (_startInFlight.has(key)) return;
  _startInFlight.add(key);

  try {
    try {
      const resp = await authedFetch(`/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
      if (resp.ok) {
        const data = await resp.json();
        if (data.active && data.active.state === 'Active') {
          store.addSystemMessage(channel, `Joining existing voice session (${data.active.participant_count} participants)`);
          // Seed the session NOW so CallPanel can mount on this same click —
          // setting activeAvSession alone, before the 5s poll populates the
          // map, leaves CallPanel with nothing to render.
          seedAvSessionFromRest(data.active);
          joinAvSession(channel, data.active.id);
          store.setAvAudioActive(true);
          return;
        }
      }
    } catch (e) {
      console.warn('[av] Failed to check existing sessions:', e);
    }

    store.addSystemMessage(channel, 'Starting voice session...');
    pendingAvStart = { channel, did: store.authDid };
    currentAvInstance = generateAvInstanceId();
    const tags: Record<string, string> = {
      '+freeq.at/av-start': '',
      '+freeq.at/av-instance': currentAvInstance,
    };
    if (title) tags['+freeq.at/av-title'] = title;
    client?.raw(format('TAGMSG', [channel], tags));
    store.setAvAudioActive(true);

    // Converge on the session we just created. The av-state SDK event is
    // supposed to fire and set activeAvSession (see the avSessionUpdate
    // handler), but if it doesn't fire or its createdBy doesn't match, a user
    // starting a call ALONE is left with avAudioActive=true and no
    // activeAvSession — so CallPanel never mounts and the call seems to never
    // start. Poll the channel roster for our freshly-created session and
    // activate it directly. Idempotent with the event: whichever sets
    // activeAvSession first wins; the other no-ops.
    const myDid = store.authDid;
    for (let i = 0; i < avStartPoll.attempts; i++) {
      if (useStore.getState().activeAvSession) { pendingAvStart = null; break; }
      await new Promise((r) => setTimeout(r, avStartPoll.intervalMs));
      try {
        const r = await authedFetch(`/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
        if (!r.ok) continue;
        const d = await r.json();
        const active = d.active;
        if (active && active.state === 'Active' && active.created_by === myDid) {
          if (!useStore.getState().activeAvSession) {
            seedAvSessionFromRest(active);
            useStore.getState().setActiveAvSession(active.id);
          }
          pendingAvStart = null;
          break;
        }
      } catch { /* keep polling */ }
    }
  } finally {
    _startInFlight.delete(key);
  }
}

export function joinAvSession(channel: string, sessionId?: string) {
  // Without a sessionId there's no way for the server to route the join,
  // so don't send a half-formed TAGMSG that just looks like noise. Callers
  // that don't know the session ID yet should call `startAvSession`
  // (which discovers and joins as appropriate).
  if (!sessionId) return;
  if (!currentAvInstance) currentAvInstance = generateAvInstanceId();
  const tags: Record<string, string> = {
    '+freeq.at/av-join': '',
    '+freeq.at/av-instance': currentAvInstance,
    '+freeq.at/av-id': sessionId,
  };
  useStore.getState().setActiveAvSession(sessionId);
  client?.raw(format('TAGMSG', [channel], tags));
}

export function leaveAvSession(channel: string, sessionId: string) {
  const tags: Record<string, string> = {
    '+freeq.at/av-leave': '',
    '+freeq.at/av-id': sessionId,
  };
  if (currentAvInstance) tags['+freeq.at/av-instance'] = currentAvInstance;
  client?.raw(format('TAGMSG', [channel], tags));
  currentAvInstance = null;
  // Explicit leave — a reconnect must NOT drag us back into the call.
  pendingCallRejoin = null;
  useStore.getState().setActiveAvSession(null);
}

export function endAvSession(channel: string, sessionId: string) {
  const tags: Record<string, string> = {
    '+freeq.at/av-end': '',
    '+freeq.at/av-id': sessionId,
  };
  client?.raw(format('TAGMSG', [channel], tags));
}

export function sendAvSignal(targetNick: string, data: string) {
  const encoded = encodeURIComponent(data);
  const MAX_CHUNK = 4000;
  if (encoded.length <= MAX_CHUNK) {
    client?.raw(format('TAGMSG', [targetNick], { '+freeq.at/av-signal': encoded }));
  } else {
    const id = Math.random().toString(36).slice(2, 8);
    const chunks = Math.ceil(encoded.length / MAX_CHUNK);
    for (let i = 0; i < chunks; i++) {
      const chunk = encoded.slice(i * MAX_CHUNK, (i + 1) * MAX_CHUNK);
      client?.raw(format('TAGMSG', [targetNick], {
        '+freeq.at/av-signal': chunk,
        '+freeq.at/av-chunk': `${id}:${i}:${chunks}`,
      }));
    }
  }
}

// ── Event wiring: SDK events → Zustand store ──

/**
 * Test-only export of the event wiring. Production callers should
 * use {@link connect}, which wires events as part of bringing up the
 * real SDK client. Tests use this to drive synthetic events through
 * a stub `FreeqClient` and assert on the resulting store state.
 */
export function __wireEventsForTests(c: FreeqClient): void {
  wireEvents(c);
}

function wireEvents(c: FreeqClient) {
  const s = () => useStore.getState();

  c.on('connectionStateChanged', (state) => {
    s().setConnectionState(state);
    if (state !== 'connected') {
      // Nothing is going to arrive over a socket that is gone, so the pages
      // waiting on one end here rather than ten seconds from now. Held off
      // as well as ended: asking again while there is no transport would
      // just queue another dead request.
      for (const key of [...historyTimers.keys()]) {
        clearHistoryTimer(key);
        useStore.getState().historyFetchFailed(key);
      }
    } else {
      // Back again, so the reason for holding off is gone. Other buffers
      // re-arm when the reader returns to them, which they already do.
      useStore.getState().historyAutoResumed(useStore.getState().activeChannel);
    }
    // Left 'connected' while in a call: capture the call identity so the
    // reconnect can rejoin the SAME session with the SAME instance within
    // the server's AV grace window (mirrors macOS
    // tearDownCallLocallyOnDisconnect). Guarded on `!pendingCallRejoin` so
    // the intermediate disconnected → connecting transitions don't reset the
    // drop timestamp — the window is measured from the actual drop.
    const instance = currentAvInstance;
    if (state !== 'connected' && !pendingCallRejoin && instance) {
      const store = s();
      const sess = store.activeAvSession
        ? store.avSessions.get(store.activeAvSession)
        : null;
      if (store.avAudioActive && sess && sess.channel) {
        pendingCallRejoin = {
          channel: sess.channel,
          sessionId: sess.id,
          instance,
          disconnectedAt: Date.now(),
        };
      }
    }
  });

  c.on('registered', (nick) => {
    s().setNick(nick);
    s().setRegistered(true);
    s().setConnectedServer(c['opts'].url);

    // Restore last active channel after joins complete
    const savedActive = localStorage.getItem('freeq-active-channel');
    if (savedActive && savedActive !== 'server') {
      setTimeout(() => {
        const ch = useStore.getState().channels.get(savedActive.toLowerCase());
        if (ch) useStore.getState().setActiveChannel(savedActive);
      }, 500);
    }

    // Roaming favorites: pull the DID's server-side favorites, union with
    // local (no device loses one), write back if changed, then keep the
    // server in sync on subsequent toggles. Only for authenticated users
    // (the bearer arrives via the API-BEARER notice around SASL success).
    syncFavorites(c);
  });

  c.on('nickChanged', (nick) => {
    s().setNick(nick);
  });

  c.on('authenticated', (did, message) => {
    s().setAuth(did, message);
    if (did) prefetchProfiles([did]);
  });

  c.on('authError', (error) => {
    s().setAuthError(error);
  });

  c.on('channelJoined', (channel) => {
    s().addChannel(channel);
    s().clearMembers(channel);
    const savedActive = localStorage.getItem('freeq-active-channel');
    if (!savedActive || s().activeChannel === 'server') {
      s().setActiveChannel(channel);
    }
    saveJoinedChannels();

    // If a blip dropped us mid-call in this channel, rejoin the same AV
    // session with the same instance — the server held the slot in its grace
    // window, so this re-enters in place and instance-keyed peers see media
    // continuity. joinAvSession re-sends av-join and re-activates the panel.
    if (shouldRejoinCall(pendingCallRejoin, channel, Date.now())) {
      const rejoin = pendingCallRejoin!;
      pendingCallRejoin = null;
      currentAvInstance = rejoin.instance; // stable across the blip
      joinAvSession(rejoin.channel, rejoin.sessionId);
      s().setAvAudioActive(true);
    } else if (
      pendingCallRejoin &&
      Date.now() - pendingCallRejoin.disconnectedAt >= AV_REJOIN_WINDOW_MS
    ) {
      // Stale pending (past the window) — clear so it can't fire on a later join.
      pendingCallRejoin = null;
    }
  });

  c.on('channelLeft', (channel) => {
    s().removeChannel(channel);
    saveJoinedChannels();
  });

  c.on('memberJoined', (channel, member) => {
    if (channel) s().addMember(channel, member);
    if (member.did) prefetchProfiles([member.did]);
  });

  c.on('memberLeft', (channel, nick) => {
    s().removeMember(channel, nick);
  });

  c.on('userQuit', (nick, reason) => {
    s().removeUserFromAll(nick, reason);
  });

  c.on('userRenamed', (oldNick, newNick) => {
    s().renameUser(oldNick, newNick);
  });

  c.on('userAway', (nick, reason) => {
    s().setUserAway(nick, reason);
  });

  c.on('typing', (channel, nick, isTyping) => {
    s().setTyping(channel, nick, isTyping);
  });

  c.on('topicChanged', (channel, topic, setBy) => {
    s().setTopic(channel, topic, setBy);
  });

  c.on('modeChanged', (channel, mode, arg, setBy) => {
    s().handleMode(channel, mode, arg, setBy);
  });

  c.on('membersList', (channel, members) => {
    for (const m of members) {
      s().addMember(channel, m);
    }
  });

  // End-of-NAMES: replace the roster with the server's authoritative snapshot.
  // This is what makes a self-JOIN clear / nick collision / reconnect unable to
  // leave the member list showing only live-joined members (the bug where
  // everyone delivered via NAMES — zapnap, etc. — vanished).
  c.on('membersSync', (channel, members) => {
    s().setMembers(channel, members);
    for (const m of members) if (m.did) prefetchProfiles([m.did]);
  });

  c.on('memberDid', (nick, did) => {
    s().updateMemberDid(nick, did);
  });

  c.on('message', (channel, message) => {
    // Prefetch avatar by DID if available (from account-tag)
    if (message.tags?.account) prefetchProfiles([message.tags.account]);

    // Ensure DM buffer exists
    const isChannel = channel.startsWith('#') || channel.startsWith('&');
    if (!isChannel && !useStore.getState().channels.has(channel.toLowerCase())) {
      s().addChannel(channel);
    }
    s().addMessage(channel, message as import('../store').Message);

    // Mention/DM notification
    const isMention = !message.isSelf && message.text.toLowerCase().includes(c.nick.toLowerCase());
    const isDM = !isChannel && !message.isSelf;
    if (isMention) s().incrementMentions(channel);
    if (isDM) s().incrementMentions(channel);
    if ((isMention || isDM) && !useStore.getState().mutedChannels.has(channel.toLowerCase())) {
      notify(
        isDM ? `DM from ${message.from}` : channel,
        `${message.from}: ${message.text.slice(0, 100)}`,
        () => useStore.getState().setActiveChannel(channel),
        isDM ? 'dm' : 'mention',
      );
    }
  });

  c.on('messageEdited', (channel, originalMsgId, newText, newMsgId, isStreaming, editorNick, editorAccount) => {
    // Ensure DM buffer exists
    const isChannel = channel.startsWith('#') || channel.startsWith('&');
    if (!isChannel && !useStore.getState().channels.has(channel.toLowerCase())) {
      s().addChannel(channel);
    }
    s().editMessage(channel, originalMsgId, newText, newMsgId, isStreaming, editorNick, editorAccount);
  });

  c.on('messageDeleted', (channel, msgId, deleterNick, deleterAccount) => {
    s().deleteMessage(channel, msgId, deleterNick, deleterAccount);
  });

  c.on('serverFail', (text) => {
    // A refusal is an answer. Resolving it here rather than waiting out the
    // timer is what turns an old server's ACCOUNT_REQUIRED, or an anchor it
    // does not know, into the button at once instead of ten seconds of
    // spinner. The timer stays as the backstop for silence.
    const pending = pendingHistoryTargetIn(text);
    if (pending) {
      clearHistoryTimer(pending);
      useStore.getState().historyFetchFailed(pending);
    }
    // Server rejected an action (FAIL <cmd> <code> <desc>). Show it where
    // the user is looking — silent rejections are undebuggable. Exception:
    // background history probes (speculative CHATHISTORY on opening a
    // thread) fail routinely for guest peers; rendering those spams a red
    // line per open while telling the user nothing actionable.
    if (/^CHATHISTORY (INVALID_TARGET|ACCOUNT_REQUIRED)/.test(text)) return;
    const active = useStore.getState().activeChannel || 'server';
    s().addSystemMessage(active, `Server error: ${text}`);
  });

  c.on('reactionAdded', (channel, msgId, emoji, fromNick) => {
    s().addReaction(channel, msgId, emoji, fromNick);
  });

  c.on('reactionRemoved', (channel, msgId, emoji, fromNick) => {
    s().removeReaction(channel, msgId, emoji, fromNick);
  });

  c.on('systemMessage', (target, text) => {
    // Skip internal mention markers
    if (target === '__mention__') return;
    s().addSystemMessage(target, text);
  });

  c.on('historyBatch', (channel, messages, info) => {
    // Prefetch avatars by DID for history messages
    const dids = messages.map((m: any) => m.tags?.account).filter(Boolean);
    if (dids.length) prefetchProfiles(dids);

    const key = channel.toLowerCase();
    const held = () => useStore.getState().channels.get(key)?.messages.length ?? 0;

    // A page that lands where the window has not reached becomes the window
    // rather than merging into it: an around page is somewhere the reader
    // jumped to, and a newest page asked for from a window away from the
    // live end is the reader coming back to the present. Merging either one
    // would leave a run of the conversation missing in the middle of the
    // held list with nothing to say it was.
    const waiting = useStore.getState().channels.get(key);
    const replaces = waiting?.historyFetching && (!info || info.mode === waiting.historyFetchMode)
      && (waiting.historyFetchMode === 'around'
        || (waiting.historyFetchMode === 'latest' && waiting.newerEdge === 'more'));

    // Merge first, then report both counts: the size off the wire, which is
    // the only thing that says whether more history exists, and how many
    // rows actually reached the held list, which is what says whether
    // asking again on the same anchor would get anywhere.
    const before = held();
    if (replaces) {
      useStore.getState().openWindow(
        channel,
        messages as import('../store').Message[],
        waiting!.historyFetchMode === 'latest',
      );
    } else {
      useStore.getState().mergeHistory(
        channel,
        messages as import('../store').Message[],
      );
    }
    const added = replaces ? held() : held() - before;

    const ch = useStore.getState().channels.get(key);
    // The channel is waiting on one particular page. An answer the bridge
    // cannot place against it leaves the channel reading as still loading
    // until the timer runs out.
    const expected = ch?.historyFetchMode ?? 'latest';
    if (ch?.historyFetching && (!info || info.mode === expected)) {
      clearHistoryTimer(key);
      useStore.getState().historyPageReceived(
        channel, messages.length, info?.count ?? HISTORY_PAGE, added,
      );
    } else if (info?.mode === 'latest') {
      // The opening page, which the SDK asks for on join without telling the
      // app. Its size is what lets a channel shorter than one page know its
      // history is complete before anyone scrolls.
      useStore.getState().historyOpeningPage(channel, messages.length, info.count);
    }
  });

  c.on('dmTarget', (nick) => {
    s().addDmTarget(nick);
  });

  c.on('channelListEntry', (entry) => {
    s().addChannelListEntry(entry);
  });

  c.on('pins', (channel, pins) => {
    s().setPins(channel, pins);
  });

  c.on('pinAdded', (channel, msgid, pinnedBy) => {
    s().addPin(channel, msgid, pinnedBy);
  });

  c.on('pinRemoved', (channel, msgid) => {
    s().removePin(channel, msgid);
  });

  c.on('whois', (nick, info) => {
    s().updateWhois(nick, info);
  });

  c.on('whoisEnd', (nick) => {
    s().endWhoisPending(nick);
  });

  c.on('motdStart', () => {
    useStore.setState({ motd: [], motdDismissed: false });
  });

  c.on('motd', (line) => {
    s().appendMotd(line);
  });

  c.on('avSessionUpdate', (session) => {
    const sess = session as import('../store').AvSession;
    s().updateAvSession(sess);
    if (
      pendingAvStart &&
      sess.channel === pendingAvStart.channel &&
      sess.createdBy === pendingAvStart.did &&
      !s().activeAvSession
    ) {
      s().setActiveAvSession(sess.id);
      pendingAvStart = null;
    }
    // When the session we're currently in ends (anyone ran `/av end`, or
    // the host disconnected and the server reaped it), tear the panel
    // down on our side too. Without this the leaver hears nothing but
    // the remaining device still shows an "active call" UI.
    if (sess.state === 'ended' && s().activeAvSession === sess.id) {
      s().setAvAudioActive(false);
      s().setAvCameraOn(false);
      s().setActiveAvSession(null);
      currentAvInstance = null;
      if (pendingCallRejoin?.sessionId === sess.id) pendingCallRejoin = null;
    }
  });

  // Machine-readable AV failure from the server. `join-failed`: we were NOT
  // admitted to the session our UI optimistically joined — tear the call
  // state down instead of ghost-publishing into it (peers would never be
  // told to subscribe to us: we're not in the roster). `start-collision`:
  // our av-start lost a race; the tag names the winning session — converge
  // onto it immediately instead of sitting in a dead solo call.
  c.on('avError', (code, sessionId, reason) => {
    const active = s().activeAvSession;
    if (code === 'start-collision' && sessionId) {
      const winner = s().avSessions.get(sessionId);
      const channel = winner?.channel || pendingAvStart?.channel;
      pendingAvStart = null;
      if (channel) {
        joinAvSession(channel, sessionId);
        return;
      }
    }
    if (code === 'join-failed' && (active === sessionId || !sessionId)) {
      s().setAvAudioActive(false);
      s().setAvCameraOn(false);
      s().setActiveAvSession(null);
      currentAvInstance = null;
      if (pendingCallRejoin?.sessionId === sessionId) pendingCallRejoin = null;
      const ch = s().activeChannel;
      s().addSystemMessage(ch || 'server', `Couldn't join the call: ${reason || code}`);
    }
  });

  c.on('avSessionRemoved', (id) => {
    // If the SDK reaped a session we were still in (e.g. ended before we
    // saw the `state: 'ended'` update), close the panel as a safety net.
    if (s().activeAvSession === id) {
      s().setAvAudioActive(false);
      s().setAvCameraOn(false);
      s().setActiveAvSession(null);
      currentAvInstance = null;
    }
    if (pendingCallRejoin?.sessionId === id) pendingCallRejoin = null;
    s().removeAvSession(id);
  });

  c.on('avTicket', (sessionId, ticket) => {
    const session = s().avSessions.get(sessionId);
    if (session) {
      s().updateAvSession({ ...session, irohTicket: ticket } as import('../store').AvSession);
    }
  });

  c.on('joinGateRequired', (channel) => {
    if (useStore.getState().authDid) {
      s().setJoinGateChannel(channel);
    }
  });

  c.on('userKicked', (channel, kicked, _by, _reason) => {
    s().removeMember(channel, kicked);
  });

  c.on('error', (message) => {
    if (message.includes('same identity reconnected')) {
      useStore.getState().fullReset();
    }
  });

  // Handle '001' guest fallback detection — broker token refresh
  // This is handled within the SDK now; the app just needs to handle the
  // registered event, which we do above.
}
