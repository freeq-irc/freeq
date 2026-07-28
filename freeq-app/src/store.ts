import { create } from 'zustand';
import type { TransportState } from './irc/transport';
import { setLastReadMsgId } from './lib/db';

// ── Types ──

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
  reactions?: Map<string, Set<string>>; // emoji → nicks
  encrypted?: boolean; // true if this message was E2EE encrypted
}

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

/** Count members collapsed to one per account (same DID) — multi-session or
 *  nick-collision twins (e.g. chadfowler.com / chadfowlercom, or a bot that
 *  reconnected N times) count once; guests (no DID) count individually.
 *  Matches the deduped roster so header/badge counts agree with the list. */
export function uniqueMemberCount(members: Map<string, Member>): number {
  const dids = new Set<string>();
  let count = 0;
  for (const m of members.values()) {
    if (m.did) {
      if (dids.has(m.did)) continue;
      dids.add(m.did);
    }
    count++;
  }
  return count;
}

export interface PinnedMessage {
  msgid: string;
  pinned_by: string;
  pinned_at: number;
}

export interface Channel {
  name: string;
  topic: string;
  topicSetBy?: string;
  members: Map<string, Member>;
  messages: Message[];
  modes: Set<string>;
  isEncrypted: boolean; // true if +E mode or all DMs with this user are encrypted
  unreadCount: number;
  mentionCount: number;
  lastReadMsgId?: string; // last message seen when channel was active
  isJoined: boolean;
  pins: PinnedMessage[];
}

interface Batch {
  type: string;
  target: string;
  messages: Message[];
}

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

export interface ReplyContext {
  msgId: string;
  from: string;
  text: string;
  channel: string;
}

export interface EditContext {
  msgId: string;
  text: string;
  channel: string;
}

export interface ChannelListEntry {
  name: string;
  topic: string;
  count: number;
}

// ── AV Sessions ──

export interface AvSession {
  id: string;
  channel: string | null;
  createdBy: string;       // DID
  createdByNick: string;
  title?: string;
  participants: Map<string, AvParticipant>;
  state: 'active' | 'ended';
  startedAt: Date;
  irohTicket?: string;     // Room ticket for media transport
}

export interface AvParticipant {
  did: string;
  nick: string;
  role: 'host' | 'speaker' | 'listener';
  joinedAt: Date;
}

export interface Store {
  // Connection
  connectionState: TransportState;
  nick: string;
  registered: boolean;
  // Sticky version of `registered` — set true on first registration, kept true
  // through transient reconnects (so the app stays mounted), cleared on explicit
  // logout (`fullReset`). App.tsx uses this to decide ConnectScreen vs app shell.
  wasRegistered: boolean;
  authDid: string | null;
  authMessage: string | null;
  authError: string | null;
  motd: string[];
  motdDismissed: boolean;
  connectedServer: string | null;

  // Channels & DMs
  channels: Map<string, Channel>;
  activeChannel: string;
  serverMessages: Message[];

  // Active batches
  batches: Map<string, Batch>;

  // WHOIS cache
  whoisCache: Map<string, WhoisInfo>;

  // UI state
  replyTo: ReplyContext | null;
  editingMsg: EditContext | null;
  theme: 'dark' | 'light';
  messageDensity: 'default' | 'compact' | 'cozy';
  showJoinPart: boolean;
  loadExternalMedia: boolean;
  favorites: Set<string>; // lowercase channel names
  mutedChannels: Set<string>; // lowercase channel names
  bookmarks: { channel: string; msgId: string; from: string; text: string; timestamp: Date }[];
  bookmarksPanelOpen: boolean;
  hiddenDMs: Set<string>; // lowercase nicks — hidden from sidebar but messages preserved
  blockedDids: string[]; // blocked users by DID (authoritative — survives nick changes)
  blockedNicks: string[]; // lowercase nicks — fallback for DID-less (guest) users
  searchOpen: boolean;
  scrollToMsgId: string | null;
  searchQuery: string;
  channelListOpen: boolean;
  channelList: ChannelListEntry[];
  lightboxUrl: string | null;
  threadMsgId: string | null;
  threadChannel: string | null;

  // AV sessions
  avSessions: Map<string, AvSession>;
  activeAvSession: string | null;  // session ID we're in
  avAudioActive: boolean;          // call panel visible/audio connected
  avMuted: boolean;                // local mic muted
  avCameraOn: boolean;             // local camera on (off by default)
  avScreenShareOn: boolean;        // local screen share on (off by default)
  sidebarRevealChannel: string | null; // transient: scroll this channel into view in the sidebar

  // Actions — connection
  setConnectionState: (state: TransportState) => void;
  setNick: (nick: string) => void;
  setRegistered: (v: boolean) => void;
  setWasRegistered: (v: boolean) => void;
  setAuth: (did: string, message: string) => void;
  setAuthError: (error: string) => void;
  appendMotd: (line: string) => void;
  dismissMotd: () => void;
  setConnectedServer: (url: string | null) => void;
  reset: () => void;
  fullReset: () => void;

  // Actions — channels
  addChannel: (name: string) => void;
  removeChannel: (name: string) => void;
  setActiveChannel: (name: string) => void;
  setTopic: (channel: string, topic: string, setBy?: string) => void;

  // Actions — members
  clearMembers: (channel: string) => void;
  addMember: (channel: string, member: Partial<Member> & { nick: string }) => void;
  /** Replace the whole roster with the server's authoritative NAMES snapshot
   *  (end-of-NAMES). Fixes the case where a self-JOIN clear / nick collision /
   *  reconnect left the list with only live-joined members. */
  setMembers: (channel: string, members: Array<Partial<Member> & { nick: string }>) => void;
  removeMember: (channel: string, nick: string) => void;
  removeUserFromAll: (nick: string, reason: string) => void;
  renameUser: (oldNick: string, newNick: string) => void;
  setUserAway: (nick: string, reason: string | null) => void;
  setTyping: (channel: string, nick: string, typing: boolean) => void;
  updateMemberDid: (nick: string, did: string) => void;
  handleMode: (channel: string, mode: string, arg: string | undefined, setBy: string) => void;

  // Actions — messages
  addMessage: (channel: string, msg: Message) => void;
  mergeHistory: (channel: string, messages: Message[]) => void;
  addSystemMessage: (channel: string, text: string) => void;
  editMessage: (channel: string, originalMsgId: string, newText: string, newMsgId?: string, isStreaming?: boolean, editorNick?: string, editorAccount?: string) => void;
  deleteMessage: (channel: string, msgId: string, deleterNick?: string, deleterAccount?: string) => void;
  addReaction: (channel: string, msgId: string, emoji: string, fromNick: string) => void;
  removeReaction: (channel: string, msgId: string, emoji: string, fromNick: string) => void;
  incrementMentions: (channel: string) => void;
  clearUnread: (channel: string) => void;

  // Actions — DM targets
  addDmTarget: (nick: string) => void;

  // Actions — batches
  startBatch: (id: string, type: string, target: string) => void;
  addBatchMessage: (id: string, msg: Message) => void;
  endBatch: (id: string) => void;

  // Actions — whois
  updateWhois: (nick: string, info: Partial<WhoisInfo>) => void;

  // Actions — UI
  setReplyTo: (ctx: ReplyContext | null) => void;
  setEditingMsg: (ctx: EditContext | null) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  setMessageDensity: (d: 'default' | 'compact' | 'cozy') => void;
  setShowJoinPart: (v: boolean) => void;
  setLoadExternalMedia: (v: boolean) => void;
  toggleFavorite: (channel: string) => void;
  setFavorites: (channels: string[]) => void;
  toggleMuted: (channel: string) => void;
  hideDM: (nick: string) => void;
  unhideDM: (nick: string) => void;
  blockUser: (nick: string, did?: string | null) => void;
  unblockUser: (nickOrDid: string) => void;
  isBlocked: (nick: string, did?: string | null) => boolean;
  isFavorite: (channel: string) => boolean;
  isMuted: (channel: string) => boolean;
  addBookmark: (channel: string, msgId: string, from: string, text: string, timestamp: Date) => void;
  removeBookmark: (msgId: string) => void;
  setBookmarksPanelOpen: (open: boolean) => void;
  setSearchOpen: (open: boolean) => void;
  setScrollToMsgId: (id: string | null) => void;
  setPins: (channel: string, pins: PinnedMessage[]) => void;
  addPin: (channel: string, msgid: string, pinnedBy: string) => void;
  removePin: (channel: string, msgid: string) => void;
  setSearchQuery: (query: string) => void;
  setChannelListOpen: (open: boolean) => void;
  setChannelList: (list: ChannelListEntry[]) => void;
  addChannelListEntry: (entry: ChannelListEntry) => void;
  setLightboxUrl: (url: string | null) => void;
  openThread: (msgId: string, channel: string) => void;
  closeThread: () => void;

  // AV session actions
  updateAvSession: (session: AvSession) => void;
  removeAvSession: (id: string) => void;
  setActiveAvSession: (id: string | null) => void;
  setAvAudioActive: (active: boolean) => void;
  setAvMuted: (muted: boolean) => void;
  setAvCameraOn: (on: boolean) => void;
  setAvScreenShareOn: (on: boolean) => void;
  setSidebarRevealChannel: (name: string | null) => void;

  // Join gate
  joinGateChannel: string | null;
  setJoinGateChannel: (channel: string | null) => void;

  // Channel settings
  channelSettingsOpen: string | null;
  setChannelSettingsOpen: (channel: string | null) => void;
}

/** Safely parse JSON from localStorage, returning fallback on any error. */
function safeJsonParse<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function getOrCreateChannel(channels: Map<string, Channel>, name: string): Channel {
  const key = name.toLowerCase();
  let ch = channels.get(key);
  if (!ch) {
    ch = {
      name,
      topic: '',
      members: new Map(),
      messages: [],
      modes: new Set(),
      isEncrypted: false,
      unreadCount: 0,
      mentionCount: 0,
      isJoined: false,
      pins: [],
    };
    channels.set(key, ch);
  }
  return ch;
}

export const useStore = create<Store>((set, get) => ({
  // Initial state
  connectionState: 'disconnected',
  nick: '',
  registered: false,
  wasRegistered: false,
  authDid: null,
  authMessage: null,
  authError: null,
  motd: [],
  motdDismissed: false,
  connectedServer: null,
  channels: new Map(),
  activeChannel: 'server',
  serverMessages: [],
  batches: new Map(),
  whoisCache: new Map(),
  replyTo: null,
  editingMsg: null,
  theme: (localStorage.getItem('freeq-theme') as 'dark' | 'light') || 'dark',
  messageDensity: (localStorage.getItem('freeq-density') as 'default' | 'compact' | 'cozy') || 'default',
  showJoinPart: localStorage.getItem('freeq-show-join-part') !== 'false',
  loadExternalMedia: localStorage.getItem('freeq-load-media') !== 'false',
  favorites: new Set(safeJsonParse(localStorage.getItem('freeq-favorites'), [])),
  mutedChannels: new Set(safeJsonParse(localStorage.getItem('freeq-muted'), [])),
  bookmarks: safeJsonParse(localStorage.getItem('freeq-bookmarks'), []).map((b: any) => ({ ...b, timestamp: new Date(b.timestamp) })),
  bookmarksPanelOpen: false,
  hiddenDMs: new Set(safeJsonParse(localStorage.getItem('freeq-hidden-dms'), [])),
  blockedDids: safeJsonParse(localStorage.getItem('freeq-blocked-dids'), []),
  blockedNicks: safeJsonParse(localStorage.getItem('freeq-blocked-nicks'), []),
  searchOpen: false,
  scrollToMsgId: null,
  searchQuery: '',
  channelListOpen: false,
  channelList: [],
  lightboxUrl: null,
  threadMsgId: null,
  threadChannel: null,
  avSessions: new Map(),
  activeAvSession: null,
  avAudioActive: false,
  avMuted: false,
  avCameraOn: false,
  avScreenShareOn: false,
  sidebarRevealChannel: null,
  joinGateChannel: null,
  channelSettingsOpen: null,

  // Connection
  setConnectionState: (state) => set({ connectionState: state }),
  setNick: (nick) => set({ nick }),
  setRegistered: (v) => set({ registered: v }),
  setWasRegistered: (v) => set({ wasRegistered: v }),
  setAuth: (did, message) => set({ authDid: did, authMessage: message, authError: null }),
  appendMotd: (line) => set((s) => ({ motd: [...s.motd, line] })),
  dismissMotd: () => set({ motdDismissed: true }),
  setConnectedServer: (url) => set({ connectedServer: url }),
  setAuthError: (error) => set({ authError: error }),
  reset: () => set({
    connectionState: 'disconnected',
    registered: false,
    connectedServer: null,
    channels: new Map(),
    activeChannel: 'server',
    serverMessages: [],
    batches: new Map(),
    motd: [],
    motdDismissed: false,
  }),
  fullReset: () => set((s) => ({
    connectionState: 'disconnected',
    nick: '',
    registered: false,
    wasRegistered: false,
    connectedServer: null,
    authDid: null,
    authMessage: null,
    authError: null,
    channels: new Map(),
    activeChannel: 'server',
    serverMessages: [],
    batches: new Map(),
    whoisCache: new Map(),
    replyTo: null,
    editingMsg: null,
    searchOpen: false,
    searchQuery: '',
    channelListOpen: false,
    channelList: [],
    lightboxUrl: null,
    threadMsgId: null,
    threadChannel: null,
    joinGateChannel: null,
    channelSettingsOpen: null,
    avSessions: new Map(),
    activeAvSession: null,
    theme: s.theme, messageDensity: s.messageDensity, loadExternalMedia: s.loadExternalMedia, favorites: s.favorites, mutedChannels: s.mutedChannels, blockedDids: s.blockedDids, blockedNicks: s.blockedNicks, bookmarks: s.bookmarks, bookmarksPanelOpen: false, // preserve across reconnects
  })),

  // Channels
  addChannel: (name) => set((s) => {
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, name);
    ch.isJoined = true;
    channels.set(name.toLowerCase(), ch);
    return { channels };
  }),

  addDmTarget: (nick) => set((s) => {
    if (!nick || !nick.trim()) return {}; // Reject empty nick
    const channels = new Map(s.channels);
    const key = nick.toLowerCase();
    if (!channels.has(key)) {
      const ch = getOrCreateChannel(channels, nick);
      ch.isJoined = true;
      channels.set(key, ch);
    }
    return { channels };
  }),

  removeChannel: (name) => set((s) => {
    const channels = new Map(s.channels);
    channels.delete(name.toLowerCase());
    // Clean up any in-flight batches targeting this channel
    const batches = new Map(s.batches);
    for (const [id, batch] of batches) {
      if (batch.target.toLowerCase() === name.toLowerCase()) batches.delete(id);
    }
    const activeChannel = s.activeChannel.toLowerCase() === name.toLowerCase() ? 'server' : s.activeChannel;
    return { channels, batches, activeChannel };
  }),

  setActiveChannel: (name) => set((s) => {
    // Validate target exists (except 'server' which is always valid)
    if (name !== 'server' && !s.channels.has(name.toLowerCase())) return {};
    const channels = new Map(s.channels);
    // Mark last-read on the channel we're leaving
    const oldCh = channels.get(s.activeChannel.toLowerCase());
    if (oldCh && oldCh.messages.length > 0) {
      const lastMsg = oldCh.messages[oldCh.messages.length - 1];
      oldCh.lastReadMsgId = lastMsg.id;
      channels.set(s.activeChannel.toLowerCase(), oldCh);
    }
    // Clear unread on the channel we're entering
    const ch = channels.get(name.toLowerCase());
    if (ch) {
      ch.unreadCount = 0;
      ch.mentionCount = 0;
      channels.set(name.toLowerCase(), { ...ch });
    }
    if (name !== 'server') localStorage.setItem('freeq-active-channel', name);
    return { activeChannel: name, channels };
  }),

  setTopic: (channel, topic, setBy) => set((s) => {
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, channel);
    ch.topic = topic;
    if (setBy) ch.topicSetBy = setBy;
    channels.set(channel.toLowerCase(), ch);
    return { channels };
  }),

  // Members
  clearMembers: (channel) => set((s) => {
    const key = channel.toLowerCase();
    const channels = new Map(s.channels);
    const ch = channels.get(key);
    if (ch) {
      channels.set(key, { ...ch, members: new Map() });
    }
    return { channels };
  }),
  addMember: (channel, member) => set((s) => {
    if (!member.nick || !member.nick.trim()) return {}; // Reject empty/whitespace nicks
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, channel);
    const existing = ch.members.get(member.nick.toLowerCase());
    ch.members.set(member.nick.toLowerCase(), {
      nick: member.nick,
      did: member.did ?? existing?.did,
      handle: member.handle ?? existing?.handle,
      displayName: member.displayName ?? existing?.displayName,
      avatarUrl: member.avatarUrl ?? existing?.avatarUrl,
      isOp: member.isOp ?? existing?.isOp ?? false,
      isHalfop: member.isHalfop ?? existing?.isHalfop ?? false,
      isVoiced: member.isVoiced ?? existing?.isVoiced ?? false,
      away: existing?.away,
      actorClass: member.actorClass ?? existing?.actorClass,
    });
    channels.set(channel.toLowerCase(), ch);
    return { channels };
  }),

  setMembers: (channel, members) => set((s) => {
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, channel);
    const prev = new Map(ch.members); // keep enriched fields (did/handle/…) by nick
    ch.members.clear();
    for (const member of members) {
      if (!member.nick || !member.nick.trim()) continue;
      const key = member.nick.toLowerCase();
      const existing = prev.get(key);
      ch.members.set(key, {
        nick: member.nick,
        did: member.did ?? existing?.did,
        handle: member.handle ?? existing?.handle,
        displayName: member.displayName ?? existing?.displayName,
        avatarUrl: member.avatarUrl ?? existing?.avatarUrl,
        isOp: member.isOp ?? false,
        isHalfop: member.isHalfop ?? false,
        isVoiced: member.isVoiced ?? false,
        away: existing?.away,
        actorClass: member.actorClass ?? existing?.actorClass,
      });
    }
    channels.set(channel.toLowerCase(), ch);
    return { channels };
  }),

  removeMember: (channel, nick) => set((s) => {
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch) {
      ch.members.delete(nick.toLowerCase());
      channels.set(channel.toLowerCase(), ch);
    }
    return { channels };
  }),

  removeUserFromAll: (nick, reason) => set((s) => {
    const channels = new Map(s.channels);
    for (const [key, ch] of channels) {
      if (ch.members.has(nick.toLowerCase())) {
        ch.members.delete(nick.toLowerCase());
        ch.messages = [...ch.messages, {
          id: crypto.randomUUID(),
          from: '',
          text: `${nick} quit${reason ? ` (${reason})` : ''}`,
          timestamp: new Date(),
          tags: {},
          isSystem: true,
        }];
        channels.set(key, { ...ch });
      }
    }
    // Drop the cached WHOIS identity for this nick. The nick is now
    // freed and could be claimed by an entirely different account; a
    // stale cache would show the previous occupant's DID/handle.
    const whoisCache = new Map(s.whoisCache);
    whoisCache.delete(nick.toLowerCase());
    return { channels, whoisCache };
  }),

  renameUser: (oldNick, newNick) => set((s) => {
    if (!oldNick.trim() || !newNick.trim()) return {}; // Reject empty nicks
    const channels = new Map(s.channels);
    for (const [key, ch] of channels) {
      const member = ch.members.get(oldNick.toLowerCase());
      if (member) {
        ch.members.delete(oldNick.toLowerCase());
        ch.members.set(newNick.toLowerCase(), { ...member, nick: newNick });
        channels.set(key, ch);
      }
    }
    // Move the WHOIS cache entry to the new nick. The same human is
    // behind it; the old nick must not still resolve to their DID
    // because the freed nick may be reclaimed by someone else.
    const whoisCache = new Map(s.whoisCache);
    const oldKey = oldNick.toLowerCase();
    const newKey = newNick.toLowerCase();
    const cached = whoisCache.get(oldKey);
    if (cached) {
      whoisCache.delete(oldKey);
      whoisCache.set(newKey, { ...cached, nick: newNick });
    }
    return { channels, whoisCache };
  }),

  setUserAway: (nick, reason) => set((s) => {
    const channels = new Map(s.channels);
    for (const [key, ch] of channels) {
      const member = ch.members.get(nick.toLowerCase());
      if (member) {
        ch.members.set(nick.toLowerCase(), { ...member, away: reason });
        channels.set(key, { ...ch });
      }
    }
    return { channels };
  }),

  setTyping: (channel, nick, typing) => {
    set((s) => {
      const channels = new Map(s.channels);
      const ch = channels.get(channel.toLowerCase());
      if (ch) {
        const member = ch.members.get(nick.toLowerCase());
        if (member) {
          ch.members.set(nick.toLowerCase(), { ...member, typing });
          channels.set(channel.toLowerCase(), { ...ch });
        }
      }
      return { channels };
    });
    // Auto-clear typing after 10 seconds if not refreshed
    if (typing) {
      setTimeout(() => {
        const s = useStore.getState();
        const ch = s.channels.get(channel.toLowerCase());
        if (ch?.members.get(nick.toLowerCase())?.typing) {
          useStore.getState().setTyping(channel, nick, false);
        }
      }, 10_000);
    }
  },

  updateMemberDid: (nick, did) => set((s) => {
    const channels = new Map(s.channels);
    for (const [key, ch] of channels) {
      const member = ch.members.get(nick.toLowerCase());
      if (member) {
        ch.members.set(nick.toLowerCase(), { ...member, did });
        channels.set(key, { ...ch });
      }
    }
    return { channels };
  }),

  handleMode: (channel, mode, arg, _setBy) => set((s) => {
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (!ch) return { channels };

    const adding = mode.startsWith('+');
    const modeChar = mode.replace(/^[+-]/, '');

    // User modes (+o, +h, +v) require an arg (the target nick)
    const isUserMode = modeChar === 'o' || modeChar === 'h' || modeChar === 'v';
    if (isUserMode && arg) {
      const member = ch.members.get(arg.toLowerCase());
      if (member) {
        if (modeChar === 'o') member.isOp = adding;
        if (modeChar === 'h') member.isHalfop = adding;
        if (modeChar === 'v') member.isVoiced = adding;
        ch.members.set(arg.toLowerCase(), { ...member });
      }
    } else if (isUserMode && !arg) {
      // User mode without arg is a protocol error — ignore silently
      // (don't fall through to channel modes or "o" gets added to modes set)
    } else {
      // Channel modes
      if (adding) ch.modes.add(modeChar);
      else ch.modes.delete(modeChar);
      // Track encryption mode
      if (modeChar === 'E') ch.isEncrypted = adding;
    }
    channels.set(channel.toLowerCase(), { ...ch });
    return { channels };
  }),

  // Messages
  addMessage: (channel, msg) => set((s) => {
    if (channel === 'server' || channel.toLowerCase() === 'server') {
      return { serverMessages: [...s.serverMessages, msg].slice(-500) };
    }

    const key = channel.toLowerCase();
    const oldCh = s.channels.get(key);

    // Dedup by msgid — CHATHISTORY can return messages already shown live.
    // Done BEFORE any mutation so the short-circuit doesn't leak in-place
    // edits through `return {}`.
    if (msg.id && !msg.isSystem && oldCh?.messages.some((m) => m.id === msg.id)) {
      return {};
    }

    const isDMBuf = !channel.startsWith('#') && !channel.startsWith('&') && channel !== 'server';
    const base = oldCh ?? {
      name: channel,
      topic: '',
      members: new Map(),
      messages: [],
      modes: new Set(),
      isEncrypted: false,
      unreadCount: 0,
      mentionCount: 0,
      isJoined: false,
      pins: [],
    };
    // Always produce a fresh Channel object so subscribers comparing
    // channel identity (Sidebar, MessageList children, etc.) see a new
    // reference and re-render. Mutating in place can hide updates from
    // memoized components and shallow selectors.
    const ch: typeof base = {
      ...base,
      messages: [...base.messages, msg].slice(-1000),
      isJoined: base.isJoined || isDMBuf,
      unreadCount:
        !msg.isSystem && s.activeChannel.toLowerCase() !== key
          ? base.unreadCount + 1
          : base.unreadCount,
    };

    const channels = new Map(s.channels);
    channels.set(key, ch);

    // Auto-unhide DM conversations when a new live message arrives
    if (isDMBuf && !msg.isSystem && s.hiddenDMs.has(key)) {
      const hidden = new Set(s.hiddenDMs);
      hidden.delete(key);
      localStorage.setItem('freeq-hidden-dms', JSON.stringify([...hidden]));
      return { channels, hiddenDMs: hidden };
    }

    return { channels };
  }),

  mergeHistory: (channel, incoming) => set((s) => {
    if (!incoming || incoming.length === 0) return {};
    if (channel === 'server' || channel.toLowerCase() === 'server') return {};
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, channel);

    // Dedup by msgid — existing (live) copy wins over a history copy.
    // Edit-aware: a replayed row and a live row can be the SAME message
    // under different msgids (edits re-key), so also reconcile via the
    // edit anchor (editOf, root of the chain) instead of blindly
    // appending — that append rendered as a stacked duplicate.
    const existingIds = new Set(ch.messages.map((m) => m.id).filter(Boolean));
    const novel: Message[] = [];
    let reconciled = false;
    for (const m of incoming) {
      if (m.id && existingIds.has(m.id)) continue;
      const anchor = m.editOf;
      if (anchor) {
        // Incoming collapsed edit of a message we already hold → update
        // the held row in place (id, text) rather than append.
        const idx = ch.messages.findIndex(
          (e) => e.id === anchor || e.editOf === anchor,
        );
        if (idx >= 0) {
          ch.messages = ch.messages.map((e, i) => {
            if (i !== idx) return e;
            // Keep the held id: the message is the same message. Reactions
            // come back attached to whichever revision they were filed
            // against, so carry them onto the row we keep — otherwise every
            // reload dropped the reactions on an edited message.
            const reactions = m.reactions
              ? new Map([...(e.reactions ?? new Map()), ...m.reactions])
              : e.reactions;
            return {
              ...e,
              text: m.text,
              editOf: e.editOf ?? anchor,
              ...(reactions ? { reactions } : {}),
            };
          });
          reconciled = true;
          continue;
        }
      }
      // Incoming stale base row for which we already hold a collapsed
      // edit → skip it.
      if (m.id && ch.messages.some((e) => e.editOf === m.id)) continue;
      novel.push(m);
    }
    if (novel.length === 0 && !reconciled) return {};

    const merged = [...ch.messages, ...novel];
    merged.sort((a, b) => {
      const ta = a.timestamp?.getTime?.() ?? 0;
      const tb = b.timestamp?.getTime?.() ?? 0;
      if (ta !== tb) return ta - tb;
      return (a.id || '').localeCompare(b.id || '');
    });
    ch.messages = merged.slice(-1000);
    channels.set(channel.toLowerCase(), ch);
    return { channels };
  }),

  addSystemMessage: (channel, text) => {
    const msg: Message = {
      id: crypto.randomUUID(),
      from: '',
      text,
      timestamp: new Date(),
      tags: {},
      isSystem: true,
    };
    get().addMessage(channel, msg);
  },

  // `_newMsgId` — the revision's own wire id — is deliberately unused: the
  // message keeps the id it was born with. Still accepted because the wire
  // and the SDK event carry it; droppable once no caller passes it.
  editMessage: (channel, originalMsgId, newText, _newMsgId, isStreaming, editorNick, editorAccount) => set((s) => {
    // Authorship gate: only the original sender may edit. The server
    // enforces this when the thread is persisted; for unpersisted (guest)
    // threads it relays without a check, so the client is the authority.
    // Account (DID) comparison first, nick fallback; no editor identity
    // provided (own optimistic path) passes.
    const authorOk = (m: Message): boolean => {
      if (!editorNick && !editorAccount) return true;
      const mAccount = m.tags?.['account'];
      if (editorAccount && mAccount) return editorAccount === mAccount;
      if (editorNick) return editorNick.toLowerCase() === m.from.toLowerCase();
      return true;
    };
    // Treat empty edit as a "cleared" message to prevent invisible messages
    const displayText = newText || (isStreaming ? '' : '[message cleared]');
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch) {
      // An edit changes the text, never the key. The message keeps the id it
      // was born with — which is the id the server files reactions, pins and
      // deletes under, and the id a reload replays it under.
      // `editOf` records that it was edited (the "(edited)" marker) and, for
      // the transition, still matches events that name a superseded id.
      ch.messages = ch.messages.map((m) =>
        (m.id === originalMsgId || m.editOf === originalMsgId) && authorOk(m)
          ? { ...m, text: displayText, editOf: m.editOf ?? originalMsgId, isStreaming: !!isStreaming }
          : m
      );
      channels.set(channel.toLowerCase(), { ...ch });
    }

    // Also update in-flight batch messages (CHATHISTORY) for this channel
    const batches = new Map(s.batches);
    for (const [id, batch] of batches) {
      if (batch.target.toLowerCase() !== channel.toLowerCase()) continue;
      batch.messages = batch.messages.map((m) =>
        (m.id === originalMsgId || m.editOf === originalMsgId) && authorOk(m)
          ? { ...m, text: displayText, editOf: m.editOf ?? originalMsgId, isStreaming: !!isStreaming }
          : m
      );
      batches.set(id, batch);
    }

    return { channels, batches };
  }),

  deleteMessage: (channel, msgId, deleterNick, deleterAccount) => set((s) => {
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (!ch) return { channels };
    // Authorship gate — mirror of editMessage's (see there).
    const authorOk = (m: Message): boolean => {
      if (!deleterNick && !deleterAccount) return true;
      const mAccount = m.tags?.['account'];
      if (deleterAccount && mAccount) return deleterAccount === mAccount;
      if (deleterNick) return deleterNick.toLowerCase() === m.from.toLowerCase();
      return true;
    };
    // Match on id OR editOf. Ids are stable now, so `id` alone would do for
    // anything this build wrote — the `editOf` arm is transition cover for
    // rows a previous build re-keyed to an edit's msgid, which are still in
    // IndexedDB and still on screen. Removable once those can't be around.
    ch.messages = ch.messages.map((m) =>
      (m.id === msgId || m.editOf === msgId) && authorOk(m)
        ? { ...m, deleted: true, text: '' }
        : m
    );
    channels.set(channel.toLowerCase(), { ...ch });
    return { channels };
  }),

  addReaction: (channel, msgId, emoji, fromNick) => set((s) => {
    if (!emoji || !emoji.trim()) return {}; // Reject empty emoji
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (!ch) return { channels };
    ch.messages = ch.messages.map((m) => {
      if (m.id !== msgId) return m;
      const reactions = new Map(m.reactions || []);
      const nicks = new Set(reactions.get(emoji) || []);
      nicks.add(fromNick);
      reactions.set(emoji, nicks);
      return { ...m, reactions };
    });
    channels.set(channel.toLowerCase(), { ...ch });
    return { channels };
  }),

  removeReaction: (channel, msgId, emoji, fromNick) => set((s) => {
    if (!emoji) return {};
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (!ch) return { channels };
    ch.messages = ch.messages.map((m) => {
      if (m.id !== msgId || !m.reactions) return m;
      const existing = m.reactions.get(emoji);
      if (!existing || !existing.has(fromNick)) return m;
      const reactions = new Map(m.reactions);
      const nicks = new Set(existing);
      nicks.delete(fromNick);
      if (nicks.size === 0) reactions.delete(emoji);
      else reactions.set(emoji, nicks);
      return { ...m, reactions };
    });
    channels.set(channel.toLowerCase(), { ...ch });
    return { channels };
  }),

  incrementMentions: (channel) => set((s) => {
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch && s.activeChannel.toLowerCase() !== channel.toLowerCase()) {
      ch.mentionCount++;
      channels.set(channel.toLowerCase(), { ...ch });
    }
    return { channels };
  }),

  clearUnread: (channel) => set((s) => {
    const channels = new Map(s.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch) {
      ch.unreadCount = 0;
      ch.mentionCount = 0;
      // Persist last-read message ID
      const lastMsg = ch.messages[ch.messages.length - 1];
      if (lastMsg?.id) {
        setLastReadMsgId(channel, lastMsg.id).catch(() => {});
      }
      channels.set(channel.toLowerCase(), { ...ch });
    }
    return { channels };
  }),

  // Batches
  startBatch: (id, type, target) => set((s) => {
    const batches = new Map(s.batches);
    batches.set(id, { type, target, messages: [] });
    return { batches };
  }),

  addBatchMessage: (id, msg) => set((s) => {
    const batches = new Map(s.batches);
    const batch = batches.get(id);
    if (!batch) return { batches };
    batch.messages = [...batch.messages, msg];
    batches.set(id, batch);
    return { batches };
  }),

  endBatch: (id) => set((s) => {
    const batches = new Map(s.batches);
    const batch = batches.get(id);
    batches.delete(id);
    if (!batch) return { batches };

    // Flush batch messages to the channel
    const channels = new Map(s.channels);
    const ch = getOrCreateChannel(channels, batch.target);

    // Dedup by msgid when merging history
    const existingIds = new Set(ch.messages.map((m) => m.id));
    const newMsgs = batch.messages.filter((m) => !m.id || !existingIds.has(m.id));

    // Sort batch messages by timestamp (oldest first)
    newMsgs.sort((a, b) => {
      const ta = a.timestamp?.getTime?.() ?? 0;
      const tb = b.timestamp?.getTime?.() ?? 0;
      if (ta !== tb) return ta - tb;
      return (a.id || '').localeCompare(b.id || '');
    });

    // Batch messages go at the beginning (history)
    ch.messages = [...newMsgs, ...ch.messages].slice(-1000);
    channels.set(batch.target.toLowerCase(), ch);
    return { channels, batches };
  }),

  // Whois
  updateWhois: (nick, info) => set((s) => {
    const whoisCache = new Map(s.whoisCache);
    const key = nick.toLowerCase();
    const existing = whoisCache.get(key) || { nick, fetchedAt: Date.now() };
    whoisCache.set(key, { ...existing, ...info, nick, fetchedAt: Date.now() });
    return { whoisCache };
  }),

  // UI actions
  setReplyTo: (ctx) => set({ replyTo: ctx }),
  setEditingMsg: (ctx) => set({ editingMsg: ctx }),
  setTheme: (theme) => {
    localStorage.setItem('freeq-theme', theme);
    set({ theme });
  },
  setMessageDensity: (d) => {
    localStorage.setItem('freeq-density', d);
    set({ messageDensity: d });
  },
  setShowJoinPart: (v) => {
    localStorage.setItem('freeq-show-join-part', v ? 'true' : 'false');
    set({ showJoinPart: v });
  },
  setLoadExternalMedia: (v) => {
    localStorage.setItem('freeq-load-media', v ? 'true' : 'false');
    set({ loadExternalMedia: v });
  },
  toggleFavorite: (channel) => set((s) => {
    const favs = new Set(s.favorites);
    const key = channel.toLowerCase();
    if (favs.has(key)) favs.delete(key); else favs.add(key);
    localStorage.setItem('freeq-favorites', JSON.stringify([...favs]));
    return { favorites: favs };
  }),
  // Bulk replace (used by roaming-favorites sync so a server pull doesn't
  // fire N per-item pushes). Order preserved for the Favorites section.
  setFavorites: (channels) => set(() => {
    const favs = new Set(channels.map((c) => c.toLowerCase()));
    localStorage.setItem('freeq-favorites', JSON.stringify([...favs]));
    return { favorites: favs };
  }),
  toggleMuted: (channel) => set((s) => {
    const muted = new Set(s.mutedChannels);
    const key = channel.toLowerCase();
    if (muted.has(key)) muted.delete(key); else muted.add(key);
    localStorage.setItem('freeq-muted', JSON.stringify([...muted]));
    return { mutedChannels: muted };
  }),
  hideDM: (nick) => set((s) => {
    const hidden = new Set(s.hiddenDMs);
    hidden.add(nick.toLowerCase());
    localStorage.setItem('freeq-hidden-dms', JSON.stringify([...hidden]));
    // If we're viewing this DM, switch away
    const activeChannel = s.activeChannel.toLowerCase() === nick.toLowerCase() ? 'server' : s.activeChannel;
    return { hiddenDMs: hidden, activeChannel };
  }),
  unhideDM: (nick) => set((s) => {
    const hidden = new Set(s.hiddenDMs);
    hidden.delete(nick.toLowerCase());
    localStorage.setItem('freeq-hidden-dms', JSON.stringify([...hidden]));
    return { hiddenDMs: hidden };
  }),
  blockUser: (nick, did) => set((s) => {
    // Block by DID when we have one (survives nick changes); nick fallback for guests.
    if (did) {
      if (s.blockedDids.includes(did)) return {};
      const blockedDids = [...s.blockedDids, did];
      localStorage.setItem('freeq-blocked-dids', JSON.stringify(blockedDids));
      return { blockedDids };
    }
    const key = nick.toLowerCase();
    if (s.blockedNicks.includes(key)) return {};
    const blockedNicks = [...s.blockedNicks, key];
    localStorage.setItem('freeq-blocked-nicks', JSON.stringify(blockedNicks));
    return { blockedNicks };
  }),
  unblockUser: (nickOrDid) => set((s) => {
    const key = nickOrDid.toLowerCase();
    const blockedDids = s.blockedDids.filter((d) => d !== nickOrDid);
    const blockedNicks = s.blockedNicks.filter((n) => n !== key);
    if (blockedDids.length === s.blockedDids.length && blockedNicks.length === s.blockedNicks.length) return {};
    localStorage.setItem('freeq-blocked-dids', JSON.stringify(blockedDids));
    localStorage.setItem('freeq-blocked-nicks', JSON.stringify(blockedNicks));
    return { blockedDids, blockedNicks };
  }),
  isBlocked: (nick, did) => {
    const s = get();
    if (did && s.blockedDids.includes(did)) return true;
    return s.blockedNicks.includes(nick.toLowerCase());
  },
  isFavorite: (channel) => get().favorites.has(channel.toLowerCase()),
  isMuted: (channel) => get().mutedChannels.has(channel.toLowerCase()),
  addBookmark: (channel, msgId, from, text, timestamp) => set((s) => {
    if (s.bookmarks.some((b) => b.msgId === msgId)) return s;
    const bookmarks = [...s.bookmarks, { channel, msgId, from, text, timestamp }];
    localStorage.setItem('freeq-bookmarks', JSON.stringify(bookmarks));
    return { bookmarks };
  }),
  removeBookmark: (msgId) => set((s) => {
    const bookmarks = s.bookmarks.filter((b) => b.msgId !== msgId);
    localStorage.setItem('freeq-bookmarks', JSON.stringify(bookmarks));
    return { bookmarks };
  }),
  setBookmarksPanelOpen: (open) => set({ bookmarksPanelOpen: open }),
  setSearchOpen: (open) => set({ searchOpen: open, searchQuery: open ? '' : '' }),
  setScrollToMsgId: (id) => set({ scrollToMsgId: id }),
  setPins: (channel, pins) => set((state) => {
    const channels = new Map(state.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch) { ch.pins = pins; channels.set(channel.toLowerCase(), { ...ch }); }
    return { channels };
  }),
  addPin: (channel, msgid, pinnedBy) => set((state) => {
    const channels = new Map(state.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch && !ch.pins.some(p => p.msgid === msgid)) {
      ch.pins = [...ch.pins, { msgid, pinned_by: pinnedBy, pinned_at: Date.now() }];
      channels.set(channel.toLowerCase(), { ...ch });
    }
    return { channels };
  }),
  removePin: (channel, msgid) => set((state) => {
    const channels = new Map(state.channels);
    const ch = channels.get(channel.toLowerCase());
    if (ch) {
      ch.pins = ch.pins.filter(p => p.msgid !== msgid);
      channels.set(channel.toLowerCase(), { ...ch });
    }
    return { channels };
  }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  setChannelListOpen: (open) => set({ channelListOpen: open }),
  setChannelList: (list) => set({ channelList: list }),
  addChannelListEntry: (entry) => set((s) => ({
    channelList: [...s.channelList, entry],
  })),
  setLightboxUrl: (url) => set({ lightboxUrl: url }),
  openThread: (msgId, channel) => set({ threadMsgId: msgId, threadChannel: channel }),
  closeThread: () => set({ threadMsgId: null, threadChannel: null }),

  // AV sessions
  updateAvSession: (session) => set((s) => {
    const avSessions = new Map(s.avSessions);
    avSessions.set(session.id, session);
    return { avSessions };
  }),
  removeAvSession: (id) => set((s) => {
    const avSessions = new Map(s.avSessions);
    avSessions.delete(id);
    return { avSessions, activeAvSession: s.activeAvSession === id ? null : s.activeAvSession };
  }),
  setActiveAvSession: (id) => set({ activeAvSession: id }),
  setAvAudioActive: (active) => set({ avAudioActive: active }),
  setAvMuted: (muted) => set({ avMuted: muted }),
  setAvCameraOn: (on) => set({ avCameraOn: on }),
  setAvScreenShareOn: (on) => set({ avScreenShareOn: on }),
  setSidebarRevealChannel: (name) => set({ sidebarRevealChannel: name }),

  setJoinGateChannel: (channel) => set({ joinGateChannel: channel }),
  setChannelSettingsOpen: (channel) => set({ channelSettingsOpen: channel }),
}));
