import { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useStore } from '../store';
import { joinChannel, partChannel, disconnect, startAvSession, endAvSession, leaveAvSession, getNick, getClient } from '../irc/client';
import { SpeakerIcon } from './SessionIndicator';
import { MicIcon, MicOffIcon, CameraOnIcon, CameraOffIcon, PhoneOffIcon } from './CallPanel';
import { fetchProfile, getCachedProfile } from '../lib/profiles';
import { parseAwayStatus } from '../lib/status';
import { isDid, shortenDid, findMemberByKey, isPeerBlocked } from '../lib/identity';
import { claimForPerson } from '@freeq/sdk';
import { displayNameForKey } from '../lib/display-name';
import { unjoinedFavorites } from '../lib/favorites-sync';

interface SidebarProps {
  onOpenSettings: () => void;
}

export function Sidebar({ onOpenSettings }: SidebarProps) {
  const channels = useStore((s) => s.channels);
  const activeChannel = useStore((s) => s.activeChannel);
  const setActive = useStore((s) => s.setActiveChannel);
  const serverMessages = useStore((s) => s.serverMessages);
  const connectionState = useStore((s) => s.connectionState);
  const nick = useStore((s) => s.nick);
  const authDid = useStore((s) => s.authDid);
  const [joinInput, setJoinInput] = useState('');
  const [showJoin, setShowJoin] = useState(false);
  const [channelsCollapsed, setChannelsCollapsed] = useState(() => localStorage.getItem('freeq-channels-collapsed') === 'true');
  const [dmsCollapsed, setDmsCollapsed] = useState(() => localStorage.getItem('freeq-dms-collapsed') === 'true');

  const favorites = useStore((s) => s.favorites);
  useStore((s) => s.mutedChannels); // subscribe for re-render
  const hiddenDMs = useStore((s) => s.hiddenDMs);
  const blockedDids = useStore((s) => s.blockedDids);
  const blockedNicks = useStore((s) => s.blockedNicks);

  const navRef = useRef<HTMLElement>(null);
  const revealChannel = useStore((s) => s.sidebarRevealChannel);

  // When something (e.g. hitting the speaker button) asks to surface a channel,
  // scroll its row into view so the inline voice controls are visible. Expand
  // the Channels section first if it's collapsed, otherwise the row isn't in
  // the DOM to scroll to.
  useEffect(() => {
    if (!revealChannel) return;
    const isChan = revealChannel.startsWith('#') || revealChannel.startsWith('&');
    if (isChan && channelsCollapsed) {
      setChannelsCollapsed(false);
      localStorage.setItem('freeq-channels-collapsed', 'false');
    }
    const key = revealChannel.toLowerCase();
    // Defer to the next frame so a just-expanded section has rendered.
    const raf = requestAnimationFrame(() => {
      const sel = `[data-channel-key="${CSS.escape(key)}"]`;
      navRef.current?.querySelector(sel)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      useStore.getState().setSidebarRevealChannel(null);
    });
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealChannel]);

  const allJoined = [...channels.values()].filter((ch) => ch.isJoined);
  const allChans = allJoined.filter((ch) => ch.name.startsWith('#') || ch.name.startsWith('&')).sort((a, b) => a.name.localeCompare(b.name));
  const favList = allChans.filter((ch) => favorites.has(ch.name.toLowerCase()));
  const chanList = allChans.filter((ch) => !favorites.has(ch.name.toLowerCase()));
  // Favorites roam per-DID, so one set on another device can name a channel
  // we're not joined to here. Both lists above filter the joined channels, so
  // such a favorite would render nowhere — invisible AND unreachable. Surface
  // it as a join-on-click row.
  const favUnjoined = unjoinedFavorites(favorites, allChans.map((ch) => ch.name));
  const dmList = allJoined
    .filter((ch) => !ch.name.startsWith('#') && !ch.name.startsWith('&') && ch.name !== 'server')
    .filter((ch) => !hiddenDMs.has(ch.name.toLowerCase()))
    .filter((ch) => !isPeerBlocked(channels, ch.name, blockedNicks, blockedDids,
      (did) => getClient()?.getNickForDid(did)))
    // Most-recent conversation first (standard messenger order). The old
    // alphabetical-by-key sort produced arbitrary placement once thread keys
    // could be DIDs. Skip system messages — the time label and preview do,
    // and a fresh system line (join/quit/notice) must not bump a stale
    // thread to the top. Threads with no real messages sort last.
    .sort((a, b) => {
      const last = (ch: { messages: { timestamp: string | number | Date; isSystem?: boolean }[] }) => {
        for (let i = ch.messages.length - 1; i >= 0; i--) {
          if (!ch.messages[i].isSystem) return new Date(ch.messages[i].timestamp).getTime();
        }
        return 0;
      };
      return last(b) - last(a);
    });

  // Disambiguate identical DM labels. A peer who has used several DID
  // identities over time (common for bots) is honestly several threads, all
  // resolving to the same display name — suffix the compact DID so the
  // entries are tellable apart.
  const dmLabels = new Map<string, string>();
  {
    const counts = new Map<string, number>();
    for (const ch of dmList) {
      const l = displayNameForKey(ch.name);
      counts.set(l, (counts.get(l) ?? 0) + 1);
    }
    for (const ch of dmList) {
      const l = displayNameForKey(ch.name);
      dmLabels.set(
        ch.name,
        (counts.get(l) ?? 0) > 1 && isDid(ch.name) ? `${l} · ${shortenDid(ch.name)}` : l,
      );
    }
  }

  const handleJoin = () => {
    const ch = joinInput.trim();
    if (ch) {
      joinChannel(ch.startsWith('#') ? ch : `#${ch}`);
      setJoinInput('');
      setShowJoin(false);
    }
  };

  return (
    <aside data-testid="sidebar" role="navigation" aria-label="Channels and direct messages" className="w-64 h-full bg-bg-secondary flex flex-col shrink-0 overflow-hidden">
      {/* Brand */}
      <div className="h-14 flex items-center px-4 border-b border-border shrink-0 gap-2.5">
        <img src="/freeq.png" alt="" className="w-7 h-7" />
        <span className="text-accent font-bold text-xl tracking-tight">freeq</span>
        <span className={`ml-auto w-2 h-2 rounded-full ${
          connectionState === 'connected' ? 'bg-success' :
          connectionState === 'connecting' ? 'bg-warning animate-pulse' : 'bg-danger'
        }`} />
      </div>

      <nav ref={navRef} className="flex-1 overflow-y-auto py-2 px-2">
        {/* Server */}
        <button
          onClick={() => setActive('server')}
          className={`w-full text-left px-3 py-2 rounded-lg text-[15px] flex items-center gap-2.5 mb-1 ${
            activeChannel === 'server'
              ? 'bg-surface text-fg'
              : 'text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary'
          }`}
        >
          <svg className="w-4 h-4 shrink-0 opacity-60" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1.5 3A1.5 1.5 0 013 1.5h10A1.5 1.5 0 0114.5 3v2A1.5 1.5 0 0113 6.5H3A1.5 1.5 0 011.5 5V3zm1 .5v1.5h11V3.5h-11zM1.5 9A1.5 1.5 0 013 7.5h10A1.5 1.5 0 0114.5 9v2a1.5 1.5 0 01-1.5 1.5H3A1.5 1.5 0 011.5 11V9zm1 .5v1.5h11V9.5h-11z"/>
          </svg>
          <span>Server</span>
          {serverMessages.length > 0 && activeChannel !== 'server' && (
            <span className="ml-auto w-1.5 h-1.5 rounded-full bg-fg-dim" />
          )}
        </button>

        {/* Channels */}
        <div className="sticky top-0 z-10 bg-bg-secondary mt-3 mb-1 px-2 flex items-center justify-between">
          <button
            onClick={() => { const v = !channelsCollapsed; setChannelsCollapsed(v); localStorage.setItem('freeq-channels-collapsed', String(v)); }}
            className="text-xs uppercase tracking-wider text-fg-dim font-bold flex items-center gap-1 hover:text-fg-muted"
            aria-expanded={!channelsCollapsed}
          >
            <svg className={`w-3 h-3 transition-transform ${channelsCollapsed ? '-rotate-90' : ''}`} viewBox="0 0 16 16" fill="currentColor">
              <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            Channels
          </button>
          <div className="flex items-center gap-0.5">
            <button
              onClick={() => useStore.getState().setChannelListOpen(true)}
              className="text-fg-dim hover:text-accent text-lg leading-none px-1 transition-colors"
              title="Browse channels"
            >
              +
            </button>
            <button
              onClick={() => setShowJoin(!showJoin)}
              className="text-fg-dim hover:text-fg-muted text-lg leading-none px-1"
              title="Join channel"
            >
              +
            </button>
          </div>
        </div>

        {showJoin && (
          <div className="px-1 mb-2 animate-fadeIn">
            <input
              value={joinInput}
              onChange={(e) => setJoinInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleJoin()}
              placeholder="#channel"
              autoFocus
              className="w-full bg-bg-tertiary border border-border rounded px-2 py-1 text-sm text-fg outline-none focus:border-accent placeholder:text-fg-dim"
            />
          </div>
        )}

        {!channelsCollapsed && (
          <>
            {/* Favorites */}
            {(favList.length > 0 || favUnjoined.length > 0) && (
              <>
                <div className="mt-3 mb-1 px-2">
                  <span className="text-xs uppercase tracking-wider text-fg-dim font-bold flex items-center gap-1">
                    <span className="text-warning text-[10px]">★</span> Favorites
                  </span>
                </div>
                {favList.map((ch) => <ChannelButton key={ch.name} ch={ch as any} isActive={activeChannel.toLowerCase() === ch.name.toLowerCase()} onSelect={setActive} icon="#" />)}
                {favUnjoined.map((name) => (
                  <button
                    key={name}
                    onClick={() => joinChannel(name)}
                    title={`Favorited on another device — click to join ${name}`}
                    className="w-full text-left px-2 py-1 rounded flex items-center gap-1.5 text-fg-dim hover:bg-bg-hover hover:text-fg group"
                  >
                    <span className="text-fg-dim">#</span>
                    <span className="truncate flex-1">{name.replace(/^[#&]/, '')}</span>
                    <span className="text-[10px] uppercase tracking-wider font-bold text-accent opacity-0 group-hover:opacity-100">
                      Join
                    </span>
                  </button>
                ))}
              </>
            )}

            {chanList.map((ch) => <ChannelButton key={ch.name} ch={ch as any} isActive={activeChannel.toLowerCase() === ch.name.toLowerCase()} onSelect={setActive} icon="#" />)}
          </>
        )}

        {/* DMs */}
        {dmList.length > 0 && (() => {
          const dmUnread = dmList.reduce((s, ch) => s + ch.unreadCount, 0);
          return (
          <>
            <div className="sticky top-7 z-10 bg-bg-secondary mt-3 mb-1 px-2 flex items-center justify-between">
              <button
                onClick={() => { const v = !dmsCollapsed; setDmsCollapsed(v); localStorage.setItem('freeq-dms-collapsed', String(v)); }}
                className="text-xs uppercase tracking-wider text-fg-dim font-bold flex items-center gap-1 hover:text-fg-muted"
                aria-expanded={!dmsCollapsed}
              >
                <svg className={`w-3 h-3 transition-transform ${dmsCollapsed ? '-rotate-90' : ''}`} viewBox="0 0 16 16" fill="currentColor">
                  <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                Messages
              </button>
              {dmUnread > 0 && (
                <span className="bg-danger text-white text-[10px] min-w-[16px] text-center px-1 py-0.5 rounded-full font-bold leading-none">
                  {dmUnread}
                </span>
              )}
            </div>
            {!dmsCollapsed && dmList.map((ch) => <ChannelButton key={ch.name} ch={ch as any} isActive={activeChannel.toLowerCase() === ch.name.toLowerCase()} onSelect={setActive} icon="@" showPreview label={dmLabels.get(ch.name)} />)}
          </>
          );
        })()}
      </nav>

      {/* Persistent voice-connected panel — always visible while in a call */}
      <CallConnectedPanel />

      {/* User footer */}
      <div className="border-t border-border px-3 py-4 shrink-0">
        <div className="flex items-center gap-2.5">
          <SelfAvatar nick={nick} did={authDid} />
          <div className="min-w-0 flex-1">
            <div className="text-[15px] font-semibold truncate flex items-center gap-1">
              {nick}
              {claimForPerson({ binding: authDid }).showsMark && (
                <span className="text-accent text-xs" title="AT Protocol identity">✓</span>
              )}
            </div>
            {authDid && (() => {
              const handle = localStorage.getItem('freeq-handle');
              return handle ? (
                <div className="text-[11px] text-fg-dim truncate flex items-center gap-1" title={authDid}>
                  <span className="text-accent">🦋</span> {handle}
                </div>
              ) : (
                <div className="text-[11px] text-fg-dim truncate" title={authDid}>
                  {authDid.slice(0, 24)}…
                </div>
              );
            })()}
            {!authDid && (
              <div className="text-[11px] text-fg-dim">Guest</div>
            )}
          </div>
          <button
            onClick={() => useStore.getState().setBookmarksPanelOpen(true)}
            className="text-fg-dim hover:text-fg-muted p-1"
            title="Bookmarks (⌘B)"
          >
            <svg className="w-4 h-4" viewBox="0 0 16 16" fill="currentColor">
              <path d="M2 2a2 2 0 012-2h8a2 2 0 012 2v13.5a.5.5 0 01-.777.416L8 13.101l-5.223 2.815A.5.5 0 012 15.5V2zm2-1a1 1 0 00-1 1v12.566l4.723-2.482a.5.5 0 01.554 0L13 14.566V2a1 1 0 00-1-1H4z"/>
            </svg>
          </button>
          <button
            onClick={onOpenSettings}
            className="text-fg-dim hover:text-fg-muted p-1"
            title="Settings"
          >
            <svg className="w-4 h-4" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 4.754a3.246 3.246 0 100 6.492 3.246 3.246 0 000-6.492zM5.754 8a2.246 2.246 0 114.492 0 2.246 2.246 0 01-4.492 0z"/>
              <path d="M9.796 1.343c-.527-1.79-3.065-1.79-3.592 0l-.094.319a.873.873 0 01-1.255.52l-.292-.16c-1.64-.892-3.433.902-2.54 2.541l.159.292a.873.873 0 01-.52 1.255l-.319.094c-1.79.527-1.79 3.065 0 3.592l.319.094a.873.873 0 01.52 1.255l-.16.292c-.892 1.64.901 3.434 2.541 2.54l.292-.159a.873.873 0 011.255.52l.094.319c.527 1.79 3.065 1.79 3.592 0l.094-.319a.873.873 0 011.255-.52l.292.16c1.64.893 3.434-.902 2.54-2.541l-.159-.292a.873.873 0 01.52-1.255l.319-.094c1.79-.527 1.79-3.065 0-3.592l-.319-.094a.873.873 0 01-.52-1.255l.16-.292c.893-1.64-.902-3.433-2.541-2.54l-.292.159a.873.873 0 01-1.255-.52l-.094-.319z"/>
            </svg>
          </button>
          <button
            onClick={disconnect}
            className="text-fg-dim hover:text-danger p-1"
            title="Disconnect"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10 12.5a.5.5 0 01-.5.5h-8a.5.5 0 01-.5-.5v-9a.5.5 0 01.5-.5h8a.5.5 0 01.5.5v2a.5.5 0 001 0v-2A1.5 1.5 0 009.5 2h-8A1.5 1.5 0 000 3.5v9A1.5 1.5 0 001.5 14h8a1.5 1.5 0 001.5-1.5v-2a.5.5 0 00-1 0v2z"/>
              <path fillRule="evenodd" d="M15.854 8.354a.5.5 0 000-.708l-3-3a.5.5 0 00-.708.708L14.293 7.5H5.5a.5.5 0 000 1h8.793l-2.147 2.146a.5.5 0 00.708.708l3-3z"/>
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}

function SelfAvatar({ nick, did }: { nick: string; did: string | null }) {
  const [avatarUrl, setAvatarUrl] = useState<string | null>(() => {
    if (!did) return null;
    return getCachedProfile(did)?.avatar || null;
  });

  useEffect(() => {
    if (did && !avatarUrl) {
      fetchProfile(did).then((p) => p?.avatar && setAvatarUrl(p.avatar));
    }
  }, [did]);

  if (avatarUrl) {
    return <img src={avatarUrl} alt="" className="w-9 h-9 rounded-full object-cover shrink-0" />;
  }
  return (
    <div className="w-9 h-9 rounded-full bg-surface flex items-center justify-center text-accent font-bold text-[15px] shrink-0">
      {(nick || '?')[0].toUpperCase()}
    </div>
  );
}

function ChannelButton({ ch, isActive, onSelect, icon, showPreview, label: labelOverride }: {
  ch: { name: string; mentionCount: number; unreadCount: number; messages: any[]; members: Map<string, any>; isEncrypted?: boolean };
  isActive: boolean;
  onSelect: (name: string) => void;
  icon: string;
  showPreview?: boolean;
  /** Precomputed display label (used to disambiguate duplicate DM names). */
  label?: string;
}) {
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const isFav = useStore((s) => s.favorites.has(ch.name.toLowerCase()));
  const isMuted = useStore((s) => s.mutedChannels.has(ch.name.toLowerCase()));
  const hasMention = ch.mentionCount > 0;
  const hasUnread = ch.unreadCount > 0;

  // Last message preview for DMs
  const lastMsg = showPreview ? ch.messages.filter((m: any) => !m.isSystem).slice(-1)[0] : null;
  const preview = lastMsg ? `${lastMsg.from}: ${lastMsg.text}` : null;
  const lastTime = lastMsg ? formatSidebarTime(new Date(lastMsg.timestamp)) : null;

  // A DID-keyed DM resolves to a human name (learned nick → AT profile →
  // compact DID). Channels and nick DMs pass through unchanged.
  const label = (labelOverride ?? displayNameForKey(ch.name)).replace(/^[#&]/, '');

  return (
    <div data-channel-key={ch.name.toLowerCase()}>
    <button
      onClick={() => onSelect(ch.name)}
      onContextMenu={(e) => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY }); }}
      className={`w-full text-left px-3 py-2 rounded-lg flex items-center gap-2.5 ${
        isMuted ? 'opacity-40 ' : ''
      }${
        isActive
          ? 'bg-surface text-fg'
          : hasMention
            ? 'text-fg font-semibold hover:bg-bg-tertiary'
            : hasUnread
              ? 'text-fg-muted hover:bg-bg-tertiary'
              : 'text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary'
      }`}
    >
      {/* Icon / DM avatar */}
      {showPreview ? (
        <div className="relative shrink-0">
          <DmAvatar nick={ch.name} />
          <OnlineDot nick={ch.name} />
        </div>
      ) : (
        <span className={`shrink-0 text-[15px] font-medium ${isActive ? 'text-accent' : 'opacity-50'}`}>{icon}</span>
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1">
          <span className="truncate text-[15px]" title={isDid(ch.name) ? ch.name : undefined}>{label}</span>
          {(ch.isEncrypted || (!ch.name.startsWith('#') && ch.members.values().next().value?.did)) && (
            <span className="text-[10px] text-success shrink-0" title="End-to-end encrypted">🔒</span>
          )}
          {showPreview && <DmStatusText nick={ch.name} />}
          {!showPreview && ch.members.size > 0 && (
            <span className="text-[10px] text-fg-dim ml-auto shrink-0">{ch.members.size}</span>
          )}
          {showPreview && lastTime && (
            <span className="text-[10px] text-fg-dim ml-auto shrink-0">{lastTime}</span>
          )}
        </div>
        {showPreview && preview && (
          <div className="text-xs text-fg-dim truncate mt-0.5">{preview.slice(0, 50)}</div>
        )}
      </div>
      {hasMention && (
        <span className="shrink-0 bg-danger text-white text-xs min-w-[20px] text-center px-1.5 py-0.5 rounded-full font-bold">
          {ch.mentionCount}
        </span>
      )}
      {!hasMention && hasUnread && (
        <span className="shrink-0 w-1.5 h-1.5 rounded-full bg-fg-muted" />
      )}
    </button>
    {ctxMenu && <SidebarContextMenu
      channel={ch.name}
      isFav={isFav}
      isMuted={isMuted}
      isChannel={ch.name.startsWith('#')}
      position={ctxMenu}
      onClose={() => setCtxMenu(null)}
    />}
    {ch.name.startsWith('#') && <ChannelVoiceParticipants channel={ch.name} />}
    </div>
  );
}

/** Compact Discord-style list of voice participants shown inline under a channel
 *  that has a live session. Controls for *your own* call live in the persistent
 *  CallConnectedPanel, not here — so they can never scroll out of view. */
function ChannelVoiceParticipants({ channel }: { channel: string }) {
  const avSessions = useStore((s) => s.avSessions);
  const activeAvSession = useStore((s) => s.activeAvSession);
  const avAudioActive = useStore((s) => s.avAudioActive);

  const session = [...avSessions.values()].find(
    (s) => s.channel?.toLowerCase() === channel.toLowerCase() && s.state === 'active'
  );
  if (!session) return null;

  const isConnected = activeAvSession === session.id && avAudioActive;
  const participants = [...session.participants.values()];

  return (
    <div className="ml-7 mr-2 mb-1 mt-0.5">
      {participants.map((p) => (
        <div key={p.nick} className="flex items-center gap-1.5 px-1 py-0.5 text-[12px] text-fg-dim" title={p.nick}>
          <span className="w-4 h-4 rounded-full bg-accent/20 flex items-center justify-center text-accent text-[8px] font-bold shrink-0">
            {p.nick.slice(0, 1).toUpperCase()}
          </span>
          <span className="truncate">{p.nick}</span>
          <span className="text-success shrink-0"><SpeakerIcon size={10} /></span>
        </div>
      ))}
      {!isConnected && (
        <button
          onClick={(e) => { e.stopPropagation(); startAvSession(channel); }}
          className="mt-1 px-1 text-[11px] text-accent hover:text-accent/80 font-medium"
        >
          Join voice
        </button>
      )}
    </div>
  );
}

/** Persistent "Voice Connected" panel pinned above the user footer. Always on
 *  screen while in a call, so leave/mute/camera never scroll away. */
function CallConnectedPanel() {
  const avAudioActive = useStore((s) => s.avAudioActive);
  const activeAvSession = useStore((s) => s.activeAvSession);
  const avSessions = useStore((s) => s.avSessions);
  const avMuted = useStore((s) => s.avMuted);
  const avCameraOn = useStore((s) => s.avCameraOn);
  const setActive = useStore((s) => s.setActiveChannel);

  if (!avAudioActive || !activeAvSession) return null;
  const session = avSessions.get(activeAvSession);
  if (!session) return null;

  const channel = session.channel || '';
  const participantCount = session.participants.size;
  const isHost = session.createdByNick.toLowerCase() === getNick().toLowerCase();

  const leave = () => {
    useStore.getState().setAvAudioActive(false);
    useStore.getState().setAvCameraOn(false);
    if (channel) leaveAvSession(channel, session.id);
  };
  const endForAll = () => {
    useStore.getState().setAvAudioActive(false);
    useStore.getState().setAvCameraOn(false);
    if (channel) endAvSession(channel, session.id);
  };

  return (
    <div className="border-t border-border px-3 pt-2.5 pb-2 shrink-0 bg-bg-tertiary/40">
      <div className="flex items-center gap-1.5 mb-1.5">
        <span className="w-2 h-2 rounded-full bg-success animate-pulse shrink-0" />
        <span className="text-[11px] font-semibold text-success">Voice Connected</span>
        <button
          onClick={leave}
          className="ml-auto p-1 rounded-md bg-danger text-white hover:bg-danger/80 transition-colors"
          title="Disconnect"
        >
          <PhoneOffIcon size={13} />
        </button>
      </div>
      <button
        onClick={() => { if (channel) { setActive(channel); useStore.getState().setSidebarRevealChannel(channel); } }}
        className="w-full text-left flex items-center gap-1.5 mb-2 group"
        title={`Go to ${channel}`}
      >
        <span className="text-[13px] text-fg-muted group-hover:text-fg truncate">{channel}</span>
        <span className="text-[11px] text-fg-dim shrink-0">· {participantCount}</span>
      </button>
      <div className="flex items-center gap-2">
        <button
          onClick={() => useStore.getState().setAvMuted(!avMuted)}
          className={`p-1.5 rounded-full transition-colors ${
            avMuted ? 'bg-danger text-white hover:bg-danger/80' : 'bg-bg-tertiary text-fg hover:bg-bg-tertiary/80'
          }`}
          title={avMuted ? 'Unmute' : 'Mute'}
        >
          {avMuted ? <MicOffIcon size={15} /> : <MicIcon size={15} />}
        </button>
        <button
          onClick={() => useStore.getState().setAvCameraOn(!avCameraOn)}
          className={`p-1.5 rounded-full transition-colors ${
            avCameraOn ? 'bg-accent text-white hover:bg-accent/80' : 'bg-bg-tertiary text-fg hover:bg-bg-tertiary/80'
          }`}
          title={avCameraOn ? 'Turn off camera' : 'Turn on camera'}
        >
          {avCameraOn ? <CameraOnIcon size={15} /> : <CameraOffIcon size={15} />}
        </button>
        {isHost && (
          <button
            onClick={endForAll}
            className="ml-auto text-[10px] text-danger hover:text-danger/80 font-medium"
            title="End session for everyone"
          >
            End
          </button>
        )}
      </div>
    </div>
  );
}

function SidebarContextMenu({ channel, isFav, isMuted, isChannel, position, onClose }: {
  channel: string;
  isFav: boolean;
  isMuted: boolean;
  isChannel: boolean;
  position: { x: number; y: number };
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  // Portal to <body>: the sidebar's wrapper in App.tsx has a transform
  // (md:translate-x-0 + transition-transform), which makes it the containing
  // block + stacking/clip context for position:fixed descendants — so an
  // in-tree menu gets confined to the sidebar and clipped where it overlaps
  // the chat pane. Rendering at the body root lets `fixed` track the viewport.
  return createPortal(
    <div
      ref={ref}
      className="fixed z-[100] bg-bg-secondary border border-border rounded-xl shadow-2xl py-1.5 min-w-[160px] animate-fadeIn"
      style={{ left: Math.min(position.x, window.innerWidth - 180), top: Math.min(position.y, window.innerHeight - 200) }}
    >
      {isChannel && (
        <button onClick={() => { useStore.getState().toggleFavorite(channel); onClose(); }}
          className="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-bg-tertiary text-fg-muted hover:text-fg">
          <span className="w-5 text-center">{isFav ? '★' : '☆'}</span>
          {isFav ? 'Remove from Favorites' : 'Add to Favorites'}
        </button>
      )}
      <button onClick={() => { useStore.getState().toggleMuted(channel); onClose(); }}
        className="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-bg-tertiary text-fg-muted hover:text-fg">
        <span className="w-5 text-center">{isMuted ? '🔔' : '🔇'}</span>
        {isMuted ? 'Unmute' : 'Mute notifications'}
      </button>
      <button onClick={() => {
          navigator.clipboard.writeText(`https://irc.freeq.at/join/${encodeURIComponent(channel)}`);
          import('./Toast').then(m => m.showToast('Invite link copied', 'success', 2000));
          onClose();
        }}
        className="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-bg-tertiary text-fg-muted hover:text-fg">
        <span className="w-5 text-center">🔗</span>
        Copy invite link
      </button>
      <div className="h-px bg-border mx-2 my-1" />
      {isChannel ? (
        <button onClick={() => { partChannel(channel); onClose(); }}
          className="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-danger/10 text-danger">
          <span className="w-5 text-center">🚪</span>
          Leave channel
        </button>
      ) : (
        <button onClick={() => { useStore.getState().hideDM(channel); onClose(); }}
          className="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-danger/10 text-danger">
          <span className="w-5 text-center">✕</span>
          Close conversation
        </button>
      )}
    </div>,
    document.body
  );
}

/** DM avatar that resolves nick → DID → profile image. */
function DmAvatar({ nick }: { nick: string }) {
  const channels = useStore((s) => s.channels);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);

  // The thread key is either the peer's DID already, or a nick we resolve to
  // one via the channel member lists.
  const did = isDid(nick) ? nick : (findMemberByKey(channels, nick)?.member.did ?? null);

  useEffect(() => {
    if (!did) { setAvatarUrl(null); return; }
    let cancelled = false;
    const cached = getCachedProfile(did);
    if (cached?.avatar) { setAvatarUrl(cached.avatar); return; }
    fetchProfile(did).then((p) => {
      if (p?.avatar && !cancelled) setAvatarUrl(p.avatar);
    });
    return () => { cancelled = true; };
  }, [did]);

  if (avatarUrl) {
    return <img src={avatarUrl} alt="" className="w-8 h-8 rounded-full object-cover" />;
  }
  return (
    <div className="w-8 h-8 rounded-full bg-surface flex items-center justify-center text-accent font-bold text-sm">
      {(nick[0] || '?').toUpperCase()}
    </div>
  );
}

/** Custom status text for a DM contact — parsed from their AWAY reason
 *  in any shared channel. Muted + truncated so it never crowds the row. */
function DmStatusText({ nick }: { nick: string }) {
  const status = useStore((s) => {
    const hit = findMemberByKey(s.channels, nick);
    return hit ? parseAwayStatus(hit.member.away) : null;
  });
  if (!status) return null;
  return (
    <span className="text-[11px] text-fg-dim truncate min-w-0" title={status}>
      {status}
    </span>
  );
}

/** Shows a green/yellow online dot for a DM contact. `nick` is the thread key
 *  — a nick or a DID. */
function OnlineDot({ nick }: { nick: string }) {
  const channels = useStore((s) => s.channels);
  const hit = findMemberByKey(channels, nick, true);
  if (!hit) return null;
  const isAway = hit.member.away != null;
  return (
    <span className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-bg-secondary ${
      isAway ? 'bg-warning' : 'bg-success'
    }`} />
  );
}

function formatSidebarTime(d: Date): string {
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  if (diff < 60000) return 'now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
  if (diff < 86400000) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (diff < 604800000) return d.toLocaleDateString([], { weekday: 'short' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
