import { useState, useEffect } from 'react';
import type { AvParticipant } from '../store';
import { useStore, uniqueMemberCount } from '../store';
import { setTopic as sendTopic, startAvSession, getClient } from '../irc/client';
import { SpeakerIcon } from './SessionIndicator';
import { fetchProfile, type ATProfile } from '../lib/profiles';
import { isDid, resolveIdentityName } from '../lib/identity';
import { UserPopover } from './UserPopover';
import { apiFetch } from '../lib/api';

interface TopBarProps {
  onToggleSidebar?: () => void;
  onToggleMembers?: () => void;
  sidebarOpen?: boolean;
  membersOpen?: boolean;
}

export function TopBar({ onToggleSidebar, onToggleMembers, sidebarOpen, membersOpen }: TopBarProps) {
  const activeChannel = useStore((s) => s.activeChannel);
  const channels = useStore((s) => s.channels);
  const connectionState = useStore((s) => s.connectionState);
  const [editing, setEditing] = useState(false);
  const [topicDraft, setTopicDraft] = useState('');
  const [peerCard, setPeerCard] = useState<{ x: number; y: number } | null>(null);

  const ch = channels.get(activeChannel.toLowerCase());
  const whoisCache = useStore((s) => s.whoisCache);
  const topic = ch?.topic || '';
  const memberCount = ch ? uniqueMemberCount(ch.members) : 0;
  const isChannel = activeChannel !== 'server' && activeChannel.startsWith('#');
  const isDM = activeChannel !== 'server' && !activeChannel.startsWith('#');
  const setChannelSettings = useStore((s) => s.setChannelSettingsOpen);

  // For DMs, resolve partner profile. A DID-keyed DM (the thread name IS the
  // peer's DID) is its own partner DID even before we have a member row.
  const partnerWhois = isDM ? whoisCache.get(activeChannel.toLowerCase()) : undefined;
  const partnerDid = isDM
    ? (isDid(activeChannel) ? activeChannel : (ch?.members.values().next().value?.did || partnerWhois?.did))
    : undefined;
  const [partnerProfileState, setPartnerProfileState] = useState<{ did: string; profile: ATProfile | null } | null>(null);
  useEffect(() => {
    if (!isDM || !partnerDid) return;
    let cancelled = false;
    fetchProfile(partnerDid).then((profile) => {
      if (!cancelled) setPartnerProfileState({ did: partnerDid, profile });
    });
    return () => { cancelled = true; };
  }, [isDM, partnerDid]);
  const partnerProfile = partnerProfileState && partnerProfileState.did === partnerDid ? partnerProfileState.profile : null;

  // DM title: a DID-keyed thread resolves to a human name — the nick the SDK
  // learned for the DID, then the AT profile, then a compact DID as last
  // resort. A nick-keyed DM renders unchanged.
  const dmTitle = resolveIdentityName(activeChannel, {
    nickForDid: (did) => getClient()?.getNickForDid(did),
    nameForDid: () => partnerProfile?.handle || partnerProfile?.displayName,
  });

  const startEdit = () => {
    setTopicDraft(topic);
    setEditing(true);
  };

  const submitTopic = () => {
    if (ch) sendTopic(ch.name, topicDraft);
    setEditing(false);
  };

  return (
    <>
    <header className="h-14 bg-bg-secondary border-b border-border flex items-center gap-3 px-4 shrink-0">
      {/* Sidebar toggle */}
      <button
        onClick={onToggleSidebar}
        className={`text-fg-dim hover:text-fg-muted p-1.5 -ml-1 rounded-lg hover:bg-bg-tertiary shrink-0 transition-colors ${
          sidebarOpen ? 'text-fg-muted' : 'text-fg-dim'
        }`}
        title={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'}
        aria-label={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'}
        aria-pressed={sidebarOpen}
      >
        <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="3" y="4" width="14" height="12" rx="2" />
          <path d="M8 4v12" />
          <path d={sidebarOpen ? 'M12.5 8l-2 2 2 2' : 'M10.5 8l2 2-2 2'} />
        </svg>
      </button>

      {/* Connection status dot */}
      {connectionState !== 'connected' && (
        <span
          className={`shrink-0 w-2 h-2 rounded-full ${
            connectionState === 'connecting' ? 'bg-warning animate-pulse' : 'bg-danger'
          }`}
          title={connectionState === 'connecting' ? 'Connecting…' : 'Disconnected'}
        />
      )}

      {/* Channel / DM name + voice icon */}
      <div className="flex items-center gap-2 min-w-0 shrink">
        {isChannel && <span className="text-accent text-base font-bold shrink-0">#</span>}
        {isDM && <span className="text-fg-dim text-base shrink-0">💬</span>}
        {isDM ? (
          // The title opens the peer's card. This must not depend on their
          // messages being visible — after a block those are hidden, and this
          // is then the only in-thread path to the card (and to unblock).
          <button
            className="font-bold text-base text-fg truncate hover:underline text-left"
            title={isDid(activeChannel) ? activeChannel : undefined}
            onClick={(e) => setPeerCard({ x: e.clientX, y: e.clientY })}
          >
            {dmTitle}
          </button>
        ) : (
          <span className="font-bold text-base text-fg truncate">
            {isChannel ? (ch?.name || activeChannel).replace(/^#/, '') : 'Server'}
          </span>
        )}
        {peerCard && isDM && (
          <UserPopover
            nick={(partnerDid && getClient()?.getNickForDid(partnerDid)) || dmTitle}
            did={partnerDid}
            position={peerCard}
            onClose={() => setPeerCard(null)}
          />
        )}
        {ch?.isEncrypted && (
          <span className="text-success text-xs shrink-0" title="End-to-end encrypted channel">🔒</span>
        )}
        {isDM && !ch?.isEncrypted && (() => {
          const partnerDid = ch?.members.values().next().value?.did;
          return partnerDid ? (
            <span className="text-success text-xs shrink-0" title="End-to-end encrypted DM">🔒</span>
          ) : null;
        })()}
        {isChannel && <VoiceButton channel={activeChannel} />}
      </div>

      {/* Identity stats */}
      {isChannel && ch && (() => {
        const verified = [...ch.members.values()].filter((m) => m.did).length;
        return verified > 0 ? (
          <span className="text-xs text-success/80 shrink-0 flex items-center gap-1" title={`${verified} AT Protocol verified`}>
            <svg className="w-3 h-3" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 0a8 8 0 100 16A8 8 0 008 0zm3.78 5.97l-4.5 5a.75.75 0 01-1.06.02l-2-1.86a.75.75 0 011.02-1.1l1.45 1.35 3.98-4.43a.75.75 0 011.11 1.02z"/>
            </svg>
            {verified}
          </span>
        ) : null;
      })()}

      {/* Separator */}
      {(isChannel || isDM) && <div className="w-px h-5 bg-border" />}

      {/* Topic (channels) or partner info (DMs) */}
      <div className="flex-1 min-w-0 hidden sm:block">
        {isChannel ? (
          editing ? (
            <input
              value={topicDraft}
              onChange={(e) => setTopicDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') submitTopic();
                if (e.key === 'Escape') setEditing(false);
              }}
              onBlur={() => setEditing(false)}
              autoFocus
              className="w-full bg-transparent text-sm text-fg outline-none"
              placeholder="Set a topic..."
            />
          ) : (
            <button
              onClick={startEdit}
              className="text-sm text-fg-dim hover:text-fg-muted truncate block w-full text-left"
              title={topic || 'Click to set topic'}
            >
              {topic || 'Set a topic'}
            </button>
          )
        ) : isDM ? (
          <div className="flex items-center gap-2 text-sm text-fg-dim">
            {(partnerProfile?.handle || partnerWhois?.handle) && (
              <a
                href={`https://bsky.app/profile/${partnerProfile?.handle || partnerWhois?.handle}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline truncate"
              >
                @{partnerProfile?.handle || partnerWhois?.handle}
              </a>
            )}
            {!partnerProfile?.handle && !partnerWhois?.handle && partnerWhois?.host && (
              <span className="text-fg-dim font-mono text-xs truncate">{partnerWhois.host}</span>
            )}
          </div>
        ) : (
          <span className="flex-1" />
        )}
      </div>

      {/* AV session — controls moved to CallPanel + Sidebar */}

      {/* Settings gear (channels only) */}
      {isChannel && (
        <button
          onClick={() => setChannelSettings(ch?.name || activeChannel)}
          className="text-fg-dim hover:text-fg-muted p-1.5 rounded-lg hover:bg-bg-tertiary transition-colors"
          title="Channel settings"
        >
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
          </svg>
        </button>
      )}

      {/* Member list toggle (channels only) */}
      {isChannel && (
        <button
          onClick={onToggleMembers}
          className={`flex items-center gap-1.5 text-sm shrink-0 px-2.5 py-1.5 rounded-lg hover:bg-bg-tertiary transition-colors ${
            membersOpen ? 'text-fg-muted' : 'text-fg-dim'
          }`}
          title={membersOpen ? 'Hide members' : 'Show members'}
          aria-label={membersOpen ? 'Hide members sidebar' : 'Show members sidebar'}
          aria-pressed={membersOpen}
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 8a3 3 0 100-6 3 3 0 000 6zM2 14s-1 0-1-1 1-4 7-4 7 3 7 4-1 1-1 1H2z"/>
          </svg>
          {memberCount > 0 && <span className="hidden sm:inline tabular-nums">{memberCount}</span>}
        </button>
      )}

      {/* Profile panel toggle (DMs only) */}
      {isDM && (
        <button
          onClick={onToggleMembers}
          className={`flex items-center gap-1.5 text-sm shrink-0 px-2.5 py-1.5 rounded-lg hover:bg-bg-tertiary transition-colors ${
            membersOpen ? 'text-fg-muted' : 'text-fg-dim'
          }`}
          title={membersOpen ? 'Hide profile' : 'Show profile'}
          aria-label={membersOpen ? 'Hide profile sidebar' : 'Show profile sidebar'}
          aria-pressed={membersOpen}
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 8a3 3 0 100-6 3 3 0 000 6zM2 14s-1 0-1-1 1-4 7-4 7 3 7 4-1 1-1 1H2z"/>
          </svg>
        </button>
      )}
    </header>
    {/* Mobile topic bar — visible on small screens when topic exists */}
    {isChannel && topic && (
      <div className="sm:hidden px-4 py-1.5 bg-bg-secondary border-b border-border">
        <p className="text-xs text-fg-dim truncate">{topic}</p>
      </div>
    )}
    </>
  );
}

/** Speaker icon next to channel name — starts/joins voice with one click.
 *  Glows green when in an active call. */
function VoiceButton({ channel }: { channel: string }) {
  const avSessions = useStore((s) => s.avSessions);
  const activeAvSession = useStore((s) => s.activeAvSession);
  const avAudioActive = useStore((s) => s.avAudioActive);
  const authDid = useStore((s) => s.authDid);
  const connectionState = useStore((s) => s.connectionState);

  // Poll REST API to discover sessions (same logic that was in SessionIndicator)
  useEffect(() => {
    if (connectionState !== 'connected' || !channel.startsWith('#')) return;
    let cancelled = false;
    async function poll() {
      try {
        const resp = await apiFetch(`/api/v1/channels/${encodeURIComponent(channel)}/sessions`);
        if (!resp.ok || cancelled) return;
        const data = await resp.json();
        if (cancelled || !data.active) return;
        const store = useStore.getState();
        if (!store.avSessions.get(data.active.id)) {
          const participants = new Map<string, AvParticipant>();
          for (const p of data.active.participants || []) {
            participants.set(p.nick, { did: p.did || '', nick: p.nick, role: p.role || 'speaker', joinedAt: new Date(p.joined_at * 1000) });
          }
          store.updateAvSession({
            id: data.active.id, channel: data.active.channel, createdBy: data.active.created_by || '',
            createdByNick: data.active.created_by_nick || '', title: data.active.title || undefined,
            participants, state: 'active', startedAt: new Date(data.active.created_at * 1000),
            irohTicket: data.active.iroh_ticket || undefined,
          });
        }
      } catch { /* ignore */ }
    }
    poll();
    const timer = setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [channel, connectionState]);

  if (!authDid || connectionState !== 'connected') return null;

  const session = [...avSessions.values()].find(
    (s) => s.channel?.toLowerCase() === channel.toLowerCase() && s.state === 'active'
  );

  const isInCall = session && activeAvSession === session.id && avAudioActive;

  return (
    <button
      onClick={() => startAvSession(channel)}
      className={`shrink-0 p-1 rounded-md transition-all ${
        isInCall
          ? 'text-success bg-success/15 shadow-[0_0_8px_rgba(34,197,94,0.3)]'
          : 'text-fg-dim hover:text-accent hover:bg-bg-tertiary'
      }`}
      title={isInCall ? 'In voice call' : session ? 'Join voice call' : 'Start voice call'}
    >
      <SpeakerIcon size={14} />
    </button>
  );
}
/**
 * The layout every bar across the top of the app shares, so the bars cannot
 * drift apart. Each bar adds its own colours: background, text and line.
 */
export const TOP_BAR = 'flex items-center justify-center gap-3 py-1.5 px-4 text-xs shrink-0 border-b';

/** The colours of a bar that offers something rather than warns. */
export const TOP_BAR_ACCENT = 'bg-accent/5 border-accent/10';

/** The bar's sentence, which wraps before any button does. */
export const TOP_BAR_TEXT = 'min-w-0';

/** A button beside the sentence: never shrinks, never breaks onto two lines. */
export const TOP_BAR_BUTTON = 'shrink-0 whitespace-nowrap font-semibold hover:underline';

/** A second, quieter button beside the sentence. */
export const TOP_BAR_QUIET_BUTTON = 'shrink-0 whitespace-nowrap hover:underline';

/** A button inside the sentence: stays on one line. */
export const TOP_BAR_INLINE_BUTTON = 'whitespace-nowrap font-semibold hover:underline';

/** The ✕ that dismisses a bar. */
export const TOP_BAR_CLOSE = 'shrink-0 whitespace-nowrap text-fg-dim/40 hover:text-fg-dim ml-1';
