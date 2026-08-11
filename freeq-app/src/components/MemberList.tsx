import { useState, useEffect } from 'react';
import { useStore, type Member } from '../store';
import { fetchProfile, getCachedProfile, type ATProfile } from '../lib/profiles';
import { UserPopover } from './UserPopover';
import { sendWhois, getClient } from '../irc/client';
import { SpeakerIcon } from './SessionIndicator';
import { parseAwayStatus } from '../lib/status';
import { isDid, resolveIdentityName, findMemberByKey } from '../lib/identity';
import { claimForPerson, claimForSender, type PersonLookup } from '@freeq/sdk';
import { displayNameForKey } from '../lib/display-name';
import * as e2ee from '../lib/e2ee';

const NICK_COLORS = [
  '#ff6eb4', '#00d4aa', '#ffb547', '#5c9eff', '#b18cff',
  '#ff9547', '#00c4ff', '#ff5c5c', '#7edd7e', '#ff85d0',
];

function nickColor(nick: string): string {
  let h = 0;
  for (let i = 0; i < nick.length; i++) h = nick.charCodeAt(i) + ((h << 5) - h);
  return NICK_COLORS[Math.abs(h) % NICK_COLORS.length];
}

export function MemberList() {
  const activeChannel = useStore((s) => s.activeChannel);
  const channels = useStore((s) => s.channels);
  const avSessions = useStore((s) => s.avSessions);
  const ch = channels.get(activeChannel.toLowerCase());
  const [popover, setPopover] = useState<{ nick: string; did?: string; pos: { x: number; y: number } } | null>(null);

  // Nicks (lowercased) currently in this channel's active voice session.
  const voiceSession = [...avSessions.values()].find(
    (s) => s.channel?.toLowerCase() === activeChannel.toLowerCase() && s.state === 'active'
  );
  const inCall = new Set([...(voiceSession?.participants.values() ?? [])].map((p) => p.nick.toLowerCase()));

  if (!ch || activeChannel === 'server') return null;

  const isDM = !activeChannel.startsWith('#');

  if (isDM) {
    return <DMProfilePanel key={activeChannel} nick={activeChannel} channel={ch} />;
  }

  const sortedMembers = [...ch.members.values()].sort((a, b) => {
    const wa = a.isOp ? 0 : a.isHalfop ? 1 : a.isVoiced ? 2 : 3;
    const wb = b.isOp ? 0 : b.isHalfop ? 1 : b.isVoiced ? 2 : 3;
    return wa - wb || a.nick.localeCompare(b.nick);
  });
  // Collapse multiple connections of the same account (same DID) into one row.
  // The same person on two devices — or a nick-collision twin like
  // chadfowler.com / chadfowlercom — is one member, not two. Guests (no DID)
  // are always kept, keyed by nick. Prefer the connection whose nick is the
  // fuller handle (has a dot) as the canonical display.
  const bestByDid = new Map<string, Member>();
  const members: Member[] = [];
  for (const m of sortedMembers) {
    if (!m.did) { members.push(m); continue; }
    const existing = bestByDid.get(m.did);
    if (!existing) { bestByDid.set(m.did, m); members.push(m); continue; }
    // Keep the more canonical nick (dotted handle) if this one is better.
    if (m.nick.includes('.') && !existing.nick.includes('.')) {
      const idx = members.indexOf(existing);
      if (idx >= 0) members[idx] = m;
      bestByDid.set(m.did, m);
    }
  }

  const isAgent = (m: Member) => m.actorClass === 'agent' || m.actorClass === 'external_agent';
  const ops = members.filter((m) => m.isOp && !isAgent(m));
  const halfops = members.filter((m) => !m.isOp && m.isHalfop && !isAgent(m));
  const voiced = members.filter((m) => !m.isOp && !m.isHalfop && m.isVoiced && !isAgent(m));
  const regular = members.filter((m) => !m.isOp && !m.isHalfop && !m.isVoiced && !isAgent(m));
  const agents = members.filter(isAgent);

  const onMemberClick = (nick: string, did: string | undefined, e: React.MouseEvent) => {
    setPopover({ nick, did, pos: { x: e.clientX, y: e.clientY } });
  };

  return (
    <aside role="complementary" aria-label="Channel members" className="w-52 h-full bg-bg-secondary border-l border-border overflow-y-auto shrink-0">
      <div className="px-3 pt-4 pb-2">
        {ops.length > 0 && (
          <Section label={`Operators — ${ops.length}`}>
            {ops.map((m) => <MemberItem key={m.nick} member={m} onClick={onMemberClick} inCall={inCall.has(m.nick.toLowerCase())} />)}
          </Section>
        )}
        {halfops.length > 0 && (
          <Section label={`Moderators — ${halfops.length}`}>
            {halfops.map((m) => <MemberItem key={m.nick} member={m} onClick={onMemberClick} inCall={inCall.has(m.nick.toLowerCase())} />)}
          </Section>
        )}
        {voiced.length > 0 && (
          <Section label={`Voiced — ${voiced.length}`}>
            {voiced.map((m) => <MemberItem key={m.nick} member={m} onClick={onMemberClick} inCall={inCall.has(m.nick.toLowerCase())} />)}
          </Section>
        )}
        <Section label={`${ops.length > 0 || halfops.length > 0 || voiced.length > 0 ? 'Members' : 'Online'} — ${regular.length}`}>
          {regular.map((m) => <MemberItem key={m.nick} member={m} onClick={onMemberClick} inCall={inCall.has(m.nick.toLowerCase())} />)}
        </Section>
        {agents.length > 0 && (
          <Section label={`Agents — ${agents.length}`}>
            {agents.map((m) => <MemberItem key={m.nick} member={m} onClick={onMemberClick} inCall={inCall.has(m.nick.toLowerCase())} />)}
          </Section>
        )}
      </div>

      {popover && (
        <UserPopover
          nick={popover.nick}
          did={popover.did}
          position={popover.pos}
          onClose={() => setPopover(null)}
        />
      )}
    </aside>
  );
}

/** Determine online/away status by checking shared channel member lists (not
 *  the DM member map). `key` is the DM thread key — a nick or a DID. */
function usePresence(key: string): { online: boolean; away: string | null } {
  const channels = useStore((s) => s.channels);
  const hit = findMemberByKey(channels, key, true);
  return { online: !!hit, away: hit?.member.away ?? null };
}

/** Rich profile panel shown in the right sidebar for DMs */
function DMProfilePanel({ nick, channel }: { nick: string; channel: { members: Map<string, any>; isEncrypted?: boolean } }) {
  // `nick` is the DM thread key — a nick, or the peer's DID once the thread is
  // DID-keyed. Resolve it to a real nick for the lookups that need one (WHOIS
  // is a nick command; a DID target would just fail).
  const channels = useStore((s) => s.channels);
  const peerNick = isDid(nick)
    ? (findMemberByKey(channels, nick)?.nick ?? getClient()?.getNickForDid(nick))
    : nick;
  const whoisCache = useStore((s) => s.whoisCache);
  const whois = peerNick ? whoisCache.get(peerNick.toLowerCase()) : undefined;
  const partnerMember = channel.members.values().next().value;
  const did = isDid(nick) ? nick : (partnerMember?.did || whois?.did);
  const [profile, setProfile] = useState<ATProfile | null>(null);
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const presence = usePresence(nick);
  // Same rule the popover uses: pending outranks the cache, because a WHOIS
  // fills it incrementally and a half-filled entry would read as "guest" a
  // beat before the account lands.
  const whoisOut = useStore((s) => (peerNick ? s.whoisPending.has(peerNick.toLowerCase()) : false));
  // The thread's own messages carry the identity context — same rule as the
  // message rows. A message relayed from a peer names its origin, and a local
  // message with no account tag is already the guest answer.
  const thread = useStore((s) => s.channels.get(nick.toLowerCase()));
  const peerMsgs = (thread?.messages ?? []).filter(
    (m) => peerNick && m.from.toLowerCase() === peerNick.toLowerCase() && !m.isSystem,
  );
  const lastPeerMsg = peerMsgs[peerMsgs.length - 1];
  const origin = lastPeerMsg?.tags?.['+freeq.at/origin'];
  // The SDK owns the precedence: live identity first, then the thread's own
  // message evidence, then the lookup state machine.
  const lookup: PersonLookup = whoisOut ? 'inFlight' : whois ? 'noAccount' : 'notAsked';
  const claim = claimForSender({
    account: lastPeerMsg?.tags?.['account'],
    origin,
    senderPresent: presence.online,
    senderLiveDid: did,
    rowTimeUnix: lastPeerMsg ? Math.floor(lastPeerMsg.timestamp.getTime() / 1000) : undefined,
  }, lookup);

  useEffect(() => {
    if (peerNick) sendWhois(peerNick);
  }, [peerNick]);

  useEffect(() => {
    if (did) {
      fetchProfile(did).then((p) => p && setProfile(p));
    }
  }, [did]);

  useEffect(() => {
    if (did && e2ee.hasSession(did)) {
      e2ee.getSafetyNumber(did).then(setSafetyNumber);
    }
  }, [did]);

  // Never show a raw DID as the peer's name: prefer a real name, else the
  // resolved nick, and only compact the DID when nothing resolves.
  const label = resolveIdentityName(nick, {
    nickForDid: () => peerNick,
    nameForDid: () => profile?.handle || profile?.displayName,
  });
  // Same guard as UserPopover: a realname whose first token is a DID is the
  // server's "did:… (via S2S federation)" placeholder, not a human name.
  const saneRealname = whois?.realname && !isDid(whois.realname.split(' ')[0]) ? whois.realname : undefined;
  const displayName = profile?.displayName || saneRealname || label;
  const handle = profile?.handle || whois?.handle;
  const avatarUrl = profile?.avatar;

  function formatCount(n?: number): string {
    if (n == null) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
    return n.toString();
  }

  return (
    <aside role="complementary" aria-label="User profile" className="w-64 h-full bg-bg-secondary border-l border-border overflow-y-auto shrink-0">
      {/* Banner / gradient */}
      <div className="h-24 overflow-hidden">
        {profile?.banner ? (
          <img src={profile.banner} alt="" className="w-full h-full object-cover" />
        ) : (
          <div className="w-full h-full bg-gradient-to-br from-accent/30 via-purple/20 to-accent/10" />
        )}
      </div>

      {/* Avatar — overlaps banner edge */}
      <div className="relative -mt-8 flex justify-center">
        <div className="relative">
          {avatarUrl ? (
            <img
              src={avatarUrl}
              alt=""
              className="w-16 h-16 rounded-full border-4 border-bg-secondary object-cover"
            />
          ) : (
            <div className="w-16 h-16 rounded-full border-4 border-bg-secondary bg-surface flex items-center justify-center text-accent font-bold text-xl">
              {nick[0]?.toUpperCase()}
            </div>
          )}
          {/* Online/away indicator */}
          {presence.online && (
            <span className={`absolute bottom-0 right-0 w-4 h-4 rounded-full border-[3px] border-bg-secondary ${
              presence.away ? 'bg-warning' : 'bg-success'
            }`} />
          )}
          {!presence.online && (
            <span className="absolute bottom-0 right-0 w-4 h-4 rounded-full border-[3px] border-bg-secondary bg-fg-dim/30" />
          )}
        </div>
      </div>

      <div className="pt-2 px-4 pb-4 text-center">
        {/* Display name */}
        <div className="font-semibold text-fg text-base">{displayName}</div>
        {displayName !== label && (
          <div className="text-sm text-fg-muted">{label}</div>
        )}

        {/* AT Handle — linked to Bluesky (not for did:key users) */}
        {handle && !did?.startsWith('did:key:') && (
          <a
            href={`https://bsky.app/profile/${handle}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sm text-accent hover:underline mt-1"
          >
            @{handle}
            <svg className="w-3 h-3 opacity-50" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8.636 3.5a.5.5 0 00-.5-.5H1.5A1.5 1.5 0 000 4.5v10A1.5 1.5 0 001.5 16h10a1.5 1.5 0 001.5-1.5V7.864a.5.5 0 00-1 0V14.5a.5.5 0 01-.5.5h-10a.5.5 0 01-.5-.5v-10a.5.5 0 01.5-.5h6.636a.5.5 0 00.5-.5z"/>
              <path d="M16 .5a.5.5 0 00-.5-.5h-5a.5.5 0 000 1h3.793L6.146 9.146a.5.5 0 10.708.708L15 1.707V5.5a.5.5 0 001 0v-5z"/>
            </svg>
          </a>
        )}

        {/* Status */}
        <div className="text-xs text-fg-dim mt-1">
          {presence.online ? (
            presence.away ? (
              <span className="text-warning">Away{(() => {
                const status = parseAwayStatus(presence.away);
                return status ? `: ${status}` : '';
              })()}</span>
            ) : (
              <span className="text-success">Online</span>
            )
          ) : (
            <span className="text-fg-dim">Offline{did ? ' — messages will be saved' : ''}</span>
          )}
        </div>

        {/* Bluesky stats */}
        {profile && (profile.followersCount != null || profile.postsCount != null) && (
          <div className="flex justify-center gap-4 mt-3 py-2 border-y border-border">
            <div className="text-center">
              <div className="text-sm font-semibold text-fg">{formatCount(profile.postsCount)}</div>
              <div className="text-[10px] text-fg-dim uppercase tracking-wide">Posts</div>
            </div>
            <div className="text-center">
              <div className="text-sm font-semibold text-fg">{formatCount(profile.followersCount)}</div>
              <div className="text-[10px] text-fg-dim uppercase tracking-wide">Followers</div>
            </div>
            <div className="text-center">
              <div className="text-sm font-semibold text-fg">{formatCount(profile.followsCount)}</div>
              <div className="text-[10px] text-fg-dim uppercase tracking-wide">Following</div>
            </div>
          </div>
        )}

        {/* Bio */}
        {profile?.description && (
          <p className="text-xs text-fg-muted mt-3 leading-relaxed text-left">
            {profile.description}
          </p>
        )}

        {/* E2EE Safety Number */}
        {safetyNumber && (
          <div className="mt-3 p-2 bg-success/5 border border-success/20 rounded-lg text-left">
            <div className="text-[10px] text-success font-semibold mb-1 flex items-center gap-1">
              🔒 Encrypted — Safety Number
            </div>
            <div className="text-[10px] font-mono text-fg-dim leading-relaxed tracking-wider">
              {safetyNumber}
            </div>
            <div className="text-[9px] text-fg-dim mt-1">
              Compare with your contact to verify encryption
            </div>
          </div>
        )}

        {/* Encryption status */}
        {!safetyNumber && channel.isEncrypted && (
          <div className="mt-3 p-2 bg-success/5 border border-success/20 rounded-lg text-left">
            <div className="text-[10px] text-success font-semibold flex items-center gap-1">
              🔒 End-to-end encrypted
            </div>
          </div>
        )}

        {/* DID */}
        {did && (
          <div
            className="mt-3 text-[10px] text-fg-dim font-mono break-all cursor-pointer hover:text-fg-muted text-left p-2 bg-bg-tertiary rounded-lg"
            onClick={() => { navigator.clipboard.writeText(did); import('./Toast').then(m => m.showToast('DID copied', 'success', 2000)); }}
            title="Click to copy DID"
          >
            {did}
          </div>
        )}

        {/* WHOIS details */}
        {whois && (
          <div className="mt-3 space-y-1 text-left">
            {whois.user && whois.host && (
              <div className="text-[11px] text-fg-dim">
                <span className="text-fg-dim/60">Host:</span>{' '}
                <span className="font-mono">{whois.user}@{whois.host}</span>
              </div>
            )}
            {whois.channels && (
              <div className="text-[11px] text-fg-dim">
                <span className="text-fg-dim/60">Channels:</span> {whois.channels}
              </div>
            )}
            {whois.server && (
              <div className="text-[11px] text-fg-dim">
                <span className="text-fg-dim/60">Server:</span> {whois.server}
              </div>
            )}
          </div>
        )}

        {/* What we can honestly say about who this is. The two lines that name
            "the key below" belong on a surface showing that key; this panel
            has none, so those states show the label alone. While the ask is
            out it's motion, not words. */}
        {claim.isPending ? (
          <div className="mt-3 flex justify-center text-fg-dim">
            <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24" aria-hidden="true">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          </div>
        ) : (
          <div className="mt-3 text-[10px] text-fg-dim bg-bg-tertiary rounded px-2 py-1 text-left">
            <div className="font-semibold text-fg-muted">{claim.label}</div>
            {!claim.needsKeyCard && (
              <div className="mt-0.5 leading-relaxed">{claim.line}</div>
            )}
          </div>
        )}

        {/* Actions */}
        {handle && !did?.startsWith('did:key:') && (
          <div className="mt-4">
            <a
              href={`https://bsky.app/profile/${handle}`}
              target="_blank"
              rel="noopener noreferrer"
              className="block w-full bg-accent/10 hover:bg-accent/20 text-accent text-sm py-2 rounded-lg text-center font-medium transition-colors"
            >
              View on Bluesky ↗
            </a>
          </div>
        )}
      </div>
    </aside>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-3">
      <div className="text-xs uppercase tracking-wider text-fg-dim font-bold mb-2 px-1">
        {label}
      </div>
      {children}
    </div>
  );
}

interface MemberItemProps {
  member: {
    nick: string;
    did?: string;
    isOp: boolean;
    isHalfop: boolean;
    isVoiced: boolean;
    away?: string | null;
    typing?: boolean;
    actorClass?: 'human' | 'agent' | 'external_agent';
  };
  onClick: (nick: string, did: string | undefined, e: React.MouseEvent) => void;
  inCall?: boolean;
}

function MemberItem({ member, onClick, inCall }: MemberItemProps) {
  const nick = useStore((s) => s.nick);
  const authDid = useStore((s) => s.authDid);
  const isSelf = member.nick.toLowerCase() === nick.toLowerCase();
  const effectiveDid = member.did || (isSelf ? authDid : undefined) || undefined;
  const color = nickColor(member.nick);

  return (
    <button
      onClick={(e) => onClick(member.nick, effectiveDid, e)}
      className="w-full flex items-center gap-2.5 px-2 py-1.5 rounded-lg text-[15px] hover:bg-bg-tertiary group"
      title={effectiveDid || member.nick}
    >
      <div className="relative">
        <MiniAvatar nick={member.nick} did={effectiveDid} color={color} />
        {/* Presence dot */}
        <span className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-bg-secondary ${
          member.away ? 'bg-warning' : 'bg-success'
        }`} />
      </div>

      <div className="min-w-0 flex-1 flex items-center gap-1">
        {member.isOp && <span className="text-success text-xs font-bold">@</span>}
        {!member.isOp && member.isHalfop && <span className="text-accent text-xs font-bold">%</span>}
        {!member.isOp && !member.isHalfop && member.isVoiced && <span className="text-warning text-xs font-bold">+</span>}

        <span className={`truncate text-[15px] ${
          member.away ? 'text-fg-dim' : 'text-fg-muted group-hover:text-fg'
        }`}>
          {displayNameForKey(member.nick)}
        </span>

        {member.actorClass === 'agent' && (
          <span className="text-xs" title="Agent">🤖</span>
        )}
        {member.actorClass === 'external_agent' && (
          <span className="text-xs" title="External Agent">🌐</span>
        )}

        {claimForPerson({ binding: effectiveDid }).showsMark && !member.actorClass?.includes('agent') && (
          <span className="text-accent text-xs" title="AT Protocol identity">✓</span>
        )}

        {inCall && (
          <span className="text-success shrink-0" title="In voice call"><SpeakerIcon size={12} /></span>
        )}

        {member.typing && (
          <span className="text-accent text-xs ml-auto animate-pulse">typing</span>
        )}
      </div>
    </button>
  );
}

function MiniAvatar({ nick, did, color }: { nick: string; did?: string; color: string }) {
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
    return <img src={avatarUrl} alt="" className="w-8 h-8 rounded-full object-cover shrink-0" />;
  }

  return (
    <div
      className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
      style={{ backgroundColor: color + '20', color }}
    >
      {nick[0]?.toUpperCase()}
    </div>
  );
}
