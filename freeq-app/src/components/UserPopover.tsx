import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { fetchProfile, type ATProfile } from '../lib/profiles';
import { useStore } from '../store';
import { sendWhois, getNick } from '../irc/client';
import { REPORT_REASONS, reportUser } from '../lib/safety';
import { parseAwayStatus } from '../lib/status';
import { isDid } from '../lib/identity';
import { claimForSender, type PersonLookup } from '@freeq/sdk';
import { displayNameForKey } from '../lib/display-name';
import { showToast } from './Toast';
import * as e2ee from '../lib/e2ee';

export interface CreatorChainLink {
  did: string;
  nick: string | null;
  displayName: string | null;
  avatar: string | null;
  isHuman: boolean;
}

/** Default depth cap when callers don't pass one. Picked deep enough
 *  to cover realistic nesting (bot owns bot owns bot owns human is
 *  already exotic) without enabling runaway loops on bad data. */
export const CREATOR_CHAIN_MAX_DEPTH = 8;

interface CreatorChainActorResp {
  nick?: string | null;
  provenance?: { creator_did?: string | null } | null;
}

interface CreatorChainProfile {
  displayName?: string | null;
  handle?: string | null;
  avatar?: string | null;
}

/**
 * Walk the creator lineage starting from `rootDid`. Returns links in
 * order of distance from the displayed user (closest first).
 *
 * Stops on:
 *  - empty/undefined `rootDid` (returns [])
 *  - actor response with no `provenance.creator_did` (root reached)
 *  - cycle (DID seen twice)
 *  - hit `maxDepth`
 *
 * `fetchActor` and `fetchProfileFn` are injected so this is testable
 * without a network. In production, callers pass the live fetch +
 * fetchProfile from `lib/profiles`.
 */
export async function walkCreatorChain(
  rootDid: string | null | undefined,
  fetchActor: (did: string) => Promise<CreatorChainActorResp | null>,
  fetchProfileFn: (did: string) => Promise<CreatorChainProfile | null>,
  maxDepth: number = CREATOR_CHAIN_MAX_DEPTH,
): Promise<CreatorChainLink[]> {
  if (!rootDid) return [];
  const chain: CreatorChainLink[] = [];
  const seen = new Set<string>();
  // Explicit annotations on `did` + the Promise.all tuple are not just
  // documentation — tsc -b (project-references mode) can't infer them
  // without help because `nextDid` is reassigned inside the loop from
  // `actorResp.provenance.creator_did`, which itself depends on the
  // tuple type. The implicit-any inference becomes circular.
  let nextDid: string | null | undefined = rootDid;
  while (nextDid && chain.length < maxDepth) {
    if (seen.has(nextDid)) break;
    seen.add(nextDid);
    const did: string = nextDid;
    const isDidKey = did.startsWith('did:key:');
    const [actorResp, profile]: [
      CreatorChainActorResp | null,
      CreatorChainProfile | null,
    ] = await Promise.all([
      fetchActor(did).catch(() => null),
      isDidKey ? Promise.resolve(null) : fetchProfileFn(did).catch(() => null),
    ]);
    chain.push({
      did,
      nick: actorResp?.nick ?? null,
      displayName: profile?.displayName ?? profile?.handle ?? null,
      avatar: profile?.avatar ?? null,
      isHuman: !isDidKey,
    });
    nextDid = actorResp?.provenance?.creator_did ?? null;
  }
  return chain;
}

function defaultFetchActor(did: string): Promise<CreatorChainActorResp | null> {
  return fetch(`/api/v1/actors/${encodeURIComponent(did)}`)
    .then((r) => (r.ok ? r.json() : null))
    .catch(() => null);
}

export function ProvenanceBlock({ provenance }: { provenance: NonNullable<ActorInfo['provenance']> }) {
  // Walks the creator lineage to render e.g. "Creator: lobot ← Nap"
  // so the chain of trust is visible at a glance for nested bot
  // hierarchies (panel-2 owned by lobot owned by a human). See
  // `walkCreatorChain` for the walk logic + stop conditions.
  const [creatorChain, setCreatorChain] = useState<CreatorChainLink[]>([]);
  useEffect(() => {
    if (!provenance.creator_did) {
      setCreatorChain([]);
      return;
    }
    let cancelled = false;
    walkCreatorChain(provenance.creator_did, defaultFetchActor, fetchProfile).then(
      (chain) => {
        if (!cancelled) setCreatorChain(chain);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [provenance.creator_did]);

  return (
    <div className="mt-2 p-2 bg-bg-tertiary rounded-lg text-left">
      <div className="text-[10px] text-fg-dim font-semibold mb-1">Provenance</div>
      {creatorChain.length > 0 && (
        <div className="text-[10px] text-fg-dim flex items-center gap-1.5 flex-wrap">
          <span className="text-fg-dim/60">Creator:</span>
          {creatorChain.map((link, i) => (
            <span key={link.did} className="flex items-center gap-1.5">
              {i > 0 && <span className="text-fg-dim/40" aria-hidden="true">←</span>}
              <button
                onClick={() => { navigator.clipboard.writeText(link.did); import('./Toast').then(m => m.showToast('DID copied', 'success', 2000)); }}
                title={`Click to copy DID\n${link.did}`}
                className="flex items-center gap-1 cursor-pointer hover:opacity-80"
              >
                {link.avatar && (
                  <img src={link.avatar} alt="" className="w-3.5 h-3.5 rounded-full" />
                )}
                <span className="text-fg-muted">
                  {link.displayName || link.nick || link.did}
                </span>
              </button>
            </span>
          ))}
        </div>
      )}
      {provenance.source_repo && (
        <div className="text-[10px] text-fg-dim">
          <span className="text-fg-dim/60">Source:</span>{' '}
          <a href={provenance.source_repo} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            {provenance.source_repo.replace('https://', '')}
          </a>
        </div>
      )}
      {provenance.implementation_ref && (
        <div className="text-[10px] text-fg-dim">
          <span className="text-fg-dim/60">Impl:</span>{' '}
          <span className="font-mono">{provenance.implementation_ref}</span>
        </div>
      )}
    </div>
  );
}

interface ActorInfo {
  actor_class?: string;
  did?: string;
  online?: boolean;
  spawned?: boolean;
  parent_did?: string;
  parent_nick?: string;
  channel?: string;
  capabilities?: string[];
  ttl?: number;
  task?: string;
  provenance?: {
    creator_did?: string;
    source_repo?: string;
    implementation_ref?: string;
    revocation_authority?: string;
    origin_type?: string;
    authority_basis?: string;
  };
  presence?: {
    state?: string;
    status?: string;
    task?: string;
  };
  heartbeat?: {
    last_seen?: string;
    ttl?: number;
    healthy?: boolean;
  };
}

/** What a message row hands to a person surface opened from it. */
export interface RowEvidence {
  /** The row's `account` tag, if any. */
  account?: string;
  /** The row's timestamp, unix seconds. */
  timeUnix?: number;
  /** Whether the sender is in the venue's roster right now. */
  present?: boolean;
}

interface UserPopoverProps {
  nick: string;
  did?: string;
  /** Set when opened from a federated message (+freeq.at/origin = peer name).
   *  The sender is vouched for by that server, not verified here — so the card
   *  says so and suppresses the local mark / WHOIS context. */
  origin?: string;
  /** The anchoring message's evidence, when opened from a row: its account
   *  tag, its timestamp, and whether the sender is in the room. When live
   *  identity can't answer, the row does — the SDK owns that precedence. */
  evidence?: RowEvidence;
  position: { x: number; y: number };
  onClose: () => void;
}

export function UserPopover({ nick, did, origin, evidence, position, onClose }: UserPopoverProps) {
  const [profile, setProfile] = useState<ATProfile | null>(null);
  const [loading, setLoading] = useState(false);
  const setActive = useStore((s) => s.setActiveChannel);
  const addChannel = useStore((s) => s.addChannel);
  const whois = useStore((s) => s.whoisCache.get(nick.toLowerCase()));
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [actorInfo, setActorInfo] = useState<ActorInfo | null>(null);
  const [showReportReasons, setShowReportReasons] = useState(false);

  useEffect(() => {
    // Always trigger WHOIS to get latest info
    sendWhois(nick);
  }, [nick]);

  const effectiveDid = did || whois?.did;
  const isDidKey = effectiveDid?.startsWith('did:key:');
  // What we've done about finding out. Pending outranks the cache: a WHOIS
  // fills the cache incrementally (host first, account last), so trusting a
  // half-filled entry would call someone a guest a beat before their DID
  // lands.
  const whoisOut = useStore((s) => s.whoisPending.has(nick.toLowerCase()));
  // The SDK owns the precedence: live identity first, then the anchoring
  // row's evidence, then this lookup state — which only decides when the
  // message can't answer.
  const lookup: PersonLookup = whoisOut ? 'inFlight' : whois ? 'noAccount' : 'notAsked';
  const claim = claimForSender({
    account: evidence?.account,
    origin,
    senderPresent: evidence?.present ?? false,
    senderLiveDid: effectiveDid,
    rowTimeUnix: evidence?.timeUnix,
  }, lookup);
  const isSelf = nick.toLowerCase() === getNick().toLowerCase();
  const isBlocked = useStore((s) =>
    (!!effectiveDid && s.blockedDids.includes(effectiveDid)) || s.blockedNicks.includes(nick.toLowerCase()));
  // Away status from any shared channel member list (custom status text)
  const away = useStore((s) => {
    for (const ch of s.channels.values()) {
      const m = ch.members.get(nick.toLowerCase());
      if (m) return m.away ?? null;
    }
    return null;
  });
  const awayStatus = parseAwayStatus(away);

  // Fetch safety number for E2EE verification
  useEffect(() => {
    if (effectiveDid && e2ee.hasSession(effectiveDid)) {
      e2ee.getSafetyNumber(effectiveDid).then(setSafetyNumber);
    }
  }, [effectiveDid]);

  // Fetch AT profile when we have a DID (skip did:key — they have no Bluesky profile)
  useEffect(() => {
    if (effectiveDid && !isDidKey && !profile) {
      setLoading(true);
      fetchProfile(effectiveDid).then((p) => {
        setProfile(p);
        setLoading(false);
      });
    } else if (isDidKey) {
      setLoading(false);
    }
  }, [effectiveDid]);

  // Fetch actor info from REST API (agent class, provenance, presence)
  // Try by DID first, fall back to nick (for spawned agents before WHOIS completes)
  useEffect(() => {
    const fetchActor = async () => {
      if (effectiveDid) {
        const r = await fetch(`/api/v1/actors/${encodeURIComponent(effectiveDid)}`);
        if (r.ok) { setActorInfo(await r.json()); return; }
      }
      // Fallback: try by nick (spawned agents may not have DID yet)
      const r2 = await fetch(`/api/v1/actors/${encodeURIComponent(nick)}`);
      if (r2.ok) { setActorInfo(await r2.json()); }
    };
    fetchActor().catch(() => {});
  }, [effectiveDid, nick]);

  const startDM = () => {
    // Open the thread under the same canonical key the SDK sends/echoes
    // under — the peer's DID when we know it, else the nick. Opening by nick
    // while the echo keys by DID would split one person into two threads.
    const key = effectiveDid && isDid(effectiveDid) ? effectiveDid : nick;
    addChannel(key);
    setActive(key);
    onClose();
  };

  // Position keeping on screen
  const style: React.CSSProperties = {
    position: 'fixed',
    left: Math.min(position.x, window.innerWidth - 300),
    top: Math.min(position.y, window.innerHeight - 400),
    zIndex: 100,
  };

  // A realname whose first token is a DID is not a human name — the server
  // sends "did:key:… (via S2S federation)" for remote users it can't name.
  const saneRealname = whois?.realname && !isDid(whois.realname.split(' ')[0]) ? whois.realname : undefined;
  const displayName = profile?.displayName || saneRealname || displayNameForKey(nick);
  const handle = profile?.handle || whois?.handle;
  const avatarUrl = profile?.avatar;

  // Portal to <body>: the right-sidebar shell has `will-change: transform`
  // (from the sidebar toggle animation), which makes it the containing block
  // for `position: fixed` descendants — so an in-tree popover positions
  // relative to the sidebar and lands off-screen. Rendering into <body>
  // escapes that ancestor so `position: fixed` is viewport-relative again.
  // (Same fix the channel-list context menu already uses.)
  return createPortal(
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div style={style} data-testid="user-popover" className="z-50 bg-bg-secondary border border-border rounded-xl shadow-2xl w-72 animate-fadeIn overflow-hidden">
        {/* The Relayed identity state — the one whose meaning IS provenance —
            rides a slim color bar above the card; its sentence sits in the
            card body with the other identity copy. Every other state,
            including a guest at another server, renders uniformly in the
            body. Relaying is an ordinary state, not a warning — the bar tint
            matches the header, never the warning palette. */}
        {claim.state === 'relayed' && (
          <div className="bg-purple/15 border-b border-border px-3 py-1.5 text-[11px] font-semibold text-fg-muted">
            {claim.label}
          </div>
        )}
        {/* Header */}
        <div className="h-16 bg-gradient-to-r from-accent/20 to-purple/20 relative">
          {avatarUrl ? (
            <img
              src={avatarUrl}
              alt=""
              className="absolute -bottom-6 left-4 w-14 h-14 rounded-full border-4 border-bg-secondary object-cover"
            />
          ) : (
            <div className="absolute -bottom-6 left-4 w-14 h-14 rounded-full border-4 border-bg-secondary bg-surface flex items-center justify-center text-accent font-bold text-lg">
              {nick[0]?.toUpperCase()}
            </div>
          )}
        </div>

        <div className="pt-8 px-4 pb-4">
          {/* Display name */}
          <div className="font-semibold text-fg">{displayName}</div>
          {displayName !== nick && (
            <div className="text-sm text-fg-muted">{nick}</div>
          )}

          {/* AT Handle — only for AT Protocol users (not did:key) */}
          {handle && !isDidKey && (
            <div className="text-xs text-accent mt-1 flex items-center gap-1">
              <span>@{handle}</span>
              {claim.showsMark && <span className="text-success text-[10px]" title="AT Protocol identity">✓</span>}
            </div>
          )}

          {/* Away / custom status */}
          {away != null && (
            <div className="text-xs text-warning mt-1 truncate" title={awayStatus ?? undefined}>
              Away{awayStatus ? `: ${awayStatus}` : ''}
            </div>
          )}

          {/* Agent badge */}
          {actorInfo && (actorInfo.actor_class === 'agent' || actorInfo.actor_class === 'external_agent') && (
            <div className="inline-flex items-center gap-1 mt-1 px-2 py-0.5 bg-accent/10 rounded-full text-xs text-accent">
              🤖 {actorInfo.spawned ? 'Spawned Agent' : actorInfo.actor_class === 'external_agent' ? 'External Agent' : 'Agent'}
            </div>
          )}

          {/* Spawned agent info */}
          {actorInfo?.spawned && (
            <div className="mt-2 p-2 bg-bg-tertiary rounded-lg text-left">
              <div className="text-[10px] text-fg-dim font-semibold mb-1">Spawned Agent</div>
              {actorInfo.parent_nick && (
                <div className="text-[10px] text-fg-dim">
                  <span className="text-fg-dim/60">Parent:</span>{' '}
                  <span className="font-semibold text-fg-muted">{actorInfo.parent_nick}</span>
                </div>
              )}
              {actorInfo.task && (
                <div className="text-[10px] text-fg-dim">
                  <span className="text-fg-dim/60">Task:</span> {actorInfo.task}
                </div>
              )}
              {actorInfo.capabilities && actorInfo.capabilities.length > 0 && (
                <div className="text-[10px] text-fg-dim">
                  <span className="text-fg-dim/60">Caps:</span> {actorInfo.capabilities.join(', ')}
                </div>
              )}
              {actorInfo.ttl && (
                <div className="text-[10px] text-fg-dim">
                  <span className="text-fg-dim/60">TTL:</span> {actorInfo.ttl}s
                </div>
              )}
            </div>
          )}

          {/* DID */}
          {effectiveDid && (
            <div
              className="text-[10px] text-fg-dim mt-1 font-mono break-all cursor-pointer hover:text-fg-muted"
              onClick={() => { navigator.clipboard.writeText(effectiveDid); import('./Toast').then(m => m.showToast('DID copied', 'success', 2000)); }}
              title="Click to copy DID"
            >
              {effectiveDid}
            </div>
          )}

          {/* Agent presence */}
          {actorInfo?.presence && actorInfo.presence.state && (
            <div className="mt-2 p-2 bg-bg-tertiary rounded-lg text-left">
              <div className="text-[10px] text-fg-dim font-semibold mb-1">Presence</div>
              <div className="text-xs text-fg-muted flex items-center gap-1">
                <span>{
                  { online: '🟢', idle: '💤', active: '⚡', executing: '🔨',
                    waiting_for_input: '⏳', blocked_on_permission: '🔒',
                    blocked_on_budget: '💰', degraded: '🟡', paused: '⏸️',
                    sandboxed: '📦', rate_limited: '🚦', revoked: '🚫', offline: '⚫',
                  }[actorInfo.presence.state] || '•'
                }</span>
                <span>{actorInfo.presence.state}</span>
              </div>
              {actorInfo.presence.status && (
                <div className="text-[10px] text-fg-dim mt-0.5">{actorInfo.presence.status}</div>
              )}
            </div>
          )}

          {/* Provenance */}
          {actorInfo?.provenance && (
            <ProvenanceBlock provenance={actorInfo.provenance} />
          )}

          {/* Heartbeat */}
          {actorInfo?.heartbeat && (
            <div className="mt-2 p-2 bg-bg-tertiary rounded-lg text-left">
              <div className="text-[10px] text-fg-dim font-semibold mb-1">Heartbeat</div>
              <div className="text-[10px] text-fg-dim flex items-center gap-1">
                {actorInfo.heartbeat.healthy ? (
                  <span className="text-success">💓 healthy</span>
                ) : (
                  <span className="text-danger">💔 unhealthy</span>
                )}
                {actorInfo.heartbeat.ttl && <span>· TTL {actorInfo.heartbeat.ttl}s</span>}
              </div>
            </div>
          )}

          {/* E2EE Safety Number */}
          {safetyNumber && (
            <div className="mt-2 p-2 bg-success/5 border border-success/20 rounded-lg">
              <div className="text-[10px] text-success font-semibold mb-1 flex items-center gap-1">
                🔒 Encrypted DM — Safety Number
              </div>
              <div className="text-[10px] font-mono text-fg-dim leading-relaxed tracking-wider">
                {safetyNumber}
              </div>
              <div className="text-[9px] text-fg-dim mt-1">
                Compare with your contact to verify encryption
              </div>
            </div>
          )}

          {/* Bio */}
          {profile?.description && (
            <div className="text-xs text-fg-muted mt-2 leading-relaxed line-clamp-3">
              {profile.description}
            </div>
          )}

          {/* WHOIS info (for guests or extra detail) — suppressed for federated
              senders: it's local-server, resolved-by-nick data, i.e. the wrong
              person for a relayed message. */}
          {whois && !origin && (
            <div className="mt-2 space-y-0.5">
              {whois.user && whois.host && (
                <div className="text-[11px] text-fg-dim font-mono">
                  {whois.user}@{whois.host}
                </div>
              )}
              {whois.channels && (
                <div className="text-[11px] text-fg-dim">
                  <span className="text-fg-dim">Channels:</span> {whois.channels}
                </div>
              )}
              {whois.server && (
                <div className="text-[11px] text-fg-dim">
                  <span className="text-fg-dim">Server:</span> {whois.server}
                </div>
              )}
            </div>
          )}

          {loading && !profile && !whois && (
            <div className="text-xs text-fg-dim mt-2 flex items-center gap-1">
              <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Loading...
            </div>
          )}

          {/* What we can honestly say about who this is. The two lines that
              name "the key below" belong on a surface showing that key; this
              card has none, so those states show the label alone. While the
              ask is out it's motion, not words. An origin-bearing claim's
              label already rides the bar above the card, so only its
              sentence renders here. */}
          {claim.isPending ? (
            <div className="mt-2 flex text-fg-dim">
              <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24" aria-hidden="true">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            </div>
          ) : (
            <div className="text-[10px] text-fg-dim mt-2 bg-bg-tertiary rounded px-2 py-1">
              {claim.state !== 'relayed' && <div className="font-semibold text-fg-muted">{claim.label}</div>}
              {!claim.needsKeyCard && (
                <div className={`leading-relaxed${claim.state === 'relayed' ? '' : ' mt-0.5'}`}>{claim.line}</div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 mt-3">
            <button
              onClick={startDM}
              className="flex-1 bg-accent/10 hover:bg-accent/20 text-accent text-xs py-1.5 rounded-lg font-medium"
            >
              Message
            </button>
            {handle && !isDidKey && (
              <a
                href={`https://bsky.app/profile/${handle}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex-1 bg-bg-tertiary hover:bg-surface text-fg-muted hover:text-fg text-xs py-1.5 rounded-lg text-center"
              >
                Bluesky ↗
              </a>
            )}
          </div>

          {/* Safety actions — not for yourself */}
          {!isSelf && (
            showReportReasons ? (
              <div className="mt-2">
                <div className="text-[10px] uppercase tracking-widest text-fg-dim font-semibold mb-1">Report for…</div>
                <div className="flex flex-wrap gap-1">
                  {REPORT_REASONS.map((reason) => (
                    <button
                      key={reason}
                      onClick={() => {
                        reportUser(nick, effectiveDid, reason);
                        showToast(`Reported and blocked ${nick}`, 'success', 2500);
                        onClose();
                      }}
                      className="text-[11px] px-2 py-1 rounded-lg bg-danger/10 hover:bg-danger/20 text-danger"
                    >
                      {reason}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex gap-2 mt-2">
                <button
                  onClick={() => {
                    if (isBlocked) {
                      if (effectiveDid) useStore.getState().unblockUser(effectiveDid);
                      useStore.getState().unblockUser(nick);
                      showToast(`Unblocked ${nick}`, 'success', 2000);
                    } else {
                      useStore.getState().blockUser(nick, effectiveDid);
                      showToast(`Blocked ${nick}`, 'success', 2000);
                      onClose();
                    }
                  }}
                  className="flex-1 bg-danger/10 hover:bg-danger/20 text-danger text-xs py-1.5 rounded-lg font-medium"
                >
                  {isBlocked ? 'Unblock' : 'Block'}
                </button>
                <button
                  onClick={() => setShowReportReasons(true)}
                  className="flex-1 bg-danger/10 hover:bg-danger/20 text-danger text-xs py-1.5 rounded-lg font-medium"
                >
                  Report…
                </button>
              </div>
            )
          )}
        </div>
      </div>
    </>,
    document.body,
  );
}
