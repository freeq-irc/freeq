import { useEffect, useRef, useCallback, useState, useMemo, memo } from 'react';
import { useStore, uniqueMemberCount, type Message, type PinnedMessage } from '../store';
import { getNick, getClient, requestHistory, sendReaction, sendUnreact, joinChannel } from '../irc/client';
import { fetchProfile, getCachedProfile, type ATProfile } from '../lib/profiles';
import { isDid, isPeerBlocked } from '../lib/identity';
import { displayNameForKey } from '../lib/display-name';
import { EmojiPicker } from './EmojiPicker';
import { UserPopover } from './UserPopover';
import { BlueskyEmbed } from './BlueskyEmbed';
import { LinkPreview } from './LinkPreview';
import { MessageContextMenu } from './MessageContextMenu';
import { MarkdownMessage } from './MarkdownRenderer';
import { CoordinationEventCard, isCoordinationEvent } from './CoordinationCards';
import { jumbomojiSize } from '../lib/jumbomoji';
import { buildTranscript } from '../lib/transcript';
import { useCachedVerdict, VERIFY_LABELS } from '../lib/verify-signature';
import { VerifySignaturePanel } from './VerifySignaturePanel';

// ── Colors ──

const NICK_COLORS = [
  '#ff6eb4', '#00d4aa', '#ffb547', '#5c9eff', '#b18cff',
  '#ff9547', '#00c4ff', '#ff5c5c', '#7edd7e', '#ff85d0',
];

export function nickColor(nick: string): string {
  let h = 0;
  for (let i = 0; i < nick.length; i++) h = nick.charCodeAt(i) + ((h << 5) - h);
  return NICK_COLORS[Math.abs(h) % NICK_COLORS.length];
}

function nickInitial(nick: string): string {
  return (nick[0] || '?').toUpperCase();
}

// ── Time formatting ──

function formatTime(d: Date): string {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDateSeparator(d: Date): string {
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

function shouldShowDateSep(msgs: Message[], i: number): boolean {
  if (i === 0) return true;
  const prev = msgs[i - 1];
  const curr = msgs[i];
  if (prev.isSystem || curr.isSystem) return false;
  return prev.timestamp.toDateString() !== curr.timestamp.toDateString();
}

// ── Linkify + markdown-lite ──

// Image URL patterns (CDN, direct links)
const IMAGE_URL_RE = /https?:\/\/[^\s<]+\.(?:jpg|jpeg|png|gif|webp)(?:\?[^\s<]*)?/gi;
const CDN_IMAGE_RE = /https?:\/\/cdn\.bsky\.app\/img\/[^\s<]+/gi;

// Voice message pattern: 🎤 Voice message (0:05) https://...
const VOICE_MSG_RE = /🎤[^h]*(https?:\/\/\S+)/;
// Duration in voice message
const VOICE_DURATION_RE = /\((\d+:\d+)\)/;
// Video URL patterns
const VIDEO_URL_RE = /https?:\/\/[^\s<]+\.(?:mp4|mov|m4v|webm)(?:\?[^\s<]*)?/i;
// Audio URL patterns (file extension based)
const AUDIO_URL_RE = /https?:\/\/[^\s<]+\.(?:m4a|mp3|ogg|wav|aac)(?:\?[^\s<]*)?/i;
// PDS blob URL (for audio/video blobs)
const PDS_BLOB_RE = /https?:\/\/[^\s]+\/xrpc\/com\.atproto\.sync\.getBlob[^\s]*/i;
// Proxy blob URL with mime hint
const PROXY_VIDEO_RE = /https?:\/\/[^\s]+\/api\/v1\/blob\?[^\s]*mime=video%2F[^\s]*/i;
const PROXY_AUDIO_RE = /https?:\/\/[^\s]+\/api\/v1\/blob\?[^\s]*mime=audio%2F[^\s]*/i;

function extractImageUrls(text: string): string[] {
  const urls: string[] = [];
  const matches = text.match(IMAGE_URL_RE) || [];
  const cdnMatches = text.match(CDN_IMAGE_RE) || [];
  const all = new Set([...matches, ...cdnMatches]);
  for (const u of all) urls.push(u);
  return urls;
}

/** Text WITHOUT image URLs (for display above images) */
function textWithoutImages(text: string, imageUrls: string[]): string {
  let result = text;
  for (const url of imageUrls) {
    result = result.replace(url, '').trim();
  }
  return result;
}

/** Parse text into typed segments for safe React rendering (no dangerouslySetInnerHTML). */
interface TextSegment {
  type: 'text' | 'link' | 'code' | 'codeblock' | 'bold' | 'italic' | 'strike' | 'mention' | 'channel';
  content: string;
  href?: string;
  /** For mention/channel: the actionable value (nick without @, or #channel). */
  value?: string;
}

function parseTextSegments(text: string): TextSegment[] {
  const segments: TextSegment[] = [];
  // Tokenize by splitting on markdown patterns
  // Order matters: code blocks first, then inline code, then other formatting
  const patterns: { re: RegExp; type: TextSegment['type']; group: number }[] = [
    { re: /```([\s\S]*?)```/g, type: 'codeblock', group: 1 },
    { re: /`([^`]+)`/g, type: 'code', group: 1 },
    { re: /(https?:\/\/[^\s<]+)/g, type: 'link', group: 1 },
    { re: /\*\*(.+?)\*\*/g, type: 'bold', group: 1 },
    { re: /(?<!\*)\*([^*]+)\*(?!\*)/g, type: 'italic', group: 1 },
    { re: /~~(.+?)~~/g, type: 'strike', group: 1 },
    { re: /(?<![A-Za-z0-9])@([A-Za-z0-9][A-Za-z0-9._-]*)/g, type: 'mention', group: 1 },
    { re: /(?<![\w/#])#([A-Za-z0-9][A-Za-z0-9._-]*)/g, type: 'channel', group: 1 },
  ];

  // Build a combined list of all matches with positions
  const matches: { start: number; end: number; type: TextSegment['type']; content: string; full: string }[] = [];
  for (const p of patterns) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) !== null) {
      matches.push({
        start: m.index,
        end: m.index + m[0].length,
        type: p.type,
        content: m[p.group],
        full: m[0],
      });
    }
  }

  // Sort by start position, remove overlapping
  matches.sort((a, b) => a.start - b.start);
  const filtered: typeof matches = [];
  let lastEnd = 0;
  for (const m of matches) {
    if (m.start >= lastEnd) {
      filtered.push(m);
      lastEnd = m.end;
    }
  }

  // Build segments
  let pos = 0;
  for (const m of filtered) {
    if (m.start > pos) {
      segments.push({ type: 'text', content: text.slice(pos, m.start) });
    }
    if (m.type === 'link') {
      segments.push({ type: 'link', content: m.content, href: m.content });
    } else if (m.type === 'mention') {
      // display the full "@nick", act on the bare nick
      segments.push({ type: 'mention', content: m.full, value: m.content });
    } else if (m.type === 'channel') {
      // display + act on the full "#channel"
      segments.push({ type: 'channel', content: m.full, value: m.full });
    } else {
      segments.push({ type: m.type, content: m.content });
    }
    pos = m.end;
  }
  if (pos < text.length) {
    segments.push({ type: 'text', content: text.slice(pos) });
  }

  return segments;
}

// ── Segment parse cache (avoids re-parsing on every render) ──

const _segmentCache = new Map<string, TextSegment[]>();
const SEGMENT_CACHE_MAX = 2000;

function parseTextSegmentsCached(text: string): TextSegment[] {
  const cached = _segmentCache.get(text);
  if (cached) return cached;
  const segments = parseTextSegments(text);
  if (_segmentCache.size >= SEGMENT_CACHE_MAX) {
    // Evict oldest half
    const keys = [..._segmentCache.keys()];
    for (let i = 0; i < keys.length / 2; i++) _segmentCache.delete(keys[i]);
  }
  _segmentCache.set(text, segments);
  return segments;
}

/** Render newline characters as <br> elements for inline text. */
function renderWithBreaks(text: string): React.ReactNode {
  if (!text.includes('\n')) return text;
  const parts = text.split('\n');
  return parts.map((p, i) => (
    <span key={i}>{i > 0 && <br />}{p}</span>
  ));
}

/** Context for making @nick / #channel spans interactive. */
interface RenderCtx {
  channel?: string;
  onNickClick?: (nick: string, did: string | undefined, origin: string | undefined, e: React.MouseEvent) => void;
}

/** Render text segments as React elements (XSS-safe — no innerHTML). */
function renderTextSafe(text: string, ctx?: RenderCtx): React.ReactElement {
  const segments = parseTextSegmentsCached(text);
  return (
    <>
      {segments.map((seg, i) => {
        const content = seg.content;
        switch (seg.type) {
          case 'link':
            return <a key={i} href={seg.href} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline break-all">{content}</a>;
          case 'mention':
            return (
              <button
                key={i}
                type="button"
                className="text-accent hover:underline font-medium"
                onClick={(e) => {
                  e.stopPropagation();
                  const nick = seg.value ?? content.replace(/^@/, '');
                  // Resolve DID from the channel roster (impersonation-safe).
                  const did = ctx?.channel
                    ? useStore.getState().channels.get(ctx.channel.toLowerCase())?.members.get(nick.toLowerCase())?.did
                    : undefined;
                  ctx?.onNickClick?.(nick, did, undefined, e);
                }}
              >{content}</button>
            );
          case 'channel':
            return (
              <button
                key={i}
                type="button"
                className="text-accent hover:underline font-medium"
                onClick={(e) => { e.stopPropagation(); joinChannel(seg.value ?? content); }}
              >{content}</button>
            );
          case 'codeblock':
            return <pre key={i} className="bg-surface rounded px-2 py-1.5 my-1 text-[13px] font-mono overflow-x-auto whitespace-pre-wrap">{content.replace(/^\n|\n$/g, '')}</pre>;
          case 'code':
            return <code key={i} className="bg-surface px-1 py-0.5 rounded text-[13px] font-mono text-pink">{content}</code>;
          case 'bold':
            return <strong key={i}>{renderWithBreaks(content)}</strong>;
          case 'italic':
            return <em key={i}>{renderWithBreaks(content)}</em>;
          case 'strike':
            return <del key={i} className="text-fg-dim">{renderWithBreaks(content)}</del>;
          default:
            return <span key={i}>{renderWithBreaks(content)}</span>;
        }
      })}
    </>
  );
}



// ── External image gating ──

/** Trusted domains that always load inline (our own infrastructure). */
function isTrustedImageUrl(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    // Private freeq media served from our own origin is always first-party —
    // never gate it behind the "load external media" setting.
    if (u.origin === window.location.origin && u.pathname.startsWith('/api/v1/media/')) {
      return true;
    }
    const h = u.hostname;
    return h === 'cdn.bsky.app' || h.endsWith('.bsky.app') || h.endsWith('.bsky.network')
      || h === 'freeq.at' || h.endsWith('.freeq.at') || h === 'localhost';
  } catch {
    return false;
  }
}

/** Image that respects the "Load external media" setting. */
function GatedImage({ url, onOpen }: { url: string; onOpen: () => void }) {
  const loadMedia = useStore((s) => s.loadExternalMedia);
  const [revealed, setRevealed] = useState(false);
  const trusted = isTrustedImageUrl(url);

  if (trusted || loadMedia || revealed) {
    return (
      <button onClick={onOpen} className="block cursor-zoom-in">
        <img
          src={url}
          alt=""
          className="max-w-sm max-h-80 rounded-lg border border-border object-contain bg-bg-tertiary hover:opacity-90 transition-opacity"
          loading="lazy"
          onError={(e) => { e.currentTarget.style.display = 'none'; }}
        />
      </button>
    );
  }

  return (
    <button
      onClick={() => setRevealed(true)}
      className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border bg-bg-tertiary text-fg-dim text-sm hover:bg-surface hover:text-fg-muted transition-colors"
      title={url}
    >
      <span className="text-lg">🖼</span>
      <span>Click to load external image</span>
    </button>
  );
}

// ── Message content (text + inline images) ──

// Bluesky post URL pattern
const BSKY_POST_RE = /https?:\/\/bsky\.app\/profile\/([^/]+)\/post\/([a-zA-Z0-9]+)/;
// YouTube URL pattern  
const YT_RE = /(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/;

/** Inline audio player for voice messages and audio files */
function InlineAudioPlayer({ url, label }: { url: string; label?: string }) {
  const audioRef = useRef<HTMLAudioElement>(null);
  const [playing, setPlaying] = useState(false);
  const [progress, setProgress] = useState(0);
  const [duration, setDuration] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const toggle = () => {
    const el = audioRef.current;
    if (!el) return;
    if (playing) {
      el.pause();
      setPlaying(false);
      return;
    }
    setLoading(true);
    setError(false);
    el.play()
      .then(() => { setPlaying(true); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  };

  const fmt = (s: number) => {
    if (!s || !isFinite(s)) return '0:00';
    return `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  };

  return (
    <div className="mt-1.5 flex items-center gap-3 bg-bg-tertiary border border-border rounded-xl px-3 py-2.5 max-w-[300px]">
      <button
        onClick={toggle}
        disabled={loading}
        className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center transition ${
          error ? 'bg-red-500 hover:bg-red-600' : 'bg-accent hover:brightness-110'
        }`}
      >
        {loading ? (
          <svg className="w-5 h-5 text-white animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
          </svg>
        ) : error ? (
          <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        ) : playing ? (
          <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
        ) : (
          <svg className="w-4 h-4 text-white ml-0.5" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
        )}
      </button>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5 text-xs text-fg-muted mb-1">
          <svg className="w-3 h-3 text-accent" fill="currentColor" viewBox="0 0 24 24"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3zm-1-9c0-.55.45-1 1-1s1 .45 1 1v6c0 .55-.45 1-1 1s-1-.45-1-1V5z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/></svg>
          <span className="font-medium text-fg-secondary">Voice message</span>
        </div>
        <div className="relative h-1 bg-bg-hover rounded-full overflow-hidden">
          <div
            className="absolute left-0 top-0 h-full bg-accent rounded-full transition-all"
            style={{ width: duration > 0 ? `${(progress / duration) * 100}%` : '0%' }}
          />
        </div>
        <div className="flex justify-between mt-1 text-[10px] text-fg-muted font-mono">
          <span>{fmt(playing ? progress : 0)}</span>
          <span>{label || fmt(duration)}</span>
        </div>
      </div>
      <audio
        ref={audioRef}
        src={url}
        preload="metadata"
        onLoadedMetadata={() => setDuration(audioRef.current?.duration || 0)}
        onTimeUpdate={() => setProgress(audioRef.current?.currentTime || 0)}
        onEnded={() => { setPlaying(false); setProgress(0); }}
        onError={() => { setError(true); setPlaying(false); setLoading(false); }}
      />
    </div>
  );
}

/** Inline video player */
function InlineVideoPlayer({ url }: { url: string }) {
  return (
    <div className="mt-1.5 max-w-sm">
      <video
        src={url}
        controls
        preload="metadata"
        className="rounded-lg border border-border max-h-72 bg-black"
        playsInline
      />
    </div>
  );
}

function MessageContentImpl({ msg, channel, onNickClick }: {
  msg: Message;
  channel?: string;
  onNickClick?: (nick: string, did: string | undefined, origin: string | undefined, e: React.MouseEvent) => void;
}) {
  const setLightbox = useStore((s) => s.setLightboxUrl);
  const linkCtx: RenderCtx = { channel, onNickClick };

  if (msg.isAction) {
    const color = msg.isSelf ? '#b18cff' : nickColor(msg.from);
    return (
      <div className="text-fg-muted italic text-[15px] mt-0.5">
        <span style={{ color }} className="font-semibold not-italic">{'* '}{displayNameForKey(msg.from)}</span>{' '}{msg.text}
      </div>
    );
  }

  // Coordination event cards (Phase 3)
  if (isCoordinationEvent(msg)) {
    const card = <CoordinationEventCard msg={msg} />;
    if (card) return card;
  }

  // Jumbomoji: a message of just 1–3 emoji renders large.
  const jumboSize = jumbomojiSize(msg.text);
  if (jumboSize) {
    return (
      <div className="mt-0.5">
        {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}
        <div style={{ fontSize: jumboSize, lineHeight: 1.15 }}>{msg.text.trim()}</div>
      </div>
    );
  }

  // Markdown messages — render with full markdown support
  const mimeType = msg.tags?.['+freeq.at/mime'];
  if (mimeType === 'text/markdown') {
    return (
      <div className="mt-0.5">
        {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}
        <MarkdownMessage text={msg.text} />
      </div>
    );
  }

  // Voice messages — check first before image extraction
  const voiceMatch = msg.text.match(VOICE_MSG_RE);
  if (voiceMatch) {
    const durationMatch = msg.text.match(VOICE_DURATION_RE);
    let audioUrl = voiceMatch[1];
    // Rewrite old cdn.bsky.app/img/ URLs to proxy through our server
    const cdnMatch = audioUrl.match(/cdn\.bsky\.app\/img\/[^/]+\/plain\/([^/]+)\/([^@\s]+)/);
    if (cdnMatch) {
      const pdsUrl = `https://bsky.social/xrpc/com.atproto.sync.getBlob?did=${cdnMatch[1]}&cid=${cdnMatch[2]}`;
      audioUrl = `/api/v1/blob?url=${encodeURIComponent(pdsUrl)}`;
    }
    // Proxy PDS blob URLs too
    if (audioUrl.includes('/xrpc/com.atproto.sync.getBlob')) {
      audioUrl = `/api/v1/blob?url=${encodeURIComponent(audioUrl)}`;
    }
    return (
      <div className="mt-0.5">
        {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}
        <InlineAudioPlayer url={audioUrl} label={durationMatch?.[1]} />
      </div>
    );
  }

  // Video URLs (file extension or proxy with video mime hint)
  const videoMatch = msg.text.match(VIDEO_URL_RE) || msg.text.match(PROXY_VIDEO_RE);
  if (videoMatch) {
    const cleanText = msg.text.replace(videoMatch[0], '').trim();
    return (
      <div className="mt-0.5">
        {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}
        {cleanText && <div className="text-[15px] leading-relaxed mb-1">{renderTextSafe(cleanText)}</div>}
        <InlineVideoPlayer url={videoMatch[0]} />
      </div>
    );
  }

  // Audio URLs (file extension, proxy with audio mime hint, or PDS blob)
  const audioMatch = msg.text.match(AUDIO_URL_RE) || msg.text.match(PROXY_AUDIO_RE) || msg.text.match(PDS_BLOB_RE);
  if (audioMatch && !msg.text.match(IMAGE_URL_RE) && !msg.text.match(CDN_IMAGE_RE)) {
    const cleanText = msg.text.replace(audioMatch[0], '').trim();
    return (
      <div className="mt-0.5">
        {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}
        {cleanText && <div className="text-[15px] leading-relaxed mb-1">{renderTextSafe(cleanText)}</div>}
        <InlineAudioPlayer url={audioMatch[0]} />
      </div>
    );
  }

  const imageUrls = extractImageUrls(msg.text);
  const cleanText = imageUrls.length > 0 ? textWithoutImages(msg.text, imageUrls) : msg.text;

  // Check for embeddable URLs
  const bskyMatch = msg.text.match(BSKY_POST_RE);
  const ytMatch = msg.text.match(YT_RE);

  return (
    <div className="mt-0.5">
      {/* Reply context */}
      {msg.replyTo && <ReplyBadge msgId={msg.replyTo} />}

      {cleanText && (
        <div className="text-[15px] leading-relaxed [&_pre]:my-1 [&_a]:break-all">
          {renderTextSafe(cleanText, linkCtx)}
        </div>
      )}

      {/* Inline images */}
      {imageUrls.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-2">
          {imageUrls.map((url) => (
            <GatedImage key={url} url={url} onOpen={() => setLightbox(url)} />
          ))}
        </div>
      )}

      {/* Bluesky post embed */}
      {bskyMatch && <BlueskyEmbed handle={bskyMatch[1]} rkey={bskyMatch[2]} />}

      {/* YouTube thumbnail */}
      {ytMatch && (
        <a
          href={`https://youtube.com/watch?v=${ytMatch[1]}`}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-2 block max-w-sm rounded-lg overflow-hidden border border-border hover:border-accent/50 transition-colors"
        >
          <img
            src={`https://img.youtube.com/vi/${ytMatch[1]}/mqdefault.jpg`}
            alt="YouTube video"
            className="w-full"
            loading="lazy"
          />
          <div className="bg-bg-tertiary px-3 py-1.5 text-xs text-fg-muted flex items-center gap-1">
            <span className="text-red-500">▶</span> YouTube
          </div>
        </a>
      )}

      {/* Link preview for other URLs (not images, Bluesky, or YouTube) */}
      {!bskyMatch && !ytMatch && imageUrls.length === 0 && (() => {
        const urlMatch = msg.text.match(/(https?:\/\/[^\s<\])]+)/);
        if (!urlMatch) return null;
        // Clean trailing punctuation that's not part of the URL
        let url = urlMatch[1].replace(/[.,;:!?)'"]+$/, '');
        // Skip our own API URLs, blob proxy, audio/video — not web pages
        if (/\/api\/v1\/|\.(?:m4a|mp3|mp4|mov|webm|ogg|wav|aac)/i.test(url)) return null;
        // Skip if URL is malformed after cleanup
        try { new URL(url); } catch { return null; }
        return <LinkPreview url={url} />;
      })()}
    </div>
  );
}

/** Inline reply badge showing the original message */
function ReplyBadge({ msgId }: { msgId: string }) {
  const channels = useStore((s) => s.channels);
  const activeChannel = useStore((s) => s.activeChannel);
  const ch = channels.get(activeChannel.toLowerCase());
  const original = ch?.messages.find((m) => m.id === msgId);
  if (!original) return null;

  return (
    <button
      onClick={() => useStore.getState().setScrollToMsgId(msgId)}
      className="flex items-center gap-2 text-sm text-fg-dim mb-1.5 pl-2 border-l-2 border-accent/30 hover:bg-accent/5 rounded-r cursor-pointer w-full text-left"
    >
      <span className="font-semibold text-fg-muted">{original.from}</span>
      <span className="truncate max-w-[300px]">{original.text}</span>
    </button>
  );
}

// ── Message grouping ──

function isGrouped(msgs: Message[], i: number): boolean {
  if (i === 0) return false;
  const prev = msgs[i - 1];
  const curr = msgs[i];
  if (prev.isSystem || curr.isSystem || prev.deleted || curr.deleted) return false;
  if (prev.from !== curr.from) return false;
  // Don't group across a provenance boundary: a federated message (carrying
  // +freeq.at/origin) must not collapse under a local sender's header, or it
  // loses its "via {origin}" and inherits the local verified/signed context.
  // Same sender + same origin groups; local vs federated (or different origins)
  // each start a fresh header.
  if ((prev.tags?.['+freeq.at/origin'] ?? '') !== (curr.tags?.['+freeq.at/origin'] ?? '')) return false;
  if (curr.timestamp.getTime() - prev.timestamp.getTime() > 5 * 60 * 1000) return false;
  return true;
}

// ── Avatar component with AT profile support ──

function Avatar({ nick, did, size = 40 }: { nick: string; did?: string; size?: number }) {
  const [profile, setProfile] = useState<ATProfile | null>(
    did ? getCachedProfile(did) : null
  );

  useEffect(() => {
    if (did && !profile) {
      fetchProfile(did).then((p) => p && setProfile(p));
    }
  }, [did]);

  const color = nickColor(nick);

  if (profile?.avatar) {
    return (
      <img
        src={profile.avatar}
        alt=""
        className="rounded-full object-cover shrink-0"
        style={{ width: size, height: size }}
      />
    );
  }

  return (
    <div
      className="rounded-full flex items-center justify-center font-bold shrink-0"
      style={{
        width: size,
        height: size,
        backgroundColor: color + '20',
        color,
        fontSize: size * 0.4,
      }}
    >
      {nickInitial(nick)}
    </div>
  );
}

// ── Components ──

function DateSeparator({ date }: { date: Date }) {
  return (
    <div className="flex items-center gap-3 py-3 px-4">
      <div className="flex-1 border-t border-border" />
      <span className="text-xs text-fg-dim font-semibold">{formatDateSeparator(date)}</span>
      <div className="flex-1 border-t border-border" />
    </div>
  );
}

function SystemMessageImpl({ msg }: { msg: Message }) {
  return (
    <div className="px-4 py-1 flex items-start gap-3">
      <span className="w-10 shrink-0" />
      <span className="text-fg-dim text-sm">
        <span className="opacity-60">—</span>{' '}
        {renderTextSafe(msg.text)}
      </span>
    </div>
  );
}

interface MessageProps {
  msg: Message;
  channel: string;
  onNickClick: (nick: string, did: string | undefined, origin: string | undefined, e: React.MouseEvent) => void;
}

function FullMessageImpl({ msg, channel, onNickClick }: MessageProps) {
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [pickerPos, setPickerPos] = useState<{ x: number; y: number } | undefined>();
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [verifyPanel, setVerifyPanel] = useState<{ x: number; y: number } | null>(null);
  // The only signature state a resting row ever shows: a check that already
  // answered "invalid". Everything short of that answer is silent.
  const sigInvalid = useCachedVerdict(msg.id)?.outcome === 'invalid';
  const color = msg.isSelf ? '#b18cff' : nickColor(msg.from);
  const currentNick = getNick();
  const isMention = !msg.isSelf && msg.text.toLowerCase().includes(currentNick.toLowerCase());
  const isPinned = useStore((s) => s.channels.get(channel.toLowerCase())?.pins?.some(p => p.msgid === msg.id) ?? false);

  // Find DID for this user — check channel members reactively, fall back to authDid for self
  const member = useStore((s) => s.channels.get(channel.toLowerCase())?.members.get(msg.from.toLowerCase()));
  const selfDid = useStore((s) => msg.isSelf ? s.authDid : null);
  const did = member?.did || selfDid || msg.tags?.account || undefined;
  // Federated provenance: when present, this message was relayed from another
  // server (+freeq.at/origin = its name). Its identity is peer-vouched by that
  // server, not verified here — so we show "via {origin}" and suppress the
  // local "verified" (✓) badge, which would overstate trust.
  const origin = msg.tags?.['+freeq.at/origin'];
  const isFederated = !!origin;

  const openEmojiPicker = (e: React.MouseEvent) => {
    setPickerPos({ x: e.clientX, y: e.clientY });
    setShowEmojiPicker(true);
  };

  return (
    <div
      className={`msg-full group px-4 pt-3 pb-1 hover:bg-white/[0.02] flex gap-3 relative ${
        isPinned ? 'bg-accent/[0.04] border-l-2 border-orange-400' :
        isMention ? 'bg-accent/[0.04] border-l-2 border-accent' : ''
      }`}
      onContextMenu={(e) => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY }); }}
    >
      <div
        className="cursor-pointer mt-0.5"
        onClick={(e) => onNickClick(msg.from, did, origin, e)}
      >
        <Avatar nick={msg.from} did={did} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <button
            className="font-semibold text-[15px] hover:underline"
            style={{ color }}
            title={isDid(msg.from) ? msg.from : undefined}
            onClick={(e) => onNickClick(msg.from, member?.did, origin, e)}
          >
            {displayNameForKey(msg.from)}
          </button>
          {member?.did && !isFederated && <VerifiedBadge />}
          {isFederated && <ViaBadge origin={origin!} />}
          {sigInvalid && <InvalidSigMark />}
          {member?.away != null && (
            <span className="text-xs text-fg-dim bg-warning/10 text-warning px-1.5 py-0.5 rounded">away</span>
          )}
          <span className="text-xs text-fg-dim whitespace-nowrap cursor-default" title={msg.timestamp.toLocaleString([], { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}>{formatTime(msg.timestamp)}</span>
          {msg.isStreaming && <span className="text-xs text-blue-400 animate-pulse">streaming…</span>}
          {/* `editOf` covers an edit seen live; the tag covers one replayed on
              join, where the server collapses the revisions into a single row
              and nothing else in the wire form says it was ever edited. */}
          {(msg.editOf || msg.tags['+freeq.at/edited'] === '1') && !msg.isStreaming && (
            <span className="text-xs text-fg-dim">(edited)</span>
          )}
          {msg.encrypted && <EncryptedBadge />}
        </div>
        <MessageContent msg={msg} channel={channel} onNickClick={onNickClick} />
        <Reactions msg={msg} channel={channel} />
      </div>

      {/* Message actions — hover on desktop, tap on mobile */}
      <div className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 absolute right-3 -top-3 flex items-center bg-bg-secondary border border-border rounded-lg shadow-lg overflow-hidden transition-opacity z-10">
        <HoverBtn emoji="↩️" title="Reply" onClick={() => {
          useStore.getState().setReplyTo({ msgId: msg.id, from: msg.from, text: msg.text, channel });
        }} />
        <HoverBtn emoji="🧵" title="View thread" onClick={() => {
          useStore.getState().openThread(msg.id, channel);
        }} />
        {msg.isSelf && !msg.isSystem && (
          <HoverBtn emoji="✏️" title="Edit" onClick={() => {
            useStore.getState().setEditingMsg({ msgId: msg.id, text: msg.text, channel });
          }} />
        )}
        <HoverBtn emoji="😄" title="Add reaction" onClick={openEmojiPicker} />
      </div>

      {showEmojiPicker && pickerPos && (
        <div className="fixed z-50" style={{ left: pickerPos.x - 140, top: pickerPos.y - 280 }}>
          <EmojiPicker
            onSelect={(emoji) => {
              sendReaction(channel, emoji, msg.id);
              setShowEmojiPicker(false);
            }}
            onClose={() => setShowEmojiPicker(false)}
          />
        </div>
      )}

      {ctxMenu && (
        <MessageContextMenu
          msg={msg}
          channel={channel}
          position={ctxMenu}
          onClose={() => setCtxMenu(null)}
          onReply={() => useStore.getState().setReplyTo({ msgId: msg.id, from: msg.from, text: msg.text, channel })}
          onEdit={() => useStore.getState().setEditingMsg({ msgId: msg.id, text: msg.text, channel })}
          onThread={() => useStore.getState().openThread(msg.id, channel)}
          onReact={openEmojiPicker}
          onVerify={() => setVerifyPanel(ctxMenu)}
        />
      )}

      {verifyPanel && (
        <VerifySignaturePanel
          msgid={msg.id}
          signed={!!msg.tags['+freeq.at/sig']}
          position={verifyPanel}
          onClose={() => setVerifyPanel(null)}
        />
      )}
    </div>
  );
}

function GroupedMessageImpl({ msg, channel, onNickClick }: MessageProps) {
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [pickerPos, setPickerPos] = useState<{ x: number; y: number } | undefined>();
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [verifyPanel, setVerifyPanel] = useState<{ x: number; y: number } | null>(null);
  const sigInvalid = useCachedVerdict(msg.id)?.outcome === 'invalid';
  const currentNick = getNick();
  const isMention = !msg.isSelf && msg.text.toLowerCase().includes(currentNick.toLowerCase());
  const isPinned = useStore((s) => s.channels.get(channel.toLowerCase())?.pins?.some(p => p.msgid === msg.id) ?? false);

  const openEmojiPicker = (e: React.MouseEvent) => {
    setPickerPos({ x: e.clientX, y: e.clientY });
    setShowEmojiPicker(true);
  };

  return (
    <div
      className={`group px-4 py-0.5 hover:bg-white/[0.02] flex gap-3 relative ${
        isPinned ? 'bg-accent/[0.04] border-l-2 border-orange-400' :
        isMention ? 'bg-accent/[0.04] border-l-2 border-accent' : ''
      }`}
      onContextMenu={(e) => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY }); }}
    >
      <span className="w-10 shrink-0 text-right text-[11px] text-fg-dim opacity-0 group-hover:opacity-100 leading-[24px] cursor-default" title={msg.timestamp.toLocaleString([], { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}>
        {formatTime(msg.timestamp)}
      </span>
      {/* Reserved marker slot so a line that carries a badge doesn't sit
          differently from one that doesn't. Signatures earn no resting ink —
          the only signature mark a row can wear is the ⚠ after a check
          answered "invalid". */}
      <span className="min-w-5 shrink-0 flex items-start gap-1 leading-[24px]">
        {msg.encrypted && <EncryptedBadge />}
        {sigInvalid && <InvalidSigMark />}
      </span>

      <div className="min-w-0 flex-1">
        <MessageContent msg={msg} channel={channel} onNickClick={onNickClick} />
        <Reactions msg={msg} channel={channel} />
      </div>

      <div className="opacity-0 group-hover:opacity-100 absolute right-3 -top-3 flex items-center bg-bg-secondary border border-border rounded-lg shadow-lg overflow-hidden">
        <HoverBtn emoji="↩️" title="Reply" onClick={() => {
          useStore.getState().setReplyTo({ msgId: msg.id, from: msg.from, text: msg.text, channel });
        }} />
        {msg.isSelf && !msg.isSystem && (
          <HoverBtn emoji="✏️" title="Edit" onClick={() => {
            useStore.getState().setEditingMsg({ msgId: msg.id, text: msg.text, channel });
          }} />
        )}
        <HoverBtn emoji="😄" title="Add reaction" onClick={openEmojiPicker} />
      </div>

      {showEmojiPicker && pickerPos && (
        <div className="fixed z-50" style={{ left: pickerPos.x - 140, top: pickerPos.y - 280 }}>
          <EmojiPicker
            onSelect={(emoji) => {
              sendReaction(channel, emoji, msg.id);
              setShowEmojiPicker(false);
            }}
            onClose={() => setShowEmojiPicker(false)}
          />
        </div>
      )}

      {ctxMenu && (
        <MessageContextMenu
          msg={msg}
          channel={channel}
          position={ctxMenu}
          onClose={() => setCtxMenu(null)}
          onReply={() => useStore.getState().setReplyTo({ msgId: msg.id, from: msg.from, text: msg.text, channel })}
          onEdit={() => useStore.getState().setEditingMsg({ msgId: msg.id, text: msg.text, channel })}
          onThread={() => useStore.getState().openThread(msg.id, channel)}
          onReact={(e: React.MouseEvent) => { setPickerPos({ x: e.clientX, y: e.clientY }); setShowEmojiPicker(true); }}
          onVerify={() => setVerifyPanel(ctxMenu)}
        />
      )}

      {verifyPanel && (
        <VerifySignaturePanel
          msgid={msg.id}
          signed={!!msg.tags?.['+freeq.at/sig']}
          position={verifyPanel}
          onClose={() => setVerifyPanel(null)}
        />
      )}
    </div>
  );
}

// Memoized row components. The store preserves each message object's identity
// across appends (only the new message is a fresh object), and `channel` +
// `onNickClick` are stable, so React.memo's shallow prop check lets every
// unchanged row bail out — turning a per-message re-render + media-regex
// re-parse of all ~1000 rows into a single new row. `MessageContent` is
// wrapped too so its ~10 uncached media/link regexes don't run for unchanged
// rows.
export const MessageContent = memo(MessageContentImpl);
const SystemMessage = memo(SystemMessageImpl);
const FullMessage = memo(FullMessageImpl);
const GroupedMessage = memo(GroupedMessageImpl);

/** Verification badge for AT Protocol-authenticated users */
function VerifiedBadge() {
  return (
    <span className="text-accent text-xs" title="AT Protocol verified identity">
      <svg className="w-3.5 h-3.5 inline -mt-0.5" viewBox="0 0 16 16" fill="currentColor">
        <path d="M8 0a8 8 0 100 16A8 8 0 008 0zm3.78 5.97l-4.5 5a.75.75 0 01-1.06.02l-2-1.86a.75.75 0 011.02-1.1l1.45 1.35 3.98-4.43a.75.75 0 011.11 1.02z"/>
      </svg>
    </span>
  );
}

/** Provenance badge for a federated message — relayed from another server.
    The sender's identity is vouched for by that server, not verified here. */
function ViaBadge({ origin }: { origin: string }) {
  return (
    <span
      className="text-xs text-fg-dim bg-white/5 px-1.5 py-0.5 rounded cursor-default"
      title={`Relayed from ${origin}. This server didn't verify the sender's identity — ${origin} vouches for it.`}
    >
      via {origin}
    </span>
  );
}

/** The one signature mark a resting row can wear: a check that actually
 *  answered "invalid". Never speculative — it exists only after evidence. */
function InvalidSigMark() {
  return (
    <span
      data-testid="sig-invalid-mark"
      className="text-danger text-xs cursor-default"
      title={VERIFY_LABELS.invalid.text}
    >
      ⚠
    </span>
  );
}

function EncryptedBadge() {
  const [showInfo, setShowInfo] = useState(false);
  return (
    <span className="relative inline-block">
      <button
        className="text-[10px] text-success hover:opacity-80 transition-opacity"
        onClick={(e) => { e.stopPropagation(); setShowInfo(!showInfo); }}
        title="End-to-end encrypted"
      >
        🔒
      </button>
      {showInfo && (
        <div className="absolute bottom-full left-0 mb-1 w-64 bg-bg-secondary border border-border rounded-lg shadow-xl p-3 z-50 animate-fadeIn"
             onClick={(e) => e.stopPropagation()}>
          <div className="text-xs font-semibold text-success mb-1">🔒 End-to-End Encrypted</div>
          <p className="text-[11px] text-fg-muted leading-relaxed">
            This message is end-to-end encrypted. Only you and the recipient can read it —
            the server only sees ciphertext. Uses the Double Ratchet protocol (like Signal)
            with forward secrecy.
          </p>
          <button
            className="text-[10px] text-fg-dim hover:text-fg-muted mt-1.5"
            onClick={() => setShowInfo(false)}
          >
            Dismiss
          </button>
        </div>
      )}
    </span>
  );
}

function HoverBtn({ emoji, title, onClick }: { emoji: string; title: string; onClick: (e: React.MouseEvent) => void }) {
  return (
    <button
      className="w-9 h-9 flex items-center justify-center text-sm hover:bg-bg-tertiary text-fg-dim hover:text-fg-muted"
      title={title}
      onClick={onClick}
    >
      {emoji}
    </button>
  );
}

function Reactions({ msg, channel }: { msg: Message; channel: string }) {
  if (!msg.reactions || msg.reactions.size === 0) return null;
  const myNick = getNick();
  return (
    <div className="flex gap-1.5 mt-1.5 flex-wrap">
      {[...msg.reactions.entries()].map(([emoji, nicks]) => {
        const isMine = nicks.has(myNick);
        return (
          <button
            key={emoji}
            onClick={() => isMine
              ? sendUnreact(channel, emoji, msg.id)
              : sendReaction(channel, emoji, msg.id)}
            className={`rounded-lg px-2.5 py-1 text-sm inline-flex items-center gap-1.5 border ${
              isMine
                ? 'bg-accent/10 border-accent/30 text-accent'
                : 'bg-surface border-transparent hover:border-border-bright text-fg-muted'
            }`}
            title={`reacted with ${emoji}: ${[...nicks].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())).slice(0, 12).join(', ')}${nicks.size > 12 ? ` +${nicks.size - 12} more` : ''}`}
          >
            <span>{emoji}</span>
            <span>{nicks.size}</span>
          </button>
        );
      })}
    </div>
  );
}

// ── Typing indicator ──

function TypingIndicatorBar({ channel }: { channel: string }) {
  const channels = useStore((s) => s.channels);
  const ch = channels.get(channel.toLowerCase());
  if (!ch) return null;

  const typers = [...ch.members.values()].filter((m) => m.typing).map((m) => m.nick);
  if (typers.length === 0) return null;

  const text = typers.length === 1
    ? `${typers[0]} is typing`
    : typers.length === 2
    ? `${typers[0]} and ${typers[1]} are typing`
    : `${typers[0]} and ${typers.length - 1} others are typing`;

  return (
    <div className="px-4 py-1.5 flex items-center gap-2 text-xs text-fg-dim animate-fadeIn" aria-live="polite" aria-atomic="true">
      <span className="flex gap-0.5">
        <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '0ms' }} />
        <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '150ms' }} />
        <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '300ms' }} />
      </span>
      <span className="text-fg-muted">{text}</span>
    </div>
  );
}

// ── Main export ──

/** Pinned messages bar — shows at the top of the channel message area. */
function ChannelEmptyState({ channel }: { channel: string }) {
  const ch = useStore((s) => s.channels.get(channel.toLowerCase()));
  const topic = ch?.topic;
  const memberCount = ch ? uniqueMemberCount(ch.members) : 0;
  const isEncrypted = ch?.isEncrypted;

  return (
    <>
      <div className="text-3xl mb-2">👋</div>
      <div className="text-xl text-fg font-bold">Welcome to {channel}</div>

      {topic && (
        <div className="text-sm mt-2 text-center max-w-md leading-relaxed text-fg-muted">
          {topic}
        </div>
      )}

      {!topic && (
        <div className="text-sm mt-2 text-center max-w-xs leading-relaxed text-fg-dim">
          This is the beginning of <span className="text-accent font-medium">{channel}</span>.
        </div>
      )}

      {/* Channel features */}
      <div className="flex flex-wrap justify-center gap-2 mt-4 text-[11px]">
        {memberCount > 0 && (
          <span className="bg-bg-tertiary border border-border rounded-full px-2.5 py-1 text-fg-dim">
            👥 {memberCount} {memberCount === 1 ? 'member' : 'members'}
          </span>
        )}
        {isEncrypted && (
          <span className="bg-success/5 border border-success/20 rounded-full px-2.5 py-1 text-success">
            🔒 Encrypted
          </span>
        )}
        <span className="bg-bg-tertiary border border-border rounded-full px-2.5 py-1 text-fg-dim">
          ✍️ Messages are signed
        </span>
      </div>

      {/* Info cards */}
      <div className="grid gap-2 mt-5 max-w-sm w-full">
        <div className="bg-bg-tertiary/50 border border-border rounded-lg p-3 text-left">
          <div className="text-[11px] font-semibold text-fg-muted mb-0.5">🔐 Verified Identity</div>
          <div className="text-[11px] text-fg-dim leading-relaxed">
            Users with a <span className="text-accent">✓</span> next to their name are signed in with their AT Protocol (Bluesky) identity. Their messages are cryptographically signed and can&apos;t be forged.
          </div>
        </div>
        <div className="bg-bg-tertiary/50 border border-border rounded-lg p-3 text-left">
          <div className="text-[11px] font-semibold text-fg-muted mb-0.5">💬 Getting started</div>
          <div className="text-[11px] text-fg-dim leading-relaxed">
            Type a message below to start chatting. Use <kbd className="px-1 py-0.5 bg-bg border border-border rounded text-[10px] font-mono">/help</kbd> for commands, or right-click messages for actions.
          </div>
        </div>
      </div>

      <div className="flex gap-2 mt-4">
        <button onClick={() => {
          navigator.clipboard.writeText(`https://irc.freeq.at/join/${encodeURIComponent(channel)}`);
          import('./Toast').then(m => m.showToast('Invite link copied', 'success', 2000));
        }} className="text-xs bg-bg-tertiary border border-border rounded-lg px-3 py-1.5 text-fg-dim hover:text-fg hover:border-accent transition-colors">
          🔗 Copy invite link
        </button>
      </div>
    </>
  );
}

const EMPTY_PINS: PinnedMessage[] = [];

function PinnedBar({ pins, messages }: { pins: PinnedMessage[]; messages: Message[] }) {
  const [expanded, setExpanded] = useState(false);
  if (pins.length === 0) return null;

  // Find the actual message content for each pin
  const pinnedMsgs = pins.slice(0, expanded ? 10 : 1).map((pin) => {
    const msg = messages.find((m) => m.id === pin.msgid);
    return { ...pin, msg };
  });

  return (
    <div className="border-b border-border bg-bg-secondary/50 px-4 py-1.5 text-sm">
      <div className="flex items-center gap-2">
        <span className="text-accent text-xs">📌</span>
        {pinnedMsgs[0]?.msg ? (
          <button
            className="flex-1 text-left truncate text-fg-muted hover:text-fg transition-colors"
            onClick={() => {
              useStore.getState().setScrollToMsgId(pinnedMsgs[0].msgid);
            }}
          >
            <span className="font-semibold text-fg text-xs">{pinnedMsgs[0].msg.from}</span>
            <span className="ml-1.5 text-xs">{pinnedMsgs[0].msg.text.slice(0, 120)}{pinnedMsgs[0].msg.text.length > 120 ? '…' : ''}</span>
          </button>
        ) : (
          <span className="flex-1 text-fg-dim text-xs italic">Pinned message not in view</span>
        )}
        {pins.length > 1 && (
          <button
            className="text-[10px] text-fg-dim hover:text-fg shrink-0"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? '▲' : `+${pins.length - 1} more`}
          </button>
        )}
      </div>
      {expanded && pinnedMsgs.slice(1).map((p) => (
        <div key={p.msgid} className="flex items-center gap-2 mt-1">
          <span className="text-accent text-xs">📌</span>
          {p.msg ? (
            <button
              className="flex-1 text-left truncate text-fg-muted hover:text-fg text-xs"
              onClick={() => useStore.getState().setScrollToMsgId(p.msgid)}
            >
              <span className="font-semibold text-fg">{p.msg.from}</span>
              <span className="ml-1.5">{p.msg.text.slice(0, 100)}</span>
            </button>
          ) : (
            <span className="flex-1 text-fg-dim text-xs italic">Message {p.msgid.slice(0, 8)}…</span>
          )}
        </div>
      ))}
    </div>
  );
}

export function MessageList() {
  const activeChannel = useStore((s) => s.activeChannel);
  const rawMessages = useStore((s) => {
    if (s.activeChannel === 'server') return s.serverMessages;
    return s.channels.get(s.activeChannel.toLowerCase())?.messages || [];
  });
  const showJoinPart = useStore((s) => s.showJoinPart);
  const blockedDids = useStore((s) => s.blockedDids);
  const blockedNicks = useStore((s) => s.blockedNicks);
  const activeMembers = useStore((s) => s.channels.get(s.activeChannel.toLowerCase())?.members);

  // Filter out join/part/quit noise unless the user opted in.
  // Keep moderation actions (kicks, bans, mode changes) always visible.
  const JOIN_PART_RE = /^.+ (joined|left|quit)(\s|$)/;
  const messages = useMemo(() => {
    let msgs = rawMessages;
    // Hide messages from blocked users (DID first, nick fallback for guests).
    if (blockedDids.length > 0 || blockedNicks.length > 0) {
      msgs = msgs.filter((m) => {
        if (m.isSelf || m.isSystem) return true;
        const did = activeMembers?.get(m.from.toLowerCase())?.did || m.tags?.account;
        if (did && blockedDids.includes(did)) return false;
        return !blockedNicks.includes(m.from.toLowerCase());
      });
    }
    if (showJoinPart) return msgs;
    return msgs.filter((m) => !m.isSystem || !JOIN_PART_RE.test(m.text));
  }, [rawMessages, showJoinPart, blockedDids, blockedNicks, activeMembers]);

  // In-thread blocked indicator: a blocked peer's thread is hidden from the
  // sidebar but still reachable (quick switcher), and their messages are
  // filtered — without a banner the history just looks silently one-sided.
  const allChannels = useStore((s) => s.channels);
  const peerBlocked =
    activeChannel !== 'server' &&
    !activeChannel.startsWith('#') &&
    !activeChannel.startsWith('&') &&
    isPeerBlocked(allChannels, activeChannel, blockedNicks, blockedDids,
      (did) => getClient()?.getNickForDid(did));

  const lastReadMsgId = useStore((s) => s.channels.get(s.activeChannel.toLowerCase())?.lastReadMsgId);
  const pins = useStore((s) => s.channels.get(s.activeChannel.toLowerCase())?.pins ?? EMPTY_PINS);
  const density = useStore((s) => s.messageDensity);
  const ref = useRef<HTMLDivElement>(null);
  const stickToBottomRef = useRef(true);
  const [showScrollBtn, setShowScrollBtn] = useState(false);
  const [newMsgCount, setNewMsgCount] = useState(0);
  const [popover, setPopover] = useState<{ nick: string; did?: string; origin?: string; pos: { x: number; y: number } } | null>(null);

  // Track whether user has scrolled up (unstick from bottom)
  const handleScroll = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    stickToBottomRef.current = atBottom;
    setShowScrollBtn(!atBottom);
    if (atBottom) setNewMsgCount(0);
  }, []);

  // Scroll to bottom when messages change (if stuck to bottom), or count new messages
  const prevLenRef = useRef(messages.length);
  useEffect(() => {
    const added = messages.length - prevLenRef.current;
    prevLenRef.current = messages.length;
    if (!stickToBottomRef.current) {
      if (added > 0) setNewMsgCount((c) => c + added);
      return;
    }
    const scrollBottom = () => {
      if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
    };
    // Double RAF ensures layout is complete after React render
    requestAnimationFrame(() => requestAnimationFrame(scrollBottom));
  }, [messages.length, messages]);

  // Always scroll to bottom on channel switch
  // Multiple timers to catch: initial render, layout, CHATHISTORY load
  useEffect(() => {
    stickToBottomRef.current = true;
    setShowScrollBtn(false);
    setNewMsgCount(0);
    prevLenRef.current = 0;
    const scrollBottom = () => {
      if (ref.current) {
        ref.current.scrollTop = ref.current.scrollHeight;
        stickToBottomRef.current = true;
      }
    };
    scrollBottom();
    requestAnimationFrame(() => requestAnimationFrame(scrollBottom));
    const t1 = setTimeout(scrollBottom, 100);
    const t2 = setTimeout(scrollBottom, 300);
    const t3 = setTimeout(scrollBottom, 600); // after CHATHISTORY arrives
    const t4 = setTimeout(scrollBottom, 1200); // slow networks

    // DM buffers don't get NAMES/366 so history isn't auto-fetched.
    // Always request on activation (dedup handles duplicates).
    const isDM = activeChannel !== 'server' && !activeChannel.startsWith('#') && !activeChannel.startsWith('&');
    if (isDM) {
      requestHistory(activeChannel);
    }

    return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); clearTimeout(t4); };
  }, [activeChannel]);

  // Combined scroll handler: track stick-to-bottom + load history on scroll-to-top
  const onScroll = useCallback(() => {
    handleScroll();
    const el = ref.current;
    if (!el || el.scrollTop > 50) return;
    if (activeChannel !== 'server' && messages.length > 0) {
      const oldest = messages[0];
      if (!oldest.isSystem) {
        requestHistory(activeChannel, oldest.timestamp.toISOString());
      }
    }
  }, [activeChannel, messages, handleScroll]);

  // Clean block-copy: when a selection spans ≥2 message rows, rewrite the
  // clipboard to a tidy `Name: message` transcript instead of the raw DOM
  // text (which drags in timestamps, badges, reaction pills). A partial
  // selection inside a single message is left to the native copy.
  const handleCleanCopy = useCallback((e: React.ClipboardEvent) => {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed || !ref.current) return;
    const rows = Array.from(ref.current.querySelectorAll<HTMLElement>('[id^="msg-"]'))
      .filter((n) => sel.containsNode(n, true));
    if (rows.length < 2) return; // single/partial selection → native copy
    const ids = new Set(rows.map((n) => n.id.slice(4))); // strip "msg-"
    const selected = messages.filter((m) => ids.has(m.id));
    const transcript = buildTranscript(selected, (nick) => displayNameForKey(nick));
    if (!transcript) return;
    e.clipboardData.setData('text/plain', transcript);
    e.preventDefault();
  }, [messages]);

  // Scroll to a specific message (from search, reply click, etc.)
  const scrollToMsgId = useStore((s) => s.scrollToMsgId);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  useEffect(() => {
    if (!scrollToMsgId) return;
    useStore.getState().setScrollToMsgId(null);
    // Wait for render, then scroll
    requestAnimationFrame(() => {
      const el = document.getElementById(`msg-${scrollToMsgId}`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setHighlightId(scrollToMsgId);
        setTimeout(() => setHighlightId(null), 2000);
      }
    });
  }, [scrollToMsgId]);

  // Show brief skeleton on channel switch while CHATHISTORY loads
  const [showSkeleton, setShowSkeleton] = useState(false);
  useEffect(() => {
    if (activeChannel === 'server') return;
    setShowSkeleton(true);
    const t = setTimeout(() => setShowSkeleton(false), 600);
    return () => clearTimeout(t);
  }, [activeChannel]);

  const onNickClick = useCallback((nick: string, did: string | undefined, origin: string | undefined, e: React.MouseEvent) => {
    setPopover({ nick, did, origin, pos: { x: e.clientX, y: e.clientY } });
  }, []);

  return (
    <div key={activeChannel} ref={ref} data-testid="message-list" role="log" aria-label={`Messages in ${activeChannel}`} aria-live="polite" className={`flex-1 overflow-y-auto relative ${
      density === 'compact' ? 'text-[14px] [&_.msg-full]:pt-1.5 [&_.msg-full]:pb-0' :
      density === 'cozy' ? 'text-[16px] [&_.msg-full]:pt-4 [&_.msg-full]:pb-2' : ''
    }`} onScroll={onScroll} onCopy={handleCleanCopy}>
      {activeChannel.startsWith('#') && pins.length > 0 && (
        <div className="sticky top-0 z-10">
          <PinnedBar pins={pins} messages={messages} />
        </div>
      )}
      {peerBlocked && (
        <div className="sticky top-0 z-10 px-4 py-2 bg-danger/10 border-b border-danger/30 text-sm text-fg-muted flex items-center justify-between gap-2">
          <span>
            You've blocked <span className="font-semibold">{displayNameForKey(activeChannel)}</span> — their messages are hidden.
          </span>
          <button
            className="text-danger hover:underline shrink-0 text-xs"
            onClick={() => {
              const s = useStore.getState();
              s.unblockUser(activeChannel);
              const peerNick = getClient()?.getNickForDid(activeChannel);
              if (peerNick) s.unblockUser(peerNick);
            }}
          >
            Unblock
          </button>
        </div>
      )}
      {messages.length === 0 && showSkeleton && activeChannel !== 'server' && (
        <div className="px-4 pt-4 space-y-4 animate-pulse">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="flex gap-3">
              <div className="w-10 h-10 rounded-full bg-surface shrink-0" />
              <div className="flex-1 space-y-2 pt-1">
                <div className="flex gap-2">
                  <div className="h-3 w-20 bg-surface rounded" />
                  <div className="h-3 w-12 bg-surface/50 rounded" />
                </div>
                <div className="h-3 bg-surface/70 rounded" style={{ width: `${40 + Math.random() * 50}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
      {messages.length === 0 && !showSkeleton && (
        <div className="flex flex-col items-center justify-center h-full text-fg-dim px-8">
          <img src="/freeq.png" alt="freeq" className="w-14 h-14 mb-4 opacity-20" />
          {activeChannel === 'server' ? (
            <>
              <div className="text-base text-fg-muted font-medium">Welcome to freeq</div>
              <div className="text-sm mt-1 text-center">Server messages and notices will appear here.</div>
              <div className="text-xs mt-3 text-center space-y-1">
                <div><kbd className="px-1.5 py-0.5 text-xs bg-bg-tertiary border border-border rounded font-mono">⌘K</kbd> Quick switch · <kbd className="px-1.5 py-0.5 text-xs bg-bg-tertiary border border-border rounded font-mono">⌘/</kbd> Shortcuts</div>
              </div>
            </>
          ) : activeChannel.startsWith('#') ? (
            <ChannelEmptyState channel={activeChannel} />
          ) : (
            <>
              <div className="text-3xl mb-2">💬</div>
              <div className="text-xl text-fg font-bold" title={isDid(activeChannel) ? activeChannel : undefined}>
                Conversation with {displayNameForKey(activeChannel)}
              </div>
              <div className="text-sm mt-2 text-center max-w-xs leading-relaxed text-fg-dim">
                Direct messages are private between you and <span className="text-fg-muted">{displayNameForKey(activeChannel)}</span>.
              </div>
            </>
          )}
        </div>
      )}
      <div className="pb-2">
        {messages.map((msg, i) => {
          // Collapse consecutive join/part/quit system messages
          const isJoinPart = msg.isSystem && /^.+ (joined|left)$/.test(msg.text);
          if (isJoinPart) {
            // Skip if the previous message was also a join/part (we'll render them as a group)
            const prev = i > 0 ? messages[i - 1] : null;
            const prevIsJP = prev?.isSystem && /^.+ (joined|left)$/.test(prev.text);
            const next = i < messages.length - 1 ? messages[i + 1] : null;
            const nextIsJP = next?.isSystem && /^.+ (joined|left)$/.test(next.text);
            if (prevIsJP) return null; // skip — rendered by the first in the group
            if (nextIsJP) {
              // First in a group — collect all consecutive
              const group: Message[] = [msg];
              for (let j = i + 1; j < messages.length; j++) {
                const m = messages[j];
                if (m.isSystem && /^.+ (joined|left)$/.test(m.text)) group.push(m);
                else break;
              }
              const joins = group.filter(m => m.text.endsWith(' joined')).map(m => m.text.replace(' joined', ''));
              const parts = group.filter(m => m.text.endsWith(' left')).map(m => m.text.replace(' left', ''));
              const parts_list: string[] = [];
              if (joins.length > 0) parts_list.push(`${joins.slice(0, 3).join(', ')}${joins.length > 3 ? ` and ${joins.length - 3} more` : ''} joined`);
              if (parts.length > 0) parts_list.push(`${parts.slice(0, 3).join(', ')}${parts.length > 3 ? ` and ${parts.length - 3} more` : ''} left`);
              return (
                <div key={msg.id} id={`msg-${msg.id}`} className="px-4 py-0.5 flex items-start gap-3">
                  <span className="w-10 shrink-0" />
                  <span className="text-fg-dim text-xs opacity-60">— {parts_list.join('; ')}</span>
                </div>
              );
            }
          }
          return (
          <div key={msg.id} id={`msg-${msg.id}`} className={highlightId === msg.id ? 'bg-accent/10 transition-colors duration-1000' : ''}>
            {lastReadMsgId && i > 0 && messages[i - 1].id === lastReadMsgId && !msg.isSelf && (
              <div className="flex items-center gap-3 px-4 my-3" id="unread-marker">
                <div className="flex-1 h-px bg-danger/40" />
                <span className="text-xs font-bold text-danger/70 uppercase tracking-wider">New</span>
                <div className="flex-1 h-px bg-danger/40" />
              </div>
            )}
            {shouldShowDateSep(messages, i) && <DateSeparator date={msg.timestamp} />}
            {msg.deleted ? (
              <div className="px-4 py-0.5 text-xs italic text-[var(--text-muted)] opacity-50">
                Message from {displayNameForKey(msg.from)} deleted
              </div>
            ) : msg.isSystem ? (
              <SystemMessage msg={msg} />
            ) : isGrouped(messages, i) ? (
              <GroupedMessage msg={msg} channel={activeChannel} onNickClick={onNickClick} />
            ) : (
              <FullMessage msg={msg} channel={activeChannel} onNickClick={onNickClick} />
            )}
          </div>
          );
        })}
        <TypingIndicatorBar channel={activeChannel} />
      </div>

      {/* Scroll to bottom button */}
      {showScrollBtn && (
        <button
          onClick={() => {
            if (ref.current) {
              ref.current.scrollTop = ref.current.scrollHeight;
              stickToBottomRef.current = true;
              setShowScrollBtn(false);
            }
          }}
          className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-bg-secondary border border-border rounded-full px-4 py-2 shadow-xl flex items-center gap-2 text-sm text-fg-muted hover:text-fg hover:border-accent transition-all z-10 animate-fadeIn"
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="currentColor">
            <path fillRule="evenodd" d="M8 1a.5.5 0 01.5.5v11.793l3.146-3.147a.5.5 0 01.708.708l-4 4a.5.5 0 01-.708 0l-4-4a.5.5 0 01.708-.708L7.5 13.293V1.5A.5.5 0 018 1z"/>
          </svg>
          {newMsgCount > 0 ? `${newMsgCount} new message${newMsgCount === 1 ? '' : 's'}` : 'Jump to bottom'}
        </button>
      )}

      {popover && (
        <UserPopover
          nick={popover.nick}
          did={popover.did}
          origin={popover.origin}
          position={popover.pos}
          onClose={() => setPopover(null)}
        />
      )}
    </div>
  );
}
