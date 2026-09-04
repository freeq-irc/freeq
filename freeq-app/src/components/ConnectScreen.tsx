import { useState, useRef, useEffect, useCallback } from 'react';
import { connect, setSaslCredentials } from '../irc/client';
import { useStore } from '../store';

type LoginMode = 'at-proto' | 'guest';

function AuthStep({ done, active, label }: { done?: boolean; active?: boolean; label: string }) {
  return (
    <div className={`flex items-center gap-2 text-[11px] ${done ? 'text-success' : active ? 'text-fg-muted' : 'text-fg-dim/40'}`}>
      {done ? (
        <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 16 16" fill="currentColor">
          <path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z" />
        </svg>
      ) : active ? (
        <svg className="w-3.5 h-3.5 shrink-0 animate-spin" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="8" cy="8" r="6" strokeDasharray="28" strokeDashoffset="8" strokeLinecap="round" />
        </svg>
      ) : (
        <div className="w-3.5 h-3.5 shrink-0 rounded-full border border-current opacity-30" />
      )}
      <span>{label}</span>
    </div>
  );
}

function friendlyError(error: string): string {
  if (error.includes('SASL authentication failed'))
    return 'Could not verify your identity. Make sure your handle is correct and try again.';
  if (error.includes('Too many SASL failures'))
    return 'Too many login attempts. Please wait a moment and try again.';
  if (error.includes('unavailable'))
    return 'The identity service is starting up. This usually takes a few seconds — please try again.';
  if (error.includes('502') || error.includes('Bad Gateway'))
    return 'The identity service is temporarily unavailable. Try again in a few seconds.';
  if (error.includes('timeout') || error.includes('Timeout'))
    return 'The connection timed out. Check your internet connection and try again.';
  if (error.includes('Nick') && error.includes('registered'))
    return 'That nickname is registered to another user. Sign in with AT Protocol to reclaim it, or choose a different nick.';
  if (error.includes('OAuth'))
    return 'The Bluesky authorization was cancelled or failed. Please try again.';
  if (error.includes('WebSocket') || error.includes('websocket'))
    return 'Could not connect to the server. Check your internet connection.';
  return error;
}

// Module-level flags survive ConnectScreen remounts
let brokerAutoAttempts = 0;
const MAX_BROKER_AUTO_ATTEMPTS = 3;
// Synchronous guard: prevents broker effect from racing with OAuth result effect
let oauthConnectInProgress = false;
/**
 * One session restore per load, not one per effect invocation.
 *
 * React StrictMode double-invokes effects in development, and `brokerAutoAttempts`
 * does not stop it: both invocations run before either increments past the
 * limit, so the app fires two POST /session calls for one page load. Each one
 * rotates a single-use AT Protocol refresh token upstream, and racing that
 * rotation is what bricked persistent sessions until 2026-07-03. The broker
 * serialises callers now, so this is no longer a correctness bug — but two PDS
 * round-trips per load is still waste, and it is the precondition the race
 * needed. Reported in #33 by an outside contributor before any of it happened.
 *
 * Module-level, matching `oauthConnectInProgress` above: a ref would be
 * per-component-instance, and StrictMode's second instance is exactly the
 * caller being guarded against.
 */
let sessionRefreshInFlight = false;

/**
 * Is this shaped like an AT Protocol handle — that is, a domain?
 *
 * Deliberately loose: the server's `is_valid_handle` is the authority, and a
 * client that rejects something the server would have accepted is worse than
 * one that lets a doomed request through. This only catches what is certainly
 * wrong (no dot, spaces, a URL someone pasted) so the user is told here
 * instead of on a page they cannot get back from.
 */
function isProbablyHandle(h: string): boolean {
  if (h.length > 253 || /[\s/@:\\?#]/.test(h)) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  return labels.every((l) => l.length >= 1 && l.length <= 63 && /^[a-zA-Z0-9-]+$/.test(l) && !l.startsWith('-') && !l.endsWith('-'));
}

type OAuthResultData = {
  did?: string;
  handle?: string;
  token?: string;
  web_token?: string;
  access_jwt?: string;
  broker_token?: string;
  pds_url?: string;
};

type BrokerSessionResponse = {
  token: string;
  nick: string;
  did: string;
  handle: string;
};

// Default AT Protocol hosting suffixes — strip these to get short nick
const DEFAULT_SUFFIXES = [
  '.bsky.social',
  '.bsky.app',
  '.bsky.team',
  '.bsky.network',
  '.atproto.com',
];

/** Derive an IRC nick from an AT Protocol handle.
 * Custom domains (e.g. chadfowler.com) → use full handle as nick.
 * Default hosting (e.g. chad.bsky.social) → strip suffix → "chad".
 */
function nickFromHandle(handle: string): string {
  const h = handle.toLowerCase().trim();
  for (const suffix of DEFAULT_SUFFIXES) {
    if (h.endsWith(suffix)) {
      return h.slice(0, -suffix.length);
    }
  }
  // Custom domain — use the full handle as nick
  return h;
}

// localStorage keys
const LS_HANDLE = 'freeq-handle';
const LS_CHANNELS = 'freeq-channels';
const LS_BROKER_TOKEN = 'freeq-broker-token';
const LS_BROKER_BASE = 'freeq-broker-base';

export function ConnectScreen() {
  const registered = useStore((s) => s.registered);
  const connectionState = useStore((s) => s.connectionState);
  const authError = useStore((s) => s.authError);

  const [mode, setMode] = useState<LoginMode>('at-proto');
  const [handle, setHandle] = useState(() => localStorage.getItem(LS_HANDLE) || '');
  const [nick, setNick] = useState(() => 'web' + Math.floor(Math.random() * 99999));
  const [atNick, setAtNick] = useState(''); // derived nick for AT login, editable
  const [channels, setChannels] = useState(() => {
    // Check for auto-join from invite link (e.g. #auto-join=#channel)
    const hash = window.location.hash;
    if (hash.startsWith('#auto-join=')) {
      const ch = decodeURIComponent(hash.slice('#auto-join='.length));
      window.location.hash = '';
      const existing = localStorage.getItem(LS_CHANNELS) || '';
      const merged = new Set(existing.split(',').map(s => s.trim()).filter(Boolean));
      merged.add(ch);
      const result = [...merged].join(',');
      // Persist through OAuth redirect
      localStorage.setItem(LS_CHANNELS, result);
      return result;
    }
    return localStorage.getItem(LS_CHANNELS) || '#freeq';
  });
  const isTauri = !!(window as any).__TAURI_INTERNALS__;
  const [server, setServer] = useState(() => {
    if (isTauri) return 'wss://irc.freeq.at/irc';
    const loc = window.location;
    const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
    // In dev, replace localhost with 127.0.0.1 for OAuth compliance
    const host = loc.host.replace('localhost', '127.0.0.1');
    return `${proto}//${host}/irc`;
  });
  const [webOrigin, setWebOrigin] = useState(() => {
    if (isTauri) return 'https://irc.freeq.at';
    const loc = window.location;
    const host = loc.host.replace('localhost', '127.0.0.1');
    return `${loc.protocol}//${host}`;
  });
  const [brokerOrigin] = useState(() => {
    const stored = localStorage.getItem(LS_BROKER_BASE);
    if (stored) return stored;
    if (isTauri) return 'https://auth.freeq.at';
    const host = window.location.host;
    if (host === 'irc.freeq.at') return 'https://auth.freeq.at';
    return webOrigin;
  });
  const [error, setError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [oauthPending, setOauthPending] = useState(false);
  const [autoConnecting, setAutoConnecting] = useState(false);
  const handleRef = useRef<HTMLInputElement>(null);
  const nickRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (mode === 'at-proto') handleRef.current?.focus();
    else nickRef.current?.focus();
  }, [mode]);

  // Update derived nick when handle changes
  useEffect(() => {
    if (handle.trim()) {
      setAtNick(nickFromHandle(handle.trim()));
    }
  }, [handle]);

  // Check for OAuth result on mount (same-window redirect flow for Tauri/desktop).
  // The callback page stores the result in localStorage and redirects to /.
  // No "pending" flag needed — if a result exists, consume it.
  useEffect(() => {
    const hash = window.location.hash;
    if (hash.startsWith('#oauth=')) {
      const payload = hash.slice('#oauth='.length);
      try {
        const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        // Inject _ts so the staleness check below knows when we received the result
        const parsed = JSON.parse(json);
        parsed._ts = Date.now();
        localStorage.setItem('freeq-oauth-result', JSON.stringify(parsed));
      } catch { /* ignore */ }
      window.location.hash = '';
    }

    const raw = localStorage.getItem('freeq-oauth-result');
    if (!raw) return;
    localStorage.removeItem('freeq-oauth-result');
    localStorage.removeItem('freeq-oauth-pending');
    try {
      const result = JSON.parse(raw) as OAuthResultData & { _ts?: number };
      // Reject stale OAuth results (>30 minutes old) — prevents auto-connect
      // with consumed web-tokens from previous sessions
      const age = result._ts ? Date.now() - result._ts : Infinity;
      if (age > 30 * 60 * 1000) return;
      if (result?.did) {
        if (result.broker_token) {
          localStorage.setItem(LS_BROKER_TOKEN, result.broker_token);
          localStorage.setItem(LS_BROKER_BASE, brokerOrigin);
        }
        // Set synchronous flag BEFORE async state update — prevents broker
        // effect from also calling connect() in the same render cycle.
        oauthConnectInProgress = true;
        setAutoConnecting(true);
        const h = localStorage.getItem(LS_HANDLE) || result.handle || '';
        // Use saved joined channels if available (reflects actual PART/JOIN state),
        // otherwise fall back to the saved channels from connect screen input.
        const savedJoined = localStorage.getItem('freeq-joined-channels');
        const ch = savedJoined
          ? JSON.parse(savedJoined)
          : (localStorage.getItem(LS_CHANNELS) || '#freeq').split(',').map(s => s.trim()).filter(Boolean);
        const finalNick = nickFromHandle(result.handle || h);
        const token = result.web_token || result.token || result.access_jwt || '';
        setSaslCredentials(token, result.did, result.pds_url || '', 'web-token');
        const loc = window.location;
        const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = loc.host.replace('localhost', '127.0.0.1');
        connect(`${proto}//${host}/irc`, finalNick, ch);
      }
    } catch { /* ignore parse errors */ }
  }, [brokerOrigin]);

  // Attempt broker session refresh on load (persistent login)
  useEffect(() => {
    if (registered || oauthPending || autoConnecting) return;
    // Synchronous check: if OAuth result effect already called connect(), skip
    if (oauthConnectInProgress) return;
    if (brokerAutoAttempts >= MAX_BROKER_AUTO_ATTEMPTS) return;
    if (sessionRefreshInFlight) return;
    const brokerToken = localStorage.getItem(LS_BROKER_TOKEN);
    if (!brokerToken) return;
    // Refresh via `${brokerOrigin}/session` regardless of deployment: for a
    // standalone broker brokerOrigin is the separate auth host; for an embedded
    // server it equals webOrigin (the server serves /session in-process). A
    // stale/cross-server token simply 401s below and is cleared there.

    brokerAutoAttempts++;
    sessionRefreshInFlight = true;
    setAutoConnecting(true);
    // Use saved joined channels if available (reflects actual PART/JOIN state),
    // otherwise fall back to the saved channels from connect screen input.
    const savedJoined = localStorage.getItem('freeq-joined-channels');
    const ch = savedJoined
      ? JSON.parse(savedJoined)
      : (localStorage.getItem(LS_CHANNELS) || '#freeq').split(',').map(s => s.trim()).filter(Boolean);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const brokerBody = JSON.stringify({ broker_token: brokerToken });
    const doFetch = () => fetch(`${brokerOrigin}/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: brokerBody,
      signal: controller.signal,
    });
    doFetch()
      .then(async (res) => {
        clearTimeout(timeout);
        // Retry once on 502 (DPoP nonce rotation causes first call to fail)
        if (res.status === 502) {
          const r2 = await doFetch();
          if (!r2.ok) throw new Error(await r2.text());
          return r2.json();
        }
        // 401 = broker token is genuinely invalid/expired — only then remove it.
        // Tagged, because the catch below has to tell "your session ended, sign
        // in again" apart from "the network is having a moment": one is final
        // and the user must act, the other resolves itself on a retry.
        if (res.status === 401) {
          localStorage.removeItem(LS_BROKER_TOKEN);
          const err = new Error(await res.text());
          err.name = 'SessionExpired';
          throw err;
        }
        if (!res.ok) throw new Error(await res.text());
        return res.json();
      })
      .then((session: BrokerSessionResponse) => {
        localStorage.setItem(LS_HANDLE, session.handle || localStorage.getItem(LS_HANDLE) || '');
        setSaslCredentials(session.token, session.did, '', 'web-token');
        const finalNick = nickFromHandle(session.handle || localStorage.getItem(LS_HANDLE) || session.nick);
        connect(server, finalNick, ch);
      })
      .catch((e) => {
        clearTimeout(timeout);
        // Don't remove broker token on transient errors (timeout, 502, network).
        // Only removed above on explicit 401.
        setAutoConnecting(false);

        // A dead session is final: the token is gone, so retrying cannot
        // succeed, and saying nothing drops the user on the sign-in form with
        // no idea why they were signed out. That silence is the whole
        // complaint in #33 and #71 — it reads as "the app forgot me" and the
        // user has nothing to report.
        if (e?.name === 'SessionExpired') {
          brokerAutoAttempts = MAX_BROKER_AUTO_ATTEMPTS;
          setError('Your session expired. Sign in with AT Protocol again, or connect as guest.');
          return;
        }
        if (brokerAutoAttempts < MAX_BROKER_AUTO_ATTEMPTS) {
          // Retry with backoff
          const delay = 2000 * brokerAutoAttempts;
          setTimeout(() => setAutoConnecting(false), delay); // triggers re-run of this effect
          return;
        }
        // Out of retries. Whatever went wrong, say something — an unexplained
        // sign-in form is the failure users cannot report.
        setError(
          e?.name === 'AbortError'
            ? 'Authentication service unavailable. Try again or connect as guest.'
            : 'Could not restore your session. Try again or connect as guest.',
        );
      })
      // Released however it settles: a guard that leaks on failure would block
      // every later attempt, turning one bad response into a permanent one.
      .finally(() => {
        sessionRefreshInFlight = false;
      });
  }, [registered, oauthPending, autoConnecting, brokerOrigin, server]);

  // Clear autoConnecting on auth failure or disconnect
  useEffect(() => {
    if (!autoConnecting) return;
    if (registered) { setAutoConnecting(false); brokerAutoAttempts = 0; oauthConnectInProgress = false; return; }
    if (authError) { setAutoConnecting(false); oauthConnectInProgress = false; return; }
    // If we were connecting but dropped back to disconnected, give a brief grace period
    // then show the form. This prevents a permanent spinner if SASL fails.
    if (connectionState === 'disconnected') {
      const t = setTimeout(() => setAutoConnecting(false), 2000);
      return () => clearTimeout(t);
    }
  }, [autoConnecting, registered, connectionState, authError]);

  const chans = channels.split(',').map((s) => s.trim()).filter(Boolean);

  // AT Protocol OAuth login
  const doAtLogin = useCallback(async () => {
    const h = handle.trim().replace(/^@/, '');
    if (!h) { setError('Enter your AT Protocol handle'); return; }
    // Catch an obvious typo here rather than after a navigation. Signing in
    // leaves the app for the PDS, so a handle the server cannot resolve used
    // to land the user on a bare error page with no way back — on the single
    // most common first-run mistake there is. The server still validates;
    // this only stops the trip.
    if (!isProbablyHandle(h)) {
      setError(`"${h}" doesn't look like an AT Protocol handle. Handles are domains, like you.bsky.social.`);
      return;
    }
    setError('');
    setOauthPending(true);

    try {
      // Persist handle + channels for next visit
      localStorage.setItem(LS_HANDLE, h);
      localStorage.setItem(LS_CHANNELS, channels);
      localStorage.setItem(LS_BROKER_BASE, brokerOrigin);

      // Clear any stale OAuth result
      try { localStorage.removeItem('freeq-oauth-result'); } catch { /* ignore */ }

      // Use webOrigin for auth URLs (same-origin in browser, explicit server in Tauri)
      const baseAuthUrl = `${brokerOrigin}/auth/login?handle=${encodeURIComponent(h)}`;
      const authUrl = `${baseAuthUrl}&return_to=${encodeURIComponent(window.location.origin)}`;

      // Pre-flight check: verify broker is reachable before redirecting
      const check = await fetch(`${brokerOrigin}/health`, { signal: AbortSignal.timeout(5000) }).catch(() => null);
      if (!check?.ok) {
        setError('Authentication service unavailable. Try again later or connect as guest.');
        setOauthPending(false);
        return;
      }

      // Same-window flow (more reliable than popup in browsers)
      localStorage.setItem('freeq-oauth-pending', '1');
      window.location.href = authUrl;
      return;
    } catch (e) {
      setError(`OAuth error: ${e}`);
      setOauthPending(false);
    }
  }, [handle, server, channels, atNick, chans]);

  // Guest login (no AT auth)
  const doGuestLogin = () => {
    if (!nick.trim()) { setError('Enter a nickname'); return; }
    setError('');
    // Persist the channel input for next visit (doAtLogin does the same).
    localStorage.setItem(LS_CHANNELS, channels);
    // Use saved joined channels if available (reflects actual PART/JOIN state),
    // otherwise fall back to what's typed in the connect screen input.
    const savedJoined = localStorage.getItem('freeq-joined-channels');
    const ch = savedJoined
      ? JSON.parse(savedJoined)
      : (channels || '#freeq').split(',').map(s => s.trim()).filter(Boolean);
    connect(server, nick.trim(), ch);
  };

  const connecting = connectionState === 'connecting' || connectionState === 'connected';
  const displayError = error || authError;

  // Early returns MUST come after all hooks (React rules of hooks)
  if (registered) return null;

  if (autoConnecting || oauthPending) {
    return (
      <div className="flex-1 flex items-center justify-center bg-bg">
        <div className="text-center">
          <img src="/freeq.png" alt="freeq" className="w-16 h-16 mx-auto mb-4 animate-pulse" />
          <h1 className="text-2xl font-bold mb-2">
            <span className="text-accent">free</span><span className="text-fg">q</span>
          </h1>
          <p className="text-fg-dim text-sm">
            {oauthPending
              ? 'Waiting for Bluesky authorization...'
              : 'Connecting to identity provider...'}
          </p>
          <div className="mt-3 space-y-1.5 text-left max-w-[200px] mx-auto">
            <AuthStep done label="Resolving identity" />
            <AuthStep done={!oauthPending} active={oauthPending} label={oauthPending ? 'Authorize in popup' : 'Verifying credentials'} />
            <AuthStep active={!oauthPending} label="Establishing session" />
          </div>
          {authError && (
            <p className="text-danger text-xs mt-3">{authError}</p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex items-center justify-center bg-bg relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-accent/[0.03] rounded-full blur-[100px]" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple/[0.03] rounded-full blur-[100px]" />
      </div>

      <div className="bg-bg-secondary border border-border rounded-2xl p-8 w-[420px] max-w-[92vw] shadow-2xl relative animate-fadeIn">
        {/* Logo */}
        <div className="text-center mb-6">
          <img src="/freeq.png" alt="freeq" className="w-16 h-16 mx-auto mb-2" />
          <h1 className="text-3xl font-bold tracking-tight">
            <span className="text-accent">free</span><span className="text-fg">q</span>
          </h1>
          <p className="text-fg-dim text-xs mt-1 leading-relaxed max-w-[300px] mx-auto">
            Chat where your identity is yours. Messages are cryptographically signed.
            No platform lock-in. E2EE DMs.
          </p>
          <div className="flex justify-center gap-4 mt-2.5 text-[10px] text-fg-dim">
            <span className="flex items-center gap-1">
              <span className="text-success">✓</span> Signed messages
            </span>
            <span className="flex items-center gap-1">
              <span className="text-success">🔒</span> E2EE DMs
            </span>
            <span className="flex items-center gap-1">
              <span className="text-accent">🦋</span> AT Protocol identity
            </span>
          </div>
        </div>

        {/* Mode tabs */}
        <div className="flex gap-1 bg-bg rounded-lg p-1 mb-4">
          <button
            onClick={() => setMode('at-proto')}
            className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-colors ${
              mode === 'at-proto'
                ? 'bg-accent/10 text-accent'
                : 'text-fg-dim hover:text-fg-muted'
            }`}
          >
            AT Protocol
          </button>
          <button
            onClick={() => setMode('guest')}
            className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-colors ${
              mode === 'guest'
                ? 'bg-bg-tertiary text-fg-muted'
                : 'text-fg-dim hover:text-fg-muted'
            }`}
          >
            Guest
          </button>
        </div>

        <div className="space-y-3">
          {mode === 'at-proto' ? (
            <>
              {/* AT Handle */}
              <div>
                <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
                  AT Protocol Handle
                </label>
                <input
                  ref={handleRef}
                  value={handle}
                  onChange={(e) => setHandle(e.target.value)}
                  placeholder="you.bsky.social"
                  onKeyDown={(e) => e.key === 'Enter' && doAtLogin()}
                  className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors placeholder:text-fg-dim"
                />
              </div>

              {/* Derived nick (editable) */}
              <div>
                <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
                  Nickname
                </label>
                <input
                  value={atNick}
                  onChange={(e) => setAtNick(e.target.value)}
                  placeholder="derived from handle"
                  onKeyDown={(e) => e.key === 'Enter' && doAtLogin()}
                  className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors placeholder:text-fg-dim"
                />
                <p className="text-xs text-fg-dim mt-1.5">
                  Your IRC nick. Defaults to your handle — edit if you prefer something different.
                </p>
              </div>
            </>
          ) : (
            <>
              {/* Nick */}
              <div>
                <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
                  Nickname
                </label>
                <input
                  ref={nickRef}
                  value={nick}
                  onChange={(e) => setNick(e.target.value)}
                  placeholder="your_nick"
                  onKeyDown={(e) => e.key === 'Enter' && doGuestLogin()}
                  className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors placeholder:text-fg-dim"
                />
              </div>
            </>
          )}

          {/* Channels */}
          <div>
            <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
              Auto-join channels
            </label>
            <input
              value={channels}
              onChange={(e) => setChannels(e.target.value)}
              placeholder="#freeq"
              onKeyDown={(e) => e.key === 'Enter' && (mode === 'at-proto' ? doAtLogin() : doGuestLogin())}
              className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors placeholder:text-fg-dim"
            />
          </div>

          {/* Advanced */}
          {showAdvanced && (
            <div className="animate-fadeIn space-y-3">
              <div>
                <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
                  WebSocket URL
                </label>
                <input
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
                  className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors font-mono text-xs placeholder:text-fg-dim"
                />
              </div>
              <div>
                <label className="block text-xs uppercase tracking-wider text-fg-dim font-bold mb-2">
                  Server HTTP Origin
                </label>
                <input
                  value={webOrigin}
                  onChange={(e) => setWebOrigin(e.target.value)}
                  className="w-full bg-bg border border-border rounded-lg px-4 py-3 text-base text-fg outline-none focus:border-accent transition-colors font-mono text-xs placeholder:text-fg-dim"
                />
                <p className="text-xs text-fg-dim mt-1.5">
                  HTTP origin of the freeq server (for OAuth). Must match --web-addr.
                </p>
              </div>
            </div>
          )}

          {!showAdvanced && (
            <button
              onClick={() => setShowAdvanced(true)}
              className="text-[11px] text-fg-dim hover:text-fg-muted"
            >
              Advanced settings ›
            </button>
          )}

          {/* Consent preview — show what we're asking Bluesky for BEFORE
              redirecting, so the consent screen there is no surprise. */}
          {mode === 'at-proto' && !oauthPending && !connecting && (
            <div className="bg-bg/50 border border-border/60 rounded-lg px-3 py-2.5 text-[11px] leading-relaxed text-fg-dim">
              <div className="font-semibold text-fg-muted mb-1">
                What freeq will ask Bluesky for
              </div>
              <ul className="space-y-0.5 list-disc list-inside marker:text-fg-dim/60">
                <li>Prove you are <span className="font-mono">@{handle || 'your.handle'}</span></li>
              </ul>
              <div className="mt-1.5 text-fg-dim/80">
                That's it for sign-in. Image upload to your PDS asks for one
                extra permission, only the first time you upload — never up
                front.
              </div>
            </div>
          )}

          {/* Connect button */}
          <button
            onClick={mode === 'at-proto' ? doAtLogin : doGuestLogin}
            disabled={connecting || oauthPending}
            className="w-full bg-accent text-black font-bold py-3 rounded-xl text-lg transition-all hover:bg-accent-hover hover:shadow-[0_0_24px_rgba(0,212,170,0.15)] disabled:opacity-50 disabled:hover:shadow-none mt-1"
          >
            {oauthPending ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Waiting for authorization...
              </span>
            ) : connecting ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Connecting...
              </span>
            ) : mode === 'at-proto' ? (
              'Sign in with AT Protocol'
            ) : (
              'Connect as Guest'
            )}
          </button>
        </div>

        {displayError && (
          <div className="mt-3 bg-danger/10 border border-danger/20 rounded-lg px-3 py-2.5 text-xs animate-fadeIn">
            <div className="font-semibold text-danger mb-0.5">
              {displayError.includes('SASL') || displayError.includes('auth') || displayError.includes('Auth')
                ? '🔑 Authentication Error'
                : displayError.includes('unavailable') || displayError.includes('timeout') || displayError.includes('502')
                  ? '🌐 Connection Error'
                  : '⚠️ Error'}
            </div>
            <div className="text-danger/80">
              {friendlyError(displayError)}
            </div>
          </div>
        )}

        <div className="text-center mt-5 flex items-center justify-center gap-3 text-[10px]">
          <a href="https://freeq.at" target="_blank" className="text-fg-dim hover:text-fg-muted">freeq.at</a>
          <span className="text-border">·</span>
          <a href="https://github.com/freeq-irc/freeq" target="_blank" className="text-fg-dim hover:text-fg-muted">GitHub</a>
          <span className="text-border">·</span>
          <a href="https://www.freeq.at/docs/" target="_blank" rel="noopener noreferrer" className="text-fg-dim hover:text-fg-muted">Docs</a>
        </div>

        {/* Live social proof */}
        <ServerStats />
      </div>
    </div>
  );
}

/**
 * Wait for OAuth result from popup window.
 * Tries BroadcastChannel, postMessage, and localStorage polling.
 */
function ServerStats() {
  const [stats, setStats] = useState<{ connections: number; channels: number } | null>(null);

  useEffect(() => {
    fetch('/api/v1/health')
      .then((r) => r.ok ? r.json() : null)
      .then((d) => d && setStats(d))
      .catch(() => {});
  }, []);

  if (!stats || stats.connections === 0) return null;

  return (
    <div className="text-center mt-3 animate-fadeIn">
      <div className="inline-flex items-center gap-2 bg-bg/60 rounded-full px-3 py-1.5 border border-border/50">
        <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
        <span className="text-[11px] text-fg-dim">
          <span className="text-fg-muted font-medium">{stats.connections}</span> online · <span className="text-fg-muted font-medium">{stats.channels}</span> channels
        </span>
      </div>
    </div>
  );
}

