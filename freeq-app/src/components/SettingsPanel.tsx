import { useStore } from '../store';
import { displayNameForKey } from '../lib/display-name';
import { requestPermission } from '../lib/notifications';
import { getPreferences, setPreferences } from '../lib/db';
import { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { AudioTest } from './AudioTest';
import { formatTime } from './MessageList';
import { useSyncExternalStore } from 'react';
import {
  getDeviceKeyState,
  listDeviceRows,
  signInToPublishKeys,
  signOutDevice,
  subscribeDeviceKey,
  type DeviceRow,
} from '../irc/client';

interface SettingsPanelProps {
  open: boolean;
  onClose: () => void;
}

export function SettingsPanel({ open, onClose }: SettingsPanelProps) {
  const nick = useStore((s) => s.nick);
  const authDid = useStore((s) => s.authDid);
  const connectionState = useStore((s) => s.connectionState);
  const connectedServer = useStore((s) => s.connectedServer);
  const theme = useStore((s) => s.theme);
  const setTheme = useStore((s) => s.setTheme);
  const density = useStore((s) => s.messageDensity);
  const setDensity = useStore((s) => s.setMessageDensity);
  const showJoinPart = useStore((s) => s.showJoinPart);
  const setShowJoinPart = useStore((s) => s.setShowJoinPart);
  const loadMedia = useStore((s) => s.loadExternalMedia);
  const setLoadMedia = useStore((s) => s.setLoadExternalMedia);
  const blockedDids = useStore((s) => s.blockedDids);
  const blockedNicks = useStore((s) => s.blockedNicks);
  const unblockUser = useStore((s) => s.unblockUser);

  const [notifs, setNotifs] = useState(true);
  const [sounds, setSounds] = useState(true);

  useEffect(() => {
    if (open) {
      getPreferences().then((p) => {
        setNotifs(p.notifications);
        setSounds(p.sounds);
      });
    }
  }, [open]);

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-80 bg-bg-secondary border-l border-border shadow-2xl animate-slideIn overflow-y-auto">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="font-semibold">Settings</h2>
          <button onClick={onClose} className="text-fg-dim hover:text-fg text-lg">✕</button>
        </div>

        <div className="p-4 space-y-6">
          {/* Account */}
          <Section title="Account">
            <InfoRow label="Nickname" value={nick} />
            <InfoRow label="Connection" value={connectionState} />
            {connectedServer && (() => {
              const stripped = connectedServer.replace(/^wss?:\/\//, '').replace(/\/.*$/, '');
              const isProxy = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(stripped);
              const target = typeof __FREEQ_TARGET__ === 'string' ? __FREEQ_TARGET__.replace(/^https?:\/\//, '') : null;
              return <InfoRow label="Server" value={isProxy && target ? `${target} (via proxy)` : stripped} />;
            })()}
            {authDid && <InfoRow label="DID" value={authDid} mono />}
          </Section>

          {/* Appearance */}
          <Section title="Appearance">
            <div className="flex items-center justify-between text-sm">
              <span className="text-fg-muted">Theme</span>
              <div className="flex gap-1 bg-bg rounded-lg p-0.5">
                <button
                  onClick={() => setTheme('dark')}
                  className={`px-2.5 py-1 text-xs rounded-md ${theme === 'dark' ? 'bg-surface text-fg' : 'text-fg-dim'}`}
                >
                  🌙 Dark
                </button>
                <button
                  onClick={() => setTheme('light')}
                  className={`px-2.5 py-1 text-xs rounded-md ${theme === 'light' ? 'bg-surface text-fg' : 'text-fg-dim'}`}
                >
                  ☀️ Light
                </button>
              </div>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-fg-muted">Message density</span>
              <div className="flex gap-1 bg-bg rounded-lg p-0.5">
                {(['cozy', 'default', 'compact'] as const).map((d) => (
                  <button
                    key={d}
                    onClick={() => setDensity(d)}
                    className={`px-2 py-1 text-xs rounded-md capitalize ${density === d ? 'bg-surface text-fg' : 'text-fg-dim'}`}
                  >
                    {d}
                  </button>
                ))}
              </div>
            </div>
            <Toggle
              label="Show join/part messages"
              checked={showJoinPart}
              onChange={setShowJoinPart}
            />
            <p className="text-[11px] text-fg-dim leading-relaxed mt-1">
              Show when users join and leave channels. Kicks and moderation actions are always shown.
            </p>
          </Section>

          {/* Notifications */}
          <Section title="Notifications">
            <Toggle
              label="Desktop notifications"
              checked={notifs}
              onChange={async (v) => {
                setNotifs(v);
                await setPreferences({ notifications: v });
                if (v) {
                  const ok = await requestPermission();
                  if (!ok) {
                    setNotifs(false);
                    await setPreferences({ notifications: false });
                  }
                }
              }}
            />
            <Toggle
              label="Sound effects"
              checked={sounds}
              onChange={async (v) => {
                setSounds(v);
                await setPreferences({ sounds: v });
              }}
            />
          </Section>

          {/* Audio — local speaker + mic test */}
          <Section title="Audio">
            <AudioTest />
          </Section>

          {/* Privacy */}
          <Section title="Privacy">
            <Toggle
              label="Load external media"
              checked={loadMedia}
              onChange={setLoadMedia}
            />
            <p className="text-[11px] text-fg-dim leading-relaxed mt-1">
              When off, images from external URLs require a click to load. Prevents IP leakage via tracking pixels.
            </p>

            <div className="pt-2">
              <div className="text-sm text-fg-muted mb-1">Blocked users</div>
              {blockedNicks.length === 0 && blockedDids.length === 0 ? (
                <p className="text-[11px] text-fg-dim leading-relaxed">
                  No blocked users. Block someone from their profile or a message&apos;s context menu.
                </p>
              ) : (
                <div className="space-y-1">
                  {blockedNicks.map((n) => (
                    <BlockedUserRow key={n} id={n} onUnblock={() => unblockUser(n)} />
                  ))}
                  {blockedDids.map((d) => (
                    <BlockedUserRow key={d} id={d} mono onUnblock={() => unblockUser(d)} />
                  ))}
                </div>
              )}
            </div>

            <div className="mt-2 p-2 bg-bg-tertiary rounded-lg">
              <p className="text-[11px] text-fg-dim leading-relaxed">
                freeq has zero tolerance for objectionable content and abusive users.
                Blocking hides someone immediately; reporting also flags them for review.
                To escalate, email{' '}
                <a href="mailto:abuse@freeq.at" className="text-accent hover:underline">abuse@freeq.at</a>.
              </p>
            </div>
          </Section>

          {authDid && (
            <Section title="Devices">
              <DevicesSection />
            </Section>
          )}

          {/* Keyboard shortcuts */}
          <Section title="Keyboard Shortcuts">
            <ShortcutRow keys="⌘ K" desc="Quick switcher" />
            <ShortcutRow keys="⌘ F" desc="Search messages" />
            <ShortcutRow keys="⌥ 1-0" desc="Switch channel" />
            <ShortcutRow keys="Esc" desc="Close panel / cancel" />
            <ShortcutRow keys="↑" desc="Edit last message" />
            <ShortcutRow keys="Tab" desc="Autocomplete nick" />
          </Section>

          {/* About */}
          <Section title="About">
            <p className="text-xs text-fg-dim leading-relaxed">
              freeq — IRC with AT Protocol identity.
              <br />
              Open source at{' '}
              <a href="https://github.com/freeq-irc/freeq" target="_blank" className="text-accent hover:underline">
                github.com/freeq-irc/freeq
              </a>
              {typeof __GIT_COMMIT__ === 'string' && __GIT_COMMIT__ !== 'unknown' && (
                <>
                  <br />
                  <span className="text-fg-dim/50">Build {__GIT_COMMIT__}</span>
                </>
              )}
            </p>
          </Section>
        </div>
      </div>
    </>
  );
}

/** A date, the way the app writes one older than a week, and its time. */
function day(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${formatTime(d)}`;
}

/** The one meta line a row carries. */
function metaLine(row: DeviceRow): string {
  if (row.state === 'unpublished') return 'Key not published · this device';
  if (row.state === 'signedOut') return `Signed out · ${day(row.date)}`;
  if (row.state === 'expired') return `Expired · ${day(row.date)}`;
  return `Active · since ${day(row.date)}`;
}

/**
 * Every signing key the account has published, newest first, and the one
 * action each offers: sign another device out, publish this device's key, or
 * nothing at all for a key already signed out.
 */
export function DevicesSection() {
  const key = useSyncExternalStore(subscribeDeviceKey, getDeviceKeyState);
  const [rows, setRows] = useState<DeviceRow[]>([]);
  // Until the first read settles.
  const [loading, setLoading] = useState(true);
  // Set by a sign-out, so the next read lists the account afresh.
  const refreshNext = useRef(false);
  // Set once this open has listed the account afresh.
  const listedOnOpen = useRef(false);
  const [ask, setAsk] = useState<DeviceRow | null>(null);
  const [signIn, setSignIn] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  // What happened to a sign-out that is not a failure.
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Re-read on mount, and again whenever this device's own key changes —
  // publishing it is the one thing that lands there rather than here. On open
  // the cached rows show at once, then the account is listed afresh so a
  // device that signed in since the cached listing appears.
  useEffect(() => {
    let live = true;
    const refresh = refreshNext.current;
    refreshNext.current = false;
    const thenRefresh = !refresh && !listedOnOpen.current;
    (async () => {
      let cached: DeviceRow[] = [];
      try {
        cached = await listDeviceRows({ refresh });
      } catch {
        // Left empty; the refresh below may still fill it.
      }
      if (!live) return;
      setRows(cached);
      if (!thenRefresh || cached.length > 0) setLoading(false);
      if (!thenRefresh) return;
      listedOnOpen.current = true;
      try {
        const fresh = await listDeviceRows({ refresh: true });
        if (live) setRows(fresh);
      } catch {
        // Keep the cached rows.
      }
      if (live) setLoading(false);
    })();
    return () => {
      live = false;
    };
  }, [key.kid, key.published, busy]);

  async function confirmSignOut(row: DeviceRow) {
    setBusy(true);
    setFailed(null);
    setNote(null);
    try {
      const outcome = await signOutDevice(row.kid);
      switch (outcome.kind) {
        case 'notReady':
          setFailed("To sign out other devices, sign in and publish this device's key first.");
          break;
        case 'noKey':
          setFailed(
            "This browser won't let freeq store its key. Change your browser settings to allow this site to store data, or try another browser.",
          );
          break;
        case 'needsSignIn':
          // The account provider refuses the write without the publish grant.
          setSignIn(true);
          break;
        case 'notSaved':
          setFailed(
            `Couldn't sign out ${row.name} because your account provider didn't respond. Try again in a moment.`,
          );
          break;
        case 'retired':
          // Not failures: the retirement is in the account either way.
          if (outcome.sessionsClosed === null) {
            setNote(
              `${row.name}'s key has been retired, so anything it sends now is flagged. It may still be signed in, here or somewhere else. To sign it out there too, open freeq on that server and sign it out from Devices.`,
            );
          } else if (outcome.sessionsClosed === 0) {
            setNote(
              `${row.name}'s key has been retired, so anything it sends now is flagged. It isn't connected to this server, so it may still be signed in somewhere else. To sign it out there too, open freeq on that server and sign it out from Devices.`,
            );
          }
          break;
      }
    } catch {
      setFailed(`Couldn't sign out ${row.name}. Try again.`);
    } finally {
      setAsk(null);
      refreshNext.current = true;
      setBusy(false);
    }
  }

  return (
    <>
      {loading && <p className="text-[11px] text-fg-dim leading-relaxed">{'Loading devices…'}</p>}
      {rows.map((row) => (
        <div
          key={row.kid}
          data-device-row
          className="flex items-center justify-between text-sm gap-2"
        >
          <span className="flex items-center gap-2 min-w-0">
            <span
              aria-hidden
              className={row.state === 'signedOut' || row.state === 'expired' ? 'opacity-40' : ''}
            >
              {'💻'}
            </span>
            <span className="min-w-0">
              <span data-testid="device-name" className="block truncate text-fg">
                {row.name}
              </span>
              <span data-device-meta className="block text-[11px] text-fg-dim">
                {metaLine(row)}
              </span>
            </span>
          </span>
          <span className="shrink-0 text-xs">
            {row.state === 'active' && row.thisDevice && (
              <span className="text-fg-dim">{'This device'}</span>
            )}
            {row.state === 'active' && !row.thisDevice && (
              <button
                disabled={busy}
                onClick={() => setAsk(row)}
                className="text-accent font-semibold hover:underline disabled:opacity-50"
              >
                {'Sign out'}
              </button>
            )}
            {row.state === 'unpublished' && (
              <button
                onClick={() => setSignIn(true)}
                className="text-accent font-semibold hover:underline"
              >
                {'Publish key'}
              </button>
            )}
          </span>
        </div>
      ))}

      <p className="text-[11px] text-fg-dim leading-relaxed">
        {'A signed-out device has to sign in again before it can post as you. Messages it already sent stay signed.'}
      </p>

      {failed && <p className="text-[11px] text-red-400">{failed}</p>}
      {note && <p className="text-[11px] text-fg-dim leading-relaxed">{note}</p>}

      {ask && (
        <Modal onClose={() => setAsk(null)}>
          <div role="dialog" className="p-3 space-y-2">
            <p className="text-sm font-semibold">{`Sign out ${ask.name}?`}</p>
            <p className="text-[11px] text-fg-dim leading-relaxed">
              {'It will be signed out and will need to sign in again. Messages it already sent stay signed.'}
            </p>
            <div className="flex justify-end gap-3 text-xs">
              <button onClick={() => setAsk(null)} className="text-fg-dim hover:text-fg">
                {'Cancel'}
              </button>
              <button
                disabled={busy}
                onClick={() => void confirmSignOut(ask)}
                className="text-accent font-semibold hover:underline disabled:opacity-50"
              >
                {'Sign out'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {signIn && (
        <Modal onClose={() => setSignIn(false)}>
          <div className="p-3 space-y-2">
            <p className="text-sm font-semibold">{'Sign in to continue'}</p>
            <p className="text-[11px] text-fg-dim leading-relaxed">
              {'Your account needs a fresh sign-in before freeq can change your devices.'}
            </p>
            <div className="flex justify-end gap-3 text-xs">
              <button onClick={() => setSignIn(false)} className="text-fg-dim hover:text-fg">
                {'Not now'}
              </button>
              <button
                onClick={() => signInToPublishKeys()}
                className="text-accent font-semibold hover:underline"
              >
                {'Sign in'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}

/**
 * A modal over the whole window. The Settings panel is fixed and animated with
 * a transform, which would contain a fixed box inside it, so this renders into
 * document.body; the shell is JoinGateModal's.
 */
function Modal({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-bg-secondary border border-border rounded-xl shadow-2xl w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[10px] uppercase tracking-widest text-fg-dim font-semibold mb-2">{title}</h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function BlockedUserRow({ id, mono, onUnblock }: { id: string; mono?: boolean; onUnblock: () => void }) {
  // A DID entry resolves to the peer's known name where possible; the full
  // DID stays one hover away (title) so the entry is still exact.
  const label = displayNameForKey(id);
  return (
    <div className="flex items-center justify-between text-sm gap-2">
      <span className={`text-fg truncate ${mono && label === id ? 'font-mono text-xs' : ''}`} title={id}>
        {label}
      </span>
      <button onClick={onUnblock} className="text-xs text-danger hover:underline shrink-0">
        Unblock
      </button>
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-fg-muted">{label}</span>
      <span className={`text-fg truncate max-w-[160px] ${mono ? 'font-mono text-xs' : ''}`} title={value}>
        {value}
      </span>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-fg-muted">{label}</span>
      <button
        onClick={() => onChange(!checked)}
        className={`w-11 h-6 rounded-full relative shrink-0 transition-colors ${checked ? 'bg-accent' : 'bg-surface'}`}
      >
        <span className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-white shadow-sm transition-[left] ${
          checked ? 'left-6' : 'left-1'
        }`} />
      </button>
    </div>
  );
}

function ShortcutRow({ keys, desc }: { keys: string; desc: string }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-fg-muted">{desc}</span>
      <kbd className="text-[10px] text-fg-dim bg-bg-tertiary px-1.5 py-0.5 rounded font-mono">{keys}</kbd>
    </div>
  );
}
