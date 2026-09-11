import { useStore } from '../store';
import { displayNameForKey } from '../lib/display-name';
import { requestPermission } from '../lib/notifications';
import { getPreferences, setPreferences } from '../lib/db';
import { useState, useEffect } from 'react';
import { AudioTest } from './AudioTest';
import { useSyncExternalStore } from 'react';
import {
  getDeviceKeyState,
  signInToPublishKeys,
  subscribeDeviceKey,
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
            {authDid && <DeviceKeyRows />}
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

/**
 * This device's signing key: where it is kept, and whether the account knows
 * about it. A key the account does not have yet can be published from here,
 * which means signing in again for the permission to write the record.
 */
function DeviceKeyRows() {
  const key = useSyncExternalStore(subscribeDeviceKey, getDeviceKeyState);
  const [confirm, setConfirm] = useState(false);

  const shortKid = key.kid ? `${key.kid.slice(0, 8)}…` : '';
  const made = key.createdAt ? new Date(key.createdAt).toLocaleDateString() : '';

  return (
    <>
      <div className="flex items-center justify-between text-sm gap-2">
        <span className="text-fg-muted">
          {key.published ? `${shortKid} · ${made}` : 'Key not published · this device'}
        </span>
        {!key.published && (
          <button
            onClick={() => setConfirm(true)}
            className="text-accent text-xs font-semibold hover:underline"
          >
            {'Publish key'}
          </button>
        )}
      </div>
      {confirm && (
        <div className="rounded-lg border border-border bg-bg p-3 space-y-2">
          <p className="text-sm font-semibold">{'Sign in to continue'}</p>
          <p className="text-[11px] text-fg-dim leading-relaxed">
            {'freeq needs permission to publish keys to your account. Continue to your account provider?'}
          </p>
          <div className="flex justify-end gap-3 text-xs">
            <button onClick={() => setConfirm(false)} className="text-fg-dim hover:text-fg">
              {'Not now'}
            </button>
            <button
              onClick={() => signInToPublishKeys()}
              className="text-accent font-semibold hover:underline"
            >
              {'Continue'}
            </button>
          </div>
        </div>
      )}
      <div className="flex items-center justify-between text-sm gap-2">
        <span className="text-fg-muted">{'Signing key · kept in this browser'}</span>
      </div>
    </>
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
