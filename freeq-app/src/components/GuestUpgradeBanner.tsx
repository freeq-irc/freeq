import { useStore } from '../store';
import { disconnect } from '../irc/client';
import { useState } from 'react';
import { TOP_BAR, TOP_BAR_ACCENT, TOP_BAR_CLOSE, TOP_BAR_INLINE_BUTTON, TOP_BAR_TEXT } from './TopBar';

export function GuestUpgradeBanner() {
  const authDid = useStore((s) => s.authDid);
  const registered = useStore((s) => s.registered);
  const [dismissed, setDismissed] = useState(false);

  // Only show for guests who are registered
  if (authDid || !registered || dismissed) return null;

  return (
    <div className={`${TOP_BAR} ${TOP_BAR_ACCENT}`}>
      <span className={`${TOP_BAR_TEXT} text-fg-dim`}>
        🔑 <button onClick={() => disconnect()} className={`${TOP_BAR_INLINE_BUTTON} text-accent`}>Sign in with Bluesky</button>
        {' '}to get an AT Protocol identity, upload images, and keep your nick
      </span>
      <button onClick={() => setDismissed(true)} className={TOP_BAR_CLOSE}>✕</button>
    </div>
  );
}
