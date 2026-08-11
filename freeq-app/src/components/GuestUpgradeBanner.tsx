import { useStore } from '../store';
import { disconnect } from '../irc/client';
import { useState } from 'react';

export function GuestUpgradeBanner() {
  const authDid = useStore((s) => s.authDid);
  const registered = useStore((s) => s.registered);
  const [dismissed, setDismissed] = useState(false);

  // Only show for guests who are registered
  if (authDid || !registered || dismissed) return null;

  return (
    <div className="flex items-center justify-center gap-3 py-1.5 px-4 text-xs shrink-0 bg-accent/5 border-b border-accent/10">
      <span className="text-fg-dim">
        🔑 <button onClick={() => disconnect()} className="text-accent font-semibold hover:underline">Sign in with Bluesky</button>
        {' '}to get an AT Protocol identity, upload images, and keep your nick
      </span>
      <button onClick={() => setDismissed(true)} className="text-fg-dim/40 hover:text-fg-dim ml-1">✕</button>
    </div>
  );
}
