import { useStore } from '../store';
import { disconnect, reconnect } from '../irc/client';
import { useState, useEffect } from 'react';
import { TOP_BAR, TOP_BAR_BUTTON, TOP_BAR_QUIET_BUTTON, TOP_BAR_TEXT } from './topBar';

export function ReconnectBanner() {
  const connectionState = useStore((s) => s.connectionState);
  const registered = useStore((s) => s.registered);
  const authDid = useStore((s) => s.authDid);
  const [disconnectedSecs, setDisconnectedSecs] = useState(0);

  // Track how long we've been disconnected
  useEffect(() => {
    if (connectionState === 'disconnected') {
      setDisconnectedSecs(0);
      const iv = setInterval(() => setDisconnectedSecs(s => s + 1), 1000);
      return () => clearInterval(iv);
    } else {
      setDisconnectedSecs(0);
    }
  }, [connectionState]);

  // Show identity loss warning (reconnected as guest after having AT identity)
  const hadIdentity = !!localStorage.getItem('freeq-handle');
  const identityLost = registered && connectionState === 'connected' && !authDid && hadIdentity;

  // Show reconnecting/disconnected banner
  const showReconnect = registered && connectionState !== 'connected';

  if (!showReconnect && !identityLost) return null;

  if (identityLost) {
    return (
      <div className={`${TOP_BAR} bg-warning/10 text-warning border-warning/10`}>
        <span className={TOP_BAR_TEXT}>Signed in as guest — AT Protocol session expired</span>
        <button
          onClick={() => disconnect()}
          className={TOP_BAR_BUTTON}
        >
          Sign in again
        </button>
      </div>
    );
  }

  return (
    <div className={`${TOP_BAR} ${
      connectionState === 'connecting'
        ? 'bg-warning/5 text-warning border-warning/10'
        : 'bg-danger/10 text-danger border-danger/10'
    }`}>
      {connectionState === 'connecting' ? (
        <>
          <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Reconnecting...
        </>
      ) : (
        <>
          <span>●</span>
          {disconnectedSecs < 5 ? 'Reconnecting...' : 'Connection lost'}
          <button
            onClick={() => reconnect()}
            className={TOP_BAR_BUTTON}
          >
            Reconnect now
          </button>
          {disconnectedSecs >= 10 && (
            <button
              onClick={() => disconnect()}
              className={`${TOP_BAR_QUIET_BUTTON} text-danger/60`}
            >
              Sign out
            </button>
          )}
        </>
      )}
    </div>
  );
}
