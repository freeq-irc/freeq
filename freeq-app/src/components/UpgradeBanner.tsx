/**
 * The bar above the message list about this device's signing key.
 *
 * `UpgradeBanner` offers the security upgrade while this device's key is not
 * published to the account: messages still send and still carry that key.
 *
 * It is dismissable and not a pop-up: nothing here blocks the room.
 */
import { useState, useSyncExternalStore } from 'react';
import { getDeviceKeyState, signInToPublishKeys, subscribeDeviceKey } from '../irc/client';
import { TOP_BAR, TOP_BAR_ACCENT, TOP_BAR_CLOSE, TOP_BAR_INLINE_BUTTON, TOP_BAR_TEXT } from './topBar';

const BAR = `${TOP_BAR} ${TOP_BAR_ACCENT}`;

export function UpgradeBanner() {
  const needsSignIn = useSyncExternalStore(subscribeDeviceKey, getDeviceKeyState).needsSignIn;
  const [dismissed, setDismissed] = useState(false);

  if (!needsSignIn || dismissed) return null;

  return (
    <div className={BAR}>
      <span className={`${TOP_BAR_TEXT} text-fg-dim`}>
        🔑 {'Security upgrade available:'}{' '}
        <button
          onClick={() => signInToPublishKeys()}
          className={`${TOP_BAR_INLINE_BUTTON} text-accent`}
        >
          {'Publish your key'}
        </button>{' '}
        {'so others can verify messages from this device'}
      </span>
      <button onClick={() => setDismissed(true)} className={TOP_BAR_CLOSE}>✕</button>
    </div>
  );
}
