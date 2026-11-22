import { useEffect, useState } from 'react';

/** The current time, refreshed every `everyMs` while `active` — for a label
 *  that counts up ("for 3m") without the sender re-publishing anything. */
export function useNow(everyMs: number, active = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(t);
  }, [everyMs, active]);
  return now;
}
