import { useEffect, useRef, useState } from 'react';
import { verifySignature, VERIFY_LABELS, type VerifyAnswer } from '../lib/verify-signature';

interface Props {
  msgid: string;
  signed: boolean;
  position: { x: number; y: number };
  onClose: () => void;
}

const PANEL_W = 288;
const PANEL_H_ESTIMATE = 210;

/**
 * The verdict panel behind "Verify Signature…" in the message context menu.
 *
 * Opened by an explicit request, so opening is what fires the check. Renders
 * `position: fixed` at the requesting click, clamped inside the viewport, and
 * closes on click-away, Escape, or its own Dismiss — the same manners as the
 * context menu that opened it, which is also what keeps two panels from ever
 * being open at once.
 */
export function VerifySignaturePanel({ msgid, signed, position, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [answer, setAnswer] = useState<VerifyAnswer | null>(null);
  const [checking, setChecking] = useState(signed);
  const retriesLeft = useRef(2);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('keydown', esc);
    };
  }, [onClose]);

  useEffect(() => {
    if (!signed) return;
    let alive = true;
    const runCheck = () => {
      setChecking(true);
      verifySignature(msgid).then((a) => {
        if (!alive) return;
        setAnswer(a);
        setChecking(false);
        // The one retryable flavour: the server is fetching the signer's key
        // as a side effect of having been asked — re-ask a couple of times.
        if (a.transient && retriesLeft.current > 0) {
          retriesLeft.current -= 1;
          retryTimer.current = setTimeout(runCheck, 2000);
        }
      });
    };
    runCheck();
    return () => {
      alive = false;
      if (retryTimer.current) clearTimeout(retryTimer.current);
    };
  }, [msgid, signed]);

  const outcome = answer?.outcome ?? null;
  const headerTone = signed && outcome ? VERIFY_LABELS[outcome].tone : 'text-fg-muted';
  const stillFetchingKey = !checking && answer?.transient && retriesLeft.current > 0;

  const style: React.CSSProperties = {
    position: 'fixed',
    left: Math.max(8, Math.min(position.x, window.innerWidth - PANEL_W - 8)),
    top: Math.max(8, Math.min(position.y, window.innerHeight - PANEL_H_ESTIMATE - 8)),
    width: PANEL_W,
    zIndex: 100,
  };

  return (
    <div
      ref={ref}
      style={style}
      data-testid="verify-panel"
      data-verdict={signed ? (checking ? 'checking' : outcome) : 'unsigned'}
      className="bg-bg-secondary border border-border rounded-xl shadow-2xl p-3 animate-fadeIn"
      onClick={(e) => e.stopPropagation()}
    >
      <div className={`text-xs font-semibold mb-1 ${headerTone}`}>
        {signed ? 'Message Signature' : 'Unsigned Message'}
      </div>

      {signed && (checking || stillFetchingKey) && (
        <div className="text-[11px] text-fg-dim flex items-center gap-1.5 mb-1">
          <svg className="animate-spin w-3 h-3 shrink-0" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          {answer?.transient
            ? 'This server doesn’t hold the signer’s key yet — it’s fetching it from the origin server now, and this panel re-checks by itself…'
            : 'Checking signature…'}
        </div>
      )}

      {signed && !checking && !stillFetchingKey && outcome && (
        <div className={`text-[11px] font-medium mb-1 ${VERIFY_LABELS[outcome].tone}`}>
          {(outcome === 'device' || outcome === 'server') && '✓ '}
          {outcome === 'invalid' && '⚠ '}
          {VERIFY_LABELS[outcome].text}
        </div>
      )}

      <p className="text-[11px] text-fg-muted leading-relaxed">
        {signed ? (
          <>This message carries a cryptographic signature tied to the sender&apos;s
          AT Protocol DID. The check above is the server&apos;s answer from its
          signing keys.</>
        ) : (
          <>Nothing was signed — there is no signature to check. Typical for
          guest accounts and messages from legacy servers.</>
        )}
      </p>

      <button
        className="text-[10px] text-fg-dim hover:text-fg-muted mt-1.5"
        onClick={onClose}
      >
        Dismiss
      </button>
    </div>
  );
}
