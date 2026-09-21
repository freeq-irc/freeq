import { useEffect, useRef } from 'react';
import {
  CHECKING_COPY,
  copyForVerdict,
  unsignedCopy,
  useCachedVerdict,
  type VerdictCopy,
} from '../lib/verify-signature';

interface Props {
  msgid: string;
  signed: boolean;
  position: { x: number; y: number };
  onClose: () => void;
  /** What the id names — adjusts the panel wording. Coordination events are
   *  checked the same way messages are. */
  noun?: 'message' | 'event';
}

/** Where a key was found, named as the server's verify answer names it
 *  (`key_source`), so one vocabulary covers both. */
const KEY_SOURCES: Record<string, string> = {
  IdentityRecord: 'identity-record',
  DidDocument: 'did-document',
  OriginServer: 'origin-server',
};

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
export function VerifySignaturePanel({ msgid, signed, position, onClose, noun = 'message' }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  // The verdict this client reached for the line. Nothing is asked of the
  // server here: the check already ran when the line arrived, and a verdict
  // that settles while the panel is open lands through this subscription.
  const verdict = useCachedVerdict(msgid);

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

  const state = signed ? (verdict?.state ?? 'pending') : 'unsigned';
  const checking = state === 'pending';

  // Nothing signed is its own answer, not a failed check. A key still being
  // looked up says so, and the answer replaces it when it lands.
  const copy: VerdictCopy = !signed
    ? unsignedCopy(noun)
    : verdict && !checking
      ? copyForVerdict(verdict, noun)
      : CHECKING_COPY;

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
      data-msgid={msgid}
      data-verdict={state}
      data-key-source={verdict?.keySource ?? ''}
      className="bg-bg-secondary border border-border rounded-xl shadow-2xl p-3 animate-fadeIn"
      onClick={(e) => e.stopPropagation()}
    >
      <div className={`text-xs font-semibold mb-1 ${copy.tone}`}>{copy.heading}</div>

      {checking && (
        <svg className="animate-spin w-3 h-3 shrink-0 text-fg-dim mb-1" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}

      <p className={`text-[11px] leading-relaxed mb-1 ${copy.tone}`}>
        {state === 'device' && '✓ '}
        {(state === 'invalid' || state === 'retired') && '⚠ '}
        {copy.line}
      </p>

      {/* The key the check used, and where it was found. */}
      {verdict?.kid && (
        <p className="text-[10px] text-fg-dim font-mono break-all" data-testid="verify-key">
          {verdict.kid}
          {verdict.keySource ? ` · ${KEY_SOURCES[verdict.keySource]}` : ''}
        </p>
      )}

      <button
        className="text-[10px] text-fg-dim hover:text-fg-muted mt-1.5"
        onClick={onClose}
      >
        Dismiss
      </button>
    </div>
  );
}
