import { useEffect, useRef, useState } from 'react';
import { useStore, type Message } from '../store';
import { sendDelete, pinMessage, unpinMessage, getNick } from '../irc/client';
import { REPORT_REASONS, reportUser, type ReportReason } from '../lib/safety';
import { showToast } from './Toast';

interface Props {
  msg: Message;
  channel: string;
  position: { x: number; y: number };
  onClose: () => void;
  onReply: () => void;
  onEdit: () => void;
  onThread: () => void;
  onReact: (e: React.MouseEvent) => void;
  onVerify: () => void;
}

export function MessageContextMenu({ msg, channel, position, onClose, onReply, onEdit, onThread, onReact, onVerify }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [showReportReasons, setShowReportReasons] = useState(false);

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

  const copyText = () => {
    navigator.clipboard.writeText(msg.text); showToast('Copied to clipboard', 'success', 2000);
    onClose();
  };

  const copyLink = () => {
    const url = `${window.location.origin}/#${channel}/${msg.id}`;
    navigator.clipboard.writeText(url); showToast('Link copied', 'success', 2000);
    onClose();
  };

  const handleDelete = () => {
    if (confirm('Delete this message?')) {
      sendDelete(channel, msg.id);
    }
    onClose();
  };

  // DID for the sender — member list first, `account` tag fallback
  const senderDid = () =>
    useStore.getState().channels.get(channel.toLowerCase())?.members.get(msg.from.toLowerCase())?.did
    || msg.tags?.account;

  const handleBlock = () => {
    useStore.getState().blockUser(msg.from, senderDid());
    showToast(`Blocked ${msg.from}`, 'success', 2000);
    onClose();
  };

  const handleReport = (reason: ReportReason) => {
    reportUser(msg.from, senderDid(), reason, { channel, msgid: msg.id });
    showToast(`Reported and blocked ${msg.from}`, 'success', 2500);
    onClose();
  };

  // Position on screen
  const style: React.CSSProperties = {
    position: 'fixed',
    left: Math.min(position.x, window.innerWidth - 200),
    top: Math.min(position.y, window.innerHeight - 300),
    zIndex: 100,
  };

  return (
    <div ref={ref} style={style} className="bg-bg-secondary border border-border rounded-xl shadow-2xl py-1.5 min-w-[180px] animate-fadeIn">
      <MenuItem icon="↩️" label="Reply" onClick={() => { onReply(); onClose(); }} />
      <MenuItem icon="🧵" label="View Thread" onClick={() => { onThread(); onClose(); }} />
      <MenuItem icon="😄" label="Add Reaction" onClick={(e) => { onReact(e); onClose(); }} />
      <div className="h-px bg-border mx-2 my-1" />
      <MenuItem icon="📋" label="Copy Text" onClick={copyText} />
      <MenuItem icon="🔗" label="Copy Link" onClick={copyLink} />
      {msg.id && <MenuItem icon="🆔" label="Copy Message ID" onClick={() => {
        navigator.clipboard.writeText(msg.id);
        showToast('Message ID copied', 'success', 2000);
        onClose();
      }} />}
      {msg.id && !msg.isSystem && (
        <MenuItem icon="🔏" label="Verify Signature…" onClick={() => { onVerify(); onClose(); }} />
      )}
      <MenuItem icon="🔖" label="Bookmark" onClick={() => {
        useStore.getState().addBookmark(channel, msg.id, msg.from, msg.text, msg.timestamp);
        onClose();
      }} />
      {channel.startsWith('#') && (() => {
        const ch = useStore.getState().channels.get(channel.toLowerCase());
        const myNick = getNick();
        const myMember = ch?.members.get(myNick.toLowerCase());
        const isOp = myMember?.isOp ?? false;
        if (!isOp) return null; // Only ops can pin/unpin
        const isPinned = ch?.pins.some(p => p.msgid === msg.id);
        return (
          <MenuItem icon="📌" label={isPinned ? "Unpin Message" : "Pin Message"} onClick={() => {
            if (isPinned) {
              unpinMessage(channel, msg.id);
              useStore.getState().setPins(channel, (ch?.pins || []).filter(p => p.msgid !== msg.id));
            } else {
              pinMessage(channel, msg.id);
              const now = Math.floor(Date.now() / 1000);
              useStore.getState().setPins(channel, [{ msgid: msg.id, pinned_by: 'you', pinned_at: now }, ...(ch?.pins || [])]);
            }
            onClose();
          }} />
        );
      })()}
      <MenuItem icon="🦋" label="Share to Bluesky" onClick={() => {
        const bskyUrl = `https://bsky.app/intent/compose?text=${encodeURIComponent(`"${msg.text.slice(0, 200)}" — ${msg.from} on freeq`)}`;
        window.open(bskyUrl, '_blank');
        onClose();
      }} />
      {msg.isSelf && !msg.isSystem && (
        <>
          <div className="h-px bg-border mx-2 my-1" />
          <MenuItem icon="✏️" label="Edit" onClick={() => { onEdit(); onClose(); }} />
          <MenuItem icon="🗑️" label="Delete" onClick={handleDelete} danger />
        </>
      )}
      {!msg.isSelf && !msg.isSystem && (
        <>
          <div className="h-px bg-border mx-2 my-1" />
          {showReportReasons ? (
            <>
              <div className="px-3 py-1 text-[10px] uppercase tracking-widest text-fg-dim font-semibold">Report for…</div>
              {REPORT_REASONS.map((reason) => (
                <MenuItem key={reason} icon="🚩" label={reason} onClick={() => handleReport(reason)} danger />
              ))}
            </>
          ) : (
            <>
              <MenuItem icon="🚩" label="Report…" onClick={() => setShowReportReasons(true)} danger />
              <MenuItem icon="🚫" label={`Block ${msg.from}`} onClick={handleBlock} danger />
            </>
          )}
        </>
      )}
    </div>
  );
}

function MenuItem({ icon, label, onClick, danger }: { icon: string; label: string; onClick: (e: React.MouseEvent) => void; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-1.5 text-sm flex items-center gap-2.5 hover:bg-bg-tertiary transition-colors ${
        danger ? 'text-danger hover:bg-danger/10' : 'text-fg-muted hover:text-fg'
      }`}
    >
      <span className="text-sm w-5 text-center">{icon}</span>
      {label}
    </button>
  );
}
