/**
 * TaskTimeline — focused view for a single task.
 *
 * The task is fetched from `/api/v1/actions/{id}` and shown as what it is —
 * the moves made on it, each under the word for the verb it carried.
 */
import { useEffect, useState } from 'react';
import { VerifySignaturePanel } from './VerifySignaturePanel';
import { displayNameForKey } from '../lib/display-name';
import { actHeadline } from '../lib/act-verbs';
import { apiFetch } from '../lib/api';
import { useStore } from '../store';

export function TaskTimeline(props: { actId: string; onClose: () => void }) {
  return <ActionTimeline actId={props.actId} onClose={props.onClose} />;
}

/** One event of an action, as `/api/v1/actions/{id}` serves it. */
interface ActionEvent {
  event_id: string;
  canonical: string;
  signature?: string;
  actor_did?: string;
  confirm_state?: string;
  timestamp: number;
}

function ActionTimeline({ actId, onClose }: { actId: string; onClose: () => void }) {
  const [data, setData] = useState<{ task: any; events: ActionEvent[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [verify, setVerify] = useState<{ id: string; signed: boolean; pos: { x: number; y: number } } | null>(null);
  // The line a step wrote is known to the store, not to the endpoint: the
  // task's events carry the msgid of the companion each one was paired with.
  const holder = useStore(s => s.bufferHoldingTask(actId));
  const actTasks = useStore(s => (holder ? s.channels.get(holder.toLowerCase())?.actTasks : undefined));
  const task = actTasks?.get(actId);
  const setScrollToMsgId = useStore(s => s.setScrollToMsgId);

  useEffect(() => {
    // Authed: an action in a direct conversation is readable only by the two
    // people in it, and the server tells them apart by the session bearer. A
    // bare fetch 403s, and the panel shows a participant "Task not found".
    apiFetch(`/api/v1/actions/${encodeURIComponent(actId)}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [actId]);

  if (loading) return <div className="p-4 text-fg-dim text-sm">Loading task...</div>;
  if (!data?.events?.length) return <div className="p-4 text-fg-dim text-sm">Task not found.</div>;

  // The document each event signed is where its verb and title live, so the
  // view reads the same bytes the signature covers.
  const docs = data.events.map(e => {
    let doc: Record<string, string> = {};
    try { doc = JSON.parse(e.canonical); } catch { /* an unreadable event still lists */ }
    return { event: e, doc };
  });
  // Only the opener signs a title, so a reader holding no opener is shown
  // none: the id beside it is a handle, not a name for the work.
  const title = docs.find(d => d.doc['act-title'])?.doc['act-title'];

  return (
    <div className="rounded-lg border border-border overflow-hidden bg-bg-secondary max-w-md">
      <div className="flex items-center justify-between px-3 py-2 bg-surface/50 border-b border-border/50">
        <div className="flex items-center gap-2">
          <span>📋</span>
          {title && <span className="font-semibold text-sm text-fg">{title}</span>}
          <span className="text-[10px] font-mono text-fg-dim/60">{actId.slice(0, 12)}</span>
        </div>
        <div className="flex items-center gap-2">
          {/*
            A permalink to the public receipt.
            The in-app panel already proves a signature to whoever is logged
            in; this is the version you can paste to somebody who is not, and
            who has no reason to take our word for anything. The page carries
            the canonical bytes and the key-fetch command rather than a tick.
            It inherits the room's privacy - a task in a +i, +k or E2EE
            channel answers 403 to a stranger - so the link is offered for
            every task and is honest either way rather than us guessing here
            which rooms are public.
          */}
          <a
            href={`/act/${encodeURIComponent(actId)}`}
            target="_blank"
            rel="noopener noreferrer"
            title="Public receipt: the signed chain, with the exact bytes, checkable by anyone"
            className="text-[10px] text-fg-dim/60 hover:text-fg-muted underline decoration-dotted"
          >
            receipt ↗
          </a>
          <button onClick={onClose} className="text-fg-dim hover:text-fg text-sm">✕</button>
        </div>
      </div>

      <div className="px-3 py-2">
        {docs.map(({ event, doc }) => {
          // A receipt and an expiry send no companion line, so there is
          // nothing for their row to jump to and it does not react.
          const msgId = task?.events.find(e => e.eventId === event.event_id)?.msgId;
          return (
          <div
            key={event.event_id}
            className={`flex items-center gap-2 text-xs py-1${msgId ? ' rounded px-1 hover:bg-surface/30' : ''}`}
            onClick={msgId ? () => { setScrollToMsgId(msgId); onClose(); } : undefined}
          >
            <span className="font-semibold text-fg-muted">{actHeadline(doc['act-verb'] ?? '')}</span>
            <span className="text-fg-dim truncate">
              {event.actor_did ? displayNameForKey(event.actor_did) : ''}
            </span>
            <span className="ml-auto text-[10px] text-fg-dim/50">
              {new Date(event.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
            <button
              className="text-[10px] text-fg-dim/60 hover:text-fg-muted underline decoration-dotted"
              title="Check this event's signature"
              onClick={ev => {
                ev.stopPropagation();
                setVerify({ id: event.event_id, signed: !!event.signature, pos: { x: ev.clientX, y: ev.clientY } });
              }}
            >
              verify
            </button>
          </div>
          );
        })}
      </div>

      {verify && (
        <VerifySignaturePanel
          msgid={verify.id}
          signed={verify.signed}
          position={verify.pos}
          noun="event"
          onClose={() => setVerify(null)}
        />
      )}
    </div>
  );
}
