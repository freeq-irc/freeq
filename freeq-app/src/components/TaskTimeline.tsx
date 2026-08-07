/**
 * TaskTimeline — focused view for a single task.
 * Fetches from GET /api/v1/tasks/{taskId}
 */
import { useEffect, useState } from 'react';
import { VerifySignaturePanel } from './VerifySignaturePanel';

interface TaskEvent {
  event_id: string;
  event_type: string;
  actor_did: string;
  channel: string;
  ref_id?: string;
  payload_json: string;
  signature?: string;
  timestamp: number;
}

interface TaskData {
  task: TaskEvent | null;
  events: TaskEvent[];
}

const phaseOrder = ['specifying', 'designing', 'building', 'reviewing', 'testing', 'deploying'];

export function TaskTimeline({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const [data, setData] = useState<TaskData | null>(null);
  const [loading, setLoading] = useState(true);
  const [verify, setVerify] = useState<{ id: string; signed: boolean; pos: { x: number; y: number } } | null>(null);

  useEffect(() => {
    fetch(`/api/v1/tasks/${encodeURIComponent(taskId)}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [taskId]);

  if (loading) return <div className="p-4 text-fg-dim text-sm">Loading task...</div>;
  if (!data?.task) return <div className="p-4 text-fg-dim text-sm">Task not found.</div>;

  const task = data.task;
  const events = data.events || [];

  // Parse task description
  let description = '';
  try { description = JSON.parse(task.payload_json)?.description || ''; } catch {}

  // Determine status
  const complete = events.some(e => e.event_type === 'task_complete');
  const failed = events.some(e => e.event_type === 'task_failed');

  // Find completed phases
  const completedPhases = new Set<string>();
  events.filter(e => e.event_type === 'task_update').forEach(e => {
    try { completedPhases.add(JSON.parse(e.payload_json)?.phase); } catch {}
  });

  // Evidence items
  const evidence = events.filter(e => e.event_type === 'evidence_attach');

  // Duration
  const firstTs = task.timestamp;
  const lastTs = events.length > 0 ? events[events.length - 1].timestamp : firstTs;
  const durationSec = lastTs - firstTs;
  const durationStr = durationSec >= 60
    ? `${Math.floor(durationSec / 60)}m ${durationSec % 60}s`
    : `${durationSec}s`;

  // Complete event URL
  let resultUrl = '';
  const completeEvt = events.find(e => e.event_type === 'task_complete');
  if (completeEvt) {
    try { resultUrl = JSON.parse(completeEvt.payload_json)?.url || ''; } catch {}
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden bg-bg-secondary max-w-md">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-surface/50 border-b border-border/50">
        <div className="flex items-center gap-2">
          <span>📋</span>
          <span className="font-semibold text-sm text-fg">Task</span>
          <span className="text-[10px] font-mono text-fg-dim/60">{taskId.slice(0, 12)}</span>
          <button
            className="text-[10px] text-fg-dim/60 hover:text-fg-muted underline decoration-dotted"
            title="Check this event's signature"
            onClick={e => setVerify({ id: task.event_id, signed: !!task.signature, pos: { x: e.clientX, y: e.clientY } })}
          >
            verify
          </button>
        </div>
        <button onClick={onClose} className="text-fg-dim hover:text-fg text-sm">✕</button>
      </div>

      {/* Status */}
      <div className="px-3 py-2 border-b border-border/30">
        <div className="text-sm text-fg">{description}</div>
        <div className="flex items-center gap-2 mt-1 text-xs text-fg-dim">
          <span className={complete ? 'text-success' : failed ? 'text-error' : 'text-accent'}>
            {complete ? '✅ Complete' : failed ? '❌ Failed' : '⏳ In Progress'}
          </span>
          <span>•</span>
          <span>{durationStr}</span>
          {resultUrl && (
            <>
              <span>•</span>
              <a href={resultUrl} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                {resultUrl}
              </a>
            </>
          )}
        </div>
      </div>

      {/* Phase progression */}
      <div className="px-3 py-2 border-b border-border/30">
        <div className="flex flex-wrap gap-1">
          {phaseOrder.map(phase => {
            const done = completedPhases.has(phase);
            return (
              <span
                key={phase}
                className={`text-[10px] px-1.5 py-0.5 rounded ${
                  done ? 'bg-success/20 text-success' : 'bg-surface text-fg-dim/50'
                }`}
              >
                {done ? '✅' : '○'} {phase}
              </span>
            );
          })}
        </div>
      </div>

      {/* Evidence */}
      {evidence.length > 0 && (
        <div className="px-3 py-2">
          <div className="text-[10px] text-fg-dim font-semibold mb-1">Evidence ({evidence.length})</div>
          {evidence.map((e, i) => {
            let payload: any = {};
            try { payload = JSON.parse(e.payload_json); } catch {}
            const type = payload.evidence_type || payload.type || 'evidence';
            const summary = payload.summary || '';
            return (
              <div key={i} className="flex items-center gap-1.5 text-xs text-fg-muted py-0.5">
                <span>📎</span>
                <span className="font-semibold capitalize">{type.replace(/_/g, ' ')}</span>
                <span className="text-fg-dim truncate">{summary}</span>
                <button
                  className="text-[10px] text-fg-dim/60 hover:text-fg-muted underline decoration-dotted"
                  title="Check this event's signature"
                  onClick={ev => setVerify({ id: e.event_id, signed: !!e.signature, pos: { x: ev.clientX, y: ev.clientY } })}
                >
                  verify
                </button>
              </div>
            );
          })}
        </div>
      )}

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
