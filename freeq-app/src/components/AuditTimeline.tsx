/**
 * AuditTimeline — shows chronological audit trail for a channel.
 * Fetches from GET /api/v1/channels/{name}/audit
 */
import { useEffect, useState } from 'react';
import { displayNameForKey } from '../lib/display-name';
import { apiFetch } from '../lib/api';
import { VerifySignaturePanel } from './VerifySignaturePanel';

interface AuditEvent {
  timestamp: string;
  category: string;
  event: string;
  actor_did: string;
  actor_name?: string;
  details: Record<string, any>;
  signature?: string;
  /** Present on coordination rows — the id the verify endpoint answers for. */
  event_id?: string;
}

interface AuditTimelineProps {
  channel: string;
  onClose: () => void;
}

const categoryColors: Record<string, string> = {
  coordination: 'text-accent',
  governance: 'text-warning',
  capability: 'text-success',
  membership: 'text-fg-dim',
};

const categoryIcons: Record<string, string> = {
  coordination: '📋',
  governance: '⚡',
  capability: '🔑',
  membership: '👤',
};

const eventIcons: Record<string, string> = {
  task_request: '📋', task_accept: '👍', task_update: '📝',
  task_complete: '✅', task_failed: '❌', evidence_attach: '📎',
  pause: '⏸', resume: '▶', revoke: '🚫',
  granted: '🔓', revoked: '🔒',
  join: '→', part: '←', quit: '✕',
};

export function AuditTimeline({ channel, onClose }: AuditTimelineProps) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [actorFilter, setActorFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [verify, setVerify] = useState<{ id: string; signed: boolean; pos: { x: number; y: number } } | null>(null);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '200' });
    if (actorFilter) params.set('actor', actorFilter);
    if (categoryFilter) params.set('type', categoryFilter);

    apiFetch(`/api/v1/channels/${encodeURIComponent(channel.replace(/^#/, ''))}/audit?${params}`)
      .then(r => r.ok ? r.json() : { events: [] })
      .then(data => {
        setEvents(data.timeline || data.events || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [channel, actorFilter, categoryFilter]);

  // Unique actors for filter dropdown
  const actors = [...new Set(events.map(e => e.actor_name || e.actor_did))].sort();

  const filtered = events;

  return (
    <div className="flex flex-col h-full bg-bg-primary">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-lg">📋</span>
          <span className="font-semibold text-fg">Audit Timeline</span>
          <span className="text-sm text-fg-dim">{displayNameForKey(channel)}</span>
        </div>
        <button onClick={onClose} className="text-fg-dim hover:text-fg text-lg">✕</button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/50 text-xs">
        <select
          value={actorFilter}
          onChange={e => setActorFilter(e.target.value)}
          className="bg-surface text-fg-muted rounded px-2 py-1 border border-border/50"
        >
          <option value="">All actors</option>
          {/* The value stays the identifier the API filters on; only the label
              is resolved, so a DID never faces the reader. */}
          {actors.map(a => <option key={a} value={a}>{displayNameForKey(a)}</option>)}
        </select>
        <select
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
          className="bg-surface text-fg-muted rounded px-2 py-1 border border-border/50"
        >
          <option value="">All types</option>
          <option value="coordination">Coordination</option>
          <option value="governance">Governance</option>
          <option value="capability">Capability</option>
          <option value="membership">Membership</option>
        </select>
        <span className="text-fg-dim ml-auto">{filtered.length} events</span>
      </div>

      {/* Timeline */}
      <div className="flex-1 overflow-y-auto px-4 py-2">
        {loading ? (
          <div className="text-fg-dim text-center py-8">Loading...</div>
        ) : filtered.length === 0 ? (
          <div className="text-fg-dim text-center py-8">No audit events found.</div>
        ) : (
          <div className="space-y-1">
            {filtered.map((evt, i) => (
              <AuditEventRow
                key={i}
                event={evt}
                onVerify={(id, signed, pos) => setVerify({ id, signed, pos })}
              />
            ))}
          </div>
        )}
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

function AuditEventRow({ event, onVerify }: {
  event: AuditEvent;
  onVerify: (id: string, signed: boolean, pos: { x: number; y: number }) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const ts = new Date(event.timestamp);
  const time = ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const icon = eventIcons[event.event] || categoryIcons[event.category] || '•';
  const color = categoryColors[event.category] || 'text-fg-dim';

  // Build summary text
  let summary = '';
  const d = event.details;
  switch (event.event) {
    case 'task_request': summary = `created task: ${d.description || ''}`; break;
    case 'task_update': summary = `→ ${d.phase || ''}: ${d.summary || ''}`; break;
    case 'task_complete': summary = `completed task${d.url ? ` — ${d.url}` : ''}`; break;
    case 'task_failed': summary = `task failed: ${d.error || ''}`; break;
    case 'evidence_attach': summary = `evidence: ${d.evidence_type || ''} — ${d.summary || ''}`; break;
    case 'pause': summary = `paused by ${d.issuer_name || d.issued_by || ''}`; break;
    case 'resume': summary = `resumed by ${d.issuer_name || d.issued_by || ''}`; break;
    case 'revoke': summary = `revoked by ${d.issuer_name || d.issued_by || ''}`; break;
    case 'granted': summary = `granted: ${d.capability || ''}`; break;
    case 'join': summary = 'joined'; break;
    case 'part': summary = 'left'; break;
    default: summary = event.event;
  }

  return (
    <div
      className="flex items-start gap-2 py-1 hover:bg-surface/30 rounded px-1 cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <span className="text-[11px] font-mono text-fg-dim/60 w-[65px] flex-shrink-0 pt-0.5">{time}</span>
      <span className="w-5 text-center flex-shrink-0">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className={`text-xs font-semibold ${color}`}>
            {event.actor_name || (event.actor_did ? displayNameForKey(event.actor_did) : '')}
          </span>
          <span className="text-xs text-fg-muted truncate">{summary}</span>
          {event.event_id && (
            <button
              className="text-[10px] text-fg-dim/60 hover:text-fg-muted underline decoration-dotted"
              title="Check this event's signature"
              onClick={e => { e.stopPropagation(); onVerify(event.event_id!, !!event.signature, { x: e.clientX, y: e.clientY }); }}
            >
              verify
            </button>
          )}
        </div>
        {expanded && (
          <pre className="mt-1 p-2 bg-surface rounded text-[11px] font-mono text-fg-dim overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(event.details, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
