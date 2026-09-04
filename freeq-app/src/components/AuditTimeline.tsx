/**
 * AuditTimeline — shows chronological audit trail for a channel.
 * Fetches from GET /api/v1/channels/{name}/audit
 */
import { Fragment, useEffect, useState } from 'react';
import { displayNameForKey } from '../lib/display-name';
import { apiFetch } from '../lib/api';
import { VerifySignaturePanel } from './VerifySignaturePanel';
import { Seal, SealPanel } from './ActCards';
import { actHeadline, actEmoji } from '../lib/act-verbs';
import { sealPanelHeader } from '../lib/seal-panel-copy';
import { actFacts } from '../lib/act-facts';

/** The home's ruling on a step, as the step's row carries it. */
interface AuditReceipt {
  event_id: string;
  /** Unix seconds, like the row's own stamp. */
  timestamp: number;
  signature?: string;
}

interface AuditEvent {
  /** Unix seconds, as both sources send them. */
  timestamp: number;
  category: string;
  event: string;
  actor_did: string;
  actor_name?: string;
  details: Record<string, any> & {
    /** On an act row the home has ruled on. */
    receipt?: AuditReceipt;
    /** The home's reading of the step: confirmed, unconfirmed, superseded. */
    confirm_state?: string;
  };
  signature?: string;
  /** Present on coordination rows — the id the verify endpoint answers for. */
  event_id?: string;
}

interface AuditTimelineProps {
  channel: string;
  onClose: () => void;
}

const categoryIcons: Record<string, string> = {
  coordination: '📋',
  governance: '⚡',
};

const eventIcons: Record<string, string> = {
  pause: '⏸', resume: '▶', revoke: '🚫',
  granted: '🔓', revoked: '🔒',
  join: '→', part: '←', quit: '✕',
};

export function AuditTimeline({ channel, onClose }: AuditTimelineProps) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  /** Why the list is empty when it is: the server refused the read, or the
   *  request failed. An empty answer is neither. */
  const [refused, setRefused] = useState<'forbidden' | 'failed' | null>(null);
  const [actorFilter, setActorFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [verify, setVerify] = useState<{ id: string; signed: boolean; pos: { x: number; y: number } } | null>(null);
  const [actors, setActors] = useState<{ did: string; name: string; isServer: boolean }[]>([]);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '200' });
    if (actorFilter) params.set('actor', actorFilter);

    setRefused(null);
    apiFetch(`/api/v1/channels/${encodeURIComponent(channel.replace(/^#/, ''))}/audit?${params}`)
      .then(r => {
        if (r.ok) return r.json();
        // A refusal is not an empty audit: say which it was.
        setRefused(r.status === 401 || r.status === 403 ? 'forbidden' : 'failed');
        return { events: [] };
      })
      .then(data => {
        const rows: AuditEvent[] = data.timeline || data.events || [];
        setEvents(rows);
        // The menu lists who the room has, not who the current filter left
        // standing: rebuilding it from a filtered answer leaves one name in
        // it and no way back.
        if (!actorFilter) {
          const seen = new Map<string, string>();
          for (const e of rows) {
            if (e.actor_did) seen.set(e.actor_did, e.actor_name || displayNameForKey(e.actor_did));
          }
          setActors(
            [...seen]
              .map(([did, name]) => ({ did, name, isServer: did.startsWith('did:web:') }))
              .sort((a, b) => a.name.localeCompare(b.name)),
          );
        }
        setLoading(false);
      })
      .catch(() => { setRefused('failed'); setLoading(false); });
  }, [channel, actorFilter]);

  // The route filters by actor and by window; the kind of row is filtered
  // here, over what it answered.
  const filtered = categoryFilter ? events.filter(e => e.category === categoryFilter) : events;

  return (
    <div className="@container flex flex-col h-full bg-bg-primary">
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
          {/* The value is the identifier the route filters on; only the label
              is resolved, so a DID never faces the reader. A home is not a
              person: the servers sit below the people, after a break. */}
          {actors.filter(a => !a.isServer).map(a => (
            <option key={a.did} value={a.did}>{a.name}</option>
          ))}
          {actors.some(a => a.isServer) && <option disabled>──────────</option>}
          {actors.filter(a => a.isServer).map(a => (
            <option key={a.did} value={a.did}>{a.name}</option>
          ))}
        </select>
        <select
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
          className="bg-surface text-fg-muted rounded px-2 py-1 border border-border/50"
        >
          <option value="">All types</option>
          <option value="coordination">Events</option>
          <option value="act">Tasks</option>
          <option value="governance">Governance</option>
        </select>
        <span className="text-fg-dim ml-auto">{filtered.length} events</span>
      </div>

      {/* Timeline */}
      <div className="flex-1 overflow-y-auto px-4 py-2">
        {loading ? (
          <div className="text-fg-dim text-center py-8">Loading...</div>
        ) : refused === 'forbidden' ? (
          <div className="text-fg-dim text-center py-8">This channel's audit is shown only to signed-in members.</div>
        ) : refused === 'failed' ? (
          <div className="text-fg-dim text-center py-8">The audit could not be loaded.</div>
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

/** What each exception word means, for the reader who hovers it. */
const STATE_HOVER: Record<string, string> = {
  unconfirmed: "The task's home server has not confirmed this step yet",
  superseded: 'An earlier step won this move; this one did not count',
};

/** A name wherever the value is an identifier — a DID is never shown raw. */
function readable(value: unknown): string {
  if (typeof value !== 'string') return JSON.stringify(value);
  return value.startsWith('did:') ? displayNameForKey(value) : value;
}

/**
 * The rows a task step's details carry: the cards' own labelled facts, with
 * names resolved, then the task this step belongs to and the home's ruling.
 *
 * The route sends the step's act tags with their prefix stripped, so they are
 * re-keyed to the form the cards' fact reader speaks. `kind` is the seal
 * panel's header, `act_id` becomes the task row, `confirm_state` is the word
 * in the row itself, and the receipt is drawn with its own check.
 */
function actDetailFacts(event: AuditEvent, d: Record<string, any>): Array<[string, string]> {
  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(d)) {
    if (key === 'kind' || key === 'act_id' || key === 'confirm_state' || key === 'receipt') continue;
    fields[`act-${key}`] = typeof value === 'string' ? value : JSON.stringify(value);
  }
  const facts = actFacts(fields, d.act_id === event.event_id, displayNameForKey);
  if (d.act_id) facts.push(['task', String(d.act_id)]);
  return facts;
}

function AuditEventRow({ event, onVerify }: {
  event: AuditEvent;
  onVerify: (id: string, signed: boolean, pos: { x: number; y: number }) => void;
}) {
  // One disclosure at a time: the chevron's details and the seal's panel open
  // in the same place, so opening either closes the other.
  const [open, setOpen] = useState<'details' | 'seal' | null>(null);
  // The server sends unix seconds; a row read them as milliseconds and dated
  // every event to 1970.
  const clock = (at: Date) =>
    at.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const time = clock(new Date(event.timestamp * 1000));
  const isAct = event.category === 'act';
  const icon = isAct
    ? actEmoji(event.event)
    : eventIcons[event.event] || categoryIcons[event.category] || '•';

  // A row from an older server carries no details object at all, and the
  // ruling slot reads this before any arm of the summary does.
  const d = event.details ?? {};
  const receipt = d.receipt;
  const actorName = event.actor_name || (event.actor_did ? displayNameForKey(event.actor_did) : '');
  // A home is not a person: it wears its own weight, and the rest of the
  // column is one colour whatever the row is about.
  const isHome = (event.actor_did || '').startsWith('did:web:');

  // What the row says, as one line: every row carries the same marks in the
  // same slots, so the words are the only thing that changes.
  let summaryText: string;
  let summary: React.ReactNode;
  if (isAct) {
    // The verb's own word, as the cards say it, then whatever the step named
    // itself: a task event's own fields, not a sentence written about it.
    const said = [d.title, d.note].filter(Boolean).map(String);
    summaryText = [actHeadline(event.event), ...said].join(' · ');
    summary = (
      <>
        <span className="text-fg">{actHeadline(event.event)}</span>
        {said.map(part => (
          <Fragment key={part}> · <span className="text-fg-muted">{part}</span></Fragment>
        ))}
      </>
    );
  } else if (event.category === 'governance') {
    switch (event.event) {
      case 'pause': summaryText = `paused by ${readable(d.issuer_name || d.issued_by || '')}`; break;
      case 'resume': summaryText = `resumed by ${readable(d.issuer_name || d.issued_by || '')}`; break;
      case 'revoke': summaryText = `revoked by ${readable(d.issuer_name || d.issued_by || '')}`; break;
      case 'granted': summaryText = `granted: ${d.capability || ''}`; break;
      default: summaryText = event.event;
    }
    summary = summaryText;
  } else {
    // An event carries the name it was sent under, and nothing is written
    // about it here.
    summaryText = event.event;
    summary = <span className="font-mono text-[12px]">{event.event}</span>;
  }

  // The column speaks only when something is wrong: a step the home has not
  // ruled on, or one an earlier step beat. A confirmed step says nothing.
  const state = d.confirm_state === 'unconfirmed' || d.confirm_state === 'superseded'
    ? String(d.confirm_state)
    : '';

  const detailRows: Array<[string, React.ReactNode]> = isAct
    ? actDetailFacts(event, d).map(([label, value]) => [label, value] as [string, React.ReactNode])
    : Object.entries(d)
        .filter(([key]) => key !== 'receipt')
        .map(([key, value]) => [key, readable(value)] as [string, React.ReactNode]);
  if (receipt) {
    // The ruling under its own key: the id, which a reader may want to copy,
    // and the check. Its signature is not drawn — an eye cannot check one and
    // `verify` does — and its stamp is the step's own stamp, already on the
    // row: the home rules on arrival.
    detailRows.push([
      'receipt',
      <>
        {receipt.event_id}{' '}
        <button
          className="underline decoration-dotted hover:text-fg-muted"
          title="Check the receipt's signature"
          onClick={e => { e.stopPropagation(); onVerify(receipt.event_id, !!receipt.signature, { x: e.clientX, y: e.clientY }); }}
        >
          verify
        </button>
      </>,
    ]);
  }

  return (
    <div>
      {/* The disclosures are siblings of the row, never cells in it: a block
          inside the grid moved the row's own line as it opened. */}
      <div
        data-testid="audit-row"
        className="grid grid-cols-[64px_24px_128px_minmax(0,1fr)_96px_88px] @max-[640px]:grid-cols-[44px_20px_minmax(0,1fr)] items-center gap-2.5 @max-[640px]:gap-x-2 @max-[640px]:gap-y-0.5 min-h-[30px] px-2 @max-[640px]:px-1 rounded hover:bg-surface/30 text-[13px] leading-[1.3]"
      >
        <span
          data-testid="audit-time"
          className="font-mono text-[11px] @max-[640px]:text-[10.5px] text-fg-dim tabular-nums self-center"
        >
          {time.slice(0, -3)}
          <span className="@max-[640px]:hidden">{time.slice(-3)}</span>
        </span>
        <span className="text-center text-[14px] leading-none self-center">{icon}</span>
        {/* Two columns where there is room; one line, name then summary, where
            there is not. */}
        <span className="contents @max-[640px]:flex @max-[640px]:min-w-0 @max-[640px]:items-baseline @max-[640px]:gap-1.5">
          {/* On one line the summary is what gives way; a name shortened to
              its first letter names nobody. */}
          <span className={`text-[12.5px] min-w-0 truncate @max-[640px]:shrink-0 ${isHome ? 'font-medium text-fg-muted' : 'font-semibold text-fg'}`}>
            {actorName}
          </span>
          {/* One line, and the whole of it on hover, the way the task-id chip
              already answers. */}
          <span data-testid="audit-summary" className="min-w-0 text-fg-muted truncate" title={summaryText}>{summary}</span>
        </span>
        <span className="contents @max-[640px]:col-start-3 @max-[640px]:flex @max-[640px]:items-center @max-[640px]:justify-end @max-[640px]:gap-1.5">
          <span
            data-testid="audit-ruling"
            className="text-[10px] text-warning text-right"
            title={STATE_HOVER[state]}
          >
            {state}
          </span>
          <span className="grid grid-cols-[20px_44px_20px] items-center justify-items-center gap-0.5">
            {/* The seal says which rules were enforced, and opens the same
                panel it opens on a card. */}
            {isAct ? (
              <Seal
                title={sealPanelHeader(String(d.kind ?? ''))}
                onClick={() => setOpen(open === 'seal' ? null : 'seal')}
              />
            ) : <span />}
            {event.event_id ? (
              <button
                className="text-[10px] text-fg-dim hover:text-fg-muted underline decoration-dotted"
                title="Check this event's signature"
                onClick={e => { e.stopPropagation(); onVerify(event.event_id!, !!event.signature, { x: e.clientX, y: e.clientY }); }}
              >
                verify
              </button>
            ) : <span />}
            <button
              aria-label="Details"
              aria-expanded={open === 'details'}
              className="text-fg-dim hover:text-fg-muted p-1 inline-flex"
              onClick={() => setOpen(open === 'details' ? null : 'details')}
            >
              <svg className={`w-3 h-3 transition-transform ${open === 'details' ? '' : '-rotate-90'}`} viewBox="0 0 16 16" fill="currentColor">
                <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
          </span>
        </span>
      </div>
      {open === 'details' && (
        <div
          data-testid="audit-details"
          className="w-full min-w-0 mt-0.5 mb-1.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 bg-surface rounded px-3 py-2 text-[10px] text-fg-dim"
        >
          {detailRows.map(([label, value]) => (
            <Fragment key={label}>
              <span>{label}</span>
              <span data-testid="audit-detail-value" className="text-fg-muted break-all">{value}</span>
            </Fragment>
          ))}
        </div>
      )}
      {open === 'seal' && (
        <div className="w-full min-w-0 mt-0.5 mb-1.5 bg-surface rounded">
          {/* No task timeline on this surface, so the panel shows no link to
              one — the rule the cards doc states for the other clients. */}
          <SealPanel kind={String(d.kind ?? '')} verb={event.event} />
        </div>
      )}
    </div>
  );
}

