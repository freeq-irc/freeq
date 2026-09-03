/**
 * The generic event card.
 *
 * Every `+freeq.at/event` message renders through this one card, whatever the
 * event type says: there is no list of types that card and no per-type face,
 * so an event nobody has taught this client reads exactly like one it knows.
 * Grayscale and edgeless throughout — colour and a left edge belong to the act
 * cards, and are how a reader tells the two classes apart.
 */
import React from 'react';
import type { Message } from '../store';
import { payloadRows } from '../lib/event-payload';

// ─── Helpers ────────────────────────────────────────

function tag(msg: Message, key: string): string | undefined {
  return msg.tags?.[`+freeq.at/${key}`] || msg.tags?.[`freeq.at/${key}`];
}

// ─── The generic card ───────────────────────────────

/** The payload as always-visible rows. A long value scrolls inside its own
 *  row rather than growing the card. */
function PayloadRows({ msg }: { msg: Message }) {
  const rows = payloadRows(tag(msg, 'payload'));
  if (rows.length === 0) return null;
  return (
    <dl
      data-testid="event-payload"
      className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs"
    >
      {rows.map((row) => (
        <React.Fragment key={row.key}>
          <dt className="font-mono text-fg-dim">{row.key}</dt>
          <dd className="font-mono text-fg-muted max-h-24 overflow-auto whitespace-pre-wrap break-all">
            {row.value}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

/**
 * A coordination event as a card. Returns null only when the message carries
 * no event tag at all — every event type gets the same card.
 */
export function CoordinationEventCard({ msg }: { msg: Message }): React.ReactElement | null {
  const eventType = tag(msg, 'event');
  if (!eventType) return null;

  return (
    <div
      data-testid="event-card"
      className="mt-1 rounded-lg border border-border/50 overflow-hidden"
    >
      <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-surface/50 text-xs text-fg-dim">
        <span aria-hidden="true">◇</span>
        <span data-testid="event-card-type" className="font-mono text-fg-muted">
          {eventType.toLowerCase()}
        </span>
        <span className="ml-auto text-[10px] text-fg-dim/50">
          {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </span>
      </div>
      <div className="px-2.5 py-2 text-sm space-y-1.5">
        {msg.text && <div className="text-fg-muted whitespace-pre-wrap">{msg.text}</div>}
        <PayloadRows msg={msg} />
      </div>
    </div>
  );
}
