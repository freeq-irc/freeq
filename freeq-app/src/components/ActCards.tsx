/**
 * Task event cards.
 *
 * A task event rides as a TAGMSG the message list never shows; the line its
 * sender wrote beside it is what a reader sees, and that line becomes this
 * card. Every event keeps a card of its own — the headline is the word for
 * the verb that event carried, never a word read off the task's state, so a
 * progress report never reads as a claim.
 *
 * An act card is the coloured class: one hue, taken from the register of the
 * state its step lands the action in, on the headline word, a left edge every
 * act card carries, and the border. The generic event card wears neither, and
 * the edge is how a reader tells the two apart.
 */
import React, { useState } from 'react';
import { createPortal } from 'react-dom';
import type { Message, ActTask, ActEvent } from '../store';
import { TaskTimeline } from './TaskTimeline';
import { useStore } from '../store';
import { actHeadline, actEmoji, actRegister, type ActRegister } from '../lib/act-verbs';
import { sealPanelHeader, sealPanelSentence, sealPanelLinkText } from '../lib/seal-panel-copy';

/**
 * The hue each register wears, in this client's own tokens.
 *
 * Written out rather than composed, because the class names have to survive
 * into the stylesheet as literals.
 */
const PAINT: Record<ActRegister, { word: string; edge: string; border: string }> = {
  new: { word: 'text-purple', edge: 'border-l-purple', border: 'border-purple/30' },
  inProgress: { word: 'text-blue', edge: 'border-l-blue', border: 'border-blue/30' },
  endedWell: { word: 'text-success', edge: 'border-l-success', border: 'border-success/30' },
  didNotEndWell: { word: 'text-danger', edge: 'border-l-danger', border: 'border-danger/30' },
  neutralEnd: { word: 'text-warning', edge: 'border-l-warning', border: 'border-warning/30' },
};

function TaskIdBadge({ taskId, onClick }: { taskId?: string; onClick: () => void }) {
  if (!taskId) return null;
  const short = taskId.length > 10 ? taskId.slice(0, 10) + '…' : taskId;
  return (
    <span
      className="text-[10px] font-mono text-fg-dim/60 ml-1 cursor-default hover:underline"
      title={taskId}
      onClick={onClick}
    >
      {short}
    </span>
  );
}

/**
 * The seal: the mark that says a server checked this step against the action's
 * rules before it filed it.
 *
 * Monochrome always — it is never the card's hue and never green, because a
 * seal that borrowed the hue would read as part of the outcome rather than as
 * a statement about the rules. The glyph is the rosette the other three
 * clients draw (`checkmark.seal` on Apple, `verified` on Android), inline so
 * it inherits `currentColor` and nothing else.
 */
function Seal({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      data-testid="act-seal"
      aria-label="What the server enforced"
      onClick={onClick}
      className="text-fg-dim hover:text-fg-muted leading-none"
    >
      <svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" aria-hidden="true">
        <path d="M23 12l-2.44-2.79.34-3.69-3.61-.82-1.89-3.2L12 2.96 8.6 1.5 6.71 4.69 3.1 5.5l.34 3.7L1 12l2.44 2.79-.34 3.7 3.61.82L8.6 22.5l3.4-1.47 3.4 1.46 1.89-3.19 3.61-.82-.34-3.69L23 12zm-12.91 4.72l-3.8-3.81 1.48-1.48 2.32 2.33 5.85-5.87 1.48 1.48-7.33 7.35z" />
      </svg>
    </button>
  );
}

/**
 * The disclosure behind the seal: what the server enforced on this one step,
 * and the way through to the whole action.
 *
 * The sentence is picked off the role the rules file gives the verb, never off
 * the verb's name and never off the kind. A verb the rules file does not name
 * has no rule about a person to state, so the panel states none.
 */
function SealPanel({ kind, verb, onHistory }: {
  kind: string;
  verb: string;
  onHistory: () => void;
}) {
  const sentence = sealPanelSentence(verb);
  return (
    <div
      data-testid="act-seal-panel"
      className="border-t border-border/50 px-2.5 py-2 text-[11px] leading-relaxed"
    >
      <div className="font-semibold text-fg-muted uppercase tracking-wide">
        {sealPanelHeader(kind)}
      </div>
      {sentence && <p className="mt-1 text-fg-dim">{sentence}</p>}
      <button
        type="button"
        data-testid="act-seal-history"
        onClick={onHistory}
        className="mt-1.5 text-accent hover:underline"
      >
        {sealPanelLinkText()}
      </button>
    </div>
  );
}

/**
 * The cards either side of this one, by companion msgid.
 *
 * A task's cards are its events in the order they were made, minus the two
 * the home signs for itself: those are system lines, with no card to land on.
 * Absent at each end, which is what stops the links being offered there.
 */
export function cardNeighbours(task: ActTask, event: ActEvent): { prev?: string; next?: string } {
  const cards = task.events.filter(e => e.msgId);
  const i = cards.findIndex(e => e.eventId === event.eventId);
  if (i === -1) return {};
  return { prev: cards[i - 1]?.msgId, next: cards[i + 1]?.msgId };
}

export function ActEventCard({ msg, task, event }: {
  msg: Message;
  task: ActTask;
  event: ActEvent;
}) {
  const [open, setOpen] = useState(false);
  const sealOpen = useStore(s => s.sealPanelFor === msg.id);
  const setSealPanelFor = useStore(s => s.setSealPanelFor);
  const setScrollToMsgId = useStore(s => s.setScrollToMsgId);
  const note = event.fields['act-note'];
  const ctx = event.fields['act-ctx'];
  const kind = event.fields['act'] || task.kind;
  const { prev, next } = cardNeighbours(task, event);
  // A system verb draws no card at all, so the fallback is only ever reached
  // by a verb the rules file has not been taught.
  const paint = PAINT[actRegister(event.verb) ?? 'neutralEnd'];
  const taskId = msg.tags?.['+freeq.at/ref'] || msg.tags?.['+freeq.at/task-id'];

  return (
    <>
      {/* The title and the task id are the way into the history; the rest of
          the card body takes no click. */}
      <div data-testid="act-card">
        <div
          className={`mt-1 rounded-lg border overflow-hidden border-l-[3px] ${paint.border} ${paint.edge}`}
        >
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-surface/50 text-xs text-fg-dim">
            <span>{actEmoji(event.verb)}</span>
            <span
              data-testid="act-headline"
              className={`font-semibold uppercase ${paint.word}`}
            >
              {actHeadline(event.verb)}
            </span>
            <TaskIdBadge taskId={taskId} onClick={() => setOpen(true)} />
            <Seal onClick={() => setSealPanelFor(sealOpen ? null : msg.id)} />
            <span className="ml-auto text-[10px] text-fg-dim/50">
              {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>


          <div className="px-2.5 py-2 text-sm">
            {task.title && (
              <div
                className="text-fg whitespace-pre-wrap cursor-default hover:underline"
                title="View full history"
                onClick={() => setOpen(true)}
              >
                {task.title}
              </div>
            )}
            {note && <div className="text-fg-muted whitespace-pre-wrap">{note}</div>}
            {ctx && (
              <a
                href={ctx}
                target="_blank"
                rel="noopener noreferrer"
                // The hash is what the signature covers, so it rides along for
                // anyone checking the bytes they fetched.
                title={event.fields['act-ctx-h']}
                className="text-accent hover:underline break-all text-xs"
              >
                {ctx}
              </a>
            )}
            {ctx && event.fields['act-ctx-h'] && (
              <div className="font-mono text-[10px] text-fg-dim break-all">
                {event.fields['act-ctx-h']}
              </div>
            )}
          </div>

          {sealOpen && (
            <SealPanel kind={kind} verb={event.verb} onHistory={() => setOpen(true)} />
          )}

          {(prev || next) && (
            // The links live under the body behind a hairline, so the header
            // stays the card's only filled strip.
            <div
              data-testid="card-footer"
              className="flex items-center border-t border-border/50 px-2.5 py-1.5 text-[11px]"
            >
              {prev && (
                <button className="text-fg-dim hover:text-fg-muted" onClick={() => setScrollToMsgId(prev)}>
                  ← prev
                </button>
              )}
              {next && (
                <button className="ml-auto text-fg-dim hover:text-fg-muted" onClick={() => setScrollToMsgId(next)}>
                  next →
                </button>
              )}
            </div>
          )}
        </div>
      </div>
      {open && createPortal(
        // Portaled to the body: rendered inline, this overlay lives inside a
        // virtualized list row, and rows after it hit-test above it — clicks
        // pass through the modal into the list behind.
        <div
          data-testid="act-timeline-modal"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          onClick={() => setOpen(false)}
        >
          <div onClick={e => e.stopPropagation()}>
            <TaskTimeline actId={task.taskId} onClose={() => setOpen(false)} />
          </div>
        </div>,
        document.body,
      )}
    </>
  );
}

/**
 * The task and event a message is the companion line of, if it is one.
 *
 * Reads the channel's task map, so it answers only for a message whose event
 * the store has already seen — which is every companion, once its event has
 * arrived, live or in replay.
 */
export function useActCompanion(msg: Message, channel?: string): { task: ActTask; event: ActEvent } | null {
  const actTasks = useStore(s => (channel ? s.channels.get(channel.toLowerCase())?.actTasks : undefined));
  const ref = msg.tags?.['+freeq.at/ref'];
  if (!ref) return null;
  const task = actTasks?.get(ref);
  if (!task) return null;
  const event = task.events.find(e => e.msgId === msg.id);
  return event ? { task, event } : null;
}
