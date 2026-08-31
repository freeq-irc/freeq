/**
 * Task event cards.
 *
 * A task event rides as a TAGMSG the message list never shows; the line its
 * sender wrote beside it is what a reader sees, and that line becomes this
 * card. Every event keeps a card of its own — the headline is the word for
 * the verb that event carried, never a word read off the task's state, so a
 * progress report never reads as a claim.
 */
import { useState } from 'react';
import { createPortal } from 'react-dom';
import type { Message, ActTask, ActEvent } from '../store';
import { CardFrame } from './CoordinationCards';
import { TaskTimeline } from './TaskTimeline';
import { useStore } from '../store';
import { actHeadline, actEmoji, actAccent, type ActAccent } from '../lib/act-verbs';

/**
 * The left edge each accent paints, in this client's own theme colours.
 *
 * Only the moves that put work on a plate, end well, or fail carry one —
 * an edge on every card is an edge that says nothing.
 */
const ACCENT_EDGE: Record<ActAccent, string> = {
  none: '',
  handoff: 'border-l-2 border-l-purple',
  success: 'border-l-2 border-l-success',
  failure: 'border-l-2 border-l-danger',
};

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
  const setScrollToMsgId = useStore(s => s.setScrollToMsgId);
  const note = event.fields['act-note'];
  const ctx = event.fields['act-ctx'];
  const { prev, next } = cardNeighbours(task, event);

  return (
    <>
      <div data-testid="act-card" onClick={() => setOpen(true)} className="cursor-pointer">
        <CardFrame
          icon={actEmoji(event.verb)}
          label={actHeadline(event.verb)}
          uppercaseLabel
          msg={msg}
          className={ACCENT_EDGE[actAccent(event.verb)]}
          footer={(prev || next) && (
            // The links live under the body behind a hairline, so the
            // header stays the card's only filled strip.
            <div className="flex w-full items-center" onClick={e => e.stopPropagation()}>
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
        >
          {task.title && <div className="text-fg whitespace-pre-wrap">{task.title}</div>}
          {note && <div className="text-fg-muted whitespace-pre-wrap">{note}</div>}
          {ctx && (
            <a
              href={ctx}
              target="_blank"
              rel="noopener noreferrer"
              // The hash is what the signature covers, so it rides along for
              // anyone checking the bytes they fetched.
              title={event.fields['act-ctx-h']}
              onClick={e => e.stopPropagation()}
              className="text-accent hover:underline break-all text-xs"
            >
              {ctx}
            </a>
          )}
        </CardFrame>
      </div>
      {open && createPortal(
        // Portaled to the body: rendered inline, this overlay lives inside a
        // virtualized list row, and rows after it hit-test above it — clicks
        // pass through the modal into the list behind.
        <div
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
