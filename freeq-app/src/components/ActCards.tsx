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
import type { Message, ActTask, ActEvent } from '../store';
import { CardFrame } from './CoordinationCards';
import { TaskTimeline } from './TaskTimeline';
import { useStore } from '../store';
import { actHeadline } from '../lib/act-verbs';

export function ActEventCard({ msg, task, event }: {
  msg: Message;
  task: ActTask;
  event: ActEvent;
}) {
  const [open, setOpen] = useState(false);
  const note = event.fields['act-note'];
  const ctx = event.fields['act-ctx'];

  return (
    <>
      <div data-testid="act-card" onClick={() => setOpen(true)} className="cursor-pointer">
        <CardFrame icon="📋" label={actHeadline(event.verb)} msg={msg}>
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
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          onClick={() => setOpen(false)}
        >
          <div onClick={e => e.stopPropagation()}>
            <TaskTimeline actId={task.taskId} onClose={() => setOpen(false)} />
          </div>
        </div>
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
