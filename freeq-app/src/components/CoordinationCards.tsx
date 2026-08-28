/**
 * Coordination event cards for Phase 3: Coordinated Work.
 *
 * When a message has +freeq.at/event tags, it renders as a structured card
 * instead of plain text. Falls back gracefully for unknown event types.
 */
import React, { useState } from 'react';
import type { Message } from '../store';

// ─── Helpers ────────────────────────────────────────

function tag(msg: Message, key: string): string | undefined {
  return msg.tags?.[`+freeq.at/${key}`] || msg.tags?.[`freeq.at/${key}`];
}

function PhaseIcon({ phase }: { phase?: string }) {
  const icons: Record<string, string> = {
    specifying: '📝', designing: '🏗', building: '🔨', reviewing: '🔍',
    testing: '🧪', deploying: '🚀', monitoring: '📊',
  };
  return <span>{icons[phase || ''] || '📌'}</span>;
}

function EvidenceIcon({ type }: { type?: string }) {
  const icons: Record<string, string> = {
    spec_document: '📄', architecture_doc: '📐', file_manifest: '📁',
    code_review: '🔍', test_result: '🧪', deploy_log: '🚀',
    commit: '📦', artifact_link: '🔗',
  };
  return <span>{icons[type || ''] || '📎'}</span>;
}

function TaskIdBadge({ taskId }: { taskId?: string }) {
  if (!taskId) return null;
  const short = taskId.length > 10 ? taskId.slice(0, 10) + '…' : taskId;
  return (
    <span className="text-[10px] font-mono text-fg-dim/60 ml-1" title={taskId}>
      {short}
    </span>
  );
}

// ─── Card Wrapper ───────────────────────────────────

export function CardFrame({ icon, label, children, msg, className }: {
  icon: string;
  label: string;
  children: React.ReactNode;
  msg: Message;
  className?: string;
}) {
  const taskId = tag(msg, 'ref') || tag(msg, 'task-id');

  return (
    <div className={`mt-1 rounded-lg border border-border/50 overflow-hidden ${className || ''}`}>
      <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-surface/50 text-xs text-fg-dim">
        <span>{icon}</span>
        <span className="font-semibold text-fg-muted">{label}</span>
        <TaskIdBadge taskId={taskId} />
        <span className="ml-auto text-[10px] text-fg-dim/50">
          {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </span>
      </div>
      <div className="px-2.5 py-2 text-sm">
        {children}
      </div>
    </div>
  );
}

// ─── Event Cards ────────────────────────────────────

function TaskRequestCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="📋" label="New Task" msg={msg} className="border-accent/30">
      <div className="text-fg whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

function TaskAcceptCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="👍" label="Task Accepted" msg={msg}>
      <div className="text-fg-muted whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

function TaskUpdateCard({ msg }: { msg: Message }) {
  const phase = tag(msg, 'phase');
  return (
    <CardFrame icon="" label="" msg={msg}>
      <div className="flex items-center gap-1.5">
        <PhaseIcon phase={phase} />
        {phase && <span className="text-xs font-semibold text-accent capitalize">{phase}</span>}
        <span className="text-fg-muted">{msg.text}</span>
      </div>
    </CardFrame>
  );
}

function TaskCompleteCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="🎉" label="Task Complete" msg={msg} className="border-success/30">
      <div className="text-success whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

function TaskFailedCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="❌" label="Task Failed" msg={msg} className="border-error/30">
      <div className="text-error whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

function EvidenceCard({ msg }: { msg: Message }) {
  const [expanded, setExpanded] = useState(false);
  const evidenceType = tag(msg, 'evidence-type') || 'evidence';
  const payload = tag(msg, 'payload');

  let parsedPayload: any = null;
  if (payload) {
    try { parsedPayload = JSON.parse(payload); } catch {}
  }

  return (
    <CardFrame icon="" label="" msg={msg}>
      <div
        className="flex items-center gap-1.5 cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <EvidenceIcon type={evidenceType} />
        <span className="text-xs font-semibold text-fg-dim capitalize">
          {evidenceType.replace(/_/g, ' ')}
        </span>
        <span className="text-fg-muted flex-1">{msg.text}</span>
        <span className="text-[10px] text-fg-dim/50">{expanded ? '▼' : '▶'}</span>
      </div>
      {expanded && parsedPayload && (
        <pre className="mt-2 p-2 bg-surface rounded text-[12px] font-mono text-fg-dim overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(parsedPayload, null, 2)}
        </pre>
      )}
    </CardFrame>
  );
}

function DelegationCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="🔀" label="Delegation" msg={msg}>
      <div className="text-fg-muted whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

function StatusUpdateCard({ msg }: { msg: Message }) {
  return (
    <CardFrame icon="💬" label="Status" msg={msg}>
      <div className="text-fg-muted whitespace-pre-wrap">{msg.text}</div>
    </CardFrame>
  );
}

// ─── Dispatcher ─────────────────────────────────────

/**
 * Check if a message is a coordination event and render the appropriate card.
 * Returns null if not a coordination event (caller should render normally).
 */
export function CoordinationEventCard({ msg }: { msg: Message }): React.ReactElement | null {
  const eventType = tag(msg, 'event');
  if (!eventType) return null;

  switch (eventType) {
    case 'task_request':
      return <TaskRequestCard msg={msg} />;
    case 'task_accept':
      return <TaskAcceptCard msg={msg} />;
    case 'task_update':
      return <TaskUpdateCard msg={msg} />;
    case 'task_complete':
      return <TaskCompleteCard msg={msg} />;
    case 'task_failed':
      return <TaskFailedCard msg={msg} />;
    case 'evidence_attach':
      return <EvidenceCard msg={msg} />;
    case 'delegation_notice':
      return <DelegationCard msg={msg} />;
    case 'status_update':
      return <StatusUpdateCard msg={msg} />;
    default:
      // Unknown event type — show as a generic card
      return (
        <CardFrame icon="📌" label={eventType} msg={msg}>
          <div className="text-fg-muted whitespace-pre-wrap">{msg.text}</div>
        </CardFrame>
      );
  }
}

/**
 * Returns true if the message is a coordination event.
 */
export function isCoordinationEvent(msg: Message): boolean {
  return !!(tag(msg, 'event'));
}
