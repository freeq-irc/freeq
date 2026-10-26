interface Props {
  onFormat: (prefix: string, suffix: string) => void;
}

export function FormatToolbar({ onFormat }: Props) {
  return (
    <div className="flex flex-wrap items-center gap-0.5 px-2 py-1 border-b border-border/50">
      <FmtBtn label="B" title="Bold (wrap with **)" className="font-bold" onClick={() => onFormat('**', '**')} />
      <FmtBtn label="I" title="Italic (wrap with *)" className="italic" onClick={() => onFormat('*', '*')} />
      <FmtBtn label="S" title="Strikethrough (wrap with ~~)" className="line-through" onClick={() => onFormat('~~', '~~')} />
      <FmtBtn label="<>" title="Inline code (wrap with `)" className="font-mono text-[11px]" onClick={() => onFormat('`', '`')} />
      <FmtBtn label="```" title="Code block" className="font-mono text-[10px]" onClick={() => onFormat('```\n', '\n```')} />
      <div className="w-px h-4 bg-border mx-1" />
      <FmtBtn label="🔗" title="Link" className="text-[12px]" onClick={() => onFormat('[', '](url)')} />
    </div>
  );
}

function FmtBtn({ label, title, className, onClick }: { label: string; title: string; className?: string; onClick: () => void }) {
  return (
    <button
      onMouseDown={(e) => { e.preventDefault(); onClick(); }}
      title={title}
      className={`px-2 py-1 text-xs text-fg-dim hover:text-fg hover:bg-bg-tertiary rounded transition-colors ${className || ''}`}
    >
      {label}
    </button>
  );
}
