import { useStore } from '../store';

export function BookmarksPanel() {
  const open = useStore((s) => s.bookmarksPanelOpen);
  const bookmarks = useStore((s) => s.bookmarks);
  const removeBookmark = useStore((s) => s.removeBookmark);
  const setActive = useStore((s) => s.setActiveChannel);
  const setScrollToMsgId = useStore((s) => s.setScrollToMsgId);
  const setOpen = useStore((s) => s.setBookmarksPanelOpen);

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={() => setOpen(false)} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-80 bg-bg-secondary border-l border-border shadow-2xl animate-slideIn overflow-y-auto">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="font-semibold flex items-center gap-2">
            <span>🔖</span> Bookmarks
          </h2>
          <button onClick={() => setOpen(false)} className="text-fg-dim hover:text-fg text-lg">✕</button>
        </div>

        {bookmarks.length === 0 ? (
          <div className="p-8 text-center">
            <div className="text-3xl mb-3">🔖</div>
            <div className="text-sm text-fg-muted">No bookmarks yet</div>
            <div className="text-xs text-fg-dim mt-1">Right-click a message → Bookmark</div>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {[...bookmarks].reverse().map((bm) => (
              <div key={bm.msgId} className="px-4 py-3 hover:bg-bg-tertiary/50">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold text-accent">{bm.from}</span>
                  <span className="text-[10px] text-fg-dim">{bm.channel}</span>
                  <span className="text-[10px] text-fg-dim ml-auto">
                    {bm.timestamp.toLocaleDateString([], { month: 'short', day: 'numeric' })}
                  </span>
                </div>
                <div className="text-sm text-fg-muted line-clamp-3">{bm.text}</div>
                <div className="flex gap-2 mt-2">
                  <button
                    onClick={() => {
                      // The channel first, then the row: the list mounts for
                      // the new buffer with the row already asked for, and
                      // fetches the window around it if it holds neither.
                      setActive(bm.channel);
                      setScrollToMsgId(bm.msgId);
                      setOpen(false);
                    }}
                    className="text-[11px] text-accent hover:underline"
                  >
                    Go to message
                  </button>
                  <button
                    onClick={() => removeBookmark(bm.msgId)}
                    className="text-[11px] text-fg-dim hover:text-danger"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
