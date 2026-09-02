import { useState, useRef, useCallback, useEffect, useMemo, type KeyboardEvent, type DragEvent } from 'react';
import { useStore } from '../store';
import { sendMessage, sendReply, sendEdit, sendMarkdown, sendAction, joinChannel, partChannel, setTopic, setMode, kickUser, inviteUser, setAway, rawCommand, sendWhois, startTyping, stopTyping } from '../irc/client';
import { detectStepUpRequired, requestStepUp } from '../lib/oauth-step-up';
import { displayNameForKey } from '../lib/display-name';
import { EmojiPicker, EMOJI_DATA } from './EmojiPicker';
import { SlashCommands, getCommandCount } from './SlashCommands';
import { FormatToolbar } from './FormatToolbar';
import { apiFetch } from '../lib/api';

/** One `+typing=active` covers this long; keep sending while the box has
 *  text. Matches the cadence the other clients type at. */
const TYPING_INTERVAL_MS = 3000;

// Max file size: 10MB
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'audio/mpeg', 'audio/ogg', 'application/pdf'];

interface PendingUpload {
  file: File;
  preview?: string;
  uploading: boolean;
  error?: string;
}

export function ComposeBox() {
  const [text, setText] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyPos, setHistoryPos] = useState(-1);
  const [showEmoji, setShowEmoji] = useState(false);
  const [autocomplete, setAutocomplete] = useState<{ items: string[]; selected: number; startPos: number } | null>(null);
  const [slashCmd, setSlashCmd] = useState<{ filter: string; selected: number } | null>(null);
  const [showFormatBar, setShowFormatBar] = useState(false);
  const [markdownMode, setMarkdownMode] = useState(false);

  const applyFormat = (prefix: string, suffix: string) => {
    const el = inputRef.current;
    if (!el) return;
    const start = el.selectionStart || 0;
    const end = el.selectionEnd || 0;
    const selected = text.slice(start, end);
    const newText = text.slice(0, start) + prefix + selected + suffix + text.slice(end);
    setText(newText);
    // Place cursor after the formatted text
    requestAnimationFrame(() => {
      el.focus();
      const cursorPos = selected ? start + prefix.length + selected.length + suffix.length : start + prefix.length;
      el.setSelectionRange(cursorPos, cursorPos);
    });
  };
  const [pendingUpload, setPendingUpload] = useState<PendingUpload | null>(null);
  // Media is private to this channel/DM by default. These two opt-in toggles
  // are the only way bytes leave freeq: save a public copy to the user's PDS,
  // and/or also post it to their Bluesky feed (which implies the PDS copy).
  const [sharePds, setSharePds] = useState(false);
  const [shareBluesky, setShareBluesky] = useState(false);
  // Store the file in the user's own repo inside this channel's media space.
  // Offered only when the server has the feature configured.
  const [spaceMedia, setSpaceMedia] = useState(false);
  const [spacesAvailable, setSpacesAvailable] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const emojiRef = useRef<HTMLButtonElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);
  // When we last told the room we were composing; -Infinity is "never".
  const lastTypingSent = useRef(-Infinity);
  const activeChannel = useStore((s) => s.activeChannel);
  const channels = useStore((s) => s.channels);
  const authDid = useStore((s) => s.authDid);
  const replyTo = useStore((s) => s.replyTo);
  const editingMsg = useStore((s) => s.editingMsg);
  const ch = channels.get(activeChannel.toLowerCase());

  // Initialize edit mode with message text
  useEffect(() => {
    if (editingMsg && editingMsg.channel.toLowerCase() === activeChannel.toLowerCase()) {
      setText(editingMsg.text);
      inputRef.current?.focus();
    }
  }, [editingMsg]);

  // Focus on reply
  useEffect(() => {
    if (replyTo && replyTo.channel.toLowerCase() === activeChannel.toLowerCase()) {
      inputRef.current?.focus();
    }
  }, [replyTo]);

  // Members for autocomplete - use size as dependency since Map reference doesn't change
  const memberNicks = useMemo(() => {
    if (!ch) return [];
    return [...ch.members.values()].map((m) => m.nick).sort();
  }, [ch, ch?.members.size]);

  // Clear compose and focus on channel switch
  useEffect(() => {
    setText('');
    setAutocomplete(null);
    inputRef.current?.focus();
  }, [activeChannel]);

  // Autocomplete logic
  const updateAutocomplete = (value: string, cursorPos: number) => {
    const before = value.slice(0, cursorPos);
    const atIdx = before.lastIndexOf('@');
    if (atIdx >= 0 && (atIdx === 0 || before[atIdx - 1] === ' ')) {
      const partial = before.slice(atIdx + 1).toLowerCase();
      if (partial.length > 0) {
        const matches = memberNicks.filter((n) => n.toLowerCase().startsWith(partial));
        if (matches.length > 0) {
          setAutocomplete({ items: matches.slice(0, 8), selected: 0, startPos: atIdx });
          return;
        }
      }
    }
    const hashIdx = before.lastIndexOf('#');
    if (hashIdx >= 0 && (hashIdx === 0 || before[hashIdx - 1] === ' ')) {
      const partial = before.slice(hashIdx + 1).toLowerCase();
      if (partial.length > 0) {
        const chanNames = [...channels.values()].map((c) => c.name).filter((n) => n.toLowerCase().includes(partial));
        if (chanNames.length > 0) {
          setAutocomplete({ items: chanNames.slice(0, 8), selected: 0, startPos: hashIdx });
          return;
        }
      }
    }
    // Emoji autocomplete (:keyword)
    const colonIdx = before.lastIndexOf(':');
    if (colonIdx >= 0 && (colonIdx === 0 || before[colonIdx - 1] === ' ')) {
      const partial = before.slice(colonIdx + 1).toLowerCase();
      if (partial.length > 0 && !partial.includes(' ')) {
        const matches = EMOJI_DATA
          .filter(([, ...kws]) => kws.some(k => k.startsWith(partial) || k.includes(partial)))
          .slice(0, 8)
          .map(([emoji, ...kws]) => `${emoji} ${kws[0]}`);
        if (matches.length > 0) {
          setAutocomplete({ items: matches, selected: 0, startPos: colonIdx });
          return;
        }
      }
    }
    setAutocomplete(null);
  };

  const acceptAutocomplete = (item: string) => {
    if (!autocomplete) return;
    const before = text.slice(0, autocomplete.startPos);
    const after = text.slice(inputRef.current?.selectionStart || text.length);
    const isChannel = item.startsWith('#');
    const isEmoji = /^\p{Emoji}/u.test(item);
    let newText: string;
    if (isEmoji) {
      newText = before + item.split(' ')[0] + ' ' + after;
    } else {
      newText = before + (isChannel ? item : `@${item}`) + ' ' + after;
    }
    setText(newText);
    setAutocomplete(null);
    inputRef.current?.focus();
  };

  // ── File upload ──

  // Listen for file drops from FileDropOverlay
  useEffect(() => {
    const handler = (e: Event) => {
      const file = (e as CustomEvent).detail?.file;
      if (file) handleFileSelect(file);
    };
    window.addEventListener('freeq-file-drop', handler);
    return () => window.removeEventListener('freeq-file-drop', handler);
  }, []);

  const handleFileSelect = useCallback((file: File) => {
    if (!authDid) {
      useStore.getState().addSystemMessage(activeChannel, 'File upload requires AT Protocol authentication');
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      useStore.getState().addSystemMessage(activeChannel, `File too large (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`);
      return;
    }
    if (!ALLOWED_TYPES.includes(file.type) && !file.type.startsWith('image/')) {
      useStore.getState().addSystemMessage(activeChannel, `Unsupported file type: ${file.type}`);
      return;
    }

    const preview = file.type.startsWith('image/') ? URL.createObjectURL(file) : undefined;
    setPendingUpload({ file, preview, uploading: false });
  }, [authDid, activeChannel]);

  const cancelUpload = () => {
    if (pendingUpload?.preview) URL.revokeObjectURL(pendingUpload.preview);
    setPendingUpload(null);
    setSharePds(false);
    setShareBluesky(false);
    setSpaceMedia(false);
  };

  // Does this server offer private media spaces?
  useEffect(() => {
    let cancelled = false;
    fetch('/api/v1/health')
      .then((r) => (r.ok ? r.json() : null))
      .then((h) => { if (!cancelled && h?.media_spaces) setSpacesAvailable(true); })
      .catch(() => { /* keep option hidden */ });
    return () => { cancelled = true; };
  }, []);

  const doUpload = useCallback(async () => {
    if (!pendingUpload || !authDid) return;
    setPendingUpload((p) => p ? { ...p, uploading: true, error: undefined } : null);

    try {
      const buildForm = () => {
        const f = new FormData();
        f.append('file', pendingUpload.file);
        f.append('did', authDid);
        if (activeChannel !== 'server' && activeChannel.startsWith('#')) f.append('channel', activeChannel);
        if (text.trim()) f.append('alt', text.trim());
        // A file goes to exactly one destination: the channel's private
        // space, or a public PDS/Bluesky copy. The server rejects both at
        // once, so never send both.
        if (spaceMedia) {
          f.append('space_media', 'true');
          return f;
        }
        // share_bluesky implies share_pds (feed embed references the PDS blob).
        if (sharePds || shareBluesky) f.append('share_pds', 'true');
        if (shareBluesky) f.append('share_bluesky', 'true');
        return f;
      };

      let resp = await fetch('/api/v1/upload', { method: 'POST', body: buildForm() });

      // 403 step_up_required: the user has a Login session but hasn't
      // granted blob upload yet. Drive the step-up popup, then retry
      // once with a fresh form. This is the Phase 2 incremental-auth
      // path — we never asked for blob upload at sign-in time.
      const purpose = await detectStepUpRequired(resp);
      if (purpose === 'blob_upload' || purpose === 'media_space') {
        const outcome = await requestStepUp(purpose, authDid);
        if (outcome.ok) {
          resp = await fetch('/api/v1/upload', { method: 'POST', body: buildForm() });
        } else {
          // Tailor the message to *why* it failed so the user knows
          // whether to allow popups, retry, or wait less next time.
          const what = purpose === 'media_space' ? 'private media' : 'a public copy';
          const msg =
            outcome.reason === 'popup_blocked'
              ? `Allow popups for this site so freeq can ask your PDS for permission to save ${what}, then retry.`
              : outcome.reason === 'timeout'
                ? 'The permission popup timed out. Try the upload again.'
                : `Saving ${what} to your PDS needs one extra permission. Try again and complete the popup.`;
          throw new Error(msg);
        }
      }

      // If session expired, try to refresh via broker and retry once
      if (resp.status === 401) {
        const brokerToken = localStorage.getItem('freeq-broker-token');
        const brokerBase = localStorage.getItem('freeq-broker-base');
        console.log('[upload] 401 — attempting broker refresh', { hasBrokerToken: !!brokerToken, brokerBase });
        if (brokerToken && brokerBase) {
          try {
            const brokerBody = JSON.stringify({ broker_token: brokerToken });
            let refreshResp = await fetch(`${brokerBase}/session`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: brokerBody,
            });
            // Retry once on 502 (DPoP nonce rotation)
            if (refreshResp.status === 502) {
              refreshResp = await fetch(`${brokerBase}/session`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: brokerBody,
              });
            }
            console.log('[upload] broker refresh response:', refreshResp.status);
            if (refreshResp.ok) {
              // Broker pushed fresh OAuth session to server — retry upload
              resp = await fetch('/api/v1/upload', { method: 'POST', body: buildForm() });
              console.log('[upload] retry response:', resp.status);
            }
          } catch (e) {
            console.warn('[upload] broker refresh error:', e);
          }
        }
        if (resp.status === 401) {
          throw new Error('Upload session expired. Try refreshing the page, or log out and sign in again.');
        }
      }

      if (!resp.ok) {
        throw new Error(await resp.text());
      }

      const result = await resp.json();
      const target = ch?.name || activeChannel;
      if (target && target !== 'server') {
        // Send as PRIVMSG with the media URL (and alt text as message)
        const msgText = text.trim() ? `${text.trim()} ${result.url}` : result.url;
        sendMessage(target, msgText);
      }

      if (pendingUpload.preview) URL.revokeObjectURL(pendingUpload.preview);
      setPendingUpload(null);
      setText('');
      setSharePds(false);
      setShareBluesky(false);
      setSpaceMedia(false);
    } catch (e: any) {
      setPendingUpload((p) => p ? { ...p, uploading: false, error: e.message || 'Upload failed' } : null);
    }
  }, [pendingUpload, authDid, activeChannel, text, ch, sharePds, shareBluesky, spaceMedia]);

  // ── Drag & drop ──

  const onDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer?.types.includes('Files')) setDragOver(true);
  };

  const onDragLeave = (e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const file = e.dataTransfer?.files[0];
    if (file) handleFileSelect(file);
  };

  // ── Paste ──

  const onPaste = useCallback((e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
      if (item.kind === 'file') {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) handleFileSelect(file);
        return;
      }
    }
    // Auto-grow textarea after text paste
    setTimeout(() => {
      const el = inputRef.current;
      if (el) {
        el.style.height = 'auto';
        el.style.height = Math.min(el.scrollHeight, 200) + 'px';
      }
    }, 0);
  }, [handleFileSelect]);

  const cancelReplyEdit = () => {
    useStore.getState().setReplyTo(null);
    useStore.getState().setEditingMsg(null);
    setText('');
  };

  const submit = useCallback(() => {
    // If there's a pending upload, do that instead of sending text
    if (pendingUpload && !pendingUpload.uploading) {
      doUpload();
      return;
    }

    const trimmed = text.trim();
    if (!trimmed) return;
    setHistory((h) => [...h.slice(-100), trimmed]);
    setHistoryPos(-1);

    if (trimmed.startsWith('/')) {
      handleCommand(trimmed, activeChannel);
    } else if (activeChannel !== 'server') {
      const target = ch?.name || activeChannel;
      // The message itself is the news now — retract the typing hint, and let
      // the next keystroke re-announce without waiting out the interval.
      stopTyping(target);
      lastTypingSent.current = -Infinity;
      if (markdownMode) {
        sendMarkdown(target, trimmed);
      } else if (editingMsg && editingMsg.channel.toLowerCase() === activeChannel.toLowerCase()) {
        sendEdit(target, editingMsg.msgId, trimmed);
        useStore.getState().setEditingMsg(null);
      } else if (replyTo && replyTo.channel.toLowerCase() === activeChannel.toLowerCase()) {
        sendReply(target, replyTo.msgId, trimmed);
        useStore.getState().setReplyTo(null);
      } else {
        sendMessage(target, trimmed);
      }
    }
    setText('');
    setAutocomplete(null);
    if (inputRef.current) inputRef.current.style.height = 'auto';
  }, [text, activeChannel, ch, pendingUpload, doUpload, editingMsg, replyTo, markdownMode]);

  const onKeyDown = (e: KeyboardEvent) => {
    // Tab completion
    if (e.key === 'Tab') {
      e.preventDefault();
      e.stopPropagation();
      if (autocomplete) {
        acceptAutocomplete(autocomplete.items[autocomplete.selected]);
      } else {
        const el = inputRef.current;
        if (el) {
          const pos = el.selectionStart || 0;
          const before = text.slice(0, pos);
          const spIdx = before.lastIndexOf(' ');
          const partial = before.slice(spIdx + 1).toLowerCase();
          if (partial.length > 0) {
            const isAtPrefix = partial.startsWith('@');
            const search = isAtPrefix ? partial.slice(1) : partial;
            const match = memberNicks.find((n) => n.toLowerCase().startsWith(search));
            if (match) {
              const prefix = isAtPrefix ? '@' : '';
              const suffix = spIdx < 0 ? ': ' : ' ';
              const newText = before.slice(0, spIdx + 1) + prefix + match + suffix + text.slice(pos);
              setText(newText);
              setAutocomplete(null);
            }
          }
        }
      }
      return;
    }

    // Slash command autocomplete
    if (slashCmd) {
      if (e.key === 'Enter' || e.key === 'Tab') {
        // Don't select if it's an exact match and Enter (user wants to submit)
        // Only intercept Tab, or Enter when there's a partial filter
        if (e.key === 'Tab' || (slashCmd.filter && getCommandCount(slashCmd.filter) > 0)) {
          // Let the SlashCommands component handle via onSelect
          // Actually we need to select here
          e.preventDefault();
          // Get the filtered list and pick the selected one
          const filter = slashCmd.filter.toLowerCase();
          const COMMANDS = ['join','part','topic','invite','kick','op','deop','voice','mode','msg','me','md','whois','away','encrypt','decrypt','pins','policy','raw','help'];
          const filtered = filter ? COMMANDS.filter(c => c.startsWith(filter)) : COMMANDS;
          if (filtered[slashCmd.selected]) {
            setText(`/${filtered[slashCmd.selected]} `);
            setSlashCmd(null);
            setTimeout(onInput, 0);
          }
          return;
        }
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const count = getCommandCount(slashCmd.filter);
        setSlashCmd({ ...slashCmd, selected: Math.min(slashCmd.selected + 1, count - 1) });
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSlashCmd({ ...slashCmd, selected: Math.max(slashCmd.selected - 1, 0) });
        return;
      }
      if (e.key === 'Escape') {
        setSlashCmd(null);
        return;
      }
    }

    // Autocomplete navigation
    if (autocomplete) {
      if (e.key === 'Enter') {
        e.preventDefault();
        acceptAutocomplete(autocomplete.items[autocomplete.selected]);
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setAutocomplete({ ...autocomplete, selected: Math.min(autocomplete.selected + 1, autocomplete.items.length - 1) });
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setAutocomplete({ ...autocomplete, selected: Math.max(autocomplete.selected - 1, 0) });
        return;
      }
      if (e.key === 'Escape') {
        setAutocomplete(null);
        return;
      }
    }

    // Escape cancels pending upload, reply, or edit
    if (e.key === 'Escape') {
      if (pendingUpload) { cancelUpload(); return; }
      if (replyTo || editingMsg) { cancelReplyEdit(); return; }
    }

    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    } else if (e.key === 'ArrowUp' && !text && !editingMsg && !replyTo) {
      e.preventDefault();
      if (historyPos < 0 && history.length === 0) {
        // No history — try edit last own message (Slack-style)
        const msgs = ch?.messages;
        if (msgs) {
          for (let i = msgs.length - 1; i >= 0; i--) {
            const m = msgs[i];
            if (m.isSelf && !m.isSystem && !m.deleted) {
              useStore.getState().setEditingMsg({ msgId: m.id, text: m.text, channel: activeChannel });
              break;
            }
          }
        }
      } else if (history.length > 0) {
        const pos = historyPos < 0 ? history.length - 1 : Math.max(0, historyPos - 1);
        setHistoryPos(pos);
        setText(history[pos] || '');
      }
    } else if (e.key === 'ArrowDown' && historyPos >= 0) {
      e.preventDefault();
      const pos = historyPos + 1;
      if (pos >= history.length) {
        setHistoryPos(-1);
        setText('');
      } else {
        setHistoryPos(pos);
        setText(history[pos] || '');
      }
    }
  };

  const onInput = () => {
    const el = inputRef.current;
    if (el) {
      el.style.height = 'auto';
      el.style.height = Math.min(el.scrollHeight, 200) + 'px';
      updateAutocomplete(el.value, el.selectionStart || 0);

      // Slash command autocomplete
      const val = el.value;
      if (val.startsWith('/') && !val.includes(' ')) {
        const filter = val.slice(1);
        const count = getCommandCount(filter);
        if (count > 0) {
          setSlashCmd({ filter, selected: 0 });
        } else {
          setSlashCmd(null);
        }
      } else {
        setSlashCmd(null);
      }

      // Tell the room we are composing, at the cadence the rest of the
      // clients use. A quiet box says nothing; the server buffer has nobody
      // to say it to.
      if (activeChannel !== 'server' && el.value.trim()) {
        const now = Date.now();
        if (now - lastTypingSent.current >= TYPING_INTERVAL_MS) {
          lastTypingSent.current = now;
          startTyping(ch?.name || activeChannel);
        }
      }
    }
  };

  const canSend = activeChannel !== 'server' || text.startsWith('/');

  return (
    <div
      className={`border-t border-border bg-bg-secondary shrink-0 relative ${dragOver ? 'ring-2 ring-accent/50 ring-inset' : ''}`}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      {/* Drag overlay */}
      {dragOver && (
        <div className="absolute inset-0 bg-accent/5 flex items-center justify-center z-30 pointer-events-none">
          <div className="bg-bg-secondary border-2 border-dashed border-accent rounded-xl px-6 py-4 text-accent font-medium">
            Drop file to upload
          </div>
        </div>
      )}

      {/* Reply context */}
      {replyTo && replyTo.channel.toLowerCase() === activeChannel.toLowerCase() && (
        <div className="px-3 py-2 border-b border-border flex items-center gap-2 animate-fadeIn bg-accent/[0.03]">
          <div className="w-1 h-8 bg-accent rounded-full shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-xs text-accent font-bold">Replying to {replyTo.from}</div>
            <div className="text-xs text-fg-muted truncate">{replyTo.text}</div>
          </div>
          <button onClick={cancelReplyEdit} className="text-fg-dim hover:text-danger text-lg shrink-0 p-1">✕</button>
        </div>
      )}

      {/* Edit context */}
      {editingMsg && editingMsg.channel.toLowerCase() === activeChannel.toLowerCase() && (
        <div className="px-3 py-2 border-b border-border flex items-center gap-2 animate-fadeIn bg-warning/[0.03]">
          <div className="w-1 h-8 bg-warning rounded-full shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-xs text-warning font-bold">Editing message</div>
            <div className="text-xs text-fg-muted truncate">{editingMsg.text}</div>
          </div>
          <button onClick={cancelReplyEdit} className="text-fg-dim hover:text-danger text-lg shrink-0 p-1">✕</button>
        </div>
      )}

      {/* Pending upload preview */}
      {pendingUpload && (
        <div className="px-3 py-2 border-b border-border flex items-center gap-3 animate-fadeIn">
          {pendingUpload.preview ? (
            <img src={pendingUpload.preview} alt="" className="w-16 h-16 rounded-lg object-cover border border-border" />
          ) : (
            <div className="w-16 h-16 rounded-lg border border-border bg-bg-tertiary flex items-center justify-center text-fg-dim text-xl">
              📎
            </div>
          )}
          <div className="flex-1 min-w-0">
            <div className="text-sm text-fg truncate">{pendingUpload.file.name}</div>
            <div className="text-xs text-fg-dim">
              {(pendingUpload.file.size / 1024).toFixed(0)} KB · {pendingUpload.file.type}
            </div>
            {pendingUpload.error && (
              <div className="text-xs text-danger mt-0.5">{pendingUpload.error}</div>
            )}
            {authDid && (
              <div className="mt-1 space-y-0.5">
                <div className="flex items-center gap-1 text-[11px] text-fg-dim">
                  <span>🔒</span>
                  <span>Private to {ch?.name || activeChannel} by default</span>
                </div>
                {spacesAvailable && activeChannel.startsWith('#') && !ch?.isEncrypted && (
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={spaceMedia}
                      // A file goes to one place. Choosing the private space
                      // clears the public options rather than letting the
                      // server silently drop them.
                      onChange={(e) => {
                        setSpaceMedia(e.target.checked);
                        if (e.target.checked) { setSharePds(false); setShareBluesky(false); }
                      }}
                      className="w-3 h-3 rounded accent-blue"
                    />
                    <span className="text-sm text-fg-dim">
                      Keep it on my PDS ({ch?.modes.has('i') || ch?.modes.has('k')
                        ? 'private to this channel'
                        : 'anyone who can read this channel'})
                    </span>
                  </label>
                )}
                <label className={`flex items-center gap-1.5 ${spaceMedia ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}>
                  <input
                    type="checkbox"
                    checked={!spaceMedia && (sharePds || shareBluesky)}
                    disabled={shareBluesky || spaceMedia}
                    onChange={(e) => setSharePds(e.target.checked)}
                    className="w-3 h-3 rounded accent-blue"
                  />
                  <span className="text-sm text-fg-dim">Save a public copy to my PDS</span>
                </label>
                <label className={`flex items-center gap-1.5 ${spaceMedia ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}>
                  <input
                    type="checkbox"
                    checked={!spaceMedia && shareBluesky}
                    disabled={spaceMedia}
                    onChange={(e) => setShareBluesky(e.target.checked)}
                    className="w-3 h-3 rounded accent-blue"
                  />
                  <span className="text-sm text-fg-dim">Also post to Bluesky feed</span>
                  <span className="text-[10px]">🦋</span>
                </label>
              </div>
            )}
          </div>
          {pendingUpload.uploading ? (
            <svg className="animate-spin w-5 h-5 text-accent shrink-0" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          ) : (
            <button onClick={cancelUpload} className="text-fg-dim hover:text-danger text-lg shrink-0 p-1" title="Cancel">
              ✕
            </button>
          )}
        </div>
      )}

      {/* Slash command autocomplete */}
      {slashCmd && (
        <SlashCommands
          filter={slashCmd.filter}
          selected={slashCmd.selected}
          onSelect={(cmd) => {
            setText(`/${cmd} `);
            setSlashCmd(null);
            inputRef.current?.focus();
          }}
        />
      )}

      {/* Autocomplete dropdown */}
      {autocomplete && (
        <div className="absolute bottom-full left-3 mb-1 bg-bg-secondary border border-border rounded-lg shadow-2xl overflow-hidden animate-fadeIn z-20 min-w-[200px]">
          {autocomplete.items.map((item, i) => (
            <button
              key={item}
              onClick={() => acceptAutocomplete(item)}
              onMouseEnter={() => setAutocomplete({ ...autocomplete, selected: i })}
              className={`w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 ${
                i === autocomplete.selected ? 'bg-bg-tertiary text-fg' : 'text-fg-muted'
              }`}
            >
              {item.startsWith('#') ? (
                <span className="text-accent text-xs">#</span>
              ) : /^\p{Emoji}/u.test(item) ? (
                <span className="text-base">{item.split(' ')[0]}</span>
              ) : (
                <span className="text-purple text-xs">@</span>
              )}
              {/^\p{Emoji}/u.test(item) ? item.split(' ').slice(1).join(' ') : item.replace(/^#/, '')}
            </button>
          ))}
        </div>
      )}

      <div className="flex items-end gap-2.5 px-4 py-3">
        {/* File upload button (only for AT-authenticated users) */}
        {authDid && activeChannel !== 'server' && (
          <>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-9 h-9 rounded-lg flex items-center justify-center text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary shrink-0"
              title="Upload file (or drag & drop, or paste)"
            >
              <svg className="w-4 h-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M14 10v3a1 1 0 01-1 1H3a1 1 0 01-1-1v-3M11 5L8 2M8 2L5 5M8 2v8" />
              </svg>
            </button>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              accept="image/*,video/mp4,video/webm,audio/mpeg,audio/ogg,application/pdf"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileSelect(file);
                e.target.value = '';
              }}
            />
            {/* Camera capture (mobile) */}
            <button
              onClick={() => cameraInputRef.current?.click()}
              className="w-9 h-9 rounded-lg items-center justify-center text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary shrink-0 hidden max-sm:flex"
              title="Take photo"
            >
              <svg className="w-4 h-4" viewBox="0 0 16 16" fill="currentColor">
                <path d="M10.5 8.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"/>
                <path d="M2 4a2 2 0 00-2 2v6a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1.172a2 2 0 01-1.414-.586l-.828-.828A2 2 0 009.172 2H6.828a2 2 0 00-1.414.586l-.828.828A2 2 0 013.172 4H2zm.5 2a.5.5 0 110-1 .5.5 0 010 1zm9 2.5a3.5 3.5 0 11-7 0 3.5 3.5 0 017 0z"/>
              </svg>
            </button>
            <input
              ref={cameraInputRef}
              type="file"
              className="hidden"
              accept="image/*"
              capture="environment"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileSelect(file);
                e.target.value = '';
              }}
            />
          </>
        )}

        {/* Emoji button */}
        <button
          ref={emojiRef}
          onClick={() => setShowEmoji(!showEmoji)}
          className="w-10 h-10 rounded-lg flex items-center justify-center text-lg text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary shrink-0"
          title="Emoji"
        >
          😊
        </button>

        {/* Format toggle */}
        <button
          onClick={() => setShowFormatBar(!showFormatBar)}
          className={`w-10 h-10 rounded-lg flex items-center justify-center text-sm shrink-0 ${
            showFormatBar ? 'text-accent bg-accent/10' : 'text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary'
          }`}
          title="Formatting"
        >
          Aa
        </button>

        {/* Markdown mode toggle */}
        <button
          onClick={() => setMarkdownMode(!markdownMode)}
          className={`w-10 h-10 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${
            markdownMode ? 'text-accent bg-accent/10' : 'text-fg-dim hover:text-fg-muted hover:bg-bg-tertiary'
          }`}
          title={markdownMode ? 'Markdown mode ON — click to disable' : 'Enable markdown mode'}
        >
          M↓
        </button>

        {/* Compose area */}
        <div className={`flex-1 bg-bg-tertiary rounded-lg border focus-within:border-accent/50 flex flex-col ${markdownMode ? 'border-accent/30' : 'border-border'}`}>
          {markdownMode && (
            <div className="px-3 py-1 text-[10px] text-accent font-medium border-b border-accent/20 bg-accent/[0.03]">
              Markdown — headers, lists, tables, code blocks will render
            </div>
          )}
          {showFormatBar && <FormatToolbar onFormat={applyFormat} />}
          <div className="flex items-end">
          <textarea
            data-testid="compose-input"
            aria-label={`Message ${displayNameForKey(activeChannel)}`}
            ref={inputRef}
            value={text}
            onChange={(e) => { setText(e.target.value); onInput(); }}
            onKeyDown={onKeyDown}
            onPaste={onPaste}
            placeholder={
              pendingUpload
                ? 'Add a caption (optional)...'
                : activeChannel === 'server'
                  ? 'Type /help for commands...'
                  : ch?.isEncrypted
                    ? `🔒 Message ${displayNameForKey(ch?.name || activeChannel)} (encrypted)`
                    : `Message ${displayNameForKey(ch?.name || activeChannel)}`
            }
            rows={1}
            className="flex-1 bg-transparent px-3 py-2.5 text-base text-fg outline-none placeholder:text-fg-dim resize-none min-h-[44px] max-h-[200px] leading-relaxed"
            autoComplete="off"
            spellCheck
          />
          </div>
        </div>

        {/* Send */}
        <button
          onClick={submit}
          disabled={(!text.trim() && !pendingUpload) || !canSend}
          className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
            (text.trim() || pendingUpload) && canSend
              ? 'bg-accent text-black hover:bg-accent-hover'
              : 'bg-bg-tertiary text-fg-dim cursor-not-allowed'
          }`}
          title={pendingUpload ? 'Upload' : 'Send'}
        >
          {pendingUpload ? (
            <svg className="w-4 h-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M14 10v3a1 1 0 01-1 1H3a1 1 0 01-1-1v-3M11 5L8 2M8 2L5 5M8 2v8" />
            </svg>
          ) : (
            <svg className="w-4 h-4" viewBox="0 0 16 16" fill="currentColor">
              <path d="M15.854 8.354a.5.5 0 000-.708L12.207 4l-.707.707L14.293 7.5H1v1h13.293l-2.793 2.793.707.707 3.647-3.646z"/>
            </svg>
          )}
        </button>
      </div>

      {/* Emoji picker */}
      {showEmoji && (
        <div className="absolute bottom-full left-3 mb-2 z-50">
          <EmojiPicker
            onSelect={(emoji) => {
              setText((t) => t + emoji);
              setShowEmoji(false);
              inputRef.current?.focus();
            }}
            onClose={() => setShowEmoji(false)}
          />
        </div>
      )}
    </div>
  );
}

function handleCommand(text: string, activeChannel: string) {
  const sp = text.indexOf(' ');
  const cmd = (sp > 0 ? text.slice(1, sp) : text.slice(1)).toLowerCase();
  const args = sp > 0 ? text.slice(sp + 1) : '';
  const store = useStore.getState();
  const target = activeChannel !== 'server'
    ? store.channels.get(activeChannel.toLowerCase())?.name || activeChannel
    : '';

  switch (cmd) {
    case 'join': case 'j': {
      // Trim spaces around the commas for multiple channel lists.
      const [chanList = '', keyList = ''] = args.trim().replace(/\s*,\s*/g, ',').split(/\s+/);
      const keys = keyList.split(',');
      chanList.split(',').filter(Boolean).forEach((c, i) =>
        joinChannel(c.startsWith('#') ? c : `#${c}`, keys[i] || undefined)
      );
      break;
    }
    case 'part': case 'leave':
      partChannel(args || target);
      break;
    case 'topic': case 't':
      if (target) setTopic(target, args);
      break;
    case 'mode': case 'm':
      if (args) rawCommand(`MODE ${args.startsWith('#') ? '' : target + ' '}${args}`);
      else if (target) rawCommand(`MODE ${target}`);
      break;
    case 'kick': case 'k': {
      const kp = args.split(' ');
      if (kp[0] && target) kickUser(target, kp[0], kp.slice(1).join(' ') || undefined);
      break;
    }
    case 'op': if (args && target) setMode(target, '+o', args); break;
    case 'deop': if (args && target) setMode(target, '-o', args); break;
    case 'voice': if (args && target) setMode(target, '+v', args); break;
    case 'invite': if (args && target) inviteUser(target, args); break;
    case 'away': setAway(args || undefined); break;
    case 'whois': case 'wi': if (args) sendWhois(args); break;
    case 'msg': case 'query': {
      const mp = args.split(' ');
      if (mp[0] && mp[1]) sendMessage(mp[0], mp.slice(1).join(' '));
      break;
    }
    case 'md': case 'markdown':
      if (args && target) sendMarkdown(target, args);
      break;
    case 'pins': {
      if (!target) break;
      const chanName = target.startsWith('#') ? target.slice(1) : target;
      apiFetch(`${window.location.origin}/api/v1/channels/${encodeURIComponent(chanName)}/pins`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          const pins = data?.pins || [];
          if (pins.length === 0) {
            store.addSystemMessage(activeChannel, `No pinned messages in ${target}`);
          } else {
            store.addSystemMessage(activeChannel, `── Pinned messages in ${target} (${pins.length}) ──`);
            for (const p of pins) {
              store.addSystemMessage(activeChannel, `📌 ${p.from}: ${p.text}`);
            }
          }
        })
        .catch(() => store.addSystemMessage(activeChannel, `Failed to fetch pins for ${target}`));
      break;
    }
    case 'me': case 'action':
      if (target) sendAction(target, args);
      break;
    case 'raw': case 'quote':
      rawCommand(args);
      break;
    case 'help':
      store.addSystemMessage(activeChannel, '── Commands ──');
      store.addSystemMessage(activeChannel, '/join #channel  ·  /part  ·  /topic text');
      store.addSystemMessage(activeChannel, '/kick user  ·  /op user  ·  /voice user  ·  /invite user');
      store.addSystemMessage(activeChannel, '/pins  — list pinned messages');
      store.addSystemMessage(activeChannel, '/whois user  ·  /away reason  ·  /me action');
      store.addSystemMessage(activeChannel, '/msg user text  ·  /mode +o user  ·  /raw IRC_LINE');
      store.addSystemMessage(activeChannel, '/md **bold** text  — send as rendered markdown');
      store.addSystemMessage(activeChannel, '── Encryption ──');
      store.addSystemMessage(activeChannel, '/encrypt passphrase  ·  /decrypt  — E2EE for channels');
      store.addSystemMessage(activeChannel, '── Policy ──');
      store.addSystemMessage(activeChannel, '/policy #ch SET <rules>  ·  /policy #ch INFO  ·  /policy #ch ACCEPT');
      store.addSystemMessage(activeChannel, '/policy #ch REQUIRE <type> issuer=... url=... label=...');
      store.addSystemMessage(activeChannel, '/policy #ch SET-ROLE <role> <json>  ·  /policy #ch CLEAR');
      store.addSystemMessage(activeChannel, '/policy #ch VERIFY github <org-or-owner/repo>');
      store.addSystemMessage(activeChannel, '── Shortcuts ──');
      store.addSystemMessage(activeChannel, '⌘K quick switch  ·  ⌘F search  ·  ⌘/ shortcuts  ·  ↑ edit last');
      break;
    case 'encrypt': case 'e2ee': {
      if (!args.trim()) {
        store.addSystemMessage(activeChannel, 'Usage: /encrypt <passphrase> — enables E2EE for this channel');
        break;
      }
      import('../lib/e2ee').then(async (e2eeLib) => {
        await e2eeLib.setChannelKey(target, args.trim());
        store.addSystemMessage(activeChannel, '🔒 End-to-end encryption enabled. All messages you send will be encrypted.');
        store.addSystemMessage(activeChannel, 'Others need the same passphrase to read your messages.');
        // Mark channel as encrypted in store
        const channels = new Map(store.channels);
        const ch = channels.get(activeChannel.toLowerCase());
        if (ch) {
          channels.set(activeChannel.toLowerCase(), { ...ch, isEncrypted: true });
          useStore.setState({ channels });
        }
      });
      break;
    }
    case 'decrypt': case 'unencrypt': {
      import('../lib/e2ee').then((e2eeLib) => {
        e2eeLib.removeChannelKey(target);
        store.addSystemMessage(activeChannel, '🔓 Encryption disabled for this channel.');
        const channels = new Map(store.channels);
        const ch = channels.get(activeChannel.toLowerCase());
        if (ch) {
          channels.set(activeChannel.toLowerCase(), { ...ch, isEncrypted: false });
          useStore.setState({ channels });
        }
      });
      break;
    }
    default:
      rawCommand(`${cmd.toUpperCase()}${args ? ' ' + args : ''}`);
  }
}
