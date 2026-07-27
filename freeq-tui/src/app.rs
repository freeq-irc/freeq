//! Application state for the TUI.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::editor::{LineEditor, Mode};

/// Maximum number of messages to keep per buffer.
const MAX_MESSAGES: usize = 1000;

/// Maximum entries in the nick → host cloak cache. A hostile or noisy
/// network with thousands of join/quit nicks would otherwise grow this
/// map indefinitely; we evict arbitrary entries when over the cap.
pub const NICK_HOST_CAP: usize = 4096;

/// Cap on the number of in-flight (open, unclosed) BATCH groups. A
/// hostile server could otherwise spam BATCH START with unique ids
/// and never close them, growing `app.batches` without bound.
pub const BATCH_CONCURRENT_CAP: usize = 16;

/// Cap on the number of accumulated lines in a single in-flight BATCH.
/// A hostile server could otherwise open a BATCH and stream messages
/// forever (never sending BATCH END), pinning the lines vec in memory.
/// CHATHISTORY requests cap at 50 by client convention so this is well
/// above legitimate usage.
pub const BATCH_LINE_CAP: usize = 2000;

/// Defensive cap on the per-channel pinned-message set. The server
/// authoritatively limits pins to 50 per channel, but the TUI populates
/// its set from `+freeq.at/pin` notification tags on the wire — a
/// hostile peer could flood those. Cap at slightly above the server's
/// limit so we tolerate legitimate growth without unbounded memory.
pub const PINNED_CAP: usize = 64;

/// Upper bound on accepted `msgid` length. Server-assigned msgids are
/// ULIDs (26 chars). The cap leaves headroom for benign experimentation
/// without letting a hostile peer feed the buffer index a megabyte string.
pub const MSGID_MAX_LEN: usize = 64;

/// True for commands that carry secrets in their arguments and so must
/// NOT be persisted in the input-history ring. Match the command word
/// case-insensitively; only the leading slash-token matters.
pub fn is_secret_command(line: &str) -> bool {
    let first = line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(first.as_str(), "/encrypt" | "/oper" | "/pass" | "/password")
}

/// Word-boundary-aware mention check. Returns true when `nick` appears
/// in `text` as a standalone token (preceded by start-of-string or a
/// non-alphanumeric, followed by end-of-string or a non-alphanumeric).
/// Case-insensitive. Empty nick never matches.
///
/// Used both by the renderer's mention highlight and by `chat_msg`'s
/// `has_mention` flag — they must agree, or the tab indicator would
/// disagree with the inline highlight.
pub fn is_mention(text: &str, nick: &str) -> bool {
    if nick.is_empty() {
        return false;
    }
    let text_lower = text.to_lowercase();
    let nick_lower = nick.to_lowercase();
    let mut search_from = 0;
    while let Some(pos) = text_lower[search_from..].find(&nick_lower) {
        let abs = search_from + pos;
        let end = abs + nick_lower.len();
        let before_ok = abs == 0
            || !text_lower[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let after_ok = end == text_lower.len()
            || !text_lower[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if before_ok && after_ok {
            return true;
        }
        search_from = abs + nick_lower.chars().next().map_or(1, |c| c.len_utf8());
    }
    false
}

/// Reject `msgid` values that would either:
/// 1. Inject IRC commands when interpolated into raw lines (CR/LF/NUL).
/// 2. Split into extra params when used in `PIN <ch> <id>` etc. (whitespace).
/// 3. Confuse IRCv3 tag parsing (`;` separator, leading `:` for prefix).
/// 4. Bleed into terminal escapes when displayed (control chars).
/// 5. Visually spoof or hide content (BiDi overrides, zero-width chars,
///    Unicode line/paragraph separators — all non-Cc but still hostile).
/// 6. Exhaust memory (length cap).
///
/// Real server-assigned msgids are ULIDs (Crockford base32, upper-case)
/// with optional plain alphanumerics for legacy/test rigs, so an ASCII
/// graphic-only allow-list is both safe and accurate.
pub fn is_valid_msgid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MSGID_MAX_LEN
        && !s.starts_with(':')
        && s.chars().all(|c| {
            // ASCII printable, excluding space and the IRC tag/list/prefix
            // metacharacters. This excludes every non-ASCII char by
            // construction, which kills BiDi, zero-width, and U+2028/2029
            // attacks at the door.
            c.is_ascii_graphic() && c != ';' && c != ',' && c != ':'
        })
}

/// A single line in a message buffer.
#[derive(Debug, Clone)]
pub struct BufferLine {
    pub timestamp: String,
    pub from: String,
    pub text: String,
    pub is_system: bool,
    /// If this message has an associated image, its URL (key into ImageCache).
    pub image_url: Option<String>,
    /// Server-assigned message ID (ULID) from the IRCv3 `msgid` tag.
    /// `None` for system lines, our own optimistic echoes before the server reply,
    /// or messages from servers that don't advertise message-tags.
    pub msgid: Option<String>,
    /// Set when an inbound `+draft/edit` for this message has been applied.
    /// Rendering layer shows an "(edited)" suffix.
    pub is_edited: bool,
    /// Set when an inbound `+draft/delete` for this message has been applied.
    /// Rendering layer replaces the body with a muted placeholder.
    pub is_deleted: bool,
    /// Parent message ID this is a reply to (from IRCv3 `+reply` tag).
    pub reply_to: Option<String>,
    /// Root msgid of this message's edit chain. A message keeps its original
    /// msgid for life — an edit changes `text`, never `msgid` — so this is
    /// set purely as a marker that an edit was applied (and it equals
    /// `msgid` for lines edited in place).
    pub edit_of: Option<String>,
}

/// State of a cached image.
pub enum ImageState {
    /// Image is being fetched.
    Loading,
    /// Image is ready to render.
    #[allow(dead_code)]
    Ready(image::DynamicImage),
    /// Fetch failed.
    #[allow(dead_code)]
    Failed(String),
}

/// Thread-safe cache of fetched images, keyed by URL.
pub type ImageCache = Arc<Mutex<HashMap<String, ImageState>>>;

/// How many terminal rows an image takes up in the message area.
#[cfg(feature = "inline-images")]
pub const IMAGE_ROWS: u16 = 10;

/// Maximum entries in the image cache (LRU eviction).
const MAX_IMAGE_CACHE: usize = 50;
/// Maximum image download size (10 MB).
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;

/// A named message buffer (channel, PM, or status).
#[derive(Debug)]
pub struct Buffer {
    pub name: String,
    pub messages: VecDeque<BufferLine>,
    pub nicks: Vec<String>,
    /// Channel topic, if set.
    pub topic: Option<String>,
    /// Scroll offset from the bottom (0 = at bottom).
    pub scroll: u16,
    /// Unread message count since the buffer was last active.
    pub unread: usize,
    /// Whether any unread message mentions the user's nick.
    pub has_mention: bool,
    /// Scroll offset for nick list (0 = top).
    pub nick_scroll: usize,
    /// Whether we're accumulating nicks from multiple 353 replies.
    pub names_pending: bool,
    /// Msgids of currently pinned messages in this buffer (channels only).
    /// Updated from `+freeq.at/pin` / `+freeq.at/unpin` tags on incoming notices.
    pub pinned: HashSet<String>,
    /// True when we've requested CHATHISTORY BEFORE and haven't yet seen
    /// the closing BATCH. Prevents fan-out requests while scrolling.
    pub history_in_flight: bool,
    /// True once we've seen an empty CHATHISTORY batch — no older messages
    /// exist on the server, so we should stop firing requests.
    pub history_exhausted: bool,
}

/// In-progress BATCH buffer (e.g., CHATHISTORY).
#[derive(Debug, Clone)]
pub struct BatchBuffer {
    pub target: String,
    pub lines: Vec<(i64, BufferLine)>,
    /// IRCv3 batch type (e.g. "chathistory", "labeled-response").
    /// Used by `end_batch` to decide whether an empty batch should mark
    /// the buffer's history as exhausted. Without this, an empty batch
    /// of an unrelated type would permanently disable scroll-up fetch.
    pub batch_type: String,
}

impl BatchBuffer {
    /// Apply a `+draft/edit` to an accumulated line. Used during CHATHISTORY
    /// replay so the original message is rewritten in place instead of
    /// displaying both the original and the edit. Same authorship check
    /// as `Buffer::apply_edit`.
    pub fn apply_edit(
        &mut self,
        editor_nick: &str,
        original_msgid: &str,
        _new_msgid: Option<&str>,
        new_text: &str,
    ) -> bool {
        for (_, line) in self.lines.iter_mut() {
            if line.msgid.as_deref() == Some(original_msgid) {
                if !line.from.eq_ignore_ascii_case(editor_nick) || line.is_deleted {
                    return false;
                }
                line.text = sanitize_text(new_text);
                line.is_edited = true;
                // The line keeps the msgid it was born with — the identity
                // the server files reactions, pins and deletes under. The
                // edit's own wire id is not this message's name.
                return true;
            }
        }
        false
    }

    /// Apply a `+draft/delete` to an accumulated line.
    pub fn apply_delete(&mut self, deleter_nick: &str, msgid: &str) -> bool {
        for (_, line) in self.lines.iter_mut() {
            if line.msgid.as_deref() == Some(msgid) {
                if !line.from.eq_ignore_ascii_case(deleter_nick) {
                    return false;
                }
                line.is_deleted = true;
                line.text.clear();
                return true;
            }
        }
        false
    }
}

impl Buffer {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            messages: VecDeque::new(),
            nicks: Vec::new(),
            topic: None,
            scroll: 0,
            unread: 0,
            has_mention: false,
            nick_scroll: 0,
            names_pending: false,
            pinned: HashSet::new(),
            history_in_flight: false,
            history_exhausted: false,
        }
    }

    pub fn push(&mut self, mut line: BufferLine) {
        // Dedup by msgid at the single chokepoint: the server replays
        // history BOTH unbatched on JOIN and via CHATHISTORY batches, and a
        // message can arrive live first. Without this, a rejoin doubles the
        // buffer. A line keeps its msgid across edits, so the id alone is
        // enough — replayed pre-edit rows carry the same id the line holds.
        if let Some(ref id) = line.msgid
            && self.messages.iter().any(|l| l.msgid.as_deref() == Some(id))
        {
            return;
        }
        // SECURITY: a hostile peer can put ANSI escapes (cursor moves, color
        // resets, screen clears) into their nick or message body. We render
        // both directly into the terminal, so we strip control chars at the
        // single chokepoint here — no caller can forget. `text` already
        // tolerates `\n`/`\t` for legitimate formatting; the `from` field
        // never contains either in a real IRC nick.
        line.from = sanitize_text(&line.from)
            .chars()
            .filter(|c| *c != '\n' && *c != '\t')
            .collect();
        line.text = sanitize_text(&line.text);
        self.messages.push_back(line);
        if self.messages.len() > MAX_MESSAGES {
            self.messages.pop_front();
        }
        // Auto-scroll to bottom when new message arrives
        self.scroll = 0;
    }

    /// Add a pinned msgid, enforcing `PINNED_CAP`. When the cap would be
    /// exceeded we drop one arbitrary entry — true LRU isn't worth the
    /// bookkeeping for what's already a defense-in-depth bound.
    pub fn add_pinned(&mut self, msgid: &str) {
        if self.pinned.contains(msgid) {
            return;
        }
        if self.pinned.len() >= PINNED_CAP
            && let Some(victim) = self.pinned.iter().next().cloned()
        {
            self.pinned.remove(&victim);
        }
        self.pinned.insert(msgid.to_string());
    }

    pub fn push_system(&mut self, text: &str) {
        self.push(BufferLine {
            timestamp: now_str(),
            from: String::new(),
            text: sanitize_text(text),
            is_system: true,
            image_url: None,
            msgid: None,
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
        });
    }

    /// Find a message by its server-assigned msgid.
    /// O(n) over MAX_MESSAGES; fine at the current buffer size.
    pub fn find_by_msgid(&self, msgid: &str) -> Option<&BufferLine> {
        self.messages
            .iter()
            .rev()
            .find(|line| line.msgid.as_deref() == Some(msgid))
    }

    /// Mutable variant of `find_by_msgid`. Used by the upcoming `/edit` and
    /// `/delete` commands to mutate a previously-received message in place.
    #[allow(dead_code)]
    pub fn find_by_msgid_mut(&mut self, msgid: &str) -> Option<&mut BufferLine> {
        self.messages
            .iter_mut()
            .rev()
            .find(|line| line.msgid.as_deref() == Some(msgid))
    }

    /// Oldest non-system message in this buffer that has a server-assigned
    /// msgid. Used as the anchor for `CHATHISTORY BEFORE` auto-fetch.
    pub fn oldest_msgid(&self) -> Option<&str> {
        self.messages
            .iter()
            .find(|line| !line.is_system && line.msgid.is_some())
            .and_then(|line| line.msgid.as_deref())
    }

    /// Most recent non-system message that has a server-assigned msgid.
    /// Used by `/react`, `/reply`, etc. when no explicit target is given —
    /// the natural TUI gesture is "act on the message I just saw."
    pub fn recent_msgid(&self) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|line| !line.is_system && !line.is_deleted && line.msgid.is_some())
            .and_then(|line| line.msgid.as_deref())
    }

    /// Most recent non-system, non-deleted message authored by `nick`
    /// that has a server-assigned msgid. Used by `/edit` and `/delete`
    /// to act on the user's own last message.
    pub fn recent_own_msgid(&self, nick: &str) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|line| {
                !line.is_system
                    && !line.is_deleted
                    && line.from.eq_ignore_ascii_case(nick)
                    && line.msgid.is_some()
            })
            .and_then(|line| line.msgid.as_deref())
    }

    /// Apply an inbound `+draft/edit`. The edit message carries its own
    /// fresh `msgid`; we swap the line's msgid to the new one so subsequent
    /// edits chain correctly (matches the iOS pattern).
    ///
    /// SECURITY: the `editor_nick` (sender of the edit message) MUST match
    /// the original line's author. The server enforces this too, but a
    /// trusting client can be spoofed by a malicious peer (or a buggy/
    /// compromised server) into rewriting other users' history. We refuse
    /// the edit and return false in that case.
    ///
    /// Also refuses to "edit" a deleted line — that would resurrect a
    /// deletion the user explicitly performed.
    ///
    /// Returns true if an existing line was edited; false if the target
    /// wasn't in this buffer, the sender doesn't match, or the line is
    /// already deleted.
    pub fn apply_edit(
        &mut self,
        editor_nick: &str,
        original_msgid: &str,
        _new_msgid: Option<&str>,
        new_text: &str,
    ) -> bool {
        if let Some(line) = self.find_by_msgid_mut(original_msgid) {
            if !line.from.eq_ignore_ascii_case(editor_nick) {
                return false;
            }
            if line.is_deleted {
                return false;
            }
            line.text = sanitize_text(new_text);
            line.is_edited = true;
            if line.edit_of.is_none() {
                line.edit_of = Some(original_msgid.to_string());
            }
            // The line keeps the msgid it was born with. That id is what the
            // server files reactions, pins and deletes under, what replay
            // returns the message under, and what every other client holds —
            // so pins need no re-keying and replayed pre-edit rows dedup on
            // the id alone. The edit's own wire id is audit trail, not a name.
            true
        } else {
            false
        }
    }

    /// Apply an inbound `+draft/delete`. We don't drop the line — the
    /// rendering layer shows a muted placeholder so scrollback positions
    /// stay stable.
    ///
    /// SECURITY: like `apply_edit`, the `deleter_nick` MUST match the
    /// original author (channel ops can also delete server-side, but the
    /// server's permission check is authoritative there; this client-side
    /// check is the defense-in-depth layer for spoofed peer-to-peer wire
    /// events).
    ///
    /// Returns true if a line was marked deleted.
    pub fn apply_delete(&mut self, deleter_nick: &str, msgid: &str) -> bool {
        // Match the current msgid OR the edit-chain root: `apply_edit` rewrites
        // `msgid` to the edit's id, while a delete names the ORIGINAL. Matching
        // only the current id left edited messages on screen after the server
        // had removed them.
        if let Some(line) = self
            .messages
            .iter_mut()
            .rev()
            .find(|l| l.msgid.as_deref() == Some(msgid) || l.edit_of.as_deref() == Some(msgid))
        {
            if !line.from.eq_ignore_ascii_case(deleter_nick) {
                return false;
            }
            line.is_deleted = true;
            line.text.clear();
            // Drop the pin too so the renderer doesn't keep flagging
            // a `[deleted]` line as "pinned" — both an inconsistency and
            // a small information leak about which deleted messages were
            // significant.
            self.pinned.remove(msgid);
            true
        } else {
            false
        }
    }
}

/// Top-level application state.
/// Holds PDS credentials for media upload.
#[derive(Clone)]
pub struct MediaUploader {
    pub did: String,
    pub pds_url: String,
    pub access_token: String,
    pub dpop_key: Option<freeq_sdk::oauth::DpopKey>,
    pub dpop_nonce: Option<String>,
}

/// Transport type for the current connection.
#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Tcp,
    Tls,
    #[allow(dead_code)]
    WebSocket,
    Iroh,
}

impl Transport {
    pub fn label(&self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
            Transport::WebSocket => "WS",
            Transport::Iroh => "IROH",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Transport::Tcp => "⚡",       // unencrypted, fast
            Transport::Tls => "🔒",       // encrypted
            Transport::WebSocket => "🌐", // web
            Transport::Iroh => "🕳️",      // hole-punching / p2p
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Transport::Tcp => "Plain TCP (unencrypted)",
            Transport::Tls => "TLS 1.3 (encrypted)",
            Transport::WebSocket => "WebSocket (browser-compatible)",
            Transport::Iroh => "Iroh QUIC (encrypted, NAT-traversing, P2P-capable)",
        }
    }
}

pub struct App {
    /// Per-channel E2EE keys, keyed by lowercase channel name.
    /// Derived from passphrase via HKDF-SHA256.
    pub channel_keys: HashMap<String, [u8; 32]>,
    /// Named buffers, keyed by lowercase name. "status" is always present.
    pub buffers: BTreeMap<String, Buffer>,
    /// In-progress batch buffers (chathistory), keyed by batch ID.
    pub batches: HashMap<String, BatchBuffer>,
    /// Currently active buffer key.
    pub active_buffer: String,
    /// Line editor (handles input, cursor, emacs/vi keybindings).
    pub editor: LineEditor,
    /// Connection state display.
    pub connection_state: String,
    /// Transport type for the current connection.
    pub transport: Transport,
    /// Server address we connected to.
    pub server_addr: String,
    /// Iroh endpoint ID (if connected via iroh).
    pub iroh_endpoint_id: Option<String>,
    /// Time of connection establishment.
    pub connected_at: Option<std::time::Instant>,
    /// Authenticated DID (if any).
    pub authenticated_did: Option<String>,
    /// Whether to show the /net stats popup.
    pub show_net_popup: bool,
    /// Our nick.
    pub nick: String,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Whether a reconnect attempt should be made.
    pub reconnect_pending: bool,
    /// When the next reconnect attempt should happen.
    pub reconnect_at: Option<std::time::Instant>,
    /// Current reconnect backoff delay.
    pub reconnect_delay: Duration,
    /// Input history (most recent last).
    pub history: Vec<String>,
    /// Current position in history (None = not browsing).
    pub history_pos: Option<usize>,
    /// Saved input line when browsing history.
    pub history_saved: String,
    /// Media uploader (present when authenticated with PDS session).
    pub media_uploader: Option<MediaUploader>,
    /// Cache of fetched images for inline rendering.
    pub image_cache: ImageCache,
    /// Image protocol picker (detects terminal capabilities).
    #[cfg(feature = "inline-images")]
    pub picker: Option<ratatui_image::picker::Picker>,
    /// Prepared image protocol states for rendering, keyed by URL.
    #[cfg(feature = "inline-images")]
    pub image_protos: HashMap<String, ratatui_image::protocol::StatefulProtocol>,
    /// Channel for background tasks to send results back to the main loop.
    pub bg_result_tx: tokio::sync::mpsc::Sender<BgResult>,
    /// Receiver end (held by main loop).
    pub bg_result_rx: Option<tokio::sync::mpsc::Receiver<BgResult>>,
    /// Show raw IRC lines in the status buffer (toggled by /debug).
    pub debug_raw: bool,
    /// P2P direct messaging handle (None if P2P not started).
    pub p2p_handle: Option<freeq_sdk::p2p::P2pHandle>,
    /// P2P event receiver (moved to main loop on first use).
    pub p2p_event_rx: Option<tokio::sync::mpsc::Receiver<freeq_sdk::p2p::P2pEvent>>,
    /// Pending URL from a server notice (waiting for user to press Enter to open).
    pub pending_url: Option<String>,
    /// Most recently observed host for each nick (lowercase keys).
    /// Populated by parsing the IRC prefix on JOIN lines. Used to surface
    /// hostname cloaks like `freeq/plc/xxx` in join system messages and
    /// /whois output without changing the SDK Event::Joined signature.
    pub nick_hosts: HashMap<String, String>,
    /// Display names for DID-keyed DM buffers (DID → nick). Fed by
    /// `Event::MemberDid` and the conversation list's partner DIDs.
    /// Display-grade only — never used to address outgoing messages.
    pub did_names: HashMap<String, String>,
    /// Buffer keys (channels and DMs) we've already requested history for
    /// this session, so activating one fetches its backlog exactly once.
    pub history_requested: HashSet<String>,
}

/// Canonical buffer-map key for a name. Nicks and channels are
/// case-insensitive in IRC and key by lowercase; DIDs are case-sensitive
/// identifiers (did:key is base58) that also double as the wire target
/// for DID-keyed DMs, so they pass through unchanged.
pub fn buffer_key(name: &str) -> String {
    if freeq_sdk::address::is_did(name) {
        name.to_string()
    } else {
        name.to_lowercase()
    }
}

/// Compact a DID for display: `did:plc:k2n3e2vsihf3farequ44t5j7` →
/// `plc:k2n3…t5j7`. Non-DIDs pass through unchanged.
pub fn shorten_did(s: &str) -> String {
    if !freeq_sdk::address::is_did(s) {
        return s.to_string();
    }
    let mut parts = s.splitn(3, ':');
    let (_, method, id) = (
        parts.next(),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 12 {
        format!("{method}:{id}")
    } else {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{method}:{head}…{tail}")
    }
}

/// Results from background tasks that need to update the UI.
pub enum BgResult {
    /// Profile lines to display in a buffer, with optional avatar URL for the last line.
    ProfileLines(String, Vec<String>, Option<String>),
}

impl App {
    pub fn new(nick: &str, vi_mode: bool) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let mut buffers = BTreeMap::new();
        let mut status = Buffer::new("status");
        let mode_name = if vi_mode { "vi" } else { "emacs" };
        status.push_system(&format!(
            "Welcome to freeq ({mode_name} mode). Type /help for commands."
        ));
        buffers.insert("status".to_string(), status);

        let mode = if vi_mode { Mode::Vi } else { Mode::Emacs };

        Self {
            channel_keys: HashMap::new(),
            buffers,
            batches: HashMap::new(),
            active_buffer: "status".to_string(),
            editor: LineEditor::new(mode),
            connection_state: "connecting".to_string(),
            transport: Transport::Tcp,
            server_addr: String::new(),
            iroh_endpoint_id: None,
            connected_at: None,
            authenticated_did: None,
            show_net_popup: false,
            debug_raw: false,
            nick: nick.to_string(),
            should_quit: false,
            reconnect_pending: false,
            reconnect_at: None,
            reconnect_delay: Duration::from_secs(1),
            history: Vec::new(),
            history_pos: None,
            history_saved: String::new(),
            media_uploader: None,
            image_cache: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "inline-images")]
            picker: None,
            #[cfg(feature = "inline-images")]
            image_protos: HashMap::new(),
            bg_result_tx: tx,
            bg_result_rx: Some(rx),
            p2p_handle: None,
            p2p_event_rx: None,
            pending_url: None,
            nick_hosts: HashMap::new(),
            did_names: HashMap::new(),
            history_requested: HashSet::new(),
        }
    }

    /// Get or create a buffer.
    pub fn buffer_mut(&mut self, name: &str) -> &mut Buffer {
        let key = buffer_key(name);
        self.buffers.entry(key).or_insert_with(|| Buffer::new(name))
    }

    /// Symmetric E2EE salt for a DM buffer: the canonical conversation key
    /// (both DIDs, sorted) so each peer derives the *same* key from a shared
    /// passphrase. Passphrase E2EE was built for channels (salt = the shared
    /// channel name); a DM salted by the local buffer name uses the peer's
    /// identity, which differs per side, so keys never matched. Returns None
    /// when we can't resolve both DIDs (a guest, or a peer whose DID we
    /// haven't learned) — symmetric E2EE isn't possible then.
    pub fn dm_e2ee_salt(&self, buffer_key: &str) -> Option<String> {
        let my_did = self.authenticated_did.as_deref()?;
        let peer_did = if freeq_sdk::address::is_did(buffer_key) {
            buffer_key.to_string()
        } else {
            self.did_for_nick(buffer_key)?
        };
        let mut pair = [my_did.to_string(), peer_did];
        pair.sort();
        Some(format!("dm:{},{}", pair[0], pair[1]))
    }

    /// Reverse of the display map: the DID whose learned nick is `nick`, if
    /// we've seen that binding. Lets `/switch <nick>` open the DID-keyed
    /// thread rather than minting a separate nick-keyed one.
    pub fn did_for_nick(&self, nick: &str) -> Option<String> {
        self.did_names
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(nick))
            .map(|(did, _)| did.clone())
    }

    /// Human name for a buffer key that may be a raw DID: the learned
    /// display binding, else the compacted DID. Plain names pass through.
    pub fn display_name(&self, key: &str) -> String {
        if !freeq_sdk::address::is_did(key) {
            return key.to_string();
        }
        match self.did_names.get(key) {
            Some(nick) => nick.clone(),
            None => shorten_did(key),
        }
    }

    /// Record a learned nick↔DID binding: remember the display name and
    /// fold any nick-keyed DM buffer into the DID-keyed one (a cold first
    /// DM keys by nick until the peer's DID is learned — without the
    /// merge, one person becomes two threads).
    pub fn record_member_did(&mut self, nick: &str, did: &str) {
        if !freeq_sdk::address::is_did(did)
            || nick.starts_with('#')
            || nick.starts_with('&')
            || nick.eq_ignore_ascii_case(did)
        {
            return;
        }
        self.did_names.insert(did.to_string(), nick.to_string());
        self.merge_dm_buffer(nick, did);
    }

    /// Fold the nick-keyed DM buffer into the DID-keyed one. Messages
    /// dedupe by msgid; unread state carries over; the active buffer,
    /// any E2EE key, and in-flight batches follow the re-key.
    fn merge_dm_buffer(&mut self, nick: &str, did: &str) {
        let nick_key = buffer_key(nick);
        let did_key = buffer_key(did);
        if nick_key == did_key {
            return;
        }
        let Some(nick_buf) = self.buffers.remove(&nick_key) else {
            return;
        };
        match self.buffers.get_mut(&did_key) {
            Some(did_buf) => {
                let known: HashSet<&str> = did_buf
                    .messages
                    .iter()
                    .filter_map(|l| l.msgid.as_deref())
                    .collect();
                let fresh: Vec<BufferLine> = nick_buf
                    .messages
                    .into_iter()
                    .filter(|l| l.msgid.as_deref().is_none_or(|id| !known.contains(id)))
                    .collect();
                for line in fresh {
                    did_buf.messages.push_back(line);
                    if did_buf.messages.len() > MAX_MESSAGES {
                        did_buf.messages.pop_front();
                    }
                }
                did_buf.unread += nick_buf.unread;
                did_buf.has_mention |= nick_buf.has_mention;
            }
            None => {
                let mut buf = nick_buf;
                buf.name = did.to_string();
                self.buffers.insert(did_key.clone(), buf);
            }
        }
        if let Some(key) = self.channel_keys.remove(&nick_key) {
            self.channel_keys.entry(did_key.clone()).or_insert(key);
        }
        for batch in self.batches.values_mut() {
            if buffer_key(&batch.target) == nick_key {
                batch.target = did.to_string();
            }
        }
        if self.active_buffer == nick_key {
            self.active_buffer = did_key;
        }
    }

    /// Keep DID display names current across a peer's nick change.
    pub fn did_rename(&mut self, old_nick: &str, new_nick: &str) {
        for nick in self.did_names.values_mut() {
            if nick.eq_ignore_ascii_case(old_nick) {
                *nick = new_nick.to_string();
            }
        }
    }

    /// Push a system message to the status buffer.
    pub fn status_msg(&mut self, text: &str) {
        self.buffer_mut("status").push_system(text);
    }

    /// Push a chat message to the appropriate buffer.
    pub fn chat_msg(&mut self, target: &str, from: &str, text: &str) {
        // If it's a PM to us, use the sender's nick as the buffer
        let buffer_name = if !target.starts_with('#') && !target.starts_with('&') {
            if from == self.nick {
                target.to_string()
            } else {
                from.to_string()
            }
        } else {
            target.to_string()
        };

        let clean_text = sanitize_text(text);
        let clean_from = sanitize_text(from);
        let buf_key = buffer_name.to_lowercase();
        let is_active = buf_key == self.active_buffer;

        self.buffer_mut(&buffer_name).push(BufferLine {
            timestamp: now_str(),
            from: clean_from,
            text: clean_text.clone(),
            is_system: false,
            image_url: None,
            msgid: None,
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
        });

        // Track unread + mentions for inactive buffers. IRC nicks are
        // case-insensitive — without `eq_ignore_ascii_case`, the echo
        // of our own message under a server-canonicalized case would
        // count as someone else's message and bump unread.
        if !is_active
            && !from.eq_ignore_ascii_case(&self.nick)
            && let Some(buf) = self.buffers.get_mut(&buf_key)
        {
            buf.unread += 1;
            if is_mention(&clean_text, &self.nick) {
                buf.has_mention = true;
            }
        }
    }

    /// Start a BATCH (e.g., CHATHISTORY). Bounds concurrent in-flight
    /// batches via `BATCH_CONCURRENT_CAP` — a hostile server can't open
    /// thousands of never-closed batches to exhaust memory. The default
    /// type is "chathistory"; call `start_batch_typed` to specify
    /// otherwise. (Convenience for tests; the event handler always
    /// uses `start_batch_typed` with the server-supplied type.)
    #[allow(dead_code)]
    pub fn start_batch(&mut self, id: &str, target: &str) {
        self.start_batch_typed(id, target, "chathistory");
    }

    pub fn start_batch_typed(&mut self, id: &str, target: &str, batch_type: &str) {
        if self.batches.len() >= BATCH_CONCURRENT_CAP
            && let Some(victim) = self.batches.keys().next().cloned()
        {
            self.batches.remove(&victim);
        }
        self.batches.insert(
            id.to_string(),
            BatchBuffer {
                target: target.to_string(),
                lines: Vec::new(),
                batch_type: batch_type.to_string(),
            },
        );
    }

    /// Add a line to a batch by ID. Drops the line if the batch is at
    /// `BATCH_LINE_CAP` — bounds memory in the face of a malicious or
    /// runaway server that opens a BATCH and never closes it.
    pub fn add_batch_line(&mut self, id: &str, timestamp_ms: i64, line: BufferLine) {
        if let Some(batch) = self.batches.get_mut(id)
            && batch.lines.len() < BATCH_LINE_CAP
        {
            batch.lines.push((timestamp_ms, line));
        }
    }

    /// Flush a batch into its target buffer (prepended as history).
    pub fn end_batch(&mut self, id: &str) {
        if let Some(mut batch) = self.batches.remove(id) {
            // Targetless batches (e.g. chathistory-targets) have nowhere to
            // flush — dropping them beats minting a nameless buffer.
            if batch.target.is_empty() {
                return;
            }
            let buf = self.buffer_mut(&batch.target);
            batch.lines.sort_by_key(|a| a.0);
            let was_empty = batch.lines.is_empty();
            let was_chathistory = batch.batch_type.eq_ignore_ascii_case("chathistory");
            // Skip lines already in the buffer by msgid. A CHATHISTORY LATEST
            // fetch (used to backfill a DM on open) overlaps messages that
            // arrived live, which would otherwise double them.
            let present: HashSet<String> = buf
                .messages
                .iter()
                .filter_map(|l| l.msgid.clone())
                .collect();
            // Prepend in order (oldest first)
            for (_, line) in batch.lines.into_iter().rev() {
                if let Some(ref id) = line.msgid
                    && present.contains(id)
                {
                    continue;
                }
                buf.messages.push_front(line);
                if buf.messages.len() > MAX_MESSAGES {
                    buf.messages.pop_back();
                }
            }
            // Auto-fetch tracking: only CHATHISTORY batches drive these
            // flags. An empty `labeled-response` (or anything else) must
            // not permanently disable scroll-up history fetch.
            if was_chathistory {
                buf.history_in_flight = false;
                if was_empty {
                    buf.history_exhausted = true;
                }
            }
        }
    }

    /// Record a nick → host mapping observed on a JOIN line. Enforces the
    /// `NICK_HOST_CAP` so that flooding the channel with distinct nicks
    /// can't OOM the TUI. Eviction is arbitrary: when the cap is hit we
    /// drop a single existing entry before inserting the new one.
    pub fn remember_nick_host(&mut self, nick: &str, host: &str) {
        let key = nick.to_lowercase();
        if !self.nick_hosts.contains_key(&key) && self.nick_hosts.len() >= NICK_HOST_CAP {
            // Evict one arbitrary entry — true LRU isn't worth the bookkeeping
            // for a defense-in-depth bound on a host-display cache.
            if let Some(victim) = self.nick_hosts.keys().next().cloned() {
                self.nick_hosts.remove(&victim);
            }
        }
        self.nick_hosts.insert(key, host.to_string());
    }

    /// Apply a `+draft/edit` either to an in-flight batch (during CHATHISTORY
    /// replay) or to the live buffer. The edit message carries its own
    /// `msgid`; that becomes the line's new id so subsequent edits chain.
    ///
    /// Does NOT lazily create a buffer for `buf_name`. A spoofed or
    /// misrouted edit targeting a buffer the user never opened would
    /// otherwise spawn a phantom empty buffer in the tab bar.
    pub fn apply_edit(
        &mut self,
        editor_nick: &str,
        batch_id: Option<&str>,
        buf_name: &str,
        original_msgid: &str,
        new_msgid: Option<&str>,
        new_text: &str,
    ) -> bool {
        let mut applied = false;
        if let Some(id) = batch_id
            && let Some(batch) = self.batches.get_mut(id)
        {
            applied = batch.apply_edit(editor_nick, original_msgid, new_msgid, new_text);
        }
        // ALSO apply to the live buffer (not either/or): the server replays
        // history both unbatched on JOIN and via CHATHISTORY batches, so the
        // pre-edit row may already sit in the buffer while the edit row
        // arrives inside a batch. Rewriting only the batch copy left the
        // buffer's stale row co-existing with the batch's edited one (the
        // duplicated-edited-message bug, 2026-07-23).
        let key = buffer_key(buf_name);
        if let Some(buf) = self.buffers.get_mut(&key) {
            applied |= buf.apply_edit(editor_nick, original_msgid, new_msgid, new_text);
        }
        applied
    }

    /// Apply a `+draft/delete` either to an in-flight batch or the live
    /// buffer. Same no-phantom-buffer guarantee as `apply_edit`.
    pub fn apply_delete(
        &mut self,
        deleter_nick: &str,
        batch_id: Option<&str>,
        buf_name: &str,
        msgid: &str,
    ) -> bool {
        if let Some(id) = batch_id
            && let Some(batch) = self.batches.get_mut(id)
        {
            return batch.apply_delete(deleter_nick, msgid);
        }
        let key = buffer_key(buf_name);
        if let Some(buf) = self.buffers.get_mut(&key) {
            buf.apply_delete(deleter_nick, msgid)
        } else {
            false
        }
    }

    /// Switch to the next buffer.
    /// Remove a buffer (e.g. after being kicked from a channel).
    /// Switches to the previous buffer if the removed one was active.
    pub fn remove_buffer(&mut self, name: &str) {
        let key = buffer_key(name);
        self.buffers.remove(&key);
        if self.active_buffer == key {
            // Switch to first available buffer, or "status"
            self.active_buffer = self
                .buffers
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "status".to_string());
        }
    }

    pub fn next_buffer(&mut self) {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        if let Some(pos) = keys.iter().position(|k| k == &self.active_buffer) {
            let next = (pos + 1) % keys.len();
            self.active_buffer = keys[next].clone();
            self.clear_active_unread();
        }
    }

    /// Switch to the previous buffer.
    pub fn prev_buffer(&mut self) {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        if let Some(pos) = keys.iter().position(|k| k == &self.active_buffer) {
            let prev = if pos == 0 { keys.len() - 1 } else { pos - 1 };
            self.active_buffer = keys[prev].clone();
            self.clear_active_unread();
        }
    }

    /// Switch to a named buffer.
    pub fn switch_to(&mut self, name: &str) {
        let key = buffer_key(name);
        if self.buffers.contains_key(&key) {
            self.active_buffer = key;
            self.clear_active_unread();
        }
    }

    /// Clear unread state for the currently active buffer.
    fn clear_active_unread(&mut self) {
        if let Some(buf) = self.buffers.get_mut(&self.active_buffer) {
            buf.unread = 0;
            buf.has_mention = false;
        }
    }

    /// Get the ordered list of buffer names for the tab bar.
    pub fn buffer_names(&self) -> Vec<String> {
        self.buffers.keys().cloned().collect()
    }

    /// Take and clear the input line, pushing it to history. Commands
    /// that carry credentials (`/encrypt <passphrase>`, `/oper <name>
    /// <password>`) are NOT recorded — leaking them via Ctrl-P recall
    /// or a memory dump would compromise the user's secrets.
    pub fn input_take(&mut self) -> String {
        self.history_pos = None;
        let line = self.editor.take();
        if !line.is_empty() && !is_secret_command(&line) {
            self.history.push(line.clone());
        }
        line
    }

    /// Browse up in input history.
    pub fn history_up(&mut self) {
        if self.history.is_empty() {
            return;
        }
        match self.history_pos {
            None => {
                self.history_saved = self.editor.text.clone();
                self.history_pos = Some(self.history.len() - 1);
            }
            Some(pos) if pos > 0 => {
                self.history_pos = Some(pos - 1);
            }
            _ => return,
        }
        let pos = self.history_pos.unwrap();
        self.editor.set(self.history[pos].clone());
    }

    /// Browse down in input history.
    pub fn history_down(&mut self) {
        if let Some(pos) = self.history_pos {
            if pos + 1 < self.history.len() {
                self.history_pos = Some(pos + 1);
                self.editor.set(self.history[pos + 1].clone());
            } else {
                self.history_pos = None;
                let saved = std::mem::take(&mut self.history_saved);
                self.editor.set(saved);
            }
        }
    }
}

fn now_str() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Strip terminal control characters (ESC sequences, C0/C1 controls) from text.
/// Prevents malicious users from injecting escape sequences that could
/// mess up the terminal display.
pub fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            // Allow normal printable chars + newline/tab
            c == '\n' || c == '\t' || (c >= ' ' && c != '\x7f')
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_with_msgid(text: &str, msgid: Option<&str>) -> BufferLine {
        line(text, "alice", msgid)
    }

    fn line(text: &str, from: &str, msgid: Option<&str>) -> BufferLine {
        BufferLine {
            timestamp: "12:00:00".into(),
            from: from.into(),
            text: text.into(),
            is_system: false,
            image_url: None,
            msgid: msgid.map(String::from),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
        }
    }

    #[test]
    fn find_by_msgid_round_trip() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hello", Some("01ABC")));
        buf.push(line_with_msgid("world", Some("01DEF")));

        assert_eq!(
            buf.find_by_msgid("01ABC").map(|l| l.text.as_str()),
            Some("hello")
        );
        assert_eq!(
            buf.find_by_msgid("01DEF").map(|l| l.text.as_str()),
            Some("world")
        );
        assert!(buf.find_by_msgid("missing").is_none());
    }

    #[test]
    fn find_by_msgid_mut_allows_in_place_edit() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("original", Some("01ABC")));

        let line = buf.find_by_msgid_mut("01ABC").expect("line exists");
        line.text = "edited".into();

        assert_eq!(buf.find_by_msgid("01ABC").unwrap().text, "edited");
    }

    #[test]
    fn recent_msgid_skips_system_lines() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("first", Some("01AAA")));
        buf.push_system("alice has joined");
        buf.push(line_with_msgid("second", Some("01BBB")));
        buf.push_system("bob has left");

        // Most recent non-system, msgid-bearing line wins.
        assert_eq!(buf.recent_msgid(), Some("01BBB"));
    }

    #[test]
    fn recent_msgid_skips_lines_without_msgid() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("with id", Some("01AAA")));
        buf.push(line_with_msgid("no id", None));

        // Lines without msgid (e.g. our own optimistic local echo) are not selectable.
        assert_eq!(buf.recent_msgid(), Some("01AAA"));
    }

    #[test]
    fn recent_msgid_none_on_empty_buffer() {
        let buf = Buffer::new("#test");
        assert!(buf.recent_msgid().is_none());
    }

    #[test]
    fn push_system_has_no_msgid() {
        let mut buf = Buffer::new("#test");
        buf.push_system("welcome");
        assert!(buf.messages.back().unwrap().msgid.is_none());
        assert!(buf.messages.back().unwrap().is_system);
    }

    #[test]
    fn apply_edit_rewrites_text_and_flips_flag() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hi", Some("01ABC")));

        let ok = buf.apply_edit("alice", "01ABC", Some("01DEF"), "hello world");
        assert!(ok);

        // The message keeps the id it was born with; the edit's own wire id
        // never becomes a name anything can be looked up by.
        let edited = buf.find_by_msgid("01ABC").expect("original id resolves");
        assert_eq!(edited.text, "hello world");
        assert!(edited.is_edited);
        assert!(buf.find_by_msgid("01DEF").is_none());
    }

    #[test]
    fn apply_edit_without_new_msgid_keeps_original_id() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hi", Some("01ABC")));

        assert!(buf.apply_edit("alice", "01ABC", None, "hello"));
        let edited = buf.find_by_msgid("01ABC").expect("id should still resolve");
        assert_eq!(edited.text, "hello");
        assert!(edited.is_edited);
    }

    #[test]
    fn apply_edit_unknown_msgid_is_noop() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hi", Some("01ABC")));

        assert!(!buf.apply_edit("alice", "01ZZZ", None, "should not appear"));
        assert_eq!(buf.find_by_msgid("01ABC").unwrap().text, "hi");
    }

    #[test]
    fn apply_edit_sanitizes_control_chars() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hi", Some("01ABC")));

        // Inject a NUL byte and an ANSI escape — both should be stripped.
        buf.apply_edit("alice", "01ABC", None, "safe\x00\x1b[31mtext");
        let edited = buf.find_by_msgid("01ABC").unwrap();
        assert_eq!(edited.text, "safe[31mtext");
    }

    #[test]
    fn apply_delete_marks_and_clears_text() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("secret", Some("01ABC")));

        assert!(buf.apply_delete("alice", "01ABC"));
        let deleted = buf.find_by_msgid("01ABC").expect("line still exists by id");
        assert!(deleted.is_deleted);
        assert!(deleted.text.is_empty());
    }

    #[test]
    fn apply_delete_unknown_is_noop() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("hi", Some("01ABC")));
        assert!(!buf.apply_delete("alice", "01ZZZ"));
        assert!(!buf.find_by_msgid("01ABC").unwrap().is_deleted);
    }

    #[test]
    fn recent_msgid_skips_deleted() {
        let mut buf = Buffer::new("#test");
        buf.push(line_with_msgid("first", Some("01AAA")));
        buf.push(line_with_msgid("second", Some("01BBB")));
        buf.apply_delete("alice", "01BBB");
        // 01BBB is the newest, but it's deleted — fall back to 01AAA.
        assert_eq!(buf.recent_msgid(), Some("01AAA"));
    }

    #[test]
    fn recent_own_msgid_filters_by_nick() {
        let mut buf = Buffer::new("#test");
        buf.push(line("from alice", "alice", Some("01AAA")));
        buf.push(line("from bob", "bob", Some("01BBB")));
        buf.push(line("from alice 2", "alice", Some("01CCC")));

        assert_eq!(buf.recent_own_msgid("alice"), Some("01CCC"));
        assert_eq!(buf.recent_own_msgid("bob"), Some("01BBB"));
        assert_eq!(buf.recent_own_msgid("carol"), None);
    }

    #[test]
    fn recent_own_msgid_is_case_insensitive() {
        let mut buf = Buffer::new("#test");
        buf.push(line("hello", "Alice", Some("01AAA")));
        // IRC nicks are case-insensitive for comparison.
        assert_eq!(buf.recent_own_msgid("alice"), Some("01AAA"));
        assert_eq!(buf.recent_own_msgid("ALICE"), Some("01AAA"));
    }

    #[test]
    fn recent_own_msgid_skips_deleted() {
        let mut buf = Buffer::new("#test");
        buf.push(line("first", "alice", Some("01AAA")));
        buf.push(line("second", "alice", Some("01BBB")));
        buf.apply_delete("alice", "01BBB");
        // alice's newest non-deleted msgid is 01AAA.
        assert_eq!(buf.recent_own_msgid("alice"), Some("01AAA"));
    }

    #[test]
    fn reply_to_propagates_to_buffer_line() {
        let mut buf = Buffer::new("#test");
        let mut line = line_with_msgid("a reply", Some("01CHILD"));
        line.reply_to = Some("01PARENT".into());
        buf.push(line);
        let found = buf.find_by_msgid("01CHILD").unwrap();
        assert_eq!(found.reply_to.as_deref(), Some("01PARENT"));
    }

    #[test]
    fn oldest_msgid_skips_system_lines() {
        let mut buf = Buffer::new("#test");
        buf.push_system("joined");
        buf.push(line_with_msgid("first", Some("01AAA")));
        buf.push(line_with_msgid("second", Some("01BBB")));
        assert_eq!(buf.oldest_msgid(), Some("01AAA"));
    }

    #[test]
    fn oldest_msgid_none_on_empty_buffer() {
        let buf = Buffer::new("#test");
        assert!(buf.oldest_msgid().is_none());
    }

    #[test]
    fn end_batch_clears_in_flight_and_marks_exhausted_when_empty() {
        let mut buffers = std::collections::BTreeMap::new();
        let mut b = Buffer::new("#test");
        b.history_in_flight = true;
        buffers.insert("#test".to_string(), b);
        let mut app = App {
            channel_keys: HashMap::new(),
            buffers,
            batches: HashMap::new(),
            active_buffer: "#test".into(),
            editor: crate::editor::LineEditor::new(crate::editor::Mode::Emacs),
            connection_state: String::new(),
            transport: Transport::Tcp,
            server_addr: String::new(),
            iroh_endpoint_id: None,
            connected_at: None,
            authenticated_did: None,
            show_net_popup: false,
            debug_raw: false,
            nick: "alice".into(),
            should_quit: false,
            reconnect_pending: false,
            reconnect_at: None,
            reconnect_delay: Duration::from_secs(1),
            history: Vec::new(),
            history_pos: None,
            history_saved: String::new(),
            media_uploader: None,
            image_cache: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "inline-images")]
            picker: None,
            #[cfg(feature = "inline-images")]
            image_protos: HashMap::new(),
            bg_result_tx: tokio::sync::mpsc::channel(1).0,
            bg_result_rx: None,
            p2p_handle: None,
            p2p_event_rx: None,
            pending_url: None,
            nick_hosts: HashMap::new(),
            did_names: HashMap::new(),
            history_requested: HashSet::new(),
        };
        app.start_batch("b1", "#test");
        app.end_batch("b1");
        let buf = app.buffers.get("#test").unwrap();
        assert!(!buf.history_in_flight, "in-flight cleared on batch end");
        assert!(buf.history_exhausted, "empty batch ⇒ no more history");
    }

    /// SECURITY: edits must only be applied if the editor matches the
    /// original author. Otherwise a malicious peer can rewrite anyone's
    /// message by crafting a +draft/edit targeting their msgid.
    #[test]
    fn apply_edit_rejects_spoofed_sender() {
        let mut buf = Buffer::new("#test");
        buf.push(line("alice's secret", "alice", Some("01ALICE")));

        let applied = buf.apply_edit("mallory", "01ALICE", None, "rewritten by mallory");
        assert!(!applied, "edit from a non-author MUST be rejected");
        let line = buf.find_by_msgid("01ALICE").unwrap();
        assert_eq!(line.text, "alice's secret");
        assert!(!line.is_edited);
    }

    /// CORRECTNESS: `apply_edit` swaps a line's msgid to the new id
    /// the server assigned to the edit. But the channel's pinned set
    /// still referenced the OLD msgid, so the renderer (which checks
    /// `msg.msgid in buffer.pinned`) silently dropped the 📌 marker
    /// from the pinned message. Fix: when swapping msgid, also move
    /// the pin entry.
    #[test]
    fn apply_edit_leaves_a_pin_where_it_is() {
        // Pins key on the message's lifelong id, so an edit needs no pin
        // bookkeeping at all — the marker survives because nothing moved.
        let mut buf = Buffer::new("#test");
        buf.push(line("important", "alice", Some("01OLD")));
        buf.add_pinned("01OLD");

        assert!(buf.apply_edit("alice", "01OLD", Some("01NEW"), "important (refined)"));
        assert!(
            buf.pinned.contains("01OLD"),
            "the pin stays under the message's id: {:?}",
            buf.pinned
        );
        assert!(!buf.pinned.contains("01NEW"));
    }

    /// CORRECTNESS: `end_batch` set `history_exhausted = true` for
    /// every empty batch, regardless of type. But IRCv3 has many batch
    /// types (labeled-response, netjoin, etc.) and an empty
    /// non-CHATHISTORY batch is perfectly normal — it would
    /// permanently disable scroll-up history fetch on that buffer.
    /// Only CHATHISTORY batches should drive that flag.
    #[test]
    fn end_batch_only_marks_exhausted_for_chathistory_type() {
        let mut app = App::new("alice", false);
        app.buffers.insert("#test".into(), Buffer::new("#test"));
        // Non-CHATHISTORY empty batch (e.g., labeled-response).
        app.start_batch_typed("b1", "#test", "labeled-response");
        app.end_batch("b1");
        let buf = app.buffers.get("#test").unwrap();
        assert!(
            !buf.history_exhausted,
            "non-CHATHISTORY empty batch must not mark history exhausted"
        );

        // CHATHISTORY empty batch DOES mark exhausted.
        app.start_batch_typed("b2", "#test", "chathistory");
        app.end_batch("b2");
        let buf = app.buffers.get("#test").unwrap();
        assert!(
            buf.history_exhausted,
            "empty CHATHISTORY batch should mark exhausted"
        );
    }

    /// CORRECTNESS: IRC nicks are case-insensitive (RFC 1459). The
    /// echo of our own message can come back with whatever case the
    /// server canonicalized, but we compared with `==` and so counted
    /// it as someone else's message — incrementing unread + mention on
    /// our own ping.
    #[test]
    fn chat_msg_treats_own_echo_case_insensitively() {
        let mut app = App::new("alice", false);
        app.active_buffer = "status".to_string(); // ensure #ch is inactive

        // Echo of our own message with a different case canonicalization.
        app.chat_msg("#ch", "ALICE", "hello");
        let buf = app.buffers.get("#ch").unwrap();
        assert_eq!(buf.unread, 0, "own echo must not bump unread");
        assert!(!buf.has_mention, "own echo must not flag mention");
    }

    /// DoS: `app.batches` is a HashMap keyed by batch id. A hostile
    /// server could send thousands of BATCH START messages with unique
    /// ids and no matching BATCH END — the map grows forever even
    /// though each individual batch is now capped (Cycle 19). Bound
    /// the number of concurrent in-flight batches.
    #[test]
    fn batches_map_caps_concurrent_in_flight() {
        let mut app = App::new("alice", false);
        for i in 0..(BATCH_CONCURRENT_CAP + 200) {
            app.start_batch(&format!("b{i}"), "#test");
        }
        assert!(
            app.batches.len() <= BATCH_CONCURRENT_CAP,
            "concurrent batch count must be capped at {BATCH_CONCURRENT_CAP}, got {}",
            app.batches.len()
        );
    }

    /// DoS: `add_batch_line` had no upper bound, so a hostile server
    /// could open a BATCH and stream lines forever (never sending the
    /// terminating BATCH END), causing unbounded memory growth in the
    /// `lines` vec. Cap each batch.
    #[test]
    fn batch_buffer_caps_in_flight_lines() {
        let mut app = App::new("alice", false);
        app.start_batch("b1", "#test");
        for i in 0..(BATCH_LINE_CAP + 500) {
            app.add_batch_line(
                "b1",
                i as i64,
                BufferLine {
                    timestamp: "12:00:00".into(),
                    from: "evil-server".into(),
                    text: format!("flood {i}"),
                    is_system: false,
                    image_url: None,
                    msgid: Some(format!("01F{i:05}")),
                    is_edited: false,
                    is_deleted: false,
                    reply_to: None,
                    edit_of: None,
                },
            );
        }
        let batch = app.batches.get("b1").unwrap();
        assert!(
            batch.lines.len() <= BATCH_LINE_CAP,
            "batch lines must be capped at {BATCH_LINE_CAP}, got {}",
            batch.lines.len()
        );
    }

    /// SECURITY: `input_take` pushed every command into the input
    /// history (Ctrl-P / Up-arrow recall). That happily included
    /// `/encrypt <passphrase>` (E2EE channel key) and `/oper <name>
    /// <password>`. A user who scrolls back through history (or whose
    /// session memory is dumped) leaks the passphrase/password. Strip
    /// these before they reach the history vector.
    #[test]
    fn input_history_redacts_sensitive_commands() {
        let mut app = App::new("alice", false);

        app.editor.set("/encrypt sup3r-secret-passphrase".into());
        let _ = app.input_take();
        assert!(
            !app.history.iter().any(|h| h.contains("sup3r-secret")),
            "passphrase must not be in history: {:?}",
            app.history
        );

        app.editor.set("/oper opname my-oper-pass".into());
        let _ = app.input_take();
        assert!(
            !app.history.iter().any(|h| h.contains("my-oper-pass")),
            "oper password must not be in history"
        );

        // Normal commands should still be remembered for recall.
        app.editor.set("/join #freeq".into());
        let _ = app.input_take();
        assert!(app.history.iter().any(|h| h == "/join #freeq"));
    }

    /// CORRECTNESS: `chat_msg` set `buf.has_mention` whenever the text
    /// contained the user's nick as a substring — same false-positive
    /// bug we already fixed in the renderer's mention highlight. A user
    /// nicked "ben" got pinged for every "benevolent", "benchmark", etc.
    #[test]
    fn chat_msg_mention_requires_word_boundary() {
        let mut app = App::new("ben", false);
        // #ch is not active (active buffer is "status").
        app.chat_msg("#ch", "alice", "benevolent leader");
        let buf = app.buffers.get("#ch").unwrap();
        assert!(
            !buf.has_mention,
            "substring 'ben' inside 'benevolent' must not flag mention"
        );

        // Real mention should still set the flag.
        app.chat_msg("#ch", "alice", "ben: please review");
        let buf = app.buffers.get("#ch").unwrap();
        assert!(
            buf.has_mention,
            "actual ping with word boundary must flag mention"
        );
    }

    /// CORRECTNESS: `App::apply_edit`/`apply_delete` route to
    /// `buffer_mut(name)`, which lazily creates the buffer if missing.
    /// A spoofed/misrouted edit targeting a buffer the user never had
    /// open would silently spawn a phantom empty buffer in the tab bar.
    /// We must look up read-only first and bail if the buffer doesn't
    /// exist.
    #[test]
    fn apply_edit_does_not_create_phantom_buffer() {
        let mut app = App::new("alice", false);
        let before: std::collections::BTreeSet<String> = app.buffers.keys().cloned().collect();

        let applied = app.apply_edit(
            "mallory",
            None,
            "#never-joined",
            "01NONEXISTENT",
            None,
            "phantom edit",
        );
        assert!(!applied);
        let after: std::collections::BTreeSet<String> = app.buffers.keys().cloned().collect();
        assert_eq!(
            before, after,
            "no buffer should be created for an edit that didn't apply"
        );
    }

    #[test]
    fn apply_delete_does_not_create_phantom_buffer() {
        let mut app = App::new("alice", false);
        let before: std::collections::BTreeSet<String> = app.buffers.keys().cloned().collect();

        let applied = app.apply_delete("mallory", None, "#never-joined", "01NOPE");
        assert!(!applied);
        let after: std::collections::BTreeSet<String> = app.buffers.keys().cloned().collect();
        assert_eq!(before, after);
    }

    /// DoS: the server caps pins at 50 per channel, but the TUI was
    /// trusting the wire and stuffing every observed `+freeq.at/pin`
    /// tag into the buffer's pin set. A hostile peer (or a buggy/
    /// compromised server) could flood thousands of pin notifications
    /// and balloon memory. Cap defensively on the client.
    #[test]
    fn pinned_set_is_capped_per_channel() {
        let mut buf = Buffer::new("#test");
        for i in 0..(PINNED_CAP + 200) {
            buf.add_pinned(&format!("01PIN{i:04}"));
        }
        assert!(
            buf.pinned.len() <= PINNED_CAP,
            "pinned set should be capped at {PINNED_CAP}, got {}",
            buf.pinned.len()
        );
    }

    /// CORRECTNESS: when a message is deleted, it must be removed from
    /// the channel's pin set too — otherwise the renderer keeps showing
    /// 📌 on a `[deleted]` line, which is confusing and arguably a leak
    /// of the fact that "the deleted message was important enough to pin".
    #[test]
    fn apply_delete_unpins_the_message() {
        let mut buf = Buffer::new("#test");
        buf.push(line("important", "alice", Some("01PIN")));
        buf.pinned.insert("01PIN".to_string());
        assert!(buf.pinned.contains("01PIN"));

        assert!(buf.apply_delete("alice", "01PIN"));
        assert!(
            !buf.pinned.contains("01PIN"),
            "deleted message must be unpinned"
        );
    }

    /// SECURITY: a hostile peer can put an ANSI escape into their nick or
    /// the message body. The render layer interpolates `from` and `text`
    /// directly into terminal output via `<{from}> {text}`, so an escape
    /// would let them move the cursor, recolor everything, or even
    /// repaint the screen. Sanitize at the buffer entry point so no
    /// matter which call site builds a BufferLine, the dangerous bytes
    /// can't reach the terminal.
    #[test]
    fn buffer_push_strips_terminal_escapes_from_from_and_text() {
        let mut buf = Buffer::new("#test");
        buf.push(BufferLine {
            timestamp: "12:00:00".into(),
            from: "alice\x1b[31m\x07".into(),
            text: "hi\x1b[2J\x00there".into(),
            is_system: false,
            image_url: None,
            msgid: Some("01ABC".into()),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
        });
        let line = buf.messages.back().unwrap();
        for c in line.from.chars() {
            assert!(
                !c.is_control(),
                "from must have no control chars, got {:?}",
                line.from
            );
        }
        for c in line.text.chars() {
            assert!(
                c == '\n' || c == '\t' || !c.is_control(),
                "text must have no control chars (except \\n/\\t), got {:?}",
                line.text
            );
        }
    }

    /// SECURITY: `char::is_control()` only catches General_Category=Cc.
    /// Unicode line/paragraph separators (U+2028/U+2029) and BiDi format
    /// chars (U+202E RTL OVERRIDE) are *not* Cc, so `is_control()`
    /// returns false for them. They can still:
    /// - inject into multi-line IRC text (LINE SEPARATOR splits a message
    ///   when the receiving terminal honors Unicode line breaks),
    /// - reverse the visual order of text after them (RTL OVERRIDE — the
    ///   classic "RIGHT-TO-LEFT spoofing" attack),
    /// - be invisible (zero-width joiner, BOM, byte-order mark).
    /// Reject them in msgids — there's no legitimate reason for any of
    /// these to appear in a server-assigned identifier.
    #[test]
    fn is_valid_msgid_rejects_unicode_line_breaks_and_format_chars() {
        // Line/paragraph separators.
        assert!(!is_valid_msgid("abc\u{2028}def"));
        assert!(!is_valid_msgid("abc\u{2029}def"));
        // RTL override (visual spoofing).
        assert!(!is_valid_msgid("abc\u{202E}def"));
        // Zero-width joiner & non-joiner.
        assert!(!is_valid_msgid("abc\u{200D}def"));
        assert!(!is_valid_msgid("abc\u{200C}def"));
        // BOM / zero-width no-break space.
        assert!(!is_valid_msgid("abc\u{FEFF}def"));
    }

    /// SECURITY: a malicious peer (or buggy server) might send a `msgid`
    /// tag whose value contains CR/LF or whitespace. If we pipe that
    /// straight into `handle.pin/unpin/edit/delete`, the SDK formats it
    /// into a raw IRC line — `\r\n` would let the attacker inject a
    /// second command (e.g. `NICK pwn`), and a space alone would split
    /// the command into extra params. Reject anything that isn't a
    /// well-formed token.
    #[test]
    fn is_valid_msgid_rejects_dangerous_inputs() {
        // ULIDs and similar plain tokens are fine.
        assert!(is_valid_msgid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(is_valid_msgid("abc-123_x.y"));
        // Empty is invalid.
        assert!(!is_valid_msgid(""));
        // Whitespace inside.
        assert!(!is_valid_msgid("abc def"));
        assert!(!is_valid_msgid("abc\tdef"));
        // CR/LF — IRC command injection vector.
        assert!(!is_valid_msgid("abc\r\nNICK pwn"));
        assert!(!is_valid_msgid("abc\nfoo"));
        // NUL.
        assert!(!is_valid_msgid("abc\x00def"));
        // ESC — terminal injection.
        assert!(!is_valid_msgid("abc\x1b[31mEVIL"));
        // IRC tag separator and prefix marker.
        assert!(!is_valid_msgid("abc;def"));
        assert!(!is_valid_msgid(":abc"));
        // Length cap — server msgids are ≤ 64 chars; ULIDs are 26.
        let long = "a".repeat(MSGID_MAX_LEN + 1);
        assert!(!is_valid_msgid(&long));
    }

    /// DoS: a hostile network where a flood of distinct nicks JOIN+QUIT
    /// would otherwise grow `nick_hosts` without bound. Cap it.
    #[test]
    fn nick_hosts_does_not_grow_without_bound() {
        let mut app = App::new("alice", false);
        for i in 0..(NICK_HOST_CAP + 500) {
            app.remember_nick_host(&format!("user{i}"), "freeq/plc/test");
        }
        assert!(
            app.nick_hosts.len() <= NICK_HOST_CAP,
            "nick_hosts capped at {NICK_HOST_CAP}, got {}",
            app.nick_hosts.len()
        );
    }

    /// CORRECTNESS: an edit arriving for a line that's already been
    /// deleted must NOT resurrect it — that would leak content the user
    /// expected to be gone, and contradicts the deletion the user (or an
    /// op) just performed.
    #[test]
    fn apply_edit_refuses_to_resurrect_deleted_line() {
        let mut buf = Buffer::new("#test");
        buf.push(line("original", "alice", Some("01ABC")));
        assert!(buf.apply_delete("alice", "01ABC"));
        assert!(buf.find_by_msgid("01ABC").unwrap().is_deleted);

        // alice (or a malicious peer who slipped past the sender check)
        // tries to edit the deleted line.
        let applied = buf.apply_edit("alice", "01ABC", None, "BACK FROM THE DEAD");
        assert!(!applied, "must not edit a deleted line");
        let line = buf.find_by_msgid("01ABC").unwrap();
        assert!(line.is_deleted);
        assert!(line.text.is_empty(), "deleted text must stay empty");
    }

    /// SECURITY: deletes must only be honored from the original author.
    #[test]
    fn apply_delete_rejects_spoofed_sender() {
        let mut buf = Buffer::new("#test");
        buf.push(line("alice's secret", "alice", Some("01ALICE")));

        let applied = buf.apply_delete("mallory", "01ALICE");
        assert!(!applied, "delete from a non-author MUST be rejected");
        let line = buf.find_by_msgid("01ALICE").unwrap();
        assert_eq!(line.text, "alice's secret");
        assert!(!line.is_deleted);
    }

    #[test]
    fn pin_set_tracks_per_channel() {
        let mut buf = Buffer::new("#test");
        buf.pinned.insert("01ABC".into());
        assert!(buf.pinned.contains("01ABC"));
        buf.pinned.remove("01ABC");
        assert!(!buf.pinned.contains("01ABC"));
    }

    #[test]
    fn batch_apply_edit_updates_text_in_place() {
        let mut batch = BatchBuffer {
            target: "#test".into(),
            lines: vec![
                (1, line_with_msgid("v1", Some("01AAA"))),
                (2, line_with_msgid("unrelated", Some("01BBB"))),
            ],
            batch_type: "chathistory".into(),
        };
        assert!(batch.apply_edit("alice", "01AAA", Some("01CCC"), "v2"));
        assert_eq!(batch.lines[0].1.text, "v2");
        assert!(batch.lines[0].1.is_edited);
        // The line keeps the id it was born with; the edit's wire id is
        // never a message's name.
        assert_eq!(batch.lines[0].1.msgid.as_deref(), Some("01AAA"));
        // Other line untouched.
        assert_eq!(batch.lines[1].1.text, "unrelated");
        assert!(!batch.lines[1].1.is_edited);
    }

    #[test]
    fn batch_apply_delete_within_batch() {
        let mut batch = BatchBuffer {
            target: "#test".into(),
            lines: vec![(1, line_with_msgid("secret", Some("01AAA")))],
            batch_type: "chathistory".into(),
        };
        assert!(batch.apply_delete("alice", "01AAA"));
        assert!(batch.lines[0].1.is_deleted);
        assert!(batch.lines[0].1.text.is_empty());
    }

    #[test]
    fn find_by_msgid_survives_ring_buffer_eviction() {
        let mut buf = Buffer::new("#test");
        // Fill past MAX_MESSAGES so early lines get evicted.
        for i in 0..MAX_MESSAGES + 5 {
            buf.push(line_with_msgid(
                &format!("msg {i}"),
                Some(&format!("id{i:04}")),
            ));
        }
        // The first 5 should be gone.
        assert!(buf.find_by_msgid("id0000").is_none());
        assert!(buf.find_by_msgid("id0004").is_none());
        // The most recent one should still be findable.
        let last = MAX_MESSAGES + 4;
        let last_id = format!("id{last:04}");
        assert!(buf.find_by_msgid(&last_id).is_some());
    }

    const DID: &str = "did:plc:k2n3e2vsihf3farequ44t5j7";
    // did:key ids are base58 — mixed case matters on the wire.
    const DID_KEY: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn buffer_key_lowercases_nicks_and_channels_but_not_dids() {
        assert_eq!(buffer_key("#Rust"), "#rust");
        assert_eq!(buffer_key("Alice"), "alice");
        assert_eq!(buffer_key(DID_KEY), DID_KEY);
    }

    #[test]
    fn shorten_did_compacts_long_ids() {
        assert_eq!(shorten_did(DID), "plc:k2n3…t5j7");
        assert_eq!(shorten_did("did:web:example.com"), "web:example.com");
        assert_eq!(shorten_did("alice"), "alice");
    }

    #[test]
    fn display_name_prefers_binding_then_shortens() {
        let mut app = App::new("me", false);
        assert_eq!(app.display_name("alice"), "alice");
        assert_eq!(app.display_name(DID), "plc:k2n3…t5j7");
        app.record_member_did("alice", DID);
        assert_eq!(app.display_name(DID), "alice");
    }

    #[test]
    fn member_did_rekeys_a_lone_nick_thread() {
        let mut app = App::new("me", false);
        app.buffer_mut("Alice")
            .push(line("hi", "alice", Some("01A")));
        app.active_buffer = "alice".to_string();

        app.record_member_did("alice", DID);

        assert!(!app.buffers.contains_key("alice"));
        let buf = app.buffers.get(DID).expect("re-keyed buffer");
        assert_eq!(buf.name, DID);
        assert_eq!(buf.messages.len(), 1);
        // The open thread follows the re-key.
        assert_eq!(app.active_buffer, DID);
    }

    #[test]
    fn member_did_folds_nick_thread_into_existing_did_thread() {
        let mut app = App::new("me", false);
        let nick_buf = app.buffer_mut("alice");
        nick_buf.push(line("cold-start", "alice", Some("01A")));
        nick_buf.push(line("dupe", "alice", Some("01B")));
        nick_buf.unread = 2;
        let did_buf = app.buffer_mut(DID);
        did_buf.push(line("dupe", "alice", Some("01B")));
        did_buf.unread = 1;

        app.record_member_did("alice", DID);

        assert!(!app.buffers.contains_key("alice"));
        let buf = app.buffers.get(DID).unwrap();
        // 01B deduped by msgid; 01A carried over.
        assert_eq!(buf.messages.len(), 2);
        assert!(buf.find_by_msgid("01A").is_some());
        assert_eq!(buf.unread, 3);
    }

    #[test]
    fn member_did_moves_e2ee_key_with_the_thread() {
        let mut app = App::new("me", false);
        app.buffer_mut("alice")
            .push(line("hi", "alice", Some("01A")));
        app.channel_keys.insert("alice".to_string(), [7u8; 32]);

        app.record_member_did("alice", DID);

        assert!(!app.channel_keys.contains_key("alice"));
        assert_eq!(app.channel_keys.get(DID), Some(&[7u8; 32]));
    }

    #[test]
    fn member_did_ignores_channels_and_self_bindings() {
        let mut app = App::new("me", false);
        app.buffer_mut("#general")
            .push(line("hi", "alice", Some("01A")));

        app.record_member_did("#general", DID);
        assert!(app.buffers.contains_key("#general"));
        assert!(!app.buffers.contains_key(DID));

        // A non-DID never becomes a thread key.
        app.record_member_did("alice", "not-a-did");
        assert!(!app.did_names.contains_key("not-a-did"));
    }

    #[test]
    fn push_dedups_unbatched_join_replay() {
        // The server replays history unbatched on JOIN; a line that already
        // arrived (live or via a batch) must not double when pushed again.
        let mut app = App::new("me", false);
        app.buffer_mut("#ship")
            .push(line("hello", "ana", Some("01A")));
        app.buffer_mut("#ship")
            .push(line("hello", "ana", Some("01A")));
        assert_eq!(app.buffers.get("#ship").unwrap().messages.len(), 1);

        // Pre-edit row replayed unbatched after a live edit: the line kept
        // its id, so plain msgid dedup covers it.
        app.buffer_mut("#ship")
            .push(line("v1", "chad", Some("01B")));
        app.apply_edit("chad", None, "#ship", "01B", Some("01C"), "v2");
        app.buffer_mut("#ship")
            .push(line("v1", "chad", Some("01B")));
        let buf = app.buffers.get("#ship").unwrap();
        assert_eq!(buf.messages.len(), 2, "{:?}", buf.messages);
    }

    #[test]
    fn edit_in_batch_also_rewrites_live_buffer_row() {
        // JOIN replay put the pre-edit row in the BUFFER; the edit row then
        // arrives inside a CHATHISTORY batch. The edit must rewrite the
        // buffer's copy too, or the flush appends an edited duplicate.
        let mut app = App::new("me", false);
        app.buffer_mut("#ship")
            .push(line("v1", "chad", Some("01A")));

        app.start_batch_typed("h1", "#ship", "chathistory");
        app.add_batch_line("h1", 1, line("v1", "chad", Some("01A")));
        app.apply_edit("chad", Some("h1"), "#ship", "01A", Some("01B"), "v2");
        app.end_batch("h1");

        let buf = app.buffers.get("#ship").unwrap();
        assert_eq!(
            buf.messages.len(),
            1,
            "one row after batch edit over join-replayed original: {:?}",
            buf.messages
                .iter()
                .map(|l| (&l.text, &l.msgid))
                .collect::<Vec<_>>()
        );
        let row = buf.messages.front().unwrap();
        assert_eq!(row.text, "v2");
        assert!(row.is_edited);
        assert_eq!(row.msgid.as_deref(), Some("01A"));
    }

    #[test]
    fn second_history_replay_does_not_resurrect_pre_edit_row() {
        // The staging bug (2026-07-23): join-time + activate-time CHATHISTORY
        // both fire. Batch 1 replays original(01A) + edit row — apply_edit
        // rewrites the line's msgid to 01B. Batch 2 replays the SAME rows;
        // the pre-edit row (01A) must dedup via the edit alias, not re-append
        // the stale text alongside the edited line.
        let mut app = App::new("me", false);

        // Batch 1: original + in-batch edit.
        app.start_batch_typed("h1", "#ship", "chathistory");
        app.add_batch_line("h1", 1, line("shipping it aa", "chad", Some("01A")));
        app.apply_edit(
            "chad",
            Some("h1"),
            "#ship",
            "01A",
            Some("01B"),
            "shipping it 🚀",
        );
        app.end_batch("h1");
        {
            let buf = app.buffers.get("#ship").unwrap();
            assert_eq!(buf.messages.len(), 1);
            assert_eq!(buf.messages.front().unwrap().msgid.as_deref(), Some("01A"));
            assert!(buf.messages.front().unwrap().is_edited);
        }

        // Batch 2 (racing duplicate request): same two rows again.
        app.start_batch_typed("h2", "#ship", "chathistory");
        app.add_batch_line("h2", 1, line("shipping it aa", "chad", Some("01A")));
        app.apply_edit(
            "chad",
            Some("h2"),
            "#ship",
            "01A",
            Some("01B"),
            "shipping it 🚀",
        );
        app.end_batch("h2");

        let buf = app.buffers.get("#ship").unwrap();
        assert_eq!(
            buf.messages.len(),
            1,
            "pre-edit row must not resurrect on a second replay: {:?}",
            buf.messages
                .iter()
                .map(|l| (&l.text, &l.msgid))
                .collect::<Vec<_>>()
        );
        assert_eq!(buf.messages.front().unwrap().text, "shipping it 🚀");
    }

    #[test]
    fn live_edit_then_history_replay_of_original_dedups() {
        // Live path variant: message arrived live (01A), a live edit rewrote
        // it to 01B, then a CHATHISTORY backfill replays the original row.
        let mut app = App::new("me", false);
        app.buffer_mut("#ship")
            .push(line("v1", "chad", Some("01A")));
        app.apply_edit("chad", None, "#ship", "01A", Some("01B"), "v2");

        app.start_batch_typed("h1", "#ship", "chathistory");
        app.add_batch_line("h1", 1, line("v1", "chad", Some("01A")));
        app.end_batch("h1");

        let buf = app.buffers.get("#ship").unwrap();
        assert_eq!(
            buf.messages.len(),
            1,
            "original row must dedup via edit alias"
        );
        assert_eq!(buf.messages.front().unwrap().text, "v2");
    }

    #[test]
    fn end_batch_dedups_by_msgid_against_existing() {
        // A DM's CHATHISTORY LATEST backfill overlaps messages already shown
        // live; the flush must not double them.
        let mut app = App::new("me", false);
        app.buffer_mut("bob")
            .push(line("live", "bob", Some("01LIVE")));

        app.start_batch("h1", "bob");
        // History returns an older message plus the one already present.
        app.add_batch_line("h1", 1, line("older", "bob", Some("01OLD")));
        app.add_batch_line("h1", 2, line("live", "bob", Some("01LIVE")));
        app.end_batch("h1");

        let buf = app.buffers.get("bob").unwrap();
        assert_eq!(buf.messages.len(), 2, "duplicate msgid must be skipped");
        // Older prepended, the live one kept its single copy.
        assert_eq!(
            buf.messages.front().unwrap().msgid.as_deref(),
            Some("01OLD")
        );
        assert_eq!(
            buf.messages.back().unwrap().msgid.as_deref(),
            Some("01LIVE")
        );
    }

    #[test]
    fn dm_e2ee_salt_is_symmetric() {
        let alice = "did:plc:alice";
        let bob = "did:key:z6MkBobBobBob";

        // Alice's DM buffer with Bob is keyed by Bob's DID; Bob's by Alice's.
        let mut a = App::new("alice", false);
        a.authenticated_did = Some(alice.to_string());
        let salt_a = a.dm_e2ee_salt(bob).expect("alice salt");

        let mut b = App::new("bob", false);
        b.authenticated_did = Some(bob.to_string());
        let salt_b = b.dm_e2ee_salt(alice).expect("bob salt");

        // Same canonical salt → same derived key from a shared passphrase.
        assert_eq!(salt_a, salt_b, "both peers derive the same DM salt");
        assert_eq!(
            freeq_sdk::e2ee::derive_key("hunter2", &salt_a),
            freeq_sdk::e2ee::derive_key("hunter2", &salt_b),
        );

        // No symmetric salt when the peer DID is unknown, or we're a guest.
        assert!(a.dm_e2ee_salt("someguest").is_none(), "unknown peer DID");
        let mut guest = App::new("g", false);
        assert!(guest.dm_e2ee_salt(bob).is_none(), "guest has no own DID");
    }

    #[test]
    fn did_rename_tracks_display_name() {
        let mut app = App::new("me", false);
        app.record_member_did("alice", DID);
        app.did_rename("Alice", "alicia");
        assert_eq!(app.display_name(DID), "alicia");
    }
}

/// Evict oldest entries from image cache if over capacity.
pub fn evict_image_cache(cache: &ImageCache) {
    let mut guard = cache.lock().unwrap();
    if guard.len() > MAX_IMAGE_CACHE {
        // Simple eviction: remove Failed entries first, then arbitrary
        let failed_keys: Vec<String> = guard
            .iter()
            .filter(|(_, v)| matches!(v, ImageState::Failed(_)))
            .map(|(k, _)| k.clone())
            .collect();
        for k in failed_keys {
            guard.remove(&k);
            if guard.len() <= MAX_IMAGE_CACHE {
                return;
            }
        }
        // Still over? Remove arbitrary entries until within limit
        let keys: Vec<String> = guard.keys().cloned().collect();
        for k in keys {
            if guard.len() <= MAX_IMAGE_CACHE {
                break;
            }
            guard.remove(&k);
        }
    }
}

#[cfg(test)]
mod delete_after_edit_tests {
    //! Deleting an *edited* message must still work.
    //!
    //! Deletes always name the ORIGINAL msgid — the identity clients hold,
    //! and what the server relays in `+draft/delete`. A line keeps that id
    //! across edits, so the delete resolves by plain id lookup; these tests
    //! pin that an edit never breaks the delete path.
    use super::*;

    fn line(msgid: &str, from: &str, text: &str) -> BufferLine {
        BufferLine {
            timestamp: "12:00".into(),
            from: from.into(),
            text: text.into(),
            is_system: false,
            image_url: None,
            msgid: Some(msgid.into()),
            is_edited: false,
            is_deleted: false,
            reply_to: None,
            edit_of: None,
        }
    }

    #[test]
    fn delete_by_original_msgid_after_edit() {
        let mut buf = Buffer::new("#t");
        buf.messages.push_back(line("orig", "alice", "secret v1"));
        assert!(buf.apply_edit("alice", "orig", Some("edit1"), "secret v2"));

        assert!(
            buf.apply_delete("alice", "orig"),
            "delete naming the original msgid must apply after an edit"
        );
        let l = buf.messages.back().unwrap();
        assert!(l.is_deleted);
        assert!(l.text.is_empty());
    }

    #[test]
    fn an_edit_never_changes_the_line_id() {
        // The invariant everything else here rests on: reactions, pins,
        // deletes and replay dedup all key on the id the message was born
        // with, so an edit must leave it alone.
        let mut buf = Buffer::new("#t");
        buf.messages.push_back(line("orig", "alice", "v1"));
        assert!(buf.apply_edit("alice", "orig", Some("edit1"), "v2"));
        let l = buf.messages.back().unwrap();
        assert_eq!(l.msgid.as_deref(), Some("orig"));
        assert_eq!(l.text, "v2");
        assert!(l.is_edited);
        // A pin on the message needs no re-keying to survive the edit.
        buf.pinned.insert("orig".into());
        assert!(buf.apply_edit("alice", "orig", Some("edit2"), "v3"));
        assert!(buf.pinned.contains("orig"));
    }

    #[test]
    fn author_check_still_applies_through_the_alias() {
        // The nick check is the client-side defence against spoofed wire events;
        // reaching the line via editOf must not bypass it.
        let mut buf = Buffer::new("#t");
        buf.messages.push_back(line("orig", "alice", "v1"));
        buf.apply_edit("alice", "orig", Some("edit1"), "v2");
        assert!(!buf.apply_delete("mallory", "orig"));
        assert!(!buf.messages.back().unwrap().is_deleted);
    }

    #[test]
    fn unrelated_lines_are_untouched() {
        let mut buf = Buffer::new("#t");
        buf.messages.push_back(line("orig", "alice", "v1"));
        buf.messages.push_back(line("other", "alice", "keep me"));
        buf.apply_edit("alice", "orig", Some("edit1"), "v2");
        buf.apply_delete("alice", "orig");
        let other = buf
            .messages
            .iter()
            .find(|l| l.msgid.as_deref() == Some("other"))
            .unwrap();
        assert!(!other.is_deleted);
        assert_eq!(other.text, "keep me");
    }
}
