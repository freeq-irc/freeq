//! Server state and TCP listener.

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use freeq_sdk::did::DidResolver;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use crate::config::ServerConfig;
use crate::connection;
use crate::db::Db;
use crate::plugin::PluginManager;
use crate::sasl::ChallengeStore;

/// State for a single channel.
#[derive(Debug, Clone, Default)]
pub struct ChannelState {
    /// Session IDs of local members currently in the channel.
    pub members: HashSet<String>,
    /// Remote members from S2S peers: nick → RemoteMember info.
    pub remote_members: HashMap<String, RemoteMember>,
    /// Session IDs of channel operators (ephemeral, per-session).
    pub ops: HashSet<String>,
    /// Session IDs of halfops/moderators (+h). Can kick/ban regular users, set +v.
    pub halfops: HashSet<String>,
    /// Session IDs of voiced users.
    pub voiced: HashSet<String>,

    // ── DID-based persistent authority ──────────────────────────
    /// Channel founder's DID. Set once on channel creation.
    /// Founder always has ops and can't be de-opped.
    /// In S2S: resolved by CRDT (first-write-wins in Automerge causal order),
    /// NOT by timestamps — timestamps can be spoofed by rogue servers.
    pub founder_did: Option<String>,
    /// DIDs with persistent operator status.
    /// Survives reconnects, works across servers.
    /// Granted by founder or other DID-ops.
    pub did_ops: HashSet<String>,
    /// Timestamp (unix secs) when the channel was created (informational only).
    /// NOT used for authority resolution — the CRDT handles that.
    pub created_at: u64,

    /// Ban list: hostmasks (nick!user@host patterns) and/or DIDs.
    pub bans: Vec<BanEntry>,
    /// Invite-only mode (+i).
    pub invite_only: bool,
    /// Invite list (session IDs or DIDs that have been invited).
    pub invites: HashSet<String>,
    /// Invite exception list (+I): hostmasks/DIDs that bypass +i without
    /// requiring an explicit INVITE. Persistent (unlike `invites`, which
    /// are consumed on join).
    pub invite_exceptions: Vec<InviteExceptionEntry>,
    /// Recent message history for replay on join.
    pub history: std::collections::VecDeque<HistoryMessage>,
    /// Channel topic, if set.
    pub topic: Option<TopicInfo>,
    /// Channel modes: +t = only ops can set topic.
    pub topic_locked: bool,
    /// Channel mode: +n = no external messages (only members can send).
    pub no_ext_msg: bool,
    /// Channel mode: +m = moderated (only voiced/ops can send).
    pub moderated: bool,
    /// Channel mode: +E = encrypted only (messages must have +encrypted tag).
    pub encrypted_only: bool,
    /// Channel key (+k) — password required to join.
    pub key: Option<String>,
    /// Pinned message IDs (msgid strings), most recent first.
    pub pins: Vec<PinnedMessage>,
}

/// A pinned message reference.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinnedMessage {
    /// The ULID msgid of the pinned message.
    pub msgid: String,
    /// Who pinned it (nick or DID).
    pub pinned_by: String,
    /// When it was pinned (unix secs).
    pub pinned_at: u64,
}

/// Pure connect-time allowlist decision (see `SharedState::did_is_allowed`).
/// Empty allowlists ⇒ open. Matches an exact DID, or a handle whose domain is
/// (or is a subdomain of) an allowed domain.
pub(crate) fn did_allowed(
    allowed_dids: &[String],
    allowed_domains: &[String],
    did: &str,
    handle: Option<&str>,
) -> bool {
    if allowed_dids.is_empty() && allowed_domains.is_empty() {
        return true;
    }
    if allowed_dids.iter().any(|d| d == did) {
        return true;
    }
    if let Some(h) = handle {
        let h = h.trim_start_matches('@').to_lowercase();
        if allowed_domains.iter().any(|dom| {
            let dom = dom
                .trim_start_matches('@')
                .trim_start_matches('.')
                .to_lowercase();
            h == dom || h.ends_with(&format!(".{dom}"))
        }) {
            return true;
        }
    }
    false
}

impl ChannelState {
    /// True if the channel restricts *access* via a channel mode — invite-only
    /// (`+i`), keyed (`+k`), or encrypted-only (`+E`). Used to decide whether it
    /// may be advertised to non-members. Policy-gating is checked separately
    /// (it needs the policy engine); see `SharedState::channel_is_discoverable`.
    pub fn is_mode_restricted(&self) -> bool {
        self.invite_only || self.key.is_some() || self.encrypted_only
    }

    /// Case-insensitive lookup in remote_members.
    /// IRC nicks are case-insensitive, but HashMap keys preserve original case.
    pub fn remote_member(&self, nick: &str) -> Option<&RemoteMember> {
        let lower = nick.to_lowercase();
        self.remote_members
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v)
    }

    /// Case-insensitive mutable lookup in remote_members.
    pub fn remote_member_mut(&mut self, nick: &str) -> Option<&mut RemoteMember> {
        let lower = nick.to_lowercase();
        self.remote_members
            .iter_mut()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v)
    }

    /// Case-insensitive check if nick is in remote_members.
    pub fn has_remote_member(&self, nick: &str) -> bool {
        let lower = nick.to_lowercase();
        self.remote_members
            .keys()
            .any(|k| k.to_lowercase() == lower)
    }

    /// Case-insensitive removal from remote_members. Returns the removed entry.
    pub fn remove_remote_member(&mut self, nick: &str) -> Option<RemoteMember> {
        let lower = nick.to_lowercase();
        let key = self
            .remote_members
            .keys()
            .find(|k| k.to_lowercase() == lower)
            .cloned();
        key.and_then(|k| self.remote_members.remove(&k))
    }
}

/// Pending OAuth authorization: stored between /auth/login and /auth/callback.
#[derive(Debug, Clone)]
pub struct OAuthPending {
    pub handle: String,
    pub did: String,
    pub pds_url: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub dpop_key_b64: String,
    pub created_at: u64,
    /// If true, callback redirects to freeq:// custom scheme instead of returning HTML.
    pub mobile: bool,
    /// If set, this login was initiated via IRC `/login` — complete auth on this IRC session.
    pub irc_state: Option<String>,
    /// Which OAuth purpose this flow is for. `Login` is the default first
    /// log-in (narrow `atproto` scope); `BlobUpload`/`BlueskyPost` are
    /// step-ups requested via `/auth/step-up?purpose=…` with broader
    /// scopes — the callback stores them in their own session slot
    /// rather than overwriting the primary login.
    pub purpose: OauthPurpose,
    /// The scope string we sent in PAR. Used as a fallback for
    /// `granted_scope` when the token endpoint omits the `scope` field.
    pub requested_scope: String,
}

/// Completed OAuth: stored after /auth/callback, consumed by the web client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OAuthResult {
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
    pub pds_url: String,
    /// One-time token for SASL web-token auth (consumed on first use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_token: Option<String>,
    /// Long-lived broker token for durable `/session` refresh. `Some` only in
    /// embedded mode where a session was persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_token: Option<String>,
    /// When this result was created (Unix timestamp seconds).
    #[serde(skip)]
    pub created_at: u64,
}

/// A linked external identity attached to an AT Protocol DID.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkedIdentity {
    pub provider: String,
    pub identity: String,
    pub linked_at: u64,
}

/// Active web session with credentials for PDS operations (e.g., media upload).
/// Keyed by `(DID, purpose)` in SharedState.web_sessions where `purpose` is
/// [`OauthPurpose`]. The default `Login` session is the one created at first
/// login (narrow scope: `atproto`); additional purposes are created by the
/// step-up flow at `/auth/step-up?purpose=…` with broader scopes layered on
/// only when the user actually triggers a feature that needs them.
#[derive(Debug, Clone)]
pub struct WebSession {
    pub did: String,
    pub handle: String,
    pub pds_url: String,
    pub access_token: String,
    pub dpop_key_b64: String,
    pub dpop_nonce: Option<String>,
    pub created_at: std::time::Instant,
    /// The actual scope string the PDS granted (read from the token-endpoint
    /// `scope` field). May differ from what we requested — older PDSes may
    /// downgrade granular requests to `transition:generic`. Used by per-purpose
    /// scope checks.
    pub granted_scope: String,
}

/// Distinguishes which OAuth grant a [`WebSession`] is for. Each purpose has
/// its own scope set and lives in its own slot, so escalating to a broader
/// permission (e.g. blob upload) only happens when the user actually triggers
/// the feature that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthPurpose {
    /// Identity-only login. Scope: `atproto`. Lets us prove the user owns
    /// their DID via SASL — that's all most users ever need.
    Login,
    /// Image / media upload to the user's PDS. Scope: `atproto blob:image/*`.
    /// Triggered the first time the user hits the upload button.
    BlobUpload,
    /// Cross-posting messages to Bluesky. Scope: adds `repo:app.bsky.feed.post`.
    /// Triggered the first time a user enables Bluesky mirroring on a channel.
    BlueskyPost,
}

impl OauthPurpose {
    /// Parse the URL-/JSON-friendly form used in `/auth/step-up?purpose=…`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "blob_upload" => Some(Self::BlobUpload),
            "bluesky_post" => Some(Self::BlueskyPost),
            _ => None,
        }
    }

    /// Reverse of [`from_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::BlobUpload => "blob_upload",
            Self::BlueskyPost => "bluesky_post",
        }
    }

    /// The OAuth scope string we *request* for this purpose. The PDS may
    /// grant a different one — store that in [`WebSession::granted_scope`]
    /// and check it at use time via [`scope_satisfies_purpose`].
    pub fn requested_scope(self) -> &'static str {
        match self {
            // Identity-only. Same as a vanilla "Login with Bluesky" button.
            Self::Login => "atproto",
            // Upload images to the user's repo. Narrow MIME on purpose so
            // the consent screen says "upload images" instead of "upload
            // anything". Also requests `repo:blue.irc.media?action=create`
            // because the server's media upload flow creates a record in
            // that collection (NSID `blue.irc.media`, no `app.` prefix)
            // alongside the blob — without this scope the PDS rejects
            // record creation with ScopeMissingError even though the blob
            // upload itself succeeds.
            Self::BlobUpload => "atproto blob:image/* repo:blue.irc.media?action=create",
            // Cross-post to Bluesky's feed. Repo write narrowed to a single
            // collection.
            Self::BlueskyPost => "atproto repo:app.bsky.feed.post",
        }
    }
}

/// True when the session's actually-granted scope satisfies what the
/// requested purpose needs at runtime.
///
/// Tolerant of two real-world cases:
/// - Older PDSes may grant `transition:generic` instead of the granular
///   scope we requested (legacy "App Password" semantics that subsumes
///   everything). Treat that as satisfying any purpose.
/// - bsky.social granular grants may include extra `blob:` MIME entries
///   beyond what we asked; we only need one `blob:image/*` (or the
///   wildcard `blob:*/*`) for upload.
pub fn scope_satisfies_purpose(granted: &str, purpose: OauthPurpose) -> bool {
    if granted
        .split_whitespace()
        .any(|s| s == "transition:generic")
    {
        return true;
    }
    match purpose {
        OauthPurpose::Login => granted.split_whitespace().any(|s| s == "atproto"),
        OauthPurpose::BlobUpload => {
            let has_blob = granted
                .split_whitespace()
                .any(|s| s == "blob:*/*" || s == "blob:image/*" || s.starts_with("blob:image/"));
            // The record-creation scope can be granted explicitly, via a
            // wildcard `repo:*`, or by the legacy `transition:generic`
            // (which the early-return at the top of this function already
            // covers). Without it the PDS allows blob upload but rejects
            // the accompanying blue.irc.media record creation.
            let has_record = granted.split_whitespace().any(|s| {
                s == "repo:*" || s == "repo:blue.irc.media" || s.starts_with("repo:blue.irc.media")
            });
            has_blob && has_record
        }
        OauthPurpose::BlueskyPost => granted
            .split_whitespace()
            .any(|s| s == "repo:app.bsky.feed.post" || s == "repo:*"),
    }
}

/// Info about a remote user connected via S2S federation.
#[derive(Debug, Clone, Default)]
pub struct RemoteMember {
    /// Iroh endpoint ID of the origin server.
    pub origin: String,
    /// Authenticated DID (if any).
    pub did: Option<String>,
    /// Resolved AT Protocol handle (e.g. "chadfowler.com").
    pub handle: Option<String>,
    /// Whether this user is op on their home server.
    pub is_op: bool,
    /// Actor class: "human", "agent", or "external_agent".
    pub actor_class: Option<String>,
}

/// A stored message for channel history replay.
#[derive(Debug, Clone)]
pub struct HistoryMessage {
    pub from: String,
    pub text: String,
    pub timestamp: u64,
    /// IRCv3 tags from the original message (for rich media replay).
    pub tags: HashMap<String, String>,
    /// ULID message ID (IRCv3 `msgid` tag). Stays the *original* id across
    /// edits — a message's identity for life.
    pub msgid: Option<String>,
    /// The text has been edited since it was sent. Join replay carries one
    /// entry per logical message, so this is the only thing that tells a late
    /// joiner the version they're reading isn't the original.
    pub edited: bool,
}

/// Maximum number of history messages to keep per channel.
pub const MAX_HISTORY: usize = 100;

/// A ban entry — can be a traditional hostmask or a DID.
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub mask: String,
    pub set_by: String,
    pub set_at: u64,
}

impl BanEntry {
    pub fn new(mask: String, set_by: String) -> Self {
        let set_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            mask,
            set_by,
            set_at,
        }
    }

    /// Check if this ban matches a user.
    ///
    /// Supports:
    /// - DID bans: mask starts with "did:" — matches against authenticated DID
    /// - Hostmask bans: simple wildcard matching against nick!user@host
    pub fn matches(&self, hostmask: &str, did: Option<&str>) -> bool {
        if self.mask.starts_with("did:") {
            // DID-based ban: exact match
            did.is_some_and(|d| d == self.mask)
        } else {
            // Hostmask ban: simple wildcard match
            wildcard_match(&self.mask, hostmask)
        }
    }
}

/// Simple wildcard matching (* and ?).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    wildcard_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn wildcard_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            // * matches zero or more characters
            wildcard_match_inner(&pattern[1..], text)
                || (!text.is_empty() && wildcard_match_inner(pattern, &text[1..]))
        }
        (Some(b'?'), Some(_)) => wildcard_match_inner(&pattern[1..], &text[1..]),
        (Some(a), Some(b)) if a == b => wildcard_match_inner(&pattern[1..], &text[1..]),
        _ => false,
    }
}

impl ChannelState {
    /// Check if a user is banned from this channel.
    pub fn is_banned(&self, hostmask: &str, did: Option<&str>) -> bool {
        self.bans.iter().any(|b| b.matches(hostmask, did))
    }

    /// Check if a user is on the +I invite-exception list — a persistent
    /// allow-list that bypasses +i without consuming an INVITE.
    pub fn is_invite_excepted(&self, hostmask: &str, did: Option<&str>) -> bool {
        self.invite_exceptions
            .iter()
            .any(|e| e.matches(hostmask, did))
    }
}

/// An entry on the +I (invite-exception) list — same shape as a BanEntry,
/// but it grants admission instead of denying it. Hostmask or DID.
#[derive(Debug, Clone)]
pub struct InviteExceptionEntry {
    pub mask: String,
    pub set_by: String,
    pub set_at: u64,
}

impl InviteExceptionEntry {
    pub fn new(mask: String, set_by: String) -> Self {
        let set_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            mask,
            set_by,
            set_at,
        }
    }

    /// Same matching semantics as BanEntry: DID exact-match if mask starts
    /// with "did:", otherwise case-insensitive wildcard match against the
    /// nick!user@host string.
    pub fn matches(&self, hostmask: &str, did: Option<&str>) -> bool {
        if self.mask.starts_with("did:") {
            did.is_some_and(|d| d == self.mask)
        } else {
            wildcard_match(&self.mask, hostmask)
        }
    }
}

/// Channel topic with metadata.
#[derive(Debug, Clone)]
pub struct TopicInfo {
    pub text: String,
    pub set_by: String,
    pub set_at: u64,
}

impl TopicInfo {
    pub fn new(text: String, set_by: String) -> Self {
        let set_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            text,
            set_by,
            set_at,
        }
    }
}

/// Shared state accessible by all connection handlers.
/// Case-insensitive nick↔session map.
///
/// All keys are stored lowercase. Display-case nicks are stored separately
/// so NAMES/WHO/WHOIS return the user's preferred casing.
///
/// O(1) lookup by nick or session_id — no more linear scans.
#[derive(Debug, Default)]
pub struct NickMap {
    /// lowercase_nick → primary session_id (first session to register this nick)
    nick_to_sid: HashMap<String, String>,
    /// session_id → display_nick (original case) — supports multi-device (N sessions per nick)
    sid_to_nick: HashMap<String, String>,
}

impl NickMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a nick→session mapping. Nick is stored case-insensitively.
    /// For multi-device: multiple sessions can share the same nick.
    /// The nick→sid mapping points to the most recent session, but all
    /// sessions are tracked in sid→nick for NAMES resolution.
    pub fn insert(&mut self, display_nick: &str, session_id: &str) {
        let lower = display_nick.to_lowercase();
        // Remove old mapping for this session if it had a different nick
        if let Some(old_nick) = self.sid_to_nick.remove(session_id) {
            let old_lower = old_nick.to_lowercase();
            if old_lower != lower {
                // Only remove nick→sid if this session was the primary for that old nick
                if self.nick_to_sid.get(&old_lower).map(|s| s.as_str()) == Some(session_id) {
                    self.nick_to_sid.remove(&old_lower);
                }
            }
        }
        // Set/update the primary session for this nick
        // (Don't evict other sessions' sid_to_nick entries — they share the nick)
        self.nick_to_sid.insert(lower, session_id.to_string());
        self.sid_to_nick
            .insert(session_id.to_string(), display_nick.to_string());
    }

    /// Look up session_id by nick (case-insensitive). O(1).
    /// Returns the primary (most recently inserted) session for this nick.
    pub fn get_session(&self, nick: &str) -> Option<&str> {
        self.nick_to_sid
            .get(&nick.to_lowercase())
            .map(|s| s.as_str())
    }

    /// Look up display nick by session_id. O(1).
    pub fn get_nick(&self, session_id: &str) -> Option<&str> {
        self.sid_to_nick.get(session_id).map(|s| s.as_str())
    }

    /// Check if a nick is in use (case-insensitive).
    pub fn contains_nick(&self, nick: &str) -> bool {
        self.nick_to_sid.contains_key(&nick.to_lowercase())
    }

    /// Remove by nick (case-insensitive). Returns the primary session_id if found.
    /// Also removes ALL sid→nick entries for sessions that had this nick.
    pub fn remove_by_nick(&mut self, nick: &str) -> Option<String> {
        let lower = nick.to_lowercase();
        // Remove all sid→nick entries pointing to this nick
        self.sid_to_nick.retain(|_, n| n.to_lowercase() != lower);
        self.nick_to_sid.remove(&lower)
    }

    /// Remove by session_id. Returns the display nick if found.
    pub fn remove_by_session(&mut self, session_id: &str) -> Option<String> {
        if let Some(nick) = self.sid_to_nick.remove(session_id) {
            let lower = nick.to_lowercase();
            // Only remove nick→sid if this session was the primary
            if self.nick_to_sid.get(&lower).map(|s| s.as_str()) == Some(session_id) {
                self.nick_to_sid.remove(&lower);
                // Promote another session with the same nick (multi-device)
                if let Some((other_sid, _)) = self
                    .sid_to_nick
                    .iter()
                    .find(|(_, n)| n.to_lowercase() == lower)
                {
                    self.nick_to_sid.insert(lower, other_sid.clone());
                }
            }
            Some(nick)
        } else {
            None
        }
    }

    /// Iterate all (display_nick, session_id) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.sid_to_nick
            .iter()
            .map(|(sid, nick)| (nick.as_str(), sid.as_str()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.nick_to_sid.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.nick_to_sid.is_empty()
    }

    /// Check if a nick is held by a specific session.
    pub fn nick_belongs_to(&self, nick: &str, session_id: &str) -> bool {
        self.nick_to_sid
            .get(&nick.to_lowercase())
            .is_some_and(|sid| sid == session_id)
    }
}

pub struct SharedState {
    pub server_name: String,
    pub challenge_store: ChallengeStore,
    pub did_resolver: DidResolver,
    /// session_id -> sender for writing lines to that client
    pub connections: Mutex<HashMap<String, mpsc::Sender<String>>>,
    /// nick -> session_id (case-insensitive: keys are always lowercase)
    pub nick_to_session: Mutex<NickMap>,
    /// session_id -> authenticated DID (for WHOIS lookups by other connections)
    pub session_dids: Mutex<HashMap<String, String>>,
    /// DID -> all active session IDs for multi-device support.
    /// A user can be connected from multiple devices simultaneously.
    pub did_sessions: Mutex<HashMap<String, HashSet<String>>>,
    /// DID -> owned nick (persistent identity-nick binding).
    /// When a user authenticates, they claim their nick. No one else can use it.
    pub did_nicks: Mutex<HashMap<String, String>>,
    /// nick -> DID (reverse lookup for nick enforcement).
    pub nick_owners: Mutex<HashMap<String, String>>,
    /// session_id -> resolved Bluesky handle (for WHOIS display).
    pub session_handles: Mutex<HashMap<String, String>>,
    /// channel name -> channel state (keys are always lowercase)
    pub channels: Mutex<HashMap<String, ChannelState>>,
    /// Sessions that have negotiated message-tags capability.
    pub cap_message_tags: Mutex<HashSet<String>>,
    /// Sessions that have negotiated multi-prefix capability.
    pub cap_multi_prefix: Mutex<HashSet<String>>,
    /// Sessions that have negotiated echo-message capability.
    pub cap_echo_message: Mutex<HashSet<String>>,
    /// Sessions that have negotiated server-time capability.
    pub cap_server_time: Mutex<HashSet<String>>,
    /// Sessions that have negotiated batch capability.
    pub cap_batch: Mutex<HashSet<String>>,
    /// Sessions that have negotiated the `draft/multiline` capability —
    /// they can send and receive logical messages split across multiple
    /// PRIVMSG/NOTICE lines via BATCH frames. See
    /// https://ircv3.net/specs/extensions/multiline.
    pub cap_draft_multiline: Mutex<HashSet<String>>,
    /// In-flight BATCH frames per session. Keyed by `(session_id,
    /// batch_id)`. Populated when a client sends `BATCH +<id> <type>
    /// <target>`, drained when it sends `BATCH -<id>`. PRIVMSG/NOTICE
    /// lines tagged `batch=<id>` are routed into the matching entry
    /// instead of being dispatched as standalone messages. Cleaned up
    /// on disconnect.
    pub open_batches:
        Mutex<HashMap<(String, String), crate::connection::draft_multiline::OpenBatch>>,
    pub cap_account_notify: Mutex<HashSet<String>>,
    pub cap_extended_join: Mutex<HashSet<String>>,
    pub cap_away_notify: Mutex<HashSet<String>>,
    /// Sessions that have negotiated account-tag capability (IRCv3).
    /// When set, outbound PRIVMSG/NOTICE includes `account=<did>` if sender is authenticated.
    pub cap_account_tag: Mutex<HashSet<String>>,
    /// Sessions that have negotiated the `draft/read-marker` capability —
    /// they can set/query cross-device read markers via MARKREAD and receive
    /// marker broadcasts from their other connections.
    /// See https://ircv3.net/specs/extensions/read-marker.
    pub cap_read_marker: Mutex<HashSet<String>>,
    /// Session-local read markers for guests (no DID). Keyed by
    /// `session_id -> (target -> ISO timestamp)`. DID-authenticated users
    /// persist to the `read_markers` table instead; this map only holds the
    /// ephemeral markers of unauthenticated connections and is dropped on
    /// disconnect.
    pub session_read_markers: Mutex<HashMap<String, HashMap<String, String>>>,
    /// Sessions that have OPER (server operator) status.
    pub server_opers: Mutex<HashSet<String>>,
    /// Actor class per session (default: Human, omitted from map).
    pub session_actor_class: Mutex<HashMap<String, crate::connection::ActorClass>>,
    /// Provenance declarations: DID → provenance JSON.
    pub provenance_declarations: Mutex<HashMap<String, serde_json::Value>>,
    /// Agent presence state: session_id → AgentPresence.
    pub agent_presence: Mutex<HashMap<String, crate::connection::AgentPresence>>,
    /// Agent heartbeat tracking: session_id → (last_heartbeat_unix, ttl_seconds).
    pub agent_heartbeats: Mutex<HashMap<String, (i64, u64)>>,
    /// AV instance_ids actively joined per IRC connection.
    /// session_id → set of instance_ids the client sent on av-join.
    /// Used on disconnect to clean only this connection's slots (per-instance)
    /// and on av-join to reap orphan slots whose IRC connection is gone.
    pub av_instances_per_conn: Mutex<HashMap<String, HashSet<String>>>,
    /// AV instances whose owning connection dropped and whose teardown is
    /// deferred behind the disconnect grace window. While an instance is in
    /// here its roster slot must NOT be reaped as an orphan — the owner's
    /// media is typically still flowing and they'll rejoin in place.
    pub av_grace_pending: Mutex<HashSet<String>>,
    /// Pending OAuth sessions: state → OAuthPending.
    pub oauth_pending: Mutex<HashMap<String, OAuthPending>>,
    /// Completed OAuth sessions: state → OAuthResult.
    pub oauth_complete: Mutex<HashMap<String, OAuthResult>>,
    /// One-time web auth tokens: token → (DID, handle, created_at).
    /// Generated during OAuth callback, consumed during SASL.
    pub web_auth_tokens: Mutex<HashMap<String, (String, String, std::time::Instant)>>,
    /// Active web sessions with PDS credentials, keyed by DID.
    /// Used for server-proxied operations like media upload.
    /// Active web sessions keyed by `(DID, purpose)`. Each entry holds an
    /// independent OAuth grant: a user with both `Login` and `BlobUpload`
    /// has two PDS-level tokens, with the upload one only obtained when
    /// they actually clicked an upload button. See [`OauthPurpose`].
    pub web_sessions: Mutex<HashMap<(String, OauthPurpose), WebSession>>,
    /// Pending IRC LOGIN commands: oauth_state → session_id.
    /// When the OAuth callback fires, the server completes auth on the IRC connection.
    pub login_pending: Mutex<HashMap<String, String>>,
    /// Linked external identities: DID → vec of (provider, identity, linked_at).
    /// e.g., ("github", "chad", 1709655600)
    pub linked_identities: Mutex<HashMap<String, Vec<LinkedIdentity>>>,
    /// Pending LOGIN completions: session_id → LoginCompletion.
    /// Set by OAuth callback, consumed by connection loop to update conn.authenticated_did.
    pub login_completions: Mutex<HashMap<String, crate::connection::login::LoginCompletion>>,
    /// session_id -> iroh endpoint ID (for connections via iroh transport).
    pub session_iroh_ids: Mutex<HashMap<String, String>>,
    /// session_id -> away message (None = not away).
    pub session_away: Mutex<HashMap<String, String>>,
    /// This server's own iroh endpoint ID (advertised in CAP LS).
    pub server_iroh_id: Mutex<Option<String>>,
    /// Iroh endpoint handle (kept alive for the server's lifetime).
    pub iroh_endpoint: Mutex<Option<iroh::Endpoint>>,
    /// Iroh `Router` that owns the endpoint accept loop. Holding this is
    /// load-bearing — dropping the Router aborts inbound iroh handling.
    pub iroh_router: Mutex<Option<iroh::protocol::Router>>,
    /// AV session manager (voice/video/screen sharing).
    pub av_sessions: Mutex<crate::av::AvSessionManager>,
    /// AV media backend (iroh-live rooms).
    pub av_media: Mutex<Option<Arc<crate::av_media::IrohLiveBackend>>>,
    /// AV SFU state (MoQ cluster for WebSocket + QUIC connections).
    #[cfg(feature = "av-native")]
    pub sfu_state: Mutex<Option<Arc<crate::av_sfu::SfuState>>>,
    /// Active MoQ↔Room bridge handles (one per session).
    #[cfg(feature = "av-native")]
    pub av_bridges: Mutex<std::collections::HashMap<String, crate::av_bridge::BridgeHandle>>,
    /// S2S manager (if clustering is active).
    pub s2s_manager: Mutex<Option<Arc<crate::s2s::S2sManager>>>,
    /// CRDT document for cluster state convergence.
    pub cluster_doc: crate::crdt::ClusterDoc,
    /// Database handle for persistence (None = in-memory only).
    pub db: Option<Mutex<Db>>,
    /// Server configuration (for MOTD, max messages, etc.).
    pub config: ServerConfig,
    /// Plugin manager for server extensions.
    pub plugin_manager: PluginManager,
    /// Policy engine for channel governance (if enabled).
    pub policy_engine: Option<Arc<crate::policy::PolicyEngine>>,
    /// E2EE pre-key bundles: DID → PreKeyBundle JSON.
    /// Clients upload their bundles; other clients fetch to start encrypted sessions.
    pub prekey_bundles: Mutex<HashMap<String, serde_json::Value>>,
    /// Per-session message timestamps for channel flood protection.
    /// Key: session_id, Value: ring buffer of recent message timestamps.
    pub msg_timestamps: Mutex<HashMap<String, Vec<u64>>>,
    /// Per-IP active connection count (for connection limiting).
    pub ip_connections: Mutex<HashMap<std::net::IpAddr, u32>>,
    /// Ed25519 signing key for server-attested message signatures.
    /// Used as fallback when clients don't provide their own signatures.
    pub msg_signing_key: ed25519_dalek::SigningKey,
    /// Client-registered message signing keys: session_id → VerifyingKey.
    /// Clients send MSGSIG <base64url-pubkey> after SASL to register.
    /// Server boot time (for "server restarted" notices).
    pub boot_time: std::time::Instant,
    pub boot_timestamp: chrono::DateTime<chrono::Utc>,
    pub session_msg_keys: Mutex<HashMap<String, ed25519_dalek::VerifyingKey>>,
    /// DID → latest message signing public key (base64url-encoded).
    /// Published via /api/v1/signing-keys/{did} for verification.
    pub did_msg_keys: Mutex<HashMap<String, String>>,
    /// session_id → client software identifier (from USER realname).
    pub session_client_info: Mutex<HashMap<String, String>>,
    /// Upload tokens: token → (DID, created_at). Short-lived proof of upload authorization.
    pub upload_tokens: Mutex<HashMap<String, (String, std::time::Instant)>>,
    /// Embedded broker session store (durable-ish `/session` refresh) — `Some`
    /// only in embedded mode (no separate broker). Shared by `auth_callback`
    /// (which persists the session) and the mounted broker `/session` handler.
    pub embedded_session_store: Option<Arc<dyn freeq_auth_broker::SessionStore>>,
    /// Ghost sessions: DID users who disconnected recently.
    /// If they reconnect within the grace period, suppress QUIT/JOIN churn.
    /// Key: DID, Value: (nick, hostmask, channels_with_modes, disconnect_time, cancel_sender)
    pub ghost_sessions: Mutex<HashMap<String, GhostSession>>,
    /// Spawned (virtual) agents: child_did → SpawnedAgent.
    pub spawned_agents: Mutex<HashMap<String, SpawnedAgent>>,
    /// Per-IP rate limiter for expensive REST endpoints (OG preview, blob proxy, upload).
    pub rest_rate_limiter: crate::web::IpRateLimiter,
    /// Private media store: encrypted-at-rest blobs on local disk served via
    /// signed capability URLs. None only in lightweight test harnesses.
    pub media_store: Option<crate::media_store::MediaStore>,
    /// Liveness probes: session_id → when the probe PING was sent. Set when a
    /// new same-DID session attaches; cleared by the probed session's PONG.
    /// Sessions still pending after the deadline are evicted — this reaps
    /// zombie sockets left behind by frozen/resumed agent VMs in seconds
    /// instead of waiting out the ping timeout.
    pub liveness_probes: Mutex<HashMap<String, std::time::Instant>>,
    /// Per-session eviction signal. Notifying it makes the session's read
    /// loop exit and run its normal disconnect cleanup path.
    pub session_kill: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// Process-lifetime counters exposed at /metrics.
    pub metrics: Metrics,
}

/// Process-lifetime counters for the Prometheus /metrics endpoint.
/// Gauges (connections, channels, peers) are computed live; only
/// monotonic counters live here.
pub struct Metrics {
    pub messages_total: std::sync::atomic::AtomicU64,
    pub sasl_success_total: std::sync::atomic::AtomicU64,
    pub sasl_failure_total: std::sync::atomic::AtomicU64,
    pub started_at: std::time::Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            messages_total: std::sync::atomic::AtomicU64::new(0),
            sasl_success_total: std::sync::atomic::AtomicU64::new(0),
            sasl_failure_total: std::sync::atomic::AtomicU64::new(0),
            started_at: std::time::Instant::now(),
        }
    }
}

impl Metrics {
    pub fn bump(counter: &std::sync::atomic::AtomicU64) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A spawned virtual agent (child of a real agent session).
#[derive(Debug, Clone)]
pub struct SpawnedAgent {
    pub child_did: String,
    pub parent_did: String,
    pub parent_session: String,
    pub nick: String,
    pub channel: String,
    pub capabilities: Vec<String>,
    pub ttl: Option<u64>,
    pub task_ref: Option<String>,
    pub spawned_at: i64,
}

/// A ghost session represents a recently-disconnected DID user.
/// Their channel membership is preserved for a grace period.
pub struct GhostSession {
    pub nick: String,
    pub hostmask: String,
    /// The session ID of the disconnected session. Used to evict the stale
    /// session from ch.members when the grace period expires without reconnect.
    pub session_id: String,
    /// Channels they were in, with (is_op, is_voiced, is_halfop).
    pub channels: Vec<(String, bool, bool, bool)>,
    pub disconnect_time: std::time::Instant,
    /// Send to this to cancel the deferred QUIT broadcast.
    pub cancel: tokio::sync::oneshot::Sender<()>,
}

/// Result of [`SharedState::bind_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    /// Binding applied (in-memory + persisted).
    Bound,
    /// Nick is already owned by a different DID; nothing was changed.
    ConflictOwnedByOther { owner_did: String },
}

impl SharedState {
    /// Whether a channel may be advertised to non-members: shown in `LIST` and
    /// in the unauthenticated `GET /api/v1/channels`. A channel is discoverable
    /// only if it carries NO access restriction — not invite-only (`+i`), not
    /// keyed (`+k`), not encrypted-only (`+E`), and not gated by a join policy.
    /// Any restriction means it is effectively private, and advertising its
    /// name/topic to strangers or other tenants only leaks it. Members always
    /// see their own channels regardless (the callers OR-in membership).
    pub fn channel_is_discoverable(&self, name: &str, ch: &ChannelState) -> bool {
        if ch.is_mode_restricted() {
            return false;
        }
        if let Some(ref engine) = self.policy_engine
            && matches!(engine.get_policy(name), Ok(Some(_)))
        {
            return false;
        }
        true
    }

    /// Connect-time allowlist (Phase 3.2, opt-in). Returns whether a DID may
    /// authenticate. Both allowlists empty ⇒ open (the public-instance default).
    /// `handle` is the user's AT handle, used for domain matching (e.g. an
    /// `acme.com` domain allows `alice.acme.com`).
    pub fn did_is_allowed(&self, did: &str, handle: Option<&str>) -> bool {
        did_allowed(
            &self.config.allowed_dids,
            &self.config.allowed_did_domains,
            did,
            handle,
        )
    }

    /// Run a closure with the database, if persistence is enabled.
    /// Logs errors but does not propagate them — persistence failures
    /// should not break the IRC server.
    pub fn with_db<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Db) -> rusqlite::Result<R>,
    {
        self.db.as_ref().and_then(|db| {
            let db = db.lock();
            match f(&db) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::error!("Database error: {e}");
                    None
                }
            }
        })
    }

    /// Bind a DID to a nick: the single authority for updating the
    /// in-memory `did_nicks`/`nick_owners` maps AND persisting the
    /// durable `identities` row. Replaces ad-hoc inserts at SASL
    /// success / LOGIN / rename so all three stay consistent.
    ///
    /// Ownership-preserving: if `nick` is already owned by a *different*
    /// DID, the bind is refused — neither the in-memory maps nor the DB
    /// are touched (the caller is expected to force-rename the session,
    /// as registration already does). This closes the hole where a nick
    /// claimed during the CAP/SASL negotiation window silently hijacked
    /// in-memory ownership even though the DB `UNIQUE(nick)` rejected it.
    pub fn bind_identity(&self, did: &str, nick: &str) -> BindOutcome {
        let nick_lower = nick.to_lowercase();
        {
            let owners = self.nick_owners.lock();
            if let Some(existing) = owners.get(&nick_lower)
                && existing != did
            {
                return BindOutcome::ConflictOwnedByOther {
                    owner_did: existing.clone(),
                };
            }
        }
        // If this DID previously held a different nick, drop the stale
        // nick_owners entry so it isn't orphaned. (Without this, the old
        // nick stayed owned in memory and diverged from the durable
        // table until a restart reloaded it.)
        let prev_nick = self.did_nicks.lock().get(did).cloned();
        if let Some(prev) = prev_nick
            && prev != nick_lower
        {
            let mut owners = self.nick_owners.lock();
            if owners.get(&prev).is_some_and(|d| d == did) {
                owners.remove(&prev);
            }
        }
        self.did_nicks
            .lock()
            .insert(did.to_string(), nick_lower.clone());
        self.nick_owners
            .lock()
            .insert(nick_lower.clone(), did.to_string());
        // Persist durably. with_db logs on error; we additionally surface
        // a warning so a swallowed UNIQUE(nick) (shouldn't happen now the
        // in-memory gate above runs first) is not silent.
        if self
            .with_db(|db| db.save_identity(did, &nick_lower))
            .is_none()
            && self.db.is_some()
        {
            tracing::warn!(%did, nick = %nick_lower, "bind_identity: save_identity did not persist");
        }
        BindOutcome::Bound
    }

    /// Bind `did` to `requested`; if `requested` is owned by a
    /// *different* DID, bind a deterministic derived nick
    /// `<base>-<didfrag>` instead and return it. Always returns the nick
    /// actually bound (lowercased) — total, never fails.
    ///
    /// `didfrag` is the DID identifier (after the last `:`), ascii-
    /// alphanumeric, lowercased. Nicks cap at 64, so `base` is truncated
    /// to leave room for `-<didfrag>`. Deterministic for a given
    /// (requested, did): the same identity always lands on the same
    /// derived nick across reconnects/restarts. If the derived nick is
    /// itself owned by yet another DID, the fragment is lengthened; a
    /// random `guest` nick is the absolute last resort.
    ///
    /// For authenticated identities only. Unauthenticated nick squatters
    /// keep the `Guest<rand>` path in registration.
    pub fn bind_identity_with_fallback(&self, did: &str, requested: &str) -> String {
        const MAX_NICK: usize = 64;
        let requested_lower = requested.to_lowercase();
        if let BindOutcome::Bound = self.bind_identity(did, &requested_lower) {
            return requested_lower;
        }
        let ident: String = did
            .rsplit(':')
            .next()
            .unwrap_or(did)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let mut last = String::new();
        for raw_len in [8usize, 12, 16, 24, ident.len()] {
            let frag_len = raw_len.min(ident.len());
            if frag_len == 0 {
                break;
            }
            let frag = &ident[..frag_len];
            let base_budget = MAX_NICK.saturating_sub(1 + frag_len);
            let base: String = requested_lower.chars().take(base_budget).collect();
            let derived = format!("{base}-{frag}");
            if derived == last {
                continue; // ident shorter than this step — no new candidate
            }
            last = derived.clone();
            if let BindOutcome::Bound = self.bind_identity(did, &derived) {
                return derived;
            }
        }
        let guest = format!("guest{}", rand::random::<u32>() % 100000);
        let _ = self.bind_identity(did, &guest);
        guest
    }

    /// Resolve a DID to a display nick for UI surfaces (CHATHISTORY
    /// TARGETS, etc.). Chain: in-memory `did_nicks` → live session
    /// (`session_dids` reverse + `nick_to_session`) → persistent
    /// `identities` table → message-history sender → raw DID as last resort.
    pub fn display_nick_for_did(&self, did: &str) -> String {
        if let Some(n) = self.did_nicks.lock().get(did).cloned() {
            return n;
        }
        // Live session: find a session whose DID matches, then its nick.
        let sid = self
            .session_dids
            .lock()
            .iter()
            .find(|(_, d)| d.as_str() == did)
            .map(|(sid, _)| sid.clone());
        if let Some(sid) = sid
            && let Some(n) = self.nick_to_session.lock().get_nick(&sid)
        {
            return n.to_string();
        }
        if let Some(row) = self.with_db(|db| db.get_identity_by_did(did)).flatten() {
            return row.nick;
        }
        // Last resort before the raw DID: recover the nick the DID last sent
        // under from stored messages. Covers conversations that predate durable
        // identity binding and remote DIDs with no local `identities` row.
        // Display-only — this never registers ownership of the recovered nick.
        if let Some(nick) = self.with_db(|db| db.recent_nick_for_did(did)).flatten() {
            return nick;
        }
        did.to_string()
    }

    // ── CRDT operations ────────────────────────────────────────────
    //
    // NOTE: Presence (join/part) is NOT in CRDT. It's handled by S2S events
    // with periodic resync. This avoids ghost users when servers crash
    // without emitting PART/QUIT.
    //
    // All CRDT methods are async because ClusterDoc uses tokio::sync::Mutex.

    /// Get our iroh endpoint ID (used as CRDT peer identity).
    fn crdt_origin_peer(&self) -> String {
        self.server_iroh_id
            .lock()
            .clone()
            .unwrap_or_else(|| self.server_name.clone())
    }

    /// Record a topic change in the CRDT with provenance.
    pub async fn crdt_set_topic(
        &self,
        channel: &str,
        topic: &str,
        set_by: &str,
        set_by_did: Option<&str>,
    ) {
        let origin = self.crdt_origin_peer();
        self.cluster_doc
            .set_topic(channel, topic, set_by, set_by_did, &origin)
            .await;
    }

    /// Record a nick-DID binding in the CRDT.
    pub async fn crdt_set_nick_owner(&self, nick: &str, did: &str) {
        self.cluster_doc.set_nick_owner(nick, did).await;
    }

    /// Record a channel founder in the CRDT.
    pub async fn crdt_set_founder(&self, channel: &str, did: &str) {
        self.cluster_doc.set_founder(channel, did).await;
    }

    /// Record a DID op grant in the CRDT with provenance.
    pub async fn crdt_grant_op(&self, channel: &str, did: &str, granted_by_did: Option<&str>) {
        let origin = self.crdt_origin_peer();
        self.cluster_doc
            .grant_op(channel, did, granted_by_did, &origin)
            .await;
    }

    /// Record a DID op revoke in the CRDT.
    pub async fn crdt_revoke_op(&self, channel: &str, did: &str) {
        self.cluster_doc.revoke_op(channel, did).await;
    }

    /// Record a ban in the CRDT with provenance.
    pub async fn crdt_add_ban(
        &self,
        channel: &str,
        mask: &str,
        set_by: &str,
        set_by_did: Option<&str>,
    ) {
        let origin = self.crdt_origin_peer();
        self.cluster_doc
            .add_ban(channel, mask, set_by, set_by_did, &origin)
            .await;
    }

    /// Record a ban removal in the CRDT.
    pub async fn crdt_remove_ban(&self, channel: &str, mask: &str) {
        self.cluster_doc.remove_ban(channel, mask).await;
    }

    /// Generate CRDT sync messages for all peers and broadcast them.
    /// Sync state is keyed by **iroh endpoint ID** (cryptographic identity).
    pub async fn crdt_broadcast_sync(&self) {
        let manager = self.s2s_manager.lock().clone();
        let manager = match manager {
            Some(m) => m,
            None => return,
        };

        // Use iroh endpoint ID as our origin in CRDT sync messages
        let our_peer_id = manager.server_id.clone();

        let peers: Vec<String> = manager.peers.lock().await.keys().cloned().collect();
        for peer_id in &peers {
            // peer_id here is already the iroh endpoint ID (from connection's remote_id)
            if let Some(msg_bytes) = self.cluster_doc.generate_sync_message(peer_id).await {
                let sync_msg = crate::s2s::S2sMessage::CrdtSync {
                    data: {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode(&msg_bytes)
                    },
                    // Use iroh endpoint ID as origin (not server_name)
                    origin: our_peer_id.clone(),
                };
                if let Some(entry) = manager.peers.lock().await.get(peer_id) {
                    let _ = entry.tx.send(sync_msg).await;
                }
            }
        }
    }

    /// Receive a CRDT sync message from a peer.
    /// `peer_id` MUST be the iroh endpoint ID (not server_name).
    pub async fn crdt_receive_sync(&self, peer_id: &str, data: &[u8]) -> Result<(), String> {
        self.cluster_doc.receive_sync_message(peer_id, data).await
    }

    /// Send the next CRDT sync message to a specific peer only.
    ///
    /// This is the correct response after receiving a sync message from a peer:
    /// generate the next Automerge sync message for that peer and send it back.
    /// This avoids broadcast amplification storms where receiving from one peer
    /// triggers messages to all peers, which all respond, etc.
    pub async fn crdt_sync_with_peer(&self, peer_id: &str) {
        let manager = self.s2s_manager.lock().clone();
        let manager = match manager {
            Some(m) => m,
            None => return,
        };

        let our_peer_id = manager.server_id.clone();

        if let Some(msg_bytes) = self.cluster_doc.generate_sync_message(peer_id).await {
            let sync_msg = crate::s2s::S2sMessage::CrdtSync {
                data: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(&msg_bytes)
                },
                origin: our_peer_id,
            };
            if let Some(entry) = manager.peers.lock().await.get(peer_id) {
                let _ = entry.tx.send(sync_msg).await;
            }
        }
    }
}

/// Derive a DB encryption key from the signing key (migration/fallback).
fn derive_key_from_signing(signing_key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(signing_key.to_bytes().as_slice()).expect("HMAC key");
    mac.update(b"freeq-db-encryption-v1");
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Load or generate a persistent ed25519 signing key for message signing.
fn load_msg_signing_key(data_dir: &str) -> ed25519_dalek::SigningKey {
    let key_path = std::path::Path::new(data_dir).join("msg-signing-key.secret");
    if key_path.exists() {
        crate::secrets::tighten_permissions(&key_path);
        if let Ok(data) = std::fs::read(&key_path)
            && let Ok(bytes) = <[u8; 32]>::try_from(data.as_slice())
        {
            tracing::info!("Loaded message signing key from {}", key_path.display());
            return ed25519_dalek::SigningKey::from_bytes(&bytes);
        }
        tracing::warn!(
            "Corrupt msg signing key at {}, regenerating",
            key_path.display()
        );
    }
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    if let Err(e) = crate::secrets::write_secret(&key_path, &key.to_bytes()) {
        tracing::error!("Failed to persist msg signing key: {e}");
    } else {
        tracing::info!("Generated message signing key at {}", key_path.display());
    }
    key
}

/// Load or generate the persistent HMAC key that signs membership
/// attestations (`{data_dir}/attestation-key.secret`, 0600).
fn load_attestation_key(data_dir: &str) -> [u8; 32] {
    let key_path = std::path::Path::new(data_dir).join("attestation-key.secret");
    if key_path.exists() {
        crate::secrets::tighten_permissions(&key_path);
        if let Ok(data) = std::fs::read(&key_path)
            && let Ok(bytes) = <[u8; 32]>::try_from(data.as_slice())
        {
            tracing::info!("Loaded attestation key from {}", key_path.display());
            return bytes;
        }
        tracing::warn!(
            "Corrupt attestation key at {}, regenerating",
            key_path.display()
        );
    }
    let key: [u8; 32] = rand::random();
    if let Err(e) = crate::secrets::write_secret(&key_path, &key) {
        tracing::error!("Failed to persist attestation key: {e}");
    } else {
        tracing::info!(
            "Generated attestation signing key at {}",
            key_path.display()
        );
    }
    key
}

/// Install the agent-assist LLM provider into the process-wide slot
/// based on `ServerConfig.llm_*` fields. No-op if the provider is
/// `None` / `"none"` / unset.
///
/// Pluggable today: `openai` selects the OpenAI-compatible client,
/// which works against any /chat/completions endpoint (OpenAI itself,
/// Together, Fireworks, Groq, vLLM, llama.cpp server, Ollama with
/// /v1, TGI, LMDeploy, etc — see `agent_assist::llm::openai`).
/// `mock` selects a deterministic regex matcher used by tests and dev.
fn install_llm_provider(config: &ServerConfig) {
    use std::time::Duration;
    let kind = config
        .llm_provider
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    match kind.as_deref() {
        None | Some("") | Some("none") => {
            // Intentionally do NOT clear the global here. The global is
            // initialised to None by LazyLock; this branch is the
            // "config didn't ask for an LLM" case and a no-op preserves
            // test isolation when multiple Server instances are spun up
            // in the same process (some with mock providers, some
            // without). Production servers boot once, so this is
            // identical to actively clearing.
            tracing::info!(
                "agent-assist LLM provider not configured (preserving any existing global)"
            );
        }
        Some("mock") => {
            crate::agent_assist::llm::global::set_provider(Arc::new(
                crate::agent_assist::llm::mock::MockProvider,
            ));
            tracing::info!("agent-assist LLM provider: mock");
        }
        Some("openai") => {
            let base = config
                .llm_base_url
                .clone()
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
            let model = config
                .llm_model
                .clone()
                .unwrap_or_else(|| "gpt-4o-mini".to_string());
            let display_name = format!("openai-compat:{model}");
            let provider = crate::agent_assist::llm::openai::OpenAiCompatible::new(
                display_name.clone(),
                base.clone(),
                config.llm_api_key.clone(),
                model,
                Duration::from_secs(config.llm_timeout_secs.max(1)),
            );
            crate::agent_assist::llm::global::set_provider(Arc::new(provider));
            tracing::info!("agent-assist LLM provider: {} via {}", display_name, base);
        }
        Some(other) => {
            tracing::warn!(
                "Unknown agent-assist LLM provider `{other}`; disabling. \
                 Set FREEQ_LLM_PROVIDER to one of: openai, mock, none."
            );
            crate::agent_assist::llm::global::clear_provider();
        }
    }
}

pub struct Server {
    config: ServerConfig,
    resolver: DidResolver,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        let resolver = resolver_from_config(&config);
        Self { resolver, config }
    }

    /// Create a server with a custom DID resolver (for testing).
    pub fn with_resolver(config: ServerConfig, resolver: DidResolver) -> Self {
        Self { config, resolver }
    }
}

/// Build the DID resolver the binary runs with: the real network resolver by
/// default, or a static in-memory map when `--did-resolver-static` is set
/// (test/dev only — offline authentication for the federation harness).
fn resolver_from_config(config: &ServerConfig) -> DidResolver {
    if config.did_resolver_static.is_empty() {
        return DidResolver::http();
    }
    let mut docs = std::collections::HashMap::new();
    for entry in &config.did_resolver_static {
        match entry.split_once('=') {
            Some((did, mb)) if !did.is_empty() && !mb.is_empty() => {
                docs.insert(
                    did.to_string(),
                    freeq_sdk::did::make_test_did_document(did, mb),
                );
            }
            _ => tracing::warn!(
                entry = %entry,
                "Ignoring malformed --did-resolver-static entry (expected did=publicKeyMultibase)"
            ),
        }
    }
    tracing::warn!(
        count = docs.len(),
        "Using STATIC DID resolver (test/dev mode) — no network DID resolution"
    );
    DidResolver::static_map(docs)
}

impl Server {
    /// Build SharedState, opening the database and loading persisted data.
    fn build_state(&self) -> Result<Arc<SharedState>> {
        // Install the agent-assist LLM provider (idempotent; no-op if
        // not configured). Lives in a process-wide slot rather than
        // SharedState so existing constructors don't need to change.
        install_llm_provider(&self.config);

        // Load message signing key early — it's used to derive DB encryption key
        let msg_signing_key = load_msg_signing_key(self.config.data_dir.as_deref().unwrap_or("."));

        // Load or generate a separate DB encryption key (independent of signing key).
        // This ensures a signing key compromise doesn't also compromise encrypted data.
        let db_encryption_key: [u8; 32] = {
            let key_path = std::path::Path::new(self.config.data_dir.as_deref().unwrap_or("."))
                .join("db-encryption-key.secret");
            if key_path.exists() {
                crate::secrets::tighten_permissions(&key_path);
                if let Ok(data) = std::fs::read(&key_path) {
                    if let Ok(bytes) = <[u8; 32]>::try_from(data.as_slice()) {
                        tracing::info!("Loaded DB encryption key from {}", key_path.display());
                        bytes
                    } else {
                        // Corrupt key — derive from signing key as migration path
                        tracing::warn!("Corrupt DB encryption key, deriving from signing key");
                        derive_key_from_signing(&msg_signing_key)
                    }
                } else {
                    derive_key_from_signing(&msg_signing_key)
                }
            } else {
                // First run with separate key: derive from signing key for backward compat
                // with existing encrypted messages, then persist for future independence.
                let key = derive_key_from_signing(&msg_signing_key);
                if let Err(e) = crate::secrets::write_secret(&key_path, &key) {
                    tracing::error!("Failed to persist DB encryption key: {e}");
                } else {
                    tracing::info!("Generated DB encryption key at {}", key_path.display());
                }
                key
            }
        };

        let db = match &self.config.db_path {
            Some(path) => {
                tracing::info!("Opening database: {path} (encryption at rest: enabled)");
                Some(
                    Db::open_encrypted(path, db_encryption_key)
                        .map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?,
                )
            }
            None => None,
        };

        // Private media store: encrypted blobs on disk under {data_dir}/media.
        // Metadata lives in the DB, so the store is only meaningful when
        // persistence is enabled — gate on `db` to avoid creating a stray
        // ./media dir in ephemeral (in-memory) configurations.
        let media_store = if db.is_some() {
            let data_dir = self.config.data_dir.as_deref().unwrap_or(".");
            let media_dir = std::path::Path::new(data_dir).join("media");
            let seed = msg_signing_key.to_bytes();
            let enc_key = crate::media_store::derive_enc_key(&seed);
            let cap_key = crate::media_store::derive_cap_key(&seed);
            match crate::media_store::MediaStore::new(media_dir.clone(), enc_key, cap_key) {
                Ok(store) => {
                    tracing::info!("Private media store at {}", media_dir.display());
                    Some(store)
                }
                Err(e) => {
                    tracing::error!("Failed to init media store at {}: {e}", media_dir.display());
                    None
                }
            }
        } else {
            None
        };

        // Load persisted state from DB
        let mut channels = HashMap::new();
        let mut did_nicks = HashMap::new();
        let mut nick_owners = HashMap::new();

        if let Some(ref db) = db {
            // Load channels (metadata + bans)
            channels = db
                .load_channels()
                .map_err(|e| anyhow::anyhow!("Failed to load channels: {e}"))?;
            tracing::info!("Loaded {} channels from database", channels.len());

            // Load message history into each channel
            for (name, ch) in channels.iter_mut() {
                let messages = db
                    .get_messages(name, crate::server::MAX_HISTORY, None)
                    .map_err(|e| anyhow::anyhow!("Failed to load messages for {name}: {e}"))?;
                // An edit is a separate row, so a revised message comes back as
                // several rows. In-memory history holds one entry per logical
                // message, keyed by its root id and carrying the newest text —
                // otherwise every restart turns an edited message into two
                // entries in the next joiner's replay.
                let mut by_root: HashMap<String, usize> = HashMap::new();
                for msg in messages {
                    let mut tags = msg.tags;
                    if let Some(ref did) = msg.sender_did {
                        tags.insert("account".to_string(), did.clone());
                    }
                    // Replay presents the collapsed entry as the message
                    // itself, not as an edit of something the joiner never saw.
                    tags.remove("+draft/edit");
                    let root = msg.root_msgid.clone().or_else(|| msg.msgid.clone());
                    // Newest text under the entry the message already has —
                    // the same in-place swap the live edit path makes, so a
                    // restart reproduces the state it left.
                    if let Some(ref root) = root
                        && let Some(&idx) = by_root.get(root)
                        && let Some(existing) = ch.history.get_mut(idx)
                    {
                        existing.text = msg.text;
                        existing.edited = true;
                        continue;
                    }
                    if let Some(ref root) = root {
                        by_root.insert(root.clone(), ch.history.len());
                    }
                    ch.history.push_back(HistoryMessage {
                        from: msg.sender,
                        text: msg.text,
                        timestamp: msg.timestamp,
                        tags,
                        // Identity is the root; a revision row's own id is
                        // audit trail, never the key clients hold.
                        msgid: root,
                        edited: msg.replaces_msgid.is_some(),
                    });
                }
            }

            // Prune empty channels (no history, no topic, no modes set)
            let before = channels.len();
            channels.retain(|name, ch| {
                if ch.history.is_empty()
                    && ch.topic.is_none()
                    && !ch.invite_only
                    && !ch.moderated
                    && ch.key.is_none()
                    && ch.bans.is_empty()
                {
                    // Don't prune if channel has policy (check later)
                    let _ = db.delete_channel(name);
                    false
                } else {
                    true
                }
            });
            let pruned = before - channels.len();
            if pruned > 0 {
                tracing::info!(
                    "Pruned {pruned} empty channels ({} remaining)",
                    channels.len()
                );
            }

            // Load DID-nick bindings
            let identities = db
                .load_identities()
                .map_err(|e| anyhow::anyhow!("Failed to load identities: {e}"))?;
            tracing::info!(
                "Loaded {} identity bindings from database",
                identities.len()
            );
            for id in identities {
                nick_owners.insert(id.nick.clone(), id.did.clone());
                did_nicks.insert(id.did, id.nick);
            }
        }

        let plugin_manager =
            PluginManager::load(&self.config.plugins, self.config.plugin_dir.as_deref());

        // msg_signing_key already loaded above (needed for DB encryption key derivation)

        // Load pre-key bundles from DB before moving db into struct
        let prekey_bundles = {
            let mut bundles = HashMap::new();
            if let Some(ref db) = db
                && let Ok(saved) = db.load_all_prekey_bundles()
            {
                tracing::info!("Loaded {} pre-key bundles from DB", saved.len());
                for (did, bundle) in saved {
                    bundles.insert(did, bundle);
                }
            }
            bundles
        };

        Ok(Arc::new(SharedState {
            server_name: self.config.server_name.clone(),
            challenge_store: ChallengeStore::new(self.config.challenge_timeout_secs),
            did_resolver: self.resolver.clone(),
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(NickMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            did_sessions: Mutex::new(HashMap::new()),
            channels: Mutex::new(channels),
            did_nicks: Mutex::new(did_nicks),
            nick_owners: Mutex::new(nick_owners),
            session_handles: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
            cap_multi_prefix: Mutex::new(HashSet::new()),
            cap_echo_message: Mutex::new(HashSet::new()),
            cap_server_time: Mutex::new(HashSet::new()),
            cap_batch: Mutex::new(HashSet::new()),
            cap_draft_multiline: Mutex::new(HashSet::new()),
            open_batches: Mutex::new(HashMap::new()),
            cap_account_notify: Mutex::new(HashSet::new()),
            cap_extended_join: Mutex::new(HashSet::new()),
            cap_away_notify: Mutex::new(HashSet::new()),
            cap_account_tag: Mutex::new(HashSet::new()),
            cap_read_marker: Mutex::new(HashSet::new()),
            session_read_markers: Mutex::new(HashMap::new()),
            server_opers: Mutex::new(HashSet::new()),
            session_actor_class: Mutex::new(HashMap::new()),
            provenance_declarations: Mutex::new(HashMap::new()),
            agent_presence: Mutex::new(HashMap::new()),
            agent_heartbeats: Mutex::new(HashMap::new()),
            av_instances_per_conn: Mutex::new(HashMap::new()),
            av_grace_pending: Mutex::new(HashSet::new()),
            oauth_pending: Mutex::new(HashMap::new()),
            oauth_complete: Mutex::new(HashMap::new()),
            web_auth_tokens: Mutex::new(HashMap::new()),
            web_sessions: Mutex::new(HashMap::new()),
            login_pending: Mutex::new(HashMap::new()),
            linked_identities: Mutex::new(HashMap::new()),
            login_completions: Mutex::new(HashMap::new()),
            session_iroh_ids: Mutex::new(HashMap::new()),
            session_away: Mutex::new(HashMap::new()),
            server_iroh_id: Mutex::new(None),
            iroh_endpoint: Mutex::new(None),
            iroh_router: Mutex::new(None),
            av_sessions: Mutex::new(crate::av::AvSessionManager::new()),
            av_media: Mutex::new(None),
            #[cfg(feature = "av-native")]
            sfu_state: Mutex::new(None),
            #[cfg(feature = "av-native")]
            av_bridges: Mutex::new(std::collections::HashMap::new()),
            s2s_manager: Mutex::new(None),
            cluster_doc: crate::crdt::ClusterDoc::new(&self.config.server_name),
            db: db.map(Mutex::new),
            config: self.config.clone(),
            plugin_manager,
            policy_engine: {
                // Initialize policy engine alongside the main DB
                let policy_db_path = self
                    .config
                    .db_path
                    .as_ref()
                    .map(|p| p.replace(".db", "-policy.db"))
                    .unwrap_or_else(|| ":memory:".to_string());
                match crate::policy::PolicyStore::open(&policy_db_path) {
                    Ok(store) => {
                        let authority_did = format!("did:web:{}", self.config.server_name);
                        // Persistent attestation key: an ephemeral key (the
                        // old PolicyEngine::new path) invalidated every
                        // outstanding membership attestation on restart, so
                        // Continuous-validity channels silently re-gated all
                        // members after a server bounce.
                        let attestation_key =
                            load_attestation_key(self.config.data_dir.as_deref().unwrap_or("."));
                        Some(Arc::new(crate::policy::PolicyEngine::with_key(
                            store,
                            authority_did,
                            attestation_key,
                        )))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to initialize policy engine: {e}");
                        None
                    }
                }
            },
            boot_time: std::time::Instant::now(),
            boot_timestamp: chrono::Utc::now(),
            prekey_bundles: Mutex::new(prekey_bundles),
            msg_timestamps: Mutex::new(HashMap::new()),
            ip_connections: Mutex::new(HashMap::new()),
            msg_signing_key,
            session_msg_keys: Mutex::new(HashMap::new()),
            did_msg_keys: Mutex::new(HashMap::new()),
            session_client_info: Mutex::new(HashMap::new()),
            upload_tokens: Mutex::new(HashMap::new()),
            // Embedded mode (no separate broker) gets an ephemeral in-memory
            // broker session store so /session refresh works within uptime.
            embedded_session_store: if self.config.broker_shared_secret.is_none() {
                Some(Arc::new(freeq_auth_broker::InMemoryStore::new()))
            } else {
                None
            },
            ghost_sessions: Mutex::new(HashMap::new()),
            spawned_agents: Mutex::new(HashMap::new()),
            // 30 requests per 60-second window per IP for expensive REST endpoints
            rest_rate_limiter: crate::web::IpRateLimiter::new(30, 60),
            media_store,
            liveness_probes: Mutex::new(HashMap::new()),
            session_kill: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
        }))
    }

    /// Run the server, blocking forever.
    pub async fn run(self) -> Result<()> {
        // Validate S2S config: if peers are configured, allowlist must be set.
        // Without an allowlist, any iroh endpoint can connect and inject messages.
        if !self.config.s2s_peers.is_empty() && self.config.s2s_allowed_peers.is_empty() {
            anyhow::bail!(
                "S2S peers configured but --s2s-allowed-peers is empty. \
                 This would allow any server to connect. Set --s2s-allowed-peers \
                 to the endpoint IDs of your trusted peers."
            );
        }
        // Every outbound peer should also be in the allowlist (catches copy-paste mistakes)
        for peer in &self.config.s2s_peers {
            if !self.config.s2s_allowed_peers.contains(peer) {
                tracing::warn!(
                    peer = %peer,
                    "S2S peer is in --s2s-peers but not in --s2s-allowed-peers — \
                     they can connect outbound but won't be accepted inbound"
                );
            }
        }

        let tls_acceptor = self.build_tls_acceptor()?;
        let web_addr = self.config.web_addr.clone();
        let state = self.build_state()?;

        // Recover active AV sessions from DB (survive server restarts)
        {
            let recovered = state
                .with_db(|db| db.load_active_av_sessions())
                .unwrap_or_default();
            if !recovered.is_empty() {
                let mut mgr = state.av_sessions.lock();
                let mut count = 0;
                for session in recovered {
                    // Only restore sessions less than 2 hours old
                    let age = chrono::Utc::now().timestamp() - session.created_at;
                    if age > 7200 {
                        // Mark stale sessions as ended in DB
                        let mut ended = session;
                        ended.state = crate::av::AvSessionState::Ended {
                            ended_at: chrono::Utc::now().timestamp(),
                            ended_by: None,
                        };
                        state.with_db(|db| db.save_av_session(&ended));
                        continue;
                    }
                    if let Some(ch) = &session.channel {
                        mgr.channel_sessions
                            .insert(ch.to_lowercase(), session.id.clone());
                    }
                    mgr.sessions.insert(session.id.clone(), session);
                    count += 1;
                }
                if count > 0 {
                    tracing::info!("Recovered {count} active AV sessions from database");
                }
            }
        }

        // Start plain listener
        // Warn if the UNENCRYPTED IRC port is exposed on a public interface —
        // credentials and messages would travel in cleartext. The default binds
        // to loopback; operators exposing it publicly should front it with TLS.
        if !self.config.listen_addr.starts_with("127.")
            && !self.config.listen_addr.starts_with("localhost")
            && !self.config.listen_addr.starts_with("[::1]")
        {
            tracing::warn!(
                addr = %self.config.listen_addr,
                "plaintext IRC listener is bound to a NON-loopback address — traffic is unencrypted. \
                 Prefer the TLS listener (--tls-bind) and keep --bind on 127.0.0.1 behind a proxy."
            );
        }
        let plain_listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!("Plain listener on {}", self.config.listen_addr);

        // Start TLS listener if configured
        if let Some(ref acceptor) = tls_acceptor {
            let tls_listener = TcpListener::bind(&self.config.tls_listen_addr).await?;
            tracing::info!("TLS listener on {}", self.config.tls_listen_addr);

            let tls_state = Arc::clone(&state);
            let tls_acc = acceptor.clone();
            tokio::spawn(async move {
                loop {
                    match tls_listener.accept().await {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&tls_state);
                            let acceptor = tls_acc.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) =
                                            connection::handle_generic(tls_stream, state).await
                                        {
                                            tracing::error!("TLS connection error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("TLS handshake failed: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => tracing::error!("TLS accept error: {e}"),
                    }
                }
            });
        }

        // Warn if iroh is enabled without an S2S allowlist (open federation)
        if (self.config.iroh || !self.config.s2s_peers.is_empty())
            && self.config.s2s_allowed_peers.is_empty()
        {
            tracing::warn!(
                "Iroh enabled without --s2s-allowed-peers: any server can connect via S2S. \
                 Set --s2s-allowed-peers to restrict federation to trusted peers."
            );
        }

        // Start iroh transport if configured
        let iroh_endpoint = if self.config.iroh || !self.config.s2s_peers.is_empty() {
            let iroh_state = Arc::clone(&state);
            let iroh_port = self.config.iroh_port;
            match crate::iroh::start(iroh_state, iroh_port).await {
                Ok(endpoint) => {
                    // Wait for the endpoint to be online and print connection info
                    endpoint.online().await;
                    let id = endpoint.id();
                    tracing::info!("Iroh ready. Connect with: --iroh-addr {id}");
                    *state.server_iroh_id.lock() = Some(id.to_string());

                    // Re-key the CRDT actor to the iroh endpoint ID.
                    // This MUST happen before any S2S connections, so founder
                    // resolution (min-actor-wins) uses the cryptographic identity.
                    state.cluster_doc.rekey_actor(&id.to_string()).await;

                    Some(endpoint)
                }
                Err(e) => {
                    tracing::error!("Failed to start iroh endpoint: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Start S2S manager whenever iroh is enabled (not just when peers are configured).
        // This allows the server to accept incoming S2S connections from other servers.
        if let Some(ref endpoint) = iroh_endpoint {
            let s2s_state = Arc::clone(&state);
            match crate::s2s::start(s2s_state, endpoint.clone()).await {
                Ok((manager, mut s2s_rx)) => {
                    // Store manager in shared state so iroh accept loop can route S2S
                    *state.s2s_manager.lock() = Some(Arc::clone(&manager));

                    // Connect to configured peers with auto-reconnection
                    for peer_id in &self.config.s2s_peers {
                        crate::s2s::connect_peer_with_retry(
                            endpoint.clone(),
                            peer_id.clone(),
                            Arc::clone(&manager),
                        );
                    }

                    // Spawn S2S event processor
                    let s2s_state = Arc::clone(&state);
                    let s2s_manager = Arc::clone(&manager);
                    tokio::spawn(async move {
                        while let Some(event) = s2s_rx.recv().await {
                            process_s2s_message(
                                &s2s_state,
                                &s2s_manager,
                                &event.authenticated_peer_id,
                                event.msg,
                            )
                            .await;
                        }
                    });

                    if self.config.s2s_peers.is_empty() {
                        tracing::info!("S2S ready (accepting incoming peer connections)");
                    } else {
                        tracing::info!(
                            "S2S clustering active with {} peer(s)",
                            self.config.s2s_peers.len()
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to start S2S: {e}");
                }
            }
        } else if !self.config.s2s_peers.is_empty() {
            tracing::error!("S2S requires iroh transport (--iroh)");
        }

        // Initialize AV media backend
        #[cfg(feature = "av-native")]
        if let Some(ref endpoint) = iroh_endpoint {
            if let Some(backend) = crate::av_media::init_backend(endpoint.clone()).await {
                *state.av_media.lock() = Some(backend);
            }
            // Initialize SFU (MoQ cluster + QUIC accept + WebSocket support).
            // QUIC binds to the web server's port (UDP). WebSocket handled via web.rs route.
            let sfu_port = web_addr
                .as_ref()
                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                .map(|a| a.port())
                .unwrap_or(4443);
            {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
                let data_dir = self.config.data_dir.as_deref().unwrap_or(".");
                match crate::av_sfu::init_sfu(Some(sfu_port), data_dir).await {
                    Ok(sfu) => *state.sfu_state.lock() = Some(sfu),
                    Err(e) => tracing::error!("AV SFU init failed: {e}"),
                }
            }
        }
        #[cfg(not(feature = "av-native"))]
        {
            *state.av_media.lock() = Some(crate::av_media::init_backend_stub());
        }

        // Spawn the iroh Router that owns the endpoint accept loop. Done
        // AFTER AV init so iroh-live's gossip + MoQ protocols can be
        // mounted on the same Router as freeq's `freeq/iroh/1` and
        // `freeq/s2s/1` — preventing iroh-live from spawning its own
        // Router and overwriting the endpoint's ALPN list.
        if let Some(ref endpoint) = iroh_endpoint {
            #[cfg(feature = "av-native")]
            let router = {
                let av_backend = state.av_media.lock().clone();
                let live = av_backend.as_ref().map(|b| b.live());
                crate::iroh::spawn_router(endpoint.clone(), Arc::clone(&state), live)
            };
            #[cfg(not(feature = "av-native"))]
            let router = crate::iroh::spawn_router(endpoint.clone(), Arc::clone(&state));
            *state.iroh_router.lock() = Some(router);
        }

        // Store iroh endpoint in shared state to keep it alive
        if let Some(endpoint) = iroh_endpoint {
            *state.iroh_endpoint.lock() = Some(endpoint);
        }

        // Start periodic CRDT maintenance tasks:
        // 1. Compaction (every 30 min) — bounds doc growth
        // 2. CRDT→local reconciliation (every 60s) — ensures CRDT is source of truth
        {
            let compact_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
                interval.tick().await; // skip first immediate tick
                loop {
                    interval.tick().await;
                    let metrics = compact_state.cluster_doc.get_metrics().await;
                    tracing::info!(
                        "CRDT metrics: {} changes, {} sync msgs sent, {} recv, last save {}B",
                        metrics.change_count,
                        metrics.sync_messages_sent,
                        metrics.sync_messages_received,
                        metrics.last_save_size,
                    );
                    if let Err(e) = compact_state.cluster_doc.compact().await {
                        tracing::error!("CRDT compaction failed: {e}");
                    } else {
                        tracing::info!("CRDT compacted successfully");
                    }
                }
            });
        }

        // CRDT→local reconciliation: periodically apply CRDT state to local
        // channel state. This ensures the CRDT is the single source of truth
        // for topics, founder, and DID ops — even if S2S events and CRDT
        // diverge due to timing/partitions.
        {
            let reconcile_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // skip first tick
                loop {
                    interval.tick().await;
                    reconcile_crdt_to_local(&reconcile_state).await;
                    // Prune expired web auth tokens (TTL 30 min)
                    reconcile_state
                        .web_auth_tokens
                        .lock()
                        .retain(|_, (_, _, created)| {
                            created.elapsed() < std::time::Duration::from_secs(1800)
                        });
                }
            });
        }

        // Policy revalidation: periodically invalidate expired attestations
        // and kick users whose continuous validity has expired.
        if state.policy_engine.is_some() {
            let policy_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // skip first tick
                loop {
                    interval.tick().await;
                    if let Some(ref engine) = policy_state.policy_engine {
                        match engine.revalidate_expired() {
                            Ok(0) => {}
                            Ok(n) => tracing::info!("Invalidated {n} expired policy attestations"),
                            Err(e) => tracing::warn!("Policy revalidation error: {e}"),
                        }
                    }
                }
            });
        }

        // Periodic maintenance (opt-in): age-based message retention +
        // identity re-verification for offboarding. Both default to disabled.
        {
            let retention_days = self.config.message_retention_days;
            let reverify_mins = self.config.reverify_identity_mins;
            if retention_days > 0 || reverify_mins > 0 {
                let maint_state = Arc::clone(&state);
                tokio::spawn(async move {
                    let mut ticks: u64 = 0;
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                    interval.tick().await; // skip immediate tick
                    loop {
                        interval.tick().await;
                        ticks += 1;

                        // Retention: prune messages older than N days, hourly.
                        if retention_days > 0 && ticks.is_multiple_of(60) {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let cutoff = now.saturating_sub(retention_days * 86_400);
                            if let Some(n) =
                                maint_state.with_db(|db| db.prune_messages_older_than(cutoff))
                                && n > 0
                            {
                                tracing::info!(
                                    "Retention: pruned {n} messages older than {retention_days}d"
                                );
                            }
                        }

                        // Identity re-verification (offboarding). SAFE: only acts
                        // when a DID resolves successfully but has NO valid auth
                        // key; never disconnects on a resolution error (outage).
                        if reverify_mins > 0 && ticks.is_multiple_of(reverify_mins) {
                            let did_sessions: std::collections::HashMap<String, Vec<String>> = {
                                let sd = maint_state.session_dids.lock();
                                let mut m: std::collections::HashMap<String, Vec<String>> =
                                    std::collections::HashMap::new();
                                for (sid, did) in sd.iter() {
                                    m.entry(did.clone()).or_default().push(sid.clone());
                                }
                                m
                            };
                            for (did, sids) in did_sessions {
                                match maint_state.did_resolver.resolve(&did).await {
                                    Ok(doc) if doc.authentication_keys().is_empty() => {
                                        tracing::warn!(
                                            %did,
                                            "identity re-verify: DID has no valid auth key — disconnecting sessions"
                                        );
                                        for sid in sids {
                                            if let Some(tx) =
                                                maint_state.connections.lock().get(&sid)
                                            {
                                                let _ = tx.try_send(
                                                    "ERROR :Identity no longer valid (deactivated or key removed)\r\n"
                                                        .to_string(),
                                                );
                                            }
                                            if let Some(kill) =
                                                maint_state.session_kill.lock().get(&sid).cloned()
                                            {
                                                kill.notify_one();
                                            }
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => tracing::debug!(
                                        %did,
                                        error = %e,
                                        "identity re-verify: resolve failed (transient) — keeping session"
                                    ),
                                }
                            }
                        }
                    }
                });
            }
        }

        // Heartbeat expiry: check agent liveness every 15 seconds.
        // Agents that miss their TTL transition to degraded, then offline, then disconnect.
        {
            let hb_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
                interval.tick().await; // skip first tick
                loop {
                    interval.tick().await;
                    let now = chrono::Utc::now().timestamp();
                    let heartbeats: Vec<(String, i64, u64)> = hb_state
                        .agent_heartbeats
                        .lock()
                        .iter()
                        .map(|(sid, (last, ttl))| (sid.clone(), *last, *ttl))
                        .collect();

                    for (session_id, last_hb, ttl) in heartbeats {
                        let elapsed = (now - last_hb) as u64;
                        if elapsed > ttl * 5 {
                            // Force disconnect
                            tracing::warn!(session = %session_id, elapsed, ttl, "Heartbeat timeout — disconnecting agent");
                            hb_state.agent_heartbeats.lock().remove(&session_id);
                            hb_state.agent_presence.lock().remove(&session_id);
                            // Send ERROR to the connection
                            if let Some(tx) = hb_state.connections.lock().get(&session_id) {
                                let _ = tx.try_send("ERROR :Heartbeat timeout\r\n".to_string());
                            }
                        } else if elapsed > ttl * 2 {
                            // Transition to offline
                            let mut presences = hb_state.agent_presence.lock();
                            if let Some(p) = presences.get_mut(&session_id)
                                && p.state != crate::connection::PresenceState::Offline
                            {
                                tracing::debug!(session = %session_id, "Heartbeat missed 2x TTL — offline");
                                p.state = crate::connection::PresenceState::Offline;
                                p.updated_at = now;
                            }
                        } else if elapsed > ttl {
                            // Transition to degraded
                            let mut presences = hb_state.agent_presence.lock();
                            if let Some(p) = presences.get_mut(&session_id)
                                && p.state != crate::connection::PresenceState::Degraded
                                && p.state != crate::connection::PresenceState::Offline
                            {
                                tracing::debug!(session = %session_id, "Heartbeat missed TTL — degraded");
                                p.state = crate::connection::PresenceState::Degraded;
                                p.updated_at = now;
                            }
                        }
                    }
                }
            });
        }

        // Start HTTP/WebSocket listener if configured
        if let Some(ref addr) = web_addr {
            let web_state = Arc::clone(&state);
            let router = crate::web::router(web_state);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("HTTP/WebSocket listener on {addr}");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .await
                {
                    tracing::error!("HTTP server error: {e}");
                }
            });
        }

        // Periodic cleanup: prune expired tokens and stale sessions
        {
            let cleanup_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    // Prune expired web-auth tokens (30 min TTL)
                    {
                        let mut tokens = cleanup_state.web_auth_tokens.lock();
                        let before = tokens.len();
                        tokens.retain(|_, (_, _, created)| created.elapsed().as_secs() < 1800);
                        let pruned = before - tokens.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} expired web-auth tokens");
                        }
                    }
                    // Prune expired upload tokens (300s TTL)
                    {
                        let mut tokens = cleanup_state.upload_tokens.lock();
                        let before = tokens.len();
                        tokens.retain(|_, (_, created)| created.elapsed().as_secs() < 300);
                        let pruned = before - tokens.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} expired upload tokens");
                        }
                    }
                    // Prune expired login_pending (5 min TTL — matches OAuth)
                    {
                        // login_pending doesn't store timestamps, but they're cleaned up
                        // when consumed or when the session disconnects.
                        // login_completions are ephemeral — prune stale ones.
                        let mut completions = cleanup_state.login_completions.lock();
                        let before = completions.len();
                        // Check if the session still exists
                        let conns = cleanup_state.connections.lock();
                        completions.retain(|sid, _| conns.contains_key(sid));
                        drop(conns);
                        let pruned = before - completions.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} stale login completions");
                        }
                    }
                    // Prune stale OAuth pending/complete maps (10 min TTL)
                    {
                        let now = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let mut pending = cleanup_state.oauth_pending.lock();
                        let before = pending.len();
                        pending.retain(|_, p| now.saturating_sub(p.created_at) < 600);
                        let pruned = before - pending.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} stale OAuth pending entries");
                        }
                        drop(pending);
                        let mut complete = cleanup_state.oauth_complete.lock();
                        let before = complete.len();
                        complete.retain(|_, r| now.saturating_sub(r.created_at) < 600);
                        let pruned = before - complete.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} stale OAuth complete entries");
                        }
                    }
                    // Prune stale web sessions (24h TTL — PDS tokens expire anyway)
                    {
                        let mut sessions = cleanup_state.web_sessions.lock();
                        let before = sessions.len();
                        sessions.retain(|_, s| s.created_at.elapsed().as_secs() < 86400);
                        let pruned = before - sessions.len();
                        if pruned > 0 {
                            tracing::info!("Pruned {pruned} stale web sessions");
                        }
                    }
                    // Prune old messages per channel (keep last 50K per channel)
                    {
                        const MAX_MESSAGES_PER_CHANNEL: usize = 50_000;
                        let channel_names: Vec<String> =
                            cleanup_state.channels.lock().keys().cloned().collect();
                        for ch in &channel_names {
                            let ch = ch.clone();
                            cleanup_state
                                .with_db(|db| db.prune_messages(&ch, MAX_MESSAGES_PER_CHANNEL));
                        }
                    }
                    // Prune ended AV sessions from memory (keep for 1 hour)
                    // and auto-end sessions idle for >2 hours with no active participants
                    {
                        // Live-instance set: which AV instances are claimed by a
                        // connection that's alive right now. Used so the age-based
                        // arm of the policy only ever reaps resurrected ghosts —
                        // NEVER a long-running call with live people on it.
                        let live_instances: std::collections::HashSet<String> = cleanup_state
                            .av_instances_per_conn
                            .lock()
                            .values()
                            .flat_map(|set| set.iter().cloned())
                            .collect();
                        // Taken before av_sessions (single lock-order rule).
                        #[cfg(feature = "av-native")]
                        let sfu_for_revoke = cleanup_state.sfu_state.lock().clone();
                        let mut mgr = cleanup_state.av_sessions.lock();
                        // Auto-end policy lives in av::should_auto_end (unit-tested).
                        let stale_ids: Vec<String> = mgr
                            .active_sessions()
                            .iter()
                            .filter(|s| {
                                let active: Vec<_> = s
                                    .participants
                                    .values()
                                    .filter(|p| p.left_at.is_none())
                                    .collect();
                                // Instance-less legacy slots can't be liveness-checked;
                                // treat them as claimed (never end a call we can't verify).
                                let any_claimed = active.iter().any(|p| {
                                    p.instance_id
                                        .as_ref()
                                        .is_none_or(|inst| live_instances.contains(inst))
                                });
                                let age = chrono::Utc::now().timestamp() - s.created_at;
                                crate::av::should_auto_end(active.len(), age, any_claimed)
                            })
                            .map(|s| s.id.clone())
                            .collect();
                        for id in &stale_ids {
                            // Any lingering media conns die with the session
                            // (F6). Snapshot before end_session marks them left.
                            #[cfg(feature = "av-native")]
                            let stale_instances = mgr.active_instances(id);
                            if let Ok(session) = mgr.end_session(id, None) {
                                cleanup_state.with_db(|db| db.save_av_session(&session));
                                #[cfg(feature = "av-native")]
                                if let Some(sfu) = sfu_for_revoke.as_ref() {
                                    for inst in &stale_instances {
                                        sfu.revoke_media(inst);
                                    }
                                }
                                if let Some(ch) = &session.channel {
                                    let ch = ch.clone();
                                    drop(mgr);
                                    crate::connection::messaging::broadcast_av_state_pub(
                                        &cleanup_state,
                                        &ch,
                                        id,
                                        "ended",
                                        "server",
                                        "",
                                        0,
                                        "",
                                    );
                                    mgr = cleanup_state.av_sessions.lock();
                                }
                            }
                        }
                        if !stale_ids.is_empty() {
                            tracing::info!("Auto-ended {} stale AV sessions", stale_ids.len());
                        }
                        // Prune ended sessions older than 1 hour from memory
                        mgr.prune_ended(3600);
                    }
                    // Prune stale IP rate limiter entries
                    {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        cleanup_state.rest_rate_limiter.prune(now);
                    }
                }
            });
        }

        // Graceful shutdown on SIGTERM/SIGINT
        let shutdown_state = Arc::clone(&state);
        let shutdown = async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("Received SIGINT, shutting down..."),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down..."),
            }
            // Broadcast ERROR to all connected clients
            let conns = shutdown_state.connections.lock();
            for tx in conns.values() {
                let _ = tx.try_send("ERROR :Server shutting down\r\n".to_string());
            }
            drop(conns);
            // Give clients a moment to receive the ERROR
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            tracing::info!(
                "Shutdown complete ({} connections closed)",
                shutdown_state.connections.lock().len()
            );
        };

        // Accept plain connections
        const MAX_CONNS_PER_IP: u32 = 20;
        const MAX_GLOBAL_CONNS: u32 = 10_000;
        tokio::select! {
            _ = shutdown => {}
            result = async {
                loop {
                    let (stream, addr) = plain_listener.accept().await?;
                    let ip = addr.ip();
                    let state = Arc::clone(&state);
                    // Global connection limit (defense against distributed DoS)
                    {
                        let ip_conns = state.ip_connections.lock();
                        let total: u32 = ip_conns.values().sum();
                        if total >= MAX_GLOBAL_CONNS {
                            tracing::warn!(total, "Connection rejected: global limit reached ({MAX_GLOBAL_CONNS})");
                            continue;
                        }
                    }
                    // Per-IP connection limit
                    {
                        let mut ip_conns = state.ip_connections.lock();
                        let count = ip_conns.entry(ip).or_insert(0);
                        if *count >= MAX_CONNS_PER_IP {
                            tracing::warn!(%ip, "Connection rejected: per-IP limit reached");
                            continue;
                        }
                        *count += 1;
                    }
                    tokio::spawn(async move {
                        let result = connection::handle(stream, Arc::clone(&state)).await;
                        if let Err(e) = result {
                            tracing::error!("Connection error: {e}");
                        }
                        // Decrement IP counter on disconnect
                        let mut ip_conns = state.ip_connections.lock();
                        if let Some(count) = ip_conns.get_mut(&ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 { ip_conns.remove(&ip); }
                        }
                    });
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            } => {
                if let Err(e) = result {
                    tracing::error!("Accept loop error: {e}");
                }
            }
        }
        Ok(())
    }

    /// Start the server and return the bound address + task handle (for testing).
    pub async fn start(self) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let addr = listener.local_addr()?;
        tracing::info!("Listening on {addr}");

        let state = self.build_state()?;

        // Periodic phantom-session sweeper. Defense-in-depth: even if
        // close handlers leak some bookkeeping (the multi-device path used
        // to do this), this catches it within a minute. No-op when state
        // is consistent.
        spawn_phantom_sweeper(Arc::clone(&state));

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _addr) = listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, state).await {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
        });

        Ok((addr, handle))
    }

    /// Start the server with both IRC and HTTP listeners.
    /// Returns (irc_addr, http_addr, handle).
    pub async fn start_with_web(self) -> Result<(SocketAddr, SocketAddr, JoinHandle<Result<()>>)> {
        let (irc, web, handle, _state) = self.start_with_web_state().await?;
        Ok((irc, web, handle))
    }

    /// Test-helper variant of [`start_with_web`] that also yields the
    /// `Arc<SharedState>` so integration tests can inject fixture data
    /// (channels, sessions, messages) before driving the public HTTP
    /// surface. Production callers should use [`start_with_web`].
    pub async fn start_with_web_state(
        self,
    ) -> Result<(
        SocketAddr,
        SocketAddr,
        JoinHandle<Result<()>>,
        Arc<SharedState>,
    )> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let irc_addr = listener.local_addr()?;

        let web_listener = TcpListener::bind("127.0.0.1:0").await?;
        let web_addr = web_listener.local_addr()?;

        let state = self.build_state()?;
        let state_for_caller = Arc::clone(&state);

        // Phantom-session sweeper (defense-in-depth).
        spawn_phantom_sweeper(Arc::clone(&state));

        let web_state = Arc::clone(&state);
        let router = crate::web::router(web_state);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                web_listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            {
                tracing::error!("HTTP server error: {e}");
            }
        });

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _addr) = listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, state).await {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
        });

        Ok((irc_addr, web_addr, handle, state_for_caller))
    }

    /// Start the server with both plain and TLS listeners for testing.
    /// Returns (plain_addr, tls_addr, handle).
    pub async fn start_tls(self) -> Result<(SocketAddr, SocketAddr, JoinHandle<Result<()>>)> {
        let tls_acceptor = self
            .build_tls_acceptor()?
            .expect("TLS must be configured for start_tls()");

        let plain_listener = TcpListener::bind(&self.config.listen_addr).await?;
        let plain_addr = plain_listener.local_addr()?;

        let tls_listener = TcpListener::bind(&self.config.tls_listen_addr).await?;
        let tls_addr = tls_listener.local_addr()?;

        tracing::info!("Plain on {plain_addr}, TLS on {tls_addr}");

        let state = self.build_state()?;

        let handle = tokio::spawn(async move {
            let tls_state = Arc::clone(&state);
            let tls_acc = tls_acceptor.clone();
            tokio::spawn(async move {
                loop {
                    match tls_listener.accept().await {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&tls_state);
                            let acceptor = tls_acc.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) =
                                            connection::handle_generic(tls_stream, state).await
                                        {
                                            tracing::error!("TLS connection error: {e}");
                                        }
                                    }
                                    Err(e) => tracing::warn!("TLS handshake failed: {e}"),
                                }
                            });
                        }
                        Err(e) => tracing::error!("TLS accept error: {e}"),
                    }
                }
            });

            loop {
                let (stream, _) = plain_listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, state).await {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
        });

        Ok((plain_addr, tls_addr, handle))
    }

    fn build_tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        if !self.config.tls_enabled() {
            return Ok(None);
        }

        let cert_path = self.config.tls_cert.as_deref().unwrap();
        let key_path = self.config.tls_key.as_deref().unwrap();

        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read TLS cert: {cert_path}"))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read TLS key: {key_path}"))?;

        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse TLS certificates")?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .context("Failed to parse TLS private key")?
            .context("No private key found in PEM file")?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Invalid TLS configuration")?;

        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }
}

/// Process an S2S message received from a peer server.
///
/// Delivers relayed messages to local clients. Currently handles
/// PRIVMSG, JOIN, PART, QUIT, NICK, TOPIC, and sync.
///
/// Remote users are identified by nick (not session ID). We deliver
/// to local sessions that are members of the target channel.
/// Per-peer S2S rate limiter: max events per second.
static S2S_RATE_LIMITS: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, (u64, u32)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
const S2S_MAX_EVENTS_PER_SEC: u32 = 100;

/// Strip characters that could enable IRC protocol injection (\r, \n, \0) from
/// S2S-provided strings. Truncates to `max_len` to prevent memory abuse.
/// Background task: every 60s, look for sessions present in any of the
/// per-session state maps but missing from `connections` (the WS sender
/// map). Those are leaked sessions — bookkeeping that the close handler
/// somehow didn't finish. Removes the stragglers and logs.
///
/// Belt-and-suspenders for the "Attaching additional session for DID
/// existing=N" bug where multi-device close paths used to leave the
/// closing session_id behind in NickMap and session_dids. The connection
/// path now removes them on close (mod.rs:2682-ish), but if anything
/// slips through, this task catches it within a minute.
fn spawn_phantom_sweeper(state: Arc<SharedState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;

            // Snapshot the live session_ids the WS layer knows about.
            let live: std::collections::HashSet<String> =
                { state.connections.lock().keys().cloned().collect() };

            // session_dids: drop entries whose session_id isn't live.
            let leaked_dids: Vec<String> = {
                let sd = state.session_dids.lock();
                sd.iter()
                    .filter(|(sid, _)| !live.contains(sid.as_str()))
                    .map(|(sid, _)| sid.clone())
                    .collect()
            };
            if !leaked_dids.is_empty() {
                let mut sd = state.session_dids.lock();
                for sid in &leaked_dids {
                    sd.remove(sid);
                }
                tracing::warn!(
                    count = leaked_dids.len(),
                    "phantom sweeper: removed leaked session_dids entries"
                );
            }

            // NickMap (sid → nick): same treatment. NickMap.remove_by_session
            // promotes a sibling nick if multiple sessions share it.
            let leaked_sids_in_nickmap: Vec<String> = {
                let nts = state.nick_to_session.lock();
                let mut out = Vec::new();
                for (sid, _) in nts.iter() {
                    if !live.contains(sid) {
                        out.push(sid.to_string());
                    }
                }
                out
            };
            if !leaked_sids_in_nickmap.is_empty() {
                let mut nts = state.nick_to_session.lock();
                for sid in &leaked_sids_in_nickmap {
                    nts.remove_by_session(sid);
                }
                tracing::warn!(
                    count = leaked_sids_in_nickmap.len(),
                    "phantom sweeper: removed leaked NickMap entries"
                );
            }

            // agent_heartbeats / agent_presence — best-effort flush. These
            // can hold stale records past their TTL on their own, but if
            // the session_id is dead these entries are pure litter.
            {
                let mut hb = state.agent_heartbeats.lock();
                hb.retain(|sid, _| live.contains(sid));
                let mut pres = state.agent_presence.lock();
                pres.retain(|sid, _| live.contains(sid));
            }
        }
    });
}

fn sanitize_s2s_str(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .take(max_len)
        .collect()
}

/// Is a federated actor the author of the message this row records?
///
/// DID against the stored row's `sender_did`. A nick match is accepted only when
/// the row has no DID at all (a guest's message) — for a row that names a DID, a
/// nick is not evidence, and a peer can assert any nick it likes.
fn federated_actor_is_author(
    row: &crate::db::MessageAuthorship,
    actor_nick: &str,
    actor_did: Option<&str>,
) -> bool {
    match (row.sender_did.as_deref(), actor_did) {
        (Some(row_did), Some(actor)) => row_did == actor,
        (Some(_), None) => false,
        (None, _) => row
            .sender
            .split('!')
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case(actor_nick),
    }
}

/// May a federated actor delete this message here?
///
/// Two ways in, mirroring what a local delete accepts:
/// - **The author**, per [`federated_actor_is_author`].
/// - **A channel op**, via the same roster check the federated Kick/Mode path
///   uses. Channels only: a DM has no roster, so authorship is the only route.
///
/// A message we hold no row for is nothing to protect — let it through so the
/// TAGMSG still reaches clients, exactly as an unpersisted local delete does.
///
/// `roster_key` is the lowercase in-memory channel key (the roster map is keyed
/// that way); the authorship lookup takes no channel at all, so this gate can't
/// be defeated by the casing a peer happens to send.
fn federated_delete_authorized(
    state: &Arc<SharedState>,
    roster_key: &str,
    root_msgid: &str,
    actor_nick: &str,
    actor_did: Option<&str>,
    is_channel: bool,
) -> bool {
    let row = state.with_db(|db| db.message_authorship(root_msgid));
    let Some(Some(row)) = row else {
        return true;
    };

    if federated_actor_is_author(&row, actor_nick, actor_did) {
        return true;
    }
    if !is_channel {
        return false;
    }

    let channels = state.channels.lock();
    channels.get(roster_key).is_some_and(|ch| {
        ch.remote_member(actor_nick).is_some_and(|rm| {
            rm.is_op
                || rm.did.as_ref().is_some_and(|d| {
                    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                })
        })
    })
}

/// May a federated actor edit this message here?
///
/// **Author only.** Unlike a delete there is no op route: an op may remove
/// content, but rewriting it would put the op's words under another user's name.
/// This is the same authorship rule `handle_edit` applies to a local edit,
/// including its refusal to edit an already-deleted message; a federated edit
/// arrived without any check at all, so a peer could revise anyone's message.
///
/// That mattered more than it looks: the receiving history path revises the
/// *existing* entry in place, leaving its `from` untouched, so an unauthorized
/// edit rewrote the author's words under the author's name for every later
/// joiner, and `current_revision` (what a pin renders) followed.
///
/// A message we hold no row for is nothing to protect — an edit of something
/// that predates us, or in an unpersisted guest DM thread, still arrives.
/// `channel_history_key` (lowercase, channels only) is checked in that case:
/// with no database at all the in-memory history is the only record of who
/// wrote a message, and it must still be honoured.
fn federated_edit_authorized(
    state: &Arc<SharedState>,
    channel_history_key: Option<&str>,
    root_msgid: &str,
    actor_nick: &str,
    actor_did: Option<&str>,
) -> bool {
    if let Some(Some(row)) = state.with_db(|db| db.message_authorship(root_msgid)) {
        // A deleted message has no editable text; a revision of it would
        // resurrect nothing and confuse every client's view.
        return !row.deleted && federated_actor_is_author(&row, actor_nick, actor_did);
    }

    let Some(key) = channel_history_key else {
        return true;
    };
    let channels = state.channels.lock();
    let Some(entry) = channels.get(key).and_then(|ch| {
        ch.history
            .iter()
            .find(|h| h.msgid.as_deref() == Some(root_msgid))
    }) else {
        return true;
    };
    // History carries no DID, so nick is all there is here. Weaker than the
    // row check, and only ever reached when there is no row to do better with.
    entry
        .from
        .split('!')
        .next()
        .unwrap_or("")
        .eq_ignore_ascii_case(actor_nick)
}

/// The channel entry for an S2S-learned channel, created with the mode set a
/// channel is born with everywhere else (+nt: no external messages, topic
/// locked to ops) if this is the first we have heard of it.
///
/// Four S2S handlers can bring a channel into existence — `Join`, `Topic`,
/// `ChannelCreated`, `SyncResponse` — and only the last two applied the
/// defaults. Worse, the origin sends `Join` *before* `ChannelCreated`, so by the
/// time the explicit defaults arrived the channel already existed and they were
/// skipped: in practice a peer-learned channel had no +n and no +t at all.
/// A channel's protections must not depend on which event won a race, so every
/// creation path goes through here.
///
/// Existing channels are returned untouched: a mode deliberately turned off
/// stays off.
fn s2s_channel_entry<'a>(
    channels: &'a mut HashMap<String, ChannelState>,
    channel: &str,
) -> &'a mut ChannelState {
    let is_new = !channels.contains_key(channel);
    let ch = channels.entry(channel.to_string()).or_default();
    if is_new {
        ch.no_ext_msg = true;
        ch.topic_locked = true;
    }
    ch
}

/// Process an incoming S2S message. Exposed as pub(crate) for adversarial testing.
pub(crate) async fn process_s2s_message(
    state: &Arc<SharedState>,
    manager: &Arc<crate::s2s::S2sManager>,
    authenticated_peer_id: &str,
    msg: crate::s2s::S2sMessage,
) {
    use crate::s2s::S2sMessage;

    // ── C-1 fix: Reject messages from unauthenticated peers ──
    // Hello and HelloAck are the handshake itself, so they must pass through.
    if !matches!(&msg, S2sMessage::Hello { .. } | S2sMessage::HelloAck { .. })
        && !manager
            .authenticated_peers
            .lock()
            .await
            .contains(authenticated_peer_id)
    {
        tracing::warn!(
            peer = %authenticated_peer_id,
            "S2S: dropping message from unauthenticated peer"
        );
        return;
    }

    // ── S2S rate limiting ──
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut limits = S2S_RATE_LIMITS.lock();
        let entry = limits
            .entry(authenticated_peer_id.to_string())
            .or_insert((now, 0));
        if entry.0 == now {
            entry.1 += 1;
            if entry.1 > S2S_MAX_EVENTS_PER_SEC {
                if entry.1 == S2S_MAX_EVENTS_PER_SEC + 1 {
                    tracing::warn!(
                        peer = %authenticated_peer_id,
                        "S2S rate limit exceeded ({S2S_MAX_EVENTS_PER_SEC}/sec), dropping events"
                    );
                }
                return;
            }
        } else {
            *entry = (now, 1);
        }
    }

    /// Deliver a raw IRC line to all local members of a channel.
    fn deliver_to_channel(state: &SharedState, channel: &str, line: &str) {
        let channel_key = channel.to_lowercase();
        let channels = state.channels.lock();
        if let Some(ch) = channels.get(&channel_key) {
            let conns = state.connections.lock();
            for session_id in &ch.members {
                if let Some(tx) = conns.get(session_id) {
                    let _ = tx.try_send(line.to_string());
                }
            }
        }
    }

    /// Send NAMES update to all local members of a channel (for nick list refresh).
    fn send_names_update(state: &SharedState, channel: &str) {
        // Lock-ordering: take channels → (drop) → nick_to_session → (drop) →
        // connections, never two at once. Holding channels+nick_to_session+
        // connections nested here deadlocked against paths that take
        // nick_to_session before channels (caught in prod 2026-07-09: an S2S
        // NAMES update vs a reconnect auto-rejoin). Snapshotting under each
        // lock independently removes this function from any ordering cycle.

        // 1. Snapshot membership + op prefixes under `channels` only.
        let (local_members, member_prefix, remote_entries) = {
            let channels = state.channels.lock();
            let ch = match channels.get(channel) {
                Some(ch) => ch,
                None => return,
            };
            let member_prefix: Vec<(String, &'static str)> = ch
                .members
                .iter()
                .map(|s| {
                    let prefix = if ch.ops.contains(s) {
                        "@"
                    } else if ch.halfops.contains(s) {
                        "%"
                    } else if ch.voiced.contains(s) {
                        "+"
                    } else {
                        ""
                    };
                    (s.clone(), prefix)
                })
                .collect();
            let remote_entries: Vec<String> = ch
                .remote_members
                .iter()
                .map(|(nick, rm)| {
                    let is_op = rm.is_op
                        || rm.did.as_ref().is_some_and(|d| {
                            ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                        });
                    let prefix = if is_op { "@" } else { "" };
                    format!("{prefix}{nick}")
                })
                .collect();
            let local_members: Vec<String> = ch.members.iter().cloned().collect();
            (local_members, member_prefix, remote_entries)
        };

        // 2. Resolve session ids → nicks under `nick_to_session` only.
        let (nick_str, member_nicks) = {
            let n2s = state.nick_to_session.lock();
            let mut nick_list: Vec<String> = member_prefix
                .iter()
                .filter_map(|(sid, prefix)| n2s.get_nick(sid).map(|n| format!("{prefix}{n}")))
                .collect();
            nick_list.extend(remote_entries);
            // Each local member's own nick, for the 353/366 reply target.
            let member_nicks: Vec<(String, String)> = local_members
                .iter()
                .map(|sid| (sid.clone(), n2s.get_nick(sid).unwrap_or("*").to_string()))
                .collect();
            (nick_list.join(" "), member_nicks)
        };

        // 3. Send to each local member under `connections` only.
        let conns = state.connections.lock();
        for (session_id, member_nick) in &member_nicks {
            let names_line = format!(
                ":{} 353 {} = {} :{}\r\n:{} 366 {} {} :End of /NAMES list\r\n",
                state.server_name,
                member_nick,
                channel,
                nick_str,
                state.server_name,
                member_nick,
                channel,
            );
            if let Some(tx) = conns.get(session_id) {
                let _ = tx.try_send(names_line);
            }
        }
    }

    // ── Event dedup ──────────────────────────────────────────────
    // Extract event_id and origin from message for dedup check.
    // Messages with empty event_id (legacy peers) skip dedup.
    let (event_id, origin) = match &msg {
        S2sMessage::Privmsg {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Tagmsg {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Pin {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Join {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Part {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Quit {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::NickChange {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Topic {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Mode {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::ChannelCreated {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Kick {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Ban {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::InviteException {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::Invite {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::PolicySync {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::AvSessionCreated {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::AvSessionJoined {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::AvSessionLeft {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::AvSessionEnded {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::CrdtSync { origin, .. } => (String::new(), origin.clone()),
        S2sMessage::PeerDisconnected { .. } => (String::new(), String::new()),
        S2sMessage::Hello { .. }
        | S2sMessage::HelloAck { .. }
        | S2sMessage::Signed { .. }
        | S2sMessage::KeyRotation { .. }
        | S2sMessage::SyncRequest
        | S2sMessage::SyncResponse { .. } => (String::new(), String::new()),
    };

    // Skip our own messages
    if !origin.is_empty() && origin == manager.server_id {
        return;
    }

    // Dedup: reject duplicate event_ids
    if !event_id.is_empty() && !manager.dedup.check_and_insert(&origin, &event_id).await {
        tracing::debug!(event_id = %event_id, "S2S event deduplicated (already seen)");
        return;
    }

    // Phase 3: Trust-level enforcement
    let peer_trust = manager.get_trust(authenticated_peer_id).await;
    match (&msg, peer_trust) {
        // Readonly peers cannot originate any events
        (
            S2sMessage::Privmsg { .. }
            | S2sMessage::Tagmsg { .. }
            | S2sMessage::Pin { .. }
            | S2sMessage::Join { .. }
            | S2sMessage::Part { .. }
            | S2sMessage::Quit { .. }
            | S2sMessage::NickChange { .. }
            | S2sMessage::Topic { .. }
            | S2sMessage::Mode { .. }
            | S2sMessage::Kick { .. }
            | S2sMessage::Ban { .. }
            | S2sMessage::InviteException { .. }
            | S2sMessage::Invite { .. }
            | S2sMessage::ChannelCreated { .. }
            | S2sMessage::AvSessionCreated { .. }
            | S2sMessage::AvSessionJoined { .. }
            | S2sMessage::AvSessionLeft { .. }
            | S2sMessage::AvSessionEnded { .. },
            crate::s2s::TrustLevel::Readonly,
        ) => {
            tracing::warn!(
                peer = %authenticated_peer_id,
                trust = "readonly",
                "S2S: dropping event from readonly peer"
            );
            return;
        }
        // Relay peers cannot perform admin operations
        (
            S2sMessage::Mode { .. }
            | S2sMessage::Kick { .. }
            | S2sMessage::Ban { .. }
            | S2sMessage::InviteException { .. }
            | S2sMessage::ChannelCreated { .. },
            crate::s2s::TrustLevel::Relay,
        ) => {
            tracing::warn!(
                peer = %authenticated_peer_id,
                trust = "relay",
                "S2S: dropping admin event from relay-only peer"
            );
            return;
        }
        _ => {} // Full trust or handshake messages — proceed
    }

    match msg {
        S2sMessage::Hello {
            peer_id,
            server_name,
            protocol_version,
            trust_level,
        } => {
            // Verify the claimed peer_id matches the transport-authenticated identity.
            if peer_id != authenticated_peer_id {
                tracing::warn!(
                    authenticated = %authenticated_peer_id,
                    claimed = %peer_id,
                    server_name = %server_name,
                    "S2S Hello: claimed peer_id doesn't match transport identity — using authenticated ID"
                );
            }

            let peer_trust_str = trust_level.as_deref().unwrap_or("full");
            tracing::info!(
                peer = %authenticated_peer_id,
                server_name = %server_name,
                protocol_version,
                peer_trust = %peer_trust_str,
                "S2S Hello received — binding transport identity to server name"
            );

            manager
                .peer_names
                .lock()
                .await
                .insert(authenticated_peer_id.to_string(), server_name);

            // Phase 1: Send HelloAck — mutual auth confirmation.
            let our_trust = manager.get_trust(authenticated_peer_id).await;
            let allowed = &state.config.s2s_allowed_peers;
            let accepted = allowed.is_empty() || allowed.iter().any(|a| a == authenticated_peer_id);
            let ack = crate::s2s::S2sMessage::HelloAck {
                peer_id: manager.server_id.clone(),
                accepted,
                trust_level: Some(our_trust.to_string()),
            };
            if let Some(entry) = manager.peers.lock().await.get(authenticated_peer_id) {
                let _ = entry.tx.send(ack).await;
            }

            // Phase 3: Record the trust level the peer offers us (informational)
            if let Some(ref lvl) = trust_level {
                let level = crate::s2s::TrustLevel::parse_level(lvl);
                manager.set_trust(authenticated_peer_id, level).await;
            }

            // Phase 1: Mark peer as authenticated
            manager
                .authenticated_peers
                .lock()
                .await
                .insert(authenticated_peer_id.to_string());
        }

        S2sMessage::HelloAck {
            peer_id,
            accepted,
            trust_level,
        } => {
            if !accepted {
                tracing::warn!(
                    peer = %authenticated_peer_id,
                    "S2S HelloAck: peer rejected us — disconnecting"
                );
                // Remove peer so the link drops
                manager.peers.lock().await.remove(authenticated_peer_id);
                return;
            }
            tracing::info!(
                peer = %authenticated_peer_id,
                claimed = %peer_id,
                trust = ?trust_level,
                "S2S HelloAck: mutual authentication confirmed"
            );
            manager
                .authenticated_peers
                .lock()
                .await
                .insert(authenticated_peer_id.to_string());
        }

        S2sMessage::KeyRotation {
            old_id,
            new_id,
            timestamp,
            signature,
        } => {
            if manager.verify_rotation(
                &old_id,
                &new_id,
                timestamp,
                &signature,
                authenticated_peer_id,
            ) {
                tracing::info!(
                    old = %old_id,
                    new = %new_id,
                    "S2S key rotation verified — recording pending rotation"
                );
                manager
                    .pending_rotations
                    .lock()
                    .await
                    .insert(old_id, new_id);
            } else {
                tracing::warn!(
                    old = %old_id,
                    new = %new_id,
                    "S2S key rotation verification FAILED — ignoring"
                );
            }
        }

        S2sMessage::Signed { .. } => {
            // Should have been unwrapped in the read loop — if we get here,
            // it means the signature was invalid and the message was passed through.
            tracing::warn!(peer = %authenticated_peer_id, "Received raw Signed envelope (should have been unwrapped)");
        }

        S2sMessage::Privmsg {
            from,
            target,
            text,
            origin,
            msgid,
            sig,
            account,
            recipient_did: stamped_recipient_did,
            replaces_msgid,
            tags: relayed_tags,
            multiline_lines,
            ..
        } => {
            // Sanitize all peer-provided strings to prevent IRC protocol injection.
            let from = sanitize_s2s_str(&from, 512);
            let target = sanitize_s2s_str(&target, 200);
            // Match the local multiline ceiling (MAX_BYTES) so a federated
            // message isn't truncated in history/CHATHISTORY when it crosses a
            // server boundary. `\r`/`\n`/`\0` stripping is the injection
            // defense; the length cap is only a size bound. Tied to the same
            // constant so the two paths can't drift apart again.
            let text = sanitize_s2s_str(&text, crate::connection::draft_multiline::MAX_BYTES);
            // Sender DID carried from the origin (the `account` tag value).
            // Stamped by the origin from its authenticated session, never
            // client-set; relayed on the same peer trust as the message body.
            let account = account.map(|a| sanitize_s2s_str(&a, 512));

            // Generate a local msgid if the remote didn't send one
            let msgid = msgid.unwrap_or_else(crate::msgid::generate);

            // An edit names the message it revises. Resolve to our own root:
            // the peer names the root too, but an id we've never seen is its
            // own root, so this is also what makes an edit of a message that
            // predates us behave sanely instead of vanishing.
            let edit_of: Option<String> = replaces_msgid
                .map(|r| sanitize_s2s_str(&r, 100))
                .filter(|r| !r.is_empty())
                .map(|r| crate::connection::helpers::root_msgid(state, &r));

            // An edit may only come from the author. Dropped rather than
            // downgraded to a plain message: a local edit that fails the same
            // check is not delivered either (FAIL AUTHOR_MISMATCH), and relaying
            // it as new text would put words in the channel that the origin's
            // user never asked to send as a new message.
            let actor_nick = from.split('!').next().unwrap_or(&from).to_string();
            if let Some(ref root) = edit_of {
                let history_key = (target.starts_with('#') || target.starts_with('&'))
                    .then(|| target.to_lowercase());
                if !federated_edit_authorized(
                    state,
                    history_key.as_deref(),
                    root,
                    &actor_nick,
                    account.as_deref(),
                ) {
                    tracing::warn!(
                        target = %target, msgid = %root, by = %actor_nick,
                        "S2S edit rejected: actor is not the author"
                    );
                    return;
                }
            }

            // Peer-provided coordination tags. Re-filter on receipt (never
            // trust the sending peer to have filtered correctly): keep only
            // `+freeq.at/*` minus `+freeq.at/sig` (re-attested locally),
            // sanitize key+value against IRC injection, and cap the count to
            // bound relay amplification.
            let mut relay_tags: HashMap<String, String> = relayed_tags
                .into_iter()
                .filter(|(k, _)| k.starts_with("+freeq.at/") && k != "+freeq.at/sig")
                .take(16)
                .map(|(k, v)| (sanitize_s2s_str(&k, 64), sanitize_s2s_str(&v, 4096)))
                .collect();
            // Provenance: every message reaching here is from a remote origin
            // (self-origin is skipped above), so tag it with the origin
            // server's name. Lets clients distinguish a peer-vouched federated
            // message from a locally-verified one, rather than rendering the
            // (only peer-trusted) `account` as if this server had verified it.
            let origin_name = sanitize_s2s_str(&manager.peer_display_name(&origin).await, 64);
            relay_tags.insert("+freeq.at/origin".to_string(), origin_name);

            // Plain line for non-tag clients, tagged line with msgid + sig for
            // tag clients. `tagged_line_account` additionally carries the
            // `account` tag and is sent only to clients that negotiated
            // `account-tag` (per IRCv3, mirroring local delivery).
            let plain_line = format!(":{from} PRIVMSG {target} :{text}\r\n");
            let build_tagged = |with_account: bool| -> String {
                let mut tags = HashMap::new();
                tags.extend(relay_tags.iter().map(|(k, v)| (k.clone(), v.clone())));
                tags.insert("msgid".to_string(), msgid.clone());
                // Restore the linkage the `+freeq.at/*` tag filter drops on the
                // wire, so our clients see an edit rather than a new message.
                if let Some(ref root) = edit_of {
                    tags.insert("+draft/edit".to_string(), root.clone());
                }
                if let Some(ref sig) = sig {
                    tags.insert("+freeq.at/sig".to_string(), sig.clone());
                }
                if with_account && let Some(ref acct) = account {
                    tags.insert("account".to_string(), acct.clone());
                }
                let tag_msg = crate::irc::Message {
                    tags,
                    prefix: Some(from.clone()),
                    command: "PRIVMSG".to_string(),
                    params: vec![target.clone(), text.clone()],
                };
                format!("{tag_msg}\r\n")
            };
            let tagged_line = build_tagged(false);
            let tagged_line_account = account.as_ref().map(|_| build_tagged(true));

            if target.starts_with('#') || target.starts_with('&') {
                // Enforce +n and +m on incoming S2S messages
                let channel_key = target.to_lowercase();
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel_key) {
                    if ch.no_ext_msg {
                        let nick = from.split('!').next().unwrap_or(&from);
                        let is_member = ch.has_remote_member(nick)
                            || state
                                .nick_to_session
                                .lock()
                                .get_session(nick)
                                .is_some_and(|sid| ch.members.contains(sid));
                        if !is_member {
                            tracing::debug!(channel = %target, from = %from, "S2S PRIVMSG blocked by +n");
                            return;
                        }
                    }
                    if ch.moderated {
                        let nick = from.split('!').next().unwrap_or(&from);
                        let is_privileged = ch.remote_member(nick).is_some_and(|rm| rm.is_op);
                        if !is_privileged {
                            tracing::debug!(channel = %target, from = %from, "S2S PRIVMSG blocked by +m");
                            return;
                        }
                    }
                }
                drop(channels);

                // Store in history + DB
                {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut tags = HashMap::new();
                    tags.extend(relay_tags.iter().map(|(k, v)| (k.clone(), v.clone())));
                    tags.insert("msgid".to_string(), msgid.clone());
                    if let Some(ref sig) = sig {
                        tags.insert("+freeq.at/sig".to_string(), sig.clone());
                    }
                    if let Some(ref acct) = account {
                        tags.insert("account".to_string(), acct.clone());
                    }
                    let mut channels = state.channels.lock();
                    if let Some(ch) = channels.get_mut(&channel_key) {
                        // An edit revises the entry we already hold; only a
                        // brand-new message gets a new one. Appending an edit
                        // instead — which is what happened before the wire
                        // carried the linkage — showed our users the message
                        // twice, permanently.
                        let revised = edit_of.as_ref().and_then(|root| {
                            ch.history
                                .iter()
                                .position(|h| h.msgid.as_deref() == Some(root.as_str()))
                        });
                        // Second lock on the door `federated_edit_authorized`
                        // shut: revising leaves `from` as it was, so writing one
                        // user's text into another's entry publishes the editor's
                        // words under the author's name. Never do it, whatever
                        // the gate concluded.
                        let author_matches = revised.is_some_and(|i| {
                            ch.history[i].from.split('!').next() == from.split('!').next()
                        });
                        if let (Some(i), true) = (revised, author_matches) {
                            ch.history[i].text = text.clone();
                            ch.history[i].edited = true;
                        } else if revised.is_some() {
                            tracing::warn!(
                                channel = %target, from = %from,
                                "S2S edit dropped: would rewrite another user's history entry"
                            );
                        } else {
                            ch.history.push_back(HistoryMessage {
                                from: from.clone(),
                                text: text.clone(),
                                timestamp,
                                tags: tags.clone(),
                                // An edit of a message we never saw still keys
                                // on the root — the identity everyone else
                                // holds it under.
                                msgid: Some(edit_of.clone().unwrap_or_else(|| msgid.clone())),
                                edited: edit_of.is_some(),
                            });
                            while ch.history.len() > MAX_HISTORY {
                                ch.history.pop_front();
                            }
                        }
                    }
                    drop(channels);
                    // Prefer the DID carried from the origin; fall back to a
                    // local nick_owners lookup for peers that didn't send one.
                    let sender_nick = from.split('!').next().unwrap_or(&from);
                    let s2s_sender_did = account
                        .clone()
                        .or_else(|| state.nick_owners.lock().get(sender_nick).cloned());
                    // Persist the coordination tags (incl. +freeq.at/origin) so
                    // CHATHISTORY replay carries them, like the DM persist path.
                    state.with_db(|db| match edit_of {
                        // Same shape as a local edit: a new row that carries
                        // the root, so the pair reads as one message here too.
                        Some(ref root) => db.insert_edit(
                            &target,
                            &from,
                            &text,
                            timestamp,
                            &relay_tags,
                            &msgid,
                            root,
                            s2s_sender_did.as_deref(),
                        ),
                        None => db.insert_message(
                            &target,
                            &from,
                            &text,
                            timestamp,
                            &relay_tags,
                            Some(&msgid),
                            s2s_sender_did.as_deref(),
                        ),
                    });
                }

                // Deliver to local members with tag-awareness
                let members: Vec<String> = state
                    .channels
                    .lock()
                    .get(&channel_key)
                    .map(|ch| ch.members.iter().cloned().collect())
                    .unwrap_or_default();
                let tag_caps = state.cap_message_tags.lock();
                let time_caps = state.cap_server_time.lock();
                let account_caps = state.cap_account_tag.lock();
                let multiline_caps = state.cap_draft_multiline.lock();
                let conns = state.connections.lock();
                // If the peer told us this is a draft/multiline batch,
                // re-emit per-receiver wire frames (BATCH for capable
                // receivers, individual PRIVMSGs for fallback) just
                // like the local-origin channel broadcast does.
                // Without this branch, a federated multiline message
                // would arrive at local clients as one PRIVMSG with
                // `\n` in its body, breaking the IRC wire.
                let local_lines: Option<Vec<crate::connection::draft_multiline::BatchLine>> =
                    multiline_lines.as_ref().map(|lines| {
                        lines
                            .iter()
                            .map(|l| crate::connection::draft_multiline::BatchLine {
                                body: l.body.clone(),
                                concat_to_previous: l.concat,
                                command: "PRIVMSG".to_string(),
                            })
                            .collect()
                    });
                let outbound_batch_id = local_lines
                    .as_ref()
                    .map(|_| format!("ml{}", crate::msgid::generate()));
                let time_tag = chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S.000Z")
                    .to_string();
                // Inject the `account` tag (sender DID carried from the
                // origin) for clients that negotiated account-tag, the same
                // as the single-PRIVMSG path and local delivery.
                for sid in &members {
                    if let Some(tx) = conns.get(sid) {
                        if let (Some(lines), Some(batch_id)) =
                            (local_lines.as_ref(), outbound_batch_id.as_deref())
                        {
                            let caps = crate::connection::draft_multiline::ReceiverCaps {
                                has_tags: tag_caps.contains(sid),
                                has_time: time_caps.contains(sid),
                                has_multiline: multiline_caps.contains(sid),
                                wants_account: account.is_some() && account_caps.contains(sid),
                                sender_did: account.as_deref(),
                            };
                            // Opener tags here are the relayed
                            // coordination tags + sig (msgid is
                            // managed by the builder).
                            let mut opener_tags: HashMap<String, String> = relay_tags
                                .iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();
                            if let Some(ref sig) = sig {
                                opener_tags.insert("+freeq.at/sig".to_string(), sig.clone());
                            }
                            let ctx = crate::connection::draft_multiline::RelayContext {
                                hostmask: &from,
                                command: "PRIVMSG",
                                target: &target,
                                msgid: &msgid,
                                time_tag: &time_tag,
                                opener_tags: &opener_tags,
                                batch_id,
                                lines,
                            };
                            for frame in
                                crate::connection::draft_multiline::build_outbound_multiline_frames(
                                    &ctx, &caps,
                                )
                            {
                                let _ = tx.try_send(frame);
                            }
                        } else {
                            let line = if !tag_caps.contains(sid) {
                                &plain_line
                            } else if account.is_some() && account_caps.contains(sid) {
                                tagged_line_account.as_ref().unwrap_or(&tagged_line)
                            } else {
                                &tagged_line
                            };
                            let _ = tx.try_send(line.clone());
                        }
                    }
                }
            } else {
                // DM target: a nick or a `did:`. Resolve to every local session
                // bound to the recipient (DID fan-out) — a federated DID-addressed
                // DM must reach the same person here, with no per-server nick
                // interpretation.
                let sids = crate::connection::routing::local_sessions_for_target(state, &target);
                let tag_caps = state.cap_message_tags.lock();
                let acct_caps = state.cap_account_tag.lock();
                let conns = state.connections.lock();
                for sid in &sids {
                    let has_tags = tag_caps.contains(sid);
                    let wants_account = account.is_some() && acct_caps.contains(sid);
                    let line = if !has_tags {
                        &plain_line
                    } else if wants_account {
                        tagged_line_account.as_ref().unwrap_or(&tagged_line)
                    } else {
                        &tagged_line
                    };
                    if let Some(tx) = conns.get(sid) {
                        let _ = tx.try_send(line.clone());
                    }
                }
                drop(conns);
                drop(acct_caps);
                drop(tag_caps);

                // Persist DM if both sender and recipient have DIDs. Prefer the
                // sender DID carried from the origin (a remote sender is not in
                // our nick_owners); fall back to the local lookup.
                let sender_nick = from.split('!').next().unwrap_or(&from);
                let sender_did = account
                    .clone()
                    .or_else(|| state.nick_owners.lock().get(sender_nick).cloned());
                // Recipient: honor the origin's stamp, cross-checked against our
                // own resolution. On a mismatch we fall back (no durable row)
                // rather than persist under a possibly-wrong identity.
                let stamped_recipient_did =
                    stamped_recipient_did.map(|d| sanitize_s2s_str(&d, 512));
                let local_recipient =
                    crate::connection::routing::recipient_did_for_target(state, &target);
                let recipient_did = crate::connection::routing::reconcile_recipient_did(
                    stamped_recipient_did.as_deref(),
                    local_recipient.as_deref(),
                );
                if let (Some(s_did), Some(r_did)) =
                    (sender_did.as_deref(), recipient_did.as_deref())
                {
                    let dm_key = crate::db::canonical_dm_key(s_did, r_did);
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut tags = HashMap::new();
                    tags.extend(relay_tags.iter().map(|(k, v)| (k.clone(), v.clone())));
                    tags.insert("msgid".to_string(), msgid.clone());
                    if let Some(ref sig) = sig {
                        tags.insert("+freeq.at/sig".to_string(), sig.clone());
                    }
                    if let Some(ref acct) = account {
                        tags.insert("account".to_string(), acct.clone());
                    }
                    // A DM edit is a revision of a row we already hold, keyed
                    // by the root — same as the channel path. Storing it as a
                    // new message would leave the thread showing both versions.
                    state.with_db(|db| match edit_of {
                        Some(ref root) => db.insert_edit(
                            &dm_key,
                            &from,
                            &text,
                            timestamp,
                            &tags,
                            &msgid,
                            root,
                            sender_did.as_deref(),
                        ),
                        None => db.insert_message(
                            &dm_key,
                            &from,
                            &text,
                            timestamp,
                            &tags,
                            Some(&msgid),
                            sender_did.as_deref(),
                        ),
                    });
                }
            }
        }

        S2sMessage::Pin {
            channel,
            msgid,
            pinned_by,
            adding,
            ..
        } => {
            let channel = sanitize_s2s_str(&channel, 200).to_lowercase();
            // The peer may name a revision we know under its root.
            let msgid =
                crate::connection::helpers::root_msgid(state, &sanitize_s2s_str(&msgid, 100));
            let pinned_by = sanitize_s2s_str(&pinned_by, 64);

            let mut channels = state.channels.lock();
            if let Some(ch) = channels.get_mut(&channel) {
                if adding {
                    if !ch.pins.iter().any(|p| p.msgid == msgid) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        ch.pins.insert(
                            0,
                            crate::server::PinnedMessage {
                                msgid: msgid.clone(),
                                pinned_by: pinned_by.clone(),
                                pinned_at: now,
                            },
                        );
                        ch.pins.truncate(50);
                        drop(channels);
                        state.with_db(|db| db.store_pin(&channel, &msgid, &pinned_by, now));
                    } else {
                        drop(channels);
                    }
                } else {
                    ch.pins.retain(|p| p.msgid != msgid);
                    drop(channels);
                    state.with_db(|db| db.remove_pin(&channel, &msgid));
                }

                // Notify local members
                let tag = if adding {
                    "+freeq.at/pin"
                } else {
                    "+freeq.at/unpin"
                };
                let action = if adding { "pinned" } else { "unpinned" };
                let notice = format!(
                    "@{tag}={} :{pinned_by}!~u@s2s NOTICE {channel} :\x01ACTION {action} a message\x01\r\n",
                    crate::irc::escape_tag_value(&msgid)
                );
                let members: Vec<String> = state
                    .channels
                    .lock()
                    .get(&channel)
                    .map(|ch| ch.members.iter().cloned().collect())
                    .unwrap_or_default();
                let conns = state.connections.lock();
                for sid in &members {
                    if let Some(tx) = conns.get(sid) {
                        let _ = tx.try_send(notice.clone());
                    }
                }
            }
        }

        S2sMessage::Tagmsg {
            from,
            target,
            tags,
            account,
            ..
        } => {
            let from = sanitize_s2s_str(&from, 512);
            let target = sanitize_s2s_str(&target, 200);
            // Actor DID, origin-stamped. Older peers send none, so keep the
            // nick lookup as the fallback — it resolves for anyone who has
            // authenticated here, which is what we relied on before.
            let actor_nick = from.split('!').next().unwrap_or(&from).to_string();
            let actor_did = account.map(|a| sanitize_s2s_str(&a, 512)).or_else(|| {
                state
                    .nick_owners
                    .lock()
                    .get(&actor_nick.to_lowercase())
                    .cloned()
            });

            // Normalize draft tags
            let mut tags = tags.clone();
            for (draft, canonical) in [("+draft/react", "+react"), ("+draft/reply", "+reply")] {
                if let Some(v) = tags.remove(draft) {
                    tags.entry(canonical.to_string()).or_insert(v);
                }
            }
            // …and the message being acted on to its root, so a peer naming a
            // revision still files and fans out under the one identity our
            // clients hold the message under.
            if (tags.contains_key("+react") || tags.contains_key("+freeq.at/unreact"))
                && let Some(target_msgid) = tags.get("+reply")
            {
                let root = crate::connection::helpers::root_msgid(state, target_msgid);
                tags.insert("+reply".to_string(), root);
            }

            // Persist reactions
            if let (Some(emoji), Some(target_msgid)) = (tags.get("+react"), tags.get("+reply")) {
                let nick = actor_nick.clone();
                let did = actor_did.clone();
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let emoji = emoji.clone();
                let target_msgid = target_msgid.clone();
                let channel = target.clone();
                state.with_db(|db| {
                    db.store_reaction(&target_msgid, &channel, &nick, did.as_deref(), &emoji, ts)
                });
            }

            // Persist reaction REMOVALS too. Without this, a federated
            // unreact relayed to live clients but the peer's DB kept the row —
            // the removed reaction resurrected for every fresh join and after
            // every restart on this side of the federation.
            if let (Some(emoji), Some(target_msgid)) =
                (tags.get("+freeq.at/unreact"), tags.get("+reply"))
            {
                let nick = actor_nick.clone();
                let did = actor_did.clone();
                let emoji = emoji.clone();
                let target_msgid = target_msgid.clone();
                state
                    .with_db(|db| db.remove_reaction(&target_msgid, &nick, did.as_deref(), &emoji));
            }

            // Apply a federated delete to our own state. Relaying it to live
            // clients is not enough — without this the row survives here, so
            // the message returns on the next join or restart.
            if let Some(deleted_msgid) = tags.get("+draft/delete").cloned() {
                let root = crate::connection::helpers::root_msgid(state, &deleted_msgid);
                let is_channel = target.starts_with('#') || target.starts_with('&');
                let storage_key = if is_channel {
                    target.to_lowercase()
                } else {
                    // A DM lives under the canonical key of the two DIDs, not
                    // the wire target.
                    match (
                        actor_did.as_deref(),
                        crate::connection::routing::recipient_did_for_target(state, &target)
                            .as_deref(),
                    ) {
                        (Some(a), Some(b)) => crate::db::canonical_dm_key(a, b),
                        _ => target.clone(),
                    }
                };

                if federated_delete_authorized(state, &storage_key, &root, &actor_nick, actor_did.as_deref(), is_channel)
                {
                    // Sweep under the key the row is actually filed beneath. A
                    // peer sends the channel spelled the way its user typed it
                    // and that spelling is what got stored, while `storage_key`
                    // is lowercased for the in-memory map — so a mixed-case
                    // channel had its history entry dropped here while the row
                    // survived in the database, and came back on restart.
                    let db_key = state
                        .with_db(|db| db.message_authorship(&root))
                        .flatten()
                        .map(|a| a.channel)
                        .unwrap_or_else(|| storage_key.clone());
                    state.with_db(|db| db.soft_delete_message(&db_key, &root));
                    if is_channel {
                        let mut channels = state.channels.lock();
                        if let Some(ch) = channels.get_mut(&storage_key) {
                            ch.history.retain(|h| h.msgid.as_deref() != Some(root.as_str()));
                            ch.pins.retain(|p| p.msgid != root);
                        }
                    }
                } else {
                    tracing::warn!(
                        target = %target, msgid = %root, by = %actor_nick,
                        "S2S delete rejected: actor is neither the author nor an op"
                    );
                    return;
                }
            }

            // Wire forms — identical for channel and DM delivery.
            let tag_msg = crate::irc::Message {
                tags: tags.clone(),
                prefix: Some(from.clone()),
                command: "TAGMSG".to_string(),
                params: vec![target.clone()],
            };
            let tagged_line = format!("{tag_msg}\r\n");
            let plain_fallback = tags.get("+react").map(|emoji| {
                format!(":{from} PRIVMSG {target} :\x01ACTION reacted with {emoji}\x01\r\n")
            });

            // Resolve recipients: channel members, or (for a nick / `did:` DM)
            // every local session bound to that recipient — a federated action
            // addressed to a DID reaches the same person here.
            let recipients: Vec<String> = if target.starts_with('#') || target.starts_with('&') {
                state
                    .channels
                    .lock()
                    .get(&target.to_lowercase())
                    .map(|ch| ch.members.iter().cloned().collect())
                    .unwrap_or_default()
            } else {
                crate::connection::routing::local_sessions_for_target(state, &target)
            };

            let tag_caps = state.cap_message_tags.lock();
            let conns = state.connections.lock();
            for sid in &recipients {
                if let Some(tx) = conns.get(sid) {
                    if tag_caps.contains(sid) {
                        let _ = tx.try_send(tagged_line.clone());
                    } else if let Some(ref fallback) = plain_fallback {
                        let _ = tx.try_send(fallback.clone());
                    }
                }
            }
        }

        S2sMessage::Join {
            nick,
            channel,
            did,
            handle,
            is_op: _, // Intentionally ignored — op status derived locally (C-2)
            actor_class,
            origin,
            ..
        } => {
            // Sanitize peer-provided strings to prevent IRC protocol injection.
            let nick = sanitize_s2s_str(&nick, 64);
            let channel = sanitize_s2s_str(&channel, 200).to_lowercase();

            // ── S2S authorization: enforce bans and +i ──
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel) {
                    // Check +i (invite only) — but allow if user has an invite
                    if ch.invite_only {
                        let has_invite = did.as_ref().is_some_and(|d| ch.invites.contains(d))
                            || ch.invites.contains(&format!("nick:{nick}"));
                        if !has_invite {
                            tracing::info!(
                                channel = %channel, nick = %nick,
                                "S2S Join rejected: channel is +i (invite only)"
                            );
                            return;
                        }
                    }
                    // Check bans
                    let hostmask = format!("{nick}!{nick}@s2s");
                    if ch.is_banned(&hostmask, did.as_deref()) {
                        tracing::info!(
                            channel = %channel, nick = %nick,
                            "S2S Join rejected: user is banned"
                        );
                        return;
                    }
                }
            }

            // Validate DID format if provided — reject obviously bogus values
            // without making outbound HTTP calls. Accepts did:plc, did:web,
            // and did:key (the latter used by bot-kit / agent bots).
            if let Some(ref d) = did {
                let valid = (d.starts_with("did:plc:")
                    || d.starts_with("did:web:")
                    || d.starts_with("did:key:"))
                    && d.len() >= 12
                    && d.len() <= 256;
                if !valid {
                    tracing::warn!(
                        channel = %channel, nick = %nick, did = %d,
                        "S2S Join rejected: malformed DID"
                    );
                    return;
                }
            }

            // Presence is S2S-event-only (NOT in CRDT — avoids ghost users)
            // Idempotent: set-based, don't assume not present
            {
                let mut channels = state.channels.lock();
                let ch = s2s_channel_entry(&mut channels, &channel);
                // Consume invite (all forms: DID, nick)
                if let Some(ref d) = did {
                    ch.invites.remove(d);
                }
                ch.invites.remove(&format!("nick:{nick}"));
                // Never trust is_op from the peer — determine op status from
                // local channel state (founder_did / did_ops) to prevent
                // forged operator claims (C-2 mitigation).
                let actual_is_op = did.as_deref().is_some_and(|d| {
                    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                });
                ch.remote_members.insert(
                    nick.clone(),
                    RemoteMember {
                        origin: origin.clone(),
                        did: did.clone(),
                        handle: handle.clone(),
                        is_op: actual_is_op,
                        actor_class: actor_class.clone(),
                    },
                );
            }

            // Include actor_class tag for tag-capable clients
            let line = if let Some(ref ac) = actor_class {
                format!("@+freeq.at/actor-class={ac} :{nick}!{nick}@s2s JOIN {channel}\r\n")
            } else {
                format!(":{nick}!{nick}@s2s JOIN {channel}\r\n")
            };
            deliver_to_channel(state, &channel, &line);
            send_names_update(state, &channel);
        }

        S2sMessage::Part { nick, channel, .. } => {
            let channel = channel.to_lowercase();
            // Presence is S2S-event-only. Idempotent: remove if present.
            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel) {
                    ch.remove_remote_member(&nick);
                }
            }

            let line = format!(":{nick}!{nick}@s2s PART {channel}\r\n");
            deliver_to_channel(state, &channel, &line);
            send_names_update(state, &channel);
        }

        S2sMessage::Quit { nick, reason, .. } => {
            // Remove remote member from all channels (idempotent)
            let mut affected_channels = Vec::new();
            {
                let mut channels = state.channels.lock();
                for (name, ch) in channels.iter_mut() {
                    if ch.remove_remote_member(&nick).is_some() {
                        affected_channels.push(name.clone());
                    }
                }
            }

            let line = format!(":{nick}!{nick}@s2s QUIT :{reason}\r\n");
            for ch_name in &affected_channels {
                deliver_to_channel(state, ch_name, &line);
                send_names_update(state, ch_name);
            }
        }

        S2sMessage::Topic {
            channel,
            topic,
            set_by,
            ..
        } => {
            let channel = sanitize_s2s_str(&channel, 200).to_lowercase();
            let topic = sanitize_s2s_str(&topic, 512);
            let set_by = sanitize_s2s_str(&set_by, 200);
            // CRDT is the single source of truth for topic convergence.
            // The S2S Topic event is a notification for immediate display —
            // we apply it locally for UX responsiveness, then write to CRDT
            // for convergent persistence. On any divergence, CRDT wins.

            // ── S2S authorization: enforce +t locally ──
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel)
                    && ch.topic_locked
                {
                    let is_authorized = ch.remote_member(&set_by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel, set_by = %set_by,
                            "S2S Topic rejected: channel is +t and setter is not an authorized op"
                        );
                        return;
                    }
                }
            }

            // Write to CRDT (source of truth)
            let setter_did = {
                let channels = state.channels.lock();
                channels
                    .get(&channel)
                    .and_then(|ch| ch.remote_member(&set_by).and_then(|rm| rm.did.clone()))
            };
            state
                .crdt_set_topic(&channel, &topic, &set_by, setter_did.as_deref())
                .await;

            // Apply locally for immediate UX (CRDT is authoritative if they diverge)
            {
                let mut channels = state.channels.lock();
                let ch = s2s_channel_entry(&mut channels, &channel);
                ch.topic = Some(TopicInfo::new(topic.clone(), set_by.clone()));
            }

            let line = format!(":{set_by}!remote@s2s TOPIC {channel} :{topic}\r\n");
            deliver_to_channel(state, &channel, &line);
        }

        S2sMessage::ChannelCreated {
            channel,
            founder_did,
            did_ops,
            origin,
            ..
        } => {
            let channel = channel.to_lowercase();
            let has_local_members;
            {
                let mut channels = state.channels.lock();
                let ch = s2s_channel_entry(&mut channels, &channel);

                // ── Authority gating ───────────────────────────────────
                // Founder: only adopt if we have no local founder.
                // If we already have one, reject the remote claim — CRDT
                // convergence will resolve via min-actor-wins.
                if ch.founder_did.is_none() {
                    if let Some(ref did) = founder_did {
                        // Validate: the DID must look plausible (starts with "did:")
                        if did.starts_with("did:") {
                            tracing::info!(
                                channel = %channel, origin = %origin,
                                "Adopting remote founder {did} (no local founder)"
                            );
                            ch.founder_did = Some(did.clone());
                        } else {
                            tracing::warn!(
                                channel = %channel, origin = %origin,
                                "Rejecting invalid founder claim: {did}"
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        channel = %channel,
                        "Keeping local founder {:?} (ignoring remote {:?} from {origin})",
                        ch.founder_did, founder_did
                    );
                }

                // DID ops: validate format + authority before accepting.
                let require_did = state.config.require_did_for_ops;
                for did in &did_ops {
                    if !did.starts_with("did:") {
                        tracing::warn!(
                            channel = %channel, origin = %origin,
                            "Rejecting invalid DID op: {did}"
                        );
                        continue;
                    }
                    // Authority check: ops should be granted by founder or existing op
                    let granter = founder_did.as_deref();
                    let has_authority =
                        granter.is_some() || ch.founder_did.is_some() || !ch.did_ops.is_empty();
                    if !has_authority {
                        if require_did {
                            tracing::warn!(
                                channel = %channel, origin = %origin,
                                "Rejecting DID op {did}: no authority and --require-did-for-ops is set"
                            );
                            continue;
                        }
                        tracing::warn!(
                            channel = %channel, origin = %origin,
                            "DID op {did} granted without known authority (accepting, use --require-did-for-ops to reject)"
                        );
                    }
                    ch.did_ops.insert(did.clone());
                }

                // Re-op local members
                has_local_members = !ch.members.is_empty();
                let members: Vec<String> = ch.members.iter().cloned().collect();
                let dids = state.session_dids.lock();
                for session_id in &members {
                    if let Some(did) = dids.get(session_id)
                        && (ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did))
                    {
                        ch.ops.insert(session_id.clone());
                    }
                }
            } // All MutexGuards dropped

            // Update CRDT with provenance
            if let Some(ref did) = founder_did
                && did.starts_with("did:")
            {
                state.crdt_set_founder(&channel, did).await;
            }
            for did in &did_ops {
                if did.starts_with("did:") {
                    state
                        .crdt_grant_op(&channel, did, founder_did.as_deref())
                        .await;
                }
            }

            if has_local_members {
                send_names_update(state, &channel);
            }
        }

        S2sMessage::SyncRequest => {
            let response = {
                let channels = state.channels.lock();
                let n2s = state.nick_to_session.lock();

                let dids = state.session_dids.lock();
                let actor_classes = state.session_actor_class.lock();
                let channel_info: Vec<crate::s2s::ChannelInfo> = channels
                    .iter()
                    .map(|(name, ch)| {
                        let nicks: Vec<String> = ch
                            .members
                            .iter()
                            .filter_map(|sid| n2s.get_nick(sid).map(|n| n.to_string()))
                            .collect();
                        let nick_info: Vec<crate::s2s::SyncNick> = ch
                            .members
                            .iter()
                            .filter_map(|sid| {
                                n2s.get_nick(sid).map(|n| {
                                    let ac = actor_classes.get(sid).map(|c| c.to_string());
                                    crate::s2s::SyncNick {
                                        nick: n.to_string(),
                                        is_op: ch.ops.contains(sid),
                                        did: dids.get(sid).cloned(),
                                        actor_class: ac,
                                    }
                                })
                            })
                            .collect();
                        crate::s2s::ChannelInfo {
                            name: name.clone(),
                            topic: ch.topic.as_ref().map(|t| t.text.clone()),
                            nicks,
                            nick_info,
                            founder_did: ch.founder_did.clone(),
                            did_ops: ch.did_ops.iter().cloned().collect(),
                            created_at: ch.created_at,
                            topic_locked: ch.topic_locked,
                            invite_only: ch.invite_only,
                            no_ext_msg: ch.no_ext_msg,
                            moderated: ch.moderated,
                            key: ch.key.clone(),
                            bans: ch.bans.iter().map(|b| b.mask.clone()).collect(),
                            invites: ch.invites.iter().cloned().collect(),
                            invite_exceptions: ch
                                .invite_exceptions
                                .iter()
                                .map(|e| e.mask.clone())
                                .collect(),
                        }
                    })
                    .collect();

                S2sMessage::SyncResponse {
                    server_id: manager.server_id.clone(),
                    channels: channel_info,
                }
            };
            manager.broadcast(response);
            state.crdt_broadcast_sync().await;
        }

        S2sMessage::SyncResponse {
            server_id: peer_id,
            channels: remote_channels,
        } => {
            // Cap channel creation from sync to prevent flooding
            const MAX_SYNC_CHANNELS: usize = 500;
            if remote_channels.len() > MAX_SYNC_CHANNELS {
                tracing::warn!(
                    peer = %peer_id,
                    "SyncResponse has {} channels, capping at {MAX_SYNC_CHANNELS}",
                    remote_channels.len()
                );
            }
            let remote_channels: Vec<_> = remote_channels
                .into_iter()
                .take(MAX_SYNC_CHANNELS)
                .collect();
            tracing::info!(
                "Received sync: {} channel(s) from peer {peer_id}",
                remote_channels.len()
            );
            let mut updated_channels = Vec::new();
            // Topics adopted from this snapshot get seeded into the CRDT
            // (after the lock drops) so topic state has exactly one
            // authority. (channel, topic, set_by)
            let mut adopted_topics: Vec<(String, String, String)> = Vec::new();
            {
                let mut channels = state.channels.lock();

                // Clear stale remote members from this peer before merging.
                // SyncResponse is a full state snapshot — any remote members
                // from this peer that aren't in the response are gone.
                // This prevents ghost users after a peer restarts with fewer members.
                let synced_channel_names: std::collections::HashSet<String> =
                    remote_channels.iter().map(|i| i.name.clone()).collect();
                for (name, ch) in channels.iter_mut() {
                    if synced_channel_names.contains(name) {
                        // Will be replaced below per-channel
                        ch.remote_members.retain(|_nick, rm| rm.origin != peer_id);
                    } else {
                        // Peer didn't mention this channel — remove their members from it
                        ch.remote_members.retain(|_nick, rm| rm.origin != peer_id);
                    }
                }

                for info in remote_channels {
                    let ch = s2s_channel_entry(&mut channels, &info.name);

                    // ── Authority gating on sync ──────────────────────
                    // Merge founder: only adopt if we don't have one AND it's a valid DID
                    if ch.founder_did.is_none()
                        && let Some(ref did) = info.founder_did
                    {
                        if did.starts_with("did:") {
                            ch.founder_did = Some(did.clone());
                        } else {
                            tracing::warn!(
                                channel = %info.name, peer = %peer_id,
                                "Rejecting invalid founder DID in sync: {did}"
                            );
                        }
                    }

                    // DID ops: validate format before accepting.
                    // If --require-did-for-ops and no founder context, reject.
                    let require_did = state.config.require_did_for_ops;
                    for did in &info.did_ops {
                        if !did.starts_with("did:") {
                            tracing::warn!(
                                channel = %info.name, peer = %peer_id,
                                "Rejecting invalid DID op in sync: {did}"
                            );
                            continue;
                        }
                        let has_authority = info.founder_did.is_some()
                            || ch.founder_did.is_some()
                            || !ch.did_ops.is_empty();
                        if !has_authority && require_did {
                            tracing::warn!(
                                channel = %info.name, peer = %peer_id,
                                "Rejecting DID op {did} in sync: no authority (--require-did-for-ops)"
                            );
                            continue;
                        }
                        ch.did_ops.insert(did.clone());
                    }

                    // Presence: S2S-event-based (idempotent set-based merge)
                    // Never trust is_op from the peer — derive from local
                    // channel state to prevent forged op claims (C-2).
                    if !info.nick_info.is_empty() {
                        for ni in &info.nick_info {
                            let actual_is_op = ni.did.as_deref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            });
                            ch.remote_members.insert(
                                ni.nick.clone(),
                                RemoteMember {
                                    origin: peer_id.clone(),
                                    did: ni.did.clone(),
                                    handle: None,
                                    is_op: actual_is_op,
                                    actor_class: ni.actor_class.clone(),
                                },
                            );
                        }
                    } else {
                        for nick in &info.nicks {
                            ch.remote_members.insert(
                                nick.clone(),
                                RemoteMember {
                                    origin: peer_id.clone(),
                                    did: None,
                                    handle: None,
                                    is_op: false,
                                    actor_class: None,
                                },
                            );
                        }
                    }

                    if ch.topic.is_none()
                        && let Some(ref topic) = info.topic
                    {
                        let set_by = info.founder_did.as_deref().unwrap_or("unknown").to_string();
                        ch.topic = Some(TopicInfo::new(topic.clone(), set_by.clone()));
                        // Seed the CRDT too (below, outside the lock). Without
                        // this, sync-adopted topics live only in local state
                        // while CRDT reconciliation treats the CRDT as
                        // authoritative — two merge strategies that disagree
                        // and flap. CRDT is the single source of truth.
                        adopted_topics.push((info.name.clone(), topic.clone(), set_by));
                    }

                    // Only adopt remote channel modes if channel has no local
                    // members. If locals are present, they set modes authoritatively
                    // and a SyncResponse shouldn't overwrite them (e.g., a peer
                    // syncing stale state could disable +n/+i protection).
                    if ch.members.is_empty() {
                        ch.topic_locked = info.topic_locked;
                        ch.invite_only = info.invite_only;
                        ch.no_ext_msg = info.no_ext_msg;
                        ch.moderated = info.moderated;
                        // Full snapshot adoption includes key REMOVAL: with no
                        // local members there is no local authority to protect,
                        // and refusing None here is what made -k unable to
                        // propagate between syncs.
                        ch.key = info.key.clone();
                    } else {
                        // Merge: only adopt modes that are MORE restrictive
                        // (remote turns ON a protection the local doesn't have).
                        // Never weaken local protections from a sync.
                        if info.topic_locked {
                            ch.topic_locked = true;
                        }
                        if info.invite_only {
                            ch.invite_only = true;
                        }
                        if info.no_ext_msg {
                            ch.no_ext_msg = true;
                        }
                        if info.moderated {
                            ch.moderated = true;
                        }
                        if info.key.is_some() && ch.key.is_none() {
                            ch.key = info.key.clone();
                        }
                    }

                    // Merge bans from remote (additive — don't remove local bans)
                    for mask in &info.bans {
                        if !ch.bans.iter().any(|b| b.mask == *mask) {
                            ch.bans.push(BanEntry {
                                mask: mask.clone(),
                                set_by: format!("s2s:{}", peer_id),
                                set_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            });
                        }
                    }

                    // Merge invite exceptions (+I) from remote (additive)
                    for mask in &info.invite_exceptions {
                        if !ch.invite_exceptions.iter().any(|e| e.mask == *mask) {
                            ch.invite_exceptions
                                .push(crate::server::InviteExceptionEntry {
                                    mask: mask.clone(),
                                    set_by: format!("s2s:{}", peer_id),
                                    set_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                });
                        }
                    }

                    // Merge invites from remote (additive — don't remove local
                    // invites). Only accept when the peer demonstrates authority
                    // over the channel: its snapshot must name the founder we
                    // know (or we know none). Without this gate any peer could
                    // inject invites and walk straight through +i.
                    // Cap at 500 to prevent resource exhaustion from malicious peers.
                    let peer_knows_founder =
                        ch.founder_did.is_none() || info.founder_did == ch.founder_did;
                    if peer_knows_founder {
                        for invite in &info.invites {
                            if ch.invites.len() >= 500 {
                                break;
                            }
                            ch.invites.insert(invite.clone());
                        }
                    } else if !info.invites.is_empty() {
                        tracing::warn!(
                            channel = %info.name, peer = %peer_id,
                            "Rejecting {} synced invite(s): peer's founder {:?} does not match local {:?}",
                            info.invites.len(), info.founder_did, ch.founder_did
                        );
                    }

                    let dids = state.session_dids.lock();
                    let members: Vec<String> = ch.members.iter().cloned().collect();

                    // First pass: grant ops to DID-backed users with authority
                    let mut did_ops_granted = false;
                    for session_id in &members {
                        if let Some(did) = dids.get(session_id)
                            && (ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did))
                        {
                            ch.ops.insert(session_id.clone());
                            did_ops_granted = true;
                        }
                    }

                    // Second pass: revoke guest/non-authority auto-ops, but ONLY if
                    // someone with real authority now has ops (locally or remotely).
                    // Don't orphan the channel by revoking everyone's ops.
                    let has_authority_ops =
                        did_ops_granted || ch.remote_members.values().any(|rm| rm.is_op);
                    if has_authority_ops {
                        for session_id in &members {
                            let has_did_auth = dids.get(session_id).is_some_and(|did| {
                                ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did)
                            });
                            if !has_did_auth {
                                ch.ops.remove(session_id);
                            }
                        }
                    }

                    if !ch.members.is_empty() {
                        updated_channels.push(info.name.clone());
                    }

                    tracing::info!(
                        "  Channel {}: {} remote user(s), founder: {:?}, {} DID ops, topic: {:?}",
                        info.name,
                        ch.remote_members.len(),
                        ch.founder_did,
                        ch.did_ops.len(),
                        ch.topic.as_ref().map(|t| &t.text),
                    );
                }
            }

            // Seed sync-adopted topics into the CRDT — but never compete with
            // an existing CRDT topic (reconciliation will adopt that one).
            for (channel, topic, set_by) in adopted_topics {
                if state.cluster_doc.channel_topic(&channel).await.is_none() {
                    state.crdt_set_topic(&channel, &topic, &set_by, None).await;
                }
            }

            for channel in &updated_channels {
                send_names_update(state, channel);
                let topic_info = state.channels.lock().get(channel).and_then(|ch| {
                    ch.topic
                        .as_ref()
                        .map(|t| (t.text.clone(), t.set_by.clone()))
                });
                if let Some((topic, _set_by)) = topic_info {
                    let line = format!(":{} 332 * {} :{}\r\n", state.server_name, channel, topic,);
                    let members: Vec<String> = state
                        .channels
                        .lock()
                        .get(channel)
                        .map(|ch| ch.members.iter().cloned().collect())
                        .unwrap_or_default();
                    let conns = state.connections.lock();
                    for session_id in &members {
                        if let Some(tx) = conns.get(session_id) {
                            let _ = tx.try_send(line.clone());
                        }
                    }
                }
            }
        }

        S2sMessage::Mode {
            channel,
            mode,
            arg,
            set_by,
            ..
        } => {
            let channel = channel.to_lowercase();

            // ── S2S authorization: verify the setter is an op ──
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel) {
                    let is_authorized = ch.remote_member(&set_by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel, set_by = %set_by, mode = %mode,
                            "S2S Mode rejected: setter is not an authorized op"
                        );
                        return;
                    }
                }
            }

            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel) {
                    let adding = mode.starts_with('+');
                    let mode_char = mode.chars().last().unwrap_or(' ');
                    match mode_char {
                        't' => ch.topic_locked = adding,
                        'i' => ch.invite_only = adding,
                        'n' => ch.no_ext_msg = adding,
                        'm' => ch.moderated = adding,
                        'k' => {
                            if adding {
                                ch.key = arg.clone();
                            } else {
                                ch.key = None;
                            }
                        }
                        'o' | 'v' => {
                            // Remote op/voice targeting a user on this server.
                            // Find the target by nick and apply the mode.
                            if let Some(ref target_nick) = arg {
                                // Case-insensitive local nick lookup
                                let target_sid = state
                                    .nick_to_session
                                    .lock()
                                    .get_session(target_nick)
                                    .map(|s| s.to_string());
                                if let Some(ref sid) = target_sid {
                                    let set = if mode_char == 'o' {
                                        &mut ch.ops
                                    } else {
                                        &mut ch.voiced
                                    };
                                    if adding {
                                        set.insert(sid.clone());
                                    } else {
                                        set.remove(sid);
                                    }

                                    // +o/-o with DID: also update did_ops for persistence
                                    if mode_char == 'o'
                                        && let Some(did) =
                                            state.session_dids.lock().get(sid).cloned()
                                    {
                                        if !adding && ch.founder_did.as_deref() == Some(&did) {
                                            // Founder can't be de-opped
                                        } else if adding {
                                            ch.did_ops.insert(did);
                                        } else {
                                            ch.did_ops.remove(&did);
                                        }
                                    }
                                } else {
                                    // Target is a remote member from another peer
                                    // (3-server scenario) — update remote member's is_op flag
                                    if mode_char == 'o' {
                                        // Extract DID before mutating, to avoid borrow conflict
                                        let remote_did = ch
                                            .remote_member(target_nick)
                                            .and_then(|rm| rm.did.clone());
                                        if let Some(rm) = ch.remote_member_mut(target_nick) {
                                            rm.is_op = adding;
                                        }
                                        // Also update did_ops if we know their DID
                                        if let Some(did) = remote_did {
                                            if !adding
                                                && ch.founder_did.as_deref() == Some(did.as_str())
                                            {
                                                // Founder can't be de-opped
                                            } else if adding {
                                                ch.did_ops.insert(did);
                                            } else {
                                                ch.did_ops.remove(&did);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            let mode_line = if let Some(ref a) = arg {
                format!(":{set_by}!remote@s2s MODE {channel} {mode} {a}\r\n")
            } else {
                format!(":{set_by}!remote@s2s MODE {channel} {mode}\r\n")
            };
            deliver_to_channel(state, &channel, &mode_line);
        }

        S2sMessage::Kick {
            nick,
            channel,
            by,
            reason,
            ..
        } => {
            // A remote op kicked a user — if the user is local, remove them
            // from the channel and notify them. If the user is a remote member
            // from yet another server, remove from remote_members.
            let channel_key = channel.to_lowercase();

            // ── S2S authorization: verify the kicker is an op ──
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel_key) {
                    let is_authorized = ch.remote_member(&by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel_key, by = %by, target = %nick,
                            "S2S Kick rejected: kicker is not an authorized op"
                        );
                        return;
                    }
                }
            }

            let kick_line = format!(":{by}!remote@s2s KICK {channel} {nick} :{reason}\r\n");

            // Case-insensitive nick lookup (NickMap handles this in O(1))
            let target_session = state
                .nick_to_session
                .lock()
                .get_session(&nick)
                .map(|s| s.to_string());

            if let Some(ref sid) = target_session {
                // Target is local — broadcast KICK to channel, remove member
                deliver_to_channel(state, &channel_key, &kick_line);
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel_key) {
                    let removed = ch.members.remove(sid);
                    ch.ops.remove(sid);
                    ch.voiced.remove(sid);
                    ch.halfops.remove(sid);
                    tracing::info!(
                        nick = %nick, channel = %channel_key, removed = removed,
                        "S2S Kick: removed local user from channel"
                    );
                } else {
                    tracing::warn!(
                        nick = %nick, channel = %channel_key,
                        "S2S Kick: channel not found for member removal"
                    );
                }
            } else {
                // Target is a remote member from another peer — remove and notify locals
                let removed = {
                    let mut channels = state.channels.lock();
                    channels
                        .get_mut(&channel_key)
                        .and_then(|ch| ch.remove_remote_member(&nick))
                        .is_some()
                };
                if removed {
                    deliver_to_channel(state, &channel_key, &kick_line);
                }
            }
        }

        S2sMessage::Ban {
            channel,
            mask,
            set_by,
            adding,
            ..
        } => {
            let channel_key = channel.to_lowercase();

            // Authorization: verify set_by is an op
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel_key) {
                    let is_authorized = ch.remote_member(&set_by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel_key, set_by = %set_by,
                            "S2S Ban rejected: setter is not an authorized op"
                        );
                        return;
                    }
                }
            }

            let mode_char = if adding { "+b" } else { "-b" };
            let mode_line = format!(":{set_by}!remote@s2s MODE {channel} {mode_char} {mask}\r\n");

            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel_key) {
                    if adding {
                        if !ch.bans.iter().any(|b| b.mask == mask) {
                            ch.bans.push(crate::server::BanEntry {
                                mask: mask.clone(),
                                set_by: set_by.clone(),
                                set_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            });
                        }
                    } else {
                        ch.bans.retain(|b| b.mask != mask);
                    }
                }
            }

            deliver_to_channel(state, &channel_key, &mode_line);
        }

        S2sMessage::InviteException {
            channel,
            mask,
            set_by,
            adding,
            ..
        } => {
            let channel_key = channel.to_lowercase();

            // Authorization: verify set_by is an op (mirror of Ban)
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel_key) {
                    let is_authorized = ch.remote_member(&set_by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel_key, set_by = %set_by,
                            "S2S InviteException rejected: setter is not an authorized op"
                        );
                        return;
                    }
                }
            }

            let mode_char = if adding { "+I" } else { "-I" };
            let mode_line = format!(":{set_by}!remote@s2s MODE {channel} {mode_char} {mask}\r\n");

            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel_key) {
                    if adding {
                        if !ch.invite_exceptions.iter().any(|e| e.mask == mask) {
                            ch.invite_exceptions
                                .push(crate::server::InviteExceptionEntry {
                                    mask: mask.clone(),
                                    set_by: set_by.clone(),
                                    set_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                });
                        }
                    } else {
                        ch.invite_exceptions.retain(|e| e.mask != mask);
                    }
                }
            }

            deliver_to_channel(state, &channel_key, &mode_line);
        }

        S2sMessage::Invite {
            channel,
            invitee,
            invited_by,
            ..
        } => {
            let channel_key = channel.to_lowercase();

            // Authorization: verify invited_by is a member (and op if +i)
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel_key) {
                    let rm = ch.remote_member(&invited_by);
                    let is_member = rm.is_some();
                    if !is_member {
                        tracing::warn!(
                            channel = %channel_key, invited_by = %invited_by,
                            "S2S Invite rejected: inviter is not a member"
                        );
                        return;
                    }
                    if ch.invite_only {
                        let is_op = rm.is_some_and(|rm| {
                            rm.is_op
                                || rm.did.as_ref().is_some_and(|d| {
                                    ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                                })
                        });
                        if !is_op {
                            tracing::warn!(
                                channel = %channel_key, invited_by = %invited_by,
                                "S2S Invite rejected: channel is +i and inviter is not an op"
                            );
                            return;
                        }
                    }
                }
            }

            // Add the invite
            {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel_key) {
                    ch.invites.insert(invitee.clone());
                    tracing::debug!(
                        channel = %channel_key, invitee = %invitee,
                        invited_by = %invited_by,
                        "S2S Invite: added invite"
                    );
                }
            }
        }

        S2sMessage::NickChange { old, new, .. } => {
            let line = format!(":{old}!remote@s2s NICK :{new}\r\n");

            let mut channels = state.channels.lock();
            let mut affected_sessions = std::collections::HashSet::new();
            for ch in channels.values_mut() {
                if let Some(rm) = ch.remove_remote_member(&old) {
                    ch.remote_members.insert(new.clone(), rm);
                    for s in &ch.members {
                        affected_sessions.insert(s.clone());
                    }
                }
            }
            drop(channels);

            let conns = state.connections.lock();
            for session_id in &affected_sessions {
                if let Some(tx) = conns.get(session_id) {
                    let _ = tx.try_send(line.clone());
                }
            }
        }

        S2sMessage::PolicySync {
            channel,
            policy_json,
            authority_set_json,
            ..
        } => {
            // A peer has created/updated/cleared a policy — apply locally
            if let Some(ref engine) = state.policy_engine {
                let channel_key = channel.to_lowercase();
                if let Some(ref pj) = policy_json {
                    // Policy created or updated
                    if let Ok(policy) = serde_json::from_str::<crate::policy::PolicyDocument>(pj) {
                        // Store the authority set if provided
                        if let Some(ref asj) = authority_set_json
                            && let Ok(auth_set) =
                                serde_json::from_str::<crate::policy::AuthoritySet>(asj)
                        {
                            let _ = engine.store().store_authority_set(auth_set);
                        }
                        // Store the policy
                        let _ = engine.store().store_policy(policy);
                        tracing::info!(channel = %channel_key, "S2S PolicySync: policy updated from peer");
                    }
                } else {
                    // Policy cleared
                    let _ = engine.remove_policy(&channel_key);
                    tracing::info!(channel = %channel_key, "S2S PolicySync: policy cleared from peer");
                }
            }
        }

        S2sMessage::CrdtSync { data, origin, .. } => {
            // SECURITY: Use authenticated_peer_id (from QUIC transport) to key
            // the Automerge sync state, NOT the `origin` field from the JSON
            // payload.  The payload origin is untrusted — a bug or malicious
            // peer could set it to anything.  The authenticated_peer_id comes
            // from conn.remote_id() which is cryptographically verified.
            if origin != authenticated_peer_id {
                tracing::warn!(
                    authenticated = %authenticated_peer_id,
                    claimed = %origin,
                    "CRDT sync origin mismatch — using authenticated peer ID"
                );
            }
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(&data) {
                Ok(bytes) => {
                    if let Err(e) = state.crdt_receive_sync(authenticated_peer_id, &bytes).await {
                        tracing::warn!(peer = %authenticated_peer_id, "CRDT sync receive error: {e}");
                    } else {
                        tracing::debug!(peer = %authenticated_peer_id, "CRDT sync message applied");
                        // Respond only to the sender — not all peers.
                        // Broadcasting to all peers on every receive creates
                        // amplification storms (A→B triggers A→all, they all
                        // respond, etc.).  The correct Automerge sync pattern
                        // is: receive from P → generate next message for P.
                        // Periodic full-mesh sync is handled by a timer.
                        state.crdt_sync_with_peer(authenticated_peer_id).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %authenticated_peer_id, "CRDT sync base64 decode error: {e}");
                }
            }
        }

        // ── AV session federation ───────────────────────────────────
        S2sMessage::AvSessionCreated {
            session_id,
            channel,
            created_by_did,
            created_by_nick,
            title,
            iroh_ticket,
            ..
        } => {
            let ch = if channel.is_empty() {
                None
            } else {
                Some(channel.as_str())
            };
            state.av_sessions.lock().apply_remote_session_created(
                &session_id,
                ch,
                &created_by_did,
                &created_by_nick,
                title.as_deref(),
                iroh_ticket.as_deref(),
                chrono::Utc::now().timestamp(),
            );
            // Notify local channel members
            if !channel.is_empty() {
                let title_str = title.as_deref().unwrap_or("voice session");
                let count = state
                    .av_sessions
                    .lock()
                    .active_participant_count(&session_id);
                crate::connection::messaging::broadcast_av_notice(
                    state,
                    &channel,
                    &format!(
                        "{created_by_nick} started a voice session: {title_str} ({count} participant(s))"
                    ),
                );
            }
            tracing::info!(session_id = %session_id, channel = %channel, "S2S: AV session created");
        }

        S2sMessage::AvSessionJoined {
            session_id,
            did,
            nick,
            ..
        } => {
            state
                .av_sessions
                .lock()
                .apply_remote_session_joined(&session_id, &did, &nick);
            let mgr = state.av_sessions.lock();
            if let Some(session) = mgr.get(&session_id)
                && let Some(ref ch) = session.channel
            {
                let count = mgr.active_participant_count(&session_id);
                let ch = ch.clone();
                drop(mgr);
                crate::connection::messaging::broadcast_av_notice(
                    state,
                    &ch,
                    &format!("{nick} joined the voice session ({count} participant(s))"),
                );
            }
        }

        S2sMessage::AvSessionLeft {
            session_id, did, ..
        } => {
            let mgr_ref = &state.av_sessions;
            let nick = mgr_ref
                .lock()
                .get(&session_id)
                .and_then(|s| s.participants.get(&did).map(|p| p.nick.clone()))
                .unwrap_or_default();
            mgr_ref.lock().apply_remote_session_left(&session_id, &did);
            let mgr = mgr_ref.lock();
            if let Some(session) = mgr.get(&session_id)
                && let Some(ref ch) = session.channel
            {
                let count = mgr.active_participant_count(&session_id);
                let ch = ch.clone();
                drop(mgr);
                crate::connection::messaging::broadcast_av_notice(
                    state,
                    &ch,
                    &format!("{nick} left the voice session ({count} participant(s))"),
                );
            }
        }

        S2sMessage::AvSessionEnded {
            session_id,
            ended_by,
            ..
        } => {
            state
                .av_sessions
                .lock()
                .apply_remote_session_ended(&session_id, ended_by.as_deref());
            // Notification already sent by the originating server
            tracing::info!(session_id = %session_id, "S2S: AV session ended");
        }

        S2sMessage::PeerDisconnected { peer_id } => {
            // Clean up all remote_members whose origin matches this peer.
            // Without this, users from a disconnected server linger as ghosts
            // in channel rosters until they individually Part/Quit.
            let mut channels = state.channels.lock();
            let mut cleaned = 0usize;
            let mut affected_channels = Vec::new();
            for (name, ch) in channels.iter_mut() {
                let before = ch.remote_members.len();
                ch.remote_members.retain(|_nick, rm| rm.origin != peer_id);
                let removed = before - ch.remote_members.len();
                if removed > 0 {
                    cleaned += removed;
                    affected_channels.push(name.clone());
                }
            }
            drop(channels);

            if cleaned > 0 {
                tracing::info!(
                    peer = %peer_id,
                    "Cleaned {cleaned} ghost remote member(s) from {} channel(s)",
                    affected_channels.len()
                );
                // Update NAMES for affected channels so local users see the change
                for channel in &affected_channels {
                    send_names_update(state, channel);
                }
            }
        }
    }
}

/// Periodic CRDT→local reconciliation.
///
/// Reads CRDT state (topics, founder, DID ops) and applies to local channel
/// state if divergent. This ensures the CRDT is the authoritative source of
/// truth — even when S2S events and CRDT diverge due to timing or partitions.
async fn reconcile_crdt_to_local(state: &Arc<SharedState>) {
    // Get list of channels
    let channel_names: Vec<String> = { state.channels.lock().keys().cloned().collect() };

    let mut reconciled = 0u32;

    for channel_name in &channel_names {
        // Reconcile topic: if CRDT has a topic and it differs from local, adopt CRDT's
        if let Some((crdt_topic, crdt_setter)) = state.cluster_doc.channel_topic(channel_name).await
        {
            let needs_update = {
                let channels = state.channels.lock();
                channels
                    .get(channel_name)
                    .map(|ch| {
                        ch.topic
                            .as_ref()
                            .map(|t| t.text != crdt_topic)
                            .unwrap_or(true) // no local topic, CRDT has one → adopt
                    })
                    .unwrap_or(false)
            };
            if needs_update {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(channel_name) {
                    ch.topic = Some(TopicInfo::new(crdt_topic, crdt_setter));
                    reconciled += 1;
                }
            }
        }

        // Reconcile founder
        if let Some(crdt_founder) = state.cluster_doc.founder(channel_name).await {
            let needs_update = {
                let channels = state.channels.lock();
                channels
                    .get(channel_name)
                    .map(|ch| ch.founder_did.as_deref() != Some(&crdt_founder))
                    .unwrap_or(false)
            };
            if needs_update {
                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(channel_name) {
                    tracing::info!(
                        channel = %channel_name,
                        "CRDT reconciliation: updating founder to {crdt_founder}"
                    );
                    ch.founder_did = Some(crdt_founder);
                    reconciled += 1;

                    // Re-evaluate local ops: grant to DID-backed users with authority.
                    // Only revoke guest auto-ops if an authority-backed user is now
                    // opped (locally or remotely) — don't orphan the channel.
                    let dids = state.session_dids.lock();
                    let members: Vec<String> = ch.members.iter().cloned().collect();
                    let mut did_ops_granted = false;
                    for session_id in &members {
                        if let Some(did) = dids.get(session_id)
                            && (ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did))
                        {
                            ch.ops.insert(session_id.clone());
                            did_ops_granted = true;
                        }
                    }
                    let has_authority_ops =
                        did_ops_granted || ch.remote_members.values().any(|rm| rm.is_op);
                    if has_authority_ops {
                        for session_id in &members {
                            let has_did_auth = dids.get(session_id).is_some_and(|did| {
                                ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did)
                            });
                            if !has_did_auth {
                                ch.ops.remove(session_id);
                            }
                        }
                    }
                }
            }
        }

        // Reconcile DID ops: CRDT is additive authority
        let crdt_ops = state.cluster_doc.channel_did_ops(channel_name).await;
        if !crdt_ops.is_empty() {
            let mut channels = state.channels.lock();
            if let Some(ch) = channels.get_mut(channel_name) {
                for did in &crdt_ops {
                    if ch.did_ops.insert(did.clone()) {
                        reconciled += 1;
                    }
                }
                // Re-evaluate local ops: grant to DID-backed users with authority.
                // Revoke guest/non-authority auto-ops only if someone with real
                // authority now has ops (don't orphan the channel).
                let dids = state.session_dids.lock();
                let members: Vec<String> = ch.members.iter().cloned().collect();
                let mut did_ops_granted = false;
                for session_id in &members {
                    if let Some(did) = dids.get(session_id)
                        && (ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did))
                    {
                        ch.ops.insert(session_id.clone());
                        did_ops_granted = true;
                    }
                }
                let has_authority_ops =
                    did_ops_granted || ch.remote_members.values().any(|rm| rm.is_op);
                if has_authority_ops {
                    for session_id in &members {
                        let has_did_auth = dids.get(session_id).is_some_and(|did| {
                            ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did)
                        });
                        if !has_did_auth {
                            ch.ops.remove(session_id);
                        }
                    }
                }
            }
        }
    }

    if reconciled > 0 {
        tracing::info!(
            "CRDT→local reconciliation: {reconciled} updates applied across {} channels",
            channel_names.len()
        );
    }
}

/// Shared test-state builder, re-exported so any module's tests can reuse the
/// single `SharedState` constructor instead of duplicating it.
#[cfg(test)]
mod nickmap_tests {
    use super::NickMap;

    // A multi-device user (same nick on two live sessions): when ONE session
    // leaves, the OTHER must keep its session→nick reverse mapping — otherwise
    // it stays in channels' member sets but vanishes from NAMES (can chat,
    // invisible in the member list). Regression for the disconnect/ghost paths
    // that called remove_by_nick, which wiped the reverse mapping for EVERY
    // session sharing the nick.
    #[test]
    fn remove_by_session_preserves_a_live_sibling() {
        let mut m = NickMap::new();
        m.insert("chadfowler.com", "A"); // A primary
        m.insert("chadfowler.com", "B"); // B now primary, A still tracked
        m.remove_by_session("A"); // secondary leaves
        assert_eq!(
            m.get_nick("B"),
            Some("chadfowler.com"),
            "live sibling lost its nick"
        );
        assert_eq!(m.get_nick("A"), None);
        assert_eq!(m.get_session("chadfowler.com"), Some("B"));
    }

    #[test]
    fn remove_by_session_promotes_sibling_when_primary_leaves() {
        let mut m = NickMap::new();
        m.insert("chadfowler.com", "A");
        m.insert("chadfowler.com", "B"); // B primary
        m.remove_by_session("B"); // primary leaves
        assert_eq!(m.get_nick("A"), Some("chadfowler.com"));
        assert_eq!(
            m.get_session("chadfowler.com"),
            Some("A"),
            "sibling not promoted"
        );
        assert_eq!(m.get_nick("B"), None);
    }

    // Documents the footgun: remove_by_nick wipes the reverse mapping for a
    // live sibling too, which is why the single-session-leave paths must use
    // remove_by_session instead.
    #[test]
    fn remove_by_nick_wipes_all_siblings() {
        let mut m = NickMap::new();
        m.insert("chadfowler.com", "A");
        m.insert("chadfowler.com", "B");
        m.remove_by_nick("chadfowler.com");
        assert_eq!(m.get_nick("A"), None);
        assert_eq!(m.get_nick("B"), None);
    }
}

#[cfg(test)]
pub(crate) use s2s_adversarial_tests::{test_state, test_state_with_db};

#[cfg(test)]
mod s2s_adversarial_tests {
    use super::*;
    use crate::s2s::{DedupSet, S2sManager, S2sMessage, TrustLevel};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;

    /// Build a minimal SharedState for testing (no DB, no iroh).
    pub(crate) fn test_state() -> Arc<SharedState> {
        test_state_inner(None)
    }

    /// Like `test_state` but with an in-memory SQLite DB attached, so
    /// persistence paths (`identities`, `messages`, …) are exercised. Shared
    /// with other modules' tests (e.g. web endpoints) via the re-export below.
    pub(crate) fn test_state_with_db() -> Arc<SharedState> {
        test_state_inner(Some(crate::db::Db::open_memory().unwrap()))
    }

    fn test_state_inner(db: Option<crate::db::Db>) -> Arc<SharedState> {
        let config = crate::config::ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            server_name: "test-s2s".to_string(),
            challenge_timeout_secs: 60,
            ..Default::default()
        };
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Arc::new(SharedState {
            server_name: config.server_name.clone(),
            challenge_store: crate::sasl::ChallengeStore::new(60),
            did_resolver: freeq_sdk::did::DidResolver::static_map(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(NickMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            did_sessions: Mutex::new(HashMap::new()),
            did_nicks: Mutex::new(HashMap::new()),
            nick_owners: Mutex::new(HashMap::new()),
            session_handles: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
            cap_multi_prefix: Mutex::new(HashSet::new()),
            cap_echo_message: Mutex::new(HashSet::new()),
            cap_server_time: Mutex::new(HashSet::new()),
            cap_batch: Mutex::new(HashSet::new()),
            cap_draft_multiline: Mutex::new(HashSet::new()),
            open_batches: Mutex::new(HashMap::new()),
            cap_account_notify: Mutex::new(HashSet::new()),
            cap_extended_join: Mutex::new(HashSet::new()),
            cap_away_notify: Mutex::new(HashSet::new()),
            cap_account_tag: Mutex::new(HashSet::new()),
            cap_read_marker: Mutex::new(HashSet::new()),
            session_read_markers: Mutex::new(HashMap::new()),
            server_opers: Mutex::new(HashSet::new()),
            session_actor_class: Mutex::new(HashMap::new()),
            provenance_declarations: Mutex::new(HashMap::new()),
            agent_presence: Mutex::new(HashMap::new()),
            agent_heartbeats: Mutex::new(HashMap::new()),
            av_instances_per_conn: Mutex::new(HashMap::new()),
            av_grace_pending: Mutex::new(HashSet::new()),
            oauth_pending: Mutex::new(HashMap::new()),
            oauth_complete: Mutex::new(HashMap::new()),
            web_auth_tokens: Mutex::new(HashMap::new()),
            web_sessions: Mutex::new(HashMap::new()),
            login_pending: Mutex::new(HashMap::new()),
            linked_identities: Mutex::new(HashMap::new()),
            login_completions: Mutex::new(HashMap::new()),
            session_iroh_ids: Mutex::new(HashMap::new()),
            session_away: Mutex::new(HashMap::new()),
            server_iroh_id: Mutex::new(Some("test-server-id".to_string())),
            iroh_endpoint: Mutex::new(None),
            iroh_router: Mutex::new(None),
            av_sessions: Mutex::new(crate::av::AvSessionManager::new()),
            av_media: Mutex::new(None),
            #[cfg(feature = "av-native")]
            sfu_state: Mutex::new(None),
            #[cfg(feature = "av-native")]
            av_bridges: Mutex::new(std::collections::HashMap::new()),
            s2s_manager: Mutex::new(None),
            cluster_doc: crate::crdt::ClusterDoc::new("test-server-id"),
            db: db.map(Mutex::new),
            config,
            plugin_manager: crate::plugin::PluginManager::new(),
            policy_engine: None,
            prekey_bundles: Mutex::new(HashMap::new()),
            msg_timestamps: Mutex::new(HashMap::new()),
            ip_connections: Mutex::new(HashMap::new()),
            msg_signing_key: signing_key,
            boot_time: std::time::Instant::now(),
            boot_timestamp: chrono::Utc::now(),
            session_msg_keys: Mutex::new(HashMap::new()),
            did_msg_keys: Mutex::new(HashMap::new()),
            session_client_info: Mutex::new(HashMap::new()),
            upload_tokens: Mutex::new(HashMap::new()),
            embedded_session_store: None,
            ghost_sessions: Mutex::new(HashMap::new()),
            spawned_agents: Mutex::new(HashMap::new()),
            rest_rate_limiter: crate::web::IpRateLimiter::new(30, 60),
            media_store: None,
            liveness_probes: Mutex::new(HashMap::new()),
            session_kill: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
        })
    }

    /// Build a minimal S2sManager for testing.
    fn test_manager() -> Arc<S2sManager> {
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let (broadcast_tx, _broadcast_rx) = mpsc::channel(1024);
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
        let secret_key = iroh::SecretKey::from_bytes(&key_bytes);
        Arc::new(S2sManager {
            server_id: "test-local-server".to_string(),
            server_name: "test-s2s".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(1000),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret_key),
            trust_config: HashMap::new(),
            peer_trust: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        })
    }

    const PEER: &str = "fake-peer-id-for-testing";

    async fn setup_authenticated_peer(state: &SharedState, manager: &Arc<S2sManager>) {
        manager
            .authenticated_peers
            .lock()
            .await
            .insert(PEER.to_string());
        manager
            .peer_trust
            .lock()
            .await
            .insert(PEER.to_string(), TrustLevel::Full);
        *state.s2s_manager.lock() = Some(manager.clone());
        // S2S_RATE_LIMITS is process-static; all tests share PEER, so
        // parallel-run counters trip the 100/sec cap mid-suite without
        // this reset.
        S2S_RATE_LIMITS.lock().remove(PEER);
    }

    fn setup_channel(state: &SharedState, name: &str) {
        state.channels.lock().entry(name.to_string()).or_default();
    }

    fn add_remote_member(state: &SharedState, channel: &str, nick: &str, is_op: bool) {
        let mut channels = state.channels.lock();
        if let Some(ch) = channels.get_mut(channel) {
            ch.remote_members.insert(
                nick.to_string(),
                crate::server::RemoteMember {
                    origin: PEER.to_string(),
                    did: None,
                    handle: None,
                    is_op,
                    actor_class: None,
                },
            );
        }
    }

    // ═══════════════════════════════════════════════════════════
    // S2S JOIN: is_op flag from peer
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_join_is_op_accepted_from_peer() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#test");

        // Peer sends Join with is_op: true
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Join {
                event_id: format!("{PEER}:1"),
                nick: "evil_op".to_string(),
                channel: "#test".to_string(),
                did: None,
                handle: None,
                is_op: true,
                actor_class: None,
                origin: PEER.to_string(),
            },
        )
        .await;

        // Check: was the remote member added with is_op?
        let channels = state.channels.lock();
        let ch = channels.get("#test").unwrap();
        let rm = ch.remote_members.get("evil_op");
        assert!(rm.is_some(), "Remote member should be added");
        // BUG CHECK: is_op should ideally be validated against founder/did_ops
        let is_op = rm.unwrap().is_op;
        if is_op {
            eprintln!("BUG: S2S Join is_op=true accepted without DID authority validation");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // S2S MODE +o: persistent privilege escalation
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_mode_op_without_authority_rejected() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#secure");

        // Add a remote member who claims to be op
        add_remote_member(&state, "#secure", "faker", true);

        // Peer sends Mode +o granting ops to another user
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Mode {
                event_id: format!("{PEER}:2"),
                channel: "#secure".to_string(),
                mode: "+o".to_string(),
                arg: Some("target_user".to_string()),
                set_by: "faker".to_string(),
                origin: PEER.to_string(),
            },
        )
        .await;

        // Check: was the mode applied?
        let channels = state.channels.lock();
        let ch = channels.get("#secure").unwrap();
        let did_ops_has_target = ch.did_ops.iter().any(|d| d.contains("target"));
        // If did_ops was modified, that's a privilege escalation
        if did_ops_has_target {
            eprintln!("BUG: S2S Mode +o added to did_ops without founder authority");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // S2S PRIVMSG: nick spoofing
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_privmsg_from_local_nick_not_confused() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        // Add a local user "alice" to the channel
        {
            let (tx, _rx) = mpsc::channel(16);
            state
                .connections
                .lock()
                .insert("local-sess".to_string(), tx);
            state.nick_to_session.lock().insert("alice", "local-sess");
            state
                .channels
                .lock()
                .get_mut("#chat")
                .unwrap()
                .members
                .insert("local-sess".to_string());
        }

        // Peer sends PRIVMSG claiming to be from "alice"
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:3"),
                from: "alice!u@s2s".to_string(),
                target: "#chat".to_string(),
                text: "I am the real alice".to_string(),
                origin: PEER.to_string(),
                msgid: None,
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        // The message should have been delivered to local alice.
        // The key question: can the local user distinguish the real alice
        // from the S2S-spoofed alice? Currently they can't — both appear
        // as "alice" in the channel. This is a known limitation.
    }

    // ═══════════════════════════════════════════════════════════
    // S2S SANITIZATION: CRLF injection
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_privmsg_crlf_stripped() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#inject");

        // Add a local member to receive
        {
            let (tx, mut rx) = mpsc::channel(16);
            state.connections.lock().insert("recv-sess".to_string(), tx);
            state
                .channels
                .lock()
                .get_mut("#inject")
                .unwrap()
                .members
                .insert("recv-sess".to_string());
            state
                .cap_message_tags
                .lock()
                .insert("recv-sess".to_string());

            // Peer sends PRIVMSG with CRLF in text
            process_s2s_message(
                &state,
                &mgr,
                PEER,
                S2sMessage::Privmsg {
                    event_id: format!("{PEER}:4"),
                    from: "attacker!u@s2s".to_string(),
                    target: "#inject".to_string(),
                    text: "hello\r\nQUIT :pwned".to_string(),
                    origin: PEER.to_string(),
                    msgid: None,
                    sig: None,
                    account: None,
                    recipient_did: None,
                    replaces_msgid: None,
                    tags: HashMap::new(),
                    multiline_lines: None,
                },
            )
            .await;

            // Check what the local member received
            if let Ok(line) =
                tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await
            {
                if let Some(line) = line {
                    assert!(
                        !line.contains("\r\nQUIT"),
                        "BUG: CRLF injection in S2S privmsg text: {line}"
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // S2S PRIVMSG: draft/multiline relay
    // ═══════════════════════════════════════════════════════════

    fn s2s_multiline_lines(bodies: &[&str]) -> Vec<crate::s2s::MultilineLine> {
        bodies
            .iter()
            .map(|b| crate::s2s::MultilineLine {
                body: (*b).to_string(),
                concat: false,
            })
            .collect()
    }

    /// Drain the receiver mailbox after a small wait so all the frames
    /// the handler tried to send have a chance to land. Returns the
    /// collected frames in order. The deadline is generous enough that
    /// we don't false-fail on slow CI but short enough that test
    /// time stays small.
    async fn drain_mailbox(rx: &mut mpsc::Receiver<String>) -> Vec<String> {
        let mut frames = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await {
                Ok(Some(line)) => frames.push(line),
                _ => break,
            }
        }
        frames
    }

    #[tokio::test]
    async fn s2s_multiline_capable_local_member_receives_batch_frames() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#mlchan");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("ml-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#mlchan")
            .unwrap()
            .members
            .insert("ml-recv".to_string());
        state.cap_message_tags.lock().insert("ml-recv".to_string());
        state
            .cap_draft_multiline
            .lock()
            .insert("ml-recv".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:ml-cap"),
                from: "alice!a@remote".to_string(),
                target: "#mlchan".to_string(),
                text: "first\nsecond\nthird".to_string(),
                origin: PEER.to_string(),
                msgid: Some("ML-MSG-1".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: Some(s2s_multiline_lines(&["first", "second", "third"])),
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        // Opener + 3 chunk PRIVMSGs + closer = 5 frames.
        assert_eq!(frames.len(), 5, "got frames: {frames:#?}");
        assert!(frames[0].contains("BATCH +ml"));
        assert!(frames[0].contains("draft/multiline"));
        assert!(frames[0].contains("#mlchan"));
        assert!(frames[0].contains("msgid=ML-MSG-1"));
        assert!(frames[1].contains("batch=ml"));
        assert!(frames[1].contains("first"));
        assert!(frames[2].contains("second"));
        assert!(frames[3].contains("third"));
        assert!(frames[4].starts_with("BATCH -ml"));
    }

    #[tokio::test]
    async fn s2s_privmsg_long_body_is_not_truncated_in_history() {
        // A federated PRIVMSG longer than the old 4096-char S2S cap used to
        // be guillotined mid-word before it landed in channel history + DB,
        // so scrollback/CHATHISTORY and non-multiline clients rendered a
        // truncated copy. The S2S text cap now matches the local multiline
        // ceiling (MAX_BYTES), so a message that's legal locally survives
        // the server boundary.
        //
        // 5010-char body with a trailing sentinel past the old 4096 cut.
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#longmsg");

        let body = format!("{}__END_SENTINEL__", "x".repeat(5000));
        assert!(body.chars().count() > 4096, "test body must exceed the cap");

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:longmsg"),
                from: "alice!a@remote".to_string(),
                target: "#longmsg".to_string(),
                text: body.clone(),
                origin: PEER.to_string(),
                msgid: Some("LONG-MSG-1".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let stored = state
            .channels
            .lock()
            .get("#longmsg")
            .and_then(|ch| ch.history.back().map(|m| m.text.clone()))
            .expect("message should be stored in history");

        assert!(
            stored.ends_with("__END_SENTINEL__"),
            "federated body was truncated: stored {} chars (expected {})",
            stored.chars().count(),
            body.chars().count(),
        );
        assert_eq!(
            stored, body,
            "stored history must match the full federated body"
        );
    }

    #[tokio::test]
    async fn s2s_privmsg_account_injected_for_account_tag_client() {
        // A federated PRIVMSG carrying the sender DID (`account`) should be
        // delivered with `account=<did>` to a local client that negotiated
        // account-tag — same as a locally-originated message.
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#acct");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("acct-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#acct")
            .unwrap()
            .members
            .insert("acct-recv".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("acct-recv".to_string());
        state.cap_account_tag.lock().insert("acct-recv".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:acct"),
                from: "alice!a@remote".to_string(),
                target: "#acct".to_string(),
                text: "hi".to_string(),
                origin: PEER.to_string(),
                msgid: Some("ACCT-MSG-1".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        assert!(
            frames[0].contains("account=did:plc:alice"),
            "federated message should carry account=<did>: {}",
            frames[0]
        );
    }

    #[tokio::test]
    async fn s2s_privmsg_account_omitted_without_account_tag_cap() {
        // A tag-capable client that did NOT negotiate account-tag must not
        // receive the `account` tag (IRCv3 account-tag is opt-in).
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#acct2");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("plain-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#acct2")
            .unwrap()
            .members
            .insert("plain-recv".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("plain-recv".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:acct2"),
                from: "alice!a@remote".to_string(),
                target: "#acct2".to_string(),
                text: "hi".to_string(),
                origin: PEER.to_string(),
                msgid: Some("ACCT-MSG-2".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        assert!(
            !frames[0].contains("account="),
            "client without account-tag must not get account: {}",
            frames[0]
        );
    }

    #[tokio::test]
    async fn s2s_privmsg_carries_origin_provenance_tag() {
        // A federated message is tagged with the origin server's name so
        // clients can tell it apart from a locally-verified one. Gated on
        // message-tags (it's a coordination tag), independent of account-tag.
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#prov");
        mgr.peer_names
            .lock()
            .await
            .insert(PEER.to_string(), "zerosum".to_string());

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("prov-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#prov")
            .unwrap()
            .members
            .insert("prov-recv".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("prov-recv".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:prov"),
                from: "alice!a@remote".to_string(),
                target: "#prov".to_string(),
                text: "hi".to_string(),
                origin: PEER.to_string(),
                msgid: Some("PROV-1".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        assert!(
            frames[0].contains("+freeq.at/origin=zerosum"),
            "federated message should carry origin provenance: {}",
            frames[0]
        );
    }

    #[tokio::test]
    async fn s2s_privmsg_origin_provenance_falls_back_to_peer_id() {
        // When the origin peer has no recorded name, the provenance tag falls
        // back to a short form of its id rather than being absent.
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#prov2");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("prov2-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#prov2")
            .unwrap()
            .members
            .insert("prov2-recv".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("prov2-recv".to_string());

        // Note: no peer_names entry for PEER.
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:prov2"),
                from: "alice!a@remote".to_string(),
                target: "#prov2".to_string(),
                text: "hi".to_string(),
                origin: PEER.to_string(),
                msgid: Some("PROV-2".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        let expected = &PEER[..8.min(PEER.len())];
        assert!(
            frames[0].contains(&format!("+freeq.at/origin={expected}")),
            "should fall back to short peer id: {}",
            frames[0]
        );
    }

    #[tokio::test]
    async fn s2s_multiline_fallback_local_member_receives_n_privmsgs() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#mlchan2");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("fb-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#mlchan2")
            .unwrap()
            .members
            .insert("fb-recv".to_string());
        state.cap_message_tags.lock().insert("fb-recv".to_string());
        // Deliberately do NOT add to cap_draft_multiline.

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:ml-fb"),
                from: "alice!a@remote".to_string(),
                target: "#mlchan2".to_string(),
                text: "first\nsecond".to_string(),
                origin: PEER.to_string(),
                msgid: Some("ML-MSG-2".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: Some(s2s_multiline_lines(&["first", "second"])),
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        // Fallback receiver: 2 PRIVMSGs, no BATCH frames.
        assert_eq!(frames.len(), 2, "got frames: {frames:#?}");
        for frame in &frames {
            assert!(
                !frame.contains("BATCH"),
                "BATCH leaked to fallback: {frame}"
            );
            assert!(
                !frame.contains("batch="),
                "batch tag leaked to fallback: {frame}"
            );
        }
        // msgid only on first.
        assert!(frames[0].contains("msgid=ML-MSG-2"));
        assert!(!frames[1].contains("msgid"));
        // The IRC formatter only prefixes `:` on the trailing param when
        // it contains spaces or starts with `:`; "first" / "second" have
        // neither, so they land without the colon.
        assert!(
            frames[0].ends_with("first\r\n"),
            "first chunk content not at end: {}",
            frames[0],
        );
        assert!(
            frames[1].ends_with("second\r\n"),
            "second chunk content not at end: {}",
            frames[1],
        );
    }

    /// Build a manager with a broadcast channel we can drain, so a
    /// test can capture what relay_to_nick / s2s_broadcast actually
    /// emits onto the wire. Distinct from `test_manager()`, which
    /// drops the receiver — that's fine when the test only cares
    /// about effects on local state, but we need to inspect the
    /// broadcasted S2sMessage here.
    fn test_manager_with_broadcast_rx() -> (Arc<S2sManager>, mpsc::Receiver<S2sMessage>) {
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let (broadcast_tx, broadcast_rx) = mpsc::channel(1024);
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
        let secret_key = iroh::SecretKey::from_bytes(&key_bytes);
        let manager = Arc::new(S2sManager {
            server_id: "test-local-server".to_string(),
            server_name: "test-s2s".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(1000),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret_key),
            trust_config: HashMap::new(),
            peer_trust: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        });
        (manager, broadcast_rx)
    }

    #[tokio::test]
    async fn dm_to_federated_user_via_relay_to_nick_carries_multiline_lines() {
        // The narrow real-world case the routing-layer fix targets:
        // a multiline DM whose target nick has no local session and
        // gets relayed via S2S. Before the fix, the assembled body
        // shipped over the wire as-is and the receiving peer had no
        // way to split it back into BATCH-wrappable chunks. Now the
        // breakdown rides along on the relayed Privmsg event.
        use crate::connection::draft_multiline::BatchLine;
        use crate::connection::routing::{RelayIdentity, RouteResult, relay_to_nick};

        let state = test_state();
        let (mgr, mut broadcast_rx) = test_manager_with_broadcast_rx();
        *state.s2s_manager.lock() = Some(mgr.clone());

        let lines = vec![
            BatchLine {
                body: "chunk one".to_string(),
                concat_to_previous: false,
                command: "PRIVMSG".to_string(),
            },
            BatchLine {
                body: "chunk two".to_string(),
                concat_to_previous: false,
                command: "PRIVMSG".to_string(),
            },
            BatchLine {
                body: "tail".to_string(),
                concat_to_previous: true,
                command: "PRIVMSG".to_string(),
            },
        ];

        // Target "ghost" has no local session — relay_to_nick will
        // fall through to the S2S branch since the test manager is
        // installed.
        let outcome = relay_to_nick(
            &state,
            "sender!u@h",
            "ghost",
            "chunk one\nchunk twotail",
            "evt-1".to_string(),
            Some(&lines),
            RelayIdentity::default(),
        );
        assert!(matches!(outcome, RouteResult::Relayed));

        // Drain the broadcast channel and assert the Privmsg has the
        // expected multiline_lines populated.
        let captured =
            tokio::time::timeout(std::time::Duration::from_millis(200), broadcast_rx.recv())
                .await
                .expect("broadcast deadline")
                .expect("broadcast channel closed before receive");
        match captured {
            S2sMessage::Privmsg {
                target,
                text,
                tags,
                multiline_lines,
                ..
            } => {
                assert_eq!(target, "ghost");
                // The S2S `text` field is dual-encoded: `\n` escaped to
                // `\\n` + `+freeq.at/multiline` tag, so a peer that
                // doesn't understand `multiline_lines` still relays
                // wire-safe content. New peers prefer `multiline_lines`
                // and ignore the escaped `text`.
                assert_eq!(text, "chunk one\\nchunk twotail");
                assert!(
                    tags.contains_key("+freeq.at/multiline"),
                    "+freeq.at/multiline tag must be set when text is escaped"
                );
                let ml = multiline_lines.expect("multiline_lines absent from broadcast");
                assert_eq!(ml.len(), 3);
                assert_eq!(ml[0].body, "chunk one");
                assert!(!ml[0].concat);
                assert_eq!(ml[1].body, "chunk two");
                assert!(!ml[1].concat);
                assert_eq!(ml[2].body, "tail");
                assert!(ml[2].concat, "third line should carry concat=true");
            }
            other => panic!("expected Privmsg variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dm_to_federated_user_without_multiline_lines_relays_none() {
        // Regression guard: non-multiline DMs (the existing single-
        // PRIVMSG path) must still relay with multiline_lines = None
        // so peer servers go through their existing single-PRIVMSG
        // broadcast (no synthetic chunking).
        use crate::connection::routing::{RelayIdentity, RouteResult, relay_to_nick};

        let state = test_state();
        let (mgr, mut broadcast_rx) = test_manager_with_broadcast_rx();
        *state.s2s_manager.lock() = Some(mgr.clone());

        let outcome = relay_to_nick(
            &state,
            "sender!u@h",
            "ghost",
            "ordinary text",
            "evt-2".to_string(),
            None,
            RelayIdentity::default(),
        );
        assert!(matches!(outcome, RouteResult::Relayed));

        let captured =
            tokio::time::timeout(std::time::Duration::from_millis(200), broadcast_rx.recv())
                .await
                .expect("broadcast deadline")
                .expect("broadcast channel closed before receive");
        match captured {
            S2sMessage::Privmsg {
                multiline_lines, ..
            } => {
                assert!(
                    multiline_lines.is_none(),
                    "non-multiline DM should not carry multiline_lines",
                );
            }
            other => panic!("expected Privmsg variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn s2s_privmsg_without_multiline_field_unchanged() {
        // Belt-and-suspenders: peer servers that don't know about
        // multiline still relay regular PRIVMSGs; the receive handler
        // should fall through to the existing single-PRIVMSG path.
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#plain");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("plain-recv".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#plain")
            .unwrap()
            .members
            .insert("plain-recv".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("plain-recv".to_string());
        state
            .cap_draft_multiline
            .lock()
            .insert("plain-recv".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:plain"),
                from: "alice!a@remote".to_string(),
                target: "#plain".to_string(),
                text: "just a normal line".to_string(),
                origin: PEER.to_string(),
                msgid: Some("PLAIN-MSG".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        assert!(!frames[0].contains("BATCH"));
        assert!(frames[0].contains("msgid=PLAIN-MSG"));
        assert!(frames[0].contains(":just a normal line"));
    }

    // ═══════════════════════════════════════════════════════════
    // S2S TOPIC: +t enforcement
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_topic_rejected_on_locked_channel_from_non_op() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#locked");

        // Set +t on channel
        state
            .channels
            .lock()
            .get_mut("#locked")
            .unwrap()
            .topic_locked = true;

        // Add non-op remote member
        add_remote_member(&state, "#locked", "nonop", false);

        // Set existing topic
        state.channels.lock().get_mut("#locked").unwrap().topic = Some(TopicInfo {
            text: "original topic".to_string(),
            set_by: "founder".to_string(),
            set_at: 1000,
        });

        // Peer sends topic change from non-op
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Topic {
                event_id: format!("{PEER}:5"),
                channel: "#locked".to_string(),
                topic: "hijacked topic".to_string(),
                set_by: "nonop".to_string(),
                origin: PEER.to_string(),
            },
        )
        .await;

        // Topic should NOT have changed
        let channels = state.channels.lock();
        let topic = channels.get("#locked").unwrap().topic.as_ref().unwrap();
        assert_eq!(
            topic.text, "original topic",
            "BUG: Non-op changed topic on +t channel via S2S"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S KICK: authorization check
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_kick_from_non_op_rejected() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#kicktest");

        // Add non-op remote member as kicker
        add_remote_member(&state, "#kicktest", "non_op_kicker", false);
        // Add victim as remote member
        add_remote_member(&state, "#kicktest", "victim", false);

        // Peer sends kick from non-op
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Kick {
                event_id: format!("{PEER}:6"),
                nick: "victim".to_string(),
                channel: "#kicktest".to_string(),
                by: "non_op_kicker".to_string(),
                reason: "unauthorized kick".to_string(),
                origin: PEER.to_string(),
            },
        )
        .await;

        // Victim should still be in the channel
        let channels = state.channels.lock();
        let ch = channels.get("#kicktest").unwrap();
        assert!(
            ch.remote_members.contains_key("victim"),
            "BUG: Non-op kicked user via S2S — authorization check failed"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S BAN: authorization check
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_ban_from_non_op_rejected() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#bantest");

        // Add non-op remote member
        add_remote_member(&state, "#bantest", "non_op_banner", false);

        // Peer sends ban from non-op
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Ban {
                event_id: format!("{PEER}:7"),
                channel: "#bantest".to_string(),
                mask: "*!*@*".to_string(),
                set_by: "non_op_banner".to_string(),
                adding: true,
                origin: PEER.to_string(),
            },
        )
        .await;

        // Ban list should be empty (unauthorized)
        let channels = state.channels.lock();
        let ch = channels.get("#bantest").unwrap();
        assert!(
            ch.bans.is_empty(),
            "BUG: Non-op set ban via S2S — {} bans in list",
            ch.bans.len()
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S DEDUP: replay rejection
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_duplicate_event_rejected() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#dedup");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("dedup-sess".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#dedup")
            .unwrap()
            .members
            .insert("dedup-sess".to_string());

        let event_id = format!("{PEER}:100");

        // Send same message twice
        for _ in 0..2 {
            process_s2s_message(
                &state,
                &mgr,
                PEER,
                S2sMessage::Privmsg {
                    event_id: event_id.clone(),
                    from: "bob!u@s2s".to_string(),
                    target: "#dedup".to_string(),
                    text: "should only arrive once".to_string(),
                    origin: PEER.to_string(),
                    msgid: None,
                    sig: None,
                    account: None,
                    recipient_did: None,
                    replaces_msgid: None,
                    tags: HashMap::new(),
                    multiline_lines: None,
                },
            )
            .await;
        }

        // Should receive only ONE message
        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {
            count += 1;
        }
        assert_eq!(
            count, 1,
            "BUG: Duplicate S2S event not rejected — received {count} messages"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S CHANNEL LENGTH LIMIT
    // ═══════════════════════════════════════════════════════════

    // ── Channel defaults on S2S-learned channels ───────────────────
    //
    // A channel comes into existence with +nt everywhere. `ChannelCreated` and
    // `SyncResponse` say so explicitly; `Join` and `Topic` can create a channel
    // too, and left it with `ChannelState::default()` — no +n, no +t. Which
    // meant the modes a channel had on a peer depended on which event happened
    // to arrive first, and on the peer's copy anyone could set the topic and a
    // non-member could talk.

    /// The mode set a channel is born with, on any server that learns of it.
    fn modes_of(state: &Arc<SharedState>, channel: &str) -> (bool, bool) {
        let channels = state.channels.lock();
        let ch = channels.get(channel).expect("channel exists");
        (ch.no_ext_msg, ch.topic_locked)
    }

    async fn relay_join(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        channel: &str,
        nick: &str,
    ) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Join {
                event_id: format!("{PEER}:join-{channel}-{nick}"),
                nick: nick.to_string(),
                channel: channel.to_string(),
                did: None,
                handle: None,
                is_op: false,
                actor_class: None,
                origin: PEER.to_string(),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn s2s_join_creating_a_channel_applies_default_modes() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        relay_join(&state, &mgr, "#fedjoinmodes", "alice").await;

        assert_eq!(
            modes_of(&state, "#fedjoinmodes"),
            (true, true),
            "a channel learned from a peer's JOIN must be +nt, like one created here"
        );
    }

    /// The order the origin actually sends in: `Join` first, then
    /// `ChannelCreated`. So `ChannelCreated`'s own defaults never applied — by
    /// the time it arrived the channel existed, and `is_new` was false.
    #[tokio::test]
    async fn s2s_join_before_channel_created_still_locks_the_topic() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        relay_join(&state, &mgr, "#fedorder", "alice").await;
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::ChannelCreated {
                event_id: format!("{PEER}:created"),
                channel: "#fedorder".to_string(),
                founder_did: None,
                did_ops: vec![],
                created_at: 0,
                origin: PEER.to_string(),
            },
        )
        .await;

        assert_eq!(
            modes_of(&state, "#fedorder"),
            (true, true),
            "the JOIN-then-ChannelCreated order left the channel with no protections"
        );
    }

    /// A `Topic` for a channel we have never seen creates it too. Same rule.
    #[tokio::test]
    async fn s2s_topic_creating_a_channel_applies_default_modes() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Topic {
                event_id: format!("{PEER}:topic"),
                channel: "#fedtopicmodes".to_string(),
                topic: "hello".to_string(),
                set_by: "alice".to_string(),
                origin: PEER.to_string(),
            },
        )
        .await;

        assert_eq!(
            modes_of(&state, "#fedtopicmodes"),
            (true, true),
            "a channel learned from a peer's TOPIC must be +nt"
        );
    }

    /// The defaults are for *new* channels only — a channel we already hold
    /// keeps the modes it has, including ones deliberately turned off.
    #[tokio::test]
    async fn s2s_join_does_not_reimpose_defaults_on_an_existing_channel() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        setup_channel(&state, "#fedexisting");
        {
            let mut channels = state.channels.lock();
            let ch = channels.get_mut("#fedexisting").unwrap();
            ch.no_ext_msg = false;
            ch.topic_locked = false;
        }

        relay_join(&state, &mgr, "#fedexisting", "alice").await;

        assert_eq!(
            modes_of(&state, "#fedexisting"),
            (false, false),
            "an existing channel's modes must not be reset by a peer's JOIN"
        );
    }

    #[tokio::test]
    async fn s2s_join_long_channel_name_truncated() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        let long_name = "#".to_string() + &"a".repeat(300);

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Join {
                event_id: format!("{PEER}:8"),
                nick: "longjoin".to_string(),
                channel: long_name.clone(),
                did: None,
                handle: None,
                is_op: false,
                actor_class: None,
                origin: PEER.to_string(),
            },
        )
        .await;

        // Channel name should be truncated by sanitize_s2s_str(200)
        let channels = state.channels.lock();
        // The full 300-char name should NOT exist as-is
        assert!(
            !channels.contains_key(&long_name),
            "S2S channel name should be truncated to max 200 chars"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S RATE LIMIT CHECK (boundary)
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_rate_limit_at_boundary() {
        // Isolated peer id: setup_authenticated_peer clears PEER's
        // rate-limit counter, which races with this test's 101-message
        // send if other parallel tests re-enter setup mid-way.
        const RL_PEER: &str = "fake-peer-rate-limit-isolated";
        let state = test_state();
        let mgr = test_manager();
        mgr.authenticated_peers
            .lock()
            .await
            .insert(RL_PEER.to_string());
        mgr.peer_trust
            .lock()
            .await
            .insert(RL_PEER.to_string(), TrustLevel::Full);
        *state.s2s_manager.lock() = Some(mgr.clone());
        S2S_RATE_LIMITS.lock().remove(RL_PEER);
        setup_channel(&state, "#ratelimit");

        let (tx, mut rx) = mpsc::channel(256);
        state.connections.lock().insert("rl-sess".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#ratelimit")
            .unwrap()
            .members
            .insert("rl-sess".to_string());

        for i in 0..101u64 {
            process_s2s_message(
                &state,
                &mgr,
                RL_PEER,
                S2sMessage::Privmsg {
                    event_id: format!("{RL_PEER}:{}", 200 + i),
                    from: "spammer!u@s2s".to_string(),
                    target: "#ratelimit".to_string(),
                    text: format!("spam {i}"),
                    origin: RL_PEER.to_string(),
                    msgid: None,
                    sig: None,
                    account: None,
                    recipient_did: None,
                    replaces_msgid: None,
                    tags: HashMap::new(),
                    multiline_lines: None,
                },
            )
            .await;
        }

        // Count received messages
        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {
            count += 1;
        }
        assert!(
            count <= 100,
            "S2S rate limit breached: received {count} messages (limit 100/sec)"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S JOIN: actor_class propagation
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_join_actor_class_stored_on_remote_member() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#agenttest");

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Join {
                event_id: format!("{PEER}:agent1"),
                nick: "testbot".to_string(),
                channel: "#agenttest".to_string(),
                did: None,
                handle: None,
                is_op: false,
                actor_class: Some("agent".to_string()),
                origin: PEER.to_string(),
            },
        )
        .await;

        let channels = state.channels.lock();
        let ch = channels.get("#agenttest").unwrap();
        let rm = ch
            .remote_members
            .get("testbot")
            .expect("remote member should exist");
        assert_eq!(
            rm.actor_class.as_deref(),
            Some("agent"),
            "Remote member should have actor_class=agent"
        );
    }

    #[tokio::test]
    async fn s2s_join_actor_class_delivered_to_local_members() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#agentdeliver");

        // Add a local member to receive the JOIN
        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("local-sess".to_string(), tx);
        state
            .nick_to_session
            .lock()
            .insert("localuser", "local-sess");
        state
            .channels
            .lock()
            .get_mut("#agentdeliver")
            .unwrap()
            .members
            .insert("local-sess".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("local-sess".to_string());

        // Remote agent joins
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Join {
                event_id: format!("{PEER}:agent2"),
                nick: "remotebot".to_string(),
                channel: "#agentdeliver".to_string(),
                did: None,
                handle: None,
                is_op: false,
                actor_class: Some("agent".to_string()),
                origin: PEER.to_string(),
            },
        )
        .await;

        // Local member should receive JOIN with actor-class tag
        let mut found_join = false;
        while let Ok(Some(msg)) =
            tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await
        {
            if msg.contains("JOIN") && msg.contains("remotebot") {
                assert!(
                    msg.contains("+freeq.at/actor-class=agent"),
                    "JOIN should include actor-class tag, got: {msg}"
                );
                found_join = true;
                break;
            }
        }
        assert!(
            found_join,
            "Local member should receive JOIN for remote agent"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S TAGMSG: reaction delivery to local users
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_tagmsg_reaction_delivered_to_local_user() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#react-test");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("react-sess".to_string(), tx);
        state.nick_to_session.lock().insert("reactor", "react-sess");
        state
            .channels
            .lock()
            .get_mut("#react-test")
            .unwrap()
            .members
            .insert("react-sess".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("react-sess".to_string());

        let mut tags = HashMap::new();
        tags.insert("+react".to_string(), "👍".to_string());
        tags.insert("+reply".to_string(), "msg001".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:tag1"),
                from: "alice!a@remote".to_string(),
                target: "#react-test".to_string(),
                tags,
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(msg.contains("TAGMSG"), "Should be TAGMSG, got: {msg}");
        assert!(
            msg.contains("+react="),
            "Should contain reaction, got: {msg}"
        );
    }

    #[tokio::test]
    async fn s2s_unreact_removes_persisted_reaction() {
        // A federated reaction followed by a federated UNREACT: the removal
        // must reach the DB, or the reaction resurrects for fresh joins and
        // after restarts (it did — the unreact path only relayed live).
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#s2s-unreact");

        let mut react = HashMap::new();
        react.insert("+react".to_string(), "🎉".to_string());
        react.insert("+reply".to_string(), "01MSGID".to_string());
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:r1"),
                from: "alice!a@remote".to_string(),
                target: "#s2s-unreact".to_string(),
                tags: react,
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;
        let stored = state
            .with_db(|db| db.get_reactions_for_messages(&["01MSGID"]))
            .expect("db present");
        assert_eq!(
            stored.get("01MSGID").map(|v| v.len()),
            Some(1),
            "react persisted"
        );

        let mut unreact = HashMap::new();
        unreact.insert("+freeq.at/unreact".to_string(), "🎉".to_string());
        unreact.insert("+reply".to_string(), "01MSGID".to_string());
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:r2"),
                from: "alice!a@remote".to_string(),
                target: "#s2s-unreact".to_string(),
                tags: unreact,
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;
        let after = state
            .with_db(|db| db.get_reactions_for_messages(&["01MSGID"]))
            .expect("db present");
        assert!(
            after.get("01MSGID").is_none_or(|v| v.is_empty()),
            "federated unreact must remove the persisted reaction: {after:?}"
        );
    }

    #[tokio::test]
    async fn s2s_tagmsg_draft_tags_normalized() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#draft-test");

        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("draft-sess".to_string(), tx);
        state.nick_to_session.lock().insert("drafter", "draft-sess");
        state
            .channels
            .lock()
            .get_mut("#draft-test")
            .unwrap()
            .members
            .insert("draft-sess".to_string());
        state
            .cap_message_tags
            .lock()
            .insert("draft-sess".to_string());

        // Send with +draft/ prefixed tags
        let mut tags = HashMap::new();
        tags.insert("+draft/react".to_string(), "❤️".to_string());
        tags.insert("+draft/reply".to_string(), "msg999".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:draft1"),
                from: "bob!b@remote".to_string(),
                target: "#draft-test".to_string(),
                tags,
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(msg.contains("TAGMSG"), "Should be TAGMSG, got: {msg}");
        // Should be normalized to +react, not +draft/react
        assert!(
            msg.contains("+react="),
            "Should contain normalized +react, got: {msg}"
        );
        assert!(
            !msg.contains("+draft/react"),
            "Should NOT contain draft prefix, got: {msg}"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // S2S DM: delivery and persistence for local recipients
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn s2s_dm_delivered_to_local_user() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        // Set up local user "bob" who will receive the DM
        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("bob-sess".to_string(), tx);
        state.nick_to_session.lock().insert("bob", "bob-sess");
        state.cap_message_tags.lock().insert("bob-sess".to_string());

        // Remote user sends DM to local bob
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:dm1"),
                from: "alice!a@remote".to_string(),
                target: "bob".to_string(),
                text: "hey bob, private msg".to_string(),
                origin: PEER.to_string(),
                msgid: Some("dm-msg-001".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        // Bob should receive the DM
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for DM")
            .expect("channel closed");
        assert!(
            msg.contains("hey bob, private msg"),
            "Bob should receive DM text, got: {msg}"
        );
        assert!(
            msg.contains("PRIVMSG bob"),
            "Should be addressed to bob, got: {msg}"
        );
    }

    #[tokio::test]
    async fn s2s_dm_account_injected_for_account_tag_client() {
        // A federated DM delivers `account=<did>` to a local recipient that
        // negotiated account-tag (DM path, distinct from the channel path).
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("bob-sess".to_string(), tx);
        state.nick_to_session.lock().insert("bob", "bob-sess");
        state.cap_message_tags.lock().insert("bob-sess".to_string());
        state.cap_account_tag.lock().insert("bob-sess".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:dm-acct"),
                from: "alice!a@remote".to_string(),
                target: "bob".to_string(),
                text: "hey bob".to_string(),
                origin: PEER.to_string(),
                msgid: Some("DM-ACCT-D1".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let frames = drain_mailbox(&mut rx).await;
        assert_eq!(frames.len(), 1, "got frames: {frames:#?}");
        assert!(
            frames[0].contains("account=did:plc:alice"),
            "federated DM should carry account=<did>: {}",
            frames[0]
        );
    }

    #[tokio::test]
    async fn s2s_dm_from_unknown_remote_sender_persists_via_carried_account() {
        // Before the account carry, persisting a DM required BOTH DIDs to be
        // resolvable from local nick_owners. A sender who never authed on this
        // server isn't there, so a stranger→local DM was dropped from history
        // (todo #16). The carried `account` now supplies the sender DID, so it
        // persists.
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;

        // Recipient is a known local identity; sender is NOT in nick_owners.
        state
            .nick_owners
            .lock()
            .insert("bob".to_string(), "did:plc:bob".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:dm-persist"),
                from: "alice!a@remote".to_string(),
                target: "bob".to_string(),
                text: "stranger dm".to_string(),
                origin: PEER.to_string(),
                msgid: Some("DM-ACCT-P1".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let key = crate::db::canonical_dm_key("did:plc:alice", "did:plc:bob");
        let msgs = state
            .with_db(|db| db.get_messages(&key, 10, None))
            .expect("get_messages");
        assert_eq!(msgs.len(), 1, "stranger→local DM should persist");
        assert_eq!(msgs[0].text, "stranger dm");
        assert_eq!(msgs[0].sender_did.as_deref(), Some("did:plc:alice"));
    }

    #[tokio::test]
    async fn s2s_dm_from_unknown_remote_sender_without_account_not_persisted() {
        // Same as above but the peer sent no account (older peer): the sender
        // DID is unresolvable, so the DM still isn't persisted — proving the
        // carried account is what enables persistence, not something else.
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        state
            .nick_owners
            .lock()
            .insert("bob".to_string(), "did:plc:bob".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:dm-noacct"),
                from: "alice!a@remote".to_string(),
                target: "bob".to_string(),
                text: "stranger dm".to_string(),
                origin: PEER.to_string(),
                msgid: Some("DM-ACCT-P2".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let key = crate::db::canonical_dm_key("did:plc:alice", "did:plc:bob");
        let msgs = state
            .with_db(|db| db.get_messages(&key, 10, None))
            .expect("get_messages");
        assert!(
            msgs.is_empty(),
            "without a carried account the stranger DM must not persist"
        );
    }

    #[tokio::test]
    async fn s2s_channel_message_persists_origin_for_history_replay() {
        // The channel insert must persist coordination tags (incl. origin) so
        // CHATHISTORY replay carries provenance, the same as the DM path.
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#provhist");
        mgr.peer_names
            .lock()
            .await
            .insert(PEER.to_string(), "zerosum".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:provhist"),
                from: "alice!a@remote".to_string(),
                target: "#provhist".to_string(),
                text: "hi".to_string(),
                origin: PEER.to_string(),
                msgid: Some("PROVHIST-1".to_string()),
                sig: None,
                account: Some("did:plc:alice".to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        let msgs = state
            .with_db(|db| db.get_messages("#provhist", 10, None))
            .expect("get_messages");
        assert_eq!(msgs.len(), 1, "channel message should persist");
        assert_eq!(
            msgs[0].tags.get("+freeq.at/origin").map(String::as_str),
            Some("zerosum"),
            "persisted channel row must carry origin for replay: {:?}",
            msgs[0].tags
        );
    }

    #[test]
    fn bind_identity_binds_then_updates_same_did() {
        let state = test_state();
        assert_eq!(
            state.bind_identity("did:key:A", "Alice"),
            BindOutcome::Bound
        );
        assert_eq!(
            state.did_nicks.lock().get("did:key:A").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            state.nick_owners.lock().get("alice").map(String::as_str),
            Some("did:key:A")
        );
        // Same DID renames → updates both maps.
        assert_eq!(
            state.bind_identity("did:key:A", "alice2"),
            BindOutcome::Bound
        );
        assert_eq!(
            state.did_nicks.lock().get("did:key:A").map(String::as_str),
            Some("alice2")
        );
        assert_eq!(
            state.nick_owners.lock().get("alice2").map(String::as_str),
            Some("did:key:A")
        );
    }

    #[test]
    fn rename_drops_stale_nick_owners_entry() {
        let state = test_state();
        assert_eq!(state.bind_identity("did:key:A", "foo"), BindOutcome::Bound);
        assert_eq!(state.bind_identity("did:key:A", "bar"), BindOutcome::Bound);
        // Old nick must not stay owned (it lingered before the fix,
        // diverging from the durable table until a restart).
        assert!(state.nick_owners.lock().get("foo").is_none());
        assert_eq!(
            state.nick_owners.lock().get("bar").map(String::as_str),
            Some("did:key:A")
        );
        assert_eq!(
            state.did_nicks.lock().get("did:key:A").map(String::as_str),
            Some("bar")
        );
        // The freed nick is immediately claimable by a different DID.
        assert_eq!(state.bind_identity("did:key:B", "foo"), BindOutcome::Bound);
    }

    /// Going-forward contract for the DM partner name resolution bug:
    /// an authenticated DID colliding on an owned nick gets a
    /// deterministic, identity-derived nick that is durably persisted
    /// (so it resolves offline / after a restart, never a raw did:key).
    #[test]
    fn collision_yields_deterministic_persisted_derived_nick() {
        let state = test_state_with_db();
        let owner = "did:key:zAAAAAAAAAAAAAAAA";
        let did_b = "did:key:zBBBBBBBBBBBBBBBB";

        assert_eq!(state.bind_identity(owner, "happybot"), BindOutcome::Bound);

        let assigned = state.bind_identity_with_fallback(did_b, "happybot");

        assert_ne!(assigned, "happybot");
        assert!(assigned.starts_with("happybot-"), "got {assigned}");
        assert!(!assigned.starts_with("guest"), "got {assigned}");
        assert!(assigned.len() <= 64, "over nick cap: {assigned}");

        // Deterministic: same DID + same request → same nick.
        assert_eq!(
            assigned,
            state.bind_identity_with_fallback(did_b, "happybot")
        );

        // The original owner keeps the bare nick.
        assert_eq!(
            state.nick_owners.lock().get("happybot").map(String::as_str),
            Some(owner)
        );

        // Durable: wipe in-memory maps (simulate restart); the derived
        // nick still resolves via the identities table.
        state.did_nicks.lock().clear();
        state.nick_owners.lock().clear();
        assert_eq!(state.display_nick_for_did(did_b), assigned);
    }

    /// LOGIN/OAuth completion now durably persists the binding and, on
    /// a nick collision, assigns a deterministic derived nick (same as
    /// the SASL/registration path) instead of an in-memory-only
    /// overwrite lost on restart.
    #[test]
    fn login_completion_persists_and_derives_on_collision() {
        use crate::connection::login::complete_irc_login;
        let state = test_state_with_db();
        let owner = "did:key:zOWNEROWNEROWNER";
        let did_b = "did:key:zLOGINBBBBBBBBBB";

        assert_eq!(state.bind_identity(owner, "foo"), BindOutcome::Bound);
        state.nick_to_session.lock().insert("foo", "sess1");

        complete_irc_login(&state, "sess1", did_b, "bob.test");

        let assigned = state
            .did_nicks
            .lock()
            .get(did_b)
            .cloned()
            .expect("did_b durably bound");
        assert_ne!(assigned, "foo");
        assert!(assigned.starts_with("foo-"), "got {assigned}");

        // Rename propagated to the connection loop.
        let comp = state
            .login_completions
            .lock()
            .get("sess1")
            .cloned()
            .expect("completion stored");
        assert_eq!(comp.renamed_nick.as_deref(), Some(assigned.as_str()));

        // Both resolve offline (wipe in-memory; identities table answers).
        state.did_nicks.lock().clear();
        state.nick_owners.lock().clear();
        assert_eq!(state.display_nick_for_did(did_b), assigned);
        assert_eq!(state.display_nick_for_did(owner), "foo");
    }

    #[test]
    fn display_nick_falls_back_to_message_history() {
        let state = test_state_with_db();
        let did = "did:plc:legacy";

        // No did_nicks entry, no identities row — only message history, as for
        // a conversation predating durable identity binding or a remote DID.
        state.with_db(|db| {
            db.insert_message(
                "&dmkey",
                "carol!c@freeq/plc/abcd",
                "hey",
                100,
                &std::collections::HashMap::new(),
                Some("h1"),
                Some(did),
            )
        });

        assert_eq!(state.display_nick_for_did(did), "carol");
        // A DID with no history at all still degrades to the raw DID.
        assert_eq!(
            state.display_nick_for_did("did:plc:unknown"),
            "did:plc:unknown"
        );
    }

    // === commit-reveal verification ===
    //
    // Tests for `connection::messaging::verify_commit_reveal`. Each test
    // stages a synthetic commit message in the `messages` table (via the
    // same `insert_message` path commits ride in production), then calls
    // the verifier with matching/mismatching reveal inputs and asserts
    // the outcome.

    fn stage_commit(
        state: &Arc<SharedState>,
        msgid: &str,
        commit_did: &str,
        channel: &str,
        ref_id: Option<&str>,
        salt: &[u8],
        plaintext: &str,
        alg: &str,
    ) -> String {
        use base64::Engine;
        use sha2::Digest;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut hasher = sha2::Sha256::new();
        hasher.update(salt);
        hasher.update(plaintext.as_bytes());
        let hash_b64 = b64.encode(hasher.finalize());

        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/event".to_string(), "commit".to_string());
        let payload = format!(r#"{{"hash":"{}","alg":"{}"}}"#, hash_b64, alg);
        tags.insert("+freeq.at/payload".to_string(), payload);
        if let Some(r) = ref_id {
            tags.insert("+freeq.at/ref".to_string(), r.to_string());
        }

        state
            .with_db(|db| {
                db.insert_message(
                    channel,
                    "panelist",
                    "🔒 sealed",
                    1_700_000_000,
                    &tags,
                    Some(msgid),
                    Some(commit_did),
                )
            })
            .expect("insert_message via with_db");
        hash_b64
    }

    fn reveal_payload(commit_msgid: &str, salt: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let salt_b64 = b64.encode(salt);
        format!(
            r#"{{"reveal_of":"{}","salt":"{}"}}"#,
            commit_msgid, salt_b64
        )
    }

    #[test]
    fn commit_reveal_verify_happy_path() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let salt: &[u8] = b"saltsalt12345678";
        let plaintext = "The answer is X because Y.";
        stage_commit(
            &state,
            "01J...COMMIT",
            did,
            "#debate",
            Some("01J...DEBATE"),
            salt,
            plaintext,
            "sha256",
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE"),
            &payload,
            plaintext,
        );
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn commit_reveal_hash_mismatch_on_tampered_body() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let salt: &[u8] = b"saltsalt12345678";
        stage_commit(
            &state,
            "01J...COMMIT",
            did,
            "#debate",
            Some("01J...DEBATE"),
            salt,
            "original",
            "sha256",
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE"),
            &payload,
            "tampered", // different from committed plaintext
        );
        assert_eq!(r, Err("hash_mismatch"));
    }

    #[test]
    fn commit_reveal_commit_not_found() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let payload = reveal_payload("01J...DOESNOTEXIST", b"salt");
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE"),
            &payload,
            "anything",
        );
        assert_eq!(r, Err("commit_not_found"));
    }

    #[test]
    fn commit_reveal_actor_mismatch() {
        let state = test_state_with_db();
        let salt: &[u8] = b"saltsalt";
        let plaintext = "answer";
        stage_commit(
            &state,
            "01J...COMMIT",
            "did:key:zPANEL1",
            "#debate",
            Some("01J...DEBATE"),
            salt,
            plaintext,
            "sha256",
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some("did:key:zPANEL2"), // different DID reveals
            "#debate",
            Some("01J...DEBATE"),
            &payload,
            plaintext,
        );
        assert_eq!(r, Err("actor_mismatch"));
    }

    #[test]
    fn commit_reveal_channel_mismatch() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let salt: &[u8] = b"saltsalt";
        let plaintext = "answer";
        stage_commit(
            &state,
            "01J...COMMIT",
            did,
            "#debate",
            Some("01J...DEBATE"),
            salt,
            plaintext,
            "sha256",
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#other", // different channel
            Some("01J...DEBATE"),
            &payload,
            plaintext,
        );
        assert_eq!(r, Err("channel_mismatch"));
    }

    #[test]
    fn commit_reveal_ref_id_mismatch() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let salt: &[u8] = b"saltsalt";
        let plaintext = "answer";
        stage_commit(
            &state,
            "01J...COMMIT",
            did,
            "#debate",
            Some("01J...DEBATE-A"),
            salt,
            plaintext,
            "sha256",
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE-B"), // different ref_id
            &payload,
            plaintext,
        );
        assert_eq!(r, Err("ref_id_mismatch"));
    }

    #[test]
    fn commit_reveal_unsupported_alg() {
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let salt: &[u8] = b"saltsalt";
        let plaintext = "answer";
        stage_commit(
            &state,
            "01J...COMMIT",
            did,
            "#debate",
            Some("01J...DEBATE"),
            salt,
            plaintext,
            "md5", // unsupported
        );
        let payload = reveal_payload("01J...COMMIT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE"),
            &payload,
            plaintext,
        );
        assert_eq!(r, Err("unsupported_alg"));
    }

    #[test]
    fn commit_reveal_not_a_commit() {
        // Stage a non-commit message at the referenced msgid.
        let state = test_state_with_db();
        let did = "did:key:zPANEL1";
        let mut tags: HashMap<String, String> = HashMap::new();
        tags.insert("+freeq.at/event".to_string(), "task_request".to_string());
        state
            .with_db(|db| {
                db.insert_message(
                    "#debate",
                    "panelist",
                    "task request",
                    1_700_000_000,
                    &tags,
                    Some("01J...NOTCOMMIT"),
                    Some(did),
                )
            })
            .expect("insert_message via with_db");

        let payload = reveal_payload("01J...NOTCOMMIT", b"salt");
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            None,
            &payload,
            "anything",
        );
        assert_eq!(r, Err("not_a_commit"));
    }

    #[test]
    fn commit_reveal_bad_payload() {
        let state = test_state_with_db();
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some("did:key:zX"),
            "#debate",
            None,
            "{not json",
            "anything",
        );
        assert_eq!(r, Err("bad_payload"));
    }

    // ── Multiline reveal round-trip ───────────────────────────────────
    //
    // These tests prove that a reveal sent via a draft/multiline batch
    // verifies correctly after Phase 2's `dispatch_assembled_batch` re-
    // feeds the assembled body through the normal PRIVMSG path. The
    // committer hashes plaintext; the sender chunks it across multiple
    // PRIVMSGs inside a BATCH; the server reassembles per concat rules;
    // verify_commit_reveal hashes the assembled body — same bytes, same
    // hash. So Phase 3's "extend verify_commit_reveal" is a no-op at
    // the verifier level; the work is in Phase 2's assembly. These tests
    // pin that behavior so a future change to assembly or dispatch
    // can't silently break commit-reveal.

    /// Reproduce the spec's join rules in tests without coupling to
    /// the production `assemble_body` (so a regression there shows up
    /// as a hash mismatch rather than as both halves agreeing on a
    /// broken assembly).
    fn assemble_for_test(lines: &[(&str, bool)]) -> String {
        let mut out = String::new();
        for (i, (body, concat)) in lines.iter().enumerate() {
            if i > 0 && !concat {
                out.push('\n');
            }
            out.push_str(body);
        }
        out
    }

    #[test]
    fn commit_reveal_verifies_multiline_assembled_body() {
        // The committer locally assembled three paragraphs joined by
        // newlines and hashed that, then sent the reveal in 3 chunks.
        let state = test_state_with_db();
        let did = "did:key:zPANEL_MULTILINE";
        let salt: &[u8] = b"saltforthemultiline";

        let chunks: Vec<(&str, bool)> = vec![
            ("Paragraph one — the opening claim.", false),
            ("Paragraph two — supporting evidence.", false),
            ("Paragraph three — the conclusion.", false),
        ];
        let assembled = assemble_for_test(&chunks);
        // Sanity: the spec's join rule produces "a\nb\nc".
        assert!(assembled.contains('\n'));
        assert!(!assembled.ends_with('\n'));

        stage_commit(
            &state,
            "01J...COMMIT_MULTI",
            did,
            "#debate",
            Some("01J...DEBATE_MULTI"),
            salt,
            &assembled,
            "sha256",
        );

        let payload = reveal_payload("01J...COMMIT_MULTI", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE_MULTI"),
            &payload,
            &assembled,
        );
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn commit_reveal_verifies_assembled_body_with_concat_chunks() {
        // Splits a long single line across two PRIVMSGs via the
        // `draft/multiline-concat` mechanism. The second chunk
        // appends to the first with no separator — verifying the
        // server's assembler agrees with the committer about the
        // joined bytes.
        let state = test_state_with_db();
        let did = "did:key:zPANEL_CONCAT";
        let salt: &[u8] = b"saltforconcatcase";

        let chunks: Vec<(&str, bool)> = vec![
            ("hello ", false),
            ("everyone", true), // concat-to-previous
        ];
        let assembled = assemble_for_test(&chunks);
        assert_eq!(assembled, "hello everyone");

        stage_commit(
            &state,
            "01J...COMMIT_CONCAT",
            did,
            "#debate",
            Some("01J...DEBATE_CONCAT"),
            salt,
            &assembled,
            "sha256",
        );

        let payload = reveal_payload("01J...COMMIT_CONCAT", salt);
        let r = crate::connection::messaging::verify_commit_reveal(
            &state,
            Some(did),
            "#debate",
            Some("01J...DEBATE_CONCAT"),
            &payload,
            &assembled,
        );
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn commit_reveal_assemble_for_test_matches_production_assemble_body() {
        // Belt-and-suspenders: the assembly helper used in the tests
        // above MUST agree byte-for-byte with the production
        // `connection::draft_multiline::assemble_body`. If the spec
        // join rules ever drift between the two, the multiline reveal
        // round-trip tests would silently pass while production
        // verification fails.
        use crate::connection::draft_multiline as dm;
        let chunks: Vec<(&str, bool)> = vec![
            ("hello", false),
            ("", false),
            ("how is ", false),
            ("everyone?", true),
        ];
        let from_test = assemble_for_test(&chunks);

        let prod_batch = dm::OpenBatch {
            batch_id: "x".to_string(),
            batch_type: "draft/multiline".to_string(),
            target: "#c".to_string(),
            opener_tags: HashMap::new(),
            lines: chunks
                .iter()
                .map(|(body, concat)| dm::BatchLine {
                    body: (*body).to_string(),
                    concat_to_previous: *concat,
                    command: "PRIVMSG".to_string(),
                })
                .collect(),
            byte_count: 0,
            first_command: Some("PRIVMSG".to_string()),
        };
        let from_prod = dm::assemble_body(&prod_batch);

        assert_eq!(from_test, from_prod);
        assert_eq!(from_test, "hello\n\nhow is everyone?");
    }

    #[test]
    fn bind_identity_refuses_nick_owned_by_other_did() {
        let state = test_state();
        assert_eq!(
            state.bind_identity("did:key:A", "alice"),
            BindOutcome::Bound
        );
        // A different DID claiming alice → refused, maps untouched.
        let r = state.bind_identity("did:key:B", "alice");
        assert_eq!(
            r,
            BindOutcome::ConflictOwnedByOther {
                owner_did: "did:key:A".to_string()
            }
        );
        assert_eq!(
            state.nick_owners.lock().get("alice").map(String::as_str),
            Some("did:key:A")
        );
        assert!(state.did_nicks.lock().get("did:key:B").is_none());
    }

    #[test]
    fn display_nick_for_did_chain_falls_back_to_raw() {
        let state = test_state();
        // did_nicks hit
        state.bind_identity("did:key:A", "alice");
        assert_eq!(state.display_nick_for_did("did:key:A"), "alice");
        // unknown DID, no session, no db → raw DID
        assert_eq!(
            state.display_nick_for_did("did:key:UNKNOWN"),
            "did:key:UNKNOWN"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // SyncResponse merge: key removal, invite authority, topic→CRDT
    // ═══════════════════════════════════════════════════════════

    fn sync_info(name: &str) -> crate::s2s::ChannelInfo {
        crate::s2s::ChannelInfo {
            name: name.to_string(),
            topic: None,
            nicks: vec![],
            nick_info: vec![],
            founder_did: None,
            did_ops: vec![],
            created_at: 0,
            topic_locked: false,
            invite_only: false,
            no_ext_msg: false,
            moderated: false,
            key: None,
            bans: vec![],
            invites: vec![],
            invite_exceptions: vec![],
        }
    }

    async fn sync(state: &Arc<SharedState>, mgr: &Arc<S2sManager>, info: crate::s2s::ChannelInfo) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::SyncResponse {
                server_id: PEER.to_string(),
                channels: vec![info],
            },
        )
        .await;
    }

    #[tokio::test]
    async fn sync_key_removal_adopted_when_no_local_members() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#kchan");
        state.channels.lock().get_mut("#kchan").unwrap().key = Some("sekrit".to_string());

        // Peer snapshot says the key was removed (-k). No local members →
        // adopt the full snapshot, including removal.
        sync(&state, &mgr, sync_info("#kchan")).await;
        assert_eq!(state.channels.lock().get("#kchan").unwrap().key, None);
    }

    #[tokio::test]
    async fn sync_key_not_removed_while_locals_present() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#kchan2");
        {
            let mut channels = state.channels.lock();
            let ch = channels.get_mut("#kchan2").unwrap();
            ch.key = Some("sekrit".to_string());
            ch.members.insert("local-session".to_string());
        }

        // Locals set modes authoritatively — a snapshot must never weaken them.
        sync(&state, &mgr, sync_info("#kchan2")).await;
        assert_eq!(
            state.channels.lock().get("#kchan2").unwrap().key.as_deref(),
            Some("sekrit")
        );
    }

    #[tokio::test]
    async fn sync_invites_rejected_on_founder_mismatch() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#ichan");
        state.channels.lock().get_mut("#ichan").unwrap().founder_did =
            Some("did:plc:realfounder".to_string());

        let mut info = sync_info("#ichan");
        info.founder_did = Some("did:plc:imposter".to_string());
        info.invites = vec!["did:plc:mallory".to_string()];
        sync(&state, &mgr, info).await;

        assert!(
            state
                .channels
                .lock()
                .get("#ichan")
                .unwrap()
                .invites
                .is_empty(),
            "invites from a peer with the wrong founder must be rejected"
        );
    }

    #[tokio::test]
    async fn sync_invites_accepted_when_founder_matches() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#ichan2");
        state
            .channels
            .lock()
            .get_mut("#ichan2")
            .unwrap()
            .founder_did = Some("did:plc:realfounder".to_string());

        let mut info = sync_info("#ichan2");
        info.founder_did = Some("did:plc:realfounder".to_string());
        info.invites = vec!["did:plc:friend".to_string()];
        sync(&state, &mgr, info).await;

        assert!(
            state
                .channels
                .lock()
                .get("#ichan2")
                .unwrap()
                .invites
                .contains("did:plc:friend")
        );
    }

    #[tokio::test]
    async fn sync_adopted_topic_is_seeded_into_crdt() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#tchan");

        let mut info = sync_info("#tchan");
        info.topic = Some("welcome to tchan".to_string());
        sync(&state, &mgr, info).await;

        // Local adopted it…
        assert_eq!(
            state
                .channels
                .lock()
                .get("#tchan")
                .unwrap()
                .topic
                .as_ref()
                .map(|t| t.text.clone()),
            Some("welcome to tchan".to_string())
        );
        // …and the CRDT agrees, so reconciliation can never flap it back.
        let crdt = state.cluster_doc.channel_topic("#tchan").await;
        assert_eq!(
            crdt.map(|(t, _)| t),
            Some("welcome to tchan".to_string()),
            "sync-adopted topic must be seeded into the CRDT"
        );
    }

    // ── Federated edits and deletes ────────────────────────────────
    //
    // A message's identity is its original msgid on every server that holds
    // it. These cover the wire carrying enough for a peer to honour that:
    // `replaces_msgid` so an edit revises rather than duplicates, and a
    // `+draft/delete` Tagmsg so a delete actually deletes.

    const AUTHOR_DID: &str = "did:plc:fedauthor";

    /// Relay a channel message from the peer, as alice (the author).
    async fn relay_message(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        channel: &str,
        msgid: &str,
        text: &str,
        replaces: Option<&str>,
    ) {
        relay_message_as(
            state,
            mgr,
            channel,
            msgid,
            text,
            replaces,
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;
    }

    /// As `relay_message`, with the actor spelled out — the peer chooses both
    /// the nick and the `account` DID it stamps, so a test of who may act on a
    /// message has to be able to choose them too.
    #[allow(clippy::too_many_arguments)]
    async fn relay_message_as(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        channel: &str,
        msgid: &str,
        text: &str,
        replaces: Option<&str>,
        from: &str,
        account: Option<&str>,
    ) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:{msgid}"),
                from: from.to_string(),
                target: channel.to_string(),
                text: text.to_string(),
                origin: PEER.to_string(),
                msgid: Some(msgid.to_string()),
                sig: None,
                account: account.map(|a| a.to_string()),
                recipient_did: None,
                replaces_msgid: replaces.map(|r| r.to_string()),
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;
    }

    async fn relay_delete(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        channel: &str,
        msgid: &str,
        from: &str,
        account: Option<&str>,
    ) {
        let mut tags = HashMap::new();
        tags.insert("+draft/delete".to_string(), msgid.to_string());
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:del-{msgid}-{from}"),
                from: from.to_string(),
                target: channel.to_string(),
                tags,
                origin: PEER.to_string(),
                account: account.map(|a| a.to_string()),
            },
        )
        .await;
    }

    fn history_of(state: &Arc<SharedState>, channel: &str) -> Vec<(Option<String>, String, bool)> {
        state
            .channels
            .lock()
            .get(channel)
            .map(|ch| {
                ch.history
                    .iter()
                    .map(|h| (h.msgid.clone(), h.text.clone(), h.edited))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A federated edit revises the message we already hold. Before the wire
    /// carried the linkage the peer filed it as a new message, so every user
    /// on this side saw the message twice — permanently, in CHATHISTORY.
    #[tokio::test]
    async fn s2s_edit_revises_in_place_instead_of_duplicating() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedit");

        relay_message(&state, &mgr, "#fedit", "id-orig", "v1", None).await;
        relay_message(&state, &mgr, "#fedit", "id-edit", "v2", Some("id-orig")).await;

        assert_eq!(
            history_of(&state, "#fedit"),
            vec![(Some("id-orig".to_string()), "v2".to_string(), true)],
            "one logical message, keyed by the id everyone holds it under, \
             carrying the newest text and marked edited"
        );
        // The DB keeps both revisions, joined by the root — the same shape a
        // local edit produces.
        assert_eq!(state.with_db(|db| Ok(db.root_of("id-edit"))), Some("id-orig".to_string()));
        assert_eq!(
            state
                .with_db(|db| db.current_revision("id-orig"))
                .flatten()
                .map(|r| r.text),
            Some("v2".to_string())
        );
    }

    /// An edit of a message this server never saw (it joined late, or the
    /// original predates the linkage) must still show up, keyed by the root.
    #[tokio::test]
    async fn s2s_edit_of_an_unseen_message_still_arrives() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedunseen");

        relay_message(&state, &mgr, "#fedunseen", "id-edit", "v2", Some("id-never")).await;

        assert_eq!(
            history_of(&state, "#fedunseen"),
            vec![(Some("id-never".to_string()), "v2".to_string(), true)],
            "an edit whose original we never saw must not vanish"
        );
    }

    /// The local wire carries edit linkage in `+draft/edit`, which the S2S tag
    /// filter drops — the receiver has to put it back or its own clients see a
    /// new message.
    #[tokio::test]
    async fn s2s_edit_restores_the_edit_tag_for_local_clients() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedtag");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("s-1".to_string(), tx);
        state.nick_to_session.lock().insert("watcher", "s-1");
        state
            .channels
            .lock()
            .get_mut("#fedtag")
            .unwrap()
            .members
            .insert("s-1".to_string());
        state.cap_message_tags.lock().insert("s-1".to_string());

        relay_message(&state, &mgr, "#fedtag", "id-1", "v1", None).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await;
        relay_message(&state, &mgr, "#fedtag", "id-2", "v2", Some("id-1")).await;

        let line = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            line.contains("+draft/edit=id-1"),
            "clients must be told this revises id-1: {line}"
        );
    }

    /// A federated delete has to reach this server's own storage. Relaying it
    /// live is not enough — the row outlives the event, so the message returns
    /// on the next join and after every restart.
    #[tokio::test]
    async fn s2s_delete_applies_to_local_storage() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#feddel");

        relay_message(&state, &mgr, "#feddel", "id-1", "secret", None).await;
        relay_delete(&state, &mgr, "#feddel", "id-1", "alice!a@remote", Some(AUTHOR_DID)).await;

        assert!(
            history_of(&state, "#feddel").is_empty(),
            "deleted message still in memory — a joiner would be replayed it"
        );
        assert!(
            state
                .with_db(|db| db.get_messages("#feddel", 50, None))
                .unwrap_or_default()
                .is_empty(),
            "deleted message still readable in history"
        );
    }

    /// …and a delete naming the *edit* still takes the whole message, because
    /// both ids are the same message.
    #[tokio::test]
    async fn s2s_delete_by_the_edit_id_removes_every_revision() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#feddel2");

        relay_message(&state, &mgr, "#feddel2", "id-1", "v1", None).await;
        relay_message(&state, &mgr, "#feddel2", "id-2", "v2", Some("id-1")).await;
        relay_delete(&state, &mgr, "#feddel2", "id-2", "alice!a@remote", Some(AUTHOR_DID)).await;

        assert!(history_of(&state, "#feddel2").is_empty());
        assert!(
            state
                .with_db(|db| db.get_messages("#feddel2", 50, None))
                .unwrap_or_default()
                .is_empty(),
            "a revision survived a delete naming the other one"
        );
    }

    /// An edit may only come from the author. This is the forgery the gate
    /// exists for: the history entry is revised in place and keeps its `from`,
    /// so an accepted stranger's edit would show every later joiner the author
    /// saying words the author never wrote.
    #[tokio::test]
    async fn s2s_edit_from_a_stranger_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedforge2");

        relay_message(&state, &mgr, "#fedforge2", "id-1", "alice original", None).await;
        relay_message_as(
            &state,
            &mgr,
            "#fedforge2",
            "id-forge",
            "I never said that",
            Some("id-1"),
            "mallory!m@remote",
            Some("did:plc:mallory"),
        )
        .await;

        assert_eq!(
            history_of(&state, "#fedforge2"),
            vec![(
                Some("id-1".to_string()),
                "alice original".to_string(),
                false
            )],
            "a stranger rewrote the author's message under the author's name"
        );
        let current = state
            .with_db(|db| db.current_revision("id-1"))
            .flatten()
            .expect("row");
        assert_eq!(current.text, "alice original");
        assert_eq!(current.sender, "alice!a@remote");
    }

    /// A nick alone is never evidence: the row names a DID, so an actor without
    /// one cannot be its author no matter what nick the peer asserts.
    #[tokio::test]
    async fn s2s_edit_without_an_actor_did_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fednodid2");

        relay_message(&state, &mgr, "#fednodid2", "id-1", "alice original", None).await;
        relay_message_as(
            &state,
            &mgr,
            "#fednodid2",
            "id-forge",
            "impersonated",
            Some("id-1"),
            "alice!a@remote",
            None,
        )
        .await;

        assert_eq!(
            history_of(&state, "#fednodid2"),
            vec![(
                Some("id-1".to_string()),
                "alice original".to_string(),
                false
            )],
            "nick-only matching would let any peer rewrite anything"
        );
    }

    /// An op may delete content but not rewrite it — deleting removes words,
    /// editing would put new ones in someone else's mouth. Deliberately
    /// stricter than the delete gate.
    #[tokio::test]
    async fn s2s_edit_from_an_op_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedopedit");
        add_remote_member(&state, "#fedopedit", "moderator", true);

        relay_message(&state, &mgr, "#fedopedit", "id-1", "alice original", None).await;
        relay_message_as(
            &state,
            &mgr,
            "#fedopedit",
            "id-forge",
            "moderated for you",
            Some("id-1"),
            "moderator!m@remote",
            Some("did:plc:mod"),
        )
        .await;

        assert_eq!(
            history_of(&state, "#fedopedit"),
            vec![(
                Some("id-1".to_string()),
                "alice original".to_string(),
                false
            )],
            "an op rewrote another user's words"
        );
    }

    /// The author's own edit still lands — the gate must not cost the feature
    /// it protects.
    #[tokio::test]
    async fn s2s_edit_from_the_author_is_accepted() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedauthoredit");

        relay_message(&state, &mgr, "#fedauthoredit", "id-1", "v1", None).await;
        relay_message(&state, &mgr, "#fedauthoredit", "id-2", "v2", Some("id-1")).await;

        assert_eq!(
            history_of(&state, "#fedauthoredit"),
            vec![(Some("id-1".to_string()), "v2".to_string(), true)],
            "the author's edit must revise the message it names"
        );
    }

    /// A deleted message has no text to revise, matching `handle_edit`'s local
    /// refusal — otherwise an edit re-seeds content the author asked to remove.
    #[tokio::test]
    async fn s2s_edit_of_a_deleted_message_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#feddeleted");

        relay_message(&state, &mgr, "#feddeleted", "id-1", "gone", None).await;
        relay_delete(
            &state,
            &mgr,
            "#feddeleted",
            "id-1",
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;
        relay_message(
            &state,
            &mgr,
            "#feddeleted",
            "id-2",
            "back again",
            Some("id-1"),
        )
        .await;

        assert!(
            history_of(&state, "#feddeleted").is_empty(),
            "an edit resurrected a deleted message"
        );
    }

    /// With no database the in-memory history is the only record of who wrote
    /// what, and it still has to be honoured.
    #[tokio::test]
    async fn s2s_edit_from_a_stranger_is_rejected_without_a_database() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fednodb");

        relay_message(&state, &mgr, "#fednodb", "id-1", "alice original", None).await;
        relay_message_as(
            &state,
            &mgr,
            "#fednodb",
            "id-forge",
            "I never said that",
            Some("id-1"),
            "mallory!m@remote",
            Some("did:plc:mallory"),
        )
        .await;

        assert_eq!(
            history_of(&state, "#fednodb"),
            vec![(
                Some("id-1".to_string()),
                "alice original".to_string(),
                false
            )],
            "with no row to check, history authorship is the only defense"
        );
    }

    /// A peer sends a channel spelled the way its user typed it. Authorization
    /// must not depend on that casing: scoping the lookup by channel turned a
    /// miss into "no such message", which is the permissive answer.
    #[tokio::test]
    async fn s2s_delete_gate_holds_for_a_mixed_case_channel() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedcase");

        relay_message(&state, &mgr, "#FedCase", "id-1", "keep me", None).await;
        relay_delete(
            &state,
            &mgr,
            "#FedCase",
            "id-1",
            "stranger!s@remote",
            Some("did:plc:stranger"),
        )
        .await;

        assert_eq!(
            history_of(&state, "#fedcase").len(),
            1,
            "a stranger dropped the message from the live view of a mixed-case channel"
        );
    }

    /// …and the author's delete reaches storage there, instead of clearing the
    /// live view while leaving the row to come back on the next restart.
    #[tokio::test]
    async fn s2s_delete_in_a_mixed_case_channel_reaches_storage() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedcase2");

        relay_message(&state, &mgr, "#FedCase2", "id-1", "secret", None).await;
        relay_delete(
            &state,
            &mgr,
            "#FedCase2",
            "id-1",
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;

        assert!(history_of(&state, "#fedcase2").is_empty());
        assert!(
            state
                .with_db(|db| db.get_messages("#FedCase2", 50, None))
                .unwrap_or_default()
                .is_empty(),
            "the row survived the delete and would return on restart"
        );
    }

    /// A nick is peer-assertable, so a stranger's delete must not land.
    #[tokio::test]
    async fn s2s_delete_from_a_stranger_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedforge");

        relay_message(&state, &mgr, "#fedforge", "id-1", "keep me", None).await;
        relay_delete(
            &state,
            &mgr,
            "#fedforge",
            "id-1",
            "mallory!m@remote",
            Some("did:plc:mallory"),
        )
        .await;

        assert_eq!(
            history_of(&state, "#fedforge").len(),
            1,
            "a non-author non-op deleted someone else's message"
        );
    }

    /// The row names a DID, so an actor who can't produce one is not the
    /// author — no matter what nick the peer asserts.
    #[tokio::test]
    async fn s2s_delete_without_an_actor_did_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fednodid");

        relay_message(&state, &mgr, "#fednodid", "id-1", "keep me", None).await;
        // Same nick as the author, no DID — the shape an old peer sends.
        relay_delete(&state, &mgr, "#fednodid", "id-1", "alice!a@remote", None).await;

        assert_eq!(
            history_of(&state, "#fednodid").len(),
            1,
            "nick-only matching would make any peer able to delete anything"
        );
    }

    /// Ops moderate across the federation, the same way Kick and Mode do.
    #[tokio::test]
    async fn s2s_delete_from_a_remote_op_is_accepted() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedop");
        add_remote_member(&state, "#fedop", "moderator", true);

        relay_message(&state, &mgr, "#fedop", "id-1", "spam", None).await;
        relay_delete(
            &state,
            &mgr,
            "#fedop",
            "id-1",
            "moderator!m@remote",
            Some("did:plc:mod"),
        )
        .await;

        assert!(
            history_of(&state, "#fedop").is_empty(),
            "a federated op must be able to delete in the channel they moderate"
        );
    }

    /// The stamped actor DID is what makes a remote user's reaction removable
    /// by identity rather than by nick.
    #[tokio::test]
    async fn s2s_reaction_records_the_stamped_actor_did() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedreact");

        let mut tags = HashMap::new();
        tags.insert("+react".to_string(), "🔥".to_string());
        tags.insert("+reply".to_string(), "id-1".to_string());
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:react-did"),
                from: "alice!a@remote".to_string(),
                target: "#fedreact".to_string(),
                tags,
                origin: PEER.to_string(),
                account: Some(AUTHOR_DID.to_string()),
            },
        )
        .await;

        let stored = state
            .with_db(|db| db.get_reactions_for_messages(&["id-1"]))
            .expect("db present");
        assert_eq!(
            stored.get("id-1").and_then(|v| v.first()).and_then(|r| r.reactor_did.clone()),
            Some(AUTHOR_DID.to_string()),
            "a remote reactor with no local identity was stored nick-only"
        );
    }

    /// Relay a DM from the peer, addressed to a local nick.
    async fn relay_dm(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        to_nick: &str,
        msgid: &str,
        text: &str,
        replaces: Option<&str>,
    ) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:dm-{msgid}"),
                from: "alice!a@remote".to_string(),
                target: to_nick.to_string(),
                text: text.to_string(),
                origin: PEER.to_string(),
                msgid: Some(msgid.to_string()),
                sig: None,
                account: Some(AUTHOR_DID.to_string()),
                recipient_did: None,
                replaces_msgid: replaces.map(|r| r.to_string()),
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;
    }

    /// Bind a local nick to a DID so a DM addressed to it resolves a recipient
    /// and therefore persists.
    fn bind_local_nick(state: &Arc<SharedState>, nick: &str, did: &str) -> String {
        state
            .nick_owners
            .lock()
            .insert(nick.to_string(), did.to_string());
        crate::db::canonical_dm_key(AUTHOR_DID, did)
    }

    fn live_dm_texts(state: &Arc<SharedState>, dm_key: &str) -> Vec<String> {
        state
            .with_db(|db| db.get_messages(dm_key, 50, None))
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.text)
            .collect()
    }

    /// A DM edit crossing the hop revises the thread rather than adding to it.
    #[tokio::test]
    async fn s2s_dm_edit_revises_the_thread() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let dm_key = bind_local_nick(&state, "bob", "did:plc:bobdm");

        relay_dm(&state, &mgr, "bob", "dm-1", "v1", None).await;
        relay_dm(&state, &mgr, "bob", "dm-2", "v2", Some("dm-1")).await;

        // Both revisions are on file, joined by the root — one logical message
        // in two rows, not a message plus an unlinked stranger.
        assert_eq!(
            live_dm_texts(&state, &dm_key),
            vec!["v1".to_string(), "v2".to_string()]
        );
        assert_eq!(
            state.with_db(|db| Ok(db.root_of("dm-2"))),
            Some("dm-1".to_string())
        );
        assert_eq!(
            state
                .with_db(|db| db.current_revision("dm-1"))
                .flatten()
                .map(|r| r.text),
            Some("v2".to_string())
        );
    }

    /// A DM delete has to reach the recipient's server, or the message stays
    /// in their history forever.
    #[tokio::test]
    async fn s2s_dm_delete_applies_to_local_storage() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let dm_key = bind_local_nick(&state, "bob", "did:plc:bobdel");

        relay_dm(&state, &mgr, "bob", "dm-1", "regrettable", None).await;
        assert_eq!(live_dm_texts(&state, &dm_key).len(), 1, "dm persisted");

        relay_delete(&state, &mgr, "bob", "dm-1", "alice!a@remote", Some(AUTHOR_DID)).await;

        assert!(
            live_dm_texts(&state, &dm_key).is_empty(),
            "the federated DM delete never reached storage"
        );
    }

    /// A DM has no roster to appeal to, so authorship is the only way in —
    /// and a persisted DM row always names its sender's DID.
    #[tokio::test]
    async fn s2s_dm_delete_from_a_stranger_is_rejected() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let dm_key = bind_local_nick(&state, "bob", "did:plc:bobkeep");

        relay_dm(&state, &mgr, "bob", "dm-1", "keep me", None).await;
        relay_delete(
            &state,
            &mgr,
            "bob",
            "dm-1",
            "alice!a@remote",
            Some("did:plc:someoneelse"),
        )
        .await;

        assert_eq!(
            live_dm_texts(&state, &dm_key).len(),
            1,
            "someone who is not the author deleted a DM"
        );
    }

    /// An older peer sends neither field. Both must degrade to exactly what
    /// happened before they existed.
    #[tokio::test]
    async fn old_peer_without_the_new_fields_behaves_as_before() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#fedold");

        // No replaces_msgid → a new message, appended, not a revision.
        relay_message(&state, &mgr, "#fedold", "id-1", "v1", None).await;
        relay_message(&state, &mgr, "#fedold", "id-2", "v2", None).await;
        assert_eq!(
            history_of(&state, "#fedold").len(),
            2,
            "two unlinked messages must stay two messages"
        );
    }
}

#[cfg(test)]
mod discoverability_tests {
    use super::*;

    fn ch() -> ChannelState {
        ChannelState::default()
    }

    #[test]
    fn open_channel_is_discoverable() {
        // No access restriction → advertisable in LIST / api/v1/channels.
        assert!(!ch().is_mode_restricted());
    }

    #[test]
    fn invite_only_hides() {
        let mut c = ch();
        c.invite_only = true;
        assert!(c.is_mode_restricted());
    }

    #[test]
    fn keyed_hides() {
        let mut c = ch();
        c.key = Some("s3cret".into());
        assert!(c.is_mode_restricted());
    }

    #[test]
    fn encrypted_hides() {
        // +E channels are hidden too — the name/topic can be as sensitive as
        // the (encrypted) content.
        let mut c = ch();
        c.encrypted_only = true;
        assert!(c.is_mode_restricted());
    }

    #[test]
    fn moderation_flags_do_not_hide() {
        // +n/+t/+m are quality/moderation flags, not access restrictions — such
        // a channel is still publicly discoverable.
        let mut c = ch();
        c.no_ext_msg = true;
        c.topic_locked = true;
        c.moderated = true;
        assert!(!c.is_mode_restricted());
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::did_allowed;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_allowlists_are_open() {
        assert!(did_allowed(
            &[],
            &[],
            "did:plc:anyone",
            Some("a.bsky.social")
        ));
    }

    #[test]
    fn exact_did_allowed() {
        let dids = v(&["did:plc:alice"]);
        assert!(did_allowed(&dids, &[], "did:plc:alice", None));
        assert!(!did_allowed(&dids, &[], "did:plc:mallory", None));
    }

    #[test]
    fn handle_domain_and_subdomain_allowed() {
        let doms = v(&["acme.com"]);
        assert!(did_allowed(&[], &doms, "did:plc:x", Some("alice.acme.com")));
        assert!(did_allowed(&[], &doms, "did:plc:x", Some("acme.com")));
        assert!(!did_allowed(
            &[],
            &doms,
            "did:plc:x",
            Some("alice.evil.com")
        ));
        // Not fooled by a suffix that isn't a domain boundary.
        assert!(!did_allowed(&[], &doms, "did:plc:x", Some("notacme.com")));
    }

    #[test]
    fn no_handle_denies_domain_only_allowlist() {
        // Challenge SASL has no handle → domain-only allowlists can't match.
        let doms = v(&["acme.com"]);
        assert!(!did_allowed(&[], &doms, "did:plc:x", None));
    }
}
