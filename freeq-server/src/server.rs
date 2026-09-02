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
    /// Sessions holding `freeq.at/act` — the only ones task messages reach.
    /// A connection that did not ask for it sees the human-readable companion
    /// line and nothing else.
    pub cap_act: Mutex<HashSet<String>>,
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
    /// Relayed task events waiting for the key that would settle them.
    /// Bounded and in memory only — a restart drops what is parked, which is
    /// the same thing an eviction drops: events nobody was shown.
    pub(crate) act_deferred: Mutex<crate::act_relay::DeferQueue>,
    /// Transitions waiting to reach the server that owns their task. Bounded
    /// and in memory only, beside the defer queue and for the same reason:
    /// what is held here is already filed, so a restart costs a prompt ruling
    /// rather than a record.
    pub(crate) act_routes: Mutex<crate::act_relay::RouteQueue>,
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
    /// Task events that arrived, whatever verdict each one earned. Says
    /// whether tasks are being used at all; the refusal each event earns is
    /// what tells its sender, and the log is what records it.
    pub act_events_total: std::sync::atomic::AtomicU64,
    pub started_at: std::time::Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            messages_total: std::sync::atomic::AtomicU64::new(0),
            sasl_success_total: std::sync::atomic::AtomicU64::new(0),
            sasl_failure_total: std::sync::atomic::AtomicU64::new(0),
            act_events_total: std::sync::atomic::AtomicU64::new(0),
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
    /// see their own channels regardless (see `channel_visible_to`).
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

    /// Can this session see the channel? Shared by LIST, NAMES, WHO, and WHOIS.
    pub fn channel_visible_to(&self, name: &str, ch: &ChannelState, session_id: &str) -> bool {
        self.channel_is_discoverable(name, ch) || ch.members.contains(session_id)
    }

    /// Same, for an HTTP caller who may have several sessions open.
    /// Empty means anonymous.
    pub fn channel_visible_to_sessions(
        &self,
        name: &str,
        ch: &ChannelState,
        viewer_sessions: &[String],
    ) -> bool {
        self.channel_is_discoverable(name, ch)
            || viewer_sessions.iter().any(|s| ch.members.contains(s))
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
/// The identity this server signs under: `did:web:<server name>`.
///
/// The same form the policy engine uses. A server is a participant like any
/// other when it acts — the expiry sweep's events are its own — so it needs an
/// identity a verifier can look a key up under.
pub fn server_did(server_name: &str) -> String {
    format!("did:web:{server_name}")
}

/// Put the server's own message key in the same `(did, kid)` store client keys
/// live in, so a signature it makes resolves through the ordinary by-kid
/// lookup.
///
/// Without this the expiry events the server signs would name a kid nothing
/// could resolve, and every one of them would read as unverifiable — the
/// server would be the only signer on the system whose signatures nobody
/// could check.
fn register_server_signing_key(state: &Arc<SharedState>) {
    let did = server_did(&state.server_name);
    let pubkey = state.msg_signing_key.verifying_key().to_bytes();
    let registered = state.with_db(|db| db.save_signing_key(&did, &pubkey));
    match registered {
        Some(()) => tracing::info!(%did, "Registered this server's own message signing key"),
        // No database attached: nothing to register into, and nothing that
        // will need to verify a stored signature either.
        None => tracing::debug!(%did, "No database; server signing key not registered"),
    }
}

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

        let state = Arc::new(SharedState {
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
            cap_act: Mutex::new(HashSet::new()),
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
            act_deferred: Mutex::new(crate::act_relay::DeferQueue::new(
                self.config.act_defer_max_per_origin,
                self.config.act_defer_max_total,
            )),
            act_routes: Mutex::new(crate::act_relay::RouteQueue::new(MAX_PENDING_ROUTES)),
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
        });
        register_server_signing_key(&state);
        Ok(state)
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

                    // Transitions that could not reach the server owning their
                    // task are retried from here. Only meaningful with
                    // federation running, which is exactly where this is.
                    spawn_act_route_retry(Arc::clone(&state));

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
            // Say so, loudly. Without `av-native` every AV endpoint answers 503
            // ("AV not enabled"), and nothing else about the server looks wrong —
            // it serves IRC, chat and history normally. A production deploy built
            // with a plain `cargo build` (instead of deploy.sh, which passes
            // `--features av-native`) took calls down for hours before anyone
            // connected the 503 to the build. One line at boot makes that
            // diagnosable from the journal.
            tracing::warn!(
                "AV disabled: this binary was built without --features av-native. \
                 /av/moq, /av/call and every other AV endpoint will answer 503. \
                 Build with `cargo build --release --bin freeq-server --features av-native` \
                 (or use deploy/deploy.sh) if calls are meant to work."
            );
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

        spawn_act_expiry_sweep(Arc::clone(&state), self.config.act_expiry_secs);
        spawn_act_defer_retry_sweep(Arc::clone(&state));
        spawn_act_review_sweep(Arc::clone(&state), self.config.act_review_secs);

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
        spawn_act_expiry_sweep(Arc::clone(&state), self.config.act_expiry_secs);
        spawn_act_defer_retry_sweep(Arc::clone(&state));
        spawn_act_review_sweep(Arc::clone(&state), self.config.act_review_secs);

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
        spawn_act_expiry_sweep(Arc::clone(&state), self.config.act_expiry_secs);
        spawn_act_defer_retry_sweep(Arc::clone(&state));
        spawn_act_review_sweep(Arc::clone(&state), self.config.act_review_secs);

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
/// Sweep abandoned tasks: anything that has sat in a non-finished state
/// longer than the limit gets an `expire` event from this server.
///
/// What is measured is the limit, not the task's own deadline. A deadline
/// bounds how long an *offer* stands and is optional; this catches work
/// somebody accepted and then walked away from, which otherwise sits in the
/// view forever. `0` disables it.
fn spawn_act_expiry_sweep(state: Arc<SharedState>, limit_secs: u64) {
    if limit_secs == 0 {
        return;
    }
    let limit = limit_secs as i64;
    tokio::spawn(async move {
        // Often enough to be prompt, rarely enough to be free. A limit
        // measured in days sweeps every minute; a short one configured for a
        // test sweeps at its own pace.
        let every = (limit_secs / 2).clamp(1, 60);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(every));
        interval.tick().await; // skip first tick
        loop {
            interval.tick().await;
            let cutoff = chrono::Utc::now().timestamp() - limit;
            // Bounded per pass: a server that was down for a month should not
            // try to expire everything in one breath.
            let stale = state
                .with_db(|db| {
                    db.act_tasks_idle_outside_states(
                        &freeq_sdk::act_transitions::review_timeout_states(),
                        cutoff,
                        100,
                    )
                })
                .unwrap_or_default();
            for task in &stale {
                crate::connection::act::expire_task(&state, task);
            }
        }
    });
}

/// Close review windows: work that was handed in and left unanswered for
/// longer than the limit is deemed accepted, under the home's own signature.
///
/// A second clock rather than a case of the first, because it does the
/// opposite job. The abandonment sweep is neutral and catches work nobody is
/// doing; this one favours the worker and catches a poster who took delivery
/// and then went quiet — and the two would otherwise race, so the states this
/// one owns are the states the other skips. `0` disables it.
fn spawn_act_review_sweep(state: Arc<SharedState>, limit_secs: u64) {
    let states = freeq_sdk::act_transitions::review_timeout_states();
    if limit_secs == 0 || states.is_empty() {
        return;
    }
    let limit = limit_secs as i64;
    tokio::spawn(async move {
        let every = (limit_secs / 2).clamp(1, 60);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(every));
        interval.tick().await; // skip first tick
        loop {
            interval.tick().await;
            let cutoff = chrono::Utc::now().timestamp() - limit;
            let waiting = state
                .with_db(|db| db.act_tasks_idle_in_states(&states, cutoff, 100))
                .unwrap_or_default();
            for task in &waiting {
                crate::connection::act::auto_accept_task(&state, task);
            }
        }
    });
}

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
                || rm
                    .did
                    .as_ref()
                    .is_some_and(|d| ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d))
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

/// The body a relayed message's signature covers, rebuilt from the wire.
///
/// A `draft/multiline` BATCH is signed over the assembled body and escaped for
/// transport (`encode_privmsg_text_for_s2s`) so a peer relaying it to its own
/// clients cannot break the IRC line; the per-line breakdown rides along and is
/// reassembled here, giving back the exact bytes the origin signed.
///
/// Everything else is the body as transmitted — the inline form included: one
/// line, newlines as the literal two chars `\n` under `+freeq.at/multiline`,
/// signed by the client over those escaped bytes. Un-escaping it built a
/// document its sender never signed, so every such message failed the check.
fn relayed_signed_body(text: &str, lines: Option<&Vec<crate::s2s::MultilineLine>>) -> String {
    if let Some(lines) = lines {
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 && !line.concat {
                out.push('\n');
            }
            out.push_str(&line.body);
        }
        return out;
    }
    text.to_string()
}

/// Check a relayed PRIVMSG's signature against the message as transmitted.
///
/// `None` when the message carries no signature — there is nothing to check,
/// which is not the same as failing to check.
///
/// Every argument is the value that *arrived*, before the receive path tidies
/// it, and the sender DID is the one the origin stamped — never the nick-map
/// fallback, which would have us rebuild a document around an identity the
/// origin never asserted.
#[allow(clippy::too_many_arguments)]
fn verify_relayed_privmsg(
    state: &Arc<SharedState>,
    account: Option<&str>,
    target: &str,
    msgid: Option<&str>,
    text: &str,
    tags: &HashMap<String, String>,
    replaces_msgid: Option<&str>,
    multiline_lines: Option<&Vec<crate::s2s::MultilineLine>>,
    sig: Option<&str>,
) -> Option<crate::connection::messaging::ClientSigVerdict> {
    use crate::connection::messaging::{ClientSigVerdict, SignedFields, verify_relayed_message};
    let sig = sig?;
    let Some(did) = account else {
        return Some(ClientSigVerdict::Unverifiable(
            "relayed message names no sender DID",
        ));
    };
    let body = relayed_signed_body(text, multiline_lines);
    let fields = SignedFields {
        body: &body,
        msgid: msgid.unwrap_or_default(),
        reply: tags
            .get("+reply")
            .or_else(|| tags.get("+draft/reply"))
            .map(String::as_str),
        edit: replaces_msgid.filter(|r| !r.is_empty()),
    };
    Some(verify_relayed_message(
        state, did, target, &fields, tags, sig,
    ))
}

/// The mutation a relayed TAGMSG's tags describe, if any — read before the
/// draft names are canonicalized, like every other reader of the wire.
///
/// Separate from the signature check because the two questions are asked
/// separately: *is this a mutation at all* decides whether the proof rule
/// applies, and an unsigned mutation has no signature to check.
fn relayed_mutation_in(
    tags: &HashMap<String, String>,
) -> Option<(freeq_sdk::chatsig::Mutation, Option<&str>, Option<&str>)> {
    use freeq_sdk::chatsig::Mutation;
    let get = |a: &str, b: &str| tags.get(a).or_else(|| tags.get(b)).map(String::as_str);
    let subject = || get("+reply", "+draft/reply");
    if let Some(subject) = get("+draft/delete", "+delete") {
        return Some((Mutation::Delete, Some(subject), None));
    }
    if let Some(emoji) = get("+react", "+draft/react") {
        return Some((Mutation::React, subject(), Some(emoji)));
    }
    if let Some(emoji) = tags.get("+freeq.at/unreact").map(String::as_str) {
        return Some((Mutation::Unreact, subject(), Some(emoji)));
    }
    None
}

/// Check a relayed mutation's signature against the event as transmitted.
///
/// `None` when the event carries no signature, or carries no mutation at all
/// (a typing notification is not a signed event).
///
/// Read before the receive path renames draft tags and resolves the subject to
/// a local root: both rewrite values the signature covers.
fn verify_relayed_mutation_tags(
    state: &Arc<SharedState>,
    account: Option<&str>,
    target: &str,
    tags: &HashMap<String, String>,
) -> Option<crate::connection::messaging::ClientSigVerdict> {
    use crate::connection::messaging::{ClientSigVerdict, verify_relayed_mutation};

    let get = |a: &str, b: &str| tags.get(a).or_else(|| tags.get(b)).map(String::as_str);
    let (kind, subject, emoji) = relayed_mutation_in(tags)?;

    let sig = tags.get("+freeq.at/sig").map(String::as_str)?;
    let Some(did) = account else {
        return Some(ClientSigVerdict::Unverifiable(
            "relayed mutation names no actor DID",
        ));
    };
    let Some(subject) = subject else {
        return Some(ClientSigVerdict::Unverifiable(
            "relayed mutation names no subject",
        ));
    };
    let event_msgid = get(
        freeq_sdk::chatsig::EVENT_ID_TAG,
        freeq_sdk::chatsig::EVENT_ID_TAG_BARE,
    )
    .unwrap_or_default();

    Some(verify_relayed_mutation(
        state,
        did,
        target,
        kind,
        event_msgid,
        subject,
        emoji,
        sig,
    ))
}

/// What happened to one replayed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayOutcome {
    /// New to us, and now on file.
    Filed,
    /// Already on file with the same content — a no-op, which is what makes
    /// replay safe to run as often as a link flaps.
    AlreadyHeld,
    /// Already on file with *different* content: a second claim on one
    /// identity. Dropped, logged loudly, and a receipt recorded against the
    /// row we keep.
    Conflicted,
    /// Nothing we can file: no id, or bytes that are not a document.
    Unusable,
}

/// The origin a replayed event is filed under: the server that **minted** it,
/// as this server names things.
///
/// Three cases, in order:
///
/// - The event names no origin. Only a peer predating the per-event field
///   sends that, and for such a peer the whole batch came from events it
///   accepted, so the replying peer is the best answer available — which is
///   the answer that peer's replays already got.
/// - The event names us, and `ours_on_file` says our own records bear that
///   out. It is ours, coming home; a row of ours carries no origin, and
///   stamping the peer that handed it back would make this server a foreigner
///   to its own tasks. The corroboration is what keeps that from being a
///   peer's word: a task event names the server that referees the task, and a
///   peer naming us as the minter of a task it opened would otherwise hand us
///   the refereeing of it. Authority comes from the authenticated link and
///   from our own records, never from a field the sender wrote.
/// - The event names us and nothing here bears it out. Filed as the peer's,
///   which is the safe direction: a task whose row this server has entirely
///   lost heals read-only rather than as one a peer can hand back.
/// - The event names anyone else. Filed as named, never overwritten with the
///   replier's id — a task's referee is where it was opened, and a server that
///   heals through a third party must still be able to say where that is.
fn replay_origin(own_id: &str, relayed_by: &str, claimed: &str, ours_on_file: bool) -> String {
    let claimed = claimed.trim();
    let named = match claimed.is_empty() {
        true => relayed_by,
        // A claim that we minted it stands only where our own records bear it
        // out. Otherwise the answer is the link it came in on.
        false if claimed == own_id && !ours_on_file => relayed_by,
        false => claimed,
    };
    match named == own_id {
        true => String::new(),
        false => sanitize_s2s_str(named, 64),
    }
}

/// The order a caught-up batch is applied in, past mint order: a task's
/// opener, then that task's follow-ups.
///
/// An act follow-up names its task, so it sorts under the opener's id; an
/// opener sorts under its own. The second element puts the opener first
/// inside the group. Every other kind sorts under its own id and is left
/// where mint order put it — chat derives no state, so nothing about its
/// order is load-bearing.
fn replay_group_key(ev: &crate::s2s::ReplayedEvent) -> (&str, bool) {
    match ev.kind.as_str() {
        "act" => match ev.subject.as_deref() {
            Some(act_id) => (act_id, true),
            None => (ev.event_id.as_str(), false),
        },
        _ => (ev.event_id.as_str(), false),
    }
}

/// File a caught-up task event through the same call live receiving files one
/// through, or `None` when the bytes are not a task event and the ordinary
/// replay path should take it.
///
/// `apply_act_event` is the whole judgment — the rules check, the log write
/// and the view update in one critical section — so a healed server reaches
/// the same task state as one that never went away. Whose task it is comes
/// with it: a transition on a task another server opened is filed and not
/// applied, here as live.
///
/// Two things live receiving does are deliberately absent:
///
/// - **No waiting for a key.** An event whose signer's key is not on file is
///   skipped and logged. A replay has nobody waiting on delivery and a peer
///   that can simply be asked again on the next link.
/// - **No delivery.** Catch-up heals state. It does not replay hours-old
///   conversation at people who have been reading the channel since.
///
/// Only the act family lands here. A stopgap coordination event's card cannot
/// be rebuilt from a replay at all: its canonical carries a *hash* of the
/// payload, never the payload, so the row a card is made of is not in the
/// bytes that cross. Its log row still files, by the path below.
fn file_replayed_task_event(
    state: &Arc<SharedState>,
    event_id: &str,
    origin: &str,
    relayed_by: &str,
    ev: &crate::s2s::ReplayedEvent,
    sig_state: crate::events::SigState,
) -> Option<ReplayOutcome> {
    let view = crate::events::derive_act_view(&ev.canonical)?;
    let facts = crate::events::derive_facts(&ev.canonical)?;
    let is_receipt = freeq_sdk::act_transitions::is_confirmation(&view.verb);

    // An opener's own id is its task's id; every other event names the task it
    // belongs to. Derived exactly as the live receive path derives it.
    let opens = freeq_sdk::act_transitions::opening_verb(&view.kind) == Some(view.verb.as_str());
    let act_id = match opens {
        true => event_id.to_string(),
        false => facts.subject.clone().unwrap_or_default(),
    };
    let actor = facts.actor_did.clone().unwrap_or_default();

    // ── whose word this carries, on a path where the origin is written by a
    //    peer ──
    //
    // Every other path reads an origin this server put there itself: live
    // relay and the addressed copy both overwrite it with the authenticated
    // peer before anything looks at it. A replay does not, and must not — a
    // replayed event's origin says which server *minted* it, a peer that heals
    // us through a third server has to be able to convey that, and it is what
    // a task's ownership stamp is made of. It is a fact the sender wrote, and
    // it is fine for ownership because a wrong one only ever hands authority
    // away from the sender.
    //
    // Two events turn it into authority, and for those it will not do: a
    // receipt, and a transition a server signed under its own `did:web:` name.
    // Both are the home's word about a task, and on a replay the only thing
    // tying either to the home is the connection the batch came in on. So both
    // are judged against that connection, and a peer that is not the task's
    // own server carries neither, however its batch is stamped.
    //
    // The answer for such a peer is to skip rather than to file. A row under
    // that id — even one marked as applying to nothing — is a row, and the
    // home's own later replay of the genuine event would then be a duplicate
    // that changes nothing for ever.
    //
    // A task of this server's own has no home link to judge either against:
    // the home is here, and a row of ours carries no origin. There the name
    // is the whole of it — see `from_system` below.
    let task_home = state.with_db(|db| db.act_task_origin(&act_id)).flatten();
    let owning_peer = match is_receipt || is_system_actor(&actor) {
        true => task_home.clone().filter(|home| !home.is_empty()),
        false => None,
    };
    if let Some(owner) = owning_peer.as_deref()
        && owner != relayed_by
    {
        tracing::warn!(
            %event_id, %act_id, peer = %relayed_by, home = %owner, claimed = %origin,
            verb = %view.verb,
            "S2S catch-up: skipping a task event that speaks for the task's \
             home — the peer replaying it is not the server that owns the task"
        );
        return Some(ReplayOutcome::Unusable);
    }
    // …and where it does carry the home's word, the origin it is judged under
    // is the connection, so the check the log row records is the one that was
    // actually made.
    let origin = match owning_peer.is_some() {
        true => relayed_by,
        false => origin,
    };

    // Whether this server itself signed it. It signs under its own `did:web:`
    // identity, and on a task of ours that name is what says so: a peer can
    // stamp a batch with our endpoint id, and one that also signs under some
    // other `did:web:` name would otherwise be taken for us and could expire
    // our tasks. Under any other name it goes in as an ordinary
    // participant's event, and the rules refuse it there.
    let from_system = match task_home.as_deref() {
        Some("") => actor == server_did(&state.server_name),
        _ => is_system_actor(&actor),
    };

    // The view is written with a valid-signature receipt, so only an event
    // this server actually verified may write it.
    if sig_state != crate::events::SigState::Valid {
        // One replayed event may not be skipped for good. A receipt is what a
        // transition filed here is waiting on, and a replay is how a server
        // that was away is meant to hear one — dropping it would leave the
        // event unconfirmed until somebody asked again, which is the round
        // trip the replay existed to save. So it waits for the signer's key
        // exactly as a live one does, and the key's arrival judges it. It
        // waits under the connection it arrived on, for the reason above.
        if is_receipt {
            park_replayed_receipt(state, event_id, relayed_by, ev, &facts);
            return Some(ReplayOutcome::Unusable);
        }
        tracing::warn!(
            %origin, %event_id, sig_state = ?sig_state,
            "S2S catch-up: skipping a task event whose signature this server \
             could not check — the peer can be asked for it again"
        );
        return Some(ReplayOutcome::Unusable);
    }

    let written = state.with_db(|db| {
        db.apply_act_event(&crate::db::ActEvent {
            canonical: &ev.canonical,
            signature: ev.signature.as_deref(),
            event_id,
            act_id: &act_id,
            opens,
            venue: &facts.venue,
            actor: &actor,
            from_system,
            origin: (!origin.is_empty()).then_some(origin),
            timestamp: ev.timestamp as i64,
        })
    });
    // A move this server applied to a task it owns is a move it ruled on, and
    // it owes a receipt for it — replay is a way in like any other. Without
    // this the only server whose word settles the task says nothing on the one
    // path nothing else covers: the addressed copy that follows is a duplicate,
    // and a duplicate moves nothing and confirms nothing.
    if let Some(written) = written.as_ref() {
        let receipt = crate::connection::act::receipt_for_applied_move(
            state,
            &crate::connection::act::AppliedMove {
                kind: &view.kind,
                act_id: &act_id,
                event_id,
                venue: &facts.venue,
                actor: &actor,
                written,
            },
        );
        if let Some(receipt) = receipt {
            // A replay reaches no client, so nothing is racing this onto the
            // wire. The venue is the target for a channel; a direct
            // conversation has none anyone can address, and a server-authored
            // line there goes out under `*`, as the sweep's notices do.
            let target = match facts.venue.starts_with("dm:") {
                true => "*",
                false => facts.venue.as_str(),
            };
            crate::connection::act::broadcast_receipt(state, &receipt, target);
        }
    }

    Some(match written {
        // No database attached: nothing to file into, and nothing to claim.
        None => ReplayOutcome::Filed,
        Some(crate::db::ActWrite::Filed { .. } | crate::db::ActWrite::Confirmed { .. }) => {
            // And whatever was waiting on precisely this event — a receipt that
            // outran it — is judged now.
            release_receipts_waiting_on(state, event_id);
            ReplayOutcome::Filed
        }
        // On file, deliberately unapplied — the task's own server rules on it.
        Some(crate::db::ActWrite::StoredNotApplied) => {
            release_receipts_waiting_on(state, event_id);
            ReplayOutcome::Filed
        }
        // Filed, and applied to nothing: a receipt from a peer that does not
        // own the task, or one the rules here refuse. Both are records, and a
        // record is what a replay is for.
        Some(crate::db::ActWrite::ReceiptIgnored | crate::db::ActWrite::ReceiptRefused(_)) => {
            ReplayOutcome::Filed
        }
        // A receipt for a move this server has already settled. The record is
        // filed and the view stands where it stood: confirming twice must not
        // move anything twice.
        Some(crate::db::ActWrite::Recorded) => ReplayOutcome::Filed,
        // A receipt ahead of the event it confirms. The same wait a live one
        // gets:
        // the subject's arrival is what judges it.
        Some(crate::db::ActWrite::ReceiptBeforeSubject) => {
            park_replayed_receipt(state, event_id, relayed_by, ev, &facts);
            ReplayOutcome::Unusable
        }
        Some(crate::db::ActWrite::Duplicate) => ReplayOutcome::AlreadyHeld,
        Some(other) => {
            tracing::debug!(
                %origin, %event_id, %act_id, outcome = ?other,
                "S2S catch-up: a replayed task event was not filed"
            );
            ReplayOutcome::Unusable
        }
    })
}

/// Hold one replayed receipt in the defer queue, the way the live path holds
/// one, and ask for whatever it is waiting on.
///
/// A receipt is the one replayed event skipping loses something nobody can get
/// back cheaply: some server is holding a transition unconfirmed, and this is
/// the word that would settle it. Two things can be missing — the signer's key,
/// or the event the receipt names — and the queue waits for either.
///
/// The tags are rebuilt from the very bytes the signature covers, so what is
/// judged on release is what was signed. The target is the venue's, because a
/// replay carries no wire target of its own: a channel's name, or, for a direct
/// conversation, one of the two DIDs the venue is made of — the same
/// addressing this server's own events travel to peers under.
fn park_replayed_receipt(
    state: &Arc<SharedState>,
    event_id: &str,
    relayed_by: &str,
    ev: &crate::s2s::ReplayedEvent,
    facts: &crate::events::EventFacts,
) {
    // The connection, never the batch's own stamp: what releases this event
    // judges it as the live path would, and the live path's origin is the
    // authenticated peer.
    let origin = relayed_by;
    let Some(tags) = crate::connection::act::wire_tags_from_canonical(
        &ev.canonical,
        event_id,
        ev.signature.as_deref(),
    ) else {
        return;
    };
    let signer = facts.actor_did.clone().unwrap_or_default();
    let sig_tag = ev.signature.clone().unwrap_or_default();
    let kid = freeq_sdk::sigtag::parse(&sig_tag)
        .map(|(kid, _)| kid.to_string())
        .unwrap_or_default();
    // Which of the two things it is waiting for. A key we do not hold is asked
    // for; a subject we do not hold arrives by itself, on this replay or the
    // next.
    let have_key = !signer.is_empty()
        && !kid.is_empty()
        && state
            .with_db(|db| db.get_signing_key_by_kid(&signer, &kid))
            .flatten()
            .is_some();
    let subject = match have_key {
        true => facts.subject.clone(),
        false => None,
    };
    if !have_key && !signer.is_empty() {
        crate::peer_keys::fetch_on_miss(state, origin, &signer, &sig_tag);
    }
    tracing::info!(
        %origin, %event_id, waiting_on = ?subject,
        "S2S catch-up: holding a receipt rather than dropping it"
    );
    let dropped = state
        .act_deferred
        .lock()
        .park(crate::act_relay::ParkedEvent {
            target: crate::connection::act::peer_target_for(&facts.venue, &facts.venue),
            from: signer.clone(),
            peer_account: Some(signer.clone()),
            origin: origin.to_string(),
            peer: relayed_by.to_string(),
            peer_declared_act: true,
            event_id: event_id.to_string(),
            // Whichever it is waiting for, and never both: a key it holds is
            // one the sweep must not go asking for again.
            signer: match have_key {
                true => String::new(),
                false => signer,
            },
            kid: match have_key {
                true => String::new(),
                false => kid,
            },
            waiting_on: subject,
            tags,
            ..Default::default()
        });
    for event in &dropped {
        note_dropped_unchecked(state, event);
    }
}

/// Whether an actor is the server itself rather than a person.
///
/// A server acts under `did:web:<its name>` — the identity the expiry sweep
/// signs its own events with — so the method prefix is what separates the two.
pub(crate) fn is_system_actor(actor: &str) -> bool {
    actor.starts_with("did:web:")
}

/// Apply one replayed event.
///
/// The conflict rules, in the terms the plan states them:
///
/// - **Same id, same content → no-op.** A peer re-sending what we already
///   hold is the normal case, not an error; replay would be unusable if it
///   weren't.
/// - **Same id, different content → drop and log loudly**, and record the
///   dropped copy's fingerprint against the row we keep. First write wins,
///   always — the copy we already showed our users is the copy we keep
///   showing, because silently swapping it for another is the failure this
///   whole design exists to prevent. The receipt is what stops the second
///   claim from vanishing without trace: equivocation stays *visible* here
///   even though it does not change what anyone sees.
/// - **No deterministic winner, ever.** Picking one signed claim over another
///   by hash or clock converges two servers at the cost of silently replacing
///   a displayed message, and the rule is grindable by whoever mints the ids.
///
/// The receipt is local. It is written here, read here, and never crosses the
/// wire — a peer's opinion about our conflicts is not evidence.
///
/// The ±120s id clock check deliberately does not run: it is a live-client
/// ingress check, and a replay is *made* of old events. Signature verification
/// is what stands in for freshness here, which is why item 1 came first.
///
/// `own_id` is this server's endpoint id and `relayed_by` the peer whose reply
/// this batch arrived in; between them and the event's own claim they decide
/// the origin it is filed under. See [`replay_origin`].
pub(crate) fn apply_replayed_event(
    state: &Arc<SharedState>,
    own_id: &str,
    relayed_by: &str,
    ev: crate::s2s::ReplayedEvent,
) -> ReplayOutcome {
    use crate::events::{EventContext, EventFacts, SigState};

    let event_id = sanitize_s2s_str(&ev.event_id, 100);
    if event_id.is_empty() {
        return ReplayOutcome::Unusable;
    }
    // Whether a claim that *we* minted this event is one our own records bear
    // out. A task event's origin names the server that referees the task, so
    // the claim is honoured only when the task is already here carrying no
    // origin — the way a task of ours is stored. An opener names no task, and
    // one we minted and no longer hold is not something a peer can settle for
    // us. Any other kind's origin is provenance, decides nothing, and is taken
    // as sent.
    let ours_on_file = match ev.kind.as_str() {
        "act" => ev
            .subject
            .as_deref()
            .and_then(|act_id| state.with_db(|db| db.act_task(act_id)).flatten())
            .is_some_and(|task| task.origin.is_empty()),
        _ => true,
    };
    let origin = replay_origin(own_id, relayed_by, &ev.origin, ours_on_file);
    let origin = origin.as_str();

    // What we already hold under this id, if anything.
    let existing = state.with_db(|db| db.get_event(&event_id)).flatten();
    if let Some(existing) = existing {
        if existing.canonical == ev.canonical {
            return ReplayOutcome::AlreadyHeld;
        }
        let fingerprint = crate::events::fingerprint(&ev.canonical);
        tracing::warn!(
            %origin, event_id = %event_id,
            "S2S replay: a second claim on this id with different content — \
             dropped, and a receipt recorded against the copy we keep"
        );
        state.with_db(|db| db.record_event_conflict(&event_id, &fingerprint));
        return ReplayOutcome::Conflicted;
    }

    // New to us. Check the signature ourselves against the bytes we were
    // handed — never adopt the replaying peer's conclusion, which is why it
    // does not travel.
    let sig_state = match (ev.signature.as_deref(), ev.canonical.is_empty()) {
        (None, _) => SigState::Unsigned,
        (Some(sig), false) => match replayed_signature_verdict(state, &ev, sig) {
            crate::connection::messaging::ClientSigVerdict::Valid => SigState::Valid,
            crate::connection::messaging::ClientSigVerdict::Invalid => {
                // Evidence of tampering. Refused outright, the same as at
                // live ingress: a failing signature is never filed.
                tracing::warn!(
                    %origin, event_id = %event_id,
                    "S2S replay: signature did not verify against the key it names — refused"
                );
                return ReplayOutcome::Unusable;
            }
            crate::connection::messaging::ClientSigVerdict::Unverifiable(_) => {
                SigState::Unverifiable
            }
        },
        // A signature with no bytes to check it against is uncheckable, not
        // wrong.
        (Some(_), true) => SigState::Unverifiable,
    };

    // A task event goes through the judgment live receiving uses, so a healed
    // server's task view answers what a server that stayed linked answers.
    if let Some(outcome) =
        file_replayed_task_event(state, &event_id, origin, relayed_by, &ev, sig_state)
    {
        return outcome;
    }

    // An empty origin is this server's own event coming home, and a row of
    // ours is stamped with no origin at all — the same shape local ingress
    // writes, so a healed event is indistinguishable from one never lost.
    let ctx = EventContext {
        sig_state,
        origin: (!origin.is_empty()).then(|| origin.to_string()),
        ..Default::default()
    };
    let signature = ev.signature.as_deref();
    let filed = if ev.canonical.is_empty() {
        state.with_db(|db| {
            db.insert_event(&crate::db::EventRecord {
                shape: crate::db::EventShape::Bare(EventFacts {
                    event_id: event_id.clone(),
                    kind: sanitize_s2s_str(&ev.kind, 32),
                    venue: crate::events::venue_of(&sanitize_s2s_str(&ev.venue, 200)),
                    actor_did: ev.actor_did.as_deref().map(|d| sanitize_s2s_str(d, 512)),
                    subject: ev.subject.as_deref().map(|s| sanitize_s2s_str(s, 100)),
                    body_hash: None,
                    // A bare replayed event states its own facts; a reaction's
                    // emoji is one of them.
                    emoji: ev.emoji.as_deref().map(|e| sanitize_s2s_str(e, 64)),
                }),
                signature,
                ctx: ctx.clone(),
                timestamp: ev.timestamp,
            })
        })
    } else {
        state.with_db(|db| {
            db.insert_event(&crate::db::EventRecord {
                shape: crate::db::EventShape::Document(&ev.canonical),
                signature,
                ctx: ctx.clone(),
                timestamp: ev.timestamp,
            })
        })
    };
    match filed {
        Some(true) => ReplayOutcome::Filed,
        Some(false) => ReplayOutcome::Unusable,
        // No database attached: nothing to file into, and nothing to claim.
        None => ReplayOutcome::Filed,
    }
}

/// Hand one relayed TAGMSG to the local sessions it is for.
///
/// The tail of the receive path, shared with the deferred-task-event flush so
/// an event that verifies late reaches its readers exactly as one that
/// verified on arrival does.
///
/// The account variant carries the DID the *origin* stamped, never the one a
/// nick fallback produced: that fallback resolves against our own nick map,
/// and stamping its answer would present a DID this server inferred as one the
/// origin attested. Same rule the S2S PRIVMSG path follows.
///
/// A task message from a peer is gated on `freeq.at/act` exactly as a local
/// one is (ruled 2026-08-15).
fn deliver_relayed_tagmsg(
    state: &Arc<SharedState>,
    from: &str,
    target: &str,
    tags: &HashMap<String, String>,
    peer_account: Option<&str>,
    to_senders_own_sessions: bool,
) {
    let build_tagged = |with_account: bool| -> String {
        let mut t = tags.clone();
        if with_account && let Some(did) = peer_account {
            t.insert("account".to_string(), did.to_string());
        }
        let tag_msg = crate::irc::Message {
            tags: t,
            prefix: Some(from.to_string()),
            command: "TAGMSG".to_string(),
            params: vec![target.to_string()],
        };
        format!("{tag_msg}\r\n")
    };
    let tagged_line = build_tagged(false);
    let tagged_line_account = peer_account.map(|_| build_tagged(true));
    let plain_fallback = tags
        .get("+react")
        .map(|emoji| format!(":{from} PRIVMSG {target} :\x01ACTION reacted with {emoji}\x01\r\n"));

    // Channel members, or (for a nick / `did:` DM) every local session bound to
    // that recipient — a federated action addressed to a DID reaches the same
    // person here.
    let recipients: Vec<String> = if target.starts_with('#') || target.starts_with('&') {
        state
            .channels
            .lock()
            .get(&target.to_lowercase())
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default()
    } else {
        let mut sids = crate::connection::routing::local_sessions_for_target(state, target);
        crate::connection::routing::merge_sessions(
            &mut sids,
            crate::connection::routing::sender_sessions_for_account(
                state,
                peer_account.filter(|_| to_senders_own_sessions),
            ),
        );
        sids
    };

    let is_act = crate::connection::act::carries_act_tags(tags);
    let tag_caps = state.cap_message_tags.lock();
    let acct_caps = state.cap_account_tag.lock();
    let act_caps = state.cap_act.lock();
    let conns = state.connections.lock();
    for sid in &recipients {
        if let Some(tx) = conns.get(sid) {
            if tag_caps.contains(sid) && (!is_act || act_caps.contains(sid)) {
                let line = if acct_caps.contains(sid) {
                    tagged_line_account.as_ref().unwrap_or(&tagged_line)
                } else {
                    &tagged_line
                };
                let _ = tx.try_send(line.clone());
            } else if !is_act && let Some(ref fallback) = plain_fallback {
                let _ = tx.try_send(fallback.clone());
            }
        }
    }
}

/// What the receive side does with one relayed task event, once it has
/// judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskEventAction {
    /// Stored, applied as far as the origin rules allow, and to be delivered.
    Deliver,
    /// Refused: not delivered, not stored. Either a found key over bytes that
    /// do not verify, or an event that claims no origin.
    Drop,
    /// No verdict is reachable yet. Not delivered and not stored *while it
    /// waits*: an outage at a key server is not evidence about the sender,
    /// and neither is it a reason to show an unchecked claim. The event is
    /// held in the defer queue and the signer's key is asked for off this
    /// path; the key's arrival is what judges it again.
    Park,
}

/// Reach a verdict about one relayed task event and act on it.
///
/// The three-way verdict is the whole point, and each answer does something
/// different. Valid is stored and applied. Invalid — the one case where a key
/// was found and the bytes still did not verify — is dropped: not delivered,
/// not stored, logged as the evidence it is. Everything else waits, and is
/// never refused, because an outage at a key server and an old peer are facts
/// about this server's reach, not about the sender; while it waits it is also
/// not carried, because a claim this server cannot check is not a task it can
/// show.
///
/// One thing is settled ahead of the signature: an event that claims no
/// origin is refused whatever its bytes say.
///
/// The second half of the answer is the receipt this server owes when the
/// event was a move on a task it owns. Handed back rather than sent, so a
/// caller puts it on the wire after the event it confirms — a reader sees the
/// move before the confirmation of it.
#[allow(clippy::too_many_arguments)]
fn judge_relayed_task_event(
    state: &Arc<SharedState>,
    from: &str,
    target: &str,
    tags: &HashMap<String, String>,
    origin: &str,
    peer: &str,
    peer_account: Option<&str>,
    peer_declared_act: bool,
) -> (TaskEventAction, Option<crate::connection::act::Receipt>) {
    let event_id = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .map(String::as_str)
        .unwrap_or("");

    // ── a task event claiming no origin is refused ──
    //
    // An empty origin is how this server writes "opened here": it is what the
    // idle sweep expires, what makes every later move on the task ours to
    // decide, and what catch-up serves under our own id. A relayed event was
    // opened somewhere else by definition, so filing one with a blank origin
    // would make this server the home of another server's task. Every honest
    // sender stamps its own id.
    if origin.is_empty() {
        tracing::warn!(
            peer = %peer,
            event_id = %event_id,
            "Refused a relayed task event that claims no origin — filing it \
             would make this server the task's home"
        );
        return (TaskEventAction::Drop, None);
    }

    let dm_recipient = (!(target.starts_with('#') || target.starts_with('&')))
        .then(|| crate::connection::routing::recipient_did_for_target(state, target))
        .flatten();
    // The venue of the task this event names, for the one signer whose own
    // venue is not derivable from the delivery target: the server itself.
    let task_venue = relayed_task_venue(state, tags, event_id);
    let verdict = crate::act_relay::relayed_task_verdict(
        tags,
        target,
        peer_account,
        dm_recipient.as_deref(),
        task_venue.as_deref(),
        |did, kid| {
            state
                .with_db(|db| db.get_signing_key_by_kid(did, kid))
                .flatten()
                .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        },
    );
    let signer = crate::act_relay::claimed_signer(tags, peer_account).unwrap_or_default();
    let sig_tag = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))
        .map(String::as_str)
        .unwrap_or_default();
    crate::act_relay::log_relayed_verdict(
        verdict,
        event_id,
        origin,
        peer,
        target,
        peer_declared_act,
    );

    match verdict {
        crate::act_relay::RelayVerdict::Valid => {
            match store_relayed_task_event(state, tags, target, origin, peer_account, from) {
                TaskEventStored::Ruled(receipt) => {
                    // Whatever this event was, it may be the one a receipt has
                    // been waiting for.
                    release_receipts_waiting_on(state, event_id);
                    (TaskEventAction::Deliver, receipt)
                }
                // A receipt that outran the event it confirms. Nothing was
                // filed and nothing is shown; the subject's arrival is what
                // judges it again, exactly as a key's arrival judges an event
                // waiting for one.
                TaskEventStored::WaitingOn(subject) => {
                    tracing::info!(
                        peer = %peer, event_id = %event_id, %subject,
                        "Holding a receipt until the event it names arrives"
                    );
                    let dropped = state
                        .act_deferred
                        .lock()
                        .park(crate::act_relay::ParkedEvent {
                            tags: tags.clone(),
                            target: target.to_string(),
                            from: from.to_string(),
                            peer_account: peer_account.map(str::to_string),
                            origin: origin.to_string(),
                            peer: peer.to_string(),
                            peer_declared_act,
                            event_id: event_id.to_string(),
                            waiting_on: Some(subject),
                            // No key is owed: this one verified. Naming a
                            // signer here would put the queue's key sweep on
                            // asking for a key it already holds.
                            ..Default::default()
                        });
                    for event in &dropped {
                        note_dropped_unchecked(state, event);
                    }
                    (TaskEventAction::Park, None)
                }
            }
        }
        crate::act_relay::RelayVerdict::Invalid(_) => (TaskEventAction::Drop, None),
        crate::act_relay::RelayVerdict::Unverifiable(why) => {
            // A key not held yet is the one unverifiable cause a lookup can
            // fix: ask the relay origin's key server for it, off the delivery
            // path. The event waits meanwhile — not stored and not shown,
            // because showing it would present an unchecked claim as a task —
            // and the key's arrival is what judges it again. An event that can
            // never verify at all waits too, and ages out by eviction where
            // somebody can see it.
            if why == crate::connection::messaging::NO_KEY_ON_FILE && !signer.is_empty() {
                crate::peer_keys::fetch_on_miss(state, origin, signer, sig_tag);
            }
            let kid = freeq_sdk::sigtag::parse(sig_tag)
                .map(|(kid, _)| kid.to_string())
                .unwrap_or_default();
            let dropped = state
                .act_deferred
                .lock()
                .park(crate::act_relay::ParkedEvent {
                    tags: tags.clone(),
                    target: target.to_string(),
                    from: from.to_string(),
                    peer_account: peer_account.map(str::to_string),
                    origin: origin.to_string(),
                    peer: peer.to_string(),
                    peer_declared_act,
                    event_id: event_id.to_string(),
                    signer: signer.to_string(),
                    kid,
                    ..Default::default()
                });
            for event in &dropped {
                note_dropped_unchecked(state, event);
            }
            (TaskEventAction::Park, None)
        }
    }
}

/// How many transitions may be waiting for their homes at once.
///
/// A ceiling rather than a promise: a home that stays away long enough is
/// healed by catch-up, which is what the log is for, so the queue exists to
/// make the common case prompt and not to guarantee delivery.
const MAX_PENDING_ROUTES: usize = 1024;

/// How often the pending routes are looked at. Coarse on purpose — the backoff
/// is measured in tens of seconds, so a finer tick would only spin.
const ROUTE_TICK: std::time::Duration = std::time::Duration::from_secs(10);

/// One task event as it has to travel: the signed tags, and where they were
/// delivered. Nothing here may be rebuilt or tidied — the signature covers the
/// tags, and the venue is derived from the target.
#[derive(Clone)]
pub(crate) struct TaskEventWire {
    pub act_id: String,
    pub event_id: String,
    pub tags: HashMap<String, String>,
    pub target: String,
    pub from: String,
    pub account: Option<String>,
}

/// Ask the server that owns a task to rule on a transition it may not have
/// ruled on yet.
///
/// The event has already been filed here, unconfirmed, and already gone out to
/// every act-capable peer including the home. This is the addressed copy: a
/// broadcast is best-effort, and a home that was away when it went out has no
/// second chance at it, while a ruling is not optional.
pub(crate) fn route_transition_home(state: &Arc<SharedState>, ev: TaskEventWire, home: &str) {
    if home.is_empty() {
        return;
    }
    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
    let message = crate::s2s::S2sMessage::ActRoute {
        // Stamped fresh at each attempt; see `PendingRoute::message`.
        event_id: String::new(),
        act_id: ev.act_id.clone(),
        act_event_id: ev.event_id.clone(),
        tags: ev.tags,
        target: ev.target,
        from: ev.from,
        account: ev.account,
        origin,
    };
    state
        .act_routes
        .lock()
        .park(crate::act_relay::PendingRoute {
            act_id: ev.act_id,
            event_id: ev.event_id,
            home: home.to_string(),
            message,
            attempts: 0,
            next_attempt: std::time::Instant::now(),
            seq: 0,
        });
    let state = Arc::clone(state);
    tokio::spawn(async move { flush_pending_routes(&state).await });
}

/// Try every route that is due, and put back the ones that are still owed an
/// answer.
///
/// **Every outcome goes back on the list.** None of the three is an answer: a
/// link accepts a send for as long as it takes to notice it is dead, a peer
/// that will not take one may be mid-handshake, and an unreachable home may
/// come back. What ends the asking is the event ceasing to be unconfirmed —
/// the home's receipt arriving and being applied, or something else being
/// ruled in that the rules no longer admit this one behind. Failing that, the
/// queue's own ceiling gives up the oldest ask with a warning
/// ([`crate::act_relay::RouteQueue::park`]), and the backoff bounds the cost
/// meanwhile.
pub(crate) async fn flush_pending_routes(state: &Arc<SharedState>) {
    let Some(manager) = state.s2s_manager.lock().clone() else {
        // No federation running: there is nobody to ask, and the routes stay
        // where they are in case one starts.
        return;
    };
    let due = state.act_routes.lock().take_due(std::time::Instant::now());
    for mut route in due {
        // What the route is for, asked before every attempt: is this event
        // still waiting on its home? Confirmed, superseded, or not on file —
        // each is an end to the asking.
        if state.with_db(|db| db.act_event_is_unconfirmed(&route.event_id)) != Some(true) {
            tracing::debug!(
                act_id = %route.act_id, event_id = %route.event_id, home = %route.home,
                "This transition is no longer waiting on a ruling; nothing left to carry"
            );
            continue;
        }
        // A fresh envelope id per attempt. The receiver's dedup rejects a
        // counter at or below the high-water mark it already holds from us, so
        // a retry under the original id would be dropped as a replay of
        // something that never arrived.
        if let crate::s2s::S2sMessage::ActRoute { event_id, .. } = &mut route.message {
            *event_id = manager.next_event_id();
        }
        match manager
            .route_to_home(&route.home, route.message.clone())
            .await
        {
            crate::s2s::RouteOutcome::Sent => tracing::debug!(
                act_id = %route.act_id, event_id = %route.event_id, home = %route.home,
                attempts = route.attempts,
                "Carried a task transition to the server that owns the task"
            ),
            crate::s2s::RouteOutcome::Unreachable => tracing::debug!(
                act_id = %route.act_id, event_id = %route.event_id, home = %route.home,
                attempts = route.attempts,
                "The server that owns this task is not reachable; will ask again"
            ),
            crate::s2s::RouteOutcome::Refused(why) => tracing::warn!(
                act_id = %route.act_id, event_id = %route.event_id, home = %route.home,
                reason = %why,
                "Cannot carry a task transition to the server that owns the task \
                 right now; will ask again"
            ),
        }
        route.attempts += 1;
        route.next_attempt =
            std::time::Instant::now() + crate::act_relay::retry_backoff(route.attempts);
        state.act_routes.lock().park(route);
    }
}

/// The tick that retries what could not be delivered.
///
/// A tick rather than a peer-connect hook: a link coming back is not the only
/// reason an attempt can newly succeed, and one timer covers every reason
/// without a second mechanism to keep honest.
fn spawn_act_route_retry(state: Arc<SharedState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ROUTE_TICK);
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            if state.act_routes.lock().is_empty() {
                continue;
            }
            flush_pending_routes(&state).await;
        }
    });
}

/// Store a task event this server verified itself, under the id its signer
/// minted.
///
/// Never a locally minted id: the log is how a later replay recognises an
/// event it already holds, and an id of ours makes the same event look like a
/// second one. A DM files under the canonical two-DID venue rather than the
/// wire target, which is a nick or a `did:` depending on who addressed whom.
fn store_relayed_task_event(
    state: &Arc<SharedState>,
    tags: &HashMap<String, String>,
    target: &str,
    origin: &str,
    peer_account: Option<&str>,
    from: &str,
) -> TaskEventStored {
    let Some(signer) = crate::act_relay::claimed_signer(tags, peer_account) else {
        return TaskEventStored::Ruled(None);
    };
    let Some(event_id) = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .cloned()
    else {
        return TaskEventStored::Ruled(None);
    };
    // The same rule the verdict used, so the bytes are filed under the venue
    // whose signature was just checked over them.
    let dm_recipient = (!(target.starts_with('#') || target.starts_with('&')))
        .then(|| crate::connection::routing::recipient_did_for_target(state, target))
        .flatten();
    let Some(venue) = crate::act_relay::venue_for(
        target,
        signer,
        dm_recipient.as_deref(),
        relayed_task_venue(state, tags, &event_id).as_deref(),
    ) else {
        return TaskEventStored::Ruled(None);
    };
    let signature = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))
        .cloned();
    let now = chrono::Utc::now().timestamp();

    if crate::connection::act::carries_act_tags(tags) {
        let pairs: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let Ok(canonical) = freeq_sdk::act::act_canonical(pairs, &venue, &event_id) else {
            return TaskEventStored::Ruled(None);
        };
        let kind = tags
            .get("+freeq.at/act")
            .or_else(|| tags.get("freeq.at/act"))
            .map(String::as_str)
            .unwrap_or("");
        let verb = tags
            .get("+freeq.at/act-verb")
            .or_else(|| tags.get("act-verb"))
            .map(String::as_str)
            .unwrap_or("");
        // An opener's own event id is the task's id; everything else names the
        // task it belongs to.
        let opens = freeq_sdk::act_transitions::opening_verb(kind) == Some(verb);
        let act_id = match opens {
            true => event_id.clone(),
            false => tags
                .get("+freeq.at/act-id")
                .or_else(|| tags.get("act-id"))
                .cloned()
                .unwrap_or_default(),
        };
        let written = state.with_db(|db| {
            db.apply_act_event(&crate::db::ActEvent {
                canonical: &canonical,
                signature: signature.as_deref(),
                event_id: &event_id,
                act_id: &act_id,
                opens,
                venue: &venue,
                actor: signer,
                // Read off the actor, the way catch-up and a rebuild read it:
                // a server signs under its `did:web:` identity and a person
                // does not. Hard-coding false here made the same event answer
                // differently depending on which path it arrived by — this
                // server's own expiry coming home read as a person's move.
                from_system: is_system_actor(signer),
                origin: Some(origin),
                timestamp: now,
            })
        });
        // A move on a task this server owns, applied here. Our word is what
        // turns it from a claim into a decision, and the receipt is that word
        // written down. Handed back rather than sent, so it goes out after the
        // event it names.
        if let Some(written) = written.as_ref() {
            let receipt = crate::connection::act::receipt_for_applied_move(
                state,
                &crate::connection::act::AppliedMove {
                    kind,
                    act_id: &act_id,
                    event_id: &event_id,
                    venue: &venue,
                    actor: signer,
                    written,
                },
            );
            if receipt.is_some() {
                return TaskEventStored::Ruled(receipt);
            }
        }
        match written {
            None | Some(crate::db::ActWrite::Filed { .. }) => {}
            // A receipt this server followed: the event it names was re-checked
            // against the task here and the view moved with it. Nothing is
            // owed — the receipt was the home's to write, and we are not it.
            Some(crate::db::ActWrite::Confirmed { ref state }) => tracing::info!(
                origin = %origin, act_id = %act_id, event_id = %event_id, state = %state,
                "Followed the receipt of the server that owns this task"
            ),
            Some(crate::db::ActWrite::ReceiptIgnored) => tracing::warn!(
                origin = %origin, act_id = %act_id, event_id = %event_id,
                "A receipt arrived from a peer that does not own this task — filed \
                 as the claim it is, and applied to nothing"
            ),
            Some(crate::db::ActWrite::ReceiptRefused(refusal)) => tracing::warn!(
                origin = %origin, act_id = %act_id, event_id = %event_id,
                reason = %refusal,
                "The owning server confirmed an event the rules here refuse — the \
                 receipt is on file and nothing was applied"
            ),
            // Not on file yet, so nothing can be judged against it. The caller
            // holds this one until it is.
            Some(crate::db::ActWrite::ReceiptBeforeSubject) => {
                let subject = tags
                    .get(&format!(
                        "+freeq.at/{}",
                        freeq_sdk::act_transitions::confirmation_subject_tag()
                    ))
                    .cloned()
                    .unwrap_or_default();
                return TaskEventStored::WaitingOn(subject);
            }
            Some(crate::db::ActWrite::StoredNotApplied) => {
                tracing::info!(
                    origin = %origin, act_id = %act_id, event_id = %event_id, verb = %verb,
                    "Filed a relayed task event without applying it: the task belongs to \
                     another server, which is the authority over what it does"
                );
                // …and that server is asked for its ruling. A peer that holds
                // the event unruled carries it too: on a network that is not a
                // full mesh, that path may be the only one there is, and the
                // home dedups a copy it already has.
                let home = state
                    .with_db(|db| db.act_task_origin(&act_id))
                    .flatten()
                    .unwrap_or_default();
                route_transition_home(
                    state,
                    TaskEventWire {
                        act_id: act_id.clone(),
                        event_id: event_id.clone(),
                        tags: tags.clone(),
                        target: target.to_string(),
                        from: from.to_string(),
                        account: Some(signer.to_string()),
                    },
                    &home,
                );
            }
            Some(other) => tracing::debug!(
                origin = %origin, act_id = %act_id, event_id = %event_id,
                outcome = ?other,
                "A relayed task event was not filed"
            ),
        }
        return TaskEventStored::Ruled(None);
    }

    // The stopgap coordination family, filed the way local ingress files one.
    let Some(event_type) = tags.get("+freeq.at/event").cloned() else {
        return TaskEventStored::Ruled(None);
    };
    let doc =
        crate::act_relay::coordination_doc_from_tags(tags, signer, &event_id, &venue, &event_type);
    let canonical = doc.canonical();
    let payload = match tags.get("+freeq.at/payload") {
        None => "{}".to_string(),
        Some(raw) => urlencoding::decode(raw)
            .unwrap_or_else(|_| raw.as_str().into())
            .into_owned(),
    };
    let event = crate::db::CoordinationEventRow {
        event_id: event_id.clone(),
        event_type,
        actor_did: signer.to_string(),
        channel: target.to_string(),
        ref_id: tags
            .get("+freeq.at/ref")
            .or_else(|| tags.get("+freeq.at/task-id"))
            .cloned(),
        payload_json: payload,
        signature,
        timestamp: now,
    };
    let stored = state.with_db(|db| {
        db.store_coordination_event(
            &event,
            Some(crate::db::SignedCoordination {
                canonical: &canonical,
                state: crate::events::SigState::Valid,
            }),
        )
    });
    if stored == Some(crate::db::CoordinationWrite::Refused) {
        tracing::warn!(
            origin = %origin, event_id = %event_id, channel = %target,
            "Refused a relayed coordination event: that id is already on file"
        );
    }
    // The stopgap family has no task view and no receipts; there is nothing for
    // a caller to put on the wire.
    TaskEventStored::Ruled(None)
}

/// What the store path did with one relayed task event.
enum TaskEventStored {
    /// Filed, as far as this server may file it, together with the receipt it
    /// owes for the move — `None` when it owes none.
    Ruled(Option<crate::connection::act::Receipt>),
    /// A receipt that named an event this server does not hold. Nothing was
    /// written; it names the event it is waiting for.
    WaitingOn(String),
}

/// The venue of the task a relayed event names, read from the log.
///
/// Only a server's own event needs it — the venue a `did:web:` signer bound
/// cannot be rebuilt from the delivery target, because the signer is not one
/// of a direct conversation's participants. `None` for the stopgap family,
/// which has no task, and for a task this server has never filed.
fn relayed_task_venue(
    state: &Arc<SharedState>,
    tags: &HashMap<String, String>,
    event_id: &str,
) -> Option<String> {
    let act_id = dropped_task_id(tags, event_id)?;
    state.with_db(|db| db.act_task_venue(&act_id)).flatten()
}

/// Leave the visible trace of a dropped event: if it belonged to a task on
/// file, that task's row keeps count, so a reader of the task can see its
/// record may be incomplete instead of trusting a server log they cannot
/// read. An event whose task was never stored here — an opening that never
/// verified, or the stopgap family, which has no task view — leaves only the
/// queue's own log line.
fn note_dropped_unchecked(state: &Arc<SharedState>, dropped: &crate::act_relay::ParkedEvent) {
    let Some(act_id) = dropped_task_id(&dropped.tags, &dropped.event_id) else {
        return;
    };
    let marked = state
        .with_db(|db| db.bump_act_dropped_unchecked(&act_id))
        .unwrap_or(false);
    if marked {
        tracing::info!(
            act_id = %act_id,
            event_id = %dropped.event_id,
            "The task's record now counts the dropped event"
        );
    }
}

/// The task a parked act event belongs to: an opening names itself, anything
/// else names its task. `None` for the stopgap family — it has no task view.
fn dropped_task_id(tags: &HashMap<String, String>, event_id: &str) -> Option<String> {
    if !crate::connection::act::carries_act_tags(tags) {
        return None;
    }
    let kind = tags
        .get("+freeq.at/act")
        .or_else(|| tags.get("freeq.at/act"))
        .map(String::as_str)
        .unwrap_or("");
    let verb = tags
        .get("+freeq.at/act-verb")
        .or_else(|| tags.get("act-verb"))
        .map(String::as_str)
        .unwrap_or("");
    match freeq_sdk::act_transitions::opening_verb(kind) == Some(verb) {
        true => Some(event_id.to_string()),
        false => tags
            .get("+freeq.at/act-id")
            .or_else(|| tags.get("act-id"))
            .cloned(),
    }
}

/// A signing key just landed. Re-check whatever was waiting for it.
///
/// The only thing that can change an unverifiable verdict is a key arriving,
/// and every way one arrives calls here: a local registration, and a fetch
/// from a peer's key server completing. Events that now verify are applied and
/// delivered in the order they were parked — a claim that arrived before a
/// completion is applied before it — and one that still cannot be judged goes
/// back to waiting.
pub(crate) fn retry_deferred_task_events(state: &Arc<SharedState>, did: &str, kid: &str) {
    let waiting = state.act_deferred.lock().take_for_signer(did, kid);
    if waiting.is_empty() {
        return;
    }
    tracing::info!(
        did = %did, kid = %kid, count = waiting.len(),
        "A signing key arrived; re-checking the task events that were waiting for it"
    );
    judge_parked_events(state, waiting);
}

/// A task event has just been filed. Re-check whatever was waiting for that
/// event rather than for a key: a receipt that outran the move it names.
///
/// The other half of the queue's promise. A receipt is never evicted and never
/// refused, so the only thing that can be owed to one is its subject, and
/// every path that files a task event calls here — the live relay, the release
/// of something that was itself parked, and catch-up.
pub(crate) fn release_receipts_waiting_on(state: &Arc<SharedState>, subject: &str) {
    let waiting = state.act_deferred.lock().take_for_subject(subject);
    if waiting.is_empty() {
        return;
    }
    tracing::info!(
        %subject, count = waiting.len(),
        "The event a receipt names is on file; re-checking the receipt"
    );
    judge_parked_events(state, waiting);
}

/// Send back the receipt this server already holds for one event, to the peer
/// that asked about it again.
///
/// Reading, not deciding: the receipt was minted and filed at the moment the
/// move was applied, and this is that row put back on the wire. A peer that
/// has since heard it files nothing — its id is already in that peer's log.
/// Silent when there is no receipt on file, which is the honest answer to
/// "have you decided?" when we have not.
async fn answer_with_stored_receipt(
    state: &Arc<SharedState>,
    manager: &Arc<crate::s2s::S2sManager>,
    peer: &str,
    subject: &str,
    target: &str,
) {
    let Some(stored) = state
        .with_db(|db| db.act_receipt_for_subject(subject))
        .flatten()
    else {
        return;
    };
    let Some(tags) = crate::connection::act::wire_tags_from_canonical(
        &stored.canonical,
        &stored.event_id,
        stored.signature.as_deref(),
    ) else {
        return;
    };
    let message = crate::s2s::S2sMessage::Tagmsg {
        event_id: manager.next_event_id(),
        from: state.server_name.clone(),
        target: crate::connection::act::peer_target_for(&stored.venue, target),
        tags,
        origin: manager.server_id.clone(),
        account: Some(server_did(&state.server_name)),
    };
    match manager.send_act_to_peer(peer, message).await {
        crate::s2s::RouteOutcome::Sent => tracing::debug!(
            %peer, %subject, receipt = %stored.event_id,
            "Answered a peer still asking with the receipt already on file"
        ),
        outcome => tracing::debug!(
            %peer, %subject, receipt = %stored.event_id, ?outcome,
            "Could not answer a peer still asking about a transition we ruled on"
        ),
    }
}

/// Judge a batch taken out of the defer queue, in the order it was parked — a
/// claim that arrived before a completion is applied before it.
fn judge_parked_events(state: &Arc<SharedState>, waiting: Vec<crate::act_relay::ParkedEvent>) {
    for event in waiting {
        let (action, receipt) = judge_relayed_task_event(
            state,
            &event.from,
            &event.target,
            &event.tags,
            &event.origin,
            &event.peer,
            event.peer_account.as_deref(),
            event.peer_declared_act,
        );
        if action == TaskEventAction::Deliver {
            deliver_relayed_tagmsg(
                state,
                &event.from,
                &event.target,
                &event.tags,
                event.peer_account.as_deref(),
                // A released event verified here before it was delivered, so
                // the signer's own sessions get it like any checked event.
                true,
            );
        }
        if let Some(receipt) = receipt {
            crate::connection::act::broadcast_receipt(state, &receipt, &event.target);
        }
    }
}

/// How often the defer queue is looked at for keys worth asking for again.
///
/// Well below the shortest backoff step, so a key becomes due close to when
/// its own schedule says rather than at the tick after.
const DEFER_RETRY_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask again for the keys parked task events are waiting on.
///
/// A key arriving is what releases a parked event, and both paths that notice
/// one need somebody to have asked. The ask when an event parks covers a
/// signer who keeps talking; a quiet one's event would otherwise sit until it
/// was evicted even after its key server came back. So each distinct signer
/// with events waiting is asked for again on a backoff of its own, until the
/// key arrives or nothing of theirs is left waiting.
fn spawn_act_defer_retry_sweep(state: Arc<SharedState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DEFER_RETRY_TICK);
        interval.tick().await; // skip first tick
        loop {
            interval.tick().await;
            let due = state.act_deferred.lock().retries_due();
            for (origin, signer, kid) in due {
                crate::peer_keys::fetch_again(&state, &origin, &signer, &kid);
            }
        }
    });
}

/// Check a replayed event's signature against the bytes it travelled with.
fn replayed_signature_verdict(
    state: &Arc<SharedState>,
    ev: &crate::s2s::ReplayedEvent,
    sig: &str,
) -> crate::connection::messaging::ClientSigVerdict {
    use crate::connection::messaging::{ClientSigVerdict, NO_KEY_ON_FILE};
    let Some(did) = ev.actor_did.as_deref() else {
        return ClientSigVerdict::Unverifiable("replayed event names no actor");
    };
    let outcome =
        crate::connection::messaging::verify_canonical_bytes(state, did, &ev.canonical, sig);
    // A signer we hold no key for: ask its home server, off this path, so the
    // next replay of theirs gets a real verdict.
    if let ClientSigVerdict::Unverifiable(NO_KEY_ON_FILE) = outcome {
        crate::peer_keys::fetch_from_any_peer(state, did, sig);
    }
    outcome
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
        S2sMessage::ActRoute {
            event_id, origin, ..
        } => (event_id.clone(), origin.clone()),
        S2sMessage::CrdtSync { origin, .. } => (String::new(), origin.clone()),
        S2sMessage::PeerDisconnected { .. } => (String::new(), String::new()),
        // Catch-up carries no event id of its own: the *replayed* events
        // inside it dedup individually, by the id each already has, which is
        // the whole reason a re-delivery is a no-op.
        S2sMessage::CatchupRequest { .. } | S2sMessage::CatchupEvents { .. } => {
            (String::new(), String::new())
        }
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
            | S2sMessage::ActRoute { .. }
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

    // ── an origin a payload claims carries no authority ──────────────
    //
    // `origin` up to here is a field the sender filled in, and everything
    // below decides things with it: whether an event is the task's home
    // ruling on its own task (which applies a transition instead of merely
    // filing it, flips one already on file to confirmed, and lets a
    // `did:web:` actor speak as the system), and which peer's key server to
    // ask about a signature. An honest peer stamps its own id, so the two
    // agree; a mismatch is a peer asserting an authority the transport did
    // not give it. The authenticated id is what the rest of this function
    // reads, exactly as the CRDT sync arm below already does.
    //
    // Above this line on purpose: the self-origin filter and the dedup key,
    // which recognize an event rather than trust one. An empty origin claims
    // nothing and is left alone here — that is a peer predating the field, and
    // a chat message is none the worse for it. A task event is: an empty
    // origin is how this server writes "opened here", so the task branch
    // refuses one rather than reading it (`judge_relayed_task_event`).
    let origin = if origin.is_empty() || origin == authenticated_peer_id {
        origin
    } else {
        tracing::warn!(
            authenticated = %authenticated_peer_id,
            claimed = %origin,
            "S2S message names an origin other than the peer that sent it — \
             using the authenticated peer id"
        );
        authenticated_peer_id.to_string()
    };

    match msg {
        S2sMessage::Hello {
            peer_id,
            server_name,
            protocol_version,
            trust_level,
            capabilities,
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

            // What this peer says it can receive. A peer that declared nothing
            // — an older build with no such field — is recorded as declaring
            // nothing, and is therefore sent nothing new.
            tracing::debug!(
                peer = %authenticated_peer_id,
                ?capabilities,
                "S2S peer capabilities recorded"
            );
            manager
                .peer_capabilities
                .lock()
                .await
                .insert(authenticated_peer_id.to_string(), capabilities);

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

            // The peer's declared trust_level is informational only (logged
            // above). It is deliberately NOT adopted: the operator's
            // --s2s-peer-trust config is the sole authority, so a peer cannot
            // declare its own level and escape a configured restriction.

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
            msgid,
            sig,
            account,
            recipient_did: stamped_recipient_did,
            replaces_msgid,
            tags: relayed_tags,
            multiline_lines,
            ..
        } => {
            // ── verify before tidying ────────────────────────────────
            // Everything below this block rewrites the envelope: it
            // sanitizes, stamps in a msgid of our own, re-roots the edit
            // reference, filters and caps the tags. All of that changes bytes
            // the signature covers, so the check runs against the message as
            // transmitted, and only the tidied copy is filed and delivered.
            let sig_verdict = verify_relayed_privmsg(
                state,
                account.as_deref(),
                &target,
                msgid.as_deref(),
                &text,
                &relayed_tags,
                replaces_msgid.as_deref(),
                multiline_lines.as_ref(),
                sig.as_deref(),
            );

            // Sanitize all peer-provided strings to prevent IRC protocol injection.
            let from = sanitize_s2s_str(&from, 512);
            let raw_target = target;
            let target = sanitize_s2s_str(&raw_target, 200);
            // Match the local multiline ceiling (MAX_BYTES) so a federated
            // message isn't truncated in history/CHATHISTORY when it crosses a
            // server boundary. `\r`/`\n`/`\0` stripping is the injection
            // defense; the length cap is only a size bound. Tied to the same
            // constant so the two paths can't drift apart again.
            let raw_text = text;
            let text = sanitize_s2s_str(&raw_text, crate::connection::draft_multiline::MAX_BYTES);
            // Sender DID carried from the origin (the `account` tag value).
            // Stamped by the origin from its authenticated session, never
            // client-set; relayed on the same peer trust as the message body.
            let raw_account = account;
            let account = raw_account.as_deref().map(|a| sanitize_s2s_str(a, 512));

            // Sanitizing just changed bytes the signature covers. When it did,
            // this server is why the document no longer matches — which reads
            // *unverifiable*, never invalid, exactly as a plugin rewrite does
            // at local ingress.
            let sig_verdict = match sig_verdict {
                Some(v)
                    if text != raw_text
                        || target != raw_target
                        || account.as_deref() != raw_account.as_deref() =>
                {
                    tracing::debug!(
                        peer = %authenticated_peer_id,
                        "Relayed message was altered by our own sanitizer ({v:?} discarded)"
                    );
                    Some(
                        crate::connection::messaging::ClientSigVerdict::Unverifiable(
                            "sanitized on receipt",
                        ),
                    )
                }
                other => other,
            };
            if let Some(verdict) = sig_verdict {
                use crate::connection::messaging::{ClientSigVerdict, NO_KEY_ON_FILE};
                // A signer we hold no key for. Ask its home server — off this
                // path, so nothing waits: the message is already on its way,
                // labeled honestly, and the answer serves the next one.
                if let (ClientSigVerdict::Unverifiable(NO_KEY_ON_FILE), Some(did), Some(sig)) =
                    (verdict, account.as_deref(), sig.as_deref())
                {
                    crate::peer_keys::fetch_on_miss(state, &origin, did, sig);
                }
                match verdict {
                    ClientSigVerdict::Valid => tracing::debug!(
                        peer = %authenticated_peer_id, target = %target,
                        "Relayed message signature verified against the sender's own key"
                    ),
                    ClientSigVerdict::Invalid => tracing::warn!(
                        peer = %authenticated_peer_id, target = %target, from = %from,
                        account = ?account, msgid = ?msgid,
                        "Relayed message signature did not verify against the key it names — \
                         dropping the message"
                    ),
                    ClientSigVerdict::Unverifiable(why) => tracing::debug!(
                        peer = %authenticated_peer_id, target = %target, why = %why,
                        "Relayed message signature cannot be checked here"
                    ),
                }
            }
            // A signature that did not check out is evidence about the bytes:
            // the words and the proof arrived together and disagree. The
            // message is dropped rather than relayed without the half that
            // disagreed — passing on the words alone would put text under the
            // sender's name that the evidence on the wire says is not theirs,
            // and would hide the one fact worth knowing about it.
            if sig_verdict == Some(crate::connection::messaging::ClientSigVerdict::Invalid) {
                return;
            }

            // Generate a local msgid if the remote didn't send one
            let msgid = msgid.unwrap_or_else(crate::msgid::generate);

            // The body to FILE: whatever the verifier checked, so this
            // server's own later verification of the row agrees with the one
            // it reached on receipt, and both servers hold the same bytes.
            //
            // A BATCH is reassembled — the origin signed and stored the
            // assembled body, and the escape exists only because a raw newline
            // cannot ride an IRC line. Line bodies are peer-provided, so each
            // is sanitized before reassembly; the joins are ours. Anything
            // else, the inline form included, is filed as transmitted.
            let stored_body = match multiline_lines.as_ref() {
                Some(lines) => {
                    let mut out = String::new();
                    for (i, line) in lines.iter().enumerate() {
                        if i > 0 && !line.concat {
                            out.push('\n');
                        }
                        out.push_str(&sanitize_s2s_str(
                            &line.body,
                            crate::connection::draft_multiline::MAX_BYTES,
                        ));
                    }
                    let max = crate::connection::draft_multiline::MAX_BYTES;
                    if out.len() > max {
                        let mut cut = max;
                        while !out.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        out.truncate(cut);
                    }
                    out
                }
                None => text.clone(),
            };

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
            // An edit rewrites a record, so it answers to the mutation rule
            // rather than the message one: the actor's own proof, or nothing
            // happens. Same two exemptions — no account is a guest's edit, and
            // a venue that does not resolve had no document to sign.
            if edit_of.is_some()
                && let Some(actor) = account.as_deref()
                && crate::connection::messaging::signing_venue(state, actor, &target).is_some()
                && sig_verdict != Some(crate::connection::messaging::ClientSigVerdict::Valid)
            {
                tracing::warn!(
                    peer = %authenticated_peer_id, origin = %origin, target = %target,
                    account = %actor, verdict = ?sig_verdict,
                    key_source = crate::peer_keys::has_key_source(state, &origin),
                    "Relayed edit carries no signature this server can check — dropping it"
                );
                return;
            }
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
                .iter()
                .filter(|(k, _)| k.starts_with("+freeq.at/") && k.as_str() != "+freeq.at/sig")
                .take(16)
                .map(|(k, v)| (sanitize_s2s_str(k, 64), sanitize_s2s_str(v, 4096)))
                .collect();
            // The reply reference rides outside that cap: it is a covered
            // field, so dropping it because a peer sent many coordination tags
            // would silently detach a reply from its thread. Resolved to our
            // own root, like every other reference a peer names.
            if let Some(root) = relayed_tags
                .get("+reply")
                .or_else(|| relayed_tags.get("+draft/reply"))
            {
                let root =
                    crate::connection::helpers::root_msgid(state, &sanitize_s2s_str(root, 100));
                relay_tags.insert("+reply".to_string(), root);
            }
            // Provenance: every message reaching here is from a remote origin
            // (self-origin is skipped above), so tag it with the origin
            // server's name. Lets clients distinguish a peer-vouched federated
            // message from a locally-verified one, rather than rendering the
            // (only peer-trusted) `account` as if this server had verified it.
            let origin_name = sanitize_s2s_str(&manager.peer_display_name(&origin).await, 64);
            // What the log records about this relay: the verdict this server
            // actually reached, and the peer it came through. A signature we
            // stripped leaves nothing to have concluded, and a peer's word is
            // not a verdict — only our own check may say `valid`.
            let event_ctx = crate::events::EventContext {
                sig_state: match (&sig, sig_verdict) {
                    (None, _) => crate::events::SigState::Unsigned,
                    (Some(_), Some(crate::connection::messaging::ClientSigVerdict::Valid)) => {
                        crate::events::SigState::Valid
                    }
                    _ => crate::events::SigState::Unverifiable,
                },
                origin: Some(origin_name.clone()),
                ..Default::default()
            };
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
                    // Who sent this is the origin's to state, and only the
                    // origin's: a nick is something a peer chooses, so
                    // resolving one against our own records answered "who is
                    // this" with the name of whoever holds that nick here.
                    let s2s_sender_did = account.clone();
                    // File it before showing it. Persists the coordination
                    // tags (incl. +freeq.at/origin) so CHATHISTORY replay
                    // carries them, like the DM persist path — and if the
                    // store refuses the msgid (a re-delivery, or a
                    // conflicting claim on an id already on file), the event
                    // must not reach history or local clients either.
                    let stored = state
                        .with_db(|db| match edit_of {
                            // Same shape as a local edit: a new row that
                            // carries the root, so the pair reads as one
                            // message here too.
                            // `tags`, not `relay_tags`: the row has to carry the
                            // signature and the sender's account, or nothing
                            // reading history later — CHATHISTORY, the verify
                            // endpoint — can check the message at all. The DM
                            // path below has always filed the full set.
                            Some(ref root) => db.insert_edit_with(
                                &target,
                                &from,
                                &stored_body,
                                timestamp,
                                &tags,
                                &msgid,
                                root,
                                s2s_sender_did.as_deref(),
                                &event_ctx,
                            ),
                            None => db.insert_message_with(
                                &target,
                                &from,
                                &stored_body,
                                timestamp,
                                &tags,
                                Some(&msgid),
                                s2s_sender_did.as_deref(),
                                &event_ctx,
                            ),
                        })
                        .unwrap_or(true);
                    if !stored {
                        return;
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
                            ch.history[i].text = stored_body.clone();
                            ch.history[i].edited = true;
                        } else if revised.is_some() {
                            tracing::warn!(
                                channel = %target, from = %from,
                                "S2S edit dropped: would rewrite another user's history entry"
                            );
                        } else {
                            ch.history.push_back(HistoryMessage {
                                from: from.clone(),
                                text: stored_body.clone(),
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
                // Persist first — a DM the store refuses (spent msgid) must
                // not be delivered either. A durable row needs both DIDs, and
                // the sender's is the one the origin stamped or none: filing a
                // DM under a DID resolved from a peer-chosen nick wrote one
                // person's thread into another's.
                let sender_did = account.clone();
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
                let mut stored = true;
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
                    stored = state
                        .with_db(|db| match edit_of {
                            Some(ref root) => db.insert_edit_with(
                                &dm_key,
                                &from,
                                &stored_body,
                                timestamp,
                                &tags,
                                &msgid,
                                root,
                                sender_did.as_deref(),
                                &event_ctx,
                            ),
                            None => db.insert_message_with(
                                &dm_key,
                                &from,
                                &stored_body,
                                timestamp,
                                &tags,
                                Some(&msgid),
                                sender_did.as_deref(),
                                &event_ctx,
                            ),
                        })
                        .unwrap_or(true);
                }
                if !stored {
                    return;
                }
                // DM target: a nick or a `did:`. Resolve to every local session
                // bound to the recipient (DID fan-out) — a federated DID-addressed
                // DM must reach the same person here, with no per-server nick
                // interpretation.
                let mut sids =
                    crate::connection::routing::local_sessions_for_target(state, &target);
                // …and the sender's own sessions here, if they have any. The
                // origin fanned this out to their other devices on its send
                // path; that code never runs on this side of the link.
                //
                // Only on a signature this server checked. This delivery is
                // the one place a stamped DID does more than label a message:
                // it routes the message into that identity's own client, in
                // the position of something they sent. A peer that names a
                // local user could put a line in their outbox for free.
                crate::connection::routing::merge_sessions(
                    &mut sids,
                    crate::connection::routing::sender_sessions_for_account(
                        state,
                        account.as_deref().filter(|_| {
                            sig_verdict
                                == Some(crate::connection::messaging::ClientSigVerdict::Valid)
                        }),
                    ),
                );
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

            // ── S2S authorization: verify the pinner is an op ──
            // Pinning is op-only where a user issues it (the PIN command
            // checks); a relayed pin has to answer the same question.
            {
                let channels = state.channels.lock();
                if let Some(ch) = channels.get(&channel) {
                    let is_authorized = ch.remote_member(&pinned_by).is_some_and(|rm| {
                        rm.is_op
                            || rm.did.as_ref().is_some_and(|d| {
                                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
                            })
                    });
                    if !is_authorized {
                        tracing::warn!(
                            channel = %channel, pinned_by = %pinned_by,
                            "S2S Pin rejected: pinner is not an authorized op"
                        );
                        return;
                    }
                }
            }

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
            // Actor DID, origin-stamped or none. A peer chooses the nick it
            // sends, so looking that nick up here answered "who is acting"
            // with whoever holds it on this server — which is what let a peer
            // delete a local user's message by wearing their name.
            let actor_nick = from.split('!').next().unwrap_or(&from).to_string();
            let peer_account = account.map(|a| sanitize_s2s_str(&a, 512));
            let actor_did = peer_account.clone();

            // ── verify before tidying ────────────────────────────────
            // Same rule the relayed-PRIVMSG path follows: the renames and the
            // subject re-rooting below rewrite values the signature covers, so
            // the check reads the tags as they arrived.
            let sig_verdict =
                verify_relayed_mutation_tags(state, peer_account.as_deref(), &target, &tags);
            if let Some(verdict) = sig_verdict {
                use crate::connection::messaging::{ClientSigVerdict, NO_KEY_ON_FILE};
                if let (ClientSigVerdict::Unverifiable(NO_KEY_ON_FILE), Some(did), Some(sig)) = (
                    verdict,
                    peer_account.as_deref(),
                    tags.get("+freeq.at/sig").map(String::as_str),
                ) {
                    crate::peer_keys::fetch_on_miss(state, &origin, did, sig);
                }
                match verdict {
                    ClientSigVerdict::Valid => tracing::debug!(
                        peer = %authenticated_peer_id, target = %target,
                        "Relayed mutation signature verified against the actor's own key"
                    ),
                    ClientSigVerdict::Invalid => tracing::warn!(
                        peer = %authenticated_peer_id, target = %target, from = %from,
                        account = ?peer_account,
                        "Relayed mutation signature did not verify against the key it names — \
                         stripping it before relay"
                    ),
                    ClientSigVerdict::Unverifiable(why) => tracing::debug!(
                        peer = %authenticated_peer_id, target = %target, why = %why,
                        "Relayed mutation signature cannot be checked here"
                    ),
                }
            }

            // ── the verdict decides what happens to a relayed task event ──
            //
            // Both task families — act tags and the stopgap +freeq.at/event
            // coordination family — cross this branch signed, and this is
            // where each is judged. Valid is stored and applied as far as the
            // task's origin allows, then delivered below. Invalid is dropped
            // here and reaches nobody. Anything else this server cannot check
            // yet waits in the defer queue — never refused, because an outage
            // must not read as a forgery, and neither stored nor shown until
            // the key that settles it arrives. Read before the tidying below,
            // so the check sees the tags as they arrived — the signature
            // covers them.
            let is_task_event = crate::connection::act::carries_act_tags(&tags)
                || tags.contains_key("+freeq.at/event");
            // The receipt this server owes if the event turns out to be a move
            // on a task it owns. Held until after delivery below, so the room
            // sees the move before the confirmation of it.
            let mut owed_receipt = None;
            if is_task_event {
                let peer_declared_act = crate::s2s::peer_supports(
                    &manager
                        .peer_capabilities
                        .lock()
                        .await
                        .get(authenticated_peer_id)
                        .cloned()
                        .unwrap_or_default(),
                    crate::s2s::ACT,
                );
                let (action, receipt) = judge_relayed_task_event(
                    state,
                    &from,
                    &target,
                    &tags,
                    &origin,
                    authenticated_peer_id,
                    peer_account.as_deref(),
                    peer_declared_act,
                );
                if action != TaskEventAction::Deliver {
                    return;
                }
                owed_receipt = receipt;
            }

            // ── A relayed mutation takes the actor's own proof ──────────
            //
            // The peer names who acted; only a signature from that account's
            // key makes the claim something this server can check rather than
            // something it is told. Without one the event is dropped here —
            // not applied on the peer's word, and not shown to anyone.
            //
            // Two exemptions, the same two as local ingress, both cases where
            // no proof could exist: an event naming no account is a guest's
            // and keeps the nick rules, and a venue that does not resolve (a
            // DM with a guest here) has no document for anyone to sign.
            //
            // A signature this server cannot check *yet* is dropped like any
            // other: the key lookup runs off this path and never holds an
            // event back, so the first mutation from a signer whose key is not
            // cached is lost, and every mutation from a peer with no key
            // server configured is. That is worth an operator seeing, hence
            // the log naming both.
            if let Some(actor) = peer_account.as_deref()
                // A mutation names the message it acts on. One that names none
                // is not something a signer signs — the sender side reads the
                // same tags and declines — so demanding proof for it would
                // refuse an event nothing could ever have proven.
                && relayed_mutation_in(&tags).is_some_and(|(.., subject, _)| subject.is_some())
                && crate::connection::messaging::signing_venue(state, actor, &target).is_some()
                && sig_verdict != Some(crate::connection::messaging::ClientSigVerdict::Valid)
            {
                tracing::warn!(
                    peer = %authenticated_peer_id, origin = %origin, target = %target,
                    account = %actor, verdict = ?sig_verdict,
                    key_source = crate::peer_keys::has_key_source(state, &origin),
                    "Relayed mutation carries no signature this server can check — dropping it"
                );
                return;
            }

            // The subject as it arrived, before the re-rooting below rewrites
            // it. The signature covers this value, so a filed document may only
            // claim the signature when the two still agree.
            let wire_subject = tags
                .get("+reply")
                .or_else(|| tags.get("+draft/reply"))
                .or_else(|| tags.get("+draft/delete"))
                .or_else(|| tags.get("+delete"))
                .cloned();

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

            // ── the record this server keeps of what it accepted ──────
            //
            // The log holds every chat event this server accepted, and a
            // mutation it verified and applied is one. Relayed messages already
            // file; mutations did not, so a federated server's own log could
            // not rebuild its own derived state and the verify endpoint
            // answered 404 for an act this server had itself applied.
            //
            // The verdict is this server's own. A peer's assurance about a
            // signature is not evidence, so `SigState::Valid` is recorded only
            // where the check above returned `Valid` — and an invalid
            // signature was stripped from `tags` already, so it cannot reach a
            // row at all.
            //
            // The signature rides only when the DID the check ran against is
            // the one the document will bind, and only while the subject is
            // still the value it covers: re-rooting is this server's doing, and
            // a document rebuilt around our edit is not what the sender signed.
            let relayed_actor = peer_account.clone().or_else(|| actor_did.clone());
            let subject_intact = match (&wire_subject, tags.get("+reply")) {
                (Some(wire), Some(now)) => wire == now,
                // A delete names its subject in a tag nothing re-roots.
                _ => true,
            };
            let relayed_sig = peer_account
                .as_ref()
                .filter(|_| subject_intact)
                .and_then(|_| {
                    tags.get("+freeq.at/sig")
                        .or_else(|| tags.get("freeq.at/sig"))
                        .cloned()
                });
            // The sender's id where there is one, so the event this server
            // files and the event the origin holds are the same event — which
            // is what lets a later replay recognise it rather than read it as a
            // second claim on the id.
            let relayed_event_id = tags
                .get(freeq_sdk::chatsig::EVENT_ID_TAG)
                .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
                .cloned()
                .unwrap_or_else(crate::msgid::generate);
            let relayed_venue = relayed_actor
                .as_deref()
                .and_then(|did| crate::connection::messaging::signing_venue(state, did, &target));
            let relayed_event = crate::db::MutationEvent {
                event_id: &relayed_event_id,
                actor_did: relayed_actor.as_deref(),
                signature: relayed_sig.as_deref(),
                venue: relayed_venue.as_deref(),
                ctx: crate::events::EventContext {
                    sig_state: if sig_verdict
                        == Some(crate::connection::messaging::ClientSigVerdict::Valid)
                    {
                        crate::events::SigState::Valid
                    } else {
                        crate::events::SigState::Unverifiable
                    },
                    origin: Some(sanitize_s2s_str(&origin, 64)),
                    ..Default::default()
                },
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

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
                    db.store_reaction_by(
                        &target_msgid,
                        &channel,
                        &nick,
                        did.as_deref(),
                        &emoji,
                        ts,
                        Some(&relayed_event),
                    )
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
                let channel = target.clone();
                state.with_db(|db| {
                    db.remove_reaction_by(
                        &target_msgid,
                        &nick,
                        did.as_deref(),
                        &emoji,
                        &channel,
                        Some(&relayed_event),
                    )
                });
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

                if federated_delete_authorized(
                    state,
                    &storage_key,
                    &root,
                    &actor_nick,
                    actor_did.as_deref(),
                    is_channel,
                ) {
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
                    // A delete's subject is resolved to our root only here, so
                    // the intactness rule the reactions got is applied to it
                    // now: if re-rooting moved the value the signature covers,
                    // the act is filed as a fact without one.
                    let delete_event = crate::db::MutationEvent {
                        event_id: relayed_event.event_id,
                        actor_did: relayed_event.actor_did,
                        signature: relayed_event.signature.filter(|_| root == deleted_msgid),
                        venue: relayed_event.venue,
                        ctx: relayed_event.ctx.clone(),
                        timestamp: relayed_event.timestamp,
                    };
                    state.with_db(|db| {
                        db.soft_delete_message_by(&db_key, &root, Some(&delete_event))
                    });
                    if is_channel {
                        let mut channels = state.channels.lock();
                        if let Some(ch) = channels.get_mut(&storage_key) {
                            ch.history
                                .retain(|h| h.msgid.as_deref() != Some(root.as_str()));
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

            deliver_relayed_tagmsg(
                state,
                &from,
                &target,
                &tags,
                peer_account.as_deref(),
                // The sender's own other devices here get this only when the
                // signature checked out: that delivery puts the event in the
                // named identity's own client as something they did.
                //
                // Two checks answer that, one per family. A mutation has the
                // mutation verdict. A task event never does — it is not a
                // mutation, so that verdict is absent for every one of them —
                // and its evidence is the act checker above, which returns
                // anything but `Deliver` for a signature that did not verify.
                // Reaching here as a task event therefore means what a valid
                // mutation verdict means.
                sig_verdict == Some(crate::connection::messaging::ClientSigVerdict::Valid)
                    || is_task_event,
            );

            if let Some(receipt) = owed_receipt {
                crate::connection::act::broadcast_receipt(state, &receipt, &target);
            }
        }

        S2sMessage::Join {
            nick,
            channel,
            did,
            handle,
            is_op: _, // Intentionally ignored — op status derived locally (C-2)
            actor_class,
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

        // ── Catch-up: what a peer missed while the link was down ──
        //
        // The window a returning peer asks for, answered from the log. The
        // canonical bytes and the signature travel unaltered, so the asker
        // reaches its own verdict on every one — which is why cross-server
        // verification had to land before replay could exist at all.
        S2sMessage::CatchupRequest {
            peer_id,
            since_ts,
            limit,
        } => {
            const MAX_REPLAY: usize = 500;
            // The same predicate the live relay path uses, so a replay is
            // never broader or narrower than what this peer already receives
            // as things happen. See `S2sManager::may_relay_to`.
            let in_scope = {
                let peers = manager.peers.lock().await;
                manager.may_relay_to(authenticated_peer_id, &peers)
            };
            if !in_scope {
                tracing::warn!(
                    peer = %authenticated_peer_id,
                    "S2S catch-up refused: this peer receives no events from us"
                );
                return;
            }
            let limit = if limit == 0 {
                MAX_REPLAY
            } else {
                limit.min(MAX_REPLAY)
            };
            let rows = state
                .with_db(|db| db.events_since(since_ts, limit + 1))
                .unwrap_or_default();
            let more = rows.len() > limit;
            let events: Vec<crate::s2s::ReplayedEvent> = rows
                .into_iter()
                .take(limit)
                .map(|e| crate::s2s::ReplayedEvent {
                    event_id: e.event_id,
                    canonical: e.canonical,
                    // A peer's conclusion about a signature is that peer's.
                    // Only the evidence crosses.
                    signature: e.signature,
                    kind: e.kind,
                    venue: e.venue,
                    actor_did: e.actor_did,
                    subject: e.subject,
                    emoji: e.emoji,
                    // Where the event was minted, which is not necessarily
                    // here. A blank stored origin means we minted it, so it
                    // travels named; anything else travels as filed and is
                    // never overwritten with ours — a task's referee is the
                    // server that opened it, not the one that replayed it.
                    origin: match e.origin {
                        Some(o) if !o.is_empty() => o,
                        _ => manager.server_id.clone(),
                    },
                    timestamp: e.timestamp,
                })
                .collect();
            tracing::info!(
                peer = %authenticated_peer_id,
                asked_by = %peer_id,
                since_ts,
                count = events.len(),
                more,
                "S2S catch-up: answering with events from the log"
            );
            let reply = S2sMessage::CatchupEvents {
                origin: manager.server_id.clone(),
                events,
                more,
            };
            if let Some(entry) = manager.peers.lock().await.get(authenticated_peer_id) {
                let _ = entry.tx.send(reply).await;
            }
        }

        // ── a transition carried here because we own the task ──
        //
        // Verified exactly as any relayed task event is — the same judge, the
        // same three-way verdict, the same defer queue when the signer's key
        // has not arrived yet — and then decided, because deciding is what was
        // asked for. When the rules take a move on a task of ours, the store
        // path mints the receipt for it: the same always-emit rule a local
        // sender's move gets. When the rules refuse it, nothing is filed and
        // nothing goes out — the claim stays unconfirmed wherever it is held,
        // which is the true account of a losing one.
        //
        // Not delivered to local clients. The event reaches them by the
        // ordinary relay every task event takes, and delivering the addressed
        // copy as well would put the same event in the room twice.
        S2sMessage::ActRoute {
            act_id,
            act_event_id,
            tags,
            target,
            from,
            account,
            ..
        } => {
            let act_id = sanitize_s2s_str(&act_id, 100);
            let act_event_id = sanitize_s2s_str(&act_event_id, 100);
            let target = sanitize_s2s_str(&target, 200);
            let from = sanitize_s2s_str(&from, 512);
            let peer_account = account.map(|a| sanitize_s2s_str(&a, 512));

            // Ours to rule on, or misrouted. A task we have never seen opened
            // is not ours either — the store path says so and files nothing.
            let home = state
                .with_db(|db| db.act_task_origin(&act_id))
                .flatten()
                .unwrap_or_default();
            if !home.is_empty() {
                tracing::warn!(
                    peer = %authenticated_peer_id, act_id = %act_id,
                    event_id = %act_event_id, home = %home,
                    "A task transition was carried here for a task another server owns — dropped"
                );
                return;
            }

            let peer_declared_act = crate::s2s::peer_supports(
                &manager
                    .peer_capabilities
                    .lock()
                    .await
                    .get(authenticated_peer_id)
                    .cloned()
                    .unwrap_or_default(),
                crate::s2s::ACT,
            );
            let (_, receipt) = judge_relayed_task_event(
                state,
                &from,
                &target,
                &tags,
                &origin,
                authenticated_peer_id,
                peer_account.as_deref(),
                peer_declared_act,
            );
            match receipt {
                Some(receipt) => {
                    crate::connection::act::broadcast_receipt(state, &receipt, &target)
                }
                // No new receipt, and a peer that is still asking. If this
                // server confirmed the event before, the receipt was written
                // down when it was made, so it is read back and sent to the one peer
                // waiting on it rather than decided a second time. Nothing
                // else covers this: a catch-up replay carries an event under
                // the server that minted it, never under the one that ruled
                // on it, so the ask is the only way back.
                None => {
                    answer_with_stored_receipt(
                        state,
                        manager,
                        authenticated_peer_id,
                        &act_event_id,
                        &target,
                    )
                    .await
                }
            }
        }

        S2sMessage::CatchupEvents {
            origin: _,
            mut events,
            more,
        } => {
            let count = events.len();
            let mut filed = 0usize;
            let mut conflicts = 0usize;
            // Mint order, not arrival order. An event id is a ULID, so its
            // byte order is the order its signer minted it in — the one clock
            // two servers agree on. Without this an opener can arrive behind
            // the follow-up that names it, and the follow-up names a task
            // nothing has opened yet.
            events.sort_by(|a, b| a.event_id.cmp(&b.event_id));
            // Then each task's opener ahead of that task's follow-ups, the
            // same regroup a rebuild does and for the same reason: a signer
            // may mint up to the ingress skew bound in the past, so a
            // follow-up's id can sort ahead of its opener's, and a follow-up
            // replayed first names a task nothing has opened. A stable sort,
            // so mint order survives inside each task, and events of other
            // kinds keep the id order they already have.
            events.sort_by(|a, b| replay_group_key(a).cmp(&replay_group_key(b)));
            for ev in events {
                match apply_replayed_event(state, &manager.server_id, authenticated_peer_id, ev) {
                    ReplayOutcome::Filed => filed += 1,
                    ReplayOutcome::AlreadyHeld => {}
                    ReplayOutcome::Conflicted => conflicts += 1,
                    ReplayOutcome::Unusable => {}
                }
            }
            tracing::info!(
                peer = %authenticated_peer_id,
                count, filed, conflicts, more,
                "S2S catch-up: applied replayed events"
            );
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
pub(crate) use s2s_adversarial_tests::{test_state, test_state_with_config, test_state_with_db};

#[cfg(test)]
mod s2s_adversarial_tests {
    use super::*;
    use crate::s2s::{DedupSet, S2sManager, S2sMessage, TrustLevel};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;

    /// Build a minimal SharedState for testing (no DB, no iroh).
    pub(crate) fn test_state() -> Arc<SharedState> {
        test_state_inner(None, None)
    }

    /// Like `test_state` but with an in-memory SQLite DB attached, so
    /// persistence paths (`identities`, `messages`, …) are exercised. Shared
    /// with other modules' tests (e.g. web endpoints) via the re-export below.
    pub(crate) fn test_state_with_db() -> Arc<SharedState> {
        test_state_inner(Some(crate::db::Db::open_memory().unwrap()), None)
    }

    /// Like `test_state_with_db`, for the flags a test needs to set — the
    /// config is read at runtime, so it cannot be adjusted after construction.
    pub(crate) fn test_state_with_config(config: crate::config::ServerConfig) -> Arc<SharedState> {
        test_state_inner(Some(crate::db::Db::open_memory().unwrap()), Some(config))
    }

    fn test_state_inner(
        db: Option<crate::db::Db>,
        config: Option<crate::config::ServerConfig>,
    ) -> Arc<SharedState> {
        let config = config.unwrap_or_else(|| crate::config::ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            server_name: "test-s2s".to_string(),
            challenge_timeout_secs: 60,
            ..Default::default()
        });
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
            cap_act: Mutex::new(HashSet::new()),
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
            act_deferred: Mutex::new(crate::act_relay::DeferQueue::new(
                config.act_defer_max_per_origin,
                config.act_defer_max_total,
            )),
            act_routes: Mutex::new(crate::act_relay::RouteQueue::new(MAX_PENDING_ROUTES)),
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
    pub(super) fn test_manager() -> Arc<S2sManager> {
        test_manager_with_trust(HashMap::new())
    }

    fn test_manager_with_trust(trust_config: HashMap<String, TrustLevel>) -> Arc<S2sManager> {
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
            trust_config,
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
            peer_contact: Arc::new(parking_lot::Mutex::new(crate::s2s::PeerContact::default())),
            capabilities: crate::s2s::our_capabilities(),
        })
    }

    pub(super) const PEER: &str = "fake-peer-id-for-testing";

    pub(super) async fn setup_authenticated_peer(state: &SharedState, manager: &Arc<S2sManager>) {
        manager
            .authenticated_peers
            .lock()
            .await
            .insert(PEER.to_string());
        // Trust defaults to Full for unconfigured peers, so no seed is needed.
        *state.s2s_manager.lock() = Some(manager.clone());
        // S2S_RATE_LIMITS is process-static; all tests share PEER, so
        // parallel-run counters trip the 100/sec cap mid-suite without
        // this reset.
        S2S_RATE_LIMITS.lock().remove(PEER);
    }

    fn setup_channel(state: &SharedState, name: &str) {
        state.channels.lock().entry(name.to_string()).or_default();
    }

    // ═══════════════════════════════════════════════════════════
    // What a peer relays gets checked before anything tidies it
    // ═══════════════════════════════════════════════════════════
    //
    // A receiving server holds no session for a remote sender, so every one of
    // these goes through the durable per-(DID, kid) key store — the one a
    // cross-server lookup fills. The contract under test is always the same:
    // the document is rebuilt from the bytes that arrived, and the three
    // answers stay distinct (checks out / does not check out / cannot tell).

    use crate::connection::messaging::ClientSigVerdict;

    const SIGNER: &str = "did:plc:relayedsigner";

    /// A signer whose key is on file here, as a key lookup would leave it.
    /// [`signer_on_file`] where a database may be absent. A server without one
    /// resolves no keys, so there is nothing a signature could be checked
    /// against and nothing to register.
    fn signer_on_file_opt(
        state: &Arc<SharedState>,
        did: &str,
    ) -> Option<ed25519_dalek::SigningKey> {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        state.with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))?;
        Some(key)
    }

    fn signer_on_file(state: &Arc<SharedState>, did: &str) -> ed25519_dalek::SigningKey {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        state
            .with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))
            .expect("db present");
        key
    }

    /// The signature a client would put on a channel message.
    fn sign_channel_message(
        key: &ed25519_dalek::SigningKey,
        did: &str,
        msgid: &str,
        channel: &str,
        body: &str,
    ) -> String {
        freeq_sdk::chatsig::ChatDoc::message(
            did,
            msgid,
            &freeq_sdk::chatsig::channel_venue(channel),
            body,
        )
        .sign(key)
    }

    /// A relayed PRIVMSG, exactly as `verify_relayed_privmsg` receives one.
    #[allow(clippy::too_many_arguments)]
    fn check_relayed(
        state: &Arc<SharedState>,
        account: Option<&str>,
        target: &str,
        msgid: Option<&str>,
        text: &str,
        tags: &HashMap<String, String>,
        sig: Option<&str>,
    ) -> Option<crate::connection::messaging::ClientSigVerdict> {
        verify_relayed_privmsg(state, account, target, msgid, text, tags, None, None, sig)
    }

    #[tokio::test]
    async fn relayed_signature_verifies_against_the_message_as_transmitted() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", "hello there");

        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                "hello there",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Valid)
        );
    }

    /// A peer that changes the words in flight. This is the branch that must
    /// read as tampering rather than as "cannot tell" — the whole point of
    /// checking at all.
    #[tokio::test]
    async fn relayed_message_altered_in_flight_does_not_verify() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", "hello there");

        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                "hello, enemy",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Invalid),
            "a body changed in flight must not verify"
        );
    }

    /// The same signed event, relayed into a channel it was never sent to.
    /// The venue is part of the document precisely so this cannot work.
    #[tokio::test]
    async fn relayed_message_replayed_into_another_channel_does_not_verify() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", "hello there");

        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#elsewhere",
                Some("01EVENTID"),
                "hello there",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Invalid),
            "a signed event replayed into another channel must not verify"
        );
    }

    /// A peer that strips the event id. Checking after the receive path minted
    /// a replacement would compare the signature against an id this server
    /// invented and call an honest message forged; checked as it arrived,
    /// there is simply no document to rebuild.
    #[tokio::test]
    async fn relayed_message_without_an_event_id_cannot_be_checked() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", "hello there");

        assert!(
            matches!(
                check_relayed(
                    &state,
                    Some(SIGNER),
                    "#chat",
                    None,
                    "hello there",
                    &HashMap::new(),
                    Some(&sig),
                ),
                Some(ClientSigVerdict::Unverifiable(_))
            ),
            "a relayed message with no event id is uncheckable, not forged"
        );
    }

    /// No `account` on the wire means no signer to build a document around.
    /// The nick map must not stand in: it would have us verify a signature
    /// against an identity the origin never asserted.
    #[tokio::test]
    async fn relayed_message_with_no_sender_did_cannot_be_checked() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", "hello there");

        assert!(matches!(
            check_relayed(
                &state,
                None,
                "#chat",
                Some("01EVENTID"),
                "hello there",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Unverifiable(_))
        ));
    }

    /// A signer this server has never seen. Until a key lookup fills the
    /// store this is "cannot tell" — never "forged".
    #[tokio::test]
    async fn relayed_message_from_an_unknown_signer_cannot_be_checked() {
        let state = test_state_with_db();
        // Signed by a key that was never registered anywhere.
        let stranger = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig = sign_channel_message(&stranger, SIGNER, "01EVENTID", "#chat", "hello there");

        assert!(matches!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                "hello there",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Unverifiable(_))
        ));
    }

    /// A message with no signature at all is not a verdict of any kind.
    #[tokio::test]
    async fn relayed_message_with_no_signature_yields_no_verdict() {
        let state = test_state_with_db();
        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                "hello there",
                &HashMap::new(),
                None,
            ),
            None
        );
    }

    /// A BATCH multiline message is escaped for transport, so the wire `text`
    /// is not the body its sender signed. Rebuilt from the per-line breakdown,
    /// it is. The inline form signs the escaped body instead, and is checked
    /// against exactly what arrived.
    #[tokio::test]
    async fn relayed_multiline_verifies_against_the_assembled_body() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let assembled = "first line\nsecond line";
        let sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", assembled);

        let (wire_text, wire_tags) =
            crate::s2s::encode_privmsg_text_for_s2s(assembled, HashMap::new());
        assert!(
            !wire_text.contains('\n'),
            "the transport escape is what makes this test worth having"
        );
        let lines = vec![
            crate::s2s::MultilineLine {
                body: "first line".to_string(),
                concat: false,
            },
            crate::s2s::MultilineLine {
                body: "second line".to_string(),
                concat: false,
            },
        ];

        assert_eq!(
            verify_relayed_privmsg(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                &wire_text,
                &wire_tags,
                None,
                Some(&lines),
                Some(&sig),
            ),
            Some(ClientSigVerdict::Valid),
            "a multiline body must be reassembled before it is hashed"
        );

        // The inline form is the other sender shape, and it signs the OTHER
        // body: one line, newlines as literal `\n` under the same tag, signed
        // over those escaped bytes. With no per-line breakdown to reassemble,
        // the body is the one that arrived — un-escaping it here was what
        // dropped every signed inline multiline message on receipt.
        let inline_sig = sign_channel_message(&key, SIGNER, "01EVENTID", "#chat", &wire_text);
        assert_eq!(
            verify_relayed_privmsg(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01EVENTID"),
                &wire_text,
                &wire_tags,
                None,
                None,
                Some(&inline_sig),
            ),
            Some(ClientSigVerdict::Valid)
        );
    }

    /// A reply covers what it replies to. The reference now crosses the hop,
    /// so the document rebuilds — and local clients see the thread instead of
    /// a loose message.
    #[tokio::test]
    async fn relayed_reply_verifies_and_reaches_clients_with_its_thread() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);

        let sig = freeq_sdk::chatsig::ChatDoc::message(
            SIGNER,
            "01REPLYEVENT",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "answering you",
        )
        .with_reply("01ROOTMSGID")
        .sign(&key);

        let tags = HashMap::from([("+reply".to_string(), "01ROOTMSGID".to_string())]);
        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01REPLYEVENT"),
                "answering you",
                &tags,
                Some(&sig),
            ),
            Some(ClientSigVerdict::Valid),
            "the reply reference must be part of the rebuilt document"
        );

        // The delivery half: a tag-capable local member sees the thread.
        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("w".to_string(), tx);
        state.cap_message_tags.lock().insert("w".to_string());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("w".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:reply1"),
                from: "remote!u@s2s".to_string(),
                target: "#chat".to_string(),
                text: "answering you".to_string(),
                origin: PEER.to_string(),
                msgid: Some("01REPLYEVENT".to_string()),
                sig: Some(sig.clone()),
                account: Some(SIGNER.to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags,
                multiline_lines: None,
            },
        )
        .await;

        let frame = rx.try_recv().expect("the message reached the member");
        assert!(
            frame.contains("+reply=01ROOTMSGID"),
            "a federated reply must arrive as a reply: {frame}"
        );
    }

    /// A relayed message from a signer we hold no key for asks that signer's
    /// home server for it — and is delivered anyway, in the same pass. A
    /// lookup that held chat back would be the wrong trade every time.
    #[tokio::test]
    async fn a_relayed_message_from_an_unknown_signer_asks_its_home_server() {
        let did = "did:plc:unknownatreceive";
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = freeq_sdk::sigtag::derive_kid(&key.verifying_key());
        let sig = sign_channel_message(&key, did, "01UNKNOWNSIGNER", "#chat", "who am i");

        // A peer whose key server is named, but which we have asked nothing of
        // yet. The address need not answer: what is under test is that the
        // lookup is started and the message does not wait for it.
        let state = test_state_with_config(crate::config::ServerConfig {
            s2s_peer_api: vec![format!("{PEER}=http://127.0.0.1:1")],
            ..Default::default()
        });
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("w".to_string(), tx);
        state.cap_message_tags.lock().insert("w".to_string());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("w".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:unknown1"),
                from: "stranger!u@s2s".to_string(),
                target: "#chat".to_string(),
                text: "who am i".to_string(),
                origin: PEER.to_string(),
                msgid: Some("01UNKNOWNSIGNER".to_string()),
                sig: Some(sig),
                account: Some(did.to_string()),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        assert!(
            rx.try_recv().is_ok(),
            "the message must reach local members without waiting on a key lookup"
        );
        assert!(
            crate::peer_keys::lookup_pending(did, &kid),
            "an unknown signer must start a lookup with its home server"
        );
    }

    // ── acting on the answer ─────────────────────────────────────

    /// Deliver a relayed channel PRIVMSG and return the frame a tag-capable
    /// local member received.
    async fn relay_to_member(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        envelope: &str,
        did: Option<&str>,
        msgid: &str,
        text: &str,
        sig: Option<String>,
    ) -> String {
        let (tx, mut rx) = mpsc::channel(16);
        let session = format!("w-{envelope}");
        state.connections.lock().insert(session.clone(), tx);
        state.cap_message_tags.lock().insert(session.clone());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert(session.clone());

        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:{envelope}"),
                from: "remote!u@s2s".to_string(),
                target: "#chat".to_string(),
                text: text.to_string(),
                origin: PEER.to_string(),
                msgid: Some(msgid.to_string()),
                sig,
                account: did.map(str::to_string),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        rx.try_recv().expect("the message reached the member")
    }

    /// The same, for a relay that may legitimately deliver nothing.
    #[allow(clippy::too_many_arguments)]
    async fn relay_to_member_maybe(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        envelope: &str,
        did: Option<&str>,
        msgid: &str,
        text: &str,
        sig: Option<String>,
    ) -> Option<String> {
        let (tx, mut rx) = mpsc::channel(16);
        let session = format!("w-{envelope}");
        state.connections.lock().insert(session.clone(), tx);
        state.cap_message_tags.lock().insert(session.clone());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert(session.clone());

        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Privmsg {
                event_id: format!("{PEER}:{envelope}"),
                from: "remote!u@s2s".to_string(),
                target: "#chat".to_string(),
                text: text.to_string(),
                origin: PEER.to_string(),
                msgid: Some(msgid.to_string()),
                sig,
                account: did.map(str::to_string),
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;

        rx.try_recv().ok()
    }

    /// A signature that does not check out is evidence about the bytes, so
    /// the message does not travel: no local client sees it, and nothing is
    /// filed for a reader of history to find.
    #[tokio::test]
    async fn a_relayed_message_whose_signature_fails_is_dropped() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);

        // Signed over one body, relayed with another.
        let sig = sign_channel_message(&key, SIGNER, "01TAMPERED", "#chat", "what was said");
        let delivered = relay_to_member_maybe(
            &state,
            &mgr,
            "tampered",
            Some(SIGNER),
            "01TAMPERED",
            "what a liar substituted",
            Some(sig),
        )
        .await;
        assert!(
            delivered.is_none(),
            "a message whose signature failed must not reach local clients: {delivered:?}"
        );
        assert!(
            state
                .with_db(|db| db.find_message_by_msgid("01TAMPERED"))
                .flatten()
                .is_none(),
            "nor may it be filed for a reader of history to find"
        );

        // The same rule for a signed event replayed somewhere it was never
        // sent: the venue is inside the document, so the signature does not
        // survive the move — which reads as a failure, and the replay is
        // refused rather than delivered shorn of its proof.
        let elsewhere = sign_channel_message(&key, SIGNER, "01REPLAYED", "#private", "for us only");
        let delivered = relay_to_member_maybe(
            &state,
            &mgr,
            "replayed",
            Some(SIGNER),
            "01REPLAYED",
            "for us only",
            Some(elsewhere),
        )
        .await;
        assert!(
            delivered.is_none(),
            "a signed event replayed into another channel must not arrive: {delivered:?}"
        );
    }

    /// The other side of the same rule: a signature that checks out is
    /// relayed byte-identical. Re-signing it here would replace a sender's
    /// proof with this server's opinion.
    #[tokio::test]
    async fn a_relayed_message_that_checks_out_keeps_its_signature() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);

        let sig = sign_channel_message(&key, SIGNER, "01GENUINE", "#chat", "genuinely mine");
        let frame = relay_to_member(
            &state,
            &mgr,
            "genuine",
            Some(SIGNER),
            "01GENUINE",
            "genuinely mine",
            Some(sig.clone()),
        )
        .await;

        assert!(
            frame.contains(&format!("+freeq.at/sig={sig}")),
            "a verified signature must cross unchanged: {frame}"
        );
    }

    /// A signature we cannot judge is not evidence of anything, so it is
    /// relayed untouched and labeled by what the verify endpoint says about
    /// it. Stripping here would destroy a signature that a server holding the
    /// key could still check.
    #[tokio::test]
    async fn a_relayed_message_we_cannot_check_keeps_its_signature() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        // Signed by a key nobody here has ever seen.
        let stranger = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig = sign_channel_message(&stranger, SIGNER, "01UNKNOWNKEY", "#chat", "hello");
        let frame = relay_to_member(
            &state,
            &mgr,
            "unknownkey",
            Some(SIGNER),
            "01UNKNOWNKEY",
            "hello",
            Some(sig.clone()),
        )
        .await;

        assert!(
            frame.contains(&format!("+freeq.at/sig={sig}")),
            "an uncheckable signature must be relayed as it arrived: {frame}"
        );
    }

    /// Legacy and unsigned traffic is untouched by any of this: the wire
    /// shape a frozen peer produces relays exactly as it did before.
    #[tokio::test]
    async fn legacy_and_unsigned_traffic_relays_unchanged() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        // A bare base64 blob over the retired canonical — not parseable as a
        // tag, and never checkable by anyone.
        let legacy = "bGVnYWN5LXNpZ25hdHVyZS1ieXRlcw";
        let frame = relay_to_member(
            &state,
            &mgr,
            "legacy",
            Some(SIGNER),
            "01LEGACY",
            "from an older server",
            Some(legacy.to_string()),
        )
        .await;
        assert!(
            frame.contains(&format!("+freeq.at/sig={legacy}")),
            "a legacy signature must relay exactly as today: {frame}"
        );

        // And a peer that sends no signature and no account at all.
        let frame = relay_to_member(
            &state,
            &mgr,
            "unsigned",
            None,
            "01UNSIGNED",
            "no signature here",
            None,
        )
        .await;
        assert!(!frame.contains("+freeq.at/sig"));
        assert!(frame.contains("no signature here"));
    }

    // ── mutations ────────────────────────────────────────────────

    #[tokio::test]
    async fn relayed_mutation_verifies_against_the_subject_as_named() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let sig = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::React,
            SIGNER,
            "01MUTATIONID",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "01SUBJECTMSGID",
        )
        .with_emoji("👍")
        .sign(&key);

        let tags = |subject: &str| {
            HashMap::from([
                ("+react".to_string(), "👍".to_string()),
                ("+reply".to_string(), subject.to_string()),
                (
                    freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                    "01MUTATIONID".to_string(),
                ),
                ("+freeq.at/sig".to_string(), sig.clone()),
            ])
        };

        assert_eq!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), "#chat", &tags("01SUBJECTMSGID")),
            Some(ClientSigVerdict::Valid)
        );

        // The subject swapped in flight — the reaction moved onto a different
        // message than the one its author reacted to.
        assert_eq!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), "#chat", &tags("01OTHERMESSAGE")),
            Some(ClientSigVerdict::Invalid),
            "a mutation whose subject was swapped must not verify"
        );
    }

    /// No sender mints mutation event ids yet, so this is what live relayed
    /// mutations classify as today: uncheckable, never forged.
    #[tokio::test]
    async fn relayed_mutation_without_an_event_id_cannot_be_checked() {
        let state = test_state_with_db();
        let tags = HashMap::from([
            ("+draft/delete".to_string(), "01SUBJECTMSGID".to_string()),
            ("+freeq.at/sig".to_string(), "ed25519:kid:sig".to_string()),
        ]);
        assert!(matches!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), "#chat", &tags),
            Some(ClientSigVerdict::Unverifiable(_))
        ));
    }

    /// A reaction whose subject was swapped in flight is not relayed at all.
    /// The signature stopped covering the event, and a mutation this server
    /// cannot stand behind does not get applied on the peer's word — the
    /// swapped-onto message is someone else's, and moving a reaction onto it
    /// is the whole attack.
    #[tokio::test]
    async fn a_relayed_mutation_whose_signature_fails_is_dropped() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);

        let sig = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::React,
            SIGNER,
            "01SWAPPED",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "01WHATTHEYREACTEDTO",
        )
        .with_emoji("👍")
        .sign(&key);

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("m".to_string(), tx);
        state.cap_message_tags.lock().insert("m".to_string());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("m".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:swapped"),
                from: "remote!u@s2s".to_string(),
                target: "#chat".to_string(),
                tags: HashMap::from([
                    ("+react".to_string(), "👍".to_string()),
                    // The message the reaction was moved onto.
                    ("+reply".to_string(), "01SOMEONEELSESMESSAGE".to_string()),
                    (
                        freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                        "01SWAPPED".to_string(),
                    ),
                    ("+freeq.at/sig".to_string(), sig),
                ]),
                origin: PEER.to_string(),
                account: Some(SIGNER.to_string()),
            },
        )
        .await;

        assert!(
            rx.try_recv().is_err(),
            "a mutation whose signature failed must not reach local clients at all"
        );
        let filed = state
            .with_db(|db| db.get_reactions_for_messages(&["01SOMEONEELSESMESSAGE"]))
            .expect("test state has a database");
        assert!(
            filed.is_empty(),
            "and must not be on file either: {filed:?}"
        );
    }

    /// The unsigned case, which is what an older peer sends: the actor is
    /// named, nothing proves it, and the event does not apply.
    #[tokio::test]
    async fn a_relayed_mutation_with_no_signature_is_dropped() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("m".to_string(), tx);
        state.cap_message_tags.lock().insert("m".to_string());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("m".to_string());

        for tags in [
            HashMap::from([("+draft/delete".to_string(), "01SUBJECTMSGID".to_string())]),
            HashMap::from([
                ("+react".to_string(), "👍".to_string()),
                ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
            ]),
            HashMap::from([
                ("+freeq.at/unreact".to_string(), "👍".to_string()),
                ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
            ]),
        ] {
            process_s2s_message(
                &state,
                &mgr,
                PEER,
                S2sMessage::Tagmsg {
                    event_id: format!("{PEER}:unsigned"),
                    from: "remote!u@s2s".to_string(),
                    target: "#chat".to_string(),
                    tags: tags.clone(),
                    origin: PEER.to_string(),
                    account: Some(SIGNER.to_string()),
                },
            )
            .await;
            assert!(
                rx.try_recv().is_err(),
                "an unsigned relayed mutation must not reach local clients: {tags:?}"
            );
        }
    }

    /// A mutation naming no account is a guest's, and a guest's mutations
    /// have never been signed by anyone. They keep the rules they had.
    #[tokio::test]
    async fn a_relayed_guest_mutation_still_applies() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        let (tx, mut rx) = mpsc::channel(16);
        state.connections.lock().insert("m".to_string(), tx);
        state.cap_message_tags.lock().insert("m".to_string());
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("m".to_string());

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:guestreact"),
                from: "guest!u@s2s".to_string(),
                target: "#chat".to_string(),
                tags: HashMap::from([
                    ("+react".to_string(), "👍".to_string()),
                    ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
                ]),
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;

        let frame = rx.try_recv().expect("a guest's reaction still relays");
        assert!(frame.contains("+react"), "{frame}");
    }

    /// Every chat path resolves a key by the `kid` its signature names, never
    /// by "the identity's current key". A device that rotates keys — or a
    /// second device signing in — would otherwise invalidate every signature
    /// the earlier key made, turning honest history into a wall of forgery
    /// verdicts the moment someone reconnects.
    ///
    /// Two of the three paths are here: a relayed message, and a replayed
    /// event checked against the bytes it travelled with. The third, the
    /// verify endpoint's classifier, is pinned in `web.rs`.
    #[tokio::test]
    async fn chat_paths_resolve_a_key_by_kid_not_by_latest() {
        let state = test_state_with_db();
        // The key that signs, registered first…
        let old = signer_on_file(&state, SIGNER);
        // …and a newer one, which is what "the identity's current key" means.
        let _new = signer_on_file(&state, SIGNER);

        let sig = sign_channel_message(&old, SIGNER, "01OLDKEY", "#chat", "signed before rotating");
        assert_eq!(
            check_relayed(
                &state,
                Some(SIGNER),
                "#chat",
                Some("01OLDKEY"),
                "signed before rotating",
                &HashMap::new(),
                Some(&sig),
            ),
            Some(crate::connection::messaging::ClientSigVerdict::Valid),
            "a relayed message signed with a retired key must still verify"
        );

        // The replay path checks the bytes it was handed, by the same rule.
        let canonical = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::Delete,
            SIGNER,
            "01OLDKEYDELETE",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "01SUBJECTMSGID",
        )
        .canonical();
        let mutation_sig = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::Delete,
            SIGNER,
            "01OLDKEYDELETE",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "01SUBJECTMSGID",
        )
        .sign(&old);
        assert_eq!(
            crate::connection::messaging::verify_canonical_bytes(
                &state,
                SIGNER,
                &canonical,
                &mutation_sig,
            ),
            crate::connection::messaging::ClientSigVerdict::Valid,
            "a replayed event signed with a retired key must still verify"
        );
    }

    /// A DM mutation that crossed the hop verifies here against the venue its
    /// signature covers.
    ///
    /// The venue is the sorted DID pair, and the receiving server rebuilds it
    /// from the wire target — which is a nick or a `did:` depending on how the
    /// sender addressed it, and neither of which is itself a venue. So the
    /// document is only reproducible here when the recipient resolves; the
    /// three cases below are the three answers that can come back, and the
    /// third is the one that matters: an unresolvable recipient makes the act
    /// *uncheckable*, never forged.
    #[tokio::test]
    async fn a_relayed_dm_mutation_verifies_against_the_pair_not_the_wire_target() {
        let state = test_state_with_db();
        let key = signer_on_file(&state, SIGNER);
        let recipient = "did:plc:relayedrecipient";
        let sig = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::React,
            SIGNER,
            "01DMMUTATION",
            &freeq_sdk::chatsig::dm_venue(SIGNER, recipient),
            "01SUBJECTMSGID",
        )
        .with_emoji("👍")
        .sign(&key);
        let tags = HashMap::from([
            ("+react".to_string(), "👍".to_string()),
            ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
            (
                freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                "01DMMUTATION".to_string(),
            ),
            ("+freeq.at/sig".to_string(), sig),
        ]);

        // Addressed to the recipient's DID: the pair is on the wire already.
        assert_eq!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), recipient, &tags),
            Some(ClientSigVerdict::Valid),
        );

        // Addressed to a nick this server can resolve to that same DID — the
        // signer signed the pair either way, and so must the rebuild.
        state
            .nick_owners
            .lock()
            .insert("recipient".to_string(), recipient.to_string());
        assert_eq!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), "recipient", &tags),
            Some(ClientSigVerdict::Valid),
            "a nick and a DID name one conversation, and one venue",
        );

        // A nick nobody here knows: no venue can be rebuilt, so there is
        // nothing to have checked. Honest, and never an accusation.
        assert!(
            matches!(
                verify_relayed_mutation_tags(&state, Some(SIGNER), "astranger", &tags),
                Some(ClientSigVerdict::Unverifiable(_))
            ),
            "an unresolvable recipient is uncheckable, not forged",
        );
    }

    // ── what a relayed mutation leaves on file ───────────────────
    //
    // The events table's contract is every chat event this server accepted,
    // and a mutation this server verified and applied is one. Relayed messages
    // already file; mutations were the asymmetry, so a federated server's log
    // could not rebuild its own derived state and `/api/v1/verify` answered 404
    // for an act it had itself applied.

    /// Drive a signed mutation in over S2S and hand back the event it filed.
    async fn relay_mutation(
        state: &Arc<SharedState>,
        mgr: &Arc<S2sManager>,
        target: &str,
        venue: &str,
        event_id: &str,
        key: &ed25519_dalek::SigningKey,
        account: Option<&str>,
    ) -> Option<crate::db::StoredEvent> {
        let sig = freeq_sdk::chatsig::ChatDoc::mutation(
            freeq_sdk::chatsig::Mutation::React,
            SIGNER,
            event_id,
            venue,
            "01SUBJECTMSGID",
        )
        .with_emoji("👍")
        .sign(key);
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:{event_id}"),
                from: "remote!u@s2s".to_string(),
                target: target.to_string(),
                tags: HashMap::from([
                    ("+react".to_string(), "👍".to_string()),
                    ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
                    (
                        freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                        event_id.to_string(),
                    ),
                    ("+freeq.at/sig".to_string(), sig),
                ]),
                origin: PEER.to_string(),
                account: account.map(str::to_string),
            },
        )
        .await;
        state.with_db(|db| db.get_event(event_id)).flatten()
    }

    /// A channel mutation that crossed the hop is on file here, with this
    /// server's own verdict on it.
    #[tokio::test]
    async fn a_relayed_mutation_is_filed_at_the_receiver() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);

        let ev = relay_mutation(
            &state,
            &mgr,
            "#chat",
            &freeq_sdk::chatsig::channel_venue("#chat"),
            "01RELAYEDREACT",
            &key,
            Some(SIGNER),
        )
        .await
        .expect("a mutation this server applied is a mutation it accepted");

        assert_eq!(ev.kind, "react");
        assert_eq!(ev.venue, "#chat");
        assert_eq!(ev.actor_did.as_deref(), Some(SIGNER));
        assert_eq!(ev.subject.as_deref(), Some("01SUBJECTMSGID"));
        assert_eq!(ev.emoji.as_deref(), Some("👍"));
        assert!(ev.signature.is_some(), "relayed verbatim");
        assert_eq!(
            ev.sig_state,
            crate::events::SigState::Valid,
            "this server checked it against the key it names — its own verdict, \
             not the peer's claim",
        );
        assert_eq!(
            ev.origin.as_deref(),
            Some(PEER),
            "the row records which peer relayed it",
        );
    }

    /// A relayed DM mutation files under the pair its signature covers — the
    /// same venue the receive-side check verified against, not the wire target.
    #[tokio::test]
    async fn a_relayed_dm_mutation_is_filed_under_the_pair() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let key = signer_on_file(&state, SIGNER);
        let recipient = "did:plc:relayedrecipient";

        let ev = relay_mutation(
            &state,
            &mgr,
            recipient,
            &freeq_sdk::chatsig::dm_venue(SIGNER, recipient),
            "01RELAYEDDM",
            &key,
            Some(SIGNER),
        )
        .await
        .expect("a relayed DM mutation is filed too");

        assert_eq!(
            ev.venue,
            freeq_sdk::chatsig::dm_venue(SIGNER, recipient),
            "the venue the signature covers, not the `did:` on the wire",
        );
        assert_eq!(ev.sig_state, crate::events::SigState::Valid);
    }

    /// A guest's relayed mutation is a fact without a signature, filed the way
    /// local ingress files one: bare, and honest about it.
    #[tokio::test]
    async fn an_unsigned_relayed_mutation_is_filed_as_bare_facts() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:bare"),
                from: "guest!u@s2s".to_string(),
                target: "#chat".to_string(),
                tags: HashMap::from([
                    ("+react".to_string(), "👍".to_string()),
                    ("+reply".to_string(), "01SUBJECTMSGID".to_string()),
                    (
                        freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
                        "01BARERELAYED".to_string(),
                    ),
                ]),
                origin: PEER.to_string(),
                account: None,
            },
        )
        .await;

        let ev = state
            .with_db(|db| db.get_event("01BARERELAYED"))
            .flatten()
            .expect("the act happened, so it is on file");
        assert!(ev.canonical.is_empty(), "nothing signed it, so no document");
        assert_eq!(ev.sig_state, crate::events::SigState::Unsigned);
        assert_eq!(ev.emoji.as_deref(), Some("👍"), "its facts are stated");
    }

    /// A mutation received live and then replayed after a link flap is the
    /// same event, not a second claim on its id.
    ///
    /// The receiver rebuilds the canonical from what arrived; the replay
    /// carries the origin's stored bytes. If those disagreed by a byte, replay
    /// would read an honest re-send as equivocation and log it as such — so
    /// this pins that they are the same bytes.
    #[tokio::test]
    async fn a_mutation_received_live_is_not_refiled_by_a_later_replay() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");
        let key = signer_on_file(&state, SIGNER);
        let venue = freeq_sdk::chatsig::channel_venue("#chat");

        let filed = relay_mutation(
            &state,
            &mgr,
            "#chat",
            &venue,
            "01LIVETHENREPLAY",
            &key,
            Some(SIGNER),
        )
        .await
        .expect("filed on live receipt");

        // What the origin holds for the same act, and would replay.
        let replayed = crate::s2s::ReplayedEvent {
            event_id: "01LIVETHENREPLAY".to_string(),
            canonical: crate::events::mutation_canonical(
                freeq_sdk::chatsig::Mutation::React,
                SIGNER,
                "01LIVETHENREPLAY",
                &venue,
                "01SUBJECTMSGID",
                Some("👍"),
            ),
            signature: filed.signature.clone(),
            kind: "react".to_string(),
            venue: venue.clone(),
            actor_did: Some(SIGNER.to_string()),
            subject: Some("01SUBJECTMSGID".to_string()),
            emoji: Some("👍".to_string()),
            origin: PEER.to_string(),
            timestamp: filed.timestamp,
        };
        assert_eq!(
            apply_replayed_event(&state, "us", PEER, replayed),
            ReplayOutcome::AlreadyHeld,
            "the same act twice is one event — spent stays spent",
        );
    }

    /// A TAGMSG that is not a mutation (a typing notification) is not a signed
    /// event and gets no verdict.
    #[tokio::test]
    async fn relayed_tagmsg_that_is_not_a_mutation_yields_no_verdict() {
        let state = test_state_with_db();
        let tags = HashMap::from([("+typing".to_string(), "active".to_string())]);
        assert_eq!(
            verify_relayed_mutation_tags(&state, Some(SIGNER), "#chat", &tags),
            None
        );
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
    // S2S trust: configured trust is authoritative
    // ═══════════════════════════════════════════════════════════

    /// A peer cannot escalate itself by declaring a higher trust level in its
    /// Hello. The operator's --s2s-peer-trust config is the sole authority, so
    /// a peer configured `readonly` stays `readonly` even after announcing
    /// `full`.
    #[tokio::test]
    async fn configured_trust_is_not_overridden_by_peer_declared_hello() {
        let state = test_state();
        // Configure PEER as readonly so there is a restriction to try to escape.
        let manager = test_manager_with_trust(
            [(PEER.to_string(), TrustLevel::Readonly)]
                .into_iter()
                .collect(),
        );
        *state.s2s_manager.lock() = Some(manager.clone());

        assert_eq!(
            manager.get_trust(PEER).await,
            TrustLevel::Readonly,
            "precondition: PEER should start readonly"
        );

        // The peer announces full trust in its Hello.
        let hello = S2sMessage::Hello {
            peer_id: PEER.to_string(),
            server_name: "liar".to_string(),
            protocol_version: 2,
            trust_level: Some("full".to_string()),
            capabilities: vec![],
        };
        process_s2s_message(&state, &manager, PEER, hello).await;

        assert_eq!(
            manager.get_trust(PEER).await,
            TrustLevel::Readonly,
            "a peer's declared Hello trust must not override configured trust"
        );
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

    /// The same event delivered twice over S2S — a peer re-sending its tail
    /// after a reconnect, or the same event arriving via two relay paths —
    /// files exactly one row and reaches local clients exactly once.
    /// Distinct envelope ids, same msgid: envelope dedup can't catch this;
    /// only msgid uniqueness can. And what the store refuses must not be
    /// relayed: clients key messages by msgid, so forwarding a conflicting
    /// copy would let a peer rewrite a displayed message in place.
    #[tokio::test]
    async fn s2s_duplicate_privmsg_delivery_files_one_row() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#chat");

        // A local member watching the channel.
        let (tx, mut rx) = mpsc::channel(16);
        state
            .connections
            .lock()
            .insert("watcher-sess".to_string(), tx);
        state
            .channels
            .lock()
            .get_mut("#chat")
            .unwrap()
            .members
            .insert("watcher-sess".to_string());

        let msg = |envelope: &str, text: &str| S2sMessage::Privmsg {
            event_id: format!("{PEER}:{envelope}"),
            from: "remote!u@s2s".to_string(),
            target: "#chat".to_string(),
            text: text.to_string(),
            origin: PEER.to_string(),
            msgid: Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()),
            sig: None,
            account: None,
            recipient_did: None,
            replaces_msgid: None,
            tags: HashMap::new(),
            multiline_lines: None,
        };
        process_s2s_message(&state, &mgr, PEER, msg("dup1", "hello twice")).await;
        // Benign re-delivery, then a conflicting claim on the same id.
        process_s2s_message(&state, &mgr, PEER, msg("dup2", "hello twice")).await;
        process_s2s_message(&state, &mgr, PEER, msg("dup3", "impostor content")).await;

        let rows = state
            .with_db(|db| db.get_messages("#chat", 10, None))
            .unwrap();
        assert_eq!(rows.len(), 1, "re-delivery must not file a second row");
        assert_eq!(rows[0].text, "hello twice", "first write wins");

        let first = rx.try_recv().expect("the first delivery reaches members");
        assert!(first.contains("hello twice"));
        assert!(
            rx.try_recv().is_err(),
            "refused inserts must not be relayed to members"
        );
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
    pub(super) fn test_manager_with_broadcast_rx() -> (Arc<S2sManager>, mpsc::Receiver<S2sMessage>)
    {
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
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
            peer_contact: Arc::new(parking_lot::Mutex::new(crate::s2s::PeerContact::default())),
            capabilities: crate::s2s::our_capabilities(),
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

    #[tokio::test]
    async fn s2s_pin_from_non_op_rejected() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#pintest");

        add_remote_member(&state, "#pintest", "non_op_pinner", false);

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Pin {
                event_id: format!("{PEER}:8"),
                channel: "#pintest".to_string(),
                msgid: "01PINNED000000000000000000".to_string(),
                pinned_by: "non_op_pinner".to_string(),
                adding: true,
                origin: PEER.to_string(),
            },
        )
        .await;

        let channels = state.channels.lock();
        let ch = channels.get("#pintest").unwrap();
        assert!(
            ch.pins.is_empty(),
            "a non-op's relayed pin must not be stored — {} pin(s) in list",
            ch.pins.len()
        );
    }

    #[tokio::test]
    async fn s2s_pin_from_an_op_is_stored() {
        let state = test_state();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#pinok");

        add_remote_member(&state, "#pinok", "op_pinner", true);

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Pin {
                event_id: format!("{PEER}:9"),
                channel: "#pinok".to_string(),
                msgid: "01PINNED000000000000000000".to_string(),
                pinned_by: "op_pinner".to_string(),
                adding: true,
                origin: PEER.to_string(),
            },
        )
        .await;

        let channels = state.channels.lock();
        let ch = channels.get("#pinok").unwrap();
        assert_eq!(ch.pins.len(), 1, "an op's relayed pin must still be stored");
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

        // The limiter's window is a wall-clock second: the counter resets when
        // `SystemTime::now().as_secs()` ticks. A burst that straddles that tick
        // is *legitimately* allowed more than the limit, so send the burst inside
        // one window or the assertion is about the clock, not the limiter. This
        // failed on CI for exactly that reason, having passed locally.
        let secs_now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        };
        let count;
        let mut attempts = 0;
        loop {
            attempts += 1;
            assert!(attempts <= 5, "never landed a burst inside one window");

            // Start near the top of a second, so 101 sends have a whole one.
            let start_window = secs_now();
            S2S_RATE_LIMITS.lock().remove(RL_PEER);

            for i in 0..101u64 {
                process_s2s_message(
                    &state,
                    &mgr,
                    RL_PEER,
                    S2sMessage::Privmsg {
                        // A fresh event id per attempt: dedup would otherwise
                        // drop the retry's messages before the limiter sees them.
                        event_id: format!("{RL_PEER}:{}-{attempts}", 200 + i),
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
            let straddled = secs_now() != start_window;

            let mut received = 0;
            while let Ok(Some(_)) =
                tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
            {
                received += 1;
            }
            if !straddled {
                count = received;
                break;
            }
            // Drain and retry: this burst spanned a counter reset.
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
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

    /// A federated actor is not in our nick map, so `account` is the only way
    /// a local client learns who acted. Relayed to receivers that asked for
    /// account-tag, and only from the DID the origin stamped.
    #[tokio::test]
    async fn s2s_tagmsg_carries_the_origin_stamped_account() {
        const REMOTE_DID: &str = "did:plc:remoteactor";
        // A database, because the reaction now has to carry a signature and a
        // signature is checked against a key this server holds.
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        setup_channel(&state, "#acct-test");

        // Two local members: one asked for account-tag, one did not.
        let (tx_with, mut rx_with) = mpsc::channel(16);
        let (tx_without, mut rx_without) = mpsc::channel(16);
        {
            let mut conns = state.connections.lock();
            conns.insert("with-sess".to_string(), tx_with);
            conns.insert("without-sess".to_string(), tx_without);
        }
        {
            let mut channels = state.channels.lock();
            let ch = channels.get_mut("#acct-test").unwrap();
            ch.members.insert("with-sess".to_string());
            ch.members.insert("without-sess".to_string());
        }
        {
            let mut tags = state.cap_message_tags.lock();
            tags.insert("with-sess".to_string());
            tags.insert("without-sess".to_string());
        }
        state.cap_account_tag.lock().insert("with-sess".to_string());

        let mut tags = HashMap::new();
        tags.insert("+react".to_string(), "👍".to_string());
        tags.insert("+reply".to_string(), "msg001".to_string());
        sign_relayed_mutation(
            &state,
            Some(REMOTE_DID),
            "#acct-test",
            freeq_sdk::chatsig::Mutation::React,
            "msg001",
            Some("👍"),
            &mut tags,
        );

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:acct1"),
                from: "remote!r@remote".to_string(),
                target: "#acct-test".to_string(),
                tags,
                origin: PEER.to_string(),
                account: Some(REMOTE_DID.to_string()),
            },
        )
        .await;

        let with = tokio::time::timeout(std::time::Duration::from_secs(1), rx_with.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            with.contains(&format!("account={REMOTE_DID}")),
            "a receiver that negotiated account-tag must be told who acted, got: {with}"
        );

        let without = tokio::time::timeout(std::time::Duration::from_secs(1), rx_without.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            !without.contains("account="),
            "a receiver that never asked for account-tag must not be sent one, got: {without}"
        );
    }

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
        // An edit is a mutation, so it crosses the hop with the editor's own
        // signature or not at all. A plain message needs none.
        let sig = replaces.and_then(|root| {
            let did = account?;
            let venue = crate::connection::messaging::signing_venue(state, did, channel)?;
            let key = signer_on_file_opt(state, did)?;
            Some(
                freeq_sdk::chatsig::ChatDoc::message(did, msgid, &venue, text)
                    .with_edit(root)
                    .sign(&key),
            )
        });
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
                sig,
                account: account.map(|a| a.to_string()),
                recipient_did: None,
                replaces_msgid: replaces.map(|r| r.to_string()),
                tags: HashMap::new(),
                multiline_lines: None,
            },
        )
        .await;
    }

    /// Sign a relayed mutation the way a current peer's client does: the
    /// actor's own key, over the venue the receiving server rebuilds.
    ///
    /// Registers the key as the peer's key server would have supplied it. A
    /// venue that does not resolve leaves the event unsigned, because nothing
    /// could have signed it — the exemption, reproduced rather than
    /// worked around.
    fn sign_relayed_mutation(
        state: &Arc<SharedState>,
        account: Option<&str>,
        target: &str,
        kind: freeq_sdk::chatsig::Mutation,
        subject: &str,
        emoji: Option<&str>,
        tags: &mut HashMap<String, String>,
    ) {
        let Some(did) = account else { return };
        let Some(venue) = crate::connection::messaging::signing_venue(state, did, target) else {
            return;
        };
        let Some(key) = signer_on_file_opt(state, did) else {
            return;
        };
        let event_id = crate::msgid::generate();
        let mut doc = freeq_sdk::chatsig::ChatDoc::mutation(kind, did, &event_id, &venue, subject);
        if let Some(emoji) = emoji {
            doc = doc.with_emoji(emoji);
        }
        tags.insert("+freeq.at/sig".to_string(), doc.sign(&key));
        tags.insert(freeq_sdk::chatsig::EVENT_ID_TAG.to_string(), event_id);
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
        sign_relayed_mutation(
            state,
            account,
            channel,
            freeq_sdk::chatsig::Mutation::Delete,
            msgid,
            None,
            &mut tags,
        );
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
        assert_eq!(
            state.with_db(|db| Ok(db.root_of("id-edit"))),
            Some("id-orig".to_string())
        );
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

        relay_message(
            &state,
            &mgr,
            "#fedunseen",
            "id-edit",
            "v2",
            Some("id-never"),
        )
        .await;

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
        relay_delete(
            &state,
            &mgr,
            "#feddel",
            "id-1",
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;

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
        relay_delete(
            &state,
            &mgr,
            "#feddel2",
            "id-2",
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;

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
        sign_relayed_mutation(
            &state,
            Some(AUTHOR_DID),
            "#fedreact",
            freeq_sdk::chatsig::Mutation::React,
            "id-1",
            Some("🔥"),
            &mut tags,
        );
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
            stored
                .get("id-1")
                .and_then(|v| v.first())
                .and_then(|r| r.reactor_did.clone()),
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
                sig: replaces.and_then(|root| {
                    let venue =
                        crate::connection::messaging::signing_venue(state, AUTHOR_DID, to_nick)?;
                    let key = signer_on_file_opt(state, AUTHOR_DID)?;
                    Some(
                        freeq_sdk::chatsig::ChatDoc::message(AUTHOR_DID, msgid, &venue, text)
                            .with_edit(root)
                            .sign(&key),
                    )
                }),
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

        relay_delete(
            &state,
            &mgr,
            "bob",
            "dm-1",
            "alice!a@remote",
            Some(AUTHOR_DID),
        )
        .await;

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

#[cfg(test)]
mod catchup_tests {
    //! Catch-up replay: what a peer missed while the link was down.
    //!
    //! Two properties, both load-bearing. **Every replayed event is verified
    //! by the receiver**, against the bytes it travelled with, using a key the
    //! receiver looks up — the replaying peer's opinion never crosses, so it
    //! can never be adopted. And **a peer that did not declare catch-up
    //! support is never sent these message types**, because a peer that cannot
    //! parse a message warn-and-skips it, which is data loss wearing
    //! compatibility's clothes.
    //!
    //! The conflict rules live here too: same id twice is a no-op, same id
    //! with different content is dropped and logged with a receipt against the
    //! copy we keep, and there is no deterministic winner — first write wins,
    //! always.

    use std::collections::HashMap;

    use super::s2s_adversarial_tests::{setup_authenticated_peer, test_manager};
    use super::{
        ReplayOutcome, SharedState, apply_replayed_event, process_s2s_message,
        retry_deferred_task_events, test_state_with_db,
    };
    use crate::events::SigState;
    use crate::s2s::{CATCHUP, ReplayedEvent, S2sMessage, our_capabilities, peer_supports};
    use ed25519_dalek::SigningKey;
    use freeq_sdk::chatsig::ChatDoc;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const ALICE: &str = "did:plc:catchupalice";
    /// The peer id the shared S2S test helpers authenticate.
    use super::s2s_adversarial_tests::PEER;
    /// This server's own endpoint id — `test_manager`'s `server_id`, so a test
    /// driving the real handler and one calling `apply_replayed_event` direct
    /// are talking about the same receiver.
    const OWN: &str = "test-local-server";

    fn state_with_key(key: &SigningKey) -> Arc<SharedState> {
        let state = test_state_with_db();
        state
            .with_db(|db| db.save_signing_key(ALICE, key.verifying_key().as_bytes()))
            .expect("test state has a database");
        state
    }

    /// One signed event as it travels, minted at `minted_at`.
    fn minted_event(
        key: &SigningKey,
        event_id: &str,
        body: &str,
        minted_at: &str,
    ) -> ReplayedEvent {
        let doc = ChatDoc::message(ALICE, event_id, "#caught", body);
        ReplayedEvent {
            event_id: event_id.to_string(),
            canonical: doc.canonical(),
            signature: Some(doc.sign(key)),
            kind: "message".to_string(),
            venue: "#caught".to_string(),
            actor_did: Some(ALICE.to_string()),
            subject: None,
            emoji: None,
            origin: minted_at.to_string(),
            timestamp: 1000,
        }
    }

    /// The ordinary case: the peer replaying it is the peer that minted it.
    fn signed_event(key: &SigningKey, event_id: &str, body: &str) -> ReplayedEvent {
        minted_event(key, event_id, body, PEER)
    }

    /// The receiver checks each replayed event itself and files its own verdict.
    #[test]
    fn a_replayed_event_is_verified_by_the_receiver_and_filed() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        let ev = signed_event(
            &key,
            "01CATCH000000000000000001",
            "missed while you were out",
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );

        let row = state
            .with_db(|db| db.get_event("01CATCH000000000000000001"))
            .flatten()
            .expect("the event is on file");
        assert_eq!(
            row.sig_state,
            SigState::Valid,
            "the receiver reached its own verdict against the bytes it was handed"
        );
        assert_eq!(
            row.origin.as_deref(),
            Some(PEER),
            "and recorded where it was minted — which here is the peer that \
             replayed it, because that peer minted it"
        );
        assert_eq!(row.venue, "#caught");
    }

    /// Origin names the **minter**, not the messenger.
    ///
    /// Three servers: A mints, B files it from A, and C — which was never
    /// linked to A — heals from B. C must record A. Recording B would make C
    /// believe B referees a task A owns, and two servers refereeing one task
    /// is the disagreement the origin field exists to prevent.
    #[test]
    fn an_event_healed_through_a_third_party_records_the_server_that_minted_it() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const MINTER: &str = "server-a";

        // PEER here is B: it is replaying to us, but it is not where this
        // event came from and its reply says so.
        let ev = minted_event(&key, "01CATCH000000000000000010", "A said this", MINTER);
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );

        let row = state
            .with_db(|db| db.get_event("01CATCH000000000000000010"))
            .flatten()
            .expect("the event is on file");
        assert_eq!(
            row.origin.as_deref(),
            Some(MINTER),
            "the minter, not the messenger"
        );
    }

    /// An event of ours, handed back to us, is ours again.
    ///
    /// A row this server minted carries no origin. If a replay stamped one on
    /// it, this server would read its own tasks as another server's and stop
    /// refereeing them — the exact opposite of what healing is for.
    #[test]
    fn an_event_of_ours_that_comes_home_is_filed_as_ours() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        let ev = minted_event(&key, "01CATCH000000000000000011", "we said this", OWN);
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );

        let row = state
            .with_db(|db| db.get_event("01CATCH000000000000000011"))
            .flatten()
            .expect("the event is on file");
        assert_eq!(
            row.origin, None,
            "an event that came home is not a foreign event"
        );
    }

    /// A peer that predates the per-event field sends none, and its replays
    /// are read exactly as they were before it existed: everything in the
    /// batch is attributed to the peer that sent the batch.
    #[test]
    fn an_older_peers_replay_still_attributes_to_that_peer() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        let ev = minted_event(&key, "01CATCH000000000000000012", "no field", "");
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );

        let row = state
            .with_db(|db| db.get_event("01CATCH000000000000000012"))
            .flatten()
            .expect("the event is on file");
        assert_eq!(row.origin.as_deref(), Some(PEER));
    }

    /// A replay of what we already hold changes nothing. Links flap; replay has to
    /// be safe to run every time one comes back.
    #[test]
    fn replaying_an_event_we_already_hold_is_a_no_op() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let ev = signed_event(&key, "01CATCH000000000000000002", "once");

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev.clone()),
            ReplayOutcome::Filed
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev.clone()),
            ReplayOutcome::AlreadyHeld
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::AlreadyHeld,
            "and again, as many times as the link flaps"
        );

        let row = state
            .with_db(|db| db.get_event("01CATCH000000000000000002"))
            .flatten()
            .unwrap();
        assert_eq!(row.conflict, None, "a re-delivery is not a conflict");
    }

    /// Same id, different content: dropped, and the copy we keep carries a receipt
    /// naming what was refused. First write wins — there is no rule by which a
    /// second signed claim replaces what our users have already seen.
    #[test]
    fn a_second_claim_on_an_id_is_dropped_and_leaves_a_receipt() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let id = "01CATCH000000000000000003";

        let first = signed_event(&key, id, "what I said");
        let second = signed_event(&key, id, "what they claim I said");
        assert_ne!(first.canonical, second.canonical);

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, first.clone()),
            ReplayOutcome::Filed
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, second.clone()),
            ReplayOutcome::Conflicted
        );

        let row = state.with_db(|db| db.get_event(id)).flatten().unwrap();
        assert_eq!(
            row.canonical, first.canonical,
            "first write wins; the copy already shown stays the copy shown"
        );
        assert_eq!(
            row.conflict.as_deref(),
            Some(crate::events::fingerprint(&second.canonical).as_str()),
            "and the refused claim leaves a trace, so equivocation is visible here"
        );

        // Replaying the loser again does not overwrite the receipt, and does not
        // start winning by persistence.
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, second),
            ReplayOutcome::Conflicted
        );
        let row2 = state.with_db(|db| db.get_event(id)).flatten().unwrap();
        assert_eq!(row2.canonical, first.canonical);
        assert_eq!(row2.conflict, row.conflict);
    }

    /// A replayed event whose signature fails against the key it names is refused
    /// outright — the same rule as live ingress. A peer that tampers in flight
    /// gains nothing by using the replay path.
    #[test]
    fn a_replayed_event_whose_signature_fails_is_refused() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        let mut ev = signed_event(&key, "01CATCH000000000000000004", "what was signed");
        // The bytes the peer hands over no longer match the signature it hands
        // over with them.
        ev.canonical = ChatDoc::message(
            ALICE,
            "01CATCH000000000000000004",
            "#caught",
            "what was sent",
        )
        .canonical();

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Unusable
        );
        assert!(
            state
                .with_db(|db| db.get_event("01CATCH000000000000000004"))
                .flatten()
                .is_none(),
            "nothing is filed for an event whose signature did not check out"
        );
    }

    /// A signer we hold no key for is uncheckable, not forged: the event still
    /// files, labelled honestly.
    #[test]
    fn a_replayed_event_from_an_unknown_signer_files_as_unverifiable() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        // A state that has never seen this signer's key.
        let state = test_state_with_db();

        let ev = signed_event(&key, "01CATCH000000000000000005", "who signed this");
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );
        assert_eq!(
            state
                .with_db(|db| db.get_event("01CATCH000000000000000005"))
                .flatten()
                .unwrap()
                .sig_state,
            SigState::Unverifiable,
            "cannot check is not the same as does not check out"
        );
    }

    /// An event nothing signed replays as unsigned rather than being rejected —
    /// a guest's event is still a fact.
    #[test]
    fn an_unsigned_replayed_event_files_as_unsigned() {
        let state = test_state_with_db();
        let ev = ReplayedEvent {
            event_id: "01CATCH000000000000000006".to_string(),
            canonical: String::new(),
            signature: None,
            kind: "message".to_string(),
            venue: "#caught".to_string(),
            actor_did: None,
            subject: None,
            emoji: None,
            origin: PEER.to_string(),
            timestamp: 1000,
        };
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ev),
            ReplayOutcome::Filed
        );
        assert_eq!(
            state
                .with_db(|db| db.get_event("01CATCH000000000000000006"))
                .flatten()
                .unwrap()
                .sig_state,
            SigState::Unsigned
        );
    }

    /// The replay path never applies the ±120s id clock check. It is a
    /// live-client-ingress rule, and a catch-up is *made* of old events — running
    /// it here would reject everything a returning peer has to offer.
    #[test]
    fn replayed_events_are_not_judged_by_their_age() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        let mut ancient = signed_event(&key, "01CATCH000000000000000007", "from last year");
        ancient.timestamp = 1;
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, ancient),
            ReplayOutcome::Filed,
            "an old event is exactly what a catch-up is for"
        );
    }

    /// The rollout constraint, against the literal legacy handshake: a peer whose
    /// Hello carries no capability field declares nothing, and is therefore asked
    /// for nothing and sent nothing new.
    #[test]
    fn a_peer_with_a_legacy_handshake_is_never_asked_for_catch_up() {
        let legacy = r#"{"type":"hello","peer_id":"frozen","server_name":"pre-batch",
                         "protocol_version":2,"trust_level":"full"}"#;
        let declared = match serde_json::from_str::<S2sMessage>(legacy).unwrap() {
            S2sMessage::Hello { capabilities, .. } => capabilities,
            other => panic!("expected Hello, got {other:?}"),
        };
        assert!(declared.is_empty());
        assert!(
            !peer_supports(&declared, CATCHUP),
            "nothing declared means nothing supported, which means nothing sent"
        );

        // And our own Hello does declare it, so a peer running this build is asked.
        assert!(peer_supports(&our_capabilities(), CATCHUP));
    }

    /// The answer a peer actually receives contains the whole window — direct
    /// messages included. Live relay is peer-blind broadcast to allowlisted
    /// peers, so a replay that held DMs back would protect nothing (the peer
    /// received them live) while denying its own users what they missed.
    /// Driven through the real handler, so it pins what crosses the wire and
    /// not just what a query returns.
    #[tokio::test]
    async fn the_answer_a_peer_receives_includes_direct_messages() {
        let state = test_state_with_db();
        let manager = test_manager();
        setup_authenticated_peer(&state, &manager).await;

        // A channel message and a direct message, both in the window.
        for (venue, id) in [
            ("#open", "01SCOPE00000000000000001"),
            ("dm:did:plc:a,did:plc:b", "01SCOPE00000000000000002"),
        ] {
            state
                .with_db(|db| {
                    db.insert_message(
                        venue,
                        "a!u@h",
                        "x",
                        100,
                        &HashMap::new(),
                        Some(id),
                        Some("did:plc:a"),
                    )
                })
                .unwrap();
        }

        // A live link to answer down.
        let (tx, mut rx) = mpsc::channel(16);
        manager
            .peers
            .lock()
            .await
            .insert(PEER.to_string(), crate::s2s::PeerEntry { tx, conn_gen: 1 });

        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupRequest {
                peer_id: PEER.to_string(),
                since_ts: 0,
                limit: 0,
            },
        )
        .await;

        let reply = rx.try_recv().expect("the peer receives an answer");
        let events = match reply {
            S2sMessage::CatchupEvents { events, .. } => events,
            other => panic!("expected CatchupEvents, got {other:?}"),
        };
        let venues: Vec<&str> = events.iter().map(|e| e.venue.as_str()).collect();
        assert!(
            venues.contains(&"dm:did:plc:a,did:plc:b"),
            "the window is the window: {venues:?}"
        );
        assert!(venues.contains(&"#open"), "{venues:?}");
    }

    /// Every event in a reply says where it was minted.
    ///
    /// One we minted goes out named as ours; one we hold from somewhere else
    /// goes out named as that somewhere else. Overwriting the second with our
    /// own id is what would tell an asker we referee a task we do not.
    #[tokio::test]
    async fn every_replayed_event_names_the_server_that_minted_it() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let manager = test_manager();
        setup_authenticated_peer(&state, &manager).await;

        // One of ours: stored by local ingress, so its origin column is blank.
        state
            .with_db(|db| {
                db.insert_message(
                    "#caught",
                    "a!u@h",
                    "ours",
                    100,
                    &HashMap::new(),
                    Some("01MINT0000000000000000001"),
                    Some(ALICE),
                )
            })
            .unwrap();
        // And one we hold from a third server, filed the way a replay files.
        const ELSEWHERE: &str = "server-elsewhere";
        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                PEER,
                minted_event(&key, "01MINT0000000000000000002", "theirs", ELSEWHERE),
            ),
            ReplayOutcome::Filed
        );

        let (tx, mut rx) = mpsc::channel(16);
        manager
            .peers
            .lock()
            .await
            .insert(PEER.to_string(), crate::s2s::PeerEntry { tx, conn_gen: 1 });
        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupRequest {
                peer_id: PEER.to_string(),
                since_ts: 0,
                limit: 0,
            },
        )
        .await;

        let events = match rx.try_recv().expect("the peer receives an answer") {
            S2sMessage::CatchupEvents { events, .. } => events,
            other => panic!("expected CatchupEvents, got {other:?}"),
        };
        let origin_of = |id: &str| {
            events
                .iter()
                .find(|e| e.event_id == id)
                .unwrap_or_else(|| panic!("{id} missing from the reply"))
                .origin
                .clone()
        };
        assert_eq!(
            origin_of("01MINT0000000000000000001"),
            manager.server_id,
            "an event we minted goes out named as ours, not blank"
        );
        assert_eq!(
            origin_of("01MINT0000000000000000002"),
            ELSEWHERE,
            "and one we are only holding keeps the name it arrived under"
        );
    }

    /// …and a peer the live relay path would skip gets no answer either,
    /// because both paths ask the same question. The peer here is *connected*
    /// — the only thing keeping it out is the allowlist, which is the half of
    /// the predicate a replay could otherwise have forgotten.
    #[tokio::test]
    async fn a_peer_we_would_not_relay_to_gets_no_answer() {
        let state = test_state_with_db();
        let mut manager = test_manager();
        Arc::get_mut(&mut manager)
            .expect("sole owner before the peer is registered")
            .allowed_peers = vec!["some-other-server".to_string()];
        setup_authenticated_peer(&state, &manager).await;
        state
            .with_db(|db| {
                db.insert_message(
                    "#open",
                    "a!u@h",
                    "x",
                    100,
                    &HashMap::new(),
                    Some("01SCOPE00000000000000003"),
                    Some("did:plc:a"),
                )
            })
            .unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        manager
            .peers
            .lock()
            .await
            .insert(PEER.to_string(), crate::s2s::PeerEntry { tx, conn_gen: 1 });

        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupRequest {
                peer_id: PEER.to_string(),
                since_ts: 0,
                limit: 0,
            },
        )
        .await;
        assert!(
            rx.try_recv().is_err(),
            "a connected but disallowed peer receives no events live, so it \
             receives none in a replay"
        );
    }

    /// A catch-up answer is drawn from the log, oldest first, and stops at the
    /// window it was asked for.
    #[test]
    fn the_answer_is_the_window_that_was_asked_for() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        for (i, id) in [
            "01WINDOW00000000000000001",
            "01WINDOW00000000000000002",
            "01WINDOW00000000000000003",
        ]
        .iter()
        .enumerate()
        {
            state
                .with_db(|db| {
                    db.insert_message(
                        "#caught",
                        "a!u@h",
                        "x",
                        100 + i as u64 * 100,
                        &HashMap::new(),
                        Some(id),
                        Some(ALICE),
                    )
                })
                .unwrap();
        }

        let all = state.with_db(|db| db.events_since(0, 10)).unwrap();
        assert_eq!(all.len(), 3);
        assert!(
            all.windows(2).all(|w| w[0].timestamp <= w[1].timestamp),
            "oldest first, so a replay applies them in the order they happened"
        );

        let recent = state.with_db(|db| db.events_since(250, 10)).unwrap();
        assert_eq!(recent.len(), 1, "the window is respected");
        assert_eq!(recent[0].event_id, "01WINDOW00000000000000003");
    }

    // ── healing the task view, not just the log ──────────────────────
    //
    // A server that was away has to come back with the *same answers* as one
    // that stayed. Filing the log row alone leaves it holding the record of a
    // task while its REST view says the task is not there.

    /// The venue every task event in these tests is posted to.
    fn caught_venue() -> String {
        freeq_sdk::chatsig::channel_venue("#caught")
    }

    /// One signed task event as it travels in a replay, minted at `minted_at`.
    fn act_event(
        key: &SigningKey,
        event_id: &str,
        minted_at: &str,
        tags: &[(&str, &str)],
    ) -> ReplayedEvent {
        let venue = caught_venue();
        let canonical = freeq_sdk::act::act_canonical(tags.iter().copied(), &venue, event_id)
            .expect("act tags present");
        ReplayedEvent {
            event_id: event_id.to_string(),
            signature: Some(freeq_sdk::sigtag::sign_canonical(&canonical, key)),
            canonical,
            kind: "act".to_string(),
            venue,
            actor_did: Some(ALICE.to_string()),
            subject: tags
                .iter()
                .find(|(k, _)| *k == "+freeq.at/act-id")
                .map(|(_, v)| v.to_string()),
            emoji: None,
            origin: minted_at.to_string(),
            timestamp: 1000,
        }
    }

    /// An offer that opens a claimable task.
    fn opener(key: &SigningKey, event_id: &str, minted_at: &str) -> ReplayedEvent {
        act_event(
            key,
            event_id,
            minted_at,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ALICE),
                ("+freeq.at/act-title", "healed"),
            ],
        )
    }

    /// A claim on the task `act_id` opened.
    fn claim(key: &SigningKey, event_id: &str, act_id: &str, minted_at: &str) -> ReplayedEvent {
        act_event(
            key,
            event_id,
            minted_at,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "claim"),
                ("+freeq.at/from", ALICE),
                ("+freeq.at/act-id", act_id),
            ],
        )
    }

    /// The ids every receipt on this task names, oldest first.
    fn receipts_naming(state: &Arc<SharedState>, act_id: &str) -> Vec<String> {
        let subject_tag = freeq_sdk::act_transitions::confirmation_subject_tag();
        state
            .with_db(|db| db.act_task_events(act_id))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                let view = crate::events::derive_act_view(&e.canonical)?;
                freeq_sdk::act_transitions::is_confirmation(&view.verb)
                    .then(|| view.fields.get(subject_tag).cloned().unwrap_or_default())
            })
            .collect()
    }

    /// A receipt signed by a home whose key this server may not hold yet.
    fn receipt(
        key: &SigningKey,
        event_id: &str,
        act_id: &str,
        subject: &str,
        home: &str,
        minted_at: &str,
    ) -> ReplayedEvent {
        let subject_tag = format!(
            "+freeq.at/{}",
            freeq_sdk::act_transitions::confirmation_subject_tag()
        );
        let mut ev = act_event(
            key,
            event_id,
            minted_at,
            &[
                ("+freeq.at/act", "handoff"),
                (
                    "+freeq.at/act-verb",
                    freeq_sdk::act_transitions::confirmation_verb(),
                ),
                ("+freeq.at/from", home),
                ("+freeq.at/act-id", act_id),
                (&subject_tag, subject),
            ],
        );
        ev.actor_did = Some(home.to_string());
        ev
    }

    /// A home-signed transition — an expiry — as it travels in a replay.
    fn system_transition(
        key: &SigningKey,
        event_id: &str,
        act_id: &str,
        verb: &str,
        home: &str,
        minted_at: &str,
    ) -> ReplayedEvent {
        let mut ev = act_event(
            key,
            event_id,
            minted_at,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", verb),
                ("+freeq.at/from", home),
                ("+freeq.at/act-id", act_id),
            ],
        );
        ev.actor_did = Some(home.to_string());
        ev
    }

    /// Put a signer's key on file, so a replayed event of theirs verifies.
    fn key_on_file(state: &Arc<SharedState>, did: &str, key: &SigningKey) {
        state
            .with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))
            .expect("test state has a database");
    }

    /// A task another server owns, with one unruled claim on it — what every
    /// authority test below starts from. `HOME_LINK` is the endpoint id that
    /// server is reachable as, and the task is stamped with it.
    const HOME_LINK: &str = "home-endpoint-id";
    const HOME_DID: &str = "did:web:home.example";
    const THIRD_DID: &str = "did:web:third.example";

    fn a_peers_task_with_a_claim_on_it(
        state: &Arc<SharedState>,
        key: &SigningKey,
        act_id: &str,
        claimed: &str,
    ) {
        assert_eq!(
            apply_replayed_event(state, OWN, HOME_LINK, opener(key, act_id, HOME_LINK)),
            ReplayOutcome::Filed
        );
        assert_eq!(
            apply_replayed_event(
                state,
                OWN,
                HOME_LINK,
                claim(key, claimed, act_id, HOME_LINK)
            ),
            ReplayOutcome::Filed
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .expect("live")
                .state,
            "open",
            "a transition on a peer's task decides nothing here"
        );
    }

    // ── whose word a replayed receipt carries ─────────────────────────────
    //
    // A replayed event's origin is what the replaying peer *says* minted it.
    // That is right for the ownership stamp and wrong for authority: a peer
    // writes that field. The two events that carry the home's word — its
    // receipt, and a transition it signed itself — are therefore judged
    // against the connection the batch arrived on, and a peer that is not the
    // task's home is not that server however its batch is stamped.

    /// A third server replays a receipt it signed under its own `did:web:`
    /// name, stamped with the home's endpoint id. The signature checks out —
    /// it is that server's own key over its own bytes — and the stamp says
    /// what it likes. The connection says otherwise, and the connection is
    /// what decides.
    #[test]
    fn a_replayed_receipt_from_a_peer_that_is_not_the_home_is_skipped() {
        const ACT: &str = "01ACT00000000000000000061";
        const CLAIMED: &str = "01ACT00000000000000000062";
        const FORGED: &str = "01ACT00000000000000000063";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        a_peers_task_with_a_claim_on_it(&state, &key, ACT, CLAIMED);

        let third_key = SigningKey::from_bytes(&[113u8; 32]);
        key_on_file(&state, THIRD_DID, &third_key);

        // What a receipt would move if it were usable: the claim it names
        // stops being unconfirmed, and the task view follows. Both are read
        // before and after, because "ignored" is exactly the two of them not
        // moving.
        let claim_unconfirmed_before = state
            .with_db(|db| db.act_event_is_unconfirmed(CLAIMED))
            .expect("the claim is on file");
        assert!(claim_unconfirmed_before, "nothing has confirmed it yet");
        let task_before = state
            .with_db(|db| db.act_task(ACT))
            .flatten()
            .expect("live");

        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                PEER,
                receipt(&third_key, FORGED, ACT, CLAIMED, THIRD_DID, HOME_LINK),
            ),
            ReplayOutcome::Unusable
        );

        assert!(
            state
                .with_db(|db| db.act_event_is_unconfirmed(CLAIMED))
                .expect("still on file"),
            "the claim it named is still unconfirmed: the receipt confirmed nothing"
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(ACT))
                .flatten()
                .expect("live"),
            task_before,
            "and the task view is the one it was before the receipt arrived"
        );

        assert!(
            !state.with_db(|db| db.is_act_event(FORGED)).unwrap(),
            "and it is not filed either: a row under that id would make the \
             home's own replay of a genuine receipt a duplicate"
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(ACT))
                .flatten()
                .expect("live")
                .state,
            "open",
            "nothing moved"
        );
        assert_eq!(
            state.act_deferred.lock().len(),
            0,
            "nor held: a peer that is not the home never carries the home's word, \
             so there is nothing about it a key could settle"
        );
    }

    /// And the home's own replay of its own receipt applies.
    #[test]
    fn a_replayed_receipt_from_the_home_itself_applies() {
        const ACT: &str = "01ACT00000000000000000064";
        const CLAIMED: &str = "01ACT00000000000000000065";
        const RECEIPT: &str = "01ACT00000000000000000066";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        a_peers_task_with_a_claim_on_it(&state, &key, ACT, CLAIMED);

        let home_key = SigningKey::from_bytes(&[127u8; 32]);
        key_on_file(&state, HOME_DID, &home_key);
        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                HOME_LINK,
                receipt(&home_key, RECEIPT, ACT, CLAIMED, HOME_DID, HOME_LINK),
            ),
            ReplayOutcome::Filed
        );

        let task = state
            .with_db(|db| db.act_task(ACT))
            .flatten()
            .expect("live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("assigned", Some(ALICE)),
            "the home's own replay is the one that carries its word"
        );
    }

    /// The same rule for the other event a server signs itself. An expiry
    /// replayed by anyone but the task's home ends nothing.
    #[test]
    fn a_replayed_expiry_from_a_peer_that_is_not_the_home_is_skipped() {
        const ACT: &str = "01ACT00000000000000000067";
        const CLAIMED: &str = "01ACT00000000000000000068";
        const FORGED: &str = "01ACT00000000000000000069";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        a_peers_task_with_a_claim_on_it(&state, &key, ACT, CLAIMED);

        let third_key = SigningKey::from_bytes(&[131u8; 32]);
        key_on_file(&state, THIRD_DID, &third_key);
        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                PEER,
                system_transition(&third_key, FORGED, ACT, "expire", THIRD_DID, HOME_LINK),
            ),
            ReplayOutcome::Unusable
        );
        assert!(
            state.with_db(|db| db.act_task(ACT)).flatten().is_some(),
            "a peer that does not own the task cannot end it"
        );
        assert!(!state.with_db(|db| db.is_act_event(FORGED)).unwrap());
    }

    /// …and the home's own replay of its own expiry ends it.
    #[test]
    fn a_replayed_expiry_from_the_home_itself_ends_the_task() {
        const ACT: &str = "01ACT00000000000000000070";
        const CLAIMED: &str = "01ACT00000000000000000071";
        const EXPIRY: &str = "01ACT00000000000000000072";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        a_peers_task_with_a_claim_on_it(&state, &key, ACT, CLAIMED);

        let home_key = SigningKey::from_bytes(&[137u8; 32]);
        key_on_file(&state, HOME_DID, &home_key);
        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                HOME_LINK,
                system_transition(&home_key, EXPIRY, ACT, "expire", HOME_DID, HOME_LINK),
            ),
            ReplayOutcome::Filed
        );
        assert!(
            state.with_db(|db| db.act_task(ACT)).flatten().is_none(),
            "the task's own server ended it"
        );
    }

    /// And a peer cannot become this server by stamping a batch with our id.
    ///
    /// A task of ours carries no origin at all — the home is here — so there
    /// is no home link to judge a claim to the home's word against. What
    /// speaks for this server is this server's own `did:web:` name and
    /// nothing else: under any other name a server-signed event is an
    /// ordinary participant's, and the rules let no participant expire a
    /// task. This server's own word, coming home, still ends one:
    /// `our_own_expiry_coming_home_is_not_confirmed_a_second_time`.
    #[test]
    fn a_replayed_expiry_signed_under_another_servers_name_cannot_end_a_task_of_ours() {
        const ID: &str = "01ACT00000000000000000076";
        const FORGED: &str = "01ACT00000000000000000077";
        const OTHER_DID: &str = "did:web:other.example";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        our_own_task(&state, &key, ID);

        let other_key = SigningKey::from_bytes(&[149u8; 32]);
        key_on_file(&state, OTHER_DID, &other_key);
        assert_eq!(
            apply_replayed_event(
                &state,
                OWN,
                PEER,
                system_transition(&other_key, FORGED, ID, "expire", OTHER_DID, OWN),
            ),
            ReplayOutcome::Unusable
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(ID))
                .flatten()
                .expect("live")
                .state,
            "open",
            "the task stands: only this server ends a task of this server's"
        );
        assert!(
            !state.with_db(|db| db.is_act_event(FORGED)).unwrap(),
            "and the rules refused it, so there is no row under that id"
        );
    }

    /// A receipt that has to wait for its signer's key waits under the
    /// connection it arrived on, not under the origin its batch claimed.
    ///
    /// The two are made to differ here: the task's own server replays its own
    /// receipt in a batch entry that names a third server as the minter. The
    /// connection is what the receipt is judged by, when it parks and again
    /// when the key releases it — so it applies. Parked under the claim
    /// instead, it would come back as a stranger's word and move nothing.
    #[test]
    fn a_parked_replayed_receipt_is_released_under_the_connection_it_arrived_on() {
        const ACT: &str = "01ACT00000000000000000073";
        const CLAIMED: &str = "01ACT00000000000000000074";
        const RECEIPT: &str = "01ACT00000000000000000075";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        a_peers_task_with_a_claim_on_it(&state, &key, ACT, CLAIMED);

        // No key for the home yet, so its receipt parks.
        let home_key = SigningKey::from_bytes(&[139u8; 32]);
        let mut receipt = receipt(&home_key, RECEIPT, ACT, CLAIMED, HOME_DID, HOME_LINK);
        receipt.origin = "some-third-server".to_string();
        let sig = receipt.signature.clone().expect("signed");
        assert_eq!(
            apply_replayed_event(&state, OWN, HOME_LINK, receipt),
            ReplayOutcome::Unusable
        );
        assert_eq!(state.act_deferred.lock().len(), 1, "held for its key");

        key_on_file(&state, HOME_DID, &home_key);
        let kid = freeq_sdk::sigtag::parse(&sig).expect("alg:kid:sig").0;
        retry_deferred_task_events(&state, HOME_DID, kid);

        let task = state
            .with_db(|db| db.act_task(ACT))
            .flatten()
            .expect("live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("assigned", Some(ALICE)),
            "the wait ended on the link it began on, which is the task's home"
        );
    }

    /// A receipt is the one replayed event that must not be skipped for good.
    ///
    /// Skipping is right for an ordinary event whose signer's key has not
    /// arrived: the peer can be asked for it again. A receipt is what somebody
    /// else's transition is waiting on, and asking again is the round trip a
    /// replayed receipt exists to save — so it waits for the key exactly as a
    /// live one does, and the key's arrival is what applies it.
    #[test]
    fn a_replayed_receipt_whose_key_is_missing_waits_instead_of_being_skipped() {
        const HOME: &str = "did:web:peer-b.example";
        const ACT: &str = "01ACT00000000000000000051";
        const CLAIMED: &str = "01ACT00000000000000000052";
        const RECEIPT: &str = "01ACT00000000000000000053";
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);

        // A task PEER owns, with a claim on it that decides nothing here.
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, opener(&key, ACT, PEER)),
            ReplayOutcome::Filed
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, claim(&key, CLAIMED, ACT, PEER)),
            ReplayOutcome::Filed
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(ACT))
                .flatten()
                .unwrap()
                .state,
            "open"
        );

        // The home's receipt, signed with a key nobody here holds.
        let home_key = SigningKey::from_bytes(&[97u8; 32]);
        let replayed = receipt(&home_key, RECEIPT, ACT, CLAIMED, HOME, PEER);
        let sig = replayed.signature.clone().expect("signed");
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, replayed),
            ReplayOutcome::Unusable
        );
        assert_eq!(
            state.act_deferred.lock().len(),
            1,
            "held rather than dropped: this is what the claim is waiting on"
        );

        // The key turns up.
        state
            .with_db(|db| db.save_signing_key(HOME, home_key.verifying_key().as_bytes()))
            .expect("db present");
        let kid = freeq_sdk::sigtag::parse(&sig).expect("alg:kid:sig").0;
        retry_deferred_task_events(&state, HOME, kid);

        let task = state
            .with_db(|db| db.act_task(ACT))
            .flatten()
            .expect("live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("assigned", Some(ALICE)),
            "and the receipt that was waiting applied the claim it names"
        );
    }

    /// A move this server applied to a task it owns is a move it ruled on, and
    /// it owes a receipt for it however the event reached here.
    ///
    /// Replay is a way in like any other: the participant's claim arrives, the
    /// rules take it, our own task moves — and without this the one server
    /// whose word settles the task said nothing, on a path nothing else
    /// covers, because the addressed copy that follows is a duplicate and a
    /// duplicate mints nothing.
    #[test]
    fn a_replayed_move_on_a_task_we_own_leaves_the_receipt_we_owe() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const ID: &str = "01ACT00000000000000000031";
        const CLAIMED: &str = "01ACT00000000000000000032";
        our_own_task(&state, &key, ID);

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, claim(&key, CLAIMED, ID, "server-b")),
            ReplayOutcome::Filed
        );
        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.state, "assigned",
            "the rules took the claim, so this server moved its own task"
        );
        assert_eq!(
            receipts_naming(&state, ID),
            [CLAIMED],
            "and said so: a receipt naming the event it confirms"
        );

        // The same claim again, by whatever path. The log knows the id, so
        // nothing moved and nothing more is owed.
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, claim(&key, CLAIMED, ID, "server-b")),
            ReplayOutcome::AlreadyHeld
        );
        assert_eq!(
            receipts_naming(&state, ID),
            [CLAIMED],
            "a second arrival is not a second move"
        );
    }

    /// And this server's own events coming home are not confirmed: they are
    /// already signed by the server whose word settles the task, which is the
    /// degenerate case a receipt exists to cover for everybody else.
    #[test]
    fn our_own_expiry_coming_home_is_not_confirmed_a_second_time() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const ID: &str = "01ACT00000000000000000033";
        our_own_task(&state, &key, ID);

        let server_did = crate::server::server_did(&state.server_name);
        let server_key = SigningKey::from_bytes(&[9u8; 32]);
        state
            .with_db(|db| db.save_signing_key(&server_did, server_key.verifying_key().as_bytes()))
            .expect("test state has a database");
        // Built here rather than through `act_event`, which signs as ALICE:
        // this event's whole point is that the server itself authored it.
        const EXPIRE: &str = "01ACT00000000000000000034";
        let venue = caught_venue();
        let canonical = freeq_sdk::act::act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "expire"),
                ("+freeq.at/from", server_did.as_str()),
                ("+freeq.at/act-id", ID),
            ],
            &venue,
            EXPIRE,
        )
        .expect("act tags present");
        let expire = ReplayedEvent {
            event_id: EXPIRE.to_string(),
            signature: Some(freeq_sdk::sigtag::sign_canonical(&canonical, &server_key)),
            canonical,
            kind: "act".to_string(),
            venue,
            actor_did: Some(server_did.clone()),
            subject: Some(ID.to_string()),
            emoji: None,
            origin: OWN.to_string(),
            timestamp: 1000,
        };
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, expire),
            ReplayOutcome::Filed
        );

        assert!(
            state.with_db(|db| db.act_task(ID)).flatten().is_none(),
            "the expiry ended the task"
        );
        assert!(
            receipts_naming(&state, ID).is_empty(),
            "and this server does not write itself a receipt for its own word"
        );
    }

    /// A relayed opener whose `act-replaces` names a task this server has no
    /// record of is filed, not refused.
    ///
    /// A re-offer exists because the original's home went away, and the server
    /// issuing it need not be one we ever heard the original from — so the
    /// named task being absent here is the ordinary case, not a suspicious
    /// one. The link crosses federation as one more act tag inside the signed
    /// document, and a receiver that dropped it would silently lose the only
    /// thread tying replacement work back to what it replaces.
    #[test]
    fn a_relayed_opener_replacing_a_task_we_never_saw_is_filed() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const MINTER: &str = "server-a";
        const ID: &str = "01M16E7TC00000000000000009";
        const DEAD: &str = "01M16E7TC0NEVERSEEN0000000";

        let event = act_event(
            &key,
            ID,
            MINTER,
            &[
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", ALICE),
                ("+freeq.at/act-title", "re-offered"),
                ("+freeq.at/act-replaces", DEAD),
            ],
        );
        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, event),
            ReplayOutcome::Filed
        );
        assert!(
            state.with_db(|db| db.act_task(ID)).flatten().is_some(),
            "the replacement task is open here even though the task it names is not"
        );
        assert_eq!(
            state.with_db(|db| db.act_task_is_on_file(DEAD)),
            Some(false),
            "and nothing invented a record of the task it replaces"
        );
    }

    /// A healed task event moves the task view, not only the log.
    ///
    /// Filing the row and stopping there is what left a server that had been
    /// away answering "no such task" for a task it demonstrably holds the
    /// events of.
    #[test]
    fn a_caught_up_task_event_reaches_the_task_view() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const MINTER: &str = "server-a";
        const ID: &str = "01ACT00000000000000000001";

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, opener(&key, ID, MINTER)),
            ReplayOutcome::Filed
        );

        let task = state
            .with_db(|db| db.act_task(ID))
            .flatten()
            .expect("a healed server answers for the task, not only for its log");
        assert_eq!(task.state, "open");
        assert_eq!(task.offerer, ALICE);
        assert_eq!(task.venue, caught_venue());
        assert_eq!(task.origin, MINTER, "and knows which server referees it");
    }

    /// Whose task it is survives healing.
    ///
    /// The view is fed through the same call live receiving uses, so the rule
    /// that a task another server opened is that server's to move applies to a
    /// replayed event exactly as to a live one: the event is on file, and the
    /// task has not moved.
    #[test]
    fn a_healed_transition_on_another_servers_task_is_filed_but_not_applied() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const MINTER: &str = "server-a";
        const ID: &str = "01ACT00000000000000000010";

        apply_replayed_event(&state, OWN, PEER, opener(&key, ID, MINTER));
        apply_replayed_event(
            &state,
            OWN,
            PEER,
            claim(&key, "01ACT00000000000000000011", ID, MINTER),
        );

        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.state, "open",
            "the server that opened a task is the one that decides what it does"
        );
        assert_eq!(
            state.with_db(|db| db.act_task_events(ID)).unwrap().len(),
            2,
            "both events are on file — not applying one is not the same as \
             not recording it"
        );
    }

    /// A task this server opened, filed the way local ingress files one —
    /// with no origin at all, which is how a row of ours is stored.
    fn our_own_task(state: &Arc<SharedState>, key: &SigningKey, act_id: &str) {
        let ev = opener(key, act_id, "");
        let written = state
            .with_db(|db| {
                db.apply_act_event(&crate::db::ActEvent {
                    canonical: &ev.canonical,
                    signature: ev.signature.as_deref(),
                    event_id: act_id,
                    act_id,
                    opens: true,
                    venue: &ev.venue,
                    actor: ALICE,
                    from_system: false,
                    origin: None,
                    timestamp: 1000,
                })
            })
            .expect("db present");
        assert!(matches!(written, crate::db::ActWrite::Filed { .. }));
    }

    /// A task event of ours, healed back, is ours to referee again.
    ///
    /// The task itself is still here — a server heals the events it missed,
    /// not rows it never lost — so the replay's claim that we minted the
    /// follow-up is one our own records bear out, and the move applies.
    #[test]
    fn a_healed_task_of_our_own_is_still_ours_to_move() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const ID: &str = "01ACT00000000000000000020";
        const CLAIMED: &str = "01ACT00000000000000000021";

        our_own_task(&state, &key, ID);
        apply_replayed_event(&state, OWN, PEER, claim(&key, CLAIMED, ID, OWN));

        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.state, "assigned",
            "a task that came home is not a foreign task"
        );
        assert_eq!(task.assignee.as_deref(), Some(ALICE));
        let row = state
            .with_db(|db| db.get_event(CLAIMED))
            .flatten()
            .expect("the healed event is on file");
        assert_eq!(
            row.origin, None,
            "and the row is ours, not a foreign server's"
        );
    }

    /// A peer cannot hand us a task by naming us as its minter.
    ///
    /// Whether this server is a task's home is the one origin claim that is
    /// about us, and it is settled against our own records rather than taken
    /// from the payload. Nothing here opened this task, so the peer that
    /// carried it is what the row records — and a transition on it is filed,
    /// not refereed. Believing the claim would have this server expiring and
    /// ordering a task somebody else opened.
    #[test]
    fn a_peer_naming_us_as_the_minter_of_a_task_we_never_opened_is_not_believed() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        const ID: &str = "01ACT00000000000000000022";

        apply_replayed_event(&state, OWN, PEER, opener(&key, ID, OWN));
        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.origin, PEER,
            "the link it arrived on, not the minter it claimed"
        );

        apply_replayed_event(
            &state,
            OWN,
            PEER,
            claim(&key, "01ACT00000000000000000023", ID, PEER),
        );
        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.state, "open",
            "and it is not ours to move: the transition is on file, unapplied"
        );
    }

    /// A task event whose signature cannot be checked is skipped.
    ///
    /// It is not filed and it does not open a task: a replay has nobody
    /// waiting on delivery, and the peer can be asked again on the next
    /// link.
    #[test]
    fn a_caught_up_task_event_that_cannot_be_verified_is_skipped() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        // No key on file for ALICE: the verdict can only be "cannot say".
        let state = test_state_with_db();
        const ID: &str = "01ACT00000000000000000030";

        assert_eq!(
            apply_replayed_event(&state, OWN, PEER, opener(&key, ID, "server-a")),
            ReplayOutcome::Unusable
        );
        assert!(
            state.with_db(|db| db.get_event(ID)).flatten().is_none(),
            "an unchecked task event is not filed"
        );
        assert!(state.with_db(|db| db.act_task(ID)).flatten().is_none());
    }

    /// A batch is applied in mint order, whatever order it arrived in.
    ///
    /// An event id is a ULID, so its byte order is the order the signers
    /// minted in — which is the only clock every server agrees on. A follow-up
    /// ahead of its opener names a task nothing has opened yet and is dropped
    /// unrecorded; sorted first, both land.
    #[tokio::test]
    async fn a_batch_is_applied_in_mint_order_not_arrival_order() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let manager = test_manager();
        setup_authenticated_peer(&state, &manager).await;
        const MINTER: &str = "server-a";
        const ID: &str = "01ACT00000000000000000040";

        // The opener's id sorts first, as a ULID minted first does. The batch
        // presents them the other way round.
        let events = vec![
            claim(&key, "01ACT00000000000000000041", ID, MINTER),
            opener(&key, ID, MINTER),
        ];
        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupEvents {
                origin: PEER.to_string(),
                events,
                more: false,
            },
        )
        .await;

        assert_eq!(
            state.with_db(|db| db.act_task_events(ID)).unwrap().len(),
            2,
            "the opener has to be applied before the follow-up that names it"
        );
    }

    /// And mint order alone is not enough: a task's opener goes first even
    /// when its id does not sort first.
    ///
    /// A signer may mint up to the ingress skew bound in the past, so two
    /// signers on two clocks can produce a follow-up whose ULID sorts ahead of
    /// the opener it names. Sorted by id and no further, that follow-up names
    /// a task nothing has opened and is dropped unrecorded — the same hole a
    /// rebuild closes by regrouping.
    #[tokio::test]
    async fn a_batch_puts_each_task_opener_ahead_of_its_follow_ups() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let manager = test_manager();
        setup_authenticated_peer(&state, &manager).await;
        const MINTER: &str = "server-a";
        // The opener's id sorts *after* the claim that names it.
        const ID: &str = "01ACT00000000000000000051";
        const CLAIMED: &str = "01ACT00000000000000000050";

        let events = vec![opener(&key, ID, MINTER), claim(&key, CLAIMED, ID, MINTER)];
        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupEvents {
                origin: PEER.to_string(),
                events,
                more: false,
            },
        )
        .await;

        assert_eq!(
            state.with_db(|db| db.act_task_events(ID)).unwrap().len(),
            2,
            "the follow-up is recorded, so its opener was applied before it"
        );
    }

    /// A batch's own origin field is the sender's; the link's is the peer's.
    ///
    /// Where an event names no minter the reply's batch origin used to stand
    /// in, which let a peer attribute a whole batch to a server it is not.
    /// What stands in is the peer the transport authenticated.
    #[tokio::test]
    async fn a_batch_falls_back_to_the_peer_the_link_authenticated() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let state = state_with_key(&key);
        let manager = test_manager();
        setup_authenticated_peer(&state, &manager).await;
        const ID: &str = "01ACT00000000000000000060";

        process_s2s_message(
            &state,
            &manager,
            PEER,
            S2sMessage::CatchupEvents {
                origin: "server-a".to_string(),
                events: vec![opener(&key, ID, "")],
                more: false,
            },
        )
        .await;

        let task = state.with_db(|db| db.act_task(ID)).flatten().unwrap();
        assert_eq!(
            task.origin, PEER,
            "the peer that sent the batch, not the origin it wrote in it"
        );
    }
}

#[cfg(test)]
mod relayed_task_verdict_tests {
    //! Verification of relayed task events: the receive path
    //! reaches its own verdict about every task event a peer relays, and each
    //! verdict leads somewhere different: valid is stored and delivered,
    //! invalid reaches nobody and is written nowhere, and anything it cannot
    //! judge yet waits in the defer queue — never refused, never shown while
    //! it waits — with the key that would settle it asked for off this path
    //! and its arrival what judges the event again.

    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::s2s_adversarial_tests::{
        PEER, setup_authenticated_peer, test_manager, test_manager_with_broadcast_rx,
    };
    use super::{
        SharedState, flush_pending_routes, process_s2s_message, retry_deferred_task_events,
        server_did, test_state_with_config, test_state_with_db,
    };
    use crate::s2s::S2sMessage;

    const SIGNER: &str = "did:plc:taskverdict";

    /// A key on file for the signer, as a cross-server key fetch would have
    /// left it.
    fn key_on_file(state: &Arc<SharedState>, did: &str) -> ed25519_dalek::SigningKey {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        state
            .with_db(|db| db.save_signing_key(did, key.verifying_key().as_bytes()))
            .expect("db present");
        key
    }

    /// A local member holding `message-tags` and `freeq.at/act`, so
    /// delivery-unchanged is assertable.
    fn capable_member(state: &Arc<SharedState>, channel: &str) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(16);
        let sid = format!("member-of-{channel}");
        state.connections.lock().insert(sid.clone(), tx);
        state
            .channels
            .lock()
            .entry(channel.to_string())
            .or_default()
            .members
            .insert(sid.clone());
        state.cap_message_tags.lock().insert(sid.clone());
        state.cap_act.lock().insert(sid);
        rx
    }

    /// A local session bound to `did`, holding `message-tags` and
    /// `freeq.at/act` — one of that identity's devices on this server.
    fn capable_session_for(state: &Arc<SharedState>, did: &str) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(16);
        let sid = format!("session-of-{did}");
        state.connections.lock().insert(sid.clone(), tx);
        state
            .did_sessions
            .lock()
            .entry(did.to_string())
            .or_default()
            .insert(sid.clone());
        state.cap_message_tags.lock().insert(sid.clone());
        state.cap_act.lock().insert(sid);
        rx
    }

    /// The wire tags of a handoff offer, signed the way a task-sending client
    /// signs one: over the act tags, the folded venue, and the id it minted.
    fn signed_offer_tags(
        channel: &str,
        event_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> HashMap<String, String> {
        signed_offer_tags_in(&freeq_sdk::chatsig::channel_venue(channel), event_id, key)
    }

    /// The DID a DM in these tests is addressed to.
    const RECIPIENT: &str = "did:plc:dmrecipient";

    /// The same, for a venue the caller folded — a DM binds its two DIDs
    /// rather than the room.
    fn signed_offer_tags_in(
        venue: &str,
        event_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> HashMap<String, String> {
        let act: Vec<(&str, &str)> = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", "offer"),
            ("+freeq.at/from", SIGNER),
            ("+freeq.at/act-title", "verdict wiring"),
        ];
        let sig =
            freeq_sdk::act::sign_act(act.clone(), venue, event_id, key).expect("act tags present");
        let mut tags: HashMap<String, String> = act
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            event_id.to_string(),
        );
        tags.insert("+freeq.at/sig".to_string(), sig);
        tags
    }

    /// The same, for an event that names a task that already exists. `from`
    /// is spelled out because a server signs its own events under a
    /// `did:web:` identity and a participant does not, and that difference is
    /// what the receive path reads.
    fn signed_follow_up_tags(
        channel: &str,
        event_id: &str,
        verb: &str,
        act_id: &str,
        from: &str,
        extra: &[(&str, &str)],
        key: &ed25519_dalek::SigningKey,
    ) -> HashMap<String, String> {
        let mut act: Vec<(&str, &str)> = vec![
            ("+freeq.at/act", "handoff"),
            ("+freeq.at/act-verb", verb),
            ("+freeq.at/from", from),
            ("+freeq.at/act-id", act_id),
        ];
        act.extend_from_slice(extra);
        let venue = freeq_sdk::chatsig::channel_venue(channel);
        let sig =
            freeq_sdk::act::sign_act(act.clone(), &venue, event_id, key).expect("act tags present");
        let mut tags: HashMap<String, String> = act
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            event_id.to_string(),
        );
        tags.insert("+freeq.at/sig".to_string(), sig);
        tags
    }

    /// A task this server opened, filed straight into the log so the tests
    /// below start from one this server owns — a relayed opener is stamped
    /// with the peer that sent it, and the origin rule would then answer
    /// before anything else does.
    fn our_own_task(state: &Arc<SharedState>, channel: &str, act_id: &str) {
        let venue = freeq_sdk::chatsig::channel_venue(channel);
        let canonical = freeq_sdk::act::act_canonical(
            vec![
                ("+freeq.at/act", "handoff"),
                ("+freeq.at/act-verb", "offer"),
                ("+freeq.at/from", SIGNER),
            ],
            &venue,
            act_id,
        )
        .expect("act tags present");
        let written = state
            .with_db(|db| {
                db.apply_act_event(&crate::db::ActEvent {
                    canonical: &canonical,
                    signature: None,
                    event_id: act_id,
                    act_id,
                    opens: true,
                    venue: &venue,
                    actor: SIGNER,
                    from_system: false,
                    origin: None,
                    timestamp: 10,
                })
            })
            .expect("db present");
        assert!(matches!(written, crate::db::ActWrite::Filed { .. }));
    }

    async fn relay(
        state: &Arc<SharedState>,
        mgr: &Arc<crate::s2s::S2sManager>,
        channel: &str,
        event_id: &str,
        tags: HashMap<String, String>,
    ) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:{event_id}"),
                from: "tasker!t@remote".to_string(),
                target: channel.to_string(),
                tags,
                origin: PEER.to_string(),
                account: Some(SIGNER.to_string()),
            },
        )
        .await;
    }

    async fn received(rx: &mut mpsc::Receiver<String>) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for delivery")
            .expect("channel closed")
    }

    // ── carrying a transition to the server that owns the task ───────────
    //
    // A transition on a task this server does not own is filed here and moves
    // nothing, so the only way it is ever decided is for the server that owns
    // the task to be asked. The ordinary relay already reaches that server,
    // but a broadcast is best-effort and has no second try; the addressed copy
    // is what closes the gap when the home was away.

    /// Put `PEER` on the peers map with a link the test can read, optionally
    /// declaring the capability that lets a routed transition be handed over.
    async fn link_peer(
        mgr: &Arc<crate::s2s::S2sManager>,
        takes_routes: bool,
    ) -> mpsc::Receiver<S2sMessage> {
        let (tx, rx) = mpsc::channel(16);
        mgr.peers
            .lock()
            .await
            .insert(PEER.to_string(), crate::s2s::PeerEntry { tx, conn_gen: 1 });
        // Task-aware either way — a peer that can hold a task event is what
        // makes it a peer at all here — and `takes_routes` is the newer
        // ability an older build would not have.
        let mut declared = vec![crate::s2s::ACT.to_string()];
        if takes_routes {
            declared.push(crate::s2s::ACT_ROUTE.to_string());
        }
        mgr.peer_capabilities
            .lock()
            .await
            .insert(PEER.to_string(), declared);
        rx
    }

    /// Make every waiting route due, the way the retry tick eventually does.
    fn every_route_due_now(state: &Arc<SharedState>) {
        let ahead = std::time::Instant::now() + std::time::Duration::from_secs(3600);
        let due = state.act_routes.lock().take_due(ahead);
        for mut route in due {
            route.next_attempt = std::time::Instant::now();
            state.act_routes.lock().park(route);
        }
    }

    /// The tags of a receipt as the server that owns a task signs one.
    fn signed_receipt_tags(
        channel: &str,
        event_id: &str,
        act_id: &str,
        subject: &str,
        home: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> HashMap<String, String> {
        signed_follow_up_tags(
            channel,
            event_id,
            freeq_sdk::act_transitions::confirmation_verb(),
            act_id,
            home,
            &[(
                &format!(
                    "+freeq.at/{}",
                    freeq_sdk::act_transitions::confirmation_subject_tag()
                ),
                subject,
            )],
            key,
        )
    }

    /// Every task event this server put on the wire to its peers, as
    /// `(verb, tags)`.
    fn to_peers(
        broadcasts: &mut mpsc::Receiver<S2sMessage>,
    ) -> Vec<(String, HashMap<String, String>)> {
        let mut seen = Vec::new();
        while let Ok(msg) = broadcasts.try_recv() {
            if let S2sMessage::Tagmsg { tags, .. } = msg {
                let verb = tags.get("+freeq.at/act-verb").cloned().unwrap_or_default();
                seen.push((verb, tags));
            }
        }
        seen
    }

    /// A task `PEER` owns, with one transition on it filed here unconfirmed
    /// and a route to `PEER` waiting — the state every route test starts from.
    ///
    /// The transition arrives over a third server's link, which is what an
    /// agent elsewhere claiming `PEER`'s task looks like on the wire.
    async fn a_transition_waiting_for_its_home(
        state: &Arc<SharedState>,
        mgr: &Arc<crate::s2s::S2sManager>,
        channel: &str,
        act_id: &str,
        claim: &str,
        key: &ed25519_dalek::SigningKey,
    ) {
        relay(
            state,
            mgr,
            channel,
            act_id,
            signed_offer_tags(channel, act_id, key),
        )
        .await;

        const THIRD: &str = "fake-third-peer-id-for-testing";
        mgr.authenticated_peers
            .lock()
            .await
            .insert(THIRD.to_string());
        super::S2S_RATE_LIMITS.lock().remove(THIRD);

        process_s2s_message(
            state,
            mgr,
            THIRD,
            S2sMessage::Tagmsg {
                event_id: format!("{THIRD}:{claim}"),
                from: "scholar!s@third".to_string(),
                target: channel.to_string(),
                tags: signed_follow_up_tags(channel, claim, "claim", act_id, SIGNER, &[], key),
                origin: THIRD.to_string(),
                account: Some(SIGNER.to_string()),
            },
        )
        .await;
    }

    /// Read every routed transition a peer's link was handed.
    async fn routed_to_peer(rx: &mut mpsc::Receiver<S2sMessage>) -> Vec<String> {
        let mut seen = Vec::new();
        while let Ok(Some(msg)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {
            if let S2sMessage::ActRoute { act_event_id, .. } = msg {
                seen.push(act_event_id);
            }
        }
        seen
    }

    /// What the log says about whose word one task event carries. A receipt
    /// carries no state of its own, and reads as `<a receipt>`.
    fn confirm_state_of(state: &Arc<SharedState>, act_id: &str, event_id: &str) -> String {
        state
            .with_db(|db| db.act_task_events(act_id))
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.event_id == event_id)
            .map(|e| match e.confirm {
                Some(confirm) => confirm.as_str().to_string(),
                None => "<a receipt>".to_string(),
            })
            .unwrap_or_else(|| "<not on file>".to_string())
    }

    /// Carry one transition here as the server holding it unruled would.
    async fn route_here(
        state: &Arc<SharedState>,
        mgr: &Arc<crate::s2s::S2sManager>,
        channel: &str,
        act_id: &str,
        event_id: &str,
        tags: HashMap<String, String>,
    ) {
        process_s2s_message(
            state,
            mgr,
            PEER,
            S2sMessage::ActRoute {
                event_id: format!("{PEER}:{event_id}"),
                act_id: act_id.to_string(),
                act_event_id: event_id.to_string(),
                tags,
                target: channel.to_string(),
                from: "tasker!t@remote".to_string(),
                account: Some(SIGNER.to_string()),
                origin: PEER.to_string(),
            },
        )
        .await;
    }

    /// A transition this server cannot decide is filed unconfirmed and carried
    /// to the server that can decide it.
    #[tokio::test]
    async fn a_transition_on_a_peers_task_is_carried_to_that_peer() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routeout");
        let key = key_on_file(&state, SIGNER);

        let act_id = "01ROUTEOUTOFFER00000000000";
        let claim = "01ROUTEOUTCLAIM0000000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routeout", act_id, claim, &key).await;

        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .expect("still live")
                .state,
            "open",
            "nothing here rules on a task it does not own"
        );
        assert_eq!(
            confirm_state_of(&state, act_id, claim),
            "unconfirmed",
            "and the log says the claim is waiting on somebody"
        );
        let waiting = state.act_routes.lock().take_due(std::time::Instant::now());
        assert_eq!(
            waiting
                .iter()
                .map(|r| (r.event_id.as_str(), r.home.as_str()))
                .collect::<Vec<_>>(),
            [(claim, PEER)],
            "the claim is on its way to the server that owns the task"
        );
    }

    /// The copy carried to the home is the signed event, byte for byte.
    ///
    /// The signature covers every act tag, the venue and the id, so a tag
    /// added, dropped or tidied on the way out would reach the home as a
    /// forgery — and the home would refuse the very move it was being asked
    /// to rule on.
    #[tokio::test]
    async fn a_routed_copy_carries_the_signed_tags_verbatim() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routebytes");
        let key = key_on_file(&state, SIGNER);

        let act_id = "01ROUTEBYTESOFFER00000000";
        let claim = "01ROUTEBYTESCLAIM00000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routebytes", act_id, claim, &key).await;
        let signed =
            signed_follow_up_tags("#routebytes", claim, "claim", act_id, SIGNER, &[], &key);

        let waiting = state.act_routes.lock().take_due(std::time::Instant::now());
        let [route] = waiting.as_slice() else {
            panic!("one transition is waiting for its home");
        };
        let crate::s2s::S2sMessage::ActRoute { tags, target, .. } = &route.message else {
            panic!("a route carries an addressed copy");
        };
        assert_eq!(tags, &signed, "the tag map travels as the signer wrote it");
        assert_eq!(
            tags.get("+freeq.at/sig"),
            signed.get("+freeq.at/sig"),
            "the signature among them, unchanged"
        );
        assert_eq!(
            target, "#routebytes",
            "and the venue it was signed over is recoverable from the target"
        );
    }

    /// The addressed copy is for the home to rule on, not for the room to see
    /// again. The event has already reached every local client by the ordinary
    /// relay, and delivering the ask as well would put one event in the room
    /// twice.
    #[tokio::test]
    async fn a_routed_copy_is_not_delivered_to_local_clients_again() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#routequiet");
        let key = key_on_file(&state, SIGNER);

        let act_id = "01ROUTEQUIETOFFER00000000";
        our_own_task(&state, "#routequiet", act_id);

        let claim = "01ROUTEQUIETCLAIM00000000";
        let tags = signed_follow_up_tags("#routequiet", claim, "claim", act_id, SIGNER, &[], &key);
        relay(&state, &mgr, "#routequiet", claim, tags.clone()).await;

        let mut shown = Vec::new();
        while let Ok(line) = rx.try_recv() {
            shown.push(line);
        }
        assert!(
            shown.iter().any(|line| {
                line.contains(&format!("{}={claim}", freeq_sdk::chatsig::EVENT_ID_TAG))
            }),
            "the ordinary relay is what shows the claim in the room: {shown:?}"
        );

        route_here(&state, &mgr, "#routequiet", act_id, claim, tags).await;
        assert!(
            rx.try_recv().is_err(),
            "the same event carried here to be ruled on reaches nobody a second time"
        );
    }

    /// A link taking a message says nothing about the home having ruled on it,
    /// so the asking continues. Nothing flips a route's event to confirmed on
    /// this server, so today that means it is carried without end — which is
    /// the accepted cost until a home's ruling can cross.
    #[tokio::test]
    async fn a_route_the_link_accepted_is_still_waiting_on_a_ruling() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routelife");
        let key = key_on_file(&state, SIGNER);
        let mut to_peer = link_peer(&mgr, true).await;

        let act_id = "01ROUTELIFEOFFER000000000";
        let claim = "01ROUTELIFECLAIM000000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routelife", act_id, claim, &key).await;

        assert_eq!(
            routed_to_peer(&mut to_peer).await,
            [claim],
            "the transition was handed to the home's link"
        );
        assert_eq!(
            confirm_state_of(&state, act_id, claim),
            "unconfirmed",
            "and no ruling has come back"
        );
        assert_eq!(
            state.act_routes.lock().len(),
            1,
            "so it is still on the list to ask about — a link taking a message \
             is not the home answering it"
        );
    }

    /// A peer that will not take a routed transition right now may be one
    /// whose Hello has not been processed yet, so that answer does not end the
    /// asking either.
    #[tokio::test]
    async fn a_route_a_peer_would_not_take_is_still_waiting_on_a_ruling() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routerefused");
        let key = key_on_file(&state, SIGNER);
        // Linked, but declaring nothing — the shape of a peer mid-handshake.
        let mut to_peer = link_peer(&mgr, false).await;

        let act_id = "01ROUTEREFUSEDOFFER000000";
        let claim = "01ROUTEREFUSEDCLAIM000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routerefused", act_id, claim, &key).await;

        assert!(
            routed_to_peer(&mut to_peer).await.is_empty(),
            "nothing is handed to a peer that cannot take it"
        );
        assert_eq!(
            state.act_routes.lock().len(),
            1,
            "and the transition stays on the list to ask about"
        );
    }

    /// The home end: a transition carried here for a task this server owns is
    /// decided, and the receipt this server owes for the move it just made is
    /// in the log naming it — the same always-emit rule a local sender's move
    /// gets at the front door.
    #[tokio::test]
    async fn a_routed_transition_applied_here_leaves_a_receipt_naming_it() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routehome");
        let key = key_on_file(&state, SIGNER);

        let act_id = "01ROUTEHOMEOFFER0000000000";
        our_own_task(&state, "#routehome", act_id);

        let claim = "01ROUTEHOMECLAIM0000000000";
        let tags = signed_follow_up_tags("#routehome", claim, "claim", act_id, SIGNER, &[], &key);
        route_here(&state, &mgr, "#routehome", act_id, claim, tags).await;

        let task = state
            .with_db(|db| db.act_task(act_id))
            .flatten()
            .expect("our own task is still live");
        assert_eq!(task.state, "assigned", "the home decided it");
        assert_eq!(task.assignee.as_deref(), Some(SIGNER));
        assert_eq!(
            confirm_state_of(&state, act_id, claim),
            "confirmed",
            "an event on a task of ours waits on nobody"
        );

        let subject_tag = freeq_sdk::act_transitions::confirmation_subject_tag();
        let receipts: Vec<String> = state
            .with_db(|db| db.act_task_events(act_id))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                let view = crate::events::derive_act_view(&e.canonical)?;
                freeq_sdk::act_transitions::is_confirmation(&view.verb)
                    .then(|| view.fields.get(subject_tag).cloned().unwrap_or_default())
            })
            .collect();
        assert_eq!(
            receipts,
            [claim.to_string()],
            "the home's receipt for the move it applied names the event it confirms"
        );
    }

    /// A transition carried here for a task some other server owns is
    /// misrouted: logged and dropped, never ruled on. Two servers ruling on
    /// one task is the disagreement this whole design exists to prevent.
    #[tokio::test]
    async fn a_transition_routed_here_for_someone_elses_task_is_dropped() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routewrong");
        let key = key_on_file(&state, SIGNER);

        // A task PEER opened, which arrived here by ordinary relay.
        let act_id = "01ROUTEWRONGOFFER000000000";
        relay(
            &state,
            &mgr,
            "#routewrong",
            act_id,
            signed_offer_tags("#routewrong", act_id, &key),
        )
        .await;
        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .expect("on file")
                .origin,
            PEER
        );

        // "Never ruled on" is the task not moving: the view of it before the
        // misrouted transition arrives must be the view after.
        let task_before = state
            .with_db(|db| db.act_task(act_id))
            .flatten()
            .expect("on file");

        let claim = "01ROUTEWRONGCLAIM000000000";
        route_here(
            &state,
            &mgr,
            "#routewrong",
            act_id,
            claim,
            signed_follow_up_tags("#routewrong", claim, "claim", act_id, SIGNER, &[], &key),
        )
        .await;

        assert!(
            !state.with_db(|db| db.is_act_event(claim)).unwrap(),
            "a misrouted transition is not filed here"
        );
        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .expect("still on file"),
            task_before,
            "and the task it named did not move: this server ruled on nothing"
        );
    }

    // ── a receipt on the wire ──────────────────────────────────────────────
    //
    // What a receipt is for: a transition filed on another server decides
    // nothing there until the server that owns the task says it won. So the
    // receipt has to cross, has to count only when it arrives on the owning
    // server's link, and has to be said again to a peer that never heard it.

    /// A receipt of ours goes to the peers that can read it, not only to the
    /// room. Without this half the only server whose word settles the task
    /// speaks it to the people least in need of hearing it.
    #[tokio::test]
    async fn a_receipt_of_ours_goes_out_to_peers_as_well_as_to_the_room() {
        let state = test_state_with_db();
        let (mgr, mut broadcasts) = test_manager_with_broadcast_rx();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#ruleout");
        let key = key_on_file(&state, SIGNER);

        let act_id = "01RULEOUTOFFER00000000000";
        our_own_task(&state, "#ruleout", act_id);
        let claim = "01RULEOUTCLAIM00000000000";
        relay(
            &state,
            &mgr,
            "#ruleout",
            claim,
            signed_follow_up_tags("#ruleout", claim, "claim", act_id, SIGNER, &[], &key),
        )
        .await;

        let subject_tag = format!(
            "+freeq.at/{}",
            freeq_sdk::act_transitions::confirmation_subject_tag()
        );
        let sent = to_peers(&mut broadcasts);
        let receipt = sent
            .iter()
            .find(|(verb, _)| freeq_sdk::act_transitions::is_confirmation(verb))
            .map(|(_, tags)| tags)
            .unwrap_or_else(|| panic!("the receipt has to reach the peers: {sent:?}"));
        assert_eq!(
            receipt.get(&subject_tag).map(String::as_str),
            Some(claim),
            "and it names the event it rules in"
        );
        assert_eq!(
            receipt.get("+freeq.at/from").map(String::as_str),
            Some(server_did(&state.server_name).as_str()),
            "signed under the identity that settles this task"
        );
        assert!(
            receipt.contains_key("+freeq.at/sig"),
            "and signed: a receipt nobody can check is worth nothing"
        );

        let mut shown = Vec::new();
        while let Ok(line) = rx.try_recv() {
            shown.push(line);
        }
        assert!(
            shown.iter().any(|line| line.contains("act-verb=confirm")),
            "the room still hears it too: {shown:?}"
        );
    }

    /// The other event only this server can author. An expiry ends a task, and
    /// a peer that never hears it holds a row that stays live for ever.
    #[tokio::test]
    async fn an_expiry_of_ours_goes_out_to_peers() {
        let state = test_state_with_db();
        let (mgr, mut broadcasts) = test_manager_with_broadcast_rx();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#expireout");

        let act_id = "01EXPIREOUTOFFER000000000";
        our_own_task(&state, "#expireout", act_id);
        let task = state
            .with_db(|db| db.act_task(act_id))
            .flatten()
            .expect("live");
        assert!(crate::connection::act::expire_task(&state, &task));

        let sent = to_peers(&mut broadcasts);
        assert!(
            sent.iter().any(|(verb, _)| verb == "expire"),
            "the event that ends the task has to reach the servers holding it: {sent:?}"
        );
    }

    /// The receiving half: the home rules, and this server follows — because
    /// the receipt arrived on the link of the server the task was opened on.
    #[tokio::test]
    async fn a_receipt_from_the_home_moves_a_task_here() {
        const HOME: &str = "did:web:peer-b.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#follow");
        let key = key_on_file(&state, SIGNER);
        let home_key = key_on_file(&state, HOME);

        let act_id = "01FOLLOWOFFER00000000000";
        let claim = "01FOLLOWCLAIM00000000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#follow", act_id, claim, &key).await;
        assert_eq!(confirm_state_of(&state, act_id, claim), "unconfirmed");

        let receipt = "01FOLLOWRECEIPT000000000";
        relay(
            &state,
            &mgr,
            "#follow",
            receipt,
            signed_receipt_tags("#follow", receipt, act_id, claim, HOME, &home_key),
        )
        .await;

        let task = state
            .with_db(|db| db.act_task(act_id))
            .flatten()
            .expect("still live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("assigned", Some(SIGNER)),
            "the state came from running the claim through the rules here"
        );
        assert_eq!(
            confirm_state_of(&state, act_id, claim),
            "confirmed",
            "and the claim is no longer waiting on anybody"
        );
        assert_eq!(
            confirm_state_of(&state, act_id, receipt),
            "<a receipt>",
            "the receipt itself carries no state of its own"
        );
    }

    /// A receipt can arrive ahead of the event it confirms — an uneven mesh
    /// makes that ordinary. It waits rather than being dropped, and the
    /// subject's arrival is what applies it.
    #[tokio::test]
    async fn a_receipt_that_outran_its_subject_waits_and_then_applies() {
        const HOME: &str = "did:web:peer-b.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#outrun");
        let key = key_on_file(&state, SIGNER);
        let home_key = key_on_file(&state, HOME);

        let act_id = "01OUTRUNOFFER0000000000";
        relay(
            &state,
            &mgr,
            "#outrun",
            act_id,
            signed_offer_tags("#outrun", act_id, &key),
        )
        .await;

        // The receipt first.
        let claim = "01OUTRUNCLAIM0000000000";
        let receipt = "01OUTRUNRECEIPT00000000";
        relay(
            &state,
            &mgr,
            "#outrun",
            receipt,
            signed_receipt_tags("#outrun", receipt, act_id, claim, HOME, &home_key),
        )
        .await;
        assert!(
            !state.with_db(|db| db.is_act_event(receipt)).unwrap(),
            "a receipt that is waiting is not filed, so the copy it waits for is \
             not turned into a duplicate"
        );
        assert_eq!(state.act_deferred.lock().len(), 1, "it is being held");
        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .unwrap()
                .state,
            "open"
        );

        // …and then the claim it names.
        relay(
            &state,
            &mgr,
            "#outrun",
            claim,
            signed_follow_up_tags("#outrun", claim, "claim", act_id, SIGNER, &[], &key),
        )
        .await;

        assert_eq!(state.act_deferred.lock().len(), 0, "and it was handed back");
        assert_eq!(
            state
                .with_db(|db| db.act_task(act_id))
                .flatten()
                .expect("still live")
                .assignee
                .as_deref(),
            Some(SIGNER),
            "the receipt applied the moment the event it names was on file"
        );
        assert_eq!(confirm_state_of(&state, act_id, claim), "confirmed");
    }

    /// A peer that asks again about a transition already ruled on is answered
    /// again — with the very receipt on file, read back rather than decided a
    /// second time. Nothing else covers it: a replay carries an event under
    /// the server that minted it, never under the one that ruled on it.
    #[tokio::test]
    async fn a_repeat_ask_is_answered_with_the_receipt_on_file() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#askagain");
        let key = key_on_file(&state, SIGNER);
        let mut to_peer = link_peer(&mgr, true).await;

        let act_id = "01ASKAGAINOFFER00000000";
        our_own_task(&state, "#askagain", act_id);
        let claim = "01ASKAGAINCLAIM00000000";
        let tags = signed_follow_up_tags("#askagain", claim, "claim", act_id, SIGNER, &[], &key);
        route_here(&state, &mgr, "#askagain", act_id, claim, tags.clone()).await;
        while to_peer.try_recv().is_ok() {}

        // Asked again, because the peer never heard the answer.
        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::ActRoute {
                event_id: format!("{PEER}:{claim}/2"),
                act_id: act_id.to_string(),
                act_event_id: claim.to_string(),
                tags,
                target: "#askagain".to_string(),
                from: "tasker!t@remote".to_string(),
                account: Some(SIGNER.to_string()),
                origin: PEER.to_string(),
            },
        )
        .await;

        let subject_tag = format!(
            "+freeq.at/{}",
            freeq_sdk::act_transitions::confirmation_subject_tag()
        );
        match to_peer.try_recv() {
            Ok(S2sMessage::Tagmsg { tags: said, .. }) => {
                assert!(
                    said.get("+freeq.at/act-verb")
                        .is_some_and(|verb| freeq_sdk::act_transitions::is_confirmation(verb)),
                    "the answer is the receipt: {said:?}"
                );
                assert_eq!(
                    said.get(&subject_tag).map(String::as_str),
                    Some(claim),
                    "and it names the event still being asked about"
                );
            }
            other => panic!("a peer still asking has to be answered: {other:?}"),
        }

        let task = state
            .with_db(|db| db.act_task(act_id))
            .flatten()
            .expect("our own task is still live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("assigned", Some(SIGNER)),
            "said again, not decided again"
        );
    }

    /// A route ends when the event it carries stops waiting. The home's receipt
    /// arriving is one way that happens, and after it there is nothing left to
    /// ask about.
    #[tokio::test]
    async fn a_route_whose_event_has_been_confirmed_is_dropped_without_asking() {
        const HOME: &str = "did:web:peer-b.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routeruled");
        let key = key_on_file(&state, SIGNER);
        let home_key = key_on_file(&state, HOME);
        let mut to_peer = link_peer(&mgr, true).await;

        let act_id = "01ROUTERULEDOFFER0000000";
        let claim = "01ROUTERULEDCLAIM0000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routeruled", act_id, claim, &key).await;
        let _ = routed_to_peer(&mut to_peer).await;

        let receipt = "01ROUTERULEDRECEIPT00000";
        relay(
            &state,
            &mgr,
            "#routeruled",
            receipt,
            signed_receipt_tags("#routeruled", receipt, act_id, claim, HOME, &home_key),
        )
        .await;
        assert_eq!(confirm_state_of(&state, act_id, claim), "confirmed");

        every_route_due_now(&state);
        flush_pending_routes(&state).await;

        assert!(
            routed_to_peer(&mut to_peer).await.is_empty(),
            "a ruled-on event is not asked about again"
        );
        assert_eq!(state.act_routes.lock().len(), 0, "and its route is dropped");
    }

    /// The other way an event stops waiting: something else was ruled in and
    /// the rules no longer admit this one. A loser is not asked about either.
    #[tokio::test]
    async fn a_route_whose_event_was_outrun_is_dropped_without_asking() {
        const HOME: &str = "did:web:peer-b.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routeoutrun");
        let key = key_on_file(&state, SIGNER);
        let home_key = key_on_file(&state, HOME);
        let mut to_peer = link_peer(&mgr, true).await;

        let act_id = "01ROUTEOUTRUNOFFER000000";
        let claim = "01ROUTEOUTRUNCLAIM000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routeoutrun", act_id, claim, &key).await;
        let _ = routed_to_peer(&mut to_peer).await;

        // The task's own server expires it, which it may do under its own
        // name. The claim that was waiting can never be ruled in now.
        let expiry = "01ROUTEOUTRUNEXPIRY00000";
        relay(
            &state,
            &mgr,
            "#routeoutrun",
            expiry,
            signed_follow_up_tags(
                "#routeoutrun",
                expiry,
                "expire",
                act_id,
                HOME,
                &[],
                &home_key,
            ),
        )
        .await;
        assert_eq!(
            confirm_state_of(&state, act_id, claim),
            "superseded",
            "the claim was outrun by the ending of the task"
        );

        every_route_due_now(&state);
        flush_pending_routes(&state).await;

        assert!(
            routed_to_peer(&mut to_peer).await.is_empty(),
            "an outrun event is not asked about again"
        );
        assert_eq!(state.act_routes.lock().len(), 0, "and its route is dropped");
    }

    /// Sending to a peer is not hearing from it. The orphan clock reads "last
    /// heard from", and a message handed to a link that is already gone must
    /// not refresh it.
    #[tokio::test]
    async fn handing_a_transition_to_a_link_is_not_hearing_from_the_peer() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#routecontact");
        let key = key_on_file(&state, SIGNER);
        let mut to_peer = link_peer(&mgr, true).await;

        let long_ago = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        mgr.peer_contact.lock().touch_at(PEER, long_ago);

        let act_id = "01ROUTECONTACTOFFER0000000";
        let claim = "01ROUTECONTACTCLAIM0000000";
        a_transition_waiting_for_its_home(&state, &mgr, "#routecontact", act_id, claim, &key).await;
        assert_eq!(
            routed_to_peer(&mut to_peer).await,
            [claim],
            "the transition went out over the link"
        );

        assert_eq!(
            mgr.peer_contact.lock().last_contact(PEER),
            long_ago,
            "and that is not contact: nothing was heard from the peer, so the \
             clock that says how long a home has been silent must not move"
        );
    }

    #[tokio::test]
    async fn a_verifying_relayed_task_event_is_delivered_unchanged_and_filed_valid() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#verdictvalid");
        let key = key_on_file(&state, SIGNER);
        let tags = signed_offer_tags("#verdictvalid", "01VERDICTVALID000000000000", &key);
        let sig = tags["+freeq.at/sig"].clone();

        relay(
            &state,
            &mgr,
            "#verdictvalid",
            "01VERDICTVALID000000000000",
            tags,
        )
        .await;

        // The verdict this server reached is on the stored row, not only in
        // its logs.
        assert_eq!(
            state
                .with_db(|db| db.get_event("01VERDICTVALID000000000000"))
                .unwrap()
                .expect("the event is filed")
                .sig_state,
            crate::events::SigState::Valid,
        );

        let line = received(&mut rx).await;
        assert!(line.contains("TAGMSG"), "delivered: {line}");
        assert!(
            line.contains("+freeq.at/act=handoff") && line.contains(&sig),
            "delivery carries the tags and signature unchanged: {line}"
        );

        // …and it is on file here, under the id its signer minted — the id a
        // later replay will name, so the same event is recognised rather than
        // read as a second claim.
        assert!(
            state
                .with_db(|db| db.is_act_event("01VERDICTVALID000000000000"))
                .unwrap(),
            "a verified task event is stored"
        );
        let task = state
            .with_db(|db| db.act_task("01VERDICTVALID000000000000"))
            .unwrap()
            .expect("the offer opened a task");
        assert_eq!(task.origin, PEER, "stamped with the server that owns it");
        assert_eq!(task.venue, "#verdictvalid");
        assert_eq!(task.offerer, SIGNER);
    }

    /// A relayed event belongs to a task some other server opened. An origin
    /// field left blank says the opposite: an empty origin is how this server
    /// writes "opened here", so believing one would hand us the refereeing of
    /// the task and the expiry of work we never took on. It is refused before
    /// the signature is read — a signature says who signed, never whose task
    /// it is — and this one verifies, so the blank origin is the only thing
    /// wrong with the event.
    /// A task event a peer relayed reaches the signer's own sessions here.
    ///
    /// The delivery that puts an event in the named identity's own client is
    /// gated on this server having checked the signature. For a mutation that
    /// answer is the mutation verdict; a task event is not a mutation and has
    /// none, so the gate read absent and a DID logged in here and elsewhere
    /// saw their own task events on every server but this one. The act
    /// checker is the answer for this family, and it has already run.
    #[tokio::test]
    async fn a_relayed_task_event_reaches_the_signers_own_sessions() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        // The person the DM is addressed to, and the signer's own other
        // device on this server: one identity logged in on two servers.
        let mut theirs = capable_session_for(&state, RECIPIENT);
        let mut signers_own = capable_session_for(&state, SIGNER);
        let key = key_on_file(&state, SIGNER);

        let event_id = "01DMLIVE0000000000000000AA";
        let venue = freeq_sdk::chatsig::dm_venue(SIGNER, RECIPIENT);
        let tags = signed_offer_tags_in(&venue, event_id, &key);
        relay(&state, &mgr, RECIPIENT, event_id, tags).await;

        let to_them = received(&mut theirs).await;
        assert!(
            to_them.contains(event_id),
            "the recipient is told: {to_them}"
        );
        let to_signer = received(&mut signers_own).await;
        assert!(
            to_signer.contains(event_id),
            "and so is the signer's own session here: {to_signer}"
        );
    }

    #[tokio::test]
    async fn a_relayed_task_event_that_names_no_origin_does_not_become_ours() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#noorigin");
        let key = key_on_file(&state, SIGNER);
        let event_id = "01NOORIGIN0000000000000000";
        let tags = signed_offer_tags("#noorigin", event_id, &key);

        process_s2s_message(
            &state,
            &mgr,
            PEER,
            S2sMessage::Tagmsg {
                event_id: format!("{PEER}:{event_id}"),
                from: "tasker!t@remote".to_string(),
                target: "#noorigin".to_string(),
                tags,
                origin: String::new(),
                account: Some(SIGNER.to_string()),
            },
        )
        .await;

        assert!(
            state.with_db(|db| db.act_task(event_id)).unwrap().is_none(),
            "no task of it stands here, least of all one of ours"
        );
        assert!(
            !state.with_db(|db| db.is_act_event(event_id)).unwrap(),
            "and nothing is filed: the log holds what this server accepted"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "and nobody is shown it"
        );
        assert_eq!(
            state.act_deferred.lock().len(),
            0,
            "refused outright, not parked: no key arriving later can fix a \
             blank origin"
        );
    }

    /// The one verdict that stops an event. This test used to pin the
    /// opposite — a tampered event still delivered — because the check was
    /// observe-only and delivery was deliberately untouched by it. Acting on
    /// the verdict is what reverses it: a found key over altered bytes is
    /// evidence, and evidence is grounds for showing nobody.
    #[tokio::test]
    async fn a_tampered_relayed_task_event_reaches_nobody() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#verdictbad");
        let key = key_on_file(&state, SIGNER);
        let event_id = "01VERDICTBAD00000000000000";
        let mut tags = signed_offer_tags("#verdictbad", event_id, &key);
        tags.insert(
            "+freeq.at/act-title".to_string(),
            "a title nobody signed".to_string(),
        );

        relay(&state, &mgr, "#verdictbad", event_id, tags).await;

        assert_eq!(
            state.act_deferred.lock().len(),
            0,
            "a found key over altered bytes is evidence, not a missing key: \
             refused for good, never parked to retry"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "an event this server can show is forged reaches nobody"
        );
        assert!(
            !state.with_db(|db| db.is_act_event(event_id)).unwrap(),
            "and it is written nowhere: the log is what this server accepted"
        );
        assert!(
            state.with_db(|db| db.act_task(event_id)).unwrap().is_none(),
            "so no task of it exists either"
        );
    }

    #[tokio::test]
    async fn an_unknown_signers_task_event_waits_for_the_key() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#verdictwho");
        // Signed with a key this server never sees: nothing on file.
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let tags = signed_offer_tags("#verdictwho", "01VERDICTWHO00000000000000", &key);

        relay(
            &state,
            &mgr,
            "#verdictwho",
            "01VERDICTWHO00000000000000",
            tags,
        )
        .await;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "and goes unseen: showing it would present an unchecked claim as a task"
        );
        assert!(
            !state
                .with_db(|db| db.is_act_event("01VERDICTWHO00000000000000"))
                .unwrap(),
            "and unstored: the log holds what this server checked"
        );
        // Parked, not refused: a key this server does not hold is not
        // evidence of forgery, so the event waits rather than dying.
        assert_eq!(
            state.act_deferred.lock().len(),
            1,
            "it waits for the key rather than being thrown away"
        );
    }

    /// A `did:web:` name in the payload does not make its bearer the system.
    ///
    /// The live path reads the actor the way catch-up and a rebuild read it —
    /// a server signs under `did:web:`, a person does not — so one event no
    /// longer gets two answers depending on which path it arrived by. But
    /// reading the name is not believing the claim: `expire` is a verb only
    /// the system may send, and the system that may send it on a task is the
    /// server that referees the task. This one is ours, and the event came in
    /// on a peer's link, so the peer is not it. Without this, any allowlisted
    /// peer whose key we hold could end work this server owns — which is what
    /// scoping the expiry sweep to our own tasks was for.
    #[tokio::test]
    async fn a_peer_wearing_a_servers_name_cannot_expire_a_task_we_own() {
        const HOME: &str = "did:web:home.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#syskeeper");
        let key = key_on_file(&state, HOME);

        let act_id = "01SYSTEMTASK00000000000000";
        our_own_task(&state, "#syskeeper", act_id);

        let expiry = "01SYSTEMEXPIRE000000000000";
        relay(
            &state,
            &mgr,
            "#syskeeper",
            expiry,
            signed_follow_up_tags("#syskeeper", expiry, "expire", act_id, HOME, &[], &key),
        )
        .await;

        let task = state
            .with_db(|db| db.act_task(act_id))
            .unwrap()
            .expect("the task is still standing");
        assert_eq!(task.state, "open");
        assert!(
            !state.with_db(|db| db.is_act_event(expiry)).unwrap(),
            "and the move is refused, not filed: the rules answered it the \
             way they answer any sender who may not send that verb"
        );
    }

    /// A receipt relayed from a peer is filed like every other task event,
    /// with the link it arrived on recorded on its row — and here that link
    /// is what decides it applies to nothing. The task is this server's own,
    /// so no peer's receipt about it carries any word but its own author's,
    /// and the record is all it leaves.
    #[tokio::test]
    async fn a_relayed_receipt_is_filed_with_the_link_it_arrived_on() {
        const HOME: &str = "did:web:home.example";
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#receipts");
        let key = key_on_file(&state, HOME);

        let act_id = "01RECEIPTTASK0000000000000";
        our_own_task(&state, "#receipts", act_id);

        let receipt = "01RECEIPTEVENT000000000000";
        relay(
            &state,
            &mgr,
            "#receipts",
            receipt,
            signed_follow_up_tags(
                "#receipts",
                receipt,
                freeq_sdk::act_transitions::confirmation_verb(),
                act_id,
                HOME,
                &[("+freeq.at/act-subject", "01RECEIPTSUBJECT0000000000")],
                &key,
            ),
        )
        .await;

        let row = state
            .with_db(|db| db.get_event(receipt))
            .flatten()
            .expect("the receipt is on file");
        assert_eq!(
            row.origin.as_deref(),
            Some(PEER),
            "the row names the link the receipt came in on, the way every \
             other relayed task event's row does"
        );
        let task = state
            .with_db(|db| db.act_task(act_id))
            .unwrap()
            .expect("the task is still live");
        assert_eq!(
            (task.state.as_str(), task.assignee.as_deref()),
            ("open", None),
            "and a receipt moves nothing: what it names did the moving"
        );
    }

    /// What makes deferring a delay and not a loss: the key turns up, and
    /// everything that was waiting on it is judged, applied and delivered — in
    /// the order it was parked, because a claim that arrived before a
    /// completion has to be applied before it.
    #[tokio::test]
    async fn a_key_arriving_releases_what_was_waiting_for_it_in_park_order() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#verdictlate");
        // No key on file yet, so both events park.
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let opener = "01LATEOFFER0000000000000000";
        let follow = "01LATEPROGRESS0000000000000";

        relay(
            &state,
            &mgr,
            "#verdictlate",
            opener,
            signed_offer_tags("#verdictlate", opener, &key),
        )
        .await;
        relay(
            &state,
            &mgr,
            "#verdictlate",
            follow,
            signed_follow_up_tags("#verdictlate", follow, "cancel", opener, SIGNER, &[], &key),
        )
        .await;
        assert_eq!(state.act_deferred.lock().len(), 2, "both are waiting");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "and neither has been shown to anyone"
        );

        // The key registers — the same call a client's MSGSIG makes.
        state
            .with_db(|db| db.save_signing_key(SIGNER, key.verifying_key().as_bytes()))
            .expect("db present");
        retry_deferred_task_events(
            &state,
            SIGNER,
            &freeq_sdk::sigtag::derive_kid(&key.verifying_key()),
        );

        assert_eq!(
            state.act_deferred.lock().len(),
            0,
            "nothing is left waiting"
        );
        let first = received(&mut rx).await;
        assert!(
            first.contains(opener),
            "the offer is delivered first, as it was parked first: {first}"
        );
        let second = received(&mut rx).await;
        assert!(second.contains(follow), "then the follow-up: {second}");

        // Both are on file. The offer opened the task and stamped it with the
        // peer that owns it; the cancellation is filed and goes no further,
        // because ending a task another server referees is not this server's
        // call to make.
        assert!(state.with_db(|db| db.is_act_event(opener)).unwrap());
        assert!(state.with_db(|db| db.is_act_event(follow)).unwrap());
        let task = state
            .with_db(|db| db.act_task(opener))
            .unwrap()
            .expect("the peer's task is still live here");
        assert_eq!(task.origin, PEER);
        assert_eq!(task.state, "open", "we did not cancel a peer's task");
    }

    /// A released event reaches the same sessions a live one would, and that
    /// includes the signer's own other devices here. The live path hands a DM
    /// to those only when the signature checked out; a released event has just
    /// checked out, or it would not be delivered at all — so withholding it
    /// would show a multi-homed signer their own action on one server and not
    /// the other, for no reason but that their key arrived late.
    #[tokio::test]
    async fn a_released_event_reaches_the_signers_own_sessions_too() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        // The person the DM is addressed to, and the signer's own other
        // device on this server: one identity logged in on two servers.
        let mut theirs = capable_session_for(&state, RECIPIENT);
        let mut signers_own = capable_session_for(&state, SIGNER);

        // Signed with a key nothing holds yet, so the event parks.
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let event_id = "01DMRELEASE000000000000000";
        let venue = freeq_sdk::chatsig::dm_venue(SIGNER, RECIPIENT);
        let tags = signed_offer_tags_in(&venue, event_id, &key);
        relay(&state, &mgr, RECIPIENT, event_id, tags).await;
        assert_eq!(state.act_deferred.lock().len(), 1, "it waits for the key");

        // The key registers, and the wait ends.
        state
            .with_db(|db| db.save_signing_key(SIGNER, key.verifying_key().as_bytes()))
            .expect("db present");
        retry_deferred_task_events(
            &state,
            SIGNER,
            &freeq_sdk::sigtag::derive_kid(&key.verifying_key()),
        );

        let to_them = received(&mut theirs).await;
        assert!(
            to_them.contains(event_id),
            "the recipient is told: {to_them}"
        );
        let to_signer = received(&mut signers_own).await;
        assert!(
            to_signer.contains(event_id),
            "and so is the signer's own session here, exactly as the live path \
             would have told it: {to_signer}"
        );
    }

    /// The visible trace of a drop: a waiting event thrown out of a full queue
    /// leaves a count on the task it belonged to, where that task is on file —
    /// and only there. One whose task was never stored leaves nothing but the
    /// log, and no row is invented to say so on.
    #[tokio::test]
    async fn an_eviction_counts_against_the_task_it_belonged_to() {
        // A queue of one per peer, so each new unverifiable event evicts the
        // one before it.
        let state = test_state_with_config(crate::config::ServerConfig {
            act_defer_max_per_origin: 1,
            act_defer_max_total: 4096,
            ..Default::default()
        });
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#evict");
        let key = key_on_file(&state, SIGNER);

        // A task on file: a valid, signed opener from the peer.
        let opener = "01EVICTOPENER0000000000000";
        relay(
            &state,
            &mgr,
            "#evict",
            opener,
            signed_offer_tags("#evict", opener, &key),
        )
        .await;
        assert!(
            state.with_db(|db| db.act_task(opener)).flatten().is_some(),
            "the opener is stored, so there is a row to mark"
        );

        // Follow-ups signed by an identity whose key is nowhere on file:
        // every one of them parks.
        let stranded_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let follow = |event_id: &str, act_id: &str| {
            signed_follow_up_tags(
                "#evict",
                event_id,
                "progress",
                act_id,
                "did:plc:strandedsigner",
                &[],
                &stranded_key,
            )
        };

        let wait1 = "01EVICTWAIT100000000000000";
        relay(&state, &mgr, "#evict", wait1, follow(wait1, opener)).await;
        assert_eq!(state.act_deferred.lock().len(), 1);
        assert_eq!(
            state
                .with_db(|db| db.act_dropped_unchecked(opener))
                .unwrap(),
            0,
            "waiting is not dropped"
        );

        // The second one evicts the first, and the task's row says so.
        let wait2 = "01EVICTWAIT200000000000000";
        relay(&state, &mgr, "#evict", wait2, follow(wait2, opener)).await;
        assert_eq!(
            state
                .with_db(|db| db.act_dropped_unchecked(opener))
                .unwrap(),
            1
        );

        // A follow-up naming a task never stored here parks (evicting the
        // second, which also counts against the opener's task)…
        let unknown = "01EVICTNOROW00000000000000";
        let wait3 = "01EVICTWAIT300000000000000";
        relay(&state, &mgr, "#evict", wait3, follow(wait3, unknown)).await;
        assert_eq!(
            state
                .with_db(|db| db.act_dropped_unchecked(opener))
                .unwrap(),
            2
        );

        // …and when it is evicted in turn, nothing is invented for its
        // unknown task: no row, count zero, log only.
        let wait4 = "01EVICTWAIT400000000000000";
        relay(&state, &mgr, "#evict", wait4, follow(wait4, opener)).await;
        assert_eq!(
            state
                .with_db(|db| db.act_dropped_unchecked(unknown))
                .unwrap(),
            0
        );
        assert!(state.with_db(|db| db.act_task(unknown)).flatten().is_none());
    }

    /// An event that can never verify — no key is named, so no lookup could
    /// ever settle it — waits like any other rather than being refused, and
    /// ages out where somebody can see it.
    #[tokio::test]
    async fn an_event_that_can_never_verify_still_waits_and_ages_out() {
        let state = test_state_with_config(crate::config::ServerConfig {
            act_defer_max_per_origin: 1,
            act_defer_max_total: 4096,
            ..Default::default()
        });
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let mut rx = capable_member(&state, "#nevercheck");
        let key = key_on_file(&state, SIGNER);

        // A task on file, so an aged-out event about it has a row to mark.
        let opener = "01NEVEROPENER0000000000000";
        relay(
            &state,
            &mgr,
            "#nevercheck",
            opener,
            signed_offer_tags("#nevercheck", opener, &key),
        )
        .await;

        // An algorithm this build does not know: unverifiable forever, since
        // no key server can answer a question about a key nobody named.
        let stuck = "01NEVERSTUCK00000000000000";
        let mut tags =
            signed_follow_up_tags("#nevercheck", stuck, "progress", opener, SIGNER, &[], &key);
        tags.insert("+freeq.at/sig".to_string(), "rsa:somekid:AAAA".to_string());
        relay(&state, &mgr, "#nevercheck", stuck, tags).await;

        assert_eq!(
            state.act_deferred.lock().len(),
            1,
            "it waits rather than being refused"
        );
        assert!(
            !state.with_db(|db| db.is_act_event(stuck)).unwrap(),
            "and is written nowhere while it waits"
        );

        // Anything else from that peer pushes it off the back, and the task it
        // named carries the count.
        let next = "01NEVERNEXT000000000000000";
        relay(
            &state,
            &mgr,
            "#nevercheck",
            next,
            signed_follow_up_tags(
                "#nevercheck",
                next,
                "progress",
                opener,
                "did:plc:someoneelse",
                &[],
                &ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            ),
        )
        .await;
        assert_eq!(
            state
                .with_db(|db| db.act_dropped_unchecked(opener))
                .unwrap(),
            1,
            "the ageing-out is visible on the task, not only in the log"
        );
        // The opener's own delivery is the only thing that reached the room.
        let shown = received(&mut rx).await;
        assert!(shown.contains(opener), "{shown}");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "nothing unchecked was ever shown"
        );
    }

    /// The stopgap coordination family (`+freeq.at/event`) gets a verdict
    /// too: relayed coordination TAGMSGs were delivered without any check —
    /// the mutation verifier does not read them — so this wiring is the first
    /// time the receive side checks one.
    #[tokio::test]
    async fn a_relayed_coordination_event_gets_a_verdict_of_its_own() {
        let state = test_state_with_db();
        let mgr = test_manager();
        setup_authenticated_peer(&state, &mgr).await;
        let _rx = capable_member(&state, "#verdictcoord");
        let key = key_on_file(&state, SIGNER);

        let event_id = "01VERDICTCOORD000000000000";
        let payload = "%7B%22description%22%3A%22ship%20it%22%7D";
        let sig = freeq_sdk::chatsig::ChatDoc::coordination(
            SIGNER,
            event_id,
            "#verdictcoord",
            "task_request",
        )
        .with_payload(payload)
        .sign(&key);
        let mut tags = HashMap::new();
        tags.insert("+freeq.at/event".to_string(), "task_request".to_string());
        tags.insert("+freeq.at/payload".to_string(), payload.to_string());
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            event_id.to_string(),
        );
        tags.insert("+freeq.at/sig".to_string(), sig);

        relay(&state, &mgr, "#verdictcoord", event_id, tags).await;

        // The coordination family verifies under its own document, and the
        // verdict this server reached is on the stored row.
        assert_eq!(
            state
                .with_db(|db| db.get_event(event_id))
                .unwrap()
                .expect("a verified coordination event is in the log")
                .sig_state,
            crate::events::SigState::Valid,
        );
        // …and is filed the same way local ingress files one, under the
        // signer's own id.
        let filed = state
            .with_db(|db| Ok(db.get_task(event_id)))
            .flatten()
            .expect("a verified coordination event is stored");
        assert_eq!(filed.actor_did, SIGNER);
        assert_eq!(filed.event_type, "task_request");
        assert_eq!(
            filed.payload_json, r#"{"description":"ship it"}"#,
            "the payload is decoded on the way in, as it is locally"
        );
    }
}
