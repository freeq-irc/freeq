//! Server-to-server (S2S) clustering via iroh.
//!
//! Servers connect to each other using iroh's QUIC transport, forming
//! a mesh network. State is propagated via a simple message protocol
//! on bidirectional streams.
//!
//! # Design (post-audit)
//!
//! - **Peer identity**: iroh endpoint ID is the root identity everywhere.
//!   `server_name` is untrusted display metadata included for logging.
//! - **Event dedup**: every S2S event carries an `event_id` (origin + counter).
//!   A bounded LRU per peer prevents duplicate application on reconnect.
//! - **Source of truth**: presence is S2S-event-only (not CRDT). Topic and
//!   durable authority use CRDT as the convergent source of truth; S2S
//!   events are notifications for immediate UX delivery.
//! - **CRDT sync keyed by iroh endpoint ID** (cryptographic identity).
//!
//! # Protocol
//!
//! Each S2S link uses a single bidirectional QUIC stream carrying
//! newline-delimited JSON messages. Messages are typed:
//!
//! ```json
//! {"type":"hello","peer_id":"44f1415c...","server_name":"freeq"}
//! {"type":"privmsg","event_id":"44f1415c:42","from":"nick!user@host","target":"#channel","text":"hello"}
//! ```
//!
//! # Topology
//!
//! Simple mesh: each server connects to all configured peers. Messages
//! are forwarded with origin tracking to prevent loops.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::server::SharedState;

/// ALPN for server-to-server links.
pub const S2S_ALPN: &[u8] = b"freeq/s2s/1";

/// Maximum number of event IDs to remember per peer for dedup.
const DEDUP_CAPACITY: usize = 10_000;

// ── Phase 3: Capability-based trust levels ──────────────────────

/// Trust level for an S2S peer. Controls what operations they can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Full trust: can relay messages, set ops, kick, ban, set modes, change topics.
    Full,
    /// Relay trust: can relay messages (PRIVMSG, JOIN, PART, QUIT, NICK, TOPIC on non-+t).
    /// Cannot set modes, kick, or ban.
    Relay,
    /// Read-only: receives channel state but cannot originate events.
    /// For monitoring, logging, or archive servers.
    Readonly,
}

impl TrustLevel {
    /// Parse from config string (e.g. "full", "relay", "readonly").
    pub fn parse_level(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "relay" => Self::Relay,
            "readonly" | "read-only" | "ro" => Self::Readonly,
            _ => Self::Full,
        }
    }

    /// Can this peer relay chat messages (PRIVMSG, JOIN, PART, QUIT, NICK)?
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::Full | Self::Relay)
    }

    /// Can this peer perform authority operations (MODE, KICK, BAN, channel creation)?
    pub fn can_admin(&self) -> bool {
        matches!(self, Self::Full)
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Relay => write!(f, "relay"),
            Self::Readonly => write!(f, "readonly"),
        }
    }
}

/// Parse --s2s-peer-trust config into a map of endpoint_id → TrustLevel.
pub fn parse_trust_config(entries: &[String]) -> HashMap<String, TrustLevel> {
    let mut map = HashMap::new();
    for entry in entries {
        if let Some((id, level)) = entry.split_once(':') {
            map.insert(id.to_string(), TrustLevel::parse_level(level));
        }
    }
    map
}

/// Select the application coordination tags that should ride along with a
/// PRIVMSG when it is relayed to S2S peers.
///
/// These (`+freeq.at/event`, `+freeq.at/payload`, `+freeq.at/task-id`,
/// `+freeq.at/evidence-type`, and any future `+freeq.at/*`) are message
/// content — relayed on the same peer-trust basis as the message text, so a
/// federated client can render the same coordination card the origin server
/// shows. Server-controlled tags are deliberately NOT relayed here and stay
/// handled out-of-band: `+freeq.at/sig` (carried in its own field and
/// re-attested on receipt), and `account`/`time`/`msgid` (regenerated
/// locally; not `+freeq.at/`-prefixed so excluded anyway).
pub fn relay_coordination_tags(full: &HashMap<String, String>) -> HashMap<String, String> {
    let mut relayed: HashMap<String, String> = full
        .iter()
        .filter(|(k, _)| k.starts_with("+freeq.at/") && k.as_str() != "+freeq.at/sig")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // The reply reference is part of what a signature covers, so it has to
    // reach the peer intact — a receiver rebuilding the document without it
    // gets a different canonical and reads an honest reply as tampering.
    // Normalized to the canonical spelling, the one local delivery emits.
    if let Some(root) = full.get("+reply").or_else(|| full.get("+draft/reply")) {
        relayed.insert("+reply".to_string(), root.clone());
    }
    relayed
}

/// Encode a PRIVMSG body for the S2S `text` field so that ANY peer
/// can relay it safely to its local clients, regardless of whether
/// that peer understands `multiline_lines`. If the body contains `\n`
/// (i.e., the message is multi-line), `\n` is escaped to the two
/// literal chars `\\n` and the `+freeq.at/multiline` tag is added —
/// the freeq inline encoding that's been understood by freeq clients
/// since before the `draft/multiline` track existed.
///
/// **Why:** the S2S wire field is a JSON String and tolerates real
/// `\n` bytes during transport. But when a peer that doesn't process
/// `multiline_lines` constructs a PRIVMSG from `text` and writes it
/// to its local clients' TCP/WS connections, an embedded `\n` ends
/// the IRC line mid-body and everything after is lost (parsed as
/// unknown commands). Pre-escaping keeps the wire safe everywhere.
///
/// New peers prefer `multiline_lines` for proper BATCH emission and
/// the escaped `text` is ignored. Old peers ignore `multiline_lines`
/// and use the escaped `text` — their local freeq clients decode the
/// tag back to real `\n` on render.
///
/// Returns `(text_for_wire, tags_with_multiline_tag_if_set)`.
pub fn encode_privmsg_text_for_s2s(
    text: &str,
    mut tags: HashMap<String, String>,
) -> (String, HashMap<String, String>) {
    if text.contains('\n') {
        tags.insert("+freeq.at/multiline".to_string(), String::new());
        (text.replace('\n', "\\n"), tags)
    } else {
        (text.to_string(), tags)
    }
}

/// One line of a draft/multiline batch, serialized for S2S relay.
/// Kept minimal so the wire size doesn't balloon for typical agent
/// turns: just the body and the concat flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultilineLine {
    pub body: String,
    /// True if this line carried `draft/multiline-concat` (join to
    /// previous with no separator). Serialized only when non-default
    /// to keep typical-case wire small.
    #[serde(default, skip_serializing_if = "is_false")]
    pub concat: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The capabilities a server may declare in its Hello.
///
/// **This list is the only source of truth.** Both the advertisement and every
/// check read from here — no string literals at call sites — because a
/// capability name typed twice is a capability that silently stops gating
/// anything the day one of the two is misspelled. `capabilities_are_all_used`
/// enforces the other half: a name here that no send site consults is a test
/// failure, not a zombie.
///
/// **What belongs here:** new wire message types, and nothing else. Not
/// preferences, not tuning knobs, not "this peer prefers X" — those are
/// configuration, and putting them here turns a compatibility list into a
/// settings bag nobody can reason about.
///
/// **Retirement.** A capability lives until the feature it gates is baseline
/// for every peer, which is what a `protocol_version` bump means. At that bump
/// the entry is *deleted*, not kept for sentiment — the version bump is the
/// purge moment, and an entry that outlives its purpose is exactly the rot
/// this list is designed to avoid.
///
/// **Names are append-only.** A breaking revision of a capability ships as a
/// new name rather than a changed meaning, because a peer that declares the
/// old name is telling you what it can actually do. If a capability ever needs
/// parameters, they attach as `name=value` — the name itself never changes
/// shape.
pub struct Capability {
    /// The wire name. Append-only.
    pub name: &'static str,
    /// What it gates, and when it arrived — so a reader years later can tell
    /// whether it is still doing anything.
    pub gates: &'static str,
}

/// Every capability this build declares. See [`Capability`] for the rules.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        name: CATCHUP,
        // Added 2026-08-05. Retire at the next protocol_version bump, once no
        // peer predates event replay.
        gates: "CatchupRequest / CatchupEvents — replay of events missed while a link was down",
    },
    Capability {
        name: ACT,
        // Added 2026-08-17. Retire at the next protocol_version bump, once no
        // peer predates task events.
        gates: "Tagmsg carrying task tags — a peer that cannot parse them could strip \
                them in relay, and a stripped tag map breaks the signature downstream",
    },
];

/// Catch-up replay. A peer that does not declare this is never sent
/// [`S2sMessage::CatchupRequest`] or [`S2sMessage::CatchupEvents`]; it would
/// warn-and-skip them, which is data loss dressed as compatibility.
pub const CATCHUP: &str = "catchup";

/// Task events. A peer that does not declare this is never sent a Tagmsg
/// whose tags form a task document: a relay that strips tags it does not
/// know would break the signature over them, and downstream that reads as
/// forgery when the real cause is an old server.
pub const ACT: &str = "act";

/// The capability list this server advertises.
pub fn our_capabilities() -> Vec<String> {
    CAPABILITIES.iter().map(|c| c.name.to_string()).collect()
}

/// Whether `peer_caps` — as declared in that peer's Hello — includes `name`.
///
/// The only way to ask. A peer that declared nothing (an older build, whose
/// Hello has no capability field at all) gets an empty list and therefore a
/// `false` for everything, which is precisely the intended answer: send it
/// nothing it cannot parse.
pub fn peer_supports(peer_caps: &[String], name: &str) -> bool {
    peer_caps
        .iter()
        .any(|c| c == name || c.starts_with(&format!("{name}=")))
}

/// One event, as it travels in a catch-up reply.
///
/// The canonical bytes and the signature ride together and unaltered: a
/// receiver rebuilds nothing and trusts nothing, it checks the signature
/// against the bytes it was handed and reaches its own verdict. `sig_state` is
/// deliberately **not** on the wire — a peer's conclusion about a signature is
/// that peer's, and repeating it would invite a receiver to adopt it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayedEvent {
    pub event_id: String,
    /// The exact JCS bytes the signature covers. Empty when nothing signed
    /// this event, in which case there is nothing to check and it is filed as
    /// unsigned.
    #[serde(default)]
    pub canonical: String,
    #[serde(default)]
    pub signature: Option<String>,
    pub kind: String,
    pub venue: String,
    #[serde(default)]
    pub actor_did: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    /// A reaction's emoji, for an event with no canonical to carry it.
    #[serde(default)]
    pub emoji: Option<String>,
    /// The server this event was **minted** at, not whoever is replaying it.
    ///
    /// A task's origin names the server that referees it, so an event healed
    /// through a third party has to arrive still naming its minter. Empty from
    /// a peer that predates this field, and the peer the link authenticated
    /// stands in — for an honest peer that is the id it used to stamp the
    /// whole batch, so an older peer is no worse off than it was.
    #[serde(default)]
    pub origin: String,
    pub timestamp: u64,
}

/// Messages exchanged between servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum S2sMessage {
    /// Identity handshake — sent immediately on link establishment.
    /// Binds the transport identity (iroh endpoint ID) to the logical
    /// server_name. The peer_id is verified against the QUIC connection's
    /// remote_id() — spoofing is impossible.
    #[serde(rename = "hello")]
    Hello {
        /// Iroh endpoint ID (must match connection's remote_id).
        peer_id: String,
        /// Human-readable server name (untrusted display metadata).
        server_name: String,
        /// Protocol version. Reserved for genuinely breaking envelope
        /// changes; feature negotiation goes through `capabilities` instead,
        /// so two independent features can ship in either order.
        #[serde(default)]
        protocol_version: u32,
        /// Trust level this server offers to the peer (informational).
        #[serde(default)]
        trust_level: Option<String>,
        /// What this server can receive — see [`CAPABILITIES`].
        ///
        /// `serde(default)` is the whole compatibility story: a peer that
        /// predates this field deserializes to an empty list, so it declares
        /// nothing, so it is sent nothing new. The rollout constraint is
        /// satisfied by construction rather than by remembering to check.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },

    /// Phase 1: Mutual auth acknowledgment — sent after receiving Hello.
    /// Confirms the peer is in our allowlist and we accept them.
    #[serde(rename = "hello_ack")]
    HelloAck {
        /// Our endpoint ID (for verification).
        peer_id: String,
        /// Whether we accept this peer (in our allowlist).
        accepted: bool,
        /// Our trust level for this peer.
        #[serde(default)]
        trust_level: Option<String>,
    },

    /// Phase 2: Signed message envelope. All messages after Hello/HelloAck
    /// are wrapped in this envelope for non-repudiation.
    #[serde(rename = "signed")]
    Signed {
        /// Base64url-encoded serialized inner S2sMessage.
        payload: String,
        /// Base64url-encoded ed25519 signature over the payload bytes.
        signature: String,
        /// Signing server's endpoint ID (for key lookup).
        signer: String,
    },

    /// Phase 4: Key rotation announcement. Signed by the OLD key to prove
    /// continuity. Peers update their allowlists to accept the new ID.
    #[serde(rename = "key_rotation")]
    KeyRotation {
        /// The old endpoint ID (must match current transport identity).
        old_id: String,
        /// The new endpoint ID that will replace it.
        new_id: String,
        /// Unix timestamp of the rotation.
        timestamp: u64,
        /// Signature by the old key over "rotate:{old_id}:{new_id}:{timestamp}".
        signature: String,
    },

    /// A PRIVMSG or NOTICE relayed between servers.
    #[serde(rename = "privmsg")]
    Privmsg {
        /// Stable event ID for dedup: "{origin_peer_id}:{counter}".
        #[serde(default)]
        event_id: String,
        from: String,
        target: String,
        text: String,
        /// Origin iroh endpoint ID (to prevent relay loops).
        origin: String,
        /// ULID message ID (IRCv3 `msgid` tag).
        #[serde(default)]
        msgid: Option<String>,
        /// Server-attested message signature (`+freeq.at/sig`).
        #[serde(default)]
        sig: Option<String>,
        /// Sender's DID — the value of the IRCv3 `account` tag. Carried
        /// so the receiving server can stamp `account` for a remote
        /// sender it has no local session for; without it the receiver
        /// has no DID and federated clients show no identity. Always
        /// origin-stamped from the authenticated session, never
        /// client-set (preserves the anti-spoof rule across S2S).
        /// `serde(default)` → older peers omit it (wire back-compat).
        #[serde(default)]
        account: Option<String>,
        /// Recipient's DID for a directed (DM) message — resolved ONCE at the
        /// origin (the authoritative point for the target nick) and stamped
        /// here so a receiver keys durable DM history off the DID instead of
        /// re-resolving the nick to whoever *it* thinks it is. Origin-asserted
        /// and unauthenticated: receivers cross-check when they can and fall
        /// back rather than persist on mismatch. `None` for channel messages
        /// and when the origin couldn't resolve the recipient. `serde(default)`
        /// → older peers omit it (wire back-compat).
        #[serde(default)]
        recipient_did: Option<String>,
        /// When this message is an edit, the identity of the message it
        /// revises — the **root** msgid, the id that message keeps for life.
        ///
        /// Without it a relayed edit is indistinguishable from a new message,
        /// so the receiving peer files a second row and shows its users a
        /// duplicate that never links back to the original. The local wire
        /// carries this as `+draft/edit`, which cannot ride in `tags`: that map
        /// is filtered to `+freeq.at/*` on both send and receive. `serde(default)`
        /// → older peers omit it and the receiver treats the message as new,
        /// which is exactly today's behavior.
        #[serde(default)]
        replaces_msgid: Option<String>,
        /// Application coordination tags (`+freeq.at/event` etc.) that ride
        /// with the message so federated clients render the same card the
        /// origin shows. `serde(default)` → older peers omit it, deserialize
        /// to empty (wire back-compat). See `relay_coordination_tags`.
        #[serde(default)]
        tags: HashMap<String, String>,
        /// When the relayed message originated as a `draft/multiline`
        /// batch, the per-line breakdown so the receiving peer can
        /// re-emit BATCH-wrapped frames to its own multiline-capable
        /// clients (and N PRIVMSGs to fallback clients) instead of a
        /// single PRIVMSG with `\n` in the body. Absent for normal
        /// single-PRIVMSG sends; `text` always carries the assembled
        /// body so peers without multiline-aware fan-out still get
        /// the content (even if wire-broken on their own clients).
        ///
        /// # Why one event with a per-line breakdown, not N events
        ///
        /// An alternative shape would have been to ship a multiline
        /// message as a sequence of N `S2sMessage::Privmsg` events,
        /// mirroring the local wire shape (N PRIVMSGs grouped by
        /// BATCH). That was rejected because:
        ///
        /// - **Atomicity**: a logical message is a single delivery
        ///   unit; receiving peers shouldn't have to wait for N events
        ///   to arrive (in order, with no drops) before they can fan
        ///   out to their local channel members.
        /// - **Dedup**: each event carries an `event_id`. Splitting
        ///   into N events means N dedup entries and a separate
        ///   grouping mechanism so a partial re-sync doesn't
        ///   half-deliver.
        /// - **Signatures**: `+freeq.at/sig` is signed over the
        ///   assembled body. One sig per logical message keeps the
        ///   verification cheap and unambiguous; N separately-signed
        ///   chunks would either expensive (N sigs) or leak unverified
        ///   payload (sig on first chunk only).
        /// - **msgid placement**: a multiline message has one msgid
        ///   per the IRCv3 spec. Bundling keeps "one event = one
        ///   msgid" intact; splitting forces a non-obvious choice
        ///   about which event owns the msgid.
        ///
        /// This bundling pattern is consistent with how the rest of
        /// freeq's S2S layer transmits atomic-application units:
        /// `SyncResponse` carries `Vec<ChannelInfo>` (the cluster's
        /// channel view as of now, not N per-channel events);
        /// `PolicySync` ships the full PolicyDocument JSON in one
        /// event; `CrdtSync` bundles many CRDT ops into one payload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        multiline_lines: Option<Vec<MultilineLine>>,
    },

    /// A PIN/UNPIN relayed between servers.
    #[serde(rename = "pin")]
    Pin {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// The ULID msgid of the pinned/unpinned message.
        msgid: String,
        /// Who pinned/unpinned it.
        pinned_by: String,
        /// true = pin added, false = pin removed.
        #[serde(default)]
        adding: bool,
        origin: String,
    },

    /// A TAGMSG relayed between servers (reactions, typing, etc.).
    #[serde(rename = "tagmsg")]
    Tagmsg {
        #[serde(default)]
        event_id: String,
        from: String,
        target: String,
        /// IRCv3 tags (e.g. +react, +reply, +typing).
        tags: HashMap<String, String>,
        origin: String,
        /// Acting user's DID — the value of the IRCv3 `account` tag, stamped by
        /// the origin from its authenticated session, never client-set (the
        /// same trust shape as `Privmsg.account`).
        ///
        /// A remote actor is not in the receiver's `nick_owners` (that map is
        /// seeded from identities that authenticated *here*), so without this
        /// the receiver can only identify a federated actor by nick. That is
        /// enough for a reaction, but not for authorizing a delete — a nick is
        /// peer-assertable. `serde(default)` → older peers omit it, and the
        /// receiver falls back to the nick lookup exactly as before.
        #[serde(default)]
        account: Option<String>,
    },

    /// A user joined a channel.
    #[serde(rename = "join")]
    Join {
        #[serde(default)]
        event_id: String,
        nick: String,
        channel: String,
        /// Authenticated DID (if any) — used for DID-based ops.
        did: Option<String>,
        /// Resolved AT Protocol handle (e.g. "chadfowler.com").
        handle: Option<String>,
        /// Whether this user is an operator on their home server.
        #[serde(default)]
        is_op: bool,
        /// Actor class: "human", "agent", or "external_agent".
        #[serde(default)]
        actor_class: Option<String>,
        origin: String,
    },

    /// A channel was created (carries founder info for authority resolution).
    #[serde(rename = "channel_created")]
    ChannelCreated {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// DID of the channel founder.
        founder_did: Option<String>,
        /// DIDs with operator status.
        did_ops: Vec<String>,
        /// Unix timestamp of channel creation (informational only).
        created_at: u64,
        origin: String,
    },

    /// A user left a channel.
    #[serde(rename = "part")]
    Part {
        #[serde(default)]
        event_id: String,
        nick: String,
        channel: String,
        origin: String,
    },

    /// A user quit.
    #[serde(rename = "quit")]
    Quit {
        #[serde(default)]
        event_id: String,
        nick: String,
        reason: String,
        origin: String,
    },

    /// A user changed nick.
    #[serde(rename = "nick_change")]
    NickChange {
        #[serde(default)]
        event_id: String,
        old: String,
        new: String,
        origin: String,
    },

    /// Channel topic changed.
    #[serde(rename = "topic")]
    Topic {
        #[serde(default)]
        event_id: String,
        channel: String,
        topic: String,
        set_by: String,
        origin: String,
    },

    /// Channel mode changed.
    #[serde(rename = "mode")]
    Mode {
        #[serde(default)]
        event_id: String,
        channel: String,
        mode: String,
        arg: Option<String>,
        set_by: String,
        origin: String,
    },

    /// Request full state sync (sent on initial link).
    #[serde(rename = "sync_request")]
    SyncRequest,

    /// Ask a peer for the events it accepted in a venue since `since_ts`.
    ///
    /// Sent on link establishment to a peer that declared [`CATCHUP`], and
    /// never to one that didn't — a frozen peer warn-and-skips a message type
    /// it cannot parse, which is data loss wearing compatibility's clothes.
    ///
    /// A window rather than a cursor: the asking server states how far back it
    /// wants, so a peer holding more history than we ever had does not have to
    /// reason about what we might be missing.
    #[serde(rename = "catchup_request")]
    CatchupRequest {
        /// Our endpoint ID, so the answer comes back to us.
        peer_id: String,
        /// Earliest event timestamp wanted (unix seconds).
        since_ts: u64,
        /// Most events to send back. The answering peer caps this itself.
        #[serde(default)]
        limit: usize,
    },

    /// Events a peer missed, in reply to a [`S2sMessage::CatchupRequest`].
    ///
    /// Each event carries its own signature and the bytes that signature
    /// covers, so the receiver reaches its own verdict rather than trusting
    /// the peer that replayed them — which is why cross-server verification
    /// had to land before replay could.
    #[serde(rename = "catchup_events")]
    CatchupEvents {
        /// The peer replaying this batch. Kept, not retired: it is the
        /// fallback each event's own [`ReplayedEvent::origin`] falls back to
        /// when the replying peer predates that field, and dropping it would
        /// leave an older peer's events with no origin at all.
        origin: String,
        events: Vec<ReplayedEvent>,
        /// True when the answer was cut short by the cap, so the asker can
        /// come back for more rather than assume it has everything.
        #[serde(default)]
        more: bool,
    },

    /// Response with current server state.
    #[serde(rename = "sync_response")]
    SyncResponse {
        /// Server's iroh endpoint ID.
        server_id: String,
        /// Active channels and their topics.
        channels: Vec<ChannelInfo>,
    },

    /// Automerge CRDT sync message for convergent state.
    #[serde(rename = "crdt_sync")]
    CrdtSync {
        /// Base64-encoded Automerge sync message.
        data: String,
        /// Origin iroh endpoint ID (used to key sync state).
        origin: String,
    },

    /// A user was kicked from a channel.
    #[serde(rename = "kick")]
    Kick {
        #[serde(default)]
        event_id: String,
        /// Nick of the user being kicked.
        nick: String,
        channel: String,
        /// Nick of the op who kicked them.
        by: String,
        reason: String,
        origin: String,
    },

    /// A ban was set or removed on a channel.
    #[serde(rename = "ban")]
    Ban {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// The ban mask (nick!user@host or DID).
        mask: String,
        /// Who set/removed the ban.
        set_by: String,
        /// true = ban added, false = ban removed.
        adding: bool,
        origin: String,
    },

    /// An invite-exception (+I) entry was set or removed on a channel.
    #[serde(rename = "invite_exception")]
    InviteException {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// The mask (nick!user@host or DID).
        mask: String,
        /// Who set/removed the entry.
        set_by: String,
        /// true = entry added, false = entry removed.
        adding: bool,
        origin: String,
    },

    /// Policy sync — share a channel's policy document with peers.
    /// Sent when a policy is created/updated/cleared.
    #[serde(rename = "policy_sync")]
    PolicySync {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// JSON-serialized PolicyDocument (None = policy cleared).
        policy_json: Option<String>,
        /// JSON-serialized AuthoritySet.
        authority_set_json: Option<String>,
        origin: String,
    },

    /// An invite was issued for a user on a channel.
    #[serde(rename = "invite")]
    Invite {
        #[serde(default)]
        event_id: String,
        channel: String,
        /// The invitee identifier (DID, nick:XXX, or session ID).
        invitee: String,
        /// Nick of the user who issued the invite.
        invited_by: String,
        origin: String,
    },

    // ── AV session federation ───────────────────────────────────────
    /// An AV session was created (voice/video call started).
    #[serde(rename = "av_session_created")]
    AvSessionCreated {
        #[serde(default)]
        event_id: String,
        session_id: String,
        channel: String,
        created_by_did: String,
        created_by_nick: String,
        title: Option<String>,
        iroh_ticket: Option<String>,
        origin: String,
    },

    /// A user joined an AV session.
    #[serde(rename = "av_session_joined")]
    AvSessionJoined {
        #[serde(default)]
        event_id: String,
        session_id: String,
        did: String,
        nick: String,
        origin: String,
    },

    /// A user left an AV session.
    #[serde(rename = "av_session_left")]
    AvSessionLeft {
        #[serde(default)]
        event_id: String,
        session_id: String,
        did: String,
        origin: String,
    },

    /// An AV session ended.
    #[serde(rename = "av_session_ended")]
    AvSessionEnded {
        #[serde(default)]
        event_id: String,
        session_id: String,
        ended_by: Option<String>,
        origin: String,
    },

    /// Internal event: a peer's S2S link has disconnected.
    /// Not sent over the wire — synthesized locally so the event processor
    /// can clean up remote_members for that peer's origin.
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected {
        /// The iroh endpoint ID of the peer that disconnected.
        peer_id: String,
    },
}

/// Per-user info in a channel sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncNick {
    pub nick: String,
    #[serde(default)]
    pub is_op: bool,
    pub did: Option<String>,
    /// Actor class: "human", "agent", or "external_agent".
    #[serde(default)]
    pub actor_class: Option<String>,
}

/// Channel info for sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub topic: Option<String>,
    /// Legacy field: plain nick list (for backward compat with old servers).
    #[serde(default)]
    pub nicks: Vec<String>,
    /// Rich nick list with per-user metadata (preferred over `nicks`).
    #[serde(default)]
    pub nick_info: Vec<SyncNick>,
    /// Channel founder DID.
    pub founder_did: Option<String>,
    /// DIDs with persistent operator status.
    pub did_ops: Vec<String>,
    /// Channel creation timestamp.
    pub created_at: u64,
    /// Channel modes: topic_locked, invite_only, no_ext_msg, moderated
    #[serde(default)]
    pub topic_locked: bool,
    #[serde(default)]
    pub invite_only: bool,
    #[serde(default)]
    pub no_ext_msg: bool,
    #[serde(default)]
    pub moderated: bool,
    #[serde(default)]
    pub key: Option<String>,
    /// Active bans (mask strings).
    #[serde(default)]
    pub bans: Vec<String>,
    /// Active invites (DIDs, nick:XXX tokens).
    #[serde(default)]
    pub invites: Vec<String>,
    /// Active +I invite-exception entries (mask strings, hostmask or DID).
    #[serde(default)]
    pub invite_exceptions: Vec<String>,
}

/// Bounded set for event dedup. Uses two layers:
/// 1. **Monotonic high-water mark** per peer: if the event_id counter
///    portion is ≤ the highest seen, reject it outright. This survives
///    beyond the ring buffer window.
/// 2. **Ring buffer** (VecDeque + HashSet): for non-monotonic or
///    near-duplicate IDs within the recent window.
///
/// Event ID format: `{origin_peer_id}:{counter}` where counter is
/// microseconds-since-epoch (monotonically increasing per sender).
pub struct DedupSet {
    /// Per-peer seen event IDs (ring buffer). Key = origin peer_id.
    seen: tokio::sync::Mutex<HashMap<String, HashSet<String>>>,
    /// Per-peer insertion order for bounded eviction (O(1) pop_front).
    order: tokio::sync::Mutex<HashMap<String, VecDeque<String>>>,
    /// Per-peer monotonic high-water mark: highest counter value seen.
    /// Any event with counter ≤ this is rejected, even outside the ring buffer.
    high_water: tokio::sync::Mutex<HashMap<String, u64>>,
}

impl Default for DedupSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DedupSet {
    pub fn new() -> Self {
        Self {
            seen: tokio::sync::Mutex::new(HashMap::new()),
            order: tokio::sync::Mutex::new(HashMap::new()),
            high_water: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Extract the counter portion from an event_id ("origin:counter" → counter).
    fn parse_counter(event_id: &str) -> Option<u64> {
        event_id.rsplit_once(':').and_then(|(_, c)| c.parse().ok())
    }

    /// Returns true if this event_id is new (not a duplicate).
    /// Returns true for empty event_ids (backward compat with old peers).
    pub async fn check_and_insert(&self, origin: &str, event_id: &str) -> bool {
        if event_id.is_empty() {
            return true; // No dedup for legacy messages
        }

        // Layer 1: monotonic high-water mark check
        if let Some(counter) = Self::parse_counter(event_id) {
            let mut hw = self.high_water.lock().await;
            let mark = hw.entry(origin.to_string()).or_insert(0);
            if counter <= *mark {
                return false; // Counter is ≤ highest seen — stale/replay
            }
            *mark = counter;
        }

        // Layer 2: ring buffer for exact-match dedup
        let mut seen = self.seen.lock().await;
        let mut order = self.order.lock().await;

        let peer_seen = seen.entry(origin.to_string()).or_default();
        let peer_order = order.entry(origin.to_string()).or_default();

        if peer_seen.contains(event_id) {
            return false; // Exact duplicate in ring buffer
        }

        // Evict oldest if at capacity — O(1) with VecDeque
        if peer_seen.len() >= DEDUP_CAPACITY
            && let Some(oldest) = peer_order.pop_front()
        {
            peer_seen.remove(&oldest);
        }

        peer_seen.insert(event_id.to_string());
        peer_order.push_back(event_id.to_string());
        true
    }

    /// Remove all state for a disconnected peer.
    pub async fn remove_peer(&self, origin: &str) {
        self.seen.lock().await.remove(origin);
        self.order.lock().await.remove(origin);
        // Reset high-water mark on disconnect. The old rationale was that
        // time-seeded counters always increase across restarts, but that
        // assumption fails on NTP backward steps, VM resume, or clock skew.
        // After a full disconnect+reconnect, the peer sends a SyncResponse
        // anyway, so we don't need the high-water to protect against replays
        // from the previous session — the ring buffer handles near-term dedup.
        self.high_water.lock().await.remove(origin);
    }
}

/// State for managing S2S links.
/// A peer connection entry with a generation counter for safe cleanup.
#[derive(Clone)]
pub struct PeerEntry {
    pub tx: mpsc::Sender<S2sMessage>,
    pub conn_gen: u64,
}

pub struct S2sManager {
    /// Our server's iroh endpoint ID (cryptographic identity).
    pub server_id: String,
    /// Our server's human-readable name (for Hello messages).
    pub server_name: String,
    /// Connected peer servers: peer_id (iroh endpoint ID) → sender + generation.
    pub peers: Arc<tokio::sync::Mutex<HashMap<String, PeerEntry>>>,
    /// Mapping: iroh endpoint ID → server_name (populated from Hello handshake).
    pub peer_names: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    /// Channel for S2S events that need to be applied to server state.
    pub event_tx: mpsc::Sender<AuthenticatedS2sEvent>,
    /// Monotonic counter for generating unique event IDs.
    pub event_counter: AtomicU64,
    /// Event dedup set.
    pub dedup: Arc<DedupSet>,
    /// Ordered broadcast queue: ensures messages are sent to peers in the
    /// same order their event IDs were assigned.  Without this, independent
    /// tokio::spawn tasks can reorder messages, causing the receiver's
    /// monotonic high-water-mark dedup to reject out-of-order events.
    pub broadcast_tx: mpsc::Sender<S2sMessage>,
    /// Monotonic counter for connection generations — used to ensure cleanup
    /// only removes its own peer entry, not a replacement's.
    pub conn_gen: Arc<AtomicU64>,
    /// Phase 2: Signing key for message envelopes.
    pub signing_key: Arc<iroh::SecretKey>,
    /// Phase 3: Trust levels per peer (from --s2s-peer-trust config).
    /// This is the sole authority for peer trust — a peer's own declared level
    /// is informational and never adopted, so it cannot escalate itself.
    pub trust_config: HashMap<String, TrustLevel>,
    /// Phase 4: Pending key rotations announced by peers (old_id → new_id).
    pub pending_rotations: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    /// Phase 1: Peers that have completed mutual HelloAck handshake.
    pub authenticated_peers: Arc<tokio::sync::Mutex<HashSet<String>>>,
    /// What each peer declared it can receive, from its Hello. A peer absent
    /// from this map, or present with an empty list, is sent nothing new —
    /// see [`CAPABILITIES`].
    pub peer_capabilities: Arc<tokio::sync::Mutex<HashMap<String, Vec<String>>>>,
    /// `--s2s-allowed-peers`, empty meaning no restriction. Held here rather
    /// than read from config at each call site so [`S2sManager::may_relay_to`]
    /// can state the whole rule in one place.
    pub allowed_peers: Vec<String>,
}

impl S2sManager {
    /// Generate a unique event ID for outgoing messages.
    pub fn next_event_id(&self) -> String {
        let counter = self.event_counter.fetch_add(1, Ordering::Relaxed);
        format!("{}:{}", self.server_id, counter)
    }

    /// Queue a message for ordered broadcast to all peer servers.
    /// Messages are processed by a single task to preserve event ID ordering.
    pub fn broadcast(&self, msg: S2sMessage) {
        if self.broadcast_tx.try_send(msg).is_err() {
            tracing::warn!("S2S broadcast queue full or closed");
        }
    }

    /// **The** scope predicate: may events this server holds go to `peer_id`?
    ///
    /// One function, two readers. The live relay path calls it per peer, and
    /// the catch-up replay path calls it before answering — so a replay can
    /// never be broader or narrower than what that same peer receives as
    /// things happen. That symmetry is the rule, not an implementation
    /// detail: scoping replay on its own made it *stricter* than live, which
    /// protected nothing (the peer gets everything live regardless) while
    /// withholding its own users' missed messages. See the near-term
    /// decisions in `docs/FEDERATION-TOPOLOGY.md`.
    ///
    /// Today the answer is "the peer is connected and allowlisted", and live
    /// relay is peer-blind: every allowlisted peer receives every event,
    /// channels and direct messages alike. When relay becomes targeted —
    /// membership-scoped channels, residency-routed direct messages — the
    /// narrowing goes **here**, and replay inherits it with no second edit.
    ///
    /// Connectedness is passed in as the peer map the caller already holds,
    /// rather than locked here: the live path calls this while iterating it.
    pub fn may_relay_to(&self, peer_id: &str, peers: &HashMap<String, PeerEntry>) -> bool {
        peers.contains_key(peer_id) && self.is_allowlisted(peer_id)
    }

    /// Whether the operator permits this peer at all. An empty allowlist means
    /// no restriction, matching `--s2s-allowed-peers`.
    fn is_allowlisted(&self, peer_id: &str) -> bool {
        self.allowed_peers.is_empty() || self.allowed_peers.iter().any(|p| p == peer_id)
    }

    /// Internal: send a message directly to all connected peers (called by broadcast worker).
    ///
    /// Task events are the one message with a narrower audience: a Tagmsg
    /// whose tags form a task document goes only to peers that declared
    /// [`ACT`] in their Hello. The check lives here, on the one ordered path
    /// every broadcast takes, so no call site can forget it.
    async fn broadcast_to_peers(&self, msg: S2sMessage) {
        let act_event_id = match &msg {
            S2sMessage::Tagmsg { event_id, tags, .. }
                if crate::connection::act::carries_act_tags(tags) =>
            {
                Some(event_id.clone())
            }
            _ => None,
        };
        // Snapshot before taking the peers lock, never nested inside it.
        let caps_by_peer = if act_event_id.is_some() {
            Some(self.peer_capabilities.lock().await.clone())
        } else {
            None
        };
        let peers = self.peers.lock().await;
        if peers.is_empty() {
            return;
        }
        for (peer_id, entry) in peers.iter() {
            if !self.may_relay_to(peer_id, &peers) {
                continue;
            }
            if let (Some(event_id), Some(caps_by_peer)) = (&act_event_id, &caps_by_peer) {
                let declared = caps_by_peer.get(peer_id).cloned().unwrap_or_default();
                if !peer_supports(&declared, ACT) {
                    tracing::info!(
                        peer = %peer_id,
                        event = %event_id,
                        "S2S: task event withheld — peer did not declare the act capability"
                    );
                    continue;
                }
            }
            if entry.tx.send(msg.clone()).await.is_err() {
                tracing::warn!(peer = %peer_id, "S2S broadcast: failed to send to peer");
            }
        }
    }

    /// How far back a reconnecting link asks for. Generous on purpose: the
    /// cost of asking for more than we missed is a few duplicate events, each
    /// of which is a no-op, while the cost of asking for less is a hole.
    pub const CATCHUP_WINDOW_SECS: u64 = 24 * 60 * 60;

    /// Ask a peer to replay what we missed, once it has said it can.
    ///
    /// The Hello that carries a peer's capabilities and the link coming up are
    /// two different moments, so this waits a short while for the declaration
    /// rather than deciding from a map that has not been filled in yet. A peer
    /// that never declares [`CATCHUP`] is never asked — the whole point.
    pub async fn request_catchup_when_supported(&self, peer_id: &str, our_id: &str) {
        for _ in 0..20 {
            let declared = self
                .peer_capabilities
                .lock()
                .await
                .get(peer_id)
                .cloned()
                .unwrap_or_default();
            if peer_supports(&declared, CATCHUP) {
                let since_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(Self::CATCHUP_WINDOW_SECS);
                let req = S2sMessage::CatchupRequest {
                    peer_id: our_id.to_string(),
                    since_ts,
                    limit: 0,
                };
                if let Some(entry) = self.peers.lock().await.get(peer_id) {
                    let _ = entry.tx.send(req).await;
                    tracing::info!(peer = %peer_id, since_ts, "S2S catch-up requested");
                }
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        tracing::debug!(
            peer = %peer_id,
            "S2S peer declared no catch-up support — nothing new will be sent to it"
        );
    }

    /// Look up the human-readable name for a peer (from Hello handshake).
    pub async fn peer_display_name(&self, peer_id: &str) -> String {
        self.peer_names
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| peer_id[..8.min(peer_id.len())].to_string())
    }

    // ── Phase 2: Message signing ────────────────────────────────

    /// Sign an S2S message and wrap it in a Signed envelope.
    pub fn sign_message(&self, msg: &S2sMessage) -> S2sMessage {
        let payload_json = serde_json::to_string(msg).unwrap_or_default();
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig = self.signing_key.sign(payload_json.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        S2sMessage::Signed {
            payload: payload_b64,
            signature: sig_b64,
            signer: self.server_id.clone(),
        }
    }

    /// Verify and unwrap a Signed envelope. Returns the inner message if valid.
    pub fn verify_signed(
        &self,
        payload_b64: &str,
        signature_b64: &str,
        signer_id: &str,
        authenticated_peer_id: &str,
    ) -> Option<S2sMessage> {
        // The signer must match the transport-authenticated peer
        if signer_id != authenticated_peer_id {
            tracing::warn!(
                signer = %signer_id,
                transport = %authenticated_peer_id,
                "Signed message: signer doesn't match transport identity"
            );
            return None;
        }

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .ok()?;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .ok()?;

        if sig_bytes.len() != 64 {
            tracing::warn!("Signed message: invalid signature length");
            return None;
        }

        // Parse the peer's public key from their endpoint ID
        let pub_key: iroh::PublicKey = signer_id.parse().ok()?;
        let sig = iroh::Signature::from_bytes(sig_bytes[..64].try_into().ok()?);

        if pub_key.verify(&payload_bytes, &sig).is_err() {
            tracing::warn!(
                signer = %signer_id,
                "Signed message: signature verification FAILED"
            );
            return None;
        }

        serde_json::from_slice(&payload_bytes).ok()
    }

    // ── Phase 3: Trust level management ─────────────────────────

    /// Get the trust level for a peer. Read from the operator's configured
    /// trust only; a peer's self-declared level is never consulted. Defaults
    /// to Full for peers with no explicit config (open federation).
    pub async fn get_trust(&self, peer_id: &str) -> TrustLevel {
        self.trust_config
            .get(peer_id)
            .copied()
            .unwrap_or(TrustLevel::Full)
    }

    // ── Phase 4: Key rotation ───────────────────────────────────

    /// Create a key rotation announcement signed by our current key.
    pub fn announce_rotation(&self, new_id: &str) -> S2sMessage {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = format!("rotate:{}:{}:{}", self.server_id, new_id, timestamp);
        let sig = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        S2sMessage::KeyRotation {
            old_id: self.server_id.clone(),
            new_id: new_id.to_string(),
            timestamp,
            signature: sig_b64,
        }
    }

    /// Verify a key rotation announcement from a peer.
    pub fn verify_rotation(
        &self,
        old_id: &str,
        new_id: &str,
        timestamp: u64,
        signature_b64: &str,
        authenticated_peer_id: &str,
    ) -> bool {
        // Old ID must match transport identity
        if old_id != authenticated_peer_id {
            tracing::warn!("Key rotation: old_id doesn't match transport");
            return false;
        }
        // Timestamp must be recent (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(timestamp) > 300 {
            tracing::warn!("Key rotation: timestamp too old/future");
            return false;
        }

        let msg = format!("rotate:{old_id}:{new_id}:{timestamp}");
        let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature_b64)
        {
            Ok(b) => b,
            Err(_) => return false,
        };
        if sig_bytes.len() != 64 {
            return false;
        }

        let pub_key: iroh::PublicKey = match old_id.parse() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = iroh::Signature::from_bytes(sig_bytes[..64].try_into().unwrap());
        pub_key.verify(msg.as_bytes(), &sig).is_ok()
    }
}

/// An S2S message annotated with the transport-authenticated peer identity.
/// The `authenticated_peer_id` comes from `conn.remote_id()` (iroh's
/// cryptographic endpoint ID) — it cannot be spoofed by the payload.
#[derive(Debug, Clone)]
pub struct AuthenticatedS2sEvent {
    /// The iroh endpoint ID of the peer that sent this message,
    /// verified by the QUIC transport layer.
    pub authenticated_peer_id: String,
    /// The deserialized S2S message from the peer.
    pub msg: S2sMessage,
}

/// Start the S2S subsystem.
///
/// Returns the manager + event receiver.
pub async fn start(
    state: Arc<SharedState>,
    endpoint: iroh::Endpoint,
) -> Result<(Arc<S2sManager>, mpsc::Receiver<AuthenticatedS2sEvent>)> {
    let (event_tx, event_rx) = mpsc::channel(1024);
    let server_id = endpoint.id().to_string();
    let signing_key = endpoint.secret_key().clone();
    let trust_config = parse_trust_config(&state.config.s2s_peer_trust);

    let (broadcast_tx, mut broadcast_rx) = mpsc::channel::<S2sMessage>(1024);

    let manager = Arc::new(S2sManager {
        server_id: server_id.clone(),
        server_name: state.server_name.clone(),
        peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        event_tx: event_tx.clone(),
        // Initialize counter from wall clock (microseconds since epoch) so
        // restarts produce strictly increasing event IDs. Peers can use the
        // counter portion for monotonic dedup even across our restarts.
        event_counter: AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
        ),
        dedup: Arc::new(DedupSet::new()),
        broadcast_tx,
        conn_gen: Arc::new(AtomicU64::new(0)),
        signing_key: Arc::new(signing_key),
        trust_config,
        pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        allowed_peers: state.config.s2s_allowed_peers.clone(),
    });

    // Spawn the ordered broadcast worker.  All outbound S2S messages flow
    // through this single task, guaranteeing they reach the QUIC writer in
    // the same order their event IDs were assigned.
    let bcast_manager = Arc::clone(&manager);
    tokio::spawn(async move {
        while let Some(msg) = broadcast_rx.recv().await {
            bcast_manager.broadcast_to_peers(msg).await;
        }
    });

    Ok((manager, event_rx))
}

/// `ProtocolHandler` that dispatches accepted S2S connections.
#[derive(Clone)]
pub struct S2sProtocol {
    pub state: Arc<SharedState>,
}

impl std::fmt::Debug for S2sProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sProtocol").finish()
    }
}

impl iroh::protocol::ProtocolHandler for S2sProtocol {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        tracing::info!("Incoming S2S connection from {}", conn.remote_id());
        handle_incoming_s2s(conn, Arc::clone(&self.state)).await;
        Ok(())
    }
}

/// Handle an incoming S2S connection (called from iroh accept loop).
pub async fn handle_incoming_s2s(conn: iroh::endpoint::Connection, state: Arc<SharedState>) {
    let manager = state.s2s_manager.lock().clone();
    let manager = match manager {
        Some(m) => m,
        None => {
            tracing::warn!("Incoming S2S connection but no S2S manager active");
            return;
        }
    };
    let peer_id = conn.remote_id().to_string();

    // Check allowlist
    let allowed = &state.config.s2s_allowed_peers;
    if !allowed.is_empty() && !allowed.contains(&peer_id) {
        tracing::warn!(
            peer = %peer_id,
            "Rejecting S2S connection: peer not in --s2s-allowed-peers allowlist"
        );
        conn.close(1u32.into(), b"not authorized");
        return;
    }

    tracing::info!(peer = %peer_id, "S2S incoming connection (routed by ALPN)");
    handle_s2s_connection_from_manager(conn, &manager, true).await;
}

/// Parse an S2S peer spec into a dial target. Two forms:
///
/// - `<endpoint-id>` — resolve the peer via discovery (production default).
/// - `<endpoint-id>@<host:port>` — dial a direct socket address, bypassing
///   discovery. Used for LAN/static deployments and the federation test harness
///   (hermetic localhost peering).
///
/// Returns the bare endpoint ID (used as the peer-map key / log label, matching
/// what an incoming connection registers) alongside the `EndpointAddr` to dial.
pub(crate) fn parse_peer_spec(spec: &str) -> Result<(iroh::EndpointId, iroh::EndpointAddr)> {
    let (id_str, direct) = match spec.split_once('@') {
        Some((id, addr)) => (id, Some(addr)),
        None => (spec, None),
    };
    let endpoint_id: iroh::EndpointId = id_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid peer endpoint ID '{id_str}': {e}"))?;
    let mut addr = iroh::EndpointAddr::new(endpoint_id);
    if let Some(direct) = direct {
        let sock: std::net::SocketAddr = direct
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid peer direct address '{direct}': {e}"))?;
        addr = addr.with_ip_addr(sock);
    }
    Ok((endpoint_id, addr))
}

/// How long an S2S connection may go without a packet from its peer before
/// QUIC gives up on it.
///
/// The peers map is what stops the retry loop dialling and what makes a
/// returning peer's dial look like a duplicate, so an entry that outlives the
/// process it points at strands the link for exactly as long as it survives.
/// QUIC's 30s default meant a peer that went without a closing handshake — a
/// crash, a kill, a machine going down — stayed in the map for half a minute.
/// Six seconds reaps it well inside the federation harness's settle window.
const S2S_MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(6);

/// How long an otherwise silent S2S connection waits before pinging its peer.
///
/// Under a third of `S2S_MAX_IDLE`, so two pings can go missing without the
/// idle timeout firing. A ping is ack-eliciting and the reply resets the idle
/// timer, so the short timeout above costs a trickle of traffic rather than a
/// link that drops whenever a channel goes quiet.
const S2S_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(2);

/// Dial a peer with the S2S transport parameters.
///
/// Set per dial rather than on the endpoint, which also carries client
/// connections — a phone in a pocket has every reason to survive a quiet
/// stretch that a federation link does not. QUIC negotiates the idle timeout
/// down to the lower of the two ends' advertised values, so a connection dialled
/// with these governs both ends of it whatever the peer advertises, and whatever
/// version the peer is running.
async fn dial_peer(
    endpoint: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
) -> Result<iroh::endpoint::Connection> {
    let transport = iroh::endpoint::QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            S2S_MAX_IDLE
                .try_into()
                .expect("S2S_MAX_IDLE is within QUIC's idle-timeout range"),
        ))
        .keep_alive_interval(S2S_KEEP_ALIVE)
        .build();
    let opts = iroh::endpoint::ConnectOptions::new().with_transport_config(transport);
    Ok(endpoint
        .connect_with_opts(addr, S2S_ALPN, opts)
        .await?
        .await?)
}

/// Connect to a peer server by iroh endpoint ID (optionally `id@host:port`).
pub async fn connect_peer(
    endpoint: &iroh::Endpoint,
    peer_id: &str,
    manager: &Arc<S2sManager>,
) -> Result<()> {
    let (_id, addr) = parse_peer_spec(peer_id)?;

    tracing::info!(peer = %peer_id, "Connecting to S2S peer");
    let conn = dial_peer(endpoint, addr).await?;

    let manager = Arc::clone(manager);
    tokio::spawn(async move {
        handle_s2s_connection_from_manager(conn, &manager, false).await;
    });

    Ok(())
}

/// Connect to a peer with automatic reconnection on failure.
pub fn connect_peer_with_retry(
    endpoint: iroh::Endpoint,
    peer_id: String,
    manager: Arc<S2sManager>,
) {
    tokio::spawn(async move {
        // Parse once — a malformed spec never becomes valid, so don't retry it.
        let (endpoint_id, addr) = match parse_peer_spec(&peer_id) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(peer = %peer_id, "Invalid peer spec (not retrying): {e}");
                return;
            }
        };
        // The peer map is keyed by the bare endpoint ID (what an incoming
        // connection registers), not the full spec, so `id@host:port` still
        // dedups against an inbound link from the same peer.
        let bare_id = endpoint_id.to_string();
        let mut backoff = std::time::Duration::from_secs(1);
        let max_backoff = std::time::Duration::from_secs(60);

        loop {
            // Skip reconnect if we already have a live connection (e.g. incoming replaced ours)
            if manager.peers.lock().await.contains_key(&bare_id) {
                tracing::info!(peer = %peer_id, "S2S peer already connected (via incoming), skipping outgoing attempt");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
                continue;
            }

            tracing::info!(peer = %peer_id, "Connecting to S2S peer");
            match dial_peer(&endpoint, addr.clone()).await {
                Ok(conn) => {
                    backoff = std::time::Duration::from_secs(1);
                    tracing::info!(peer = %peer_id, "S2S peer connected, entering link handler");
                    handle_s2s_connection_from_manager(conn, &manager, false).await;
                    tracing::warn!(peer = %peer_id, "S2S link dropped, will reconnect");
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer_id,
                        backoff_secs = backoff.as_secs(),
                        "S2S connect failed: {e}"
                    );
                }
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    });
}

/// Convenience wrapper that extracts fields from the manager.
async fn handle_s2s_connection_from_manager(
    conn: iroh::endpoint::Connection,
    manager: &Arc<S2sManager>,
    incoming: bool,
) {
    let peers = Arc::clone(&manager.peers);
    let peer_names = Arc::clone(&manager.peer_names);
    let event_tx: mpsc::Sender<AuthenticatedS2sEvent> = manager.event_tx.clone();
    let server_id = manager.server_id.clone();
    let server_name = manager.server_name.clone();
    let conn_gen = Arc::clone(&manager.conn_gen);
    let dedup = Arc::clone(&manager.dedup);
    let mgr = Arc::clone(manager);
    handle_s2s_connection(
        conn,
        peers,
        peer_names,
        event_tx,
        server_id,
        server_name,
        conn_gen,
        dedup,
        incoming,
        mgr,
    )
    .await;
}

/// Which of two simultaneous links between the same pair of servers survives.
///
/// When both servers list each other in `--s2s-peers` — the natural
/// configuration — each dials the other and the pair ends up holding two QUIC
/// connections. Both must independently pick the *same* one to keep, or each
/// keeps the one the other is tearing down: the loser's link task ends, its
/// retry loop dials again, that new connection displaces the peer's entry, and
/// the two servers trade teardowns forever. (Observed: 39 connection
/// generations in 20 seconds, with no link stable long enough to carry a
/// message.)
///
/// The rule is a total order on the pair, so it needs no negotiation: **the
/// server with the lower endpoint ID keeps its outgoing connection**, and the
/// one with the higher ID keeps its incoming. Both sides evaluate this and
/// arrive at the same surviving connection.
///
/// Applied only when a duplicate actually exists. A server that is dialed but
/// does not dial back has exactly one link, and must keep it whichever side of
/// the ID comparison it falls on.
///
/// Yielding is safe only because a dead connection leaves the peers map within
/// `S2S_MAX_IDLE`. The side that keeps its outgoing link is the side that has
/// to dial to recover, and it will not dial while an entry sits in the map — so
/// an entry pointing at a peer that has died is a link neither end holds, and
/// every dial the peer makes to rebuild it gets yielded away as a duplicate
/// until the entry is reaped. Lengthen that timeout and you lengthen the outage
/// after any peer restart.
fn duplicate_link_wins(my_id: &str, peer_id: &str, incoming: bool) -> bool {
    // Lower ID keeps outgoing → for that side, an incoming duplicate loses.
    // Higher ID keeps incoming → for that side, an outgoing duplicate loses.
    incoming != (my_id < peer_id)
}

/// Handle an S2S connection (both incoming and outgoing).
async fn handle_s2s_connection(
    conn: iroh::endpoint::Connection,
    peers: Arc<tokio::sync::Mutex<HashMap<String, PeerEntry>>>,
    peer_names: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    event_tx: mpsc::Sender<AuthenticatedS2sEvent>,
    server_id: String,
    server_name: String,
    conn_gen: Arc<AtomicU64>,
    dedup: Arc<DedupSet>,
    incoming: bool,
    manager: Arc<S2sManager>,
) {
    let peer_id = conn.remote_id().to_string();

    // For incoming: accept_bi, for outgoing: open_bi
    let (send, recv) = if incoming {
        match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %peer_id, "S2S accept_bi failed: {e}");
                return;
            }
        }
    } else {
        match conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %peer_id, "S2S open_bi failed: {e}");
                return;
            }
        }
    };

    // Write channel — with duplicate connection tie-breaking. See
    // `duplicate_link_wins`: both servers apply the same total order, so they
    // keep the same connection instead of tearing down each other's.
    let (write_tx, mut write_rx) = mpsc::channel::<S2sMessage>(256);
    let my_gen = conn_gen.fetch_add(1, Ordering::Relaxed);
    {
        let mut peers_guard = peers.lock().await;
        if peers_guard.contains_key(&peer_id) {
            if !duplicate_link_wins(&server_id, &peer_id, incoming) {
                tracing::info!(
                    peer = %peer_id, incoming, gen = my_gen,
                    "S2S duplicate connection — yielding to the link both sides keep"
                );
                // Leave the map untouched: the surviving entry is the peer's,
                // and the retry loop skips reconnecting while it is there.
                drop(peers_guard);
                conn.close(0u32.into(), b"duplicate link");
                return;
            }
            tracing::info!(
                peer = %peer_id, incoming, gen = my_gen,
                "S2S duplicate connection — replacing existing (generation-safe cleanup)"
            );
        }
        peers_guard.insert(
            peer_id.clone(),
            PeerEntry {
                tx: write_tx,
                conn_gen: my_gen,
            },
        );
    }

    tracing::info!(peer = %peer_id, incoming, "S2S link established");

    // Bridge QUIC recv → DuplexStream for BufReader line reading
    let (bridge_side, irc_side) = tokio::io::duplex(16384);
    let (_bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    let recv_peer = peer_id.clone();
    tokio::spawn(async move {
        let mut recv = recv;
        let mut buf = vec![0u8; 4096];
        let mut bytes_received: u64 = 0;
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    bytes_received += n as u64;
                    if bridge_write.write_all(&buf[..n]).await.is_err() {
                        tracing::warn!(peer = %recv_peer, "S2S recv bridge write failed after {bytes_received} bytes");
                        break;
                    }
                }
                Ok(None) => {
                    tracing::info!(peer = %recv_peer, "S2S recv stream finished (EOF) after {bytes_received} bytes");
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %recv_peer, "S2S recv error after {bytes_received} bytes: {e}");
                    break;
                }
            }
        }
        let _ = bridge_write.shutdown().await;
    });

    // Read JSON lines from the peer.
    // Each message is wrapped with the transport-authenticated peer ID
    // (from conn.remote_id()) so the event processor can trust the identity
    // without relying on the `origin` field in the JSON payload.
    let read_peer = peer_id.clone();
    let authenticated_peer_id = peer_id.clone(); // from conn.remote_id() — cryptographic
    let read_event_tx = event_tx.clone();
    let read_manager = Arc::clone(&manager);
    let read_handle = tokio::spawn(async move {
        let reader = BufReader::new(irc_side);
        let mut lines = reader.lines();
        let mut msg_count: u64 = 0;
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => match serde_json::from_str::<S2sMessage>(&line) {
                    Ok(msg) => {
                        msg_count += 1;
                        tracing::debug!(peer = %read_peer, msg_count, "S2S received: {}", line.chars().take(120).collect::<String>());

                        // Phase 2: Unwrap signed envelopes
                        // C-7 fix: Reject unsigned operational messages.
                        // Only Hello/HelloAck/KeyRotation are exempt (handshake/key mgmt).
                        let msg = match msg {
                            S2sMessage::Signed {
                                ref payload,
                                ref signature,
                                ref signer,
                            } => {
                                match read_manager.verify_signed(
                                    payload,
                                    signature,
                                    signer,
                                    &authenticated_peer_id,
                                ) {
                                    Some(inner) => inner,
                                    None => {
                                        tracing::warn!(peer = %read_peer, "S2S: dropped message with invalid signature");
                                        continue;
                                    }
                                }
                            }
                            S2sMessage::Hello { .. }
                            | S2sMessage::HelloAck { .. }
                            | S2sMessage::KeyRotation { .. } => msg,
                            other => {
                                tracing::warn!(
                                    peer = %read_peer,
                                    msg_type = %serde_json::to_string(&other).unwrap_or_default().chars().take(60).collect::<String>(),
                                    "S2S: rejected unsigned message — signing required"
                                );
                                continue;
                            }
                        };

                        let event = AuthenticatedS2sEvent {
                            authenticated_peer_id: authenticated_peer_id.clone(),
                            msg,
                        };
                        if read_event_tx.send(event).await.is_err() {
                            tracing::warn!(peer = %read_peer, "S2S event_tx closed after {msg_count} messages");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(peer = %read_peer, "S2S invalid JSON: {e} — line: {}", line.chars().take(200).collect::<String>());
                    }
                },
                Ok(None) => {
                    tracing::info!(peer = %read_peer, "S2S read EOF after {msg_count} messages");
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %read_peer, "S2S read error after {msg_count} messages: {e}");
                    break;
                }
            }
        }
    });

    // Write JSON lines to the peer
    // Phase 2: Sign all non-handshake messages before sending.
    let write_peer = peer_id.clone();
    let write_manager = Arc::clone(&manager);
    let write_handle = tokio::spawn(async move {
        let mut send = send;
        let mut msg_count: u64 = 0;
        while let Some(msg) = write_rx.recv().await {
            // Sign non-handshake messages for non-repudiation
            let msg_to_send = match &msg {
                S2sMessage::Hello { .. }
                | S2sMessage::HelloAck { .. }
                | S2sMessage::Signed { .. }
                | S2sMessage::KeyRotation { .. } => msg,
                _ => write_manager.sign_message(&msg),
            };
            match serde_json::to_string(&msg_to_send) {
                Ok(json) => {
                    msg_count += 1;
                    let line = format!("{json}\n");
                    tracing::debug!(peer = %write_peer, msg_count, "S2S sending: {}", json.chars().take(120).collect::<String>());
                    if let Err(e) = send.write_all(line.as_bytes()).await {
                        tracing::warn!(peer = %write_peer, "S2S write error after {msg_count} messages: {e}");
                        break;
                    }
                    if let Err(e) = send.flush().await {
                        tracing::warn!(peer = %write_peer, "S2S flush error after {msg_count} messages: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %write_peer, "S2S serialize error: {e}");
                }
            }
        }
        tracing::info!(peer = %write_peer, "S2S write channel closed after {msg_count} messages");
        let _ = send.finish();
    });

    // Send Hello handshake — binds transport identity to logical name.
    // The receiver verifies peer_id matches connection's remote_id().
    // Phase 3: Include trust level offered to this peer.
    {
        let trust = manager.get_trust(&peer_id).await;
        let hello = S2sMessage::Hello {
            peer_id: server_id.clone(),
            server_name: server_name.clone(),
            protocol_version: 2, // v2 = signed envelopes + HelloAck
            trust_level: Some(trust.to_string()),
            capabilities: our_capabilities(),
        };
        if let Some(entry) = peers.lock().await.get(&peer_id) {
            let _ = entry.tx.send(hello).await;
        }
    }

    // Both sides send sync request
    {
        let sync_req = S2sMessage::SyncRequest;
        if let Some(entry) = peers.lock().await.get(&peer_id) {
            let _ = entry.tx.send(sync_req).await;
        }
    }

    // Ask for what we missed while the link was down — but only of a peer that
    // said it can answer. A peer that declared nothing warn-and-skips a type
    // it cannot parse, so asking it would be silence dressed as an empty
    // answer. The peer's Hello may not have arrived yet, so this waits briefly
    // for it rather than racing the handshake.
    {
        let manager = Arc::clone(&manager);
        let peer_id = peer_id.clone();
        let server_id = server_id.clone();
        tokio::spawn(async move {
            manager
                .request_catchup_when_supported(&peer_id, &server_id)
                .await;
        });
    }

    // Wait for either direction to end
    let mut read_handle = read_handle;
    let mut write_handle = write_handle;
    let which = tokio::select! {
        _ = &mut read_handle => "read",
        _ = &mut write_handle => "write",
    };
    tracing::warn!(peer = %peer_id, side = which, gen = my_gen, "S2S link ending — {which} task finished first");

    // Only remove peer entry if it's still ours (same generation).
    // A replacement connection may have already inserted a new entry.
    {
        let mut peers_guard = peers.lock().await;
        if let Some(entry) = peers_guard.get(&peer_id) {
            if entry.conn_gen == my_gen {
                peers_guard.remove(&peer_id);
                peer_names.lock().await.remove(&peer_id);
                dedup.remove_peer(&peer_id).await;
                tracing::info!(peer = %peer_id, gen = my_gen, "S2S link closed (entry removed)");

                // Emit PeerDisconnected so the event processor can clean up
                // remote_members for this peer's origin. This prevents ghost
                // users lingering in channel rosters after a link drop.
                let _ = event_tx
                    .send(AuthenticatedS2sEvent {
                        authenticated_peer_id: peer_id.clone(),
                        msg: S2sMessage::PeerDisconnected {
                            peer_id: peer_id.clone(),
                        },
                    })
                    .await;
            } else {
                tracing::info!(
                    peer = %peer_id, my_gen, current_gen = entry.conn_gen,
                    "S2S link closed (entry kept — newer connection exists)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Both sides of a duplicate must choose the same surviving link, or they
    /// trade teardowns until one of them is restarted.
    #[test]
    fn duplicate_links_are_resolved_the_same_way_by_both_servers() {
        let low = "aaaa";
        let high = "bbbb";

        // The low-ID server keeps its outgoing; the high-ID server keeps its
        // incoming. Those are the same connection, seen from the two ends.
        assert!(duplicate_link_wins(low, high, false), "low keeps outgoing");
        assert!(duplicate_link_wins(high, low, true), "high keeps incoming");

        // And each discards the other one — again, one connection, two ends.
        assert!(!duplicate_link_wins(low, high, true), "low drops incoming");
        assert!(
            !duplicate_link_wins(high, low, false),
            "high drops outgoing"
        );
    }

    /// Exactly one of the two ends survives, for any pair of ids in any order.
    #[test]
    fn exactly_one_end_of_a_duplicate_survives() {
        for (a, b) in [("aaa", "bbb"), ("bbb", "aaa"), ("a", "ab"), ("zz", "zza")] {
            // The connection a→b: outgoing at `a`, incoming at `b`.
            let a_to_b = duplicate_link_wins(a, b, false) && duplicate_link_wins(b, a, true);
            // The connection b→a: outgoing at `b`, incoming at `a`.
            let b_to_a = duplicate_link_wins(b, a, false) && duplicate_link_wins(a, b, true);
            assert!(
                a_to_b ^ b_to_a,
                "({a}, {b}): exactly one direction must survive, got a→b={a_to_b} b→a={b_to_a}"
            );
        }
    }

    use super::*;

    #[test]
    fn parse_peer_spec_bare_and_direct() {
        // A real endpoint ID string, derived so we don't hardcode the encoding.
        let id = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let id_str = id.to_string();

        // Bare id → no direct address, id round-trips.
        let (got_id, addr) = parse_peer_spec(&id_str).expect("bare id parses");
        assert_eq!(got_id, id);
        assert_eq!(addr.ip_addrs().count(), 0, "bare spec has no direct addr");

        // id@host:port → same id, one direct address attached.
        let (got_id, addr) =
            parse_peer_spec(&format!("{id_str}@127.0.0.1:9999")).expect("direct spec parses");
        assert_eq!(got_id, id);
        let ips: Vec<_> = addr.ip_addrs().copied().collect();
        assert_eq!(ips, vec!["127.0.0.1:9999".parse().unwrap()]);

        // Malformed pieces are rejected, not silently accepted.
        assert!(parse_peer_spec("not-an-endpoint-id").is_err());
        assert!(parse_peer_spec(&format!("{id_str}@not-a-socket")).is_err());
    }

    #[test]
    fn trust_level_parse() {
        assert_eq!(TrustLevel::parse_level("full"), TrustLevel::Full);
        assert_eq!(TrustLevel::parse_level("relay"), TrustLevel::Relay);
        assert_eq!(TrustLevel::parse_level("readonly"), TrustLevel::Readonly);
        assert_eq!(TrustLevel::parse_level("read-only"), TrustLevel::Readonly);
        assert_eq!(TrustLevel::parse_level("ro"), TrustLevel::Readonly);
        assert_eq!(TrustLevel::parse_level("FULL"), TrustLevel::Full);
        assert_eq!(TrustLevel::parse_level("unknown"), TrustLevel::Full); // default
    }

    #[test]
    fn trust_level_capabilities() {
        assert!(TrustLevel::Full.can_relay());
        assert!(TrustLevel::Full.can_admin());

        assert!(TrustLevel::Relay.can_relay());
        assert!(!TrustLevel::Relay.can_admin());

        assert!(!TrustLevel::Readonly.can_relay());
        assert!(!TrustLevel::Readonly.can_admin());
    }

    #[test]
    fn trust_config_parsing() {
        let entries = vec![
            "abc123:full".to_string(),
            "def456:relay".to_string(),
            "ghi789:readonly".to_string(),
        ];
        let config = parse_trust_config(&entries);
        assert_eq!(config.get("abc123"), Some(&TrustLevel::Full));
        assert_eq!(config.get("def456"), Some(&TrustLevel::Relay));
        assert_eq!(config.get("ghi789"), Some(&TrustLevel::Readonly));
        assert_eq!(config.get("unknown"), None);
    }

    #[test]
    fn trust_config_empty() {
        let config = parse_trust_config(&[]);
        assert!(config.is_empty());
    }

    #[test]
    fn signed_envelope_roundtrip() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();

        let trust_config = HashMap::new();
        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config,
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        // Sign a message
        let msg = S2sMessage::Privmsg {
            event_id: "test:1".to_string(),
            from: "alice!a@b".to_string(),
            target: "#test".to_string(),
            text: "hello world".to_string(),
            origin: server_id.clone(),
            msgid: Some("MSG123".to_string()),
            sig: None,
            account: None,
            recipient_did: None,
            replaces_msgid: None,
            tags: HashMap::new(),
            multiline_lines: None,
        };

        let signed = manager.sign_message(&msg);
        match &signed {
            S2sMessage::Signed {
                payload,
                signature,
                signer,
            } => {
                assert_eq!(signer, &server_id);
                // Verify
                let inner = manager.verify_signed(payload, signature, signer, &server_id);
                assert!(inner.is_some(), "Signature should verify");
                match inner.unwrap() {
                    S2sMessage::Privmsg { text, .. } => assert_eq!(text, "hello world"),
                    _ => panic!("Expected Privmsg"),
                }
            }
            _ => panic!("Expected Signed envelope"),
        }
    }

    #[test]
    fn signed_envelope_rejects_wrong_signer() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let other_secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();
        let other_id = other_secret.public().to_string();

        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        let msg = S2sMessage::SyncRequest;
        let signed = manager.sign_message(&msg);

        match &signed {
            S2sMessage::Signed {
                payload,
                signature,
                signer,
            } => {
                // Verify with wrong authenticated peer ID — should reject
                let result = manager.verify_signed(payload, signature, signer, &other_id);
                assert!(result.is_none(), "Should reject signer mismatch");
            }
            _ => panic!("Expected Signed"),
        }
    }

    #[test]
    fn signed_envelope_rejects_tampered_payload() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();

        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        let msg = S2sMessage::Privmsg {
            event_id: "test:1".to_string(),
            from: "alice!a@b".to_string(),
            target: "#test".to_string(),
            text: "original".to_string(),
            origin: server_id.clone(),
            msgid: None,
            sig: None,
            account: None,
            recipient_did: None,
            replaces_msgid: None,
            tags: HashMap::new(),
            multiline_lines: None,
        };

        let signed = manager.sign_message(&msg);
        match signed {
            S2sMessage::Signed {
                payload: _,
                signature,
                signer,
            } => {
                // Tamper: encode a different payload
                let tampered = S2sMessage::Privmsg {
                    event_id: "test:1".to_string(),
                    from: "alice!a@b".to_string(),
                    target: "#test".to_string(),
                    text: "TAMPERED".to_string(),
                    origin: server_id.clone(),
                    msgid: None,
                    sig: None,
                    account: None,
                    recipient_did: None,
                    replaces_msgid: None,
                    tags: HashMap::new(),
                    multiline_lines: None,
                };
                let tampered_json = serde_json::to_string(&tampered).unwrap();
                let tampered_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(tampered_json.as_bytes());

                let result = manager.verify_signed(&tampered_b64, &signature, &signer, &server_id);
                assert!(result.is_none(), "Should reject tampered payload");
            }
            _ => panic!("Expected Signed"),
        }
    }

    #[test]
    fn key_rotation_roundtrip() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let new_secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();
        let new_id = new_secret.public().to_string();

        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        let rotation = manager.announce_rotation(&new_id);
        match rotation {
            S2sMessage::KeyRotation {
                ref old_id,
                ref new_id,
                timestamp,
                ref signature,
            } => {
                assert!(manager.verify_rotation(old_id, new_id, timestamp, signature, &server_id));
            }
            _ => panic!("Expected KeyRotation"),
        }
    }

    #[test]
    fn key_rotation_rejects_wrong_signer() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let other_secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let new_secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();
        let other_id = other_secret.public().to_string();
        let new_id = new_secret.public().to_string();

        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        let rotation = manager.announce_rotation(&new_id);
        match rotation {
            S2sMessage::KeyRotation {
                ref old_id,
                ref new_id,
                timestamp,
                ref signature,
            } => {
                // Verify with wrong authenticated peer — should reject
                assert!(!manager.verify_rotation(old_id, new_id, timestamp, signature, &other_id));
            }
            _ => panic!("Expected KeyRotation"),
        }
    }

    #[test]
    fn key_rotation_rejects_expired() {
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let new_secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();
        let new_id = new_secret.public().to_string();

        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);

        let manager = S2sManager {
            server_id: server_id.clone(),
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret.clone()),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        // Manually create a rotation with an old timestamp
        let old_timestamp = 1000; // way in the past
        let msg = format!("rotate:{}:{}:{}", server_id, new_id, old_timestamp);
        let sig = secret.sign(msg.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        assert!(!manager.verify_rotation(&server_id, &new_id, old_timestamp, &sig_b64, &server_id));
    }

    #[test]
    fn hello_serialization_with_new_fields() {
        let hello = S2sMessage::Hello {
            peer_id: "abc123".to_string(),
            server_name: "test-server".to_string(),
            protocol_version: 2,
            trust_level: Some("full".to_string()),
            capabilities: our_capabilities(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("protocol_version"));
        assert!(json.contains("trust_level"));

        // Verify backward compat: old Hello without new fields still parses
        let old_json = r#"{"type":"hello","peer_id":"abc","server_name":"old"}"#;
        let parsed: S2sMessage = serde_json::from_str(old_json).unwrap();
        match parsed {
            S2sMessage::Hello {
                protocol_version,
                trust_level,
                ..
            } => {
                assert_eq!(protocol_version, 0); // default
                assert!(trust_level.is_none()); // default
            }
            _ => panic!("Expected Hello"),
        }
    }

    #[test]
    fn hello_ack_serialization() {
        let ack = S2sMessage::HelloAck {
            peer_id: "abc123".to_string(),
            accepted: true,
            trust_level: Some("relay".to_string()),
        };
        let json = serde_json::to_string(&ack).unwrap();
        let parsed: S2sMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            S2sMessage::HelloAck {
                accepted,
                trust_level,
                ..
            } => {
                assert!(accepted);
                assert_eq!(trust_level.as_deref(), Some("relay"));
            }
            _ => panic!("Expected HelloAck"),
        }
    }

    #[test]
    fn signed_envelope_serialization() {
        let signed = S2sMessage::Signed {
            payload: "dGVzdA".to_string(),
            signature: "c2ln".to_string(),
            signer: "abc123".to_string(),
        };
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains(r#""type":"signed""#));
        let parsed: S2sMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            S2sMessage::Signed { payload, .. } => assert_eq!(payload, "dGVzdA"),
            _ => panic!("Expected Signed"),
        }
    }

    #[test]
    fn dedup_set_basic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dedup = DedupSet::new();
            assert!(dedup.check_and_insert("peer1", "peer1:100").await);
            assert!(!dedup.check_and_insert("peer1", "peer1:100").await); // duplicate
            assert!(!dedup.check_and_insert("peer1", "peer1:50").await); // below high water
            assert!(dedup.check_and_insert("peer1", "peer1:200").await); // new
            assert!(dedup.check_and_insert("peer2", "peer2:50").await); // different peer
        });
    }

    #[test]
    fn encode_privmsg_text_for_s2s_passes_single_line_through() {
        let (text, tags) = encode_privmsg_text_for_s2s("hello world", HashMap::new());
        assert_eq!(text, "hello world");
        assert!(!tags.contains_key("+freeq.at/multiline"));
    }

    #[test]
    fn encode_privmsg_text_for_s2s_escapes_multiline_and_sets_tag() {
        let (text, tags) =
            encode_privmsg_text_for_s2s("line one\nline two\nline three", HashMap::new());
        // Wire-safe: no literal `\n` after escape
        assert!(
            !text.contains('\n'),
            "escaped text must not contain literal \\n"
        );
        assert_eq!(text, "line one\\nline two\\nline three");
        // Tag set so receivers can decode on render
        assert!(tags.contains_key("+freeq.at/multiline"));
    }

    #[test]
    fn encode_privmsg_text_for_s2s_preserves_existing_coordination_tags() {
        let mut existing = HashMap::new();
        existing.insert("+freeq.at/event".to_string(), "reveal".to_string());
        existing.insert("+freeq.at/payload".to_string(), "%7B%7D".to_string());
        let (_text, tags) = encode_privmsg_text_for_s2s("a\nb", existing);
        assert_eq!(
            tags.get("+freeq.at/event").map(String::as_str),
            Some("reveal")
        );
        assert_eq!(
            tags.get("+freeq.at/payload").map(String::as_str),
            Some("%7B%7D")
        );
        assert!(tags.contains_key("+freeq.at/multiline"));
    }

    /// The federation skew invariant: a peer that DOESN'T understand
    /// `multiline_lines` (e.g. pre-Phase-4c) still receives a wire-safe
    /// `text` field — relaying it to its local clients produces ONE
    /// PRIVMSG with literal `\\n` and a tag, NOT a broken multi-line
    /// PRIVMSG that splits across IRC line framing.
    #[test]
    fn encode_privmsg_text_for_s2s_keeps_old_peer_safe() {
        let body = "a\nb\nc";
        let (text, tags) = encode_privmsg_text_for_s2s(body, HashMap::new());
        // Simulate the old peer's relay: it ignores any unknown fields,
        // builds a PRIVMSG with `text`, writes to a TCP socket. The bytes
        // it writes must NOT contain `\n` mid-body or the IRC parser at
        // the recipient breaks framing.
        let bytes = format!(":sender PRIVMSG #room :{text}\r\n");
        let body_bytes = bytes
            .strip_prefix(":sender PRIVMSG #room :")
            .unwrap()
            .strip_suffix("\r\n")
            .unwrap();
        assert!(
            !body_bytes.contains('\n'),
            "old peer's wire bytes would contain literal \\n — wire is broken!"
        );
        // And the tag is there so the old peer's freeq-aware clients
        // know to decode on render.
        assert!(tags.contains_key("+freeq.at/multiline"));
    }

    /// A signed message covers what it replies to, so the reply reference has
    /// to survive the hop or the receiving server rebuilds a different
    /// document and reads an honest reply as tampering. Both client spellings
    /// cross under the canonical one.
    #[test]
    fn relay_coordination_tags_carry_the_reply_reference() {
        for spelling in ["+reply", "+draft/reply"] {
            let mut full = HashMap::new();
            full.insert(spelling.to_string(), "01ROOTMSGID".to_string());
            let relayed = relay_coordination_tags(&full);
            assert_eq!(
                relayed.get("+reply").map(String::as_str),
                Some("01ROOTMSGID"),
                "{spelling} must cross S2S as +reply"
            );
        }

        // A message that replies to nothing gains no reply tag.
        let relayed = relay_coordination_tags(&HashMap::from([(
            "+freeq.at/event".to_string(),
            "x".to_string(),
        )]));
        assert!(!relayed.contains_key("+reply"));
    }

    #[test]
    fn relay_coordination_tags_keeps_app_drops_server_controlled() {
        let mut full = HashMap::new();
        full.insert("+freeq.at/event".to_string(), "task_request".to_string());
        full.insert("+freeq.at/payload".to_string(), "%7B%7D".to_string());
        full.insert("+freeq.at/task-id".to_string(), "01HZ".to_string());
        full.insert(
            "+freeq.at/evidence-type".to_string(),
            "code_review".to_string(),
        );
        // server-controlled / non-app — must NOT cross via the tags field:
        full.insert("+freeq.at/sig".to_string(), "deadbeef".to_string());
        full.insert("account".to_string(), "did:plc:x".to_string());
        full.insert("time".to_string(), "2026-05-15T00:00:00Z".to_string());
        full.insert("msgid".to_string(), "01HZMSGID".to_string());

        let relayed = relay_coordination_tags(&full);

        assert_eq!(
            relayed.get("+freeq.at/event").map(String::as_str),
            Some("task_request")
        );
        assert_eq!(
            relayed.get("+freeq.at/payload").map(String::as_str),
            Some("%7B%7D")
        );
        assert_eq!(
            relayed.get("+freeq.at/task-id").map(String::as_str),
            Some("01HZ")
        );
        assert_eq!(
            relayed.get("+freeq.at/evidence-type").map(String::as_str),
            Some("code_review")
        );
        assert!(
            !relayed.contains_key("+freeq.at/sig"),
            "sig is re-attested out-of-band"
        );
        assert!(
            !relayed.contains_key("account"),
            "account injected per-recipient locally"
        );
        assert!(!relayed.contains_key("time"));
        assert!(
            !relayed.contains_key("msgid"),
            "msgid carried in its own field"
        );
        assert_eq!(relayed.len(), 4);
    }

    #[test]
    fn privmsg_tags_serde_roundtrip_and_backcompat() {
        // Round-trip: tags survive serialize → deserialize.
        let mut tags = HashMap::new();
        tags.insert("+freeq.at/event".to_string(), "task_complete".to_string());
        let msg = S2sMessage::Privmsg {
            event_id: "p:1".to_string(),
            from: "swarm!u@h".to_string(),
            target: "#swarm".to_string(),
            text: "done".to_string(),
            origin: "peerA".to_string(),
            msgid: Some("01HZ".to_string()),
            sig: None,
            account: None,
            recipient_did: None,
            replaces_msgid: None,
            tags: tags.clone(),
            multiline_lines: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        match serde_json::from_str::<S2sMessage>(&json).unwrap() {
            S2sMessage::Privmsg { tags: rt, .. } => assert_eq!(rt, tags),
            _ => panic!("expected Privmsg"),
        }

        // Back-compat: a peer on the old wire format omits `tags` entirely.
        let old = r##"{"type":"privmsg","event_id":"p:2","from":"a!u@h","target":"#c","text":"hi","origin":"peerB"}"##;
        match serde_json::from_str::<S2sMessage>(old).unwrap() {
            S2sMessage::Privmsg {
                tags,
                msgid,
                sig,
                account,
                ..
            } => {
                assert!(tags.is_empty(), "missing tags → empty via serde default");
                assert!(msgid.is_none());
                assert!(sig.is_none());
                assert!(
                    account.is_none(),
                    "missing account → None via serde default"
                );
            }
            _ => panic!("expected Privmsg"),
        }
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    /// Every registered capability is actually consulted somewhere. A name
    /// nobody checks gates nothing, and a list full of those is exactly the
    /// rot this registry is meant to prevent — so it fails the build rather
    /// than sitting there looking authoritative.
    ///
    /// Checked by source inspection because that is where the marriage lives:
    /// the constant has to be *named* at a send site, not merely exist.
    #[test]
    fn every_registered_capability_gates_a_real_send_site() {
        let sources = [include_str!("s2s.rs"), include_str!("server.rs")];
        for cap in CAPABILITIES {
            // The const identifier, not the wire string: call sites use the
            // constant, which is what makes a typo a compile error.
            let ident = cap.name.to_uppercase();
            let uses: usize = sources
                .iter()
                .map(|src| {
                    src.matches(&format!("peer_supports(&declared, {ident})"))
                        .count()
                        + src
                            .matches(&format!("peer_supports(caps, {ident})"))
                            .count()
                })
                .sum();
            assert!(
                uses > 0,
                "capability `{}` is registered but no send site is gated on it — \
                 either gate something or delete the entry ({})",
                cap.name,
                cap.gates
            );
        }
    }

    /// …and nothing gates on a string literal, which would drift silently.
    #[test]
    fn no_send_site_gates_on_a_bare_string() {
        for src in [include_str!("s2s.rs"), include_str!("server.rs")] {
            for cap in CAPABILITIES {
                let literal = format!("peer_supports(&declared, \"{}\"", cap.name);
                assert!(
                    !src.contains(&literal),
                    "gate on the registry constant, not the literal `{}`",
                    cap.name
                );
            }
        }
    }

    /// Captures what the code under test logs, so a test can assert a skip
    /// was loud. Cloned handles share one buffer.
    #[derive(Clone, Default)]
    struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> LogSink {
            self.clone()
        }
    }

    /// The act gate itself: a task-tagged Tagmsg reaches only peers that
    /// declared [`ACT`]; every other message — the companion plain-text line
    /// included — still reaches every peer, and each withheld send is logged
    /// naming the peer and the event, so a wrong declaration never fails
    /// silent.
    ///
    /// The federation harness cannot stage the withheld half end to end —
    /// both of its servers run this build and declare every capability — so
    /// this is where that half is pinned.
    #[tokio::test]
    async fn a_task_event_is_withheld_from_a_peer_that_did_not_declare_act() {
        let sink = LogSink::default();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(sink.clone())
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id = secret.public().to_string();
        let (broadcast_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);
        let manager = S2sManager {
            server_id,
            server_name: "test".to_string(),
            peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_names: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_tx,
            event_counter: AtomicU64::new(0),
            dedup: Arc::new(DedupSet::new()),
            broadcast_tx,
            conn_gen: Arc::new(AtomicU64::new(0)),
            signing_key: Arc::new(secret),
            trust_config: HashMap::new(),
            pending_rotations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            authenticated_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            peer_capabilities: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            allowed_peers: Vec::new(),
        };

        let (cap_tx, mut cap_rx) = mpsc::channel(8);
        let (plain_tx, mut plain_rx) = mpsc::channel(8);
        {
            let mut peers = manager.peers.lock().await;
            peers.insert(
                "cap-peer".into(),
                PeerEntry {
                    tx: cap_tx,
                    conn_gen: 0,
                },
            );
            peers.insert(
                "plain-peer".into(),
                PeerEntry {
                    tx: plain_tx,
                    conn_gen: 0,
                },
            );
        }
        {
            let mut caps = manager.peer_capabilities.lock().await;
            caps.insert("cap-peer".into(), vec![ACT.to_string()]);
            // Declared something, just not `act` — an older build.
            caps.insert("plain-peer".into(), vec![CATCHUP.to_string()]);
        }

        let tagmsg = |event_id: &str, tag: (&str, &str)| S2sMessage::Tagmsg {
            event_id: event_id.to_string(),
            from: "eliza!e@h".to_string(),
            target: "#ops".to_string(),
            tags: HashMap::from([(tag.0.to_string(), tag.1.to_string())]),
            origin: "srv".to_string(),
            account: None,
        };

        manager
            .broadcast_to_peers(tagmsg("srv:1", ("+freeq.at/act", "handoff")))
            .await;
        assert!(
            matches!(cap_rx.try_recv(), Ok(S2sMessage::Tagmsg { .. })),
            "a peer that declared act receives the task event"
        );
        assert!(
            plain_rx.try_recv().is_err(),
            "a peer that did not declare act is not sent the task event"
        );
        let logged = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(
            logged.contains("task event withheld")
                && logged.contains("plain-peer")
                && logged.contains("srv:1"),
            "the skip must be logged naming the peer and the event, got: {logged}"
        );

        // An ordinary tag message — a reaction — is not narrowed.
        manager
            .broadcast_to_peers(tagmsg("srv:2", ("+react", "👍")))
            .await;
        assert!(matches!(cap_rx.try_recv(), Ok(S2sMessage::Tagmsg { .. })));
        assert!(
            matches!(plain_rx.try_recv(), Ok(S2sMessage::Tagmsg { .. })),
            "an ordinary tag message still reaches every peer"
        );

        // The companion plain-text line a task sender posts alongside is an
        // ordinary message: it reaches the peer the task event was withheld
        // from.
        manager
            .broadcast_to_peers(S2sMessage::Privmsg {
                event_id: "srv:3".to_string(),
                from: "eliza!e@h".to_string(),
                target: "#ops".to_string(),
                text: "offered: cross-the-hop".to_string(),
                origin: "srv".to_string(),
                msgid: Some("M1".to_string()),
                sig: None,
                account: None,
                recipient_did: None,
                replaces_msgid: None,
                tags: HashMap::new(),
                multiline_lines: None,
            })
            .await;
        assert!(matches!(cap_rx.try_recv(), Ok(S2sMessage::Privmsg { .. })));
        assert!(
            matches!(plain_rx.try_recv(), Ok(S2sMessage::Privmsg { .. })),
            "the companion plain-text message still reaches a peer without act"
        );
    }

    /// A peer that declared nothing supports nothing. This is the rollout
    /// constraint in one line: a frozen peer's Hello has no capability field,
    /// deserializes to empty, and is therefore never sent a new message type.
    #[test]
    fn a_peer_that_declared_nothing_supports_nothing() {
        assert!(!peer_supports(&[], CATCHUP));
        assert!(peer_supports(&[CATCHUP.to_string()], CATCHUP));
        assert!(
            !peer_supports(&["something-else".to_string()], CATCHUP),
            "and declaring one thing is not declaring another"
        );
    }

    /// Parameters attach as `name=value` without changing the name, so a
    /// capability can gain them later without a peer's declaration becoming
    /// unreadable.
    #[test]
    fn a_parameterised_declaration_still_names_its_capability() {
        assert!(peer_supports(&[format!("{CATCHUP}=window:3600")], CATCHUP));
        assert!(
            !peer_supports(&[format!("{CATCHUP}x")], CATCHUP),
            "and a longer name is a different capability, not this one"
        );
    }

    /// A Hello from a peer that predates the field parses, and declares
    /// nothing — the wire back-compat this whole design rests on.
    #[test]
    fn a_legacy_hello_parses_and_declares_nothing() {
        let legacy = r#"{"type":"hello","peer_id":"abc","server_name":"old",
                         "protocol_version":2,"trust_level":"full"}"#;
        match serde_json::from_str::<S2sMessage>(legacy).expect("a legacy Hello still parses") {
            S2sMessage::Hello { capabilities, .. } => {
                assert!(capabilities.is_empty(), "no field means no declaration");
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    /// Our own Hello carries the list, and omits it entirely when empty so a
    /// peer's parser never sees a field it has no need for.
    #[test]
    fn our_hello_declares_what_we_can_receive() {
        let hello = S2sMessage::Hello {
            peer_id: "us".to_string(),
            server_name: "ours".to_string(),
            protocol_version: 2,
            trust_level: None,
            capabilities: our_capabilities(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains(CATCHUP), "{json}");
    }

    /// A catch-up reply round-trips, and does not carry the answering peer's
    /// verdict — only the evidence, so the receiver reaches its own.
    #[test]
    fn a_replayed_event_carries_evidence_and_not_a_verdict() {
        let ev = ReplayedEvent {
            event_id: "01REPLAY000000000000000000".to_string(),
            canonical: r##"{"body":"sha256:aa","from":"did:plc:x","msgid":"01REPLAY000000000000000000","target":"#room"}"##.to_string(),
            signature: Some("ed25519:kid:sig".to_string()),
            kind: "message".to_string(),
            venue: "#room".to_string(),
            actor_did: Some("did:plc:x".to_string()),
            subject: None,
            emoji: None,
            origin: "minting-server".to_string(),
            timestamp: 42,
        };
        let json = serde_json::to_string(&S2sMessage::CatchupEvents {
            origin: "peer".to_string(),
            events: vec![ev.clone()],
            more: false,
        })
        .unwrap();
        assert!(
            !json.contains("sig_state"),
            "a peer's conclusion is not evidence: {json}"
        );
        match serde_json::from_str::<S2sMessage>(&json).unwrap() {
            S2sMessage::CatchupEvents { events, .. } => assert_eq!(events, vec![ev]),
            other => panic!("expected CatchupEvents, got {other:?}"),
        }
    }

    /// The per-event origin is additive on the wire in both directions, which
    /// is what lets it ship without a new capability name.
    ///
    /// A peer that predates the field sends a batch without it and reads a
    /// batch containing it: serde fills the missing field from `default` and
    /// ignores the unknown one, so neither end sees a parse error. The
    /// fallback for an absent value is the batch-level origin, which is
    /// precisely the behaviour that peer already had.
    #[test]
    fn a_catchup_batch_from_an_older_peer_still_parses() {
        // Exactly what a build without the field emits.
        let older = r##"{"type":"catchup_events","origin":"peer","events":[{
            "event_id":"01OLD00000000000000000000",
            "canonical":"",
            "signature":null,
            "kind":"message",
            "venue":"#room",
            "actor_did":"did:plc:x",
            "subject":null,
            "emoji":null,
            "timestamp":42}],"more":false}"##;
        match serde_json::from_str::<S2sMessage>(older).unwrap() {
            S2sMessage::CatchupEvents { origin, events, .. } => {
                assert_eq!(origin, "peer");
                assert_eq!(
                    events[0].origin, "",
                    "an absent per-event origin reads as unset, not as a claim"
                );
            }
            other => panic!("expected CatchupEvents, got {other:?}"),
        }

        // And a batch carrying a field an older build never heard of parses
        // there too — nothing on this type refuses unknown fields.
        let newer = r##"{"type":"catchup_events","origin":"peer","events":[{
            "event_id":"01NEW00000000000000000000",
            "kind":"message","venue":"#room","timestamp":42,
            "origin":"minting-server",
            "some_field_from_the_future":"ignored"}],"more":false}"##;
        match serde_json::from_str::<S2sMessage>(newer).unwrap() {
            S2sMessage::CatchupEvents { events, .. } => {
                assert_eq!(events[0].origin, "minting-server");
            }
            other => panic!("expected CatchupEvents, got {other:?}"),
        }
    }
}
