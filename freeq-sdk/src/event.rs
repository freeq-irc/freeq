//! Events emitted by the IRC client for the UI layer to consume.

/// Events that the SDK emits to the consumer (TUI, GUI, bot, etc.)
#[derive(Debug, Clone)]
pub enum Event {
    /// Successfully connected to the server.
    Connected,

    /// IRC registration complete. `nick` is our confirmed nick.
    Registered {
        nick: String,
    },

    /// SASL authentication result.
    Authenticated {
        did: String,
    },
    AuthFailed {
        reason: String,
    },

    /// Joined a channel.
    Joined {
        channel: String,
        nick: String,
        /// Extended-join account — the joiner's DID (`did:plc:…` / `did:key:…`),
        /// or `None` when unauthenticated. Lets a consumer resolve who joined
        /// to their real identity (e.g. DID → Bluesky handle).
        account: Option<String>,
    },

    /// Someone left a channel.
    Parted {
        channel: String,
        nick: String,
    },

    /// A message in a channel or private message.
    Message {
        from: String,
        target: String,
        text: String,
        /// IRCv3 message tags (empty if none).
        tags: std::collections::HashMap<String, String>,
        /// For a DM: the canonical conversation key — the peer's DID when
        /// known, else their nick (`address::dm_peer_key`). `None` for
        /// channel messages. Direction-independent: our echo and the peer's
        /// reply carry the same value, so one person is one thread. Assumes
        /// one authenticated identity per client session (a multi-account
        /// consumer must namespace its stores per account).
        dm_key: Option<String>,
    },

    /// A TAGMSG (tags only, no body) — used for reactions, typing indicators, etc.
    TagMsg {
        from: String,
        target: String,
        tags: std::collections::HashMap<String, String>,
        /// Same as [`Event::Message::dm_key`]: the DM conversation key,
        /// `None` for channels.
        dm_key: Option<String>,
    },

    /// A task event: a TAGMSG carrying `act` tags, already read.
    ///
    /// The line still arrives as [`Event::TagMsg`] too, the way a coordination
    /// TAGMSG does — this variant is the parse, not a replacement for the
    /// message. A consumer that renders task cards listens here; one that
    /// wants the raw tags has them either way.
    ///
    /// Emitted once per event id. The same event arrives up to three times —
    /// our own echo, the replay a channel hands a joiner, and the history that
    /// joiner asks for next — and the second and third sightings are dropped.
    Act {
        from: String,
        target: String,
        /// The task kind — the `act` tag's value, e.g. `handoff`.
        kind: String,
        /// The move: `offer`, `claim`, `progress`, `confirm`, …
        verb: String,
        /// The acting identity: the `from` tag, else the server's `account`.
        did: Option<String>,
        /// The signer-minted id of this event.
        event_id: String,
        /// The action this event is about — the one it names, or its own id
        /// when it names none, because an opener's id *is* the action's.
        task_id: String,
        /// Every act tag, keyed by its name with the vendor prefix stripped.
        /// Exactly what the signature covers.
        fields: std::collections::BTreeMap<String, String>,
        /// The signature over the act document, if the line carried one.
        sig_tag: Option<String>,
        /// True when this arrived from history rather than live.
        replayed: bool,
        /// Same as [`Event::Message::dm_key`]: the DM conversation key,
        /// `None` for channels.
        dm_key: Option<String>,
    },

    /// BATCH start (e.g., chathistory)
    BatchStart {
        id: String,
        batch_type: String,
        target: String,
    },

    /// BATCH end
    BatchEnd {
        id: String,
    },

    /// A DM conversation target from CHATHISTORY TARGETS.
    /// `nick` is the display nick of the conversation partner.
    /// `timestamp` is the ISO 8601 time of the last message (from server-time tag).
    ChatHistoryTarget {
        nick: String,
        timestamp: Option<String>,
        /// The partner's DID from the server's `freeq.at/partner-did` tag —
        /// the conversation's stable identity (key threads by this, not the
        /// display nick). `None` from servers that don't send the tag.
        partner_did: Option<String>,
    },

    /// A nick↔DID binding was learned (extended-join, WHOIS, or a message's
    /// account tag). Consumers should fold any nick-keyed DM thread for
    /// `nick` into the DID-keyed one — a cold first DM keys by nick until
    /// the peer's identity is learned here. Emitted only when the binding
    /// is new or changed.
    MemberDid {
        nick: String,
        did: String,
    },

    /// NAMES list for a channel (one 353 reply; may arrive in multiple parts).
    Names {
        channel: String,
        nicks: Vec<String>,
    },

    /// End of NAMES list (366).
    NamesEnd {
        channel: String,
    },

    /// Channel mode changed.
    ModeChanged {
        channel: String,
        mode: String,
        arg: Option<String>,
        set_by: String,
    },

    /// Someone was kicked from a channel.
    Kicked {
        channel: String,
        nick: String,
        by: String,
        reason: String,
    },

    /// A user's AWAY status changed (via away-notify cap).
    /// `away_msg` is Some("reason") when going away, None when coming back.
    AwayChanged {
        nick: String,
        away_msg: Option<String>,
    },

    /// A user changed nick.
    NickChanged {
        old_nick: String,
        new_nick: String,
    },

    /// A read marker was set or reported for a target (IRCv3
    /// `draft/read-marker`). Emitted both as the reply to our own
    /// `mark_read`/`get_read_marker` and when another of our devices advances
    /// the marker. `timestamp` is `Some(iso)` (ISO 8601, as in server-time) or
    /// `None` when the server reports no marker (`MARKREAD <target> *`).
    ReadMarker {
        target: String,
        timestamp: Option<String>,
    },

    /// We were invited to a channel.
    Invited {
        channel: String,
        by: String,
    },

    /// Channel topic changed or received on join.
    TopicChanged {
        channel: String,
        topic: String,
        set_by: Option<String>,
    },

    /// WHOIS response line (numeric code + text).
    WhoisReply {
        nick: String,
        info: String,
    },

    /// The server has finished answering a WHOIS.
    ///
    /// The reason this exists: every other WHOIS event reports something the
    /// server found. Only this one reports that it has nothing more to say,
    /// which is the difference between "this person has no account" and "the
    /// answer hasn't arrived yet". Without it a caller can only guess with a
    /// timer, and a timer long enough to be safe is long enough to be seen.
    WhoisEnd {
        nick: String,
    },

    /// Server sent an error or notice.
    ServerNotice {
        text: String,
    },

    /// Someone quit the server.
    UserQuit {
        nick: String,
        reason: String,
    },

    /// Connection was closed.
    Disconnected {
        reason: String,
    },

    /// Raw server line (for debugging).
    RawLine(String),
}
