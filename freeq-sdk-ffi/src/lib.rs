//! FFI wrapper around freeq-sdk for Swift/Kotlin consumption via UniFFI.

use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};

/// Install a tracing subscriber that writes to stderr the first time anyone
/// touches the SDK. iOS captures this in the Xcode console pane while
/// debugging — invaluable for triaging connect-path hangs. Idempotent: a
/// second install is a no-op.
fn install_tracing_subscriber() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("freeq_sdk=debug,freeq_sdk_ffi=debug,info")
                }),
            )
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_ansi(false)
            .try_init();
    });
}

static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    install_tracing_subscriber();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("Failed to create tokio runtime")
});

uniffi::include_scaffolding!("freeq");

// ── Types (must match UDL exactly) ──

/// The identity-claim rule, passed through unchanged from the SDK — see
/// `freeq_sdk::identity_claim` and `spec/identity-claims.json`. The FFI layer
/// converts owned strings to the SDK's borrowed inputs and copies the finished
/// claim back out; it adds no logic, so the vectors that pin the SDK pin this
/// surface too.
pub enum IdentityClaimState {
    AtProtocol,
    SelfIssued,
    Relayed,
    Guest,
    LookingUp,
    Unknown,
}

pub enum PersonLookup {
    NotAsked,
    InFlight,
    NoAccount,
    NoSuchNick,
    TimedOut,
}

pub struct MessageClaimInput {
    pub account: Option<String>,
    pub origin: Option<String>,
    pub sender_present: bool,
    pub sender_live_did: Option<String>,
    pub row_time_unix: Option<u64>,
}

pub struct PersonClaimInput {
    pub binding: Option<String>,
    pub seen_only_via_peer: bool,
    pub via_peer_origin: Option<String>,
    pub via_peer_had_account: bool,
    pub lookup: PersonLookup,
}

pub struct IdentityClaim {
    pub state: IdentityClaimState,
    pub did: Option<String>,
    pub origin: Option<String>,
    pub label: Option<String>,
    pub line: Option<String>,
    pub shows_mark: bool,
    pub is_pending: bool,
    pub needs_key_card: bool,
}

impl From<freeq_sdk::identity_claim::IdentityClaim> for IdentityClaim {
    fn from(c: freeq_sdk::identity_claim::IdentityClaim) -> Self {
        use freeq_sdk::identity_claim::IdentityClaimState as S;
        Self {
            state: match c.state {
                S::AtProtocol => IdentityClaimState::AtProtocol,
                S::SelfIssued => IdentityClaimState::SelfIssued,
                S::Relayed => IdentityClaimState::Relayed,
                S::Guest => IdentityClaimState::Guest,
                S::LookingUp => IdentityClaimState::LookingUp,
                S::Unknown => IdentityClaimState::Unknown,
            },
            did: c.did,
            origin: c.origin,
            label: c.label,
            line: c.line,
            shows_mark: c.shows_mark,
            is_pending: c.is_pending,
            needs_key_card: c.needs_key_card,
        }
    }
}

impl PersonLookup {
    fn to_sdk(&self) -> freeq_sdk::identity_claim::PersonLookup {
        use freeq_sdk::identity_claim::PersonLookup as L;
        match self {
            PersonLookup::NotAsked => L::NotAsked,
            PersonLookup::InFlight => L::InFlight,
            PersonLookup::NoAccount => L::NoAccount,
            PersonLookup::NoSuchNick => L::NoSuchNick,
            PersonLookup::TimedOut => L::TimedOut,
        }
    }
}

pub fn claim_for_message(input: MessageClaimInput) -> IdentityClaim {
    freeq_sdk::identity_claim::claim_for_message(&freeq_sdk::identity_claim::MessageClaimInput {
        account: input.account.as_deref(),
        origin: input.origin.as_deref(),
        sender_present: input.sender_present,
        sender_live_did: input.sender_live_did.as_deref(),
        row_time_unix: input.row_time_unix,
    })
    .into()
}

pub fn claim_for_person(input: PersonClaimInput) -> IdentityClaim {
    freeq_sdk::identity_claim::claim_for_person(&freeq_sdk::identity_claim::PersonClaimInput {
        binding: input.binding.as_deref(),
        seen_only_via_peer: input.seen_only_via_peer,
        via_peer_origin: input.via_peer_origin.as_deref(),
        via_peer_had_account: input.via_peer_had_account,
        lookup: input.lookup.to_sdk(),
    })
    .into()
}

pub fn claim_for_sender(input: MessageClaimInput, lookup: PersonLookup) -> IdentityClaim {
    freeq_sdk::identity_claim::claim_for_sender(
        &freeq_sdk::identity_claim::MessageClaimInput {
            account: input.account.as_deref(),
            origin: input.origin.as_deref(),
            sender_present: input.sender_present,
            sender_live_did: input.sender_live_did.as_deref(),
            row_time_unix: input.row_time_unix,
        },
        lookup.to_sdk(),
    )
    .into()
}

pub fn identity_stamping_epoch_unix() -> u64 {
    freeq_sdk::identity_claim::stamping_epoch_unix()
}

pub struct IrcMessage {
    pub from_nick: String,
    pub target: String,
    pub text: String,
    pub msgid: Option<String>,
    pub reply_to: Option<String>,
    pub replaces_msgid: Option<String>,
    pub edit_of: Option<String>,
    pub batch_id: Option<String>,
    pub pin_msgid: Option<String>,
    pub unpin_msgid: Option<String>,
    pub is_action: bool,
    pub is_signed: bool,
    pub timestamp_ms: i64,
    pub account: Option<String>,
    /// Origin server name when this message was relayed from a federated
    /// peer (the `+freeq.at/origin` tag). `None` for locally-originated
    /// messages. Clients use it to distinguish a peer-vouched identity
    /// ("via {origin}") from one this server verified — and must not show a
    /// federated message as locally verified/signed.
    pub origin: Option<String>,
    /// Persisted reactions delivered on the message itself via the
    /// server's `+freeq.at/reactions` tag (CHATHISTORY / JOIN replay).
    /// Live reactions still arrive as separate `TagMsg` events.
    pub reactions: Vec<ReactionTally>,
    /// This message has been edited since it was sent.
    ///
    /// A live edit is recognizable from `edit_of`, but join replay collapses
    /// every revision into one row and sends no `+draft/edit` — so without
    /// the server's `+freeq.at/edited` tag (which this reads), a message
    /// edited before you joined renders as though it were the original.
    pub edited: bool,
    /// For a DM: the canonical conversation key — the peer's DID when known,
    /// else their nick. `None` for channel messages. Key DM threads by this,
    /// not by from/target (which flip with message direction).
    pub dm_key: Option<String>,
    /// Present when this message carries an agent coordination event
    /// (`+freeq.at/event` + friends). Clients render it as a structured
    /// task/evidence card instead of plain text (parity with the web
    /// `CoordinationCards`); a tag-unaware view still shows `text`.
    pub coordination: Option<CoordinationEvent>,
}

/// A parsed agent coordination event (the `+freeq.at/*` task tag family).
pub struct CoordinationEvent {
    pub event_type: String,
    pub task_id: Option<String>,
    pub phase: Option<String>,
    pub evidence_type: Option<String>,
    pub reference: Option<String>,
    pub payload: Option<String>,
}

pub struct ReactionTally {
    pub emoji: String,
    pub nicks: Vec<String>,
}

/// Parse the server's `+freeq.at/reactions` value
/// (`emoji1:nick1,nick2;emoji2:nick3`) into structured tallies.
/// Malformed segments are skipped.
fn parse_reactions_tag(raw: &str) -> Vec<ReactionTally> {
    raw.split(';')
        .filter_map(|seg| {
            let (emoji, nicks) = seg.split_once(':')?;
            let emoji = emoji.trim();
            if emoji.is_empty() {
                return None;
            }
            let nicks: Vec<String> = nicks
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .collect();
            if nicks.is_empty() {
                return None;
            }
            Some(ReactionTally {
                emoji: emoji.to_string(),
                nicks,
            })
        })
        .collect()
}

pub struct TagEntry {
    pub key: String,
    pub value: String,
}

pub struct TagMessage {
    pub from: String,
    pub target: String,
    pub tags: Vec<TagEntry>,
    pub dm_key: Option<String>,
}

pub struct IrcMember {
    pub nick: String,
    pub is_op: bool,
    pub is_halfop: bool,
    pub is_voiced: bool,
    pub away_msg: Option<String>,
}

pub struct ChannelTopic {
    pub text: String,
    pub set_by: Option<String>,
}

pub enum FreeqEvent {
    Connected,
    Registered {
        nick: String,
    },
    Authenticated {
        did: String,
    },
    AuthFailed {
        reason: String,
    },
    Joined {
        channel: String,
        nick: String,
    },
    Parted {
        channel: String,
        nick: String,
    },
    NickChanged {
        old_nick: String,
        new_nick: String,
    },
    AwayChanged {
        nick: String,
        away_msg: Option<String>,
    },
    Message {
        msg: IrcMessage,
    },
    TagMsg {
        msg: TagMessage,
    },
    Names {
        channel: String,
        members: Vec<IrcMember>,
    },
    TopicChanged {
        channel: String,
        topic: ChannelTopic,
    },
    ModeChanged {
        channel: String,
        mode: String,
        arg: Option<String>,
        set_by: String,
    },
    Kicked {
        channel: String,
        nick: String,
        by: String,
        reason: String,
    },
    UserQuit {
        nick: String,
        reason: String,
    },
    BatchStart {
        id: String,
        batch_type: String,
        target: String,
    },
    BatchEnd {
        id: String,
    },
    ChatHistoryTarget {
        nick: String,
        timestamp: Option<String>,
        /// The conversation's stable identity (`freeq.at/partner-did` tag).
        partner_did: Option<String>,
    },
    /// A nick↔DID binding was learned; merge any nick-keyed DM thread for
    /// `nick` into the DID-keyed one. Emitted only for new/changed bindings.
    MemberDid {
        nick: String,
        did: String,
    },
    ReadMarker {
        target: String,
        timestamp: Option<String>,
    },
    WhoisReply {
        nick: String,
        info: String,
    },
    /// The server has finished answering a WHOIS for this nick. A surface
    /// waiting to learn whether someone has an account settles here.
    WhoisEnd {
        nick: String,
    },
    Notice {
        text: String,
    },
    Disconnected {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FreeqError {
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Not connected")]
    NotConnected,
    #[error("Send failed")]
    SendFailed,
    #[error("Invalid argument")]
    InvalidArgument,
}

pub trait EventHandler: Send + Sync + 'static {
    fn on_event(&self, event: FreeqEvent);
}

// ── Client ──

pub struct FreeqClient {
    server: String,
    nick: Arc<Mutex<String>>,
    handler: Arc<dyn EventHandler>,
    handle: Arc<Mutex<Option<freeq_sdk::client::ClientHandle>>>,
    connected: Arc<Mutex<bool>>,
    web_token: Arc<Mutex<Option<String>>>,
    platform: Arc<Mutex<String>>,
    /// WebSocket URL (`wss://host/path`). When set, connect() prefers this
    /// transport over raw TCP — used by iOS so it can reach the server on
    /// networks that block port 6667.
    websocket_url: Arc<Mutex<Option<String>>>,
}

/// Flatten the FFI's tag list into the map the SDK sends with. UniFFI has no
/// map type in this binding, so tags cross the boundary as a sequence; a key
/// repeated by the caller keeps its last value, as it would on the wire.
fn tag_entries_to_map(tags: Vec<TagEntry>) -> std::collections::HashMap<String, String> {
    tags.into_iter().map(|t| (t.key, t.value)).collect()
}

impl FreeqClient {
    pub fn new(
        server: String,
        nick: String,
        handler: Box<dyn EventHandler>,
    ) -> Result<Self, FreeqError> {
        Ok(Self {
            server,
            nick: Arc::new(Mutex::new(nick)),
            handler: Arc::from(handler),
            handle: Arc::new(Mutex::new(None)),
            connected: Arc::new(Mutex::new(false)),
            web_token: Arc::new(Mutex::new(None)),
            platform: Arc::new(Mutex::new("freeq ios".to_string())),
            websocket_url: Arc::new(Mutex::new(None)),
        })
    }

    pub fn set_web_token(&self, token: String) -> Result<(), FreeqError> {
        tracing::debug!("[FFI] set_web_token called, token len={}", token.len());
        *self.web_token.lock().unwrap() = Some(token);
        Ok(())
    }

    pub fn set_platform(&self, platform: String) -> Result<(), FreeqError> {
        *self.platform.lock().unwrap() = platform;
        Ok(())
    }

    /// Set the WebSocket URL the next `connect()` should use. Pass an empty
    /// string to clear and fall back to the configured `server` (TCP).
    pub fn set_websocket_url(&self, url: String) -> Result<(), FreeqError> {
        let trimmed = url.trim();
        let value = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        tracing::debug!("[FFI] set_websocket_url: {:?}", value);
        *self.websocket_url.lock().unwrap() = value;
        Ok(())
    }

    pub fn connect(&self) -> Result<(), FreeqError> {
        let nick = self.nick.lock().unwrap().clone();
        let web_token = self.web_token.lock().unwrap().take();
        let websocket_url = self.websocket_url.lock().unwrap().clone();
        tracing::debug!(
            "[FFI] connect: nick={}, web_token={}, ws={}",
            nick,
            web_token.is_some(),
            websocket_url.is_some()
        );
        let config = freeq_sdk::client::ConnectConfig {
            server_addr: self.server.clone(),
            nick: nick.clone(),
            user: nick.clone(),
            realname: self.platform.lock().unwrap().clone(),
            tls: self.server.contains(":6697") || self.server.contains(":443"),
            tls_insecure: false,
            web_token,
            websocket_url,
        };

        // MUST call connect() inside the runtime — it uses tokio::spawn internally.
        let handle_store = self.handle.clone();
        let connected_store = self.connected.clone();
        let handler = self.handler.clone();
        let nick_state = self.nick.clone();

        // Use a std::thread to avoid blocking the main thread (UniFFI calls from Swift main thread).
        // The thread enters the tokio runtime, calls connect, then pumps events.
        std::thread::spawn(move || {
            RUNTIME.block_on(async move {
                let (client_handle, mut event_rx) = freeq_sdk::client::connect(config, None);

                *handle_store.lock().unwrap() = Some(client_handle);
                *connected_store.lock().unwrap() = true;

                // Pump events
                while let Some(event) = event_rx.recv().await {
                    let Some(ffi_event) = convert_event(&event) else {
                        continue;
                    };
                    if let FreeqEvent::Disconnected { .. } = &ffi_event {
                        *connected_store.lock().unwrap() = false;
                    }
                    if let FreeqEvent::Registered { ref nick } = &ffi_event {
                        *nick_state.lock().unwrap() = nick.clone();
                    }
                    handler.on_event(ffi_event);
                }
            });
        });

        Ok(())
    }

    pub fn disconnect(&self) {
        let handle = self.handle.lock().unwrap().take();
        if let Some(handle) = handle {
            // Spawn quit on the runtime — don't block_on from arbitrary thread
            RUNTIME.spawn(async move {
                let _ = handle.quit(Some("Goodbye")).await;
            });
        }
        *self.connected.lock().unwrap() = false;
    }

    pub fn join(&self, channel: String) -> Result<(), FreeqError> {
        let handle = self
            .handle
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)?;
        // Use spawn + oneshot to avoid block_on deadlock
        let (tx, rx) = std::sync::mpsc::channel();
        RUNTIME.spawn(async move {
            let result = handle
                .join(&channel)
                .await
                .map_err(|_| FreeqError::SendFailed);
            let _ = tx.send(result);
        });
        rx.recv().map_err(|_| FreeqError::SendFailed)?
    }

    pub fn part(&self, channel: String) -> Result<(), FreeqError> {
        let handle = self
            .handle
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)?;
        let (tx, rx) = std::sync::mpsc::channel();
        RUNTIME.spawn(async move {
            let result = handle
                .raw(&format!("PART {channel}"))
                .await
                .map_err(|_| FreeqError::SendFailed);
            let _ = tx.send(result);
        });
        rx.recv().map_err(|_| FreeqError::SendFailed)?
    }

    pub fn send_message(&self, target: String, text: String) -> Result<(), FreeqError> {
        let handle = self
            .handle
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)?;
        let (tx, rx) = std::sync::mpsc::channel();
        RUNTIME.spawn(async move {
            let result = handle
                .privmsg(&target, &text)
                .await
                .map_err(|_| FreeqError::SendFailed);
            let _ = tx.send(result);
        });
        rx.recv().map_err(|_| FreeqError::SendFailed)?
    }

    pub fn send_raw(&self, line: String) -> Result<(), FreeqError> {
        tracing::debug!("[FFI] send_raw called: {}", &line);
        let handle = self
            .handle
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)?;
        let (tx, rx) = std::sync::mpsc::channel();
        let line_clone = line.clone();
        RUNTIME.spawn(async move {
            let result = handle
                .raw(&line_clone)
                .await
                .map_err(|_| FreeqError::SendFailed);
            let _ = tx.send(result);
        });
        match rx.recv() {
            Ok(Ok(())) => {
                tracing::debug!("[FFI] send_raw OK: {}", &line);
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::error!("[FFI] send_raw failed: {:?}", e);
                Err(e)
            }
            Err(_) => {
                tracing::error!("[FFI] send_raw channel error");
                Err(FreeqError::SendFailed)
            }
        }
    }

    // ── Typed senders ──
    //
    // Everything a client sends that carries a message or mutates one goes
    // through these rather than `send_raw`. A raw line reaches the wire as
    // `Command::Raw`, which the SDK deliberately never signs; only the
    // structured commands behind these methods get a signature and an event
    // id. A hand-built `@+draft/delete=... TAGMSG` therefore travels
    // unsigned no matter what the server negotiated.

    /// Send a PRIVMSG with IRCv3 tags — reply, edit, and any tag combination
    /// a client needs on a message body. Signed like any other message.
    pub fn send_tagged(
        &self,
        target: String,
        text: String,
        tags: Vec<TagEntry>,
    ) -> Result<(), FreeqError> {
        let tags = tag_entries_to_map(tags);
        self.on_handle(move |h| async move { h.send_tagged(&target, &text, tags).await })
    }

    /// Add a reaction emoji to a message.
    pub fn react(&self, target: String, emoji: String, msgid: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.react(&target, &emoji, &msgid).await })
    }

    /// Withdraw a reaction emoji previously added to a message.
    pub fn unreact(&self, target: String, emoji: String, msgid: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.unreact(&target, &emoji, &msgid).await })
    }

    /// Delete one of your own messages.
    pub fn delete_message(&self, target: String, msgid: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.delete_message(&target, &msgid).await })
    }

    /// Replace the text of one of your own messages.
    pub fn edit_message(
        &self,
        target: String,
        msgid: String,
        new_text: String,
    ) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.edit_message(&target, &msgid, &new_text).await })
    }

    /// Send a message that answers another one.
    pub fn reply(&self, target: String, msgid: String, text: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.reply(&target, &msgid, &text).await })
    }

    /// Announce that we are typing. Ephemeral — carries no event id and is
    /// not signed, because nothing about it is worth attesting to later.
    pub fn typing_start(&self, target: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.typing_start(&target).await })
    }

    /// Announce that we stopped typing.
    pub fn typing_stop(&self, target: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.typing_stop(&target).await })
    }

    /// Ask who `nick` is. The DID, if the server knows one, arrives later as
    /// a `MemberDid` event — this call only poses the question.
    pub fn request_whois(&self, nick: String) -> Result<(), FreeqError> {
        self.on_handle(move |h| async move { h.whois(&nick).await })
    }

    /// Run `f` against the live client handle on the SDK runtime and wait for
    /// its result. Spawn-plus-channel rather than `block_on`, because these
    /// are called from the platform's UI thread, which the runtime may
    /// already be borrowing.
    fn on_handle<F, Fut, E>(&self, f: F) -> Result<(), FreeqError>
    where
        F: FnOnce(freeq_sdk::client::ClientHandle) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), E>> + Send + 'static,
        E: Send + 'static,
    {
        let handle = self
            .handle
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)?;
        let (tx, rx) = std::sync::mpsc::channel();
        RUNTIME.spawn(async move {
            let result = f(handle).await.map_err(|_| FreeqError::SendFailed);
            let _ = tx.send(result);
        });
        rx.recv().map_err(|_| FreeqError::SendFailed)?
    }

    pub fn set_topic(&self, channel: String, topic: String) -> Result<(), FreeqError> {
        self.send_raw(format!("TOPIC {channel} :{topic}"))
    }

    pub fn nick(&self, new_nick: String) -> Result<(), FreeqError> {
        self.send_raw(format!("NICK {new_nick}"))
    }

    pub fn is_connected(&self) -> bool {
        *self.connected.lock().unwrap()
    }

    pub fn current_nick(&self) -> Option<String> {
        Some(self.nick.lock().unwrap().clone())
    }
}

// ── Event conversion ──

/// Convert an SDK event to its FFI form. `None` for events not yet exposed
/// through the UDL (adding a variant requires regenerating the checked-in
/// Kotlin/Swift bindings, which happens in the native build environments).
fn convert_event(event: &freeq_sdk::event::Event) -> Option<FreeqEvent> {
    use freeq_sdk::event::Event;
    Some(match event {
        Event::MemberDid { nick, did } => FreeqEvent::MemberDid {
            nick: nick.clone(),
            did: did.clone(),
        },
        Event::Connected => FreeqEvent::Connected,
        Event::Registered { nick } => FreeqEvent::Registered { nick: nick.clone() },
        Event::Authenticated { did } => FreeqEvent::Authenticated { did: did.clone() },
        Event::AuthFailed { reason } => FreeqEvent::AuthFailed {
            reason: reason.clone(),
        },
        Event::Joined { channel, nick, .. } => FreeqEvent::Joined {
            channel: channel.clone(),
            nick: nick.clone(),
        },
        Event::Parted { channel, nick } => FreeqEvent::Parted {
            channel: channel.clone(),
            nick: nick.clone(),
        },
        Event::Message {
            from,
            target,
            text,
            tags,
            dm_key,
        } => {
            let msgid = tags.get("msgid").cloned();
            let reply_to = tags.get("+reply").cloned();
            let replaces_msgid = tags.get("+draft/edit").cloned();
            let edit_of = tags.get("+draft/edit").cloned();
            let batch_id = tags.get("batch").cloned();
            let pin_msgid = tags.get("+freeq.at/pin").cloned();
            let unpin_msgid = tags.get("+freeq.at/unpin").cloned();
            let is_action = text.starts_with("\x01ACTION ") && text.ends_with('\x01');
            let clean_text = if is_action {
                text.trim_start_matches("\x01ACTION ")
                    .trim_end_matches('\x01')
                    .to_string()
            } else {
                text.clone()
            };
            let ts = tags
                .get("time")
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|dt: chrono::DateTime<chrono::FixedOffset>| dt.timestamp_millis())
                .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
            let reactions = tags
                .get("+freeq.at/reactions")
                .map(|raw| parse_reactions_tag(raw))
                .unwrap_or_default();
            let is_edited = edit_of.is_some()
                || tags.get("+freeq.at/edited").map(|v| v == "1").unwrap_or(false);
            // Agent coordination event: the `+freeq.at/event` tag (with the
            // `freeq.at/` unprefixed fallback some senders use) turns this
            // message into a structured card on every client.
            let coord_tag = |name: &str| {
                tags.get(&format!("+freeq.at/{name}"))
                    .or_else(|| tags.get(&format!("freeq.at/{name}")))
                    .cloned()
            };
            let coordination = coord_tag("event").map(|event_type| CoordinationEvent {
                event_type,
                task_id: coord_tag("task-id"),
                phase: coord_tag("phase"),
                evidence_type: coord_tag("evidence-type"),
                reference: coord_tag("ref"),
                payload: coord_tag("payload"),
            });
            FreeqEvent::Message {
                msg: IrcMessage {
                    from_nick: from.clone(),
                    target: target.clone(),
                    text: clean_text,
                    msgid,
                    reply_to,
                    replaces_msgid,
                    edit_of,
                    batch_id,
                    pin_msgid,
                    unpin_msgid,
                    is_action,
                    is_signed: tags.contains_key("+freeq.at/sig"),
                    timestamp_ms: ts,
                    account: tags.get("account").cloned(),
                    origin: tags.get("+freeq.at/origin").cloned(),
                    reactions,
                    // Either signal: `edit_of` for an edit seen live, the tag
                    // for one the server already collapsed into replay.
                    edited: is_edited,
                    dm_key: dm_key.clone(),
                    coordination,
                },
            }
        }
        Event::TagMsg { from, target, tags, dm_key } => {
            let tag_entries = tags
                .iter()
                .map(|(k, v)| TagEntry {
                    key: k.clone(),
                    value: v.clone(),
                })
                .collect::<Vec<_>>();
            FreeqEvent::TagMsg {
                msg: TagMessage {
                    from: from.clone(),
                    target: target.clone(),
                    tags: tag_entries,
                    dm_key: dm_key.clone(),
                },
            }
        }
        Event::Names { channel, nicks } => {
            let members = nicks
                .iter()
                .map(|n| {
                    let (is_op, is_halfop, is_voiced, nick) =
                        if let Some(rest) = n.strip_prefix('@') {
                            (true, false, false, rest.to_string())
                        } else if let Some(rest) = n.strip_prefix('%') {
                            (false, true, false, rest.to_string())
                        } else if let Some(rest) = n.strip_prefix('+') {
                            (false, false, true, rest.to_string())
                        } else {
                            (false, false, false, n.clone())
                        };
                    IrcMember {
                        nick,
                        is_op,
                        is_halfop,
                        is_voiced,
                        away_msg: None,
                    }
                })
                .collect();
            FreeqEvent::Names {
                channel: channel.clone(),
                members,
            }
        }
        Event::NamesEnd { channel } => {
            // Signal end of NAMES list — client should flush pending members + request history
            FreeqEvent::Notice {
                text: format!("__NAMES_END__{}", channel),
            }
        }
        Event::ModeChanged {
            channel,
            mode,
            arg,
            set_by,
        } => FreeqEvent::ModeChanged {
            channel: channel.clone(),
            mode: mode.clone(),
            arg: arg.clone(),
            set_by: set_by.clone(),
        },
        Event::Kicked {
            channel,
            nick,
            by,
            reason,
        } => FreeqEvent::Kicked {
            channel: channel.clone(),
            nick: nick.clone(),
            by: by.clone(),
            reason: reason.clone(),
        },
        Event::TopicChanged {
            channel,
            topic,
            set_by,
        } => FreeqEvent::TopicChanged {
            channel: channel.clone(),
            topic: ChannelTopic {
                text: topic.clone(),
                set_by: set_by.clone(),
            },
        },
        Event::ServerNotice { text } => FreeqEvent::Notice { text: text.clone() },
        Event::UserQuit { nick, reason } => FreeqEvent::UserQuit {
            nick: nick.clone(),
            reason: reason.clone(),
        },
        Event::NickChanged { old_nick, new_nick } => FreeqEvent::NickChanged {
            old_nick: old_nick.clone(),
            new_nick: new_nick.clone(),
        },
        Event::AwayChanged { nick, away_msg } => FreeqEvent::AwayChanged {
            nick: nick.clone(),
            away_msg: away_msg.clone(),
        },
        Event::BatchStart {
            id,
            batch_type,
            target,
        } => FreeqEvent::BatchStart {
            id: id.clone(),
            batch_type: batch_type.clone(),
            target: target.clone(),
        },
        Event::BatchEnd { id } => FreeqEvent::BatchEnd { id: id.clone() },
        Event::ChatHistoryTarget { nick, timestamp, partner_did } => FreeqEvent::ChatHistoryTarget {
            nick: nick.clone(),
            timestamp: timestamp.clone(),
            partner_did: partner_did.clone(),
        },
        Event::Disconnected { reason } => FreeqEvent::Disconnected {
            reason: reason.clone(),
        },
        Event::Invited { channel, by } => FreeqEvent::Notice {
            text: format!("{by} invited you to {channel}"),
        },
        Event::WhoisReply { nick, info } => FreeqEvent::WhoisReply {
            nick: nick.clone(),
            info: info.clone(),
        },
        Event::WhoisEnd { nick } => FreeqEvent::WhoisEnd { nick: nick.clone() },
        Event::ReadMarker { target, timestamp } => FreeqEvent::ReadMarker {
            target: target.clone(),
            timestamp: timestamp.clone(),
        },
        Event::RawLine(_) => FreeqEvent::Notice {
            text: String::new(),
        },
    })
}

// ── E2EE Manager ───────────────────────────────────────────────────

use freeq_sdk::ratchet::{self, Session as RatchetSession};
use std::collections::HashMap;

/// E2EE manager for iOS — wraps Rust Double Ratchet sessions.
pub struct FreeqE2ee {
    sessions: Mutex<HashMap<String, RatchetSession>>,
    identity_secret: Mutex<Option<[u8; 32]>>,
    identity_public: Mutex<Option<[u8; 32]>>,
    spk_secret: Mutex<Option<[u8; 32]>>,
    spk_public: Mutex<Option<[u8; 32]>>,
}

/// Pre-key bundle for uploading to the server.
pub struct PreKeyBundle {
    pub identity_key: String,   // base64url
    pub signed_pre_key: String, // base64url
    pub spk_signature: String,  // base64url (Ed25519 sig of SPK)
    pub spk_id: u32,
}

/// Safety number for verification.
pub struct SafetyNumber {
    pub number: String,
}

impl FreeqE2ee {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            identity_secret: Mutex::new(None),
            identity_public: Mutex::new(None),
            spk_secret: Mutex::new(None),
            spk_public: Mutex::new(None),
        }
    }

    /// Generate identity and signed pre-key. Returns the bundle to upload.
    fn generate_keys(&self) -> Result<PreKeyBundle, FreeqError> {
        use aes_gcm::aead::OsRng;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;
        use x25519_dalek::{PublicKey, StaticSecret};

        let ik_secret = StaticSecret::random_from_rng(OsRng);
        let ik_public = PublicKey::from(&ik_secret);
        let spk_secret = StaticSecret::random_from_rng(OsRng);
        let spk_public = PublicKey::from(&spk_secret);

        *self.identity_secret.lock().unwrap() = Some(ik_secret.to_bytes());
        *self.identity_public.lock().unwrap() = Some(ik_public.to_bytes());
        *self.spk_secret.lock().unwrap() = Some(spk_secret.to_bytes());
        *self.spk_public.lock().unwrap() = Some(spk_public.to_bytes());

        // Sign SPK with Ed25519 signing key
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::generate(&mut OsRng);
        let sig = signing_key.sign(spk_public.as_bytes());

        Ok(PreKeyBundle {
            identity_key: B64.encode(ik_public.as_bytes()),
            signed_pre_key: B64.encode(spk_public.as_bytes()),
            spk_signature: B64.encode(sig.to_bytes()),
            spk_id: 1,
        })
    }

    /// Restore keys from persisted base64url strings (from Keychain).
    fn restore_keys(
        &self,
        ik_secret_b64: String,
        spk_secret_b64: String,
    ) -> Result<PreKeyBundle, FreeqError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;
        use x25519_dalek::{PublicKey, StaticSecret};

        let ik_bytes: [u8; 32] = B64
            .decode(&ik_secret_b64)
            .map_err(|_| FreeqError::InvalidArgument)?
            .try_into()
            .map_err(|_| FreeqError::InvalidArgument)?;
        let spk_bytes: [u8; 32] = B64
            .decode(&spk_secret_b64)
            .map_err(|_| FreeqError::InvalidArgument)?
            .try_into()
            .map_err(|_| FreeqError::InvalidArgument)?;

        let ik_secret = StaticSecret::from(ik_bytes);
        let ik_public = PublicKey::from(&ik_secret);
        let spk_secret = StaticSecret::from(spk_bytes);
        let spk_public = PublicKey::from(&spk_secret);

        *self.identity_secret.lock().unwrap() = Some(ik_bytes);
        *self.identity_public.lock().unwrap() = Some(ik_public.to_bytes());
        *self.spk_secret.lock().unwrap() = Some(spk_bytes);
        *self.spk_public.lock().unwrap() = Some(spk_public.to_bytes());

        Ok(PreKeyBundle {
            identity_key: B64.encode(ik_public.as_bytes()),
            signed_pre_key: B64.encode(spk_public.as_bytes()),
            spk_signature: String::new(),
            spk_id: 1,
        })
    }

    /// Export private keys as base64url for Keychain persistence.
    fn export_keys(&self) -> Result<Vec<String>, FreeqError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;

        let ik = self
            .identity_secret
            .lock()
            .unwrap()
            .ok_or(FreeqError::NotConnected)?;
        let spk = self
            .spk_secret
            .lock()
            .unwrap()
            .ok_or(FreeqError::NotConnected)?;
        Ok(vec![B64.encode(ik), B64.encode(spk)])
    }

    /// Establish a session with a remote user from their pre-key bundle.
    /// `bundle_json` is the JSON from GET /api/v1/keys/{did}.
    fn establish_session(
        &self,
        remote_did: String,
        their_ik_b64: String,
        their_spk_b64: String,
    ) -> Result<(), FreeqError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;
        use x25519_dalek::{PublicKey, StaticSecret};

        let their_ik: [u8; 32] = B64
            .decode(&their_ik_b64)
            .map_err(|_| FreeqError::InvalidArgument)?
            .try_into()
            .map_err(|_| FreeqError::InvalidArgument)?;
        let their_spk: [u8; 32] = B64
            .decode(&their_spk_b64)
            .map_err(|_| FreeqError::InvalidArgument)?
            .try_into()
            .map_err(|_| FreeqError::InvalidArgument)?;

        let my_ik_secret = self
            .identity_secret
            .lock()
            .unwrap()
            .ok_or(FreeqError::NotConnected)?;
        let my_ik = StaticSecret::from(my_ik_secret);
        let their_ik_pk = PublicKey::from(their_ik);

        // X3DH: DH(our IK, their SPK) — simplified, same as web client
        let dh_out = my_ik.diffie_hellman(&their_ik_pk).to_bytes();
        let their_spk_pk = PublicKey::from(their_spk);
        let dh_out2 = my_ik.diffie_hellman(&their_spk_pk).to_bytes();

        // Combine DH outputs
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(dh_out);
        hasher.update(dh_out2);
        let shared_secret: [u8; 32] = hasher.finalize().into();

        // Canonical order: lower public key is "initiator"
        let my_pk = self
            .identity_public
            .lock()
            .unwrap()
            .ok_or(FreeqError::NotConnected)?;
        let we_are_first = my_pk < their_ik;

        let session = if we_are_first {
            RatchetSession::init_alice(shared_secret, their_spk)
        } else {
            let my_spk = self
                .spk_secret
                .lock()
                .unwrap()
                .ok_or(FreeqError::NotConnected)?;
            RatchetSession::init_bob(shared_secret, my_spk)
        };

        self.sessions.lock().unwrap().insert(remote_did, session);
        Ok(())
    }

    /// Encrypt a message for a remote user. Returns ENC3:... wire format.
    fn encrypt_message(&self, remote_did: String, plaintext: String) -> Result<String, FreeqError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&remote_did)
            .ok_or(FreeqError::NotConnected)?;
        session
            .encrypt(&plaintext)
            .map_err(|_| FreeqError::SendFailed)
    }

    /// Decrypt a message from a remote user.
    fn decrypt_message(&self, remote_did: String, wire: String) -> Result<String, FreeqError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&remote_did)
            .ok_or(FreeqError::NotConnected)?;
        session
            .decrypt(&wire)
            .map_err(|_| FreeqError::InvalidArgument)
    }

    /// Check if we have an active session with a user.
    fn has_session(&self, remote_did: String) -> bool {
        self.sessions.lock().unwrap().contains_key(&remote_did)
    }

    /// Check if a message is encrypted.
    fn is_encrypted(&self, text: String) -> bool {
        text.starts_with(ratchet::ENC3_PREFIX)
    }

    /// Get safety number for a session (hash of both identity keys).
    fn get_safety_number(&self, remote_did: String) -> Result<SafetyNumber, FreeqError> {
        use sha2::{Digest, Sha256};
        let my_pk = self
            .identity_public
            .lock()
            .unwrap()
            .ok_or(FreeqError::NotConnected)?;

        // Combine in canonical order
        let mut hasher = Sha256::new();
        let remote_bytes = remote_did.as_bytes();
        if my_pk.as_slice() < remote_bytes {
            hasher.update(my_pk);
            hasher.update(remote_bytes);
        } else {
            hasher.update(remote_bytes);
            hasher.update(my_pk);
        }
        let hash: [u8; 32] = hasher.finalize().into();

        // 12 groups of 5 digits
        let mut digits = Vec::new();
        for i in 0..12 {
            let val = ((hash[i * 2] as u32) << 8 | hash[i * 2 + 1] as u32) % 100000;
            digits.push(format!("{val:05}"));
        }
        Ok(SafetyNumber {
            number: digits.join(" "),
        })
    }

    /// Serialize a session state for persistence.
    fn export_session(&self, remote_did: String) -> Result<String, FreeqError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(&remote_did).ok_or(FreeqError::NotConnected)?;
        serde_json::to_string(session).map_err(|_| FreeqError::SendFailed)
    }

    /// Restore a session from serialized state.
    fn import_session(&self, remote_did: String, json: String) -> Result<(), FreeqError> {
        let session: RatchetSession =
            serde_json::from_str(&json).map_err(|_| FreeqError::InvalidArgument)?;
        self.sessions.lock().unwrap().insert(remote_did, session);
        Ok(())
    }
}

// ── P2P via iroh ──────────────────────────────────────────────────

pub enum P2pEvent {
    EndpointReady { endpoint_id: String },
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    DirectMessage { peer_id: String, text: String },
    Error { message: String },
}

pub trait P2pEventHandler: Send + Sync + 'static {
    fn on_p2p_event(&self, event: P2pEvent);
}

pub struct FreeqP2p {
    handle: Mutex<Option<freeq_sdk::p2p::P2pHandle>>,
    endpoint_id: Mutex<Option<String>>,
    _shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl FreeqP2p {
    fn new(handler: Box<dyn P2pEventHandler>) -> Result<Self, FreeqError> {
        let (p2p_handle, mut event_rx) = RUNTIME
            .block_on(freeq_sdk::p2p::start())
            .map_err(|_| FreeqError::ConnectionFailed)?;

        let endpoint_id = p2p_handle.endpoint_id.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Spawn event forwarding task
        RUNTIME.spawn(async move {
            loop {
                tokio::select! {
                    evt = event_rx.recv() => {
                        match evt {
                            Some(e) => {
                                let ffi_event = match e {
                                    freeq_sdk::p2p::P2pEvent::EndpointReady { endpoint_id } => {
                                        P2pEvent::EndpointReady { endpoint_id }
                                    }
                                    freeq_sdk::p2p::P2pEvent::PeerConnected { peer_id } => {
                                        P2pEvent::PeerConnected { peer_id }
                                    }
                                    freeq_sdk::p2p::P2pEvent::PeerDisconnected { peer_id } => {
                                        P2pEvent::PeerDisconnected { peer_id }
                                    }
                                    freeq_sdk::p2p::P2pEvent::DirectMessage { peer_id, text } => {
                                        P2pEvent::DirectMessage { peer_id, text }
                                    }
                                    freeq_sdk::p2p::P2pEvent::Error { message } => {
                                        P2pEvent::Error { message }
                                    }
                                };
                                handler.on_p2p_event(ffi_event);
                            }
                            None => break,
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Ok(Self {
            handle: Mutex::new(Some(p2p_handle)),
            endpoint_id: Mutex::new(Some(endpoint_id)),
            _shutdown: Mutex::new(Some(shutdown_tx)),
        })
    }

    fn endpoint_id(&self) -> Result<String, FreeqError> {
        self.endpoint_id
            .lock()
            .unwrap()
            .clone()
            .ok_or(FreeqError::NotConnected)
    }

    fn connect_peer(&self, endpoint_id: String) -> Result<(), FreeqError> {
        let handle = self.handle.lock().unwrap();
        let h = handle.as_ref().ok_or(FreeqError::NotConnected)?;
        let h = h.clone();
        RUNTIME.spawn(async move {
            if let Err(e) = h.connect_peer(&endpoint_id).await {
                tracing::error!("P2P connect error: {e}");
            }
        });
        Ok(())
    }

    fn send_message(&self, peer_id: String, text: String) -> Result<(), FreeqError> {
        let handle = self.handle.lock().unwrap();
        let h = handle.as_ref().ok_or(FreeqError::NotConnected)?;
        let h = h.clone();
        RUNTIME.spawn(async move {
            if let Err(e) = h.send_message(&peer_id, &text).await {
                tracing::error!("P2P send error: {e}");
            }
        });
        Ok(())
    }

    fn connected_peers(&self) -> Vec<String> {
        // TODO: expose connected peers list from P2pHandle
        Vec::new()
    }

    fn shutdown(&self) {
        let _ = self._shutdown.lock().unwrap().take();
        let _ = self.handle.lock().unwrap().take();
    }
}

// ── AV (voice/video via MoQ SFU) ─────────────────────────────────

pub enum AvEvent {
    Connected,
    Disconnected {
        reason: String,
    },
    ParticipantJoined {
        nick: String,
        /// Stable per-device id from the media path `{session}/{nick}~{instance}`.
        /// Clients key presence on this, not `nick` (which can differ from the
        /// server's `left` signal for multi-nick accounts). "" for legacy peers.
        instance: String,
    },
    ParticipantLeft {
        nick: String,
        instance: String,
    },
    AudioTrackStarted {
        nick: String,
    },
    AudioTrackStopped {
        nick: String,
    },
    VideoTrackStarted {
        nick: String,
    },
    VideoTrackStopped {
        nick: String,
    },
    VideoFrame {
        nick: String,
        bgra: Vec<u8>,
        width: u32,
        height: u32,
    },
    ScreenTrackStarted {
        nick: String,
    },
    ScreenTrackStopped {
        nick: String,
    },
    ScreenFrame {
        nick: String,
        bgra: Vec<u8>,
        width: u32,
        height: u32,
    },
    // R1 interface freeze: shapes are stable; AudioLevel emission lands
    // with the playout tap, reconnect events with the retry loop.
    AudioLevel {
        nick: String,
        level: f32,
    },
    Reconnecting {
        attempt: u32,
    },
    Reconnected,
    Error {
        message: String,
    },
}

/// An audio output device for the speaker picker (see
/// `FreeqAv::list_output_devices`).
pub struct AvAudioDevice {
    pub id: String,
    pub name: String,
    pub is_default: bool,
}

pub trait AvEventHandler: Send + Sync + 'static {
    fn on_av_event(&self, event: AvEvent);
}

/// Pure mic jitter-buffer logic (producer cap + consumer drain). Always
/// compiled — and unit-tested — independent of the heavy `av` media stack.
///
/// Its callers all live in `av_impl`, which is `#[cfg(feature = "av")]`, so
/// without that feature the only thing exercising these items is this module's
/// own tests — which dead-code analysis does not count as use. That made
/// `cargo check --workspace` fail under CI's `-D warnings` on the default
/// feature set, for code that is deliberately feature-independent.
#[cfg_attr(not(feature = "av"), allow(dead_code))]
mod audio_buffer;

#[cfg(feature = "av")]
mod av_impl {
    use super::{AvEvent, AvEventHandler, FreeqError, RUNTIME};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use iroh_live::media::codec::{AudioCodec, VideoCodec};
    use iroh_live::media::format::{
        AudioFormat, AudioPreset, PixelFormat, VideoFormat, VideoFrame, VideoPreset,
    };
    use iroh_live::media::publish::LocalBroadcast;
    use iroh_live::media::traits::{AudioSource, VideoSource};

    /// Wraps an [`AudioSource`] and zero-fills output when muted. Used so that
    /// muting doesn't tear down the audio track (which would surface as
    /// `AudioTrackStopped` to peers and cause a noticeable reconnect blip).
    pub(super) struct MuteableAudioSource {
        inner: Box<dyn AudioSource>,
        muted: Arc<AtomicBool>,
    }

    impl AudioSource for MuteableAudioSource {
        fn format(&self) -> AudioFormat {
            self.inner.format()
        }
        fn pop_samples(&mut self, buf: &mut [f32]) -> anyhow::Result<Option<usize>> {
            let result = self.inner.pop_samples(buf)?;
            if let Some(n) = result {
                if self.muted.load(Ordering::Relaxed) {
                    for s in &mut buf[..n] {
                        *s = 0.0;
                    }
                }
            }
            Ok(result)
        }
    }

    /// Latest-frame-only video source fed from Swift via `push_video_frame`.
    ///
    /// The encoder pipeline calls `pop_frame` at the desired output rate; we
    /// surface whatever Swift pushed most recently. Older frames are dropped
    /// silently — this is the right behaviour for camera capture (display the
    /// fresh frame, not a backlog).
    pub(super) struct PushVideoSource {
        pub(super) pending: Arc<Mutex<Option<VideoFrame>>>,
        pub(super) format: Arc<Mutex<VideoFormat>>,
        /// Toggled by `set_camera_enabled`. While false, pop_frame returns
        /// None (encoder idles); the source itself stays registered so the
        /// catalog keeps advertising the video rendition.
        pub(super) enabled: Arc<AtomicBool>,
    }

    impl VideoSource for PushVideoSource {
        fn name(&self) -> &str {
            "swift-push"
        }
        fn format(&self) -> VideoFormat {
            self.format.lock().unwrap().clone()
        }
        fn pop_frame(&mut self) -> anyhow::Result<Option<VideoFrame>> {
            if !self.enabled.load(Ordering::Relaxed) {
                return Ok(None);
            }
            Ok(self.pending.lock().unwrap().take())
        }
        fn start(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
        fn stop(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Rate Swift resamples mic audio to before pushing it in.
    pub(super) use crate::audio_buffer::PUSH_AUDIO_RATE;

    /// Audio source fed from Swift via `push_audio_frame`. Swift owns the
    /// real mic capture (`AVAudioEngine`) — the same arrangement as video —
    /// because iroh-live's audio *input* backend isn't viable on iOS.
    pub(super) struct PushAudioSource {
        pub(super) queue: Arc<Mutex<std::collections::VecDeque<f32>>>,
    }

    impl AudioSource for PushAudioSource {
        fn format(&self) -> AudioFormat {
            AudioFormat {
                sample_rate: PUSH_AUDIO_RATE,
                channel_count: 1,
            }
        }
        fn pop_samples(&mut self, buf: &mut [f32]) -> anyhow::Result<Option<usize>> {
            // FIFO drain with silence-padding on underrun. The backlog bound
            // is enforced producer-side in `push_audio` (a stalled encoder
            // never reaches here, so capping here couldn't bound it). Always
            // hand the encoder a full buffer.
            let mut q = self.queue.lock().unwrap();
            crate::audio_buffer::drain_into(&mut q, buf);
            Ok(Some(buf.len()))
        }
    }

    pub(super) const DEFAULT_VIDEO_FORMAT: VideoFormat = VideoFormat {
        pixel_format: PixelFormat::Bgra,
        dimensions: [1280, 720],
    };

    pub(super) struct State {
        /// Held so the producer side of the broadcast (audio + video
        /// sources, encoder pipelines) stays alive for the call's lifetime.
        /// Dropping it would tear down the publish path.
        pub _broadcast: LocalBroadcast,
        // Keeps audio/video device handles alive for the session; also the
        // handle for output-device switching (speaker picker).
        pub audio_backend: iroh_live::media::audio_backend::AudioBackend,
        // The moq transport is owned by the media loop task (it re-dials on
        // reconnect), not by State. `leave()` signals shutdown and the loop
        // drops the session inside the runtime.
        /// Also used to publish/retract the screen broadcast post-connect.
        pub origin: moq_lite::OriginProducer,
        pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
        pub connected: bool,
        pub muted: Arc<AtomicBool>,
        /// Gated by `set_camera_enabled`. The video source is registered at
        /// connect time so the catalog always advertises the rendition;
        /// the flag just controls whether `pop_frame` actually returns
        /// pushed frames or short-circuits to None.
        pub camera_enabled: Arc<AtomicBool>,
        pub pending_frame: Arc<Mutex<Option<VideoFrame>>>,
        pub video_format: Arc<Mutex<VideoFormat>>,
        /// Mic samples pushed from Swift, drained by the Opus encoder.
        pub audio_queue: Arc<Mutex<std::collections::VecDeque<f32>>>,
        /// Our published MoQ path — the screen broadcast publishes at
        /// `{broadcast_name}/screen` (web-client convention).
        pub broadcast_name: String,
        /// Live screen-share broadcast; Some while sharing. Dropping the
        /// producer retracts the announcement for peers.
        pub screen_broadcast: Option<LocalBroadcast>,
        pub screen_enabled: Arc<AtomicBool>,
        pub screen_pending: Arc<Mutex<Option<VideoFrame>>>,
        pub screen_format: Arc<Mutex<VideoFormat>>,
    }

    pub(super) fn connect(
        server_url: String,
        session_id: String,
        nick: String,
        instance_id: String,
        handler: Box<dyn AvEventHandler>,
    ) -> Result<State, FreeqError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // S2 session scoping (coordinated rollout — see `SCOPED_SESSIONS`).
        // When scoped, we dial `/av/moq/s/{session}` so the relay roots this
        // connection at the session and never announces OTHER sessions'
        // broadcasts to us (server-enforced isolation for every client). Our
        // own broadcast path is then RELATIVE to that root — `{nick}~{inst}`,
        // NOT `{session}/{nick}~{inst}` — or it would double-prefix. When
        // unscoped (today), everything is global + absolute as before.
        //
        // Broadcast path includes a per-call instance suffix so two devices
        // signed in as the same DID/nick get distinct MoQ paths (matches the
        // `+freeq.at/av-instance` av-join tag).
        let leaf = if instance_id.is_empty() {
            nick.clone()
        } else {
            format!("{nick}~{instance_id}")
        };
        let broadcast_name = if SCOPED_SESSIONS {
            leaf
        } else {
            format!("{session_id}/{leaf}")
        };
        // Any query string on `server_url` is preserved onto the dial URL —
        // this is how the app layer passes the per-session MoQ access token
        // (`?jwt=<token>`, delivered by the server as a `+freeq.at/av-token`
        // TAGMSG after av-join). No UDL change needed: callers append the
        // query to the server URL they already pass in.
        let (base_url, query) = match server_url.split_once('?') {
            Some((base, q)) => (base.trim_end_matches('/').to_string(), Some(q.to_string())),
            None => (server_url.trim_end_matches('/').to_string(), None),
        };
        let mut moq_url_str = if SCOPED_SESSIONS {
            format!("{base_url}/av/moq/s/{session_id}")
        } else {
            format!("{base_url}/av/moq")
        };
        if let Some(q) = query {
            moq_url_str.push('?');
            moq_url_str.push_str(&q);
        }
        let moq_url: url::Url = moq_url_str
            .parse()
            .map_err(|_| FreeqError::InvalidArgument)?;

        let muted = Arc::new(AtomicBool::new(false));
        let pending_frame: Arc<Mutex<Option<VideoFrame>>> = Arc::new(Mutex::new(None));
        let video_format = Arc::new(Mutex::new(DEFAULT_VIDEO_FORMAT));
        let camera_enabled_flag = Arc::new(AtomicBool::new(false));
        let audio_queue: Arc<Mutex<std::collections::VecDeque<f32>>> =
            Arc::new(Mutex::new(std::collections::VecDeque::new()));

        let dial_url = moq_url.clone();
        let (session, origin, sub_consumer, audio_backend, broadcast, client) =
            RUNTIME.block_on(async {
                let broadcast = LocalBroadcast::new();
                let audio_backend = iroh_live::media::audio_backend::AudioBackend::default();
                audio_backend.set_aec_enabled(false);

                // Mic capture is Swift-driven (AVAudioEngine →
                // `push_audio_frame` → `PushAudioSource`). iroh-live's audio
                // *input* backend isn't viable on iOS — the same reason
                // video capture is Swift-driven. `audio_backend` is still
                // used, for *playback* of remote audio.
                let push_audio = PushAudioSource {
                    queue: audio_queue.clone(),
                };
                let muteable = MuteableAudioSource {
                    inner: Box::new(push_audio),
                    muted: muted.clone(),
                };

                broadcast
                    .audio()
                    .set(muteable, AudioCodec::Opus, [AudioPreset::Hq])
                    .map_err(|_| FreeqError::ConnectionFailed)?;

                // Advertise video in the catalog NOW, before any peer
                // subscribes. moq-watch (used by the web client) reads the
                // catalog at sub time; if we wait until the user toggles
                // their camera on, peers who subscribed earlier never pick
                // up the video track and silently render a black tile.
                // The encoder happily idles while pop_frame returns None.
                let push_source = PushVideoSource {
                    pending: pending_frame.clone(),
                    format: video_format.clone(),
                    enabled: camera_enabled_flag.clone(),
                };
                // iOS encodes with SOFTWARE openh264 (the media stack's
                // VideoToolbox H.264 *encoder* is compiled macOS-only), so
                // 720p@30 overloads the phone and the outgoing video lags for
                // receivers. Cap the camera to 360p on iOS; desktop keeps 720p.
                #[cfg(target_os = "ios")]
                let camera_preset = VideoPreset::P360;
                #[cfg(not(target_os = "ios"))]
                let camera_preset = VideoPreset::P720;
                broadcast
                    .video()
                    .set_source(push_source, VideoCodec::H264, [camera_preset])
                    .map_err(|e| {
                        tracing::warn!("AV: initial video set_source failed: {e}");
                        FreeqError::ConnectionFailed
                    })?;

                let origin = moq_lite::Origin::produce();
                origin.publish_broadcast(&broadcast_name, broadcast.consume());

                let sub_origin = moq_lite::Origin::produce();
                let sub_consumer = sub_origin.consume();

                let mut client_config = moq_native::ClientConfig::default();
                client_config.tls.disable_verify = Some(true);
                client_config.backend = Some(moq_native::QuicBackend::Noq);
                let client = client_config
                    .init()
                    .map_err(|_| FreeqError::ConnectionFailed)?;

                let session = client
                    .clone()
                    .with_publish(origin.consume())
                    .with_consume(sub_origin)
                    .connect(moq_url)
                    .await
                    .map_err(|_| FreeqError::ConnectionFailed)?;

                Ok::<_, FreeqError>((session, origin, sub_consumer, audio_backend, broadcast, client))
            })?;

        tracing::info!(broadcast = %broadcast_name, "AV: connected to MoQ SFU");
        handler.on_av_event(AvEvent::Connected);

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let our_name = broadcast_name.clone();
        let session_scope = session_id.clone();
        let audio_for_playback = audio_backend.clone();
        let handler: Arc<dyn AvEventHandler> = Arc::from(handler);
        let handler_loop = handler.clone();
        let origin_loop = origin.clone();

        RUNTIME.spawn(async move {
            // The initial transport, moved in here so the loop OWNS
            // reconnection: on an unexpected drop we re-dial with the same
            // origin (our broadcast is still published on it) and a fresh
            // subscribe consumer, rather than ending the call. The session's
            // Drop needs a reactor — it runs inside this spawned task (in
            // RUNTIME), so that's satisfied.
            //
            // `session` is Some while connected. We drop it before re-dialing
            // so the dead transport releases promptly.
            let mut session = Some(session);
            let mut sub_consumer = sub_consumer;

            let end_reason = loop {
                let outcome = watch_announcements(
                    &mut sub_consumer,
                    &mut shutdown_rx,
                    &our_name,
                    &session_scope,
                    &audio_for_playback,
                    &handler_loop,
                )
                .await;
                if matches!(outcome, WatchOutcome::Shutdown) {
                    break "session ended";
                }

                // Transport dropped. Release it, then re-dial with backoff.
                drop(session.take());

                let mut attempt: u32 = 0;
                let reconnected = loop {
                    attempt += 1;
                    if attempt > MAX_RECONNECT_ATTEMPTS {
                        break None;
                    }
                    handler_loop.on_av_event(AvEvent::Reconnecting { attempt });

                    tokio::select! {
                        _ = tokio::time::sleep(reconnect_backoff(attempt)) => {}
                        _ = &mut shutdown_rx => break None,
                    }

                    match redial(&client, &dial_url, &origin_loop).await {
                        Ok((new_session, new_sub)) => {
                            sub_consumer = new_sub;
                            handler_loop.on_av_event(AvEvent::Reconnected);
                            tracing::info!(attempt, "AV: reconnected to MoQ SFU");
                            break Some(new_session);
                        }
                        Err(e) => {
                            tracing::warn!(attempt, "AV: reconnect dial failed: {e}");
                        }
                    }
                };

                match reconnected {
                    Some(new_session) => session = Some(new_session),
                    None => break "reconnect failed",
                }
            };

            handler_loop.on_av_event(AvEvent::Disconnected {
                reason: end_reason.to_string(),
            });
        });

        Ok(State {
            _broadcast: broadcast,
            audio_backend,
            origin,
            shutdown_tx: Some(shutdown_tx),
            connected: true,
            muted,
            camera_enabled: camera_enabled_flag,
            pending_frame,
            video_format,
            audio_queue,
            broadcast_name,
            screen_broadcast: None,
            screen_enabled: Arc::new(AtomicBool::new(false)),
            screen_pending: Arc::new(Mutex::new(None)),
            screen_format: Arc::new(Mutex::new(DEFAULT_VIDEO_FORMAT)),
        })
    }

    /// S2 rollout flag. FALSE = today's behavior (dial `/av/moq`, absolute
    /// `{session}/{nick}` paths, global namespace + client-side session
    /// filter). TRUE = dial `/av/moq/s/{session}`, relative `{nick}` paths,
    /// server-enforced per-session isolation.
    ///
    /// MUST stay false until the scoping-capable server is DEPLOYED — a scoped
    /// client against an un-deployed server would root at a path the relay
    /// doesn't special-case and see no peers. Flip to true only after the
    /// server is live, and flip web + iOS in the SAME release (a scoped and an
    /// unscoped client in one call root differently and can't see each other).
    /// See docs/QUEUE-FOR-CHAD.md #3 and freeq-server/src/av_sfu.rs.
    pub(super) const SCOPED_SESSIONS: bool = false;

    /// Whether a peer broadcast path belongs to our call. Unscoped: the SFU
    /// relays ALL sessions through one namespace and announces everything, so
    /// we must filter by the `{session}/` prefix (without this, a client in
    /// call A plays call B's media — observed live 2026-07-03). Scoped: the
    /// relay only ever announces our session's broadcasts, so every announced
    /// path already belongs to us (paths are relative, no session prefix).
    pub(super) fn belongs_to_session(path: &str, session_id: &str) -> bool {
        if SCOPED_SESSIONS {
            return true;
        }
        path.strip_prefix(session_id)
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Cap on consecutive reconnect attempts before the call is declared
    /// dead. With the backoff schedule below this spans ~30s of retries.
    pub(super) const MAX_RECONNECT_ATTEMPTS: u32 = 8;

    /// Capped exponential backoff for reconnect attempt `n` (1-based):
    /// 250ms, 500ms, 1s, 2s, 4s, then 5s flat. Keeps the first retries snappy
    /// (a brief network blip recovers in well under a second) without
    /// hammering the SFU on a longer outage.
    pub(super) fn reconnect_backoff(attempt: u32) -> Duration {
        // Cap the exponent at 6 so 250·2^5 = 8000 then clamps to the 5s
        // ceiling; earlier attempts (1..=5) give 250ms…4s unclamped.
        let capped = attempt.clamp(1, 6);
        let ms = 250u64 << (capped - 1);
        Duration::from_millis(ms.min(5_000))
    }

    /// Re-dial the SFU on the same origin (our broadcast is still published
    /// there, so it re-announces) with a fresh subscribe consumer.
    async fn redial(
        client: &moq_native::Client,
        moq_url: &url::Url,
        origin: &moq_lite::OriginProducer,
    ) -> anyhow::Result<(moq_lite::Session, moq_lite::OriginConsumer)> {
        let sub_origin = moq_lite::Origin::produce();
        let sub_consumer = sub_origin.consume();
        let session = client
            .clone()
            .with_publish(origin.consume())
            .with_consume(sub_origin)
            .connect(moq_url.clone())
            .await?;
        Ok((session, sub_consumer))
    }

    /// Why the announcement watch returned.
    pub(super) enum WatchOutcome {
        /// Explicit leave / drop — end the call cleanly, no reconnect.
        Shutdown,
        /// The transport ended unexpectedly — caller should reconnect.
        TransportLost,
    }

    /// Watch one transport's announcements until it ends. Spawns and reaps the
    /// per-participant playback tasks; aborts them all before returning so
    /// inbound audio stops the instant the transport goes (leave or drop).
    async fn watch_announcements(
        sub_consumer: &mut moq_lite::OriginConsumer,
        shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
        our_name: &str,
        session_scope: &str,
        audio_for_playback: &iroh_live::media::audio_backend::AudioBackend,
        handler: &Arc<dyn AvEventHandler>,
    ) -> WatchOutcome {
        // Per-participant playback tasks live in this set. Aborting it when
        // the transport ends stops inbound audio immediately — otherwise
        // these tasks run on and you keep hearing people after you've left.
        let mut remote_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        let outcome = loop {
            tokio::select! {
                _ = &mut *shutdown_rx => break WatchOutcome::Shutdown,
                announced = sub_consumer.announced() => {
                    match announced {
                        Some((path, Some(broadcast_consumer))) => {
                            let path_str = path.to_string();
                            if path_str == our_name || path_str == format!("{our_name}/screen") {
                                continue;
                            }
                            if !belongs_to_session(&path_str, session_scope) {
                                tracing::debug!(path = %path_str, "AV: ignoring broadcast from another session");
                                continue;
                            }
                            // Paths: `{session}/{nick}[~{instance}]` for the
                            // main broadcast, `/screen` suffix for a share.
                            let (nick, instance, is_screen) = parse_broadcast_path(&path_str);
                            tracing::info!(nick = %nick, instance = %instance, screen = is_screen, path = %path_str, "AV: participant broadcast");
                            if !is_screen {
                                handler.on_av_event(AvEvent::ParticipantJoined {
                                    nick: nick.clone(),
                                    instance: instance.clone(),
                                });
                            }
                            let ab = audio_for_playback.clone();
                            let h = handler.clone();
                            let nick_for_task = nick.clone();
                            remote_tasks.spawn(async move {
                                handle_remote_broadcast(path_str, broadcast_consumer, ab, h, nick_for_task, is_screen).await;
                            });
                        }
                        Some((path, None)) => {
                            let path_str = path.to_string();
                            if path_str == our_name || path_str == format!("{our_name}/screen") {
                                continue;
                            }
                            if !belongs_to_session(&path_str, session_scope) {
                                continue;
                            }
                            let (nick, instance, is_screen) = parse_broadcast_path(&path_str);
                            if is_screen {
                                handler.on_av_event(AvEvent::ScreenTrackStopped { nick });
                            } else {
                                handler.on_av_event(AvEvent::ParticipantLeft { nick, instance });
                            }
                        }
                        // Announcement stream ended = transport gone.
                        None => break WatchOutcome::TransportLost,
                    }
                }
            }
        };
        remote_tasks.abort_all();
        outcome
    }

    /// `{session}/{nick}[~{instance}][/screen]` → (display nick, is_screen).
    /// `{session}/{nick}[~{instance}][/screen]` → (display nick, instance, is_screen).
    /// The instance is the stable per-device id; it's what clients key presence
    /// teardown on, since the nick can differ between this media path and the
    /// server's `left` signal for multi-nick accounts. "" when absent (legacy).
    pub(super) fn parse_broadcast_path(path_str: &str) -> (String, String, bool) {
        let segments: Vec<&str> = path_str.split('/').collect();
        let is_screen = segments.last() == Some(&"screen") && segments.len() >= 2;
        let nick_segment = if is_screen {
            segments[segments.len() - 2]
        } else {
            segments.last().copied().unwrap_or("unknown")
        };
        let mut parts = nick_segment.splitn(2, '~');
        let nick = parts.next().unwrap_or(nick_segment).to_string();
        let instance = parts.next().unwrap_or("").to_string();
        (nick, instance, is_screen)
    }

    async fn handle_remote_broadcast(
        path_str: String,
        broadcast_consumer: moq_lite::BroadcastConsumer,
        audio_backend: iroh_live::media::audio_backend::AudioBackend,
        handler: Arc<dyn AvEventHandler>,
        nick: String,
        is_screen: bool,
    ) {
        // iroh-live's default policy is 150ms max_latency with cross-track
        // sync. 150ms is conservative — fine for streaming a published
        // talk, painful for a 1:1 video call. Cut it to 60ms; on a stable
        // network this gives noticeably snappier video and the synced
        // playout still keeps audio and video aligned. If we see decode
        // stutter on poor networks we can dial back up.
        let policy = iroh_live::media::playout::PlaybackPolicy::default()
            .with_max_latency(Duration::from_millis(60));
        let remote = match iroh_live::media::subscribe::RemoteBroadcast::with_playback_policy(
            &path_str,
            broadcast_consumer,
            policy,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(nick = %nick, "AV: subscribe error: {e}");
                return;
            }
        };

        let mut tracks = match remote.media(&audio_backend, Default::default()).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(nick = %nick, "AV: media error: {e}");
                return;
            }
        };

        if tracks.audio.is_some() && !is_screen {
            tracing::info!(nick = %nick, "AV: playing remote audio");
            handler.on_av_event(AvEvent::AudioTrackStarted { nick: nick.clone() });
        }

        // R1: per-participant playout level → AvEvent::AudioLevel. The
        // output sink already tracks a smoothed peak (0…1); poll it at
        // 10 Hz and emit on meaningful change so silence costs nothing.
        let audio_level_handle = if is_screen {
            None
        } else {
            tracks.audio.as_ref().map(|a| a.handle().cloned_boxed())
        };

        // `media()` samples the catalog once. A peer who joined the call
        // before enabling their camera has no video rendition in the
        // catalog at sub time, so `tracks.video` is None permanently.
        // Watch the catalog and (re)subscribe when video appears.
        let mut video = tracks.video.take();

        // Hold audio + broadcast alive for the duration of the function.
        let remote_for_watch = remote.clone();
        let _tracks = tracks;

        let level_loop = {
            let handler = handler.clone();
            let nick = nick.clone();
            async move {
                let Some(handle) = audio_level_handle else {
                    // No audio track — park forever; the select! below keeps
                    // running the video side.
                    std::future::pending::<()>().await;
                    unreachable!()
                };
                let mut last = 0.0f32;
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let Some(level) = handle.smoothed_peak_normalized() else { continue };
                    let activity_flipped = (level > 0.01) != (last > 0.01);
                    if (level - last).abs() > 0.02 || activity_flipped {
                        last = level;
                        handler.on_av_event(AvEvent::AudioLevel {
                            nick: nick.clone(),
                            level,
                        });
                    }
                }
            }
        };

        let video_loop = async move {
        loop {
            match video.take() {
                Some(mut v) => {
                    tracing::info!(nick = %nick, screen = is_screen, decoder = %v.decoder_name(), "AV: remote video track present");
                    handler.on_av_event(if is_screen {
                        AvEvent::ScreenTrackStarted { nick: nick.clone() }
                    } else {
                        AvEvent::VideoTrackStarted { nick: nick.clone() }
                    });
                    while let Some(frame) = v.next_frame().await {
                        let (w, h) = (frame.width(), frame.height());
                        // Decoded frames arrive as I420/NV12/GPU depending on
                        // backend. rgba_image() unifies them into packed RGBA;
                        // swap R↔B for BGRA (kCVPixelFormatType_32BGRA), which
                        // is what Swift's AVSampleBufferDisplayLayer expects.
                        let rgba = frame.rgba_image();
                        let mut bgra = rgba.as_raw().clone();
                        for chunk in bgra.chunks_exact_mut(4) {
                            chunk.swap(0, 2);
                        }
                        handler.on_av_event(if is_screen {
                            AvEvent::ScreenFrame {
                                nick: nick.clone(),
                                bgra,
                                width: w,
                                height: h,
                            }
                        } else {
                            AvEvent::VideoFrame {
                                nick: nick.clone(),
                                bgra,
                                width: w,
                                height: h,
                            }
                        });
                    }
                    tracing::info!(nick = %nick, screen = is_screen, "AV: remote video track ended; will re-subscribe if it returns");
                    handler.on_av_event(if is_screen {
                        AvEvent::ScreenTrackStopped { nick: nick.clone() }
                    } else {
                        AvEvent::VideoTrackStopped { nick: nick.clone() }
                    });
                    // Track ended — fall through and wait for video to come back.
                }
                None => {
                    // No video yet (or it ended). Wait for it.
                    match remote_for_watch.video_ready().await {
                        Ok(v) => {
                            video = Some(v);
                        }
                        Err(e) => {
                            tracing::warn!(nick = %nick, "AV: video_ready error: {e}; staying audio-only");
                            // Keep the function alive so audio + broadcast
                            // stay subscribed until the caller cancels.
                            std::future::pending::<()>().await;
                        }
                    }
                }
            }
        }
        };

        // Both loops run for the broadcast's lifetime; neither returns.
        // When the caller aborts this task (participant left / call over),
        // both stop together — no detached task to leak.
        tokio::select! {
            _ = level_loop => {},
            _ = video_loop => {},
        }
    }

    pub(super) fn enable_camera(state: &State) -> Result<(), FreeqError> {
        if state.camera_enabled.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        tracing::info!("AV: camera enabled");
        Ok(())
    }

    pub(super) fn disable_camera(state: &State) {
        if !state.camera_enabled.swap(false, Ordering::Relaxed) {
            return;
        }
        *state.pending_frame.lock().unwrap() = None;
        tracing::info!("AV: camera disabled");
    }

    pub(super) fn push_frame(state: &State, bgra: Vec<u8>, width: u32, height: u32, ts_us: u64) {
        if !state.camera_enabled.load(Ordering::Relaxed) {
            return; // drop frames while camera is off
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(4));
        if expected != Some(bgra.len()) {
            tracing::warn!(
                got = bgra.len(),
                expected = ?expected,
                width,
                height,
                "AV: push_video_frame size mismatch — dropping"
            );
            return;
        }
        {
            let mut fmt = state.video_format.lock().unwrap();
            if fmt.dimensions != [width, height] {
                tracing::info!(
                    old_w = fmt.dimensions[0],
                    old_h = fmt.dimensions[1],
                    new_w = width,
                    new_h = height,
                    "AV: source frame dimensions changed"
                );
                *fmt = VideoFormat {
                    pixel_format: PixelFormat::Bgra,
                    dimensions: [width, height],
                };
            }
        }
        // Periodic frame-push heartbeat — useful when diagnosing why the
        // catalog never advertises video: if pushes flow but the encoder
        // never produces packets, it's an encoder-side problem (e.g.,
        // preset dimension mismatch).
        {
            use std::sync::atomic::{AtomicU64, Ordering};
            static FRAMES: AtomicU64 = AtomicU64::new(0);
            let n = FRAMES.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(60) {
                tracing::info!(frame_no = n, width, height, "AV: pushed frame");
            }
        }
        let frame = VideoFrame::new_packed(
            bgra.into(),
            width,
            height,
            PixelFormat::Bgra,
            Duration::from_micros(ts_us),
        );
        *state.pending_frame.lock().unwrap() = Some(frame);
    }

    /// Publish the screen broadcast at `{broadcast_name}/screen`. Unlike the
    /// camera (advertised in the catalog from connect time), the screen
    /// broadcast only exists while sharing — the web client's ScreenTile
    /// reveals its spotlight when this path goes live, so publishing eagerly
    /// would show every macOS participant as a phantom screen share.
    pub(super) fn enable_screen(state: &mut State) -> Result<(), FreeqError> {
        if state.screen_broadcast.is_some() {
            state.screen_enabled.store(true, Ordering::Relaxed);
            return Ok(());
        }
        let broadcast = RUNTIME.block_on(async {
            let broadcast = LocalBroadcast::new();
            let push_source = PushVideoSource {
                pending: state.screen_pending.clone(),
                format: state.screen_format.clone(),
                enabled: state.screen_enabled.clone(),
            };
            broadcast
                .video()
                .set_source(push_source, VideoCodec::H264, [VideoPreset::P720])
                .map_err(|e| {
                    tracing::warn!("AV: screen set_source failed: {e}");
                    FreeqError::ConnectionFailed
                })?;
            let path = format!("{}/screen", state.broadcast_name);
            state.origin.publish_broadcast(&path, broadcast.consume());
            tracing::info!(path = %path, "AV: screen share published");
            Ok::<_, FreeqError>(broadcast)
        })?;
        state.screen_enabled.store(true, Ordering::Relaxed);
        state.screen_broadcast = Some(broadcast);
        Ok(())
    }

    /// Retract the screen broadcast. Peers see the path unannounced →
    /// `ScreenTrackStopped` natively, `status != live` on the web.
    pub(super) fn disable_screen(state: &mut State) {
        state.screen_enabled.store(false, Ordering::Relaxed);
        *state.screen_pending.lock().unwrap() = None;
        if let Some(broadcast) = state.screen_broadcast.take() {
            // The broadcast owns encoder tasks whose Drop needs a Tokio
            // reactor (same crash class as the leave() fix).
            let _guard = RUNTIME.enter();
            drop(broadcast);
            tracing::info!("AV: screen share retracted");
        }
    }

    pub(super) fn push_screen(state: &State, bgra: Vec<u8>, width: u32, height: u32, ts_us: u64) {
        if !state.screen_enabled.load(Ordering::Relaxed) {
            return;
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(4));
        if expected != Some(bgra.len()) {
            tracing::warn!(
                got = bgra.len(),
                expected = ?expected,
                width,
                height,
                "AV: push_screen_frame size mismatch — dropping"
            );
            return;
        }
        {
            let mut fmt = state.screen_format.lock().unwrap();
            if fmt.dimensions != [width, height] {
                *fmt = VideoFormat {
                    pixel_format: PixelFormat::Bgra,
                    dimensions: [width, height],
                };
            }
        }
        // Frame heartbeat, mirroring push_frame: proves capture is actually
        // delivering (TCC-denied ScreenCaptureKit fails without frames).
        {
            use std::sync::atomic::{AtomicU64, Ordering};
            static FRAMES: AtomicU64 = AtomicU64::new(0);
            let n = FRAMES.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(60) {
                tracing::info!(frame_no = n, width, height, "AV: pushed screen frame");
            }
        }
        let frame = VideoFrame::new_packed(
            bgra.into(),
            width,
            height,
            PixelFormat::Bgra,
            Duration::from_micros(ts_us),
        );
        *state.screen_pending.lock().unwrap() = Some(frame);
    }

    pub(super) fn push_audio(state: &State, samples: Vec<f32>) {
        // Bound the backlog on the PRODUCER side: if the encoder stalls it
        // never calls pop_samples, so the cap has to live here or the queue
        // grows without bound (memory leak + seconds of stale audio on
        // resume). Drops oldest to keep real-time latency low.
        let mut q = state.audio_queue.lock().unwrap();
        crate::audio_buffer::push_capped(&mut q, samples, crate::audio_buffer::MAX_BACKLOG_SAMPLES);
    }

    /// Output devices for the speaker picker (remote audio plays through
    /// the Rust cpal backend, not AVFoundation).
    pub(super) fn list_output_devices() -> Vec<crate::AvAudioDevice> {
        iroh_live::media::audio_backend::AudioBackend::list_outputs()
            .into_iter()
            .map(|d| crate::AvAudioDevice {
                id: d.id.to_string(),
                name: d.name,
                is_default: d.is_default,
            })
            .collect()
    }

    /// Route remote-audio playback to a device (None = system default).
    pub(super) fn set_output_device(state: &State, device_id: Option<String>) -> Result<(), FreeqError> {
        use std::str::FromStr;
        let device = match device_id {
            None => None,
            Some(id) => Some(
                iroh_live::media::audio_backend::DeviceId::from_str(&id)
                    .map_err(|_| FreeqError::InvalidArgument)?,
            ),
        };
        RUNTIME
            .block_on(state.audio_backend.switch_output(device))
            .map_err(|e| {
                tracing::warn!("AV: switch_output failed: {e}");
                FreeqError::SendFailed
            })
    }
}

#[cfg(feature = "av")]
pub struct FreeqAv {
    state: Mutex<Option<av_impl::State>>,
}

#[cfg(not(feature = "av"))]
pub struct FreeqAv;

#[cfg(feature = "av")]
impl FreeqAv {
    fn new(
        server_url: String,
        session_id: String,
        nick: String,
        instance_id: String,
        handler: Box<dyn AvEventHandler>,
    ) -> Result<Self, FreeqError> {
        let state = av_impl::connect(server_url, session_id, nick, instance_id, handler)?;
        Ok(Self {
            state: Mutex::new(Some(state)),
        })
    }

    fn leave(&self) {
        // Take the State out under the lock, then release the lock before the
        // teardown so we don't hold the mutex during async shutdown.
        let taken = {
            let mut guard = self.state.lock().unwrap();
            if let Some(state) = guard.as_mut() {
                if let Some(tx) = state.shutdown_tx.take() {
                    let _ = tx.send(());
                }
                state.connected = false;
            }
            guard.take()
        };
        // Drop the State (which tears down the MoQ / web-transport session)
        // INSIDE the tokio runtime context. The session's Drop impl spawns
        // shutdown work and panics ("there is no reactor running, must be
        // called from the context of a Tokio 1.x runtime") if dropped from a
        // plain FFI thread — which crashes the host app on `/av leave`.
        if let Some(state) = taken {
            let _enter = RUNTIME.enter();
            drop(state);
        }
    }

    fn set_muted(&self, muted: bool) {
        let guard = self.state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            state
                .muted
                .store(muted, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(muted, "AV: mute set");
        }
    }

    fn set_camera_enabled(&self, enabled: bool) -> Result<(), FreeqError> {
        let mut guard = self.state.lock().unwrap();
        let state = guard.as_mut().ok_or(FreeqError::NotConnected)?;
        if enabled {
            av_impl::enable_camera(state)
        } else {
            av_impl::disable_camera(state);
            Ok(())
        }
    }

    fn push_video_frame(&self, bgra: Vec<u8>, width: u32, height: u32, timestamp_us: u64) {
        let guard = self.state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            av_impl::push_frame(state, bgra, width, height, timestamp_us);
        }
    }

    fn push_audio_frame(&self, samples: Vec<f32>) {
        let guard = self.state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            av_impl::push_audio(state, samples);
        }
    }

    fn set_screen_enabled(&self, enabled: bool) -> Result<(), FreeqError> {
        let mut guard = self.state.lock().unwrap();
        let state = guard.as_mut().ok_or(FreeqError::NotConnected)?;
        if enabled {
            av_impl::enable_screen(state)
        } else {
            av_impl::disable_screen(state);
            Ok(())
        }
    }

    fn push_screen_frame(&self, bgra: Vec<u8>, width: u32, height: u32, timestamp_us: u64) {
        let guard = self.state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            av_impl::push_screen(state, bgra, width, height, timestamp_us);
        }
    }

    fn list_output_devices(&self) -> Vec<AvAudioDevice> {
        av_impl::list_output_devices()
    }

    fn set_output_device(&self, device_id: Option<String>) -> Result<(), FreeqError> {
        let guard = self.state.lock().unwrap();
        let state = guard.as_ref().ok_or(FreeqError::NotConnected)?;
        av_impl::set_output_device(state, device_id)
    }

    fn is_connected(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.connected)
            .unwrap_or(false)
    }
}

#[cfg(feature = "av")]
impl Drop for FreeqAv {
    fn drop(&mut self) {
        // Belt-and-suspenders for the same reason as `leave()`: if the object
        // is deallocated while still holding a live session (e.g. a call that
        // was never explicitly left), tear it down inside the runtime context
        // so the web-transport session's Drop has a reactor.
        if let Ok(mut guard) = self.state.lock() {
            if let Some(state) = guard.take() {
                let _enter = RUNTIME.enter();
                drop(state);
            }
        }
    }
}

#[cfg(not(feature = "av"))]
impl FreeqAv {
    fn new(
        _server_url: String,
        _session_id: String,
        _nick: String,
        _instance_id: String,
        _handler: Box<dyn AvEventHandler>,
    ) -> Result<Self, FreeqError> {
        Err(FreeqError::ConnectionFailed) // AV not compiled in
    }

    fn leave(&self) {}
    fn set_muted(&self, _muted: bool) {}
    fn set_camera_enabled(&self, _enabled: bool) -> Result<(), FreeqError> {
        Err(FreeqError::NotConnected)
    }
    fn push_video_frame(&self, _bgra: Vec<u8>, _w: u32, _h: u32, _ts: u64) {}
    fn push_audio_frame(&self, _samples: Vec<f32>) {}
    fn set_screen_enabled(&self, _enabled: bool) -> Result<(), FreeqError> {
        Err(FreeqError::NotConnected)
    }
    fn push_screen_frame(&self, _bgra: Vec<u8>, _w: u32, _h: u32, _ts: u64) {}
    fn list_output_devices(&self) -> Vec<AvAudioDevice> {
        Vec::new()
    }
    fn set_output_device(&self, _device_id: Option<String>) -> Result<(), FreeqError> {
        Err(FreeqError::NotConnected)
    }
    fn is_connected(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestAvHandler {
        connected: Arc<AtomicBool>,
    }

    impl AvEventHandler for TestAvHandler {
        fn on_av_event(&self, event: AvEvent) {
            match event {
                AvEvent::Connected => {
                    self.connected.store(true, Ordering::Relaxed);
                    println!("[test] AV connected");
                }
                AvEvent::Disconnected { reason } => {
                    println!("[test] AV disconnected: {reason}");
                }
                AvEvent::ParticipantJoined { nick, instance } => {
                    println!("[test] Participant joined: {nick} (instance {instance})");
                }
                AvEvent::ParticipantLeft { nick, instance } => {
                    println!("[test] Participant left: {nick} (instance {instance})");
                }
                AvEvent::Error { message } => {
                    println!("[test] AV error: {message}");
                }
                _ => {}
            }
        }
    }

    #[test]
    fn av_event_types_exist() {
        // Verify all event variants can be constructed
        let _ = AvEvent::Connected;
        let _ = AvEvent::Disconnected {
            reason: "test".to_string(),
        };
        let _ = AvEvent::ParticipantJoined {
            nick: "alice".to_string(),
            instance: "devA".to_string(),
        };
        let _ = AvEvent::ParticipantLeft {
            nick: "bob".to_string(),
            instance: "devB".to_string(),
        };
        let _ = AvEvent::AudioTrackStarted {
            nick: "carol".to_string(),
        };
        let _ = AvEvent::AudioTrackStopped {
            nick: "dave".to_string(),
        };
        let _ = AvEvent::VideoTrackStarted {
            nick: "eve".to_string(),
        };
        let _ = AvEvent::VideoTrackStopped {
            nick: "frank".to_string(),
        };
        let _ = AvEvent::VideoFrame {
            nick: "grace".to_string(),
            bgra: vec![0; 4],
            width: 1,
            height: 1,
        };
        let _ = AvEvent::ScreenTrackStarted {
            nick: "heidi".to_string(),
        };
        let _ = AvEvent::ScreenTrackStopped {
            nick: "heidi".to_string(),
        };
        let _ = AvEvent::ScreenFrame {
            nick: "heidi".to_string(),
            bgra: vec![0; 4],
            width: 1,
            height: 1,
        };
        let _ = AvEvent::Error {
            message: "test error".to_string(),
        };
    }

    #[cfg(feature = "av")]
    #[test]
    fn reconnect_backoff_is_capped_exponential() {
        use super::av_impl::reconnect_backoff;
        use std::time::Duration;
        assert_eq!(reconnect_backoff(1), Duration::from_millis(250));
        assert_eq!(reconnect_backoff(2), Duration::from_millis(500));
        assert_eq!(reconnect_backoff(3), Duration::from_millis(1000));
        assert_eq!(reconnect_backoff(4), Duration::from_millis(2000));
        assert_eq!(reconnect_backoff(5), Duration::from_millis(4000));
        // Capped at 5s flat thereafter — no unbounded growth or overflow.
        assert_eq!(reconnect_backoff(6), Duration::from_millis(5000));
        assert_eq!(reconnect_backoff(100), Duration::from_millis(5000));
        assert_eq!(reconnect_backoff(u32::MAX), Duration::from_millis(5000));
    }

    #[cfg(feature = "av")]
    #[test]
    fn session_scoping_filters_foreign_broadcasts() {
        use super::av_impl::belongs_to_session;
        assert!(belongs_to_session("sess-a/alice~ff00", "sess-a"));
        assert!(belongs_to_session("sess-a/alice~ff00/screen", "sess-a"));
        // Another call's broadcast must never be subscribed.
        assert!(!belongs_to_session("sess-b/clyde~0144", "sess-a"));
        // Prefix collisions don't count: "sess-a2/..." is not in "sess-a".
        assert!(!belongs_to_session("sess-a2/mallory", "sess-a"));
        assert!(!belongs_to_session("sess-a", "sess-a"));
    }

    #[cfg(feature = "av")]
    #[test]
    fn broadcast_path_parsing() {
        use super::av_impl::parse_broadcast_path;
        // Instance is extracted (not stripped) so clients can key presence on it.
        assert_eq!(
            parse_broadcast_path("sess-1/alice~ff00aa11"),
            ("alice".to_string(), "ff00aa11".to_string(), false)
        );
        assert_eq!(
            parse_broadcast_path("sess-1/alice~ff00aa11/screen"),
            ("alice".to_string(), "ff00aa11".to_string(), true)
        );
        // Legacy peer with no ~instance suffix → empty instance.
        assert_eq!(
            parse_broadcast_path("sess-1/bob"),
            ("bob".to_string(), String::new(), false)
        );
        assert_eq!(
            parse_broadcast_path("sess-1/bob/screen"),
            ("bob".to_string(), String::new(), true)
        );
        // A bare nick "screen" with no parent segment is not a screen share.
        assert_eq!(
            parse_broadcast_path("screen"),
            ("screen".to_string(), String::new(), false)
        );
        // A nick that itself contains a dotted domain keeps the dots; only the
        // first ~ splits nick from instance.
        assert_eq!(
            parse_broadcast_path("sess-1/chadfowler.com~dev42"),
            ("chadfowler.com".to_string(), "dev42".to_string(), false)
        );
    }

    #[test]
    fn av_handler_trait_works() {
        let connected = Arc::new(AtomicBool::new(false));
        let handler = TestAvHandler {
            connected: connected.clone(),
        };
        handler.on_av_event(AvEvent::Connected);
        assert!(connected.load(Ordering::Relaxed));
    }

    #[test]
    fn av_without_server_fails_gracefully() {
        let connected = Arc::new(AtomicBool::new(false));
        let handler = Box::new(TestAvHandler { connected });

        // Connecting to a non-existent server should fail, not panic
        let result = FreeqAv::new(
            "http://127.0.0.1:19999".to_string(), // no server here
            "test-session".to_string(),
            "test-nick".to_string(),
            "test-instance".to_string(),
            handler,
        );

        assert!(result.is_err());
    }

    #[cfg(feature = "av")]
    #[test]
    fn av_leave_sets_disconnected() {
        // Can't create without a server, but we can test the stub path
        // by verifying the non-av build returns error
    }

    #[test]
    fn parse_reactions_tag_handles_canonical_format() {
        let tallies = parse_reactions_tag("👍:alice,bob;❤️:carol");
        assert_eq!(tallies.len(), 2);
        assert_eq!(tallies[0].emoji, "👍");
        assert_eq!(
            tallies[0].nicks,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(tallies[1].emoji, "❤️");
        assert_eq!(tallies[1].nicks, vec!["carol".to_string()]);
    }

    #[test]
    fn parse_reactions_tag_skips_malformed_segments() {
        // missing colon, empty emoji, empty nicks, stray ; — all dropped silently
        let tallies = parse_reactions_tag("notacolon;:no_emoji;👍:;👎:dave");
        assert_eq!(tallies.len(), 1);
        assert_eq!(tallies[0].emoji, "👎");
        assert_eq!(tallies[0].nicks, vec!["dave".to_string()]);
    }

    #[test]
    fn parse_reactions_tag_empty_input() {
        assert!(parse_reactions_tag("").is_empty());
    }

    /// A message edited before you joined arrives already collapsed: the
    /// server sends one row, the current text, and no `+draft/edit` to hint
    /// that it was ever revised. `+freeq.at/edited` is the only signal, so a
    /// client that doesn't surface it renders the revision as the original.
    #[test]
    fn convert_event_message_marks_edited_from_replay_tag() {
        let mk = |extra: Option<(&str, &str)>| {
            let mut tags = std::collections::HashMap::new();
            tags.insert("msgid".to_string(), "01ABC".to_string());
            if let Some((k, v)) = extra {
                tags.insert(k.to_string(), v.to_string());
            }
            let ev = freeq_sdk::event::Event::Message {
                from: "alice".to_string(),
                target: "#naptest".to_string(),
                text: "hi".to_string(),
                tags,
                dm_key: None,
            };
            let FreeqEvent::Message { msg } = convert_event(&ev).expect("exposed event") else {
                panic!("expected Message variant");
            };
            msg
        };

        assert!(!mk(None).edited, "an untouched message must not be marked");
        assert!(
            mk(Some(("+freeq.at/edited", "1"))).edited,
            "replay marker ignored — an edited message would look original"
        );
        // A live edit is still recognizable on its own.
        assert!(mk(Some(("+draft/edit", "01ORIG"))).edited);
    }

    #[test]
    fn convert_event_message_populates_reactions_from_tag() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("msgid".to_string(), "01ABC".to_string());
        tags.insert(
            "+freeq.at/reactions".to_string(),
            "👍:alice,bob;🎉:carol".to_string(),
        );
        let ev = freeq_sdk::event::Event::Message {
            from: "smoke-tx".to_string(),
            target: "#naptest".to_string(),
            text: "hi".to_string(),
            tags,
            dm_key: None,
        };
        let out = convert_event(&ev).expect("exposed event");
        let FreeqEvent::Message { msg } = out else {
            panic!("expected Message variant");
        };
        assert_eq!(msg.reactions.len(), 2);
        assert!(msg
            .reactions
            .iter()
            .any(|r| r.emoji == "👍" && r.nicks == vec!["alice".to_string(), "bob".to_string()]));
        assert!(msg
            .reactions
            .iter()
            .any(|r| r.emoji == "🎉" && r.nicks == vec!["carol".to_string()]));
    }

    #[test]
    fn convert_event_message_parses_coordination_tags() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("msgid".to_string(), "01ABC".to_string());
        tags.insert("+freeq.at/event".to_string(), "task_update".to_string());
        tags.insert("+freeq.at/task-id".to_string(), "T4821".to_string());
        tags.insert("+freeq.at/phase".to_string(), "testing".to_string());
        tags.insert("+freeq.at/payload".to_string(), "{\"step\":3}".to_string());
        let ev = freeq_sdk::event::Event::Message {
            from: "relay-agent".to_string(),
            target: "#ship-it".to_string(),
            text: "cart ok".to_string(),
            tags,
            dm_key: None,
        };
        let FreeqEvent::Message { msg } = convert_event(&ev).expect("event") else {
            panic!("expected Message");
        };
        let coord = msg.coordination.expect("coordination populated");
        assert_eq!(coord.event_type, "task_update");
        assert_eq!(coord.task_id.as_deref(), Some("T4821"));
        assert_eq!(coord.phase.as_deref(), Some("testing"));
        assert_eq!(coord.payload.as_deref(), Some("{\"step\":3}"));
    }

    #[test]
    fn convert_event_message_unprefixed_coordination_fallback() {
        // Some senders emit `freeq.at/event` without the leading `+`.
        let mut tags = std::collections::HashMap::new();
        tags.insert("freeq.at/event".to_string(), "task_complete".to_string());
        let ev = freeq_sdk::event::Event::Message {
            from: "a".to_string(), target: "#c".to_string(), text: "done".to_string(),
            tags, dm_key: None,
        };
        let FreeqEvent::Message { msg } = convert_event(&ev).expect("event") else {
            panic!("expected Message");
        };
        assert_eq!(msg.coordination.expect("coord").event_type, "task_complete");
    }

    #[test]
    fn convert_event_message_no_event_tag_yields_no_coordination() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("msgid".to_string(), "01Q".to_string());
        let ev = freeq_sdk::event::Event::Message {
            from: "a".to_string(), target: "#c".to_string(), text: "plain".to_string(),
            tags, dm_key: None,
        };
        let FreeqEvent::Message { msg } = convert_event(&ev).expect("event") else {
            panic!("expected Message");
        };
        assert!(msg.coordination.is_none());
    }

    #[test]
    fn convert_event_message_no_reactions_tag_yields_empty() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("msgid".to_string(), "01XYZ".to_string());
        let ev = freeq_sdk::event::Event::Message {
            from: "alice".to_string(),
            target: "#x".to_string(),
            text: "no reactions here".to_string(),
            tags,
            dm_key: None,
        };
        let out = convert_event(&ev).expect("exposed event");
        let FreeqEvent::Message { msg } = out else {
            panic!("expected Message variant");
        };
        assert!(msg.reactions.is_empty());
    }

    // ── typed senders ──

    #[test]
    fn tag_entries_become_a_tag_map() {
        let map = tag_entries_to_map(vec![
            TagEntry {
                key: "+reply".to_string(),
                value: "01ABC".to_string(),
            },
            TagEntry {
                key: "+draft/edit".to_string(),
                value: "01DEF".to_string(),
            },
        ]);
        assert_eq!(map.get("+reply").map(String::as_str), Some("01ABC"));
        assert_eq!(map.get("+draft/edit").map(String::as_str), Some("01DEF"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn valueless_tags_survive_the_conversion() {
        // A bare tag is `key` with no `=value` on the wire — the empty string
        // has to reach the SDK as a present key, not get dropped.
        let map = tag_entries_to_map(vec![TagEntry {
            key: "+freeq.at/multiline".to_string(),
            value: String::new(),
        }]);
        assert_eq!(map.get("+freeq.at/multiline").map(String::as_str), Some(""));
    }

    #[test]
    fn a_repeated_tag_key_keeps_the_last_value() {
        let map = tag_entries_to_map(vec![
            TagEntry {
                key: "+reply".to_string(),
                value: "first".to_string(),
            },
            TagEntry {
                key: "+reply".to_string(),
                value: "second".to_string(),
            },
        ]);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("+reply").map(String::as_str), Some("second"));
    }

    struct SilentHandler;
    impl EventHandler for SilentHandler {
        fn on_event(&self, _event: FreeqEvent) {}
    }

    fn unconnected_client() -> FreeqClient {
        FreeqClient::new(
            "localhost:6667".to_string(),
            "tester".to_string(),
            Box::new(SilentHandler),
        )
        .expect("client")
    }

    /// Every typed sender refuses before there is a connection to send on,
    /// and says so as `NotConnected` rather than a generic send failure —
    /// the caller distinguishes "not yet" from "it went wrong".
    #[test]
    fn typed_senders_report_not_connected() {
        macro_rules! assert_not_connected {
            ($call:expr) => {
                match $call {
                    Err(FreeqError::NotConnected) => {}
                    other => panic!(
                        "{}: expected NotConnected, got {other:?}",
                        stringify!($call)
                    ),
                }
            };
        }
        let c = unconnected_client();
        assert!(!c.is_connected());
        assert_not_connected!(c.send_tagged("#c".into(), "hi".into(), Vec::new()));
        assert_not_connected!(c.react("#c".into(), "👍".into(), "01A".into()));
        assert_not_connected!(c.unreact("#c".into(), "👍".into(), "01A".into()));
        assert_not_connected!(c.delete_message("#c".into(), "01A".into()));
        assert_not_connected!(c.edit_message("#c".into(), "01A".into(), "new".into()));
        assert_not_connected!(c.reply("#c".into(), "01A".into(), "text".into()));
        assert_not_connected!(c.typing_start("#c".into()));
        assert_not_connected!(c.typing_stop("#c".into()));
        assert_not_connected!(c.request_whois("bob".into()));
    }

    /// The FFI layer adds no logic, but a field mix-up in the conversion
    /// would still compile — so one claim crosses the boundary end to end.
    #[test]
    fn a_claim_crosses_the_ffi_conversion_intact() {
        let relayed = claim_for_message(MessageClaimInput {
            account: Some("did:plc:abc".into()),
            origin: Some("irc.freeq.at".into()),
            sender_present: false,
            sender_live_did: None,
            row_time_unix: Some(1_786_320_000),
        });
        assert!(matches!(relayed.state, IdentityClaimState::Relayed));
        assert_eq!(relayed.did.as_deref(), Some("did:plc:abc"));
        assert_eq!(relayed.origin.as_deref(), Some("irc.freeq.at"));
        assert_eq!(relayed.label.as_deref(), Some("Relayed identity"));
        assert!(relayed.line.unwrap().contains("irc.freeq.at vouches for it"));
        assert!(!relayed.shows_mark);
        assert!(!relayed.is_pending);
        assert!(!relayed.needs_key_card);

        let pending = claim_for_sender(
            MessageClaimInput {
                account: None,
                origin: None,
                sender_present: false,
                sender_live_did: None,
                row_time_unix: Some(1_750_000_000),
            },
            PersonLookup::InFlight,
        );
        assert!(matches!(pending.state, IdentityClaimState::LookingUp));
        assert!(pending.is_pending);
        assert_eq!(pending.label, None);
        assert_eq!(pending.line, None);

        assert_eq!(identity_stamping_epoch_unix(), 1_785_542_400);
    }
}
